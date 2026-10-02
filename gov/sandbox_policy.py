"""Declarative sandbox policy-as-data (wave-284 lane 7, nsjail STEAL).

PATTERN LINEAGE: google/nsjail (Apache-2.0 -- LICENSE bytes verified by
the wave-283 prospecting lane): the declarative ``config.proto`` policy
taxonomy (namespaces, rlimits, cgroup budgets, mounts) and the Kafel
syscall-policy grammar (``POLICY`` blocks, syscall argument filters,
fail-closed by construction: no DEFAULT -> KILL). This is a clean-room
stdlib re-implementation of the *mechanisms* only; no nsjail/Kafel code,
protos, or prose are vendored here. Kafel itself is a separate repo
(``google/kafel``, also Apache-2.0).

What this module adds:

* a VERSIONED, content-digest-pinned sandbox-policy document
  (namespaces / rlimits / cgroup-style budgets / mount policy /
  syscall policy) -- policy-as-data: hashable, diffable, audit-loggable
  per execution, exactly what the HMAC-chained audit log wants to
  record;
* a Kafel-derived syscall grammar (``POLICY`` blocks, ``ALLOW`` /
  ``DENY`` / ``DEFAULT``, argument filters like
  ``mmap((prot & 4) == 0)``) compiled to a deterministic decision
  function;
* pin-and-diff use-time guarantees: a sandbox never runs under an
  unpinned policy (``sandbox-policy-unpinned``) or a drifted one
  (``sandbox-policy-drift``, including subset/superset diffs); every
  diff names the changed field paths;
* fail-closed by construction: a syscall policy without an explicit
  ``DEFAULT`` action is refused at compile time
  (``sandbox-policy-no-default``); every kill is an audit event;
* host validation: the declared isolation requirements are checked
  against what the host/executor can actually enforce
  (``sandbox-policy-host-mismatch``) -- the wave-176/177 EPERM lesson,
  now as code instead of folklore.

Honest boundary (documented, not hidden): this prototype compiles the
Kafel-derived grammar to a *process-supervision-level* decision function
-- it decides which syscalls a supervised tool script may invoke, and
``gov/sandbox.py`` enforces the declared namespaces/rlimits at spawn.
It is NOT a kernel seccomp-bpf filter; true seccomp enforcement still
needs a supervisor like nsjail itself (or landlock/seccomp on Linux).
The value here is the *reviewable, pinned, audited* policy artifact --
the same value the prospectus identifies in nsjail.

Composition, not duplication: this module supplies the policy LAYER for
``gov/sandbox.py`` -- it does not spawn processes and does not re-create
the executor. :func:`bind` checks a compiled policy against its pin and
against the isolation the executor can actually enforce, returning a
:class:`PolicyBinding` whose ``decide`` audits every decision.
"""

import hashlib
import json
import os
import re
import sys

SCHEMA_VERSION = 1

#: Closed namespace vocabulary (nsjail's CLONE_* taxonomy).
NAMESPACES = ("uts", "mount", "pid", "ipc", "net", "user", "cgroup", "time")

#: Closed rlimit vocabulary.
RLIMITS = ("cpu_seconds", "address_space_bytes", "file_size_bytes",
           "open_files", "nproc")

#: Closed cgroup-style budget vocabulary.
BUDGETS = ("max_wall_seconds", "max_output_bytes")

#: Closed mount-policy sections.
MOUNT_SECTIONS = ("readonly", "writable", "masked")

#: Closed DEFAULT actions for the syscall policy.
DEFAULT_ACTIONS = ("allow", "deny", "kill")

#: Record type for per-decision audit events.
DECISION_RECORD_TYPE = "sandbox-policy-decision"


class SandboxPolicyError(ValueError):
    """Base for sandbox-policy failures.

    Every refusal carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text).
    """

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


class SandboxPolicyInvalid(SandboxPolicyError):
    """The policy document or syscall grammar is malformed (compile
    time). Fail-closed: nothing runs under a policy that cannot be
    compiled."""


class SandboxPolicyRefused(SandboxPolicyError):
    """The policy is well-formed but use is refused (use time):
    unpinned, drifted, or unenforceable on this host. Loud refusal,
    never silent degradation."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest_of(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Kafel-derived syscall grammar
# ---------------------------------------------------------------------------
#
# Supported subset (deliberately small, deterministic, auditable):
#
#   POLICY <name> {
#     DEFAULT KILL | ALLOW | DENY
#     ALLOW { read, write, mmap((prot & 4) == 0) }
#     DENY { execve, execveat }
#   }
#
# Multiple POLICY blocks merge. Within ALLOW/DENY, entries are bare
# syscall names or ``name(<expr>)`` filters; an entry with a filter
# only matches when the filter evaluates true. Filter expressions
# support identifiers (syscall argument names), integer/hex constants,
# ``&`` (bitwise and), comparisons (== != < > <= >=), and parentheses.
# A missing argument fails the filter CLOSED (the syscall is killed).
#
# NOT supported (documented): #include composition, USE clauses, arch
# guards, string arguments, syscall numbers. If a policy needs them, it
# belongs in a real Kafel/nsjail supervisor, not this prototype.

_SYSCALL_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

_TOKEN_RE = re.compile(r"""
    (?P<hex>0[xX][0-9a-fA-F]+)
  | (?P<num>\d+)
  | (?P<ident>[a-zA-Z_][a-zA-Z0-9_]*)
  | (?P<op><=|>=|==|!=|<|>|&)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<ws>\s+)
""", re.VERBOSE)


def _tokenize(expr):
    tokens = []
    pos = 0
    while pos < len(expr):
        match = _TOKEN_RE.match(expr, pos)
        if not match:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "unparseable filter expression near %r" % (expr[pos:pos + 16],))
        pos = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        tokens.append((kind, match.group()))
    if not tokens:
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "empty filter expression")
    return tokens


class _FilterParser:
    """Recursive-descent parser for filter expressions.

    Supported grammar (deliberately small and total -- the compiler
    cannot hang on hostile input)::

        comparison := bitand (("==" | "!=" | "<" | ">" | "<=" | ">=") bitand)?
        bitand     := primary ("&" primary)*
        primary    := integer | hex | identifier | "(" comparison ")"

    Logical and/or are NOT supported. A filter that cannot be
    evaluated (missing or wrong-typed argument) fails closed at
    decision time.
    """

    def __init__(self, tokens):
        self._tokens = tokens
        self._pos = 0

    def parse(self):
        node = self._comparison()
        if self._pos != len(self._tokens):
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "trailing tokens in filter expression")
        return node

    def _peek(self):
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return (None, None)

    def _next(self):
        tok = self._peek()
        self._pos += 1
        return tok

    def _primary(self):
        kind, text = self._next()
        if kind == "hex":
            return ("const", int(text, 16))
        if kind == "num":
            return ("const", int(text))
        if kind == "ident":
            return ("arg", text)
        if kind == "lparen":
            node = self._comparison()
            kind2, _ = self._next()
            if kind2 != "rparen":
                raise SandboxPolicyInvalid(
                    "sandbox-policy-invalid",
                    "missing closing parenthesis in filter")
            return node
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "unexpected token %r in filter expression" % (text,))

    def _bitand(self):
        node = self._primary()
        while self._peek() == ("op", "&"):
            self._next()
            node = ("band", node, self._primary())
        return node

    def _comparison(self):
        node = self._bitand()
        kind, text = self._peek()
        if kind == "op" and text in ("==", "!=", "<", ">", "<=", ">="):
            self._next()
            node = ("cmp", text, node, self._bitand())
        return node


def _eval_filter(node, args):
    kind = node[0]
    if kind == "const":
        return node[1]
    if kind == "arg":
        # A missing argument fails the filter CLOSED.
        if node[1] not in args:
            raise _FilterFailClosed()
        value = args[node[1]]
        if not isinstance(value, int) or isinstance(value, bool):
            raise _FilterFailClosed()
        return value
    if kind == "band":
        return _eval_filter(node[1], args) & _eval_filter(node[2], args)
    if kind == "cmp":
        _, op, left, right = node
        left = _eval_filter(left, args)
        right = _eval_filter(right, args)
        return {
            "==": left == right,
            "!=": left != right,
            "<": left < right,
            ">": left > right,
            "<=": left <= right,
            ">=": left >= right,
        }[op]
    raise SandboxPolicyInvalid(  # pragma: no cover - parser is total
        "sandbox-policy-invalid",
        "internal: unknown filter node %r" % (kind,))


class _FilterFailClosed(Exception):
    """Internal: a filter could not be evaluated; the syscall is
    killed. Never surfaces to callers."""


_POLICY_HEAD_RE = re.compile(
    r"POLICY\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.DOTALL)
_SECTION_RE = re.compile(
    r"(DEFAULT|ALLOW|DENY)\s+(?:(KILL|ALLOW|DENY)\s*)?"
    r"(?:\{([^{}]*)\})?",
    re.DOTALL)


def _extract_policy_blocks(rule_text):
    """Yield (name, body) for each POLICY block, honoring nested
    braces (ALLOW/DENY sections have their own { ... })."""
    blocks = []
    pos = 0
    spans = []
    while True:
        match = _POLICY_HEAD_RE.search(rule_text, pos)
        if not match:
            break
        depth = 1
        idx = match.end()
        while idx < len(rule_text) and depth:
            char = rule_text[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            idx += 1
        if depth:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "unbalanced braces in POLICY block %r"
                % (match.group(1),))
        blocks.append((match.group(1), rule_text[match.end():idx - 1]))
        spans.append((match.start(), idx))
        pos = idx
    leftover = "".join(
        rule_text[end:start]
        for (end, start) in
        zip([0] + [s[1] for s in spans], [s[0] for s in spans] + [len(rule_text)]))
    if re.sub(r"\s+", "", leftover):
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "unparseable syscall rule text near %r"
            % (leftover.strip()[:48],))
    return blocks


def _parse_syscall_rules(rules):
    """Compile the Kafel-derived syscall rules.

    Returns (default_action, allow_map, deny_set) where allow_map maps
    a syscall name to a list of filter ASTs (empty list = unconditional
    allow) and deny_set is the unconditional deny set. Raises
    ``SandboxPolicyInvalid``; a missing DEFAULT raises with code
    ``sandbox-policy-no-default``.
    """
    default = None
    allow_map = {}
    deny_set = set()
    seen_any = False
    for rule_text in rules:
        if not isinstance(rule_text, str):
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "syscall rules must be strings, got %r"
                % type(rule_text).__name__)
        blocks = _extract_policy_blocks(rule_text)
        if rule_text.strip() and not blocks:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "syscall rule has no POLICY block: %r"
                % (rule_text.strip()[:48],))
        seen_any = seen_any or bool(blocks)
        for _name, body in blocks:
            sections = list(_SECTION_RE.finditer(body))
            # Anything inside the block that is not a well-formed
            # section is refused LOUD: a policy that silently differs
            # from what a reviewer read is not a reviewable policy
            # (catches ALLOW{read} without space, FOOBAR { ... },
            # nested POLICY blocks, and entries on a DEFAULT section).
            remainder = body
            for section in reversed(sections):
                remainder = (remainder[:section.start()]
                             + remainder[section.end():])
            if re.sub(r"\s+", "", remainder):
                raise SandboxPolicyInvalid(
                    "sandbox-policy-invalid",
                    "unparseable content inside POLICY block: %r"
                    % (remainder.strip()[:48],))
            for section in sections:
                kind, action, entries = (section.group(1), section.group(2),
                                        section.group(3))
                if kind == "DEFAULT":
                    if action not in ("KILL", "ALLOW", "DENY"):
                        raise SandboxPolicyInvalid(
                            "sandbox-policy-invalid",
                            "DEFAULT must be KILL, ALLOW, or DENY")
                    if entries:
                        raise SandboxPolicyInvalid(
                            "sandbox-policy-invalid",
                            "DEFAULT takes no entries: %r" % (entries.strip(),))
                    default = action.lower()
                else:
                    if not entries:
                        continue
                    for entry in entries.split(","):
                        entry = entry.strip()
                        if not entry:
                            continue
                        match = re.match(
                            r"^([a-z_][a-z0-9_]*)\s*(\((.*)\))?$",
                            entry, re.DOTALL)
                        if not match:
                            raise SandboxPolicyInvalid(
                                "sandbox-policy-invalid",
                                "bad syscall entry %r" % (entry,))
                        syscall, _paren, expr = match.groups()
                        if not _SYSCALL_RE.match(syscall):
                            raise SandboxPolicyInvalid(
                                "sandbox-policy-invalid",
                                "bad syscall name %r" % (syscall,))
                        if kind == "DENY":
                            if expr:
                                raise SandboxPolicyInvalid(
                                    "sandbox-policy-invalid",
                                    "DENY entries take no filter: %r"
                                    % (entry,))
                            deny_set.add(syscall)
                        else:
                            filters = allow_map.setdefault(syscall, [])
                            if expr is not None:
                                parser = _FilterParser(_tokenize(expr))
                                filters.append(parser.parse())
    if default is None:
        raise SandboxPolicyInvalid(
            "sandbox-policy-no-default",
            "syscall policy declares no DEFAULT action: fail-closed by "
            "construction -- add an explicit DEFAULT KILL/ALLOW/DENY")
    return default, allow_map, deny_set


# ---------------------------------------------------------------------------
# Policy document
# ---------------------------------------------------------------------------

def _require_dict(value, where):
    if not isinstance(value, dict):
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "%s must be a dict, got %r" % (where, type(value).__name__))
    return value


def _validate_namespaces(value):
    value = _require_dict(value, "namespaces")
    for name, want in value.items():
        if name not in NAMESPACES:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "unknown namespace %r (expected one of %s)"
                % (name, ", ".join(NAMESPACES)))
        if not isinstance(want, bool):
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "namespace %r must be a bool, got %r"
                % (name, type(want).__name__))
    return {name: value.get(name, False) for name in NAMESPACES}


def _validate_int_map(value, vocabulary, where):
    value = _require_dict(value, where)
    out = {}
    for name, limit in value.items():
        if name not in vocabulary:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "unknown %s key %r" % (where, name))
        if not isinstance(limit, int) or isinstance(limit, bool) \
                or limit < 0:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "%s.%s must be a non-negative int" % (where, name))
    for name in vocabulary:
        out[name] = value.get(name, 0)
    return out


def _validate_mounts(value):
    value = _require_dict(value, "mounts")
    out = {}
    for section in MOUNT_SECTIONS:
        paths = value.get(section, [])
        if not isinstance(paths, list) or not all(
                isinstance(p, str) and p.startswith("/") for p in paths):
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "mounts.%s must be a list of absolute paths" % (section,))
        out[section] = sorted(set(paths))
    unknown = sorted(set(value) - set(MOUNT_SECTIONS))
    if unknown:
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "unknown mounts sections: %s" % (", ".join(unknown),))
    return out


def _validate_syscalls(value):
    value = _require_dict(value, "syscalls")
    default = value.get("default")
    if default not in DEFAULT_ACTIONS:
        raise SandboxPolicyInvalid(
            "sandbox-policy-no-default",
            "syscalls.default must be one of %s, got %r"
            % (", ".join(DEFAULT_ACTIONS), default))
    for key in ("allow", "deny"):
        names = value.get(key, [])
        if not isinstance(names, list) or not all(
                isinstance(n, str) and _SYSCALL_RE.match(n) for n in names):
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "syscalls.%s must be a list of syscall names" % (key,))
    rules = value.get("rules", [])
    if not isinstance(rules, list) or not all(
            isinstance(r, str) for r in rules):
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "syscalls.rules must be a list of rule strings")
    rule_default, rule_allows, rule_denies = _parse_syscall_rules(rules)
    if rule_default != default:
        raise SandboxPolicyInvalid(
            "sandbox-policy-invalid",
            "syscalls.default %r disagrees with the rule DEFAULT %r: "
            "declare it once" % (default, rule_default))
    return {
        "default": default,
        "allow": sorted(set(value.get("allow", []))),
        "deny": sorted(set(value.get("deny", []))),
        "rules": list(rules),
        "_rule_allows": {k: v for k, v in rule_allows.items()},
        "_rule_denies": sorted(rule_denies),
    }


class CompiledPolicy:
    """A validated, normalized, digest-pinned sandbox policy.

    ``decide(syscall, args)`` is the compiled deterministic decision
    function: "allow", "deny", or "kill". ``digest`` is the sha256 over
    the canonical normalized document -- the identity the pin store
    and the audit log use.
    """

    def __init__(self, doc):
        _require_dict(doc, "policy")
        if doc.get("policy_schema_version") != SCHEMA_VERSION:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "policy_schema_version must be %d, got %r"
                % (SCHEMA_VERSION, doc.get("policy_schema_version")))
        policy_id = doc.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "policy_id must be a non-empty string")
        unknown = sorted(set(doc) - {"policy_schema_version", "policy_id",
                                     "namespaces", "rlimits", "budgets",
                                     "mounts", "syscalls"})
        if unknown:
            raise SandboxPolicyInvalid(
                "sandbox-policy-invalid",
                "unknown policy sections: %s" % (", ".join(unknown),))
        self.policy_id = policy_id
        self.namespaces = _validate_namespaces(doc.get("namespaces", {}))
        self.rlimits = _validate_int_map(doc.get("rlimits", {}), RLIMITS,
                                         "rlimits")
        self.budgets = _validate_int_map(doc.get("budgets", {}), BUDGETS,
                                         "budgets")
        self.mounts = _validate_mounts(doc.get("mounts", {}))
        syscalls = _validate_syscalls(doc.get("syscalls", {}))
        self.default = syscalls["default"]
        self.allow = syscalls["allow"]
        self.deny = syscalls["deny"]
        self.rules = syscalls["rules"]
        self._rule_allows = syscalls["_rule_allows"]
        self._rule_denies = set(syscalls["_rule_denies"])
        self.digest = _digest_of(self._normalized())

    def _normalized(self):
        return {
            "policy_schema_version": SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "namespaces": self.namespaces,
            "rlimits": self.rlimits,
            "budgets": self.budgets,
            "mounts": self.mounts,
            "syscalls": {
                "default": self.default,
                "allow": self.allow,
                "deny": self.deny,
                "rules": self.rules,
            },
        }

    def decide(self, syscall, args):
        """Deterministic decision: "allow", "deny", or "kill".

        Precedence: DENY (document list or rule) always kills, even a
        syscall also on an allow list; then rule ALLOW filters (all must
        hold); then the document-level allow list; then DEFAULT.

        This is the PURE decision function -- it does not audit. The
        enforcement entry point is :class:`PolicyBinding` (returned by
        :func:`bind`), whose ``decide`` audits every decision. Callers
        must not enforce with ``CompiledPolicy.decide`` directly.

        Process-supervision level only -- see the module docstring for
        the honest boundary vs kernel seccomp-bpf.
        """
        if not isinstance(syscall, str) or not _SYSCALL_RE.match(syscall):
            return "kill"
        if syscall in self.deny or syscall in self._rule_denies:
            return "kill"
        filters = self._rule_allows.get(syscall)
        if filters is not None:
            if not filters:
                return "allow"
            args = args if isinstance(args, dict) else {}
            try:
                if all(_eval_filter(f, args) for f in filters):
                    return "allow"
            except _FilterFailClosed:
                pass
            return "kill"
        if syscall in self.allow:
            return "allow"
        return self.default

    def __repr__(self):  # pragma: no cover - debugging aid
        return "CompiledPolicy(%r, digest=%s...)" % (
            self.policy_id, self.digest[:12])


def compile_policy(doc):
    """Validate and compile a policy document. Raises
    ``SandboxPolicyInvalid`` (fail-closed) on anything malformed."""
    return CompiledPolicy(doc)


# ---------------------------------------------------------------------------
# Policy diff (names the changed field paths)
# ---------------------------------------------------------------------------

def _flatten(prefix, obj, out):
    if isinstance(obj, dict):
        for key in sorted(obj):
            if key.startswith("_"):
                continue
            _flatten(prefix + "." + key if prefix else key, obj[key], out)
    elif isinstance(obj, (list, tuple)):
        out[prefix] = list(obj)
    else:
        out[prefix] = obj


def policy_diff(a, b):
    """Field paths that differ between two compiled policies.

    Returns a sorted list like ``["namespaces.net",
    "syscalls.allow"]``. Any non-empty diff is a drift at use time
    (``sandbox-policy-drift``) -- subset/superset changes refuse just as
    loudly as unrelated ones: a "narrower" policy is still a different
    policy.
    """
    if not isinstance(a, CompiledPolicy) or not isinstance(b, CompiledPolicy):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "policy_diff takes two CompiledPolicy values")
    fa, fb = {}, {}
    _flatten("", a._normalized(), fa)
    _flatten("", b._normalized(), fb)
    return sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))


# ---------------------------------------------------------------------------
# Pin store (atomic JSON, like the osquery-pack precedent)
# ---------------------------------------------------------------------------

def pin_policy(policy_id, digest, path):
    """Commit a policy pin: policy_id -> digest. Atomic write; loud on
    any I/O or JSON failure."""
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "policy_id must be a non-empty string")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}",
                                                       digest):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "digest must be a 64-hex sha256")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            pins = json.load(handle)
    except FileNotFoundError:
        pins = {}
    except (OSError, ValueError) as exc:
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin store unreadable: %s" % (exc,)) from exc
    if not isinstance(pins, dict):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin store is not a dict")
    pins[policy_id] = digest
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(pins, handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin store write failed: %s" % (exc,)) from exc
    return digest


def load_pins(path):
    """Load the committed pin table. A missing file is an empty table
    (fresh install); anything unreadable refuses LOUD."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            pins = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin store unreadable: %s" % (exc,)) from exc
    if not isinstance(pins, dict):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin store is not a dict")
    return dict(pins)


def check_policy_use(policy, pins):
    """Use-time gate: the policy's digest must equal its committed pin.

    Returns the digest. Raises ``SandboxPolicyRefused`` with
    ``sandbox-policy-unpinned`` (no pin) or ``sandbox-policy-drift``
    (digest mismatch, however small the diff). A sandbox never runs
    under a policy that fails this gate.
    """
    if not isinstance(policy, CompiledPolicy):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "check_policy_use takes a CompiledPolicy")
    if not isinstance(pins, dict):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pins must be a dict")
    pinned = pins.get(policy.policy_id)
    if pinned is None:
        raise SandboxPolicyRefused(
            "sandbox-policy-unpinned",
            "policy %r has no committed pin: refusing to run under an "
            "unpinned policy" % (policy.policy_id,))
    if not isinstance(pinned, str):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "pin for %r is not a digest string" % (policy.policy_id,))
    if pinned != policy.digest:
        raise SandboxPolicyRefused(
            "sandbox-policy-drift",
            "policy %r drifted from its pin (live %s..., pinned %s...): "
            "refusing to run under a changed policy"
            % (policy.policy_id, policy.digest[:12], pinned[:12]))
    return policy.digest


# ---------------------------------------------------------------------------
# Audit (digests-only events, like the inventory-query precedent)
# ---------------------------------------------------------------------------

_emit = None
_emit_loud_done = False


def set_emit(sink):
    """Install (or clear, with None) the audit-event sink. A dead sink
    never breaks a run: emit failures are swallowed after one loud
    stderr line (the first failure of the process), so a broken audit
    pipeline cannot silently degrade into silent.
    """
    global _emit
    _emit = sink


def audit_decision(policy_digest, syscall, decision, code=None):
    """Emit one digest-bound decision event. The policy travels by
    digest only; the syscall name is audit content (not a credential).
    Kill decisions carry ``code="sandbox-policy-kill"`` so the event is
    a taxonomy decision-code event, not just a dict.
    """
    if _emit is None:
        return
    event = {
        "record_type": DECISION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "policy_digest": policy_digest,
        "syscall": str(syscall),
        "decision": decision,
    }
    if code is not None:
        event["code"] = code
    try:
        _emit(event)
    except Exception as exc:  # noqa: BLE001 -- audit never breaks execution
        global _emit_loud_done
        if not _emit_loud_done:
            _emit_loud_done = True
            sys.stderr.write(
                "sandbox-policy: audit sink failed (suppressing further "
                "warnings): %r\n" % (exc,))


# ---------------------------------------------------------------------------
# Binding: policy x pin x host enforcement
# ---------------------------------------------------------------------------

class PolicyBinding:
    """A compiled policy checked against its pin and against the
    isolation the executor/host can actually enforce.

    ``decide(syscall, args)`` applies the compiled decision function
    and audits every decision (the audit event is the per-execution
    evidence the policy was enforced as declared).
    """

    def __init__(self, policy, enforced_namespaces):
        self._policy = policy
        self._enforced = frozenset(enforced_namespaces)

    @property
    def policy(self):
        return self._policy

    @property
    def digest(self):
        return self._policy.digest

    def decide(self, syscall, args):
        decision = self._policy.decide(syscall, args)
        audit_decision(self._policy.digest, syscall, decision,
                       code="sandbox-policy-kill"
                       if decision == "kill" else None)
        return decision


def bind(policy, pins, *, enforced_namespaces):
    """Check a policy for use: pin gate, then host-enforcement gate.

    ``enforced_namespaces`` is the set of namespaces the executor/host
    actually enforces for this run (e.g. from per-call ground-truth
    reporting, the wave-280 honest-isolation-reporting precedent). Every
    namespace the policy declares required must be enforced; otherwise
    the run is refused with ``sandbox-policy-host-mismatch`` -- never
    run degraded under a stronger declaration. Returns a
    :class:`PolicyBinding`.
    """
    digest = check_policy_use(policy, pins)
    if not isinstance(enforced_namespaces, (set, frozenset, list, tuple)):
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "enforced_namespaces must be a collection")
    enforced = set(enforced_namespaces)
    unknown = sorted(set(enforced) - set(NAMESPACES))
    if unknown:
        raise SandboxPolicyError(
            "sandbox-policy-invalid",
            "unknown enforced namespaces: %s" % (", ".join(unknown),))
    required = sorted(n for n, want in policy.namespaces.items() if want)
    missing = [n for n in required if n not in enforced]
    if missing:
        raise SandboxPolicyRefused(
            "sandbox-policy-host-mismatch",
            "policy %r requires namespaces the host cannot enforce: %s "
            "-- refusing to run degraded (declare weaker or fix the host)"
            % (policy.policy_id, ", ".join(missing)))
    return PolicyBinding(policy, enforced)


# ---------------------------------------------------------------------------
# Composition with gov/sandbox.py (the executor side)
# ---------------------------------------------------------------------------
#
# This module is the policy LAYER, not a second executor: it never
# spawns processes. The deployment wires it into gov/sandbox.py like
# this (one call per tool execution, no sandbox.py edits required)::
#
#     from gov import sandbox, sandbox_policy
#
#     policy = sandbox_policy.compile_policy(POLICY_DOC)   # fail-closed
#     pins = sandbox_policy.load_pins(PIN_PATH)             # committed pins
#     sb = sandbox.Sandbox(require_pidns=True, require_netns=True)
#     result = sb.run(argv, ...)                            # SandboxResult
#     enforced = sandbox_policy.enforced_from_sandbox_result(result)
#     binding = sandbox_policy.bind(policy, pins,
#                                    enforced_namespaces=enforced)
#     # ... binding.decide(syscall, args) for each supervised call,
#     # audited per decision.
#
# ``enforced_from_sandbox_result`` reads the per-call ground-truth
# isolation flags (the wave-280 honest-isolation-reporting precedent):
# only namespaces the executor PROVED it established count as
# enforced. A declared-but-unenforced namespace refuses LOUD in
# ``bind`` (``sandbox-policy-host-mismatch``) -- the wave-176/177
# EPERM lesson as code.

def enforced_from_sandbox_result(result):
    """Build the enforced-namespaces set from a ``gov.sandbox``
    ``SandboxResult`` (duck-typed: any object with ``network_isolated``
    / ``pid_isolated`` attributes works, so tests need no root).

    Only PROVEN isolation counts: a namespace the executor could not
    establish is absent from the set, and ``bind`` will refuse any
    policy that declares it required.
    """
    enforced = set()
    if getattr(result, "network_isolated", False) is True:
        enforced.add("net")
    if getattr(result, "pid_isolated", False) is True:
        enforced.add("pid")
    return enforced


def bind_result(policy, pins, result):
    """``bind`` against the isolation a ``gov.sandbox.SandboxResult``
    actually established. One call: pin gate, host-enforcement gate,
    audited :class:`PolicyBinding`."""
    return bind(policy, pins,
                enforced_namespaces=enforced_from_sandbox_result(result))
