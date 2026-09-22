"""Verdict-parity suite for gov/policy_export.py (D3, A14).

For each scenario: build our PolicyEngine from a YAML policy, compute the
engine's verdict (role gate + evaluate), translate the policy with
gov/policy_export.py, and evaluate the *emitted text* with an in-repo
reference authorizer that implements Cedar semantics (forbid-wins,
default-deny) plus the documented Dogwood subset (``when temporal``,
``formerly within``, ``count_within``, ``exists`` bindings). The
reference parses the actual emitted text — the artifact the D2 benchmark
will consume — not the translator's internals.

Honest scope: the reference evaluator validates *translation
correctness* (the mapping), not the real Dogwood interpreter. Running
the export under real Dogwood is the D2 validation loop (future wave).

Adversarial mutation checks at the bottom prove the suite FAILS when the
exporter regresses: dropped stateful keys, swallowed require_approval,
dropped deny rules, narrowed min_sends.
"""

import re
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from gov.policy import PolicyEngine
from gov import policy_export
from gov.policy_export import (
    PolicyExportError,
    translate,
    translate_for_cedar,
    translate_for_dogwood,
)


# ---------------------------------------------------------------------------
# Reference evaluator for the emitted Cedar/Dogwood subset
# ---------------------------------------------------------------------------

class _Missing:
    pass


MISSING = _Missing()

_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<num>\d+)
  | (?P<op>\|\||&&|==|!=|>=|<=|>|<|!)
  | (?P<punct>[(){}.,:])
  | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)


def _unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class _WhenParser:
    """Recursive-descent parser for the emitted ``when`` expressions."""

    def __init__(self, text):
        self.toks = [(m.lastgroup, m.group(0))
                     for m in _TOKEN_RE.finditer(text)
                     if m.lastgroup != "ws"]
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def next(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, kind, value=None):
        k, v = self.next()
        if k != kind or (value is not None and v != value):
            raise ValueError("expected %s %r, got %s %r" % (kind, value, k, v))
        return v

    def parse(self):
        node = self.parse_or()
        if self.peek() != (None, None):
            raise ValueError("trailing tokens in when-expr")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() == ("op", "||"):
            self.next()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_unary()
        while self.peek() == ("op", "&&"):
            self.next()
            node = ("and", node, self.parse_unary())
        return node

    def parse_unary(self):
        if self.peek() == ("op", "!"):
            self.next()
            return ("not", self.parse_unary())
        if self.peek() == ("punct", "("):
            self.next()
            node = self.parse_or()
            self.expect("punct", ")")
            return node
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_operand()
        if self.peek()[0] == "op" and self.peek()[1] in (
                "==", "!=", ">=", "<=", ">", "<"):
            op = self.next()[1]
            right = self.parse_operand()
            return ("cmp", op, left, right)
        return left

    def _entity_ref(self):
        """Parse ``A::B::"name"``; returns the trailing string."""
        parts = [self.expect("word")]
        while self.peek() == ("punct", ":"):
            self.next()
            self.expect("punct", ":")
            k, v = self.next()
            if k == "word":
                parts.append(v)
            elif k == "string":
                return _unescape(v[1:-1])
            else:
                raise ValueError("bad entity ref")
        raise ValueError("entity ref needs a trailing string")

    def parse_operand(self):
        k, v = self.next()
        if k == "string":
            return ("lit", _unescape(v[1:-1]))
        if k == "num":
            return ("lit", int(v))
        if k == "word" and v in ("true", "false"):
            return ("lit", v == "true")
        if k == "word" and v == "context":
            parts = []
            while self.peek() == ("punct", "."):
                self.next()
                w = self.expect("word")
                if w == "contains":
                    self.expect("punct", "(")
                    kk, vv = self.next()
                    if kk != "string":
                        raise ValueError("contains needs a string")
                    self.expect("punct", ")")
                    return ("contains", parts, _unescape(vv[1:-1]))
                parts.append(w)
            return ("path", parts)
        if k == "word" and v == "principal":
            self.expect("punct", ".")
            return ("pattr", self.expect("word"))
        if k == "word" and v == "action":
            op = self.expect("op")
            if op != "==":
                raise ValueError("action only supports ==")
            return ("actioneq", self._entity_ref())
        raise ValueError("unexpected operand %s %r" % (k, v))


def _resolve_path(parts, ctx):
    cur = ctx
    for part in parts:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return MISSING
    return cur


def _eval(node, ctx):
    """Kleene-ish eval: MISSING (unresolvable attribute) propagates, but
    ``False && MISSING`` is False and ``True || MISSING`` is True — the
    same observable outcome as the engine's per-condition evaluation."""
    tag = node[0]
    if tag == "lit":
        return node[1]
    if tag == "path":
        v = _resolve_path(node[1], ctx["context"])
        return MISSING if v is MISSING else v
    if tag == "pattr":
        v = ctx["principal"].get(node[1], MISSING)
        return v
    if tag == "actioneq":
        return ctx["action"] == node[1]
    if tag == "contains":
        obj = _resolve_path(node[1], ctx["context"])
        if obj is MISSING:
            return MISSING
        return node[2] in str(obj)
    if tag == "not":
        v = _eval(node[1], ctx)
        return MISSING if v is MISSING else (not v)
    if tag == "and":
        a = _eval(node[1], ctx)
        b = _eval(node[2], ctx)
        if a is False or b is False:
            return False
        if a is MISSING or b is MISSING:
            return MISSING
        return True
    if tag == "or":
        a = _eval(node[1], ctx)
        b = _eval(node[2], ctx)
        if a is True or b is True:
            return True
        if a is MISSING or b is MISSING:
            return MISSING
        return False
    if tag == "cmp":
        _, op, l, r = node
        lv = _eval(l, ctx)
        rv = _eval(r, ctx)
        if lv is MISSING or rv is MISSING:
            return MISSING
        try:
            if op == "==":
                return lv == rv
            if op == "!=":
                return lv != rv
            if op == ">=":
                return lv >= rv
            if op == "<=":
                return lv <= rv
            if op == ">":
                return lv > rv
            if op == "<":
                return lv < rv
        except TypeError:
            return MISSING
    raise ValueError("bad node %r" % (node,))


# --- temporal expressions ---

_FORMERLY_RE = re.compile(r"""
    ^(?P<neg>!\(\s*)?
    formerly\ within\ (?P<num>\d+)(?P<unit>[hm])\s+
    AgentCore::Action::"(?P<action>[^"]+)"::(?P<kind>request|response)
    \{(?P<fields>[^}]*)\}
    \s*(?P<closeparen>\)?)$$""", re.VERBOSE)

_COUNT_RE = re.compile(
    r'^\(count_within\((?P<num>\d+)(?P<unit>[hm]),\s*'
    r'AgentCore::Action::"(?P<action>[^"]+)"::request\{\s*_\s*\}\)\)'
    r'\s*==\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)$')

_CHECK_RE = re.compile(
    r'^([A-Za-z_][A-Za-z0-9_]*(?:\s*\+\s*[A-Za-z_][A-Za-z0-9_]*)*)'
    r'\s*(>=|<=|>|<|==|!=)\s*(\d+)$')

_EXISTS_RE = re.compile(r'^exists\s*\(([A-Za-z_][A-Za-z0-9_]*):\s*Long\)\.\s*')


def _dur_secs(num, unit):
    return int(num) * (3600 if unit == "h" else 60)


def _split_top(text, sep):
    parts, depth, cur = [], 0, []
    i = 0
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if depth == 0 and text.startswith(sep, i):
            parts.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _strip_outer_parens(text):
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        wraps = True
        for i, c in enumerate(text):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            if depth == 0 and i < len(text) - 1:
                wraps = False  # first paren closes before the end
                break
        if not wraps:
            break
        text = text[1:-1].strip()
    return text


def _parse_field_value(raw, ctx):
    raw = raw.strip()
    if raw == "_":
        return ("wildcard", None)
    if raw.startswith("context.input."):
        field = raw[len("context.input."):]
        val = ctx["context"].get("input", {}).get(field, MISSING)
        return ("corr", val)
    if raw.startswith('"') and raw.endswith('"'):
        return ("lit", _unescape(raw[1:-1]))
    if raw in ("true", "false"):
        return ("lit", raw == "true")
    if re.fullmatch(r"\d+", raw):
        return ("lit", int(raw))
    raise ValueError("bad temporal field value %r" % raw)


def _eval_formerly(m, ctx, events):
    window = _dur_secs(m.group("num"), m.group("unit"))
    action, kind = m.group("action"), m.group("kind")
    fields = {}
    for chunk in _split_top(m.group("fields"), ","):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, value = chunk.partition(":")
        fields[name.strip()] = _parse_field_value(value, ctx)
    hit = False
    for ev in events:
        if ev["action"] != action or ev["kind"] != kind:
            continue
        if ev.get("age", 0) > window:
            continue
        ok = True
        for name, (fkind, fval) in fields.items():
            if fkind == "wildcard":
                continue
            if fkind == "corr" and fval is MISSING:
                ok = False
                break
            ev_val = ev.get("fields", {}).get(name, MISSING)
            if ev_val is MISSING or ev_val != fval:
                ok = False
                break
        if ok:
            hit = True
            break
    if m.group("neg"):
        return not hit
    return hit


def _eval_counts(body, ctx, events):
    counts = {}
    checks = []
    for part in _split_top(body, "&&"):
        part = part.strip()
        mc = _COUNT_RE.match(part)
        if mc:
            window = _dur_secs(mc.group("num"), mc.group("unit"))
            n = sum(1 for ev in events
                    if ev["action"] == mc.group("action")
                    and ev["kind"] == "request"
                    and ev.get("age", 0) <= window)
            counts[mc.group("var")] = n
            continue
        mh = _CHECK_RE.match(part)
        if mh:
            checks.append((mh.group(1), mh.group(2), int(mh.group(3))))
            continue
        raise ValueError("bad count block part %r" % part)
    for expr, op, num in checks:
        total = sum(counts[v.strip()] for v in expr.split("+"))
        if op == ">=" and not (total >= num):
            return False
        if op == "<=" and not (total <= num):
            return False
        if op == ">" and not (total > num):
            return False
        if op == "<" and not (total < num):
            return False
        if op == "==" and not (total == num):
            return False
        if op == "!=" and not (total != num):
            return False
    return True


def _eval_temporal(text, ctx, events):
    text = text.strip()
    if text.startswith("exists"):
        rest = text
        while True:
            m = _EXISTS_RE.match(rest)
            if not m:
                break
            rest = rest[m.end():]
        return _eval_counts(_strip_outer_parens(rest), ctx, events)
    m = _FORMERLY_RE.match(text)
    if m:
        return _eval_formerly(m, ctx, events)
    raise ValueError("bad temporal conjunct %r" % text)


# --- policy text parsing ---

def _extract_balanced(text, start):
    """Extract the bracketed region starting at text[start] (open char)."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    open_c = text[start]
    close_c = pairs[open_c]
    depth = 0
    for i in range(start, len(text)):
        if text[i] == open_c:
            depth += 1
        elif text[i] == close_c:
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
    raise ValueError("unbalanced brackets")


def _parse_exported(text):
    """Parse emitted Cedar/Dogwood text into policy dicts."""
    lines = [ln for ln in text.splitlines()
             if not ln.lstrip().startswith("//")]
    body = "\n".join(lines)
    policies = []
    for chunk in body.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"(permit|forbid)\s*\(", chunk)
        if not m:
            raise ValueError("bad policy chunk %r" % chunk[:60])
        kind = m.group(1)
        scope, pos = _extract_balanced(chunk, m.end() - 1)
        scope_action = None
        sm = re.search(r'action\s*==\s*AgentCore::Action::"([^"]+)"', scope)
        if sm:
            scope_action = sm.group(1)
        rest = chunk[pos:]
        whens, temporals = [], []
        mt = re.search(r"when\s+temporal\s*\{", rest)
        if mt:
            tblock, tend = _extract_balanced(rest, mt.end() - 1)
            rest = rest[:mt.start()] + rest[tend:]
            for conj in _split_top(tblock, "&&"):
                conj = conj.strip()
                if conj:
                    temporals.append(conj)
        mw = re.search(r"when\s*\{", rest)
        if mw:
            wblock, _ = _extract_balanced(rest, mw.end() - 1)
            whens.append(_WhenParser(wblock).parse())
        policies.append({"kind": kind, "scope_action": scope_action,
                         "whens": whens, "temporals": temporals})
    return policies


class ReferenceAuthorizer:
    """Cedar semantics over the emitted subset: forbid-wins, default-deny.

    A policy whose ``when`` errors (missing attribute) does not apply —
    matching the engine, where a missing path makes the condition False.
    """

    def __init__(self, text):
        self.policies = _parse_exported(text)

    def decide(self, principal, action_tool, context, events):
        ctx = {"principal": principal, "action": action_tool,
               "context": context}
        permitted = False
        for p in self.policies:
            if p["scope_action"] is not None \
                    and p["scope_action"] != action_tool:
                continue
            applies = True
            for w in p["whens"]:
                if _eval(w, ctx) is not True:
                    applies = False
                    break
            if not applies:
                continue
            for t in p["temporals"]:
                if not _eval_temporal(t, ctx, events):
                    applies = False
                    break
            if not applies:
                continue
            if p["kind"] == "forbid":
                return "deny"
            permitted = True
        return "allow" if permitted else "deny"


# ---------------------------------------------------------------------------
# Scenario harness
# ---------------------------------------------------------------------------

def _write_policy(yaml_text):
    tmpdir = tempfile.mkdtemp(prefix="gov-parity-")
    path = Path(tmpdir) / "policy.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return str(path)


def _counter_events(counters):
    """Engine per-run counters -> synthetic Dogwood trajectory request events."""
    events = []
    for tool, n in (counters or {}).items():
        for _ in range(int(n)):
            events.append({"action": tool, "kind": "request",
                           "age": 0, "fields": {}})
    return events


def _signal_events(signals):
    return [{"action": "LedgerSignal", "kind": "response", "age": 0,
             "fields": {"output.signal": s, "output.value": True}}
            for s in (signals or [])]


def check_parity(testcase, yaml_text, *, tool, role, agent_id="agent-1",
                 args=None, context=None, expect=None, format="auto",
                 counters=None, ledger_signals=(), extra_events=()):
    """Core parity assertion: exported verdict == engine verdict.

    The engine verdict includes the executor's pre-evaluation role gate
    (role_allows), which the export encodes as forbid policies.
    """
    args = args or {}
    context = dict(context or {})
    path = _write_policy(yaml_text)
    try:
        engine = PolicyEngine(path)
        action = {"tool": tool, "role": role, "agent_id": agent_id,
                  "args": dict(args)}
        eng_ctx = dict(context)
        if counters is not None:
            eng_ctx["counters"] = dict(counters)
        if engine.role_allows(role, tool):
            engine_verdict = engine.evaluate(action, eng_ctx).effect
        else:
            # Executor rejects before policy evaluation.
            engine_verdict = "deny"
        if expect is not None:
            testcase.assertEqual(
                engine_verdict, expect,
                "engine verdict != expected (scenario may be vacuous)")

        exported = translate(path, format=format)
        auth = ReferenceAuthorizer(exported)

        ref_ctx = dict(context)
        ref_ctx.setdefault("path", str(args.get("path", "")))
        ref_ctx["counters"] = dict(counters or {})
        ref_ctx["input"] = {
            "path": str(args.get("path", "")),
            "domain": str(args.get("domain", "")),
            "role": role,
            "agent": agent_id,
        }
        events = (_counter_events(counters) + _signal_events(ledger_signals)
                  + list(extra_events))
        principal = {"role": role, "agent": agent_id}
        ref_verdict = auth.decide(principal, tool, ref_ctx, events)
        testcase.assertEqual(
            ref_verdict, engine_verdict,
            "PARITY MISMATCH: engine=%s exported=%s\npolicy:\n%s"
            % (engine_verdict, ref_verdict, yaml_text))
        return exported
    finally:
        try:
            Path(path).unlink()
            Path(path).parent.rmdir()
        except OSError:
            pass


def check_bridge_parity(testcase, yaml_text, *, tool, role, agent_id="agent-1",
                        args=None, context=None):
    """Parity for bridged require_approval: engine says require_approval;
    the export must be a *conditional* temporal permit — allow with a
    fresh matching approval event, deny without/expired/denied/mismatched.
    """
    args = args or {}
    context = dict(context or {})
    path = _write_policy(yaml_text)
    try:
        engine = PolicyEngine(path)
        action = {"tool": tool, "role": role, "agent_id": agent_id,
                  "args": dict(args)}
        testcase.assertTrue(engine.role_allows(role, tool))
        engine_verdict = engine.evaluate(action, dict(context)).effect
        testcase.assertEqual(engine_verdict, "require_approval")

        exported = translate(path, format="auto")
        testcase.assertIn("when temporal", exported)
        testcase.assertIn("output.approved: true", exported)
        auth = ReferenceAuthorizer(exported)

        def ref(events):
            ref_ctx = dict(context)
            ref_ctx.setdefault("path", str(args.get("path", "")))
            ref_ctx["counters"] = {}
            ref_ctx["input"] = {
                "path": str(args.get("path", "")),
                "domain": str(args.get("domain", "")),
                "role": role,
                "agent": agent_id,
            }
            return auth.decide({"role": role, "agent": agent_id},
                               tool, ref_ctx, list(events))

        def approval_ev(age, approved, fields):
            return {"action": "ApproveWrite", "kind": "response",
                    "age": age,
                    "fields": {"output.approved": approved, **fields}}

        base_fields = {"input.path": str(args.get("path", ""))}
        # With a fresh, matching, approved event -> permit.
        testcase.assertEqual(
            ref([approval_ev(120, True, base_fields)]), "allow",
            "bridged permit must fire with a fresh approval event")
        # Without any event -> default deny (never an unconditional permit).
        testcase.assertEqual(ref([]), "deny",
                             "bridged permit must NOT fire without an event")
        # Expired event -> deny.
        testcase.assertEqual(ref([approval_ev(3600, True, base_fields)]),
                             "deny", "expired approval must not authorize")
        # Denied approval -> deny.
        testcase.assertEqual(ref([approval_ev(60, False, base_fields)]),
                             "deny", "approved:false must not authorize")
        # Match-field mismatch -> deny.
        testcase.assertEqual(
            ref([approval_ev(60, True, {"input.path": "/other/path"})]),
            "deny", "match-field mismatch must not authorize")
        return exported
    finally:
        try:
            Path(path).unlink()
            Path(path).parent.rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Scenario policies
# ---------------------------------------------------------------------------

P_BASIC = """\
version: 2
roles:
  coder: [read_file, write_file, delete_file, api_call]
  support: [read_file, send_email]
policies:
  - id: deny-secret-reads
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret, .env]
    reason: no secret reads
  - id: deny-delete-outside
    effect: deny
    match:
      tool: [delete_file]
      path_outside_sandbox: true
  - id: deny-unallowlisted-egress
    effect: deny
    match:
      tool: [send_email, http_post]
      domain_allowlisted: false
  - id: allow-sandbox-writes
    effect: allow
    match:
      tool: [write_file]
      path_outside_sandbox: false
  - id: allow-coder-api
    effect: allow
    match:
      tool: [api_call]
      role: [coder]
  - id: allow-reads
    effect: allow
    match:
      tool: [read_file]
"""

P_WHEN = """\
version: 2
roles:
  coder: [api_call]
policies:
  - id: deny-gte
    effect: deny
    match:
      tool: [api_call]
      when:
        - path: counters.api_call
          gte: 5
  - id: deny-lt
    effect: deny
    match:
      tool: [api_call]
      when:
        - path: counters.api_call
          lt: 2
  - id: deny-eq-str
    effect: deny
    match:
      tool: [api_call]
      when:
        - path: flags.tier
          eq: "free"
  - id: deny-neq-bool
    effect: deny
    match:
      tool: [api_call]
      when:
        - path: flags.vetted
          neq: true
  - id: allow-api
    effect: allow
    match:
      tool: [api_call]
"""

P_AGENT_ROLE = """\
version: 2
roles:
  coder: [read_file, write_file]
  support: [read_file]
policies:
  - id: allow-agent1-write
    effect: allow
    match:
      tool: [write_file]
      agent: [agent-1]
  - id: allow-support-read
    effect: allow
    match:
      tool: [read_file]
      role: [support, coder]
"""

P_STATEFUL = """\
version: 2
roles:
  publisher: [send_email, http_post]
  coder: [api_call, write_file, delete_file]
policies:
  - id: deny-many-sends
    effect: deny
    match:
      tool: [send_email, http_post]
      min_sends: 3
  - id: deny-many-writes
    effect: deny
    match:
      tool: [write_file]
      min_writes: 2
  - id: deny-many-deletes
    effect: deny
    match:
      tool: [delete_file]
      min_deletes: 1
  - id: deny-bulk-api
    effect: deny
    match:
      tool: [api_call]
      min_external_calls: 5
  - id: allow-sends
    effect: allow
    match:
      tool: [send_email, http_post]
  - id: allow-writes
    effect: allow
    match:
      tool: [write_file]
  - id: allow-deletes
    effect: allow
    match:
      tool: [delete_file]
  - id: allow-api
    effect: allow
    match:
      tool: [api_call]
"""

P_LEDGER = """\
version: 2
roles:
  coder: [api_call]
policies:
  - id: deny-campaign
    effect: deny
    match:
      tool: [api_call]
      cross_run_campaign: true
  - id: deny-velocity
    effect: deny
    match:
      tool: [api_call]
      velocity_exceeded: true
  - id: allow-api
    effect: allow
    match:
      tool: [api_call]
"""

P_LEDGER_NEG = """\
version: 2
roles:
  coder: [api_call]
policies:
  - id: deny-when-no-campaign
    effect: deny
    match:
      tool: [api_call]
      cross_run_campaign: false
  - id: allow-api
    effect: allow
    match:
      tool: [api_call]
"""

P_BRIDGE = """\
version: 2
roles:
  coder: [write_file, read_file]
policies:
  - id: deny-write-outside-dlp
    effect: deny
    match:
      tool: [write_file]
      path_outside_sandbox: true
      when:
        - path: flags.dlp_hit
          eq: true
  - id: approve-outside-write
    effect: require_approval
    match:
      tool: [write_file]
      path_outside_sandbox: true
    bridge:
      approval_action: "ApproveWrite"
      ttl_seconds: 600
      match_fields: [path]
    reason: outside writes need a human
  - id: allow-inside-write
    effect: allow
    match:
      tool: [write_file]
      path_outside_sandbox: false
  - id: allow-reads
    effect: allow
    match:
      tool: [read_file]
"""

P_MIXED = """\
version: 2
roles:
  coder: [read_file, send_email]
policies:
  - id: deny-secret
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
  - id: deny-many-sends
    effect: deny
    match:
      tool: [send_email]
      min_sends: 2
  - id: allow-reads
    effect: allow
    match:
      tool: [read_file]
  - id: allow-sends
    effect: allow
    match:
      tool: [send_email]
"""

# F88: the engine's pass order lets require_approval shadow later allow
# rules. An exporter that forgets this emits an unconditional allow
# permit next to the gated temporal permit — silently weakening the
# approval gate. The forbid companion must suppress the allow.
P_BRIDGE_SHADOW = P_BRIDGE + """\
  - id: allow-all-writes
    effect: allow
    match:
      tool: [write_file]
"""


# ---------------------------------------------------------------------------
# A. Stateless deny/allow + role gating (Cedar)
# ---------------------------------------------------------------------------

class StatelessParityTests(unittest.TestCase):
    def test_secret_read_denied(self):
        check_parity(self, P_BASIC, tool="read_file", role="coder",
                     args={"path": "/run/secret.txt"}, expect="deny")

    def test_plain_read_allowed(self):
        check_parity(self, P_BASIC, tool="read_file", role="coder",
                     args={"path": "/run/notes.txt"}, expect="allow")

    def test_delete_outside_denied(self):
        check_parity(self, P_BASIC, tool="delete_file", role="coder",
                     args={"path": "/etc/x"},
                     context={"path_outside_sandbox": True}, expect="deny")

    def test_delete_inside_default_deny(self):
        # No allow rule covers delete_file: default-deny on both sides.
        check_parity(self, P_BASIC, tool="delete_file", role="coder",
                     args={"path": "/run/x"},
                     context={"path_outside_sandbox": False},
                     expect="deny")

    def test_unallowlisted_egress_denied(self):
        check_parity(self, P_BASIC, tool="send_email", role="support",
                     context={"domain_allowlisted": False}, expect="deny")

    def test_egress_no_allow_rule_default_deny(self):
        check_parity(self, P_BASIC, tool="send_email", role="support",
                     context={"domain_allowlisted": True}, expect="deny")

    def test_role_scoped_allow(self):
        check_parity(self, P_BASIC, tool="api_call", role="coder",
                     expect="allow")

    def test_role_allowlist_forbid(self):
        # support may not use api_call at all (executor role gate).
        check_parity(self, P_BASIC, tool="api_call", role="support",
                     expect="deny")

    def test_unknown_role_forbid(self):
        check_parity(self, P_BASIC, tool="read_file", role="intruder",
                     args={"path": "/run/notes.txt"}, expect="deny")

    def test_forbid_wins_over_permit(self):
        # Secret read inside sandbox matches deny-secret-reads AND
        # allow-reads: forbid wins, exactly like deny-first.
        check_parity(self, P_BASIC, tool="read_file", role="coder",
                     args={"path": "/run/.env"}, expect="deny")

    def test_sandbox_write_allowed(self):
        check_parity(self, P_BASIC, tool="write_file", role="coder",
                     args={"path": "/run/out.txt"},
                     context={"path_outside_sandbox": False},
                     expect="allow")

    def test_outside_write_default_deny(self):
        check_parity(self, P_BASIC, tool="write_file", role="coder",
                     args={"path": "/etc/out.txt"},
                     context={"path_outside_sandbox": True}, expect="deny")


# ---------------------------------------------------------------------------
# B. `when` comparisons
# ---------------------------------------------------------------------------

class WhenParityTests(unittest.TestCase):
    def test_gte_fires(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 5}, expect="deny")

    def test_gte_quiet(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 4}, expect="allow")

    def test_lt_fires(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 1}, expect="deny")

    def test_lt_quiet(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 2}, expect="allow")

    def test_eq_string_fires(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 3},
                     context={"flags": {"tier": "free"}}, expect="deny")

    def test_eq_string_quiet(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 3},
                     context={"flags": {"tier": "pro"}}, expect="allow")

    def test_neq_bool_fires(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 3},
                     context={"flags": {"vetted": False}}, expect="deny")

    def test_neq_bool_quiet(self):
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 3},
                     context={"flags": {"vetted": True}}, expect="allow")

    def test_missing_path_skips_rule(self):
        # Engine: missing path -> condition False -> rule skipped.
        # Export: missing attribute -> policy does not apply. Same verdict.
        check_parity(self, P_WHEN, tool="api_call", role="coder",
                     counters={"api_call": 3}, expect="allow")


# ---------------------------------------------------------------------------
# C. Agent + multi-role scoping
# ---------------------------------------------------------------------------

class AgentRoleParityTests(unittest.TestCase):
    def test_agent_scoped_allow(self):
        check_parity(self, P_AGENT_ROLE, tool="write_file", role="coder",
                     agent_id="agent-1", expect="allow")

    def test_other_agent_default_deny(self):
        check_parity(self, P_AGENT_ROLE, tool="write_file", role="coder",
                     agent_id="agent-2", expect="deny")

    def test_multi_role_allow(self):
        check_parity(self, P_AGENT_ROLE, tool="read_file", role="support",
                     agent_id="agent-9", expect="allow")

    def test_role_list_second_member(self):
        check_parity(self, P_AGENT_ROLE, tool="read_file", role="coder",
                     expect="allow")


# ---------------------------------------------------------------------------
# D. Stateful keys (Dogwood count_within)
# ---------------------------------------------------------------------------

class StatefulParityTests(unittest.TestCase):
    def test_plain_cedar_refuses_stateful(self):
        path = _write_policy(P_STATEFUL)
        try:
            with self.assertRaises(PolicyExportError):
                translate_for_cedar(path)
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_min_sends_below(self):
        check_parity(self, P_STATEFUL, tool="send_email", role="publisher",
                     counters={"send_email": 1, "http_post": 1},
                     expect="allow", format="dogwood")

    def test_min_sends_at_threshold(self):
        check_parity(self, P_STATEFUL, tool="send_email", role="publisher",
                     counters={"send_email": 3}, expect="deny",
                     format="dogwood")

    def test_min_sends_sums_both_tools(self):
        # Engine sums send_email + http_post; the export must too.
        check_parity(self, P_STATEFUL, tool="http_post", role="publisher",
                     counters={"send_email": 1, "http_post": 2},
                     expect="deny", format="dogwood")

    def test_min_sends_http_post_only(self):
        check_parity(self, P_STATEFUL, tool="http_post", role="publisher",
                     counters={"http_post": 5}, expect="deny",
                     format="dogwood")

    def test_min_writes_below(self):
        check_parity(self, P_STATEFUL, tool="write_file", role="coder",
                     counters={"write_file": 1}, expect="allow",
                     format="dogwood")

    def test_min_writes_at_threshold(self):
        check_parity(self, P_STATEFUL, tool="write_file", role="coder",
                     counters={"write_file": 2}, expect="deny",
                     format="dogwood")

    def test_min_deletes_zero(self):
        check_parity(self, P_STATEFUL, tool="delete_file", role="coder",
                     counters={"delete_file": 0}, expect="allow",
                     format="dogwood")

    def test_min_deletes_one(self):
        check_parity(self, P_STATEFUL, tool="delete_file", role="coder",
                     counters={"delete_file": 1}, expect="deny",
                     format="dogwood")

    def test_min_external_calls_below(self):
        check_parity(self, P_STATEFUL, tool="api_call", role="coder",
                     counters={"api_call": 4}, expect="allow",
                     format="dogwood")

    def test_min_external_calls_at_threshold(self):
        check_parity(self, P_STATEFUL, tool="api_call", role="coder",
                     counters={"api_call": 5}, expect="deny",
                     format="dogwood")


# ---------------------------------------------------------------------------
# E. Ledger signals (cross_run_campaign / velocity_exceeded)
# ---------------------------------------------------------------------------

class LedgerSignalParityTests(unittest.TestCase):
    def test_campaign_signal_denies(self):
        check_parity(self, P_LEDGER, tool="api_call", role="coder",
                     ledger_signals=["cross_run_campaign"],
                     context={"cross_run_campaign": True},
                     expect="deny", format="dogwood")

    def test_no_campaign_allows(self):
        check_parity(self, P_LEDGER, tool="api_call", role="coder",
                     context={"cross_run_campaign": False},
                     expect="allow", format="dogwood")

    def test_velocity_signal_denies(self):
        check_parity(self, P_LEDGER, tool="api_call", role="coder",
                     ledger_signals=["velocity_exceeded"],
                     context={"velocity_exceeded": True},
                     expect="deny", format="dogwood")

    def test_no_velocity_allows(self):
        check_parity(self, P_LEDGER, tool="api_call", role="coder",
                     context={"velocity_exceeded": False},
                     expect="allow", format="dogwood")

    def test_negated_signal_absent_denies(self):
        # cross_run_campaign: false matches when the signal is absent.
        check_parity(self, P_LEDGER_NEG, tool="api_call", role="coder",
                     context={"cross_run_campaign": False},
                     expect="deny", format="dogwood")

    def test_negated_signal_present_allows(self):
        check_parity(self, P_LEDGER_NEG, tool="api_call", role="coder",
                     ledger_signals=["cross_run_campaign"],
                     context={"cross_run_campaign": True},
                     expect="allow", format="dogwood")


# ---------------------------------------------------------------------------
# F. Bridged require_approval (Dogwood temporal permit)
# ---------------------------------------------------------------------------

class BridgeParityTests(unittest.TestCase):
    def test_bridged_approval_conditional(self):
        check_bridge_parity(
            self, P_BRIDGE, tool="write_file", role="coder",
            args={"path": "/etc/data.txt"},
            context={"path_outside_sandbox": True})

    def test_bridged_with_dlp_deny_still_forbids(self):
        # The deny rule also matches (dlp_hit) and an approval event is
        # present: forbid still wins — approvals can't override denies.
        path = _write_policy(P_BRIDGE)
        try:
            exported = translate(path, format="dogwood")
            auth = ReferenceAuthorizer(exported)
            ref_ctx = {"path_outside_sandbox": True,
                       "flags": {"dlp_hit": True},
                       "path": "/etc/data.txt", "counters": {},
                       "input": {"path": "/etc/data.txt", "domain": "",
                                 "role": "coder", "agent": "agent-1"}}
            events = [{"action": "ApproveWrite", "kind": "response",
                       "age": 60,
                       "fields": {"output.approved": True,
                                  "input.path": "/etc/data.txt"}}]
            self.assertEqual(
                auth.decide({"role": "coder", "agent": "agent-1"},
                            "write_file", ref_ctx, events), "deny")
            engine = PolicyEngine(path)
            action = {"tool": "write_file", "role": "coder",
                      "agent_id": "agent-1", "args": {"path": "/etc/x"}}
            self.assertEqual(
                engine.evaluate(action, {"path_outside_sandbox": True,
                                         "flags": {"dlp_hit": True}}).effect,
                "deny")
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_require_approval_without_bridge_refused(self):
        policy = """\
version: 2
roles:
  coder: [write_file]
policies:
  - id: needs-human
    effect: require_approval
    match:
      tool: [write_file]
"""
        path = _write_policy(policy)
        try:
            for fmt in ("auto", "cedar", "dogwood"):
                with self.assertRaises(PolicyExportError, msg=fmt):
                    translate(path, format=fmt)
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_bridge_validation_errors(self):
        bad_bridges = [
            "approval_action: ''",          # empty action name
            "ttl_seconds: 0",               # non-positive
            "ttl_seconds: 90",              # not a multiple of 60
            "ttl_seconds: '600'",           # wrong type
            "ttl_seconds: true",            # bool is not an int
            "match_fields: [nope]",         # unknown field
            "bogus_key: 1",                 # unknown key
        ]
        for i, bad in enumerate(bad_bridges):
            policy = ("version: 2\nroles:\n  coder: [write_file]\n"
                      "policies:\n  - id: r%d\n    effect: require_approval\n"
                      "    match:\n      tool: [write_file]\n"
                      "    bridge:\n      approval_action: \"ApproveWrite\"\n"
                      "      ttl_seconds: 600\n      %s\n" % (i, bad))
            path = _write_policy(policy)
            try:
                with self.assertRaises(PolicyExportError, msg=bad):
                    translate(path, format="dogwood")
            finally:
                Path(path).unlink()
                Path(path).parent.rmdir()

    def test_bridge_on_allow_rule_refused(self):
        policy = """\
version: 2
roles:
  coder: [read_file]
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
    bridge:
      approval_action: "ApproveWrite"
      ttl_seconds: 600
"""
        path = _write_policy(policy)
        try:
            with self.assertRaises(PolicyExportError):
                translate(path, format="dogwood")
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_f88_approval_shadowing_preserved(self):
        # F88 regression test: P_BRIDGE_SHADOW adds an UNCONDITIONAL
        # allow for write_file. An outside write with no approval event
        # must still be denied (forbid companion suppresses the allow);
        # with a fresh approval event it must be allowed.
        path = _write_policy(P_BRIDGE_SHADOW)
        try:
            engine = PolicyEngine(path)
            action = {"tool": "write_file", "role": "coder",
                      "agent_id": "agent-1", "args": {"path": "/etc/d"}}
            self.assertEqual(
                engine.evaluate(
                    action, {"path_outside_sandbox": True}).effect,
                "require_approval")
            exported = translate(path, format="dogwood")
            self.assertIn("forbid companion", exported)
            auth = ReferenceAuthorizer(exported)
            ref_ctx = {"path_outside_sandbox": True, "path": "/etc/d",
                       "counters": {},
                       "input": {"path": "/etc/d", "domain": "",
                                 "role": "coder", "agent": "agent-1"}}
            principal = {"role": "coder", "agent": "agent-1"}
            self.assertEqual(
                auth.decide(principal, "write_file", ref_ctx, []), "deny",
                "F88: unconditional allow must not shadow the approval gate")
            event = [{"action": "ApproveWrite", "kind": "response",
                      "age": 60,
                      "fields": {"output.approved": True,
                                 "input.path": "/etc/d"}}]
            self.assertEqual(
                auth.decide(principal, "write_file", ref_ctx, event),
                "allow")
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()


# ---------------------------------------------------------------------------
# G. Mixed stateless + stateful policy (whole-policy Dogwood)
# ---------------------------------------------------------------------------

class MixedParityTests(unittest.TestCase):
    def test_mixed_stateless_rule(self):
        exported = check_parity(
            self, P_MIXED, tool="read_file", role="coder",
            args={"path": "/run/secret.txt"}, expect="deny",
            format="dogwood")
        self.assertIn("when temporal", exported)

    def test_mixed_stateful_rule(self):
        check_parity(self, P_MIXED, tool="send_email", role="coder",
                     counters={"send_email": 2}, expect="deny",
                     format="dogwood")

    def test_mixed_stateful_quiet(self):
        check_parity(self, P_MIXED, tool="send_email", role="coder",
                     counters={"send_email": 1}, expect="allow",
                     format="dogwood")

    def test_default_policy_cedar_refused(self):
        from gov.policy import default_policy_path
        with self.assertRaises(PolicyExportError):
            translate_for_cedar(str(default_policy_path()))

    def test_default_policy_dogwood_refused_bridgeless_approval(self):
        # policies/default.yaml has require_approval rules WITHOUT bridge:
        # bindings. The honest export refuses instead of silently
        # permitting them.
        from gov.policy import default_policy_path
        with self.assertRaises(PolicyExportError) as cm:
            translate_for_dogwood(str(default_policy_path()))
        self.assertIn("require_approval", str(cm.exception))


# ---------------------------------------------------------------------------
# H. Adversarial mutation checks
#
# Each test simulates a regressed ("weakened") exporter and asserts the
# parity suite FAILS against it. If any of these stops failing, the
# suite has lost its ability to catch that regression class.
# ---------------------------------------------------------------------------

def _strip_companions(text):
    """Mutant: remove every forbid-companion policy (the F88 regression:
    bridged require_approval without its "deny until approval" forbid).
    """
    kept = []
    for chunk in text.split(";"):
        if "forbid companion" in chunk:
            continue
        kept.append(chunk)
    return ";".join(kept)


def _strip_forbids(text):
    """Mutant: remove every forbid policy."""
    kept = []
    for chunk in text.split(";"):
        # strip comment lines: each policy chunk starts with // comments
        code = "\n".join(ln for ln in chunk.splitlines()
                         if not ln.lstrip().startswith("//"))
        if re.match(r"\s*forbid\s*\(", code):
            continue
        kept.append(chunk)
    return ";".join(kept)


class MutationTests(unittest.TestCase):
    def test_mutant_dropped_stateful_key_is_caught(self):
        # A regressed exporter that silently drops min_sends turns the
        # deny rule into an unconditional forbid: below-threshold sends
        # must then mismatch (engine allows, mutant denies).
        orig = policy_export._temporal_conjuncts

        def weakened(rule_id, match):
            match = {k: v for k, v in match.items()
                     if k != "min_sends"}
            return orig(rule_id, match)

        policy_export._temporal_conjuncts = weakened
        try:
            with self.assertRaises(AssertionError):
                check_parity(self, P_STATEFUL, tool="send_email",
                             role="publisher",
                             counters={"send_email": 1},
                             expect="allow", format="dogwood")
        finally:
            policy_export._temporal_conjuncts = orig

    def test_mutant_dropped_companion_is_caught(self):
        # F88 mutant: a regressed exporter that emits the gated temporal
        # permit but drops the forbid companion. The unconditional
        # allow-all-writes permit then fires for a request the engine
        # queued for approval — the suite's no-event assertion (must be
        # deny) has to fail. The suite sees the mutant through the
        # translate() seam.
        import sys
        from unittest import mock
        path = _write_policy(P_BRIDGE_SHADOW)
        try:
            real = translate(path, format="dogwood")
            self.assertIn("forbid companion", real)
            mutant = _strip_companions(real)
            self.assertNotIn("forbid companion", mutant)
            # Sanity: the mutant really is broken (allows with no event).
            auth = ReferenceAuthorizer(mutant)
            ref_ctx = {"path_outside_sandbox": True, "path": "/etc/d",
                       "counters": {},
                       "input": {"path": "/etc/d", "domain": "",
                                 "role": "coder", "agent": "agent-1"}}
            self.assertEqual(
                auth.decide({"role": "coder", "agent": "agent-1"},
                            "write_file", ref_ctx, []), "allow")
            with mock.patch.object(sys.modules[__name__], "translate",
                                   return_value=mutant):
                with self.assertRaises(AssertionError):
                    check_bridge_parity(
                        self, P_BRIDGE_SHADOW, tool="write_file",
                        role="coder", args={"path": "/etc/d"},
                        context={"path_outside_sandbox": True})
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_mutant_dropped_deny_is_caught(self):
        # A regressed exporter that drops deny rules: the secret-read
        # scenario must mismatch (engine denies, mutant's allow rule
        # fires). The suite sees the mutant through the translate() seam.
        import sys
        from unittest import mock
        path = _write_policy(P_BASIC)
        try:
            real = translate(path, format="cedar")
            mutant = _strip_forbids(real)
            # Sanity: the mutant really is broken (allow rule fires).
            auth = ReferenceAuthorizer(mutant)
            ref_ctx = {"path": "/run/secret.txt", "counters": {},
                       "input": {"path": "/run/secret.txt", "domain": "",
                                 "role": "coder", "agent": "agent-1"}}
            self.assertEqual(
                auth.decide({"role": "coder", "agent": "agent-1"},
                            "read_file", ref_ctx, []), "allow")
            with mock.patch.object(sys.modules[__name__], "translate",
                                   return_value=mutant):
                with self.assertRaises(AssertionError):
                    check_parity(self, P_BASIC, tool="read_file",
                                 role="coder",
                                 args={"path": "/run/secret.txt"},
                                 expect="deny")
        finally:
            Path(path).unlink()
            Path(path).parent.rmdir()

    def test_mutant_narrowed_min_sends_is_caught(self):
        # A regressed exporter counting only send_email for min_sends:
        # http_post-heavy traffic must mismatch (engine denies, mutant
        # allows).
        orig = policy_export._temporal_conjuncts

        def narrowed(rule_id, match):
            conjuncts = []
            for c in orig(rule_id, match):
                if "send_email" in c and "http_post" in c:
                    c = ("exists (n: Long). ((count_within(24h, "
                         "AgentCore::Action::\"send_email\"::request{ _ })) "
                         "== n && n >= 3)")
                conjuncts.append(c)
            return conjuncts

        policy_export._temporal_conjuncts = narrowed
        try:
            with self.assertRaises(AssertionError):
                check_parity(self, P_STATEFUL, tool="http_post",
                             role="publisher",
                             counters={"http_post": 5},
                             expect="deny", format="dogwood")
        finally:
            policy_export._temporal_conjuncts = orig


if __name__ == "__main__":
    unittest.main()
