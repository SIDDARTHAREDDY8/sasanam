"""Behavioral fetch->decrypt->read->unrelated-egress sequence gate (steal lane A).

PATTERN LINEAGE: Adversa's GitHub Copilot CLI disclosure (reported to
GitHub's bug bounty Sep 17 2026; disclosed Oct 6-7 2026,
https://cyberpress.org/github-copilot-cli-prompt-injection/): an
attacker plants instructions in an ENCRYPTED blob the agent itself
fetches and decrypts. The plaintext versions were caught by the CLI's
prompt-injection classifier and refused; the encrypted version sailed
through, after which the agent read local files/credentials and
contacted an unrelated host. GitHub triage validated the report but
declined to classify it a vulnerability (the user asked the CLI to
fetch attacker-controlled content with full autonomous permissions);
their recommended controls are per-session tool-call traces,
action-chain alerting, confirmation for new network destinations, and
quarantine of fetched content.

This module is the DETERMINISTIC half of that control list: a
behavioral sequence gate blocking the observable tool-call chain

    untrusted fetch -> decrypt/decode/execute -> sensitive read
        -> egress to a host unrelated to the fetch origin

regardless of payload content. No LLM in the judgement loop, no
classifier, no prompt inspection: the verdict is a pure function of
the operator-declared tool ROLES, the URL hosts observed in args, and
the session's prior calls. This is a clean-room stdlib-only
implementation of the *mechanism*; no upstream code is vendored.

Composition, not duplication:
* ``gov/tool_rules.py`` decides DECLARED sequence (may this call
  happen now per the operator's Init/Child/Terminal/Conditional
  grammar). This module decides TAINT sequence (does this call
  complete a known-exploitable behavior chain). The two run as sibling
  pre-filters in ``gov/invocation_pipeline.py`` and refuse
  independently -- see ``_sequence_gate`` / ``_taint_gate``.
* ``gov/quarantine.py`` stages untrusted BYTES; this gate never looks
  at bytes -- only at the declared chain of tool calls.
* ``gov/taint_ledger.py`` persists read-taint across runs; this gate
  is per-session (its window is the declared session history) and
  tracks chain ARMING, not content overlap.

Design (deterministic, $0, stdlib-only):
* The operator declares tool roles in the gate document: which tools
  FETCH external content, which TRANSFORM (decrypt/decode/execute)
  content, which READ sensitive local data, and which EGRESS to the
  network. The four roles are disjoint at compile time (fail-closed).
* A fetch is UNTRUSTED unless its URL host is in the operator's
  ``trusted_hosts``. Host extraction is stdlib ``urllib.parse``; a
  missing or unparseable URL arg is UNTRUSTED (fail-closed: an
  unevaluatable fetch cannot be proven benign). An untrusted fetch
  arms the session's taint and records the origin host (bounded set).
* A transform while taint is armed arms ``transformed``; a sensitive
  read while armed arms ``credential_taint``. ORDER matters: a
  transform or read with no preceding untrusted fetch arms nothing
  (decrypting one's own vault, or reading credentials without any
  fetched instructions, is the benign shape).
* An egress while the FULL chain is armed REFUSES coded
  ``seqgate-chain-blocked`` when the egress host is UNRELATED to
  every recorded fetch origin and is not in ``trusted_hosts`` or
  ``related_hosts``. Egress back to the fetch origin, or to a trusted
  / declared-related host, is the benign report-back shape and stays
  allowed.
* Anything short of the full 4-step chain passes: fetching without
  transforming, transforming trusted content, reading without an
  unrelated egress. The gate is fail-closed ONLY at the completed
  attack sequence.

Bounds (fail-closed, never silently allow):
* History scan: at most MAX_HISTORY_SCAN (512) entries; a longer
  declared history refuses coded ``seqgate-state-overflow``.
* Distinct untrusted fetch hosts per session: at most MAX_FETCH_HOSTS
  (64); the 65th refuses coded ``seqgate-state-overflow`` (a session
  with 64 distinct untrusted origins is pathological, not a workload).
* No wall-clock, no I/O, no LLM, no payload inspection.

Honest boundaries (documented, not hidden):
* The gate decides on the DECLARED session history handed to
  :meth:`check_call` -- the same honest boundary as the
  declared-sequence checker: it cannot observe whether the tools
  actually executed what was declared (actual-vs-claimed is the
  Tetragon-class observation tier, post-v1).
* Tool-role declaration is operator truth: mislabeling a tool's role
  misplaces the gate. Compile refuses overlapping roles; undeclared
  tools are in no role and neither arm nor trigger.
* Direct host access outside the governed tool boundary (raw sockets
  in the tool body) is invisible -- the gate sees tool calls, not
  syscalls (same coverage ceiling as gov/taint_ledger.py).
* Intra-origin exfiltration (egress BACK TO the fetch origin) is the
  benign report-back shape and stays allowed; an attacker who
  exfiltrates THROUGH the origin host evades this gate by
  construction. The read->novel-egress behavioral flag (wave-137) is
  the complementary tier for that shape.
* Encrypted-content DETECTION is explicitly out of scope: the gate
  never inspects payloads. A fetch from a TRUSTED host whose content
  is attacker-controlled (compromised trusted host) is outside this
  gate's model.
* Binding the gate mid-session cannot un-ring the past: a chain that
  completed before binding is not retroactively blocked; the next
  armed egress still refuses.

All refusals are LOUD: coded :class:`SeqGateError`, never silent.
"""

import hashlib
import json
import re
from types import MappingProxyType
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEQ_GATE_FORMAT = "sasanam-seqgate/v1"

#: Decision-code vocabulary (registered in gov/decision_codes.py).
SEQ_CHAIN_BLOCKED = "seqgate-chain-blocked"
SEQ_STATE_OVERFLOW = "seqgate-state-overflow"
SEQ_CONFIG_INVALID = "seqgate-config-invalid"

#: Compile-time bounds (bounded documents only).
MAX_TOOLS_PER_ROLE = 256
MAX_NAME_LEN = 128
MAX_HOST_LEN = MAX_NAME_LEN
MAX_HOSTS = 1024
MAX_URL_ARG_LEN = 128

#: Runtime bounds.
MAX_HISTORY_SCAN = 512
MAX_FETCH_HOSTS = 64

__all__ = [
    "SEQ_GATE_FORMAT",
    "SEQ_CHAIN_BLOCKED",
    "SEQ_STATE_OVERFLOW",
    "SEQ_CONFIG_INVALID",
    "SeqGateError",
    "CompiledSeqGate",
    "compile_seqgate",
    "seqgate_digest",
]


class SeqGateError(ValueError):
    """LOUD coded refusal for the taint-sequence seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest + deep freeze (the F330/F340 pattern)
# ---------------------------------------------------------------------------

def _json_default(obj):
    if isinstance(obj, MappingProxyType):
        return dict(obj)
    if isinstance(obj, (set, frozenset)):
        # Sorted for determinism: the digest must not depend on
        # iteration order.
        return sorted(obj)
    raise TypeError("object of type %s is not JSON serializable"
                    % type(obj).__name__)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=_json_default).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _freeze(obj):
    """Deep-freeze a validated gate document (F330/F340 pattern)."""
    if isinstance(obj, dict):
        return MappingProxyType(
            {key: _freeze(value) for key, value in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(value) for value in obj)
    if isinstance(obj, (set, frozenset)):
        return frozenset(_freeze(value) for value in obj)
    return obj


def seqgate_digest(doc):
    """Content digest of a seqgate document (the pin)."""
    return _digest(doc)


# ---------------------------------------------------------------------------
# Host extraction (deterministic, fail-closed)
# ---------------------------------------------------------------------------

def _host_of(url):
    """Extract the lowercase host from a URL arg value.

    Returns None for anything unevaluatable (non-string, empty,
    unparseable, no host part) -- the caller treats None as
    untrusted/unrelated, never as benign. Never raises.
    """
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    try:
        host = parts.hostname
    except ValueError:
        # e.g. invalid port in netloc: unevaluatable.
        return None
    if not host:
        return None
    return host


# ---------------------------------------------------------------------------
# Compile-time validation (fail-closed)
# ---------------------------------------------------------------------------

#: Closed vocabularies (pattern strings, not compiled regex objects:
#: the ``re`` module cache handles them, so this module adds no new
#: regex-compilation call sites).
_NAME_PAT = r"[A-Za-z0-9_.:-]+"
_HOST_PAT = r"[A-Za-z0-9.-]+"


def _refuse_config(message):
    raise SeqGateError("seqgate refused: %s" % (message,),
                       code=SEQ_CONFIG_INVALID)


def _check_name(value, what):
    if not isinstance(value, str) or not value \
            or len(value) > MAX_NAME_LEN \
            or re.fullmatch(_NAME_PAT, value) is None:
        _refuse_config("%s must be a non-empty string of "
                       "[A-Za-z0-9_.:-] (<= %d chars); got %r"
                       % (what, MAX_NAME_LEN, value))
    return value


def _check_host(value, what):
    if not isinstance(value, str) or not value \
            or len(value) > MAX_HOST_LEN \
            or re.fullmatch(_HOST_PAT, value) is None:
        _refuse_config("%s must be a non-empty hostname of "
                       "[A-Za-z0-9.-] (<= %d chars); got %r"
                       % (what, MAX_HOST_LEN, value))
    return value.lower()


def _check_role_list(doc, key):
    value = doc.get(key)
    if not isinstance(value, list) or not value \
            or len(value) > MAX_TOOLS_PER_ROLE:
        _refuse_config("%s must be a non-empty list of tool names "
                       "(<= %d)" % (key, MAX_TOOLS_PER_ROLE))
    out = []
    for tool in value:
        _check_name(tool, "%s entry" % (key,))
        if tool in out:
            _refuse_config("duplicate tool %r in %s" % (tool, key))
        out.append(tool)
    return out


def _check_host_list(doc, key):
    value = doc.get(key, [])
    if not isinstance(value, list) or len(value) > MAX_HOSTS:
        _refuse_config("%s must be a list of hostnames (<= %d)"
                       % (key, MAX_HOSTS))
    out = []
    for host in value:
        host = _check_host(host, "%s entry" % (key,))
        if host in out:
            _refuse_config("duplicate host %r in %s" % (host, key))
        out.append(host)
    return out


def compile_seqgate(doc):
    """Validate a seqgate document fail-closed and compile it.

    Returns a frozen :class:`CompiledSeqGate`. Any shape violation
    refuses LOUD with coded ``seqgate-config-invalid``.
    """
    if not isinstance(doc, dict):
        _refuse_config("seqgate document must be a dict; got %r"
                       % (type(doc),))
    for key in doc:
        if key not in ("format", "name", "fetch_tools", "transform_tools",
                       "read_tools", "egress_tools", "trusted_hosts",
                       "related_hosts", "fetch_url_arg", "egress_url_arg"):
            _refuse_config("unknown top-level key %r" % (key,))
    if doc.get("format") != SEQ_GATE_FORMAT:
        _refuse_config("format must be %r; got %r"
                       % (SEQ_GATE_FORMAT, doc.get("format")))
    name = _check_name(doc.get("name"), "name")
    fetch_tools = _check_role_list(doc, "fetch_tools")
    transform_tools = _check_role_list(doc, "transform_tools")
    read_tools = _check_role_list(doc, "read_tools")
    egress_tools = _check_role_list(doc, "egress_tools")
    # Roles are disjoint: a tool in two roles would make arming and
    # triggering ambiguous, so the document is refused instead of
    # guessed at.
    seen = {}
    for role, tools in (("fetch_tools", fetch_tools),
                        ("transform_tools", transform_tools),
                        ("read_tools", read_tools),
                        ("egress_tools", egress_tools)):
        for tool in tools:
            if tool in seen:
                _refuse_config("tool %r is in both %s and %s; roles are "
                               "disjoint" % (tool, seen[tool], role))
            seen[tool] = role
    trusted_hosts = _check_host_list(doc, "trusted_hosts")
    related_hosts = _check_host_list(doc, "related_hosts")
    fetch_url_arg = doc.get("fetch_url_arg", "url")
    egress_url_arg = doc.get("egress_url_arg", "url")
    for arg_name, key in ((fetch_url_arg, "fetch_url_arg"),
                          (egress_url_arg, "egress_url_arg")):
        if not isinstance(arg_name, str) or not arg_name \
                or len(arg_name) > MAX_URL_ARG_LEN:
            _refuse_config("%s must be a non-empty string (<= %d chars); "
                           "got %r" % (key, MAX_URL_ARG_LEN, arg_name))
    frozen = _freeze({
        "name": name,
        "fetch_tools": tuple(fetch_tools),
        "transform_tools": tuple(transform_tools),
        "read_tools": tuple(read_tools),
        "egress_tools": tuple(egress_tools),
        "trusted_hosts": frozenset(trusted_hosts),
        "related_hosts": frozenset(related_hosts),
        "fetch_url_arg": fetch_url_arg,
        "egress_url_arg": egress_url_arg,
    })
    return CompiledSeqGate(frozen)


class CompiledSeqGate:
    """One compiled behavioral sequence gate: the enforceable taint
    checker.

    IMMUTABLE after compilation (the F330/F340 pattern): ``_doc`` is
    deep-frozen, so post-compile in-process mutation fails at the
    source. Stateless across calls: the taint state is derived from
    the declared session history handed to :meth:`check_call` on each
    call -- there is no mutable session table to overflow or poison.
    """

    def __init__(self, frozen_doc):
        self._doc = _freeze(frozen_doc)
        self.digest = _digest(self._doc)

    @property
    def name(self):
        return self._doc["name"]

    def _refuse_chain(self, message):
        raise SeqGateError("taint-sequence refused: %s" % (message,),
                           code=SEQ_CHAIN_BLOCKED)

    def _refuse_overflow(self, message):
        raise SeqGateError("taint-sequence refused: %s" % (message,),
                           code=SEQ_STATE_OVERFLOW)

    def _refuse_shape(self, message):
        raise SeqGateError("taint-sequence refused: %s" % (message,),
                           code=SEQ_CONFIG_INVALID)

    def _check_history_shape(self, history):
        if not isinstance(history, (list, tuple)):
            self._refuse_shape(
                "session history must be a list; got %r" % (type(history),))
        if len(history) > MAX_HISTORY_SCAN:
            self._refuse_overflow(
                "session history exceeds the %d-entry scan bound"
                % (MAX_HISTORY_SCAN,))
        for i, entry in enumerate(history):
            if not isinstance(entry, dict) \
                    or not isinstance(entry.get("tool"), str) \
                    or not entry.get("tool"):
                self._refuse_shape(
                    "history entry %d must be a dict with a non-empty "
                    "string 'tool'; got %r" % (i, entry))
            args = entry.get("args", {})
            if not isinstance(args, dict):
                self._refuse_shape(
                    "history entry %d 'args' must be a dict; got %r"
                    % (i, type(args)))

    def check_call(self, tool, args=None, history=()):
        """Check one tool call against the behavioral taint chain.

        Returns an ``allowed`` record dict. The ONLY blocking verdict
        is the completed 4-step chain: untrusted fetch -> transform ->
        sensitive read -> egress to a host unrelated to the fetch
        origin (coded ``seqgate-chain-blocked``). Everything else --
        including unevaluatable URL args (treated as untrusted, which
        can only ARM, never allow) and over-bound inputs (coded
        ``seqgate-state-overflow``) -- is fail-closed by construction.
        """
        # 1. Input shape (fail-closed: unevaluatable input is refused,
        #    never silently allowed).
        if not isinstance(tool, str) or not tool:
            self._refuse_shape("tool must be a non-empty string; got %r"
                               % (tool,))
        if args is None:
            args = {}
        if not isinstance(args, dict):
            self._refuse_shape("args must be a dict; got %r"
                               % (type(args),))
        for key in args:
            if not isinstance(key, str):
                self._refuse_shape("args keys must be strings; got %r"
                                   % (key,))
        if history is None:
            history = ()
        self._check_history_shape(history)

        fetch_tools = self._doc["fetch_tools"]
        transform_tools = self._doc["transform_tools"]
        read_tools = self._doc["read_tools"]
        egress_tools = self._doc["egress_tools"]
        trusted = self._doc["trusted_hosts"]
        related = self._doc["related_hosts"]
        fetch_url_arg = self._doc["fetch_url_arg"]
        egress_url_arg = self._doc["egress_url_arg"]

        # 2. Replay the session in order, deriving taint deterministically.
        #    The current call is the last entry: only it can COMPLETE the
        #    chain (history entries were each checked as current calls in
        #    their own turn).
        untrusted = False
        transformed = False
        credential_taint = False
        fetch_hosts = set()
        entries = list(history) + [{"tool": tool, "args": dict(args)}]
        for i, entry in enumerate(entries):
            entry_tool = entry["tool"]
            entry_args = entry.get("args") or {}
            if entry_tool in fetch_tools:
                host = _host_of(entry_args.get(fetch_url_arg))
                if host is None or host not in trusted:
                    # Unevaluatable URL -> untrusted (fail-closed: it can
                    # only arm, never prove benign).
                    untrusted = True
                    if host is not None:
                        if len(fetch_hosts) >= MAX_FETCH_HOSTS:
                            self._refuse_overflow(
                                "distinct untrusted fetch hosts exceed "
                                "the %d-host bound" % (MAX_FETCH_HOSTS,))
                        fetch_hosts.add(host)
            elif entry_tool in transform_tools:
                if untrusted:
                    transformed = True
            elif entry_tool in read_tools:
                if untrusted and transformed:
                    credential_taint = True
            elif entry_tool in egress_tools:
                if i == len(entries) - 1 and untrusted and transformed \
                        and credential_taint:
                    host = _host_of(entry_args.get(egress_url_arg))
                    if host is None or (host not in trusted
                                        and host not in related
                                        and host not in fetch_hosts):
                        self._refuse_chain(
                            "fetch->decrypt->read->unrelated-egress chain "
                            "completed at tool %r: untrusted fetch from "
                            "%s, transform, sensitive read, then egress "
                            "to unrelated host %r; refused fail-closed "
                            "before the egress executes"
                            % (entry_tool,
                               sorted(fetch_hosts) or ["unknown"],
                               host))
        return {"allowed": True, "tool": tool,
                "seqgate": self._doc["name"], "digest": self.digest,
                "history_len": len(history)}
