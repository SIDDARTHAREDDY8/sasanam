"""Mandatory invocation filter pipeline around every tool execution.

Wave-294 lane 3 -- microsoft/semantic-kernel STEAL (MIT), mechanism only,
stdlib only.

PATTERN LINEAGE: semantic-kernel's unavoidable filter pipeline -- pre/post
invocation filters through which every kernel function call must pass. This
is a clean-room stdlib-only reimplementation of the *mechanism*; no upstream
code is vendored.

Mechanisms adapted:
* Unavoidable pipeline -- the tool body is reachable only through
  :meth:`FilterStack.invoke`; there is no public seam that executes a tool
  body directly. Every invocation traverses the full filter stack.
* Pre/post filters -- filters are ``filter_fn(context, next)``; pre-work
  runs in registration order before ``next()``, post-work in reverse order
  after it. Skipping ``next()`` is a coded DENY
  (``toolfilter-skip-denied``): a filter that swallows the chain without a
  coded refusal is itself refused LOUD, so skipping never silently allows.
  Calling ``next()`` twice refuses coded as well -- double execution is a
  chain-contract violation.
* Frozen stack -- the filter list is fixed at construction (the F330/F340
  pattern); ``add_filter`` after construction refuses coded
  ``toolcall-filter-frozen``.
* Budget pre-filter -- reserve-then-reconcile cost budgets per caller per
  window. Reservation failure refuses coded ``toolcall-budget-exhausted``;
  malformed reservations refuse ``toolcall-budget-reserve-invalid``.
* Post-filters -- output redaction of secret-shaped values, budget
  reconciliation against actual cost, and a signed per-call log record.

Composition, not duplication:
* ``gov/tool_rules.py`` decides SEQUENCE. In a default stack the sequence
  checker runs as a pre-filter (the sequence gate), so "every tool call
  passes a runtime-checked declaration" holds end-to-end through the
  pipeline, not just in the policy object. Binding is opt-in via
  :meth:`FilterStack.bind_rule_set` -- the same opt-in path as
  ``CompiledToolPolicy.bind_rule_set``. With no rule set bound the gate is
  a pass-through.
* Budget reservation is reserve-then-reconcile. ``gov/aggregate_budget.py``
  is a cumulative charge ledger with no reservation concept and no release;
  a reservation ledger is a distinct mechanism (documented, not hidden).
* The output-side secret redactor shares the bounded secret-shape
  vocabulary of ``gov/tool_rules.py``'s input-side gate (re-implemented
  here because that module's patterns are private; the shared vocabulary
  is documented).

Honest boundary (documented, not hidden): filters run in-process and are
trusted code. The pipeline enforces the chain contract
(next-called-at-most-once, skip-refused-coded) and writes a signed
per-call record, but it cannot stop a malicious filter from mutating the
result -- result tampering between the tool body and the audit post-filter
is DETECTED (the signed record carries both the raw-result digest and the
final-result digest, so an unrecorded transform is evident) rather than
prevented. Actual-vs-claimed execution remains post-v1 (Tetragon-class
observation), same as the policy and tool-rules layers.

All refusals are LOUD: coded :class:`InvocationPipelineError`, never
silent.
"""

import copy
import hashlib
import json
import marshal
import math
import re
import time
import uuid

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PIPELINE_FORMAT = "sasanam-invocation-pipeline/v1"
RECORD_FORMAT = "sasanam-invocation-record/v1"

#: Decision-code vocabulary (registered in gov/decision_codes.py).
SKIP_DENIED = "toolfilter-skip-denied"
BUDGET_EXHAUSTED = "toolcall-budget-exhausted"
RESERVE_INVALID = "toolcall-budget-reserve-invalid"
FILTER_FROZEN = "toolcall-filter-frozen"
#: Reused (not minted here): ill-typed seam inputs.
INVALID_CALL = "toolcall-invalid-call"

#: Compile-time / runtime bounds (bounded documents only).
MAX_FILTERS = 32
MAX_NAME_LEN = 128
MAX_HISTORY_SCAN = 4096
MAX_RESULT_BYTES = 1048576
MAX_LOG_ENTRIES = 4096
MAX_REDACT_DEPTH = 6
MAX_REDACT_BYTES = 65536
MAX_REDACT_PATHS = 64

#: Shared secret-shape vocabulary with gov/tool_rules.py's input-side gate
#: (re-implemented; that module's patterns are private).
_SECRET_VALUE_PATTERNS = (
    r"sk-[A-Za-z0-9]{16,}",
    r"gh[pousr]_[A-Za-z0-9]{16,}",
    r"xox[baprs]-[A-Za-z0-9-]{8,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
)
_SECRET_VALUE_RE = re.compile("|".join("(?:%s)" % p
                                       for p in _SECRET_VALUE_PATTERNS))
_SECRET_NAME_RE = re.compile(
    r"(?i)^[\w-]*?(?:api[_-]?key|secret|passwd|password|client[_-]?secret"
    r"|access[_-]?token|refresh[_-]?token|private[_-]?key|auth[_-]?token"
    r"|session[_-]?token)$")

__all__ = [
    "PIPELINE_FORMAT",
    "RECORD_FORMAT",
    "InvocationPipelineError",
    "InvocationContext",
    "BudgetLedger",
    "FilterStack",
    "build_filter_stack",
    "default_stack",
    "make_budget_filter",
    "make_redact_postfilter",
    "make_audit_filter",
]


class InvocationPipelineError(ValueError):
    """LOUD coded refusal for the invocation-pipeline seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------

def _safe_repr(obj):
    try:
        return repr(obj)
    except Exception:  # noqa: BLE001
        return "<unrepresentable %s>" % (type(obj).__name__,)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=_safe_repr).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _digest_result(result):
    """Bounded digest of a tool result (1 MiB cap, deterministic)."""
    raw = _canonical(result)
    if len(raw) > MAX_RESULT_BYTES:
        head = raw[:MAX_RESULT_BYTES]
        raw = (b'{"__truncated_sha256__":'
               + json.dumps(hashlib.sha256(raw).hexdigest()).encode()
               + b',"__head__":'
               + json.dumps(head.decode("utf-8", "replace")).encode()
               + b"}")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Invocation context
# ---------------------------------------------------------------------------

def _refuse_invalid(message):
    raise InvocationPipelineError(
        "invocation context refused: %s" % (message,), code=INVALID_CALL)


def _check_history_shape(history):
    if not isinstance(history, (list, tuple)):
        _refuse_invalid("history must be a list; got %r" % (type(history),))
    if len(history) > MAX_HISTORY_SCAN:
        _refuse_invalid("history exceeds the %d-entry scan bound"
                        % (MAX_HISTORY_SCAN,))
    for i, entry in enumerate(history):
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("tool"), str) \
                or not entry.get("tool"):
            _refuse_invalid("history entry %d must be a dict with a "
                            "non-empty string 'tool'; got %r" % (i, entry))


class InvocationContext:
    """One tool invocation's immutable core plus a filter scratch channel.

    Core fields are read-only properties (validated fail-closed at
    construction). ``_scratch`` is the in-process channel filters use to
    hand state down the chain (reservation tokens, check records,
    redaction paths); filters are trusted in-process code.
    """

    def __init__(self, *, tool, args=None, caller=None, session_id,
                 call_id, history=(), context_flags=None,
                 declared_cost=None):
        if not isinstance(tool, str) or not tool:
            _refuse_invalid("tool must be a non-empty string; got %r"
                            % (tool,))
        if args is None:
            args = {}
        if not isinstance(args, dict):
            _refuse_invalid("args must be a dict; got %r" % (type(args),))
        for key in args:
            if not isinstance(key, str):
                _refuse_invalid("args keys must be strings; got %r" % (key,))
        if caller is None:
            caller = {}
        if not isinstance(caller, dict):
            _refuse_invalid("caller must be a dict; got %r" % (type(caller),))
        if not isinstance(session_id, str) or not session_id:
            _refuse_invalid("session_id must be a non-empty string; got %r"
                            % (session_id,))
        if not isinstance(call_id, str) or not call_id:
            _refuse_invalid("call_id must be a non-empty string; got %r"
                            % (call_id,))
        if history is None:
            history = ()
        _check_history_shape(history)
        if context_flags is None:
            context_flags = {}
        if not isinstance(context_flags, dict):
            _refuse_invalid("context_flags must be a dict; got %r"
                            % (type(context_flags),))
        if declared_cost is not None:
            if isinstance(declared_cost, bool) \
                    or not isinstance(declared_cost, (int, float)) \
                    or not math.isfinite(declared_cost) \
                    or declared_cost <= 0:
                raise InvocationPipelineError(
                    "declared_cost must be a positive finite number; got %r"
                    % (declared_cost,), code=RESERVE_INVALID)
        self._tool = tool
        self._args = dict(args)
        self._caller = dict(caller)
        self._session_id = session_id
        self._call_id = call_id
        self._history = tuple(history)
        self._context_flags = dict(context_flags)
        self._declared_cost = declared_cost
        self._scratch = {}

    @property
    def tool(self):
        return self._tool

    @property
    def args(self):
        return dict(self._args)

    @property
    def caller(self):
        return dict(self._caller)

    @property
    def caller_id(self):
        identity = self._caller.get("identity")
        if isinstance(identity, str) and identity:
            return identity
        return "anonymous"

    @property
    def session_id(self):
        return self._session_id

    @property
    def call_id(self):
        return self._call_id

    @property
    def history(self):
        return self._history

    @property
    def context_flags(self):
        return dict(self._context_flags)

    @property
    def declared_cost(self):
        return self._declared_cost


# ---------------------------------------------------------------------------
# Budget ledger: reserve-then-reconcile per caller per window
# ---------------------------------------------------------------------------

def _refuse_reserve(message):
    raise InvocationPipelineError(
        "budget reservation refused: %s" % (message,), code=RESERVE_INVALID)


def _check_amount(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value):
        _refuse_reserve("%s must be a finite number; got %r" % (what, value))
    return float(value)


class BudgetLedger:
    """Reserve-then-reconcile cost budgets, keyed by (caller, window).

    Distinct from ``gov/aggregate_budget.py`` (cumulative charge, no
    reservation, no release): here a caller RESERVES its declared cost
    before the tool runs; on success the reservation is RECONCILED to the
    actual cost; on any refusal or crash it is RELEASED with no charge.
    """

    def __init__(self, now=None):
        self._now = now if callable(now) else time.time
        self._scopes = {}        # caller_id -> {cap, window_seconds,
        #                          window_start, used}
        self._reservations = {}  # token_id -> {caller_id, call_id, amount}

    def declare_scope(self, caller_id, cap, *, window_seconds):
        """Declare a per-caller per-window cap. Re-declaration refuses:
        a cap change mid-wave is a deployment decision, not a runtime
        mutation."""
        if not isinstance(caller_id, str) or not caller_id:
            _refuse_reserve("caller_id must be a non-empty string; got %r"
                            % (caller_id,))
        cap = _check_amount(cap, "cap")
        window_seconds = _check_amount(window_seconds, "window_seconds")
        if cap <= 0:
            _refuse_reserve("cap must be positive; got %r" % (cap,))
        if window_seconds <= 0:
            _refuse_reserve("window_seconds must be positive; got %r"
                            % (window_seconds,))
        if caller_id in self._scopes:
            _refuse_reserve("scope %r is already declared" % (caller_id,))
        self._scopes[caller_id] = {
            "cap": cap,
            "window_seconds": window_seconds,
            "window_start": self._now(),
            "used": 0.0,
        }
        return dict(self._scopes[caller_id])

    def _maybe_roll(self, caller_id):
        cfg = self._scopes[caller_id]
        if self._now() >= cfg["window_start"] + cfg["window_seconds"]:
            cfg["window_start"] = self._now()
            cfg["used"] = 0.0
            return True
        return False

    def _outstanding(self, caller_id):
        return sum(rec["amount"] for rec in self._reservations.values()
                   if rec["caller_id"] == caller_id)

    def reserve(self, caller_id, call_id, amount):
        """Reserve ``amount`` for one call. Refuses coded
        ``toolcall-budget-exhausted`` when the reservation would push the
        caller past its window cap (including outstanding reservations),
        ``toolcall-budget-reserve-invalid`` for malformed inputs."""
        if not isinstance(caller_id, str) or not caller_id:
            _refuse_reserve("caller_id must be a non-empty string; got %r"
                            % (caller_id,))
        if not isinstance(call_id, str) or not call_id:
            _refuse_reserve("call_id must be a non-empty string; got %r"
                            % (call_id,))
        amount = _check_amount(amount, "amount")
        if amount <= 0:
            _refuse_reserve("amount must be positive; got %r" % (amount,))
        cfg = self._scopes.get(caller_id)
        if cfg is None:
            _refuse_reserve("scope %r was never declared" % (caller_id,))
        self._maybe_roll(caller_id)
        for rec in self._reservations.values():
            if rec["caller_id"] == caller_id and rec["call_id"] == call_id:
                _refuse_reserve("call %r already holds an outstanding "
                                "reservation" % (call_id,))
        if cfg["used"] + self._outstanding(caller_id) + amount > cfg["cap"]:
            raise InvocationPipelineError(
                "budget exhausted: reserving %r for caller %r would exceed "
                "the window cap %r (used %r, outstanding %r)"
                % (amount, caller_id, cfg["cap"], cfg["used"],
                   self._outstanding(caller_id)),
                code=BUDGET_EXHAUSTED)
        token_id = uuid.uuid4().hex
        token = {
            "token_id": token_id,
            "caller_id": caller_id,
            "call_id": call_id,
            "amount": amount,
            "issued_at": self._now(),
        }
        token["digest"] = _digest(token)
        self._reservations[token_id] = {
            "caller_id": caller_id, "call_id": call_id, "amount": amount,
        }
        return dict(token)

    def _lookup(self, token):
        if not isinstance(token, dict):
            _refuse_reserve("reservation token must be a dict; got %r"
                            % (type(token),))
        token_id = token.get("token_id")
        rec = self._reservations.get(token_id)
        if rec is None:
            _refuse_reserve("unknown or already-settled reservation token")
        return token_id, rec

    def reconcile(self, token, actual):
        """Settle a reservation against the actual cost. ``actual`` above
        the reserved amount is an overrun and refuses coded; a negative
        actual refuses coded. The reservation is consumed exactly once."""
        token_id, rec = self._lookup(token)
        actual = _check_amount(actual, "actual")
        if actual < 0:
            _refuse_reserve("actual cost must be >= 0; got %r" % (actual,))
        if actual > rec["amount"]:
            _refuse_reserve("budget overrun: actual %r exceeds reserved %r "
                            "for call %r"
                            % (actual, rec["amount"], rec["call_id"]))
        cfg = self._scopes[rec["caller_id"]]
        self._maybe_roll(rec["caller_id"])
        cfg["used"] += actual
        del self._reservations[token_id]
        return {
            "caller_id": rec["caller_id"],
            "call_id": rec["call_id"],
            "reserved": rec["amount"],
            "actual": actual,
            "used": cfg["used"],
            "cap": cfg["cap"],
        }

    def release(self, token):
        """Cancel an outstanding reservation with no charge (the DENY /
        crash path). Releasing an unknown token refuses coded."""
        token_id, rec = self._lookup(token)
        del self._reservations[token_id]
        return {"caller_id": rec["caller_id"], "call_id": rec["call_id"],
                "released": rec["amount"]}

    def state(self, caller_id):
        """The caller's budget state (copy): cap, window, used, and total
        outstanding reservations. Per-call tokens are not exposed."""
        cfg = self._scopes.get(caller_id)
        if cfg is None:
            _refuse_reserve("scope %r was never declared" % (caller_id,))
        self._maybe_roll(caller_id)
        return {"caller_id": caller_id, "cap": cfg["cap"],
                "window_seconds": cfg["window_seconds"],
                "window_start": cfg["window_start"], "used": cfg["used"],
                "outstanding": self._outstanding(caller_id)}


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def _filter_name(fn):
    return getattr(fn, "__name__", type(fn).__name__)


def _filter_fingerprint(fn):
    """Stable per-process fingerprint of the filter CALLABLE itself.

    Binds (a) the filter's name, (b) its code object (marshal-dumped --
    a same-named function with different code has a different
    fingerprint), and (c) the callable's identity (``id`` -- a
    same-code closure *instance* is a different object). The identity
    component is stable for the object's lifetime; the stack holds the
    filter tuple, so live filters cannot be garbage-collected and their
    ids cannot be reused while the stack lives. A wholesale ``_filters``
    replacement therefore always changes the drift digest, regardless
    of names (F368).

    ``id`` is a process-local value and the digest is never persisted,
    so cross-process instability is not a concern.
    """
    name = _filter_name(fn)
    code = getattr(fn, "__code__", None)
    if code is not None:
        try:
            blob = marshal.dumps(code)
        except Exception:  # noqa: BLE001
            # Fallback: canonicalize the code attributes directly.
            blob = _canonical((code.co_code, code.co_consts,
                               code.co_names, code.co_varnames,
                               code.co_argcount, code.co_flags))
        code_sha = hashlib.sha256(blob).hexdigest()
    else:
        # Non-Python callables (functools.partial, C callables, objects
        # with __call__): bind by object identity plus a type tag.
        code_sha = None
    return {
        "name": name,
        "kind": type(fn).__name__,
        "code_sha256": code_sha,
        "identity": "0x%x" % id(fn),
    }


def make_budget_filter(ledger):
    """Pre/post filter: reserve the declared cost before ``next()``,
    reconcile against the actual cost after, release on any refusal or
    crash. Calls with no declared cost pass through (documented)."""
    if not isinstance(ledger, BudgetLedger):
        raise InvocationPipelineError(
            "make_budget_filter needs a BudgetLedger; got %r"
            % (type(ledger),), code=INVALID_CALL)

    def budget_filter(context, next):
        declared = context.declared_cost
        if declared is None:
            return next(context)
        reservation = ledger.reserve(context.caller_id, context.call_id,
                                     declared)
        context._scratch["budget_reservation"] = dict(reservation)
        try:
            result = next(context)
        except Exception:  # noqa: BLE001
            # Fail-closed: a reservation must never leak on the DENY or
            # crash path. A release failure here is LOUD (it masks
            # nothing silently -- the raise below still carries the
            # original outcome via implicit chaining).
            ledger.release(reservation)
            raise
        try:
            actual = declared
            if isinstance(result, dict):
                claimed = result.get("actual_cost")
                if claimed is not None:
                    actual = claimed
            record = ledger.reconcile(reservation, actual)
        except Exception:  # noqa: BLE001
            ledger.release(reservation)
            raise
        context._scratch["budget_reconciled"] = record
        return result

    budget_filter.__name__ = "budget_filter"
    return budget_filter


def _redact_walk(value, depth, budget, paths, prefix):
    """Return (redacted_value, changed); records redacted paths."""
    if depth > MAX_REDACT_DEPTH or budget[0] <= 0:
        return value, False
    if isinstance(value, str):
        chunk = value[:budget[0]]
        budget[0] -= len(chunk)
        redacted, n = _SECRET_VALUE_RE.subn("[REDACTED]", chunk)
        if n and len(paths) < MAX_REDACT_PATHS:
            paths.append(prefix)
        return redacted + value[len(chunk):], n > 0
    if isinstance(value, dict):
        changed = False
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_NAME_RE.match(key):
                if item is None or item == "" or item == [] \
                        or item == {} or item == ():
                    out[key] = item
                    continue
                if len(paths) < MAX_REDACT_PATHS:
                    paths.append("%s.%s" % (prefix, key))
                out[key] = "[REDACTED]"
                changed = True
                continue
            new_item, item_changed = _redact_walk(
                item, depth + 1, budget, paths,
                "%s.%s" % (prefix, key))
            out[key] = new_item
            changed = changed or item_changed
        return out, changed
    if isinstance(value, (list, tuple)):
        changed = False
        out = []
        for i, item in enumerate(value):
            new_item, item_changed = _redact_walk(
                item, depth + 1, budget, paths, "%s[%d]" % (prefix, i))
            out.append(new_item)
            changed = changed or item_changed
        return type(value)(out) if isinstance(value, tuple) else out, changed
    return value, False


def make_redact_postfilter():
    """Post-filter: redact secret-shaped values from the tool result
    (bounded walk). Records redacted paths in the context scratch so the
    audit record can distinguish legitimate redaction from tampering."""

    def redact_postfilter(context, next):
        result = next(context)
        paths = []
        redacted, changed = _redact_walk(result, 0, [MAX_REDACT_BYTES],
                                         paths, "$")
        if changed:
            context._scratch["redactions"] = list(paths)
            return redacted
        return result

    redact_postfilter.__name__ = "redact_postfilter"
    return redact_postfilter


def make_audit_filter(*, signer=None, signer_id="pipeline"):
    """Terminal post-filter: write one signed per-call record per
    invocation -- allowed AND denied (a denial is still an accountable
    event). ``signer`` is ``bytes -> bytes``; without one the record is
    marked unsigned (honest, not hidden). The entry list is bounded."""

    if signer is not None and not callable(signer):
        raise InvocationPipelineError(
            "make_audit_filter signer must be callable; got %r"
            % (type(signer),), code=INVALID_CALL)
    if not isinstance(signer_id, str) or not signer_id:
        raise InvocationPipelineError(
            "make_audit_filter signer_id must be a non-empty string",
            code=INVALID_CALL)
    entries = []

    def audit_filter(context, next):
        outcome = "allowed"
        code = None
        note = None
        final_digest = None
        try:
            result = next(context)
        except InvocationPipelineError as e:
            outcome = "denied"
            code = e.code
            raise
        except Exception as e:  # noqa: BLE001
            outcome = "crashed"
            note = "%s: %s" % (type(e).__name__, str(e)[:200])
            raise
        else:
            final_digest = _digest_result(result)
            return result
        finally:
            record = {
                "format": RECORD_FORMAT,
                "call_id": context.call_id,
                "session_id": context.session_id,
                "tool": context.tool,
                "caller_id": context.caller_id,
                "outcome": outcome,
                "code": code,
                "note": note,
                "raw_result_digest":
                    context._scratch.get("raw_result_digest"),
                "final_result_digest": final_digest,
                "redactions":
                    list(context._scratch.get("redactions", [])),
                "sequence_check":
                    context._scratch.get("sequence_check"),
                "budget_reconciled":
                    context._scratch.get("budget_reconciled"),
            }
            payload = _canonical(record)
            signature = None
            if signer is not None:
                signature = signer(payload)
                if not isinstance(signature, bytes):
                    raise InvocationPipelineError(
                        "audit signer returned non-bytes %r: refused "
                        "fail-closed" % (type(signature),),
                        code=SKIP_DENIED)
            entries.append({
                "record": record,
                "signature": signature.hex() if signature else None,
                "signer_id": signer_id,
                "unsigned": signer is None,
            })
            overflow = len(entries) - MAX_LOG_ENTRIES
            if overflow > 0:
                del entries[:overflow]

    audit_filter.__name__ = "audit_filter"
    audit_filter.log = entries
    return audit_filter


def _sequence_gate(holder):
    """Pre-filter slot for the declared-sequence checker. Pass-through
    until a rule set is bound via :meth:`FilterStack.bind_rule_set`."""

    def sequence_gate(context, next):
        from gov import tool_rules as _tool_rules
        rule_set = holder.get("rule_set")
        if rule_set is None:
            return next(context)
        try:
            allowed = rule_set.check_call(
                context.tool, context.args, history=context.history,
                context_flags=context.context_flags)
        except _tool_rules.ToolRuleError as e:
            raise InvocationPipelineError(
                "sequence pre-filter denied: %s" % (e,), code=e.code)
        context._scratch["sequence_check"] = {
            "rule_set": allowed["rule_set"],
            "digest": allowed["digest"],
        }
        return next(context)

    sequence_gate.__name__ = "sequence_gate"
    return sequence_gate


# ---------------------------------------------------------------------------
# Filter stack
# ---------------------------------------------------------------------------

def _validate_filters(filters):
    if not isinstance(filters, (list, tuple)):
        raise InvocationPipelineError(
            "filters must be a list; got %r" % (type(filters),),
            code=INVALID_CALL)
    if not filters:
        raise InvocationPipelineError(
            "a filter stack needs at least one filter; an empty stack is "
            "a degenerate pipeline", code=INVALID_CALL)
    if len(filters) > MAX_FILTERS:
        raise InvocationPipelineError(
            "too many filters (%d > %d)" % (len(filters), MAX_FILTERS),
            code=INVALID_CALL)
    for i, fn in enumerate(filters):
        if not callable(fn):
            raise InvocationPipelineError(
                "filter %d is not callable: %r" % (i, fn), code=INVALID_CALL)
    return tuple(filters)


def _came_through_next(exc):
    """True iff the exception propagated out of this filter's ``next()``
    call (i.e. it belongs to the inner chain or the tool body, not to
    this filter's own code). Attribution matters: only the filter's OWN
    crash is wrapped as ``toolfilter-skip-denied``; inner-chain outcomes
    (coded refusals, body crashes) must propagate unchanged so the host
    still sees the original exception."""
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_name in ("nxt", "terminal"):
            return True
        tb = tb.tb_next
    return False


def _stack_digest(name, filters, gate_holder):
    # F368: the digest binds each filter's name, code object, and
    # callable identity -- never names alone. A wholesale _filters
    # replacement with same-named functions (or same-code closure
    # instances) changes this digest and refuses coded at invoke time.
    return _digest({
        "format": PIPELINE_FORMAT,
        "name": name,
        "filters": [_filter_fingerprint(fn) for fn in filters],
        "sequence_gate": gate_holder is not None,
    })


class FilterStack:
    """One compiled invocation pipeline: the enforceable filter chain.

    IMMUTABLE after construction (the F330/F340 pattern): ``_filters`` is
    a tuple fixed at build time, so post-construction in-process mutation
    fails at the source instead of silently changing the pipeline under a
    still-valid digest. :meth:`add_filter` exists only to refuse LOUD.
    Belt and braces: :meth:`invoke` re-verifies the digest against the
    live filter list on every call, so even a freeze-bypassing wholesale
    replacement of ``_filters`` is caught as ``toolcall-filter-frozen``
    (the ``CompiledToolPolicy`` drift-detection pattern) -- the pipeline
    never decides under a mutated stack. The digest binds each filter's
    name, code object, AND callable identity (F368): a replacement with
    same-named but different-code functions, or with same-code closure
    instances, changes the digest and refuses coded. The ``filters``
    property still reports names only (execution order), not identity.
    """

    def __init__(self, filters, *, name="filter-stack", _gate_holder=None,
                 _audit_fn=None):
        if not isinstance(name, str) or not name \
                or len(name) > MAX_NAME_LEN:
            raise InvocationPipelineError(
                "stack name must be a non-empty string (<= %d chars)"
                % (MAX_NAME_LEN,), code=INVALID_CALL)
        self._filters = _validate_filters(filters)
        self._name = name
        self._gate_holder = _gate_holder
        self._audit_fn = _audit_fn
        self.digest = _stack_digest(name, self._filters, _gate_holder)

    @property
    def name(self):
        return self._name

    @property
    def filters(self):
        """Filter names in execution (pre) order."""
        return tuple(_filter_name(fn) for fn in self._filters)

    def add_filter(self, filter_fn):
        """Always refuses: the stack is frozen at construction. A filter
        added after freeze would change decisions under a still-valid
        digest -- that is refused LOUD, never applied silently."""
        raise InvocationPipelineError(
            "filter stack %r is frozen at construction (F330/F340 "
            "pattern); filters cannot be added after construction"
            % (self._name,), code=FILTER_FROZEN)

    def bind_rule_set(self, rule_set):
        """Opt-in: bind a compiled tool-rule set; the sequence gate in
        this stack then runs the declared-sequence checker as a
        pre-filter. Mirrors ``CompiledToolPolicy.bind_rule_set``."""
        from gov import tool_rules as _tool_rules
        if not isinstance(rule_set, _tool_rules.CompiledToolRuleSet):
            raise InvocationPipelineError(
                "bind_rule_set needs a CompiledToolRuleSet; got %r"
                % (type(rule_set),),
                code=_tool_rules.RULE_COMPILE_INVALID)
        if self._gate_holder is None:
            raise InvocationPipelineError(
                "bind_rule_set on a stack built without a sequence gate "
                "(use default_stack or build_filter_stack(..., "
                "sequence_gate=True)); the binding would never be "
                "consulted", code=_tool_rules.RULE_COMPILE_INVALID)
        self._gate_holder["rule_set"] = rule_set
        return rule_set

    def audit_log(self):
        """Copies of the signed per-call records (default stacks only).

        Deep copies: mutating the returned entries (including the nested
        ``record`` dict) cannot touch the stored log. (F369: the shallow
        ``dict(entry)`` copy aliased the stored record.)
        """
        if self._audit_fn is None:
            raise InvocationPipelineError(
                "no audit filter in this stack", code=INVALID_CALL)
        return [copy.deepcopy(entry) for entry in self._audit_fn.log]

    # -- execution -----------------------------------------------------

    def invoke(self, tool_body, context):
        """Run one tool invocation through the full filter stack.

        The tool body is reachable ONLY here: ``tool_body`` is a
        caller-supplied callable invoked by the terminal link of the
        chain. There is no other public seam that executes a tool body.
        """
        if not callable(tool_body):
            raise InvocationPipelineError(
                "tool_body must be callable; got %r" % (type(tool_body),),
                code=INVALID_CALL)
        if not isinstance(context, InvocationContext):
            raise InvocationPipelineError(
                "context must be an InvocationContext; got %r"
                % (type(context),), code=INVALID_CALL)
        # Drift check (the CompiledToolPolicy pattern): the pipeline never
        # decides under a mutated stack -- even a freeze-bypassing
        # wholesale replacement of _filters refuses LOUD here.
        if _stack_digest(self._name, self._filters,
                         self._gate_holder) != self.digest:
            raise InvocationPipelineError(
                "filter stack %r drift: the live filter list no longer "
                "matches the construction digest; refused fail-closed"
                % (self._name,), code=FILTER_FROZEN)

        state = {"body_ran": False}

        def terminal(ctx):
            state["body_ran"] = True
            # The body itself is the host's code: its exceptions propagate
            # unchanged (they are not pipeline refusals). The raw result
            # digest is stashed so the audit post-filter can DETECT
            # tampering between the body and the log.
            result = tool_body(ctx)
            ctx._scratch["raw_result"] = result
            ctx._scratch["raw_result_digest"] = _digest_result(result)
            return result

        nxt = terminal
        for filter_fn in reversed(self._filters):
            nxt = self._wrap(filter_fn, nxt)
        result = nxt(context)
        if not state["body_ran"]:
            # A filter returned without calling next() and without raising
            # a coded refusal: the call was swallowed. That is refused
            # LOUD -- skipping never silently allows.
            raise InvocationPipelineError(
                "a filter returned without calling next() and without a "
                "coded refusal: the invocation was swallowed; refused "
                "fail-closed", code=SKIP_DENIED)
        return result

    @staticmethod
    def _wrap(filter_fn, inner_next):
        fname = _filter_name(filter_fn)

        def nxt(ctx):
            if nxt._called:  # noqa: SLF001 -- per-invocation chain state
                raise InvocationPipelineError(
                    "filter %r called next() twice: double execution "
                    "refused" % (fname,), code=SKIP_DENIED)
            nxt._called = True
            return inner_next(ctx)

        nxt._called = False

        def run(ctx):
            try:
                return filter_fn(ctx, nxt)
            except InvocationPipelineError:
                raise
            except Exception as exc:  # noqa: BLE001
                if _came_through_next(exc):
                    # Raised by the inner chain through next(): not this
                    # filter's crash -- propagate unchanged.
                    raise
                # An uncoded crash in the filter's OWN code is a pipeline
                # defect: wrap it LOUD and coded rather than letting it
                # escape raw or, worse, pass silently.
                raise InvocationPipelineError(
                    "filter %r crashed uncoded (%r): refused fail-closed"
                    % (fname, exc), code=SKIP_DENIED)

        return run


def build_filter_stack(filters, *, name="filter-stack", sequence_gate=False):
    """Compile a custom filter stack, fail-closed, frozen at construction.

    With ``sequence_gate=True`` a sequence-gate pre-filter is prepended
    and :meth:`FilterStack.bind_rule_set` becomes available.
    """
    holder = {} if sequence_gate else None
    if sequence_gate:
        filters = [_sequence_gate(holder)] + list(filters)
    return FilterStack(filters, name=name, _gate_holder=holder)


def default_stack(*, name="default", budget_ledger=None, signer=None,
                  signer_id="pipeline"):
    """The standard pipeline: audit (outermost, logs allowed AND denied),
    sequence gate, budget reserve/reconcile, output redaction.

    Pre order: audit, sequence, budget-reserve, redact, body.
    Post order: redact, budget-reconcile, sequence, audit-log.
    The sequence gate is pass-through until :meth:`bind_rule_set`.
    """
    holder = {}
    audit_fn = make_audit_filter(signer=signer, signer_id=signer_id)
    filters = [audit_fn, _sequence_gate(holder)]
    if budget_ledger is not None:
        filters.append(make_budget_filter(budget_ledger))
    filters.append(make_redact_postfilter())
    return FilterStack(filters, name=name, _gate_holder=holder,
                       _audit_fn=audit_fn)
