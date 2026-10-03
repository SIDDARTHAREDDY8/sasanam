"""Declared agent lifecycle supervision (erlang/otp pattern).

Pattern lineage: erlang/otp (Apache-2.0) -- declared restart
strategies, bounded intensity, escalation. Mechanisms only; no
vendored code; stdlib only. Answers "who watches (and restarts) the
agents": a supervisor owns a CLOSED inventory of declared child
specs and decides, on each signed crash report, which children
restart -- or whether the failure escalates to the parent
supervisor instead.

A ``Supervisor`` is declared, not discovered:

* every child is declared up front with its agent id, its child
  public key (which signs that child's crash reports), a restart
  strategy, and bounded intensity limits; undeclared children
  cannot be supervised -- ``supervision-undeclared-child``;
* restart strategy per child spec: ``one_for_one`` (only the
  crashed child restarts), ``one_for_all`` (all children restart --
  for co-dependent agents), ``rest_for_one`` (the crashed child and
  all children started after it restart);
* bounded intensity: at most ``max_restarts`` restarts inside any
  ``window_seconds`` window (both bounded, declared at
  construction). Exceeding intensity refuses coded
  ``supervision-intensity-exceeded`` and ESCALATES -- a supervisor
  whose children all exceed intensity must not silently stop
  supervising; every escalation is a signed record and is
  audit-logged via the module sink;
* crash reports are signed, structured records. The child signs
  ``{child_id, reason_kind, reason_bytes, crashed_at}`` with its
  declared key; the supervisor stores reason DIGESTS only -- never
  raw payloads beyond the bounded size. A crash-loop (the same
  reason digest ``_CRASH_LOOP_STREAK`` times in a row) refuses
  coded ``supervision-crash-loop`` and escalates: restarting an
  agent that crashes identically every time is a livelock, not a
  recovery.

This module is a DECISION layer, like ``gov/coordination_lease.py``:
``report_crash`` returns a restart decision
(``{"action": "restart", "restart_set": [...], ...}``); the actual
re-spawning of agent processes is deployment-owned. All refusals
raise ``SupervisionError`` carrying the machine code (the F351
contract: every refusal is coded).

Composition points (documented here; this lane is self-contained
and changes no existing API):

* ``gov/coordination_lease.py``: a restarted agent MUST re-acquire
  its lease -- zombie fencing tokens already kill the old epoch's
  writes (``coord-lease-fencing``), so a crashed agent that restarts
  and keeps writing under its OLD fencing token is refused loud.
  The supervisor's restart decision is the trigger; lease
  re-acquisition is the agent's first post-restart act. Wiring a
  ``on_restart`` hook that forces lease re-acquisition before the
  child is marked running again is future work -- this module
  exposes the restart set in decision order so a deployment can
  gate re-entry on it.
* Incident-workflow (future lane): an escalation record is the
  machine-readable input a parent supervisor or an incident
  pipeline consumes -- escalation records carry digests and ids
  only, never key material, so they are safe to forward.

THREAT MODEL:

* The supervisor seed is the trust anchor (signs escalations).
  The supervisor is in-memory per verifier (wave-292 decay
  precedent): two verifiers do not share supervision state, so this
  is per-coordinator-plane supervision, not distributed consensus.
* ``crashed_at`` / ``at`` are freshness markers, not a clock.
  Callers pass explicit instants; this module orders events, it
  does not run a clock.
* A compromised child key can file false crash reports -- the
  compromised-host class; the report proves what was claimed, not
  that the child really crashed. Forged reports from OTHER keys
  refuse coded ``supervision-invalid``.
"""

import hashlib
import json
import re

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1753 -> 1757).
# ---------------------------------------------------------------------------

SUP_CRASH_LOOP = "supervision-crash-loop"
SUP_INTENSITY = "supervision-intensity-exceeded"
SUP_INVALID = "supervision-invalid"
SUP_UNDECLARED = "supervision-undeclared-child"

_DOMAIN = "supervision"

# Strategies (erlang/otp vocabulary, kebab-free on purpose: the
# strategy name is also the wire value).
ONE_FOR_ONE = "one_for_one"
ONE_FOR_ALL = "one_for_all"
REST_FOR_ONE = "rest_for_one"
_STRATEGIES = (ONE_FOR_ONE, ONE_FOR_ALL, REST_FOR_ONE)

# Supervisor/child/agent ids and crash-reason kinds: bounded identifier
# grammar (coord-lease precedent).
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

_MAX_REASON_BYTES = 4096      # crash reason payload bound; digest-only storage
_CRASH_LOOP_STREAK = 3        # identical reason digests in a row -> loop

_MIN_RESTARTS = 1
_MAX_RESTARTS = 1000
_MIN_WINDOW = 1
_MAX_WINDOW = 86400            # 24h; there is no unbounded intensity window
_MAX_ESCALATIONS = 1024       # bounded in-memory escalation log (decay
                              # precedent: overflow refuses loud, never
                              # silently evicts)

_CRASH_FIELDS = ("child_id", "reason_kind", "reason_bytes", "crashed_at")


class SupervisionError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = SUP_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise SupervisionError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    """Returns True if a sink consumed the event, False when no sink
    is wired or the sink raised. Never raises (F345-class)."""
    if _EMIT is None:
        return False
    try:
        _EMIT(event, fields)
        return True
    except Exception:
        return False


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(SUP_INVALID, "supervision material is not canonicalizable "
                           "(circular or non-JSON structure)")


def _sig_ok(pubkey_hex, signature_hex, message):
    """True only on exact verification success (wave-243 lesson:
    ``ed25519.verify`` is bool-returning; check ``is True``)."""
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    ok = ed25519.verify(pub, message, sig)
    return ok is True


def _check_id(value, what="id"):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(SUP_INVALID,
              "%s must match [a-z][a-z0-9-]{0,63}; got %r" % (what, value))


def _check_pubkey_hex(value, what="child public key"):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(SUP_INVALID,
              "%s must be 64 lowercase hex chars" % what)


def _check_seed(value, what="supervisor seed"):
    if not isinstance(value, bytes) or len(value) != 32:
        _fail(SUP_INVALID, "%s must be 32 raw bytes" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(SUP_INVALID, "%s must be a non-negative int" % what)


def _check_strategy(value):
    if value not in _STRATEGIES:
        _fail(SUP_INVALID,
              "restart strategy must be one of %s; got %r"
              % ("/".join(_STRATEGIES), value))


def _check_intensity(max_restarts, window_seconds):
    if not isinstance(max_restarts, int) or isinstance(max_restarts, bool):
        _fail(SUP_INVALID, "max_restarts must be an int")
    if max_restarts < _MIN_RESTARTS or max_restarts > _MAX_RESTARTS:
        _fail(SUP_INVALID,
              "max_restarts must be bounded %d..%d; there is no "
              "unbounded intensity" % (_MIN_RESTARTS, _MAX_RESTARTS))
    if not isinstance(window_seconds, int) or isinstance(window_seconds, bool):
        _fail(SUP_INVALID, "window_seconds must be an int")
    if window_seconds < _MIN_WINDOW or window_seconds > _MAX_WINDOW:
        _fail(SUP_INVALID,
              "window_seconds must be bounded %d..%d seconds; there is "
              "no unbounded window" % (_MIN_WINDOW, _MAX_WINDOW))


def _check_reason(value):
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        _fail(SUP_INVALID, "reason_bytes must be str or bytes")
    if len(raw) > _MAX_REASON_BYTES:
        _fail(SUP_INVALID,
              "crash reason payload exceeds %d bytes -- digests only, "
              "never unbounded raw payloads" % _MAX_REASON_BYTES)
    return raw


def _reason_digest(raw):
    return hashlib.sha256(raw).hexdigest()


class ChildSpec:
    """One declared, immutable child spec. Deep-frozen at
    construction (F330/F340 precedent): the spec cannot be mutated
    into a different strategy or looser intensity after the fact."""

    __slots__ = ("child_id", "child_pubkey", "strategy",
                 "max_restarts", "window_seconds")

    def __init__(self, child_id, child_pubkey, strategy,
                 max_restarts, window_seconds):
        _check_id(child_id, "child_id")
        _check_pubkey_hex(child_pubkey)
        _check_strategy(strategy)
        _check_intensity(max_restarts, window_seconds)
        # Frozen at declaration: __init__ bypasses the __setattr__
        # guard below; every later assignment refuses coded.
        object.__setattr__(self, "child_id", child_id)
        object.__setattr__(self, "child_pubkey", child_pubkey)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "max_restarts", max_restarts)
        object.__setattr__(self, "window_seconds", window_seconds)

    def __setattr__(self, name, value):
        _fail(SUP_INVALID,
              "child specs are frozen at declaration -- strategy and "
              "intensity cannot be mutated")


class Supervisor:
    """In-memory supervisor for one coordinator plane.

    ``_specs`` maps child_id -> frozen ChildSpec (closed inventory).
    ``_start_order`` is the running order (drives rest_for_one).
    ``_restarts`` maps child_id -> list of restart instants (bounded
    intensity accounting; pruned outside the window).
    ``_loop`` maps child_id -> (last_reason_digest, streak).
    ``_escalations`` is the bounded escalation log -- never
    silently evicted (overflow refuses loud).
    """

    def __init__(self, name, child_specs, supervisor_seed):
        _check_id(name, "supervisor name")
        _check_seed(supervisor_seed)
        if not isinstance(child_specs, (list, tuple)) or not child_specs:
            _fail(SUP_INVALID,
                  "supervisor requires a non-empty list of child specs")
        specs = {}
        for spec in child_specs:
            if not isinstance(spec, ChildSpec):
                _fail(SUP_INVALID,
                      "child specs must be ChildSpec instances; got %r"
                      % type(spec).__name__)
            if spec.child_id in specs:
                _fail(SUP_INVALID,
                      "duplicate child_id %r in supervisor declaration"
                      % spec.child_id)
            specs[spec.child_id] = spec
        self._name = name
        self._specs = specs
        self._seed = bytes(supervisor_seed)
        self._pubkey = ed25519.publickey(supervisor_seed).hex()
        self._start_order = []
        self._restarts = {cid: [] for cid in specs}
        self._loop = {cid: (None, 0) for cid in specs}
        self._escalations = []

    # -- lifecycle --------------------------------------------------------

    def start(self, at=0):
        """Mark all declared children running, in declaration order.
        Returns the start order. Idempotent only in the sense that a
        second start re-runs the same order -- deployments call it
        once."""
        _check_ts(at, "at")
        self._start_order = list(self._specs.keys())
        _emit_event("supervision.started",
                    {"supervisor": self._name,
                     "children": len(self._specs),
                     "started_at": at})
        return list(self._start_order)

    # -- crash handling -----------------------------------------------------

    def report_crash(self, child_id, report, at=0):
        """Handle a signed crash report from ``child_id``.

        Refuses coded: ``supervision-undeclared-child`` (closed
        inventory), ``supervision-invalid`` (malformed report, bad
        signature, oversized reason), ``supervision-crash-loop``
        (identical reason streak), ``supervision-intensity-exceeded``
        (bounded intensity). The loop and intensity refusals each
        append a SIGNED escalation record first -- escalation is
        fail-closed and loud.

        Returns the restart decision dict on success.
        """
        _check_id(child_id, "child_id")
        _check_ts(at, "at")
        spec = self._specs.get(child_id)
        if spec is None:
            _fail(SUP_UNDECLARED,
                  "child %r is not declared in supervisor %r -- the "
                  "inventory is closed; undeclared children cannot be "
                  "supervised" % (child_id, self._name))
        body = self._check_report(child_id, report)
        raw = _check_reason(body["reason_bytes"])
        digest = _reason_digest(raw)

        # Crash-loop: the same reason digest _CRASH_LOOP_STREAK times
        # in a row is a livelock, not a recovery.
        last, streak = self._loop[child_id]
        streak = streak + 1 if last == digest else 1
        self._loop[child_id] = (digest, streak)
        if streak >= _CRASH_LOOP_STREAK:
            self._escalate(SUP_CRASH_LOOP, child_id, digest, at,
                           "crash-loop: reason digest %s repeated %d "
                           "times in a row" % (digest[:16], streak))
            _fail(SUP_CRASH_LOOP,
                  "child %r crashed with identical reason %d times in "
                  "a row -- restart refused, escalated"
                  % (child_id, streak))

        # Bounded intensity: at most max_restarts inside the window.
        window = [t for t in self._restarts[child_id]
                  if t > at - spec.window_seconds]
        if len(window) >= spec.max_restarts:
            self._escalate(SUP_INTENSITY, child_id, digest, at,
                           "intensity exceeded: %d restarts in %d "
                           "seconds (max %d)"
                           % (len(window), spec.window_seconds,
                              spec.max_restarts))
            _fail(SUP_INTENSITY,
                  "child %r exceeded restart intensity (%d in %d "
                  "seconds) -- restart refused, escalated"
                  % (child_id, len(window), spec.window_seconds))

        restart_set = self._restart_set(child_id, spec.strategy)
        for cid in restart_set:
            self._restarts[cid].append(at)
        self._reorder(child_id, spec.strategy, restart_set)
        _emit_event("supervision.restart",
                    {"supervisor": self._name,
                     "child_id": child_id,
                     "strategy": spec.strategy,
                     "restart_set": list(restart_set),
                     "reason_digest": digest,
                     "restarts_in_window": len(window) + 1})
        return {"action": "restart",
                "supervisor": self._name,
                "child_id": child_id,
                "strategy": spec.strategy,
                "restart_set": list(restart_set),
                "reason_digest": digest,
                "code": None}

    def _check_report(self, child_id, report):
        if not isinstance(report, dict):
            _fail(SUP_INVALID, "crash report must be a dict")
        if sorted(report.keys()) != sorted(_CRASH_FIELDS + ("signature",)):
            _fail(SUP_INVALID,
                  "crash report must carry exactly %s plus signature"
                  % ("/".join(_CRASH_FIELDS),))
        if report["child_id"] != child_id:
            _fail(SUP_INVALID,
                  "crash report child_id %r does not match caller %r"
                  % (report["child_id"], child_id))
        _check_id(report["reason_kind"], "reason_kind")
        _check_ts(report["crashed_at"], "crashed_at")
        if not isinstance(report["signature"], str) or \
                not _HEX128_RE.match(report["signature"]):
            _fail(SUP_INVALID, "crash report signature must be 128 "
                               "lowercase hex chars")
        body = {k: report[k] for k in _CRASH_FIELDS}
        _canonical(body)  # canonicalizability gate (F361-class)
        if not _sig_ok(self._specs[child_id].child_pubkey,
                       report["signature"], _canonical(body)):
            _fail(SUP_INVALID,
                  "crash report signature does not verify under the "
                  "declared child key -- forged reports are refused")
        return body

    def _restart_set(self, crashed_id, strategy):
        if strategy == ONE_FOR_ONE:
            return [crashed_id]
        if strategy == ONE_FOR_ALL:
            return list(self._specs.keys())
        # REST_FOR_ONE: the crashed child and every child started
        # after it.
        order = self._start_order or list(self._specs.keys())
        idx = order.index(crashed_id)
        return order[idx:]

    def _reorder(self, crashed_id, strategy, restart_set):
        if strategy == ONE_FOR_ONE:
            order = [c for c in self._start_order if c != crashed_id]
            order.append(crashed_id)
            self._start_order = order
        elif strategy == REST_FOR_ONE:
            prefix = [c for c in self._start_order if c not in restart_set]
            self._start_order = prefix + list(restart_set)
        # ONE_FOR_ALL restarts in place: order is unchanged.

    # -- escalation ---------------------------------------------------------

    def _escalate(self, code, child_id, reason_digest, at, detail):
        if len(self._escalations) >= _MAX_ESCALATIONS:
            _fail(SUP_INVALID,
                  "escalation log full (%d records) -- refusing LOUD; "
                  "escalations are never silently evicted"
                  % _MAX_ESCALATIONS)
        record = {
            "supervisor": self._name,
            "child_id": child_id,
            "code": code,
            "reason_digest": reason_digest,
            "escalated_at": at,
            "detail": detail,
        }
        record["signature"] = ed25519.sign(
            self._seed, _canonical(record)).hex()
        self._escalations.append(record)
        _emit_event("supervision.escalation",
                    {"supervisor": self._name,
                     "child_id": child_id,
                     "code": code,
                     "reason_digest": reason_digest,
                     "escalated_at": at})

    @property
    def escalations(self):
        """The bounded escalation log (signed records)."""
        return list(self._escalations)

    def verify_escalation(self, record):
        """Verify a signed escalation record under this supervisor's
        key. Returns True only on exact success (wave-243 lesson)."""
        if not isinstance(record, dict):
            return False
        sig = record.get("signature")
        if not isinstance(sig, str) or not _HEX128_RE.match(sig):
            return False
        body = {k: v for k, v in record.items() if k != "signature"}
        return _sig_ok(self._pubkey, sig, _canonical(body))

    # -- introspection ------------------------------------------------------

    @property
    def name(self):
        return self._name

    @property
    def child_ids(self):
        return list(self._specs.keys())

    @property
    def supervisor_pubkey(self):
        return self._pubkey

    def restarts_in_window(self, child_id, at):
        """Intensity accounting probe (deployment introspection)."""
        _check_id(child_id, "child_id")
        spec = self._specs.get(child_id)
        if spec is None:
            _fail(SUP_UNDECLARED, "child %r is not declared" % child_id)
        _check_ts(at, "at")
        return sum(1 for t in self._restarts[child_id]
                   if t > at - spec.window_seconds)
