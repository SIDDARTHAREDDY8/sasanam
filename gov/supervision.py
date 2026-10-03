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
  Wave-298 wires the ``on_restart`` hook: children declared with
  ``requires_lease=True`` get a signed, single-use, time-boxed
  ``reacquire_lease`` obligation on every restart decision
  (``decision["lease_obligations"]``); the child is not re-entered
  until ``attest_reacquisition`` proves it holds a fresh lease
  issued after the crash under a different fencing token. The old
  token is recorded dead-on-restart (``guard_write`` refuses it
  coded even if the lease module would consider it live), and an
  expired unsatisfied obligation escalates signed
  (``supervision-lease-obligation-expired``) instead of silently
  stranding the child. The supervisor's restart decision remains
  the trigger; lease re-acquisition is the agent's first
  post-restart act; actual re-spawning stays deployment-owned.
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
from gov import coordination_lease

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1753 -> 1757).
# ---------------------------------------------------------------------------

SUP_CRASH_LOOP = "supervision-crash-loop"
SUP_INTENSITY = "supervision-intensity-exceeded"
SUP_INVALID = "supervision-invalid"
SUP_LEASE_OBLIGATION_EXPIRED = "supervision-lease-obligation-expired"
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

# Lease re-acquisition obligations (wave-298): a crashed lease-gated
# child is not running again until it proves it holds a fresh lease.
_OBLIGATION_SCHEMA = "supervision/lease-obligation/v1"
_OBLIGATION_FIELDS = ("schema", "supervisor", "child_id", "obligation_id",
                      "crash_instant", "old_fencing_token", "issued_at",
                      "expires_at")
_DEFAULT_OBLIGATION_TTL = 300  # 5 minutes; a crashed child must prove
                               # re-acquisition promptly, not whenever
_MIN_OBLIGATION_TTL = 1
_MAX_OBLIGATION_TTL = 86400    # 24h; there is no unbounded obligation

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
    into a different strategy or looser intensity after the fact.

    ``requires_lease`` (wave-298, default False): a lease-gated
    child cannot be marked running again after a crash until it
    proves lease re-acquisition (``attest_reacquisition``). The
    gate composes supervision with ``gov/coordination_lease.py``:
    a restarted agent must hold a fresh fencing token before
    re-entry, so zombie writes under the old token are refused
    even at the supervision seam.
    """

    __slots__ = ("child_id", "child_pubkey", "strategy",
                 "max_restarts", "window_seconds", "requires_lease")

    def __init__(self, child_id, child_pubkey, strategy,
                 max_restarts, window_seconds, requires_lease=False):
        _check_id(child_id, "child_id")
        _check_pubkey_hex(child_pubkey)
        _check_strategy(strategy)
        _check_intensity(max_restarts, window_seconds)
        if not isinstance(requires_lease, bool):
            _fail(SUP_INVALID,
                  "requires_lease must be a bool; got %r"
                  % (requires_lease,))
        # Frozen at declaration: __init__ bypasses the __setattr__
        # guard below; every later assignment refuses coded.
        object.__setattr__(self, "child_id", child_id)
        object.__setattr__(self, "child_pubkey", child_pubkey)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "max_restarts", max_restarts)
        object.__setattr__(self, "window_seconds", window_seconds)
        object.__setattr__(self, "requires_lease", requires_lease)

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
    ``_obligations`` maps obligation_id -> pending lease re-acquisition
    obligation records for lease-gated children (wave-298).
    ``_dead_tokens`` is the belt-and-suspenders kill list of
    (child_id, fencing_token) pairs that died on restart -- the lease
    module's own fencing check stays authoritative.
    ``_reentered`` is the set of lease-gated children that have proven
    re-acquisition since their last crash.
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
        self._obligations = {}
        self._dead_tokens = set()
        self._reentered = set()
        self._obligation_seq = 0

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

    def report_crash(self, child_id, report, at=0,
                     old_fencing_tokens=None, obligation_ttl=None):
        """Handle a signed crash report from ``child_id``.

        Refuses coded: ``supervision-undeclared-child`` (closed
        inventory), ``supervision-invalid`` (malformed report, bad
        signature, oversized reason), ``supervision-crash-loop``
        (identical reason streak), ``supervision-intensity-exceeded``
        (bounded intensity). The loop and intensity refusals each
        append a SIGNED escalation record first -- escalation is
        fail-closed and loud.

        Wave-298: for every lease-gated child (``requires_lease``)
        in the restart set, the decision carries a signed,
        digest-bound, single-use, time-boxed ``reacquire_lease``
        obligation (``decision["lease_obligations"][cid]``). The
        crashed child is NOT running again until
        ``attest_reacquisition`` proves it holds a fresh lease --
        the ``on_restart`` hook the wave-297 lane left documented.
        ``old_fencing_tokens`` maps child_id -> the fencing token
        the child held when it crashed; tokens handed here are
        recorded dead-on-restart (``guard_write`` refuses them
        coded). ``obligation_ttl`` bounds the obligation window
        (default 300s, 1..86400s).

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
        dead = self._check_dead_tokens(old_fencing_tokens)
        ttl = _DEFAULT_OBLIGATION_TTL if obligation_ttl is None \
            else obligation_ttl
        if not isinstance(ttl, int) or isinstance(ttl, bool) or \
                ttl < _MIN_OBLIGATION_TTL or ttl > _MAX_OBLIGATION_TTL:
            _fail(SUP_INVALID,
                  "obligation_ttl must be bounded %d..%d seconds; there "
                  "is no unbounded obligation"
                  % (_MIN_OBLIGATION_TTL, _MAX_OBLIGATION_TTL))
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
            self._reentered.discard(cid)  # crashed again: re-entry lapsed
        self._reorder(child_id, spec.strategy, restart_set)
        _emit_event("supervision.restart",
                    {"supervisor": self._name,
                     "child_id": child_id,
                     "strategy": spec.strategy,
                     "restart_set": list(restart_set),
                     "reason_digest": digest,
                     "restarts_in_window": len(window) + 1})
        decision = {"action": "restart",
                "supervisor": self._name,
                "child_id": child_id,
                "strategy": spec.strategy,
                "restart_set": list(restart_set),
                "reason_digest": digest,
                "code": None}
        obligations = {}
        for cid in restart_set:
            if not self._specs[cid].requires_lease:
                continue
            old_token = dead.get(cid)
            if old_token is not None:
                self._dead_tokens.add((cid, old_token))
            obligations[cid] = self._issue_lease_obligation(
                cid, at, old_token, ttl)
        if obligations:
            decision["lease_obligations"] = obligations
        return decision

    def _check_dead_tokens(self, old_fencing_tokens):
        if old_fencing_tokens is None:
            return {}
        if not isinstance(old_fencing_tokens, dict):
            _fail(SUP_INVALID,
                  "old_fencing_tokens must be a dict of "
                  "child_id -> fencing token")
        dead = {}
        for cid, token in old_fencing_tokens.items():
            _check_id(cid, "old_fencing_tokens child_id")
            if cid not in self._specs:
                _fail(SUP_UNDECLARED,
                      "child %r is not declared" % (cid,))
            if not isinstance(token, int) or isinstance(token, bool) \
                    or token < 1:
                _fail(SUP_INVALID,
                      "fencing token for child %r must be a positive "
                      "int" % (cid,))
            dead[cid] = token
        return dead

    def _issue_lease_obligation(self, child_id, at, old_token, ttl):
        """Mint one signed, single-use, time-boxed re-acquisition
        obligation for a lease-gated child. The obligation binds the
        child, the crash instant, and the dead fencing token; the
        supervisor's signature makes it unforgeable by the child."""
        self._obligation_seq += 1
        preimage = _canonical({
            "supervisor": self._name,
            "child_id": child_id,
            "crash_instant": at,
            "seq": self._obligation_seq,
        })
        obligation_id = hashlib.sha256(preimage).hexdigest()
        body = {
            "schema": _OBLIGATION_SCHEMA,
            "supervisor": self._name,
            "child_id": child_id,
            "obligation_id": obligation_id,
            "crash_instant": at,
            "old_fencing_token": old_token,
            "issued_at": at,
            "expires_at": at + ttl,
        }
        body["signature"] = ed25519.sign(
            self._seed, _canonical(body)).hex()
        record = {"body": dict(body), "state": "pending"}
        self._obligations[obligation_id] = record
        _emit_event("supervision.lease-obligation",
                    {"supervisor": self._name,
                     "child_id": child_id,
                     "obligation_id": obligation_id,
                     "expires_at": at + ttl})
        return dict(body)

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

    # -- lease re-acquisition (wave-298) ------------------------------------

    def attest_reacquisition(self, child_id, obligation, new_lease,
                             authority_pubkey, old_fencing_token=None, at=0):
        """Prove a lease-gated child holds a fresh lease after its
        crash, and mark it re-entered. The ``on_restart`` hook: the
        child is not running again until this succeeds.

        Checks, in order: the child is declared and lease-gated
        (``supervision-undeclared-child`` / ``supervision-invalid``);
        the obligation is well-shaped, supervisor-signed, issued by
        THIS supervisor, single-use, and unexpired
        (``supervision-invalid``; an expired obligation escalates
        first, then refuses coded
        ``supervision-lease-obligation-expired``); the new lease
        verifies under the authority key via
        ``gov.coordination_lease.verify_lease`` (coded lease
        refusals propagate); the lease holder is the child; the
        lease was issued AFTER the crash instant; its fencing token
        differs from the crashed token. Token rotation cannot be
        proved without a pinned old token -- if neither the
        obligation nor the caller supplies one, attestation refuses
        coded (fail-closed).

        Returns the re-entry record on success.
        """
        _check_id(child_id, "child_id")
        _check_ts(at, "at")
        spec = self._specs.get(child_id)
        if spec is None:
            _fail(SUP_UNDECLARED, "child %r is not declared" % (child_id,))
        if not spec.requires_lease:
            _fail(SUP_INVALID,
                  "child %r is not lease-gated -- attestation is "
                  "meaningless without a declared requires_lease spec"
                  % (child_id,))
        if not isinstance(authority_pubkey, str) or \
                not _HEX64_RE.match(authority_pubkey):
            _fail(SUP_INVALID,
                  "authority_pubkey must be 64 lowercase hex chars")

        body = self._check_obligation(child_id, obligation)
        record = self._obligations.get(body["obligation_id"])
        if record is None:
            _fail(SUP_INVALID,
                  "obligation %r was not issued by supervisor %r"
                  % (body.get("obligation_id"), self._name))
        if record["state"] == "consumed":
            _fail(SUP_INVALID,
                  "obligation %r already consumed -- obligations are "
                  "single-use; replays are refused"
                  % (body["obligation_id"],))
        if record["state"] == "expired_escalated":
            _fail(SUP_LEASE_OBLIGATION_EXPIRED,
                  "obligation %r expired unsatisfied (already "
                  "escalated) -- the child must crash and restart "
                  "again" % (body["obligation_id"],))
        if at >= body["expires_at"]:
            record["state"] = "expired_escalated"
            self._escalate(SUP_LEASE_OBLIGATION_EXPIRED, child_id,
                           hashlib.sha256(
                               body["obligation_id"].encode()).hexdigest(),
                           at,
                           "lease re-acquisition obligation %s expired "
                           "unsatisfied after %d seconds -- the child "
                           "is not re-entered" %
                           (body["obligation_id"][:16],
                            body["expires_at"] - body["issued_at"]))
            _fail(SUP_LEASE_OBLIGATION_EXPIRED,
                  "lease re-acquisition obligation expired unsatisfied "
                  "-- escalated; the child is not re-entered")

        old_token = body["old_fencing_token"]
        if old_token is None:
            old_token = old_fencing_token
        if not isinstance(old_token, int) or isinstance(old_token, bool) \
                or old_token < 1:
            _fail(SUP_INVALID,
                  "cannot prove fencing-token rotation: no old "
                  "fencing token is pinned on the obligation and "
                  "none was supplied -- attestation refuses "
                  "fail-closed")

        # The lease module's verification is authoritative for the
        # lease envelope: shape, signature, expiry. Its coded
        # refusals propagate unchanged.
        ok, detail = coordination_lease.verify_lease(
            new_lease, authority_pubkey, checked_at=at)
        if ok is not True:
            _fail(SUP_INVALID,
                  "lease verification did not succeed")  # defensive;
                                                         # verify_lease
                                                         # raises coded
        if detail["holder_id"] != child_id:
            _fail(SUP_INVALID,
                  "new lease is held by %r, not the restarted child "
                  "%r" % (detail["holder_id"], child_id))
        if new_lease["issued_at"] <= body["crash_instant"]:
            _fail(SUP_INVALID,
                  "new lease was issued at %d, not after the crash "
                  "instant %d -- a pre-crash lease cannot re-enter "
                  "a restarted child"
                  % (new_lease["issued_at"], body["crash_instant"]))
        if detail["fencing_token"] == old_token:
            _fail(SUP_INVALID,
                  "new lease reuses the crashed fencing token %d -- "
                  "token rotation is mandatory; the old token is "
                  "dead-on-restart" % (old_token,))

        record["state"] = "consumed"
        self._reentered.add(child_id)
        _emit_event("supervision.lease-reacquired",
                    {"supervisor": self._name,
                     "child_id": child_id,
                     "obligation_id": body["obligation_id"],
                     "new_fencing_token": detail["fencing_token"]})
        return {"action": "reentered",
                "supervisor": self._name,
                "child_id": child_id,
                "obligation_id": body["obligation_id"],
                "new_fencing_token": detail["fencing_token"],
                "code": None}

    def _check_obligation(self, child_id, obligation):
        if not isinstance(obligation, dict):
            _fail(SUP_INVALID, "lease obligation must be a dict")
        if sorted(obligation.keys()) != \
                sorted(_OBLIGATION_FIELDS + ("signature",)):
            _fail(SUP_INVALID,
                  "lease obligation must carry exactly %s plus "
                  "signature" % ("/".join(_OBLIGATION_FIELDS),))
        if obligation["schema"] != _OBLIGATION_SCHEMA:
            _fail(SUP_INVALID,
                  "unknown obligation schema %r" % (obligation["schema"],))
        if obligation["supervisor"] != self._name:
            _fail(SUP_INVALID,
                  "obligation is for supervisor %r, not %r"
                  % (obligation["supervisor"], self._name))
        if obligation["child_id"] != child_id:
            _fail(SUP_INVALID,
                  "obligation child_id %r does not match caller %r"
                  % (obligation["child_id"], child_id))
        if not isinstance(obligation["obligation_id"], str) or \
                not _HEX64_RE.match(obligation["obligation_id"]):
            _fail(SUP_INVALID,
                  "obligation_id must be 64 lowercase hex chars")
        _check_ts(obligation["crash_instant"], "crash_instant")
        _check_ts(obligation["issued_at"], "issued_at")
        _check_ts(obligation["expires_at"], "expires_at")
        if obligation["expires_at"] <= obligation["issued_at"]:
            _fail(SUP_INVALID, "obligation expiry must be after issuance")
        old = obligation["old_fencing_token"]
        if old is not None and \
                (not isinstance(old, int) or isinstance(old, bool)
                 or old < 1):
            _fail(SUP_INVALID,
                  "old_fencing_token must be null or a positive int")
        sig = obligation["signature"]
        if not isinstance(sig, str) or not _HEX128_RE.match(sig):
            _fail(SUP_INVALID, "obligation signature must be 128 "
                               "lowercase hex chars")
        body = {k: obligation[k] for k in _OBLIGATION_FIELDS}
        _canonical(body)  # canonicalizability gate (F361-class)
        if not _sig_ok(self._pubkey, sig, _canonical(body)):
            _fail(SUP_INVALID,
                  "obligation signature does not verify under the "
                  "supervisor key -- forged obligations are refused")
        return body

    def guard_write(self, child_id, fencing_token, at=0):
        """Belt-and-suspenders write guard for the restart seam.
        Refuses coded ``coord-lease-fencing`` when ``fencing_token``
        is dead-on-restart for ``child_id`` (recorded when the crash
        obligation was issued) -- even if the lease module would
        otherwise consider it live. The lease module's own fencing
        check stays authoritative; this guard exists so a restarted
        child cannot slip a zombie write past a deployment that
        checks the supervision seam first. Returns True otherwise."""
        _check_ts(at, "at")
        if (child_id, fencing_token) in self._dead_tokens:
            raise coordination_lease.CoordinationLeaseError(
                "write denied: fencing token %d for child %r is "
                "dead-on-restart -- the child must re-acquire its "
                "lease before writing" % (fencing_token, child_id),
                code=coordination_lease.LEASE_FENCING)
        return True

    def sweep_obligations(self, at=0):
        """Deployment periodic sweep: every pending obligation whose
        window has elapsed escalates (supervisor-signed
        ``supervision-lease-obligation-expired``) instead of
        silently stranding the child half-restarted. Terminal
        states (consumed / already escalated) are never
        re-escalated. Returns the number of escalations emitted."""
        _check_ts(at, "at")
        swept = 0
        for obligation_id, record in self._obligations.items():
            if record["state"] != "pending":
                continue
            body = record["body"]
            if at < body["expires_at"]:
                continue
            record["state"] = "expired_escalated"
            self._escalate(SUP_LEASE_OBLIGATION_EXPIRED,
                           body["child_id"],
                           hashlib.sha256(
                               obligation_id.encode()).hexdigest(),
                           at,
                           "lease re-acquisition obligation %s expired "
                           "unsatisfied after %d seconds -- the child "
                           "is not re-entered" %
                           (obligation_id[:16],
                            body["expires_at"] - body["issued_at"]))
            swept += 1
        return swept

    def is_reentered(self, child_id):
        """True only when a lease-gated child has proven
        re-acquisition since its last crash."""
        _check_id(child_id, "child_id")
        spec = self._specs.get(child_id)
        if spec is None:
            _fail(SUP_UNDECLARED, "child %r is not declared" % (child_id,))
        return child_id in self._reentered

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
