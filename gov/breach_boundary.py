"""Assume-breach boundary (W246-8).

ADOM shape, patterns only (nothing copied): enforcement that lives
OUTSIDE the agent's mutable context. The deployment declares which
components are assumed-breachable; the boundary guarantees fail-closed
containment even when they are breached:

1. Quarantine. Outputs ingested from an assumed-breachable component
   are wrapped with containment metadata. Using a quarantined output
   without a deployment-vouched verification step is refused
   ``breach-boundary-unverified-use-refused``. Verified outputs carry a
   tamper-evident HMAC seal over (component, seq, output, verifier_id,
   evidence); use() refuses a missing or mismatched seal as
   ``breach-boundary-seal-invalid``, so a forged verified flag or a
   post-verification mutation cannot pass. Verified outputs are
   allowed-but-marked (``breach-boundary-quarantined``), never silent.

2. Consequence budgets. Each declared component may carry a budget of
   consequential actions per deployment-supplied window. Windows are
   monotonic deployment ticks -- no wall clock, fully deterministic.
   Overspend refuses ``breach-boundary-budget-exceeded`` and trips the
   circuit breaker.

3. Circuit breakers. ``signal_breach`` trips the breaker: every later
   ingest/use for that component refuses
   ``breach-boundary-circuit-tripped`` (fail-closed) until a
   deployment-vouched reset. A self-asserted reset refuses
   ``breach-boundary-reset-unvouched``.

4. Compromise + rotation. The GitLab CVE-2026-85706 shape (unauthenticated
   file read; instance assumed compromised -- rotate everything the
   host holds): ``mark_compromised`` refuses every later use of that
   component's outputs as ``breach-boundary-compromised-source`` until
   a deployment-vouched ``rotate``. A self-asserted rotation refuses
   ``breach-boundary-rotation-unvouched``. Compromise is per-component:
   rotating one component never clears another.

Trust classes are a closed vocabulary: ``governed``,
``assumed-breachable``, ``external-untrusted``. Outputs from an
``external-untrusted`` component are refused outright
(``breach-boundary-external-untrusted``) -- they sit outside the
boundary, not inside it under quarantine.

Verification order (fail-closed): shape -> declaration -> containment
state (circuit, compromise) -> verification -> use.

Honest residuals:
- Declarations are deployment-supplied. The boundary refuses what is
  not vouched; it cannot catch a deployment that vouches a lie.
- The primitive sees records, not live processes. Binding a component
  declaration to the live component is deployment-owned.
- Verification evidence is caller-supplied; the boundary checks the
  verifier's vouch, never the verifier's judgment.
- Verification seals are bound to the boundary instance's seal key.
  Unless the deployment supplies a stable ``seal_key``, a fresh random
  key is generated and verified records do not survive boundary
  reconstruction (persistence, process restart). Seal *values* are
  therefore instance-keyed; allow/refuse behavior is deterministic.

Stdlib only. Deterministic. No env reads, no I/O, no wall clock.
Fail-closed on malformed input.
"""

import hashlib
import hmac
import secrets

# Machine codes (all registered in gov/decision_codes.py TAXONOMY).
BREACH_BOUNDARY_RECORD_MALFORMED = "breach-boundary-record-malformed"
BREACH_BOUNDARY_UNKNOWN_COMPONENT = "breach-boundary-unknown-component"
BREACH_BOUNDARY_UNVERIFIED_USE_REFUSED = \
    "breach-boundary-unverified-use-refused"
BREACH_BOUNDARY_CIRCUIT_TRIPPED = "breach-boundary-circuit-tripped"
BREACH_BOUNDARY_BUDGET_EXCEEDED = "breach-boundary-budget-exceeded"
BREACH_BOUNDARY_RESET_UNVOUCHED = "breach-boundary-reset-unvouched"
BREACH_BOUNDARY_COMPROMISED_SOURCE = "breach-boundary-compromised-source"
BREACH_BOUNDARY_ROTATION_UNVOUCHED = "breach-boundary-rotation-unvouched"
BREACH_BOUNDARY_EXTERNAL_UNTRUSTED = "breach-boundary-external-untrusted"
BREACH_BOUNDARY_VERIFIER_UNVOUCHED = "breach-boundary-verifier-unvouched"
BREACH_BOUNDARY_QUARANTINED = "breach-boundary-quarantined"
BREACH_BOUNDARY_SEAL_INVALID = "breach-boundary-seal-invalid"

# Closed trust-class vocabulary. Unknown classes are malformed, never
# treated as benign.
TRUST_GOVERNED = "governed"
TRUST_ASSUMED_BREACHABLE = "assumed-breachable"
TRUST_EXTERNAL_UNTRUSTED = "external-untrusted"
_TRUST_CLASSES = frozenset([
    TRUST_GOVERNED, TRUST_ASSUMED_BREACHABLE, TRUST_EXTERNAL_UNTRUSTED])

# Vouch marker a deployment map must carry for verifier/reset/rotation
# identities. Exact match; anything else is unvouched.
VOUCHED = "deployment-vouched"

_QUARANTINE_MARKER = "_breach_boundary_quarantined"

# Seal field attached by verify(); checked by use(). Leading
# underscore keeps it out of the deployment-visible record shape.
_SEAL_FIELD = "_verification_seal"

# Domain separator for the seal HMAC input.
_SEAL_DOMAIN = b"sasanam/breach-boundary/verify/v1"

# Minimum deployment-supplied seal key length (bytes). Shorter keys
# are refused at construction -- fail closed on weak keys.
_SEAL_KEY_MIN_BYTES = 16


def _canonical(value):
    """Total deterministic canonicalization to bytes.

    Type-tagged and length-prefixed so concatenation is unambiguous.
    Handles arbitrary values without raising: unknown types fall back
    to their type name plus repr. Dict key order is normalized."""
    if value is None:
        return b"n"
    if value is True:
        return b"b1"
    if value is False:
        return b"b0"
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii")
    if isinstance(value, float):
        return b"f" + repr(value).encode("ascii")
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"s" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(value, bytes):
        return b"y" + str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, dict):
        parts = [b"d"]
        for key in sorted(value.keys(),
                          key=lambda k: (type(k).__name__, repr(k))):
            parts.append(_canonical(key))
            parts.append(_canonical(value[key]))
        return b"".join(parts)
    if isinstance(value, (list, tuple)):
        return b"l" + b"".join(_canonical(item) for item in value)
    if isinstance(value, (set, frozenset)):
        items = sorted((_canonical(item) for item in value))
        return b"t" + b"".join(items)
    return (b"o" + type(value).__name__.encode("ascii", "replace")
            + b":" + repr(value).encode("utf-8", "replace"))


def _seal_input(component, seq, output, verifier_id, evidence):
    """The exact bytes sealed by verify() and re-checked by use()."""
    return b"\x00".join([
        _SEAL_DOMAIN,
        _canonical(component),
        _canonical(seq),
        _canonical(output),
        _canonical(verifier_id),
        _canonical(evidence),
    ])


class BreachBoundaryError(Exception):
    """Fail-closed boundary refusal. ``code`` is the machine code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _refuse(code, message):
    raise BreachBoundaryError(code, message)


def _require_dict(value, what):
    if not isinstance(value, dict):
        _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                "%s must be a dict, got %s"
                % (what, type(value).__name__))
    return value


def _require_str(value, what):
    if not isinstance(value, str) or not value:
        _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                "%s must be a non-empty string" % (what,))
    return value


class BreachBoundary:
    """The assume-breach boundary. Deployment-constructed, deterministic.

    ``seal_key`` is the HMAC key binding verified records to this
    boundary instance. Deployments that need verified records to
    survive boundary reconstruction (persistence, process restart)
    MUST supply a stable key; otherwise a fresh random key is
    generated and seals are instance-bound. Seal *values* therefore
    differ across instances unless the key is supplied, but
    allow/refuse behavior is deterministic. A deployment-supplied key
    must be bytes of at least 16 bytes; anything weaker is refused
    at construction.
    """

    def __init__(self, seal_key=None):
        if seal_key is None:
            seal_key = secrets.token_bytes(32)
        if (not isinstance(seal_key, bytes)
                or len(seal_key) < _SEAL_KEY_MIN_BYTES):
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "seal_key must be bytes of at least %d bytes"
                    % (_SEAL_KEY_MIN_BYTES,))
        self._seal_key = seal_key
        self._components = {}
        self._seq = 0

    def _seal(self, component, seq, output, verifier_id, evidence):
        return hmac.new(
            self._seal_key,
            _seal_input(component, seq, output, verifier_id, evidence),
            hashlib.sha256).hexdigest()

    def _check_seal(self, record):
        """Fail-closed seal verification for use(). A record claiming
        verified status without a matching seal was forged or mutated
        after verification."""
        component = record["component"]
        seal = record.get(_SEAL_FIELD)
        if not isinstance(seal, str):
            _refuse(BREACH_BOUNDARY_SEAL_INVALID,
                    "quarantined record from %r claims verified status "
                    "without a verification seal" % (component,))
        verification = record.get("verification") or {}
        expected = self._seal(
            component, record.get("seq"), record.get("output"),
            verification.get("verifier_id"),
            verification.get("evidence"))
        if not hmac.compare_digest(expected, seal):
            _refuse(BREACH_BOUNDARY_SEAL_INVALID,
                    "quarantined record from %r failed seal verification: "
                    "forged or mutated after verification" % (component,))
        return True

    # -- declaration -------------------------------------------------

    def declare_component(self, name, trust_class, budget=None, window=None):
        """Declare a component's trust class and optional consequence
        budget (max consequential actions per ``window`` deployment
        ticks). Redeclaration is refused; trust classes are closed
        vocabulary; a budget without a window (or vice versa) is
        malformed."""
        _require_str(name, "component name")
        if trust_class not in _TRUST_CLASSES:
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "unknown trust class %r" % (trust_class,))
        if name in self._components:
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "component %r already declared" % (name,))
        if (budget is None) != (window is None):
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "budget and window must be given together")
        if budget is not None:
            if (not isinstance(budget, int) or isinstance(budget, bool)
                    or budget <= 0):
                _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                        "budget must be a positive int")
            if (not isinstance(window, int) or isinstance(window, bool)
                    or window <= 0):
                _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                        "window must be a positive int")
        self._components[name] = {
            "trust_class": trust_class,
            "budget": budget,
            "window": window,
            "tripped": False,
            "compromised": False,
            "spend": {},
        }
        return {"decision": "declared", "component": name,
                "trust_class": trust_class, "budget": budget,
                "window": window}

    def _component(self, name):
        try:
            return self._components[name]
        except KeyError:
            _refuse(BREACH_BOUNDARY_UNKNOWN_COMPONENT,
                    "component %r was never declared" % (name,))

    # -- quarantine --------------------------------------------------

    def ingest(self, component, output):
        """Ingest one output from ``component``.

        Governed components pass through. Assumed-breachable outputs are
        quarantined (containment metadata attached). External-untrusted
        outputs are refused outright. A tripped circuit refuses
        fail-closed."""
        _require_str(component, "component")
        if output is None:
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "ingested output must not be None")
        comp = self._component(component)
        if comp["tripped"]:
            _refuse(BREACH_BOUNDARY_CIRCUIT_TRIPPED,
                    "circuit tripped for %r; ingest refused" % (component,))
        trust = comp["trust_class"]
        if trust == TRUST_EXTERNAL_UNTRUSTED:
            _refuse(BREACH_BOUNDARY_EXTERNAL_UNTRUSTED,
                    "output from external-untrusted %r refused; outside "
                    "the boundary" % (component,))
        if trust == TRUST_GOVERNED:
            return {"decision": "passthrough", "component": component,
                    "trust_class": trust, "output": output}
        self._seq += 1
        return {
            _QUARANTINE_MARKER: True,
            "decision": "quarantined",
            "code": BREACH_BOUNDARY_QUARANTINED,
            "component": component,
            "trust_class": trust,
            "seq": self._seq,
            "output": output,
            "verified": False,
            "verification": None,
        }

    @staticmethod
    def _quarantined(record):
        _require_dict(record, "quarantined output")
        if not record.get(_QUARANTINE_MARKER):
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "not a quarantined output record")
        return record

    @staticmethod
    def _vouched(identity, vouch_map, refusal_code, what):
        _require_dict(vouch_map, "vouch map")
        if vouch_map.get(identity) != VOUCHED:
            _refuse(refusal_code,
                    "%s %r is not deployment-vouched" % (what, identity))
        return True

    def verify(self, quarantined, verifier_record, vouch_map):
        """Mark a quarantined output verified by a deployment-vouched
        verifier. Returns a NEW record; the input is not mutated. The
        boundary checks the verifier's vouch, never its judgment.

        The returned record carries a tamper-evident HMAC seal over
        (component, seq, output, verifier_id, evidence). use() refuses
        any record whose seal is missing or does not match the
        record's current contents."""
        record = self._quarantined(quarantined)
        _require_dict(verifier_record, "verifier record")
        verifier_id = _require_str(verifier_record.get("verifier_id"),
                                   "verifier_id")
        self._vouched(verifier_id, vouch_map,
                      BREACH_BOUNDARY_VERIFIER_UNVOUCHED, "verifier")
        comp = self._component(record["component"])
        if comp["tripped"]:
            _refuse(BREACH_BOUNDARY_CIRCUIT_TRIPPED,
                    "circuit tripped for %r; verify refused"
                    % (record["component"],))
        evidence = verifier_record.get("evidence")
        verified = dict(record)
        verified["verified"] = True
        verified["verification"] = {
            "verifier_id": verifier_id,
            "evidence": evidence,
        }
        verified[_SEAL_FIELD] = self._seal(
            record["component"], record["seq"], record["output"],
            verifier_id, evidence)
        return verified

    # -- use ---------------------------------------------------------

    def use(self, quarantined):
        """Consume a quarantined output. Order: declaration, circuit,
        compromise, verification flag, seal integrity -- every check
        fail-closed. A record claiming verified status without a
        valid seal (forged flag or post-verification mutation) is
        refused."""
        record = self._quarantined(quarantined)
        comp = self._component(record["component"])
        if comp["tripped"]:
            _refuse(BREACH_BOUNDARY_CIRCUIT_TRIPPED,
                    "circuit tripped for %r; use refused"
                    % (record["component"],))
        if comp["compromised"]:
            _refuse(BREACH_BOUNDARY_COMPROMISED_SOURCE,
                    "component %r is marked compromised; rotate before "
                    "use" % (record["component"],))
        if not record.get("verified"):
            _refuse(BREACH_BOUNDARY_UNVERIFIED_USE_REFUSED,
                    "quarantined output from %r used without "
                    "deployment-vouched verification"
                    % (record["component"],))
        self._check_seal(record)
        return {"decision": "allow",
                "code": BREACH_BOUNDARY_QUARANTINED,
                "note": "verified quarantined output used; containment "
                        "marked, never silent",
                "component": record["component"],
                "seq": record["seq"],
                "verification": record["verification"],
                "output": record["output"]}

    # -- consequence budgets ------------------------------------------

    def spend(self, component, tick):
        """Record one consequential action at deployment tick ``tick``
        (non-negative int, monotonic per deployment). Overspend refuses
        ``breach-boundary-budget-exceeded`` and trips the circuit."""
        _require_str(component, "component")
        if (not isinstance(tick, int) or isinstance(tick, bool)
                or tick < 0):
            _refuse(BREACH_BOUNDARY_RECORD_MALFORMED,
                    "tick must be a non-negative int")
        comp = self._component(component)
        if comp["tripped"]:
            _refuse(BREACH_BOUNDARY_CIRCUIT_TRIPPED,
                    "circuit tripped for %r; spend refused" % (component,))
        budget = comp["budget"]
        if budget is None:
            return {"decision": "spend-recorded", "component": component,
                    "note": "no budget configured; recorded only"}
        window = comp["window"]
        window_id = tick // window
        used = comp["spend"].get(window_id, 0)
        if used >= budget:
            comp["tripped"] = True
            _refuse(BREACH_BOUNDARY_BUDGET_EXCEEDED,
                    "component %r exceeded budget %d per %d ticks; "
                    "circuit tripped" % (component, budget, window))
        comp["spend"][window_id] = used + 1
        return {"decision": "spend-recorded", "component": component,
                "window_id": window_id,
                "remaining": budget - used - 1}

    # -- circuit breaker ----------------------------------------------

    def signal_breach(self, component, signal):
        """Trip the circuit breaker for ``component``. The signal is a
        record (``{"signal": ..., "detail": ...}``); malformed signals
        fail closed."""
        _require_str(component, "component")
        _require_dict(signal, "breach signal")
        _require_str(signal.get("signal"), "signal.signal")
        comp = self._component(component)
        comp["tripped"] = True
        return {"decision": "circuit-tripped",
                "code": BREACH_BOUNDARY_CIRCUIT_TRIPPED,
                "component": component,
                "signal": signal["signal"]}

    def reset(self, component, reset_record, vouch_map):
        """Clear a tripped circuit. The reset must be
        deployment-vouched; a self-asserted reset is refused."""
        _require_str(component, "component")
        _require_dict(reset_record, "reset record")
        reset_id = _require_str(reset_record.get("reset_id"), "reset_id")
        self._vouched(reset_id, vouch_map,
                      BREACH_BOUNDARY_RESET_UNVOUCHED, "reset")
        comp = self._component(component)
        was_tripped = comp["tripped"]
        comp["tripped"] = False
        return {"decision": "circuit-reset", "component": component,
                "was_tripped": was_tripped, "reset_id": reset_id}

    # -- compromise + rotation -----------------------------------------

    def mark_compromised(self, component, record):
        """Mark a component compromised (the GitLab CVE-2026-85706
        shape: the instance is assumed compromised -- rotate everything
        the host holds). Every later use of its outputs is refused
        until a vouched rotation."""
        _require_str(component, "component")
        _require_dict(record, "compromise record")
        _require_str(record.get("reason"), "reason")
        comp = self._component(component)
        comp["compromised"] = True
        return {"decision": "marked-compromised",
                "code": BREACH_BOUNDARY_COMPROMISED_SOURCE,
                "component": component, "reason": record["reason"]}

    def rotate(self, component, rotation_record, vouch_map):
        """Clear the compromised mark with a deployment-vouched
        rotation. Per-component: rotating one component never clears
        another."""
        _require_str(component, "component")
        _require_dict(rotation_record, "rotation record")
        rotation_id = _require_str(rotation_record.get("rotation_id"),
                                   "rotation_id")
        self._vouched(rotation_id, vouch_map,
                      BREACH_BOUNDARY_ROTATION_UNVOUCHED, "rotation")
        comp = self._component(component)
        was_compromised = comp["compromised"]
        comp["compromised"] = False
        return {"decision": "rotated", "component": component,
                "was_compromised": was_compromised,
                "rotation_id": rotation_id}
