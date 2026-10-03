"""Authority leases with heartbeats: issuance is a moment, validity is a
stream of re-proofs, and silence revokes.

Wave-303 lane 6. Stdlib only. Additive: composes ``gov/ed25519``
(signatures) and ``gov/delegation_revocation.DelegationRevoker``
(per-delegator revoker sets, the wave-302/F379 model). Modifies none
of them.

ADAPT from the wave-302 continuous-authorization prospectus
(``~/workspace/teams/wave302-prospect/PROSPECTUS.md``):
apereo/cas ticket-typed lifecycles (typed authority, single-use
re-proofs), Microsoft Entra CAE (critical-event-driven invalidation,
not TTL-driven), oauth2-proxy (fail-closed on failed re-verification:
never serve a stale session), Janssen (idle knobs distinct from
absolute lifetime), authentik (session binding / designated
re-provers), ejbca (an explicit SUSPENDED state between valid and
revoked). The extracted standing rule:

    "Authority is a lease with a heartbeat -- issuance is a moment;
    validity is a stream of re-proofs, and silence revokes."

``AuthorityLeaseManager`` issues ed25519-signed leases
{lease_id, subject, scope_digest, issued_at, ttl, heartbeat_interval}.
A lease is ACTIVE only while a stream of heartbeat re-proofs arrives
inside the interval:

* each heartbeat is a signed proof by the subject (or a designated
  monitor) binding {lease_id, subject_id, scope_digest, counter,
  proof_issued_at}; counters are strictly monotonic (replay refuses),
  proofs bind the lease (cross-lease and foreign-signer proofs
  refuse);
* a missed interval marks the lease SUSPENDED (fail-closed:
  ``check()`` refuses) and journals the transition -- the stream can
  restart only via ``resume()`` with a FRESH heartbeat inside ttl;
* ttl expiry marks the lease EXPIRED (terminal, journaled);
* a per-delegator revoker entry targeting the lease id (granter's or
  subject's revoker, with per-revoker anti-substitution per the F379
  model) marks the lease REVOKED (terminal; a revoked lease never
  heartbeats, checks, or resumes back to life).

``suspend()`` / ``resume()`` are explicit operator/owner actions: the
caller presents an ed25519-signed authorization over
{action, lease_id, actor_id, at} and the actor must be the granter or
the subject (the stored pubkey is compared; forged or non-owner
authorizations refuse). Suspension PARKS the lease -- it never extends
ttl: resuming after ttl refuses ``authority-lifecycle-expired``.

Every issuance, heartbeat, suspension, resumption, revocation, and
expiry is journaled in a hash-chained in-memory journal;
``verify_evidence()`` replays the chain and reports tampering.
``check()`` is an evaluation (it may journal a missed-heartbeat
suspension or an expiry/revocation transition -- the oauth2-proxy
discipline: a failed re-verification invalidates immediately, never
limps on); ``state_of()`` is the pure query.

Coded refusals (3 minted by this lane; revoker-shape defects reuse the
delegation-revocation-* codes):
* ``authority-lifecycle-expired`` -- the lease is past its ttl.
* ``authority-lifecycle-heartbeat-lapsed`` -- the re-proof stream
  broke: missed window, replayed/stale/misbound/forged heartbeat,
  proof-subject mismatch, presentation of a suspended lease, or an
  invalid suspend/resume authorization. Silence revokes.
* ``authority-lifecycle-revoked`` -- a per-delegator revoker entry
  targets this lease; terminal.

Threat model: the granter key is the trust anchor (compromised-host
class); instants are caller-supplied (deployment clock -- a backwards
instant refuses heartbeat-lapsed, never silently passes); revocation
freshness is deployment-owned (a revocation record dated after the
evaluation instant is not yet effective at that instant); the journal
is in-memory (restart loses it -- persistence is deployment-owned).
The revoker list is verified on every evaluation; a tampered list
fails closed. Unknown lease ids are KeyError (caller bug, not a
refusal).

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import hashlib
import json
import math

from gov import delegation_revocation as _rv
from gov import ed25519 as _ed

# ---------------------------------------------------------------------------
# Codes (F351: every refusal carries one). Three minted by this lane.
# ---------------------------------------------------------------------------

AL_EXPIRED = "authority-lifecycle-expired"
AL_LAPSED = "authority-lifecycle-heartbeat-lapsed"
AL_REVOKED = "authority-lifecycle-revoked"

# ---------------------------------------------------------------------------
# Default heartbeat schedule (wave-304 lane D). The wave-303 prospectus
# refined rule: "A heartbeat is a re-proof, not a renewal -- silence
# revokes, and a missed proof never extends the lease." The schedule
# follows the fraction-of-lifetime convention (SPIRE uses 1/2 of
# lifetime; step-ca >2/3; Kubernetes 80%):
#
#   heartbeat_interval_seconds
#       = max(ceil(heartbeat_fraction * ttl_seconds),
#             remediation_floor_seconds)
#
# clamped to ttl_seconds: the default schedule can never violate the
# "interval must not exceed ttl" contract (an explicit interval is a
# hard override and still fails fast on that contract). The 60-second
# floor is the minimum lead time between the first due re-proof and
# expiry, so a missed proof still leaves remediation time; it is
# deliberately small relative to production lifetimes (minutes to
# hours) so it cannot swallow short synthetic leases -- and the clamp
# is the backstop when a deployment floor meets a shorter ttl.
# ---------------------------------------------------------------------------

HEARTBEAT_FRACTION_DEFAULT = 0.5
REMEDIATION_FLOOR_SECONDS_DEFAULT = 60

# Suspend/resume authorization action names (bound into the signed
# authorization).
ACT_SUSPEND = "authority-lifecycle-suspend"
ACT_RESUME = "authority-lifecycle-resume"

# Journal event kinds.
_KINDS = (
    "lease-issued",
    "heartbeat",
    "lease-suspended-missed-heartbeat",
    "lease-suspended-operator",
    "lease-resumed",
    "lease-revoked",
    "lease-expired",
)

_GENESIS_PREV = "0" * 64


class AuthorityLifecycleError(Exception):
    """Code-first exception for authority-lifecycle failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise AuthorityLifecycleError(detail, code=code)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ValueError("material is not JSON-canonicalizable: %r" % (e,))


def _shahex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _check_id(value, what):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("%s must be a 1-256 char string" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("%s must be a non-negative int instant" % what)


def _check_positive_int(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("%s must be a positive int" % what)


def _check_fraction(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not 0 < value <= 1:
        raise ValueError("heartbeat_fraction must be a number in (0, 1]")
    return value


def _check_seed(value, what):
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError("%s must be 32 bytes" % what)


def lease_id_for(granter_id, subject_id, scope_digest, issued_at):
    """Deterministic lease id: sha256 over the issuance identity."""
    _check_id(granter_id, "granter_id")
    _check_id(subject_id, "subject_id")
    if not _is_hex64(scope_digest):
        raise ValueError("scope_digest must be 64 lowercase hex")
    _check_ts(issued_at, "issued_at")
    return _shahex(_canonical({
        "granter_id": granter_id,
        "subject_id": subject_id,
        "scope_digest": scope_digest,
        "issued_at": issued_at,
    }))


def make_proof(*, lease_id, subject_id, scope_digest, counter,
               proof_issued_at, signer_id, signer_seed):
    """Build a signed heartbeat re-proof.

    The proof binds {lease_id, subject_id, scope_digest, counter,
    proof_issued_at, signer_id}. The signer must be the lease's
    subject or its designated monitor (enforced at ``heartbeat()``);
    the signature is checked there. Shape defects are ValueError
    (caller bug); semantic defects refuse coded at heartbeat time.
    """
    if not _is_hex64(lease_id):
        raise ValueError("lease_id must be 64 lowercase hex")
    _check_id(subject_id, "subject_id")
    if not _is_hex64(scope_digest):
        raise ValueError("scope_digest must be 64 lowercase hex")
    if not isinstance(counter, int) or isinstance(counter, bool) \
            or counter < 0:
        raise ValueError("counter must be a non-negative int")
    _check_ts(proof_issued_at, "proof_issued_at")
    _check_id(signer_id, "signer_id")
    _check_seed(signer_seed, "signer_seed")
    unsigned = {"lease_id": lease_id, "subject_id": subject_id,
                "scope_digest": scope_digest, "counter": counter,
                "proof_issued_at": proof_issued_at, "signer_id": signer_id}
    sig = _ed.sign(bytes(signer_seed), _canonical(unsigned))
    return dict(unsigned, signature=sig.hex())


def make_authorization(*, action, lease_id, actor_id, actor_seed, at):
    """Build a signed suspend/resume authorization.

    The actor signs {action, lease_id, actor_id, at}. The manager
    checks the actor is the lease's granter or subject, that the
    presented pubkey matches the stored one (no substitution), and
    that the signature verifies. Shape defects are ValueError.
    """
    if action not in (ACT_SUSPEND, ACT_RESUME):
        raise ValueError("action must be %r or %r" % (ACT_SUSPEND,
                                                      ACT_RESUME))
    if not _is_hex64(lease_id):
        raise ValueError("lease_id must be 64 lowercase hex")
    _check_id(actor_id, "actor_id")
    _check_seed(actor_seed, "actor_seed")
    _check_ts(at, "at")
    unsigned = {"action": action, "lease_id": lease_id,
                "actor_id": actor_id, "at": at}
    sig = _ed.sign(bytes(actor_seed), _canonical(unsigned))
    return dict(unsigned,
                actor_pubkey_hex=_ed.publickey(bytes(actor_seed)).hex(),
                signature=sig.hex())


class AuthorityLeaseManager:
    """Issues and evaluates heartbeat authority leases.

    ``revokers`` is the per-delegator revoker mapping
    {delegator_id: DelegationRevoker} (the wave-302/F379 model): a
    revoker entry targeting a lease id kills that lease. A revoker
    whose ``delegator_id`` does not match the mapping key is ignored
    (anti-substitution). ``journal_sink``, when set, receives a copy
    of every journaled event.
    """

    def __init__(self, revokers=None, journal_sink=None):
        self._revokers = dict(revokers) if revokers else {}
        for key, revoker in self._revokers.items():
            if not isinstance(revoker, _rv.DelegationRevoker):
                raise ValueError("revokers must map delegator_id -> "
                                 "DelegationRevoker")
            _check_id(key, "revoker mapping key")
        if journal_sink is not None and not callable(journal_sink):
            raise ValueError("journal_sink must be callable")
        self._sink = journal_sink
        self._leases = {}  # lease_id -> lease record (mutable runtime state)
        self._journal = []  # hash-chained evidence entries (live dicts)

    # -- issuance --------------------------------------------------------

    def issue_lease(self, *, granter_id, granter_seed, subject_id,
                    subject_pubkey_hex, scope_digest, issued_at,
                    ttl_seconds, heartbeat_interval_seconds=None,
                    heartbeat_fraction=HEARTBEAT_FRACTION_DEFAULT,
                    remediation_floor_seconds=
                    REMEDIATION_FLOOR_SECONDS_DEFAULT,
                    monitor_id=None, monitor_pubkey_hex=None,
                    lease_id=None):
        """Issue a granter-signed authority lease.

        The granter's signature binds the full issuance body. The
        lease id defaults to ``lease_id_for(...)`` (deterministic).

        Heartbeat schedule (wave-304 lane D, the wave-303 prospectus
        refined rule): when ``heartbeat_interval_seconds`` is not
        given, the interval is derived as
        ``max(ceil(heartbeat_fraction * ttl_seconds),
        remediation_floor_seconds)``, clamped to ``ttl_seconds`` so
        the default schedule can never violate the interval <= ttl
        contract (the floor must not swallow the ttl). An explicit
        interval is a hard override and still fails fast when it
        exceeds ``ttl_seconds`` (a lease that expires before any
        heartbeat is due cannot carry a heartbeat stream).

        Scheduling arithmetic only: the heartbeat remains a re-proof,
        never an extension. The derived schedule is recorded on the
        lease-issued journal entry (the auditor evidence event).
        Returns the lease record.
        """
        _check_id(granter_id, "granter_id")
        _check_seed(granter_seed, "granter_seed")
        _check_id(subject_id, "subject_id")
        if not _is_hex64(subject_pubkey_hex):
            raise ValueError("subject_pubkey_hex must be 64 lowercase hex")
        if not _is_hex64(scope_digest):
            raise ValueError("scope_digest must be 64 lowercase hex")
        _check_ts(issued_at, "issued_at")
        _check_positive_int(ttl_seconds, "ttl_seconds")
        heartbeat_fraction = _check_fraction(heartbeat_fraction)
        _check_positive_int(remediation_floor_seconds,
                            "remediation_floor_seconds")
        if heartbeat_interval_seconds is None:
            # Default schedule (wave-304 lane D); see the banner above
            # and the issue_lease docstring for the formula.
            schedule = "derived"
            heartbeat_interval_seconds = max(
                math.ceil(heartbeat_fraction * ttl_seconds),
                remediation_floor_seconds)
            if heartbeat_interval_seconds > ttl_seconds:
                heartbeat_interval_seconds = ttl_seconds
        else:
            schedule = "explicit"
            _check_positive_int(heartbeat_interval_seconds,
                                "heartbeat_interval_seconds")
            if heartbeat_interval_seconds > ttl_seconds:
                raise ValueError("heartbeat_interval_seconds must not "
                                 "exceed ttl_seconds")
        if monitor_pubkey_hex is not None:
            if not _is_hex64(monitor_pubkey_hex):
                raise ValueError("monitor_pubkey_hex must be 64 lowercase "
                                 "hex")
            if monitor_id is None:
                monitor_id = "monitor"
            _check_id(monitor_id, "monitor_id")
            if monitor_id == subject_id:
                raise ValueError("monitor_id must differ from subject_id")
        elif monitor_id is not None:
            raise ValueError("monitor_id without monitor_pubkey_hex")
        lease_id = (lease_id_for(granter_id, subject_id, scope_digest,
                                 issued_at)
                    if lease_id is None else lease_id)
        if not _is_hex64(lease_id):
            raise ValueError("lease_id must be 64 lowercase hex")
        if lease_id in self._leases:
            raise ValueError("lease_id already issued by this manager")

        body = {"lease_id": lease_id, "granter_id": granter_id,
                "subject_id": subject_id,
                "subject_pubkey_hex": subject_pubkey_hex,
                "monitor_id": monitor_id,
                "monitor_pubkey_hex": monitor_pubkey_hex,
                "scope_digest": scope_digest, "issued_at": issued_at,
                "ttl_seconds": ttl_seconds,
                "heartbeat_interval_seconds": heartbeat_interval_seconds}
        granter_pub = _ed.publickey(bytes(granter_seed))
        sig = _ed.sign(bytes(granter_seed), _canonical(body))
        lease = dict(body,
                     granter_pubkey_hex=granter_pub.hex(),
                     granter_signature=sig.hex(),
                     # Mutable runtime state (transitions are journaled).
                     last_heartbeat_at=issued_at,
                     last_heartbeat_counter=0,
                     suspended=False, suspended_at=None,
                     revoked=False, expired=False)
        self._leases[lease_id] = lease
        self._append("lease-issued", lease_id, issued_at,
                     {"granter_id": granter_id, "subject_id": subject_id,
                      "scope_digest": scope_digest,
                      "ttl_seconds": ttl_seconds,
                      "heartbeat_interval_seconds":
                          heartbeat_interval_seconds,
                      "heartbeat_fraction": heartbeat_fraction,
                      "remediation_floor_seconds":
                          remediation_floor_seconds,
                      "schedule": schedule})
        return dict(lease)

    # -- evaluation ------------------------------------------------------

    def _revoked_at(self, lease, at):
        """Scan the per-delegator revokers for a live entry targeting
        this lease (F379 model). Returns the revocation record or None.

        Anti-substitution: a revoker is consulted only when its own
        ``delegator_id`` matches the mapping key it was registered
        under; each record must name the same delegator. Only records
        with ``revoked_at <= at`` are effective at instant ``at``.
        """
        lease_id = lease["lease_id"]
        for delegator_id in (lease["granter_id"], lease["subject_id"]):
            revoker = self._revokers.get(delegator_id)
            if revoker is None:
                continue
            if revoker.delegator_id != delegator_id:
                # Does not speak for this delegator: ignore (F379
                # anti-substitution).
                continue
            try:
                ok = revoker.verify_list()
            except Exception as e:  # noqa: BLE001 -- fail closed
                _fail(AL_LAPSED,
                      "revoker list for %r failed verification: %r "
                      "(fail closed)" % (delegator_id, e))
            if ok is not True:
                _fail(AL_LAPSED,
                      "revoker list for %r did not verify (fail closed)"
                      % (delegator_id,))
            for record in revoker.export_list():
                if record.get("target_receipt_id") != lease_id:
                    continue
                if record.get("delegator_id") != delegator_id:
                    continue
                if not isinstance(record.get("revoked_at"), int):
                    continue
                if record["revoked_at"] <= at:
                    return record
        return None

    def _evaluate(self, lease, at):
        """Pure state evaluation at instant ``at`` (no transitions, no
        journaling). Returns one of ACTIVE / SUSPENDED / LAPSED /
        EXPIRED / REVOKED. LAPSED means the heartbeat interval was
        missed but the suspension transition has not been journaled
        yet -- the lease is not valid in this state."""
        _check_ts(at, "at")
        if lease["revoked"] or self._revoked_at(lease, at) is not None:
            return "REVOKED"
        if lease["expired"] or at > lease["issued_at"] + lease["ttl_seconds"]:
            return "EXPIRED"
        if lease["suspended"]:
            return "SUSPENDED"
        if at < lease["last_heartbeat_at"]:
            # Backwards evaluation instant: refuse, never silently pass.
            return "LAPSED"
        if at - lease["last_heartbeat_at"] \
                > lease["heartbeat_interval_seconds"]:
            return "LAPSED"
        return "ACTIVE"

    def _get(self, lease_id):
        if not _is_hex64(lease_id):
            raise ValueError("lease_id must be 64 lowercase hex")
        try:
            return self._leases[lease_id]
        except KeyError:
            raise KeyError("unknown lease_id: %r" % (lease_id,))

    def _transition(self, lease, at, to_state, kind, fields=None):
        lease[{"SUSPENDED": "suspended",
               "REVOKED": "revoked",
               "EXPIRED": "expired"}[to_state]] = True
        if to_state == "SUSPENDED":
            lease["suspended_at"] = at
        self._append(kind, lease["lease_id"], at, fields or {})

    def state_of(self, lease_id, *, at):
        """Pure query: the lease's state at instant ``at``."""
        return self._evaluate(self._get(lease_id), at)

    def check(self, lease_id, *, at):
        """Evaluate a lease at instant ``at``; fail closed.

        ACTIVE returns a verdict dict. A missed heartbeat journals a
        suspension transition (the oauth2-proxy discipline: a failed
        re-verification invalidates immediately). Revocation and
        expiry journal their terminal transitions on first detection.
        Every non-ACTIVE outcome raises a coded refusal.
        """
        lease = self._get(lease_id)
        state = self._evaluate(lease, at)
        if state == "REVOKED":
            if not lease["revoked"]:
                self._transition(lease, at, "REVOKED", "lease-revoked")
            _fail(AL_REVOKED,
                  "lease %r is revoked (per-delegator revoker entry)"
                  % (lease_id,))
        if state == "EXPIRED":
            if not lease["expired"]:
                self._transition(lease, at, "EXPIRED", "lease-expired")
            _fail(AL_EXPIRED,
                  "lease %r is past its ttl (expired at %d)"
                  % (lease_id, lease["issued_at"] + lease["ttl_seconds"]))
        if state == "SUSPENDED":
            _fail(AL_LAPSED,
                  "lease %r is suspended: the heartbeat stream lapsed; "
                  "resume with a fresh heartbeat" % (lease_id,))
        if state == "LAPSED":
            # Silence revokes: journal the suspension now.
            self._transition(lease, at, "SUSPENDED",
                             "lease-suspended-missed-heartbeat",
                             {"last_heartbeat_at":
                                  lease["last_heartbeat_at"]})
            _fail(AL_LAPSED,
                  "lease %r missed its heartbeat window (silence "
                  "revokes); suspended" % (lease_id,))
        return {"lease_id": lease_id, "state": "ACTIVE",
                "last_heartbeat_at": lease["last_heartbeat_at"],
                "last_heartbeat_counter": lease["last_heartbeat_counter"],
                "next_heartbeat_due": (lease["last_heartbeat_at"]
                                       + lease["heartbeat_interval_seconds"]),
                "expires_at": lease["issued_at"] + lease["ttl_seconds"]}

    # -- heartbeats ------------------------------------------------------

    def _verify_proof(self, lease, proof, at, *, fresh=False):
        """Verify a heartbeat proof against the lease; coded refusal on
        any defect. With ``fresh=True`` (resume path) the proof must
        also be fresh: issued within one heartbeat interval of ``at``.
        """
        if not isinstance(proof, dict):
            _fail(AL_LAPSED, "heartbeat proof must be a dict")
        for field in ("lease_id", "subject_id", "scope_digest", "counter",
                      "proof_issued_at", "signer_id", "signature"):
            if field not in proof:
                _fail(AL_LAPSED,
                      "heartbeat proof missing %r" % (field,))
        if proof["lease_id"] != lease["lease_id"]:
            _fail(AL_LAPSED,
                  "heartbeat proof is bound to a different lease")
        if proof["subject_id"] != lease["subject_id"]:
            _fail(AL_LAPSED, "heartbeat proof subject mismatch")
        if proof["scope_digest"] != lease["scope_digest"]:
            _fail(AL_LAPSED, "heartbeat proof scope mismatch")
        signer_id = proof["signer_id"]
        if signer_id == lease["subject_id"]:
            signer_pub = lease["subject_pubkey_hex"]
        elif lease["monitor_id"] is not None and signer_id == lease[
                "monitor_id"]:
            signer_pub = lease["monitor_pubkey_hex"]
        else:
            _fail(AL_LAPSED,
                  "heartbeat signer %r is neither the subject nor the "
                  "designated monitor" % (signer_id,))
        unsigned = {k: proof[k] for k in (
            "lease_id", "subject_id", "scope_digest", "counter",
            "proof_issued_at", "signer_id")}
        try:
            sig_ok = _ed.verify(bytes.fromhex(signer_pub),
                                _canonical(unsigned),
                                bytes.fromhex(proof["signature"]))
        except (ValueError, TypeError):
            _fail(AL_LAPSED, "heartbeat proof has malformed key material")
        if sig_ok is not True:
            _fail(AL_LAPSED, "heartbeat proof signature does not verify")
        counter = proof["counter"]
        if not isinstance(counter, int) or isinstance(counter, bool):
            _fail(AL_LAPSED, "heartbeat counter must be an int")
        if counter <= lease["last_heartbeat_counter"]:
            _fail(AL_LAPSED,
                  "heartbeat counter %d does not advance past %d "
                  "(replayed heartbeat)" % (
                      counter, lease["last_heartbeat_counter"]))
        pia = proof["proof_issued_at"]
        if not isinstance(pia, int) or isinstance(pia, bool):
            _fail(AL_LAPSED, "proof_issued_at must be an int")
        if pia > at or pia < lease["last_heartbeat_at"]:
            _fail(AL_LAPSED,
                  "heartbeat proof is not fresh relative to the stream "
                  "(proof_issued_at=%r)" % (pia,))
        if fresh and at - pia > lease["heartbeat_interval_seconds"]:
            _fail(AL_LAPSED,
                  "resume requires a fresh heartbeat proof (issued "
                  "within one interval of now)")

    def heartbeat(self, lease_id, proof, *, at):
        """Accept one heartbeat re-proof for a lease.

        The lease's state is evaluated first (revoked/expired/
        suspended/lapsed all refuse coded, with the missed-heartbeat
        suspension journaled). Then the proof is verified: binding,
        signer, signature, strictly-advancing counter, freshness.
        Returns the acceptance record; journals the heartbeat.
        """
        lease = self._get(lease_id)
        # State first: a dead lease never accepts a heartbeat.
        state = self._evaluate(lease, at)
        if state != "ACTIVE":
            # Reuse check()'s transition + coded-refusal logic.
            self.check(lease_id, at=at)
            _fail(AL_LAPSED, "unreachable")  # check() always raises here
        self._verify_proof(lease, proof, at)
        lease["last_heartbeat_at"] = at
        lease["last_heartbeat_counter"] = proof["counter"]
        self._append("heartbeat", lease_id, at,
                     {"counter": proof["counter"],
                      "signer_id": proof["signer_id"]})
        return {"lease_id": lease_id, "counter": proof["counter"],
                "accepted_at": at, "state": "ACTIVE"}

    # -- suspend / resume -------------------------------------------------

    def _verify_authorization(self, lease, authorization, action, at):
        """Verify an operator/owner authorization: the actor must be
        the granter or the subject, the presented pubkey must match the
        stored one (no substitution), and the signature must verify.
        Coded refusal (AL_LAPSED) on any defect."""
        if not isinstance(authorization, dict):
            _fail(AL_LAPSED, "authorization must be a dict")
        for field in ("action", "lease_id", "actor_id",
                      "actor_pubkey_hex", "at", "signature"):
            if field not in authorization:
                _fail(AL_LAPSED, "authorization missing %r" % (field,))
        if authorization["action"] != action:
            _fail(AL_LAPSED,
                  "authorization action %r is not %r"
                  % (authorization["action"], action))
        if authorization["lease_id"] != lease["lease_id"]:
            _fail(AL_LAPSED, "authorization is for a different lease")
        if authorization["at"] != at:
            _fail(AL_LAPSED,
                  "authorization instant does not match the call instant")
        actor_id = authorization["actor_id"]
        if actor_id == lease["granter_id"]:
            stored_pub = lease["granter_pubkey_hex"]
        elif actor_id == lease["subject_id"]:
            stored_pub = lease["subject_pubkey_hex"]
        else:
            _fail(AL_LAPSED,
                  "authorization actor %r is neither the granter nor the "
                  "subject" % (actor_id,))
        if authorization["actor_pubkey_hex"] != stored_pub:
            _fail(AL_LAPSED,
                  "authorization pubkey does not match the stored %s key "
                  "(substitution)" % (actor_id,))
        unsigned = {"action": action, "lease_id": lease["lease_id"],
                    "actor_id": actor_id, "at": at}
        try:
            sig_ok = _ed.verify(bytes.fromhex(stored_pub),
                                _canonical(unsigned),
                                bytes.fromhex(authorization["signature"]))
        except (ValueError, TypeError):
            _fail(AL_LAPSED, "authorization has malformed key material")
        if sig_ok is not True:
            _fail(AL_LAPSED,
                  "authorization signature does not verify for %r"
                  % (actor_id,))

    def suspend(self, lease_id, *, authorization, at):
        """Explicitly suspend a lease (operator/owner-authorized).

        Parks the lease WITHOUT extending ttl. Idempotent: suspending
        an already-suspended lease is a no-op verdict. Revoked and
        expired leases refuse coded.
        """
        lease = self._get(lease_id)
        self._verify_authorization(lease, authorization, ACT_SUSPEND, at)
        state = self._evaluate(lease, at)
        if state == "REVOKED":
            if not lease["revoked"]:
                self._transition(lease, at, "REVOKED", "lease-revoked")
            _fail(AL_REVOKED, "lease %r is revoked" % (lease_id,))
        if state == "EXPIRED":
            if not lease["expired"]:
                self._transition(lease, at, "EXPIRED", "lease-expired")
            _fail(AL_EXPIRED, "lease %r is expired" % (lease_id,))
        if state == "LAPSED":
            self._transition(lease, at, "SUSPENDED",
                             "lease-suspended-missed-heartbeat",
                             {"last_heartbeat_at":
                                  lease["last_heartbeat_at"]})
            return {"lease_id": lease_id, "state": "SUSPENDED",
                    "suspended_at": at, "via": "missed-heartbeat"}
        if lease["suspended"]:
            return {"lease_id": lease_id, "state": "SUSPENDED",
                    "suspended_at": lease["suspended_at"], "noop": True}
        self._transition(lease, at, "SUSPENDED",
                         "lease-suspended-operator",
                         {"actor_id": authorization["actor_id"]})
        return {"lease_id": lease_id, "state": "SUSPENDED",
                "suspended_at": at}

    def resume(self, lease_id, *, authorization, proof, at):
        """Resume a suspended lease with a fresh heartbeat.

        Re-verifies the operator/owner authorization, requires the
        lease to be suspended and inside ttl, then requires a FRESH
        heartbeat proof (issued within one interval of ``at``) that
        advances the stream. Revoked leases never resume; resuming
        past ttl refuses expired (the suspension parked, never
        extended).
        """
        lease = self._get(lease_id)
        self._verify_authorization(lease, authorization, ACT_RESUME, at)
        state = self._evaluate(lease, at)
        if state == "REVOKED":
            if not lease["revoked"]:
                self._transition(lease, at, "REVOKED", "lease-revoked")
            _fail(AL_REVOKED,
                  "lease %r is revoked and never resumes" % (lease_id,))
        if state == "EXPIRED":
            if not lease["expired"]:
                self._transition(lease, at, "EXPIRED", "lease-expired")
            _fail(AL_EXPIRED,
                  "lease %r is past its ttl; suspension did not extend it"
                  % (lease_id,))
        if state != "SUSPENDED":
            raise ValueError("resume() requires a suspended lease "
                             "(state=%s)" % (state,))
        self._verify_proof(lease, proof, at, fresh=True)
        lease["suspended"] = False
        lease["suspended_at"] = None
        self._append("lease-resumed", lease_id, at,
                     {"actor_id": authorization["actor_id"],
                      "counter": proof["counter"]})
        lease["last_heartbeat_at"] = at
        lease["last_heartbeat_counter"] = proof["counter"]
        self._append("heartbeat", lease_id, at,
                     {"counter": proof["counter"],
                      "signer_id": proof["signer_id"],
                      "via": "resume"})
        return {"lease_id": lease_id, "state": "ACTIVE",
                "counter": proof["counter"], "resumed_at": at}

    # -- evidence ----------------------------------------------------------

    @property
    def journal(self):
        """The live hash-chained evidence journal (list of dicts).

        Entries are returned live: mutating them is tampering, and
        ``verify_evidence()`` detects it. Read, don't write.
        """
        return self._journal

    def _append(self, kind, lease_id, at, fields):
        if kind not in _KINDS:
            raise ValueError("unknown journal kind %r" % (kind,))
        prev = self._journal[-1]["digest"] if self._journal \
            else _GENESIS_PREV
        entry = {"seq": len(self._journal), "at": at, "kind": kind,
                 "lease_id": lease_id, "fields": dict(fields),
                 "prev": prev}
        entry["digest"] = _shahex(_canonical(
            {"seq": entry["seq"], "at": at, "kind": kind,
             "lease_id": lease_id, "fields": entry["fields"],
             "prev": prev}))
        self._journal.append(entry)
        if self._sink is not None:
            self._sink(dict(entry))

    def verify_evidence(self):
        """Replay the journal: chain linkage, digest recomputation,
        known kinds, required fields. Returns {"ok", "events",
        "failure"}. A tampered entry fails the replay -- evidence,
        never authority."""
        prev = _GENESIS_PREV
        for i, entry in enumerate(self._journal):
            if not isinstance(entry, dict):
                return {"ok": False, "events": len(self._journal),
                        "failure": "entry %d is not a dict" % i}
            for field in ("seq", "at", "kind", "lease_id", "fields",
                          "prev", "digest"):
                if field not in entry:
                    return {"ok": False, "events": len(self._journal),
                            "failure": "entry %d missing %r" % (i, field)}
            if entry["seq"] != i or entry["prev"] != prev:
                return {"ok": False, "events": len(self._journal),
                        "failure": "entry %d breaks the chain" % i}
            if entry["kind"] not in _KINDS:
                return {"ok": False, "events": len(self._journal),
                        "failure": "entry %d has unknown kind %r"
                                   % (i, entry["kind"])}
            expect = _shahex(_canonical(
                {"seq": entry["seq"], "at": entry["at"],
                 "kind": entry["kind"], "lease_id": entry["lease_id"],
                 "fields": entry["fields"], "prev": entry["prev"]}))
            if entry["digest"] != expect:
                return {"ok": False, "events": len(self._journal),
                        "failure": "entry %d digest mismatch (tampered)"
                                   % i}
            prev = entry["digest"]
        return {"ok": True, "events": len(self._journal), "failure": None}
