"""Seata-style branch registration + XID propagation + coordinator-driven
commit/rollback + lease-across-suspension for multi-step agent workflows.

ADAPT from apache/seata (Apache-2.0): the XID is propagated through the
invoke chain, every branch registers with the coordinator BEFORE it may
commit, and a single signed coordinator decision drives commit/rollback.
Rebuilt on Sasanam discipline (stdlib only, no network, no Java).

Standing design rule: "A workflow outlives its runner -- every step is
checkpointed, and every resume re-proves its authority."

THREAT MODEL: the coordinator seed is the trust anchor (compromised-host
class if stolen). Instants are caller-supplied freshness markers, not a
trusted clock. XIDs are 64-hex random ids -- uniqueness rests on the
standard os.urandom assumption. The lease manager passed to
suspend/resume is deployment-owned; this module never mints leases.

DECISION CODES (3 new, domain ``workflow-branch``):
- ``workflow-branch-xid-mismatch`` (high): a step ran without the
  expected XID, or a decision package was applied under the wrong XID.
- ``workflow-branch-unregistered`` (high): an unregistered branch tried
  to apply a coordinator decision (registration must precede commit).
- ``workflow-branch-decision-forgery`` (critical): the coordinator
  decision's signature does not verify under the coordinator's key.

Reused (not minted): ``coord-lease-expired`` / ``coord-lease-fencing``
for suspension resume refusals; ``decision-code-malformed`` for shape
errors; ``coord-lease-denied`` for duplicate branch registration.
"""

import hashlib
import json
import os
import re

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1812 -> 1815).
# ---------------------------------------------------------------------------

WB_XID_MISMATCH = "workflow-branch-xid-mismatch"
WB_UNREGISTERED = "workflow-branch-unregistered"
WB_DECISION_FORGERY = "workflow-branch-decision-forgery"

# Reused (not minted): lease refusals and shape errors.
LEASE_EXPIRED = "coord-lease-expired"
LEASE_FENCING = "coord-lease-fencing"
MALFORMED = "decision-code-malformed"
LEASE_DENIED = "coord-lease-denied"

__all__ = [
    "BranchCoordinator",
    "WorkflowBranchError",
    "WB_XID_MISMATCH",
    "WB_UNREGISTERED",
    "WB_DECISION_FORGERY",
    "_canonical_decision_body",
]

_XID_RE = re.compile(r"^[0-9a-f]{64}$")
_BRANCH_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

_COMMIT = "commit"
_ROLLBACK = "rollback"


class WorkflowBranchError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = MALFORMED

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise WorkflowBranchError(detail, code=code)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(MALFORMED, "branch material is not canonicalizable "
                         "(circular or non-JSON structure)")


def _check_xid(value, what="xid"):
    if not isinstance(value, str) or not _XID_RE.match(value):
        _fail(MALFORMED, "%s must be 64 lowercase hex; got %r"
              % (what, value))


def _check_branch_id(value):
    if not isinstance(value, str) or not _BRANCH_RE.match(value):
        _fail(MALFORMED, "branch_id must match [a-z][a-z0-9-]{0,63}; "
                         "got %r" % (value,))


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(MALFORMED, "%s must be a non-negative int" % what)


def _canonical_decision_body(package):
    """The exact bytes the coordinator signs (and verifiers re-check):
    the package minus the signature envelope."""
    body = {k: package[k] for k in ("xid", "decision", "votes_digest",
                                    "coordinator_pubkey", "decided_at")
            if k in package}
    return _canonical(body)


class BranchCoordinator:
    """Seata-style transaction coordinator (in-memory, deployment-owned).

    ``begin`` mints an XID bound to the coordinator's public key.
    Branches ``register_branch`` before they may record steps or apply
    decisions. Votes are collected; ``decide`` issues ONE signed
    decision; branches ``apply_decision`` it. Suspension parks a
    coordination lease with the transaction and re-validates it --
    never silently extends it -- on resume.
    """

    def __init__(self):
        self._txns = {}  # xid -> transaction record

    # -- transaction lifecycle --------------------------------------

    def begin(self, coordinator_seed, xid=None):
        """Open a transaction. Returns the XID. The coordinator's
        public key is pinned to the transaction at begin time."""
        if not isinstance(coordinator_seed, bytes) or \
                len(coordinator_seed) != 32:
            _fail(MALFORMED, "coordinator_seed must be 32 raw bytes")
        if xid is None:
            xid = os.urandom(32).hex()
        _check_xid(xid)
        if xid in self._txns:
            _fail(MALFORMED, "xid %s already begun" % xid[:12])
        pubkey = ed25519.publickey(coordinator_seed).hex()
        self._txns[xid] = {
            "xid": xid,
            "coordinator_pubkey": pubkey,
            "state": "open",
            "branches": {},   # branch_id -> record
            "decision": None,
        }
        return xid

    def _txn(self, xid):
        _check_xid(xid)
        txn = self._txns.get(xid)
        if txn is None:
            _fail(MALFORMED, "unknown xid %s" % xid[:12])
        return txn

    # -- branch registration (BEFORE commit) -------------------------

    def register_branch(self, xid, branch_id, participant_id):
        """Register a participant branch. Refuses coded
        ``coord-lease-denied`` on duplicate branch_id (a second
        registration would silently replace the first)."""
        txn = self._txn(xid)
        _check_branch_id(branch_id)
        if not isinstance(participant_id, str) or not participant_id:
            _fail(MALFORMED, "participant_id must be a non-empty string")
        if txn["state"] != "open":
            _fail(MALFORMED, "transaction %s is %s, not open"
                  % (xid[:12], txn["state"]))
        if branch_id in txn["branches"]:
            _fail(LEASE_DENIED, "branch %r already registered on xid %s"
                  % (branch_id, xid[:12]))
        txn["branches"][branch_id] = {
            "participant_id": participant_id,
            "vote": None,
            "steps": 0,
            "applied": None,
        }

    def _branch(self, txn, branch_id):
        _check_branch_id(branch_id)
        branch = txn["branches"].get(branch_id)
        if branch is None:
            _fail(WB_UNREGISTERED,
                  "branch %r is not registered on xid %s -- registration "
                  "must precede commit" % (branch_id, txn["xid"][:12]))
        return branch

    # -- XID-propagated steps -----------------------------------------

    def record_step(self, xid, branch_id, step_record):
        """Record one step's execution. The step MUST carry the
        transaction's XID -- a step running without the expected XID
        refuses coded ``workflow-branch-xid-mismatch``."""
        txn = self._txn(xid)
        branch = self._branch(txn, branch_id)
        if not isinstance(step_record, dict):
            _fail(MALFORMED, "step_record must be a dict")
        if step_record.get("xid") != xid:
            _fail(WB_XID_MISMATCH,
                  "step on branch %r ran under xid %r, expected %s"
                  % (branch_id, step_record.get("xid"), xid[:12]))
        branch["steps"] += 1

    def branch_state(self, xid, branch_id):
        txn = self._txn(xid)
        branch = self._branch(txn, branch_id)
        return {"steps": branch["steps"], "vote": branch["vote"],
                "applied": branch["applied"]}

    # -- voting --------------------------------------------------------

    def vote(self, xid, branch_id, vote):
        """A registered branch votes ``commit`` or ``rollback``."""
        txn = self._txn(xid)
        branch = self._branch(txn, branch_id)
        if vote not in (_COMMIT, _ROLLBACK):
            _fail(MALFORMED, "vote must be 'commit' or 'rollback'")
        if txn["state"] != "open":
            _fail(MALFORMED, "transaction %s is %s, not open"
                  % (xid[:12], txn["state"]))
        branch["vote"] = vote

    # -- coordinator decision -------------------------------------------

    def decide(self, xid, decision, coordinator_seed, decided_at=None):
        """Issue the single signed coordinator decision. Requires every
        registered branch to have voted. The decision commits to the
        vote vector digest so a decision over different votes is
        detectable. ``decided_at`` is a caller-supplied instant
        (freshness marker, not a trusted clock); it may be None."""
        txn = self._txn(xid)
        if decision not in (_COMMIT, _ROLLBACK):
            _fail(MALFORMED, "decision must be 'commit' or 'rollback'")
        if not isinstance(coordinator_seed, bytes) or \
                len(coordinator_seed) != 32:
            _fail(MALFORMED, "coordinator_seed must be 32 raw bytes")
        if ed25519.publickey(coordinator_seed).hex() != \
                txn["coordinator_pubkey"]:
            _fail(WB_DECISION_FORGERY,
                  "decide called with a seed that is not the transaction's "
                  "coordinator key")
        if txn["state"] != "open":
            _fail(MALFORMED, "transaction %s already decided" % xid[:12])
        unvoted = [b for b, r in txn["branches"].items()
                   if r["vote"] is None]
        if unvoted:
            _fail(MALFORMED, "branches have not voted: %s"
                  % sorted(unvoted))
        votes = {b: r["vote"] for b, r in
                 sorted(txn["branches"].items())}
        votes_digest = hashlib.sha256(_canonical(votes)).hexdigest()
        body = {
            "xid": xid,
            "decision": decision,
            "votes_digest": votes_digest,
            "coordinator_pubkey": txn["coordinator_pubkey"],
            "decided_at": None,  # caller-supplied instant, see below
        }
        if decided_at is not None:
            _check_ts(decided_at, "decided_at")
        return self._sign_decision(body, coordinator_seed, decided_at)

    def _sign_decision(self, body, coordinator_seed, decided_at):
        body = dict(body)
        body["decided_at"] = decided_at
        sig = ed25519.sign(coordinator_seed,
                           _canonical_decision_body(body)).hex()
        package = dict(body)
        package["signature"] = sig
        return package

    def apply_decision(self, xid, branch_id, package):
        """Apply the coordinator's decision at a branch. Verifies, in
        order: XID binding, branch registration, coordinator
        signature. Returns True."""
        txn = self._txn(xid)
        if not isinstance(package, dict):
            _fail(MALFORMED, "decision package must be a dict")
        if package.get("xid") != xid:
            _fail(WB_XID_MISMATCH,
                  "decision package is for xid %r, applied under %s"
                  % (package.get("xid"), xid[:12]))
        branch = self._branch(txn, branch_id)
        signature = package.get("signature")
        if not isinstance(signature, str):
            _fail(WB_DECISION_FORGERY,
                  "decision package carries no signature")
        try:
            pub = bytes.fromhex(txn["coordinator_pubkey"])
            sig = bytes.fromhex(signature)
        except (ValueError, TypeError):
            _fail(WB_DECISION_FORGERY,
                  "decision package has malformed key/signature encoding")
        ok = ed25519.verify(pub, _canonical_decision_body(package), sig)
        if ok is not True:
            _fail(WB_DECISION_FORGERY,
                  "coordinator decision signature does not verify under "
                  "the transaction's coordinator key")
        decision = package.get("decision")
        if decision not in (_COMMIT, _ROLLBACK):
            _fail(MALFORMED, "decision package has bad decision %r"
                  % (decision,))
        branch["applied"] = decision
        if all(r["applied"] is not None
               for r in txn["branches"].values()):
            txn["state"] = ("committed" if decision == _COMMIT
                            else "rolled-back")
            txn["decision"] = decision
        return True

    def transaction_state(self, xid):
        return self._txn(xid)["state"]

    # -- lease-across-suspension ----------------------------------------

    def suspend_lease(self, xid, lease_manager, scope, fencing_token,
                      holder_id, suspended_at):
        """Park a coordination lease with the suspension record. The
        lease is NOT renewed or extended -- the record captures the
        fencing token, holder, and the suspension instant so resume
        can re-validate liveness. The XID and the coordinator's public
        key are bound into the record; resume re-resolves the XID
        against this coordinator's live transactions and requires the
        presented record to match the parked one exactly (F385)."""
        txn = self._txn(xid)
        _check_ts(suspended_at, "suspended_at")
        if not isinstance(lease_manager, object) or \
                not hasattr(lease_manager, "check_write"):
            _fail(MALFORMED, "lease_manager must expose check_write")
        record = {
            "xid": xid,
            "scope": scope,
            "fencing_token": fencing_token,
            "holder_id": holder_id,
            "suspended_at": suspended_at,
            "coordinator_pubkey": txn["coordinator_pubkey"],
        }
        # F385: the coordinator remembers exactly what it parked. A
        # suspension record is a bearer token -- without this memory,
        # a caller could edit the xid field and resume under a
        # different transaction. resume_lease compares the presented
        # record against this parked copy.
        txn["suspension"] = dict(record)
        return record

    def resume_lease(self, suspension, lease_manager, checked_at):
        """Re-validate the parked lease. Fail-closed: an expired lease
        refuses ``coord-lease-expired``; a stale fencing token refuses
        ``coord-lease-fencing``. The lease's expiry is NEVER extended
        by suspend/resume -- the deployment must renew explicitly via
        the lease manager if it wants more time.

        F385: the suspension's XID is resolved against this
        coordinator's live transactions -- unknown XIDs refuse coded
        (``decision-code-malformed``), and so do transactions that are
        no longer open (committed / rolled-back). The presented record
        must then match, field for field, the suspension parked for
        that XID by ``suspend_lease``: a record parked under xid_A
        cannot resume under xid_B, even when both transactions belong
        to the same coordinator. Mismatch refuses
        ``workflow-branch-xid-mismatch``.
        """
        if not isinstance(suspension, dict):
            _fail(MALFORMED, "suspension must be a dict")
        _check_ts(checked_at, "checked_at")
        for key in ("xid", "scope", "fencing_token", "holder_id",
                    "coordinator_pubkey"):
            if key not in suspension:
                _fail(MALFORMED, "suspension is missing %r" % key)
        _check_xid(suspension["xid"])
        pubkey = suspension["coordinator_pubkey"]
        if not isinstance(pubkey, str) or not pubkey:
            _fail(MALFORMED, "suspension coordinator_pubkey must be a "
                             "non-empty string")
        # F385: bind the resume to a live transaction of THIS
        # coordinator. _txn fails closed on unknown XIDs; the state
        # check pins it to a LIVE transaction -- a suspension parked
        # under a committed or rolled-back transaction cannot resume.
        txn = self._txn(suspension["xid"])
        if txn["state"] != "open":
            _fail(MALFORMED, "transaction %s is %s, not open"
                  % (suspension["xid"][:12], txn["state"]))
        if pubkey != txn["coordinator_pubkey"]:
            _fail(WB_XID_MISMATCH,
                  "suspension's xid %s is not the transaction it was "
                  "parked under (coordinator key mismatch)"
                  % suspension["xid"][:12])
        # F385: the record must be the one parked for this xid. The
        # coordinator's own memory -- not the record's self-description
        # -- is the binding. An edited xid (A->B swap) or any other
        # field edit fails here, even when both transactions share the
        # coordinator's key.
        parked = txn.get("suspension")
        if parked is None or suspension != parked:
            _fail(WB_XID_MISMATCH,
                  "suspension does not match the record parked for xid "
                  "%s" % suspension["xid"][:12])
        # check_write is the liveness oracle: it refuses
        # coord-lease-expired / coord-lease-fencing itself, and returns
        # True without mutating anything (a pure authorization check).
        lease_manager.check_write(
            suspension["scope"], suspension["fencing_token"],
            suspension["holder_id"], checked_at=checked_at)
        return True
