"""Rotation lifecycle for the KMS envelope keyring (OpenBao ADAPT).

Wave-201. Stdlib-only. Operates on the :class:`gov.kms.KmsProvider`
interface — no provider changes, no vendored code (OpenBao is MPL-2.0;
re-implemented, never vendored; Vault BSL-1.1 excluded).

The gap this closes (wave-200 Lane C spike, verdict ADAPT): the product
has envelope encryption with a manual ``rotate()`` but no rotation
*lifecycle*. OpenBao's one materially better thing is the lifecycle
discipline — versioned keyring, rotation policy (``auto_rotate_period``),
grace windows, monotonic version floors, two-operator ceremony,
hash-chained rotation audit entries with externally-pinned heads. This
module is that discipline, re-implemented on our seams:

* :class:`VersionedRing` — a :class:`gov.kms.EnvelopeKeyRing` plus a
  persisted policy sidecar (atomic 0600 JSON) tracking per-version
  lifecycle state (``active`` -> ``decrypt_only`` -> ``retired`` ->
  ``destroyed``), the monotonic version floor, grace deadlines, and the
  pending-rotation journal.
* Two-operator ceremony: ``begin_rotation(proposer)`` then
  ``approve_pending(proposal_id, approver, provider, ...)``. The approver
  must be a distinct, non-empty operator identity; self-approval and
  quorum-less execution refuse loudly.
* Crash safety as a transaction: the pending journal is cleared only
  after activate + chained audit + head pin ALL complete. Any failure
  before that leaves the journal behind; the next ``load()`` runs
  ``reconcile()`` and reports explicit ``STUCK`` (naming both versions),
  blocking further rotations until a human completes or discards — the
  discard is itself a chained audit event. Nothing goes silent.
* Rotation entries are chained into the existing hash-chained audit log
  (``gov.log.ActionLog``): ``keyring_bootstrap``, ``rotation_proposed``,
  ``rotation_wrapped_new``, ``rotation_complete``,
  ``rotation_head_pinned`` / ``rotation_head_unpinned``,
  ``grace_expired``, ``version_floor_raised``, ``version_destroyed``,
  ``rotation_stuck``, ``rotation_discarded``. All events are
  material-free (epoch ids, key ids, statuses, digests — no key bytes,
  no wrapped blobs).
* Head pinning (the spike's honest residual): a hash chain alone cannot
  see tail truncation, so ``rotation_complete`` is externally pinned.
  ``head_pinner`` is an operator-wired callable
  ``(log_path, seq, head_hash) -> dict`` returning JSON-serializable
  receipt metadata; the receipt is chained as ``rotation_head_pinned``.
  With ``require_head_pin=True`` (default) the ceremony REFUSES LOUDLY
  when no pinner is wired — never silently skips. With
  ``require_head_pin=False`` the event records ``head_pinned: false``
  and :meth:`VersionedRing.audit_no_silent_swap` flags the unpinned head
  loudly. To wire the real Rekor path, close the audit-log epoch with
  ``gov.anchorer.Anchorer`` (or your existing anchor daemon) and return
  the anchor receipt from the pinner; ``gov.anchorer.audit_anchors``
  then verifies anchored-head == chain-head.

Honest boundaries (not hidden):

* Operator identity is a caller-supplied string today; binding the
  ceremony to the agent-identity story (dex tokens / key ceremony) is
  follow-on work.
* Grace-period, floor, and auto-rotate values are deployment policy,
  not code constants.
* The version floor governs :meth:`VersionedRing.unwrap_epoch` (the
  operational unwrap path). ``materialize()`` / ``verify_log()``
  deliberately stay exempt — history verification must not break under
  a floor — while ``destroy_version`` removes the blob entirely (old
  history under that epoch stops verifying; explicit, loud, audited).
* Rekor has no consistency-proof path in v1 (standing residual):
  head-pinning is digest-existence evidence, the same honest boundary
  as F203.
* ``materialize`` is not wrapped: callers using the full-materialization
  path must enforce the floor themselves (documented; the unwrap seam
  is where the policy bites).
"""

import json
import re
import time
import uuid
from pathlib import Path

from .keys import _atomic_write_bytes, rotation_lock
from .kms import EnvelopeKeyRing, KmsError

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

ACTIVE = "active"
DECRYPT_ONLY = "decrypt_only"   # grace window after rotation
RETIRED = "retired"             # floor-gated, history-verifiable
DESTROYED = "destroyed"         # blob gone; unwrap refuses, loudly
WRAPPED = "wrapped"             # KMS-wrapped but never activated (in a
                                # pending ceremony); unwrap refuses —
                                # fail-closed until activation

VERSION_STATES = frozenset((ACTIVE, DECRYPT_ONLY, RETIRED, DESTROYED,
                            WRAPPED))

STATE_FORMAT = "sasanam-rotation-state/v1"

# Audit event names chained into gov.log.
EV_BOOTSTRAP = "keyring_bootstrap"
EV_PROPOSED = "rotation_proposed"
EV_WRAPPED = "rotation_wrapped_new"
EV_COMPLETE = "rotation_complete"
EV_PINNED = "rotation_head_pinned"
EV_UNPINNED = "rotation_head_unpinned"
EV_GRACE = "grace_expired"
EV_FLOOR = "version_floor_raised"
EV_DESTROYED = "version_destroyed"
EV_STUCK = "rotation_stuck"
EV_DISCARDED = "rotation_discarded"

_EPOCH_NUM_RE = re.compile(r"^epoch-(\d+)$")


class RotationError(Exception):
    """Any rotation-policy failure: ceremony violation, floor/grace
    refusal, stuck journal, silent-swap detection, audit or pin
    failure. ALWAYS fail-closed; never carries key material."""


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch_number(epoch):
    """Numeric suffix of ``epoch-N`` labels, or None for non-numeric."""
    m = _EPOCH_NUM_RE.match(epoch or "")
    return int(m.group(1)) if m else None


def _check_operator(name, role):
    if not isinstance(name, str) or not name.strip():
        raise RotationError(
            "rotation %s must be a non-empty operator identity, got %r"
            % (role, name))
    return name.strip()


# ---------------------------------------------------------------------------
# VersionedRing
# ---------------------------------------------------------------------------

class VersionedRing:
    """An envelope keyring with a persisted rotation-lifecycle sidecar.

    Owns ``keyring_path`` (the :class:`EnvelopeKeyRing` v2 file) and the
    sidecar (default ``<keyring_path>.rotation.json``). Every mutating
    method serializes on the keyring rotation lock and persists both
    files atomically (0600).
    """

    def __init__(self, keyring_path, state_path=None, *, policy=None,
                 audit_log_path=None, deployment_mode=None,
                 head_pinner=None, clock=None):
        self._keyring_path = Path(keyring_path)
        self._state_path = (Path(state_path) if state_path is not None
                            else Path(str(keyring_path) + ".rotation.json"))
        policy = dict(policy or {})
        self._auto_rotate_period_s = policy.get("auto_rotate_period_s")
        if (self._auto_rotate_period_s is not None
                and (not isinstance(self._auto_rotate_period_s,
                                    (int, float))
                     or self._auto_rotate_period_s <= 0)):
            raise RotationError(
                "auto_rotate_period_s must be positive seconds or None, "
                "got %r" % (self._auto_rotate_period_s,))
        self._grace_period_s = policy.get("grace_period_s", 3600)
        if (not isinstance(self._grace_period_s, (int, float))
                or self._grace_period_s < 0):
            raise RotationError(
                "grace_period_s must be non-negative seconds, got %r"
                % (self._grace_period_s,))
        self._require_head_pin = policy.get("require_head_pin", True)
        if not isinstance(self._require_head_pin, bool):
            raise RotationError("require_head_pin must be a bool")
        if not audit_log_path:
            raise RotationError(
                "audit_log_path is required: rotations without chained "
                "audit entries are silent ceremonies — the exact gap "
                "this module closes")
        self._audit_log_path = str(audit_log_path)
        self._deployment_mode = deployment_mode
        if head_pinner is not None and not callable(head_pinner):
            raise RotationError("head_pinner must be callable or None")
        self._head_pinner = head_pinner
        self._clock = clock or time.time
        # Loaded state (filled by bootstrap()/load()).
        self._ring = None
        self._floor = 1
        self._versions = {}    # epoch -> {state, grace_deadline, key_id, ...}
        self._destroyed = {}   # epoch -> tombstone
        self._pending = None
        self._last_ceremony_at = None
        self._stuck = False

    # -- construction -------------------------------------------------

    @classmethod
    def bootstrap(cls, keyring_path, provider, kms_key_id, operator,
                  epoch="epoch-1", **kwargs):
        """Create a new ring + sidecar and chain the bootstrap ceremony.

        ``operator`` is the bootstrapping operator identity. The audit
        log is pre-flighted BEFORE anything is created: if the log is
        not writable the ceremony refuses instead of creating an
        unaudited ring.
        """
        operator = _check_operator(operator, "operator")
        self = cls(keyring_path, **kwargs)
        self._preflight_audit()
        # Head-pinner preflight BEFORE any mutation: a bootstrap that
        # cannot pin its head must refuse before creating state, not
        # after.
        if self._require_head_pin and self._head_pinner is None:
            raise RotationError(
                "no head_pinner wired and require_head_pin=True: "
                "refusing to bootstrap an unpinnable ring (tail "
                "truncation of the bootstrap ceremony would be "
                "invisible)")
        ring = EnvelopeKeyRing.generate(provider, kms_key_id, epoch=epoch)
        now = self._clock()
        self._ring = ring
        self._versions = {epoch: {
            "state": ACTIVE,
            "grace_deadline": None,
            "key_id": ring.get(epoch).key_id,
            "kms_key_id": kms_key_id,
            "created_at": now,
        }}
        self._last_ceremony_at = now
        with rotation_lock(self._keyring_path):
            self._save_all()
        self._audit({
            "event": EV_BOOTSTRAP,
            "operator": operator,
            "active_epoch": epoch,
            "versions": self._public_versions(),
            "version_floor": self._floor,
        })
        # Bootstrap is a ceremony: pin the head like any rotation.
        self._pin_head_after(EV_BOOTSTRAP)
        return self

    @classmethod
    def load(cls, keyring_path, **kwargs):
        """Load ring + sidecar and reconcile the pending journal.

        A leftover ``wrapped`` pending entry means the previous process
        died mid-ceremony: ``reconcile()`` marks it STUCK (naming both
        versions), chains ``rotation_stuck``, and blocks further
        rotations until a human completes or discards.
        """
        self = cls(keyring_path, **kwargs)
        with rotation_lock(self._keyring_path):
            self._load_all()
            self._reconcile_locked()
        return self

    # -- persistence --------------------------------------------------

    def _state_dict(self):
        return {
            "format": STATE_FORMAT,
            "version_floor": self._floor,
            "active_epoch": (self._ring._active_epoch
                             if self._ring is not None else None),
            "versions": self._versions,
            "destroyed": self._destroyed,
            "pending": self._pending,
            "last_ceremony_at": self._last_ceremony_at,
            "policy": {
                "auto_rotate_period_s": self._auto_rotate_period_s,
                "grace_period_s": self._grace_period_s,
                "require_head_pin": self._require_head_pin,
            },
        }

    def _save_all(self):
        """Persist ring + sidecar atomically (0600). Caller holds the
        rotation lock."""
        self._ring.save(self._keyring_path)
        data = (json.dumps(self._state_dict(), indent=2, sort_keys=True)
                + "\n").encode("utf-8")
        _atomic_write_bytes(self._state_path, data)

    def _load_all(self):
        """Load ring + sidecar and cross-check them. Loud on mismatch."""
        ring = EnvelopeKeyRing.load(self._keyring_path)
        try:
            raw = self._state_path.read_text(encoding="utf-8")
        except OSError as e:
            raise RotationError(
                "rotation sidecar %s unreadable: %s"
                % (self._state_path, e))
        try:
            st = json.loads(raw)
        except ValueError as e:
            raise RotationError(
                "rotation sidecar %s is not valid JSON: %s"
                % (self._state_path, e))
        if st.get("format") != STATE_FORMAT:
            raise RotationError(
                "rotation sidecar has unknown format %r (expected %r)"
                % (st.get("format"), STATE_FORMAT))
        if st.get("active_epoch") != ring._active_epoch:
            raise RotationError(
                "sidecar/ring mismatch: sidecar says active %r, ring "
                "says %r — refusing to operate on a diverged keyring"
                % (st.get("active_epoch"), ring._active_epoch))
        ring_epochs = set(ring._wrapped)
        state_epochs = set(st.get("versions", {}))
        if ring_epochs != state_epochs:
            raise RotationError(
                "sidecar/ring epoch mismatch: ring has %s, sidecar has "
                "%s — refusing to operate on a diverged keyring"
                % (sorted(ring_epochs), sorted(state_epochs)))
        for ep, v in st.get("versions", {}).items():
            if v.get("state") not in VERSION_STATES:
                raise RotationError(
                    "sidecar carries unknown version state %r for %r"
                    % (v.get("state"), ep))
            if v.get("key_id") != ring.get(ep).key_id:
                raise RotationError(
                    "sidecar/ring key_id mismatch for %r — refusing"
                    % (ep,))
        self._ring = ring
        self._floor = st.get("version_floor", 1)
        self._versions = st.get("versions", {})
        self._destroyed = st.get("destroyed", {})
        self._pending = st.get("pending")
        self._last_ceremony_at = st.get("last_ceremony_at")
        self._stuck = bool(self._pending
                           and self._pending.get("state") == "stuck")

    # -- audit seam ----------------------------------------------------

    def _preflight_audit(self):
        """Prove the audit log is writable BEFORE a ceremony mutates
        anything. Loud refusal instead of an unaudited ceremony."""
        from . import log as _log
        try:
            _log._active_key(self._deployment_mode)
            _log.open_audit_log(self._audit_log_path,
                                deployment_mode=self._deployment_mode)
        except Exception as e:
            raise RotationError(
                "audit log %s not writable (%s): refusing ceremony — "
                "rotations without chained audit entries are silent"
                % (self._audit_log_path, e))

    def _audit(self, event):
        """Chain one material-free event into the audit log. Any failure
        raises RotationError — audit gaps are never silent."""
        from . import log as _log
        if not isinstance(event, dict):
            raise RotationError("audit event must be a dict")
        try:
            lg = _log.open_audit_log(
                self._audit_log_path,
                deployment_mode=self._deployment_mode)
            return lg.append(event)
        except Exception as e:
            raise RotationError(
                "failed to chain audit event %r into %s: %s — audit "
                "gaps are never silent"
                % (event.get("event"), self._audit_log_path, e))

    def _pin_head_after(self, triggering_event):
        """Pin the audit-log head externally after a ceremony.

        The pinned head is the hash of the latest chained entry. With
        ``require_head_pin=True`` (default) a missing pinner refuses
        LOUDLY; with False the ``rotation_head_unpinned`` event records
        the gap and the audit flags it.
        """
        from . import log as _log
        entries = _log.read_entries(self._audit_log_path)
        if not entries:
            raise RotationError("audit log empty after %s — cannot pin "
                                "a head that does not exist"
                                % (triggering_event,))
        head = entries[-1]
        seq, head_hash = head["seq"], head["hash"]
        if self._head_pinner is None:
            if self._require_head_pin:
                raise RotationError(
                    "no head_pinner wired and require_head_pin=True: "
                    "refusing to leave %s unpinned (tail truncation "
                    "would be invisible)" % (triggering_event,))
            self._audit({
                "event": EV_UNPINNED,
                "triggering_event": triggering_event,
                "pinned_seq": seq,
                "head_hash": head_hash,
                "head_pinned": False,
            })
            return None
        try:
            receipt = self._head_pinner(self._audit_log_path, seq,
                                        head_hash)
        except Exception as e:
            raise RotationError(
                "head_pinner failed for seq %d: %s" % (seq, e))
        if not isinstance(receipt, dict):
            raise RotationError(
                "head_pinner must return a JSON-serializable dict, got "
                "%r" % type(receipt).__name__)
        try:
            json.dumps(receipt)
        except (TypeError, ValueError) as e:
            raise RotationError(
                "head_pinner receipt is not JSON-serializable: %s" % e)
        self._audit({
            "event": EV_PINNED,
            "triggering_event": triggering_event,
            "pinned_seq": seq,
            "head_hash": head_hash,
            "head_pinned": True,
            "receipt": receipt,
        })
        return receipt

    # -- ceremony ------------------------------------------------------

    def _ensure_no_pending(self, action):
        if self._stuck:
            raise RotationError(
                "cannot %s: rotation journal is STUCK (%s) — resolve "
                "with complete_stuck() or discard_stuck() first"
                % (action, self._pending.get("stuck_reason",
                                            "unresolved")))
        if self._pending is not None:
            raise RotationError(
                "cannot %s: rotation %s is already pending (state %r) — "
                "finish or discard it first"
                % (action, self._pending.get("proposal_id"),
                   self._pending.get("state")))

    def begin_rotation(self, proposer):
        """Open a two-operator rotation ceremony. Returns a proposal id.

        The audit log is pre-flighted first: an unwritable log refuses
        the ceremony before anything mutates.
        """
        proposer = _check_operator(proposer, "proposer")
        self._preflight_audit()
        with rotation_lock(self._keyring_path):
            self._load_all()
            self._ensure_no_pending("begin a rotation")
            proposal_id = uuid.uuid4().hex[:16]
            self._pending = {
                "proposal_id": proposal_id,
                "proposer": proposer,
                "proposed_at": self._clock(),
                "state": "proposed",
                "old_epoch": self._ring._active_epoch,
                "new_epoch": None,
                "activated": False,
                "completion_logged": False,
                "pinned": False,
            }
            self._save_all()
        self._audit({
            "event": EV_PROPOSED,
            "proposal_id": proposal_id,
            "proposer": proposer,
            "old_epoch": self._pending["old_epoch"],
        })
        return proposal_id

    def approve_pending(self, proposal_id, approver, provider,
                        kms_key_id=None):
        """Second operator approves and executes the pending rotation.

        Distinct-operator quorum: ``approver`` must differ from the
        proposer. The fallible KMS wrap happens BEFORE any activation;
        the pending journal is cleared only after activate + chained
        ``rotation_complete`` + head pin ALL succeed — anything earlier
        failing leaves the journal for ``reconcile()`` to mark STUCK.
        """
        approver = _check_operator(approver, "approver")
        self._preflight_audit()
        if self._require_head_pin and self._head_pinner is None:
            raise RotationError(
                "no head_pinner wired and require_head_pin=True: "
                "refusing to execute an unpinnable rotation")
        with rotation_lock(self._keyring_path):
            self._load_all()
            if self._stuck:
                raise RotationError(
                    "cannot approve: rotation journal is STUCK — resolve "
                    "with complete_stuck() or discard_stuck() first")
            pend = self._pending
            if pend is None:
                raise RotationError(
                    "cannot approve: no rotation is pending (quorum-less "
                    "execution refused)")
            if pend.get("proposal_id") != proposal_id:
                raise RotationError(
                    "proposal id mismatch: pending is %r, asked to "
                    "approve %r" % (pend.get("proposal_id"), proposal_id))
            if approver == pend["proposer"]:
                raise RotationError(
                    "self-approval refused: approver %r is the proposer; "
                    "rotation requires two distinct operators"
                    % (approver,))
            old_epoch = pend["old_epoch"]
            # Wrap the new epoch first (fallible KMS call before any
            # activation). Persist the ring with the new epoch PRESENT
            # but not yet active, plus the pending journal: a crash
            # after this point is recoverable by reconcile().
            if not pend.get("new_epoch"):
                new_epoch = self._ring._next_epoch_label()
                if new_epoch in self._ring._wrapped:
                    raise RotationError(
                        "epoch %r already exists" % (new_epoch,))
                wrapped = EnvelopeKeyRing._wrap_new(
                    provider, kms_key_id or
                    self._ring.get(old_epoch).kms_key_id,
                    new_epoch)  # may raise KmsError; ring untouched
                self._ring._wrapped[new_epoch] = wrapped
                # Record the epoch in the sidecar NOW (state "wrapped"):
                # the ring/sidecar cross-check must hold at every
                # persisted instant, including a crash right after this
                # save. Unwrap refuses "wrapped" epochs until activation.
                self._versions[new_epoch] = {
                    "state": WRAPPED,
                    "grace_deadline": None,
                    "key_id": wrapped.key_id,
                    "kms_key_id": wrapped.kms_key_id,
                    "created_at": self._clock(),
                }
                pend["new_epoch"] = new_epoch
                pend["state"] = "wrapped"
                self._save_all()
                new_key_id = wrapped.key_id
            else:
                new_epoch = pend["new_epoch"]
                new_key_id = self._ring.get(new_epoch).key_id
            self._audit({
                "event": EV_WRAPPED,
                "proposal_id": proposal_id,
                "proposer": pend["proposer"],
                "approver": approver,
                "old_epoch": old_epoch,
                "new_epoch": new_epoch,
                "new_key_id": new_key_id,
            })
            self._activate_locked(new_epoch, old_epoch, approver, pend,
                                  proposal_id)
        return new_epoch

    def _activate_locked(self, new_epoch, old_epoch, approver, pend,
                         proposal_id):
        """Activate + audit + pin. Caller holds the rotation lock and a
        freshly loaded state. Idempotent across retries: each step is
        skipped once recorded in the pending journal."""
        now = self._clock()
        if not pend.get("activated"):
            old_state = self._versions[old_epoch]["state"]
            if old_state != ACTIVE:
                raise RotationError(
                    "cannot activate: old epoch %r is in state %r, not "
                    "active — ring diverged under the ceremony"
                    % (old_epoch, old_state))
            self._ring._active_epoch = new_epoch
            self._versions[old_epoch]["state"] = DECRYPT_ONLY
            self._versions[old_epoch]["grace_deadline"] = (
                now + self._grace_period_s)
            self._versions[new_epoch] = {
                "state": ACTIVE,
                "grace_deadline": None,
                "key_id": self._ring.get(new_epoch).key_id,
                "kms_key_id": self._ring.get(new_epoch).kms_key_id,
                "created_at": now,
            }
            # The envelope ring's own retired marker follows.
            self._ring.get(old_epoch).status = "retired"
            pend["activated"] = True
            self._save_all()
        if not pend.get("completion_logged"):
            entry = self._audit({
                "event": EV_COMPLETE,
                "proposal_id": proposal_id,
                "proposer": pend["proposer"],
                "approver": approver,
                "old_epoch": old_epoch,
                "new_epoch": new_epoch,
                "versions": self._public_versions(),
                "version_floor": self._floor,
            })
            pend["completion_logged"] = True
            pend["completion_seq"] = entry["seq"]
            self._save_all()
        if not pend.get("pinned"):
            self._pin_head_after(EV_COMPLETE)
            pend["pinned"] = True
            self._pending = None
            self._last_ceremony_at = now
            self._save_all()

    # -- stuck reconciliation ------------------------------------------

    def _reconcile_locked(self):
        """Mark a leftover ``wrapped`` pending entry STUCK. Called on
        every load: a new process finding a ``wrapped`` journal means the
        previous holder died mid-ceremony (or released without
        completing — equally a human decision now)."""
        pend = self._pending
        if pend is not None and pend.get("state") == "wrapped":
            pend["state"] = "stuck"
            reason = ("previous process left rotation %s wrapped-but-not-"
                      "completed (old=%s new=%s)"
                      % (pend.get("proposal_id"), pend.get("old_epoch"),
                         pend.get("new_epoch")))
            pend["stuck_reason"] = reason
            self._stuck = True
            self._save_all()
            self._audit({
                "event": EV_STUCK,
                "proposal_id": pend.get("proposal_id"),
                "old_epoch": pend.get("old_epoch"),
                "new_epoch": pend.get("new_epoch"),
                "reason": reason,
            })

    def complete_stuck(self, provider, approver):
        """Finish a STUCK rotation: idempotent activate + audit + pin,
        then clear the journal. The approver must differ from the
        original proposer (quorum still applies)."""
        approver = _check_operator(approver, "approver")
        self._preflight_audit()
        with rotation_lock(self._keyring_path):
            self._load_all()
            if not self._stuck or self._pending is None:
                raise RotationError("no stuck rotation to complete")
            pend = self._pending
            if approver == pend.get("proposer"):
                raise RotationError(
                    "self-approval refused: approver %r is the proposer"
                    % (approver,))
            self._audit({
                "event": EV_WRAPPED,
                "proposal_id": pend.get("proposal_id"),
                "resumed": True,
                "approver": approver,
                "old_epoch": pend.get("old_epoch"),
                "new_epoch": pend.get("new_epoch"),
            })
            self._activate_locked(pend["new_epoch"], pend["old_epoch"],
                                  approver, pend, pend.get("proposal_id"))
            self._stuck = False
        return pend.get("new_epoch")

    def discard_stuck(self, reason, operator):
        """Abandon a STUCK rotation: the wrapped-but-never-activated new
        epoch's blob is dropped from the ring file (it was never
        referenced), the journal is cleared, and the discard is chained.
        The old epoch stays active — no silent switch ever happened."""
        operator = _check_operator(operator, "operator")
        if not isinstance(reason, str) or not reason.strip():
            raise RotationError("discard reason must be a non-empty string")
        self._preflight_audit()
        with rotation_lock(self._keyring_path):
            self._load_all()
            if not self._stuck or self._pending is None:
                raise RotationError("no stuck rotation to discard")
            pend = self._pending
            new_epoch = pend.get("new_epoch")
            if new_epoch in self._ring._wrapped:
                del self._ring._wrapped[new_epoch]
            self._versions.pop(new_epoch, None)
            self._pending = None
            self._stuck = False
            self._save_all()
        self._audit({
            "event": EV_DISCARDED,
            "proposal_id": pend.get("proposal_id"),
            "operator": operator,
            "reason": reason.strip(),
            "dropped_epoch": new_epoch,
            "active_epoch": self._ring._active_epoch,
        })
        return new_epoch

    # -- policy: floor, grace, pacing ------------------------------------

    def set_floor(self, version_floor):
        """Raise the monotonic version floor. Lowering refuses loudly;
        non-integer or < 1 refuses loudly."""
        if (isinstance(version_floor, bool)
                or not isinstance(version_floor, int)
                or version_floor < 1):
            raise RotationError(
                "version floor must be an integer >= 1, got %r"
                % (version_floor,))
        self._preflight_audit()
        with rotation_lock(self._keyring_path):
            self._load_all()
            if version_floor < self._floor:
                raise RotationError(
                    "refusing to lower version floor %d -> %d: floors "
                    "are monotonic (downgrade protection)"
                    % (self._floor, version_floor))
            if version_floor == self._floor:
                return self._floor
            self._floor = version_floor
            self._save_all()
        self._audit({
            "event": EV_FLOOR,
            "version_floor": version_floor,
        })
        return self._floor

    @property
    def version_floor(self):
        return self._floor

    def sweep_grace(self, now=None):
        """Move decrypt_only versions past their grace deadline to
        retired. Returns the list of swept epochs. Each sweep is a
        chained audit event."""
        now = self._clock() if now is None else now
        swept = []
        with rotation_lock(self._keyring_path):
            self._load_all()
            for epoch, v in self._versions.items():
                if v["state"] == DECRYPT_ONLY and \
                        v["grace_deadline"] is not None and \
                        now >= v["grace_deadline"]:
                    v["state"] = RETIRED
                    v["grace_deadline"] = None
                    swept.append(epoch)
            if swept:
                self._save_all()
        for epoch in swept:
            self._audit({
                "event": EV_GRACE,
                "epoch": epoch,
                "new_state": RETIRED,
            })
        return swept

    def due_for_rotation(self, now=None):
        """True when auto_rotate_period_s elapsed since the last
        ceremony. None period (manual-only) is never due."""
        if self._auto_rotate_period_s is None:
            return False
        now = self._clock() if now is None else now
        if self._last_ceremony_at is None:
            return True
        return (now - self._last_ceremony_at) >= self._auto_rotate_period_s

    def destroy_version(self, epoch, operator):
        """Terminally destroy a non-active version: the wrapped blob is
        removed from the ring file (old history under that epoch stops
        verifying — explicit and audited), a tombstone is kept in the
        sidecar, and any later unwrap attempt refuses loudly with
        'destroyed'. Destroying the active epoch refuses loudly."""
        operator = _check_operator(operator, "operator")
        self._preflight_audit()
        with rotation_lock(self._keyring_path):
            self._load_all()
            self._ensure_no_pending("destroy a version")
            if epoch == self._ring._active_epoch:
                raise RotationError(
                    "refusing to destroy the active epoch %r" % (epoch,))
            if epoch in self._destroyed:
                raise RotationError(
                    "epoch %r is already destroyed" % (epoch,))
            if epoch not in self._versions:
                raise RotationError(
                    "unknown version %r (known: %s)"
                    % (epoch, sorted(self._versions)))
            v = self._versions.pop(epoch)
            del self._ring._wrapped[epoch]
            self._destroyed[epoch] = {
                "key_id": v["key_id"],
                "destroyed_at": self._clock(),
                "destroyed_by": operator,
            }
            self._save_all()
        self._audit({
            "event": EV_DESTROYED,
            "epoch": epoch,
            "key_id": v["key_id"],
            "operator": operator,
        })
        return epoch

    # -- policy-enforced unwrap -------------------------------------------

    def unwrap_epoch(self, provider, epoch):
        """Unwrap one epoch's data key under the rotation policy.

        Refuses loudly: destroyed versions, versions below the floor,
        unknown versions. decrypt_only versions past their grace
        deadline are swept to retired first (audited). KMS failures
        propagate as KmsError (fail-closed).
        """
        with rotation_lock(self._keyring_path):
            self._load_all()
            if epoch in self._destroyed:
                raise RotationError(
                    "refusing to unwrap version %r: destroyed at %s by "
                    "%s" % (epoch,
                            self._destroyed[epoch]["destroyed_at"],
                            self._destroyed[epoch]["destroyed_by"]))
            v = self._versions.get(epoch)
            if v is None:
                raise RotationError(
                    "unknown version %r (known: %s)"
                    % (epoch, sorted(self._versions)))
            num = _epoch_number(epoch)
            if num is not None and num < self._floor:
                raise RotationError(
                    "refusing to unwrap version %r: below version floor "
                    "%d" % (epoch, self._floor))
            if v["state"] == DECRYPT_ONLY and \
                    v["grace_deadline"] is not None and \
                    self._clock() >= v["grace_deadline"]:
                # Lazy grace sweep on the operational path (audited).
                v["state"] = RETIRED
                v["grace_deadline"] = None
                self._save_all()
                self._audit({
                    "event": EV_GRACE,
                    "epoch": epoch,
                    "new_state": RETIRED,
                })
            if v["state"] not in (ACTIVE, DECRYPT_ONLY, RETIRED):
                # WRAPPED: KMS-wrapped but never activated — nobody was
                # ever authorized to encrypt under it. DESTROYED (sidecar
                # state): blob gone. Both refuse, loudly.
                raise RotationError(
                    "refusing to unwrap version %r: state %r is not an "
                    "active/decryptable version" % (epoch, v["state"]))
            wd = self._ring.get(epoch)
        # KMS call outside the lock (fail-closed on its own terms).
        try:
            return provider.unwrap_data_key(wd.kms_key_id, wd.wrapped_blob)
        except KmsError:
            raise
        except Exception as e:
            raise RotationError(
                "unwrap of version %r failed: %s" % (epoch, e))

    # -- verification -------------------------------------------------------

    def audit_no_silent_swap(self):
        """Ceremony-replay audit: prove every live version traces to a
        chained ceremony and every ceremony head is pinned.

        1. The audit chain itself must verify (tamper / middle-deletion
           break it — loud).
        2. Every non-destroyed version in the ring must be covered by a
           ``keyring_bootstrap`` or ``rotation_complete`` ceremony; a
           version with no ceremony is a silent swap — loud.
        3. Every ``rotation_complete`` / ``keyring_bootstrap`` head must
           be followed by a matching ``rotation_head_pinned``; an
           unpinned head (tail-truncation-vulnerable) is loud.

        Returns a report dict; raises RotationError on any violation.
        """
        from . import log as _log
        try:
            ok, broken_seq, entry_count = _log.verify_chain(
                self._audit_log_path)
        except Exception as e:
            raise RotationError(
                "audit chain failed verification: %s" % (e,))
        if not ok:
            # verify_chain returns a verdict (never raises): a tampered
            # or middle-deleted log fails LOUD here.
            raise RotationError(
                "audit chain failed verification at seq %s (%d "
                "entries checked): tamper or deletion detected"
                % (broken_seq, entry_count))
        entries = _log.read_entries(self._audit_log_path)
        by_event = {}
        for e in entries:
            by_event.setdefault(e.get("event"), []).append(e)
        report = {"ceremonies": 0, "pinned_heads": 0,
                  "unpinned_heads": [], "violations": []}
        # Ceremony coverage: every live version needs a ceremony.
        covered = set()
        for e in by_event.get(EV_BOOTSTRAP, []):
            for v in e.get("versions", {}):
                covered.add(v.get("epoch"))
        for e in by_event.get(EV_COMPLETE, []):
            if e.get("new_epoch"):
                covered.add(e["new_epoch"])
        for e in by_event.get(EV_WRAPPED, []):
            # Wrapped-but-never-completed epochs are either pending
            # (visible in the journal) or discarded (chained). A wrapped
            # epoch that is live in the ring with no completion is
            # covered by the stuck/discard machinery, not silent.
            pass
        live = set(self._versions)
        for epoch in sorted(live - covered):
            # The currently-active epoch at bootstrap time is covered;
            # anything else live-but-uncovered is a silent injection.
            report["violations"].append(
                "version %r is live in the ring with no chained "
                "ceremony (silent swap?)" % (epoch,))
        report["ceremonies"] = (len(by_event.get(EV_BOOTSTRAP, []))
                                + len(by_event.get(EV_COMPLETE, [])))
        # Head-pin coverage: each ceremony's head must be pinned.
        pinned_seqs = {e.get("pinned_seq")
                       for e in by_event.get(EV_PINNED, [])}
        unpinned = [e for e in by_event.get(EV_UNPINNED, [])]
        for e in by_event.get(EV_BOOTSTRAP, []) + \
                by_event.get(EV_COMPLETE, []):
            seq = e.get("seq")
            if seq not in pinned_seqs:
                report["unpinned_heads"].append(seq)
                report["violations"].append(
                    "ceremony %s at seq %d has no pinned head "
                    "(tail-truncation-vulnerable)" % (e.get("event"), seq))
        for e in unpinned:
            report["unpinned_heads"].append(e.get("pinned_seq"))
            report["violations"].append(
                "explicitly unpinned head at seq %s (require_head_pin "
                "was disabled)" % (e.get("pinned_seq"),))
        report["pinned_heads"] = len(pinned_seqs)
        if report["violations"]:
            raise RotationError(
                "silent-swap audit FAILED:\n  - " +
                "\n  - ".join(report["violations"]))
        return report

    # -- introspection --------------------------------------------------------

    def _public_versions(self):
        """Material-free version projection (KeysetInfo-style)."""
        return [{"epoch": ep,
                 "key_id": v["key_id"],
                 "state": v["state"]}
                for ep, v in sorted(self._versions.items())]

    def describe(self):
        """Material-free ring description: states, floor, policy,
        pending/stuck — never key material."""
        with rotation_lock(self._keyring_path):
            self._load_all()
            return {
                "keyring_path": str(self._keyring_path),
                "active_epoch": self._ring._active_epoch,
                "version_floor": self._floor,
                "versions": self._public_versions(),
                "destroyed": sorted(self._destroyed),
                "pending": (dict(self._pending)
                            if self._pending else None),
                "stuck": self._stuck,
                "due_for_rotation": self.due_for_rotation(),
                "policy": {
                    "auto_rotate_period_s": self._auto_rotate_period_s,
                    "grace_period_s": self._grace_period_s,
                    "require_head_pin": self._require_head_pin,
                },
            }
