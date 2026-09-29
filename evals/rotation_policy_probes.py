#!/usr/bin/env python3
"""Wave-201 lane B red-team probes: KMS rotation lifecycle.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
OpenBao's rotation lifecycle — versioned keyring, rotation policy
(auto_rotate_period), grace windows, monotonic version floors,
two-operator ceremony, hash-chained rotation audit entries with
externally-pinned heads (MPL-2.0, pattern-only -- re-implemented
stdlib-only, nothing vendored).

The pristine tree's KMS layer (gov.kms.EnvelopeKeyRing) has a MANUAL
rotate() with NO lifecycle: no auto_rotate_period, no grace window,
retired epochs unwrap lazily forever, no version floor, no two-operator
ceremony, no rotation entries in the hash-chained audit log, no
stuck-rotation detection, no head pinning. Each probe attacks that gap:

  R1  ROTATE_CEREMONY  two-operator propose+approve completes: new
                       active, old decrypt_only, chained events, head
                       pinned
  R2  SELF_APPROVAL    approver == proposer refused loudly
  R3  QUORUMLESS       approve with no pending / wrong proposal id
                       refused
  R4  GRACE_UNWRAP     old epoch unwraps during the grace window
  R5  GRACE_SWEEP      past-deadline decrypt_only -> retired (audited);
                       history still verifiable
  R6  DESTROY          destroy_version -> unwrap refused "destroyed";
                       destroying the active epoch refused
  R7  FLOOR            below-floor unwrap refused; floor lowering
                       refused; bad floor values refused
  R8  UNKNOWN_VERSION  unknown epoch unwrap refused loudly
  R9  SILENT_SWAP      ring version with no chained ceremony flagged
  R10 LOG_TAMPER       tampered audit log breaks the replay audit
  R11 MIDDLE_DELETE    deleted middle record breaks the replay audit
  R12 TAIL_TRUNCATE    truncated tail still verifies as a chain but the
                       ceremony replay flags the uncovered live version
  R13 STUCK            crash between wrap and activate -> next load
                       reports STUCK naming both versions; further
                       rotations blocked; old version still active
  R14 STUCK_DISCARD    explicit logged discard resolves; new blob gone
  R15 STUCK_COMPLETE   complete_stuck finishes the ceremony (quorum
                       still applies)
  R16 DUE              due_for_rotation honors auto_rotate_period
  R17 NO_PINNER        require_head_pin=True with no pinner -> loud
                       refusal before any mutation
  R18 UNPINNED         require_head_pin=False -> head_pinned:false is
                       chained AND flagged by the replay audit
  R19 PINNER_FAILS     pinner raising -> RotationError, journal kept
                       for reconcile
  R20 OPERATOR_EMPTY   empty operator identities refused
  R21 DOUBLE_BEGIN     begin while a rotation is pending refused
  R22 AUDIT_UNWRITABLE unwritable audit log refuses the ceremony
                       before any mutation (no silent ceremony)
  R23 MATERIAL_FREE    describe()/audit events carry zero key bytes
  R24 KMS_OUTAGE       provider outage mid-ceremony -> fail-closed,
                       ring unmutated, old epoch still active
  R25 PENDING_JOURNAL  pending journal survives as explicit state
                       (proposed -> wrapped -> cleared only after
                       activate+audit+pin)

On the pristine tree every probe reports GAP (gov.rotation_policy
absent -- genuine red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: injected clock; FakeKmsProvider (counter nonces); every
probe runs twice and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import contextlib
import io
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import rotation_policy as _rp
    from gov.kms import FakeKmsProvider, KmsError, EnvelopeKeyRing
    _ABSENT = False
except ImportError:
    _rp = None
    _ABSENT = True

_GAP = (False, "GAP: gov.rotation_policy absent on this tree")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _log_key():
    """Provision the audit-log HMAC key for the battery, scrub after."""
    old_key = os.environ.get("GOV_LOG_KEY")
    old_epoch = os.environ.get("GOV_LOG_KEY_EPOCH")
    os.environ["GOV_LOG_KEY"] = "rotation-probe-test-key-material"
    os.environ["GOV_LOG_KEY_EPOCH"] = "probe-epoch"
    try:
        yield
    finally:
        if old_key is None:
            os.environ.pop("GOV_LOG_KEY", None)
        else:
            os.environ["GOV_LOG_KEY"] = old_key
        if old_epoch is None:
            os.environ.pop("GOV_LOG_KEY_EPOCH", None)
        else:
            os.environ["GOV_LOG_KEY_EPOCH"] = old_epoch


@contextlib.contextmanager
def _no_log_key():
    """Scrub every key source: the ceremony must refuse, loudly."""
    olds = {}
    for name in ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_KEYRING_FILE"):
        olds[name] = os.environ.pop(name, None)
    try:
        yield
    finally:
        for name, val in olds.items():
            if val is not None:
                os.environ[name] = val


class _Clock:
    def __init__(self, start=1_700_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _Pinner:
    """Fake head pinner: records calls, returns receipt metadata."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, log_path, seq, head_hash):
        self.calls.append((log_path, seq, head_hash))
        if self.fail:
            raise RuntimeError("simulated pinner outage")
        return {"pinned_seq": seq, "head_hash": head_hash,
                "by": "fake-pinner"}


def _fresh_ring(tmp, clock=None, pinner=None, policy=None, operator="alice"):
    """Bootstrap a VersionedRing in tmp; returns (ring, provider, ...)."""
    clock = clock or _Clock()
    pinner = pinner if pinner is not None else _Pinner()
    provider = FakeKmsProvider(["master-1"])
    ring = _rp.VersionedRing.bootstrap(
        os.path.join(tmp, "keyring.json"),
        provider, "master-1", operator,
        audit_log_path=os.path.join(tmp, "audit.jsonl"),
        deployment_mode="staging",
        head_pinner=pinner, clock=clock,
        policy=policy or {"grace_period_s": 100},
    )
    return ring, provider, clock, pinner


def _tmp():
    return tempfile.mkdtemp(prefix="rotprobe-")


def _read_log(path):
    with io.open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# ---------------------------------------------------------------------------
# Probes: each returns (held: bool, detail: str)
# ---------------------------------------------------------------------------

def _probe_r1_rotate_ceremony():
    """R1: two-operator ceremony completes with chained evidence."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        new_epoch = ring.approve_pending(pid, "bob", provider)
        assert new_epoch == "epoch-2", new_epoch
        d = ring.describe()
        states = {v["epoch"]: v["state"] for v in d["versions"]}
        assert states == {"epoch-1": "decrypt_only",
                          "epoch-2": "active"}, states
        assert d["active_epoch"] == "epoch-2"
        assert d["pending"] is None and not d["stuck"]
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        for want in ("keyring_bootstrap", "rotation_proposed",
                     "rotation_wrapped_new", "rotation_complete",
                     "rotation_head_pinned"):
            assert want in events, events
        assert pinner.calls, "head pinner was never called"
        # The pinned head is the rotation_complete entry's hash.
        log = _read_log(os.path.join(tmp, "audit.jsonl"))
        complete = [e for e in log
                    if e["event"] == "rotation_complete"][0]
        pinned = [e for e in log
                  if e["event"] == "rotation_head_pinned"
                  and e["pinned_seq"] == complete["seq"]]
        assert pinned, "no pin event for the rotation_complete head"
        pinned = pinned[0]
        assert pinned["pinned_seq"] == complete["seq"]
        assert pinned["head_hash"] == complete["hash"]
        assert pinned["head_pinned"] is True
        report = ring.audit_no_silent_swap()
        assert report["violations"] == [], report
    return True, "propose+approve completed; evidence chained; head pinned"


def _probe_r2_self_approval():
    """R2: approver == proposer is refused loudly."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        try:
            ring.approve_pending(pid, "alice", provider)
        except _rp.RotationError as e:
            assert "self-approval" in str(e), e
        else:
            return False, "self-approval was NOT refused"
        d = ring.describe()
        assert d["active_epoch"] == "epoch-1"
        assert d["pending"] is not None, "pending journal lost"
    return True, "self-approval refused; ceremony still pending"


def _probe_r3_quorumless():
    """R3: approve with no pending rotation, or a wrong proposal id,
    is refused."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        try:
            ring.approve_pending("nope", "bob", provider)
        except _rp.RotationError as e:
            assert "no rotation is pending" in str(e), e
        else:
            return False, "quorum-less approve was NOT refused"
        pid = ring.begin_rotation("alice")
        try:
            ring.approve_pending("wrong-id", "bob", provider)
        except _rp.RotationError as e:
            assert "proposal id mismatch" in str(e), e
        else:
            return False, "wrong proposal id was NOT refused"
        assert ring.describe()["active_epoch"] == "epoch-1"
    return True, "quorum-less and mismatched approvals refused"


def _probe_r4_grace_unwrap():
    """R4: the retired epoch unwraps during the grace window."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        before = ring.unwrap_epoch(provider, "epoch-1")
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        after = ring.unwrap_epoch(provider, "epoch-1")
        assert before == after, "grace unwrap returned different bytes"
        d = ring.describe()
        st = {v["epoch"]: v["state"] for v in d["versions"]}
        assert st["epoch-1"] == "decrypt_only", st
    return True, "old epoch unwraps byte-identically during grace"


def _probe_r5_grace_sweep():
    """R5: past-deadline decrypt_only -> retired (audited); history
    stays verifiable."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        clock.advance(101)  # grace was 100s
        swept = ring.sweep_grace()
        assert swept == ["epoch-1"], swept
        st = {v["epoch"]: v["state"]
              for v in ring.describe()["versions"]}
        assert st["epoch-1"] == "retired", st
        # History still verifiable: unwrap works above the floor.
        pt = ring.unwrap_epoch(provider, "epoch-1")
        assert len(pt) == 32
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        assert "grace_expired" in events
    return True, "grace swept to retired with audit; history verifiable"


def _probe_r6_destroy():
    """R6: destroy_version kills the blob; unwrap refuses 'destroyed';
    destroying the active epoch refuses."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        try:
            ring.destroy_version("epoch-2", "carol")
        except _rp.RotationError as e:
            assert "active epoch" in str(e), e
        else:
            return False, "destroying the active epoch was NOT refused"
        ring.destroy_version("epoch-1", "carol")
        try:
            ring.unwrap_epoch(provider, "epoch-1")
        except _rp.RotationError as e:
            assert "destroyed" in str(e), e
        else:
            return False, "unwrap of destroyed version was NOT refused"
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        assert "version_destroyed" in events
        assert ring.describe()["destroyed"] == ["epoch-1"]
    return True, "destroyed version refuses loudly; active destroy refused"


def _probe_r7_floor():
    """R7: below-floor unwrap refused; floor lowering refused; bad
    floor values refused."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        assert ring.set_floor(2) == 2
        try:
            ring.unwrap_epoch(provider, "epoch-1")
        except _rp.RotationError as e:
            assert "below version floor" in str(e), e
        else:
            return False, "below-floor unwrap was NOT refused"
        # New epoch still works.
        assert len(ring.unwrap_epoch(provider, "epoch-2")) == 32
        try:
            ring.set_floor(1)
        except _rp.RotationError as e:
            assert "lower" in str(e), e
        else:
            return False, "floor lowering was NOT refused"
        for bad in (0, -3, "2", 2.5, True):
            try:
                ring.set_floor(bad)
            except _rp.RotationError:
                pass
            else:
                return False, "bad floor %r was NOT refused" % (bad,)
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        assert "version_floor_raised" in events
    return True, "floor enforced monotonically; bad values refused"


def _probe_r8_unknown_version():
    """R8: unknown epoch unwrap refuses loudly."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        try:
            ring.unwrap_epoch(provider, "epoch-99")
        except _rp.RotationError as e:
            assert "unknown version" in str(e), e
        else:
            return False, "unknown version unwrap was NOT refused"
    return True, "unknown version refused loudly"


def _probe_r9_silent_swap():
    """R9: a ring version with no chained ceremony is flagged."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        # Attacker with file write: inject epoch-9 into the ring file
        # AND the sidecar (both cross-checks pass) but cannot forge a
        # chained rotation_complete without the log key.
        from gov.keys import rotation_lock
        evil = EnvelopeKeyRing._wrap_new(provider, "master-1", "epoch-9")
        with rotation_lock(ring._keyring_path):
            ring._load_all()
            ring._ring._wrapped["epoch-9"] = evil
            ring._versions["epoch-9"] = {
                "state": "active", "grace_deadline": None,
                "key_id": evil.key_id, "kms_key_id": "master-1",
                "created_at": clock(),
            }
            ring._save_all()
        ring2 = _rp.VersionedRing.load(
            ring._keyring_path,
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=pinner, clock=clock)
        try:
            ring2.audit_no_silent_swap()
        except _rp.RotationError as e:
            assert "epoch-9" in str(e) and "no chained ceremony" in str(e), e
        else:
            return False, "injected version was NOT flagged"
    return True, "silent version injection flagged by ceremony replay"


def _probe_r10_log_tamper():
    """R10: a tampered audit log breaks the replay audit."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        logp = os.path.join(tmp, "audit.jsonl")
        lines = io.open(logp, encoding="utf-8").read().splitlines()
        assert len(lines) >= 2
        # Tamper with a middle record's payload.
        rec = json.loads(lines[1])
        rec["event"] = "forged_event"
        lines[1] = json.dumps(rec)
        io.open(logp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        try:
            ring.audit_no_silent_swap()
        except _rp.RotationError as e:
            assert "chain" in str(e), e
        else:
            return False, "tampered log was NOT detected"
    return True, "log tamper breaks the replay audit"


def _probe_r11_middle_delete():
    """R11: deleting a middle record breaks the replay audit."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        logp = os.path.join(tmp, "audit.jsonl")
        lines = io.open(logp, encoding="utf-8").read().splitlines()
        assert len(lines) >= 4
        del lines[2]  # middle deletion
        io.open(logp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        try:
            ring.audit_no_silent_swap()
        except _rp.RotationError as e:
            assert "chain" in str(e), e
        else:
            return False, "middle deletion was NOT detected"
    return True, "middle-record deletion breaks the replay audit"


def _probe_r12_tail_truncate():
    """R12: the spike's honest residual, end to end.

    A bare hash chain cannot see a CONSISTENT truncation: an attacker
    with file write truncates the log AND the local checkpoint sidecar
    to an earlier consistent point and the local verifier reports
    ok=True (demonstrated below). The defense is the EXTERNAL head pin
    plus the ceremony replay: the pinner's out-of-band record names a
    head (seq/hash) that no longer resolves in the log, and the replay
    flags the live-but-unceremonied version.
    """
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        logp = os.path.join(tmp, "audit.jsonl")
        ckpt = os.path.join(tmp, "checkpoints.jsonl")
        # The external pinner saw the full ceremony head (out of band).
        _logp, pinned_seq, pinned_hash = pinner.calls[-1]
        assert pinned_seq == 5, pinner.calls  # rotation_complete's seq
        # Attacker truncates BOTH files to the consistent seq-4 point,
        # dropping rotation_complete (seq 5) and its head pin (seq 6).
        kept = [e for e in _read_log(logp) if e["seq"] <= 4]
        assert kept[-1]["event"] == "rotation_wrapped_new"
        io.open(logp, "w", encoding="utf-8").write(
            "\n".join(json.dumps(e, ensure_ascii=True, default=str)
                      for e in kept) + "\n")
        ck_lines = [json.loads(l) for l in
                    io.open(ckpt, encoding="utf-8").read().splitlines()
                    if l.strip()]
        ck_lines = [c for c in ck_lines if c["seq"] <= 4]
        io.open(ckpt, "w", encoding="utf-8").write(
            "\n".join(json.dumps(c, ensure_ascii=True, default=str)
                      for c in ck_lines) + "\n")
        # The residual: the local chain verifier is blind to this.
        from gov import log as _log
        ok, _, _ = _log.verify_chain(logp)
        assert ok, "consistent truncation should be invisible locally"
        # The ceremony replay still flags the uncovered live version...
        try:
            ring.audit_no_silent_swap()
        except _rp.RotationError as e:
            assert "epoch-2" in str(e) and "no chained ceremony" in str(e), e
        else:
            return False, "truncated ceremony was NOT flagged"
        # ...and the externally pinned head no longer resolves in the
        # log, so the operator's out-of-band pin record catches it too.
        assert not any(e.get("hash") == pinned_hash
                       for e in _read_log(logp)), \
            "pinned head still resolves -- truncation did not happen"
    return True, "consistent truncation invisible locally; replay+pin flag it"


def _probe_r13_stuck():
    """R13: crash between wrap and activate -> next load is STUCK,
    naming both versions; further rotations blocked; old still active."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        orig = _rp.VersionedRing._activate_locked

        def _crash(*a, **k):
            raise RuntimeError("simulated kill -9")

        _rp.VersionedRing._activate_locked = _crash
        try:
            ring.approve_pending(pid, "bob", provider)
        except RuntimeError:
            pass
        finally:
            _rp.VersionedRing._activate_locked = orig
        # "New process": fresh load reconciles.
        ring2 = _rp.VersionedRing.load(
            ring._keyring_path,
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=pinner, clock=clock)
        d = ring2.describe()
        assert d["stuck"] is True, d
        assert d["active_epoch"] == "epoch-1", "silent switch happened!"
        pend = d["pending"]
        assert pend["old_epoch"] == "epoch-1"
        assert pend["new_epoch"] == "epoch-2"
        assert "epoch-1" in pend["stuck_reason"]
        assert "epoch-2" in pend["stuck_reason"]
        try:
            ring2.begin_rotation("carol")
        except _rp.RotationError as e:
            assert "STUCK" in str(e), e
        else:
            return False, "rotation while STUCK was NOT blocked"
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        assert "rotation_stuck" in events
    return True, "crash -> STUCK naming both versions; rotations blocked"


def _probe_r14_stuck_discard():
    """R14: explicit logged discard resolves STUCK; the never-activated
    blob is dropped; the old epoch stays active."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        orig = _rp.VersionedRing._activate_locked

        def _crash(*a, **k):
            raise RuntimeError("simulated kill -9")

        _rp.VersionedRing._activate_locked = _crash
        try:
            ring.approve_pending(pid, "bob", provider)
        except RuntimeError:
            pass
        finally:
            _rp.VersionedRing._activate_locked = orig
        ring2 = _rp.VersionedRing.load(
            ring._keyring_path,
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=pinner, clock=clock)
        dropped = ring2.discard_stuck("operator decision: bad timing",
                                      "carol")
        assert dropped == "epoch-2", dropped
        d = ring2.describe()
        assert not d["stuck"] and d["pending"] is None
        assert d["active_epoch"] == "epoch-1"
        assert "epoch-2" not in [v["epoch"] for v in d["versions"]]
        events = [e["event"] for e in _read_log(
            os.path.join(tmp, "audit.jsonl"))]
        assert "rotation_discarded" in events
        # And the floor is usable again.
        pid2 = ring2.begin_rotation("dave")
        ring2.approve_pending(pid2, "erin", provider)
        assert ring2.describe()["active_epoch"] == "epoch-2"
    return True, "discard resolved STUCK with a chained event"


def _probe_r15_stuck_complete():
    """R15: complete_stuck finishes the ceremony; quorum still applies
    (approver must differ from proposer)."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        orig = _rp.VersionedRing._activate_locked

        def _crash(*a, **k):
            raise RuntimeError("simulated kill -9")

        _rp.VersionedRing._activate_locked = _crash
        try:
            ring.approve_pending(pid, "bob", provider)
        except RuntimeError:
            pass
        finally:
            _rp.VersionedRing._activate_locked = orig
        ring2 = _rp.VersionedRing.load(
            ring._keyring_path,
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=pinner, clock=clock)
        try:
            ring2.complete_stuck(provider, "alice")  # proposer herself
        except _rp.RotationError as e:
            assert "self-approval" in str(e), e
        else:
            return False, "stuck self-completion was NOT refused"
        new_epoch = ring2.complete_stuck(provider, "bob")
        assert new_epoch == "epoch-2"
        d = ring2.describe()
        assert not d["stuck"] and d["active_epoch"] == "epoch-2"
        report = ring2.audit_no_silent_swap()
        assert report["violations"] == []
    return True, "STUCK completed with quorum; ceremony fully evidenced"


def _probe_r16_due():
    """R16: due_for_rotation honors auto_rotate_period_s."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        clock = _Clock()
        ring, provider, _, _ = _fresh_ring(
            tmp, clock=clock,
            policy={"grace_period_s": 100, "auto_rotate_period_s": 50})
        assert ring.due_for_rotation() is False
        clock.advance(49)
        assert ring.due_for_rotation() is False
        clock.advance(1)
        assert ring.due_for_rotation() is True
        # Manual-only policy is never due.
        ring2, _, _, _ = _fresh_ring(
            _tmp(), policy={"grace_period_s": 100})
        assert ring2.due_for_rotation() is False
    return True, "auto_rotate_period honored; manual-only never due"


def _probe_r17_no_pinner():
    """R17: require_head_pin=True with no pinner refuses BEFORE any
    mutation."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        clock = _Clock()
        provider = FakeKmsProvider(["master-1"])
        try:
            _rp.VersionedRing.bootstrap(
                os.path.join(tmp, "keyring.json"), provider, "master-1",
                "alice",
                audit_log_path=os.path.join(tmp, "audit.jsonl"),
                deployment_mode="staging", head_pinner=None, clock=clock,
                policy={"grace_period_s": 100, "require_head_pin": True})
        except _rp.RotationError as e:
            assert "head_pinner" in str(e), e
        else:
            return False, "bootstrap without pinner did NOT refuse"
        assert not os.path.exists(os.path.join(tmp, "keyring.json")), \
            "keyring file was created despite refusal"
    return True, "bootstrap refuses without pinner before any mutation"


def _probe_r17b_no_pinner_approve():
    """R17b: approve_pending refuses loudly when the pinner is missing
    and pinning is required (checked before mutation)."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        clock = _Clock()
        pinner = _Pinner()
        provider = FakeKmsProvider(["master-1"])
        ring = _rp.VersionedRing.bootstrap(
            os.path.join(tmp, "keyring.json"), provider, "master-1",
            "alice",
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=pinner, clock=clock,
            policy={"grace_period_s": 100, "require_head_pin": True})
        ring._head_pinner = None  # operator unwired it afterwards
        pid = ring.begin_rotation("alice")
        try:
            ring.approve_pending(pid, "bob", provider)
        except _rp.RotationError as e:
            assert "head_pinner" in str(e), e
        else:
            return False, "approve without pinner did NOT refuse"
        d = ring.describe()
        assert d["active_epoch"] == "epoch-1", "mutated despite refusal"
        assert d["pending"] is not None
    return True, "missing pinner refuses before any mutation"


def _probe_r18_unpinned():
    """R18: require_head_pin=False chains head_pinned:false AND the
    replay audit flags the unpinned head."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        clock = _Clock()
        provider = FakeKmsProvider(["master-1"])
        ring = _rp.VersionedRing.bootstrap(
            os.path.join(tmp, "keyring.json"), provider, "master-1",
            "alice",
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=None, clock=clock,
            policy={"grace_period_s": 100, "require_head_pin": False})
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        log = _read_log(os.path.join(tmp, "audit.jsonl"))
        unpinned = [e for e in log
                    if e["event"] == "rotation_head_unpinned"]
        assert unpinned and unpinned[0]["head_pinned"] is False
        try:
            ring.audit_no_silent_swap()
        except _rp.RotationError as e:
            assert "unpinned" in str(e), e
        else:
            return False, "unpinned head was NOT flagged"
    return True, "unpinned head chained AND flagged loudly"


def _probe_r19_pinner_fails():
    """R19: a failing pinner -> RotationError; the journal is kept so
    reconcile() can mark STUCK and a human can retry."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        clock = _Clock()
        pinner = _Pinner(fail=True)
        provider = FakeKmsProvider(["master-1"])
        # Bootstrap pins too: use a working pinner for bootstrap, then
        # swap in the failing one.
        good = _Pinner()
        ring = _rp.VersionedRing.bootstrap(
            os.path.join(tmp, "keyring.json"), provider, "master-1",
            "alice",
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=good, clock=clock,
            policy={"grace_period_s": 100, "require_head_pin": True})
        ring._head_pinner = pinner
        pid = ring.begin_rotation("alice")
        try:
            ring.approve_pending(pid, "bob", provider)
        except _rp.RotationError as e:
            assert "head_pinner failed" in str(e), e
        else:
            return False, "pinner failure did NOT raise"
        # Journal kept: next load -> STUCK, human retries with a good
        # pinner.
        ring2 = _rp.VersionedRing.load(
            ring._keyring_path,
            audit_log_path=os.path.join(tmp, "audit.jsonl"),
            deployment_mode="staging", head_pinner=good, clock=clock)
        assert ring2.describe()["stuck"] is True
        ring2.complete_stuck(provider, "bob")
        assert ring2.describe()["active_epoch"] == "epoch-2"
    return True, "pinner failure fails closed; retry completes"


def _probe_r20_operator_empty():
    """R20: empty operator identities are refused."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        for bad in ("", "   ", None, 123):
            try:
                ring.begin_rotation(bad)
            except _rp.RotationError:
                pass
            else:
                return False, "empty proposer %r NOT refused" % (bad,)
        pid = ring.begin_rotation("alice")
        for bad in ("", "   ", None, 123):
            try:
                ring.approve_pending(pid, bad, provider)
            except _rp.RotationError:
                pass
            else:
                return False, "empty approver %r NOT refused" % (bad,)
        assert ring.describe()["active_epoch"] == "epoch-1"
    return True, "empty operator identities refused"


def _probe_r21_double_begin():
    """R21: begin_rotation while one is pending is refused."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        ring.begin_rotation("alice")
        try:
            ring.begin_rotation("carol")
        except _rp.RotationError as e:
            assert "already pending" in str(e), e
        else:
            return False, "double begin was NOT refused"
    return True, "second begin refused while one is pending"


def _probe_r22_audit_unwritable():
    """R22: with no audit key, the ceremony refuses BEFORE mutating."""
    if _ABSENT:
        return _GAP
    with _no_log_key():
        tmp = _tmp()
        provider = FakeKmsProvider(["master-1"])
        try:
            _rp.VersionedRing.bootstrap(
                os.path.join(tmp, "keyring.json"), provider, "master-1",
                "alice",
                audit_log_path=os.path.join(tmp, "audit.jsonl"),
                deployment_mode="staging", head_pinner=_Pinner(),
                clock=_Clock())
        except _rp.RotationError as e:
            assert "audit log" in str(e), e
        else:
            return False, "bootstrap without audit key did NOT refuse"
        assert not os.path.exists(os.path.join(tmp, "keyring.json")), \
            "keyring file was created despite refusal"
    return True, "unwritable audit log refuses before any mutation"


def _probe_r23_material_free():
    """R23: describe() and audit events carry zero key material."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", provider)
        blob_texts = set()
        for ep in ("epoch-1", "epoch-2"):
            wd = ring._ring.get(ep)
            blob_texts.add(wd.wrapped_blob.hex())
        desc_text = json.dumps(ring.describe())
        for b in blob_texts:
            assert b not in desc_text, "wrapped blob leaked into describe()"
        log_text = io.open(os.path.join(tmp, "audit.jsonl"),
                           encoding="utf-8").read()
        for b in blob_texts:
            assert b not in log_text, "wrapped blob leaked into audit log"
        for ev in _read_log(os.path.join(tmp, "audit.jsonl")):
            assert "wrapped_b64" not in json.dumps(ev)
    return True, "no key bytes in describe() or audit events"


def _probe_r24_kms_outage():
    """R24: KMS outage mid-ceremony fails closed; ring unmutated."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        pid = ring.begin_rotation("alice")
        provider.outage = True
        try:
            ring.approve_pending(pid, "bob", provider)
        except KmsError:
            pass
        else:
            return False, "KMS outage did NOT fail closed"
        finally:
            provider.outage = False
        d = ring.describe()
        assert d["active_epoch"] == "epoch-1", "ring mutated on outage"
        assert d["pending"]["state"] == "proposed", d["pending"]
        assert [v["epoch"] for v in d["versions"]] == ["epoch-1"]
    return True, "outage fails closed; ring unmutated"


def _probe_r25_pending_journal():
    """R25: the pending journal is explicit at every step and clears
    only after activate + audit + pin."""
    if _ABSENT:
        return _GAP
    with _log_key():
        tmp = _tmp()
        ring, provider, clock, pinner = _fresh_ring(tmp)
        assert ring.describe()["pending"] is None
        pid = ring.begin_rotation("alice")
        pend = ring.describe()["pending"]
        assert pend["state"] == "proposed"
        assert pend["activated"] is False
        new_epoch = ring.approve_pending(pid, "bob", provider)
        assert new_epoch == "epoch-2"
        assert ring.describe()["pending"] is None, \
            "journal not cleared after full ceremony"
    return True, "journal explicit; cleared only after full ceremony"


_PROBES = (
    ("R1", "ROTATE_CEREMONY", _probe_r1_rotate_ceremony),
    ("R2", "SELF_APPROVAL", _probe_r2_self_approval),
    ("R3", "QUORUMLESS", _probe_r3_quorumless),
    ("R4", "GRACE_UNWRAP", _probe_r4_grace_unwrap),
    ("R5", "GRACE_SWEEP", _probe_r5_grace_sweep),
    ("R6", "DESTROY", _probe_r6_destroy),
    ("R7", "FLOOR", _probe_r7_floor),
    ("R8", "UNKNOWN_VERSION", _probe_r8_unknown_version),
    ("R9", "SILENT_SWAP", _probe_r9_silent_swap),
    ("R10", "LOG_TAMPER", _probe_r10_log_tamper),
    ("R11", "MIDDLE_DELETE", _probe_r11_middle_delete),
    ("R12", "TAIL_TRUNCATE", _probe_r12_tail_truncate),
    ("R13", "STUCK", _probe_r13_stuck),
    ("R14", "STUCK_DISCARD", _probe_r14_stuck_discard),
    ("R15", "STUCK_COMPLETE", _probe_r15_stuck_complete),
    ("R16", "DUE", _probe_r16_due),
    ("R17", "NO_PINNER", _probe_r17_no_pinner),
    ("R17b", "NO_PINNER_APPROVE", _probe_r17b_no_pinner_approve),
    ("R18", "UNPINNED", _probe_r18_unpinned),
    ("R19", "PINNER_FAILS", _probe_r19_pinner_fails),
    ("R20", "OPERATOR_EMPTY", _probe_r20_operator_empty),
    ("R21", "DOUBLE_BEGIN", _probe_r21_double_begin),
    ("R22", "AUDIT_UNWRITABLE", _probe_r22_audit_unwritable),
    ("R23", "MATERIAL_FREE", _probe_r23_material_free),
    ("R24", "KMS_OUTAGE", _probe_r24_kms_outage),
    ("R25", "PENDING_JOURNAL", _probe_r25_pending_journal),
)


def main():
    results = []
    for tag, name, fn in _PROBES:
        try:
            run1 = fn()
        except Exception as e:  # harness failure, not a probe verdict
            import traceback
            traceback.print_exc()
            print("%s %s: ERROR (unexpected exception: %r)" % (tag, name, e))
            results.append("ERROR")
            continue
        try:
            run2 = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("%s %s: ERROR (unexpected exception on rerun: %r)"
                  % (tag, name, e))
            results.append("ERROR")
            continue
        if run1[0] != run2[0]:
            print("%s %s: ERROR (verdict changed between runs: %r vs %r)"
                  % (tag, name, run1, run2))
            results.append("ERROR")
            continue
        held, detail = run1
        print("%s %s: %s -- %s" % (tag, name,
                                   "HELD" if held else "GAP", detail))
        results.append("HELD" if held else "GAP")
    held_n = results.count("HELD")
    print("rotation-policy: %d/%d HELD" % (held_n, len(results)))
    return 0 if held_n == len(results) else 1


def _green_check():
    """Depth-1 green check: adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for suite in ("tests.test_rotation_policy", "tests.test_kms",
                  "tests.test_keyset"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                            " | ".join(tail)))
        if r.returncode != 0:
            return False
    return True


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
