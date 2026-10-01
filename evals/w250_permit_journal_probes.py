"""Wave-250 permit-journal probes: break-first pins for gov/permit_journal.py.

Break-first discipline (diagnosing-bugs skill): each probe drives the
ACTUAL journal code path and asserts the attacker's exact win condition
or the durability property. A probe that goes red (BREAK/GAP) on the
pristine base is the missing capability; after the build every probe
must go green (HELD).

Attack shapes (adversarial durability threat model, local-only):
  restart_loss      - permit state must survive process restart
                      (durable JSONL + replay, not deployment memory)
  replay_confusion   - full lifecycle must replay to the correct state
  terminal_escape    - expired/revoked/finalized permits must refuse
                      further transitions (no resurrection)
  pre_grant_use      - USE/EXPIRE/REVOKE/FINALIZE before GRANT must
                      refuse (unknown permit)
  double_grant       - a second GRANT for the same permit id must refuse
  event_replay       - re-appending an event_id must refuse (idempotent
                      append)
  mac_forge          - a record with a valid sha256 chain link but a
                      forged HMAC must fail closed on load
  key_confusion      - opening the journal with the wrong key must fail
                      closed (HMAC binds the key)
  byte_flip          - flipping a byte mid-file must fail closed
  torn_tail          - a crash-torn final line must fail closed
  snapshot_lie       - a tampered snapshot sidecar (with a re-anchored
                      SnapshotLoaded record) must fail closed at the
                      snapshot-MAC layer
  weak_key           - keys shorter than 16 bytes must refuse

Properties pinned:
  mac_determinism, mac_binds_payload, compact_preserves_state,
  chain_continues_across_compact, snapshot_anchor_binding.

RED run (2026-09-30, pristine 5495ece): 0/16 HELD, 16 GAP
  (gov.permit_journal absent -- the capability does not exist).
GREEN run: 16/16 HELD (staging and env -u GOV_DEPLOYMENT_MODE).

Hygiene: module-level staging setdefault; no in-repo git subprocesses;
fresh TMPDIR per run; stdlib only. Green check is depth-1 and honors
GOV_SKIP_GREEN (runs the lane's own unit tests, never another battery).
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from gov import permit_journal as pj
    from gov import durable_journal as dj
    _IMPORT_ERROR = None
except Exception as exc:  # pristine base: capability absent
    pj = None
    dj = None
    _IMPORT_ERROR = exc


# ---------------------------------------------------------------------------
# Probe harness
# ---------------------------------------------------------------------------

def _run(name, fn):
    """Run one probe. Returns (name, verdict, evidence)."""
    if _IMPORT_ERROR is not None:
        return (name, "GAP",
                "gov.permit_journal absent: %r" % (_IMPORT_ERROR,))
    try:
        verdict, evidence = fn()
    except AssertionError as exc:
        return (name, "GAP", "assertion failed: %s" % (exc,))
    except Exception as exc:  # probe harness error, not a product verdict
        return (name, "ERROR", "%r" % (exc,))
    return (name, verdict, evidence)


def _held(evidence):
    return ("HELD", evidence)


def _tmpdir():
    return tempfile.mkdtemp(prefix="w250-pj-")


def _key():
    return os.urandom(32)


def _expect_code(fn, code):
    """Assert fn() raises PermitJournalError with the exact code."""
    try:
        fn()
    except pj.PermitJournalError as exc:
        assert exc.code == code, \
            "wrong code: %r, want %r (detail: %s)" % (
                exc.code, code, exc)
        return _held("refused with %s" % code)
    raise AssertionError("no refusal raised; want %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_grant_survives_restart():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("permit-1", {"scope": "read", "principal": "agent-7"})
        del j  # process restart: drop the instance entirely
        j2 = pj.PermitJournal(path, key=key)
        st = j2.permit_state("permit-1")
        assert st["state"] == "granted", st
        assert st["granted"]["payload"]["scope"] == "read", st
        return _held("grant replayed after restart")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_full_lifecycle_replay():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("p", {"scope": "write"})
        j.record_use("p", {"tool": "shell", "argv_digest": "a" * 64})
        j.record_use("p", {"tool": "shell", "argv_digest": "b" * 64})
        j.finalize("p", "d" * 64)
        st = j.permit_state("p")
        assert st["state"] == "finalized", st
        assert st["n_events"] == 4, st
        assert st["terminal"] == pj.PERMIT_FINALIZED, st
        return _held("grant->use->use->finalize replays to finalized")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_expired_is_terminal():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {})
        j.expire("p", "ttl elapsed")
        st = j.permit_state("p")
        assert st["state"] == "expired", st
        return _expect_code(
            lambda: j.record_use("p", {"tool": "x"}),
            "permit-journal-transition-illegal")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_revoked_is_terminal():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {})
        j.revoke("p", "operator recall", revoked_by="op-1")
        st = j.permit_state("p")
        assert st["state"] == "revoked", st
        return _expect_code(
            lambda: j.grant("p", {}),
            "permit-journal-transition-illegal")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_finalize_is_terminal():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {})
        j.finalize("p", "r" * 64)
        return _expect_code(
            lambda: j.expire("p", "too late"),
            "permit-journal-transition-illegal")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_use_before_grant_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        assert j.permit_state("ghost")["state"] == "unknown"
        return _expect_code(
            lambda: j.record_use("ghost", {"tool": "x"}),
            "permit-journal-unknown-permit")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_double_grant_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {"scope": "read"})
        return _expect_code(
            lambda: j.grant("p", {"scope": "write"}),
            "permit-journal-transition-illegal")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_duplicate_event_id_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {}, event_id="e" * 32)
        # a replayed event_id on a DIFFERENT permit must also refuse:
        # event ids are globally unique, not per-permit.
        return _expect_code(
            lambda: j.grant("q", {}, event_id="e" * 32),
            "permit-journal-duplicate-event")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_forged_mac_detected():
    """Valid sha256 chain link, forged HMAC: the HMAC layer (not the
    sha256 layer) must fail closed."""
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("honest", {"scope": "read"})
        del j
        # attacker appends through the raw durable journal: the sha256
        # chain stays valid, but the HMAC is forged.
        raw = dj.Journal(path)
        evil = {"permit_id": "evil", "event_id": "f" * 32,
                "event_type": pj.PERMIT_GRANTED,
                "issued_at": "2026-09-30T00:00:00+00:00",
                "mono_ns": 1, "payload": {"scope": "root"},
                "prev_mac": "0" * 64, "mac": "f" * 64}
        raw.append(pj.PERMIT_GRANTED, evil)
        try:
            pj.PermitJournal(path, key=key)
        except pj.PermitJournalError as exc:
            assert exc.code == "permit-journal-chain-broken", exc.code
            return _held("forged MAC failed closed (chain-broken)")
        raise AssertionError("forged MAC was accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_wrong_key_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        j = pj.PermitJournal(path, key=_key())
        j.grant("p", {"scope": "read"})
        del j
        try:
            pj.PermitJournal(path, key=_key())  # different key
        except pj.PermitJournalError as exc:
            assert exc.code == "permit-journal-chain-broken", exc.code
            return _held("wrong key failed closed (chain-broken)")
        raise AssertionError("wrong key was accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_byte_flip_detected():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("p", {"scope": "read"})
        j.record_use("p", {"tool": "shell"})
        del j
        with open(path, "rb") as f:
            data = bytearray(f.read())
        data[len(data) // 2] ^= 0x01  # flip one byte mid-file
        with open(path, "wb") as f:
            f.write(bytes(data))
        try:
            pj.PermitJournal(path, key=key)
        except pj.PermitJournalError as exc:
            assert exc.code == "permit-journal-corrupted", exc.code
            return _held("byte flip failed closed (corrupted)")
        raise AssertionError("byte flip was accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_torn_tail_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("p", {"scope": "read"})
        del j
        with open(path, "rb") as f:
            data = f.read()
        lines = data.split(b"\n")
        # cut the final record line in half: crash mid-fsync.
        torn = b"\n".join(lines[:-2] + [lines[-2][: len(lines[-2]) // 2]])
        with open(path, "wb") as f:
            f.write(torn)
        try:
            pj.PermitJournal(path, key=key)
        except pj.PermitJournalError as exc:
            assert exc.code == "permit-journal-corrupted", exc.code
            return _held("torn tail failed closed (corrupted)")
        raise AssertionError("torn tail was accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_compact_preserves_state():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("p1", {"scope": "read"})
        j.record_use("p1", {"tool": "shell"})
        j.grant("p2", {"scope": "write"})
        j.take_snapshot()
        j.compact()
        del j
        j2 = pj.PermitJournal(path, key=key)
        s1 = j2.permit_state("p1")
        s2 = j2.permit_state("p2")
        assert s1["state"] == "used" and s1["n_events"] == 2, s1
        assert s2["state"] == "granted" and s2["n_events"] == 1, s2
        # the HMAC chain continues across the snapshot boundary
        j2.record_use("p2", {"tool": "shell"})
        assert j2.permit_state("p2")["state"] == "used"
        return _held("states + chain survive snapshot/compact")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def p_compact_tampered_snapshot_refused():
    """Tamper the snapshot sidecar, then re-anchor the SnapshotLoaded
    record so the durable-journal anchor still verifies: the
    permit-journal snapshot-MAC layer must fail closed."""
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        j.grant("p1", {"scope": "read"})
        ref = j.take_snapshot()
        j.compact()
        del j
        sidecar = os.path.join(d, ref["snapshot_path"])
        with open(sidecar, "rb") as f:
            stored = json.loads(f.read().decode("utf-8"))
        # lie: claim p1 was revoked in the folded snapshot state
        stored["body"]["states"]["p1"]["state"] = "revoked"
        raw = (json.dumps(stored, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
        with open(sidecar, "wb") as f:
            f.write(raw)
        new_sidecar_hash = hashlib.sha256(raw).hexdigest()
        # re-anchor: fix the SnapshotLoaded record to match
        with open(path, "rb") as f:
            lines = f.read().split(b"\n")
        rec = json.loads(lines[0].decode("utf-8"))
        assert rec["type"] == "SnapshotLoaded", rec["type"]
        rec["body"]["snapshot_hash"] = new_sidecar_hash
        rec["hash"] = hashlib.sha256(_canonical({
            "seq": rec["seq"], "prev": rec["prev"], "txn": rec["txn"],
            "type": rec["type"], "body": rec["body"]})).hexdigest()
        lines[0] = _canonical(rec)
        with open(path, "wb") as f:
            f.write(b"\n".join(lines))
        try:
            pj.PermitJournal(path, key=key)
        except pj.PermitJournalError as exc:
            assert exc.code == "permit-journal-snapshot-tampered", \
                exc.code
            return _held("tampered snapshot failed closed "
                         "(snapshot-tampered)")
        raise AssertionError("tampered snapshot was accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_short_key_refused():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        return _expect_code(
            lambda: pj.PermitJournal(path, key=b"short"),
            "permit-journal-key-weak")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def p_mac_binds_payload():
    d = _tmpdir()
    try:
        path = os.path.join(d, "j.jsonl")
        key = _key()
        j = pj.PermitJournal(path, key=key)
        e1 = j.grant("p1", {"scope": "read"})
        e2 = j.grant("p2", {"scope": "read"})
        # same fields except permit_id/event_id -> different MACs
        assert e1["mac"] != e2["mac"], "MAC does not bind the event"
        # determinism: rebuild the MAC over e1's bytes by hand
        recomputed = pj.event_mac(
            key, e1["permit_id"], e1["event_id"], e1["event_type"],
            e1["issued_at"], e1["mono_ns"], e1["payload"],
            e1["prev_mac"])
        assert recomputed == e1["mac"], "MAC not deterministic"
        return _held("MAC binds full event bytes, deterministic")
    finally:
        shutil.rmtree(d, ignore_errors=True)


PROBES = [
    ("grant_survives_restart", p_grant_survives_restart),
    ("full_lifecycle_replay", p_full_lifecycle_replay),
    ("expired_is_terminal", p_expired_is_terminal),
    ("revoked_is_terminal", p_revoked_is_terminal),
    ("finalize_is_terminal", p_finalize_is_terminal),
    ("use_before_grant_refused", p_use_before_grant_refused),
    ("double_grant_refused", p_double_grant_refused),
    ("duplicate_event_id_refused", p_duplicate_event_id_refused),
    ("forged_mac_detected", p_forged_mac_detected),
    ("wrong_key_refused", p_wrong_key_refused),
    ("byte_flip_detected", p_byte_flip_detected),
    ("torn_tail_refused", p_torn_tail_refused),
    ("compact_preserves_state", p_compact_preserves_state),
    ("compact_tampered_snapshot_refused",
     p_compact_tampered_snapshot_refused),
    ("short_key_refused", p_short_key_refused),
    ("mac_binds_payload", p_mac_binds_payload),
]


def green_check():
    """Depth-1 green check: run the lane's unit tests, nothing deeper.

    Honors GOV_SKIP_GREEN. Never spawns another battery's main.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    repo_root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_permit_journal"],
        cwd=repo_root, env=env, capture_output=True, text=True,
        timeout=300)
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    return proc.returncode


def main():
    results = [_run(name, fn) for name, fn in PROBES]
    held = [r for r in results if r[1] == "HELD"]
    gap = [r for r in results if r[1] == "GAP"]
    err = [r for r in results if r[1] == "ERROR"]
    for name, verdict, evidence in results:
        print("%-32s %-6s %s" % (name, verdict, evidence))
    print("HELD %d / GAP %d / ERROR %d (of %d)" % (
        len(held), len(gap), len(err), len(results)))
    if gap or err:
        return 1
    if len(held) != len(PROBES):
        print("probe count mismatch")
        return 1
    return green_check()


if __name__ == "__main__":
    sys.exit(main())
