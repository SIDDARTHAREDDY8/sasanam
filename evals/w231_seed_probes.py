#!/usr/bin/env python3
"""Wave-231 lane B: seeded refusal digests + denial-evidence durability.

Re-derived pattern (nothing copied): a denial record is seeded into the
audit log OUTSIDE the denied transaction -- its digest chain anchors to
the audit log's current head, never to the transaction that was denied,
so a rolled-back transaction cannot erase its own denial. When a signed
denial receipt cannot be formed, an explicit receipt-less-denial record
carries its own reason instead of silence: silence is never evidence.

Seams under test:
* gov/seeded_denials.py -- seed_denial(...) produces a record anchored
  to the passed log-head digest; verify_denial(record,
  denied_txn_digests) recomputes the digest and refuses
  ``denial-anchored-in-denied-transaction`` when the anchor lives
  inside the denied transaction's digest chain; receipt-less records
  refuse ``seeded-denial-malformed`` when they carry neither a
  receipt digest nor a ``denial-receipt-unavailable-<cause>`` reason;
  tampered records refuse ``seeded-denial-digest-mismatch``;
  denial_survives_rollback(record, post_rollback_entries) refuses
  ``denial-evidence-lost`` when the committed record digest is absent
  from the post-rollback log; denial_as_authority refuses
  ``seeded-denial-not-authorization``.

Attack shapes: anchor the denial inside the denied transaction (then
roll it back); drop the denial commit during rollback; flip a record
field; present None instead of a record; emit a receipt-less record
with no reason (silence); smuggle a non-digest anchor.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-230 HEAD
04cf20c3c286e5a83eddbcc0bf970e1c9ae08194.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g231b
  TMPDIR=/var/tmp/g231b ~/workspace/.gov-venv/bin/python evals/w231_seed_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import subprocess
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import seeded_denials as _sd
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

PROBE_NAMES = [
    "seed-outside-transaction-verifies",
    "seed-anchored-in-transaction-refused",
    "receipt-less-denial-explicit",
    "receipt-less-silence-refused",
    "rollback-survives",
    "rollback-loss-refused",
    "tampered-record-refused",
    "malformed-record-refused",
]


def _d(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _refuses(fn, code):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            return True
        raise AssertionError(
            "expected code %r, got %r (%r)" % (code, got, exc))
    return False


def _chain(*labels):
    """A synthetic audit-log digest chain: entries with hash/prev_hash."""
    entries = []
    prev = "00" * 32
    for label in labels:
        h = hashlib.sha256(
            (prev + _d(label)).encode("utf-8")).hexdigest()
        entries.append({"label": label, "prev_hash": prev, "hash": h})
        prev = h
    return entries


def _seed_args(anchor, receipt_digest=None, cause=None):
    kw = {
        "decision_digest": _d("decision-1"),
        "deny_reason_code": "hybrid-suite-not-accepted",
        "rule_path": "policy/default/hybrid-gate",
        "log_head_digest": anchor,
    }
    if receipt_digest is not None:
        kw["receipt_digest"] = receipt_digest
    if cause is not None:
        kw["receipt_unavailable_cause"] = cause
    return kw


def _p01_outside():
    log = _chain("e1", "e2")
    txn = _chain("t1", "t2")
    rec = _sd.seed_denial(**_seed_args(log[-1]["hash"],
                                       receipt_digest=_d("receipt-1")))
    out = _sd.verify_denial(rec, denied_txn_digests={
        e["hash"] for e in txn})
    if not out.get("ok"):
        return "BREAK", "outside-anchored denial did not verify: %r" % out
    if out.get("anchor") != log[-1]["hash"]:
        return "BREAK", "anchor not the log head: %r" % out
    return "HELD", "outside-anchored denial verifies"


def _p02_inside():
    log = _chain("e1", "e2")
    txn = _chain("t1", "t2")
    rec = _sd.seed_denial(**_seed_args(txn[0]["hash"],
                                       receipt_digest=_d("receipt-1")))
    ok = _refuses(
        lambda: _sd.verify_denial(
            rec, denied_txn_digests={e["hash"] for e in txn}),
        "denial-anchored-in-denied-transaction")
    return (("HELD", "in-transaction anchor refused "
             "denial-anchored-in-denied-transaction")
            if ok else ("BREAK", "in-transaction anchor accepted"))


def _p03_receipt_less():
    log = _chain("e1", "e2")
    txn = _chain("t1", "t2")
    rec = _sd.seed_denial(**_seed_args(
        log[-1]["hash"], receipt_digest=None,
        cause="no-intent-evidence"))
    if rec.get("kind") != "receipt-less-denial":
        return "BREAK", "receipt-less kind not marked: %r" % rec.get("kind")
    reason = rec.get("receipt_less_reason")
    if reason != "denial-receipt-unavailable-no-intent-evidence":
        return "BREAK", "reason not exact: %r" % (reason,)
    out = _sd.verify_denial(rec, denied_txn_digests={
        e["hash"] for e in txn})
    if not out.get("ok"):
        return "BREAK", "receipt-less denial did not verify: %r" % out
    return "HELD", "receipt-less denial explicit with cause"


def _p04_silence():
    log = _chain("e1", "e2")
    # Silence is never evidence: None fails closed.
    ok_none = _refuses(
        lambda: _sd.verify_denial(None, denied_txn_digests=set()),
        "seeded-denial-malformed")
    # A receipt-less record carrying neither receipt nor reason is
    # silence in record form.
    rec = _sd.seed_denial(**_seed_args(log[-1]["hash"],
                                       receipt_digest=_d("receipt-1")))
    silent = dict(rec)
    del silent["digest"]
    silent["kind"] = "receipt-less-denial"
    silent["receipt_digest"] = None
    silent["receipt_less_reason"] = None
    silent["digest"] = _sd.record_digest(
        {k: v for k, v in silent.items() if k != "digest"})
    ok_silent = _refuses(
        lambda: _sd.verify_denial(silent, denied_txn_digests=set()),
        "seeded-denial-malformed")
    if ok_none and ok_silent:
        return "HELD", "None and reason-less records refuse malformed"
    return "BREAK", "silence accepted: none=%r silent=%r" % (
        ok_none, ok_silent)


def _p05_survives():
    log = _chain("e1", "e2")
    txn = _chain("t1", "t2")
    rec = _sd.seed_denial(**_seed_args(log[-1]["hash"],
                                       receipt_digest=_d("receipt-1")))
    commit = _sd.denial_commit_entry(rec)
    post = list(log) + [dict(commit, seq=3, prev_hash=log[-1]["hash"])]
    # The denied transaction rolled back: its entries are gone, the
    # denial commit (outside the region) survives.
    out = _sd.denial_survives_rollback(
        rec, post_rollback_entries=post)
    if not out.get("ok"):
        return "BREAK", "surviving denial not found: %r" % out
    return "HELD", "denial commit survives rollback of the denied txn"


def _p06_loss():
    log = _chain("e1", "e2")
    txn = _chain("t1", "t2")
    # Attacker seeds inside the transaction and the rollback eats the
    # commit: the denial record is gone.
    rec = _sd.seed_denial(**_seed_args(txn[0]["hash"],
                                       receipt_digest=_d("receipt-1")))
    post = list(log)  # rollback removed everything past e2
    ok = _refuses(
        lambda: _sd.denial_survives_rollback(
            rec, post_rollback_entries=post),
        "denial-evidence-lost")
    return (("HELD", "lost denial refuses denial-evidence-lost")
            if ok else ("BREAK", "lost denial treated as present"))


def _p07_tampered():
    log = _chain("e1", "e2")
    rec = _sd.seed_denial(**_seed_args(log[-1]["hash"],
                                       receipt_digest=_d("receipt-1")))
    bad = dict(rec)
    bad["decision_digest"] = _d("other-decision")
    ok = _refuses(lambda: _sd.verify_denial(bad, denied_txn_digests=set()),
                  "seeded-denial-digest-mismatch")
    return (("HELD", "tampered record refuses "
             "seeded-denial-digest-mismatch")
            if ok else ("BREAK", "tampered record accepted"))


def _p08_malformed():
    log = _chain("e1", "e2")
    head = log[-1]["hash"]
    # Non-digest anchor refused at seed time.
    ok_seed = _refuses(lambda: _sd.seed_denial(**_seed_args("not-a-digest")),
                       "seeded-denial-malformed")
    # Contradictory receipt + cause refused.
    ok_contra = _refuses(
        lambda: _sd.seed_denial(**_seed_args(
            head, receipt_digest=_d("r"), cause="x")),
        "seeded-denial-malformed")
    # Unknown-field record refused at verify.
    rec = _sd.seed_denial(**_seed_args(head, receipt_digest=_d("receipt-1")))
    bad = dict(rec)
    bad["extra"] = "field"
    ok_extra = _refuses(lambda: _sd.verify_denial(bad, denied_txn_digests=set()),
                        "seeded-denial-malformed")
    # Authority-shaped use refused.
    ok_auth = _refuses(lambda: _sd.denial_as_authority(rec),
                       "seeded-denial-not-authorization")
    all_ok = ok_seed and ok_contra and ok_extra and ok_auth
    return (("HELD", "malformed/contradiction/unknown-field/authority refused")
            if all_ok else ("BREAK", "seed=%r contra=%r extra=%r auth=%r"
                            % (ok_seed, ok_contra, ok_extra, ok_auth)))


_PROBES = [
    _p01_outside, _p02_inside, _p03_receipt_less, _p04_silence,
    _p05_survives, _p06_loss, _p07_tampered, _p08_malformed,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            results.append((name, "GAP",
                            "gov/seeded_denials.py absent (pristine red)"))
            continue
        t0 = time.time()
        try:
            verdict, detail = probe()
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
            detail = "%r %s" % (exc, traceback.format_exc(limit=2))
        dt = time.time() - t0
        results.append((name, verdict, "%s (%.2fs)" % (detail, dt)))
    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_decision_codes.py",
                 "tests/test_deny_receipts.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w231 seeded-denial probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
