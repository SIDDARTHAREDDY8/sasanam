#!/usr/bin/env python3
"""Wave-229 lane A: MMR-signed audit-log checkpoints.

STEAL (re-derived prose; nothing copied) of the checkpointed-local-log
MMR pattern: a Merkle Mountain Range over the audit log's chained entry
digests, with signed checkpoints committing to the peak list + entry
count. Checkpoints prove order, contemporaneity and completeness WITHOUT
publishing record bodies.

This differs from gov/log.py's format-2 checkpoints (RFC 6962-style
signed tree heads): those need the signer at append time and a single
root over a contiguous 1..seq range; the MMR here folds in incrementally
with peak lists, works over digests alone (no log file needed), and the
checkpoints here are standalone governance records a third party can
verify against a digest list it collected.

Seams under test:
* gov/checkpoints.py — MerkleMountainRange.append(digest) folds a leaf
  digest in; .peaks() / .count() expose the commitment; .checkpoint(
  alg, secret, key_id, prev_checkpoint) emits a signed checkpoint
  committing to peaks + count + prev_checkpoint digest.
  verify_checkpoint(checkpoint, entry_digests, key):
  - malformed checkpoint / entry shape refuses ``checkpoint-malformed``
    (checked first);
  - signature verified BEFORE any log comparison: a mutated peak list
    or forged checkpoint refuses ``checkpoint-signature-invalid``
    (forgery fails before state lookups);
  - fewer entries than the committed count refuses
    ``checkpoint-log-incomplete`` (tail truncation);
  - more entries than the committed count refuses
    ``checkpoint-count-mismatch``;
  - same count but peaks disagree refuses ``checkpoint-log-reordered``
    (covers reordering AND silent content substitution at fixed
    count — indistinguishable from peaks alone, documented);
  - checkpoint_evidence(checkpoint) returns a digest-linked evidence
    record that a capsule / audit entry may carry; authority-shaped
    use refuses ``checkpoint-evidence-not-authorization``;
  - verify_checkpoint_chain(checkpoints, keys) checks signatures and
    prev_digest links: a swapped chain refuses
    ``checkpoint-chain-broken``.

Attack shapes: truncate the log tail; reorder two entries; rewrite an
entry's content; flip a peak byte; forge under a wrong key; replay a
checkpoint against a longer log; chain two checkpoints out of order;
offer checkpoint evidence as authority.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-228 HEAD
45fc6cbfa96f82f56e651388513c13af01c3d7b3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g229a
  TMPDIR=/var/tmp/g229a ~/workspace/.gov-venv/bin/python evals/w229_mmr_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g229a-u \\
      ~/workspace/.gov-venv/bin/python evals/w229_mmr_probes.py
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
    from gov import checkpoints as _cp
    from gov import alg_registry as _alg
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False
    _cp = None
    _alg = None

ED = "ed25519-rfc8032"
MAC = "hmac-sha256-mac"

PROBE_NAMES = [
    "mmr-01-valid-checkpoint-verifies",
    "mmr-02-tail-truncation-refused",
    "mmr-03-reorder-refused",
    "mmr-04-tampered-checkpoint-refused",
    "mmr-05-longer-log-refused",
    "mmr-06-checkpoint-chain-consistent",
    "mmr-07-empty-log-checkpoint",
    "mmr-08-wrong-key-forgery-refused",
    "mmr-09-mac-tier-honest-labeling",
    "mmr-10-evidence-not-authority",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _digest(i):
    return hashlib.sha256(("entry-%d" % i).encode()).hexdigest()


def _ed_keypair():
    reg = _alg.default_registry()
    seed, pub = reg.keygen(ED)
    return reg, seed, pub


def _mac_keypair():
    reg = _alg.default_registry()
    key, _ = reg.keygen(MAC)
    return reg, key


def _build(n=7):
    digests = [_digest(i) for i in range(n)]
    mmr = _cp.MerkleMountainRange()
    for d in digests:
        mmr.append(d)
    return digests, mmr


# ----------------------------------------------------------------------
# Probes. Each returns (verdict, detail).
# ----------------------------------------------------------------------

def _p01_valid():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    try:
        out = _cp.verify_checkpoint(cp, digests, pub)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "valid checkpoint refused: %r" % exc
    if out.get("count") != 7 or not out.get("ok"):
        return "BREAK", "valid checkpoint did not verify: %r" % out
    return "HELD", "checkpoint verifies; count=%d peaks=%d" % (
        out["count"], len(cp["peaks"]))


def _p02_truncation():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    # Drop the last entry: the log is shorter than the committed count.
    ok = _refuses(lambda: _cp.verify_checkpoint(cp, digests[:-1], pub),
                  "checkpoint-log-incomplete")
    return ("HELD" if ok else "BREAK",
            "tail truncation refuses checkpoint-log-incomplete")


def _p03_reorder():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    swapped = list(digests)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    ok = _refuses(lambda: _cp.verify_checkpoint(cp, swapped, pub),
                  "checkpoint-log-reordered")
    return ("HELD" if ok else "BREAK",
            "reordered log refuses checkpoint-log-reordered")


def _p04_tampered():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    bad = dict(cp)
    peaks = list(bad["peaks"])
    first = peaks[0]
    peaks[0] = ("0" if first[0] != "0" else "1") + first[1:]
    bad["peaks"] = peaks
    ok = _refuses(lambda: _cp.verify_checkpoint(bad, digests, pub),
                  "checkpoint-signature-invalid")
    return ("HELD" if ok else "BREAK",
            "tampered peak list refuses checkpoint-signature-invalid")


def _p05_longer():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    ok = _refuses(lambda: _cp.verify_checkpoint(cp, digests + [_digest(99)],
                                                pub),
                  "checkpoint-count-mismatch")
    return ("HELD" if ok else "BREAK",
            "longer log refuses checkpoint-count-mismatch")


def _p06_chain():
    reg, seed, pub = _ed_keypair()
    mmr = _cp.MerkleMountainRange()
    checkpoints = []
    prev = None
    for i in range(9):
        d = _digest(i)
        mmr.append(d)
        cp = mmr.checkpoint(ED, seed, "k-ed-1", prev_checkpoint=prev)
        checkpoints.append(cp)
        prev = cp
    try:
        keys = [pub] * len(checkpoints)
        out = _cp.verify_checkpoint_chain(checkpoints, keys)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "checkpoint chain refused: %r" % exc
    if not out.get("ok") or out.get("checked") != len(checkpoints):
        return "BREAK", "chain did not verify: %r" % out
    # Swap two checkpoints: the prev_digest links must break.
    swapped = list(checkpoints)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    ok = _refuses(lambda: _cp.verify_checkpoint_chain(swapped, keys),
                  "checkpoint-chain-broken")
    if not ok:
        return "BREAK", "swapped chain did not refuse checkpoint-chain-broken"
    return "HELD", "9 sequential checkpoints chain consistently"


def _p07_empty():
    mmr = _cp.MerkleMountainRange()
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    try:
        out = _cp.verify_checkpoint(cp, [], pub)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "empty-log checkpoint refused: %r" % exc
    if out.get("count") != 0:
        return "BREAK", "empty-log checkpoint count not 0: %r" % out
    ok = _refuses(lambda: _cp.verify_checkpoint(cp, [_digest(0)], pub),
                  "checkpoint-count-mismatch")
    return ("HELD" if ok else "BREAK",
            "empty-log checkpoint defined; garbage refused")


def _p08_wrong_key():
    digests, mmr = _build(7)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    _, other_seed, other_pub = _ed_keypair()
    ok = _refuses(lambda: _cp.verify_checkpoint(cp, digests, other_pub),
                  "checkpoint-signature-invalid")
    return ("HELD" if ok else "BREAK",
            "checkpoint under wrong key refuses checkpoint-signature-invalid")


def _p09_mac_tier():
    digests, mmr = _build(7)
    reg, key = _mac_keypair()
    cp = mmr.checkpoint(MAC, key, "k-mac-1")
    try:
        out = _cp.verify_checkpoint(cp, digests, key)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "MAC-tier checkpoint refused: %r" % exc
    if out.get("non_repudiation"):
        return "BREAK", "MAC-tier checkpoint claims non-repudiation"
    if not out.get("ok"):
        return "BREAK", "MAC-tier checkpoint did not verify: %r" % out
    return "HELD", "MAC-tier checkpoint verifies, honestly non-repudiation=False"


def _p10_evidence():
    digests, mmr = _build(5)
    reg, seed, pub = _ed_keypair()
    cp = mmr.checkpoint(ED, seed, "k-ed-1")
    ev = _cp.checkpoint_evidence(cp)
    if ev.get("kind") != "mmr-checkpoint-evidence":
        return "BREAK", "evidence record mislabeled: %r" % ev
    # Tampering the evidence must break its digest commitment.
    bad = dict(ev)
    bad["count"] = ev["count"] + 1
    if _cp.evidence_digest(bad) == _cp.evidence_digest(ev):
        return "BREAK", "evidence digest not tamper-evident"
    ok = _refuses(lambda: _cp.evidence_as_authority(ev),
                  "checkpoint-evidence-not-authorization")
    return ("HELD" if ok else "BREAK",
            "evidence digest-linked; authority-shaped use refused")


_PROBES = [
    _p01_valid, _p02_truncation, _p03_reorder, _p04_tampered, _p05_longer,
    _p06_chain, _p07_empty, _p08_wrong_key, _p09_mac_tier, _p10_evidence,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            results.append((name, "GAP",
                            "gov/checkpoints.py absent (pristine red)"))
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
    for unit in ("tests/test_key_identity.py",
                 "tests/test_alg_registry.py"):
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
    print("w229 mmr-checkpoint probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
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
