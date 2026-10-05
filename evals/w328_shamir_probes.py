"""Break-first probes for the wave-328 Shamir t-of-n custody ceremonies.

Red-first: gov/shamir_custody.py is new in this lane, so "red" is
demonstrated two ways: (1) every probe below FAILS on the base tree
(54cdac0d) with ImportError (the module does not exist there --
verified); (2) the product was mutated during development (fresh
coefficients per (byte, x) instead of per byte -- the shares landed on
different curves) and the round-trip probes caught it before any
commit: the battery is genuinely coupled to the behavior, not to the
module's existence.

What the battery pins:
1. split/combine round-trip for several (n, t); any t of n reconstruct.
2. t-1 shares refuse coded custody-shamir-insufficient-shares (never a guess).
3. A corrupted share byte refuses coded custody-shamir-commitment-mismatch.
4. Mixed-ceremony shards refuse coded custody-shamir-ceremony-mismatch.
5. Duplicate share index refuses coded custody-shamir-duplicate-share.
6. Bad params refuse coded custody-shamir-bad-params: t=1, t>n, n<2,
   n>255, empty/short secret, bad ceremony id.
7. Share length mismatch / malformed shards refuse coded
   custody-shamir-share-malformed.
8. distribute: happy path (atomic 0600 files, manifest), duplicate
   custodian paths refused, existing file refused, missing parent
   refused -- all coded custody-shamir-distribute-refused, nothing
   half-written.
9. rekey: new ceremony combines; old+new shards never mix
   (custody-shamir-ceremony-mismatch).
10. Transcript: chain verifies; tampering refuses coded
    custody-shamir-transcript-corrupt; never appends to a broken chain.
11. Pin 2077 + footer open F415 / next F417 (wave-330 merge: F414 closed, F415/F416 filed).

Staging default is set at module level (the harness refuses the declared
ungoverned_ack in production mode).
"""

import base64
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2077  # Wave-327 merge pin 2056; wave-328 lane 3 repoints to 2044 (+8 custody-shamir-*); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)

FOOTER_OPEN = "none"  # F409-F416 CLOSED; no open findings (wave-331 merge).
FOOTER_NEXT = "F417"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def _expect_code(pid, fn, want_code, note):
    from gov import shamir_custody as sc
    try:
        fn()
    except sc.ShamirCustodyError as exc:
        if exc.code == want_code:
            _held(pid, "%s: refused coded %s" % (note, want_code))
        else:
            _break(pid, "%s: refused coded %s, want %s" % (note, exc.code, want_code))
    except Exception as exc:  # noqa: BLE001
        _error(pid, "%s: uncoded %r" % (note, exc))
    else:
        _break(pid, "%s: ACCEPTED, want coded %s" % (note, want_code))


# ---------------------------------------------------------------------------
# P1: round-trips.
# ---------------------------------------------------------------------------

def _p1():
    from gov import shamir_custody as sc
    try:
        for n, t in ((5, 3), (3, 2), (9, 5), (7, 7)):
            secret = sc.generate_secret(32)
            shards = sc.split(secret, n, t, "p1-%d-%d" % (n, t))
            if sc.combine(shards[:t]) != secret:
                return _break("P1-roundtrip", "first-t failed for (%d,%d)" % (n, t))
            if sc.combine(shards) != secret:
                return _break("P1-roundtrip", "all-n failed for (%d,%d)" % (n, t))
            if sc.combine(list(reversed(shards))[:t]) != secret:
                return _break("P1-roundtrip", "reversed failed for (%d,%d)" % (n, t))
        _held("P1-roundtrip", "split/combine round-trips for (5,3),(3,2),(9,5),(7,7)")
    except Exception as exc:  # noqa: BLE001
        _error("P1-roundtrip", "uncoded %r" % (exc,))


# ---------------------------------------------------------------------------
# P2: t-1 refuses.
# ---------------------------------------------------------------------------

def _p2():
    from gov import shamir_custody as sc
    secret = sc.generate_secret(24)
    shards = sc.split(secret, 5, 3, "p2")
    _expect_code("P2-subthreshold-refused",
                 lambda: sc.combine(shards[:2]),
                 "custody-shamir-insufficient-shares",
                 "2 of 3 shares")


# ---------------------------------------------------------------------------
# P3: corrupted share.
# ---------------------------------------------------------------------------

def _p3():
    from gov import shamir_custody as sc
    secret = sc.generate_secret(16)
    shards = sc.split(secret, 5, 3, "p3")
    bad = [dict(s) for s in shards[:3]]
    bad0 = dict(bad[0])
    raw = bytearray(bad0["share"])
    raw[0] ^= 0x01
    bad0["share"] = bytes(raw)
    bad[0] = bad0
    _expect_code("P3-corrupt-share-refused",
                 lambda: sc.combine(bad),
                 "custody-shamir-commitment-mismatch",
                 "one flipped share byte")


# ---------------------------------------------------------------------------
# P4: mixed ceremonies.
# ---------------------------------------------------------------------------

def _p4():
    from gov import shamir_custody as sc
    secret = sc.generate_secret(16)
    a = sc.split(secret, 5, 3, "p4-a")
    b = sc.split(secret, 5, 3, "p4-b")
    _expect_code("P4-ceremony-mix-refused",
                 lambda: sc.combine([a[0], a[1], b[2]]),
                 "custody-shamir-ceremony-mismatch",
                 "shards from two ceremonies")


# ---------------------------------------------------------------------------
# P5: duplicate index.
# ---------------------------------------------------------------------------

def _p5():
    from gov import shamir_custody as sc
    secret = sc.generate_secret(16)
    shards = sc.split(secret, 5, 3, "p5")
    _expect_code("P5-duplicate-index-refused",
                 lambda: sc.combine([shards[0], shards[1], shards[0]]),
                 "custody-shamir-duplicate-share",
                 "same shard twice")


# ---------------------------------------------------------------------------
# P6: bad params.
# ---------------------------------------------------------------------------

def _p6():
    from gov import shamir_custody as sc
    good = sc.generate_secret(16)

    def _t1():
        sc.split(good, 5, 1, "p6-t1")

    def _t_gt_n():
        sc.split(good, 5, 6, "p6-tgtn")

    def _n1():
        sc.split(good, 1, 1, "p6-n1")

    def _n256():
        sc.split(good, 256, 2, "p6-n256")

    def _short():
        sc.split(b"short", 5, 3, "p6-short")

    def _empty():
        sc.split(b"", 5, 3, "p6-empty")

    def _badid():
        sc.split(good, 5, 3, "   ")

    def _badgen():
        sc.generate_secret(8)

    for pid, fn, note in (
            ("P6a-t1-refused", _t1, "t=1"),
            ("P6b-t-gt-n-refused", _t_gt_n, "t>n"),
            ("P6c-n1-refused", _n1, "n=1"),
            ("P6d-n256-refused", _n256, "n=256"),
            ("P6e-short-secret-refused", _short, "short secret"),
            ("P6f-empty-secret-refused", _empty, "empty secret"),
            ("P6g-bad-ceremony-id-refused", _badid, "blank ceremony id"),
            ("P6h-short-gen-refused", _badgen, "generate_secret(8)")):
        _expect_code(pid, fn, "custody-shamir-bad-params", note)


# ---------------------------------------------------------------------------
# P7: malformed shards.
# ---------------------------------------------------------------------------

def _p7():
    from gov import shamir_custody as sc
    secret = sc.generate_secret(16)
    shards = sc.split(secret, 5, 3, "p7")

    def _missing_key():
        bad = dict(shards[0])
        del bad["share"]
        sc.combine([bad, shards[1], shards[2]])

    def _len_mismatch():
        bad = dict(shards[0])
        bad["share"] = bad["share"] + b"\x00"
        sc.combine([bad, shards[1], shards[2]])

    def _bad_index():
        bad = dict(shards[0])
        bad["index"] = 99
        sc.combine([bad, shards[1], shards[2]])

    def _not_dict():
        sc.combine(["nope", shards[1], shards[2]])

    def _bad_blob():
        sc.parse_shard(b"not json")

    for pid, fn, note in (
            ("P7a-missing-key-refused", _missing_key, "missing share key"),
            ("P7b-length-mismatch-refused", _len_mismatch, "share length drift"),
            ("P7c-bad-index-refused", _bad_index, "index out of range"),
            ("P7d-nondict-refused", _not_dict, "non-dict shard"),
            ("P7e-bad-blob-refused", _bad_blob, "unparseable blob")):
        _expect_code(pid, fn, "custody-shamir-share-malformed", note)


# ---------------------------------------------------------------------------
# P8: distribute.
# ---------------------------------------------------------------------------

def _p8():
    from gov import shamir_custody as sc
    tmp = tempfile.mkdtemp(prefix="shamir-p8-")
    try:
        secret = sc.generate_secret(16)
        shards = sc.split(secret, 3, 2, "p8")
        assigns = {"alice": os.path.join(tmp, "alice.shard"),
                   "bob": os.path.join(tmp, "bob.shard"),
                   "carol": os.path.join(tmp, "carol.shard")}
        manifest = sc.distribute(shards, assigns)
        if sorted(manifest) != ["alice", "bob", "carol"]:
            return _break("P8a-distribute-happy", "manifest wrong: %r" % (manifest,))
        # Round-trip through the files.
        loaded = [sc.parse_shard(open(assigns[c], "rb").read()) for c in ("alice", "bob")]
        if sc.combine(loaded) != secret:
            return _break("P8a-distribute-happy", "file round-trip failed")
        # 0600 modes.
        modes = {oct(os.stat(assigns[c]).st_mode & 0o777) for c in assigns}
        if modes != {"0o600"}:
            return _break("P8a-distribute-happy", "modes not 0600: %r" % (modes,))
        _held("P8a-distribute-happy", "3 shards distributed, file round-trip OK, 0600")

        # Transcript parameter: distribute records the ceremony event.
        tr = sc.CeremonyTranscript(os.path.join(tmp, "dist.jsonl"))
        sc.distribute(shards,
                      {"d1": os.path.join(tmp, "d1.shard"),
                       "d2": os.path.join(tmp, "d2.shard"),
                       "d3": os.path.join(tmp, "d3.shard")},
                      transcript=tr)
        if tr.verify() != 1:
            return _break("P8g-distribute-transcript",
                          "distribute event not recorded")
        _held("P8g-distribute-transcript",
              "distribute recorded a transcript event")

        def _dup_path():
            sc.distribute(shards, {"alice": os.path.join(tmp, "x.shard"),
                                   "bob": os.path.join(tmp, "x.shard"),
                                   "carol": os.path.join(tmp, "y.shard")})

        def _overwrite():
            sc.distribute(shards, {"alice": assigns["alice"],
                                   "bob": os.path.join(tmp, "b2.shard"),
                                   "carol": os.path.join(tmp, "c2.shard")})

        def _missing_parent():
            sc.distribute(shards, {"alice": os.path.join(tmp, "nope", "a.shard"),
                                   "bob": os.path.join(tmp, "b3.shard"),
                                   "carol": os.path.join(tmp, "c3.shard")})

        def _count_mismatch():
            sc.distribute(shards, {"alice": os.path.join(tmp, "a4.shard")})

        for pid, fn, note in (
                ("P8b-dup-path-refused", _dup_path, "two custodians one path"),
                ("P8c-overwrite-refused", _overwrite, "existing shard file"),
                ("P8d-missing-parent-refused", _missing_parent, "missing parent dir"),
                ("P8e-count-mismatch-refused", _count_mismatch, "custodian count")):
            _expect_code(pid, fn, "custody-shamir-distribute-refused", note)
        # Nothing half-written by the refused distributions.
        leftovers = [p for p in ("x.shard", "y.shard", "b2.shard", "c2.shard",
                                 "b3.shard", "c3.shard", "a4.shard")
                     if os.path.exists(os.path.join(tmp, p))]
        if leftovers:
            _break("P8f-nothing-half-written",
                   "refused distributions left files: %r" % (leftovers,))
        else:
            _held("P8f-nothing-half-written", "refused distributions wrote nothing")
    except Exception as exc:  # noqa: BLE001
        _error("P8-distribute", "uncoded %r" % (exc,))


# ---------------------------------------------------------------------------
# P9: rekey.
# ---------------------------------------------------------------------------

def _p9():
    from gov import shamir_custody as sc
    tmp = tempfile.mkdtemp(prefix="shamir-p9-")
    try:
        secret = sc.generate_secret(20)
        old = sc.split(secret, 5, 3, "p9-old")
        new = sc.rekey(secret, 5, 3, "p9-new", supersedes="p9-old")
        if sc.combine(new[:3]) != secret:
            return _break("P9a-rekey-combines", "new ceremony does not combine")
        _held("P9a-rekey-combines", "rekeyed ceremony combines")
        _expect_code("P9b-old-new-never-mix",
                     lambda: sc.combine([old[0], old[1], new[2]]),
                     "custody-shamir-ceremony-mismatch",
                     "old + new shards")
        # Transcript parameter: rekey records the ceremony event.
        tr = sc.CeremonyTranscript(os.path.join(tmp, "rekey.jsonl"))
        sc.rekey(secret, 5, 3, "p9-new2", supersedes="p9-new",
                 transcript=tr)
        if tr.verify() != 1:
            return _break("P9c-rekey-transcript",
                          "rekey event not recorded")
        _held("P9c-rekey-transcript", "rekey recorded a transcript event")
    except Exception as exc:  # noqa: BLE001
        _error("P9-rekey", "uncoded %r" % (exc,))


# ---------------------------------------------------------------------------
# P10: transcript.
# ---------------------------------------------------------------------------

def _p10():
    from gov import shamir_custody as sc
    tmp = tempfile.mkdtemp(prefix="shamir-p10-")
    try:
        tpath = os.path.join(tmp, "ceremony.jsonl")
        tr = sc.CeremonyTranscript(tpath)
        tr.record("init", {"ceremony_id": "p10", "threshold": 2, "share_count": 3})
        tr.record("distribute", {"ceremony_id": "p10", "custodians": ["a", "b", "c"]})
        tr.record("combine", {"ceremony_id": "p10", "custodians": ["a", "c"]})
        if tr.verify() != 3:
            return _break("P10a-transcript-verifies", "verify count wrong")
        _held("P10a-transcript-verifies", "3-event chain verifies")

        # Positive pin: revoke on a HEALTHY chain records and verifies.
        tr.record("revoke", {"ceremony_id": "p10", "reason": "custodian-b-retired"})
        if tr.verify() != 4:
            return _break("P10a2-revoke-healthy", "revoke event did not verify")
        _held("P10a2-revoke-healthy", "revoke on healthy chain records, 4-event chain verifies")

        def _bad_event():
            tr.record("explode", {})

        _expect_code("P10b-bad-event-refused", _bad_event,
                     "custody-shamir-bad-params", "unknown event")

        # Tamper: flip a byte in the middle line.
        with open(tpath, "rb") as fh:
            lines = fh.readlines()
        lines[1] = lines[1].replace(b'"a"', b'"X"', 1)
        with open(tpath, "wb") as fh:
            fh.writelines(lines)
        _expect_code("P10c-tamper-refused",
                     lambda: sc.CeremonyTranscript(tpath).verify(),
                     "custody-shamir-transcript-corrupt",
                     "tampered middle line")

        # Never appends to a broken chain.
        def _append_broken():
            sc.CeremonyTranscript(tpath).record("revoke", {"ceremony_id": "p10"})

        _expect_code("P10d-no-append-to-broken", _append_broken,
                     "custody-shamir-transcript-corrupt",
                     "record on tampered transcript")
    except Exception as exc:  # noqa: BLE001
        _error("P10-transcript", "uncoded %r" % (exc,))


# ---------------------------------------------------------------------------
# P11: pin + footer.
# ---------------------------------------------------------------------------

def _p11():
    from gov import decision_codes as dc
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    if len(codes) != TAXONOMY_PIN or len(set(codes)) != TAXONOMY_PIN:
        return _break("P11-pin-taxonomy-2077-sorted",
                      "want 2077/2077 got %d/%d" % (len(codes), len(set(codes))))
    if codes != sorted(codes):
        return _break("P11-pin-taxonomy-2077-sorted", "not sorted")
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return _break("P11-pin-taxonomy-2077-sorted", "TAXONOMY dict size drift")
    _held("P11-pin-taxonomy-2077-sorted", "2077/2077/0 sorted unique")
    # Footer state.
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    m = None
    for line in text.splitlines():
        if "Next free finding" in line:
            m = line
    if m is None or "F415" not in m or "F416" not in m or "F417" not in m:
        _break("P11-footer-open-none-next-F419", "footer line wrong: %r" % (m,))
    else:
        _held("P11-footer-open-none-next-F419", "footer open none / next F419")


# ---------------------------------------------------------------------------
# Green checks (depth-1: children run with GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skip", "HELD", "green checks skipped (child mode)")
        return
    import subprocess
    children = [["-m", "unittest", "tests.test_shamir_custody", "-v"]]
    for child in children:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        try:
            proc = subprocess.run(
                [sys.executable] + child,
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
            ok = proc.returncode == 0 and "OK" in (proc.stdout + proc.stderr)
            note = (proc.stdout + proc.stderr)[-500:]
        except Exception as exc:  # noqa: BLE001
            ok = False
            note = "%s" % (exc,)
        _record("green-" + ".".join(child[1:3]), "HELD" if ok else "BREAK",
                "%s: %s" % ("ok" if ok else "FAILED", note))


def main(argv):
    for fn in (_p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            _error(fn.__name__, "uncoded %r" % (exc,))
    _green()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    print("w328_shamir battery: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    for pid, verdict, note in _results:
        if verdict != "HELD":
            print("  [%s] %s: %s" % (verdict, pid, note))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if not green_ok:
        print("GREEN CHECKS FAILED")
    return 1 if (breaks or errors or not green_ok) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
