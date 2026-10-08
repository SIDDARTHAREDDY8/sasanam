"""Wave-329 independent red-team battery.

Base: dd034c36 (wave-328 merge). Footer: open F415 / next F417
(F413/F414 CLOSED; F415/F416 filed by wave-330 lane 3, LOW, OPEN). Pin: 2100.

P1  wave-328 seams not yet broken: Shamir custody (share forgery,
    ceremony mixing, duplicates, length drift, commitment games,
    transcript tamper, distribute overwrite, t=1, <t shares, rekey),
    standing_verdicts post-F412 (atomic conflict shape, legacy replay,
    tip-guard), the 7 residual hardenings.
P2  F413 re-probe (HELD -- F413 CLOSED wave-329 lane 1).
P3  F412/F411/F410 closure-regression probes (all must stay HELD).
P4  merge-defect class: wave-328's pin-only --theirs clobbering of
    semantic changes (P1a/P1h rewrites, _EXPECTED_BREAKS) -- probe the
    shipped tree actually contains the lane-2 semantics and pin
    comments match the pin value.
P5  pin 2100 + footer state probes.
P6  prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env),
    tallies verified by direct child runs.

gov/ is byte-identical to base: this battery changes no product code and
files findings only (from F414; F414 CLOSED by wave-330 lane 1).
No new decision codes from this lane.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F640, F641, F642, F643"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F426-F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640


FOOTER_NEXT = "F644"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


def _expect_code(pid, fn, exc_types, code, note):
    """fn must raise an exc with .code == code. HELD iff so."""
    try:
        fn()
    except exc_types as exc:
        if getattr(exc, "code", None) == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: wrong code %r (want %s)"
                      % (note, getattr(exc, "code", None), code))
    except Exception as exc:
        return _break(pid, "%s: unexpected %s (want coded %s)"
                      % (note, type(exc).__name__, code))
    return _break(pid, "%s: no refusal (want coded %s)" % (note, code))


from gov import shamir_custody as sc  # noqa: E402
from gov import standing_verdicts as sv  # noqa: E402


def _tmpd():
    return tempfile.mkdtemp(prefix="w329-", dir=_run_root())


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w329rt")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


# ---------------------------------------------------------------------------
# P1: Shamir custody seams.
# ---------------------------------------------------------------------------

@probe("P1a-shamir-share-forgery-refused")
def _p1a():
    """A forged share (bytes flipped, commitment intact) refuses coded.

    The commitment is the backstop: reconstruction against the shards'
    published commitment must reject the wrong secret, never return it.
    """
    shards = sc.split(b"f" * 32, 5, 3, "p1a-ceremony")
    forged = dict(shards[0])
    bad = bytearray(bytes(forged["share"]))
    bad[0] ^= 0xFF
    forged["share"] = bytes(bad)
    return _expect_code(
        "P1a-shamir-share-forgery-refused",
        lambda: sc.combine([forged, shards[1], shards[2]]),
        sc.ShamirCustodyError, "custody-shamir-commitment-mismatch",
        "forged share")


@probe("P1b-shamir-ceremony-mixing-refused")
def _p1b():
    """Shards from two ceremonies for the same secret never mix."""
    secret = b"m" * 32
    a = sc.split(secret, 5, 3, "p1b-ceremony-a")
    b = sc.split(secret, 5, 3, "p1b-ceremony-b")
    return _expect_code(
        "P1b-shamir-ceremony-mixing-refused",
        lambda: sc.combine([a[0], a[1], b[2]]),
        sc.ShamirCustodyError, "custody-shamir-ceremony-mismatch",
        "cross-ceremony set")


@probe("P1c-shamir-duplicate-share-refused")
def _p1c():
    """The same share index twice refuses coded (Lagrange would invert 0)."""
    shards = sc.split(b"c" * 32, 5, 3, "p1c-ceremony")
    return _expect_code(
        "P1c-shamir-duplicate-share-refused",
        lambda: sc.combine([shards[0], dict(shards[0]), shards[1]]),
        sc.ShamirCustodyError, "custody-shamir-duplicate-share",
        "duplicate index")


@probe("P1d-shamir-length-drift-refused")
def _p1d():
    """A truncated share refuses coded."""
    shards = sc.split(b"d" * 32, 5, 3, "p1d-ceremony")
    short = dict(shards[0])
    short["share"] = bytes(short["share"])[:16]
    return _expect_code(
        "P1d-shamir-length-drift-refused",
        lambda: sc.combine([short, shards[1], shards[2]]),
        sc.ShamirCustodyError, "custody-shamir-share-malformed",
        "short share")


@probe("P1e-shamir-forged-commitment-set-refused")
def _p1e():
    """Same ceremony, divergent commitment across shards: refused coded."""
    shards = sc.split(b"e" * 32, 5, 3, "p1e-ceremony")
    evil = dict(shards[0])
    evil["commitment"] = hashlib.sha256(b"other").hexdigest()
    return _expect_code(
        "P1e-shamir-forged-commitment-set-refused",
        lambda: sc.combine([evil, shards[1], shards[2]]),
        sc.ShamirCustodyError, "custody-shamir-commitment-mismatch",
        "divergent commitment")


@probe("P1f-shamir-transcript-tamper-refused")
def _p1f():
    """A tampered ceremony transcript refuses coded on verify."""
    d = _tmpd()
    tp = sc.CeremonyTranscript(os.path.join(d, "ceremony.jsonl"))
    tp.record("init", {"ceremony_id": "p1f-c"})
    tp.record("combine", {"ceremony_id": "p1f-c", "shares": 3})
    with open(tp.path, "a", encoding="utf-8") as fh:
        fh.write('{"schema": "tampered"}\n')
    return _expect_code(
        "P1f-shamir-transcript-tamper-refused",
        tp.verify,
        sc.ShamirCustodyError, "custody-shamir-transcript-corrupt",
        "tampered transcript")


@probe("P1g-shamir-distribute-overwrite-refused")
def _p1g():
    """distribute never overwrites a live shard; nothing is written."""
    d = _tmpd()
    shards = sc.split(b"g" * 32, 2, 2, "p1g-ceremony")
    live = os.path.join(d, "shard0")
    with open(live, "wb") as fh:
        fh.write(b"live")
    try:
        sc.distribute(shards, {"alice": live,
                               "bob": os.path.join(d, "shard1")})
    except sc.ShamirCustodyError as exc:
        if exc.code != "custody-shamir-distribute-refused":
            return _break("P1g-shamir-distribute-overwrite-refused",
                          "wrong code %r" % (exc.code,))
    else:
        return _break("P1g-shamir-distribute-overwrite-refused",
                      "no refusal on live shard")
    left = sorted(os.listdir(d))
    if left != ["shard0"]:
        return _break("P1g-shamir-distribute-overwrite-refused",
                      "partial write: %r" % (left,))
    with open(live, "rb") as fh:
        if fh.read() != b"live":
            return _break("P1g-shamir-distribute-overwrite-refused",
                          "live shard clobbered")
    return _held("P1g-shamir-distribute-overwrite-refused",
                 "live shard protected, nothing written")


@probe("P1h-shamir-distribute-symlink-alias-partial-write")
def _p1h():
    """F414 (CLOSED 2026-10-04 wave-330 lane 1): symlink aliases must not
    defeat distribute's pre-flight atomicity.

    Two assignment paths that spell the same file differently
    (symlink vs real path) must refuse coded in the pre-flight BEFORE
    anything is written. The probe asserts: (a) the refusal carries the
    coded `custody-shamir-distribute-refused` (never a bare OSError), and
    (b) the target directory is empty afterwards -- no partial write.
    On the open tree this probe demonstrated the BREAK (loud refusal
    AFTER one shard was written); on the closed tree it asserts the
    coded pre-flight refusal.
    """
    d = _tmpd()
    link = os.path.join(_run_root(), "w329-link")
    try:
        os.symlink(d, link)
    except OSError:
        return _held("P1h-shamir-distribute-symlink-alias-partial-write",
                     "symlink creation unavailable in this env (skip)")
    try:
        shards = sc.split(b"h" * 32, 2, 2, "p1h-ceremony")
        try:
            sc.distribute(shards,
                          {"alice": os.path.join(d, "shard"),
                           "bob": os.path.join(link, "shard")})
            return _break(
                "P1h-shamir-distribute-symlink-alias-partial-write",
                "no refusal at all on aliased paths")
        except sc.ShamirCustodyError as exc:
            if exc.code != "custody-shamir-distribute-refused":
                return _break(
                    "P1h-shamir-distribute-symlink-alias-partial-write",
                    "wrong code %r" % (exc.code,))
        left = sorted(os.listdir(d))
        if left == ["shard"]:
            return _break(
                "P1h-shamir-distribute-symlink-alias-partial-write",
                "F414 reproduces: loud refusal AFTER one shard was "
                "written (partial distribution under symlink alias); "
                "the 'before anything is written' guarantee is broken")
        return _held("P1h-shamir-distribute-symlink-alias-partial-write",
                     "no partial write (left=%r)" % (left,))
    finally:
        try:
            os.unlink(link)
        except OSError:
            pass


@probe("P1i-shamir-t1-refused")
def _p1i():
    """t=1 is not threshold custody: refused at split."""
    return _expect_code(
        "P1i-shamir-t1-refused",
        lambda: sc.split(b"i" * 32, 5, 1, "p1i-ceremony"),
        sc.ShamirCustodyError, "custody-shamir-bad-params",
        "t=1")


@probe("P1j-shamir-insufficient-shares-refused")
def _p1j():
    """t-1 shares are refused without guessing the secret."""
    shards = sc.split(b"j" * 32, 5, 3, "p1j-ceremony")
    return _expect_code(
        "P1j-shamir-insufficient-shares-refused",
        lambda: sc.combine(shards[:2]),
        sc.ShamirCustodyError, "custody-shamir-insufficient-shares",
        "2 of 3")


@probe("P1k-shamir-rekey-retires-old-shards")
def _p1k():
    """Rekeyed shards never mix with the retired ceremony's shards."""
    secret = b"k" * 32
    old = sc.split(secret, 5, 3, "p1k-old")
    new = sc.rekey(secret, 5, 3, "p1k-new", supersedes="p1k-old")
    if sc.combine(new[:3]) != secret:
        return _break("P1k-shamir-rekey-retires-old-shards",
                      "fresh ceremony does not reconstruct")
    return _expect_code(
        "P1k-shamir-rekey-retires-old-shards",
        lambda: sc.combine([old[0], old[1], new[2]]),
        sc.ShamirCustodyError, "custody-shamir-ceremony-mismatch",
        "old+new mix")


@probe("P1l-shamir-secret-floor-holds")
def _p1l():
    """The 128-bit secret floor holds, including non-int/bool input."""
    bad = 0
    for arg in (b"short", b"", True, 15):
        try:
            sc.generate_secret(arg)
        except sc.ShamirCustodyError as exc:
            if exc.code == "custody-shamir-bad-params":
                bad += 1
                continue
            return _break("P1l-shamir-secret-floor-holds",
                          "wrong code %r for %r" % (exc.code, arg))
        except Exception as exc:
            return _break("P1l-shamir-secret-floor-holds",
                          "uncoded %s for %r" % (type(exc).__name__, arg))
        else:
            return _break("P1l-shamir-secret-floor-holds",
                          "accepted %r" % (arg,))
    if bad != 4:
        return _break("P1l-shamir-secret-floor-holds",
                      "only %d/4 refused" % (bad,))
    return _held("P1l-shamir-secret-floor-holds",
                 "floor holds for short/empty/bool/15")

# ---------------------------------------------------------------------------
# P1 (cont.): standing_verdicts post-F412 + residual hardenings.
# ---------------------------------------------------------------------------

def _sv_store():
    d = _tmpd()
    return sv.StandingStore(os.path.join(d, "journal.jsonl")), d


def _k(digest, standing, known_since, origin="o", collector="c",
       justification="j", supersedes=None):
    return {"artifact_digest": digest, "asserted_standing": standing,
            "justification": justification, "origin": origin,
            "collector": collector, "known_since": known_since,
            "supersedes": supersedes}


@probe("P1m-standing-legacy-crash-journal-recovers")
def _p1m():
    """A legacy two-append crash journal replays to pre-conflict knowledge.

    Hand-crafted legacy shape: conflict metadata with NO asserted_standing
    as the journal tip (the F412 crash window). Reload must NOT wedge:
    standing_of reads the pre-conflict standing and writes attach.
    """
    store, d = _sv_store()
    digest = "sha256:" + "a" * 64
    store.register_artifact(digest, "test")
    store.attach_knowledge(_k(digest, "trusted", 100))
    # Append a legacy crash-window conflict entry directly (no knowledge).
    with open(store._path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "conflict", "seq": 2,
                             "artifact_digest": digest,
                             "code": "supplychain-standing-conflict",
                             "winner_standing": "quarantined",
                             "loser_standing": "trusted"}) + "\n")
    store2 = sv.StandingStore(store._path)
    got = store2.standing_of(digest)
    if got["standing"] != "trusted":
        return _break("P1m-standing-legacy-crash-journal-recovers",
                      "standing=%r, want pre-conflict 'trusted'"
                      % (got["standing"],))
    # Writes must attach (tip is at pre-conflict knowledge, supersedes=1).
    try:
        e = store2.attach_knowledge(_k(digest, "quarantined", 200,
                                       supersedes=1))
    except Exception as exc:
        return _break("P1m-standing-legacy-crash-journal-recovers",
                      "write refused: %s" % (exc,))
    if store2.standing_of(digest)["standing"] != "quarantined":
        return _break("P1m-standing-legacy-crash-journal-recovers",
                      "write did not take")
    return _held("P1m-standing-legacy-crash-journal-recovers",
                 "legacy crash journal replays clean, never wedges")


@probe("P1n-standing-atomic-conflict-entry-valid-tip")
def _p1n():
    """A post-F412 conflict entry is a valid tip with full audit metadata."""
    store, d = _sv_store()
    digest = "sha256:" + "b" * 64
    store.register_artifact(digest, "test")
    e1 = store.attach_knowledge(_k(digest, "trusted", 100))
    # Concurrent conflicting write (same parent as the tip, seq 1).
    conflict = store.attach_knowledge(_k(digest, "quarantined", 200,
                                        supersedes=None))
    if conflict.get("kind") != "conflict":
        return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                      "kind=%r, want 'conflict'" % (conflict.get("kind"),))
    if "asserted_standing" not in conflict:
        return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                      "conflict entry has no asserted_standing (F412 shape)")
    if conflict["asserted_standing"] != "quarantined":
        return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                      "winner standing=%r" % (conflict["asserted_standing"],))
    # A second concurrent conflict against the same parent.
    conflict2 = store.attach_knowledge(_k(digest, "revoked", 300,
                                          supersedes=1))
    if conflict2.get("kind") != "conflict" \
            or conflict2.get("asserted_standing") != "revoked":
        return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                      "second conflict malformed: %r"
                      % (conflict2.get("kind"),))
    # Reload: the tip must be the conflict entry and standing_of must work.
    store2 = sv.StandingStore(store._path)
    got = store2.standing_of(digest)
    if got["standing"] != "revoked":
        return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                      "reloaded standing=%r, want 'revoked'"
                      % (got["standing"],))
    for field in ("winner_standing", "loser_standing", "winner_known_since",
                  "loser_known_since", "code"):
        if conflict2.get(field) is None:
            return _break("P1n-standing-atomic-conflict-entry-valid-tip",
                          "audit metadata missing: %s" % (field,))
    return _held("P1n-standing-atomic-conflict-entry-valid-tip",
                 "single-entry conflicts are valid tips with audit metadata")


@probe("P1o-standing-tip-guard-refuses-coded")
def _p1o():
    """_tip_entry refuses coded (never bare KeyError) on a corrupt tip."""
    store, d = _sv_store()
    digest = "sha256:" + "c" * 64
    store.register_artifact(digest, "test")
    store.attach_knowledge(_k(digest, "trusted", 100))
    # Corrupt the in-memory tip pointer to a non-knowledge seq (white-box).
    store._tips[digest] = 0  # seq 0 is the register entry
    return _expect_code(
        "P1o-standing-tip-guard-refuses-coded",
        lambda: store.standing_of(digest),
        sv.StandingError, "supplychain-standing-journal-corrupt",
        "corrupt tip")


@probe("P1p-scan-reregistration-refused-loud")
def _p1p():
    """register_skill twice refuses LOUD; history is not re-baselined."""
    from gov import background_scan as bs
    d = _tmpd()
    sp = os.path.join(d, "state.json")
    kw = dict(skill_path="skill-a", delegation_wire=b"dw", authz_wire=b"aw",
              skill_bytes=b"bytes", ttl_seconds=3600,
              scan_interval_seconds=60, now=1000)
    bs.register_skill(sp, **kw)
    try:
        bs.register_skill(sp, **kw)
    except Exception as exc:
        if getattr(exc, "code", None) == \
                "supplychain-scan-already-registered":
            return _held("P1p-scan-reregistration-refused-loud",
                         "re-registration refused coded")
        return _break("P1p-scan-reregistration-refused-loud",
                      "wrong code %r" % (getattr(exc, "code", None),))
    return _break("P1p-scan-reregistration-refused-loud",
                  "re-registration silently re-baselined")


@probe("P1q-scan-config-path-cannot-rebaseline")
def _p1q():
    """update_skill_registration changes config only, never the baseline."""
    from gov import background_scan as bs
    d = _tmpd()
    sp = os.path.join(d, "state.json")
    bs.register_skill(sp, skill_path="skill-b", delegation_wire=b"dw",
                      authz_wire=b"aw", skill_bytes=b"bytes1",
                      ttl_seconds=3600, scan_interval_seconds=60, now=1000)
    rec = bs.update_skill_registration(sp, skill_path="skill-b",
                                       ttl_seconds=7200)
    if rec.get("digest") is None:
        return _break("P1q-scan-config-path-cannot-rebaseline",
                      "digest missing after config update")
    try:
        bs.update_skill_registration(sp, skill_path="skill-b",
                                     ttl_seconds=7200,
                                     scan_interval_seconds=120)
    except Exception as exc:
        return _break("P1q-scan-config-path-cannot-rebaseline",
                      "legit config change refused: %s" % (exc,))
    # No digest/baseline parameter exists on the config path by design.
    import inspect
    params = inspect.signature(bs.update_skill_registration).parameters
    if any(p in params for p in ("skill_bytes", "delegation_wire",
                                 "authz_wire", "digest")):
        return _break("P1q-scan-config-path-cannot-rebaseline",
                      "config path accepts baseline material")
    return _held("P1q-scan-config-path-cannot-rebaseline",
                 "config path is baseline-free")


@probe("P1r-scan-missed-intervals-arithmetic-under-clock-jump")
def _p1r():
    """A pathological caller clock cannot spin the scan O(gap)."""
    from gov import background_scan as bs
    d = _tmpd()
    sp = os.path.join(d, "state.json")
    bs.register_skill(sp, skill_path="skill-c", delegation_wire=b"dw",
                      authz_wire=b"aw", skill_bytes=b"bytes",
                      ttl_seconds=3600, scan_interval_seconds=60, now=1000)
    rec = {"scan_interval_seconds": 60, "next_scan_at": 1000,
           "digest": "x", "delegations_version": None,
           "ttl_seconds": 3600, "status": "never-scanned"}
    missed, total = None, None
    try:
        trig, missed, total = bs._evaluate_triggers(
            rec, digest_now="x", deleg_version_now=None, now=10 ** 12)
    except Exception as exc:
        return _break("P1r-scan-missed-intervals-arithmetic-under-clock-jump",
                      "raised %s" % (exc,))
    if total <= 0:
        return _break("P1r-scan-missed-intervals-arithmetic-under-clock-jump",
                      "total=%r" % (total,))
    if len(missed) > bs.MAX_MISSED_INTERVALS_REPORTED:
        return _break("P1r-scan-missed-intervals-arithmetic-under-clock-jump",
                      "list not capped: %d" % (len(missed),))
    if total != (10 ** 12 - 1000 - 1) // 60:
        return _break("P1r-scan-missed-intervals-arithmetic-under-clock-jump",
                      "total not arithmetic: %r" % (total,))
    return _held("P1r-scan-missed-intervals-arithmetic-under-clock-jump",
                 "total=%d arithmetic, list capped at %d"
                 % (total, len(missed)))


@probe("P1s-scan-clock-trust-loud")
def _p1s():
    """Every scan report carries the caller-supplied clock-trust contract."""
    from gov import background_scan as bs
    if getattr(bs, "CLOCK_TRUST", None) != "caller-supplied":
        return _break("P1s-scan-clock-trust-loud",
                      "CLOCK_TRUST=%r" % (getattr(bs, "CLOCK_TRUST", None),))
    if "caller-supplied" not in (bs.run_scan.__doc__ or "") \
            and "clock_trust" not in (bs.run_scan.__doc__ or ""):
        # The contract lives on the report and the module docs; the
        # report field is the load-bearing part (checked below).
        pass
    d = _tmpd()
    sp = os.path.join(d, "state.json")
    bs.register_skill(sp, skill_path="skill-d", delegation_wire=b"dw",
                      authz_wire=b"aw", skill_bytes=b"bytes",
                      ttl_seconds=3600, scan_interval_seconds=60, now=1000)
    try:
        reports = bs.run_scan(
            sp,
            [{"skill_path": "skill-d", "skill_bytes": b"bytes",
              "delegation_wire": b"dw", "authz_wire": b"aw"}],
            root_trust={}, now=1000)
    except Exception as exc:
        return _break("P1s-scan-clock-trust-loud",
                      "run_scan raised %s" % (exc,))
    if not reports:
        return _break("P1s-scan-clock-trust-loud", "no reports")
    for rep in reports:
        if rep.get("clock_trust") != "caller-supplied":
            return _break("P1s-scan-clock-trust-loud",
                          "report clock_trust=%r" % (rep.get("clock_trust"),))
    return _held("P1s-scan-clock-trust-loud",
                 "clock_trust=caller-supplied on every report")


@probe("P1t-standing-chain-includes-agreeing-tip")
def _p1t():
    """The justification chain omits no knowledge voice (W327-4)."""
    store, d = _sv_store()
    digest = "sha256:" + "d" * 64
    store.register_artifact(digest, "test")
    e1 = store.attach_knowledge(_k(digest, "trusted", 100))
    # Agreeing concurrent attach (same parent, same standing).
    store.attach_knowledge(_k(digest, "trusted", 150, supersedes=None))
    chain = store.standing_of(digest)["chain"]
    seqs = [c["seq"] for c in chain]
    if len(chain) < 2:
        return _break("P1t-standing-chain-includes-agreeing-tip",
                      "chain has %d entries, want >= 2" % (len(chain),))
    return _held("P1t-standing-chain-includes-agreeing-tip",
                 "chain seqs=%r" % (seqs,))


@probe("P1u-advisory-version-tie-refused")
def _p1u():
    """An exact version tie between different records refuses LOUD."""
    from gov import advisory_binding as ab
    from gov.advisory_binding import PinnedAdvisory
    a = PinnedAdvisory({"version": 3, "advisory_id": "a"})
    b = PinnedAdvisory({"version": 3, "advisory_id": "b"})
    try:
        ab.supersede([a, b])
    except Exception as exc:
        if getattr(exc, "code", None) == "advisory-version-tie":
            return _held("P1u-advisory-version-tie-refused",
                         "tie refused coded")
        return _break("P1u-advisory-version-tie-refused",
                      "wrong code %r" % (getattr(exc, "code", None),))
    return _break("P1u-advisory-version-tie-refused",
                  "tie silently first-wins")


@probe("P1v-advisory-input-unpinned-refused")
def _p1v():
    """check_package accepts only bind_advisory_input-sealed records."""
    from gov import advisory_binding as ab
    hand = {"advisory_policy_input": "p", "advisory_id": "x", "version": 1,
            "fetched_at": 1.0, "freshness_seconds": 60,
            "signature_threshold": 1, "valid_signatures": 1, "flags": {}}
    try:
        ab.check_package(hand, "pkg", 10)
    except Exception as exc:
        if getattr(exc, "code", None) == "advisory-input-unpinned":
            return _held("P1v-advisory-input-unpinned-refused",
                         "hand-built dict refused coded")
        return _break("P1v-advisory-input-unpinned-refused",
                      "wrong code %r" % (getattr(exc, "code", None),))
    return _break("P1v-advisory-input-unpinned-refused",
                  "hand-built dict accepted")


@probe("P1w-advisory-seal-convention-honest")
def _p1w():
    """The PinnedAdvisory seal is documented as convention-grade (W326-3).

    A deliberately hand-built PinnedAdvisory passes the isinstance gate;
    the module docstring says so honestly ('a caller that deliberately
    builds one is attacking its own check'). This probe pins the
    documented honesty so a future silent upgrade/downgrade is visible.
    """
    from gov import advisory_binding as ab
    from gov.advisory_binding import PinnedAdvisory
    doc = PinnedAdvisory.__doc__ or ""
    if "attacking its own check" not in doc:
        return _break("P1w-advisory-seal-convention-honest",
                      "honesty note missing from PinnedAdvisory docstring")
    return _held("P1w-advisory-seal-convention-honest",
                 "convention-grade seal documented honestly")


# ---------------------------------------------------------------------------
# P2: F413 re-probes (HELD -- F413 CLOSED wave-329 lane 1).
# ---------------------------------------------------------------------------

@probe("P2a-f413-feed-version-ordering")
def _p2a():
    import w328_redteam_probes as w328
    return _relabel("P2a-f413-feed-version-ordering", w328._p1b)


@probe("P2b-f413-intermediate-revocation-recorded")
def _p2b():
    import w328_redteam_probes as w328
    return _relabel("P2b-f413-intermediate-revocation-recorded", w328._p1c)


# ---------------------------------------------------------------------------
# P3: F412/F411/F410 closure-regression probes (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P3a-f412-closure-regression")
def _p3a():
    import w327_redteam_probes as w327
    return _relabel("P3a-f412-closure-regression", w327._p1f)


@probe("P3b-f411-closure-regression")
def _p3b():
    import w327_redteam_probes as w327
    return _relabel("P3b-f411-closure-regression", w327._p3a)


@probe("P3c-f410-closure-regression-t4c")
def _p3c():
    import w327_redteam_probes as w327
    return _relabel("P3c-f410-closure-regression-t4c", w327._p2a)


@probe("P3d-f410-closure-regression-t4d")
def _p3d():
    import w327_redteam_probes as w327
    return _relabel("P3d-f410-closure-regression-t4d", w327._p2b)


# ---------------------------------------------------------------------------
# P4: the wave-328 merge defect class (pin-only --theirs clobbering).
# ---------------------------------------------------------------------------

@probe("P4a-merge-semantics-p1a-p1h-present")
def _p4a():
    """Lane-2's P1a/P1h rewrites survive in the shipped w326 battery.

    The wave-328 merge's pin-only --theirs silently dropped lane 2's
    P1a/P1h rewrites (transplanted back pre-push). This probe pins
    their presence so a future merge clobber is loud.
    """
    src = open(os.path.join(REPO, "evals", "w326_redteam_probes.py")).read()
    missing = []
    for needle in ("P1a-supersede-tie-order-dependent",
                   "P1h-handbuilt-pin-inflated-signatures",
                   "HARDENED (wave-328 lane 2)",
                   "advisory-version-tie"):
        if needle not in src:
            missing.append(needle)
    if missing:
        return _break("P4a-merge-semantics-p1a-p1h-present",
                      "clobbered: %r" % (missing,))
    return _held("P4a-merge-semantics-p1a-p1h-present",
                 "lane-2 semantics present in shipped battery")


@probe("P4b-merge-expected-breaks-not-clobbered")
def _p4b():
    """w328_redteam's _EXPECTED_BREAKS still excludes the removed P5x IDs.

    The wave-328 merge's lane-2 _EXPECTED_BREAKS overwrite dropped lane
    1's emptied set (restored pre-push); wave-329 lane 1 emptied it again
    for the F413 closure. Pin the post-closure state.
    """
    import w328_redteam_probes as w328
    removed = {"P5b", "P5c", "P5e", "P5f", "P5g"}
    # The closed set must be empty: F413 CLOSED wave-329 lane 1.
    want = set()
    if set(w328._EXPECTED_BREAKS) != want:
        return _break("P4b-merge-expected-breaks-not-clobbered",
                      "_EXPECTED_BREAKS=%r" % (sorted(w328._EXPECTED_BREAKS),))
    return _held("P4b-merge-expected-breaks-not-clobbered",
                 "_EXPECTED_BREAKS is empty (F413 closed)")


@probe("P4c-pin-comments-match-pin-value")
def _p4c():
    """Pin history comments name the real pin (blind-repoint drift check).

    The wave-328 merge caught blind-repoint corruption of lane history
    comments (restored pre-push). Probe: every TAXONOMY_PIN line's
    claimed final value equals the live constant on that line.
    """
    bad = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        for skip in (".git", "__pycache__"):
            if skip in dirnames:
                dirnames.remove(skip)
        for name in filenames:
            if not name.endswith(".py"):
                continue
            p = os.path.join(dirpath, name)
            try:
                blob = open(p, "rb").read().decode("utf-8", "replace")
            except OSError:
                continue
            for m in re.finditer(r"TAXONOMY_PIN\s*=\s*(\d+)", blob):
                line = blob[:m.start()].count("\n") + 1
                # The full comment line: the FINAL "-> N" in the history
                # prose is the claim about the current pin. (The wave-328
                # merge's blind repoint corrupted these; the restore fixed
                # the ones it touched. Older waves' value-token repoints
                # intentionally leave prose history alone.)
                eol = blob.find("\n", m.end())
                comment = blob[m.end():] if eol < 0 else blob[m.end():eol]
                claimed = re.findall(r"->\s*(\d{4})", comment)
                if claimed and claimed[-1] != m.group(1):
                    bad.append("%s:%d final claim ->%s, pin=%s"
                               % (os.path.relpath(p, REPO), line,
                                  claimed[-1], m.group(1)))
    if bad:
        return _break("P4c-pin-comments-match-pin-value",
                      "drift: %r" % (bad[:5],))
    return _held("P4c-pin-comments-match-pin-value",
                 "pin comments match live pin values")

# ---------------------------------------------------------------------------
# P5: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P5a-pin-taxonomy-2140-sorted")
def _p5a():
    """Taxonomy pin 2100: raw source literals sorted and unique."""
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != TAXONOMY_PIN:
        return _break("P5a-pin-taxonomy-2140-sorted",
                      "want %d, got %d" % (TAXONOMY_PIN, len(lits)))
    if len(set(lits)) != len(lits):
        return _break("P5a-pin-taxonomy-2140-sorted", "duplicate literals")
    if lits != sorted(lits):
        return _break("P5a-pin-taxonomy-2140-sorted", "not sorted")
    return _held("P5a-pin-taxonomy-2140-sorted",
                 "2140/2140/0 sorted unique on raw source literals")


@probe("P5b-footer-open-f433-f434-f435-next-f436")
def _p5b():
    """Footer: open F415; next free F417 (F414/F416 CLOSED wave-330 lane 1 /
    wave-331 lane 2; F415 OPEN filed wave-330 lane 3)."""
    footer = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    # The footer is a long paragraph with historical "Next free" entries;
    # the live one is the LAST.
    ms = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                          r"\*\*Open findings: ([^*]*)\.\*\*",
                          footer))
    if not ms:
        return _break("P5b-footer-open-f433-f434-f435-next-f436",
                      "footer line not found")
    m = ms[-1]
    if m.group(1) != "F" + FOOTER_NEXT[1:]:
        return _break("P5b-footer-open-f433-f434-f435-next-f436",
                      "next=%r, want F%s" % (m.group(1), FOOTER_NEXT[1:]))
    opens = m.group(2).strip()
    if opens != FOOTER_OPEN:
        return _break("P5b-footer-open-f433-f434-f435-next-f436",
                      "open=%r, want %r" % (opens, FOOTER_OPEN))
    return _held("P5b-footer-open-f433-f434-f435-next-f436",
                 "footer open none / next F417")


# ---------------------------------------------------------------------------
# P6: prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env).
# ---------------------------------------------------------------------------

def _run_child_output(battery, timeout=600):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w329child-",
                            dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


def _run_child(battery, marker, fmt, timeout=600):
    """Run a prior battery; parse ITS OWN summary line (for green checks).

    ``marker`` is the battery's distinctive summary-line prefix;
    ``fmt`` is "bhe" (``B BREAK / H HELD / E ERROR``) or "hbe"
    (``H/B/E held/break/error``). Matching the marker avoids picking up
    a nested child battery's tally line.
    """
    text = _run_child_output(battery, timeout)
    lines = [ln for ln in text.splitlines() if marker in ln]
    if not lines:
        return None, "no summary line (%r): %s" % (marker, text[-300:])
    line = lines[-1]
    if fmt == "bhe":
        m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                      line)
        if not m:
            return None, "unparseable summary: %s" % (line[-200:],)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))), None
    m = re.search(r"(\d+)/(\d+)/(\d+)\s+held/break/error", line)
    if not m:
        return None, "unparseable summary: %s" % (line[-200:],)
    return (int(m.group(2)), int(m.group(1)), int(m.group(3))), None


# Every BREAK below is a genuinely open finding, not the wave-305-class
# footer cascade: the F414 closure re-pins child footer-state probes to
# open F415 / next F417 at the wave-330 merge. Until that sweep, the
# closure's own cascade (child probes still pinning open F414) is listed
# per battery below. This probe fails LOUD on any break OUTSIDE the
# cascade (a genuine regression).
_CHILD_CASCADE = {
    # F414 CLOSED 2026-10-04 wave-330 lane 1; F415/F416 OPEN filed
    # 2026-10-04 wave-330 lane 3. The wave-330 merge sweep re-pinned all
    # child footer-state probes to open F415 / next F417, so every
    # cascade set is EMPTY again (wave-305 class). Any child BREAK below
    # is a genuine regression.
    "w328_redteam_probes.py": set(),
    "w328_resid_probes.py": set(),
    "w328_shamir_probes.py": set(),
    "w327_redteam_probes.py": set(),
    "w327_polchan_probes.py": set(),
    "w326_tufaudit_probes.py": set(),
    "w326_redteam_probes.py": set(),
    "w326_standing_probes.py": set(),
    "w326_sched_probes.py": set(),
}

_CHILD_TALLIES = (
    # battery, summary marker, format; tallies observed on this tree
    # (F414 closed) via direct child runs, kept as documentation.
    ("w328_redteam_probes.py", "w328_redteam battery:", "bhe"),
    ("w328_resid_probes.py", "w328_resid battery:", "bhe"),
    ("w328_shamir_probes.py", "w328_shamir battery:", "bhe"),
    ("w327_redteam_probes.py", "w327_redteam battery:", "bhe"),
    ("w327_polchan_probes.py", "w327_polchan battery:", "bhe"),
    ("w326_tufaudit_probes.py", "w326 TUF section-5 audit probes:", "hbe"),
    ("w326_redteam_probes.py", "w326_redteam battery:", "bhe"),
    ("w326_standing_probes.py", "w326_standing battery:", "bhe"),
    ("w326_sched_probes.py", "w326_sched battery:", "bhe"),
)


@probe("P6a-prior-batteries-child-mode-tallies")
def _p6a():
    """Prior batteries: every BREAK is inside the documented cascade.

    Runs each prior battery as a subprocess (GOV_SKIP_GREEN=1 in the
    child env, fresh TMPDIR) and parses its per-probe BREAK IDs. A BREAK
    outside _CHILD_CASCADE -- or any ERROR -- is a genuine regression,
    not the F414-closure footer cascade. Observed tallies on this tree are
    recorded in the note for the merge coordinator's sweep.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return _held("P6a-prior-batteries-child-mode-tallies",
                     "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    bad = []
    tallies = []
    for battery, marker, fmt in _CHILD_TALLIES:
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            bad.append("%s: ERROR %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
        if errors:
            bad.append("%s: ERRORs %s" % (battery, sorted(errors)[:3]))
        outside = breaks - _CHILD_CASCADE[battery]
        if outside:
            bad.append("%s: non-cascade BREAKs %s"
                       % (battery, sorted(outside)[:4]))
        tallies.append("%s breaks=%d" % (battery, len(breaks)))
    if bad:
        return _break("P6a-prior-batteries-child-mode-tallies",
                      "; ".join(bad[:6]))
    return _held("P6a-prior-batteries-child-mode-tallies",
                 "all child BREAKs inside the F414-closure footer cascade; "
                 + "; ".join(tallies))


# ---------------------------------------------------------------------------
# Expected BREAK set, green check, main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # F414 CLOSED 2026-10-04 wave-330 lane 1:
# P1h flips to HELD; no open findings remain on this tree.


def _green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1.

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    # Adjacent batteries most likely to shift under this lane's probes.
    # Assert every BREAK is inside the documented F414-closure cascade
    # set (a genuine regression breaks LOUD here).
    for battery in ("w328_redteam_probes.py",
                    "w327_redteam_probes.py",
                    "w327_polchan_probes.py"):
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            _record("green-check", "ERROR",
                    "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
        outside = breaks - _CHILD_CASCADE[battery]
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-cascade %s" %
                    (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all in cascade" % (battery, len(breaks)))


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    # Only probe IDs (not the green-check record) count toward the set.
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w329_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected: F414 closed 2026-10-04 wave-330 lane 1)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
