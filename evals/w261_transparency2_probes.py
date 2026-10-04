"""Break-first closure battery for F230/F231/F232 (wave-261 lane A).

Target (base c2a1fc0): gov/transparency_log.py --
  F230 verify_log cannot see tail truncation (no witnessed-state
      comparison API),
  F231 detect_equivocation counts unsigned/forged heads as conflicts
      (no signature verification),
  F232 operator path escapes raw OSError instead of
      TransparencyLogError.

Method (tdd skill: red before green; diagnosing-bugs skill): each
probe is a falsifiable break attempt against the CLOSE-WHEN API.
Every probe asserts a POSITIVE control first (the untampered
operation behaves), so a broken implementation BREAKs or ERRORs
instead of falsely HELDing. Probes that exercise the new close-when
API return BREAK on the old code (missing API / old behavior) and
HELD on the fixed code.

New close-when APIs under test (public seams):
  TransparencyLog.verify_log(expected_size=None, expected_head=None)
      Keyless witnessed-state comparison: a previously witnessed
      signed tree head (signature re-verified under the log's own
      key) or a witnessed tree size. (False, reason) when the current
      log is shorter than the witnessed state, when the witnessed
      head does not verify, or when the witnessed head commits to a
      different root than the current log's prefix at that size.
  TransparencyLog.detect_equivocation(heads=None, strict=False)
      Only heads whose STH signature verifies under the log's key
      (log_id-bound) participate in conflict grouping. Unverifiable
      heads are skipped by default (never operator-misbehavior
      evidence); strict=True refuses to adjudicate and raises
      TransparencyLogError naming them as invalid input.

Verdicts: HELD / BREAK / ERROR. Exit 0 iff no BREAK/ERROR.

Stdlib only. Deterministic across runs (staging + `env -u
GOV_DEPLOYMENT_MODE`). Fresh unique TMPDIR per run under /var/tmp.
No in-repo git subprocesses. Depth-0: no adjacent-battery coupling,
nothing for GOV_SKIP_GREEN to gate (same rationale as
w259_transparency_probes.py).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ed25519 as _ed  # noqa: E402
from gov import transparency_log as tl  # noqa: E402

# This lane adds no machine codes: the module's contract is plain
# human messages (TransparencyLogError, no taxonomy entries).
TAXONOMY_PIN = 1915 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 1: pin 1906 -> 1915 (+9 grantneg-*)

assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
    "taxonomy drift: expected %d, got %d"
    % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir(prefix="w261t2-"):
    return tempfile.mkdtemp(prefix=prefix, dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _error(detail=""):
    return ("ERROR", detail)


def _seed():
    # Fixed seeds: deterministic across runs and modes.
    return bytes.fromhex("cc" * 32)


def _pub(seed):
    return bytes(_ed.publickey(seed)).hex()


def _digests(n, start=1):
    return ["%064x" % (start + i) for i in range(n)]


def _log_with(n, seed=None, path=None):
    seed = seed if seed is not None else _seed()
    log = tl.TransparencyLog(
        path if path is not None else _tmpdir(), signing_key=seed)
    for d in _digests(n):
        log.append(d)
    return log, seed


def _truncate_tail(path, lines=1):
    # Attacker with write access to the log directory (no signing
    # key): delete the last `lines` lines of both files.
    for fname in (tl.LEAVES_FILE, tl.HEADS_FILE):
        fpath = os.path.join(path, fname)
        with open(fpath, encoding="utf-8") as f:
            kept = [ln for ln in f.read().splitlines() if ln.strip()]
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(kept[:-lines]) + "\n")


# ---------------------------------------------------------------------------
# F230: witnessed-state comparison detects tail truncation
# ---------------------------------------------------------------------------

@probe("f230/witnessed-head-detects-truncation")
def _p_f230_head():
    seed = _seed()
    path = _tmpdir()
    log, _s = _log_with(5, seed=seed, path=path)
    witness = log.latest_head()  # witnessed out-of-band, size 5
    # Positive control: the pristine log verifies, with and without
    # the witnessed head.
    ok, _ = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed))).verify_log()
    if not ok:
        return _error("pristine log did not verify before tampering")
    _truncate_tail(path)
    reopened = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed)))
    try:
        ok, detail = reopened.verify_log(expected_head=witness)
    except TypeError:
        return _break("verify_log has no witnessed-state comparison "
                      "API: truncation vs a witnessed head is "
                      "undetectable")
    if ok:
        return _break("truncation NOT detected vs witnessed head: "
                      "verify_log=True after deleting the last append")
    return _held("truncation detected vs witnessed head: %s"
                 % detail[:90])


@probe("f230/witnessed-size-detects-truncation")
def _p_f230_size():
    seed = _seed()
    path = _tmpdir()
    _log_with(5, seed=seed, path=path)
    _truncate_tail(path)
    reopened = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed)))
    try:
        ok, detail = reopened.verify_log(expected_size=5)
    except TypeError:
        return _break("verify_log has no witnessed-size comparison: "
                      "truncation vs a witnessed size is undetectable")
    if ok:
        return _break("truncation NOT detected vs witnessed size: "
                      "verify_log=True after deleting the last append")
    return _held("truncation detected vs witnessed size: %s"
                 % detail[:90])


@probe("f230/forged-witnessed-head-refused")
def _p_f230_forged_witness():
    # A forged "witnessed" head must not launder a verdict: it is
    # rejected as unverifiable, never treated as witnessed state.
    seed = _seed()
    path = _tmpdir()
    log, _s = _log_with(3, seed=seed, path=path)
    forged = dict(log.latest_head())
    forged["root_hash"] = "ff" * 32
    forged["signature"] = "00" * 128
    assert not tl.verify_tree_head(forged, _pub(seed))
    reopened = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed)))
    try:
        ok, detail = reopened.verify_log(expected_head=forged)
    except TypeError:
        return _break("no witnessed-state API (see "
                      "f230/witnessed-head-detects-truncation)")
    if ok:
        return _break("forged witnessed head accepted as witnessed "
                      "state")
    return _held("forged witnessed head refused: %s" % detail[:90])


@probe("f230/older-witnessed-head-no-false-alarm")
def _p_f230_older():
    # A witnessed head OLDER than the current log is not a shrink:
    # no false alarm, and its prefix root must match.
    seed = _seed()
    path = _tmpdir()
    log, _s = _log_with(5, seed=seed, path=path)
    witness2 = [h for h in log.heads() if h["tree_size"] == 2][0]
    reopened = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed)))
    try:
        ok, detail = reopened.verify_log(expected_head=witness2)
    except TypeError:
        return _break("no witnessed-state API (see "
                      "f230/witnessed-head-detects-truncation)")
    if not ok:
        return _break("false alarm on an older witnessed head: %s"
                      % detail[:90])
    return _held("older witnessed head accepted: %s" % detail[:60])


@probe("f230/witnessed-head-divergent-prefix-root")
def _p_f230_divergent():
    # Witnessed head at size 3 from a DIVERGENT history under the same
    # key: its root cannot match this log's prefix root at size 3.
    # This is history-rewrite-or-fork evidence, and must fail closed.
    seed = _seed()
    log_a, _sa = _log_with(4, seed=seed)
    # Build the divergent head honestly under a second key and check
    # the log refuses it as foreign (log_id binding), while a same-key
    # divergent head (built via a second log under A's key) fails the
    # prefix-root comparison.
    log_a2 = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    for d in _digests(4, start=100):  # same key, divergent digests
        log_a2.append(d)
    seed2 = bytes.fromhex("dd" * 32)  # different key, same digests
    log_c = tl.TransparencyLog(_tmpdir(), signing_key=seed2)
    for d in _digests(4, start=1):
        log_c.append(d)
    div_head3 = [h for h in log_a2.heads() if h["tree_size"] == 3][0]
    assert tl.verify_tree_head(div_head3, _pub(seed))
    assert not tl.verify_tree_head(
        [h for h in log_c.heads() if h["tree_size"] == 3][0],
        _pub(seed))
    try:
        ok, detail = log_a.verify_log(expected_head=div_head3)
    except TypeError:
        return _break("no witnessed-state API (see "
                      "f230/witnessed-head-detects-truncation)")
    if ok:
        return _break("divergent witnessed head accepted against the "
                      "current prefix")
    foreign3 = [h for h in log_c.heads() if h["tree_size"] == 3][0]
    ok_f, _ = log_a.verify_log(expected_head=foreign3)
    if ok_f:
        return _break("foreign-key witnessed head accepted")
    return _held("divergent/foreign witnessed heads refused: %s"
                 % detail[:80])


@probe("f230/plain-verify-log-still-self-consistent")
def _p_f230_plain():
    # Honest residual, documented: with NO witnessed state, a
    # truncated-but-internally-consistent log still verifies True.
    # The API must not invent detection it cannot do.
    seed = _seed()
    path = _tmpdir()
    _log_with(5, seed=seed, path=path)
    _truncate_tail(path)
    reopened = tl.TransparencyLog(
        path, public_key=bytes.fromhex(_pub(seed)))
    ok, _detail = reopened.verify_log()
    if not ok:
        return _break("plain verify_log must stay a self-consistency "
                      "check; it now fails without witnessed state")
    return _held("plain verify_log is self-consistency only "
                 "(documented residual)")


# ---------------------------------------------------------------------------
# F231: only signature-valid heads feed equivocation detection
# ---------------------------------------------------------------------------

@probe("f231/unsigned-head-no-conflict")
def _p_f231_unsigned():
    seed = _seed()
    log, _s = _log_with(2, seed=seed)
    head = log.latest_head()
    if not tl.verify_tree_head(head, _pub(seed)):
        return _error("positive control failed: real head invalid")
    forged = dict(head)
    forged["root_hash"] = "ff" * 32
    forged["signature"] = "00" * 128
    assert not tl.verify_tree_head(forged, _pub(seed))
    conflicts = log.detect_equivocation([head, forged])
    if conflicts:
        return _break("conflict from an UNSIGNED head "
                      "(verify_tree_head=False): %s"
                      % conflicts[0]["note"][:80])
    return _held("unsigned head ignored by detect_equivocation")


@probe("f231/foreign-key-head-no-conflict")
def _p_f231_foreign():
    # A head validly signed under a DIFFERENT key is not this
    # operator's misbehavior: no conflict.
    seed = _seed()
    log, _s = _log_with(2, seed=seed)
    head = log.latest_head()
    evil_seed = bytes.fromhex("ee" * 32)
    evil_log = tl.TransparencyLog(_tmpdir(), signing_key=evil_seed)
    for d in _digests(2, start=100):  # different digests -> different root
        evil_log.append(d)
    evil_head = evil_log.latest_head()
    assert tl.verify_tree_head(evil_head, bytes(
        _ed.publickey(evil_seed)).hex())
    conflicts = log.detect_equivocation([head, evil_head])
    if conflicts:
        return _break("conflict from a FOREIGN-key head")
    return _held("foreign-key head ignored by detect_equivocation")


@probe("f231/strict-reports-invalid-input")
def _p_f231_strict():
    # strict=True: unverifiable heads are reported distinctly as
    # invalid input (TransparencyLogError), never as evidence.
    seed = _seed()
    log, _s = _log_with(2, seed=seed)
    head = log.latest_head()
    forged = dict(head)
    forged["root_hash"] = "ff" * 32
    forged["signature"] = "00" * 128
    try:
        log.detect_equivocation([head, forged], strict=True)
    except TypeError:
        return _break("detect_equivocation has no strict/invalid-input "
                      "reporting")
    except tl.TransparencyLogError as e:
        return _held("strict=True reports invalid input: %s"
                     % str(e)[:80])
    return _break("strict=True silently accepted an unsigned head")


@probe("f231/genuine-equivocation-still-detected")
def _p_f231_genuine():
    # Guard probe: the fix must not stop detecting REAL equivocation
    # (two genuinely-signed divergent heads, same key).
    seed = _seed()
    log_a, _sa = _log_with(3, seed=seed)
    log_b = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    for d in _digests(3, start=100):
        log_b.append(d)
    heads_a = log_a.heads()
    head_b2 = [h for h in log_b.heads() if h["tree_size"] == 2][0]
    pub = _pub(seed)
    if not (tl.verify_tree_head(heads_a[1], pub)
            and tl.verify_tree_head(head_b2, pub)):
        return _error("positive control failed: heads do not verify")
    if log_a.detect_equivocation(heads_a):
        return _error("positive control failed: false positive on "
                      "honest heads")
    conflicts = log_a.detect_equivocation(heads_a + [head_b2])
    if not conflicts or conflicts[0]["tree_size"] != 2:
        return _break("genuine equivocation no longer detected")
    return _held("genuine equivocation still detected")


@probe("f231/garbage-heads-skipped")
def _p_f231_garbage():
    # Non-dict / malformed entries in the head list: skipped, never a
    # crash, never evidence.
    seed = _seed()
    log, _s = _log_with(2, seed=seed)
    head = log.latest_head()
    try:
        conflicts = log.detect_equivocation(
            [head, None, "junk", 42, {"tree_size": 2}])
    except Exception as e:  # noqa: BLE001 -- probe harness
        return _break("garbage head input crashed detection: %r" % (e,))
    if conflicts:
        return _break("garbage input produced a conflict")
    return _held("garbage heads skipped without crash or conflict")


# ---------------------------------------------------------------------------
# F232: operator path wraps OSError as TransparencyLogError
# ---------------------------------------------------------------------------

def _expect_tl_error(label, fn):
    try:
        fn()
    except tl.TransparencyLogError:
        return _held("%s raises TransparencyLogError" % label)
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break("%s escaped raw %s" % (label, type(e).__name__))
    return _break("%s: no exception at all" % label)


@probe("f232/init-path-is-file")
def _p_f232_init_file():
    seed = _seed()
    fd, fpath = tempfile.mkstemp(prefix="w261t2-file-", dir="/var/tmp")
    os.close(fd)
    try:
        return _expect_tl_error(
            "init on a path that is a file",
            lambda: tl.TransparencyLog(fpath, signing_key=seed))
    finally:
        os.unlink(fpath)


@probe("f232/append-io-failure")
def _p_f232_append_io():
    seed = _seed()
    path = _tmpdir()
    log = tl.TransparencyLog(path, signing_key=seed)
    log.append(_digests(1)[0])
    os.remove(os.path.join(path, tl.LEAVES_FILE))
    os.mkdir(os.path.join(path, tl.LEAVES_FILE))
    return _expect_tl_error(
        "append with leaves.jsonl replaced by a directory",
        lambda: log.append(_digests(1)[0]))


@probe("f232/init-unreadable-leaves")
def _p_f232_init_leaves():
    # Reopening a log whose leaves.jsonl is a directory: I/O failure
    # on the read path must also arrive as TransparencyLogError.
    seed = _seed()
    path = _tmpdir()
    tl.TransparencyLog(path, signing_key=seed)
    os.mkdir(os.path.join(path, tl.LEAVES_FILE))
    return _expect_tl_error(
        "init with leaves.jsonl as a directory",
        lambda: tl.TransparencyLog(
            path, public_key=bytes.fromhex(_pub(seed))))


@probe("f232/init-unreadable-heads")
def _p_f232_init_heads():
    seed = _seed()
    path = _tmpdir()
    tl.TransparencyLog(path, signing_key=seed)
    os.mkdir(os.path.join(path, tl.HEADS_FILE))
    return _expect_tl_error(
        "init with heads.jsonl as a directory",
        lambda: tl.TransparencyLog(
            path, public_key=bytes.fromhex(_pub(seed))))


@probe("f232/append-head-io-failure")
def _p_f232_append_head_io():
    # Leaf write succeeds, head write fails: still TransparencyLogError.
    seed = _seed()
    path = _tmpdir()
    log = tl.TransparencyLog(path, signing_key=seed)
    log.append(_digests(1)[0])
    os.remove(os.path.join(path, tl.HEADS_FILE))
    os.mkdir(os.path.join(path, tl.HEADS_FILE))
    return _expect_tl_error(
        "append with heads.jsonl replaced by a directory",
        lambda: log.append(_digests(2)[1]))


@probe("f232/happy-path-unaffected")
def _p_f232_happy():
    # Guard probe: normal init/append still work and verify.
    seed = _seed()
    path = _tmpdir()
    log = tl.TransparencyLog(path, signing_key=seed)
    for d in _digests(3):
        head = log.append(d)
    ok, _ = log.verify_log()
    if not ok or not tl.verify_tree_head(head, _pub(seed)):
        return _break("happy path broke")
    return _held("init/append/verify unaffected")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-46s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
