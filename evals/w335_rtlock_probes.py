"""Wave-335 lane 3 battery: refresh-token race-guard lock (F421 filed+closed).

Base: 0fd4f736 (wave-334 merge). Footer at merge: open F423 / next F424
(F421 filed then CLOSED here). Pin: 2106 (+1 identity-refresh-lock-unavailable).

P1  F421 red-first, now closed: the /tmp/red_rtlock.py double-spend
    (two threads, barrier-aligned, 0.2s slow issuer modeling a
    production remote/KMS signer) now yields EXACTLY ONE success; the
    loser is refused coded identity-refresh-reuse-detected and the
    chain is revoked (the existing theft response).
P2  Sequential refresh round-trip unchanged: mint -> refresh -> verify
    identity token; the rotated pair refreshes again.
P3  Lock timeout fails closed: with the token's rotation lock pre-held
    and a short injected timeout, refresh refuses coded
    identity-refresh-lock-unavailable (never proceeds unlocked); after
    release the same refresh succeeds (no poisoned state).
P4  Single-threaded reuse semantics preserved: second presentation of
    a rotated token -> identity-refresh-reuse-detected, and the whole
    chain (including the fresh descendant) is revoked.
P5  Per-token independence: two distinct tokens refresh concurrently
    (barrier-aligned) -> both succeed; their rotation locks are
    distinct objects (no global serialization).
P6  _revoke_chain under concurrent mint: a spinner thread mints in a
    loop while the main thread triggers reuse-revocation repeatedly --
    no RuntimeError, refusals stay coded.
P7  Pin 2106 + footer state (open F423 / next F424; F421 CLOSED);
    taxonomy sorted-unique on raw literals; the new code centrally
    registered.
P8  Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs
    tests/test_dex_identity.py as a child with GOV_SKIP_GREEN=1
    (fresh TMPDIR).

gov/ changes in this lane: gov/agent_identity.py (per-token rotation
locks, bounded lock acquisition with fail-closed coded refusal,
snapshot iteration in _revoke_chain; lock_timeout_seconds ctor arg) +
1 code in gov/decision_codes.py (pin 2100 -> 2106 at merge). Findings: F421
filed then CLOSED here.
"""

import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2106  # Wave-335 lane 3: pin 2100 -> 2101 (+1 identity-refresh-lock-unavailable, F421). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).
FOOTER_OPEN = "F423, F424, F425"  # F421 CLOSED 2026-10-05 (wave-335 lane 3). F424/F425 filed 2026-10-05 wave-336 lane 5, OPEN.
FOOTER_NEXT = "F426"  # Next free finding number.

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _break(pid, "assertion: %s" % exc)
    except Exception:  # noqa: BLE001 - every probe must report, not crash
        _record(pid, "ERROR", traceback.format_exc(limit=3).replace(
            "\n", " | ")[:300])


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _run_root():
    d = os.environ.get("TMPDIR") or tempfile.gettempdir()
    os.makedirs(d, exist_ok=True)
    return d


def _tmpd(prefix="w335rtlock-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import agent_identity as ai  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


_KEY = b"k" * 32
_NOW = 1_800_000_000


def _oidc(**over):
    claims = {"sub": "agent-7", "email": "agent-7@example.com",
              "email_verified": True, "groups": ["ops"]}
    claims.update(over)
    return claims


def _pair(**kw):
    issuer = ai.IdentityTokenIssuer(_KEY, time_fn=lambda: _NOW)
    store = ai.RefreshTokenStore(time_fn=lambda: _NOW, **kw)
    return issuer, store


def _mint(store, **kw):
    ident = ai.normalize_claims(_oidc(), "oidc")
    return store.mint_refresh(ident, "oidc", _oidc(), **kw)


def _slow_issuer(issuer, delay=0.2):
    """Model a production remote/KMS-backed signer: hold the race window
    open deterministically. Returns a wrapped issuer."""
    real_issue = issuer.issue

    def slow_issue(identity, audience, **kw):
        time.sleep(delay)
        return real_issue(identity, audience, **kw)

    issuer.issue = slow_issue
    return issuer


# ---------------------------------------------------------------------------
# P1: F421 red-first, now closed -- concurrent double-refresh.
# ---------------------------------------------------------------------------

@_probe("P1-concurrent-double-refresh")
def _p1():
    pid = "P1-concurrent-double-refresh"
    issuer, store = _pair()
    _slow_issuer(issuer)
    rid, secret = _mint(store)
    barrier = threading.Barrier(2)
    results = {}

    def worker(name):
        barrier.wait()
        try:
            results[name] = ("ok", store.refresh(issuer, rid, secret,
                                                 "agents"))
        except ai.IdentityTokenRejection as e:
            results[name] = ("refused", e.code)

    threads = [threading.Thread(target=worker, args=("t%d" % i,))
               for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(not t.is_alive() for t in threads), "worker thread hung"
    oks = sorted(n for n, (s, _) in results.items() if s == "ok")
    assert len(oks) == 1, "expected exactly one winner, got %r" % (results,)
    loser = [n for n in results if n not in oks][0]
    assert results[loser] == ("refused", "identity-refresh-reuse-detected"), \
        "loser not reuse-refused: %r" % (results[loser],)
    # The theft response fired: the winner's fresh chain is revoked too.
    _, (_, new_rid, new_secret) = results[oks[0]]
    try:
        store.refresh(issuer, new_rid, new_secret, "agents")
    except ai.IdentityTokenRejection as e:
        assert e.code == "identity-refresh-revoked", e.code
    else:
        raise AssertionError("winner chain not revoked after race")
    return _held(pid, "exactly-one-wins; loser identity-refresh-reuse-"
                      "detected; chain revoked (theft response)")


# ---------------------------------------------------------------------------
# P2: sequential behavior unchanged.
# ---------------------------------------------------------------------------

@_probe("P2-sequential-round-trip")
def _p2():
    pid = "P2-sequential-round-trip"
    issuer, store = _pair()
    rid, secret = _mint(store)
    token, rid2, secret2 = store.refresh(issuer, rid, secret, "agents")
    got = issuer.verify_token(token, "agents", now=_NOW)
    assert got["subject"] == "agent-7", got
    assert rid2 != rid
    # The rotated pair refreshes again (chain continues).
    token2, _, _ = store.refresh(issuer, rid2, secret2, "agents")
    got2 = issuer.verify_token(token2, "agents", now=_NOW)
    assert got2["subject"] == "agent-7", got2
    return _held(pid, "mint->refresh->refresh chain works sequentially")


# ---------------------------------------------------------------------------
# P3: lock timeout fails closed with a coded refusal.
# ---------------------------------------------------------------------------

@_probe("P3-lock-timeout-fail-closed")
def _p3():
    pid = "P3-lock-timeout-fail-closed"
    issuer, store = _pair(lock_timeout_seconds=0.2)
    rid, secret = _mint(store)
    held = store._lock_for(rid)
    assert held.acquire(blocking=False), "could not pre-hold test lock"
    try:
        try:
            store.refresh(issuer, rid, secret, "agents")
        except ai.IdentityTokenRejection as e:
            assert e.code == "identity-refresh-lock-unavailable", e.code
        else:
            raise AssertionError("refresh proceeded while lock held")
    finally:
        held.release()
    # No poisoned state: the same refresh succeeds after release.
    token, _, _ = store.refresh(issuer, rid, secret, "agents")
    got = issuer.verify_token(token, "agents", now=_NOW)
    assert got["subject"] == "agent-7", got
    return _held(pid, "timeout -> identity-refresh-lock-unavailable; "
                      "post-release refresh clean")


# ---------------------------------------------------------------------------
# P4: single-threaded reuse semantics preserved.
# ---------------------------------------------------------------------------

@_probe("P4-single-threaded-reuse")
def _p4():
    pid = "P4-single-threaded-reuse"
    issuer, store = _pair()
    rid, secret = _mint(store)
    _, rid2, secret2 = store.refresh(issuer, rid, secret, "agents")
    try:
        store.refresh(issuer, rid, secret, "agents")
    except ai.IdentityTokenRejection as e:
        assert e.code == "identity-refresh-reuse-detected", e.code
    else:
        raise AssertionError("rotated token reuse not detected")
    # Whole chain revoked, including the fresh descendant.
    try:
        store.refresh(issuer, rid2, secret2, "agents")
    except ai.IdentityTokenRejection as e:
        assert e.code == "identity-refresh-revoked", e.code
    else:
        raise AssertionError("revoked chain still refreshable")
    return _held(pid, "reuse detected coded; chain revoked")


# ---------------------------------------------------------------------------
# P5: per-token independence (no global serialization).
# ---------------------------------------------------------------------------

@_probe("P5-per-token-independence")
def _p5():
    pid = "P5-per-token-independence"
    issuer, store = _pair()
    _slow_issuer(issuer)
    rid1, secret1 = _mint(store)
    rid2, secret2 = _mint(store)
    assert store._lock_for(rid1) is not store._lock_for(rid2), \
        "tokens share one lock (global serialization)"
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, rid, secret):
        barrier.wait()
        try:
            results[name] = ("ok", store.refresh(issuer, rid, secret,
                                                 "agents"))
        except ai.IdentityTokenRejection as e:
            results[name] = ("refused", e.code)

    threads = [threading.Thread(target=worker, args=("a", rid1, secret1)),
               threading.Thread(target=worker, args=("b", rid2, secret2))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(not t.is_alive() for t in threads), "worker thread hung"
    assert results["a"][0] == "ok", results
    assert results["b"][0] == "ok", results
    return _held(pid, "distinct tokens refresh concurrently; distinct locks")


# ---------------------------------------------------------------------------
# P6: _revoke_chain under concurrent mint (no RuntimeError).
# ---------------------------------------------------------------------------

@_probe("P6-revoke-under-concurrent-mint")
def _p6():
    pid = "P6-revoke-under-concurrent-mint"
    issuer, store = _pair()
    stop = threading.Event()
    errors = []

    def spinner():
        try:
            while not stop.is_set():
                _mint(store)
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    t = threading.Thread(target=spinner)
    t.start()
    try:
        for _ in range(30):
            rid, secret = _mint(store)
            store.refresh(issuer, rid, secret, "agents")
            try:
                store.refresh(issuer, rid, secret, "agents")
            except ai.IdentityTokenRejection as e:
                assert e.code == "identity-refresh-reuse-detected", e.code
            else:
                raise AssertionError("reuse not detected under mint load")
    finally:
        stop.set()
        t.join(30)
    assert not errors, "spinner errors: %r" % (errors[:2],)
    assert not t.is_alive(), "spinner thread hung"
    return _held(pid, "30 revoke cycles under concurrent mint: no crash, "
                      "refusals coded")


# ---------------------------------------------------------------------------
# P7: pin + footer + taxonomy.
# ---------------------------------------------------------------------------

@_probe("P7-pin-footer-taxonomy")
def _p7():
    pid = "P7-pin-footer-taxonomy"
    assert len(dc.TAXONOMY) == TAXONOMY_PIN, \
        "want %d, got %d" % (TAXONOMY_PIN, len(dc.TAXONOMY))
    assert len(set(dc.TAXONOMY)) == TAXONOMY_PIN
    codes = sorted(dc.TAXONOMY)
    assert codes == sorted(set(codes)), "taxonomy not sorted-unique"
    assert "identity-refresh-lock-unavailable" in dc.TAXONOMY, \
        "new code not centrally registered"
    # Wave-260 lesson: uniqueness on raw source literals, not the
    # deduped dict. The new code's literal must appear exactly twice
    # (dict key + "code" field), never duplicated by a merge slip.
    dc_src = open(os.path.join(REPO, "gov", "decision_codes.py"),
                  encoding="utf-8").read()
    assert dc_src.count("'identity-refresh-lock-unavailable'") == 2, \
        "new code literal count != 2"
    # Raw-literal footer assertions (wave-331 lesson).
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    assert "Next free finding: **%s**." % FOOTER_NEXT in text, \
        "footer next-free mismatch"
    assert "**Open findings: %s.**" % FOOTER_OPEN in text, \
        "footer open-findings mismatch"
    assert "## F421" in text and "CLOSED 2026-10-05 wave-335 lane 3" in text, \
        "F421 closure not recorded"
    return _held(pid, "taxonomy 2106/2106/0 sorted-unique; new code "
                      "registered; F421 CLOSED; footer open F423 / next F424")


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(path, timeout):
    d = _tmpd("w335rtlock-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the dex-identity unit suite as a child with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output(
            os.path.join(REPO, "tests", "test_dex_identity.py"),
            timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "dex_identity: %s" % exc)
        return
    breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    # unittest-style failures surface as FAIL/ERROR lines instead.
    failed = ("FAILED" in out or "failures=" in out.lower())
    m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
    if m2:
        import ast as _ast
        try:
            breaks.update(_ast.literal_eval(m2.group(1)))
        except Exception:
            pass
    if breaks or errors or failed:
        _record("green-check", "BREAK",
                "dex_identity non-green: %s" % sorted(breaks | errors)[:4])
    else:
        _record("green-check", "HELD", "test_dex_identity green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w335_rtlock battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
