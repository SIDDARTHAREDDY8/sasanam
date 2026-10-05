"""Break-first battery for the F236 closure (wave-262 lane B).

Wave-262 lane B closes F236: ``EnrollmentAuthority`` in
gov/svid_enrollment.py had zero concurrency control -- concurrent
``redeem()`` of one key double-issued SVIDs (check-then-set on
``record["used"]``) and ``live_keys()`` raised ``RuntimeError`` under
concurrent ``issue_key()``. The fix serializes the key-table
check-then-set under a lock and snapshots the table for
``live_keys()``.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Pre-fix the two concurrency probes BREAK (verified in-lane:
4/150 trials double-issued at 64 threads; 8/8 live_keys readers
crashed with RuntimeError); post-fix they HELD -- and deterministically
so, because a lock makes the double-issue interleaving impossible
(the widened-window experiment -- 10ms sleep between the used-check
and the burn -- took the rate from 4/150 to 20/20, pinning the race
to exactly that check-then-set).

Targets (base 8bf6c418fefb40ee1d977fbbd6b396e7b5728765, pin 1106):
- gov/svid_enrollment.py -- EnrollmentAuthority key-table
  concurrency: no double-issue under concurrent redeem of one key;
  live_keys() safe under concurrent issue_key(); concurrent redeem of
  DISTINCT keys still all succeed (no false serialization);
  sequential redeem-after-redeem still refused with the existing
  svid-enrollment-key-replayed code; the lock is not held across
  issuer.issue so an exception in the issue path cannot deadlock.

Verdicts: HELD (invariant holds), BREAK (defect -- F236 not closed),
ERROR (harness bug -- fix the harness, never the product).

No in-repo git subprocesses (wave-36 supply-chain probe: fail
closed). Depth-1 green checks honoring GOV_SKIP_GREEN=1.
"""

import os
import sys
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import svid_enrollment as enr  # noqa: E402
from gov import svid_issuer as sv  # noqa: E402

# No new machine codes for this closure (existing burn/refusal codes
# cover every path) -- pin stays at the wave-261 value. If the count
# moves, the delta must be explained by a landed taxonomy change --
# never repoint blindly (replace the VALUE only).
TAXONOMY_PIN = 2126 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return deco
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _pair():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    return enr.EnrollmentAuthority(issuer)


_SPIFFE = "spiffe://example.org/w/r"
_PUBKEY = "bb" * 32


@probe("enrollment/concurrent-redeem-double-issues-single-key")
def _p_double_issue():
    # Probabilistic by nature pre-fix (race window is a few dozen
    # bytecodes): 64 threads x 150 trials measured 4 double-issuances
    # on base in-lane (red team: 1-7/150). Post-fix the lock makes the
    # double-issue interleaving impossible, so the probe is
    # deterministic: it can only go red on the defect.
    auth = _pair()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)  # harness-side scheduling pressure only
    try:
        double = 0
        trials, nthreads = 150, 64
        for _ in range(trials):
            key = auth.issue_key(spiffe_id=_SPIFFE)
            barrier = threading.Barrier(nthreads)
            results = []
            rlock = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    auth.redeem(key, _SPIFFE, _PUBKEY, 5)
                    r = "svid"
                except sv.SvidError as e:
                    r = e.code
                with rlock:
                    results.append(r)

            ths = [threading.Thread(target=worker)
                   for _ in range(nthreads)]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            if results.count("svid") > 1:
                double += 1
    finally:
        sys.setswitchinterval(old_interval)
    if double:
        return _break(
            "%d/%d trials issued 2+ SVIDs from ONE enrollment key "
            "(single-use invariant broken under concurrency)" % (double,
                                                                 trials))
    return _held("exactly one SVID per key over %d x 64-thread storms"
                 % trials)


@probe("enrollment/live-keys-raises-under-concurrent-issue")
def _p_live_keys():
    # Near-deterministic pre-fix: 8/8 readers crashed with
    # RuntimeError in-lane on base. Post-fix live_keys() snapshots the
    # table under the lock, so iteration never meets a mutation.
    auth = _pair()
    for _ in range(50):
        auth.issue_key()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)
    stop = threading.Event()
    crashed = []
    try:
        def reader():
            while not stop.is_set():
                try:
                    auth.live_keys()
                except Exception as e:  # noqa: BLE001 -- defect shape
                    crashed.append(type(e).__name__)
                    return

        def writer():
            while not stop.is_set():
                auth.issue_key()

        ths = ([threading.Thread(target=reader) for _ in range(8)]
               + [threading.Thread(target=writer) for _ in range(4)])
        for th in ths:
            th.start()
        time.sleep(3)
        stop.set()
        for th in ths:
            th.join()
    finally:
        sys.setswitchinterval(old_interval)
    if crashed:
        return _break(
            "live_keys() raised %s under concurrent issue_key "
            "(key table iterated without a lock)" % crashed[0])
    return _held("live_keys() survived 3s of concurrent mutation")


@probe("enrollment/concurrent-redeem-distinct-keys-all-succeed")
def _h_distinct_keys():
    # Guard against over-serialization: N threads redeeming N
    # DISTINCT keys concurrently must ALL succeed -- the lock must not
    # turn contention into spurious replayed/unknown refusals.
    auth = _pair()
    n = 64
    keys = [auth.issue_key(spiffe_id=_SPIFFE) for _ in range(n)]
    barrier = threading.Barrier(n)
    results = []
    rlock = threading.Lock()

    def worker(i):
        barrier.wait()
        try:
            auth.redeem(keys[i], _SPIFFE, _PUBKEY, 5)
            r = "svid"
        except sv.SvidError as e:
            r = e.code
        with rlock:
            results.append(r)

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(30)
    alive = [th for th in ths if th.is_alive()]
    if alive:
        return _break("%d/%d distinct-key redeems hung (lock deadlock?)"
                      % (len(alive), n))
    if results.count("svid") != n:
        return _break("%d/%d distinct-key redeems succeeded "
                      "(false serialization)" % (results.count("svid"), n))
    if auth.live_keys() != 0:
        return _break("live_keys() = %d after all keys redeemed"
                      % auth.live_keys())
    return _held("%d/%d distinct keys redeemed concurrently; table empty"
                 % (n, n))


@probe("enrollment/sequential-redeem-after-redeem-refused-replayed")
def _h_sequential_replay():
    # The existing burn code must survive the fix: redeem once (ok),
    # redeem again -> svid-enrollment-key-replayed, no SVID.
    auth = _pair()
    key = auth.issue_key(spiffe_id=_SPIFFE)
    auth.redeem(key, _SPIFFE, _PUBKEY, 5)
    try:
        auth.redeem(key, _SPIFFE, _PUBKEY, 5)
        return _break("second sequential redeem minted an SVID")
    except sv.SvidError as e:
        if e.code != enr.ENROLLMENT_KEY_REPLAYED_CODE:
            return _break("second redeem refused as %s, not %s"
                          % (e.code, enr.ENROLLMENT_KEY_REPLAYED_CODE))
    return _held("sequential replay refused with "
                 "svid-enrollment-key-replayed")


@probe("enrollment/lock-released-when-issuance-raises")
def _h_issue_exception():
    # The lock must not be held across issuer.issue(): an exception in
    # the issue path (unknown profile -> SvidError post-burn) must
    # release the lock, so later operations proceed and concurrent
    # failing redeems cannot deadlock.
    auth = _pair()
    key = auth.issue_key(spiffe_id=_SPIFFE)
    try:
        auth.redeem(key, _SPIFFE, _PUBKEY, 5, profile="no-such-profile")
        return _break("redeem with unknown profile did not raise")
    except sv.SvidError as e:
        if e.code == enr.ENROLLMENT_KEY_REPLAYED_CODE:
            return _break("issuer error masked as replayed")
    # Key stayed burned (burn-before-issue), lock is free: a second
    # redeem of the same key must refuse as replayed, not hang.
    try:
        auth.redeem(key, _SPIFFE, _PUBKEY, 5)
        return _break("redeem after failed issuance minted an SVID")
    except sv.SvidError as e:
        if e.code != enr.ENROLLMENT_KEY_REPLAYED_CODE:
            return _break("post-failure redeem refused as %s" % e.code)
    # Fresh key on the happy path still works after the failure.
    key2 = auth.issue_key(spiffe_id=_SPIFFE)
    auth.redeem(key2, _SPIFFE, _PUBKEY, 5)
    # Concurrent failing redeems must all terminate (no deadlock).
    n = 16
    keys = [auth.issue_key(spiffe_id=_SPIFFE) for _ in range(n)]
    barrier = threading.Barrier(n)
    done = []
    dlock = threading.Lock()

    def worker(i):
        barrier.wait()
        try:
            auth.redeem(keys[i], _SPIFFE, _PUBKEY, 5,
                        profile="no-such-profile")
            r = "NO-RAISE"
        except sv.SvidError as e:
            r = e.code
        with dlock:
            done.append(r)

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(30)
    alive = [th for th in ths if th.is_alive()]
    if alive:
        return _break("%d/%d failing redeems hung: lock not released "
                      "on the exception path" % (len(alive), n))
    if len(done) != n:
        return _break("only %d/%d failing redeems returned" % (len(done),
                                                               n))
    return _held("exception in issue path keeps key burned, releases "
                 "the lock, and never deadlocks (%d threads)" % n)


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent batteries still green. Honors GOV_SKIP_GREEN
    (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w260_identity2_probes.py",
                    "evals/w261_redteam_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes"
          % (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
