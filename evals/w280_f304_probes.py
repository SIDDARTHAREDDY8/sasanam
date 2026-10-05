"""Wave-280 F304 closure battery (break-first audit of the fix).

F304 (LOW): TripFatigueTracker.note_trip raises TypeError on mixed
`now` types at eviction -- the "Total on hostile input" contract is
violated. `_window_of` (the F299 fix) is total and never raises, but the
bounded-store eviction path compares raw `now` values with min():
``oldest = min(self._store.items(), key=lambda kv: kv[1][2])[0]``
while ``rec[2] = now`` stores the raw value. A full store holding
mixed `now` types (e.g. None and int -- both blessed by the F299
contract) raises ``TypeError: '<' not supported between instances of
'NoneType' and 'int'``.

Close-when criteria (from the F304 entry):
  (1) probe `f299-eviction-mixed-types` flips to HELD (eviction never
      raises on mixed `now` types);
  (2) the F299 `_window_of` contract probes stay HELD;
  (3) `tests/test_decoy_grants.py` and `evals/w278_f299_probes.py`
      stay green.

The fix (gov/decoy_grants.py): eviction orders by a monotonic touch
sequence number instead of the raw `now` value -- the raw value can be
any hostile type and has no total ordering, while a sequence is always
total. "Oldest-touched" keeps its call-order meaning; `_window_of`'s
contract is reused, not reinvented.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed inputs, no random);
fresh unique /var/tmp/g280* TMPDIR (`mkdir -p` first); depth-1 green
checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib
only.
"""

import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g280-f304-%d-" % os.getpid(), dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import decoy_grants as dg  # noqa: E402

TAXONOMY_PIN = 2128 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-279 merge pin; this lane adds no codes.; Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _held(pid, note):
    return ("HELD", note)


def _broken(pid, note):
    return ("BREAK", note)


# ---------------------------------------------------------------------------
# (1) The F304 shape: red-team repro, must never raise.
# ---------------------------------------------------------------------------

def f304_redteam_repro():
    """The w279 red-team probe shape: full store with mixed now types.

    Four keys with now = 1000 / None / "later" / 2000.5; the 5th
    note_trip must not raise (BREAK on base) and the store must stay
    bounded at max_keys.
    """
    tr = dg.TripFatigueTracker(window_s=300, full_events_per_window=5,
                               max_keys=4)
    tr.note_trip(decoy="d", agent_key="a", now=1000)
    tr.note_trip(decoy="d", agent_key="b", now=None)
    tr.note_trip(decoy="d", agent_key="c", now="later")
    tr.note_trip(decoy="d", agent_key="e", now=2000.5)
    try:
        r = tr.note_trip(decoy="d", agent_key="f", now=3000)
    except TypeError as exc:
        return _broken("f304-redteam-repro",
                       "F304: eviction raises TypeError: %s" % (exc,))
    if len(tr._store) > 4:
        return _broken("f304-redteam-repro",
                       "store unbounded after eviction: %d" % len(tr._store))
    return _held("f304-redteam-repro",
                 "no raise; store bounded; emit_full=%r" % (r["emit_full"],))


# ---------------------------------------------------------------------------
# (2) Broader hostile eviction: every hostile now shape must evict cleanly.
# ---------------------------------------------------------------------------

def f304_eviction_all_hostile():
    """A full store of ONLY hostile now values evicts without raising.

    F299's contract blesses bool / nan / inf / non-numeric as fresh-
    window-per-call inputs; all of them must also be evictable.
    """
    hostile = [None, True, False, float("nan"), float("inf"),
               float("-inf"), "soon", b"bytes", ["list"], {"k": 1},
               (1, 2), -5.5, 0.0]
    tr = dg.TripFatigueTracker(window_s=300, full_events_per_window=5,
                               max_keys=len(hostile))
    for i, now in enumerate(hostile):
        tr.note_trip(decoy="d", agent_key="a%d" % i, now=now)
    try:
        # Force one eviction per remaining note; all must stay total.
        for j in range(4):
            tr.note_trip(decoy="d", agent_key="new%d" % j, now=9999 + j)
    except Exception as exc:  # noqa: BLE001
        return _broken("f304-eviction-all-hostile",
                       "F304: %s: %s" % (type(exc).__name__, exc))
    return _held("f304-eviction-all-hostile",
                 "all hostile evictions total; store=%d" % len(tr._store))


# ---------------------------------------------------------------------------
# (3) Eviction still picks the oldest-touched entry (public seam).
# ---------------------------------------------------------------------------

def f304_eviction_oldest_touched():
    """Eviction removes the oldest-touched key, deterministically.

    max_keys=3: note d0, d1, d2, then d3 evicts d0 (the oldest touch).
    Re-noting d1 must show the still-resident record (window_count 2);
    re-noting d0 must show a FRESH record (window_count 1) because d0
    was the evicted key. Observable entirely through the public
    note_trip return shape.
    """
    tr = dg.TripFatigueTracker(window_s=10 ** 6, full_events_per_window=5,
                               max_keys=3)
    base = 10
    for i in range(3):
        tr.note_trip(decoy="d", agent_key="a%d" % i, now=base + i)
    tr.note_trip(decoy="d", agent_key="a3", now=base + 3)  # evicts a0
    r1 = tr.note_trip(decoy="d", agent_key="a1", now=base + 4)
    r0 = tr.note_trip(decoy="d", agent_key="a0", now=base + 5)
    if not (r1["emit_full"] and r1["window_count"] == 2):
        return _broken("f304-eviction-oldest-touched",
                       "a1 should still be resident with count 2: %r"
                       % (r1,))
    if not (r0["emit_full"] and r0["window_count"] == 1):
        return _broken("f304-eviction-oldest-touched",
                       "a0 should have been evicted (fresh record): %r"
                       % (r0,))
    return _held("f304-eviction-oldest-touched",
                 "a0 evicted (fresh record), a1 resident (count 2)")


# ---------------------------------------------------------------------------
# (4) F299 contract re-pin: int/float windowing unchanged by the fix.
# ---------------------------------------------------------------------------

def f304_f299_contract_holds():
    """The F299 _window_of contract survives the eviction change.

    Finite floats coerce via int() and window like ints (no eternal
    window); bool/nan/inf/non-numeric start a fresh window per call
    (emit_full forever, window_count always 1).
    """
    tr = dg.TripFatigueTracker(window_s=300, full_events_per_window=5)
    res = [tr.note_trip(decoy="d", agent_key="a", now=100.0 + i * 400.0)
           for i in range(12)]
    if not all(r["emit_full"] and r["window_count"] == 1 for r in res):
        return _broken("f304-f299-contract-holds",
                       "float windowing changed: %r" % (res,))
    for now in ("2026-10-01T00:00:00+00:00", None, True,
                float("nan"), float("inf")):
        res = [tr.note_trip(decoy="d", agent_key="a", now=now)
               for _ in range(8)]
        if not all(r["emit_full"] and r["window_count"] == 1 for r in res):
            return _broken("f304-f299-contract-holds",
                           "fresh-window contract broken for now=%r" % (now,))
    return _held("f304-f299-contract-holds",
                 "F299 windowing contract intact")


# ---------------------------------------------------------------------------
# (5) Denial posture: tracker results never suppress the denial.
# ---------------------------------------------------------------------------

def f304_denial_unaffected():
    """The tracker still only compacts audit volume, never gates denial.

    After full_events_per_window trips in one window, further trips
    return emit_full False with a suppressed count -- the denial itself
    is untouched (enforce() never consults the tracker).
    """
    tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=2)
    rs = [tr.note_trip(decoy="d", agent_key="a", now=10) for _ in range(5)]
    if not all(r["emit_full"] for r in rs[:2]):
        return _broken("f304-denial-unaffected",
                       "first two trips must emit full")
    if any(r["emit_full"] for r in rs[2:]):
        return _broken("f304-denial-unaffected",
                       "trips 3+ must compact")
    if rs[4]["suppressed"] != 3:
        return _broken("f304-denial-unaffected",
                       "suppressed count wrong: %r" % (rs[4],))
    return _held("f304-denial-unaffected", "volume-only compaction intact")


# ---------------------------------------------------------------------------
# (6) Taxonomy pin: this lane must add no decision codes.
# ---------------------------------------------------------------------------

def f304_taxonomy_pin():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return _broken("pin-taxonomy-1495",
                       "taxonomy pin drift: %d literals, pin %d"
                       % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return _broken("pin-taxonomy-1495", "duplicate code literals")
    if literals != sorted(literals):
        return _broken("pin-taxonomy-1495", "code literals not sorted")
    return _held("pin-taxonomy-1495", "%d/%d/0 sorted" % (len(literals),
                                                          len(literals)))


# ---------------------------------------------------------------------------
# Depth-1 green checks (GOV_SKIP_GREEN=1 in the child env; no recursion).
# ---------------------------------------------------------------------------

def green_check():
    """Run the adjacent F299 battery + the decoy unit suite depth-1.

    A parent battery's green check runs each adjacent suite's main with
    GOV_SKIP_GREEN=1 in the child env; the child records a skip note and
    returns without spawning (depth-1, never nested).
    """
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "depth-1 boundary")]
    out = []
    checks = [
        (["evals/w278_f299_probes.py"], "w278_f299"),
        (["-m", "unittest", "tests.test_decoy_grants", "-v"],
         "test_decoy_grants"),
    ]
    for argv, name in checks:
        tmp = tempfile.mkdtemp(prefix="g280-f304-green-", dir="/var/tmp")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        cmd = [sys.executable] + argv
        try:
            proc = subprocess.run(cmd, cwd=REPO, env=env,  # noqa: S603
                                  capture_output=True, text=True, timeout=600)
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
            verdict = ("HELD" if proc.returncode == 0
                       else "BREAK")
            out.append((name, verdict,
                        "rc=%d; %s" % (proc.returncode, " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            out.append((name, "ERROR", "%s: %s"
                        % (type(exc).__name__, exc)))
    return out


def main():
    probes = [
        ("f304-redteam-repro", "HELD", f304_redteam_repro),
        ("f304-eviction-all-hostile", "HELD", f304_eviction_all_hostile),
        ("f304-eviction-oldest-touched", "HELD", f304_eviction_oldest_touched),
        ("f304-f299-contract-holds", "HELD", f304_f299_contract_holds),
        ("f304-denial-unaffected", "HELD", f304_denial_unaffected),
        ("pin-taxonomy-1495", "HELD", f304_taxonomy_pin),
    ]
    for pid, expected, fn in probes:
        _run(pid, expected, fn)
    for name, verdict, note in green_check():
        _RESULTS.append(("green:" + name, "HELD", verdict,
                         verdict == "HELD", note))
    n_ok = sum(1 for r in _RESULTS if r[3])
    n_bad = len(_RESULTS) - n_ok
    print("w280_f304: %d/%d HELD, %d BREAK/ERROR" % (n_ok, len(_RESULTS),
                                                     n_bad))
    for pid, expected, verdict, ok, note in _RESULTS:
        print("%-32s %-5s %-5s %s" % (pid, expected, verdict, note))
    return 0 if n_bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
