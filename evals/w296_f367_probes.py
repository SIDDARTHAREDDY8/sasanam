"""Wave-296 lane 1 battery: F367 closure (coordination_lease future-dated
issued_at bypass).

Base: wave-295 merge 10777555 (verified via git rev-parse HEAD before work).

Red-first: on the pristine base the future-dated acquire probe BREAKs
(the live-lease check runs at the caller-supplied issued_at, so it
bypasses coord-lease-denied and evicts the live lease); on the fixed
tree every probe HELDs.

Run:
  mkdir -p /var/tmp/g296-f367 && TMPDIR=/var/tmp/g296-f367 \
    ~/workspace/.gov-venv/bin/python evals/w296_f367_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g296-f367b \
    ~/workspace/.gov-venv/bin/python evals/w296_f367_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import time
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1933 # Wave-296 lane 1: unchanged (F367 fix reuses existing; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)
                     # codes; no new decision codes minted).

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    _record("pin-taxonomy", "HELD", "1916 raw literals, unique, sorted")


def _import_cl():
    from gov import coordination_lease
    return coordination_lease


_SEED = bytes(range(32))


def _mgr(cl):
    return cl.LeaseManager()


def p_future_grant_coexists():
    # F367 core (queueing design): a future-dated, NON-OVERLAPPING
    # acquire is granted -- but it QUEUES alongside the live lease
    # instead of evicting it. The live holder's record and writes
    # survive.
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    la = m.acquire("fscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=now)
    try:
        lb = m.acquire("fscope", 3600, "mallory", authority_seed=_SEED,
                       issued_at=now + 7200)
    except cl.CoordinationLeaseError as e:
        return _record("f367-future-grant-coexists", "BREAK",
                       "non-overlapping future grant refused coded %r; "
                       "the queueing design grants it without evicting "
                       "the live lease" % (e.code,))
    if lb["holder_id"] != "mallory":
        return _record("f367-future-grant-coexists", "BREAK",
                       "future grant recorded for wrong holder")
    try:
        ok = m.check_write("fscope", la["fencing_token"], "alice",
                           checked_at=now + 30)
    except cl.CoordinationLeaseError as e:
        return _record("f367-future-grant-coexists", "BREAK",
                       "F367 STILL PRESENT: live holder's write dies "
                       "with coded %r after the future grant -- the "
                       "live record was evicted" % (e.code,))
    if ok is not True:
        return _record("f367-future-grant-coexists", "BREAK",
                       "live holder's write not authorized after the "
                       "future grant")
    _record("f367-future-grant-coexists", "HELD",
            "future grant queues (token %d); live holder's lease and "
            "writes survive" % (lb["fencing_token"],))


def p_overlap_denied():
    # The coded path: a grant OVERLAPPING the live lease's interval
    # refuses coded coord-lease-denied regardless of the claimed
    # issued_at.
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    m.acquire("oscope", 3600, "alice", authority_seed=_SEED,
              issued_at=now)
    try:
        m.acquire("oscope", 3600, "mallory", authority_seed=_SEED,
                  issued_at=now + 1800)
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_DENIED:
            return _record("f367-overlap-denied", "BREAK",
                           "overlapping grant refused with %r, want "
                           "coord-lease-denied" % (e.code,))
        return _record("f367-overlap-denied", "HELD",
                       "overlapping grant refuses coded "
                       "coord-lease-denied")
    _record("f367-overlap-denied", "BREAK",
            "overlapping grant was granted (no denial)")


def p_no_eviction_after_grant():
    # After the queued future grant, the live holder's lease must
    # still be the one honored by check_write at a live instant.
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    la = m.acquire("escope", 3600, "alice", authority_seed=_SEED,
                   issued_at=now)
    try:
        m.acquire("escope", 3600, "mallory", authority_seed=_SEED,
                  issued_at=now + 7200)
    except cl.CoordinationLeaseError as e:
        return _record("f367-no-eviction", "BREAK",
                       "non-overlapping future grant refused coded %r"
                       % (e.code,))
    try:
        ok = m.check_write("escope", la["fencing_token"], "alice",
                           checked_at=now + 30)
    except cl.CoordinationLeaseError as e:
        return _record("f367-no-eviction", "BREAK",
                       "F367: preempted holder's write dies with coded "
                       "%r -- the live lease was evicted by the "
                       "future-dated acquire" % (e.code,))
    if ok is not True:
        return _record("f367-no-eviction", "BREAK",
                       "live holder's write not authorized")
    _record("f367-no-eviction", "HELD",
            "live holder's lease survives the queued future grant")


def p_renew_cannot_steal_future():
    # Renewing the live lease into a queued future grant's interval
    # refuses coded coord-lease-denied (F367: renewal cannot steal a
    # queued future).
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    la = m.acquire("rnscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=now)
    m.acquire("rnscope", 3600, "mallory", authority_seed=_SEED,
              issued_at=now + 7200)
    try:
        m.renew("rnscope", la["fencing_token"], "alice", 7200,
                authority_seed=_SEED, checked_at=now + 30)
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_DENIED:
            return _record("f367-renew-cannot-steal", "BREAK",
                           "overlap renewal refused with %r, want "
                           "coord-lease-denied" % (e.code,))
        return _record("f367-renew-cannot-steal", "HELD",
                       "renewal into a queued future refuses coded "
                       "coord-lease-denied")
    _record("f367-renew-cannot-steal", "BREAK",
            "renewal stole the queued future grant's interval")


def p_release_queued_keeps_future():
    # Releasing the live lease surrenders only its own interval; the
    # queued future grant remains usable.
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    la = m.acquire("rlscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=now)
    lb = m.acquire("rlscope", 3600, "mallory", authority_seed=_SEED,
                   issued_at=now + 7200)
    m.release("rlscope", la["fencing_token"], "alice")
    try:
        ok = m.check_write("rlscope", lb["fencing_token"], "mallory",
                           checked_at=now + 7300)
    except cl.CoordinationLeaseError as e:
        return _record("f367-release-queued", "BREAK",
                       "queued future grant unusable after release of "
                       "the live lease: %r" % (e.code,))
    if ok is not True:
        return _record("f367-release-queued", "BREAK",
                       "queued future grant write not authorized")
    _record("f367-release-queued", "HELD",
            "release surrenders one interval; queued future survives")


def p_denied_when_live_normal():
    # Baseline contract: double acquire with no issued_at claims refuses.
    cl = _import_cl()
    m = _mgr(cl)
    m.acquire("nscope", 3600, "alice", authority_seed=_SEED)
    try:
        m.acquire("nscope", 3600, "bob", authority_seed=_SEED)
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_DENIED:
            return _record("f367-denied-normal", "BREAK",
                           "refused with %r, want coord-lease-denied"
                           % (e.code,))
        return _record("f367-denied-normal", "HELD",
                       "second acquire on live scope refuses coded")
    _record("f367-denied-normal", "BREAK",
            "second acquire on live scope was granted (no denial)")


def p_reacquire_after_expiry():
    # A future-dated issued_at must NOT refuse when no lease is live at
    # grant time (the fix is about the check instant, not about banning
    # the issued_at parameter itself).
    cl = _import_cl()
    m = _mgr(cl)
    now = int(time.time())
    # Lease that is already expired at grant time.
    m.acquire("xscope", 1, "alice", authority_seed=_SEED,
              issued_at=now - 3600)
    try:
        lb = m.acquire("xscope", 3600, "bob", authority_seed=_SEED,
                       issued_at=now + 7200)
    except cl.CoordinationLeaseError as e:
        return _record("f367-reacquire-after-expiry", "BREAK",
                       "re-acquire after expiry refused coded %r; the "
                       "fix must only deny while a lease is live at "
                       "grant time" % (e.code,))
    if lb["holder_id"] != "bob":
        return _record("f367-reacquire-after-expiry", "BREAK",
                       "re-acquire granted to wrong holder")
    _record("f367-reacquire-after-expiry", "HELD",
            "expired scope re-acquires even with a future issued_at")


def p_default_issued_at_is_grant_time():
    # issued_at omitted: the grant must timestamp the lease at grant time.
    cl = _import_cl()
    m = _mgr(cl)
    before = int(time.time())
    lease = m.acquire("gscope", 3600, "alice", authority_seed=_SEED)
    after = int(time.time())
    if not (before <= lease["issued_at"] <= after):
        return _record("f367-default-issued-at", "BREAK",
                       "default issued_at %d outside grant window [%d,%d]"
                       % (lease["issued_at"], before, after))
    _record("f367-default-issued-at", "HELD",
            "default issued_at equals grant time")


def p_docstring_contract():
    # The module contract must state the queueing rule explicitly:
    # non-overlapping future grants queue instead of evicting.
    with open(os.path.join(REPO, "gov", "coordination_lease.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    if "F367" not in src or "evict" not in src.lower():
        return _record("f367-docstring", "BREAK",
                       "acquire docstring does not document the "
                       "no-eviction queueing rule (F367)")
    _record("f367-docstring", "HELD",
            "no-eviction queueing rule is documented at the acquire "
            "seam")


def _green_checks():
    if SKIP_GREEN:
        _record("green-skip", "HELD",
                "GOV_SKIP_GREEN=1: child green checks skipped (depth-1)")
        return
    for battery, want_breaks in (
            # w295_redteam: 4 BREAK on the pristine base (F367-F370);
            # on the composed wave-296 tree all four are CLOSED, so 0
            # BREAK expected-open (the lane-local tree had 3 open).
            ("evals/w295_redteam_probes.py", 0),
            ("evals/w294_coord_lease_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g296f367green")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, battery)],
            capture_output=True, text=True, env=env,
            cwd=REPO, timeout=600)
        tail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        m_break = re.search(r"(\d+)\s+BREAK", tail)
        nb = int(m_break.group(1)) if m_break else -1
        m_err = re.search(r"(\d+)\s+ERROR", tail)
        ne = int(m_err.group(1)) if m_err else -1
        tag = os.path.basename(battery)
        # rc=1 is the battery's normal "breaks present" exit; what
        # matters is the break/error counts matching expectation.
        if p.returncode not in (0, 1) or nb != want_breaks or ne != 0:
            _record("green-%s" % tag, "BREAK",
                    "rc=%d breaks=%d (want %d) errors=%d tail=%r\n%s"
                    % (p.returncode, nb, want_breaks, ne, tail,
                       p.stderr[-500:]))
        else:
            _record("green-%s" % tag, "HELD",
                    "%d BREAK (expected-open) / 0 ERROR" % (want_breaks,))


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in (
            ("f367-future-grant-coexists", p_future_grant_coexists),
            ("f367-overlap-denied", p_overlap_denied),
            ("f367-no-eviction", p_no_eviction_after_grant),
            ("f367-renew-cannot-steal", p_renew_cannot_steal_future),
            ("f367-release-queued", p_release_queued_keeps_future),
            ("f367-denied-normal", p_denied_when_live_normal),
            ("f367-reacquire-after-expiry", p_reacquire_after_expiry),
            ("f367-default-issued-at", p_default_issued_at_is_grant_time),
            ("f367-docstring", p_docstring_contract)):
        _safe(pid, fn)
    _green_checks()
    b = sum(1 for _, v, _ in _results if v == "BREAK")
    h = sum(1 for _, v, _ in _results if v == "HELD")
    e = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w296_f367: %d BREAK / %d HELD / %d ERROR" % (b, h, e))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, b, h, e)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    if b or e:
        print("-- full notes --")
        for pid, v, note in _results:
            if v in ("BREAK", "ERROR"):
                print("### %s\n%s" % (pid, note))
    sys.exit(1 if (b or e) else 0)


if __name__ == "__main__":
    main()
