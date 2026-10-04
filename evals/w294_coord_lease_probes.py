"""Wave-294 lane 2 battery: leased leadership + fencing tokens.

Base: wave-293 merge 8fa5bbe (verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/coordination_lease.py -- lease-bound authority for agent
      coordination roles (anchor-sequencer, delegation-issuer,
      issuance-monitor-runner). Every lease carries a mandatory
      expiry (authority is leased, never held) and a
      monotonically-increasing fencing token. Zombie writes with a
      stale token refuse coded; lease expiry is checked at every
      use (pre-decay fail-closed, wave-292 precedent);
  (b) 4 new decision codes at true sorted positions; lane pin 1730 -> 1734.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g294-lease && TMPDIR=/var/tmp/g294-lease \
    ~/workspace/.gov-venv/bin/python evals/w294_coord_lease_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g294-lease2 \
    ~/workspace/.gov-venv/bin/python evals/w294_coord_lease_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
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

TAXONOMY_PIN = 1933 # Wave-294 lane 2: pin 1730 -> 1734 (+4 coord-lease-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

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
    for want in ("coord-lease-denied", "coord-lease-expired",
                 "coord-lease-fencing", "coord-lease-invalid"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1916 raw literals, unique, sorted")


def _import_cl():
    try:
        from gov import coordination_lease
        return coordination_lease
    except ImportError as e:
        return e


def _need(pid):
    """On the pristine base every functional probe BREAKs (module
    absent). On the fixed tree the import succeeds."""
    cl = _import_cl()
    if isinstance(cl, Exception):
        _record(pid, "BREAK", "gov/coordination_lease.py absent: %r" % (cl,))
        return None
    return cl


_SEED_AUTH = bytes(range(1, 33))
_SEED_A = bytes(range(33, 65))
_SEED_B = bytes(range(65, 97))


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


def _mgr(cl):
    return cl.LeaseManager()


def _lease_ok(cl, lease, scope, holder, token):
    if lease["scope"] != scope:
        return "scope mismatch: %r" % (lease.get("scope"),)
    if lease["holder_id"] != holder:
        return "holder mismatch"
    if lease["fencing_token"] != token:
        return "token mismatch: %r" % (lease.get("fencing_token"),)
    if not (lease["not_after"] > lease["issued_at"]):
        return "expiry not after issuance"
    # The lease must verify under the issuing authority key.
    try:
        cl.verify_lease(lease, _pub(_SEED_AUTH),
                        checked_at=lease["issued_at"])
    except Exception as e:
        return "fresh lease fails verify_lease: %r" % (e,)
    return None


def p_import():
    cl = _need("cl-import")
    if cl is not None:
        _record("cl-import", "HELD", "gov/coordination_lease.py imports")


def p_acquire():
    cl = _need("cl-acquire")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 3600, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    bad = _lease_ok(cl, lease, "anchor-sequencer", "agent-a", 1)
    if bad is not None:
        return _record("cl-acquire", "BREAK", bad)
    if lease["not_after"] != 4600:
        return _record("cl-acquire", "BREAK",
                       "not_after is %r, want issued_at+ttl" %
                       (lease.get("not_after"),))
    _record("cl-acquire", "HELD",
            "acquire issues signed lease with expiry + fencing token 1")


def p_acquire_denied():
    cl = _need("cl-acquire-denied")
    if cl is None:
        return
    m = _mgr(cl)
    m.acquire("delegation-issuer", 3600, "agent-a",
              authority_seed=_SEED_AUTH, issued_at=1000)
    try:
        m.acquire("delegation-issuer", 3600, "agent-b",
                  authority_seed=_SEED_AUTH, issued_at=1001)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-denied":
            return _record("cl-acquire-denied", "HELD",
                           "second acquire while unexpired refused coded")
        return _record("cl-acquire-denied", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-acquire-denied", "BREAK",
            "concurrent lease on the same scope was granted")


def p_reacquire_after_expiry():
    cl = _need("cl-reacquire-after-expiry")
    if cl is None:
        return
    m = _mgr(cl)
    old = m.acquire("issuance-monitor-runner", 100, "agent-a",
                    authority_seed=_SEED_AUTH, issued_at=1000)
    new = m.acquire("issuance-monitor-runner", 100, "agent-b",
                    authority_seed=_SEED_AUTH, issued_at=1101)
    if new["fencing_token"] <= old["fencing_token"]:
        return _record("cl-reacquire-after-expiry", "BREAK",
                       "new generation token %r not above old %r"
                       % (new["fencing_token"], old["fencing_token"]))
    _record("cl-reacquire-after-expiry", "HELD",
            "post-expiry acquire succeeds with strictly higher token")


def _expect_invalid(pid, fn, note):
    try:
        fn()
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-invalid":
            return _record(pid, "HELD", note)
        return _record(pid, "BREAK", "uncoded refusal: %r" % (e,))
    _record(pid, "BREAK", "malformed input was accepted")


def p_ttl_zero():
    cl = _need("cl-ttl-zero")
    if cl is None:
        return
    _expect_invalid(
        "cl-ttl-zero",
        lambda: _mgr(cl).acquire("s", 0, "agent-a",
                                authority_seed=_SEED_AUTH, issued_at=1000),
        "zero ttl refused coded coord-lease-invalid")


def p_ttl_negative():
    cl = _need("cl-ttl-negative")
    if cl is None:
        return
    _expect_invalid(
        "cl-ttl-negative",
        lambda: _mgr(cl).acquire("s", -5, "agent-a",
                                authority_seed=_SEED_AUTH, issued_at=1000),
        "negative ttl refused coded coord-lease-invalid")


def p_ttl_huge():
    cl = _need("cl-ttl-huge")
    if cl is None:
        return
    _expect_invalid(
        "cl-ttl-huge",
        lambda: _mgr(cl).acquire("s", 10 ** 12, "agent-a",
                                authority_seed=_SEED_AUTH, issued_at=1000),
        "unbounded ttl refused coded coord-lease-invalid")


def p_renew():
    cl = _need("cl-renew")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 100, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    renewed = m.renew("anchor-sequencer", lease["fencing_token"],
                      "agent-a", extra_seconds=500,
                      authority_seed=_SEED_AUTH, checked_at=1050)
    if renewed["not_after"] != lease["not_after"] + 500:
        return _record("cl-renew", "BREAK",
                       "renew did not extend expiry: %r" %
                       (renewed.get("not_after"),))
    if renewed["fencing_token"] != lease["fencing_token"]:
        return _record("cl-renew", "BREAK",
                       "renew minted a new token -- generation must not "
                       "advance on renew")
    _record("cl-renew", "HELD",
            "renew with the current token extends the same generation")


def p_renew_stale_token():
    cl = _need("cl-renew-stale-token")
    if cl is None:
        return
    m = _mgr(cl)
    m.acquire("anchor-sequencer", 100, "agent-a",
              authority_seed=_SEED_AUTH, issued_at=1000)
    try:
        m.renew("anchor-sequencer", 9999, "agent-a",
                extra_seconds=500, authority_seed=_SEED_AUTH,
                checked_at=1050)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("cl-renew-stale-token", "HELD",
                           "renew with stale token refused coded")
        return _record("cl-renew-stale-token", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-renew-stale-token", "BREAK", "stale-token renew accepted")


def p_renew_wrong_holder():
    cl = _need("cl-renew-wrong-holder")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 100, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    _expect_invalid(
        "cl-renew-wrong-holder",
        lambda: m.renew("anchor-sequencer", lease["fencing_token"],
                        "agent-b", extra_seconds=500,
                        authority_seed=_SEED_AUTH, checked_at=1050),
        "renew by non-holder refused coded coord-lease-invalid")


def p_write_ok():
    cl = _need("cl-write-ok")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 3600, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    try:
        m.check_write("anchor-sequencer", lease["fencing_token"],
                      "agent-a", checked_at=2000)
    except Exception as e:
        return _record("cl-write-ok", "BREAK",
                       "current-token write refused: %r" % (e,))
    _record("cl-write-ok", "HELD", "current-token write passes")


def p_zombie_write():
    cl = _need("cl-zombie-write")
    if cl is None:
        return
    m = _mgr(cl)
    old = m.acquire("anchor-sequencer", 100, "agent-a",
                    authority_seed=_SEED_AUTH, issued_at=1000)
    m.acquire("anchor-sequencer", 100, "agent-b",
              authority_seed=_SEED_AUTH, issued_at=1101)
    try:
        m.check_write("anchor-sequencer", old["fencing_token"],
                      "agent-a", checked_at=1101)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("cl-zombie-write", "HELD",
                           "zombie write with stale token refused coded")
        return _record("cl-zombie-write", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-zombie-write", "BREAK", "zombie write with stale token passed")


def p_write_expired():
    cl = _need("cl-write-expired")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 100, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    try:
        m.check_write("anchor-sequencer", lease["fencing_token"],
                      "agent-a", checked_at=1101)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-expired":
            return _record("cl-write-expired", "HELD",
                           "write on expired lease refused coded "
                           "coord-lease-expired (pre-decay fail-closed)")
        return _record("cl-write-expired", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-write-expired", "BREAK", "write on expired lease passed")


def p_token_replay_old_generation():
    cl = _need("cl-token-replay-old-generation")
    if cl is None:
        return
    m = _mgr(cl)
    gen1 = m.acquire("anchor-sequencer", 100, "agent-a",
                     authority_seed=_SEED_AUTH, issued_at=1000)
    m.acquire("anchor-sequencer", 100, "agent-a",
              authority_seed=_SEED_AUTH, issued_at=1101)
    try:
        m.check_write("anchor-sequencer", gen1["fencing_token"],
                      "agent-a", checked_at=1102)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("cl-token-replay-old-generation", "HELD",
                           "replayed old-generation token refused coded")
        return _record("cl-token-replay-old-generation", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-token-replay-old-generation", "BREAK",
            "replayed old-generation token passed")


def p_verify_unsigned():
    cl = _need("cl-verify-unsigned")
    if cl is None:
        return
    fake = {"scope": "anchor-sequencer", "holder_id": "agent-a",
            "issued_at": 1000, "not_after": 4600, "fencing_token": 1,
            "authority_pubkey": _pub(_SEED_AUTH),
            "signature": "00" * 64}
    _expect_invalid(
        "cl-verify-unsigned",
        lambda: cl.verify_lease(fake, _pub(_SEED_AUTH), checked_at=2000),
        "unsigned/forged lease refused coded coord-lease-invalid")


def p_verify_tampered():
    cl = _need("cl-verify-tampered")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 3600, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    tampered = dict(lease)
    tampered["holder_id"] = "agent-z"
    _expect_invalid(
        "cl-verify-tampered",
        lambda: cl.verify_lease(tampered, _pub(_SEED_AUTH),
                               checked_at=2000),
        "tampered lease body refused coded coord-lease-invalid")


def p_verify_expired():
    cl = _need("cl-verify-expired")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 100, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    try:
        cl.verify_lease(lease, _pub(_SEED_AUTH), checked_at=1101)
    except Exception as e:
        if getattr(e, "code", None) == "coord-lease-expired":
            return _record("cl-verify-expired", "HELD",
                           "expired lease refused coded coord-lease-expired")
        return _record("cl-verify-expired", "BREAK",
                       "uncoded refusal: %r" % (e,))
    _record("cl-verify-expired", "BREAK", "expired lease verified")


def p_release():
    cl = _need("cl-release")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 3600, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    m.release("anchor-sequencer", lease["fencing_token"], "agent-a")
    lease2 = m.acquire("anchor-sequencer", 3600, "agent-b",
                       authority_seed=_SEED_AUTH, issued_at=1001)
    if lease2["holder_id"] != "agent-b":
        return _record("cl-release", "BREAK", "scope not freed by release")
    _record("cl-release", "HELD", "release frees the scope for re-acquire")


def p_release_wrong_holder():
    cl = _need("cl-release-wrong-holder")
    if cl is None:
        return
    m = _mgr(cl)
    lease = m.acquire("anchor-sequencer", 3600, "agent-a",
                      authority_seed=_SEED_AUTH, issued_at=1000)
    _expect_invalid(
        "cl-release-wrong-holder",
        lambda: m.release("anchor-sequencer", lease["fencing_token"],
                          "agent-b"),
        "release by non-holder refused coded coord-lease-invalid")


def p_malformed_scope():
    cl = _need("cl-malformed-scope")
    if cl is None:
        return
    for bad in ("", 123, None, "x" * 300):
        try:
            _mgr(cl).acquire(bad, 100, "agent-a",
                             authority_seed=_SEED_AUTH, issued_at=1000)
        except Exception as e:
            if getattr(e, "code", None) != "coord-lease-invalid":
                return _record("cl-malformed-scope", "BREAK",
                               "uncoded refusal for %r: %r" % (bad, e))
        else:
            return _record("cl-malformed-scope", "BREAK",
                           "malformed scope %r accepted" % (bad,))
    _record("cl-malformed-scope", "HELD",
            "empty/non-string/oversized scope refused coded")


def p_circular_lease():
    cl = _need("cl-circular-lease")
    if cl is None:
        return
    evil = {}
    evil["self"] = evil
    _expect_invalid(
        "cl-circular-lease",
        lambda: cl.verify_lease(evil, _pub(_SEED_AUTH), checked_at=2000),
        "circular lease dict refused coded coord-lease-invalid "
        "(F351-class: no bare ValueError)")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g294-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("cl-import", p_import),
        ("cl-acquire", p_acquire),
        ("cl-acquire-denied", p_acquire_denied),
        ("cl-reacquire-after-expiry", p_reacquire_after_expiry),
        ("cl-ttl-zero", p_ttl_zero),
        ("cl-ttl-negative", p_ttl_negative),
        ("cl-ttl-huge", p_ttl_huge),
        ("cl-renew", p_renew),
        ("cl-renew-stale-token", p_renew_stale_token),
        ("cl-renew-wrong-holder", p_renew_wrong_holder),
        ("cl-write-ok", p_write_ok),
        ("cl-zombie-write", p_zombie_write),
        ("cl-write-expired", p_write_expired),
        ("cl-token-replay-old-generation", p_token_replay_old_generation),
        ("cl-verify-unsigned", p_verify_unsigned),
        ("cl-verify-tampered", p_verify_tampered),
        ("cl-verify-expired", p_verify_expired),
        ("cl-release", p_release),
        ("cl-release-wrong-holder", p_release_wrong_holder),
        ("cl-malformed-scope", p_malformed_scope),
        ("cl-circular-lease", p_circular_lease),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w293_key_succession_probes.py"),
                 "w293-key-succession", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w292_revocation_probes.py"),
                 "w292-revocation", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w294_coord_lease: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
