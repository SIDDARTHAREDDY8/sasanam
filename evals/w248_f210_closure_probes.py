"""Wave-248 F210 closure probes: break-first verification that the
BreachBoundary quarantine bypass is closed.

F210 (MEDIUM): gov/breach_boundary.py use() trusted the caller-supplied
``verified`` flag on a plain dict -- a forged flag bypassed the
deployment-vouched verification step, and a verify-then-mutate TOCTOU
allowed never-verified output. Both shapes are pinned as BREAK in
evals/w247_redteam_probes.py (probes breach_forged_verified and
breach_verify_then_mutate).

Closure: verify() now HMAC-seals verified records over (component,
seq, rotation epoch, output, verifier_id, evidence); use() refuses a
missing/stale/mismatched seal. In THIS battery HELD means the secure
behavior holds (the attack is refused / the honest path works) and
BREAK means the closure failed (the attack succeeded). Exit code is
non-zero on any BREAK or PROBE-ERROR.

Hygiene: module-level staging setdefault; no in-repo git subprocesses;
fresh TMPDIR per run; stdlib only. Depth-1 green checks honor
GOV_SKIP_GREEN.
"""

import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, REPO_ROOT)

from gov import breach_boundary as _bb

_KEY_A = b"f210-closure-key-a-00000000000001"
_KEY_B = b"f210-closure-key-b-00000000000002"


def _vouch(*identities):
    return {i: _bb.VOUCHED for i in identities}


def _boundary(key=_KEY_A):
    b = _bb.BreachBoundary(seal_key=key)
    b.declare_component("tool-svc", _bb.TRUST_ASSUMED_BREACHABLE)
    return b


def _verified(b, output=None):
    q = b.ingest("tool-svc", {"cmd": "benign --dry-run"}
                 if output is None else output)
    return b.verify(q, {"verifier_id": "checker-1", "evidence": "ok"},
                    _vouch("checker-1"))


def _refused_with(fn, code):
    """Run fn(); HELD iff it raises BreachBoundaryError with `code`."""
    try:
        fn()
    except _bb.BreachBoundaryError as exc:
        if exc.code == code:
            return ("HELD", "refused with %s" % code)
        return ("BREAK", "refused but with wrong code %s (want %s)"
                % (exc.code, code))
    return ("BREAK", "ALLOWED -- closure failed")


# ---------------------------------------------------------------------------
# Closure probes
# ---------------------------------------------------------------------------

def probe_forged_verified_refused():
    """F210(a): fabricated record with forged verified=True."""
    def attack():
        b = _boundary()
        forged = {
            "_breach_boundary_quarantined": True,
            "decision": "quarantined",
            "component": "tool-svc",
            "trust_class": "assumed-breachable",
            "seq": 999,
            "output": {"exfil": "attacker-controlled"},
            "verified": True,
            "verification": {"verifier_id": "nobody",
                             "evidence": None},
        }
        b.use(forged)
    return _refused_with(attack, "breach-boundary-seal-invalid")


def probe_verify_then_mutate_refused():
    """F210(b): legitimate verify() on benign output, then mutate."""
    def attack():
        b = _boundary()
        v = _verified(b)
        v["output"] = {"cmd": "exfil --send-all"}
        b.use(v)
    return _refused_with(attack, "breach-boundary-seal-invalid")


def probe_mutated_verifier_id_refused():
    """Swapping the verification metadata must invalidate the seal."""
    def attack():
        b = _boundary()
        v = _verified(b)
        v["verification"] = {"verifier_id": "attacker",
                             "evidence": "ok"}
        b.use(v)
    return _refused_with(attack, "breach-boundary-seal-invalid")


def probe_stripped_seal_refused():
    """A verified record with the seal stripped must be refused."""
    def attack():
        b = _boundary()
        v = _verified(b)
        del v["_verification_seal"]
        b.use(v)
    return _refused_with(attack, "breach-boundary-seal-invalid")


def probe_wrong_key_refused():
    """A seal from another boundary instance (different key) must be
    refused -- seals are instance-keyed."""
    def attack():
        b1 = _boundary(key=_KEY_A)
        b2 = _boundary(key=_KEY_B)
        v = _verified(b1)
        b2.use(v)
    return _refused_with(attack, "breach-boundary-seal-invalid")


def probe_honest_path_allowed():
    """The honest ingest -> verify -> use path must stay green."""
    b = _boundary()
    v = _verified(b)
    try:
        result = b.use(v)
    except _bb.BreachBoundaryError as exc:
        return ("BREAK", "honest path refused: %s" % exc.code)
    if (result.get("decision") == "allow"
            and result.get("output") == {"cmd": "benign --dry-run"}):
        return ("HELD", "honest path allowed with output intact")
    return ("BREAK", "honest path returned unexpected shape: %r"
            % (result,))


def probe_reverify_after_rotation_allowed():
    """After a vouched rotation, re-verification must work."""
    b = _boundary()
    b.rotate("tool-svc", {"rotation_id": "r1"}, _vouch("r1"))
    v = _verified(b)
    try:
        result = b.use(v)
    except _bb.BreachBoundaryError as exc:
        return ("BREAK", "post-rotation re-verify refused: %s"
                % exc.code)
    if result.get("decision") == "allow":
        return ("HELD", "post-rotation re-verification allowed")
    return ("BREAK", "unexpected shape: %r" % (result,))


def probe_unverified_use_still_refused():
    """Pre-existing behavior: unverified use refuses with the original
    code (no behavior change for the unsealed path)."""
    def attack():
        b = _boundary()
        q = b.ingest("tool-svc", {"x": 1})
        b.use(q)
    return _refused_with(attack, "breach-boundary-unverified-use-refused")


def probe_deterministic_seal_with_fixed_key():
    """Deployment-supplied keys make seals deterministic across
    instances with identical operations."""
    v1 = _verified(_boundary(key=_KEY_A))
    v2 = _verified(_boundary(key=_KEY_A))
    if v1["_verification_seal"] == v2["_verification_seal"]:
        return ("HELD", "identical seals under identical key+ops")
    return ("BREAK", "seals differ under identical key+ops")


# ---------------------------------------------------------------------------
# Depth-1 green check (adjacent unit suites)
# ---------------------------------------------------------------------------

_ADJACENT_UNITS = [
    "tests.test_breach_boundary",
    "tests.test_breach_boundary_f210",
]


def _green_check():
    name = "f210_closure_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "standalone for full depth-1 adjacency")
    failures = []
    for i, module in enumerate(_ADJACENT_UNITS):
        tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                           "f210-green-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", module],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
            timeout=600)
        if proc.returncode != 0:
            tail = (proc.stderr.strip().splitlines() or [""])[-1]
            failures.append("%s -> rc=%d (%s)"
                            % (module, proc.returncode, tail))
    if failures:
        return (name, "BREAK", "; ".join(failures))
    return (name, "HELD",
            "adjacent unit suites green at depth 1: %s"
            % ", ".join(_ADJACENT_UNITS))


# ---------------------------------------------------------------------------
# Registry + main
# ---------------------------------------------------------------------------

PROBES = [
    ("forged_verified_refused", probe_forged_verified_refused),
    ("verify_then_mutate_refused", probe_verify_then_mutate_refused),
    ("mutated_verifier_id_refused", probe_mutated_verifier_id_refused),
    ("stripped_seal_refused", probe_stripped_seal_refused),
    ("wrong_key_refused", probe_wrong_key_refused),
    ("honest_path_allowed", probe_honest_path_allowed),
    ("reverify_after_rotation_allowed",
     probe_reverify_after_rotation_allowed),
    ("unverified_use_still_refused", probe_unverified_use_still_refused),
    ("deterministic_seal_with_fixed_key",
     probe_deterministic_seal_with_fixed_key),
]


def _run(name, fn):
    try:
        verdict, evidence = fn()
    except Exception as exc:
        return (name, "PROBE-ERROR",
                "%s: %s" % (type(exc).__name__, exc))
    assert verdict in ("HELD", "BREAK"), verdict
    return (name, verdict, evidence)


def main():
    results = [_run(name, fn) for name, fn in PROBES]
    results.append(_green_check())
    held = sum(1 for _n, v, _e in results if v == "HELD")
    broken = sum(1 for _n, v, _e in results if v == "BREAK")
    errored = sum(1 for _n, v, _e in results if v == "PROBE-ERROR")
    print("w248 F210 closure: %d checks: %d HELD / %d BREAK / %d "
          "PROBE-ERROR" % (len(results), held, broken, errored))
    for name, verdict, evidence in results:
        print("[%s] %s: %s" % (verdict, name, evidence))
    # Non-zero exit on any BREAK/PROBE-ERROR: the closure is not
    # complete until every check is HELD.
    return 0 if (broken == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
