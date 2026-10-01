"""Break-first closure battery for F223 and F224.

Wave-258 lane 3. Stdlib only. Deterministic across runs (staging +
`env -u GOV_DEPLOYMENT_MODE`).

Targets (both in gov/short_lived_credentials.py, filed by the
wave-257 lane 4 red-team):
- F223: unknown-id vs secret-mismatch refusal paths must be
  timing-indistinguishable within noise (BREAK: systematic delta
  > 1000 ns, median-of-medians, mirroring the red-team method).
- F224: non-numeric `now` on verify()/expire_due() must be
  machine-coded (BREAK: raw TypeError escapes).

Controls: the documented test-hook behavior (past numeric `now`
honored) and the normal lifecycle must keep working.
"""

import os
import statistics
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import short_lived_credentials as slc  # noqa: E402

TAXONOMY_PIN = 1325  # Wave-269 merge: pin -> 1325.

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    d = tempfile.mkdtemp(prefix="w258f223f224-", dir="/var/tmp")
    return d


def _held(detail=""):
    return ("HELD", detail)


def _break(detail):
    return ("BREAK", detail)


def _issuer():
    key = bytes.fromhex("ab" * 32)
    return slc.CredentialIssuer(
        os.path.join(_tmpdir(), "cred.journal"), key=key)


@probe("f223/timing-id-existence-delta")
def _p_timing():
    # F223 close-when: unknown-id vs secret-mismatch are
    # timing-indistinguishable within noise. Median-of-medians
    # over 3x800 samples after warmup; BREAK on systematic delta
    # > 1000 ns (the red-team's bar).
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    real_id = cred["credential_id"]

    def bench(fn, n):
        for _ in range(50):  # warmup, discarded
            try:
                fn()
            except slc.CredentialRefusal:
                pass
        ts = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            try:
                fn()
            except slc.CredentialRefusal:
                pass
            ts.append(time.perf_counter_ns() - t0)
        return statistics.median(ts)

    deltas = []
    for _ in range(3):
        m_unknown = bench(lambda: iss.verify("f" * 32, "x"), 800)
        m_wrong = bench(lambda: iss.verify(real_id, "wrong"), 800)
        deltas.append(m_wrong - m_unknown)
    delta = statistics.median(deltas)
    if delta > 1000:
        return _break(
            "F223: systematic timing delta %d ns (mismatch slower); "
            "id-existence leaks via timing" % int(delta))
    return _held("timing delta %d ns (indistinguishable)"
                 % int(delta))


@probe("f224/non-numeric-now-verify")
def _p_now_verify():
    # F224 close-when: non-numeric `now` on verify() is refused
    # with short-lived-credential-malformed, not raw TypeError.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    try:
        iss.verify(cred["credential_id"], cred["secret"],
                   now="yesterday")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.MALFORMED_CODE:
            return _break("verify() refused with wrong code %s"
                          % exc.code)
        return _held("verify() machine-coded %s" % exc.code)
    except TypeError:
        return _break("F224: raw TypeError escaped verify()")
    return _break("verify() accepted non-numeric now (no refusal)")


@probe("f224/non-numeric-now-expire-due")
def _p_now_expire_due():
    # F224 close-when: same on expire_due().
    iss = _issuer()
    iss.issue("agent-a", "db:read", 600)
    try:
        iss.expire_due(now="yesterday")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.MALFORMED_CODE:
            return _break("expire_due() refused with wrong code %s"
                          % exc.code)
        return _held("expire_due() machine-coded %s" % exc.code)
    except TypeError:
        return _break("F224: raw TypeError escaped expire_due()")
    return _break("expire_due() accepted non-numeric now")


@probe("f224/non-numeric-now-shapes")
def _p_now_shapes():
    # F224 variants: bool, list, NaN, inf are all refused with the
    # malformed code. (bool is an int subclass but carries no
    # timestamp semantics; NaN would silently never trigger
    # expiry since `nan >= expires_at` is False.)
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    bad = []
    for label, value in [("bool", True), ("list", [1]),
                         ("nan", float("nan")),
                         ("inf", float("inf"))]:
        try:
            iss.verify(cred["credential_id"], cred["secret"],
                       now=value)
        except slc.CredentialRefusal as exc:
            if exc.code != slc.MALFORMED_CODE:
                bad.append("%s:wrong-code:%s" % (label, exc.code))
        except TypeError:
            bad.append("%s:raw-TypeError" % label)
        else:
            bad.append("%s:accepted" % label)
    if bad:
        return _break("F224: non-numeric now shapes not coded: %s"
                      % ",".join(bad))
    return _held("bool/list/nan/inf now all machine-coded")


@probe("control/past-numeric-now-test-hook")
def _p_past_now_hook():
    # Control: a PAST numeric `now` is honored by design (documented
    # test hook; the caller is the trusted deployment). This probe
    # pins that behavior HELD -- it is NOT F224.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    past = cred["issued_at"] + 1
    try:
        out = iss.verify(cred["credential_id"], cred["secret"],
                         now=past)
    except slc.CredentialError as exc:
        return _break("past numeric now refused: %s" % exc.code)
    if out["credential_id"] != cred["credential_id"]:
        return _break("past numeric now returned wrong credential")
    return _held("past numeric now honored (test hook intact)")


@probe("control/normal-lifecycle")
def _p_lifecycle():
    # Control: the normal paths still work -- verify, wrong secret
    # refused with the unknown code, revoke, revoked verify
    # refused, expire_due with default now.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 60)
    cid, sec = cred["credential_id"], cred["secret"]
    try:
        iss.verify(cid, sec)
    except slc.CredentialError as exc:
        return _break("good verify refused: %s" % exc.code)
    try:
        iss.verify(cid, "wrong-secret")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.UNKNOWN_CODE:
            return _break("wrong secret code %s" % exc.code)
    else:
        return _break("wrong secret accepted")
    iss.revoke(cid)
    try:
        iss.verify(cid, sec)
    except slc.CredentialRefusal as exc:
        if exc.code != slc.REVOKED_CODE:
            return _break("revoked verify code %s" % exc.code)
    else:
        return _break("revoked credential verified")
    if iss.expire_due() != 0:
        return _break("expire_due() with no expired credentials")
    return _held("issue/verify/wrong-secret/revoke/expire_due OK")


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    ok = True
    for battery in ("evals/w256_credentials_probes.py",):
        path = os.path.join(root, battery)
        try:
            r = subprocess.run(
                [sys.executable, path], env=env, cwd=root,
                capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001 -- harness
            print("GREEN CHECK: %s error %r" % (battery, exc))
            ok = False
            continue
        tail = (r.stdout or "").strip().splitlines()[-1:]
        print("GREEN CHECK: %s -> rc=%d %s"
              % (battery, r.returncode, tail))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
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
        print("%-38s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 1
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
