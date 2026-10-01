"""Break-first closure battery for F228.

Wave-260 lane B. Stdlib only. Deterministic across runs (staging +
`env -u GOV_DEPLOYMENT_MODE`).

Target (gov/short_lived_credentials.py, filed by the wave-259
red-team): F228 -- verify() validates `now` only on the
good-secret path. F224's close-when (1) requires non-numeric `now`
to be refused as short-lived-credential-malformed "on verify()";
on the unfixed tree the unknown-id and secret-mismatch paths return
short-lived-credential-unknown for now="yesterday" -- only the
good-secret path returns malformed. Same defect class as F224.

Close-when: _validate_now() runs before ANY refusal decision in
verify() (unknown-id, mismatch, and good-secret paths all refuse
malformed `now` with short-lived-credential-malformed); the
past-numeric test hook keeps working; F223 timing symmetry is
preserved (re-run evals/w258_f223f224_probes.py, delta within the
1000ns bar -- the reordering puts validation BEFORE the id lookup,
so every refusal path does identical validation work; no new
id-existence delta).

Controls: past numeric `now` honored; normal lifecycle intact.
"""

import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import short_lived_credentials as slc  # noqa: E402

TAXONOMY_PIN = 1372  # Wave-270 merge: pin 1325 -> 1372 (+47 codes: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w260f228-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail):
    return ("BREAK", detail)


def _issuer():
    key = bytes.fromhex("ab" * 32)
    return slc.CredentialIssuer(
        os.path.join(_tmpdir(), "cred.journal"), key=key)


def _code_of(fn):
    try:
        fn()
    except slc.CredentialError as exc:
        return exc.code
    return "NO-EXC"


@probe("f228/non-numeric-now-unknown-id")
def _p_unknown_id():
    # F228 core: unknown-id + non-numeric now must refuse
    # short-lived-credential-malformed, not unknown. On the
    # unfixed tree this BREAKs (unknown returned instead).
    iss = _issuer()
    code = _code_of(
        lambda: iss.verify("f" * 32, "x", now="yesterday"))
    if code != slc.MALFORMED_CODE:
        return _break(
            "unknown-id + now='yesterday' -> %s (expected "
            "short-lived-credential-malformed)" % code)
    return _held("unknown-id + non-numeric now -> malformed")


@probe("f228/non-numeric-now-secret-mismatch")
def _p_mismatch():
    # F228 core: secret-mismatch + non-numeric now must refuse
    # short-lived-credential-malformed. On the unfixed tree this
    # BREAKs (unknown returned instead).
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    code = _code_of(
        lambda: iss.verify(cred["credential_id"], "wrong-secret",
                           now="yesterday"))
    if code != slc.MALFORMED_CODE:
        return _break(
            "mismatch + now='yesterday' -> %s (expected "
            "short-lived-credential-malformed)" % code)
    return _held("mismatch + non-numeric now -> malformed")


@probe("f228/non-numeric-now-good-secret")
def _p_good_secret():
    # Control: the good-secret path already returned malformed on
    # the unfixed tree (F224). Pins no regression on that path.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    code = _code_of(
        lambda: iss.verify(cred["credential_id"], cred["secret"],
                           now="yesterday"))
    if code != slc.MALFORMED_CODE:
        return _break(
            "good-secret + now='yesterday' -> %s (expected "
            "short-lived-credential-malformed)" % code)
    return _held("good-secret + non-numeric now -> malformed")


@probe("f228/now-shapes-on-refusal-paths")
def _p_shapes():
    # bool/list/NaN/inf refused as malformed on BOTH refusal
    # paths (unknown-id and mismatch), not just good-secret.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    cid = cred["credential_id"]
    bad = []
    for label, value in [("bool", True), ("list", [1]),
                         ("nan", float("nan")),
                         ("inf", float("inf"))]:
        for path, fn in [
                ("unknown",
                 lambda v=value: iss.verify("f" * 32, "x", now=v)),
                ("mismatch",
                 lambda v=value: iss.verify(cid, "wrong", now=v))]:
            code = _code_of(fn)
            if code != slc.MALFORMED_CODE:
                bad.append("%s/%s:%s" % (path, label, code))
    if bad:
        return _break("now shapes not malformed on refusal paths: "
                      "%s" % ",".join(bad))
    return _held("bool/list/nan/inf malformed on both refusal paths")


@probe("control/past-numeric-now-test-hook")
def _p_past_hook():
    # Control: a PAST numeric `now` is honored by design
    # (documented test hook; caller is the trusted deployment).
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


@probe("control/now-none-defaults-to-clock")
def _p_none_hook():
    # Control: now=None still defaults to the wall clock.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    try:
        out = iss.verify(cred["credential_id"], cred["secret"],
                         now=None)
    except slc.CredentialError as exc:
        return _break("now=None refused: %s" % exc.code)
    if out["credential_id"] != cred["credential_id"]:
        return _break("now=None returned wrong credential")
    return _held("now=None defaults to wall clock")


@probe("control/refusal-codes-unchanged-with-numeric-now")
def _p_codes_numeric():
    # Control: with a valid numeric now, the refusal codes are
    # unchanged -- unknown-id and mismatch still share the
    # unknown code (F223 API-level claim).
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    now = cred["issued_at"] + 1
    c1 = _code_of(
        lambda: iss.verify("f" * 32, "x", now=now))
    c2 = _code_of(
        lambda: iss.verify(cred["credential_id"], "wrong", now=now))
    if c1 != slc.UNKNOWN_CODE or c2 != slc.UNKNOWN_CODE:
        return _break("refusal codes changed with numeric now: "
                      "unknown=%s mismatch=%s" % (c1, c2))
    return _held("numeric-now refusals still unknown/unknown")


@probe("control/normal-lifecycle")
def _p_lifecycle():
    # Control: the normal lifecycle is intact -- verify, revoke,
    # revoked-refused, expired journaling, expire_due default now.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    cid, sec = cred["credential_id"], cred["secret"]
    try:
        iss.verify(cid, sec)
    except slc.CredentialError as exc:
        return _break("good verify refused: %s" % exc.code)
    iss.revoke(cid)
    code = _code_of(lambda: iss.verify(cid, sec))
    if code != slc.REVOKED_CODE:
        return _break("revoked verify -> %s" % code)
    c2 = iss.issue("agent-b", "db:read", 60)
    if iss.expire_due() != 0:
        return _break("expire_due() with no expired credentials")
    n = iss.expire_due(now=c2["expires_at"] + 1.0)
    if n != 1:
        return _break("expire_due() with numeric now -> %d" % n)
    code = _code_of(
        lambda: iss.verify(c2["credential_id"], c2["secret"]))
    if code != slc.EXPIRED_CODE:
        return _break("expired verify -> %s" % code)
    return _held("issue/verify/revoke/expire_due/expiry OK")


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    ok = True
    for argv in (
            ("evals/w258_f223f224_probes.py",),   # F223 timing + F224 pins
            ("-m", "unittest", "tests.test_short_lived_credentials"),
    ):
        try:
            r = subprocess.run(
                [sys.executable] + list(argv), env=env, cwd=root,
                capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001 -- harness
            print("GREEN CHECK: %s error %r" % (argv, exc))
            ok = False
            continue
        tail = (r.stdout or "").strip().splitlines()[-1:]
        print("GREEN CHECK: %s -> rc=%d %s"
              % (argv, r.returncode, tail))
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
        print("%-42s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 1
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())

