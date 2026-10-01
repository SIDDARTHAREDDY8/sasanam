"""Break-first battery for short-lived credential issuance.

Wave-256 lane 2. Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets gov/short_lived_credentials.py (infisical lease-shape ADAPT):
mint-on-demand, TTL enforcement, revocation, journaled lifetime,
explicit bounded TTL, explicit non-wildcard scope.

Expected verdicts:
  pristine base (23967f50, module absent): all GAP
  fixed code:                            all HELD
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)

try:
    from gov import short_lived_credentials as slc  # noqa: E402
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

assert len(decision_codes.TAXONOMY) == 1325, "taxonomy pin 1299"  # Wave-269 merge: pin -> 1325.

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _tmpdir():
    d = tempfile.mkdtemp(prefix="w256cred-", dir="/var/tmp")
    os.makedirs(d, exist_ok=True)
    return d


def _issuer(tmp, **kw):
    kw.setdefault("max_ttl_seconds", 3600)
    return slc.CredentialIssuer(os.path.join(tmp, "creds.jsonl"), **kw)


def _refused(fn, code):
    """HELD iff fn raises a CredentialError carrying exactly `code`."""
    try:
        fn()
    except slc.CredentialError as exc:
        return "HELD" if exc.code == code else "BREAK(wrong %s)" % exc.code
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def expired_use_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    return _refused(
        lambda: iss.verify(cred["credential_id"], cred["secret"],
                           now=cred["expires_at"] + 1.0),
        "short-lived-credential-expired")


@probe
def revoked_use_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    iss.revoke(cred["credential_id"])
    return _refused(
        lambda: iss.verify(cred["credential_id"], cred["secret"]),
        "short-lived-credential-revoked")


@probe
def unbounded_ttl_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    for bad in (None, 0, -5, 3601, 10 ** 12):
        v = _refused(lambda b=bad: iss.issue("agent-1", "tool:read", b),
                     "short-lived-credential-ttl-unbounded")
        if v != "HELD":
            return "BREAK(ttl=%r -> %s)" % (bad, v)
    return "HELD"


@probe
def wildcard_scope_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    for wild in ("*", "tool:*", "*:read"):
        v = _refused(lambda w=wild: iss.issue("agent-1", w, 60),
                     "short-lived-credential-scope-forbidden")
        if v != "HELD":
            return "BREAK(scope=%r -> %s)" % (wild, v)
    return "HELD"


@probe
def journal_forgery_detected():
    tmp = _tmpdir()
    path = os.path.join(tmp, "creds.jsonl")
    iss = _issuer(tmp)
    iss.issue("agent-1", "tool:read", 60)
    with open(path, "r+b") as fh:
        data = bytearray(fh.read())
    data[len(data) // 2] ^= 0x01  # flip one byte mid-file
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    try:
        slc.CredentialIssuer(path)
    except slc.CredentialError as exc:
        if exc.code in ("short-lived-credential-chain-broken",
                        "short-lived-credential-corrupted"):
            return "HELD"
        return "BREAK(wrong %s)" % exc.code
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def unknown_id_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    return _refused(lambda: iss.verify("no-such-id", "nope"),
                    "short-lived-credential-unknown")


@probe
def secret_mismatch_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    return _refused(
        lambda: iss.verify(cred["credential_id"], "wrong-secret"),
        "short-lived-credential-unknown")


@probe
def lifetime_reconstructable():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    iss.verify(cred["credential_id"], cred["secret"])
    iss.revoke(cred["credential_id"])
    kinds = [e["event_type"] for e in
             iss.history(cred["credential_id"])]
    if kinds == ["CRED_ISSUED", "CRED_USED", "CRED_REVOKED"]:
        return "HELD"
    return "BREAK(%r)" % (kinds,)


@probe
def scope_binding_enforced():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    return _refused(
        lambda: iss.verify(cred["credential_id"], cred["secret"],
                           scope="tool:write"),
        "short-lived-credential-scope-forbidden")


@probe
def malformed_inputs_refused():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    bads = [
        lambda: iss.issue("", "tool:read", 60),       # empty principal
        lambda: iss.issue(123, "tool:read", 60),       # non-str principal
        lambda: iss.issue("a", "", 60),                # empty scope
        lambda: iss.issue("a", "tool:read", "60"),    # str ttl
        lambda: iss.issue("a", "tool:read", True),    # bool ttl
        lambda: iss.issue("a", "tool:read", 1.5),     # float ttl
    ]
    for i, bad in enumerate(bads):
        v = _refused(bad, "short-lived-credential-malformed")
        if v != "HELD":
            return "BREAK(case %d -> %s)" % (i, v)
    return "HELD"


@probe
def use_is_journaled():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    iss.verify(cred["credential_id"], cred["secret"])
    kinds = [e["event_type"] for e in
             iss.history(cred["credential_id"])]
    if "CRED_USED" in kinds:
        return "HELD"
    return "BREAK(%r)" % (kinds,)


@probe
def expiry_lazy_journaled_once():
    tmp = _tmpdir()
    iss = _issuer(tmp)
    cred = iss.issue("agent-1", "tool:read", 60)
    cid = cred["credential_id"]
    for _ in range(2):
        try:
            iss.verify(cid, cred["secret"],
                       now=cred["expires_at"] + 5.0)
        except slc.CredentialError as exc:
            if exc.code != "short-lived-credential-expired":
                return "BREAK(wrong %s)" % exc.code
    kinds = [e["event_type"] for e in iss.history(cid)]
    if kinds.count("CRED_EXPIRED") == 1:
        return "HELD"
    return "BREAK(%r)" % (kinds,)


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_permit_journal",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g256-cred-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: permit_journal + decision_codes green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-32s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                 len(results)))
    if HAVE_MODULE and not green_check():
        return 1
    return 1 if (brk or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
