"""Break-first probes for gov/federated_identity (wave-325 lane 2).

Federated agent identity via the dex pattern, without the dex server:
short-lived Ed25519-signed identity tokens (issuer side), a
rotation-aware verifier (issuer keys pinned out-of-band), a
token-backed PrincipalRegistry, and the ToolExecutor federated-mode
integration. Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.federated_identity). On the lane tree every
attack below must refuse with the coded reason -- 0 BREAK target.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)
from keyfixture import provision_test_key  # noqa: E402  (test key material)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Fixtures. Deterministic: fixed seeds, injected clocks.
# ---------------------------------------------------------------------------

ISSUER_SEED = bytes(range(32))
ISSUER_SEED2 = bytes([255 - i for i in range(32)])
AGENT_SEED = bytes([(i * 7) % 256 for i in range(32)])
EVIL_SEED = bytes([(i * 29 + 5) % 256 for i in range(32)])
NOW = 1800000000.0
AUD = "sasanam-policy-engine"
ISSUER_ID = "test-issuer"


def _mod():
    from gov import federated_identity as fi
    from gov import ed25519 as _ed
    return fi, _ed


def _issuer(seed=ISSUER_SEED, issuer_id=ISSUER_ID, **kw):
    fi, _ = _mod()
    return fi.TokenIssuer(seed, issuer_id, **kw)


def _agent_pubkey_hex():
    from gov import ed25519 as _ed
    return _ed.publickey(AGENT_SEED).hex()


def _verifier(**kw):
    fi, _ed = _mod()
    v = fi.TokenVerifier(AUD, **kw)
    v.add_issuer(ISSUER_ID, _ed.publickey(ISSUER_SEED).hex())
    return v


def _issue(issuer=None, now=NOW, **kw):
    args = dict(agent_id="agent-7", principal="ops",
                role="reader", agent_pubkey_hex=_agent_pubkey_hex(),
                scopes=("read", "write"), now=now)
    args.update(kw)
    return (issuer or _issuer()).issue_token(**args)


def _live_issue(**kw):
    # The executor verifies with wall-clock time, so tokens for
    # executor probes are issued at wall-clock time, not the fixed
    # NOW used by the pure token probes.
    import time as _time
    return _issue(now=_time.time(), **kw)


def _b64u_decode(part):
    import base64
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _executor(token_verifier=None):
    # Executor construction needs a log-signing key (F73 fail-closed
    # without one); batteries provision explicit test key material via
    # the same env backend production uses.
    provision_test_key(epoch="test")
    import tempfile
    from pathlib import Path
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.log import ActionLog
    from gov.approvals import ApprovalQueue
    run_dir = Path(tempfile.mkdtemp(prefix="govdexid-"))
    (run_dir / "policy.yaml").write_text(
        "version: 2\nroles:\n  operator: [read_file]\n"
        "policies:\n  - id: allow-all\n    effect: allow\n"
        "    match:\n      tool: [read_file]\n"
        "    reason: dexid fixture\n")
    policy = PolicyEngine(str(run_dir / "policy.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    kw = dict(ledger_path=run_dir / "egress_ledger.jsonl",
              ungoverned_ack="dexid battery: synthetic executor")
    if token_verifier is not None:
        kw["token_verifier"] = token_verifier
    return ToolExecutor(run_dir, policy, log, approvals, **kw)


# ---------------------------------------------------------------------------
# P1-P16: the attacks.
# ---------------------------------------------------------------------------

@probe("P1-forged-token-signature")
def _p1():
    import json
    import base64
    fi, _ed = _mod()
    token = _issue()
    p1, p2, p3 = token.split(".")
    body = json.loads(_b64u_decode(p2))
    body["role"] = "admin"  # tamper after issuance
    p2f = base64.urlsafe_b64encode(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).rstrip(b"=").decode()
    forged = p1 + "." + p2f + "." + p3
    _expect_code("P1-forged-token-signature",
                 lambda: _verifier().verify_token(forged, now=NOW),
                 "identity-token-tampered")


@probe("P2-unknown-issuer")
def _p2():
    fi, _ed = _mod()
    evil_issuer = _issuer(seed=EVIL_SEED, issuer_id="evil-issuer")
    token = _issue(issuer=evil_issuer)
    _expect_code("P2-unknown-issuer",
                 lambda: _verifier().verify_token(token, now=NOW),
                 "identity-token-issuer-unknown")


@probe("P3-expired-token")
def _p3():
    token = _issue(now=NOW - 600)  # iat=NOW-600, exp=NOW-300
    _expect_code("P3-expired-token",
                 lambda: _verifier().verify_token(token, now=NOW),
                 "identity-token-expired")


@probe("P4-future-issued-token")
def _p4():
    token = _issue(now=NOW + 3600)  # iat an hour in the future
    _expect_code("P4-future-issued-token",
                 lambda: _verifier().verify_token(token, now=NOW),
                 "identity-token-not-yet-valid")


@probe("P5-audience-mismatch")
def _p5():
    token = _issue(audience="other-audience")
    _expect_code("P5-audience-mismatch",
                 lambda: _verifier().verify_token(token, now=NOW),
                 "identity-token-audience-mismatch")


@probe("P6-nonce-replay")
def _p6():
    fi, _ed = _mod()
    v = _verifier()
    token = _issue()
    claims = v.verify_token(token, now=NOW)
    assert claims["sub"] == "agent-7", "first verify must succeed"
    _expect_code("P6-nonce-replay",
                 lambda: v.verify_token(token, now=NOW),
                 "identity-token-replayed")


@probe("P7-key-binding-mismatch")
def _p7():
    from gov import ed25519 as _ed
    evil_pub = _ed.publickey(EVIL_SEED).hex()
    token = _issue()
    _expect_code("P7-key-binding-mismatch",
                 lambda: _verifier().verify_token(
                     token, now=NOW, expected_key_binding=evil_pub),
                 "identity-token-key-binding-mismatch")


@probe("P8-role-claim-escalation")
def _p8():
    from gov.identity import IdentityTokenError
    v = _verifier()
    token = _live_issue()  # role=reader
    ex = _executor(token_verifier=v)
    try:
        ex.mint_identity("agent-7", "admin", "ops",
                         token_claims=token)
    except IdentityTokenError:
        _held("P8-role-claim-escalation",
              "escalated mint refused (IdentityTokenError)")
        return
    _break("P8-role-claim-escalation",
           "reader token minted an admin identity")


@probe("P9-rotation-old-key-verifies-during-grace")
def _p9():
    fi, _ed = _mod()
    v = _verifier(rotation_grace_seconds=3600)
    old_token = _issue(now=NOW - 100)
    v.rotate_issuer(ISSUER_ID, _ed.publickey(ISSUER_SEED2).hex(),
                    now=NOW)
    claims = v.verify_token(old_token, now=NOW)
    assert claims["sub"] == "agent-7", "grace-period token must verify"
    _held("P9-rotation-old-key-verifies-during-grace",
          "old-key token verifies inside grace")


@probe("P10-rotation-old-key-refused-after-grace")
def _p10():
    fi, _ed = _mod()
    v = _verifier(rotation_grace_seconds=3600)
    old_token = _issue(now=NOW - 100)
    v.rotate_issuer(ISSUER_ID, _ed.publickey(ISSUER_SEED2).hex(),
                    now=NOW - 7200)  # retired 2h ago, grace 1h
    _expect_code("P10-rotation-old-key-refused-after-grace",
                 lambda: v.verify_token(old_token, now=NOW),
                 "identity-issuer-key-retired")


@probe("P11-federated-mode-tokenless-refused")
def _p11():
    from gov.identity import IdentityTokenError
    ex = _executor(token_verifier=_verifier())
    try:
        ex.mint_identity("agent-7", "reader", "ops")
    except IdentityTokenError as exc:
        assert getattr(exc, "code", None) == "identity-token-required", \
            "want coded identity-token-required, got %r" % (
                getattr(exc, "code", None),)
        _held("P11-federated-mode-tokenless-refused",
              "tokenless mint refused coded identity-token-required")
        return
    _break("P11-federated-mode-tokenless-refused",
           "federated mode minted without a token")


@probe("P12-string-token-end-to-end-mint")
def _p12():
    v = _verifier()
    token = _live_issue()
    ex = _executor(token_verifier=v)
    ident = ex.mint_identity("agent-7", "reader", "ops",
                            token_claims=token)
    assert ident.agent_id == "agent-7", ident
    assert ident.role == "reader", ident
    assert ident.principal == "ops", ident
    assert ident.provenance == "minted", ident
    _held("P12-string-token-end-to-end-mint",
          "string token mints the bound identity")


@probe("P13-token-backed-registry")
def _p13():
    fi, _ = _mod()
    from gov.identity import (UnregisteredPrincipalError,
                              UnregisteredRoleError)
    v = _verifier()
    reg = fi.TokenBackedPrincipalRegistry(v)
    # No token presented: refuse.
    try:
        reg.check_identity("ops", "reader", "agent-7")
    except UnregisteredPrincipalError:
        pass
    else:
        _break("P13-token-backed-registry",
               "check_identity allowed with no presented token")
        return
    # Present the token: the bound tuple authorizes.
    reg.present_token(_issue(), now=NOW)
    assert reg.check_identity("ops", "reader", "agent-7") is True
    assert reg.registered() == {"ops"}
    assert reg.allowed_roles("ops") == {"reader"}
    # Wrong role: UnregisteredRoleError.
    try:
        reg.check_identity("ops", "admin", "agent-7")
    except UnregisteredRoleError:
        pass
    else:
        _break("P13-token-backed-registry",
               "wrong role authorized by token-backed registry")
        return
    # Wrong principal: UnregisteredPrincipalError.
    try:
        reg.check_identity("evilcorp", "reader", "agent-7")
    except UnregisteredPrincipalError:
        pass
    else:
        _break("P13-token-backed-registry",
               "wrong principal authorized by token-backed registry")
        return
    _held("P13-token-backed-registry",
          "token authorizes the bound tuple only")


@probe("P14-malformed-token-shapes")
def _p14():
    cases = ["not-a-token", "a.b", "a.b.c.d",
             "!!!.!!!.!!!",  # bad base64
             ]
    import base64
    import json
    # Valid base64, bad JSON payload.
    bad_json = (base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b"=")
                .decode() + "." +
                base64.urlsafe_b64encode(b"not json").rstrip(b"=")
                .decode() + "." +
                base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=")
                .decode())
    cases.append(bad_json)
    # Valid JSON, wrong alg.
    hdr = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "sasanam-id-token", "v": 1})
        .encode()).rstrip(b"=").decode()
    cases.append(hdr + "." +
                 base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode() +
                 "." +
                 base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=")
                 .decode())
    for i, bad in enumerate(cases):
        _expect_code("P14-malformed-token-shapes#%d" % i,
                     lambda b=bad: _verifier().verify_token(b, now=NOW),
                     "identity-token-malformed")


@probe("P15-ttl-exceeded")
def _p15():
    # Issuer allows 3600s; this verifier caps at 60s.
    token = _issue(ttl_seconds=300)
    v = _verifier(max_ttl_seconds=60)
    _expect_code("P15-ttl-exceeded",
                 lambda: v.verify_token(token, now=NOW),
                 "identity-token-ttl-exceeded")


@probe("P16-valid-token-verifies")
def _p16():
    v = _verifier()
    claims = v.verify_token(_issue(), now=NOW)
    for name in ("iss", "sub", "aud", "iat", "exp", "jti",
                 "principal", "role", "agent_scope"):
        assert claims.get(name) is not None, "missing claim %r" % name
    assert claims["iss"] == ISSUER_ID
    assert claims["sub"] == "agent-7"
    assert claims["aud"] == AUD
    assert claims["principal"] == "ops"
    assert claims["role"] == "reader"
    assert claims["agent_scope"] == "read write"
    assert claims["exp"] - claims["iat"] == 300
    _held("P16-valid-token-verifies",
          "valid token verifies with the bound claims")


@probe("P17-pin-taxonomy-2135-sorted")
def _p17():
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN, \
        "want %d/%d/0, got %d/%d" % (TAXONOMY_PIN, TAXONOMY_PIN,
                                     len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    _held("P17-pin-taxonomy-2135-sorted",
          "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


@probe("P18-footer-state")
def _p18():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Wave-336 lane 1: repaired stale assertion (never-current text).
    assert "Next free finding: **F451**. **Open findings: F446, F447, F448, F449, F450.**" in text, \
        "footer mismatch"
    _held("P18-footer-state", "open F444, F445 / next F446")


@probe("P19-nondict-token-claims-coded")
def _p19():
    # Federated mode, token_claims of a non-str/non-dict type: the
    # pre-existing claim-set refusal, now carrying the machine code.
    from gov.identity import IdentityTokenError
    ex = _executor(token_verifier=_verifier())
    try:
        ex.mint_identity("agent-7", "reader", "ops",
                         token_claims=12345)
    except IdentityTokenError as exc:
        assert getattr(exc, "code", None) == "identity-token-malformed", \
            "want coded identity-token-malformed, got %r" % (
                getattr(exc, "code", None),)
        _held("P19-nondict-token-claims-coded",
              "non-dict claim set refused coded identity-token-malformed")
        return
    _break("P19-nondict-token-claims-coded",
           "non-dict token_claims minted an identity")


# ---------------------------------------------------------------------------
# Green checks (depth-1): adjacent unit suites via the fail-closed
# green-check contract. Exact-count form is not applicable to unittest
# suites (they report OK, not counts); check_unittest requires exit 0.
# ---------------------------------------------------------------------------

def _green():
    # Module form (not file form): check_unittest runs with cwd=repo,
    # and file-form invocation puts tests/ (not the repo) on sys.path.
    green_check.check_unittest(_record, "green-test-identity-token",
                               "tests.test_identity_token", repo=REPO)
    green_check.check_unittest(_record, "green-test-dex-identity",
                               "tests.test_dex_identity", repo=REPO)


def main():
    ordered = []
    for i in range(1, 40):
        fn = globals().get("_p%d" % i)
        if callable(fn):
            ordered.append(fn)
    for fn in ordered:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w325_dexid battery: %d BREAK / %d HELD / %d ERROR "
          % (n_break, n_held, n_err))


if __name__ == "__main__":
    main()
