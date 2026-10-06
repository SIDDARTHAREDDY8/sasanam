"""Wave-334 MCP server-side token guard battery (F419 closure).

Base: a40c2ef4 (wave-333 merge). Footer at close: open F417 / next F420
(F419 CLOSED here). Pin: 2100 (+11 mcp-server-auth-*).

P1  F419 red-first, cross-resource replay: a token minted for resource
    A presented at resource B refuses coded
    mcp-server-auth-resource-misbound (HTTP 401); the WWW-Authenticate
    challenge is RFC 6750-shaped and names the code, never token bytes.
    (On the base tree no server gate existed -- /tmp/red_mcpsrv.py
    ACCEPT-BY-ABSENCE.)
P2  Missing token: absent/blank Authorization header refuses coded
    mcp-server-auth-missing-token; the 401 challenge carries the
    deployment's resource_metadata URL.
P3  Time window: expired token refuses coded
    mcp-server-auth-token-expired; not-yet-valid (nbf) refuses coded
    mcp-server-auth-token-not-yet-valid; missing/non-numeric exp
    refuses coded mcp-server-auth-malformed.
P4  Issuer: missing iss refuses coded mcp-server-auth-issuer-missing;
    wrong iss refuses coded mcp-server-auth-issuer-mismatched.
P5  Malformed: wrong scheme / empty token / illegal token characters
    refuse coded mcp-server-auth-malformed; a token in the query
    string refuses coded mcp-server-auth-token-in-query.
P6  Valid token at the right resource with covering scope returns an
    ALLOW verdict (resource/issuer/scopes/subject/token_digest; the
    digest is sha256(token), the token itself never appears);
    insufficient scope refuses coded
    mcp-server-auth-insufficient-scope with HTTP 403 and an
    error="insufficient_scope" challenge.
P7  Verifier rejection (raising verifier, non-dict claims) refuses
    coded mcp-server-auth-token-invalid; the challenge never leaks
    token bytes and strips header-injection characters.
P8  Pin 2100 + footer state (open F421 / next F422; F419 CLOSED);
    taxonomy sorted-unique on raw literals; the 11 new codes centrally
    registered.
P9  Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs the
    MCP-OAuth-adjacent battery w245_mcp_oauth_binding_probes.py as a
    child with GOV_SKIP_GREEN=1 (fresh TMPDIR). w245 exercises
    gov/mcp_oauth_binding (the module this lane wires its audience
    check through) and carries no footer probe, so this lane's
    intentional footer change cannot stale it.

gov/ changes in this lane: new gov/mcp_server_authz.py (+11 codes in
gov/decision_codes.py, pin 2077 -> 2088). Findings: F419 filed then
CLOSED here.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F476, F477"  # F423/F424/F425 CLOSED; F426 closed wave-338 lane 1. F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)


FOOTER_NEXT = "F478"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w334mcpsrv")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _tmpd(prefix="w334mcpsrv-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import mcp_server_authz as sa  # noqa: E402
from gov import decision_codes as dc  # noqa: E402

_NOW = 1750000000.0
_SERVER_A = "https://mcp-a.example.com"
_SERVER_B = "https://mcp-b.example.com"
_ISSUER = "https://as.example.com"
_PRM = "https://mcp-b.example.com/.well-known/oauth-protected-resource"

_TOK_VALID = "tok-valid-AAAA"
_TOK_OTHER = "tok-other-BBBB"


def _claims(**kw):
    c = {"iss": _ISSUER, "sub": "agent-7",
         "aud": _SERVER_B, "resource": _SERVER_B,
         "exp": _NOW + 3600.0, "iat": _NOW - 10.0,
         "scope": "tools:call tools:read"}
    c.update(kw)
    return c


def _verifier(mapping):
    def verify(token):
        if token in mapping:
            return mapping[token]
        raise ValueError("bad signature")
    return verify


def _expect_code(pid, fn, want_code, want_status=None):
    try:
        fn()
    except sa.McpServerAuthzError as exc:
        if exc.code != want_code:
            return _break(pid, "wrong code %r want %r" % (exc.code, want_code))
        if want_status is not None and exc.http_status != want_status:
            return _break(pid, "wrong http status %r want %r"
                          % (exc.http_status, want_status))
        return None
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "wrong exception %r" % type(exc).__name__)
    return _break(pid, "no refusal raised")


# ---------------------------------------------------------------------------
# P1 -- F419 red-first: cross-resource replay refused coded.
# ---------------------------------------------------------------------------

@probe("P1-cross-resource-replay-refused-coded")
def _p1():
    pid = "P1-cross-resource-replay-refused-coded"
    # Token minted for A, presented at B.
    claims = _claims(aud=_SERVER_A, resource=_SERVER_A)
    verify = _verifier({_TOK_VALID: claims})
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_RESOURCE_MISBOUND, 401)
    if err:
        return err
    # The 401 challenge is RFC 6750-shaped and names the code.
    status, challenge = sa.refusal_response(
        sa.MCP_SERVER_AUTH_RESOURCE_MISBOUND, "replay",
        resource_metadata_url=_PRM)
    if status != 401:
        return _break(pid, "challenge status %r" % status)
    if not challenge.startswith('Bearer error="invalid_token"'):
        return _break(pid, "challenge not invalid_token: %r" % challenge[:60])
    if "mcp-server-auth-resource-misbound" not in challenge:
        return _break(pid, "challenge lacks machine code")
    if 'resource_metadata="%s"' % _PRM not in challenge:
        return _break(pid, "challenge lacks resource_metadata")
    if _TOK_VALID in challenge:
        return _break(pid, "challenge leaks token bytes")
    return _held(pid, "A-replayed-at-B refuses coded "
                      "mcp-server-auth-resource-misbound; 401 challenge "
                      "RFC 6750-shaped, no token leak")


# ---------------------------------------------------------------------------
# P2 -- missing token.
# ---------------------------------------------------------------------------

@probe("P2-missing-token-401-challenge")
def _p2():
    pid = "P2-missing-token-401-challenge"
    verify = _verifier({})
    for hdr in (None, "", "   "):
        err = _expect_code(
            pid,
            lambda h=hdr: sa.validate_bearer_request(
                _SERVER_B, h, verify, expected_issuer=_ISSUER, now=_NOW),
            sa.MCP_SERVER_AUTH_MISSING_TOKEN, 401)
        if err:
            return err
    status, challenge = sa.refusal_response(
        sa.MCP_SERVER_AUTH_MISSING_TOKEN, "",
        resource_metadata_url=_PRM)
    if status != 401 or 'resource_metadata="%s"' % _PRM not in challenge:
        return _break(pid, "missing-token challenge malformed: %r" % challenge[:80])
    return _held(pid, "absent/blank header refuses coded "
                      "mcp-server-auth-missing-token; challenge carries "
                      "resource_metadata")


# ---------------------------------------------------------------------------
# P3 -- time window.
# ---------------------------------------------------------------------------

@probe("P3-time-window-refusals-coded")
def _p3():
    pid = "P3-time-window-refusals-coded"
    cases = [
        (_claims(exp=_NOW - 1.0), sa.MCP_SERVER_AUTH_TOKEN_EXPIRED),
        (_claims(exp=_NOW), sa.MCP_SERVER_AUTH_TOKEN_EXPIRED),
        (_claims(nbf=_NOW + 60.0), sa.MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID),
        (_claims(exp="soon"), sa.MCP_SERVER_AUTH_MALFORMED),
        (_claims(nbf="later"), sa.MCP_SERVER_AUTH_MALFORMED),
        (_claims(iat="now"), sa.MCP_SERVER_AUTH_MALFORMED),
    ]
    for i, (claims, want) in enumerate(cases):
        verify = _verifier({_TOK_VALID: claims})
        err = _expect_code(
            pid,
            lambda: sa.validate_bearer_request(
                _SERVER_B, "Bearer " + _TOK_VALID, verify,
                expected_issuer=_ISSUER, now=_NOW),
            want, 401)
        if err:
            return _break(pid, "case %d: %s" % (i, err[2]))
    # Missing exp is malformed (tokens without expiry are not valid here).
    claims = _claims()
    del claims["exp"]
    verify = _verifier({_TOK_VALID: claims})
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_MALFORMED, 401)
    if err:
        return err
    return _held(pid, "expired / not-yet-valid / non-numeric / missing "
                      "exp all refuse with the coded time-window refusals")


# ---------------------------------------------------------------------------
# P4 -- issuer.
# ---------------------------------------------------------------------------

@probe("P4-issuer-refusals-coded")
def _p4():
    pid = "P4-issuer-refusals-coded"
    claims = _claims()
    del claims["iss"]
    verify = _verifier({_TOK_VALID: claims})
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_ISSUER_MISSING, 401)
    if err:
        return err
    verify = _verifier({_TOK_VALID: _claims(iss="https://rogue.example.com")})
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_ISSUER_MISMATCHED, 401)
    if err:
        return err
    return _held(pid, "missing/wrong iss refuse coded "
                      "mcp-server-auth-issuer-missing/mismatched")


# ---------------------------------------------------------------------------
# P5 -- malformed shapes and token-in-query.
# ---------------------------------------------------------------------------

@probe("P5-malformed-and-query-refusals-coded")
def _p5():
    pid = "P5-malformed-and-query-refusals-coded"
    verify = _verifier({_TOK_VALID: _claims()})
    bad_headers = [
        ("Basic dXNlcjpwYXNz", sa.MCP_SERVER_AUTH_MALFORMED),
        ("Bearer ", sa.MCP_SERVER_AUTH_MALFORMED),
        ("Bearer", sa.MCP_SERVER_AUTH_MALFORMED),
        ("Bearer tok en", sa.MCP_SERVER_AUTH_MALFORMED),
        ("Bearer tok$en!", sa.MCP_SERVER_AUTH_MALFORMED),
        ("Bearer\x00tok", sa.MCP_SERVER_AUTH_MALFORMED),
    ]
    for hdr, want in bad_headers:
        err = _expect_code(
            pid,
            lambda h=hdr: sa.validate_bearer_request(
                _SERVER_B, h, verify, expected_issuer=_ISSUER, now=_NOW),
            want, 401)
        if err:
            return _break(pid, "header %r: %s" % (hdr, err[2]))
    # Token in the query string is refused outright.
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW,
            query_string="access_token=" + _TOK_VALID),
        sa.MCP_SERVER_AUTH_TOKEN_IN_QUERY, 401)
    if err:
        return err
    # Benign query strings pass through to the header check.
    verdict = sa.validate_bearer_request(
        _SERVER_B, "Bearer " + _TOK_VALID, verify,
        expected_issuer=_ISSUER, now=_NOW,
        query_string="foo=bar&x=1")
    if verdict.resource != _SERVER_B:
        return _break(pid, "benign query string broke validation")
    return _held(pid, "wrong scheme / empty / illegal chars refuse coded "
                      "mcp-server-auth-malformed; token-in-query refuses "
                      "coded mcp-server-auth-token-in-query")


# ---------------------------------------------------------------------------
# P6 -- valid token allows; insufficient scope is 403.
# ---------------------------------------------------------------------------

@probe("P6-valid-allows-scope-403-coded")
def _p6():
    pid = "P6-valid-allows-scope-403-coded"
    verify = _verifier({_TOK_VALID: _claims()})
    verdict = sa.validate_bearer_request(
        _SERVER_B, "Bearer " + _TOK_VALID, verify,
        expected_issuer=_ISSUER, now=_NOW,
        required_scopes=("tools:call",))
    if verdict.resource != _SERVER_B or verdict.issuer != _ISSUER:
        return _break(pid, "verdict resource/issuer wrong")
    if verdict.scopes != frozenset({"tools:call", "tools:read"}):
        return _break(pid, "verdict scopes %r" % (verdict.scopes,))
    if verdict.subject != "agent-7":
        return _break(pid, "verdict subject %r" % (verdict.subject,))
    want_digest = hashlib.sha256(_TOK_VALID.encode("utf-8")).hexdigest()
    if verdict.token_digest != want_digest:
        return _break(pid, "token_digest mismatch")
    if _TOK_VALID in repr(verdict):
        return _break(pid, "verdict leaks token bytes")
    # Insufficient scope: valid token, missing required scope -> 403.
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, verify,
            expected_issuer=_ISSUER, now=_NOW,
            required_scopes=("tools:call", "admin:wipe")),
        sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE, 403)
    if err:
        return err
    status, challenge = sa.refusal_response(
        sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE, "need admin:wipe")
    if status != 403 or 'error="insufficient_scope"' not in challenge:
        return _break(pid, "scope challenge wrong: %r" % challenge[:80])
    return _held(pid, "valid token allows with audit-safe verdict; "
                      "insufficient scope refuses coded 403 "
                      "insufficient_scope")


# ---------------------------------------------------------------------------
# P7 -- verifier rejection; challenge hygiene.
# ---------------------------------------------------------------------------

@probe("P7-verifier-rejection-challenge-hygiene")
def _p7():
    pid = "P7-verifier-rejection-challenge-hygiene"
    def raising(_token):
        raise ValueError("bad signature")
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, raising,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_TOKEN_INVALID, 401)
    if err:
        return err
    def nondict(_token):
        return ["not", "a", "dict"]
    err = _expect_code(
        pid,
        lambda: sa.validate_bearer_request(
            _SERVER_B, "Bearer " + _TOK_VALID, nondict,
            expected_issuer=_ISSUER, now=_NOW),
        sa.MCP_SERVER_AUTH_TOKEN_INVALID, 401)
    if err:
        return err
    # Header-injection characters are stripped from the challenge.
    _status, challenge = sa.refusal_response(
        sa.MCP_SERVER_AUTH_TOKEN_INVALID,
        'evil"\r\nX-Injected: 1')
    if "\r" in challenge or "\n" in challenge:
        return _break(pid, "challenge carries CR/LF: %r" % challenge[:80])
    inner = challenge.split('error_description="')[1]
    if '"' in inner[: inner.rfind('"')]:
        return _break(pid, "challenge detail carries quotes")
    if _TOK_VALID in challenge:
        return _break(pid, "challenge leaks token bytes")
    return _held(pid, "raising/non-dict verifier refuses coded "
                      "mcp-server-auth-token-invalid; challenge strips "
                      "injection characters, never leaks the token")


# ---------------------------------------------------------------------------
# P8 -- pin + footer.
# ---------------------------------------------------------------------------

@probe("P8-pin-2135-footer-f430-f431")
def _p8():
    pid = "P8-pin-2135-footer-f430-f431"
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    if len(lits) != TAXONOMY_PIN or len(set(lits)) != TAXONOMY_PIN \
            or lits != sorted(lits):
        return _break(pid, "taxonomy %d/%d/sorted=%s want %d"
                      % (len(lits), len(set(lits)), lits == sorted(lits),
                         TAXONOMY_PIN))
    new_codes = [c for c in sa.CODES]
    missing = [c for c in new_codes if "'%s'" % c not in src]
    if missing:
        return _break(pid, "codes not centrally registered: %r" % missing[:3])
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        foot = fh.read()
    # The current footer is the LAST match (the file carries the full
    # history of footer lines).
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]*)\.\*\*", foot)
    if not ms:
        return _break(pid, "footer not parseable")
    next_free, open_now = ms[-1]
    if next_free != FOOTER_NEXT or FOOTER_OPEN not in open_now \
            or "F419" in open_now:
        return _break(pid, "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    if "## F419" not in foot or "Status: CLOSED" not in foot.split("## F419")[1][:2500]:
        return _break(pid, "F419 entry not CLOSED")
    return _held(pid, "taxonomy 2135/2135/0 sorted unique; 11 codes "
                      "registered; footer open F421 / next F422; F419 CLOSED")


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(battery, timeout):
    d = _tmpd("w334mcpsrv-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the MCP-OAuth-adjacent battery
    w245_mcp_oauth_binding_probes.py as a child with GOV_SKIP_GREEN=1
    (fresh TMPDIR). w245 tests gov/mcp_oauth_binding, the module this
    lane's server guard wires its audience check through; it carries
    no footer probe, so this lane's intentional footer change
    (F419 filed+closed) cannot stale it. Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output("w245_mcp_oauth_binding_probes.py",
                                timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "w245: %s" % exc)
        return
    # w245 format: "<name> BREAK <note>" per probe line (no brackets).
    bad = [ln.strip() for ln in out.splitlines()
           if re.search(r"^\S+\s+BREAK(\s|$)", ln)]
    if bad:
        _record("green-check", "BREAK",
                "w245 non-green: %s" % bad[:4])
    elif "summary:" in out and "0 GAP" not in out:
        _record("green-check", "BREAK",
                "w245 summary not fully HELD")
    else:
        _record("green-check", "HELD", "w245_mcp_oauth_binding green")


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
    print("w334_mcpsrvauthz battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
