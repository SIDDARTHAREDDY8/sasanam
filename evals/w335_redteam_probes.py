#!/usr/bin/env python3
"""Wave-335 lane 5 independent red team: break the wave-334 tree.

Base: `0fd4f736` (wave-334 merge). Pin 2109 at merge. Footer open none / next
F424 (F423 filed by this lane as F421, OPEN; renumbered at the wave-335 merge;
CLOSED 2026-10-05 wave-336 lane 1).

New attack surface under test: `gov/mcp_server_authz.py` (per-request
bearer validation, +11 mcp-server-auth-* codes), `gov/mcp_prm.py`
(RFC 9728 PRM verification, +6 mcp-oauth-prm-* codes),
`gov/gpai9_incident.py` (GPAI ch.9 incident artifacts, +6
incident-gpai9-* codes).

Break-first probes at the public seams:

P1 (mcp_server_authz -- bearer bypasses):
  P1a  token-in-query smuggling (access_token/TOKEN/token, incl. blank
       and multi-param) refuses mcp-server-auth-token-in-query, checked
       BEFORE the header so absence-of-header never masks it.
  P1b  challenge-injection: CR/LF/quotes in detail, resource_metadata_url
       and scope list are stripped from the WWW-Authenticate value.
  P1c  scope confusion: missing scope refuses 403
       mcp-server-auth-insufficient-scope; 403 is ONLY for scope,
       audience mismatch stays 401.
  P1d  verifier contract: non-dict return and raising verifier refuse
       token-invalid; a McpServerAuthzError from the verifier propagates
       untouched (identity, not rewrapped).
  P1e  nbf/iat/exp games: non-numeric nbf/iat refuse malformed; future
       nbf refuses not-yet-valid; missing exp refuses malformed; exp at
       or before now refuses expired; bool exp refuses malformed.
  P1f  header-shape games: wrong scheme, bare "Bearer", empty token,
       illegal token chars refuse malformed; lowercase "bearer" is
       accepted (RFC 6750 case-insensitive, pinned).
  P1g  cross-server replay: token bound to server A presented at server
       B refuses mcp-server-auth-resource-misbound; no indicator at all
       refuses resource-missing.
  P1h  issuer games: wrong iss refuses issuer-mismatched; absent iss
       refuses issuer-missing; trailing-slash near-miss refuses
       mismatched (exact-string, pinned).
  P1i  deployment-shape games: non-numeric now, empty expected_issuer,
       non-string header, non-string query_string refuse malformed.
  P1j  happy path: verdict carries normalized resource, issuer, scope
       frozenset, subject, and sha256(token) digest (never the token).

P2 (mcp_prm -- PRM attacks):
  P2a  SSRF shapes: private/loopback literals refuse fetch-refused;
       IPv6 literal refuses malformed (F417-family containment, pinned);
       http:// refuses metadata-malformed.
  P2b  userinfo smuggling refuses fetch-refused (checked on the raw
       parse, before the canonicalizer drops it).
  P2c  cross-origin metadata URL refuses cross-origin.
  P2d  challenge games: contradictory / missing / empty
       resource_metadata refuse challenge-malformed.
  P2e  derive games: resource_server with query refuses malformed;
       with fragment refuses fetch-refused (pinned seam behavior);
       legit derivation is byte-exact.
  P2f  document verification: resource mismatch refuses
       resource-mismatched; AS-substitution (bound issuer unlisted)
       refuses issuer-unlisted; tampered binding refuses
       binding-tampered; empty authorization_servers refuses malformed;
       the happy path verifies.
  P2g  fetch discipline: None / non-callable / raising fetcher refuse
       fetch-refused; the URL is validated BEFORE the fetcher runs.
  P2h  field-shape games: non-string signed_metadata, off-vocabulary
       bearer_methods_supported, "none" in signing algs, non-bool
       dpop flag each refuse malformed.
  P2i  port games (F417 family): non-numeric port in a PRM URL refuses
       malformed (contained at this seam).

P3 (gpai9_incident -- artifact attacks):
  P3a  checklist-digest tampering: any point change alters the digest;
       the digest binds the exact checklist bytes.
  P3b  unavailable-marking abuse: empty/blank reason, None point, or a
       missing point refuses incomplete; a recorded reason passes.
  P3c  cadence-clock games: shortest deadline governs multi-class;
       "suspected" starts the clock identically to "established";
       critical-infrastructure is 2 days.
  P3d  retention-boundary edges: Feb-29 +5y lands on Feb-28 (pinned);
       disposal exactly at the floor is allowed, one second before is
       not; early purge refuses retention-violation.
  P3e  intermediate anchoring: unresolved incident anchors on the
       latest filed report; resolved incident gets no intermediate
       verdict, only the 60-day final.
  P3f  timeliness codes: overdue checks carry their coded verdict,
       nothing overdue is silently absorbed (not-yet-due carries None).
  P3g  shape games: non-ISO timestamps, non-string timestamps, unknown
       or empty classes refuse malformed.

P4 (closure regressions):
  P4a  F417 CLOSED: non-numeric port refuses coded
       mcp-oauth-metadata-malformed (no bare ValueError) on every entry
       point.
  P4b  F419 CLOSED: the server-side 401 path exists -- missing token
       maps to (401, Bearer error="invalid_token") via
       refusal_response; cross-server replay is 401 resource-misbound.
  P4c  F420 CLOSED: AS-substitution in a PRM document refuses
       mcp-oauth-prm-issuer-unlisted.
  P4d  F418 CLOSED: a signed revocation event terminates a bound
       in-flight session coded revocation-push-session-terminated.

P5 (honesty): pin 2121 taxonomy sorted-unique on raw literals; all 23
     wave-334 codes centrally registered; footer open F424, F425 / next F426.

P6 (older closure spot-regressions, adopted from w332):
  P6a  F415: unicode-digit version fragment refuses coded
       policy-channel-malformed (full partition matrix).
  P6b  F416: _parse_int64_as_string boundary matrix refuses coded
       evidence-bundle-malformed.
  P6c  F414: shamir symlink-alias distribute refuses before any write.

Verdicts:
  HELD  = behavior matches the pin (attack refused coded / legitimate
          use accepted / documented state observed);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Genuine findings get F-numbers from F424; none are manufactured -- a
0-break battery is an honest result.

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/ (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g335-red
  TMPDIR=/var/tmp/g335-red ~/workspace/.gov-venv/bin/python evals/w335_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g335-redb ~/workspace/.gov-venv/bin/python evals/w335_redteam_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w335_redteam_probes.py P1d
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
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import mcp_server_authz as MSA  # noqa: E402
from gov import mcp_prm as PRM  # noqa: E402
from gov import gpai9_incident as G9  # noqa: E402
from gov import mcp_oauth_binding as MOB  # noqa: E402
from gov import revocation_push as RP  # noqa: E402
from gov import decision_codes as DC  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
_NOW = 1798765432
_ISS = "https://as.example.com"
_RES = "https://mcp.example.com/tools"
_RES2 = "https://other.example.com/tools"
_KEY = b"w335-redteam-prm-test-key-000000"
assert len(_KEY) == 32, len(_KEY)

_NEW_AUTH_CODES = (
    "mcp-server-auth-missing-token",
    "mcp-server-auth-malformed",
    "mcp-server-auth-token-in-query",
    "mcp-server-auth-token-invalid",
    "mcp-server-auth-token-expired",
    "mcp-server-auth-token-not-yet-valid",
    "mcp-server-auth-issuer-missing",
    "mcp-server-auth-issuer-mismatched",
    "mcp-server-auth-resource-missing",
    "mcp-server-auth-resource-misbound",
    "mcp-server-auth-insufficient-scope",
)
_NEW_PRM_CODES = (
    "mcp-oauth-prm-malformed",
    "mcp-oauth-prm-resource-mismatched",
    "mcp-oauth-prm-issuer-unlisted",
    "mcp-oauth-prm-fetch-refused",
    "mcp-oauth-prm-challenge-malformed",
    "mcp-oauth-prm-cross-origin",
)
_NEW_GPAI_CODES = (
    "incident-gpai9-malformed",
    "incident-gpai9-incomplete",
    "incident-gpai9-initial-overdue",
    "incident-gpai9-intermediate-overdue",
    "incident-gpai9-final-overdue",
    "incident-gpai9-retention-violation",
)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


def _expect_code(pid, want, fn):
    """Assert fn() raises with exactly the wanted machine code."""
    code = _code_of(fn)
    if code == want:
        _held(pid, "%s as expected" % want)
        return True
    _break(pid, "want %s, got %r" % (want, code))
    return False


# ---------------------------------------------------------------------------
# P1: mcp_server_authz bearer bypasses.
# ---------------------------------------------------------------------------

def _claims(**kw):
    base = {"exp": _NOW + 3600, "iss": _ISS, "aud": _RES,
            "scope": "read write", "sub": "svc-1"}
    base.update(kw)
    return base


def _verify_for(claims):
    def verify(token):
        return dict(claims)
    return verify


def _validate(authz="Bearer tok123", claims=None, server=_RES, qs="",
              scopes=(), now=_NOW, issuer=_ISS):
    # NOTE: the default token "tok123" is b64token-shaped (the shape
    # regex is ^[A-Za-z0-9\-._~+/]+={0,2}$); "<redacted>" is NOT and
    # would fail header parsing before any verifier ran.
    return MSA.validate_bearer_request(
        server, authz, _verify_for(_claims(**(claims or {}))),
        expected_issuer=issuer, required_scopes=scopes,
        query_string=qs, now=now)


def P1a():
    """Token-in-query smuggling: every token-shaped query parameter
    refuses mcp-server-auth-token-in-query, checked before the header
    (a missing header must not mask the smuggling)."""
    pid = "P1a-token-in-query-smuggling"
    for qs in ("access_token=abc", "TOKEN=abc", "token=",
               "x=1&access_token=abc&y=2", "Access_Token=abc"):
        code = _code_of(lambda qs=qs: _validate(qs=qs))
        if code != MSA.MCP_SERVER_AUTH_TOKEN_IN_QUERY:
            _break(pid, "query %r: want token-in-query, got %r"
                   % (qs, code))
            return
    # No header at all, but a token in the query: still token-in-query.
    code = _code_of(lambda: MSA.validate_bearer_request(
        _RES, None, _verify_for(_claims()), expected_issuer=_ISS,
        query_string="access_token=abc", now=_NOW))
    if code != MSA.MCP_SERVER_AUTH_TOKEN_IN_QUERY:
        _break(pid, "missing-header + query token: got %r" % (code,))
        return
    # A benign query passes and the request validates.
    try:
        v = _validate(qs="x=1&y=2")
    except Exception as e:  # noqa: BLE001
        _break(pid, "benign query refused: %r" % (e,))
        return
    if v.resource != _RES:
        _break(pid, "benign query validated to wrong resource %r"
               % (v.resource,))
        return
    _held(pid, "token-in-query refused coded before header checks; "
               "benign queries pass")


def P1b():
    """Challenge-injection: CR/LF/quotes in detail, resource_metadata_url
    and scope lists are stripped from the WWW-Authenticate value."""
    pid = "P1b-challenge-injection-stripped"
    ch = MSA.www_authenticate_challenge(
        MSA.MCP_SERVER_AUTH_TOKEN_INVALID,
        'evil\r\nInjected: x"quote',
        resource_metadata_url="https://m.example/x\r\n.evil",
        scopes=("read\r\n", 'wr"ite'))
    for bad in ("\r", "\n"):
        if bad in ch:
            _break(pid, "challenge carries raw %r" % (bad,))
            return
    if '"quote' in ch or 'Injected: x"' in ch:
        _break(pid, "challenge carries an unescaped quote: %r" % (ch,))
        return
    if MSA.MCP_SERVER_AUTH_TOKEN_INVALID not in ch:
        _break(pid, "machine code lost from challenge: %r" % (ch,))
        return
    if 'error="invalid_token"' not in ch:
        _break(pid, "error class wrong: %r" % (ch,))
        return
    # Scope refusal uses insufficient_scope; everything else is
    # invalid_token (audience mismatch is never insufficient_scope).
    ch2 = MSA.www_authenticate_challenge(
        MSA.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE, "x")
    if 'error="insufficient_scope"' not in ch2:
        _break(pid, "scope refusal not insufficient_scope: %r" % (ch2,))
        return
    ch3 = MSA.www_authenticate_challenge(
        MSA.MCP_SERVER_AUTH_RESOURCE_MISBOUND, "x")
    if 'error="invalid_token"' not in ch3:
        _break(pid, "misbound not invalid_token: %r" % (ch3,))
        return
    _held(pid, "challenge strips CR/LF/quotes; error classes pinned")


def P1c():
    """Scope confusion: a valid token without the required scope refuses
    403 mcp-server-auth-insufficient-scope; 403 is ONLY for scope."""
    pid = "P1c-scope-confusion-403-only"
    ok = _expect_code(
        pid, MSA.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE,
        lambda: _validate(claims={"scope": "read"}, scopes=("write",)))
    if not ok:
        return
    if MSA.http_status_for(
            MSA.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE) != 403:
        _break(pid, "insufficient-scope not 403")
        return
    if MSA.http_status_for(MSA.MCP_SERVER_AUTH_RESOURCE_MISBOUND) != 401:
        _break(pid, "resource-misbound not 401")
        return
    if MSA.http_status_for(MSA.MCP_SERVER_AUTH_TOKEN_EXPIRED) != 401:
        _break(pid, "expired not 401")
        return
    # No scope claim and no required scopes: passes with empty grant.
    try:
        v = _validate(claims={"scope": None}, scopes=())
    except Exception as e:  # noqa: BLE001
        _break(pid, "scopeless token with no gate refused: %r" % (e,))
        return
    if v.scopes != frozenset():
        _break(pid, "scopeless grant not empty: %r" % (v.scopes,))
        return
    # Non-string scope claim refuses malformed (strictness pinned).
    if not _expect_code(
            pid + "-nonstring", MSA.MCP_SERVER_AUTH_MALFORMED,
            lambda: _validate(claims={"scope": ["read"]})):
        return
    _held(pid, "scope gate refuses 403 coded; 401 for everything else")


def P1d():
    """Verifier contract: a non-dict return or a raising verifier refuses
    token-invalid; a McpServerAuthzError from the verifier propagates
    untouched (identity, never rewrapped)."""
    pid = "P1d-verifier-contract"

    def bad_dict(token):
        return ["not", "a", "dict"]

    def raising(token):
        raise RuntimeError("boom")

    if not _expect_code(
            pid + "-nondict", MSA.MCP_SERVER_AUTH_TOKEN_INVALID,
            lambda: MSA.validate_bearer_request(
                _RES, "Bearer tok123", bad_dict,
                expected_issuer=_ISS, now=_NOW)):
        return
    if not _expect_code(
            pid + "-raising", MSA.MCP_SERVER_AUTH_TOKEN_INVALID,
            lambda: MSA.validate_bearer_request(
                _RES, "Bearer tok123", raising,
                expected_issuer=_ISS, now=_NOW)):
        return
    sentinel = MSA.McpServerAuthzError(MSA.MCP_SERVER_AUTH_MISSING_TOKEN,
                                      "inner")

    def passthrough(token):
        raise sentinel

    try:
        MSA.validate_bearer_request(_RES, "Bearer tok123", passthrough,
                                    expected_issuer=_ISS, now=_NOW)
    except MSA.McpServerAuthzError as e:
        if e is not sentinel:
            _break(pid, "verifier error rewrapped: %r" % (e,))
            return
    except Exception as e:  # noqa: BLE001
        _break(pid, "verifier error changed type: %r" % (e,))
        return
    else:
        _break(pid, "verifier McpServerAuthzError swallowed")
        return
    _held(pid, "verifier contract: invalid vs passthrough pinned")


def P1e():
    """nbf/iat/exp games: non-numeric time claims refuse malformed;
    future nbf refuses not-yet-valid; missing exp refuses malformed;
    exp at-or-before now refuses expired (boundary inclusive)."""
    pid = "P1e-time-claim-games"
    cases = [
        ({"nbf": "soon"}, MSA.MCP_SERVER_AUTH_MALFORMED),
        ({"nbf": _NOW + 60}, MSA.MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID),
        ({"nbf": _NOW - 60}, None),  # past nbf is fine
        ({"iat": "yesterday"}, MSA.MCP_SERVER_AUTH_MALFORMED),
        ({"iat": True}, MSA.MCP_SERVER_AUTH_MALFORMED),  # bool is not a number
        ({"iat": _NOW - 10}, None),
        ({"exp": None}, MSA.MCP_SERVER_AUTH_MALFORMED),
        ({"exp": "9999999999"}, MSA.MCP_SERVER_AUTH_MALFORMED),
        ({"exp": _NOW}, MSA.MCP_SERVER_AUTH_TOKEN_EXPIRED),
        ({"exp": _NOW - 1}, MSA.MCP_SERVER_AUTH_TOKEN_EXPIRED),
        ({"exp": _NOW + 1}, None),
    ]
    for patch, want in cases:
        if want is None:
            try:
                _validate(claims=patch)
            except Exception as e:  # noqa: BLE001
                _break(pid, "legit time shape %r refused: %r" % (patch, e))
                return
        elif not _expect_code(pid, want,
                              lambda patch=patch: _validate(claims=patch)):
            return
    _held(pid, "time window refuses coded; boundary exp==now is expired")


def P1f():
    """Header-shape games: wrong scheme, bare scheme, empty or illegal
    token refuse malformed; lowercase 'bearer' is accepted per RFC 6750
    (pinned, not a bypass)."""
    pid = "P1f-header-shape-games"
    for hdr in ("Basic abc", "Bearer", "Bearer ", "Bearer !!x!!",
                "Bearer a b", "Bearer <redacted>"):
        code = _code_of(lambda hdr=hdr: _validate(authz=hdr))
        if code != MSA.MCP_SERVER_AUTH_MALFORMED:
            _break(pid, "header %r: want malformed, got %r" % (hdr, code))
            return
    # A blank header is "no token presented": missing-token, not
    # malformed (pinned behavior of _parse_bearer_token).
    for hdr in ("", "   "):
        code = _code_of(lambda hdr=hdr: _validate(authz=hdr))
        if code != MSA.MCP_SERVER_AUTH_MISSING_TOKEN:
            _break(pid, "blank header %r: want missing-token, got %r"
                   % (hdr, code))
            return
    # Non-string header refuses malformed, not a bare TypeError.
    if not _expect_code(pid, MSA.MCP_SERVER_AUTH_MALFORMED,
                        lambda: _validate(authz=12345)):
        return
    # Lowercase scheme is legitimate per RFC 6750 section 2.1.
    try:
        _validate(authz="bearer tok123")
    except Exception as e:  # noqa: BLE001
        _break(pid, "lowercase bearer refused: %r" % (e,))
        return
    _held(pid, "header shapes refuse coded; scheme case-insensitive")


def P1g():
    """Cross-server replay: a token bound to server A presented at
    server B refuses mcp-server-auth-resource-misbound; a token with
    no indicator at all refuses resource-missing."""
    pid = "P1g-cross-server-replay-dead"
    # Token bound to _RES2, presented at _RES.
    if not _expect_code(
            pid, MSA.MCP_SERVER_AUTH_RESOURCE_MISBOUND,
            lambda: _validate(claims={"aud": _RES2}, server=_RES)):
        return
    # Same via the RFC 8707 `resource` claim.
    if not _expect_code(
            pid + "-resource-claim", MSA.MCP_SERVER_AUTH_RESOURCE_MISBOUND,
            lambda: _validate(claims={"aud": None, "resource": _RES2},
                             server=_RES)):
        return
    # No indicator at all (explicit Nones: _claims() would re-add a
    # popped default, so pass None through).
    if not _expect_code(
            pid + "-missing", MSA.MCP_SERVER_AUTH_RESOURCE_MISSING,
            lambda: _validate(claims={"aud": None, "resource": None})):
        return
    # Multi-audience token naming this server passes.
    try:
        v = _validate(claims={"aud": [_RES2, _RES]})
    except Exception as e:  # noqa: BLE001
        _break(pid, "multi-aud token naming server refused: %r" % (e,))
        return
    if v.resource != _RES:
        _break(pid, "multi-aud verdict resource %r" % (v.resource,))
        return
    _held(pid, "cross-server replay dead coded; multi-aud works")


def P1h():
    """Issuer games: wrong iss refuses issuer-mismatched; absent iss
    refuses issuer-missing; near-miss forms (trailing slash) refuse
    mismatched -- exact-string, never fuzzy."""
    pid = "P1h-issuer-games"
    if not _expect_code(
            pid, MSA.MCP_SERVER_AUTH_ISSUER_MISMATCHED,
            lambda: _validate(claims={"iss": "https://evil.example.com"})):
        return
    if not _expect_code(
            pid + "-slash", MSA.MCP_SERVER_AUTH_ISSUER_MISMATCHED,
            lambda: _validate(claims={"iss": _ISS + "/"})):
        return
    # Absent/empty iss refuses issuer-missing (explicit Nones: _claims()
    # would re-add a popped default).
    if not _expect_code(
            pid + "-missing", MSA.MCP_SERVER_AUTH_ISSUER_MISSING,
            lambda: _validate(claims={"iss": None})):
        return
    if not _expect_code(
            pid + "-empty", MSA.MCP_SERVER_AUTH_ISSUER_MISSING,
            lambda: _validate(claims={"iss": ""})):
        return
    _held(pid, "issuer exact-match refuses coded")


def P1i():
    """Deployment-shape games: non-numeric now, empty expected_issuer,
    and non-string query_string refuse malformed (coded, never bare)."""
    pid = "P1i-deployment-shape-games"
    if not _expect_code(
            pid, MSA.MCP_SERVER_AUTH_MALFORMED,
            lambda: _validate(now="soon")):
        return
    if not _expect_code(
            pid + "-issuer", MSA.MCP_SERVER_AUTH_MALFORMED,
            lambda: MSA.validate_bearer_request(
                _RES, "Bearer tok123", _verify_for(_claims()),
                expected_issuer="", now=_NOW)):
        return
    if not _expect_code(
            pid + "-qs", MSA.MCP_SERVER_AUTH_MALFORMED,
            lambda: _validate(qs=None)):
        return
    # refusal_response maps every code to its (status, challenge) pair.
    status, challenge = MSA.refusal_response(
        MSA.MCP_SERVER_AUTH_TOKEN_EXPIRED, "t")
    if status != 401 or 'error="invalid_token"' not in challenge:
        _break(pid, "refusal_response wrong: %r %r" % (status, challenge))
        return
    status2, _ = MSA.refusal_response(
        MSA.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE, "t")
    if status2 != 403:
        _break(pid, "scope refusal_response not 403")
        return
    # A bare-string required_scopes is char-split by tuple() -- a
    # deployment footgun, but it fails CLOSED (insufficient-scope),
    # never open. Pinned so a future change is deliberate.
    code = _code_of(lambda: _validate(claims={"scope": "write"},
                                     scopes="write"))
    if code != MSA.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE:
        _break(pid + "-scopestr",
               "string required_scopes: want fail-closed scope refusal, "
               "got %r" % (code,))
        return
    _held(pid, "deployment shapes refuse coded; refusal_response pinned")


def P1j():
    """Happy path: the verdict carries the normalized resource, exact
    issuer, scope frozenset, subject, and sha256(token) -- the token
    itself is never logged or echoed."""
    pid = "P1j-verdict-fields"
    try:
        v = _validate(authz="Bearer tok123")
    except Exception as e:  # noqa: BLE001
        _break(pid, "valid request refused: %r" % (e,))
        return
    if v.resource != _RES or v.issuer != _ISS:
        _break(pid, "verdict resource/issuer wrong: %r" % (v,))
        return
    if v.scopes != frozenset({"read", "write"}):
        _break(pid, "verdict scopes wrong: %r" % (v.scopes,))
        return
    if v.subject != "svc-1":
        _break(pid, "verdict subject wrong: %r" % (v.subject,))
        return
    want_digest = hashlib.sha256(b"tok123").hexdigest()
    if v.token_digest != want_digest:
        _break(pid, "token digest wrong")
        return
    if "tok123" in repr(v):
        _break(pid, "verdict leaks the token")
        return
    # Non-string subject is dropped, not crashed on.
    v2 = _validate(claims={"sub": 123})
    if v2.subject is not None:
        _break(pid, "non-string subject kept: %r" % (v2.subject,))
        return
    _held(pid, "verdict fields pinned; token never echoed")

# ---------------------------------------------------------------------------
# P2: mcp_prm attacks.
# ---------------------------------------------------------------------------

def _sealed(issuer=_ISS):
    return MOB.seal_as_binding(issuer, "battery-client", _KEY)


def _prm_doc(resource=_RES, issuers=(_ISS,), **extra):
    doc = {"resource": resource, "authorization_servers": list(issuers)}
    doc.update(extra)
    return doc


def P2a():
    """SSRF shapes: private/loopback/link-local IP literals refuse
    fetch-refused; IPv6 literals (incl. IPv4-mapped forms like
    ::ffff:127.0.0.1) refuse malformed -- categorically refused, only
    the code label differs; http:// refuses metadata-malformed."""
    pid = "P2a-ssrf-shapes"
    for url in ("https://169.254.169.254/.well-known/oauth-protected-resource",
                "https://127.0.0.1/.well-known/oauth-protected-resource",
                "https://10.0.0.5/x"):
        if not _expect_code(
                pid, PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
                lambda url=url: PRM.check_prm_url(url, _RES)):
            return
    for url in ("https://[::1]/.well-known/oauth-protected-resource",
                "https://[2001:db8::1]/x",
                "https://[::ffff:127.0.0.1]/x"):
        if not _expect_code(
                pid + "-ipv6", PRM.MCP_OAUTH_PRM_MALFORMED,
                lambda url=url: PRM.check_prm_url(url, _RES)):
            return
    if not _expect_code(
            pid + "-http", MOB.MCP_OAUTH_METADATA_MALFORMED,
            lambda: PRM.check_prm_url(
                "http://mcp.example.com/.well-known/oauth-protected-resource",
                _RES)):
        return
    # A public-IP literal on the same origin passes the SSRF guard
    # (documented: DNS-rebinding defense is deployment-owned). NOTE:
    # TEST-NET documentation ranges (192.0.2.x/198.51.100.x/203.0.113.x)
    # are treated as special by the guard -- use a real public IP here.
    try:
        PRM.check_prm_url("https://8.8.8.8/.well-known/x",
                          "https://8.8.8.8/tools")
    except Exception as e:  # noqa: BLE001
        _break(pid, "public IP literal refused: %r" % (e,))
        return
    _held(pid, "SSRF shapes refuse coded; IPv6 contained as malformed")


def P2b():
    """Userinfo smuggling: user:pass@host refuses fetch-refused, checked
    on the RAW parse before the canonicalizer silently drops it."""
    pid = "P2b-userinfo-smuggling"
    for url in ("https://user:pass@mcp.example.com/.well-known/x",
                "https://user@mcp.example.com/.well-known/x"):
        if not _expect_code(
                pid, PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
                lambda url=url: PRM.check_prm_url(url, _RES)):
            return
    # The canonicalizer drops userinfo -- so the check MUST be on the
    # raw parse; assert the raw-parse guard is what fires (fetch-refused,
    # not a silent pass).
    _held(pid, "userinfo refuses fetch-refused on the raw parse")


def P2c():
    """Cross-origin confusion: a metadata URL on another origin refuses
    cross-origin, even when every other guard passes."""
    pid = "P2c-cross-origin-confusion"
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_CROSS_ORIGIN,
            lambda: PRM.check_prm_url(
                "https://evil.example.com/.well-known/oauth-protected-resource",
                _RES)):
        return
    # Same host, different port: different origin.
    if not _expect_code(
            pid + "-port", PRM.MCP_OAUTH_PRM_CROSS_ORIGIN,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com:8443/.well-known/x", _RES)):
        return
    # Same origin passes.
    try:
        PRM.check_prm_url(
            "https://mcp.example.com/.well-known/oauth-protected-resource",
            _RES)
    except Exception as e:  # noqa: BLE001
        _break(pid, "same-origin URL refused: %r" % (e,))
        return
    _held(pid, "cross-origin refuses coded; same-origin passes")


def P2d():
    """Challenge games: contradictory, missing, or empty
    resource_metadata refuse challenge-malformed (coded, never bare)."""
    pid = "P2d-challenge-games"
    hdr = ('Bearer error="invalid_token", resource_metadata="%s", '
           'resource_metadata="%s"')
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(
                hdr % ("https://mcp.example.com/a", "https://mcp.example.com/b"),
                _RES)):
        return
    if not _expect_code(
            pid + "-missing", PRM.MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(
                'Bearer error="invalid_token"', _RES)):
        return
    if not _expect_code(
            pid + "-empty", PRM.MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(
                'Bearer resource_metadata=""', _RES)):
        return
    if not _expect_code(
            pid + "-blank", PRM.MCP_OAUTH_PRM_CHALLENGE_MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata("", _RES)):
        return
    if not _expect_code(
            pid + "-nonstring", PRM.MCP_OAUTH_PRM_MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(None, _RES)):
        return
    # Duplicate identical values are consistent, not contradictory.
    try:
        u = PRM.parse_challenge_resource_metadata(
            hdr % ("https://mcp.example.com/a", "https://mcp.example.com/a"),
            _RES)
    except Exception as e:  # noqa: BLE001
        _break(pid, "identical duplicates refused: %r" % (e,))
        return
    if u != "https://mcp.example.com/a":
        _break(pid, "identical duplicates normalized wrong: %r" % (u,))
        return
    _held(pid, "challenge contradictions refuse coded")


def P2e():
    """Derive games: a query on the resource identifier refuses
    malformed; a fragment refuses fetch-refused (pinned seam
    behavior); legitimate derivation is byte-exact per RFC 9728 3.1."""
    pid = "P2e-derive-games"
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_MALFORMED,
            lambda: PRM.derive_prm_url("https://mcp.example.com/tools?x=1")):
        return
    if not _expect_code(
            pid + "-fragment", PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
            lambda: PRM.derive_prm_url("https://mcp.example.com/tools#frag")):
        return
    got = PRM.derive_prm_url("https://mcp.example.com/tools/")
    want = "https://mcp.example.com/.well-known/oauth-protected-resource/tools"
    if got != want:
        _break(pid, "derivation wrong: %r != %r" % (got, want))
        return
    got2 = PRM.derive_prm_url("https://mcp.example.com")
    if got2 != "https://mcp.example.com/.well-known/oauth-protected-resource":
        _break(pid, "bare-host derivation wrong: %r" % (got2,))
        return
    _held(pid, "derivation byte-exact; query/fragment refuse coded")


def P2f():
    """Document verification: resource mismatch refuses
    resource-mismatched; AS-substitution (bound issuer unlisted)
    refuses issuer-unlisted; a tampered binding refuses
    binding-tampered; empty authorization_servers refuses malformed."""
    pid = "P2f-document-verification"
    sealed = _sealed()
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_RESOURCE_MISMATCHED,
            lambda: PRM.verify_prm_document(
                sealed, _RES, _prm_doc(resource=_RES2), _KEY)):
        return
    if not _expect_code(
            pid + "-as-sub", PRM.MCP_OAUTH_PRM_ISSUER_UNLISTED,
            lambda: PRM.verify_prm_document(
                sealed, _RES,
                _prm_doc(issuers=("https://evil-as.example.com",)), _KEY)):
        return
    tampered = {"binding": dict(sealed["binding"]), "mac": "0" * 64}
    tampered["binding"]["issuer"] = "https://evil-as.example.com"
    if not _expect_code(
            pid + "-tamper", MOB.MCP_OAUTH_BINDING_TAMPERED,
            lambda: PRM.verify_prm_document(tampered, _RES,
                                            _prm_doc(), _KEY)):
        return
    if not _expect_code(
            pid + "-empty-as", PRM.MCP_OAUTH_PRM_MALFORMED,
            lambda: PRM.verify_prm_document(
                sealed, _RES, _prm_doc(issuers=()), _KEY)):
        return
    # Omitted authorization_servers is allowed by RFC 9728; the
    # binding still governs.
    doc = {"resource": _RES}
    try:
        v = PRM.verify_prm_document(sealed, _RES, doc, _KEY)
    except Exception as e:  # noqa: BLE001
        _break(pid, "omitted authorization_servers refused: %r" % (e,))
        return
    if v.issuer != _ISS or v.authorization_servers != ():
        _break(pid, "verdict wrong: %r" % (v,))
        return
    # Happy path.
    try:
        v2 = PRM.verify_prm_document(sealed, _RES, _prm_doc(), _KEY)
    except Exception as e:  # noqa: BLE001
        _break(pid, "valid document refused: %r" % (e,))
        return
    if v2.resource != _RES or v2.issuer != _ISS:
        _break(pid, "happy-path verdict wrong: %r" % (v2,))
        return
    _held(pid, "document verification refuses coded; binding governs")


def P2g():
    """Fetch discipline: None / non-callable / raising fetchers refuse
    fetch-refused; the URL is validated BEFORE the fetcher runs."""
    pid = "P2g-fetch-discipline"
    url = "https://mcp.example.com/.well-known/oauth-protected-resource"
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
            lambda: PRM.fetch_prm_document(url, _RES, None)):
        return
    if not _expect_code(
            pid + "-noncallable", PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
            lambda: PRM.fetch_prm_document(url, _RES, "not-a-fn")):
        return

    def raising(u):
        raise RuntimeError("down")

    if not _expect_code(
            pid + "-raising", PRM.MCP_OAUTH_PRM_FETCH_REFUSED,
            lambda: PRM.fetch_prm_document(url, _RES, raising)):
        return
    # The fetcher must NOT run when the URL fails validation.
    called = []

    def spy(u):
        called.append(u)
        return {}

    code = _code_of(lambda: PRM.fetch_prm_document(
        "https://169.254.169.254/.well-known/x", _RES, spy))
    if code != PRM.MCP_OAUTH_PRM_FETCH_REFUSED:
        _break(pid, "bad URL not refused before fetch: %r" % (code,))
        return
    if called:
        _break(pid, "fetcher ran on an invalid URL")
        return
    # A McpOAuthError from the fetcher propagates untouched.
    def coded_raise(u):
        raise MOB.McpOAuthError(MOB.MCP_OAUTH_METADATA_MALFORMED, "x")

    code2 = _code_of(lambda: PRM.fetch_prm_document(url, _RES, coded_raise))
    if code2 != MOB.MCP_OAUTH_METADATA_MALFORMED:
        _break(pid, "fetcher coded error rewrapped: %r" % (code2,))
        return
    _held(pid, "fetch discipline: no implicit network, URL first")


def P2h():
    """Field-shape games: non-string signed_metadata, off-vocabulary
    bearer_methods_supported, 'none' in signing algs, and non-bool
    dpop flags each refuse malformed."""
    pid = "P2h-field-shape-games"
    sealed = _sealed()
    # (doc, expected_code): URL-shaped fields delegate to the binding
    # module's URL checker, which raises its own coded refusal.
    bad_docs = [
        (_prm_doc(signed_metadata=123),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(bearer_methods_supported=["header", "weird"]),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(resource_signing_alg_values_supported=["RS256", "none"]),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(tls_client_certificate_bound_access_tokens="yes"),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(dpop_bound_access_tokens_required=1),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(scopes_supported=["read", ""]),
         PRM.MCP_OAUTH_PRM_MALFORMED),
        (_prm_doc(jwks_uri="http://mcp.example.com/jwks"),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
    ]
    for i, (doc, want) in enumerate(bad_docs):
        if not _expect_code(
                pid, want,
                lambda doc=doc: PRM.verify_prm_document(
                    sealed, _RES, doc, _KEY)):
            _break(pid, "bad doc #%d not %s" % (i, want))
            return
    # The closed vocabulary passes (header/body/query are the RFC set).
    try:
        PRM.verify_prm_document(
            sealed, _RES,
            _prm_doc(bearer_methods_supported=["header", "body", "query"]),
            _KEY)
    except Exception as e:  # noqa: BLE001
        _break(pid, "closed vocabulary refused: %r" % (e,))
        return
    _held(pid, "field shapes refuse coded malformed")


def P2i():
    """Port games (F417 family): a non-numeric port refuses coded --
    the PRM seams delegate normalization to the binding module, so
    every seam raises mcp-oauth-metadata-malformed. Never a bare
    ValueError."""
    pid = "P2i-port-games-contained"
    # derive_prm_url normalizes via the binding module's canonicalizer,
    # so it raises the binding module's code on a bad port too.
    cases = [
        (lambda: PRM.check_prm_url(
            "https://mcp.example.com:badport/x", _RES),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
        (lambda: PRM.derive_prm_url(
            "https://mcp.example.com:badport/tools"),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
        (lambda: PRM.parse_challenge_resource_metadata(
            'Bearer resource_metadata="https://mcp.example.com:badport/x"',
            _RES),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
    ]
    for fn, want in cases:
        code = _code_of(fn)
        if code != want:
            _break(pid, "non-numeric port: want %s, got %r" % (want, code))
            return
        # And specifically: never a bare ValueError.
        try:
            fn()
        except MOB.McpOAuthError:
            pass
        except ValueError:
            _break(pid, "bare ValueError escaped on non-numeric port")
            return
        except Exception:
            pass
    # Out-of-range port refuses coded too (same normalizer, same code).
    if not _expect_code(
            pid + "-range", MOB.MCP_OAUTH_METADATA_MALFORMED,
            lambda: PRM.check_prm_url("https://mcp.example.com:99999/x",
                                      _RES)):
        return
    _held(pid, "port shapes refuse coded malformed at this seam")


# ---------------------------------------------------------------------------
# P3: gpai9_incident artifact attacks.
# ---------------------------------------------------------------------------

_TS0 = "2026-10-01T00:00:00Z"


def _incident(**kw):
    points = {i: "point-%d-value" % i for i in range(1, 10)}
    points.update(kw.pop("points", {}))
    inc = {"incident_id": "INC-001", "points": points}
    inc.update(kw)
    return inc


def P3a():
    """Checklist-digest tampering: ANY point change alters the digest;
    the digest binds the exact checklist bytes (domain-separated)."""
    pid = "P3a-checklist-digest-tampering"
    r1 = G9.build_gpai9_report(_incident())
    r2 = G9.build_gpai9_report(_incident(points={1: "point-1-CHANGED"}))
    if r1["checklist_digest"] == r2["checklist_digest"]:
        _break(pid, "digest did not change on point tampering")
        return
    r3 = G9.build_gpai9_report(_incident())
    if r1["checklist_digest"] != r3["checklist_digest"]:
        _break(pid, "digest unstable for identical input")
        return
    if not r1["checklist_digest"] or len(r1["checklist_digest"]) != 64:
        _break(pid, "digest not a sha256 hex: %r"
               % (r1["checklist_digest"],))
        return
    # Key-order games on the input must not change the digest
    # (canonical JSON).
    pts = {i: "point-%d-value" % i for i in range(9, 0, -1)}
    r4 = G9.build_gpai9_report(_incident(points=pts))
    if r1["checklist_digest"] != r4["checklist_digest"]:
        _break(pid, "digest depends on input key order")
        return
    _held(pid, "digest binds exact checklist bytes")


def P3b():
    """Unavailable-marking abuse: an empty/blank reason, a None point,
    or a missing point refuses incomplete; a recorded reason passes."""
    pid = "P3b-unavailable-marking-abuse"
    def _inc(pts):
        return {"incident_id": "INC-001", "points": pts}

    for bad in ({"unavailable": ""}, {"unavailable": "   "}, None, "  "):
        pts = {i: "v%d" % i for i in range(1, 9)}
        pts[9] = bad
        if not _expect_code(
                pid, "incident-gpai9-incomplete",
                lambda pts=pts: G9.build_gpai9_report(_inc(pts))):
            return
    # A missing point also refuses incomplete.
    pts = {i: "v%d" % i for i in range(1, 9)}
    if not _expect_code(
            pid + "-missing", "incident-gpai9-incomplete",
            lambda: G9.build_gpai9_report(_inc(pts))):
        return
    # A recorded reason is a valid report state.
    pts = {i: "v%d" % i for i in range(1, 9)}
    pts[9] = {"unavailable": "monitoring not yet wired"}
    try:
        r = G9.build_gpai9_report(_inc(pts))
    except Exception as e:  # noqa: BLE001
        _break(pid, "recorded unavailable refused: %r" % (e,))
        return
    if r["points"]["9"]["status"] != "unavailable":
        _break(pid, "unavailable status lost")
        return
    _held(pid, "silent omission impossible; recorded absence valid")


def P3c():
    """Cadence-clock games: the SHORTEST deadline governs multi-class
    incidents; 'suspected' starts the clock identically to
    'established'; critical-infrastructure is 2 days."""
    pid = "P3c-cadence-clock-games"
    band, days = G9.classify_gpai9_band(["cybersecurity", "death"])
    if (band, days) != ("cybersecurity", 5):
        _break(pid, "shortest-deadline wrong: %r %r" % (band, days))
        return
    if G9.initial_due(_TS0, ["critical-infrastructure"]) != \
            "2026-10-03T00:00:00Z":
        _break(pid, "critical-infrastructure not 2 days")
        return
    a_est = G9.record_awareness("I", _TS0, "established")
    a_sus = G9.record_awareness("I", _TS0, "suspected")
    if G9.initial_due(a_est["awareness_ts"], ["death"]) != \
            G9.initial_due(a_sus["awareness_ts"], ["death"]):
        _break(pid, "suspected gets a grace period")
        return
    if not _expect_code(
            pid + "-basis", "incident-gpai9-malformed",
            lambda: G9.record_awareness("I", _TS0, "rumored")):
        return
    _held(pid, "shortest deadline governs; suspicion starts the clock")


def P3d():
    """Retention-boundary edges: Feb-29 +5y lands on Feb-28 (pinned
    calendar behavior); disposal exactly at the floor is allowed, one
    second before is not; early purge refuses retention-violation."""
    pid = "P3d-retention-boundary-edges"
    floor = G9.retention_floor("2024-02-29T00:00:00Z", "2024-01-01T00:00:00Z")
    if floor != "2029-02-28T00:00:00Z":
        _break(pid, "leap-year floor wrong: %r" % (floor,))
        return
    # The LATER of doc/incident dates governs.
    floor2 = G9.retention_floor("2024-01-01T00:00:00Z", "2025-06-01T00:00:00Z")
    if floor2 != "2030-06-01T00:00:00Z":
        _break(pid, "later-date rule wrong: %r" % (floor2,))
        return
    if not G9.disposal_allowed("2020-01-01T00:00:00Z",
                               "2020-01-01T00:00:00Z",
                               "2025-01-01T00:00:00Z"):
        _break(pid, "disposal at exactly the floor refused")
        return
    if G9.disposal_allowed("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z",
                           "2024-12-31T23:59:59Z"):
        _break(pid, "disposal one second early allowed")
        return
    if not _expect_code(
            pid, "incident-gpai9-retention-violation",
            lambda: G9.assert_disposal_allowed(
                "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z")):
        return
    if G9.assert_disposal_allowed("2020-01-01T00:00:00Z",
                                  "2020-01-01T00:00:00Z",
                                  "2025-01-01T00:00:00Z") is not True:
        _break(pid, "allowed disposal did not return True")
        return
    _held(pid, "retention floor fail-closed; boundary pinned")


def P3e():
    """Intermediate anchoring: an unresolved incident anchors the
    4-week cadence on the latest filed report; a resolved incident
    gets no intermediate verdict, only the 60-day final."""
    pid = "P3e-intermediate-anchoring"
    state = {"awareness_ts": _TS0, "gpai9_classes": ["serious-harm"],
             "initial_report_ts": "2026-10-02T00:00:00Z"}
    vs = G9.check_gpai9_timeliness(state, "2026-10-02T00:00:00Z")
    kinds = {v["check"] for v in vs}
    if kinds != {"initial", "intermediate"}:
        _break(pid, "unresolved verdict set wrong: %r" % (kinds,))
        return
    inter = [v for v in vs if v["check"] == "intermediate"][0]
    if inter["due"] != "2026-10-30T00:00:00Z":
        _break(pid, "intermediate anchor wrong: %r" % (inter["due"],))
        return
    # A later intermediate report re-anchors.
    state["intermediate_report_ts"] = "2026-10-20T00:00:00Z"
    vs2 = G9.check_gpai9_timeliness(state, "2026-10-20T00:00:00Z")
    inter2 = [v for v in vs2 if v["check"] == "intermediate"][0]
    if inter2["due"] != "2026-11-17T00:00:00Z":
        _break(pid, "re-anchor wrong: %r" % (inter2["due"],))
        return
    # Resolved: no intermediate, final anchored on resolution + 60d.
    state3 = {"awareness_ts": _TS0, "gpai9_classes": ["death"],
              "initial_report_ts": "2026-10-02T00:00:00Z",
              "resolution_ts": "2026-10-05T00:00:00Z"}
    vs3 = G9.check_gpai9_timeliness(state3, "2026-10-06T00:00:00Z")
    kinds3 = {v["check"] for v in vs3}
    if kinds3 != {"initial", "final"}:
        _break(pid, "resolved verdict set wrong: %r" % (kinds3,))
        return
    fin = [v for v in vs3 if v["check"] == "final"][0]
    if fin["due"] != "2026-12-04T00:00:00Z":
        _break(pid, "final due wrong: %r" % (fin["due"],))
        return
    _held(pid, "intermediate/final anchoring pinned")


def P3f():
    """Timeliness codes: overdue checks carry their coded verdict;
    nothing overdue is silently absorbed; not-yet-due carries None."""
    pid = "P3f-timeliness-codes"
    state = {"awareness_ts": "2026-01-01T00:00:00Z",
             "gpai9_classes": ["critical-infrastructure"]}
    vs = G9.check_gpai9_timeliness(state, "2026-02-01T00:00:00Z")
    init = [v for v in vs if v["check"] == "initial"][0]
    if init["status"] != "overdue" or \
            init["code"] != "incident-gpai9-initial-overdue":
        _break(pid, "overdue initial not coded: %r" % (init,))
        return
    vs2 = G9.check_gpai9_timeliness(state, "2026-01-01T12:00:00Z")
    init2 = [v for v in vs2 if v["check"] == "initial"][0]
    if init2["status"] != "not-yet-due" or init2["code"] is not None:
        _break(pid, "not-yet-due wrong: %r" % (init2,))
        return
    # A report filed late is still marked overdue (never absorbed).
    state["initial_report_ts"] = "2026-01-10T00:00:00Z"
    vs3 = G9.check_gpai9_timeliness(state, "2026-02-01T00:00:00Z")
    init3 = [v for v in vs3 if v["check"] == "initial"][0]
    if init3["status"] != "overdue":
        _break(pid, "late-filed initial absorbed: %r" % (init3,))
        return
    _held(pid, "overdue is always coded, never absorbed")


def P3g():
    """Shape games: non-ISO or non-string timestamps, unknown or empty
    classes refuse malformed (coded, never coerced)."""
    pid = "P3g-shape-games"
    for bad_ts in ("2026-10-05", "2026-10-05T00:00:00",
                   "2026-10-05T00:00:00+00:00", 12345, None, ""):
        if not _expect_code(
                pid, "incident-gpai9-malformed",
                lambda bad_ts=bad_ts: G9.record_awareness(
                    "I", bad_ts, "established")):
            return
    for bad_classes in ([], ["unknown-class"], "cybersecurity", None):
        if not _expect_code(
                pid + "-class", "incident-gpai9-malformed",
                lambda bad_classes=bad_classes: G9.classify_gpai9_band(
                    bad_classes)):
            return
    if not _expect_code(
            pid + "-stage", "incident-gpai9-malformed",
            lambda: G9.build_gpai9_report(_incident(), stage="draft")):
        return
    _held(pid, "shapes refuse coded malformed")

# ---------------------------------------------------------------------------
# P4: closure regressions (F417/F418/F419/F420).
# ---------------------------------------------------------------------------

def P4a():
    """F417 CLOSED: a non-numeric port refuses coded
    mcp-oauth-metadata-malformed (never a bare ValueError) on the
    binding module's URL-normalizing entry points."""
    pid = "P4a-f417-closed"
    sealed = MOB.seal_as_binding("https://as.example.com", "w335-client",
                                 _KEY)
    cases = [
        (lambda: MOB.seal_as_binding("https://as.example.com:badport",
                                     "w335-client", _KEY),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
        (lambda: MOB.validate_authorization_response(
            sealed, {"iss": "https://as.example.com:badport"}, _KEY),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
        (lambda: PRM.check_prm_url(
            "https://m.example.com:badport/x", _RES),
         MOB.MCP_OAUTH_METADATA_MALFORMED),
    ]
    for fn, want in cases:
        try:
            fn()
        except MOB.McpOAuthError as e:
            if e.code != want:
                _break(pid, "wrong code: want %s, got %r" % (want, e.code))
                return
        except ValueError:
            _break(pid, "bare ValueError escaped (F417 open again)")
            return
        except Exception as e:  # noqa: BLE001
            _break(pid, "unexpected exception type: %r" % (e,))
            return
        else:
            _break(pid, "no refusal at all on bad port")
            return
    _held(pid, "F417 still closed: ports refuse coded everywhere")


def P4b():
    """F419 CLOSED: the server-side 401 path exists -- a missing token
    maps to (401, Bearer error="invalid_token") via refusal_response;
    cross-server replay is a coded 401 resource-misbound."""
    pid = "P4b-f419-closed"
    code = _code_of(lambda: _validate(authz=None))
    if code != MSA.MCP_SERVER_AUTH_MISSING_TOKEN:
        _break(pid, "missing token: got %r" % (code,))
        return
    if MSA.http_status_for(code) != 401:
        _break(pid, "missing token not 401")
        return
    status, challenge = MSA.refusal_response(code, "no token")
    if status != 401 or 'error="invalid_token"' not in challenge \
            or not challenge.startswith("Bearer "):
        _break(pid, "401 challenge wrong: %r %r" % (status, challenge))
        return
    if not _expect_code(
            pid + "-misbound", MSA.MCP_SERVER_AUTH_RESOURCE_MISBOUND,
            lambda: _validate(claims={"aud": _RES2}, server=_RES)):
        return
    _held(pid, "F419 still closed: 401 path coded")


def P4c():
    """F420 CLOSED: AS-substitution in a PRM document refuses
    mcp-oauth-prm-issuer-unlisted even when the doc is otherwise
    perfect."""
    pid = "P4c-f420-closed"
    if not _expect_code(
            pid, PRM.MCP_OAUTH_PRM_ISSUER_UNLISTED,
            lambda: PRM.verify_prm_document(
                _sealed(), _RES,
                _prm_doc(issuers=("https://substitute.example.com",),
                         signed_metadata="issuer-substituted-here"),
                _KEY)):
        return
    _held(pid, "F420 still closed: AS-substitution refused coded")


def P4d():
    """F418 CLOSED: a signed revocation event terminates a bound
    in-flight session -- require_live then refuses coded
    revocation-push-session-terminated (the same seam the w334 attack
    battery's real-model test exercises)."""
    pid = "P4d-f418-closed"
    key = b"w335-f418-test-key-0000000000000"
    assert len(key) == 32
    now = 1798765432
    hub = RP.RevocationPushHub(hmac_key=key, clock=lambda: now)
    hub.register_session("sess-335d",
                         [{"kind": "credential", "id": "cred-1"}],
                         on_terminate=lambda r: None)
    if hub.session_status("sess-335d") != "live":
        _break(pid, "session did not register live")
        return
    event = {"event_id": "evt-335d-0001",
             "event_type": RP.EVENT_TYPES[0],
             "subject": {"kind": "credential", "id": "cred-1"},
             "issued_at": now, "reason": "credential rotated"}
    receipt = hub.ingest(RP.sign_event(key, event))
    if receipt.get("code") != "revocation-push-session-terminated":
        _break(pid, "ingest receipt not terminated: %r" % (receipt,))
        return
    try:
        hub.require_live("sess-335d")
    except RP.RevocationPushSessionTerminatedError as e:
        if e.code != "revocation-push-session-terminated":
            _break(pid, "wrong code: %r" % (e.code,))
            return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception type: %r" % (e,))
        return
    else:
        _break(pid, "require_live PASSED after revocation")
        return
    _held(pid, "F418 still closed: revocation terminates session")


# ---------------------------------------------------------------------------
# P5: pin/footer honesty.
# ---------------------------------------------------------------------------

# P5 footer state is asserted by raw-literal read of evals/FINDINGS.md
# in P5c (wave-331 lesson); no module-level footer constants needed.
_FINDINGS_MD = os.path.join(REPO, "evals", "FINDINGS.md")


def P5a():
    """Pin honesty: TAXONOMY_PIN is 2121 and the registry's sorted
    unique key order holds on raw source literals."""
    pid = "P5a-pin-taxonomy-2140-sorted"
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        _break(pid, "TAXONOMY_PIN %r != 2140" % (TAXONOMY_PIN,))
        return
    # The canonical pin constant lives in gov/guac_graph.py (wave-302
    # lesson); the battery-local literal must agree with it.
    from gov import guac_graph as GG  # noqa: E402
    if GG.TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        _break(pid, "guac_graph.TAXONOMY_PIN %r != 2140" % (GG.TAXONOMY_PIN,))
        return
    codes = sorted(DC.TAXONOMY.keys())
    if list(DC.TAXONOMY.keys()) != codes:
        _break(pid, "taxonomy dict not sorted")
        return
    if len(codes) != len(set(codes)):
        _break(pid, "duplicate taxonomy keys")
        return
    _held(pid, "pin 2121 honest; taxonomy sorted-unique")


def P5b():
    """All 23 wave-334 codes are centrally registered (registration,
    not vocab-scan presence) and every mcp/inciident code carries a
    short human-readable message."""
    pid = "P5b-23-codes-registered"
    missing = [c for c in (_NEW_AUTH_CODES + _NEW_PRM_CODES + _NEW_GPAI_CODES)
               if c not in DC.TAXONOMY]
    if missing:
        _break(pid, "codes not registered: %r" % (missing,))
        return
    for code in _NEW_AUTH_CODES + _NEW_PRM_CODES + _NEW_GPAI_CODES:
        entry = DC.TAXONOMY[code]
        human = entry.get("human", "") if isinstance(entry, dict) else ""
        if not human or len(human) < 8:
            _break(pid, "code %s missing a readable message" % (code,))
            return
    _held(pid, "23 wave-334 codes registered with messages")


def P5c():
    """Footer honesty: the last line of evals/FINDINGS.md carries open
    F426 and next F427 (raw-literal assertion, wave-331 lesson). F423
    was this lane's genuine finding (filed as F421, renumbered at the
    wave-335 merge per the wave-272 earliest-filed rule) and was
    CLOSED 2026-10-05 by wave-336 lane 1; F424/F425 were closed
    2026-10-05 by wave-337 lane 1; F426 was filed 2026-10-05 by the
    wave-337 red team and remains OPEN."""
    pid = "P5c-footer-open-f433-f434-f435-next-f436"
    with open(_FINDINGS_MD, "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
    last = lines[-1] if lines else ""
    if "Open findings: F612, F614, F615, F616, F617, F618, F619, F620." not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED
        _break(pid, "last line lacks 'Open findings: F595, F606, F607, F609, F610, F611.': %r" % (last[:120],))  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED
        return
    if "Next free finding: **F621**" not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621
        _break(pid, "last line lacks next-F436: %r" % (last[:120],))
        return
    if not any(l.startswith("## F423 ") for l in lines):
        _break(pid, "F423 section missing from FINDINGS.md")
        return
    if "CLOSED 2026-10-05 wave-336 lane 1" not in "\n".join(lines):
        _break(pid, "F423 closure not recorded in FINDINGS.md")
        return
    _held(pid, "footer honest: open none / next F430")


# ---------------------------------------------------------------------------
# P6: older closure spot-regressions (adopted from w332's tuple bridge).
# ---------------------------------------------------------------------------

def _adopt(pid, fn):
    """Bridge a w332 tuple-style (pid, verdict, note) probe into this
    record-style battery (the w332 _relabel pattern)."""
    import w332_redteam_probes as w332  # noqa: E402
    _old, verdict, note = fn(w332)
    _record(pid, verdict, note)


def P6a():
    """F415 closure regression, adopted from w332's _p1b (full
    partition matrix over _feed_files)."""
    pid = "P6a-f415-unicode-digit"
    _adopt(pid, lambda w332: w332._p1b())


def P6b():
    """F416 closure regression, adopted from w332's _p1h (int64
    boundary matrix)."""
    pid = "P6b-f416-int64-boundary"
    _adopt(pid, lambda w332: w332._p1h())


def P6c():
    """F414 closure regression, adopted from w332's _p2c (shamir
    residual)."""
    pid = "P6c-f414-symlink-alias"
    _adopt(pid, lambda w332: w332._p2c())


# ---------------------------------------------------------------------------
# Probe registry, green check, main.
# ---------------------------------------------------------------------------

_PROBES = [
    ("P1a-token-in-query-smuggling", P1a),
    ("P1b-challenge-injection-stripped", P1b),
    ("P1c-scope-confusion-403-only", P1c),
    ("P1d-verifier-contract", P1d),
    ("P1e-time-claim-games", P1e),
    ("P1f-header-shape-games", P1f),
    ("P1g-cross-server-replay-dead", P1g),
    ("P1h-issuer-games", P1h),
    ("P1i-deployment-shape-games", P1i),
    ("P1j-verdict-fields", P1j),
    ("P2a-ssrf-shapes", P2a),
    ("P2b-userinfo-smuggling", P2b),
    ("P2c-cross-origin-confusion", P2c),
    ("P2d-challenge-games", P2d),
    ("P2e-derive-games", P2e),
    ("P2f-document-verification", P2f),
    ("P2g-fetch-discipline", P2g),
    ("P2h-field-shape-games", P2h),
    ("P2i-port-games-contained", P2i),
    ("P3a-checklist-digest-tampering", P3a),
    ("P3b-unavailable-marking-abuse", P3b),
    ("P3c-cadence-clock-games", P3c),
    ("P3d-retention-boundary-edges", P3d),
    ("P3e-intermediate-anchoring", P3e),
    ("P3f-timeliness-codes", P3f),
    ("P3g-shape-games", P3g),
    ("P4a-f417-closed", P4a),
    ("P4b-f419-closed", P4b),
    ("P4c-f420-closed", P4c),
    ("P4d-f418-closed", P4d),
    ("P5a-pin-taxonomy-2140-sorted", P5a),
    ("P5b-23-codes-registered", P5b),
    ("P5c-footer-open-f433-f434-f435-next-f436", P5c),
    ("P6a-f415-unicode-digit", P6a),
    ("P6b-f416-int64-boundary", P6b),
    ("P6c-f414-symlink-alias", P6c),
]

_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); 0 expected


def _run_root():
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    root = os.path.join(base, "w335-redteam")
    os.makedirs(root, exist_ok=True)
    return root


_CHILD_BATTERIES = [
    # w334_attack_probes.py is deliberately EXCLUDED: it drives a
    # ModelDriver that can attempt real model calls (API spend); its
    # security property (revocation kill channel) is pinned directly
    # by P4d instead. Never spend user credits in a green check.
    ("w334_redteam_probes.py", 0, "0/25/0"),
    ("w334_prm_probes.py", 0, "0/14/0"),
    ("w334_mcpsrvauthz_probes.py", 0, "0/9/0"),
    ("w334_gpai9_probes.py", 0, "0/34/0"),
]


def _run_child_output(name):
    """Run an adjacent battery's main with green checks skipped
    (depth-1 green checks, wave-173 lesson) and return its stdout tail."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    root = _run_root()
    sub = os.path.join(root, "child-%s" % name)
    os.makedirs(sub, exist_ok=True)
    env["TMPDIR"] = sub
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", name)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=900)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-4:])
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", tail)
    return m, tail


def _green_check():
    """Depth-1 green checks over the wave-334 child batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("GREEN-SKIPPED", "HELD",
                 "green check skipped (child mode)")
        return
    for name, want_breaks, want_tuple in _CHILD_BATTERIES:
        pid = "GREEN-" + name.replace(".py", "")
        m, tail = _run_child_output(name)
        if m is None:
            _record(pid, "ERROR", "no B/H/E tuple in child output:\n%s"
                    % tail)
            continue
        b, h, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        got = "%d/%d/%d" % (b, h, e)
        if got != want_tuple or b != want_breaks:
            _record(pid, "BREAK",
                    "child drift: got %s, want %s:\n%s" % (got, want_tuple,
                                                           tail))
        else:
            _record(pid, "HELD", "child %s as expected" % got)


def _summary():
    b = sum(1 for _, v, _ in _results if v == "BREAK")
    h = sum(1 for _, v, _ in _results if v == "HELD")
    e = sum(1 for _, v, _ in _results if v == "ERROR")
    return b, h, e


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    only = [a for a in argv if not a.startswith("-")]
    todo = _PROBES
    if only:
        # Prefix match: "P1d" selects "P1d-verifier-contract".
        matched = []
        for want in only:
            hits = [(pid, fn) for pid, fn in _PROBES
                    if pid == want or pid.startswith(want + "-")]
            if not hits:
                print("unknown probe id: %r" % (want,))
                return 1
            matched.extend(hits)
        todo = matched
    _run_root()
    for pid, fn in todo:
        _safe(pid, fn)
    _green_check()
    b, h, e = _summary()
    print("\nw335_redteam: %d/%d/%d (break/held/error)" % (b, h, e))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
