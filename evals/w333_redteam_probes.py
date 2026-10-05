"""Wave-333 lane 5 break battery: independent red team vs the wave-332 merge.

Base: 43d539c7 (wave-332 merge). Pin: 2062. Footer: open none / next F417.

The wave-332 merge's only new gov/ attack surface is the MCP OAuth
hardening (RFC 9207 iss validation + RFC 8707 resource indicators,
4 new codes, pin 2058 -> 2062). Everything else in gov/ is unchanged
from wave-331. This battery attacks the new seams adversarially --
issuer confusion, resource mismatch, token substitution across
resources, audience tricks, binding tampering, verdict replay -- plus
F415/F416 closure regressions, the Shamir write-time residual, pin /
footer honesty, and F410-F416 regression coverage via relabelled
proven probes.

Break-first discipline (diagnosing-bugs): every probe asserts the
CODED refusal (or the documented grant), never the absence of a
crash. A probe that grants where a coded refusal is required, refuses
with the wrong code, or lets a bare exception escape is a BREAK and a
candidate F-number from F417. An all-HELD battery is an honest
result, not a failure to find.

P1  RFC 9207 issuer confusion: rogue iss, missing iss, empty iss,
    non-string iss, http iss, IDN homograph, normalization
    consistency, non-verdict iss check, non-dict response,
    malformed-port uncoded crash (F417).
P2  RFC 8707 resource indicators: A-at-B, resourceless, empty aud,
    garbage aud, multi-aud any-match, suffix attack, path attack,
    trailing-slash normalization, token-response substitution,
    non-string resource claim.
P3  Binding + choke point: tampered MAC, attacker-sealed binding,
    verdict replay (exchange_fn must not run), iss-gated exchange,
    non-bool provider flag, allowlist subdomain confusion,
    issuer_hint mismatch, credential AS mismatch, http seal.
P4  F415/F416 closure regressions (relabelled w332 probes).
P5  Shamir write-time residual (relabelled w332 probe).
P6  Pin/footer honesty: taxonomy 2100/2100/0 on raw literals,
    footer open none / next F417, live pin constants == 2100.
P7  Child mode: w332_mcpoauth battery, BREAKs inside the cascade.
"""

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

TAXONOMY_PIN = 2100 # Wave-332 merge: pin 2058 -> 2062 (+4 mcp-oauth-*).; Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*).
FOOTER_OPEN = "none"  # F417 CLOSED 2026-10-05 (wave-334 lane 1: port guard; no open findings).
FOOTER_NEXT = "F421"  # Next free finding number (F417 closed wave-334 lane 1; F418 closed at wave-333 merge).

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


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


def _tmpd(prefix="w333-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w333rt")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


from gov import mcp_oauth_binding as mob  # noqa: E402

_KEY = b"w333-redteam-test-key-0001"
_AS = "https://as.example.com"
_MCP = "https://mcp.example.com"


def _sealed(issuer=_AS, allowlist=None):
    return mob.seal_as_binding(issuer, "w333-client", _KEY,
                               token_endpoint_allowlist=allowlist)


def _expect_code(pid, fn, want_code, note):
    """HELD iff fn() raises McpOAuthError with exactly want_code."""
    try:
        fn()
    except mob.McpOAuthError as exc:
        if exc.code != want_code:
            return _break(pid, "%s: wrong code %r, want %r"
                          % (note, exc.code, want_code))
        return _held(pid, "%s: refused coded %s" % (note, want_code))
    except Exception as exc:
        return _break(pid, "%s: UNCODED %s escapes: %s"
                      % (note, type(exc).__name__, str(exc)[:120]))
    return _break(pid, "%s: GRANTED, want coded %s" % (note, want_code))


def _expect_grant(pid, fn, note):
    """HELD iff fn() returns without raising (documented grant)."""
    try:
        fn()
    except mob.McpOAuthError as exc:
        return _break(pid, "%s: refused %s, want grant" % (note, exc.code))
    except Exception as exc:
        return _break(pid, "%s: UNCODED %s escapes" % (note,
                                                       type(exc).__name__))
    return _held(pid, "%s: granted (documented)" % note)


# ---------------------------------------------------------------------------
# P1: RFC 9207 issuer confusion.
# ---------------------------------------------------------------------------

@probe("P1a-oauth-rogue-iss-mismatched")
def _p1a():
    sealed = _sealed()
    return _expect_code(
        "P1a-oauth-rogue-iss-mismatched",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": "https://rogue.example.com"}, _KEY),
        mob.MCP_OAUTH_ISS_MISMATCHED,
        "rogue-AS authorization response")


@probe("P1b-oauth-missing-iss")
def _p1b():
    sealed = _sealed()
    return _expect_code(
        "P1b-oauth-missing-iss",
        lambda: mob.validate_authorization_response(sealed, {}, _KEY),
        mob.MCP_OAUTH_ISS_MISSING,
        "authorization response with no iss")


@probe("P1c-oauth-empty-iss-malformed")
def _p1c():
    """Present-but-empty iss is malformed, not missing: the two shapes
    must not be conflated (missing = AS never identified; empty =
    corrupt input)."""
    sealed = _sealed()
    return _expect_code(
        "P1c-oauth-empty-iss-malformed",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": ""}, _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "empty-string iss")


@probe("P1d-oauth-nonstring-iss-malformed")
def _p1d():
    sealed = _sealed()
    return _expect_code(
        "P1d-oauth-nonstring-iss-malformed",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": 12345}, _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-string iss")


@probe("P1e-oauth-http-iss-malformed")
def _p1e():
    """Bearer material never travels over http: a plaintext iss is
    refused outright, never normalized."""
    sealed = _sealed()
    return _expect_code(
        "P1e-oauth-http-iss-malformed",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": "http://as.example.com"}, _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "http-scheme iss")


@probe("P1f-oauth-homograph-iss-mismatched")
def _p1f():
    """IDN homograph: Cyrillic 'а' (U+0430) in the host must never be
    conflated with ASCII 'a'. The module does no IDNA mapping, so the
    two identifiers stay distinct and the rogue one is refused."""
    sealed = _sealed()
    homograph = "https://\u0430s.example.com"
    return _expect_code(
        "P1f-oauth-homograph-iss-mismatched",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": homograph}, _KEY),
        mob.MCP_OAUTH_ISS_MISMATCHED,
        "homograph iss (Cyrillic a)")


@probe("P1g-oauth-normalization-consistent-grant")
def _p1g():
    """Canonicalization must be stable: sealed as
    https://AS.EXAMPLE.COM:443/ (case + default port + trailing
    slash), checked as https://as.example.com -- both normalize to
    the same identifier, so this grants."""
    sealed = _sealed(issuer="https://AS.EXAMPLE.COM:443/")
    return _expect_grant(
        "P1g-oauth-normalization-consistent-grant",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": "https://as.example.com"}, _KEY),
        "case/port/slash normalization")


@probe("P1h-oauth-iss-check-nonverdict")
def _p1h():
    return _expect_code(
        "P1h-oauth-iss-check-nonverdict",
        lambda: mob.check_response_iss(
            {"not": "a verdict"}, {"iss": _AS}),
        mob.MCP_OAUTH_VERDICT_MISMATCHED,
        "iss check with a non-verdict object")


@probe("P1i-oauth-response-nondict-malformed")
def _p1i():
    sealed = _sealed()
    return _expect_code(
        "P1i-oauth-response-nondict-malformed",
        lambda: mob.validate_authorization_response(
            sealed, ["not", "a", "dict"], _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-dict authorization response")


@probe("P1j-oauth-malformed-port-uncoded")
def _p1j():
    """F417 (CLOSED 2026-10-05, wave-334 lane 1): a non-numeric port in an
    attacker-influenced URL used to escape _normalize_url as a BARE
    ValueError (`port = parts.port` raised before the isinstance guard
    below it ever ran -- dead code). Now the .port access is guarded so
    any ValueError refuses coded mcp-oauth-metadata-malformed. The iss
    is an EMITTER CLAIM (server-supplied redirect parameters); token
    aud/resource claims and issuer_hint funnel through the same
    _normalize_url and refuse coded too."""
    sealed = _sealed()
    return _expect_code(
        "P1j-oauth-malformed-port-uncoded",
        lambda: mob.validate_authorization_response(
            sealed, {"iss": "https://as.example.com:badport"}, _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-numeric port in iss")


# ---------------------------------------------------------------------------
# P2: RFC 8707 resource indicators.
# ---------------------------------------------------------------------------

@probe("P2a-oauth-token-a-at-b-misbound")
def _p2a():
    return _expect_code(
        "P2a-oauth-token-a-at-b-misbound",
        lambda: mob.check_token_resource(
            "https://mcp-b.example.com",
            {"resource": "https://mcp-a.example.com"}),
        mob.MCP_OAUTH_RESOURCE_MISBOUND,
        "token minted for A presented at B")


@probe("P2b-oauth-token-resourceless-missing")
def _p2b():
    return _expect_code(
        "P2b-oauth-token-resourceless-missing",
        lambda: mob.check_token_resource(_MCP, {"sub": "agent-1"}),
        mob.MCP_OAUTH_RESOURCE_MISSING,
        "token with no resource/aud indicator")


@probe("P2c-oauth-token-empty-aud-missing")
def _p2c():
    return _expect_code(
        "P2c-oauth-token-empty-aud-missing",
        lambda: mob.check_token_resource(_MCP, {"aud": []}),
        mob.MCP_OAUTH_RESOURCE_MISSING,
        "token with empty aud list")


@probe("P2d-oauth-token-garbage-aud-malformed")
def _p2d():
    return _expect_code(
        "P2d-oauth-token-garbage-aud-malformed",
        lambda: mob.check_token_resource(
            _MCP, {"aud": ["not a url \x00"]}),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-URL aud candidate")


@probe("P2e-oauth-token-multi-aud-any-match-grant")
def _p2e():
    """Any-match semantics: an aud list naming the server among others
    grants. Documented grant -- binding is checked here, authenticity
    is the caller's job (a caller feeding claims from an unverified
    token gets binding checks on attacker-chosen bytes)."""
    return _expect_grant(
        "P2e-oauth-token-multi-aud-any-match-grant",
        lambda: mob.check_token_resource(
            _MCP, {"aud": ["https://other.example.com", _MCP]}),
        "multi-aud with server present")


@probe("P2f-oauth-token-suffix-attack-misbound")
def _p2f():
    """Suffix confusion: mcp.example.com.evil.com must not match
    mcp.example.com -- comparison is exact on the normalized URL,
    never prefix/suffix."""
    return _expect_code(
        "P2f-oauth-token-suffix-attack-misbound",
        lambda: mob.check_token_resource(
            _MCP, {"aud": ["https://mcp.example.com.evil.com"]}),
        mob.MCP_OAUTH_RESOURCE_MISBOUND,
        "suffix-attack aud")


@probe("P2g-oauth-token-path-attack-misbound")
def _p2g():
    """Path confusion: https://mcp.example.com/admin is a different
    resource identifier than https://mcp.example.com."""
    return _expect_code(
        "P2g-oauth-token-path-attack-misbound",
        lambda: mob.check_token_resource(
            _MCP, {"resource": "https://mcp.example.com/admin"}),
        mob.MCP_OAUTH_RESOURCE_MISBOUND,
        "path-attack resource claim")


@probe("P2h-oauth-token-trailing-slash-grant")
def _p2h():
    """Trailing-slash normalization is stable: the candidate
    https://mcp.example.com/ normalizes to the server identifier."""
    return _expect_grant(
        "P2h-oauth-token-trailing-slash-grant",
        lambda: mob.check_token_resource(
            _MCP, {"resource": "https://mcp.example.com/"}),
        "trailing-slash resource normalization")


@probe("P2i-oauth-token-response-substituted-misbound")
def _p2i():
    return _expect_code(
        "P2i-oauth-token-response-substituted-misbound",
        lambda: mob.check_token_response_resource(
            _MCP, {"resource": "https://evil.example.com"}),
        mob.MCP_OAUTH_RESOURCE_MISBOUND,
        "token response naming a substituted resource")


@probe("P2j-oauth-token-nonstring-resource-malformed")
def _p2j():
    return _expect_code(
        "P2j-oauth-token-nonstring-resource-malformed",
        lambda: mob.check_token_resource(_MCP, {"resource": 42}),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-string resource claim")


# ---------------------------------------------------------------------------
# P3: binding + choke point.
# ---------------------------------------------------------------------------

@probe("P3a-oauth-tampered-mac")
def _p3a():
    sealed = _sealed()
    sealed = dict(sealed)
    sealed["mac"] = "0" * 64
    return _expect_code(
        "P3a-oauth-tampered-mac",
        lambda: mob.authorize_token_exchange(
            sealed, _AS + "/token", _KEY, issuer_hint=_AS),
        mob.MCP_OAUTH_BINDING_TAMPERED,
        "binding with a forged MAC")


@probe("P3b-oauth-attacker-sealed-binding")
def _p3b():
    """An agent holds a sealed binding but can never rebind it: a
    binding sealed under the attacker's own key is tamper, not a
    shape gap, when presented with the deployment key."""
    attacker_sealed = mob.seal_as_binding(
        "https://rogue.example.com", "w333-client", b"attacker-key")
    return _expect_code(
        "P3b-oauth-attacker-sealed-binding",
        lambda: mob.authorize_token_exchange(
            attacker_sealed, "https://rogue.example.com/token", _KEY,
            issuer_hint="https://rogue.example.com"),
        mob.MCP_OAUTH_BINDING_TAMPERED,
        "attacker-sealed binding under deployment key")


@probe("P3c-oauth-verdict-replay-exchange-blocked")
def _p3c():
    """Verdict replay: a verdict granted for endpoint A presented at
    endpoint B refuses AND the exchange function never runs."""
    sealed = _sealed()
    verdict = mob.authorize_token_exchange(
        sealed, _AS + "/token", _KEY, issuer_hint=_AS)
    called = []
    try:
        mob.run_bound_exchange(
            verdict, _AS + "/other",
            lambda: called.append(True))
    except mob.McpOAuthError as exc:
        if exc.code != mob.MCP_OAUTH_VERDICT_MISMATCHED:
            return _break("P3c-oauth-verdict-replay-exchange-blocked",
                          "wrong code %r" % (exc.code,))
    except Exception as exc:
        return _break("P3c-oauth-verdict-replay-exchange-blocked",
                      "uncoded %s escapes" % type(exc).__name__)
    else:
        return _break("P3c-oauth-verdict-replay-exchange-blocked",
                      "replayed verdict GRANTED")
    if called:
        return _break("P3c-oauth-verdict-replay-exchange-blocked",
                      "exchange_fn RAN on a refused verdict")
    return _held("P3c-oauth-verdict-replay-exchange-blocked",
                 "verdict replay refused coded; exchange_fn never ran")


@probe("P3d-oauth-iss-gated-exchange-blocked")
def _p3d():
    """The choke point gates on the RFC 9207 iss too: a response with
    no iss refuses BEFORE the exchange runs."""
    sealed = _sealed()
    verdict = mob.authorize_token_exchange(
        sealed, _AS + "/token", _KEY, issuer_hint=_AS)
    called = []
    try:
        mob.run_bound_exchange(
            verdict, _AS + "/token",
            lambda: called.append(True),
            authorization_response={"code": "abc"})
    except mob.McpOAuthError as exc:
        if exc.code != mob.MCP_OAUTH_ISS_MISSING:
            return _break("P3d-oauth-iss-gated-exchange-blocked",
                          "wrong code %r" % (exc.code,))
    except Exception as exc:
        return _break("P3d-oauth-iss-gated-exchange-blocked",
                      "uncoded %s escapes" % type(exc).__name__)
    else:
        return _break("P3d-oauth-iss-gated-exchange-blocked",
                      "iss-less response GRANTED at the choke point")
    if called:
        return _break("P3d-oauth-iss-gated-exchange-blocked",
                      "exchange_fn RAN on an iss-less response")
    return _held("P3d-oauth-iss-gated-exchange-blocked",
                 "iss-less response refused coded; exchange_fn never ran")


@probe("P3e-oauth-nonbool-provider-flag-malformed")
def _p3e():
    sealed = _sealed()
    return _expect_code(
        "P3e-oauth-nonbool-provider-flag-malformed",
        lambda: mob.authorize_token_exchange(
            sealed, _AS + "/token", _KEY, issuer_hint=_AS,
            provider_requires_issuer="yes"),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "non-bool provider_requires_issuer")


@probe("P3f-oauth-allowlist-subdomain-confusion")
def _p3f():
    """Allowlist subdomain confusion: the deployment-declared
    alternate https://token.example.com must not admit
    https://token.example.com.evil.com -- origin comparison is
    exact."""
    sealed = _sealed(allowlist=["https://token.example.com"])
    return _expect_code(
        "P3f-oauth-allowlist-subdomain-confusion",
        lambda: mob.authorize_token_exchange(
            sealed, "https://token.example.com.evil.com/token", _KEY,
            issuer_hint=_AS),
        mob.MCP_OAUTH_ISSUER_UNBOUND,
        "allowlist subdomain-confusion endpoint")


@probe("P3g-oauth-issuer-hint-mismatch")
def _p3g():
    sealed = _sealed()
    return _expect_code(
        "P3g-oauth-issuer-hint-mismatch",
        lambda: mob.authorize_token_exchange(
            sealed, _AS + "/token", _KEY,
            issuer_hint="https://evil.example.com"),
        mob.MCP_OAUTH_ISSUER_UNVERIFIED,
        "issuer_hint naming a different AS")


@probe("P3h-oauth-credential-as-mismatch")
def _p3h():
    sealed = _sealed()
    return _expect_code(
        "P3h-oauth-credential-as-mismatch",
        lambda: mob.authorize_token_exchange(
            sealed, _AS + "/token", _KEY, issuer_hint=_AS,
            presented_as_issuer="https://other-as.example.com"),
        mob.MCP_OAUTH_CREDENTIAL_MISBOUND,
        "credential stored under AS-X at AS-Y")


@probe("P3i-oauth-http-seal-malformed")
def _p3i():
    return _expect_code(
        "P3i-oauth-http-seal-malformed",
        lambda: mob.seal_as_binding(
            "http://as.example.com", "w333-client", _KEY),
        mob.MCP_OAUTH_METADATA_MALFORMED,
        "sealing a plaintext-http issuer")


# ---------------------------------------------------------------------------
# P4: F415/F416 closure regressions (relabelled proven probes).
# ---------------------------------------------------------------------------

@probe("P4a-f415-closure-regression")
def _p4a():
    import w332_redteam_probes as w332
    return _relabel("P4a-f415-closure-regression", w332._p1a)


@probe("P4b-f416-closure-regression")
def _p4b():
    import w332_redteam_probes as w332
    return _relabel("P4b-f416-closure-regression", w332._p1e)


@probe("P4c-f416-witness-ordering-regression")
def _p4c():
    import w332_redteam_probes as w332
    return _relabel("P4c-f416-witness-ordering-regression", w332._p1g)


# ---------------------------------------------------------------------------
# P5: Shamir write-time residual.
# ---------------------------------------------------------------------------

@probe("P5a-shamir-write-time-residual")
def _p5a():
    import w332_redteam_probes as w332
    return _relabel("P5a-shamir-write-time-residual", w332._p2a)


# ---------------------------------------------------------------------------
# P6: pin + footer honesty.
# ---------------------------------------------------------------------------

@probe("P6a-pin-taxonomy-2100-sorted")
def _p6a():
    if TAXONOMY_PIN != 2100:
        return _break("P6a-pin-taxonomy-2100-sorted",
                      "TAXONOMY_PIN is %r, want 2100" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2100 or len(set(lits)) != 2100 \
            or lits != sorted(lits):
        return _break("P6a-pin-taxonomy-2100-sorted",
                      "want 2100/2100/0 sorted, got %d/%d/sorted=%s"
                      % (len(lits), len(set(lits)), lits == sorted(lits)))
    return _held("P6a-pin-taxonomy-2100-sorted",
                 "2100/2100/0 sorted unique on raw source literals")


@probe("P6b-footer-open-none-next-f421")
def _p6b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Raw-literal assertions (wave-331 lesson): the footer must read
    # correctly as literal text, not only via constants.
    if "Next free finding: **F421**." not in text:
        return _break("P6b-footer-open-none-next-f421",
                      "raw literal 'Next free finding: **F421**.' absent")
    if "**Open findings: none.**" not in text:
        return _break("P6b-footer-open-none-next-f421",
                      "raw literal '**Open findings: none.**' absent")
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break("P6b-footer-open-none-next-f421",
                      "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break("P6b-footer-open-none-next-f421",
                      "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held("P6b-footer-open-none-next-f421",
                 "footer open none / next F419 (raw literals + parse)")


@probe("P6c-pin-constants-2100-live")
def _p6c():
    """Wave-302 lesson: every live module-level TAXONOMY_PIN constant
    must equal the new pin; stale values hide in files the
    value-token sweep never matched."""
    grandfathered = {"evals/w259_f225_probes.py",
                     "tests/test_replay_manifest.py"}
    bad = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, REPO)
            try:
                src = open(p, encoding="utf-8").read()
            except Exception:
                continue
            for m in re.finditer(r"^TAXONOMY_PIN\s*=\s*(\d+)", src, re.M):
                if rel in grandfathered:
                    continue
                if int(m.group(1)) != 2100:
                    bad.append("%s:%s" % (rel, m.group(1)))
    if bad:
        return _break("P6c-pin-constants-2100-live",
                      "stale pin constants: %s" % (bad[:6],))
    return _held("P6c-pin-constants-2100-live",
                 "all live module-level TAXONOMY_PIN == 2100")


# ---------------------------------------------------------------------------
# P7: prior battery in child mode.
# ---------------------------------------------------------------------------

def _run_child_output(battery, timeout=1800):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w333child-", dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> set of BREAK probe IDs that are NOT regressions on this
# tree. The F417-filing footer cascade (footer open F417 / next F419)
# is closed: F417 was closed 2026-10-05 by wave-334 lane 1 and every
# battery's footer probe was repointed to open none / next F419
# (wave-305/331 lessons), so all children are expected fully green.
_CHILD_CASCADE = {
    "w332_mcpoauth_probes.py": set(),  # footer probe asserts open none/next F419: green.
    "w332_redteam_probes.py": set(),  # P5b + P7a children all assert open none/next F419: green.
}

# P7a runs only the battery directly adjacent to this lane's new
# seams; the w332 red-team battery is covered by the green check.
_P7A_BATTERIES = ("w332_mcpoauth_probes.py",)


@probe("P7a-prior-battery-child-mode-tally")
def _p7a():
    """Prior battery: every BREAK is inside the documented cascade."""
    bad = []
    tallies = []
    for battery in _P7A_BATTERIES:
        out = _run_child_output(battery)
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        outside = breaks - _CHILD_CASCADE[battery]
        if errors or outside:
            bad.append("%s: non-cascade %s"
                       % (battery, sorted(outside | errors)[:4]))
        tallies.append("%s breaks=%d" % (battery, len(breaks)))
    if bad:
        return _break("P7a-prior-battery-child-mode-tally",
                      "; ".join(bad[:6]))
    return _held("P7a-prior-battery-child-mode-tally",
                 "all child BREAKs inside the documented cascade; "
                 + "; ".join(tallies))


# ---------------------------------------------------------------------------
# Expected BREAK set, green check, main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # F417 CLOSED 2026-10-05, wave-334 lane 1.


def _green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1.

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery in ("w332_redteam_probes.py",
                    "w332_mcpoauth_probes.py"):
        try:
            out = _run_child_output(battery, timeout=1800)
        except Exception as exc:
            _record("green-check", "ERROR",
                    "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        outside = breaks - _CHILD_CASCADE.get(battery, set())
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-cascade %s" %
                    (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all in cascade" % (battery, len(breaks)))


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    # Only probe IDs (not the green-check record) count toward the set.
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w333_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAK expected: F417 closed, P1j HELD)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
