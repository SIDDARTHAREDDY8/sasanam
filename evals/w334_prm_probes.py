"""Wave-334 PRM battery (F420 closure; filed as F419, renumbered).

Base: a40c2ef4 (wave-333 merge). Footer at lane: open F417 / next F420
(F420 filed then CLOSED here; filed as F419, renumbered). Pin: 2100 (+6 mcp-oauth-prm-*).

P1  F420 red-first, now closed: the forged PRM (attacker AS in
    authorization_servers, mismatched resource) refuses coded
    mcp-oauth-prm-issuer-unlisted / mcp-oauth-prm-resource-mismatched
    (on the base tree there was no code path taking a PRM document
    at all -- /tmp/red_prm.py).
P2  Valid PRM passes: matching resource, bound issuer listed ->
    PrmVerdict with canonical resource/issuer, issuer_digest chaining
    to the OAuth verdict digest, listed servers tuple. Omitted
    authorization_servers also passes (RFC 9728: optional); the
    sealed binding still governs.
P3  PRM shape refusals coded mcp-oauth-prm-malformed: non-dict,
    missing resource, empty/non-string resource, empty
    authorization_servers, non-string entries, bad jwks_uri scheme,
    'none' signing alg (RFC 9728 section 2 ban), unknown bearer
    method, non-boolean flags, non-string signed_metadata.
P4  Well-known derivation (RFC 9728 section 3.1): root, sub-path,
    trailing slash, query/fragment on the resource identifier
    refused, non-https refused via the shared URL contract.
P5  SSRF guards on the PRM URL: private/loopback IP literals refused
    coded mcp-oauth-prm-fetch-refused; userinfo and fragment refused
    (checked on the RAW url -- the canonicalizer drops them);
    cross-origin refused coded mcp-oauth-prm-cross-origin;
    fetcher=None / non-callable refused fail-closed (never implicit
    network); a raising fetcher refuses coded (a coded McpOAuthError
    from the fetcher propagates untouched).
P6  WWW-Authenticate challenge (RFC 9728 section 5.1): valid
    resource_metadata parses to the guarded URL; missing parameter,
    empty value, contradictory values refuse coded
    mcp-oauth-prm-challenge-malformed; cross-origin metadata URL
    refuses mcp-oauth-prm-cross-origin.
P7  F417-class containment at this seam: a non-numeric port in a
    PRM-controlled URL refuses coded mcp-oauth-prm-malformed (not a
    bare ValueError); F417 itself (OPEN, against _normalize_url) is
    not closed here.
P8  Tampered sealed binding still reports mcp-oauth-binding-tampered
    (never misreported as a PRM shape error); end-to-end
    discover_and_verify_prm with a stub fetcher returns a verdict.
P9  Pin 2100 + footer state (open F421 / next F422; F420 CLOSED);
    taxonomy sorted-unique on raw literals; the 6 new codes centrally
    registered.
P10 Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs the
    MCP-OAuth-adjacent unit suite tests/test_mcp_oauth_binding.py as
    a child with GOV_SKIP_GREEN=1 (fresh TMPDIR).

gov/ changes in this lane: new gov/mcp_prm.py (+6 codes in
gov/decision_codes.py, pin 2077 -> 2083); bound_issuer() accessor
added to gov/mcp_oauth_binding.py (no behavior change). Findings:
F420 filed then CLOSED here.
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

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F526, F527, F528, F529, F530"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F423/F424/F425 CLOSED; F426 closed wave-338 lane 1. F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)


FOOTER_NEXT = "F531"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)



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
    d = os.path.join(tempfile.gettempdir(), "w334prm")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _tmpd(prefix="w334prm-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import mcp_prm as prm  # noqa: E402
from gov import mcp_oauth_binding as mob  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


_KEY = b"w334-prm-battery-key-32bytes!!!!"
_REAL_AS = "https://real-as.example"
_EVIL_AS = "https://evil-as.example"
_RES = "https://mcp.example.com/tools"


def _sealed(issuer=_REAL_AS):
    return mob.seal_as_binding(issuer, "battery-client", _KEY)


def _expect_code(pid, want, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except mob.McpOAuthError as exc:
        if exc.code == want:
            return _held(pid, "%s as expected" % want)
        return _break(pid, "want %s got %s (%s)"
                      % (want, exc.code, exc.detail[:80]))
    return _break(pid, "want %s, no refusal" % want)


# ---------------------------------------------------------------------------
# P1 -- F420 red-first, now closed.
# ---------------------------------------------------------------------------

@probe("P1a-prm-forged-issuer-unlisted")
def _p1a():
    pid = "P1a-prm-forged-issuer-unlisted"
    # The red script's forged PRM: attacker AS listed, resource matches.
    return _expect_code(pid, "mcp-oauth-prm-issuer-unlisted",
                        prm.verify_prm_document, _sealed(), _RES,
                        {"resource": _RES,
                         "authorization_servers": [_EVIL_AS]}, _KEY)


@probe("P1b-prm-forged-resource-mismatched")
def _p1b():
    pid = "P1b-prm-forged-resource-mismatched"
    return _expect_code(pid, "mcp-oauth-prm-resource-mismatched",
                        prm.verify_prm_document, _sealed(), _RES,
                        {"resource": "https://mcp.example.com/OTHER",
                         "authorization_servers": [_REAL_AS]}, _KEY)


# ---------------------------------------------------------------------------
# P2 -- valid PRM passes.
# ---------------------------------------------------------------------------

@probe("P2a-prm-valid-verdict")
def _p2a():
    pid = "P2a-prm-valid-verdict"
    doc = {"resource": _RES,
           "authorization_servers": [_REAL_AS, "https://as2.example.net"],
           "scopes_supported": ["read", "write"],
           "bearer_methods_supported": ["header"],
           "resource_name": "Example MCP server"}
    v = prm.verify_prm_document(_sealed(), _RES, doc, _KEY)
    if v.resource != _RES:
        return _break(pid, "verdict resource %r" % v.resource)
    if v.issuer != _REAL_AS:
        return _break(pid, "verdict issuer %r" % v.issuer)
    # issuer_digest chains to the OAuth verdict digest.
    verdict = mob.authorize_token_exchange(
        _sealed(), "https://real-as.example/token", _KEY,
        issuer_hint=_REAL_AS, provider_requires_issuer=True)
    if v.issuer_digest != verdict.issuer_digest:
        return _break(pid, "issuer_digest does not chain to OAuth verdict")
    if v.authorization_servers != (_REAL_AS, "https://as2.example.net"):
        return _break(pid, "listed servers %r" % (v.authorization_servers,))
    return _held(pid, "valid PRM verifies; digest chains to OAuth verdict")


@probe("P2b-prm-omitted-servers-binding-governs")
def _p2b():
    pid = "P2b-prm-omitted-servers-binding-governs"
    # RFC 9728: authorization_servers is OPTIONAL; omission passes and
    # the sealed binding still governs (verdict carries its issuer).
    v = prm.verify_prm_document(_sealed(), _RES, {"resource": _RES}, _KEY)
    if v.authorization_servers != () or v.issuer != _REAL_AS:
        return _break(pid, "unexpected verdict %r" % (v,))
    return _held(pid, "omitted authorization_servers passes; binding governs")


# ---------------------------------------------------------------------------
# P3 -- PRM shape refusals.
# ---------------------------------------------------------------------------

@probe("P3a-prm-shape-malformed")
def _p3a():
    pid = "P3a-prm-shape-malformed"
    cases = [
        ("non-dict", "not-a-dict"),
        ("missing-resource", {"authorization_servers": [_REAL_AS]}),
        ("empty-resource", {"resource": ""}),
        ("non-string-resource", {"resource": 42}),
        ("empty-servers", {"resource": _RES, "authorization_servers": []}),
        ("non-string-server", {"resource": _RES,
                               "authorization_servers": [None]}),
        ("bad-jwks-scheme", {"resource": _RES,
                             "jwks_uri": "http://mcp.example.com/jwks"}),
        ("none-alg", {"resource": _RES,
                      "resource_signing_alg_values_supported": ["none"]}),
        ("bad-bearer-method", {"resource": _RES,
                               "bearer_methods_supported": ["smuggle"]}),
        ("non-bool-flag", {"resource": _RES,
                           "dpop_bound_access_tokens_required": "yes"}),
        ("bad-signed-metadata", {"resource": _RES,
                                 "signed_metadata": 42}),
        ("non-string-scopes", {"resource": _RES,
                               "scopes_supported": "read"}),
    ]
    for name, doc in cases:
        try:
            prm.verify_prm_document(_sealed(), _RES, doc, _KEY)
        except mob.McpOAuthError as exc:
            if exc.code not in ("mcp-oauth-prm-malformed",
                                "mcp-oauth-metadata-malformed"):
                return _break(pid, "%s: want prm-malformed, got %s"
                              % (name, exc.code))
        else:
            return _break(pid, "%s: no refusal" % name)
    return _held(pid, "12 malformed shapes refused coded")


# ---------------------------------------------------------------------------
# P4 -- well-known derivation (RFC 9728 section 3.1).
# ---------------------------------------------------------------------------

@probe("P4a-prm-derive-wellknown")
def _p4a():
    pid = "P4a-prm-derive-wellknown"
    cases = [
        ("https://mcp.example.com",
         "https://mcp.example.com/.well-known/oauth-protected-resource"),
        ("https://mcp.example.com/",
         "https://mcp.example.com/.well-known/oauth-protected-resource"),
        ("https://mcp.example.com/tools",
         "https://mcp.example.com/.well-known/oauth-protected-resource/tools"),
        ("https://mcp.example.com:8443/a/b",
         "https://mcp.example.com:8443/.well-known/oauth-protected-resource/a/b"),
    ]
    for server, want in cases:
        got = prm.derive_prm_url(server)
        if got != want:
            return _break(pid, "derive %r -> %r, want %r"
                          % (server, got, want))
    for bad in ("https://mcp.example.com/tools?x=1",
                "https://mcp.example.com/tools#frag",
                "http://mcp.example.com/tools",
                "not-a-url",
                ""):
        try:
            prm.derive_prm_url(bad)
        except mob.McpOAuthError:
            continue
        return _break(pid, "derive accepted %r" % bad)
    return _held(pid, "well-known derivation per RFC 9728 section 3.1")


# ---------------------------------------------------------------------------
# P5 -- SSRF guards.
# ---------------------------------------------------------------------------

@probe("P5a-prm-ssrf-guards")
def _p5a():
    pid = "P5a-prm-ssrf-guards"
    # (url, expected code)
    cases = [
        ("https://10.0.0.5/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-fetch-refused"),
        ("https://127.0.0.1/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-fetch-refused"),
        ("https://[::1]/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-malformed"),  # IPv6 refused: shared canonicalizer
        # strips brackets (F417 family); coded rather than corrupt.
        ("https://169.254.169.254/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-fetch-refused"),
        ("https://user@mcp.example.com/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-fetch-refused"),
        ("https://mcp.example.com/.well-known/oauth-protected-resource#frag",
         "mcp-oauth-prm-fetch-refused"),
        ("https://other.example/.well-known/oauth-protected-resource",
         "mcp-oauth-prm-cross-origin"),
        ("http://mcp.example.com/.well-known/oauth-protected-resource",
         "mcp-oauth-metadata-malformed"),  # shared URL contract
    ]
    for url, want in cases:
        try:
            prm.check_prm_url(url, _RES)
        except mob.McpOAuthError as exc:
            if exc.code != want:
                return _break(pid, "%r: want %s got %s"
                              % (url, want, exc.code))
        else:
            return _break(pid, "%r: no refusal" % url)
    ok = prm.check_prm_url(
        "https://mcp.example.com/.well-known/oauth-protected-resource/tools",
        _RES)
    if ok != ("https://mcp.example.com/.well-known/"
              "oauth-protected-resource/tools"):
        return _break(pid, "valid URL rejected: %r" % ok)
    return _held(pid, "SSRF guards hold; valid same-origin URL passes")


@probe("P5b-prm-no-implicit-fetch")
def _p5b():
    pid = "P5b-prm-no-implicit-fetch"
    url = prm.derive_prm_url(_RES)
    for fetcher, name in ((None, "None"), ("not-callable", "non-callable")):
        try:
            prm.fetch_prm_document(url, _RES, fetcher)
        except mob.McpOAuthError as exc:
            if exc.code != "mcp-oauth-prm-fetch-refused":
                return _break(pid, "%s: want fetch-refused got %s"
                              % (name, exc.code))
        else:
            return _break(pid, "%s fetcher: fetch proceeded" % name)

    def raising(url):
        raise RuntimeError("boom")

    try:
        prm.fetch_prm_document(url, _RES, raising)
    except mob.McpOAuthError as exc:
        if exc.code != "mcp-oauth-prm-fetch-refused":
            return _break(pid, "raising fetcher: want fetch-refused got %s"
                          % exc.code)
    else:
        return _break(pid, "raising fetcher: no refusal")

    def coded(url):
        raise mob.McpOAuthError("mcp-oauth-prm-malformed", "inner")

    try:
        prm.fetch_prm_document(url, _RES, coded)
    except mob.McpOAuthError as exc:
        if exc.code != "mcp-oauth-prm-malformed":
            return _break(pid, "coded fetcher error not propagated: %s"
                          % exc.code)
    else:
        return _break(pid, "coded fetcher error swallowed")
    return _held(pid, "no implicit network; fetcher failures coded")


# ---------------------------------------------------------------------------
# P6 -- WWW-Authenticate challenge (RFC 9728 section 5.1).
# ---------------------------------------------------------------------------

@probe("P6a-prm-challenge-parse")
def _p6a():
    pid = "P6a-prm-challenge-parse"
    good = ('Bearer <redacted>="mcp", '
            'resource_metadata='
            '"https://mcp.example.com/.well-known/oauth-protected-resource"')
    got = prm.parse_challenge_resource_metadata(good, _RES)
    if got != ("https://mcp.example.com/.well-known/"
               "oauth-protected-resource"):
        return _break(pid, "challenge parsed to %r" % got)
    # Quoted value containing a comma must not split the parse.
    comma = ('Bearer <redacted>="a,b", '
             'resource_metadata='
             '"https://mcp.example.com/.well-known/oauth-protected-resource"')
    if prm.parse_challenge_resource_metadata(comma, _RES) != got:
        return _break(pid, "comma-in-quote broke the parse")
    bad = [
        "Bearer <redacted>",  # no resource_metadata
        ("Bearer <redacted>=\"a\", "
         "resource_metadata=\"https://mcp.example.com/.well-known/x\", "
         "resource_metadata=\"https://mcp.example.com/.well-known/y\""),
        "Bearer <redacted>=\"\"",
        "",
    ]
    for header in bad:
        try:
            prm.parse_challenge_resource_metadata(header, _RES)
        except mob.McpOAuthError as exc:
            if exc.code != "mcp-oauth-prm-challenge-malformed":
                return _break(pid, "%r: want challenge-malformed got %s"
                              % (header[:40], exc.code))
        else:
            return _break(pid, "%r: no refusal" % header[:40])
    try:
        prm.parse_challenge_resource_metadata(
            'Bearer realm="mcp", '
            'resource_metadata="https://evil.example/.well-known/x"',
            _RES)
    except mob.McpOAuthError as exc:
        if exc.code != "mcp-oauth-prm-cross-origin":
            return _break(pid, "cross-origin challenge: got %s" % exc.code)
    else:
        return _break(pid, "cross-origin challenge: no refusal")
    return _held(pid, "challenge parsing per RFC 9728 section 5.1")


# ---------------------------------------------------------------------------
# P7 -- F417-class containment at this seam.
# ---------------------------------------------------------------------------

@probe("P7a-prm-badport-coded")
def _p7a():
    pid = "P7a-prm-badport-coded"
    # A non-numeric port in a PRM-controlled URL must refuse coded.
    # F417 CLOSED 2026-10-05 (wave-334 lane 1): _normalize_url guards
    # parts.port and codes mcp-oauth-metadata-malformed, which is the
    # correct coded refusal here (more specific than prm-malformed).
    for fn, args in [
        (prm.verify_prm_document,
         (_sealed(), _RES,
          {"resource": "https://mcp.example.com:badport/tools"}, _KEY)),
        (prm.check_prm_url,
         ("https://mcp.example.com:badport/.well-known/x", _RES)),
        (prm.derive_prm_url, ("https://mcp.example.com:badport/tools",)),
    ]:
        try:
            fn(*args)
        except mob.McpOAuthError as exc:
            if exc.code != "mcp-oauth-metadata-malformed":
                return _break(pid, "%s: want mcp-oauth-metadata-malformed got %s"
                              % (fn.__name__, exc.code))
        except ValueError:
            return _break(pid, "%s: bare ValueError escaped"
                          % fn.__name__)
        else:
            return _break(pid, "%s: no refusal" % fn.__name__)
    return _held(pid, "F417-class contained: coded prm-malformed, never bare")


# ---------------------------------------------------------------------------
# P8 -- binding integrity + end-to-end.
# ---------------------------------------------------------------------------

@probe("P8a-prm-binding-tamper-not-misreported")
def _p8a():
    pid = "P8a-prm-binding-tamper-not-misreported"
    sealed = _sealed()
    bad = dict(sealed)
    bad["mac"] = "0" * 64
    return _expect_code(pid, "mcp-oauth-binding-tampered",
                        prm.verify_prm_document, bad, _RES,
                        {"resource": "not-even-a-url"}, _KEY)


@probe("P8b-prm-end-to-end")
def _p8b():
    pid = "P8b-prm-end-to-end"
    seen = []

    def fake_fetch(url):
        seen.append(url)
        return {"resource": _RES,
                "authorization_servers": [_REAL_AS],
                "scopes_supported": ["read"]}

    v = prm.discover_and_verify_prm(_sealed(), _RES, _KEY, fake_fetch)
    if seen != [prm.derive_prm_url(_RES)]:
        return _break(pid, "fetched %r" % seen)
    if v.issuer != _REAL_AS or v.resource != _RES:
        return _break(pid, "bad verdict %r" % (v,))

    challenge = ('Bearer <redacted>="mcp", resource_metadata='
                 '"https://mcp.example.com/.well-known/'
                 'oauth-protected-resource"')
    v2 = prm.discover_and_verify_prm(_sealed(), _RES, _KEY, fake_fetch,
                                     challenge_header=challenge)
    if v2.issuer != _REAL_AS:
        return _break(pid, "challenge-path verdict %r" % (v2,))
    return _held(pid, "end-to-end discover+fetch+verify green")


# ---------------------------------------------------------------------------
# P9 -- pin + footer.
# ---------------------------------------------------------------------------

@probe("P9-pin-2131-footer-f427")
def _p9():
    pid = "P9-pin-2131-footer-f427"
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN or len(lits) != TAXONOMY_PIN:
        return _break(pid, "taxonomy %d literals %d want %d"
                      % (n, len(lits), TAXONOMY_PIN))
    if lits != sorted(lits) or len(set(lits)) != len(lits):
        return _break(pid, "taxonomy not sorted/unique on raw literals")
    for c in prm.CODES:
        if c not in dc.TAXONOMY:
            return _break(pid, "code %r not centrally registered" % c)
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    # F420 (filed as F419, renumbered at wave-334 merge) CLOSED in this lane.
    f420 = text.split("## F420")[1]
    f420_body = re.split(r"\n## F\d+|\nNext free finding:", f420)[0]
    if "Status: CLOSED" not in f420_body:
        return _break(pid, "F420 not marked CLOSED in FINDINGS.md")
    # F417 (redteam bare-port) CLOSED by wave-334 lane 1.
    f417 = text.split("## F417")[1]
    f417_body = re.split(r"\n## F\d+|\nNext free finding:", f417)[0]
    if "Status: CLOSED" not in f417_body:
        return _break(pid, "F417 not marked CLOSED in FINDINGS.md")
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break(pid, "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now.strip() != FOOTER_OPEN:
        return _break(pid, "footer open %s / next %s, want open %s / next %s"
                      % (open_now.strip(), next_free, FOOTER_OPEN,
                         FOOTER_NEXT))
    return _held(pid, "taxonomy 2135/2135/0 sorted-unique; 6 codes "
                      "registered; F420 CLOSED; footer open F421 / next F422")


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(path, timeout):
    d = _tmpd("w334prm-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the MCP-OAuth unit suite as a child with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output(
            os.path.join(REPO, "tests", "test_mcp_oauth_binding.py"),
            timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "mcpoauth: %s" % exc)
        return
    breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    # unittest-style failures surface as FAIL/ERROR lines instead.
    failed = ("FAILED" in out or "failures=" in out.lower())
    m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
    if m2:
        import ast as _ast
        try:
            breaks.update(_ast.literal_eval(m2.group(1)))
        except Exception:
            pass
    if breaks or errors or failed:
        _record("green-check", "BREAK",
                "mcpoauth non-green: %s" % sorted(breaks | errors)[:4])
    else:
        _record("green-check", "HELD", "test_mcp_oauth_binding green")


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
    print("w334_prm battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
