#!/usr/bin/env python3
"""Wave-337 lane 3 battery: CIMD safe-subset (gov/mcp_cimd.py).

Base: 2f270987 (wave-336 merge). Pin: 2121 (+15 mcp-oauth-cimd-*).
Footer unchanged: open F424, F425 / next F426 (no findings filed here).

Builds w336 research prospectus R1/R2 section 1 (CIMD safe-subset spec):
Part A document emission, Part B URL shape + document binding, Part C
pre-registration intake with the full fetch control set, document-hash
pinning, and key-rotation revocation events.

P1  URL shape rule table (one bypass probe per rule row; all 9 rows).
P2  Document shape contract (credential smuggling, jwks misbinding,
    redirect origin, malformed inputs, MUST-ignore-unknown).
P3  Emission (exact field list, serving contract, fail-closed
    construction, byte-stable canonical form, no logo emitted).
P4  Document binding (string equality, :443 confusion).
P5  Pre-registration intake (mock fetcher/resolver -- all SSRF cases
    offline): happy path, redirect, non-200, SSRF ranges, rebind,
    allowlist, size cap, timeout, transport failure, binding, rotation,
    pinned verification.
P6  Deliberate deviations pinned (no logo prefetch, no loopback
    exception, no CIMD Service, fetch-scheme fold, pin-mismatch fold).
P7  Pin/taxonomy honesty (2140/2140/0 sorted-unique, 15 codes
    registered, footer state).
P8  Green check (depth-1): tests/test_decision_codes.py as a child.

gov/ changes in this lane: gov/mcp_cimd.py (new) + gov/decision_codes.py
(15 new mcp-oauth-cimd-* codes). Findings: none filed.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = (
               "F570", "F571", "F572", "F573",
               "F574", "F575", "F576", "F577",
               "F578", "F579", "F580", "F581",
               "F582"
               )  # F426-F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)

FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _break(pid, "assertion: %s" % exc)
    except Exception:  # noqa: BLE001 - every probe must report, not crash
        _record(pid, "ERROR", traceback.format_exc(limit=3).replace(
            "\n", " | ")[:300])


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _run_root():
    d = os.environ.get("TMPDIR") or tempfile.gettempdir()
    os.makedirs(d, exist_ok=True)
    return d


def _tmpd(prefix="w337cimd-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import mcp_cimd as CIMD  # noqa: E402
from gov import decision_codes as dc  # noqa: E402

_CONTROLS = [chr(c) for c in list(range(0x00, 0x20)) + [0x7F]]


def _expect_code(pid, code, fn):
    """HELD iff fn() raises CIMDError with the expected coded refusal."""
    try:
        fn()
    except CIMD.CIMDError as exc:
        assert exc.code == code, \
            "got %r want %r (%s)" % (exc.code, code, exc)
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError("wrong exception: %r" % exc)
    raise AssertionError("no refusal raised (want %s)" % code)


def _good_doc(**over):
    d = {
        "client_id": "https://client.example.com/oauth/client",
        "client_name": "Example Client",
        "redirect_uris": ["https://client.example.com/cb"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://client.example.com/.well-known/jwks.json",
    }
    d.update(over)
    return d


_DEP = {"trusted_domain_patterns": ["*.example.com", "example.com"],
        "timeout_seconds": 5}


def _mock_world(doc=None, jwks=None, status=200, headers=None, body=None,
                ips=("93.184.216.34",), ips2=None, fetch_exc=None):
    """Build (fetcher, resolver, calls) with everything mocked offline."""
    doc = _good_doc() if doc is None else doc
    jwks = {"keys": []} if jwks is None else jwks
    dbody = CIMD.canonical_document_bytes(doc)
    calls = {"fetch": [], "resolve": []}

    def resolver(host):
        calls["resolve"].append(host)
        if len(calls["resolve"]) > 1 and ips2 is not None:
            return list(ips2)
        return list(ips)

    def fetcher(url, timeout):
        calls["fetch"].append((url, timeout))
        if fetch_exc is not None:
            raise fetch_exc
        if url == doc["client_id"] or url.endswith("/oauth/client"):
            b = dbody if body is None else body
        elif url == doc.get("jwks_uri"):
            b = json.dumps(jwks).encode()
        else:
            raise AssertionError("unexpected fetch: %r" % url)
        return {"status": status, "headers": dict(headers or {}),
                "body": b}

    return fetcher, resolver, calls


# ---------------------------------------------------------------------------
# P1: URL shape rule table.
# ---------------------------------------------------------------------------

@_probe("P1a-scheme")
def _p1a():
    _expect_code("P1a-scheme", CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                 lambda: CIMD.validate_client_id_url(
                     "http://client.example.com/oauth/client"))
    _held("P1a-scheme", "http refused coded")


@_probe("P1b-userinfo")
def _p1b():
    _expect_code("P1b-userinfo", CIMD.MCP_OAUTH_CIMD_URL_USERINFO,
                 lambda: CIMD.validate_client_id_url(
                     "https://user:pass@client.example.com/oauth/client"))
    _held("P1b-userinfo", "userinfo refused coded")


@_probe("P1c-dot-segment")
def _p1c():
    for url in ("https://client.example.com/a/../oauth/client",
                "https://client.example.com/%2e%2e/oauth/client",
                "https://client.example.com/./oauth/client"):
        _expect_code("P1c-dot-segment",
                     CIMD.MCP_OAUTH_CIMD_URL_DOT_SEGMENT,
                     lambda u=url: CIMD.validate_client_id_url(u))
    _held("P1c-dot-segment", "raw and encoded dot segments refused coded")


@_probe("P1d-query")
def _p1d():
    _expect_code("P1d-query", CIMD.MCP_OAUTH_CIMD_URL_QUERY,
                 lambda: CIMD.validate_client_id_url(
                     "https://client.example.com/oauth/client?x=1"))
    _held("P1d-query", "query refused coded (stricter than draft)")


@_probe("P1e-fragment")
def _p1e():
    _expect_code("P1e-fragment", CIMD.MCP_OAUTH_CIMD_URL_FRAGMENT,
                 lambda: CIMD.validate_client_id_url(
                     "https://client.example.com/oauth/client#frag"))
    _held("P1e-fragment", "fragment refused coded")


@_probe("P1f-root-path")
def _p1f():
    for url in ("https://client.example.com",
                "https://client.example.com/"):
        _expect_code("P1f-root-path", CIMD.MCP_OAUTH_CIMD_URL_ROOT_PATH,
                     lambda u=url: CIMD.validate_client_id_url(u))
    _held("P1f-root-path", "empty/root path refused coded (stricter)")


@_probe("P1g-control-chars")
def _p1g():
    for ch in _CONTROLS:
        url = "https://client.example.com/oauth/cl" + ch + "ient"
        try:
            CIMD.validate_client_id_url(url)
        except CIMD.CIMDError as exc:
            assert exc.code == CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS, \
                (repr(ch), exc.code)
            continue
        raise AssertionError("control %r not refused" % ch)
    _held("P1g-control-chars",
          "all 33 ASCII controls refused coded (never stripped)")


@_probe("P1h-bad-port")
def _p1h():
    # F417 class: malformed non-numeric port refuses coded, not uncoded.
    _expect_code("P1h-bad-port", CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                 lambda: CIMD.validate_client_id_url(
                     "https://client.example.com:abc/oauth/client"))
    _held("P1h-bad-port", "non-numeric port refused coded")


@_probe("P1i-legitimate")
def _p1i():
    good = "https://client.example.com:8443/oauth/client"
    assert CIMD.validate_client_id_url(good) == good
    assert CIMD.validate_client_id_url(
        "https://client.example.com/oauth/client")
    _held("P1i-legitimate", "valid URLs (incl. explicit port) pass")


# ---------------------------------------------------------------------------
# P2: document shape contract.
# ---------------------------------------------------------------------------

@_probe("P2a-credential-present")
def _p2a():
    for key in ("client_secret", "client_secret_expires_at"):
        doc = _good_doc(**{key: "smuggled"})
        _expect_code("P2a-credential-present",
                     CIMD.MCP_OAUTH_CIMD_CREDENTIAL_PRESENT,
                     lambda d=doc: CIMD.validate_document_shape(d))
    _held("P2a-credential-present",
          "client_secret* members refused, never ignored")


@_probe("P2b-jwks-misbinding")
def _p2b():
    doc = _good_doc()
    del doc["jwks_uri"]
    _expect_code("P2b-jwks-misbinding",
                 CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                 lambda: CIMD.validate_document_shape(doc))
    doc2 = _good_doc(jwks_uri="http://client.example.com/jwks.json")
    _expect_code("P2b-jwks-misbinding",
                 CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                 lambda: CIMD.validate_document_shape(doc2))
    _held("P2b-jwks-misbinding",
          "private_key_jwt without discoverable https jwks refused")


@_probe("P2c-redirect-origin")
def _p2c():
    doc = _good_doc(
        redirect_uris=["https://attacker.example/steal"])
    _expect_code("P2c-redirect-origin",
                 CIMD.MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                 lambda: CIMD.validate_document_shape(doc))
    doc2 = _good_doc(
        redirect_uris=["http://client.example.com/cb"])
    _expect_code("P2c-redirect-origin",
                 CIMD.MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                 lambda: CIMD.validate_document_shape(doc2))
    _held("P2c-redirect-origin",
          "cross-origin and non-https redirect_uris refused coded")


@_probe("P2d-malformed")
def _p2d():
    for bad in (None, [], "x", {}, {"client_name": "n"}):
        _expect_code("P2d-malformed",
                     CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                     lambda b=bad: CIMD.validate_document_shape(b))
    _held("P2d-malformed", "non-record / client_id-less docs refused")


@_probe("P2e-unknown-ignored")
def _p2e():
    doc = _good_doc(software_statement="ignored",
                    future_extension={"a": 1})
    assert CIMD.validate_document_shape(doc) is True
    _held("P2e-unknown-ignored", "unknown fields ignored (MUST-ignore)")


@_probe("P2f-logo")
def _p2f():
    doc = _good_doc(logo_uri="http://client.example.com/logo.png")
    _expect_code("P2f-logo", CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                 lambda: CIMD.validate_document_shape(doc))
    doc2 = _good_doc(logo_uri="https://client.example.com/logo.png")
    assert CIMD.validate_document_shape(doc2) is True
    _held("P2f-logo", "non-https logo refused; https logo accepted "
                      "but never fetched")


@_probe("P2g-clean-doc")
def _p2g():
    assert CIMD.validate_document_shape(_good_doc()) is True
    _held("P2g-clean-doc", "well-formed document passes")


# ---------------------------------------------------------------------------
# P3: emission.
# ---------------------------------------------------------------------------

@_probe("P3a-emit-shape")
def _p3a():
    doc = CIMD.emit_document("client.example.com", "Example Client",
                             redirect_uris=["https://client.example.com/cb"])
    assert doc["client_id"] == \
        "https://client.example.com/oauth/client", doc["client_id"]
    assert doc["token_endpoint_auth_method"] == "private_key_jwt"
    assert doc["jwks_uri"] == \
        "https://client.example.com/.well-known/jwks.json"
    assert "logo_uri" not in doc, "logo_uri must never be emitted"
    assert not any(k.startswith("client_secret") for k in doc)
    assert "software_statement" not in doc
    _held("P3a-emit-shape", "exact field list; no logo/secret/statement")


@_probe("P3b-emit-fail-closed")
def _p3b():
    _expect_code("P3b-emit-fail-closed",
                 CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                 lambda: CIMD.emit_document("http://evil.example/x", "n"))
    # Cross-origin redirect_uris at emission refuse with the shape
    # contract's own code (emission reuses validate_document_shape).
    _expect_code("P3b-emit-fail-closed",
                 CIMD.MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH,
                 lambda: CIMD.emit_document(
                     "client.example.com", "n",
                     redirect_uris=["https://attacker.example/cb"]))
    _expect_code("P3b-emit-fail-closed",
                 CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED,
                 lambda: CIMD.emit_document("client.example.com", ""))
    _held("P3b-emit-fail-closed",
          "bad domain / cross-origin redirect / empty name refused")


@_probe("P3c-emit-roundtrip")
def _p3c():
    doc = CIMD.emit_document("client.example.com", "Example Client")
    assert CIMD.validate_document_shape(doc) is True
    status, headers, body = CIMD.serve_document(doc)
    assert status == 200, status
    assert headers.get("Content-Type") == "application/json", headers
    assert json.loads(body.decode("utf-8"))["client_id"] == \
        doc["client_id"]
    _held("P3c-emit-roundtrip", "emitted doc validates; 200 + JSON served")


@_probe("P3d-canonical-stable")
def _p3d():
    doc = CIMD.emit_document("client.example.com", "Example Client")
    b1 = CIMD.canonical_document_bytes(doc)
    b2 = CIMD.canonical_document_bytes(
        dict(reversed(list(doc.items()))))
    assert b1 == b2, "canonical form must be key-order independent"
    assert CIMD.document_sha256(doc) == CIMD.document_sha256(b1)
    _held("P3d-canonical-stable", "byte-stable canonical form; sha256 pin")


# ---------------------------------------------------------------------------
# P4: document binding.
# ---------------------------------------------------------------------------

@_probe("P4a-binding")
def _p4a():
    doc = _good_doc()
    assert CIMD.check_document_binding(
        doc, "https://client.example.com/oauth/client") is True
    # Rule 9: simple string comparison -- :443 is NOT the same string.
    _expect_code("P4a-binding", CIMD.MCP_OAUTH_CIMD_BINDING_MISMATCH,
                 lambda: CIMD.check_document_binding(
                     doc, "https://client.example.com:443/oauth/client"))
    evil = _good_doc(
        client_id="https://attacker.example/oauth/client")
    _expect_code("P4a-binding", CIMD.MCP_OAUTH_CIMD_BINDING_MISMATCH,
                 lambda: CIMD.check_document_binding(
                     evil, "https://client.example.com/oauth/client"))
    _held("P4a-binding", "binding by string equality; :443 confusion "
                         "refused")

# ---------------------------------------------------------------------------
# P5: pre-registration intake (all SSRF cases offline via mocks).
# ---------------------------------------------------------------------------

@_probe("P5a-onboard-happy")
def _p5a():
    fetcher, resolver, calls = _mock_world()
    rec = CIMD.onboard_cimd("https://client.example.com/oauth/client",
                            fetcher, _DEP, resolver=resolver)
    assert rec["document_sha256"] == CIMD.document_sha256(
        rec["document"]), "pin must cover the fetched bytes"
    assert len(rec["jwks_sha256"]) == 64
    assert rec["rotation"] is None
    assert calls["fetch"][0][1] == 5  # deployment timeout honored
    _held("P5a-onboard-happy", "onboarding pins document + jwks hashes")


@_probe("P5b-fetch-redirect")
def _p5b():
    fetcher, resolver, _ = _mock_world(
        status=302, headers={"Location": "https://x.example/"})
    _expect_code("P5b-fetch-redirect",
                 CIMD.MCP_OAUTH_CIMD_FETCH_REDIRECT,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5b-fetch-redirect", "redirect never followed; refused coded")


@_probe("P5c-fetch-non200")
def _p5c():
    fetcher, resolver, _ = _mock_world(status=404)
    _expect_code("P5c-fetch-non200",
                 CIMD.MCP_OAUTH_CIMD_FETCH_NON200,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5c-fetch-non200", "non-200 aborts without a document")


@_probe("P5d-ssrf-range")
def _p5d():
    for ip in ("10.1.2.3", "192.168.1.1", "127.0.0.1", "::1",
               "169.254.169.254", "0.0.0.0"):
        fetcher, resolver, calls = _mock_world(ips=(ip,))
        try:
            CIMD.onboard_cimd(
                "https://client.example.com/oauth/client",
                fetcher, _DEP, resolver=resolver)
        except CIMD.CIMDError as exc:
            assert exc.code == CIMD.MCP_OAUTH_CIMD_FETCH_SSRF_RANGE, \
                (ip, exc.code)
            assert not calls["fetch"], \
                "no fetch may happen to a special-range address"
            continue
        raise AssertionError("SSRF range %s not refused" % ip)
    _held("P5d-ssrf-range", "RFC 6890 ranges refused before any fetch")


@_probe("P5e-rebind")
def _p5e():
    fetcher, resolver, _ = _mock_world(
        ips=("93.184.216.34",), ips2=("10.9.9.9",))
    _expect_code("P5e-rebind", CIMD.MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5e-rebind", "DNS rebind detected and refused")


@_probe("P5f-allowlist")
def _p5f():
    fetcher, resolver, calls = _mock_world()
    dep = {"trusted_domain_patterns": ["*.trusted.example"],
           "timeout_seconds": 5}
    _expect_code("P5f-allowlist", CIMD.MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, dep, resolver=resolver))
    assert not calls["resolve"], "untrusted domain: no DNS at all"
    _held("P5f-allowlist", "domain outside allowlist refused pre-DNS")


@_probe("P5g-too-large")
def _p5g():
    big = b"x" * (CIMD.MAX_DOCUMENT_BYTES + 1)
    fetcher, resolver, _ = _mock_world(body=big)
    _expect_code("P5g-too-large", CIMD.MCP_OAUTH_CIMD_FETCH_TOO_LARGE,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5g-too-large", "5 KB cap enforced")


@_probe("P5h-timeout")
def _p5h():
    fetcher, resolver, _ = _mock_world(fetch_exc=TimeoutError("slow"))
    _expect_code("P5h-timeout", CIMD.MCP_OAUTH_CIMD_FETCH_TIMEOUT,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5h-timeout", "timeout refused coded")


@_probe("P5i-transport-failure")
def _p5i():
    fetcher, resolver, _ = _mock_world(
        fetch_exc=ConnectionError("refused"))
    _expect_code("P5i-transport-failure",
                 CIMD.MCP_OAUTH_CIMD_FETCH_NON200,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5i-transport-failure", "transport failure: no document, "
                                   "refused coded")


@_probe("P5j-no-fetcher")
def _p5j():
    _, resolver, _ = _mock_world()
    try:
        CIMD.onboard_cimd("https://client.example.com/oauth/client",
                          None, _DEP, resolver=resolver)
    except TypeError:
        _held("P5j-no-fetcher", "missing fetcher is a loud TypeError")
        return
    raise AssertionError("no fetcher did not fail closed")


@_probe("P5k-intake-binding")
def _p5k():
    evil = _good_doc(client_id="https://attacker.example/oauth/client",
                     redirect_uris=["https://attacker.example/cb"],
                     jwks_uri="https://attacker.example/.well-known/jwks.json")
    fetcher, resolver, _ = _mock_world(doc=evil)
    _expect_code("P5k-intake-binding",
                 CIMD.MCP_OAUTH_CIMD_BINDING_MISMATCH,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5k-intake-binding", "fetched doc bound to the fetch URL")


@_probe("P5l-intake-credential")
def _p5l():
    evil = _good_doc(client_secret="smuggled")
    fetcher, resolver, _ = _mock_world(doc=evil)
    _expect_code("P5l-intake-credential",
                 CIMD.MCP_OAUTH_CIMD_CREDENTIAL_PRESENT,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P5l-intake-credential", "smuggled secret refused at intake")


@_probe("P5m-rotation")
def _p5m():
    fetcher, resolver, _ = _mock_world()
    rec = CIMD.onboard_cimd("https://client.example.com/oauth/client",
                            fetcher, _DEP, resolver=resolver)
    fetcher2, _, _ = _mock_world(jwks={"keys": [{"kty": "OKP"}]})
    sunk = []
    rec2 = CIMD.reonboard_cimd(
        "https://client.example.com/oauth/client", fetcher2, _DEP, rec,
        revocation_sink=sunk.append, resolver=resolver)
    rot = rec2["rotation"]
    assert rot is not None and rot["advisory"] == "key-rotated", rot
    assert len(sunk) == 1, "rotation must emit exactly one event"
    evt = sunk[0]
    assert evt["event_type"] == \
        "urn:sasanam:revocation-push:credential-revoked", evt
    assert evt["subject"]["kind"] == "credential", evt
    assert "key rotation" in evt["reason"], evt["reason"]
    # No rotation -> silent re-pin is forbidden: rotation must be None
    # and no event when the key is unchanged.
    sunk2 = []
    rec3 = CIMD.reonboard_cimd(
        "https://client.example.com/oauth/client", fetcher, _DEP, rec,
        revocation_sink=sunk2.append, resolver=resolver)
    assert rec3["rotation"] is None and not sunk2
    _held("P5m-rotation", "rotation emits credential-revoked; "
                           "unchanged key emits nothing")


@_probe("P5n-verify-pinned")
def _p5n():
    fetcher, resolver, _ = _mock_world()
    rec = CIMD.onboard_cimd("https://client.example.com/oauth/client",
                            fetcher, _DEP, resolver=resolver)
    body = CIMD.canonical_document_bytes(rec["document"])
    assert CIMD.verify_pinned(
        "https://client.example.com/oauth/client", body, rec)
    tampered = CIMD.canonical_document_bytes(
        _good_doc(client_name="Tampered"))
    _expect_code("P5n-verify-pinned",
                 CIMD.MCP_OAUTH_CIMD_BINDING_MISMATCH,
                 lambda: CIMD.verify_pinned(
                     "https://client.example.com/oauth/client",
                     tampered, rec))
    _held("P5n-verify-pinned", "pin mismatch is a binding break "
                               "(documented fold)")


@_probe("P5o-fetch-scheme-fold")
def _p5o():
    # The fetch path is unreachable with a non-https URL: the shape gate
    # fires first, so the fetcher spy is never called.
    fetcher, resolver, calls = _mock_world()
    _expect_code("P5o-fetch-scheme-fold",
                 CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS,
                 lambda: CIMD.onboard_cimd(
                     "http://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    assert not calls["fetch"] and not calls["resolve"]
    _held("P5o-fetch-scheme-fold", "scheme enforced at the shape gate; "
                                  "no separate fetch-scheme code")


# ---------------------------------------------------------------------------
# P6: deliberate deviations pinned.
# ---------------------------------------------------------------------------

@_probe("P6a-no-logo-prefetch")
def _p6a():
    src = open(os.path.join(REPO, "gov", "mcp_cimd.py")).read()
    assert "urllib.request" not in src and "urlopen" not in src, \
        "the module must never fetch"
    assert "socket" in src  # only for the default DNS resolver
    doc = CIMD.emit_document("client.example.com", "Example")
    assert "logo_uri" not in doc
    _held("P6a-no-logo-prefetch", "no logo emitted, none fetched "
                                  "(documented deviation)")


@_probe("P6b-no-loopback-exception")
def _p6b():
    # Draft section 8.6 MAY would allow a dev loopback exception; we
    # refuse loopback unconditionally (production-only rule).
    fetcher, resolver, _ = _mock_world(ips=("127.0.0.1",))
    _expect_code("P6b-no-loopback-exception",
                 CIMD.MCP_OAUTH_CIMD_FETCH_SSRF_RANGE,
                 lambda: CIMD.onboard_cimd(
                     "https://client.example.com/oauth/client",
                     fetcher, _DEP, resolver=resolver))
    _held("P6b-no-loopback-exception", "no dev loopback exception "
                                       "(documented)")


@_probe("P6c-no-cimd-service")
def _p6c():
    src = open(os.path.join(REPO, "gov", "mcp_cimd.py")).read().lower()
    assert "cimd_service" not in src and "provision" not in src, \
        "the module must not operate a CIMD Service"
    _held("P6c-no-cimd-service", "no CIMD Service (draft appendix "
                                 "out of scope)")


# ---------------------------------------------------------------------------
# P7: pin/taxonomy honesty.
# ---------------------------------------------------------------------------

@_probe("P7a-taxonomy-pin")
def _p7a():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert len(lits) == TAXONOMY_PIN == 2140, \
        "literal count %d != pin %d" % (len(lits), TAXONOMY_PIN)
    assert len(set(lits)) == TAXONOMY_PIN, "duplicate code literals"
    assert lits == sorted(lits), "literals not sorted"
    assert len(dc.TAXONOMY) == TAXONOMY_PIN
    missing = [c for c in CIMD.CIMD_CODES if c not in dc.TAXONOMY]
    assert not missing, "unregistered: %r" % missing
    assert all(dc.TAXONOMY[c]["domain"] == "mcp-oauth"
               for c in CIMD.CIMD_CODES)
    assert len(CIMD.CIMD_CODES) == 15
    _held("P7a-taxonomy-pin", "2140/2140/0 sorted-unique; 15 cimd codes "
                              "registered in domain mcp-oauth")


@_probe("P7b-footer")
def _p7b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    assert "Open findings: F595, F606, F607, F608, F609, F610, F611." in text, "footer open findings"  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
    assert "Next free finding: **F612**" in text, "footer next free"  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
    assert "F424" in text and "F425" in text and "F426" in text
    _held("P7b-footer", "footer open F444, F445 / next F446 (F424-F426 filed)")


# ---------------------------------------------------------------------------
# P8: green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(args, timeout):
    d = _tmpd("w337cimd-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: tests/test_decision_codes.py (it owns the
    taxonomy registry contract) as a child with GOV_SKIP_GREEN=1 (fresh
    TMPDIR). Honors GOV_SKIP_GREEN by recording a skip, never spawning."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        rc, out = _run_child_output(
            [sys.executable, "-m", "unittest", "tests.test_decision_codes",
             "-v"], timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "test_decision_codes: %s" % exc)
        return
    bad = re.findall(r"^(FAIL|ERROR):", out, re.M)
    if rc != 0 or bad or "OK" not in out:
        _record("green-check", "BREAK",
                "test_decision_codes non-green rc=%d: %s"
                % (rc, out[-400:]))
    else:
        _record("green-check", "HELD", "test_decision_codes green")


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
    print("w337_cimd battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
