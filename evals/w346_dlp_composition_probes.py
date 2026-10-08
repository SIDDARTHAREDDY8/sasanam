#!/usr/bin/env python3
"""Wave-346 DLP layer-composition audit battery (lane 6).

After the wave-342..345 closure series (F428 JSFuck, F429 text escapes,
F430 JS string expressions, F431 bidi + Cyrillic homoglyphs, F432
single-escape threshold, F433 CSS non-hex terminators, F434
Array.join, F435 Greek/Cherokee homoglyphs -- all CLOSED; F436 narrowed
OPEN), this battery proves the decode LAYERS COMPOSE: for pairs of
encoding layers (URL x base64 x hex x base32 x escape x entity x
JS-expression x confusable x bidi x CSS-escape), a credential encoded
through two layers in sequence must still block, because
_decoded_variants runs 2 decode layers and each _decode_layer step
applies every sub-decoder independently.

Every stacked shape carries a REAL-PARSER roundtrip ground truth: the
shape is only a genuine attack if an actual parser stack recovers the
credential (base64.b64decode / html.unescape / urllib.parse.unquote /
unicode_escape / a CSS Syntax L3 4.3.7 escape decoder / a minimal
JS-concat evaluator). Shapes whose roundtrip fails are test bugs, not
findings -- the probe asserts the roundtrip first.

Audit outcome (2026-10-05, all verified on the merged tree):
  * 25 composition pairs: all BLOCK coded dlp-slack-token (layers compose).
  * F436 (OPEN): 2 narrowed residuals still MISS (expected BREAKs).
  * F440 (LOW, CLOSED 2026-10-06 wave-347 lane 4; filed wave-346 lane 6,
    renumbered F437->F440 at merge): double-HTML-entity encoding --
    ``&amp;#xHH;`` / ``&#38;#xHH;`` / ``&amp#xHH;`` -- evaded the entity
    sub-layer (the _ENTITY_RUN regex never matched named entities, and
    numeric-wrapped runs fragmented so the inner entity never
    materialized within the 2-layer budget). Closed by the whole-text
    bounded named+numeric double-decode layer (F440); the amp-numeric
    shape had already been absorbed by the F436 closure (wave-346 merge
    scope note). 3 residuals + 1 absorbed control, all assert coded
    refusal.
  * F441 (LOW, CLOSED 2026-10-05 wave-347 lane 5; filed wave-346 lane 6,
    renumbered F438->F441 at merge): double-backslash escapes --
    ``\\\\uXXXX`` / ``\\\\xXX`` -- evaded the escape sub-layer (no
    ``\\\\`` -> ``\\`` production; the inner escape decoded inside-out).
    Closed by the escaped-backslash whole-text production (F441), wired
    FIRST in _decode_layer before the per-run escape layers. 4 shapes,
    all assert coded refusal.
  * Documented design boundaries (pinned HELD, NOT findings):
    - depth-4+ base64 stacks miss: the base64 decode-until-fixpoint
      is bounded at 3 rounds (F439, wave-347 lane 3); depth-4+ is the
      stated boundary, same family as the documented ASCII gate.
    - F429's ASCII-printable escape gate rejects escape runs decoding
      to non-ASCII (documented strictness, wave-344 lane 2 P7).
  * Discrimination: honest double-encoded text, Windows paths,
    ``&amp;`` prose, and innocent base64 stay quiet.

Expected state on the CLOSED tree (w311_redteam convention):
  0 BREAK / 45 HELD / 0 ERROR, exit 0; F436's 2 residuals are CLOSED (wave-346 lane 1), F440's 3 residuals + 1 absorbed control are CLOSED (wave-347 lane 4), F441's 4 shapes are CLOSED (wave-347 lane 5) and all assert coded refusal. Any
  unexpected BREAK (a
  finding closed without flipping its probes -- the wave-306 lesson),
  fails the battery.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here. Do NOT add ModelDriver/SpendLedger usage here.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w346_dlp_composition_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import binascii
import codecs
import html
import subprocess
import sys
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-346: pin 2134 (no new codes in lane 6); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F595, F606, F607, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (4/5): F454-F460 CLOSED; open none (next F461)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # Wave-352 merge (2/5): F456+F457 CLOSED; F458-F460 still OPEN (next F461)  # Wave-351 lanes 1+3: F451+F453 CLOSED (merge finalizes tree-wide); F452 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 lane 4: F458-F460 CLOSED (merge finalizes tree-wide); Wave-351 lanes 1+3: F451+F453 CLOSED (merge finalizes tree-wide); F452 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 2: F463 CLOSED, F469 filed OPEN (next F470)  # Wave-353 lane 2 renumber: F469->F472 (attack lane committed F469-F471 first, e79af076); footer next F473  # Wave-353 lane 1: F461+F462 CLOSED (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-354: F470 CLOSED  # Wave-354 lane 3: F471 CLOSED  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 lane 5: F603 CLOSED  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED

FOOTER_NEXT = "F612"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 lane 3: next F612 (F607 CLOSED locally)


from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential (base64 = 52 chars, well over the 24-char precision
# guard). Constructed via concatenation -- never a literal.
_CRED = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"
_RULE = "dlp-slack-token"


# ------------------------------------------------------- payload builders
def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _hex(s):
    return binascii.hexlify(s.encode()).decode()


def _b32(s):
    return base64.b32encode(s.encode()).decode()


def _url(s):
    return "".join("%%%02X" % ord(c) for c in s)


def _esc_x(s):
    return "".join("\\x%02x" % ord(c) for c in s)


def _ent_hex(s):
    return "".join("&#x%x;" % ord(c) for c in s)


def _jsconcat(a, b):
    return '"%s" + "%s"' % (a, b)


def _css_nospace(s):
    # CSS escapes terminated by the next backslash (non-hex, not
    # consumed); the final char is terminated by end-of-input.
    return "".join("\\%x" % ord(c) for c in s)


# ------------------------------------------------------- roundtrip ground truth
def _rt_url_b64(p):
    return base64.b64decode(urllib.parse.unquote(p)).decode() == _CRED


def _rt_b64_url(p):
    return urllib.parse.unquote(base64.b64decode(p).decode()) == _CRED


def _rt_b64_hex(p):
    return bytes.fromhex(base64.b64decode(p).decode()).decode() == _CRED


def _rt_hex_b64(p):
    return base64.b64decode(bytes.fromhex(p).decode()).decode() == _CRED


def _rt_b64_esc(p):
    return codecs.decode(
        base64.b64decode(p).decode().encode("ascii"),
        "unicode_escape") == _CRED


def _rt_esc_b64(p):
    return base64.b64decode(
        codecs.decode(p.encode("ascii"), "unicode_escape")) == _CRED.encode()


def _rt_b64_ent(p):
    return html.unescape(base64.b64decode(p).decode()) == _CRED


def _rt_ent_b64(p):
    return base64.b64decode(html.unescape(p)).decode() == _CRED


def _rt_jsconcat(s):
    # minimal "..." + "..." evaluator (test-only ground truth)
    parts, cur, inq = [], [], False
    for c in s:
        if c == '"' and not inq:
            inq = True
        elif c == '"' and inq:
            inq = False
            parts.append("".join(cur))
            cur = []
        elif inq:
            cur.append(c)
    return "".join(parts)


def _rt_b64_jsconcat(p):
    return _rt_jsconcat(base64.b64decode(p).decode()) == _CRED


def _rt_jsconcat_ent(p):
    return _rt_jsconcat(html.unescape(p)) == _CRED


def _rt_url_url(p):
    return urllib.parse.unquote(urllib.parse.unquote(p)) == _CRED


def _rt_b64_b64(p):
    return base64.b64decode(base64.b64decode(p)).decode() == _CRED


def _rt_url_esc(p):
    return codecs.decode(
        urllib.parse.unquote(p).encode("ascii"),
        "unicode_escape") == _CRED


def _rt_hex_url(p):
    return urllib.parse.unquote(bytes.fromhex(p).decode()) == _CRED


def _rt_b32_esc(p):
    return codecs.decode(
        base64.b32decode(p).decode().encode("ascii"),
        "unicode_escape") == _CRED


def _rt_esc_b32(p):
    return base64.b32decode(
        codecs.decode(p.encode("ascii"), "unicode_escape")) == _CRED.encode()


def _rt_confusable_jsconcat(p, homoglyph):
    return _rt_jsconcat(p).replace(homoglyph, "o") == _CRED


def _rt_bidi_jsconcat(p):
    # payload = RLO + reversed('"A" + "B"'); visual order is the concat
    return _rt_jsconcat(p[1:][::-1]) == _CRED


def _rt_esc_ent_mix(p):
    return html.unescape(
        codecs.decode(p.encode("ascii"), "unicode_escape")) == _CRED


def _rt_url_ent(p):
    return html.unescape(urllib.parse.unquote(p)) == _CRED


def _rt_b64_join(p):
    inner = base64.b64decode(p).decode()
    a = inner.split('["')[1].split('"]')[0].split('", "')
    return "".join(a) == _CRED


def _rt_join_esc(p):
    a = p.split('["')[1].split('"]')[0].split('", "')
    return "".join(
        codecs.decode(x.encode("ascii"), "unicode_escape")
        for x in a) == _CRED


def _rt_hex_hex(p):
    return bytes.fromhex(bytes.fromhex(p).decode()).decode() == _CRED


def _rt_b64_fcc(p):
    inner = base64.b64decode(p).decode()
    body = inner[len("String.fromCharCode("):-1]
    return "".join(chr(int(x)) for x in body.split(",")) == _CRED


def _rt_css(s):
    # minimal CSS Syntax L3 4.3.7 escape decoder (independent of gov/dlp)
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            j, h = i + 1, ""
            while j < n and len(h) < 6 and s[j] in "0123456789abcdefABCDEF":
                h += s[j]
                j += 1
            if h:
                out.append(chr(int(h, 16)))
                if j < n and s[j] in " \t\n\f":
                    j += 1
                elif j + 1 < n and s[j] == "\r" and s[j + 1] == "\n":
                    j += 2
                i = j
                continue
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _rt_b64_css(p):
    return _rt_css(base64.b64decode(p).decode()) == _CRED


def _rt_f437_double_unescape(p):
    return html.unescape(html.unescape(p)) == _CRED


def _rt_f437_b64(p):
    return html.unescape(
        html.unescape(base64.b64decode(p).decode())) == _CRED


def _rt_f438_double_unescape(p):
    once = codecs.decode(p.encode("ascii"), "unicode_escape")
    return codecs.decode(once.encode("ascii"), "unicode_escape") == _CRED


def _rt_f438_url(p):
    once = codecs.decode(
        urllib.parse.unquote(p).encode("ascii"), "unicode_escape")
    return codecs.decode(once.encode("ascii"), "unicode_escape") == _CRED


def _rt_f436a(p):
    # tolerant no-semicolon unescape (HTML5 legacy form, per F436)
    import re
    t = re.sub(r"&#(\d+)(?![\d;])",
               lambda m: chr(int(m.group(1))), p)
    return base64.b64decode(html.unescape(t)).decode() == _CRED


def _rt_f436b(p):
    return base64.b64decode(html.unescape(p)).decode() == _CRED


def _blocked(payload):
    return dlp.find_credential(payload) == _RULE


# ------------------------------------------------------------------ probes
def _mk(payload_fn, rt_fn, pid):
    def fn():
        payload = payload_fn()
        assert _CRED not in payload, "%s smuggles plaintext" % pid
        assert rt_fn(payload), "%s: roundtrip broken (test bug)" % pid
        return _blocked(payload)
    fn.__name__ = pid
    return fn


def _mk_absorbed(payload_fn, rt_fn, pid):
    """Absorbed-shape control: asserts the shape now BLOCKS (HELD).

    Used for shapes the F436 closure (wave-346 lane 1) absorbed at the
    wave-346 merge. A STILL-MISS here is a BREAK (absorption regressed)."""
    def fn():
        payload = payload_fn()
        assert _CRED not in payload, "%s smuggles plaintext" % pid
        assert rt_fn(payload), "%s: roundtrip broken (test bug)" % pid
        blocked = _blocked(payload)
        print("    [%s absorbed-shape %s]" % (
            pid, "blocks" if blocked else "STILL-MISS"))
        return blocked
    fn.__name__ = pid
    return fn


_OMICRON = "о"  # Cyrillic small o (U+043E) -- literal confusable char
_RLO = "‮"  # U+202E RIGHT-TO-LEFT OVERRIDE

_PROBES = [
    # --- 25 composition pairs: every one must BLOCK (layers compose) ---
    ("compose-url-b64",
     _mk(lambda: _url(_b64(_CRED)), _rt_url_b64, "compose-url-b64")),
    ("compose-b64-url",
     _mk(lambda: _b64(_url(_CRED)), _rt_b64_url, "compose-b64-url")),
    ("compose-b64-hex",
     _mk(lambda: _b64(_hex(_CRED)), _rt_b64_hex, "compose-b64-hex")),
    ("compose-hex-b64",
     _mk(lambda: _hex(_b64(_CRED)), _rt_hex_b64, "compose-hex-b64")),
    ("compose-b64-esc",
     _mk(lambda: _b64(_esc_x(_CRED)), _rt_b64_esc, "compose-b64-esc")),
    ("compose-esc-b64",
     _mk(lambda: _esc_x(_b64(_CRED)), _rt_esc_b64, "compose-esc-b64")),
    ("compose-b64-entity",
     _mk(lambda: _b64(_ent_hex(_CRED)), _rt_b64_ent, "compose-b64-entity")),
    ("compose-entity-b64",
     _mk(lambda: _ent_hex(_b64(_CRED)), _rt_ent_b64, "compose-entity-b64")),
    ("compose-b64-jsconcat",
     _mk(lambda: _b64(_jsconcat(_CRED[:12], _CRED[12:])),
         _rt_b64_jsconcat, "compose-b64-jsconcat")),
    ("compose-jsconcat-entity",
     _mk(lambda: _jsconcat(_ent_hex(_CRED[:6]), _CRED[6:]),
         _rt_jsconcat_ent, "compose-jsconcat-entity")),
    ("compose-url-url",
     _mk(lambda: _url(_url(_CRED)), _rt_url_url, "compose-url-url")),
    ("compose-b64-b64",
     _mk(lambda: _b64(_b64(_CRED)), _rt_b64_b64, "compose-b64-b64")),
    ("compose-url-esc",
     _mk(lambda: _url(_esc_x(_CRED)), _rt_url_esc, "compose-url-esc")),
    ("compose-hex-url",
     _mk(lambda: _hex(_url(_CRED)), _rt_hex_url, "compose-hex-url")),
    ("compose-b32-esc",
     _mk(lambda: _b32(_esc_x(_CRED)), _rt_b32_esc, "compose-b32-esc")),
    ("compose-esc-b32",
     _mk(lambda: _esc_x(_b32(_CRED)), _rt_esc_b32, "compose-esc-b32")),
    ("compose-confusable-jsconcat",
     _mk(lambda: _jsconcat(_CRED[:12].replace("o", _OMICRON, 1),
                           _CRED[12:]),
         lambda p: _rt_confusable_jsconcat(p, _OMICRON),
         "compose-confusable-jsconcat")),
    ("compose-bidi-jsconcat",
     _mk(lambda: _RLO + _jsconcat(_CRED[:12], _CRED[12:])[::-1],
         _rt_bidi_jsconcat, "compose-bidi-jsconcat")),
    ("compose-esc-entity-mix",
     _mk(lambda: "\\x26" + "#x%x;" % ord(_CRED[0]) + _CRED[1:],
         _rt_esc_ent_mix, "compose-esc-entity-mix")),
    ("compose-url-entity",
     _mk(lambda: _url("&#x%x;" % ord(_CRED[0])) + _CRED[1:],
         _rt_url_ent, "compose-url-entity")),
    ("compose-b64-join",
     _mk(lambda: _b64('["%s", "%s"].join("")'
                      % (_CRED[:12], _CRED[12:])),
         _rt_b64_join, "compose-b64-join")),
    ("compose-join-esc",
     _mk(lambda: '["%s", "%s"].join("")'
                 % (_esc_x(_CRED[:12]), _esc_x(_CRED[12:])),
         _rt_join_esc, "compose-join-esc")),
    ("compose-hex-hex",
     _mk(lambda: _hex(_hex(_CRED)), _rt_hex_hex, "compose-hex-hex")),
    ("compose-b64-fromcharcode",
     _mk(lambda: _b64("String.fromCharCode(%s)"
                      % ",".join(str(ord(c)) for c in _CRED)),
         _rt_b64_fcc, "compose-b64-fromcharcode")),
    ("compose-b64-css-nospace",
     _mk(lambda: _b64(_css_nospace(_CRED)),
         _rt_b64_css, "compose-b64-css-nospace")),

    # --- F436 (CLOSED 2026-10-05 wave-346 lane 1): residuals now assert coded refusal ---
    ("f436-residual-no-semicolon",
     _mk(lambda: "&#%d" % ord(_b64(_CRED)[0]) + _b64(_CRED)[1:],
         _rt_f436a, "f436-residual-no-semicolon")),
    ("f436-residual-two-apart",
     _mk(lambda: (lambda b: "&#%d;" % ord(b[0]) + b[1:25]
                  + "&#%d;" % ord(b[25]) + b[26:])(_b64(_CRED)),
         _rt_f436b, "f436-residual-two-apart")),

    # --- F440 (CLOSED 2026-10-06 wave-347 lane 4): double-entity residuals
    # now assert coded refusal ---
    ("f440-amp-named",
     _mk(lambda: "".join("&amp;#x%x;" % ord(c) for c in _CRED),
         _rt_f437_double_unescape, "f440-amp-named")),
    # f440-amp-numeric ABSORBED by the F436 closure (wave-346 lane 1
    # whole-text entity pass): now blocks. Kept as a control asserting the
    # absorption holds (wave-346 merge scope note on F440).
    ("f440-amp-numeric-absorbed",
     _mk_absorbed(lambda: "".join("&#38;#x%x;" % ord(c) for c in _CRED),
                  _rt_f437_double_unescape, "f440-amp-numeric-absorbed")),
    ("f440-amp-no-semicolon",
     _mk(lambda: "".join("&amp#x%x;" % ord(c) for c in _CRED),
         _rt_f437_double_unescape, "f440-amp-no-semicolon")),
    ("f440-b64-stacked",
     _mk(lambda: _b64("".join("&amp;#x%x;" % ord(c) for c in _CRED)),
         _rt_f437_b64, "f440-b64-stacked")),

    # --- F441 (CLOSED 2026-10-05 wave-347 lane 5): double-backslash
    # shapes now assert coded refusal ---
    ("f441-bslash-u",
     _mk_absorbed(lambda: "".join("\\\\u%04x" % ord(c) for c in _CRED),
         _rt_f438_double_unescape, "f441-bslash-u")),
    ("f441-bslash-x",
     _mk_absorbed(lambda: "".join("\\\\x%02x" % ord(c) for c in _CRED),
         _rt_f438_double_unescape, "f441-bslash-x")),
    ("f441-bslash-mixed",
     _mk_absorbed(lambda: "".join("\\\\u%04x" % ord(c) for c in _CRED[:19])
                 + "".join("\\\\x%02x" % ord(c) for c in _CRED[19:]),
         _rt_f438_double_unescape, "f441-bslash-mixed")),
    ("f441-url-stacked",
     _mk_absorbed(lambda: _url("".join("\\\\u%04x" % ord(c)
                              for c in _CRED[:12]))
                 + "".join("\\\\u%04x" % ord(c) for c in _CRED[12:]),
         _rt_f438_url, "f441-url-stacked")),
]


def p_bound_depth3_b64():
    payload = _b64(_b64(_b64(_CRED)))
    assert base64.b64decode(
        base64.b64decode(base64.b64decode(payload))).decode() == _CRED
    # F439 CLOSED (wave-347 lane 3): the bounded base64
    # decode-until-fixpoint (max 3 rounds) blocks triple stacks coded.
    return dlp.find_credential(payload) == "dlp-slack-token"


def p_bound_depth3_url_b64_url():
    payload = _url(_b64(_url(_CRED)))
    assert urllib.parse.unquote(
        base64.b64decode(urllib.parse.unquote(payload)).decode()) == _CRED
    return dlp.find_credential(payload) is None


def p_bound_depth3_esc_b64_hex():
    payload = _esc_x(_b64(_hex(_CRED)))
    assert bytes.fromhex(base64.b64decode(codecs.decode(
        payload.encode("ascii"), "unicode_escape")).decode()).decode() == _CRED
    return dlp.find_credential(payload) is None


def p_bound_ascii_gate_cyrillic_esc():
    # single-backslash escapes (one unicode_escape pass -> homoglyph text)
    payload = "".join("\\u%04x" % ord(c)
                      for c in _CRED.replace("o", _OMICRON, 1))
    assert codecs.decode(
        payload.encode("ascii"), "unicode_escape").replace(
            _OMICRON, "o") == _CRED
    # F429's ASCII-printable escape gate: documented strictness
    return dlp.find_credential(payload) is None


def p_quiet_double_b64_innocent():
    payload = _b64(_b64("deployment config value xyzzy-1234"))
    return dlp.find_credential(payload) is None


def p_quiet_url_path():
    return dlp.find_credential("%5CUsers%5Cadmin%5Cdocs") is None


def p_quiet_b64_prose():
    payload = _b64("hello world this is a routine status message")
    return dlp.find_credential(payload) is None


def p_quiet_winpath_double_backslash():
    return dlp.find_credential("C:\\\\Users\\\\admin\\\\docs") is None


def p_quiet_amp_prose():
    return dlp.find_credential("fish &amp; chips &#x41;") is None


def p_pin_and_footer():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    footer = ""
    for ln in reversed(lines):
        if "Next free finding:" in ln:
            footer = ln
            break
    ok = ok and ("Next free finding: **%s**." % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return ok


_PROBES += [
    ("bound-depth3-b64", p_bound_depth3_b64),
    ("bound-depth3-url-b64-url", p_bound_depth3_url_b64_url),
    ("bound-depth3-esc-b64-hex", p_bound_depth3_esc_b64_hex),
    ("bound-ascii-gate-cyrillic-esc", p_bound_ascii_gate_cyrillic_esc),
    ("quiet-double-b64-innocent", p_quiet_double_b64_innocent),
    ("quiet-url-path", p_quiet_url_path),
    ("quiet-b64-prose", p_quiet_b64_prose),
    ("quiet-winpath-double-backslash", p_quiet_winpath_double_backslash),
    ("quiet-amp-prose", p_quiet_amp_prose),
    ("pin-footer", p_pin_and_footer),
]


# ------------------------------------------------- expected BREAKs + runner
_EXPECTED_BREAKS = set()  # F440's residuals + absorbed control CLOSED (wave-347 lane 4);
# F441's 4 shapes CLOSED (wave-347 lane 5) -- all assert coded refusal.


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001 - battery harness reports
        print("%-36s ERROR %s: %s" % (pid, type(e).__name__, e))
        return (pid, "ERROR")
    print("%-36s %s" % (pid, "HELD" if ok else "BREAK"))
    return (pid, "HELD" if ok else "BREAK")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w345_attack_probes.py", "w345_f432close_probes.py"):
        tmp = "/var/tmp/g346-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w346_dlp_composition: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    # Open-findings sweep: exactly the expected BREAKs (all OPEN).
    # Exit 1 when any BREAK is present (open findings), like the
    # w310/w311 red-team batteries.
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing (finding closed? flip the probe): %s"
              % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
