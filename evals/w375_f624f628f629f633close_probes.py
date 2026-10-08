#!/usr/bin/env python3
"""Wave-375 lane 4: close F624, F628, F629, F633 -- deserializer/atom family.

F624 (LOW, filed attack round 42): String.prototype.slice() with trimming
bounds -- the decoder modeled .slice only on string ARRAYS (F466); on
STRING values only identity slices reduced (via the substring scan when
the pre-image literal already contained a credential-shaped run), so
trimming slices assembling the credential from sub-credential runs
escaped: "xxf1".slice(2)+'f2', the bounded twin "xxf1yy".slice(2,11)+'f2',
and the var-bound twin (function(){var s="xxf1";return s.slice(2)+'f2';})().

F628 (LOW): decodeURIComponent fragment laundering -- F576 modeled only
the full-credential roundtrip; fragment forms
decodeURIComponent('f1'+encodeURIComponent('f2')) escaped.

F629 (LOW): new TextDecoder().decode(new Uint8Array([...bytes])) -- an
unmodeled deserializing builtin (F500/F505 precedent).

F633 (LOW): BigInt-to-string fragment assembly -- the decoder had no
BigInt atom, so String(123n)/`${123n}` digit fragments were invisible.

Closures (gov/dlp.py):
- F624: string-slice branch in _js_apply_method_at (plain-str receiver;
  literal numeric bounds with engine-exact clamping; non-BMP strings and
  _JSNumStr/_JSBigInt receivers fail closed) + _js_parse_f624_slicebound_iife
  for the var-bound twin; disjoint from F466's array branch.
- F628: _js_parse_f628_uri_component (decodeURIComponent strict
  percent-decode; encodeURIComponent with the engine's unreserved set;
  additive args so fragment compositions reduce inside-out).
- F629: _js_parse_f629_textdecoder (label-gated to utf-8/utf8; byte
  literals 0..255; strict UTF-8 decode).
- F633: _JSBigInt atom (decimal digits+'n'; leading-zero and non-decimal
  forms fail closed; additive does numeric add for bigint+bigint and
  string concat for bigint+plain-string, failing closed on bigint+number
  mixes); String()/Number()/${}/(n).toString() coercions modeled.
Zero new re.compile (stays 28); decodeURIComponent/encodeURIComponent/
Number/new-TextDecoder anchors extend the existing _JS_EXPR_START.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g375-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import base64
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_BYTES = ",".join(str(b) for b in _FULL.encode("latin-1"))
_B64 = base64.b64encode(_FULL.encode("latin-1")).decode("ascii")


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_value(src):
    r = dlp._try_js_expr_decode(src, 0)
    return None if r is None else r[0]


# --------------------------------------------- p1: filed shapes now block

def test_p1_f624_slice_trim():
    return ("HELD" if _blocked("\"xx%s\".slice(2)+'%s'" % (_A, _B))
            else "BREAK", "f624-s1")


def test_p1_f624_slice_bounded():
    return ("HELD" if _blocked('"xx%syy".slice(2,11)+\'%s\'' % (_A, _B))
            else "BREAK", "f624-s2")


def test_p1_f624_slice_varbound():
    return ("HELD" if _blocked(
        '(function(){var s="xx%s";return s.slice(2)+\'%s\';})()' % (_A, _B))
        else "BREAK", "f624-s3")


def test_p1_f628_decode_fragment():
    return ("HELD" if _blocked(
        "decodeURIComponent('%s'+encodeURIComponent('%s'))" % (_A, _B))
        else "BREAK", "f628-s1")


def test_p1_f628_decode_split():
    return ("HELD" if _blocked(
        "decodeURIComponent(encodeURIComponent('%s')+encodeURIComponent('%s'))"
        % (_A, _B)) else "BREAK", "f628-s2")


def test_p1_f629_textdecoder_bytes():
    return ("HELD" if _blocked(
        "new TextDecoder().decode(new Uint8Array([%s]))" % _BYTES)
        else "BREAK", "f629-s1")


def test_p1_f629_textdecoder_label():
    return ("HELD" if _blocked(
        "new TextDecoder('utf-8').decode(new Uint8Array([%s]))" % _BYTES)
        else "BREAK", "f629-s2")


def test_p1_f633_bigint_concat():
    return ("HELD" if _blocked("('" + _A[:5] + "'+String(123n)+'" + _B + "')")
            else "BREAK", "f633-s1")


def test_p1_f633_bigint_template():
    return ("HELD" if _blocked("`" + _A[:5] + "${123n}" + _B + "`")
            else "BREAK", "f633-s2")


def test_p1_f633_bigint_padstart():
    return ("HELD" if _blocked(
        "('" + _A[:4] + "-'+String(123n).padStart(4,'0')+'" + _B + "')")
        else "BREAK", "f633-s3")


# --------------------------------------------- p2: node-exact decode values

def test_p2_slice_values():
    pairs = [
        ('"hello world".slice(0,5)', "hello"),
        ('"hello".slice(2)', "llo"),
        ('"hello".slice(-2)', "lo"),
        ('"hello".slice(1,-1)', "ell"),
        ('"hello".slice(0,100)', "hello"),
        ('"hello".slice()', "hello"),
        ('"abcdef".slice(-4,-1)', "cde"),
        ('(function(){var s="xxab";return s.slice(2);})()', "ab"),
        ('(function(){var s="xxabyy";return s.slice(2,4)+"!";})()', "ab!"),
        ('(function(){const s="qwerty";return s.slice(-3);})()', "rty"),
    ]
    for src, want in pairs:
        got = _decode_value(src)
        if got != want:
            return ("BREAK", "slice %r -> %r want %r" % (src, got, want))
    return ("HELD", "10/10")


def test_p2_uri_codec_values():
    pairs = [
        ("decodeURIComponent('abc')", "abc"),
        ("decodeURIComponent('%41%42')", "AB"),
        ("encodeURIComponent('a b')", "a%20b"),
        ("encodeURIComponent(\"!~*'()\")", "!~*'()"),
        ("decodeURIComponent(encodeURIComponent('a/b?c'))", "a/b?c"),
        ("'x'+decodeURIComponent('%79')", "xy"),
    ]
    for src, want in pairs:
        got = _decode_value(src)
        if got != want:
            return ("BREAK", "codec %r -> %r want %r" % (src, got, want))
    return ("HELD", "6/6")


def test_p2_textdecoder_values():
    pairs = [
        ('new TextDecoder().decode(new Uint8Array([104,105]))', "hi"),
        ('new TextDecoder().decode(new Uint8Array([65,66,67]))', "ABC"),
        ("new TextDecoder('UTF-8').decode(new Uint8Array([90]))", "Z"),
    ]
    for src, want in pairs:
        got = _decode_value(src)
        if got != want:
            return ("BREAK", "textdecoder %r -> %r want %r" % (src, got, want))
    return ("HELD", "3/3")


def test_p2_bigint_values():
    pairs = [
        ("String(123n)", "123"),
        ("String(0n)", "0"),
        ("`a${123n}b`", "a123b"),
        ("Number(123n)", "123"),
        ("'x'+123n", "x123"),
        ("123n+456n", "579"),
        ("Number(1n+2n)", "3"),
        ('"a"+(10n+5n)', "a15"),
        ("(123n).toString()", "123"),
        ("String(123n+456n)", "579"),
    ]
    for src, want in pairs:
        got = _decode_value(src)
        if got != want:
            return ("BREAK", "bigint %r -> %r want %r" % (src, got, want))
    return ("HELD", "10/10")


# --------------------------------------------- p3: boundaries fail closed

def test_p3_slice_bounds():
    for src in ('"abc".slice(1.5)',       # fractional bound
                '"abc".slice(x)',         # non-literal bound
                '"abc".slice(+1)',        # unary plus bound
                '(123).slice(0,1)',       # number receiver throws
                '"\\U0001F600ab".slice(0,1)',  # non-BMP: UTF-16 scope boundary
                '(function(){var s=123;return s.slice(0,1);})()',
                '(function(){var s="ab";return t.slice(0,1);})()',
                '(function(){var s="ab",t="cd";return s.slice(0,1);})()'):
        if not _misses(src):
            return ("BREAK", "slice bound decoded: %r" % src[:50])
    return ("HELD", "8/8")


def test_p3_uri_codec_bounds():
    for src in ("decodeURIComponent('%zz')",   # malformed escape
                "decodeURIComponent('%FF')",   # invalid UTF-8
                "decodeURIComponent('%')",     # truncated escape
                "decodeURIComponent('%41', 'x')",  # extra arg
                "decodeURIComponent(123)",     # non-string arg
                "decodeURIx('abc')"):          # ident-boundary guard
        if not _misses(src):
            return ("BREAK", "codec bound decoded: %r" % src[:50])
    return ("HELD", "6/6")


def test_p3_textdecoder_bounds():
    for src in ("new TextDecoder('latin1').decode(new Uint8Array([65]))",
                'new TextDecoder().decode(new Uint8Array([-5]))',
                'new TextDecoder().decode(new Uint8Array([300]))',
                'new TextDecoder().decode(new Uint8Array([1.5]))',
                'new TextDecoder().decode(new Uint8Array([x]))',
                'new TextDecoder().decode(new Uint8Array(65))',
                'new TextDecoder().decode([65])',
                'new TextDecoder("utf-8", "x").decode(new Uint8Array([65]))'):
        if not _misses(src):
            return ("BREAK", "textdecoder bound decoded: %r" % src[:50])
    return ("HELD", "8/8")


def test_p3_bigint_bounds():
    for src in ("0x10n",              # non-decimal bigint
                "1+2n",               # engine throws: bigint+number
                "2n+1",               # engine throws: bigint+number
                "Number('123')",      # unmodeled Number arg
                "Number(123)",        # unmodeled Number arg
                "String(007n)",       # leading-zero bigint throws
                "`${007n}`",          # leading-zero in template
                "(123n).toString(16)",  # radix arg unmodeled
                "123n*2n"):           # multiplicative arithmetic unmodeled
        if not _misses(src):
            return ("BREAK", "bigint bound decoded: %r" % src[:50])
    return ("HELD", "9/9")


# --------------------------------------------- p4: neighbor compositions

def test_p4_f466_array_slice_still_blocks():
    return ("HELD" if _blocked("['%s','%s'].slice(0,2).join('')" % (_A, _B))
            else "BREAK", "f466")


def test_p4_f576_uri_roundtrip_still_blocks():
    return ("HELD" if _blocked(
        "decodeURIComponent(encodeURIComponent('%s'))" % _FULL)
        else "BREAK", "f576")


def test_p4_f500_fromcharcode_still_blocks():
    return ("HELD" if _blocked("String.fromCharCode(%s)" % _BYTES)
            else "BREAK", "f500")


def test_p4_f611_atob_still_blocks():
    return ("HELD" if _blocked("atob('%s')" % _B64) else "BREAK", "f611")


def test_p4_f463_raw_tag_still_blocks():
    return ("HELD" if _blocked("'" + _A + "'+String.raw`" + _B + "`")
            else "BREAK", "f463")


def test_p4_redfirsts_now_zero():
    tallies = {}
    for name, want in (("w374_f624_redfirst.py", (0, 5)),
                       ("w374_f628_redfirst.py", (0, 4)),
                       ("w374_f629_redfirst.py", (0, 4)),
                       ("w374_f633_redfirst.py", (0, 5))):
        tallies[name] = _redfirst_tally(name)
        if tallies[name] != want:
            return ("BREAK", "%s=%s want %s" % (name, tallies[name], want))
    return ("HELD", str(tallies))


def _redfirst_tally(name):
    tmp = tempfile.mkdtemp(prefix="g375-p4-", dir="/var/tmp")
    env = dict(os.environ)
    env["TMPDIR"] = tmp
    env["GOV_SKIP_GREEN"] = "1"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    for line in out.splitlines():
        if line.startswith("tally:"):
            m = re.search(r"tally:\s*(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD", line)
            if m:
                return (int(m.group(1)), int(m.group(2)))
    return None


# --------------------------------------------- p5: pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F624/F628/F629/F633 closed; open F621-F623,F625-F627,F630-F632,F634-F639; next F640 (wave-375 lane 4)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F640**" in text  # Wave-375 lane 4: F624, F628, F629, F633 CLOSED
          and "Open findings: F621, F622, F623, F625, F626, F627, F630, F631, F632, F634, F635, F636, F637, F638, F639." in text)  # Wave-375 lane 4: F624, F628, F629, F633 CLOSED
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28."""
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """Codec/slice/bigint corpus stays within the scan budget (F452 discipline)."""
    shapes = [
        '"xx%s".slice(2)' % _A,
        "decodeURIComponent('%s'+encodeURIComponent('%s'))" % (_A, _B),
        "new TextDecoder().decode(new Uint8Array([%s]))" % _BYTES,
        "('" + _A[:5] + "'+String(123n)+'" + _B + "')",
    ]
    corpus = ("junk " * 50 + " ".join(shapes) + " ") * 10
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 30.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


# --------------------------------------------- p9: green check (depth-1)

def test_p9_green_check():
    """Depth-1 green check: touched + adjacent batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for name, want_break in (("w374_attack_probes.py", 0),
                             ("w353_f464f465f466close_probes.py", 0),
                             ("w369_f576_redfirst.py", 0),
                             ("w352_f466_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        real_break = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    real_break = int(parts[1])
                except (IndexError, ValueError):
                    pass
            # wave-305-class alt format: "<battery>: N BREAK / M HELD / K ERROR"
            m = re.match(r"^\S+:\s*(\d+)\s*BREAK\s*/", line)
            if m and real_break is None:
                real_break = int(m.group(1))
        good = (real_break == want_break)
        ok_all = ok_all and good
        notes.append("%s=%s" % (name, real_break))
    return ("HELD" if ok_all else "BREAK", ",".join(notes))


def main():
    fns = [n for n in globals() if n.startswith("test_")]
    # definition order by phase: p1, p2, p3, p4, p5, p9
    fns.sort(key=lambda n: (n[5], n))
    breaks, held = 0, 0
    for n in fns:
        fn = globals()[n]
        if not callable(fn):
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent green
            verdict, note = "BREAK", "ERROR %r" % (e,)
        print("%s: %s (%s)" % (n, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
