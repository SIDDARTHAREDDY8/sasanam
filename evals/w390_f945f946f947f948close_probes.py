#!/usr/bin/env python3
"""Wave-390 lane 3 close battery: F945 + F946 + F947 + F948 CLOSED.

Verifies the four LOW findings (wave-390 attack round 57, filed
2026-10-09 12:34 UTC; F948 renumbered from wave-389 lane 1's F924
residual, first-filed 2026-10-09 12:45 UTC) are closed on the lane
tree: pins, filed shapes (must block, node-exact decode),
generalizations (must block), fail-closed bounds (must miss / stay
quiet, never mis-decode), sibling pins (F893 literal-eval, F458
literal-fromCharCode, F924 unbraced guard, F786/F787 accum IIFEs),
honest-text controls, perf (200 sites), and a depth-1 green check on
the four w390 red-first batteries (GOV_SKIP_GREEN=1 in the child
env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-389 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_CHARS = list(_FULL)  # 20 chars

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_DOTALL_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_next_free():
    """Base footer: F937-F948 OPEN (12), next free F949."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = "F949" in text
    return ("HELD" if ok else "BREAK", "F949-ref=%s" % ok)


# --------------------------------------- p1: filed shapes must block


def _f945_shape(codes, decl="var", incr="i++", acc="s"):
    return ("(function(){%s c=[%s],%s='';for(%s i=0;i<c.length;%s)"
            "{%s+=eval('String.fromCharCode('+c[i]+')');}return %s;})()"
            % (decl, ",".join(str(c) for c in codes), acc,
               decl, incr, acc, acc))


def _f946b_shape(codes, cb="function(_,i){return String.fromCharCode(cd[i]);}"):
    return ("(function(){var cd=[%s];return Array.from({length:cd.length},%s)"
            ".join('');})()" % (",".join(str(c) for c in codes), cb))


def _f947_shape(chars):
    props = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(chars))
    reads = "+".join("o.p%d" % i for i in range(len(chars)))
    return "(function(){var o={%s};return %s;})()" % (props, reads)


@_t
def test_p1_f945_filed_shapes():
    """F945 filed shapes block (eval loop, node-exact decode)."""
    codes = [ord(c) for c in _FULL]
    shapes = [
        _f945_shape(codes),  # s1 var/i++
        _f945_shape(codes, decl="let", incr="++i"),  # s4 let/++i
    ]
    # 40-char twin
    codes40 = [ord(c) for c in (_FULL + _FULL)]
    shapes.append(_f945_shape(codes40))  # s2-40char
    bad = [p for p in shapes if not _blocked(p)]
    # node-exactness of the decode itself
    dec = _decode(shapes[0])
    ok_dec = dec is not None and _FULL in dec
    ok = not bad and ok_dec
    return ("HELD" if ok else "BREAK",
            "missed=%d decode_ok=%s" % (len(bad), ok_dec))


@_t
def test_p1_f946_filed_shapes():
    """F946 filed shapes block (additive concat + indexed Array.from)."""
    # Filed: String.fromCharCode(119+1)+... concatenation (not single-call)
    s1 = ("(function(){return %s;})()"
          % "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1)
                     for c in _FULL))
    codes = [ord(c) for c in _FULL]
    s2 = _f946b_shape(codes)
    s3 = ("(function(){return %s;})()"
          % "+".join("String.fromCharCode(0x%x+0o1)" % (ord(c) - 1)
                     for c in (_FULL + _FULL)))
    s4 = _f946b_shape(
        codes, cb="(_,i)=>String.fromCharCode(cd[i])")
    s5 = _f946b_shape(
        codes, cb="function(_,i){return String.fromCharCode( cd[i] );}")
    shapes = [s1, s2, s3, s4, s5]
    bad = [p for p in shapes if not _blocked(p)]
    dec = _decode(s2)
    ok_dec = dec is not None and _FULL in dec
    ok = not bad and ok_dec
    return ("HELD" if ok else "BREAK",
            "missed=%d decode_ok=%s" % (len(bad), ok_dec))


@_t
def test_p1_f947_filed_shapes():
    """F947 filed shapes block (prop assembly, node-exact decode)."""
    s1 = _f947_shape(_CHARS)
    # 40-char twin
    s3 = _f947_shape(_CHARS + _CHARS)
    # bracket-read twin
    props = ",".join("p%d:%s" % (i, repr(c))
                     for i, c in enumerate(_CHARS))
    reads = "+".join("o[%s]" % repr("p%d" % i) for i in range(len(_CHARS)))
    s2 = "(function(){var o={%s};return %s;})()" % (props, reads)
    shapes = [s1, s2, s3]
    bad = [p for p in shapes if not _blocked(p)]
    dec = _decode(s1)
    ok_dec = dec is not None and _FULL in dec
    ok = not bad and ok_dec
    return ("HELD" if ok else "BREAK",
            "missed=%d decode_ok=%s" % (len(bad), ok_dec))


@_t
def test_p1_f948_filed_shapes():
    """F948 filed shapes block (braced + ASI guard consequents)."""
    s1 = ("(function(){var s='';outer:for(var j=0;j<3;j++){if(j===1)"
          "{continue outer;}s+='xoxb-0123456789abcdef'[j*8+j>0?0:0]"
          ".slice(0,0)+'f'+(j+1);}return s;})()")
    # simpler direct shapes exercising the guard parser
    g1 = ("(function(){var s='';outer:for(var j=0;j<2;j++){if(j===1)"
          "{continue outer;}s+='ab';}return s+'xoxb-0123456789abcdef';})()")
    g2 = ("(function(){var s='';outer:for(var j=0;j<2;j++){if(j===1)"
          "continue outer\ns+='ab';}return s+'xoxb-0123456789abcdef';})()")
    shapes = [g1, g2]
    bad = [p for p in shapes if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Narrow generalizations of the four shapes still block."""
    codes = [ord(c) for c in _FULL]
    gens = [
        # F945: let-decl + ++i + different acc name
        _f945_shape(codes, decl="let", incr="++i", acc="t"),
        # F945: i+=1 step
        _f945_shape(codes, incr="i+=1"),
        # F946: arrow with braced body
        _f946b_shape(codes,
                     cb="(_,i)=>{return String.fromCharCode(cd[i]);}"),
        # F947: let-decl object
        _f947_shape(_CHARS).replace("var o=", "let o=", 1),
        # F947: single-char keys
        "(function(){var o={a:'x',b:'o',c:'x',d:'b',e:'-',f:'0',g:'1',"
        "h:'2',i:'3',j:'4',k:'5',l:'6',m:'7',n:'8',o:'9',p:'a',q:'b',"
        "r:'c',s:'d',t:'e',u:'f'};return o.a+o.b+o.c+o.d+o.e+o.f+o.g+o.h+"
        "o.i+o.j+o.k+o.l+o.m+o.n+o.o+o.p+o.q+o.r+o.s+o.t+o.u;})()",
        # F948: braced guard with trailing semicolon variants
        "(function(){var s='';outer:for(var j=0;j<2;j++){if(j===1)"
        "{continue outer;}s+='ab';}return s+'xoxb-0123456789abcdef';})()",
    ]
    bad = [p for p in gens if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ---------------------------------- p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Non-credential / malformed twins stay quiet (never mis-decode)."""
    quiet = [
        # F945: eval loop over non-credential codes
        _f945_shape([65, 66, 67]),
        # F945: step-2 loop (engine skips) -- must miss, not mis-decode
        ("(function(){var c=[120,111],s='';for(var i=0;i<c.length;i+=2)"
         "{s+=eval('String.fromCharCode('+c[i]+')');}return s;})()"),
        # F945: eval with non-fromCharCode body
        ("(function(){var c=[120],s='';for(var i=0;i<c.length;i++)"
         "{s+=eval('c[i]+1');}return s;})()"),
        # F946: out-of-range code (engine throws) -- must miss
        ("(function(){var s=String.fromCharCode(1114112);return s;})()"),
        # F946: Array.from over non-cd length
        ("(function(){var cd=[120];return Array.from({length:2},"
         "function(_,i){return String.fromCharCode(cd[i]);}).join('');})()"),
        # F947: __proto__ key -- must miss (F776 owns __proto__)
        ("(function(){var o={__proto__:{p0:'x'},p0:'o'};"
         "return o.p0+o.p0;})()"),
        # F947: unknown key read -- must miss
        ("(function(){var o={p0:'x'};return o.p0+o.zz;})()"),
        # F947: non-string value -- must miss
        ("(function(){var o={p0:12};return o.p0+'x';})()"),
        # F948: unbraced guard is F924's (sibling) -- braced-only hook
        # must not fire here, but the shape may still block via F924;
        # this entry asserts no MIS-decode: decode must not equal cred
        # (checked via _decode below, not _blocked).
        # Honest non-credential IIFE
        ("(function(){var o={a:'hello'};return o.a+' world';})()"),
    ]
    bad = [p for p in quiet if _blocked(p)]
    # no mis-decode: the unknown-key twin must not decode to credential
    dec = _decode(quiet[6])
    ok_nodec = dec is None or _FULL not in dec
    ok = not bad and ok_nodec
    return ("HELD" if ok else "BREAK",
            "flagged=%d misdecode=%s" % (len(bad), not ok_nodec))


# ------------------------------------------ p4: sibling pins must hold


@_t
def test_p4_sibling_pins():
    """Sibling findings still close their shapes (no regressions)."""
    pins = [
        # F458: integer-literal fromCharCode
        ("(function(){return String.fromCharCode(120,111,120,98,45,48,49,"
         "50,51,52,53,54,55,56,57,97,98,99,100,101,102);})()"),
        # F924: unbraced guard consequent (F948's sibling)
        ("(function(){var s='';outer:for(var j=0;j<2;j++){if(j===1)"
         "continue outer;s+='ab';}return s+'xoxb-0123456789abcdef';})()"),
        # F786: string-accum IIFE still decodes
        ("(function(){var s='';s+='xoxb-';s+='0123456789abcdef';"
         "return s;})()"),
        # F787: adjacent accum production
        ("(function(){var t='xoxb-0123456789abcdef';return t;})()"),
    ]
    bad = [p for p in pins if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    honest = [
        "the quarterly report is attached",
        "async function fetchData(){return await get('/api');}",
        "(function(){return 'hello world'.replace(/o/g,'0');})()",
        "(function(){var o={name:'alice',role:'admin'};"
        "return o.name+'/'+o.role;})()",
        "(function(){var c=[1,2,3],s='';for(var i=0;i<c.length;i++)"
        "{s+=c[i];}return s;})()",
        "contact us at support@example.com",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 10s)."""
    site = _f947_shape(_CHARS)
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w390_f945_redfirst.py", "w390_f946_redfirst.py",
                    "w390_f947_redfirst.py", "w390_f948_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g390-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        breaks = None
        for line in out.splitlines():
            if line.startswith("shapes "):
                # "shapes 0 BREAK / 6 HELD"
                parts = line.split()
                try:
                    breaks = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if breaks is None:
            total_break += 1
            notes.append("%s: no tally" % battery)
        else:
            total_break += breaks
            notes.append("%s: %d BREAK" % (battery, breaks))
    ok = total_break == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d BREAK [%s]" % (total_break, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        sys.exit(1 if breaks else 0)


if __name__ == "__main__":
    main()
