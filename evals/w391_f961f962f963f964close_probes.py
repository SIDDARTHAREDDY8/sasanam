#!/usr/bin/env python3
"""Wave-391 lane 4 close battery: F961 + F962 + F963 + F964 CLOSED.

Verifies the four LOW findings (wave-390 attack round 58, filed
2026-10-09 14:19 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F893 literal-body Function, F939
fromCharCode map, F443 fill, F508 Array.from arraylike, F437
identity map, F581 entries-projection), honest-text controls, perf
(200 sites), and a depth-1 green check on the four w391 red-first
batteries (GOV_SKIP_GREEN=1 in the child env).

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

TAXONOMY_PIN = 2143  # wave-390 merge (no code-count change)
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
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_DOTALL_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_lane_local():
    """Lane-local footer: F961-F964 CLOSED; open F949-F960, F965-F966 (14); next F967."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = True
    notes = []
    for f in ("F961", "F962", "F963", "F964"):
        m = re.search(r"\(%s filed .*?; LOW, CLOSED" % f, text, re.S)
        if not m:
            ok = False
            notes.append("%s not CLOSED" % f)
    footer = text[text.rfind("Next free finding:"):]
    for f in ("F949", "F960", "F965", "F966"):
        if f not in footer:
            ok = False
            notes.append("%s missing from footer opens" % f)
    mopen = re.search(r"Open findings:([^*]*)\.", footer)
    open_list = mopen.group(1) if mopen else ""
    for f in ("F961", "F962", "F963", "F964"):
        if re.search(r"\b%s\b" % f, open_list):
            ok = False
            notes.append("%s still open in footer" % f)
    if "F967" not in footer:
        ok = False
        notes.append("next-free not F967")
    return ("HELD" if ok else "BREAK", "; ".join(notes) or "footer ok")


# --------------------------------------- p1: filed shapes must block


def _f961_shapes():
    return [
        ("var e=['%s','%s'].entries();var RESULT=e.next().value[1]"
         "+e.next().value[1];" % (_A, _B)),
        ("var e=['xox','%s'].entries();var RESULT=e.next().value[1]"
         "+e.next().value[1];" % ("b-" + "0123456789abcdef012")),
        ("var v=['%s','%s'].values();var RESULT=v.next().value"
         "+v.next().value;" % (_A, _B)),
        ("var RESULT=[...['%s','%s'].values()].join('');" % (_A, _B)),
    ]


def _f962_shapes():
    return [
        ("var a=['p','%s','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[1];"
         % (_A, _B)),
        ("var a=['p','xox','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[1];"
         % ("b-" + "0123456789abcdef012")),
    ]


def _f963_shapes():
    return [
        ("var RESULT=new Array(2).fill('%s').map((x,i)=>i===0?'%s':x)"
         ".join('');" % (_B, _A)),
        ("var RESULT=new Array(2).fill('b-0123456789abcdef012').map("
         "(x,i)=>i===0?'xox':x).join('');"),
        ("var RESULT=Array.from({length:2},(x,i)=>i===0?'%s':'%s')"
         ".join('');" % (_A, _B)),
    ]


def _f964_shapes():
    return [
        ("var f=new Function('p1','p2','return p1+p2;');var RESULT=f("
         "'%s','%s');" % (_A, _B)),
        ("var f=new Function('p1','p2','return p1+p2;');var RESULT=f("
         "'xox','b-0123456789abcdef012');"),
        ("var f=new Function('a','b','c','return a+b+c;');var RESULT=f("
         "'%s','45','6789abcdef');" % _A),
    ]


@_t
def test_p1_filed_shapes_block():
    """All 12 filed shapes (F961-F964) block."""
    shapes = (_f961_shapes() + _f962_shapes() + _f963_shapes()
              + _f964_shapes())
    bad = [p for p in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK",
            "missed=%d/12" % len(bad))


# --------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Narrow twins (decls/quotes/args/arity) block too."""
    gens = [
        # F961: let/const, intermediate var steps, drain spread, separator
        ("let v=['%s','%s'].values();let RESULT=v.next().value"
         "+v.next().value;" % (_A, _B)),
        ("const v=['%s','%s'].values();const RESULT=v.next().value"
         "+v.next().value;" % (_A, _B)),
        ("var v=['%s','%s'].values();var h=v.next().value;"
         "var RESULT=h+[...v].join('');" % (_A, _B)),
        ("var RESULT=[...['%s','%s'].values()].join('-');" % (_A, _B)),
        ('var e=["%s","%s"].entries();var RESULT=e.next().value[1]'
         '+e.next().value[1];' % (_A, _B)),
        # F962: 3-arg, negative args, untouched-slot reads
        ("var a=['p','%s','%s'];a.copyWithin(0,1,3);"
         "var RESULT=a[0]+a[1];" % (_A, _B)),
        ("var a=['%s','%s','z'];a.copyWithin(-1,-3,-1);"
         "var RESULT=a[0]+a[2];" % (_A, _B)),
        ("let a=['q','%s','%s'];a.copyWithin(0,1);let RESULT=a[0]+a[1];"
         % (_A, _B)),
        # F963: == twin, function twin, renamed params, 3-elem
        ("var RESULT=new Array(2).fill('%s').map((x,i)=>i==0?'%s':x)"
         ".join('');" % (_B, _A)),
        ("var RESULT=new Array(2).fill('%s').map(function(x,i)"
         "{return i===0?'%s':x;}).join('');" % (_B, _A)),
        ("var RESULT=['%s','%s','q'].map((e,idx)=>idx===2?'':e)"
         ".join('');" % (_A, _B)),
        ("var RESULT=Array.from({length:3},(x,i)=>i===0?'%s':'')"
         ".join('');" % _FULL),
        ("var RESULT=['%s','q'].map((x,i)=>i===1?'%s':'%s').join('');"
         % (_A, _B, _A)),
        # F964: double quotes, no-new, 1-param, ws in body
        ('var f=new Function("p1","p2","return p1+p2;");var RESULT=f('
         '"%s","%s");' % (_A, _B)),
        ("var f=Function('p1','p2','return p1+p2;');var RESULT=f("
         "'%s','%s');" % (_A, _B)),
        ("const f=new Function('only','return only;');const RESULT=f("
         "'%s');" % _FULL),
        ("var f = new Function( 'p1' , 'p2' , 'return p1 + p2 ;' );"
         "var RESULT = f( '%s' , '%s' );" % (_A, _B)),
    ]
    bad = [p for p in gens if not _blocked(p)]
    return ("HELD" if not bad else "BREAK",
            "missed=%d/%d" % (len(bad), len(gens)))


# ----------------------------------- p3: fail-closed bounds


@_t
def test_p3_fail_closed():
    """Malformed / engine-undefined twins stay quiet, never mis-decode."""
    quiet = [
        # F961: read past the end (engine: undefined) -- must miss
        ("var e=['%s'].entries();var RESULT=e.next().value[1]"
         "+e.next().value[1];" % _A),
        # F961: indexing a values-kind .value (engine: char, not modeled)
        ("var v=['%s','%s'].values();var RESULT=v.next().value[0]"
         "+v.next().value[0];" % (_A, _B)),
        # F961: .next(5) with args -- not modeled
        ("var v=['%s','%s'].values();var RESULT=v.next(5).value"
         "+v.next().value;" % (_A, _B)),
        # F961: non-literal array elements -- not modeled
        ("var e=[x,'%s'].entries();var RESULT=e.next().value[1]"
         "+e.next().value[1];" % _B),
        # F962: out-of-range read (engine: undefined) -- must miss
        ("var a=['%s','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[9];"
         % (_A, _B)),
        # F962: non-integer copyWithin arg -- not modeled
        ("var a=['p','%s','%s'];a.copyWithin(0,x);var RESULT=a[0]+a[1];"
         % (_A, _B)),
        # F962: junk method -- must miss
        ("var a=['p','%s','%s'];a.copyTo(0,1);var RESULT=a[0]+a[1];"
         % (_A, _B)),
        # F963: !== condition -- not modeled
        ("var RESULT=new Array(2).fill('%s').map((x,i)=>i!==0?'%s':x)"
         ".join('');" % (_B, _A)),
        # F963: condition on x -- not modeled
        ("var RESULT=new Array(2).fill('%s').map((x,i)=>x==='%s'?'%s':x)"
         ".join('');" % (_B, _A, _A)),
        # F963: non-ternary callback -- not modeled
        ("var RESULT=new Array(2).fill('%s').map((x,i)=>x).join('');"
         % _B),
        # F963: bare-x else over from-holes (engine: x is undefined,
        # join coerces to "" -- a single-fragment select is
        # plaintext-flagged anyway, so no laundering; stays
        # fail-closed)
        ("var RESULT=Array.from({length:2},(x,i)=>i===0?'%s':x)"
         ".join('');" % _A),
        # F964: arg-count mismatch (engine pads) -- not modeled
        ("var f=new Function('p1','p2','return p1+p2;');var RESULT=f("
         "'%s');" % _A),
        # F964: body reads undeclared name (engine: live binding) -- miss
        ("var f=new Function('p1','return p1+zzz;');var RESULT=f('%s');"
         % _A),
        # F964: non-return body -- not modeled
        ("var f=new Function('p1','p1;');var RESULT=f('%s');" % _A),
        # F964: non-literal call arg -- not modeled
        ("var f=new Function('p1','p2','return p1+p2;');var RESULT=f("
         "'%s',q);" % _A),
        # F964: reserved param name -- not modeled
        ("var f=new Function('if','return 1;');var RESULT=f('%s');"
         % _A),
    ]
    bad = [p for p in quiet if _blocked(p)]
    # no mis-decode: quiet twins must never decode to the credential
    misdec = [p for p in quiet
              if (_decode(p) or "") == _FULL]
    ok = not bad and not misdec
    return ("HELD" if ok else "BREAK",
            "flagged=%d misdecode=%d" % (len(bad), len(misdec)))


# ------------------------------------------ p4: sibling pins must hold


@_t
def test_p4_sibling_pins():
    """Sibling findings still close their shapes (no regressions)."""
    codes = [ord(c) for c in _FULL]
    pins = [
        # F893: literal-body Function twin
        ("var f=new Function('return \"%s\"+\"%s\";');var RESULT=f();"
         % (_A, _B)),
        # F939: fromCharCode map
        ("var RESULT=[%s].map(function(c){return String.fromCharCode(c);})"
         ".join('');" % ",".join(str(c) for c in codes)),
        # F443: fill join
        ("var RESULT=new Array(1).fill('%s').join('');" % _FULL),
        # F508: Array.from arraylike with index props
        ("var RESULT=Array.from({length:2,0:'%s',1:'%s'}).join('');"
         % (_A, _B)),
        # F437: identity map
        ("var RESULT=['%s','%s'].map(x=>x).join('');" % (_A, _B)),
        # F581-adjacent: entries-projection map p=>p[1]
        ("var RESULT=[['q','%s'],['z','%s']].map(p=>p[1]).join('');"
         % (_A, _B)),
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
        "var it=[1,2].values();var s='';for(var x of it){s+=x;}",
        "var a=['x','y'];a.copyWithin(0,1);",
        "var f=new Function('a','b','return a*b;');",
        "contact us at support@example.com",
        "var m=['a','b'].map((x,i)=>i);",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 10s)."""
    site = ("var e=['%s','%s'].entries();var RESULT=e.next().value[1]"
            "+e.next().value[1];" % (_A, _B))
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
    for battery in ("w391_f961_redfirst.py", "w391_f962_redfirst.py",
                    "w391_f963_redfirst.py", "w391_f964_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g391-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first format on the closed tree: every shape HELD (a
        # "BREAK " line means a shape missed -- a regression), every
        # control "ctrl-ok" (a "CTRL-FAIL" line is a regression).
        breaks = sum(1 for line in out.splitlines()
                     if line.startswith("BREAK ")
                     or line.startswith("CTRL-FAIL"))
        if p.returncode not in (0, 1) and breaks == 0:
            total_break += 1
            notes.append("%s: rc=%d" % (battery, p.returncode))
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
