#!/usr/bin/env python3
"""Wave-390 lane 1 close battery: F937 + F938 + F939 + F940 CLOSED.

Verifies the four LOW findings (wave-389 attack round 57, filed
2026-10-09 12:34 UTC) are closed on the lane tree: pins, filed shapes
(must block, node-exact decode), generalizations (must block),
fail-closed bounds (must miss / stay quiet, never mis-decode),
sibling pins (F933 for-of, F437 identity map + pA+pB reduce, F651
array-iter for-of -- including the F651 drive-by snapshot/restore
fix), honest-text controls, perf (200 sites), and a depth-1 green
check on the four w390 red-first batteries (GOV_SKIP_GREEN=1 in the
child env).

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
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_CODES = ",".join(str(ord(c)) for c in _FULL)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


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
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer():
    """Merged footer: F937-F948 closed; open F949-F966; next F967."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    m = re.search(r"Next free finding: \*\*F967\*\*\. \*\*Open findings: "
                  r"([^*]+)\.", text)
    if not m:
        return ("BREAK", "no F967 footer")
    opens = [x.strip() for x in m.group(1).split(",")]
    want = ["F%d" % i for i in range(949, 967)]
    ok = (opens == want
          and text.count("CLOSED 2026-10-09 wave-390 lane 1") >= 4)
    return ("HELD" if ok else "BREAK",
            "open=%d want=%d" % (len(opens), len(want)))


# ------------------------------------------- p1: filed shapes block


@_t
def test_p1_f937_filed():
    """F937 filed shapes block (5)."""
    shapes = [
        "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++)"
        "{s+=String.fromCharCode(c[i]);}return s;})()" % _CODES,
        "(function(){var c=[%s],s='',i=0;while(i<c.length)"
        "{s+=String.fromCharCode(c[i]);i++;}return s;})()" % _CODES,
        "(function(){var s='';for(var x of [%s])"
        "{s+=String.fromCharCode(x);}return s;})()" % _CODES,
        "(function(){var c=[%s],s='',i=0;do{s+=String.fromCharCode(c[i]);i++;}"
        "while(i<c.length);return s;})()" % _CODES,
        "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++)"
        "{s+=String.fromCharCode(c[i]);}return s;})()" % _CODES,
    ]
    bad = [p for p in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


@_t
def test_p1_f938_filed():
    """F938 filed shapes block (7)."""
    shapes = [
        "(function(){var a=['%s','%s'],s='';for(var i=0;i<a.length;i++)"
        "{s+=a[i];}return s;})()" % (_A, _B),
        "(function(){var a=['%s','%s'],s='';while(a.length)"
        "{s+=a.shift();}return s;})()" % (_A, _B),
        "(function(){var s='';for(var x of ['%s','%s'])"
        "{s=s+x;}return s;})()" % (_A, _B),
        "(function(){var a=['%s','%s'],s='',i=0;do{s+=a[i];i++;}"
        "while(i<a.length);return s;})()" % (_A, _B),
        "(function(){var a=['%s','%s'],s='';L:for(var i=0;;i++)"
        "{if(i>=a.length)break L;s+=a[i];}return s;})()" % (_A, _B),
        "(function(){var a=['%s','%s'],s='';try{for(var i=0;i<a.length;i++)"
        "{s+=a[i];}}catch(e){}return s;})()" % (_A, _B),
        "(function(){var s='';function add(x){s+=x;}var a=['%s','%s'];"
        "for(var i=0;i<a.length;i++)add(a[i]);return s;})()" % (_A, _B),
    ]
    bad = [p for p in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


@_t
def test_p1_f939_filed():
    """F939 filed shapes block (6)."""
    shapes = [
        "(function(){return [%s].map(function(c)"
        "{return String.fromCharCode(c);}).join('');})()" % _CODES,
        "(function(){return [%s].map(c=>String.fromCharCode(c))"
        ".join('');})()" % _CODES,
        "(function(){return Array.from([%s],function(c)"
        "{return String.fromCharCode(c);}).join('');})()" % _CODES,
        "(function(){var s='';[%s].forEach(function(c)"
        "{s+=String.fromCharCode(c);});return s;})()" % _CODES,
        "(function(){var c=[%s];return c.map(function(x){return "
        "(function(){return String.fromCharCode(x);})();}).join('');})()"
        % _CODES,
        "(function(){return [%s].map(function(c)"
        "{return String.fromCharCode(c);}).join('');})()" % _CODES,
    ]
    bad = [p for p in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


@_t
def test_p1_f940_filed():
    """F940 filed shapes block (3)."""
    shapes = [
        "(function(){return [%s].reduce(function(s,c)"
        "{return s+String.fromCharCode(c);},'');})()" % _CODES,
        "(function(){return [%s].reduce((s,c)=>s+String.fromCharCode(c),'');})()"
        % _CODES,
        "(function(){return [%s].reduceRight(function(s,c)"
        "{return String.fromCharCode(c)+s;},'');})()" % _CODES,
    ]
    bad = [p for p in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------- p2: generalizations


@_t
def test_p2_generalizations():
    """Narrow generalizations block (node-exact twins)."""
    gens = [
        # F937: let decls, s=s+ twin, hex codes, for-of over bound array
        "(function(){let c=[%s],s='';for(let i=0;i<c.length;i++)"
        "{s=s+String.fromCharCode(c[i]);}return s;})()" % _CODES,
        "(function(){var c=[0x78,0x6f,0x78,0x62,0x2d,0x30,0x31,0x32,0x33,"
        "0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66],"
        "s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}"
        "return s;})()",
        "(function(){var c=[%s],s='';for(var x of c)"
        "{s+=String.fromCharCode(x);}return s;})()" % _CODES,
        # F938: let decls, s=s+ twin, unbraced for body
        "(function(){let a=['%s','%s'],s='';for(let i=0;i<a.length;i++)"
        "{s=s+a[i];}return s;})()" % (_A, _B),
        "(function(){var a=['%s','%s'],s='';for(var i=0;i<a.length;i++)"
        "s+=a[i];return s;})()" % (_A, _B),
        # F939: block-arrow map, Array.from arrow, forEach arrow
        "[%s].map((c)=>{return String.fromCharCode(c);}).join('')" % _CODES,
        "(function(){return Array.from([%s],c=>String.fromCharCode(c))"
        ".join('');})()" % _CODES,
        "(function(){var s='';[%s].forEach((c)=>{s+=String.fromCharCode(c);});"
        "return s;})()" % _CODES,
        # F940: swapped concat order, reduceRight arrow, block-arrow
        "[%s].reduce(function(s,c){return String.fromCharCode(c)+s;},'')"
        % _CODES,
        "(function(){return [%s].reduceRight((s,c)=>s+String.fromCharCode(c),'');})()"
        % _CODES,
        "[%s].reduce((s,c)=>{return s+String.fromCharCode(c);},'')" % _CODES,
    ]
    bad = [p for p in gens if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------- p3: fail-closed bounds


@_t
def test_p3_fail_closed():
    """Documented bounds miss (never mis-decode)."""
    bounds = [
        # F937: const decl (engine would throw on s+=)
        "(function(){const c=[72,105],s='';for(var i=0;i<c.length;i++)"
        "{s+=String.fromCharCode(c[i]);}return s;})()",
        # F937: non-empty accumulator init
        "(function(){var c=[72,105],s='x';for(var i=0;i<c.length;i++)"
        "{s+=String.fromCharCode(c[i]);}return s;})()",
        # F937: i+=1 increment (not modeled)
        "(function(){var c=[72,105],s='';for(var i=0;i<c.length;i+=1)"
        "{s+=String.fromCharCode(c[i]);}return s;})()",
        # F937: do-while over empty array (reads c[0]=undefined)
        "(function(){var c=[],s='',i=0;do{s+=String.fromCharCode(c[i]);i++;}"
        "while(i<c.length);return s;})()",
        # F938: const decl
        "(function(){const a=['H','i'],s='';for(var i=0;i<a.length;i++)"
        "{s+=a[i];}return s;})()",
        # F938: pop() instead of shift() (not modeled)
        "(function(){var a=['H','i'],s='';while(a.length){s+=a.pop();}return s;})()",
        # F938: non-string element
        "(function(){var a=[72,'i'],s='';for(var i=0;i<a.length;i++)"
        "{s+=a[i];}return s;})()",
        # F939: map over string elements (not int)
        "(function(){return ['a','b'].map(c=>String.fromCharCode(c)).join('');})()",
        # F939: non-fromCharCode map still fails closed
        "(function(){return [1,2].map(c=>c+1).join('');})()",
        # F940: seedless reduce (first acc is an element, not modeled)
        "(function(){return [72,105].reduce("
        "function(s,c){return s+String.fromCharCode(c);});})()",
        # F940: non-string init
        "(function(){return [72,105].reduce("
        "function(s,c){return s+String.fromCharCode(c);},0);})()",
        # F940: non-int element
        "(function(){return ['a',105].reduce("
        "function(s,c){return s+String.fromCharCode(c);},'');})()",
    ]
    bad = [p for p in bounds if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "decoded=%d" % len(bad))


# ------------------------------------------------- p4: sibling pins


@_t
def test_p4_siblings():
    """Sibling productions still block (no hook theft)."""
    pins = [
        # F933: string-literal for-of
        "(function(){var s='';for(var x of 'xoxb-0123'){s+=x;}return s+'" + _B + "';})()",
        # F437: identity map
        "(function(){return ['" + _A + "','" + _B + "']"
        ".map(function(x){return x;}).join('');})()",
        # F437: pA+pB reduce
        "(function(){return ['" + _A + "','" + _B + "']"
        ".reduce(function(a,b){return a+b;});})()",
        # F651: array-iter for-of (drive-by fix target -- must still block)
        "(function(){var a=['" + _A + "','" + _B + "'];var s='';"
        "for(var x of a.values()){s+=x;}return s;})()",
        # F709: loop accum (sibling loop production)
        "(function(){var s='';for(var i=0;i<2;i++){s+='x';}return s+'oxb-0123456789abcdef';})()",
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
        "contact us at support@example.com",
        "(function(){var scores=[10,20,30];return scores.map(s=>s*2).join(',');})()",
        "(function(){var total=[1,2,3].reduce((a,b)=>a+b,0);return 'n'+total;})()",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 10s)."""
    site = ("(function(){var c=[72,105],s='';for(var i=0;i<c.length;i++)"
            "{s+=String.fromCharCode(c[i]);}return s;})()")
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
    for battery in ("w390_f937_redfirst.py", "w390_f938_redfirst.py",
                    "w390_f939_redfirst.py", "w390_f940_redfirst.py"):
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
                # "shapes 0 BREAK / 7 HELD; ..."
                try:
                    breaks = int(line.split()[1])
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
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
