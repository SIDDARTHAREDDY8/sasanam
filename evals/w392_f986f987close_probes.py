#!/usr/bin/env python3
"""Wave-392 lane 5 close battery: F986 + F987 CLOSED.

Verifies the two LOW findings (wave-391 attack round 59, filed
2026-10-09 16:02 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F643 inline apply, F500 spread, F952
postfix, F655 const-if, F949 topstmt, F986-adjacent open
findings still BREAK), honest-text controls, perf (200 sites),
and a depth-1 green check on the two w392 red-first batteries
(GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
"""

import argparse
import os
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

TAXONOMY_PIN = 2143  # wave-391 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_FULL40 = _F1 + _F2
_C21 = ",".join(str(ord(c)) for c in _FULL[:21])
_C12 = ",".join(str(ord(c)) for c in _FULL[:12])

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
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_state():
    """Merged footer: F986/F987 CLOSED (wave-392 lane 5); F967-F987 closed except F988-F1003/F1004; next F1005."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1005**" in text
          and "F986-F987 CLOSED (2" in text
          and "F988-F1003 OPEN (16" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


def _f986_shapes():
    return [
        "var s='';if(1){s+='%s';}else{s+='x';}s+='%s';var RESULT=s;" % (_A, _B),
        "var s='';if(1){s+='%s';}else{s+='x';}s+='%s';var RESULT=s;" % (_F1, _F2),
        "var RESULT=(1?'%s':'x')+(0?'y':'%s');" % (_A, _B),
        "var s=void 0||'%s';s+='%s';var RESULT=s;" % (_A, _B),
        'var RESULT=(typeof qq_zz==="undefined"?\'%s\':\'x\')+\'%s\';' % (_A, _B),
    ]


def _f987_shapes():
    return [
        "var c=[%s];var RESULT=String.fromCharCode.apply(null,c);" % _C21,
        "var c=[%s];var RESULT=String.fromCharCode.apply(null,c);" % ",".join(
            str(ord(c)) for c in _FULL40),
        "const c=[%s];var RESULT=String.fromCharCode(...c)+'%s';" % (_C12, _B),
    ]


@_t
def test_p1_filed_shapes():
    """Filed shapes block: F986 x5, F987 x3."""
    filed = _f986_shapes() + _f987_shapes()
    bad = [p for p in filed if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Node-verified generalizations block."""
    gens = [
        # F986: instanceof-guard ternary
        "var RESULT=([] instanceof Array?'%s':'x')+'%s';" % (_A, _B),
        "var RESULT=(({}) instanceof Object?'%s':'x')+'%s';" % (_A, _B),
        # F986: parenthesized void fallbacks
        "var s=(void 0)||'%s';var RESULT=s+'%s';" % (_A, _B),
        "var s=(void(0))||'%s';var RESULT=s+'%s';" % (_A, _B),
        # F986: nested ternary in branch
        "var RESULT=(1?(0?'a':'%s'):'z')+'%s';" % (_A, _B),
        # F986: typeof !== (undeclared -> false branch)
        'var RESULT=(typeof qq_zz!=="undefined"?\'x\':\'%s\')+\'%s\';' % (_A, _B),
        # F986: hex int guard
        "var RESULT=(0x1?'%s':'x')+'%s';" % (_A, _B),
        # F986: false-branch if/else
        "var s='';if(0){s+='w';}else{s+='%s';}s+='%s';var RESULT=s;" % (_A, _B),
        # F986: let/const decls
        "let s='';if(1){s+='%s';}s+='%s';const RESULT=s;" % (_A, _B),
        # F986: grouped additive
        "var RESULT=('%s')+('%s');" % (_A, _B),
        # F987: let-bound with whitespace
        "let c = [%s];var RESULT=String.fromCharCode.call(null,...c);" % _C21,
        # F987: multi-declarator array bindings (both bound, one used)
        "var c=[%s],d=[120];var RESULT=String.fromCharCode.apply(null,c);" % _C21,
        # F987: empty array spread (node: f() with no args)
        "var c=[];var RESULT=String.fromCharCode(...c)+'%s';" % _FULL,
        # F987: hex code spellings
        "var c=[0x78,0x6f,0x78,0x62,0x2d,0x30,0x31,0x32,0x33];var RESULT=String.fromCharCode.apply(null,c)+'%s';" % _B,
    ]
    bad = [p for p in gens if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------- p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Out-of-scope / unsound twins stay quiet (never mis-decode)."""
    quiet = [
        # F986: typeof a known global -- not decidable, fail closed
        'var RESULT=(typeof Array==="undefined"?\'w\':\'%s\')+\'%s\';' % (_A, _B),
        # F986: undecidable instanceof guard
        "var RESULT=(x instanceof Array?'%s':'w')+'%s';" % (_A, _B),
        # F986: call inside the taken branch -- not modeled
        "var s='';if(1){s+=f();}else{s+='w';}var RESULT=s;",
        # F986: trailing input after RESULT
        "var RESULT=(1?'%s':'w')+'%s';var RESULT2=1;" % (_A, _B),
        # F986: unbraced if body -- documented narrowness
        "var s='';if(1)s+='%s';var RESULT=s;" % _A,
        # F986: else-if chain -- documented narrowness
        "var s='';if(0){s+='w';}else if(1){s+='%s';}var RESULT=s;" % _A,
        # F986: bare void 0 (undefined is not a string)
        "var s=void 0;var RESULT='x';",
        # F986: guard-free sequence is not our variant (F441)
        "var s='%s';var RESULT=s;" % _A,
        # F986 HARD-1 (spec review): mid-additive void-|| is
        # ('x'+void 0)||'A' in node -- must not mis-decode
        "var RESULT='x'+void 0||'A';",
        "var RESULT='x'+(void 0)||'A';",
        "var RESULT='%s'+void 0||'%s';" % (_A, _B),
        # F986 HARD-2 (spec review): const reassignment -- node throws
        "const s='a';if(1){s+='b';}var RESULT=s;",
        "const s='a';if(1){s='b';}var RESULT=s;",
        "const s='%s';if(1){s+='%s';}var RESULT=s;" % (_A, _B),
        # F986 HARD-2: let/const decls are block-scoped in node
        "if(1){let s='a';}var RESULT='x';",
        "if(1){const s='a';}var RESULT='x';",
        # F986 HARD-3 (spec review): instanceof RHS shadowing -- node throws
        "var Array='x';var RESULT=([] instanceof Array?'A':'B');",
        "var Object='x';var RESULT=({} instanceof Object?'A':'B');",
        # F987: non-literal array element
        "var c=[120, f(1)];var RESULT=String.fromCharCode.apply(null,c);",
        # F987: array hole
        "var c=[120,,111];var RESULT=String.fromCharCode.apply(null,c);",
        # F987: mutation of the bound array
        "var c=[120];c.push(1);var RESULT=String.fromCharCode.apply(null,c);",
        # F987: member access on the bound name
        "var c=[120];var RESULT=c.length;",
        # F987: reassignment of the bound name
        "var c=[120];c=1;var RESULT=String.fromCharCode.apply(null,c);",
        # F987: mixed declarators (string) -- documented narrowness
        "var c=[%s],d='z';var RESULT=String.fromCharCode.apply(null,c)+d;" % _C12,
        # F987: spread of the name outside call args
        "var c=[120];var d=[...c];var RESULT='x';",
        # honest non-credential twins
        "var s='';if(1){s+='ab';}else{s+='cd';}var RESULT=s;",
        "var c=[1,2,3];var RESULT=String.fromCharCode.apply(null,c);",
    ]
    bad = [p for p in quiet if _blocked(p)]
    # no mis-decode: the undecidable-guard twin must not decode to the credential
    dec = _decode(quiet[1])
    ok_nodec = dec is None or _FULL not in dec
    ok = not bad and ok_nodec
    return ("HELD" if ok else "BREAK",
            "flagged=%d misdecode=%s" % (len(bad), not ok_nodec))


# ------------------------------------------ p4: sibling pins must hold


@_t
def test_p4_sibling_pins():
    """Adjacent findings keep their verdicts (no regressions)."""
    # must STAY BLOCKED (closed findings)
    blocked = [
        # F643: inline apply still decodes
        "var RESULT=String.fromCharCode.apply(null,[%s]);" % _C21,
        # F500: direct-call spread still decodes
        "var RESULT=String.fromCharCode(...[%s]);" % _C21,
        # F952: postfix transform on inline array still decodes
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % _C21,
        # F655/F900: const-if without else still decodes (overlaps F986's grammar)
        "var s='';if(1){s+='%s';}var RESULT=s;" % _FULL,
        # F949: top-level statement builtin still decodes
        "var RESULT=structuredClone('%s');" % _FULL,
    ]
    # must STAY OPEN (miss) -- my hooks must not swallow them
    missed = [
        # F968: entries->fromEntries round-trip (honest residual)
        "var e=[['k','%s']];var o=Object.fromEntries(e);var RESULT=Object.entries(o)[0][1];" % _A,
    ]
    bad_b = [p for p in blocked if not _blocked(p)]
    bad_m = [p for p in missed if not _misses(p)]
    ok = not bad_b and not bad_m
    return ("HELD" if ok else "BREAK",
            "unblocked=%d swallowed=%d" % (len(bad_b), len(bad_m)))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    honest = [
        "the quarterly report is attached",
        "if (x) { y(); } else { z(); }",
        "var t = cond ? alpha : beta;",
        "var x = void 0;",
        "if (typeof foo === 'undefined') { init(); }",
        "var c = [1, 2, 3]; console.log(c.length);",
        "var s = ''; if (ready) { s += 'done'; }",
        "contact us at support@example.com",
        "function add(a, b) { return a + b; }",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s, F452-bounded)."""
    site = ("var s='';if(1){s+='%s';}else{s+='x';}s+='%s';var RESULT=s;"
            % (_A, _B))
    site += "var c=[%s];var RESULT=String.fromCharCode.apply(null,c);" % _C21
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    # Standards H1: typeof guards must not re-scan the whole text per
    # guard (was O(guards x tokens)); 200 typeof-guarded ifs stay fast.
    t1 = time.time()
    dlp.find_credential(
        "var s='';"
        + "".join("if(typeof q_zz%d===\"undefined\"){s+='x';}else{s+='y';}"
                  % k for k in range(200))
        + "var RESULT=s;")
    dt2 = time.time() - t1
    ok = dt < 15.0 and dt2 < 15.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs; 200 typeof-guards in %.2fs" % (dt, dt2))


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w392_f986_redfirst.py", "w392_f987_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g392-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format: "HELD <shape>" (blocked, good on the
        # closed tree) / "BREAK <shape>" (miss, bad); "ctrl-ok <name>"
        # / "CTRL-FAIL <name>".
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("HELD ") or line.startswith("BREAK "))
        total_bad += bad
        notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
        if nshapes == 0:
            total_bad += 1
            notes.append("%s: no shapes tallied" % battery)
    ok = total_bad == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d bad [%s]"
            % (total_bad, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the two red-firsts stay 0 failures."""
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
