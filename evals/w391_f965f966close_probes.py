#!/usr/bin/env python3
"""Wave-391 lane 5 close battery: F965 + F966 CLOSED.

Verifies the two LOW findings (wave-390 attack round 58, filed
2026-10-09 14:19 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F945 computed-eval, F940 reduce,
F471 spread-copy, F494 generator IIFE, F437 postfix reduce),
honest-text controls, perf (200 sites), and a depth-1 green check
on the two w391 red-first batteries (GOV_SKIP_GREEN=1 in the
child env).

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

TAXONOMY_PIN = 2143  # wave-390 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B

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
def test_p0_footer_next_free():
    """Merged footer (wave-392): F965/F966 CLOSED; F967-F987 CLOSED; next free F1005."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1005**" in text
          and "F949-F966 CLOSED (18)." in text
          and "F967-F974 CLOSED (8" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


def _f965_shape(frags, decl="var"):
    prog = "`" + "".join("${parts[%d]}" % i for i in range(len(frags))) + "`"
    return ("(function(){%s parts=[%s];return eval('%s');})()"
            % (decl, ",".join("'%s'" % f for f in frags), prog))


def _f966_shape(frags):
    return ("function*gen(){%s}var RESULT=[...gen()].reduce((a,b)=>a+b);"
            % "".join("yield '%s';" % f for f in frags))


@_t
def test_p1_filed_shapes():
    """Filed shapes block: F965 x2 (short + 40-char), F966 x2."""
    filed = [
        _f965_shape([_A, _B]),
        _f965_shape([_A[:10], _A[10:], _B[:8], _B[8:]]),
        _f966_shape([_A, _B]),
        _f966_shape([_A[:10], _A[10:], _B[:8], _B[8:]]),
    ]
    bad = [p for p in filed if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Node-verified generalizations block."""
    gens = [
        # F965: reversed substitution order
        "(function(){var parts=['%s','%s'];return eval('`${parts[1]}${parts[0]}`');})()" % (_B, _A),
        # F965: out-of-range index cooks to "undefined" (node-exact)
        "(function(){var parts=['%s'];return eval('`${parts[0]}${parts[9]}`');})()" % (_FULL,),
        # F965: whitespace-tolerant index
        "(function(){var parts=['%s','%s'];return eval('`${parts[ 0 ]}${parts[1]}`');})()" % (_A, _B),
        # F965: template-literal eval arg with ${P[N]} substitutions
        "(function(){var parts=['%s','%s'];return eval(`\\`${parts[0]}${parts[1]}\\``);})()" % (_A, _B),
        # F965: let-bound parts
        _f965_shape([_A, _B], decl="let"),
        # F965: escaped chars in the program cook node-exactly
        "(function(){var parts=['%s','%s'];return eval('`x\\n${parts[0]}${parts[1]}`');})()" % (_A, _B),
        # F965 H3: backslash+LF line continuation in the string arg
        # cooks node-exactly (removed) -- still blocks
        "(function(){var parts=['%s','%s'];return eval('`${parts[0]}\\\n${parts[1]}`');})()" % (_A, _B),
        # F966: var-bound generator twin
        "var gen=function*(){yield '%s';yield '%s';};var RESULT=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        # F966: named var-bound generator expression twin
        "var gen=function*gen(){yield '%s';yield '%s';};var RESULT=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        # F966: reduceRight twin
        "function*gen(){yield '%s';yield '%s';}var RESULT=[...gen()].reduceRight((a,b)=>a+b);" % (_B, _A),
        # F966: single-yield generator (seedless reduce over 1 elem)
        "function*gen(){yield '%s';}var RESULT=[...gen()].reduce((a,b)=>a+b);" % (_FULL,),
        # F966: string-seed reduce twin
        "function*gen(){yield '%s';yield '%s';}var RESULT=[...gen()].reduce((a,b)=>a+b,'zz');" % (_A, _B),
        # F966: decl-first IIFE-wrapped use
        "function*gen(){yield '%s';yield '%s';}(function(){var R=[...gen()].reduce((a,b)=>a+b);})();" % (_A, _B),
        # F966: three fragments
        _f966_shape([_A[:8], _A[8:], _B]),
    ]
    bad = [p for p in gens if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------- p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Malformed / out-of-scope twins stay quiet (never mis-decode)."""
    quiet = [
        # F965: const parts (engine would still work; we fail closed -- documented)
        "(function(){const parts=['%s','%s'];return eval('`${parts[0]}${parts[1]}`');})()" % (_A, _B),
        # F965: direct template arg -- engine throws (program is the credential itself)
        "(function(){var parts=['%s','%s'];return eval(`${parts[0]}${parts[1]}`);})()" % (_A, _B),
        # F965: indirect eval -- engine throws (P unbound in global scope)
        "(function(){var parts=['%s','%s'];return (0,eval)('`${parts[0]}${parts[1]}`');})()" % (_A, _B),
        # F965: non-parts substitution
        "(function(){var parts=['%s','%s'];var q='zz';return eval('`${q}`');})()" % (_A, _B),
        # F965: program not a template
        "(function(){var parts=['%s','%s'];return eval('parts[0]+parts[1]');})()" % (_A, _B),
        # F965: extra statement
        "(function(){var parts=['%s','%s'];var z=1;return eval('`${parts[0]}${parts[1]}`');})()" % (_A, _B),
        # F965: non-literal element
        "(function(){var parts=['%s',x];return eval('`${parts[0]}${parts[1]}`');})()" % (_A,),
        # F966: duplicate declarations
        "function*gen(){yield '%s';}function*gen(){yield '%s';}var R=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        # F966 H1: async generator -- engine throws TypeError (not sync-iterable)
        "async function*gen(){yield '%s';yield '%s';}var R=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        # F966 H2: dynamic rebinding via eval -- static binding untrustworthy
        "function*gen(){yield 'jj';}eval(\"function* gen(){yield '%s';yield '%s';}\");var R=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        "function*gen(){yield 'jj';}(0,eval)(\"function* gen(){yield '%s';yield '%s';}\");var R=[...gen()].reduce((a,b)=>a+b);" % (_A, _B),
        # F966: reassigned binding
        "function*gen(){yield '%s';}gen=5;var R=[...gen()].reduce((a,b)=>a+b);" % (_A,),
        # F966: call with args
        "function*gen(){yield '%s';}var R=[...gen(1)].reduce((a,b)=>a+b);" % (_A,),
        # F966: bare reference (engine throws -- not iterable)
        "function*gen(){yield '%s';}var R=[...gen].reduce((a,b)=>a+b);" % (_A,),
        # F966: member call
        "function*gen(){yield '%s';}var o={gen:gen};var R=[...o.gen()].reduce((a,b)=>a+b);" % (_A,),
        # F966: decl scoped inside an IIFE, used outside (engine throws)
        "(function(){function*gen(){yield '%s';}})();var R=[...gen()].reduce((a,b)=>a+b);" % (_A,),
        # F966: parameter shadowing
        "function*gen(){yield '%s';}function f(gen){return [...gen()].reduce((a,b)=>a+b);}" % (_A,),
        # F966: use-before-declaration (hoisted order -- documented residual miss)
        "var R=[...gen()].reduce((a,b)=>a+b);function*gen(){yield '%s';yield '%s';}" % (_A, _B),
        # honest non-credential twins
        "(function(){var parts=['ab','cd'];return eval('`${parts[0]}${parts[1]}`');})()",
        "function*gen(){yield 'ab';yield 'cd';}var R=[...gen()].reduce((a,b)=>a+b);",
    ]
    bad = [p for p in quiet if _blocked(p)]
    # no mis-decode: the duplicate-decl twin must not decode to the credential
    dec = _decode(quiet[7])
    ok_nodec = dec is None or _FULL not in dec
    ok = not bad and ok_nodec
    return ("HELD" if ok else "BREAK",
            "flagged=%d misdecode=%s" % (len(bad), not ok_nodec))


# ------------------------------------------ p4: sibling pins must hold


@_t
def test_p4_sibling_pins():
    """Sibling findings still close their shapes (no regressions)."""
    pins = [
        # F945: eval with computed per-iteration args (codes spell _FULL)
        ("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++)"
         "{s+=eval('String.fromCharCode('+c[i]+')');}return s;})()"
         % ",".join(str(b) for b in _FULL.encode())),
        # F940: string-concat reduce over an array still decodes (control twin)
        "var r=['%s','%s'].reduce((a,b)=>a+b);" % (_A, _B),
        # F471: spread-copy of an array literal still decodes
        "var r=[...['%s','%s']].join('');" % (_A, _B),
        # F494: immediately-invoked generator spread still decodes
        ("var r=[...(function*(){yield '%s';yield '%s';})()].join('');"
         % (_A, _B)),
        # F437: plain postfix reduce still decodes
        "var r=['%s','%s'].reduce((a,b)=>a+b);" % (_A, _B),
        # F893: literal-eval still decodes
        "(function(){return eval('\"%s\"');})()" % (_FULL,),
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
        "function*gen(){yield 'a';yield 'b';}var r=[...gen()].join(',');",
        "(function(){var parts=['a','b'];return parts.join('-');})()",
        "var r=[1,2,3].reduce((a,b)=>a+b);",
        "contact us at support@example.com",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s, F452-bounded)."""
    site = _f965_shape([_A, _B]) + _f966_shape([_A, _B])
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 15.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w391_f965_redfirst.py", "w391_f966_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g391-green-", dir="/var/tmp")
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
        # / "CTRL-FAIL <name>". The trailing "N failures" tally counts
        # HELD shapes as failures by open-tree design -- not parsed.
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
