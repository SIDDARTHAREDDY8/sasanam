#!/usr/bin/env python3
"""Wave-373 lane 5 close battery: F609 String.replace function replacements.

F609 (LOW, filed attack round 40 as F608, renumbered wave-372 merge per
wave-272): String.prototype.replace with FUNCTION-valued replacements
bypasses the bounded static JS-expression decoder -- F603 (CLOSED,
wave-372 lane 5) models literal patterns and $-patterns in the
replacement STRING, but a function-valued replacement computes the
replacement at runtime and had no modeled path. This lane models the
replacer callback node-exactly (v24.20.0): the replacer is called once
per modeled match with the engine's positional args (match, p1..pn,
offset, string); its return value is inserted LITERALLY (node does not
$-expand function return values). Return grammar: string/numeric
literal, callback param, P==='lit'/P===N (strict only), and
COND ? A : B over those. 3+ params, /,/g with a function replacement,
loose ==/!==, concatenation, template literals, unknown names, member
access, and nested ternaries fail closed (documented).

Correction (honest): the filed args-using shape used off===5, but node
puts the 'XX' match at offset 9 (A1 is 9 chars), so the filed shape
never recovered the credential on node. off===9 is the node-exact twin.
The off===5 form is kept here as an exact-value else-branch pin.

All probes print HELD on the closed tree (green), BREAK on the open
tree for the filed shapes. Node differential shells to node v24.20.0
at runtime. No paid API calls (grep-verified $0).
"""
import argparse
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Concatenated: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"          # len 9
_A2 = "456789" + "abcdef"       # len 12

TAXONOMY_PIN = 2140  # pin 2140 (unchanged wave-373)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ------------------------------------------------------------- P1: filed
def p1_f609_filed_shapes():
    shapes = [
        # string pattern, zero-arg arrow returning a literal
        "\"'%sXX'.replace('XX',()=>'%s')\"" % (_A1, _A2),
        # regex-pattern twin
        "\"'%sXX'.replace(/XX/,()=>'%s')\"" % (_A1, _A2),
        # args-using twin (corrected: off===9 is the node-exact form;
        # the filed off===5 never recovered the credential on node)
        "\"'%sXX'.replace('XX',(m,off)=>off===9?'%s':'')\"" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ---------------------------------------------------------- P2: variants
def p2_f609_variants():
    shapes = [
        # block-body twin
        "\"'%sXX'.replace('XX',()=>{return '%s';})\"" % (_A1, _A2),
        # block-body twin, no semicolon (node ASI)
        "\"'%sXX'.replace('XX',()=>{return '%s'})\"" % (_A1, _A2),
        # function-expression twin
        "\"'%sXX'.replace('XX',function(){return '%s';})\"" % (_A1, _A2),
        # single-param arrow returning a literal
        "\"'%sXX'.replace('XX',(m)=>'%s')\"" % (_A1, _A2),
        # bare-ident single param
        "\"'%sXX'.replace('XX',m=>'%s')\"" % (_A1, _A2),
        # reversed === operand order
        "\"'%sXX'.replace('XX',(m,off)=>9===off?'%s':'')\"" % (_A1, _A2),
        # string comparison on the match param
        "\"'%sXX'.replace('XX',(m)=>m==='XX'?'%s':'q')\"" % (_A1, _A2),
        # named function expression
        "\"'%sXX'.replace('XX',function f(){return '%s';})\"" % (_A1, _A2),
        # duplicate params in function form: last-wins (node sloppy-mode)
        "\"'%sXX'.replace('XX',function(m,m){return '%s';})\"" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


# ------------------------------------------------------------ P3: bounds
def p3_f609_bounds():
    # Shapes that must fail closed (never mis-decode the credential).
    quiet = [
        # 3+ params: documented residual
        "\"'%sXX'.replace('XX',(m,off,str)=>off)\"" % _A1,
        # /,/g with a function replacement: documented residual
        "\"'a,b'.replace(/,/g,()=>'X')\"",
        # loose ==: not modeled
        "\"'%sXX'.replace('XX',(m,off)=>off==9?'%s':'')\"" % (_A1, _A2),
        # !==: not modeled
        "\"'%sXX'.replace('XX',(m,off)=>off!==9?'%s':'')\"" % (_A1, _A2),
        # concatenation in the return: not modeled
        "\"'%sXX'.replace('XX',()=>'%s'+'q')\"" % (_A1, _A2),
        # template literal return: not modeled
        "\"'%sXX'.replace('XX',()=>`%s`)\"" % (_A1, _A2),
        # unknown name: not a param
        "\"'%sXX'.replace('XX',(m)=>q)\"" % _A1,
        # member access in the return: not modeled
        "\"'%sXX'.replace('XX',(m)=>m.length)\"" % _A1,
        # nested ternary: not modeled
        "\"'%sXX'.replace('XX',(m)=>m==='XX'?(m==='YY'?'a':'b'):'c')\"" % _A1,
        # non-=== ternary condition: not modeled
        "\"'%sXX'.replace('XX',()=>'a'?'%s':'c')\"" % (_A1, _A2),
        # duplicate params in arrow form: node throws SyntaxError
        "\"'%sXX'.replace('XX',(m,m)=>m)\"" % _A1,
    ]
    bad = [s for s in quiet if not _misses(s)]
    # Exact-value pins: the model must EVALUATE the condition, not just
    # take a branch. off===5 is false on node (match at 9): the decoder
    # must produce exactly A1, and find_credential must stay quiet.
    else_branch = "\"'%sXX'.replace('XX',(m,off)=>off===5?'%s':'')\"" % (_A1, _A2)
    else_ok = _decode(else_branch) == "\"%s\"" % _A1 and _misses(else_branch)
    # Dollar patterns are NOT expanded in function return values
    # (node-verified): the return inserts literally.
    dollar = "\"'XX'.replace('XX',()=>'$$')\""
    dollar_ok = _decode(dollar) == "\"$$\"" and _misses(dollar)
    # With a capture group, the 2nd positional arg is p1, not offset
    # (node-verified): (m,off)=>off binds off to the group 'X'.
    group = "\"'aXXb'.replace(/(X)(X)/,(m,off)=>off)\""
    group_ok = _decode(group) == "\"aXb\""
    ok = not bad and else_ok and dollar_ok and group_ok
    return ("HELD" if ok else "BREAK",
            "%d/%d bounds fail closed, else-exact=%s dollar-literal=%s group-pos=%s"
            % (len(quiet) - len(bad), len(quiet), else_ok, dollar_ok,
               group_ok))


# ----------------------------------------------------- P4: compositions
def p4_compositions():
    # F603 literal-pattern replacement still decodes alongside.
    s1 = "\"'%sX%s'.replace('X','')\"" % (_A1, _A2)
    # F464 comma scope with a STRING replacement still decodes.
    s2 = "\"'a,b'.replace(/,/g,'X')\""
    # Two function replacements in one payload both decode.
    s3 = "\"'%sXX'.replace('XX',()=>'%s')+''\"" % (_A1, _A2)
    # Chained: fn-replace feeding a second fn-replace.
    s4 = "\"'%sXX'.replace('XX',()=>'%s').replace('456789',()=>'456789')\"" % (_A1, _A2)
    ok = (_blocked(s1) and not _blocked(s2)
          and _decode(s3) == "\"%s%s\"" % (_A1, _A2)
          and _blocked(s4))
    return ("HELD" if ok else "BREAK",
            "f603-held=%s f464-quiet=%s two-fn=%s chained=%s"
            % (_blocked(s1), not _blocked(s2),
               _decode(s3) == "\"%s%s\"" % (_A1, _A2), _blocked(s4)))


# ------------------------------------------------- P5: node differential
_NODE_CASES = [
    "'%sXX'.replace('XX',()=>'%s')",
    "'%sXX'.replace(/XX/,()=>'%s')",
    "'%sXX'.replace('XX',(m,off)=>off===9?'%s':'')",
    "'%sXX'.replace('XX',(m,off)=>off===5?'%s':'')",
    "'XX'.replace('XX',()=>'$$')",
    "'%sXX'.replace('XX',(m)=>m)",
    "'%sXX'.replace('XX',(m,off)=>'%s'===m?'Q':'Z')",
    "'aXb'.replace('X',()=>7)",
    "'%sXX'.replace('XX',()=>{return '%s';})",
    "'%sXX'.replace('XX',function(){return '%s';})",
    "'abc'.replace('ZZ',()=>'%s')",
    "'aXXb'.replace(/(X)(X)/,(m,p1)=>p1)",
    "'aXXb'.replace(/(X)(X)/,(m,off)=>off)",
    "'abc'.replace('',()=>'X')",
    "'aXb'.replace('X','Q')",
]


def p5_node_differential():
    mismatches = []
    for tmpl in _NODE_CASES:
        n = tmpl.count("%s")
        args = (_A1, _A2)[:n] if n <= 2 else (_A1, _A2)
        expr = tmpl % args
        got = _decode("\"" + expr + "\"")
        proc = subprocess.run(
            ["node", "-e",
             "console.log(JSON.stringify(eval(%s)))" % json.dumps(expr)],
            capture_output=True, text=True, timeout=20)
        want = json.loads(proc.stdout.strip())
        if got != "\"" + want + "\"":
            mismatches.append("%s: dec=%r node=%r" % (tmpl, got, want))
    return ("HELD" if not mismatches else "BREAK",
            "%d/%d decoder agrees with node v24.20.0%s"
            % (len(_NODE_CASES) - len(mismatches), len(_NODE_CASES),
               "" if not mismatches else ": " + "; ".join(mismatches)))


# ------------------------------------------------------ P6: pin + footer
def p6_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F672**" in text  # Wave-373 lane 5: next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "**Open findings: F662, F663, F664, F665, F666, F667, F668, F669, F670, F671.**"  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
              in text  # Wave-373 lane 5: F609 closed
          and "**Status: CLOSED 2026-10-08 wave-373 lane 5." in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------ P7: perf bound
def p7_perf_bound():
    # Hostile input: many function-replace anchors -- each replacer call
    # is bounded single-call work (F452: the call charges one op); the
    # corpus must starve fast and stay quiet.
    junk = ("\"'abXX'.replace('XX',()=>'cd')\""
            "\"'abXX'.replace('XX',(m,off)=>off===9?'cd':'')\""
            "\"'abXX'.replace('XX',(m,off,str)=>off)\"") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor fn-replace corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w372_f609_redfirst.py",
    "evals/w372_f603close_probes.py",
    "evals/w372_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g373l5-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" % (rel,
                                                 line[-1] if line else "rc=%d" % r.returncode,
                                                 time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f609-filed", p1_f609_filed_shapes),
    ("p2-f609-variants", p2_f609_variants),
    ("p3-f609-bounds", p3_f609_bounds),
    ("p4-compositions", p4_compositions),
    ("p5-node-differential", p5_node_differential),
    ("p6-pin-footer", p6_pin_footer),
    ("p7-perf-bound", p7_perf_bound),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", default=None)
    args = parser.parse_args()
    breaks, held, errors = 0, 0, 0
    for name, fn in PROBES:
        if args.probe and args.probe != name:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-22s %s | %s" % (name, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 1
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
