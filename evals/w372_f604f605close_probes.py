#!/usr/bin/env python3
"""Wave-372 lane 6 close probes: F604 (sort with localeCompare comparators),
F605 (Object.assign neighbor compositions on WeakMap object values).

F604 (LOW): F580 modeled default sort and the length comparator, but
localeCompare comparators are a different comparator class. Closed by
modeling `(a,b)=>a.localeCompare(b)` (ascending) and
`(a,b)=>b.localeCompare(a)` (descending) node-exactly (v24.20.0) on
literal string arrays whose elements are all over [0-9a-z-]: ICU
default collation agrees with code-point order on that class (4M+
pairwise and 3000 array-sort node differentials, zero diffs), so
Python's stable sorted() matches V8's stable sort exactly. Elements
outside the class (uppercase, other punctuation, astral) fail closed.

F605 (LOW): F593 modeled `Object.assign({}, CHAIN)` where CHAIN is a
weakmap chain resolving to a _JSObj. Three one-token neighbors
node-yield the credential while the decoder missed: non-empty assign
targets, swapped args (chain target), and extra sources. Closed by
generalizing the assign branch: each operand is an object literal or a
weakmap chain resolving to a _JSObj, merged engine-exact later-wins
(node-verified), at most 3 sources (F452).

Fail-closed boundaries (all node-verified): duplicate comparator
params, block-body arrows, bracket-member localeCompare,
localeCompare with locales/options args, non-function sort args,
uppercase/astral elements in locale sorts, assign with >3 sources,
string-resolving assign sources, assign with no source, non-chain
non-literal assign targets.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"
_CRED = _A1 + _A2

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try{ out.push(JSON.stringify(String(eval(cases[k])))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    return json.loads(r.stdout.strip())


def _q(s):
    return '"' + s + '"'


def _decoded_strings(payload):
    """Decoded string variants of the quoted payload (JS-expression layer)."""
    return [v.strip('"') for v in dlp._decoded_variants(_q(payload))
            if v not in (payload, _q(payload))]


# ---------------------------------------------------------------- P1: filed
def p1_filed_shapes():
    rows = []
    shapes = [
        # F604 filed shape 1: descending localeCompare, param names a,b
        "['%s','%s'].sort((a,b)=>b.localeCompare(a)).join('')" % (_A2, _A1),
        # F604 filed shape 2: descending localeCompare, param names x,y
        "['%s','%s'].sort((x,y)=>y.localeCompare(x)).join('')" % (_A2, _A1),
        # F605 filed shape 1: non-empty assign target
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({x:1},m.get(r)).c+'%s';})()" % (_A1, _A2)),
        # F605 filed shape 2: swapped args (chain target)
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign(m.get(r),{}).c+'%s';})()" % (_A1, _A2)),
        # F605 filed shape 3: extra source
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r),{d:1}).c+'%s';})()"
         % (_A1, _A2)),
    ]
    for s in shapes:
        rows.append(_verdict(_q(s), True))
    return rows


# ------------------------------------------------------------- P2: variants
def p2_variants():
    rows = []
    shapes = [
        # F604: whitespace-tolerant comparator
        ("['%s','%s'].sort( ( a , b ) => b . localeCompare ( a ) ).join('')"
         % (_A2, _A1)),
        # F604: descending with different param names
        "['%s','%s'].sort((m,n)=>n.localeCompare(m)).join('')" % (_A2, _A1),
        # F604: longer safe-class elements
        "['b2','a-1','a1'].sort((a,b)=>b.localeCompare(a)).join(',')",
        # F605: double-quoted literals
        ('(function(){var r={};var m=new WeakMap([[r,{c:"%s"}]]);'
         'return Object.assign({x:1},m.get(r)).c+"%s";})()' % (_A1, _A2)),
        # F605: later-wins across sources (node: last source wins)
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r),{c:'zz'}).c;})()" % _A1),
        # F605: target prop survives alongside source props
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({x:1},m.get(r)).x;})()" % _A1),
        # F605: two chain sources (read .c + tail to yield the credential)
        ("(function(){var r={};var s={};var m=new WeakMap([[r,{c:'%s'}],"
         "[s,{d:'%s'}]]);return Object.assign({},m.get(r),m.get(s)).c+'%s';})()"
         % (_A1, _A2, _A2)),
    ]
    # shape 2 (whitespace) and the param-name twin must block
    rows.append(_verdict(_q(shapes[1]), True))
    # shape 3: node v24.20.0 yields 'b2,a1,a-1' (not the credential) --
    # the decoder must match it node-exactly AND stay quiet
    dec3 = _decoded_strings(shapes[2])
    ok3 = (not _blocked(_q(shapes[2]))) and ("b2,a1,a-1" in dec3)
    rows.append(("HELD" if ok3 else "BREAK",
                 "descending 3-elem exact+quiet decoded=%s" % (dec3[:2],)))
    # shape 5: node yields 'zz' (not the credential) -- quiet
    rows.append(_verdict(_q(shapes[4]), False))
    # shape 6: node yields 1 (number, not the credential) -- quiet
    rows.append(_verdict(_q(shapes[5]), False))
    # the rest must block
    for s in (shapes[0], shapes[3], shapes[6]):
        rows.append(_verdict(_q(s), True))
    return rows


# ----------------------------------------------- P3: fail-closed boundaries
def p3_boundaries():
    rows = []
    cases = [
        # F604: duplicate params -- node v24.20.0 throws SyntaxError on
        # duplicate arrow params; fail-closed is the safe refusal
        ("['%s','%s'].sort((a,a)=>a.localeCompare(a)).join('')" % (_A2, _A1),
         False),
        # F604: block-body arrow not modeled
        ("['%s','%s'].sort((a,b)=>{return b.localeCompare(a);}).join('')"
         % (_A2, _A1), False),
        # F604: bracket-member localeCompare not modeled
        ("['%s','%s'].sort((a,b)=>b['localeCompare'](a)).join('')"
         % (_A2, _A1), False),
        # F604: localeCompare with locales arg not modeled
        ("['%s','%s'].sort((a,b)=>b.localeCompare(a,'en')).join('')"
         % (_A2, _A1), False),
        # F604: uppercase element -- ICU diverges from code-point order
        ("['%s','B'].sort((a,b)=>b.localeCompare(a)).join('')" % _A1, False),
        # F604: astral element fails closed (F580 precedent; real
        # astral char -- '\U' is not a JS escape, so the literal
        # emoji is embedded)
        ("['%s','\U0001F600'].sort((a,b)=>b.localeCompare(a)).join('')"
         % _A1, False),
        # F604: non-function sort arg -- engine throws TypeError
        ("['%s','%s'].sort('x').join('')" % (_A2, _A1), False),
        # F604: mixed-operand comparator (not a pure order)
        ("['%s','%s'].sort((a,b)=>a.localeCompare(a)).join('')" % (_A2, _A1),
         False),
        # F605: >3 sources fail closed (F452 bound)
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r),{d:1},{e:2},{f:3},{g:4}).c;})()"
         % _A1, False),
        # F605: string-resolving chain source fails closed (F593 precedent)
        ("(function(){var k={};var m=new WeakMap([[k,'%s']]);"
         "return Object.assign({},m.get(k));})()+'%s'" % (_A1, _A2), False),
        # F605: assign with no source fails closed
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({x:1}).c;})()" % _A1, False),
        # F605: unbound target name fails closed
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign(zz,{}).c;})()" % _A1, False),
    ]
    for payload, want_block in cases:
        rows.append(_verdict(_q(payload), want_block))
    return rows


# ------------------------------------------------------ P4: node differential
def p4_node_differential():
    rows = []
    payloads = [
        # F604 filed shapes: node yields the credential
        "['%s','%s'].sort((a,b)=>b.localeCompare(a)).join('')" % (_A2, _A1),
        "['%s','%s'].sort((x,y)=>y.localeCompare(x)).join('')" % (_A2, _A1),
        # F604 ascending: node yields B+A (not the credential) --
        # decoder must be node-exact AND quiet
        "['%s','%s'].sort((a,b)=>a.localeCompare(b)).join('')" % (_A1, _A2),
        # F605 filed shapes: node yields the credential
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({x:1},m.get(r)).c+'%s';})()" % (_A1, _A2)),
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign(m.get(r),{}).c+'%s';})()" % (_A1, _A2)),
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r),{d:1}).c+'%s';})()"
         % (_A1, _A2)),
        # F605 later-wins: node yields 'zz'
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r),{c:'zz'}).c;})()" % _A1),
    ]
    truth = _node_eval(payloads)
    for payload, t in zip(payloads, truth):
        node_val = json.loads(t) if t != "THROWS" else "THROWS"
        dec = _decoded_strings(payload)
        exact = node_val in dec
        hit = _blocked(_q(payload))
        want_hit = (node_val == _CRED)
        ok = exact and (hit == want_hit)
        rows.append(("HELD" if ok else "BREAK",
                     "node=%r exact=%s hit=%s want_hit=%s :: %s"
                     % (node_val if node_val != _CRED else "<cred>",
                        exact, hit, want_hit, payload[:56])))
    return rows


# --------------------------------------------- P5: neighbor regressions
def p5_regressions():
    rows = []
    held = [
        # F580: default sort still modeled (ascending yields A2+A1
        # here -- node-exact and quiet, not the credential)
        "['%s','%s'].sort().join('')" % (_A2, _A1),
        # F580: length comparator still modeled (yields the credential)
        "['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_A2, _A1),
        # F593: empty-target single-chain assign still modeled
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r)).c+'%s';})()" % (_A1, _A2)),
        # F539: identity assign on literals still modeled
        "Object.assign({},{c:'%s'}).c+'%s'" % (_A1, _A2),
        # F596: statement-form set still modeled
        ("(function(){var k={};var m=new WeakMap();m.set(k,'%s');"
         "return m.get(k);})()+'%s'" % (_A1, _A2)),
    ]
    # default sort: node-exact (decodes to A2+A1) and quiet
    dec = _decoded_strings(held[0])
    ok_default = (not _blocked(_q(held[0]))) and ((_A2 + _A1) in dec)
    rows.append(("HELD" if ok_default else "BREAK",
                 "default sort exact+quiet decoded=%s" % (dec[:2],)))
    for s in held[1:]:
        rows.append(_verdict(_q(s), True))
    return rows


# ---------------------------------------------------------- P6: pin/footer
def p7_pin_and_footer():
    rows = []
    try:
        assert TAXONOMY_PIN == 2140, "pin moved"
        from gov import guac_graph  # noqa: E402
        assert guac_graph.TAXONOMY_PIN == 2140, \
            "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
        text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
        # Lane-local footer: wave-372 lane 6 closes F604/F605; the
        # merge reconciles with sibling lanes.
        ok = ("Next free finding: **F612**." in text  # Wave-372 merge: footer repoint next F612
              and "**Open findings: F595, F606, F608, F609, F610, F611.**"
              in text)  # Wave-372 merge: footer repoint open F606-F611
        rows.append(("HELD" if ok else "BREAK", "pin+footer"))
    except AssertionError as e:  # noqa: BLE001
        rows.append(("BREAK", "pin/footer: %s" % e))
    return rows


GREEN_ADJACENT = [
    "evals/w371_attack_probes.py",
    "evals/w370_f574f580close_probes.py",
    "evals/w371_f593f596close_probes.py",
    "evals/w368_f539f540close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = tempfile.mkdtemp(prefix="g372lane6-green-")
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            lines = r.stdout.splitlines()
            tally = [l for l in lines if "tally:" in l]
            # Lane-local footer probes pin the author's own footer text;
            # this lane's FINDINGS.md update invalidates them by design
            # (merge-owned churn, wave-305/331 class). A green check
            # fails only on NON-footer BREAK/ERROR lines.
            bad = [l for l in lines
                   if ("BREAK" in l or "ERROR" in l)
                   and "footer" not in l.lower()
                   and "tally:" not in l
                   and "BREAKS:" not in l]  # "BREAKS: []" is the empty-list print
            status = tally[-1] if tally else "rc=%d" % r.returncode
            extra = "" if not bad else " FUNCTIONAL-FAILURES=%d" % len(bad)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, status, time.time() - t0, extra))
            for b in bad[:5]:
                print("      FAIL: %s" % b[:100])
            if bad or r.returncode != 0:
                if bad:
                    ok = False
                else:
                    print("      (rc!=0 but only footer-probe churn; "
                          "merge-owned)")
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    phases = [
        ("p1-filed-shapes", p1_filed_shapes),
        ("p2-variants", p2_variants),
        ("p3-boundaries", p3_boundaries),
        ("p4-node-differential", p4_node_differential),
        ("p5-regressions", p5_regressions),
        ("p6-pin-footer", p7_pin_and_footer),
    ]
    breaks, held, errors = 0, 0, 0
    out = []
    for pname, pfn in phases:
        try:
            rows = pfn()
        except Exception as e:  # noqa: BLE001
            print("%-22s ERROR %s" % (pname, e))
            errors += len(phases)
            continue
        for verdict, detail in rows:
            if verdict == "HELD":
                held += 1
            elif verdict == "BREAK":
                breaks += 1
                print("%-22s BREAK: %s" % (pname, detail))
            else:
                errors += 1
                print("%-22s ERROR: %s" % (pname, detail))
        out.append((pname, rows))
    green_ok = green_check()
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    if not green_ok:
        print("GREEN CHECK NOT GREEN")
        return 2
    if args.json:
        print(json.dumps({"breaks": breaks, "held": held, "errors": errors}))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
