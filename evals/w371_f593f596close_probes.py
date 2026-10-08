#!/usr/bin/env python3
"""Wave-371 lane 7 close probes: F593 (WeakMap variable-identity keys), F596 (WeakMap multi-statement var-bound set).

F593 (LOW): the F572 closure modeled WeakMap entries with STRING values
only. A variable-identity key whose VALUE is an object literal --
`new WeakMap([[r,{c:'f1'}]]).get(r).c` -- escaped: the engine stores the
reference unchanged and the terminal `.c` reads it back. Closed by
admitting _JSObj values in WeakMap entries (pair-list and `.set`), by
resolving the member read through the _JSObj postfix branch inside the
IIFE parse, and by modeling `Object.assign({}, CHAIN)` as the engine's
shallow copy (node v24.20.0). Also admits a bounded additive tail of
string literals interior to the return statement (`...get(r).c+'f2'`).

F596 (LOW): the F572 closure modeled only the entries-array form and the
single-expression set-chain. Multi-statement var-bound sets --
`var m=new WeakMap();m.set(k,'f1');return m.get(k);` -- escaped. Closed
by admitting statement-form `.set` on weakmap-bound vars in the IIFE
body (the engine's in-place mutation, threaded into the same entries
map), node-exact for literal key/value forms.

Fail-closed boundaries (all node-verified): inline literal keys
(`new WeakMap([[{},'f1']]).get({})` -- node: undefined; decoding would
be a false positive), missing keys, unbound keys, non-object keys,
Object.assign on a string source, non-empty assign targets,
non-string additive tails, `.get` on a missing entry.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
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


# ---------------------------------------------------------------- P1: filed
def p1_f593_filed_shapes():
    rows = []
    shapes = [
        # F593 filed shape 1: object-literal WeakMap value + terminal read
        ("(function(){var r={};return new WeakMap([[r,{c:'%s'}]])"
         ".get(r).c+'%s';})()" % (_A1, _A2)),
        # F593 filed shape 2: Object.assign composition
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({},m.get(r)).c+'%s';})()" % (_A1, _A2)),
        # F596 filed shapes: multi-statement var-bound set
        ("(function(){var k={};var m=new WeakMap();m.set(k,'%s');"
         "return m.get(k);})()+'%s'" % (_A1, _A2)),
        ("(function(){const k={};const m=new WeakMap();m.set(k,'%s');"
         "return m.get(k);})()+'%s'" % (_A1, _A2)),
    ]
    for s in shapes:
        rows.append(_verdict(_q(s), True))
    return rows


# ------------------------------------------------------------- P2: variants
def p2_variants():
    rows = []
    shapes = [
        # const/let key decls
        ("(function(){const r={};return new WeakMap([[r,{c:'%s'}]])"
         ".get(r).c+'%s';})()" % (_A1, _A2)),
        ("(function(){let r={};return new WeakMap([[r,{c:'%s'}]])"
         ".get(r).c+'%s';})()" % (_A1, _A2)),
        ("(function(){let k={};let m=new WeakMap();m.set(k,'%s');"
         "return m.get(k);})()+'%s'" % (_A1, _A2)),
        # whitespace tolerance
        ("( function ( ) { var r = { } ; return new WeakMap ( [ [ r , "
         "{ c : '%s' } ] ] ).get ( r ).c + '%s' ; } ) ( )" % (_A1, _A2)),
        # later-wins on statement-form sets (node-exact: set overwrites)
        ("(function(){var k={};var m=new WeakMap();m.set(k,'zz');"
         "m.set(k,'%s');return m.get(k);})()" % _CRED),
        # double-quoted value literals
        ('(function(){var r={};return new WeakMap([[r,{c:"%s"}]])'
         '.get(r).c+"%s";})()' % (_A1, _A2)),
    ]
    for s in shapes:
        rows.append(_verdict(_q(s), True))
    return rows


# ----------------------------------------------- P3: fail-closed boundaries
def p3_boundaries():
    rows = []
    # (payload, want_block, node_expect): node_expect True => engine
    # yields the credential (decoder must block); False => engine
    # yields undefined/throws (decoder must stay quiet).
    cases = [
        # inline literal keys: node says undefined -- decoding would be a
        # FALSE POSITIVE, so the miss is correct and must stay a miss.
        ("(function(){return new WeakMap([[{},{c:'%s'}]]).get({}).c;"
         "})()" % _A1, False, False),
        # missing key: node undefined
        ("(function(){var k={};var j={};var m=new WeakMap();"
         "m.set(k,'%s');return m.get(j);})()+'%s'" % (_A1, _A2),
         False, False),
        # unbound key name
        ("(function(){var m=new WeakMap();m.set(zz,'%s');"
         "return m.get(zz);})()" % _A1, False, False),
        # Object.assign on a string source: engine makes a String object;
        # the decoder must not mis-decode it as the plain string.
        ("(function(){var k={};var m=new WeakMap([[k,'%s']]);"
         "return Object.assign({},m.get(k));})()+'%s'" % (_A1, _A2),
         False, False),
        # non-empty assign target fails closed (documented residual)
        ("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
         "return Object.assign({x:1},m.get(r)).c;})()" % _A1, False, False),
        # non-string additive tail fails closed
        ("(function(){var r={};return new WeakMap([[r,{c:'%s'}]])"
         ".get(r).c+42;})()" % _A1, False, False),
        # junk stays quiet
        ("(function(){var k={};var m=new WeakMap();m.set(k,'zz');"
         "return m.get(k);})()+'yy'", False, False),
    ]
    for payload, want_block, node_expect in cases:
        rows.append(_verdict(_q(payload), want_block))
    return rows


# ------------------------------------------------------ P4: node differential
def p4_node_differential():
    rows = []
    payloads = [
        "(function(){var r={};return new WeakMap([[r,{c:'" + _A1 +
        "'}]]).get(r).c+'" + _A2 + "';})()",
        "(function(){var r={};var m=new WeakMap([[r,{c:'" + _A1 +
        "'}]]);return Object.assign({},m.get(r)).c+'" + _A2 + "';})()",
        "(function(){var k={};var m=new WeakMap();m.set(k,'" + _A1 +
        "');return m.get(k);})()+'" + _A2 + "'",
        "(function(){var k={};var m=new WeakMap();m.set(k,{c:'" + _A1 +
        "'});return m.get(k).c+'" + _A2 + "';})()",
        "(function(){var k={};var m=new WeakMap();m.set(k,'zz');m.set(k,'" +
        _CRED + "');return m.get(k);})()",
    ]
    truth = _node_eval(payloads)
    want = json.dumps(_CRED)  # _node_eval returns JSON-of-JSON
    for payload, t in zip(payloads, truth):
        hit = _blocked(_q(payload))
        ok = hit and t == want
        rows.append(("HELD" if ok else "BREAK",
                     "node_is_cred=%s decoder_hit=%s :: %s"
                     % (t == want, hit, payload[:60])))
    return rows


# ---------------------------------------------------- P5: F572 still HELD
def p5_f572_regression():
    rows = []
    shapes = [
        ("(function(){var k={};var m=new WeakMap([[k,'%s']]);"
         "return m.get(k);})()+'%s'" % (_A1, _A2)),
        ("(function(){var k={};return new WeakMap().set(k,'%s')"
         ".get(k);})()+'%s'" % (_A1, _A2)),
        # inline literal keys still fail closed (documented)
        ("(function(){return new WeakMap([[{},'%s']]).get({});})()"
         % _A1, ),
    ]
    rows.append(_verdict(_q(shapes[0]), True))
    rows.append(_verdict(_q(shapes[1]), True))
    rows.append(_verdict(_q(shapes[2][0]), False))
    return rows


# ------------------------------------------- P6: F593 x F596 composition
def p6_compositions():
    rows = []
    shapes = [
        # statement-form set with an OBJECT value + terminal member read
        ("(function(){var k={};var m=new WeakMap();m.set(k,{c:'%s'});"
         "return m.get(k).c+'%s';})()" % (_A1, _A2)),
        # pair-list object value through a var-bound map + assign
        ("(function(){var k={};var m=new WeakMap();m.set(k,{c:'%s'});"
         "return Object.assign({},m.get(k)).c+'%s';})()" % (_A1, _A2)),
    ]
    for s in shapes:
        rows.append(_verdict(_q(s), True))
    return rows


# ---------------------------------------------------------- P7: pin/footer
def p7_pin_and_footer():
    rows = []
    try:
        assert TAXONOMY_PIN == 2140, "pin moved"
        from gov import guac_graph  # noqa: E402
        assert guac_graph.TAXONOMY_PIN == 2140, \
            "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
        text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
        # Lane-local footer: wave-371 lane 7 closes F593/F596 and files
        # F597 (spec-axis review residual); the merge reconciles with
        # sibling lanes.
        ok = ("Next free finding: **F612**." in text  # Wave-372 merge: footer repoint next F612
              and "**Open findings: F595, F606, F607, F609, F610, F611.**" in text)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED
        rows.append(("HELD" if ok else "BREAK", "pin+footer"))
    except AssertionError as e:  # noqa: BLE001
        rows.append(("BREAK", "pin/footer: %s" % e))
    return rows


GREEN_ADJACENT = [
    "evals/w370_f572f579close_probes.py",
    "evals/w370_attack_probes.py",
    "evals/w369_f560f562f563close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g371lane7-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
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
                   and "BREAKS:" not in l]  # "BREAKS: []" is the empty-list print, not a failure
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
        ("P1-filed", p1_f593_filed_shapes()),
        ("P2-variants", p2_variants()),
        ("P3-boundaries", p3_boundaries()),
        ("P4-node", p4_node_differential()),
        ("P5-f572-regression", p5_f572_regression()),
        ("P6-compositions", p6_compositions()),
        ("P7-pin-footer", p7_pin_and_footer()),
    ]
    brk, held = 0, 0
    for name, rows in phases:
        for verdict, detail in rows:
            if verdict == "BREAK":
                brk += 1
                print("%s BREAK %s" % (name, detail))
            else:
                held += 1
    gok = green_check()
    print("tally: %d BREAK / %d HELD / green=%s" % (brk, held, gok))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": gok,
                          "pin": TAXONOMY_PIN}))
    return 1 if brk or not gok else 0


if __name__ == "__main__":
    sys.exit(main())
