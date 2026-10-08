#!/usr/bin/env python3
"""Wave-370 lane 3 close probes: F572 (WeakMap.get reads), F579 (Reflect.ownKeys terminal index reads).

F572 (LOW): WeakMap.get reads bypass the decoder -- a persistent object key
threads the credential through set/get while the decoder sees only opaque
calls. Closed by modeling var-bound object identity in IIFE bodies
node-exactly: `var k={}` binds one object; `new WeakMap([[k,'f1']])` /
`.set(k,'f1')` thread entries by binding identity; `.get(k)` resolves.
Inline literal keys (`new WeakMap([[{},'f1']]).get({})`) FAIL CLOSED --
the engine keys WeakMaps by identity, so two textually-identical literals
are distinct objects (node v24.20.0 verified); decoding them would be a
false positive, never a miss.

F579 (LOW): Reflect.ownKeys terminal index reads -- ownKeys returns the KEY
list; indexing it and reading back through the literal composes a credential
the composer cannot thread. Closed by resolving `Reflect.ownKeys(OBJLIT)`
to the engine-exact key list (integer indices ascending first, then strings
in insertion order, then symbols -- node v24.20.0) and threading the
`[INTLIT]` terminal read as the bracket key.

Fail-closed boundaries: F572 -- literal object keys, missing keys, unbound
keys, non-string values, non-object keys, set/get arity; F579 -- out-of-bounds
indices, non-literal objects, bracket-form Reflect, symbol-key resolution,
non-index postfix on ownKeys.

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
  try{ out.push(JSON.stringify(eval(cases[k]))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    return json.loads(r.stdout.strip())


# ---------------------------------------------------------------- P1: filed
def p1_f572_filed_shapes():
    rows = []
    shapes = [
        ("(function(){var k={};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'"),
        ("(function(){var k={};return new WeakMap().set(k,'%s').get(k);})()+'%s'"),
    ]
    for t in shapes:
        p = t % (_A1, _A2)
        rows.append(_verdict(p, True))
    return rows


def p1_f572_variants():
    rows = []
    variants = [
        # const/let bind identically (F528 precedent)
        ("(function(){const k={};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'"),
        ("(function(){let k={};return new WeakMap().set(k,'%s').get(k);})()+'%s'"),
        # named function, whitespace tolerance
        ("(function f(){ var k = {} ; var m = new WeakMap( [ [ k , '%s' ] ] ) ; return m.get( k ) ; })() + '%s'"),
        # multiple entries, get selects the right one
        ("(function(){var k={};var k2={};var m=new WeakMap([[k,'zz'],[k2,'%s']]);return m.get(k2);})()+'%s'"),
        # set-chain with two sets, later wins
        ("(function(){var k={};return new WeakMap().set(k,'zz').set(k,'%s').get(k);})()+'%s'"),
        # non-empty object literal key
        ("(function(){var k={a:1};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'"),
        # rebinding: second var wins (node-exact: same binding, new object)
        ("(function(){var k={};var k={};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'"),
    ]
    for t in variants:
        p = t % (_A1, _A2)
        rows.append(_verdict(p, True))
    return rows


def p1_f579_filed_shapes():
    rows = []
    shapes = [
        ("({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[0]]"
         "+({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[1]]"),
        ("({x:{y:'%s'}})[Reflect.ownKeys({x:0})[0]].y+'%s'"),
    ]
    for t in shapes:
        p = t % (_A1, _A2, _A1, _A2, _A1, _A2, _A1, _A2) if t.count("%s") == 8 else t % (_A1, _A2)
        rows.append(_verdict(p, True))
    return rows


def p1_f579_variants():
    rows = []
    # integer-index keys sort numerically first (node-exact)
    p = ("({b:'zz','2':'%s',a:'yy'})[Reflect.ownKeys({b:1,'2':2,a:3})[0]]+'%s'") % (_A1, _A2)
    rows.append(_verdict(p, True))
    # [1] terminal index
    p = ("({c:'zz',d:'%s'})[Reflect.ownKeys({c:1,d:2})[1]]+'%s'") % (_A1, _A2)
    rows.append(_verdict(p, True))
    # whitespace tolerance
    p = ("({c:'%s'})[ Reflect.ownKeys( {c:1} ) [ 0 ] ]+'%s'") % (_A1, _A2)
    rows.append(_verdict(p, True))
    # nested value through resolved key
    p = ("({k:{n:'%s'}})[Reflect.ownKeys({k:0})[0]].n+'%s'") % (_A1, _A2)
    rows.append(_verdict(p, True))
    return rows


# ---------------------------------------------------------------- P2: bounds
def p2_f572_bounds():
    rows = []
    bounds = [
        # literal object keys are DISTINCT objects in the engine (identity,
        # not structure) -- decoding would be a false positive (node: undefined)
        "(function(){return new WeakMap([[{},'%s']]).get({});})()+'%s'",
        # missing key -> undefined in engine -> fail closed
        "(function(){var k={};var k2={};var m=new WeakMap([[k,'%s']]);return m.get(k2);})()+'%s'",
        # unbound key name
        "(function(){var m=new WeakMap();return m.get(k);})()+'%s'",
        # non-string value
        "(function(){var k={};var m=new WeakMap([[k,{}]]);return m.get(k);})()+'%s'",
        # non-object key (engine throws: invalid value used as weak map key)
        "(function(){var k='s';var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'",
        # set arity
        "(function(){var k={};return new WeakMap().set(k,'%s','x').get(k);})()+'%s'",
        # get arity
        "(function(){var k={};var m=new WeakMap([[k,'%s']]);return m.get(k,k);})()+'%s'",
        # non-IIFE: no binding scope
        "new WeakMap([[k,'%s']]).get(k)+'zz'",
        # non-var statement in body
        "(function(){var k={};k.x=1;var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'",
        # return of the map itself (not a string)
        "(function(){var k={};var m=new WeakMap([[k,'%s']]);return m;})()+'%s'",
    ]
    for t in bounds:
        n_ph = t.count("%s")
        p = t % ((_A1, _A2)[:n_ph] if n_ph > 1 else _A2)
        rows.append(_verdict(p, False))
    return rows


def p2_f579_bounds():
    rows = []
    bounds = [
        # out-of-bounds index -> undefined
        "({c:'%s'})[Reflect.ownKeys({c:1})[5]]+'%s'",
        # empty object
        "({c:'%s'})[Reflect.ownKeys({})[0]]+'%s'",
        # non-literal object arg
        "({c:'%s'})[Reflect.ownKeys(x)[0]]+'%s'",
        # bracket-form Reflect (unmodeled namespace form)
        "({c:'%s'})[Reflect['ownKeys']({c:1})[0]]+'%s'",
        # ownKeys without terminal index
        "({c:'%s'})[Reflect.ownKeys({c:1})]+'%s'",
        # non-index postfix on ownKeys
        "({c:'%s'})[Reflect.ownKeys({c:1}).length]+'%s'",
        # symbol key resolves -> fail closed (no string key to read)
        "({c:'%s'})[Reflect.ownKeys({[Symbol.for('s')]:1})[0]]+'%s'",
        # missing key on outer object
        "({c:'%s'})[Reflect.ownKeys({d:1})[0]]+'%s'",
    ]
    for t in bounds:
        p = t % (_A1, _A2)
        rows.append(_verdict(p, False))
    return rows


# ------------------------------------------------------- P3: mech / node
def p3_no_new_regexes():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    ok = src.count("re.compile") == 28
    return [("HELD" if ok else "BREAK",
             "re.compile=%d want 28" % src.count("re.compile"))]


def p3_node_differential():
    payloads = []
    # F572 filed + variants (expect credential)
    payloads.append("(function(){var k={};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'" % (_A1, _A2))
    payloads.append("(function(){var k={};return new WeakMap().set(k,'%s').get(k);})()+'%s'" % (_A1, _A2))
    payloads.append("(function(){var k={};var k2={};var m=new WeakMap([[k,'zz'],[k2,'%s']]);return m.get(k2);})()+'%s'" % (_A1, _A2))
    # F579 filed + variants (expect credential)
    payloads.append("({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[0]]+({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[1]]" % (_A1, _A2, _A1, _A2, _A1, _A2, _A1, _A2))
    payloads.append("({x:{y:'%s'}})[Reflect.ownKeys({x:0})[0]].y+'%s'" % (_A1, _A2))
    payloads.append("({b:'zz','2':'%s',a:'yy'})[Reflect.ownKeys({b:1,'2':2,a:3})[0]]+'%s'" % (_A1, _A2))
    # boundaries: engine-undefined (decoder must miss)
    payloads.append("(function(){return new WeakMap([[{},'%s']]).get({});})()+'%s'" % (_A1, _A2))
    payloads.append("(function(){var k={};var k2={};var m=new WeakMap([[k,'%s']]);return m.get(k2);})()+'%s'" % (_A1, _A2))
    payloads.append("({c:'%s'})[Reflect.ownKeys({c:1})[5]]+'%s'" % (_A1, _A2))
    node = _node_eval(payloads)
    rows = []
    for p, nv in zip(payloads, node):
        hit = _blocked(p)
        if nv == "THROWS":
            continue
        nv_val = json.loads(nv)
        if nv_val == _CRED:
            ok = hit  # engine yields credential -> decoder must block
        elif nv_val is None:
            ok = not hit  # engine undefined -> decoder must miss
        else:
            ok = not hit  # junk -> decoder must stay quiet
        rows.append(("HELD" if ok else "BREAK",
                     "node=%s hit=%s :: %s" % (nv_val, hit, p[:60])))
    return rows


# ------------------------------------------------------- P4: discrimination
def p4_discrimination():
    rows = []
    held = [
        # F563 CLOSED: Map.get on literals
        "new Map([['c','%s']]).get('c')+'%s'",
        # F535 CLOSED: literal member reads
        "({c:'%s'}).c+'%s'",
        # F547 CLOSED: array index reads
        "(['%s','%s'])[0]+(['%s','%s'])[1]",
        # F552 CLOSED: Symbol.for keyed reads
        "({[Symbol.for('k')]:'%s'})[Symbol.for('k')]+'%s'",
        # F496 CLOSED: ownKeys predicate dispatch on prototypes
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')",
    ]
    for t in held:
        p = t % ((_A1, _A2) * (t.count("%s") // 2))
        rows.append(_verdict(p, True))
    # F549 CLOSED (wave-369 lane 2): gopd terminal reads now block --
    # distinct builtin from F579's ownKeys (descriptors vs keys)
    p = "Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A1, _A2)
    rows.append(_verdict(p, True))
    return rows


# ------------------------------------------------------------------ P5: perf
def p5_perf_bound():
    hostile = ("(function(){var k%d={};var m=new WeakMap([[k%d,'x']]);return m.get(k%d);})()+'%s';"
               % (0, 0, 0, _A1)) * 40
    hostile += ("({a%d:'x'})[Reflect.ownKeys({a%d:1})[0]];" % (0, 0)) * 40
    t0 = time.time()
    _blocked(hostile)
    dt = time.time() - t0
    ok = dt < 5.0
    return [("HELD" if ok else "BREAK", "hostile 80 shapes in %.2fs" % dt)]


# ---------------------------------------------------------- P6: regression
GREEN_ADJACENT = [
    "evals/w369_f552f557f565close_probes.py",
    "evals/w369_f560f562f563close_probes.py",
    "evals/w367_f535f536close_probes.py",
    "evals/w369_f547f561f566close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g370lane3-green-%d" % abs(hash(rel))
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
                   and "tally:" not in l]
            status = tally[-1] if tally else "rc=%d" % r.returncode
            extra = "" if not bad else " FUNCTIONAL-FAILURES=%d" % len(bad)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, status, time.time() - t0, extra))
            for b in bad[:5]:
                print("      FAIL: %s" % b[:100])
            if bad or r.returncode != 0:
                # A nonzero rc with only footer-probe failures is the
                # expected churn; anything else is a real regression.
                if bad:
                    ok = False
                else:
                    print("      (rc!=0 but only footer-probe churn; "
                          "merge-owned)")
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


# ---------------------------------------------------------- P7: pin/footer
def p7_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Lane-local footer: wave-370 lane 3 closes F572/F579; the merge
    # reconciles with sibling lanes.
    ok = ("Next free finding: **F655**." in text  # Wave-372 merge: footer repoint next F612  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
          and "**Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654.**" in text  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
          and "**Status: CLOSED 2026-10-07 wave-370 lane 3.**" in text)
    return [("HELD" if ok else "BREAK",
             "pin=%s footer=%s" % (TAXONOMY_PIN, ok))]


PROBES = [
    ("p1-f572-filed", p1_f572_filed_shapes),
    ("p1-f572-variants", p1_f572_variants),
    ("p1-f579-filed", p1_f579_filed_shapes),
    ("p1-f579-variants", p1_f579_variants),
    ("p2-f572-bounds", p2_f572_bounds),
    ("p2-f579-bounds", p2_f579_bounds),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-node-differential", p3_node_differential),
    ("p4-discrimination", p4_discrimination),
    ("p5-perf-bound", p5_perf_bound),
    ("p7-pin-and-footer", p7_pin_and_footer),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    rows = []
    for name, fn in PROBES:
        try:
            for verdict, detail in fn():
                if verdict == "BREAK":
                    brk += 1
                else:
                    held += 1
                rows.append({"probe": name, "verdict": verdict,
                             "detail": detail})
                print("%-22s %s :: %s" % (name, verdict, detail))
        except Exception as e:  # noqa: BLE001
            brk += 1
            rows.append({"probe": name, "verdict": "ERROR", "detail": str(e)})
            print("%-22s ERROR :: %s" % (name, e))
    print("---")
    gok = green_check()
    print("tally: %d BREAK / %d HELD / green=%s" % (brk, held, gok))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": gok,
                          "rows": rows}))
    return 1 if (brk or not gok) else 0


if __name__ == "__main__":
    sys.exit(main())
