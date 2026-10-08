#!/usr/bin/env python3
"""Close battery for F600 (Map keys iteration), F601 (Map.prototype.forEach),
F602 (Set iteration).

F600 (LOW, filed 2026-10-07 wave-371 attack round 39): F589 modeled Map
ENTRIES iteration, but the KEYS iterator is a different read path:
  Array.from(new Map([['f1',1],['f2',2]]).keys()).join('')
  [...new Map([['f1',1],['f2',2]]).keys()].join('')
  (function(){var s='';new Map([['f1',1],['f2',2]]).keys().forEach(function(k){s+=k;});return s;})()
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Root cause: the `_JSMap` postfix branch modeled
only `.get`/`.entries()`.

F601 (LOW, filed 2026-10-07 wave-371 attack round 39): Map.prototype.forEach
with value-accumulating callbacks is a different grammatical shape:
  (function(){var s='';new Map([['a','f1'],['b','f2']]).forEach(function(v){s+=v;});return s;})()
and the arrow-callback twin both node-evaluate to the exact credential
(v24.20.0) while the decoder produced zero variants.

F602 (LOW, filed 2026-10-07 wave-371 attack round 39): Set iteration --
for-of over a Set and Set.prototype.forEach had no modeled read path:
  (function(){var s='';for(var x of new Set(['f1','f2'])){s+=x;}return s;})()
  (function(){var s='';var st=new Set(['f1','f2']);st.forEach(function(x){s+=x;});return s;})()
both node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. (The [...new Set(...)] spread IS modeled -- control.)

Closed (wave-372 lane 4):
- F600: `.keys()` on a `_JSMap` yields the opaque `_JSMapKeys`
  (insertion-ordered keys, _JSNumStr provenance per SameValueZero);
  consumed by the F471 spread-copy factory and by
  `Array.from(new Map(...).keys())`. Maps with non-string-literal
  values parse keys-only via `_js_parse_f563_map(..., _keys_only=True)`
  (values unobservable through the keys iterator, node-verified);
  `.keys().forEach` accumulation is modeled in the exact-statement
  IIFE grammar.
- F601: `(function(){var|let S='';new Map([PAIRS]).forEach(CB);
  return S;})()` -- CB is `function(P){S+=E;}` / `(P)=>S+=E` /
  `(P)=>{S+=E;}` / bare-param arrow, 1-2 positional params
  (value, key); E is additive over the params, substituted per
  iteration and re-parsed by the additive grammar.
- F602: `(function(){var|let S='';for(var|let|const X of
  new Set([LITS])){S+=X;}return S;})()` (SameValueZero dedupe,
  first-occurrence insertion order) and the var/let/const-bound
  `ST.forEach(CB)` twin (engine passes (value, value, set)).

Boundaries (all fail closed, never mis-decoded): unspread `.keys()`
index reads/method calls (engine TypeError); `.keys('x')`;
`Array.from(new Map(...).values())` (engine iterates pairs, not
values); `.get` on non-string values; forEach with 3+ params, `s=v`
bodies, callbacks referencing outer idents, params shadowing the
accumulator; non-string Set elements; forEach on a different ident;
`const`/non-empty accumulators; call args on the IIFE.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov import decision_codes  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def p1_filed_shapes_held():
    """F600/F601/F602 filed shapes now block coded."""
    shapes = [
        # F600
        "Array.from(new Map([['%s',1],['%s',2]]).keys()).join('')" % (_A, _B),
        "[...new Map([['%s',1],['%s',2]]).keys()].join('')" % (_A, _B),
        "(function(){var s='';new Map([['%s',1],['%s',2]]).keys()"
        ".forEach(function(k){s+=k;});return s;})()" % (_A, _B),
        # F601
        "(function(){var s='';new Map([['a','%s'],['b','%s']])"
        ".forEach(function(v){s+=v;});return s;})()" % (_A, _B),
        "(function(){var s='';new Map([['a','%s'],['b','%s']])"
        ".forEach((v)=>s+=v);return s;})()" % (_A, _B),
        # F602
        "(function(){var s='';for(var x of new Set(['%s','%s'])){s+=x;}"
        "return s;})()" % (_A, _B),
        "(function(){var s='';var st=new Set(['%s','%s']);"
        "st.forEach(function(x){s+=x;});return s;})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Decoder variants of the filed shapes block coded."""
    shapes = [
        # F600 variants
        "Array.from(new Map([['%s',1]])['keys']()).join('')" % _CRED,
        "[...new Map([['%s','x']]).keys()].join('')" % _CRED,
        "Array.from(new Map([[1,'x'],['%s',2]]).keys()).join('')" % _CRED,
        "[...new Map([['%s',1],['%s',2],['%s',3]]).keys()].join('')"
        % (_A, _A, _B),
        "(function(){var s='';new Map([['%s',1],['%s',2]]).keys()"
        ".forEach(k=>s+=k);return s;})()" % (_A, _B),
        "(function(){var s='';new Map([['%s',1],['%s',2]]).keys()"
        ".forEach(function(k,i){s+=k;});return s;})()" % (_A, _B),
        # F601 variants
        "(function(){var s='';new Map([['a','%s'],['b','%s']])"
        ".forEach((v)=>{s+=v;});return s;})()" % (_A, _B),
        "(function(){var s='';new Map([['a','%s'],['b','%s']])"
        ".forEach(function(v,k){s+=v+k;});return s;})()" % (_A, _B),
        # F602 variants
        "(function(){var s='';for(var x of new Set(['%s','%s']))s+=x;"
        "return s;})()" % (_A, _B),
        "(function(){var s='';for(var x of new Set(['%s','%s','%s'])){s+=x;}"
        "return s;})()" % (_A, _A, _B),
        "(function(){var s='';var st=new Set(['%s','%s']);"
        "st.forEach(function(x,i){s+=x;});return s;})()" % (_A, _B),
        "(function(){let s='';const st=new Set(['%s','%s']);"
        "st.forEach(x=>s+=x);return s;})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p3_fail_closed_boundaries():
    """Boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # F600 boundaries
        "new Map([['a','%s']]).keys().join('')" % _A,
        "Array.from(new Map([['a','%s']]).values())" % _A,
        "Array.from(new Map([['a','%s']]).keys('x'))" % _A,
        "new Map([['a',1]]).get('a')",
        "new Map([['%s','x'],['%s','y']]).keys()[0]+'!'" % (_A, _B),
        # F601 boundaries
        "(function(){var s='';new Map([['a','%s']])"
        ".forEach(function(a,b,c){s+=a;});return s;})()" % _A,
        "(function(){var s='';new Map([['a','%s']])"
        ".forEach(function(v){s=v;});return s;})()" % _A,
        "(function(){var s='';var t='!';new Map([['a','%s']])"
        ".forEach(function(v){s+=v+t;});return s;})()" % _A,
        "(function(){var s='';new Map([['a','%s']])"
        ".forEach(function(v){s+=v;});return s;})('x')" % _A,
        "(function(){const s='';new Map([['a','%s']])"
        ".forEach(function(v){s+=v;});return s;})()" % _A,
        # F602 boundaries
        "(function(){var s='';for(var x of new Set([1,2])){s+=x;}"
        "return s;})()",
        "(function(){var s='';var st=new Set(['%s']);var q=new Set(['x']);"
        "q.forEach(function(x){s+=x;});return s;})()" % _A,
        "(function(){var s='x';for(var x of new Set(['%s'])){s+=x;}"
        "return s;})()" % _A,
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p4_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    cases = [
        # (js, node-yields-credential?)
        ("Array.from(new Map([['%s',1],['%s',2]]).keys()).join('')"
         % (_A, _B), True),
        ("[...new Map([['%s',1],['%s',2]]).keys()].join('')" % (_A, _B),
         True),
        ("(function(){var s='';new Map([['%s',1],['%s',2]]).keys()"
         ".forEach(function(k){s+=k;});return s;})()" % (_A, _B), True),
        ("(function(){var s='';new Map([['a','%s'],['b','%s']])"
         ".forEach(function(v){s+=v;});return s;})()" % (_A, _B), True),
        ("(function(){var s='';new Map([['a','%s'],['b','%s']])"
         ".forEach(v=>s+=v);return s;})()" % (_A, _B), True),
        ("(function(){var s='';for(var x of new Set(['%s','%s'])){s+=x;}"
         "return s;})()" % (_A, _B), True),
        ("(function(){var s='';var st=new Set(['%s','%s']);"
         "st.forEach(function(x){s+=x;});return s;})()" % (_A, _B), True),
        # open-neighbor controls: node does NOT yield the credential
        # (engine TypeError / non-credential values)
        ("new Map([['a','%s']]).keys().join('')" % _A, "err"),
        ("new Map([['a',1]]).get('a')", False),
        ("(function(){var s='';for(var x of new Set([1,2])){s+=x;}"
         "return s;})()", False),
    ]
    js = "const R=[];\n" + "\n".join(
        "try{R.push(eval(%s)===%s)}catch(e){R.push('err')}"
        % (repr(c), repr(_CRED)) for c, _ in cases) + "\nconsole.log(JSON.stringify(R));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for (c, want), truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        if want == "err":
            agree = (truth == "err") and not dec_hit
        else:
            agree = (truth is True) == want and dec_hit == want
        if not agree:
            bad.append(c[:60])
    # value-level: SameValueZero key order and numeric-key join
    val_cases = [
        ("[...new Map([[2,'x'],[10,'y'],[1,'z']]).keys()].join('-')",
         "2-10-1"),
        ("Array.from(new Map([[1,'a'],['1','b']]).keys()).join('')", "11"),
        ("(function(){var s='';for(var x of new Set(['b','a','b'])){s+=x;}"
         "return s;})()", "ba"),
        # additive E composition over forEach params (the '!' splits
        # the credential, so find_credential correctly stays quiet --
        # assert the value instead)
        ("(function(){var s='';new Map([['a','x'],['b','y']])"
         ".forEach(function(v){s+=v+'!';});return s;})()", "x!y!"),
    ]
    for src, want in val_cases:
        state = {"ops": 0, "parts": 0}
        try:
            got, _ = dlp._js_parse_additive(src, 0, 0, state)
        except Exception:  # noqa: BLE001
            got = None
        if got != want:
            bad.append("value:%s" % src[:40])
    total = len(cases) + len(val_cases)
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement" % (total - len(bad), total))


def p5_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F563 (.get) stays HELD
        "new Map([['c','%s']]).get('c')+'%s'" % (_A, _B),
        # F589 (entries) stays HELD
        "[...new Map([['c','%s']]).entries()][0][1]+'%s'" % (_A, _B),
        # F583 (Object.keys) stays HELD
        "Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B),
        # F494 (Set spread) stays HELD
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),
        # F597 (flatMap scalar) CLOSED wave-372 lane 1 -- moved from open
        "['%s','%s'].flatMap((x)=>x).join('')" % (_A, _B),
        # F598 (stringify derived) CLOSED wave-372 lane 2 -- moved from open
        "JSON.parse(JSON.stringify(Array.from(new Set(['%s','%s'])))).join('')"
        % (_A, _B),
        # F599 (USP append) CLOSED wave-372 lane 3 -- moved from open
        "(function(){var p=new URLSearchParams('q=%s');p.append('q','%s');"
        "return p.getAll('q').join('');})()" % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    # open neighbors: decoder must still MISS (BREAK = still open)
    # (exact filed shapes from FINDINGS.md)
    open_cases = [
        # F606: USP append-mutated sort guard (OPEN, wave-372 lane 3)
        "(function(){var p=new URLSearchParams('q=%s');"
        "p.append('q','%s');p.sort();"
        "return p.getAll('q').join('');})()" % (_A, _B),
        # F607: filter with non-trivial predicates (OPEN, wave-372 lane 7)
        "['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A, _B),
    ]
    bad_open = [s for s in open_cases if _blocked(s)]
    bad = bad_held + ["absorbed:" + s[:40] for s in bad_open]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions ok" % (len(held) + len(open_cases) - len(bad),
                                       len(held) + len(open_cases)))



def p6_honest_text_quiet():
    """Honest text stays quiet."""
    texts = [
        "the meeting notes mention map keys and set iteration",
        "Array.from(iterable) converts array-like objects",
        "use .forEach to iterate over collections safely",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad), len(texts)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F600/F601/F602 closed, next F606."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-07 wave-372 lane 4" in text
                 and "Open findings: F606, F607, F608, F609, F610, F611." in text  # Wave-372 merge: footer repoint open F606-F611 / next F612
                 and "Next free finding: **F612**" in text)  # Wave-372 merge: footer repoint next F612
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail) if (pin_ok and footer_ok)
            else ("BREAK", detail))


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w371_f600_redfirst.py",
               "w371_f601_redfirst.py",
               "w371_f602_redfirst.py",
               "w371_attack_probes.py",
               "w371_f583f589close_probes.py",
               "w369_f560f562f563close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g372-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        m = re.search(r"tally:\s*(\d+)\s*BREAK", out)
        if m is None:
            m = re.search(r"(\d+) BREAK / \d+ HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_filed_shapes_held, p2_variants_held,
              p3_fail_closed_boundaries, p4_node_differential,
              p5_compositions, p6_honest_text_quiet, p7_pin_and_footer]
    breaks, held, errors = 0, 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (fn.__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    gc = _green_check()
    print("green-check: %s" % gc)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
