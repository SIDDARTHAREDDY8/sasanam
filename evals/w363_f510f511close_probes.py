#!/usr/bin/env python3
"""Wave-363 lane 4: F510/F511 closure probes.

F510 (LOW, OPEN on base): Object.values indirection on objects holding
fragments bypasses the bounded static JS-expression decoder -- the
decoder modeled object-literal array-like receivers (F487) and
freeze/seal-wrapped dispatch forms (F502/F503), but the Object.values
call site, which enumerates an object's values into an array, was
unmodeled for plain, frozen, sealed, and nested objects alike.

F511 (LOW, OPEN on base): Array.prototype.splice.call/.apply dispatch
is unmodeled -- the decoder modeled direct .splice() on array literals
(F466, literal (0,2) only) and slice.call on plain arrays and
array-like receivers (F487), but the splice method had no
.call/.apply dispatch entry at all.

Closure (gov/dlp.py):
- F510: new _js_parse_object_values / _js_parse_object_literal_values /
  _js_parse_entries_reduce_values / _js_parse_values_source /
  _js_parse_values_wrapper. Object.values desugars to the engine-exact
  ordered value list (integer-index keys ascending numerically first,
  then string keys in insertion order; duplicates later-wins at the
  first-insertion position; node v24.20.0 verified). Sources: plain
  object literals, Object.freeze/seal/preventExtensions wrappers
  (identity, F502/F503 family), and the
  Object.entries(OBJLIT).reduce((A,[B,C])=>(A[B]=C,A),{}) rebuild idiom
  (structurally matched, never evaluated). _JS_EXPR_START's Object
  alternative gains `values` (literal-alternation only; re.compile
  count unchanged at 28). Object['values'] modeled (F480 convention).
- F511: "splice" joins _F478_ARRAY_METHODS; the .call path routes
  through the existing _js_apply_method_at splice branch and the
  .apply path is mirrored in _js_apply_method_values -- both keep the
  F466 literal-(0,2)-only rule. F506 shapes untouched (lane 1's scope).

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed shape
misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import json
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-363 lane 4; pin stays 2135

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

F510_FILED = [
    ("values-plain",
     "Object.values({0:'%s',1:'%s'}).join('')" % (_A, _B)),
    ("values-freeze",
     "Object.values(Object.freeze({0:'%s',1:'%s'})).join('')" % (_A, _B)),
    ("values-seal",
     "Object.values(Object.seal({0:'%s',1:'%s'})).join('')" % (_A, _B)),
    ("values-nested",
     "Object.values(Object.freeze(Object.entries({0:'%s',1:'%s'})"
     ".reduce((o,[k,v])=>(o[k]=v,o),{}))).join('')" % (_A, _B)),
]

F511_FILED = [
    ("splice-call-plainarr",
     "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A, _B)),
    ("splice-call-arraylike",
     "Array.prototype.splice.call({length:2,0:'%s',1:'%s'},0,2).join('')"
     % (_A, _B)),
    ("splice-apply",
     "Array.prototype.splice.apply(['%s','%s'],[0,2]).join('')" % (_A, _B)),
]


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def p1_filed_shapes_held():
    """All filed F510/F511 shapes (plus the modeled .apply form) block."""
    bad = []
    for name, shape in F510_FILED + F511_FILED:
        if not _blocked(shape):
            bad.append(name)
    if bad:
        return ("BREAK", "filed shapes missed: %s" % bad)
    return ("HELD", "%d filed shapes block" % (len(F510_FILED) + len(F511_FILED)))


def p2_node_differential():
    """Decoded values are byte-identical to node v24.20.0 (independent
    source of truth), including the enumeration-ordering edge cases."""
    try:
        node = subprocess.run(["node", "--version"], capture_output=True,
                              text=True, timeout=30)
        if "v24.20.0" not in node.stdout:
            return ("ERROR", "node is not v24.20.0: %s" % node.stdout.strip())
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node unavailable: %s" % e)
    shapes = [
        "Object.values({0:'a',1:'b'}).join('')",
        "Object.values({1:'a',0:'b'}).join('')",
        "Object.values({b:'x',0:'a'}).join('')",
        "Object.values({'01':'s','1':'i'}).join('')",
        "Object.values({0:'a',0:'b'}).join('')",
        "Object.values({a:'x',2:'c',10:'d',1:'b'}).join('')",
        "Object.values({b:'y',4294967294:'x'}).join('')",
        "Object.values(Object.freeze({0:'a',1:'b'})).join('')",
        "Object.values(Object.seal({0:'a',1:'b'})).join('')",
        "Object.values(Object.preventExtensions({0:'a',1:'b'})).join('')",
        "Object.values(Object['freeze']({0:'a',1:'b'})).join('')",
        "Object['values']({0:'a',1:'b'}).join('')",
        "Object.values(Object.freeze(Object.entries({0:'a',1:'b'})"
        ".reduce((o,[k,v])=>(o[k]=v,o),{}))).join('')",
        "Object.values(Object.entries({1:'a',b:'x',0:'c'})"
        ".reduce((acc,[key,val])=>(acc[key]=val,acc),{})).join('')",
        "Array.prototype.splice.call(['a','b'],0,2).join('')",
        "Array.prototype.splice.call(['a','b','c'],0,2).join('')",
        "Array.prototype.splice.call({length:2,0:'a',1:'b'},0,2).join('')",
        "Array.prototype.splice.apply(['a','b'],[0,2]).join('')",
        "Array.prototype['splice'].call(['a','b'],0,2).join('')",
        "['a','b'].splice(0,2).join('')",
    ]
    src = ("const S=%s; for (const s of S) { let r; try { r = "
           "JSON.stringify(eval(s)); } catch (e) { r = 'THROW'; } "
           "console.log(r); }" % json.dumps(shapes))
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    wants = r.stdout.splitlines()
    bad = []
    for s, want in zip(shapes, wants):
        got = _decoded(s)
        if json.dumps(got) != want:
            bad.append((s, want, json.dumps(got)))
    if bad:
        return ("BREAK", "node mismatches: %s" % bad[:3])
    return ("HELD", "%d shapes byte-identical to node v24.20.0" % len(shapes))


def p3_fail_closed_boundaries():
    """Every documented fail-closed boundary misses (no mis-decode)."""
    bounds = [
        "Object.values({0:1,1:'b'}).join('')",          # non-string value
        "Object.values({['k']:'a'}).join('')",          # computed key
        "Object.values({__proto__:{},0:'a'}).join('')",  # __proto__
        "Object.values({get 0(){return 'a'}}).join('')",  # getter
        "Object.values({...{0:'a'}}).join('')",        # spread
        "Object.values('ab').join('')",                # non-object arg
        "Object.values({0:'a'},1).join('')",           # extra arg
        "Object.values({01:'a'}).join('')",            # octal-looking key
        "Object.values(Object.entries({0:'a'}).reduce((o,v)=>(o[v]=1,o),{}))"
        ".join('')",                                    # wrong callback
        "Object.values(Object.entries({0:'a'}).reduce((o,[k,v])=>{o[k]=v;return o;},{})))"
        ".join('')",                                    # block callback
        "Object.values(Object.entries({0:'a'}).reduce((o,[k,v])=>(o[k]=v,o),{x:1})))"
        ".join('')",                                    # non-empty init
        "Array.prototype.splice.call(['a','b'],1,1).join('')",  # bad args
        "Array.prototype.splice.apply(['a','b'],'x').join('')",  # bad argsArray
        "Array.prototype.splice.call('ab',0,2).join('')",  # non-array recv
        "Array.prototype.splice.call(['a','b'],0,2,9).join('')",  # extra arg
    ]
    bad = [s for s in bounds if _blocked(s)]
    if bad:
        return ("BREAK", "boundaries decoded: %s" % bad)
    return ("HELD", "%d fail-closed boundaries miss" % len(bounds))


def p4_compositions():
    """Cross-finding compositions stay consistent; F506 untouched."""
    # F510 x F503: integrity wrappers compose with values
    if not _blocked("Object.values(Object.seal(Object.freeze({0:'%s',1:'%s'}))).join('')" % (_A, _B)):
        return ("BREAK", "F510xF503 nested wrappers missed")
    # F511 x F482: bracket prototype form
    if not _blocked("Array.prototype['spli'+'ce'].call(['%s','%s'],0,2).join('')" % (_A, _B)):
        return ("BREAK", "F511xF482 folded-key splice missed")
    # F511 x F487: array-like receiver already covered in p1; direct control
    if not _blocked("['%s','%s'].splice(0,2).join('')" % (_A, _B)):
        return ("BREAK", "F466 direct splice regressed")
    if not _blocked("Array.prototype.slice.call(['%s','%s'],0).join('')" % (_A, _B)):
        return ("BREAK", "F487 slice.call regressed")
    # F506 independence: Reflect.apply indirection still OPEN (lane 1's scope)
    if _blocked("Reflect.apply.call(Reflect,[].concat,[],['%s','%s']).join('')" % (_A, _B)):
        return ("BREAK", "F506 accidentally closed by this lane")
    return ("HELD", "F510xF503, F511xF482/F487, F466 controls consistent; F506 untouched")


def p5_pin_and_footer():
    """Pin stays 2135; F510/F511 closed in FINDINGS; anchor covers values;
    re.compile count unchanged."""
    if TAXONOMY_PIN != 2135:
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    for f in ("F510", "F511"):
        if f not in text:
            return ("BREAK", "%s entry missing" % f)
    if "F506-F511 CLOSED" not in text:
        return ("BREAK", "merged footer not repointed")  # wave-363 merge: lanes 1-4 closed F506-F511
    if dlp._JS_EXPR_START.search("Object.values") is None:
        return ("BREAK", "anchor missing values")
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    return ("HELD", "pin 2135; F510/F511 closed; anchor covers values; 28 re.compile")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w362_f510_redfirst.py",
               "w362_f511_redfirst.py",
               "w362_f503close_probes.py",
               "w362_f504close_probes.py",
               "w362_f505close_probes.py",
               "w362_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g363-green-%s-%d" % (script.replace(".py", ""),
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
        m = re.search(r"(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_filed_shapes_held, p2_node_differential,
              p3_fail_closed_boundaries, p4_compositions, p5_pin_and_footer]
    breaks, held = 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "HELD":
            held += 1
        else:
            breaks += 1
    print("green check: %s" % _green_check())
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
