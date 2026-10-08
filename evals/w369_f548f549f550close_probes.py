#!/usr/bin/env python3
"""Wave-369 lane 2: F548/F549/F550 closure probes.

F548 (LOW, filed 2026-10-07 wave-368 lane 5, OPEN on base):
`Object.create` prototype-chain member reads bypass the bounded
static JS-expression decoder -- Object.create builds a NEW object
with the argument as prototype, and the decoder resolved no member
reads through the prototype chain:
`Object.create({c:'f1'}).c+'f2'` (dot), the bracket form, and
nested `Object.create(Object.create({c:'f1'})).c` all node-evaluate
(v24.20.0) to the exact credential while the decoder produced zero
variants. Distinct from F535 (literal sources -- these go through
a builtin) and F539 (identity-preserving builtins -- create
returns a NEW object, not its argument).

F549 (LOW, filed 2026-10-07 wave-368 lane 5, OPEN on base):
`Object.getOwnPropertyDescriptor` reads are terminal -- the decoder
modeled the descriptor read only as a terminal direct yield, so
`Object.getOwnPropertyDescriptor({c:'f1'},'c').value+'f2'` and
`Object.getOwnPropertyDescriptor({get c(){return 'f1';}},'c').get()`
`+'f2'` node-evaluate (v24.20.0) to the exact credential with zero
decoder variants. Distinct from F540 (Reflect.get -- a different
builtin) and F535 (member-access syntax). (F491 already owns the
Array/String-prototype gopd targets; this lane owns object-literal
targets.)

F550 (LOW, filed 2026-10-07 wave-368 lane 5, OPEN on base):
`Object.defineProperty` property-adding laundering -- defineProperty
RETURNS its target (identity) but ADDS the credential-bearing
property via descriptor semantics, which no model interpreted:
`Object.defineProperty({},'c',{get:function(){return 'f1';}}).c+'f2'`
and `Object.defineProperty({},'c',{value:'f1'}).c+'f2'`
node-evaluate (v24.20.0) to the exact credential with zero decoder
variants. Distinct from F535 (literal getter syntax -- this is a
builtin call) and F539 (identity-preserving builtins -- those
preserve PRE-EXISTING properties; defineProperty introduces new
ones).

Closure (gov/dlp.py):
- `_js_parse_f548_object_create`: `Object.create(PROTO[, PROPS])`
  desugars to a _JSObj with the proto chain attached (new `proto`
  slot; member reads delegate via `_jsobj_lookup`, own properties
  shadow, engine-exact -- node v24.20.0 verified). PROTO: an
  object literal, a nested `Object.create(...)`, or `null`;
  PROPS: `{}` or `{k:{value:V}}` (value descriptors only).
  Non-literal protos, `get`/`set` prop descriptors, and
  `Object['create']` fail closed (documented).
- `_js_parse_f549_gopd_object`: `Object.getOwnPropertyDescriptor`
  on object-literal targets, parsed accessor-aware (new
  `_JSAccessor` marker + `accessor_aware` flag on
  `_js_parse_f535_object`, preserving the data-vs-accessor
  distinction). `.value` on data properties and `.get()` (zero-arg
  call) on accessor properties resolve node-exactly; `.value` on
  an accessor / `.get()` on data / `.set` / bracket terminals
  fail closed (node: the field is undefined -- documented).
- `_js_parse_f550_define_property`: `Object.defineProperty(OBJ,
  KEY, DESC)` returns a fresh props dict (target props + KEY ->
  descriptor value, later wins, engine-exact). `{value:V}` and
  `{get:function(){return EXPR}}` descriptors modeled
  node-exactly (the getter body uses the F535 getter grammar --
  `this`-dependent bodies fail closed); `set` descriptors,
  non-literal keys, and `Object['defineProperty']` fail closed
  (documented).
- `Object.create` / `Object.defineProperty` join the existing
  Object member anchor class in `_JS_EXPR_START` (no new
  re.compile -- count stays 28).

Deviations from the lane brief (honest, node-verified): the brief
scoped F549 to `.value` and F550 to `value` descriptors, but the
filed red-first shapes include `.get()` and
`{get:function(){...}}` -- both are modeled node-exactly here
(getter bodies use the F535 `this`-free grammar), so both filed
shapes close honestly with no narrowing.

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed
shape misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""

import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

import gov.dlp as dlp  # noqa: E402
from gov.dlp import _try_js_expr_decode, find_credential  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-369 lane 2: pin 2140 (Watcher v1 merge: 2135 -> 2140)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


F548_FILED = [
    ("f548-dot",
     "Object.create({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f548-bracket",
     "Object.create({c:'%s'})['c']+'%s'" % (_A1, _A2)),
    ("f548-nested",
     "Object.create(Object.create({c:'%s'})).c+'%s'" % (_A1, _A2)),
]

F549_FILED = [
    ("f549-value",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'"
     % (_A1, _A2)),
    ("f549-get",
     "Object.getOwnPropertyDescriptor({get c(){return '%s';}},'c')"
     ".get()+'%s'" % (_A1, _A2)),
]

F550_FILED = [
    ("f550-get",
     "Object.defineProperty({},'c',{get:function(){return '%s';}})"
     ".c+'%s'" % (_A1, _A2)),
    ("f550-value",
     "Object.defineProperty({},'c',{value:'%s'}).c+'%s'"
     % (_A1, _A2)),
]

F548_VARIANTS = [
    ("f548-2arg-shadow",
     "Object.create({c:'zz'},{c:{value:'%s'}}).c+'%s'" % (_A1, _A2)),
    ("f548-2arg-newkey",
     "Object.create({c:'zz'},{d:{value:'%s'}}).d+'%s'" % (_A1, _A2)),
    ("f548-2arg-empty",
     "Object.create({c:'%s'},{}).c+'%s'" % (_A1, _A2)),
    ("f548-getter-proto",
     "Object.create({get c(){return '%s';}}).c+'%s'" % (_A1, _A2)),
    ("f548-nested-bracket",
     "Object.create(Object.create({c:'%s'}))['c']+'%s'" % (_A1, _A2)),
    ("f548-nested-2deep",
     "Object.create(Object.create(Object.create({c:'%s'}))).c+'%s'"
     % (_A1, _A2)),
    ("f548-ws",
     "Object . create ( { c : '%s' } ) . c + '%s'" % (_A1, _A2)),
    ("f548-int-key",
     "Object.create({0:'%s'})['0']+'%s'" % (_A1, _A2)),
]

F549_VARIANTS = [
    ("f549-value-nested",
     "Object.getOwnPropertyDescriptor({c:{d:'%s'}},'c').value.d+'%s'"
     % (_A1, _A2)),
    ("f549-get-additive",
     "Object.getOwnPropertyDescriptor({get c(){return 'xoxb-'+'0123';}},"
     "'c').get()+'%s'" % _A2),
    ("f549-ws",
     "Object . getOwnPropertyDescriptor ( { c : '%s' } , 'c' ) . "
     "value + '%s'" % (_A1, _A2)),
    ("f549-int-key",
     "Object.getOwnPropertyDescriptor({0:'%s'},'0').value+'%s'"
     % (_A1, _A2)),
]

F550_VARIANTS = [
    ("f550-get-named",
     "Object.defineProperty({},'c',{get:function g(){return '%s';}})"
     ".c+'%s'" % (_A1, _A2)),
    ("f550-get-additive",
     "Object.defineProperty({},'c',{get:function(){return 'xoxb-'+"
     "'0123';}}).c+'%s'" % _A2),
    ("f550-target-props",
     "Object.defineProperty({a:'zz'},'c',{value:'%s'}).c+'%s'"
     % (_A1, _A2)),
    ("f550-overwrite",
     "Object.defineProperty({c:'zz'},'c',{value:'%s'}).c+'%s'"
     % (_A1, _A2)),
    ("f550-flags-ignored",
     "Object.defineProperty({},'c',{value:'%s',writable:true,"
     "enumerable:false}).c+'%s'" % (_A1, _A2)),
    ("f550-bracket-read",
     "Object.defineProperty({},'c',{value:'%s'})['c']+'%s'"
     % (_A1, _A2)),
    ("f550-ws",
     "Object . defineProperty ( {} , 'c' , { value : '%s' } ) . c + "
     "'%s'" % (_A1, _A2)),
    ("f550-nested-value",
     "Object.defineProperty({},'c',{value:{d:'%s'}}).c.d+'%s'"
     % (_A1, _A2)),
]

BOUNDARIES = [
    # (name, payload) -- each must MISS (fail closed, no hit)
    ("f548-null-proto",
     "Object.create(null).c+'%s'" % _A2),
    ("f548-ident-proto",
     "Object.create(x).c+'%s'" % _A2),
    ("f548-call-proto",
     "Object.create(f()).c+'%s'" % _A2),
    ("f548-missing-key",
     "Object.create({c:'%s'}).x+'%s'" % (_A1, _A2)),
    ("f548-bracket-form",
     "Object['create']({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f548-props-getter",
     "Object.create({},{c:{get:function(){return '%s';}}}).c+'%s'"
     % (_A1, _A2)),
    ("f548-props-set",
     "Object.create({},{c:{set:function(v){}}}).c+'%s'" % _A2),
    ("f548-props-nonliteral",
     "Object.create({},'c')+'%s'" % _A2),
    ("f548-no-paren",
     "Object.create+'%s'" % _A2),
    ("f548-junk-quiet",
     "Object.create({c:'zz'}).c+'yy'"),
    ("f549-value-on-accessor",
     "Object.getOwnPropertyDescriptor({get c(){return '%s';}},'c')"
     ".value+'%s'" % (_A1, _A2)),
    ("f549-get-on-data",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c').get()+'%s'"
     % (_A1, _A2)),
    ("f549-set-field",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c').set+'%s'"
     % (_A1, _A2)),
    ("f549-bracket-terminal",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c')['value']+'%s'"
     % (_A1, _A2)),
    ("f549-missing-key",
     "Object.getOwnPropertyDescriptor({c:'%s'},'x').value+'%s'"
     % (_A1, _A2)),
    ("f549-nonliteral-key",
     "Object.getOwnPropertyDescriptor({c:'" + _A1 + "'},k).value+'"
     + _A2 + "'"),
    ("f549-get-with-args",
     "Object.getOwnPropertyDescriptor({get c(){return '%s';}},'c')"
     ".get(1)+'%s'" % (_A1, _A2)),
    ("f549-extra-arg",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c','x').value+'%s'"
     % (_A1, _A2)),
    ("f549-no-terminal",
     "Object.getOwnPropertyDescriptor({c:'%s'},'c')+'%s'"
     % (_A1, _A2)),
    ("f549-junk-quiet",
     "Object.getOwnPropertyDescriptor({c:'zz'},'c').value+'yy'"),
    ("f550-set-descriptor",
     "Object.defineProperty({},'c',{set:function(v){}}).c+'%s'"
     % _A2),
    ("f550-value-plus-get",
     "Object.defineProperty({},'c',{value:'%s',get:function(){return "
     "'x';}}).c+'%s'" % (_A1, _A2)),
    ("f550-get-plus-writable",
     "Object.defineProperty({},'c',{get:function(){return '%s';},"
     "writable:true}).c+'%s'" % (_A1, _A2)),
    ("f550-writable-plus-get",
     "Object.defineProperty({},'c',{writable:false,get:function(){"
     "return '%s';}}).c+'%s'" % (_A1, _A2)),
    ("f550-nonliteral-key",
     "Object.defineProperty({},k,{value:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f550-proto-key",
     "Object.defineProperty({},'__proto__',{value:'%s'}).c+'%s'"
     % (_A1, _A2)),
    ("f550-bracket-form",
     "Object['defineProperty']({},'c',{value:'%s'}).c+'%s'"
     % (_A1, _A2)),
    ("f550-nonliteral-target",
     "Object.defineProperty(x,'c',{value:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f550-empty-descriptor",
     "Object.defineProperty({},'c',{}).c+'%s'" % _A2),
    ("f550-this-getter",
     "Object.defineProperty({},'c',{get:function(){return this.x;}})"
     ".c+'%s'" % _A2),
    ("f550-junk-quiet",
     "Object.defineProperty({},'c',{value:'zz'}).c+'yy'"),
]

# (name, source, node-v24.20.0 ground truth) -- decoder must be exact.
NODE_EXACT = [
    ("create-dot", "Object.create({c:'f1'}).c", "f1"),
    ("create-bracket", "Object.create({c:'f1'})['c']", "f1"),
    ("create-nested", "Object.create(Object.create({c:'f1'})).c",
     "f1"),
    ("create-shadow",
     "Object.create({c:'no'},{c:{value:'yes'}}).c", "yes"),
    ("create-newkey",
     "Object.create({c:'no'},{d:{value:'yes'}}).d", "yes"),
    ("create-getter-proto",
     "Object.create({get c(){return 'f1'}}).c", "f1"),
    ("gopd-value",
     "Object.getOwnPropertyDescriptor({c:'f1'},'c').value", "f1"),
    ("gopd-get",
     "Object.getOwnPropertyDescriptor({get c(){return 'f1'}},'c')"
     ".get()", "f1"),
    ("gopd-nested",
     "Object.getOwnPropertyDescriptor({c:{d:'f1'}},'c').value.d",
     "f1"),
    ("dp-value", "Object.defineProperty({},'c',{value:'f1'}).c",
     "f1"),
    ("dp-get",
     "Object.defineProperty({},'c',{get:function(){return 'f1'}}).c",
     "f1"),
    ("dp-get-named",
     "Object.defineProperty({},'c',{get:function g(){return 'f1'}})"
     ".c", "f1"),
    ("dp-overwrite",
     "Object.defineProperty({c:'no'},'c',{value:'yes'}).c", "yes"),
    ("dp-flags",
     "Object.defineProperty({},'c',{value:'f1',writable:true}).c",
     "f1"),
    ("dp-nested",
     "Object.defineProperty({},'c',{value:{d:'f1'}}).c.d", "f1"),
]

COMPOSITIONS = [
    # (name, payload, want_hit) -- neighbors stay honest
    ("f535-literal",
     "({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f535-getter",
     "({get c(){return '%s';}}).c+'%s'" % (_A1, _A2), True),
    ("f539-freeze",
     "Object.freeze({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f539-assign",
     "Object.assign({},{c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f540-reflect-get",
     "Reflect.get({c:'%s'},'c')+'%s'" % (_A1, _A2), True),
    ("f491-gopd-proto",
     "Object.getOwnPropertyDescriptor(Array.prototype,'concat')"
     ".value+'%s'" % _A2, False),
    ("f536-clone",
     "structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f548-in-additive",
     "\"x\"+Object.create({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f550-then-create",
     "Object.create(Object.defineProperty({},'c',{value:'%s'}))"
     ".c+'%s'" % (_A1, _A2), False),  # defineProperty result is not
    # a literal -- create's proto must be a literal or create(...)
    ("junk-quiet-create", "Object.create({c:'ab'}).c+'cd'", False),
    ("junk-quiet-gopd",
     "Object.getOwnPropertyDescriptor({c:'ab'},'c').value+'cd'",
     False),
    ("junk-quiet-dp",
     "Object.defineProperty({},'c',{value:'ab'}).c+'cd'", False),
]

FOOTER_OPEN = (  # Wave-369 lane 2 local: F548/F549/F550 CLOSED (merge finalizes); wave-370 lane 4: F573/F578 CLOSED
               "F570", "F571", "F572",
               "F574", "F575", "F576", "F577",
               "F579", "F580", "F581",
               "F582"
               )
FOOTER_NEXT = "F655"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)


def p1_f548_filed_held():
    """F548 filed shapes decode (HELD)."""
    misses = [n for n, p in F548_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F548 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F548 filed shapes decode"
            % (len(F548_FILED), len(F548_FILED)))


def p2_f549_filed_held():
    """F549 filed shapes decode (HELD)."""
    misses = [n for n, p in F549_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F549 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F549 filed shapes decode"
            % (len(F549_FILED), len(F549_FILED)))


def p3_f550_filed_held():
    """F550 filed shapes decode (HELD)."""
    misses = [n for n, p in F550_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F550 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F550 filed shapes decode"
            % (len(F550_FILED), len(F550_FILED)))


def p4_variants_held():
    """Variant shapes decode (HELD) -- node-exact extensions."""
    misses = ([n for n, p in F548_VARIANTS if not _hit(p)]
              + [n for n, p in F549_VARIANTS if not _hit(p)]
              + [n for n, p in F550_VARIANTS if not _hit(p)])
    total = (len(F548_VARIANTS) + len(F549_VARIANTS)
             + len(F550_VARIANTS))
    if misses:
        return ("BREAK", "variants missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d variants decode" % (total, total))


def p5_boundaries_fail_closed():
    """Every documented boundary fails closed (no credential hit)."""
    bad = [n for n, p in BOUNDARIES if _hit(p)]
    if bad:
        return ("BREAK", "boundaries decoded: %s" % ",".join(bad))
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(BOUNDARIES), len(BOUNDARIES)))


def p6_node_exact():
    """Decoder reproduces node-v24.20.0 ground truth exactly."""
    wrong = []
    for name, src, want in NODE_EXACT:
        r = _try_js_expr_decode(src, 0)
        got = r[0] if r else None
        if got != want:
            wrong.append("%s(got %r)" % (name, got))
    if wrong:
        return ("BREAK", "node-inexact: %s" % ",".join(wrong))
    return ("HELD", "%d/%d node-exact" % (len(NODE_EXACT),
                                         len(NODE_EXACT)))


def p7_compositions_honest():
    """Neighbor findings and composition shapes stay honest."""
    wrong = [n for n, p, want in COMPOSITIONS if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest"
            % (len(COMPOSITIONS), len(COMPOSITIONS)))


def p8_perf_bound():
    """Hostile corpus: many fail-closed matches must starve fast."""
    payload = (("Object.create(x).c+'%s';" % _A1)
               + ("Object.defineProperty(y,'c',{value:'z'}).c+'%s';"
                  % _A1)) * 300
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK",
            "600-anchor hostile corpus %.2fs (budget 5s)" % dt)


def p9_pin_and_footer():
    """Pin stays 2140; re.compile stays 28; F548/F549/F550 CLOSED in
    FINDINGS; lane-local footer."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if text.count("CLOSED 2026-10-07 wave-369 lane 2") < 3:
        return ("BREAK", "F548/F549/F550 CLOSED entries missing")
    if ("**Open findings: %s.**" % ", ".join(FOOTER_OPEN)) not in text:  # Wave-369 lane 2 local: F548/F549/F550 CLOSED (merge finalizes)
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **%s**" % FOOTER_NEXT not in text:
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2140; 28 re.compile; F548/F549/F550 CLOSED; "
            "footer F547,F551-F569/next F570 (wave-369 lane 2)")


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w368_f548_redfirst.py",
               "w368_f549_redfirst.py",
               "w368_f550_redfirst.py",
               "w368_attack_probes.py",
               "w368_f539f540close_probes.py",
               "w367_f535f536close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g369-green-%s-%d" % (script.replace(".py", ""),
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
    probes = (p1_f548_filed_held, p2_f549_filed_held,
              p3_f550_filed_held, p4_variants_held,
              p5_boundaries_fail_closed, p6_node_exact,
              p7_compositions_honest, p8_perf_bound,
              p9_pin_and_footer)
    breaks, held = 0, 0
    for probe in probes:
        verdict, note = probe()
        print("%s: %s -- %s" % (probe.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    print("green check: %s" % _green_check())
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
