#!/usr/bin/env python3
"""Wave-378 lane 4: close F658 -- flatMap with literal-array-returning callback.

F658 (LOW, filed attack round 45): F554 (CLOSED) models only the
`.bind`-bound flatMap triple path (`[].flatMap.bind(...)` dispatched
through the F513 Reflect.apply/.call chain); a DIRECT flatMap call
whose callback returns a literal fragment array --
`['x'].flatMap(function(){return ['f1','f2'];}).join('')` and the
arrow twin `['x'].flatMap(()=>['f1','f2']).join('')` -- node-evaluates
to the exact credential (v24.20.0) while the decoder produced zero
variants. The closure (`_js_parse_f658_flatmap_literal_array`,
gov/dlp.py) parses the callback in the existing `name == "flatMap"`
postfix branch, between the F574 identity grammar and the F597
scalar grammar (the three are disjoint on the return head:
`[P]` vs `[`-literal vs scalar). flatMap is map + flat(1):
each element maps to the same literal array, then one-level flatten
(node-exact, incl. the empty-array filter). Zero new re.compile
(28 stays).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

import gov.dlp as _dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
# Fragments such that NO literal below contains the full credential
# (the raw whole-text scan must not decide these probes).
_F1 = _A[:5]          # 'xoxb-'
_F2 = _A[5:][1:]      # '123' (drops the '0')
_F3 = _B
_CRED = _A + _B  # what the assembled shapes yield (only inside payloads)


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_value(js):
    """Whole-text decoded variant (internal seam) for value checks."""
    return _dlp._try_js_expr_decode_all(js)


def _node_val(js):
    r = subprocess.run(
        ["node", "-e",
         "try{var v=eval(process.argv[1]);"
         "console.log(typeof v==='string'?v:JSON.stringify(v))}"
         "catch(e){console.log('THROW:'+e.name)}",
         js], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s %s" % (name, verdict, note))


# ------------------------------------------------ p1 filed shapes (must block)

def test_p1_filed_function():
    """Filed shape 1: function callback returning the literal array."""
    ok = _blocked("['x'].flatMap(function(){return ['%s','%s'];}).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p1_filed_arrow():
    """Filed shape 2: arrow callback returning the literal array."""
    ok = _blocked("['x'].flatMap(()=>['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


# ------------------------------------------------ p2 variants (must block)

def test_p2_named_function():
    ok = _blocked("['x'].flatMap(function f(){return ['%s','%s'];}).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_arrow_one_param():
    ok = _blocked("['x'].flatMap((y)=>['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_arrow_block_body():
    ok = _blocked("['x'].flatMap((y)=>{return ['%s','%s'];}).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_function_one_param():
    ok = _blocked("['x'].flatMap(function(y){return ['%s','%s'];}).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_two_element_source():
    """Each source element maps to the same literal array (node-exact)."""
    dec = _decode_value("['a','b'].flatMap(()=>['%s']).join('')" % _A)
    ok = dec is not None and (_A + _A) in dec
    return ("HELD" if ok else "BREAK", "value=%s" % ok)


def test_p2_dquote():
    ok = _blocked('["x"].flatMap(()=>["%s","%s"]).join("")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_ws_inside():
    """Whitespace inside the call parens is tolerated (node-exact)."""
    ok = _blocked("['x'].flatMap( ()=> ['%s','%s'] ).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_join_separator():
    ok = _blocked("['x'].flatMap(()=>['%s','%s']).join('-')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p2_single_element_return():
    """Single-literal return decodes to exactly that literal."""
    dec = _decode_value("['x'].flatMap(()=>['%s']).join('')" % _A)
    ok = dec is not None and _A in dec and _CRED not in dec
    return ("HELD" if ok else "BREAK", "value=%s" % ok)


def test_p2_bare_param_arrow():
    ok = _blocked("['x'].flatMap(y=>['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


# ------------------------------------------------ p3 fail-closed bounds
#
# Discipline: bounds use _A/_B as SEPARATE literals (the red-first
# convention) -- no literal contains the full credential, so a bound
# only hits if the decoder wrongly assembles _CRED from the halves.

def _bound(name, js):
    ok = _misses(js)
    return ("HELD" if ok else "BREAK", "%s quiet=%s" % (name, ok))


def test_p3_nested_array_return():
    """Nested arrays in the return fail closed (documented boundary)."""
    return _bound("nested",
                 "['x'].flatMap(()=>[['%s'],['%s']]).join('')" % (_A, _B))


def test_p3_template_return():
    # Junk template: a credential can never sit inside a template
    # literal without the raw-text rule firing, so the bound asserts
    # the template path fails closed.
    return _bound("template", "['x'].flatMap(()=>[`jx`]).join('')")


def test_p3_ident_return():
    """An ident element is not a literal -- and F574 owns x=>[x]."""
    return _bound("ident",
                 "['x'].flatMap(()=>['%s','%s',y]).join('')" % (_A, _B))


def test_p3_two_params():
    return _bound("two-params",
                 "['x'].flatMap((a,b)=>['%s','%s']).join('')" % (_A, _B))


def test_p3_function_two_params():
    return _bound("fn-two-params",
                 "['x'].flatMap(function(a,b){return ['%s','%s'];}).join('')"
                 % (_A, _B))


def test_p3_non_return_body():
    return _bound("non-return",
                 "['x'].flatMap(()=>{var q=['%s','%s'];}).join('')"
                 % (_A, _B))


def test_p3_extra_statements():
    return _bound("extra-stmt",
                 "['x'].flatMap(()=>{var q=1;return ['%s','%s'];}).join('')"
                 % (_A, _B))


def test_p3_hole_in_return():
    return _bound("hole",
                 "['x'].flatMap(()=>['%s','%s',]).join('')" % (_A, _B))


def test_p3_numeric_element():
    return _bound("numeric",
                 "['x'].flatMap(()=>[1,'%s','%s']).join('')" % (_A, _B))


def test_p3_missing_semi():
    """Block body without the F574-required ';' fails closed."""
    return _bound("no-semi",
                 "['x'].flatMap(()=>{return ['%s','%s']}).join('')"
                 % (_A, _B))


def test_p3_named_function_bad_name():
    return _bound("bad-fn",
                 "['x'].flatMap(functional(){return ['%s','%s'];}).join('')"
                 % (_A, _B))


# ------------------------------------------------ p4 open neighbors still miss

def test_p4_sibling_closures_hold():
    """F655-F657, F659-F661 CLOSED by sibling lanes (wave-378 merge):
    their shapes must now block.

    Neighbor shapes use _A/_B halves (the red-first convention): the
    full credential appears only if the decoder assembles it.
    """
    shapes = [
        # F655 statement-IIFE multi-statement accumulation
        ("(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B)),
        # F656 generator .next().value reads
        ("(function*(){yield '%s';yield 'junk';})().next().value+'%s'"
         % (_A, _B)),
        # F657 var-bound Map forEach
        ("(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';"
         "m.forEach(function(v){s+=v;});return s;})()" % (_A, _B)),
        # F659 yield* spread
        ("[...(function*(){yield* ['%s','%s'];})()].join('')"
         % (_A, _B)),
        # F660 env-threaded tail read (F652 family)
        ("(function(){var x;return (x='%s',x)+'%s%s'+x;})()"
         % (_A, _F2, _F3)),
        # F661 declaration-position sequence
        ("(function(){var s=('jx','%s');return s+'%s%s';})()"
         % (_F1, _F2, _F3)),
    ]
    missed = sum(1 for s in shapes if _misses(s))
    ok = missed == 0
    return ("HELD" if ok else "BREAK", "unblocked=%d/%d" % (missed, len(shapes)))


# ------------------------------------------------ p5 closed neighbors still held

def test_p5_f554_still_held():
    """F554's .bind-bound flatMap triple is untouched by this lane."""
    ok = _blocked(
        "Reflect.apply([].flatMap.bind([['%s'],['%s']],"
        "function(e){return e;}),null,[]).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p5_f574_identity_still_held():
    """F574 identity on a credential array still blocks coded."""
    ok = _blocked("['%s','%s'].flatMap(x=>[x]).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p5_f597_scalar_still_held():
    """F597 scalar identity on a credential array still blocks coded."""
    ok = _blocked("['%s','%s'].flatMap((x)=>x).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p5_array_join_still_blocks():
    ok = _blocked("['%s','%s'].join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


# ------------------------------------------------ p6 composition

def test_p6_map_after_flatmap():
    """flatMap result flows through a chained identity map."""
    ok = _blocked("['x'].flatMap(()=>['%s','%s']).map(x=>x).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p6_junk_prefix():
    """Junk expression ahead of the real one still decodes (F444)."""
    ok = _blocked("var q='noise';['x'].flatMap(()=>['%s','%s']).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p6_two_flatmaps():
    ok = _blocked("['x'].flatMap(()=>['%s','%s']).flatMap(y=>[y]).join('')"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p6_scalar_concat_return():
    """A scalar concat return still blocks -- via the additive grammar,
    not F658 (which requires a literal-array return)."""
    ok = _blocked("['x'].flatMap(()=>'%s'+'%s').join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


# ------------------------------------------------ p7 node differential

def test_p7_node_differential():
    """Decoder whole-text values match node v24.20.0 exactly."""
    value_cases = [
        "['x'].flatMap(()=>['%s','%s']).join('')" % (_A, _B),
        "['x'].flatMap(function(){return ['%s','%s'];}).join('')" % (_A, _B),
        "['a','b'].flatMap(()=>['%s']).join('')" % _A,
    ]
    quiet_cases = [
        "['x'].flatMap(()=>[]).join('')",
        "[].flatMap(()=>['%s']).join('')" % _A,
    ]
    bad = []
    for js in value_cases:
        nv = _node_val(js)
        dec = _decode_value(js)
        if not nv or dec is None or nv not in dec:
            bad.append("value:" + js[:30])
    for js in quiet_cases:
        nv = _node_val(js)
        dec = _decode_value(js)
        if _CRED in nv or (dec is not None and _CRED in dec):
            bad.append("quiet:" + js[:30])
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "diff=%s" % (bad or "5/5 exact"))


# ------------------------------------------------ p8 junk-quiet

def test_p8_junk_quiet():
    """Junk returns stay quiet through the new grammar."""
    shapes = [
        "['x'].flatMap(()=>['jx']).join('')",
        "['x'].flatMap(function(){return ['jy'];}).join('')",
        "['x'].flatMap(()=>[]).join('')",
    ]
    quiet = sum(1 for s in shapes if _misses(s))
    ok = quiet == len(shapes)
    return ("HELD" if ok else "BREAK", "quiet=%d/%d" % (quiet, len(shapes)))


# ------------------------------------------------ p9 pin + footer

def test_p9_pin_and_footer():
    """Pin 2140; merge footer: F655-F661 closed, open F662-F671, next F672."""
    lines = open(os.path.join(REPO_ROOT, "evals",
                              "FINDINGS.md"), encoding="utf-8").read()
    ok_pin = TAXONOMY_PIN == 2140
    foot = [ln for ln in lines.splitlines()
            if ln.startswith("Next free finding:")]
    last = foot[-1] if foot else ""
    open_seg = (" " + last.split("Open findings:")[-1]
                if "Open findings:" in last else "")
    live_list = open_seg.split("#")[0]  # history comments may name F-numbers
    ok_foot = ("**F672**" in last
               and "F662, F663, F664, F665, F666, F667, F669, F670, F671" in live_list  # Wave-379 lane 6: F668 CLOSED (lane-local)
               and "F655" not in live_list)
    ok = ok_pin and ok_foot
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


# ------------------------------------------------ p10 perf

def test_p10_perf():
    """200 flatMap sites decode in bounded time."""
    js = "['x'].flatMap(()=>['%s','%s']).join('')" % (_A, _B)
    import time
    t0 = time.time()
    for _ in range(200):
        find_credential("var x='%s';" % js)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------ p11 re.compile count

def test_p11_recompile_count():
    """gov/dlp.py keeps exactly 28 re.compile calls."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py"),
               encoding="utf-8").read()
    n = src.count("re.compile(")
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


# ------------------------------------------------ green check (depth-1)

def _redfirst_tally(path):
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True,
        timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1",
                         "TMPDIR": tempfile.mkdtemp(prefix="g378-l4-rf-",
                                                    dir="/var/tmp")})
    breaks = held = 0
    for line in (out.stdout + out.stderr).splitlines():
        if line.startswith("tally:"):
            parts = line.replace("tally:", "").split("/")
            breaks, held = int(parts[0].split()[0]), int(parts[1].split()[0])
    return breaks, held


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    red = os.path.join(REPO_ROOT, "evals/w377_f658_redfirst.py")
    breaks, held = _redfirst_tally(red)
    print("green:w377_f658_redfirst -> %d BREAK / %d HELD" % (breaks, held))
    if breaks != 0:
        ok = False
    atk = os.path.join(REPO_ROOT, "evals/w377_attack_probes.py")
    r = subprocess.run(
        [sys.executable, atk], capture_output=True, text=True, timeout=300,
        env={**os.environ, "GOV_SKIP_GREEN": "1",
             "TMPDIR": tempfile.mkdtemp(prefix="g378-l4-gc-", dir="/var/tmp")})
    tail = (r.stdout + r.stderr).strip().splitlines()[-2:]
    print("green:w377_attack exit=%d %s" % (r.returncode, tail))
    if r.returncode != 0:
        ok = False
    return ok


def main():
    global results
    _t("p1-filed-function", test_p1_filed_function)
    _t("p1-filed-arrow", test_p1_filed_arrow)
    _t("p2-named-function", test_p2_named_function)
    _t("p2-arrow-one-param", test_p2_arrow_one_param)
    _t("p2-arrow-block-body", test_p2_arrow_block_body)
    _t("p2-function-one-param", test_p2_function_one_param)
    _t("p2-two-element-source", test_p2_two_element_source)
    _t("p2-dquote", test_p2_dquote)
    _t("p2-ws-inside", test_p2_ws_inside)
    _t("p2-join-separator", test_p2_join_separator)
    _t("p2-single-element-return", test_p2_single_element_return)
    _t("p2-bare-param-arrow", test_p2_bare_param_arrow)
    _t("p3-nested-array-return", test_p3_nested_array_return)
    _t("p3-template-return", test_p3_template_return)
    _t("p3-ident-return", test_p3_ident_return)
    _t("p3-two-params", test_p3_two_params)
    _t("p3-function-two-params", test_p3_function_two_params)
    _t("p3-non-return-body", test_p3_non_return_body)
    _t("p3-extra-statements", test_p3_extra_statements)
    _t("p3-hole-in-return", test_p3_hole_in_return)
    _t("p3-numeric-element", test_p3_numeric_element)
    _t("p3-missing-semi", test_p3_missing_semi)
    _t("p3-named-function-bad-name", test_p3_named_function_bad_name)
    _t("p4-sibling-closures-hold", test_p4_sibling_closures_hold)
    _t("p5-f554-still-held", test_p5_f554_still_held)
    _t("p5-f574-identity-still-held", test_p5_f574_identity_still_held)
    _t("p5-f597-scalar-still-held", test_p5_f597_scalar_still_held)
    _t("p5-array-join-still-blocks", test_p5_array_join_still_blocks)
    _t("p6-map-after-flatmap", test_p6_map_after_flatmap)
    _t("p6-junk-prefix", test_p6_junk_prefix)
    _t("p6-two-flatmaps", test_p6_two_flatmaps)
    _t("p6-scalar-concat-return", test_p6_scalar_concat_return)
    _t("p7-node-differential", test_p7_node_differential)
    _t("p8-junk-quiet", test_p8_junk_quiet)
    _t("p9-pin-and-footer", test_p9_pin_and_footer)
    _t("p10-perf", test_p10_perf)
    _t("p11-recompile-count", test_p11_recompile_count)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errs = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    gc_ok = _green_check()
    print("green-check: %s" % ("PASS" if gc_ok else "FAIL"))
    return 1 if (breaks or errs or not gc_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
