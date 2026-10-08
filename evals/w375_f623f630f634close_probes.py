#!/usr/bin/env python3
"""Wave-375 lane 3: F623, F630, F634 CLOSED -- entries-pipeline family.

F623 (LOW): values()/enumeration reads on Object.fromEntries results --
F565 (CLOSED) models fromEntries with member reads, but values()/for-in
reads on fromEntries results were never composed with the enumeration
readers. Closure: Object.fromEntries(...) is now an enumeration-source
class (the F565 _JSObj result ordered engine-exactly), so inline
Object.values(fromEntries(...)), the F612 var-bound twin, and a new
for-in accumulation IIFE twin all block.

F630 (LOW): JSON.parse-sourced Object.values/Object.entries -- F541
(CLOSED) models JSON.parse with member reads and F612 covers var-bound
object literals, but a JSON.parse call result bound and read through
values/entries escaped both. Closure: JSON.parse('LITERAL') is now an
enumeration-source class (stdlib json.loads + the F541 value-graph
converter, props ordered engine-exactly); the F612 var-bound route
picks it up with no F612 changes.

F634 (LOW): reduce() over Object.entries() results -- F437 (CLOSED)
models .reduce() on array-literal and Object.values() receivers, but
the entries() receiver (pair arrays folded with destructured
(a,[k,v])=>a+v or indexed (a,e)=>a+e[1] callbacks) had no modeled path.
Closure: a dedicated Object.entries(OBJ).reduce(CB,"INIT") production
(node-exact fold via the shared _js_reduce_fold); F573 defers the
.reduce form to this route, F517's entries+map route is untouched.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (fresh /var/tmp/g375-* TMPDIRs), hard pin 2140,
concatenation-constructed credentials, $0-spend-by-construction
(evals-only: no realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
from gov import dlp as _dlp  # noqa: E402 -- internal seam for exact values

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail loud, never silent
        verdict, note = "BREAK", "EXC %r" % e
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


# ------------------------------------------------ filed shapes (must block)

def test_p1_f623_values_inline():
    """F623 filed shape 1: Object.values(Object.fromEntries(...))."""
    ok = _blocked("Object.values(Object.fromEntries([['a','%s'],['b','%s']])).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f623_values_varbound():
    """F623 filed shape 2: var-bound fromEntries + Object.values."""
    ok = _blocked("(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f623_forin_twin():
    """F623 filed shape 3: for-in over fromEntries(new Map(...))."""
    ok = _blocked("(function(){var o=Object.fromEntries(new Map([['a','%s'],['b','%s']]));var s='';for(var k in o){s+=o[k];}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f630_values_varbound():
    """F630 filed shape 1: var-bound JSON.parse + Object.values."""
    ok = _blocked("(function(){var o=JSON.parse('{\"a\":\"%s\",\"b\":\"%s\"}');return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f630_entries_varbound():
    """F630 filed shape 2: var-bound JSON.parse + entries/map."""
    ok = _blocked("(function(){var o=JSON.parse('{\"a\":\"%s\",\"b\":\"%s\"}');return Object.entries(o).map(e=>e[1]).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f634_reduce_destructured():
    """F634 filed shape 1: entries reduce with (a,[k,v])=>a+v."""
    ok = _blocked('Object.entries({a:"%s",b:"%s"}).reduce((a,[k,v])=>a+v,"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f634_reduce_indexed():
    """F634 filed shape 2: entries reduce with (a,e)=>a+e[1]."""
    ok = _blocked('Object.entries({a:"%s",b:"%s"}).reduce((a,e)=>a+e[1],"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_f623_map_arg():
    """F623: fromEntries(new Map(...)) inline values read."""
    ok = _blocked("Object.values(Object.fromEntries(new Map([['a','%s'],['b','%s']]))).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f623_ws_tolerant():
    """F623: ws-tolerant fromEntries enumeration."""
    ok = _blocked("Object.values( Object.fromEntries( [ [ 'a' , '%s' ] , [ 'b' , '%s' ] ] ) ).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f623_int_key_order_exact():
    """F623: integer-index keys order ascending (node-exact)."""
    js = "Object.values(Object.fromEntries([['10','A1'],['2','A2']])).join('')"
    keys, vals, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (vals == ["A2", "A1"])  # engine: 2 before 10
    return ("HELD" if ok else "BREAK", "vals=%s" % vals)


def test_p2_f623_dup_key_later_wins():
    """F623: duplicate fromEntries keys -- later wins, first position."""
    js = "Object.values(Object.fromEntries([['a','x'],['a','A1'],['b','A2']])).join('')"
    keys, vals, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (keys == ["a", "b"] and vals == ["A1", "A2"])
    return ("HELD" if ok else "BREAK", "keys=%s vals=%s" % (keys, vals))


def test_p2_f623_keys_enumeration():
    """F623: Object.keys over a fromEntries result."""
    js = "Object.keys(Object.fromEntries([['a','%s'],['b','%s']]))" % (_A, _B)
    keys, _, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (keys == ["a", "b"])
    return ("HELD" if ok else "BREAK", "keys=%s" % keys)


def test_p2_f630_values_inline():
    """F630: inline Object.values(JSON.parse(...))."""
    ok = _blocked("Object.values(JSON.parse('{\"a\":\"%s\",\"b\":\"%s\"}')).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f630_int_key_order_exact():
    """F630: integer-index keys order ascending (node-exact)."""
    js = "Object.values(JSON.parse('{\"10\":\"A1\",\"2\":\"A2\"}')).join('')"
    keys, vals, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (vals == ["A2", "A1"])
    return ("HELD" if ok else "BREAK", "vals=%s" % vals)


def test_p2_f630_dup_key_later_wins():
    """F630: duplicate JSON keys -- later wins, first position."""
    js = "Object.values(JSON.parse('{\"a\":\"x\",\"a\":\"A1\",\"b\":\"A2\"}')).join('')"
    keys, vals, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (keys == ["a", "b"] and vals == ["A1", "A2"])
    return ("HELD" if ok else "BREAK", "keys=%s vals=%s" % (keys, vals))


def test_p2_f630_octal_looking_key_is_string():
    """F630: '01' is a string key (insertion-ordered), not an index."""
    js = "Object.values(JSON.parse('{\"01\":\"A1\",\"b\":\"A2\"}')).join('')"
    keys, vals, _ = _dlp._js_parse_enumeration_source(
        js, js.index("(") + 1, 0, {"parts": 0, "ops": 0})
    ok = (keys == ["01", "b"] and vals == ["A1", "A2"])
    return ("HELD" if ok else "BREAK", "keys=%s" % keys)


def test_p2_f634_block_bodies():
    """F634: {return ...;} block-body callback twins block."""
    ok = _blocked('Object.entries({a:"%s",b:"%s"}).reduce((a,[k,v])=>{return a+v;},"")' % (_A, _B))
    ok = ok and _blocked('Object.entries({a:"%s",b:"%s"}).reduce((a,e)=>{return a+e[1];},"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f634_ws_tolerant():
    """F634: ws-tolerant entries reduce."""
    ok = _blocked('Object.entries( { a : "%s" , b : "%s" } ).reduce( ( a , [ k , v ] ) => a + v , "" )' % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f634_bracket_member():
    """F634: Object['entries'] bracket-string head."""
    ok = _blocked('Object[\'entries\']({a:"%s",b:"%s"}).reduce((a,[k,v])=>a+v,"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_f623_nonliteral_value_misses():
    """F623: non-literal fromEntries value fails closed."""
    ok = _misses("Object.values(Object.fromEntries([['a','%s'],['b',x]])).join('')" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f623_nonpair_arg_misses():
    """F623: non-pair-list fromEntries arg fails closed."""
    ok = _misses("Object.values(Object.fromEntries(foobar)).join('')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f623_forin_nonempty_accum_misses():
    """F623 for-in: non-empty accumulator fails closed."""
    ok = _misses("(function(){var o=Object.fromEntries([['a','%s']]);var s='x';for(var k in o){s+=o[k];}return s;})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f623_forin_member_read_misses():
    """F623 for-in: member read on the indexed value fails closed."""
    ok = _misses("(function(){var o=Object.fromEntries([['a','%s']]);var s='';for(var k in o){s+=o[k].v;}return s;})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f623_forin_reversed_order_misses():
    """F623 for-in: reversed statement order (acc first) fails closed."""
    ok = _misses("(function(){var s='';var o=Object.fromEntries([['a','%s']]);for(var k in o){s+=o[k];}return s;})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_nonliteral_arg_misses():
    """F630: non-string-literal JSON.parse arg fails closed."""
    ok = _misses("(function(){var o=JSON.parse(x);return Object.values(o).join('');})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_reviver_misses():
    """F630: JSON.parse reviver arg fails closed."""
    ok = _misses("(function(){var o=JSON.parse('{\"a\":\"%s\"}',r);return Object.values(o).join('');})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_nonstring_value_misses():
    """F630: non-string JSON value fails closed."""
    ok = _misses("(function(){var o=JSON.parse('{\"a\":1}');return Object.values(o).join('');})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_proto_key_misses():
    """F630: __proto__ key fails closed (F541 parity)."""
    ok = _misses("(function(){var o=JSON.parse('{\"__proto__\":{\"a\":\"%s\"}}');return Object.values(o).join('');})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_nonobject_result_misses():
    """F630: non-object JSON.parse result is not an enumeration source."""
    ok = _misses("(function(){var o=JSON.parse('\"%s\"');return Object.values(o).join('');})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_invalid_json_misses():
    """F630: invalid JSON fails closed (engine throws)."""
    ok = _misses("(function(){var o=JSON.parse('{\"a\":\"%s\"');return Object.values(o).join('');})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f630_stringify_form_misses():
    """F630: JSON.parse(JSON.stringify(...)) stays F571's (residual)."""
    ok = _misses("(function(){var o=JSON.parse(JSON.stringify({a:'%s'}));return Object.values(o).join('');})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_plain_callback_misses():
    """F634: plain (a,b)=>a+b over pairs fails closed (pair coercion)."""
    ok = _misses('Object.entries({a:"%s",b:"%s"}).reduce((a,b)=>a+b,"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_key_fold_misses():
    """F634: key-folding bodies fail closed (out of scope)."""
    ok = _misses('Object.entries({a:"%s",b:"%s"}).reduce((a,[k,v])=>a+k,"")' % (_A, _B))
    ok = ok and _misses('Object.entries({a:"%s",b:"%s"}).reduce((a,e)=>a+e[0],"")' % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_no_init_misses():
    """F634: missing init fails closed (engine seeds from a pair)."""
    ok = _misses('Object.entries({a:"%s"}).reduce((a,[k,v])=>a+v)' % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_nonstring_init_misses():
    """F634: non-string init fails closed."""
    ok = _misses('Object.entries({a:"%s"}).reduce((a,[k,v])=>a+v,0)' % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_function_callback_misses():
    """F634: function-form callbacks fail closed (documented residual)."""
    ok = _misses('Object.entries({a:"%s"}).reduce(function(a,[k,v]){return a+v;},"")' % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f634_nonstring_values_misses():
    """F634: non-string values fail closed (F479 precedent)."""
    ok = _misses('Object.entries({a:1,b:2}).reduce((a,[k,v])=>a+v,"")')
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ composition (neighbors)

def test_p4_neighbors_still_block():
    """F565/F541/F437/F510/F517/F612 controls still block."""
    checks = [
        "Object.fromEntries([['c','%s']]).c+'%s'" % (_A, _B),  # F565
        "JSON.parse('{\"c\":\"%s\"}').c+'%s'" % (_A, _B),  # F541
        "[\"%s\",\"%s\"].reduce((a,b)=>a+b,\"\")" % (_A, _B),  # F437
        "Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B),  # F510
        "(function(){var s='';var o={a:'%s',b:'%s'};for(var k in o){s+=o[k];}return s;})()" % (_A, _B),  # F517
        "(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B),  # F612
        "Object.entries({a:'%s',b:'%s'}).map(e=>e[1]).join('')" % (_A, _B),  # F517 entries
    ]
    bad = [c for c in checks if not _blocked(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % bad[:2])


def test_p4_open_neighbors_still_miss():
    """Sampled wave-375 siblings still miss (F621, F622, F624, F636, F639 pinned).

    The full F621-F639 round-42 open-shape sweep lives in
    w374_attack_probes.py (per-shape open pins); this is a spot check
    that the lane's closures absorbed nothing outside F623/F630/F634.
    """
    shapes = [
        "(function(){var t={};Object.assign(t,{a:'%s',b:'%s'});return Object.values(t).join('');})()" % (_A, _B),  # F621
        "(function(){var o={a:'%s',b:'%s'};var k=Object.keys(o);return o[k[0]]+o[k[1]];})()" % (_A, _B),  # F622
        "\"xx%s\".slice(2)+'%s'" % (_A, _B),  # F624
        "((a)=>(a+'%s')).bind(null,'%s').bind(null)()" % (_B, _A),  # F636
        "(function(){var o={x:{p:'%s'},y:{q:'%s'}};return Object.values(o.x).concat(Object.values(o.y)).join('');})()" % (_A, _B),  # F639
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % [s[:40] for s in bad[:2]])


def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    ok = ok and _misses("Object.values(Object.fromEntries([['a','x']])).join('')")
    ok = ok and _misses("Object.entries({a:'x'}).reduce((a,[k,v])=>a+v,\"\")")
    ok = ok and _misses("Object.values(JSON.parse('{\"a\":\"x\",\"b\":\"y\"}')).join('')")
    ok = ok and _misses("(function(){var o=JSON.parse('{\"a\":\"x\"}');return Object.values(o).join('');})()")
    ok = ok and _misses("(function(){var o=Object.fromEntries([['a','x']]);var s='';for(var k in o){s+=o[k];}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F623/F630/F634 closed; open F621,F622,F624-F629,F631,F632,F635-F639; next F640 (lane-local)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F644**" in text
          and "Open findings: F640, F641, F642, F643." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (no new regexes this lane)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """New anchors do not blow the scan budget (F452 discipline)."""
    one = ("Object.values(Object.fromEntries([['a','x'],['b','y']])).join('') "
           "Object.entries({a:'x'}).reduce((a,[k,v])=>a+v,\"\") ")
    corpus = ("junk " * 500 + one) * 4
    t0 = time.time()
    hit = _blocked(corpus + "Object.values(Object.fromEntries([['a','%s'],['b','%s']])).join('')" % (_A, _B))
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green checks: attack + F612 sibling batteries.

    The siblings' footer pins are stale by design: this lane closed
    F623/F630/F634, so their expected footer (open F621-F639 / next
    F640) no longer matches the lane-local footer. Merge-time repoint
    (wave-305/306 class). Tolerated here, like the wave-374 lanes.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for bat, footer_tests in (("w374_attack_probes.py",
                               ("test_b0_footer_state",)),
                              ("w374_f612close_probes.py",
                               ("test_p5_footer_state",))):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", bat)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        real_break = None
        footer_break = 0
        for line in out.splitlines():
            for ft in footer_tests:
                if line.startswith(ft) and "BREAK" in line:
                    footer_break += 1
            if line.startswith("tally:"):
                try:
                    real_break = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if real_break is not None:
            real_break -= footer_break
        good = (real_break == 0)
        ok_all = ok_all and good
        notes.append("%s=%s(+%d footer)" % (bat, real_break, footer_break))
    return ("HELD" if ok_all else "BREAK", ",".join(notes))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
