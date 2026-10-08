#!/usr/bin/env python3
"""Wave-375 lane 1: close F621 -- Object.assign mutated-target reads.

F621 (LOW, filed attack round 42): the bounded static JS-expression
decoder never modeled mutation of a var-bound assign target. F593
(CLOSED) models `Object.assign({}, CHAIN)` in the RETURN position with
member reads on the call result and F605 (CLOSED) generalizes the
operand grammar, but a var-bound target mutated by an assign STATEMENT
and read back through Object.values/Object.entries escaped:

  (function(){var t={};Object.assign(t,{a:'f1',b:'f2'});return Object.values(t).join('');})()
  (function(){var t={};Object.assign(t,{a:'f1',b:'f2'});return Object.entries(t).map(e=>e[1]).join('');})()
  (function(){var t=new Object();Object.assign(t,{a:'f1',b:'f2'});return Object.values(t).join('');})()

All three node-evaluate to the exact credential (v24.20.0) while the
decoder produced zero variants (red-first 3 BREAK / 2 HELD on the open
tree).

Closure (gov/dlp.py, F621): a standalone statement-IIFE parser
`_js_parse_f621_assign_mutate_iife`, dispatched after F612. The decl
binds an EMPTY target (`var|const|let NAME={};` or `new Object();`);
1..3 `Object.assign(NAME, SRC, ...);` statements mutate it in place
(later-wins, each SRC an F510-strict object literal, 1..3 sources per
statement, each merged prop charging the parts budget); the return is
`Object.values(NAME)` / `Object.entries(NAME).map(P=>P[0|1])` on the
bare bound ident, with the merged props re-serialized through F510's
`_js_parse_enumeration_source` so integer-index keys order ascending
first -- the ordering can never drift from F510. Zero new re.compile
(stays 28).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g375-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

import gov.dlp as dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


def _assign(tdecl, stmt, ret):
    return ("(function(){%s;%s;return %s;})()" % (tdecl, stmt, ret))


def _src(*pairs):
    return "{" + ",".join("%s:'%s'" % (k, v) for k, v in pairs) + "}"


# ------------------------------------------------ filed shapes (must block)

def test_p1_assign_values():
    """F621 shape 1 CLOSED: assign-statement + values readback blocks."""
    ok = _blocked(_assign("var t={}",
                          "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                          "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_assign_entries():
    """F621 shape 2 CLOSED: assign-statement + entries/map readback blocks."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.entries(t).map(e=>e[1]).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_assign_ctor_target():
    """F621 shape 3 CLOSED: new Object() target blocks."""
    ok = _blocked(_assign(
        "var t=new Object()",
        "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_const_decl():
    """const-bound empty target blocks."""
    ok = _blocked(_assign(
        "const t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_let_decl():
    """let-bound empty target blocks."""
    ok = _blocked(_assign(
        "let t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_ws_tolerant():
    """Whitespace-tolerant assign statement blocks."""
    ok = _blocked("(function(){var t = {} ; Object.assign( t , %s ) ; "
                  "return Object.values( t ).join( '' ) ; })()"
                  % _src(("a", _A), ("b", _B)))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_bracket_values():
    """Object['values'] bracket-member readback blocks (F510 head)."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object['values'](t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_entries_keys_proj():
    """entries keys projection (.map(e=>e[0])) blocks with key order."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,{'%s':'x','%s':'y'})" % (_A, _B),
        "Object.entries(t).map(e=>e[0]).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_multi_source():
    """Two sources, later-wins: blocks."""
    ok = _blocked(_assign(
        "var t={}",
        "Object.assign(t,%s,%s)" % (_src(("a", "x")), _src(("a", _A), ("b", _B))),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_multi_stmt():
    """Two assign statements accumulate in place: blocks."""
    ok = _blocked("(function(){var t={};Object.assign(t,%s);"
                  "Object.assign(t,%s);return Object.values(t).join('');})()"
                  % (_src(("a", _A)), _src(("b", _B))))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_int_keys():
    """Integer-like keys order ascending (engine-exact): blocks."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,{'1':'%s','0':'%s'})" % (_B, _A),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_sep_join():
    """Non-empty join separator blocks."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('-')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_dupe_in_source():
    """Duplicate key inside one source, later wins: blocks."""
    ok = _blocked(_assign(
        "var t={}",
        "Object.assign(t,{a:'x',a:'%s',b:'%s'})" % (_A, _B),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_new_object_ws():
    """new Object () with spaces blocks."""
    ok = _blocked(_assign(
        "var t = new Object ()",
        "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_entries_paren_param():
    """Entries projection with parenthesized param blocks."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.entries(t).map((e)=>e[1]).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_mixed_int_str_keys():
    """Mixed integer/string keys: integer first, then insertion order."""
    ok = _blocked(_assign(
        "var t={}", "Object.assign(t,{b:'%s','0':'%s',a:'%s'})" % (_B, _A, _A),
        "Object.values(t).join('')"))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ boundaries (must miss)

def _miss(name, payload):
    ok = _misses(payload)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonempty_target():
    """Non-empty literal target fails closed (F539 precedent)."""
    return _miss("p3", _assign(
        "var t={z:'q'}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))


def test_p3_new_object_noparen():
    """new Object without parens fails closed."""
    return _miss("p3", _assign(
        "var t=new Object",
        "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))


def test_p3_wrong_target():
    """Assign to a different var fails closed."""
    return _miss("p3", "(function(){var t={};var u={};"
                       "Object.assign(u,%s);"
                       "return Object.values(t).join('');})()"
                % _src(("a", _A), ("b", _B)))


def test_p3_no_source():
    """Object.assign(t) with no source fails closed."""
    return _miss("p3", _assign("var t={}", "Object.assign(t)",
                              "Object.values(t).join('')"))


def test_p3_four_sources():
    """Four sources exceeds the F605 3-source bound: fails closed."""
    return _miss("p3", _assign(
        "var t={}",
        "Object.assign(t,%s,%s,%s,%s)" % (_src(("a", _A)), _src(("b", _B)),
                                             _src(("c", "x")), _src(("d", "y"))),
        "Object.values(t).join('')"))


def test_p3_string_source():
    """String source would spread to indexed props: fails closed (F593)."""
    return _miss("p3", _assign("var t={}", "Object.assign(t,'ab')",
                              "Object.values(t).join('')"))


def test_p3_null_source():
    """null source (engine-ignored) fails closed -- refusing is safe."""
    return _miss("p3", _assign(
        "var t={}", "Object.assign(t,null,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))


def test_p3_number_value():
    """Non-string literal value fails closed (F510 boundary)."""
    return _miss("p3", _assign(
        "var t={}", "Object.assign(t,{a:1,b:'%s'})" % _B,
        "Object.values(t).join('')"))


def test_p3_getter_source():
    """Getter source fails closed (F510 boundary)."""
    return _miss("p3", _assign(
        "var t={}",
        "Object.assign(t,{get a(){return '%s';},b:'%s'})" % (_A, _B),
        "Object.values(t).join('')"))


def test_p3_proto_key():
    """__proto__ key fails closed."""
    return _miss("p3", _assign(
        "var t={}",
        "Object.assign(t,{'__proto__':{x:1},a:'%s',b:'%s'})" % (_A, _B),
        "Object.values(t).join('')"))


def test_p3_entries_no_map():
    """Bare Object.entries(t) without map projection fails closed (F517)."""
    return _miss("p3", _assign(
        "var t={}", "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.entries(t).join('')"))


def test_p3_wrong_ident():
    """values() on a different ident fails closed."""
    return _miss("p3", "(function(){var t={};var u={a:'%s',b:'%s'};"
                       "Object.assign(t,%s);"
                       "return Object.values(u).join('');})()"
                % (_A, _B, _src(("a", _A), ("b", _B))))


def test_p3_extra_stmt():
    """Extra statement between assign and return fails closed."""
    return _miss("p3", "(function(){var t={};Object.assign(t,%s);var x=1;"
                       "return Object.values(t).join('');})()"
                % _src(("a", _A), ("b", _B)))


def test_p3_named_fn():
    """Named function IIFE fails closed."""
    return _miss("p3", "(function foo(){var t={};Object.assign(t,%s);"
                       "return Object.values(t).join('');})()"
                % _src(("a", _A), ("b", _B)))


def test_p3_call_args():
    """IIFE with call args fails closed."""
    return _miss("p3", "(function(){var t={};Object.assign(t,%s);"
                       "return Object.values(t).join('');})(1)"
                % _src(("a", _A), ("b", _B)))


def test_p3_bracket_assign():
    """Object['assign'] bracket form fails closed (F539 precedent)."""
    return _miss("p3", _assign(
        "var t={}", "Object['assign'](t,%s)" % _src(("a", _A), ("b", _B)),
        "Object.values(t).join('')"))


def test_p3_reassign_target():
    """Reassignment of the target var fails closed."""
    return _miss("p3", "(function(){var t={};Object.assign(t,%s);t={b:'%s'};"
                       "return Object.values(t).join('');})()"
                % (_src(("a", _A)), _B))


# ------------------------------------------------ composition (neighbors)

def test_p4_f593_still_blocks():
    """F593 (call-position assign + member read) still blocks -- not absorbed."""
    ok = _blocked("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
                  "return Object.assign({x:1},m.get(r)).c+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f605_still_blocks():
    """F605 (generalized assign operands) still blocks -- not absorbed."""
    ok = _blocked("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
                  "return Object.assign(m.get(r),{d:1}).c+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f612_still_blocks():
    """F612 (var-bound values/entries, no assign) still blocks -- not absorbed."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f510_inline_still_blocks():
    """F510 (inline values) still blocks -- not absorbed."""
    ok = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f639_still_misses():
    """F639 (nested var-bound paths, OPEN) still misses -- not absorbed."""
    ok = _misses("(function(){var o={x:{p:'%s'},y:{q:'%s'}};"
                 "return Object.values(o.x).concat(Object.values(o.y))"
                 ".join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_f622_still_misses():
    """F622 (OPEN) still misses -- not absorbed."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};var k=Object.keys(o);"
                 "return o[k[0]]+o[k[1]];})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Taxonomy pin is 2140."""
    import gov.decision_codes as _dc
    ok = (len(_dc.TAXONOMY) == TAXONOMY_PIN)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F621 closed this lane; open F622-F639; next F640."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F640**" in text  # Wave-375 lane 1: F621 CLOSED
          and "Open findings: F622, F623, F624, F625, F626, F627, F628, "
              "F629, F630, F631, F632, F633, F634, F635, F636, F637, "
              "F638, F639." in text)  # Wave-375 lane 1: F621 CLOSED
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28."""
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """200 assign-mutation sites stay within the scan budget (F452)."""
    site = ("(function(){var t={};Object.assign(t,{a:'%s',b:'%s'});"
            "return Object.values(t).join('');})()" % (_A, _B))
    corpus = ("junk " * 50 + site + " ") * 200
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


# ------------------------------------------------ node differential

def test_p6_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    cases = [
        # (js, node-yields-credential?)
        (_assign("var t={}",
                 "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                 "Object.values(t).join('')"), True),
        (_assign("var t={}",
                 "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                 "Object.entries(t).map(e=>e[1]).join('')"), True),
        (_assign("var t=new Object()",
                 "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                 "Object.values(t).join('')"), True),
        (_assign("const t={}",
                 "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                 "Object.values(t).join('')"), True),
        (_assign("var t={}",
                 "Object.assign(t,%s,%s)" % (_src(("a", "x")),
                                             _src(("a", _A), ("b", _B))),
                 "Object.values(t).join('')"), True),
        (_assign("var t={}",
                 "Object.assign(t,{'1':'%s','0':'%s'})" % (_B, _A),
                 "Object.values(t).join('')"), True),
        # fail-closed shapes: the decoder must MISS regardless of node
        # (node yields "q"+credential here, so === C is False)
        (_assign("var t={z:'q'}",
                 "Object.assign(t,%s)" % _src(("a", _A), ("b", _B)),
                 "Object.values(t).join('')"), False),
        (_assign("var t={}", "Object.assign(t,'ab')",
                 "Object.values(t).join('')"), False),
        (_assign("var t={}", "Object.assign(t)",
                 "Object.values(t).join('')"), False),
    ]
    js = ("const C=%s;const R=[];\n" % repr(_FULL) +
          "\n".join("try{R.push(eval(%s)===C)}catch(e){R.push('err')}"
                    % repr(c) for c, _ in cases) +
          "\nconsole.log(JSON.stringify(R));")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    node_truth = json.loads(r.stdout.strip())
    bad = []
    for (c, want), truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        # decoder must agree with node on credential-yielding shapes;
        # on fail-closed shapes the decoder must MISS regardless.
        if truth is True and want and not dec_hit:
            bad.append("miss:" + c[:60])
        if truth is False and dec_hit:
            bad.append("falsepos:" + c[:60])
    # value-level: decoded value is node-exact, not just flagged
    val_cases = [
        (_assign("var t={}",
                 "Object.assign(t,%s)" % _src(("a", "b"), ("c", "d")),
                 "Object.values(t).join('')"), "bd"),
        (_assign("var t={}",
                 "Object.assign(t,{'1':'b','0':'a'})",
                 "Object.values(t).join('')"), "ab"),
        (_assign("var t={}",
                 "Object.assign(t,{b:'y','0':'x',a:'z'})",
                 "Object.values(t).join('')"), "xyz"),
        (_assign("var t={}",
                 "Object.assign(t,%s)" % _src(("a", "b"), ("c", "d")),
                 "Object.entries(t).map(e=>e[0]).join('-')"), "a-c"),
        (_assign("var t=new Object()",
                 "Object.assign(t,{x:'p'},{x:'q',y:'r'})",
                 "Object.values(t).join('')"), "qr"),
    ]
    for src, want in val_cases:
        state = {"ops": 0, "parts": 0}
        try:
            got, _ = dlp._js_parse_f621_assign_mutate_iife(src, 0, 0, state)
        except Exception:  # noqa: BLE001
            got = None
        if got != want:
            bad.append("value:%s got=%r" % (src[:50], got))
    total = len(cases) + len(val_cases)
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement%s"
            % (total - len(bad), total, (" " + ";".join(bad[:3])) if bad else ""))


# ------------------------------------------------ honest text quiet

def test_p8_honest_assign_quiet():
    """Benign assign-mutation decodes but carries no credential: quiet."""
    ok = _misses("(function(){var t={};Object.assign(t,{a:'hello',b:'world'});"
                 "return Object.values(t).join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p8_junk_quiet():
    """Junk control stays quiet."""
    ok = _misses("\"(function(){var s='ab';return s;})()\"")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ green check (depth-1)

def test_p9_green_check():
    """Depth-1 green check: adjacent batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for name, want_break in (("w374_attack_probes.py", 0),
                             ("w374_f621_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        real_break = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    real_break = int(parts[1])
                except (IndexError, ValueError):
                    pass
        good = (real_break == want_break)
        ok_all = ok_all and good
        notes.append("%s=%s" % (name, real_break))
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
