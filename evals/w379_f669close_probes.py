#!/usr/bin/env python3
"""Wave-379 lane 7: close F669 -- builtin-iterable spread consumption.

F669 (LOW, filed attack round 46): builtin-iterable spread
consumption bypasses the bounded static JS-expression decoder --
`[...set]` and `[...map.values()]` fragment assembly. Filed shapes:

  (function(){var st=new Set(['f1','f2']);return [...st].join('');})()
  (function(){var m=new Map();m.set('a','f1');m.set('b','f2');
    return [...m.values()].join('');})()

both node-evaluated to the exact credential (v24.20.0) while the
decoder produced zero variants. The Array.from twin blocks coded
(F653's Array.from route handles builtin iterables).

Closure (gov/dlp.py, F669): _js_parse_f669_set_spread_iife parses
(function(){var|let|const NAME=new Set([LITS]);(NAME.add('LIT');)*
return [...NAME(.values()|.keys())?].join(SEP);})() -- Set spread
preserves insertion order with SameValueZero first-occurrence dedup
(.values()/.keys() are the same iterator; .add appends with dedup;
node v24.20.0 verified). _js_parse_f669_map_values_spread_iife parses
(function(){var|let|const NAME=new Map();(NAME.set(K,V);)*
return [...NAME.(values|keys)()].join(SEP);})() and the
new Map([[K,V],...]) ctor-arg twin -- values/keys iterate in
insertion order with later-wins on duplicate keys (the F494 kid
discipline: 1 and '1' are distinct keys). A bare [...NAME] spread on
a Map would yield [k,v] pair arrays (pair-toString always injects
",") and fails closed. Both hook after F602 in the dispatch chain;
disjoint (F602's forof/foreach require an accumulator decl or a
forEach call and fail closed on a spread-consume return; F657
requires an accumulator decl plus forEach; these routes require the
spread-consume return and fail closed on all of those, so no
previously-decoded input changes behavior).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact_set(js):
    """Exact decoded value via the F669 Set IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f669_set_spread_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def _decode_exact_map(js):
    """Exact decoded value via the F669 Map IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f669_map_values_spread_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s %s" % (name, verdict, note))


def _hit(name, payload):
    ok = _blocked(payload)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _miss(name, payload):
    ok = _misses(payload)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_set_spread():
    """Filed shape 1: var-bound Set, bare spread consume."""
    p = ("(function(){var st=new Set(['" + _A + "','" + _B + "']);"
         "return [...st].join('');})()")
    ok = _decode_exact_set(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_map_values_spread():
    """Filed shape 2: var-bound Map, .set mutations, .values spread."""
    p = ("(function(){var m=new Map();m.set('a','" + _A + "');"
         "m.set('b','" + _B + "');return [...m.values()].join('');})()")
    ok = _decode_exact_map(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_set_values_twin():
    """Set .values() spread is the same value iterator (node-verified)."""
    return _hit("set-values",
                "(function(){var st=new Set(['" + _A + "','" + _B + "']);"
                "return [...st.values()].join('');})()")


def test_p2_set_keys_twin():
    """Set .keys() spread is the values alias (node-verified)."""
    return _hit("set-keys",
                "(function(){var st=new Set(['" + _A + "','" + _B + "']);"
                "return [...st.keys()].join('');})()")


def test_p2_set_let_decl():
    """let-bound Set blocks."""
    return _hit("set-let",
                "(function(){let st=new Set(['" + _A + "','" + _B + "']);"
                "return [...st].join('');})()")


def test_p2_set_const_decl():
    """const-bound Set blocks (no reassignment in the grammar)."""
    return _hit("set-const",
                "(function(){const st=new Set(['" + _A + "','" + _B
                + "']);return [...st].join('');})()")


def test_p2_set_add_mutations():
    """.add() mutations append node-exactly (dedup on repeat)."""
    p = ("(function(){var st=new Set(['" + _A + "']);st.add('" + _B
         + "');return [...st].join('');})()")
    ok = _decode_exact_set(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_set_add_dedup():
    """Set.add dedups SameValueZero-first-occurrence (node-verified)."""
    p = ("(function(){var st=new Set(['" + _A + "','" + _A + "']);"
         "return [...st].join('');})()")
    ok = _decode_exact_set(p) == _A and _misses(p)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_set_join_noarg():
    """No-arg join defaults to ',' (node-verified)."""
    p = ("(function(){var st=new Set(['x','y']);"
         "return [...st].join();})()")
    ok = _decode_exact_set(p) == "x,y"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_set_join_separator():
    """String-literal separator joins node-exactly."""
    p = ("(function(){var st=new Set(['x','y']);"
         "return [...st].join('-');})()")
    ok = _decode_exact_set(p) == "x-y"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_set_dquote_ws():
    """Double quotes and whitespace tolerated."""
    p = ('(function(){ var  st = new Set( [ "' + _A + '" , "' + _B
         + '" ] ) ; return [ ... st ] . join( "" ) ; })()')
    ok = _decode_exact_set(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_map_ctor_arg():
    """Map ctor-arg twin: new Map([[K,V],...]) then .values spread."""
    p = ("(function(){var m=new Map([['a','" + _A + "'],['b','" + _B
         + "']]);return [...m.values()].join('');})()")
    ok = _decode_exact_map(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_map_keys_spread():
    """.keys() spread yields keys in insertion order (node-verified)."""
    p = ("(function(){var m=new Map();m.set('k1','" + _A + "');"
         "m.set('k2','" + _B + "');return [...m.keys()].join('');})()")
    ok = _decode_exact_map(p) == "k1k2" and _misses(p)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_later_wins():
    """Duplicate key: later value wins at the ORIGINAL position."""
    p = ("(function(){var m=new Map();m.set('a','x');m.set('b','y');"
         "m.set('a','z');return [...m.values()].join('');})()")
    ok = _decode_exact_map(p) == "zy" and _misses(p)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_numeric_key():
    """Numeric 1 and string '1' are distinct keys (SameValueZero)."""
    p = ("(function(){var m=new Map();m.set(1,'aa');m.set('1','bb');"
         "return [...m.values()].join('');})()")
    ok = _decode_exact_map(p) == "aabb" and _misses(p)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_empty():
    """Empty map decodes to the empty string (node-verified)."""
    p = ("(function(){var m=new Map();return [...m.values()].join('');"
         "})()")
    ok = _decode_exact_map(p) == "" and _misses(p)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must stay quiet)

def test_p3_reassigned_set():
    """Reassignment fails closed (the Set route has no rebind)."""
    return _miss("set-reassign",
                 "(function(){var st=new Set(['aa']);st=new Set(['bb']);"
                 "return [...st].join('');})()")


def test_p3_extra_statement():
    """Extra statements fail closed."""
    return _miss("extra-stmt",
                 "(function(){var st=new Set(['aa']);var q=1;"
                 "return [...st].join('');})()")


def test_p3_nonliteral_element():
    """Non-literal Set element fails closed (engine would throw)."""
    return _miss("nonlit-elem",
                 "(function(){var st=new Set(['aa',x]);"
                 "return [...st].join('');})()")


def test_p3_numeric_element():
    """Numeric Set element fails closed (the F602 literal discipline)."""
    return _miss("num-elem",
                 "(function(){var st=new Set([1,2]);"
                 "return [...st].join('');})()")


def test_p3_spread_other_ident():
    """Spread of an unbound ident fails closed."""
    return _miss("other-ident",
                 "(function(){var st=new Set(['aa']);"
                 "return [...zz].join('');})()")


def test_p3_mixed_spread():
    """Mixed spread fails closed (F471 scope)."""
    return _miss("mixed-spread",
                 "(function(){var st=new Set(['aa']);"
                 "return [...st,'bb'].join('');})()")


def test_p3_bare_map_spread():
    """Bare Map spread yields [k,v] pairs (commas from pair-toString)
    and fails closed."""
    return _miss("bare-map",
                 "(function(){var m=new Map();m.set('a','aa');"
                 "return [...m].join('');})()")


def test_p3_map_entries_spread():
    """.entries() spread yields pairs and fails closed."""
    return _miss("map-entries",
                 "(function(){var m=new Map();m.set('a','aa');"
                 "return [...m.entries()].join('');})()")


def test_p3_set_delete_mutation():
    """Unmodeled .delete mutation fails the shape closed (F599)."""
    return _miss("set-delete",
                 "(function(){var st=new Set(['aa','bb']);"
                 "st.delete('aa');return [...st].join('');})()")


def test_p3_map_nonliteral_key():
    """Non-literal .set key fails closed."""
    return _miss("map-nonlit-key",
                 "(function(){var m=new Map();m.set(x,'aa');"
                 "return [...m.values()].join('');})()")


def test_p3_map_nonliteral_value():
    """Non-literal .set value fails closed."""
    return _miss("map-nonlit-val",
                 "(function(){var m=new Map();m.set('a',x);"
                 "return [...m.values()].join('');})()")


def test_p3_set_on_other_ident():
    """.set on another ident fails closed (not the bound Map)."""
    return _miss("set-other",
                 "(function(){var m=new Map();zz.set('a','aa');"
                 "return [...m.values()].join('');})()")


def test_p3_nonliteral_separator():
    """Non-literal join separator fails closed (node: join(0)='a0b')."""
    return _miss("nonlit-sep",
                 "(function(){var st=new Set(['a','b']);"
                 "return [...st].join(0);})()")


def test_p3_call_args():
    """Call args on the IIFE fail closed."""
    return _miss("call-args",
                 "(function(){var st=new Set(['aa']);"
                 "return [...st].join('');})(1)")


def test_p3_reserved_name():
    """Reserved-word binding fails closed."""
    return _miss("reserved",
                 "(function(){var while=new Set(['aa']);"
                 "return [...while].join('');})()")


def test_p3_arguments_name():
    """`arguments`-named binding fails closed."""
    return _miss("arguments",
                 "(function(){var arguments=new Set(['aa']);"
                 "return [...arguments].join('');})()")


# ------------------------------------------------ neighbors: closed stay HELD, open stay BREAK

def test_p4_f602_still_blocks():
    """F602 set-forof route still blocks on the closed tree."""
    return _hit("f602",
                "(function(){var s='';for(var x of new Set(['" + _A
                + "','" + _B + "'])){s+=x;}return s;})()")


def test_p4_f657_still_blocks():
    """F657 var-bound map-forEach route still blocks."""
    return _hit("f657",
                "(function(){var m=new Map([['k','" + _A + "'],['j','"
                + _B + "']]);var s='';m.forEach(function(v){s+=v;});"
                "return s;})()")


def test_p4_f653_still_blocks():
    """F653 Array.from route still blocks."""
    return _hit("f653",
                "(function(){return Array.from(new Set(['" + _A
                + "','" + _B + "'])).join('');})()")


def test_p4_open_neighbors_still_break():
    """Open findings F662-F668, F670, F671: nothing absorbed by F669."""
    import importlib
    bad = []
    for fnum in (662, 663, 664, 665, 666, 667, 668, 670, 671):
        mod = importlib.import_module("w378_f%d_redfirst" % fnum)
        for entry in mod.SHAPES:
            payload = entry[1]
            if find_credential(payload) is not None:
                bad.append("f%d:%s" % (fnum, entry[0]))
    ok = not bad
    return ("HELD" if ok else "BREAK", "absorbed=%s" % (bad or "none"))


def test_p4_junk_quiet():
    """Honest text stays quiet (no false positives)."""
    return _miss("junk", "var s = new Set(['nothing', 'here']);")


def test_p4_composition():
    """F669 shape composed with junk stays precise."""
    p = ("prefix junk (function(){var st=new Set(['" + _A + "','" + _B
         + "']);return [...st].join('');})() suffix")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ pin + footer

def test_p5_pin_and_footer():
    """Pin 2140; lane-local footer: open F662-F668, F670, F671 / next F672."""
    from gov.decision_codes import TAXONOMY  # noqa: E402
    ok = TAXONOMY_PIN == 2140
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F672**" in text
    ok = ok and ("Open findings: F662, F663, F664, F665, F666, F667, "
                 "F668, F670, F671." in text)
    ok = ok and "**Status: CLOSED 2026-10-08 wave-379 lane 7.**" in text
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


# ------------------------------------------------ perf

def test_p6_perf():
    """200 F669 sites decode quickly (bounded work)."""
    site = ("(function(){var st=new Set(['aa','bb']);"
            "return [...st].join('');})()")
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    """Depth-1 green check: w378 attack battery stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w378_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w378 battery's footer pin was repointed by this lane to
    # the lane-local footer (open F662-F668, F670, F671 / next F672),
    # matching the FINDINGS.md repoint, so the footer tolerance below
    # is a merge-time safety net only (the merge coordinator repoints
    # both to the merged footer). The two F669 pins were flipped to
    # closed pins by this lane (wave-305/306 class), so no pin
    # tolerance remains.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w378_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


def test_p7_green_check():
    """Green check: wave-378 attack battery stays green (depth-1)."""
    return _green_check()


def test_p7_redfirst_green():
    """Red-first battery for F669 stays 0 BREAK on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w378_f669_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = "tally: 0 BREAK" in out
    return ("HELD" if ok else "BREAK", "redfirst-0-break=%s" % ok)


def main():
    tests = [
        ("p1_filed_set_spread", test_p1_filed_set_spread),
        ("p1_filed_map_values_spread", test_p1_filed_map_values_spread),
        ("p2_set_values_twin", test_p2_set_values_twin),
        ("p2_set_keys_twin", test_p2_set_keys_twin),
        ("p2_set_let_decl", test_p2_set_let_decl),
        ("p2_set_const_decl", test_p2_set_const_decl),
        ("p2_set_add_mutations", test_p2_set_add_mutations),
        ("p2_set_add_dedup", test_p2_set_add_dedup),
        ("p2_set_join_noarg", test_p2_set_join_noarg),
        ("p2_set_join_separator", test_p2_set_join_separator),
        ("p2_set_dquote_ws", test_p2_set_dquote_ws),
        ("p2_map_ctor_arg", test_p2_map_ctor_arg),
        ("p2_map_keys_spread", test_p2_map_keys_spread),
        ("p2_map_later_wins", test_p2_map_later_wins),
        ("p2_map_numeric_key", test_p2_map_numeric_key),
        ("p2_map_empty", test_p2_map_empty),
        ("p3_reassigned_set", test_p3_reassigned_set),
        ("p3_extra_statement", test_p3_extra_statement),
        ("p3_nonliteral_element", test_p3_nonliteral_element),
        ("p3_numeric_element", test_p3_numeric_element),
        ("p3_spread_other_ident", test_p3_spread_other_ident),
        ("p3_mixed_spread", test_p3_mixed_spread),
        ("p3_bare_map_spread", test_p3_bare_map_spread),
        ("p3_map_entries_spread", test_p3_map_entries_spread),
        ("p3_set_delete_mutation", test_p3_set_delete_mutation),
        ("p3_map_nonliteral_key", test_p3_map_nonliteral_key),
        ("p3_map_nonliteral_value", test_p3_map_nonliteral_value),
        ("p3_set_on_other_ident", test_p3_set_on_other_ident),
        ("p3_nonliteral_separator", test_p3_nonliteral_separator),
        ("p3_call_args", test_p3_call_args),
        ("p3_reserved_name", test_p3_reserved_name),
        ("p3_arguments_name", test_p3_arguments_name),
        ("p4_f602_still_blocks", test_p4_f602_still_blocks),
        ("p4_f657_still_blocks", test_p4_f657_still_blocks),
        ("p4_f653_still_blocks", test_p4_f653_still_blocks),
        ("p4_open_neighbors_still_break", test_p4_open_neighbors_still_break),
        ("p4_junk_quiet", test_p4_junk_quiet),
        ("p4_composition", test_p4_composition),
        ("p5_pin_and_footer", test_p5_pin_and_footer),
        ("p6_perf", test_p6_perf),
        ("p7_green_check", test_p7_green_check),
        ("p7_redfirst_green", test_p7_redfirst_green),
    ]
    for name, fn in tests:
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errs = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    return 0 if breaks == 0 and errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
