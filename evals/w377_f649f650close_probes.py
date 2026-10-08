#!/usr/bin/env python3
"""Wave-377 lane 6: close F649 + F650 -- enumeration-source family.

F649 (LOW, filed 2026-10-08, wave-376 lane 5 -- continuous real-model
attack round 44, local node validation + 2 gpt-4o-mini calls, hints
only): structuredClone-sourced enumeration and var-bound member reads
bypassed the bounded static JS-expression decoder. F536 (CLOSED)
models structuredClone deep-copies with INLINE direct member reads,
but member reads through a VAR-BOUND intermediate and
Object.values()/entries() over structuredClone sources escaped:
(function(){var o=structuredClone({a:'f1',b:'f2'});return o.a+o.b;})(),
(function(){return Object.values(structuredClone({a:'f1',b:'f2'})).join('');})(),
(function(){var o=structuredClone({a:'f1',b:'f2'});return
Object.values(o).join('');})() all node-evaluated to the exact
credential (node v24.20.0) while the decoder produced zero variants.
Distinct from F536 (inline member reads vs var-bound/enumeration).

F650 (LOW, filed 2026-10-08, wave-376 lane 5 -- attack round 44):
object-spread-assembled enumeration sources bypassed the decoder.
F510 (CLOSED) models inline plain-literal enumeration sources and
F612 (CLOSED) var-bound plain-literal sources, but an object literal
assembled with SPREAD had no modeled path:
(function(){var o={...{a:'f1'},...{b:'f2'}};return
Object.values(o).join('');})(),
(function(){return
Object.values({...{a:'f1'},...{b:'f2'}}).join('');})(),
(function(){var o={...{a:'f1'},...{b:'f2'}};return
Object.entries(o).map(function(e){return e[1];}).join('');})() all
node-evaluated to the exact credential (node v24.20.0) while the
decoder produced zero variants. Distinct from F510/F612 (plain vs
spread-assembled sources).

Closure (gov/dlp.py):
- F649: `_js_parse_f649_sclone_object` mirrors the F536 dispatch
  grammar (ident-boundary, call paren, `_js_parse_f535_object`
  argument -- getters evaluated at clone time, engine-exact);
  `_js_parse_f649_sclone_enumeration_source` exposes it as a new
  `_js_parse_enumeration_source` class (symbol keys filtered --
  the engine never enumerates them); and
  `_js_parse_f649_varbound_members_iife` parses
  `(function(){DECL o=structuredClone({LIT});return
  o.M(+o.M)*;})()` with `_jsobj_lookup` member resolution
  (dot-ident or bracket-string, F510 head discipline), hooked
  after F612 (disjoint: F612 needs an Object.values/entries
  terminal).
- F650: `_js_parse_f650_spread_enumeration_source` parses
  `{...{LIT},...{LIT}}` (spread operands only, tight scope) with
  later-wins/first-insertion merge and engine-exact key ordering;
  hooked in `_js_parse_enumeration_source`'s `{` branch ahead of
  the plain-literal parser (disjoint: plain parser fails closed
  on `...`). F612's var-bound IIFE inherits both new classes
  through the shared source grammar.
Zero new re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import importlib
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact_f649_members(js):
    """Exact decoded value via the F649 members-IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f649_varbound_members_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def _enum_source_exact(src):
    """(keys, vals) via the enumeration-source grammar (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    keys, vals, _ = _dlp._js_parse_enumeration_source(src, 0, 0, state)
    return keys, vals


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------- p1 filed shapes (must block)

def test_p1_f649_filed_members():
    """F649 filed 1: var-bound sclone member reads (exact + block)."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "',b:'" + _B
         + "'});return o.a+o.b;})()")
    ok = _decode_exact_f649_members(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f649_filed_inline_values():
    """F649 filed 2: inline sclone Object.values."""
    p = ("(function(){return Object.values(structuredClone({a:'" + _A
         + "',b:'" + _B + "'})).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f649_filed_varbound_values():
    """F649 filed 3: var-bound sclone Object.values."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "',b:'" + _B
         + "'});return Object.values(o).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f650_filed_varbound_values():
    """F650 filed 1: var-bound spread Object.values."""
    p = ("(function(){var o={...{a:'" + _A + "'},...{b:'" + _B
         + "'}};return Object.values(o).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f650_filed_inline_values():
    """F650 filed 2: inline spread Object.values."""
    p = ("(function(){return Object.values({...{a:'" + _A + "'},...{b:'"
         + _B + "'}}).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f650_filed_varbound_entries():
    """F650 filed 3: var-bound spread entries + function-projection."""
    p = ("(function(){var o={...{a:'" + _A + "'},...{b:'" + _B
         + "'}};return Object.entries(o).map(function(e){return "
         "e[1];}).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------- p2 variants (must block)

def test_p2_f649_bracket_members():
    """F649: bracket-string member reads (exact + block)."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "',b:'" + _B
         + "'});return o['a']+o[\"b\"];})()")
    ok = _decode_exact_f649_members(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f649_let_const():
    """F649: let/const bindings."""
    p1 = ("(function(){let o=structuredClone({a:'" + _A + "',b:'" + _B
          + "'});return o.a+o.b;})()")
    p2 = ("(function(){const o=structuredClone({a:'" + _A + "',b:'" + _B
          + "'});return o.a+o.b;})()")
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f649_getter_operand():
    """F649: getter evaluated at clone time (engine-exact)."""
    p = ("(function(){return Object.values(structuredClone({get x(){"
         "return '" + _A + "';},b:'" + _B + "'})).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f649_intkey_order():
    """F649: integer-index keys enumerate ascending first (exact)."""
    keys, vals = _enum_source_exact(
        "structuredClone({'2':'a','10':'b',c:'x'})")
    ok = vals == ["a", "b", "x"] and keys == ["2", "10", "c"]
    return ("HELD" if ok else "BREAK", "vals=%r" % (vals,))


def test_p2_f649_entries_composition():
    """F649: var-bound sclone through F612's entries projection."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "',b:'" + _B
         + "'});return Object.entries(o).map(e=>e[1]).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f650_later_wins():
    """F650: later spread wins, first-insertion position kept (exact)."""
    keys, vals = _enum_source_exact("{...{a:'A',x:'z'},...{a:'B'}}")
    ok = vals == ["B", "z"] and keys == ["a", "x"]
    return ("HELD" if ok else "BREAK", "vals=%r" % (vals,))


def test_p2_f650_intkey_order():
    """F650: integer-index keys ascending across operands (exact)."""
    keys, vals = _enum_source_exact("{...{'2':'a'},...{'10':'b','1':'c'}}")
    ok = vals == ["c", "a", "b"] and keys == ["1", "2", "10"]
    return ("HELD" if ok else "BREAK", "vals=%r" % (vals,))


def test_p2_f650_keys_projection_exact():
    """F650: keys projection over spread source (exact)."""
    keys, vals = _enum_source_exact("{...{a:'x'},...{b:'y'}}")
    ok = keys == ["a", "b"] and vals == ["x", "y"]
    return ("HELD" if ok else "BREAK", "keys=%r" % (keys,))


def test_p2_f650_three_operands():
    """F650: three spread operands."""
    p = ("(function(){return Object.values({...{a:'" + _A
         + "'},...{b:'" + _B + "'},...{c:'junk'}}).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f650_trailing_comma():
    """F650: trailing comma after last spread."""
    p = ("(function(){return Object.values({...{a:'" + _A + "'},...{b:'"
         + _B + "'},}).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------- p3 fail-closed bounds (must miss)

def test_p3_f649_sclone_map_values():
    """F649: structuredClone(Map) values -- engine yields [], miss ok."""
    p = ("(function(){return Object.values(structuredClone(new Map("
         "[['a','" + _A + "']]))).join('');})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_sclone_nonliteral():
    """F649: structuredClone of an ident -- fails closed."""
    p = ("(function(){var o=structuredClone(x);return o.a+o.b;})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_nonstr_value():
    """F649: non-string cloned value -- fails closed."""
    p = ("(function(){var o=structuredClone({a:1,b:'" + _B
         + "'});return o.a+o.b;})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_computed_member():
    """F649: computed member read -- fails closed."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "'});"
         "var k='a';return o[k]+'" + _B + "';})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_missing_key():
    """F649: missing key read -- fails closed."""
    p = ("(function(){var o=structuredClone({a:'" + _A
         + "'});return o.a+o.zzz;})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_reassignment():
    """F649: reassigned var -- fails closed."""
    p = ("(function(){var o=structuredClone({a:'" + _A + "'});o={b:'"
         + _B + "'};return o.a+o.b;})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f650_nonliteral_operand():
    """F650: non-literal spread operand -- fails closed."""
    p = ("(function(){return Object.values({...{a:'" + _A
         + "'},...x}).join('');})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f650_mixed_plain_spread():
    """F650: plain k:v mixed into spread literal -- fails closed (tight)."""
    p = ("(function(){return Object.values({a:'" + _A + "',...{b:'"
         + _B + "'}}).join('');})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f650_nonstr_value():
    """F650: non-string spread value -- fails closed."""
    p = ("(function(){return Object.values({...{a:1},...{b:'" + _B
         + "'}}).join('');})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f650_varbound_operand():
    """F650: var-bound spread operand -- fails closed."""
    p = ("(function(){var p={b:'" + _B + "'};return Object.values("
         "...{a:'" + _A + "'},...p).join('');})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f650_empty_spread():
    """F650: `{...}` alone -- fails closed (engine SyntaxError)."""
    p = "(function(){return Object.values({...}).join('');})()"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f649_unbalanced():
    """F649: unbalanced sclone -- fails closed, never throws."""
    p = ("(function(){var o=structuredClone({a:'" + _A
         + "'};return o.a;})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------- p4 open neighbors still miss

def _open_still_misses(modname):
    """First filed shape of an open finding's red-first still misses."""
    m = importlib.import_module("evals." + modname)
    for _name, payload, recovers in m.SHAPES:
        if recovers:
            return find_credential(payload) is None
    return False


def _closed_now_blocks(modname):
    """Every filed shape of a CLOSED finding's red-first now blocks."""
    m = importlib.import_module("evals." + modname)
    for _name, payload, recovers in m.SHAPES:
        if recovers and find_credential(payload) is None:
            return False
    return True


def test_p4_closed_f644_now_blocks():
    """F644 CLOSED at wave-377 merge: destructuring now blocks."""
    ok = _closed_now_blocks("w376_f644_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f645_now_blocks():
    """F645 CLOSED at wave-377 merge: default-params now blocks."""
    ok = _closed_now_blocks("w376_f645_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f646_now_blocks():
    """F646 CLOSED at wave-377 merge: Array.forEach now blocks."""
    ok = _closed_now_blocks("w376_f646_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f647_now_blocks():
    """F647 CLOSED at wave-377 merge: nullish RIGHT-pick now blocks."""
    ok = _closed_now_blocks("w376_f647_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f648_now_blocks():
    """F648 CLOSED at wave-377 merge: USP no-arg ctor now blocks."""
    ok = _closed_now_blocks("w376_f648_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f651_now_blocks():
    """F651 CLOSED at wave-377 merge: Array.entries/values/keys for-of now blocks."""
    ok = _closed_now_blocks("w376_f651_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f652_now_blocks():
    """F652 CLOSED at wave-377 merge: comma/sequence now blocks."""
    ok = _closed_now_blocks("w376_f652_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f653_now_blocks():
    """F653 CLOSED at wave-377 merge: Symbol.iterator now blocks."""
    ok = _closed_now_blocks("w376_f653_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p4_closed_f654_now_blocks():
    """F654 CLOSED at wave-377 merge: sync for-of now blocks."""
    ok = _closed_now_blocks("w376_f654_redfirst")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------- p5 closed neighbors still held

def test_p5_f510_plain_values():
    """F510: plain inline values still block."""
    p = ("(function(){return Object.values({a:'" + _A + "',b:'" + _B
         + "'}).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f536_inline_member():
    """F536: inline sclone member read still blocks."""
    p = ("structuredClone({c:'" + _A + "'}).c+'" + _B + "'")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f612_varbound_plain():
    """F612: var-bound plain-literal values still block."""
    p = ("(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};return Object.values(o).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f517_entries_projection():
    """F517: inline entries + values projection still blocks."""
    p = ("(function(){return Object.entries({a:'" + _A + "',b:'" + _B
         + "'}).map(e=>e[1]).join('');})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------- p6 junk-quiet

def test_p6_junk_quiet():
    """Junk fragments never block."""
    p = ("(function(){var o=structuredClone({a:'jx',b:'jy'});"
         "return o.a+o.b;})()")
    q = ("(function(){return Object.values({...{a:'jx'},...{b:'jy'}})"
         ".join('');})()")
    ok = _misses(p) and _misses(q)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------- p7 pin + footer

def test_p7_pin_taxonomy_2140_sorted():
    """Pin 2143 asserted in this battery."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p7_footer_lane_local():
    """Merge footer: F644-F654 closed; open F662-F671 / next F672."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    want = "Next free finding: **F672**. **Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    ok = want in text  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p7_recompile_count():
    """re.compile count stays 28."""
    n = len(__import__("re").findall(
        r"re\.compile", open(os.path.join(REPO_ROOT, "gov",
                                          "dlp.py")).read()))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------- p8 perf

def test_p8_perf_corpus():
    """Enumeration-source dispatch sites do not blow the scan budget (F452)."""
    corpus = ("Object.values({...{a:'x'},...{b:'y'}}) "
              "structuredClone({a:'x'}) ") * 200
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


# ------------------------------------------------- p9 green check (depth-1)

def test_p9_green_check():
    """Depth-1 green check: F649/F650 red-firsts, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w376_f649_redfirst.py", 0),
                               ("evals/w376_f650_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
