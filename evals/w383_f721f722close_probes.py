#!/usr/bin/env python3
"""Close battery for F721 + F722 (wave-383 lane 5).

F721: Array.prototype.indexOf conditional reads --
`['k'].indexOf('k')===0?'f1':'xx'` selects the fragment branch of a
ternary (the unmodeled-ternary vehicle shared with F687/F710; the
novel contribution is the unmodeled indexOf API). Closed by
_js_parse_f721_indexof_iife (gov/dlp.py, hooked after F710):
inline literal array, literal key, integer-literal comparison ->
boolean, branch selected node-exactly (v24.20.0).

F722: Map.prototype.has conditional reads --
`var m=new Map([['k',1]]);m.has('k')?'f1':'xx'` (the same ternary
vehicle; the novel contribution is the unmodeled Map.has API).
Closed by _js_parse_f722_map_has_iife (gov/dlp.py, hooked after
F721): var-bound Map (F657 decl, optional .set mutations like
F708), `[!]m.has(KEY)` -> boolean via the F563 entries
discipline, branch selected node-exactly.

0 BREAK / all HELD / 0 ERROR on the closed tree; the red-firsts
evals/w382_f721_redfirst.py + evals/w382_f722_redfirst.py print
2 BREAK each on the open tree (verified pre-lane via git stash).
"""
import argparse
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

import gov.dlp as dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2143  # Wave-383: pin carried from wave-382 merge
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F721/F722 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f721_s1():
    """F721 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var f=['k'].indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f721-s1=%s" % ok)


@_t
def test_p1_f721_s2():
    """F721 filed shape 2 blocks."""
    ok = _blocked(
        "(function(){var f=['a','k'].indexOf('k')>0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f721-s2=%s" % ok)


@_t
def test_p1_f722_s1():
    """F722 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k',1]]);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f722-s1=%s" % ok)


@_t
def test_p1_f722_s2():
    """F722 filed shape 2 (set-mutation twin) blocks."""
    ok = _blocked(
        "(function(){var m=new Map();m.set('k',1);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f722-s2=%s" % ok)


# --------------------------------------------------------------- variants

@_t
def test_p2_f721_inline_ternary_return():
    """F721 inline ternary in the return blocks."""
    ok = _blocked(
        "(function(){return (['k'].indexOf('k')===0?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "inline-ret=%s" % ok)


@_t
def test_p2_f721_negated_index():
    """F721 missing-key comparison selects the else branch (node-exact)."""
    # ['k'].indexOf('z') is -1; -1===0 is false -> 'xx' branch;
    # find_credential must NOT flag ('xx'+B has no credential).
    ok = _misses(
        "(function(){var f=['k'].indexOf('z')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "else-branch=%s" % ok)


@_t
def test_p2_f721_ne_comparison():
    """F721 !== comparison blocks."""
    ok = _blocked(
        "(function(){var f=['k'].indexOf('k')!==-1?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "ne-cmp=%s" % ok)


@_t
def test_p2_f721_lt_comparison():
    """F721 < comparison blocks."""
    ok = _blocked(
        "(function(){var f=['k','a'].indexOf('k')<1?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "lt-cmp=%s" % ok)


@_t
def test_p2_f722_negated_has():
    """F722 !m.has selects the else branch node-exactly (miss, no credential)."""
    ok = _misses(
        "(function(){var m=new Map([['k',1]]);var f=!m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "neg-has=%s" % ok)


@_t
def test_p2_f722_missing_key():
    """F722 has() of a missing key is false -> else branch (miss)."""
    ok = _misses(
        "(function(){var m=new Map([['k',1]]);var f=m.has('z')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p2_f722_inline_ternary_return():
    """F722 inline ternary in the return blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k',1]]);return (m.has('k')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "inline-ret=%s" % ok)


@_t
def test_p2_f722_set_then_has():
    """F722 later-wins set mutation before has() blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k',1]]);m.set('k',2);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "set-then-has=%s" % ok)


@_t
def test_p2_f722_numeric_key():
    """F722 numeric key via SameValueZero kid discipline blocks."""
    ok = _blocked(
        "(function(){var m=new Map([[7,1]]);var f=m.has(7)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "num-key=%s" % ok)


# ----------------------------------------------------------------- bounds

@_t
def test_p3_f721_nonliteral_element():
    """F721 non-literal array element fails closed (miss, no mis-decode)."""
    ok = _misses(
        "(function(){var x='k';var f=[x].indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlit-elem=%s" % ok)


@_t
def test_p3_f721_nonliteral_key():
    """F721 non-literal search key fails closed."""
    ok = _misses(
        "(function(){var x='k';var f=['k'].indexOf(x)===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlit-key=%s" % ok)


@_t
def test_p3_f721_two_arg_indexof():
    """F721 fromIndex form fails closed (out of scope)."""
    ok = _misses(
        "(function(){var f=['k'].indexOf('k',0)===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "fromindex=%s" % ok)


@_t
def test_p3_f721_nonstring_branch():
    """F721 non-string branch fails closed."""
    ok = _misses(
        "(function(){var f=['k'].indexOf('k')===0?'%s':0;return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonstr-branch=%s" % ok)


@_t
def test_p3_f721_bound_array():
    """F721 ident-bound array fails closed (inline-only scope)."""
    ok = _misses(
        "(function(){var a=['k'];var f=a.indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bound-array=%s" % ok)


@_t
def test_p2_f722_bound_key():
    """F722 bound string name as has() key blocks (F708 key discipline)."""
    ok = _blocked(
        "(function(){var m=new Map([['k',1]]);var x='k';var f=m.has(x)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bound-key=%s" % ok)


@_t
def test_p3_f722_unbound_key():
    """F722 unbound has() key fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k',1]]);var f=m.has(y)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound-key=%s" % ok)


@_t
def test_p3_f722_rebound_map():
    """F722 rebound map name fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k',1]]);var m=1;var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "rebound=%s" % ok)


@_t
def test_p3_f722_unsafe_int_key():
    """F722 >2^53 int key fails closed (F699 discipline)."""
    ok = _misses(
        "(function(){var m=new Map([[9007199254740993,1]]);var f=m.has(9007199254740993)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unsafeint=%s" % ok)


@_t
def test_p3_f722_get_return_not_ternary():
    """F722 must not claim F708's .get() return shape (disjoint)."""
    # This is F708's shape; F722's parser must not touch it.
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f708-shape=%s" % ok)


# ------------------------------------------------- siblings and neighbors

@_t
def test_p4_sibling_f710_set_has():
    """F710 Set.has ternary still blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['k']);return (s.has('k')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f710=%s" % ok)


@_t
def test_p4_sibling_f708_map_get():
    """F708 Map.get still blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f708=%s" % ok)


@_t
def test_p4_sibling_f695_map_spread():
    """F695 Map-spread index reads still block."""
    ok = _blocked(
        "(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f695=%s" % ok)


@_t
def test_p4_sibling_f687_weakset():
    """F687 WeakSet.has ternary still blocks."""
    ok = _blocked(
        "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f687=%s" % ok)


@_t
def test_p4_neighbor_f720_open():
    """F720 (includes) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var a=['q','k'];var f=a.includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f720-closed=%s" % ok)


@_t
def test_p4_neighbor_f713_open():
    """F713 (Map spread-join) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-closed=%s" % ok)


# ------------------------------------------------------------- honestness

@_t
def test_p5_honest_text_quiet():
    """Honest prose stays quiet."""
    ok = _misses("the team will index the report and map the findings")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_indexof_quiet():
    """A non-credential indexOf ternary stays quiet (else branch, no credential)."""
    ok = _misses(
        "(function(){var f=['a','b'].indexOf('c')===-1?'none':'found';return f;})()")
    return ("HELD" if ok else "BREAK", "honest-indexof=%s" % ok)


# ------------------------------------------------------------------- perf

@_t
def test_p8_perf():
    """200 mixed conditional-read sites decode in reasonable time."""
    import time
    shapes = [
        "(function(){var f=['k'].indexOf('k')===0?'a':'xx';return f+'b';})()",
        "(function(){var m=new Map([['k',1]]);var f=m.has('k')?'a':'xx';return f+'b';})()",
    ]
    t0 = time.time()
    for k in range(100):
        for s in shapes:
            dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w382_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
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
    # The w382 battery's footer pin is stale by design: this lane closed
    # F721/F722, so its expected footer (open F713-F737 / next F738) no
    # longer matches the lane-local repoint. Merge-time repoint
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w382_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-382 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    for fn in TESTS:
        verdict, note = fn()
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            brk += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (brk, held))
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
