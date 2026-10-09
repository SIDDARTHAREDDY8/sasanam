#!/usr/bin/env python3
"""Close battery for F746 + F747 (wave-384 lane 5).

F746 (LOW, attack round 51): class extends builtin construction --
`class M extends Map{}` with `new M()` / `new M([[k,v],...])`
spreads node-exactly while the decoder produced zero variants.
Closed by `_js_parse_f746_subclass_map_iife` (gov/dlp.py, hooked
after F712): the class declaration binds M as a Map subclass
(empty body only); `new M(ARGS?)` constructs with the F563
entries discipline; `m.set('K','V');` mutates later-wins; the
return is `[...m.values()].join('SEP')` or a for-of accumulator.

F747 (LOW, attack round 51): F647 residual -- missing-key
nullish-LEFT (`o.x` on a tracked literal whose keyset provably
excludes the key reads undefined, so `??` picks RIGHT) and the
`??=` logical assignment. Closed by
`_js_parse_f747_nullish_right_iife` (gov/dlp.py, hooked after
F647): var/let bindings track nullish / string / restricted
object literals; `??` picks RIGHT exactly when the extended LEFT
is provably nullish (node-exact); `??=` assigns exactly when the
current binding is nullish.

Prints BREAK on any regression. Standalone: 0 BREAK expected.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

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


# ------------------------------------------------------------- controls

TAXONOMY_PIN = 2144  # Wave-385: pin 2143 -> 2144


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f746_s1():
    """F746 filed shape 1 (subclass + set + values spread) blocks."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M();"
        "m.set('k','%s');return [...m.values()].join('')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f746-s1=%s" % ok)


@_t
def test_p1_f746_s2():
    """F746 filed shape 2 (subclass + entries arg + for-of) blocks."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M([['k','%s']]);"
        "var s='';for(var v of m.values())s+=v;return s+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f746-s2=%s" % ok)


@_t
def test_p1_f747_s1():
    """F747 filed shape 1 (missing-key nullish-LEFT) blocks."""
    ok = _blocked(
        "(function(){var o={};return (o.x??'%s')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f747-s1=%s" % ok)


@_t
def test_p1_f747_s2():
    """F747 filed shape 2 (statement nullish pick) blocks."""
    ok = _blocked(
        "(function(){var x=null;var y=x??'%s';return y+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f747-s2=%s" % ok)


# ------------------------------------------------------ generalizations (p2)

@_t
def test_p2_f746_multi_entry_join():
    """Subclass entries arg with a non-empty join separator."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M("
        "[['a','%s'],['b','%s']]);return [...m.values()].join('-');})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "multi-join=%s" % ok)


@_t
def test_p2_f746_set_overwrite():
    """Later .set wins (node-exact)."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M();"
        "m.set('k','zz');m.set('k','%s');"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "set-overwrite=%s" % ok)


@_t
def test_p2_f746_let_const_decl():
    """let/const map bindings decode."""
    ok = _blocked(
        "(function(){class M extends Map{}let m=new M();"
        "m.set('k','%s');return [...m.values()].join('')+'%s';})()"
        % (_A, _B))
    ok2 = _blocked(
        "(function(){class M extends Map{}const m=new M([['k','%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_f746_numeric_key():
    """Numeric-literal keys keep SameValueZero identity."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M([[1,'%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "numkey=%s" % ok)


@_t
def test_p2_f746_braced_forof():
    """Braced for-of body decodes."""
    ok = _blocked(
        "(function(){class M extends Map{}var m=new M([['k','%s']]);"
        "var s='';for(var v of m.values()){s+=v;}return s+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "braced=%s" % ok)


@_t
def test_p2_f747_augassign_ident():
    """`x ??=` assigns exactly when nullish (node-exact)."""
    ok = _blocked(
        "(function(){var x=null;x??='%s';return x+'%s';})()"
        % (_A, _B))
    ok2 = _misses(
        "(function(){var x='g';x??='%s';return x+'%s';})()"
        % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "augassign=%s" % ok)


@_t
def test_p2_f747_augassign_member():
    """`o.x ??=` installs a missing key, no-ops on a present key."""
    ok = _blocked(
        "(function(){var o={};o.x??='%s';return o.x+'%s';})()"
        % (_A, _B))
    ok2 = _misses(
        "(function(){var o={y:'g'};o.y??='%s';return o.y+'%s';})()"
        % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "augassign-member=%s" % ok)


@_t
def test_p2_f747_present_key_picks_left():
    """Present-key LEFT is non-nullish: `??` picks LEFT (node-exact)."""
    ok = _blocked(
        "(function(){var o={a:'%s'};return (o.a??'xx')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "present-left=%s" % ok)


@_t
def test_p2_f747_bracket_missing_key():
    """Bracket-string missing-key read picks RIGHT."""
    ok = _blocked(
        "(function(){var o={};return (o['k']??'%s')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_f747_bound_ident_frag():
    """Bound-ident FRAG `(o.q ?? p)` decodes (node-exact)."""
    ok = _blocked(
        "(function(){var o={};var p='%s';return (o.q??p)+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "ident-frag=%s" % ok)


@_t
def test_p2_f747_void_left():
    """`void 0` LEFT picks RIGHT (F647 form in the new grammar)."""
    ok = _blocked(
        "(function(){var x=void 0;var y=x??'%s';return y+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "void-left=%s" % ok)


# -------------------------------------------------------------- bounds (p3)

@_t
def test_p3_f746_bound_nonempty_body():
    """Non-empty class body fails closed."""
    ok = _misses(
        "(function(){class M extends Map{getx(){return 1;}}"
        "var m=new M();return 'zz';})()")
    return ("HELD" if ok else "BREAK", "nonempty-body=%s" % ok)


@_t
def test_p3_f746_bound_nonmap_super():
    """Non-Map superclass fails closed."""
    ok = _misses(
        "(function(){class M extends Set{}var m=new M();return 'zz';})()")
    return ("HELD" if ok else "BREAK", "nonmap-super=%s" % ok)


@_t
def test_p3_f746_bound_set_nonstring():
    """Non-string .set value fails closed."""
    ok = _misses(
        "(function(){class M extends Map{}var m=new M();"
        "m.set('k',123);return 'zz';})()")
    return ("HELD" if ok else "BREAK", "set-nonstr=%s" % ok)


@_t
def test_p3_f746_bound_keys_iter():
    """`.keys()` iteration is unmodeled: fails closed."""
    ok = _misses(
        "(function(){class M extends Map{}var m=new M();"
        "return [...m.keys()].join('');})()")
    return ("HELD" if ok else "BREAK", "keys-iter=%s" % ok)


@_t
def test_p3_f746_bound_join_noarg():
    """`.join()` without a separator fails closed (engine joins ',')."""
    ok = _misses(
        "(function(){class M extends Map{}var m=new M();"
        "return [...m.values()].join();})()")
    return ("HELD" if ok else "BREAK", "join-noarg=%s" % ok)


@_t
def test_p3_f746_bound_set_on_other():
    """`.set` on another receiver fails closed."""
    ok = _misses(
        "(function(){class M extends Map{}var m=new M();var n=new Map();"
        "n.set('k','a');return 'zz';})()")
    return ("HELD" if ok else "BREAK", "set-other=%s" % ok)


@_t
def test_p3_f747_bound_proto_member():
    """Proto-member key reads fail closed (not undefined)."""
    ok = _misses(
        "(function(){var o={};return (o.toString??'%s')+'%s';})()"
        % (_A, _B))
    ok2 = _misses(
        "(function(){var o={};return (o['__proto__']??'%s')+'%s';})()"
        % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "proto=%s" % ok)


@_t
def test_p3_f747_bound_proto_key_literal():
    """`__proto__` as a literal key fails closed."""
    ok = _misses(
        "(function(){var o={__proto__:'a'};return 'zz';})()")
    return ("HELD" if ok else "BREAK", "proto-lit=%s" % ok)


@_t
def test_p3_f747_bound_augassign_unbound():
    """`??=` on an unbound ident fails closed (ReferenceError)."""
    ok = _misses("(function(){var x=null;y??='a';return 'zz';})()")
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_f747_bound_missing_key_read_term():
    """A missing-key read as a bare return term fails closed."""
    ok = _misses("(function(){var o={};return o.x+'zz';})()")
    return ("HELD" if ok else "BREAK", "missing-term=%s" % ok)


@_t
def test_p3_f747_bound_const():
    """`const` bindings fail closed."""
    ok = _misses("(function(){const x=null;return (x??'a')+'zz';})()")
    return ("HELD" if ok else "BREAK", "const=%s" % ok)


@_t
def test_p3_f747_bound_rebind():
    """Rebinding fails closed (conservative)."""
    ok = _misses(
        "(function(){var x=null;var x='a';return (x??'b')+'zz';})()")
    return ("HELD" if ok else "BREAK", "rebind=%s" % ok)


# ------------------------------------------- siblings still block (p4)

@_t
def test_p4_sibling_f712():
    """F712 plain-Map values spread still blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f712=%s" % ok)


@_t
def test_p4_sibling_f708():
    """F708 Map.get still blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);"
        "return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f708=%s" % ok)


@_t
def test_p4_sibling_f647():
    """F647 nullish groups still block."""
    ok = _blocked("(function(){return (null??'%s')+'%s';})()" % (_A, _B))
    ok2 = _blocked("(function(){var z;return (z??'%s')+'%s';})()" % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "f647=%s" % ok)


@_t
def test_p4_sibling_f669():
    """F669 Set spread still blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['%s']);s.add('%s');"
        "return [...s].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669=%s" % ok)


# ------------------------------------------- open neighbors still miss (p4b)

@_t
def test_p4b_neighbor_f745_now_closed():
    """F745 (Set.prototype.union) now blocks (closed wave-384 lane 4)."""
    ok = _blocked(
        "(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
        "return [...a.union(b)].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f745-closed=%s" % ok)


@_t
def test_p4b_neighbor_f748_now_closed():
    """F748 (||= / &&=) now blocks (closed wave-384 lane 6)."""
    ok = _blocked(
        "(function(){var x;x||='%s';x+='%s';return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f748-closed=%s" % ok)


# ------------------------------------------------------------- honest (p5)

@_t
def test_p5_honest_quiet():
    """Honest subclass / nullish code stays quiet."""
    ok = _misses("class M extends Map {}")
    ok2 = _misses("(function(){var o={};return (o.x??'dflt')+'!';})()")
    ok3 = _misses("(function(){var x=null;x??='dflt';return x;})()")
    return ("HELD" if (ok and ok2 and ok3) else "BREAK",
            "honest=%s,%s,%s" % (ok, ok2, ok3))


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ---------------------------------------------------------------- perf (p8)

@_t
def test_p8_perf():
    """200 mixed sites decode quickly (F452 budget intact)."""
    t0 = time.time()
    for _ in range(50):
        _blocked("(function(){class M extends Map{}var m=new M();"
                 "m.set('k','ab');return [...m.values()].join('');})()")
        _blocked("(function(){var o={};return (o.x??'ab')+'cd';})()")
        _misses("(function(){class M extends Set{}"
                "var m=new M();return 'zz';})()")
        _misses("(function(){var o={};return (o.toString??'ab');})()")
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ---------------------------------------------------------- green check (p9)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree. The
    # w383_attack battery must show 0 BREAK with the F746/F747
    # pins flipped to closed (footer repointed at wave-384 merge).
    for batt, expect_break in (("evals/w383_f746_redfirst.py", 0),
                               ("evals/w383_f747_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p9_green_check():
    """Depth-1 green check: F746/F747 red-firsts + wave-383 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
