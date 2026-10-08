#!/usr/bin/env python3
"""Wave-373 lane 2: close F606, F610 (URLSearchParams mutation family).

F606 (LOW, filed 2026-10-08 by wave-372 lane 3 as a spec-axis residual
of the F599 closure): F599 (CLOSED) models `.append`/`.set`
statement-form mutations with a getAll terminal but fails the whole
shape closed on any other mutation statement, so one-token neighbors
node-yield the exact credential (v24.20.0) while the decoder produced
zero variants: `.sort()` / `.delete('N')` mutations before the getAll
terminal, and an `if(p.has('N')){...}`-guarded getAll terminal.

F610 (LOW, filed 2026-10-07 by wave-372 lane 7 attack round 40 as F609,
renumbered per wave-272 -- lane 3 filed F606 first at 02:24 UTC, attack
at 02:48 UTC): F599 models append/set mutations with a getAll
terminal and F576 (CLOSED) models `.get` on constructor strings, but a
set() mutation read back via `.get()` is a different read path --
set() OVERWRITES (first N-pair takes the value, other N-pairs dropped)
while get() returns the FIRST value: the filed shapes node-evaluate
to the exact credential while the decoder produced zero variants.
Verified still missing on the F599-closed lane tree (wave-372 merge
re-verified the composition), so it survived F599's closure.

Closure (gov/dlp.py, zero new re.compile):
- new `_js_parse_f606_params_mutation2_iife`: statement-form IIFE
  with append/set/sort/delete mutations (sort: UTF-16 code-unit
  order, stable, BMP-guarded; delete: drops every N-pair) and a
  getAll terminal, or the has-guarded form
  `if(p.has('N')){return p.getAll('K')<postfix>;}return 'LIT';`
  (guard evaluated statically -- node-exact on both branches).
- new `_js_parse_f610_params_setget_iife`: statement-form IIFE with
  append/set mutations and a `return p.get('K')<postfix>[+'LIT']*;`
  terminal (get of a missing name fails closed -- the `null+'x'`
  coercion is out of scope).
Both dispatch after F599 in `_js_parse_primary`; F599/F606 fail
closed on each other's terminals, so no previously-decoded input
changes behavior.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g373-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (grep-verified).  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    # fail-closed boundary: decoder must NOT flag (no variants).
    return dlp.find_credential(payload) is None


def _decode(expr):
    r = dlp._try_js_expr_decode(expr, 0)
    return r[0] if r is not None else None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer -- open F612-F615, F618-F621 / next F622 (wave-374 lane 5)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 5: F621 FILED OPEN  # Wave-374 lane 5: F616, F617 CLOSED; F621 FILED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 lane 5: F616, F617 CLOSED  # Wave-374 lane 5: F621 FILED OPEN  # Wave-374 lane 5: F616, F617 CLOSED; F621 FILED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------------- F606 filed shapes now decode (must block)

@_t
def test_p1_f606_sort():
    """F606 filed shape 1: sort() mutation before getAll blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=%s');"
                   "p.append('q','%s');p.sort();"
                   "return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f606_delete():
    """F606 filed shape 2: delete() mutation before getAll blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('a=1&q=%s');"
                   "p.append('q','%s');p.delete('a');"
                   "return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f606_hasguard():
    """F606 filed shape 3: if(p.has())-guarded getAll blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=%s');"
                   "p.append('q','%s');if(p.has('q')){"
                   "return p.getAll('q').join('');}return '';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------------- F610 filed shapes now decode (must block)

@_t
def test_p1_f610_ctor():
    """F610 filed shape 1: set() then .get() blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=xx');"
                   "p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f610_empty():
    """F610 filed shape 2: empty-constructor twin blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('');"
                   "p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f610_const():
    """F610 filed shape 3: const twin blocks."""
    hit = _blocked("(function(){const p=new URLSearchParams('q=zz');"
                   "p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- variants (node-exact values)

@_t
def test_p2_sort_orders():
    """sort() orders pairs by name (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('b=1&a=2');"
                  "p.sort();return p.getAll('a').join('');})()")
    return ("HELD" if got == "2" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_sort_stable():
    """sort() is stable for equal names (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('b=1&a=2&b=3');"
                  "p.sort();return p.getAll('b').join('');})()")
    return ("HELD" if got == "13" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_sort_bracket():
    """Bracket member form p['sort']() decodes (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('b=1&a=2');"
                  "p['sort']();return p.getAll('a').join('');})()")
    return ("HELD" if got == "2" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_delete_multi():
    """delete() drops every pair with the name (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('a=1&a=2&b=3');"
                  "p.delete('a');return p.getAll('b').join('');})()")
    return ("HELD" if got == "3" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_delete_other_key():
    """delete() of another key leaves the read key intact."""
    got = _decode("(function(){var p=new URLSearchParams('a=1&q=AA');"
                  "p.delete('a');return p.getAll('q').join('!');})()")
    return ("HELD" if got == "AA" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_hasguard_false():
    """has() false takes the fallthrough branch (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('a=1');"
                  "if(p.has('b')){return p.getAll('b').join('');}"
                  "return 'X';})()")
    return ("HELD" if got == "X" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_hasguard_bracket():
    """Bracket member form p['has']() decodes (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('q=AA');"
                  "p.append('q','BB');if(p['has']('q')){"
                  "return p.getAll('q').join('');}return '';})()")
    return ("HELD" if got == "AABB" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f610_set_missing_appends():
    """set() on a missing name appends (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('a=1');"
                  "p.set('b','2');return p.get('b')+'!';})()")
    return ("HELD" if got == "2!" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f610_set_first_only():
    """set() replaces only the first pair (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('a=1&a=2');"
                  "p.set('a','9');return p.get('a');})()")
    return ("HELD" if got == "9" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f610_append_then_set():
    """append() then set() composes node-exactly."""
    got = _decode("(function(){var p=new URLSearchParams('q=xx');"
                  "p.append('q','yy');p.set('q','AA');"
                  "return p.get('q')+'!';})()")
    return ("HELD" if got == "AA!" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f610_double_tail():
    """Two literal additive tails compose (node-exact)."""
    got = _decode("(function(){var p=new URLSearchParams('q=xx');"
                  "p.set('q','A');return p.get('q')+'B'+'C';})()")
    return ("HELD" if got == "ABC" else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f610_let():
    """let-bound twin decodes (node-exact)."""
    got = _decode("(function(){let p=new URLSearchParams('q=xx');"
                  "p.set('q','Q');return p.get('q')+'!';})()")
    return ("HELD" if got == "Q!" else "BREAK", "got=%r" % (got,))


# ------------------------------------------------- fail-closed bounds (must stay quiet)

@_t
def test_b1_sort_with_arg():
    """sort('x') -- non-zero-arg sort fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "p.sort('x');return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b2_delete_nonliteral():
    """delete(x) -- non-literal name fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "p.delete(x);return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b3_guard_else():
    """else-clause on the has-guard fails closed (documented residual)."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "if(p.has('q')){return p.getAll('q').join('');}"
                "else{return '';}return '';})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b4_guard_other_ident():
    """if-guard on another ident fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');var r=p;"
                "if(r.has('q')){return p.getAll('q').join('');}"
                "return '';})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b5_bare_has_statement():
    """Bare p.has('q'); mutation statement fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "p.has('q');return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b6_named_function():
    """Named function IIFE fails closed."""
    ok = _quiet("(function foo(){var p=new URLSearchParams('q=AA');"
                "p.sort();return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b7_mutation_nonliteral_value():
    """Non-literal mutation value fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "p.append('q',x);return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b8_get_missing_name():
    """get() of a missing name fails closed (null coercion out of scope)."""
    ok = _quiet("(function(){var p=new URLSearchParams('a=1');"
                "p.set('b','2');return p.get('z')+'!';})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b9_sort_get_hybrid():
    """sort() mutation with a .get() terminal fails closed (honest residual)."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=AA');"
                "p.sort();return p.get('q')+'!';})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b10_tail_nonliteral():
    """Non-literal additive tail fails closed."""
    ok = _quiet("(function(){var p=new URLSearchParams('q=xx');"
                "p.set('q','AA');return p.get('q')+x;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_b11_url_binding():
    """new URL(...).searchParams with a sort() mutation fails closed.

    Wave-374 lane 5 (F617 CLOSED): the searchParams receiver itself is
    now modeled, but sort() on it is a documented F617 residual --
    this probe pins that the sort hybrid stays quiet.
    """
    ok = _quiet("(function(){var p=new URL('http://x/?q=AA');"
                "p.searchParams.sort();"
                "return p.searchParams.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------- compositions (neighbors unaffected)

@_t
def test_p3_f599_still_blocks():
    """F599 (CLOSED): append/set + getAll still blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=%s');"
                   "p.append('q','%s');return p.getAll('q').join('');})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p3_f576_still_blocks():
    """F576 (CLOSED): .get on constructor strings still blocks."""
    hit = _blocked("new URLSearchParams('q=%s').get('q')" % _CRED)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p3_f584_still_blocks():
    """F584: .getAll on constructor strings still blocks."""
    hit = _blocked("new URLSearchParams('q=%s&q=%s').getAll('q').join('')"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- node differential (v24.20.0)

_NODE_CASES = [
    ("(function(){var p=new URLSearchParams('q=AA');p.append('q','BB');p.sort();"
     "return p.getAll('q').join('');})()", "AABB"),
    ("(function(){var p=new URLSearchParams('a=1&q=AA');p.append('q','BB');"
     "p.delete('a');return p.getAll('q').join('');})()", "AABB"),
    ("(function(){var p=new URLSearchParams('q=AA');p.append('q','BB');"
     "if(p.has('q')){return p.getAll('q').join('');}return '';})()", "AABB"),
    ("(function(){var p=new URLSearchParams('q=xx');p.set('q','AA');"
     "return p.get('q')+'BB';})()", "AABB"),
    ("(function(){var p=new URLSearchParams('b=1&a=2');p.sort();"
     "return p.getAll('a').join('');})()", "2"),
    ("(function(){var p=new URLSearchParams('b=1&a=2&b=3');p.sort();"
     "return p.getAll('b').join('');})()", "13"),
    ("(function(){var p=new URLSearchParams('a=1&a=2&b=3');p.delete('a');"
     "return p.getAll('b').join('');})()", "3"),
    ("(function(){var p=new URLSearchParams('a=1');"
     "if(p.has('b')){return p.getAll('b').join('');}return 'X';})()", "X"),
    ("(function(){var p=new URLSearchParams('a=1');p.set('b','2');"
     "return p.get('b')+'!';})()", "2!"),
    ("(function(){var p=new URLSearchParams('a=1&a=2');p.set('a','9');"
     "return p.get('a');})()", "9"),
]


@_t
def test_p4_node_differential():
    """node v24.20.0 differential: 10/10 decoder==engine."""
    import json as _json
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as f:
        _json.dump([c for c, _ in _NODE_CASES], f)
        path = f.name
    p = subprocess.run(["node", "-e",
                        "const fs=require('fs');"
                        "const cs=JSON.parse(fs.readFileSync(%r,'utf8'));"
                        "for(const c of cs){try{"
                        "console.log(JSON.stringify(eval(c)))}"
                        "catch(e){console.log('THREW')}}" % path],
                       capture_output=True, text=True, timeout=60)
    os.unlink(path)
    node_vals = (p.stdout or "").splitlines()
    bad = 0
    for (case, want), nv in zip(_NODE_CASES, node_vals):
        got = _decode(case)
        nv_val = nv[1:-1] if nv.startswith('"') else nv
        if got != want or nv_val != want:
            bad += 1
    return ("HELD" if bad == 0 and len(node_vals) == len(_NODE_CASES)
            else "BREAK",
            "diff=%d/%d" % (len(_NODE_CASES) - bad, len(_NODE_CASES)))


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-372 attack battery with
    GOV_SKIP_GREEN=1 in the child env. Tolerated: its stale footer pin
    (the lane-local footer now closes F606/F610; the merge repoints it --
    wave-305/331 class). The battery's F610 probe is flipped by this
    lane to test_p1_f610_closed -- a BREAK there is a real
    regression, not tolerated."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g373-2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w372_attack_probes.py")],
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
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w372_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-372 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001
            status, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        elif status == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        sys.exit(0)
    sys.exit(main())
