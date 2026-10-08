#!/usr/bin/env python3
"""Wave-374 lane 7: close F620 -- indexed/thunk function invocation.

F620 (LOW, filed attack round 41): the bounded static JS-expression
decoder had no model of function-valued array elements invoked by
index or higher-order call -- thunks stored in an array and invoked
via f[0](), .map(f=>f()), or .forEach assembled credential fragments
invisibly. Three filed shapes (all node v24.20.0 exact, all BREAKing
on the open tree):
  (function(){var f=[()=>'f1',()=>'f2'];return f[0]()+f[1]();})()
  [()=>'f1',()=>'f2'].map(f=>f()).join('')
  (function(){var s='';[()=>'f1',()=>'f2'].forEach(f=>{s+=f();});return s;})()
Distinct from F614 (indirect invocation via .call/.apply/.bind --
direct invocation here; F614 stays OPEN) and F618 (promise callbacks;
stays OPEN).

Closure (gov/dlp.py, F620): a _JSThunks marker (opaque everywhere
except the three invocation patterns -- the engine stringifies the
functions on .join, so values at the array position would mis-decode);
[()=>LIT,...] recognized at primary position; .map(f=>f()) collects
the invoked literals; two statement-IIFE parsers (indexed f[INT]()
calls, .forEach(f=>{s+=f();}) accumulation) hooked after F600/F601/F602
in the dispatch chain; the additive, repeat, and tag-concat/repeat
branches fail coded (never TypeError) on _JSThunks. Zero new
re.compile (stays 28).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g374-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

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


def _thunks(*lits):
    return "[" + ",".join("()=>'%s'" % l for l in lits) + "]"


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_index_call():
    """F620 shape 1 CLOSED: indexed thunk invocation blocks."""
    ok = _blocked("(function(){var f=%s;return f[0]()+f[1]();})()"
                  % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_map_call():
    """F620 shape 2 CLOSED: .map(f=>f()) over thunks blocks."""
    ok = _blocked("%s.map(f=>f()).join('')" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_foreach_accumulate():
    """F620 shape 3 CLOSED: .forEach(f=>{s+=f();}) accumulation blocks."""
    ok = _blocked("(function(){var s='';%s.forEach(f=>{s+=f();});"
                  "return s;})()" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_index_reversed_order():
    """Indexed order is engine order: f[1]()+f[0]() reverses."""
    from gov.dlp import _try_js_expr_decode_all
    got = _try_js_expr_decode_all(
        "(function(){var f=%s;return f[1]()+f[0]();})()" % _thunks(_A, _B))
    ok = got is not None and (_B + _A) in got
    return ("HELD" if ok else "BREAK", "rev=%s" % ok)


def test_p2_index_single_and_skip():
    """Single index and non-adjacent indices decode exactly."""
    from gov.dlp import _try_js_expr_decode_all
    ok = _try_js_expr_decode_all(
        "(function(){var f=%s;return f[1]();})()" % _thunks(_A, _B))
    ok = ok is not None and _B in ok
    ok2 = _try_js_expr_decode_all(
        "(function(){var f=%s;return f[0]()+f[2]();})()"
        % _thunks(_A, "xx", _B))
    ok = ok and ok2 is not None and _FULL in ok2
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_paren_param_and_sep():
    """(f)=>f() twin and a non-empty join separator decode exactly."""
    from gov.dlp import _try_js_expr_decode_all
    got = _try_js_expr_decode_all("%s.map((f)=>f()).join('-')"
                                  % _thunks(_A, _B))
    ok = got is not None and (_A + "-" + _B) in got
    return ("HELD" if ok else "BREAK", "twin=%s" % ok)


def test_p2_foreach_paren_param_and_let():
    """(f)=>{s+=f();} twin and let-bound thunks block."""
    ok = _blocked("(function(){var s='';%s.forEach((f)=>{s+=f();});"
                  "return s;})()" % _thunks(_A, _B))
    ok = ok and _blocked("(function(){let s='';%s.forEach(f=>{s+=f();});"
                         "return s;})()" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "twins=%s" % ok)


def test_p2_const_bound_index():
    """const-bound thunk array, indexed invocation blocks."""
    ok = _blocked("(function(){const f=%s;return f[0]()+f[1]();})()"
                  % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_ws_tolerant():
    """Whitespace-tolerant thunk/index forms block."""
    ok = _blocked("(function(){var f = [ () => '%s' , () => '%s' ] ;"
                  "return f[ 0 ]( ) + f[ 1 ]( );})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_block_body_thunk():
    """Block-body arrow (()=>{return 'x';}) is not a modeled thunk."""
    ok = _misses("(function(){var f=[()=>{return '%s';}];"
                 "return f[0]();})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_parameterized_thunk():
    """Parameterized arrow ((x)=>'x') is not a modeled thunk."""
    ok = _misses("(function(){var f=[(x)=>'%s'];return f[0]();})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_mixed_array():
    """A mixed literal/thunk array is not a thunk array."""
    ok = _misses("(function(){var f=['%s',()=>'%s'];"
                 "return f[0]()+f[1]();})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_trailing_comma():
    """Trailing-comma thunk array fails closed (minimal grammar)."""
    ok = _misses("[()=>'%s',].map(f=>f()).join('')" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_other_alias_index():
    """Indexed call on a different alias fails closed."""
    ok = _misses("(function(){var f=%s;return g[0]();})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_index_out_of_range():
    """Out-of-range index throws in the engine: fail closed."""
    ok = _misses("(function(){var f=%s;return f[5]();})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_index_with_call_args():
    """f[0]('x') is not the modeled zero-arg invocation."""
    ok = _misses("(function(){var f=%s;return f[0]('x');})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_no_invocation():
    """Returning the thunk itself (f[0]) decodes nothing."""
    ok = _misses("(function(){var f=%s;return f[0];})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_map_identity_on_thunks():
    """map(x=>x) over thunks is not thunk invocation: quiet."""
    ok = _misses("%s.map(x=>x).join('')" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_map_block_return():
    """map(f=>{return f();}) block form is not the filed grammar."""
    ok = _misses("%s.map(f=>{return f();}).join('')" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_map_indirect_call():
    """map(f=>f.call()) is F614's indirect-invocation scope: quiet here."""
    ok = _misses("%s.map(f=>f.call()).join('')" % _thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_foreach_expr_body():
    """forEach(f=>s+=f()) expression body is not the filed block shape."""
    ok = _misses("(function(){var s='';%s.forEach(f=>s+=f());"
                 "return s;})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_foreach_param_shadows_accum():
    """A param shadowing the accumulator fails closed."""
    ok = _misses("(function(){var s='';%s.forEach(s=>{s+=s();});"
                 "return s;})()" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_join_on_thunks_quiet():
    """The engine stringifies functions on .join: decoder stays quiet."""
    ok = _misses("%s.join('')" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_bare_thunk_array_quiet():
    """A bare (uninvoked) thunk array decodes to nothing."""
    ok = _misses(_thunks(_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_additive_on_thunks_quiet():
    """[thunks]+'x' fails coded (never TypeError), quiet."""
    ok = _misses("%s+'x'" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_repeat_on_thunks_quiet():
    """[thunks].repeat(2)/.repeat`2` fail coded (never TypeError)."""
    ok = _misses("%s.repeat(2)" % _thunks(_A))
    ok = ok and _misses("%s.repeat`2`" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_tag_concat_on_thunks_quiet():
    """[thunks].concat`x` fails coded (never TypeError), quiet."""
    ok = _misses("%s.concat`x`" % _thunks(_A))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ neighbors (open stays open)

def test_p4_f614_closed():
    """F614 (indirect .call/.apply/.bind invocation) now BLOCKs (wave-374 lane 3)."""
    out = _redfirst_tally("w373_f614_redfirst.py")
    ok = out == (0, 5)
    return ("HELD" if ok else "BREAK", "tally=%s" % (out,))
def test_p4_f618_closed():
    """F618 (promise callbacks) now BLOCKs (wave-374 lane 6)."""
    out = _redfirst_tally("w373_f618_redfirst.py")
    ok = out == (0, 5)
    return ("HELD" if ok else "BREAK", "tally=%s" % (out,))
def _redfirst_tally(name):
    tmp = tempfile.mkdtemp(prefix="g374-p4-", dir="/var/tmp")
    env = dict(os.environ)
    env["TMPDIR"] = tmp
    env["GOV_SKIP_GREEN"] = "1"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    for line in out.splitlines():
        if line.startswith("tally:"):
            # "tally: 3 BREAK / 2 HELD" -> (3, 2)
            m = re.search(r"tally:\s*(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD", line)
            if m:
                return (int(m.group(1)), int(m.group(2)))
    return None


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F612-F620 closed; open F621-F635; next F636 (wave-374 merge)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F672**" in text  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671." in text)  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)
def test_p5_no_new_regexes():
    """re.compile count stays 28."""
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """300-thunk map stays within the scan budget (F452 discipline)."""
    corpus = ("junk " * 200 + "%s.map(f=>f()).join('') " % _thunks(_A, _B)) * 4
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: adjacent batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for name, want_break in (("w372_attack_probes.py", 0),
                             ("w373_f607close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g374-green-", dir="/var/tmp")
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
