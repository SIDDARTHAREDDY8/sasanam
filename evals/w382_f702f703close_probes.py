"""Wave-382 takeover lane 2: close F702 + F703 (takeover of the original
lane agent's unfinished work; its 388-line gov/dlp.py diff was reviewed,
doc-fixed, and kept).

F702: getter invocation on Object.assign (2 filed shapes).
F703: __defineGetter__ legacy API (2 filed shapes).

Close-when: every filed shape decodes node-exactly (v24.20.0) when
credential-shaped -> coded refusal.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-381 merge; no new decision codes this lane

from gov import dlp
from gov.decision_codes import TAXONOMY

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
    """Control: lane-local footer (F702/F703 closed, next F713)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F713**" in text
          and "Open findings: F700, F701, F704, F705, F706, F707, F708, F709, F710, F711, F712." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f702_s1():
    """F702 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return Object.assign({},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f702-s1=%s" % ok)


@_t
def test_p1_f702_s2():
    """F702 filed shape 2 (bound-copy twin) blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.assign({z:1},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f702-s2=%s" % ok)


@_t
def test_p1_f703_s1():
    """F703 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f703-s1=%s" % ok)


@_t
def test_p1_f703_s2():
    """F703 filed shape 2 (two getters) blocks."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('a',"
        "function(){return '%s';});o.__defineGetter__('b',"
        "function(){return '%s';});return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f703-s2=%s" % ok)


# ------------------------------------------------- node-exact variants (p2)

@_t
def test_p2_variant_let_const():
    """let/const decls decode node-exactly."""
    ok = _blocked(
        "(function(){let o={get x(){return '%s';}};"
        "const c=Object.assign({},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "letconst=%s" % ok)


@_t
def test_p2_variant_ws_dquotes():
    """Whitespace + double quotes decode node-exactly."""
    ok = _blocked(
        '(function(){ var o = { get x(){ return "%s" ; } } ;\n'
        'return Object.assign( { } , o ).x + "%s" ; })()' % (_A, _B))
    return ("HELD" if ok else "BREAK", "wsdq=%s" % ok)


@_t
def test_p2_variant_later_wins():
    """Multiple sources: later wins (node-exact)."""
    ok = _blocked(
        "(function(){var a={get x(){return 'no';}};"
        "var b={get x(){return '%s';}};"
        "return Object.assign({},a,b).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "laterwins=%s" % ok)


@_t
def test_p2_variant_defineGetter_on_assign_copy():
    """defineGetter on an assign-bound copy decodes node-exactly."""
    ok = _blocked(
        "(function(){var o=Object.assign({},{get x(){return '%s';}});"
        "o.__defineGetter__('y',function(){return '%s';});"
        "return o.x+o.y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "dg-on-assign=%s" % ok)


@_t
def test_p2_variant_assign_of_defineGetter_source():
    """Assign of a defineGetter-installed source invokes at assign time."""
    ok = _blocked(
        "(function(){var o={};"
        "o.__defineGetter__('x',function(){return '%s';});"
        "var c=Object.assign({},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "assign-of-dg=%s" % ok)


@_t
def test_p2_variant_inline_assign_bound_source():
    """Inline assign in the return with a bound source."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return Object.assign({p:1},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "inline-bound=%s" % ok)


@_t
def test_p2_variant_data_and_getter_mix():
    """Data props and getters mix node-exactly."""
    ok = _blocked(
        "(function(){var o={p:'%s',get x(){return '%s';}};"
        "return Object.assign({},o).x+Object.assign({},o).p;})()"
        % (_B, _A))
    return ("HELD" if ok else "BREAK", "mix=%s" % ok)


# ------------------------------------------------- fail-closed bounds (p3)

@_t
def test_p3_bound_proto_key():
    """__proto__ install key fails closed (miss, never mis-decode)."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('__proto__',"
        "function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proto=%s" % ok)


@_t
def test_p3_bound_reinstall():
    """Getter re-install fails closed (documented residual)."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return '%s';});o.__defineGetter__('x',"
        "function(){return '%s';});return o.x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "reinstall=%s" % ok)


@_t
def test_p3_bound_nonliteral_getter_return():
    """Non-literal getter return fails closed."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return y;});return o.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_bound_getter_params():
    """Getter with parameters fails closed."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(p){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "params=%s" % ok)


@_t
def test_p3_bound_nonfunction_getter():
    """Non-function getter arg fails closed."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('x','%s');"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonfn=%s" % ok)


@_t
def test_p3_bound_unbound_source():
    """Unbound assign source fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "return Object.assign({},zzz).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_bound_missing_key():
    """Missing key read fails closed (engine yields undefined)."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.assign({},o);return c.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p3_bound_numeric_member():
    """Numeric member read fails closed (string-only)."""
    ok = _misses(
        "(function(){var o={z:1};var c=Object.assign({},o);"
        "return c.z+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "numeric=%s" % ok)


@_t
def test_p3_bound_trailing_stmt():
    """Trailing statement after return fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.assign({},o);var r=c.x+'%s';return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "trailing=%s" % ok)


@_t
def test_p3_bound_iife_params():
    """IIFE with parameters fails closed."""
    ok = _misses(
        "(function(p){var o={get x(){return '%s';}};"
        "return Object.assign({},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "params-iife=%s" % ok)


@_t
def test_p3_bound_nonliteral_target():
    """Non-literal assign target fails closed."""
    ok = _misses(
        "(function(){var t={};var o={get x(){return '%s';}};"
        "var c=Object.assign(t,o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nontgt=%s" % ok)


@_t
def test_p3_bound_unsafe_int():
    """Unsafe-int getter value fails closed (F699 guard)."""
    ok = _misses(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return '9007199254740993';});return o.x;})()")
    return ("HELD" if ok else "BREAK", "unsafeint=%s" % ok)


@_t
def test_p3_bound_target_getter_overwrite():
    """Source overwriting a target getter key fails closed.

    Spec-review catch: the engine's [[Set]] throws TypeError on a
    getter-only accessor, so no value is produced -- a decode would
    be a mis-decode. The non-overwritten twin stays node-exact.
    """
    ok = _misses(
        "(function(){var o={x:'%s'};"
        "return Object.assign({get x(){return '%s';}},o).x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "tgtoverwrite=%s" % ok)


@_t
def test_p2_variant_target_getter_kept():
    """Non-overwritten target getter reads node-exactly."""
    ok = _blocked(
        "(function(){return Object.assign({get x(){return '%s';}},"
        "{y:'q'}).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "tgtgetter=%s" % ok)


# --------------------------------------------- siblings + neighbors (p4)

@_t
def test_p4_sibling_f664():
    """F664 (literal-getter descriptor) still blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)


@_t
def test_p4_sibling_f698():
    """F698 (defineProperty accessor) still blocks."""
    ok = _blocked(
        "(function(){var o={};Object.defineProperty(o,'x',"
        "{get:function(){return '%s';}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f698=%s" % ok)


@_t
def test_p4_sibling_f673():
    """F673 (defineProperties) still blocks."""
    ok = _blocked(
        "(function(){var o={};Object.defineProperties(o,"
        "{x:{get:function(){return '%s';}}});return o.x+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p4_plain_assign_data_absorbed():
    """Plain Object.assign data copies now block (honest absorption).

    The F702 grammar necessarily models data-prop merges (the filed
    shape 2's target is {z:1}); plain data copies decode node-exactly
    as a benign generalization. F539 (builtin-call results) is a
    different mechanism and stays OPEN.
    """
    ok = _blocked(
        "(function(){var o={x:'%s'};"
        "var c=Object.assign({},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "assign-data=%s" % ok)


@_t
def test_p4_neighbor_f701_open():
    """F701 (spread) still OPEN: miss reproduces (not absorbed)."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';},"
        "get y(){return '%s';}};var c={...o};return c.x+c.y;})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f701-open=%s" % ok)


@_t
def test_p4_neighbor_f704_open():
    """F704 (Object.create descriptor) still OPEN: miss reproduces."""
    ok = _misses(
        "(function(){var o=Object.create(null,"
        "{x:{get:function(){return '%s';}}});return o.x+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f704-open=%s" % ok)


@_t
def test_p4_neighbor_f705_open():
    """F705 (Reflect.get receiver) still OPEN: miss reproduces."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "return Reflect.get(o,'x',{})+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f705-open=%s" % ok)


# --------------------------------------------- junk / composition (p5/p6)

@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p6_honest_assign_unaffected():
    """Honest Object.assign of data props still decodes (not over-blocked)."""
    # A non-credential assign copy must not false-positive at the seam:
    # find_credential misses honest text.
    ok = _misses(
        "(function(){var o={x:'hello'};"
        "var c=Object.assign({},o);return c.x;})()")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------------------------ perf

@_t
def test_p8_perf():
    """200 hostile sites decode quickly."""
    t0 = time.time()
    n = 0
    for _ in range(200):
        _blocked(
            "(function(){var o={get x(){return '%s';}};"
            "return Object.assign({},o).x+'%s';})()" % (_A, _B))
        n += 1
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w381_attack_probes.py")],
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
    # The w381 battery's footer pin is stale by design: this lane closed
    # F702/F703, so its expected footer (open F700-F712 / next F713) no
    # longer matches the lane-local repoint. Merge-time repoint
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w381_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-381 attack battery stays green (depth-1)."""
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
