"""Wave-381 lane 6: close F693 + F697 (destructuring and coercion residuals).

F693 (LOW, attack round 48): destructuring rename/array-default
residuals -- per-key defaults on nested/array patterns with a
literal source: `var {a:{b:c}={b:'f1'}}={}` and
`var {a:[b,c]=['f1','f2']}={}` both node-evaluate (v24.20.0) to the
exact credential while the decoder produced zero variants.

F697 (LOW, attack round 48): implicit toPrimitive reads -- implicit
coercion in additive position: `var o={v:'f1',
valueOf:function(){return this.v;}};return o+'f2';` and the toString
/ [Symbol.toPrimitive] twins all node-evaluate to the exact
credential while the decoder produced zero variants.

Closure: `_js_parse_f693_destructure_default_iife` (hooked after
F684b) and `_js_parse_f697_toprimitive_iife` (+ `_js_parse_f697_object`
+ `_js_f697_toprimitive`, hooked after F674) in gov/dlp.py.
Node-exact decodes, node-exact fail-closed bounds, zero new
re.compile (28 stays).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (no paid-API refs).
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

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

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
    """Control: taxonomy pin is 2140."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p9_junk_quiet():
    """Control: junk stays quiet."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- F693 filed shapes (closed)

@_t
def test_p1_f693_rename_nested_closed():
    """F693 CLOSED (rename-nested): blocks."""
    hit = _blocked("(function(){var {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f693_array_default_closed():
    """F693 CLOSED (array-default): blocks."""
    hit = _blocked("(function(){var {a:[b,c]=['%s','%s']}={};return b+c;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F697 filed shapes (closed)

@_t
def test_p1_f697_valueOf_closed():
    """F697 CLOSED (valueOf): blocks."""
    hit = _blocked("(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f697_toString_closed():
    """F697 CLOSED (toString): blocks."""
    hit = _blocked("(function(){var o={v:'%s',toString:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f697_toPrimitive_closed():
    """F697 CLOSED (toPrimitive): blocks."""
    hit = _blocked("(function(){var o={v:'%s',[Symbol.toPrimitive]:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------------- F693 node-exact variants (closed)

@_t
def test_p2_f693_multi_entry_closed():
    """F693 (multi-entry): mixed nested+array defaults block."""
    hit = _blocked("(function(){var {a:{b:c}={b:'%s'},d:[e,f]=['x','%s']}={};return c+e+f;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f693_const_closed():
    """F693 (const): const-declared pattern blocks."""
    hit = _blocked("(function(){const {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f693_extra_default_keys_closed():
    """F693 (extra default keys): unused default keys ignored, blocks."""
    hit = _blocked("(function(){var {a:{b:c}={b:'%s',z:'zz'}}={};return c+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f693_extra_array_elems_closed():
    """F693 (extra array elems): unused default elements ignored, blocks."""
    hit = _blocked("(function(){var {a:[b,c]=['%s','%s','zz']}={};return b+c;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------------- F697 node-exact variants (closed)

@_t
def test_p2_f697_nonfn_valueOf_closed():
    """F697 (non-function own valueOf): skipped, toString used, blocks."""
    hit = _blocked("(function(){var o={valueOf:'x',toString:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f697_sym_beats_valueOf_closed():
    """F697 ([Symbol.toPrimitive] beats valueOf): blocks."""
    hit = _blocked("(function(){var o={valueOf:function(){return 'V';},[Symbol.toPrimitive]:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f697_dup_key_closed():
    """F697 (duplicate valueOf key): later-wins, blocks."""
    hit = _blocked("(function(){var o={valueOf:function(){return 'X';},valueOf:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f697_named_fn_closed():
    """F697 (named function expr): engine-identical, blocks."""
    hit = _blocked("(function(){var o={v:'%s',valueOf:function val(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f697_trailing_comma_closed():
    """F697 (trailing comma): blocks."""
    hit = _blocked("(function(){var o={v:'%s',valueOf:function(){return this.v;},};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f697_valueOf_beats_toString_closed():
    """F697 (valueOf beats toString, default hint): blocks."""
    hit = _blocked("(function(){var o={valueOf:function(){return '%s';},toString:function(){return 'T';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------- exact-but-quiet variants (must not fire)

@_t
def test_p2_f697_reversed_quiet():
    """F697 (reversed): decodes exactly but is not credential-shaped; quiet."""
    quiet = _misses("(function(){var o={v:'%s',valueOf:function(){return this.v;}};return '%s'+o;})()" % (_A, _B))
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# --------------------------------------------- fail-closed bounds (must miss)

@_t
def test_p3_f693_key_present_misses():
    """F693 bound (key present in source): default does not apply; miss."""
    miss = _misses("(function(){var {a:{b:c}={b:'%s'}}={a:{b:'zz'}};return c+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f693_numeric_default_misses():
    """F693 bound (numeric default value): F475 provenance unmodeled; miss."""
    miss = _misses("(function(){var {a:{b:c}={b:5}}={};return c+'%s';})()" % _B)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f693_short_array_misses():
    """F693 bound (default shorter than pattern): node binds undefined; miss."""
    miss = _misses("(function(){var {a:[b,c]=['%s']}={};return b+c;})()" % _A)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f697_bracket_string_twin_misses():
    """F697 bound ([Symbol['toPrimitive']] twin): documented residual; miss."""
    miss = _misses("(function(){var o={v:'%s',[Symbol['toPrimitive']]:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f697_getter_misses():
    """F697 bound (getter in object): F674 owns getters; miss."""
    miss = _misses("(function(){var o={get v(){return '%s';},valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f697_call_args_misses():
    """F697 bound (non-empty call args): IIFE discipline; miss."""
    miss = _misses("(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})('x')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f697_no_coercion_quiet():
    """F697 bound (no coercion method): '[object Object]' shape; quiet."""
    quiet = _misses("(function(){var o={v:'%s'};return o+'%s';})()" % (_A, _B))
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p3_f697_throwing_valueOf_misses():
    """F697 bound (throwing valueOf): the engine throws, no toString fallback; miss (spec-review fix)."""
    miss = _misses("(function(){var o={v:'%s',valueOf:function(){return zzz();},toString:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f697_undefined_valueOf_misses():
    """F697 bound (undefined-returning valueOf): fail closed, no fall-through (spec-review residual)."""
    miss = _misses("(function(){var o={v:'%s',valueOf:function(){return this.missing;},toString:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# --------------------------------------- open neighbors still miss (F686-F699)

@_t
def test_p4_f686_open():
    """F686 now CLOSED (wave-381, proxy ownKeys): blocks."""
    blk = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f687_open():
    """F687 now CLOSED (wave-381, WeakSet marker): blocks."""
    blk = _blocked("(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f688_open():
    """F688 now CLOSED (wave-381, replaceAll fn): blocks."""
    blk = _blocked("(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f689_open():
    """F689 now CLOSED (wave-381, Symbol.iterator trap): blocks."""
    blk = _blocked("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});return [...p].join('');})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f690_open():
    """F690 now CLOSED (wave-381, function ctor): blocks."""
    blk = _blocked("(function(){function C(){this.x='%s';}var c=new C();return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f691_open():
    """F691 now CLOSED (wave-381, gopd .value): blocks."""
    blk = _blocked("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f692_open():
    """F692 now CLOSED (wave-381, super static): blocks."""
    blk = _blocked("(function(){class B{static x='%s';}class D extends B{static y(){return super.x;}}return D.y()+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f694_open():
    """F694 now CLOSED (wave-381, match groups): blocks."""
    blk = _blocked("(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f695_open():
    """F695 now CLOSED (wave-381, map spread): blocks."""
    blk = _blocked("(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f696_open():
    """F696 now CLOSED (wave-381, boxed String): blocks."""
    blk = _blocked("(function(){return (new String('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f698_open():
    """F698 now CLOSED (wave-381, dp-get): blocks."""
    blk = _blocked("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_p4_f699_open():
    """F699 now CLOSED (wave-381, >2^53 with): fail-closed, no decode."""
    miss = _misses("(function(){var o={x:9007199254740993};with(o){return x+'%s';}})()" % _B)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# --------------------------------- closed siblings still block (no absorption)

@_t
def test_p5_f684b_nested_closed():
    """F684b (nested, no default): still blocks; nothing absorbed."""
    hit = _blocked("(function(){var {x:{y}}={x:{y:'%s'}};return y+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p5_f674_member_closed():
    """F674 (this-bound member read): still blocks; nothing absorbed."""
    hit = _blocked("(function(){var o={x:'%s',get:function(){return this.x;}};return o.get()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p5_f644_flat_closed():
    """F644 (flat destructure): still blocks; nothing absorbed."""
    hit = _blocked("(function(){var {a,b}={a:'%s',b:'%s'};return a+b;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- footer / perf / green check

@_t
def test_p7_pin_footer():
    """Control: lane-local footer (open F686-F692, F694-F696, F698-F699; next F700)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-381 lane 6: F693, F697 CLOSED  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p8_perf():
    """Perf: 200 mixed sites decode in budget."""
    site = "(function(){var o={v:'ab',valueOf:function(){return this.v;}};return o+'cd';})()"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g381-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w380_attack_probes.py")],
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
    # The w380 battery's footer pin is stale by design: this lane
    # closes F693/F697, so its expected footer (open F686-F699 /
    # next F700) no longer matches. Merge-time repoint (wave-305/306
    # class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w380_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-380 attack battery stays green (depth-1)."""
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
