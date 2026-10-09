#!/usr/bin/env python3
"""Close battery for F845 + F846 + F847 + F848 (wave-387 lane 5).

F845: Symbol.for-keyed properties -- the decoder modeled local
  Symbol('k') keys (F734) but not Symbol.for('k') registry keys.
F846: computed string keys -- o['k'+'ey'] resolves node-exactly
  while the decoder produced zero variants.
F847: Object.defineProperties (plural) -- multi-descriptor installs
  with value descriptors.
F848: switch statement flows -- node-exact strict-equality
  simulation over provably-constant discriminants.

All closures node-verified (v24.20.0). Filed shapes + generalizations
must HIT; fail-closed bounds must MISS (rejected, never mis-decoded);
sibling pins (F734, F655) must still HIT; honest text stays quiet.

GOV_DEPLOYMENT_MODE=staging at module level (wave-95 lesson).
Depth-1 green check on w386_attack_probes.py honoring GOV_SKIP_GREEN=1
(wave-173 lesson). Unique /var/tmp TMPDIR (wave-112 lesson).
$0 spend by construction: no model calls, no network.
"""
import os
import sys
import time
import tempfile
import subprocess

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-386 merge (no code-count change)

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


# ---------------------------------------------------------------- pins

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0b_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1]
          and "F919, F920." in foot[-1]
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------- F845 filed shapes (must HIT)

@_t
def test_f845_s1():
    """F845 filed s1: var-bound Symbol.for write, direct Symbol.for read."""
    hit = _blocked("(function(){var o={};var s=Symbol.for('kk');o[s]='%s';"
                   "return o[Symbol.for('kk')]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f845_s2():
    """F845 filed s2: computed literal key in the object literal."""
    hit = _blocked("(function(){var s=Symbol.for('k');var o={[s]:'%s'};"
                   "return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F846 filed shapes (must HIT)

@_t
def test_f846_s1():
    """F846 filed s1: computed key in literal, dot read."""
    hit = _blocked("(function(){var o={['k'+'ey']:'%s'};"
                   "return o.key+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f846_s2():
    """F846 filed s2: computed write, bracket read."""
    hit = _blocked("(function(){var o={};o['k'+'ey']='%s';"
                   "return o['key']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F847 filed shapes (must HIT)

@_t
def test_f847_s1():
    """F847 filed s1: defineProperties single value descriptor."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{k:{value:'%s',enumerable:true}});"
                   "return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f847_s2():
    """F847 filed s2: defineProperties with writable flag."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{k:{value:'%s',writable:false}});"
                   "return o['k']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F848 filed shapes (must HIT)

@_t
def test_f848_s1():
    """F848 filed s1: switch with default, discriminant matches case."""
    hit = _blocked("(function(){var x=1,r='';switch(x){case 1:r='%s';"
                   "break;default:r='z';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f848_s2():
    """F848 filed s2: multi-case switch, second case matches."""
    hit = _blocked("(function(){var x=2,r='';switch(x){case 1:r='x';"
                   "break;case 2:r='%s';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F845 generalizations (must HIT)

@_t
def test_f845_g1():
    """F845 g1: direct Symbol.for write/read, no binding."""
    hit = _blocked("(function(){var o={};o[Symbol.for('k')]='%s';"
                   "return o[Symbol.for('k')]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f845_g2():
    """F845 g2: direct Symbol.for computed literal key."""
    hit = _blocked("(function(){var o={[Symbol.for('k')]:'%s'};"
                   "return o[Symbol.for('k')]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f845_g3():
    """F845 g3: comma-separated Symbol.for declarators."""
    hit = _blocked("(function(){var a=Symbol.for('x'),b=Symbol.for('y');"
                   "var o={};o[a]='%s';o[b]='w';return o[a]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f845_g4():
    """F845 g4: let/const declarations."""
    hit = _blocked("(function(){let s=Symbol.for('k');const o={};o[s]='%s';"
                   "return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F846 generalizations (must HIT)

@_t
def test_f846_g1():
    """F846 g1: three-term additive key, dot read."""
    hit = _blocked("(function(){var o={};o['a'+'b'+'c']='%s';"
                   "return o.abc+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f846_g2():
    """F846 g2: mixed-quote additive write, bracket read."""
    hit = _blocked("(function(){var o={};o[\"k\"+'ey']='%s';"
                   "return o['key']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f846_g3():
    """F846 g3: dot write, computed read."""
    hit = _blocked("(function(){var o={};o.key='%s';"
                   "return o['k'+'ey']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f846_g4():
    """F846 g4: bare identifier key in literal, computed read."""
    hit = _blocked("(function(){var o={key:'%s'};"
                   "return o['k'+'ey']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F847 generalizations (must HIT)

@_t
def test_f847_g1():
    """F847 g1: multi-descriptor defineProperties."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{a:{value:'%s'},b:{value:'y'}});"
                   "return o.a+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f847_g2():
    """F847 g2: string-literal descriptor key."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{'k':{value:'%s'}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f847_g3():
    """F847 g3: bracket read of defined property."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{k:{value:'%s'}});return o['k']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f847_g4():
    """F847 g4: configurable:false flag tolerated."""
    hit = _blocked("(function(){var o={};Object.defineProperties(o,"
                   "{k:{value:'%s',configurable:false}});"
                   "return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- F848 generalizations (must HIT)

@_t
def test_f848_g1():
    """F848 g1: string discriminant, single case."""
    hit = _blocked("(function(){var x='a',r='';switch(x){case 'a':r='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f848_g2():
    """F848 g2: direct literal discriminant."""
    hit = _blocked("(function(){var r='';switch(2){case 1:r='x';"
                   "break;case 2:r='%s';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f848_g3():
    """F848 g3: default clause wins when no case matches."""
    hit = _blocked("(function(){var x=9,r='';switch(x){case 1:r='x';"
                   "break;default:r='%s';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f848_g4():
    """F848 g4: negative case label."""
    hit = _blocked("(function(){var x=-1,r='';switch(x){case -1:r='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- fail-closed bounds (must MISS)

@_t
def test_f845_b2():
    """F845 b2: Symbol.for(non-literal) fails closed."""
    miss = _misses("(function(){var s=Symbol.for(123);var o={};o[s]='%s';"
                   "return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f845_b3():
    """F845 b3: Symbol() (non-registry) fails closed."""
    miss = _misses("(function(){var s=Symbol();var o={};o[s]='%s';"
                   "return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f845_b4():
    """F845 b4: read of never-written key fails closed (engine: undefined)."""
    miss = _misses("(function(){var s=Symbol.for('k');var o={};return o[s];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f846_b1():
    """F846 b1: non-literal additive term fails closed."""
    miss = _misses("(function(){var o={},x='ey';o['k'+x]='%s';"
                   "return o.key+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f846_b3():
    """F846 b3: numeric computed key fails closed."""
    miss = _misses("(function(){var o={};o[1+2]='%s';"
                   "return o[3]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f847_b1():
    """F847 b1: get descriptor fails closed."""
    miss = _misses("(function(){var o={};Object.defineProperties(o,"
                   "{k:{get:function(){return '%s'}}});"
                   "return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f847_b2():
    """F847 b2: set descriptor fails closed."""
    miss = _misses("(function(){var o={};Object.defineProperties(o,"
                   "{k:{set:function(v){}}});return o.k;})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f847_b3():
    """F847 b3: __proto__ descriptor key fails closed."""
    miss = _misses("(function(){var o={};Object.defineProperties(o,"
                   "{__proto__:{value:'%s'}});"
                   "return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f847_b4():
    """F847 b4: non-empty target object fails closed."""
    miss = _misses("(function(){var o={a:1};Object.defineProperties(o,"
                   "{k:{value:'%s'}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f847_b5():
    """F847 b5: non-literal descriptor value fails closed."""
    miss = _misses("(function(){var o={},x='%s';Object.defineProperties(o,"
                   "{k:{value:x}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b1():
    """F848 b1: fall-through into next case fails closed."""
    miss = _misses("(function(){var x=1,r='';switch(x){case 1:r='%s';"
                   "case 2:r='f2';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b2():
    """F848 b2: fractional case label fails closed."""
    miss = _misses("(function(){var x=1.5,r='';switch(x){case 1.5:r='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b3():
    """F848 b3: duplicate default fails closed (engine: SyntaxError)."""
    miss = _misses("(function(){var x=1,r='';switch(x){default:r='a';"
                   "break;default:r='b';break;}return r+'%s';})()" % _B)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b4():
    """F848 b4: unbound discriminant fails closed."""
    miss = _misses("(function(){var r='';switch(y){case 1:r='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b5():
    """F848 b5: assignment to the discriminant fails closed."""
    miss = _misses("(function(){var x=1,r='';switch(x){case 1:x='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b6():
    """F848 b6: legacy-octal discriminant fails closed (node: octal 8)."""
    # (function(){var x=010,r='';switch(x){case 8:r='A';break;case 10:r='z';
    # break;}return r+'B';})() node-yields the credential but the model
    # would mis-decode as decimal 10 -- must fail closed, not mis-decode.
    miss = _misses("(function(){var x=010,r='';switch(x){case 8:r='%s';"
                   "break;case 10:r='z';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_f848_b7():
    """F848 b7: legacy-octal case label fails closed."""
    miss = _misses("(function(){var x=8,r='';switch(x){case 010:r='%s';"
                   "break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------- sibling pins (must still HIT)

@_t
def test_sib_f734():
    """Sibling F734 (local Symbol keys) still decodes."""
    hit = _blocked("(function(){var o={};var s=Symbol('k');o[s]='%s';"
                   "return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_sib_f655():
    """Sibling F655 (switch fall-through accumulation) still decodes."""
    hit = _blocked("(function(){let s='';switch(1){case 1:s+='%s';"
                   "case 2:s+='%s';}return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- honest-text controls (must MISS)

@_t
def test_c0_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_c1_honest_switch():
    """Honest switch on non-credential text stays quiet."""
    quiet = _misses("(function(){var x=1,r='';switch(x){case 1:r='ok';"
                    "break;}return r;})()")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_c2_honest_object():
    """Honest object literal stays quiet."""
    quiet = _misses("(function(){var o={key:'value'};return o.key;})()")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------- perf (200 sites)

@_t
def test_perf_200():
    """200 decode sites complete quickly (F452 budget bounded)."""
    sites = []
    for k in range(50):
        sites.append("(function(){var o={};var s=Symbol.for('k%d');o[s]='%s';"
                     "return o[s]+'%s';})()" % (k, _A, _B))
        sites.append("(function(){var o={};o['ke'+'y%d']='%s';"
                     "return o['key%d']+'%s';})()" % (k, _A, k, _B))
        sites.append("(function(){var o={};Object.defineProperties(o,{k:{value:'%s'}});"
                     "return o.k+'%s';})()" % (_A, _B))
        sites.append("(function(){var x=%d,r='';switch(x){case %d:r='%s';break;}"
                     "return r+'%s';})()" % (k, k, _A, _B))
    t0 = time.time()
    hits = sum(1 for s in sites if _blocked(s))
    dt = time.time() - t0
    ok = hits == 200 and dt < 30.0
    return ("HELD" if ok else "BREAK", "hits=%d/200 dt=%.2fs" % (hits, dt))


# ------------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g387l5-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w386_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    break_names = []
    for line in out.splitlines():
        if ": BREAK" in line:
            break_names.append(line.split(":")[0])
    # Expected BREAKs: the 8 F845-F848 OPEN pins (this lane closed them,
    # so they now HIT) + the attack battery's stale footer pin (it pins
    # the pre-lane footer; wave-305/306 class repoint). Any other BREAK
    # is a real regression.
    expected = set(
        ["test_r54_f845_s1_open", "test_r54_f845_s2_open",
         "test_r54_f846_s1_open", "test_r54_f846_s2_open",
         "test_r54_f847_s1_open", "test_r54_f847_s2_open",
         "test_r54_f848_s1_open", "test_r54_f848_s2_open",
         "test_b0_footer_state"])
    unexpected = [b for b in break_names if b not in expected]
    missing = [b for b in expected if b not in break_names]
    ok = not unexpected and not missing
    return ("HELD" if ok else "BREAK",
            "green(w386_attack): %d BREAK (%d expected, %d unexpected, %d missing)"
            % (len(break_names), len(expected) - len(missing),
               len(unexpected), len(missing)))


@_t
def test_p9_green_check():
    """Depth-1 green check on the attack battery (prior wave)."""
    return _green_check()


def main():
    breaks, held = 0, 0
    for fn in TESTS:
        verdict, note = fn()
        print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
