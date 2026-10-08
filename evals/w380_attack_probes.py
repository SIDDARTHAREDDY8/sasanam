"""Wave-380 lane 8: attack round 48 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (13, all LOW, all OPEN), filed from F686:
- F686: Proxy ownKeys-trap key-name laundering -- Object.keys,
  for-in, Object.getOwnPropertyNames, Reflect.ownKeys over a proxy
  whose ownKeys trap returns fragment key names (4 shapes).
- F687: WeakSet membership-marker conditional reads -- fragment
  selected by w.has(k) membership (2 shapes).
- F688: replace/replaceAll functional-replacer fragment assembly
  (2 shapes).
- F689: Proxy Symbol.iterator-trap iterable spread/for-of -- the get
  trap returns a generator as Symbol.iterator (2 shapes).
- F690: constructor-this member reads -- function and class
  constructors assigning this.x (2 shapes).
- F691: data-descriptor .value reads -- Object/Reflect
  getOwnPropertyDescriptor(...).value (2 shapes).
- F692: super reads in static methods (2 shapes).
- F693: destructuring rename/array-default residuals (2 shapes).
- F694: regex match-group fragment reassembly -- match/matchAll
  group extraction (2 shapes).
- F695: Map-spread index/key reads -- [...map][0][1], [...map][0][0],
  Array.from(map)[0][1] (3 shapes).
- F696: boxed-String coercion reads -- new String + additive/valueOf
  (2 shapes).
- F697: implicit toPrimitive reads -- valueOf/toString/
  Symbol.toPrimitive in additive position (3 shapes).
- F698: F664 residual -- defineProperty-installed accessor +
  descriptor .get() invocation (the F664 closure models only
  literal-getter sources) (2 shapes).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F672-F685 (round 47), F690, F691, F692, F693, F696, F697, F698, F699 (round 48;
F686, F687, F689, F695 closed wave-381 lanes 1-2; F688, F694 closed wave-381 lane 3).

Closed pins (must BLOCK, else BREAK): F463, F510, F535, F601, F612,
F619, F642, F653, F655, F657, F658, F661, F662-F671 (rounds 46-47
closures), F688, F694 (round 48; closed wave-381 lane 3).

Rides-with-documented-scope (validated, NOT filed):
- Array toSorted on the fragments -- malformed (sort order);
  discarded.
- WeakMap fragment stores -- BLOCK; already modeled (F562/F563).
- Object.values index reads, Array.from with mapping fn, for-await
  over sync iterables, structuredClone member reads -- all BLOCK;
  already modeled.
- `[...new Set(...)][0]` index reads -- BLOCK; already modeled.
- Template-literal interpolation -- BLOCK; already modeled.
- Junk-quiet controls pass.
Model note: 2/2 prompts returned usable hints (0 timeouts). The
trap/object hints (ownKeys, defineProperty) and iterator/destructuring
hints (return delegation, nested destructuring) guided hand-crafted
extensions validated node-exact (v24.20.0).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g380-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000238
logged separately in the realmodel ledger).
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

TAXONOMY_PIN = 2140  # no new decision codes this round

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
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F693, F696, F697, F699 open, next F700 (merged lanes 1-5)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F700**" in text
          and "Open findings: F693, F696, F697, F699." in text)  # Wave-381 merge: lanes 1-5 (F686-F692, F694, F695, F698 CLOSED)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\'ab\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f463_closed():
    """F463 CLOSED: still blocks."""
    ok = _blocked("String.raw`%s%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f463=%s" % ok)

@_t
def test_p1_f510_closed():
    """F510 CLOSED: still blocks."""
    ok = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f510=%s" % ok)

@_t
def test_p1_f535_closed():
    """F535 CLOSED: still blocks."""
    ok = _blocked("({get x(){return '%s%s';}}).x" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)

@_t
def test_p1_f601_closed():
    """F601 CLOSED: still blocks."""
    ok = _blocked("(function(){var s='';new Map([['k','%s%s']]).forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f601=%s" % ok)

@_t
def test_p1_f612_closed():
    """F612 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f612=%s" % ok)

@_t
def test_p1_f619_closed():
    """F619 CLOSED: still blocks."""
    ok = _blocked("[...(function*(){yield '%s';yield '%s';})()].join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f619=%s" % ok)

@_t
def test_p1_f642_closed():
    """F642 CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f642=%s" % ok)

@_t
def test_p1_f653_closed():
    """F653 CLOSED: still blocks."""
    ok = _blocked("Array.from(new Set(['%s','%s'])).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f653=%s" % ok)

@_t
def test_p1_f655_closed():
    """F655 CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f655=%s" % ok)

@_t
def test_p1_f657_closed():
    """F657 CLOSED: still blocks."""
    ok = _blocked("(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f657=%s" % ok)

@_t
def test_p1_f658_closed():
    """F658 CLOSED: still blocks."""
    ok = _blocked("(function(){return ['%s','%s'].flatMap(function(x){return [x];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f658=%s" % ok)

@_t
def test_p1_f661_closed():
    """F661 CLOSED: still blocks."""
    ok = _blocked("(function(){var s=('jx','%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f661=%s" % ok)

@_t
def test_p1_f662_closed():
    """F662 CLOSED: still blocks."""
    ok = _blocked("(function(){class C{static x='%s';}return C.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f662=%s" % ok)

@_t
def test_p1_f663_closed():
    """F663 CLOSED: still blocks."""
    ok = _blocked("(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f663=%s" % ok)

@_t
def test_p1_f664_closed():
    """F664 CLOSED: still blocks (literal-getter source, the closure's modeled form)."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)

@_t
def test_p1_f665_closed():
    """F665 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={x:'%s'};return o?.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f665=%s" % ok)

@_t
def test_p1_f666_closed():
    """F666 CLOSED: still blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{apply:function(){return '%s%s';}});return p();})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f666=%s" % ok)

@_t
def test_p1_f667_closed():
    """F667 CLOSED: still blocks."""
    ok = _blocked("(function(){with({x:'%s'}){return x+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f667=%s" % ok)

@_t
def test_p1_f668_closed():
    """F668 CLOSED: still blocks."""
    ok = _blocked("(function(){function tag(s){return s[0];}return tag`%s`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f668=%s" % ok)

@_t
def test_p1_f669_closed():
    """F669 CLOSED: still blocks."""
    ok = _blocked("(function(){return [...new Set(['%s','%s'])].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669=%s" % ok)

@_t
def test_p1_f670_closed():
    """F670 CLOSED: still blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{get:function(t,k){return '%s%s';}});return p.x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f670=%s" % ok)

@_t
def test_p1_f671_closed():
    """F671 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={a:'%s'};return o.a+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


# ------------------------------------------- F686-F690, F692-F697 open pins (must miss); F691 closed pins (must block)

@_t
def test_r48_f686_keys_join_closed():
    """F686 CLOSED (keys-join): blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)

@_t
def test_r48_f686_for_in_closed():
    """F686 CLOSED (for-in): blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});var s='';for(var k in p){s+=k;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)

@_t
def test_r48_f686_getOwnPropertyNames_closed():
    """F686 CLOSED (getOwnPropertyNames): blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.getOwnPropertyNames(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)

@_t
def test_r48_f686_Reflect_ownKeys_closed():
    """F686 CLOSED (Reflect-ownKeys): blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Reflect.ownKeys(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)

@_t
def test_r48_f687_has_ternary_closed():
    """F687 CLOSED 2026-10-08 wave-381 lane 2 (has-ternary): blocks coded."""
    ok = _blocked("(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f687_two_key_guard_closed():
    """F687 CLOSED 2026-10-08 wave-381 lane 2 (two-key-guard): blocks coded."""
    ok = _blocked("(function(){var w=new WeakSet();var k={};var j={};w.add(k);return (w.has(k)&&!w.has(j)?'%s':'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f688_replaceAll_fn_closed():
    """F688 CLOSED (replaceAll-fn): coded refusal."""
    ok = _blocked("(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f688_replace_fn_closed():
    """F688 CLOSED (replace-fn): coded refusal."""
    ok = _blocked("(function(){return 'ab'.replace(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f689_spread_closed():
    """F689 CLOSED (spread): blocks."""
    ok = _blocked("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});return [...p].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f689=%s" % ok)

@_t
def test_r48_f689_for_of_closed():
    """F689 CLOSED (for-of): blocks."""
    ok = _blocked("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});var s='';for(var x of p){s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f689=%s" % ok)

@_t
def test_r48_f690_function_ctor_closed():
    """F690 CLOSED (function-ctor): still blocks."""
    ok = _blocked("(function(){function C(){this.x='%s';}var c=new C();return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f690=%s" % ok)

@_t
def test_r48_f690_class_ctor_closed():
    """F690 CLOSED (class-ctor): still blocks."""
    ok = _blocked("(function(){class C{constructor(){this.x='%s';}}return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f690=%s" % ok)

@_t
def test_r48_f691_gopd_value_closed():
    """F691 CLOSED (gopd-value): blocks coded (wave-381 lane 5)."""
    hit = _blocked("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r48_f691_reflect_value_closed():
    """F691 CLOSED (reflect-value): blocks coded (wave-381 lane 5)."""
    hit = _blocked("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Reflect.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r48_f692_super_static_field_closed():
    """F692 CLOSED (super-static-field): still blocks."""
    ok = _blocked("(function(){class B{static x='%s';}class D extends B{static y(){return super.x;}}return D.y()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f692=%s" % ok)

@_t
def test_r48_f692_super_static_getter_closed():
    """F692 CLOSED (super-static-getter): still blocks."""
    ok = _blocked("(function(){class B{static get x(){return '%s';}}class D extends B{static y(){return super.x;}}return D.y()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f692=%s" % ok)

@_t
def test_r48_f693_rename_nested_open():
    """F693 OPEN (rename-nested): miss reproduces."""
    miss = _misses("(function(){var {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f693_array_default_open():
    """F693 OPEN (array-default): miss reproduces."""
    miss = _misses("(function(){var {a:[b,c]=['%s','%s']}={};return b+c;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f694_match_closed():
    """F694 CLOSED (match): coded refusal."""
    ok = _blocked("(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f694_matchAll_closed():
    """F694 CLOSED (matchAll): coded refusal."""
    ok = _blocked("(function(){var m=[...'%s:%s'.matchAll(/(%s):(%s)/g)][0];return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f695_pair_value_closed():
    """F695 CLOSED 2026-10-08 wave-381 lane 2 (pair-value): blocks coded."""
    ok = _blocked("(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f695_pair_key_closed():
    """F695 CLOSED 2026-10-08 wave-381 lane 2 (pair-key): blocks coded."""
    ok = _blocked("(function(){return [...new Map([['%s','junk']])][0][0]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f695_arrayfrom_pair_closed():
    """F695 CLOSED 2026-10-08 wave-381 lane 2 (arrayfrom-pair): blocks coded."""
    ok = _blocked("(function(){return Array.from(new Map([['k','%s']]))[0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r48_f696_plus_coerce_open():
    """F696 OPEN (plus-coerce): miss reproduces."""
    miss = _misses("(function(){return (new String('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f696_valueOf_open():
    """F696 OPEN (valueOf): miss reproduces."""
    miss = _misses("(function(){return new String('%s').valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f697_valueOf_open():
    """F697 OPEN (valueOf): miss reproduces."""
    miss = _misses("(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f697_toString_open():
    """F697 OPEN (toString): miss reproduces."""
    miss = _misses("(function(){var o={v:'%s',toString:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r48_f697_toPrimitive_open():
    """F697 OPEN (toPrimitive): miss reproduces."""
    miss = _misses("(function(){var o={v:'%s',[Symbol.toPrimitive]:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)



# ------------------------------------------- F698 closed pins (must block)

@_t
def test_r48_f698_dp_get_fn_closed():
    """F698 CLOSED (dp-get-fn): blocks coded (wave-381 lane 5)."""
    hit = _blocked("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r48_f698_dp_get_arrow_closed():
    """F698 CLOSED (dp-get-arrow): blocks coded (wave-381 lane 5)."""
    hit = _blocked("(function(){var o={};Object.defineProperty(o,'x',{get:()=>'%s'});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w379_attack_probes.py")],
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
    # The w379 battery's footer pin is stale by design: this lane filed
    # F686-F697, so its expected footer (open F672-F685 / next F686)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w379_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-379 attack battery stays green (depth-1)."""
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
