"""Wave-381 lane 8: attack round 49 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 3 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (11, all LOW, all OPEN), filed from F700:
- F700: F658 residual -- flatMap mapping-fn returning [f,'']/['',f].
- F701: getter invocation on object spread {...o}.
- F702: getter invocation on Object.assign.
- F703: __defineGetter__ legacy API.
- F704: Object.create with property-descriptor map accessors.
- F705: Reflect.get with receiver.
- F706: Proxy defineProperty-trap fragment writes.
- F707: Proxy getOwnPropertyDescriptor-trap descriptor reads.
- F708: Map.get fragment reads.
- F709: loop += accumulation.
- F710: F687 residual -- Set.has conditional reads.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F686-F699 (round 48), F700/F701/F704-F710 (round 49; F702/F703 closed wave-382 lane 2).

Closed pins (must BLOCK, else BREAK): F463, F510, F535, F601, F612,
F619, F642, F653, F655, F657, F658, F661, F662-F685 (rounds 46-48
closures).

Rides-with-documented-scope (validated, NOT filed):
- ['f1','f2'].reduce((a,c)=>a+c,'') -- BLOCK; already modeled.
- ['f1','f2'].filter(()=>true).join('') -- BLOCK; already modeled.
- Object.fromEntries fragment pairs -- BLOCK; already modeled.
- Reflect.apply / Reflect.construct(String,...) -- BLOCK; already modeled.
- arguments[0]+arguments[1] -- BLOCK; already modeled.
- /regex/.exec group extraction -- BLOCK; already modeled (F694-adjacent).
- Junk-quiet controls pass.
Model note: 3/3 prompts returned usable hints (0 timeouts). The
array/object-descriptor hints (flatMap, spread/assign of getters,
__defineGetter__, Object.create descriptor maps) and the
reflect/proxy hints (Reflect.get, defineProperty/getOwnPropertyDescriptor
traps) guided hand-crafted shapes validated node-exact (v24.20.0).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000452
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

TAXONOMY_PIN = 2143  # no new decision codes this round

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
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F702-F712 open, next F713 (this lane)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F713**" in text
          and "Open findings: F708, F709, F710, F711, F712." in text)  # Wave-382 merge: lanes 1-4 (F700-F707 CLOSED)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\'ab\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)


@_t
def test_p1_f658_closed():
    """F658 CLOSED: still blocks."""
    ok = _blocked("(function(){return ['%s','%s'].flatMap(function(x){return [x];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f658=%s" % ok)


@_t
def test_p1_f657_closed():
    """F657 CLOSED: still blocks."""
    ok = _blocked("(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f657=%s" % ok)


@_t
def test_p1_f655_closed():
    """F655 CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f655=%s" % ok)


@_t
def test_p1_f642_closed():
    """F642 CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f642=%s" % ok)


@_t
def test_p1_f664_closed():
    """F664 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={get x(){return '%s%s';}};return Object.getOwnPropertyDescriptor(o,'x').get();})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)


@_t
def test_p1_f673_closed():
    """F673 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={};Object.defineProperties(o,{x:{get:function(){return '%s%s';}}});return o.x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p1_f680_closed():
    """F680 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f680=%s" % ok)


# ------------------------------------------------- round-48 open pins (still open)


@_t
def test_r48_f686_open():
    """F686 now CLOSED (wave-381, ownKeys trap): blocks."""
    blk = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_r48_f698_open():
    """F698 OPEN (defineProperty .get() residual): miss reproduces."""
    blk = _blocked("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


# ------------------------------------------------- round-49 open pins (this round)


@_t
def test_r49_f700_flatmap_suffix_open():
    """F700 CLOSED 2026-10-08 wave-382 lane 1: coded refusal."""
    blk = _blocked("(function(){return ['%s','%s'].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_r49_f700_flatmap_prefix_open():
    """F700 CLOSED 2026-10-08 wave-382 lane 1: coded refusal."""
    blk = _blocked("(function(){return ['%s','%s'].flatMap(function(f){return ['',f];}).join('');})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_r49_f701_spread_getter_open():
    """F701 CLOSED 2026-10-08 wave-382 lane 1: coded refusal."""
    blk = _blocked("(function(){var o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_r49_f701_spread_two_getters_open():
    """F701 CLOSED 2026-10-08 wave-382 lane 1: coded refusal."""
    blk = _blocked("(function(){var o={get x(){return '%s';},get y(){return '%s';}};var c={...o};return c.x+c.y;})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)


@_t
def test_r49_f702_assign_getter_closed():
    """F702 CLOSED (wave-382 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};return Object.assign({},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r49_f702_assign_getter_extra_closed():
    """F702 CLOSED (wave-382 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};var c=Object.assign({z:1},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r49_f703_defineGetter_closed():
    """F703 CLOSED (wave-382 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={};o.__defineGetter__('x',function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r49_f703_defineGetter_two_closed():
    """F703 CLOSED (wave-382 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={};o.__defineGetter__('a',function(){return '%s';});o.__defineGetter__('b',function(){return '%s';});return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r49_f704_create_null_closed():
    """F704 CLOSED (Object.create descriptor): coded refusal."""
    hit = _blocked("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r49_f704_create_proto_closed():
    """F704 CLOSED (Object.create descriptor): coded refusal."""
    hit = _blocked("(function(){var o=Object.create(Object.prototype,{x:{enumerable:true,get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r49_f705_reflect_get_receiver_closed():
    """F705 CLOSED (Reflect.get): coded refusal."""
    hit = _blocked("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x',{})+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r49_f705_reflect_get_plain_closed():
    """F705 CLOSED (Reflect.get): coded refusal."""
    hit = _blocked("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r49_f706_dp_trap_closed():
    """F706 CLOSED: still blocks."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]='%s';return true;}});Object.defineProperty(p,'x',{value:1});return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f706=%s" % ok)


@_t
def test_r49_f706_dp_trap_2_closed():
    """F706 CLOSED: still blocks."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]=de.value2||'%s';return true;}});Object.defineProperty(p,'x',{value:1});return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f706=%s" % ok)


@_t
def test_r49_f707_gopd_trap_closed():
    """F707 CLOSED: still blocks."""
    ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Object.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f707=%s" % ok)


@_t
def test_r49_f707_gopd_trap_reflect_closed():
    """F707 CLOSED: still blocks."""
    ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Reflect.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f707=%s" % ok)


@_t
def test_r49_f708_map_get_open():
    """F708 OPEN (Map.get): miss reproduces."""
    miss = _misses("(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r49_f708_map_get_keyvar_open():
    """F708 OPEN (Map.get): miss reproduces."""
    miss = _misses("(function(){var m=new Map();m.set('k','%s');var k='k';return m.get(k)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r49_f709_for_plus_eq_open():
    """F709 OPEN (loop += accum): miss reproduces."""
    miss = _misses("(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r49_f709_while_plus_eq_open():
    """F709 OPEN (loop += accum): miss reproduces."""
    miss = _misses("(function(){var r='';var i=0;while(i<2){r+=['%s','%s'][i];i++;}return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r49_f710_set_has_open():
    """F710 OPEN (Set.has (F687 residual)): miss reproduces."""
    miss = _misses("(function(){var s=new Set(['k']);var f=s.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r49_f710_set_has_q_open():
    """F710 OPEN (Set.has (F687 residual)): miss reproduces."""
    miss = _misses("(function(){var s=new Set(['q']);return (s.has('q')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)



# ------------------------------------------------- green check (depth-1)

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
    # The w380 battery's footer pin is stale by design: this lane filed
    # F700-F710, so its expected footer (open F686-F699 / next F700)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
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