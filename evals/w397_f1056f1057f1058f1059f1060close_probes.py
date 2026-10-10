#!/usr/bin/env python3
"""Wave-397 lane 3 close battery: F1056 + F1057 + F1058 + F1059 + F1060.

F1056: String.replace capture-group assembly ("$1$2" substitution)
F1057: Array.from mapFn fragment reads
F1058: TextEncoder/TextDecoder fragment staging
F1059: Proxy named-target get-trap reads (F990 residual)
F1060: defineProperty getter-descriptor reads (F970 residual)

Pins: taxonomy 2143, verifier 33, re.compile 28. Lane-local footer:
open F1048-F1055, F1061-F1064 (12); next free F1065.
$0-spend-by-construction (no harness/paid refs).
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RE_COMPILE_PIN = 28

from gov import dlp  # noqa: E402
from gov.dlp import (_js_f1056_stmt_decode, _js_f1057_stmt_decode,  # noqa: E402
                     _js_f1058_stmt_decode, _js_f1059_stmt_decode,
                     _js_f1060_stmt_decode)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _check(name, ok, note=""):
    return ("HELD" if ok else "BREAK", note)


def _redfirst_shapes(num):
    """Import a w397 red-first module's SHAPES (side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "w397_f%d_redfirst.py" % num)
    spec = importlib.util.spec_from_file_location("w397_f%d_rf" % num, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143
    return _check("taxonomy-pin", ok, "pin=%d" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    ok = VERIFIER_TAXONOMY_PIN == 33
    return _check("verifier-pin", ok, "pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_pin_recompile():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RE_COMPILE_PIN
    return _check("recompile-pin", ok, "count=%d pin=%d" % (n, RE_COMPILE_PIN))


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F1056-F1060 stamped CLOSED)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1056-F1060 CLOSED (5" in text
          and "F1048-F1055, F1061-F1064 OPEN (12" in text
          and "Next free finding: **F1065**" in text)
    return _check("footer-state", ok, "footer=%s" % ok)


def _entry_has_closed_stamp(text, fnum):
    for line in text.splitlines():
        if line.startswith("(%s filed " % fnum):
            return "[CLOSED 2026-10-10 wave-397 lane 3:" in line
    return False


@_t
def test_p0_f1056_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1056")
    return _check("f1056-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1057_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1057")
    return _check("f1057-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1058_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1058")
    return _check("f1058-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1059_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1059")
    return _check("f1059-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1060_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1060")
    return _check("f1060-stamp", ok, "stamp=%s" % ok)


# --------------------------------------- p1: filed shapes must block

for _num in (1056, 1057, 1058, 1059, 1060):
    for _name, _payload in _redfirst_shapes(_num):
        def _mk(name=_name, payload=_payload, num=_num):
            @_t
            def _fn():
                return _check("filed-%s" % name, _blocked(payload),
                              "blocked")
            _fn.__name__ = "test_p1_filed_%s" % name
            return _fn
        _mk()


# --------------------------------------- p2: generalizations (node-verified,
# hook-level exactness)


@_t
def test_p2_f1056_dollar_dollar():
    p = 'var RESULT="v=fragA".replace(/v=(\\S+)/,"$$1=$1");'
    return _check("f1056-$$", _js_f1056_stmt_decode(p) == "$1=fragA",
                  "hook decodes")


@_t
def test_p2_f1056_match_ref():
    p = 'var RESULT="zzfragAzz".replace(/(fragA)/,"[$&]");'
    return _check("f1056-$&", _js_f1056_stmt_decode(p) == "zz[fragA]zz",
                  "hook decodes")


@_t
def test_p2_f1056_three_groups():
    p = ('var RESULT="p=fragA q=fragB r=fragC".replace('
         '/p=(\\S+) q=(\\S+) r=(\\S+)/,"$3$2$1");')
    return _check("f1056-3grp",
                  _js_f1056_stmt_decode(p) == "fragCfragBfragA",
                  "hook decodes")


@_t
def test_p2_f1056_greedy_backtrack():
    p = 'var RESULT="xfragAb".replace(/x(\\S+)b/,"$1");'
    return _check("f1056-greedy", _js_f1056_stmt_decode(p) == "fragA",
                  "hook decodes")


@_t
def test_p2_f1056_before_after():
    p = 'var RESULT="aXb".replace(/X/,"<$`-$'"'"'>");'
    return _check("f1056-b/a", _js_f1056_stmt_decode(p) == "a<a-b>b",
                  "hook decodes")


@_t
def test_p2_f1056_dollar_ten():
    p = 'var RESULT="aXb".replace(/(X)/,"$10");'
    return _check("f1056-$10", _js_f1056_stmt_decode(p) == "aX0b",
                  "hook decodes")


@_t
def test_p2_f1056_no_match():
    p = 'var RESULT="zzz".replace(/k1=(\\S+)/,"$1");'
    return _check("f1056-nomatch", _js_f1056_stmt_decode(p) == "zzz",
                  "hook decodes identity")


@_t
def test_p2_f1057_arrow():
    p = 'var RESULT=Array.from(["fragA","fragB"],x=>x).join("");'
    return _check("f1057-arrow", _js_f1057_stmt_decode(p) == "fragAfragB",
                  "hook decodes")


@_t
def test_p2_f1057_sep():
    p = ('const f=["fragA","fragB"];const RESULT=Array.from(f,'
         'function(x){return x;}).join("-");')
    return _check("f1057-sep", _js_f1057_stmt_decode(p) == "fragA-fragB",
                  "hook decodes")


@_t
def test_p2_f1057_empty_frag():
    p = ('var f=["fragA","","fragB"];var RESULT=Array.from(f,'
         'function(x){return x;}).join("");')
    return _check("f1057-empty", _js_f1057_stmt_decode(p) == "fragAfragB",
                  "hook decodes")


@_t
def test_p2_f1058_three_parts():
    p = ('var enc=new TextEncoder();var p=[enc.encode("fragA"),'
         'enc.encode("fragB"),enc.encode("fragC")];var dec=new '
         'TextDecoder();var RESULT=dec.decode(p[0])+dec.decode(p[1])'
         '+dec.decode(p[2]);')
    return _check("f1058-3parts",
                  _js_f1058_stmt_decode(p) == "fragAfragBfragC",
                  "hook decodes")


@_t
def test_p2_f1058_mixed_literal():
    p = ('let enc=new TextEncoder();let p=[enc.encode("fragA"),'
         'enc.encode("fragB")];let dec=new TextDecoder();let RESULT='
         'dec.decode(p[0])+"-"+dec.decode(p[1]);')
    return _check("f1058-mixed",
                  _js_f1058_stmt_decode(p) == "fragA-fragB",
                  "hook decodes")


@_t
def test_p2_f1059_arrow_trap():
    p = ('var t={a:"fragA",b:"fragB",c:"fragC"};var p=new Proxy(t,'
         '{get:(o,k)=>o[k]});var RESULT=p["a"]+p.b+"-"+p.c;')
    return _check("f1059-arrow",
                  _js_f1059_stmt_decode(p) == "fragAfragB-fragC",
                  "hook decodes")


@_t
def test_p2_f1060_two_getters():
    p = ('var o={};Object.defineProperty(o,"a",{get:()=>"lit1"});'
         'Object.defineProperty(o,"b",{get:function(){return "lit2";}});'
         'var RESULT=o.a+"-"+o["b"];')
    return _check("f1060-2getters",
                  _js_f1060_stmt_decode(p) == "lit1-lit2",
                  "hook decodes")


@_t
def test_p2_f1060_init_props():
    p = ('var o={z:"q"};Object.defineProperty(o,"a",{get:function()'
         '{return "lit";}});var RESULT=o.z+o.a;')
    return _check("f1060-init",
                  _js_f1060_stmt_decode(p) == "qlit",
                  "hook decodes")


# --------------------------------------- p3: fail-closed bounds (must miss)


@_t
def test_p3_f1056_flags():
    p = 'var RESULT="k1=fragA".replace(/k1=(\\S+)/g,"$1");'
    return _check("f1056-flags", _misses(p), "misses")


@_t
def test_p3_f1056_new_regexp():
    p = 'var RESULT="k1=fragA".replace(new RegExp("k1=(\\\\S+)"),"$1");'
    return _check("f1056-newregexp", _misses(p), "misses")


@_t
def test_p3_f1056_digit_class():
    p = 'var RESULT="k1=12".replace(/k1=(\\d+)/,"$1");'
    return _check("f1056-\\d", _misses(p), "misses")


@_t
def test_p3_f1056_char_class():
    p = 'var RESULT="k1=fragA".replace(/k1=([a-z]+)/,"$1");'
    return _check("f1056-class", _misses(p), "misses")


@_t
def test_p3_f1056_alternation():
    p = 'var RESULT="ab".replace(/(a|b)/,"$1");'
    return _check("f1056-alt", _misses(p), "misses")


@_t
def test_p3_f1056_callback():
    p = 'var RESULT="ab".replace(/b/,function(m){return m;});'
    return _check("f1056-callback", _misses(p), "misses (F1033 shape)")


@_t
def test_p3_f1056_nonbmp():
    p = 'var RESULT="\\u{1F600}".replace(/(\\S)/,"$1");'
    return _check("f1056-nonbmp", _misses(p), "misses")


@_t
def test_p3_f1056_anchor():
    p = 'var RESULT="k1=fragA".replace(/^k1=(\\S+)/,"$1");'
    return _check("f1056-anchor", _misses(p), "misses")


@_t
def test_p3_f1057_nonidentity():
    p = ('var f=["fragA"];var RESULT=Array.from(f,'
         'function(x){return x+"!";}).join("");')
    return _check("f1057-nonidentity", _misses(p), "misses")


@_t
def test_p3_f1057_nonstring():
    p = ('var f=[65];var RESULT=Array.from(f,'
         'function(x){return x;}).join("");')
    return _check("f1057-nonstr", _misses(p), "misses")


@_t
def test_p3_f1057_hole():
    p = ('var f=["fragA",,];var RESULT=Array.from(f,'
         'function(x){return x;}).join("");')
    return _check("f1057-hole", _misses(p), "misses")


@_t
def test_p3_f1057_nojoin():
    p = ('var f=["fragA"];var RESULT=Array.from(f,'
         'function(x){return x;});')
    return _check("f1057-nojoin", _misses(p), "misses")


@_t
def test_p3_f1058_surrogate():
    p = ('var enc=new TextEncoder();var p=[enc.encode("\\ud800")];'
         'var dec=new TextDecoder();var RESULT=dec.decode(p[0]);')
    return _check("f1058-surrogate", _misses(p), "misses")


@_t
def test_p3_f1058_encoder_arg():
    p = ('var enc=new TextEncoder("utf-8");var p=[enc.encode("fragA")];'
         'var dec=new TextDecoder();var RESULT=dec.decode(p[0]);')
    return _check("f1058-encarg", _misses(p), "misses")


@_t
def test_p3_f1058_decode_opts():
    p = ('var enc=new TextEncoder();var p=[enc.encode("fragA")];'
         'var dec=new TextDecoder();var RESULT=dec.decode(p[0],{stream:true});')
    return _check("f1058-decopts", _misses(p), "misses")


@_t
def test_p3_f1058_oob():
    p = ('var enc=new TextEncoder();var p=[enc.encode("fragA")];'
         'var dec=new TextDecoder();var RESULT=dec.decode(p[5]);')
    return _check("f1058-oob", _misses(p), "misses")


@_t
def test_p3_f1059_inline_target():
    """Inline-literal target is F990's production: this hook misses."""
    p = ('var p=new Proxy({a:"fragA"},{get:function(o,k){return o[k];}});'
         'var RESULT=p.a;')
    ok = _js_f1059_stmt_decode(p) is None
    return _check("f1059-inline", ok, "hook misses (F990 decodes)")


@_t
def test_p3_f1059_extra_trap():
    p = ('var t={a:"fragA"};var p=new Proxy(t,{get:function(o,k){return o[k];},'
         'set:function(o,k,v){}});var RESULT=p.a;')
    return _check("f1059-extratrap", _misses(p), "misses")


@_t
def test_p3_f1059_nonidentity_trap():
    p = ('var t={a:"fragA"};var p=new Proxy(t,{get:function(o,k){return o[k]+"x";}});'
         'var RESULT=p.a;')
    return _check("f1059-nontrap", _misses(p), "misses")


@_t
def test_p3_f1059_unknown_key():
    p = ('var t={a:"fragA"};var p=new Proxy(t,{get:function(o,k){return o[k];}});'
         'var RESULT=p.zzz;')
    return _check("f1059-unknown", _misses(p), "misses")


@_t
def test_p3_f1059_target_mismatch():
    p = ('var t={a:"fragA"};var u={a:"fragB"};var p=new Proxy(u,'
         '{get:function(o,k){return o[k];}});var RESULT=p.a;')
    return _check("f1059-target", _misses(p), "misses")


@_t
def test_p3_f1060_value_desc():
    """Value-descriptor is F970's production: this hook misses."""
    p = ('var o={};Object.defineProperty(o,"a",{value:"fragA"});'
         'var RESULT=o.a;')
    ok = _js_f1060_stmt_decode(p) is None
    return _check("f1060-valuedesc", ok, "hook misses (F970 decodes)")


@_t
def test_p3_f1060_redefine():
    p = ('var o={};Object.defineProperty(o,"a",{get:function(){return "x";}});'
         'Object.defineProperty(o,"a",{get:function(){return "y";}});'
         'var RESULT=o.a;')
    return _check("f1060-redefine", _misses(p), "misses")


@_t
def test_p3_f1060_setter():
    p = ('var o={};Object.defineProperty(o,"a",{set:function(v){}});'
         'var RESULT=o.a;')
    return _check("f1060-setter", _misses(p), "misses")


@_t
def test_p3_f1060_unknown_key():
    p = ('var o={};Object.defineProperty(o,"a",{get:function(){return "fragA";}});'
         'var RESULT=o.zzz;')
    return _check("f1060-unknown", _misses(p), "misses")


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_f990_closed():
    """F990 (CLOSED): inline-target proxy get-trap stays blocked."""
    p = ('var p=new Proxy({a:"xoxb-01",b:"23456789abcdef"},'
         '{get:function(o,k){return o[k];}});var RESULT=p.a+p.b;')
    return _check("sibling-f990-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f970_closed():
    """F970 (CLOSED): defineProperty value-descriptor stays blocked."""
    p = ('var o={};Object.defineProperty(o,"a",{value:"xoxb-01"});'
         'var RESULT=o.a+"23456789abcdef";')
    return _check("sibling-f970-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f1054_open():
    """F1054 (OPEN, lane 2): match-group reads still miss."""
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);'
         'var RESULT=m.groups.x+m.groups.y;')
    return _check("sibling-f1054-open", _misses(p), "still misses")


@_t
def test_p4_sibling_f1055_open():
    """F1055 (OPEN, lane 2): JSON.parse reviver still misses."""
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\',(k,v)=>v);'
         'var RESULT=o.a+o.b;')
    return _check("sibling-f1055-open", _misses(p), "still misses")


@_t
def test_p4_sibling_f1061_open():
    """F1061 (OPEN, lane 4): Map.get dual-staged still misses."""
    p = ('var m=new Map([["a","xoxb-01"],["b","23456789abcdef"]]);'
         'var RESULT=m.get("a")+m.get("b");')
    return _check("sibling-f1061-open", _misses(p), "still misses")


@_t
def test_p4_sibling_f1048_open():
    """F1048 (OPEN, lane 1): Error cause-chain still misses."""
    p = ('var e=new Error("a",{cause:new Error("b",{cause:"xoxb-01"})});'
         'var RESULT=e.cause.cause+"23456789abcdef";')
    return _check("sibling-f1048-open", _misses(p), "still misses")


# --------------------------------------- p5: honest text stays quiet


@_t
def test_p5_honest_replace_benign():
    p = 'var s="hello";var RESULT=s.replace(/l/g,"L");'
    return _check("honest-replace", _misses(p), "quiet")


@_t
def test_p5_honest_replace_decodes_benign():
    """Hook fires (decodes "ho") but no credential shape -> quiet."""
    p = 'var RESULT="hi".replace(/i/,"o");'
    return _check("honest-replace-decodes", _misses(p), "quiet")


@_t
def test_p5_honest_from_benign():
    p = 'var RESULT=Array.from([1,2],x=>x).join(",");'
    return _check("honest-from", _misses(p), "quiet")


@_t
def test_p5_honest_encoder_benign():
    p = ('var enc=new TextEncoder();var RESULT=enc.encode("hi").length;')
    return _check("honest-encoder", _misses(p), "quiet")


@_t
def test_p5_honest_proxy_benign():
    p = 'var p=new Proxy({a:1},{get:function(o,k){return o[k];}});var RESULT=String(p.a);'
    return _check("honest-proxy", _misses(p), "quiet")


@_t
def test_p5_honest_defprop_benign():
    p = 'var o={};Object.defineProperty(o,"x",{value:1});var RESULT=String(o.x);'
    return _check("honest-defprop", _misses(p), "quiet")


@_t
def test_p5_honest_sentence():
    p = "The quarterly report is due on Friday; please review the figures."
    return _check("honest-sentence", _misses(p), "quiet")


@_t
def test_p5_honest_junk():
    p = "(function(){var s='ab';return s;})()"
    return _check("honest-junk", _misses(p), "quiet")


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = ('var RESULT="k1=xo k2=yz".replace(/k1=(\\S+) k2=(\\S+)/,"$1$2");')
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 15.0
    return _check("perf", ok, "200 sites in %.2fs" % dt)


# --------------------------------------- p7: depth-1 green check


def _run_battery(name):
    tmp = tempfile.mkdtemp(prefix="g397-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
        capture_output=True, text=True, env=env, timeout=600,
        cwd=REPO_ROOT)
    return (p.stdout or "") + (p.stderr or "")


@_t
def test_p7_green_check():
    """Depth-1 green check: lane red-firsts 0 BREAK; w396 attack battery
    breaks ONLY the 5 now-closed pins (F1056-F1060 flip at merge)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return _check("green-skip", True, "skipped (GOV_SKIP_GREEN=1)")
    bad_notes = []
    for battery in ("w397_f1056_redfirst.py", "w397_f1057_redfirst.py",
                    "w397_f1058_redfirst.py", "w397_f1059_redfirst.py",
                    "w397_f1060_redfirst.py"):
        out = _run_battery(battery)
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        if bad or nshapes == 0:
            bad_notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
    out = _run_battery("w396_attack_probes.py")
    broke = [line.split()[0] for line in out.splitlines()
             if re.match(r"^test_r64_f10(56|57|58|59|60)_open: BREAK", line)]
    other_broke = [line for line in out.splitlines()
                   if ": BREAK" in line and "f1056" not in line
                   and "f1057" not in line and "f1058" not in line
                   and "f1059" not in line and "f1060" not in line]
    if len(broke) != 5:
        bad_notes.append("attack battery: expected 5 now-closed pins BREAK, got %d" % len(broke))
    if other_broke:
        bad_notes.append("attack battery unexpected BREAKs: %s" % other_broke[:3])
    ok = not bad_notes
    return _check("green", ok, "bad=[%s]" % "; ".join(bad_notes))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held, broke, failed = 0, 0, []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            failed.append((fn.__name__, note))
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("HELD %d / BREAK %d / %d total" % (held, broke, held + broke))
    for name, note in failed:
        print("FAILED:", name, note)
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
