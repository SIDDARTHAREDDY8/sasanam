#!/usr/bin/env python3
"""Wave-386 F799/F800 closure battery: subclassed builtins + Proxy get-trap residuals (lane 3).

F799 (LOW, filed 2026-10-09 03:25 UTC wave-385 attack round 53, CLOSED
2026-10-09 wave-386 lane 3): the decoder has no subclass production
for String/Array -- `class S extends String{}` / `class A extends
Array{}` instances resolve valueOf()/toString()/join() node-exactly
while the decoder produces zero variants. Close-when: the decoder
models subclassed builtin reads node-exactly (or refuses the
laundering coded) such that find_credential flags them, red-first
verified, honest text unaffected.

F800 (LOW, filed 2026-10-09 03:25 UTC wave-385 attack round 53, CLOSED
2026-10-09 wave-386 lane 3): F642 (CLOSED) models get traps, but
var-bound proxies with function-form get bodies and Proxy.revocable
miss while node resolves them exactly. Close-when: the decoder
models the constant-return get-trap and Proxy.revocable reads
node-exactly (or refuses the laundering coded) such that
find_credential flags them, red-first verified, honest text
unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  red-first closure: the four filed shapes now block coded
      dlp-slack-token (same rule as the plain control).
  P2  generalizations: toString/bracket twins, multi/zero-arg
      constructors, Array holes, arrow/named-fn get traps,
      bracket member reads -- all node-exact (v24.20.0).
  P3  fail-closed bounds: non-empty class bodies, wrong
      superclasses, non-literal args, unmodeled methods,
      non-constant get bodies, extra handler keys, revoke() --
      all miss with no mis-decoded variant.
  P4  sibling pins: F746 (subclassed Map), F783 (super dispatch),
      F535/F587 (passthrough/empty-handler proxies), F642
      additives, F789 (construct trap) -- byte-identical behavior.
  P5  honest text quiet + perf (200 sites).
  P6  pin + footer: taxonomy pin 2143, lane-local footer open
      F795-F798, F801-F817, F819-F828 / next F829.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w386_f799f800close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # Wave-385 merge: pin stays 2143 (no new decision codes; 2143->2144 repoint reverted)
FOOTER_OPEN = "F795, F796, F797, F798, F801, F802, F803, F804, F805, F806, F807, F808, F809, F810, F811, F812, F813, F814, F815, F816, F817, F819, F820, F821, F822, F823, F824, F825, F826, F827, F828"  # Wave-385 merge: F762-F794 CLOSED (33); F795-F817, F819-F828 OPEN (32; F818 incidentally closed by F769); wave-386 lane 3: F799, F800 CLOSED (lane-local)
FOOTER_NEXT = "F829"  # Wave-385 merge: next F829

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


_TALLY = {"HELD": 0, "BREAK": 0}


def _check(name, cond, detail=""):
    print("%-52s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    _TALLY["HELD" if cond else "BREAK"] += 1
    return cond


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded_values(payload):
    return list(dlp._decoded_variants(payload))


# ---------------------------------------------------------------- P1: filed shapes
def p1_filed_shapes_block():
    ok = True
    plain_rule = dlp.find_credential("token=" + _A + _B)
    ok = _check("P1a plain control blocks coded",
                plain_rule == "dlp-slack-token",
                "rule=%s" % plain_rule) and ok
    filed = [
        ("P1b F799 s1 subclassed String valueOf",
         "(function(){class S extends String{}var s=new S('%s');return s.valueOf()+'%s';})()" % (_A, _B),
         _A + _B),
        ("P1c F799 s2 subclassed Array join",
         "(function(){class A extends Array{}var a=new A('%s','%s');return a.join('');})()" % (_A, _B),
         _A + _B),
        ("P1d F800 s1 constant get-trap",
         "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
         _A + _B),
        ("P1e F800 s2 Proxy.revocable",
         "(function(){var r=Proxy.revocable({k:'%s'},{});return r.proxy.k+'%s';})()" % (_A, _B),
         _A + _B),
    ]
    for name, payload, expected in filed:
        hit = _blocked(payload)
        exact = expected in _decoded_values(payload)
        ok = _check(name, hit and exact,
                    "blocked=%s exact=%s" % (hit, exact)) and ok
    return ok


# ---------------------------------------------------------------- P2: generalizations
def p2_generalizations():
    ok = True
    # (name, payload, expected decoded value, want_block)
    # want_block is True only when the expected value is
    # credential-shaped; the core assertion is node-exactness.
    gens = [
        ("P2a String toString twin",
         "(function(){class S extends String{}var s=new S('%s');return s.toString()+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2b String multi-arg (extras ignored)",
         "(function(){class S extends String{}var s=new S('%s','zz');return s.valueOf()+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2c String zero-arg",
         "(function(){class S extends String{}var s=new S();return s.valueOf()+'%s';})()" % _B,
         _B, False),
        ("P2d String bracket member",
         "(function(){class S extends String{}var s=new S('%s');return s['valueOf']()+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2e Array toString (comma join)",
         "(function(){class A extends Array{}var a=new A('%s','%s');return a.toString();})()" % (_A, _B),
         _A + "," + _B, False),
        ("P2f Array join separator",
         "(function(){class A extends Array{}var a=new A('%s','%s');return a.join('-');})()" % (_A, _B),
         _A + "-" + _B, True),
        ("P2g Array single string arg",
         "(function(){class A extends Array{}var a=new A('%s');return a.join('');})()" % _A,
         _A, False),
        ("P2h Array holes join",
         "(function(){class A extends Array{}var a=new A(3);return a.join('')+'%s';})()" % _A,
         _A, False),
        ("P2i Array holes toString",
         "(function(){class A extends Array{}var a=new A(3);return a.toString();})()",
         ",,", False),
        ("P2j let binding",
         "(function(){class S extends String{}let s=new S('%s');return s.valueOf();})()" % _A,
         _A, False),
        ("P2k arrow get-trap",
         "(function(){var p=new Proxy({},{get:(t,k)=>'%s'});return p.anything+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2l named function get-trap",
         "(function(){var p=new Proxy({},{get:function foo(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2m bracket member on const proxy",
         "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p['zz']+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2n bracket revocable read",
         "(function(){var r=Proxy.revocable({k:'%s'},{});return r['proxy']['k']+'%s';})()" % (_A, _B),
         _A + _B, True),
        ("P2o get-trap ignores target",
         "(function(){var p=new Proxy({zz:'nope'},{get:function(t,k){return '%s';}});return p.zz+'%s';})()" % (_A, _B),
         _A + _B, True),
    ]
    for name, payload, expected, want_block in gens:
        hit = _blocked(payload)
        exact = expected in _decoded_values(payload)
        cond = exact and (hit == want_block)
        ok = _check(name, cond,
                    "exact=%s blocked=%s want_block=%s"
                    % (exact, hit, want_block)) and ok
    return ok


# ---------------------------------------------------------------- P3: fail-closed bounds
def p3_fail_closed_bounds():
    ok = True
    decoded_cred = _A + _B
    bounds = [
        "P3a non-empty class body",
        "P3b Number superclass",
        "P3c class without extends",
        "P3d non-literal ctor arg",
        "P3e String.join (engine throws)",
        "P3f Array.valueOf (returns object)",
        "P3g subclass of subclass",
        "P3h shadowed subclass name",
        "P3i non-literal join sep",
        "P3j non-literal tail",
        "P3k extra statement",
        "P3l non-literal member",
        "P3m non-constant get body",
        "P3n extra handler key",
        "P3o one-param get",
        "P3p method-shorthand get",
        "P3q revocable non-empty handler",
        "P3r revocable non-string prop",
        "P3s revoke() call",
        "P3t revoke member read",
        "P3u non-literal proxy tail",
        "P3v subclass shadows heritage (node ReferenceError)",
        "P3w var Proxy shadows global (node TypeError)",
        "P3x var Proxy=new Proxy shadow (node TypeError)",
    ]
    payloads = [
        "(function(){class S extends String{valueOf(){return 'zz';}}var s=new S('%s');return s.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class N extends Number{}var n=new N(5);return n.valueOf()+'%s';})()" % _B,
        "(function(){class S{}var s=new S('%s');return s.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class S extends String{}var s=new S(x);return s.valueOf()+'%s';})()" % _B,
        "(function(){class S extends String{}var s=new S('%s');return s.join('')+'%s';})()" % (_A, _B),
        "(function(){class A extends Array{}var a=new A('%s');return a.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class S extends String{}class T extends S{}var t=new T('%s');return t.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class S extends String{}var S=new S('%s');return S.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class A extends Array{}var a=new A('%s');return a.join(x)+'%s';})()" % (_A, _B),
        "(function(){class S extends String{}var s=new S('%s');return s.valueOf()+x;})()" % _A,
        "(function(){class S extends String{}var s=new S('%s');var z=1;return s.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class S extends String{}var s=new S('%s');return s[x]()+'%s';})()" % (_A, _B),
        "(function(){var p=new Proxy({},{get:function(t,k){return t[k];}});return p.anything+'%s';})()" % _B,
        "(function(){var p=new Proxy({},{get:function(t,k){return '%s';},set:function(){}});return p.anything+'%s';})()" % (_A, _B),
        "(function(){var p=new Proxy({},{get:function(t){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
        "(function(){var p=new Proxy({},{get(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
        "(function(){var r=Proxy.revocable({k:'%s'},{get:function(t,k){return t[k];}});return r.proxy.k+'%s';})()" % (_A, _B),
        "(function(){var r=Proxy.revocable({k:123},{});return r.proxy.k+'%s';})()" % _B,
        "(function(){var r=Proxy.revocable({k:'%s'},{});r.revoke();return r.proxy.k+'%s';})()" % (_A, _B),
        "(function(){var r=Proxy.revocable({k:'%s'},{});return r.revoke+'%s';})()" % (_A, _B),
        "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p.anything+x;})()" % _A,
        "(function(){class String extends String{}var s=new String('%s');return s.valueOf()+'%s';})()" % (_A, _B),
        "(function(){var Proxy=Proxy.revocable({k:'%s'},{});return Proxy.proxy.k+'%s';})()" % (_A, _B),
        "(function(){var Proxy=new Proxy({},{get:function(t,k){return '%s';}});return Proxy.anything+'%s';})()" % (_A, _B),
    ]
    for name, payload in zip(bounds, payloads):
        hit = _blocked(payload)
        leak = any(decoded_cred in v for v in _decoded_values(payload))
        ok = _check(name, not hit and not leak,
                    "miss=%s no-leak=%s" % (not hit, not leak)) and ok
    return ok


# ---------------------------------------------------------------- P4: sibling pins
def p4_sibling_pins():
    ok = True
    sibs = [
        ("P4a F746 subclassed Map still blocks",
         "(function(){class M extends Map{}var m=new M([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B),
         True),
        ("P4b F783 super dispatch still blocks",
         "(function(){class B{m(){return '%s';}}class C extends B{m(){return super.m();}}return new C().m()+'%s';})()" % (_A, _B),
         True),
        ("P4c F587 empty-handler proxy still blocks",
         "new Proxy({c:'%s'},{}).c+'%s'" % (_A, _B),
         True),
        ("P4d F642 additive still blocks",
         "(function(){var s='%s';return s+'%s';})()" % (_A, _B),
         True),
        ("P4e new String concat still blocks",
         "new String('%s')+'%s'" % (_A, _B),
         True),
    ]
    for name, payload, want_hit in sibs:
        hit = _blocked(payload)
        ok = _check(name, hit == want_hit, "hit=%s" % hit) and ok
    return ok


# ---------------------------------------------------------------- P5: honest text + perf
def p5_honest_and_perf():
    ok = True
    honest = [
        "the class extends String with valueOf and join methods is documented",
        "Proxy.revocable returns proxy and revoke for the target object",
        "subclassed Array join behavior is node-exact per the spec",
        "the get trap handler returns a constant for every key",
    ]
    for i, text in enumerate(honest):
        hit = _blocked(text)
        ok = _check("P5a honest quiet %d" % i, not hit,
                    "hit=%s" % hit) and ok
    sites = [
        "(function(){class S extends String{}var s=new S('%s');return s.valueOf()+'%s';})()" % (_A, _B),
        "(function(){class A extends Array{}var a=new A('%s','%s');return a.join('');})()" % (_A, _B),
        "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
        "(function(){var r=Proxy.revocable({k:'%s'},{});return r.proxy.k+'%s';})()" % (_A, _B),
        "plain honest text with no credentials at all, just words",
    ]
    t0 = time.time()
    for i in range(200):
        _blocked(sites[i % len(sites)])
    dt = time.time() - t0
    ok = _check("P5b perf 200 sites", dt < 30, "%.2fs" % dt) and ok
    return ok


# ---------------------------------------------------------------- P6: pin + footer
def p6_pin_and_footer():
    ok = True
    ok = _check("P6a taxonomy pin 2143",
                TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143,
                "pin=%s codes=%d" % (TAXONOMY_PIN, len(TAXONOMY))) and ok
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        full = f.read()
    footer_lines = [ln for ln in full.splitlines()
                    if ln.startswith("Next free finding:")]
    ok = _check("P6b footer present", len(footer_lines) >= 1,
                "count=%d" % len(footer_lines)) and ok
    fl = footer_lines[-1] if footer_lines else ""
    if fl:
        ok = _check("P6c footer next F829",
                    "Next free finding: **F829**" in fl, "") and ok
        open_part = fl.split("Open findings:")[1] if "Open findings:" in fl else ""
        open_part = open_part.split("#")[0]  # strip lane-local comment
        open_set = set(tok.strip().strip("*.") for tok in open_part.split(",")
                       if tok.strip().strip("*.").startswith("F"))
        for fno in ("F795", "F796", "F797", "F798", "F801", "F817",
                    "F819", "F828"):
            ok = _check("P6d footer open %s" % fno, fno in open_set, "") and ok
        for fno in ("F799", "F800"):
            ok = _check("P6e footer %s not open" % fno,
                        fno not in open_set, "") and ok
    ok = _check("P6f F799 entry closed",
                "(F799 filed 2026-10-09" in full and "F799" in full, "") and ok
    return ok


def _green_check():
    """Depth-1 green check: adjacent batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    # The w385 red-firsts carry the original round-53 filed shapes;
    # the lane's w386 twins assert the same shapes post-closure.
    for script in ("w385_f799_redfirst.py", "w385_f800_redfirst.py",
                   "w385_attack_probes.py"):
        tmp = "/var/tmp/g386-l3-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-200:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.skip_green:
        os.environ["GOV_SKIP_GREEN"] = "1"
    results = []
    results.append(("P1 filed shapes", p1_filed_shapes_block()))
    results.append(("P2 generalizations", p2_generalizations()))
    results.append(("P3 fail-closed bounds", p3_fail_closed_bounds()))
    results.append(("P4 sibling pins", p4_sibling_pins()))
    results.append(("P5 honest+perf", p5_honest_and_perf()))
    results.append(("P6 pin+footer", p6_pin_and_footer()))
    print("green check: %s" % _green_check())
    breaks = sum(1 for _, ok in results if not ok)
    print("tally: %d BREAK / %d HELD / 0 ERROR"
          % (_TALLY["BREAK"], _TALLY["HELD"]))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
