#!/usr/bin/env python3
"""Wave-355 F473 closure battery (lane 1 takeover).

F473 (LOW, filed 2026-10-06 wave-354 lane 5, attack round 22): the
array-receiver paren .concat bypassed the bounded static JS-expression
decoder -- ['frag1'].concat(['frag2']).join(''),
[].concat(...['frag1'],...['frag2']).join(''),
['frag1','frag2'].concat([]).join(''),
Array(1).fill('frag1').concat('frag2').join('') and
Array(1).fill('frag1').concat(...['frag2']).join('') all node-evaluate
to the credential, but the decoder's paren-concat branch failed closed
on _JSArr receivers ("method on unjoined array") -- a deliberate
boundary that real engines do not share. Distinct from F462
(string-receiver spread concat, closed wave-353): this is the
ARRAY-receiver class. Correction to the round-21 scope note: the
[].concat(...Array(1).fill('a'),...) miss was attributed to F462's
spread mechanism; the miss is the array receiver, i.e. this finding's
mechanism.

Closure design (gov/dlp.py, F473): `_js_apply_array_concat` models
engine-exact Array.prototype.concat on a parsed string array, returning
a fresh _JSArr so the chain continues into .join/.map/.filter/etc.
String args are appended as-is; array args are appended element-wise
exactly one level deep; ...spread args expand in engine order reusing
the F462 spread machinery (spread target parses as a primary;
non-array spreads and non-string spread elements fail closed). Each
appended element charges the F430 parts budget via `_js_add_concat_part`,
exactly like the string-receiver form. Wired into `_js_apply_method`
BEFORE the "method on unjoined array" guard, and into
`_js_apply_tag_method` (array-receiver tag concat == .concat(cooked)).

Fail closed (node-verified): nested-array args beyond one level (the
decoder's domain is flat string arrays), args that are neither str nor
_JSArr (numbers stringify in node but the decoder refuses -- the
conservative direction), spread of non-arrays (including spread of
strings -- filed separately as F475 by the parallel lane 3 tree; this
battery pins it quiet), and _JSArr args carrying non-string elements.
An explicit type check on every arg keeps this branch free of the
F474-class uncaught TypeError. No new regexes; never evals.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 5 filed F473 shapes block (lit-arr concat lit-arr,
      empty concat spreads, lit-arr concat empty, fill concat str-arg,
      fill concat spread-arg).
  P2  compositions: multi-array args, receiver from Reflect.construct
      (F468), receiver from spread-copy (F471), zero-arg concat,
      tagged-template concat on array receiver (F463 x F473).
  P3  fail-closed: nested-array arg, numeric arg (node stringifies;
      decoder refuses), spread-of-string (F475, stays quiet here),
      non-parsed receiver, concat on number receiver.
  P4  discrimination: honest array-concat text quiet; junk quiet.
  P5  ReDoS: hostile inputs complete fast, zero exceptions.
  P6  no-regression: adjacent closures still block (F462, F468, F471,
      F434, F443, F463).
  P7  pin (2135) and footer state.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"
CRED = A1 + A2

TAXONOMY_PIN = 2135  # Wave-355: F473 closed; F475 filed; no new decision codes


def _hit(payload):
    return find_credential(payload) is not None


def _safe(pid, fn):
    try:
        ok, note = fn()
    except Exception as e:  # noqa: BLE001
        return pid, "ERROR"
    return pid, ("HELD" if ok else "BREAK")


# ---------------------------------------------------------------- P1: closure
def p1_filed_shapes_block():
    shapes = [
        "['%s'].concat(['%s']).join('')" % (A1, A2),
        "[].concat(...['%s'],...['%s']).join('')" % (A1, A2),
        "['%s','%s'].concat([]).join('')" % (A1, A2),
        "Array(1).fill('%s').concat('%s').join('')" % (A1, A2),
        "Array(1).fill('%s').concat(...['%s']).join('')" % (A1, A2),
    ]
    bad = [s for s in shapes if not _hit(s)]
    return (not bad, "missed=%d" % len(bad))


# ---------------------------------------------------------- P2: compositions
def p2_compositions_block():
    shapes = [
        # multi-array args
        "['%s'].concat(['%s'],['zz']).join('')" % (A1, A2),
        # receiver from Reflect.construct (F468)
        "Reflect.construct(Array,['%s']).concat(['%s']).join('')"
        % (A1, A2),
        # receiver from spread-copy (F471)
        "[...['%s']].concat(['%s']).join('')" % (A1, A2),
        # receiver from Array(N) constructor (F454)
        "Array('%s').concat(['%s']).join('')" % (A1, A2),
        # zero-arg concat (identity)
        "['%s','%s'].concat().join('')" % (A1, A2),
        # tagged-template concat on array receiver (F463 x F473)
        "['%s'].concat`%s`.join('')" % (A1, A2),
        # concat result feeds .slice (F466)
        "['%s'].concat(['%s']).slice(0,2).join('')" % (A1, A2),
        # concat result feeds .reverse (F461)
        "['%s','%s'].reverse().concat(['zz']).join('')" % (A2, A1),
    ]
    bad = [s for s in shapes if not _hit(s)]
    return (not bad, "missed=%d" % len(bad))


# ------------------------------------------------------------ P3: fail-closed
def p3_fail_closed():
    # (name, payload) -- all must stay quiet (no decode variant)
    shapes = [
        ("nested-array-arg", "['%s'].concat([['%s']]).join('')" % (A1, A2)),
        ("numeric-arg", "['%s'].concat(1).join('')" % A1),
        ("spread-of-string", "['%s'].concat(...'%s').join('')" % (A1, A2)),
        ("spread-of-number", "['%s'].concat(...1).join('')" % A1),
        ("concat-non-array-spread", "['%s'].concat(...{}).join('')" % A1),
        ("bool-arg", "['%s'].concat(true).join('')" % A1),
    ]
    loud = [n for n, s in shapes if _hit(s)]
    return (not loud, "loud=%s" % loud)


# --------------------------------------------------------- P4: discrimination
def p4_discrimination():
    honest = [
        "the docs say ['a'].concat(['b']) joins arrays",
        "Array.prototype.concat appends its arguments",
        "['x','y'].concat(['z']) is ordinary JS",
        "see the changelog for concat behavior",
    ]
    loud = [s for s in honest if _hit(s)]
    junk_quiet = not _hit("['ab'].concat(['cd']).join('')")
    return (not loud and junk_quiet, "loud=%d junk_quiet=%s"
            % (len(loud), junk_quiet))


# ------------------------------------------------------------------ P5: ReDoS
def p5_redos():
    hostile = [
        "[" + "'a'," * 200,
        "['a']" + ".join('')" * 60,
        "Array.of(" + "'a'," * 100,
        "xoxb-" + "a" * 5000,
    ]
    t0 = time.time()
    for h in hostile:
        try:
            find_credential(h)
        except Exception:  # noqa: BLE001
            return (False, "raised")
    dt = time.time() - t0
    return (dt < 5.0, "dt=%.2fs" % dt)


# ---------------------------------------------------------- P6: no-regression
def p6_noreg():
    shapes = [
        ("f462", "''.concat(...['%s','%s'])" % (A1, A2)),
        ("f468", "Reflect.construct(Array,['%s','%s']).join('')" % (A1, A2)),
        ("f471-spreadcopy", "[...['%s','%s']].join('')" % (A1, A2)),
        ("f471-objassign", "Object.assign([],['%s','%s']).join('')"
         % (A1, A2)),
        ("f434", "['%s','%s'].join('')" % (A1, A2)),
        ("f443", "Array(2).fill('%s').join('')" % A1),
        ("f463-tag", "['%s','%s'].join` `" % (A1, A2)),
        ("f469", "Reflect.apply(Array.prototype.concat,[],"
         "[['%s'],['%s']]).join('')" % (A1, A2)),
    ]
    bad = [n for n, s in shapes if not _hit(s)]
    return (not bad, "regressed=%s" % bad)


# ---------------------------------------------------------- P7: pin + footer
def p7_pin_and_footer():
    import gov.decision_codes as dc
    codes = sorted(dc.TAXONOMY.keys())
    ok = (len(codes) == TAXONOMY_PIN == 2135 and
          codes == sorted(set(codes)))
    t = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Multiple historical footers exist; the live one is the LAST match.
    matches = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                         r"\*\*Open findings: ([^*]*)\.\*\*", t)
    if not matches:
        return (False, "footer not found")
    nxt, open_s = matches[-1][0], matches[-1][1].strip()
    # This lane: F473 CLOSED. Merged: F473-F475 CLOSED; F476, F477 OPEN.
    ok = ok and nxt == "F478" and open_s == "F476, F477"
    return (ok, "nxt=%s open=%s" % (nxt, open_s))


_PROBES = [
    ("p1-filed-shapes-block", p1_filed_shapes_block),
    ("p2-compositions-block", p2_compositions_block),
    ("p3-fail-closed", p3_fail_closed),
    ("p4-discrimination", p4_discrimination),
    ("p5-redos-hostile-inputs", p5_redos),
    ("p6-noreg-adjacent", p6_noreg),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Parses both verdict formats
    (wave-320 class: a parse matching neither format passes vacuously)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w354_attack_probes.py",
               "w354_f469close_probes.py",
               "w354_f470close_probes.py",
               "w354_f471close_probes.py",
               "w354_f472close_probes.py",
               "w353_attack_probes.py",)
    stale_footer_ok = {}
    for script in scripts:
        if script.endswith("_redfirst.py"):
            continue
        tmp = "/var/tmp/g355-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        breaks = set()
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "BREAK" and len(parts) >= 2:
                breaks.add(parts[1].rstrip(":"))
            elif len(parts) >= 2 and parts[1] == "BREAK":
                breaks.add(parts[0])
        if not breaks and r.returncode != 0:
            raise AssertionError("green check failed: could not parse any "
                                 "probe verdicts from child output: %s"
                                 % notes[-1])
        if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
            raise AssertionError("green check failed: %s" % notes[-1])
        allowed = stale_footer_ok.get(script, set())
        if not breaks <= allowed:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
        if breaks:
            notes.append("tolerated stale footer probe: %s" % sorted(breaks))
        # A nonzero rc is expected when only the tolerated stale-footer
        # probe breaks (attack batteries return 1 on any BREAK).
        if r.returncode != 0 and not breaks <= allowed:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                print("%s: %s" % (pid2, verdict))
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    for pid, v in results:
        print("%s: %s" % (pid, v))
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w355_f473close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
