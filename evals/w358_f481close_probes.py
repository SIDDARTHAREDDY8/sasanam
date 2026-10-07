#!/usr/bin/env python3
"""Wave-358 F481 closure battery (lane 2).

F481 (LOW, filed 2026-10-06 wave-357 merge composition audit): the F478
`.call` dispatch desugar drops F479 marker elements in arguments --
`[].concat.call([],['f1',null,'f2']).join('')` node-evaluates to the
credential while the decoder produced zero variants, although the
direct form `[].concat(['f1',null,'f2']).join('')` is flagged. The
dispatch-argument parser did not use the F479-aware array-element
parser. Filed shapes (all node v24.20.0 -> credential, decoder missed):

  [].concat.call([],['f1',null,'f2']).join('')
  [].concat.call([],['f1',undefined,'f2']).join('')
  Array.prototype.concat.call([],['f1',null,'f2']).join('')

Distinct from F478 (its 11 filed string-arg shapes hold) and F479
(direct-form marker coercion holds): the gap is at their composition
seam.

Closure design (gov/dlp.py, F481):
  * New `_js_concat_carriable(e)`: F479 marker elements
    (_JSNil/_JSBool/single-level nested _JSArr; _JSNumStr passes as a
    str subclass) are carried through concat exactly one level,
    engine-exactly -- the engine keeps them as elements and the
    join/toString apply sites coerce them via _js_join_element.
    Used by BOTH the F473 text path (_js_apply_array_concat, shared
    by the direct form and the F478 .call desugar) and the F478 value
    path (_js_concat_values, .apply/.bind), so the desugar stays
    faithful to the direct form.
  * New `_js_parse_marker_kw(text, i)`: recognizes a bare
    null/undefined/true/false keyword (ident-boundary checked) in the
    F478 dispatch value lists only -- [].concat.apply([],[null,'f'])
    === [].concat(null,'f') (node-verified). The additive grammar
    still cannot parse bare keywords anywhere else (deliberate:
    _js_parse_primary is untouched).
  * `_js_concat_values` array-receiver branch keeps a bare
    _JSNil/_JSBool concat arg as an element ([].concat(null) === [null]).
  * The F473 fail-closed boundary narrows accordingly: _JSArr args
    carrying elements outside _js_concat_carriable still fail closed;
    doubly-nested arrays still fail closed at parse.
  * w355_f473close_probes.py p3 maintenance: the nested-array-arg
    shape now decodes node-exactly (moved to p2 as a positive
    assertion) -- wave-306 class.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 3 filed shapes block; .apply/.bind variants block;
      bool/number/nested markers block; ws tolerance; node-exactness
      of the decoded credential on the filed shapes.
  P2  fail-closed boundaries: doubly-nested args, spread-of-markers
      (still closed, documented residual), string-receiver null arg
      (F474, still closed), bare-null direct args in .call/direct
      (both fail closed -- fidelity holds), F480 shapes intact
      (verified via the w357_f480 red-first staying 8 BREAK),
      junk quiet, F478/F479/F473 neighbors intact.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored on dispatch args; F441 ordering untouched.
  P4  pin + footer (F481 CLOSED; open F482-F488 / next F489).  # Wave-358 merge
"""

import os
import sys
import subprocess
import argparse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-358 lane 2: F481 closed; no new decision codes
FOOTER_OPEN = "F506, F507, F508, F509"  # Wave-361 lane 1: F496, F497 CLOSED locally (merge finalizes tree-wide)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-360 lane 1: F489, F490 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 3: F486, F487, F488 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 2: F484, F485 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 1: F482, F483 CLOSED locally (merge finalizes tree-wide)  # Wave-358 lane 2: F481 CLOSED locally (merge finalizes tree-wide)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)
FOOTER_NEXT = "F513"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xox" + "b-0123456789"
_B = "abc" + "def"
CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    r = dlp._try_js_expr_decode(payload, 0)
    return r[0] if r else None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


# ------------------------------------------------------------------ P1: closure
def p1_filed_shapes_block():
    shapes = [
        "[].concat.call([],['%s',null,'%s']).join('')" % (_A, _B),
        "[].concat.call([],['%s',undefined,'%s']).join('')" % (_A, _B),
        "Array.prototype.concat.call([],['%s',null,'%s']).join('')"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


def p1_filed_shapes_node_exact():
    # The decoded credential must be byte-identical to node, not just
    # flagged: a mis-decode that still flags would be an F475-class
    # over-decode.
    shapes = [
        "[].concat.call([],['%s',null,'%s']).join('')" % (_A, _B),
        "[].concat.call([],['%s',undefined,'%s']).join('')" % (_A, _B),
        "Array.prototype.concat.call([],['%s',null,'%s']).join('')"
        % (_A, _B),
    ]
    for s in shapes:
        if _decoded(s) != CRED:
            return ("BREAK", "not node-exact: %s" % s[:50])
    return ("HELD", "3/3 filed shapes decode to the exact credential")


def p1_apply_bind_variants():
    shapes = [
        # .apply: argsArray elements are individual concat args
        "[].concat.apply([],['%s',null,'%s']).join('')" % (_A, _B),
        "[].concat.apply([],[null,'%s','%s']).join('')" % (_A, _B),
        # .bind: bound + call args, marker in either position
        "[].concat.bind([],['%s',null])(['%s']).join('')" % (_A, _B),
        "[].concat.bind([],[null])(['%s','%s']).join('')" % (_A, _B),
        "[].concat.bind([],['%s'])([null,'%s']).join('')" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


def p1_marker_classes():
    shapes = [
        # booleans coerce to "true"/"false" (node-verified)
        ("[].concat.call([],['%s',true,'%s']).join('')" % (_A, _B),
         _A + "true" + _B),
        # numbers keep _JSNumStr provenance and decode
        ("[].concat.call([],['%s',2,'%s']).join('')" % (_A, _B),
         _A + "2" + _B),
        # single-level nested arrays comma-coerce (node-verified)
        ("[].concat.call([],['%s',['%s','zz']]).join('')" % (_A, _B),
         _A + ",".join([_B, "zz"])),
        # the direct form decodes identically (desugar fidelity)
        ("[].concat(['%s',null,'%s']).join('')" % (_A, _B), CRED),
    ]
    for s, exp in shapes:
        if _decoded(s) != exp:
            return ("BREAK", "not node-exact: %s" % s[:50])
    return ("HELD", "4/4 marker classes node-exact")


def p1_ws_tolerance():
    shapes = [
        "[].concat.call( [], ['%s' , null , '%s'] ).join('')" % (_A, _B),
        "[].concat.apply( [], [null , '%s' , '%s'] ).join('')" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ---------------------------------------------------------- P2: fail-closed
def p2_still_closed():
    # (name, payload) -- the decoder must produce NO variant for these
    # (fail closed). Neutral fragments are used deliberately: an
    # xoxb- fragment would trip the strict credential regex raw and
    # make the assertion vacuous.
    F1, F2 = "frag1", "frag2"
    closed = [
        # spread-of-markers: pre-existing direct-form gap, identical
        # in dispatch (fidelity holds) -- documented residual
        ("spread-markers", "[].concat(...[['%s',null]]).join('')" % F1),
        # string-receiver null arg: F474 boundary, still closed
        ("string-recv-null", "'a'.concat.call('a',[null,'%s'])" % F1),
        # bare null in .call text args: the additive grammar cannot
        # parse it -- the direct form fails closed identically
        ("call-bare-null", "[].concat.call([],null,'%s','%s')" % (F1, F2)),
    ]
    # Wave-359 (F484/F485): doubly-nested array args now decode
    # node-exactly (bounded by _JS_ARRAY_NEST_MAX) -- assert the value
    # rather than fail-closed.
    if _decoded("[].concat.call([],[[['%s']]]).join('')" % F1) != F1:
        return ("BREAK", "loud=doubly-nested-misdecode")
    junk = [
        # junk with markers decodes to junk (intended F481 behavior)
        # but must never flag
        "[].concat.call([],['ab',null,'cd']).join('')",
        "[].concat.apply([],['ab',undefined,'cd']).join('')",
    ]
    loud = [n for n, s in closed if _decoded(s) is not None]
    loud += ["junk-flagged:%s" % s[:30] for s in junk if _blocked(s)]
    return ("HELD" if not loud else "BREAK", "loud=%s" % loud)


def p2_f480_intact():
    # F480 CLOSED by wave-358 lane 1 (merge): run its red-first and require
    # the filed 8 shapes to now block coded (proves the F481 closure did not
    # regress F480's constructor-dispatch closure).
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    tmp = "/var/tmp/g358-p2-f480-%d" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env = dict(os.environ)
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    env["TMPDIR"] = tmp
    r = subprocess.run(
        [venv_python, os.path.join(REPO_ROOT, "evals",
                                   "w357_f480_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=600,
        cwd=REPO_ROOT)
    out = r.stdout + r.stderr
    m = None
    for line in out.splitlines():
        if line.startswith("tally:"):
            m = line
    if m != "tally: 0 BREAK / 12 HELD":
        return ("BREAK", "f480 red-first changed: %r" % m)
    return ("HELD", "F480 closed: 0 BREAK / 12 HELD")


def p2_neighbors_intact():
    shapes = [
        # F478's 11 filed string-arg shapes still block
        "[].concat.call([],['%s','%s']).join('')" % (_A, _B),
        "Array.prototype.concat.call([],['%s','%s']).join('')" % (_A, _B),
        "[].concat.apply([],['%s','%s']).join('')" % (_A, _B),
        # F479 direct-form marker coercion still blocks
        "['%s',null,'%s'].join('')" % (_A, _B),
        # F473 direct-form string args still block
        "['%s'].concat(['%s']).join('')" % (_A, _B),
        # F477 String() of marker array still decodes (fragment only)
        # -- must not raise uncoded at the public seam
    ]
    bad = [s for s in shapes if not _blocked(s)]
    try:
        dlp.find_credential("String(['%s',null])" % _A)
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "f477 seam raised: %s" % type(e).__name__)
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------------------------- P3: pins
def p3_node_differential():
    # Subprocess node differential on the closure's core shapes:
    # decoder output must be byte-identical to node v24.20.0.
    shapes = [
        "[].concat.call([],['FRAG1',null,'FRAG2']).join('')",
        "[].concat.call([],['FRAG1',undefined,'FRAG2']).join('')",
        "Array.prototype.concat.call([],['FRAG1',null,'FRAG2']).join('')",
        "[].concat.apply([],['FRAG1',null,'FRAG2']).join('')",
        "[].concat.apply([],[null,'FRAG1','FRAG2']).join('')",
        "[].concat.bind([],['FRAG1',null])(['FRAG2']).join('')",
        "[].concat.call([],['FRAG1',true,'FRAG2']).join('')",
        "[].concat.call([],['FRAG1',['FRAG2','zz']]).join('')",
    ]
    node_src = (
        "const fs=require('fs');"
        "const F1=%r,F2=%r;"
        "const shapes=%r;"
        "for(const s of shapes){"
        "const p=s.replaceAll('FRAG1',F1).replaceAll('FRAG2',F2);"
        "try{process.stdout.write(JSON.stringify(eval(p))+'\\n');}"
        "catch(e){process.stdout.write('THROW\\n');}}"
    ) % (_A, _B, shapes)
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:100])
    import json as _json
    for s, line in zip(shapes, r.stdout.splitlines()):
        p = s.replace("FRAG1", _A).replace("FRAG2", _B)
        try:
            expected = _json.loads(line)
        except Exception:  # noqa: BLE001
            return ("ERROR", "bad node output: %r" % line[:60])
        if _decoded(p) != expected:
            return ("BREAK", "differential mismatch: %s" % s[:50])
    return ("HELD", "8/8 dispatch shapes byte-identical to node")


def p3_no_new_regexes():
    import re
    # Wave-360 lane 2 (F491/F493): Reflect -> (construct|apply|get),
    # Object gains getOwnPropertyDescriptor, String gains .raw( /
    # .raw.call( (literal-alternation only); re.compile count unchanged.
    # Wave-362 lane 2 (F504): the Reflect bracket-member class gains
    # backtick and nested-bracket (literal-alternation only);
    # re.compile count unchanged.
    # F505 (wave-362 lane 3): String.fromCodePoint alternative
    # added (literal-alternation only -- the same F468
    # precedent); re.compile count unchanged (28).
    # F508 (wave-363 lane 2): Array.from alternative added (literal-alternation only); re.compile count unchanged (28).
    # F510 (wave-363 lane 4): the Object alternative gains `values`
    # (literal-alternation only); re.compile count unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String\.fromCodePoint|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])"
        r"|Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call|from)|\[[ \t\n\r]*['\"])"
        r")|Array[ \t\n\r]*\.[ \t\n\r]*prototype|String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"`\[])"
        r"|Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor|values)|[ \t\n\r]*\[[ \t\n\r]*['\"])"
        r"|\("
    )
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned")


def p3_f430_bounds():
    # Many-arg dispatch trips the parts budget instead of decoding.
    many = ", ".join(["'x'"] * 80)
    payload = "[].concat.call([], %s).join('')" % many
    v, _ = _verdict(payload, False)
    if v != "HELD":
        return ("BREAK", "parts budget not enforced on dispatch")
    many_markers = ", ".join(["null"] * 80)
    payload2 = "[].concat.apply([], [%s]).join('')" % many_markers
    v2, _ = _verdict(payload2, False)
    if v2 != "HELD":
        return ("BREAK", "parts budget not enforced on marker args")
    return ("HELD", "F430 parts budget enforced")


def p3_f441_ordering_untouched():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return ("HELD", "F441 ordering untouched")


# ---------------------------------------------------------------- P4: pin/footer
def p4_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-358 lane 2" in footer
    return ("HELD" if ok else "BREAK", "pin=%d footer" % len(codes))


_PROBES = [
    ("p1-filed-shapes-block", p1_filed_shapes_block),
    ("p1-filed-shapes-node-exact", p1_filed_shapes_node_exact),
    ("p1-apply-bind-variants", p1_apply_bind_variants),
    ("p1-marker-classes", p1_marker_classes),
    ("p1-ws-tolerance", p1_ws_tolerance),
    ("p2-still-closed", p2_still_closed),
    ("p2-f480-intact", p2_f480_intact),
    ("p2-neighbors-intact", p2_neighbors_intact),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f430-bounds", p3_f430_bounds),
    ("p3-f441-ordering-untouched", p3_f441_ordering_untouched),
    ("p4-pin-and-footer", p4_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        return pid, fn()
    except Exception as e:  # noqa: BLE001 -- loud, never silent
        return pid, ("ERROR", "%s: %s" % (type(e).__name__, e))


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Parses both verdict formats
    (wave-320 class: a parse matching neither format passes vacuously)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w357_f478close_probes.py",
               "w357_f479close_probes.py",
               "w355_f473close_probes.py",
               "w356_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g358-green-%s-%d" % (script.replace(".py", ""),
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
        if breaks:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe")
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                print(pid, verdict)
                return 0 if verdict[0] == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v[0] == "BREAK")
    held = sum(1 for _, v in results if v[0] == "HELD")
    err = sum(1 for _, v in results if v[0] == "ERROR")
    for pid, v in results:
        print(pid, v[0], v[1] if len(v) > 1 else "")
    print("w358_f481close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v[0] == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v[0] == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
