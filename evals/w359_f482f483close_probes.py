#!/usr/bin/env python3
"""Wave-359 F482+F483 closure battery (lane 1).

F482 (LOW, filed 2026-10-06 wave-358 attack round 26): bracket-string
member access on prototype methods under .call/.apply dispatch --
Array.prototype['concat'].call, [].concat['call'], and friends bypassed
the F478 dot-form dispatch anchor. All 10 filed shapes node-evaluated
(v24.20.0) to the exact credential while the decoder produced zero
variants.

F483 (LOW, filed 2026-10-06 wave-358 attack round 26): .apply/.bind
dispatch (and dispatch chains) on non-concat prototype methods -- the
wave-357 F478 closure modeled .call for all methods but .apply/.bind
for concat only (documented residual). All 11 filed shapes
node-evaluated to the exact credential while the decoder missed.

Closure design (gov/dlp.py, F482+F483):
  * F482: `_js_peek_dispatch_call` accepts the bracket-string dispatch
    name (`['call']`/`['apply']`/`['bind']`, engine-identical to the
    dot form); `_js_parse_prototype_dispatch` accepts
    `X.prototype['METHOD']`; `_js_parse_postfix_dispatch` accepts
    `EXPR['METHOD']` (no conflict: bracket access on values was fully
    fail-closed before).
  * F483: `_js_parse_dispatch_value` parses one dispatch value
    (marker keyword, unary-minus numeric, additive, or a callback
    token whose grammar is fixed by the dispatched method -- never
    guessed); `_js_parse_value_list` gains `...` spread and a cb_kind
    parameter; `_js_apply_method_values` mirrors each method's
    direct-form rules over values (join/slice/reduce/reduceRight/map/
    filter via shared `_js_reduce_fold` / `_js_filter_spec_apply`
    helpers extracted from the direct branches -- zero divergence);
    `_js_apply_fn_dispatch` models .apply/.bind for every method plus
    the bind-then-dispatch chain (`T.bind(R,b...).call(_,c...)`);
    `_js_parse_function_dispatch` models double dispatch
    (`Function.prototype.call.call(F,R,...)` and the apply variants);
    the anchor gains the `Function.prototype` alternative
    (character-class-only; re.compile stays 28).
  * Documented residuals: `String.prototype.replace.apply` (a regex
    pattern cannot arrive as a dispatch value; the .call text form
    still covers replace); `EXPR['METHOD']` on non-dispatch members
    still ends the chain per F461.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all 10 F482 + all 11 F483 filed shapes block coded and
      decode byte-identical to node; bracket dispatch names; ws
      tolerance.
  P2  fail-closed boundaries: unmodeled members, undefined targets,
      replace-apply residual, bind without call, bad double dispatch,
      junk quiet, F480/F481/F486 intact, F478/F479 neighbors intact.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored on dispatch args; F441 ordering untouched.
  P4  pin + footer (F482, F483 CLOSED; open F484-F488 / next F489).
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

TAXONOMY_PIN = 2140  # Wave-359 lane 1: F482, F483 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F640, F641, F642, F643"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-367 merge: F537-F546 open (next F547)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-359 lane 1: F482, F483 CLOSED locally (merge finalizes tree-wide)  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
FOOTER_NEXT = "F644"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"
CRED = A1 + A2


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    r = dlp._try_js_expr_decode(payload, 0)
    return r[0] if r else None


# ------------------------------------------------------------------ P1: closure
_F482_SHAPES = [
    "Array.prototype['concat'].call([], '%s','%s').join('')",
    "Array.prototype['join'].call(['%s','%s'], '')",
    "Array.prototype['slice'].call(['%s','%s'], 0, 2).join('')",
    "Array.prototype['concat'].apply([], ['%s','%s']).join('')",
    "String.prototype['concat'].call('%s','%s')",
    "Array.prototype['filter'].call(['%s','%s',''], x=>x!=='').join('')",
    "Array.prototype['slice'].call(['%s','%s'], 0).join('')",
    "[].concat['call']([], '%s','%s').join('')",
    "Array.prototype.concat['apply']([], ['%s','%s']).join('')",
    "Array.prototype['join'].call(['%s',null,'%s'], '')",
]

_F483_SHAPES = [
    "Array.prototype.join.apply(['%s','%s'], [''])",
    "Array.prototype.slice.apply(['%s','%s'], [0,2]).join('')",
    "Array.prototype.filter.apply(['%s','%s',''], [x=>x!=='']).join('')",
    "Array.prototype.map.bind(['%s','%s'], String)().join('')",
    "Array.prototype.reduce.bind(['%s','%s'], (a,c)=>a+c, '')()",
    "Array.prototype.join.bind(['%s','%s'], '')()",
    "Array.prototype.slice.bind(['%s','%s'], 0, 2)().join('')",
    "Array.prototype.filter.bind(['%s','%s',''], x=>x!=='')().join('')",
    "Array.prototype.concat.apply([], [...['%s','%s']]).join('')",
    "Function.prototype.call.call(Array.prototype.concat, [], '%s','%s').join('')",
    "String.prototype.concat.bind('%s').call(null, '%s')",
]


def _shapes_filled(shapes):
    # Alternate A1/A2 across the %s slots.
    out = []
    for s in shapes:
        n = s.count("%s")
        vals = tuple((A1, A2) * ((n + 1) // 2))[:n]
        out.append(s % vals)
    return out


def p1_f482_filed_shapes_block():
    bad = [s for s in _shapes_filled(_F482_SHAPES) if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


def p1_f482_node_exact():
    for s in _shapes_filled(_F482_SHAPES):
        if _decoded(s) != CRED:
            return ("BREAK", "not node-exact: %s" % s[:55])
    return ("HELD", "10/10 F482 filed shapes decode to the exact credential")


def p1_f483_filed_shapes_block():
    bad = [s for s in _shapes_filled(_F483_SHAPES) if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


def p1_f483_node_exact():
    for s in _shapes_filled(_F483_SHAPES):
        if _decoded(s) != CRED:
            return ("BREAK", "not node-exact: %s" % s[:55])
    return ("HELD", "11/11 F483 filed shapes decode to the exact credential")


def p1_bracket_dispatch_names():
    shapes = [
        "[].concat['call']([], '%s','%s').join('')" % (A1, A2),
        "[].concat['apply']([], ['%s','%s']).join('')" % (A1, A2),
        "String.prototype.concat['bind']('%s')('%s')" % (A1, A2),
        "Array.prototype.join['apply'](['%s','%s'], [''])" % (A1, A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


def p1_ws_tolerance():
    shapes = [
        "Array . prototype [ 'concat' ] . call( [], '%s' , '%s' ).join('')" % (A1, A2),
        "Array.prototype.join.apply( ['%s' , '%s'] , [''] )" % (A1, A2),
        "Function . prototype . call . call( Array.prototype.concat , [] , '%s' , '%s' ).join('')" % (A1, A2),
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
        # unmodeled method under dispatch: not a dispatch target
        ("unmodeled-member", "Array.prototype['sort'].call(['%s'])" % F1),
        # undefined target: Array.prototype.replace does not exist
        ("undefined-target", "Array.prototype['replace'].call('a,b', 'x')"),
        # join on a non-array receiver
        ("join-nonarray", "Array.prototype.join.apply('ab', [''])"),
        # replace via .apply: a regex pattern cannot arrive as a
        # dispatch value (documented residual)
        ("replace-apply", "String.prototype.replace.apply('a,b', ['x',''])"),
        # bind without an immediate call or chain: not a value
        ("bind-no-call", "String.prototype.concat.bind('%s')" % F1),
        # double dispatch on a non-target
        ("dbl-bad-target", "Function.prototype.call.call(x, [], '%s')" % F1),
        # double dispatch with a non-dispatch outer member
        ("dbl-bad-outer", "Function.prototype.call.bind(Array.prototype.concat)"),
        # double dispatch with malformed args
        ("dbl-bad-args", "Function.prototype.call.call(Array.prototype.concat)"),
        # triple dispatch (beyond one level): fails closed, documented
        ("dbl-triple", "Function.prototype.call.call.call(Array.prototype.concat, [], '%s')" % F1),
        # bind-then-dispatch with a bad chain member
        ("chain-bad-member", "String.prototype.concat.bind('a').sort('b')"),
    ]
    junk = [
        "Array.prototype['concat'].call([], 'ab','cd').join('')",
        "Array.prototype.join.apply(['ab','cd'], [''])",
        "Function.prototype.call.call(Array.prototype.concat, [], 'ab','cd').join('')",
    ]
    loud = [n for n, s in closed if _decoded(s) is not None]
    loud += ["junk-flagged:%s" % s[:30] for s in junk if _blocked(s)]
    return ("HELD" if not loud else "BREAK", "loud=%s" % loud)


def p2_f480_f481_intact():
    # F480/F481 CLOSED on this base: their red-first batteries must
    # show 0 BREAK (proves this lane did not regress them).
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    for script, want in (("w357_f480_redfirst.py", "tally: 0 BREAK / 12 HELD"),
                         ("w357_f481_redfirst.py", None)):
        tmp = "/var/tmp/g359-p2-%s-%d" % (script.replace(".py", ""), os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        m = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                m = line
        if want is not None and m != want:
            return ("BREAK", "%s changed: %r" % (script, m))
        if want is None and (m is None or "BREAK" in (m.split("/")[0])):
            # f481 red-first: require zero BREAKs on the closed tree
            if m is None or not m.startswith("tally: 0 BREAK"):
                return ("BREAK", "%s changed: %r" % (script, m))
    return ("HELD", "F480/F481 red-first intact")


def p2_f486_intact():
    # F486 is now CLOSED (wave-359 lane 3): static-factory dispatch
    # shapes must block. (Lane-1 version asserted they stayed open;
    # updated at the wave-359 merge.)
    shapes = [
        "Array.of.call([], '%s','%s').join('')" % (A1, A2),
        "[].constructor.of.call([].constructor, '%s','%s').join('')" % (A1, A2),
    ]
    quiet = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not quiet else "BREAK", "missed=%d" % len(quiet))


def p2_neighbors_intact():
    shapes = [
        # F478's dot-form dispatch still blocks
        "[].concat.call([], '%s','%s').join('')" % (A1, A2),
        "Array.prototype.concat.call([], '%s','%s').join('')" % (A1, A2),
        # F479 direct-form marker coercion still blocks
        "['%s',null,'%s'].join('')" % (A1, A2),
        # F480 constructor dispatch still blocks
        "Array.apply(Array,['%s','%s']).join('')" % (A1, A2),
        # F481 marker carriage still blocks
        "[].concat.call([],['%s',null,'%s']).join('')" % (A1, A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------------------------- P3: pins
def p3_node_differential():
    # Subprocess node differential on the closure's core shapes:
    # decoder output must be byte-identical to node v24.20.0.
    shapes = [
        "Array.prototype['concat'].call([], 'FRAG1','FRAG2').join('')",
        "Array.prototype['join'].call(['FRAG1','FRAG2'], '')",
        "Array.prototype['filter'].call(['FRAG1','FRAG2',''], x=>x!=='').join('')",
        "[].concat['call']([], 'FRAG1','FRAG2').join('')",
        "Array.prototype.join.apply(['FRAG1','FRAG2'], [''])",
        "Array.prototype.slice.apply(['FRAG1','FRAG2'], [0,2]).join('')",
        "Array.prototype.slice.apply(['FRAG1','FRAG2'], [-1]).join('')",
        "Array.prototype.reduce.bind(['FRAG1','FRAG2'], (a,c)=>a+c, '')()",
        "Array.prototype.map.bind(['FRAG1','FRAG2'], String)().join('')",
        "Array.prototype.concat.apply([], [...['FRAG1','FRAG2']]).join('')",
        "Function.prototype.call.call(Array.prototype.concat, [], 'FRAG1','FRAG2').join('')",
        "String.prototype.concat.bind('FRAG1').call(null, 'FRAG2')",
        "Array.prototype.join.apply(['FRAG1',null,'FRAG2'], [''])",
    ]
    node_src = (
        "const F1=%r,F2=%r;"
        "const shapes=%r;"
        "for(const s of shapes){"
        "const p=s.replaceAll('FRAG1',F1).replaceAll('FRAG2',F2);"
        "try{process.stdout.write(JSON.stringify(eval(p))+'\\n');}"
        "catch(e){process.stdout.write('THROW\\n');}}"
    ) % (A1, A2, shapes)
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:100])
    import json as _json
    for s, line in zip(shapes, r.stdout.splitlines()):
        p = s.replace("FRAG1", A1).replace("FRAG2", A2)
        try:
            expected = _json.loads(line)
        except Exception:  # noqa: BLE001
            return ("ERROR", "bad node output: %r" % line[:60])
        if expected == "THROW":
            return ("ERROR", "node threw: %s" % s[:50])
        if _decoded(p) != expected:
            return ("BREAK", "differential mismatch: %s" % s[:55])
    return ("HELD", "13/13 dispatch shapes byte-identical to node")


def p3_no_new_regexes():
    import re
    # Wave-360 lane 2 (F491/F493): Reflect -> (construct|apply|get),
    # Object gains getOwnPropertyDescriptor, String gains .raw( /
    # .raw.call( (literal-alternation only); re.compile count unchanged.
    # Wave-362 lane 2 (F504): the Reflect bracket-member class gains
    # backtick and nested-bracket (literal-alternation only);
    # re.compile count unchanged. (Pin repaired: it had drifted from
    # the shipped pattern before this lane.)
    # F505 (wave-362 lane 3): String.fromCodePoint alternative
    # added (literal-alternation only -- the same F468
    # precedent); re.compile count unchanged (28).
    # F508 (wave-363 lane 2): Array.from alternative added (literal-alternation only); re.compile count unchanged (28).
    # F510 (wave-363 lane 4): the Object alternative gains `values`
    # (literal-alternation only); re.compile count unchanged (28).
    # F525 (wave-365 lane 2): the Object dot-member alternative gains
    # getOwnPropertyNames/getOwnPropertyDescriptors (key/descriptor
    # enumeration indirection) -- new member-name alternatives, pinned
    # exactly here; re.compile count unchanged (28).
    # Wave-367 lane 4 (F536): structuredClone alternative added to the anchor
    # (ident-boundary-checked; literal-alternation only); re.compile count unchanged.
    # F539 (wave-368 lane 2): the Object dot-member alternative gains
    # freeze (identity-preserving builtin on object literals) -- new
    # member-name alternative, pinned exactly here; re.compile count
    # unchanged (28).
    # F565 (wave-369 lane 5): the Object dot-member alternative gains
    # fromEntries (deserializing builtin on literal pair lists / Map)
    # -- new member-name alternative, pinned exactly here; re.compile
    # count unchanged (28).
    # Wave-369 lane 5 (F565): re-pinned to the live anchor --
    # the pin had gone stale (JSON (F541, wave-368 lane 3); new WeakRef (F539, wave-368 lane 2)
    # added without re-pin); exactness restored and the
    # fromEntries member alternative added. re.compile count
    # unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String\.fromCodePoint|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call|from)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"`\[])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor|getOwnPropertyNames|getOwnPropertyDescriptors|values|keys|entries|freeze|fromEntries)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"structuredClone(?![_$A-Za-z0-9])|JSON(?![_$A-Za-z0-9])|new[ \t\n\r]+WeakRef(?![_$A-Za-z0-9])|"
        r"\("
    )
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned")


def p3_f430_bounds():
    # Many-arg dispatch trips the parts budget instead of decoding.
    many = ", ".join(["'x'"] * 80)
    payload = "Array.prototype.join.apply(['x'], [%s])" % many
    if _decoded(payload) is not None:
        return ("BREAK", "parts budget not enforced on apply args")
    many_binds = ", ".join(["'x'"] * 80)
    payload2 = "Array.prototype.join.bind(['x'], %s)()" % many_binds
    if _decoded(payload2) is not None:
        return ("BREAK", "parts budget not enforced on bind args")
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
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("**Open findings: %s.**" % FOOTER_OPEN) in footer  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    ok = ok and "CLOSED 2026-10-06 wave-359 lane 1" in footer
    return ("HELD" if ok else "BREAK", "pin=%d footer" % len(codes))


_PROBES = [
    ("p1-f482-filed-shapes-block", p1_f482_filed_shapes_block),
    ("p1-f482-node-exact", p1_f482_node_exact),
    ("p1-f483-filed-shapes-block", p1_f483_filed_shapes_block),
    ("p1-f483-node-exact", p1_f483_node_exact),
    ("p1-bracket-dispatch-names", p1_bracket_dispatch_names),
    ("p1-ws-tolerance", p1_ws_tolerance),
    ("p2-still-closed", p2_still_closed),
    ("p2-f480-f481-intact", p2_f480_f481_intact),
    ("p2-f486-intact", p2_f486_intact),
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
    scripts = ("w358_attack_probes.py",
               "w358_f480close_probes.py",
               "w358_f481close_probes.py",
               "w357_f478close_probes.py",
               "w357_f479close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g359-green-%s-%d" % (script.replace(".py", ""),
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
    print("w359_f482f483close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
