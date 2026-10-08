#!/usr/bin/env python3
"""Wave-366 F527/F530 closure battery (lane 2).

Two LOW findings, both OPEN on the wave-365-merged base (node
v24.20.0 -> credential, decoder missed):

F527: quadruple-nested bracket member keys on string receivers.
  F515 models double-nested array-index-folded keys
  ([['concat'][0]]) and F523 models the triple-nested form
  ([[[['concat'][0]]][0]]), but a FOURTH nesting level escapes the
  triple-specific fold:
    'f1'[[[[['concat'][0]]][0]][0]]('f2')
    String('f1')[[[[['concat'][0]]][0]][0]](String('f2'))
  Both node-evaluate to the exact credential. Distinct from F523
  (triple) and F515 (double) by the same depth argument F523 used
  against F515.

F530: Reflect.apply with a .bind-bound JOIN target. F521 models
  .bind-bound CONCAT targets, but the bound function can be any
  builtin -- `[].join.bind(['f1','f2'], '')` is a bound join whose
  invocation returns the joined credential directly (a string, not an
  array):
    Reflect.apply([].join.bind(['f1','f2'], ''), null, [])
    Reflect.apply.call(Reflect, [].join.bind(['f1','f2'], ''), null, [])
    Reflect.apply.bind(Reflect)([].join.bind(['f1','f2'], ''), null, [])
  All three node-evaluate to the exact credential. Distinct from F521
  (concat-family bound targets -- different builtin, different value
  shape: join returns a string; per the F500/F505 precedent different
  builtins are separate findings). Filed as F526 by wave-365 lane 1,
  renumbered to F530 at the wave-365 merge per the wave-272 rule
  (attack lane's F526 filed earlier).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * F527: `_js_parse_quad_nested_bracket_key` folds
    `[[[[['concat'][0]]][0]][0]]` node-exactly. The quad key is the
    F523 triple key re-wrapped once more and indexed again: with T =
    the triple key (engine-identical to `[['concat']]`), the quad key
    is `[[T]][0]` (node v24.20.0 verified), whose ToPropertyKey is
    `'concat'`. Tried BEFORE the triple parser in the
    `_js_parse_postfix` fallback chain (the quad parser rejects
    triple input chargeless -- its inner indexed-key entry check
    expects `[` but finds the quote; the triple parser likewise
    rejects quad input chargeless at its inner element check).
    The extra wrap layer charges one part. Fail closed: 5+ nestings,
    non-literal indices, non-zero indices, malformed structure.
  * F530: `_js_parse_f530_bound_join_target` parses
    `[].join.bind(BINDTHIS, SEP)` / `Array.prototype.join.bind(BINDTHIS,
    SEP)` (node: `[].join === Array.prototype.join`, v24.20.0). The
    `.bind` member accepts the dot form, the F490 `?.` form, and the
    F482 bracket-string form; the inner `join` member is dot-only
    (F506 precedent). BINDTHIS is an array literal or
    Array-constructor form with all-string elements (the F506 thisArg
    classes). Exactly ONE bound arg, the separator, must be a string
    literal (F454 grammar). `_js_parse_f530_bound_join_triple` parses
    `BOUND, thisArg, argsList`: thisArg is parsed and discarded (the
    bound function's this is fixed by .bind -- node-verified, F483
    precedent); argsList is a string-literal-only list (F519 grammar)
    parsed and DISCARDED (the engine ignores every join argument after
    the bound separator -- node v24.20.0 verified). The result is the
    separator-joined STRING (join returns a string directly, unlike
    F521's concat which yields an array).
  * Three dispatch sites route to the F530 triple:
    - direct: `_js_parse_reflect_call` gains a "boundjoin" target
      class in `_js_peek_reflect_apply_target` (pure lookahead for the
      `[].join.bind(` / `Array.prototype.join.bind(` head) ->
      `_js_parse_reflect_apply_bound_join`.
    - call-indirect: `_js_parse_f521_call_dispatch` falls back to the
      F530 bound-join triple when the F521 triple raises (clean: the
      F521 raise commits nothing on join input -- it rejects at the
      non-concat member check before any value parse).
    - bind-indirect: `_js_parse_f513_reflect_bind` falls back to the
      F530 bound-join triple after the F521 triple (same clean-raise
      discipline).

Fail-closed boundaries (documented): F527 -- 5+ nestings, non-literal
  or non-zero indices, malformed structure; F530 -- `.bind` on
  non-join builtins, zero bound args (separator-via-argsList), extra
  bound args, non-literal separators, non-array BINDTHIS, deeper
  `.bind` chains, unbound targets through the call-indirect form
  (documented residual -- not filed). Junk stays quiet.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2140  # Wave-366 lane 2; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f527_filed_shapes():
    shapes = [
        "'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A1, _A2),
        "String('%s')[[[[['concat'][0]]][0]][0]](String('%s'))" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F527 filed shapes block" % (len(shapes) - len(bad),
                                               len(shapes)))


def p1_f530_filed_shapes():
    shapes = [
        "Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
        "Reflect.apply.call(Reflect, [].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)([].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F530 filed shapes block" % (len(shapes) - len(bad),
                                               len(shapes)))


def p1_combos_and_variants():
    shapes = [
        # F527: whitespace tolerance (F455 class)
        "'%s' [[[[[ 'concat' ][ 0 ]]][ 0 ]][ 0 ]] ( '%s' )" % (_A1, _A2),
        # F527: double-quoted key literal (F504 indexed-fold class)
        "'%s'[[[[[\"concat\"][0]]][0]][0]]('%s')" % (_A1, _A2),
        # F527: folded inner element ('con'+'cat' -- F514 composition)
        "'%s'[[[[['con'+'cat'][0]]][0]][0]]('%s')" % (_A1, _A2),
        # F530: Array.prototype.join receiver (F469 class, node-identical)
        "Reflect.apply(Array.prototype.join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
        # F530: non-empty separator (node-exact: separator-joined)
        "Reflect.apply([].join.bind(['%s','%s'], '-'), null, [])" % (_A1, _A2),
        # F530: argsList parsed-and-ignored (engine ignores extra join args)
        "Reflect.apply([].join.bind(['%s','%s'], ''), null, ['x','y'])" % (_A1, _A2),
        # F530: whitespace tolerance
        "Reflect . apply ( [].join . bind ( [ '%s' , '%s' ] , '' ) , null , [ ] )" % (_A1, _A2),
        # F530: ?.bind dispatch member (F490 -- provably non-null)
        "Reflect.apply([].join?.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d combos/variants block" % (len(shapes) - len(bad),
                                             len(shapes)))


def p1_compositions():
    # Independence: sibling closures still hold; open findings still miss.
    pairs = [
        # F523 triple stays HELD (quad parser must not swallow it)
        ("'%s'[[[['concat'][0]]][0]]('%s')" % (_A1, _A2), True),
        # F515 double stays HELD
        ("'%s'[[['concat'][0]]]('%s')" % (_A1, _A2), True),
        # F514 array-wrapped stays HELD
        ("String('%s')[[['concat'][0]]]('%s')" % (_A1, _A2), True),
        # F507 single bracket stays HELD
        ("'%s'['concat']('%s')" % (_A1, _A2), True),
        # F521 concat-bound stays HELD (independence both directions)
        ("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2), True),
        # F506 call/apply indirection stays HELD
        ("Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')"
         % (_A1, _A2), True),
        # F519 literal function target stays HELD
        ("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2), True),
        # F469 concat target stays HELD
        ("Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (_A1, _A2), True),
        # F526 two-hop bind stays OPEN (miss)
        ("Reflect.apply([].concat.bind([],'%(a)s').bind([]), null, ['%(b)s'])"
         % {"a": _A1, "b": _A2}, False),
        # Parenthesized-arrow IIFE target: out of F522/F528 scope (not a nested
        # IIFE nor a block body); honestly OPEN (miss) -- candidate for a future
        # finding, not silently asserted.
        ("Reflect.apply((()=>((a,b)=>a+b))(), null, ['%s','%s'])" % (_A1, _A2), False),
        # F529 aliased-arguments enumeration CLOSED wave-366 lane 3
        ("(function(){var a=arguments;return Object.keys(a).map(i=>a[i]).join('')})('%s','%s')"
         % (_A1, _A2), True),
    ]
    bad = ["%s want=%s" % (p[:48], w)
           for p, w in pairs if _verdict(p, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions honest%s" % (
                len(pairs) - len(bad), len(pairs),
                "" if not bad else ": " + "; ".join(bad)))


# ------------------------------------------------- P2: fail-closed bounds
def p2_f527_bounds():
    # All must MISS (fail closed, never mis-decode).
    misses = [
        # 5 nestings: documented residual, not filed
        "'%s'[[[[[['concat'][0]]][0]][0]][0]]('%s')" % (_A1, _A2),
        # non-zero index: [1] is undefined -> different key
        "'%s'[[[[['concat'][1]]][0]][0]]('%s')" % (_A1, _A2),
        "'%s'[[[[['concat'][0]]][1]][0]]('%s')" % (_A1, _A2),
        "'%s'[[[[['concat'][0]]][0]][1]]('%s')" % (_A1, _A2),
        # non-literal index
        "'%s'[[[[['concat'][0]]][i]][0]]('%s')" % (_A1, _A2),
        # malformed: missing a close
        "'%s'[[[[['concat'][0]]][0]][0]('%s')" % (_A1, _A2),
        # junk stays quiet
        "'ab'[[[[['concat'][0]]][0]][0]]('cd')",
    ]
    bad = ["%s" % p[:48] for p in misses if _verdict(p, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F527 boundaries fail closed%s" % (
                len(misses) - len(bad), len(misses),
                "" if not bad else ": " + "; ".join(bad)))


def p2_f530_bounds():
    # All must MISS (fail closed, never mis-decode).
    misses = [
        # .bind on a non-join builtin (documented F521-scope boundary)
        "Reflect.apply([].concat.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
        "Reflect.apply([].slice.bind(['%s','%s'], ''), null, [])" % (_A1, _A2),
        # zero bound args: separator-via-argsList (documented boundary)
        "Reflect.apply([].join.bind(['%s','%s']), null, [''])" % (_A1, _A2),
        # extra bound args (documented boundary)
        "Reflect.apply([].join.bind(['%s','%s'], '', 'junk'), null, [])" % (_A1, _A2),
        # non-literal separator
        "Reflect.apply([].join.bind(['%s','%s'], 'a'+'b'), null, [])" % (_A1, _A2),
        # non-array BINDTHIS
        "Reflect.apply([].join.bind('ab', ''), null, [])",
        # two-hop bind chain (F526 stays OPEN)
        "Reflect.apply([].join.bind(['%s','%s'], '').bind([]), null, [])" % (_A1, _A2),
        # junk stays quiet
        "Reflect.apply([].join.bind(['ab','cd'], ''), null, [])",
    ]
    bad = ["%s" % p[:48] for p in misses if _verdict(p, False)[0] == "BREAK"]
    # Numeric BINDTHIS elements are NOT a fail-closed boundary: they
    # decode node-exactly via the F475 _JSNumStr machinery (consistent
    # with F521); they just never produce a credential.
    num_payload = "Reflect.apply([].join.bind(['%s', 1], ''), null, [])" % _A1
    num_tup = dlp._try_js_expr_decode(num_payload, 0)
    num_ok = (num_tup is not None and num_tup[0] == "%s1" % _A1
              and dlp.find_credential(num_payload) is None)
    if not num_ok:
        bad.append("numeric-element node-exact decode")
    total = len(misses) + 1
    return ("HELD" if not bad else "BREAK",
            "%d/%d F530 boundaries fail closed%s" % (
                total - len(bad), total,
                "" if not bad else ": " + "; ".join(bad)))


# ------------------------------------------------- P3: node differential
def p3_node_differential():
    """Byte-identical-or-miss differential vs node v24.20.0.

    For each payload: node evaluates (or throws); the decoder must
    either produce the exact credential (HIT) or miss. A HIT whose
    decoded value differs from node's is a BREAK.
    """
    import subprocess as _sp
    cases = [
        ("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A1, _A2), True),
        ("String('%s')[[[[['concat'][0]]][0]][0]](String('%s'))" % (_A1, _A2), True),
        ("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2), True),
        ("Reflect.apply.call(Reflect, [].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2), True),
        ("Reflect.apply.bind(Reflect)([].join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2), True),
        ("Reflect.apply(Array.prototype.join.bind(['%s','%s'], ''), null, [])" % (_A1, _A2), True),
        ("Reflect.apply([].join.bind(['%s','%s'], '-'), null, [])" % (_A1, _A2), True),
    ]
    # node script: print JSON of each evaluation (or THROW)
    js = "const A1=%s,A2=%s;const out=[];\n" % (repr(_A1), repr(_A2))
    exprs = [c for c, _ in cases]
    for i, e in enumerate(exprs):
        je = e.replace("'%s'" % _A1, "A1").replace('"%s"' % _A1, "A1")
        je = je.replace("'%s'" % _A2, "A2").replace('"%s"' % _A2, "A2")
        js += ("try{out.push('VAL:'+String(%s))}catch(e){out.push('THROW')}\n"
               % je)
    js += "console.log(JSON.stringify(out))"
    try:
        r = _sp.run(["node", "-e", js], capture_output=True, text=True,
                    timeout=60)
        node_vals = [v[4:] if v.startswith("VAL:") else "THROW"
                     for v in __import__("json").loads(r.stdout.strip())]
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node differential failed: %r" % (e,))
    bad = []
    for (payload, _), nv in zip(cases, node_vals):
        hit = dlp.find_credential(payload)
        if nv == "THROW":
            if hit is not None:
                bad.append("node-throws-but-decodes: %s" % payload[:48])
            continue
        # node produced a value; the decoder's JS-expression desugar
        # must produce the byte-identical value (or the whole-text
        # find_credential must hit it).
        tup = dlp._try_js_expr_decode(payload, 0)
        decoded = tup[0] if tup is not None else None
        if decoded != nv:
            bad.append("desugar-mismatch: %s node=%r decoded=%r" % (
                payload[:48], nv, decoded))
        elif hit is None:
            bad.append("node-hit-decoder-miss: %s" % payload[:48])
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-differential honest%s" % (
                len(cases) - len(bad), len(cases),
                "" if not bad else ": " + "; ".join(bad)))


def p3_no_new_regexes():
    n = len(re.findall(r"re\.compile\(", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK",
            "re.compile count %d (want 28)" % n)


def p3_perf_bound():
    # Hostile corpus: many fail-closed matches must starve fast (F512).
    payload = ("x" + "'%s'[[[[['concat'][0]]][0]][0]]" % _A1) * 600
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK",
            "600-anchor hostile corpus %.2fs (budget 5s)" % dt)


# ------------------------------------------------- P4: pin and footer
# Merge footer (wave-367): F531/F533/F534 CLOSED in lanes 1-3;
# F535, F536 remain OPEN; merge finalizes tree-wide.
FOOTER_OPEN = (
               "F570", "F571", "F572", "F573",
               "F574", "F575", "F576", "F577",
               "F578", "F579", "F580", "F581",
               "F582"
               )  # Wave-367 merge; wave-368 lane 1: F537/F538/F542 CLOSED
FOOTER_NEXT = "F640"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640


def p4_pin_and_footer():
    notes = []
    ok = True
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        ok = False
        notes.append("TAXONOMY_PIN=%s want 2140" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # FINDINGS.md carries historical footer lines; the live footer is
    # the LAST match.
    ms = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                          r"\*\*Open findings: ([^*]+)\.\*\*", text))
    if not ms:
        ok = False
        notes.append("footer pattern not found")
        m = None
    else:
        m = ms[-1]
    if m is not None:
        nxt, open_s = m.group(1), m.group(2)
        open_got = tuple(s.strip() for s in open_s.split(","))
        if nxt != FOOTER_NEXT or open_got != FOOTER_OPEN:
            # Wave-367 merge: F526-F534 CLOSED (F531/F533/F534 in lanes 1-3),
            # F532 CLOSED at wave-366 merge; open F535, F536; next F537.
            # A footer regression BREAKs.
            ok = False
            notes.append("lane-local footer: next=%s open=%s "
                         "(want next=%s open=%s)" % (
                             nxt, open_got, FOOTER_NEXT, FOOTER_OPEN))
    for fid in ("F526", "F527", "F528", "F529", "F530", "F531", "F532", "F533", "F534"):
        # Wave-367 merge: lanes 1-3 closed F531/F533/F534 (lane 3's stale
        # F526/F528/F529-OPEN assertion corrected at the wave-367 lane-3 merge).
        if not re.search(r"\(%s .*CLOSED" % fid, text):
            ok = False
            notes.append("%s not marked CLOSED" % fid)
    for fid in ("F535", "F536"):
        if not re.search(r"\(%s .*OPEN" % fid, text):
            ok = False
            notes.append("%s not OPEN" % fid)
    return ("HELD" if ok else "BREAK",
            "pin/footer %s%s" % ("ok" if ok else "MISMATCH",
                                 "" if not notes else ": " + "; ".join(notes)))


PROBES = [
    ("p1-f527-filed-shapes", p1_f527_filed_shapes),
    ("p1-f530-filed-shapes", p1_f530_filed_shapes),
    ("p1-combos-and-variants", p1_combos_and_variants),
    ("p1-compositions", p1_compositions),
    ("p2-f527-bounds", p2_f527_bounds),
    ("p2-f530-bounds", p2_f530_bounds),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-perf-bound", p3_perf_bound),
    ("p4-pin-and-footer", p4_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        return fn()
    except AssertionError as e:
        return ("BREAK", "assert: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%r" % (e,))


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    if not os.path.exists(venv_python):
        venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w365_f527_redfirst.py",
               "w365_f530_redfirst.py",
               "w365_attack_probes.py",
               "w364_attack_probes.py",
               "w365_f521close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g366-green-%s-%d" % (script.replace(".py", ""),
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
        if script in ("w365_attack_probes.py", "w364_attack_probes.py"):
            # These batteries' footers were repointed in this lane to
            # the lane-local footer (F527/F530 CLOSED; open F526, F528,
            # F529 / next F531); the filings were wave-365 lane 5
            # (attack round 33). The tolerance below is a safety net
            # for merge-time repoint (wave-305/306 class): tolerate
            # exactly a footer-state BREAK and nothing else.
            breaks = [l for l in out.splitlines()
                      if ": BREAK" in l]
            others = [l for l in breaks
                      if "footer" not in l and "FOOTER" not in l]
            if r.returncode != 0 and not others and breaks:
                notes.append("(%s footer stale tolerated by design)"
                             % script)
                continue
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    breaks = held = errors = 0
    for pid, fn in PROBES:
        status, note = _safe(pid, fn)
        print("%s: %s -- %s" % (pid, status, note))
        if status == "BREAK":
            breaks += 1
        elif status == "ERROR":
            errors += 1
        else:
            held += 1
    gc = _green_check()
    print("green-check: %s" % gc.splitlines()[0])
    for line in gc.splitlines()[1:]:
        print("  " + line)
    green_ok = gc.startswith("green check passed") or gc.startswith("skipped")
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors or not green_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
