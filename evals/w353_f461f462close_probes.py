#!/usr/bin/env python3
"""Wave-353 F461+F462 closure battery (lane 1).

F461 (LOW, filed 2026-10-06 wave-352 lane 5, continuous real-model
attack, re-validated from the wave-351 round-19 validated-but-unfiled
list): the array-reversal primitive bypassed the bounded static
JS-expression decoder -- ['frag2','frag1'].reverse().join('')
node-evaluates to the credential (reversed fragment order), but the
decoder's chain grammar modeled no .reverse() step and the shape
failed closed with zero decode variants, while the plain credential
blocked coded. Distinct from F437 (reduce folds): an order-
transformation primitive, not a fold.

F462 (LOW, same round): spread-args concat bypassed the bounded
static JS-expression decoder -- "".concat(...['frag1','frag2'])
node-evaluates to the credential, but the decoder's concat model
accepted only literal arguments; the spread form failed closed with
zero decode variants, while the plain credential blocked coded.
Distinct from the already-blocked ''.concat('a','b') literal-args
form (wave-351 dead proposal): argument-spreading is a different
call shape.

Closure design (gov/dlp.py, all node-verified byte-identical against
node v24.20.0):
- F461: new "reverse" branch in _js_apply_method (no-arg only) plus
  "reverse" in the _js_parse_postfix chain list. Reversal is the
  node-exact element-list reversal on parsed _JSArr values
  (literal/factory/constructed arrays), bounded by the parts budget
  (every parsed element is parts-charged at parse time; the reversal
  adds no new parts, and charges the ops budget like every other
  array-valued op), composing with .join/.map/.filter/.fill.
  reverse-with-args,
  reverse on non-arrays, and unmodeled chain steps (.sort,
  .toString, ...) fail closed -- the postfix parse ends at the
  unmodeled step and the unjoined _JSArr decodes to nothing.
- F462: the concat arg loop in _js_apply_method accepts
  ...spread-of-array args: the spread target parses as a primary
  (array literal/factory/constructor, postfix chains allowed) and
  each string element becomes a concat arg in engine-exact order,
  each charged to the parts budget. Non-array spreads
  ("".concat(..."ab")), nested spreads (...[...['a']]), empty
  spreads, and non-string elements fail closed.

No new regexes (parser-only); no eval/exec; F430 bounds (parts,
output bytes); the F441 _decode_layer ordering is untouched (pinned).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed F461 shapes block (reverse-join, reverse with
      separator, double-reverse, reverse over Array.fill); filed F462
      shapes block (spread, mixed literal+spread, spread of reversed
      array, spread of Array.fill).
  P2  controls: plain credential blocks; junk reverse/spread quiet;
      neighbor closed shapes still block (plain join, literal-args
      concat, identity map-join).
  P3  decoder pins: whole-text decode byte-exact on junk shapes;
      reverse end-index; F441 ordering intact; no new regexes;
      reverse on _JSArr only.
  P4  discrimination: reverse-with-args quiet; .sort() chain quiet;
      non-array spread quiet; nested spread quiet; empty spread
      quiet; spread of a postfix-joined (non-array) target quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F437 reduce,
      F443 Array.fill, F443 filter(Boolean), F454 multi-arg Array,
      F455 Array.of, F458 fcc octal, F459 filter index, F460 map
      String, F434 plain join).
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      footer open F463-F468 / next F469, F461/F462 CLOSED entries
      present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w353_f461f462close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import glob
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-353: F461+F462 closed, no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-355 lane 2: F474 CLOSED  # Wave-353 lane 1: F461+F462 CLOSED (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-354: F470 CLOSED  # Wave-354 lane 3: F471 CLOSED  # Wave-354 lane 4: F472 CLOSED  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)

FOOTER_NEXT = "F570"  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)


# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001
        print("%-46s ERROR %s" % (pid, e))
        return pid, "ERROR"
    print("%-46s %s" % (pid, "HELD" if ok else "BREAK"))
    return pid, ("HELD" if ok else "BREAK")


# ---------------------------------------------------------------- P1: closure

def p1_closure_f461_reverse_join():
    return _blocked("['%s','%s'].reverse().join('')" % (_B, _A))


def p1_closure_f461_reverse_separator():
    return _blocked("['%s','%s'].reverse().join('-')" % (_B, _A))


def p1_closure_f461_double_reverse():
    # Double reversal is the identity: fragments in filed order still join.
    return _blocked("['%s','%s'].reverse().reverse().join('')" % (_A, _B))


def p1_closure_f461_reverse_over_fill():
    return _blocked("Array(2).fill('%s').reverse().join('')" % _A)


def p1_closure_f462_spread():
    return _blocked("\"\".concat(...['%s','%s'])" % (_A, _B))


def p1_closure_f462_spread_mixed():
    return _blocked("'x'.concat('%s',...['%s'],'%s')" % (_A, _B, _A))


def p1_closure_f462_spread_of_reversed():
    return _blocked("\"\".concat(...['%s','%s'].reverse())" % (_B, _A))


def p1_closure_f462_spread_of_fill():
    return _blocked("\"\".concat(...Array(2).fill('%s'))" % _A)


# ---------------------------------------------------------------- P2: controls

def p2_control_plain_credential():
    return _blocked(_A + _B)


def p2_control_junk_reverse_quiet():
    return not _blocked("['ab','cd'].reverse().join('')")


def p2_control_junk_spread_quiet():
    return not _blocked("\"\".concat(...['ab','cd'])")


def p2_control_plain_join_blocks():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


def p2_control_literal_concat_blocks():
    return _blocked("\"\".concat('%s','%s')" % (_A, _B))


def p2_control_identity_map_join_blocks():
    return _blocked("['%s','%s'].map(s=>s).join('')" % (_A, _B))


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_reverse_decode_exact():
    # Whole-text decode of a junk reverse payload is byte-exact.
    return _decoded("['zz','yy'].reverse().join('')") == "yyzz"


def p3_pin_spread_decode_exact():
    return _decoded("\"x\".concat(...['p','q'])") == "xpq"


def p3_pin_spread_multi_decode_exact():
    return _decoded("\"\".concat(...['p'],...['q','r'])") == "pqr"


def p3_pin_f441_ordering_intact():
    # The F441 production stays FIRST in _decode_layer, before the
    # per-run escape layers -- the F461/F462 edits must not disturb it.
    import inspect
    src = inspect.getsource(dlp._decode_layer)
    i_prod = src.find("_try_bslash_unescape_all")
    i_run = src.find("_ESC_RUN")
    return 0 <= i_prod < i_run


def p3_pin_no_new_regexes():
    # The closures are parser-only: _js_apply_method / _js_parse_postfix
    # reference no re-module calls (pre-existing credential-rule regexes
    # elsewhere in gov/dlp.py are untouched by this lane).
    import inspect
    for fn in (dlp._js_apply_method, dlp._js_parse_postfix,
               dlp._js_add_concat_part):
        src = inspect.getsource(fn)
        if re.search(r"\bre\.", src):
            print("    re usage in %s" % fn.__name__)
            return False
    return True


def p3_pin_reverse_only_on_jsarr():
    # 'a'.reverse() is not an expression the grammar decodes at all.
    return _decoded("'a'.reverse()") is None


# ---------------------------------------------------------------- P4: discrimination

def p4_disc_reverse_with_args_quiet():
    # Node reverses anyway (ignores args); the decoder fails closed.
    return _decoded("['a','b'].reverse(1).join('')") is None


def p4_disc_sort_chain_quiet():
    # .sort is unmodeled: the parse ends at the unmodeled step and the
    # unjoined array decodes to nothing.
    return _decoded("['b','a'].reverse().sort().join('')") is None


def p4_disc_spread_nonarray_quiet():
    # Node spreads the string into chars; the decoder fails closed.
    return _decoded("\"\".concat(...'ab')") is None


def p4_disc_spread_nested_decodes():
    # Wave-354 lane 3 (F471): the inner [...['a']] is now a modeled
    # spread-copy factory, so the F462 spread-concat target resolves
    # through it -- node-evaluates to 'a' (node v24.20.0), and the
    # decoder agrees byte-exactly. The old quiet pin (nested spreads
    # fail closed) is superseded by the F471 composition.
    return _decoded("\"\".concat(...[...['a']])") == "a"


def p4_disc_spread_empty_quiet():
    return _decoded("\"\".concat(...)") is None


def p4_disc_spread_joined_array_quiet():
    # A spread target that postfix-reduces to a string is not an array:
    # the strict single-expression decode at the concat fails (the
    # inner join still decodes honestly on its own match, as it should).
    return dlp._try_js_expr_decode("\"\".concat(...['a','b'].join(','))", 0) is None


def p1_closure_f462_spread_ws_after_dots():
    # Whitespace after ... is skipped by the primary parse; node and
    # the decoder agree byte-exactly ("xpq"), so the shape blocks.
    return _blocked("\"\".concat(... ['%s','%s'])" % (_A, _B))


# ---------------------------------------------------------------- P5: ReDoS

def _timed(payload):
    t0 = time.time()
    try:
        _decoded(payload)
    except Exception:  # noqa: BLE001
        pass
    return time.time() - t0


def p5_redos_reverse_junk():
    dt = _timed("['a'," * 2000 + "].reverse(" * 50)
    print("    reverse-junk %.3fs" % dt)
    return dt < 5.0


def p5_redos_spread_junk():
    dt = _timed("\"\".concat(..." * 500 + "['a']")
    print("    spread-junk %.3fs" % dt)
    return dt < 5.0


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f437_reduce():
    return _blocked("['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B))


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('%s').join('')" % _A)


def p6_noreg_f443_filter_boolean():
    return _blocked("['%s','','%s'].filter(Boolean).join('')" % (_A, _B))


def p6_noreg_f454_multiarg_array():
    return _blocked("Array('%s','%s').join('')" % (_A, _B))


def p6_noreg_f455_array_of():
    return _blocked("Array.of('%s','%s').join('')" % (_A, _B))


def p6_noreg_f458_fcc_octal():
    codes = ",".join("0o%o" % ord(c) for c in _A + _B)
    return _blocked("String.fromCharCode(%s)" % codes)


def p6_noreg_f459_filter_index():
    return _blocked("['%s','%s','zz'].filter((x,i)=>i<2).join('')" % (_A, _B))


def p6_noreg_f460_map_string():
    return _blocked("['%s','%s'].map(String).join('')" % (_A, _B))


def p6_noreg_f434_plain_join():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    for fn in ("F461", "F462"):
        ok = ok and ("**Status: CLOSED 2026-10-06 wave-353 lane 1.**"
                     in footer)
    return ok


_PROBES = [
    ("p1-closure-f461-reverse-join", p1_closure_f461_reverse_join),
    ("p1-closure-f461-reverse-separator", p1_closure_f461_reverse_separator),
    ("p1-closure-f461-double-reverse", p1_closure_f461_double_reverse),
    ("p1-closure-f461-reverse-over-fill", p1_closure_f461_reverse_over_fill),
    ("p1-closure-f462-spread", p1_closure_f462_spread),
    ("p1-closure-f462-spread-mixed", p1_closure_f462_spread_mixed),
    ("p1-closure-f462-spread-of-reversed", p1_closure_f462_spread_of_reversed),
    ("p1-closure-f462-spread-of-fill", p1_closure_f462_spread_of_fill),
    ("p2-control-plain-credential", p2_control_plain_credential),
    ("p2-control-junk-reverse-quiet", p2_control_junk_reverse_quiet),
    ("p2-control-junk-spread-quiet", p2_control_junk_spread_quiet),
    ("p2-control-plain-join-blocks", p2_control_plain_join_blocks),
    ("p2-control-literal-concat-blocks", p2_control_literal_concat_blocks),
    ("p2-control-identity-map-join-blocks", p2_control_identity_map_join_blocks),
    ("p3-pin-reverse-decode-exact", p3_pin_reverse_decode_exact),
    ("p3-pin-spread-decode-exact", p3_pin_spread_decode_exact),
    ("p3-pin-spread-multi-decode-exact", p3_pin_spread_multi_decode_exact),
    ("p3-pin-f441-ordering-intact", p3_pin_f441_ordering_intact),
    ("p3-pin-no-new-regexes", p3_pin_no_new_regexes),
    ("p3-pin-reverse-only-on-jsarr", p3_pin_reverse_only_on_jsarr),
    ("p4-disc-reverse-with-args-quiet", p4_disc_reverse_with_args_quiet),
    ("p4-disc-sort-chain-quiet", p4_disc_sort_chain_quiet),
    ("p4-disc-spread-nonarray-quiet", p4_disc_spread_nonarray_quiet),
    ("p4-disc-spread-nested-decodes", p4_disc_spread_nested_decodes),
    ("p4-disc-spread-empty-quiet", p4_disc_spread_empty_quiet),
    ("p4-disc-spread-joined-array-quiet", p4_disc_spread_joined_array_quiet),
    ("p1-closure-f462-spread-ws-after-dots", p1_closure_f462_spread_ws_after_dots),
    ("p5-redos-reverse-junk", p5_redos_reverse_junk),
    ("p5-redos-spread-junk", p5_redos_spread_junk),
    ("p6-noreg-f437-reduce", p6_noreg_f437_reduce),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f443-filter-boolean", p6_noreg_f443_filter_boolean),
    ("p6-noreg-f454-multiarg-array", p6_noreg_f454_multiarg_array),
    ("p6-noreg-f455-array-of", p6_noreg_f455_array_of),
    ("p6-noreg-f458-fcc-octal", p6_noreg_f458_fcc_octal),
    ("p6-noreg-f459-filter-index", p6_noreg_f459_filter_index),
    ("p6-noreg-f460-map-string", p6_noreg_f460_map_string),
    ("p6-noreg-f434-plain-join", p6_noreg_f434_plain_join),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1).

    Wave-305-class note: this lane moved the footer to open F463-F468 /
    next F469, so footer-state probes in the adjacent batteries are
    expected to BREAK until the merge coordinator's tree-wide sweep
    repoints them; the F461/F462 open pins in w352_attack were flipped
    to closed assertions in-lane. Any OTHER break is a real regression
    and fails this check.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w352_attack_probes.py",
               "w352_f454f455close_probes.py",
               "w352_f456close_probes.py",
               "w352_f457close_probes.py",
               "w352_f458f459f460close_probes.py",
               "w346_dlp_composition_probes.py")
    # Footer probes repointed in-lane for the new footer, so no tolerated
    # stale probes are expected here.
    tolerated = {}
    attack_style = {"w352_attack_probes.py"}
    for script in scripts:
        tmp = "/var/tmp/g353-green-%s-%d" % (script.replace(".py", ""),
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
        if script in attack_style:
            breaks = set()
            for line in out.splitlines():
                if line.startswith("BREAK "):
                    breaks.add(line.split()[1].rstrip(":"))
            allowed = tolerated.get(script, set())
            notes.append("%s rc=%d breaks=%s %s"
                         % (script, r.returncode, sorted(breaks), tail))
            if not breaks <= allowed:
                raise AssertionError("green check failed: %s" % notes[-1])
            if r.returncode != 0 and not breaks:
                raise AssertionError("green check failed: %s" % notes[-1])
        else:
            notes.append("%s rc=%d %s" % (script, r.returncode, tail))
            if ("unexpected BREAKs" in out
                    or "expected BREAKs missing" in out):
                raise AssertionError("green check failed: %s" % notes[-1])
            if r.returncode != 0:
                raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w353_f461f462close: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
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
