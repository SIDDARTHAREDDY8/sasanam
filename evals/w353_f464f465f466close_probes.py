#!/usr/bin/env python3
"""Wave-353 F464+F465+F466 closure battery (lane 3).

F464 (LOW, filed 2026-10-06 wave-352 lane 5, continuous real-model
attack): .toString().replace(/,/g,'') bypassed the bounded static
JS-expression decoder -- ['frag1','frag2'].toString().replace(/,/g,'')
node-evaluates to the credential (toString comma-joins, the replace
strips commas). Neither toString nor the regex replace was modeled.
Distinct from F460 (.map(String)): a string-rewrite primitive.

F465 (LOW, same round): .padStart credential assembly --
'89abcdef'.padStart(21,'xoxb-012345678') node-evaluates to the
21-char credential (the pad string fills the left). The decoder
modeled no padding primitive. The red-first uses the fragment-split
form where neither literal matches the seam, so the MISS was the
decoder's, not the seam's.

F466 (LOW, same round): an unmodeled no-op chain step --
['frag1','frag2'].slice(0,2).join('') node-evaluates to the
credential. The chain grammar knew no .slice step. Distinct from
F448 (callback body shapes): a missing chain-grammar step. The F464
scope note's .flat()/.splice(0,2) no-ops ride with this close-when.

Closure design (gov/dlp.py, all node-verified byte-identical against
node v24.20.0):
- F464: .toString() on parsed string arrays (engine-exact comma join,
  args fail closed) feeding the string pipeline; .replace() modeled
  ONLY for the literal-comma regex with flags in {g,i} (the /,/gi
  variant is comma-identical, node-verified) and a literal-string
  replacement -- without "g" only the first comma is replaced,
  exactly as the engine does. General regex replace is NOT modeled.
- F465: .padStart(targetLen,padString)/.padEnd(...) on strings with
  literal numeric length (_js_parse_number) and literal pad string:
  engine-exact repeat/truncate fill; targets at/below the string
  length and the empty pad string are no-ops. Non-literal args fail
  closed.
- F466: .slice(start[,end]) on parsed string arrays with literal
  numeric bounds (optional leading '-'; _js_parse_slice_int): negative
  indices and out-of-range bounds clamp engine-exact
  (_js_slice_bound); plus .flat() (no-arg identity over the
  decoder's string-only arrays) and the literal .splice(0,2) form
  (returns the removed elements, node-verified). Non-literal bounds
  and every other splice arg shape fail closed.
- Boundaries (documented, pinned): space-after-dot (F437); empty
  decode results filtered by _ascii_printable_or_none (pre-existing);
  toString args; regex bodies other than ","; flags outside {g,i};
  string first-arg replace; one-arg padStart; float/plus slice
  bounds; flat/splice with other args.

No new regexes (hand-parsed); no eval/exec; F430 bounds (parts,
output bytes); the F441 _decode_layer ordering is untouched (pinned).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the three filed shapes block (F464 toString+replace,
      F465 padStart, F466 slice no-op); the F464 scope-note shapes
      block (.flat()/.splice(0,2) ahead of toString+replace).
  P2  controls: junk variants quiet; plain credential blocks;
      neighbor shapes block; /,/gi variant blocks; pad-hits-seam
      blocks (pad string itself matches the seam); first-only
      replace decodes engine-exact; ws-tolerant forms block.
  P3  decoder pins: _js_slice_bound values; _js_parse_comma_regex
      flags/ends; _js_parse_slice_int signs; toString/slice/flat/
      splice end-indices; F441 ordering intact; no new regexes.
  P4  discrimination: out-of-scope shapes fail closed and stay quiet
      (toString args, non-comma bodies, bad flags, string first-arg,
      one-arg pad, non-literal slice, float/plus bounds, flat/splice
      arg shapes, space-after-dot).
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F434 join, F437
      reduce, F443 Array.fill/filter(Boolean), F444 junk-prefix,
      F445 short-b64, F446 Array.of, F454 multi-arg, F460 map(String),
      F447/F448).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F461, F462, F463, F467, F468 / next F469,
      F464/F465/F466 CLOSED entries present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w353_f464f465f466close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-353: F464/F465/F466 closed, no new decision codes
FOOTER_OPEN = "F496, F497, F498, F499, F500, F501, F502"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-353 lane 3: F464-F466 CLOSED (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-354: F470 CLOSED  # Wave-354 lane 3: F471 CLOSED  # Wave-354 lane 4: F472 CLOSED  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN

FOOTER_NEXT = "F503"  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496


# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_C1 = "xoxb-" + "012345678"
_C2 = "89abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001
        print("%-46s ERROR %s" % (pid, e))
        return pid, "ERROR"
    print("%-46s %s" % (pid, "HELD" if ok else "BREAK"))
    return pid, ("HELD" if ok else "BREAK")


# ---------------------------------------------------------------- P1: closure

def p1_closure_f464_tostring_replace():
    return _blocked("['%s','%s'].toString().replace(/,/g,'')" % (_A, _B))


def p1_closure_f465_padstart():
    return _blocked("'%s'.padStart(21,'%s')" % (_C2, _C1))


def p1_closure_f465_padend():
    # padEnd(21,...) assembles '89abcdefxoxb-01234567' -- only 8 chars
    # after 'xoxb-', below the seam's {10,} floor, so the filed 21-char
    # form cannot flag via padEnd with these fragments (node-verified).
    # padEnd(29,...) repeats the pad string and DOES assemble a
    # seam-matching credential: the primitive is what closes.
    return _blocked("'%s'.padEnd(29,'%s')" % (_C2, _C1))


def p1_closure_f466_slice_noop():
    return _blocked("['%s','%s'].slice(0,2).join('')" % (_A, _B))


def p1_closure_f466_flat_noop():
    return _blocked("['%s','%s'].flat().join('')" % (_A, _B))


def p1_closure_f466_splice02():
    return _blocked("['%s','%s'].splice(0,2).join('')" % (_A, _B))


def p1_closure_f464_scope_flat_tostring():
    # F464 scope note: .flat() ahead of the toString+replace chain.
    return _blocked("['%s','%s'].flat().toString().replace(/,/g,'')"
                    % (_A, _B))


def p1_closure_f464_scope_splice_tostring():
    # F464 scope note: .splice(0,2) ahead of the toString+replace chain.
    return _blocked("['%s','%s'].splice(0,2).toString().replace(/,/g,'')"
                    % (_A, _B))


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_A + _B)


def p2_control_neighbor_join():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


def p2_control_f464_junk_quiet():
    return not _blocked("['ab','cd'].toString().replace(/,/g,'')")


def p2_control_f465_junk_quiet():
    return not _blocked("'89abcd'.padStart(21,'zz')")


def p2_control_f466_junk_quiet():
    return not _blocked("['ab','cd'].slice(0,2).join('')")


def p2_control_replace_gi():
    # /,/gi is comma-identical to /,/g (node-verified): must block.
    return _blocked("['%s','%s'].toString().replace(/,/gi,'')" % (_A, _B))


def p2_control_replace_first_only():
    # Without "g" only the first comma goes -- the decoded variant
    # 'ab,c' is junk and must stay quiet.
    return not _blocked("['a,b','c'].toString().replace(/,/,'')")


def p2_control_pad_hits_seam():
    # The pad string itself matches the slack seam: blocks, correctly.
    return _blocked("'89abcd'.padStart(21,'%s')" % _C1)


def p2_control_tostring_alone_variant():
    # .toString() alone yields the comma-joined variant in the
    # decode pipeline (engine-exact).
    r = dlp._try_js_expr_decode("['ab','cd'].toString()", 0)
    return r is not None and r[0] == "ab,cd"


def p2_control_slice_real():
    # A real (non-no-op) slice composes with join.
    return _blocked("['%s','%s','zz'].slice(0,2).join('')" % (_A, _B))


def p2_control_slice_negative():
    return _blocked("['zz','%s','%s'].slice(-2).join('')" % (_A, _B))


def p2_control_ws_tolerant():
    return _blocked("['%s','%s'].slice ( 0 , 2 ).join ( '' )" % (_A, _B))


def p2_control_chained_composition():
    # slice -> toString -> replace -> padEnd composes across all three.
    return _blocked(
        "['%s','%s'].slice(0,2).toString().replace(/,/g,'')"
        ".padEnd(21,'z')" % (_A, _B))


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_slice_bound():
    cases = [
        ((0, 3), 0), ((2, 3), 2), ((5, 3), 3), ((3, 3), 3),
        ((-1, 3), 2), ((-2, 3), 1), ((-3, 3), 0), ((-9, 3), 0),
        ((-1, 0), 0), ((0, 0), 0),
    ]
    for (k, n), want in cases:
        if dlp._js_slice_bound(k, n) != want:
            print("    slice_bound mismatch: (%d,%d)" % (k, n))
            return False
    return True


def p3_pin_comma_regex():
    if dlp._js_parse_comma_regex("/,/g,'')", 0) != ("g", 4):
        return False
    if dlp._js_parse_comma_regex("/,/gi,'')", 0) != ("gi", 5):
        return False
    if dlp._js_parse_comma_regex("/,/ig,'')", 0) != ("ig", 5):
        return False
    if dlp._js_parse_comma_regex("/,/i,'')", 0) != ("i", 4):
        return False
    if dlp._js_parse_comma_regex("/,/,'')", 0) != ("", 3):
        return False
    for bad in ("/x/g", "/,/gu", "/,/gg", "/\\,/g", "'a'", "/,",
                "//g", "/,,/g"):
        try:
            dlp._js_parse_comma_regex(bad, 0)
        except Exception:  # noqa: BLE001
            continue
        print("    comma regex accepted: %s" % bad)
        return False
    return True


def p3_pin_slice_int():
    if dlp._js_parse_slice_int("-2", 0) != (-2, 2):
        return False
    if dlp._js_parse_slice_int("- 2", 0) != (-2, 3):
        return False
    if dlp._js_parse_slice_int("0x10", 0) != (16, 4):
        return False
    if dlp._js_parse_slice_int("-0", 0) != (0, 2):
        return False
    # The helper itself fails closed on non-numbers and signs; a
    # trailing ".5" is left unconsumed and the CALLER fails it closed
    # (pinned by p4-discr-slice-nonliteral-quiet).
    for bad in ("x", "+1", "--2"):
        try:
            dlp._js_parse_slice_int(bad, 0)
        except Exception:  # noqa: BLE001
            continue
        print("    slice int accepted: %s" % bad)
        return False
    if dlp._js_parse_slice_int("1.5", 0) != (1, 1):
        return False
    return True


def p3_pin_method_end_indices():
    # toString consumes exactly through ")".
    r = dlp._try_js_expr_decode("['ab'].toString()", 0)
    if r != ("ab", 17):
        print("    toString end: %r" % (r,))
        return False
    # replace consumes through ")".
    r = dlp._try_js_expr_decode("'a,b'.replace(/,/g,'')", 0)
    if r != ("ab", 22):
        print("    replace end: %r" % (r,))
        return False
    # padStart consumes through ")".
    r = dlp._try_js_expr_decode("'ab'.padStart(5,'z')", 0)
    if r != ("zzzab", 20):
        print("    padStart end: %r" % (r,))
        return False
    return True


def p3_pin_f441_ordering_intact():
    # The F441 production stays FIRST in _decode_layer, before the
    # per-run escape layers -- the F464/F465/F466 edits must not
    # disturb it.
    import inspect
    src = inspect.getsource(dlp._decode_layer)
    i_prod = src.find("_try_bslash_unescape_all")
    i_run = src.find("_ESC_RUN")
    return 0 <= i_prod < i_run


def p3_pin_no_new_regexes():
    # The closures are parser-only: none of the touched/new decoder
    # functions references the re module (pre-existing credential-rule
    # regexes elsewhere in gov/dlp.py are untouched by this lane).
    import inspect
    for fn in (dlp._js_parse_comma_regex, dlp._js_parse_slice_int,
               dlp._js_slice_bound, dlp._js_apply_method,
               dlp._js_parse_postfix):
        src = inspect.getsource(fn)
        if re.search(r"\bre\.", src):
            print("    re usage in %s" % fn.__name__)
            return False
    return True


def p3_pin_pad_values():
    # Engine-exact padding values pinned at the decoder seam.
    if dlp._try_js_expr_decode("'abcdefgh'.padStart(3,'xy')", 0)[0] \
            != "abcdefgh":
        return False
    if dlp._try_js_expr_decode("'abcdefgh'.padStart(10,'xy')", 0)[0] \
            != "xyabcdefgh":
        return False
    if dlp._try_js_expr_decode("'ab'.padStart(5,'')", 0)[0] != "ab":
        return False
    return True


# ---------------------------------------------------------------- P4: discrimination

def _quiet_decode(payload):
    return dlp._try_js_expr_decode(payload, 0) is None


def p4_discr_tostring_args_quiet():
    return _quiet_decode("['%s','%s'].toString('x')" % (_A, _B))


def p4_discr_replace_body_quiet():
    return _quiet_decode("['%s','%s'].toString().replace(/x/g,'')"
                         % (_A, _B))


def p4_discr_replace_flags_quiet():
    for flags in ("gu", "gg", "y", "m"):
        p = "['%s','%s'].toString().replace(/,/%s,'')" % (_A, _B, flags)
        if not _quiet_decode(p):
            print("    replace flags parsed: %s" % flags)
            return False
    return True


def p4_discr_replace_strarg_quiet():
    return _quiet_decode("'a,b'.replace(',','')")


def p4_discr_replace_on_array_quiet():
    return _quiet_decode("['%s','%s'].replace(/,/g,'')" % (_A, _B))


def p4_discr_pad_one_arg_quiet():
    return _quiet_decode("'%s'.padStart(5)" % _A)


def p4_discr_pad_nonliteral_quiet():
    for p in ("'%s'.padStart(x,'y')" % _A,
              "'%s'.padStart(5,y)" % _A,
              "'%s'.padStart(5.0,'y')" % _A):
        if not _quiet_decode(p):
            print("    pad non-literal parsed: %s" % p)
            return False
    return True


def p4_discr_pad_on_array_quiet():
    return _quiet_decode("['%s','%s'].padStart(21,'%s')" % (_A, _B, _C1))


def p4_discr_slice_nonliteral_quiet():
    for p in ("['%s','%s'].slice(x)" % (_A, _B),
              "['%s','%s'].slice(0.5,2)" % (_A, _B),
              "['%s','%s'].slice(+1)" % (_A, _B),
              "['%s','%s'].slice('0')" % (_A, _B)):
        if not _quiet_decode(p):
            print("    slice non-literal parsed: %s" % p)
            return False
    return True


def p4_discr_flat_splice_args_quiet():
    for p in ("['%s','%s'].flat(1)" % (_A, _B),
              "['%s','%s'].splice(0,1)" % (_A, _B),
              "['%s','%s'].splice()" % (_A, _B),
              "['%s','%s'].splice(0,2,9)" % (_A, _B)):
        if not _quiet_decode(p):
            print("    flat/splice args parsed: %s" % p)
            return False
    return True


def p4_discr_space_after_dot_quiet():
    # Documented F437 boundary: space after the dot is not modeled.
    return _quiet_decode("['%s','%s']. slice(0,2).join('')" % (_A, _B))


def p4_discr_slice_on_string_quiet():
    # .slice on a STRING falls to the pre-existing generic
    # unknown-method path (concat-shaped), never a string slice --
    # pinned: no false string-slice variant is produced.
    r = dlp._try_js_expr_decode("'%s'.slice(1)" % _A, 0)
    return r is None or r[0] != _A[1:]


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        "['a']" + ".toString()" * 200,
        "'" + "a," * 5000 + "'.replace(/,/g,'" + "b" * 5000 + "')",
        "['a','b']" + ".slice(0,2)" * 200 + ".join('')",
        "'" + "x" * 2000 + "'.padStart(1114111,'" + "y" * 2000 + "')",
        "['a','b'].replace(" + "/" * 500 + ",'')",
        "['a','b'].splice(" + "0," * 500 + ")",
        "['a'" + ",'a'" * 200 + "]" + ".flat()" * 100,
        "'ab'.padStart(" + "9" * 5000 + ",'z')",
    ]
    for h in hostile:
        t0 = time.time()
        try:
            dlp.find_credential(h)
        except Exception:
            return False
        if time.time() - t0 > 5:
            print("    slow input: %r..." % h[:40])
            return False
    return True


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f434_join():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


def p6_noreg_f437_reduce():
    return _blocked("['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B))


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('%s').join('')" % _A)


def p6_noreg_f443_filter_boolean():
    return _blocked("['%s','','%s'].filter(Boolean).join('')" % (_A, _B))


def p6_noreg_f444_junk_prefix():
    junk = "".join("'%s';" % ("j%d" % i) for i in range(3))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    return _blocked(junk + real)


def p6_noreg_f445_short_b64():
    import base64
    return _blocked("k=" + base64.b64encode((_A + _B).encode()).decode())


def p6_noreg_f446_array_of():
    return _blocked("Array.of('%s','%s').join('')" % (_A, _B))


def p6_noreg_f454_multi_arg():
    return _blocked("Array('%s','%s').join('')" % (_A, _B))


def p6_noreg_f447_truthy():
    return _blocked("['%s','','%s'].filter(x=>x!=='').join('')" % (_A, _B))


def p6_noreg_f448_blockbody_map():
    return _blocked("['%s','%s'].map(function(s){return s;}).join('')"
                    % (_A, _B))


def p6_noreg_f460_map_string():
    return _blocked("['%s','%s'].map(String).join('')" % (_A, _B))


# ---------------------------------------------------------------- P7: pin + footer

_FP_BASELINE = {
    "README.md": "dlp-github-token",
    "SITUATION_MATRIX.md": "dlp-aws-access-key",
    "docs/decision-code-coverage.md": "dlp-entropy-tripwire",
    "evals/FINDINGS.md": "dlp-aws-access-key",
    "evals/SITUATION_MATRIX.md": "dlp-aws-access-key",
}


def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and footer.count("**Status: CLOSED 2026-10-06 wave-353 lane 3.**") \
        == 3
    # FP corpus hit-set identical to the wave-352 baseline.
    corpus = sorted(glob.glob("README.md") + glob.glob("docs/*.md")
                    + glob.glob("evals/*.md")
                    + ["BUILD_LOG.md", "THREAT_MODEL.md",
                       "SITUATION_MATRIX.md"])
    hits = {}
    for p in corpus:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                t = f.read()
        except OSError:
            continue
        r = dlp.find_credential(t[:200000])
        if r:
            hits[p] = r
    ok = ok and hits == _FP_BASELINE
    return ok


_PROBES = [
    ("p1-closure-f464-tostring-replace", p1_closure_f464_tostring_replace),
    ("p1-closure-f465-padstart", p1_closure_f465_padstart),
    ("p1-closure-f465-padend", p1_closure_f465_padend),
    ("p1-closure-f466-slice-noop", p1_closure_f466_slice_noop),
    ("p1-closure-f466-flat-noop", p1_closure_f466_flat_noop),
    ("p1-closure-f466-splice02", p1_closure_f466_splice02),
    ("p1-closure-f464-scope-flat-tostring",
     p1_closure_f464_scope_flat_tostring),
    ("p1-closure-f464-scope-splice-tostring",
     p1_closure_f464_scope_splice_tostring),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-neighbor-join", p2_control_neighbor_join),
    ("p2-control-f464-junk-quiet", p2_control_f464_junk_quiet),
    ("p2-control-f465-junk-quiet", p2_control_f465_junk_quiet),
    ("p2-control-f466-junk-quiet", p2_control_f466_junk_quiet),
    ("p2-control-replace-gi", p2_control_replace_gi),
    ("p2-control-replace-first-only", p2_control_replace_first_only),
    ("p2-control-pad-hits-seam", p2_control_pad_hits_seam),
    ("p2-control-tostring-alone-variant", p2_control_tostring_alone_variant),
    ("p2-control-slice-real", p2_control_slice_real),
    ("p2-control-slice-negative", p2_control_slice_negative),
    ("p2-control-ws-tolerant", p2_control_ws_tolerant),
    ("p2-control-chained-composition", p2_control_chained_composition),
    ("p3-pin-slice-bound", p3_pin_slice_bound),
    ("p3-pin-comma-regex", p3_pin_comma_regex),
    ("p3-pin-slice-int", p3_pin_slice_int),
    ("p3-pin-method-end-indices", p3_pin_method_end_indices),
    ("p3-pin-f441-ordering-intact", p3_pin_f441_ordering_intact),
    ("p3-pin-no-new-regexes", p3_pin_no_new_regexes),
    ("p3-pin-pad-values", p3_pin_pad_values),
    ("p4-discr-tostring-args-quiet", p4_discr_tostring_args_quiet),
    ("p4-discr-replace-body-quiet", p4_discr_replace_body_quiet),
    ("p4-discr-replace-flags-quiet", p4_discr_replace_flags_quiet),
    ("p4-discr-replace-strarg-quiet", p4_discr_replace_strarg_quiet),
    ("p4-discr-replace-on-array-quiet", p4_discr_replace_on_array_quiet),
    ("p4-discr-pad-one-arg-quiet", p4_discr_pad_one_arg_quiet),
    ("p4-discr-pad-nonliteral-quiet", p4_discr_pad_nonliteral_quiet),
    ("p4-discr-pad-on-array-quiet", p4_discr_pad_on_array_quiet),
    ("p4-discr-slice-nonliteral-quiet", p4_discr_slice_nonliteral_quiet),
    ("p4-discr-flat-splice-args-quiet", p4_discr_flat_splice_args_quiet),
    ("p4-discr-space-after-dot-quiet", p4_discr_space_after_dot_quiet),
    ("p4-discr-slice-on-string-quiet", p4_discr_slice_on_string_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f434-join", p6_noreg_f434_join),
    ("p6-noreg-f437-reduce", p6_noreg_f437_reduce),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f443-filter-boolean", p6_noreg_f443_filter_boolean),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f445-short-b64", p6_noreg_f445_short_b64),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f454-multi-arg", p6_noreg_f454_multi_arg),
    ("p6-noreg-f447-truthy", p6_noreg_f447_truthy),
    ("p6-noreg-f448-blockbody-map", p6_noreg_f448_blockbody_map),
    ("p6-noreg-f460-map-string", p6_noreg_f460_map_string),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1).

    Run BEFORE the lane's FINDINGS.md footer update, so every child
    still pins the wave-352 footer (open F461-F468 / next F469) and
    must pass clean -- any BREAK here is a real regression and fails
    this check. After the footer moves (open F461, F462, F463, F467,
    F468 / next F469), the children's footer probes go stale; the
    merge coordinator's tree-wide footer sweep repoints them.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w352_attack_probes.py",
               "w351_attack_probes.py",
               "w352_f458f459f460close_probes.py",
               "w352_f456close_probes.py",
               "w352_f457close_probes.py",
               "w346_dlp_composition_probes.py")
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
        notes.append("%s rc=%d tail=%s"
                     % (script, r.returncode,
                        out[-160:].strip().replace("\n", " | ")))
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
    print("w353_f464f465f466close: %d BREAK / %d HELD / %d ERROR"
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
