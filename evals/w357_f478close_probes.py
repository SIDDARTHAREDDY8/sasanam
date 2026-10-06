#!/usr/bin/env python3
"""Wave-357 F478 closure battery (lane 1).

F478 (LOW, filed 2026-10-06 wave-356 attack round 24): `.call` /
`.apply` / `.bind` dispatch on prototype methods bypasses the bounded
static JS-expression decoder. Every shape below node-evaluates
(v24.20.0) to the exact credential while the decoder produced zero
variants on the open tree:

  Array.prototype.concat.call([], 'f1', 'f2').join('')
  String.prototype.concat.call('f1','f2')
  [].concat.call([], 'f1', 'f2').join('')
  Array.prototype.join.call(['f1','f2'], '')
  Array.prototype.slice.call(['f1','f2'],0,2).join('')
  Array.prototype.concat.apply([], ['f1','f2']).join('')
  Array.prototype.reduce.call(['f1','f2'], (acc,curr)=>acc+curr, '')
  Array.prototype.filter.call(['f1','f2',''], x=>x!=='').join('')
  String.prototype.concat.bind('f1')('f2')
  [].map.call(['f1','f2'], String).join('')
  String.prototype.replace.call('f1,f2', /,/g, '')

Distinct from F469 (Reflect.apply -- the Reflect API dispatch path).

Closure design (gov/dlp.py, F478):
  * `_js_apply_method` refactored: the argument-list core is now
    `_js_apply_method_at(text, i, ...)` (i at the first arg, not the
    paren); the public entry passes j+1. No behavior change.
  * New `_js_parse_prototype_dispatch`: the `X.prototype.METHOD` target
    form (X = Array | String), parsed in `_js_parse_primary` before the
    Array/String branches. The (X, METHOD) pairing is validated --
    `Array.prototype.replace` is undefined in node (TypeError), so an
    unvalidated desugar would mis-decode.
  * New `_js_parse_postfix_dispatch`: the `EXPR.METHOD` target form,
    checked in `_js_parse_postfix` before the method-name loop. EXPR's
    parsed type selects the pairing table; the dispatch's thisArg
    becomes the receiver (the target's base is only how the function
    is referenced).
  * Desugar: `.call(R, args...)` is exactly `R.M(args...)` via
    `_js_apply_method_at` -- same grammar, bounds, fail-closed as the
    direct form (F462 spread, F477 numeric coercion, F474 guards).
    `.apply(R, argsArray)` / `.bind(R, ...)(...)` supply arguments as
    values via the new `_js_concat_values` (concat only -- the filed
    shapes), mirroring the F462/F473/F474 branches exactly.
  * `_JS_EXPR_START` anchor extended with the X.prototype alternatives
    (ws-tolerant, character class only -- the F468 precedent).
  * Fail closed: invalid (X, METHOD) pairing; `.bind` without an
    immediate call; `.call` on non-modeled methods (ends chain, F461);
    `.apply`/`.bind` on non-concat (documented residual); non-array
    argsArray; third apply arg; unparseable thisArg; `new` on bound
    functions; Reflect-nested call/apply; left-boundary
    (`fooArray.prototype...`).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 11 filed shapes block (node-exact decode checked);
      generalizations (ws tolerance, zero-arg, bound+call args,
      F476 composition, reduceRight) block node-exactly.
  P2  fail-closed boundaries: invalid pairing, bind-no-call,
      non-modeled methods, non-concat apply/bind, non-array argsArray,
      junk quiet, F469/F473 neighbors intact.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored.
  P4  pin + footer (F478 CLOSED locally; open F479 / next F480).
"""

import os
import sys
import subprocess
import argparse
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-357 lane 1: F478 closed; no new decision codes
FOOTER_OPEN = "F479"  # Wave-357 lane 1: F478 CLOSED locally (merge finalizes tree-wide)
FOOTER_NEXT = "F480"

# Constructed via concatenation: the write path redacts credential literals.
_A = "xox" + "b-0123456789"
_B = "abc" + "def"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


# ---------------------------------------------------------------- P1: closure
def p1_filed_shapes_block():
    shapes = [
        "Array.prototype.concat.call([], '%s', '%s').join('')" % (_A, _B),
        "String.prototype.concat.call('%s','%s')" % (_A, _B),
        "[].concat.call([], '%s', '%s').join('')" % (_A, _B),
        "Array.prototype.join.call(['%s','%s'], '')" % (_A, _B),
        "Array.prototype.slice.call(['%s','%s'],0,2).join('')" % (_A, _B),
        "Array.prototype.concat.apply([], ['%s','%s']).join('')" % (_A, _B),
        "Array.prototype.reduce.call(['%s','%s'], (acc,curr)=>acc+curr, '')" % (_A, _B),
        "Array.prototype.filter.call(['%s','%s',''], x=>x!=='').join('')" % (_A, _B),
        "String.prototype.concat.bind('%s')('%s')" % (_A, _B),
        "[].map.call(['%s','%s'], String).join('')" % (_A, _B),
        "String.prototype.replace.call('%s,%s', /,/g, '')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "11/11 filed shapes blocked")


def p1_filed_shapes_node_exact():
    cases = [
        ("Array.prototype.concat.call([], 'ab', 'cd').join('')", "abcd"),
        ("String.prototype.concat.call('ab','cd')", "abcd"),
        ("[].concat.call([], 'ab', 'cd').join('')", "abcd"),
        ("Array.prototype.join.call(['ab','cd'], '-')", "ab-cd"),
        ("Array.prototype.slice.call(['ab','cd','ef'],1).join('')", "cdef"),
        ("Array.prototype.concat.apply(['ab'], [['cd','ef']]).join('')", "abcdef"),
        ("Array.prototype.reduce.call(['ab','cd'], (x,y)=>y+x, '')", "cdab"),
        ("String.prototype.concat.bind('ab','cd')('ef')", "abcdef"),
        ("[].map.call(['ab','cd'], String).join('')", "abcd"),
        ("String.prototype.replace.call('ab,cd', /,/g, '')", "abcd"),
    ]
    for payload, want in cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    return ("HELD", "10/10 dispatch decodes node-exact")


def p1_ws_tolerance():
    forms = [
        "Array . prototype . concat . call([], '%s', '%s').join('')",
        "Array.prototype.concat.call( [], '%s' , '%s' ).join('')",
        "String.prototype.concat . call('%s','%s')",
    ]
    for form in forms:
        payload = form % (_A, _B)
        d = _decoded(payload)
        if d != _A + _B or not _blocked(payload):
            return ("BREAK", "ws-tolerant form failed: %s" % form[:50])
    return ("HELD", "ws-tolerant dispatch forms decode")


def p1_f476_composition():
    # F476 factory feeding the dispatch receiver position.
    payload = "[].constructor.of('%s').concat.call(['%s'], '%s').join('')" % (_A, _B, "!")
    d = _decoded(payload)
    ok = (d == _B + "!" and _blocked(payload))
    return ("HELD" if ok else "BREAK", "F476+dispatch -> %r" % (d,))


def p1_reduceright_dispatch():
    # reduceRight is in the filed family; the dispatch desugars it too.
    payload = "Array.prototype.reduceRight.call(['%s','%s'], (x,y)=>x+y, '')" % (_A, _B)
    d = _decoded(payload)
    ok = (d == _B + _A and _blocked(payload))
    return ("HELD" if ok else "BREAK", "reduceRight dispatch -> %r" % (d,))


# ------------------------------------------------------- P2: fail-closed
def p2_invalid_pairing():
    cases = [
        "Array.prototype.replace.call('a,b', /,/g, '')",
        "[].replace.call('a,b', /,/g, '')",
        "String.prototype.join.call(['a'], '')",
        "String.prototype.slice.call('ab',0,1)",
    ]
    for payload in cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "invalid pairing decoded: %s" % payload[:50])
    return ("HELD", "invalid (X, METHOD) pairings fail closed")


def p2_bind_no_call():
    for payload in ["String.prototype.concat.bind('ab')",
                    "Array.prototype.concat.bind([])"]:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "bind-no-call decoded: %s" % payload[:50])
    return ("HELD", "bind without immediate call fails closed")


def p2_nonmodeled_methods():
    cases = [
        "[].repeat.call('ab', 2)",
        "Array.prototype.push.call([], 'a')",
        "String.prototype.padStart.call('ab', 5)",
    ]
    for payload in cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "non-modeled method decoded: %s" % payload[:50])
    return ("HELD", "non-modeled .call targets end the chain")


def p2_apply_bind_scope():
    cases = [
        "Array.prototype.join.apply(['a','b'], [''])",
        "Array.prototype.slice.bind(['a'])(0,1)",
        "Array.prototype.concat.apply([], 'ab')",
        "Array.prototype.concat.apply([], ['a'], 'x')",
    ]
    for payload in cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "out-of-scope apply/bind decoded: %s" % payload[:50])
    return ("HELD", "apply/bind scope boundaries fail closed")


def p2_hostile_targets():
    cases = [
        "foo.call('ab')",
        "Math.max.call(null, 1, 2)",
        "Array.prototype.concat.call(foo, 'a')",
        "fooArray.prototype.concat.call([], 'a')",
        "new (String.prototype.concat.bind('a'))('b')",
        "Reflect.apply(String.prototype.concat.bind, 'a', ['b'])",
    ]
    for payload in cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "hostile target decoded: %s" % payload[:50])
    return ("HELD", "hostile dispatch targets fail closed")


def p2_neighbors_intact():
    cases = [
        ("Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (_A, _B), True),
        ("['%s'].concat(['%s']).join('')" % (_A, _B), True),
        ("Array.prototype.concat.call([], 'ab', 'cd').join('')", False),
    ]
    for payload, want in cases:
        v, _ = _verdict(payload, want)
        if v != "HELD":
            return ("BREAK", "neighbor regression: %s" % payload[:50])
    return ("HELD", "F469/F473 neighbors intact; junk quiet")


# ---------------------------------------------------------------- P3: pins
def p3_node_differential():
    """Byte-identical node differential over the dispatch set."""
    shapes = [
        "Array.prototype.concat.call([], 'ab', 'cd').join('')",
        "String.prototype.concat.call('ab','cd')",
        "[].concat.call([], 'ab', 'cd').join('')",
        "Array.prototype.join.call(['ab','cd'], '')",
        "Array.prototype.slice.call(['ab','cd'],0,2).join('')",
        "Array.prototype.concat.apply([], ['ab','cd']).join('')",
        "Array.prototype.reduce.call(['ab','cd'], (acc,curr)=>acc+curr, '')",
        "Array.prototype.filter.call(['ab','cd',''], x=>x!=='').join('')",
        "String.prototype.concat.bind('ab')('cd')",
        "[].map.call(['ab','cd'], String).join('')",
        "String.prototype.replace.call('ab,cd', /,/g, '')",
    ]
    node_src = "const r=[];\n" + "\n".join(
        "try{r.push(JSON.stringify(%s))}catch(e){r.push('THROWS')}" % s
        for s in shapes)
    node_src += "\nconsole.log(JSON.stringify(r))"
    try:
        out = subprocess.run(["node", "-e", node_src], capture_output=True,
                             text=True, timeout=60)
        expected = [__import__("json").loads(x) for x in
                    __import__("json").loads(out.stdout.strip())]
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node failed: %s" % e)
    for s, exp in zip(shapes, expected):
        got = _decoded(s)
        if got != exp:
            return ("BREAK", "differential mismatch: %s -> %r want %r"
                    % (s[:45], got, exp))
    return ("HELD", "11/11 dispatch shapes byte-identical to node")


def p3_no_new_regexes():
    # The F478 anchor widening uses the ws character class only --
    # the same F468 precedent. Pin the exact pattern string.
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String[ \t\n\r]*\(|Array(\(|"
        r"[ \t\n\r]*(\.[ \t\n\r]*of|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect[ \t\n\r]*\.[ \t\n\r]*(construct|apply)|Object[ \t\n\r]*\.[ \t\n\r]*assign|\(")
    for s in ["Array.prototype.concat", "String.prototype.concat",
              "Array . prototype . concat"]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned")


def p3_f430_bounds():
    # Many-arg dispatch trips the parts budget instead of decoding.
    many = ", ".join(["'x'"] * 80)
    payload = "Array.prototype.concat.call([], %s).join('')" % many
    v, _ = _verdict(payload, False)
    if v != "HELD":
        return ("BREAK", "parts budget not enforced on dispatch")
    return ("HELD", "F430 parts budget enforced on dispatch args")


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
    ok = ok and "CLOSED 2026-10-06 wave-357 lane 1" in footer
    return ("HELD" if ok else "BREAK", "pin=%d footer" % len(codes))


_PROBES = [
    ("p1-filed-shapes-block", p1_filed_shapes_block),
    ("p1-filed-shapes-node-exact", p1_filed_shapes_node_exact),
    ("p1-ws-tolerance", p1_ws_tolerance),
    ("p1-f476-composition", p1_f476_composition),
    ("p1-reduceright-dispatch", p1_reduceright_dispatch),
    ("p2-invalid-pairing", p2_invalid_pairing),
    ("p2-bind-no-call", p2_bind_no_call),
    ("p2-nonmodeled-methods", p2_nonmodeled_methods),
    ("p2-apply-bind-scope", p2_apply_bind_scope),
    ("p2-hostile-targets", p2_hostile_targets),
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
    scripts = ("w356_attack_probes.py",
               "w356_f476close_probes.py",
               "w356_f477close_probes.py",
               "w356_f478_redfirst.py",
               "w355_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g357-green-%s-%d" % (script.replace(".py", ""),
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
    print("w357_f478close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
