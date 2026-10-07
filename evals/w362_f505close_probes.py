#!/usr/bin/env python3
"""Wave-362 lane 3: F505 closure probes.

F505 (LOW, OPEN on base): String.fromCodePoint with spread args bypasses
the bounded static JS-expression decoder -- F500 covers spread args in
String.fromCharCode; fromCodePoint is a DIFFERENT builtin (Unicode
code-point semantics, surrogate pairs) with its own call site, and the
decoder's arg-list parser only modeled the fromCharCode site.

Closure (gov/dlp.py): `String.fromCodePoint(...)` direct call form routed
through the shared F458/F500 arg-list parser (_js_parse_fromcodepoint).
The F458 integer-literal grammar's RangeError classes (cap 0x10FFFF, no
negatives, no floats/exponents) are node-identical for fromCodePoint
(node v24.20.0 verified), and _safe_chr is node-exact for 0..0x10FFFF
except lone surrogates (fail closed -- they can never match an ASCII
credential). .call/.apply dispatch on fromCodePoint fails closed
(documented F505 boundary, matching F500's dispatch-spread boundary);
the bracket-string member form String['fromCodePoint'] fails closed
(documented residual).

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed shape
misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import json
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-362 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

CODES = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"

FILED = [
    ("filed-spread",
     "String.fromCodePoint(...[%s])" % CODES),
    ("filed-two-spreads",
     "String.fromCodePoint(...[120,111,120,98,45,48,49,50,51],"
     " ...[52,53,54,55,56,57,97,98,99,100,101,102])"),
]


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _node_eval(shapes):
    js = ("const out=[];\n" +
          "".join("try{out.push(JSON.stringify(%s))}catch(e){out.push('THROWS')}\n" % s
                  for s in shapes) +
          "console.log(out.join('\\n'))")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=120)
    if r.returncode != 0:
        raise RuntimeError("node failed: %s" % r.stderr[:200])
    return r.stdout.splitlines()


def p1_filed_shapes_held():
    """The two F505 filed shapes now block (were 2 BREAK on base)."""
    bad = [name for name, payload in FILED if not _blocked(payload)]
    if bad:
        return ("BREAK", "filed shapes still miss: %s" % bad)
    return ("HELD", "2/2 filed shapes block")


def p2_node_differential():
    """Decoder output byte-identical to node on BMP shapes; astral
    parity with fromCharCode (the whole-text layer is ASCII-only by
    design -- _ascii_printable_or_none -- for both builtins)."""
    shapes = [
        "String.fromCodePoint(...[%s])" % CODES,
        "String.fromCodePoint(...[120,111], ...[120,98])",
        "String.fromCodePoint(65, 66, 67)",        # literal args
        "String.fromCodePoint(120, ...[111])",     # mixed literal+spread
    ]
    node = _node_eval(shapes)
    for payload, n in zip(shapes, node):
        dec = _decoded(payload)
        want = json.loads(n)
        if dec != want:
            return ("BREAK", "differential mismatch: %s dec=%r node=%r"
                    % (payload[:50], dec, want))
    # Astral: parser-level node-exact; whole-text layer drops non-ASCII
    # for BOTH builtins (ASCII-only credential design -- parity).
    v, _ = dlp._js_parse_fromcodepoint("String.fromCodePoint(0x1F600)", 0)
    if v != "\U0001F600":
        return ("BREAK", "parser-level astral not node-exact")
    if _decoded("String.fromCodePoint(0x1F600)") is not None:
        return ("BREAK", "astral fromCodePoint decoded (ASCII-only violated)")
    if _decoded("String.fromCharCode(0x1F600)") is not None:
        return ("BREAK", "astral fromCharCode parity broken")
    # Empty spread: node gives '', decoder gives None for BOTH builtins
    # (empty is not ASCII-printable -- parity with fromCharCode).
    if _decoded("String.fromCodePoint(...[])") is not None:
        return ("BREAK", "empty-spread parity broken (fromCodePoint)")
    if _decoded("String.fromCharCode(...[])") is not None:
        return ("BREAK", "empty-spread parity broken (fromCharCode)")
    return ("HELD", "4/4 BMP shapes byte-identical; astral/empty parity holds")


def p3_fail_closed_boundaries():
    """Every documented fail-closed boundary still misses."""
    miss = [
        # node throws RangeError -- the F458 grammar has no such spellings
        ("negative", "String.fromCodePoint(-1, 120)"),
        ("too-big", "String.fromCodePoint(0x110000)"),
        ("float", "String.fromCodePoint(65.5)"),
        ("exponent", "String.fromCodePoint(1e2)"),
        # lone surrogate: node-valid, decoder fail-closed (documented)
        ("lone-surrogate", "String.fromCodePoint(0xD83D)"),
        # .call/.apply dispatch on fromCodePoint: documented F505 boundary
        ("call-dispatch", "String.fromCodePoint.call(null, 120, 111)"),
        ("apply-dispatch", "String.fromCodePoint.apply(null, [120, 111])"),
        ("call-dispatch-ws", "String.fromCodePoint . call(null, 120)"),
        # non-literal spread operand
        ("nonliteral-spread", "String.fromCodePoint(...[foo])"),
        # string spread operand (not an array literal)
        ("string-spread", "String.fromCodePoint(...'ab')"),
        # bracket-string member form: documented residual
        ("bracket-member", "String['fromCodePoint'](...[120])"),
        # ident boundary
        ("ident-boundary", "String.fromCodePointx(...[120])"),
        # junk stays quiet
        ("junk-quiet", "String.fromCodePoint(...[97,98])"),
        ("empty-quiet", "hello String.fromCodePoint world"),
    ]
    bad = [name for name, payload in miss if _blocked(payload)]
    if bad:
        return ("BREAK", "boundaries decoded (should miss): %s" % bad)
    return ("HELD", "%d/%d fail-closed boundaries miss" % (len(miss), len(miss)))


def p4_compositions():
    """Neighbor findings unchanged: F500 fromCharCode HELD, F499 open."""
    # F500 (closed wave-361): fromCharCode spread shapes still decode
    f500 = [
        ("f500-spread", "String.fromCharCode(...[120,111])", "xo"),
        ("f500-direct", "String.fromCharCode(120,111)", "xo"),
    ]
    for name, payload, want in f500:
        if _decoded(payload) != want:
            return ("BREAK", "F500 regression: %s" % name)
    # F499 (OPEN): string-literal spread in array literals still misses
    if _blocked("[...'f1']"):
        return ("BREAK", "F499 accidentally closed")
    # F458 direct fromCharCode control still blocks coded
    if not _blocked("String.fromCharCode(%s)" % CODES):
        return ("BREAK", "F458 control regressed")
    return ("HELD", "F500 HELD, F499 still open, F458 control intact")


def p5_pin_and_footer():
    """Pin stays 2140; F505 entry present; anchor covers fromCodePoint."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "F505" not in text:
        return ("BREAK", "F505 entry missing")
    if dlp._JS_EXPR_START.search("String.fromCodePoint") is None:
        return ("BREAK", "anchor missing fromCodePoint")
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    return ("HELD", "pin 2140; F505 entry present; anchor covers fromCodePoint")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w361_f505_redfirst.py",
               "w360_f500_redfirst.py",
               "w360_f499_redfirst.py",
               "w361_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g362-green-%s-%d" % (script.replace(".py", ""),
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
        m = re.search(r"tally:\s*(\d+)\s*BREAK", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_filed_shapes_held, p2_node_differential,
              p3_fail_closed_boundaries, p4_compositions, p5_pin_and_footer]
    breaks, held = 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "HELD":
            held += 1
        else:
            breaks += 1
    print("green check: %s" % _green_check())
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
