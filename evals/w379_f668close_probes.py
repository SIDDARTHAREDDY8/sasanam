#!/usr/bin/env python3
"""Wave-379 lane 6: close F668 -- custom tag-function templates.

F668 (LOW, filed 2026-10-08 by wave-378 lane 7, attack round 46, local
node validation + 2 gpt-4o-mini calls, hints only, $0 spend): custom
tag-function templates bypass the bounded static JS-expression
decoder -- F463 (CLOSED) models only the String.raw tag form; an
arbitrary tag function receiving the strings array has no modeled
path:
(function(){function tag(s){return s[0]+'f2';}return tag`f1`;})() and
the raw-index twin
(function(){var tag=function(s){return s.raw[0]+'f2';};return tag`f1`;})()
both node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants. Distinct from F463 (String.raw),
F472/F493/F551/F575/F613 (String.raw positions).

Closure (gov/dlp.py): new _js_parse_f668_tag_iife (+
_js_parse_f668_tag_template_both, _js_scan_f668_body,
_js_parse_f668_tag_body_additive) parses
(function(){function NAME(s){return ADD;}return NAME`T`;})() and the
var-bound function-expression twin (var|let|const NAME=function(s){
return ADD;};). The tag receives the cooked strings array with a
.raw parallel array (node-exact v24.20.0); the body additive resolves
PARAM[<int>] to the cooked strings and PARAM.raw[<int>] to the raw
source text. ${ interpolation fails closed (the F463 discipline).
The decoded tag-call value flows through the normal postfix chain.
Hooked after F661 in _js_parse_primary. Zero new re.compile (28
stays).

Accepted generalizations (same mechanism, node-exact,
battery-pinned): named IIFE heads, named function expressions,
let/const twins, ASI (`;`-less bodies, `;` after a function
declaration), whitespace, escapes (cooked vs raw diverge
node-exactly). Pre-existing blocking (not this lane): return-position
`tag`+`'LIT'` composition already blocks on the base tree via the
template route -- pinned as blocking, composition safety holds.

Fail-closed boundaries (documented residuals): ${ interpolation,
multi/rest/default params, out-of-range or non-integer indices, a
callee other than the declared tag, a bare `s` read (no index),
non-raw member reads (s.foo[0]), invocation with arguments,
undeclared tag names, reserved-word tag/param names, extra
statements in the body, nested function expressions in the body,
`{`/`(`/backtick inside the body, member-expression tag calls
(obj.tag`..`), s.length, bare `tag` template at expression level
(no IIFE binding).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov.dlp import find_credential, _try_js_expr_decode_all  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_BT = chr(96)

results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decodes_exact(payload, expect):
    """Internal-seam exact decode: the JS-expression variant equals expect."""
    v = _try_js_expr_decode_all(payload)
    return v == expect


# ------------------------------------------------ F668 filed shapes (must block)

def test_p1_filed_strings_idx():
    """Filed shape 1: function declaration, s[0] cooked index."""
    s = ("(function(){function tag(s){return s[0]+'%s';}return tag%s%s%s;})()"
         % (_B, _BT, _A, _BT))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


def test_p1_filed_raw_idx():
    """Filed shape 2: var-bound function expression, s.raw[0]."""
    s = ("(function(){var tag=function(s){return s.raw[0]+'%s';};"
         "return tag%s%s%s;})()" % (_B, _BT, _A, _BT))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------ variants (node-exact, pinned)

def test_p2_variants():
    """Node-exact variants: escapes, named forms, let/const, ASI, ws."""
    cases = [
        # (name, payload, expected decode)
        ("escape-cooked-raw",
         "(function(){function tag(s){return s[0]+'/'+s.raw[0];}return tag`a\\nb`;})()",
         "a\nb/a\\nb"),
        ("raw-second",
         "(function(){function tag(s){return 'A'+s.raw[0];}return tag`a\\nb`;})()",
         "A" + "a\\nb"),
        ("named-iife",
         "(function foo(){function tag(s){return s[0];}return tag`ab`;})()",
         "ab"),
        ("named-fnexpr",
         "(function(){var tag=function mytag(s){return s[0];};return tag`ab`;})()",
         "ab"),
        ("let-twin",
         "(function(){let tag=function(s){return s[0];};return tag`ab`;})()",
         "ab"),
        ("const-twin",
         "(function(){const tag=function(s){return s[0];};return tag`ab`;})()",
         "ab"),
        ("no-semi-body",
         "(function(){function tag(s){return s[0]}return tag`ab`;})()",
         "ab"),
        ("semi-after-decl",
         "(function(){function tag(s){return s[0];};return tag`ab`;})()",
         "ab"),
        ("ws",
         "(function(){ function tag ( s ) { return s [ 0 ] ; } return tag `ab` ; })()",
         "ab"),
        ("multi-term",
         "(function(){function tag(s){return s[0]+'-'+s.raw[0];}return tag`ab`;})()",
         "ab-ab"),
        ("dq-template-adjacent",
         "(function(){function tag(s){return s[0];}return tag`a\"b`;})()",
         "a\"b"),
    ]
    bad = []
    for name, payload, expect in cases:
        v = _try_js_expr_decode_all(payload)
        if v != expect:
            bad.append("%s: got %r want %r" % (name, v, expect))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d exact%s" % (len(cases) - len(bad), len(cases),
                               "" if ok else " :: " + "; ".join(bad)))


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_bounds():
    """Fail-closed bounds: every shape misses the credential."""
    shapes = [
        ("interp",
         "(function(){function tag(s){return s[0];}return tag`ab${'x'}`;})()"),
        ("two-params",
         "(function(){function tag(s,t){return s[0];}return tag`ab`;})()"),
        ("rest-param",
         "(function(){function tag(s,...r){return s[0];}return tag`ab`;})()"),
        ("default-param",
         "(function(){function tag(s='x'){return s[0];}return tag`ab`;})()"),
        ("oor-index",
         "(function(){function tag(s){return s[5]+'x';}return tag`ab`;})()"),
        ("nonint-index",
         "(function(){function tag(s){return s[x]+'x';}return tag`ab`;})()"),
        ("callee-mismatch",
         "(function(){function tag(s){return s[0];}return other`ab`;})()"),
        ("bare-s",
         "(function(){function tag(s){return s;}return tag`ab`;})()"),
        ("bad-member",
         "(function(){function tag(s){return s.foo[0];}return tag`ab`;})()"),
        ("invoke-args",
         "(function(){function tag(s){return s[0];}return tag`ab`;})('x')"),
        ("undeclared-tag",
         "(function(){return tag`ab`;})()"),
        ("reserved-tag",
         "(function(){function while(s){return s[0];}return while`ab`;})()"),
        ("reserved-param",
         "(function(){function tag(class){return class[0];}return tag`ab`;})()"),
        ("extra-stmt",
         "(function(){function tag(s){return s[0];}var x=1;return tag`ab`;})()"),
        ("nested-fn",
         "(function(){function tag(s){return function(){return 1;}();}return tag`ab`;})()"),
        ("brace-in-body",
         "(function(){function tag(s){return {x:s[0]};}return tag`ab`;})()"),
        ("call-in-body",
         "(function(){function tag(s){return s[0].toString();}return tag`ab`;})()"),
        ("member-tag-call",
         "(function(){var o={tag:function(s){return s[0];}};return o.tag`ab`;})()"),
        ("length-read",
         "(function(){function tag(s){return s.length;}return tag`ab`;})()"),
        ("double-index",
         "(function(){function tag(s){return s[0][0];}return tag`ab`;})()"),
    ]
    bad = [name for name, p in shapes if not _misses(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d miss%s" % (len(shapes) - len(bad), len(shapes),
                              "" if ok else " :: blocked=" + ",".join(bad)))


# ------------------------------------------------ sibling closures still held

def test_p4_sibling_closures_hold():
    """String.raw family (F463/F613/F472/F493/F551/F575) still blocks."""
    cases = [
        ("f463-string-raw-tag", "String.raw`%s`+'%s'" % (_A, _B)),
        ("f613-raw-call-subst",
         "String.raw({raw:['%s','']},'%s')" % (_A, _B)),
        ("array-join", "['%s','%s'].join('')" % (_A, _B)),
        ("join-tag-empty", "['%s','%s'].join``" % (_A, _B)),
    ]
    bad = [name for name, p in cases if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d held%s" % (len(cases) - len(bad), len(cases),
                              "" if ok else " :: missed=" + ",".join(bad)))


# ------------------------------------------------ open neighbors still miss (nothing absorbed)

_OPEN_NEIGHBORS = [
    ("f662", "(function(){class C{static x='%s';}return C.x+'%s';})()" % (_A, _B)),
    ("f663", "(function(){var o=Object.fromEntries([['x','%s']]);return o.x+'%s';})()" % (_A, _B)),
    ("f664", "(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B)),
    ("f665", "(function(){var o={x:'%s'};return o?.x+'%s';})()" % (_A, _B)),
    ("f666", "(function(){var p=new Proxy(function(){},{apply:function(){return '%s';}});return p()+'%s';})()" % (_A, _B)),
    ("f667", "(function(){var o={x:'%s'};with(o){return x+'%s';}})()" % (_A, _B)),
    ("f669", "(function(){var st=new Set(['%s','%s']);return [...st].join('');})()" % (_A, _B)),
    ("f670", "(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()" % (_A, _B)),
    ("f671", "(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B)),
]


def test_p5_open_neighbors_still_miss():
    """F662-F667/F669-F671 now CLOSED (wave-379 merge): representative shapes block."""
    bad = [name for name, p in _OPEN_NEIGHBORS if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d block%s" % (len(_OPEN_NEIGHBORS) - len(bad),
                              len(_OPEN_NEIGHBORS),
                              "" if ok else " :: not_blocked=" + ",".join(bad)))


# ------------------------------------------------ junk quiet + composition

def test_p6_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


def test_p6_composition():
    """Return-position tag+'LIT' composition blocks (pre-existing route)."""
    hit = _blocked("(function(){function tag(s){return s[0];}return tag`%s`+'%s';})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------ node differential

def test_p7_node_differential():
    """Decoder agrees with node v24.20.0 on the exact-decode set."""
    try:
        out = subprocess.run(
            ["node", "-e",
             "const cs=["
             "[\"(function(){function tag(s){return s[0]+'B';}return tag`A`;})()\",\"AB\"],"
             "[\"(function(){var tag=function(s){return s.raw[0]+'B';};return tag`A`;})()\",\"AB\"]"
             "];"
             "for(const [src,want] of cs){"
             "  const got=eval(src);"
             "  if(got!==want){console.log('NODE-MISMATCH '+src+' got='+JSON.stringify(got));process.exit(1);}"
             "}"
             "console.log('node-ok');"],
            capture_output=True, text=True, timeout=30)
        node_ok = (out.returncode == 0 and "node-ok" in (out.stdout or ""))
    except Exception:
        node_ok = False
    dec_ok = all(_decodes_exact(p, e) for p, e in [
        ("(function(){function tag(s){return s[0]+'B';}return tag`A`;})()", "AB"),
        ("(function(){var tag=function(s){return s.raw[0]+'B';};return tag`A`;})()", "AB"),
    ])
    ok = node_ok and dec_ok
    return ("HELD" if ok else "BREAK", "node=%s dec=%s" % (node_ok, dec_ok))


# ------------------------------------------------ pin + footer + re.compile

def test_p8_pin_footer():
    """Pin 2143 and lane-local footer (F668 CLOSED: open F662-F667,F669-F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-379 lane 6: F668 CLOSED; footer repoint open F662-F667,F669-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-379 lane 6: F668 CLOSED; footer repoint open F662-F667,F669-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and (_dlp is not None)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


def test_p8_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ perf

def test_p9_perf():
    """200 mixed F668 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){function tag(s){return s[0];}return tag`a%d`;})()" % k)
        corpus.append("(function(){var tag=function(s){return s.raw[0];};return tag`b%d`;})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ green check (depth-1)

def test_p10_green_check():
    """Depth-1 green check: F668 red-first + F463 close battery + w378 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w378_f668_redfirst.py", 0),
                               ("evals/w353_f463close_probes.py", 0),
                               ("evals/w378_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif "BREAK /" in line and "HELD" in line:
                try:
                    nbreak = int(line.split("BREAK")[0].rsplit(":", 1)[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        if name == "test_p8_pin_footer":
            continue  # runs after the footer repoint; see below
        _t(name, globals()[name])
    # Footer repoint must land before the pin+footer probe runs.
    _t("test_p8_pin_footer", test_p8_pin_footer)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
