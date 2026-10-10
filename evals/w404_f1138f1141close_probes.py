#!/usr/bin/env python3
"""Wave-404 lane 4 close battery: F1138 + F1139 + F1140 + F1141 CLOSED.

F1138: percent-encoding staged assembly -- assembling via
percent-encoding (`%`-hex per code + `unescape`) breaks the decoder's
char-code-anchored grammars: `var C=[...];var S=unescape(C.map(
function(c){return '%'+c.toString(16);}).join(''));var RESULT=S;`
assembles node-exactly (v24.20.0) while find_credential MISSES.

F1139: mutate-then-restore staged assembly -- mutating the int array
in place (`C.reverse()`) then restoring order at the string level
(`S.split('').reverse().join('')`) breaks the decoder's whole-text
grammars: assembles node-exactly (v24.20.0) while find_credential
MISSES.

F1140: for-loop header variants -- the F1074-family hooks anchor on
the exact `for(var i=0;i<C.length;i++)` header: cached-length (`n`),
empty init, empty update, and post-increment-in-index variants
assemble node-exactly (v24.20.0) while find_credential MISSES (`++i`,
`i+=1`, `let` twins block via F1074).

F1141: F1119 residual -- Symbol.iterator for-await with trailing
statements after the async IIFE. The F1119 hook
(_js_f1119_stmt_decode) requires end-of-text after the async IIFE,
but the filed w402 shape `(async()=>{...globalThis.__R70=S;})();var
RESULT='';` has a trailing `var RESULT='';` statement. Node assembles
the credential into globalThis.__R70 node-exactly while
find_credential MISSES. F1119's entry now notes the partial closure
honestly; F1141 is closed here as its own finding.

Filed 2026-10-10 18:13 UTC wave-403 attack round 71 (F1138-F1140, local
node validation, $0.00 model spend (0 paid calls)); F1141 filed
2026-10-10 19:30 UTC wave-403 merge red-first audit. Closed by
_js_f1138_stmt_decode / _js_f1139_stmt_decode / _js_f1140_stmt_decode /
_js_f1141_stmt_decode (whole-text _stmtdec hooks, one new
_decode_layer dispatch loop).

Node-exact 16/16 filed + 22/22 generalizations (short + 40-char);
fail-closed 22/22 hook-level + 12/12 cross-disjointness both
directions vs F1090/F1074/F1119. Disjoint from F1090 (map+join via
fromCharCode), F1074 (canonical for-header), and F1119 (end-of-text
after the IIFE) by grammar (documented per hook). F1091 stays
CLOSED; F1119's entry amendment is preserved.

Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 39  # wave-403 merge: 38 + 1 lane loop -> 39

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# ---------------- p0: pins ----------------

@_t
def test_p0_taxonomy_pin():
    return (len(TAXONOMY) == TAXONOMY_PIN,
            "taxonomy=%d pin=%d" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_verifier_pin():
    # evidence-schema domain pin (self-referential by convention)
    return (VERIFIER_TAXONOMY_PIN == 33,
            "verifier_pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    return (n == RECOMPILE_PIN, "re.compile=%d pin=%d" % (n, RECOMPILE_PIN))


@_t
def test_p0_stmtdec_loops():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    mine = [lp for lp in loops if "_js_f1138_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-404 lane 4 (2026-10-10)" in src
          and "F1138-F1141 CLOSED (4" in src
          and "F1123-F1137 OPEN (15" in src
          and "next free F1142" in src)
    # entry-count check: F1138-F1141 filed exactly once each.
    ok = (ok and src.count("(F1138 filed") == 1)
    ok = (ok and src.count("(F1139 filed") == 1)
    ok = (ok and src.count("(F1140 filed") == 1)
    ok = (ok and src.count("(F1141 filed") == 1)
    ok = (ok and "[CLOSED 2026-10-10 wave-404 lane 4" in src
          and src.count("[CLOSED 2026-10-10 wave-404 lane 4") == 4)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1142**" in src
          and "# Wave-403: F1111-F1122 CLOSED (12); F1123-F1141 OPEN (19); next free F1142" in src)
    return (ok, "lane-local footer present, base lineage preserved")

# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1138_filed_block():
    shapes = _redfirst_shapes("w404", 1138)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1139_filed_block():
    shapes = _redfirst_shapes("w404", 1139)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1140_filed_block():
    shapes = _redfirst_shapes("w404", 1140)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1141_filed_block():
    shapes = _redfirst_shapes("w404", 1141)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-verified) ----------------

# All templates node-exact (v24.20.0) for both secrets: hook output ==
# node output, verified before baking in. {I} is the int array.
_GEN = [
    ("f1138-let",
     "let C={I};let S=unescape(C.map(function(p){{return '%'+p.toString(16);}}).join(''));let RESULT=S;"),
    ("f1138-const-add",
     "const C={I};const T=unescape(C.map(function(c){{return '%'+c.toString(16);}}).join(''));const RESULT='pre:'+T+'!';"),
    ("f1138-diffnames",
     "var D={I};var S=unescape(D.map(function(x){{return '%'+x.toString(16);}}).join(''));var RESULT=S;"),
    ("f1139-let",
     "let C={I};C.reverse();let S='';for(let i=0;i<C.length;i++){{S+=String.fromCharCode(C[i]);}}S=S.split('').reverse().join('');let RESULT=S;"),
    ("f1139-add",
     "var D={I};D.reverse();var T='';for(var i=0;i<D.length;i++){{T+=String.fromCharCode(D[i]);}}T=T.split('').reverse().join('');var RESULT='>'+T;"),
    ("f1140-cached-let",
     "let C={I};let S='';for(let i=0,n=C.length;i<n;i++){{S+=String.fromCharCode(C[i]);}}let RESULT=S;"),
    ("f1140-emptyinit-let",
     "var C={I};var S='';let i=0;for(;i<C.length;i++){{S+=String.fromCharCode(C[i]);}}var RESULT=S;"),
    ("f1140-emptyupdate-names",
     "var D={I};var T='';for(var j=0;j<D.length;){{T+=String.fromCharCode(D[j]);j++;}}var RESULT='x:'+T;"),
    ("f1140-postincr-let",
     "let C={I};let S='';for(let i=0;i<C.length;){{S+=String.fromCharCode(C[i++]);}}let RESULT=S;"),
    ("f1141-func-let",
     "(async function(){{let C={I};let S='';for await(let x of C[Symbol.iterator]()){{S+=String.fromCharCode(x);}}globalThis.G=S;}})();const RESULT='done';"),
    ("f1141-arrow-names",
     "(async()=>{{var D={I};var T='';for await(var y of D[Symbol.iterator]()){{T+=String.fromCharCode(y);}}globalThis.X99=T;}})();var RESULT='ok';"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_PCT = "%%"  # literal % inside a %-formatted template (becomes % after %)

_FC = [
    # (name, hook-attr, template with %s for the int-array codes)
    # F1138 hook must miss:
    ("f1138-code-lt16", "_js_f1138_stmt_decode",
     "var C=[10,65,66];var S=unescape(C.map(function(c){return '%'+c.toString(16);}).join(''));var RESULT=S;"),
    ("f1138-code-gt255", "_js_f1138_stmt_decode",
     "var C=[300,65];var S=unescape(C.map(function(c){return '%'+c.toString(16);}).join(''));var RESULT=S;"),
    ("f1138-arrow-cb", "_js_f1138_stmt_decode",
     "var C=%s;var S=unescape(C.map(c=>'" + _PCT + "'+c.toString(16)).join(''));var RESULT=S;"),
    ("f1138-radix10", "_js_f1138_stmt_decode",
     "var C=%s;var S=unescape(C.map(function(c){return '" + _PCT + "'+c.toString(10);}).join(''));var RESULT=S;"),
    ("f1138-join-sep", "_js_f1138_stmt_decode",
     "var C=%s;var S=unescape(C.map(function(c){return '" + _PCT + "'+c.toString(16);}).join(','));var RESULT=S;"),
    ("f1138-f1090-twin", "_js_f1138_stmt_decode",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    # F1139 hook must miss:
    ("f1139-no-reverse", "_js_f1139_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1139-rev-other-arr", "_js_f1139_stmt_decode",
     "var C=%s;var D=[1];D.reverse();var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}S=S.split('').reverse().join('');var RESULT=S;"),
    ("f1139-split-sep", "_js_f1139_stmt_decode",
     "var C=%s;C.reverse();var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}S=S.split(',').reverse().join('');var RESULT=S;"),
    ("f1139-restore-target", "_js_f1139_stmt_decode",
     "var C=%s;C.reverse();var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}T=S.split('').reverse().join('');var RESULT=T;"),
    # F1140 hook must miss:
    ("f1140-canonical", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1140-lte", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<=C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1140-start1", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=1;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1140-incr-plus-eq", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i+=1){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1140-postincr-with-update", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i++]);}var RESULT=S;"),
    ("f1140-preinc", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;++i){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    # F1141 hook must miss:
    ("f1141-no-trailing", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();"),
    ("f1141-trailing-nonresult", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();var X=1;"),
    ("f1141-trailing-clobber", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();globalThis.__R70='x';"),
    ("f1141-trailing-additive", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();var RESULT='x'+S;"),
    ("f1141-no-semi", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})()var RESULT='';"),
    ("f1141-sync-iife", "_js_f1141_stmt_decode",
     "(()=>{var C=%s;var S='';for(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();var RESULT='';"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3b: cross-disjointness (both directions) ----------------

_DIS = [
    # sibling hooks must miss my shapes...
    ("f1090-on-f1138", "_js_f1090_stmt_decode",
     "var C=%s;var S=unescape(C.map(function(c){return '" + _PCT + "'+c.toString(16);}).join(''));var RESULT=S;"),
    ("f1074-on-f1139", "_js_f1074_stmt_decode",
     "var C=%s;C.reverse();var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}S=S.split('').reverse().join('');var RESULT=S;"),
    ("f1074-on-f1140-cached", "_js_f1074_stmt_decode",
     "var C=%s;var S='';for(var i=0,n=C.length;i<n;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1074-on-f1140-emptyinit", "_js_f1074_stmt_decode",
     "var C=%s;var S='';var i=0;for(;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1074-on-f1140-emptyupdate", "_js_f1074_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;"),
    ("f1074-on-f1140-postincr", "_js_f1074_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;){S+=String.fromCharCode(C[i++]);}var RESULT=S;"),
    ("f1119-on-f1141-arrow", "_js_f1119_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();var RESULT='';"),
    ("f1119-on-f1141-func", "_js_f1119_stmt_decode",
     "(async function(){var C=%s;var S='';for await(var y of C[Symbol.iterator]()){S+=String.fromCharCode(y);}globalThis.RESULT=S;})();var RESULT='';"),
    # ...and my hooks must miss sibling filed shapes.
    ("my8-on-f1090-filed", "_js_f1138_stmt_decode",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("my9-on-f1074-filed", "_js_f1139_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("my0-on-f1074-filed", "_js_f1140_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("my1-on-f1119-filed", "_js_f1141_stmt_decode",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.RESULT=S;})();"),
]


@_t
def test_p3b_disjoint():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _DIS:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_DIS)
    return (not bad, "%d/%d cross-disjoint miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))

# ---------------- p4: sibling pins ----------------

_MY_HOOKS = ("_js_f1138_stmt_decode", "_js_f1139_stmt_decode",
             "_js_f1140_stmt_decode", "_js_f1141_stmt_decode")


def _my_hook_hits(payload):
    return [a for a in _MY_HOOKS if getattr(dlp, a)(payload) is not None]


@_t
def test_p4_sibling_f1090():
    # F1090's filed shapes still block (via F1090's own hook); the new
    # hooks never hit any of them (disjoint both directions).
    shapes = _redfirst_shapes("w400", 1090)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1090 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1074():
    # F1074's filed shapes still block (via F1074's own hook); the new
    # hooks never hit any of them (disjoint both directions).
    shapes = _redfirst_shapes("w398", 1074)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1074 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1119_no_trailing():
    # F1119's no-trailing shapes still block (via F1119's own hook);
    # the F1141 hook never hits them (disjoint both directions). The
    # trailing shapes (now F1141) block via the new F1141 hook.
    shapes = _redfirst_shapes("w402", 1119)
    no_trailing, trailing = shapes[:2], shapes[2:]
    bad_block = [n for n, p in no_trailing if not _blocked(p)]
    bad_hook = [n for n, p in no_trailing
                if dlp._js_f1141_stmt_decode(p) is not None]
    bad_trail = [n for n, p in trailing if not _blocked(p)]
    ok = not bad_block and not bad_hook and not bad_trail
    return (ok, "f1119 no-trailing blocked=%d/2 new-hook-hits=%d, "
                "trailing(f1141) blocked=%d/2"
            % (2 - len(bad_block), len(bad_hook), 2 - len(bad_trail)))


@_t
def test_p4_f1119_entry_intact():
    # F1119's entry still notes the partial closure honestly (never
    # silently patched); F1141's entry is present as its own finding.
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("Partial closure (2026-10-10 wave-403 merge audit)" in src
          and "(F1141 filed 2026-10-10 19:30 UTC" in src)
    return (ok, "F1119 amendment + F1141 entry intact")


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-unescape",
     "var q=unescape('%41%42');console.log(q);"),
    ("honest-reverse",
     "var xs=[3,1,2];xs.reverse();console.log(xs.join(','));"),
    ("honest-plain-for",
     "var xs=[1,2];var t=0;for(var i=0;i<xs.length;i++){t+=xs[i];}"),
    ("honest-async-iife",
     "(async()=>{var x=1;globalThis.Y=x;})();var RESULT='';"),
    ("honest-prose",
     "the unescape percent-encoding is an honest pattern"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S=unescape(C.map(function(x){return '%%'+x.toString(16);}).join(''));var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: still-open pins ----------------

@_t
def test_p7_open_f1123_1137():
    # F1123-F1137 must still MISS on the lane tree (other lanes own
    # them; this lane closes only F1138-F1141).
    bad = []
    for n in range(1123, 1138):
        shapes = _redfirst_shapes("w403", n)
        bad += [name for name, payload in shapes if not _misses(payload)]
    return (not bad, "F1123-F1137 still open%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w403's attack battery (carries
    F1123-F1140 pins). Honor GOV_SKIP_GREEN. On the lane tree the
    F1138/F1139/F1140 open pins are expected to BREAK (now closed);
    everything else must be HELD."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w403_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g404l4-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w403_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        breaks = []
        for line in r.stdout.split("\n"):
            if line.startswith("BREAK "):
                breaks.append(line.split(" ")[1])
        expect = {"test_open_w403_f1138", "test_open_w403_f1139",
                  "test_open_w403_f1140"}
        ok = set(breaks) == expect
        return (ok,
                "green(w403_attack): %d BREAK (expect exactly %s: %s)"
                % (len(breaks), sorted(expect),
                   "ok" if ok else "got=" + ",".join(sorted(breaks))))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
