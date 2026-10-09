#!/usr/bin/env python3
"""Wave-387 lane 9: close F861 + F862 + F863 + F864.

F861 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder has no Headers production -- `h.set('x-k','f1');h.get('k')`
and the `new Headers({'x-k':'f1'})` constructor twin resolve
node-exactly while the decoder produced zero variants.

F862 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models `new Error('f1').message` through the try/catch routes
(F750/F787) but not direct subclass message reads --
`new TypeError('f1').message` and `new DOMException('f1').message`
resolve node-exactly while the decoder produced zero variants.

F863 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models plain JSON but not `toJSON` --
`JSON.parse(JSON.stringify({toJSON:()=>'f1'}))` resolves node-exactly
while the decoder produced zero variants.

F864 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models plain JSON.parse and guarded revivers (F683/F744) but
not IDENTITY revivers --
`JSON.parse('{"k":"f1"}',(k,v)=>v)` resolves node-exactly while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- count stays 28):
- F861: _js_parse_f861_headers_iife -- var/const/let binding, no-arg /
  object / sequence ctor, set/append mutations, get terminal with a
  string-literal additive tail. Node-exact (v24.20.0): names
  lowercased + token-validated, values OWS-trimmed, set replaces,
  append joins with ", ". Hooked after F810; disjoint by binding
  head.
- F862: _js_parse_f862_error_message_iife -- `[new] CTOR('LIT').message`
  with a string-literal additive tail; DOMException new-only.
  Hooked after F861; disjoint by bare-return head.
- F863: _js_parse_f863_tojson_value + _js_parse_f863_tojson_fn --
  toJSON function props resolving to plain strings; hooked into
  _js_parse_f571_stringify_call's object branch (before F595) and as
  an F611 varbound initializer. Disjoint: F595 fails closed on
  function-valued props.
- F864: _js_parse_f864_identity_reviver + _js_f864_identity_return --
  `function(k,v){return v;}`, the `k===''?v:v` guard twin, and the
  arrow twins; hooked after F744 in the JSON dispatch. Disjoint:
  F683/F744 require non-identity consequents.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed /var/tmp TMPDIRs), no in-repo git in
self-pins, concatenation-constructed credentials, pin 2143,
VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider openai / ledger refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane
EXPECTED_RE_COMPILE = 28  # zero new re.compile( this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decodes(payload):
    return dlp._try_js_expr_decode_all(payload)


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins
@_t
def test_p0_pin_taxonomy():
    """Every *_PIN in gov.dlp stays 2143; registry loads."""
    import gov.dlp as _d
    pins = []
    for name in dir(_d):
        if name.endswith("_PIN") and name != "VERIFIER_TAXONOMY_PIN":
            v = getattr(_d, name)
            if isinstance(v, int):
                pins.append((name, v))
    bad = [n for n, v in pins if v != TAXONOMY_PIN]
    ok = not bad and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK",
            "pins-ok" if ok else "stale=%s" % (bad[:3],))


@_t
def test_p0_no_new_re_compile():
    """Zero new re.compile( in gov/dlp.py (count stays 28)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == EXPECTED_RE_COMPILE else "BREAK",
            "re.compile=%d" % n)


# ------------------------------------------------ p1: filed shapes
@_t
def test_p1_f861_s1():
    """F861 s1: Headers set/get blocks."""
    hit = _blocked("(function(){var h=new Headers();h.set('x-k','%s');"
                   "return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f861_s2():
    """F861 s2: Headers object-literal ctor twin blocks."""
    hit = _blocked("(function(){var h=new Headers({'x-k':'%s'});"
                   "return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f862_s1():
    """F862 s1: new TypeError(...).message blocks."""
    hit = _blocked("(function(){return new TypeError('%s').message+'%s';})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f862_s2():
    """F862 s2: new DOMException(...).message blocks."""
    hit = _blocked("(function(){return new DOMException('%s').message+'%s';})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f863_s1():
    """F863 s1: var-bound toJSON literal-return blocks."""
    hit = _blocked("(function(){var o={toJSON:function(){return '%s';}};"
                   "return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f863_s2():
    """F863 s2: var-bound toJSON this.k-return blocks."""
    hit = _blocked("(function(){var o={k:'%s',toJSON:function(){return this.k;}};"
                   "return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f864_s1():
    """F864 s1: identity reviver on a string literal blocks."""
    hit = _blocked("(function(){return JSON.parse('{\"k\":\"%s\"}',"
                   "function(k,v){return v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f864_s2():
    """F864 s2: empty-key-guard identity reviver on a round trip blocks."""
    hit = _blocked("(function(){return JSON.parse(JSON.stringify({k:'%s'}),"
                   "function(k,v){return k===''?v:v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------ p2: generalizations
@_t
def test_p2_f861_append():
    """F861: append mutation decodes node-exactly."""
    got = _decodes("(function(){var h=new Headers();h.append('x-k','%s');"
                   "return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if got == _A + _B else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f861_seq_init():
    """F861: sequence ctor init decodes node-exactly."""
    got = _decodes("(function(){var h=new Headers([['x-k','%s']]);"
                   "return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if got == _A + _B else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f861_case_insensitive():
    """F861: set('X-K') / get('x-k') decodes node-exactly."""
    got = _decodes("(function(){var h=new Headers();h.set('X-K','%s');"
                   "return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if got == _A + _B else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f861_bracket_member():
    """F861: h['set']/h['get'] bracket twins decode node-exactly."""
    got = _decodes("(function(){var h=new Headers();h['set']('x-k','%s');"
                   "return h['get']('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if got == _A + _B else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f861_ows_trim():
    """F861: OWS around the value trims node-exactly."""
    got = _decodes("(function(){var h=new Headers();h.set('x-k','  %s  ');"
                   "return h.get('x-k');})()" % (_A,))
    return ("HELD" if got == _A else "BREAK", "got=%r" % (got,))


@_t
def test_p2_f861_case_dup_keys():
    """F861: case-differing duplicate init keys are ALL kept (HARD-1).

    The engine fills Headers from the JS record key-by-key
    (case-sensitive); only byte-identical keys dedupe. Node-verified.
    """
    bad = []
    for tmpl, want in (
            ("(function(){var h=new Headers({'X-K':'a','x-k':'%s'});"
             "return h.get('x-k')+'%s';})()", "a, " + _A + _B),
            ("(function(){var h=new Headers({'X-K':'a','x-k':'b'});"
             "h.append('x-k','%s');return h.get('x-k')+'%s';})()",
             "a, b, " + _A + _B),
            ("(function(){var h=new Headers({'x-k':'a','x-k':'%s'});"
             "return h.get('x-k')+'%s';})()", _A + _B),
    ):
        got = _decodes(tmpl % (_A, _B))
        if got != want:
            bad.append((tmpl[:30], got))
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p2_f862_siblings():
    """F862: RangeError/EvalError/bracket/no-arg/no-new decode node-exactly."""
    shapes = [
        ("(function(){return new RangeError('%s').message+'%s';})()", _A + _B),
        ("(function(){return new EvalError('%s').message+'%s';})()", _A + _B),
        ("(function(){return new TypeError('%s')['message']+'%s';})()", _A + _B),
        ("(function(){return new TypeError().message+'%s';})()", _A),
        ("(function(){return TypeError('%s').message+'%s';})()", _A + _B),
    ]
    bad = []
    for tmpl, want in shapes:
        got = _decodes(tmpl % (_A, _B) if tmpl.count("%s") == 2
                       else tmpl % (_A,))
        if got != want:
            bad.append((tmpl[:30], got))
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p2_f863_arrow_inline():
    """F863: arrow toJSON and inline-object toJSON recover the credential.

    (Whole-text scan splices the decoded inner expression; the bare
    `(function(){return ...;})()` wrapper has no production, so the
    assertion is containment, node-verified.)
    """
    bad = []
    for tmpl in ("(function(){var o={toJSON:()=>'%s'};"
                 "return JSON.parse(JSON.stringify(o))+'%s';})()",
                 "(function(){return JSON.parse(JSON.stringify("
                 "{toJSON:function(){return '%s';}}))+'%s';})()"):
        got = _decodes(tmpl % (_A, _B))
        if got is None or (_A + _B) not in got:
            bad.append((tmpl[:30], got))
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p2_f864_arrow_nested():
    """F864: arrow identity reviver + nested member reads recover the credential.

    (Whole-text scan splices the decoded inner expression; the bare
    `(function(){return ...;})()` wrapper has no production, so the
    assertion is containment, node-verified.)
    """
    bad = []
    for tmpl, want in (
            ("(function(){return JSON.parse('{\"k\":\"%s\"}',(k,v)=>v).k+'%s';})()",
             _A + _B),
            ("(function(){return JSON.parse('{\"a\":{\"k\":\"%s\"}}',"
             "function(k,v){return v;}).a.k+'%s';})()", _A + _B),
            ("(function(){return JSON.parse('[\"%s\"]',function(k,v){return v;})"
             "[0]+'%s';})()", _A + _B)):
        got = _decodes(tmpl % (_A, _B))
        if got is None or want not in got:
            bad.append((tmpl[:30], got))
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ p3: fail-closed bounds
def _iife_misses(parser, payload):
    """Direct parser check: returns True when the new IIFE parser rejects."""
    state = {"ops": 0, "parts": 0}
    try:
        return parser(payload, 0, 0, state) is None
    except Exception:  # noqa: BLE001 -- loud reject counts as fail-closed
        return True


@_t
def test_p3e_f863_parts_pure_on_miss():
    """F863: the toJSON parser restores parts/ops on every miss path
    (wave-383 lesson; Standards review H-1)."""
    bad = []
    for obj in ("{a:'x',b:'y'}", "{toJSON:'x',a:'y'}", "{a:'x',",
                "{toJSON:function(){return 1;}}"):
        state = {"ops": 0, "parts": 0}
        try:
            r = dlp._js_parse_f863_tojson_value(obj, 0, 0, state)
        except Exception:  # noqa: BLE001 -- reject counts as a miss
            r = None
        if r is not None or state != {"ops": 0, "parts": 0}:
            bad.append((obj[:20], r, dict(state)))
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p3_f861_bounds():
    """F861: missing get / delete / string-init / bad name fail closed.

    (Parser-level: the F861 IIFE parser itself rejects. Seam-level:
    no credential is recovered from the whole text.)
    """
    shapes = [
        "(function(){var h=new Headers();return h.get('x-k')+'%s';})()" % (_B,),
        "(function(){var h=new Headers();h.delete('x-k');return h.get('x-k');})()",
        "(function(){var h=new Headers('x-k:f1');return h.get('x-k');})()",
        "(function(){var h=new Headers();h.set('x k','%s');return h.get('x k');})()" % (_A,),
        "(function(){var h=new Headers();h.set('x-k','a\\nb');return h.get('x-k');})()",
        "(function(){var h=new Headers();h.set('x-k','%s','z');return h.get('x-k');})()" % (_A,),
    ]
    bad = [s[:40] for s in shapes
           if not _iife_misses(dlp._js_parse_f861_headers_iife, s)
           or not _misses(s)]
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p3_f862_bounds():
    """F862: non-literal arg / .name / no-new DOMException / extra args fail closed."""
    shapes = [
        "(function(){return new TypeError(123).message+'%s';})()" % (_B,),
        "(function(){return new TypeError('%s').name+'%s';})()" % (_A, _B),
        "(function(){return DOMException('%s').message+'%s';})()" % (_A, _B),
        "(function(){return new TypeError('%s','x').message+'%s';})()" % (_A, _B),
        "(function(){return new AggregateError([],'f1').message;})()",
    ]
    bad = [s[:40] for s in shapes
           if not _iife_misses(dlp._js_parse_f862_error_message_iife, s)
           or not _misses(s)]
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p3_f863_bounds():
    """F863: undefined resolution / paramed toJSON / non-string fail closed.

    (Parser-level: the toJSON object parser itself rejects. Seam-level:
    the whole text yields no variant.)
    """
    objs = [
        "{toJSON:function(){return this.zzz;}}",
        "{toJSON:function(k){return k;}}",
        "{toJSON:function(){return 42;}}",
    ]
    bad = []
    for o in objs:
        state = {"ops": 0, "parts": 0}
        try:
            hit = dlp._js_parse_f863_tojson_value(o, 0, 0, state) is not None
        except Exception:  # noqa: BLE001 -- reject counts as fail-closed
            hit = False
        if hit:
            bad.append(o[:30])
    for payload in (
            "(function(){var o={toJSON:function(){return this.zzz;}};"
            "return JSON.parse(JSON.stringify(o))+'';})()",
            "(function(){var o={toJSON:function(k){return k;}};"
            "return JSON.parse(JSON.stringify(o))+'';})()",
            "(function(){var o={toJSON:function(){return 42;}};"
            "return JSON.parse(JSON.stringify(o))+'';})()",
    ):
        if not _fails_closed(payload):
            bad.append(payload[:40])
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p3_f864_bounds():
    """F864: named / non-identity / non-empty-guard / extra-arg revivers fail closed.

    (Parser-level: the identity-reviver parser itself rejects.
    Seam-level: the whole text yields no variant.)
    """
    exprs = [
        "JSON.parse('{\"k\":\"x\"}',function r(k,v){return v;})",
        "JSON.parse('{\"k\":\"x\"}',function(k,v){return k==='k'?v:v;})",
        "JSON.parse('{\"k\":\"x\"}',function(k,v){return v.x;})",
        "JSON.parse('{\"k\":\"x\"}',function(k,v){return v;},1)",
    ]
    bad = []
    for e in exprs:
        state = {"ops": 0, "parts": 0}
        try:
            hit = dlp._js_parse_f864_identity_reviver(e, 0, 0, state) is not None
        except Exception:  # noqa: BLE001 -- reject counts as fail-closed
            hit = False
        if hit:
            bad.append(e[:30])
    for payload in (
            "(function(){return JSON.parse('{\"k\":\"%s\"}',function r(k,v){return v;}).k+'%s';})()" % (_A, _B),
            "(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return k==='k'?v:v;}).k+'%s';})()" % (_A, _B),
            "(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return v.x;}).k+'%s';})()" % (_A, _B),
            "(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return v;},1).k;})()" % (_A,),
    ):
        if not _fails_closed(payload):
            bad.append(payload[:40])
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ p4: sibling pins
@_t
def test_p4_sibling_f648():
    """Sibling F648 (URLSearchParams no-arg) still blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams();p.append('q','%s');"
                   "p.append('q','%s%s');return p.getAll('q').join('');})()"
                   % (_A, _B, ""))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p4_sibling_f750():
    """Sibling F750 (try/catch Error message) still blocks."""
    hit = _blocked("(function(){try{throw new Error('%s');}catch(e){"
                   "return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p4_sibling_f541_f683_f744():
    """Sibling F541/F683/F744 JSON shapes still block."""
    bad = []
    for payload in (
            "JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B),
            "(function(){return JSON.parse('{\"x\":\"%s\"}',"
            "function(k,v){return k==='x'?v+'%s':v;}).x;})()" % (_A, _B),
            "(function(){return JSON.parse('{\"k\":\"x\"}',"
            "function(k,v){return k==='k'?'%s':v;}).k+'%s';})()" % (_A, _B),
            "JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')" % (_A, _B),
    ):
        if not _blocked(payload):
            bad.append(payload[:40])
    return ("HELD" if not bad else "BREAK", "bad=%s" % (bad,))


@_t
def test_p4_sibling_f571_plain_object():
    """Sibling F571/F595: plain-object stringify round trip still blocks."""
    hit = _blocked("JSON.parse(JSON.stringify({o:{c:'%s'}})).o.c+'%s'"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------ p5: honest-text controls
@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_headers_text():
    """Honest Headers prose stays quiet."""
    quiet = _misses("set the request headers and get the response code")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_json_text():
    """Honest JSON prose stays quiet."""
    quiet = _misses("JSON.parse the config and return the value")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------ p6: perf
@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for n in range(200):
        if n % 4 == 0:
            sites.append("(function(){var h=new Headers();h.set('x-%d','v%d');"
                         "return h.get('x-%d');})()" % (n, n, n))
        elif n % 4 == 1:
            sites.append("(function(){return new TypeError('e%d').message;})()" % n)
        elif n % 4 == 2:
            sites.append("(function(){var o={toJSON:function(){return 'j%d';}};"
                         "return JSON.parse(JSON.stringify(o));})()" % n)
        else:
            sites.append("(function(){return JSON.parse('{\"k\":\"r%d\"}',"
                         "function(k,v){return v;}).k;})()" % n)
    t0 = time.time()
    hits = 0
    for s in sites:
        if dlp.find_credential(s) is not None:
            hits += 1
    dt = time.time() - t0
    ok = dt < 20.0 and hits == 0
    return ("HELD" if ok else "BREAK", "200 in %.2fs hits=%d" % (dt, hits))


# ------------------------------------------------ p7: depth-1 green check
def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # This lane's four red-firsts must be 0 BREAK (F861-F864 closed).
    # The wave-386 attack battery is expected to report exactly 9
    # BREAKs: its b0 footer pin (this lane's footer is lane-local with
    # F861-F864 closed) and the eight F861-F864 open-state pins, which
    # now hit because this lane closes them -- tree-wide maintenance
    # is merge-owned (wave-306 lesson). All functional probes must HELD.
    for batt, expect_break in (
            ("evals/w387_f861_redfirst.py", 0),
            ("evals/w387_f862_redfirst.py", 0),
            ("evals/w387_f863_redfirst.py", 0),
            ("evals/w387_f864_redfirst.py", 0),
            ("evals/w386_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: lane red-firsts 0 BREAK + wave-386 attack
    battery 9 BREAKs (footer + 8 closed pins, lane-local; merge-owned)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
