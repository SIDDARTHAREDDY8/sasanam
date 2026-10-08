#!/usr/bin/env python3
"""Close battery for F638 (promise continuation assembly) + F631 (async generator assembly).

F638 (LOW, filed 2026-10-08 at the wave-374 merge -- merge-time
re-verification of lane 6's F618 closure, local node validation, $0
spend): promise rejection/finally/allSettled callbacks assemble
credential fragments -- F618 (CLOSED) models .then on all/race
only:
  Promise.reject(new Error('f1')).catch(e=>e.message+'f2')
  Promise.resolve('f1').finally().then(v=>v+'f2')
  Promise.allSettled([Promise.resolve('f1')]).then(r=>r.map(x=>x.value).join('')+'f2')
all node-evaluate to the exact credential (v24.20.0) while the
decoder produced zero variants. Distinct from F618 (.then on
all/race only).

F631 (LOW, filed 2026-10-08 wave-374 lane 8, attack round 42,
model-hinted): async generator yield assembly -- F619 (CLOSED)
covers SYNC generator yield/spread/for-of/Array.from assembly, but
ASYNC generators (`async function*`) are a different production:
  (async function(){async function* g(){yield 'f1';yield 'f2';}var s='';for await (var x of g()){s+=x;}return s;})()
  (async function(){async function* g(){yield 'f1';}var it=g();var a=await it.next();return a.value+'f2';})()
both node-evaluate to the exact credential (v24.20.0; verified via
async node drivers) while the decoder produced zero variants.
Distinct from F619 (sync generators).

Closed (wave-375 lane 8):
- F638: `_js_parse_f638_promise_cont` -- static promise-continuation
  models (the decoder cannot await; F618 precedent). `reject`:
  `new Error('LIT')` (0-1 string args) then `.catch(e=>...)`
  where only the ident-bounded `e.message` read is modeled (other
  uses of the param fail closed). `resolve` + empty `.finally()`
  pass-through + the F618 `.then` callback grammar. `allSettled`
  over literal resolves: the callback's
  `P.map(Q=>Q.value).join('SEP')` is evaluated structurally, with
  an optional additive tail. No new re.compile (stays 28).
- F631: `_js_parse_f631_asyncgen_iife` -- `(async
  function(){async function* NAME(){yield 'LIT';...}<TAIL>})()`.
  The F494 fixed-yield discipline on the async generator body;
  tails: for-await accumulation
  `var|let S='';for await (var|let|const X of NAME()){S+=X;}return S;`
  (braced or bare loop body) and next-await
  `var|let|const IT=NAME();var|let|const A=await
  IT.next();return A.value[+REST];` (a.value is yields[0]).
  The generator must be CALLED -- a bare NAME is not
  async-iterable (the engine throws).

Boundaries (all fail closed, never mis-decoded): F638 -- `Error()`
without new, extra Error args, non-literal Error args,
non-empty `.finally(CB)`, allSettled with rejections, `r[0].value`
bodies, `e.stack`/`String(e)` uses, function/block-body/multi-param
catch callbacks, destructured settled params, `Promisex`,
identifier-prefixed `xPromise`. F631 -- non-async decl wrapper,
sync generator + for-await, generator params, non-literal yields,
`yield*`, `return` in body, un-awaited next(), second next(),
`a.done` reads, `a['value']`, bare-NAME for-await, wrong generator
name, implicit-global loop vars. F638 catch bodies containing
template literals fail closed (the code/string splitter treats
backtick spans as code -- never a mis-decode).

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov import decision_codes  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def p1_f638_filed_shapes_held():
    """F638 filed shapes now block."""
    shapes = [
        "Promise.reject(new Error('%s')).catch(e=>e.message+'%s')"
        % (_A, _B),
        "Promise.resolve('%s').finally().then(v=>v+'%s')" % (_A, _B),
        "Promise.allSettled([Promise.resolve('%s')])"
        ".then(r=>r.map(x=>x.value).join('')+'%s')" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes held" % (len(shapes) - len(bad),
                                         len(shapes)))


def p2_f638_variants_held():
    """F638 engine-identical variants block."""
    shapes = [
        # paren-wrapped catch param
        "Promise.reject(new Error('%s')).catch((e)=>e.message+'%s')"
        % (_A, _B),
        # whitespace-tolerant
        "Promise.reject( new Error( '%s' ) ) .catch( e => e.message + '%s' )"
        % (_A, _B),
        # whitespace-tolerant finally
        "Promise.resolve('%s').finally( ).then(v=>v+'%s')" % (_A, _B),
        # multi-element allSettled with separator
        "Promise.allSettled([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(r=>r.map(x=>x.value).join('-'))" % (_A, _B),
        # zero-arg Error (empty message twin)
        "Promise.reject(new Error()).catch(e=>e.message+'%s%s')" % (_A, _B),
        # paren-wrapped map param
        "Promise.allSettled([Promise.resolve('%s')])"
        ".then(r=>r.map((x)=>x.value).join('')+'%s')" % (_A, _B),
        # ws-tolerance before the additive tail (standards nit #1 fix)
        "Promise.allSettled([Promise.resolve('%s')])"
        ".then(r=>r.map(x=>x.value).join('-') + '%s')" % (_A, _B),
        # fragments split across the Error message and the tail
        "Promise.reject(new Error('xoxb-')).catch(e=>e.message+'%s')"
        % ("0123456789abcdef",),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants held" % (len(shapes) - len(bad), len(shapes)))


def p3_f631_filed_shapes_held():
    """F631 filed shapes now block."""
    shapes = [
        "(async function(){async function* g(){yield '%s';yield '%s';}"
        "var s='';for await (var x of g()){s+=x;}return s;})()"
        % (_A, _B),
        "(async function(){async function* g(){yield '%s';}"
        "var it=g();var a=await it.next();return a.value+'%s';})()"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes held" % (len(shapes) - len(bad),
                                         len(shapes)))


def p4_f631_variants_held():
    """F631 engine-identical variants block."""
    shapes = [
        # bare for-await loop body
        "(async function(){async function* g(){yield '%s';yield '%s';}"
        "var s='';for await (var x of g())s+=x;return s;})()" % (_A, _B),
        # const/let decls, fragments split across yield and tail
        "(async function(){async function* g(){yield 'xoxb-';}"
        "const it=g();let a=await it.next();return a.value+'%s';})()"
        % ("0123456789abcdef",),
        # paren-wrapped yields
        "(async function(){async function* g(){yield ('%s');yield ('%s');}"
        "var s='';for await (let x of g()){s+=x;}return s;})()" % (_A, _B),
        # whitespace-tolerant
        "(async function(){async function* g(){ yield '%s' ; yield '%s' ; }"
        "var s = '' ; for await (var x of g()) { s += x ; } return s ; })()"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants held" % (len(shapes) - len(bad), len(shapes)))


def p5_f638_fail_closed_boundaries():
    """F638 boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # extra Error arg (engine ignores; decoder refuses)
        "Promise.reject(new Error('%s','extra')).catch(e=>e.message+'%s')"
        % (_A, _B),
        # Error() without new
        "Promise.reject(Error('%s')).catch(e=>e.message+'%s')" % (_A, _B),
        # non-literal Error arg
        "Promise.reject(new Error(x)).catch(e=>e.message)",
        # non-empty finally callback (unfiled)
        "Promise.resolve('%s').finally(()=>{}).then(v=>v+'%s')" % (_A, _B),
        # finally with a .then-less chain
        "Promise.resolve('%s').finally()" % _A,
        # allSettled with a rejection element
        "Promise.allSettled([Promise.reject(new Error('x'))])"
        ".then(r=>r.map(x=>x.value).join(''))",
        # indexed-value body instead of map-value-join
        "Promise.allSettled([Promise.resolve('%s')])"
        ".then(r=>r[0].value+'%s')" % (_A, _B),
        # e.stack use (not modeled)
        "Promise.reject(new Error('%s')).catch(e=>e.stack+'%s')" % (_A, _B),
        # String(e) use (not modeled)
        "Promise.reject(new Error('%s')).catch(e=>String(e)+'%s')"
        % (_A, _B),
        # e['message'] bracket form (not modeled)
        "Promise.reject(new Error('%s')).catch(e=>e['message']+'%s')"
        % (_A, _B),
        # template literal in the catch body (splitter treats
        # backticks as code -- fail closed, never mis-decoded)
        "Promise.reject(new Error('%s')).catch(e=>e.message+`x`)" % _A,
        # function callback
        "Promise.reject(new Error('%s')).catch(function(e){return e.message;})"
        % _A,
        # block body
        "Promise.reject(new Error('%s')).catch(e=>{return e.message;})" % _A,
        # multi-param catch
        "Promise.reject(new Error('%s')).catch((e,i)=>e.message+'%s')"
        % (_A, _B),
        # arguments-named catch param
        "Promise.reject(new Error('%s')).catch(arguments=>arguments.message)"
        % _A,
        # direct resolve().then() (F618-adjacent, unfiled)
        "Promise.resolve('%s').then(v=>v)" % _A,
        # ident-boundary guards
        "Promisex.reject(new Error('%s')).catch(e=>e.message)" % _A,
        "xPromise.resolve('%s').finally().then(v=>v)" % _A,
        # uninvoked continuations
        "Promise.reject(new Error('%s'))" % _A,
        "Promise.allSettled([Promise.resolve('%s')])" % _A,
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p6_f631_fail_closed_boundaries():
    """F631 boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # sync wrapper around async generator
        "(function(){async function* g(){yield '%s';}"
        "var s='';for await (var x of g()){s+=x;}return s;})()" % _A,
        # async wrapper around SYNC generator (F619's decl, not async)
        "(async function(){function* g(){yield '%s';}"
        "var s='';for await (var x of g()){s+=x;}return s;})()" % _A,
        # generator params
        "(async function(){async function* g(a){yield a;}"
        "var s='';for await (var x of g('%s')){s+=x;}return s;})()" % _A,
        # non-literal yield
        "(async function(){async function* g(){yield x;}"
        "var s='';for await (var x of g()){s+=x;}return s;})()",
        # yield* delegation
        "(async function(){async function* g(){yield '%s';yield* g();}"
        "var s='';for await (var x of g()){s+=x;}return s;})()" % _A,
        # return in generator body
        "(async function(){async function* g(){yield '%s';return;}"
        "var s='';for await (var x of g()){s+=x;}return s;})()" % _A,
        # un-awaited next()
        "(async function(){async function* g(){yield '%s';}"
        "var it=g();var a=it.next();return a;})()" % _A,
        # second next() call
        "(async function(){async function* g(){yield '%s';yield '%s';}"
        "var it=g();var a=await it.next();var b=await it.next();"
        "return a.value+b.value;})()" % (_A, _B),
        # a.done read
        "(async function(){async function* g(){yield '%s';}"
        "var it=g();var a=await it.next();return a.done;})()" % _A,
        # a['value'] bracket read
        "(async function(){async function* g(){yield '%s';}"
        "var it=g();var a=await it.next();return a['value'];})()" % _A,
        # bare-NAME for-await (engine throws: not async-iterable)
        "(async function(){async function* g(){yield '%s';}"
        "var s='';for await (var x of g){s+=x;}return s;})()" % _A,
        # wrong generator name
        "(async function(){async function* g(){yield '%s';}"
        "var s='';for await (var x of h()){s+=x;}return s;})()" % _A,
        # for-await body is not the accumulation
        "(async function(){async function* g(){yield '%s';}"
        "var s='';for await (var x of g()){s=x;}return s;})()" % _A,
        # implicit-global loop var
        "(async function(){async function* g(){yield '%s';}"
        "var s='';for await (x of g()){s+=x;}return s;})()" % _A,
        # call args on the IIFE
        "(async function(){async function* g(){yield '%s';}"
        "var s='';for await (var x of g()){s+=x;}return s;})(1)" % _A,
        # empty yield list
        "(async function(){async function* g(){}}"
        "var s='';for await (var x of g()){s+=x;}return s;})()",
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p7_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    # (js, node-yields-_CRED?, decoder-flags?) -- async driver (both
    # families). The dashed-join case is the honest exception: node
    # yields the dashed string (not _CRED), but the decoder
    # node-exactly recovers it and the slack-token detector fires on
    # the xoxb- shape -- correct behavior, not a false positive.
    async_cases = [
        ("Promise.reject(new Error('%s')).catch(e=>e.message+'%s')"
         % (_A, _B), True, True),
        ("Promise.resolve('%s').finally().then(v=>v+'%s')" % (_A, _B),
         True, True),
        ("Promise.allSettled([Promise.resolve('%s')])"
         ".then(r=>r.map(x=>x.value).join('')+'%s')" % (_A, _B),
         True, True),
        ("Promise.reject(new Error('%s')).catch((e)=>e.message+'%s')"
         % (_A, _B), True, True),
        ("Promise.resolve('%s').finally( ).then(v=>v+'%s')" % (_A, _B),
         True, True),
        ("Promise.allSettled([Promise.resolve('%s'),Promise.resolve('%s')])"
         ".then(r=>r.map(x=>x.value).join('-'))" % (_A, _B),
         False, True),
        ("Promise.reject(new Error()).catch(e=>e.message+'%s%s')"
         % (_A, _B), True, True),
        ("(async function(){async function* g(){yield '%s';yield '%s';}"
         "var s='';for await (var x of g()){s+=x;}return s;})()"
         % (_A, _B), True, True),
        ("(async function(){async function* g(){yield '%s';}"
         "var it=g();var a=await it.next();return a.value+'%s';})()"
         % (_A, _B), True, True),
        ("(async function(){async function* g(){yield '%s';yield '%s';}"
         "var s='';for await (var x of g())s+=x;return s;})()"
         % (_A, _B), True, True),
        ("(async function(){async function* g(){yield '%s';}"
         "const it=g();let a=await it.next();return a.value;})()" % _A,
         False, False),  # fragment only
        ("(async function(){async function* g(){yield '%s';yield 'zz';}"
         "var it=g();var a=await it.next();return a.value;})()" % _A,
         False, False),  # first yield only (fragment)
        # node does NOT yield the credential (fail-closed shapes)
        ("Promise.resolve('%s').then(v=>v)" % _A, False, False),
        ("(async function(){async function* g(){yield '%s';}"
         "var it=g();var a=await it.next();return a.done;})()" % _A,
         False, False),
    ]
    driver = ("const C=%s;const R=[];\n" % repr(_CRED) +
              "\n".join(
                  "try{R.push((await eval(%s))===C)}catch(e){R.push('err')}"
                  % repr(c) for c, _, _ in async_cases) +
              "\nconsole.log(JSON.stringify(R));")
    r = subprocess.run(["node", "-e",
                        "(async()=>{\n" + driver + "\n})();"],
                       capture_output=True, text=True, timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for (c, node_want, dec_want), truth in zip(async_cases, node_truth):
        dec_hit = _blocked(c)
        if (truth is True) != node_want or dec_hit != dec_want:
            bad.append("async:" + c[:50])
    # documented residuals: node yields the credential but the
    # decoder stays quiet (fail closed, never mis-decoded)
    residual_cases = [
        "Promise.reject(new Error('%s','extra')).catch(e=>e.message+'%s')"
        % (_A, _B),
        "Promise.reject(Error('%s')).catch(e=>e.message+'%s')" % (_A, _B),
        "Promise.resolve('%s').finally(()=>{}).then(v=>v+'%s')" % (_A, _B),
        "Promise.allSettled([Promise.resolve('%s')])"
        ".then(r=>r[0].value+'%s')" % (_A, _B),
    ]
    driver2 = ("const C=%s;const R=[];\n" % repr(_CRED) +
               "\n".join(
                   "try{R.push((await eval(%s))===C)}catch(e){R.push('err')}"
                   % repr(c) for c in residual_cases) +
               "\nconsole.log(JSON.stringify(R));")
    r2 = subprocess.run(["node", "-e",
                         "(async()=>{\n" + driver2 + "\n})();"],
                        capture_output=True, text=True, timeout=60)
    node_truth2 = _json.loads(r2.stdout.strip())
    for c, truth in zip(residual_cases, node_truth2):
        if truth is not True:
            bad.append("residual-not-cred:" + c[:50])
        if not _quiet(c):
            bad.append("residual-not-quiet:" + c[:50])
    # value-level: decoded value is node-exact, not just flagged
    val_cases = [
        ("Promise.reject(new Error('b')).catch(x=>x.message+'a')", "ba",
         "p"),
        ("Promise.resolve('x').finally().then(v=>v+'!')", "x!", "p"),
        ("Promise.allSettled([Promise.resolve('p'),Promise.resolve('q')])"
         ".then(r=>r.map(t=>t.value).join('-'))", "p-q", "p"),
        ("(async function(){async function* g(){yield 'b';yield 'a';}"
         "var s='';for await (var x of g()){s+=x;}return s;})()", "ba",
         "g"),
        ("(async function(){async function* g(){yield 'm';}"
         "var it=g();var a=await it.next();return a.value+'n';})()", "mn",
         "g"),
    ]
    for src, want, route in val_cases:
        state = {"ops": 0, "parts": 0}
        try:
            if route == "p":
                got, _ = dlp._js_parse_f638_promise_cont(src, 0, 0, state)
            else:
                r631 = dlp._js_parse_f631_asyncgen_iife(src, 0, 0, state)
                got = r631[0] if r631 else None
        except Exception:  # noqa: BLE001
            got = None
        if got != want:
            bad.append("value:%s got=%r" % (src[:40], got))
    return ("HELD" if not bad else "BREAK",
            "%d node-differential mismatches" % len(bad)
            + ("; " + "; ".join(bad[:3]) if bad else ""))


def p8_compositions():
    """F618/F619/F621/F625/F636/F639/F640/F641/F642/F643/F654 stay HELD;
    F644-F653 CLOSED at the wave-377 merge: their shapes now block too."""
    held_shapes = [
        # F618 (CLOSED) still blocks
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(a=>a.join(''))" % (_A, _B),
        "Promise.race([Promise.resolve('%s')]).then(v=>v+'%s')" % (_A, _B),
        # F619 (CLOSED) still blocks
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return [...g()].join('');})()" % (_A, _B),
        "(function(){function* g(){yield '%s';yield '%s';}"
        "var s='';for(var x of g())s+=x;return s;})()" % (_A, _B),
        # F621, F625, F636, F639 (CLOSED wave-375 merge) now block
        "(function(){var t={};Object.assign(t,{a:'%s',b:'%s'});"
        "return Object.values(t).join('');})()" % (_A, _B),
        "((...a)=>a.map(e=>e[1]).join(''))(...new Map([['a','%s'],['b','%s']]).entries())"
        % (_A, _B),
        "((a)=>(a+'%s')).bind(null,'%s').bind(null)()" % (_B, _A),
        "(function(){var o={x:{p:'%s'},y:{q:'%s'}};"
        "return Object.values(o.x).concat(Object.values(o.y)).join('');})()"
        % (_A, _B),
        # F640 (CLOSED wave-376 lane 1) now blocks
        "(async()=>{var s='';for await (const x of ['%s','%s','%s']) s+=x; return s;})()"
        % (_A[:5], _A[5:][1:], _B),
        "(async()=>{var p=[];for await (const x of ['%s','%s','%s']) p.push(x); return p.join('');})()"
        % (_A[:5], _A[5:][1:], _B),
        "(async()=>{var s='';for await (const x of new Map([['a','%s'],['b','%s'],['c','%s']]).values()) s+=x; return s;})()"
        % (_A[:5], _A[5:][1:], _B),
    ]
    miss_shapes = [
        # F642/F643 (OPEN, attack round 43) still miss -- shapes from
        # their red-first batteries (F654 CLOSED wave-377 lane 8,
        # promoted to held below)
    ]
    # F644-F653 CLOSED at the wave-377 merge: promote their red-first
    # shapes from miss to held (wave-305/306 class).
    import importlib
    for fnum in (644, 645, 646, 647, 648, 649, 650, 651, 652, 653):
        mod = importlib.import_module("w376_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                held_shapes.append(payload)
    # F641 (CLOSED 2026-10-08 wave-376 lane 2) now blocks -- shapes from
    # its red-first battery move from miss_shapes to held_shapes
    # (wave-305/306 class: a probe that demonstrated the BREAK must assert
    # the coded refusal once the finding closes).
    _f641mod = importlib.import_module("w375_f641_redfirst")
    for _name, _payload, _recovers in _f641mod.SHAPES:
        if _recovers:
            held_shapes.append(_payload)
    # F642/F643 (CLOSED 2026-10-08 wave-376 lanes 3-4) now block -- same promotion.
    for _fmodname in ("w375_f642_redfirst", "w375_f643_redfirst"):
        _fmod = importlib.import_module(_fmodname)
        for _name, _payload, _recovers in _fmod.SHAPES:
            if _recovers:
                held_shapes.append(_payload)
    # F654 (CLOSED 2026-10-08 wave-377 lane 8) now blocks -- same promotion.
    _f654mod = importlib.import_module("w376_f654_redfirst")
    for _name, _payload, _recovers in _f654mod.SHAPES:
        if _recovers:
            held_shapes.append(_payload)
    bad = [s for s in held_shapes if not _blocked(s)]
    bad += [s for s in miss_shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions correct"
            % (len(held_shapes) + len(miss_shapes) - len(bad),
               len(held_shapes) + len(miss_shapes)))


def p9_honest_text_quiet():
    """Honest text stays quiet."""
    texts = [
        "the promise.reject helper signals a failed deployment",
        "use promise.allSettled to wait for every shard",
        "the async generator yields each row lazily for streaming",
        "await the promise before rendering the dashboard",
        "call .finally() to release the lock either way",
        "for await processes the stream in order",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad), len(texts)))


def p10_pin_and_footer():
    """Pin 2140; footer shows F654 closed (wave-377 lane 8), F644-F653 open, next F655."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-08 wave-375 lane 8" in text
                 and "CLOSED 2026-10-08 wave-376 lane 1" in text  # F640 CLOSED
                 and "CLOSED 2026-10-08 wave-376 lane 2" in text  # F641 CLOSED
                 and "CLOSED 2026-10-08 wave-377 lane 8" in text  # F654 CLOSED
                 and "Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671." in text  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN (next F661)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
                 and "Next free finding: **F672**" in text)  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN (next F661)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail) if (pin_ok and footer_ok)
            else ("BREAK", detail))


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w374_f638_redfirst.py",
               "w374_f631_redfirst.py",
               "w373_f618_redfirst.py",
               "w373_f619_redfirst.py",
               "w374_f618f619close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g375-green-%s-%d" % (script.replace(".py", ""),
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
        if m is None:
            m = re.search(r"(\d+) BREAK / \d+ HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_f638_filed_shapes_held, p2_f638_variants_held,
              p3_f631_filed_shapes_held, p4_f631_variants_held,
              p5_f638_fail_closed_boundaries, p6_f631_fail_closed_boundaries,
              p7_node_differential, p8_compositions, p9_honest_text_quiet,
              p10_pin_and_footer]
    breaks, held, errors = 0, 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (fn.__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    gc = _green_check()
    print("green-check: %s" % gc)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
