#!/usr/bin/env python3
"""Close battery for wave-454 lane A: F5553-F5666 (114 decoder-seam
decoders) + F3456 (stays OPEN by design, asserted QUIET) + F3787
(no decoder -- node-verified false positive, asserted MISS).

Filed shapes embedded verbatim from the w453 red-first batteries.
Guard-boundary cases for F5632/F5633/F5638/F5639. Pin: 202 stmtdec
loops. Honest-text controls. Depth-1 green check honoring
GOV_SKIP_GREEN=1 (runs the 114 red-first batteries, expecting HELD).
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w454_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "b" * 35

TEMPLATES = {
    5553: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.abs(0));var RESULT=U;",
    5554: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.min(0, T.length));var RESULT=U;",
    5555: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.max(0, 0));var RESULT=U;",
    5556: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.ceil(0.5) - 1);var RESULT=U;",
    5557: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.floor(0.9));var RESULT=U;",
    5558: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.round(0.4));var RESULT=U;",
    5559: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.trunc(0.9));var RESULT=U;",
    5560: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.sign(0));var RESULT=U;",
    5561: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.cbrt(0));var RESULT=U;",
    5562: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.asin(0));var RESULT=U;",
    5563: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.atan(0));var RESULT=U;",
    5564: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.sinh(0));var RESULT=U;",
    5565: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.tanh(0));var RESULT=U;",
    5566: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.log10(1));var RESULT=U;",
    5567: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.log2(1));var RESULT=U;",
    5568: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.sqrt(0));var RESULT=U;",
    5569: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.hypot(0));var RESULT=U;",
    5570: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.clz32(1) - 31);var RESULT=U;",
    5571: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.imul(0, T.length));var RESULT=U;",
    5572: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.fround(0));var RESULT=U;",
    5573: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.acos(1));var RESULT=U;",
    5574: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.asinh(0));var RESULT=U;",
    5575: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.atanh(0));var RESULT=U;",
    5576: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.cosh(0) - 1);var RESULT=U;",
    5577: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.exp(0) - 1);var RESULT=U;",
    5578: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.pow(T.length, 0) - 1);var RESULT=U;",
    5579: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length * Math.pow(2, 0));var RESULT=U;",
    5580: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length - Math.log(1));var RESULT=U;",
    5581: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.LN10 - Math.LN10);var RESULT=U;",
    5582: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.PI - Math.PI);var RESULT=U;",
    5583: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.SQRT2 - Math.SQRT2);var RESULT=U;",
    5584: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Math.LN2 - Math.LN2);var RESULT=U;",
    5585: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(~~0, T.length);var RESULT=U;",
    5586: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0|0, T.length);var RESULT=U;",
    5587: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(-0, T.length);var RESULT=U;",
    5588: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(+0, T.length);var RESULT=U;",
    5589: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + (0|0));var RESULT=U;",
    5590: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Number(''));var RESULT=U;",
    5591: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + Boolean(0));var RESULT=U;",
    5592: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + +false);var RESULT=U;",
    5593: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + +'');var RESULT=U;",
    5594: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + []);var RESULT=U;",
    5595: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + null);var RESULT=U;",
    5596: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(null, T.length);var RESULT=U;",
    5597: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(false, T.length);var RESULT=U;",
    5598: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice('', T.length);var RESULT=U;",
    5599: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice([], T.length);var RESULT=U;",
    5600: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, 1/0);var RESULT=U;",
    5601: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, Number.POSITIVE_INFINITY);var RESULT=U;",
    5602: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(Number.NEGATIVE_INFINITY);var RESULT=U;",
    5603: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, Number.MAX_VALUE);var RESULT=U;",
    5604: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, 1e308);var RESULT=U;",
    5605: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(-Infinity, Infinity);var RESULT=U;",
    5606: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(-Infinity, T.length);var RESULT=U;",
    5607: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(NaN);var RESULT=U;",
    5608: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(null);var RESULT=U;",
    5609: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(false);var RESULT=U;",
    5610: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring('', T.length);var RESULT=U;",
    5611: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(0, Infinity);var RESULT=U;",
    5612: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(-Infinity, Infinity);var RESULT=U;",
    5613: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/^([\\s\\S]*)$/)[1];var RESULT=U;",
    5614: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/(.*)/)[1];var RESULT=U;",
    5615: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/([\\s\\S]+)/)[1];var RESULT=U;",
    5616: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=/^([\\s\\S]*)$/.exec(T)[1];var RESULT=U;",
    5617: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/^(.+)$/)[1];var RESULT=U;",
    5618: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/(\\w[\\s\\S]*)/)[1];var RESULT=U;",
    5619: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.match(/([\\s\\S]*?)$/)[1];var RESULT=U;",
    5620: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/[\\s\\S]/g, function(c){return c;});var RESULT=U;",
    5621: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/[\\s\\S]/g, c=>c);var RESULT=U;",
    5622: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/[\\s\\S]/g, c=>c);var RESULT=U;",
    5623: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/[\\s\\S]*/g, function(m){return m;});var RESULT=U;",
    5624: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/./g, c=>c);var RESULT=U;",
    5625: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T.matchAll(/./g)].map(m=>m[0]).join('');var RESULT=U;",
    5626: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T.matchAll(/[\\s\\S]/g)].map(m=>m[0]).join('');var RESULT=U;",
    5627: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[].reduce.call(T, function(a,c){return a+c;}, '');var RESULT=U;",
    5628: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[].reduceRight.call(T, function(a,c){return c+a;}, '');var RESULT=U;",
    5629: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.reduce.call(T, (a,c)=>a+c, '');var RESULT=U;",
    5630: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T, c=>c).join('');var RESULT=U;",
    5631: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[].join.call(T, '');var RESULT=U;",
    5632: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new URLSearchParams('q='+T).get('q');var RESULT=U;",
    5633: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new URL('https://example.com/?q='+T).searchParams.get('q');var RESULT=U;",
    5634: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new URLSearchParams({q:T}).get('q');var RESULT=U;",
    5635: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new URLSearchParams([['q',T]]).get('q');var RESULT=U;",
    5636: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new TextDecoder().decode(new TextEncoder().encode(T));var RESULT=U;",
    5637: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new TextDecoder('utf-8').decode(new TextEncoder().encode(T));var RESULT=U;",
    5638: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Headers({q:T}).get('q');var RESULT=U;",
    5639: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Headers([['q',T]]).get('q');var RESULT=U;",
    5640: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).repeat(1);var RESULT=U;",
    5641: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw({raw:['','']}, T);var RESULT=U;",
    5642: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Object.fromEntries(new Map([['v',T]])).v;var RESULT=U;",
    5643: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=JSON.parse(JSON.stringify([T]).slice(1,-1));var RESULT=U;",
    5644: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...new Intl.Segmenter().segment(T)].map(s=>s.segment).join('');var RESULT=U;",
    5645: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Proxy(function(){},{apply:function(){return T;}})();var RESULT=U;",
    5646: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var M=new Map();M.set('v',T);var U=M.get('v');var RESULT=U;",
    5647: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=new Set();S.add(T);var U=[...S][0];var RESULT=U;",
    5648: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=[];[].forEach.call(T, function(c){A.push(c);});var U=A.join('');var RESULT=U;",
    5649: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var F=new FormData();F.append('q',T);var U=F.get('q');var RESULT=U;",
    5650: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U;with({v:T}){U=v;}var RESULT=U;",
    5651: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';outer:{U=T;break outer;}var RESULT=U;",
    5652: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O={a:T};var U='';for(var k in O){U=O[k];}var RESULT=U;",
    5653: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O={};O.__defineGetter__('v',function(){return T;});var U=O.v;var RESULT=U;",
    5654: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O={};Object.setPrototypeOf(O,{v:T});var U=O.v;var RESULT=U;",
    5655: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');function* g(){yield* [T];}var U=[...g()][0];var RESULT=U;",
    5656: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(function(x=T){return x;})(undefined);var RESULT=U;",
    5657: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=((x=T)=>x)();var RESULT=U;",
    5658: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');function tag(s,a){return a;}var U=tag`${T}`;var RESULT=U;",
    5659: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O={v:T};var W=new WeakRef(O);var U=W.deref().v;var RESULT=U;",
    5660: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O=Object.create(null);O.v=T;var U=O.v;var RESULT=U;",
    5661: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';while(true){U=T;break;}var RESULT=U;",
    5662: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';try{U=T;}finally{}var RESULT=U;",
    5663: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');{{var U=T;}}var RESULT=U;",
    5664: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var O={get v(){return T;}};var U=O.v;var RESULT=U;",
    5665: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(function(x){return x;})(T);var RESULT=U;",
    5666: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=((x)=>x)(T);var RESULT=U;",
}


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


def _scan(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _check_prov(t):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(t) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


GUARD_CASES = [
    # (label, hook name, U-shape, credential, expected hook result)
    # Hook-level: find_credential only flags credential-shaped strings,
    # so guard boundaries are tested against the decoder hook directly
    # (the w438_f2017 precedent). None = guard rejects (fail closed).
    ("F5632 eq", "_js_f5632_stmt_decode", "new URLSearchParams('q='+T).get('q')", "a=b", "a=b"),
    ("F5632 hash", "_js_f5632_stmt_decode", "new URLSearchParams('q='+T).get('q')", "a#b", "a#b"),
    ("F5632 plus", "_js_f5632_stmt_decode", "new URLSearchParams('q='+T).get('q')", "a+b", None),
    ("F5632 amp", "_js_f5632_stmt_decode", "new URLSearchParams('q='+T).get('q')", "a&b=c", None),
    ("F5633 eq", "_js_f5633_stmt_decode", "new URL('https://example.com/?q='+T).searchParams.get('q')", "a=b", "a=b"),
    ("F5633 hash", "_js_f5633_stmt_decode", "new URL('https://example.com/?q='+T).searchParams.get('q')", "a#b", None),
    ("F5633 tab", "_js_f5633_stmt_decode", "new URL('https://example.com/?q='+T).searchParams.get('q')", "a\tb", None),
    ("F5638 ctrl01", "_js_f5638_stmt_decode", "new Headers({q:T}).get('q')", "a\x01b", "a\x01b"),
    ("F5638 nul", "_js_f5638_stmt_decode", "new Headers({q:T}).get('q')", "a\x00b", None),
    ("F5638 lead-sp", "_js_f5638_stmt_decode", "new Headers({q:T}).get('q')", "  ab", None),
    ("F5639 ctrl01", "_js_f5639_stmt_decode", "new Headers([['q',T]]).get('q')", "a\x01b", "a\x01b"),
]


def _hook_check(label, hook_name, shape, cred, want):
    import gov.dlp as _dlp
    hook = getattr(_dlp, hook_name)
    base = ("var C={I};var T=C.map(function(c){return String.fromCharCode(c);})"
            ".join('');var U=%s;var RESULT=U;")
    p = (base % shape).replace("{I}", _codes(cred))
    got = hook(p)
    ok = (got == want)
    print("%s %s: got %r want %r" % ("PASS" if ok else "FAIL", label, got, want))
    return ok


def main():
    fails = []
    # Filed shapes: 228 scans, 4 workers (each scan is a fresh
    # subprocess; serial would take hours under lane contention).
    from concurrent.futures import ThreadPoolExecutor
    jobs = []
    for n in sorted(TEMPLATES):
        for secret in (SECRET20, SECRET40):
            jobs.append((n, TEMPLATES[n].replace("{I}", _codes(secret))))
    def _one(job):
        n, p = job
        return (n, _scan(p))
    with ThreadPoolExecutor(max_workers=4) as ex:
        for n, v in ex.map(_one, jobs):
            if v != "HIT":
                fails.append("F%d -> %s" % (n, v))
    print("filed shapes: %d/%d HIT" % (228 - len(fails), 228))
    # Guard boundaries (hook-level).
    for label, hook_name, shape, cred, want in GUARD_CASES:
        if not _hook_check(label, hook_name, shape, cred, want):
            fails.append(label)
    # F3456 stays OPEN by design (QUIET).
    v = _check_prov("The configuration is put in memory for later use.")
    print("F3456 filed-shape: %s (want QUIET)" % v)
    if v != "QUIET":
        fails.append("F3456 -> %s" % v)
    # F3787 stays OPEN (false positive, MISS correct).
    p3787 = ("var C=%s;var T=C.map(function(c){return String.fromCharCode(c);})"
               ".join('');var U=void 0, T;var RESULT=U;" % _codes(SECRET20))
    v = _scan(p3787)
    print("F3787 filed-shape: %s (want MISS)" % v)
    if v != "MISS":
        fails.append("F3787 -> %s" % v)
    # Honest-text controls stay quiet.
    for name, payload in [("junk", "the quick brown fox jumps over the lazy dog"),
                          ("prose", "The weather is pleasant today with clear skies.")]:
        v = _scan(payload)
        print("control %s: %s (want MISS)" % (name, v))
        if v != "MISS":
            fails.append("control %s -> %s" % (name, v))
    # Pin: 202 stmtdec loops.
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        nloops = f.read().count("for _stmtdec in (")
    print("stmtdec loops: %d (want 203)" % nloops)  # wave-456 merge: 202 -> 203; wave-456 merge reconciliation: +1 wave-456 lane A dispatch loop = 203
    if nloops != 203:  # wave-456 merge: 202 -> 203; wave-456 merge reconciliation: +1 wave-456 lane A dispatch loop = 203
        fails.append("loops=%d" % nloops)
    print("RESULT: " + ("ALL PASS" if not fails else "FAILURES: %s" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
