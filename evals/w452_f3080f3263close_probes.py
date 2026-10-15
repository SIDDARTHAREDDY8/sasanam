#!/usr/bin/env python3
"""Close battery for wave-452 lane A: F3080-F3263 except F3093 (183 decoder-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1
(runs the 183 red-first batteries, expecting HELD on the closed tree).
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w452_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "b" * 35
SECRET_UPPER = "xoxb-" + "A" * 15


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


# F-number -> filed full payload (exact attack-round-119 shapes,
# {I} = the integer-code array for the secret). F3093 is NOT here:
# it was already CLOSED incidental in wave-451 (sibling pin below).
TEMPLATES = {
    3080: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(undefined, undefined);var RESULT=U;",
    3081: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(undefined, undefined);var RESULT=U;",
    3082: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + 0);var RESULT=U;",
    3083: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length - 0);var RESULT=U;",
    3084: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length * 1);var RESULT=U;",
    3085: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length * 1.0);var RESULT=U;",
    3086: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length / 1);var RESULT=U;",
    3087: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, -T.length + 2*T.length);var RESULT=U;",
    3088: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(Math.ceil(0), T.length);var RESULT=U;",
    3089: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(Math.round(0), T.length);var RESULT=U;",
    3090: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(Math.trunc(0.9), T.length);var RESULT=U;",
    3091: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, Math.abs(T.length));var RESULT=U;",
    3092: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, Math.pow(T.length, 1));var RESULT=U;",
    3094: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, -(-T.length));var RESULT=U;",
    3095: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, Number(T.length));var RESULT=U;",
    3096: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, parseInt(T.length));var RESULT=U;",
    3097: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, parseFloat(T.length));var RESULT=U;",
    3098: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length | 0);var RESULT=U;",
    3099: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length & -1);var RESULT=U;",
    3100: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length ^ 0);var RESULT=U;",
    3101: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length << 0);var RESULT=U;",
    3102: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length >> 0);var RESULT=U;",
    3103: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length >>> 0);var RESULT=U;",
    3104: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, ~~T.length);var RESULT=U;",
    3105: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, [T.length][0]);var RESULT=U;",
    3106: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + -0);var RESULT=U;",
    3107: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, -0 + T.length);var RESULT=U;",
    3108: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length - -0);var RESULT=U;",
    3109: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length | -0);var RESULT=U;",
    3110: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, 0.5 + T.length);var RESULT=U;",
    3111: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + 0.5);var RESULT=U;",
    3112: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + 0.9);var RESULT=U;",
    3113: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length + 0.1);var RESULT=U;",
    3114: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(-Infinity);var RESULT=U;",
    3115: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(-5);var RESULT=U;",
    3116: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(-Infinity);var RESULT=U;",
    3117: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(-T.length);var RESULT=U;",
    3118: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(-Infinity);var RESULT=U;",
    3119: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(undefined, undefined);var RESULT=U;",
    3120: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(undefined);var RESULT=U;",
    3121: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(null);var RESULT=U;",
    3122: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(false);var RESULT=U;",
    3123: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice('');var RESULT=U;",
    3124: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(NaN);var RESULT=U;",
    3125: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0.0);var RESULT=U;",
    3126: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0e0);var RESULT=U;",
    3127: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(-0.0);var RESULT=U;",
    3128: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0, undefined);var RESULT=U;",
    3129: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toUpperCase().toLowerCase().toUpperCase().toLowerCase();var RESULT=U;",
    3130: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trim().trim();var RESULT=U;",
    3131: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart().trimEnd();var RESULT=U;",
    3132: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(0).padEnd(0);var RESULT=U;",
    3133: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(T.length).padEnd(T.length);var RESULT=U;",
    3134: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(0, 'x');var RESULT=U;",
    3135: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(0, 'x');var RESULT=U;",
    3136: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).slice(0);var RESULT=U;",
    3137: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).substring(0);var RESULT=U;",
    3138: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(0).slice(0);var RESULT=U;",
    3139: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0).slice(0);var RESULT=U;",
    3140: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).substr(0);var RESULT=U;",
    3141: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('').concat('');var RESULT=U;",
    3142: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('').slice(0);var RESULT=U;",
    3143: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).concat('');var RESULT=U;",
    3144: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(0, T.length + 0);var RESULT=U;",
    3145: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0, T.length + 0);var RESULT=U;",
    3146: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0, Infinity);var RESULT=U;",
    3147: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T + '';var RESULT=U;",
    3148: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='' + T;var RESULT=U;",
    3149: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T + T.slice(0,0);var RESULT=U;",
    3150: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}${''}`;var RESULT=U;",
    3151: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw({raw: [T, '']}, '');var RESULT=U;",
    3152: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(T, T);var RESULT=U;",
    3153: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(T.slice(0,0), '');var RESULT=U;",
    3154: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/x^/, '');var RESULT=U;",
    3155: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/a^/g, '');var RESULT=U;",
    3156: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/(?!)/g, '');var RESULT=U;",
    3157: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/(?:)/g, '');var RESULT=U;",
    3158: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/()/g, '');var RESULT=U;",
    3159: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/\\b/g, '');var RESULT=U;",
    3160: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/^/g, '');var RESULT=U;",
    3161: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/$/g, '');var RESULT=U;",
    3162: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/x^/g, '');var RESULT=U;",
    3163: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/(?!)/g, '');var RESULT=U;",
    3164: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/(?:)/g, '');var RESULT=U;",
    3165: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/()/g, '');var RESULT=U;",
    3166: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(/\\b/g, '');var RESULT=U;",
    3167: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').join('') + '';var RESULT=U;",
    3168: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='' + T.split('').join('');var RESULT=U;",
    3169: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').join('') + T.slice(0,0);var RESULT=U;",
    3170: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Buffer.from(T).toString();var RESULT=U;",
    3171: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Buffer.from(T, 'utf8').toString('utf8');var RESULT=U;",
    3172: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Buffer.from(T).toString('utf-8');var RESULT=U;",
    3173: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.normalize('NFC').normalize('NFD').normalize('NFC');var RESULT=U;",
    3174: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0, T.length).join('');var RESULT=U;",
    3175: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').filter(function(c){return true;}).join('');var RESULT=U;",
    3176: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(-Infinity).join('');var RESULT=U;",
    3177: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(-T.length).join('');var RESULT=U;",
    3178: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(undefined).join('');var RESULT=U;",
    3179: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(null).join('');var RESULT=U;",
    3180: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(false).join('');var RESULT=U;",
    3181: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(NaN).join('');var RESULT=U;",
    3182: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0.0).join('');var RESULT=U;",
    3183: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(-0.0).join('');var RESULT=U;",
    3184: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0, undefined).join('');var RESULT=U;",
    3185: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0, Infinity).join('');var RESULT=U;",
    3186: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0, T.length + 0).join('');var RESULT=U;",
    3187: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').toSpliced(0, 0).join('');var RESULT=U;",
    3188: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').join('').split('').join('').split('').join('');var RESULT=U;",
    3189: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T).slice(0).join('');var RESULT=U;",
    3190: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Array(...T).join('');var RESULT=U;",
    3191: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[T].join('');var RESULT=U;",
    3192: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[[T]][0][0];var RESULT=U;",
    3193: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[[[T]]].flat(2)[0];var RESULT=U;",
    3194: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[[[T]]].flat(Infinity).join('');var RESULT=U;",
    3195: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=structuredClone(T).split('').join('');var RESULT=U;",
    3196: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U={...{v:T}, ...{}}.v;var RESULT=U;",
    3197: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Object(T).toString();var RESULT=U;",
    3198: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T).split('').join('');var RESULT=U;",
    3199: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new T.constructor(T).valueOf();var RESULT=U;",
    3200: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new (T.constructor)(T).valueOf();var RESULT=U;",
    3201: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new (T['constructor'])(T).valueOf();var RESULT=U;",
    3202: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T.split('').values()].join('');var RESULT=U;",
    3203: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T.split('').entries()].map(function(e){return e[1];}).join('');var RESULT=U;",
    3204: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T.split('').keys()].map(function(i){return T[i];}).join('');var RESULT=U;",
    3205: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').at(0) + T.split('').slice(1).join('');var RESULT=U;",
    3206: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').shift() + T.split('').slice(1).join('');var RESULT=U;",
    3207: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.at(0) + T.slice(1);var RESULT=U;",
    3208: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T[0] + T.substring(1);var RESULT=U;",
    3209: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.charAt(0) + T.slice(1);var RESULT=U;",
    3210: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(0,1) + T.slice(1);var RESULT=U;",
    3211: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0,1) + T.slice(1);var RESULT=U;",
    3212: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.fromCharCode(...T.split('').map(function(c){return c.charCodeAt(0);}));var RESULT=U;",
    3213: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.fromCharCode.apply(null, T.split('').map(function(c){return c.charCodeAt(0);}));var RESULT=U;",
    3214: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.fromCodePoint(...T.split('').map(function(c){return c.codePointAt(0);}));var RESULT=U;",
    3215: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.fromCodePoint.apply(null, T.split('').map(function(c){return c.codePointAt(0);}));var RESULT=U;",
    3216: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.slice.call(T);var RESULT=U;",
    3217: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.substring.call(T);var RESULT=U;",
    3218: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.substr.call(T);var RESULT=U;",
    3219: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.concat.call(T);var RESULT=U;",
    3220: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.normalize.call(T);var RESULT=U;",
    3221: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.trimStart.call(T);var RESULT=U;",
    3222: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.trimEnd.call(T);var RESULT=U;",
    3223: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.padStart.call(T, 0);var RESULT=U;",
    3224: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.padEnd.call(T, 0);var RESULT=U;",
    3225: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.repeat.call(T, 1);var RESULT=U;",
    3226: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.at.call(T, 0) + String.prototype.slice.call(T, 1);var RESULT=U;",
    3227: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.slice.call(T).join('');var RESULT=U;",
    3228: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.concat.call(T).join('');var RESULT=U;",
    3229: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.map.call(T, function(c){return c;}).join('');var RESULT=U;",
    3230: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.filter.call(T, function(){return true;}).join('');var RESULT=U;",
    3231: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.reduce.call(T, function(a,c){return a+c;}, '');var RESULT=U;",
    3232: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.flat.call([T]).join('');var RESULT=U;",
    3233: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.flatMap.call([T], function(x){return x;}).join('');var RESULT=U;",
    3234: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String.prototype.slice, T, [0]);var RESULT=U;",
    3235: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T['slice'], T, [0]);var RESULT=U;",
    3236: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String.prototype.concat, T, ['']);var RESULT=U;",
    3237: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String.prototype.trim, T, []);var RESULT=U;",
    3238: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.get(String.prototype, 'slice').call(T, 0);var RESULT=U;",
    3239: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length).trim();var RESULT=U;",
    3240: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length).toLowerCase();var RESULT=U;",
    3241: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length).normalize();var RESULT=U;",
    3242: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length).padStart(0);var RESULT=U;",
    3243: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length).split('').join('');var RESULT=U;",
    3244: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0).split('').join('');var RESULT=U;",
    3245: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(0).split('').join('');var RESULT=U;",
    3246: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0).split('').join('');var RESULT=U;",
    3247: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(0).split('').join('');var RESULT=U;",
    3248: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(0).split('').join('');var RESULT=U;",
    3249: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(1).split('').join('');var RESULT=U;",
    3250: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().split('').join('');var RESULT=U;",
    3251: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString().split('').join('');var RESULT=U;",
    3252: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Object(T).valueOf().split('').join('');var RESULT=U;",
    3253: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new String(T).valueOf().split('').join('');var RESULT=U;",
    3254: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0, T.length) + '';var RESULT=U;",
    3255: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='' + T.slice(0, T.length);var RESULT=U;",
    3256: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var {v: U} = {v: T};var RESULT=U;",
    3257: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var [U, ...rest] = [T];var RESULT=U;",
    3258: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var {v: U = T} = {};var RESULT=U;",
    3259: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var [U = T] = [];var RESULT=U;",
    3260: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U = T, RESULT = U;",
    3261: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');U = T;var RESULT = U;",
    3262: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT='';for (var U of [T]) { RESULT = U; }",
    3263: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';var RESULT='';while (U !== T) { U = T; RESULT = U; }",
}


def _payload(n, secret):
    return TEMPLATES[n].replace("{I}", _codes(secret))


def _shape(expr, secret):
    return ("var C=" + _codes(secret) + ";"
            "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "var U=" + expr + ";var RESULT=U;")


PASS = []
FAIL = []


def check(name, cond, msg=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ((" -- " + msg) if msg and not cond else ""), flush=True)


def main():
    # --- Pins ---
    import gov.dlp as dlp_mod
    import inspect
    src = inspect.getsource(dlp_mod)
    nloops = src.count("for _stmtdec in (")
    check("pin N_STMTDEC_LOOPS==202", nloops == 202)  # wave-454 merge reconciliation: 199 stale, true 200 on base +1 lane A = 201; wave-455 merge reconciliation: +1 wave-455 lane A dispatch loop = 202
    nre = len(re.findall(r"re\.compile\(", src))
    check("pin re.compile==29", nre == 29)
    # --- Footer / stamp pin: F3080-F3263 except F3093 CLOSED, open F3264-F3644 (367) ---
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        findings = f.read()
    stamped = 0
    for n in range(3080, 3264):
        if n == 3093:
            continue
        if ("(F%d filed" % n) in findings and ("LOW, CLOSED 2026-10-13 wave-452 lane A:" in findings):
            for line in findings.split("\n"):
                if line.startswith("(F%d filed" % n) and "LOW, CLOSED 2026-10-13 wave-452 lane A:" in line:
                    stamped += 1
                    break
    check("footer F3080-F3263 except F3093 stamped CLOSED 183/183", stamped == 183)
    check("footer lane line present",
          "# Wave-452 lane A: F3080-F3263 except F3093 CLOSED (183" in findings)
    check("footer open F3264-F3644 (367)",
          "F3264-F3644 OPEN (367" in findings)
    check("footer next free F3645", "next free F3645" in findings)

    # --- Filed decoder shapes: 183, must HIT on both secrets ---
    for fnum in sorted(TEMPLATES):
        check("F%d filed 20" % fnum, _scan(_payload(fnum, SECRET20)) == "HIT")
        check("F%d filed 40" % fnum, _scan(_payload(fnum, SECRET40)) == "HIT")

    # --- Generalizations ---
    g1 = _payload(3080, SECRET20).replace("var C=", "let C=").replace("var T=", "let T=").replace("var U=", "let U=").replace("var RESULT=", "let RESULT=")
    check("generalize let", _scan(g1) == "HIT")
    g2 = _payload(3167, SECRET20).replace("var ", "const ")
    check("generalize const", _scan(g2) == "HIT")
    # Renamed vars: S for T, V for U, D for C, W for RESULT.
    g3 = ("var D=" + _codes(SECRET20) + ";"
          "var S=D.map(function(c){return String.fromCharCode(c);}).join('');"
          "var V=S.slice(undefined, undefined);var W=V;")
    # NOTE: parse_result requires RESULT literally, so the renamed-RESULT
    # form is expected MISS (documented scope boundary, same as prior waves).
    check("generalize renamed vars except RESULT", _scan(g3) == "MISS")
    g4 = ("var C=" + _codes(SECRET20) + ";"
          "var S=C.map(function(c){return String.fromCharCode(c);}).join('');"
          "var V=S.slice(undefined, undefined);var RESULT=V;")
    check("generalize renamed T/U", _scan(g4) == "HIT")
    # No space after comma still HITs (parser is ws-tolerant; the
    # F3082 pre-check does not span the comma).
    g5 = _shape("T.slice(0,T.length + 0)", SECRET20)
    check("generalize no space after comma", _scan(g5) == "HIT")
    # NOTE: spaces inside slice args (e.g. `T.slice( 0, ...)`) are NOT
    # asserted: pre-checks are space-sensitive by the wave-450
    # convention, so extra-whitespace variants are separate findings.

    # --- Fail-closed: malformed variants must MISS ---
    check("failclosed slice arg 1", _scan(_shape("T.slice(1)", SECRET20)) == "MISS")
    check("failclosed slice range", _scan(_shape("T.slice(0, 5)", SECRET20)) == "MISS")
    check("failclosed slice len-1", _scan(_shape("T.slice(0, T.length - 1)", SECRET20)) == "MISS")
    check("failclosed slice len+1", _scan(_shape("T.slice(0, T.length + 1)", SECRET20)) == "MISS")
    check("failclosed slice 0-neglen", _scan(_shape("T.slice(0, -T.length)", SECRET20)) == "MISS")
    check("failclosed toUpperCase single", _scan(_shape("T.toUpperCase()", SECRET20)) == "MISS")
    check("failclosed concat x", _scan(_shape("T.concat('x')", SECRET20)) == "MISS")
    check("failclosed template x", _scan(_shape("`${T}${'x'}`", SECRET20)) == "MISS")
    check("failclosed replace x", _scan(_shape("T.replace(/x^/, 'x')", SECRET20)) == "MISS")
    check("failclosed replace /a/", _scan(_shape("T.replace(/a/, '')", SECRET20)) == "MISS")
    check("failclosed splitjoin comma", _scan(_shape("T.split(',').join(',')", SECRET20)) == "MISS")
    check("failclosed splitjoin x", _scan(_shape("T.split('').join('x')", SECRET20)) == "MISS")
    check("failclosed buffer utf16le", _scan(_shape("Buffer.from(T, 'utf16le').toString('utf16le')", SECRET20)) == "MISS")
    check("failclosed charCodeAt 1", _scan(_shape("String.fromCharCode(...T.split('').map(function(c){return c.charCodeAt(1);}))", SECRET20)) == "MISS")
    check("failclosed codePointAt 1", _scan(_shape("String.fromCodePoint(...T.split('').map(function(c){return c.codePointAt(1);}))", SECRET20)) == "MISS")
    check("failclosed proto slice arg 1", _scan(_shape("String.prototype.slice.call(T, 1)", SECRET20)) == "MISS")
    check("failclosed proto trim arg", _scan(_shape("Reflect.apply(String.prototype.trim, T, ['x'])", SECRET20)) == "MISS")
    check("failclosed entries idx 0", _scan(_shape("[...T.split('').entries()].map(function(e){return e[0];}).join('')", SECRET20)) == "MISS")
    check("failclosed keys idx+1", _scan(_shape("[...T.split('').keys()].map(function(i){return T[i+1];}).join('')", SECRET20)) == "MISS")
    check("failclosed reduce init x", _scan(_shape("Array.prototype.reduce.call(T, function(a,c){return a+c;}, 'x')", SECRET20)) == "MISS")
    # NOTE: `new Array(T).join('')` is NOT asserted MISS: F2650
    # (wave-450 lane A) already covers exactly that shape.
    check("failclosed destructure wrong key", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var {w: U} = {w: T};var RESULT=U;") == "MISS")
    check("failclosed destructure default obj present", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var {v: U = T} = {v: T};var RESULT=U;") == "MISS")
    check("failclosed destructure default arr present", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var [U = T] = [T];var RESULT=U;") == "MISS")
    check("failclosed destructure rest 2elem", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var [U, ...rest] = [T, T];var RESULT=U;") == "MISS")
    check("failclosed comma-decl order", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT = U, U = T;") == "MISS")
    check("failclosed bare assign RESULT", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');RESULT = T;var RESULT = U;") == "MISS")
    check("failclosed forof 2elem", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT='';for (var U of [T, T]) { RESULT = U; }") == "MISS")
    check("failclosed while ne", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';var RESULT='';while (U != T) { U = T; RESULT = U; }") == "MISS")
    check("failclosed while eq", _scan("var C=" + _codes(SECRET20) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';var RESULT='';while (U == T) { U = T; RESULT = U; }") == "MISS")
    # Guard-isolating fail-closed tests: each input is reachable
    # through the base parser and would HIT if its guard were
    # missing, because the unguarded variant still contains a
    # credential-shaped substring.
    check("failclosed F3129 upper", _scan(_shape("T.toUpperCase().toLowerCase().toUpperCase().toLowerCase()", SECRET_UPPER)) == "MISS")
    check("failclosed F3240 upper", _scan(_shape("T.slice(0, T.length).toLowerCase()", SECRET_UPPER)) == "MISS")
    padded = SECRET20 + " "  # trailing space
    check("failclosed F3239 padded", _scan(_shape("T.slice(0, T.length).trim()", padded)) == "MISS")
    check("failclosed F3237 padded", _scan(_shape("Reflect.apply(String.prototype.trim, T, [])", padded)) == "MISS")
    check("failclosed F3221 padded lead", _scan(_shape("String.prototype.trimStart.call(T)", " " + SECRET20)) == "MISS")
    check("failclosed F3222 padded trail", _scan(_shape("String.prototype.trimEnd.call(T)", padded)) == "MISS")
    SECRET_NFC_BAD = SECRET20 + "\u0301"  # trailing combining acute: non-NFC
    check("failclosed F3241 non-NFC", _scan(_shape("T.slice(0, T.length).normalize()", SECRET_NFC_BAD)) == "MISS")
    check("failclosed F3173 non-NFC", _scan(_shape("T.normalize('NFC').normalize('NFD').normalize('NFC')", SECRET_NFC_BAD)) == "MISS")
    check("failclosed F3220 non-NFC", _scan(_shape("String.prototype.normalize.call(T)", SECRET_NFC_BAD)) == "MISS")
    SECRET_LONE = SECRET20 + "\ud800"  # trailing lone surrogate
    check("failclosed F3170 lone surrogate", _scan(_shape("Buffer.from(T).toString()", SECRET_LONE)) == "MISS")
    check("failclosed F3171 lone surrogate", _scan(_shape("Buffer.from(T, 'utf8').toString('utf8')", SECRET_LONE)) == "MISS")
    check("failclosed F3172 lone surrogate", _scan(_shape("Buffer.from(T).toString('utf-8')", SECRET_LONE)) == "MISS")
    # Post-review (Spec H1/H2/H3): Unicode-skew + $-substitution repros.
    SECRET_1C89 = SECRET20 + "\u1c89"  # U+1C89: JS lowercases, Python 15.0 does not
    check("failclosed F3240 U+1C89", _scan(_shape("T.slice(0, T.length).toLowerCase()", SECRET_1C89)) == "MISS")
    SECRET_DOLLAR = SECRET20 + "$'"  # $-substitution changes replace(T, T)
    check("failclosed F3152 dollar", _scan(_shape("T.replace(T, T)", SECRET_DOLLAR)) == "MISS")
    SECRET_ASTRAL_NFC = SECRET20 + "\ud818\udd1e\ud818\udd1e"  # U+1611E x2: JS NFC composes
    check("failclosed F3241 astral-NFC", _scan(_shape("T.slice(0, T.length).normalize()", SECRET_ASTRAL_NFC)) == "MISS")
    check("failclosed F3173 astral-NFC", _scan(_shape("T.normalize('NFC').normalize('NFD').normalize('NFC')", SECRET_ASTRAL_NFC)) == "MISS")
    check("failclosed F3220 astral-NFC", _scan(_shape("String.prototype.normalize.call(T)", SECRET_ASTRAL_NFC)) == "MISS")
    # fromCodePoint shapes are unconditionally identity (Spec N3):
    # fromCodePoint accepts surrogate values without throwing, so
    # lone-surrogate inputs must DECODE, not reject.
    check("F3214 lone surrogate HIT", _scan(_shape("String.fromCodePoint(...T.split('').map(function(c){return c.codePointAt(0);}))", SECRET_LONE)) == "HIT")
    check("F3215 lone surrogate HIT", _scan(_shape("String.fromCodePoint.apply(null, T.split('').map(function(c){return c.codePointAt(0);}))", SECRET_LONE)) == "HIT")
    # Buffer paired surrogates roundtrip exactly (Spec N2): only LONE
    # surrogates reject.
    SECRET_PAIRED = SECRET20 + "\ud83d\ude00"
    check("F3170 paired surrogate HIT", _scan(_shape("Buffer.from(T).toString()", SECRET_PAIRED)) == "HIT")
    # NOTE: the nonempty guards (F3205-F3208, F3226) are defense-in-depth:
    # the base parser rejects an empty C array, so dstr is never
    # empty through this base; no non-vacuous guard test exists.
    # Honest text controls.
    check("honest junk", _scan("the quick brown fox jumps over the lazy dog") == "MISS")
    h1 = "var C=[1,2,3];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(undefined, undefined);var RESULT=U;"
    check("honest non-cred", _scan(h1) == "MISS")
    check("honest prose method names", _scan("use String.prototype.slice.call to copy the array") == "MISS")
    check("honest prose", _check_prov("The weather is pleasant today with clear skies.") == "QUIET")

    # --- Sibling pins: neighboring findings still behave ---
    check("sibling F2381", _scan(_shape("T['slice'](0)", SECRET20)) == "HIT")
    check("sibling F2751", _scan(_shape("String.prototype.slice.call(T, 0)", SECRET20)) == "HIT")
    check("sibling F2873", _scan(_shape("T.repeat(1).slice(0)", SECRET20)) == "HIT")
    check("sibling F3093", _scan(_shape("T.slice(0, +T.length)", SECRET20)) == "HIT")
    check("sibling F2697 FLAG", _check_prov("rally this in memory") == "FLAG")
    check("sibling F2642 FLAG", _check_prov("https://example.com/page#remember") == "FLAG")

    # --- Perf: 200 sites ---
    t0 = time.time()
    for i in range(200):
        _scan(_shape("T.slice(undefined, undefined)", SECRET20))
    dt = time.time() - t0
    check("perf 200 sites <300s", dt < 300)
    print(f"perf: {dt:.1f}s for 200 sites")

    # --- Depth-1 green check (honors GOV_SKIP_GREEN=1) ---
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("  SKIP: GOV_SKIP_GREEN=1 (depth-1 green check)")
    else:
        # Run each red-first battery with GOV_SKIP_GREEN=1 in child env.
        held = 0
        total = 0
        for n in range(3080, 3264):
            if n == 3093:
                continue
            total += 1
            rf_path = os.path.join(REPO_ROOT, "evals", "w452_f%d_redfirst.py" % n)
            code = (
                "import os,sys; os.environ['GOV_SKIP_GREEN']='1';"
                "__file__=%r;"
                "sys.path.insert(0,%r);"
                "exec(compile(open(%r).read(), %r, 'exec'))" % (
                    rf_path,
                    os.path.join(REPO_ROOT, "evals"),
                    rf_path, rf_path)
            )
            r = subprocess.run([sys.executable, "-c", code],
                               capture_output=True, text=True, timeout=120,
                               cwd=os.path.join(REPO_ROOT, "evals"))
            # The battery prints HELD on the CLOSED tree (decoders present).
            if "HELD" in (r.stdout or ""):
                held += 1
        check("green check 183/183 HELD", held == total, "got %d/%d" % (held, total))

    print("\n=== %d PASS, %d FAIL ===" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
