#!/usr/bin/env python3
"""Close battery for wave-451 lane A: F2751-F2873 (123 decoder-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1
(runs the 123 red-first batteries, expecting HELD on the closed tree).
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w451_close_")
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


def _shape(expr, secret):
    return ("var C=" + _codes(secret) + ";"
            "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "var U=" + expr + ";var RESULT=U;")


# F-number -> filed decoder expression (exact attack-template shapes).
FILED = {

    2751: 'String.prototype.slice.call(T, 0)',
    2752: 'String.prototype.toLowerCase.call(T)',
    2753: "Array.prototype.join.call(T, '')",
    2754: "Array.prototype.slice.call(T, 0).join('')",
    2755: 'T.slice.call(T, 0)',
    2756: 'T.substring.call(T, 0)',
    2757: "T.concat.call(T, '')",
    2758: 'T.trim.call(T)',
    2759: 'T.toLowerCase.call(T)',
    2760: 'T.normalize.call(T)',
    2761: "T['slice'].apply(T, [0])",
    2762: 'T.slice.apply(T, [0])',
    2763: 'T.__proto__.constructor(T)',
    2764: "T['__proto__']['constructor'](T)",
    2765: 'T.__proto__.valueOf.call(T)',
    2766: "''.constructor(T)",
    2767: 'T.toString(T)',
    2768: 'T.slice(0, T.length)',
    2769: 'T.slice(0, Infinity)',
    2770: 'T.slice(T.length - T.length)',
    2771: 'T.slice(0 | 0)',
    2772: "T.slice(+'')",
    2773: "T.slice(Number(''))",
    2774: "T.slice(parseInt('0'))",
    2775: 'T.slice(Math.min(0, 1))',
    2776: 'T.slice(Math.max(0, -1))',
    2777: 'T.slice(Math.floor(0.5))',
    2778: 'T.charAt(0) + T.substring(1)',
    2779: 'T.at(0) + T.substring(1)',
    2780: 'T.substring(0,1) + T.substring(1)',
    2781: 'T.substr(0,1) + T.substr(1)',
    2782: 'T.slice(0, T.length-1) + T.slice(-1)',
    2783: 'T.slice(0, -1) + T.slice(-1)',
    2784: 'T.slice(0,1) + T.substring(1)',
    2785: 'T[0] + T.slice(1)',
    2786: 'T.charAt(0) + T.substr(1)',
    2787: "T.split('').splice(0).join('')",
    2788: "T.split('').splice(0, T.length).join('')",
    2789: "T.split('').filter(Boolean).join('')",
    2790: "T.split('').flat().join('')",
    2791: "T.split('').flatMap(function(c){return c;}).join('')",
    2792: "T.split('').flat(1).join('')",
    2793: "T.split('').flat(Infinity).join('')",
    2794: "T.split('').toReversed().toReversed().join('')",
    2795: "T.split('').with(0, T[0]).join('')",
    2796: "T.split('').fill(T[0], 0, 1).join('')",
    2797: "T.split('').copyWithin(0, 0).join('')",
    2798: "T.split('').reduce(function(a,c){return a+c;}, '')",
    2799: "T.split('').join('').split('').join('')",
    2800: 'T.split(T).join(T)',
    2801: "T.split(/\\n/).join('')",
    2802: "T.split('\\n').join('')",
    2803: "T.split('\\x00').join('')",
    2804: "T.split(/a^/).join('')",
    2805: "T.split(/(?!)/).join('')",
    2806: "T.split(/(?:)/).join('')",
    2807: "T.split(/()/).join('')",
    2808: "T.match(/[\\s\\S]/g).join('')",
    2809: "T.match(/[^]/g).join('')",
    2810: 'T.match(/\\n/g) || T',
    2811: 'T.replace(/./, function(m){return m;})',
    2812: "T.replace(/./g, '$&')",
    2813: "T.replaceAll(/./g, '$&')",
    2814: "T.replace(/\\n/g, '')",
    2815: "T.replace(/(.)/g, '$1')",
    2816: "T.replaceAll(/(.)/g, '$1')",
    2817: "T.replace(/(.)/, '$1')",
    2818: "T.replace(/^(.*)$/, '$1')",
    2819: "T.replace(/(.*)/, '$1')",
    2820: 'Object.assign({v:T}, {}).v',
    2821: '{...{v:T}}.v',
    2822: "{...{v:T}}['v']",
    2823: '({...{}, v:T}).v',
    2824: 'Object.create(null, {v:{value:T}}).v',
    2825: 'Object.defineProperties({}, {v:{value:T}}).v',
    2826: "Reflect.getOwnPropertyDescriptor({v:T}, 'v').value",
    2827: "Object.getOwnPropertyDescriptor({v:T}, 'v').value",
    2828: 'Object.getOwnPropertyDescriptors({v:T}).v.value',
    2829: 'Object.setPrototypeOf({v:T}, null).v',
    2830: 'Object.preventExtensions({v:T}).v',
    2831: 'Object.seal({v:T}).v',
    2832: "({v:T})['v']",
    2833: "[T]['0']",
    2834: "new Map().set('k',T).get('k')",
    2835: 'new Set().add(T).values().next().value',
    2836: "new Set([T]).size === 1 ? T : ''",
    2837: 'JSON.parse(JSON.stringify([T]))[0]',
    2838: 'JSON.parse(JSON.stringify(T), function(k,v){return v;})',
    2839: 'structuredClone([T])[0]',
    2840: "structuredClone([T]).join('')",
    2841: 'structuredClone({v:T}).v',
    2842: "Array.from(T, c => c).join('')",
    2843: "[...T].map(c => c).join('')",
    2844: "T.split('').map(c => c).join('')",
    2845: "T.split('').filter(c => true).join('')",
    2846: "T.split('').reduce((a,c) => a+c, '')",
    2847: '((x) => x)(T)',
    2848: '(x => x)(T)',
    2849: '((x) => { return x; })(T)',
    2850: 'new (function(){this.v=T;})().v',
    2851: 'new (function(){return {v:T};})().v',
    2852: 'T?.valueOf()',
    2853: "T?.concat('')",
    2854: 'T?.substring(0)',
    2855: 'T?.substr(0)',
    2856: 'T?.trim()',
    2857: 'T?.toLowerCase()',
    2858: 'T?.padStart(0)',
    2859: 'T?.normalize()',
    2860: 'T?.at(0) + T?.slice(1)',
    2861: "(T ?? '')?.substring(0)",
    2862: "(T || '')?.trim()",
    2863: '(T && T)?.valueOf()',
    2864: 'T?.slice?.(0, T?.length)',
    2865: 'T?.slice?.(0, T.length)',
    2866: "T.normalize().normalize('NFC')",
    2867: "T.normalize('NFD').normalize('NFC')",
    2868: "T.normalize('NFKD').normalize('NFC')",
    2869: 'T.toLocaleLowerCase().toLocaleUpperCase().toLocaleLowerCase()',
    2870: 'String.fromCharCode.apply(null, [...T].map(function(c){return c.charCodeAt(0);}))',
    2871: 'String.fromCharCode(...[...T].map(c=>c.charCodeAt(0)))',
    2872: 'T[Symbol.iterator]().next().value + T.slice(1)',
    2873: 'T.repeat(1).slice(0)',
}

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
    # --- Footer / stamp pin: F2751-F2873 CLOSED, open F2874-F3079 (204) ---
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        findings = f.read()
    stamped = 0
    for n in range(2751, 2874):
        if ("(F%d filed" % n) in findings and ("LOW, CLOSED 2026-10-13 wave-451 lane A:" in findings):
            # The stamp must be on THIS finding's entry line.
            for line in findings.split("\n"):
                if line.startswith("(F%d filed" % n) and "LOW, CLOSED 2026-10-13 wave-451 lane A:" in line:
                    stamped += 1
                    break
    check("footer F2751-F2873 stamped CLOSED 123/123", stamped == 123)
    check("footer lane line present",
          "# Wave-451 lane A: F2751-F2873 CLOSED (123" in findings)
    check("footer open F2874-F3079 (204)",
          "F2874-F3079 OPEN except F3033/F3035 (204" in findings)
    check("footer next free F3080", "next free F3080" in findings)

    # --- Filed decoder shapes: 123, must HIT on both secrets ---
    for fnum, expr in sorted(FILED.items()):
        check("F%d filed 20" % fnum, _scan(_shape(expr, SECRET20)) == "HIT")
        check("F%d filed 40" % fnum, _scan(_shape(expr, SECRET40)) == "HIT")

    # --- Generalizations ---
    g1 = _shape("String.prototype.slice.call(T, 0)", SECRET20).replace("var C=", "let C=").replace("var T=", "let T=").replace("var U=", "let U=").replace("var RESULT=", "let RESULT=")
    check("generalize let", _scan(g1) == "HIT")
    g2 = _shape("T.split('').splice(0).join('')", SECRET20).replace("var ", "const ")
    check("generalize const", _scan(g2) == "HIT")
    # Renamed vars: S for T, V for U, D for C, W for RESULT.
    g3 = ("var D=" + _codes(SECRET20) + ";"
          "var S=D.map(function(c){return String.fromCharCode(c);}).join('');"
          "var V=S.slice.call(S, 0);var W=V;")
    # NOTE: parse_result requires RESULT literally, so the renamed-RESULT
    # form is expected MISS (documented scope boundary, same as prior waves).
    check("generalize renamed vars except RESULT", _scan(g3) == "MISS")
    g4 = ("var C=" + _codes(SECRET20) + ";"
          "var S=C.map(function(c){return String.fromCharCode(c);}).join('');"
          "var V=S.slice.call(S, 0);var RESULT=V;")
    check("generalize renamed T/U", _scan(g4) == "HIT")
    # Fewer-spaces variant still HITs (parser is ws-tolerant; prechecks are
    # space-sensitive, so extra-whitespace variants are separate findings
    # per the wave-450 convention and are NOT asserted here).
    g5 = _shape("T.slice(0,T.length)", SECRET20)
    check("generalize no space after comma", _scan(g5) == "HIT")

    # --- Fail-closed: malformed variants must MISS ---
    check("failclosed slice.call arg 1", _scan(_shape("T.slice.call(T, 1)", SECRET20)) == "MISS")
    check("failclosed slice arg 1", _scan(_shape("T.slice(1)", SECRET20)) == "MISS")
    check("failclosed slice range", _scan(_shape("T.slice(0, 5)", SECRET20)) == "MISS")
    check("failclosed charAt-substring 2", _scan(_shape("T.charAt(0) + T.substring(2)", SECRET20)) == "MISS")
    check("failclosed splice 1", _scan(_shape("T.split('').splice(1).join('')", SECRET20)) == "MISS")
    check("failclosed with x", _scan(_shape("T.split('').with(0, 'x').join('')", SECRET20)) == "MISS")
    check("failclosed single toReversed", _scan(_shape("T.split('').toReversed().join('')", SECRET20)) == "MISS")
    check("failclosed replace x", _scan(_shape("T.replace(/./g, 'x')", SECRET20)) == "MISS")
    check("failclosed assign wrong prop", _scan(_shape("Object.assign({v:T}, {}).x", SECRET20)) == "MISS")
    check("failclosed Set size 2", _scan(_shape("new Set([T]).size === 2 ? T : ''", SECRET20)) == "MISS")
    check("failclosed slice optional range", _scan(_shape("T?.slice?.(0, 1)", SECRET20)) == "MISS")
    check("failclosed charCodeAt 1", _scan(_shape("String.fromCharCode.apply(null, [...T].map(function(c){return c.charCodeAt(1);}))", SECRET20)) == "MISS")
    check("failclosed iterator slice 2", _scan(_shape("T[Symbol.iterator]().next().value + T.slice(2)", SECRET20)) == "MISS")
    check("failclosed arrow wrong var", _scan(_shape("(x => y)(T)", SECRET20)) == "MISS")
    check("failclosed array index 1", _scan(_shape("[T]['1']", SECRET20)) == "MISS")
    check("failclosed split on a", _scan(_shape("T.split(/a/).join('')", SECRET20)) == "MISS")
    check("failclosed replace newline x", _scan(_shape("T.replace(/\\n/g, 'x')", SECRET20)) == "MISS")
    check("failclosed split newline x", _scan(_shape("T.split(/\\n/).join('x')", SECRET20)) == "MISS")
    check("failclosed head-tail drop", _scan(_shape("T.slice(0, T.length-2) + T.slice(-1)", SECRET20)) == "MISS")
    check("failclosed upper toLowerCase.call", _scan(_shape("T.toLowerCase.call(T)", SECRET_UPPER)) == "MISS")
    check("failclosed upper optional toLowerCase", _scan(_shape("T?.toLowerCase()", SECRET_UPPER)) == "MISS")
    check("failclosed upper locale roundtrip", _scan(_shape("T.toLocaleLowerCase().toLocaleUpperCase().toLocaleLowerCase()", SECRET_UPPER)) == "MISS")
    # Padded credential + trim shape: the trim guard must reject (no variant).
    # The padded string still contains a credential-shaped substring, so a
    # missing guard would HIT via substring match -- this isolates the guard.
    padded = SECRET20 + " "  # trailing space
    check("failclosed trim padded", _scan(_shape("T.trim.call(T)", padded)) == "MISS")
    check("failclosed trim padded opt", _scan(_shape("T?.trim()", padded)) == "MISS")
    # Guard-isolating fail-closed tests (Spec review): each input is BMP +
    # non-empty (reachable through the base parser) and would HIT if its
    # guard were missing, because the unguarded variant still contains a
    # credential-shaped substring.
    SECRET_NFC_BAD = SECRET20 + "\u0301"  # trailing combining acute: non-NFC
    SECRET_LIG = SECRET20 + "\ufb01"  # trailing fi ligature: NFKD-unstable
    SECRET_NONASCII = SECRET20 + "\u00c9"  # trailing non-ASCII uppercase
    SECRET_NL = SECRET20 + "\n"  # trailing newline
    SECRET_NUL = SECRET20 + "\x00"  # trailing NUL
    check("failclosed normalize non-NFC", _scan(_shape("T.normalize.call(T)", SECRET_NFC_BAD)) == "MISS")
    check("failclosed normalize NFKD nonstable", _scan(_shape("T.normalize('NFKD').normalize('NFC')", SECRET_LIG)) == "MISS")
    check("failclosed locale non-ASCII", _scan(_shape("T.toLocaleLowerCase().toLocaleUpperCase().toLocaleLowerCase()", SECRET_NONASCII)) == "MISS")
    check("failclosed split newline", _scan(_shape("T.split(/\\n/).join('')", SECRET_NL)) == "MISS")
    check("failclosed split newline str", _scan(_shape("T.split('\\n').join('')", SECRET_NL)) == "MISS")
    check("failclosed match newline or", _scan(_shape("T.match(/\\n/g) || T", SECRET_NL)) == "MISS")
    check("failclosed replace newline", _scan(_shape("T.replace(/\\n/g, '')", SECRET_NL)) == "MISS")
    check("failclosed replace whole newline", _scan(_shape("T.replace(/^(.*)$/, '$1')", SECRET_NL)) == "MISS")
    check("failclosed split NUL", _scan(_shape("T.split('\\x00').join('')", SECRET_NUL)) == "MISS")
    check("failclosed optional normalize non-NFC", _scan(_shape("T?.normalize()", SECRET_NFC_BAD)) == "MISS")
    # Honest text controls.
    check("honest junk", _scan("the quick brown fox jumps over the lazy dog") == "MISS")
    h1 = "var C=[1,2,3];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.slice.call(T, 0);var RESULT=U;"
    check("honest non-cred", _scan(h1) == "MISS")
    check("honest prose method names", _scan("use String.prototype.slice.call to copy the array") == "MISS")
    check("honest prose", _check_prov("The weather is pleasant today with clear skies.") == "QUIET")

    # --- Sibling pins: neighboring findings still behave ---
    check("sibling F2381", _scan(_shape("T['slice'](0)", SECRET20)) == "HIT")
    check("sibling F2643", _scan(_shape("T?.slice?.(0)", SECRET20)) == "HIT")
    check("sibling F2697 FLAG", _check_prov("rally this in memory") == "FLAG")
    check("sibling F2642 FLAG", _check_prov("https://example.com/page#remember") == "FLAG")

    # --- Perf: 200 sites ---
    t0 = time.time()
    for i in range(200):
        _scan(_shape("String.prototype.slice.call(T, 0)", SECRET20))
    dt = time.time() - t0
    check("perf 200 sites <300s", dt < 300)
    print(f"perf: {dt:.1f}s for 200 sites")

    # --- Depth-1 green check (honors GOV_SKIP_GREEN=1) ---
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("  SKIP: GOV_SKIP_GREEN=1 (depth-1 green check)")
    else:
        # Run each red-first battery with GOV_SKIP_GREEN=1 in child env.
        import importlib.util
        held = 0
        total = 0
        for n in range(2751, 2874):
            total += 1
            rf_path = os.path.join(REPO_ROOT, "evals", "w451_f%d_redfirst.py" % n)
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
        check("green check 123/123 HELD", held == total, "got %d/%d" % (held, total))

    print("\n=== %d PASS, %d FAIL ===" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
