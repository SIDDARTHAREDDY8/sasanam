#!/usr/bin/env python3
"""Wave-375 lane 6: F625 closure probes -- Map entries()/keys() spread args.

F625 (LOW): `...new Map([[k,v],...]).entries()` / `.keys()` spread into
call arguments bypassed the bounded static JS-expression decoder.
F615 (CLOSED) covers the `.values()` spread source; the F500/F505
spread-source precedent says the SOURCE production matters, and
entries()/keys() had no modeled path.

Closure (gov/dlp.py):
- `_js_parse_new_map_head`: the F494 entry-validation head factored
  out (F494's `.values()` wrapper is behavior-identical).
- `_js_parse_f625_mapspread_args`: parses the entries()/keys() spread
  sources; entry validation via the shared head; a rescan recovers
  each surviving entry's raw source text (pair spans for entries,
  key spans for keys) with later-wins order, agreement-checked
  against the validated head (fail closed on divergence).
- Both spread call sites (`_js_parse_f577_arrow_rest_iife` rest-param,
  `_js_parse_f608_fixed_arrow_spread_iife` fixed-param) now try the
  F625 source after F608/F615; mixed spread kinds in one call fail
  closed (unfiled residual).
- `_js_bind_f625_pair_arguments`: fixed params bound to [k,v] pair
  arrays -- bare `a` or the engine index reads `a[0]`/`a[1]` only;
  everything else fails closed.

Tally convention: 0 BREAK / N HELD. Pin 2140. $0 spend (evals-only).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-374 merge: F636-F639 FILED OPEN; next F640

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def _msrc(entries):
    return "new Map(%s)" % entries


def p1_filed_shapes_held():
    """The 3 F625 filed shapes now block."""
    shapes = [
        # entries spread, rest-param, values projection
        "((...a)=>a.map(e=>e[1]).join(''))(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # entries spread, fixed-param, pair index reads
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # keys spread, rest-param
        "((...a)=>a.join(''))(...%s.keys())"
        % _msrc("[['%s','x'],['%s','y']]" % (_A, _B)),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Engine-exact variants block."""
    shapes = [
        # later-wins on duplicate keys (entries + keys)
        "((...a)=>a.map(e=>e[1]).join(''))(...%s.entries())"
        % _msrc("[['a','x'],['a','%s'],['b','%s']]" % (_A, _B)),
        "((...a)=>a.join(''))(...%s.keys())"
        % _msrc("[['%s','x'],['%s','y'],['%s','z']]" % (_A, _B, _A)),
        # numeric keys (SameValueZero identity)
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[[0,'%s'],[1,'%s']]" % (_A, _B)),
        # numeric keys with later-wins (SameValueZero identity)
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[[0,'x'],[0,'%s'],[1,'%s']]" % (_A, _B)),
        # hex numeric keys
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[[0x0,'%s'],[0x1,'%s']]" % (_A, _B)),
        # keys fixed-param
        "((a,b)=>a+b)(...%s.keys())"
        % _msrc("[['%s','x'],['%s','y']]" % (_A, _B)),
        # entries rest-param with the keys projection (F517 grammar)
        "((...a)=>a.map(e=>e[0]).join(''))(...%s.entries())"
        % _msrc("[['%s','x'],['%s','y']]" % (_A, _B)),
        # the .call dispatch twins
        "((a,b)=>a[1]+b[1]).call(null,...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        "((...a)=>a.map(e=>e[1]).join('')).call(null,...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # pair index 0 reads (keys out of pairs)
        "((a,b)=>a[0]+b[0])(...%s.entries())"
        % _msrc("[['%s','x'],['%s','y']]" % (_A, _B)),
        # three-entry maps, extra args dropped
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s'],['c','z']]" % (_A, _B)),
        # mixed quote styles in the entry literals
        '((...a)=>a.map(e=>e[1]).join(""))(...%s.entries())'
        % _msrc('[["a","%s"],["b","%s"]]' % (_A, _B)),
        # entries rest with block-body arrow projection
        "((...a)=>a.map(e=>{return e[1];}).join(''))(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p3_fail_closed_boundaries():
    """Boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # bare Map spread (no member)
        "((a)=>a)(...%s)" % _msrc("[['a','%s']]" % _A),
        # array spread
        "((a,b)=>a+b)(...['%s','%s'])" % (_A, _B),
        # non-literal keys / values
        "((a)=>a)(...%s.entries())" % _msrc("[x,'%s']" % _A),
        "((a)=>a)(...%s.entries())" % _msrc("['a',x]"),
        # negative numeric keys: the F494 validator rejects them
        "((a,b)=>a[1]+b[1])(...%s.entries())"
        % _msrc("[[-1,'%s'],[2,'%s']]" % (_A, _B)),
        # malformed entry arrays
        "((a)=>a)(...%s.entries())" % _msrc(""),
        "((a)=>a)(...%s.entries())" % _msrc("['a']"),
        "((a)=>a)(...%s.entries())" % _msrc("['a','%s','zz']" % _A),
        # arity shortfall (engine coerces undefined -- never guessed)
        "((a,b,c)=>a[1]+b[1]+c[1])(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # non-0/1 pair indices
        "((a,b)=>a[2]+b[2])(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # member / call / spread uses of a pair param
        "((a,b)=>a.M+b.M)(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        "((a,b)=>a()+b())(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        "((a,b)=>[...a,...b])(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # .apply (documented residual)
        "((a,b)=>a[1]+b[1]).apply(null,...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # mixed spread kinds in one call (unfiled residual)
        "((...a)=>a.join(''))(...new Set(['%s']),...%s.entries())"
        % (_A, _msrc("[['a','%s']]" % _A)),
        "((a,b)=>a[1]+b[1])(...%s.entries(),...%s.keys())"
        % (_msrc("[['a','%s']]" % _A), _msrc("[['b','%s']]" % _B)),
        # var-bound Map (literal-only scope, documented residual)
        "(function(){var m=%s;"
        "return ((a,b)=>a[1]+b[1])(...m.entries());})()" % _msrc(
            "[['a','%s'],['b','%s']]" % (_A, _B)),
        # Set.entries spread (Set source, unfiled residual)
        "((...a)=>a.map(e=>e[1]).join(''))(...new Set(['%s','%s']).entries())"
        % (_A, _B),
        # pairs joined directly (node yields 'a,f1b,f2' -- no credential)
        "((...a)=>a.join(''))(...%s.entries())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p4_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    import json as _json
    import subprocess as _sp
    cases = [
        # (js, node-yields-credential?)
        (("((...a)=>a.map(e=>e[1]).join(''))(...%s.entries())"
          % _msrc("[['a','%s'],['b','%s']]" % (_A, _B))), True),
        (("((a,b)=>a[1]+b[1])(...%s.entries())"
          % _msrc("[['a','%s'],['b','%s']]" % (_A, _B))), True),
        (("((...a)=>a.join(''))(...%s.keys())"
          % _msrc("[['%s','x'],['%s','y']]" % (_A, _B))), True),
        (("((...a)=>a.map(e=>e[1]).join(''))(...%s.entries())"
          % _msrc("[['a','x'],['a','%s'],['b','%s']]" % (_A, _B))), True),
        (("((a,b)=>a[1]+b[1])(...%s.entries())"
          % _msrc("[[0,'%s'],[1,'%s']]" % (_A, _B))), True),
        (("((a,b)=>a+b)(...%s.keys())"
          % _msrc("[['%s','x'],['%s','y']]" % (_A, _B))), True),
        (("((...a)=>a.map(e=>e[0]).join(''))(...%s.entries())"
          % _msrc("[['%s','x'],['%s','y']]" % (_A, _B))), True),
        (("((a,b)=>a[1]+b[1]).call(null,...%s.entries())"
          % _msrc("[['a','%s'],['b','%s']]" % (_A, _B))), True),
        # node-quiet controls
        (("((a,b,c)=>a[1]+b[1]+c[1])(...%s.entries())"
          % _msrc("[['a','%s'],['b','%s']]" % (_A, _B))), False),
        (("((...a)=>a.join(''))(...%s.entries())"
          % _msrc("[['a','%s'],['b','%s']]" % (_A, _B))), False),
    ]
    js = "const R=[];\n" + "\n".join(
        "try{R.push(eval(%s)===%s)}catch(e){R.push('err')}"
        % (repr(c), repr(_CRED)) for c, _ in cases) + \
        "\nconsole.log(JSON.stringify(R));"
    r = _sp.run(["node", "-e", js], capture_output=True, text=True,
                timeout=60)
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for (c, _), truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        if truth == "err":
            truth = False
        if dec_hit != truth:
            bad.append(c)
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement" % (len(cases) - len(bad),
                                              len(cases)))


def _open_neighbor_shapes():
    """Filed shapes of the still-OPEN round-42/merge findings.

    F621-F624, F626-F639 must still BREAK (F625 is this lane --
    excluded). This lane must not absorb them.
    """
    import importlib
    shapes = []
    for fnum in (621, 622, 623, 624, 626, 627, 628, 629, 630, 631,
                 632, 633, 634, 636, 637, 638, 639):
        mod = importlib.import_module("w374_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append((fnum, name, payload))
    return shapes


def p5_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F615 (Map.values spread) stays HELD
        "((...a)=>a.join(''))(...%s.values())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        "((a,b)=>a+b)(...%s.values())"
        % _msrc("[['a','%s'],['b','%s']]" % (_A, _B)),
        # F608 (Set spread) stays HELD
        "((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B),
        "((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B),
        # F494 (Map.values array spread) stays HELD
        "[...%s.values()].join('')" % _msrc("[['a','%s'],['b','%s']]"
                                            % (_A, _B)),
        # F517 (entries projection on Object.entries) stays HELD
        "Object.entries({a:'%s',b:'%s'}).map(e=>e[1]).join('')"
        % (_A, _B),
        # F577 (rest-param arrow, literal args) stays HELD
        "((...a)=>a.join(''))('%s','%s')" % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    bad_open = []
    for fnum, name, payload in _open_neighbor_shapes():
        if _blocked(payload):
            bad_open.append((fnum, name))
    ok = not bad_held and not bad_open
    return ("HELD" if ok else "BREAK",
            "%d/%d compositions ok%s" % (
                len(held) + len(_open_neighbor_shapes())
                - len(bad_held) - len(bad_open),
                len(held) + len(_open_neighbor_shapes()),
                "" if ok else " " + repr(bad_held + bad_open)[:200]))


def p6_honest_text_quiet():
    """Honest texts stay quiet."""
    texts = [
        "the map entries spread across the quarterly report",
        "she spread the keys on the table before the meeting",
        "new Map([[1,2],[3,4]]) is not valid credential text",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad),
                                          len(texts)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F625 closed, next F640."""
    from gov import decision_codes as _dc
    n = len(_dc.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "FINDINGS.md")
    text = open(path).read()
    footer_ok = ("CLOSED 2026-10-08 wave-375 lane 6" in text
                 and "Next free finding: **F640**" in text  # Wave-375 lane 6: F625 CLOSED
                 and "Open findings: F621, F622, F623, F624, F626, F627, F628, F629, F630, F631, F632, F633, F634, F635, F636, F637, F638, F639." in text)  # Wave-375 lane 6: F625 CLOSED
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail) if (pin_ok and footer_ok)
            else ("BREAK", detail))


def p8_perf():
    """F452: the spread corpus stays bounded."""
    import time as _t
    corpus = []
    for i in range(300):
        corpus.append(
            "((...a)=>a.map(e=>e[1]).join(''))(...%s.entries())"
            % _msrc("[['k%d','v%d'],['j%d','w%d']]" % (i, i, i, i)))
    t0 = _t.time()
    for c in corpus:
        dlp.find_credential(c)
    dt = _t.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "300-site corpus %.2fs" % dt)


def p9_documented_residuals():
    """Pre-existing F577/postfix boundaries pin their current behavior.

    None are F625 regressions (all verified identical on the base
    tree a08a5406): the nested-function binder guard, whitespace
    around the member dot, and the post-invocation `.call(null)`
    false-positive (engine throws TypeError; decoder hits -- a
    conservative false positive, not a miss).
    """
    notes = []
    # nested-function callback in a rest-param body: the F577 binder
    # guard fails closed (pre-existing).
    s1 = ("((...a)=>a.map(function(p){return p[1];}).join(''))"
          "(...%s.entries())" % _msrc("[['a','%s'],['b','%s']]"
                                     % (_A, _B)))
    notes.append(("nested-fn-callback", _quiet(s1)))
    # whitespace around the member dot: pre-existing postfix limit.
    s2 = (("(( ... a ) => a . map ( e => e[1] ) . join ( '' ) )"
           "( ... %s . entries ( ) )" % _msrc("[['a','%s'],['b','%s']]"
                                             % (_A, _B))))
    notes.append(("ws-member-dot", _quiet(s2)))
    # post-invocation .call(null): engine throws; decoder hits
    # (pre-existing conservative false positive, F577 family).
    s3 = ("((...a)=>a.map(e=>e[1]).join(''))"
          "(...%s.entries()).call(null)" % _msrc("[['a','%s'],['b','%s']]"
                                                 % (_A, _B)))
    notes.append(("postcall-fp", _blocked(s3)))
    bad = [n for n, ok in notes if not ok]
    return ("HELD" if not bad else "BREAK",
            "%d/%d residuals pinned (%s)" % (len(notes) - len(bad),
                                             len(notes),
                                             ",".join(n for n, _ in notes)))


def _green_check():
    """Depth-1 green check: adjacent batteries' mains with GOV_SKIP_GREEN=1.

    A battery is green when its tally line reports 0 BREAK and it
    exits 0 (the repo convention). Unique /var/tmp TMPDIRs per child.
    """
    import re as _re
    import subprocess as _sp
    import tempfile as _tf
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for b in ("w374_f625_redfirst.py", "w374_f615close_probes.py",
              "w373_f608close_probes.py"):
        tmp = _tf.mkdtemp(prefix="g375-green-", dir="/var/tmp")
        env = dict(os.environ, GOV_DEPLOYMENT_MODE="staging",
                   GOV_SKIP_GREEN="1", TMPDIR=tmp)
        r = _sp.run([venv_python, os.path.join(here, b)],
                    capture_output=True, text=True, timeout=1800,
                    env=env, cwd=repo)
        out = r.stdout + r.stderr
        m = _re.search(r"tally:\s*(\d+)\s*BREAK", out)
        if m is None:
            m = _re.search(r"(\d+) BREAK / \d+ HELD", out)
        good = (r.returncode == 0 and m and m.group(1) == "0")
        notes.append((b, good))
    bad = [b for b, good in notes if not good]
    return ("green" if not bad else "RED",
            "; ".join("%s: %s" % (b, "green" if g else "NOT GREEN")
                      for b, g in notes))


def main():
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green-check skipped (GOV_SKIP_GREEN=1)")
        return 0
    probes = [p1_filed_shapes_held, p2_variants_held,
              p3_fail_closed_boundaries, p4_node_differential,
              p5_compositions, p6_honest_text_quiet, p7_pin_and_footer,
              p8_perf, p9_documented_residuals]
    brk = err = 0
    for p in probes:
        try:
            verdict, msg = p()
        except Exception as e:  # noqa: BLE001
            verdict, msg = "ERROR", "%r" % e
        print("%s: %s -- %s" % (p.__name__, verdict, msg))
        if verdict == "BREAK":
            brk += 1
        elif verdict == "ERROR":
            err += 1
    gc, gcmsg = _green_check()
    print("green-check: %s" % gcmsg)
    print("tally: %d BREAK / %d HELD / %d ERROR"
          % (brk, len(probes) - brk - err, err))
    return 1 if (brk or err or gc == "RED") else 0


if __name__ == "__main__":
    sys.exit(main())
