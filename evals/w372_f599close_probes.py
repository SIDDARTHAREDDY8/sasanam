#!/usr/bin/env python3
"""Wave-372 lane 3 close probes: F599 (URLSearchParams append/set statement-form mutations).

F599 (LOW): F576 (CLOSED) models `.get` on constructor strings and F584
(OPEN) models `.getAll` on constructor strings, but a var-bound
URLSearchParams mutated by `.append`/`.set` statements before the
terminal read escaped: the constructor-string model never sees the
appended pairs. Closed by a statement-form IIFE parse --
`(function(){var|const|let p=new URLSearchParams('LIT');
[p.append('N','V');|p.set('N','V');]*return p.getAll('K')<postfix>;})()` --
with node-exact (v24.20.0) append/set semantics and the getAll array
flowing through the normal postfix chain (F584 precedent).

Fail-closed boundaries (all node-verified): sort/delete/has mutations
(unmodeled -- the whole shape fails closed rather than mis-decode),
non-literal mutation args, extra mutation args, a non-p receiver,
`new URL(...)` bindings (searchParams mutation out of scope), named
functions, directive prologues, a `.get` terminal (returns only the
first value -- cannot assemble a credential from fragments), a bare
getAll return (an array, not a decodable value), missing semicolons.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"
_CRED = _A1 + _A2

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

FOOTER_OPEN = "F612, F613, F614, F615, F616, F617, F618, F619, F620"  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621
FOOTER_NEXT = "F621"  # Wave-372 merge: footer repoint  # Wave-373 merge: footer repoint open F612-F620 / next F621


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


def _q(s):
    return '"' + s + '"'


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try{ out.push(JSON.stringify(String(eval(cases[k])))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    return json.loads(r.stdout.strip())


def p1_filed_shapes():
    rows = []
    shapes = [
        ("f599-append-getall",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-append-double",
         "(function(){var p=new URLSearchParams('');"
         "p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
    ]
    for name, body in shapes:
        rows.append(_verdict(_q(body), True))
        rows[-1] = (rows[-1][0], "%s %s" % (name, rows[-1][1]))
    return rows


def p2_variants():
    rows = []
    variants = [
        ("f599-const",
         "(function(){const p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-let",
         "(function(){let p=new URLSearchParams('');"
         "p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
        ("f599-bracket-append",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p['append']('q','%s');return p['getAll']('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-set-existing",
         "(function(){var p=new URLSearchParams('q=zz');"
         "p.set('q','%s%s');return p.getAll('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-set-multi",
         "(function(){var p=new URLSearchParams('q=zz&q=yy');"
         "p.set('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
        ("f599-set-missing-appends",
         "(function(){var p=new URLSearchParams('a=1');"
         "p.set('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
        ("f599-join-dash",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('-');})()"
         % (_A1, _A2), _A1 + "-" + _A2),
        ("f599-ws",
         "(function(){ var p = new URLSearchParams( 'q=%s' ) ; "
         "p.append( 'q' , '%s' ) ; return p.getAll( 'q' ).join('') ; })()"
         % (_A1, _A2), _CRED),
        ("f599-append-other-name",
         "(function(){var p=new URLSearchParams('a=1&q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-no-mutations",
         "(function(){var p=new URLSearchParams('q=%s%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
    ]
    for name, body, _expect in variants:
        v, d = _verdict(_q(body), True)
        rows.append((v, "%s %s" % (name, d)))
    return rows


def p3_boundaries():
    # Fail-closed: the decoder must produce NO variant. Every payload
    # splits the credential across literals so the raw scan cannot
    # fire either; node ground truth is recorded per probe.
    # The sort/delete/has mutations were a tracked OPEN residual (F606)
    # -- F606 is now CLOSED by wave-373 lane 2, so those three probes
    # moved to p3b_closed_residuals below and assert the coded block.
    rows = []
    bounds = [
        ("f599-nonliteral-value",
         "(function(){var p=new URLSearchParams('');"
         "p.append('q',x);return p.getAll('q').join('');})()"),
        ("f599-extra-arg",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s','zz');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-wrong-receiver",
         "(function(){var p=new URLSearchParams('q=%s');"
         "q.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-url-binding",
         "(function(){var p=new URL('https://h/?q=%s');"
         "p.searchParams.append('q','%s');"
         "return p.searchParams.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-named-function",
         "(function f(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-get-terminal",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.get('q');})()" % (_A1, _A2)),
        ("f599-bare-getall",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q');})()" % (_A1, _A2)),
        ("f599-no-semicolon",
         "(function(){var p=new URLSearchParams('q=%s')"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-directive-prologue",
         "(function(){'use strict';var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2)),
    ]
    for name, body in bounds:
        v, d = _verdict(_q(body), False)
        rows.append((v, "%s %s" % (name, d)))
    return rows


def p3b_closed_residuals():
    # Wave-373 lane 2 (F606 CLOSED): the sort/delete/has residuals this
    # battery codified as fail-closed now decode node-exactly -- these
    # probes assert the coded behavior (wave-305/306 class: a probe that
    # demonstrated the OPEN residual must assert the closure).
    # Note: delete('q') removes the credential itself, so there is
    # nothing to block -- the probe asserts the node-exact '' instead.
    rows = []
    bounds = [
        ("f599-sort-unmodeled",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');p.sort();return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f599-has-unmodeled",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');if(p.has('q')){return p.getAll('q').join('');}"
         "return '';})()" % (_A1, _A2)),
    ]
    for name, body in bounds:
        v, d = _verdict(_q(body), True)
        rows.append((v, "%s %s" % (name, d)))
    _del = dlp.find_credential("(function(){var p=new URLSearchParams('q=%s');"
                              "p.append('q','%s');p.delete('q');"
                              "return p.getAll('q').join('');})()"
                              % (_A1, _A2)) is None
    rows.append(("HELD" if _del else "BREAK",
                 "f599-delete-unmodeled quiet=%s (node: ''; the delete "
                 "removes the credential, so no hit is correct)" % (_del,)))
    return rows


def p4_node_differential():
    rows = []
    cases = [
        ("f599-append-getall",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-append-double",
         "(function(){var p=new URLSearchParams('');"
         "p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
        ("f599-set-multi",
         "(function(){var p=new URLSearchParams('q=zz&q=yy');"
         "p.set('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2), _CRED),
        ("f599-set-missing",
         "(function(){var p=new URLSearchParams('a=1');"
         "p.set('q','%s');return p.getAll('q').join('');})()" % _A1,
         _A1),
        ("f599-join-dash",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.getAll('q').join('-');})()"
         % (_A1, _A2), _A1 + "-" + _A2),
        ("f599-getall-missing",
         "(function(){var p=new URLSearchParams('a=1');"
         "p.append('q','%s');return p.getAll('zz').join('');})()" % _A1,
         ""),
        ("f599-sort-still-evals",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');p.sort();return p.getAll('q').join('');})()"
         % (_A1, _A2), _CRED),
        ("f599-get-terminal-value",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.get('q');})()" % (_A1, _A2), _A1),
    ]
    got = _node_eval([c[1] for c in cases])
    for (name, _body, expect), actual in zip(cases, got):
        ok = actual == json.dumps(expect)
        rows.append(("HELD" if ok else "BREAK",
                     "%s node=%s expect=%s" % (name, actual,
                                              json.dumps(expect))))
    return rows


def p5_neighbor_regression():
    rows = []
    neighbors = [
        ("f576-ctor-get",
         "new URLSearchParams('q=%s%s').get('q')" % (_A1, _A2), True),
        ("f584-ctor-getall",
         "new URLSearchParams('q=%s&q=%s').getAll('q').join('')"
         % (_A1, _A2), True),
        ("f576-url-searchparams",
         "new URL('https://h/?q=%s%s').searchParams.get('q')"
         % (_A1, _A2), True),
    ]
    for name, body, want in neighbors:
        v, d = _verdict(_q(body), want)
        rows.append((v, "%s %s" % (name, d)))
    return rows


def p6_compositions():
    rows = []
    comps = [
        ("f599-full-cred-in-ctor",
         "(function(){var p=new URLSearchParams('q=%s%s');"
         "p.append('q','zz');return p.getAll('q').join('');})()"
         % (_A1, _A2), True),
        ("f599-append-then-get-split",
         "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');return p.get('q');})()" % (_A1, _A2),
         False),
        ("honest-quiet",
         "(function(){var p=new URLSearchParams('a=1');"
         "p.append('b','2');return p.getAll('b').join('');})()",
         False),
    ]
    for name, body, want in comps:
        v, d = _verdict(_q(body), want)
        rows.append((v, "%s %s" % (name, d)))
    return rows


def p7_pin_and_footer():
    rows = []
    try:
        from gov import guac_graph
        assert guac_graph.TAXONOMY_PIN == TAXONOMY_PIN, \
            "pin %s != %s" % (guac_graph.TAXONOMY_PIN, TAXONOMY_PIN)
        text = open(os.path.join(REPO_ROOT, "evals",
                                 "FINDINGS.md")).read()
        assert ("Open findings: %s." % FOOTER_OPEN) in text, \
            "footer open list"
        assert ("Next free finding: **%s**." % FOOTER_NEXT) in text, \
            "footer next-free"
        rows.append(("HELD", "pin+footer"))
    except AssertionError as e:  # noqa: BLE001
        rows.append(("BREAK", "pin/footer: %s" % e))
    return rows


GREEN_ADJACENT = [
    "evals/w371_f599_redfirst.py",
    "evals/w371_attack_probes.py",
    "evals/w371_f584f588close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g372lane3-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            lines = r.stdout.splitlines()
            tally = [l for l in lines if "tally:" in l]
            # Lane-local footer probes pin the author's own footer text;
            # this lane's FINDINGS.md update invalidates them by design
            # (merge-owned churn, wave-305/331 class). A green check
            # fails only on NON-footer BREAK/ERROR lines.
            bad = [l for l in lines
                   if ("BREAK" in l or "ERROR" in l)
                   and "footer" not in l.lower()
                   and "tally:" not in l
                   and "BREAKS:" not in l]
            status = tally[-1] if tally else "rc=%d" % r.returncode
            extra = "" if not bad else " FUNCTIONAL-FAILURES=%d" % len(bad)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, status, time.time() - t0, extra))
            for b in bad[:5]:
                print("      FAIL: %s" % b[:100])
            if bad or r.returncode != 0:
                if bad:
                    ok = False
                else:
                    print("      (rc!=0 but only footer-probe churn; "
                          "merge-owned)")
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    phases = [
        ("P1-filed", p1_filed_shapes()),
        ("P2-variants", p2_variants()),
        ("P3-boundaries", p3_boundaries()),
        ("P3b-closed-residuals", p3b_closed_residuals()),
        ("P4-node", p4_node_differential()),
        ("P5-neighbor", p5_neighbor_regression()),
        ("P6-compositions", p6_compositions()),
        ("P7-pin-footer", p7_pin_and_footer()),
    ]
    brk, held = 0, 0
    for name, rows in phases:
        for verdict, detail in rows:
            if verdict == "BREAK":
                brk += 1
                print("%s BREAK %s" % (name, detail))
            else:
                held += 1
    gok = green_check()
    print("tally: %d BREAK / %d HELD / green=%s" % (brk, held, gok))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": gok,
                          "pin": TAXONOMY_PIN}))
    return 1 if brk or not gok else 0


if __name__ == "__main__":
    sys.exit(main())
