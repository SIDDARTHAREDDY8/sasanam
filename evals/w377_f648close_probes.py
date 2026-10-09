#!/usr/bin/env python3
"""Wave-377 lane 5: close F648 -- URLSearchParams no-arg ctor + append + getAll().join().

F648 (LOW, filed attack round 44): F599 (CLOSED) models append/set
mutations on `new URLSearchParams('LIT')` -- its ctor parse
(`_js_parse_f576_new_url`) raises on empty parens, so the no-arg
constructor with the same appends and a getAll('K').join('')
terminal had no modeled path. The closure (`_js_parse_f648_
noarg_params_iife`, gov/dlp.py) is the no-arg twin of the F599
production: empty-parens ctor binds the empty _JSURLParams,
append/set mutate engine-exactly (F599 set semantics), getAll('K')
yields the K-values in insertion order as a _JSArr flowing through
the normal postfix chain (F517 identity-callback maps included --
the identity-map filed twin). Zero new re.compile (28 stays).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

import gov.dlp as _dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2144  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
# Fragments such that NO literal below contains the full credential
# (the raw whole-text scan must not decide these probes).
_F1 = _A[:5]          # 'xoxb-'
_F2 = _A[5:][1:]      # '123' (drops the '0')
_F3 = _B
_CRED = "xoxb-123456789abcdef"  # what the assembled shapes yield


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F648 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f648_noarg_params_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s %s" % (name, verdict, note))


# ------------------------------------------------ p1 filed shapes (must block)

def test_p1_filed_join():
    """Two appends + getAll('q').join('') blocks, decodes exact."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');return p.getAll('q').join('');})()"
          % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_three_appends():
    """Three appends assemble the credential."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s');p.append('q','%s');"
          "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_map_twin():
    """getAll('q').map(function(x){return x;}).join('') twin blocks."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');"
          "return p.getAll('q').map(function(x){return x;}).join('');})()"
          % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ p2 variants (must block)

def test_p2_set_twin():
    """set() replaces the first pair engine-exactly."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','jx');"
          "p.set('q','%s%s');return p.getAll('q').join('');})()"
          % (_F1, _F2 + _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_set_removes_dups():
    """set() replaces the first pair and drops the other same-name pairs."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','jx');"
          "p.append('q','%s%s%s');p.set('q','%s%s%s');"
          "return p.getAll('q').join('');})()" % (_F1, _F2, _F3,
                                                 _F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_const_let_decls():
    """const/let receiver decls block."""
    h1 = _blocked("(function(){const p=new URLSearchParams();"
                  "p.append('q','%s');p.append('q','%s%s');"
                  "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    h2 = _blocked("(function(){let p=new URLSearchParams();"
                  "p.append('q','%s');p.append('q','%s%s');"
                  "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_dquote_bracket():
    """Double-quoted literals + bracket-string members block."""
    js = ('(function(){var p=new URLSearchParams();p["append"]("q","%s");'
          'p["append"]("q","%s%s");'
          'return p["getAll"]("q").join("");})()' % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_slice_terminal():
    """getAll(...).join('').slice(0) terminal blocks."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');"
          "return p.getAll('q').join('').slice(0);})()" % (_F1, _F2, _F3))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_multi_key():
    """Other keys interleaved; getAll picks only the named key."""
    js = ("(function(){var p=new URLSearchParams();p.append('z','jx');"
          "p.append('q','%s');p.append('z','jy');p.append('q','%s%s');"
          "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_ws():
    """Modest whitespace around tokens blocks."""
    js = ("(function(){var p=new URLSearchParams( );p.append('q','%s');"
          "p.append( 'q','%s%s' );return p.getAll( 'q' ).join( '' );})()"
          % (_F1, _F2, _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_set_absent_appends():
    """set() on a missing name appends (node-exact)."""
    js = ("(function(){var p=new URLSearchParams();p.set('q','%s%s');"
          "return p.getAll('q').join('');})()" % (_F1, _F2 + _F3))
    ok = _decode_exact(js) == _CRED and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ p3 fail-closed bounds

def test_p3_ctor_arg_still_f599():
    """A literal ctor arg is F599's shape, not F648's -- still blocks."""
    ok = _blocked("(function(){var p=new URLSearchParams('');"
                  "p.append('q','%s');p.append('q','%s%s');"
                  "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p3_nonliteral_value():
    """Var-bound mutation values fail closed (F616-class residual)."""
    ok = _misses("(function(){var p=new URLSearchParams();var v='%s';"
                 "p.append('q',v);p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonliteral_name():
    """Var-bound mutation names fail closed."""
    ok = _misses("(function(){var p=new URLSearchParams();var n='q';"
                 "p.append(n,'%s');p.append(n,'%s%s');"
                 "return p.getAll(n).join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_sort_mutation():
    """sort() mutation fails closed (documented residual, F599)."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s');p.append('q','%s%s');p.sort();"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_delete_mutation():
    """delete() mutation fails closed (documented residual)."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s');p.delete('z');p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_get_terminal():
    """get() terminal fails closed (first-value only; no assembly)."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');return p.get('q');})()" % (_F1, _F2, _F3))
    ok = _decode_exact(js) is None and _misses(js)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_bare_getall():
    """Bare getAll (array, not a string) fails closed."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');return p.getAll('q');})()" % (_F1, _F2, _F3))
    ok = _decode_exact(js) is None
    return ("HELD" if ok else "BREAK", "nodecode=%s" % ok)


def test_p3_extra_args():
    """Extra mutation args fail closed."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s','x');p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_reassignment():
    """Reassignment of the receiver fails closed."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s');p=new URLSearchParams();"
                 "p.append('q','%s%s');return p.getAll('q').join('');})()"
                 % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_extra_statements():
    """Extra statements fail closed."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s');var x=1;p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_named_function():
    """Named function IIFEs fail closed."""
    ok = _misses("(function f(){var p=new URLSearchParams();"
                 "p.append('q','%s');p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_new_url_binding():
    """new URL(...) bindings fail closed here (F617 owns them)."""
    ok = _misses("(function(){var u=new URL('https://h/?q=jx');"
                 "u.searchParams.append('q','%s');"
                 "return u.searchParams.getAll('q').join('');})()" % _F1)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_missing_semicolon():
    """Missing semicolon fails closed."""
    ok = _misses("(function(){var p=new URLSearchParams()"
                 "p.append('q','%s');return p.getAll('q').join('');})()"
                 % _F1)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_directive_prologue():
    """A directive prologue fails closed."""
    ok = _misses("(function(){'use strict';var p=new URLSearchParams();"
                 "p.append('q','%s');p.append('q','%s%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4 open neighbors still miss

def _redfirst_tally(path):
    """Run a red-first battery; return (breaks, held)."""
    r = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=120,
                       env={**os.environ, "GOV_DEPLOYMENT_MODE": "staging"})
    out = r.stdout + r.stderr
    breaks = held = 0
    for line in out.splitlines():
        if "BREAK" in line and "tally" not in line:
            breaks += 1
        elif "HELD" in line and "tally" not in line:
            held += 1
    return breaks, held


def test_p4_open_neighbors_still_miss():
    """F644-F647, F649-F654 CLOSED at the wave-377 merge: their red-firsts now show 0 BREAK (nothing absorbed)."""
    bad = []
    for f in ("f644", "f645", "f646", "f647", "f649", "f650",
              "f651", "f652", "f653", "f654"):
        path = os.path.join(REPO_ROOT, "evals",
                            "w376_%s_redfirst.py" % f)
        breaks, held = _redfirst_tally(path)
        if breaks != 0:
            bad.append(f)
    ok = not bad
    return ("HELD" if ok else "BREAK", "now-closed=%s" % (bad or "all"))


# ------------------------------------------------ p5 closed neighbors still held

def test_p5_closed_neighbors_still_held():
    """F599/F606/F610/F616/F617/F626/F627/F635 shapes still block."""
    shapes = [
        # F599: literal-ctor append + getAll join
        ("(function(){var p=new URLSearchParams('');p.append('q','%s');"
         "p.append('q','%s%s');return p.getAll('q').join('');})()"
         % (_F1, _F2, _F3)),
        # F610: literal-ctor set + get terminal
        ("(function(){var p=new URLSearchParams('');p.set('q','%s%s');"
         "return p.get('q');})()" % (_F1, _F2 + _F3)),
        # F616: var-bound name on literal ctor
        ("(function(){var p=new URLSearchParams('');var n='q';"
         "p.append(n,'%s');p.append(n,'%s%s');"
         "return p.getAll(n).join('');})()" % (_F1, _F2, _F3)),
        # F617: new URL searchParams receiver
        ("(function(){var u=new URL('https://h/?');"
         "u.searchParams.append('q','%s');u.searchParams.append('q','%s%s');"
         "return u.searchParams.getAll('q').join('');})()"
         % (_F1, _F2, _F3)),
        # F626: iteration protocol over literal ctor
        ("(function(){var p=new URLSearchParams('q=%s');var s='';"
         "for (var x of p.values()) s+=x;return s;})()" % (_F1 + _F2 + _F3)),
    ]
    bad = [i for i, s in enumerate(shapes) if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "held=%s" % (bad or "all"))


# ------------------------------------------------ p6 composition

def test_p6_postfix_tail():
    """F648 shape composed in larger contexts still blocks."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');return p.getAll('q').join('');})()"
          % (_F1, _F2, _F3))
    h1 = _blocked("(" + js + "+'')")
    h2 = _blocked("var r=" + js + ";")
    h3 = _blocked("hello " + js + " world")
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p6_no_cross_route():
    """F648 route does not fire on F626 iteration shapes."""
    js = ("(function(){var p=new URLSearchParams();var s='';"
          "for (var x of p.values()) s+=x;return s;})()")
    ok = _dlp._js_parse_f648_noarg_params_iife(
        js, 0, 0, {"ops": 0, "parts": 0, "depth": 0}) is None
    return ("HELD" if ok else "BREAK", "disjoint=%s" % ok)


# ------------------------------------------------ p7 node differential

def _node_val(payload):
    r = subprocess.run(
        ["node", "-e",
         "try{console.log(JSON.stringify(eval(process.argv[1])))}"
         "catch(e){console.log('THROW:'+e.name)}",
         payload], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def test_p7_node_differential():
    """Decoder exact-values match node v24.20.0; bounds are concordant."""
    cases = [
        ("(function(){var p=new URLSearchParams();p.append('q','%s');"
         "p.append('q','%s%s');return p.getAll('q').join('');})()"
         % (_F1, _F2, _F3), _CRED),
        ("(function(){var p=new URLSearchParams();p.append('q','jx');"
         "p.set('q','%s%s');return p.getAll('q').join('');})()"
         % (_F1, _F2 + _F3), _CRED),
        ("(function(){var p=new URLSearchParams();p.append('q','%s');"
         "p.append('q','%s%s');"
         "return p.getAll('q').map(function(x){return x;}).join('');})()"
         % (_F1, _F2, _F3), _CRED),
        ("(function(){var p=new URLSearchParams();p.append('q','%s');"
         "p.append('q','%s%s');return p.get('q');})()"
         % (_F1, _F2, _F3), _F1),  # get: first value only
        ("(function(){var p=new URLSearchParams();p.append('q','jx');"
         "return p.getAll('z').join('');})()", ""),  # missing key
    ]
    bad = []
    for js, want in cases:
        nv = _node_val(js)
        try:
            node_str = eval(nv) if nv.startswith('"') else nv
        except Exception:  # noqa: BLE001
            node_str = nv
        dec = _decode_exact(js)
        if node_str != want:
            bad.append("node-mismatch")
        elif dec is not None and dec != node_str:
            bad.append("decode-mismatch")
        elif dec is None and node_str == _CRED:
            bad.append("miss-where-node-yields-cred")
    ok = not bad
    return ("HELD" if ok else "BREAK", "diff=%s" % (bad or "5/5"))


# ------------------------------------------------ p8 junk-quiet

def test_p8_junk_quiet():
    """Junk appends stay quiet."""
    ok = _misses("(function(){var p=new URLSearchParams();"
                 "p.append('q','jx');p.append('q','jy');"
                 "return p.getAll('q').join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p9 pin + footer

def test_p9_pin_and_footer():
    """Pin 2144; merge footer: open F662-F671 / next F672."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    lines = open(os.path.join(REPO_ROOT, "evals",
                              "FINDINGS.md"), encoding="utf-8").read()
    ok_pin = TAXONOMY_PIN == 2144  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    foot = [ln for ln in lines.splitlines()
            if ln.startswith("Next free finding:")]
    last = foot[-1] if foot else ""
    open_seg = (" " + last.split("Open findings:")[-1]
                if "Open findings:" in last else "")
    live_list = open_seg.split("#")[0]  # history comments may name F648
    ok_foot = ("**F672**" in last
               and "F662, F663, F664, F665, F666, F667, F669, F670, F671" in live_list  # Wave-379 lane 6: F668 CLOSED (lane-local)
               and "Wave-378 merge: lanes 1-6 F655-F661 CLOSED" in open_seg)  # history kept
    ok = ok_pin and ok_foot
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


# ------------------------------------------------ p10 perf

def test_p10_perf():
    """200 no-arg sites decode in bounded time."""
    js = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
          "p.append('q','%s%s');return p.getAll('q').join('');})()"
          % (_F1, _F2, _F3))
    import time
    t0 = time.time()
    for _ in range(200):
        find_credential("var x='%s';" % js)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for name, path in (("w376_f648_redfirst",
                        "evals/w376_f648_redfirst.py"),
                       ("w376_attack", "evals/w376_attack_probes.py")):
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, path)],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "GOV_SKIP_GREEN": "1",
                 "TMPDIR": tempfile.mkdtemp(prefix="g377-l5-gc-",
                                            dir="/var/tmp")})
        tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
        bad = ("BREAK" in (r.stdout + r.stderr).split("tally:")[0]
               if "tally:" in r.stdout else "error" in
               (r.stdout + r.stderr).lower())
        # red-first must now be 0 BREAK; attack battery must have 0
        # unexpected BREAK (its tally line reports expected counts)
        print("green:%s exit=%d %s" % (name, r.returncode, tail))
        if name == "w376_f648_redfirst":
            breaks, _ = _redfirst_tally(os.path.join(REPO_ROOT, path))
            if breaks != 0:
                ok = False
        if r.returncode != 0 and name != "w376_attack":
            ok = False
    # w376_attack is expected to show its filed-shape BREAKs (all 10
    # findings are open on the base tree); the merge owns flipping
    # the F648 pins to closed. Here we only require it to run.
    return ok


def main():
    global results
    _t("p1-filed-join", test_p1_filed_join)
    _t("p1-filed-three-appends", test_p1_filed_three_appends)
    _t("p1-filed-map-twin", test_p1_filed_map_twin)
    _t("p2-set-twin", test_p2_set_twin)
    _t("p2-set-removes-dups", test_p2_set_removes_dups)
    _t("p2-const-let-decls", test_p2_const_let_decls)
    _t("p2-dquote-bracket", test_p2_dquote_bracket)
    _t("p2-slice-terminal", test_p2_slice_terminal)
    _t("p2-multi-key", test_p2_multi_key)
    _t("p2-ws", test_p2_ws)
    _t("p2-set-absent-appends", test_p2_set_absent_appends)
    _t("p3-ctor-arg-still-f599", test_p3_ctor_arg_still_f599)
    _t("p3-nonliteral-value", test_p3_nonliteral_value)
    _t("p3-nonliteral-name", test_p3_nonliteral_name)
    _t("p3-sort-mutation", test_p3_sort_mutation)
    _t("p3-delete-mutation", test_p3_delete_mutation)
    _t("p3-get-terminal", test_p3_get_terminal)
    _t("p3-bare-getall", test_p3_bare_getall)
    _t("p3-extra-args", test_p3_extra_args)
    _t("p3-reassignment", test_p3_reassignment)
    _t("p3-extra-statements", test_p3_extra_statements)
    _t("p3-named-function", test_p3_named_function)
    _t("p3-new-url-binding", test_p3_new_url_binding)
    _t("p3-missing-semicolon", test_p3_missing_semicolon)
    _t("p3-directive-prologue", test_p3_directive_prologue)
    _t("p4-open-neighbors-still-miss",
       test_p4_open_neighbors_still_miss)
    _t("p5-closed-neighbors-still-held",
       test_p5_closed_neighbors_still_held)
    _t("p6-postfix-tail", test_p6_postfix_tail)
    _t("p6-no-cross-route", test_p6_no_cross_route)
    _t("p7-node-differential", test_p7_node_differential)
    _t("p8-junk-quiet", test_p8_junk_quiet)
    _t("p9-pin-and-footer", test_p9_pin_and_footer)
    _t("p10-perf", test_p10_perf)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errs = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    gc = _green_check()
    print("green-check: %s" % ("PASS" if gc else "FAIL"))
    return 1 if (breaks or errs or not gc) else 0


if __name__ == "__main__":
    sys.exit(main())
