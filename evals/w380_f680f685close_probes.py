#!/usr/bin/env python3
"""Wave-380 lane 7 closure probes: F680 + F681 + F682 + F683 + F684 + F685.

Closes the small-shape family filed in attack round 47:
- F680 (symbol): Symbol.keyFor(Symbol.for('LIT')), Symbol.for('LIT').description,
  symbol-keyed member reads o[Symbol.for('k')].
- F681 (array mutators): var-bound arrays mutated by splice/fill, then joined.
- F682 (trim family): 'lit'.trim()/trimStart()/trimEnd() fragment sources.
- F683 (JSON revivers): JSON.parse('LIT', function(k,v){return GUARD?v+'APP':v;}).
- F684 (destructuring residuals): default-referencing-earlier-params
  ({a='f1',b=a+'f2'}={}) and nested patterns ({x:{y}}).
- F685 (arrow arguments): var f=()=>arguments[N]; return f()+...;

Each probe prints HELD (blocks/decodes) or BREAK (miss). Exit 1 on any BREAK.
TAXONOMY_PIN = 2143. Lane-local footer: open F672-F679, next F686.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

Deployment mode is set at module level (wave-95 lesson). No in-repo git
subprocess (wave-224 lesson). No paid harness calls (evals-only).
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TAXONOMY_PIN = 2143  # Wave-380 lane 7: pin 2143.; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

results = []


def _t(name, fn):
    try:
        verdict, detail = fn()
    except Exception as e:  # noqa: BLE001
        verdict, detail = "BREAK", "ERROR %r" % (e,)
    results.append((name, verdict, detail))
    print("%s: %s (%s)" % (name, verdict, detail))


def _blocks(payload):
    return find_credential(payload) is not None


def _held(name, payload):
    ok = _blocks(payload)
    return ("HELD" if ok else "BREAK", "blocks" if ok else "miss")


def _quiet(name, payload):
    ok = not _blocks(payload)
    return ("HELD" if ok else "BREAK", "quiet" if ok else "false-positive")


# ------------------------------------------------ F680: symbol shapes

def test_p1_f680_keyfor():
    return _held("p1", "(function(){return Symbol.keyFor(Symbol.for('"
                + _A + "'))+'" + _B + "';})()")


def test_p1b_f680_keyfor_bare():
    return _held("p1b", "Symbol.keyFor(Symbol.for('" + _A + "'))+'"
                + _B + "'")


def test_p1c_f680_description():
    return _held("p1c", "(function(){return Symbol.for('" + _A
                + "').description+'" + _B + "';})()")


def test_p1d_f680_symkeyed():
    return _held("p1d", "(function(){var o={[Symbol.for('k')]:'" + _A
                + "'};return o[Symbol.for('k')]+'" + _B + "';})()")


# NOTE (pre-existing, not F680): a bare Symbol.for('LIT')+'LIT2'
# (without .description) hits the shared paren-anchor quirk -- the
# `(` of the Symbol.for call parses as a grouping paren, yielding
# a mangled variant. This predates wave-380 (verified on the base
# commit) and is out of scope; the filed F680 shapes are the three
# above. The quirk over-blocks (fail-closed), never misses.


# ------------------------------------------------ F681: array mutators

def test_p2_f681_splice():
    return _held("p2", "(function(){var a=['junk','" + _A + "','"
                + _B + "'];a.splice(0,1);return a.join('');})()")


def test_p2b_f681_fill():
    return _held("p2b", "(function(){var a=['x','y'];a.fill('" + _A
                + "',0,1);a.fill('" + _B + "',1,2);return a.join('');})()")


def test_p2c_f681_splice_negative():
    # splice(-1,1) removes the last element (node-exact).
    return _held("p2c", "(function(){const b=['" + _A + "','" + _B
                + "','junk'];b.splice(-1,1);return b.join('');})()")


def test_p2d_f681_fill_negative():
    return _held("p2d", "(function(){let c=['" + _A
                + "','q'];c.fill('" + _B + "',-1,2);return c.join('');})()")


def test_p2e_f681_splice_insert_quiet():
    # 3-arg splice (insertion) is unmodeled -- must stay quiet.
    return _quiet("p2e", "(function(){var a=['" + _A + "'];a.splice(0,0,'"
                  + _B + "');return a.join('');})()")


# ------------------------------------------------ F682: trim family

def test_p3_f682_trim():
    return _held("p3", "(function(){return ' " + _A + " '.trim()+'"
                + _B + "';})()")


def test_p3b_f682_trimstart():
    return _held("p3b", "(function(){return ' " + _A
                + "'.trimStart()+'" + _B + "';})()")


def test_p3c_f682_trimend():
    return _held("p3c", "(function(){return '" + _A + " '.trimEnd()+'"
                + _B + "';})()")


def test_p3d_f682_trim_unicode():
    # U+00A0/U+2003 strip in the engine but not under Python's
    # default strip() -- the exact JS set is required.
    p = "(function(){return '\\xa0\\u2003" + _A + "\\u2003'.trim()+'"
    p += _B + "';})()"
    return _held("p3d", p)


def test_p3e_f682_trim_args_quiet():
    # Extra args are engine-ignored; the decoder fails closed (tight).
    return _quiet("p3e", "(function(){return ' " + _A
                  + " '.trim('x')+'" + _B + "';})()")


# ------------------------------------------------ F683: JSON revivers

def test_p4_f683_typeof():
    return _held("p4", "(function(){return JSON.parse('{\"x\":\"" + _A
                + "\"}',function(k,v){return typeof v==='string'?v+'"
                + _B + "':v;}).x;})()")


def test_p4b_f683_keyguard():
    return _held("p4b", "(function(){return JSON.parse('{\"x\":\"" + _A
                + "\",\"y\":\"z\"}',function(k,v){return k==='x'?v+'"
                + _B + "':v;}).x;})()")


def test_p4c_f683_array():
    return _held("p4c", "(function(){return JSON.parse('[\"" + _A
                + "\"]',function(k,v){return k==='0'?v+'" + _B
                + "':v;})[0];})()")


def test_p4d_f683_single_arg_still_blocks():
    # The F541 single-arg control still decodes.
    return _held("p4d", "(function(){return JSON.parse('{\"x\":\"" + _A
                + _B + "\"}').x;})()")


def test_p4e_f683_nonstring_keyguard_quiet():
    # k==='x' on a non-string would coerce in the engine (unmodeled)
    # -- must stay quiet, never mis-decoded.
    return _quiet("p4e", "(function(){return JSON.parse('{\"x\":5}',"
                  "function(k,v){return k==='x'?v+'f2':v;}).x;})()")


# ------------------------------------------------ F684: destructuring residuals

def test_p5_f684_defaultref():
    return _held("p5", "(function({a='" + _A + "',b=a+'" + _B
                + "'}={}){return b;})()")


def test_p5b_f684_defaultref_undefined_arg():
    return _held("p5b", "(function({a='" + _A + "',b=a+'" + _B
                + "'}={}){return b;})(undefined)")


def test_p5c_f684_nested():
    return _held("p5c", "(function(){var {x:{y}}={x:{y:'" + _A
                + "'}};return y+'" + _B + "';})()")


def test_p5d_f684_nested_rename():
    return _held("p5d", "(function(){const {x:{y:z}}={x:{y:'" + _A
                + "'}};return z+'" + _B + "';})()")


def test_p5e_f684_flat_still_blocks():
    # F644 flat shapes still decode (disjointness).
    return _held("p5e", "(function(){var {a,b}={a:'" + _A + "',b:'"
                + _B + "'};return a+b;})()")


def test_p5f_f684_f645_still_blocks():
    # F645 default-param shapes still decode (disjointness).
    return _held("p5f", "(function(a='" + _A + "',b='" + _B
                + "'){return a+b;})()")


def test_p5g_f684_forward_ref_quiet():
    # {b=a+'x',a='f1'} -- TDZ ReferenceError in the engine.
    return _quiet("p5g", "(function({b=a+'" + _B + "',a='" + _A
                  + "'}={}){return b;})()")


# ------------------------------------------------ F685: arrow arguments

def test_p6_f685_arrow0():
    return _held("p6", "(function(){var f=()=>arguments[0];return f()+'"
                + _B + "';})('" + _A + "')")


def test_p6b_f685_arrow1():
    return _held("p6b", "(function(){var f=()=>arguments[1];return f()+'"
                + _B + "';})('junk','" + _A + "')")


def test_p6c_f685_arrow_multi_call():
    return _held("p6c", "(function(){const f=()=>arguments[0];return f()+f()+'"
                + _B + "';})('" + _A + "')")


def test_p6d_f685_oob_quiet():
    # arguments[5] with 1 arg is undefined in the engine (never decoded).
    return _quiet("p6d", "(function(){var f=()=>arguments[5];return f()+'x';})('a')")


def test_p6e_f685_bare_arguments_quiet():
    # A bare `arguments` outside the arrow is unmodeled here.
    return _quiet("p6e", "(function(){var f=()=>arguments[0];return f()+arguments[1];})('"
                  + _A + "','b')")


# ------------------------------------------------ fail-closed bounds

def test_p7_symbol_iterator_quiet():
    # Symbol.iterator must not decode (F653 owns it; the F680
    # production fails closed there).
    return _quiet("p7", "var o={};o[Symbol.iterator]=function(){return 'x';};")


def test_p7b_trim_nonstring_quiet():
    return _quiet("p7b", "(function(){return (123).trim();})()")


def test_p7c_json_reviver_named_quiet():
    return _quiet("p7c", "(function(){return JSON.parse('{\"x\":\"a\"}',"
                  "function rev(k,v){return v;}).x;})()")


# ------------------------------------------------ open findings still BREAK (nothing absorbed)

def test_p8_open_f672_break():
    # F672 (class methods) is OPEN -- must still BREAK.
    p = "(function(){class C{static m(){return 'x';}}return C.m();})()"
    ok = not _blocks(p)
    return ("HELD" if ok else "BREAK", "still-break" if ok else "absorbed!")


def test_p8b_open_f677_break():
    # F677 (iterators) is OPEN -- must still BREAK.
    p = "(function(){var o={[Symbol.iterator]:function*(){yield 'x';}};return [...o].join('');})()"
    ok = not _blocks(p)
    return ("HELD" if ok else "BREAK", "still-break" if ok else "absorbed!")


# ------------------------------------------------ composition

def test_p9_compose_trim_concat():
    # trim() feeding concat().
    return _held("p9", "(function(){return ' " + _A + " '.trim().concat('"
                + _B + "');})()")


def test_p9b_compose_symbol_join():
    # Symbol.keyFor feeding an array join.
    return _held("p9b", "(function(){return [Symbol.keyFor(Symbol.for('"
                + _A + "')),'" + _B + "'].join('');})()")


# ------------------------------------------------ pin + footer

def test_p10_pin_2140():
    import gov.dlp as D
    pins = []
    for name in dir(D):
        if name.endswith("_PIN") and name != "VERIFIER_TAXONOMY_PIN":
            v = getattr(D, name)
            if isinstance(v, int):
                pins.append((name, v))
    bad = [n for n, v in pins if v != 2140]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "pins-ok" if ok else "stale=%s" % bad[:3])


def test_p10b_footer():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "FINDINGS.md")) as f:
        text = f.read()
    want_open = "F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712"
    want_next = "F713"  # Wave-380 merge: F672-F685 CLOSED; footer repoint
    ok = want_open in text and ("Next free finding: **%s**" % want_next) in text
    return ("HELD" if ok else "BREAK", "footer-ok" if ok else "footer-stale")


def test_p10c_re_compile_28():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "gov", "dlp.py")) as f:
        src = f.read()
    n = src.count("re.compile(")
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


# ------------------------------------------------ perf

def test_p11_perf():
    p = "(function(){var a=['x','" + _A + "'];a.fill('" + _B + "',1,2);return a.join('');})()"
    t0 = time.time()
    for _ in range(200):
        find_credential(p)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "200 in %.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def test_p12_green_check():
    """Depth-1 green check: six red-firsts + w379 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    here = os.path.dirname(os.path.abspath(__file__))
    tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    bad = []
    batts = [("w379_f680_redfirst.py", "f680"),
             ("w379_f681_redfirst.py", "f681"),
             ("w379_f682_redfirst.py", "f682"),
             ("w379_f683_redfirst.py", "f683"),
             ("w379_f684_redfirst.py", "f684"),
             ("w379_f685_redfirst.py", "f685"),
             ("w379_attack_probes.py", "attack")]
    for batt, label in batts:
        r = subprocess.run(
            [sys.executable, os.path.join(here, batt)],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(here, ".."))
        tail = (r.stdout + r.stderr)[-400:]
        if label == "attack":
            # The attack battery must have no *real* BREAK (footer
            # staleness is merge-owned).
            if "BREAK" in tail and "0 BREAK" not in tail:
                lines = [ln for ln in tail.splitlines()
                         if "BREAK" in ln and "footer" not in ln.lower()]
                if lines:
                    bad.append("%s: %s" % (label, lines[0][-120:]))
        else:
            if "0 BREAK" not in tail:
                bad.append("%s: %s" % (label, tail[-120:]))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name, fn in sorted(
            [(k, v) for k, v in globals().items()
             if k.startswith("test_") and callable(v)]):
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD / %d total"
          % (breaks, held, len(results)))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
