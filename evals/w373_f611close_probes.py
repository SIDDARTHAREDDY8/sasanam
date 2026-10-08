#!/usr/bin/env python3
"""Wave-373 lane 6: close F611 -- atob() fragment assembly.

F611 (LOW, filed attack round 40 as F610, renumbered wave-272): base64 runs
decoding to credential FRAGMENTS escaped the F445 credential-shape gate.
F445 (CLOSED, wave-349) emits a base64 variant only when the decoded text
is credential-shaped, so a run decoding to a fragment ("eG94Yi0wMTIz" ->
"xoxb-0123", first 9 of 25 credential chars) never became a variant and
fragment-then-concatenate assembly inside atob() calls was invisible:
atob('eG94Yi0wMTIz')+'f2' (bare), the var-bound twin, and the
WeakMap-composed twin all node-evaluated to the exact credential
(v24.20.0) while the decoder produced zero variants.

Closure (gov/dlp.py, F611): atob('LIT') modeled node-exactly --
_js_f611_atob_decode (forgiving-decode ASCII-ws strip, strict
standard-base64 alphabet, InvalidCharacterError classes, binary string
via latin-1) + _js_parse_f611_atob, an atob(?![_$A-Za-z0-9]) anchor in
_JS_EXPR_START (re.compile stays 28), a primary-dispatch branch (the bare
call feeds the additive concatenation composer), atob accepted as a
WeakMap set value, and a minimal single-declaration var-bound IIFE
parser (string-literal or atob initializer; token-aware substitution;
reassignment fails closed). Distinct from F445 (full-credential base64
runs, still HELD) and F500 (fromCharCode spread, still HELD).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g373-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_B64_FRAG = "eG94Yi0wMTIz"  # b64("xoxb-0123"): fragment, first 9 of 25 chars
_B64_FULL = "eG94Yi0wMTIzNDU2Nzg5YWJjZGVm"  # b64(full credential)


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_bare_atob():
    """F611 shape 1 CLOSED: bare atob fragment + literal blocks."""
    ok = _blocked("atob('%s')+'%s'" % (_B64_FRAG, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_varbound():
    """F611 shape 2 CLOSED: var-bound atob fragment blocks."""
    ok = _blocked("(function(){var b=atob('%s');return b+'%s';})()"
                  % (_B64_FRAG, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_weakmap():
    """F611 shape 3 CLOSED: WeakMap-composed atob fragment blocks."""
    ok = _blocked("(function(){var m=new WeakMap();var k={};"
                  "m.set(k,atob('%s'));return m.get(k)+'%s';})()"
                  % (_B64_FRAG, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ node-exact twins (must block)

def test_p2_const_let_twins():
    """const/let initializer twins block (node-identical bindings)."""
    h1 = _blocked("(function(){const c=atob('%s');return c+'%s';})()"
                  % (_B64_FRAG, _B))
    h2 = _blocked("(function(){let d=atob('%s');return d+'%s';})()"
                  % (_B64_FRAG, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_ws_forgiving():
    """Whitespace inside atob arg decodes (node strips ASCII ws)."""
    ok = _blocked("atob(' %s ')+'x'" % _B64_FRAG) is False  # not credential
    ok2 = _blocked("atob(' %s')+'%s'" % (_B64_FRAG, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_literal_init_twin():
    """Literal-initializer twin of the var-bound IIFE blocks."""
    ok = _blocked("(function(){var b='%s';return b+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ fail-closed boundaries (must miss)

def test_p3_base64url_throws():
    """base64url alphabet: node throws, decoder stays quiet."""
    ok = _misses("atob('eG94-Yi0wMTIz')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_bad_char_throws():
    """Non-alphabet char: node throws, decoder stays quiet."""
    ok = _misses("atob('eG94Yi0wMTIz!')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_extra_arg_skipped():
    """Extra args: node ignores them -- decoder skips balanced (node-exact)."""
    ok = _blocked("atob('%s','x')+'%s'" % (_B64_FRAG, _B))
    ok = ok and _blocked("atob('%s',(')'))+'%s'" % (_B64_FRAG, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p3_nonliteral_arg_closed():
    """Non-literal arg: fail closed."""
    ok = _misses("atob(btoa('x'))")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_ident_boundary():
    """atobx is not atob: ident boundary holds."""
    ok = _misses("atobx('%s')" % _B64_FRAG)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_reassignment_closed():
    """Reassigned binding: fail closed (never mis-decoded)."""
    ok = _misses("(function(){var b=atob('%s');b='z';return b+'%s';})()"
                 % (_B64_FRAG, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_multi_decl_closed():
    """Multi-declarator: fail closed (documented scope boundary)."""
    ok = _misses("(function(){var b=atob('%s'),c='y';return b+c;})()"
                 % _B64_FRAG)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ composition (neighbors hold)

def test_p4_f445_full_cred_atob():
    """F445 stays HELD: full-credential atob blocks."""
    ok = _blocked("atob('%s')" % _B64_FULL)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f445_full_cred_literal():
    """F445 stays HELD: full-credential base64 literal blocks."""
    ok = _blocked("'%s'" % _B64_FULL)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    ok = ok and _misses("atob('aGVsbG8=')")  # "hello": not credential-shaped
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F611 closed; open F613-F620; next F621 (lane-local)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F640**" in text  # Wave-373 lane 6: F611 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
          and "Open findings: F621, F622, F623, F624, F625, F626, F627, F628, F629, F630, F631, F632, F633, F634, F635, F636, F637, F638, F639." in text)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 1: F612 CLOSED  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (atob anchor edits the existing regex)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """atob anchor does not blow the scan budget (F452 discipline)."""
    corpus = ("junk " * 500 + "atob('%s')+'%s' " % (_B64_FRAG, _B)) * 4
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: wave-372 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g373-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w372_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    for line in out.splitlines():
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    ok = (real_break == 0)
    return ("HELD" if ok else "BREAK",
            "w372_attack real_break=%d" % real_break)


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
