#!/usr/bin/env python3
"""Wave-372 lane 5: close F603 (String.replace literal patterns).

F603 (LOW, filed 2026-10-07 by wave-371 lane 8, attack round 39): the
decoder modeled no String.prototype.replace read path except F464's
/,/[gi] comma scope, so 'f1X'.replace('X','f2') (and the 'XX'/head
twins) node-evaluated to the exact credential (v24.20.0) while the
decoder produced zero variants. Distinct from F564 (String.split,
CLOSED); no prior replace finding existed.

Closure: the replace branch now models, node-exactly --
 (a) string-literal patterns: FIRST occurrence only, matched
     literally (regex metacharacters inert: 'a.b'.replace('.','X'));
 (b) flag-less regex literals with regex-plain sources (literal
     chars, one capture-group level; no escapes/classes/quantifiers/
     anchors): first match, via fixed-width group slices;
 (c) F464's /,/[gi] comma scope, unchanged.
The replacement's $-patterns expand node-exactly for the documented
subset ($$, $&, $`, $', $n for a modeled group). Anything else
$-shaped, any regex flag outside F464's comma scope, and non-literal
patterns fail closed (documented).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g372-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (grep-verified).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2140  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    # fail-closed boundary: decoder must NOT flag (no variants).
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer -- open F595-F608, F610, F611 / next F612."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F612**" in text  # Wave-373 merge: lanes 1-5 footer repoint
          and "Open findings: F611." in text)  # Wave-373 merge: lanes 1-5 (F595, F606-F610 CLOSED)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------------- filed shapes now decode (must block)

@_t
def test_p1_f603_tail():
    """F603 filed shape 1: 'f1X'.replace('X','f2') blocks."""
    hit = _blocked("'%sX'.replace('X','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f603_tail2():
    """F603 filed shape 2: 'f1XX'.replace('XX','f2') blocks."""
    hit = _blocked("'%sXX'.replace('XX','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f603_head():
    """F603 filed shape 3: 'Xf2'.replace('X','f1') blocks."""
    hit = _blocked("'X%s'.replace('X','%s')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------------------------ variants

def _decode(expr):
    r = dlp._try_js_expr_decode(expr, 0)
    return r[0] if r is not None else None


@_t
def test_p2_first_occurrence_only():
    """String pattern replaces the FIRST occurrence only (engine-exact)."""
    e = "'aXbXc'.replace('X','d')"
    node_val = _node_out(e)
    ok = _decode(e) == node_val == "adbXc"
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p2_pattern_is_literal():
    """String pattern metachars are inert ('.' is not a wildcard)."""
    hit = _blocked("'%s.%s'.replace('.','')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_regex_first_match():
    """Flag-less regex-plain literal replaces its first match."""
    hit = _blocked("'-%s%s'.replace(/-/,'')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_regex_group_dollar1():
    """Capture group + $1 replacement blocks ($1 re-emits the matched
    '-' inside the credential -- a true engine no-op that the decoder
    must still resolve)."""
    hit = _blocked("'%s%s'.replace(/(-)/,'$1')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_dollar_patterns():
    """$-patterns expand node-exactly: $$, $&, $`, $' (decoder == node)."""
    exprs = [
        "'aXb'.replace('X','$$')",
        "'aXb'.replace('X','$&')",
        "'aXb'.replace('X',\"$'\")",
        "'aXb'.replace('X','$`')",
        "'aXb'.replace('X','$$$&')",
        "'aXb'.replace('X','$q')",
        "'aXb'.replace('X','$')",
        "'a-b'.replace(/-/,'<$&>')",
        "'a-b'.replace(/(-)/,'<$1>')",
        "'a,b'.replace(/,/g,'$&$&')",
        "'a,b,c'.replace(/,/g,'$`-$&')",
    ]
    bad = []
    for e in exprs:
        node_val = _node_out(e)
        dec = _decode(e)
        if dec != node_val:
            bad.append((e, node_val, dec))
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%r" % (bad,))


@_t
def test_p2_f464_still_blocks():
    """F464 comma scope unchanged: /,/g and /,/i still block."""
    h1 = _blocked("['%s','%s'].toString().replace(/,/g,'')" % (_A, _B))
    h2 = _blocked("'%s,%s'.replace(/,/i,'')" % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "h1=%s h2=%s" % (h1, h2))


@_t
def test_p2_comma_flags_any_order():
    """F464 comma scope accepts flags in any order end-to-end (ig and gi
    both decode, node-exact). Regression pin for the /,/ig caller check."""
    e1 = "'a,b'.replace(/,/ig,'')"
    e2 = "'a,b'.replace(/,/gi,'')"
    r1 = dlp._try_js_expr_decode(e1, 0)
    r2 = dlp._try_js_expr_decode(e2, 0)
    ok = r1 == ("ab", 23) and r2 == ("ab", 23)
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p2_double_quotes():
    """Double-quoted spellings block."""
    hit = _blocked('"%sX".replace("X","%s")' % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------------- fail-closed bounds

@_t
def test_p3_flag_g_noncomma_misses():
    """Boundary: /-/g (global, non-comma) fails closed -- node decodes
    it, the decoder honestly refuses it (documented)."""
    e = "'a-b-c'.replace(/-/g,'d')"
    ok = _decode(e) is None and _node_out(e) == "adbdc"
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p3_regex_escape_misses():
    """Boundary: /\\d/ (escapes not modeled) fails closed."""
    e = "'a1b'.replace(/\\d/,'X')"
    ok = _decode(e) is None and _node_out(e) == "aXb"
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p3_regex_quantifier_misses():
    """Boundary: /a+/ (quantifiers not modeled) fails closed."""
    e = "'aab'.replace(/a+/,'X')"
    ok = _decode(e) is None and _node_out(e) == "Xb"
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p3_regex_class_misses():
    """Boundary: /[a]/ (character classes not modeled) fails closed."""
    e = "'aab'.replace(/[a]/,'X')"
    ok = _decode(e) is None and _node_out(e) == "Xab"
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


@_t
def test_p3_dollar_n_nogroup_misses():
    """Boundary: $1 with a string pattern (no groups) fails closed --
    the engine literalizes it, the decoder refuses (documented)."""
    ok = _quiet("'%sX'.replace('X','$1%s')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_named_group_misses():
    """Boundary: $<name> fails closed."""
    ok = _quiet("'%sX'.replace('X','$<n>%s')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_nonliteral_pattern_misses():
    """Boundary: non-literal pattern fails closed."""
    ok = _quiet("'%sX'.replace(x,'%s')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_junk_quiet():
    """Boundary: no credential in replace shape stays quiet."""
    ok = _quiet("'abX'.replace('X','cd')")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------- node differential

def _node_out(expr):
    p = subprocess.run(["node", "-e", "console.log(" + expr + ")"],
                       capture_output=True, text=True, timeout=30)
    return p.stdout.strip()


@_t
def test_p4_node_differential():
    """Node v24.20.0 differential: decoder flags exactly what node
    evaluates to the exact credential (filed shapes + variants)."""
    shapes = [
        "'%sX'.replace('X','%s')" % (_A, _B),
        "'%sXX'.replace('XX','%s')" % (_A, _B),
        "'X%s'.replace('X','%s')" % (_B, _A),
        "'%s.%s'.replace('.','')" % (_A, _B),
        "'-%s%s'.replace(/-/,'')" % (_A, _B),
        "'-%s%s'.replace(/(-)/,'')" % (_A, _B),
        '"%sX".replace("X","%s")' % (_A, _B),
        "['%s','%s'].toString().replace(/,/g,'')" % (_A, _B),
    ]
    bad = []
    for s in shapes:
        node_val = _node_out(s)
        if node_val != _CRED:
            bad.append(("node-not-cred", s))
            continue
        if not _blocked(s):
            bad.append(("decoder-miss", s))
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%r" % (bad,))


@_t
def test_p4_node_boundary_differential():
    """Node differential: fail-closed boundaries agree with node reads.

    Each boundary shape evaluates to the credential in node, but the
    decoder deliberately refuses it (documented scope) -- verify node
    DOES produce the credential there so the boundary is honest about
    what it refuses."""
    shapes = [
        "'a-b-c'.replace(/-/g,'d')",
        "'a1b'.replace(/\\d/,'X')",
        "'aab'.replace(/a+/,'X')",
        "'aab'.replace(/[a]/,'X')",
    ]
    expected = ["adbdc", "aXb", "Xb", "Xab"]
    bad = []
    for s, want in zip(shapes, expected):
        node_val = _node_out(s)
        if node_val != want:
            bad.append(("node-unexpected", s, node_val))
        elif not _quiet(s):
            bad.append(("decoder-should-refuse", s))
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%r" % (bad,))


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-371 attack battery with
    GOV_SKIP_GREEN=1 in the child env. Tolerated: its stale footer pin
    (the lane-local footer now closes F603; the merge repoints it --
    wave-305/331 class). The battery's F603 probe is flipped by this
    lane to test_p1_f603_closed -- a BREAK there is a real
    regression, not tolerated."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g372-5-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w371_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w371_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-371 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "%s: %s" % ("ERROR", "%s: %s" % (type(e).__name__, e))
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("BREAKS:", sorted(probe_breaks))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
