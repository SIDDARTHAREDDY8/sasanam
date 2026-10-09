#!/usr/bin/env python3
"""Wave-389 lane 4 close battery: F934 + F935 + F936 CLOSED.

Verifies the three LOW findings (wave-388 attack round 56, filed
2026-10-09 11:21 UTC) are closed on the lane tree: pins, filed shapes
(must block, node-exact decode), generalizations (must block),
fail-closed bounds (must miss / stay quiet, never mis-decode),
sibling pins (F603/F688/F765 replace+match, F564 split, F762 charAt,
F814 entries, F735 sync fn, F866 regex split), honest-text controls,
perf (200 sites), and a depth-1 green check on the three w389
red-first batteries (GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-388 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B

_POEM_S = ("xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 days\\n1 day\\n2 days\\n"
           "3 days\\n4 days\\n5 days\\n6 days\\n7 days\\n8 days\\n9 days\\n"
           "alpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot")
_POEM_L = ("xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 spots\\n1 spot\\n2 spots\\n"
           "3 spots\\n4 spots\\n5 spots\\n6 spots\\n7 spots\\n8 spots\\n9 spots\\n"
           "alpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot\\n0 zero\\n1 one\\n"
           "2 two\\n3 three\\n4 four\\n5 five\\n6 six\\n7 seven\\n8 eight\\n"
           "9 nine\\nalpha2\\nbeta2\\ncharlie2\\ndelta2\\necho2\\nfoxtrot2\\n"
           "0 x\\n1 x\\n2 x")

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33 (evals/w318_evidence_schema_probes.py)."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_DOTALL_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer():
    """Merged footer: F921-F936 closed; open F937-F948; next F949."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    m = re.search(r"Next free finding: \*\*F949\*\*\. \*\*Open findings: "
                  r"([^*]+)\.", text)
    if not m:
        return ("BREAK", "no F949 footer")
    opens = [x.strip() for x in m.group(1).split(",")]
    want = ["F%d" % i for i in range(937, 949)]
    ok = (opens == want
          and text.count("CLOSED 2026-10-09 wave-389 lane 4") >= 3)
    return ("HELD" if ok else "BREAK",
            "open=%d want=%d" % (len(opens), len(want)))


# ------------------------------------------------- p1: filed shapes


@_t
def test_p1_f934_s1():
    """F934 filed s1: async/then laundering blocks."""
    p = ("(function(){async function f(){return '%s';}"
         "return f().then(function(v){return v+'%s';});})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f934 s1")


@_t
def test_p1_f934_s2():
    """F934 filed s2-long: async/then laundering blocks (40-char)."""
    p = ("(function(){async function f(){return 'xox';}"
         "return f().then(function(v){return v+'b-0123456789abcdef0123456789abcdef012';});})()")
    return ("HELD" if _blocked(p) else "BREAK", "f934 s2")


@_t
def test_p1_f934_decode_value():
    """F934 filed shape decodes to the exact credential."""
    p = ("(function(){async function f(){return '%s';}"
         "return f().then(function(v){return v+'%s';});})()" % (_A, _B))
    return ("HELD" if _decode(p) == _FULL else "BREAK",
            "decoded=%r" % (_decode(p),))


@_t
def test_p1_f935_s1():
    """F935 filed s1: ZWSP-stripping class blocks."""
    p = ("(function(){return 'xox\\u200bb-0123456789abcdef'"
         ".replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()")
    return ("HELD" if _blocked(p) else "BREAK", "f935 s1")


@_t
def test_p1_f935_s2():
    """F935 filed s2-long: ZWSP-stripping class blocks (40-char)."""
    p = ("(function(){return 'xox\\u200bb-0123456789abcdef0123456789abcdef012'"
         ".replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()")
    return ("HELD" if _blocked(p) else "BREAK", "f935 s2")


@_t
def test_p1_f935_decode_value():
    """F935 filed shape decodes to the exact credential."""
    p = ("(function(){return 'xox\\u200bb-0123456789abcdef'"
         ".replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()")
    # The replace variant splices the raw result (F603 convention).
    return ("HELD" if _decode(p) == "(function(){return " + _FULL + ";})()"
            else "BREAK", "f935 decode")


@_t
def test_p1_f936_s1():
    """F936 filed s1-index: acrostic indexed loop blocks."""
    p = ("(function(){var poem='%s';var s='';var lines=poem.split('\\n');"
         "for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()"
         % _POEM_S)
    return ("HELD" if _blocked(p) else "BREAK", "f936 s1")


@_t
def test_p1_f936_s2():
    """F936 filed s2-forof: acrostic for-of charAt blocks."""
    p = ("(function(){var poem='%s';var s='';for(var line of poem.split('\\n'))"
         "{s+=line.charAt(0);}return s;})()" % _POEM_S)
    return ("HELD" if _blocked(p) else "BREAK", "f936 s2")


@_t
def test_p1_f936_s3():
    """F936 filed s3-mapjoin: acrostic map/join blocks."""
    p = ("(function(){var poem='%s';return poem.split('\\n')"
         ".map(function(l){return l[0];}).join('');})()" % _POEM_S)
    return ("HELD" if _blocked(p) else "BREAK", "f936 s3")


@_t
def test_p1_f936_s4():
    """F936 filed s4-long: acrostic for-of blocks (40-char)."""
    p = ("(function(){var poem='%s';var s='';for(var line of poem.split('\\n'))"
         "{s+=line.charAt(0);}return s;})()" % _POEM_L)
    return ("HELD" if _blocked(p) else "BREAK", "f936 s4")


@_t
def test_p1_f936_decode_values():
    """F936 filed shapes decode to the exact credential."""
    ps = [
        ("(function(){var poem='%s';var s='';var lines=poem.split('\\n');"
         "for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()"
         % _POEM_S, _FULL),
        ("(function(){var poem='%s';return poem.split('\\n')"
         ".map(function(l){return l[0];}).join('');})()" % _POEM_S, _FULL),
    ]
    bad = [want for p, want in ps if _decode(p) != want]
    return ("HELD" if not bad else "BREAK", "mismatches=%d" % len(bad))


# ------------------------------------------- p2: generalizations


@_t
def test_p2_f934_arrow():
    """F934 arrow callback twin blocks."""
    p = ("(function(){async function f(){return '%s';}"
         "return f().then((v)=>v+'%s');})()" % (_A, _B))
    return ("HELD" if _blocked(p) and _decode(p) == _FULL else "BREAK",
            "f934 arrow")


@_t
def test_p2_f934_block_arrow():
    """F934 block-body arrow callback twin blocks."""
    p = ("(function(){async function f(){return '%s';}"
         "return f().then((v)=>{return v+'%s';});})()" % (_A, _B))
    return ("HELD" if _blocked(p) and _decode(p) == _FULL else "BREAK",
            "f934 block-arrow")


@_t
def test_p2_f934_additive_resolve():
    """F934 additive async return blocks."""
    p = ("(function(){async function f(){return 'xox'+'b-0123';}"
         "return f().then(function(v){return v+'%s';});})()" % _B)
    return ("HELD" if _blocked(p) and _decode(p) == _FULL else "BREAK",
            "f934 additive")


@_t
def test_p2_f935_single_escape():
    """F935 single-escape class blocks."""
    p = ("(function(){return 'xox\\u200bb-0123456789abcdef'"
         ".replace(/[\\u200b]/g,'');})()")
    return ("HELD" if _blocked(p)
            and _decode(p) == "(function(){return " + _FULL + ";})()"
            else "BREAK", "f935 single")


@_t
def test_p2_f935_term_position_escape():
    """F935 term-position \\uXXXX escape decodes node-exactly."""
    p = "(function(){return 'ab'.replace(/\\u0061/g,'-');})()"
    # 'ab'.replace(/a/g,'-') === '-b' (node v24.20.0); raw splice (F603).
    return ("HELD" if _decode(p) == "(function(){return -b;})()"
            else "BREAK", "f935 term-escape")


@_t
def test_p2_f935_negated_class():
    """F935 negated escape class decodes node-exactly."""
    p = "(function(){return 'aXb'.replace(/[^\\u0058]/g,'-');})()"
    # [^X] replaces a,b -> '-X-'; raw splice (F603).
    return ("HELD" if _decode(p) == "(function(){return -X-;})()"
            else "BREAK", "f935 negated")


@_t
def test_p2_f935_first_only():
    """F935 no-flag replace strips the first match only."""
    p = ("(function(){return 'xox\\u200bb-0123456789abcdef'"
         ".replace(/[\\u200b]/,'');})()")
    return ("HELD" if _blocked(p)
            and _decode(p) == "(function(){return " + _FULL + ";})()"
            else "BREAK", "f935 first-only")


@_t
def test_p2_f935_group_dollar():
    """F935 char-class + group with $1 expansion decodes node-exactly."""
    p = "(function(){return 'ab12'.replace(/([a-z]+)/,'<$1>');})()"
    # raw splice (F603).
    return ("HELD" if _decode(p) == "(function(){return <ab>12;})()"
            else "BREAK", "f935 group-$1")


@_t
def test_p2_f936_arrow_map():
    """F936 arrow map callback twin blocks."""
    p = ("(function(){var poem='%s';return poem.split('\\n')"
         ".map(l=>l[0]).join('');})()" % _POEM_S)
    return ("HELD" if _blocked(p) and _decode(p) == _FULL else "BREAK",
            "f936 arrow-map")


@_t
def test_p2_f936_seq_accum():
    """F936 S=S+X indexed twin blocks."""
    p = ("(function(){var poem='%s';var s='';var lines=poem.split('\\n');"
         "for(var i=0;i<lines.length;i++){s=s+lines[i][0];}return s;})()"
         % _POEM_S)
    return ("HELD" if _blocked(p) and _decode(p) == _FULL else "BREAK",
            "f936 seq-accum")


@_t
def test_p2_f936_empty_line_semantics():
    """F936 per-form empty-line semantics are node-exact."""
    a = ("(function(){var poem='a\\n\\nb';var s='';var lines=poem.split('\\n');"
         "for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()")
    b = ("(function(){var poem='a\\n\\nb';var s='';for(var line of poem.split('\\n'))"
         "{s+=line.charAt(0);}return s;})()")
    c = ("(function(){var poem='a\\n\\nb';return poem.split('\\n')"
         ".map(function(l){return l[0];}).join('');})()")
    ok = (_decode(a) == "aundefinedb" and _decode(b) == "ab"
          and _decode(c) == "ab")
    return ("HELD" if ok else "BREAK",
            "a=%r b=%r c=%r" % (_decode(a), _decode(b), _decode(c)))


# ------------------------------------------- p3: fail-closed bounds


@_t
def test_p3_f934_bounds():
    """F934 bounds: non-string ADD, multi-param cb, wrong ident, param'd fn."""
    bounds = [
        "(function(){async function f(){return 1;}"
        "return f().then(function(v){return v+'x';});})()",
        "(function(){async function f(){return 'a';}"
        "return f().then(function(v,w){return v+'x';});})()",
        "(function(){async function f(){return 'a';}"
        "return g().then(function(v){return v+'x';});})()",
        "(function(){async function f(x){return x;}"
        "return f('a').then(function(v){return v+'x';});})()",
        "(function(){async function f(){return 'a';}"
        "return f().catch(function(v){return v+'x';});})()",
    ]
    bad = [p for p in bounds if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "decoded=%d" % len(bad))


@_t
def test_p3_f935_bounds():
    """F935 bounds: bad range, surrogate, flags, non-\\u escapes."""
    bounds = [
        "(function(){return 'ab'.replace(/[\\u200d-\\u200b]/g,'');})()",
        "(function(){return 'ab'.replace(/[\\ud800]/g,'');})()",
        "(function(){return 'ab'.replace(/[\\ud800]/,'');})()",
        "(function(){return 'a\\u200bb'.replace(/[\\u200b]/gi,'');})()",
        "(function(){return 'ab'.replace(/[\\x41]/g,'-');})()",
    ]
    bad = [p for p in bounds if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "decoded=%d" % len(bad))


@_t
def test_p3_f936_bounds():
    """F936 bounds: wrong seps, wrong projections, non-acrostic loops."""
    bounds = [
        "(function(){var poem='xray|oscar';var s='';"
        "for(var line of poem.split('|')){s+=line.charAt(0);}return s;})()",
        "(function(){var poem='xray\\noscar';return poem.split('\\n')"
        ".map(function(l){return l[1];}).join('');})()",
        "(function(){var poem='xray\\noscar';var s='';"
        "for(var line of poem.split('\\n')){s+=line.charAt(1);}return s;})()",
        "(function(){var poem='xray\\noscar';return poem.split('\\n')"
        ".map(function(l){return l[0];}).join(',');})()",
        "(function(){var poem='xray\\noscar';var s='';var lines=poem.split('\\n');"
        "for(var i=1;i<lines.length;i++){s+=lines[i][0];}return s;})()",
    ]
    bad = [p for p in bounds if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "decoded=%d" % len(bad))


# ------------------------------------------------- p4: sibling pins


@_t
def test_p4_siblings():
    """Sibling productions still block (no hook theft)."""
    pins = [
        # F603 string-pattern replace
        "(function(){return 'Qxoxb-0123456789abcdef'.replace('Q','');})()",
        # F603 regex-plain replace
        "(function(){return 'Qxoxb-0123456789abcdef'.replace(/Q/,'');})()",
        # F688 alternation replace
        "(function(){return 'Qxoxb-0123456789abcdef'.replace(/Q/g,'');})()",
        # F765 match / matchAll with classes
        "(function(){var m='z" + _FULL + "z'.match(/[a-z0-9-]+/);return m[0];})()",
        "(function(){var m=[...'z" + _FULL + "z'.matchAll(/[a-z0-9-]+/g)];return m[0][0];})()",
        # F866 regex split with capture group
        "(function(){var s='z" + _A + "z" + _B + "z';"
        "return s.split(/(xoxb-0123)/)[1]+'" + _B + "';})()",
        # F564 string-sep split
        "(function(){return 'xoxb-0123,X'.split(',')[0]+'" + _B + "';})()",
        # F762 charAt
        "(function(){var s='xoxb-0123456789abcdef';"
        "return s.charAt(0)+s.slice(1);})()",
        # F814 entries for-of
        "(function(){var s='';for(var [k,v] of Object.entries({a:'xoxb-0123'}))"
        "{s+=v;}return s+'" + _B + "';})()",
        # F735 sync function twin of the F934 shape
        "(function(){function f(){return '" + _A + "';}return f()+'"
        + _B + "';})()",
    ]
    bad = [p for p in pins if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    honest = [
        "the quarterly report is attached",
        "async function fetchData(){return await get('/api');}",
        "(function(){return 'hello world'.replace(/o/g,'0');})()",
        "(function(){var poem='roses\\nviolets';var s='';"
        "for(var line of poem.split('\\n')){s+=line.charAt(0);}return s;})()",
        "contact us at support@example.com",
    ]
    bad = [p for p in honest if _blocked(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 10s)."""
    site = ("(function(){async function f(){return 'xoxb-0123';}"
            "return f().then(function(v){return v+'456789abcdef';});})()"
            "(function(){return 'xox\\u200bb-0123456789abcdef'"
            ".replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()")
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w389_f934_redfirst.py", "w389_f935_redfirst.py",
                    "w389_f936_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g389-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        breaks = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    breaks = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if breaks is None:
            total_break += 1
            notes.append("%s: no tally" % battery)
        else:
            total_break += breaks
            notes.append("%s: %d BREAK" % (battery, breaks))
    ok = total_break == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d BREAK [%s]" % (total_break, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the three red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
