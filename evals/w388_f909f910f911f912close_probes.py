#!/usr/bin/env python3
"""Wave-388 lane 5 closure battery: F909 + F910 + F911 + F912.

F909: F800 get-trap param-form residuals -- 0-param / 1-param /
  method-shorthand constant-return get traps (arity engine-irrelevant
  for constant returns).
F910: Intl.Segmenter {granularity:'word'} modeled node-exactly
  (_js_f857_words; UAX #29, ASCII-only).
F911: Segmenter for-of admits `r=r+x.segment` (engine-exact desugar
  of `r+=x.segment`).
F912: URL .pathname modeled node-exactly on the urlsplit-faithful
  subset (backslash, dot segments incl. %2e forms, empty path,
  non-ASCII, and engine-percent-encoded chars fail closed).

Pin 2143; VERIFIER_TAXONOMY_PIN 33; re.compile( count 28 (zero new).
$0-spend-by-construction (no realmodel_harness / ModelDriver /
--provider / ledger refs -- grep-verified before running).
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

TAXONOMY_PIN = 2143  # wave-387 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ------------------------------------------------------- P0: pins/footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    from gov import guac_graph
    ok = guac_graph.TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % guac_graph.TAXONOMY_PIN)


@_t
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    src = open(os.path.join(REPO_ROOT, "evals",
                            "w318_evidence_schema_probes.py")).read()
    m = re.search(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src)
    ok = m is not None and int(m.group(1)) == VERIFIER_PIN == 33
    return ("HELD" if ok else "BREAK",
            "verifier_pin=%s" % (m.group(1) if m else None))


@_t
def test_p0_no_new_recompile():
    """Zero new re.compile( in gov/dlp.py (count 28)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = src.count("re.compile(")
    return ("HELD" if n == RE_DOTALL_COUNT else "BREAK",
            "re.compile count=%d want %d" % (n, RE_DOTALL_COUNT))


@_t
def test_p0_footer_state():
    """Footer: F909-F912 CLOSED; open F921-F926, F928-F936; next F937."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    fl = [l for l in text.split("\n")
          if l.startswith("Next free finding:")][-1]
    want_open = (["F%d" % n for n in range(921, 927)]
                 + ["F%d" % n for n in range(928, 937)])
    m = re.search(r"Open findings: ([^*]+)\.\*\*", fl)
    got_open = [x.strip() for x in m.group(1).split(",")] if m else []
    closed_ok = all(
        ("(%s filed" % f) in text
        and "LOW, CLOSED (wave-388 lane 5" in
        text[text.index("(%s filed" % f):text.index("(%s filed" % f) + 400]
        for f in ("F909", "F910", "F911", "F912"))
    ok = ("Next free finding: **F937**" in fl
          and got_open == want_open and closed_ok)
    return ("HELD" if ok else "BREAK",
            "open=%d closed4=%s" % (len(got_open), closed_ok))


# ------------------------------------------------- P1: filed shapes


@_t
def test_p1_f909_s1():
    """F909 filed: 0-param function get trap."""
    p = ("(function(){var p=new Proxy({},{get:function(){return '%s';}});"
         "return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p1_f909_s2():
    """F909 filed: method-shorthand get trap."""
    p = ("(function(){var p=new Proxy({},{get(){return '%s';}});"
         "return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p1_f909_s3():
    """F909 same-class: 0-param arrow get trap."""
    p = ("(function(){var p=new Proxy({},{get:()=>'%s'});"
         "return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p1_f910():
    """F910 filed: word granularity."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'word'})"
         ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
         "return r+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p1_f911():
    """F911 filed: plain-assignment accumulation."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r=r+x.segment;}"
         "return r+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p1_f912():
    """F912 filed: .pathname read."""
    p = ("(function(){var u=new URL('https://h/%s');"
         "return u.pathname+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


# ------------------------------------------------- P2: generalizations


@_t
def test_p2_f909_1param():
    """F909 gen: 1-param forms (arity engine-irrelevant)."""
    shapes = [
        ("(function(){var p=new Proxy({},{get:function(t){return '%s';}});"
         "return p.anything+'%s';})()"),
        ("(function(){var p=new Proxy({},{get(t){return '%s';}});"
         "return p.anything+'%s';})()"),
        ("(function(){var p=new Proxy({},{get:(t)=>'%s'});"
         "return p.anything+'%s';})()"),
    ]
    loud = [s for s in shapes if not _blocked(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d block" % (len(shapes) - len(loud), len(shapes)))


@_t
def test_p2_f909_named():
    """F909 gen: named function form + bracket read."""
    p = ("(function(){var p=new Proxy({},{get:function g(){return '%s';}});"
         "return p['anything']+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "hit=%s" % _blocked(p))


@_t
def test_p2_f910_locales():
    """F910 gen: word granularity across locales + decl variants."""
    shapes = [
        ("(function(){var s=new Intl.Segmenter('fr',{granularity:'word'})"
         ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
         "return r+'%s';})()"),
        ("(function(){let s=new Intl.Segmenter('en',{granularity:'word'})"
         ".segment('%s');let r='';for(let x of s){r+=x.segment;}"
         "return r+'%s';})()"),
        ("(function(){const s=new Intl.Segmenter('en',{granularity:'word'})"
         ".segment('%s');let r='';for(const x of s){r+=x.segment;}"
         "return r+'%s';})()"),
    ]
    loud = [s for s in shapes if not _blocked(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d block" % (len(shapes) - len(loud), len(shapes)))


@_t
def test_p2_f910_word_exact():
    """F910 gen: word segmentation is node-exact, not a shortcut."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'word'})"
         ".segment('don\\'t 1,000 x_y');var r='';for(var x of s)"
         "{r+=x.segment;}return r;})()")
    v = _decode(p)
    ok = v == "don't 1,000 x_y"
    return ("HELD" if ok else "BREAK", "decoded=%r" % (v,))


@_t
def test_p2_f911_variants():
    """F911 gen: spacing + decl variants of plain assignment."""
    shapes = [
        ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r = r + x.segment ;}"
         "return r+'%s';})()"),
        ("(function(){let s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');let r='';for(let x of s){r=r+x.segment;}"
         "return r+'%s';})()"),
    ]
    loud = [s for s in shapes if not _blocked(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d block" % (len(shapes) - len(loud), len(shapes)))


@_t
def test_p2_f912_variants():
    """F912 gen: bracket read, query present, postfix chain, userinfo."""
    shapes = [
        ("(function(){var u=new URL('https://h/%s');"
         "return u['pathname']+'%s';})()"),
        ("(function(){var u=new URL('https://h/%s?a=b');"
         "return u.pathname+'%s';})()"),
        ("(function(){var u=new URL('https://h/%s');"
         "return u.pathname.slice(1)+'%s';})()"),
        ("(function(){var u=new URL('https://u:p@h/%s');"
         "return u.pathname+'%s';})()"),
    ]
    loud = [s for s in shapes if not _blocked(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d block" % (len(shapes) - len(loud), len(shapes)))


@_t
def test_p2_f912_pathname_exact():
    """F912 gen: pathname value is node-exact."""
    v = _decode("(function(){var u=new URL('https://h/a//b');"
                "return u.pathname;})()")
    ok = v == "/a//b"
    return ("HELD" if ok else "BREAK", "decoded=%r" % (v,))


# ------------------------------------------------- P3: fail-closed bounds


@_t
def test_p3_f909_bounds():
    """F909 bounds: non-constant bodies / bad arities stay closed."""
    bounds = [
        # non-constant body
        (("(function(){var p=new Proxy({},{get:function(){return x;}});"
          "return p.anything+'%s';})()"), (_B,)),
        # 3 params
        (("(function(){var p=new Proxy({},{get:function(a,b,c){return '%s';}});"
          "return p.anything+'%s';})()"), (_A, _B)),
        # rest param
        (("(function(){var p=new Proxy({},{get:function(...a){return '%s';}});"
          "return p.anything+'%s';})()"), (_A, _B)),
        # trailing comma
        (("(function(){var p=new Proxy({},{get:function(t,){return '%s';}});"
          "return p.anything+'%s';})()"), (_A, _B)),
        # extra handler key
        (("(function(){var p=new Proxy({},{get(){return '%s';},"
          "set(){return 1;}});return p.anything+'%s';})()"), (_A, _B)),
        # not a get trap
        (("(function(){var p=new Proxy({},{getx(){return '%s';}});"
          "return p.anything+'%s';})()"), (_A, _B)),
        # non-string return
        (("(function(){var p=new Proxy({},{get(){return 42;}});"
          "return p.anything+'%s';})()"), (_B,)),
    ]
    loud = [s for s, args in bounds if not _misses(s % args)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d fail closed" % (len(bounds) - len(loud), len(bounds)))


@_t
def test_p3_f910_bounds():
    """F910 bounds: sentence / bad options / non-ASCII stay closed."""
    bounds = [
        (("(function(){var s=new Intl.Segmenter('en',{granularity:'sentence'})"
          ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
          "return r+'%s';})()"), (_A, _B)),
        (("(function(){var s=new Intl.Segmenter('en',{granularity:'WORD'})"
          ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
          "return r+'%s';})()"), (_A, _B)),
        (("(function(){var s=new Intl.Segmenter('en',{granularity:'word',x:1})"
          ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
          "return r+'%s';})()"), (_A, _B)),
        (("(function(){var s=new Intl.Segmenter('en',{granularity:'word'})"
          ".segment('caf\\u00e9');var r='';for(var x of s){r+=x.segment;}"
          "return r+'%s';})()"), (_B,)),
    ]
    loud = [s for s, args in bounds if not _misses(s % args)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d fail closed" % (len(bounds) - len(loud), len(bounds)))


@_t
def test_p3_f911_bounds():
    """F911 bounds: non-accumulation bodies stay closed."""
    bounds = [
        # bare assign (no concat) -- different semantics
        ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r=x.segment;}"
         "return r+'%s';})()"),
        # wrong var on the right
        ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r=q+x.segment;}"
         "return r+'%s';})()"),
        # equality, not assignment
        ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r==x.segment;}"
         "return r+'%s';})()"),
    ]
    loud = [s for s in bounds if not _misses(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d fail closed" % (len(bounds) - len(loud), len(bounds)))


@_t
def test_p3_f912_bounds():
    """F912 bounds: dotseg / backslash / empty / encoded paths closed; .search now blocks (F913)."""
    bounds = [
        # dot segment (normalized by the engine)
        (("(function(){var u=new URL('https://h/a/../%s');"
          "return u.pathname+'%s';})()"), (_A, _B)),
        # percent-encoded dot segment
        (("(function(){var u=new URL('https://h/%%2e%%2e/%s');"
          "return u.pathname+'%s';})()"), (_A, _B)),
        # backslash (engine converts to /)
        ((f"(function(){{var u=new URL('https://h/a\\\\b');"
          f"return u.pathname+'{_B}';}})()"), ()),
        # empty path (engine returns '/')
        ((f"(function(){{var u=new URL('https://h');"
          f"return u.pathname+'{_B}';}})()"), ()),
        # space (engine percent-encodes)
        ((f"(function(){{var u=new URL('https://h/a b');"
          f"return u.pathname+'{_B}';}})()"), ()),
        # relative URL (engine throws)
        (("(function(){var u=new URL('/%s');"
          "return u.pathname+'%s';})()"), (_A, _B)),
        # .search now modeled (F913, wave-388 lane 6) -- positive pin
        (("(function(){var u=new URL('https://h/?q=%s');"
          "return u.search+'%s';})()"), (_A, _B), True),
    ]
    loud = [s for s, args in bounds[:6] if not _misses(s % args)]
    # the .search positive pin must decode (block), not miss
    _spos, _apos, _ = bounds[6]
    search_blocks = not _misses(_spos % _apos)
    ok = not loud and search_blocks
    return ("HELD" if ok else "BREAK",
            "%d/%d fail closed; search-blocks=%s" % (len(bounds) - 1 - len(loud), len(bounds) - 1, search_blocks))


# ------------------------------------------------- P4: sibling pins


@_t
def test_p4_siblings():
    """Siblings hold: F800 2-param, F857 grapheme+Array.from,
    F858 hash/username/password, F576 searchParams."""
    sibs = [
        ("(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});"
         "return p.anything+'%s';})()"),
        ("(function(){var p=new Proxy({},{get:(t,k)=>'%s'});"
         "return p.anything+'%s';})()"),
        ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
         "return r+'%s';})()"),
        ("(function(){var s=new Intl.Segmenter('en')"
         ".segment('%s');return Array.from(s).map(function(x)"
         "{return x.segment;}).join('')+'%s';})()"),
        ("(function(){var u=new URL('https://h/#%s');"
         "return u.hash+'%s';})()"),
        ("(function(){var u=new URL('https://h/');u.username='%s';"
         "return u.username+'%s';})()"),
        ("(function(){var u=new URL('https://h/?a=%s');"
         "return u.searchParams.get('a')+'%s';})()"),
    ]
    loud = [s for s in sibs if not _blocked(s % (_A, _B))]
    return ("HELD" if not loud else "BREAK",
            "%d/%d siblings hold" % (len(sibs) - len(loud), len(sibs)))


# ------------------------------------------------- P5: honest text


@_t
def test_p5_honest():
    """Honest text stays quiet."""
    honest = [
        "'(function(){var s=\\'ab\\';return s;})()'",
        "the proxy get trap article discusses handler arity",
        "Intl.Segmenter word granularity splits text into words",
        "the URL pathname /docs/guide is where the manual lives",
        "she returned the segmenter to the rental desk",
    ]
    loud = [s for s in honest if not _misses(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d quiet" % (len(honest) - len(loud), len(honest)))


# ------------------------------------------------- P6: perf


@_t
def test_p6_perf_200_sites():
    """200 mixed sites decode within budget."""
    sites = []
    for k in range(200):
        which = k % 4
        if which == 0:
            sites.append(
                "(function(){var p=new Proxy({},{get(){return 'ab';}});"
                "return p.x;})()")
        elif which == 1:
            sites.append(
                "(function(){var s=new Intl.Segmenter('en',{granularity:'word'})"
                ".segment('hello world');var r='';for(var x of s)"
                "{r+=x.segment;}return r;})()")
        elif which == 2:
            sites.append(
                "(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
                ".segment('abc');var r='';for(var x of s){r=r+x.segment;}"
                "return r;})()")
        else:
            sites.append(
                "(function(){var u=new URL('https://h/a/b');"
                "return u.pathname;})()")
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------- P7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w388_f909_redfirst.py", "w388_f910_redfirst.py",
                    "w388_f911_redfirst.py", "w388_f912_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g388-lane5-green-", dir="/var/tmp")
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
            "green(red-firsts): %d BREAK [%s]" % (total_break,
                                                 "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__,
                                                         e)
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
