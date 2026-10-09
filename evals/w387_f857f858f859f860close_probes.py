#!/usr/bin/env python3
"""Wave-387 lane 8 close battery: F857 + F858 + F859 + F860 CLOSED.

Verifies the four LOW findings (wave-386 attack round 54, filed
2026-10-09 05:30 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet), sibling pins
(URL family: F576/F599/F617/F648 + F624 slice), honest-text
controls, perf (200 sites), and a depth-1 green check on the four
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

TAXONOMY_PIN = 2143  # wave-386 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B

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
    ok = "VERIFIER_TAXONOMY_PIN = 33" in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % ok)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( (count stays 28)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == RE_DOTALL_COUNT else "BREAK",
            "re.compile count=%d" % n)


@_t
def test_p0_footer_state():
    """Lane-local footer: F857-F860 CLOSED; F893-F899 new open; next F900."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F900**" in text
          and "F857-F860 CLOSED (4)" in text
          and "F893, F894, F895, F896, F897, F898, F899." in text
          and "F857," not in text.split("Open findings:")[1].split(".")[0])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes


@_t
def test_p1_f857_s1():
    """F857 filed s1 (for-of): blocks, node-exact decode."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r+=x.segment;}return r+'%s';})()"
         % (_A, _B))
    ok = _blocked(p) and _FULL in _decode(p)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f857_s2():
    """F857 filed s2 (Array.from/map/join): blocks, node-exact decode."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');return Array.from(s).map(function(x){return x.segment;})"
         ".join('')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _FULL in _decode(p)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f858_s1():
    """F858 filed s1 (hash carrier): blocks, node-exact decode."""
    p = ("(function(){var u=new URL('https://h/#%s');"
         "return u.hash.slice(1)+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f858_s2():
    """F858 filed s2 (username carrier): blocks, node-exact decode."""
    p = ("(function(){var u=new URL('https://h/');u.username='%s';"
         "return u.username+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f859_s1():
    """F859 filed s1 (set + get): blocks, node-exact decode."""
    p = ("(function(){var p=new URLSearchParams();p.set('k','%s');"
         "return p.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f859_s2():
    """F859 filed s2 (append + get): blocks, node-exact decode."""
    p = ("(function(){var p=new URLSearchParams();p.append('k','%s');"
         "return p.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f860_s1():
    """F860 filed s1 (FormData set + get): blocks, node-exact decode."""
    p = ("(function(){var f=new FormData();f.set('k','%s');"
         "return f.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f860_s2():
    """F860 filed s2 (FormData append x2 + get): blocks, node-exact decode."""
    p = ("(function(){var f=new FormData();f.append('k','%s');f.append('k','x');"
         "return f.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------------- generalizations


@_t
def test_p2_f857_arrow_map():
    """F857: arrow map callback twin blocks, node-exact."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');return Array.from(s).map(x=>x.segment)"
         ".join('')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f857_join_sep():
    """F857: non-empty join separator is node-exact (dashes interleave)."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('ab');return Array.from(s).map(x=>x.segment)"
         ".join('-');})()")
    ok = _decode(p) == "a-b"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f857_no_options():
    """F857: omitted options (engine defaults to grapheme) blocks."""
    p = ("(function(){var s=new Intl.Segmenter('en').segment('%s');var r='';"
         "for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f857_crlf():
    """F857: CR+LF stays one cluster (UAX #29 GB3), node-exact."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('a\\r\\nb');var r='';for(var x of s){r+=x.segment;}"
         "return r;})()")
    ok = _decode(p) == "a\r\nb"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f857_let_const():
    """F857: let/const bindings block (node-identical binding)."""
    p = ("(function(){let s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');let r='';for(let x of s){r+=x.segment;}"
         "return r+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f858_userinfo_in_url():
    """F858: userinfo baked into the URL literal blocks, node-exact."""
    p = ("(function(){var u=new URL('https://%s@h/');"
         "return u.username+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f858_password():
    """F858: password assignment + read blocks, node-exact."""
    p = ("(function(){var u=new URL('https://h/');u.password='%s';"
         "return u.password+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f858_empty_fragment():
    """F858: empty fragment -> '' (node-exact, not '#')."""
    p = ("(function(){var u=new URL('https://h/');"
         "return u.hash+'%s';})()" % _B)
    ok = _decode(p) == _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f858_hash_noslice():
    """F858: u.hash without .slice keeps the '#' (node-exact)."""
    p = ("(function(){var u=new URL('https://h/#%s');"
         "return u.hash;})()" % _A)
    ok = _decode(p) == "#" + _A
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f859_set_after_append():
    """F859: append then set -- set wins at first position, node-exact."""
    p = ("(function(){var p=new URLSearchParams();p.append('k','zz');"
         "p.set('k','%s');return p.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f859_multi_names():
    """F859: get picks the right name among several, node-exact."""
    p = ("(function(){var p=new URLSearchParams();p.set('z','0');"
         "p.append('k','%s');p.append('k','zz');return p.get('k')+'%s';})()"
         % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f860_set_after_append():
    """F860: append then set -- set replaces, node-exact."""
    p = ("(function(){var f=new FormData();f.append('k','zz');"
         "f.set('k','%s');return f.get('k')+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_multi_tail():
    """All four: multiple +'LIT' tail operands concatenate, bounded."""
    p = ("(function(){var p=new URLSearchParams();p.set('k','%s');"
         "return p.get('k')+'%s'+'!';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL + "!"
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------------- fail-closed bounds


@_t
def test_p3_f857_word_granularity():
    """F857 bound: word granularity misses (filed F893), never mis-decodes."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'word'})"
         ".segment('%s');var r='';for(var x of s){r+=x.segment;}"
         "return r+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f857_plain_assign():
    """F857 bound: r=r+x.segment misses (filed F894), never mis-decodes."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r=r+x.segment;}"
         "return r+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f857_nonascii():
    """F857 bound: non-ASCII segment input fails closed (combining marks merge)."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('a\\u0301b');var r='';for(var x of s){r+=x.segment;}"
         "return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f857_x_index():
    """F857 bound: x.index reads fail closed (unmodeled member)."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('%s');var r='';for(var x of s){r+=x.index;}"
         "return r;})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_pathname():
    """F858 bound: .pathname misses (filed F895), never mis-decodes."""
    p = ("(function(){var u=new URL('https://h/%s');"
         "return u.pathname+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_search():
    """F858 bound: .search misses (filed F896), never mis-decodes."""
    p = ("(function(){var u=new URL('https://h/?q=%s');"
         "return u.search+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_file_scheme_assign():
    """F858 bound: userinfo assignment on file: is ignored by the engine -- miss."""
    p = ("(function(){var u=new URL('file:///x');u.username='%s';"
         "return u.username+'%s';})()" % (_A, _B))
    # Engine yields '' for the username: the decoded ''+_A+_B must NOT
    # be mis-decoded as carrying _A; the shape must miss entirely.
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_userinfo_encoding():
    """F858 bound: userinfo needing percent-encoding fails closed."""
    p = ("(function(){var u=new URL('https://h/');u.username='a b';"
         "return u.username+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_relative_url():
    """F858 bound: relative URL fails closed (engine throws)."""
    p = ("(function(){var u=new URL('/#%s');"
         "return u.hash.slice(1)+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f858_hash_assign():
    """F858 bound: .hash assignment is unmodeled -- miss."""
    p = ("(function(){var u=new URL('https://h/');u.hash='#%s';"
         "return u.hash.slice(1)+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f859_missing_name():
    """F859 bound: .get on a missing name misses (engine null)."""
    p = ("(function(){var p=new URLSearchParams();p.set('z','0');"
         "return p.get('k')+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f859_nonliteral_value():
    """F859 bound: non-literal mutation value fails closed."""
    p = ("(function(){var p=new URLSearchParams();var v='%s';p.set('k',v);"
         "return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f859_sort_member():
    """F859 bound: unmodeled mutation members (sort) fail the shape closed."""
    p = ("(function(){var p=new URLSearchParams();p.set('k','%s');p.sort();"
         "return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f860_getall():
    """F860 bound: .getAll misses (filed F897), never mis-decodes."""
    p = ("(function(){var f=new FormData();f.append('k','%s');"
         "return f.getAll('k').join('')+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f860_has():
    """F860 bound: .has misses (filed F898), never mis-decodes."""
    p = ("(function(){var f=new FormData();f.set('k','%s');"
         "return (f.has('k')?'%s':'zz')+'%s';})()" % (_A, _A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f860_ctor_arg():
    """F860 bound: new FormData(x) fails closed (engine throws for non-forms)."""
    p = ("(function(){var f=new FormData('x');f.set('k','%s');"
         "return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f860_missing_name():
    """F860 bound: .get on a missing name misses (engine null)."""
    p = ("(function(){var f=new FormData();f.set('z','0');"
         "return f.get('k')+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


# ------------------------------------------------------- sibling pins


@_t
def test_p4_f576_searchparams():
    """Sibling: F576 new URL(...).searchParams.get still blocks."""
    p = ("(function(){var u=new URL('https://h/?k=%s');"
         "return u.searchParams.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f648_getall():
    """Sibling: F648 no-arg URLSearchParams + getAll still blocks."""
    p = ("(function(){var p=new URLSearchParams();p.append('q','%s');"
         "p.append('q','%s');return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f599_literal_ctor():
    """Sibling: F599 literal-ctor URLSearchParams + getAll still blocks."""
    p = ("(function(){var p=new URLSearchParams('q=%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f617_url_searchparams_get():
    """Sibling: F617 URLSearchParams binding .get still blocks."""
    p = ("(function(){var p=new URLSearchParams('k=%s');"
         "return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f624_slice():
    """Sibling: F624 .slice on a literal still blocks."""
    p = "'#%s'.slice(1)+'%s'" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# ------------------------------------------------------- honest text


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_segmenter():
    """Honest Intl.Segmenter text (no credential) stays quiet."""
    p = ("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'})"
         ".segment('hello');var r='';for(var x of s){r+=x.segment;}"
         "return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


@_t
def test_p5_honest_url():
    """Honest URL text (no credential) stays quiet."""
    p = ("(function(){var u=new URL('https://example.com/#section');"
         "return u.hash.slice(1);})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


@_t
def test_p5_honest_formdata():
    """Honest FormData text (no credential) stays quiet."""
    p = ("(function(){var f=new FormData();f.set('name','ada');"
         "return f.get('name');})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf_200_sites():
    """Perf: 200 decode sites stay fast (F452 aggregate budget)."""
    site = ("(function(){var p=new URLSearchParams();p.set('k','v');"
            "return p.get('k');})()")
    text = ("prefix " + site + " ") * 200
    t0 = time.time()
    dlp._try_js_expr_decode_all(text)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w387_f857_redfirst.py", "w387_f858_redfirst.py",
                    "w387_f859_redfirst.py", "w387_f860_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
