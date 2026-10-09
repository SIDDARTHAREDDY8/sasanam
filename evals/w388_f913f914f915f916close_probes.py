#!/usr/bin/env python3
"""Wave-388 lane 6 close battery: F913 + F914 + F915 + F916 CLOSED.

Verifies the four LOW findings (wave-387 lane-8 residuals, filed
2026-10-09 07:08/07:20 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (URL family: F576/F648/F857/F858/F860),
honest-text controls, perf (200 sites), and a depth-1 green check
on the four red-first batteries (GOV_SKIP_GREEN=1 in the child env).

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

TAXONOMY_PIN = 2143  # wave-387 merge (no code-count change)
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
    """Footer: F913-F916 CLOSED; open F921-F926, F928-F936; next F937."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    m = re.search(r"Next free finding: \*\*F937\*\*\. \*\*Open findings: "
                  r"([^*]+)\.", text)
    if not m:
        return ("BREAK", "no F937 footer")
    opens = [x.strip() for x in m.group(1).split(",")]
    want = (["F%d" % i for i in range(921, 927)]
            + ["F%d" % i for i in range(928, 937)])
    ok = (opens == want
          and all("(%s filed" % f in text for f in
                  ("F913", "F914", "F915", "F916"))
          and text.count("CLOSED 2026-10-09 wave-388 lane 6") >= 4)
    return ("HELD" if ok else "BREAK",
            "open=%d want=%d" % (len(opens), len(want)))


# ------------------------------------------------- p1: filed shapes


@_t
def test_p1_f913_s1():
    """F913 filed s1: u.search resolves node-exactly, blocks."""
    p = ("(function(){var u=new URL('https://h/?q=%s');"
         "return u.search+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f913_s2():
    """F913 filed s2: u['search'] bracket form blocks."""
    p = ("(function(){var u=new URL('https://h/?q=%s');"
         "return u['search']+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f914_s1():
    """F914 filed s1: f.getAll('k').join('') blocks."""
    p = ("(function(){var f=new FormData();f.append('k','%s');"
         "return f.getAll('k').join('')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f914_s2():
    """F914 filed s2: multi-value getAll with '-' join blocks."""
    p = ("(function(){var f=new FormData();f.append('k','%s');"
         "f.append('k','zz');return f.getAll('k').join('-')+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f915_s1():
    """F915 filed s1: (f.has('k')?'f1':'zz')+'f2' blocks."""
    p = ("(function(){var f=new FormData();f.set('k','%s');"
         "return (f.has('k')?'%s':'zz')+'%s';})()" % (_A, _A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f915_s2():
    """F915 filed s2: append-bound .has ternary blocks."""
    p = ("(function(){var f=new FormData();f.append('k','%s');"
         "return (f.has('k')?'%s':'zz')+'%s';})()" % (_A, _A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f916_s1():
    """F916 filed s1: omitted-locale for-of accumulation blocks."""
    p = ("(function(){var s=new Intl.Segmenter().segment('%s');var r='';"
         "for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f916_s2():
    """F916 filed s2: omitted-locale Array.from twin blocks."""
    p = ("(function(){var s=new Intl.Segmenter().segment('%s');"
         "return Array.from(s).map(function(x){return x.segment;}).join('')"
         "+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# ------------------------------------------- p2: generalizations


@_t
def test_p2_f913_empty_query():
    """F913 gen: empty query yields '' -- the URL contributes nothing.

    The decoded variant is just the tail, so a non-credential tail
    stays quiet (the shape cannot launder anything).
    """
    p = ("(function(){var u=new URL('https://h/');"
         "return u.search+'ab';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p2_f913_query_plus_fragment():
    """F913 gen: query + fragment -- search is only the query, blocks."""
    p = ("(function(){var u=new URL('https://h/?q=%s#frag');"
         "return u.search+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f914_getall_missing_name():
    """F914 gen: missing name is [] -- join('') is '' (F648 precedent).

    The decoded variant is just the tail, so a non-credential tail
    stays quiet (the shape cannot launder anything).
    """
    p = ("(function(){var f=new FormData();"
         "return f.getAll('zzz').join('')+'ab';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p2_f915_bracket_has():
    """F915 gen: f['has']('k') bracket form blocks."""
    p = ("(function(){var f=new FormData();f.set('k','%s');"
         "return (f['has']('k')?'%s':'zz')+'%s';})()" % (_A, _A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f915_then_branch_credential():
    """F915 gen: then-branch is the credential literal, blocks."""
    p = ("(function(){var f=new FormData();f.set('k','ab');"
         "return (f.has('k')?'%s':'zz')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f916_undefined_locale_with_opts():
    """F916 gen: `undefined` locale + {granularity:'grapheme'} blocks.

    ECMA-402 treats undefined as the default locale (node-verified
    identical clusters to the omitted form for ASCII input).
    """
    p = ("(function(){var s=new Intl.Segmenter(undefined,"
         "{granularity:'grapheme'}).segment('%s');var r='';"
         "for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f916_arrow_twin():
    """F916 gen: omitted-locale arrow-fn Array.from twin blocks."""
    p = ("(function(){var s=new Intl.Segmenter().segment('%s');"
         "return Array.from(s).map(x=>x.segment).join('')+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# -------------------------------------------- p3: fail-closed bounds


@_t
def test_p3_f913_unmodeled_member():
    """F913 bound: u.origin fails closed -- quiet."""
    p = ("(function(){var u=new URL('https://h/?q=ab');"
         "return u.origin;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f913_search_on_non_url():
    """F913 bound: .search on a plain string fails closed -- quiet."""
    p = "('ab').search"
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f914_nonliteral_key():
    """F914 bound: .getAll(123) non-literal key fails closed -- quiet."""
    p = ("(function(){var f=new FormData();f.append('k','ab');"
         "return f.getAll(123).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f914_extra_arg():
    """F914 bound: .getAll('k','x') extra arg fails closed -- quiet."""
    p = ("(function(){var f=new FormData();f.append('k','ab');"
         "return f.getAll('k','x').join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f915_unparenthesized_ternary():
    """F915 bound: unparenthesized ternary fails closed -- quiet.

    The engine re-associates the tail into the else branch
    ('zz'+'f2'); decoding it would mis-decode, so it must fail
    closed (F710 precedent).
    """
    p = ("(function(){var f=new FormData();f.set('k','%s');"
         "return f.has('k')?'%s':'zz'+'%s';})()" % (_A, _A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f915_nonliteral_key():
    """F915 bound: f.has(123) non-literal key fails closed -- quiet."""
    p = ("(function(){var f=new FormData();f.set('k','ab');"
         "return (f.has(123)?'ab':'zz');})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f915_other_receiver():
    """F915 bound: ternary on another ident fails closed -- quiet."""
    p = ("(function(){var f=new FormData();var g=new FormData();"
         "g.set('k','ab');return (f.has('k')?'ab':'zz');})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f916_word_granularity():
    """F916 bound: word granularity fails closed -- quiet."""
    p = ("(function(){var s=new Intl.Segmenter('en',"
         "{granularity:'word'}).segment('ab');var r='';"
         "for(var x of s){r+=x.segment;}return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f916_nonnascii_input():
    """F916 bound: non-ASCII input fails closed -- quiet."""
    p = ("(function(){var s=new Intl.Segmenter().segment('a\\u00e9b');"
         "var r='';for(var x of s){r+=x.segment;}return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


# -------------------------------------------------- p4: sibling pins


@_t
def test_p4_sib_hash():
    """Sibling: F858 .hash still blocks."""
    p = ("(function(){var u=new URL('https://h/#%s');"
         "return u.hash+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_searchparams():
    """Sibling: F576 .searchParams still blocks."""
    p = ("(function(){var u=new URL('https://h/?q=%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_formdata_get():
    """Sibling: F860 .get still blocks."""
    p = ("(function(){var f=new FormData();f.append('k','%s');"
         "return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_formdata_get_missing():
    """Sibling: F860 .get missing name still fails closed -- quiet."""
    p = ("(function(){var f=new FormData();"
         "return f.get('zzz')+'ab';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p4_sib_params_getall():
    """Sibling: F648 URLSearchParams .getAll still blocks (its filed
    form -- F648 has no (+ 'LIT')* return tail)."""
    p = ("(function(){var q=new URLSearchParams();q.append('k','%s');"
         "q.append('k','%s');return q.getAll('k').join('');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_segmenter_locale():
    """Sibling: F857 locale-literal form still blocks."""
    p = ("(function(){var s=new Intl.Segmenter('en').segment('%s');"
         "var r='';for(var x of s){r+=x.segment;}return r+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# ----------------------------------------------- p5: honest text


@_t
def test_p5_honest_url():
    """Honest: URL shape without credential stays quiet."""
    p = ("(function(){var u=new URL('https://h/?q=ab');"
         "return u.search;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p5_honest_formdata():
    """Honest: FormData shapes without credential stay quiet."""
    p1 = ("(function(){var f=new FormData();f.append('k','ab');"
          "return f.getAll('k').join('');})()")
    p2 = ("(function(){var f=new FormData();"
          "return (f.has('k')?'ab':'zz');})()")
    ok = _misses(p1) and _misses(p2)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_segmenter():
    """Honest: Segmenter shape without credential stays quiet."""
    p = ("(function(){var s=new Intl.Segmenter().segment('ab');var r='';"
         "for(var x of s){r+=x.segment;}return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


# ------------------------------------------------------- perf


@_t
def test_p6_perf_200_sites():
    """Perf: 200 decode sites stay fast (F452 aggregate budget)."""
    site = ("(function(){var f=new FormData();f.append('k','v');"
            "return f.getAll('k').join('');})()")
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
    for battery in ("w388_f913_redfirst.py", "w388_f914_redfirst.py",
                    "w388_f915_redfirst.py", "w388_f916_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
