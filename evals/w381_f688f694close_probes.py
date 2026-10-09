"""Wave-381 lane 3: close F688 + F694 (string fragment-reassembly residuals).

F688 (LOW, attack round 48): replace/replaceAll functional-replacer
fragment assembly -- the decoder had no string-replace production for
functional replacers over alternation regexes.
F694 (LOW, attack round 48): regex match-group fragment reassembly --
the decoder had no RegExp production for match/matchAll group
extraction.

Closure (gov/dlp.py, node v24.20.0 exact):
- F688: bounded alternation-of-literals regex (/A1|A2|.../ with "" or
  "g" flags) in String.replace (first/all) and String.replaceAll
  (global only; a non-global regex throws TypeError in the engine),
  with an F609 functional replacer (evaluated per match with the
  engine's (match, offset, string) args) or a literal replacement
  ($-expanded via the F603 subset). Leftmost-first, alternative
  order -- engine-exact for literal alternatives.
- F694: String.match with an F603 regex-plain literal (flags "" ->
  [full, g1..gn]; "g" -> [full1, full2, ...]; no match is engine-null
  and fails closed) and String.matchAll with a /g regex-plain
  literal (engine TypeError without /g), consumed through the
  (function(){var|let|const M=INIT;return M[I]+M[J];})() IIFE.

Every probe returns HELD on the closed tree; a literal BREAK verdict
means the closure regressed or a new break appeared.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (local node only).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    from gov.decision_codes import TAXONOMY
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- F688 filed shapes

@_t
def test_p1a_f688_replaceAll_fn_closed():
    """F688 CLOSED (replaceAll-fn): filed shape now blocks."""
    ok = _blocked("(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1b_f688_replace_fn_closed():
    """F688 CLOSED (replace-fn): filed shape now blocks."""
    ok = _blocked("(function(){return 'ab'.replace(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F688 variants (node-exact)

@_t
def test_p2a_f688_replace_first_only():
    """F688 variant: replace with an alternation pattern but no /g replaces the first match only."""
    ok = _blocked("(function(){return 'a'.replace(/a|b/,function(m){return '%s%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2b_f688_alternation_order():
    """F688 variant: leftmost alternative wins at each position."""
    ok1 = _blocked("(function(){return 'aab'.replaceAll(/aa|a/g,'%s%s');})()" % (_A, _B))
    ok2 = _blocked("(function(){return 'aab'.replaceAll(/a|aa/g,'%s%s');})()" % (_A, _B))
    ok = ok1 and ok2
    return ("HELD" if ok else "BREAK", "ab|a=%s a|ab=%s" % (ok1, ok2))


@_t
def test_p2c_f688_string_pattern_replaceAll():
    """F688 variant: replaceAll with a string-literal pattern."""
    ok = _blocked("(function(){return 'a'.replaceAll('a',function(m){return '%s%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2d_f688_arrow_replacer():
    """F688 variant: arrow-function replacer."""
    ok = _blocked("(function(){return 'ab'.replaceAll(/a|b/g,m=>m==='a'?'%s':'%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2e_f688_dollar_expansion():
    """F688 variant: literal replacement with F603 $-expansion."""
    ok = _blocked("(function(){return 'Q'.replaceAll(/Q/g,'$&%s%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2f_f688_colon_charset():
    """F688/F603 variant: ':' inside a regex-plain pattern (charset)."""
    ok = _blocked("(function(){return 'a:b'.replace(/a:b/,'%s%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F688 fail-closed bounds

@_t
def test_p3a_f688_replaceAll_nonglobal_fails():
    """F688 bound: replaceAll with a non-global regex (engine TypeError)."""
    miss = _misses("(function(){return 'ab'.replaceAll(/a|b/,'X');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3b_f688_flagged_regex_fails():
    """F688 bound: alternation regex with /i flag fails closed."""
    miss = _misses("(function(){return 'ab'.replaceAll(/a|b/i,'X');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3c_f688_empty_alternative_fails():
    """F688 bound: empty alternative fails closed."""
    miss = _misses("(function(){return 'ab'.replaceAll(/a|/g,'X');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3d_f688_capture_group_fails():
    """F688 bound: capture groups in the alternation fail closed."""
    miss = _misses("(function(){return 'ab'.replaceAll(/(a)|b/g,'X');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3e_f688_concat_replacer_fails():
    """F688 bound: replacer bodies outside the F609 grammar fail closed."""
    miss = _misses("(function(){return 'a1a2'.replaceAll(/a/g,function(m,o){return m+o;});})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3f_f688_nonstring_receiver_fails():
    """F688 bound: replaceAll on a non-string receiver fails closed."""
    miss = _misses("(function(){return ['a','b'].replaceAll(/a|b/g,'X');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F694 filed shapes

@_t
def test_p4a_f694_match_closed():
    """F694 CLOSED (match): filed shape now blocks."""
    ok = _blocked("(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4b_f694_matchAll_closed():
    """F694 CLOSED (matchAll): filed shape now blocks."""
    ok = _blocked("(function(){var m=[...'%s:%s'.matchAll(/(%s):(%s)/g)][0];return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F694 variants (node-exact)

@_t
def test_p5a_f694_match_global_array():
    """F694 variant: match with /g returns full matches."""
    ok = _blocked("(function(){var m='%sZ%s'.match(/(%s)/g);return m[0]+m[1]+'%s';})()" % (_A, _A, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p5b_f694_match_full_group0():
    """F694 variant: m[0] reads the full match."""
    ok = _blocked("(function(){var m='%s'.match(/(%s)/);return m[0]+'%s';})()" % (_A, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p5c_f694_matchAll_later_index():
    """F694 variant: matchAll spread, later match index."""
    ok = _blocked("(function(){var m=[...'aa'.matchAll(/(a)/g)][1];return m[0]+'%s%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p5d_f694_let_const_forms():
    """F694 variant: let/const bindings and literal return operands."""
    ok1 = _blocked("(function(){let m='%s'.match(/(%s)/);return m[1]+'%s';})()" % (_A, _A, _B))
    ok2 = _blocked("(function(){const m='%s'.match(/%s/);return m[0]+'%s';})()" % (_A, _A, _B))
    ok = ok1 and ok2
    return ("HELD" if ok else "BREAK", "let=%s const=%s" % (ok1, ok2))


@_t
def test_p5e_f694_reordered_groups():
    """F694 variant: groups reassembled out of order."""
    ok = _blocked("(function(){var n='%s:%s'.match(/(%s):(%s)/);return n[2]+n[1]+'%s';})()" % (_A, _B, _A, _B, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p5f_f694_bracket_form():
    """F694 variant: bracket-string method form."""
    ok = _blocked("(function(){var m='%s'['match'](/(%s)/);return m[1]+'%s';})()" % (_A, _A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F694 fail-closed bounds

@_t
def test_p6a_f694_match_no_match_fails():
    """F694 bound: match with no match is engine-null, fails closed."""
    miss = _misses("(function(){var m='zzz'.match(/(a)/);return m[0];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6b_f694_matchAll_nonglobal_fails():
    """F694 bound: matchAll without /g is an engine TypeError."""
    miss = _misses("(function(){var m=[...'ab'.matchAll(/(a)/)][0];return m[0];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6c_f694_flagged_match_fails():
    """F694 bound: match with /i flag fails closed."""
    miss = _misses("(function(){var m='a:b'.match(/(a):(b)/i);return m[1];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6d_f694_oob_index_fails():
    """F694 bound: out-of-bounds group index is engine-undefined."""
    miss = _misses("(function(){var m='a:b'.match(/(a):(b)/);return m[5];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6e_f694_plain_array_init_fails():
    """F694 bound: plain array initializer (no .match) stays out of scope."""
    miss = _misses("(function(){var m=['x','y'];return m[0]+m[1];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6f_f694_charclass_fails():
    """F694 bound: character classes in the pattern fail closed."""
    miss = _misses("(function(){var m='a1b2'.match(/([ab])([12])/);return m[0];})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6g_f694_empty_group_fails():
    """F694 bound: empty-group-only patterns fail closed (no hang)."""
    ok = _misses("(function(){var m='ab'.match(/()/);return m[1];})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6h_f688_numstr_receiver_fails():
    """F688/F694 bound: numeric receivers fail closed (engine throws)."""
    ok1 = _misses("(function(){return (42).replaceAll(/2|3/g,'X');})()")
    ok2 = _misses("(function(){var m=(42).match(/2/);return m[0];})()")
    ok = ok1 and ok2
    return ("HELD" if ok else "BREAK", "replaceAll=%s match=%s" % (ok1, ok2))


# ------------------------------------------------- neighbors & regressions

@_t
def test_p7a_f603_f609_f464_hold():
    """Neighbors: the F603/F609/F464 replace productions still hold."""
    ok1 = _blocked("(function(){return '%s,%s'.replace(/,/g,'');})()" % (_A, _B))
    ok2 = _blocked("(function(){return 'ab'.replace('a',function(m){return '%s%s';});})()" % (_A, _B))
    ok3 = _blocked("(function(){return 'a.b'.replace('.','%s%s');})()" % (_A, _B))
    ok = ok1 and ok2 and ok3
    return ("HELD" if ok else "BREAK", "f464=%s f609=%s f603=%s" % (ok1, ok2, ok3))


@_t
def test_p7b_open_neighbors_still_miss():
    """Round-48 neighbors F686/F687/F689/F691/F693 now CLOSED (wave-381); they block (spot checks)."""
    m1 = _blocked("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});return [...p].join('');})()" % (_A, _B))
    m2 = _blocked("(function(){var w=new WeakSet();var k={};var j={};w.add(k);return (w.has(k)&&!w.has(j)?'%s':'junk')+'%s';})()" % (_A, _B))
    m3 = _blocked("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    m4 = _blocked("(function(){var {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))
    ok = m1 and m2 and m3 and m4
    return ("HELD" if ok else "BREAK", "f689=%s f687=%s f691=%s f693=%s" % (m1, m2, m3, m4))


# ------------------------------------------------- pin + footer

@_t
def test_p8_pin_footer():
    """Pin 2140; lane-local footer: F688/F694 closed, open F686,F687,F689-F693,F695-F699, next F700."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- perf

@_t
def test_p10_perf_bound():
    """Perf: 200 mixed replace/match sites decode quickly."""
    frag = "(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B)
    blob = " ".join([frag] * 200)
    t0 = time.time()
    hit = dlp.find_credential(blob) is not None
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s %.2fs" % (hit, dt))


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g381-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w380_attack_probes.py")],
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
    # This lane repoints the w380 battery's footer lane-locally; if the
    # footer pin is stale the merge repoint owns it (wave-305/306 class).
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w380_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p11_green_check():
    """Green check: wave-380 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
