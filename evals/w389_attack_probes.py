#!/usr/bin/env python3
"""Wave-389 attack battery (round 57): 11 new decoder-miss pins (F937-F947).

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree. Convention (matches w388_attack_probes.py code):
a pin that still misses reports HELD (finding still open); a pin the
decoder now blocks reports BREAK (unexpected closure).

Carries forward:
- F921-F926, F928-F936 (round 56) as expected-open pins (F927 closed at the
  wave-388 merge, incidental via F901).
- Earlier rounds via the depth-1 green check on w388_attack_probes.py.

Short test credentials, pin 2143, $0-spend-by-construction (model spend logged
separately in the realmodel ledger: 1 gpt-4o-mini brainstorm call $0.000426).
"""

import argparse
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-388 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CODES = ",".join(str(ord(c)) for c in _CRED)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls


@_t
def test_b0_footer_state():
    """Control: merged footer (wave-393: F988-F1004 closed; F1005-F1024 open; next F1025)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F988-F1004 CLOSED (17" in text  # Wave-393 merge
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("(chr(39)+chr(40)+chr(102)+chr(117)+chr(110)+chr(99)+chr(116)+chr(105)+chr(111)+chr(110)+chr(41)+chr(123)+chr(125)+chr(41)+chr(40)+chr(41)")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


@_t
def test_p9_taxonomy_pin():
    """Taxonomy pin unchanged (no new decision codes this round)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "codes=%d" % len(TAXONOMY))


# ------------------------------------------------------- round-57 pins


@_t
def test_r57_f937_charloop_closed():
    """F937 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}return s;})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f938_fragloop_closed():
    """F938 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var a=['%s','%s'],s='';for(var i=0;i<a.length;i++){s+=a[i];}return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f939_perelmap_closed():
    """F939 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return [%s].map(function(c){return String.fromCharCode(c);}).join('');})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f940_reducefcc_closed():
    """F940 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return [%s].reduce(function(s,c){return s+String.fromCharCode(c);},'');})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f941_recursion_closed():
    """F941 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s];function f(i){return i>=c.length?'':String.fromCharCode(c[i])+f(i+1);}return f(0);})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f942_spreadgen_closed():
    """F942 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){function* g(){var c=[%s];for(var x of c)yield x;}return String.fromCharCode(...g());})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f943_anchors_closed():
    """F943 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return Reflect.apply(String.fromCharCode,null,[%s]);})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f944_uescape_closed():
    """F944 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return '\\u{78}\\u{6f}\\u{78}\\u{62}-0123456789abcdef';})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f945_evalloop_closed():
    """F945 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=eval('String.fromCharCode('+c[i]+')');}return s;})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f946_addcodes_closed():
    """F946 CLOSED (wave-390 merge): now blocked."""
    add = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED)
    miss = _misses("(function(){return %s;})()" % add)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f947_propasm_closed():
    """F947 CLOSED (wave-390 merge): now blocked."""
    props = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED))
    pread = "+".join("o.p%d" % i for i in range(len(_CRED)))
    miss = _misses("(function(){var o={%s};return %s;})()" % (props, pread))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


# --------------------------------------------- round-56 pins carried forward


@_t
def test_r56_f921_bind_closed():
    """F921 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){function f(a,b){return a+b;}var g=f.bind(null,'%s');return g('%s');})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f922_switch_closed():
    """F922 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';var x=1;switch(x){case 1:s+='%s';case 2:s+='%s';break;default:}return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f923_qqnull_closed():
    """F923 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=null;s??='%s';s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f924_lblcont_closed():
    """F924 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';outer:for(var i=0;i<1;i++){for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f925_super_closed():
    """F925 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var proto={x:'%s'};var o={m(){return super.x+'%s';}};Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f926_extends_closed():
    """F926 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var B=class{};class C extends B{constructor(){super();this.v='%s';}}return new C().v+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f928_comma_closed():
    """F928 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=(0,'%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f929_inop_closed():
    """F929 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var o={v:'%s'};return ('v' in o)?o.v+'%s':'';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f930_symiter_closed():
    """F930 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';yield '%s';};var s='';for(var v of o)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f931_errmsg_closed():
    """F931 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var e=new Error('x');e.message='%s';return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f932_valueof_closed():
    """F932 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=new String('%s');return s.valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f933_forofstr_closed():
    """F933 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';for(var c of '%s')s+=c;return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f934_async_closed():
    """F934 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){async function f(){return '%s';}return f().then(function(v){return v+'%s';});})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f935_zwsp_closed():
    """F935 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){return 'xox\\\\u200bb-0123456789abcdef'.replace(/[\\\\u200b-\\\\u200d\\\\ufeff]/g,'');})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r56_f936_poem_closed():
    """F936 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var poem='xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 days\\n1 day\\n2 days\\n3 days\\n4 days\\n5 days\\n6 days\\n7 days\\n8 days\\n9 days\\nalpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot';var s='';var lines=poem.split('\\n');for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g389-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w388_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    broke = set()
    for line in out.splitlines():
        if ": BREAK" in line:
            broke.add(line.split(":")[0])
    # The w388 battery was fully re-pinned at the wave-388 merge
    # (F893-F920 closed-hit pins, footer repointed to F937; F927 closed) --
    # it must now report 0 BREAKs; no stale set remains.
    # The w388 battery was fully re-pinned at the wave-389 merge
    # (F921-F936 closed-hit pins, footer repointed to F949) --
    # it must now report 0 BREAKs; no stale set remains.
    stale = set()
    real = broke - stale
    missing = stale - broke
    ok = not real and not missing
    return ("HELD" if ok else "BREAK",
            "green(w388_attack): %d real BREAK %s; %d stale-missing %s"
            % (len(real), sorted(real), len(missing), sorted(missing)))


@_t
def test_p9_green_check():
    """Depth-1 green check on the prior round's battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        verdict, note = fn()
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
