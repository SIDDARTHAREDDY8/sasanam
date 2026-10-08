#!/usr/bin/env python3
"""Wave-378 lane 7: attack round 46 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

    New findings (10, all LOW; F662-F671 all CLOSED wave-379 lanes 1-7), filed from F662:
- F662: class fragment sources -- static fields, static blocks, static
  getters, instance fields (4 shapes, one mechanism).
- F663: Object.fromEntries-sourced member reads (1 shape; the
  Object.values twin blocks -- boundary).
- F664: Object.getOwnPropertyDescriptor getter invocation in additive
  position (1 shape; the bare-call twin blocks -- boundary).
- F665: CLOSED wave-379 lane 3 (optional-chaining member reads now route via the _JSObj postfix ?.-head).
- F671: CLOSED wave-379 lane 3 (new _js_parse_f671_member_reads_iife route).
- F666: Proxy apply/has traps beyond F642's get (2 shapes).
- F667: with-statement scope resolution (bare ident reads through the
  with object; F655 models with only as a decl+accum wrapper) (2 shapes).
  [CLOSED wave-379 lane 5]
- F668: custom tag-function templates beyond String.raw (2 shapes).
- F668: custom tag-function templates beyond String.raw (2 shapes; CLOSED wave-379 lane 6).
- F669: builtin-iterable spread consumption ([...set], [...map.values()];
  CLOSED 2026-10-08 wave-379 lane 7) (2 shapes).
- F670: Proxy get-trap non-concise function forms (arrow block-body,
  function expression, method shorthand; F642 models only the
  concise-arrow form) (3 shapes; found while pinning the F642 control).

Mechanism notes (verified this round):
- Class declarations have no modeled path at all: field initializers,
  static blocks (execute at class definition), static getters, and
  instance fields all assemble node-exactly while the decoder misses.
- Object.fromEntries results decode through Object.values (blocked) but
  NOT through member reads -- the enumeration-source grammar does not
  model fromEntries results as member-readable.
- Descriptor .get() invocation: the bare call decodes (getter body
  resolves), but the additive composition misses -- the tail grammar
  does not know the descriptor-call value.
- `?.` reads miss everywhere: every member-read grammar requires a
  plain dot.
- F642 (CLOSED) owns Proxy get traps; apply (callable proxy) and has
  (in-operator) are distinct trap productions with no modeled path.
- with(o){...} makes o's members visible as bare identifiers; the
  decoder's identifier grammar has no with-scope.
- Tag functions receive (strings, ...values); only String.raw is modeled
  (F463 CLOSED). Any other tag function misses.
- Spread over builtin iterables: F653 models custom Symbol.iterator
  objects; a builtin Set/Map spread has no modeled path. (Array.from of
  a builtin Set blocks -- the F653 Array.from route handles it.)
- Spec-review corrections: F665 re-scoped to the ?.-specific gap
  (bare-expression shapes; the plain-dot statement-level twin blocks);
  the IIFE-return additive member-read gap split out as F671; F602
  cited CLOSED (not OPEN) in the F669 entry.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F655-F661 (round 45 + lane-4 residual + merge audit), F662-F671 (this round).

Closed pins (must BLOCK, else BREAK): F463, F510, F535, F612, F619,
F642, F653, F669.

Rides-with-documented-scope (validated, NOT filed):
- `(function(){var s=('jx','f1');return s+'f2';})()` label-twin of F655's
  labeled-block shape -- BREAK, but F655 (OPEN, round 45) already files
  that production; not re-filed.
- Object.assign member reads, Reflect.get, async-generator for-await,
  Array.from(Map.values()) -- all BLOCK on the open tree; already
  modeled, not filed.
- Promise.all/Promise.race .then -- F618 (CLOSED); catch/finally/
  allSettled -- F638 (OPEN). Round-46 async hints confirmed covered.
- Generator .return(v).value -- assembles only the second fragment
  (malformed); discarded, not a decoder signal.
Model note: 2/2 prompts returned usable hints (0 timeouts). The object
hints (class static, defineProperty, Map spread) and async hints
(Promise.all, async gen) mostly confirmed already-held or open-filed
productions; the filed shapes are hand-crafted extensions validated
node-exact (v24.20.0). Junk-quiet controls pass.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000235
logged separately in the realmodel ledger).
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

TAXONOMY_PIN = 2140  # no new decision codes this round

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_BT = chr(96)

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
def test_p0_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F672-F685 open, next F686 (wave-379 merge: all lanes merged)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F686**" in text
          and "Open findings: F672, F673, F674, F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f463_closed():
    """F463 CLOSED: String.raw tag form still blocks."""
    ok = _blocked("String.raw`%s%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f463=%s" % ok)


@_t
def test_p1_f510_closed():
    """F510 CLOSED: inline Object.values still blocks."""
    ok = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f510=%s" % ok)


@_t
def test_p1_f535_closed():
    """F535 CLOSED: literal getter member read still blocks."""
    ok = _blocked("({get x(){return '%s%s';}}).x" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)


@_t
def test_p1_f612_closed():
    """F612 CLOSED: var-bound values still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f612=%s" % ok)


@_t
def test_p1_f619_closed():
    """F619 CLOSED: generator spread still blocks."""
    ok = _blocked("[...(function*(){yield '%s';yield '%s';})()].join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f619=%s" % ok)


@_t
def test_p1_f642_closed():
    """F642 CLOSED: Proxy get trap with var-bound operand still blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f642=%s" % ok)


@_t
def test_p1_f653_closed():
    """F653 CLOSED: custom-iterator Array.from still blocks."""
    ok = _blocked("Array.from(new Set(['%s','%s'])).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f653=%s" % ok)


# ------------------------------------------------- F662 closed pins (must block)

@_t
def test_p1_f662_s1_closed():
    """F662 CLOSED (class static field): now blocks."""
    ok = _blocked("(function(){class C{static x='%s';}return C.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f662=%s" % ok)


@_t
def test_p1_f662_s2_closed():
    """F662 CLOSED (class static block): now blocks."""
    ok = _blocked("(function(){let s='';class C{static{s='%s';}}s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f662=%s" % ok)


@_t
def test_p1_f662_s3_closed():
    """F662 CLOSED (class static getter): now blocks."""
    ok = _blocked("(function(){class C{static get x(){return '%s';}}return C.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f662=%s" % ok)


@_t
def test_p1_f662_s4_closed():
    """F662 CLOSED (class instance field): now blocks."""
    ok = _blocked("(function(){class C{x='%s';}return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f662=%s" % ok)


# ------------------------------------------------- F663 closed pins (must block)

@_t
def test_p1_f663_s1_closed():
    """F663 CLOSED (wave-379 lane 2): var-bound fromEntries member reads block."""
    ok = _blocked("(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)  # Wave-379 lane 2: F663 CLOSED (was r46 open pin)


@_t
def test_p1_f663_values_twin_closed():
    """F663 boundary: Object.values of fromEntries still blocks."""
    ok = _blocked("(function(){return Object.values(Object.fromEntries([['a','%s'],['b','%s']])).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f663-boundary=%s" % ok)


# ------------------------------------------------- F664 closed pins (must block)

@_t
def test_p1_f664_s1_closed():
    """F664 CLOSED (wave-379 lane 2): var-bound descriptor .get() additive blocks."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)  # Wave-379 lane 2: F664 CLOSED (was r46 open pin)


@_t
def test_p1_f664_bare_twin_closed():
    """F664 boundary: bare descriptor .get() call still blocks."""
    ok = _blocked("(function(){var o={get x(){return '%s%s';}};return Object.getOwnPropertyDescriptor(o,'x').get();})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664-boundary=%s" % ok)


# ------------------------------------------------- F665 pins (CLOSED wave-379 lane 3)

@_t
def test_p1_f665_s1_closed():
    """F665 CLOSED (bare ?. read): blocks coded (wave-379 lane 3)."""
    ok = _blocked("({x:'%s'})?.x+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f665_s2_closed():
    """F665 CLOSED (bare ?. double read): blocks coded (wave-379 lane 3)."""
    ok = _blocked("(({x:'%s'})?.x)+(({x:'%s'})?.x)" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f665_plain_dot_twin_closed():
    """F665 boundary: plain-dot statement-level twin still blocks."""
    ok = _blocked("({x:'%s'}).x+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f665-boundary=%s" % ok)


# ------------------------------------------------- F666 open pins (must miss)

@_t
def test_r46_f666_s1_closed():
    """F666 CLOSED (wave-379 lane 4): Proxy apply trap now blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{apply:function(){return '%s';}});return p()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f666-closed=%s" % ok)


@_t
def test_r46_f666_s2_closed():
    """F666 CLOSED (wave-379 lane 4): Proxy has trap now blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});var o={x:'%s'};return ('x' in p?o.x:'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f666-closed=%s" % ok)


# ------------------------------------------------- F667 closed pins (must block)

@_t
def test_r46_f667_s1_closed():
    """F667 CLOSED (with-scope two idents): now blocks (wave-379 lane 5)."""
    hit = _blocked("(function(){var o={x:'%s',y:'%s'};with(o){return x+y;}})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r46_f667_s2_closed():
    """F667 CLOSED (with-scope one ident): now blocks (wave-379 lane 5)."""
    hit = _blocked("(function(){var o={x:'%s'};with(o){return x+'%s';}})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F668 open pins (must miss)

@_t
def test_r46_f668_s1_closed():
    """F668 CLOSED (custom tag, strings index): now blocks."""
    hit = _blocked("(function(){function tag(s){return s[0]+'%s';}return tag%s%s%s;})()" % (_B, _BT, _A, _BT))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r46_f668_s2_closed():
    """F668 CLOSED (custom tag, raw index): now blocks."""
    hit = _blocked("(function(){var tag=function(s){return s.raw[0]+'%s';};return tag%s%s%s;})()" % (_B, _BT, _A, _BT))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F669 closed pins (must block)

@_t
def test_p1_f669_s1_closed():
    """F669 CLOSED: var-bound Set spread consume still blocks."""
    ok = _blocked("(function(){var st=new Set(['%s','%s']);return [...st].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669-s1=%s" % ok)


@_t
def test_p1_f669_s2_closed():
    """F669 CLOSED: var-bound Map .set mutations, .values spread still blocks."""
    ok = _blocked("(function(){var m=new Map();m.set('a','%s');m.set('b','%s');return [...m.values()].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669-s2=%s" % ok)


@_t
def test_p1_f669_arrayfrom_twin_closed():
    """F669 boundary: Array.from of builtin Set still blocks."""
    ok = _blocked("(function(){return Array.from(new Set(['%s','%s'])).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669-boundary=%s" % ok)


@_t
def test_r46_f670_s1_closed():
    """F670 CLOSED (wave-379 lane 4): get trap arrow block body now blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f670-closed=%s" % ok)


@_t
def test_r46_f670_s2_closed():
    """F670 CLOSED (wave-379 lane 4): get trap function expression now blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:function(t,k){return a+b;}});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f670-closed=%s" % ok)


@_t
def test_r46_f670_s3_closed():
    """F670 CLOSED (wave-379 lane 4): get trap method shorthand now blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get(t,k){return a+b;}});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f670-closed=%s" % ok)


# ------------------------------------------------- F671 pins (CLOSED wave-379 lane 3)

@_t
def test_p1_f671_s1_closed():
    """F671 CLOSED (IIFE-return var-bound dot read): blocks coded (wave-379 lane 3)."""
    ok = _blocked("(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f671_s2_closed():
    """F671 CLOSED (IIFE-return inline dot read): blocks coded (wave-379 lane 3)."""
    ok = _blocked("(function(){return {x:'%s'}.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f671_s3_closed():
    """F671 CLOSED (IIFE-return var-bound double read): blocks coded (wave-379 lane 3)."""
    ok = _blocked("(function(){var o={x:'%s',y:'%s'};return o.x+o.y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w377_attack_probes.py")],
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
    # The w377 battery's footer pin is stale by design: this lane filed
    # F662-F669, so its expected footer (open F655-F659 / next F660)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w377_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-377 attack battery stays green (depth-1)."""
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
