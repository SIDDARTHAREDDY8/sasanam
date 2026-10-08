#!/usr/bin/env python3
"""Wave-377 lane 9: attack round 45 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (5, all LOW, all OPEN), filed from F655:
- F655: statement-IIFE multi-statement fragment accumulation -- 7 shapes
  (two-decl, decl+accum, switch-fallthrough, try-finally, do-while,
  with-statement, labeled-block).
- F656: generator .next().value fragment reads (F619 documented residual).
- F657: var-bound Map receiver in forEach accumulation (F601 gap).
- F658: flatMap with literal-array-returning callback (distinct from F554).
- F659: yield* spread assembly (F619 documented residual).

Mechanism notes (verified this round):
- The statement-IIFE parsers model only single-declaration+return bodies:
  `(function(){var s='A';return s+'B';})()` blocks, but two declaration
  statements or a decl+accum statement miss (F655). switch/do-while/with/
  labeled-block/try-finally wrappers are the same gap with different
  statement productions -- filed as one finding, not five.
- Round-44 declined to file switch/with as "outside the bounded
  expression-decoder seam". This round re-examined: the PLAIN two-decl
  form also misses, and F640/F641/F654 establish statement-IIFE bodies
  as in-scope. The seam is the statement-body parser, filed honestly.
- F619 (CLOSED) documents `.next().value` reads and `yield*` as
  fail-closed residuals; both are claimed here (F656, F659).
- F601 (CLOSED) requires an INLINE `new Map(...)` forEach receiver; a
  var-bound Map misses -- unlisted in F601's residuals (F657).
- F554 (CLOSED) models only the `.bind`-bound flatMap triple; a direct
  flatMap call with a literal-array-returning callback misses (F658).
All filed shapes node-verified EXACT (v24.20.0): 12/12 CRED-EXACT,
12/12 decoder-miss. Junk-quiet controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F644-F654 (rounds 44 + lane-1 residual), F655-F659 (this round).

Closed pins (must BLOCK, else BREAK): F510, F601, F612, F619.

Rides-with-documented-scope (validated, NOT filed):
- Custom Symbol.iterator for-of accumulation -- BREAK, but F653 (OPEN,
  round 44) already files that production; not re-filed.
- Array .entries() for-of with destructured `[i,v]` -- BREAK, but F651
  (OPEN, round 44) already files Array-iterator for-of; not re-filed.
- `(function*(){yield 'A';return 'B';})().return('B').value` -- malformed
  (assembles only the second fragment); discarded, not a decoder signal.
- async-generator `.next().then(r=>r.value)` -- returns a Promise, cannot
  be node-exact synchronously; discarded.
- Proxy ownKeys/get shape as hinted -- malformed (extra call); discarded.
- `if(true){...}` / `for` / `while` accumulation -- BREAK, same F655
  statement-body mechanism; documented as variants, not separate findings.
- `var a='f1',b='f2'` comma multi-decl -- BREAK, documented F612 residual;
  not re-filed.
Model note: 2/2 prompts returned usable hints (0 timeouts). The
control-flow hints (switch/do-while/try-finally/with) confirmed
locally-probed gaps; the protocol hints (Set spread, gen .return,
asyncgen .then, Proxy ownKeys, Reflect.get/apply) validated as
already-held or malformed. All filed shapes hand-crafted and
node-verified (v24.20.0). Junk-quiet controls pass.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000232
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
    """Control: lane-local footer shows F661 closed; F655-F660 open, next F662 (wave-378 lane 6)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F662**" in text  # Wave-378 lane 6: F661 CLOSED; footer repoint open F655-F660 / next F662
          and "Open findings: F655, F656, F657, F658, F659, F660." in text)  # Wave-378 lane 6: F661 CLOSED; footer repoint open F655-F660 / next F662
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f510_closed():
    """F510 CLOSED: inline Object.values still blocks."""
    ok = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f510=%s" % ok)


@_t
def test_p1_f601_closed():
    """F601 CLOSED: inline-Map forEach still blocks."""
    ok = _blocked("(function(){var s='';new Map([['k','%s'],['j','%s']]).forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f601=%s" % ok)


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


# ------------------------------------------------- F655 open pins (must miss)

@_t
def test_r45_f655_s1_open():
    """F655 OPEN (two declarations): miss reproduces."""
    miss = _misses("(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s2_open():
    """F655 OPEN (decl + accum statement): miss reproduces."""
    miss = _misses("(function(){var s='%s';s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s3_open():
    """F655 OPEN (switch fallthrough): miss reproduces."""
    miss = _misses("(function(){let s='';switch(1){case 1:s+='%s';case 2:s+='%s';}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s4_open():
    """F655 OPEN (try-finally): miss reproduces."""
    miss = _misses("(function(){let s='';try{s+='%s';}finally{s+='%s';}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s5_open():
    """F655 OPEN (do-while wrapper): miss reproduces."""
    miss = _misses("(function(){let s='';do{s+='%s';s+='%s';}while(false);return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s6_open():
    """F655 OPEN (with-statement wrapper): miss reproduces."""
    miss = _misses("(function(){let s='';with({}){s+='%s';s+='%s';}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f655_s7_open():
    """F655 OPEN (labeled-block wrapper): miss reproduces."""
    miss = _misses("(function(){let s='';blk:{s+='%s';break blk;s+='junk';}s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p1_f655_single_decl_closed():
    """Single-declaration body still blocks (F655 boundary)."""
    ok = _blocked("(function(){var s='%s';return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "single-decl=%s" % ok)


# ------------------------------------------------- F656 open pins (must miss)

@_t
def test_r45_f656_s1_open():
    """F656 OPEN (.next().value + concat): miss reproduces."""
    miss = _misses("(function*(){yield '%s';yield 'junk';})().next().value+'%s'" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f656_s2_open():
    """F656 OPEN (named gen .next().value): miss reproduces."""
    miss = _misses("(function(){var g=(function*(){yield '%s';})();return g.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F657 open pins (must miss)

@_t
def test_r45_f657_s1_open():
    """F657 OPEN (var-bound Map forEach): miss reproduces."""
    miss = _misses("(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f657_s2_open():
    """F657 OPEN (let-bound Map forEach arrow): miss reproduces."""
    miss = _misses("(function(){let m=new Map([['k','%s'],['j','%s']]);let s='';m.forEach((v)=>{s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F658 open pins (must miss)

@_t
def test_r45_f658_s1_open():
    """F658 OPEN (flatMap function callback): miss reproduces."""
    miss = _misses("['x'].flatMap(function(){return ['%s','%s'];}).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f658_s2_open():
    """F658 OPEN (flatMap arrow callback): miss reproduces."""
    miss = _misses("['x'].flatMap(()=>['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F659 open pins (must miss)

@_t
def test_r45_f659_s1_open():
    """F659 OPEN (yield* spread join): miss reproduces."""
    miss = _misses("[...(function*(){yield* ['%s','%s'];})()].join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r45_f659_s2_open():
    """F659 OPEN (named yield* gen): miss reproduces."""
    miss = _misses("(function(){var g=function*(){yield* ['%s','%s'];};return [...g()].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w376_attack_probes.py")],
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
    # The w376 battery's footer pin is stale by design: this lane filed
    # F655-F659, so its expected footer (open F640-F653 / next F654)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w376_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-376 attack battery stays green (depth-1)."""
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
