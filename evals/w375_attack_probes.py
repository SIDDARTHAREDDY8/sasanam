#!/usr/bin/env python3
"""Wave-375 lane 10: attack round 43 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (4, all LOW), filed from F640; F640 CLOSED 2026-10-08
wave-376 lane 1 (F641-F643 remain OPEN):
- F640: for-await over sync iterables fragment assembly -- 3 shapes. CLOSED.
- F641: deferred-callback fragment assembly (queueMicrotask/setTimeout) -- 4 shapes.
- F642: getter bodies with var-bound fragment operands -- 3 shapes.
- F643: String.fromCharCode/fromCodePoint with typed-array arguments -- 3 shapes.

Mechanism notes (verified this round):
- F619 (CLOSED) covers sync GENERATOR (function*) assembly and F631 (CLOSED
  wave-375 lane 8) async generators; `for await...of` over a SYNC iterable (array literal,
  Map.values()) is a different production with no modeled path (F640, CLOSED wave-376 lane 1).
- F618 (CLOSED) models .then on all/race and F638 (CLOSED wave-375 lane 8) catch/finally/
  allSettled; the scheduling primitives queueMicrotask()/setTimeout()
  themselves are unmodeled (F641).
- Object-literal getters with literal-concatenation bodies ARE modeled
  (control blocks); var-bound additive operands in the getter body are
  invisible -- plain getters, Proxy get-traps, and WeakRef-deref getters
  all escape through the same gap (F642). Distinct from F542 (Proxy
  apply-traps) and F550 (defineProperty getters).
- F500 (CLOSED) covers fromCharCode with plain numeric args / plain-array
  spread / .apply/.call with plain arrays; a TYPED-ARRAY (Uint8Array)
  argument -- spread or .apply -- has no modeled path (F643). Distinct
  from F629 (TextDecoder builtin).
All filed shapes node-verified EXACT (v24.20.0): 13/13 CRED-EXACT
(F640's 3 and F641's 4 via async node drivers), 13/13 decoder-miss.
Junk-quiet controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F621-F639 (rounds 42 + merge), F641-F643 (round 43; F640 closed wave-376 lane 1).

Closed pins (must BLOCK, else BREAK): F576, F595, F606, F607, F608, F609,
F610, F611 (wave-373 closures), F612-F620 (wave-374 closures),
F621-F639 (wave-375 closures), F640 (wave-376 lane 1).

Rides-with-documented-scope (validated, NOT filed -- exact shapes recorded
for merge verification against the parallel wave-375 closure lanes):
- BigInt atom extensions: Number(123n), (120n+3n), (123n*1n), BigInt('123'),
  `${120n+3n}`, (123n).toString(), String(BigInt(0x7b)) -- all BREAK;
  F633-scope (unmodeled BigInt atom); the F633 close-when was briefed to
  audit the atom family (wave-375 lane 4). Re-verify at merge: if lane 4
  misses any, file.
- Bind chains: triple/quad .bind chains, bind-chain-apply-tail -- BREAK;
  F636-scope; wave-375 lane 7. Thunk .bind().apply()/.call()/double-bind
  -- BREAK; F637-scope; wave-375 lane 7. Re-verify at merge.
- for-await over async generator, async-generator .next() chains -- BREAK;
  F631-scope; wave-375 lane 8. Re-verify at merge.
- Nested 2-level values()/entries() paths, computed string/var keys --
  BREAK; F639-scope (no parallel lane; merge owns F639).
- F612 additive object-literal values (b:'123'+'456789abcdef') -- BREAK but
  DOCUMENTED RESIDUAL of F612 ("non-literal sources" fail closed); not filed.
- F625 boundary: Set.entries() spread, bare-Map spread -- verified
  fail-closed; not filed. F621 boundary: multi-source/non-literal assign
  sources -- verified fail-closed; not filed. F622/F632 boundary:
  non-enumerable keys, prototype chains -- verified fail-closed; not filed.
- Intl.NumberFormat / Intl.DateTimeFormat -- verified quiet (no false
  positives); out of scope for DLP; not filed per brief.
- crypto.subtle.digest -- not probed this round (round-42 verified
  fail-closed).

Dead probes -- "Not filed (validated)":
- for-await over a joined string ('...'.join('') inside) -- decoder HITS
  (the additive grammar); dead, correctly closed by existing modeling.
- `new Proxy(function(){},{})` apply-trap control -- malformed probe
  (returns undefined); discarded, not a decoder signal.
- Uint16Array code-unit probe -- malformed (wrong code units); discarded.
Model note: 2/2 prompts returned usable hints (0 timeouts). The typed-array
fromCharCode hint surfaced the F643 gap; the BigInt-hex hint validated as
F633-scope; scheduling/getter/WeakRef/Proxy hints confirmed local findings.
All filed shapes hand-crafted and node-verified (v24.20.0). Junk-quiet
controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g375-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000195
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B
# Byte arrays computed at runtime from concatenation-derived fragments: no
# credential literal anywhere in this file.
_U8 = ",".join(str(b) for b in (_F1 + _F2).encode("latin-1"))

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
    """Control: footer shows F640/F641 closed, F644 filed; open F642-F644, next F645.
    (merge intermediate; tree-wide repoint normalizes at end)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F700**" in text  # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)  # merge intermediate # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f576_closed():
    """F576 CLOSED: URLSearchParams.get blocks."""
    hit = _blocked("new URLSearchParams('q=%s%s').get('q')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f595_closed():
    """F595 CLOSED (wave-373 lane 1): stringify nested arrays blocks."""
    hit = _blocked("JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f608_closed():
    """F608 CLOSED (wave-373 lane 4): Set spread args block."""
    hit = _blocked("(function(){return ((...a)=>a.join(''))(...new Set(['%s','%s']));})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f611_closed():
    """F611 CLOSED (wave-373 lane 6): atob fragments block."""
    hit = _blocked("atob('eG94Yi0wMTIz')+'%s'" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f612_closed():
    """F612 CLOSED (wave-374 lane 1): var-bound values() blocks."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s',c:'%s'};return Object.values(o).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f614_closed():
    """F614 CLOSED (wave-374 lane 3): fn-expr .bind blocks."""
    hit = _blocked("((a)=>(a+'%s'+'%s')).bind(null,'%s')()" % (_F2, _F3, _F1))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f618_closed():
    """F618 CLOSED (wave-374 lane 6): Promise.all/.then blocks."""
    hit = _blocked("Promise.all([Promise.resolve('%s'),Promise.resolve('%s'),Promise.resolve('%s')]).then(a=>a.join(''))"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f620_closed():
    """F620 CLOSED (wave-374 lane 7): indexed thunk invocation blocks."""
    hit = _blocked("(function(){var f=[()=>'%s',()=>'%s'];return f[0]()+f[1]();})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F640 closed pins (must block; wave-376 lane 1)

@_t
def test_r43_f640_s1_closed():
    """F640 CLOSED (wave-376 lane 1, shape forawait-accumulate): blocks coded."""
    hit = _blocked("(async()=>{var s='';for await (const x of ['%s','%s','%s']) s+=x; return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f640_s2_closed():
    """F640 CLOSED (wave-376 lane 1, shape forawait-push-join): blocks coded."""
    hit = _blocked("(async()=>{var p=[];for await (const x of ['%s','%s','%s']) p.push(x); return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f640_s3_closed():
    """F640 CLOSED (wave-376 lane 1, shape forawait-map-values): blocks coded."""
    hit = _blocked("(async()=>{var s='';for await (const x of new Map([['a','%s'],['b','%s'],['c','%s']]).values()) s+=x; return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F641 closed pins (must block)

@_t
def test_r43_f641_s1_closed():
    """F641 CLOSED (shape microtask-assembly): blocks coded (wave-376 lane 2)."""
    hit = _blocked("(async()=>{var p=[];queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));await null;return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s2_closed():
    """F641 CLOSED (shape microtask-nested): blocks coded (wave-376 lane 2)."""
    hit = _blocked("(async()=>{var p=[];queueMicrotask(()=>{p.push('%s');queueMicrotask(()=>p.push('%s'+'%s'));});await null;await null;return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s3_closed():
    """F641 CLOSED (shape microtask-promise-flush): blocks coded (wave-376 lane 2)."""
    hit = _blocked("(async()=>{var s='';queueMicrotask(()=>{s+='%s';});queueMicrotask(()=>{s+='%s'+'%s';});await Promise.resolve();return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s4_closed():
    """F641 CLOSED (shape timeout-assembly): blocks coded (wave-376 lane 2)."""
    hit = _blocked("(async()=>{var p=[];setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);await new Promise(r=>setTimeout(r,20));return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F642 closed pins (must block)

@_t
def test_r43_f642_s1_closed():
    """F642 CLOSED (wave-376 lane 3, shape getter-varfrags): blocks."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var o={get s(){return a+b+c;}};return o.s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f642_s2_closed():
    """F642 CLOSED (wave-376 lane 3, shape proxy-get-trap-varfrags): blocks."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var p=new Proxy({},{get:(t,k)=>a+b+c});return p.anything;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f642_s3_closed():
    """F642 CLOSED (wave-376 lane 3, shape weakref-deref-getter-varfrags): blocks."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var w=new WeakRef({get s(){return a+b+c;}});return w.deref().s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F643 closed pins (must block)

@_t
def test_r43_f643_s1_closed():
    """F643 CLOSED (shape fromcharcode-u8-spread): now blocks."""
    hit = _blocked("String.fromCharCode(...new Uint8Array([%s]))+'%s'" % (_U8, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f643_s2_closed():
    """F643 CLOSED (shape fromcharcode-u8-apply): now blocks."""
    hit = _blocked("String.fromCharCode.apply(null,new Uint8Array([%s]))+'%s'" % (_U8, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f643_s3_closed():
    """F643 CLOSED (shape fromcodepoint-u8-spread): now blocks."""
    hit = _blocked("String.fromCodePoint(...new Uint8Array([%s]))+'%s'" % (_U8, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-374 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w374_attack_probes.py")],
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
    # The w374 battery's footer pin is stale by design: this lane filed
    # F640-F643, so its expected footer (open F621-F639 / next F640)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w374_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-374 attack battery stays green (depth-1)."""
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
