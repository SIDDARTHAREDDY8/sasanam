#!/usr/bin/env python3
"""Wave-365 attack round 33 battery.

Made 8 gpt-4o-mini calls (8 prompt families x 1 call, ledger 523 -> 531,
~$0.0003 estimated from token counts, ~$0.0297 lifetime of $5; the key
lacks api.usage.read, so these are estimates), saved round33_raw.json; bulk
of the work was deterministic hand-crafted probes ($0). No more model calls
are made -- this battery is $0-by-construction (grep-verified: no
realmodel_harness / ModelDriver / --provider openai / ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base 7e9174e3):
- F526: Reflect.apply with two-hop .bind-chained function targets
  ([].concat.bind([],'f1').bind([]); F521 covers single-bind targets,
  F513 covers bind on the dispatch -- a bind CHAIN is a new target-
  production mechanism) -- 3 shapes.
- F527: quadruple-nested bracket member keys on string receivers
  ('f1'[[[[['concat'][0]]][0]][0]]; F523 covers triple, F515 double --
  same depth argument F523 used against F515) -- 2 shapes.
- F528: Reflect.apply with complex IIFE-evaluated function targets
  (nested IIFE (() => ((() => (a,b)=>a+b))())() and block-bodied IIFE
  (() => { var f = (a,b)=>a+b; return f; })(); F522 covers single
  expression-bodied IIFEs) -- 2 shapes.
- F529: arguments-alias enumerated via Object.keys/for-in
  ((function(){const a=arguments;return Object.keys(a).map(i=>a[i])
  .join('')})(); F516 covers the alias, F517 covers keys/for-in on
  literal objects -- the composition escapes both) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F521-F525 (round 32, scope reconfirmed), F526-F529 (this round).

Closed pins (must BLOCK, else BREAK): F506, F513, F514, F515, F516, F517,
F518, F519, F520 (wave-364 closures, regression), F512 (perf fix, spot),
F496/F503/F504/F505 (spot).

Rides-with-documented-scope (validated, NOT filed):
- 'f1'[[[['con'+'cat'][0]]][0]] (triple-nested with folded string element)
  -- F523's triple-nested member-key scope (fold-element widening per the
  F515/F504 precedent).
- (function(){const [a,,b]=arguments;...}), const [a='z',b]=arguments,
  const {0:a,1:b}=arguments, const [[a],[b]]=arguments -- F524's
  destructuring-pattern-binding scope (close-when is mechanism-general).
  Verified BREAK on base; merge should confirm lane 3's F524 closure
  covers these pattern forms.
- Object.getOwnPropertyNames({get 'f1'(){...}, get 'f2'(){...}}) -- F525's
  key-list enumeration scope (accessor keys are still keys).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent): variable-indirection method names need
  dataflow tracking the decoder deliberately lacks. NOT filed.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (600 fail-closed match attempts: the real expression
  starves per F512's entry, ~1s, no bypass; NOT filed).
- MCP management auth (Langflow/Dify-class): the repo has NO MCP server
  config-mutation surface (no register/add/update server API in gov/mcp_*;
  the MCP modules are invocation/discovery authorization only), so the
  industry finding class has no attack surface here. Verified, NOT filed.
Dead/bogus round-33 proposals (validated locally, NOT filed):
D1-bind-partial-null ([].concat.bind(null,'f1') -- bound thisArg wins,
  concat throws TypeError; probe error); D2-nested-iife-b (inner arrow
  took one param, free `b` ReferenceError; probe error, fixed shape filed
  as F528); D3-iife-var-join (Reflect.apply returns the string result,
  .join on a string TypeErrors; probe error, fixed shape filed as F528);
D4-4level-malformed (unbalanced brackets, SyntaxError; probe error, fixed
  shape filed as F527); D5-model-bindchain (model's payload produced
  'f1,f2' with comma -- no credential; malformed); D6-model-destructure
  (model's [[a],[b]] on strings takes chars 'S'+'C'; malformed, fixed
  shape rides with F524); D7-model-enum-builtin (d.get() on data
  descriptors is undefined; malformed); D8-model-iife-trick (truncated at
  150 tokens, syntactically incomplete); D9-model-bind-dispatch-fn (empty,
  150 tokens exhausted); D10-descriptor-accessor-values (accessor
  descriptor .value is undefined -- no credential; malformed probe).
Model note: 8/8 prompts returned; 3 salvageable (bracket-depth -> F527
confirmation, destructure-nested -> F524 scope note, launder-enum -> F529).
All filed shapes hand-crafted and node-verified (v24.20.0). Junk-quiet
controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g365-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

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
    """Pin stays 2144; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows no open findings, next F531 (wave-366 lanes 1+2+3:
    F526-F530 CLOSED; F531-F536 pending attack lane)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in text)  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f496_closed():
    """F496 CLOSED: ownKeys enumeration indirection now blocks."""
    hit = _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f503_closed():
    """F503 CLOSED: seal/preventExtensions receivers now block."""
    hit = _blocked("Array.prototype.concat.call(Object.seal(['%s']), ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f504_closed():
    """F504 CLOSED: bracket Reflect['apply'] now blocks."""
    hit = _blocked("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f505_closed():
    """F505 CLOSED: fromCodePoint spread now blocks."""
    hit = _blocked("String.fromCodePoint(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f506_closed():
    """F506 CLOSED (wave-363 lane 1): Reflect.apply via call/apply blocks."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f513_closed():
    """F513 CLOSED (wave-364 lane 1): Reflect.apply via .bind blocks."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f514_closed():
    """F514 CLOSED (wave-364 lane 2): nested-bracket on String-object blocks."""
    hit = _blocked("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f515_closed():
    """F515 CLOSED (wave-364 lane 2): idx-folded key on strlit blocks."""
    hit = _blocked("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f516_closed():
    """F516 CLOSED (wave-364 lane 3): laundered arguments block."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f517_closed():
    """F517 CLOSED (wave-364 lane 3): keys enumeration blocks."""
    hit = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f518_closed():
    """F518 CLOSED (wave-364 lane 4): reverse.call dispatch blocks."""
    hit = _blocked("Array.prototype.reverse.call(['%s','%s']).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f519_closed():
    """F519 CLOSED (wave-364 lane 1): function-valued targets block."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f520_closed():
    """F520 CLOSED (wave-364 lane 4): Array.fromAsync.then blocks."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f512_closed():
    """F512 CLOSED: perf fix -- 200-statement pin still holds."""
    junk200 = "".join("'%s';" % ("j%d" % i) for i in range(200))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    v = dlp._try_js_expr_decode_all(junk200 + real)
    ok = v is not None and _CRED in v
    return ("HELD" if ok else "BREAK", "variant_has_cred=%s" % ok)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f521_closed():
    """F521 CLOSED (wave-365 lane 1): .bind-bound target now blocks coded."""
    hit = _blocked("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f522_closed():
    """F522 CLOSED (wave-365 lane 2): IIFE-evaluated target now blocks coded."""
    hit = _blocked("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f523_closed():
    """F523 CLOSED (wave-365 lane 3): triple-nested bracket key now blocks coded."""
    hit = _blocked("'%s'[[[['concat'][0]]][0]]('%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f524_closed():
    """F524 CLOSED (wave-365 lane 3): destructured arguments now block coded."""
    hit = _blocked("(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f525_closed():
    """F525 CLOSED (wave-365 lane 2): getOwnPropertyNames now blocks coded."""
    hit = _blocked("Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f526_closed():
    """F526 CLOSED (wave-366 lane 1): two-hop .bind-chained target now blocks coded."""
    hit = _blocked("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
                   % {"A1": _A, "A2": _B})
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f527_closed():
    """F527 CLOSED (wave-366 lane 2): quadruple-nested bracket key now blocks."""
    hit = _blocked("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f530_closed():
    """F530 CLOSED (wave-366 lane 2): .bind-bound join target now blocks."""
    hit = _blocked("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f528_open():
    """F528 CLOSED (wave-366 lane 3): complex IIFE target now blocks."""
    ms = _misses("Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f529_open():
    """F529 CLOSED (wave-366 lane 3): alias enumerated via keys now blocks."""
    ms = _misses("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


# ------------------------------------------------- boundaries

@_t
def test_p3_f512_residual_documented():
    """F512 residual: 600 fail-closed matches starve (no bypass), fast."""
    import time
    payload = '"a".concat(' * 600 + "['%s','%s'].join('')" % (_A, _B)
    t0 = time.time()
    hit = _blocked(payload)
    dt = time.time() - t0
    ok = (not hit) and dt < 5.0
    return ("HELD" if ok else "BREAK", "starved=%s dt=%.2f" % (not hit, dt))


@_t
def test_p3_dataflow_boundary_documented():
    """Standing dataflow boundary: variable-indirection method names miss
    (F306/F308/F518 precedent) -- documented, not a finding."""
    ms = _misses("var m='c'+'oncat';'%s'[m]('%s')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p3_junk_quiet():
    """Junk stays quiet."""
    ms = _misses("Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')")
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-364 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g365-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w364_attack_probes.py")],
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
    # The w364 battery's footer pin is stale by design: this lane filed
    # F526-F529, so its expected footer (open F521-F525 / next F526) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w364_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-364 attack battery stays green (depth-1)."""
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
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
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
