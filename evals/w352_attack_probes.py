#!/usr/bin/env python3
"""Wave-352 attack round 20 regression battery.

Two workstreams this round:

(A) Re-validation of the wave-351 round-19 validated-but-unfiled bypasses
against the wave-351-merged base (76611c0b: F451/F452/F453 closed,
F454-F460 open). All 8 re-validated (node ground truth + scanner MISS)
and filed as F461-F468 (all LOW, OPEN, red-first verified):
- F461: ['b','a'].reverse().join('') -- array-reversal primitive; no
        .reverse() model in the chain grammar.
- F462: ''.concat(...['a','b']) -- spread-args concat; concat model takes
        only literal args.
- F463: ['a','b'].join`` `` -- join invoked as a tagged template; the
        template-strings array [''] becomes the separator.
- F464: ['a','b'].toString().replace(/,/g,'') -- string-rewrite primitive;
        distinct from F460 (.map(String)).
- F465: '89abcdef'.padStart(21,'xoxb-012345678') -- padding primitive
        (fragment-split so neither literal trips the plain slack seam).
- F466: ['a','b'].slice(0,2).join('') -- unmodeled no-op chain step.
- F467: ['a','b',''].filter(x=>x!==null) -- constant-true comparison
        predicate; F443 modeled only bare-Boolean, F447's domain reasoning
        covers x!=='' but not !==null; distinct from F459 (positional).
- F468: Reflect.construct(Array,['a','b']) -- reflection-API Array factory;
        distinct from F454 (direct syntax) and F446 (Array.of).

(B) Model-driven probes (gpt-4o-mini, 6 calls, ~$0.000394) against the
fresh F451/F452/F453 closure boundaries (whitespace-tolerant hex spans;
decode-producing budget; ws-b64 fixpoint seeding) plus adjacent primitive
gaps. Proposals validated locally (node ground truth + scanner verdict).
No new findings: the genuine misses are scope notes on F454/F464/F467
(pinned below); the rest were dead or bogus (documented below).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F454-F460 (wave-351, still open), F461-F468 (this round).

Scope confirmed (still as documented):
- F451 / F452 / F453 pinned CLOSED (wave-351 merge).
- F444 ~130+ junk residual: misses (bounded-budget residual, not a finding).
- F439 depth-4 base64: misses (documented non-goal); depth-3 blocks.
- F446 `[].constructor.of` / `Array['of']`: miss (honest residual).
- F447 free-variable predicates: correctly fail closed (no static binding).
- F452 70-decodable-junk pin: still blocks (F444 composition intact).
- F453 ws-b64-over-hex: still misses (documented residual, not a new number).

Round-20 scope notes (model-driven, validated, NOT new findings -- each
rides with the cited close-when):
- F467 x C5: x=>x!==undefined and function(x){return x!=null;} are the same
  constant-true null-comparison mechanism (pinned: test_b5_*).
- F454 x C6: new Array(...['a','b']) desugars to the multi-arg constructor
  (pinned: test_b5_f454_spread_new_open).
- F464 x C4: .flat()/.splice(0,2) are unmodeled no-ops ahead of the
  toString+replace -- same composition class as F466 (pinned).

Dead/bogus round-20 proposals (validated locally, NOT filed): C1
non-hex-char insertion and '-'/'/' hex splitting (bytes.fromhex rejects --
bogus); C1 varying-whitespace hex (BLOCKED -- F451 strips all whitespace);
C2 String.fromCharCode(72,...) decimal junk (BLOCKED -- claimed surface;
only useful as F444-class junk, a known residual); C2 "Goodbye".replace
junk (fails closed -- not decode-producing); C3 URL-encoded-base64 outer
(bogus as stated: %Q is not valid URL-encoding); C3 base64-of-hex outer
(the documented F453 ws-b64-over-hex residual class, pinned); C4
fill('a',0,1).concat(['b']) (does not recover 'ab' -- bogus); C5
x instanceof String && ... (false for primitives -- bogus, cf. wave-351
B3); C6 Array.from([...]) and Array.prototype.concat.call([...])
(BLOCKED -- wave-351 dead proposals, still blocked).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g352-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2135, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2135  # no new decision codes this round

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B
_C1 = "xoxb-" + "012345678"  # 13 chars: xoxb- + 8, below the {10,} rule gate
_C2 = "89abcdef"
_CRED2 = "xoxb-" + "0123456789abcdef"  # 21 chars -> 42 hex chars
_BT = chr(96)  # backtick

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    hit = _blocked("token=" + _CRED)
    return ("HELD" if hit else "BREAK", "find_credential=%s" % hit)


@_t
def test_b0_pin_taxonomy():
    """Control: taxonomy pin holds (no new decision codes)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "len(TAXONOMY)=%d want %d"
            % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_b0_footer_state():
    """Control: footer shows F461-F468 open, next F469 (wave-352 merge:
    F454-F460 closed, F461-F468 filed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F469**" in text
          and "**Open findings: F461, F462, F463, F464, F465, F466, F467, F468.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- F454-F460 closed pins (wave-352 merge)

@_t
def test_b1_f454_multiarg_array_open():
    """F454 pinned CLOSED (wave-352 merge): multi-arg Array constructor blocks."""
    hit = _blocked("Array('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f455_ws_dot_open():
    """F455 pinned CLOSED (wave-352 merge): ws before the dot in Array .of blocks."""
    hit = _blocked("Array .of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f456_b64_junk_frag_open():
    """F456 pinned CLOSED (wave-352 merge): base64 with NUL junk fragmentation blocks."""
    b64 = base64.b64encode(_CRED2.encode()).decode()
    frag, i, parts = b64, 0, []
    while i < len(frag):
        parts.append(frag[i:i + 12])
        i += 12
        if i < len(frag):
            parts.append("\x00")
    hit = _blocked("".join(parts))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f457_tmpl_interp_open():
    """F457 pinned CLOSED (wave-352 merge): template-literal ${} interpolation blocks."""
    hit = _blocked("`%s${'%s'}`" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f458_fcc_octal_open():
    """F458 pinned CLOSED (wave-352 merge): fromCharCode with octal literals blocks."""
    codes = ",".join("0o%o" % c for c in _CRED2.encode())
    hit = _blocked("String.fromCharCode(%s)" % codes)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f459_filter_index_open():
    """F459 pinned CLOSED (wave-352 merge): positional .filter predicate blocks."""
    hit = _blocked("['" + _A + "','" + _B + "','zz'].filter((x,i)=>i<2)"
                        ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f460_map_string_open():
    """F460 pinned CLOSED (wave-352 merge): .map(String) blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(String).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F461-F468 open pins

@_t
def test_b2_f461_reverse_join_open():
    """F461 pinned open: .reverse().join('') misses."""
    miss = not _blocked("['" + _B + "','" + _A + "'].reverse().join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f462_spread_concat_open():
    """F462 pinned open: spread-args concat misses."""
    miss = not _blocked("\"" + "\".concat(...['" + _A + "','" + _B + "'])")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f463_tagged_template_join_open():
    """F463 pinned open: join as a tagged template misses."""
    miss = not _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f464_tostring_replace_open():
    """F464 pinned open: .toString().replace(/,/g,'') misses."""
    miss = not _blocked("['" + _A + "','" + _B + "'].toString()"
                        ".replace(/,/g,'')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f465_padstart_open():
    """F465 pinned open: .padStart assembly misses."""
    miss = not _blocked("'" + _C2 + "'.padStart(21,'" + _C1 + "')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f466_slice_noop_open():
    """F466 pinned open: .slice(0,2).join('') misses."""
    miss = not _blocked("['" + _A + "','" + _B + "'].slice(0,2).join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f467_filter_neq_null_open():
    """F467 pinned open: .filter(x=>x!==null) misses."""
    miss = not _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null)"
                        ".join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f468_reflect_construct_open():
    """F468 pinned open: Reflect.construct(Array,[...]) misses."""
    miss = not _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                        ".join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F451-F453 closed pins

@_t
def test_b3_f451_hex_spaced_closed():
    """F451 pinned CLOSED (wave-351 merge): hex with whitespace blocks."""
    hx = _CRED2.encode().hex()
    hit = _blocked(hx[:20] + " " + hx[20:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f452_failclosed_junk32_closed():
    """F452 pinned CLOSED (wave-351 merge): 32 fail-closed junk statements
    no longer consume the scan budget; the real expression blocks."""
    junk = "".join("'%s';" % ("j%d" % i) for i in range(32))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f453_wsb64_outer_closed():
    """F453 pinned CLOSED (wave-351 merge): ws-b64 outer layer of a stack
    composes via the base64 fixpoint seed."""
    inner = base64.b64encode(_CRED.encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    hit = _blocked(outer[:10] + " " + outer[10:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- composition / scope pins

@_t
def test_b4_f444_residual_130_open():
    """F444 documented residual: ~130+ decodable junk still starves."""
    junk = "".join("'j%d'+'k%d';" % (i, i) for i in range(130))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    miss = not _blocked(junk + ";" + real)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b4_f439_depth4_open():
    """F439 documented non-goal: depth-4 base64 misses; depth-3 blocks."""
    b1 = base64.b64encode(_CRED2.encode()).decode()
    b2 = base64.b64encode(b1.encode()).decode()
    b3 = base64.b64encode(b2.encode()).decode()
    b4 = base64.b64encode(b3.encode()).decode()
    ok = _blocked(b3) and not _blocked(b4)
    return ("HELD" if ok else "BREAK", "d3=%s d4miss=%s"
            % (_blocked(b3), not _blocked(b4)))


@_t
def test_b4_f446_ctor_of_residual():
    """F446 honest residual: [].constructor.of misses (documented)."""
    miss = not _blocked("[].constructor.of('" + _A + "','" + _B + "')"
                        ".join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b4_f452_70decodable_blocks():
    """F452 composition pin: 70 decodable junk + real still block."""
    junk = "".join("'j%d'+'k%d';" % (i, i) for i in range(70))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + ";" + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f453_wsb64_over_hex_residual():
    """F453 documented residual (wave-351 merge): ws-b64-over-hex still
    misses -- the F453 fixpoint is base64-only; cross-encoding needs the
    layer pipeline."""
    hx = _CRED2.encode().hex()
    outer = base64.b64encode(hx.encode()).decode()
    miss = not _blocked(outer[:10] + " " + outer[10:])
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b4_f447_truthy_filter_blocks():
    """F447 pinned closed: truthy .filter predicate blocks (x!=='')."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!=='')"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f448_blockbody_map_blocks():
    """F448 pinned closed: block-body identity .map blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(x=>{return x;})"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- round-20 scope notes

@_t
def test_b5_f467_undefined_open():
    """F467 scope (round 20, model C5): x=>x!==undefined is constant-true
    over strings -- same null-comparison mechanism as F467; rides with
    F467's close-when."""
    miss = not _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==undefined)"
                        ".join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b5_f467_loose_null_open():
    """F467 scope (round 20, model C5): function(x){return x!=null;} is
    constant-true over strings -- same mechanism as F467."""
    miss = not _blocked("['" + _A + "','" + _B + "','']"
                        ".filter(function(x){return x!=null;}).join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b5_f454_spread_new_open():
    """F454 scope (round 20, model C6): new Array(...['a','b']) desugars to
    the multi-arg constructor -- same parser branch as F454."""
    miss = not _blocked("new Array(...['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b5_f464_flat_tostring_open():
    """F464 scope (round 20, model C4): .flat()/.splice(0,2) are unmodeled
    no-ops ahead of the F464 toString+replace -- same composition class as
    F466."""
    miss = not _blocked("['" + _A + "','" + _B + "'].flat().toString()"
                        ".replace(/,/g,'')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F454-F468 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); a literal BREAK verdict means the pin failed or a
# NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).

    Wave-305-class note: w351_attack_probes.py's test_b0_footer_state
    pins the pre-filing footer (next F461); this lane moved the footer to
    next F469, so exactly that one probe is expected to BREAK here. The
    merge coordinator's tree-wide footer sweep repoints it. Any OTHER
    break is a real regression and fails this check."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w351_attack_probes.py",):
        tmp = "/var/tmp/g352-green-%s-%d" % (script.replace(".py", ""),
                                             os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        # Extract the BREAK set. Probe lines are test-name-first
        # ("test_b0_footer_state   BREAK footer=False"); older batteries
        # print verdict-first ("BREAK test_name: note"). Parse both --
        # a parse that matches neither format passes vacuously and is a
        # silent green (wave-320 class).
        breaks = set()
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "BREAK" and len(parts) >= 2:
                breaks.add(parts[1].rstrip(":"))
            elif len(parts) >= 2 and parts[1] == "BREAK":
                breaks.add(parts[0])
        if not breaks and r.returncode != 0:
            raise AssertionError("green check failed: could not parse any "
                                 "probe verdicts from child output: %s"
                                 % notes[-1])
        allowed = {"test_b0_footer_state"}
        if not breaks <= allowed:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
        notes.append("tolerated stale footer probe: %s" % sorted(breaks))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held, probe_breaks, errors = 0, set(), 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 - probe must never abort
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("tally: %d HELD / %d BREAK / %d ERROR" % (held, len(probe_breaks),
                                                   errors))
    if probe_breaks:
        print("BREAKS:", sorted(probe_breaks))
    if errors:
        return 2
    return 0 if not (probe_breaks - _EXPECTED_BREAKS) else 1


if __name__ == "__main__":
    sys.exit(main())
