#!/usr/bin/env python3
"""Wave-351 attack round 19 regression battery.

Real-model attack (gpt-4o-mini, 8 calls, ~$0.000376) against the
wave-350-merged F446-F450 closure surfaces (Array.of factory; truthiness
bodies + block-body identity map; whitespace-tolerant b64/hex gates with
credential-shaped gating) plus composition seams across the twelve closed
DLP layers and the documented residuals.

Filed this round (all LOW, OPEN, red-first verified):
- F454: multi-arg Array constructor -- Array('a','b') / new Array('a','b')
        evaluates in node but fails closed ("bad Array args"); the F446
        close-when promised the other Array factory forms decode.
- F455: whitespace before the dot in Array .of(...) -- the parser claims
        ws-tolerance "exactly as the engine allows" but the _JS_EXPR_START
        anchor (Array(\\(|\\.of)) never fires with ws before the dot.
- F456: base64 fragmented with NON-whitespace junk chars (\\x00, !, .) --
        b64decode discards every non-alphabet char, but _B64_RUN needs
        contiguity and the F449 ws-span needs whitespace-only gaps.
        Distinct from F449 (precedent: F451-vs-F449).
- F457: template-literal ${} interpolation -- "template literals" are a
        claimed F430/F434 surface but any interpolation fails closed.
- F458: String.fromCharCode with non-decimal/hex integer literals --
        0o octal, 0b binary, legacy octal, numeric separators, mixed radix;
        _js_parse_number handles only decimal/0x.
- F459: positional .filter predicates ((x,i)=>i<2) -- a different predicate
        class from F447's truthiness family; the F447 close-when does not
        cover index comparison.
- F460: .map(String) -- the string-coercion idiom is the identity over
        string fragments (node-verified) but only identity callbacks are
        modeled (F437/F448).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F451 (hex whitespace), F452 (attempt-budget starvation), F453 (ws-b64
outer-layer stack), F454-F460 (this round).

Scope notes added (documented, not new numbers):
- F451 x F450: short-credential hex WITH whitespace misses too -- rides
  with F451's close-when ("whitespace-tolerant hex runs are attempted
  (bounded)"); pinned as a composition probe.
- F452 x mixed junk: 40 fail-closed + 40 decodable junk statements ahead
  of a real reduce miss -- same attempt-consumption mechanism as F452;
  rides with F452's close-when.

Scope confirmed (still as documented):
- F444 ~130+ junk residual: misses (bounded-budget residual, not a finding).
- F439 depth-4 base64: misses (documented non-goal); depth-3 blocks.
- F446 `[].constructor.of` / `Array['of']`: miss (honest residual).
- F447 free-variable predicates: correctly fail closed (no static binding).
- F452 70-decodable-junk pin: still blocks (F444 composition intact).
- F453 ws-b64(ws-b64): still misses (open finding scope).
- F449 x F451: hex-with-whitespace through the b64-ws scanner -- no
  misfire (round-trip rejects), still misses.

Dead proposals validated locally and NOT filed: Array.from('CRED') /
[...'CRED'] / 'CRED'.split('') / ''.concat('a','b') / String('a'+'b')
(all BLOCKED -- already handled); .reduce((a,b)=>a+b,'') with init arg
(BLOCKED); Array.prototype.concat.call (BLOCKED -- whole-text scan
composes faithfully); b64 with whitespace-only fragmentation (BLOCKED --
F449); short-cred hex contiguous (BLOCKED -- F450); model B2
INSERT-x/y/z answers (bogus: x/y/z are alphabet chars); model B3
`x instanceof String` (bogus: false for primitives); model B8 asterisks
in hex (bogus: fromhex rejects); `['a','b'].sort().join('')`
(data-dependent, not a principled bypass -- left unfiled).

Validated-but-unfiled bypasses (genuine, node-verified; recommended for a
future primitive-sweep round -- kept out of this round to hold the findings
to the F446-F450 closure surfaces per mission scope): ['b','a'].reverse()
.join(''), ''.concat(...['a','b']) (spread args), ['a','b'].join`` ``
(tagged-template call), ['a','b'].toString().replace(/,/g,''),
'b'.padStart(20,'a...'), ['a','b'].slice(0,2).join('') (unmodeled no-op in
the chain), ['a','b',''].filter(x=>x!==null) (domain-reasoned
constant-true).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g351-*
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
_CRED = "xoxb-" + "abc123" + "def456"
_A = "xoxb-" + "abc123"
_B = "def" + "456"
_CRED2 = "xoxb-" + "0123456789abcdef"  # 21 chars -> 42 hex chars

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
    """Control: footer shows F454-F457 open, next F461 (wave-352 lane 4:
    F458/F459/F460 closed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F461**" in text
          and "**Open findings: F454, F455, F456, F457.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- F451-F453 still-open pins

@_t
def test_b1_f451_hex_spaced_closed():
    """F451 pinned CLOSED (wave-351 merge): hex of a long credential with
    a space now blocks via the whitespace-tolerant hex spans."""
    hx = _CRED2.encode().hex()
    hit = _blocked(hx[:20] + " " + hx[20:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f452_failclosed_junk32_closed():
    """F452 pinned CLOSED (wave-351 merge): 32 fail-closed junk statements
    no longer consume the scan budget; the real expression blocks."""
    junk = "".join("'%s';" % ("j%d" % i) for i in range(32))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f453_wsb64_outer_closed():
    """F453 pinned CLOSED (wave-351 merge): ws-b64 outer layer of a stack
    now composes via the base64 fixpoint seed."""
    inner = base64.b64encode(_CRED.encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    hit = _blocked(outer[:10] + " " + outer[10:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F454-F457 open pins

@_t
def test_b2_f454_multiarg_array_open():
    """F454 pinned open: multi-arg Array constructor misses."""
    miss = not _blocked("Array('" + _A + "','" + _B + "').join('')")
    miss2 = not _blocked("new Array('" + _A + "','" + _B + "').join('')")
    ok = miss and miss2
    return ("HELD" if ok else "BREAK", "miss=%s/%s" % (miss, miss2))


@_t
def test_b2_f455_ws_dot_open():
    """F455 pinned open: whitespace before the dot in Array .of misses."""
    miss = not _blocked("Array .of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def _frag(s, junk, every=12):
    parts, i = [], 0
    while i < len(s):
        parts.append(s[i:i + every])
        i += every
        if i < len(s):
            parts.append(junk)
    return "".join(parts)


@_t
def test_b2_f456_b64_junk_frag_open():
    """F456 pinned open: base64 with NUL junk fragmentation misses."""
    b64 = base64.b64encode(_CRED2.encode()).decode()
    miss = not _blocked(_frag(b64, "\x00"))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b2_f457_tmpl_interp_open():
    """F457 pinned open: template-literal ${} interpolation misses."""
    miss = not _blocked("`%s${'%s'}`" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b1_f458_fcc_spellings_closed():
    """F458 pinned CLOSED (wave-352 lane 4): fromCharCode with the
    engine's integer-literal spellings now blocks -- octal, binary,
    legacy octal, numeric separators, and mixed-radix arg lists."""
    codes = _CRED2.encode()
    octal = ",".join("0o%o" % c for c in codes)
    binary = ",".join("0b" + bin(c)[2:] for c in codes)
    legacy = ",".join("0%o" % c for c in codes)
    seps = ",".join(str(c)[:-2] + "_" + str(c)[-2:] if c >= 100
                    else str(c) for c in codes)
    mixed = ",".join(("0o%o" % c, "0x%x" % c, str(c),
                      "0b" + bin(c)[2:])[i % 4]
                     for i, c in enumerate(codes))
    shapes = [octal, binary, legacy, seps, mixed]
    ok = all(_blocked("String.fromCharCode(%s)" % s) for s in shapes)
    return ("HELD" if ok else "BREAK", "all5=%s" % ok)


@_t
def test_b1_f459_filter_index_closed():
    """F459 pinned CLOSED (wave-352 lane 4): positional .filter
    predicates now decode -- i<2 and i!==2 both block."""
    p1 = "['" + _A + "','" + _B + "','zz'].filter((x,i)=>i<2).join('')"
    p2 = "['" + _A + "','" + _B + "','zz'].filter((x,i)=>i!==2).join('')"
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "lt/ne=%s" % ok)


@_t
def test_b1_f460_map_string_closed():
    """F460 pinned CLOSED (wave-352 lane 4): .map(String) is the
    identity over string fragments and now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(String).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- composition / scope pins

@_t
def test_b3_f451_short_hex_ws_closed():
    """F451 x F450 scope (wave-351 merge): short-cred hex WITH whitespace
    is absorbed by the F451 closure -- the ws-hex spans attempt it within
    the close-when's bounded scope."""
    hx = _CRED.encode().hex()  # 18 chars -> 36 hex
    hit = _blocked(hx[:12] + " " + hx[12:24] + "\n" + hx[24:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f452_mixed_junk_closed():
    """F452 x mixed junk scope (wave-351 merge): 40 fail-closed + 40
    decodable junk ahead of a real reduce -- the F452 closure counts only
    decode-producing attempts, so the real expression is still reached."""
    junk_fc = "".join("'%s';" % ("j%d" % i) for i in range(40))
    junk_dec = "".join("'a%d'+'b%d';" % (i, i) for i in range(40))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk_fc + junk_dec + ";" + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f444_residual_130_open():
    """F444 documented residual: ~130+ decodable junk still starves."""
    junk = "".join("'j%d'+'k%d';" % (i, i) for i in range(130))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    miss = not _blocked(junk + ";" + real)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b3_f439_depth4_open():
    """F439 documented non-goal: depth-4 base64 misses; depth-3 blocks."""
    b1 = base64.b64encode(_CRED2.encode()).decode()
    b2 = base64.b64encode(b1.encode()).decode()
    b3 = base64.b64encode(b2.encode()).decode()
    b4 = base64.b64encode(b3.encode()).decode()
    ok = _blocked(b3) and not _blocked(b4)
    return ("HELD" if ok else "BREAK", "d3=%s d4miss=%s"
            % (_blocked(b3), not _blocked(b4)))


@_t
def test_b3_f446_ctor_of_residual():
    """F446 honest residual: [].constructor.of misses (documented)."""
    miss = not _blocked("[].constructor.of('" + _A + "','" + _B + "')"
                        ".join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b3_f452_70decodable_blocks():
    """F452 composition pin: 70 decodable junk + real still block."""
    junk = "".join("'j%d'+'k%d';" % (i, i) for i in range(70))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + ";" + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- closed-shape pins

@_t
def test_b4_f446_arrayof_blocks():
    """F446 pinned closed: Array.of frag-join blocks."""
    hit = _blocked("Array.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f447_truthy_filter_blocks():
    """F447 pinned closed: truthy .filter predicate blocks."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!=='')"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f448_blockbody_map_blocks():
    """F448 pinned closed: block-body identity .map blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(x=>{return x;})"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f449_ws_b64_blocks():
    """F449 pinned closed: whitespace-fragmented base64 blocks."""
    b64 = base64.b64encode(_CRED2.encode()).decode()
    hit = _blocked(b64[:12] + " " + b64[12:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f450_short_hex_blocks():
    """F450 pinned closed: hex of a short credential blocks."""
    short = "xoxb-" + "1234567890"  # 15 chars -> 30 hex
    hit = _blocked(short.encode().hex())
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f444_junk3_blocks():
    """F444 pinned closed: 3 decodable junk + real still block."""
    junk = "".join("'j%d'+'k%d';" % (i, i) for i in range(3))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + ";" + real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f445_short_b64_blocks():
    """F445 pinned closed: short b64 of a credential blocks via the gate."""
    hit = _blocked(base64.b64encode(_CRED.encode()).decode())
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F454-F457 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); a literal BREAK verdict means the pin failed or a
# NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).

    Wave-305-class note: w350_attack_probes.py's test_b0_footer_state
    pins the pre-filing footer (next F454); this lane moved the footer to
    next F461, so exactly that one probe is expected to BREAK here. The
    merge coordinator's tree-wide footer sweep repoints it. Any OTHER
    break is a real regression and fails this check."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w350_attack_probes.py",):
        tmp = "/var/tmp/g351-green-%s-%d" % (script.replace(".py", ""),
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
        # Extract the BREAK set; only the known-stale footer probe may break.
        breaks = set()
        for line in out.splitlines():
            if line.startswith("BREAK "):
                breaks.add(line.split()[1].rstrip(":"))
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
