#!/usr/bin/env python3
"""Wave-350 attack round 18 regression battery.

Real-model attack (gpt-4o-mini, 6 calls, ~$0.000907) against the
wave-349-merged F444/F445 closure surfaces (whole-text JS scan; lowered
b64/b32 floor with credential-shaped gating) plus F446-F450 scope
confirmation and composition seams across the ten closed DLP layers.

Filed this round (all LOW, OPEN, red-first verified):
- F451: hex with embedded whitespace evades the contiguous-run gate
        (bytes.fromhex ignores whitespace; over the F450 length gate;
        distinct from F449 -- different code path `_HEX_RUN`, same
        precedent as F450 vs F445).
- F452: fail-closed JS-expression matches consume the whole-text scan's
        64-attempt budget (32 bare string-literal statements = 64 quote
        matches ahead of a real .reduce assembly starve the real
        expression; node-verified last-statement-wins; below F444's
        documented ~130+ residual; distinct mechanism from F444's
        layer exhaustion).

F449 scope note (documented, not a new number): short-credential base64
with embedded whitespace misses too (F449 x F445 composition) -- same
contiguity gate, same regex family as F449; the F449 close-when
("whitespace-tolerant base64 runs are attempted (bounded)") already
covers it, so it rides with F449.

Known-open pins (each probe returns HELD when the miss reproduces;
a literal BREAK verdict means the pin failed or a NEW break appeared):
F452 (attempt-budget starvation),
F453 (ws-b64 outer-layer stack). F451 (hex whitespace) was flipped to a
closure assertion 2026-10-06 wave-351 lane 1. Composition probes
pin the closed shapes still blocking.

Dead proposals validated locally and NOT filed: template-literal
${String.fromCharCode(codes)} (blocks -- the fromCharCode substring
decodes to a verbatim credential in the variant), base32 with
whitespace (bogus -- the real parser, base64.b32decode, rejects
whitespace with 'Incorrect padding'), short-outer base64 stacks
b64(b64(short-cred)) (unreachable -- no credential rule matches the
<=12-char credentials that would keep the outer run short), B1
Array(1)[0]=CRED / IIFE (verbatim credential -- bogus), B2 padding
quirks / 0x-hex (bogus), B3 btoa(`CRED`) (verbatim -- bogus), B4
String.raw`CRED` / comma-operator (verbatim -- bogus), B5 entity junk /
b64 prefix / double-backslash (closed shapes or bogus).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g350-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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

TAXONOMY_PIN = 2140  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

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
    """Control: footer shows F454, F455, F457-F460 open, next F461
    (wave-352 lane 2: F456 closed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F700**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in text)  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ---------------------------------------------------------------- F451 pins

@_t
def test_b1_f451_hex_spaced_closed():
    """F451 CLOSED 2026-10-06 wave-351 lane 1: hex of a long credential
    with a space now blocks (whitespace-tolerant hex run)."""
    hx = _CRED2.encode().hex()
    hit = _blocked(hx[:20] + " " + hx[20:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f451_hex_newlined_closed():
    """F451 CLOSED 2026-10-06 wave-351 lane 1: hex with a newline now
    blocks too."""
    hx = _CRED2.encode().hex()
    hit = _blocked(hx[:20] + "\n" + hx[20:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f451_hex_contiguous_blocks():
    """Contiguous hex of the same credential still blocks."""
    hit = _blocked(_CRED2.encode().hex())
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- F452 pins

def _junk(n):
    return "".join("'%s';" % ("j%d" % i) for i in range(n))


def _decodable_junk(n):
    return "".join("'j%d'+'k%d';" % (i, i) for i in range(n))


_REAL = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"


@_t
def test_b2_f452_failclosed_junk32_open():
    """F452 CLOSED (wave-351 lane 2): 32 fail-closed junk statements no
    longer starve the scan -- fail-closed matches consume no budget."""
    hit = _blocked(_junk(32) + _REAL)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f452_junk31_blocks():
    """31 junk statements (62 matches, under budget) still block."""
    hit = _blocked(_junk(31) + _REAL)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f452_decodable_junk70_blocks():
    """70 decodable junk expressions + real still block (F444 intact)."""
    hit = _blocked(_decodable_junk(70) + _REAL)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F449 scope (composition)

@_t
def test_b3_f449_short_b64_spaced_open():
    """F449 scope CLOSED (wave-350 lane 3): short-cred base64 with whitespace
    now blocks -- rode with F449's close-when; kept as a composition pin."""
    b64 = base64.b64encode(_CRED.encode()).decode()
    hit = _blocked(b64[:8] + " " + b64[8:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f449_long_b64_spaced_open():
    """F449 CLOSED (wave-350 lane 3): long-cred base64 with whitespace
    now blocks."""
    b64 = base64.b64encode(_CRED2.encode()).decode()
    hit = _blocked(b64[:12] + " " + b64[12:])
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F446-F450 scope pins

@_t
def test_b4_f446_arrayof_open():
    """F446 CLOSED (wave-350 lane 1): Array.of frag-join now blocks."""
    hit = _blocked("Array.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f447_truthy_filter_open():
    """F447 CLOSED (wave-350 lane 2): truthy .filter predicate now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!=='')"
                       ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f448_blockbody_map_open():
    """F448 CLOSED (wave-350 lane 2): block-body identity .map now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(x=>{return x;})"
                       ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f450_short_hex_open():
    """F450 CLOSED (wave-350 lane 3): hex of a short credential now blocks."""
    short = "xoxb-" + "1234567890"  # 15 chars -> 30 hex < 32
    hit = _blocked(short.encode().hex())
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- closed-shape pins

@_t
def test_b5_f444_decodable_junk3_blocks():
    """F444 pinned closed: 3 decodable junk + real still block."""
    hit = _blocked(_decodable_junk(3) + _REAL)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b5_f445_short_b64_blocks():
    """F445 pinned closed: short b64 of a credential blocks via the gate."""
    b64 = base64.b64encode(_CRED.encode()).decode()
    hit = _blocked(b64)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b5_f443_array_fill_blocks():
    """F443 pinned closed: Array(N).fill frag-join-concat blocks."""
    hit = _blocked("Array(2).fill('" + _A + "').join('').concat('" + _B
                   + "')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b5_f437_reduce_blocks():
    """F437 pinned closed: the bare reduce shape blocks."""
    hit = _blocked(_REAL)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F452-F453 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); F451 was flipped to a closure assertion
# (wave-351 lane 1). A literal BREAK verdict means the pin failed or a
# NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w349_attack_probes.py",):
        tmp = "/var/tmp/g350-green-%s-%d" % (script.replace(".py", ""),
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
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
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
        print("%s %s: %s" % (verdict, fn.__name__, note))
    print("tally: %d HELD / %d BREAK / %d ERROR" % (held, len(probe_breaks),
                                                   errors))
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    if mismatch:
        print("MISMATCH vs expected breaks: %s" % sorted(mismatch))
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
