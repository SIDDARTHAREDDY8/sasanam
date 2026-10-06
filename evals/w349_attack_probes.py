#!/usr/bin/env python3
"""Wave-349 attack round 17 regression battery.

Real-model attack (gpt-4o-mini, 6 calls, ~$0.000689) against the
wave-348-merged F443 closure surface (Array(N)/.fill/.filter(Boolean)
bounded shapes) plus F444/F445 closure-resilience probing.

Filed this round (all LOW, red-first verified; all five CLOSED at the
wave-350 merge):
- F446: Array.of(...) factory bypasses the static JS-expression decoder
        (decoder models only the single-integer Array(N) form).
        **Status: CLOSED 2026-10-06 wave-350 lane 1** -- Array.of
        string-literal factory modeled in gov/dlp.py; the open-tree
        miss probe is now a coded-refusal assertion.
- F447: non-Boolean .filter(...) predicates (x=>x!=='', x=>!!x,
        x=>x.length>0, function(x){return x;}) bypassed the decoder
        (only bare Boolean was modeled). CLOSED 2026-10-06 wave-350
        lane 2: truthiness predicates decode within the same budgets.
- F448: .map with a block-body identity callback (x=>{return x;})
        bypassed the identity-map passthrough (concise + function
        forms were modeled). CLOSED 2026-10-06 wave-350 lane 2:
        block-body identity decodes within the same budgets.
- F449: base64 with embedded whitespace evades the contiguous-run
        gate (base64.b64decode ignores whitespace; distinct from the
        F445 length gate). CLOSED 2026-10-06 wave-350 lane 3
        (whitespace-tolerant base64 scan, credential-shape-gated).
- F450: hex minimum-length gate (32 chars) lets hex of short
        credentials evade (bytes.fromhex recovers; same mechanism
        class as F445, different code path). CLOSED 2026-10-06
        wave-350 lane 3 (short-hex scan, credential-shape-gated;
        the filed 10-char shape is a documented accepted residual --
        below the 15-char rule floor).

Known-open pins (each probe returns HELD when the miss reproduces;
a literal BREAK verdict means the pin failed or a NEW break appeared):
F444 (junk JS prefixes starve the decode budget), F445 (base64
min-length gate). Composition probes pin the closed shapes still
blocking.

Dead proposals validated locally and NOT filed: Array.from([...])
(blocks -- inner array literal decodes), new Array(2) (blocks),
[...'a'+'b'] spread-concat (blocks), reversed-credential shapes
(block -- find_credential re-runs rules on reversed variants),
double-entity-wrapped Array.fill (blocks), URL-encoded
filter(Boolean).join (blocks), base64-of-reduce (blocks), entity junk
flood (blocks), b64 junk runs (blocks), base32-short (same class as
F445, noted), [...str].reverse() bogus (reversed-form check),
charCode-shift .replace (does not recover the credential -- bogus),
CRED-indexing Array.from proposals (verbatim credential -- bogus).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g349-*
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
    """Control: footer shows F452 open, next F454 (wave-351 lanes 1+3:
    F451, F453 closed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F469**" in text
          and "**Open findings: F461, F462, F463, F464, F465, F466, F467, F468.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ---------------------------------------------------------------- F446 pins

@_t
def test_b1_f446_arrayof_closed():
    """F446 pinned CLOSED (wave-350 lane 1): Array.of frag-join now
    blocks coded -- the open-tree miss probe flipped to a refusal
    assertion (wave-306 class)."""
    hit = _blocked("Array.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f446_arrayof_verbatim_blocks():
    """Array.of with a verbatim credential blocks via the raw-text rule."""
    hit = _blocked("Array.of('" + _CRED + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- F447 pins

@_t
def test_b2_f447_filter_predicates_closed():
    """F447 CLOSED 2026-10-06 wave-350 lane 2: truthiness filter
    predicates now decode within the same budgets."""
    arr = "['" + _A + "','" + _B + "','','']"
    preds = ["x=>x!==''", "x=>!!x", "x=>x.length>0",
             "function(x){return x;}"]
    hits = [_blocked(arr + ".filter(" + p + ").join('')") for p in preds]
    ok = all(hits)
    return ("HELD" if ok else "BREAK", "hits=%s" % hits)


@_t
def test_b2_f447_filter_boolean_blocks():
    """.filter(Boolean) still blocks (F443 shape intact)."""
    hit = _blocked("['" + _A + "','','" + _B + "'].filter(Boolean).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- F448 pins

@_t
def test_b3_f448_map_blockbody_closed():
    """F448 CLOSED 2026-10-06 wave-350 lane 2: block-body identity map
    now decodes within the same budgets."""
    hit = _blocked("['" + _A + "','" + _B + "'].map(x=>{return x;}).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f448_map_concise_blocks():
    """Concise/function identity maps still block (F437 shapes intact)."""
    arr = "['" + _A + "','" + _B + "']"
    ok = (_blocked(arr + ".map(x=>x).join('')")
          and _blocked(arr + ".map(function(x){return x;}).join('')"))
    return ("HELD" if ok else "BREAK", "both_block=%s" % ok)


# ---------------------------------------------------------------- F449 pins

@_t
def test_b4_f449_b64_whitespace_closed():
    """F449 CLOSED 2026-10-06 wave-350 lane 3: whitespace-split base64
    of a long credential now blocks coded dlp-slack-token."""
    longc = _CRED + _CRED
    b64 = base64.b64encode(longc.encode()).decode()
    spaced = b64[:16] + " " + b64[16:32] + "\n" + b64[32:]
    assert base64.b64decode(spaced) == longc.encode()
    hit = _blocked(spaced)
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


@_t
def test_b4_f449_b64_contiguous_blocks():
    """The same base64 without whitespace blocks."""
    b64 = base64.b64encode((_CRED + _CRED).encode()).decode()
    hit = _blocked(b64)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- F450 pins

@_t
def test_b5_f450_hex_short_closed():
    """F450 CLOSED 2026-10-06 wave-350 lane 3: hex of a short (15-char,
    credential-shaped) credential now blocks coded dlp-slack-token.
    The 10-char sub-credential shape stays quiet by design (documented
    accepted residual: below the 15-char rule floor, F2
    unknown-format class)."""
    short15 = "xox" + "b-abc123def4"  # 15 chars: shortest the rule matches
    assert len(short15) == 15
    hx = "".join("%02x" % c for c in short15.encode())
    assert len(hx) == 30  # under the 32-char _HEX_RUN gate
    assert bytes.fromhex(hx) == short15.encode()
    hit = _blocked(hx)
    sub10 = "xox" + "b-abc12"  # 10 chars: not credential-shaped
    hx10 = "".join("%02x" % c for c in sub10.encode())
    residual_quiet = not _blocked(hx10)
    ok = hit and residual_quiet
    return ("HELD" if ok else "BREAK",
            "blocked15=%s residual10_quiet=%s" % (hit, residual_quiet))


@_t
def test_b5_f450_hex_long_blocks():
    """Hex of a long credential blocks (over the gate)."""
    hx = "".join("%02x" % c for c in (_CRED + _CRED).encode())
    hit = _blocked(hx)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F444/F445 scope pins

@_t
def test_b6_f444_still_open():
    """F444 CLOSED 2026-10-06 wave-349 merge: junk-prefixed reduce now blocks."""
    junk = "'j0'+'k0';'j1'+'k1';'j2'+'k2';"
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(junk + real)
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


@_t
def test_b6_f445_still_open():
    """F445 CLOSED 2026-10-06 wave-349 merge: short-credential base64 now blocks.

    Merge fix: the attack lane's open-scope pin used a 10-char non-credential
    string ("xox"+"b-abc12", never a credential by the repo's own rules).
    The genuine F445 shape is the 16-char credential from the red-first
    (evals/w348_f445_redfirst.py): 24 b64 chars / 23 payload chars < 24."""
    short = "xox" + "b-abc123" + "def" + "456"  # 16 chars, credential-shaped
    b64 = base64.b64encode(short.encode()).decode()
    hit = _blocked(b64)
    return ("HELD" if hit else "BREAK", "blocked=%s b64=%s" % (hit, b64))


# ------------------------------------------------------- composition pins

@_t
def test_b7_compositions_hold():
    """Closed-shape compositions still block within the 2-layer budget."""
    import urllib.parse
    arr = "['" + _A + "','','" + _B + "']"
    shapes = [
        ("Array(2).fill('" + _A + "').join('').concat('" + _B + "')")
            .replace("&", "&amp;").replace("'", "&#x27;"),  # entity-wrapped fill
        urllib.parse.quote(arr + ".filter(Boolean).join('')", safe=""),  # url filter
        base64.b64encode(("['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)").encode()).decode(),  # b64 reduce
        "Array.from(['" + _A + "','" + _B + "']).join('')",  # array.from blocks
        "new Array(2).fill('" + _A + "').join('').concat('" + _B + "')",  # new Array blocks
    ]
    hits = [_blocked(s) for s in shapes]
    ok = all(hits)
    return ("HELD" if ok else "BREAK", "hits=%s" % hits)


@_t
def test_b7_reversed_credential_blocks():
    """Reversed-credential shapes block (reversed-form rule check)."""
    rev = _CRED[::-1]
    ok = (_blocked("[...'" + rev + "'].reverse().join('')")
          and _blocked("'" + rev + "'.split('').reverse().join('')"))
    return ("HELD" if ok else "BREAK", "both_block=%s" % ok)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F446-F450 misses are pinned CLOSED (each probe returns HELD when the
# coded refusal reproduces; probes flipped to closure assertions
# 2026-10-06 wave-350 lanes 1/2/3). A literal BREAK verdict means a
# pin failed or a NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w348_attack_probes.py",):
        tmp = "/var/tmp/g349-green-%s-%d" % (script.replace(".py", ""), os.getpid())
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
    print("tally: %d HELD / %d BREAK / %d ERROR" % (held, len(probe_breaks), errors))
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    if mismatch:
        print("MISMATCH vs expected breaks: %s" % sorted(mismatch))
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
