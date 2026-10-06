#!/usr/bin/env python3
"""Wave-347 F438 closure battery: HTML-entity + UTF-16 NUL-interleave
composition (lane 2).

F438 (LOW, filed 2026-10-05 wave-346 lane 2 (continuous real-model
attack); CLOSED 2026-10-05 wave-347 lane 2): entities separated by NUL
bytes (`&#xHH;\\x00&#xHH;\\x00...`) each decoded in their own
single-entity variant because per-run decoding spread the 8-candidate
budget, so the fully-decoded + NUL-stripped form was unreachable within
the depth-2 composition budget -- while a real chain (html.unescape
decodes every entity at once, then a control-strip) recovers the
credential.

Close-when: a whole-text decode variant strips NUL bytes and then
decodes every numeric HTML entity in one pass (bounded by
_MAX_WHOLETEXT_ITEMS via the F436 whole-text entity pass; malformed /
out-of-range / non-ASCII decodes fail closed), so find_credential
flags the stacked form -- bounded, static, never executes. The fix
costs one decode layer, so the documented depth-2 design bound is
intact (F439 triple-base64 remains a documented miss).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the verified F438 shape blocks coded dlp-slack-token
      (roundtrip-verified against html.unescape + NUL-strip).
  P2  control: the plain credential blocks coded.
  P3  decoder pins: _try_entity_nul_decode_all unit -- decodes
      entity+NUL text to the credential; returns None for text
      without NULs (delegates to existing variants) and text without
      entities; malformed references stay literal (faithful to
      html.unescape); out-of-range/surrogate codepoints and
      non-ASCII decodes fail closed; >64 entities fail closed.
  P4  discrimination: honest NUL/UTF-16 content and honest
      entity-bearing text do NOT block (UTF-16-encoded prose, HTML
      docs with escaped quotes, docs with entities but no NULs,
      NUL-separated non-credential text).
  P5  depth-2 design bound pinned: the documented composition bound
      is unchanged -- _decoded_variants still defaults to max_layers=2;
      F439 triple-base64 (the old depth-3 residual) is CLOSED
      2026-10-05 wave-347 lane 3 and now blocks coded (depth-4+ is the
      documented non-goal).
  P6  ReDoS: hostile near-miss inputs (&# storms, NUL floods)
      complete fast with no exceptions.
  P7  layering: the entity+NUL variant appears in one decode layer;
      it composes with the base64 layer inside the 2-layer budget
      (entity+NUL stacked on base64 blocks).
  P8  pin + footer: taxonomy pin 2135, footer open F437, F439, F440,
      F441, F442 / next F443 (F438 closed).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w347_f438close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64
import html
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-347: pin 2135 (no new codes in wave-347 lane 2); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F476, F477"  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # wave-350 lane 3: F449+F450 CLOSED;  F438 closed wave-347 lane 2; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # wave-350 lane 3: F449+F450 CLOSED;  F438 closed wave-347 lane 2; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)


FOOTER_NEXT = "F478"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential: 37 chars (F438 filed shape). Concatenated -- the
# write/edit tool redacts credential-shaped literals in inputs.
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


def _f438_shape(cred):
    """The verified F438 shape: each byte as &#xHH; separated by NUL."""
    return "".join("&#x%02x;\x00" % b for b in cred.encode())


def _rt_html_nul(payload):
    """Real-parser chain: html.unescape, then strip control/NULs."""
    return html.unescape(payload).replace("\x00", "")


# --------------------------------------------------------------- P1: closure
def p1_f438_shape_blocks():
    payload = _f438_shape(_LONG)
    assert _LONG not in payload, "payload smuggles plaintext"
    assert _rt_html_nul(payload) == _LONG, "roundtrip must recover cred"
    hit = _blocks(payload)
    print("    entity+NUL shape -> %s" % ("BLOCK" if hit else "MISS!"))
    return _check("p1: verified F438 shape blocks coded", hit)


# --------------------------------------------------------------- P2: control
def p2_plain_control():
    ok = _blocks(_LONG)
    return _check("p2: plain credential blocks coded", ok)


# --------------------------------------------------------------- P3: decoder pins
def p3_decoder_pins():
    f = dlp._try_entity_nul_decode_all
    ok = True

    # decodes the F438 shape to the credential
    got = f(_f438_shape(_LONG))
    ok = ok and got == _LONG
    print("    decode(F438-shape) == cred: %s" % (got == _LONG))

    # no NULs -> None (the existing whole-text entity pass owns this)
    got = f("&#x78;&#x6f;&#x62;-abc123def456")
    ok = ok and got is None
    print("    no-NUL text -> None: %s" % (got is None))

    # no entities -> None (the existing NUL-strip path owns this)
    got = f("h\x00e\x00l\x00l\x00o\x00")
    ok = ok and got is None
    print("    no-entity text -> None: %s" % (got is None))

    # malformed entity stays literal (faithful to html.unescape:
    # only valid references decode; the variant is still produced)
    got = f("&#xZZ;\x00&#x6f;\x00")
    ok = ok and got == "&#xZZ;o"
    print("    malformed entity left literal (faithful): %s" % (got == "&#xZZ;o"))

    # out-of-range codepoint -> None (fail closed)
    got = f("&#x110000;\x00&#x6f;\x00")
    ok = ok and got is None
    print("    out-of-range entity -> None: %s" % (got is None))

    # non-ASCII decode -> None (fail closed, ASCII gate)
    got = f("&#xe9;\x00&#x6f;\x00")
    ok = ok and got is None
    print("    non-ASCII entity -> None: %s" % (got is None))

    # > 64 entities -> None (bounded, delegates fail-closed)
    many = "".join("&#x61;\x00" for _ in range(70))
    got = f(many)
    ok = ok and got is None
    print("    70 entities -> None (bound): %s" % (got is None))

    return _check("p3: decoder pins (fail closed)", ok)


# --------------------------------------------------------------- P4: discrimination
def p4_honest_text_quiet():
    cases = {
        # honest UTF-16LE-style prose (no entities)
        "utf16-prose": "T\x00h\x00e\x00 \x00p\x00o\x00l\x00i\x00c\x00y\x00",
        # honest HTML docs with escaped quotes, no NULs
        "html-doc": "Tom &amp; Jerry said &#39;hello&#39; &amp; left.",
        # entities + NULs that decode to a non-credential
        "entity-nul-noncred": "&#x41;\x00&#x42;\x00&#x43;\x00",
        # NUL-separated words, no entities
        "nul-words": "alpha\x00beta\x00gamma\x00delta\x00",
        # credential-adjacent but entity-decoded to junk
        "entity-junk": "&#x78;\x00&#x6f;\x00&#x6f;\x00&#x62;\x00",
    }
    ok = True
    for label, text in cases.items():
        hit = dlp.find_credential(text) is not None
        ok = ok and not hit
        print("    %-24s -> %s" % (label, "MISS-QUIET (ok)" if not hit else "BLOCK!"))
    return _check("p4: honest NUL/entity text quiet", ok)


# --------------------------------------------------------------- P5: depth-2 bound
def p5_depth2_bound_pinned():
    ok = True
    # the design bound is intact: max_layers defaults to 2
    import inspect
    sig = inspect.signature(dlp._decoded_variants)
    ok = ok and sig.parameters["max_layers"].default == 2
    print("    _decoded_variants max_layers default: %s"
          % sig.parameters["max_layers"].default)
    # F439 triple-base64 was the documented residual of that bound --
    # CLOSED 2026-10-05 wave-347 lane 3 (bounded fixpoint, max 3 rounds):
    # triple stacks now block coded; depth-4+ is the documented non-goal.
    cred = _LONG
    w1 = base64.b64encode(cred.encode()).decode()
    w2 = base64.b64encode(w1.encode()).decode()
    w3 = base64.b64encode(w2.encode()).decode()
    hit = dlp.find_credential(w3) == "dlp-slack-token"
    ok = ok and hit
    print("    F439 triple-base64 now BLOCKS (closed): %s" % hit)
    # but double-base64 still blocks (the in-budget control)
    ok = ok and _blocks(w2)
    print("    double-base64 still blocks (control): %s" % _blocks(w2))
    return _check("p5: depth-2 design bound pinned", ok)


# --------------------------------------------------------------- P6: ReDoS
def p6_redos_safety():
    hostile = [
        ("&#" * 5000, "entity-prefix storm"),
        ("&#" + "x" * 5000, "entity-hex storm"),
        ("\x00" * 5000, "NUL flood"),
        (("&#x41;\x00" * 500), "entity-NUL alternating"),
        ("&#;;;;" * 500, "entity garbage"),
        ("&amp;#" * 2000, "named-entity storm"),
    ]
    ok = True
    for text, label in hostile:
        t0 = time.monotonic()
        try:
            dlp.find_credential(text)
            dt = time.monotonic() - t0
            fast = dt < 2.0
            print("    %-28s %.3fs" % (label, dt))
            ok = ok and fast
        except Exception as e:  # noqa: BLE001
            ok = False
            print("    %-28s EXCEPTION %r" % (label, e))
    return _check("p6: ReDoS safety (hostile inputs fast)", ok)


# --------------------------------------------------------------- P7: layering
def p7_one_layer_composition():
    # the new variant fires within ONE decode layer
    payload = _f438_shape(_LONG)
    layers = dlp._decoded_variants(payload, max_layers=1)
    in_one = any(_LONG in v for v in layers)
    # entity+NUL on top of base64: still within the 2-layer budget
    b64stack = _f438_shape(base64.b64encode(_LONG.encode()).decode())
    blocked = _blocks(b64stack)
    print("    entity+NUL variant in 1 layer: %s" % in_one)
    print("    entity+NUL-on-base64 blocks in 2 layers: %s" % blocked)
    return _check("p7: one-layer composition", in_one and blocked)


# --------------------------------------------------------------- P8: pin + footer
def p8_pin_and_footer():
    ok = (len(TAXONOMY) == TAXONOMY_PIN
          and sorted(TAXONOMY) == list(TAXONOMY))
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ok and ("Next free finding: **%s**." % FOOTER_NEXT) in text
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in text
    ok = ok and "F438 filed 2026-10-05, wave-346 lane 2" in text
    ok = ok and "CLOSED 2026-10-05 wave-347 lane 2" in text
    return _check("p8: pin 2135 + closed footer", ok)


# --------------------------------------------------------------- PZ: green checks
def _green():
    """Depth-1 green check: run adjacent batteries' mains with
    GOV_SKIP_GREEN=1 in the child env.

    House convention (w346_f436close): a red-first script is green
    when its last line is exactly HELD; a battery is green when it
    exits 0 AND its tally line shows zero BREAKs (match the count,
    not the word). The w310/w311 red-team batteries
    (w346_dlp_composition) exit 1 by convention whenever expected
    BREAKs are present: green is the absence of "unexpected BREAKs"
    / "expected BREAKs missing" lines.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    failures = []
    for battery, kind in (("evals/w346_f438_redfirst.py", "redfirst"),
                          ("evals/w346_attack_probes.py", "battery"),
                          ("evals/w346_dlp_composition_probes.py", "redteam"),
                          ("evals/w346_f436close_probes.py", "battery")):
        path = os.path.join(REPO_ROOT, battery)
        tmp = "/var/tmp/g347-f438-%s" % battery.split("/")[1].split("_")[0]
        os.makedirs(tmp, exist_ok=True)
        env2 = dict(env)
        env2["TMPDIR"] = tmp
        try:
            r = subprocess.run(
                [sys.executable, path], env=env2, capture_output=True,
                text=True, timeout=600)
            out = r.stdout + r.stderr
            tail = (r.stdout.strip().splitlines() or [""])[-1].strip()
            if kind == "redfirst":
                green = (r.returncode == 0 and tail == "HELD")
            elif kind == "redteam":
                green = ("unexpected BREAKs" not in out
                         and "expected BREAKs missing" not in out)
            else:
                m = re.search(r"(\d+)\s+BREAK", tail)
                nbreak = int(m.group(1)) if m else None
                green = (r.returncode == 0 and nbreak == 0)
            if not green:
                failures.append("%s rc=%d tail=%r" % (battery, r.returncode, tail))
        except Exception as e:  # noqa: BLE001
            failures.append("%s %r" % (battery, e))
    if failures:
        print("    green failures: %s" % "; ".join(failures))
    return "ok" if not failures else "FAIL: " + "; ".join(failures)


def main():
    probes = [p1_f438_shape_blocks, p2_plain_control, p3_decoder_pins,
              p4_honest_text_quiet, p5_depth2_bound_pinned,
              p6_redos_safety, p7_one_layer_composition, p8_pin_and_footer]
    n_break = n_held = n_err = 0
    for probe in probes:
        try:
            if probe():
                n_held += 1
            else:
                n_break += 1
        except Exception as e:  # noqa: BLE001
            n_err += 1
            print("%-46s ERROR %r" % (probe.__name__, e))
    note = _green()
    print("green: %s" % note)
    if "FAIL" in note:
        n_break += 1
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
