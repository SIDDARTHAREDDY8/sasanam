"""Break-first battery for the F235 closure (wave-262 lane A).

F235: gov/policy_distribution.py Subscriber.apply raised RecursionError
on hostile unsigned deeply-nested JSON, violating the module's explicit
"Never raises on hostile input; every refusal is machine-coded"
contract (unauthenticated availability kill at the designed transport
seam). Fix: catch RecursionError at the unsigned-input parse boundary
and refuse with the existing poldist-bundle-malformed code -- no new
code, no hard depth bound (legitimate depth still verifies).

Stdlib only. Deterministic (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail closed).

Probes:
  poldist/recursion-error-on-hostile-unsigned-input -- the wave-261
      red-team's own probe, imported and run verbatim: BREAKs pre-fix
      (RecursionError escapes apply()), HELDs post-fix.
  poldist2/depth-just-under-boundary-unsigned-refused -- a bundle just
      under the interpreter recursion budget still parses and is
      refused on the signature seam (control: HELD pre- and post-fix).
  poldist2/depth-just-over-boundary-refused-machine-coded -- a bundle
      far over the budget is refused with poldist-bundle-malformed
      (BREAKs pre-fix, HELDs post-fix).
  poldist2/signed-deep-bundle-still-verifies -- a validly signed
      bundle nested deep-but-legal still verifies and applies (the
      fix must not bound legitimate depth; control: HELD pre/post).
  poldist2/hostile-input-time-memory-bounded -- the 100000-deep
      hostile input is refused fast and small (BREAKs pre-fix, HELDs
      post-fix).

Verdicts: HELD (attack refused / gap closed), BREAK (defect still
present), ERROR (harness bug -- fix the harness, never the product).
"""

import os
import secrets
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w262-poldist2")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import policy_distribution as poldist  # noqa: E402
import evals.w261_redteam_probes as w261rt  # noqa: E402  (F235 pin probe)

# Wave-262 lane A adds no decision codes: the F235 fix reuses the
# existing poldist-bundle-malformed. Replace the VALUE only, never
# repoint blindly (wave-256 lesson).
TAXONOMY_PIN = 1205  # Taxonomy pin from the wave-262 lane brief.

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _pair(topic="policies"):
    seed = bytes.fromhex("ab" * 32)
    pub = poldist.Publisher(seed)
    return pub, poldist.Subscriber(topic, pub.pubkey)


def _hostile_nested(depth):
    """Hand-crafted hostile bytes (no stdlib json on the attack side):
    an UNSIGNED bundle whose payload nests `depth` deep."""
    return ('{"v":1,"topic":"policies","version":1,"payload":{"nest":'
            + "[" * depth + '"x"' + "]" * depth
            + '},"sig":"' + "0" * 128 + '"}').encode("utf-8")


def _code(out):
    c = out.get("code")
    return c["code"] if isinstance(c, dict) else c


@probe("poldist/recursion-error-on-hostile-unsigned-input")
def _p_f235_pin():
    # The red-team's own probe, run verbatim: it is the standing
    # regression pin for F235 (evals/FINDINGS.md).
    for name, fn in w261rt._PROBES:
        if name == "poldist/recursion-error-on-hostile-unsigned-input":
            verdict, detail = fn()
            return (verdict, "red-team pin: " + detail)
    return ("ERROR", "red-team F235 probe not found in w261 battery")


@probe("poldist2/depth-just-under-boundary-unsigned-refused")
def _p_under():
    _, sub = _pair()
    # 900 deep: well under the interpreter's recursion budget, so the
    # envelope parses and dies on the signature seam -- unsigned bytes
    # are still refused, just at a later check.
    try:
        out = sub.apply(_hostile_nested(900))
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break("under-budget unsigned input raised %s"
                      % type(e).__name__)
    c = _code(out)
    if out["outcome"] == "refused" and c == "poldist-signature-mismatch":
        return _held("900-deep unsigned bundle refused as %s" % c)
    return _break("under-budget unsigned bundle not refused on the "
                  "signature seam: %s/%s" % (out["outcome"], c))


@probe("poldist2/depth-just-over-boundary-refused-machine-coded")
def _p_over():
    _, sub = _pair()
    try:
        out = sub.apply(_hostile_nested(30000))
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break("over-budget unsigned input raised %s out of "
                      "apply(): %s" % (type(e).__name__, str(e)[:80]))
    c = _code(out)
    if out["outcome"] == "refused" and c == "poldist-bundle-malformed":
        return _held("30000-deep unsigned bundle refused as %s" % c)
    return _break("over-budget unsigned bundle mis-refused: %s/%s"
                  % (out["outcome"], c))


@probe("poldist2/signed-deep-bundle-still-verifies")
def _p_signed_deep():
    # Legitimate depth must survive the fix: a validly signed bundle
    # nested 800 deep (inside the interpreter budget) still verifies
    # and applies. A hard-coded depth bound would fail this probe.
    pub, sub = _pair()
    payload = "x"
    for _ in range(800):
        payload = [payload]
    try:
        out = sub.apply(pub.sign_bundle("policies", 1,
                                        {"nest": payload}))
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break("signed 800-deep bundle raised %s"
                      % type(e).__name__)
    if out["outcome"] == "applied" and out["version"] == 1:
        return _held("signed 800-deep bundle applied, version 1")
    return _break("signed 800-deep bundle not applied: %s/%s"
                  % (out["outcome"], _code(out)))


@probe("poldist2/hostile-input-time-memory-bounded")
def _p_bounded():
    # 100000-deep hostile input: refusal must be fast and small, not a
    # slow stack-unwind or a memory blowup. Budget: 2.0s wall (measured
    # ~2ms post-fix; pre-fix it raised instantly, so any BREAK here is
    # the defect, not a timeout).
    _, sub = _pair()
    raw = _hostile_nested(100000)
    t0 = time.time()
    try:
        out = sub.apply(raw)
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break("100000-deep input raised %s out of apply()"
                      % type(e).__name__)
    dt = time.time() - t0
    c = _code(out)
    if out["outcome"] != "refused" or c != "poldist-bundle-malformed":
        return _break("100000-deep input mis-refused: %s/%s"
                      % (out["outcome"], c))
    if dt > 2.0:
        return _break("refusal took %.2fs (>2.0s budget)" % dt)
    return _held("100000-deep input refused as %s in %.3fs"
                 % (c, dt))


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: the adjacent wave-260 poldist battery still green.
    Honors GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w260_poldist_probes.py",):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes"
          % (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
