"""Break-first red-team battery for the wave-260 policy distribution plane.

Wave-260 feature lane 1 (permitio/opal ADAPT: signed policy distribution;
pattern only, no donor code). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Target: gov/policy_distribution.py -- Publisher.sign_bundle /
Subscriber.apply with signed bundles verified (Ed25519 signature,
monotonic version, topic binding) BEFORE load.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused with the expected machine
code, or documented honest residual), GAP (capability absent --
pre-fix baseline; the lane is not built), BREAK (genuine defect in
the built capability -> filed as a finding F230+), ERROR (harness
bug -- fix the harness, never the product).

Probe roster:
  poldist/forged-signature        forged Ed25519 signature refused
  poldist/tampered-payload        payload bytes changed after signing
  poldist/replayed-older-version  older version re-applied (rollback)
  poldist/cross-topic-replay      topic-A bundle fed to topic-B subscriber
  poldist/unsigned-bundle         no signature field at all
  poldist/malformed-envelope      non-JSON / shape violations
  poldist/version-skip            gap forward (documented handling)
  poldist/duplicate-delivery      same version+payload re-applied
  poldist/equivocation            same version, different payload
  poldist/taxonomy-pin            refusal vocabulary pin
"""

import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

try:
    from gov import policy_distribution as pd  # noqa: E402
    _HAS_POLDIST = True
except ImportError:
    pd = None  # noqa: E402
    _HAS_POLDIST = False

try:
    from gov import decision_codes  # noqa: E402
    _HAS_CODES = True
except ImportError:
    decision_codes = None  # noqa: E402
    _HAS_CODES = False

# Wave-260 lane-1 base pin. The lane adds 5 poldist-* codes:
# 1080 -> 1085. If the count moves otherwise, the delta must be
# explained by a landed taxonomy change -- never repoint blindly.
TAXONOMY_PIN = 1443  # Wave-271 merge: pin 1372 -> 1411 (+39 codes: 6 ptgrant-* + 7 replay-* + 8 rsl-* + 14 gatehard-* + 4 imgtext-*).

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _require_module():
    """Return (held_tuple_or_None). GAP verdict while the lane is unbuilt."""
    if not _HAS_POLDIST:
        return ("GAP", "gov.policy_distribution absent (capability not built)")
    return None


def _pair(topic="policies"):
    """Fresh publisher/subscriber pair bound to one topic."""
    seed = os.urandom(32)
    pub = pd.Publisher(seed)
    sub = pd.Subscriber(topic=topic, pubkey=pub.pubkey)
    return pub, sub


def _outcome(result):
    return result.get("outcome")


def _code(result):
    mc = result.get("code") or {}
    return mc.get("code")


@probe("poldist/forged-signature")
def _p_forged_signature():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    bundle = pub.sign_bundle("policies", 1, {"deny": ["rm -rf"]})
    env = json.loads(bundle.decode("utf-8"))
    # Attack: forge a signature from an attacker-controlled seed over a
    # hostile payload, same topic/version.
    evil = pd.Publisher(os.urandom(32))
    evil_bundle = evil.sign_bundle("policies", 1, {"deny": []})
    evil_env = json.loads(evil_bundle.decode("utf-8"))
    env["sig"] = evil_env["sig"]
    forged = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    res = sub.apply(forged)
    if _outcome(res) == "refused" and _code(res) == "poldist-signature-mismatch":
        return ("HELD", "forged signature refused poldist-signature-mismatch")
    return ("BREAK", "forged signature outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/tampered-payload")
def _p_tampered_payload():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    bundle = pub.sign_bundle("policies", 1, {"deny": ["rm -rf"]})
    env = json.loads(bundle.decode("utf-8"))
    env["payload"] = {"deny": []}  # tamper after signing
    tampered = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    res = sub.apply(tampered)
    if _outcome(res) == "refused" and _code(res) == "poldist-signature-mismatch":
        return ("HELD", "post-signing payload tamper refused")
    return ("BREAK", "tampered payload outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/replayed-older-version")
def _p_replayed_older():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    b1 = pub.sign_bundle("policies", 1, {"a": 1})
    b2 = pub.sign_bundle("policies", 2, {"a": 2})
    r2 = sub.apply(b2)
    if _outcome(r2) != "applied":
        return ("ERROR", "setup: v2 did not apply: %r" % (r2,))
    res = sub.apply(b1)  # replay the older version
    if _outcome(res) == "refused" and _code(res) == "poldist-version-rollback":
        return ("HELD", "older-version replay refused poldist-version-rollback")
    return ("BREAK", "rollback replay outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/cross-topic-replay")
def _p_cross_topic():
    gap = _require_module()
    if gap:
        return gap
    pub, sub_b = _pair(topic="grants")
    bundle_a = pub.sign_bundle("policies", 1, {"deny": ["x"]})
    # Validly signed bundle for topic "policies" fed to the "grants"
    # subscriber: must be refused on topic binding, never applied.
    res = sub_b.apply(bundle_a)
    if _outcome(res) == "refused" and _code(res) == "poldist-topic-cross":
        return ("HELD", "cross-topic replay refused poldist-topic-cross")
    return ("BREAK", "cross-topic bundle outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/unsigned-bundle")
def _p_unsigned():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    env = {"v": 1, "topic": "policies", "version": 1,
           "payload": {"deny": []}}  # no "sig" at all
    unsigned = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    res = sub.apply(unsigned)
    if _outcome(res) == "refused" and _code(res) == "poldist-signature-missing":
        return ("HELD", "unsigned bundle refused poldist-signature-missing")
    return ("BREAK", "unsigned bundle outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/malformed-envelope")
def _p_malformed():
    gap = _require_module()
    if gap:
        return gap
    _, sub = _pair()
    cases = [
        b"not json at all",
        json.dumps({"v": 1}).encode(),                      # missing fields
        json.dumps({"v": 1, "topic": "policies", "version": "x",
                    "payload": {}, "sig": "00" * 64}).encode(),  # bad version
        json.dumps({"v": 1, "topic": "policies", "version": 1,
                    "payload": {}, "sig": "zz" * 64}).encode(),  # bad sig hex
        b"",                                                 # empty
    ]
    for raw in cases:
        res = sub.apply(raw)
        if not (_outcome(res) == "refused"
                and _code(res) == "poldist-bundle-malformed"):
            return ("BREAK", "malformed case outcome=%r code=%r (raw=%r)"
                    % (_outcome(res), _code(res), raw[:40]))
    return ("HELD", "5/5 malformed envelopes refused "
            "poldist-bundle-malformed")


@probe("poldist/version-skip")
def _p_version_skip():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    r1 = sub.apply(pub.sign_bundle("policies", 1, {"a": 1}))
    if _outcome(r1) != "applied":
        return ("ERROR", "setup: v1 did not apply: %r" % (r1,))
    # Skip forward: v1 -> v4 (missed diffs; OPAL diff updates may gap).
    # Documented handling: applied (monotonic), gap flagged in the
    # result so the deployment can reconcile.
    res = sub.apply(pub.sign_bundle("policies", 4, {"a": 4}))
    if _outcome(res) == "applied" and res.get("gap") is True:
        return ("HELD", "forward skip applied with gap=True (documented)")
    return ("BREAK", "version-skip outcome=%r code=%r gap=%r"
            % (_outcome(res), _code(res), res.get("gap")))


@probe("poldist/duplicate-delivery")
def _p_duplicate():
    gap = _require_module()
    if gap:
        return gap
    pub, sub = _pair()
    b1 = pub.sign_bundle("policies", 1, {"a": 1})
    r1 = sub.apply(b1)
    if _outcome(r1) != "applied":
        return ("ERROR", "setup: v1 did not apply: %r" % (r1,))
    res = sub.apply(b1)  # identical bytes re-delivered
    if _outcome(res) == "applied" and res.get("duplicate") is True:
        return ("HELD", "identical re-delivery applied idempotently")
    return ("BREAK", "duplicate outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/equivocation")
def _p_equivocation():
    gap = _require_module()
    if gap:
        return gap
    seed = os.urandom(32)
    pub = pd.Publisher(seed)
    sub = pd.Subscriber(topic="policies", pubkey=pub.pubkey)
    r1 = sub.apply(pub.sign_bundle("policies", 1, {"a": 1}))
    if _outcome(r1) != "applied":
        return ("ERROR", "setup: v1 did not apply: %r" % (r1,))
    # Same key, same version, DIFFERENT payload, both validly signed: a
    # fork of the topic. One Publisher instance cannot mint this (its
    # monotonic guard refuses), so the fork comes from a second
    # instance holding the same seed -- the documented fork residual.
    # The subscriber must not silently switch heads.
    fork = pd.Publisher(seed)
    res = sub.apply(fork.sign_bundle("policies", 1, {"a": 2}))
    if _outcome(res) == "refused" and _code(res) == "poldist-version-rollback":
        if sub.payload == {"a": 1} and sub.version == 1:
            return ("HELD", "same-version-different-payload refused; "
                    "head unchanged (equivocation-shaped)")
        return ("BREAK", "refused but head was mutated")
    return ("BREAK", "equivocation outcome=%r code=%r"
            % (_outcome(res), _code(res)))


@probe("poldist/taxonomy-pin")
def _p_taxonomy_pin():
    gap = _require_module()
    if gap:
        return gap
    if not _HAS_CODES:
        return ("ERROR", "gov.decision_codes not importable")
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        return ("ERROR", "taxonomy has %d keys, pin is %d" % (n, TAXONOMY_PIN))
    for code in ("poldist-bundle-malformed", "poldist-signature-missing",
                 "poldist-signature-mismatch", "poldist-topic-cross",
                 "poldist-version-rollback"):
        if code not in decision_codes.TAXONOMY:
            return ("BREAK", "code %r missing from taxonomy" % code)
    if sorted(decision_codes.TAXONOMY) != list(decision_codes.TAXONOMY):
        return ("BREAK", "taxonomy not sorted")
    return ("HELD", "pin %d holds; 5 poldist codes registered, sorted"
            % TAXONOMY_PIN)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent batteries still green. Honors GOV_SKIP_GREEN."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w259_redteam_probes.py",
                    "evals/w259_transparency_probes.py"):
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
    held = gaps = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "GAP":
            gaps += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d over %d probes"
          % (held, gaps, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
