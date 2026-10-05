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
  poldist-forged-signature        forged Ed25519 signature refused
  poldist-tampered-payload        payload bytes changed after signing
  poldist-replayed-older-version  older version re-applied (rollback)
  poldist-cross-topic-replay      topic-A bundle fed to topic-B subscriber
  poldist-unsigned-bundle         no signature field at all
  poldist-malformed-envelope      non-JSON / shape violations
  poldist-version-skip            gap forward (documented handling)
  poldist-duplicate-delivery      same version+payload re-applied
  poldist-equivocation            same version, different payload
  poldist-taxonomy-pin            refusal vocabulary pin
"""

import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

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
TAXONOMY_PIN = 2083 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)



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


@probe("poldist-forged-signature")
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


@probe("poldist-tampered-payload")
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


@probe("poldist-replayed-older-version")
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


@probe("poldist-cross-topic-replay")
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


@probe("poldist-unsigned-bundle")
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


@probe("poldist-malformed-envelope")
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


@probe("poldist-version-skip")
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


@probe("poldist-duplicate-delivery")
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


@probe("poldist-equivocation")
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


@probe("poldist-taxonomy-pin")
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


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# BASELINE is defined by these batteries as "known-open finding reproduced"
# (dead in practice: no probe returns it) and maps to BREAK as well. Raw rows
# keep the battery's own vocabulary (count code and exit contract untouched);
# the mapping happens here, at emission. Anything else fails closed as ERROR.
def _mapped(rows):
    out = []
    for _name, _verdict, _detail in rows:
        if _verdict in ("GAP", "BASELINE"):
            out.append((_name, "BREAK", "%s: %s" % (_verdict, _detail)))
        elif _verdict in ("HELD", "BREAK", "ERROR"):
            out.append((_name, _verdict, _detail))
        else:
            out.append((_name, "ERROR",
                        "unexpected verdict %r: %s" % (_verdict, _detail)))
    return out

def main():
    held = gaps = breaks = errors = 0
    rows = []
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
        rows.append((name, verdict, detail))
    mapped = _mapped(rows)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, breaks + gaps, held, errors)
    probe_lines.emit(mapped)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks + gaps, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
