"""Break-first probes for gov/vsa_threshold (wave-324 lane 3).

Multi-verifier threshold VSA decision packets: k-of-n independent
verifiers co-sign one statement over a decision packet digest; the
consumer enforces threshold, bindings, freshness, and policy-version
currency. Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.vsa_threshold). On the lane tree every
attack below must refuse with the coded reason -- 0 BREAK target.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------

SEED_V1 = bytes(range(32))
SEED_V2 = bytes([255 - i for i in range(32)])
SEED_V3 = bytes([(i * 7) % 256 for i in range(32)])
SEED_EVIL = bytes([(i * 29 + 5) % 256 for i in range(32)])

DECISION_A = "a" * 64
DECISION_B = "b" * 64
NOW = 1798765432.0  # 2027-01-01T01:03:52Z
MAX_AGE = 3600.0
FRESH_TIME = "2027-01-01T00:30:00Z"  # inside [NOW-1h, NOW]


def _mod():
    from gov import vsa_threshold as vt
    from gov.signing import Ed25519Signer
    return vt, Ed25519Signer


def _signers():
    vt, Ed25519Signer = _mod()
    s1 = Ed25519Signer(SEED_V1)
    s2 = Ed25519Signer(SEED_V2)
    s3 = Ed25519Signer(SEED_V3)
    evil = Ed25519Signer(SEED_EVIL)
    return s1, s2, s3, evil


def _inputs(policy_version=5):
    return {
        "policy": {
            "uri": "sasanam:policy/governance/v5",
            "digest": "c" * 64,
            "policy_id": "governance",
            "version": policy_version,
        },
        "artifact_digests": {"decision-packet": DECISION_A},
        "evidence_references": ["sasanam:bundle/abc123"],
    }


def _verification(verifier_id, inputs=None, verdict="PASSED",
                  levels=("decision-evidence-complete",),
                  time_verified=FRESH_TIME):
    return {
        "verifier_id": verifier_id,
        "verdict": verdict,
        "verified_levels": list(levels),
        "inputs": inputs if inputs is not None else _inputs(),
        "time_verified": time_verified,
    }


def _issue(signers, verifier_ids, decision=DECISION_A, threshold=2,
           verifications=None, inputs=None):
    vt, _ = _mod()
    s1, s2, s3, evil = signers
    by_seed = {"v1": s1, "v2": s2, "v3": s3, "evil": evil}
    verifs = (verifications if verifications is not None
              else [_verification(vid, inputs=inputs) for vid in verifier_ids])
    signer_objs = [{"verifier_id": vid,
                    "key_id": by_seed[vid].key_id,
                    "sign": by_seed[vid].sign} for vid in verifier_ids]
    return vt.issue_vsa(decision, verifs, signer_objs, threshold)


def _trust(s1, s2, s3, evil=None, min_version=5, min_threshold=None):
    trust = {
        "verifier_registry": {
            "v1": [s1.public_key.hex()],
            "v2": [s2.public_key.hex()],
            "v3": [s3.public_key.hex()],
        },
        "expected_subject_digest": DECISION_A,
        "required_level": "decision-evidence-complete",
        "max_age_seconds": MAX_AGE,
        "now": NOW,
        "policy_currency": {"policy_id": "governance", "min_version": min_version},
    }
    if evil is not None:
        trust["verifier_registry"]["evil"] = [evil.public_key.hex()]
    if min_threshold is not None:
        trust["min_threshold"] = min_threshold
    return trust


# ---------------------------------------------------------------------------
# P1-P16: the attacks.
# ---------------------------------------------------------------------------

@probe("P1-forged-verifier-signature")
def _p1():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    # Forge: replace v2's signature bytes with garbage from the evil key
    # over a different message (it will not verify over the body).
    packet["attestations"][1]["signature"] = evil.sign(b"forged").hex()
    _expect_code("P1-forged-verifier-signature",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-signature-invalid")


@probe("P2-below-threshold")
def _p2():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    # Drop v2's attestation: the roster is not part of the signed
    # statement, so v1's signature still verifies -- but the quorum is
    # no longer met (1 distinct valid < 2).
    del packet["attestations"][1]
    _expect_code("P2-below-threshold",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-below-quorum")


@probe("P3-decision-transplant")
def _p3():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    trust = _trust(s1, s2, s3)
    trust["expected_subject_digest"] = DECISION_B  # presented for decision B
    _expect_code("P3-decision-transplant",
                 lambda: vt.verify_vsa(packet, trust),
                 "vsa-packet-subject-mismatch")


@probe("P4-input-substitution")
def _p4():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    # Swap the artifact digest after signing: the signatures bind the
    # original inputs, so this must not verify.
    packet["inputs"]["artifact_digests"]["decision-packet"] = "d" * 64
    _expect_code("P4-input-substitution",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-signature-invalid")


@probe("P5-stale-policy-version")
def _p5():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                    inputs=_inputs(policy_version=3))
    _expect_code("P5-stale-policy-version",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3, min_version=5)),
                 "vsa-threshold-policy-stale")


@probe("P6-expired-vsa")
def _p6():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    old = "2026-10-03T08:00:00Z"  # 24h before NOW, max_age is 1h
    verifs = [_verification("v1", time_verified=old),
              _verification("v2", time_verified=old)]
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                    verifications=verifs)
    _expect_code("P6-expired-vsa",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-packet-window-invalid")


@probe("P7-unknown-verifier")
def _p7():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "evil"], threshold=2)
    _expect_code("P7-unknown-verifier",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-signer-unpinned")


@probe("P8-signature-replay-across-decisions")
def _p8():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet_a = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                      decision=DECISION_A)
    packet_b = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                      decision=DECISION_B)
    # Transplant v1's signature from packet A into packet B's v1 entry:
    # the signature is bound to A's body and must not verify over B.
    sig_a = packet_a["attestations"][0]["signature"]
    packet_b["attestations"][0]["signature"] = sig_a
    trust = _trust(s1, s2, s3)
    trust["expected_subject_digest"] = DECISION_B
    _expect_code("P8-signature-replay-across-decisions",
                 lambda: vt.verify_vsa(packet_b, trust),
                 "vsa-threshold-signature-invalid")


@probe("P9-malformed-packet")
def _p9():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    _expect_code("P9-malformed-packet",
                 lambda: vt.verify_vsa({"type": "sasanam-threshold-vsa/1"},
                                       _trust(s1, s2, s3)),
                 "vsa-packet-malformed")


@probe("P10-unknown-fields")
def _p10():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    packet["smuggled"] = "evil"
    _expect_code("P10-unknown-fields",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-packet-malformed")


@probe("P11-double-count-same-verifier")
def _p11():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    # v1's attestation appears twice (a copied entry): both signatures
    # verify, but set semantics must count the verifier once, so
    # threshold 2 is NOT met.
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    packet["attestations"][1] = dict(packet["attestations"][0])
    _expect_code("P11-double-count-same-verifier",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-below-quorum")


@probe("P12-unpinned-key-under-pinned-verifier")
def _p12():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    # evil signs but claims verifier_id v1: the key_id is not pinned for
    # v1, so this must refuse even though the signature itself verifies.
    verifs = [_verification("v1"), _verification("v2")]
    signer_objs = [{"verifier_id": "v1", "key_id": evil.key_id,
                    "sign": evil.sign},
                   {"verifier_id": "v2", "key_id": s2.key_id,
                    "sign": s2.sign}]
    packet = vt.issue_vsa(DECISION_A, verifs, signer_objs, 2)
    _expect_code("P12-unpinned-key-under-pinned-verifier",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-signer-unpinned")


@probe("P13-verdict-not-passed")
def _p13():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    verifs = [_verification("v1", verdict="FAILED"),
              _verification("v2", verdict="FAILED")]
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                    verifications=verifs)
    _expect_code("P13-verdict-not-passed",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-threshold-verdict-not-passed")


@probe("P14-required-level-missing")
def _p14():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    verifs = [_verification("v1", levels=("some-other-level",)),
              _verification("v2", levels=("some-other-level",))]
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2,
                    verifications=verifs)
    _expect_code("P14-required-level-missing",
                 lambda: vt.verify_vsa(packet, _trust(s1, s2, s3)),
                 "vsa-packet-levels-missing")


@probe("P15-threshold-sanity")
def _p15():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    # threshold is part of the signed statement, so it cannot be
    # tampered post-issuance (that breaks signatures first). The
    # k > n case is built honestly: issue 2-of-2, then present the
    # packet against a consumer demanding min_threshold 3.
    packet = _issue((s1, s2, s3, evil), ["v1", "v2"], threshold=2)
    trust = _trust(s1, s2, s3, min_threshold=3)
    _expect_code("P15-threshold-sanity",
                 lambda: vt.verify_vsa(packet, trust),
                 "vsa-threshold-below-quorum")


@probe("P16-honest-quorum-verifies")
def _p16():
    vt, _ = _mod()
    s1, s2, s3, evil = _signers()
    packet = _issue((s1, s2, s3, evil), ["v1", "v2", "v3"], threshold=2)
    claims = vt.verify_vsa(packet, _trust(s1, s2, s3))
    assert claims["ok"] is True
    assert claims["subject_digest"] == DECISION_A
    assert sorted(claims["verifier_ids"]) == ["v1", "v2", "v3"]
    assert "PASSED" not in claims  # no authorization verdict, ever
    _held("P16-honest-quorum-verifies", "3-of-3 quorum verifies; no verdict")


# ---------------------------------------------------------------------------
# P17/P18: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P17-pin-taxonomy-2135-sorted")
def _p17():
    from gov import decision_codes as dc
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN, \
        "want %d/%d/0, got %d/%d" % (TAXONOMY_PIN, TAXONOMY_PIN,
                                     len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    assert len(dc.TAXONOMY) == TAXONOMY_PIN
    _held("P17-pin-taxonomy-2135-sorted",
          "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


@probe("P18-footer-state")
def _p18():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Wave-336 lane 1: repaired stale assertion (never-current text).
    assert "Next free finding: **F454**. **Open findings: F446, F447, F448, F449, F450.**" in text, \
        "footer mismatch"
    _held("P18-footer-state", "open F444, F445 / next F446")


# ---------------------------------------------------------------------------
# Green checks (depth-1): delegate to evals/green_check.py per the
# fail-closed green-check contract (evals/GREEN_CHECK_CONTRACT.md, Rule 7:
# new batteries delegate instead of reimplementing the subprocess dance).
# Exact-summary form (wave-305): the child's verbatim summary line must
# appear; deviation records BREAK. Counts (not messages) are pinned, so
# a merge repoint does not break the check.
# ---------------------------------------------------------------------------

_GREEN_CHILDREN = (
    ("evals/w323_monitor_probes.py",
     "w323_monitor battery: 0 BREAK / 24 HELD / 0 ERROR "),
    ("evals/w323_exwitness_probes.py",
     "w323_exwitness battery: 0 BREAK / 30 HELD / 0 ERROR "),
    ("evals/w323_redteam_probes.py",
     "w323_redteam battery: 0 BREAK / 42 HELD / 0 ERROR "),
    ("evals/w321_redteam_probes.py",
     "RESULT: 0 BREAK / 36 HELD / 0 ERROR"),
)


def _green():
    for child, expected_summary in _GREEN_CHILDREN:
        label = "green-" + os.path.basename(child).replace("_probes.py", "")
        status, detail = green_check.check_battery_result(
            label, child, repo=REPO, expected_summary=expected_summary)
        _record(label, status, detail)


def main():
    ordered = []
    for i in range(1, 40):
        fn = globals().get("_p%d" % i)
        if callable(fn):
            ordered.append(fn)
    for fn in ordered:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w324_vsa battery: %d BREAK / %d HELD / %d ERROR "
          % (n_break, n_held, n_err))


if __name__ == "__main__":
    main()
