#!/usr/bin/env python3
"""Unit tests for gov/decision_codes.py (wave-228).

Stdlib + gov.decision_codes / gov.decision_packet only. The vocabulary
inventory is imported from the wave-228 battery (evals/w228_codes_probes.py),
which re-implements the audited refusal idioms from source -- never the
module under test.
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as _bom_mod  # noqa: E402

_EVALS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "evals")
sys.path.insert(0, _EVALS)
import importlib.util as _ilu  # noqa: E402

_spec = _ilu.spec_from_file_location(
    "w228_codes_probes", os.path.join(_EVALS, "w228_codes_probes.py"))
_probes = _ilu.module_from_spec(_spec)
# The battery only runs main() under `if __name__ == "__main__"`, so
# importing it here executes just the module level (incl. VOCAB).
_spec.loader.exec_module(_probes)
VOCAB = getattr(_probes, "VOCAB", None)

SEED = bytes.fromhex("22" * 32)
GOOD_DIGESTS = ["ab" * 32, "cd" * 32]


def _minimal_kwargs(**over):
    kw = dict(decision="deny", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              issued_at="2026-09-28T00:00:00+00:00")
    kw.update(over)
    if "bill_of_materials" not in over:
        kw["bill_of_materials"] = _bom_mod.build_bom(
            policy_id=kw["policy_id"],
            policy_version=kw["policy_version"],
            policy_digest="ab" * 32,
            evidence_head_digest=kw["evidence_head_digest"],
            principal={"agent_id": None, "role": None,
                       "principal": None, "run_id": None})
    return kw


def _packet(decision_code=None):
    body = dp.build_decision_packet(
        **_minimal_kwargs(decision_code=decision_code))
    return dp.sign_packet(body, SEED)


class VocabularyCoverageTest(unittest.TestCase):
    def test_509_vocabulary_fully_mapped(self):
        self.assertIsNotNone(VOCAB, "battery vocabulary not importable")
        missing = [c for c in VOCAB if c not in dc.TAXONOMY]
        self.assertEqual(missing, [],
                         "unmapped refusal strings: %r" % (missing[:8],))
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes: 1 breach-boundary + 9 skill-admission + 2 evidence-envelope + 6 skill-update + 13 identity + 3 combine + 7 artifact), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1723)  # Wave-279 lane 2: pin 1493 -> 1494 (+1 evbundle-contract-refused); additive only. Wave-275 lane D: pin 1485 -> 1485 (+5 coverage-*); additive only. Wave-270 merge: pin 1325 -> 1372 (+47 codes: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*); merge coordinator composed.; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        # 599 = wave-233 merge pin; + 3 wave-234 lane-A octet-digest chain
        # codes (chain-octet-digest-{mismatch,absent}, chain-record-truncated,
        # domain audit), + 7 wave-234 lane-B token-hygiene codes
        # (token-{malformed,ttl-exceeded,expired,audience-missing,
        # audience-mismatch,key-stale,in-log}), + 8 wave-234 lane-C
        # consumption-ledger codes (previously-consumed,
        # consumption-{idempotency-reused,instance-malformed,key-malformed,
        # journal-unusable,journal-write-failed,receipt-malformed,
        # receipt-tampered}), additive, zero deletions, zero key collisions,
        # composed at merge from the three lane commits by direct
        # byte-verification, pin updated here to match.
        # + 4 wave-235 lane-A trust-material codes (untrusted-key,
        # trust-key-repointed, unsigned-field-ignored,
        # trust-material-malformed, domain trust),
        # + 7 wave-235 lane-B bound-permit codes (permit-{decision,mandate,
        # policy}-absent, permit-jti-duplicate,
        # permit-leg-refusal-unmapped, permit-malformed, permit-tampered,
        # domain permit),
        # + 3 wave-235 lane-C grant-attenuation codes (grant-widened,
        # grant-attenuation-gap, grant-chain-required, domain grants;
        # grant-revoked and grant-malformed REUSED from the existing
        # taxonomy, no redefinition), additive, zero deletions,
        # zero key collisions.
        # + 7 wave-236 lane-A close-record signer binding codes
        # (close-signer-mismatch, close-trust-repointed,
        # close-unsigned-scope, close-chain-digest-mismatch,
        # close-record-malformed, close-signer-absent,
        # close-signature-invalid, domain close),
        # additive, zero deletions, zero key collisions.
        # + 4 wave-236 lane-B denial-capsule codes (denial-unsealed,
        # denial-capsule-malformed, denial-capsule-signature-invalid,
        # denial-disclosure-mismatch, domain denial), additive, zero
        # deletions, zero key collisions.
        # + 5 wave-236 lane-C permit/closure codes (permit-binding-mismatch,
        # dispatch-without-permit, closure-permit-absent,
        # closure-permit-mismatch, closure-scope-widened; domain permit;
        # permit-malformed/permit-tampered reused), additive, zero
        # deletions, zero key collisions.
        # Wave-236 merge: 631 + 16 = 647, composed from the three lane
        # commits by direct byte-verification, pin updated here to match.
        # Wave-237 merge: 647 + 20 = 667 (4 lane-A three-outcome
        # gate-rule codes: gate-tampered, gate-undecidable,
        # gate-verdict-unreasoned, gate-undecidable-allowed; 3 lane-B
        # edited-approval refusal codes: approval-edited,
        # approval-rebinding, approval-malformed; 5 lane-C
        # canonical-record codes: record-duplicate-member,
        # record-depth-exceeded, record-noncanonical-float,
        # record-malformed, record-opaque-bytes; 8 lane-D closure-scoped
        # approval codes: approval-{run,sandbox,route}-mismatch,
        # approval-capability-dead, approval-state-stale,
        # scoped-approval-{malformed,tampered,capability-unknown}),
        # additive, zero deletions, zero key collisions, composed from
        # the four lane commits by direct byte-verification, pin
        # updated here to match.
        # Wave-238 merge: 667 + 28 = 695 (10 lane-A C2SP
        # tlog-checkpoint codes: checkpoint-origin-empty,
        # checkpoint-size-malformed, checkpoint-root-malformed,
        # checkpoint-extension-empty, checkpoint-log-empty,
        # checkpoint-not-c2sp, checkpoint-note-malformed,
        # checkpoint-no-trusted-signature,
        # checkpoint-known-signature-invalid, checkpoint-inconsistent;
        # 8 lane-B bundle-verification invariant codes:
        # verify-signature-failed, verify-no-clean-verifier,
        # verify-symlink-escape, verify-artifactsfrom-empty,
        # verify-timestamp-eku-missing, verify-attestor-shadowed,
        # verify-collection-empty-match, verify-hash-downgrade;
        # 4 lane-C attested-vs-asserted codes:
        # attestation-class-unlabeled, attestation-class-inflation,
        # attestation-outcome-misread, attestation-record-malformed;
        # 6 lane-D independent-corroboration codes:
        # corroboration-malformed, corroboration-unattested,
        # corroboration-untrusted-source,
        # corroboration-signature-invalid,
        # corroboration-key-inequality, corroboration-uncorroborated),
        # additive, zero deletions, zero key collisions, composed from
        # the four lane commits by direct byte-verification, pin
        # updated here to match.
        # Wave-239 merge: 695 + 23 = 718 (8 lane-A AAuth R3
        # vocabulary grant codes: r3-unknown-operation,
        # r3-vocabulary-unknown, r3-malformed, r3-s256-mismatch,
        # r3-grant-hash-mismatch, r3-per-call-binding-broken,
        # r3-no-match, r3-grant-beyond-document; 6 lane-B
        # claim-at-dispatch codes: claim-malformed,
        # claim-invalid-grant, claim-not-presented,
        # claim-not-releasable, claim-replay, claim-lease-expired;
        # 3 lane-C refusal-oracle guard codes:
        # oracle-evaluated-and-refused, oracle-could-not-evaluate,
        # oracle-verifier-misconfigured; 6 lane-D AER-1
        # provenance non-upgrade codes: provenance-class-missing,
        # provenance-class-unknown, provenance-upgraded,
        # provenance-chain-class-mismatch, provenance-digest-mismatch,
        # provenance-step-break), additive, zero deletions, zero key
        # collisions, composed from the four lane commits by direct
        # byte-verification, pin updated here to match.
        # 585 = wave-232 merge pin; + 9 wave-233 lane-A evaluation-function
        # codes (evaluation-{malformed,incomplete-details,
        # key-role-conflation,input-swapped,non-reproducible,
        # policy-drift,revision-unknown,policy-digest-mismatch,
        # not-authorization}),
        # + 4 wave-233 lane-B exactly-one-signature / binding codes
        # (dsse-{envelope-no-signature,envelope-multi-signature,
        # payloadtype-mismatch,envelope-transplant}),
        # + 1 wave-233 lane-C honest-claims code
        # (honest-claim-reserved-token, domain honest_claims),
        # additive, zero deletions, zero key collisions, composed at merge
        # from the three lane commits by direct byte-verification, pin updated
        # here to match.
        # 567 = 546 (wave-229 merge: 530 + 16 checkpoint/policy-replay)
        # + 6 wave-230 lane-A signed-deny-receipt codes
        # (deny-receipt-refused, taxonomy-receipt-missing,
        # deny-receipt-malformed, deny-receipt-signature-invalid,
        # deny-receipt-unavailable-as-permit,
        # deny-receipt-not-authorization)
        # + 6 wave-230 lane-B definition_sha256 codes
        # (action-semantics-drift, action-depth-exceeded,
        # action-value-count-exceeded, action-duplicate-key,
        # action-material-type-mismatch, action-value-too-long)
        # + 9 wave-230 lane-C decision-effect agreement codes
        # (decision-effect-{refused,malformed,decision-drift,effect-drift,
        # disagreement,effect-absent,extra-effect,time-inversion,
        # not-authorization}),
        # composed at merge from the three lane commits by direct
        # byte-verification (each lane diff was add-only, zero deletions,
        # zero key collisions), pin updated here to match.
        # + 2 wave-231 lane-A reconcile-agreement codes
        # (agreement-input-unmapped, agreement-not-authorization)
        # + 6 wave-231 lane-B seeded-denial codes
        # (seeded-denial-{refused,malformed,digest-mismatch,
        # not-authorization}, denial-anchored-in-denied-transaction,
        # denial-evidence-lost), composed at merge from the two lane
        # commits by direct byte-verification (each lane diff add-only,
        # zero deletions, zero key collisions), pin updated here to match.
        # pin updated by the lanes that added them, taxonomy untouched
        # otherwise.

    def test_self_errors_are_mapped(self):
        for code in ("decision-code-unmapped", "decision-code-malformed",
                     "decision-code-digest-malformed",
                     "decision-code-not-authorization",
                     "decision-code-digest-mismatch"):
            self.assertIn(code, dc.TAXONOMY)

    def test_no_fallback_prose(self):
        for code, entry in dc.TAXONOMY.items():
            self.assertNotIn("refused (%s)" % code, entry["human"],
                             code)
            for field in ("domain", "code", "human", "severity",
                          "evidence_kinds_required", "reverify_steps"):
                self.assertIn(field, entry, code)
            self.assertIn(entry["severity"],
                          ("low", "medium", "high", "critical"), code)
            self.assertTrue(entry["evidence_kinds_required"], code)
            self.assertTrue(entry["reverify_steps"], code)


class FailClosedTest(unittest.TestCase):
    def test_unknown_fails_closed(self):
        with self.assertRaises(dc.DecisionCodeError) as ctx:
            dc.code_for("no-such-refusal-xyz")
        self.assertEqual(ctx.exception.code, "decision-code-unmapped")

    def test_malformed_inputs_fail_closed(self):
        for bad in ("", "   ", "UPPER-CASE-NOT-LOWER", "has space",
                    "a" * 200, "code!", None, 123, ["x"]):
            with self.assertRaises(dc.DecisionCodeError, msg=repr(bad)):
                dc.emit(bad)

    def test_malformed_digest_fails_closed(self):
        with self.assertRaises(dc.DecisionCodeError) as ctx:
            dc.emit("permit-revoked", evidence_digests=["not-a-digest"])
        self.assertEqual(ctx.exception.code,
                         "decision-code-digest-malformed")


class EmitReplayTest(unittest.TestCase):
    def test_emit_carries_reevaluate_pointer(self):
        mc = dc.emit("permit-revoked", evidence_digests=GOOD_DIGESTS)
        ree = mc["reevaluate"]
        self.assertEqual(ree["evidence_digests"], GOOD_DIGESTS)
        self.assertTrue(ree["reverify_steps"])
        self.assertEqual(mc["domain"], "permit")
        self.assertEqual(mc["severity"], "high")

    def test_replay_is_exact(self):
        mc = dc.emit("receipt-pair-decision-drift",
                     evidence_digests=GOOD_DIGESTS)
        mc2 = dc.replay(mc)
        self.assertEqual(mc, mc2)

    def test_replay_rejects_tampered_claim(self):
        mc = dc.emit("permit-revoked", evidence_digests=GOOD_DIGESTS)
        mc = copy.deepcopy(mc)
        mc["severity"] = "low"
        with self.assertRaises(dc.DecisionCodeError):
            dc.replay(mc)

    def test_machine_code_digest_stable(self):
        mc = dc.emit("permit-revoked", evidence_digests=GOOD_DIGESTS)
        d1 = dc.machine_code_digest(mc)
        d2 = dc.machine_code_digest(mc)
        self.assertEqual(d1, d2)
        self.assertRegex(d1, r"^[0-9a-f]{64}$")
        other = dc.emit("lease_expired", evidence_digests=GOOD_DIGESTS)
        self.assertNotEqual(d1, dc.machine_code_digest(other))


class AuthorityRefusalTest(unittest.TestCase):
    def test_authority_shaped_use_refused(self):
        mc = dc.emit("permit-revoked")
        mc = copy.deepcopy(mc)
        mc["authority"] = True
        with self.assertRaises(dc.DecisionCodeError) as ctx:
            dc.require_evidence_only(mc)
        self.assertEqual(ctx.exception.code,
                         "decision-code-not-authorization")

    def test_evidence_use_passes(self):
        mc = dc.emit("permit-revoked")
        self.assertTrue(dc.require_evidence_only(mc))


class CapsuleLinkageTest(unittest.TestCase):
    def _sealed(self, refusal):
        from gov import action_capsule as ac
        return ac.seal_capsule(
            {"attempt": {"tool": "t", "args": {}},
             "effect": {"status": "refused", "code": refusal,
                        "evidence": "evidence-bundle"}})

    def test_attach_and_verify(self):
        mc = dc.emit("receipt-pair-decision-drift",
                     evidence_digests=GOOD_DIGESTS)
        linked = dc.attach_decision_code(
            self._sealed("receipt-pair-decision-drift"), mc)
        got = dc.verify_capsule_decision_code(linked, mc)
        self.assertEqual(got, dc.machine_code_digest(mc))

    def test_tampered_code_breaks_link(self):
        mc = dc.emit("receipt-pair-decision-drift",
                     evidence_digests=GOOD_DIGESTS)
        linked = dc.attach_decision_code(
            self._sealed("receipt-pair-decision-drift"), mc)
        alt = dc.emit("permit-revoked", evidence_digests=GOOD_DIGESTS)
        with self.assertRaises(dc.DecisionCodeError) as ctx:
            dc.verify_capsule_decision_code(linked, alt)
        self.assertEqual(ctx.exception.code,
                         "decision-code-digest-mismatch")


class PacketIntegrationTest(unittest.TestCase):
    def test_signature_covers_attached_code(self):
        pkt = _packet(decision_code="permit-revoked")
        self.assertIn("decision_code", pkt)
        ok, _reason = dp.verify_decision_packet(pkt)
        self.assertTrue(ok, _reason)
        # Mutate the claim: signature must break.
        tampered = copy.deepcopy(pkt)
        tampered["decision_code"]["value"]["refusal"] = "lease_expired"
        tampered["decision_code"]["value"]["code"] = "lease_expired"
        ok2, _reason2 = dp.verify_decision_packet(tampered)
        self.assertFalse(ok2)

    def test_legacy_bytes_identical(self):
        legacy = dp.build_decision_packet(**_minimal_kwargs())
        explicit = dp.build_decision_packet(
            **_minimal_kwargs(decision_code=None))
        self.assertEqual(dp._canonical(legacy), dp._canonical(explicit))

    def test_lazy_legacy_verify_without_taxonomy(self):
        # A legacy packet must verify standalone even when
        # gov/decision_codes.py is unavailable (lazy import path).
        pkt = _packet()
        saved_mod = sys.modules.pop("gov.decision_codes", None)
        import builtins
        real_import = builtins.__import__

        def _blocked(name, *args, **kwargs):
            if name in ("gov.decision_codes", "decision_codes"):
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = _blocked
        try:
            ok, reason = dp.verify_decision_packet(pkt)
            self.assertTrue(ok, reason)
        finally:
            builtins.__import__ = real_import
            if saved_mod is not None:
                sys.modules["gov.decision_codes"] = saved_mod

    def test_unmapped_code_in_section_rejected(self):
        pkt = _packet(decision_code="permit-revoked")
        forged = copy.deepcopy(pkt)
        forged["decision_code"]["value"]["refusal"] =\
            "no-such-refusal-code-xyz"
        forged["decision_code"]["value"]["code"] =\
            "no-such-refusal-code-xyz"
        # Re-sign: signature valid, but taxonomy replay must still
        # refuse the unmapped claim.
        sigless = {k: v for k, v in forged.items() if k != "signature"}
        resigned = dp.sign_packet(sigless, SEED)
        ok, _reason = dp.verify_decision_packet(resigned)
        self.assertFalse(ok)

    def test_invalid_code_refused_at_build(self):
        with self.assertRaises(dp.InvalidDecisionCode):
            _packet(decision_code="no-such-refusal-xyz")
        with self.assertRaises(dp.InvalidDecisionCode):
            _packet(decision_code="")


if __name__ == "__main__":
    unittest.main()
