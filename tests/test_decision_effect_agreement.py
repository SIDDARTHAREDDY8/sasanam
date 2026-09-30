#!/usr/bin/env python3
"""Unit tests for gov/decision_effect_agreement.py.

Wave-230 lane C: decision-vs-effect agreement before acceptance.
Tests use independent fixtures built through the PUBLIC seams of
gov/receipt_pairs.py (issue/issue), not the module under test, and
compute expected digests from spec-vector literals where a value
must be pinned — never by copying the implementation's internals.
"""

import copy
import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import action_capsule as ac  # noqa: E402
from gov import decision_effect_agreement as dea  # noqa: E402
from gov import effect_status as es  # noqa: E402
from gov import receipt_pairs as rp  # noqa: E402

ISSUED = 1700000000.0
EXECUTED = 1700000060.0


def _verdict_record(action="install_package"):
    return {"attempt": {"action": action,
                       "package": "nginx-1.29"},
            "effect": {"status": "admitted",
                       "evidence": "gate allowed: pinned package"}}


def _decision(record=None):
    return rp.issue_decision_receipt(record or _verdict_record(), ISSUED)


def _execution(decision, record=None, outcome="timed-out",
               accepted=False):
    obs = {"outcome": outcome, "executor_may_have_accepted": accepted}
    return rp.issue_execution_receipt(record or _verdict_record(), obs,
                                      decision, EXECUTED)


def _code_of(fn):
    """Return the machine code fn() refuses with, or None."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None)
    return None


class AgreementVerdictTests(unittest.TestCase):
    def test_valid_pair_agrees_with_recomputed_digests(self):
        dec = _decision()
        exe = _execution(dec)
        out = dea.check_agreement(dec, exe)
        self.assertTrue(out["agreement"])
        self.assertEqual(out["decision_digest"], dec["decision_digest"])
        self.assertEqual(out["effect_digest"], exe["effect_digest"])
        self.assertEqual(out["issued_at"], ISSUED)
        self.assertEqual(out["executed_at"], EXECUTED)
        # agreement_digest is a fresh derivation over the canonical
        # agreement body — pinned here from a spec literal, not from
        # the implementation.
        body = {
            "agreement": True,
            "decision_digest": dec["decision_digest"],
            "effect_digest": exe["effect_digest"],
            "issued_at": repr(ISSUED),
            "executed_at": repr(EXECUTED),
        }
        expected = hashlib.sha256(
            ac.canonical_json_bytes(body)).hexdigest()
        self.assertEqual(out["agreement_digest"], expected)

    def test_agreement_is_pure_over_inputs(self):
        dec = _decision()
        exe = _execution(dec)
        first = dea.check_agreement(dec, exe)
        second = dea.check_agreement(copy.deepcopy(dec),
                                     copy.deepcopy(exe))
        self.assertEqual(first, second)

    def test_swapped_effect_is_disagreement(self):
        dec = _decision()
        other_exe = _execution(dec, record=_verdict_record("delete_data"))
        # The fixture is honest only if the two receipts share the
        # backlink (deterministic fixtures) but differ on attempts.
        self.assertEqual(other_exe["decision_backlink"],
                         dec["decision_digest"])
        att = lambda vr: hashlib.sha256(  # noqa: E731
            ac.canonical_json_bytes(vr["verdict_record"]["attempt"])
        ).hexdigest()
        self.assertNotEqual(att(dec), att(other_exe))
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(dec, other_exe)),
            "decision-effect-disagreement")

    def test_wrong_backlink_is_disagreement(self):
        dec = _decision()
        other = _decision(_verdict_record("delete_data"))
        exe = _execution(other)
        self.assertNotEqual(exe["decision_backlink"],
                            dec["decision_digest"])
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(dec, exe)),
            "decision-effect-disagreement")

    def test_decision_without_effect_is_absent_not_accepted(self):
        dec = _decision()
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(dec, None)),
            "decision-effect-effect-absent")

    def test_effect_without_decision_is_extra(self):
        exe = _execution(_decision())
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(None, exe)),
            "decision-effect-extra-effect")

    def test_both_absent_is_malformed(self):
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(None, None)),
            "decision-effect-malformed")

    def test_non_dict_inputs_are_malformed(self):
        for args in (("x", {}), ([], []), ({}, []), ("x", "y")):
            with self.subTest(args=args):
                self.assertEqual(
                    _code_of(lambda: dea.check_agreement(*args)),
                    "decision-effect-malformed")

    def test_wrong_kind_is_malformed(self):
        dec = _decision()
        bad = copy.deepcopy(dec)
        bad["kind"] = "execution-receipt"
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(bad, _execution(dec))),
            "decision-effect-malformed")

    def test_time_inversion_refused(self):
        # executed_at is not digest-bound in the receipt claims (it
        # only enters the pair HMAC, which the agreement predicate
        # does not re-verify), so the pair can be built inverted:
        # decision issued at 2000, effect recorded at 1000.
        dec = rp.issue_decision_receipt(_verdict_record(), 2000.0)
        exe = _execution(dec)
        inverted = copy.deepcopy(exe)
        inverted["executed_at"] = 1000.0
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(dec, inverted)),
            "decision-effect-time-inversion")

    def test_tampered_decision_bytes_caught_by_recompute(self):
        dec = _decision()
        exe = _execution(dec)
        tampered = copy.deepcopy(dec)
        tampered["verdict_record"]["attempt"]["package"] = "evil-9.9"
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(tampered, exe)),
            "decision-effect-decision-drift")

    def test_tampered_claimed_decision_digest_caught(self):
        dec = _decision()
        exe = _execution(dec)
        tampered = copy.deepcopy(dec)
        tampered["decision_digest"] = "0" * 64
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(tampered, exe)),
            "decision-effect-decision-drift")

    def test_tampered_effect_bytes_caught_by_recompute(self):
        dec = _decision()
        exe = _execution(dec)
        tampered = copy.deepcopy(exe)
        tampered["observation"]["outcome"] = "completed"
        tampered["observation"]["executor_may_have_accepted"] = True
        # Re-classification now says "completed" but the receipt
        # still claims the old status.
        self.assertEqual(
            _code_of(lambda: dea.check_agreement(dec, tampered)),
            "decision-effect-effect-drift")

    def test_tampered_capsule_bytes_caught_by_replay(self):
        dec = _decision()
        exe = _execution(dec)
        tampered = copy.deepcopy(exe)
        body = bytearray(tampered["capsule"]["jcs_json"].encode("utf-8"))
        body[-3] ^= 0x01
        tampered["capsule"]["jcs_json"] = bytes(body).decode("utf-8")
        code = _code_of(lambda: dea.check_agreement(dec, tampered))
        self.assertIn(code, ("capsule-digest-mismatch",
                             "capsule-noncanonical"))


class SealAgreementTests(unittest.TestCase):
    def test_seal_links_agreement_digest(self):
        dec = _decision()
        exe = _execution(dec)
        cap = dea.seal_agreement(dec, exe)
        body = ac.verify_capsule(cap)
        out = dea.check_agreement(dec, exe)
        self.assertEqual(body["effect"]["evidence"],
                         out["agreement_digest"])
        self.assertEqual(body["attempt"]["decision_digest"],
                         out["decision_digest"])
        self.assertEqual(body["attempt"]["effect_digest"],
                         out["effect_digest"])
        self.assertEqual(body["effect"]["status"], "admitted")

    def test_agreement_digest_of_recomputes(self):
        dec = _decision()
        exe = _execution(dec)
        cap = dea.seal_agreement(dec, exe)
        digest = dea.agreement_digest_of(cap)
        # Pinned from the same spec literal as the verdict test.
        body = {
            "agreement": True,
            "decision_digest": dec["decision_digest"],
            "effect_digest": exe["effect_digest"],
            "issued_at": repr(ISSUED),
            "executed_at": repr(EXECUTED),
        }
        expected = hashlib.sha256(
            ac.canonical_json_bytes(body)).hexdigest()
        self.assertEqual(digest, expected)
        self.assertNotEqual(digest, hashlib.sha256(b"tampered").hexdigest())

    def test_tampered_sealed_evidence_refused(self):
        dec = _decision()
        exe = _execution(dec)
        cap = dea.seal_agreement(dec, exe)
        body = ac.verify_capsule(cap)
        forged = ac.seal_capsule({
            "attempt": body["attempt"],
            "effect": {"status": "admitted",
                       "evidence": hashlib.sha256(b"lie").hexdigest()},
        })
        # The forged capsule replays as a self-consistent capsule,
        # but its evidence field does not commit to the agreement
        # attempt bytes: re-derivation refuses.
        with self.assertRaises(dea.AgreementError):
            dea.agreement_digest_of(forged)

    def test_seal_refuses_disagreement(self):
        dec = _decision()
        other_exe = _execution(dec, record=_verdict_record("delete_data"))
        self.assertEqual(
            _code_of(lambda: dea.seal_agreement(dec, other_exe)),
            "decision-effect-disagreement")

    def test_action_capsule_module_untouched(self):
        # The agreement module must compose action_capsule without
        # changing it: no new globals leaked into it.
        self.assertFalse(hasattr(ac, "decision_effect_agreement"))


class AuthorityBoundaryTests(unittest.TestCase):
    def test_verdict_as_authority_refused(self):
        out = dea.check_agreement(_decision(), _execution(_decision()))
        self.assertEqual(
            _code_of(lambda: dea.deny_authority_use(out)),
            "decision-effect-not-authorization")

    def test_sealed_capsule_as_authority_refused(self):
        dec = _decision()
        cap = dea.seal_agreement(dec, _execution(dec))
        self.assertEqual(
            _code_of(lambda: dea.deny_authority_use(cap)),
            "decision-effect-not-authorization")

    def test_non_agreement_capsule_as_authority_is_malformed(self):
        dec = _decision()
        self.assertEqual(
            _code_of(lambda: dea.deny_authority_use(dec["capsule"])),
            "decision-effect-malformed")

    def test_garbage_as_authority_is_malformed(self):
        self.assertEqual(
            _code_of(lambda: dea.deny_authority_use({"nope": True})),
            "decision-effect-malformed")

    def test_all_codes_in_taxonomy(self):
        from gov import decision_codes as dc  # noqa: E402
        codes = {
            "decision-effect-refused",
            "decision-effect-malformed",
            "decision-effect-decision-drift",
            "decision-effect-effect-drift",
            "decision-effect-disagreement",
            "decision-effect-effect-absent",
            "decision-effect-extra-effect",
            "decision-effect-time-inversion",
            "decision-effect-not-authorization",
        }
        found = {entry.get("code") for entry in dc.TAXONOMY.values()}
        self.assertTrue(codes <= found,
                        "missing from taxonomy: %s" % (codes - found))


if __name__ == "__main__":
    unittest.main(verbosity=2)
