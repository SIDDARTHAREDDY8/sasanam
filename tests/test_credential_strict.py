#!/usr/bin/env python3
"""Unit tests for the wave-266 strict credential tier
(gov/credential_strict.py + the strict seams in
gov/sentinel_substitution.py).

Stdlib + gov only. Covers: strict registration validation
(fail-closed on malformed config), the agent-side never-materialize
refusal in substitute_for_execution (machine code + loud audit, no
jti consumed, no substitution), the StrictEgressInjector gate order
(strict-known -> injector-bound -> approval -> host), the digest
receipt, and the absence of real values in audit/vault/receipts.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc  # noqa: E402
from gov import credential_strict as cst  # noqa: E402
from gov.sentinel_substitution import (  # noqa: E402
    SentinelError,
    SentinelVault,
    substitute_for_execution,
)


def _real(cid):
    return "tok_synth_strict_%s_9f2c4a1b" % cid.replace("-", "_")


def _approval(tool, dest):
    return {"approval_id": "appr-1", "decision": "approved",
            "tool": tool, "dest_host": dest}


def _mk_vault(strict_cid="cred-u1", injector="egress-prod"):
    v = SentinelVault()
    tok = v.register(strict_cid, _real(strict_cid),
                     ["api.example.com"], "api-key",
                     release_policy="attested",
                     strict=True, strict_injector=injector)
    return v, tok


def _mk_injector(vault, name="egress-prod", audit=None, sink=None,
                 approve=True):
    sink = [] if sink is None else sink

    def _check(approval, tool, dest):
        return bool(approve) and isinstance(approval, dict)\
            and approval.get("decision") == "approved"\
            and approval.get("tool") == tool\
            and approval.get("dest_host") == dest

    def _transport(tool, injected, context):
        sink.append(injected)
        return {"status": "sent"}

    inj = cst.StrictEgressInjector(vault, name,
                                   check_approval=_check,
                                   transport=_transport, audit=audit)
    return inj, sink


class TestTaxonomyPin(unittest.TestCase):
    def test_pin_1209(self):
        # Lane-local pin: 1205 + 4 credential-strict-* codes.
        self.assertEqual(len(dc.TAXONOMY), 1828)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

    def test_strict_codes_well_formed(self):
        for code in ("credential-strict-config-invalid",
                     "credential-strict-host-denied",
                     "credential-strict-refused",
                     "credential-strict-unapproved"):
            entry = dc.TAXONOMY[code]
            self.assertEqual(entry["domain"], "credential")
            self.assertEqual(entry["severity"], "high")
            self.assertEqual(
                entry["evidence_kinds_required"],
                ["credential", "binding", "digest"])


class TestStrictRegistration(unittest.TestCase):
    def test_strict_registers_with_binding(self):
        v = SentinelVault()
        tok = v.register("c1", _real("c1"), ["h.example"], "api-key",
                         strict=True, strict_injector="egress-prod")
        rec = v.lookup(tok)
        self.assertTrue(rec["strict"])
        self.assertEqual(rec["strict_injector"], "egress-prod")

    def test_strict_requires_injector_label(self):
        v = SentinelVault()
        with self.assertRaises(SentinelError) as cm:
            v.register("c2", _real("c2"), ["h.example"], "api-key",
                       strict=True, strict_injector="")
        self.assertTrue(str(cm.exception).startswith(
            "credential-strict-config-invalid"))
        with self.assertRaises(SentinelError):
            v.register("c2", _real("c2"), ["h.example"], "api-key",
                       strict=True, strict_injector=None)
        self.assertEqual(len(v), 0)  # nothing registered

    def test_injector_label_without_strict_refused(self):
        v = SentinelVault()
        with self.assertRaises(SentinelError) as cm:
            v.register("c3", _real("c3"), ["h.example"], "api-key",
                       strict_injector="egress-prod")
        self.assertTrue(str(cm.exception).startswith(
            "credential-strict-config-invalid"))
        self.assertEqual(len(v), 0)

    def test_default_registration_unaffected(self):
        v = SentinelVault()
        tok = v.register("c4", _real("c4"), ["h.example"], "api-key",
                         release_policy="legacy-host-only")
        rec = v.lookup(tok)
        self.assertFalse(rec.get("strict"))
        self.assertIsNone(rec.get("strict_injector"))

    def test_is_strict_sentinel(self):
        v, tok = _mk_vault()
        self.assertTrue(cst.is_strict_sentinel(v, tok))
        v2 = SentinelVault()
        tok2 = v2.register("plain", _real("plain"), ["h.example"],
                           "api-key",
                           release_policy="legacy-host-only")
        self.assertFalse(cst.is_strict_sentinel(v2, tok2))
        self.assertFalse(cst.is_strict_sentinel(v, "nope"))
        self.assertFalse(cst.is_strict_sentinel(None, tok))


class TestAgentSideRefusal(unittest.TestCase):
    def test_substitute_for_execution_refuses(self):
        v, tok = _mk_vault()
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        with self.assertRaises(SentinelError) as cm:
            substitute_for_execution(v, "http_post", args)
        self.assertTrue(str(cm.exception).startswith(
            "credential-strict-refused"))

    def test_refusal_audits_loudly_without_secrets(self):
        v, tok = _mk_vault()
        audit = []
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        with self.assertRaises(SentinelError):
            substitute_for_execution(v, "http_post", args,
                                     audit_log=audit)
        self.assertEqual(len(audit), 1)
        evt = audit[0]
        self.assertEqual(evt["event"], "credential_strict_refused")
        self.assertEqual(evt["code"], "credential-strict-refused")
        self.assertEqual(evt["credential_id"], "cred-u1")
        self.assertNotIn(_real("cred-u1"), repr(audit))

    def test_refusal_consumes_nothing(self):
        v, tok = _mk_vault()
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        with self.assertRaises(SentinelError):
            substitute_for_execution(v, "http_post", args)
        self.assertEqual(v.substitution_log, [])

    def test_non_strict_still_substitutes(self):
        v = SentinelVault()
        real = _real("plain")
        tok = v.register("plain", real, ["api.example.com"],
                         "api-key", release_policy="legacy-host-only")
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        out, vals = substitute_for_execution(v, "http_post", args)
        self.assertIn(real, repr(out))

    def test_error_is_sentinel_error_subclass(self):
        err = cst.CredentialStrictError("credential-strict-refused",
                                        "detail")
        self.assertIsInstance(err, SentinelError)
        self.assertEqual(err.code, "credential-strict-refused")
        self.assertTrue(str(err).startswith(
            "credential-strict-refused"))


class TestStrictEgressInjector(unittest.TestCase):
    def test_construction_validates(self):
        v, _ = _mk_vault()
        inj, _ = _mk_injector(v, "egress-prod")
        self.assertEqual(inj.name, "egress-prod")
        with self.assertRaises(cst.CredentialStrictError):
            cst.StrictEgressInjector(v, "", lambda *a: True,
                                     lambda *a: None)
        with self.assertRaises(cst.CredentialStrictError):
            cst.StrictEgressInjector("not-a-vault", "x",
                                     lambda *a: True,
                                     lambda *a: None)
        with self.assertRaises(cst.CredentialStrictError):
            cst.StrictEgressInjector(v, "x", "not-callable",
                                     lambda *a: None)

    def test_happy_path(self):
        v, tok = _mk_vault()
        audit = []
        inj, sink = _mk_injector(v, audit=audit)
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        receipt = inj.inject(
            "http_post", args,
            approval=_approval("http_post", "api.example.com"))
        real = _real("cred-u1")
        self.assertIn(real, repr(sink[0]))  # transport got the value
        self.assertEqual(receipt["credential_ids"], ["cred-u1"])
        self.assertEqual(receipt["dest_host"], "api.example.com")
        self.assertEqual(len(receipt["injected_digest"]), 64)
        self.assertNotIn(real, repr(receipt))
        self.assertNotIn(real, repr(audit))
        self.assertNotIn(real, repr(v))
        evt = audit[0]
        self.assertEqual(evt["event"], "credential_strict_injected")

    def test_digest_deterministic(self):
        v, tok = _mk_vault()
        inj, _ = _mk_injector(v)
        args = {"url": "https://api.example.com/v1",
                "headers": {"Authorization": "Bearer " + tok}}
        appr = _approval("http_post", "api.example.com")
        r1 = inj.inject("http_post", dict(args), approval=dict(appr))
        r2 = inj.inject("http_post", dict(args), approval=dict(appr))
        self.assertEqual(r1["injected_digest"], r2["injected_digest"])

    def test_gate_order(self):
        # unknown sentinel -> refused (not unapproved/host-denied)
        v = SentinelVault()
        inj, _ = _mk_injector(v)
        args = {"url": "https://api.example.com/v1",
                "h": "fake_value_"
                     "12345678-1234-1234-1234-123456789abc"}
        with self.assertRaises(cst.CredentialStrictError) as cm:
            inj.inject("http_post", args,
                       approval=_approval("http_post",
                                          "api.example.com"))
        self.assertEqual(cm.exception.code,
                         "credential-strict-refused")
        # wrong injector binding -> refused before approval check
        v2, tok2 = _mk_vault(injector="egress-prod")
        inj2, _ = _mk_injector(v2, name="egress-dev")
        args2 = {"url": "https://api.example.com/v1", "h": tok2}
        with self.assertRaises(cst.CredentialStrictError) as cm:
            inj2.inject("http_post", args2,
                        approval=_approval("http_post",
                                           "api.example.com"))
        self.assertEqual(cm.exception.code,
                         "credential-strict-refused")
        # no approval -> unapproved (before host check matters)
        v3, tok3 = _mk_vault()
        inj3, _ = _mk_injector(v3)
        args3 = {"url": "https://api.example.com/v1", "h": tok3}
        with self.assertRaises(cst.CredentialStrictError) as cm:
            inj3.inject("http_post", args3, approval=None)
        self.assertEqual(cm.exception.code,
                         "credential-strict-unapproved")
        # unauthorized host -> host-denied
        with self.assertRaises(cst.CredentialStrictError) as cm:
            inj3.inject("http_post",
                        {"url": "https://evil.example.net/v1",
                         "h": tok3},
                        approval=_approval("http_post",
                                           "evil.example.net"))
        self.assertEqual(cm.exception.code,
                         "credential-strict-host-denied")

    def test_raising_approval_check_denies(self):
        v, tok = _mk_vault()

        def _boom(approval, tool, dest):
            raise RuntimeError("approver down")

        inj = cst.StrictEgressInjector(v, "egress-prod",
                                       check_approval=_boom,
                                       transport=lambda *a: None)
        with self.assertRaises(cst.CredentialStrictError) as cm:
            inj.inject("http_post",
                       {"url": "https://api.example.com/v1",
                        "h": tok},
                       approval=_approval("http_post",
                                          "api.example.com"))
        self.assertEqual(cm.exception.code,
                         "credential-strict-unapproved")


if __name__ == "__main__":
    unittest.main()
