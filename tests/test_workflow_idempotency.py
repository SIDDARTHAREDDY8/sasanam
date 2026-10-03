"""Unit tests for gov/workflow_idempotency.py: idempotency-key discipline.

Every coded refusal is asserted by code (F351 contract). Expected values
come from the spec (the battery), not recomputed from the implementation.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes
from gov import workflow_idempotency as wi


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class IdempotencyContractTests(unittest.TestCase):
    def setUp(self):
        self.at = 1_700_000_000
        self.allow = {}

        def verifier(caller, namespace, op_class, at):
            return self.allow.get(caller, True)

        self.verifier = verifier
        self.store = wi.IdempotencyStore()

    def _begin(self, key="k1", digest=None, namespace="billing",
               op_class="refund", caller="agent-a", store=None):
        return (store or self.store).begin(
            namespace=namespace, op_class=op_class, key=key,
            op_digest=digest or _hex64("op:" + key),
            caller=caller, authority_verifier=self.verifier, at=self.at)

    def test_new_then_replay(self):
        out = self._begin()
        self.assertEqual(out.status, "new")
        self.assertIsNone(out.result_digest)
        ev = out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        self.assertIsNone(ev)  # no capacity eviction
        out2 = self._begin()
        self.assertEqual(out2.status, "replay")
        self.assertEqual(out2.result_digest, _hex64("r"))
        self.assertEqual(out2.result_ref, "ptr://r")

    def test_digest_confusion_refused_coded(self):
        out = self._begin()
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        with self.assertRaises(wi.IdempotencyConflict) as cm:
            self._begin(digest=_hex64("other"))
        self.assertEqual(cm.exception.code, "permit-idempotency-conflict")

    def test_inflight_digest_confusion_refused_coded(self):
        self._begin(key="k2")
        with self.assertRaises(wi.IdempotencyConflict) as cm:
            self._begin(key="k2", digest=_hex64("other"))
        self.assertEqual(cm.exception.code, "permit-idempotency-conflict")

    def test_namespace_isolation(self):
        out = self._begin(namespace="billing")
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        out2 = self._begin(namespace="ops")
        self.assertEqual(out2.status, "new")
        self.assertIsNone(out2.result_digest)

    def test_opclass_isolation(self):
        out = self._begin(op_class="refund")
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        out2 = self._begin(op_class="charge")
        self.assertEqual(out2.status, "new")

    def test_crash_before_mark_retries_not_replays(self):
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        o1 = self._begin(key="k9", store=s1)
        self.assertEqual(o1.status, "new")
        # crash: no complete()
        s2 = wi.IdempotencyStore(backing=backing)
        o2 = self._begin(key="k9", store=s2)
        self.assertEqual(o2.status, "retry")
        o2.complete(result_digest=_hex64("r9"), result_ref="ptr://r9")
        o3 = self._begin(key="k9", store=s2)
        self.assertEqual(o3.status, "replay")
        self.assertEqual(o3.result_digest, _hex64("r9"))

    def test_retry_after_revocation_refused_coded(self):
        out = self._begin(caller="agent-a")
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        self.allow["agent-a"] = False
        with self.assertRaises(wi.IdempotencyAuthorityLapsed) as cm:
            self._begin(caller="agent-a")
        self.assertEqual(cm.exception.code,
                         "workflow-idempotency-authority-lapsed")

    def test_verifier_exception_fails_closed(self):
        def boom(caller, namespace, op_class, at):
            raise RuntimeError("down")

        with self.assertRaises(wi.IdempotencyAuthorityLapsed):
            self.store.begin(namespace="billing", op_class="refund",
                             key="k1", op_digest=_hex64("op:k1"),
                             caller="a", authority_verifier=boom, at=self.at)

    def test_malformed_keying_material_refused_coded(self):
        bad_keys = ["", "has space", "x" * 129, "semi;colon"]
        for bad in bad_keys:
            with self.assertRaises(wi.IdempotencyKeyInvalid) as cm:
                self._begin(key=bad)
            self.assertEqual(cm.exception.code,
                             "workflow-idempotency-key-invalid")
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(namespace="Billing")
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(digest="xyz")

    def test_complete_on_replay_is_programmer_error(self):
        out = self._begin()
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        out2 = self._begin()
        with self.assertRaises(ValueError):
            out2.complete(result_digest=_hex64("r"), result_ref="ptr://r")

    def test_checkpoint_visible_to_retry(self):
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        o1 = self._begin(key="k", store=s1)
        o1.checkpoint("halfway")
        s2 = wi.IdempotencyStore(backing=backing)
        o2 = self._begin(key="k", store=s2)
        self.assertEqual(o2.status, "retry")
        self.assertEqual(o2.notes, ["halfway"])

    def test_operator_evict_returns_loud_record(self):
        out = self._begin()
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        rec = self.store.evict_completed(namespace="billing",
                                         op_class="refund", key="k1",
                                         operator="op-human", at=self.at)
        self.assertEqual(rec["evicted_key"], "k1")
        self.assertEqual(rec["operator"], "op-human")
        self.assertEqual(rec["reason"], "operator")
        out2 = self._begin()
        self.assertEqual(out2.status, "new")

    def test_evict_missing_key_raises(self):
        with self.assertRaises(KeyError):
            self.store.evict_completed(namespace="billing", op_class="refund",
                                       key="nope", operator="op")

    def test_capacity_evicts_oldest(self):
        store = wi.IdempotencyStore(max_completed=2)
        for i in range(3):
            o = self._begin(key="k%d" % i, store=store)
            ev = o.complete(result_digest=_hex64("r%d" % i),
                            result_ref="ptr://%d" % i)
            if i < 2:
                self.assertIsNone(ev)
            else:
                self.assertEqual(ev["evicted_key"], "k0")
                self.assertEqual(ev["reason"], "capacity")
        o = self._begin(key="k0", store=store)
        self.assertEqual(o.status, "new")  # evicted: genuinely gone

    def test_sink_failure_never_breaks_path(self):
        def boom(record):
            raise RuntimeError("sink down")

        store = wi.IdempotencyStore(sink=boom)
        o = self._begin(store=store)
        o.complete(result_digest=_hex64("r"), result_ref="ptr://r")
        o2 = self._begin(store=store)
        self.assertEqual(o2.status, "replay")


class IdempotencyCodeTests(unittest.TestCase):
    def test_new_codes_pinned(self):
        for code in ("workflow-idempotency-authority-lapsed",
                     "workflow-idempotency-key-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["severity"],
                             "high")
            self.assertEqual(decision_codes.TAXONOMY[code]["domain"],
                             "workflow-idempotency")

    def test_reused_code_pinned(self):
        self.assertIn("permit-idempotency-conflict",
                      decision_codes.TAXONOMY)

    def test_exception_codes_match_taxonomy(self):
        self.assertEqual(wi.IdempotencyConflict.code,
                         "permit-idempotency-conflict")
        self.assertEqual(wi.IdempotencyAuthorityLapsed.code,
                         "workflow-idempotency-authority-lapsed")
        self.assertEqual(wi.IdempotencyKeyInvalid.code,
                         "workflow-idempotency-key-invalid")


if __name__ == "__main__":
    unittest.main(verbosity=1)
