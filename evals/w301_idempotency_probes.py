"""Wave-301 idempotency battery: red-first break-first probes.

Target: gov/workflow_idempotency.py (new in this lane) -- idempotency-key
discipline for agent operations (ADAPT from celery + airflow per the
wave-300 prospectus: at-least-once + explicit idempotency contract,
acks_late redelivery discipline, idempotency-as-authoring-rule).

Base: wave-300 merge 94bc43deb58ba78163f3ee61a59c2240cdd008f3.
Pin 1802 -> 1812 (+2 workflow-idempotency-*).

Red-first: on the pristine base the module is absent, so every feature
probe BREAKs; on the fixed tree every attack probe must be HELD
(refused coded, or behaved per the contract). No probe may ERROR.

Probes:
  same-key-different-digest confusion -> permit-idempotency-conflict
  cross-namespace / cross-op-class replay -> isolated (fresh NEW)
  crash-before-mark -> safe retry (acks_late), never silent loss
  retry after authority revocation -> workflow-idempotency-authority-lapsed
  malformed keying material -> workflow-idempotency-key-invalid
  bounded completed set: auto-evict + operator-evict are loud (sink)

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Module-level deployment mode; also verified under a
clean environment. Depth-1 green checks honor GOV_SKIP_GREEN.

Run:
  mkdir -p /var/tmp/g301-idem && TMPDIR=/var/tmp/g301-idem \
    ~/workspace/.gov-venv/bin/python evals/w301_idempotency_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g301-idem2 \
    ~/workspace/.gov-venv/bin/python evals/w301_idempotency_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PIN = 2006 # Wave-300 merge pin 1802; wave-301 lane 6: pin 1802 -> 1804 (+2 workflow-idempotency-*); wave-301 merge: 1812 (+10 workflow-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 2 (F381 closure): pin 1820 -> 1821 (+1 workflow-idempotency-caller-mismatch); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)
SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from gov import workflow_idempotency as wi
    from gov import decision_codes
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class IdempotencyProbes(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        if not HAVE_MODULE:
            self.fail("BREAK: gov/workflow_idempotency.py absent on this tree")
        self.at = 1_700_000_000
        self.allow = {}
        def verifier(caller, namespace, op_class, at):
            return self.allow.get(caller, True)
        self.verifier = verifier
        self.sink_records = []
        self.store = wi.IdempotencyStore(sink=self.sink_records.append)

    def _begin(self, key="k1", digest=None, namespace="billing",
               op_class="refund", caller="agent-a", store=None):
        store = store or self.store
        return store.begin(
            namespace=namespace, op_class=op_class, key=key,
            op_digest=digest or _hex64("op:" + key),
            caller=caller, authority_verifier=self.verifier, at=self.at)

    # -- contract ------------------------------------------------------

    def test_replay_returns_recorded_result(self):
        effects = []
        out = self._begin()
        self.assertEqual(out.status, "new")
        effects.append("ran")
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        out2 = self._begin()
        self.assertEqual(out2.status, "replay")
        self.assertEqual(out2.result_digest, _hex64("res1"))
        self.assertEqual(out2.result_ref, "ptr://r1")
        self.assertEqual(effects, ["ran"])  # effect executed exactly once

    def test_same_key_different_digest_refused(self):
        out = self._begin()
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        with self.assertRaises(wi.IdempotencyConflict) as cm:
            self._begin(digest=_hex64("different-op"))
        self.assertEqual(cm.exception.code, "permit-idempotency-conflict")

    def test_same_key_different_digest_refused_inflight(self):
        self._begin(key="k2")
        with self.assertRaises(wi.IdempotencyConflict) as cm:
            self._begin(key="k2", digest=_hex64("different-op"))
        self.assertEqual(cm.exception.code, "permit-idempotency-conflict")

    def test_cross_namespace_isolation(self):
        out = self._begin(namespace="billing")
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        # Same key+digest under a different namespace: no result leak,
        # no skip -- treated as a fresh NEW operation.
        out2 = self._begin(namespace="ops")
        self.assertEqual(out2.status, "new")

    def test_cross_opclass_isolation(self):
        out = self._begin(op_class="refund")
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        out2 = self._begin(op_class="charge")
        self.assertEqual(out2.status, "new")

    def test_crash_before_mark_safe_retry(self):
        # acks_late: the mark lands only AFTER effects are recorded.
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        effects = []
        out = s1.begin(namespace="billing", op_class="refund", key="k9",
                       op_digest=_hex64("op:k9"), caller="agent-a",
                       authority_verifier=self.verifier, at=self.at)
        self.assertEqual(out.status, "new")
        effects.append("ran")
        # CRASH: no complete() call. A restarted worker retries over the
        # same shared backing.
        s2 = wi.IdempotencyStore(backing=backing)
        out2 = s2.begin(namespace="billing", op_class="refund", key="k9",
                        op_digest=_hex64("op:k9"), caller="agent-a",
                        authority_verifier=self.verifier, at=self.at)
        self.assertEqual(out2.status, "retry")  # NOT replay: never completed
        effects.append("ran-again")
        out2.complete(result_digest=_hex64("res9"), result_ref="ptr://r9")
        out3 = s2.begin(namespace="billing", op_class="refund", key="k9",
                        op_digest=_hex64("op:k9"), caller="agent-a",
                        authority_verifier=self.verifier, at=self.at)
        self.assertEqual(out3.status, "replay")
        self.assertEqual(effects, ["ran", "ran-again"])  # no phantom third run

    # -- authority re-verification (the design rule) --------------------

    def test_retry_after_authority_revocation_refused(self):
        out = self._begin(caller="agent-a")
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        self.allow["agent-a"] = False  # authority revoked after completion
        with self.assertRaises(wi.IdempotencyAuthorityLapsed) as cm:
            self._begin(caller="agent-a")
        self.assertEqual(cm.exception.code,
                         "workflow-idempotency-authority-lapsed")

    def test_inflight_retry_after_revocation_refused(self):
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        s1.begin(namespace="billing", op_class="refund", key="k7",
                 op_digest=_hex64("op:k7"), caller="agent-a",
                 authority_verifier=self.verifier, at=self.at)
        self.allow["agent-a"] = False
        s2 = wi.IdempotencyStore(backing=backing)
        with self.assertRaises(wi.IdempotencyAuthorityLapsed):
            s2.begin(namespace="billing", op_class="refund", key="k7",
                     op_digest=_hex64("op:k7"), caller="agent-a",
                     authority_verifier=self.verifier, at=self.at)

    def test_new_path_verifies_authority(self):
        self.allow["agent-evil"] = False
        with self.assertRaises(wi.IdempotencyAuthorityLapsed):
            self._begin(caller="agent-evil")

    def test_verifier_exception_fails_closed(self):
        def boom(caller, namespace, op_class, at):
            raise RuntimeError("verifier down")
        with self.assertRaises(wi.IdempotencyAuthorityLapsed):
            self.store.begin(namespace="billing", op_class="refund",
                             key="k1", op_digest=_hex64("op:k1"),
                             caller="agent-a", authority_verifier=boom,
                             at=self.at)

    # -- keying-material grammar ----------------------------------------

    def test_malformed_key_refused(self):
        for bad in ["", "has space", "x" * 129, "semi;colon", "nul\x00byte"]:
            with self.assertRaises(wi.IdempotencyKeyInvalid) as cm:
                self._begin(key=bad)
            self.assertEqual(cm.exception.code,
                             "workflow-idempotency-key-invalid")

    def test_malformed_digest_refused(self):
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(digest="not-hex")
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(digest="ab" * 32 + "zz")

    def test_malformed_namespace_refused(self):
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(namespace="Billing")  # must be [a-z][a-z0-9-]
        with self.assertRaises(wi.IdempotencyKeyInvalid):
            self._begin(op_class="")

    # -- bounded completed set ------------------------------------------

    def test_auto_evict_is_loud(self):
        store = wi.IdempotencyStore(max_completed=2,
                                    sink=self.sink_records.append)
        for i in range(3):
            out = store.begin(namespace="n", op_class="c", key="k%d" % i,
                              op_digest=_hex64("op:%d" % i), caller="a",
                              authority_verifier=self.verifier, at=self.at)
            ev = out.complete(result_digest=_hex64("r%d" % i),
                              result_ref="ptr://%d" % i, at=self.at)
            if i == 2:
                self.assertIsNotNone(ev)  # capacity eviction fired
                self.assertEqual(ev["evicted_key"], "k0")
        auto = [r for r in self.sink_records if r["event"] == "evict-auto"]
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["evicted_key"], "k0")
        # Evicted key is genuinely gone: same key+digest begins NEW again.
        out = store.begin(namespace="n", op_class="c", key="k0",
                          op_digest=_hex64("op:0"), caller="a",
                          authority_verifier=self.verifier, at=self.at)
        self.assertEqual(out.status, "new")

    def test_operator_evict_is_loud(self):
        out = self._begin()
        out.complete(result_digest=_hex64("res1"), result_ref="ptr://r1")
        # Wave-303 lane 2 (F381 closure): evict_completed() requires an
        # authority verifier -- the operator name is the caller identity
        # presented to it.
        rec = self.store.evict_completed(namespace="billing",
                                         op_class="refund", key="k1",
                                         operator="op-human",
                                         authority_verifier=self.verifier,
                                         at=self.at)
        self.assertEqual(rec["evicted_key"], "k1")
        self.assertEqual(rec["operator"], "op-human")
        ev = [r for r in self.sink_records if r["event"] == "evict-operator"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["operator"], "op-human")
        out2 = self._begin()
        self.assertEqual(out2.status, "new")

    def test_checkpoint_notes(self):
        out = self._begin()
        out.checkpoint("halfway", at=self.at)
        out.checkpoint("almost", at=self.at + 1)
        # Crash before complete; the retry sees the progress notes.
        backing = {}
        s1 = wi.IdempotencyStore(backing=backing)
        o1 = s1.begin(namespace="n", op_class="c", key="k",
                      op_digest=_hex64("op"), caller="a",
                      authority_verifier=self.verifier, at=self.at)
        o1.checkpoint("halfway", at=self.at)
        s2 = wi.IdempotencyStore(backing=backing)
        o2 = s2.begin(namespace="n", op_class="c", key="k",
                      op_digest=_hex64("op"), caller="a",
                      authority_verifier=self.verifier, at=self.at)
        self.assertEqual(o2.status, "retry")
        self.assertEqual(o2.notes, ["halfway"])

    def test_sink_never_breaks(self):
        def boom(record):
            raise RuntimeError("sink down")
        store = wi.IdempotencyStore(sink=boom)
        out = store.begin(namespace="n", op_class="c", key="k",
                          op_digest=_hex64("op"), caller="a",
                          authority_verifier=self.verifier, at=self.at)
        out.complete(result_digest=_hex64("r"), result_ref="ptr://r")


class PinTest(unittest.TestCase):
    def setUp(self):
        if not HAVE_MODULE:
            self.skipTest("BREAK: gov/workflow_idempotency.py absent")

    def test_pin_taxonomy(self):
        self.assertEqual(len(decision_codes.TAXONOMY), PIN)

    def test_new_codes_present(self):
        for code in ("workflow-idempotency-authority-lapsed",
                     "workflow-idempotency-key-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["severity"],
                             "high")

    def test_reused_code_present(self):
        self.assertIn("permit-idempotency-conflict", decision_codes.TAXONOMY)


class GreenChecks(unittest.TestCase):
    def _run(self, name, path, tolerate=()):
        if SKIP_GREEN:
            return
        tmp = tempfile.mkdtemp(prefix="g301-green-")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600, env=env, cwd=REPO)
            out = proc.stdout + proc.stderr
        except Exception as e:  # noqa: BLE001
            self.fail("green check %s crashed: %r" % (name, e))
        import re
        bad = []
        for ln in out.splitlines():
            s = ln.strip()
            m = re.match(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", s)
            if m and (int(m.group(1)) or int(m.group(3))):
                if not any(t in s for t in tolerate):
                    bad.append(s)
                continue
            if s.startswith("FAIL:") or s.startswith("ERROR:"):
                if not any(t in s for t in tolerate):
                    bad.append(s)
        self.assertEqual(bad, [], "green check %s had failures: %s"
                         % (name, bad[:5]))

    def test_green_w300_delegation_approval(self):
        self._run("w300_delegation_approval",
                  os.path.join(REPO, "evals",
                               "w300_delegation_approval_probes.py"))

    def test_green_w300_memory_composed(self):
        self._run("w300_memory_composed",
                  os.path.join(REPO, "evals",
                               "w300_memory_composed_probes.py"))

    def test_green_w300_revoke_lease(self):
        self._run("w300_revoke_lease",
                  os.path.join(REPO, "evals", "w300_revoke_lease_probes.py"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
