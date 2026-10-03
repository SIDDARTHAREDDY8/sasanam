"""Wave-301 routing-slip battery: red-first break-first probes.

Target: gov/workflow_routing.py (new in this lane) -- MassTransit
Courier ADAPT: the routing slip is a signed itinerary that travels WITH
the work. Standing rules: "Delegation narrows, never widens" and
"A workflow outlives its runner -- every step is checkpointed, and
every resume re-proves its authority."

Base: wave-300 merge 94bc43deb58ba78163f3ee61a59c2240cdd008f3.
Pin 1802 -> 1812 (lane-local 1804 at lane time; 2 new codes:
workflow-routing-slip-tampered, workflow-routing-rights-widened).

Red-first: on the pristine base the module is absent, so every feature
probe BREAKs; on the fixed tree every attack probe must be HELD
(refused coded). No probe may ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Module-level deployment mode; also verified under a
clean environment. Depth-1 green checks honor GOV_SKIP_GREEN.

Run:
  mkdir -p /var/tmp/g301-rs && TMPDIR=/var/tmp/g301-rs \
    ~/workspace/.gov-venv/bin/python evals/w301_routing_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g301-rsb \
    ~/workspace/.gov-venv/bin/python evals/w301_routing_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PIN = 1869  # Wave-300 merge pin 1802; wave-301 lane 5: pin 1802 -> 1804 (+2 workflow-routing-*); wave-301 merge: 1812 (+10 workflow-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from gov import ed25519
    from gov import workflow_routing as wr
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class RoutingSlipProbes(unittest.TestCase):
    maxDiff = None

    # -- fixtures -----------------------------------------------------

    def setUp(self):
        if not HAVE_MODULE:
            self.fail("BREAK: gov/workflow_routing.py absent on this tree")
        self.seed_issuer = hashlib.sha256(b"rs-issuer").digest()
        self.seed_b = hashlib.sha256(b"rs-b").digest()
        self.seed_c = hashlib.sha256(b"rs-c").digest()
        self.seed_d = hashlib.sha256(b"rs-d").digest()
        self.seed_evil = hashlib.sha256(b"rs-evil").digest()
        self.pub_issuer = ed25519.publickey(self.seed_issuer).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.pub_d = ed25519.publickey(self.seed_d).hex()
        self.at = 1_700_000_000
        self.trust = [self.pub_issuer]

    def _leg(self, hid, pub, rights=("tool.invoke",)):
        return {"handler_id": hid, "handler_pubkey_hex": pub,
                "rights": list(rights),
                "input_digest": _hex64("in-" + hid),
                "output_digest": _hex64("out-" + hid)}

    def _slip(self, rights_b=("tool.invoke",), rights_c=("tool.invoke",)):
        return wr.issue_slip(
            self.seed_issuer, "issuer",
            [self._leg("agent-b", self.pub_b, rights_b),
             self._leg("agent-c", self.pub_c, rights_c),
             self._leg("agent-d", self.pub_d, ("tool.invoke",))],
            issued_at=self.at, expires_at=self.at + 3600)

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    # -- E probes: BREAK-iff-vulnerable --------------------------------

    def test_E01_leg_skip(self):
        """E01: completing leg 1 while leg 0 is outstanding."""
        code = self._code_of(wr.complete_leg, self._slip(), 1, self.seed_c,
                             _hex64("res-c"), self.at, self.trust)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_E02_leg_reorder(self):
        """E02: forged next_leg rewinds a completed slip."""
        slip = wr.complete_leg(self._slip(), 0, self.seed_b,
                               _hex64("res-b"), self.at, self.trust)
        rewound = dict(slip)
        rewound["next_leg"] = 0
        code = self._code_of(wr.verify_slip, rewound, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_E03_rights_widening_at_forward(self):
        """E03: leg forwards MORE rights than it was granted."""
        slip = self._slip(rights_b=("tool.invoke",))
        code = self._code_of(
            wr.complete_leg, slip, 0, self.seed_b, _hex64("res-b"),
            self.at, self.trust,
            forwarded_rights=["tool.invoke", "memory.read"])
        self.assertEqual(code, "workflow-routing-rights-widened")

    def test_E04_downstream_grant_exceeds_forwarded(self):
        """E04: itinerary grants a later leg rights never forwarded."""
        slip = self._slip(rights_b=("tool.invoke",),
                          rights_c=("tool.invoke", "memory.read"))
        slip = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                               self.at, self.trust)
        code = self._code_of(wr.accept_leg, slip, 1, self.seed_c,
                             self.at, self.trust)
        self.assertEqual(code, "workflow-routing-rights-widened")

    def test_E05_forged_slip_signature(self):
        """E05: legs widened under the issuer's old signature."""
        slip = self._slip()
        tampered = dict(slip)
        tampered["legs"] = [dict(l) for l in slip["legs"]]
        tampered["legs"][1] = dict(slip["legs"][1])
        tampered["legs"][1]["rights"] = ["tool.invoke", "admin.all"]
        code = self._code_of(wr.verify_slip, tampered, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_E06_truncated_receipt_chain(self):
        """E06: drop a middle receipt, keep the tail signature."""
        slip = self._slip()
        slip = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                               self.at, self.trust)
        slip = wr.complete_leg(slip, 1, self.seed_c, _hex64("res-c"),
                               self.at, self.trust)
        truncated = dict(slip)
        truncated["receipts"] = slip["receipts"][:1]
        code = self._code_of(wr.verify_slip, truncated, self.trust, self.at)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    def test_E07_wrong_handler_key(self):
        """E07: attacker key completes another handler's leg."""
        code = self._code_of(wr.accept_leg, self._slip(), 0,
                             self.seed_evil, self.at, self.trust)
        self.assertEqual(code, "workflow-routing-slip-tampered")

    # -- control probes: the honest path must work ---------------------

    def test_C01_honest_three_leg_workflow(self):
        slip = self._slip()
        for i, seed in enumerate((self.seed_b, self.seed_c, self.seed_d)):
            self.assertTrue(
                wr.verify_slip(slip, self.trust, self.at) is True)
            slip = wr.complete_leg(slip, i, seed, _hex64("res-%d" % i),
                                   self.at, self.trust)
        self.assertEqual(slip["next_leg"], 3)
        self.assertTrue(wr.verify_slip(slip, self.trust, self.at) is True)

    def test_C02_attenuation_allowed(self):
        slip = self._slip(rights_b=("tool.invoke", "memory.read"))
        slip2 = wr.complete_leg(slip, 0, self.seed_b, _hex64("res-b"),
                                self.at, self.trust,
                                forwarded_rights=["tool.invoke"])
        self.assertTrue(wr.verify_slip(slip2, self.trust, self.at) is True)

    # -- pin + green checks ---------------------------------------------

    def test_pin(self):
        import gov.decision_codes as dc
        self.assertEqual(len(dc.TAXONOMY), PIN)

    def test_green_check_unit(self):
        if SKIP_GREEN:
            self.skipTest("depth-1 green check: GOV_SKIP_GREEN=1")
        import subprocess  # noqa: PLC0415 -- depth-1 green only
        r = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_workflow_routing", "-v"],
            cwd=REPO, capture_output=True, text=True,
            env={**os.environ, "GOV_SKIP_GREEN": "1",
                 "GOV_DEPLOYMENT_MODE": "staging"},
            timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
