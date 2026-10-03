"""Wave-299 delegation-receipt battery: red-first break-first probes.

Target: gov/delegation.py (new in this lane) -- signed, chained,
attenuated delegation receipts (capnproto STEAL + Agoric OCap STEAL).
Standing rule: "Delegation narrows, never widens."

Base: wave-298 merge 2af956fd880d9a58a9e26e51efb6f47e82594b4e.
Pin 1784 -> 1797 (wave-299 merge; lane-local 1784 at lane time; 4 new codes: delegation-invalid,
delegation-widened, delegation-depth-exceeded,
delegation-escrow-violated; delegation-chain-broken reused).

Red-first: on the pristine base the module is absent, so every
feature probe BREAKs; on the fixed tree every attack probe must be
HELD (refused coded). No probe may ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Module-level deployment mode; also verified under a
clean environment.

Run:
  mkdir -p /var/tmp/g299-del && TMPDIR=/var/tmp/g299-del \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g299-delb \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PIN = 1878  # was lane-local 1784; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

try:
    from gov import delegation as dg
    from gov import ed25519
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class DelegationProbes(unittest.TestCase):
    maxDiff = None

    # -- helpers ------------------------------------------------------

    def setUp(self):
        if not HAVE_MODULE:
            self.fail("BREAK: gov/delegation.py absent on this tree")
        self.seed_a = hashlib.sha256(b"delegator-a").digest()
        self.seed_b = hashlib.sha256(b"delegatee-b").digest()
        self.seed_c = hashlib.sha256(b"delegatee-c").digest()
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.at = 1_700_000_000

    def _root(self, rights=("tool.invoke", "memory.read"), delegatee="agent-b",
              seed=None, delegatee_seed=None, **kw):
        kw.setdefault("constraints",
                      {"expires_at": self.at + 3600, "max_depth": 4})
        dseed = delegatee_seed or (self.seed_b if delegatee == "agent-b"
                                   else self.seed_c)
        return dg.issue(seed or self.seed_a, "agent-a", delegatee,
                         ed25519.publickey(dseed).hex(), rights,
                         issued_at=self.at, **kw)

    def _chain(self, root, *links):
        return [root] + list(links)

    def _assert_code(self, code, fn, *args, **kwargs):
        with self.assertRaises(dg.DelegationError) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code,
                         "expected code %s, got %s (%s)"
                         % (code, ctx.exception.code, ctx.exception))

    # -- red-first feature probes --------------------------------------

    def test_module_present(self):
        self.assertTrue(HAVE_MODULE, "BREAK: module absent")

    def test_pin_taxonomy(self):
        from gov import decision_codes as dc
        n = len(dc.TAXONOMY)
        self.assertEqual(n, PIN, "BREAK: taxonomy pin %d != %d" % (n, PIN))

    def test_new_codes_registered(self):
        from gov import decision_codes as dc
        for code in ("delegation-invalid", "delegation-widened",
                     "delegation-depth-exceeded", "delegation-escrow-violated",
                     "delegation-chain-broken"):
            self.assertIn(code, dc.TAXONOMY, "BREAK: code missing: " + code)

    def test_root_issue_and_verify(self):
        root = self._root()
        verdict = dg.verify_chain(root, [root], at=self.at,
                                  trust_roots=[self.pub_a])
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["depth"], 0)

    def test_downstream_narrowing_chain(self):
        root = self._root(rights=("tool.invoke", "memory.read", "memory.write"))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke", "memory.read"), parent=root,
                       constraints={"expires_at": self.at + 1800,
                                    "max_depth": 4},
                       issued_at=self.at)
        verdict = dg.verify_chain(mid, [root, mid], at=self.at,
                                  trust_roots=[self.pub_a])
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["depth"], 1)

    def test_attenuate_interposition(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        narrow = dg.attenuate(root, ("memory.read",), self.seed_b,
                              issued_at=self.at)
        self.assertEqual(narrow["delegatee_id"], "agent-b")
        self.assertEqual(list(narrow["rights"]), ["memory.read"])
        self.assertEqual(narrow["parent_receipt_id"], root["receipt_id"])
        # the old receipt is untouched and still verifies for its rights
        v = dg.verify_chain(root, [root], at=self.at,
                            trust_roots=[self.pub_a])
        self.assertTrue(v["verified"])

    def test_authorize_no_ambient_authority(self):
        root = self._root(rights=("tool.invoke",))
        v = dg.authorize([root], "tool.invoke", "agent-b", at=self.at,
                         trust_roots=[self.pub_a])
        self.assertTrue(v["verified"])
        # right not granted -> coded refusal
        self._assert_code("delegation-invalid", dg.authorize, [root],
                         "memory.write", "agent-b", at=self.at,
                         trust_roots=[self.pub_a])

    # -- attack probes (must be HELD: refused coded) --------------------

    def test_widened_rights_refused(self):
        root = self._root(rights=("memory.read",))
        self._assert_code(
            "delegation-widened", dg.issue, self.seed_b, "agent-b",
            "agent-c", self.pub_c, ("memory.read", "tool.invoke"),
            parent=root,
            constraints={"expires_at": self.at + 1800, "max_depth": 4},
            issued_at=self.at)

    def test_forged_middle_link_refused(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke",), parent=root,
                       constraints={"expires_at": self.at + 1800,
                                    "max_depth": 4},
                       issued_at=self.at)
        evil = dict(mid)
        evil["rights"] = ["tool.invoke", "memory.write"]  # widen post-sign
        # receipt_id no longer matches the body -> chain-broken
        self._assert_code("delegation-chain-broken", dg.verify_chain,
                         evil, [root, evil], at=self.at,
                         trust_roots=[self.pub_a])

    def test_signature_forgery_refused(self):
        root = self._root()
        evil = dict(root)
        # re-sign nothing: flip a bit of the signature hex
        sig = evil["signature"]
        evil["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        self._assert_code("delegation-chain-broken", dg.verify_chain,
                         evil, [evil], at=self.at,
                         trust_roots=[self.pub_a])

    def test_third_party_redelegation_refused(self):
        # agent-c holds nothing; it cannot re-delegate agent-a's receipt
        root = self._root()
        self._assert_code(
            "delegation-chain-broken", dg.issue, self.seed_c, "agent-c",
            "agent-d", self.pub_c, ("tool.invoke",), parent=root,
            constraints={"expires_at": self.at + 1800, "max_depth": 4},
            issued_at=self.at)

    def test_depth_exceeded_refused(self):
        root = self._root(rights=("tool.invoke",),
                          constraints={"expires_at": self.at + 3600,
                                       "max_depth": 1})
        # depth 1 is fine
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke",),
                       parent=root,
                       constraints={"expires_at": self.at + 1800,
                                    "max_depth": 1},
                       issued_at=self.at)
        # depth 2 exceeds max_depth 1
        self._assert_code(
            "delegation-depth-exceeded", dg.issue, self.seed_c, "agent-c",
            "agent-d", self.pub_c, ("tool.invoke",), parent=mid,
            constraints={"expires_at": self.at + 900, "max_depth": 1},
            issued_at=self.at)

    def test_expired_link_refused(self):
        root = self._root(
            constraints={"expires_at": self.at + 10, "max_depth": 4})
        self._assert_code("delegation-expired", dg.verify_chain,
                         root, [root], at=self.at + 10,
                         trust_roots=[self.pub_a])

    def test_unknown_root_key_refused(self):
        root = self._root()
        self._assert_code("delegation-root-untrusted", dg.verify_chain,
                         root, [root], at=self.at,
                         trust_roots=[_hex64("somebody-else")])

    def test_replayed_receipt_wrong_delegatee(self):
        root = self._root(delegatee="agent-b")
        # agent-c presents agent-b's receipt as its own authority
        self._assert_code("delegation-chain-broken", dg.authorize,
                         [root], "tool.invoke", "agent-c", at=self.at,
                         trust_roots=[self.pub_a])

    def test_rights_outside_vocabulary_refused(self):
        self._assert_code("delegation-invalid", dg.issue,
                         self.seed_a, "agent-a", "agent-b", self.pub_b,
                         ("nuke.everything",),
                         constraints={"expires_at": self.at + 3600,
                                      "max_depth": 4},
                         issued_at=self.at)

    def test_allowed_targets_enforced(self):
        root = self._root(
            rights=("tool.invoke",),
            constraints={"expires_at": self.at + 3600, "max_depth": 4,
                         "allowed_targets": ["agent-b"]})
        v = dg.authorize([root], "tool.invoke", "agent-b", at=self.at,
                         trust_roots=[self.pub_a])
        self.assertTrue(v["verified"])
        # a non-holder presenting the receipt is a replay -> chain-broken
        self._assert_code("delegation-chain-broken", dg.authorize, [root],
                         "tool.invoke", "agent-e", at=self.at,
                         trust_roots=[self.pub_a])
        # targets that exclude the delegatee are contradictory at issue
        self._assert_code(
            "delegation-invalid", dg.issue, self.seed_a, "agent-a",
            "agent-b", self.pub_b, ("tool.invoke",),
            constraints={"expires_at": self.at + 3600, "max_depth": 4,
                         "allowed_targets": ["agent-c"]},
            issued_at=self.at)

    def test_attenuate_wider_refused(self):
        root = self._root(rights=("memory.read",))
        self._assert_code("delegation-widened", dg.attenuate, root,
                         ("memory.read", "tool.invoke"), self.seed_b,
                         issued_at=self.at)

    # -- escrow probes --------------------------------------------------

    def _escrow(self):
        effect1 = _hex64("effect-1")
        effect2 = _hex64("effect-2")
        steps = [{"step_id": "s1", "expected_effect_digest": effect1},
                 {"step_id": "s2", "expected_effect_digest": effect2}]
        esc = dg.escrow_begin(steps, self.seed_a, "agent-a", at=self.at)
        r1 = dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                      ("escrow.commit",), designated_object=effect1,
                      constraints={"expires_at": self.at + 3600,
                                   "max_depth": 4},
                      issued_at=self.at)
        r2 = dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                      ("escrow.commit",), designated_object=effect2,
                      constraints={"expires_at": self.at + 3600,
                                   "max_depth": 4},
                      issued_at=self.at)
        return esc, {"s1": [r1], "s2": [r2]}

    def test_escrow_commit_happy_path(self):
        esc, chains = self._escrow()
        done = dg.escrow_commit(esc, chains, at=self.at,
                                trust_roots=[self.pub_a])
        self.assertEqual(done["state"], "committed")

    def test_escrow_commit_missing_step_refused(self):
        esc, chains = self._escrow()
        del chains["s2"]
        self._assert_code("delegation-escrow-violated", dg.escrow_commit,
                         esc, chains, at=self.at, trust_roots=[self.pub_a])

    def test_escrow_commit_wrong_effect_refused(self):
        esc, chains = self._escrow()
        evil = dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                        ("escrow.commit",),
                        designated_object=_hex64("different-effect"),
                        constraints={"expires_at": self.at + 3600,
                                     "max_depth": 4},
                        issued_at=self.at)
        chains["s1"] = [evil]
        self._assert_code("delegation-escrow-violated", dg.escrow_commit,
                         esc, chains, at=self.at, trust_roots=[self.pub_a])

    def test_escrow_commit_without_right_refused(self):
        esc, chains = self._escrow()
        plain = dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                         ("tool.invoke",),
                         designated_object=_hex64("effect-1"),
                         constraints={"expires_at": self.at + 3600,
                                      "max_depth": 4},
                         issued_at=self.at)
        chains["s1"] = [plain]
        self._assert_code("delegation-escrow-violated", dg.escrow_commit,
                         esc, chains, at=self.at, trust_roots=[self.pub_a])

    def test_escrow_double_commit_refused(self):
        esc, chains = self._escrow()
        done = dg.escrow_commit(esc, chains, at=self.at,
                                trust_roots=[self.pub_a])
        self._assert_code("delegation-escrow-violated", dg.escrow_commit,
                         done, chains, at=self.at, trust_roots=[self.pub_a])

    def test_escrow_abort_always_available(self):
        esc, chains = self._escrow()
        aborted = dg.escrow_abort(esc)
        self.assertEqual(aborted["state"], "aborted")
        # aborting again refuses nothing
        again = dg.escrow_abort(aborted)
        self.assertEqual(again["state"], "aborted")

    def test_escrow_forged_signature_refused(self):
        esc, _ = self._escrow()
        evil = dict(esc)
        sig = evil["signature"]
        evil["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        self._assert_code("delegation-chain-broken", dg.escrow_commit,
                         evil, {}, at=self.at, trust_roots=[self.pub_a])

    # -- contract probes -------------------------------------------------

    def test_ed25519_contract_pinned(self):
        # wave-243: verify returns exactly True/False; callers check is True
        msg = b"contract-probe"
        sig = ed25519.sign(self.seed_a, msg)
        self.assertIs(ed25519.verify(bytes.fromhex(self.pub_a), msg, sig),
                      True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(bytes.fromhex(self.pub_a), msg,
                                     bytes(bad)), False)

    def test_sink_never_breaks(self):
        dg.set_sink(lambda record: 1 / 0)
        try:
            root = self._root()
            dg.verify_chain(root, [root], at=self.at,
                            trust_roots=[self.pub_a])
        finally:
            dg.set_sink(None)

    def test_receipts_frozen(self):
        root = self._root()
        with self.assertRaises(TypeError):
            root["rights"] = ["tool.invoke"]
        with self.assertRaises(AttributeError):
            root.new_field = 1


if __name__ == "__main__":
    unittest.main(verbosity=1)
