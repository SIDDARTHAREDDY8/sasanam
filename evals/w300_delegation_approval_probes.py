"""Wave-300 delegated-approval battery: red-first break-first probes.

Target: gov/delegation_approval.py (new in this lane) -- delegation
receipt chains composed with approval requests. Standing rule:
"Delegation narrows, never widens."

Base: wave-299 merge a830f65f80e9317aa7ae65b83b7eb14b3922bd0e.
Pin 1797 -> 1799 (lane-local 1799 at lane time; 2 new codes:
delegation-approval-chain-mismatch, delegation-approval-right-mismatch).

Red-first: on the pristine base the module is absent, so every feature
probe BREAKs; on the fixed tree every attack probe must be HELD
(refused coded). No probe may ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Module-level deployment mode; also verified under a
clean environment. Depth-1 green checks honor GOV_SKIP_GREEN.

Run:
  mkdir -p /var/tmp/g300-da && TMPDIR=/var/tmp/g300-da \
    ~/workspace/.gov-venv/bin/python evals/w300_delegation_approval_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g300-dab \
    ~/workspace/.gov-venv/bin/python evals/w300_delegation_approval_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PIN = 2128 # wave-301 merge pin 1812 (lane-local 1799 at wave-300 lane time; wave-300 pin was 1802); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)
SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from gov import delegation as dg
    from gov import delegation_approval as da
    from gov import delegation_revocation as dr
    from gov import approval_request as ar
    from gov import ed25519
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


class DelegatedApprovalProbes(unittest.TestCase):
    maxDiff = None

    # -- fixtures -----------------------------------------------------

    def setUp(self):
        if not HAVE_MODULE:
            self.fail("BREAK: gov/delegation_approval.py absent on this tree")
        self.seed_a = hashlib.sha256(b"delegator-a").digest()
        self.seed_b = hashlib.sha256(b"delegatee-b").digest()
        self.seed_c = hashlib.sha256(b"delegatee-c").digest()
        self.seed_evil = hashlib.sha256(b"evil").digest()
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.at = 1_700_000_000
        self.action = {"tool": "shell", "args": {"cmd": "ls"}}

    def _root(self, rights=("tool.invoke", "memory.read"),
              delegatee="agent-b", seed=None, delegatee_seed=None, **kw):
        kw.setdefault("constraints",
                      {"expires_at": self.at + 3600, "max_depth": 4,
                       "allowed_targets": [delegatee]})
        dseed = delegatee_seed or (self.seed_b if delegatee == "agent-b"
                                   else self.seed_c)
        return dg.issue(seed or self.seed_a, "agent-a", delegatee,
                        ed25519.publickey(dseed).hex(), rights,
                        issued_at=self.at, **kw)

    def _link(self, parent, delegatee, delegatee_seed, rights=None,
              delegator_seed=None):
        parent_delegatee = parent["delegatee_id"]
        dseed = delegatee_seed
        return dg.issue(
            delegator_seed or
            (self.seed_b if parent_delegatee == "agent-b" else self.seed_c),
            parent_delegatee, delegatee,
            ed25519.publickey(dseed).hex(),
            rights if rights is not None else tuple(parent["rights"]),
            parent=parent,
            constraints={"expires_at": self.at + 3600, "max_depth": 4,
                         "allowed_targets": [delegatee]},
            issued_at=self.at)

    def _pkg(self, chain, right="tool.invoke", requester="agent-b",
             rseed=None, action=None, **kw):
        leaf = chain[-1]
        rid = requester
        seed = rseed or (self.seed_b if rid == "agent-b" else self.seed_c)
        kw.setdefault("approver_schema", [])
        kw.setdefault("ttl_seconds", 3600)
        kw.setdefault("issued_at", self.at)
        pub = ed25519.publickey(seed).hex()
        return da.issue_delegated_request(
            chain=chain, delegation_right=right,
            action=action or self.action,
            requester_agent_id=rid, requester_principal="principal-" + rid,
            requester_pubkey_hex=pub, requester_seed=seed, **kw)

    def _verify(self, pkg, **kw):
        kw.setdefault("at", self.at)
        kw.setdefault("trust_roots", [self.pub_a])
        return da.verify_delegated_request(pkg, **kw)

    def _assert_code(self, code, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            self.assertEqual(getattr(e, "code", None), code,
                             "expected code %r, got %r (%r)"
                             % (code, getattr(e, "code", None), e))
            return
        self.fail("expected coded refusal %r, call succeeded" % (code,))

    # -- pin ----------------------------------------------------------

    def test_pin_raw_literals(self):
        import re
        pat = re.compile(r"""^\s*"code": '([a-z0-9][a-z0-9_\-\.]*)',\s*$""")
        lits = []
        with open(os.path.join(REPO, "gov", "decision_codes.py")) as f:
            for line in f:
                m = pat.match(line.rstrip("\n"))
                if m:
                    lits.append(m.group(1))
        self.assertEqual(len(lits), len(set(lits)), "duplicate code literals")
        self.assertEqual(len(lits), PIN, "pin drift: %d != %d"
                         % (len(lits), PIN))
        self.assertEqual(sorted(lits), lits, "literals not sorted")
        self.assertIn("delegation-approval-chain-mismatch", lits)
        self.assertIn("delegation-approval-right-mismatch", lits)

    # -- happy path ---------------------------------------------------

    def test_issue_verify_roundtrip(self):
        root = self._root()
        pkg = self._pkg([root])
        v = self._verify(pkg)
        self.assertEqual(v["delegator_id"], "agent-a")
        self.assertEqual(v["delegation_right"], "tool.invoke")
        self.assertEqual(v["leaf_receipt_id"], root["receipt_id"])
        self.assertEqual(v["request"]["action_digest"],
                         ar.action_digest_for(self.action))

    def test_two_link_chain_roundtrip(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_c, ("tool.invoke",))
        pkg = self._pkg([root, link], requester="agent-c", rseed=self.seed_c)
        v = self._verify(pkg)
        self.assertEqual(v["delegation_verdict"]["depth"], 1)

    def test_bindings_present_in_context_digests(self):
        root = self._root()
        pkg = self._pkg([root])
        ctx = pkg["envelope"]["request"]["context_digests"]
        self.assertEqual(ctx["delegation_chain_digest"],
                         da.chain_digest([root]))
        self.assertEqual(ctx["delegator_id_digest"], _hex64("agent-a"))
        self.assertEqual(ctx["delegation_right_digest"], _hex64("tool.invoke"))

    def test_caller_context_digests_preserved(self):
        root = self._root()
        pkg = self._pkg([root], context_digests={"evidence": _hex64("e")})
        ctx = pkg["envelope"]["request"]["context_digests"]
        self.assertEqual(ctx["evidence"], _hex64("e"))
        self.assertIn("delegation_chain_digest", ctx)

    def test_reserved_binding_names_rejected_at_issue(self):
        root = self._root()
        with self.assertRaises(da.DelegationApprovalError) as cm:
            self._pkg([root], context_digests={
                "delegation_chain_digest": _hex64("x")})
        self.assertEqual(cm.exception.code, "delegation-invalid")

    # -- binding attacks ------------------------------------------------

    def test_chain_swap_refused(self):
        root = self._root()
        pkg = self._pkg([root])
        other = self._root(rights=("tool.invoke",))
        bad = dict(pkg)
        bad["chain"] = [dict(other)]
        self._assert_code("delegation-approval-chain-mismatch",
                          self._verify, bad)

    def test_chain_link_swap_refused(self):
        # Same chain length, different leaf: digest must catch it.
        root = self._root()
        link = self._link(root, "agent-c", self.seed_c)
        pkg = self._pkg([root, link], requester="agent-c", rseed=self.seed_c)
        other_link = self._link(root, "agent-c", self.seed_c,
                                ("memory.read",))
        bad = dict(pkg)
        bad["chain"] = [dict(root), dict(other_link)]
        self._assert_code("delegation-approval-chain-mismatch",
                          self._verify, bad)

    def test_delegator_swap_refused(self):
        # A chain from a different delegator cannot satisfy the binding.
        root = self._root()
        pkg = self._pkg([root])
        evil_root = self._root(seed=self.seed_evil, delegatee="agent-b")
        # Forge the delegator label to match while the key differs: the
        # signature won't verify, but the BINDING check must fire first
        # on the digest (defense in depth ordering).
        bad = dict(pkg)
        bad["chain"] = [dict(evil_root)]
        self._assert_code("delegation-approval-chain-mismatch",
                          self._verify, bad)

    def test_right_swap_refused(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        pkg = self._pkg([root], right="tool.invoke")
        bad = dict(pkg)
        bad["delegation_right"] = "memory.read"
        self._assert_code("delegation-approval-right-mismatch",
                          self._verify, bad)

    def test_right_outside_vocabulary_refused_at_issue(self):
        root = self._root()
        with self.assertRaises(da.DelegationApprovalError) as cm:
            self._pkg([root], right="nuke.everything")
        self.assertEqual(cm.exception.code, "delegation-invalid")

    def test_non_holder_cannot_issue(self):
        root = self._root()  # tip holder is agent-b
        with self.assertRaises(da.DelegationApprovalError) as cm:
            self._pkg([root], requester="agent-c", rseed=self.seed_c)
        self.assertEqual(cm.exception.code, "delegation-invalid")

    def test_empty_chain_refused(self):
        with self.assertRaises(da.DelegationApprovalError) as cm:
            da.issue_delegated_request(
                chain=[], delegation_right="tool.invoke",
                action=self.action, requester_agent_id="agent-b",
                requester_principal="p", requester_pubkey_hex=self.pub_b,
                requester_seed=self.seed_b, approver_schema=[],
                ttl_seconds=3600, issued_at=self.at)
        self.assertEqual(cm.exception.code, "delegation-invalid")

    # -- chain attacks (delegation module codes, no new codes) ----------

    def test_broken_chain_refused(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_c)
        pkg = self._pkg([root, link], requester="agent-c", rseed=self.seed_c)
        evil_link = dict(link)
        sig = evil_link["signature"]
        evil_link["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        bad = dict(pkg)
        bad["chain"] = [dict(root), evil_link]
        # The chain digest no longer matches either (ids unchanged but
        # the signature break is inside the chain): binding check fires
        # on digest first only if ids changed; here ids are unchanged
        # so verify_chain must catch the forgery.
        self._assert_code("delegation-chain-broken", self._verify, bad)

    def test_tampered_rights_refused(self):
        # Widening rights post-issue mutates the receipt body while the
        # link keeps its old receipt_id: the chain digest still matches
        # the bound digest, so the tampering is caught one step later
        # when verify_chain recomputes the receipt_id from the body --
        # coded delegation-chain-broken. (Recomputing the receipt_id to
        # match the mutated body would break the bound chain digest
        # instead; either way it refuses fail-closed.) A validly-signed
        # widened chain is unconstructible through the public API
        # (dg.issue refuses widening at issue); the verify_chain
        # widened check is defense-in-depth.
        root = self._root(rights=("tool.invoke",))
        link = self._link(root, "agent-c", self.seed_c, ("tool.invoke",))
        pkg = self._pkg([root, link], requester="agent-c", rseed=self.seed_c)
        wide = dict(link)
        wide["rights"] = ["tool.invoke", "memory.write"]
        bad = dict(pkg)
        bad["chain"] = [dict(root), wide]
        self._assert_code("delegation-chain-broken",
                          self._verify, bad)

    def test_right_not_covered_refused(self):
        root = self._root(rights=("memory.read",))
        pkg = self._pkg([root], right="tool.invoke")
        # authorize: leaf rights do not cover the presented right.
        self._assert_code("delegation-invalid", self._verify, pkg)

    def test_expired_chain_refused(self):
        # The REQUEST must still be live so the CHAIN expiry is what
        # fires: long request ttl, short chain expiry.
        root = self._root()
        pkg = self._pkg([root], ttl_seconds=10800)
        self._assert_code("delegation-expired", self._verify, pkg,
                          at=self.at + 7200)

    def test_unknown_root_refused(self):
        root = self._root()
        pkg = self._pkg([root])
        self._assert_code("delegation-root-untrusted", self._verify, pkg,
                          trust_roots=[self.pub_c])

    def test_third_party_redelegation_refused(self):
        # agent-evil mints a "link" labeled as agent-b's delegation.
        # delegation.issue itself refuses: the evil key is not the
        # parent's designated delegatee key (key continuity, not label
        # continuity -- the confused-deputy class).
        root = self._root()
        self.assertRaises(dg.DelegationError, dg.issue,
                          self.seed_evil, "agent-b", "agent-c", self.pub_c,
                          ("tool.invoke",), parent=root,
                          constraints={"expires_at": self.at + 3600,
                                       "max_depth": 4,
                                       "allowed_targets": ["agent-c"]},
                          issued_at=self.at)

    # -- request attacks (approval-request codes) ------------------------

    def test_expired_request_refused(self):
        root = self._root()
        pkg = self._pkg([root], ttl_seconds=60, issued_at=self.at)
        self._assert_code("approval-request-expired", self._verify, pkg,
                          at=self.at + 61)

    def test_tampered_envelope_refused(self):
        root = self._root()
        pkg = self._pkg([root])
        env = json.loads(json.dumps(pkg["envelope"]))
        env["request"]["action_digest"] = _hex64("other-action")
        bad = dict(pkg)
        bad["envelope"] = env
        self._assert_code("approval-request-forgery", self._verify, bad)

    def test_envelope_without_delegation_binding_refused(self):
        # A plain (non-delegated) approval request is not a delegated
        # request: the binding check must refuse, not silently accept.
        env = ar.issue(
            action_digest=ar.action_digest_for(self.action),
            requester_agent_id="agent-b", requester_principal="p-b",
            requester_pubkey_hex=self.pub_b,
            context_digests={"evidence": _hex64("e")},
            approver_schema=[], ttl_seconds=3600, issued_at=self.at,
            requester_seed=self.seed_b)
        root = self._root()
        pkg = {"envelope": env, "chain": [dict(root)],
               "delegation_right": "tool.invoke"}
        self._assert_code("delegation-approval-chain-mismatch",
                          self._verify, pkg)

    # -- revocation ------------------------------------------------------

    def test_revoked_chain_refused(self):
        root = self._root()
        pkg = self._pkg([root])
        revoker = dr.DelegationRevoker(self.seed_a, "agent-a")
        revoker.revoke(root["receipt_id"], self.at + 10)
        self._assert_code("delegation-revoked", self._verify, pkg,
                          revoker=revoker)

    def test_revoked_ancestor_kills_descendant_request(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_c)
        pkg = self._pkg([root, link], requester="agent-c", rseed=self.seed_c)
        revoker = dr.DelegationRevoker(self.seed_a, "agent-a")
        revoker.revoke(root["receipt_id"], self.at + 10)
        self._assert_code("delegation-revoked", self._verify, pkg,
                          revoker=revoker)

    def test_no_revoker_accepts_unrevoked(self):
        # Without a revoker, revocation is not checked (documented).
        root = self._root()
        pkg = self._pkg([root])
        v = self._verify(pkg)  # no revoker
        self.assertEqual(v["leaf_receipt_id"], root["receipt_id"])

    # -- queue composition -------------------------------------------------

    def test_queue_accepts_delegated_request(self):
        import shutil
        import tempfile
        import time as _time
        from gov import approvals as AP
        from gov.identity import AgentIdentity
        from gov.log import ActionLog
        import tests.keyfixture as keyfixture
        keyfixture.provision_test_key()
        tmp = tempfile.mkdtemp(prefix="w300daq")
        try:
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
            q = AP.ApprovalQueue(run_dir, log)
            q.set_identity_verifier(
                lambda ident: isinstance(ident, AgentIdentity))
            ident = AgentIdentity(agent_id="agent-b", role="worker",
                                  run_id=q.run_id, principal="principal-b")
            # The queue verifies the request against the wall clock, so
            # the delegated request is issued at wall-clock time here.
            # (The chain's own expiry is the delegation module's
            # concern; the queue only sees the request envelope.)
            wall = int(_time.time())
            root = self._root()
            pkg = self._pkg([root], issued_at=wall)
            action = {"tool": "shell", "args": {"cmd": "ls"},
                      "redactions": []}
            decision = type("D", (), {"policy_id": "p",
                                      "reason": "r"})()
            rec_id = q.queue(action, decision, caller_identity=ident,
                             approval_request=pkg["envelope"])
            rec = q.get(rec_id)
            self.assertEqual(rec.get("approval_request"), pkg["envelope"])
            # decide() re-verifies the request at decide time.
            q.decide(rec_id, True, "ok", decided_by="human-1")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # -- contract probes ---------------------------------------------------

    def test_ed25519_contract_pinned(self):
        msg = b"contract-probe"
        sig = ed25519.sign(self.seed_a, msg)
        self.assertIs(ed25519.verify(bytes.fromhex(self.pub_a), msg, sig),
                      True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(bytes.fromhex(self.pub_a), msg,
                                     bytes(bad)), False)

    def test_sink_never_breaks(self):
        da.set_sink(lambda record: 1 / 0)
        try:
            root = self._root()
            pkg = self._pkg([root])
            self._verify(pkg)
        finally:
            da.set_sink(None)

    def test_chain_digest_stable(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_c)
        d1 = da.chain_digest([root, link])
        d2 = da.chain_digest([dict(root), dict(link)])
        self.assertEqual(d1, d2)
        self.assertTrue(all(c in "0123456789abcdef" for c in d1))
        self.assertEqual(len(d1), 64)


class GreenChecks(unittest.TestCase):
    def _run(self, name, path, tolerate=()):
        if SKIP_GREEN:
            return
        tmp = tempfile.mkdtemp(prefix="g300-green-")
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
        # Batteries print "<n> BREAK / <m> HELD / <k> ERROR" (custom
        # harness) or unittest's OK/FAILED summary. Either way, any
        # break/error fails the green check unless tolerated.
        import re
        bad = []
        for ln in out.splitlines():
            s = ln.strip()
            # Custom harness: "<n> BREAK / <m> HELD / <k> ERROR".
            m = re.match(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", s)
            if m and (int(m.group(1)) or int(m.group(3))):
                if not any(t in s for t in tolerate):
                    bad.append(s)
                continue
            # unittest: "FAIL: test_x (...)" / "ERROR: test_x (...)" lines
            # carry the per-test detail; the "FAILED (...)" summary is
            # redundant once details are collected.
            if s.startswith("FAIL:") or s.startswith("ERROR:"):
                if not any(t in s for t in tolerate):
                    bad.append(s)
        self.assertEqual(bad, [], "green check %s had failures: %s"
                         % (name, bad[:5]))

    def test_green_w297_approval_request(self):
        self._run("w297_approval_request",
                  os.path.join(REPO, "evals",
                               "w297_approval_request_probes.py"))

    def test_green_w297_approval_quorum(self):
        self._run("w297_approval_quorum",
                  os.path.join(REPO, "evals",
                               "w297_approval_quorum_probes.py"))

    def test_green_w299_delegation(self):
        # Wave-300 merge: tree and w299 battery both pin 1812.
        # Tolerate only its pin-taxonomy probe; every other break is real.
        self._run("w299_delegation",
                  os.path.join(REPO, "evals", "w299_delegation_probes.py"),
                  tolerate=("test_pin_taxonomy", "test_pin_raw_literals",
                            "pin-taxonomy"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
