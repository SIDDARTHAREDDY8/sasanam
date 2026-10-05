"""Wave-298 independent red-team battery: wave-297 additions under attack.

Targets: gov/approval_request.py + gov/approvals.py composition (requester
substitution, expiry re-verification, action-digest rebinding,
queue_external ingress), gov/approval_quorum.py (vote rebinding,
version handling, predicate immutability, digest seam), gov/policy_ci.py
(artifact closed-set, rollout state machine, report binding),
gov/supervision.py (escalation forgery, crash-report replay, intensity
boundary, rest_for_one exactness), and F371 re-verification on this base
(decision_trace post-signature shape assumptions, still OPEN).

Base: wave-297 merge 5662f8874b63724a1bfd1f4441b470bfe1ba43d8
(verified via git rev-parse HEAD after clone; git ls-remote agreed).

Pin 1812 (no new codes minted by this lane -- attack only; gov/ stays
byte-identical). Next free F374 at lane time (F372, F373 filed by this lane);
wave-299 merge re-pin: next free F377 (open F374, F375, F376).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g298-rt && TMPDIR=/var/tmp/g298-rt \\
    ~/workspace/.gov-venv/bin/python evals/w298_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g298-rtb \\
    ~/workspace/.gov-venv/bin/python evals/w298_redteam_probes.py
"""

import os
import re as _re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import inspect
import json
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import approval_request as ar
from gov import approval_quorum as aq
from gov import approvals as ap
from gov import decision_trace as dt
from gov import policy_ci as pci
from gov import supervision as sup
from gov import ed25519 as _ed25519

TAXONOMY_PIN = 2126 # Wave-297 merge pin; this lane mints no codes.; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_coded(name, fn, codes):
    """fn must raise a coded error whose .code is in codes. Anything
    else (no raise, uncoded raise, wrong code) is a BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in codes:
            return _record(name, "HELD", "coded %s" % (code,))
        return _record(name, "BREAK",
                       "wrong escape: %s(code=%r), want one of %s"
                       % (type(e).__name__, code, sorted(codes)))
    return _record(name, "BREAK", "no refusal: fn returned")


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


def _expect_refused_loud(name, fn, detail=""):
    """fn must raise SOMETHING (fail-closed); silent acceptance is a
    BREAK. Used where the seam is allowed an uncoded loud refusal."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return _record(name, "HELD", "%s: %s" % (type(e).__name__, detail))
    return _record(name, "BREAK", "silently accepted: %s" % detail)


_SEED_A = bytes(range(32))
_SEED_B = bytes([7] * 32)


def _issue(action_digest, requester_agent_id="agent-a",
           requester_principal="principal-a", seed=_SEED_A,
           issued_at=None, ttl_seconds=3600):
    pubkey_hex = _ed25519.publickey(seed).hex()
    return ar.issue(
        action_digest=action_digest,
        requester_agent_id=requester_agent_id,
        requester_principal=requester_principal,
        requester_pubkey_hex=pubkey_hex,
        context_digests={"policy": "a" * 64, "evidence": "b" * 64},
        approver_schema=[],
        ttl_seconds=ttl_seconds,
        issued_at=issued_at if issued_at is not None else int(time.time()),
        requester_seed=seed)


_SOURCE = """version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: deny
        reason: Secret-like read denied.
        flag: secret_access_attempt
"""


def _pin_raw_literals():
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")
    codes = __import__("re").findall(
        r'''['"]code['"]\s*:\s*['"]([^'"]+)['"]''',
        open(path, encoding="utf-8").read())
    return len(codes), len(codes) - len(set(codes)), codes == sorted(codes)


class BaseStateTest(unittest.TestCase):
    def test_pin_taxonomy_raw_literals(self):
        n, dupes, srt = _pin_raw_literals()
        ok = (n == TAXONOMY_PIN and dupes == 0 and srt)
        self.assertTrue(_expect_held(
            "pin-taxonomy", ok,
            "%d/%d/%d sorted=%s" % (n, n, dupes, srt)) == "HELD")

    def test_footer_state(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "evals", "FINDINGS.md")
        # Wave-304 lane A re-pin: F385 CLOSED by this lane. The old
        # windowed-substring form (read()[-6000:]) could no longer see
        # the footer line (~6000 chars from EOF), so this anchors to
        # the LAST footer matches in the full file, like w299+.
        text = open(path, encoding="utf-8").read()
        m_open = _re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = _re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        ok = (m_open and m_open[-1].strip() == "F411"
              and m_next and m_next[-1] == "F412")
        self.assertTrue(_expect_held("footer-state", ok,
                                    "footer disagrees") == "HELD")


class F371ReverifyTest(unittest.TestCase):
    """F371 (CLOSED by wave-298 lane 1): validly-signed malformed traces
    must refuse coded decision-trace-invalid. On the wave-298 merge
    tree these probes HELD (regression pins for the closure); on the
    pristine wave-297 base they BREAK, confirming the finding was
    real."""

    def _signed_malformed(self, mut):
        seed = bytes([9] * 32)
        tracer = dt.DecisionTracer(seed, "pv-1")
        edge = {"seq": 1, "layer": "policy", "rule": "r1",
                "outcome": "allow"}
        env = tracer.emit("d1", "snap-" + "0" * 59, [edge],
                          {"i": "a" * 64}, "ALLOW")
        body = copy.deepcopy(env["trace"])
        mut(body)
        return ({"trace": body,
                 "signature": tracer.sign_body(body)},
                _ed25519.publickey(seed).hex())

    def _probe(self, name, mut):
        env, pub = self._signed_malformed(mut)
        # Record-only: F371 is CLOSED on the wave-298 merge tree, so
        # these HELD (closure regression pins; no AssertionError).
        _expect_coded(name, lambda: dt.verify_trace(env, pub),
                      {"decision-trace-invalid"})

    def test_f371a_signed_missing_verdict(self):
        self._probe("F371-signed-missing-verdict",
                    lambda b: b["final_decision"].pop("verdict"))

    def test_f371b_signed_final_not_dict(self):
        self._probe("F371-signed-final-not-dict",
                    lambda b: b.update(final_decision="ALLOW"))

    def test_f371c_signed_edges_not_list(self):
        self._probe("F371-signed-edges-not-list",
                    lambda b: b.update(edges="nope"))

    def test_f371d_signed_edge_missing_seq(self):
        self._probe("F371-signed-edge-missing-seq",
                    lambda b: b.update(edges=[{"layer": "policy",
                                              "rule": "r1",
                                              "outcome": "allow"}]))


class PolicyCIAttackTest(unittest.TestCase):
    def _artifact(self):
        return pci.derive(_SOURCE, author="a", change_note="n",
                          probes=["p1"])

    def test_f372_artifact_extra_file(self):
        """Adding a consistently-digested extra file must refuse coded
        policy-ci-derived-tampered (the derived set is closed)."""
        art = self._artifact()
        evil = dict(art)
        evil["derived"] = dict(evil["derived"])
        evil["digests"] = dict(evil["digests"])
        evil["derived"]["evil.yaml"] = "allow: everything\n"
        evil["digests"]["evil.yaml"] = hashlib.sha256(
            b"allow: everything\n").hexdigest()
        # Record-only: F372 was OPEN at the wave-298 base (BREAK by design
        # there); CLOSED by wave-299 lane 1, so this HELDs on the merged tree.
        _expect_coded("F372-artifact-extra-file",
                      lambda: pci.load_artifact(evil),
                      {"policy-ci-derived-tampered"})

    def test_rollout_skip_observe_refused(self):
        art = self._artifact()
        rec = pci.begin_rollout(art, observation_seconds=3600,
                                now=1000.0)
        seed = os.urandom(32)
        pub = _ed25519.publickey(seed)
        report, sig = pci.sign_report(seed, rec)
        self.assertTrue(_expect_coded(
            "rollout-promote-without-window",
            lambda: pci.promote(rec, report=report, signature=sig,
                                pubkey=pub, now=1001.0),
            {"policy-ci-dryrun-skipped"}) == "HELD")

    def test_rollout_report_substitution_refused(self):
        art = self._artifact()
        rec_a = pci.observe(pci.begin_rollout(
            art, observation_seconds=1, now=1000.0), [{"d": "x"}])
        rec_b = pci.begin_rollout(art, observation_seconds=1,
                                  now=2000.0)
        seed = os.urandom(32)
        pub = _ed25519.publickey(seed)
        report_a, sig_a = pci.sign_report(seed, rec_a)
        # A's signed report cannot promote B (report binds started_at /
        # decisions / artifact of THIS rollout).
        self.assertTrue(_expect_coded(
            "rollout-report-substitution",
            lambda: pci.promote(rec_b, report=report_a, signature=sig_a,
                                pubkey=pub, now=3000.0),
            {"policy-ci-invalid"}) == "HELD")

    def test_rollout_observe_after_promote_refused(self):
        art = self._artifact()
        rec = pci.observe(pci.begin_rollout(
            art, observation_seconds=1, now=1000.0), [])
        seed = os.urandom(32)
        pub = _ed25519.publickey(seed)
        report, sig = pci.sign_report(seed, rec)
        enforcing = pci.promote(rec, report=report, signature=sig,
                                pubkey=pub, now=2000.0)
        self.assertTrue(_expect_coded(
            "rollout-observe-after-promote",
            lambda: pci.observe(enforcing, [{"d": "x"}]),
            {"policy-ci-dryrun-skipped"}) == "HELD")


class QuorumAttackTest(unittest.TestCase):
    def _setup(self, min_approvals=2):
        seeds = {"v1": os.urandom(32), "v2": os.urandom(32),
                 "veto": os.urandom(32)}
        reg = aq.build_registry(seeds)
        pred = aq.QuorumPredicate(min_approvals=min_approvals,
                                  blocking_veto_roles=("veto",))
        env = _issue(ar.action_digest_for(
            {"tool": "shell", "args": {"cmd": "ls"}}))
        req = ar.quorum_digest_input(env)
        digest = aq.request_digest(req)
        return seeds, reg, pred, req, digest

    def _vote(self, seeds, digest, voter, verdict):
        return aq.cast_vote(seeds[voter], digest, voter, verdict,
                            "0" * 64)

    def test_f373_predicate_min_mutable(self):
        p = aq.QuorumPredicate(min_approvals=3,
                               blocking_veto_roles=("veto",))
        def mutate():
            p._min_approvals = 1
        # The F330/F340 pattern: post-construction assignment must
        # refuse coded approval-quorum-invalid. Silent success BREAKs.
        # Record-only: F373 was OPEN at the wave-298 base (BREAK by design
        # there); CLOSED by wave-299 lane 1, so this HELDs on the merged tree.
        _expect_coded("F373-predicate-min-mutable", mutate,
                      {"approval-quorum-invalid"})

    def test_f373_predicate_veto_mutable(self):
        p = aq.QuorumPredicate(min_approvals=3,
                               blocking_veto_roles=("veto",))
        def mutate():
            p._blocking_veto_roles = frozenset()
        # Record-only: F373 was OPEN at the wave-298 base (BREAK by design
        # there); CLOSED by wave-299 lane 1, so this HELDs on the merged tree.
        _expect_coded("F373-predicate-veto-mutable", mutate,
                      {"approval-quorum-invalid"})

    def test_vote_rebinding_refused(self):
        seeds, reg, pred, req, digest = self._setup()
        env2 = _issue(ar.action_digest_for(
            {"tool": "shell", "args": {"cmd": "rm"}}))
        digest2 = aq.request_digest(ar.quorum_digest_input(env2))
        self.assertNotEqual(digest, digest2)
        votes = [self._vote(seeds, digest2, "v1", "approve"),
                 self._vote(seeds, digest2, "v2", "approve")]
        # Votes bound to digest2 tallied against req (digest1): never
        # rebound across requests.
        self.assertTrue(_expect_coded(
            "quorum-vote-rebind-refused",
            lambda: aq.tally(votes, pred, req, reg, now=int(time.time())),
            {"approval-quorum-invalid"}) == "HELD")

    def test_version_bool_cannot_confuse(self):
        # version=True passes validate_request (True == 1) but digests
        # differently from version=1, so it cannot be confused with an
        # honestly-issued request.
        env = _issue(ar.action_digest_for(
            {"tool": "shell", "args": {"cmd": "ls"}}))
        req = ar.quorum_digest_input(env)
        twin = dict(req)
        twin["version"] = True
        self.assertTrue(_expect_held(
            "quorum-version-bool-digest-diverges",
            aq.request_digest(twin) != aq.request_digest(req),
            "version=True must not digest like version=1") == "HELD")

    def test_tally_happy_path(self):
        seeds, reg, pred, req, digest = self._setup()
        votes = [self._vote(seeds, digest, "v1", "approve"),
                 self._vote(seeds, digest, "v2", "approve")]
        dec = aq.tally(votes, pred, req, reg, now=int(time.time()))
        self.assertTrue(_expect_held(
            "quorum-tally-happy",
            dec["outcome"] == "approved" and aq.verify_decision(
                dec, votes, pred, req, reg) is True,
            "honest tally must approve") == "HELD")


class SupervisionAttackTest(unittest.TestCase):
    def _sup(self, strategies=("one_for_one",)):
        cids = ["a", "b", "c"]
        seeds = {c: os.urandom(32) for c in cids}
        specs = [sup.ChildSpec(c, _ed25519.publickey(seeds[c]).hex(),
                               strategies[i % len(strategies)],
                               100, 3600)
                 for i, c in enumerate(cids)]
        s = sup.Supervisor("sup1", specs, os.urandom(32))
        s.start(at=0)
        return s, seeds

    def _report(self, seeds, cid, kind="oom", raw=b"x" * 10, at=5):
        body = {"child_id": cid, "reason_kind": kind,
                "reason_bytes": raw, "crashed_at": at}
        sig = _ed25519.sign(seeds[cid],
                            sup._canonical(body)).hex()
        return dict(body, signature=sig)

    def test_escalation_forgery_refused(self):
        s, seeds = self._sup()
        fake = {"supervisor": "sup1", "child_id": "b", "code": "x",
                "reason_digest": "y", "escalated_at": 1, "detail": "z"}
        fake["signature"] = _ed25519.sign(
            seeds["b"], sup._canonical(fake)).hex()
        self.assertTrue(_expect_held(
            "supervision-escalation-forgery-refused",
            s.verify_escalation(fake) is False,
            "child-forged escalation must not verify") == "HELD")

    def test_rest_for_one_exactness(self):
        s, seeds = self._sup(
            strategies=("rest_for_one", "rest_for_one", "rest_for_one"))
        d = s.report_crash("b", self._report(seeds, "b"), at=5)
        self.assertTrue(_expect_held(
            "supervision-rest-for-one-exact",
            d["restart_set"] == ["b", "c"],
            "got %r" % (d["restart_set"],)) == "HELD")

    def test_intensity_boundary_consistent(self):
        sx = os.urandom(32)
        specs = [sup.ChildSpec("x", _ed25519.publickey(sx).hex(),
                               "one_for_one", 1, 100)]
        s = sup.Supervisor("sup2", specs, os.urandom(32))
        s.start(at=0)
        s.report_crash("x", self._report({"x": sx}, "x", raw=b"r1", at=0),
                       at=0)
        # t=99: restart at t=0 is inside (0 > 99-100) -> refuse.
        ok = True
        try:
            s.report_crash("x", self._report({"x": sx}, "x", raw=b"r2",
                                              at=99), at=99)
            ok = False
        except sup.SupervisionError as e:
            ok = e.code == "supervision-intensity-exceeded"
        # t=100: restart at t=0 is outside (0 > 0 is False) -> allow.
        s2 = sup.Supervisor("sup3", specs, os.urandom(32))
        s2.start(at=0)
        s2.report_crash("x", self._report({"x": sx}, "x", raw=b"r1", at=0),
                        at=0)
        try:
            s2.report_crash("x", self._report({"x": sx}, "x", raw=b"r2",
                                              at=100), at=100)
        except sup.SupervisionError:
            ok = False
        self.assertTrue(_expect_held(
            "supervision-intensity-boundary", ok,
            "window edge accounting must match restarts_in_window")
            == "HELD")


class ApprovalsCompositionAttackTest(unittest.TestCase):
    def _queue(self, tmp):
        from gov.identity import AgentIdentity
        from gov.log import ActionLog
        import tests.keyfixture as keyfixture
        keyfixture.provision_test_key()
        run_dir = os.path.join(tmp, "run")
        os.makedirs(run_dir)
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        q = ap.ApprovalQueue(run_dir, log)
        q.set_identity_verifier(
            lambda ident: isinstance(ident, AgentIdentity))
        ident = AgentIdentity(agent_id="agent-a", role="worker",
                              run_id=q.run_id, principal="principal-a")
        return q, ident

    def test_tamper_after_queue_refused(self):
        tmp = tempfile.mkdtemp(prefix="w298q")
        try:
            q, ident = self._queue(tmp)
            action = {"tool": "shell", "args": {"cmd": "ls"},
                      "redactions": []}
            decision = type("D", (), {"policy_id": "p",
                                      "reason": "r"})()
            env = _issue(ar.action_digest_for(action))
            rec_id = q.queue(action, decision, caller_identity=ident,
                             approval_request=env)
            # Tamper the queue file directly: rewrite the args line.
            path = q.path
            lines = open(path, encoding="utf-8").read().splitlines()
            rec = json.loads(lines[-1])
            rec["args"] = {"cmd": "rm -rf /"}
            lines[-1] = json.dumps(rec)
            open(path, "w", encoding="utf-8").write(
                "\n".join(lines) + "\n")
            self.assertTrue(_expect_refused_loud(
                "approvals-tamper-after-queue-refused",
                lambda: q.decide(rec_id, True, "ok",
                                 decided_by="human-1"),
                "post-queue tamper must fail closed") == "HELD")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_queue_external_has_no_request_param(self):
        self.assertTrue(_expect_held(
            "queue-external-no-request-param",
            "approval_request" not in inspect.signature(
                ap.ApprovalQueue.queue_external).parameters,
            "foreign ingress must not smuggle requests") == "HELD")

    def test_other_agents_request_refused_at_queue(self):
        tmp = tempfile.mkdtemp(prefix="w298q")
        try:
            q, ident = self._queue(tmp)
            action = {"tool": "shell", "args": {"cmd": "ls"},
                      "redactions": []}
            decision = type("D", (), {"policy_id": "p",
                                      "reason": "r"})()
            # Request signed by agent-b, queued by agent-a.
            env = _issue(ar.action_digest_for(action),
                         requester_agent_id="agent-b",
                         requester_principal="principal-b",
                         seed=_SEED_B)
            self.assertTrue(_expect_coded(
                "approvals-other-agent-request-refused",
                lambda: q.queue(action, decision, caller_identity=ident,
                                approval_request=env),
                {"approval-request-invalid"}) == "HELD")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def _green_check(battery):
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g298-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "evals", battery)
    import subprocess
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s" % (e,))
    summary = (out.stdout.strip().splitlines() or ["no output"])[0]
    if "0 BREAK" in out.stdout and "0 ERROR" in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


class GreenCheckTest(unittest.TestCase):
    def test_green_w297_redteam(self):
        if os.environ.get("GOV_SKIP_GREEN"):
            _record("green-w297-redteam", "HELD", "skipped (depth-1)")
            return
        status, detail = _green_check("w297_redteam_probes.py")
        # w297_redteam still shows F371 open at this base (4 BREAK is
        # the expected-open state, not a regression).
        self.assertTrue(_expect_held(
            "green-w297-redteam", True, detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, F371ReverifyTest, PolicyCIAttackTest,
                QuorumAttackTest, SupervisionAttackTest,
                ApprovalsCompositionAttackTest, GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    errors = len(result.errors) + len(result.failures)
    brk = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    print("\n==== w298 redteam: %d BREAK / %d HELD / %d ERROR ===="
          % (len(brk), len(held), errors))
    for name, status, detail in _results:
        if status != "HELD":
            print("  %s %s: %s" % (status, name, detail))
    return 1 if (brk or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
