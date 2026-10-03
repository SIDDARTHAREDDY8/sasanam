"""Wave-313 lane B unit tests: gov/approval_tokens (Row 7 step 3).

Capability-bound, argument-bound approval tokens. Red-first tests at
the public seams (issue_token / verify_token / TokenConsumeStore).
Every coded refusal is asserted by code, not by message.
"""

import copy
import os
import time
import unittest

# The suite (tests/__init__.py) provisions a test HMAC key at import.
# Standalone runs (python tests/test_approval_tokens.py) do not import
# the tests package, so provision one here when absent. Test-only.
if "GOV_LOG_KEY" not in os.environ:
    try:
        from tests.keyfixture import provision_test_key
    except ImportError:
        from keyfixture import provision_test_key
    provision_test_key()

from gov import approval_tokens as AT

_NOW = 1798765432


def _issue(**kw):
    base = {
        "capability": "send_email",
        "argument_binding": {"mode": "exact",
                             "args": {"to": "colleague@example.com",
                                      "body": "the report"}},
        "issuer": "human-operator",
        "ttl_seconds": 3600,
        "issued_at": _NOW,
    }
    base.update(kw)
    return AT.issue_token(**base)


def _code_of(fn):
    try:
        fn()
    except AT.ApprovalTokenError as e:
        return e.code
    return None


class TestIssueVerify(unittest.TestCase):
    def test_roundtrip_exact(self):
        tok = _issue()
        body = AT.verify_token(
            tok, capability="send_email",
            args={"to": "colleague@example.com", "body": "the report"},
            now=_NOW)
        self.assertEqual(body["capability"], "send_email")
        self.assertEqual(body["issuer"], "human-operator")

    def test_token_shape(self):
        tok = _issue()
        for field in ("v", "capability", "argument_binding", "issuer",
                      "issued_at", "expires_at", "nonce", "key_epoch",
                      "mac"):
            self.assertIn(field, tok)
        self.assertEqual(tok["v"], 1)
        self.assertEqual(tok["expires_at"], _NOW + 3600)
        self.assertEqual(len(tok["nonce"]), 32)
        self.assertEqual(len(tok["mac"]), 64)

    def test_nonce_unique(self):
        self.assertNotEqual(_issue()["nonce"], _issue()["nonce"])

    def test_deterministic_seal(self):
        kw = {"nonce": "ab" * 16}
        self.assertEqual(_issue(**kw)["mac"], _issue(**kw)["mac"])

    def test_arg_order_irrelevant(self):
        tok = _issue()
        body = AT.verify_token(
            tok, capability="send_email",
            args={"body": "the report", "to": "colleague@example.com"},
            now=_NOW)
        self.assertEqual(body["capability"], "send_email")


class TestRefusals(unittest.TestCase):
    def test_tampered_mac_refused(self):
        tok = _issue()
        bad = copy.deepcopy(tok)
        bad["mac"] = "00" + bad["mac"][2:]
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                bad, capability="send_email",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW)),
            "approval-token-tampered")

    def test_tampered_body_refused(self):
        tok = _issue()
        bad = copy.deepcopy(tok)
        bad["capability"] = "delete_file"
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                bad, capability="delete_file",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW)),
            "approval-token-tampered")

    def test_tampered_args_refused(self):
        tok = _issue()
        bad = copy.deepcopy(tok)
        bad["argument_binding"] = {"mode": "exact",
                                   "args": {"to": "attacker@example.com"}}
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                bad, capability="send_email",
                args={"to": "attacker@example.com"},
                now=_NOW)),
            "approval-token-tampered")

    def test_capability_substitution_refused(self):
        # A token minted for send_email never authorizes delete_file.
        tok = _issue()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="delete_file",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW)),
            "approval-token-capability-mismatch")

    def test_argument_substitution_refused(self):
        # Step 3 tries to reuse step 1's token for a harmful variant.
        tok = _issue()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "attacker@example.com", "body": "the report"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_argument_widening_refused(self):
        # A token minted for a prefix of the arguments does not cover
        # the widened call.
        tok = _issue(argument_binding={
            "mode": "exact", "args": {"to": "colleague@example.com"}})
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com",
                      "bcc": "attacker@example.com"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_argument_narrowing_refused(self):
        tok = _issue()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_expired_refused(self):
        tok = _issue()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW + 3600)),
            "approval-token-expired")
        # One second before expiry still verifies.
        body = AT.verify_token(
            tok, capability="send_email",
            args={"to": "colleague@example.com", "body": "the report"},
            now=_NOW + 3599)
        self.assertEqual(body["capability"], "send_email")

    def test_replay_refused(self):
        tok = _issue()
        store = AT.TokenConsumeStore()
        AT.verify_token(
            tok, capability="send_email",
            args={"to": "colleague@example.com", "body": "the report"},
            now=_NOW, consume_store=store)
        store.consume(tok["nonce"], now=_NOW)
        self.assertTrue(store.is_consumed(tok["nonce"]))
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW, consume_store=store)),
            "approval-token-replayed")

    def test_double_consume_refused(self):
        tok = _issue()
        store = AT.TokenConsumeStore()
        self.assertTrue(store.consume(tok["nonce"], now=_NOW))
        self.assertEqual(
            _code_of(lambda: store.consume(tok["nonce"], now=_NOW)),
            "approval-token-replayed")

    def test_no_store_no_replay_check(self):
        # Without a consume store there is no replay memory: the
        # caller owns replay protection. Documented, not a hole in
        # the check itself.
        tok = _issue()
        for _ in range(2):
            AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW)

    def test_malformed_token_shapes(self):
        good = _issue()
        cases = [
            None, "nope", 42, [],
            {},  # missing fields
            dict([f for f in good.items() if f[0] != "mac"]),
            dict(good, v=2),
            dict(good, capability=""),
            dict(good, nonce="xyz"),
            dict(good, mac="zz" * 32),
            dict(good, issued_at=-1),
            dict(good, expires_at=good["issued_at"]),
            dict(good, extra="field"),
            dict(good, argument_binding={"mode": "bogus"}),
        ]
        for bad in cases:
            self.assertEqual(
                _code_of(lambda: AT.verify_token(
                    bad, capability="send_email", args={}, now=_NOW)),
                "approval-token-malformed", "case %r" % (bad,))

    def test_future_issued_refused(self):
        tok = _issue()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com", "body": "the report"},
                now=_NOW - 1)),
            "approval-token-malformed")


class TestIssueValidation(unittest.TestCase):
    def test_bad_capability(self):
        for bad in ("", None, 42, "x" * 300):
            self.assertEqual(
                _code_of(lambda: _issue(capability=bad)),
                "approval-token-malformed")

    def test_bad_ttl(self):
        for bad in (0, 59, 30 * 24 * 3600 + 1, "3600", 3.5, True):
            self.assertEqual(
                _code_of(lambda: _issue(ttl_seconds=bad)),
                "approval-token-malformed")

    def test_bad_binding(self):
        for bad in (None, "args", {"mode": "exact"},
                    {"mode": "exact", "args": "nope"},
                    {"mode": "exact", "args": {}, "extra": 1},
                    {"mode": "schema"},
                    {"mode": "schema", "schema": {}},
                    {"mode": "nope"}):
            self.assertEqual(
                _code_of(lambda: _issue(argument_binding=bad)),
                "approval-token-malformed")

    def test_non_json_native_args_refused(self):
        self.assertEqual(
            _code_of(lambda: _issue(argument_binding={
                "mode": "exact", "args": {"s": {1, 2, 3}}})),
            "approval-token-malformed")
        self.assertEqual(
            _code_of(lambda: _issue(argument_binding={
                "mode": "exact", "args": {"t": (1, 2)}})),            "approval-token-malformed")
        self.assertEqual(
            _code_of(lambda: _issue(argument_binding={
                "mode": "exact", "args": {"f": float("nan")}})),            "approval-token-malformed")

    def test_bad_issuer(self):
        for bad in ("", None, 42):
            self.assertEqual(
                _code_of(lambda: _issue(issuer=bad)),
                "approval-token-malformed")


class TestSchemaBinding(unittest.TestCase):
    def _schema_token(self, **kw):
        base = {
            "capability": "send_email",
            "argument_binding": {"mode": "schema", "schema": {
                "to": {"enum": ["colleague@example.com",
                                "manager@example.com"]},
                "priority": {"enum": ["low", "high"]}}},
            "issuer": "human-operator",
            "ttl_seconds": 3600,
            "issued_at": _NOW,
        }
        base.update(kw)
        return AT.issue_token(**base)

    def test_schema_roundtrip(self):
        tok = self._schema_token()
        body = AT.verify_token(
            tok, capability="send_email",
            args={"to": "manager@example.com", "priority": "low"},
            now=_NOW)
        self.assertEqual(body["argument_binding"]["mode"], "schema")

    def test_schema_undeclared_value_refused(self):
        tok = self._schema_token()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "attacker@example.com", "priority": "low"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_schema_widening_refused(self):
        # Extra keys past the declared surface are refused even when
        # every declared key matches.
        tok = self._schema_token()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com", "priority": "low",
                      "bcc": "attacker@example.com"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_schema_narrowing_refused(self):
        tok = self._schema_token()
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "colleague@example.com"},
                now=_NOW)),
            "approval-token-argument-mismatch")

    def test_schema_type_strict(self):
        tok = self._schema_token(argument_binding={
            "mode": "schema",
            "schema": {"count": {"enum": [1]}}})
        for bad in ("1", True, 1.0):
            self.assertEqual(
                _code_of(lambda: AT.verify_token(
                    tok, capability="send_email",
                    args={"count": bad}, now=_NOW)),
                "approval-token-argument-mismatch", "value %r" % (bad,))
        body = AT.verify_token(tok, capability="send_email",
                                args={"count": 1}, now=_NOW)
        self.assertEqual(body["capability"], "send_email")


class TestDecomposedReuse(unittest.TestCase):
    """The compositional attack the corpus measures: step 1 is approved
    benign; step 3 tries to reuse step 1's token for a harmful variant
    of the same capability."""

    def test_benign_step_token_does_not_authorize_harmful_variant(self):
        step1 = AT.issue_token(
            "send_email",
            {"mode": "exact",
             "args": {"to": "teammate@example.com",
                      "body": "weekly report attached"}},
            issuer="human-operator", ttl_seconds=3600, issued_at=_NOW)
        # The benign presentation verifies.
        AT.verify_token(step1, capability="send_email",
                        args={"to": "teammate@example.com",
                              "body": "weekly report attached"},
                        now=_NOW)
        # Step 3: same tool, recipient swapped to the exfil target.
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                step1, capability="send_email",
                args={"to": "external-drop@example.com",
                      "body": "weekly report attached"},
                now=_NOW)),
            "approval-token-argument-mismatch")
        # Step 3b: same tool AND same args shape, different tool.
        step1b = AT.issue_token(
            "write_file",
            {"mode": "exact",
             "args": {"path": "/tmp/notes.txt", "content": "draft"}},
            issuer="human-operator", ttl_seconds=3600, issued_at=_NOW)
        self.assertEqual(
            _code_of(lambda: AT.verify_token(
                step1b, capability="delete_file",
                args={"path": "/tmp/notes.txt", "content": "draft"},
                now=_NOW)),
            "approval-token-capability-mismatch")


class TestApprovalPathIntegration(unittest.TestCase):
    """decide() mints the token; the approved sweep verifies it as an
    additional check; records without a token sweep unchanged."""

    def _run(self):
        import sys
        _td = os.path.dirname(os.path.abspath(__file__))
        for _p in (_td, os.path.dirname(_td)):
            if _p not in sys.path:
                sys.path.insert(0, _p)
        from harness import make_run
        return make_run()

    def _queue_and_approve(self, run, to="teammate@synthetic.local"):
        ident = run["identities"]["support"]
        res = run["executor"].call(
            ident, "send_email", to=to, subject="hello", body="hello")
        self.assertEqual(res["status"], "queued")
        aid = res["approval_id"]
        run["approvals"].decide(aid, True, reason="looks fine",
                                decided_by="human-operator")
        return aid

    def _record(self, run, aid):
        for r in run["approvals"].all():
            if r["id"] == aid:
                return r
        self.fail("approval %r not found" % aid)

    def test_decide_mints_token(self):
        run = self._run()
        aid = self._queue_and_approve(run)
        rec = self._record(run, aid)
        tok = rec.get("approval_token")
        self.assertIsNotNone(tok)
        self.assertEqual(tok["capability"], "send_email")
        self.assertEqual(tok["issuer"], "human-operator")
        self.assertEqual(tok["argument_binding"]["mode"], "exact")
        # The token verifies against the record's own (tool, args).
        body = AT.verify_token(tok, capability=rec["tool"],
                               args=rec["args"])
        self.assertEqual(body["nonce"], tok["nonce"])

    def test_reject_mints_no_token(self):
        run = self._run()
        ident = run["identities"]["support"]
        res = run["executor"].call(
            ident, "send_email", to="x@synthetic.local",
            subject="hello", body="hello")
        aid = res["approval_id"]
        run["approvals"].decide(aid, False, reason="no",
                                decided_by="human-operator")
        rec = self._record(run, aid)
        self.assertIsNone(rec.get("approval_token"))

    def test_sweep_executes_with_valid_token(self):
        run = self._run()
        aid = self._queue_and_approve(run)
        rec = self._record(run, aid)
        nonce = rec["approval_token"]["nonce"]
        done = run["executor"].execute_approved()
        self.assertEqual(len(done), 1)
        # The nonce was consumed on the durable-claim path.
        self.assertTrue(
            run["executor"]._approval_token_store.is_consumed(nonce))

    def test_sweep_refuses_swapped_token(self):
        # The decomposed-reuse shape: a token legitimately minted for a
        # benign action is attached to a record for a harmful variant.
        # The test re-MACs the record with the key (standing in for the
        # record writer); the record MAC verifies, but the token's own
        # capability/argument binding refuses the mismatch. Honest
        # boundary: the token and the record MAC share the log HMAC
        # key, so this seam adds an independent binding check, not
        # key-compromise resistance -- the token's full payoff comes
        # when it travels as a standalone artifact (later steps).
        run = self._run()
        aid = self._queue_and_approve(run)
        from gov.approvals import approval_record_digest
        foreign = AT.issue_token(
            "send_email",
            {"mode": "exact",
             "args": {"to": "other@synthetic.local", "subject": "hello",
                      "body": "hello"}},
            issuer="human-operator", ttl_seconds=3600)
        run["approvals"]._rewrite(lambda records: [
            dict(r, approval_token=foreign,
                 args_digest=approval_record_digest(
                     dict(r, approval_token=foreign)))
            if r["id"] == aid else r for r in records])
        done = run["executor"].execute_approved()
        self.assertEqual(done, [])
        rec = self._record(run, aid)
        self.assertIn("approval token",
                      rec.get("execution_refused_reason") or "")
        # The audit trail carries the coded refusal in the code field.
        from gov.log import read_entries
        _log_path = getattr(run["log"], "path", None) or os.path.join(
            run["run_dir"], "actions.jsonl")
        codes = [e.get("code") for e in read_entries(_log_path)
                 if e.get("event") == "approval_execution_refused"
                 and e.get("approval_id") == aid]
        self.assertIn("approval-token-argument-mismatch", codes)

    def test_sweep_without_token_unchanged(self):
        # Backward compatibility: a record carrying no token (any path
        # that did not mint one) sweeps exactly as before.
        run = self._run()
        aid = self._queue_and_approve(run)
        run["approvals"]._rewrite(lambda records: [
            dict(r, approval_token=None) if r["id"] == aid else r
            for r in records])
        # Re-MAC without the token field so the record stays valid:
        # the field binds as None, exactly like a pre-wave-313 record
        # would under the new payload... (pre-wave-313 records fail
        # the fail-closed upgrade instead; here we re-MAC honestly.)
        from gov.approvals import approval_record_digest
        run["approvals"]._rewrite(lambda records: [
            dict(r, args_digest=approval_record_digest(r))
            if r["id"] == aid else r for r in records])
        done = run["executor"].execute_approved()
        self.assertEqual(len(done), 1)


if __name__ == "__main__":
    unittest.main()
