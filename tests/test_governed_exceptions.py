"""Unit tests for gov.governed_exceptions (wave-285 lane 8, checkov ADAPT).

Deterministic: every test passes an explicit ``now``.
"""

import unittest

from gov import governed_exceptions as ge

NOW = 1788211200  # 2026-10-02T00:00:00Z
JUST = ("temporary waiver for the migration window; re-audit after the "
        "cutover completes")


def _registry():
    reg = ge.CheckRegistry()
    reg.register("SAS_AUDIT_01", name="audit-chain-intact",
                 category="audit", severity="high",
                 rationale="audit log must stay hash-chained",
                 resource_types=["audit-log"])
    return reg


def _store():
    st = ge.ExceptionStore(_registry())
    st.set_approvers(["sec-lead@example.test"])
    return st


def _grant(st, **kw):
    args = dict(check_id="SAS_AUDIT_01", scope=("resource", "audit-log-1"),
                justification=JUST, approver="sec-lead@example.test",
                expiry_ts=NOW + 30 * 86400, created_at=NOW)
    now = kw.pop("now", NOW)
    args.update(kw)
    return st.grant(now=now, **args)


class TestCheckRegistry(unittest.TestCase):
    def test_register_and_lookup(self):
        reg = _registry()
        self.assertIn("SAS_AUDIT_01", reg)
        self.assertEqual(reg.get("SAS_AUDIT_01")["severity"], "high")

    def test_duplicate_id_refuses(self):
        reg = _registry()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            reg.register("SAS_AUDIT_01", name="dup", category="audit",
                         severity="high", rationale="x" * 30,
                         resource_types=["audit-log"])
        self.assertEqual(cm.exception.code, "exception-duplicate-check")

    def test_bad_check_id_refuses(self):
        reg = ge.CheckRegistry()
        with self.assertRaises(ge.GovernExceptionError):
            reg.register("lowercase-bad", name="n", category="c",
                         severity="high", rationale="x" * 30,
                         resource_types=["r"])

    def test_bad_severity_refuses(self):
        reg = ge.CheckRegistry()
        with self.assertRaises(ge.GovernExceptionError):
            reg.register("SAS_X_01", name="n", category="c",
                         severity="extreme", rationale="x" * 30,
                         resource_types=["r"])


class TestGrantValidation(unittest.TestCase):
    def test_grant_ok(self):
        st = _store()
        exc = _grant(st)
        self.assertEqual(len(exc.digest), 64)
        self.assertEqual(exc.status, "live")

    def test_unconfigured_approvers_fail_closed(self):
        st = ge.ExceptionStore(_registry())
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st)
        self.assertEqual(cm.exception.code, "exception-unapproved-approver")

    def test_unknown_check_refuses(self):
        st = _store()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st, check_id="SAS_NOPE_99")
        self.assertEqual(cm.exception.code, "exception-unknown-check")

    def test_duplicate_grant_refuses(self):
        st = _store()
        _grant(st)
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st)
        self.assertEqual(cm.exception.code, "exception-duplicate")

    def test_duplicate_across_created_at_refuses(self):
        # Duplicate detection is over the semantic declaration:
        # created_at is excluded from the digest.
        st = _store()
        _grant(st, created_at=NOW)
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st, created_at=NOW + 1, now=NOW + 2)
        self.assertEqual(cm.exception.code, "exception-duplicate")

    def test_future_created_at_refuses(self):
        st = _store()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st, created_at=NOW + 3600)
        self.assertEqual(cm.exception.code, "exception-declaration-invalid")

    def test_empty_category_refuses(self):
        reg = ge.CheckRegistry()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            reg.register("SAS_CAT_01", name="cat probe", category="",
                         severity="low", rationale="x" * 30,
                         resource_types=["t"])
        self.assertEqual(cm.exception.code, "exception-declaration-invalid")

    def test_malformed_scope_refuses(self):
        st = _store()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            _grant(st, scope=("galaxy", "x"))
        self.assertEqual(cm.exception.code, "exception-scope-mismatch")

    def test_reuse_of_base_exception_expired_code(self):
        # exception-expired predates this lane; the module must reference
        # the base taxonomy code, not a duplicate.
        self.assertEqual(ge.EXPIRED, "exception-expired")


class TestEvaluate(unittest.TestCase):
    def test_suppressed_is_skipped_with_digest(self):
        st = _store()
        exc = _grant(st)
        out = st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                          lambda: True, now=NOW)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertEqual(out["exception_digest"], exc.digest)

    def test_unsuppressed_runs_predicate(self):
        st = _store()
        _grant(st)
        self.assertEqual(
            st.evaluate("SAS_AUDIT_01", ("resource", "other"),
                        lambda: False, now=NOW)["status"], "FAILED")
        self.assertEqual(
            st.evaluate("SAS_AUDIT_01", ("resource", "other"),
                        lambda: True, now=NOW)["status"], "PASSED")

    def test_expired_never_silent(self):
        st = _store()
        _grant(st, expiry_ts=NOW + 10)
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                        lambda: True, now=NOW + 20)
        # Reuses the base taxonomy code with identical refusal semantics.
        self.assertEqual(cm.exception.code, "exception-expired")

    def test_revoked_never_silent(self):
        st = _store()
        exc = _grant(st)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="done", now=NOW + 5)
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                        lambda: True, now=NOW + 6)
        self.assertEqual(cm.exception.code, "exception-expired")

    def test_evaluate_scoped_cross_scope_refuses(self):
        st = _store()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.evaluate_scoped("SAS_AUDIT_01", ("resource", "a"),
                               ("resource", "b"), now=NOW)
        self.assertEqual(cm.exception.code, "exception-scope-mismatch")

    def test_revoke_unknown_digest_refuses(self):
        st = _store()
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.revoke("0" * 64, approver="sec-lead@example.test",
                      reason="x", now=NOW)
        self.assertEqual(cm.exception.code, "exception-unknown-digest")


class TestBaseline(unittest.TestCase):
    def test_pin_and_drift(self):
        st = _store()
        _grant(st)
        baseline = st.create_baseline(now=NOW)
        self.assertTrue(st.check_baseline(baseline, now=NOW)["baseline_ok"])
        _grant(st, scope=("resource", "audit-log-2"))
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.check_baseline(baseline, now=NOW)
        self.assertEqual(cm.exception.code, "exception-baseline-drift")

    def test_sweep_expired_emits_expired_event(self):
        st = _store()
        exc = _grant(st, expiry_ts=NOW + 10)
        swept = st.sweep_expired(now=NOW + 20)
        self.assertEqual(swept, [exc.digest])
        self.assertEqual(exc.status, "expired")
        kinds = {e["event"] for e in st.audit_events()}
        self.assertIn("expired", kinds)

    def test_revoke_idempotent_single_event(self):
        st = _store()
        exc = _grant(st)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="done", now=NOW)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="done again", now=NOW + 1)
        revoked = [e for e in st.audit_events() if e["event"] == "revoked"]
        self.assertEqual(len(revoked), 1)

    def test_natural_expiry_holds_baseline(self):
        st = _store()
        _grant(st, expiry_ts=NOW + 10)
        baseline = st.create_baseline(now=NOW)
        # Natural expiry is expected, not drift.
        self.assertTrue(
            st.check_baseline(baseline, now=NOW + 20)["baseline_ok"])

    def test_early_revocation_is_baseline_drift(self):
        st = _store()
        exc = _grant(st, expiry_ts=NOW + 100)
        baseline = st.create_baseline(now=NOW)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="early", now=NOW + 5)
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.check_baseline(baseline, now=NOW + 6)
        self.assertEqual(cm.exception.code, "exception-baseline-drift")
        import json
        st = _store()
        _grant(st)
        baseline = st.create_baseline(now=NOW)
        tampered = json.loads(json.dumps(baseline))
        tampered["exception_digests"] = []
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.check_baseline(tampered, now=NOW)
        self.assertEqual(cm.exception.code, "exception-baseline-drift")


class TestFindingComposition(unittest.TestCase):
    def test_exception_cannot_close_finding(self):
        from gov import finding_lifecycle as fl
        reg = fl.FindingRegistry(next_number=325)
        f_number, _ = reg.file_finding(
            title="unit probe", seam="policy-exception",
            attack_shape="suppression",
            close_when="only via its own evidence", severity="low",
            reporter="w285-exc", wave="w285-exc")
        st = _store()
        exc = _grant(st, finding_number=f_number)
        # The annotation lands ON the finding record (its scan_notes);
        # the state assertion below is non-vacuous because link_finding
        # touches the finding.
        st.link_finding(exc.digest, f_number, registry=reg, now=NOW)
        self.assertIn(exc.digest, st.finding_annotations(f_number))
        finding = reg.get(f_number)
        notes = [n for n in finding.scan_notes
                 if n.get("kind") == "exception-suppressed"]
        self.assertTrue(
            any(n.get("exception_digest") == exc.digest for n in notes))
        self.assertEqual(finding.state, "open")
        with self.assertRaises(ge.GovernExceptionError) as cm:
            st.close_finding_via_exception(exc.digest, f_number,
                                           actor="sec-lead@example.test")
        self.assertEqual(cm.exception.code, "exception-close-refused")
        self.assertEqual(reg.get(f_number).state, "open")


class TestAudit(unittest.TestCase):
    def test_grant_deny_expire_revoke_audited(self):
        st = _store()
        exc = _grant(st, expiry_ts=NOW + 10)
        try:
            _grant(st, approver="mallory@example.test")
        except ge.GovernExceptionError:
            pass
        st.sweep_expired(now=NOW + 20)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="window ended", now=NOW + 21)
        kinds = {e["event"] for e in st.audit_events()}
        self.assertTrue({"granted", "denied", "expired", "revoked"} <= kinds)
        for e in st.audit_events():
            self.assertTrue(e["exception_digest"])

    def test_emit_sink_opt_in(self):
        seen = []
        unreg = ge.set_emit(seen.append)
        try:
            st = _store()
            _grant(st)
            self.assertTrue(any(e["event"] == "granted" for e in seen))
        finally:
            unreg()


if __name__ == "__main__":
    unittest.main()
