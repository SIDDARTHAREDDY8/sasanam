"""Wave-285 lane 8 red-first battery: checkov-pattern governed exceptions.

Gap (base 0f13ce1): Sasanam has no governed-exception primitive. Policy
violations have no first-class, justified, scoped, expiring exception
path -- the checkov suppression-with-mandatory-justification shape, the
conftest exception-outcome shape, and wave-283's DefectDojo
`risk_accepted` all converge on the same missing design: exceptions as
data (mandatory justification, approver, bounded expiry, resource scope),
SKIPPED-never-PASSED suppression semantics, a check registry, and a
baseline ratchet. An exception must never be able to close a finding.

Red-first: on base every capability probe BREAKs (gov.governed_exceptions
absent; the taxonomy pin expects the 10 new exception-* codes). After the
build: checks register with ids/severity/rationale; exception declarations
fail closed on unapproved approvers, missing/short justification, and
invalid expiry (no permanent exceptions, bounded max TTL); suppressed
checks report SKIPPED with the exception digest attached, never PASSED;
scope mismatch and expired exceptions refuse LOUD; baseline drift refuses
LOUD; every grant/deny/expire is an audit event carrying the digest; and
exceptions compose with gov/finding_lifecycle.py only as annotations --
the finding state never changes through the exception path.

Pattern lineage: bridgecrewio/checkov (Apache-2.0, verified in the
wave-284 prospectus, child-b-supplychain-identity.md). ADAPT: the
suppression-with-mandatory-justification primitive, the check registry,
and the baseline ratchet as contract shapes, reimplemented in stdlib
Python -- not the tool (IaC-scoped parsers, heavy dependency tree).
$0 spend, stdlib only.
"""

import json
import os
import re
import secrets
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w285-exc")
os.environ.setdefault("TMPDIR", "/var/tmp/g285-exc")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

# Wave-285 lane 8: pin 1621 -> 1632 (+11 exception-* codes; checkov ADAPT).
TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


_RESULTS = []

PLUGIN_META = ("guardrail-evidence", "direct", "held-vs-expected")
PROBE_METADATA = {}

# Fixed clock so every probe is deterministic.
NOW = 1788211200  # 2026-10-02T00:00:00Z


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _literals():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1632/1632/0 sorted")


def _import():
    try:
        from gov import governed_exceptions as ge
        return ge, None
    except Exception as e:  # noqa: BLE001 - module absent on base
        return None, e


def p_module_present():
    ge, err = _import()
    if ge is None:
        return _record("module-present", "BREAK",
                       "gov.governed_exceptions absent: %r" % (err,))
    for name in ("CheckRegistry", "ExceptionStore", "GovernExceptionError",
                 "EXCEPTION_FORMAT", "MAX_EXCEPTION_TTL_SECONDS",
                 "MIN_JUSTIFICATION_CHARS"):
        if not hasattr(ge, name):
            return _record("module-present", "BREAK",
                           "gov.governed_exceptions missing %r" % (name,))
    _record("module-present", "HELD", "contract surface present")


def _store(ge):
    reg = ge.CheckRegistry()
    reg.register("SAS_AUDIT_01", name="audit-chain-intact",
                 category="audit", severity="high",
                 rationale="audit log must be hash-chained",
                 resource_types=["audit-log"])
    st = ge.ExceptionStore(reg)
    st.set_approvers(["sec-lead@example.test"])
    return reg, st


def p_check_registry():
    ge, err = _import()
    if ge is None:
        return _record("check-registry", "BREAK", "module absent")
    try:
        reg = ge.CheckRegistry()
        reg.register("SAS_AUDIT_01", name="audit-chain-intact",
                     category="audit", severity="high",
                     rationale="audit log must be hash-chained",
                     resource_types=["audit-log"])
        if "SAS_AUDIT_01" not in reg:
            return _record("check-registry", "BREAK",
                           "registered check not visible")
        # Duplicate id refuses LOUD.
        try:
            reg.register("SAS_AUDIT_01", name="dup", category="audit",
                         severity="high", rationale="x" * 30,
                         resource_types=["audit-log"])
            return _record("check-registry", "BREAK",
                           "duplicate check id accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-duplicate-check":
                return _record("check-registry", "BREAK",
                               "wrong code for duplicate: %r" % (e.code,))
        # Evaluating an unregistered check refuses LOUD.
        st = ge.ExceptionStore(reg)
        try:
            st.evaluate("SAS_NOPE_99", ("resource", "x"),
                        lambda: True, now=NOW)
            return _record("check-registry", "BREAK",
                           "unknown check evaluated silently")
        except ge.GovernExceptionError as e:
            if e.code != "exception-unknown-check":
                return _record("check-registry", "BREAK",
                               "wrong code for unknown: %r" % (e.code,))
        _record("check-registry", "HELD",
                "register/duplicate/unknown-check all fail closed")
    except Exception as e:  # noqa: BLE001
        _record("check-registry", "ERROR", "%r" % (e,))


def _grant(ge, st, **kw):
    args = dict(check_id="SAS_AUDIT_01", scope=("resource", "audit-log-1"),
                justification="approved temporary waiver for the migration "
                             "window; re-audit on 2026-11-01",
                approver="sec-lead@example.test",
                expiry_ts=NOW + 30 * 86400, created_at=NOW)
    now = kw.pop("now", NOW)
    args.update(kw)
    return st.grant(now=now, **args)


def p_grant_deterministic():
    ge, err = _import()
    if ge is None:
        return _record("grant-deterministic", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        e1 = _grant(ge, st)
        if not e1.digest or len(e1.digest) != 64:
            return _record("grant-deterministic", "BREAK",
                           "digest missing or malformed")
        # Same declaration on a fresh store -> same digest (A==B).
        _, st2 = _store(ge)
        e1b = _grant(ge, st2)
        if e1b.digest != e1.digest:
            return _record("grant-deterministic", "BREAK",
                           "same declaration, different digest")
        # Same semantic declaration at a later created_at must collide:
        # duplicate detection is over semantics, not timestamps.
        _, st3 = _store(ge)
        _grant(ge, st3, created_at=NOW)
        try:
            _grant(ge, st3, created_at=NOW + 1, now=NOW + 2)
            return _record("grant-deterministic", "BREAK",
                           "semantic duplicate accepted (created_at "
                           "in digest)")
        except ge.GovernExceptionError as e:
            if e.code != "exception-duplicate":
                return _record("grant-deterministic", "BREAK",
                               "wrong code for duplicate: %r" % (e.code,))
        _record("grant-deterministic", "HELD",
                "digest deterministic: %s..." % e1.digest[:16])
    except Exception as e:  # noqa: BLE001
        _record("grant-deterministic", "ERROR", "%r" % (e,))


def p_justification_mandatory():
    ge, err = _import()
    if ge is None:
        return _record("justification-mandatory", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        for bad in ("", "too short"):
            try:
                _grant(ge, st, justification=bad)
                return _record("justification-mandatory", "BREAK",
                               "justification %r accepted" % (bad,))
            except ge.GovernExceptionError as e:
                if e.code != "exception-justification-missing":
                    return _record("justification-mandatory", "BREAK",
                                   "wrong code: %r" % (e.code,))
        _record("justification-mandatory", "HELD",
                "missing/short justification refuses LOUD")
    except Exception as e:  # noqa: BLE001
        _record("justification-mandatory", "ERROR", "%r" % (e,))


def p_approver_gate():
    ge, err = _import()
    if ge is None:
        return _record("approver-gate", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        try:
            _grant(ge, st, approver="mallory@example.test")
            return _record("approver-gate", "BREAK",
                           "unapproved approver accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-unapproved-approver":
                return _record("approver-gate", "BREAK",
                               "wrong code: %r" % (e.code,))
        # Unconfigured approver set fails closed (never open by default).
        reg = ge.CheckRegistry()
        reg.register("SAS_AUDIT_01", name="n", category="audit",
                     severity="high", rationale="x" * 30,
                     resource_types=["audit-log"])
        st2 = ge.ExceptionStore(reg)
        try:
            st2.grant(check_id="SAS_AUDIT_01", scope=("resource", "x"),
                      justification="x" * 30, approver="anyone",
                      expiry_ts=NOW + 100, created_at=NOW, now=NOW)
            return _record("approver-gate", "BREAK",
                           "grant with no approvers configured accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-unapproved-approver":
                return _record("approver-gate", "BREAK",
                               "wrong code: %r" % (e.code,))
        _record("approver-gate", "HELD",
                "unapproved approver and unconfigured set fail closed")
    except Exception as e:  # noqa: BLE001
        _record("approver-gate", "ERROR", "%r" % (e,))


def p_expiry_bounds():
    ge, err = _import()
    if ge is None:
        return _record("expiry-bounds", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        # Past expiry refuses.
        try:
            _grant(ge, st, expiry_ts=NOW - 1)
            return _record("expiry-bounds", "BREAK", "past expiry accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-expiry-invalid":
                return _record("expiry-bounds", "BREAK",
                               "wrong code: %r" % (e.code,))
        # Beyond max TTL refuses (no permanent exceptions).
        try:
            _grant(ge, st, expiry_ts=NOW + ge.MAX_EXCEPTION_TTL_SECONDS + 1)
            return _record("expiry-bounds", "BREAK", "over-TTL accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-expiry-invalid":
                return _record("expiry-bounds", "BREAK",
                               "wrong code: %r" % (e.code,))
        # Max TTL exactly is the boundary that holds.
        _grant(ge, st, expiry_ts=NOW + ge.MAX_EXCEPTION_TTL_SECONDS,
               scope=("resource", "audit-log-boundary"))
        _record("expiry-bounds", "HELD",
                "past/over-TTL refuse LOUD; max-TTL boundary holds")
    except Exception as e:  # noqa: BLE001
        _record("expiry-bounds", "ERROR", "%r" % (e,))


def p_skip_never_passed():
    ge, err = _import()
    if ge is None:
        return _record("skip-never-passed", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        exc = _grant(ge, st)
        out = st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                          lambda: True, now=NOW)
        if out["status"] != "SKIPPED":
            return _record("skip-never-passed", "BREAK",
                           "suppressed check status %r, want SKIPPED"
                           % (out["status"],))
        if out.get("exception_digest") != exc.digest:
            return _record("skip-never-passed", "BREAK",
                           "SKIPPED outcome carries no/wrong digest")
        # An unsuppressed check still runs its predicate.
        out2 = st.evaluate("SAS_AUDIT_01", ("resource", "other-log"),
                           lambda: False, now=NOW)
        if out2["status"] != "FAILED":
            return _record("skip-never-passed", "BREAK",
                           "unsuppressed check did not run predicate")
        _record("skip-never-passed", "HELD",
                "suppressed -> SKIPPED+digest; unsuppressed runs")
    except Exception as e:  # noqa: BLE001
        _record("skip-never-passed", "ERROR", "%r" % (e,))


def p_scope_mismatch():
    ge, err = _import()
    if ge is None:
        return _record("scope-mismatch", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        _grant(ge, st)  # scoped to ("resource", "audit-log-1")
        # A direct grant for a different scope is fine, but evaluating
        # the first exception against a foreign scope must refuse LOUD
        # when the caller asks for a scoped check.
        try:
            st.evaluate_scoped("SAS_AUDIT_01", ("resource", "audit-log-1"),
                               ("resource", "other-log"), now=NOW)
            return _record("scope-mismatch", "BREAK",
                           "cross-scope evaluation accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-scope-mismatch":
                return _record("scope-mismatch", "BREAK",
                               "wrong code: %r" % (e.code,))
        _record("scope-mismatch", "HELD",
                "cross-scope evaluation refuses LOUD")
    except Exception as e:  # noqa: BLE001
        _record("scope-mismatch", "ERROR", "%r" % (e,))


def p_expired_use_loud():
    ge, err = _import()
    if ge is None:
        return _record("expired-use-loud", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        exc = _grant(ge, st, expiry_ts=NOW + 100)
        try:
            st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                        lambda: True, now=NOW + 200)
            return _record("expired-use-loud", "BREAK",
                           "expired exception evaluated silently")
        except ge.GovernExceptionError as e:
            if e.code != "exception-expired":
                return _record("expired-use-loud", "BREAK",
                               "wrong code: %r" % (e.code,))
        _record("expired-use-loud", "HELD",
                "expired exception refuses LOUD, never silent")
    except Exception as e:  # noqa: BLE001
        _record("expired-use-loud", "ERROR", "%r" % (e,))


def p_declaration_invalid():
    ge, err = _import()
    if ge is None:
        return _record("declaration-invalid", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        # created_at in the future refuses LOUD.
        try:
            _grant(ge, st, created_at=NOW + 3600)
            return _record("declaration-invalid", "BREAK",
                           "future created_at accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-declaration-invalid":
                return _record("declaration-invalid", "BREAK",
                               "wrong code for created_at: %r" % (e.code,))
        # Empty check category refuses LOUD.
        reg = ge.CheckRegistry()
        try:
            reg.register("SAS_CAT_01", name="cat probe", category="",
                         severity="low", rationale="x" * 30,
                         resource_types=["t"])
            return _record("declaration-invalid", "BREAK",
                           "empty category accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-declaration-invalid":
                return _record("declaration-invalid", "BREAK",
                               "wrong code for category: %r" % (e.code,))
        _record("declaration-invalid", "HELD",
                "future created_at / empty category refuse LOUD")
    except Exception as e:  # noqa: BLE001
        _record("declaration-invalid", "ERROR", "%r" % (e,))


def p_revoke_idempotent():
    ge, err = _import()
    if ge is None:
        return _record("revoke-idempotent", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        exc = _grant(ge, st)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="done", now=NOW)
        st.revoke(exc.digest, approver="sec-lead@example.test",
                  reason="done again", now=NOW + 1)
        revoked_events = [e for e in st.audit_events()
                          if e["event"] == "revoked"]
        if len(revoked_events) != 1:
            return _record("revoke-idempotent", "BREAK",
                           "%d revoked events for one digest"
                           % len(revoked_events))
        _record("revoke-idempotent", "HELD",
                "double revoke: one revoked event, no corruption")
    except Exception as e:  # noqa: BLE001
        _record("revoke-idempotent", "ERROR", "%r" % (e,))


def p_baseline_ratchet():
    ge, err = _import()
    if ge is None:
        return _record("baseline-ratchet", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        _grant(ge, st)
        baseline = st.create_baseline(now=NOW)
        st.check_baseline(baseline, now=NOW)  # no drift: holds
        # New exception beyond baseline refuses LOUD.
        _grant(ge, st, scope=("resource", "audit-log-2"))
        try:
            st.check_baseline(baseline, now=NOW)
            return _record("baseline-ratchet", "BREAK",
                           "drift beyond baseline accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-baseline-drift":
                return _record("baseline-ratchet", "BREAK",
                               "wrong code: %r" % (e.code,))
        # Tampered baseline refuses LOUD.
        tampered = json.loads(json.dumps(baseline))
        tampered["baseline_digest"] = "0" * 64
        try:
            st.check_baseline(tampered, now=NOW)
            return _record("baseline-ratchet", "BREAK",
                           "tampered baseline accepted")
        except ge.GovernExceptionError as e:
            if e.code != "exception-baseline-drift":
                return _record("baseline-ratchet", "BREAK",
                               "wrong code: %r" % (e.code,))
        _record("baseline-ratchet", "HELD",
                "pin holds; drift and tamper refuse LOUD")
    except Exception as e:  # noqa: BLE001
        _record("baseline-ratchet", "ERROR", "%r" % (e,))


def p_baseline_natural_expiry():
    ge, err = _import()
    if ge is None:
        return _record("baseline-natural-expiry", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        _grant(ge, st, expiry_ts=NOW + 100)
        baseline = st.create_baseline(now=NOW)
        # Natural expiry is expected, not drift: re-checking after the
        # bounded TTL ends must still hold.
        if not st.check_baseline(baseline, now=NOW + 200)["baseline_ok"]:
            return _record("baseline-natural-expiry", "BREAK",
                           "natural expiry reported as drift")
        # Early revocation IS drift: the pinned slot was killed early.
        _, st2 = _store(ge)
        exc2 = _grant(ge, st2, expiry_ts=NOW + 100)
        baseline2 = st2.create_baseline(now=NOW)
        st2.revoke(exc2.digest, approver="sec-lead@example.test",
                   reason="early kill", now=NOW + 50)
        try:
            st2.check_baseline(baseline2, now=NOW + 60)
            return _record("baseline-natural-expiry", "BREAK",
                           "early revocation not flagged as drift")
        except ge.GovernExceptionError as e:
            if e.code != "exception-baseline-drift":
                return _record("baseline-natural-expiry", "BREAK",
                               "wrong code: %r" % (e.code,))
        _record("baseline-natural-expiry", "HELD",
                "natural expiry holds; early revocation is drift")
    except Exception as e:  # noqa: BLE001
        _record("baseline-natural-expiry", "ERROR", "%r" % (e,))


def p_finding_composition():
    ge, err = _import()
    if ge is None:
        return _record("finding-composition", "BREAK", "module absent")
    try:
        from gov import finding_lifecycle as fl
        reg = fl.FindingRegistry(next_number=325)
        f_number, _ = reg.file_finding(
            title="exception composition probe (LOW)",
            seam="policy-exception", attack_shape="suppression",
            close_when="finding closes only via its own evidence",
            severity="low", reporter="w285-exc", wave="w285-exc")
        _, st = _store(ge)
        exc = _grant(ge, st, finding_number=f_number)
        # Real composition: the annotation lands ON the finding record
        # (its scan_notes), not just in the store's side index. The
        # state assertion below is non-vacuous because link_finding
        # touches the finding.
        st.link_finding(exc.digest, f_number, registry=reg, now=NOW)
        # The exception path must never change the finding state.
        finding = reg.get(f_number)
        if finding.state != "open":
            return _record("finding-composition", "BREAK",
                           "exception path changed finding state")
        notes = [n for n in finding.scan_notes
                 if n.get("kind") == "exception-suppressed"]
        if not any(n.get("exception_digest") == exc.digest for n in notes):
            return _record("finding-composition", "BREAK",
                           "exception-suppressed annotation missing from "
                           "the finding record")
        # The escape hatch is refused LOUD: exceptions cannot close.
        try:
            st.close_finding_via_exception(exc.digest, f_number,
                                           actor="sec-lead@example.test")
            return _record("finding-composition", "BREAK",
                           "exception closed a finding")
        except ge.GovernExceptionError as e:
            if e.code != "exception-close-refused":
                return _record("finding-composition", "BREAK",
                               "wrong code: %r" % (e.code,))
        if reg.get(f_number).state != "open":
            return _record("finding-composition", "BREAK",
                           "finding state changed after refused close")
        _record("finding-composition", "HELD",
                "annotation recorded; finding stays OPEN; close refused")
    except Exception as e:  # noqa: BLE001
        _record("finding-composition", "ERROR", "%r" % (e,))


def p_audit_events():
    ge, err = _import()
    if ge is None:
        return _record("audit-events", "BREAK", "module absent")
    try:
        _, st = _store(ge)
        exc = _grant(ge, st, expiry_ts=NOW + 100)
        # A denied grant is an audit event too.
        try:
            _grant(ge, st, approver="mallory@example.test")
        except ge.GovernExceptionError:
            pass
        # Natural expiry emits its own "expired" event (never silent).
        swept = st.sweep_expired(now=NOW + 200)
        if swept != [exc.digest]:
            return _record("audit-events", "BREAK",
                           "sweep_expired did not transition the grant")
        # Revoke a second grant; then exercise expired-use on the first.
        exc2 = _grant(ge, st, scope=("resource", "audit-log-9"))
        st.revoke(exc2.digest, approver="sec-lead@example.test",
                  reason="window ended", now=NOW + 50)
        try:
            st.evaluate("SAS_AUDIT_01", ("resource", "audit-log-1"),
                        lambda: True, now=NOW + 60)
        except ge.GovernExceptionError:
            pass
        events = st.audit_events()
        kinds = {e["event"] for e in events}
        for want in ("granted", "denied", "expired", "revoked"):
            if want not in kinds:
                return _record("audit-events", "BREAK",
                               "missing audit event kind %r" % (want,))
        for e in events:
            if not e.get("exception_digest"):
                return _record("audit-events", "BREAK",
                               "audit event missing digest")
        _record("audit-events", "HELD",
                "grant/deny/expire/revoke all audited with digests")
    except Exception as e:  # noqa: BLE001
        _record("audit-events", "ERROR", "%r" % (e,))


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    checks = (["-m", "unittest", "tests.test_decision_codes"],
              ["-m", "unittest", "tests.test_governed_exceptions"])
    for argv in checks:
        r = subprocess.run([sys.executable] + argv,
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout)[-200:].replace("\n", " | ")
        _record("green-check_" + os.path.basename(argv[-1]),
                "HELD" if r.returncode == 0 else "ERROR", tail)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_taxonomy_pin, p_module_present, p_check_registry,
                  p_grant_deterministic, p_justification_mandatory,
                  p_approver_gate, p_expiry_bounds, p_skip_never_passed,
                  p_scope_mismatch, p_expired_use_loud, p_declaration_invalid,
                  p_revoke_idempotent, p_baseline_ratchet,
                  p_baseline_natural_expiry, p_finding_composition,
                  p_audit_events):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w285_exceptions: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
