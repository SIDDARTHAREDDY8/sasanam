"""Wave-244 agent-trusts-config -> privileged-action probes (red-first).

W244-4 (threat model): the CVE-2026-18252 shape -- an agent that ingests
user-controlled configuration must never convert a config's privilege
claim into authority. Configuration the agent observes is untrusted
input; only a deployment-pinned authority source can grant.

  role-declaration-refused -- config declares role=developer/admin,
      agent acting on it -> config-authority-claim-refused.
  allowlisted-ci-path-refused -- config sets an allowlisted CI command
      path with no pinned grant -> config-authority-claim-refused.
  confirmed-pinned-grant-allowed -- config claim whose action IS in
      the pinned authority -> allow (not every config is hostile).
  provenance-anchor-vs-upload -- same privilege claim from the
      deployment trust anchor -> allow; from a user-controlled upload
      -> config-authority-claim-refused (provenance is
      deployment-vouched, never agent-asserted).
  self-asserted-provenance-refused -- config with
      provenance {"trusted": true} self-asserted and unvouched ->
      config-provenance-agent-asserted.
  missing-provenance-refused -- privilege claims with no provenance
      block at all -> config-provenance-untrusted.
  midrun-rewrite-refused-and-audited -- mid-run rewrite adding a
      privilege -> config-rewritten-privilege AND a hash-chained
      audit entry exists.
  config-quote-self-attestation-refused -- agent basis citing only
      "config:..." -> config-authority-claim-refused; config never
      self-attests into authority.
  malformed-input-fails-closed -- non-dict records, malformed grants,
      bool minted_at -> config-record-malformed.
  lapsed-grant-citation -- grant citing a lapse-registered authority
      post-lapse -> stale-authority via gov.stale_authority FIRST.
  pinned-basis-allowed -- agent basis backed by a matching pinned
      grant -> allow.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_CT = False
try:
    from gov import config_trust as _ct
    HAVE_CT = all(hasattr(_ct, n) for n in (
        "pin_authority_source", "classify_provenance",
        "check_privilege_claim", "check_agent_basis",
        "ConfigMonitor", "ConfigTrustError"))
except ImportError:
    _ct = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "role-declaration-refused",
    "allowlisted-ci-path-refused",
    "confirmed-pinned-grant-allowed",
    "provenance-anchor-vs-upload",
    "self-asserted-provenance-refused",
    "missing-provenance-refused",
    "midrun-rewrite-refused-and-audited",
    "config-quote-self-attestation-refused",
    "malformed-input-fails-closed",
    "lapsed-grant-citation",
    "pinned-basis-allowed",
]


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _pinned(grants=None):
    grants = grants if grants is not None else [
        {"action": "ci:exec"},
        {"action": "deploy:staging"},
    ]
    return _ct.pin_authority_source(
        {"verifier_policy_input": "pin:test-v1", "grants": grants})


def _upload_map():
    return {
        "deployment-anchor": "deployment-pinned",
        "user-upload": "agent-observed",
    }


def _record(settings, provenance):
    return {"settings": settings, "provenance": provenance}


def _expect_refusal(fn, code):
    try:
        fn()
    except _ct.ConfigTrustError as exc:
        assert exc.code == code, "want %s, got %s" % (code, exc.code)
        return exc
    raise AssertionError("expected refusal %s, got allow" % (code,))


def _probe_role_declaration_refused():
    pinned = _pinned()
    rec = _record({"role": "admin"},
                  {"source_id": "user-upload"})
    _expect_refusal(
        lambda: _ct.check_privilege_claim(rec, pinned, _upload_map()),
        "config-authority-claim-refused")
    return "config role=admin without a pinned grant is refused"


def _probe_allowlisted_ci_path_refused():
    pinned = _pinned(grants=[{"action": "deploy:staging"}])
    rec = _record({"allowlisted_commands": ["/usr/bin/ci-run"]},
                  {"source_id": "user-upload"})
    _expect_refusal(
        lambda: _ct.check_privilege_claim(rec, pinned, _upload_map()),
        "config-authority-claim-refused")
    return "allowlisted CI command path still needs the pinned authority"


def _probe_confirmed_pinned_grant_allowed():
    pinned = _pinned()
    rec = _record({"grants": ["ci:exec"]},
                  {"source_id": "user-upload"})
    verdict = _ct.check_privilege_claim(rec, pinned, _upload_map())
    assert verdict["decision"] == "allow", verdict
    assert verdict["verifier_policy_input"] == "pin:test-v1", verdict
    return "config claim with a confirmed pinned grant is allowed"


def _probe_provenance_anchor_vs_upload():
    pinned = _pinned()
    claim = {"role": "developer"}
    anchor = _record(claim, {"source_id": "deployment-anchor"})
    upload = _record(dict(claim), {"source_id": "user-upload"})
    anchored = _ct.check_privilege_claim(anchor, pinned, _upload_map())
    assert anchored["decision"] == "allow", anchored
    assert anchored["provenance"] == "deployment-pinned", anchored
    _expect_refusal(
        lambda: _ct.check_privilege_claim(upload, pinned,
                                          _upload_map()),
        "config-authority-claim-refused")
    return "anchor-vouched provenance allows; unvouched upload refuses"


def _probe_self_asserted_provenance_refused():
    pinned = _pinned()
    rec = _record({"role": "developer"},
                  {"source_id": "user-upload", "trusted": True})
    _expect_refusal(
        lambda: _ct.check_privilege_claim(rec, pinned, _upload_map()),
        "config-provenance-agent-asserted")
    return "self-declared provenance trust is never accepted"


def _probe_missing_provenance_refused():
    pinned = _pinned()
    rec = {"settings": {"role": "developer"}}
    _expect_refusal(
        lambda: _ct.check_privilege_claim(rec, pinned, _upload_map()),
        "config-provenance-untrusted")
    return "privilege claims with no provenance block fail closed"


def _probe_midrun_rewrite_refused_and_audited():
    pinned = _pinned()
    monitor = _ct.ConfigMonitor(_upload_map(), pinned)
    rec = _record({"grants": ["deploy:staging"]},
                  {"source_id": "user-upload"})
    first = monitor.observe(rec)
    assert first["event"] == "first-observed", first
    rewritten = _record({"grants": ["deploy:staging", "ci:exec"]},
                        {"source_id": "user-upload"})
    _expect_refusal(lambda: monitor.observe(rewritten),
                    "config-rewritten-privilege")
    entries = [e for e in monitor.audit_log
               if e["event"] == "rewrite-adds-privileges"]
    assert len(entries) == 1, monitor.audit_log
    assert entries[0]["added"] == ["ci:exec"], entries[0]
    # The rewrite is audit-logged even though the privileged action
    # fails closed: evidence AND refusal, not one or the other.
    return "rewrite refused and the audit journal records it"


def _probe_config_quote_self_attestation_refused():
    pinned = _pinned()
    _expect_refusal(
        lambda: _ct.check_agent_basis(
            {"claim": "ci:exec", "basis_source": "config:team-repo"},
            pinned),
        "config-authority-claim-refused")
    return "an agent quoting config back is never self-attesting"


def _probe_malformed_input_fails_closed():
    pinned = _pinned()
    _expect_refusal(lambda: _ct.pin_authority_source("nope"),
                    "config-record-malformed")
    _expect_refusal(lambda: _ct.check_privilege_claim(
        ["nope"], pinned, _upload_map()),
        "config-record-malformed")
    _expect_refusal(lambda: _ct.pin_authority_source(
        {"verifier_policy_input": "pin:x",
         "grants": [{"action": "ci:exec", "authority_id": "a",
                     "authority_minted_at": True}]}),
        "config-record-malformed")
    _expect_refusal(lambda: _ct.check_agent_basis({}, pinned),
                    "config-record-malformed")
    return "non-dict records, bad grants, bool minted_at fail closed"


def _probe_lapsed_grant_citation():
    minted = datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp()
    pinned = _pinned(grants=[{
        "action": "ci:exec",
        "authority_id": "draft-emirdag-scitt-ai-agent-execution-00",
        "authority_minted_at": minted}])
    rec = _record({"grants": ["ci:exec"]},
                  {"source_id": "user-upload"})
    _expect_refusal(
        lambda: _ct.check_privilege_claim(rec, pinned, _upload_map()),
        "stale-authority")
    return "lapse-registered grant citations route to stale_authority first"


def _probe_pinned_basis_allowed():
    pinned = _pinned()
    verdict = _ct.check_agent_basis(
        {"claim": "ci:exec",
         "basis_source": "deployment-pinned-authority"}, pinned)
    assert verdict["decision"] == "allow", verdict
    return "a basis backed by a pinned grant is allowed"


_PROBES = {
    "role-declaration-refused": (_probe_role_declaration_refused, HAVE_CT),
    "allowlisted-ci-path-refused": (_probe_allowlisted_ci_path_refused,
                                    HAVE_CT),
    "confirmed-pinned-grant-allowed": (_probe_confirmed_pinned_grant_allowed,
                                      HAVE_CT),
    "provenance-anchor-vs-upload": (_probe_provenance_anchor_vs_upload,
                                    HAVE_CT),
    "self-asserted-provenance-refused":
        (_probe_self_asserted_provenance_refused, HAVE_CT),
    "missing-provenance-refused": (_probe_missing_provenance_refused,
                                  HAVE_CT),
    "midrun-rewrite-refused-and-audited":
        (_probe_midrun_rewrite_refused_and_audited, HAVE_CT),
    "config-quote-self-attestation-refused":
        (_probe_config_quote_self_attestation_refused, HAVE_CT),
    "malformed-input-fails-closed": (_probe_malformed_input_fails_closed,
                                    HAVE_CT),
    "lapsed-grant-citation": (_probe_lapsed_grant_citation, HAVE_CT),
    "pinned-basis-allowed": (_probe_pinned_basis_allowed, HAVE_CT),
}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1 (never spawns another battery's main).
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_config_trust",
         "-v"],
        cwd=root, env=env, capture_output=True, text=True, timeout=300)
    notes.append("unit tests.test_config_trust rc=%d" % (proc.returncode,))
    if proc.returncode != 0:
        notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-244 config-trust probes (module: %s)" % (HAVE_CT,))
    results = []
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        results.append((name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
