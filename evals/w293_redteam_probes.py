"""Wave-293 independent red-team battery (Lane 4): attack the wave-292 merge.

Base: wave-292 merge commit 36176e57508aa24c23159e3e6ff44d842b74ed5a
(verified via git rev-parse HEAD after clone; ls-remote agrees).
gov/ is byte-identical (attack only, no product code).

Attack surface (all wave-292 additions and residual seams):
  (a) gov/revocation_status.py -- enforcement seam: can a retired/
      revoked credential be accepted by any path that does not call
      enforce_revocation? (only if a path silently passes instead of
      refusing coded -- documented issuance-only paths are attacked
      but not filed); status-envelope forgery; countersigning-key
      confusion (credential key vs status key); unknown rid
      ("unknown is never active" consistency); rotate ceremony:
      rotate-without-successor, double-rotate, revoke-then-rotate,
      duplicate/new-rid-equals-old-rid; the opt-in BuilderPolicy
      demand wiring in evidence_provenance (gate coverage vs policy
      demand).
  (b) gov/issuance_monitor.py -- log poisoning: crafted entries that
      might crash the monitor uncoded (F351-class sweep of the parse
      paths); signed report forgery; rid-collision false positives
      (same rid / same issuer / same holder re-issued -- does the
      monitor cry wolf?); inclusive window edges.
  (c) gov/delegation_chain.py decay -- ttl manipulation at issue vs a
      hand-crafted lying body that never went through delegate();
      succession forgery; lineage overflow (is the 1024 refusal really
      fail-closed?); RECENT_PREV tolerate-once (can the tolerance be
      triggered twice?); stale lineage; orphaned branch; per-hop
      decay; pre-decay records; invocation (PoP) with a retired leaf.
  (d) F356-F360 closures, re-pinned (0 BREAK expected) plus seam-edge
      attacks: execute_rebuild validation/execution URI mismatch (can
      check_rebuild_recipe see different material URIs than the
      execution uses?); seal_provenance adjacent claim sub-objects
      (the F357 non-dict class on artifact/timestamp_authority);
      check_rebuild_recipe material_uris forms (generator/dict);
      digest_of on any JSON-serializable value.

Re-pins at the public seams:
  F311-F359 (CLOSED) -- 0 BREAK expected (w291_redteam, w290_redteam,
      w290_rebuild, w291_delegation, w292_f356, w292_sweep,
      w292_revocation, w292_delegation_decay subprocesses).
  F360 (CLOSED by wave-293 lane 1) -- 0 BREAK expected (w292_redteam:
      ob-pubkey-hex-uncoded, ob-manifest-enveloped-uncoded,
      ob-ledger-line-uncoded, ob-manifest-json-uncoded).

New finding filed from F364 with severity label and falsifiable
close-when criteria.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g293-redteam && TMPDIR=/var/tmp/g293-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w293_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g293-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w293_redteam_probes.py
"""

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-292 merge: pin 1715 -> 1723 (+4 revocation-* +4 delegation-*).
TAXONOMY_PIN = 1933 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
        return
    if not any(p == pid or p.startswith(pid + "-")
               for p, _, _ in _results):
        _record(pid, "ERROR", "probe recorded nothing")


def _literals():
    # Wave-260 lesson: assert on source literals in decision_codes.py,
    # not len(TAXONOMY) (dict dedup hides duplicate inserts).
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
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
    _record("pin-taxonomy", "HELD", "1916/1916/0 sorted")


def _seed():
    return secrets.token_bytes(32)


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


# ---------------------------------------------------------------------------
# (a) Revocation enforcement seams.
# ---------------------------------------------------------------------------

def _registry_with_two():
    from gov import revocation_status as rs
    reg = rs.RevocationRegistry("reg-293", _seed())
    hpub = _pub(_seed())
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.issue("cred-002", hpub, 1000, 2000)
    return reg, hpub


def p_rvc_enforce_retired_reuse():
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    reg.rotate("cred-001", "cred-003", hpub, 1600, 2600)
    st = reg.check_status("cred-001", 1700)
    try:
        rs.enforce_revocation(st, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-retired-reuse":
            return _record("rvc-enforce-retired-reuse", "HELD",
                           "retired reuse refuses LOUD coded")
        return _record("rvc-enforce-retired-reuse", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-enforce-retired-reuse", "BREAK",
            "retired rid passed enforcement")


def p_rvc_enforce_revoked():
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    reg.revoke("cred-001", "key compromise")
    st = reg.check_status("cred-001", 1700)
    try:
        rs.enforce_revocation(st, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-revoked":
            return _record("rvc-enforce-revoked", "HELD",
                           "revoked refuses LOUD coded")
        return _record("rvc-enforce-revoked", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-enforce-revoked", "BREAK", "revoked rid passed")


def p_rvc_unknown_rid_never_active():
    from gov import revocation_status as rs
    reg, _ = _registry_with_two()
    try:
        reg.check_status("ghost-rid", 1500)
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rvc-unknown-rid-never-active", "HELD",
                           "unknown rid refuses coded, never active")
        return _record("rvc-unknown-rid-never-active", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-unknown-rid-never-active", "BREAK",
            "unknown rid got a status")


def p_rvc_verify_credential_issuance_only():
    # Documented: verify_credential checks ISSUANCE ONLY, never
    # revocation. Attacked, not filed -- a revoked rid's credential
    # still verifies as *issued*, which is the documented split.
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    cred_env = None
    # Re-issue under a fresh registry handle to grab the envelope.
    reg2 = rs.RevocationRegistry("reg-doc", _seed())
    env = reg2.issue("doc-1", hpub, 1000, 2000)
    reg2.revoke("doc-1", "testing the split")
    cred = rs.verify_credential(env, reg2.registry_pubkey_hex())
    if cred["rid"] == "doc-1":
        _record("rvc-verify-credential-issuance-only", "HELD",
                "verify_credential is issuance-only by documented "
                "design; revocation lives in enforce_revocation")
    else:
        _record("rvc-verify-credential-issuance-only", "BREAK",
                "issuance verify returned the wrong credential")


def p_rvc_status_forgery():
    from gov import revocation_status as rs
    reg, _ = _registry_with_two()
    st = reg.check_status("cred-001", 1500)
    forged = {"status": dict(st["status"], state="revoked"),
              "signature": st["signature"], "keyid": st["keyid"]}
    try:
        rs.verify_status_response(forged, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            pass
        else:
            return _record("rvc-status-forgery", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("rvc-status-forgery", "BREAK",
                       "forged state verified")
    forged2 = {"status": dict(st["status"], checked_at=9999999999),
               "signature": st["signature"], "keyid": st["keyid"]}
    try:
        rs.verify_status_response(forged2, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rvc-status-forgery", "HELD",
                           "state/checked_at forgery refuses coded")
        return _record("rvc-status-forgery", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-status-forgery", "BREAK", "forged checked_at verified")


def p_rvc_key_confusion():
    # A credential envelope presented as a status envelope and vice
    # versa must both refuse coded -- the countersigning key and the
    # credential key must not be confusable.
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    cred_env = reg.issue("cred-003", hpub, 1000, 2000)
    st = reg.check_status("cred-001", 1500)
    try:
        rs.verify_status_response(cred_env, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code != "revocation-status-unverifiable":
            return _record("rvc-key-confusion", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("rvc-key-confusion", "BREAK",
                       "credential passed as status")
    try:
        rs.verify_credential(st, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code != "revocation-status-unverifiable":
            return _record("rvc-key-confusion", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("rvc-key-confusion", "BREAK",
                       "status passed as credential")
    _record("rvc-key-confusion", "HELD",
            "cross-envelope confusion refuses coded both ways")


def p_rvc_rotate_retired_refuses():
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    reg.rotate("cred-001", "cred-003", hpub, 1600, 2600)
    try:
        reg.rotate("cred-001", "cred-004", hpub, 1700, 2700)
    except rs.RevocationError as e:
        if e.code == "revocation-refused":
            return _record("rvc-rotate-retired-refuses", "HELD",
                           "re-rotating a retired rid refuses coded")
        return _record("rvc-rotate-retired-refuses", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-rotate-retired-refuses", "BREAK",
            "retired rid rotated twice")


def p_rvc_rotate_unknown_refuses():
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    try:
        reg.rotate("ghost-rid", "cred-009", hpub, 1600, 2600)
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rvc-rotate-unknown-refuses", "HELD",
                           "rotating an unknown rid refuses coded")
        return _record("rvc-rotate-unknown-refuses", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-rotate-unknown-refuses", "BREAK",
            "unknown rid rotated")


def p_rvc_revoke_then_rotate_refuses():
    from gov import revocation_status as rs
    reg, hpub = _registry_with_two()
    reg.revoke("cred-001", "compromise")
    try:
        reg.rotate("cred-001", "cred-010", hpub, 1600, 2600)
    except rs.RevocationError as e:
        if e.code == "revocation-refused":
            return _record("rvc-revoke-then-rotate-refuses", "HELD",
                           "rotating a revoked rid refuses coded")
        return _record("rvc-revoke-then-rotate-refuses", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-revoke-then-rotate-refuses", "BREAK",
            "revoked rid rotated")


def p_rvc_double_revoke_idempotent():
    from gov import revocation_status as rs
    reg, _ = _registry_with_two()
    reg.revoke("cred-001", "first")
    if reg.revoke("cred-001", "second") is True:
        st = reg.check_status("cred-001", 1700)
        if st["status"]["revoke_reason"] == "first":
            return _record("rvc-double-revoke-idempotent", "HELD",
                           "revoke is idempotent; first record kept")
    _record("rvc-double-revoke-idempotent", "BREAK",
            "double revoke not idempotent")


def p_rvc_gate_rid_mismatch():
    from gov import revocation_status as rs
    reg, _ = _registry_with_two()
    gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
    st2 = reg.check_status("cred-002", 1500)
    try:
        gate.gate("cred-001", st2)
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rvc-gate-rid-mismatch", "HELD",
                           "status for the wrong rid refuses coded")
        return _record("rvc-gate-rid-mismatch", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-gate-rid-mismatch", "BREAK",
            "wrong-rid status passed the gate")


def _provenance_envelope(revocation_required=()):
    from gov import evidence_provenance as ep
    bseed = _seed()
    bpub = _pub(bseed)
    policy = ep.BuilderPolicy("auditor-pin-1", {"builder-1": bpub},
                              revocation_required=revocation_required)
    claim = ep.make_provenance_claim(
        "builder-1", "key-1", "ab" * 32,
        [{"uri": "src/a", "digest": "cd" * 32,
          "completeness": "verified"}],
        issued_at=1700000000)
    return ep.seal_provenance(claim, bseed), policy


def p_rvc_provenance_demand_coverage_gap():
    # F364: the policy demands ("cred-001", "cred-002") but the gate
    # only covers ("cred-001",). verify_provenance returns True --
    # the demand for cred-002 is silently dropped instead of refusing
    # coded "revocation-status-unverifiable".
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, _ = _registry_with_two()
    gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    st1 = reg.check_status("cred-001", 1500)
    try:
        ok = ep.verify_provenance(env, policy, revocation_gate=gate,
                                  revocation_statuses=[st1])
    except (rs.RevocationError, ep.ProvenanceError):
        return _record("rvc-provenance-demand-coverage-gap", "HELD",
                       "under-covering gate refuses coded")
    if ok is True:
        return _record("rvc-provenance-demand-coverage-gap", "BREAK",
                       "F364: demand for cred-002 silently dropped; "
                       "gate coverage is not bound to the policy demand")
    _record("rvc-provenance-demand-coverage-gap", "BREAK",
            "unexpected non-True return: %r" % (ok,))


def p_rvc_provenance_demand_no_gate():
    from gov import revocation_status as rs, evidence_provenance as ep
    env, policy = _provenance_envelope(
        revocation_required=("cred-001",))
    try:
        ep.verify_provenance(env, policy)
    except (rs.RevocationError, ep.ProvenanceError) as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rvc-provenance-demand-no-gate", "HELD",
                           "demand without gate fails closed coded")
        return _record("rvc-provenance-demand-no-gate", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rvc-provenance-demand-no-gate", "BREAK",
            "demand without gate passed")


def p_rvc_provenance_optin_retired():
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, hpub = _registry_with_two()
    gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001",))
    st_active = reg.check_status("cred-001", 1500)
    if ep.verify_provenance(env, policy, revocation_gate=gate,
                            revocation_statuses=[st_active]) is not True:
        return _record("rvc-provenance-optin-retired", "BREAK",
                       "active status should pass")
    reg.rotate("cred-001", "cred-003", hpub, 1600, 2600)
    st_retired = reg.check_status("cred-001", 1700)
    try:
        ep.verify_provenance(env, policy, revocation_gate=gate,
                             revocation_statuses=[st_retired])
    except rs.RevocationError as e:
        if e.code == "revocation-retired-reuse":
            return _record("rvc-provenance-optin-retired", "HELD",
                           "opt-in: active passes, retired refuses coded")
        return _record("rvc-provenance-optin-retired", "BREAK",
                       "wrong code: %s" % e.code)
    except ep.ProvenanceError as e:
        return _record("rvc-provenance-optin-retired", "BREAK",
                       "uncoded provenance error: %s" % e.code)
    _record("rvc-provenance-optin-retired", "BREAK",
            "retired rid passed opt-in verification")

# ---------------------------------------------------------------------------
# (b) Issuance monitor seams.
# ---------------------------------------------------------------------------

def _monitor_policy():
    from gov import issuance_monitor as im
    return im.MonitorPolicy("pol-1", {"k1": _pub(_seed())}, (1000, 2000))


def p_mon_crafted_entries_no_crash():
    # F351-class sweep of the monitor's parse paths: hostile entries
    # must become entry-malformed findings, never uncoded escapes.
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    hostile = [
        None, "x", 123, ["rid"],
        {"rid": b"bytes-rid", "issuer_keyid": "k1",
         "holder_pubkey": "ab" * 32, "issued_at": 1500},
        {"rid": "ok1", "issuer_keyid": "k1",
         "holder_pubkey": 12345, "issued_at": 1500},
        {"rid": "ok2", "issuer_keyid": "k1",
         "holder_pubkey": "ab" * 32, "issued_at": True},
        {"rid": "ok3", "issuer_keyid": "k1",
         "holder_pubkey": "zz", "issued_at": 1500},
        {"rid": {"nested": 1}, "issuer_keyid": "k1",
         "holder_pubkey": "ab" * 32, "issued_at": 1500},
        {"rid": "ok4", "issuer_keyid": ["k1"],
         "holder_pubkey": "ab" * 32, "issued_at": 1500},
        {},
    ]
    try:
        env = im.scan_issuance_log(hostile, policy, _seed(), 1600)
    except im.MonitorError as e:
        return _record("mon-crafted-entries-no-crash", "HELD",
                       "hostile log refuses coded: %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return _record("mon-crafted-entries-no-crash", "BREAK",
                       "uncoded escape on hostile log: %r" % (e,))
    kinds = {f["kind"] for f in env["report"]["findings"]}
    if kinds == {"entry-malformed"} and \
            env["report"]["entry_count"] == len(hostile):
        return _record("mon-crafted-entries-no-crash", "HELD",
                       "11 hostile entries -> 11 entry-malformed "
                       "findings, no crash")
    _record("mon-crafted-entries-no-crash", "BREAK",
            "unexpected finding kinds: %s" % sorted(kinds))


def p_mon_entries_not_list():
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    try:
        im.scan_issuance_log("not-a-list", policy, _seed(), 1600)
    except im.MonitorError as e:
        if e.code == "issuance-monitor-misissuance":
            return _record("mon-entries-not-list", "HELD",
                           "non-list log refuses coded")
        return _record("mon-entries-not-list", "BREAK",
                       "wrong code: %s" % e.code)
    _record("mon-entries-not-list", "BREAK", "non-list log scanned")


def p_mon_report_forgery():
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    hpub = _pub(_seed())
    seed = _seed()
    env = im.scan_issuance_log(
        [{"rid": "e1", "issuer_keyid": "k1", "holder_pubkey": hpub,
          "issued_at": 1500}], policy, seed, 1600)
    forged = {"report": dict(env["report"],
                             findings=[{"kind": "rid-collision",
                                        "rid": "e1",
                                        "detail": "planted"}]),
              "signature": env["signature"], "keyid": env["keyid"]}
    try:
        im.verify_monitor_report(forged, _pub(seed))
    except im.MonitorError as e:
        if e.code != "issuance-monitor-misissuance":
            return _record("mon-report-forgery", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("mon-report-forgery", "BREAK",
                       "tampered report verified")
    badsig = dict(env, signature="00" * 64)
    try:
        im.verify_monitor_report(badsig, _pub(seed))
    except im.MonitorError as e:
        if e.code == "issuance-monitor-misissuance":
            return _record("mon-report-forgery", "HELD",
                           "tampered findings / bad signature refuse "
                           "coded")
        return _record("mon-report-forgery", "BREAK",
                       "wrong code: %s" % e.code)
    _record("mon-report-forgery", "BREAK", "bad signature verified")


def p_mon_refuse_unverified():
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    hpub = _pub(_seed())
    seed = _seed()
    env = im.scan_issuance_log(
        [{"rid": "e1", "issuer_keyid": "evil", "holder_pubkey": hpub,
          "issued_at": 1500}], policy, seed, 1600)
    report = im.verify_monitor_report(env, _pub(seed))
    try:
        im.refuse_on_misissuance(report)
    except im.MonitorError as e:
        if e.code != "issuance-monitor-misissuance":
            return _record("mon-refuse-unverified", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("mon-refuse-unverified", "BREAK",
                       "dirty report passed the gate")
    clean = im.scan_issuance_log(
        [{"rid": "e1", "issuer_keyid": "k1", "holder_pubkey": hpub,
          "issued_at": 1500}], policy, seed, 1600)
    clean_report = im.verify_monitor_report(clean, _pub(seed))
    if im.refuse_on_misissuance(clean_report) is True:
        return _record("mon-refuse-unverified", "HELD",
                       "dirty refuses coded, clean passes")
    _record("mon-refuse-unverified", "BREAK", "clean report refused")


def p_mon_dup_identical_flagged():
    # Cry-wolf check: the registry never re-issues an rid, so an
    # identical duplicate in the log IS suspicious. Attacked, not
    # filed -- flagged by documented design.
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    hpub = _pub(_seed())
    entry = {"rid": "dup1", "issuer_keyid": "k1", "holder_pubkey": hpub,
             "issued_at": 1500}
    env = im.scan_issuance_log([entry, dict(entry)], policy,
                               _seed(), 1600)
    kinds = [f["kind"] for f in env["report"]["findings"]]
    if "rid-collision" in kinds:
        return _record("mon-dup-identical-flagged", "HELD",
                       "identical re-issuance flagged rid-collision "
                       "by design (registry never re-issues)")
    _record("mon-dup-identical-flagged", "BREAK",
            "identical duplicate not flagged: %s" % kinds)


def p_mon_window_edges():
    from gov import issuance_monitor as im
    policy = _monitor_policy()
    hpub = _pub(_seed())
    def entry(rid, at):
        return {"rid": rid, "issuer_keyid": "k1", "holder_pubkey": hpub,
                "issued_at": at}
    env = im.scan_issuance_log(
        [entry("w999", 999), entry("w1000", 1000), entry("w2000", 2000),
         entry("w2001", 2001)], policy, _seed(), 1600)
    flagged = {f["rid"] for f in env["report"]["findings"]
               if f["kind"] == "outside-issuance-window"}
    if flagged == {"w999", "w2001"}:
        return _record("mon-window-edges", "HELD",
                       "inclusive window edges pinned: 999/2001 "
                       "flagged, 1000/2000 clean")
    _record("mon-window-edges", "BREAK",
            "window edge behavior wrong: %s" % sorted(flagged))


# ---------------------------------------------------------------------------
# (c) Delegation decay seams.
# ---------------------------------------------------------------------------

_NOW = 1700000000
_CAPS = [{"with": "db", "can": ["read"]}]


def _dlg_chain():
    from gov import delegation_chain as dc
    rs_, ms, ls, hs = _seed(), _seed(), _seed(), _seed()
    root = dc.delegate(rs_, None, {
        "audience": _pub(ms), "capabilities": _CAPS,
        "not_before": _NOW - 100, "not_after": _NOW + 3600,
        "ttl": 3700, "issued_at": _NOW - 100, "nonce": "n0"})
    mid = dc.delegate(ms, _CAPS, {
        "audience": _pub(ls), "capabilities": _CAPS,
        "not_before": _NOW - 100, "not_after": _NOW + 3600,
        "ttl": 3700, "issued_at": _NOW - 100, "nonce": "n1",
        "parent": root})
    leaf = dc.delegate(ls, _CAPS, {
        "audience": _pub(hs), "capabilities": _CAPS,
        "not_before": _NOW - 100, "not_after": _NOW + 3600,
        "ttl": 3700, "issued_at": _NOW - 100, "nonce": "n2",
        "parent": mid})
    return dc, rs_, ms, ls, hs, root, mid, leaf


def _action():
    return {"with": "db", "can": "read"}


def p_dlg_lying_ttl_handcrafted():
    # A hand-crafted body that never went through delegate(): lying
    # ttl values must refuse coded at _seal_body, not slip through.
    from gov import delegation_chain as dc
    from gov import ed25519 as _ed
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    base = dict(leaf["delegation"])
    cases = [
        ("ttl-zero", dict(base, ttl_seconds=0,
                          not_after=base["issued_at"])),
        ("ttl-negative", dict(base, ttl_seconds=-5,
                              not_after=base["issued_at"] - 5)),
        ("ttl-huge", dict(base, ttl_seconds=2 ** 41,
                          not_after=base["issued_at"] + 2 ** 41)),
        ("notafter-mismatch", dict(base, ttl_seconds=3700,
                                   not_after=base["issued_at"] + 100)),
    ]
    for label, body in cases:
        sig = _ed.sign(ls, dc.SIGN_DOMAIN + dc._canonical(body)).hex()
        sealed = {"delegation": body, "signature": sig}
        v = dc.DelegationVerifier([_pub(rs_)])
        try:
            v.verify([root, mid, sealed], _action(), now=_NOW)
        except dc.DelegationError as e:
            if e.code is None:
                return _record("dlg-lying-ttl-handcrafted", "BREAK",
                               "%s: uncoded escape" % label)
            continue
        return _record("dlg-lying-ttl-handcrafted", "BREAK",
                       "%s: lying ttl verified" % label)
    _record("dlg-lying-ttl-handcrafted", "HELD",
            "lying ttl / not_after mismatch refuse coded at the seam")


def p_dlg_succession_forgery():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    req = {"ttl": 3700, "not_before": _NOW - 100,
           "not_after": _NOW + 3600, "issued_at": _NOW - 100,
           "succession_nonce": "s-forged"}
    succ, succession = dc.rotate(ls, mid, leaf, dict(req))
    # (a) succession record signed by the WRONG key.
    wrong = _seed()
    forged_body = dict(succession["delegation"])
    forged_sig = __import__("gov.ed25519",
                            fromlist=["sign"]).sign(
        wrong, dc.SUCCESSION_DOMAIN +
        dc._canonical(forged_body)).hex()
    try:
        v.register_succession(leaf, succ,
                              {"delegation": forged_body,
                               "signature": forged_sig})
    except dc.DelegationError as e:
        if e.code is None:
            return _record("dlg-succession-forgery", "BREAK",
                           "wrong-key succession: uncoded escape")
    else:
        return _record("dlg-succession-forgery", "BREAK",
                       "wrong-key succession registered")
    # (b) valid delegator signature but tampered retired_digest.
    tampered = dict(succession["delegation"],
                    retired_digest="ff" * 32)
    tampered_sig = __import__("gov.ed25519",
                              fromlist=["sign"]).sign(
        ls, dc.SUCCESSION_DOMAIN +
        dc._canonical(tampered)).hex()
    try:
        v.register_succession(leaf, succ,
                              {"delegation": tampered,
                               "signature": tampered_sig})
    except dc.DelegationError as e:
        if e.code is None:
            return _record("dlg-succession-forgery", "BREAK",
                           "tampered succession: uncoded escape")
        return _record("dlg-succession-forgery", "HELD",
                       "wrong-key and tampered successions refuse coded")
    _record("dlg-succession-forgery", "BREAK",
            "tampered retired_digest registered")


def p_dlg_lineage_overflow_failclosed():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    cur = leaf
    for i in range(1024):
        succ, succession = dc.rotate(
            ls, mid, cur,
            {"ttl": 3700, "not_before": _NOW - 100,
             "not_after": _NOW + 3600, "issued_at": _NOW - 100,
             "succession_nonce": "s%04d" % i})
        v.register_succession(cur, succ, succession)
        cur = succ
    succ, succession = dc.rotate(
        ls, mid, cur,
        {"ttl": 3700, "not_before": _NOW - 100,
         "not_after": _NOW + 3600, "issued_at": _NOW - 100,
         "succession_nonce": "s-overflow"})
    try:
        v.register_succession(cur, succ, succession)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-lineage-overflow":
            return _record("dlg-lineage-overflow-failclosed", "HELD",
                           "1025th succession refuses coded; lineage "
                           "never evicted")
        return _record("dlg-lineage-overflow-failclosed", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-lineage-overflow-failclosed", "BREAK",
            "overflow succession registered (lineage evicted?)")


def _rotate_and_register(dc, v, ls, mid, leaf, tag):
    succ, succession = dc.rotate(
        ls, mid, leaf,
        {"ttl": 3700, "not_before": _NOW - 100,
         "not_after": _NOW + 3600, "issued_at": _NOW - 100,
         "succession_nonce": tag})
    v.register_succession(leaf, succ, succession)
    return succ


def p_dlg_recent_prev_once():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    _rotate_and_register(dc, v, ls, mid, leaf, "s-prev")
    # First presentation of the retired leaf: tolerated once (declared
    # in the receipt, never silent).
    try:
        v.verify([root, mid, leaf], _action(), now=_NOW)
    except dc.DelegationError as e:
        return _record("dlg-recent-prev-once", "BREAK",
                       "first retired-leaf presentation refused: %s"
                       % getattr(e, "code", None))
    # Second presentation (different action, so the replay mark is not
    # the refusal): the tolerance must NOT fire twice.
    try:
        v.verify([root, mid, leaf], {"with": "db", "can": "write"},
                 now=_NOW)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-retired-reuse":
            return _record("dlg-recent-prev-once", "HELD",
                           "RECENT_PREV tolerated once, then refuses "
                           "coded revocation event")
        return _record("dlg-recent-prev-once", "BREAK",
                       "wrong code on second presentation: %s"
                       % getattr(e, "code", None))
    _record("dlg-recent-prev-once", "BREAK",
            "tolerance fired twice (no revocation event)")


def p_dlg_stale_lineage():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    s1 = _rotate_and_register(dc, v, ls, mid, leaf, "s1")
    _rotate_and_register(dc, v, ls, mid, s1, "s2")
    try:
        v.verify([root, mid, leaf], _action(), now=_NOW)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-stale-lineage":
            return _record("dlg-stale-lineage", "HELD",
                           "superseded generation refuses coded")
        return _record("dlg-stale-lineage", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-stale-lineage", "BREAK", "stale lineage verified")


def p_dlg_orphaned_branch():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    _rotate_and_register(dc, v, ls, mid, leaf, "s-orphan")
    # A fork minted by the leaf's HOLDER (its audience) under the RETIRED
    # leaf after the succession: an orphaned branch.
    fork = dc.delegate(hs, _CAPS, {
        "audience": _pub(_seed()), "capabilities": _CAPS,
        "not_before": _NOW - 100, "not_after": _NOW + 3600,
        "ttl": 3700, "issued_at": _NOW - 100, "nonce": "fork1",
        "parent": leaf})
    try:
        v.verify([root, mid, leaf, fork], _action(), now=_NOW)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-orphaned-branch":
            return _record("dlg-orphaned-branch", "HELD",
                           "fork under a retired leaf refuses coded")
        return _record("dlg-orphaned-branch", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-orphaned-branch", "BREAK", "orphaned branch verified")


def p_dlg_expired_hop():
    from gov import delegation_chain as dc
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    try:
        v.verify([root, mid, leaf], _action(), now=_NOW + 7200)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-expired":
            return _record("dlg-expired-hop", "HELD",
                           "post-ttl presentation refuses coded")
        return _record("dlg-expired-hop", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-expired-hop", "BREAK", "expired chain verified")


def p_dlg_predecay_refused():
    # A pre-decay record (no issued_at/ttl_seconds/generation) is
    # treated as expired and refused fail-closed -- never
    # grandfathered.
    from gov import delegation_chain as dc
    from gov import ed25519 as _ed
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    body = dict(leaf["delegation"])
    for k in ("issued_at", "ttl_seconds", "generation"):
        body.pop(k, None)
    sig = _ed.sign(ls, dc.SIGN_DOMAIN + dc._canonical(body)).hex()
    sealed = {"delegation": body, "signature": sig}
    v = dc.DelegationVerifier([_pub(rs_)])
    try:
        v.verify([root, mid, sealed], _action(), now=_NOW)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-expired":
            return _record("dlg-predecay-refused", "HELD",
                           "pre-decay record refused fail-closed coded")
        return _record("dlg-predecay-refused", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-predecay-refused", "BREAK", "pre-decay record verified")


def p_dlg_invocation_retired_refused():
    # Proof-of-possession invocation with a retired leaf: the PoP is
    # valid, but the lineage check must still fire the revocation
    # event (second presentation; the first is tolerated once).
    from gov import delegation_chain as dc
    from gov import ed25519 as _ed
    _, rs_, ms, ls, hs, root, mid, leaf = _dlg_chain()
    v = dc.DelegationVerifier([_pub(rs_)])
    _rotate_and_register(dc, v, ls, mid, leaf, "s-pop")
    invoker = _pub(hs)
    leaf_digest = dc.digest_of(leaf["delegation"])
    challenge = b"fresh-challenge-293"
    pop_sig = _ed.sign(hs, v._pop_signing_bytes(
        invoker, challenge, leaf_digest)).hex()
    try:
        v.verify_invocation([root, mid, leaf], _action(),
                            invoker_pubkey_hex=invoker,
                            pop_challenge=challenge,
                            pop_signature_hex=pop_sig, now=_NOW)
    except dc.DelegationError as e:
        return _record("dlg-invocation-retired-refused", "BREAK",
                       "first PoP presentation refused: %s"
                       % getattr(e, "code", None))
    challenge2 = b"fresh-challenge-293-b"
    pop_sig2 = _ed.sign(hs, v._pop_signing_bytes(
        invoker, challenge2, leaf_digest)).hex()
    try:
        v.verify_invocation([root, mid, leaf], _action(),
                            invoker_pubkey_hex=invoker,
                            pop_challenge=challenge2,
                            pop_signature_hex=pop_sig2, now=_NOW)
    except dc.DelegationError as e:
        if getattr(e, "code", None) == "delegation-retired-reuse":
            return _record("dlg-invocation-retired-refused", "HELD",
                           "PoP with retired leaf: tolerated once, "
                           "then coded revocation event")
        return _record("dlg-invocation-retired-refused", "BREAK",
                       "wrong code: %s" % getattr(e, "code", None))
    _record("dlg-invocation-retired-refused", "BREAK",
            "PoP replay with retired leaf never fired the lineage")

# ---------------------------------------------------------------------------
# (d) Closure seam edges (F356-F360).
# ---------------------------------------------------------------------------

def _valid_recipe():
    return {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["src/a"],
        "steps": [{"op": "concat", "order": ["src/a"]},
                  {"op": "sha256"}],
    }


def p_f356_validate_exec_same_uris():
    # F356 edge: execute_rebuild validates with check_rebuild_recipe
    # over set(material_bytes) (or set() for non-dict) and then
    # executes over the same mapping -- is there a
    # validation/execution URI mismatch path?
    from gov import evidence_provenance as ep
    recipe = _valid_recipe()
    # (a) non-dict materials: validation sees set() -> inputs not in
    # known -> coded; execution would also refuse coded.
    try:
        ep.execute_rebuild(recipe, ["src/a"])
    except ep.ProvenanceError as e:
        if e.code is None:
            return _record("f356-validate-exec-same-uris", "BREAK",
                           "non-dict materials: uncoded escape")
    else:
        return _record("f356-validate-exec-same-uris", "BREAK",
                       "non-dict materials executed")
    # (b) matching URIs: executes and returns the 32-byte digest.
    out = ep.execute_rebuild(recipe, {"src/a": b"data"})
    import hashlib
    if out != hashlib.sha256(b"data").digest():
        return _record("f356-validate-exec-same-uris", "BREAK",
                       "valid rebuild derived the wrong digest")
    # (c) materials dict missing a declared input: coded, not KeyError.
    try:
        ep.execute_rebuild(recipe, {"other": b"data"})
    except ep.ProvenanceError as e:
        if e.code == "provenance-rebuild-invalid":
            return _record("f356-validate-exec-same-uris", "HELD",
                           "validation and execution see the same URI "
                           "set; every mismatch refuses coded")
        return _record("f356-validate-exec-same-uris", "BREAK",
                       "wrong code: %s" % e.code)
    _record("f356-validate-exec-same-uris", "BREAK",
            "missing material executed")


def p_f357_seal_adjacent_objects():
    # F357 fixed the non-dict builder crash at seal. Adjacent
    # sub-objects (artifact, timestamp_authority): seal_provenance
    # does not touch them -- the seal-vs-verify discipline says the
    # VERIFIER names the malformation. Attacked, not filed.
    from gov import evidence_provenance as ep
    bseed = _seed()
    claim = ep.make_provenance_claim(
        "builder-1", "key-1", "ab" * 32,
        [{"uri": "src/a", "digest": "cd" * 32,
          "completeness": "verified"}],
        issued_at=1700000000)
    bad = dict(claim, artifact="not-a-dict")
    try:
        env = ep.seal_provenance(bad, bseed)
    except Exception as e:  # noqa: BLE001
        return _record("f357-seal-adjacent-objects", "BREAK",
                       "seal raised on non-dict artifact: %r" % (e,))
    bpub = _pub(bseed)
    policy = ep.BuilderPolicy("pin-1", {"builder-1": bpub})
    try:
        ep.verify_provenance(env, policy)
    except ep.ProvenanceError as e:
        if e.code == "provenance-envelope-malformed":
            return _record("f357-seal-adjacent-objects", "HELD",
                           "seal does not validate everything; the "
                           "verifier refuses coded (seal-vs-verify "
                           "discipline holds)")
        return _record("f357-seal-adjacent-objects", "BREAK",
                       "wrong code: %s" % e.code)
    _record("f357-seal-adjacent-objects", "BREAK",
            "malformed claim verified")


def p_f358_material_uris_forms():
    # F358: material_uris must be a sequence of URI strings.
    from gov import evidence_provenance as ep
    recipe = _valid_recipe()
    for label, uris in (("generator", (u for u in ["src/a"])),
                        ("dict", {"src/a": 1}),
                        ("non-str-entry", [123])):
        try:
            ep.check_rebuild_recipe(recipe, uris)
        except ep.ProvenanceError as e:
            if e.code != "provenance-rebuild-invalid":
                return _record("f358-material-uris-forms", "BREAK",
                               "%s: wrong code %s" % (label, e.code))
            continue
        return _record("f358-material-uris-forms", "BREAK",
                       "%s: bad material_uris accepted" % label)
    _record("f358-material-uris-forms", "HELD",
            "generator/dict/non-str material_uris refuse coded")


def p_f359_digest_any_json():
    # F359: digest_of refuses non-JSON-serializable bodies coded.
    # Any JSON-serializable value digests by design -- attacked, not
    # filed.
    from gov import delegation_chain as dc
    d1 = dc.digest_of("a string")
    d2 = dc.digest_of({"a": 1})
    if len(d1) == 64 and len(d2) == 64 and d1 != d2:
        return _record("f359-digest-any-json", "HELD",
                       "digest_of handles any JSON-serializable value "
                       "by design")
    _record("f359-digest-any-json", "BREAK", "digest_of misbehaved")


# ---------------------------------------------------------------------------
# Re-pins (subprocess; depth-1 green)
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w293-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("repin-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("repin-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("repin-" + label, "BREAK",
                "%s: %d BREAK, expected %d" % (rel, nbreak,
                                              expected_breaks))


def p_repins():
    before = len(_results)
    _run_battery("evals/w292_redteam_probes.py", 0, "w292")  # wave-293 merge: F360 closed
    _run_battery("evals/w292_f356_probes.py", 0, "w292-f356")
    _run_battery("evals/w292_sweep_probes.py", 0, "w292-sweep")
    _run_battery("evals/w292_revocation_probes.py", 0, "w292-revocation")
    _run_battery("evals/w292_delegation_decay_probes.py", 0,
                 "w292-decay")
    _run_battery("evals/w291_redteam_probes.py", 0, "w291")
    _run_battery("evals/w290_redteam_probes.py", 0, "w290")
    _run_battery("evals/w290_rebuild_probes.py", 0, "w290-rebuild")
    _run_battery("evals/w291_delegation_probes.py", 0, "w291-delegation")
    seg = _results[before:]
    bad = [p for p, v, _ in seg if v != "HELD"]
    if bad:
        _record("repin-all", "BREAK",
                "re-pin failures: %s" % ", ".join(bad))
    else:
        _record("repin-all", "HELD",
                "9/9 prior batteries at expected BREAK counts")


def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w292_revocation_probes.py",
                "evals/w292_delegation_decay_probes.py"):
        _run_battery(rel, 0, "green-" + os.path.basename(rel)[:-3])


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    # (a) revocation
    _safe("rvc-enforce-retired-reuse", p_rvc_enforce_retired_reuse)
    _safe("rvc-enforce-revoked", p_rvc_enforce_revoked)
    _safe("rvc-unknown-rid-never-active", p_rvc_unknown_rid_never_active)
    _safe("rvc-verify-credential-issuance-only",
          p_rvc_verify_credential_issuance_only)
    _safe("rvc-status-forgery", p_rvc_status_forgery)
    _safe("rvc-key-confusion", p_rvc_key_confusion)
    _safe("rvc-rotate-retired-refuses", p_rvc_rotate_retired_refuses)
    _safe("rvc-rotate-unknown-refuses", p_rvc_rotate_unknown_refuses)
    _safe("rvc-revoke-then-rotate-refuses",
          p_rvc_revoke_then_rotate_refuses)
    _safe("rvc-double-revoke-idempotent", p_rvc_double_revoke_idempotent)
    _safe("rvc-gate-rid-mismatch", p_rvc_gate_rid_mismatch)
    _safe("rvc-provenance-demand-coverage-gap",
          p_rvc_provenance_demand_coverage_gap)
    _safe("rvc-provenance-demand-no-gate", p_rvc_provenance_demand_no_gate)
    _safe("rvc-provenance-optin-retired", p_rvc_provenance_optin_retired)
    # (b) issuance monitor
    _safe("mon-crafted-entries-no-crash", p_mon_crafted_entries_no_crash)
    _safe("mon-entries-not-list", p_mon_entries_not_list)
    _safe("mon-report-forgery", p_mon_report_forgery)
    _safe("mon-refuse-unverified", p_mon_refuse_unverified)
    _safe("mon-dup-identical-flagged", p_mon_dup_identical_flagged)
    _safe("mon-window-edges", p_mon_window_edges)
    # (c) delegation decay
    _safe("dlg-lying-ttl-handcrafted", p_dlg_lying_ttl_handcrafted)
    _safe("dlg-succession-forgery", p_dlg_succession_forgery)
    _safe("dlg-lineage-overflow-failclosed",
          p_dlg_lineage_overflow_failclosed)
    _safe("dlg-recent-prev-once", p_dlg_recent_prev_once)
    _safe("dlg-stale-lineage", p_dlg_stale_lineage)
    _safe("dlg-orphaned-branch", p_dlg_orphaned_branch)
    _safe("dlg-expired-hop", p_dlg_expired_hop)
    _safe("dlg-predecay-refused", p_dlg_predecay_refused)
    _safe("dlg-invocation-retired-refused",
          p_dlg_invocation_retired_refused)
    # (d) closure seam edges
    _safe("f356-validate-exec-same-uris", p_f356_validate_exec_same_uris)
    _safe("f357-seal-adjacent-objects", p_f357_seal_adjacent_objects)
    _safe("f358-material-uris-forms", p_f358_material_uris_forms)
    _safe("f359-digest-any-json", p_f359_digest_any_json)
    # re-pins + green checks
    _safe("repin-all", p_repins)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w293_redteam: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
