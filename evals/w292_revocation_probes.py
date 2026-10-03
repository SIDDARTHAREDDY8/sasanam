"""Wave-292 lane 2 battery: revocation-status responder + issuance monitor.

Base: wave-291 merge 255478f (verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/revocation_status.py -- signed RevocationRegistry (issue /
      rotate / revoke / check_status), offline-verifiable status
      envelopes, enforce_revocation (retired reuse refuses coded
      revocation-retired-reuse -- a revocation EVENT, not an auth
      failure), RevocationGate for opt-in composition;
  (b) gov/issuance_monitor.py -- stateless DB-less issuance-log scan
      (certspotter pattern), signed monitor reports, verifier-side
      refuse_on_misissuance gate;
  (c) evidence_provenance.py opt-in: BuilderPolicy(revocation_required=())
      + verify_provenance(revocation_gate=..., revocation_statuses=...);
      default posture unchanged.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new modules); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g292-revocation && TMPDIR=/var/tmp/g292-revocation \
    ~/workspace/.gov-venv/bin/python evals/w292_revocation_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g292-revocation2 \
    ~/workspace/.gov-venv/bin/python evals/w292_revocation_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1780  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
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
    _record("pin-taxonomy", "HELD", "1780/1780/0 sorted")


try:
    from gov import revocation_status as rs  # noqa: E402
    from gov import issuance_monitor as im  # noqa: E402
    from gov import evidence_provenance as ep  # noqa: E402
    from gov import ed25519  # noqa: E402
    HAS_REVOCATION = True
except ImportError:
    HAS_REVOCATION = False


def _need(pid):
    """Feature absent on the pristine base -> BREAK (red-first)."""
    if not HAS_REVOCATION:
        _record(pid, "BREAK", "feature absent on base")
        return False
    return True


def _seed():
    return ed25519.generate_seed()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _registry(rid_prefix="cred"):
    reg = rs.RevocationRegistry("reg-test", _seed())
    hseed = _seed()
    hpub = _pub(hseed)
    return reg, hpub


# ---------------------------------------------------------------------------
# Revocation registry probes.
# ---------------------------------------------------------------------------

def p_registry_issue_happy():
    if not _need("rev-issue-happy"):
        return
    reg, hpub = _registry()
    cred = reg.issue("cred-001", hpub, 1000, 2000, ["read"])
    got = rs.verify_credential(cred, reg.registry_pubkey_hex())
    if got["rid"] != "cred-001":
        return _record("rev-issue-happy", "BREAK", "rid mismatch")
    _record("rev-issue-happy", "HELD", "issue + verify happy")


def p_status_active_enforced():
    if not _need("rev-status-active"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    st = reg.check_status("cred-001", 1500)
    # Offline verification: verifier holds only the registry pubkey.
    verified = rs.verify_status_response(st, reg.registry_pubkey_hex())
    if verified["state"] != "active":
        return _record("rev-status-active", "BREAK", "state not active")
    if rs.enforce_revocation(st, reg.registry_pubkey_hex()) is not True:
        return _record("rev-status-active", "BREAK", "enforce not True")
    _record("rev-status-active", "HELD", "signed status verifies offline")


def p_retired_reuse_refused():
    if not _need("rev-retired-reuse"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000, ["read"])
    newcred, oldst = reg.rotate("cred-001", "cred-002", hpub, 1600, 2600,
                                ["read"])
    # Successor must verify as a live credential (overlap: old AND new
    # coexist at issuance; the phased-ceremony rule).
    rs.verify_credential(newcred, reg.registry_pubkey_hex())
    # Presenting the retired predecessor: a REVOCATION EVENT, coded,
    # loud -- never a soft auth failure.
    try:
        rs.enforce_revocation(reg.check_status("cred-001", 1700),
                              reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-retired-reuse":
            return _record("rev-retired-reuse", "HELD",
                           "coded revocation-retired-reuse")
        return _record("rev-retired-reuse", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rev-retired-reuse", "BREAK", "retired reuse not refused")


def p_revoked_refused():
    if not _need("rev-revoked"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.revoke("cred-001", "key-compromise")
    try:
        rs.enforce_revocation(reg.check_status("cred-001", 1500),
                              reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-revoked":
            return _record("rev-revoked", "HELD", "coded revocation-revoked")
        return _record("rev-revoked", "BREAK", "wrong code: %s" % e.code)
    _record("rev-revoked", "BREAK", "revoked rid not refused")


def p_unknown_rid():
    if not _need("rev-unknown-rid"):
        return
    reg, _ = _registry()
    try:
        reg.check_status("never-issued", 1500)
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rev-unknown-rid", "HELD",
                           "unknown rid coded unverifiable")
        return _record("rev-unknown-rid", "BREAK", "wrong code: %s" % e.code)
    _record("rev-unknown-rid", "BREAK", "unknown rid not refused")


def p_status_forgery():
    if not _need("rev-status-forgery"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.revoke("cred-001", "key-compromise")
    st = reg.check_status("cred-001", 1500)
    # Attacker flips the state but cannot re-sign: the signature must
    # fail, coded.
    st2 = {"status": dict(st["status"], state="active"),
           "signature": st["signature"], "keyid": st["keyid"]}
    try:
        rs.verify_status_response(st2, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rev-status-forgery", "HELD",
                           "forged status coded unverifiable")
        return _record("rev-status-forgery", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rev-status-forgery", "BREAK", "forged status verified")


def p_status_nonhex_escape():
    if not _need("rev-status-nonhex"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    st = reg.check_status("cred-001", 1500)
    st2 = {"status": st["status"], "signature": "zz" * 64,
           "keyid": st["keyid"]}
    try:
        rs.verify_status_response(st2, reg.registry_pubkey_hex())
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rev-status-nonhex", "HELD",
                           "non-hex signature coded")
        return _record("rev-status-nonhex", "BREAK",
                       "wrong code: %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return _record("rev-status-nonhex", "BREAK",
                       "uncoded escape: %r" % (e,))
    _record("rev-status-nonhex", "BREAK", "non-hex signature accepted")


def p_gate_require_all():
    if not _need("rev-gate"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.issue("cred-002", hpub, 1000, 2000)
    gate = rs.RevocationGate(reg.registry_pubkey_hex(),
                             ["cred-001", "cred-002"])
    st1 = reg.check_status("cred-001", 1500)
    st2 = reg.check_status("cred-002", 1500)
    if gate.require_all([st1, st2]) is not True:
        return _record("rev-gate", "BREAK", "require_all not True")
    # Missing coverage refuses fail-closed.
    try:
        gate.require_all([st1])
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("rev-gate", "HELD",
                           "happy + missing-coverage fail-closed")
        return _record("rev-gate", "BREAK", "wrong code: %s" % e.code)
    _record("rev-gate", "BREAK", "missing coverage not refused")


def p_duplicate_rid_issue():
    if not _need("rev-duplicate-rid"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    try:
        reg.issue("cred-001", hpub, 1000, 2000)
    except rs.RevocationError as e:
        if e.code == "revocation-entry-unverifiable":
            return _record("rev-duplicate-rid", "HELD",
                           "duplicate rid coded")
        return _record("rev-duplicate-rid", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rev-duplicate-rid", "BREAK", "duplicate rid issued")


def p_rotate_inactive_refused():
    if not _need("rev-rotate-inactive"):
        return
    reg, hpub = _registry()
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
    try:
        reg.rotate("cred-001", "cred-003", hpub, 1700, 2700)
    except rs.RevocationError as e:
        if e.code == "revocation-refused":
            return _record("rev-rotate-inactive", "HELD",
                           "re-rotation of retired rid coded")
        return _record("rev-rotate-inactive", "BREAK",
                       "wrong code: %s" % e.code)
    _record("rev-rotate-inactive", "BREAK", "retired rid re-rotated")


# ---------------------------------------------------------------------------
# Issuance monitor probes.
# ---------------------------------------------------------------------------

def _mpol():
    mseed = _seed()
    ikey = _pub(_seed())
    pol = im.MonitorPolicy("mp-1", {"issuer-a": ikey}, (1000, 2000))
    return pol, mseed, ikey


def _entry(rid, keyid, holder, issued_at):
    return {"rid": rid, "issuer_keyid": keyid,
            "holder_pubkey": holder, "issued_at": issued_at}


def p_monitor_clean():
    if not _need("mon-clean"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    rep = im.scan_issuance_log([_entry("r1", "issuer-a", holder, 1500)],
                               pol, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    vrep = im.verify_monitor_report(rep, mpub)
    if vrep["findings"]:
        return _record("mon-clean", "BREAK", "clean log flagged")
    if im.refuse_on_misissuance(vrep) is not True:
        return _record("mon-clean", "BREAK", "gate not True on clean")
    _record("mon-clean", "HELD", "clean log: signed report, gate True")


def p_monitor_unexpected_issuer():
    if not _need("mon-unexpected-issuer"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    rep = im.scan_issuance_log([_entry("r1", "rogue", holder, 1500)],
                               pol, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    vrep = im.verify_monitor_report(rep, mpub)
    kinds = {f["kind"] for f in vrep["findings"]}
    if "unexpected-issuer-key" not in kinds:
        return _record("mon-unexpected-issuer", "BREAK",
                       "rogue issuer not flagged")
    try:
        im.refuse_on_misissuance(vrep)
    except im.MonitorError as e:
        if e.code == "issuance-monitor-misissuance":
            return _record("mon-unexpected-issuer", "HELD",
                           "rogue issuer refuses coded")
        return _record("mon-unexpected-issuer", "BREAK",
                       "wrong code: %s" % e.code)
    _record("mon-unexpected-issuer", "BREAK", "misissuance not refused")


def p_monitor_rid_collision():
    if not _need("mon-rid-collision"):
        return
    pol, mseed, _ = _mpol()
    rep = im.scan_issuance_log(
        [_entry("r1", "issuer-a", _pub(_seed()), 1500),
         _entry("r1", "issuer-a", _pub(_seed()), 1501)],
        pol, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    vrep = im.verify_monitor_report(rep, mpub)
    kinds = {f["kind"] for f in vrep["findings"]}
    if "rid-collision" not in kinds:
        return _record("mon-rid-collision", "BREAK", "collision not flagged")
    _record("mon-rid-collision", "HELD", "rid collision flagged")


def p_monitor_cross_issuer_duplicate():
    if not _need("mon-cross-issuer"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    # Second issuer keyid is allowlisted too, but the SAME rid under two
    # issuer keys is the cross-key forgery shape.
    ikey2 = _pub(_seed())
    pol2 = im.MonitorPolicy("mp-2",
                            {"issuer-a": pol.allowed_issuer_keys["issuer-a"],
                             "issuer-b": ikey2}, (1000, 2000))
    rep = im.scan_issuance_log(
        [_entry("r1", "issuer-a", holder, 1500),
         _entry("r1", "issuer-b", holder, 1501)],
        pol2, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    vrep = im.verify_monitor_report(rep, mpub)
    kinds = {f["kind"] for f in vrep["findings"]}
    if "duplicate-rid-different-issuer" not in kinds:
        return _record("mon-cross-issuer", "BREAK",
                       "cross-issuer duplicate not flagged")
    _record("mon-cross-issuer", "HELD", "cross-issuer duplicate flagged")


def p_monitor_window_edges():
    if not _need("mon-window-edges"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    # Inclusive boundaries: issuance AT the edge is in-window.
    edge_ok = im.scan_issuance_log(
        [_entry("e1", "issuer-a", holder, 1000),
         _entry("e2", "issuer-a", holder, 2000)], pol, mseed, 2000)
    mpub = ed25519.publickey(mseed).hex()
    if im.verify_monitor_report(edge_ok, mpub)["findings"]:
        return _record("mon-window-edges", "BREAK",
                       "inclusive boundary flagged")
    edge_bad = im.scan_issuance_log(
        [_entry("b1", "issuer-a", holder, 999),
         _entry("b2", "issuer-a", holder, 2001)], pol, mseed, 2001)
    kinds = {f["kind"]
             for f in im.verify_monitor_report(edge_bad, mpub)["findings"]}
    if kinds != {"outside-issuance-window"}:
        return _record("mon-window-edges", "BREAK",
                       "out-of-window evasion: %r" % (kinds,))
    _record("mon-window-edges", "HELD",
            "inclusive edges clean; outside refused")


def p_monitor_report_forgery():
    if not _need("mon-report-forgery"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    rep = im.scan_issuance_log([_entry("r1", "rogue", holder, 1500)],
                               pol, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    # Attacker strips the findings but cannot re-sign.
    rep2 = {"report": dict(rep["report"], findings=[]),
            "signature": rep["signature"], "keyid": rep["keyid"]}
    try:
        im.verify_monitor_report(rep2, mpub)
    except im.MonitorError as e:
        if e.code == "issuance-monitor-misissuance":
            return _record("mon-report-forgery", "HELD",
                           "tampered report coded")
        return _record("mon-report-forgery", "BREAK",
                       "wrong code: %s" % e.code)
    _record("mon-report-forgery", "BREAK", "tampered report verified")


def p_monitor_malformed_entries():
    if not _need("mon-malformed"):
        return
    pol, mseed, _ = _mpol()
    holder = _pub(_seed())
    rep = im.scan_issuance_log(
        ["not-a-dict",
         {"rid": "r1", "issuer_keyid": "issuer-a",
          "holder_pubkey": "zz", "issued_at": 1500},
         _entry("r2", "issuer-a", holder, 1500)],
        pol, mseed, 1600)
    mpub = ed25519.publickey(mseed).hex()
    kinds = {f["kind"]
             for f in im.verify_monitor_report(rep, mpub)["findings"]}
    if "entry-malformed" not in kinds:
        return _record("mon-malformed", "BREAK",
                       "malformed entries not findings")
    if len([f for f in im.verify_monitor_report(rep, mpub)["findings"]
            if f["kind"] == "entry-malformed"]) != 2:
        return _record("mon-malformed", "BREAK", "wrong malformed count")
    _record("mon-malformed", "HELD", "malformed entries become findings")


def p_monitor_nonlist_refused():
    if not _need("mon-nonlist"):
        return
    pol, mseed, _ = _mpol()
    try:
        im.scan_issuance_log("not-a-list", pol, mseed, 1600)
    except im.MonitorError as e:
        if e.code == "issuance-monitor-misissuance":
            return _record("mon-nonlist", "HELD",
                           "non-list log coded")
        return _record("mon-nonlist", "BREAK", "wrong code: %s" % e.code)
    _record("mon-nonlist", "BREAK", "non-list log scanned")


# ---------------------------------------------------------------------------
# Opt-in composition probes (evidence_provenance verify path).
# ---------------------------------------------------------------------------

def _provenance_envelope(revocation_required=()):
    bseed = _seed()
    bpub = _pub(bseed)
    policy = ep.BuilderPolicy("auditor-pin-1", {"builder-1": bpub},
                              revocation_required=revocation_required)
    claim = ep.make_provenance_claim(
        "builder-1", "key-1", "ab" * 32,
        [{"uri": "src/a", "digest": "cd" * 32, "completeness": "verified"}],
        issued_at=1700000000)
    return ep.seal_provenance(claim, bseed), policy


def p_provenance_default_unchanged():
    if not _need("prov-default-unchanged"):
        return
    env, policy = _provenance_envelope()
    # No revocation demand: posture identical to before this lane.
    if ep.verify_provenance(env, policy) is not True:
        return _record("prov-default-unchanged", "BREAK",
                       "default verify changed")
    _record("prov-default-unchanged", "HELD",
            "default admission posture unchanged")


def p_provenance_demand_no_gate():
    if not _need("prov-demand-no-gate"):
        return
    env, policy = _provenance_envelope(revocation_required=["cred-001"])
    try:
        ep.verify_provenance(env, policy)
    except ep.ProvenanceError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("prov-demand-no-gate", "HELD",
                           "demand without gate fails closed coded")
        return _record("prov-demand-no-gate", "BREAK",
                       "wrong code: %s" % e.code)
    _record("prov-demand-no-gate", "BREAK", "demand without gate passed")


def p_provenance_optin_enforced():
    if not _need("prov-optin-enforced"):
        return
    reg = rs.RevocationRegistry("reg-opt", _seed())
    hpub = _pub(_seed())
    reg.issue("cred-001", hpub, 1000, 2000)
    gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
    env, policy = _provenance_envelope(revocation_required=["cred-001"])
    st_active = reg.check_status("cred-001", 1500)
    if ep.verify_provenance(env, policy, revocation_gate=gate,
                            revocation_statuses=[st_active]) is not True:
        return _record("prov-optin-enforced", "BREAK",
                       "active status should pass")
    # Now retire the credential: the same provenance verification must
    # refuse LOUD with the retired-reuse code.
    reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
    st_retired = reg.check_status("cred-001", 1700)
    try:
        ep.verify_provenance(env, policy, revocation_gate=gate,
                             revocation_statuses=[st_retired])
    except rs.RevocationError as e:
        if e.code == "revocation-retired-reuse":
            return _record("prov-optin-enforced", "HELD",
                           "opt-in: active passes, retired refuses coded")
        return _record("prov-optin-enforced", "BREAK",
                       "wrong code: %s" % e.code)
    except ep.ProvenanceError as e:
        return _record("prov-optin-enforced", "BREAK",
                       "uncoded provenance error: %s" % e.code)
    _record("prov-optin-enforced", "BREAK",
            "retired rid passed opt-in verification")


_REPIN_BATTERIES = [
    ("evals/w291_delegation_probes.py", 0, "w291-delegation"),
    ("evals/w290_redteam_probes.py", 0, "w290-redteam"),
    # Wave-292 merge: F356 closed by wave-292 lane 1, so the
    # w291-redteam repin is 0 BREAK on the composed tree.
    ("evals/w291_redteam_probes.py", 0, "w291-redteam"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w292-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=1200,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR",
                    "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Wave-286 lesson: take the LAST "N BREAK" match (the footer),
        # not per-probe notes.
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


_PROBES = [
    p_registry_issue_happy,
    p_status_active_enforced,
    p_retired_reuse_refused,
    p_revoked_refused,
    p_unknown_rid,
    p_status_forgery,
    p_status_nonhex_escape,
    p_gate_require_all,
    p_duplicate_rid_issue,
    p_rotate_inactive_refused,
    p_monitor_clean,
    p_monitor_unexpected_issuer,
    p_monitor_rid_collision,
    p_monitor_cross_issuer_duplicate,
    p_monitor_window_edges,
    p_monitor_report_forgery,
    p_monitor_malformed_entries,
    p_monitor_nonlist_refused,
    p_provenance_default_unchanged,
    p_provenance_demand_no_gate,
    p_provenance_optin_enforced,
]


def main():
    p_taxonomy_pin()
    for probe in _PROBES:
        _safe(probe.__name__, probe)
    if not SKIP_GREEN:
        _run_repins()
    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("=" * 72)
    print("w292_revocation_probes: %d BREAK / %d HELD / %d ERROR"
          % (nb, nh, ne))
    for pid, verdict, note in _results:
        print("  %-36s %-5s %s" % (pid, verdict, note.split("\n")[0]))


if __name__ == "__main__":
    main()
