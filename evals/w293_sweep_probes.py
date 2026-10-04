"""Wave-293 sweep battery (Lane 6): uncoded-exception sweep of the newest modules.

Target: the F351 class (every public-seam refusal must carry a coded
decision code) on code that has not had a full sweep yet:

  (a) gov/revocation_status.py  (wave-292: RevocationRegistry,
      verify_credential, verify_status_response, enforce_revocation,
      RevocationGate);
  (b) gov/issuance_monitor.py   (wave-292: MonitorPolicy,
      scan_issuance_log, verify_monitor_report, refuse_on_misissuance);
  (c) gov/delegation_chain.py   decay additions (wave-292: _check_ttl,
      _check_issued_at, _check_generation, delegate ttl contract,
      rotate, register_succession, per-hop decay, theft lineage)
      plus digest_of (F359 fixed TypeError only -- ValueError untested).

Method: feed every public seam malformed inputs (wrong types, missing
keys, circular structures, mixed-type keys) and record any escape that
is NOT a coded decision code (bare KeyError/ValueError/TypeError/...,
code=None). Findings filed from F361, one per DISTINCT defect site.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g293-sweep && TMPDIR=/var/tmp/g293-sweep \\
    ~/workspace/.gov-venv/bin/python evals/w293_sweep_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g293-sweep2 \\
    ~/workspace/.gov-venv/bin/python evals/w293_sweep_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import time
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

# Wave-292 merge: pin 1715 -> 1723 (+8 revocation/delegation codes).
# This lane mints no new codes (all escapes map to existing ones).
TAXONOMY_PIN = 2012 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



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
    _record("pin-taxonomy", "HELD", "2012/2012/0 sorted")




# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _registry():
    from gov import revocation_status as rs
    from gov import ed25519
    seed = ed25519.generate_seed()
    reg = rs.RevocationRegistry("reg-test-1", seed)
    pub = reg.registry_pubkey_hex()
    return rs, reg, pub


def _credential_envelope(reg, rid="cred-1"):
    return reg.issue(rid, "ab" * 32, 1700000000, 1700003600,
                     capabilities=["read"])


def _status_envelope(reg, rid="cred-1", checked_at=1700000001):
    return reg.check_status(rid, checked_at)


def _monitor_parts():
    from gov import issuance_monitor as im
    from gov import ed25519
    mseed = ed25519.generate_seed()
    mpub = ed25519.publickey(mseed).hex()
    policy = im.MonitorPolicy(
        "pol-1", {"k1": "ab" * 32}, (1700000000, 1700003600))
    return im, policy, mseed, mpub


def _delegation_parts():
    from gov import delegation_chain as dc
    from gov import ed25519
    seed = ed25519.generate_seed()
    holder = ed25519.generate_seed()
    holder_pub = ed25519.publickey(holder).hex()
    req = {
        "audience": holder_pub,
        "capabilities": [{"with": "repo", "can": ["read"]}],
        "not_before": 1700000000,
        "issued_at": 1700000000,
        "ttl": 3600,
        "not_after": 1700003600,
        "generation": 0,
        "nonce": "n1",
    }
    return dc, seed, holder_pub, req


# ---------------------------------------------------------------------------
# (a) revocation_status.py -- uncoded-escape probes
# ---------------------------------------------------------------------------

def p_rs_verify_credential_circular():
    """verify_credential canonicalizes the attacker-supplied credential
    dict with json.dumps (no default needed for circularity): a
    circular structure raises bare ValueError (code=None) BEFORE the
    signature is even checked. F351 class."""
    rs, reg, pub = _registry()
    env = _credential_envelope(reg)
    # Positive control: the well-formed credential verifies.
    cred = rs.verify_credential(env, pub)
    assert cred["rid"] == "cred-1"
    bad = {"credential_format": rs.CREDENTIAL_FORMAT, "rid": "cred-1",
           "holder_pubkey": "ab" * 32}
    bad["evil"] = bad  # circular
    try:
        rs.verify_credential({"credential": bad, "signature": "cd" * 64,
                              "keyid": "registry"}, pub)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("rs-verify-credential-circular", "BREAK",
                           "circular credential escapes as %s (code=None)"
                           % type(e).__name__)
    _record("rs-verify-credential-circular", "HELD",
            "circular credential refuses coded")


def p_rs_verify_credential_mixed_keys():
    """Same seam, second facet: mixed-type dict keys make
    json.dumps(sort_keys=True) raise bare TypeError (code=None)."""
    rs, reg, pub = _registry()
    _credential_envelope(reg)
    bad = {"credential_format": rs.CREDENTIAL_FORMAT, "rid": "cred-1",
           "holder_pubkey": "ab" * 32, 1: "x", "a": "y"}
    try:
        rs.verify_credential({"credential": bad, "signature": "cd" * 64,
                              "keyid": "registry"}, pub)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("rs-verify-credential-mixed-keys", "BREAK",
                           "mixed-key credential escapes as %s (code=None)"
                           % type(e).__name__)
    _record("rs-verify-credential-mixed-keys", "HELD",
            "mixed-key credential refuses coded")


def p_rs_verify_status_circular():
    """verify_status_response has the same unguarded _canonical call
    over the attacker-supplied status dict: circular -> bare
    ValueError (code=None)."""
    rs, reg, pub = _registry()
    _credential_envelope(reg)
    env = _status_envelope(reg)
    # Positive control: the well-formed status verifies.
    st = rs.verify_status_response(env, pub)
    assert st["state"] == "active"
    bad = {"response_format": rs.STATUS_FORMAT, "rid": "cred-1",
           "state": "active", "checked_at": 1, "successor": None,
           "revoked_at": None, "revoke_reason": None,
           "registry_digest": "ef" * 32}
    bad["evil"] = bad  # circular
    try:
        rs.verify_status_response({"status": bad, "signature": "cd" * 64,
                                   "keyid": "registry"}, pub)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("rs-verify-status-circular", "BREAK",
                           "circular status escapes as %s (code=None)"
                           % type(e).__name__)
    _record("rs-verify-status-circular", "HELD",
            "circular status refuses coded")


# ---------------------------------------------------------------------------
# (a) revocation_status.py -- held (coded) seams
# ---------------------------------------------------------------------------

def _expect_coded(pid, fn, note):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is not None:
            return _record(pid, "HELD", "%s (code=%s)"
                           % (note, getattr(e, "code")))
        return _record(pid, "BREAK", "%s escapes uncoded: %r"
                       % (note, e))
    _record(pid, "BREAK", "%s did not refuse" % note)


def p_rs_issue_malformed():
    rs, reg, _ = _registry()
    _expect_coded("rs-issue-malformed",
                  lambda: reg.issue("bad rid!!", "ab" * 32,
                                    1700000000, 1700003600),
                  "issue with bad rid refuses coded")


def p_rs_rotate_unknown():
    rs, reg, _ = _registry()
    _expect_coded("rs-rotate-unknown",
                  lambda: reg.rotate("nope", "new-1", "ab" * 32,
                                      1700000000, 1700003600),
                  "rotate of unknown rid refuses coded")


def p_rs_revoke_unknown():
    rs, reg, _ = _registry()
    _expect_coded("rs-revoke-unknown",
                  lambda: reg.revoke("nope", "reason"),
                  "revoke of unknown rid refuses coded")


def p_rs_check_status_unknown():
    rs, reg, _ = _registry()
    _expect_coded("rs-check-status-unknown",
                  lambda: reg.check_status("nope"),
                  "check_status of unknown rid refuses coded")


def p_rs_gate_vacuous():
    rs, _, pub = _registry()
    _expect_coded("rs-gate-vacuous",
                  lambda: rs.RevocationGate(pub, ()),
                  "vacuous gate refuses coded at construction")


def p_rs_enforce_retired():
    """Positive control: retired-reuse is a coded revocation event."""
    rs, reg, pub = _registry()
    _credential_envelope(reg, "cred-1")
    _, retired_env = reg.rotate("cred-1", "cred-2", "ab" * 32,
                                1700000000, 1700003600)
    try:
        rs.enforce_revocation(retired_env, pub)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "revocation-retired-reuse":
            return _record("rs-enforce-retired", "HELD",
                           "retired reuse refuses coded "
                           "revocation-retired-reuse")
        return _record("rs-enforce-retired", "BREAK",
                       "retired reuse escapes uncoded: %r" % (e,))
    _record("rs-enforce-retired", "BREAK", "retired reuse did not refuse")


# ---------------------------------------------------------------------------
# (b) issuance_monitor.py -- uncoded-escape probes
# ---------------------------------------------------------------------------

def p_im_verify_report_circular():
    """verify_monitor_report canonicalizes the attacker-supplied report
    dict: circular -> bare ValueError (code=None). F351 class."""
    im, _, mseed, mpub = _monitor_parts()
    report = im.scan_issuance_log([], im.MonitorPolicy(
        "pol-1", {"k1": "ab" * 32}, (1700000000, 1700003600)),
        mseed, scanned_at=1700000001)
    # Positive control: the well-formed report verifies.
    assert im.verify_monitor_report(report, mpub)["entry_count"] == 0
    bad = {"report_format": im.REPORT_FORMAT, "policy_id": "p",
           "policy_digest": "ef" * 32, "scanned_at": 1,
           "entry_count": 0, "findings": []}
    bad["evil"] = bad  # circular
    try:
        im.verify_monitor_report({"report": bad, "signature": "cd" * 64,
                                  "keyid": "monitor"}, mpub)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("im-verify-report-circular", "BREAK",
                           "circular report escapes as %s (code=None)"
                           % type(e).__name__)
    _record("im-verify-report-circular", "HELD",
            "circular report refuses coded")


# ---------------------------------------------------------------------------
# (b) issuance_monitor.py -- held (coded) seams
# ---------------------------------------------------------------------------

def p_im_scan_malformed_entries():
    """Malformed log entries become findings; the signed report is
    still produced (detection, not refusal)."""
    im, policy, mseed, _ = _monitor_parts()
    entries = [
        {"rid": "r1", "issuer_keyid": "k1",
         "holder_pubkey": "ab" * 32, "issued_at": 1700000001},
        "not-a-dict",
        {"rid": "r1", "issuer_keyid": "kX",
         "holder_pubkey": "ab" * 32, "issued_at": 1700000001},
        {"rid": "r2", "issuer_keyid": "k1",
         "holder_pubkey": "ab" * 32, "issued_at": 1900000000},
    ]
    report = im.scan_issuance_log(entries, policy, mseed,
                                  scanned_at=1700000001)
    kinds = {f["kind"] for f in report["report"]["findings"]}
    want = {"entry-malformed", "unexpected-issuer-key",
            "outside-issuance-window"}
    if want <= kinds:
        _record("im-scan-malformed-entries", "HELD",
                "dirty log -> findings %s, report still signed"
                % sorted(kinds))
    else:
        _record("im-scan-malformed-entries", "BREAK",
                "missing findings: %s" % sorted(want - kinds))


def p_im_scan_nonlist():
    im, policy, mseed, _ = _monitor_parts()
    _expect_coded("im-scan-nonlist",
                  lambda: im.scan_issuance_log({"r": 1}, policy, mseed),
                  "non-list log refuses coded")


def p_im_policy_vacuous():
    from gov import issuance_monitor as im
    _expect_coded("im-policy-vacuous",
                  lambda: im.MonitorPolicy("p", {}, (1, 2)),
                  "vacuous policy refuses coded at construction")


def p_im_refuse_misissuance():
    im, policy, mseed, mpub = _monitor_parts()
    entries = [{"rid": "r1", "issuer_keyid": "kX",
                "holder_pubkey": "ab" * 32, "issued_at": 1700000001}]
    report = im.scan_issuance_log(entries, policy, mseed,
                                  scanned_at=1700000001)
    verified = im.verify_monitor_report(report, mpub)
    try:
        im.refuse_on_misissuance(verified)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "issuance-monitor-misissuance":
            return _record("im-refuse-misissuance", "HELD",
                           "dirty verified report refuses coded")
        return _record("im-refuse-misissuance", "BREAK",
                       "misissuance escapes uncoded: %r" % (e,))
    _record("im-refuse-misissuance", "BREAK",
            "misissuance report did not refuse")


# ---------------------------------------------------------------------------
# (c) delegation_chain.py decay additions
# ---------------------------------------------------------------------------

def p_dc_digest_of_circular():
    """digest_of is a public seam; F359 made it catch TypeError, but a
    circular structure raises ValueError (code=None) from json.dumps.
    The decay additions (rotate/register_succession) call it, so the
    seam is live in the new code paths too."""
    from gov import delegation_chain as dc
    # Positive control: a plain body digests.
    assert dc.digest_of({"a": 1}) == dc.digest_of({"a": 1})
    bad = {}
    bad["self"] = bad  # circular
    try:
        dc.digest_of(bad)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("dc-digest-of-circular", "BREAK",
                           "circular body escapes as %s (code=None)"
                           % type(e).__name__)
    _record("dc-digest-of-circular", "HELD",
            "circular body refuses coded")


def p_dc_delegate_no_ttl():
    from gov import delegation_chain as dc
    _, seed, holder_pub, req = _delegation_parts()
    bad = dict(req)
    del bad["ttl"]
    _expect_coded("dc-delegate-no-ttl",
                  lambda: dc.delegate(seed, None, bad),
                  "missing ttl refuses coded")


def p_dc_delegate_bad_ttl():
    from gov import delegation_chain as dc
    _, seed, _, req = _delegation_parts()
    for bad_ttl in (0, -5, float("nan"), "3600", True):
        bad = dict(req)
        bad["ttl"] = bad_ttl
        try:
            dc.delegate(seed, None, bad)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) is None:
                return _record("dc-delegate-bad-ttl", "BREAK",
                               "ttl=%r escapes uncoded: %r"
                               % (bad_ttl, e))
    _record("dc-delegate-bad-ttl", "HELD",
            "bad ttl values refuse coded")


def p_dc_rotate_widen():
    """Rotation may only narrow: widening refuses coded."""
    from gov import delegation_chain as dc
    _, seed, _, req = _delegation_parts()
    leaf = dc.delegate(seed, None, req)
    wide = dict(req)
    wide["capabilities"] = [{"with": "repo", "can": ["read", "write"]},
                            {"with": "other", "can": ["admin"]}]
    wide["ttl"] = 3600
    wide["not_before"] = 1700000000
    wide["not_after"] = 1700003600
    try:
        dc.rotate(seed, None, leaf, wide)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is not None:
            return _record("dc-rotate-widen", "HELD",
                           "widening rotation refuses coded (%s)"
                           % getattr(e, "code"))
        return _record("dc-rotate-widen", "BREAK",
                       "widening rotation escapes uncoded: %r" % (e,))
    _record("dc-rotate-widen", "BREAK", "widening rotation was issued")


def p_dc_register_succession_malformed():
    from gov import delegation_chain as dc
    _, seed, _, req = _delegation_parts()
    leaf = dc.delegate(seed, None, req)
    v = dc.DelegationVerifier([dc.ed25519.publickey(seed).hex()])
    _expect_coded("dc-register-succession-malformed",
                  lambda: v.register_succession(leaf, leaf,
                                                {"nope": 1}),
                  "malformed succession refuses coded")


def p_dc_verify_expired():
    """Per-hop decay: presenting after issued_at+ttl refuses coded."""
    from gov import delegation_chain as dc
    _, seed, _, req = _delegation_parts()
    leaf = dc.delegate(seed, None, req)
    anchor = dc.ed25519.publickey(seed).hex()
    v = dc.DelegationVerifier([anchor])
    action = {"with": "repo", "can": "read"}
    try:
        v.verify([leaf], action, now=1700003600 + 1)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "delegation-expired":
            return _record("dc-verify-expired", "HELD",
                           "post-ttl presentation refuses coded "
                           "delegation-expired")
        return _record("dc-verify-expired", "BREAK",
                       "post-ttl presentation escapes uncoded: %r" % (e,))
    _record("dc-verify-expired", "BREAK", "post-ttl presentation verified")


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
                "%s: %d BREAK, expected %d"
                % (rel, nbreak, expected_breaks))


def p_repins():
    # F311-F359 CLOSED: 0 BREAK expected.
    _run_battery("evals/w292_revocation_probes.py", 0, "w292-revocation")
    _run_battery("evals/w292_delegation_decay_probes.py", 0,
                 "w292-decay")
    # F360 closed by wave-293 lane 1: 0 BREAK expected on the composed tree.
    _run_battery("evals/w292_redteam_probes.py", 0, "w292-redteam")  # wave-293 merge: F360 closed


def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w291_delegation_probes.py",):
        _run_battery(rel, 0, "green-" + os.path.basename(rel)[:-3])


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    # (a) revocation_status escapes
    _safe("rs-verify-credential-circular", p_rs_verify_credential_circular)
    _safe("rs-verify-credential-mixed-keys", p_rs_verify_credential_mixed_keys)
    _safe("rs-verify-status-circular", p_rs_verify_status_circular)
    # (a) revocation_status held seams
    _safe("rs-issue-malformed", p_rs_issue_malformed)
    _safe("rs-rotate-unknown", p_rs_rotate_unknown)
    _safe("rs-revoke-unknown", p_rs_revoke_unknown)
    _safe("rs-check-status-unknown", p_rs_check_status_unknown)
    _safe("rs-gate-vacuous", p_rs_gate_vacuous)
    _safe("rs-enforce-retired", p_rs_enforce_retired)
    # (b) issuance_monitor escape
    _safe("im-verify-report-circular", p_im_verify_report_circular)
    # (b) issuance_monitor held seams
    _safe("im-scan-malformed-entries", p_im_scan_malformed_entries)
    _safe("im-scan-nonlist", p_im_scan_nonlist)
    _safe("im-policy-vacuous", p_im_policy_vacuous)
    _safe("im-refuse-misissuance", p_im_refuse_misissuance)
    # (c) delegation_chain decay
    _safe("dc-digest-of-circular", p_dc_digest_of_circular)
    _safe("dc-delegate-no-ttl", p_dc_delegate_no_ttl)
    _safe("dc-delegate-bad-ttl", p_dc_delegate_bad_ttl)
    _safe("dc-rotate-widen", p_dc_rotate_widen)
    _safe("dc-register-succession-malformed",
          p_dc_register_succession_malformed)
    _safe("dc-verify-expired", p_dc_verify_expired)
    _safe("repin", p_repins)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w293_sweep: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
