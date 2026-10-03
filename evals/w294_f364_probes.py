"""Wave-294 Lane 1 red-first battery: close F364 (LOW, OPEN).

F364: ``gov/evidence_provenance.py::verify_provenance`` enforces the
opt-in revocation demand via ``revocation_gate.require_all(...)``, but the
gate's ``required_rids`` were never bound to the policy's
``revocation_required``: a gate covering fewer rids than demanded silently
passes. Close-when: (1) ``verify_provenance`` refuses coded
``revocation-status-unverifiable`` when ``set(gate.required_rids)`` does not
cover ``set(policy.revocation_required)``; (2) the w293 red-team probe
``rvc-provenance-demand-coverage-gap`` flips HELD; (3) adjacent batteries
green.

Base (wave-293 merge): 1 BREAK / 7 HELD / 0 ERROR.
Fixed: 0 BREAK / 8 HELD / 0 ERROR.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g294-f364 && TMPDIR=/var/tmp/g294-f364 \\
    ~/workspace/.gov-venv/bin/python evals/w294_f364_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g294-f364b \\
    ~/workspace/.gov-venv/bin/python evals/w294_f364_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

TAXONOMY_PIN = 1900 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*)
SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

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
    _record("pin-taxonomy", "HELD", "1900/1900/0 sorted")


def _seed():
    import secrets
    return secrets.token_bytes(32)


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


def _registry_with_two():
    from gov import revocation_status as rs
    reg = rs.RevocationRegistry("reg-294", _seed())
    hpub = _pub(_seed())
    reg.issue("cred-001", hpub, 1000, 2000)
    reg.issue("cred-002", hpub, 1000, 2000)
    return reg, hpub


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


# ---------------------------------------------------------------------------
# F364: demand/gate coverage binding at the verify_provenance seam.
# ---------------------------------------------------------------------------

def p_f364_demand_coverage_gap():
    # The F364 reproduction: policy demands ("cred-001", "cred-002")
    # but the gate only covers ("cred-001",). The demand for
    # "cred-002" must refuse coded "revocation-status-unverifiable",
    # never silently pass.
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, _ = _registry_with_two()
    gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    st1 = reg.check_status("cred-001", 1500)
    try:
        ok = ep.verify_provenance(env, policy, revocation_gate=gate,
                                  revocation_statuses=[st1])
    except (rs.RevocationError, ep.ProvenanceError) as e:
        if e.code == "revocation-status-unverifiable":
            return _record("f364-demand-coverage-gap", "HELD",
                           "under-covering gate refuses coded")
        return _record("f364-demand-coverage-gap", "BREAK",
                       "wrong code: %s" % e.code)
    if ok is True:
        return _record("f364-demand-coverage-gap", "BREAK",
                       "F364: demand for cred-002 silently dropped; "
                       "gate coverage is not bound to the policy demand")
    _record("f364-demand-coverage-gap", "BREAK",
            "unexpected non-True return: %r" % (ok,))


def p_f364_exact_cover_passes():
    # No over-refusal: a gate covering exactly the demand verifies.
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, _ = _registry_with_two()
    gate = rs.RevocationGate(reg.registry_pubkey_hex(),
                             ["cred-001", "cred-002"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    sts = [reg.check_status("cred-001", 1500),
           reg.check_status("cred-002", 1500)]
    try:
        ok = ep.verify_provenance(env, policy, revocation_gate=gate,
                                  revocation_statuses=sts)
    except (rs.RevocationError, ep.ProvenanceError) as e:
        return _record("f364-exact-cover-passes", "BREAK",
                       "exact-covering gate refused: %s (%s)"
                       % (e.code, e))
    if ok is True:
        return _record("f364-exact-cover-passes", "HELD",
                       "exact-covering gate verifies True")
    _record("f364-exact-cover-passes", "BREAK",
            "unexpected non-True return: %r" % (ok,))


def p_f364_superset_cover_passes():
    # A gate covering MORE than the demand (plus all statuses
    # supplied) verifies -- the binding is one-directional.
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, _ = _registry_with_two()
    hpub = _pub(_seed())
    reg.issue("cred-003", hpub, 1000, 2000)
    gate = rs.RevocationGate(reg.registry_pubkey_hex(),
                             ["cred-001", "cred-002", "cred-003"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    sts = [reg.check_status("cred-001", 1500),
           reg.check_status("cred-002", 1500),
           reg.check_status("cred-003", 1500)]
    try:
        ok = ep.verify_provenance(env, policy, revocation_gate=gate,
                                  revocation_statuses=sts)
    except (rs.RevocationError, ep.ProvenanceError) as e:
        return _record("f364-superset-cover-passes", "BREAK",
                       "superset-covering gate refused: %s (%s)"
                       % (e.code, e))
    if ok is True:
        return _record("f364-superset-cover-passes", "HELD",
                       "superset-covering gate verifies True")
    _record("f364-superset-cover-passes", "BREAK",
            "unexpected non-True return: %r" % (ok,))


def p_f364_no_demand_no_gate_passes():
    # Default posture unchanged: no demand, no gate verifies.
    from gov import evidence_provenance as ep
    env, policy = _provenance_envelope(revocation_required=())
    try:
        ok = ep.verify_provenance(env, policy)
    except ep.ProvenanceError as e:
        return _record("f364-no-demand-no-gate-passes", "BREAK",
                       "no-demand verify refused: %s (%s)" % (e.code, e))
    if ok is True:
        return _record("f364-no-demand-no-gate-passes", "HELD",
                       "empty demand needs no gate")
    _record("f364-no-demand-no-gate-passes", "BREAK",
            "unexpected non-True return: %r" % (ok,))


def p_f364_demand_no_gate_refuses_coded():
    # Pre-existing behavior (kept covered): a non-empty demand with
    # no gate refuses fail-closed, coded.
    from gov import evidence_provenance as ep
    env, policy = _provenance_envelope(
        revocation_required=("cred-001",))
    try:
        ep.verify_provenance(env, policy, revocation_gate=None,
                             revocation_statuses=())
    except ep.ProvenanceError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("f364-demand-no-gate-refuses-coded", "HELD",
                           "demand without a trust anchor refuses coded")
        return _record("f364-demand-no-gate-refuses-coded", "BREAK",
                       "wrong code: %s" % e.code)
    _record("f364-demand-no-gate-refuses-coded", "BREAK",
            "demand with no gate passed")


def p_f364_retired_rid_in_demand_refuses_coded():
    # The binding must not weaken enforcement: a demanded rid that is
    # retired still refuses coded "revocation-retired-reuse".
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, hpub = _registry_with_two()
    reg.rotate("cred-001", "cred-003", hpub, 1600, 2600)
    gate = rs.RevocationGate(reg.registry_pubkey_hex(),
                             ["cred-001", "cred-002"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    sts = [reg.check_status("cred-001", 1700),
           reg.check_status("cred-002", 1500)]
    try:
        ep.verify_provenance(env, policy, revocation_gate=gate,
                             revocation_statuses=sts)
    except (rs.RevocationError, ep.ProvenanceError) as e:
        if e.code == "revocation-retired-reuse":
            return _record("f364-retired-rid-in-demand-refuses-coded",
                           "HELD", "retired demanded rid refuses coded")
        return _record("f364-retired-rid-in-demand-refuses-coded",
                       "BREAK", "wrong code: %s" % e.code)
    _record("f364-retired-rid-in-demand-refuses-coded", "BREAK",
            "retired demanded rid passed")


def p_f364_revoked_rid_in_demand_refuses_coded():
    # Same for revoked: demanded rid revoked refuses coded
    # "revocation-revoked".
    from gov import revocation_status as rs, evidence_provenance as ep
    reg, _ = _registry_with_two()
    reg.revoke("cred-002", "key compromise")
    gate = rs.RevocationGate(reg.registry_pubkey_hex(),
                             ["cred-001", "cred-002"])
    env, policy = _provenance_envelope(
        revocation_required=("cred-001", "cred-002"))
    sts = [reg.check_status("cred-001", 1500),
           reg.check_status("cred-002", 1500)]
    try:
        ep.verify_provenance(env, policy, revocation_gate=gate,
                             revocation_statuses=sts)
    except (rs.RevocationError, ep.ProvenanceError) as e:
        if e.code == "revocation-revoked":
            return _record("f364-revoked-rid-in-demand-refuses-coded",
                           "HELD", "revoked demanded rid refuses coded")
        return _record("f364-revoked-rid-in-demand-refuses-coded",
                       "BREAK", "wrong code: %s" % e.code)
    _record("f364-revoked-rid-in-demand-refuses-coded", "BREAK",
            "revoked demanded rid passed")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN; child batteries run with it).
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w294-green-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=1200,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("green-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("green-" + label, "BREAK",
                "%s: %d BREAK, expected %d" % (rel, nbreak,
                                              expected_breaks))


def _green_checks():
    if SKIP_GREEN:
        return
    # w293_redteam: F364 closed => 0 BREAK (expectation corrected).
    _run_battery("evals/w293_redteam_probes.py", 0, "w293-redteam")
    _run_battery("evals/w292_revocation_probes.py", 0, "w292-revocation")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("f364-demand-coverage-gap", p_f364_demand_coverage_gap)
    _safe("f364-exact-cover-passes", p_f364_exact_cover_passes)
    _safe("f364-superset-cover-passes", p_f364_superset_cover_passes)
    _safe("f364-no-demand-no-gate-passes", p_f364_no_demand_no_gate_passes)
    _safe("f364-demand-no-gate-refuses-coded",
          p_f364_demand_no_gate_refuses_coded)
    _safe("f364-retired-rid-in-demand-refuses-coded",
          p_f364_retired_rid_in_demand_refuses_coded)
    _safe("f364-revoked-rid-in-demand-refuses-coded",
          p_f364_revoked_rid_in_demand_refuses_coded)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w294_f364: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
