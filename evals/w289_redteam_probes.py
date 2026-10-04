"""Wave-289 independent red-team battery: attack the wave-288 merge.

Base: wave-288 push 18beb4044a26cba48bd895d95b505d7adc327422
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (all wave-288 additions):
  (a) gov/evidence_admission.py -- notation-pattern trust ladder
      strict>permissive>audit>skip, non-overridable integrity floor,
      fail-closed no-policy, accept-at-risk via governed_exceptions
      (floor-caused refusal must NEVER be exceptionable).
  (b) gov/runtime_posture.py -- EAT JSON-profile runtime posture:
      eat_nonce >=64-bit, submods nesting, per-claim endorsement
      slots, operator signing, trust-vector seam, TSA freshness.
  (c) gov/evidence_receipt.py -- bind_receipt re-verifies the inclusion
      tuple before signing (F337 closure surface).
  (d) gov/kms_keyset.py -- pin-key custody (F335/F336 closure surface).
  (e) gov/tool_call_policy.py -- F334/F338-F342 closure surfaces.

Re-pins at the public seams:
  F311-F333 (CLOSED) -- 0 BREAK expected.
  F334-F342 (CLOSED, wave-288 lanes) -- 0 BREAK expected.
  F343-F345 (OPEN at base) -- 3 BREAK expected-open.

New findings filed (all LOW, OPEN): F346-F351.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g289-redteam && TMPDIR=/var/tmp/g289-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w289_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g289-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w289_redteam_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

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

# Wave-288 merge: pin 1684 -> 1700 (+1 toolcall-exception-scope-mismatch
# +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-*
# +6 posture-*).
TAXONOMY_PIN = 1990 # wave-290 lane 6: 1706 -> 1710; Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


# ---------------------------------------------------------------------------
# Re-pins: run the earlier batteries as subprocesses (depth-1, no nesting)
# and check their verdict counts against the expected post-wave-288 state.
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    ("evals/w283_f311_probes.py", 0, "f311-closed"),
    ("evals/w283_redteam_probes.py", 0, "f312-315-closed"),
    ("evals/w284_f312_315_probes.py", 0, "f312-315-closed-b"),
    ("evals/w284_redteam_probes.py", 0, "f316-324-closed"),
    ("evals/w286_f325_probes.py", 0, "f325-closed"),
    ("evals/w286_f326_probes.py", 0, "f326-closed"),
    ("evals/w286_f327_f328_probes.py", 0, "f327-328-closed"),
    ("evals/w286_f329_f330_probes.py", 0, "f329-330-closed"),
    ("evals/w287_f331_probes.py", 0, "f331-closed"),
    ("evals/w287_f332_probes.py", 0, "f332-closed"),
    ("evals/w287_f333_probes.py", 0, "f333-closed"),
    # Wave-288 merge: F334-F342 all CLOSED (lanes 1-4) -> 0 BREAK expected.
    ("evals/w288_f334_f337_probes.py", 0, "f334-337-closed"),
    ("evals/w288_f335_f336_probes.py", 0, "f335-336-closed"),
    ("evals/w288_f338_f339_probes.py", 0, "f338-339-closed"),
    ("evals/w288_f340_f342_probes.py", 0, "f340-342-closed"),
    # Merge-time (wave-289): F343-F345 are CLOSED on the composed
    # tree (they were OPEN at lane time) -> 0 BREAK expected.
    ("evals/w288_redteam_probes.py", 0, "f343-345-closed"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w289-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR", "subprocess failed: %r" % (e,))
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _posture_parts(producer_id="operator", slot_source="log-op"):
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": slot_source}
    rec = rp.issue_posture(
        operator_seed=seed, operator_keyid="op1",
        eat_nonce=secrets.token_bytes(16),
        submods={"sbx": {"digest": "ab" * 32}},
        software_id="agent/1.0", config_digest="cd" * 32,
        endorsements={c: dict(slot) for c in
                      ("software_id", "config_digest", "submods")},
        producer_id=producer_id)
    return rec, seed, pub


def _anchor_parts():
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w289-rt-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w289origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    return anchored, seed


def _admission_policy(**kw):
    from gov import evidence_admission as adm
    doc = {"format": "admission-policy/1", "policy_id": "p1",
           "scopes": [{"scope": "provenance", "level": "strict"}]}
    doc.update(kw)
    return adm.compile_policy(doc)


def _risk_store():
    from gov import governed_exceptions as ge
    from gov import evidence_admission as adm
    reg = ge.CheckRegistry()
    reg.register(adm.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 category="admission", severity="low",
                 rationale="accept a refused admission at operator risk",
                 resource_types=["policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["op"])
    now = time.time()
    store.grant(adm.ACCEPT_RISK_CHECK_ID, ("policy", "p1"),
                "accepting at risk for the red-team probe with rationale",
                "op", now + 3600, now)
    return store


# ---------------------------------------------------------------------------
# F346 (LOW): audit-sink failures propagate uncoded out of runtime_posture.
# Same defect class as F345 (filed against evidence_provenance).
# _emit_event calls the installed sink without isolation: a raising sink
# escapes issue_posture as the sink's own exception type (code=None).
# ---------------------------------------------------------------------------

def p_f346_posture_sink_uncoded():
    from gov import runtime_posture as rp

    def _boom(ev):
        raise ValueError("sink boom")

    rp.set_emit(_boom)
    try:
        rec, seed, pub = _posture_parts()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f346-posture-sink", "BREAK",
                           "raising sink escaped issue_posture uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f346-posture-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    except BaseException as e:  # noqa: BLE001
        return _record("f346-posture-sink", "BREAK",
                       "raising sink escaped as %s" % type(e).__name__)
    else:
        _record("f346-posture-sink", "HELD",
                "sink failure isolated from issuance (F345 mechanism)")
    finally:
        rp.set_emit(None)


def p_f346_posture_sink_ok():
    """Positive control: a well-behaved sink does not break issuance."""
    from gov import runtime_posture as rp
    from gov import ed25519
    seen = []
    rp.set_emit(seen.append)
    try:
        rec, seed, pub = _posture_parts()
        payload = rp.verify_posture(rec, pub)
    except Exception as e:  # noqa: BLE001
        return _record("f346-sink-ok", "BREAK",
                       "well-behaved sink broke issuance: %r"
                       % getattr(e, "code", type(e).__name__))
    finally:
        rp.set_emit(None)
    if seen and payload.get("software_id") == "agent/1.0":
        return _record("f346-sink-ok", "HELD",
                       "issuance + verify fine under a good sink")
    _record("f346-sink-ok", "BREAK", "sink saw nothing or payload wrong")


# ---------------------------------------------------------------------------
# F347 (LOW): audit-sink failures propagate uncoded out of
# evidence_receipt. Same class as F345/F346: _emit is unisolated at the
# bind_receipt, verify_receipt_offline, and denounce_fork call sites.
# ---------------------------------------------------------------------------

def p_f347_receipt_sink_uncoded():
    from gov import evidence_receipt as er

    def _boom(ev):
        raise ValueError("sink boom")

    anchored, seed = _anchor_parts()
    er.set_emit(_boom)
    try:
        receipt = er.bind_receipt(anchored, seed)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f347-receipt-sink", "BREAK",
                           "raising sink escaped bind_receipt uncoded "
                           "(%s)" % type(e).__name__)
        return _record("f347-receipt-sink", "HELD",
                       "sink failure refused coded: %s" % code)
    except BaseException as e:  # noqa: BLE001
        return _record("f347-receipt-sink", "BREAK",
                       "raising sink escaped as %s" % type(e).__name__)
    else:
        _record("f347-receipt-sink", "HELD",
                "sink failure isolated from issuance (F345 mechanism)")
    finally:
        er.set_emit(None)


def p_f347_receipt_sink_ok():
    """Positive control: genuine bind still works under a good sink."""
    from gov import evidence_receipt as er
    from gov import ed25519
    anchored, seed = _anchor_parts()
    seen = []
    er.set_emit(seen.append)
    try:
        receipt = er.bind_receipt(anchored, seed)
        ok = er.verify_receipt_offline(receipt, ed25519.publickey(seed))
    except Exception as e:  # noqa: BLE001
        return _record("f347-sink-ok", "BREAK",
                       "good sink broke bind: %r"
                       % getattr(e, "code", type(e).__name__))
    finally:
        er.set_emit(None)
    if ok is True and seen:
        return _record("f347-sink-ok", "HELD",
                       "bind + offline verify fine under a good sink")
    _record("f347-sink-ok", "BREAK", "bind/verify misbehaved")


# ---------------------------------------------------------------------------
# F348 (LOW): evidence_admission.CHECKS is a mutable module-level dict.
# INTEGRITY_FLOOR is a frozenset, but admit() iterates CHECKS -- deleting
# the floor checks from CHECKS removes the floor entirely (F340 class):
# evidence then ADMITs with floor_failed=[] and no floor ever ran.
# ---------------------------------------------------------------------------

def p_f348_checks_mutation_floor_bypass():
    from gov import evidence_admission as adm
    saved = dict(adm.CHECKS)
    try:
        del adm.CHECKS["signature-valid"]
        del adm.CHECKS["digest-binds"]
        pol = _admission_policy(
            scopes=[{"scope": "provenance", "level": "skip"}])
        ev = {"kind": "provenance", "artifact_digest": "ab" * 32}
        outcomes = {c: True for c in adm.CHECKS}
        rec = adm.admit(ev, pol, outcomes)
    except Exception as e:  # noqa: BLE001
        return _record("f348-checks-mutation", "HELD",
                       "mutation refused: %r"
                       % getattr(e, "code", type(e).__name__))
    finally:
        # Post-F348 the registry is immutable (MappingProxyType): the
        # restore is a no-op then. Keep the restore for the old dict.
        try:
            adm.CHECKS.clear()
            adm.CHECKS.update(saved)
        except (TypeError, AttributeError):
            pass
    if rec.get("verdict") == "ADMIT" and not rec.get("floor_failed"):
        return _record("f348-checks-mutation", "BREAK",
                       "deleting floor checks from CHECKS bypassed the "
                       "integrity floor: ADMIT with no floor run")
    _record("f348-checks-mutation", "HELD",
            "floor still enforced after registry mutation")


def p_f348_floor_refuses():
    """Positive control: the floor still refuses on genuine failure."""
    from gov import evidence_admission as adm
    pol = _admission_policy()
    ev = {"kind": "provenance", "artifact_digest": "ab" * 32}
    outcomes = {c: True for c in adm.CHECKS}
    outcomes["signature-valid"] = False
    try:
        adm.admit(ev, pol, outcomes)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-integrity-floor-violated":
            return _record("f348-floor-refuses", "HELD",
                           "floor failure refuses coded")
        return _record("f348-floor-refuses", "BREAK",
                       "floor failure refused with wrong code: %r"
                       % getattr(e, "code", None))
    _record("f348-floor-refuses", "BREAK",
            "floor failure did not refuse")


# ---------------------------------------------------------------------------
# F349 (LOW): admit_at_risk's floor gate is caller-attested, not
# mechanism-enforced. admit() RAISES on REFUSE (never returns a decision
# record), so every refuse_decision dict is caller-synthesized; nothing
# binds it to the actual admit() outcome and decision_digest is unkeyed.
# A refuse dict that omits floor_failed yields ADMIT-AT-RISK even for
# evidence whose floor checks failed.
# ---------------------------------------------------------------------------

def p_f349_forged_refuse_floor_omitted():
    from gov import evidence_admission as adm
    store = _risk_store()
    _admission_policy()  # policy p1 exists for the exception scope
    forged = {"verdict": "REFUSE", "policy_id": "p1",
              "decision_digest": "x" * 64}
    try:
        rec = adm.admit_at_risk(forged, store)
    except Exception as e:  # noqa: BLE001
        return _record("f349-forged-refuse", "HELD",
                       "synthesized refuse refused: %r"
                       % getattr(e, "code", type(e).__name__))
    if rec.get("verdict") == "ADMIT-AT-RISK":
        return _record("f349-forged-refuse", "BREAK",
                       "floor gate reads a caller-controlled field: a "
                       "refuse dict omitting floor_failed admits at risk")
    _record("f349-forged-refuse", "HELD",
            "unexpected record: %r" % (rec.get("verdict"),))


def p_f349_floor_failed_refused():
    """Positive control: an honest floor_failed record still refuses."""
    from gov import evidence_admission as adm
    store = _risk_store()
    forged = {"verdict": "REFUSE", "policy_id": "p1",
              "decision_digest": "x" * 64,
              "floor_failed": ["signature-valid"]}
    try:
        adm.admit_at_risk(forged, store)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-exception-refused":
            return _record("f349-floor-refused", "HELD",
                           "floor_failed present -> refused coded")
        return _record("f349-floor-refused", "BREAK",
                       "wrong code: %r" % getattr(e, "code", None))
    _record("f349-floor-refused", "BREAK",
            "floor_failed record was admitted at risk")


# ---------------------------------------------------------------------------
# F350 (LOW): the posture record does not bind producer_id in the signed
# payload. issue_posture enforces endorsement independence at mint
# (source_id != producer_id), but verify_posture calls
# _check_endorsements(..., producer_id=None), skipping the check -- and
# no downstream party can re-verify it. A hand-built self-endorsed record
# signed by the operator key verifies cleanly.
# ---------------------------------------------------------------------------

def p_f350_self_endorsed_verifies():
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": "mallory"}
    protected = {"alg": "EdDSA", "kid": "op1",
                 "posture_format": rp.POSTURE_FORMAT}
    payload = {"v": 1, "eat_nonce": secrets.token_bytes(16).hex(),
               "submods": {"sbx": {"digest": "ab" * 32}},
               "software_id": "agent/1.0", "config_digest": "cd" * 32,
               "endorsements": {c: dict(slot) for c in
                                ("software_id", "config_digest", "submods")}}
    sig = ed25519.sign(bytes(seed),
                       rp._sig_structure(protected, payload)).hex()
    record = {"posture_format": rp.POSTURE_FORMAT, "protected": protected,
              "payload": payload, "signature": sig}
    try:
        rp.verify_posture(record, pub)
    except Exception as e:  # noqa: BLE001
        return _record("f350-self-endorse", "HELD",
                       "self-endorsed record refused: %r"
                       % getattr(e, "code", type(e).__name__))
    _record("f350-self-endorse", "BREAK",
            "operator-signed self-endorsed record verifies: producer_id "
            "is not bound in the payload, so independence is "
            "issuance-only")


def p_f350_issue_refuses_self_source():
    """Positive control: the module's own issuance refuses self-source."""
    from gov import runtime_posture as rp
    try:
        _posture_parts(producer_id="mallory", slot_source="mallory")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "posture-endorsement-not-independent":
            return _record("f350-issue-refuses", "HELD",
                           "issuance refuses self-sourced endorsements")
        return _record("f350-issue-refuses", "BREAK",
                       "wrong code: %r" % getattr(e, "code", None))
    _record("f350-issue-refuses", "BREAK",
            "issuance accepted self-sourced endorsements")


# ---------------------------------------------------------------------------
# F351 (LOW): uncoded escapes at wave-288 public seams (F342/F344 class).
# The repo's all-refusals-coded contract: every public-seam argument
# violation must refuse LOUD with a coded decision code, never leak a
# raw TypeError/AttributeError.
# ---------------------------------------------------------------------------

def p_f351a_receipt_str_seed():
    """bind_receipt with a str operator_seed: bytes(str) -> TypeError."""
    from gov import evidence_receipt as er
    anchored, _seed = _anchor_parts()
    try:
        er.bind_receipt(anchored, "x" * 32)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f351a-str-seed", "BREAK",
                           "str operator_seed escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351a-str-seed", "HELD",
                       "refused coded: %s" % e.code)
    _record("f351a-str-seed", "BREAK", "str seed was accepted")


def p_f351b_seam_list_endorsements():
    """as_appraisal_evidence with list endorsements -> AttributeError."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    rec["payload"]["endorsements"] = ["not", "a", "dict"]
    try:
        rp.as_appraisal_evidence(rec, "op1")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f351b-list-endorse", "BREAK",
                           "list endorsements escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351b-list-endorse", "HELD",
                       "refused coded: %s" % e.code)
    _record("f351b-list-endorse", "BREAK", "list endorsements accepted")


def p_f351c_seam_nonjson():
    """as_appraisal_evidence with a set in submods -> TypeError."""
    from gov import runtime_posture as rp
    rec, _s, _p = _posture_parts()
    rec["payload"]["submods"] = {"sbx": {"digest": set([1, 2, 3])}}
    try:
        rp.as_appraisal_evidence(rec, "op1")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f351c-nonjson", "BREAK",
                           "non-JSON submods escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351c-nonjson", "HELD",
                       "refused coded: %s" % e.code)
    _record("f351c-nonjson", "BREAK", "non-JSON submods accepted")


def p_f351d_nonstring_pin_digest():
    """admit() with a non-string pinned digest -> TypeError in
    hmac.compare_digest."""
    from gov import evidence_admission as adm
    pol = _admission_policy()
    ev = {"kind": "provenance", "artifact_digest": "ab" * 32}
    outcomes = {c: True for c in adm.CHECKS}
    try:
        adm.admit(ev, pol, outcomes, pins={"p1": 12345})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f351d-pin-digest", "BREAK",
                           "non-string pin digest escaped uncoded (%s)"
                           % type(e).__name__)
        return _record("f351d-pin-digest", "HELD",
                       "refused coded: %s" % e.code)
    _record("f351d-pin-digest", "BREAK", "non-string pin digest accepted")


# ---------------------------------------------------------------------------
# Green checks (depth-1): the wave-288 module batteries must stay green.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w288_admission_probes.py",
        "evals/w288_eat_probes.py",
        "evals/w287_ear_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w289-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    _run_repins()
    p_f346_posture_sink_uncoded()
    p_f346_posture_sink_ok()
    p_f347_receipt_sink_uncoded()
    p_f347_receipt_sink_ok()
    p_f348_checks_mutation_floor_bypass()
    p_f348_floor_refuses()
    p_f349_forged_refuse_floor_omitted()
    p_f349_floor_failed_refused()
    p_f350_self_endorsed_verifies()
    p_f350_issue_refuses_self_source()
    p_f351a_receipt_str_seed()
    p_f351b_seam_list_endorsements()
    p_f351c_seam_nonjson()
    p_f351d_nonstring_pin_digest()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w289_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
