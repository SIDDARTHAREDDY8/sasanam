"""Wave-283 lane 5 red-first battery: DefectDojo finding-lifecycle ADAPT.

Base: wave-282 push ad222ce. The gap under test is the absence of a governed
finding-lifecycle layer: FINDINGS.md is prose, so parallel lanes filing the
same defect shape race for F-numbers (the wave-272 renumber-map workaround),
states are free text (no Verified/False Positive/Risk Accepted/Duplicate/
Under Review machine states), per-severity SLA is nonexistent, and the
red-first post-wave closure audit is not an evidence-carrying state
transition. DefectDojo (django-DefectDojo, BSD-3-Clause, OSS core) supplies
the patterns: hash_code dedup over a configurable field set, close_old_findings
as a verified-close transition, the governed state machine, per-severity SLA.

ADAPTED here as gov/finding_lifecycle.py -- mechanism only, stdlib-only,
no code vendored.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (no wall-clock assertions).
Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g283-defectdojo && TMPDIR=/var/tmp/g283-defectdojo \
    ~/workspace/.gov-venv/bin/python evals/w283_defectdojo_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g283-defectdojo2 \
    ~/workspace/.gov-venv/bin/python evals/w283_defectdojo_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w283-defectdojo")
os.environ.setdefault("TMPDIR", "/var/tmp/g283-defectdojo")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-283 lane 5: 1579 -> 1581 (+2 finding-* codes).
TAXONOMY_PIN = 1991 # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

PLUGIN_META = ("finding-lifecycle", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_modules(probe_id):
    try:
        from gov import finding_lifecycle as fl
        return fl
    except ImportError:
        _record(probe_id, "BREAK", "gov.finding_lifecycle absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


_SHAPE = {
    "title": "shield-run evidence echoes credential-shaped shield details",
    "seam": "shield_registry._run_shields -> guardrail_evidence.run_guardrail",
    "attack_shape": "DLP shield quoting the offending argument lands the "
                    "credential in the record rationale",
    "close_when": "sanitize the shield detail at the run_guardrail emit "
                  "site; f309-shield-detail-echo flips to HELD",
}


def p_identity_convergence():
    fl = _needs_modules("p-identity-convergence")
    if fl is None:
        return
    noisy = {k: ("  %s \n" % v) for k, v in _SHAPE.items()}
    h1 = fl.finding_identity(**_SHAPE)
    h2 = fl.finding_identity(**noisy)
    if h1 != h2:
        return _record("p-identity-convergence", "BREAK",
                       "whitespace-variant filings did not converge: %s vs %s"
                       % (h1[:12], h2[:12]))
    if not re.fullmatch(r"[0-9a-f]{64}", h1):
        return _record("p-identity-convergence", "BREAK",
                       "identity not a 64-hex digest: %r" % h1)
    other = dict(_SHAPE)
    other["attack_shape"] = "something completely different"
    h3 = fl.finding_identity(**other)
    if h3 == h1:
        return _record("p-identity-convergence", "BREAK",
                       "identity ignores attack_shape (collision by design)")
    _record("p-identity-convergence", "HELD",
            "whitespace converges; distinct shapes diverge; %s" % h1[:16])


def p_configurable_field_set():
    fl = _needs_modules("p-configurable-field-set")
    if fl is None:
        return
    # DefectDojo's hash_code is over a *configurable* field set: two parallel
    # lanes filing the same defect shape with paraphrased titles converge
    # under the seam-focused field set.
    a = dict(_SHAPE)
    b = dict(_SHAPE)
    b["title"] = "credential material reaches the audit log via shield runs"
    full_a = fl.finding_identity(**a)
    full_b = fl.finding_identity(**b)
    if full_a == full_b:
        return _record("p-configurable-field-set", "BREAK",
                       "full field set should diverge on paraphrased titles")
    narrow_a = fl.finding_identity(fields=("seam", "attack_shape",
                                           "close_when"), **a)
    narrow_b = fl.finding_identity(fields=("seam", "attack_shape",
                                           "close_when"), **b)
    if narrow_a != narrow_b:
        return _record("p-configurable-field-set", "BREAK",
                       "seam-focused field set did not converge: %s vs %s"
                       % (narrow_a[:12], narrow_b[:12]))
    _record("p-configurable-field-set", "HELD",
            "configurable field set: title-excluded converges, full diverges")


def _mk_registry(fl, start=312):
    return fl.FindingRegistry(next_number=start, default_fields=(
        "seam", "attack_shape", "close_when"))


def p_state_machine_evidence():
    fl = _needs_modules("p-state-machine-evidence")
    if fl is None:
        return
    reg = _mk_registry(fl)
    num, kind = reg.file_finding(severity="low", reporter="red-team",
                                wave=283, **_SHAPE)
    if kind != "filed" or num != "F312":
        return _record("p-state-machine-evidence", "BREAK",
                       "filing returned %r/%r, want F312/filed" % (num, kind))
    f = reg.get(num)
    if f.state != "open":
        return _record("p-state-machine-evidence", "BREAK",
                       "new finding state %r, want open" % f.state)
    # Illegal: closure with no red-first evidence is refused loudly.
    try:
        reg.transition(num, "verified", wave=283, actor="merge-coord",
                       evidence={"note": "looks fine"})
    except fl.FindingLifecycleError as e:
        if e.code != "finding-illegal-transition":
            return _record("p-state-machine-evidence", "BREAK",
                           "wrong code on evidence-less close: %r" % e.code)
    else:
        return _record("p-state-machine-evidence", "BREAK",
                       "evidence-less close was not refused")
    # Legal path carries the red-first evidence by reference.
    ev = {"battery": "evals/w283_defectdojo_probes.py",
          "probes": ["p-identity-convergence"], "commit": "ad222ce",
          "wave": 283, "actor": "lane-5"}
    reg.transition(num, "under_review", wave=283, actor="lane-5",
                   evidence={"note": "triage in progress"})
    reg.transition(num, "verified", wave=283, actor="merge-coord",
                   evidence=ev)
    f = reg.get(num)
    if f.state != "verified":
        return _record("p-state-machine-evidence", "BREAK",
                       "state %r, want verified" % f.state)
    if not f.transitions or f.transitions[-1].evidence.get("commit") != "ad222ce":
        return _record("p-state-machine-evidence", "BREAK",
                       "closure evidence not carried on the transition")
    # Illegal: re-opening a verified finding is refused.
    try:
        reg.transition(num, "open", wave=284, actor="lane-6",
                       evidence={"note": "reopen"})
    except fl.FindingLifecycleError:
        pass
    else:
        return _record("p-state-machine-evidence", "BREAK",
                       "verified->open was not refused")
    _record("p-state-machine-evidence", "HELD",
            "illegal transitions refused; closure carries red-first evidence")


def p_sla_escalation():
    fl = _needs_modules("p-sla-escalation")
    if fl is None:
        return
    reg = _mk_registry(fl)
    num, _ = reg.file_finding(severity="low", reporter="red-team",
                             wave=282, **_SHAPE)
    f = reg.get(num)
    # LOW: 3 waves. Opened at 282 -> due at 285, breached at 286.
    if reg.check_sla(f, 285) != "due":
        return _record("p-sla-escalation", "BREAK",
                       "LOW at due wave 285 returned %r, want 'due'"
                       % reg.check_sla(f, 285))
    if reg.check_sla(f, 284) != "ok":
        return _record("p-sla-escalation", "BREAK",
                       "LOW before due wave returned non-ok")
    try:
        reg.check_sla(f, 286)
    except fl.FindingSlaBreached as e:
        if e.code != "finding-sla-breached":
            return _record("p-sla-escalation", "BREAK",
                           "wrong code on SLA breach: %r" % e.code)
    else:
        return _record("p-sla-escalation", "BREAK",
                       "SLA breach at wave 286 was not loud")
    # MEDIUM: 2 waves; HIGH: 1 wave.
    n2, _ = reg.file_finding(severity="medium", reporter="red-team",
                            wave=282, title="m", seam="s", attack_shape="a",
                            close_when="c")
    try:
        reg.check_sla(reg.get(n2), 285)
    except fl.FindingSlaBreached:
        pass
    else:
        return _record("p-sla-escalation", "BREAK",
                       "MEDIUM breach at wave 285 was not loud")
    # Risk Accepted and False Positive are excluded from SLA and metrics.
    n3, _ = reg.file_finding(severity="high", reporter="red-team",
                            wave=280, title="r", seam="s3", attack_shape="a3",
                            close_when="c3")
    reg.transition(n3, "under_review", wave=280, actor="triager",
                   evidence={"note": "reviewed"})
    reg.transition(n3, "risk_accepted", wave=280, actor="owner",
                   evidence={"note": "accepted: residual documented",
                             "expires_wave": 290})
    if reg.check_sla(reg.get(n3), 290) != "excluded":
        return _record("p-sla-escalation", "BREAK",
                       "risk_accepted not excluded from SLA")
    metric = [x.number for x in reg.metric_findings()]
    if n3 in metric:
        return _record("p-sla-escalation", "BREAK",
                       "risk_accepted leaked into metrics")
    # Unknown opening wave is loud ("unknown"), never silently OK.
    n4, _ = reg.file_finding(severity="low", reporter="r", wave=283,
                            title="u", seam="s4", attack_shape="a4",
                            close_when="c4")
    f4 = reg.get(n4)
    f4.opened_wave = None
    if reg.check_sla(f4, 300) != "unknown":
        return _record("p-sla-escalation", "BREAK",
                       "missing opened_wave did not report 'unknown'")
    if reg.sla_due_wave(f4) is not None:
        return _record("p-sla-escalation", "BREAK",
                       "sla_due_wave on missing wave did not return None")
    # Wave-boundary sweep escalates loudly with every breached number named.
    try:
        reg.sweep_sla(300)
    except fl.FindingSlaBreached as e:
        if num not in str(e) or n2 not in str(e):
            return _record("p-sla-escalation", "BREAK",
                           "sweep did not name every breached finding: %s"
                           % e)
    else:
        return _record("p-sla-escalation", "BREAK",
                       "sweep_sla did not escalate on breached findings")
    rep = reg.sla_report(284)
    if rep.get(num) != "ok" or rep.get(n4) != "unknown":
        return _record("p-sla-escalation", "BREAK",
                       "sla_report wrong: %r" % (rep,))
    _record("p-sla-escalation", "HELD",
            "LOW/MEDIUM/HIGH wave bounds enforced; RA/FP excluded; "
            "unknown wave loud; sweep names every breach")


def p_duplicate_linking():
    fl = _needs_modules("p-duplicate-linking")
    if fl is None:
        return
    reg = _mk_registry(fl)
    n1, k1 = reg.file_finding(severity="low", reporter="red-team",
                             wave=283, **_SHAPE)
    n2, k2 = reg.file_finding(severity="low", reporter="lane-9",
                             wave=283, **_SHAPE)
    if k2 != "duplicate" or n2 != n1:
        return _record("p-duplicate-linking", "BREAK",
                       "second filing returned %r/%r, want duplicate of %r"
                       % (n2, k2, n1))
    canon = reg.get(n1)
    if len(canon.filings) != 2:
        return _record("p-duplicate-linking", "BREAK",
                       "parallel filing provenance not retained: %r"
                       % (canon.filings,))
    canon_lookup = reg.lookup_identity(fl.finding_identity(
        fields=reg.default_fields, **_SHAPE))
    if canon_lookup != n1:
        return _record("p-duplicate-linking", "BREAK",
                       "identity index lookup returned %r, want %r"
                       % (canon_lookup, n1))
    # Duplicate-with-link: an explicit transition to duplicate names the
    # canonical finding; omitting the link is refused.
    reg2 = _mk_registry(fl, start=400)
    m1, _ = reg2.file_finding(severity="low", reporter="red-team",
                              wave=283, **_SHAPE)
    m2, _ = reg2.file_finding(severity="low", reporter="lane-9",
                              wave=283, title="rephrased",
                              seam="other-seam", attack_shape="other-shape",
                              close_when="other-close")
    reg2.transition(m2, "under_review", wave=283, actor="merge-coord",
                    evidence={"note": "same root cause"})
    try:
        reg2.transition(m2, "duplicate", wave=283, actor="merge-coord",
                        evidence={"note": "no link named"})
    except fl.FindingLifecycleError:
        pass
    else:
        return _record("p-duplicate-linking", "BREAK",
                       "duplicate transition without duplicate_of not refused")
    reg2.transition(m2, "duplicate", wave=283, actor="merge-coord",
                    evidence={"note": "same shape", "duplicate_of": m1})
    if reg2.get(m2).duplicate_of != m1:
        return _record("p-duplicate-linking", "BREAK",
                       "duplicate_of link not recorded")
    _record("p-duplicate-linking", "HELD",
            "parallel filings converge to %s by identity, no renumber map; "
            "duplicate-with-link enforced" % n1)


def p_human_triage_wins():
    fl = _needs_modules("p-human-triage-wins")
    if fl is None:
        return
    reg = _mk_registry(fl)
    n1, _ = reg.file_finding(severity="low", reporter="red-team",
                            wave=282, **_SHAPE)
    n2, _ = reg.file_finding(severity="medium", reporter="red-team",
                            wave=282, title="h", seam="s2", attack_shape="a2",
                            close_when="c2")
    reg.transition(n2, "under_review", wave=283, actor="human-triager",
                   evidence={"note": "human is investigating a variant"})
    scan = {
        n1: {"reproduced": False, "battery": "evals/w282_redteam_probes.py",
             "probes": ["f311-transform-detail-echo"], "commit": "ad222ce"},
        n2: {"reproduced": False, "battery": "evals/w282_redteam_probes.py",
             "probes": ["f311-deny-detail-echo"], "commit": "ad222ce"},
    }
    closed = reg.close_old_findings(scan, wave=283, actor="merge-coord")
    f1, f2 = reg.get(n1), reg.get(n2)
    if f1.state != "mitigated":
        return _record("p-human-triage-wins", "BREAK",
                       "unreproduced OPEN finding not mitigated: %r" % f1.state)
    if f1.transitions[-1].evidence.get("battery") != "evals/w282_redteam_probes.py":
        return _record("p-human-triage-wins", "BREAK",
                       "mitigation lacks the scan evidence reference")
    if f2.state != "under_review":
        return _record("p-human-triage-wins", "BREAK",
                       "human UNDER_REVIEW was overridden by the sweep: %r"
                       % f2.state)
    if closed != [n1]:
        return _record("p-human-triage-wins", "BREAK",
                       "close_old_findings returned %r, want [%r]"
                       % (closed, n1))
    _record("p-human-triage-wins", "HELD",
            "sweep mitigates with evidence; human triage is never overridden")


def p_findings_md_load():
    fl = _needs_modules("p-findings-md-load")
    if fl is None:
        return
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "evals", "FINDINGS.md")
    reg = fl.load_findings_md(path)
    got = reg.get("F311")
    if got is None or got.state != "verified":
        return _record("p-findings-md-load", "BREAK",
                       "F311 not parsed as closed: %r"
                       % (None if got is None else got.state))
    for num in ("F312", "F313", "F314", "F315"):
        ent = reg.get(num)
        if ent is None or ent.state != "verified":
            return _record("p-findings-md-load", "BREAK",
                           "%s parsed as %r, want 'verified'"
                           % (num, None if ent is None else ent.state))
    # F312-F315 closed at the wave-284 merge (lane 1); F316-F324 closed
    # at the wave-285 merge (lanes 1-4); F325-F330 filed OPEN by the
    # wave-285 independent red team, closed at the wave-286 merge
    # (lanes 1-4); F331-F333 filed OPEN by the wave-286 independent
    # red team; F331-F333 closed at the wave-287 merge (lanes 1-3);
    # F334-F342 filed OPEN by the wave-287 independent red team; F334-F342
    # closed at the wave-288 merge (lanes 1-4); F343-F345 filed OPEN by
    # the wave-288 independent red team, verified (closed) on the
    # current tree (wave-316 re-pin).
    for num in ("F316", "F317", "F318", "F319", "F320",
                "F321", "F322", "F323", "F324", "F325", "F326",
                "F327", "F328", "F329", "F330",
                "F331", "F332", "F333", "F334", "F335",
                "F336", "F337", "F338", "F339", "F340",
                "F341", "F342", "F343", "F344", "F345"):
        ent = reg.get(num)
        if ent is None or ent.state != "verified":
            return _record("p-findings-md-load", "BREAK",
                           "%s parsed as %r, want 'verified'"
                           % (num, None if ent is None else ent.state))
    for num, want in (("F310", "verified"), ("F309", "verified"),
                      ("F306", "verified"), ("F94", "verified")):
        ent = reg.get(num)
        if ent is None or ent.state != want:
            return _record("p-findings-md-load", "BREAK",
                           "%s parsed as %r, want %r"
                           % (num, None if ent is None else ent.state, want))
    if len(reg.all()) < 200:
        return _record("p-findings-md-load", "BREAK",
                       "only %d entries parsed, want >= 200" % len(reg.all()))
    # Every parsed entry carries a well-formed identity hash.
    bad = [f.number for f in reg.all()
           if not re.fullmatch(r"[0-9a-f]{64}", f.identity_hash)]
    if bad:
        return _record("p-findings-md-load", "BREAK",
                       "malformed identity hashes: %r" % bad[:3])
    _record("p-findings-md-load", "HELD",
            "%d FINDINGS.md entries parsed; F311-F345 closed, "
            "F310/F309/F306 closed"
            % len(reg.all()))


def _green_checks():
    if SKIP_GREEN:
        return
    rel = "evals/w282_redteam_probes.py"
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), rel)
    d = tempfile.mkdtemp(prefix="w283-green-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-w282-redteam", "ERROR", "green check: %r" % (e,))
        return
    out = proc.stdout
    breaks = [ln for ln in out.splitlines() if "[BREAK]" in ln]
    if proc.returncode != 0:
        _record("green-w282-redteam", "ERROR",
                "green check exit=%d: %s" % (proc.returncode, out[-300:]))
    elif breaks:
        _record("green-w282-redteam", "BREAK",
                "expected 0 BREAKs (F311 closed at the wave-283 merge); got %s"
                % (breaks[:5],))
    else:
        _record("green-w282-redteam", "HELD",
                "green: exit 0, 0 BREAKs (F311 closure holds on the merge)")


def main():
    p_taxonomy_pin()
    p_identity_convergence()
    p_configurable_field_set()
    p_state_machine_evidence()
    p_sla_escalation()
    p_duplicate_linking()
    p_human_triage_wins()
    p_findings_md_load()
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("[%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    print("SUMMARY: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 0 if n_break == 0 and n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
