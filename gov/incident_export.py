"""Regulator-shaped incident export (EU AI Act Art. 73 / Art. 50).

Turns a governed run's audit trail into a structured serious-incident
report whose sections mirror the European Commission's Art. 73 reporting
template (Regulation (EU) 2024/1689):

  1. Administrative information (reporter, contact, discovery/occurrence
     timestamps, member states)
  2. AI system data (name/version, Annex III category, EU DB registration,
     policy version in force at the time of the incident)
  3. Incident description (what happened, Art. 3(49) outcome type,
     persons affected, geographic scope)
  4. Preliminary analysis (causal-link assessment, corrective actions,
     investigation status, parallel obligations)
  5. Additional comments

plus a machine-verifiable evidence section: a curated timeline of the
run, a deterministic causal chain (the decision path that led to the
incident), and a completeness attestation hash-chained to the audit log
and anchored by a transparency-log receipt.

Regulatory-basis note (honest): this module maps FIELDS, it does not
give legal advice. Art. 73 deadlines (2 days for a widespread
infringement or an Art. 3(49)(b) critical-infrastructure incident —
two independent triggers; 10 days for death of a person; 15 days for
other serious incidents) are surfaced as a suggested tier computed
from the incident class plus operator harm fields; the operator
confirms. No regulator or auditor has accepted this format.

Field research (2026-09-27, primary sources):
  * Art. 73 deadline tiers verified against the EUR-Lex consolidated
    text of Regulation (EU) 2024/1689 (02024R1689-20260727):
    73(2) general 15 days; 73(3) 2 days for a widespread infringement
    OR an Art. 3(49)(b) critical-infrastructure incident (two
    independent triggers); 73(4) 10 days for death; 73(5) incomplete
    initial report allowed; 73(6) investigate without delay and do not
    alter the system/log in ways affecting evaluation.
  * Art. 3(49) "serious incident": (a) death/serious health harm;
    (b) serious irreversible disruption of critical infrastructure;
    (c) infringement of Union-law fundamental-rights obligations;
    (d) serious harm to property/environment.
  * Art. 50 transparency duties (in force since 2026-08-02): 50(1)
    AI-interaction disclosure (agents disclose artificial nature + on
    whose behalf they act); 50(2) machine-readable marking of
    synthetic audio/image/video/text; 50(3) emotion-recognition /
    biometric-categorisation notice; 50(4) deepfake + public-interest
    text disclosure. EC transparency guidelines adopted 2026-07-20.
  * EC draft Art. 73 reporting template (five sections) via secondary
    summaries; UNSC/EU direction brief in
    research/unsc-eu-direction-2026-09-26.md.

Design (adapted from gov/offline_bundle.py's trust pattern, not copied):
  * The source HMAC chain must verify at export time; export refuses
    from a broken chain.
  * The timeline is an UNKEYED SHA-256 export chain over exactly the
    bytes shipped; integrity comes from the ANCHOR (Ed25519-signed
    receipt commits to the timeline tip + window + causal digest), not
    from key secrecy — same Kerckhoffs argument as the offline bundle.
  * Per-entry Ed25519 signatures are required on source entries at
    export (v1); shipped timeline entries are redacted summaries.
  * Privacy: raw tool args / prompts / outputs NEVER ship. A fixed
    mandatory redaction set is dropped from every entry; an args_digest
    preserves a binding to what the agent actually attempted.
  * The causal chain is computed by a DETERMINISTIC curation rule
    (``_curate_causal_chain``). The verifier recomputes it from the
    shipped timeline: omitting a causally-relevant event from the chain
    is caught; omitting an event from the timeline is caught by the
    export-chain/containment check.

Honest ceiling (measured, not hand-waved): curation is a heuristic
over event TYPES. An adversary who knows the curation sets can keep
the real instruction inside an event type the curator ignores (e.g. a
``memory_write_provenance`` note rather than the tool_call args). The
timeline still contains the event (completeness holds), but a reader
of only the causal chain misses the narrative. Probe e5 in
``evals/incident_export_adversarial.py`` demonstrates exactly this:
the artifact verifies while the story is shaped. Curation is a lens,
not a guarantee.

$0 spend, synthetic/local only. No network.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from gov import log as _log

INCIDENT_FORMAT = "incident-report/1.0"
EXPORTER_VERSION = "1.0.0"

#: Domain separation for the timeline export hash chain (unkeyed SHA-256;
#: security via the anchor signature, same argument as offline_bundle).
EXPORT_CHAIN_DOMAIN = b"incident-export-chain/v1\x00"
EXPORT_GENESIS = "INCIDENT-EXPORT-GENESIS"

#: Fields that NEVER ship in a timeline entry (privacy by construction).
#: Dropped before chaining; each drop is listed in the redaction report.
_ALWAYS_REDACT = frozenset({
    "args", "result", "prompt", "output", "content", "body", "message",
    "tool_input", "response", "stdout", "stderr",
})

#: Chain bookkeeping the exporter manages itself; a caller can never
#: smuggle these in to forge bookkeeping (mirrors log.append's rule).
_RESERVED = frozenset({
    "seq", "ts", "prev_hash", "hash", "format_version", "key_epoch",
    "epoch_id", "ed_sig", "sig_key_id", "export_hash", "redacted",
})

#: Summary fields that DO ship per timeline entry.
_SUMMARY_FIELDS = (
    "event", "agent_id", "role", "principal", "run_id", "tool",
    "decision", "policy_id", "approval_id", "canary_id", "flag",
    "reason", "window", "target", "digest",
)

# ---------------------------------------------------------------------------
# Incident classes. Each maps to the audit events that mark its onset, plus
# the suggested Art. 73 deadline tier (operator confirms; harm fields can
# escalate).
# ---------------------------------------------------------------------------

INCIDENT_CLASSES = {
    "exfiltration_attempt": {
        "triggers": ("canary_trip",),
        "deadline_days": 15,
        "art3_49": "fundamental-rights / property (data exfiltration)",
        "description": "an egress canary tripped: the agent attempted to "
                       "move canary-marked data out of the run",
    },
    "governance_bypass_attempt": {
        "triggers": ("ungoverned_bypass", "ungoverned_bypass_refused"),
        "deadline_days": 15,
        "art3_49": "fundamental-rights (oversight evasion)",
        "description": "the agent attempted to act outside governance "
                       "(unacknowledged ungoverned mode)",
    },
    "sandbox_escape_contained": {
        "triggers": ("sandbox_traversal_contained",),
        "deadline_days": 2,
        "art3_49": "critical-infrastructure disruption (contained escape)",
        "description": "a sandbox traversal was detected and contained",
    },
    "memory_poisoning_contained": {
        "triggers": ("memory_quarantine",),
        "deadline_days": 15,
        "art3_49": "fundamental-rights (memory integrity)",
        "description": "poisoned memory content was quarantined",
    },
    "approval_integrity_violation": {
        "triggers": ("approval_integrity_violation",),
        "deadline_days": 15,
        "art3_49": "fundamental-rights (human-oversight integrity)",
        "description": "the approval record's integrity check failed",
    },
    "advisory_boundary_violation": {
        "triggers": ("advisory_monotonicity_violation",),
        "deadline_days": 15,
        "art3_49": "fundamental-rights (oversight evasion)",
        "description": "an advisor attempted to loosen a deterministic "
                       "verdict (trust-boundary probe)",
    },
    "policy_tamper_detected": {
        "triggers": ("policy_pin_mismatch",),
        "deadline_days": 15,
        "art3_49": "fundamental-rights (policy integrity)",
        "description": "the loaded policy did not match its pin",
    },
    "operator_declared": {
        "triggers": (),
        "deadline_days": 15,
        "art3_49": "operator-assessed",
        "description": "operator-declared incident (no automatic trigger; "
                       "caller supplies trigger_seq)",
    },
}

#: Event types the curator treats as causal ANCESTRY of a trigger.
_ANCESTRY_EVENTS = frozenset({
    "approval_decision",
    "approval_decision_attempt",
    "classification_taint_set",
    "agent_spawn",
    "decision_bom",
    "advisory_monotonicity_violation",
    "memory_session_flag",
    "capability_assessment_updated",
})

#: Event types the curator treats as CONTAINMENT after a trigger.
_CONTAINMENT_EVENTS = frozenset({
    "memory_quarantine",
    "decision_refused",
    "approval_execution_refused",
    "capability_gate_refused",
    "ungoverned_bypass_refused",
    "canary_trip",
    "approval_sweep_refused",
    "sandbox_traversal_contained",
})


class IncidentExportError(Exception):
    """The incident cannot be exported honestly (fail-closed)."""


class IncidentVerifyError(Exception):
    """The incident artifact failed verification."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain_hash(prev_export_hash, canonical_entry):
    return hashlib.sha256(
        EXPORT_CHAIN_DOMAIN
        + prev_export_hash.encode("utf-8") + b"\x00"
        + canonical_entry).hexdigest()


def _args_digest(entry):
    """Binding to the redacted-away attempt (pre-redaction)."""
    raw = entry.get("args", entry.get("tool_input"))
    if raw is None:
        return ""
    return hashlib.sha256(_canonical(raw)).hexdigest()


def _summarize(entry):
    """Build the shippable summary of one source entry.

    Returns (summary_dict, redacted_fields). Raw attempt/output fields
    never ship; args_digest preserves the binding.
    """
    summary = {
        "seq": entry["seq"],
        "ts": entry.get("ts", ""),
        "entry_hash": entry.get("hash", ""),
    }
    for f in _SUMMARY_FIELDS:
        if f in entry:
            summary[f] = entry[f]
    redacted = sorted(f for f in _ALWAYS_REDACT if f in entry)
    digest = _args_digest(entry)
    if digest:
        summary["args_digest"] = digest
    summary["redacted"] = bool(redacted)
    return summary, redacted


def detect_incidents(log_path, run_id=None):
    """Scan the log for incident triggers.

    Returns a list of dicts: incident_class, run_id, trigger_seq,
    trigger_ts, trigger_event, deadline_days. Sorted by trigger_seq.
    """
    entries = _log.read_entries(str(log_path))
    out = []
    for cls, spec in INCIDENT_CLASSES.items():
        for ev in spec["triggers"]:
            for e in entries:
                if e.get("event") != ev:
                    continue
                if run_id is not None and e.get("run_id") != run_id:
                    continue
                out.append({
                    "incident_class": cls,
                    "run_id": e.get("run_id", ""),
                    "trigger_seq": e["seq"],
                    "trigger_ts": e.get("ts", ""),
                    "trigger_event": ev,
                    "deadline_days": spec["deadline_days"],
                })
    out.sort(key=lambda d: d["trigger_seq"])
    return out


def _curate_causal_chain(timeline, incident_class, run_id, trigger_seq):
    """Deterministic curation of the causal chain (shared by exporter
    and verifier — the same function, so omission is checkable).

    timeline: list of summary dicts (complete window, seq order).
    Returns a list of {"seq","role","event"} in causal order, where
    role is one of policy-in-force / ancestry / trigger / containment.
    """
    spec = INCIDENT_CLASSES[incident_class]
    by_seq = {t["seq"]: t for t in timeline}
    if trigger_seq not in by_seq:
        raise IncidentExportError(
            "trigger seq %d not in timeline" % (trigger_seq,))

    # Policy in force: the latest policy_loaded at or before the trigger
    # (global — policy is deployment-scoped, not run-scoped).
    policy_seq = None
    for t in timeline:
        if t["seq"] <= trigger_seq and t.get("event") == "policy_loaded":
            policy_seq = t["seq"]

    chain = []
    if policy_seq is not None:
        chain.append({"seq": policy_seq, "role": "policy-in-force",
                      "event": "policy_loaded"})
    for t in timeline:
        s = t["seq"]
        if s >= trigger_seq:
            break
        if t.get("run_id") != run_id:
            continue
        if t.get("event") in _ANCESTRY_EVENTS:
            chain.append({"seq": s, "role": "ancestry",
                          "event": t["event"]})
    chain.append({"seq": trigger_seq, "role": "trigger",
                  "event": by_seq[trigger_seq]["event"]})
    for t in timeline:
        s = t["seq"]
        if s <= trigger_seq:
            continue
        if t.get("run_id") != run_id:
            continue
        if t.get("event") in _CONTAINMENT_EVENTS:
            chain.append({"seq": s, "role": "containment",
                          "event": t["event"]})
    # Order: policy, ancestry (seq order), trigger, containment (seq order).
    # Already in that order by construction; dedupe defensively.
    seen = set()
    deduped = []
    for item in chain:
        if item["seq"] in seen:
            continue
        seen.add(item["seq"])
        deduped.append(item)
    return deduped


def _anchor_input(incident_id, window, run_id, timeline_digest,
                  causal_digest, incident_digest, redaction_digest):
    """The exact dict the anchor receipt's statement commits to."""
    return {
        "incident_id": incident_id,
        "window": window,
        "run_id": run_id,
        "timeline_digest": timeline_digest,
        "causal_chain_digest": causal_digest,
        "incident_digest": incident_digest,
        "redaction_digest": redaction_digest,
    }

def export_incident(log_path, out_dir, adapter, *, incident_class=None,
                    run_id=None, trigger_seq=None, system=None,
                    reporter=None, harm=None, causation=None,
                    corrective=None, followup=None, narrative=None,
                    entry_signer_pubkey=None, anchor_pubkey=None,
                    incident_id=None, from_seq=None, to_seq=None):
    """Export a regulator-shaped incident report for one run.

    ``log_path``: audit-log JSONL. ``adapter``: AnchorAdapter for the
    tip anchor. ``incident_class``: key of INCIDENT_CLASSES (auto-
    detected from the run's triggers when omitted). ``run_id``: the run
    under investigation (required). ``trigger_seq``: override the onset
    entry (required for operator_declared).

    Operator-supplied sections (Art. 73 fields the engine cannot know):
    ``system`` (name/version/annex_iii/eu_db_registration/member_states),
    ``reporter`` (notifying_party/contact_person/authority),
    ``harm`` (outcome_type/persons_affected/ongoing/...),
    ``causation`` (assessment: confirmed|likely|under_investigation),
    ``corrective`` (measures list), ``followup`` (owner/milestones),
    ``narrative`` (free-text description).

    Fail-closed: broken source chain, empty log, run with no entries,
    incident class with no trigger in the run, unsigned entries, or a
    missing entry_signer_pubkey all raise IncidentExportError.
    Returns the absolute output directory path.
    """
    log_path = str(log_path)
    if not run_id:
        raise IncidentExportError("run_id is required")

    # 1. The source log must verify — never export from a broken chain.
    ok, broken, _count = _log.verify_chain(log_path)
    if not ok:
        raise IncidentExportError(
            "source log does not verify (broken at seq %r): refusing "
            "to export" % (broken,))
    entries = _log.read_entries(log_path)
    if not entries:
        raise IncidentExportError("source log is empty: nothing to export")

    run_entries = [e for e in entries if e.get("run_id") == run_id]
    if not run_entries:
        raise IncidentExportError(
            "run %r has no entries in this log: refusing to export an "
            "incident for a run that never happened" % (run_id,))

    # 2. Resolve the incident class + trigger.
    if incident_class is None:
        cands = detect_incidents(log_path, run_id=run_id)
        if not cands:
            raise IncidentExportError(
                "no incident trigger detected for run %r: pass "
                "incident_class='operator_declared' with an explicit "
                "trigger_seq" % (run_id,))
        # Earliest trigger wins: the incident's onset is the FIRST bad
        # thing that happened. A containment event that is itself a
        # trigger class (e.g. memory_quarantine) follows its onset.
        # A run with two genuinely separate incidents is exported twice
        # (incident_class= / trigger_seq= passed explicitly for the
        # second) — v1 reports one incident per export.
        chosen = cands[0]
        incident_class = chosen["incident_class"]
        trigger_seq = chosen["trigger_seq"]
    if incident_class not in INCIDENT_CLASSES:
        raise IncidentExportError(
            "unknown incident_class %r" % (incident_class,))
    spec = INCIDENT_CLASSES[incident_class]
    if trigger_seq is None:
        trig = [e for e in run_entries
                if e.get("event") in spec["triggers"]]
        if not trig:
            raise IncidentExportError(
                "incident class %r has no trigger event in run %r" %
                (incident_class, run_id))
        trigger_seq = max(e["seq"] for e in trig)
    trigger = next((e for e in entries if e["seq"] == trigger_seq), None)
    if trigger is None or trigger.get("run_id") != run_id:
        raise IncidentExportError(
            "trigger seq %d is not an entry of run %r" %
            (trigger_seq, run_id))

    # 3. Window: the run's full span (caller may narrow, never widen
    # past the run's own entries — the completeness claim is exact).
    run_seqs = sorted(e["seq"] for e in run_entries)
    lo = from_seq if from_seq is not None else run_seqs[0]
    hi = to_seq if to_seq is not None else run_seqs[-1]
    if lo < run_seqs[0] or hi > run_seqs[-1]:
        raise IncidentExportError(
            "window %d..%d exceeds run %r span %d..%d" %
            (lo, hi, run_id, run_seqs[0], run_seqs[-1]))
    window = [e for e in entries if lo <= e["seq"] <= hi]
    seqs = [e["seq"] for e in window]
    if seqs != list(range(lo, hi + 1)):
        raise IncidentExportError(
            "source log has a gap inside window %d..%d: refusing" % (lo, hi))

    # 4. Per-entry signatures required (v1, same constraint as the
    # offline bundle): the timeline's integrity story needs signed
    # source entries.
    for e in window:
        if not e.get("ed_sig") or not e.get("sig_key_id"):
            raise IncidentExportError(
                "entry seq %d has no per-entry Ed25519 signature: v1 "
                "requires a signed source log" % (e["seq"],))
    key_ids = {e["sig_key_id"] for e in window}
    if len(key_ids) != 1:
        raise IncidentExportError(
            "window spans %d entry-signer keys: v1 requires one key per "
            "incident; narrow the window" % (len(key_ids),))
    if entry_signer_pubkey is None:
        raise IncidentExportError("entry_signer_pubkey is required")
    from gov import ed25519 as _ed
    from gov.signing import ed25519_key_id
    pub = bytes(entry_signer_pubkey)
    if len(pub) != 32:
        raise IncidentExportError("entry_signer_pubkey is not 32 bytes")
    if ed25519_key_id(pub) != next(iter(key_ids)):
        raise IncidentExportError(
            "entry_signer_pubkey does not match the window's sig_key_id")
    for e in window:
        try:
            sig = bytes.fromhex(e["ed_sig"])
        except (TypeError, ValueError):
            raise IncidentExportError(
                "entry seq %d has a malformed ed_sig" % (e["seq"],))
        if not _ed.verify(pub, _log._entry_sig_body(e), sig):
            raise IncidentExportError(
                "entry seq %d: per-entry signature does not verify: "
                "refusing" % (e["seq"],))

    # 5. Summarize + redact + build the export chain over exactly what
    # ships.
    timeline = []
    field_redactions = []
    prev = EXPORT_GENESIS
    for e in window:
        summary, redacted = _summarize(e)
        if redacted:
            field_redactions.append({
                "seq": e["seq"],
                "fields": redacted,
                "sig_key_id": e["sig_key_id"],
                "note": "mandatory privacy redaction (incident export); "
                        "args_digest preserves the attempt binding",
            })
        body = {k: v for k, v in summary.items() if k != "export_hash"}
        prev = _chain_hash(prev, _canonical(body))
        summary["export_hash"] = prev
        timeline.append(summary)
    tip = prev

    # 6. Causal chain (deterministic curation).
    causal_chain = _curate_causal_chain(timeline, incident_class, run_id,
                                       trigger_seq)
    causal_digest = hashlib.sha256(
        _canonical(causal_chain)).hexdigest()
    redaction_digest = hashlib.sha256(
        _canonical(field_redactions)).hexdigest()

    # 7. Assemble the Art. 73-shaped report.
    if incident_id is None:
        incident_id = "inc-" + tip[:16]
    system = dict(system or {})
    reporter = dict(reporter or {})
    harm = dict(harm or {})
    causation = dict(causation or {})
    corrective = list(corrective or [])
    followup = dict(followup or {})

    # The policy that governed the incident: the latest policy_loaded
    # entry at or before the trigger, from the FULL log (it usually
    # predates the run's first entry and is outside the timeline
    # window; the window stays exactly the run's span so the
    # completeness claim is exact).
    policy_version = ""
    policy_digest = ""
    policy_seq = None
    for e in entries:
        if e["seq"] <= trigger_seq and e.get("event") == "policy_loaded":
            if policy_seq is None or e["seq"] > policy_seq:
                policy_seq = e["seq"]
                policy_version = str(e.get("policy_version",
                                           e.get("version", "")))
                policy_digest = str(e.get("policy_digest",
                                          e.get("digest", "")))

    # Human approvals and overrides, as a first-class list (the
    # causal chain also carries them as ancestry; this is the
    # regulator-readable roll-up).
    approvals = []
    for t in timeline:
        if t.get("event") in ("approval_decision", "approval_attempt",
                              "break_glass_used"):
            approvals.append({
                "seq": t["seq"],
                "ts": t.get("ts", ""),
                "event": t["event"],
                "approval_id": t.get("approval_id", ""),
                "decision": t.get("decision", ""),
                "tool": t.get("tool", ""),
                "agent_id": t.get("agent_id", ""),
            })

    # Agent identity + principal (Art. 50(1): the "on whose behalf"
    # disclosure). From the run's identity_minted / agent_spawn.
    agent_info = {"agent_id": "", "role": "", "principal": ""}
    for t in timeline:
        if t.get("event") == "identity_minted" and t.get("run_id") == run_id:
            agent_info = {"agent_id": t.get("agent_id", ""),
                          "role": t.get("role", ""),
                          "principal": t.get("principal", "")}
            break
    if not agent_info["agent_id"]:
        for t in timeline:
            if t.get("event") == "agent_spawn" and \
                    t.get("run_id") == run_id:
                agent_info["agent_id"] = t.get("agent_id", "")
                agent_info["role"] = t.get("role", "")
                agent_info["principal"] = t.get("principal", "")
                break

    onset_ts = trigger.get("ts", "")
    detection_ts = onset_ts  # engine-detected at trigger time (v1)
    containment = [c for c in causal_chain if c["role"] == "containment"]
    containment_ts = (by_seq_ts(timeline, containment[-1]["seq"])
                      if containment else "")

    deadline_days = spec["deadline_days"]
    if harm.get("outcome_type") == "death":
        deadline_days = 10
    # Art. 73(3): two INDEPENDENT 2-day triggers — a widespread
    # infringement (Art. 3(61)) OR a serious incident as defined in
    # Art. 3(49)(b) (serious, irreversible disruption of critical
    # infrastructure). The operator asserts which fired.
    if harm.get("critical_infrastructure") or harm.get(
            "widespread_infringement"):
        deadline_days = 2

    incident = {
        "incident_format": INCIDENT_FORMAT,
        "incident_id": incident_id,
        "exported_at": _utcnow(),
        "exporter": "gov/incident_export.py %s" % EXPORTER_VERSION,
        "regulatory_basis": {
            "regulation": "EU AI Act (Regulation (EU) 2024/1689)",
            "articles": ["73", "50"],
            "note": "Field mapping to the Art. 73 reporting template; "
                    "not legal advice. No regulator has accepted this "
                    "format.",
        },
        # --- Art. 50(1)-relevant: who acted, and on whose behalf ---
        "agent": agent_info,
        # --- human approvals and overrides (roll-up; also in the chain) ---
        "approvals": approvals,
        # --- Art. 73 §1: administrative information ---
        "reporter": {
            "notifying_party": reporter.get("notifying_party", ""),
            "notifying_role": reporter.get("notifying_role",
                                          "provider-or-deployer"),
            "contact_person": reporter.get("contact_person", ""),
            "authority": reporter.get("authority", ""),
            "awareness_ts": reporter.get("awareness_ts", _utcnow()),
            "member_states": reporter.get("member_states", []),
        },
        # --- Art. 73 §2: AI system data ---
        "system": {
            "name": system.get("name", ""),
            "version": system.get("version", ""),
            "annex_iii_category": system.get("annex_iii_category", ""),
            "eu_db_registration": system.get("eu_db_registration", ""),
            "intended_purpose": system.get("intended_purpose", ""),
            "policy_version_at_incident": policy_version,
            "policy_digest_at_incident": policy_digest,
            "policy_loaded_seq": policy_seq,
            "entry_signer_key_id": next(iter(key_ids)),
        },
        # --- Art. 73 §3: incident description ---
        "incident": {
            "class": incident_class,
            "class_description": spec["description"],
            "art3_49_outcome": spec["art3_49"],
            "run_id": run_id,
            "trigger": {"seq": trigger_seq,
                        "ts": onset_ts,
                        "event": trigger.get("event", "")},
            "onset_ts": onset_ts,
            "detection_ts": detection_ts,
            "detection_mechanism": "governance control: %s" %
                                   trigger.get("event", ""),
            "containment_ts": containment_ts,
            "narrative": narrative or "",
            "suggested_deadline_tier_days": deadline_days,
            "deadline_note": "Art. 73: 15 days general (73(2)); 2 days for "
                             "a widespread infringement OR an Art. "
                             "3(49)(b) critical-infrastructure incident "
                             "(73(3) — two independent triggers); 10 days "
                             "for death (73(4)). Suggested from class+harm; "
                             "operator confirms.",
        },
        # --- Art. 73 §3 continued: harm ---
        "harm": {
            "outcome_type": harm.get("outcome_type", ""),
            "persons_affected": harm.get("persons_affected", ""),
            "ongoing": bool(harm.get("ongoing", False)),
            "critical_infrastructure": bool(
                harm.get("critical_infrastructure", False)),
            "widespread_infringement": bool(
                harm.get("widespread_infringement", False)),
            "fundamental_rights": harm.get("fundamental_rights", ""),
            "property_environment": harm.get("property_environment", ""),
            "geographic_scope": harm.get("geographic_scope", []),
        },
        # --- Art. 73 §4: preliminary analysis ---
        "causation": {
            "assessment": causation.get("assessment",
                                        "under_investigation"),
            "root_cause_pointers": _root_cause_pointers(
                timeline, causal_chain),
            "failure_mode": causation.get("failure_mode", ""),
            "note": "Pointers reference timeline seqs; the engine states "
                    "which control fired, not why the agent chose it.",
        },
        "containment": {
            "engine_observed": [
                {"seq": c["seq"], "event": c["event"]}
                for c in containment
            ],
            "corrective_measures": corrective,
            "investigation_status": followup.get(
                "investigation_status", "open"),
        },
        "parallel_obligations": followup.get("parallel_obligations", []),
        "additional_comments": followup.get("additional_comments", ""),
        # --- evidence ---
        "causal_chain": causal_chain,
        "evidence": {
            "window": {"from_seq": lo, "to_seq": hi,
                       "entry_count": len(window)},
            "timeline_digest": tip,
            "causal_chain_digest": causal_digest,
            "completeness": {
                "claim": "the timeline lists every audit-log entry with "
                         "seq in [%d, %d]" % (lo, hi),
                "window": {"from_seq": lo, "to_seq": hi},
                "timeline_entry_count": len(timeline),
                "attested_at": _utcnow(),
                "note": "Completeness is enforced by the anchor: the "
                        "receipt's statement commits to the window and "
                        "the timeline digest. An exporter that omits an "
                        "entry changes the digest and the receipt no "
                        "longer matches.",
            },
            "redaction_report": {
                "mandatory_privacy_redactions": field_redactions,
                "entries_redacted": len(field_redactions),
                "always_redacted_fields": sorted(_ALWAYS_REDACT),
                "note": "Raw tool args / prompts / outputs never ship. "
                        "args_digest binds each summary to the redacted "
                        "attempt.",
            },
            "entry_signer": {
                "key_id": next(iter(key_ids)),
                "public_key_hex": pub.hex(),
            },
        },
        # --- Art. 73 §5: follow-up ---
        "followup": {
            "investigation_owner": followup.get("investigation_owner", ""),
            "next_milestone": followup.get("next_milestone", ""),
            "expected_supplementary_report": followup.get(
                "expected_supplementary_report", ""),
        },
        "trust": [
            "Recorded events only — the report cannot prove what was "
            "never logged.",
            "Integrity is not truth — a verified report can be a true "
            "record of a bad decision.",
            "The causal chain is a deterministic heuristic over event "
            "types (see module docstring ceiling): it can miss narrative "
            "an adversary placed in non-curated event types.",
            "Timestamps are operator wall-clock.",
            "Deadline tiers are suggestions; the operator confirms "
            "against the actual harm.",
            "Single-tenant scope; no regulator has accepted this format.",
        ],
    }

    incident_canonical = _canonical(incident)
    incident_digest = hashlib.sha256(incident_canonical).hexdigest()

    # 8. Anchor: the receipt's statement commits to everything the
    # completeness claim needs (window + digests + redaction digest).
    pubkey = anchor_pubkey
    if pubkey is None:
        pubkey = getattr(adapter, "public_key", None)
    if pubkey is None:
        raise IncidentExportError(
            "anchor adapter exposes no public key: pass anchor_pubkey= "
            "explicitly")
    pubkey = bytes(pubkey)
    if len(pubkey) != 32:
        raise IncidentExportError("anchor public key is not 32 bytes")
    anchor_input = _anchor_input(
        incident_id, incident["evidence"]["window"], run_id, tip,
        causal_digest, incident_digest, redaction_digest)
    try:
        receipt = adapter.anchor(anchor_input)
    except Exception as e:
        raise IncidentExportError("anchor refused: %s" % (e,))
    incident["evidence"]["anchor"] = {
        "adapter": adapter.name,
        "log_id": receipt.get("log_id"),
        "log_pubkey_hex": pubkey.hex(),
    }

    # 9. Write the artifact directory (deterministic file set).
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "VERSION"), "w",
              encoding="utf-8") as f:
        f.write(INCIDENT_FORMAT + "\n")
    with open(os.path.join(out_dir, "incident.json"), "w",
              encoding="utf-8") as f:
        f.write(_canonical(incident).decode("utf-8") + "\n")
    with open(os.path.join(out_dir, "timeline.jsonl"), "w",
              encoding="utf-8") as f:
        for t in timeline:
            f.write(_canonical(t).decode("utf-8") + "\n")
    with open(os.path.join(out_dir, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        f.write(_canonical(receipt).decode("utf-8") + "\n")
    digest = _transport_digest(out_dir)
    with open(os.path.join(out_dir, "INCIDENT_DIGEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")
    return os.path.abspath(out_dir)


def _transport_digest(out_dir):
    """Transport digest over the artifact file set, excluding the digest
    file itself (mirrors gov.safeguard_bundle.compute_bundle_digest,
    which only excludes its own BUNDLE_DIGEST.sha256 filename)."""
    rels = []
    for root, _dirs, names in os.walk(out_dir):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), out_dir)
            if rel == "INCIDENT_DIGEST.sha256":
                continue
            rels.append(rel)
    h = hashlib.sha256()
    for rel in sorted(rels):
        with open(os.path.join(out_dir, rel), "rb") as f:
            content = f.read()
        h.update(rel.encode("utf-8") + b"\x00" + content + b"\x00")
    return h.hexdigest()


def by_seq_ts(timeline, seq):
    for t in timeline:
        if t["seq"] == seq:
            return t.get("ts", "")
    return ""


def _root_cause_pointers(timeline, causal_chain):
    """Which control fired, with what identifier — the engine's honest
    root-cause statement."""
    by_seq = {t["seq"]: t for t in timeline}
    pointers = []
    for item in causal_chain:
        t = by_seq.get(item["seq"], {})
        p = {"seq": item["seq"], "role": item["role"],
             "event": item["event"]}
        for key in ("policy_id", "approval_id", "canary_id", "flag",
                    "tool", "decision", "agent_id"):
            if t.get(key):
                p[key] = t[key]
        pointers.append(p)
    return pointers

# ---------------------------------------------------------------------------
# Verification (operator-side; needs the repo + the operator's log key for
# the source-chain check).
# ---------------------------------------------------------------------------

def verify_incident(incident_dir, log_path=None, *,
                    entry_signer_pubkey=None, anchor_pubkey=None):
    """Verify an incident artifact.

    Checks (each returns a (name, ok, detail) finding):
      V0  format version
      T1  transport digest recomputes (INCIDENT_DIGEST)
      I1  export chain recomputes over timeline.jsonl; tip equals the
          report's timeline_digest; entry_hash linkage present
      I2  monotonicity: timeline seqs strictly increase by 1
      I3  containment: seqs exactly cover the claimed window
      R1  redaction honesty: every redacted entry is listed in the
          redaction report (fields absent); unredacted entries carry
          no unlisted redaction
      C1  causal chain recomputes deterministically from the timeline
          (omission from the chain is caught)
      C2  completeness: with log_path, the source log verifies and the
          timeline covers exactly the claimed window (omission from the
          timeline is caught); without log_path, the window claim is
          checked for internal consistency only (honest boundary)
      A1  anchor: the receipt's statement commits to THIS incident
          (window + run_id + timeline/causal/incident/redaction digests);
          the log's Ed25519 SET signature verifies; the Merkle inclusion
          proof verifies. Forged attestations fail here.

    Returns (ok, findings). Never raises on a malformed artifact —
    malformed input is a finding, not an exception (fail-closed as
    data, loud as result).
    """
    findings = []

    def _f(name, ok, detail):
        findings.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    incident_dir = str(incident_dir)

    def _read(name):
        p = os.path.join(incident_dir, name)
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

    # V0
    try:
        version = _read("VERSION").strip()
    except OSError as e:
        _f("V0", False, "VERSION unreadable: %s" % (e,))
        return False, findings
    if not _f("V0", version == INCIDENT_FORMAT,
              "format %r (want %r)" % (version, INCIDENT_FORMAT)):
        return False, findings

    # T1
    try:
        want_digest = _read("INCIDENT_DIGEST.sha256").strip()
        got_digest = _transport_digest(incident_dir)
    except Exception as e:
        _f("T1", False, "transport digest error: %s" % (e,))
        return False, findings
    if not _f("T1", got_digest == want_digest,
              "transport digest %s (want %s)" %
              (got_digest[:16], want_digest[:16])):
        return False, findings

    try:
        incident = json.loads(_read("incident.json"))
        timeline = [json.loads(l) for l in
                    _read("timeline.jsonl").splitlines() if l.strip()]
        receipt = json.loads(_read("anchor_receipt.json"))
    except (OSError, ValueError) as e:
        _f("PARSE", False, "artifact files malformed: %s" % (e,))
        return False, findings

    ev = incident.get("evidence", {})
    window = ev.get("window", {})
    lo, hi = window.get("from_seq"), window.get("to_seq")
    run_id = incident.get("incident", {}).get("run_id", "")

    # I1: export chain recompute.
    prev = EXPORT_GENESIS
    chain_ok = True
    chain_detail = ""
    for t in timeline:
        body = {k: v for k, v in t.items() if k != "export_hash"}
        prev = _chain_hash(prev, _canonical(body))
        if t.get("export_hash") != prev:
            chain_ok = False
            chain_detail = "chain broken at seq %s" % (t.get("seq"),)
            break
    if chain_ok:
        chain_detail = "%d entries, tip %s" % (len(timeline), prev[:16])
    tip_ok = _f("I1", chain_ok and prev == ev.get("timeline_digest"),
                "%s; tip matches report: %s" %
                (chain_detail, prev == ev.get("timeline_digest")))

    # I2/I3: monotonicity + containment vs the claimed window.
    seqs = [t.get("seq") for t in timeline]
    mono = all(isinstance(s, int) for s in seqs) and \
        seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    _f("I2", mono and seqs == list(range(seqs[0], seqs[-1] + 1)) if seqs
       else False,
       "seqs strictly increase by 1" if seqs else "empty timeline")
    contained = bool(seqs) and seqs[0] == lo and seqs[-1] == hi and \
        seqs == list(range(lo, hi + 1))
    _f("I3", contained,
       "timeline covers exactly [%s, %s]" % (lo, hi))

    # R1: redaction honesty.
    rr = ev.get("redaction_report", {})
    listed = {r["seq"]: set(r["fields"])
              for r in rr.get("mandatory_privacy_redactions", [])}
    r1_ok, r1_detail = True, ""
    for t in timeline:
        s = t.get("seq")
        if t.get("redacted"):
            if s not in listed:
                r1_ok = False
                r1_detail = "seq %s redacted but not listed" % (s,)
                break
            for f in listed[s]:
                if f in t:
                    r1_ok = False
                    r1_detail = ("seq %s: redacted field %r still present"
                                 % (s, f))
                    break
        elif s in listed:
            r1_ok = False
            r1_detail = "seq %s listed as redacted but not marked" % (s,)
            break
    if r1_ok:
        r1_detail = "%d redacted entries, all listed and absent" % \
            (len(listed),)
    _f("R1", r1_ok, r1_detail)

    # C1: causal chain recomputes deterministically.
    try:
        want_chain = _curate_causal_chain(
            timeline, incident["incident"]["class"], run_id,
            incident["incident"]["trigger"]["seq"])
        c1_ok = want_chain == incident.get("causal_chain")
        c1_detail = ("%d links recompute identically" % len(want_chain)
                     if c1_ok else "causal chain does not recompute: "
                     "exported chain differs from the deterministic "
                     "curation (omission or tampering)")
    except IncidentExportError as e:
        c1_ok, c1_detail = False, "curation failed: %s" % (e,)
    _f("C1", c1_ok, c1_detail)
    want_causal_digest = hashlib.sha256(
        _canonical(incident.get("causal_chain", []))).hexdigest()
    _f("C1b", want_causal_digest == ev.get("causal_chain_digest"),
       "causal digest matches" if want_causal_digest ==
       ev.get("causal_chain_digest") else "causal digest MISMATCH")

    # C2: completeness against the source log (operator-side).
    if log_path is None:
        _f("C2", True,
           "SKIPPED (no source log): window claim checked for internal "
           "consistency only — completeness against the source log needs "
           "the operator's key (honest boundary)")
    else:
        try:
            ok, broken, _n = _log.verify_chain(str(log_path))
            if not ok:
                _f("C2", False,
                   "source log does not verify (broken at %r)" % (broken,))
            else:
                src = _log.read_entries(str(log_path))
                src_window = [e["seq"] for e in src
                              if lo <= e["seq"] <= hi]
                c2_ok = src_window == list(range(lo, hi + 1))
                # Every source entry in the window must appear in the
                # timeline (by seq), and every timeline seq must exist
                # in the source window.
                c2_ok = c2_ok and set(src_window) == set(seqs)
                _f("C2", c2_ok,
                   "timeline covers the source window exactly"
                   if c2_ok else
                   "timeline/source window mismatch: omission or "
                   "injection detected")
        except Exception as e:
            _f("C2", False, "source-log check error: %s" % (e,))

    # A1: anchor authenticity.
    try:
        a1_ok, a1_detail = _verify_anchor(
            receipt, incident, ev, timeline, anchor_pubkey)
    except Exception as e:
        a1_ok, a1_detail = False, "anchor check error: %s" % (e,)
    _f("A1", a1_ok, a1_detail)

    ok_all = all(f["ok"] for f in findings)
    return ok_all, findings


def _verify_anchor(receipt, incident, ev, timeline, anchor_pubkey):
    """Check the receipt commits to this incident and is signed by the
    pinned log key. Returns (ok, detail)."""
    from gov import anchor_adapter as _aa
    from gov import ed25519 as _ed

    if not isinstance(receipt, dict):
        return False, "receipt is not an object"
    anchor = ev.get("anchor", {})
    pubkey = anchor_pubkey
    if pubkey is None:
        hp = anchor.get("log_pubkey_hex", "")
        try:
            pubkey = bytes.fromhex(hp)
        except (TypeError, ValueError):
            return False, "anchor pubkey malformed"
    if len(pubkey) != 32:
        return False, "anchor pubkey is not 32 bytes"
    if receipt.get("log_id") != hashlib.sha256(pubkey).hexdigest():
        return False, "receipt is from a different log"

    # Recompute every digest the statement commits to, from the
    # artifact itself (never trust the report's digests).
    #
    # The anchored incident_digest covers the report WITHOUT the
    # evidence.anchor field (the anchor reference itself — anchoring it
    # would be circular). The exporter computes incident_digest before
    # attaching the anchor; rebuild that exact shape here.
    prev = EXPORT_GENESIS
    for t in timeline:
        body = {k: v for k, v in t.items() if k != "export_hash"}
        prev = _chain_hash(prev, _canonical(body))
    timeline_digest = prev
    causal_digest = hashlib.sha256(
        _canonical(incident.get("causal_chain", []))).hexdigest()
    redaction_digest = hashlib.sha256(_canonical(
        ev.get("redaction_report", {}).get(
            "mandatory_privacy_redactions", []))).hexdigest()
    incident_noanchor = json.loads(json.dumps(incident))
    if isinstance(incident_noanchor.get("evidence"), dict):
        incident_noanchor["evidence"] = {
            k: v for k, v in incident_noanchor["evidence"].items()
            if k != "anchor"
        }
    incident_digest = hashlib.sha256(
        _canonical(incident_noanchor)).hexdigest()

    want_input = _anchor_input(
        incident.get("incident_id"), ev.get("window"),
        incident.get("incident", {}).get("run_id", ""),
        timeline_digest, causal_digest, incident_digest,
        redaction_digest)
    want_statement = _aa.bundle_statement(want_input)
    if receipt.get("statement") != want_statement:
        return False, ("receipt statement does not match this incident: "
                       "the attested window/digests differ (forged or "
                       "mismatched attestation)")
    stmt_hash = _aa._statement_hash(want_statement)
    if receipt.get("statement_hash") != stmt_hash:
        return False, "statement_hash mismatch"

    # SET signature over (index, root, stmt_hash).
    try:
        log_index = int(receipt["log_index"])
        root = bytes.fromhex(receipt["log_root"])
        sig = bytes.fromhex(receipt["log_sig"])
        proof = [bytes.fromhex(p)
                 for p in receipt.get("inclusion_proof", [])]
        tree_size = int(receipt.get("tree_size", 0))
    except (TypeError, ValueError, KeyError) as e:
        return False, "receipt fields malformed: %s" % (e,)
    set_body = (_aa._FAKE_SET_DOMAIN +
                ("%d|%s|%s" % (log_index, root.hex(),
                               stmt_hash)).encode("utf-8"))
    if not _ed.verify(pubkey, set_body, sig):
        return False, "anchor SET signature does not verify (forgery?)"
    # The fake log's Merkle tree stores RAW 32-byte statement hashes as
    # leaves (no leaf-domain hashing), RFC-6962-style largest-pow2
    # recursion — the same variant tools/offline-verify vendors.
    if not _raw_verify_inclusion(bytes.fromhex(stmt_hash), log_index,
                                 proof, root, tree_size):
        return False, "Merkle inclusion proof does not verify"
    return True, ("anchor verifies: statement commits to this incident, "
                  "SET signature + inclusion proof valid (index %d)" %
                  log_index)


def _mk_largest_pow2_lt(n):
    p = 1
    while 2 * p < n:
        p *= 2
    return p


def _raw_verify_inclusion(leaf32, index, proof, root, tree_size):
    """Raw-leaf Merkle inclusion (mirrors tools/offline-verify's
    vendored variant). True/False; never raises."""
    node_domain = b"gov-merkle-node/v1\x00"
    if (not isinstance(leaf32, (bytes, bytearray)) or len(leaf32) != 32
            or not isinstance(root, (bytes, bytearray))
            or len(root) != 32):
        return False
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return False
    if not (0 <= index < tree_size):
        return False
    try:
        proof = [bytes(p) for p in proof]
    except TypeError:
        return False
    if any(len(p) != 32 for p in proof):
        return False
    h = bytes(leaf32)
    pos = 0

    def rec(m, n):
        nonlocal h, pos
        if n == 1:
            return True
        if pos >= len(proof):
            return False
        k = _mk_largest_pow2_lt(n)
        sib = proof[pos]
        pos += 1
        if m < k:
            if not rec(m, k):
                return False
            h = hashlib.sha256(node_domain + h + sib).digest()
        else:
            if not rec(m - k, n - k):
                return False
            h = hashlib.sha256(node_domain + sib + h).digest()
        return True

    if not rec(index, tree_size):
        return False
    if pos != len(proof):
        return False
    return h == bytes(root)
