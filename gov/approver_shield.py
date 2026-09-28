"""GAP-3 approver integrity shield.

The approval queue hardens the gate structurally (HMAC-bound records,
separation of duties, WYSINWYS packet re-verification, cooling-off,
fatigue escalation, persuasion tripwires). This module protects the
approver's *judgment*: the research-backed attack where the agent does
not bypass the gate but CAPTURES the human -- confident misleading
summaries, a benign recipient named in the prose while the args name
another (decide-A / summarize-A' / execute-A), urgency and authority
markers (UK AISI documented an agent pressuring a maintainer into
approving malicious code).

Three parts:

1. ``shield_brief(record, ...)`` -- the independent brief, a pure
   function of the STORED record (never of agent prose): what will
   happen (tool, machine-extracted target, executor preview), risk
   tier/factors/blast radius, the capability verdict (stamped at queue
   time, or explicit "unknown"), citation-provenance verdicts for URLs
   the agent cites, persuasion tripwires, and the agent's framing
   quarantined in a labeled UNVERIFIED zone. The brief's digest is the
   MAC-bound ``packet_digest`` -- the same token the shield handshake
   acknowledges.
2. ``shield_tier(record)`` -- "capture" when manipulation signals are
   present (persuasion score >= 70, prose divergence, or critical risk
   >= 80), else "standard". Friction is proportional: only
   capture-tier approves need the handshake.
3. ``shield_challenge(record)`` / ``grade_challenge(record, answers)``
   -- three deterministic questions (option order seeded by the packet
   digest: unpredictable to the framing agent, stable for the
   approver's session). Q1 names the machine-verified target with the
   prose-claimed recipient as a distractor -- an approver who read only
   the agent's framing picks the wrong target and is refused. Q2 asks
   the governor-assigned risk tier. Q3 asks which manipulation signal
   the governor flagged.

Honest limit (stated, not solved): human approvals cannot be made
infallible. A determined, fatigued, or complicit approver who passes
the challenge on purpose is a residual -- the shield raises the bar
for *capture*, it does not certify approver virtue.

Self-contained on purpose: this module must not import gov.approvals
(the queue imports this module). Thresholds are parameters with
defaults mirroring the queue's tripwire vocabulary; the queue passes
its live constants explicitly so the two cannot drift at the
integration point.
"""

import hashlib
import hmac
import random
import re

from .citation_provenance import (
    CitationIndex,
    UNKNOWN,
    extract_urls,
    normalize_url,
    verify_citation,
)
from .log import read_entries
from .citation_provenance import upload_records_from_log_entries


SHIELD_VERSION = 1

SHIELD_TIER_STANDARD = "standard"
SHIELD_TIER_CAPTURE = "capture"

SHIELD_CHALLENGE_QUESTIONS = 3

# Defaults mirror gov.approvals' tripwire vocabulary (PERSUASION_RISK_SCORE
# = 70, COOLING_OFF_MIN_SCORE = 80). The queue passes its live constants
# explicitly; these defaults are the documented fallback.
DEFAULT_PERSUASION_RISK_SCORE = 70
DEFAULT_CRITICAL_RISK_SCORE = 80

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")

_QUARANTINE_LABEL = ("UNVERIFIED AGENT FRAMING -- the requesting agent "
                     "wrote this; the governor did not check it. Do not "
                     "treat it as fact.")


# ---------------------------------------------------------------------------
# tier
# ---------------------------------------------------------------------------

def shield_tier(record,
                persuasion_risk_score=DEFAULT_PERSUASION_RISK_SCORE,
                critical_risk_score=DEFAULT_CRITICAL_RISK_SCORE):
    """Capture tier for a stored approval record.

    "capture" when any manipulation signal is present: the persuasion
    tripwire is at/above the risk threshold, the prose names a
    different target than the action (prose_divergence), or the packet
    risk is critical. Everything else is "standard" (no shield
    friction). Pure function of stored, MAC-bound fields.
    """
    record = record or {}
    if (record.get("persuasion_score") or 0) >= persuasion_risk_score:
        return SHIELD_TIER_CAPTURE
    if record.get("prose_divergence") is not None:
        return SHIELD_TIER_CAPTURE
    if (record.get("packet_risk_score") or 0) >= critical_risk_score:
        return SHIELD_TIER_CAPTURE
    return SHIELD_TIER_STANDARD


def is_capture_tier(record):
    """True when ``record`` carries the capture tier.

    Single predicate for the tier check so the queue, the batch
    driver, and the CLI share one definition of "this approval needs
    the shield handshake".
    """
    return (record or {}).get("shield_tier") == SHIELD_TIER_CAPTURE


# ---------------------------------------------------------------------------
# machine view (local extractors; mirror gov.approvals' packet helpers
# without importing the queue module)
# ---------------------------------------------------------------------------

def _machine_target(record):
    """The machine-extracted target of the action (never agent prose)."""
    args = record.get("args") or {}
    tool = record.get("tool")
    for key in ("to", "url", "endpoint", "path", "window", "recipient",
                "destination"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    for val in args.values():
        if isinstance(val, str) and val:
            return val[:120]
    return "(no scalar target: %s)" % (tool,)


def _risk_tier_label(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    if score < 30:
        return "low"
    if score < 60:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def _claimed_addresses(text):
    return [m.group(0) for m in _EMAIL_RE.finditer(str(text or ""))]


# ---------------------------------------------------------------------------
# the independent brief
# ---------------------------------------------------------------------------

def shield_brief(record, *, citation_index=None, citing_identity=None,
                 packet=None):
    """Build the approver-facing independent brief.

    Pure function of the stored record (+ an optional citation index
    and the precomputed canonical packet when the caller has it). The
    agent's justification appears ONLY in the quarantine zone, labeled
    UNVERIFIED. Capability is reported as stamped at queue time, or as
    explicit "unknown" -- silence never implies "fine".
    """
    record = record or {}
    packet = packet or {}
    score = record.get("packet_risk_score") or 0
    justification = record.get("agent_justification") or ""
    preview = record.get("preview") or ""

    cap_verdict = record.get("capability_verdict")
    if cap_verdict:
        capability = {"verdict": str(cap_verdict), "note": (
            "capability signal stamped at queue time")}
    else:
        capability = {"verdict": "unknown", "note": (
            "no capability signal stamped at queue time -- the governor "
            "cannot say whether the requesting agent was assessed; "
            "treat absence of evidence as absence of assurance")}

    citations = _brief_citations(
        record, justification, preview,
        citation_index=citation_index, citing_identity=citing_identity)

    blast = list(packet.get("blast_radius") or [])
    markers = list(record.get("persuasion_markers") or [])

    return {
        "shield_version": SHIELD_VERSION,
        "approval_id": record.get("id"),
        "tier": record.get("shield_tier") or shield_tier(record),
        # The ack token: the approver acknowledges THIS digest, and the
        # queue's packet re-verification guarantees it is current.
        "packet_digest": record.get("packet_digest"),
        "action": {
            "tool": record.get("tool"),
            "target": packet.get("target") or _machine_target(record),
            # F190: the bound canonical target the receipt MAC-binds,
            # shown alongside the declared target.
            "canonical_target": packet.get("canonical_target"),
            "executor_preview": preview,
            "requested_by": {
                "agent_id": record.get("agent_id"),
                "role": record.get("role"),
                "principal": record.get("principal"),
            },
        },
        "risk": {
            "tier": packet.get("risk_tier") or _risk_tier_label(score),
            "score": score,
            "factors": list(record.get("packet_risk_factors") or []),
            "blast_radius": blast,
        },
        "capability": capability,
        "citations": citations,
        "persuasion": {
            "score": record.get("persuasion_score") or 0,
            "markers": markers,
            "prose_divergence": record.get("prose_divergence"),
            "note": ("manipulation tripwires: heuristic, bypassable by a "
                     "careful adversary by construction -- they raise the "
                     "cost of capture, they do not certify honesty"),
        },
        "quarantine": {
            "label": _QUARANTINE_LABEL,
            "justification": justification,
        },
    }


def _brief_citations(record, justification, preview, *,
                     citation_index=None, citing_identity=None):
    """Citation-provenance verdicts for URLs the agent cites.

    Every URL extracted from the agent's framing (and the preview) is
    checked with verify_citation. No index -- or no URLs -- yields an
    explicit "unknown", never a clean bill of health.
    """
    urls = extract_urls("%s\n%s" % (justification, preview))
    args = record.get("args") or {}
    for val in args.values():
        if isinstance(val, str):
            for u in extract_urls(val):
                if u not in urls:
                    urls.append(u)
    out = []
    for url in urls:
        if citation_index is None:
            out.append({
                "url": url,
                "url_normalized": normalize_url(url),
                "verdict": UNKNOWN,
                "reason": ("no citation index available: unverifiable -- "
                           "not a clean bill of health"),
            })
            continue
        try:
            res = verify_citation(url, citing_identity,
                                  index=citation_index)
        except Exception as e:
            out.append({
                "url": url,
                "url_normalized": normalize_url(url),
                "verdict": UNKNOWN,
                "reason": "citation check failed: %s" % e,
            })
            continue
        out.append({
            "url": res.get("url"),
            "url_normalized": res.get("url_normalized"),
            "verdict": res.get("verdict"),
            "reason": res.get("reason"),
            "same_principal": res.get("same_principal"),
            "same_agent": res.get("same_agent"),
        })
    return out


def citation_index_for_log(log_path):
    """Build a CitationIndex from a chained action-log path.

    Lets the brief (or the CLI) check agent-cited URLs against the
    run's governed upload records.
    """
    idx = CitationIndex()
    try:
        entries = list(read_entries(str(log_path)))
    except Exception:
        entries = []
    idx.add_upload_records(upload_records_from_log_entries(entries))
    return idx


# ---------------------------------------------------------------------------
# shield_ack
# ---------------------------------------------------------------------------

def shield_ack_ok(record, shield_ack):
    """Does the presented ack match the record's current packet digest?

    The ack proves the approver rendered the brief for THIS packet;
    the queue's packet re-verification (decide time) guarantees the
    packet is the one that was displayed. Constant-time compare on
    principle; a missing/foreign ack fails closed.
    """
    want = (record or {}).get("packet_digest") or ""
    got = shield_ack if isinstance(shield_ack, str) else ""
    if not want or not got:
        return False
    return hmac.compare_digest(want, got)


# ---------------------------------------------------------------------------
# the randomized challenge
# ---------------------------------------------------------------------------

def _challenge_rng(record):
    """Deterministic RNG seeded by the packet digest.

    Stable for the approver's session; unpredictable to the agent that
    authored the framing (the digest is MAC-bound after queueing and
    the agent never sees it in advance).
    """
    seed = hashlib.sha256(
        str((record or {}).get("packet_digest") or "").encode("utf-8")
    ).hexdigest()
    return random.Random(seed)


def shield_challenge(record, *, packet=None,
                     persuasion_risk_score=DEFAULT_PERSUASION_RISK_SCORE,
                     critical_risk_score=DEFAULT_CRITICAL_RISK_SCORE):
    """Three engagement questions derived from the stored record.

    Returns a list of ``{"id", "question", "options", "answer"}``;
    ``answer`` is the index of the correct option AFTER shuffling.
    Deterministic per record.
    """
    record = record or {}
    packet = packet or {}
    rng = _challenge_rng(record)
    target = packet.get("target") or _machine_target(record)
    score = record.get("packet_risk_score") or 0
    tier = packet.get("risk_tier") or _risk_tier_label(score)
    justification = record.get("agent_justification") or ""

    questions = [_target_question(target, justification, rng),
                 _tier_question(tier, rng),
                 _signal_question(record, packet, rng)]
    return questions


def _shuffled(rng, correct, distractors, n_options=4):
    options = [correct]
    for d in distractors:
        if d != correct and d not in options:
            options.append(d)
        if len(options) >= n_options:
            break
    while len(options) < n_options:
        options.append("(none of the above)")
    rng.shuffle(options)
    return options, options.index(correct)


def _target_question(target, justification, rng):
    # The prose-claimed recipient is a distractor: an approver who read
    # only the agent's framing picks it and is refused. This is the
    # direct counter to decide-A / summarize-A' / execute-A.
    claimed = [c for c in _claimed_addresses(justification)
               if c.lower() != str(target).lower()]
    distractors = []
    if claimed:
        distractors.append(claimed[0])
    distractors += ["(no specific target)",
                    "whatever the agent's summary names"]
    options, answer = _shuffled(rng, str(target), distractors)
    return {
        "id": "target",
        "question": ("What is the MACHINE-VERIFIED target of this action "
                     "(not what the agent's summary claims)?"),
        "options": options,
        "answer": answer,
    }


def _tier_question(tier, rng):
    options, answer = _shuffled(
        rng, tier, ["low", "medium", "high", "critical"])
    return {
        "id": "risk_tier",
        "question": "What risk tier did the GOVERNOR assign this action?",
        "options": options,
        "answer": answer,
    }


def _signal_question(record, packet, rng):
    signals = []
    for hint in (packet.get("blast_radius") or []):
        signals.append(str(hint))
    for marker in (record.get("persuasion_markers") or [])[:2]:
        signals.append("persuasion marker: %s" % marker)
    if record.get("prose_divergence"):
        signals.append("agent prose contradicts the action target")
    if signals:
        correct = signals[0]
        distractors = signals[1:3] + ["no manipulation signals flagged"]
    else:
        correct = "no manipulation signals flagged"
        distractors = ["high persuasion markers in agent prose",
                       "agent prose contradicts the action target",
                       "secret-like material in arguments"]
    options, answer = _shuffled(rng, correct, distractors)
    return {
        "id": "manipulation_signal",
        "question": ("Which manipulation signal did the GOVERNOR flag on "
                     "this approval?"),
        "options": options,
        "answer": answer,
    }


def grade_challenge(record, answers, *, packet=None):
    """Grade a challenge attempt. Returns (ok, detail).

    Never raises on malformed input -- a malformed attempt is a failed
    attempt (fail closed at the caller). All questions must be correct.
    """
    try:
        questions = shield_challenge(record, packet=packet)
    except Exception as e:
        return False, "challenge could not be built: %s" % e
    if not isinstance(answers, (list, tuple)):
        return False, "challenge answers must be a list of option indices"
    if len(answers) != len(questions):
        return False, ("expected %d answers, got %d"
                       % (len(questions), len(answers)))
    wrong = []
    for q, a in zip(questions, answers):
        try:
            chosen = int(a)
        except (TypeError, ValueError):
            chosen = None
        if chosen != q["answer"]:
            wrong.append(q["id"])
    if wrong:
        return False, ("challenge failed on: %s (the approver did not "
                       "demonstrate engagement with the independent "
                       "signals)" % ", ".join(wrong))
    return True, ("challenge passed (%d/%d): the approver demonstrated "
                  "engagement with the independent signals"
                  % (len(questions), len(questions)))
