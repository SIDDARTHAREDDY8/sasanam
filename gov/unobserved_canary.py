"""Row-13 unobserved-canary egress detection (wave-143 lane).

Measured residual: reads that happen out-of-band (not through the
governed ``read_file``) are invisible to the rare-token tracker -- the
tracker only knows about explicitly observed reads. A canary value
egressed with NO recorded governed read of its source document is the
detectable shape: the canary tripwire (gov/canary.py) already catches
the VALUE at the egress seam; this module adds the READ-side
distinction.

REGISTRY PRIVACY CONTRACT -- READ THIS BEFORE TOUCHING THE REGISTRY:
The canary registry (``gov.canary.CanaryRegistry``) holds ONLY planted
FAKE values. **It must never hold real secrets.** Canaries are
non-sensitive by design (honeytokens: realistic-but-fake, per-run
rotated, never valid credentials or reachable hosts), and every
consumer of the registry -- this module included -- treats its
contents as attacker-visible. Do NOT register real credentials, real
hostnames, real tokens, or any other real secret material here, ever.
A real secret in this registry would be scanned for on every egress
and named (by label) in audit events -- the opposite of the
taint ledger's blinded-commitment discipline (gov/taint_ledger.py),
which exists precisely because real content must never sit in a
detection registry.

Design
------
- On a canary hit at the egress seam, :func:`has_recorded_read`
  asks whether the agent has a recorded read covering the canary's
  source artifact (``gov.canary.CANARY_LABEL_ARTIFACTS``): the
  per-run tracker's recorded source ids (ALL reads, including
  zero-rare-token reads -- the in-run tracker stores every
  observation), plus -- when the tracker has a taint ledger
  attached -- the ledger's live document ids (cross-run; doc ids
  and counts only, never token strings).
- No recorded read -> :func:`trip_unobserved`: a LOUD
  ``unobserved_canary_egress`` audit event (a distinct event type
  from ``canary_trip``), approval-queue escalation, and
  ``CanaryTripHalt`` -- the SAME fail-closed halt the existing
  canary trip uses. Rationale: a canary value is never a legitimate
  credential, so an unread canary on the egress path is
  exfiltration intent by construction -- if anything MORE
  suspicious than the read case (out-of-band acquisition), so
  flag-and-proceed would be a downgrade. The executor's
  persistent-halt machinery (flag + marker file + restart
  persistence) applies unchanged.
- Recorded read -> the existing ``canary_trip`` path handles it;
  no duplicate unobserved event is emitted.

Wiring: ``gov.canary.check_and_trip`` branches here (local import --
no import cycle) when the executor has a rare-token tracker
installed. Without a tracker the read/unread distinction cannot be
drawn, so hits keep the existing ``canary_trip`` path (zero behavior
change vs wave-51).

Honest ceilings (documented, not hidden):
- Exact-only value matching: a canary paraphrased beyond recognition
  misses (same residual class as DLP F8 and the row-13
  prose-paraphrase class) -- fuzzy matching is out of scope.
- An exfil channel the egress proxy never sees is still invisible:
  the scan runs on the governed egress-attempt path, not on the
  wire.
- The taint-ledger consult covers token-bearing reads only (the
  ledger never records zero-token reads); the per-run consult
  covers every recorded read.
- Registry TTL/purge semantics are operator policy: the registry is
  per-run and rotation bounds its lifetime; the cross-run document
  ids inherit the taint ledger's TTL.
- Source-id matching is artifact-path based: a recorded read of a
  different same-named artifact (e.g. another ``.env`` elsewhere in
  the jail) misattributes toward "recorded" -- the benign direction
  (the existing LOUD ``canary_trip`` still fires and still halts).

$0, stdlib only, deterministic.
"""

from .canary import CANARY_LABEL_ARTIFACTS, CanaryTripHalt
from .policy import PolicyDecision

__all__ = [
    "has_recorded_read",
    "trip_unobserved",
    "source_artifacts_for",
]


def source_artifacts_for(label):
    """Jail-relative artifact paths a canary label was planted into.

    Empty tuple = registered tripwire-only (never planted in the
    jail): no governed read of it can ever exist, so a hit is
    unobserved by construction.
    """
    return CANARY_LABEL_ARTIFACTS.get(label, ())


def _covers(source_id, rel):
    """Does a recorded read source id cover a planted artifact path?

    Normalizes the wave-141 auto form ``read:auto:<rel>`` and matches
    exact or '/'-suffixed paths. Benign misattribution direction: a
    same-named artifact elsewhere in the jail counts as recorded --
    the existing ``canary_trip`` still fires LOUD and still halts.
    """
    sid = str(source_id).strip()
    if sid.startswith("read:auto:"):
        sid = sid[len("read:auto:"):]
    sid = sid.strip()
    if sid.startswith("./"):
        sid = sid[2:]
    rel = rel.strip().lstrip("/")
    return sid == rel or sid.endswith("/" + rel)


def has_recorded_read(tracker, agent_id, hit):
    """True when the agent has a recorded read of the hit canary's
    source document.

    ``tracker`` is the executor's ``RareTokenTracker`` (or None).
    Consults the per-run recorded source ids (every read, including
    zero-rare-token reads) and -- when a taint ledger is attached --
    the ledger's live document ids (cross-run; doc ids only, never
    token strings). A None tracker or a tripwire-only label (never
    planted) -> False. Any query failure (damaged ledger, broken
    tracker) yields no records, i.e. the unobserved (halting) path:
    fail-closed, never a silent exception past the tripwire.
    """
    if tracker is None or not isinstance(hit, dict):
        return False
    artifacts = source_artifacts_for(hit.get("label"))
    if not artifacts:
        # Registered tripwire-only: never planted, so no governed
        # read can exist -- unobserved by construction.
        return False
    try:
        seen = set(tracker.observed_source_ids(str(agent_id)))
    except Exception:
        return False  # query failure -> unobserved (fail-closed halt)
    try:
        seen.update(tracker.durable_source_ids(str(agent_id)))
    except Exception:
        pass  # no durable records -> unobserved path (fail-closed halt)
    return any(_covers(sid, rel) for sid in seen for rel in artifacts)


def trip_unobserved(executor, identity, tool, args, hit):
    """Unobserved-canary trip: LOUD event, escalation, fail-closed halt.

    Same blocking semantics as :func:`gov.canary.check_and_trip`
    (raises ``CanaryTripHalt``; the executor's persistent-halt
    machinery applies unchanged) with a DISTINCT audit event type
    (``unobserved_canary_egress`` / flag ``unobserved_canary_egress``)
    so operators can separate out-of-band acquisition from observed
    reads. The event carries the canary label/kind/matched field --
    never the matched value.
    """
    run_id = getattr(executor, "run_id", "?")
    agent_id = getattr(identity, "agent_id", "?")
    principal = getattr(identity, "principal", "?")
    artifacts = source_artifacts_for(hit.get("label"))
    reason = (
        "Unobserved canary egress: agent %s (principal %s) attempted "
        "egress via %s using a planted canary %s (%s) in %s with NO "
        "recorded governed read of the canary's source document (%s). "
        "The read happened out-of-band -- detection without "
        "observation. Canaries are never valid credentials or "
        "reachable hosts, so this is exfiltration intent by "
        "construction. Run halted fail-closed; escalated for human "
        "review."
        % (agent_id, principal, tool, hit.get("kind"),
           hit.get("label"), hit.get("field"),
           ",".join(artifacts) if artifacts else "<never planted>"))

    # (1) LOUD audit event -- distinct type, evidence attached, no value.
    try:
        executor.log.append({
            "event": "unobserved_canary_egress",
            "run_id": run_id,
            "agent_id": agent_id,
            "role": getattr(identity, "role", "?"),
            "principal": principal,
            "tool": tool,
            "decision": "halted",
            "policy_id": "canary-tripwire-unobserved",
            "flag": "unobserved_canary_egress",
            "canary_kind": hit.get("kind"),
            "canary_label": hit.get("label"),
            "matched_field": hit.get("field"),
            "recorded_read": False,
            "source_artifacts": list(artifacts),
            "reason": reason,
        })
    except Exception:
        pass  # the halt below is the control; audit is best-effort

    # (2) approval-queue escalation with the trip evidence (mirrors
    # the existing canary trip).
    try:
        decision = PolicyDecision(
            "require_approval", reason,
            policy_id="canary-tripwire-unobserved",
            flag="unobserved_canary_egress")
        action = {"tool": tool, "args": args,
                  "identity": identity.as_dict(),
                  "agent_justification": None, "redactions": []}
        preview = executor._preview(tool, args)
        egress_bytes = 0
        _ebf = getattr(executor, "_egress_bytes_for", None)
        if callable(_ebf):
            try:
                egress_bytes = _ebf(tool, args)
            except Exception:
                egress_bytes = 0
        executor.approvals.queue(
            action, decision, "agent_direct", preview,
            policy_hash=executor.policy.policy_hash,
            policy_flag="unobserved_canary_egress",
            egress_bytes=egress_bytes,
            caller_identity=identity)
    except Exception:
        pass  # fail-closed: queue failure must not un-halt

    # (3) halt -- never executes the call. Same exception as the
    # existing canary trip, so the executor's persistent-halt
    # machinery (flag + marker file + restart persistence) applies
    # unchanged.
    raise CanaryTripHalt(reason)
