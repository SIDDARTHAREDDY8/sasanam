"""Population-level prompt-infection monitor (S2, wave-89).

Per-agent input validation cannot see self-replicating prompts: each
hop is individually benign, so the control must live at the population
level. This monitor observes governed message sends (hooked via the
MessageBus ``notify`` callback) and looks for the replication
signature: near-duplicate payload content appearing across DISTINCT
senders inside a bounded window.

- Normalized exact-match fast path (sha256 of normalized text).
- Shingle-Jaccard >= 0.85 slow path for paraphrase-near-duplicates.
- Threshold: >= 3 distinct senders in-window -> ``infection_suspected``
  chained event + AUTO-quarantine of the origin lineage (the earliest
  sender). Auto, not human-gated, deliberately: Morris-II-class spread
  is exponential and outruns any approval queue; the quarantine is
  reversible (bus.release) and every step is chained.
- Benign operational types (``status``) are EXCLUDED from counting:
  identical heartbeats must never auto-quarantine a fleet.

Honest boundary: this detects replication, not malice. A payload that
rephrases itself below the Jaccard threshold per hop (semantic
paraphrase ladder) is NOT detected -- the battery asserts that
boundary rather than claiming otherwise. Steganographic coordination
that never repeats content is also out of scope (see
gov/messaging.py's ceiling note).
"""

import hashlib
import re
from collections import deque

_JACCARD_THRESHOLD = 0.85
_MIN_SENDERS = 3
_WINDOW_SIZE = 100  # recent messages examined per send
_SHINGLE_K = 5
_EXCLUDED_TYPES = ("status",)  # benign operational chatter


def _normalize(text):
    return re.sub(r"\s+", " ", text).strip().lower()


def _shingles(text, k=_SHINGLE_K):
    words = _normalize(text).split()
    if len(words) < k:
        return {tuple(words)} if words else set()
    return {tuple(words[i:i + k]) for i in range(len(words) - k + 1)}


def _jaccard(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _text_of(canonical):
    try:
        return canonical.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - never break the monitor on decode
        return ""


class InfectionMonitor(object):
    """Watches MessageBus sends for cross-sender replication."""

    def __init__(self, bus, log):
        self._bus = bus
        self._log = log
        self._recent = deque(maxlen=_WINDOW_SIZE)  # (sender, norm_hash, shingles, msg_id)
        self._fired = set()  # norm_hash values already escalated

    def observe(self, record):
        """MessageBus notify callback. ``record`` has msg_id, stamp,
        canonical."""
        stamp = record["stamp"]
        if stamp.get("msg_type") in _EXCLUDED_TYPES:
            return
        sender = stamp["sender"]
        text = _text_of(record["canonical"])
        norm = _normalize(text)
        if not norm:
            return
        norm_hash = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        shingles = _shingles(text)
        # Fast path: exact normalized duplicates across senders.
        same = [r for r in self._recent if r[1] == norm_hash]
        ordered = []
        for r in same:
            if r[0] not in ordered:
                ordered.append(r[0])
        if sender not in ordered:
            ordered.append(sender)
        if len(ordered) >= _MIN_SENDERS and norm_hash not in self._fired:
            self._escalate(sender, record["msg_id"], "exact_replication",
                           ordered, norm_hash)
            return
        # Slow path: near-duplicate (paraphrase) across senders.
        near_ordered = [sender]
        for other_sender, _oh, o_shingles, _om in self._recent:
            if other_sender == sender or other_sender in near_ordered:
                continue
            if _jaccard(shingles, o_shingles) >= _JACCARD_THRESHOLD:
                near_ordered.append(other_sender)
        # Anchor on a stable signature so we fire once per campaign.
        anchor = norm_hash
        if len(near_ordered) >= _MIN_SENDERS and anchor not in self._fired:
            self._escalate(sender, record["msg_id"],
                           "near_duplicate_replication",
                           near_ordered, anchor)
            return
        self._recent.append((sender, norm_hash, shingles, record["msg_id"]))

    def _escalate(self, sender, msg_id, kind, ordered_senders, anchor):
        self._fired.add(anchor)
        senders = ordered_senders  # observation order: [0] is the origin
        self._log.append({
            "event": "infection_suspected",
            "run_id": self._bus._run_dir.name,
            "agent_id": sender,
            "decision": "escalated",
            "policy_id": "infection-monitor",
            "flag": "infection_suspected",
            "reason": ("%s: payload replicated across %d distinct senders "
                       "(%s); auto-quarantining origin lineage" %
                       (kind, len(senders), ",".join(sorted(senders)))),
            "senders": sorted(senders),
            "msg_id": msg_id,
        })
        # Auto-quarantine the ORIGIN lineage: the earliest observed sender
        # of this campaign. Reversible via bus.release(); every step chained.
        from .. import messaging as _m  # local import: avoid cycles
        _m.LineageQuarantine.quarantine_origin(
            senders[0],
            "infection_suspected (%s) across %d senders" % (kind, len(senders)),
            self._bus)
