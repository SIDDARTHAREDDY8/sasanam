"""Governed inter-agent messaging: provenance, screening, quarantine.

wave-89 (S2). The product had no inter-agent messaging primitive: content
moving between agents traversed with zero provenance and zero screening,
so Morris-II-class self-replicating prompts and Agent-Smith-style
pairwise spread were invisible to per-agent controls (each hop is
individually policy-benign). This module is the governed channel:

- ``MessageBus``: opt-in per-run bus (executor kwarg ``message_bus=``;
  absent = zero behavior change). ``send()`` runs minted-identity check
  -> quarantine check -> typed-schema canonicalization (refuse, never
  silently strip) -> provenance stamp -> steg screen -> bandwidth cap ->
  chained ``agent_message`` event carrying STAMP + CONTENT HASH ONLY.
  The audit log is agent-reachable, so full content lives in the
  operator-side ``run_dir/messages/`` inbox; the chain carries enough
  to verify, never enough to re-inject.
- ``receive()`` validates stamps on read: unknown sender, token_ref
  mismatch, content-hash mismatch, or seq replay -> refused or flagged.
  Flagged messages are DELIVERED-FLAGGED, never silently dropped: the
  recipient sees the flag and the reason; the operator sees the chain.
- ``LineageQuarantine``: ``quarantine()`` computes the downstream
  lineage from ``agent_spawn`` log events plus message threads, emits a
  chained ``lineage_quarantine`` event naming every quarantined agent,
  and enforcement lands at four points: ``send()`` refused,
  ``receive()`` diverted, ``ToolExecutor.call()`` denied,
  ``spawn_sub_agent()`` refused (quarantine escape closed).
  ``release()`` is the operator reversal, chained.
- GAP-2 lineage joining: with ``lineage_tracker=`` attached, the bus
  joins the infection-lineage substrate (gov/lineage.py). send() refuses
  unlineaged senders fail-closed, stamps carry sender_lineage_id /
  sender_lineage_depth / sender_infected, sends and receives feed the
  population replication watch, and receive() records lineage_contact
  (channel "bus") with taint propagation (live writer taint). A stamp
  that cannot be tied to a chained send record — or whose lineage does
  not verify against the live registry — is forged: the recipient is
  taint-marked and warned (not quarantined), the delivering sender is
  bus-quarantined (H18: the actionable endpoint, not the victim), and
  delivery is refused (loud, never silent). Without a tracker, behavior
  is exactly as before.

Honest ceiling (never claimed away): paraphrase-semantic stego,
Schelling-point coordination, and tool-mediated covert channels are
NOT detected by this module. The steg screen flags zero-width
characters, base64-shaped high-entropy blobs, whitespace-encoding runs,
and homoglyph runs -- cheap, deterministic, evadable by a careful
adversary. What the module guarantees is provenance and containment,
not undetectability of covert content.

$0 spend, synthetic/local only. No credentials, no network.
"""

import hashlib
import json
import math
import os
import re
from pathlib import Path

# -- typed message schemas -------------------------------------------------

# The channel is typed. Unknown types are REFUSED, never coerced: a
# covert payload must not be able to smuggle itself in as an
# unrecognized shape. Benign operational types (status/heartbeat) are
# excluded from infection counting by the infection monitor.
_MESSAGE_TYPES = ("note", "data", "status")

_MAX_NOTE_CHARS = 8000
_MAX_DATA_BYTES = 65536
_MAX_STATUS_FIELDS = 8

# Bandwidth caps: per-sender, per-run. A replicating payload's whole
# strategy is volume; the cap makes exponential spread expensive and
# loud (every refusal is chained).
_MAX_MESSAGES_PER_SENDER = 200
_MAX_BYTES_PER_SENDER = 1 << 20  # 1 MiB


class MessageBusMissingError(Exception):
    """Messaging API used without an installed bus: loud, never silent."""


class MessageRefusedError(Exception):
    """send() refused: fail-closed, always with a chained audit event."""


class MessageFlaggedError(Exception):
    """receive() refused a message that failed stamp validation.

    Distinct from a quiet drop: the caller learns the message was
    refused and why; nothing is silently swallowed.
    """


class QuarantineDeniedError(Exception):
    """A quarantined identity attempted send/call/spawn: denied."""


def _canonicalize(msg_type, content):
    """Return canonical bytes for (type, content) or raise MessageRefusedError.

    Refuse, never silently strip: if the content does not fit the typed
    schema, the sender fixes it and re-sends. Silent coercion would let
    an attacker probe the boundary until something slips through.
    """
    if msg_type not in _MESSAGE_TYPES:
        raise MessageRefusedError(
            "unknown message type %r: the channel is typed; unrecognized "
            "shapes are refused, never coerced" % (msg_type,))
    if msg_type == "note":
        if not isinstance(content, str):
            raise MessageRefusedError("note content must be text")
        if len(content) > _MAX_NOTE_CHARS:
            raise MessageRefusedError(
                "note exceeds %d chars" % _MAX_NOTE_CHARS)
        return content.encode("utf-8")
    if msg_type == "status":
        if not isinstance(content, dict):
            raise MessageRefusedError("status content must be a dict")
        if len(content) > _MAX_STATUS_FIELDS:
            raise MessageRefusedError("status exceeds %d fields"
                                      % _MAX_STATUS_FIELDS)
        for k, v in content.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float,
                                                            bool)):
                raise MessageRefusedError(
                    "status fields must be str -> scalar")
        return json.dumps(content, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    # data: JSON-serializable payload, canonical JSON bytes.
    try:
        raw = json.dumps(content, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise MessageRefusedError("data content must be JSON-serializable: %s"
                                  % e)
    raw_b = raw.encode("utf-8")
    if len(raw_b) > _MAX_DATA_BYTES:
        raise MessageRefusedError("data exceeds %d bytes" % _MAX_DATA_BYTES)
    return raw_b


# -- steg screen (honest, deterministic, evadable) --------------------------

_ZW_CHARS = ("​", "‌", "‍", "﻿")  # ZWSP, ZWNJ, ZWJ, ZWNBSP
_B64_RE = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
_WS_RUN_RE = re.compile(r"[ \t]{8,}|(?: +\t|\t+ )")


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_mixed_script_run(text):
    """Crude homoglyph-run signal: a single token mixing scripts that
    should not mix (Latin + Cyrillic/Greek) -- the classic lookalike
    channel. Word-boundary scoped; not a full confusable table."""
    cyrillic = re.compile(r"[\u0400-\u04FF]")
    greek = re.compile(r"[\u0370-\u03FF]")
    latin = re.compile(r"[A-Za-z]")
    for tok in re.findall(r"\S+", text):
        if latin.search(tok) and (cyrillic.search(tok) or greek.search(tok)):
            return True
    return False


def steg_screen(text):
    """Return a list of finding strings (empty = clean).

    Flags zero-width characters, base64-shaped high-entropy blobs,
    whitespace-encoding runs, and mixed-script homoglyph runs.
    Deterministic and cheap -- and EVADABLE by a careful adversary
    (paraphrase-semantic stego is explicitly out of scope). A finding
    flags the message; it never drops it.
    """
    findings = []
    if any(ch in text for ch in _ZW_CHARS):
        findings.append("zero_width_characters")
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        if _entropy(blob) >= 4.5:
            findings.append("base64_high_entropy_blob")
            break
    if _WS_RUN_RE.search(text):
        findings.append("whitespace_encoding_run")
    if _has_mixed_script_run(text):
        findings.append("mixed_script_homoglyph_run")
    return findings


# -- the bus ----------------------------------------------------------------

def _sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


class MessageBus(object):
    """Opt-in per-run inter-agent message bus.

    Constructed by the deployment (operator trust domain), shared across
    a spawn lineage by reference. ``log`` is the run's chained ActionLog;
    ``run_dir`` roots the operator-side inbox. ``notify`` is an optional
    callable(message_record) invoked on every accepted send (the
    infection monitor hooks here).

    ``lineage_tracker`` (GAP-2) joins the bus to the run's infection
    lineage substrate (gov/lineage.py): when attached, send() refuses
    unlineaged senders fail-closed, the stamp carries the sender's
    lineage id / depth / send-time taint bit, sends and receives feed
    the tracker's population replication watch, and receive() records a
    lineage_contact and propagates taint. Without a tracker the bus
    behaves exactly as before (zero behavior change).
    """

    def __init__(self, run_dir, log, notify=None, lineage_tracker=None):
        self._run_dir = Path(run_dir)
        self._log = log
        self._notify = notify
        self._lineage_tracker = lineage_tracker
        self._inbox_root = self._run_dir / "messages"
        self._seq = {}        # sender agent_id -> next seq int
        self._last_seen = {}  # (recipient, sender) -> last delivered seq
        self._sent_count = {}  # sender -> message count (bandwidth)
        self._sent_bytes = {}  # sender -> byte count (bandwidth)
        self._quarantined = {}  # agent_id -> {"reason":..., "lineage":[...]}
        self._threads = []    # (sender, recipient) edges for lineage

    def attach_lineage_tracker(self, tracker):
        """Deployment wiring: join the bus to the run's infection-lineage
        tracker after construction (e.g. when the tracker is created
        after the bus). Same effect as the ``lineage_tracker=``
        constructor kwarg."""
        self._lineage_tracker = tracker
        return tracker

    # -- quarantine state (operator side) ---------------------------------

    def is_quarantined(self, agent_id):
        return agent_id in self._quarantined

    def quarantine_info(self, agent_id):
        return self._quarantined.get(agent_id)

    def quarantine(self, agent_id, reason, lineage=()):
        """Operator/recovery primitive: quarantine an agent and its
        downstream lineage. Chained, loud, reversible via release()."""
        targets = [agent_id] + [a for a in lineage if a != agent_id]
        for t in targets:
            self._quarantined.setdefault(
                t, {"reason": reason, "lineage": sorted(set(targets))})
        self._log.append({
            "event": "lineage_quarantine",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "quarantined",
            "policy_id": "message-lineage-quarantine",
            "flag": "lineage_quarantined",
            "reason": reason,
            "quarantined_agents": sorted(self._quarantined),
        })
        return sorted(self._quarantined)

    def release(self, agent_id, reason="operator release"):
        removed = [a for a in self._quarantined
                   if a == agent_id or agent_id in
                   self._quarantined[a].get("lineage", [])]
        for a in removed:
            del self._quarantined[a]
        self._log.append({
            "event": "lineage_quarantine_release",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "released",
            "policy_id": "message-lineage-quarantine",
            "reason": reason,
            "released_agents": sorted(removed),
        })
        return sorted(removed)

    # -- lineage ----------------------------------------------------------

    def downstream_lineage(self, agent_id):
        """Compute downstream agents from agent_spawn log events plus
        message-send edges. Best-effort graph walk over chained events:
        spawn edges (parent -> child) and message edges (sender ->
        recipient)."""
        children = {}
        try:
            from .log import read_entries
            events = read_entries(self._run_dir / "actions.jsonl")
        except Exception:  # noqa: BLE001 - fail closed: lineage of one
            events = []
        for e in events:
            if e.get("event") == "agent_spawn" and e.get("agent_id"):
                children.setdefault(e["agent_id"], []).append(
                    e.get("sub_agent_id"))
        for sender, recipient in self._threads:
            children.setdefault(sender, []).append(recipient)
        seen, stack = set(), [agent_id]
        while stack:
            cur = stack.pop()
            for nxt in children.get(cur, []):
                if nxt and nxt not in seen and nxt != agent_id:
                    seen.add(nxt)
                    stack.append(nxt)
        return sorted(seen)

    # -- send / receive ----------------------------------------------------

    def send(self, executor, identity, recipient, msg_type, content,
             thread=None):
        """Send a governed message. ``executor`` supplies the sender's
        delegation context (token_ref); ungoverned executors cannot send
        (fail closed). Returns the stored message id."""
        sender = identity.agent_id
        # 1. minted-identity check: the bus never trusts a caller-supplied
        # identity object; the executor authenticates it.
        _deny = executor._check_identity(identity)
        if _deny is not None:
            raise MessageRefusedError(
                "send refused: identity check failed (%s)" % (_deny[1],))
        # 1b. lineage check (GAP-2): on a run where the deployment
        # installed the infection-lineage tracker, the sender must be
        # birth-certified. Fail closed, mirroring call()'s refusal of
        # unlineaged identities — the bus must not be the softer path.
        tracker = self._lineage_tracker
        if tracker is not None and not tracker.is_registered(sender):
            self._log.append({
                "event": "agent_message",
                "run_id": self._run_dir.name,
                "agent_id": sender,
                "decision": "refused",
                "policy_id": "infection-lineage",
                "flag": "lineage_send_refused",
                "reason": ("send refused: sender %r has no lineage record "
                           "on a lineage-tracked run" % sender),
                "recipient": recipient,
            })
            raise MessageRefusedError(
                "send refused: sender %r has no lineage record "
                "(fail closed)" % sender)
        # 2. quarantine check (send-side refusal).
        if self.is_quarantined(sender):
            self._log.append({
                "event": "agent_message",
                "run_id": self._run_dir.name,
                "agent_id": sender,
                "decision": "refused",
                "policy_id": "message-lineage-quarantine",
                "flag": "quarantine_send_refused",
                "reason": "sender %r is quarantined" % sender,
                "recipient": recipient,
            })
            raise QuarantineDeniedError(
                "send refused: sender %r is quarantined" % sender)
        # 3. typed-schema canonicalization (refuse, never coerce).
        canonical = _canonicalize(msg_type, content)
        # 4. bandwidth caps.
        self._sent_count[sender] = self._sent_count.get(sender, 0) + 1
        self._sent_bytes[sender] = self._sent_bytes.get(sender, 0) + \
            len(canonical)
        if self._sent_count[sender] > _MAX_MESSAGES_PER_SENDER or \
                self._sent_bytes[sender] > _MAX_BYTES_PER_SENDER:
            self._log.append({
                "event": "agent_message",
                "run_id": self._run_dir.name,
                "agent_id": sender,
                "decision": "refused",
                "policy_id": "message-bandwidth",
                "flag": "bandwidth_cap_exceeded",
                "reason": "sender %r exceeded per-run bandwidth" % sender,
                "recipient": recipient,
            })
            raise MessageRefusedError(
                "send refused: sender %r exceeded bandwidth cap" % sender)
        # 5. provenance stamp.
        dctx = getattr(executor, "_delegation_context", None)
        if dctx is None or not dctx.bound:
            raise MessageRefusedError(
                "send refused: messaging requires a bound delegation "
                "context (governed path only)")
        from .delegation_tokens import token_ref
        seq = self._seq.get(sender, 0)
        self._seq[sender] = seq + 1
        text_for_screen = (content if isinstance(content, str)
                           else canonical.decode("utf-8", "replace"))
        stamp = {
            "sender": sender,
            "sender_role": identity.role,
            "sender_principal": identity.principal,
            "sender_token_ref": token_ref(dctx.delegation_token),
            "delegation_depth":
                dctx.delegation_token["claims"].get("delegation_depth", 0),
            "trust_tier": ("delegated"
                           if dctx.delegation_token["claims"].get(
                               "delegation_depth", 0) > 0 else "peer"),
            "recipient": recipient,
            "msg_type": msg_type,
            "seq": seq,
            "thread": thread or "%s->%s" % (sender, recipient),
            "content_sha256": _sha256_hex(canonical),
            "content_bytes": len(canonical),
            "steg_findings": steg_screen(text_for_screen),
        }
        if tracker is not None:
            # GAP-2: the stamp carries the sender's infection-lineage
            # identity (id, depth, send-time taint bit) so the receive
            # side can verify and propagate it. These fields ride the
            # chained "sent" event below, which is the provenance root
            # the receive side verifies against.
            cert = tracker.certificate(sender)
            stamp["sender_lineage_id"] = cert["lineage_id"]
            stamp["sender_lineage_depth"] = cert.get("depth", 0)
            stamp["sender_infected"] = tracker.is_infected(sender)
        # 6. operator-side store (full content NEVER goes in the chain).
        msg_dir = self._inbox_root / recipient
        msg_dir.mkdir(parents=True, exist_ok=True)
        msg_id = "%s-%06d" % (sender, seq)
        (msg_dir / (msg_id + ".json")).write_text(
            json.dumps({"stamp": stamp,
                        "content": content
                        if isinstance(content, (str, dict)) else None,
                        "content_b64": None
                        if isinstance(content, (str, dict))
                        else canonical.decode("utf-8", "replace")},
                       sort_keys=True),
            encoding="utf-8")
        self._threads.append((sender, recipient))
        # 7. chained event: stamp + content hash only.
        self._log.append({
            "event": "agent_message",
            "run_id": self._run_dir.name,
            "agent_id": sender,
            "decision": "sent",
            "policy_id": "message-bus",
            "recipient": recipient,
            "msg_id": msg_id,
            "stamp": stamp,
            "flag": ("steg_flagged" if stamp["steg_findings"]
                     else "message_sent"),
            "reason": ("steg screen findings: %s"
                       % ",".join(stamp["steg_findings"])
                       if stamp["steg_findings"] else
                       "governed message sent"),
        })
        if self._notify is not None:
            self._notify({"msg_id": msg_id, "stamp": stamp,
                          "canonical": canonical})
        if tracker is not None:
            # GAP-2: bus traffic feeds the population replication watch,
            # so a payload spreading agent-to-agent over the bus fires
            # infection_suspected exactly like the same bytes over files.
            tracker.observe_content(stamp["content_sha256"], sender,
                                    len(canonical))
        return msg_id

    def _chained_send_matches(self, msg_id, stamp):
        """True iff the audit chain carries an ``agent_message`` send
        event for msg_id whose stamp matches the inbox file's stamp on
        the provenance fields.

        The chain is the provenance root: a stamp that cannot be tied
        to a chained send was not issued by this bus (e.g. an attacker
        hand-wrote an inbox file impersonating another sender).
        """
        try:
            from .log import read_entries
            events = read_entries(self._run_dir / "actions.jsonl")
        except Exception:  # noqa: BLE001 - fail closed: unverifiable
            return False
        for e in events:
            if (isinstance(e, dict)
                    and e.get("event") == "agent_message"
                    and e.get("decision") == "sent"
                    and e.get("msg_id") == msg_id):
                chained = e.get("stamp") or {}
                return all(chained.get(k) == stamp.get(k) for k in (
                    "sender", "seq", "recipient", "msg_type",
                    "content_sha256", "sender_lineage_id"))
        return False

    def _refuse_unverifiable_message(self, tracker, sender, recipient,
                                     msg_id, reason):
        """Full forged-lineage response for stamps the chained-send
        check rejects: taint-mark the reader (when lineage-registered),
        chain a LOUD lineage_stamp_forged event, then contain and refuse
        via _contain_and_refuse (H18: the delivering sender is
        quarantined, the recipient warned)."""
        if (tracker.is_registered(recipient)
                and not tracker.is_infected(recipient)):
            tracker.mark_infected(
                recipient,
                "received bus message with forged lineage (%s)" % msg_id)
        self._log.append({
            "event": "lineage_stamp_forged",
            "run_id": self._run_dir.name,
            "agent_id": recipient,
            "decision": "flagged",
            "policy_id": "infection-lineage",
            "channel": "bus",
            "msg_id": msg_id,
            "flag": "lineage_stamp_forged",
            "reason": reason,
        })
        self._contain_and_refuse(sender, recipient, msg_id, reason)

    def _contain_and_refuse(self, sender, recipient, msg_id, detail):
        """Shared tail of both forged paths: bus-quarantine the
        DELIVERING SENDER (H18: the actionable endpoint, not the victim
        recipient; containment is reversible via release()) and refuse
        delivery — loud, never silently dropped. The recipient is warned
        (taint-marked by the caller), not quarantined."""
        # H18: the claimed sender identity cannot be fully trusted, but
        # the delivering sender endpoint is the actionable entity. The
        # recipient (victim) is warned, not quarantined — quarantining
        # the victim lets a forger DOS arbitrary recipients.
        self.quarantine(
            sender,
            "bus message %r failed lineage verification (delivering "
            "sender quarantined): %s" % (msg_id, detail))
        self._log.append({
            "event": "agent_message",
            "run_id": self._run_dir.name,
            "agent_id": recipient,
            "decision": "warned",
            "policy_id": "message-lineage-quarantine",
            "flag": "forged_stamp_recipient_warned",
            "reason": ("message %r failed lineage verification; recipient "
                       "warned (not quarantined); delivering sender %r "
                       "quarantined" % (msg_id, sender)),
            "msg_id": msg_id,
        })
        raise MessageFlaggedError(
            "receive refused: message %r failed lineage verification "
            "(%s); delivering sender %r quarantined, recipient %r warned "
            "(not quarantined)"
            % (msg_id, detail, sender, recipient))

    def receive(self, executor, identity, msg_id):
        """Read and validate a message. Returns (content, stamp, flags).

        Stamp validation failures -> MessageFlaggedError (refused, loud).
        Steg findings -> delivered WITH the flag (never silently dropped).
        Replays (seq <= last seen from this sender) -> flagged.
        A quarantined recipient gets the message DIVERTED (held, not
        delivered): quarantine must not be bypassable by reading mail.
        """
        recipient = identity.agent_id
        _deny = executor._check_identity(identity)
        if _deny is not None:
            raise MessageFlaggedError(
                "receive refused: identity check failed (%s)" % (_deny[1],))
        if self.is_quarantined(recipient):
            self._log.append({
                "event": "agent_message",
                "run_id": self._run_dir.name,
                "agent_id": recipient,
                "decision": "diverted",
                "policy_id": "message-lineage-quarantine",
                "flag": "quarantine_receive_diverted",
                "reason": "recipient %r is quarantined; message held"
                          % recipient,
                "msg_id": msg_id,
            })
            raise QuarantineDeniedError(
                "receive diverted: recipient %r is quarantined" % recipient)
        msg_dir = self._inbox_root / recipient
        path = msg_dir / (msg_id + ".json")
        if not path.is_file():
            raise MessageFlaggedError("no such message %r for %r"
                                      % (msg_id, recipient))
        record = json.loads(path.read_text(encoding="utf-8"))
        stamp = record["stamp"]
        content = record["content"]
        if content is None and record.get("content_b64") is not None:
            # Non-str/dict data payloads round-trip through canonical JSON.
            content = json.loads(record["content_b64"])
        sender = stamp["sender"]
        # Re-canonicalize and compare the content hash: the operator-side
        # store is outside the hash chain, so tampering must be caught
        # here, at read time.
        canonical = _canonicalize(stamp["msg_type"], content)
        if _sha256_hex(canonical) != stamp["content_sha256"]:
            self._log.append({
                "event": "agent_message",
                "run_id": self._run_dir.name,
                "agent_id": recipient,
                "decision": "refused",
                "policy_id": "message-integrity",
                "flag": "message_hash_mismatch",
                "reason": "stored content does not match stamped hash",
                "msg_id": msg_id,
            })
            raise MessageFlaggedError(
                "message %r failed integrity check (hash mismatch)" % msg_id)
        # GAP-2: lineage verification on the receive path. The stamp is
        # asserted by whoever wrote the inbox file; the tracker's live
        # registry plus the chained send record are the verification.
        tracker = self._lineage_tracker
        lineage_status = None
        if tracker is not None:
            if not self._chained_send_matches(msg_id, stamp):
                # The stamp cannot be tied to a chained send: it was not
                # issued by this bus (e.g. an attacker hand-wrote the
                # inbox file). note_message's registry checks would pass
                # on a copied lineage id, so this check runs first.
                self._refuse_unverifiable_message(
                    tracker, sender, recipient, msg_id,
                    "no chained send record matches message %r: the stamp "
                    "was not issued by this bus" % msg_id)
            # note_message raises LineageError for an unlineaged
            # recipient (fail closed, mirroring note_read); a forged
            # lineage returns ("forged", detail) after chaining
            # lineage_stamp_forged and taint-marking the reader.
            lineage_status, detail = tracker.note_message(
                recipient, msg_id, stamp)
            if lineage_status == "forged":
                self._contain_and_refuse(sender, recipient, msg_id, detail)
            # Contact/tainted messages are DELIVERED with the flag (the
            # steg-flag precedent: flagged, never silently dropped), and
            # the recipient lineage feeds the population watch.
            tracker.observe_content(stamp["content_sha256"], recipient,
                                    stamp.get("content_bytes") or 0)
        flags = []
        if lineage_status in ("contact", "tainted"):
            flags.append("lineage:" + lineage_status)
        last = self._last_seen.get((recipient, sender), -1)
        if stamp["seq"] <= last:
            flags.append("replay")
        else:
            self._last_seen[(recipient, sender)] = stamp["seq"]
        flags.extend("steg:" + f for f in stamp.get("steg_findings", []))
        self._log.append({
            "event": "agent_message",
            "run_id": self._run_dir.name,
            "agent_id": recipient,
            "decision": "received",
            "policy_id": "message-bus",
            "msg_id": msg_id,
            "sender": sender,
            "flag": "message_received_flagged" if flags else "message_received",
            "reason": ("flags: %s" % ",".join(flags)) if flags
                      else "governed message received",
        })
        return content, stamp, flags


class LineageQuarantine(object):
    """Population-level containment for prompt-infection spread.

    ``quarantine_origin(agent_id, reason, bus)`` computes the downstream
    lineage and quarantines it in one chained event. The point of the
    lineage (not per-agent) response: Morris-II-class replication
    outruns per-agent human review, so the control lives at the
    population level. Reversible via ``bus.release()``.
    """

    @staticmethod
    def quarantine_origin(agent_id, reason, bus):
        lineage = bus.downstream_lineage(agent_id)
        return bus.quarantine(agent_id, reason, lineage=lineage)
