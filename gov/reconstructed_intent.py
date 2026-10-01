"""Reconstructed-intent scoring seam (wave-266 feature lane).

F248 defense: Divide-and-Inject (arXiv:2609.36576) splits a malicious
objective into incomplete fragments across retrieved long-context
content; a reconstruction cue gets the agent to combine them.
Per-chunk detectors miss by construction (61.4% macro-average ASR in
the paper). This module scores RECONSTRUCTED intent across the run's
untrusted chunk set -- never one chunk at a time -- at the act gate.

What this module provides, stdlib-only:

* :func:`score_run`: pure deterministic ($0, no embeddings) scoring
  over (chunks, tool, args, user_text, justification). Returns a
  verdict dict; never raises on well-formed input.
* :class:`ReconstructionSeam`: owns the fail-closed shape and a
  bounded per-run chunk buffer (``note_chunk``). On ``suspect`` it
  appends an advisory ``reconstructed_intent_suspect`` flag to a
  deployment-owned journal and queues a human approval (machine
  code ``reconintent-suspect``) through a deployment-owned queue
  callable. A suspect hold with no queue callable is refused loudly
  (``reconintent-malformed``) rather than silently downgraded to
  journal-only. The seam NEVER blocks: the verdict is returned and
  execution proceeds per the queue's (human) decision.
* :class:`ReconIntentError`: loud machine-coded refusal
  (``reconintent-malformed``) when chunk shapes, fingerprints, or
  caps fail validation -- malformed input is never scored silently.

Scoring (all deterministic):

1. **Directive completeness of the union** -- the union of chunks
   carries the action's critical destination (email/url/account) plus
   an action indicator (the tool's verb stems per
   ``gov.intent_slice._verb_stems``, or an assembly-verb lexicon:
   words that ask to *combine* fragments, e.g. assemble/combine/
   reconstruct), while NO single chunk carries destination +
   indicator together. A single chunk carrying the whole directive
   is a direct instruction -- the per-chunk seams' job, not a
   reconstruction.
2. **Argument provenance** (the ToolFence direction) -- the
   destination value (or, for account identifiers, its digit tail)
   appears in the untrusted chunks but NOT in the user turn. A
   user-named destination is the judge's territory
   (``judge_queued_action`` flags slot contradictions when the user
   names the slot); this seam owns the unnamed case.
3. **Reconstruction-cue presence** -- a cue-lexicon hit
   (assemble/combine/reconstruct/piece-together) raises confidence;
   it amplifies, it does not gate, so paraphrased cues still flag.

``suspect`` requires (1) and (2) plus shared topic support (>=2
stemmed content tokens shared between the chunks and the planned
action's intent context -- user turn, justification, and arg
values): the chunks must be *about* what the action claims to do.
The score is 40*provenance + 30*union-complete
+ 20*topic + 10*cue, 0-100.

Slot machinery is reused, never duplicated:
``gov.intent_slice._extract_slots`` (emails/urls),
``_action_target_slot`` (tool-aware primary target),
``_verb_stems`` and ``_tokens``. Account identifiers (IBANs,
"account ending NNNN" tails) are extracted here -- no account slot
existed in the reused machinery.

Composition (never duplication):

* This module owns ONLY cross-chunk scoring. Input screening stays
  per-chunk (``instruction_shaping_reason``), slot contradiction
  stays with ``judge_queued_action``, carryover stays with the
  rare-token tiers, and the human decision stays in
  ``gov/approvals.py`` -- the seam emits a machine-coded request
  the deployment's queue consumes.
* Kept out of the executor hot path by design: the deployment calls
  :meth:`ReconstructionSeam.evaluate` where the run's untrusted
  chunk set meets the act gate (the executor's ingestion funnel
  already holds per-source ``_read_contents``); the seam takes the
  chunk set as an argument and holds no executor state.
* The queue request carries NO agent identity claims (F42 lesson:
  the queue never trusts caller-supplied identity fields). The
  deployment's queue attributes the request via its own session
  context and MUST enforce separation of duties -- the agent can
  never resolve its own ``reconintent-suspect`` hold.

Fail-closed behavior:

* Malformed chunks (bad shape, fingerprint mismatch, over caps)
  raise ``reconintent-malformed`` -- never scored silently.
* A throwing queue callable journals ``reconintent-queue-failed``
  loudly and the suspect verdict is still returned (the rare-token
  pattern): the flag is never dropped silently.
* This seam never denies an action. Heuristic FPs (e.g. a benign
  workflow whose destination happens to come from chunks) cost a
  human approval, never a silent block.

Honest residuals:

* Paraphrase ceilings remain: token overlap is not semantics. A
  fully reworded exfiltration whose destination shares no slot
  value with the chunks is invisible to this seam by design.
* Destination matching is exact for emails/urls and digit-tail for
  accounts; a destination laundered through a redirector or an
  alias the chunks never name is missed.
* The "no single chunk complete" delimiter is definitional, not
  semantic: a fragment like "partner uploads go to <url>" reads as
  a world-fact, not an instruction, and the per-chunk screens
  already judge it benign (the w265 finding's own
  characterization). The assembly-verb lexicon therefore treats
  the action slot as satisfied by the tool's verb stems or by a
  genuine combine-the-fragments cue -- transfer verbs are excluded
  so descriptive fragments do not trivially self-complete. An
  attacker who phrases the transfer as a plain instruction inside
  one fragment is the per-chunk seams' case, not a reconstruction.
* The union-slot signal is coarse and needs FP calibration against
  real retrieval workloads before any deployment treats a flag as
  high-confidence. Two precision limits are known: (a) the spec's
  "target" slot is not separately required -- the action side is
  carried by the tool's verb stems plus topic overlap, so a
  same-topic multi-step workflow with a chunk-sourced destination
  can score where a stricter target-slot check would not; (b) the
  assembly-verb lexicon ("gather", "collect", "prepare",
  "compile") is broad research vocabulary, not
  reconstruction-specific -- the cue only amplifies confidence, it
  never gates the verdict, but the lexicon is the noisiest of the
  four signals.
* Per-call cost is bounded by the buffer caps (64 chunks x 1MB
  text) but not cached: explicit chunk sets re-verify sha256
  fingerprints on every score_run call. The act-gate path scores
  the note-time-fingerprinted buffer without re-hashing
  (score_buffered); deployments scoring the same explicit set
  repeatedly should hold the verdict, not re-score.
* note_chunk truncates texts at the 1MB cap (best-effort context);
  explicit chunks over the cap are refused loudly. The asymmetry is
  deliberate: a loud refusal on the executor's read path would turn
  a large benign read into a denial-of-service.
* This seam does NOT replace argument-provenance enforcement at the
  policy engine (the ToolFence direction); it is the detection
  defense-in-depth layer for fatigued/auto-approved/allow-listed
  actions.
* Chunk fingerprints are verified against chunk text here, but the
  per-source trust (retrieval was not tampered upstream) is the
  deployment's ingestion contract.
"""

import hashlib
import json
import os
import re
from collections import deque

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from .intent_slice import (
    _extract_slots,
    _action_target_slot,
    _verb_stems,
    _tokens,
)

CODES = (
    "reconintent-malformed",
    "reconintent-queue-failed",
    "reconintent-suspect",
)

# Bounds: the seam scores a bounded chunk set, never an open stream.
_MAX_CHUNKS = 64
_MAX_CHUNK_TEXT = 1000000
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

# Account identifiers: IBANs plus "account ending NNNN" style tails.
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
_ACCOUNT_TAIL_RE = re.compile(
    r"account(?:\s+(?:no\.?|number|#))?\s*(?:ending(?:\s+in)?\s+)?"
    r"([0-9][0-9\s\-]{3,30})",
    re.IGNORECASE,
)
_DIGIT_RUN_RE = re.compile(r"[0-9]{4,}")

# Assembly verbs: words that ask to COMBINE fragments. Transfer verbs
# (send/share/pay/upload) are deliberately excluded -- they describe
# the action's topic, not the reconstruction.
_ASSEMBLY_STEMS = (
    "assembl", "combin", "reconstru", "piec", "synthes", "integrat",
    "merg", "join", "consolidat", "compil", "prepar", "stitch",
    "gather", "collect",
)
# The cue subset that raises confidence to "high".
_CUE_STEMS = ("assembl", "combin", "reconstru", "piec")

# Shared topic tokens required between chunks and the planned action.
_TOPIC_SUPPORT_MIN = 2


class ReconIntentError(Exception):
    """Loud reconstructed-intent failure. ``code`` is a closed
    vocabulary member of :data:`CODES`."""

    def __init__(self, code, detail=""):
        super(ReconIntentError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else "")
        )
        self.code = code
        self.detail = detail


def _require_taxonomy():
    try:
        from . import decision_codes
    except ImportError:  # standalone: codes are validated at merge
        return None
    return decision_codes.TAXONOMY


def _fail(code, detail=""):
    taxonomy = _require_taxonomy()
    if taxonomy is not None and code not in taxonomy:
        raise ReconIntentError(
            "reconintent-malformed",
            "unknown code %r" % (code,))
    raise ReconIntentError(code, detail)


def _is_hex64(value):
    return isinstance(value, str) and _FINGERPRINT_RE.match(value) \
        is not None


def _validate_chunks(chunks):
    """Fail-closed chunk validation. Returns the list of texts."""
    if not isinstance(chunks, list):
        _fail("reconintent-malformed", "chunks must be a list")
    if len(chunks) > _MAX_CHUNKS:
        _fail("reconintent-malformed",
              "chunk count %d exceeds cap %d"
              % (len(chunks), _MAX_CHUNKS))
    texts = []
    for i, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            _fail("reconintent-malformed",
                  "chunk %d is not a dict" % (i,))
        source_id = chunk.get("source_id")
        fingerprint = chunk.get("fingerprint")
        text = chunk.get("text")
        if not isinstance(source_id, str) or not source_id:
            _fail("reconintent-malformed",
                  "chunk %d: source_id must be a non-empty string"
                  % (i,))
        if not _is_hex64(fingerprint):
            _fail("reconintent-malformed",
                  "chunk %d: fingerprint must be sha256 hex" % (i,))
        if not isinstance(text, str):
            _fail("reconintent-malformed",
                  "chunk %d: text must be a string" % (i,))
        if len(text) > _MAX_CHUNK_TEXT:
            _fail("reconintent-malformed",
                  "chunk %d: text exceeds cap" % (i,))
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != fingerprint:
            _fail("reconintent-malformed",
                  "chunk %d: fingerprint does not match text" % (i,))
        texts.append(text)
    return texts


def _account_tails(text):
    """Digit tails identifying account references in free text."""
    tails = set()
    for match in _IBAN_RE.findall(str(text or "")):
        digits = "".join(ch for ch in match if ch.isdigit())
        if len(digits) >= 4:
            tails.add(digits)
    for match in _ACCOUNT_TAIL_RE.findall(str(text or "")):
        digits = "".join(ch for ch in match if ch.isdigit())
        if len(digits) >= 4:
            tails.add(digits)
    return tails


def _chunk_slots(text):
    """Destination slots carried by one text: emails, urls, account
    tails. (Paths are excluded: the house path pattern matches URL
    interiors, which would double-count destinations.)"""
    slots = _extract_slots(text)
    return {
        "emails": set(slots.get("emails", ())),
        "urls": set(slots.get("urls", ())),
        "accounts": _account_tails(text),
    }


def _tails_match(arg_tail, chunk_tail):
    return len(arg_tail) >= 4 and len(chunk_tail) >= 4 and (
        arg_tail == chunk_tail or arg_tail.endswith(chunk_tail)
        or chunk_tail.endswith(arg_tail))


def _critical_destinations(tool, args):
    """The action's critical destination values: the tool-aware
    primary target plus every email/url/account found in any arg
    value (defensive: the attacker chooses the arg shape)."""
    dest = {"emails": set(), "urls": set(), "accounts": set()}
    cls, target = _action_target_slot(tool, args)
    if cls in dest and target:
        dest[cls].add(str(target).lower())
    arg_text = " ".join(
        str(v) for v in (args or {}).values())
    slots = _extract_slots(arg_text)
    dest["emails"] |= set(slots.get("emails", ()))
    dest["urls"] |= set(slots.get("urls", ()))
    dest["accounts"] |= _account_tails(arg_text)
    for run in _DIGIT_RUN_RE.findall(arg_text):
        if len(run) >= 4:
            dest["accounts"].add(run)
    return dest


def _dest_in_slots(dest, slots):
    """True when a critical destination value appears in a slot set.
    Emails/urls match exactly; accounts match on digit tails."""
    for value in dest["emails"]:
        if value in slots["emails"]:
            return True
    for value in dest["urls"]:
        if value in slots["urls"]:
            return True
    for value in dest["accounts"]:
        for tail in slots["accounts"]:
            if _tails_match(value, tail):
                return True
    return False


def _dest_in_text(dest, text):
    """True when a destination value appears in free text (the user
    turn): exact for emails/urls, digit-tail for accounts."""
    lowered = str(text or "").lower()
    for value in dest["emails"]:
        if value and value in lowered:
            return True
    for value in dest["urls"]:
        if value and value in lowered:
            return True
    for value in dest["accounts"]:
        for run in _DIGIT_RUN_RE.findall(lowered):
            if _tails_match(value, run):
                return True
    return False


def _indicators(text, tool, exclude=()):
    """Action-indicator stems present in a text: the tool's verb
    stems (house prefix convention) plus the assembly lexicon.

    F250: tools outside ``_TOOL_VERBS`` fall back to the single
    multi-word string ``tool.replace("_", " ")`` (e.g. "slack post"),
    which no token can startswith -- the verb-stem disjunct was
    silently void for unlisted tools. The fallback is therefore
    split into single tokens here so the tool's verb tokens
    participate. Tokens in ``exclude`` (destination-derived: the
    same discipline as topic support) never count -- for an unlisted
    tool the fallback also carries the tool's name noun ("slack"),
    which would otherwise fire as a phantom indicator wherever the
    destination URL names it, wrongly engaging the single-complete
    delimiter.
    """
    toks = _tokens(text) - set(exclude)
    stems = tuple(part for s in (_verb_stems(tool) + _ASSEMBLY_STEMS)
                  for part in s.split())
    return set(s for s in stems
               if any(t.startswith(s) for t in toks))


def _cue_present(text):
    toks = _tokens(text)
    return any(any(t.startswith(s) for t in toks)
               for s in _CUE_STEMS)


def has_critical_destinations(tool, args):
    """Public gate: True when the planned action carries at least one
    critical destination slot (email/url/account). The executor's act
    path uses this to decide whether a reconstructed-intent check is
    worth running at all."""
    dest = _critical_destinations(tool, args)
    return any(dest.values())


def _args_digest(args):
    try:
        canonical = json.dumps(args or {}, sort_keys=True,
                               separators=(",", ":"),
                               default=str)
    except Exception:  # noqa: BLE001 - digest must never throw
        canonical = str(args)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def args_digest(args):
    """Public: stable digest of action args for journals and queue
    records. Raw arg values never enter the journal; the digest
    correlates the hold with the action."""
    return _args_digest(args)


def suspect_event(verdict, agent_id, tool, args, run_id):
    """Build the LOUD ``reconstructed_intent_suspect`` audit event
    dict for a suspect verdict. Single builder: the standalone seam
    path (``ReconstructionSeam.evaluate``) and the executor's act
    path share it, so the journal shape cannot drift between them.
    Carries the args digest and the reconstructed destination
    values -- never raw args.
    """
    signals = verdict.get("signals", {})
    event = {
        "event": "reconstructed_intent_suspect",
        "code": "reconintent-suspect",
        "flag": "reconstructed_intent",
        "tool": tool,
        "args_digest": _args_digest(args),
        "score": verdict.get("score", 0),
        "confidence": verdict.get("confidence", "medium"),
        "dest_values": signals.get("dest_values", []),
        "chunks_scored": signals.get("chunks_scored", 0),
        "reason": ("RECONSTRUCTED INTENT HOLD -- reconstructed "
                   "intent: the run's untrusted chunks jointly "
                   "complete an actionable directive no single "
                   "chunk carried (score %d, confidence %s); "
                   "queued for human review, never auto-approved"
                   % (verdict.get("score", 0),
                      verdict.get("confidence", "medium"))),
    }
    # The standalone seam path has no run context; the executor
    # act path always supplies it.
    if run_id is not None:
        event["run_id"] = run_id
    if agent_id is not None:
        event["agent_id"] = str(agent_id)
    return event


def hold_request(verdict, agent_id, tool, args, justification):
    """Build the ``reconintent_review`` queue request dict for a
    suspect verdict. Shared by the standalone seam path and the
    executor's synthetic-hold path.
    """
    signals = verdict.get("signals", {})
    args_out = {
        "tool": tool,
        "args_digest": _args_digest(args),
        "dest_values": signals.get("dest_values", []),
        "score": verdict.get("score", 0),
        "confidence": verdict.get("confidence", "medium"),
        "chunks_scored": signals.get("chunks_scored", 0),
    }
    if agent_id is not None:
        args_out["agent_id"] = str(agent_id)
    return {
        "tool": "reconintent_review",
        "args": args_out,
        "code": "reconintent-suspect",
        "flag": "reconstructed_intent",
        "justification": justification or (
            "human review required: the run's untrusted chunks "
            "jointly complete an actionable directive; the agent "
            "cannot resolve its own hold"),
    }


def preview_banner(verdict):
    """One-line human-facing banner for the approval preview.

    When a suspect verdict rides an already-queued action (another
    policy already required approval), the record keeps that
    policy's id/flag; this machine-generated banner leads the
    preview (the wave-89 deferred-effect banner pattern) so the
    human reviewer sees the reconstructed-intent forcing without
    correlating log-to-queue by hand.
    """
    signals = verdict.get("signals", {})
    dests = ", ".join(signals.get("dest_values", [])[:3])
    return ("RECONSTRUCTED-INTENT: the run's untrusted chunks "
            "jointly complete this action's directive (score %d, "
            "confidence %s%s). Review the reconstructed "
            "destination, not just the stated action."
            % (verdict.get("score", 0),
               verdict.get("confidence", "medium"),
               ("; reconstructed: %s" % dests) if dests else ""))


def score_run(chunks, tool, args, user_text="", justification=""):
    """Score reconstructed intent across the chunk set.

    Returns a dict with keys "suspect", "score", "confidence",
    "code", and "signals".
    ``suspect`` is True only when ALL hold: the union of chunks
    completes an actionable directive no single chunk carried, the
    action's critical destination is sourced from the chunks rather
    than the user turn, and the chunks share topic support with the
    planned action. Malformed input raises
    :class:`ReconIntentError` (``reconintent-malformed``).
    """
    args = _validate_action(tool, args)
    texts = _validate_chunks(chunks)
    return _score_texts(texts, tool, args, user_text, justification)


def _validate_action(tool, args):
    """Fail-closed action validation shared by score_run and the
    buffer path. Returns the normalized args dict."""
    if not isinstance(tool, str) or not tool:
        _fail("reconintent-malformed",
              "tool must be a non-empty string")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        _fail("reconintent-malformed", "args must be a dict")
    return args


def _score_texts(texts, tool, args, user_text, justification):
    """Deterministic scoring core over already-obtained chunk texts.

    ``texts`` must come from :func:`_validate_chunks` (explicit chunk
    sets) or from the seam's note-time-fingerprinted buffer
    (:meth:`ReconstructionSeam.score_buffered`); both paths carry a
    sha256 fingerprint bound at ingest, so this core never re-hashes
    per call -- the act-gate scores the buffer without a 64MB
    re-validation pass on every scored call.
    """
    user_text = "" if user_text is None else str(user_text)
    justification = ("" if justification is None
                     else str(justification))

    per_chunk = [_chunk_slots(t) for t in texts]
    union = {"emails": set(), "urls": set(), "accounts": set()}
    for slots in per_chunk:
        for key in union:
            union[key] |= slots[key]
    dest = _critical_destinations(tool, args)

    dest_in_union = _dest_in_slots(dest, union)
    dest_in_user = _dest_in_text(dest, user_text)
    provenance = dest_in_union and not dest_in_user

    dest_toks = _tokens(" ".join(
        sorted(dest["emails"] | dest["urls"])))
    # Account digit tails are tokens too: a destination-derived tail
    # must not count as shared "topic" support -- or as an action
    # indicator (F250: see _indicators).
    dest_toks |= set(dest["accounts"])

    union_indicators = set()
    for text in texts:
        union_indicators |= _indicators(text, tool, exclude=dest_toks)
    single_complete = any(
        _dest_in_slots(dest, slots)
        and _indicators(text, tool, exclude=dest_toks)
        for slots, text in zip(per_chunk, texts))
    union_complete = bool(dest_in_union and union_indicators
                          and not single_complete)

    action_text = (user_text + " " + justification + " " + " ".join(
        str(v) for v in args.values()))
    # The user turn is part of the action's stated intent context:
    # in the act-gate auto path the deployment may have no separate
    # justification, so the turn's topic tokens keep the signal
    # effective there. Destination-derived tokens never count (see
    # dest_toks), and a user-named destination still quiets the
    # verdict via provenance, not via topic.
    action_toks = _tokens(action_text)
    # (dest_toks computed above; destination-derived tokens never
    # count as shared "topic" support.)
    chunk_toks = _tokens(" ".join(texts))
    shared = (chunk_toks & action_toks) - dest_toks
    topic_support = len(shared) >= _TOPIC_SUPPORT_MIN

    cue = any(_cue_present(t) for t in texts)

    suspect = bool(provenance and union_complete and topic_support)
    score = (40 if provenance else 0) + \
            (30 if union_complete else 0) + \
            (20 if topic_support else 0) + \
            (10 if cue else 0)
    confidence = "none"
    if suspect:
        confidence = "high" if cue else "medium"

    dest_values = sorted(dest["emails"] | dest["urls"]
                         | dest["accounts"])
    return {
        "suspect": suspect,
        "score": score,
        "confidence": confidence,
        "code": "reconintent-suspect" if suspect else None,
        "signals": {
            "dest_provenance": provenance,
            "union_complete": union_complete,
            "topic_support": topic_support,
            "cue_present": cue,
            "dest_values": dest_values,
            "chunks_scored": len(texts),
            "shared_topic_tokens": sorted(shared)[:16],
        },
    }


class ReconstructionSeam(object):
    """Fail-closed composition around :func:`score_run`.

    ``journal`` is a deployment-owned appendable (a list works);
    ``queue_approval`` is a deployment-owned callable taking the
    request dict and returning an approval id; it may be None, in
    which case a suspect hold is refused loudly
    (``reconintent-malformed``) instead of silently downgraded to
    journal-only. On ``suspect`` the seam appends an advisory
    ``reconstructed_intent_suspect`` flag (args digest, never raw
    args) and queues a human approval with machine code
    ``reconintent-suspect``. It never blocks: the verdict is
    returned and execution proceeds per the queue's (human)
    decision. The request carries no agent identity claims; the
    deployment's queue attributes it via its own session context
    and must enforce separation of duties. When installed in a
    ``ToolExecutor``, the executor's own audit log and approval
    queue carry the hold instead (see
    ``ToolExecutor.check_reconstructed_intent``), and separation of
    duties rides ``gov.approvals``.
    """

    def __init__(self, journal=None, queue_approval=None):
        self.journal = journal if journal is not None else []
        self._queue = queue_approval
        # Bounded per-run chunk buffer: the run's untrusted chunk set
        # as (source_id, text) pairs. The executor forwards noted read
        # texts here (see note_chunk); the deployment may also pass a
        # chunk set explicitly to evaluate().
        self._chunks = deque(maxlen=_MAX_CHUNKS)

    def note_chunk(self, source_id, text):
        """Buffer one untrusted chunk for later act-gate scoring.
        Malformed notes are ignored (the buffer is best-effort
        context, not evidence); malformed chunks passed explicitly
        to evaluate()/score_run are still refused loudly."""
        if not isinstance(source_id, str) or not source_id:
            return
        if not isinstance(text, str) or not text:
            return
        stored = text[:_MAX_CHUNK_TEXT]
        self._chunks.append({
            "source_id": source_id,
            "fingerprint": hashlib.sha256(
                stored.encode("utf-8")).hexdigest(),
            "text": stored,
        })

    def has_chunks(self):
        return len(self._chunks) > 0

    def buffered_chunks(self):
        # Copies: callers must not be able to mutate the buffer's
        # note-time fingerprints out from under the act-gate path.
        return [dict(c) for c in self._chunks]

    def score_buffered(self, tool, args, user_text="",
                       justification=""):
        """Quiet scoring over the buffered chunk set: the act-gate
        primitive. No journal, no queue -- the caller owns the
        response (the executor emits the LOUD event and queues via
        the standard machinery). Buffer texts were fingerprinted at
        note time, so this does not re-hash per call; explicit
        chunk sets still go through fail-closed validation in
        :func:`score_run`.
        """
        args = _validate_action(tool, args)
        texts = [c["text"] for c in self._chunks]
        return _score_texts(texts, tool, args, user_text,
                            justification)

    def evaluate(self, chunks=None, tool=None, args=None,
                 user_text="", justification=""):
        # chunks=None scores the buffered per-run chunk set, so the
        # act-gate caller does not re-supply what note_chunk already
        # collected. Explicit chunks still go through fail-closed
        # validation inside score_run.
        if chunks is None:
            chunks = self.buffered_chunks()
        result = score_run(chunks, tool, args, user_text,
                           justification)
        if not result["suspect"]:
            return result
        if self._queue is None:
            # Fail-closed: a suspect hold with nowhere to queue would
            # silently downgrade the advisory-flag-plus-human-approval
            # shape to journal-only. Refuse loudly instead.
            _fail("reconintent-malformed",
                  "suspect hold cannot be queued: no queue_approval "
                  "was provided at construction")
        self.journal.append(
            suspect_event(result, None, tool, args, None))
        request = hold_request(result, None, tool, args,
                               justification)
        try:
            self._queue(request)
        except Exception:  # noqa: BLE001 - loud, never silent
            self.journal.append({
                "event": "reconintent_hold_queue_failed",
                "code": "reconintent-queue-failed",
                "flag": "reconstructed_intent",
                "tool": tool,
                "args_digest": _args_digest(args),
                "reason": "reconintent-suspect approval could not "
                          "be queued; the suspect flag above "
                          "remains the record -- operator must "
                          "review manually",
            })
        return result
