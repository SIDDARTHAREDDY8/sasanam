"""Retrieval-rail stage contract (wave-274 lane 2).

The retrieval rail is the named pre-prompt-assembly enforcement stage
for retrieved content: tool outputs, web-fetch chunks, memory recalls --
anything the agent did not type itself. It enforces three rules that the
industry's flagship guardrails library (NVIDIA NeMo Guardrails, per the
wave-273 prospectus) does NOT enforce, and our wave-245 provenance tiers
demand:

1. Every chunk carries a provenance label from a closed vocabulary
   (``trusted`` / ``untrusted`` / ``unknown``). An unlabeled or
   unknown-vocabulary chunk is BLOCKed fail-closed
   (``rail-chunk-unlabeled``). Labels never upgrade across turns.
2. Every chunk is content-safety screened before assembly. An
   instruction-shaped chunk is not silently dropped and not passed
   through: it is TRANSFORMed -- masked in place with a visible
   placeholder (the mask_prev_user_message pattern: scrub + visible
   placeholder) -- so the approver sees that instruction-shaped content
   arrived and what was done about it.
3. Chunks are never merged as bare strings. :func:`assemble` refuses
   ``rail-merge-contract-violated`` on anything that is not a
   :class:`RetrievedChunk`, and produces a :class:`RetrievedTranscript`
   whose segments keep per-chunk provenance. Rendering for the approver
   marks every segment with its label.

Cross-turn provenance: :class:`ChunkRegistry` binds chunk_id -> (label,
digest). A chunk re-registered with a different label refuses
``rail-chunk-relabel-refused``; a chunk re-registered with the same id
but different bytes refuses ``rail-chunk-body-mismatch``. A retrieved
chunk reused in a later turn keeps the label it arrived with.

Honest limits:
- Masking is chunk-granularity: an instruction-shaped chunk is masked
  whole. Sub-span masking is future work; the placeholder names the
  reason so the approver can pull the chunk from quarantine review.
- The content-safety screen is the deterministic instruction-shaping
  heuristic from gov/memory_provenance.py, not a semantic judge. It
  catches instruction-shaped text, not novel paraphrase. (Deliberately
  no LLM-call-per-rail judge: bypassable by construction, plus
  cost/latency.)
- TRANSFORM masking is not a security boundary against exfiltration of
  the masked bytes via other channels; the transcript marks the
  masking so the audit trail is complete.

Stdlib only. Deterministic. Never raises except through the coded
:class:`RetrievalRailError`.
"""

import hashlib

from . import rail_verdict as RV
from .memory_provenance import instruction_shaping_reason

#: Closed provenance-label vocabulary (case-exact). "unknown" is a real
#: label and fails closed at the stage -- it is never treated as trusted.
LABEL_TRUSTED = "trusted"
LABEL_UNTRUSTED = "untrusted"
LABEL_UNKNOWN = "unknown"
LABELS = (LABEL_TRUSTED, LABEL_UNTRUSTED, LABEL_UNKNOWN)

#: Codes in the rail domain owned by this module. Pinned by
#: evals/w274_rail_probes.py (shared with gov/rail_verdict.py).
RAIL_CODES = (
    "rail-chunk-unlabeled",
    "rail-chunk-relabel-refused",
    "rail-chunk-body-mismatch",
    "rail-merge-contract-violated",
)


class RetrievalRailError(Exception):
    """Coded fail-closed refusal from the retrieval rail."""

    def __init__(self, code, detail):
        super(RetrievalRailError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise RetrievalRailError(code, detail)


def _check_label(label):
    if label not in LABELS:
        _refuse("rail-chunk-unlabeled",
                "chunk label %r is not in the closed vocabulary %s; "
                "unlabeled chunks are blocked fail-closed"
                % (label, LABELS))
    return label


def _digest(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class RetrievedChunk(object):
    """One retrieved unit with its provenance attached at ingress.

    Immutable after construction. ``label`` must be in LABELS;
    ``chunk_id``, ``body``, and ``source`` must be non-empty strings;
    ``turn_id`` is an int.
    """

    __slots__ = ("chunk_id", "body", "label", "source", "turn_id")

    def __init__(self, chunk_id, body, label, source, turn_id):
        for name, value in (("chunk_id", chunk_id), ("body", body),
                            ("source", source)):
            if not isinstance(value, str) or not value:
                _refuse("rail-chunk-unlabeled",
                        "RetrievedChunk.%s must be a non-empty string"
                        % name)
        if (not isinstance(turn_id, int) or isinstance(turn_id, bool)
                or turn_id < 0):
            _refuse("rail-chunk-unlabeled",
                    "RetrievedChunk.turn_id must be a non-negative int")
        self.chunk_id = chunk_id
        self.body = body
        self.label = _check_label(label)
        self.source = source
        self.turn_id = turn_id

    def __repr__(self):
        return "RetrievedChunk(%r, label=%s)" % (self.chunk_id, self.label)


class ChunkRegistry(object):
    """Cross-turn provenance binding: chunk_id -> (label, digest).

    A chunk reused in a later turn keeps the label it arrived with.
    Re-registering an id with a different label refuses
    ``rail-chunk-relabel-refused`` (labels never upgrade across turns);
    re-registering an id with different bytes refuses
    ``rail-chunk-body-mismatch`` (content swap under a stable id).
    Same id, same label, same bytes is idempotent.
    """

    def __init__(self):
        self._entries = {}

    def register(self, chunk):
        if not isinstance(chunk, RetrievedChunk):
            _refuse("rail-merge-contract-violated",
                    "registry accepts only RetrievedChunk, got %s"
                    % type(chunk).__name__)
        digest = _digest(chunk.body)
        prior = self._entries.get(chunk.chunk_id)
        if prior is None:
            self._entries[chunk.chunk_id] = (chunk.label, digest)
            return chunk
        prior_label, prior_digest = prior
        if digest != prior_digest:
            _refuse("rail-chunk-body-mismatch",
                    "chunk %r re-registered with different bytes; "
                    "content swap under a stable id is refused"
                    % (chunk.chunk_id,))
        if chunk.label != prior_label:
            _refuse("rail-chunk-relabel-refused",
                    "chunk %r re-registered with label %r after %r; "
                    "labels never change across turns"
                    % (chunk.chunk_id, chunk.label, prior_label))
        return chunk

    def fetch(self, chunk_id):
        """Return (label, digest) for a registered id, or None."""
        return self._entries.get(chunk_id)

    def __len__(self):
        return len(self._entries)


class RetrievedTranscript(object):
    """Assembled retrieval output with per-chunk provenance preserved.

    Constructed only via :func:`assemble`. ``segments()`` returns the
    ordered list of {"chunk_id", "label", "body"} dicts. ``render()``
    marks every segment with its label for the approver; it never
    returns a bare concatenation.
    """

    def __init__(self, chunks):
        chunks = list(chunks)
        for c in chunks:
            if not isinstance(c, RetrievedChunk):
                _refuse("rail-merge-contract-violated",
                        "transcript accepts only RetrievedChunk, got %s"
                        % type(c).__name__)
        self._chunks = chunks

    def segments(self):
        return [{"chunk_id": c.chunk_id, "label": c.label, "body": c.body}
                for c in self._chunks]

    def render(self):
        """Approver-facing rendering: every segment is labeled. The
        instruction-shaped spans stay masked (placeholders intact)."""
        parts = []
        for c in self._chunks:
            parts.append("[%s|%s|%s]\n%s"
                         % (c.label, c.source, c.chunk_id, c.body))
        return "\n".join(parts)

    def __len__(self):
        return len(self._chunks)


def assemble(items):
    """Assemble retrieved chunks into a transcript. Every item must be a
    :class:`RetrievedChunk`; bare strings refuse
    ``rail-merge-contract-violated`` -- provenance is never merged away."""
    items = list(items)
    for item in items:
        if not isinstance(item, RetrievedChunk):
            _refuse("rail-merge-contract-violated",
                    "assemble accepts only RetrievedChunk, got %s; "
                    "merging bare strings drops provenance"
                    % type(item).__name__)
    return RetrievedTranscript(items)


class RetrievalRail(object):
    """The retrieval enforcement stage.

    ``stage(chunks)`` validates labels, screens each chunk for
    instruction-shaped content, and returns (stage_verdict, per_chunk)
    where per_chunk is the list of RailVerdicts in input order and
    stage_verdict is their fail-closed combination (BLOCK > TRANSFORM >
    ALLOW). Labels of "unknown" are BLOCKed, never trusted.
    """

    def __init__(self, stage_name="retrieval"):
        self._stage = stage_name

    def screen_chunk(self, chunk):
        """Screen one chunk: label check, then content-safety screen.
        Instruction-shaped chunks are TRANSFORMed (masked whole, visible
        placeholder); clean chunks are ALLOWed."""
        if not isinstance(chunk, RetrievedChunk):
            _refuse("rail-merge-contract-violated",
                    "stage accepts only RetrievedChunk, got %s"
                    % type(chunk).__name__)
        if chunk.label == LABEL_UNKNOWN:
            return RV.block("rail-chunk-unlabeled",
                            "chunk %r carries label 'unknown': blocked "
                            "fail-closed, never trusted" % (chunk.chunk_id,),
                            stage=self._stage)
        reason = instruction_shaping_reason(chunk.body)
        if reason is not None:
            return RV.mask_and_continue(
                chunk.body,
                [(0, len(chunk.body), "instruction-shaped-chunk")],
                code="rail-instruction-chunk-masked",
                reason="instruction-shaped retrieved chunk masked "
                       "(%s); approver sees the placeholder, not the "
                       "injection" % reason,
                stage=self._stage)
        return RV.allow("retrieved chunk screened clean",
                        code="rail-allow", stage=self._stage)

    def stage(self, chunks):
        chunks = list(chunks)
        per_chunk = [self.screen_chunk(c) for c in chunks]
        return RV.combine(*per_chunk), per_chunk
