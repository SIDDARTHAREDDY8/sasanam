"""Uniform rail verdicts at guard seams (wave-274 lane 2).

Adapts the stage/verdict decomposition of NVIDIA NeMo Guardrails (pattern
only, no NeMo code): a rail is a deterministic enforcement stage, and
every rail speaks one verdict vocabulary -- ALLOW / BLOCK / TRANSFORM.

The problem this closes: the product's guard seams each speak their own
vocabulary (protect gates return ``{"allowed": bool, ...}``, carrier and
egress screening return ``{"verdict": "ok"/"refuse"/"flag", ...}``). A
split-shape crossing two seams can be refused at one and silently
treated as allowed at another because the consuming seam does not
recognise the producing seam's refusal word. The adaptors in this module
are the choke point: every seam verdict is translated to a
:class:`RailVerdict` once, unknown vocabularies refuse loudly
(``rail-adapter-unknown-verdict``), and stage composition follows the
fail-closed precedence BLOCK > TRANSFORM > ALLOW.

TRANSFORM is a real semantic, not a log-only flag: it masks the
offending spans in place and continues, leaving a visible placeholder
(NeMo's ``mask_prev_user_message`` history-quarantine pattern, adapted:
scrub + visible placeholder). The masked bytes are recorded in
``masked_spans`` (never in the transformed text) so the approver sees
*that* something was scrubbed, *why*, and how much -- without the
scrubbed bytes themselves. A TRANSFORM without spans is refused:
masking with no record of what changed is an audit-trail hole, not a
verdict.

Honest limits:
- TRANSFORM masking is not a security boundary against exfiltration of
  the masked bytes via other channels (the masked value may already
  exist in the agent's context window or a parallel egress path).
- The adaptors translate verdicts; they do not re-verify the underlying
  decision. A lying producer seam is answered by that seam's own
  integrity, not by the vocabulary translation.
- "flag" from screening seams maps to BLOCK at guard seams (fail-closed);
  the monitor path remains informational and never touches these
  adaptors.

Stdlib only. Deterministic. Never raises except through the coded
:class:`RailVerdictError`.
"""

#: The three outcomes. Case-exact strings, closed vocabulary.
ALLOW = "allow"
BLOCK = "block"
TRANSFORM = "transform"
OUTCOMES = (ALLOW, BLOCK, TRANSFORM)

#: Precedence order for composition (fail-closed): BLOCK > TRANSFORM > ALLOW.
_PRECEDENCE = {BLOCK: 2, TRANSFORM: 1, ALLOW: 0}

#: Codes in the rail domain. Pinned by evals/w274_rail_probes.py.
RAIL_CODES = (
    "rail-adapter-unknown-verdict",
    "rail-transform-empty-spans",
    "rail-chunk-unlabeled",
    "rail-chunk-relabel-refused",
    "rail-merge-contract-violated",
)


class RailVerdictError(Exception):
    """Coded fail-closed refusal from the rail-verdict layer.

    ``code`` is the taxonomy refusal string; ``detail`` is human-readable
    and never carries secret material.
    """

    def __init__(self, code, detail):
        super(RailVerdictError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise RailVerdictError(code, detail)


def _placeholder(reason, nchars):
    return "[MASKED:%s:%d-chars]" % (reason, nchars)


class RailVerdict(object):
    """One uniform verdict from a guard seam.

    Attributes:
      outcome: ALLOW, BLOCK, or TRANSFORM.
      code: the taxonomy decision code carried through composition.
      reason: human-readable explanation (no secret material).
      transformed_text: for TRANSFORM, the text with masked spans replaced
        by visible placeholders; None otherwise.
      masked_spans: for TRANSFORM, the list of {"offset", "length",
        "reason"} records describing what was scrubbed. Never empty on
        TRANSFORM; the scrubbed bytes are NOT stored here.
      stage: which seam produced the verdict (informational).
      codes: the full ordered code history accumulated by combine().
    """

    __slots__ = ("outcome", "code", "reason", "transformed_text",
                 "masked_spans", "stage", "codes")

    def __init__(self, outcome, code, reason, transformed_text=None,
                 masked_spans=None, stage=None, codes=None):
        if outcome not in OUTCOMES:
            _refuse("rail-adapter-unknown-verdict",
                    "unknown rail outcome %r" % (outcome,))
        if not isinstance(code, str) or not code:
            _refuse("rail-adapter-unknown-verdict",
                    "rail verdict code must be a non-empty string")
        self.outcome = outcome
        self.code = code
        self.reason = reason if isinstance(reason, str) else str(reason)
        self.transformed_text = transformed_text
        self.masked_spans = list(masked_spans) if masked_spans else []
        self.stage = stage
        self.codes = list(codes) if codes else [code]

    def to_audit_record(self):
        """Audit-safe record: names the outcome, every code seen, and how
        many spans were masked -- never the masked bytes."""
        return {
            "outcome": self.outcome,
            "codes": list(self.codes),
            "stage": self.stage,
            "masked_spans": len(self.masked_spans),
            "span_reasons": [s.get("reason") for s in self.masked_spans],
        }

    def __repr__(self):
        return "RailVerdict(%s, %s)" % (self.outcome, self.code)


def allow(reason, code="rail-allow", stage=None):
    """An ALLOW verdict. The code defaults to the informational
    ``rail-allow``; callers SHOULD pass the seam's own code."""
    return RailVerdict(ALLOW, code, reason, stage=stage)


def block(code, reason, stage=None):
    """A BLOCK verdict. The producer's refusal code is carried through
    composition unchanged."""
    return RailVerdict(BLOCK, code, reason, stage=stage)


def mask_and_continue(text, spans, code, reason, stage=None):
    """Build a TRANSFORM verdict: mask ``spans`` in ``text`` and continue.

    ``spans`` is a list of (offset, length, span_reason) tuples. Each span
    is replaced by a visible placeholder ``[MASKED:<reason>:<n>-chars]``;
    the scrubbed bytes appear nowhere in the output. The returned verdict
    records the spans (offset/length/reason, not the bytes) and
    ``to_audit_record()`` names them, so the audit trail can never
    silently lose the fact that masking happened.

    A span list that is empty, or whose spans overlap, is refused:
    silent no-op masking and ambiguous masking are both audit holes.
    """
    if not isinstance(text, str):
        _refuse("rail-transform-empty-spans",
                "TRANSFORM text must be a string")
    spans = list(spans or [])
    if not spans:
        _refuse("rail-transform-empty-spans",
                "TRANSFORM requires at least one masked span; masking "
                "nothing with no record is an audit-trail hole")
    norm = []
    for span in spans:
        try:
            offset, length, span_reason = span
        except (TypeError, ValueError):
            _refuse("rail-transform-empty-spans",
                    "span must be (offset, length, reason)")
        if (not isinstance(offset, int) or isinstance(offset, bool)
                or not isinstance(length, int) or isinstance(length, bool)
                or offset < 0 or length <= 0
                or offset + length > len(text)):
            _refuse("rail-transform-empty-spans",
                    "span (%r, %r) out of bounds for text of length %d"
                    % (offset, length, len(text)))
        norm.append((offset, length, span_reason))
    norm.sort(key=lambda s: (s[0], s[1]))
    for (o1, l1, _), (o2, l2, _) in zip(norm, norm[1:]):
        if o2 < o1 + l1:
            _refuse("rail-transform-empty-spans",
                    "overlapping masked spans are refused: ambiguous "
                    "masking is an audit hole")
    parts = []
    cursor = 0
    masked_records = []
    for offset, length, span_reason in norm:
        parts.append(text[cursor:offset])
        parts.append(_placeholder(span_reason, length))
        masked_records.append({"offset": offset, "length": length,
                               "reason": span_reason})
        cursor = offset + length
    parts.append(text[cursor:])
    transformed = "".join(parts)
    return RailVerdict(TRANSFORM, code, reason,
                       transformed_text=transformed,
                       masked_spans=masked_records, stage=stage)


def combine(*verdicts):
    """Compose verdicts across stages: BLOCK wins over TRANSFORM wins
    over ALLOW. The winning outcome's code leads; every code seen is
    kept in ``codes``; masked spans from every TRANSFORM are kept."""
    verdicts = list(verdicts)
    if not verdicts:
        _refuse("rail-adapter-unknown-verdict",
                "combine requires at least one verdict")
    for v in verdicts:
        if not isinstance(v, RailVerdict):
            _refuse("rail-adapter-unknown-verdict",
                    "combine accepts only RailVerdict, got %s"
                    % type(v).__name__)
    best = max(verdicts, key=lambda v: _PRECEDENCE[v.outcome])
    codes = []
    for v in verdicts:
        for c in v.codes:
            if c not in codes:
                codes.append(c)
    spans = []
    for v in verdicts:
        if v.outcome == TRANSFORM:
            spans.extend(v.masked_spans)
    if best.outcome == TRANSFORM:
        # Re-derive the combined transformed text? No: combining two
        # different transformed texts is undefined. The first TRANSFORM
        # (by precedence, then order) supplies the text; all spans are
        # recorded. Documented honest limit.
        first_t = next(v for v in verdicts if v.outcome == TRANSFORM)
        return RailVerdict(TRANSFORM, best.code, best.reason,
                           transformed_text=first_t.transformed_text,
                           masked_spans=spans, stage=best.stage,
                           codes=codes)
    return RailVerdict(best.outcome, best.code, best.reason,
                       stage=best.stage, codes=codes)


# ---------------------------------------------------------------------------
# Seam adaptors: the vocabulary choke point
# ---------------------------------------------------------------------------

def _str_or_refuse(value, what):
    if not isinstance(value, str) or not value:
        _refuse("rail-adapter-unknown-verdict",
                "%s must be a non-empty string, got %r" % (what, value))
    return value


def from_gate_verdict(d, stage="protect-gate"):
    """Adapt a protect-gate verdict ``{"allowed": bool, "code": ..., ...}``
    to a RailVerdict. A missing or non-bool ``allowed`` is refused loudly:
    an unknown vocabulary must never fall through to ALLOW."""
    if not isinstance(d, dict):
        _refuse("rail-adapter-unknown-verdict",
                "gate verdict must be a dict, got %s" % type(d).__name__)
    allowed = d.get("allowed")
    if allowed is True:
        return RailVerdict(ALLOW, d.get("code") or "rail-allow",
                           "protect gate allowed", stage=stage)
    if allowed is False:
        return RailVerdict(BLOCK,
                           _str_or_refuse(d.get("code"), "gate denial code"),
                           "protect gate denied", stage=stage)
    _refuse("rail-adapter-unknown-verdict",
            "gate verdict lacks a bool 'allowed': %r" % (d,))


def from_screen_verdict(d, stage="screening"):
    """Adapt a screening verdict ``{"verdict": ..., "code": ...}`` to a
    RailVerdict. Known vocabulary: "ok"/"allow" -> ALLOW;
    "refuse"/"flag"/"block"/"deny" -> BLOCK (flag maps to BLOCK at guard
    seams, fail-closed; the monitor path never touches this adaptor).
    Unknown verdict words refuse loudly."""
    if not isinstance(d, dict):
        _refuse("rail-adapter-unknown-verdict",
                "screen verdict must be a dict, got %s" % type(d).__name__)
    verdict = d.get("verdict")
    code = d.get("code")
    if verdict == "ok" or verdict == "allow":
        return RailVerdict(ALLOW, code or "rail-allow",
                           "screening passed", stage=stage)
    if verdict in ("refuse", "flag", "block", "deny"):
        return RailVerdict(BLOCK,
                           _str_or_refuse(code, "screening refusal code"),
                           "screening refused (%s)" % verdict, stage=stage)
    _refuse("rail-adapter-unknown-verdict",
            "screening verdict word %r is not a known vocabulary; "
            "refused rather than treated as allow" % (verdict,))
