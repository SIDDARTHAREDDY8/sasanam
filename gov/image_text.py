"""Image-text extraction adapter (wave-271).

The ImageTextExtractor adapter seam: after wave-269's container-metadata
screen and LSB heuristic, this is the remaining image-carrier work
(wave-268 prospectus build #3). Parsing stays owned by
:mod:`gov.image_screen` -- this module composes with it, never forks
it: it turns ``extract_text_channels`` output into an extracted-text
record with provenance tags, reassembles text across channels BEFORE
screening, and flows the reassembled text into the house
instruction-shaping seam
(:func:`gov.memory_provenance.instruction_shaping_reason`).

Why reassembly matters: the wave-270 red team left an honest residual --
an instruction split across PNG ``tEXt`` + ``zTXt`` chunks evaded
per-chunk screening (each fragment alone is benign; only the join is
instruction-shaped). :func:`screen_image_text` closes exactly that gap:
channels are reassembled into one text first, then screened once.

Provenance tags (``rendered`` vs ``metadata``) are a documented
heuristic over channel semantics, not a capability boundary: they say
what a typical viewer/OS renders to a human, so downstream decisions
can distinguish "a human would see this" from "a parser would see
this". A human with a hex viewer can read anything; the tag does not
change the verdict.

Public seam: :func:`extract_image_text` and :func:`screen_image_text`.
Both are deterministic, stdlib-only, accept an explicit ``now``
(for pipeline symmetry -- extraction itself is clock-free by
construction), and never raise on hostile bytes.

Honest limits (listed on every verdict's ``out_of_scope``):
  * No OCR. Reading text out of pixels requires a vision model;
    the $0 constraint keeps it out. This closes the METADATA
    fragment gap, not pixel-level steganography. The LSB-plane
    chi-square in :mod:`gov.image_screen` stays flag-only advisory.
  * Extraction is only as complete as :mod:`gov.image_screen`'s
    parsers; EXIF UserComment parsing is best-effort there.
  * The reassembled screen is only as good as the house
    instruction-shaping seam it composes with.
  * Filler-omitted screening drops at most _MAX_FILLER_OMISSIONS
    channels per candidate (F282, wave-273): 3+ attacker filler
    channels between fragments remain a residual. Each omission is
    screened over its F290 window -- the union of _HOUSE_CHUNK_SPAN
    chunks and _WINDOW_HALF chars around the omitted gap(s), a true
    substring of the omission candidate's probe (F290, wave-275) --
    verdict-identical to the old global enumeration, in O(n) windows
    instead of O(n^3). There is no chunk-count cap and no truncation
    point, so no boundary an attacker can straddle by splitting a
    payload across it.
"""

import hashlib
import itertools
import re

from gov import image_screen as _image_screen
from gov import decode_trust as _dt

try:
    from gov import decision_codes as _decision_codes
except Exception:  # noqa: BLE001
    _decision_codes = None


CODES = (
    "imgtext-malformed",
    "imgtext-oversized",
    "imgtext-extraction-failed",
    "imgtext-reassembled-instruction-detected",
)

_MAX_IMAGE_BYTES = 8 * 1024 * 1024   # refuse before parsing (same budget)

# Channel -> provenance tag. "rendered" = a typical viewer/OS surfaces
# this text to a human (authored comments, displayable strings).
# "metadata" = structural metadata consumed by parsers. This is a
# judgment about typical rendering, documented here, not a security
# boundary: verdicts never depend on the tag.
_PROVENANCE = {
    # PNG tEXt: keyword/value operational metadata ("Software", ...).
    "png:text": "metadata",
    # PNG zTXt: compressed keyword/value operational metadata.
    "png:ztxt": "metadata",
    # PNG iTXt: internationalized text designed for human display
    # (PNG spec: "text intended for display to a human reader").
    "png:itxt": "rendered",
    # JPEG COM: free-text comment segment, shown by viewers.
    "jpeg:com": "rendered",
    # JPEG EXIF UserComment: authored free text, shown in photo
    # properties panels by cameras/OS viewers.
    "jpeg:exif-usercomment": "rendered",
    # JPEG XMP: structured metadata packet consumed by parsers/DAM
    # tooling; treated as metadata even though some fields display.
    "jpeg:xmp": "metadata",
    # GIF comment extension: authored human comment block.
    "gif:comment": "rendered",
}

_REASSEMBLY_SEPARATOR = "\n"

_OUT_OF_SCOPE = (
    "no-ocr",
    "provenance-heuristic-not-boundary",
    "jpeg-dct-domain-not-analyzed",
)


# ------------------------------------------------------------------
# Failure helper (never raises on hostile bytes; asserts the code is
# registered, which only fires during development).
# ------------------------------------------------------------------

def _fail(code, fmt, detail, evidence_extra=None):
    if _decision_codes is not None and code not in _decision_codes.TAXONOMY:
        raise AssertionError("unknown decision code: %r" % (code,))
    evidence = {"format": fmt, "detail": detail}
    if evidence_extra:
        evidence.update(evidence_extra)
    return {
        "verdict": "refuse",
        "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
        "code": code,
        "format": fmt,
        "texts": [],
        "reassembled": None,
        "checks": ["fail-closed"],
        "evidence": evidence,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


def provenance_of(channel):
    """Return 'rendered' | 'metadata' | 'unknown' for a text channel."""
    return _PROVENANCE.get(channel, "unknown")


# ------------------------------------------------------------------
# F290 (wave-275): bounded filler-omitted screening.
#
# F282 (wave-273) screens the full join plus every ordered
# subsequence omitting up to _MAX_FILLER_OMISSIONS channels --
# sum(comb(n, k) for k in 0..2) candidates, O(n^3) chars total.
# At 600 tiny channels that never returns (screening-path DoS).
# This block reformulates it verdict-identically in O(n) windows.
#
# The reformulation rests on the house-pattern register
# (gov/memory_provenance.py). Every pattern:
#   * starts with \b and has no ^/$ anchors, no lookarounds, no
#     backreferences (pinned by test_house_register_anchor_free) --
#     so a match inside a window substring is a match of the whole
#     probe, and the combined alternation is equivalent to the
#     member patterns;
#   * contains a literal word >= 3 letters (asserted by
#     _house_matchers) -- the keyword prefilter below;
#   * satisfies ONE of:
#     (a) chunk-span <= _HOUSE_CHUNK_SPAN: the match covers that
#         many space-separated chunks at most. Unbounded repeats
#         are whitespace-only (one collapsed space on a match-copy
#         probe) or space-free within a single chunk (e.g. the
#         [a-z]+ in evasion_confirmation_waiver) -- neither crosses
#         a chunk boundary. 13 of the 15 patterns are in this class
#         (max 5 spaces -> span 6);
#     (b) no unbounded space-free repeat and char length <=
#         _HOUSE_MAX_MATCH: the two .{0,N} wildcard patterns
#         (evasion_normative_descriptive, 225 chars;
#         evasion_verification_cost_framing, 114 chars). A match
#         straddling a gap then lies within _WINDOW_HALF chars of
#         it.
# A gap-straddling match of class (a) lies within _HOUSE_CHUNK_SPAN
# chunks of the gap; of class (b) within _WINDOW_HALF chars. The
# window for an omission is the UNION of the two -- a true
# substring of the omission candidate's probe -- so every
# gap-straddling match of every pattern is inside it, and every
# window match is a genuine candidate match (no anchors). With a
# clean full join, every match of an omission candidate strictly
# contains its gap(s) (a non-containing match lies in a
# prefix/suffix byte-identical -- up to collapsible whitespace --
# to the full join's), so screening the windows is
# verdict-identical to the wave-273 global enumeration, including
# the first-in-register-order reasons.
#
# 1. Blank chunks (match-copy whitespace-only) are dropped before
#    omission analysis. The seam matches against _match_copy(text)
#    and the match copy collapses whitespace, so a blank chunk
#    contributes only collapsible whitespace to any candidate: it
#    can neither create a match nor hide one, present or omitted.
# 2. Keyword prefilter: a window over [lo, hi) minus gaps is built
#    and regex-screened only if some surviving chunk in range
#    contains a house-pattern literal word (per-chunk prefix sums:
#    O(1) per candidate). A match reproduces a literal word
#    contiguously, and chunk junctions collapse to a space, so a
#    word can never form across one -- may_hit=False is exact.
# 3. Pair gate: a both-gap match of class (a) spans at most
#    _HOUSE_CHUNK_SPAN chunks, so b - a <= _HOUSE_CHUNK_SPAN; of
#    class (b) it is shorter than _HOUSE_MAX_MATCH chars, so the
#    collapsed distance between the gaps -- lower-bounded by the
#    surviving non-space chars between them -- is below
#    _HOUSE_MAX_MATCH. Both bounds grow with b, so the first b
#    failing both ends the inner loop.
#
# Net: identical verdicts on every input, O(n * _HOUSE_CHUNK_SPAN)
# windows of O(_HOUSE_CHUNK_SPAN + _WINDOW_HALF) chars instead of
# O(n^3). There is no chunk-count cap and no truncation point, so
# there is no boundary an attacker can straddle by splitting a
# payload across it -- every chunk gets full single- and
# pair-omission analysis.
# ------------------------------------------------------------------

_MAX_FILLER_OMISSIONS = 2

#: Max match length in match-copy chars, over the house patterns
#: WITHOUT an unbounded space-free repeat (the two .{0,N}
#: wildcard patterns: 225 and 114 chars). A match of one of these
#: straddling an omitted gap lies within _WINDOW_HALF chars of it.
#: Guarded by TestF290BoundedScreening::test_house_wildcard_span_stable.
_HOUSE_MAX_MATCH = 256

#: Max chunk-span over the house patterns WITH an unbounded
#: space-free repeat (13 patterns; the longest spans 5 spaces ->
#: 6 chunks). A gap-straddling match of one of these lies within
#: this many chunks of the gap. Guarded by
#: TestF290BoundedScreening::test_house_wildcard_span_stable.
_HOUSE_CHUNK_SPAN = 6

#: Char half-width of the screening window around an omitted gap.
#: Must exceed _HOUSE_MAX_MATCH plus junction slack (<= 3 chars:
#: the two single edge-spaces a chunk join can lose at a junction).
#: Guarded by TestF290BoundedScreening::test_house_wildcard_span_stable.
_WINDOW_HALF = 300

_WS_RUN = re.compile(r"\s+")


def _keep_chunks(parts):
    """Return ``[(chunk_text, match_copy)]`` for the non-blank chunks.

    A chunk is blank when the house seam's match copy of it is
    whitespace-only. Verdict-preserving: see the F290 comment block
    above. The match copies are reused by the keyword prefilter so
    each chunk's text is normalized once.
    """
    from gov.memory_provenance import _match_copy  # noqa: SLF001
    kept = []
    for t in parts:
        mc = _match_copy(t)
        if mc.strip():
            kept.append((t, mc))
    return kept


_HOUSE_KEYWORD_RE = None
_HOUSE_COMBINED_RE = None
_HOUSE_WILD_KEYWORD_RE = None


def _house_matchers():
    """(keyword_re, combined_re) for the house patterns -- cached.

    ``keyword_re`` matches any literal word (>= 3 letters) from the
    pattern sources; ``combined_re`` is the alternation of the full
    sources, so ``combined_re.search(probe)`` iff some house pattern
    matches the probe. Every pattern must contribute at least one
    literal word (asserted -- a wordless pattern would make the
    keyword prefilter unsound, so this fails closed at first use).
    Character classes are stripped before word extraction so class
    internals (e.g. the ``a`` in ``[a-z]``) can never become
    keywords. The register is static, so this is computed once.
    """
    global _HOUSE_KEYWORD_RE, _HOUSE_COMBINED_RE, _HOUSE_WILD_KEYWORD_RE
    if _HOUSE_KEYWORD_RE is None:
        from gov import memory_provenance as _mp  # noqa: SLF001
        registers = (_mp._MEMORY_INSTRUCTION_PATTERNS  # noqa: SLF001
                     + _mp._MEMORY_EVASION_PATTERNS  # noqa: SLF001
                     + _mp._MEMORY_P5_EVASION_PATTERNS)  # noqa: SLF001
        kws = set()
        sources = []
        for _reason, compiled in registers:
            src = compiled.pattern
            sources.append(src)
            words = re.findall(
                r"[A-Za-z]{3,}", re.sub(r"\[[^\]]*\]", "", src))
            assert words, (
                "house pattern without a literal word -- the F290 "
                "keyword prefilter would be unsound: %r" % (src,))
            kws.update(w.lower() for w in words)
        assert kws and sources, "empty house pattern register"
        _HOUSE_KEYWORD_RE = re.compile(
            "|".join(sorted(kws, key=len, reverse=True)))
        # Non-capturing wrap: some sources contain top-level `|`.
        # The register has no backreferences or named groups, so the
        # alternation matches iff some member pattern matches.
        _HOUSE_COMBINED_RE = re.compile(
            "|".join("(?:%s)" % s for s in sources))
        # F290: literal words (>=3 letters, outside char classes) from
        # the two wildcard patterns only. A both-gap match whose gaps
        # are more than _HOUSE_CHUNK_SPAN chunks apart must be a
        # wildcard (class b); it must contain one of these words, so
        # a window without any cannot yield one and its probe need
        # not be built.
        _wild = set()
        for _reason, _compiled in registers:
            if _reason not in ("evasion_normative_descriptive",
                               "evasion_verification_cost_framing"):
                continue
            _words = [w.lower() for w in re.findall(
                r"[A-Za-z]{3,}",
                re.sub(r"\[[^\]]*\]", "", _compiled.pattern))]
            # Per-pattern (not just union): a future wordless wildcard
            # pattern would silently make the far-pair prefilter
            # unsound -- fail closed at first use.
            assert _words, (
                "wildcard house pattern without a literal word -- the "
                "F290 far-pair prefilter would be unsound: %r" % (_reason,))
            _wild.update(_words)
        assert _wild, "wildcard patterns yielded no keywords"
        _HOUSE_WILD_KEYWORD_RE = re.compile(
            "|".join(sorted(_wild, key=len, reverse=True)))
    return _HOUSE_KEYWORD_RE, _HOUSE_COMBINED_RE, _HOUSE_WILD_KEYWORD_RE


def _screening_candidates(texts):
    """Yield ``(probe_or_None, may_hit)`` for the house screen.

    Lazy generator. A probe is the house seam's match copy of the
    candidate: the chunks, NFKC-normalized, invisible characters
    stripped, whitespace collapsed, lowercased -- built directly
    from the per-chunk match copies (joining then collapsing equals
    collapsing the true join: the two commute up to boundary
    whitespace runs, and blank chunks contribute only collapsible
    whitespace). Screening a probe is exactly what the house seam
    does to the candidate text.

    The full join's probe first (always screened), then every
    one-gap omission and every two-gap omission, each screened over
    its F290 window: the union of _HOUSE_CHUNK_SPAN chunks and
    _WINDOW_HALF chars around the omitted gap(s) -- a true
    substring of the omission candidate's probe. Verdict-identical
    to the wave-273 global enumeration (see the F290 block above).

    ``may_hit`` is False only when no surviving chunk in the window
    contains any house-pattern literal word -- then no pattern can
    match it. The screening loop skips those candidates entirely
    (``probe`` is None: nothing is built) without changing the
    verdict.
    """
    parts = [t for t in texts if t]
    kept = _keep_chunks(parts)
    n = len(kept)
    mcs = [mc for _, mc in kept]
    yield _WS_RUN.sub(" ", " ".join(mcs)), True
    if n == 0:
        return
    kw_re, _combined, _wild_re = _house_matchers()
    # Per-chunk keyword hit + prefix sums: a window over [lo, hi)
    # minus gaps needs screening iff some surviving chunk in range
    # contains a keyword -- O(1) per candidate.
    hit = [kw_re.search(mc) is not None for mc in mcs]
    pref = [0] * (n + 1)
    for i, h in enumerate(hit):
        pref[i + 1] = pref[i] + (1 if h else 0)
    # Wildcard-only hits + prefix sums, for far pairs (below).
    whit = [_wild_re.search(mc) is not None for mc in mcs]
    wpref = [0] * (n + 1)
    for i, h in enumerate(whit):
        wpref[i + 1] = wpref[i] + (1 if h else 0)
    # Per-chunk collapsed length + non-space prefix sums. Match
    # copies are already whitespace-collapsed; non-space chars
    # survive collapsing, so their prefix sums lower-bound collapsed
    # char distances -- used by the pair gate.
    lens = [len(mc) for mc in mcs]
    nsp = [0] * (n + 1)
    for i, mc in enumerate(mcs):
        nsp[i + 1] = nsp[i] + lens[i] - mc.count(" ")
    # Char-cover arrays: char_lo[a] = leftmost chunk index covering
    # _WINDOW_HALF collapsed chars left of gap a (or 0); char_hi[a]
    # symmetrically right. The window union below takes min/max
    # with the _HOUSE_CHUNK_SPAN chunk radius.
    char_lo = [0] * n
    char_hi = [0] * n
    for a in range(n):
        lo, cov = a, 0
        while lo > 0 and cov < _WINDOW_HALF:
            lo -= 1
            cov += lens[lo] + 1
        char_lo[a] = lo
        hi, cov = a + 1, 0
        while hi < n and cov < _WINDOW_HALF:
            cov += lens[hi] + 1
            hi += 1
        char_hi[a] = hi

    def _window(a, b):
        lo = min(a - _HOUSE_CHUNK_SPAN, char_lo[a])
        hi = max(b + _HOUSE_CHUNK_SPAN + 1, char_hi[b])
        return max(0, lo), min(n, hi)

    def _may_hit(lo, hi, gaps):
        c = pref[hi] - pref[lo]
        for g in gaps:
            if lo <= g < hi and hit[g]:
                c -= 1
        return c > 0

    def _probe(lo, hi, gaps):
        return _WS_RUN.sub(
            " ", " ".join(mcs[i] for i in range(lo, hi) if i not in gaps))

    # Wave-273 order: full join, then all singles, then all pairs
    # lexicographic -- the first hit (and its reason) coincides.
    for a in range(n):
        lo, hi = _window(a, a)
        # single omission {a}
        if _may_hit(lo, hi, (a,)):
            yield _probe(lo, hi, {a}), True
        else:
            yield None, False
    for a in range(n):
        # pair omissions {a, b}: a both-gap match of class (a)
        # spans at most _HOUSE_CHUNK_SPAN chunks, so b - a is
        # bounded; of class (b) it is shorter than _HOUSE_MAX_MATCH
        # chars, so the non-space chars between the gaps (a lower
        # bound on the collapsed distance) are bounded too. Both
        # grow with b: the first b failing both ends the inner
        # loop. A pair hit touching only one gap is already a hit
        # of the corresponding single (screened above), so only
        # both-gap hits need the pair. For b - a beyond the chunk
        # span, only a wildcard (class b) both-gap match is
        # possible, which needs a wildcard literal word in the
        # window -- without one the probe is skipped unbuilt.
        for b in range(a + 1, n):
            if (b - a > _HOUSE_CHUNK_SPAN
                    and nsp[b] - nsp[a + 1] >= _HOUSE_MAX_MATCH):
                break
            blo, bhi = _window(a, b)
            if b - a > _HOUSE_CHUNK_SPAN:
                wc = wpref[bhi] - wpref[blo]
                for g in (a, b):
                    if blo <= g < bhi and whit[g]:
                        wc -= 1
                if wc <= 0:
                    yield None, False
                    continue
            if _may_hit(blo, bhi, (a, b)):
                yield _probe(blo, bhi, {a, b}), True
            else:
                yield None, False
def _reassemble(texts, only=None):
    """Join channel texts in extraction order with the separator.

    ``only`` selects a provenance class, or None for every channel.
    Returns (joined_text, sha256_hex).
    """
    parts = [t for (c, t, p) in texts
             if (only is None or p == only) and t]
    joined = _REASSEMBLY_SEPARATOR.join(parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return joined, digest


# ------------------------------------------------------------------
# Public seam: extraction.
# ------------------------------------------------------------------

def extract_image_text(image_bytes, now=None):
    """Extract text channels into a provenance-tagged record.

    This is the UNTRUSTED-decode path (wave-274 lane 3): the input is
    treated as hostile. ``now`` is accepted for pipeline symmetry
    and ignored: extraction is clock-free by construction (no TTL,
    no expiry).

    Never raises. Refuses fail-closed (``imgtext-malformed``,
    ``imgtext-oversized``, ``imgtext-extraction-failed``) rather than
    silently dropping channels.
    """
    try:
        if not isinstance(image_bytes, (bytes, bytearray)):
            return _fail("imgtext-malformed", None,
                         "input is not bytes")
        data = bytes(image_bytes)
        if len(data) > _MAX_IMAGE_BYTES:
            return _fail("imgtext-oversized", None,
                         "input exceeds %d bytes" % (_MAX_IMAGE_BYTES,))
        fmt = _image_screen.classify_image(data)
        if fmt is None:
            return _fail("imgtext-malformed", None,
                         "unknown image format")
        try:
            channels = _image_screen.extract_text_channels(data)
        except _image_screen._Malformed as exc:  # noqa: SLF001
            return _fail("imgtext-extraction-failed", fmt, str(exc))
        texts = []
        for channel, text in channels:
            prov = provenance_of(channel)
            tb = text.encode("utf-8", "replace")
            texts.append({
                "channel": channel,
                "text": text,
                "provenance": prov,
                "bytes": len(tb),
                "text_digest": hashlib.sha256(tb).hexdigest(),
            })
        triples = [(c, t, provenance_of(c)) for c, t in channels]
        all_text, all_digest = _reassemble(triples)
        rendered_text, rendered_digest = _reassemble(
            triples, only="rendered")
        metadata_text, metadata_digest = _reassemble(
            triples, only="metadata")
        counts = {}
        for entry in texts:
            counts[entry["provenance"]] = (
                counts.get(entry["provenance"], 0) + 1)
        return {
            "verdict": "ok",
            "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
            "code": None,
            "format": fmt,
            "texts": texts,
            "reassembled": {
                "all_text": all_text,
                "all_digest": all_digest,
                "rendered_text": rendered_text,
                "rendered_digest": rendered_digest,
                "metadata_text": metadata_text,
                "metadata_digest": metadata_digest,
            },
            "checks": ["format:%s" % (fmt,), "extracted",
                       "provenance-tagged", "reassembled"],
            "evidence": {
                "channel_count": len(texts),
                "provenance_counts": counts,
                "channel_names": [e["channel"] for e in texts],
            },
            "out_of_scope": list(_OUT_OF_SCOPE),
        }
    except Exception as exc:  # noqa: BLE001 -- never raise
        return _fail("imgtext-malformed", None,
                     "internal extraction error: %r" % (exc,))


# ------------------------------------------------------------------
# Decode trust split (wave-274 lane 3; Cedar decode/decode_unchecked).
# ------------------------------------------------------------------

IMAGE_TRUST_SCOPE = "image-text"


def decode_trusted_image(image_bytes, evidence):
    """Trusted-decode path for image bytes.

    Requires ``evidence`` (a :class:`gov.decode_trust.TrustEvidence`
    sealed over THESE bytes under the ``"image-text"`` scope -- e.g.
    sealed by evidence-bundle verification of the artifact bytes);
    the digest binding is re-checked before parsing
    (decodetrust-no-evidence / decodetrust-binding-mismatch). The
    evidence speaks to byte PROVENANCE (these bytes are the ones the
    verifier saw), not byte BENIGNITY: extraction and the house
    screening seam still run, because a verified carrier can carry
    hostile text from further upstream. Use
    :func:`extract_image_text` for hostile bytes.
    """
    if not isinstance(image_bytes, (bytes, bytearray)):
        raise _dt.DecodeTrustError(
            "decodetrust-malformed-evidence",
            "trusted image decode requires bytes, got %s"
            % type(image_bytes).__name__)
    data = bytes(image_bytes)
    _dt.require_trust(evidence, data, scope=IMAGE_TRUST_SCOPE)
    record = extract_image_text(data)
    record["trust_evidence"] = evidence.as_dict()
    return record


# ------------------------------------------------------------------
# Public seam: screening (reassembly BEFORE the house seam).
# ------------------------------------------------------------------

def _house_reason(text):
    from gov.memory_provenance import instruction_shaping_reason
    if not text or not text.strip():
        return None
    return instruction_shaping_reason(text)


def screen_image_text(image_bytes, now=None):
    """Extract, reassemble across channels, then screen once.

    The reassembled all-channels text is screened through the house
    instruction-shaping seam; a hit refuses with
    ``imgtext-reassembled-instruction-detected``. Per-provenance
    reassembly reasons are recorded as evidence only.

    Never raises.
    """
    try:
        record = extract_image_text(image_bytes, now=now)
        if record["verdict"] != "ok":
            return {
                "verdict": record["verdict"],
                "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
                "code": record["code"],
                "format": record["format"],
                "extraction": record,
                "checks": record["checks"],
                "evidence": record["evidence"],
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        reas = record["reassembled"]
        # F282/F290: screen the full join plus filler-omitted
        # candidates -- any ordered subsequence may be the
        # instruction when the attacker owns chunk ordering. The
        # generator is lazy: candidates the keyword prefilter rules
        # out yield (None, False) and build nothing. Identical
        # windows from repeated filler are screened once (sha256
        # digests, not the window strings, so the set stays small).
        # The combined regex is one pass instead of fifteen; on a
        # hit the seam itself (_house_reason, idempotent on match
        # copies) supplies the exact first-in-register-order reason.
        # The loop breaks on the first hit.
        _combined_re = _house_matchers()[1]
        screened = 0
        seen = set()
        reason = None
        for probe, may_hit in _screening_candidates(
                [e["text"] for e in record["texts"]]):
            if not may_hit:
                continue
            digest = hashlib.sha256(probe.encode("utf-8")).digest()
            if digest in seen:
                continue
            seen.add(digest)
            screened += 1
            if _combined_re.search(probe):
                reason = _house_reason(probe)
                if reason is not None:
                    break
        evidence = {
            "format": record["format"],
            "instruction_reason": reason,
            "reassembled_digest": reas["all_digest"],
            "screened_candidates": screened,
            "hit_in_rendered":
                _house_reason(reas["rendered_text"]) is not None,
            "hit_in_metadata":
                _house_reason(reas["metadata_text"]) is not None,
            "channel_count": record["evidence"]["channel_count"],
        }
        checks = ["reassembled-screen"]
        if reason is not None:
            if (_decision_codes is not None
                    and "imgtext-reassembled-instruction-detected"
                    not in _decision_codes.TAXONOMY):
                raise AssertionError(
                    "unknown decision code: "
                    "'imgtext-reassembled-instruction-detected'")
            return {
                "verdict": "refuse",
                "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
                "code": "imgtext-reassembled-instruction-detected",
                "format": record["format"],
                "extraction": record,
                "checks": checks + ["instruction-hit"],
                "evidence": evidence,
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        return {
            "verdict": "allow",
            "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
            "code": None,
            "format": record["format"],
            "extraction": record,
            "checks": checks + ["clean"],
            "evidence": evidence,
            "out_of_scope": list(_OUT_OF_SCOPE),
        }
    except Exception as exc:  # noqa: BLE001 -- never raises
        return _fail("imgtext-malformed", None,
                     "internal screening error: %r" % (exc,))


def rail_verdict_of(record):
    """Adapt a carrier-screening verdict dict to the uniform rail
    vocabulary (wave-274 lane 2). The ``screen_image_text`` dict
    contract is unchanged; this is the uniform view. Unknown verdict
    words refuse ``rail-adapter-unknown-verdict``.
    """
    from gov import rail_verdict as _rv
    return _rv.from_screen_verdict(record, stage="carrier-screening")
