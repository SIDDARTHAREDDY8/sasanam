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
    channels between fragments remain a residual; the candidate count
    is sum(comb(n, k) for k in 0.._MAX_FILLER_OMISSIONS).
"""

import hashlib
import itertools

from gov import image_screen as _image_screen

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
# F282 (wave-273): filler-omitted reassembly candidates.
#
# The reassembly joins channels in file order before screening, but an
# attacker-controlled benign filler channel interleaved between two
# fragments breaks the house seam's word span in the plain join
# ("Ignore\n<filler>\n all previous instructions ..."). The attacker
# owns chunk ordering, so any ordered subsequence of channels may be
# the instruction: screen the full join plus every ordered
# subsequence that omits up to _MAX_FILLER_OMISSIONS channels.
# Omitting more than 2 is an honest residual (module docstring's
# honest limits) -- the candidate count is
# sum(comb(n, k) for k in 0.._MAX_FILLER_OMISSIONS), trivial for
# real-world channel counts.
# ------------------------------------------------------------------

_MAX_FILLER_OMISSIONS = 2


def _screening_candidates(texts):
    """Yield reassembled-text candidates for the house screen.

    Same parts as :func:`_reassemble` (non-empty, extraction order):
    the full join, then every ordered subsequence omitting up to
    ``_MAX_FILLER_OMISSIONS`` channels. Deduped.
    """
    parts = [t for t in texts if t]
    n = len(parts)
    seen = set()

    def emit(idxs):
        joined = _REASSEMBLY_SEPARATOR.join(parts[i] for i in idxs)
        if joined not in seen:
            seen.add(joined)
            yield joined

    full = list(range(n))
    yield from emit(full)
    for k in range(1, _MAX_FILLER_OMISSIONS + 1):
        for omit in itertools.combinations(full, k):
            omitted = set(omit)
            yield from emit([i for i in full if i not in omitted])


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

    ``now`` is accepted for pipeline symmetry and ignored: extraction
    is clock-free by construction (no TTL, no expiry).

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
                "code": record["code"],
                "format": record["format"],
                "extraction": record,
                "checks": record["checks"],
                "evidence": record["evidence"],
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        reas = record["reassembled"]
        # F282: screen the full join plus filler-omitted candidates --
        # any ordered subsequence may be the instruction when the
        # attacker owns chunk ordering.
        candidates = list(_screening_candidates(
            [e["text"] for e in record["texts"]]))
        reason = None
        for candidate in candidates:
            reason = _house_reason(candidate)
            if reason is not None:
                break
        evidence = {
            "format": record["format"],
            "instruction_reason": reason,
            "reassembled_digest": reas["all_digest"],
            "screened_candidates": len(candidates),
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
                "code": "imgtext-reassembled-instruction-detected",
                "format": record["format"],
                "extraction": record,
                "checks": checks + ["instruction-hit"],
                "evidence": evidence,
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        return {
            "verdict": "allow",
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
