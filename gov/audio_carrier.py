"""Audio-carrier classification and containment (F191, wave-174).

MMPIBench (Nguyen & Husain, arXiv:2609.09404, section VII) measured
spoken prompt injection against agentic frameworks: where the audio
signal reaches the model the attack COMPLETES in 49% of cells (35/72;
95% interval 37-60%), and 75% for one model (gpt-audio) -- against ~1%
completion for visual carriers. The realistic shape is a plain voice
memo with split-task framing (a benign note request plus an injected
instruction), arriving by the routes such content normally arrives
(attachment, upload, shared drive) and paraphrased on its way into
memory.

Our governance layer never hears audio, but it owns the ingestion seam
the attack crosses: audio attachments in tool arguments / tool output,
their transcriptions entering memory, and tool calls made "about" audio
content. This module is that seam's vocabulary:

- ``classify_carrier(data)``: identify WAV / MP3 / OGG / FLAC by magic
  bytes. Never trusts declared MIME or filename -- a declared
  "transcript" that smells like audio bytes is a carrier mismatch, not
  a transcript.
- ``attachment_carriers(args)``: scan tool-call argument values for
  embedded audio carriers (base64 attachments), so the approval path
  can bind a carrier marker on the queue packet.
- ``resolve_carrier(declared_mime, declared_name, data)``: reconcile
  the declared content type with the byte reality; reports mismatch
  either direction.
- ``record_audio_derived_write(...)``: convenience wrapper that records
  an audio-derived memory write through
  ``gov.memory_provenance.MemoryFirewall`` with the MAC-bound
  ``input_carrier`` marker.

Honest residuals (documented, not solved): magic-byte classification is
heuristic and evadable by mislabeled carriers (audio bytes declared as
text/plain are *contained* by the mismatch policy below, but a carrier
that defeats the heuristic entirely is invisible); transcription-path
attacks (speech-to-text feeding plain text) arrive as text by
construction and are contained only by the existing text-channel
defenses; $0 means no audio-capable model is in the loop -- nothing
here claims perceptual fidelity.

$0 spend, stdlib only, deterministic, never raises on hostile input.
"""

import base64
import binascii

# Carrier names bound on ledger records / approval packets. Keep the
# vocabulary small and stable: these strings ride MAC-bound records.
CARRIER_WAV = "wav"
CARRIER_MP3 = "mp3"
CARRIER_OGG = "ogg"
CARRIER_FLAC = "flac"
CARRIER_NAMES = (CARRIER_WAV, CARRIER_MP3, CARRIER_OGG, CARRIER_FLAC)

# Only the first _SCAN_PREFIX_LEN bytes are ever inspected: carrier
# magic is a prefix property, and tool args may carry megabytes of
# base64. Never decode more than needed.
_SCAN_PREFIX_LEN = 24
_B64_SCAN_CHARS = 64  # 64 base64 chars decode to 48 bytes >= prefix

# Declared-type hints treated as "claims audio" for mismatch detection.
# Hints are never trusted for CLASSIFICATION (bytes alone classify);
# they only feed the declared-vs-bytes mismatch check.
_AUDIO_MIME_PREFIX = "audio/"
_AUDIO_FILENAME_SUFFIXES = (
    ".wav", ".wave", ".mp3", ".ogg", ".oga", ".flac", ".m4a",
    ".opus", ".aac", ".aiff", ".aif",
)


def _as_bytes(data):
    """Best-effort prefix bytes for ``data`` (bytes or str), or None.

    Strings are assumed to be base64-encoded attachments (how audio
    arrives in tool args). A strict base64 decode is attempted first;
    only the first 64 characters are decoded -- carrier magic lives in
    the first decoded bytes. Non-base64 strings are not audio.
    """
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data[:_SCAN_PREFIX_LEN])
    if isinstance(data, str):
        s = data.strip()
        if not s:
            return None
        try:
            raw = base64.b64decode(s[:_B64_SCAN_CHARS], validate=True)
        except (binascii.Error, ValueError):
            return None
        return raw[:_SCAN_PREFIX_LEN]
    return None


def _magic_is_wav(prefix):
    return (len(prefix) >= 12 and prefix[0:4] == b"RIFF"
            and prefix[8:12] == b"WAVE")


def _magic_is_mp3(prefix):
    # ID3v2 tag header. Raw MPEG frame streams without an ID3 tag are
    # NOT classified -- the two-byte frame-sync pattern (0xFF 0xE0) is
    # too loose a heuristic and false-positives on padding bytes, so
    # this classifier refuses to guess. Documented residual.
    return len(prefix) >= 3 and prefix[0:3] == b"ID3"


def _magic_is_ogg(prefix):
    return len(prefix) >= 4 and prefix[0:4] == b"OggS"


def _magic_is_flac(prefix):
    return len(prefix) >= 4 and prefix[0:4] == b"fLaC"


_MAGIC_CHECKS = (
    (CARRIER_WAV, _magic_is_wav),
    (CARRIER_MP3, _magic_is_mp3),
    (CARRIER_OGG, _magic_is_ogg),
    (CARRIER_FLAC, _magic_is_flac),
)


def classify_carrier(data):
    """Identify the audio carrier of ``data`` by magic bytes.

    Returns one of "wav" / "mp3" / "ogg" / "flac", or None when the
    bytes are not a recognized audio carrier. Accepts raw bytes or a
    base64-encoded string (attachment form). Never raises: hostile or
    malformed input classifies as None, never as audio.
    """
    try:
        prefix = _as_bytes(data)
    except Exception:  # noqa: BLE001 -- fail to None, never loud-crash
        return None
    if not prefix:
        return None
    for name, check in _MAGIC_CHECKS:
        try:
            if check(prefix):
                return name
        except Exception:  # noqa: BLE001 -- a bad check must not crash
            continue
    return None


def _declared_claims_audio(declared_mime=None, declared_name=None):
    mime = (declared_mime or "").strip().lower()
    name = (declared_name or "").strip().lower()
    if mime.startswith(_AUDIO_MIME_PREFIX):
        return True
    return any(name.endswith(suf) for suf in _AUDIO_FILENAME_SUFFIXES)


def resolve_carrier(declared_mime=None, declared_name=None, data=None):
    """Reconcile declared type with byte reality.

    Returns ``(carrier, mismatch)`` where ``carrier`` is the
    byte-classified carrier (or None) and ``mismatch`` is True when the
    declared type and the bytes disagree in either direction:

    - audio bytes declared as text/plain (or unnamed) -- the MMPIBench
      mislabeling shape; and
    - a declared audio type whose bytes are not audio.

    Classification always governs: the declared type is a hint, never
    evidence. Mismatched carriers are *contained* (bound as the
    byte-classified carrier with ``carrier_mismatch=True`` on the
    memory record, forced untrusted tier, inbox routing when an inbox
    is attached) -- never silently accepted as what they claim to be.
    """
    carrier = classify_carrier(data)
    claims_audio = _declared_claims_audio(declared_mime, declared_name)
    mismatch = claims_audio != (carrier is not None)
    return carrier, mismatch


def _iter_arg_values(args, _depth=0):
    """Yield (str|bytes) leaf values from nested tool-arg structures."""
    if _depth > 4:
        return
    if isinstance(args, dict):
        items = args.values()
    elif isinstance(args, (list, tuple, set, frozenset)):
        items = args
    else:
        items = ()
    for value in items:
        if isinstance(value, (str, bytes, bytearray)):
            # Skip tiny values: no audio magic fits in < 4 bytes, and
            # scanning every short string wastes cycles.
            if len(value) >= 4:
                yield value
        elif isinstance(value, (dict, list, tuple, set, frozenset)):
            for sub in _iter_arg_values(value, _depth + 1):
                yield sub


def attachment_carriers(args):
    """Names of audio carriers embedded in tool-call ``args``.

    Scans string/bytes leaf values (base64 attachments arrive this
    way); returns a sorted list of unique carrier names, [] when none.
    Pure function of the args -- safe to bind MAC-bound on the approval
    record at queue time and re-derive offline. A declared filename
    (e.g. "memo.wav") with non-audio bytes is NOT a carrier; only
    bytes classify.
    """
    if not isinstance(args, dict):
        return []
    found = set()
    try:
        for value in _iter_arg_values(args):
            carrier = classify_carrier(value)
            if carrier is not None:
                found.add(carrier)
    except Exception:  # noqa: BLE001 -- scan failure reads as no carrier
        pass
    return sorted(found)


def record_audio_derived_write(firewall, principal, mem_key, content,
                               writer_agent_id, writer_run_id,
                               read_fingerprints=(), tainted_run=False,
                               carrier="audio", carrier_mismatch=False,
                               now=None):
    """Record an audio-derived memory write with the carrier bound.

    ``carrier`` names the perceptual channel the bytes came from
    ("audio" is accepted as a generic alias and normalized to the
    concrete carrier when known; unknown aliases stay literal -- the
    record names what the caller knew). The marker rides the
    HMAC-chained ledger entry (``input_carrier``), so carrier policy is
    expressible downstream: read-time banners name it, the act-gate
    discloses it, and ``carrier_mismatch=True`` forces untrusted-tier
    containment with inbox routing.

    Carrier-aware containment, not content detection: a paraphrased
    split-task memo is not "detected" here -- it is *loud* because its
    carrier is bound, so no audio-derived write ever reads silent.
    """
    carrier = _normalize_carrier(carrier)
    return firewall.record_memory_write(
        principal, mem_key, content,
        writer_agent_id=writer_agent_id, writer_run_id=writer_run_id,
        read_fingerprints=read_fingerprints, tainted_run=tainted_run,
        now=now, carrier=carrier, carrier_mismatch=carrier_mismatch)


def _normalize_carrier(carrier):
    """Normalize a caller-supplied carrier label to the bound vocabulary.

    "audio" (the generic alias used by callers that know the channel
    but not the codec) binds as "audio"; concrete names pass through;
    anything else binds literally so the record stays honest about
    what the caller knew. None stays None (no carrier claimed).
    """
    if carrier is None:
        return None
    label = str(carrier).strip().lower()
    if not label:
        return None
    if label == "audio":
        return "audio"
    return label
