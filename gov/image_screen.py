"""Image-carrier instruction screening (wave-269).

Closes the image-carrier gap from the wave-267 OWASP prospectus:
F191 closed the audio carrier; image carriers were open. Images
reach the agent through tool results, memory, and message parts,
and their container metadata (PNG ``tEXt``/``zTXt``/``iTXt``,
JPEG ``COM`` segments and APP1 EXIF ``UserComment``/XMP, GIF
comment extensions) can carry instruction text the same way audio
sub-bands could.

Public seam: :func:`screen_image` -- deterministic, stdlib-only,
never raises on hostile bytes. Container structures are parsed by
hand (magic bytes first, like :mod:`gov.audio_carrier`); the
declared MIME is never trusted. Extracted text is screened through
the house per-chunk seam
(:func:`gov.memory_provenance.instruction_shaping_reason`) rather
than a second copy of the heuristic.

The LSB-plane chi-square is a **flag-only advisory**
(``imgscreen-stego-suspect``), never a denial: it detects a
statistical anomaly consistent with least-significant-bit
embedding, which is a weaker claim than "this image carries a
payload" (compressed, palette-quantized, or re-encoded images
produce false positives; a careful embedder produces false
negatives). Honest known-FP caveat, kept in ``out_of_scope`` on
every verdict.

Known out-of-scope (listed on every verdict):
  * DCT-domain LSB analysis for JPEG (pixels never decoded).
  * EXIF parsing is best-effort: an unparseable APP1 EXIF block is
    noted, not fatal, so a corrupt camera trailer cannot flip an
    otherwise-clean verdict.
  * Instruction detection is only as good as the house
    per-chunk seam it composes with.
"""

import binascii
import hashlib
import struct
import zlib

try:
    from gov import decision_codes as _decision_codes
except Exception:  # noqa: BLE001
    _decision_codes = None


CODES = (
    "imgscreen-instruction-detected",
    "imgscreen-malformed",
    "imgscreen-oversized",
    "imgscreen-stego-suspect",
)

_MAX_IMAGE_BYTES = 8 * 1024 * 1024       # refuse before parsing
_MAX_TEXT_BYTES = 1024 * 1024           # per text channel (zlib-bomb cap)
_MAX_IDAT_DECOMPRESSED = 64 * 1024 * 1024
_MAX_LSB_SAMPLES = 200_000              # chi-square input cap
_MAX_GIF_PIXELS = 16 * 1024 * 1024
_LSB_MIN_PAIRS = 20
# Chi-square/dof ratio ceiling for flagging: a perfectly uniform
# LSB plane scores ~1.0. The ceiling is calibrated against
# synthetic stego vs. structured images in evals/w269_imgscreen_probes.py;
# keep it flag-only regardless of the value (see module docstring).
_LSB_RATIO_MAX = 2.0

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_SOI = b"\xff\xd8"
_GIF_MAGIC_87 = b"GIF87a"
_GIF_MAGIC_89 = b"GIF89a"

_OUT_OF_SCOPE = (
    "jpeg-lsb-skipped",
    "exif-best-effort",
    "stego-advisory-not-denial",
    "jpeg-dct-domain-not-analyzed",
)


# ------------------------------------------------------------------
# Failure helper.
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
        "extracted_text_digest": hashlib.sha256(b"").hexdigest(),
        "texts": [],
        "checks": ["fail-closed"],
        "evidence": evidence,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


def _verdict_dict(verdict, code, fmt, texts, checks, evidence):
    digest = hashlib.sha256(
        "\x00".join(t for _, t in texts).encode("utf-8")).hexdigest()
    text_dicts = [{"channel": c, "text": t} for (c, t) in texts]
    ev = {"format": fmt}
    ev.update(evidence or {})
    return {
        "verdict": verdict,
        "code": code,
        "format": fmt,
        "extracted_text_digest": digest,
        "texts": text_dicts,
        "checks": checks,
        "evidence": ev,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


# ------------------------------------------------------------------
# Format classification (magic bytes; never the declared MIME).
# ------------------------------------------------------------------

def classify_image(data):
    """Return 'png', 'jpeg', 'gif', or None. Never raises."""
    try:
        if not isinstance(data, (bytes, bytearray)):
            return None
        if data.startswith(_PNG_MAGIC):
            return "png"
        if data.startswith(_JPEG_SOI):
            return "jpeg"
        if data.startswith((_GIF_MAGIC_87, _GIF_MAGIC_89)):
            return "gif"
        return None
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------
# PNG parsing.
# ------------------------------------------------------------------

def _parse_png(data):
    """Return (texts, idat_bytes) or raise _Malformed."""
    pos = len(_PNG_MAGIC)
    texts = []
    idat_parts = []
    seen_iend = False
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        chunk_end = pos + 8 + length
        if chunk_end + 4 > len(data):
            raise _Malformed("truncated png chunk %r" % (ctype,))
        payload = data[pos + 8:chunk_end]
        (crc,) = struct.unpack(">I", data[chunk_end:chunk_end + 4])
        if (binascii.crc32(ctype + payload) & 0xFFFFFFFF) != crc:
            raise _Malformed("png crc mismatch on %r" % (ctype,))
        if ctype == b"tEXt":
            texts.append(("png:text", _png_text(payload)))
        elif ctype == b"zTXt":
            texts.append(("png:ztxt", _png_ztxt(payload)))
        elif ctype == b"iTXt":
            texts.append(("png:itxt", _png_itxt(payload)))
        elif ctype == b"IDAT":
            idat_parts.append(payload)
        elif ctype == b"IEND":
            seen_iend = True
            break
        pos = chunk_end + 4
    if not seen_iend:
        raise _Malformed("png missing IEND")
    return texts, b"".join(idat_parts)


class _Malformed(Exception):
    pass


def _split_keyword(payload):
    nul = payload.find(b"\x00")
    if nul < 0:
        raise _Malformed("text chunk without keyword terminator")
    return nul


def _png_text(payload):
    nul = _split_keyword(payload)
    text = payload[nul + 1:]
    if len(text) > _MAX_TEXT_BYTES:
        raise _Malformed("png tEXt too large")
    return text.decode("latin-1")


def _png_ztxt(payload):
    nul = _split_keyword(payload)
    if nul + 2 > len(payload):
        raise _Malformed("truncated png zTXt")
    comp_method = payload[nul + 1]
    if comp_method != 0:
        raise _Malformed("unknown png zTXt compression method")
    raw = payload[nul + 2:]
    try:
        out = zlib.decompress(raw, bufsize=_MAX_TEXT_BYTES + 1)
    except Exception as exc:  # noqa: BLE001
        raise _Malformed("png zTXt decompression failed: %r" % (exc,))
    if len(out) > _MAX_TEXT_BYTES:
        raise _Malformed("png zTXt too large")
    return out.decode("latin-1")


def _png_itxt(payload):
    nul = _split_keyword(payload)
    if nul + 3 > len(payload):
        raise _Malformed("truncated png iTXt header")
    comp_flag = payload[nul + 1]
    comp_method = payload[nul + 2]
    lang_end = payload.find(b"\x00", nul + 3)
    if lang_end < 0:
        raise _Malformed("truncated png iTXt language tag")
    # PNG spec: the translated keyword follows the language tag, NUL
    # terminated, and only the text AFTER it is the international text.
    # Everything from lang_end+1 through the translated-keyword NUL is
    # never displayed by a spec-compliant consumer -- keeping it in
    # extracted text hands an attacker invisible bytes at a fragment
    # join (F277 empty keyword; F283 non-empty keyword).
    translated_end = payload.find(b"\x00", lang_end + 1)
    if translated_end < 0:
        raise _Malformed("truncated png iTXt translated keyword")
    text = payload[translated_end + 1:]
    if comp_flag == 1:
        if comp_method != 0:
            raise _Malformed("unknown png iTXt compression method")
        try:
            text = zlib.decompress(text, bufsize=_MAX_TEXT_BYTES + 1)
        except Exception as exc:  # noqa: BLE001
            raise _Malformed("png iTXt decompression failed: %r"
                             % (exc,))
        if len(text) > _MAX_TEXT_BYTES:
            raise _Malformed("png iTXt too large")
    elif comp_flag != 0:
        raise _Malformed("bad png iTXt compression flag")
    return text.decode("utf-8", "replace")


def _png_ihdr(data):
    """Return (width, height, bit_depth, color_type, interlace)."""
    if len(data) < len(_PNG_MAGIC) + 25:
        raise _Malformed("png too short for IHDR")
    (length,) = struct.unpack(">I", data[8:12])
    if data[12:16] != b"IHDR" or length != 13:
        raise _Malformed("png first chunk is not IHDR")
    (width, height, bit_depth, color_type, _comp, _filt,
     interlace) = struct.unpack(">IIBBBBB", data[16:29])
    if width <= 0 or height <= 0 or width > 100000 or height > 100000:
        raise _Malformed("png impossible dimensions")
    return width, height, bit_depth, color_type, interlace


def _png_pixel_bytes(data):
    """Decode 8-bit non-interlaced PNG (types 0/2/6) to raw bytes.

    Returns the unfiltered sample stream, or None when the color
    type/bit depth is outside the decoder's scope (documented, not
    an error: the metadata path already ran).
    """
    width, height, bit_depth, color_type, interlace = _png_ihdr(data)
    if bit_depth != 8 or interlace != 0:
        return None
    bpp = {0: 1, 2: 3, 6: 4}.get(color_type)
    if bpp is None:
        return None
    texts_idat = _parse_png(data)[1]
    try:
        raw = zlib.decompress(texts_idat)
    except Exception as exc:  # noqa: BLE001
        raise _Malformed("png IDAT decompression failed: %r" % (exc,))
    if len(raw) > _MAX_IDAT_DECOMPRESSED:
        raise _Malformed("png IDAT too large")
    stride = width * bpp
    if len(raw) != height * (stride + 1):
        raise _Malformed("png IDAT size mismatch")
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _ in range(height):
        ftype = raw[pos]
        pos += 1
        cur = bytearray(raw[pos:pos + stride])
        pos += stride
        if ftype == 1:  # Sub
            for i in range(bpp, stride):
                cur[i] = (cur[i] + cur[i - bpp]) & 0xFF
        elif ftype == 2:  # Up
            for i in range(stride):
                cur[i] = (cur[i] + prev[i]) & 0xFF
        elif ftype == 3:  # Average
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:  # Paeth
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                if pa <= pb and pa <= pc:
                    pr = a
                elif pb <= pc:
                    pr = b
                else:
                    pr = c
                cur[i] = (cur[i] + pr) & 0xFF
        elif ftype != 0:
            raise _Malformed("png unknown filter type")
        out += cur
        prev = cur
    return bytes(out)


# ------------------------------------------------------------------
# JPEG parsing.
# ------------------------------------------------------------------

# Markers without a length field after them.
_JPEG_STANDALONE = frozenset(
    [0x01] + list(range(0xD0, 0xD8 + 1)))


def _parse_jpeg(data):
    """Return (texts, exif_note). JPEG pixels are never decoded."""
    texts = []
    exif_note = None
    pos = 2  # past SOI
    n = len(data)
    saw_eoi = False
    saw_sos = False
    while pos + 2 <= n:
        if data[pos] != 0xFF:
            raise _Malformed("jpeg expected marker")
        marker = data[pos + 1]
        pos += 2
        if marker == 0x00 or marker == 0xFF:
            # Fill bytes / stuffed byte: resync on next marker.
            pos -= 1
            continue
        if marker == 0xD9:  # EOI: clean end of image
            saw_eoi = True
            break
        if marker in _JPEG_STANDALONE:
            continue
        if marker == 0xDA:  # SOS: entropy data follows; stop walking.
            saw_sos = True
            break
        if pos + 2 > n:
            raise _Malformed("truncated jpeg segment header")
        (seg_len,) = struct.unpack(">H", data[pos:pos + 2])
        if seg_len < 2 or pos + seg_len > n:
            raise _Malformed("jpeg bad segment length")
        seg = data[pos + 2:pos + seg_len]
        if marker == 0xFE:  # COM
            if len(seg) > _MAX_TEXT_BYTES:
                raise _Malformed("jpeg COM too large")
            texts.append(("jpeg:com", seg.decode("latin-1")))
        elif marker == 0xE1:  # APP1: EXIF or XMP
            if seg.startswith(b"Exif\x00\x00"):
                comments, note = _exif_usercomment(seg[6:])
                for comment in comments:
                    texts.append(("jpeg:exif-usercomment", comment))
                if note:
                    exif_note = note
            elif seg.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                payload = seg[29:]
                if len(payload) > _MAX_TEXT_BYTES:
                    raise _Malformed("jpeg XMP too large")
                texts.append(("jpeg:xmp",
                              payload.decode("utf-8", "replace")))
        pos += seg_len
    if not saw_eoi and not saw_sos:
        # No EOI and no scan data: truncated container, fail closed.
        # ( past-SOS entropy tails are not EOI-verified; the metadata
        # channels that carry the security property precede SOS.)
        raise _Malformed("jpeg truncated: no EOI")
    return texts, exif_note


def _tiff_int(data, off, size, little):
    fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
    return struct.unpack(("<" if little else ">") + fmt,
                         data[off:off + size])[0]


def _read_ifd_entries(tiff, ifd_off, little):
    """Yield (tag, type, count, value_offset_or_inline) with bounds."""
    n = len(tiff)
    if ifd_off + 2 > n:
        raise _Malformed("exif ifd out of range")
    count = _tiff_int(tiff, ifd_off, 2, little)
    if count > 256 or ifd_off + 2 + count * 12 > n:
        raise _Malformed("exif ifd count impossible")
    for i in range(count):
        e = ifd_off + 2 + i * 12
        tag = _tiff_int(tiff, e, 2, little)
        ftype = _tiff_int(tiff, e + 2, 2, little)
        fcount = _tiff_int(tiff, e + 4, 4, little)
        val = _tiff_int(tiff, e + 8, 4, little)
        yield tag, ftype, fcount, val


def _exif_field_bytes(tiff, ftype, fcount, val, little):
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}
    size = sizes.get(ftype)
    if size is None:
        return None
    total = fcount * size
    if total > _MAX_TEXT_BYTES or total <= 0:
        return None
    if total <= 4:
        raw = struct.pack(("<" if little else ">") + "I", val)[:total]
        return raw
    if val + total > len(tiff):
        return None
    return tiff[val:val + total]


def _exif_usercomment(tiff):
    """Return ([text, ...], note_or_None). Best-effort: any structural
    problem yields ([], 'exif-unparseable') instead of failing the
    whole image.

    When the 8-byte charset tag is unrecognized, the field is
    ambiguous -- the head may be a nonstandard tag or the start of
    the content itself. BOTH readings are returned: the tag-stripped
    text (an unrecognized tag's bytes must not sit attacker-positioned
    at a fragment join, F284) and the whole-field text (tag-omission
    tolerance: dropping the first 8 bytes of tag-less content would
    truncate a screened instruction, w269 p12). The screen refuses if
    either reading is instruction-shaped.
    """
    try:
        if len(tiff) < 8:
            return [], "exif-unparseable"
        if tiff[:2] == b"II":
            little = True
        elif tiff[:2] == b"MM":
            little = False
        else:
            return [], "exif-unparseable"
        magic = _tiff_int(tiff, 2, 2, little)
        if magic != 42:
            return [], "exif-unparseable"
        ifd_off = _tiff_int(tiff, 4, 4, little)

        def find_comment(off, depth):
            if depth > 2:
                return None
            for tag, ftype, fcount, val in _read_ifd_entries(
                    tiff, off, little):
                if tag == 0x9286 and ftype == 7:  # UserComment
                    return _exif_field_bytes(tiff, ftype, fcount, val,
                                             little)
                if tag == 0x8769 and ftype == 4 and fcount == 1:
                    sub = _exif_field_bytes(tiff, ftype, fcount, val,
                                            little)
                    if sub is not None:
                        got = find_comment(
                            struct.unpack(
                                ("<" if little else ">") + "I",
                                sub)[0], depth + 1)
                        if got is not None:
                            return got
            return None

        raw = find_comment(ifd_off, 0)
        if raw is None:
            return [], "exif-no-usercomment"
        # The spec prefixes an 8-byte charset tag; strip it when
        # recognized and decode the rest with its charset.
        if raw[:8] == b"UNICODE\x00":
            return [raw[8:].decode("utf-16", "replace")], None
        if raw[:8] == b"ASCII\x00\x00\x00":
            return [raw[8:].decode("ascii", "replace")], None
        if raw[:8] == b"JIS\x00\x00\x00\x00\x00":
            return [raw[8:].decode("shift_jis", "replace")], None
        whole = raw.decode("latin-1")
        if len(raw) < 8:
            # No complete tag could be present; nothing ambiguous.
            return [whole], None
        # Unrecognized head: emit both readings (see docstring).
        stripped = raw[8:].decode("latin-1")
        readings = [stripped]
        if whole != stripped:
            readings.append(whole)
        return readings, None
    except _Malformed:
        return [], "exif-unparseable"
    except Exception:  # noqa: BLE001
        return [], "exif-unparseable"


# ------------------------------------------------------------------
# GIF parsing.
# ------------------------------------------------------------------

def _read_subblocks(data, pos):
    """Return (bytes, new_pos)."""
    out = bytearray()
    n = len(data)
    while True:
        if pos >= n:
            raise _Malformed("truncated gif sub-blocks")
        size = data[pos]
        pos += 1
        if size == 0:
            break
        if pos + size > n:
            raise _Malformed("truncated gif sub-block data")
        out += data[pos:pos + size]
        pos += size
        if len(out) > _MAX_TEXT_BYTES:
            raise _Malformed("gif sub-blocks too large")
    return bytes(out), pos


def _gif_lzw_decode(data, min_code, expect):
    """Decode GIF LZW to palette indices, capped at ``expect`` bytes."""
    clear = 1 << min_code
    eoi = clear + 1
    expect = min(expect, _MAX_GIF_PIXELS)
    out = bytearray()
    bitpos = 0
    nbits_total = len(data) * 8

    def read_bits(width):
        nonlocal bitpos
        val = 0
        for i in range(width):
            if bitpos >= nbits_total:
                raise _Malformed("gif lzw bit stream truncated")
            val |= ((data[bitpos >> 3] >> (bitpos & 7)) & 1) << i
            bitpos += 1
        return val

    def reset():
        table = [bytes([i]) for i in range(clear)] + [None] * (4096 - clear)
        return table, clear + 2, min_code + 1

    table, next_code, width = reset()
    prev = None
    # Width-growth timing: the decoder's table lags the encoder's by
    # exactly one entry (the encoder learns a string when it emits the
    # code that extends it; the decoder learns it when it reads the
    # next code), and both sides grow early. So the decoder tests
    # next_code + 1 -- the encoder's next_code -- after processing
    # every code, including the first after clear (which adds no
    # entry but still advances the encoder's table). The check never
    # runs on the clear itself: the first code after clear always
    # uses min+1 bits.
    def maybe_grow():
        nonlocal next_code, width
        while width < 12 and next_code + 1 >= (1 << width):
            width += 1

    while len(out) < expect:
        code = read_bits(width)
        if code == clear:
            table, next_code, width = reset()
            prev = None
            continue
        if code == eoi:
            break
        if code < len(table) and table[code] is not None:
            entry = table[code]
        elif code == next_code and prev is not None:
            entry = prev + prev[:1]
        else:
            raise _Malformed("gif lzw bad code")
        out += entry[:max(0, expect - len(out))]
        if prev is not None and next_code < 4096:
            table[next_code] = prev + entry[:1]
            next_code += 1
        maybe_grow()
        prev = entry
    return bytes(out)


def _parse_gif(data):
    """Return (texts, lsb_stream_or_None)."""
    texts = []
    lsb = None
    saw_trailer = False
    n = len(data)
    if n < 13:
        raise _Malformed("gif too short")
    packed = data[10]  # LSD packed field: width(2) height(2) packed(1)
    pos = 13
    if packed & 0x80:
        gct = 3 * (1 << ((packed & 0x07) + 1))
        pos += gct
        if pos > n:
            raise _Malformed("gif truncated global color table")
    while pos < n:
        block = data[pos]
        pos += 1
        if block == 0x3B:  # trailer
            saw_trailer = True
            break
        if block == 0x21:  # extension
            if pos >= n:
                raise _Malformed("truncated gif extension")
            label = data[pos]
            pos += 1
            if label == 0xFE:  # comment
                raw, pos = _read_subblocks(data, pos)
                texts.append(("gif:comment", raw.decode("latin-1")))
            elif label == 0xF9:  # graphic control
                if pos + 5 > n or data[pos + 4] != 0:
                    raise _Malformed("bad gif graphic control ext")
                pos += 5
            elif label == 0xFF:  # application
                if pos >= n:
                    raise _Malformed("truncated gif app ext")
                pos += data[pos] + 1
                _, pos = _read_subblocks(data, pos)
            elif label == 0x01:  # plain text
                if pos >= n:
                    raise _Malformed("truncated gif text ext")
                pos += data[pos] + 1
                _, pos = _read_subblocks(data, pos)
            else:
                _, pos = _read_subblocks(data, pos)
        elif block == 0x2C:  # image descriptor
            if pos + 9 > n:
                raise _Malformed("truncated gif image descriptor")
            iw = struct.unpack("<H", data[pos + 4:pos + 6])[0]
            ih = struct.unpack("<H", data[pos + 6:pos + 8])[0]
            ip = data[pos + 8]
            pos += 9
            if ip & 0x80:
                pos += 3 * (1 << ((ip & 0x07) + 1))
            if iw <= 0 or ih <= 0 or iw * ih > _MAX_GIF_PIXELS:
                raise _Malformed("gif impossible image size")
            if pos >= n:
                raise _Malformed("truncated gif lzw header")
            min_code = data[pos]
            pos += 1
            if min_code > 8:
                raise _Malformed("gif bad lzw min code size")
            lzw_data, pos = _read_subblocks(data, pos)
            if lsb is None:
                lsb = _gif_lzw_decode(lzw_data, min_code, iw * ih)
        else:
            raise _Malformed("gif unknown block 0x%02x" % (block,))
    if not saw_trailer:
        raise _Malformed("gif truncated: no trailer")
    return texts, lsb


# ------------------------------------------------------------------
# Text-channel extraction (public seam for pipelines).
# ------------------------------------------------------------------

def extract_text_channels(data):
    """Return [(channel, text)] for every metadata text channel.

    Raises _Malformed on truncated/impossible structure; never
    raises on merely-unparseable best-effort fields (EXIF).
    """
    fmt = classify_image(data)
    if fmt is None:
        raise _Malformed("unknown image format")
    if fmt == "png":
        texts, _ = _parse_png(data)
        return texts
    if fmt == "jpeg":
        texts, _ = _parse_jpeg(data)
        return texts
    texts, _ = _parse_gif(data)
    return texts


# ------------------------------------------------------------------
# LSB chi-square (flag-only advisory).
# ------------------------------------------------------------------

def lsb_chi_square(stream):
    """Chi-square pairs-of-values test over a byte stream.

    Returns (chi2, dof, ratio) or None when there are too few
    populated pairs to say anything. A uniform (randomized) LSB
    plane scores ratio ~1.0; structured data scores far higher.
    """
    if not stream:
        return None
    sample = stream[:_MAX_LSB_SAMPLES]
    hist = [0] * 256
    for b in sample:
        hist[b] += 1
    chi2 = 0.0
    dof = 0
    for k in range(128):
        n = hist[2 * k] + hist[2 * k + 1]
        if n < 10:
            continue
        e = n / 2.0
        chi2 += ((hist[2 * k] - e) ** 2) / e
        chi2 += ((hist[2 * k + 1] - e) ** 2) / e
        dof += 1
    if dof < _LSB_MIN_PAIRS:
        return None
    return chi2, dof, chi2 / dof


def _lsb_stream(fmt, data):
    """Return the byte stream for LSB analysis, or None when the
    format is out of the decoder's scope (documented, not an error)."""
    try:
        if fmt == "png":
            return _png_pixel_bytes(data)
        if fmt == "gif":
            _, lsb = _parse_gif(data)
            return lsb
    except _Malformed:
        raise
    except Exception:  # noqa: BLE001
        return None
    return None  # jpeg: DCT domain, documented out-of-scope


# ------------------------------------------------------------------
# Instruction screening (composes the house per-chunk seam).
# ------------------------------------------------------------------

def _screen_texts(texts):
    """Return the instruction_shaping_reason tag or None."""
    from gov.memory_provenance import instruction_shaping_reason
    for _channel, text in texts:
        if not text or not text.strip():
            continue
        reason = instruction_shaping_reason(text)
        if reason is not None:
            return reason
    return None


# ------------------------------------------------------------------
# Public seam.
# ------------------------------------------------------------------

def screen_image(image_bytes, context=None):
    """Screen image bytes for instruction carriers. Never raises.

    Verdicts: allow (no issue), flag (advisory only:
    imgscreen-stego-suspect), refuse (fail-closed: instruction
    text, malformed structure, or oversized input).
    """
    try:
        if not isinstance(image_bytes, (bytes, bytearray)):
            return _fail("imgscreen-malformed", None,
                         "input is not bytes")
        data = bytes(image_bytes)
        if len(data) > _MAX_IMAGE_BYTES:
            return _fail("imgscreen-oversized", None,
                         "input exceeds %d bytes" % (_MAX_IMAGE_BYTES,))
        fmt = classify_image(data)
        if fmt is None:
            return _fail("imgscreen-malformed", None,
                         "unknown image format")
        checks = ["format:%s" % (fmt,), "text-channels"]
        try:
            texts = extract_text_channels(data)
        except _Malformed as exc:
            return _fail("imgscreen-malformed", fmt, str(exc))
        evidence = {
            "text_channels": [
                {"channel": c,
                 "bytes": len(t.encode("utf-8", "replace")),
                 "text_digest": hashlib.sha256(
                     t.encode("utf-8", "replace")).hexdigest()}
                for c, t in texts
            ],
        }
        reason = _screen_texts(texts)
        evidence["instruction_reason"] = reason
        if reason is not None:
            return _verdict_dict("refuse",
                                 "imgscreen-instruction-detected",
                                 fmt, texts, checks + ["instruction-hit"],
                                 evidence)

        # LSB advisory (flag-only; decode failures are not verdicts).
        checks.append("lsb")
        lsb_evidence = None
        try:
            stream = _lsb_stream(fmt, data)
        except _Malformed as exc:
            return _fail("imgscreen-malformed", fmt, str(exc))
        if stream:
            stat = lsb_chi_square(stream)
            if stat is not None:
                chi2, dof, ratio = stat
                lsb_evidence = {"samples": min(len(stream),
                                               _MAX_LSB_SAMPLES),
                                "pairs": dof,
                                "chi2": round(chi2, 3),
                                "ratio": round(ratio, 3)}
                if ratio < _LSB_RATIO_MAX:
                    evidence["lsb"] = lsb_evidence
                    return _verdict_dict(
                        "flag", "imgscreen-stego-suspect", fmt, texts,
                        checks + ["lsb-anomaly"], evidence)
        if lsb_evidence is not None:
            evidence["lsb"] = lsb_evidence
        return _verdict_dict("allow", None, fmt, texts,
                             checks + ["clean"], evidence)
    except Exception as exc:  # noqa: BLE001 -- never raise on hostile bytes
        return _fail("imgscreen-malformed", None,
                     "internal screening error: %r" % (exc,))


def record_image_derived_write(firewall, principal, mem_key, content,
                               writer_agent_id, writer_run_id,
                               read_fingerprints=(), tainted_run=False,
                               carrier="image", carrier_mismatch=False,
                               now=None):
    """Record an image-derived memory write with the carrier bound.

    Mirrors :func:`gov.audio_carrier.record_audio_derived_write`:
    the carrier marker rides the HMAC-chained ledger entry so
    image-derived writes are loud, never silent. The image screen
    verdict itself is attached separately by the caller; this
    wrapper binds the carrier, not the screening outcome.
    """
    return firewall.record_memory_write(
        principal, mem_key, content,
        writer_agent_id=writer_agent_id, writer_run_id=writer_run_id,
        read_fingerprints=read_fingerprints, tainted_run=tainted_run,
        now=now, carrier=carrier, carrier_mismatch=carrier_mismatch)
