"""Agent-audit-record canonicalization contract (wave-237).

A digest join key that is stable across deployments must never be a
local-serialization artifact. This module canonicalizes JSON-shaped
audit records per RFC 8785 (JSON Canonicalization Scheme) plus the
I-JSON discipline, and refuses -- by name -- every shape that cannot
be canonicalized byte-identically on every deployment:

* ``record-duplicate-member`` -- a JSON text carrying the same object
  member twice. Duplicate keys are a canonicalization hazard: two
  deployments may keep different values. The verifier refuses rather
  than silently keeping the last one. (Duplicates can only arrive
  through ``bytes``/``str`` input: a Python ``dict`` cannot hold
  them.)
* ``record-depth-exceeded`` -- a value nested deeper than
  :data:`MAX_NESTING_DEPTH` (128) levels, where the outermost value is
  depth 1. Unbounded nesting is a parser-DoS shape; the boundary is
  pinned (a chain of 127 nested objects passes, 128 nested objects
  refuse).
* ``record-noncanonical-float`` -- ANY float value (``1.0``, ``1.5``,
  ``-0.0``, ``1e3``). Floats do not survive language boundaries
  byte-identically, so every float is a cross-deployment digest
  hazard. Integral floats are refused exactly like fractional ones:
  ``1.0`` is not ``1``.
* ``record-malformed`` -- any other shape violation: non-UTF-8 bytes
  that claim JSON, lone-surrogate escapes, non-string object keys,
  unsupported value types, invalid JSON syntax.

Deterministic output: objects sorted by UTF-16 code units (RFC 8785),
fixed ``,``/``:`` separators, no insignificant whitespace, minimal
integer encoding, short-form escapes only where required. Two
semantically-equal records -- key order shuffled, whitespace changed
-- produce byte-identical canonical output.

Non-JSON bytes are NOT coerced: ``canonicalize_record`` returns them
byte-exact with the noted ``record-opaque-bytes`` marker. The digest
then covers the raw bytes, which is still deployment-stable.

Honest non-claims (this module does not prove, it only canonicalizes):

* canonical bytes prove nothing about whether the record's claims are
  true, or that any execution happened -- they bind *which* bytes a
  digest refers to, nothing more;
* ``derive_tier`` reads the presence of non-empty attestation
  attributes (anchor, seal, receipt fields) as content structure; it
  does not authenticate them. Authentication is the verifier's job.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads. Operates on plain Python values, ``str``, or ``bytes``.
"""

import hashlib

MAX_NESTING_DEPTH = 128

MARKER_CANONICAL = "record-canonical-json"
MARKER_OPAQUE = "record-opaque-bytes"

TIER_MISMATCH_NOTE = "record-tier-mismatch"

# Tier is verifier-derived from content attributes only -- never read
# from a producer-asserted "tier" field. Higher tiers mean more
# attestation structure present, not stronger truth.
_TIER_ANCHOR_KEYS = ("anchor_digest", "transparency_log_entry")
_TIER_SEAL_KEYS = ("seal", "signature", "dsse_envelope")
_TIER_RECEIPT_KEYS = ("receipt_id", "decision_code", "capsule")


class CanonicalRecordError(Exception):
    """A record cannot be canonicalized byte-identically.

    ``code`` is the machine-readable refusal, one of
    ``record-duplicate-member``, ``record-depth-exceeded``,
    ``record-noncanonical-float``, ``record-malformed`` -- each mapped
    in ``gov/decision_codes.py`` (domain ``canonical``).
    ``detail`` names the offending position/shape for the verifier's
    log.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail))


def _malformed(detail):
    return CanonicalRecordError("record-malformed", detail)


# ---------------------------------------------------------------------------
# Strict JSON parser: duplicate-member and depth detection that the stdlib
# json module cannot do (it silently keeps the last duplicate).

class _StrictParser:
    def __init__(self, text):
        self._text = text
        self._pos = 0
        self._end = len(text)

    def parse(self):
        self._skip_ws()
        value = self._value(1)
        self._skip_ws()
        if self._pos != self._end:
            raise _malformed("trailing bytes after JSON value at %d"
                             % self._pos)
        return value

    def _skip_ws(self):
        while self._pos < self._end and self._text[self._pos] in " \t\n\r":
            self._pos += 1

    def _peek(self):
        if self._pos >= self._end:
            raise _malformed("unexpected end of JSON at %d" % self._pos)
        return self._text[self._pos]

    def _value(self, depth):
        if depth > MAX_NESTING_DEPTH:
            raise CanonicalRecordError(
                "record-depth-exceeded",
                "nesting deeper than %d levels at offset %d"
                % (MAX_NESTING_DEPTH, self._pos))
        ch = self._peek()
        if ch == "{":
            return self._object(depth)
        if ch == "[":
            return self._array(depth)
        if ch == '"':
            return self._string()
        if ch == "t":
            return self._literal("true", True)
        if ch == "f":
            return self._literal("false", False)
        if ch == "n":
            return self._literal("null", None)
        if ch == "-" or ch.isdigit():
            return self._number()
        raise _malformed("unexpected character %r at %d" % (ch, self._pos))

    def _literal(self, word, value):
        if self._text[self._pos:self._pos + len(word)] != word:
            raise _malformed("bad literal at %d" % self._pos)
        self._pos += len(word)
        return value

    def _object(self, depth):
        self._pos += 1  # consume {
        members = []
        seen = set()
        self._skip_ws()
        if self._peek() == "}":
            self._pos += 1
            return {}
        while True:
            self._skip_ws()
            if self._peek() != '"':
                raise _malformed("expected member name at %d" % self._pos)
            key = self._string()
            if key in seen:
                raise CanonicalRecordError(
                    "record-duplicate-member",
                    "duplicate member %r at offset %d" % (key, self._pos))
            seen.add(key)
            self._skip_ws()
            if self._peek() != ":":
                raise _malformed("expected ':' at %d" % self._pos)
            self._pos += 1
            self._skip_ws()
            members.append((key, self._value(depth + 1)))
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self._pos += 1
                continue
            if ch == "}":
                self._pos += 1
                return dict(members)
            raise _malformed("expected ',' or '}' at %d" % self._pos)

    def _array(self, depth):
        self._pos += 1  # consume [
        items = []
        self._skip_ws()
        if self._peek() == "]":
            self._pos += 1
            return items
        while True:
            self._skip_ws()
            items.append(self._value(depth + 1))
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self._pos += 1
                continue
            if ch == "]":
                self._pos += 1
                return items
            raise _malformed("expected ',' or ']' at %d" % self._pos)

    def _string(self):
        # Returns the decoded string; lone surrogates are malformed.
        self._pos += 1  # consume opening quote
        out = []
        while True:
            if self._pos >= self._end:
                raise _malformed("unterminated string")
            ch = self._text[self._pos]
            if ch == '"':
                self._pos += 1
                return "".join(out)
            if ch == "\\":
                out.append(self._escape())
                continue
            code = ord(ch)
            if code < 0x20:
                raise _malformed("unescaped control character at %d"
                                 % self._pos)
            out.append(ch)
            self._pos += 1

    def _escape(self):
        self._pos += 1  # consume backslash
        if self._pos >= self._end:
            raise _malformed("unterminated escape")
        esc = self._text[self._pos]
        self._pos += 1
        simple = {'"': '"', "\\": "\\", "/": "/",
                  "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
        if esc in simple:
            return simple[esc]
        if esc == "u":
            hex4 = self._text[self._pos:self._pos + 4]
            if len(hex4) != 4 or any(c not in "0123456789abcdefABCDEF"
                                     for c in hex4):
                raise _malformed("bad \\u escape at %d" % self._pos)
            self._pos += 4
            unit = int(hex4, 16)
            if 0xD800 <= unit <= 0xDBFF:
                # high surrogate: must be followed by a low surrogate
                if self._text[self._pos:self._pos + 2] != "\\u":
                    raise _malformed("lone high surrogate at %d" % self._pos)
                hex4b = self._text[self._pos + 2:self._pos + 6]
                if (len(hex4b) != 4
                        or any(c not in "0123456789abcdefABCDEF"
                               for c in hex4b)):
                    raise _malformed("bad low surrogate at %d" % self._pos)
                low = int(hex4b, 16)
                if not 0xDC00 <= low <= 0xDFFF:
                    raise _malformed("lone high surrogate at %d" % self._pos)
                self._pos += 6
                return chr(0x10000 + ((unit - 0xD800) << 10)
                           + (low - 0xDC00))
            if 0xDC00 <= unit <= 0xDFFF:
                raise _malformed("lone low surrogate at %d" % self._pos)
            return chr(unit)
        raise _malformed("bad escape %r at %d" % (esc, self._pos))

    def _number(self):
        start = self._pos
        if self._text[self._pos] == "-":
            self._pos += 1
        if self._pos >= self._end or not self._text[self._pos].isdigit():
            raise _malformed("bad number at %d" % start)
        if self._text[self._pos] == "0":
            self._pos += 1
            if (self._pos < self._end
                    and self._text[self._pos].isdigit()):
                raise _malformed("leading zero at %d" % start)
        else:
            while (self._pos < self._end
                   and self._text[self._pos].isdigit()):
                self._pos += 1
        is_float = False
        if self._pos < self._end and self._text[self._pos] == ".":
            is_float = True
            self._pos += 1
            if self._pos >= self._end or not self._text[self._pos].isdigit():
                raise _malformed("bad fraction at %d" % start)
            while (self._pos < self._end
                   and self._text[self._pos].isdigit()):
                self._pos += 1
        if (self._pos < self._end
                and self._text[self._pos] in "eE"):
            is_float = True
            self._pos += 1
            if (self._pos < self._end
                    and self._text[self._pos] in "+-"):
                self._pos += 1
            if self._pos >= self._end or not self._text[self._pos].isdigit():
                raise _malformed("bad exponent at %d" % start)
            while (self._pos < self._end
                   and self._text[self._pos].isdigit()):
                self._pos += 1
        token = self._text[start:self._pos]
        if is_float:
            # ANY float -- integral (1.0) or fractional (1.5) -- is a
            # cross-deployment digest hazard: refused, never coerced.
            raise CanonicalRecordError(
                "record-noncanonical-float",
                "float literal %r at offset %d" % (token, start))
        value = int(token)
        return 0 if value == 0 else value  # normalize -0 -> 0


# ---------------------------------------------------------------------------
# RFC 8785 serializer over parsed Python values (floats refused first).
# ---------------------------------------------------------------------------

def _utf16_sort_key(text):
    return text.encode("utf-16-be")


def _serialize_string(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_value(value, depth):
    if depth > MAX_NESTING_DEPTH:
        raise CanonicalRecordError(
            "record-depth-exceeded",
            "nesting deeper than %d levels in Python value"
            % MAX_NESTING_DEPTH)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Integral floats are refused exactly like fractional ones:
        # 1.0 is not 1 across deployments.
        raise CanonicalRecordError(
            "record-noncanonical-float",
            "float value %r cannot be canonicalized" % (value,))
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, dict):
        try:
            ordered = sorted(value.keys(), key=_utf16_sort_key)
        except Exception:  # noqa: BLE001 -- any key-shape failure is malformed
            raise _malformed("object keys must be encodable strings")
        parts = []
        for key in ordered:
            parts.append(_serialize_string(key) + ":"
                         + _serialize_value(value[key], depth + 1))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize_value(v, depth + 1)
                              for v in value) + "]"
    raise _malformed("unsupported value type %s" % type(value).__name__)


_NOT_JSON = object()


def _strict_value(text):
    """Strict-parse JSON text.

    Returns the parsed value. Raises the three mission refusal codes
    (``record-duplicate-member``, ``record-depth-exceeded``,
    ``record-noncanonical-float``) for JSON-shaped violations. Any
    other parse failure (invalid syntax, lone surrogates, leading
    zeros) returns the ``_NOT_JSON`` sentinel: the text is non-JSON,
    and non-JSON input passes through as opaque bytes.
    """
    try:
        return _StrictParser(text).parse()
    except CanonicalRecordError as exc:
        if exc.code in ("record-duplicate-member",
                        "record-depth-exceeded",
                        "record-noncanonical-float"):
            raise
        return _NOT_JSON


def _python_value(record):
    """Accept a plain Python value; refuse floats and foreign types."""
    if isinstance(record, float):
        raise CanonicalRecordError(
            "record-noncanonical-float",
            "top-level float %r cannot be canonicalized" % (record,))
    if record is None or isinstance(record, (bool, int, str, list,
                                             tuple, dict)):
        return record
    raise _malformed("unsupported record type %s"
                     % type(record).__name__)


# ---------------------------------------------------------------------------
# Public seams.
# ---------------------------------------------------------------------------

def canonicalize_record(record):
    """Canonicalize an audit record to deterministic bytes (RFC 8785).

    Returns ``(canonical_octets, marker)``. ``marker`` is
    ``record-canonical-json`` for JSON-shaped input or
    ``record-opaque-bytes`` for non-JSON bytes -- which are returned
    byte-exact, never silently coerced.

    Raises :class:`CanonicalRecordError` naming the exact shape
    violation: ``record-duplicate-member``, ``record-depth-exceeded``,
    ``record-noncanonical-float``, ``record-malformed``.
    """
    if isinstance(record, bytes):
        try:
            text = record.decode("utf-8")
        except UnicodeDecodeError:
            return bytes(record), MARKER_OPAQUE
        value = _strict_value(text)  # may raise the mission refusals
        if value is _NOT_JSON:
            return bytes(record), MARKER_OPAQUE
    elif isinstance(record, str):
        value = _strict_value(record)  # may raise the mission refusals
        if value is _NOT_JSON:
            try:
                return record.encode("utf-8"), MARKER_OPAQUE
            except UnicodeEncodeError:
                raise _malformed(
                    "record holds an unencodable lone surrogate")
    else:
        value = _python_value(record)
    try:
        octets = _serialize_value(value, 1).encode("utf-8")
    except UnicodeEncodeError:
        raise _malformed("record holds an unencodable lone surrogate")
    return octets, MARKER_CANONICAL


def derive_request_digest(record):
    """The deployment-stable digest join key for a record.

    SHA-256 (hex) over the canonical octets -- or over the raw bytes
    for opaque input. Two deployments holding semantically-equal
    records compute the same digest; no local-serialization artifact
    can enter it.
    """
    octets, _marker = canonicalize_record(record)
    return hashlib.sha256(octets).hexdigest()


def derive_tier(record):
    """Verifier-derived tier from content attributes only.

    Returns ``(tier, mismatch_note)``. The producer's asserted
    ``"tier"`` field is NEVER read: tier 3 means anchor attributes
    are present, tier 2 seal/signature attributes, tier 1 structured
    receipt attributes, tier 0 none of the above (opaque bytes are
    tier 0). When the producer asserted a tier that differs from the
    derived one, ``mismatch_note`` is ``record-tier-mismatch`` -- a
    logged note, NOT a raised refusal. The refusal belongs to the
    verifier, not to this module.

    Tier derivation reads attribute presence (non-empty values) as
    structure; it does not authenticate the attributes.
    """
    octets, marker = canonicalize_record(record)
    if marker == MARKER_OPAQUE:
        return 0, None
    value = _StrictParser(octets.decode("utf-8")).parse()
    if not isinstance(value, dict):
        return 0, None
    if any(value.get(key) for key in _TIER_ANCHOR_KEYS):
        tier = 3
    elif any(value.get(key) for key in _TIER_SEAL_KEYS):
        tier = 2
    elif any(value.get(key) for key in _TIER_RECEIPT_KEYS):
        tier = 1
    else:
        tier = 0
    asserted = value.get("tier")
    if isinstance(asserted, bool) or asserted is None:
        return tier, None
    if isinstance(asserted, int) and asserted != tier:
        return tier, TIER_MISMATCH_NOTE
    if isinstance(asserted, int):
        return tier, None
    return tier, TIER_MISMATCH_NOTE
