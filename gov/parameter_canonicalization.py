"""Parameter canonicalization (W241-6 / onedoor ND-048, re-derived prose only).

Re-derived invariant from onedoor's own honest gap ND-048
("obfuscated command construction defeats parameter rules"): a
parameter allowlist that compares raw strings is defeated by shell
obfuscation -- string-spliced literals (``"ec"ho``), quote juggling,
``sh -c`` wrapping, and base64-wrapped payloads. The invariant: the
command is canonicalized BEFORE the allowlist/denylist comparison, and
the canonical comparison is authoritative.

``canonicalize(command)`` applies, in a fixed deterministic order:
  1. ``sh -c <payload>`` / ``bash -c <payload>`` / ``dash -c <payload>``
     unwrapping, applied repeatedly (nested wrappers).
  2. base64 payload decoding: ``echo <b64> | base64 -d`` style
     constructions have their decodable payload embedded in the
     canonical form. Only strict base64 (validate=True) is decoded.
  3. quote removal: all ``"`` and ``'`` characters are stripped, so
     spliced literals (``"ec"ho``) collapse to ``echo``.
  4. whitespace normalization: runs of whitespace collapse to single
     spaces, ends stripped.

``check_parameters(command, allowed_prefixes, denied_substrings)``
canonicalizes first, then compares. A denied substring present in the
canonical form refuses ``parameter-obfuscation`` -- even when the raw
string would have passed -- because the raw comparison was the
defeated one. A command outside the allowed prefixes is not an
obfuscation refusal; it returns ``{"allowed": False, ...}``.

Honest residuals: this is a syntactic canonicalizer, not a shell
semantics engine. It does not expand variables, globs, command
substitution, or network-fetched payloads, and base64 is only decoded
when the wrapper idiom is syntactically visible. A fully general
defeat (e.g. payload fetched at runtime) remains out of scope; the
refusal names what the canonicalizer saw.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

import base64
import binascii
import re

PARAMETER_OBFUSCATION = "parameter-obfuscation"
PARAMETER_MALFORMED = "parameter-malformed"

_WRAPPER_RE = re.compile(
    r"^\s*(?:sh|bash|dash)\s+-c\s+(?P<body>.*)$", re.DOTALL)
_B64_IDIOM_RE = re.compile(
    r"echo\s+(?P<b64>[A-Za-z0-9+/=]{8,})\s*\|\s*base64\s+-(?:d|decode)")


class ParameterError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(ParameterError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ParameterError(code, detail)


def _unwrap_shell(command):
    """Repeatedly unwrap ``sh -c <payload>`` style wrappers."""
    current = command
    for _ in range(8):  # bounded: hostile nesting cannot loop forever
        match = _WRAPPER_RE.match(current)
        if not match:
            break
        body = match.group("body").strip()
        if ((body.startswith('"') and body.endswith('"'))
                or (body.startswith("'") and body.endswith("'"))):
            body = body[1:-1]
        current = body
    return current


def _embed_base64_payload(command):
    """Embed strict-decodable base64 payloads from the echo|base64 -d
    idiom into the canonical form so denied parameters inside them are
    visible to the comparison."""
    def _replace(match):
        blob = match.group("b64")
        try:
            decoded = base64.b64decode(blob, validate=True).decode(
                "utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return match.group(0)
        return decoded
    return _B64_IDIOM_RE.sub(_replace, command)


def canonicalize(command):
    """Deterministic canonical form of a command string for parameter
    matching. See module docstring for the ordered steps."""
    if not isinstance(command, str) or not command.strip():
        _refuse(PARAMETER_MALFORMED,
                "command must be a non-empty string")
    text = _unwrap_shell(command)
    text = _embed_base64_payload(text)
    # Quote removal collapses spliced literals ("ec"ho -> echo).
    text = text.replace('"', "").replace("'", "")
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        _refuse(PARAMETER_MALFORMED,
                "command canonicalizes to empty")
    return text


def check_parameters(command, allowed_prefixes, denied_substrings):
    """Canonicalize, then compare against allowlist/denylist.

    ``allowed_prefixes``: iterable of permitted command prefixes.
    ``denied_substrings``: iterable of substrings that must never
    appear in the canonical form.

    Returns ``{"allowed": True, "canonical": ...}`` when the canonical
    form matches an allowed prefix and no denied substring. Returns
    ``{"allowed": False, "canonical": ...}`` when the canonical form
    is simply not allowed. Refuses ``parameter-obfuscation`` when the
    canonical form contains a denied substring -- the raw comparison
    was defeated, and the canonical comparison is authoritative.
    """
    if isinstance(allowed_prefixes, str) or not hasattr(
            allowed_prefixes, "__iter__"):
        _refuse(PARAMETER_MALFORMED,
                "allowed_prefixes must be an iterable of strings")
    if isinstance(denied_substrings, str) or not hasattr(
            denied_substrings, "__iter__"):
        _refuse(PARAMETER_MALFORMED,
                "denied_substrings must be an iterable of strings")
    allowed = [p for p in allowed_prefixes]
    denied = [d for d in denied_substrings]
    for value in allowed + denied:
        if not isinstance(value, str) or not value:
            _refuse(PARAMETER_MALFORMED,
                    "allowlist/denylist entries must be non-empty strings")
    canonical = canonicalize(command)
    for substring in denied:
        if substring in canonical:
            _refuse(PARAMETER_OBFUSCATION,
                    "canonical form %r contains denied parameter %r"
                    % (canonical, substring))
    if any(canonical.startswith(prefix) for prefix in allowed):
        return {"allowed": True, "canonical": canonical}
    return {"allowed": False, "canonical": canonical}
