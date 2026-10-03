"""Signed provenance labels for trajectory segments (Row 7 build step 5).

Design lineage (attributed, not vendored): the label invariant comes from
Tessera (https://github.com/kenithphilip/Tessera, Apache-2.0, LICENSE text
re-verified at build time 2026-10-03: verbatim Apache-2.0, ADR-0001 accepted
2026-04-24). Tessera's library carries runtime dependencies our stdlib-only
tree cannot take (pydantic, fastapi, uvicorn), so the invariant is
re-implemented here in repo style; the TrustLabel canonical form
(origin|principal|trust_level|nonce|sha256(content)) and the HMAC-SHA256
seal are Tessera's design. Copyright 2026 Kenith Philip and Tessera
contributors (Apache-2.0).

Threat model:
- A label binds (origin, principal, trust level) to EXACT content bytes.
  Any edit to the content, the origin, the principal, or the trust level
  invalidates the seal. Verification is constant-time.
- Trust is graded at ingestion by ORIGIN, never by content: a web fetch is
  UNTRUSTED no matter how benign the text reads. Live scanners may only
  downgrade.
- Readers-ACLs (Tessera's lattice) are deliberately OUT of the seal: they
  are policy metadata, not a content commitment. Not implemented here.
- The seal key is the F34 active log key via the wave-69 guarded
  chokepoint ``gov.log._active_key()`` -- no new crypto, no new keys.
  Key epoch is bound into the MAC input, domain-separated.

Stdlib only. Deterministic: no time, no randomness in verification.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

try:
    from .log import _active_key
except ImportError:  # standalone: sibling module beside this file
    from log import _active_key

_LABEL_DOMAIN = b"provenance-label-v1:"

__all__ = [
    "TrustLevel",
    "Origin",
    "DEFAULT_TRUST",
    "LabelError",
    "ProvenanceLabel",
    "Segment",
    "grade_origin",
    "unsigned_label",
    "issue_label",
    "sign_label",
    "verify_label",
    "LABEL_VERSION",
]

LABEL_VERSION = 1


class LabelError(Exception):
    """Coded-by-construction refusal from the label machinery."""


class TrustLevel(object):
    """Ordered trust levels. Higher dominates lower in taint tracking.

    UNTRUSTED (0): anything attacker-controllable -- scraped web pages,
    retrieved documents, arbitrary tool outputs. TOOL (50): outputs from
    tools the operator has vetted. USER (100): instructions typed by the
    authenticated human principal. SYSTEM (200): the operator's system
    prompt.
    """
    UNTRUSTED = 0
    TOOL = 50
    USER = 100
    SYSTEM = 200


class Origin(object):
    """Where a segment of context came from."""
    USER = "user"
    SYSTEM = "system"
    TOOL = "tool"
    MEMORY = "memory"
    WEB = "web"


#: Default origin -> trust level mapping. WEB and MEMORY land at
#: UNTRUSTED even when the bytes look benign -- grading is by origin,
#: never by content.
DEFAULT_TRUST = {
    Origin.WEB: TrustLevel.UNTRUSTED,
    Origin.MEMORY: TrustLevel.UNTRUSTED,
    Origin.TOOL: TrustLevel.TOOL,
    Origin.USER: TrustLevel.USER,
    Origin.SYSTEM: TrustLevel.SYSTEM,
}


def grade_origin(origin):
    """Return the TrustLevel for an origin string. Unknown origins
    refuse (fail closed) -- an ungradeable segment must never default
    to trusted."""
    try:
        return DEFAULT_TRUST[origin]
    except KeyError:
        raise LabelError("provenance: unknown origin %r -- a segment "
                         "that cannot be graded cannot be trusted"
                         % (origin,))


@dataclass(frozen=True)
class ProvenanceLabel(object):
    """A provenance label bound to specific content bytes by HMAC.

    The seal covers origin, principal, trust_level, nonce, and the
    SHA-256 of the content. Verifying a label requires the content it
    was issued for; readers/metadata stay outside the seal.
    """
    origin: str
    principal: str
    trust_level: int
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str = ""

    def canonical(self, content):
        """The bytes the seal covers."""
        if not isinstance(content, str):
            raise LabelError("provenance: content must be str for sealing")
        content_digest = hashlib.sha256(
            content.encode("utf-8")).hexdigest()
        return ("%s|%s|%d|%s|%s" % (
            self.origin, self.principal, int(self.trust_level),
            self.nonce, content_digest)).encode("utf-8")

    def to_dict(self):
        return {
            "v": LABEL_VERSION,
            "origin": self.origin,
            "principal": self.principal,
            "trust_level": int(self.trust_level),
            "nonce": self.nonce,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d):
        """Rebuild from to_dict() output. Anything malformed raises
        LabelError -- callers treat that as unverifiable."""
        if not isinstance(d, dict):
            raise LabelError("provenance: label dict must be a dict")
        try:
            return cls(
                origin=str(d["origin"]),
                principal=str(d["principal"]),
                trust_level=int(d["trust_level"]),
                nonce=str(d["nonce"]),
                signature=str(d.get("signature") or ""))
        except (KeyError, TypeError, ValueError):
            raise LabelError("provenance: malformed label dict")


@dataclass(frozen=True)
class Segment(object):
    """A labeled context segment: id + label + the exact content bytes
    the label was issued for. ``label.trust_level`` is advisory until
    ``verify_label`` confirms the seal against ``content``."""
    segment_id: str
    label: ProvenanceLabel
    content: str

    def to_dict(self):
        return {
            "segment_id": self.segment_id,
            "label": self.label.to_dict(),
            "content": self.content,
        }

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            raise LabelError("provenance: segment dict must be a dict")
        try:
            return cls(
                segment_id=str(d["segment_id"]),
                label=ProvenanceLabel.from_dict(d["label"]),
                content=str(d["content"]))
        except (KeyError, TypeError, ValueError):
            raise LabelError("provenance: malformed segment dict")


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        raise LabelError("provenance: %s must be a non-empty string"
                         % what)
    return value


def unsigned_label(origin, principal, content, trust_level=None,
                   nonce=None):
    """Build an UNSEALED label (for tests, adversaries, and labels
    imported across a trust boundary before local verification). An
    unsigned label never verifies -- the sink treats it as UNTRUSTED."""
    grade_origin(origin)  # origin must still be a known vocabulary word
    _check_str(principal, "principal")
    return ProvenanceLabel(
        origin=origin,
        principal=principal,
        trust_level=(int(trust_level) if trust_level is not None
                     else grade_origin(origin)),
        nonce=nonce or secrets.token_hex(16),
        signature="")


def _seal(label, content):
    """HMAC-SHA256 seal under the active log key (the F34/_active_key()
    chokepoint), domain-separated, key epoch bound in. One call site by
    design -- the HMAC chokepoint audit allowlist pins it."""
    key, key_epoch = _active_key()
    msg = (_LABEL_DOMAIN + key_epoch.encode("utf-8") + b"|"
           + label.canonical(content))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sign_label(label, content):
    """Return a copy of ``label`` with a fresh seal for ``content``."""
    sealed = ProvenanceLabel(label.origin, label.principal,
                             label.trust_level, label.nonce,
                             _seal(label, content))
    return sealed


def issue_label(origin, principal, content, nonce=None):
    """Grade an origin, build the label, and seal it for ``content``.
    The single constructor the product uses."""
    grade_origin(origin)
    _check_str(principal, "principal")
    base = ProvenanceLabel(origin=origin, principal=principal,
                           trust_level=grade_origin(origin),
                           nonce=nonce or secrets.token_hex(16),
                           signature="")
    return sign_label(base, content)


def verify_label(label, content):
    """Constant-time verification of a label against its content.
    Returns False for ANY mismatch: wrong content, wrong key, tampered
    label fields, or a missing signature. Never raises on adversarial
    input -- callers downgrade to UNTRUSTED."""
    try:
        if not isinstance(label, ProvenanceLabel):
            return False
        if not label.signature:
            return False
        expected = _seal(
            ProvenanceLabel(label.origin, label.principal,
                            label.trust_level, label.nonce, ""),
            content)
        return hmac.compare_digest(expected, label.signature)
    except Exception:
        return False
