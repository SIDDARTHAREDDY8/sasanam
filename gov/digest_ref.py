"""Digest-first-class artifact references (Wave-199 Lane D).

go-containerregistry ADAPT (wave-198 prospectus #6): ``name.Digest``
makes digest addressing first-class -- ``registry/repo@sha256:...``
parses to a Digest, not a Tag -- so "pull by tag" is unrepresentable
at the type level rather than forbidden by convention. This module is
the stdlib-only Sasanam version of that discipline, and it makes the
wave-192 design rule ("digest becomes identity") STRUCTURAL.

The gap it closes: digest identity was stringly-typed. Every seam
took ``str`` and validated ad hoc at runtime, in three mutually
incompatible dialects -- ``gov.evidence_distribute._is_digest``
(requires the ``sha256:`` prefix), ``gov.anchor_backend._check_anchor_hash``
(requires BARE 64-hex), ``gov.load_gate.is_digest_pin`` (regex) --
and no seam could distinguish a tag from a digest at construction,
because there was no construction. A tag was a valid inhabitant of
every identity parameter's declared type; refusal happened (when it
happened) deep inside the call, with a per-module message.

:class:`DigestRef` fixes that at the type level:

* ``DigestRef.parse("repo@sha256:<64hex>")`` -- the OCI digest
  reference form (registry ports allowed: ``host:5000/repo@sha256:..``).
* ``DigestRef.from_hex("<64hex>" | "sha256:<64hex>")`` -- digest-only
  identities (Rekor anchor hashes, corpus manifest pins).
* Anything else -- ``repo:latest``, ``:latest``, ``sha256:`` with no
  repo via :meth:`parse`, bare ``"latest"``, whitespace-padded input,
  wrong-length hex, non-hex, unknown algorithms -- raises
  :class:`DigestRefError` AT CONSTRUCTION. Never returns None, never
  silently coerces. ``TypeError`` (not ``DigestRefError``) is raised
  for non-string input, so a caller passing the wrong *kind* of value
  gets the standard Python complaint.

The type is immutable, hashable, and equality-comparable (DigestRef
to DigestRef only -- comparing against a ``str`` is NotImplemented
on purpose: silent string interop is exactly the confusion this
type exists to kill; callers use ``.digest`` / ``.reference`` /
``str(ref)`` explicitly at string boundaries).

Only ``sha256`` is accepted today. The wave-198 Rekor envelope uses
SHA-512 *inside* the transparency-log protocol, but artifact identity
in this tree is SHA-256; a second algorithm would be a deliberate
extension with its own validation, not a silent accept.
"""

import re

__all__ = ["DigestRefError", "DigestRef"]


class DigestRefError(ValueError):
    """Loud construction-time refusal of a non-digest reference."""


_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_ALGORITHM = "sha256"


def _check_hex(hexpart, *, where):
    if not isinstance(hexpart, str) or not _HEX64_RE.match(hexpart):
        raise DigestRefError(
            "%s: not a 64-hex-char sha256 digest: %r" % (where, hexpart))
    return hexpart.lower()


def _check_repo(repo, *, where):
    if not isinstance(repo, str) or not repo:
        raise DigestRefError("%s: empty repository in %r" % (where, repo))
    if any(c.isspace() for c in repo):
        raise DigestRefError(
            "%s: repository contains whitespace: %r" % (where, repo))
    if "@" in repo:
        raise DigestRefError(
            "%s: repository contains '@': %r" % (where, repo))
    return repo


class DigestRef(object):
    """An immutable, digest-only artifact reference.

    Instances come from :meth:`parse` (``repo@sha256:<hex>``) or
    :meth:`from_hex` (digest-only). Direct construction validates too,
    so there is no back door.
    """

    __slots__ = ("_repo", "_hex")

    def __init__(self, repo, hexpart):
        # repo may be None (digest-only identity); otherwise validated.
        self._repo = None if repo is None else _check_repo(
            repo, where="DigestRef")
        self._hex = _check_hex(hexpart, where="DigestRef")

    # -- constructors ---------------------------------------------------

    @classmethod
    def parse(cls, text):
        """Parse ``repo@sha256:<64hex>``; refuse everything else loudly.

        Tag-only input (``repo:latest``), digest-only input
        (``sha256:<hex>`` -- use :meth:`from_hex` for that), missing or
        doubled ``@``, unknown algorithms, and malformed hex all raise
        :class:`DigestRefError`. Non-string input raises TypeError.
        """
        if not isinstance(text, str):
            raise TypeError(
                "DigestRef.parse requires str, got %s" % type(text).__name__)
        if text != text.strip() or not text:
            raise DigestRefError(
                "not a digest reference (empty or padded): %r" % (text,))
        if "@" not in text:
            if text.startswith(_ALGORITHM + ":"):
                raise DigestRefError(
                    "digest-only form %r has no repository; use "
                    "DigestRef.from_hex for digest-only identities, "
                    "DigestRef.parse for repo@sha256:<hex>" % (text,))
            raise DigestRefError(
                "not a digest reference (no '@'): %r looks like a tag; "
                "tags are mutable names, never identity -- use "
                "repo@sha256:<64hex>" % (text,))
        repo, sep, rest = text.partition("@")
        if not sep or "@" in rest or not repo:
            raise DigestRefError(
                "malformed digest reference: %r (want repo@sha256:<64hex>)"
                % (text,))
        algo, colon, hexpart = rest.partition(":")
        if not colon:
            raise DigestRefError(
                "malformed digest reference: %r (want repo@sha256:<64hex>)"
                % (text,))
        if algo != _ALGORITHM:
            raise DigestRefError(
                "unsupported digest algorithm %r in %r: only 'sha256' "
                "is an artifact identity here" % (algo, text))
        return cls(_check_repo(repo, where="parse"), _check_hex(
            hexpart, where="parse"))

    @classmethod
    def from_hex(cls, value):
        """Digest-only identity from ``<64hex>`` or ``sha256:<64hex>``.

        Accepts an existing DigestRef idempotently (returns it
        unchanged). Tag-shaped input (``"latest"``, ``"repo:latest"``)
        raises :class:`DigestRefError` with a tag-specific message.
        Non-string, non-DigestRef input raises TypeError.
        """
        if isinstance(value, DigestRef):
            return value
        if not isinstance(value, str):
            raise TypeError(
                "DigestRef.from_hex requires str or DigestRef, got %s"
                % type(value).__name__)
        text = value
        if text != text.strip() or not text:
            raise DigestRefError(
                "not a digest: empty or padded: %r" % (value,))
        if text.startswith(_ALGORITHM + ":"):
            text = text[len(_ALGORITHM) + 1:]
        elif "@" in text or ":" in text:
            raise DigestRefError(
                "not a digest: %r looks like a tag or reference; "
                "digest-only identities are 64 hex chars "
                "(optionally sha256:-prefixed)" % (value,))
        return cls(None, _check_hex(text, where="from_hex"))

    # -- accessors ------------------------------------------------------

    @property
    def repo(self):
        """Repository (``host:port/path`` allowed), or None digest-only."""
        return self._repo

    @property
    def algorithm(self):
        return _ALGORITHM

    @property
    def hex(self):
        """Lowercase 64-hex digest."""
        return self._hex

    @property
    def digest(self):
        """Canonical ``sha256:<hex>`` -- the wire form for clients."""
        return _ALGORITHM + ":" + self._hex

    @property
    def reference(self):
        """Canonical full reference: ``repo@sha256:<hex>`` or digest-only."""
        if self._repo is None:
            return self.digest
        return "%s@%s:%s" % (self._repo, _ALGORITHM, self._hex)

    # -- value semantics --------------------------------------------------

    def __str__(self):
        return self.reference

    def __repr__(self):
        return "DigestRef(%r)" % (self.reference,)

    def __eq__(self, other):
        if not isinstance(other, DigestRef):
            return NotImplemented
        return (self._repo, self._hex) == (other._repo, other._hex)

    def __ne__(self, other):
        eq = self.__eq__(other)
        return eq if eq is NotImplemented else not eq

    def __hash__(self):
        return hash((self._repo, self._hex))
