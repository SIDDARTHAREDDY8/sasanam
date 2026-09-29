"""Signed, versioned, expiring detection-rule pack manifest.

The TUF story applied to detection content (wave-198): a tampered
rule blinds the auditor, so rule content is supply-chain content.
This module is the corpus-manifest *mechanism* (threshold signatures
over a canonical body, monotonic version, expiry, keyset-purpose
binding) with a distinct format tag and keyset purpose -- rules are
not skill bundles and must never share the corpus manifest's trust
domain.

Trust model:

* The pack is signed by the deployment's rule-signing keyset
  (``keyset_purpose`` pinned in the document, checked at verify),
  via ``ThresholdSigner.sign_all``. Member shapes and rotation
  semantics are identical to ``gov.corpus_manifest``: ``KeysetSigner``
  members bind ``(key_id, key_version)``; plain ``Signer`` members
  (deployment keyholders) sign the common body and verify through the
  keyset's legacy key-id lookup; distinct key ids only.
* ``rules`` binds ``{rule_id -> "sha256:<64-hex>"}`` over the exact
  rule-file bytes. The auditor (``gov.audit_detect``) refuses to
  compile any rule whose digest does not match, and refuses to load
  a pack whose signature, version, or expiry fails -- fail closed,
  with distinct codes.
* Signatures are authoritative for the pack; the pack is never the
  sole trust anchor for the audit stream. An attacker who can mint a
  rule pack already holds the deployment's rule-signing keys.

Fail-closed codes (``RulePackError.code``):
``bad-format``, ``bad-version``, ``bad-expiry``, ``bad-rules``,
``wrong-purpose``, ``bad-threshold``, ``bad-signature``,
``threshold-unmet``, ``pack-expired``.

$0 spend, synthetic/local deterministic only. No network.
"""

import json
import re
from datetime import datetime, timezone

from . import ed25519 as _ed
from .keyset import Keyset
from .signing import ThresholdSigner

__all__ = [
    "RULE_PACK_FORMAT",
    "KEYSET_PURPOSE_RULE_PACK",
    "PERM_PACK_FORMAT",
    "KEYSET_PURPOSE_PERM_PACK",
    "RulePackError",
    "RulePack",
    "mint_rule_pack",
    "verify_rule_pack",
    "canonical_rule_pack_json",
]

#: Pack document format tag (exact match at verify).
RULE_PACK_FORMAT = "sasanam-detection-rule-pack/v1"

#: Keyset purpose bound into rule packs; a keyset minted for a
#: different purpose can never mint a rule pack (and a corpus-signing
#: keyset can never mint a rule pack either -- distinct trust domain).
KEYSET_PURPOSE_RULE_PACK = "sasanam-rule-pack-signing/v1"

#: Wave-200 (PERM model packs): the authorization-model pack is a
#: structurally identical signed member enumeration, but changing
#: what "allow" MEANS is more sensitive than changing detection
#: rules, so it lives in its own trust domain -- its own format tag
#: (exact match at verify, and the signature domain derives from it)
#: and its own keyset purpose. A rule-signing keyset can never mint
#: a PERM model pack and vice versa. ``mint_rule_pack`` /
#: ``verify_rule_pack`` take both as optional kwargs defaulting to
#: the detection-rule values, so existing callers are unaffected.
PERM_PACK_FORMAT = "sasanam-perm-model-pack/v1"

#: Keyset purpose bound into PERM model packs.
KEYSET_PURPOSE_PERM_PACK = "sasanam-perm-model-signing/v1"

#: Fields allowed on a v1 pack document (unknown fields refused).
_PACK_FIELDS = frozenset({
    "format", "pack_version", "issued_at", "expires_at",
    "keyset_purpose", "rules", "threshold", "signatures",
})

#: Envelope fields per threshold member signature.
_SIG_FIELDS = frozenset({"key_id", "key_version", "sig"})

_PACK_DOMAIN = b"sasanam-detection-rule-pack/v1\x00"


def _pack_domain_for(format_tag):
    """Signature domain for a pack kind. The default call (no
    format_tag override) returns the historic domain byte-identically,
    so previously minted packs still verify."""
    if format_tag == RULE_PACK_FORMAT:
        return _PACK_DOMAIN
    if not isinstance(format_tag, str) or not format_tag:
        raise RulePackError("bad-format", "format tag must be a "
                            "non-empty string")
    return format_tag.encode("utf-8") + b"\x00"
# Member domain: MUST be byte-identical to the body
# gov.signing.ThresholdSigner.sign_all signs for a versioned member
# (``gov/signing.py::_member_sig_body``): domain + key_id + b"|kv" +
# version + b"\x00" + common. Same convention as gov.corpus_manifest.
_MEMBER_DOMAIN = b"sasanam-threshold-member/v1\x00"

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RulePackError(Exception):
    """Fail-closed rule-pack violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        """Build the exception; the message is ``code`` + ``detail``."""
        super(RulePackError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_iso(value, what):
    if not isinstance(value, str) or not _ISO_RE.match(value):
        raise RulePackError(
            "bad-expiry", "%s is not an ISO-8601 UTC timestamp" % what)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise RulePackError(
            "bad-expiry", "%s is not parseable: %r" % (what, value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def canonical_rule_pack_json(doc):
    """RFC 8785-style canonical JSON of the pack minus ``signatures``.

    Raises RulePackError("bad-format") on any non-object or
    non-serializable input -- never a silent mismatch.
    """
    if not isinstance(doc, dict):
        raise RulePackError(
            "bad-format", "pack body is not a JSON object")
    body = {k: v for k, v in doc.items() if k != "signatures"}
    try:
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RulePackError(
            "bad-format", "pack body not canonicalizable: %s" % exc)
    return text.encode("utf-8")


def _common_body(doc, domain):
    """The bytes every member signs: domain + canonical JSON."""
    return domain + canonical_rule_pack_json(doc)


def _member_body(common, key_id, key_version):
    """Member-specific body: binds (key_id, key_version) to ``common``
    under a distinct domain so a member signature cannot be
    transplanted onto another member or version."""
    return (_MEMBER_DOMAIN + key_id.encode("utf-8") + b"|kv"
            + str(key_version).encode("ascii") + b"\x00"
            + bytes(common))


class RulePack:
    """A verified rule pack: ``{rule_id -> digest}`` plus the
    version/expiry/threshold that verified.

    Instances only come from :func:`verify_rule_pack` -- the
    constructor is not a trust boundary.
    """

    __slots__ = ("version", "expires_at", "threshold", "rules",
                 "signing_kids")

    def __init__(self, version, expires_at, threshold, rules,
                 signing_kids):
        """Store the verified pack fields (plain value object)."""
        self.version = version
        self.expires_at = expires_at
        self.threshold = threshold
        self.rules = dict(rules)
        self.signing_kids = list(signing_kids)

    def digest_for(self, rule_id):
        """The pack-bound digest for ``rule_id``, or None."""
        return self.rules.get(rule_id)


def mint_rule_pack(keyset, signers, *, rules, pack_version,
                   issued_at, expires_at, threshold,
                   purpose=KEYSET_PURPOSE_RULE_PACK,
                   format_tag=RULE_PACK_FORMAT):
    """Mint a signed rule pack (operator-side).

    ``keyset``: a :class:`Keyset` whose ``purpose`` is ``purpose``
    (default the detection-rule-pack purpose). ``signers``: non-empty
    list of ``KeysetSigner`` members of ``keyset`` (each member's
    version is cryptographically attested in the signature body --
    same semantics as the corpus manifest).
    ``rules``: ``{rule_id: "sha256:<64-hex>"}`` over the exact rule
    file bytes. ``issued_at`` / ``expires_at``: ISO-8601 UTC strings;
    ``expires_at`` must be after ``issued_at``.
    ``format_tag`` selects the pack kind (default the
    detection-rule-pack tag; wave-200 PERM model packs use
    ``PERM_PACK_FORMAT`` with ``KEYSET_PURPOSE_PERM_PACK`` -- a
    distinct trust domain with its own signature domain).
    Returns the pack dict (JSON-serializable).
    """
    if not isinstance(keyset, Keyset):
        raise TypeError("keyset must be a Keyset")
    if keyset.purpose != purpose:
        raise RulePackError(
            "wrong-purpose",
            "keyset purpose %r cannot mint %r packs"
            % (keyset.purpose, format_tag))
    domain = _pack_domain_for(format_tag)
    signers = list(signers or [])
    if not signers:
        raise RulePackError("bad-threshold", "no signers")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(signers)):
        raise RulePackError(
            "bad-threshold",
            "threshold must satisfy 1 <= k <= %d" % len(signers))
    if (isinstance(pack_version, bool)
            or not isinstance(pack_version, int)
            or pack_version < 1):
        raise RulePackError(
            "bad-version", "pack_version must be an integer >= 1")
    issued = _parse_iso(issued_at, "issued_at")
    expires = _parse_iso(expires_at, "expires_at")
    if expires <= issued:
        raise RulePackError(
            "bad-expiry", "expires_at must be after issued_at")
    if not isinstance(rules, dict):
        raise RulePackError(
            "bad-rules", "rules must be a mapping")
    for rid, digest in rules.items():
        if not isinstance(rid, str) or not rid:
            raise RulePackError(
                "bad-rules", "rule id must be a non-empty string")
        if not _SHA256_RE.match(digest or ""):
            raise RulePackError(
                "bad-rules",
                "rule %r digest is not a sha256 pin" % (rid,))
    doc = {
        "format": format_tag,
        "pack_version": pack_version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "keyset_purpose": purpose,
        "rules": {str(r): str(d) for r, d in rules.items()},
        "threshold": threshold,
        "signatures": [],
    }
    common = _common_body(doc, domain)
    doc["signatures"] = ThresholdSigner(signers, threshold).sign_all(
        common)
    return doc


def _verify_member(keyset, common, entry):
    """Verify one threshold member entry. Returns the key_id on
    success, None when the member does not verify (unknown, revoked,
    or bad signature -- never raises)."""
    if not isinstance(entry, dict):
        return None
    if set(entry) - _SIG_FIELDS:
        return None
    kid = entry.get("key_id")
    if not isinstance(kid, str) or not kid:
        return None
    try:
        sig = bytes.fromhex(entry.get("sig"))
    except (TypeError, ValueError):
        return None
    if "key_version" in entry:
        kv = entry.get("key_version")
        if isinstance(kv, bool) or not isinstance(kv, int) or kv < 1:
            return None
        keyver, _reason = keyset.find_verifying_key(
            {"sig_key_id": kid, "sig_key_version": kv})
        if keyver is None:
            return None
        body = _member_body(common, kid, kv)
    else:
        keyver, _reason = keyset.find_verifying_key({"sig_key_id": kid})
        if keyver is None:
            return None
        body = common
    try:
        ok = _ed.verify(keyver.public_key, body, sig)
    except Exception:
        ok = False
    return kid if ok else None


def verify_rule_pack(doc, keyset, *, now=None,
                     purpose=KEYSET_PURPOSE_RULE_PACK,
                     format_tag=RULE_PACK_FORMAT):
    """Verify a rule pack against the pack-signing keyset.

    ``purpose`` / ``format_tag`` select the expected trust domain
    (defaults: the detection-rule-pack domain; wave-200 PERM model
    packs verify with ``purpose=KEYSET_PURPOSE_PERM_PACK`` and
    ``format_tag=PERM_PACK_FORMAT``). A pack minted for one domain
    never verifies under another: the format tag is exact-matched,
    the keyset purpose is checked on both the pack and the keyset,
    and the signature domain derives from the format tag.

    Returns a :class:`RulePack`. Fail-closed: raises
    :class:`RulePackError` with a distinct code on every failure
    mode. Checks, in order: shape/format, version sanity, purpose
    binding, expiry, rules mapping, threshold sanity, then every
    member signature (distinct key ids only) -- at least
    ``threshold`` valid members required. A verify-only keyset
    version still verifies (rotation-stable); a revoked version's
    signature does not count.
    """
    if not isinstance(keyset, Keyset):
        raise TypeError("keyset must be a Keyset")
    if not isinstance(doc, dict):
        raise RulePackError(
            "bad-format", "pack is not a mapping")
    if set(doc) - _PACK_FIELDS:
        raise RulePackError(
            "bad-format", "pack carries unknown fields: %s"
            % sorted(set(doc) - _PACK_FIELDS))
    if doc.get("format") != format_tag:
        raise RulePackError(
            "bad-format", "format must be %r" % (format_tag,))
    version = doc.get("pack_version")
    if (isinstance(version, bool) or not isinstance(version, int)
            or version < 1):
        raise RulePackError(
            "bad-version", "pack_version must be an integer >= 1")
    if doc.get("keyset_purpose") != purpose:
        raise RulePackError(
            "wrong-purpose",
            "pack keyset_purpose %r is not %r"
            % (doc.get("keyset_purpose"), purpose))
    if keyset.purpose != purpose:
        raise RulePackError(
            "wrong-purpose",
            "verifying keyset purpose %r is not %r"
            % (keyset.purpose, purpose))
    expires = _parse_iso(doc.get("expires_at"), "expires_at")
    _parse_iso(doc.get("issued_at"), "issued_at")
    if now is None:
        now = _utcnow()
    elif isinstance(now, str):
        now = _parse_iso(now, "now")
    if now > expires:
        raise RulePackError(
            "pack-expired",
            "pack expired at %s" % (doc.get("expires_at"),))
    rules = doc.get("rules")
    if not isinstance(rules, dict) or not rules:
        raise RulePackError(
            "bad-rules", "rules must be a non-empty mapping")
    for rid, digest in rules.items():
        if not isinstance(rid, str) or not rid:
            raise RulePackError(
                "bad-rules", "rule id must be a non-empty string")
        if not _SHA256_RE.match(digest or ""):
            raise RulePackError(
                "bad-rules",
                "rule %r digest is not a sha256 pin" % (rid,))
    threshold = doc.get("threshold")
    sigs = doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise RulePackError(
            "bad-threshold", "signatures must be a non-empty list")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(sigs)):
        raise RulePackError(
            "bad-threshold",
            "threshold must satisfy 1 <= k <= %d" % len(sigs))
    common = _common_body(doc, _pack_domain_for(format_tag))
    valid_kids = []
    seen = set()
    for entry in sigs:
        kid = _verify_member(keyset, common, entry)
        if kid is not None and kid not in seen:
            seen.add(kid)
            valid_kids.append(kid)
    if not valid_kids:
        raise RulePackError(
            "bad-signature", "no member signature verifies")
    if len(valid_kids) < threshold:
        raise RulePackError(
            "threshold-unmet",
            "%d of %d required member signatures verify"
            % (len(valid_kids), threshold))
    return RulePack(version, expires, threshold, rules, valid_kids)
