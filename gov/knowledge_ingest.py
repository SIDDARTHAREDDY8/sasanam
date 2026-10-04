"""Knowledge ingestion for the standing-verdict store (OSV.dev ADAPT).

Wave-325 prospectus verdict #6: OSV.dev is a continuously-updated,
machine-readable advisory database -- the knowledge moves, the artifact
doesn't. This module ingests signed advisory documents from a local
directory feed (no network in v1) and turns them into knowledge records
for ``gov/standing_verdicts.py``.

Trust boundary: the configured feed directory. Documents are refused unless
they live inside it (realpath containment -- ``../`` escapes are refused
``supplychain-feed-outside-trust-boundary``). Every advisory is
authenticated against the configured Ed25519 feed key BEFORE it can affect
any standing: a bad signature quarantines the document as untrusted input
and raises ``supplychain-standing-flip-unauthenticated`` -- it is never
applied.

Two accepted input shapes (``schema`` field selects):

- ``sasanam-advisory/v1``: our native advisory envelope --
  ``advisory_id``, ``artifact_digest``, ``asserted_standing``,
  ``justification``, ``origin``, ``collector``, ``known_since`` (unix),
  ``supersedes`` (journal seq or null), ``signature``.
- ``osv/v1``: an OSV.dev-shaped record wrapped in our envelope --
  ``{"schema": "osv/v1", "osv": {<raw OSV record>}, "artifact_digest",
  "asserted_standing", "supersedes", "signature"}``. Field mapping
  (documented, honest about its limits):
    - ``origin``      <- ``"osv.dev"`` (constant; the OSV record's own
      ``id`` prefix, e.g. ``GHSA-...``, is preserved in ``justification``)
    - ``collector``   <- the feed config's collector name
    - ``known_since`` <- ``osv.published`` (RFC 3339) parsed to unix epoch
    - ``justification`` <- ``osv.summary`` + ``osv.details`` (truncated)
    - ``asserted_standing`` <- envelope value, default ``quarantined``.
      The OSV record itself only says "vulnerable", never "revoked": a
      "revoked" (or "trusted") assertion in an OSV envelope is the feed
      operator's signed judgment, not the OSV record's claim. The trust
      anchor is the feed-key signature over the envelope -- any standing
      the feed key signs is accepted as the operator's assertion and
      recorded as such, so an auditor always sees whose judgment moved
      the standing (origin "osv.dev", the feed's collector).
    - ``affected_packages`` <- ``osv.affected[].package`` as
      ``"ecosystem:name"`` strings (first 8; the advisory's own claim
      about which packages it affects, so an auditor can reconstruct
      the caller's package->digest mapping)
    - ``artifact_digest`` <- the envelope (caller-resolved). OSV records
      are keyed by package name + version range, NOT by digest -- the
      caller maps the affected package to the installed artifact digest
      and that mapping is recorded as the caller's claim. This module
      never invents a digest from a package name.

Signature scheme: Ed25519 over the canonical JSON bytes of the document
with the ``signature`` field removed (``json.dumps`` with
``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=True`` --
the same canonicalization as ``gov/advisory_binding.py``). The signature
itself is base64 (standard alphabet).

Fail-closed:
- unknown ``schema`` -> ``supplychain-standing-schema-unknown``;
- malformed JSON / wrong field types -> ``supplychain-malformed``;
- bad signature -> ``supplychain-standing-flip-unauthenticated`` (and the
  raw document is appended to the configured quarantine path, if any);
- path outside the feed dir -> ``supplychain-feed-outside-trust-boundary``.

Stdlib only. No network. Deterministic.
"""

import base64
import binascii
import calendar
import json
import os
import re

from gov import ed25519 as _ed25519
from gov import standing_verdicts as _sv

SCHEMA_SASANAM_V1 = "sasanam-advisory/v1"
SCHEMA_OSV_V1 = "osv/v1"

_KNOWN_SCHEMAS = (SCHEMA_SASANAM_V1, SCHEMA_OSV_V1)

_OSV_TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


class IngestError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(IngestError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise IngestError(code, detail)


def _malformed(detail):
    _refuse("supplychain-malformed", detail)


def _canonical_bytes(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _malformed("not JSON-canonicalizable: %s" % (exc,))


def _str_field(doc, name, allow_empty=False):
    value = doc.get(name)
    if isinstance(value, bool) or not isinstance(value, str):
        _malformed("%s must be a str" % name)
    if not allow_empty and not value:
        _malformed("%s must be a non-empty str" % name)
    return value


def _int_field(doc, name):
    value = doc.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _malformed("%s must be a non-negative int" % name)
    return value


def _parse_osv_time(value):
    """Parse an OSV RFC 3339 timestamp to a unix epoch int (strict)."""
    if isinstance(value, bool) or not isinstance(value, str):
        _malformed("osv.published must be a str")
    m = _OSV_TIME_RE.match(value.strip())
    if not m:
        _malformed("osv.published is not RFC 3339: %r" % (value,))
    (year, mon, day, hour, minute, sec, frac, tz) = m.groups()
    try:
        epoch = calendar.timegm((int(year), int(mon), int(day),
                                 int(hour), int(minute), int(sec),
                                 0, 0, 0))
    except (ValueError, OverflowError):
        _malformed("osv.published has out-of-range fields: %r" % (value,))
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        off = int(digits[:2]) * 3600 + int(digits[2:4]) * 60
        epoch -= sign * off
    return epoch


class FeedConfig(object):
    """Configuration for one advisory feed (the trust boundary)."""

    def __init__(self, feed_dir, feed_public_key, collector,
                 quarantine_path=None):
        if isinstance(feed_dir, bool) or not isinstance(feed_dir, str) \
                or not feed_dir:
            _malformed("feed_dir must be a non-empty str")
        feed_dir = os.path.realpath(feed_dir)
        if not os.path.isdir(feed_dir):
            _malformed("feed_dir is not a directory: %r" % (feed_dir,))
        if (not isinstance(feed_public_key, (bytes, bytearray))
                or len(feed_public_key) != 32):
            _malformed("feed_public_key must be 32 bytes")
        if isinstance(collector, bool) or not isinstance(collector, str) \
                or not collector:
            _malformed("collector must be a non-empty str")
        self.feed_dir = feed_dir
        self.feed_public_key = bytes(feed_public_key)
        self.collector = collector
        self.quarantine_path = quarantine_path


def _resolve_in_feed(path, config):
    """Realpath containment: the document must live inside the feed dir."""
    real = os.path.realpath(path)
    if real != config.feed_dir and \
            not real.startswith(config.feed_dir + os.sep):
        _refuse("supplychain-feed-outside-trust-boundary",
                "advisory path %r escapes the feed directory %r"
                % (path, config.feed_dir))
    if not os.path.isfile(real):
        _malformed("advisory path is not a file: %r" % (path,))
    return real


def _read_document(real_path):
    try:
        with open(real_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        _malformed("cannot read advisory: %s" % (exc,))
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        _malformed("advisory is not JSON: %s" % (exc,))
    if not isinstance(doc, dict):
        _malformed("advisory must be a JSON object")
    return raw, doc


def _quarantine(config, raw):
    """Append a rejected document to the quarantine log (best effort)."""
    if not config.quarantine_path:
        return
    try:
        with open(config.quarantine_path, "a", encoding="utf-8") as fh:
            fh.write(raw)
            if not raw.endswith("\n"):
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass  # quarantine is best-effort; the refusal is what matters


def _check_signature(doc, config, raw):
    sig_b64 = doc.get("signature")
    if isinstance(sig_b64, bool) or not isinstance(sig_b64, str) \
            or not sig_b64:
        _quarantine(config, raw)
        _refuse("supplychain-standing-flip-unauthenticated",
                "advisory has no signature; unauthenticated input is "
                "quarantined, never applied")
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        _quarantine(config, raw)
        _refuse("supplychain-standing-flip-unauthenticated",
                "advisory signature is not valid base64")
    body = {k: v for k, v in doc.items() if k != "signature"}
    # gov.ed25519.verify returns exact True/False, never raises.
    if _ed25519.verify(config.feed_public_key,
                       _canonical_bytes(body), sig) is not True:
        _quarantine(config, raw)
        _refuse("supplychain-standing-flip-unauthenticated",
                "advisory signature invalid for the configured feed key; "
                "quarantined, never applied")


def _knowledge_from_sasanam(doc):
    _str_field(doc, "advisory_id")
    digest = doc.get("artifact_digest")
    standing = doc.get("asserted_standing")
    justification = doc.get("justification", "")
    if isinstance(justification, bool) or not isinstance(justification, str):
        _malformed("justification must be a str")
    origin = _str_field(doc, "origin")
    collector = _str_field(doc, "collector")
    known_since = _int_field(doc, "known_since")
    supersedes = doc.get("supersedes")
    if supersedes is not None:
        if isinstance(supersedes, bool) or not isinstance(supersedes, int) \
                or supersedes < 0:
            _malformed("supersedes must be a non-negative int or null")
    # Shape-check the security-critical fields now (the store re-checks).
    if isinstance(digest, bool) or not isinstance(digest, str):
        _malformed("artifact_digest must be a str")
    if standing not in _sv.STANDINGS:
        _malformed("asserted_standing must be one of %s"
                   % ("/".join(_sv.STANDINGS),))
    return {
        "artifact_digest": digest,
        "asserted_standing": standing,
        "justification": justification,
        "origin": origin,
        "collector": collector,
        "known_since": known_since,
        "supersedes": supersedes,
        "advisory_id": doc["advisory_id"],
    }


def _knowledge_from_osv(doc, config):
    osv = doc.get("osv")
    if not isinstance(osv, dict):
        _malformed("osv/v1 envelope requires an 'osv' object")
    osv_id = osv.get("id")
    if isinstance(osv_id, bool) or not isinstance(osv_id, str) \
            or not osv_id:
        _malformed("osv.id must be a non-empty str")
    published = osv.get("published")
    known_since = _parse_osv_time(published) if published is not None \
        else _malformed("osv.published is required")
    summary = osv.get("summary", "")
    details = osv.get("details", "")
    for name, value in (("osv.summary", summary),
                        ("osv.details", details)):
        if isinstance(value, bool) or not isinstance(value, str):
            _malformed("%s must be a str" % name)
    # The advisory's own claim about which packages it affects, recorded
    # so an auditor can reconstruct the caller's package->digest mapping.
    # This is the OSV record's claim, not a verified fact.
    affected_packages = []
    affected = osv.get("affected", [])
    if not isinstance(affected, list):
        _malformed("osv.affected must be a list")
    for aff in affected[:8]:
        if not isinstance(aff, dict):
            _malformed("osv.affected entries must be objects")
        pkg = aff.get("package", {})
        if not isinstance(pkg, dict):
            _malformed("osv.affected.package must be an object")
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        for field, value in (("ecosystem", ecosystem), ("name", name)):
            if isinstance(value, bool) or not isinstance(value, str):
                _malformed("osv.affected.package.%s must be a str" % field)
        affected_packages.append("%s:%s" % (ecosystem, name))
    justification = ("[%s] %s %s" % (osv_id, summary, details)).strip()
    if len(justification) > 2000:
        justification = justification[:2000]
    digest = doc.get("artifact_digest")
    if isinstance(digest, bool) or not isinstance(digest, str):
        _malformed("artifact_digest must be a str (caller-resolved from "
                   "the OSV affected package; OSV records carry no digest)")
    standing = doc.get("asserted_standing", "quarantined")
    if standing not in _sv.STANDINGS:
        _malformed("asserted_standing must be one of %s"
                   % ("/".join(_sv.STANDINGS),))
    supersedes = doc.get("supersedes")
    if supersedes is not None:
        if isinstance(supersedes, bool) or not isinstance(supersedes, int) \
                or supersedes < 0:
            _malformed("supersedes must be a non-negative int or null")
    return {
        "artifact_digest": digest,
        "asserted_standing": standing,
        "justification": justification,
        "origin": "osv.dev",
        "collector": config.collector,
        "known_since": known_since,
        "supersedes": supersedes,
        "advisory_id": osv_id,
        "affected_packages": affected_packages or None,
    }


def ingest_file(path, config):
    """Ingest one advisory file; returns a validated knowledge record.

    The record is authenticated and shape-validated but NOT applied --
    the caller passes it to ``StandingStore.attach_knowledge``, which
    enforces inventory, history, flip, and conflict rules.
    """
    real_path = _resolve_in_feed(path, config)
    raw, doc = _read_document(real_path)
    schema = doc.get("schema")
    if schema not in _KNOWN_SCHEMAS:
        # Fail-closed AND forensic: the document is refused, but a
        # quarantine trace is left (schema-confusion probes must not be
        # silent in the audit trail either).
        _quarantine(config, raw)
        _refuse("supplychain-standing-schema-unknown",
                "unknown advisory schema %r; known: %s"
                % (schema, "/".join(_KNOWN_SCHEMAS)))
    _check_signature(doc, config, raw)
    if schema == SCHEMA_SASANAM_V1:
        return _knowledge_from_sasanam(doc)
    return _knowledge_from_osv(doc, config)


def ingest_directory(config, store):
    """Ingest every ``*.json`` file in the feed dir, sorted by name.

    Returns ``{"applied": [...], "unattached": [...], "refused": [...]}``
    with per-file outcomes. One bad file never aborts the run; every
    refusal carries its code. Files are processed in sorted name order
    for determinism.
    """
    applied, unattached, refused = [], [], []
    try:
        names = sorted(os.listdir(config.feed_dir))
    except OSError as exc:
        _malformed("cannot list feed dir: %s" % (exc,))
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(config.feed_dir, name)
        try:
            knowledge = ingest_file(path, config)
        except (IngestError, _sv.StandingError) as exc:
            refused.append({"file": name, "code": exc.code,
                            "detail": exc.detail})
            continue
        try:
            entry = store.attach_knowledge(knowledge)
        except _sv.StandingError as exc:
            refused.append({"file": name, "code": exc.code,
                            "detail": exc.detail})
            continue
        if entry["kind"] == "unattached":
            unattached.append({"file": name, "entry": entry})
        else:
            applied.append({"file": name, "entry": entry})
    return {"applied": applied, "unattached": unattached,
            "refused": refused}
