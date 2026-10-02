"""Rekor v2 second-witness write path for evidence-bundle digests.

Wave-277 lane (rekor). The v1 freeze window is NOW (wave-276 prospecting):
the product needs a v2 *write* path before the freeze fires. This module is
that path, behind an explicit flag that defaults OFF.

Layering (the whole point of this module):

* The LOCAL anchor is the PRIMARY witness. Rekor v2 is strictly a SECOND
  witness. Nothing in the product's decision path consults this module:
  ``attach()`` NEVER raises, and a witness outage degrades to a
  ``"failed"`` record -- it can never fail the product closed.
* A Rekor inclusion proof proves DIGEST EXISTENCE ONLY. Every witness
  record carries ``evidentiary_grade="digest-existence-only"`` and
  ``authority_proof=False``. Never present a witness record as
  authorization or signature correctness (standing lesson: Rekor proves
  digest existence, not authorization/signature correctness).
* Shard discovery is via TUF SigningConfig (the NVIDIA AICR pattern
  ``signing_config_rekor_v2.v0.2.json``), NEVER hardcoded URLs. The
  config names the v2 shards and their validity windows; the TSA the
  receipt needs is discovered from the same document.
* SELF-HOSTED ONLY. The pinned Sigstore production log values are
  refused by the underlying client (``gov.rekor_v2_anchor``) -- a
  prod-pinned signing config degrades to a ``"failed"`` witness record,
  never to a live production write ($0, no hosted-service trust
  dependency).

Hermetic by design: the default client is
``gov.rekor_v2_anchor.HermeticRekorV2`` (in-process tile-backed log, no
network). A live v2 transport replaces the client's ``_submit_to_log``
seam (documented in that module), not the witness-record shape here.

$0 spend, stdlib only, deterministic (injectable clock; injectable
client for outage simulation).
"""

import base64
import binascii
import hashlib
import json
import os
import time
from datetime import datetime, timezone

from .rekor_v2_anchor import HermeticRekorV2

__all__ = [
    "FLAG_ENV_VAR",
    "CONFIG_ENV_VAR",
    "WITNESS_NAME",
    "EVIDENTIARY_GRADE",
    "STATUS_ATTACHED",
    "STATUS_SKIPPED",
    "STATUS_FAILED",
    "ShardDiscoveryError",
    "witness_enabled",
    "discover_v2_shard",
    "RekorV2Witness",
    "record_in_metadata",
]

#: The explicit flag. Spelled ``GOV_REKOR_V2_WITNESS`` ("1"/"true"/"yes",
#: case-insensitive). Distinct from ``GOV_REKOR_V2_DUAL_WRITE``, which
#: governs the anchorer's v1+v2 dual-write in gov.rekor_v2_anchor --
#: this flag governs the evidence-bundle second-witness path only.
FLAG_ENV_VAR = "GOV_REKOR_V2_WITNESS"

#: Optional wiring: path to a TUF SigningConfig JSON document naming
#: the v2 shards. Used only when no explicit signing_config is passed.
CONFIG_ENV_VAR = "GOV_REKOR_V2_SIGNING_CONFIG"

#: Witness identity stamped on every record.
WITNESS_NAME = "rekor-v2"

#: The evidentiary grade, stated on every record: a Rekor proof is
#: digest-existence evidence, nothing more.
EVIDENTIARY_GRADE = "digest-existence-only"

#: Witness record statuses.
STATUS_ATTACHED = "attached"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"

#: v2 major API version selected from the signing config. Both the
#: v0.1 spelling ("apiVersion") and the v0.2 spelling
#: ("majorApiVersion") are accepted -- the upstream schema renamed the
#: field between versions and operators ship both.
_V2_API_VERSION = 2


class ShardDiscoveryError(ValueError):
    """The TUF SigningConfig names no usable v2 shard (fail-closed)."""


def witness_enabled(explicit=None):
    """Resolve the second-witness flag.

    ``explicit`` wins when given; otherwise ``GOV_REKOR_V2_WITNESS``
    ("1"/"true"/"yes", case-insensitive) enables it. Default: False --
    the local anchor stays the only witness unless the operator opts
    in explicitly.
    """
    if explicit is not None:
        return bool(explicit)
    return os.environ.get(FLAG_ENV_VAR, "").lower() in (
        "1", "true", "yes")


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _parse_rfc3339(value, where):
    if not isinstance(value, str) or not value:
        raise ShardDiscoveryError(
            "%s must be an RFC3339 timestamp, got %r" % (where, value))
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ShardDiscoveryError(
            "%s is not a parseable timestamp: %r" % (where, value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_doc(signing_config, where="signing_config"):
    """A TUF SigningConfig as a mapping.

    Accepts an already-parsed mapping, a JSON string, or a path to a
    JSON file. Anything else (or unparseable JSON) is a
    :class:`ShardDiscoveryError`, never a silent default.
    """
    if isinstance(signing_config, dict):
        return signing_config
    if isinstance(signing_config, (bytes, bytearray)):
        signing_config = bytes(signing_config).decode("utf-8")
    if isinstance(signing_config, str):
        text = signing_config.strip()
        if not text:
            raise ShardDiscoveryError("%s is empty" % (where,))
        if text.startswith("{"):
            try:
                doc = json.loads(text)
            except ValueError as e:
                raise ShardDiscoveryError(
                    "%s is not valid JSON: %s" % (where, e))
            if not isinstance(doc, dict):
                raise ShardDiscoveryError(
                    "%s JSON must be an object" % (where,))
            return doc
        try:
            with open(signing_config, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            raise ShardDiscoveryError(
                "cannot read %s at %r: %s" % (where, signing_config, e))
        try:
            doc = json.loads(text)
        except ValueError as e:
            raise ShardDiscoveryError(
                "%s at %r is not valid JSON: %s"
                % (where, signing_config, e))
        if not isinstance(doc, dict):
            raise ShardDiscoveryError(
                "%s at %r must be a JSON object" % (where, signing_config))
        return doc
    raise ShardDiscoveryError(
        "%s must be a mapping, JSON text, or file path, got %s"
        % (where, type(signing_config).__name__))


def _entry_api_version(entry):
    for key in ("majorApiVersion", "apiVersion"):
        value = entry.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ShardDiscoveryError(
                "rekor entry api version is not an integer: %r" % (value,))
    return None


def _entry_url(entry):
    # v0.2 renamed "baseUrl" to "url"; accept both spellings.
    url = entry.get("url") or entry.get("baseUrl")
    if not isinstance(url, str) or not url:
        return None
    return url.rstrip("/")


def _within_validity(valid_for, now):
    """A ``validFor`` window contains ``now`` (end is optional/open)."""
    if not isinstance(valid_for, dict):
        return False
    try:
        start = _parse_rfc3339(valid_for.get("start"), "validFor.start")
    except ShardDiscoveryError:
        return False
    end_raw = valid_for.get("end")
    end = None
    if end_raw is not None:
        try:
            end = _parse_rfc3339(end_raw, "validFor.end")
        except ShardDiscoveryError:
            return False
    return start <= now and (end is None or now < end)


def _validity_start(valid_for):
    try:
        return _parse_rfc3339(valid_for.get("start"), "validFor.start")
    except ShardDiscoveryError:
        return None


def _derive_log_id(entry, url):
    """Shard identity for the witness record (the "log generation").

    Preference: an explicit ``logId``/``log_id`` field; else the real
    Rekor derivation ``sha256(DER public key)`` from the entry's
    ``publicKey.rawBytes``; else ``sha256(url)``. Deterministic and
    documented; never invented per-run.
    """
    explicit = entry.get("logId") or entry.get("log_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    pubkey = entry.get("publicKey") or {}
    raw = pubkey.get("rawBytes")
    if isinstance(raw, str) and raw:
        try:
            der = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            der = None
        if der:
            return hashlib.sha256(der).hexdigest()
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _discover_tsa(doc, now):
    """The TSA endpoint from the signing config (the v2 receipt needs
    one). Latest-starting currently-valid entry wins; absence is
    fail-closed -- a witness receipt without a named TSA is a
    half-built receipt.
    """
    tsas = doc.get("tsa")
    if not isinstance(tsas, list):
        raise ShardDiscoveryError(
            "signing config has no 'tsa' section")
    best = None
    for entry in tsas:
        if not isinstance(entry, dict):
            continue
        if not _within_validity(entry.get("validFor"), now):
            continue
        url = _entry_url(entry)
        if url is None:
            continue
        start = _validity_start(entry.get("validFor"))
        if best is None or (start is not None and start > best[0]):
            best = (start, url)
    if best is None:
        raise ShardDiscoveryError(
            "signing config names no currently-valid TSA")
    return best[1]


def discover_v2_shard(signing_config, *, now=None):
    """Discover the currently-valid Rekor v2 shard from a TUF
    SigningConfig document.

    ``signing_config`` is a mapping, a JSON string, or a path to a
    JSON file (the ``signing_config_rekor_v2.v0.2.json`` shape: a
    ``"rekor"`` list whose entries carry ``url``/``baseUrl``,
    ``majorApiVersion``/``apiVersion`` == 2, and ``validFor``
    windows, plus a ``"tsa"`` section). Shards rotate (~6 months
    upstream), so the latest-starting currently-valid v2 entry wins;
    v1 entries and expired shards are skipped, never selected.

    Returns ``{"log_url", "log_id", "tsa_url"}`` -- the
    ``signing_config`` mapping ``HermeticRekorV2`` takes. Raises
    :class:`ShardDiscoveryError` when no usable v2 shard exists
    (fail-closed: a witness that cannot name its log writes
    nothing). No URLs are hardcoded anywhere in this module; the
    document is the only source of shard addresses.
    """
    doc = _coerce_doc(signing_config)
    rekors = doc.get("rekor")
    if not isinstance(rekors, list):
        raise ShardDiscoveryError(
            "signing config has no 'rekor' section")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    best = None
    for entry in rekors:
        if not isinstance(entry, dict):
            continue
        if _entry_api_version(entry) != _V2_API_VERSION:
            continue
        if not _within_validity(entry.get("validFor"), now):
            continue
        url = _entry_url(entry)
        if url is None:
            continue
        start = _validity_start(entry.get("validFor"))
        if best is None or (start is not None and
                             (best[0] is None or start > best[0])):
            best = (start, url, _derive_log_id(entry, url))
    if best is None:
        raise ShardDiscoveryError(
            "signing config names no currently-valid Rekor v2 shard")
    _, url, log_id = best
    return {"log_url": url, "log_id": log_id,
            "tsa_url": _discover_tsa(doc, now)}


class RekorV2Witness:
    """Second-witness Rekor v2 writer for evidence-bundle digests.

    ``signing_config`` is the TUF SigningConfig source (mapping, JSON
    text, or file path); when omitted, ``GOV_REKOR_V2_SIGNING_CONFIG``
    (a file path) is consulted. ``client`` is an injectable v2 client
    exposing ``submit_hashedrekord(anchor_hash, *, signature_b64,
    pubkey_pem, algorithm)`` (default: a lazily-built
    :class:`HermeticRekorV2` from the discovered shard).
    ``enabled`` overrides :func:`witness_enabled`.

    ``attach()`` NEVER raises: with the flag off it records
    ``"skipped"`` (zero submissions -- the client is not even built);
    on any failure -- no signing config, no valid shard, prod pins
    refused, log outage -- it records ``"failed"`` with the reason.
    The witness is not a gate: callers must never branch product
    decisions on the record, only file it in audit metadata (see
    :func:`record_in_metadata`).
    """

    def __init__(self, *, signing_config=None, client=None,
                 clock=None, enabled=None):
        self._signing_config = signing_config
        self._client_override = client
        self._resolved_client = None
        self._clock = clock or _utcnow
        self._enabled = witness_enabled(enabled)

    @property
    def enabled(self):
        return self._enabled

    def _resolve_signing_config(self):
        if self._signing_config is not None:
            return self._signing_config
        path = os.environ.get(CONFIG_ENV_VAR, "").strip()
        if path:
            return path
        return None

    def _client(self):
        if self._client_override is not None:
            return self._client_override
        if self._resolved_client is None:
            source = self._resolve_signing_config()
            if source is None:
                raise ShardDiscoveryError(
                    "no signing config: pass signing_config or set %s"
                    % (CONFIG_ENV_VAR,))
            shard = discover_v2_shard(source)
            # HermeticRekorV2 refuses the pinned Sigstore production
            # log values itself (self-hosted only) -- a prod-pinned
            # config surfaces here as a construction failure, which
            # attach() records as "failed", never as a live write.
            self._resolved_client = HermeticRekorV2(
                signing_config=shard)
        return self._resolved_client

    def _record(self, status, *, reason="", receipt=None,
                log_generation=None):
        return {
            "witness": WITNESS_NAME,
            "status": status,
            "reason": reason,
            # --- the honesty layer, on every record ---
            "evidentiary_grade": EVIDENTIARY_GRADE,
            "authority_proof": False,
            # --- the log generation, recorded on attach ---
            "log_generation": log_generation,
            "receipt": receipt,
            "recorded_at": self._clock(),
        }

    def attach(self, bundle_digest, *, signature_b64, pubkey_pem,
               algorithm="ed25519ph-sha512"):
        """Write a hashedrekord entry for ``bundle_digest`` as a
        SECOND witness. NEVER raises.

        ``bundle_digest`` is the 64-char hex sha256 of the evidence
        bundle (a ``DigestRef`` is also accepted); ``signature_b64`` /
        ``pubkey_pem`` are the anchor signature material the caller
        already holds (key custody stays with the caller -- this
        module never touches key material beyond passing it to the
        entry). Only the digest crosses the transparency boundary;
        bundle contents are never submitted.

        Returns the witness record (see :meth:`_record`). With the
        flag off the record is ``"skipped"`` and nothing is
        submitted. Any failure -- discovery, config, refusal, outage
        -- is recorded as ``"failed"`` with the reason; the product
        path is never failed closed by this seam.
        """
        if not self._enabled:
            return self._record(
                STATUS_SKIPPED,
                reason="flag-off: %s not enabled; local anchor remains "
                       "the only witness" % (FLAG_ENV_VAR,))
        try:
            client = self._client()
            receipt = client.submit_hashedrekord(
                bundle_digest, signature_b64=signature_b64,
                pubkey_pem=pubkey_pem, algorithm=algorithm)
        except Exception as e:
            # The witness is not a gate: every failure mode --
            # ShardDiscoveryError, V2ConfigError (incl. prod-pin
            # refusal), V2DownError/outage, caller-shape errors --
            # becomes a recorded "failed", never a raise.
            return self._record(
                STATUS_FAILED,
                reason="%s: %s" % (type(e).__name__, e))
        generation = {"log_id": receipt.get("log_id"),
                      "log_url": receipt.get("url")}
        return self._record(STATUS_ATTACHED, receipt=receipt,
                            log_generation=generation)


def record_in_metadata(metadata, record):
    """File a witness record in bundle audit metadata.

    ``metadata`` is the bundle's audit-metadata mapping; the record
    is appended to its ``"witnesses"`` list (created when absent).
    Both ``"attached"`` and ``"failed"`` records are filed -- a
    failed witness is audit evidence too. Returns ``metadata``.
    Raises :class:`TypeError` on a non-mapping ``metadata``/``record``
    or a non-list ``"witnesses"`` slot (fail-closed on shape, so a
    caller can never silently misfile).
    """
    if not isinstance(metadata, dict):
        raise TypeError("metadata must be a mapping, got %s"
                        % type(metadata).__name__)
    if not isinstance(record, dict):
        raise TypeError("record must be a mapping, got %s"
                        % type(record).__name__)
    witnesses = metadata.get("witnesses")
    if witnesses is None:
        witnesses = []
        metadata["witnesses"] = witnesses
    if not isinstance(witnesses, list):
        raise TypeError("metadata['witnesses'] must be a list, got %s"
                        % type(witnesses).__name__)
    witnesses.append(dict(record))
    return metadata
