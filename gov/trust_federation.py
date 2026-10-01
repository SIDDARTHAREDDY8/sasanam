"""Cross-trust-domain federation for the agent mesh (wave-264 lane 3).

An ADAPT of the SPIFFE Federation standard's *protocol* (pattern
only -- no SPIFFE code or spec text is read, copied, imported, or
vendored). The recombination target: w258's headscale-profile
control plane and w262's A2A mesh-auth cover identity *within* a
trust domain; this module covers *across* them -- our agent
inventory federates with a partner's trust domain by fetching their
bundle, polls for key rotation, and de-federates by bundle deletion.

The four adapted mechanisms:

* **Federation relationship** (:class:`FederationRelationship`):
  the foreign **trust domain name**, its **bundle endpoint URL**
  (https only), and the **endpoint profile** (``https_spiffe`` /
  ``https_web`` -- the standard's two bundle-endpoint profiles,
  recording the protocol + authentication semantics of the
  endpoint). The endpoint's bundle-signing key is pinned at
  declaration. Malformed relationships refuse
  ``federation-relationship-malformed`` at declaration time.
* **One-way by default**: a relationship is a single directed edge.
  "Alice could have a relationship with Bob but not vice versa" --
  mutual authentication is *two* relationships, one per direction.
  Trusting B's agents never lets B's view verify our SVIDs: a table
  without the reverse relationship refuses
  ``federation-untrusted-domain``. Asymmetric trust is the default,
  mapping onto asymmetric partnerships (we trust their agents'
  calls into our tools; they don't reciprocate).
* **Bundle polling with rotation tolerance**
  (:meth:`FederationTable.refresh_bundle`): the deployment polls the
  bundle endpoint (transport is deployment-supplied -- this module
  takes the fetched bytes, never fetches) and the table validates
  and installs the bundle: signature under the pinned endpoint key
  (``federation-bundle-signature-invalid``), structural checks
  (``federation-bundle-malformed``), trust-domain binding
  (``federation-bundle-confusion``), and expiry. ``next_roots``
  are keys published in advance of use: SVIDs under an announced
  next root verify while the bundle is fresh, so missing a poll
  does not break cross-domain auth during rotation. A bundle past
  ``expires_at`` refuses ``federation-bundle-expired`` -- stale is
  fail-closed at both install and verify time.
* **Termination is deletion** (:meth:`FederationTable.remove`):
  de-federation deletes the local relationship + bundle and stops
  polling -- a local operation, no handshake -- and journals
  ``federation-trust-revoked`` to the hash-chained durable journal.
  Afterwards the domain refuses ``federation-relationship-
  terminated`` (kept distinct from ``federation-untrusted-domain``
  so auditors can tell revoked trust from never-granted trust).

Composition (never duplication):

* SVID verification is delegated to
  ``gov.svid_issuer.SvidVerifier`` over the bundle's
  ``roots | next_roots`` for the foreign trust domain. Its
  ``svid-*`` refusals (unknown issuer, bad signature, expired,
  trust-domain mismatch, usage mismatch) propagate unchanged.
* :class:`FederatedMeshControl` mirrors
  ``gov.svid_issuer.MeshControl.admit``'s shape so it plugs into
  ``gov.mesh_admission.MeshAdmission`` as a fourth route requirement
  (``"require": "federated"``) -- the cross-trust-domain half of the
  mesh. Each route still evaluates exactly one seam, so the
  admission no-downgrade discipline holds across all four modes;
  the federated path is an additional trust source, never a
  fallback.
* Bundle distribution to local validators follows the signed-bundle
  discipline of ``gov.policy_distribution`` (operator-signed,
  verify-before-install); the endpoint transport itself stays
  deployment-supplied.

Machine codes (domain ``federation``):
``federation-relationship-malformed`` /
``federation-bundle-malformed`` /
``federation-bundle-signature-invalid`` /
``federation-bundle-expired`` / ``federation-bundle-confusion`` /
``federation-untrusted-domain`` / ``federation-relationship-
terminated``.

Fail-closed: every refusal is machine-coded; nothing verifies on a
partial check. The clock is injected (``now``); a None ``now``
resolves to ``time.time()`` per the F224 contract (``_validate_now``
raises the composed ``svid-malformed`` for a bad clock, exactly as
the admission seam does).

Honest boundaries
-----------------
* This module does not solve first-contact trust: the endpoint
  signing key pinned in the relationship is deployment-supplied
  trust material, exactly like SVID trust roots.
* The bundle endpoint transport (TLS, polling schedule, retry) is
  deployment-owned. ``refresh_bundle`` takes fetched bytes; a
  deployment that never polls runs on a bundle until it expires,
  then refuses -- loudly, not silently.
* A federated SVID proves the foreign issuer's attestation, not the
  foreign deployment's honesty (no Sybil resistance across trust
  domains -- same boundary as the mesh-auth contract).
* ``next_roots`` acceptance is bounded by the bundle's own
  ``expires_at``: rotation tolerance never extends trust past the
  bundle's lifetime.

Stdlib only. Deterministic: injectable clock, no I/O except the
optional journal path, no network, no in-repo git subprocesses.
"""

import hashlib
import json
import os
import re
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from . import ed25519 as _ed25519
from . import durable_journal as _durable_journal
from .svid_issuer import (
    SvidError,
    SvidVerifier,
    _validate_now,
)

__all__ = [
    "FederationError",
    "FederationRelationship",
    "TrustBundle",
    "FederationTable",
    "FederatedMeshControl",
    "ENDPOINT_PROFILE_HTTPS_SPIFFE",
    "ENDPOINT_PROFILE_HTTPS_WEB",
    "CODES",
    "RELATIONSHIP_MALFORMED_CODE",
    "BUNDLE_MALFORMED_CODE",
    "BUNDLE_SIGNATURE_INVALID_CODE",
    "BUNDLE_EXPIRED_CODE",
    "BUNDLE_CONFUSION_CODE",
    "BUNDLE_MISSING_CODE",
    "UNTRUSTED_DOMAIN_CODE",
]

#: The SPIFFE standard's two bundle-endpoint profiles.
ENDPOINT_PROFILE_HTTPS_SPIFFE = "https_spiffe"
ENDPOINT_PROFILE_HTTPS_WEB = "https_web"
_ENDPOINT_PROFILES = frozenset([
    ENDPOINT_PROFILE_HTTPS_SPIFFE,
    ENDPOINT_PROFILE_HTTPS_WEB,
])

#: Machine codes (registered in gov/decision_codes.py, domain
#: "federation").
RELATIONSHIP_MALFORMED_CODE = "federation-relationship-malformed"
BUNDLE_MALFORMED_CODE = "federation-bundle-malformed"
BUNDLE_SIGNATURE_INVALID_CODE = "federation-bundle-signature-invalid"
BUNDLE_EXPIRED_CODE = "federation-bundle-expired"
BUNDLE_CONFUSION_CODE = "federation-bundle-confusion"
BUNDLE_MISSING_CODE = "federation-bundle-missing"
UNTRUSTED_DOMAIN_CODE = "federation-untrusted-domain"

CODES = (
    RELATIONSHIP_MALFORMED_CODE,
    BUNDLE_MALFORMED_CODE,
    BUNDLE_SIGNATURE_INVALID_CODE,
    BUNDLE_EXPIRED_CODE,
    BUNDLE_CONFUSION_CODE,
    BUNDLE_MISSING_CODE,
    UNTRUSTED_DOMAIN_CODE,
)

#: Domain separation for bundle signatures, mirroring the SVID
#: convention (domain || sha256(canonical)).
_BUNDLE_DOMAIN = b"sasanam-federation-bundle/v1:"

_BUNDLE_FIELDS = ("trust_domain", "bundle_id", "issued_at",
                  "expires_at", "roots", "next_roots",
                  "endpoint_signature")

#: Trust-domain syntax (SPIFFE): same shape SvidVerifier enforces.
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-_]*[a-z0-9])?$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_MAX_KEY_ID_LEN = 128


class FederationError(Exception):
    """Machine-coded refusal. ``code`` is a decision-code taxonomy key."""

    def __init__(self, code, detail=""):
        super(FederationError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _bundle_signing_bytes(body):
    """Bytes the endpoint signs: domain || sha256(canonical(body)).

    ``body`` is the bundle WITHOUT the endpoint_signature field, so
    the signature covers every other field exactly once.
    """
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    return _BUNDLE_DOMAIN + digest.encode("ascii")


def _check_domain(value, what):
    if not isinstance(value, str) or not _TRUST_DOMAIN_RE.match(value) \
            or len(value) > 255:
        raise FederationError(
            RELATIONSHIP_MALFORMED_CODE,
            "%s must be a valid trust domain string, got %r"
            % (what, value))
    return value.lower()


def _normalize_domain(value):
    """Lowercase a trust-domain lookup key without validating it.

    Used where a non-string / unknown domain must refuse with the
    lookup's own code (untrusted-domain), not a malformed-input
    code: ``remove``/``refresh_bundle`` on a bad key refuse at the
    relationship lookup, exactly like ``verify_foreign``.
    """
    return value.lower() if isinstance(value, str) else value


def _check_endpoint_url(value):
    if not isinstance(value, str) or \
            not value.startswith("https://"):
        raise FederationError(
            RELATIONSHIP_MALFORMED_CODE,
            "bundle_endpoint must be an https:// URL, got %r"
            % (value,))
    host = value[len("https://"):].split("/", 1)[0]
    if not host or any(c.isspace() for c in value):
        raise FederationError(
            RELATIONSHIP_MALFORMED_CODE,
            "bundle_endpoint has no host (or whitespace): %r"
            % (value,))
    return value


def _check_profile(value):
    if value not in _ENDPOINT_PROFILES:
        raise FederationError(
            RELATIONSHIP_MALFORMED_CODE,
            "endpoint_profile must be one of %s, got %r"
            % (sorted(_ENDPOINT_PROFILES), value))
    return value


def _check_endpoint_key(value):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise FederationError(
            RELATIONSHIP_MALFORMED_CODE,
            "endpoint_public_key must be 64 lowercase hex chars "
            "(Ed25519)")
    return value


def _check_key_id(value, what):
    if not isinstance(value, str) or not value or \
            len(value) > _MAX_KEY_ID_LEN:
        raise FederationError(
            BUNDLE_MALFORMED_CODE,
            "%s must be a non-empty str (<= %d chars)"
            % (what, _MAX_KEY_ID_LEN))
    return value


class FederationRelationship(object):
    """One directed federation edge: foreign trust domain + bundle
    endpoint URL + endpoint profile + pinned endpoint signing key.

    Validated at construction; malformed triples refuse
    ``federation-relationship-malformed`` before any trust is
    recorded.
    """

    def __init__(self, trust_domain, bundle_endpoint,
                 endpoint_profile, endpoint_public_key):
        self._trust_domain = _check_domain(trust_domain,
                                           "trust_domain")
        self._bundle_endpoint = _check_endpoint_url(bundle_endpoint)
        self._endpoint_profile = _check_profile(endpoint_profile)
        self._endpoint_public_key = _check_endpoint_key(
            endpoint_public_key)

    @property
    def trust_domain(self):
        return self._trust_domain

    @property
    def bundle_endpoint(self):
        return self._bundle_endpoint

    @property
    def endpoint_profile(self):
        return self._endpoint_profile

    @property
    def endpoint_public_key(self):
        """Pinned endpoint signing key (64 hex chars)."""
        return self._endpoint_public_key

    def record(self):
        """The relationship as a JSON-safe record (no secrets: the
        pinned key is public material)."""
        return {
            "trust_domain": self._trust_domain,
            "bundle_endpoint": self._bundle_endpoint,
            "endpoint_profile": self._endpoint_profile,
            "endpoint_public_key": self._endpoint_public_key,
        }


class TrustBundle(object):
    """A validated foreign trust bundle.

    Built via :meth:`from_bytes`: the deployment's fetched bundle
    bytes are parsed, signature-verified under the relationship's
    pinned endpoint key, domain-bound to the relationship, and
    expiry-checked. Use :meth:`federated_roots` for the verifier's
    trust roots (``roots | next_roots`` -- rotation tolerance).
    """

    def __init__(self, body):
        self._body = body

    @classmethod
    def from_bytes(cls, raw, relationship, now=None):
        """Validate fetched bundle bytes against ``relationship``.

        Fail-closed order: parse -> structure -> domain binding ->
        signature -> expiry. ``now`` follows the F224 contract.
        """
        at = _validate_now(now)
        try:
            text = raw.decode("utf-8") if isinstance(raw, bytes) \
                else raw
            doc = json.loads(text)
        except Exception:
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "bundle bytes are not JSON/UTF-8")
        if not isinstance(doc, dict):
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "bundle must be a JSON object")
        for field in _BUNDLE_FIELDS:
            if field not in doc:
                raise FederationError(
                    BUNDLE_MALFORMED_CODE,
                    "bundle missing field %r" % (field,))
        body = {k: v for k, v in doc.items()
                if k != "endpoint_signature"}
        # Structure BEFORE domain binding: a malformed trust_domain
        # (non-string, bad shape) is federation-bundle-malformed,
        # not confusion.
        cls._check_body(body)
        # Domain binding BEFORE signature: a bundle for another
        # domain is confusion even if perfectly signed.
        if body["trust_domain"] != relationship.trust_domain:
            raise FederationError(
                BUNDLE_CONFUSION_CODE,
                "bundle trust_domain %r does not match relationship "
                "domain %r: cross-domain bundle use refused"
                % (body["trust_domain"], relationship.trust_domain))
        sig = doc["endpoint_signature"]
        if not isinstance(sig, str) or not _HEX128_RE.match(sig):
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "endpoint_signature must be 128 lowercase hex chars")
        try:
            sig_bytes = bytes.fromhex(sig)
            endpoint_pub = bytes.fromhex(
                relationship.endpoint_public_key)
            # Wave-243 lesson: ed25519.verify returns True/False and
            # never raises -- check the return, never truthiness.
            ok = _ed25519.verify(
                endpoint_pub, _bundle_signing_bytes(body),
                sig_bytes) is True
        except Exception:
            ok = False
        if not ok:
            raise FederationError(
                BUNDLE_SIGNATURE_INVALID_CODE,
                "bundle signature does not verify under the pinned "
                "endpoint key for %r" % (relationship.trust_domain,))
        if at >= body["expires_at"]:
            raise FederationError(
                BUNDLE_EXPIRED_CODE,
                "bundle for %r expired at %r"
                % (relationship.trust_domain, body["expires_at"]))
        return cls(body)

    @staticmethod
    def _check_body(body):
        if not isinstance(body.get("trust_domain"), str) or \
                not _TRUST_DOMAIN_RE.match(body["trust_domain"]):
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "bundle trust_domain is not a valid trust domain")
        if not isinstance(body.get("bundle_id"), str) or \
                not body["bundle_id"]:
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "bundle bundle_id must be a non-empty string")
        for field in ("issued_at", "expires_at"):
            value = body.get(field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise FederationError(
                    BUNDLE_MALFORMED_CODE,
                    "bundle %s must be an int epoch" % (field,))
        if body["issued_at"] > body["expires_at"]:
            raise FederationError(
                BUNDLE_MALFORMED_CODE,
                "bundle issued_at is after expires_at")
        for field in ("roots", "next_roots"):
            roots = body.get(field)
            if not isinstance(roots, dict) or not roots:
                raise FederationError(
                    BUNDLE_MALFORMED_CODE,
                    "bundle %s must be a non-empty mapping "
                    "key_id -> 64-hex Ed25519 public key" % (field,))
            for key_id, pubkey in roots.items():
                _check_key_id(key_id, "bundle %s key id" % (field,))
                if not isinstance(pubkey, str) or \
                        not _HEX64_RE.match(pubkey):
                    raise FederationError(
                        BUNDLE_MALFORMED_CODE,
                        "bundle %s key %r must be 64 lowercase hex "
                        "chars" % (field, key_id))

    @property
    def trust_domain(self):
        return self._body["trust_domain"]

    @property
    def bundle_id(self):
        return self._body["bundle_id"]

    @property
    def expires_at(self):
        return self._body["expires_at"]

    def federated_roots(self):
        """Trust roots for the verifier: ``roots | next_roots``.

        ``next_roots`` are keys the foreign domain published in
        advance of use (rotation tolerance): accepting them while
        the bundle is fresh means a missed poll does not break
        cross-domain auth mid-rotation. Bounded by the bundle's own
        ``expires_at`` -- rotation tolerance never extends trust
        past the bundle's lifetime. On a key_id collision,
        ``next_roots`` win: the bundle's author attested to the new
        key under the pinned endpoint key, so the rotation takes
        effect (first-wins would silently drop rotations).
        """
        merged = dict(self._body["roots"])
        merged.update(self._body["next_roots"])
        return {kid: bytes.fromhex(pub)
                for kid, pub in merged.items()}


_SPIFFE_ID_RE = re.compile(r"^spiffe://([^/]+)/")


class FederationTable(object):
    """The local federation state: relationships and bundles.

    ``journal_path`` (required): a ``durable_journal.Journal`` path.
    Relationship add/remove and bundle refresh are journaled, and
    ``remove()`` journals ``federation-trust-revoked`` -- the audit
    trail for de-federation is not optional: the spec journals the
    trust-revocation event in the audit log, so a table without a
    journal cannot exist.
    """

    def __init__(self, journal_path):
        self._relationships = {}
        self._bundles = {}
        self._journal = _durable_journal.Journal(journal_path)

    # -- relationship management ------------------------------------

    def add_relationship(self, trust_domain, bundle_endpoint,
                         endpoint_profile, endpoint_public_key):
        """Declare one directed federation edge. Re-adding a live
        domain replaces its relationship (re-pinning is explicit).
        """
        rel = FederationRelationship(
            trust_domain, bundle_endpoint, endpoint_profile,
            endpoint_public_key)
        domain = rel.trust_domain
        self._relationships[domain] = rel
        self._journal_append("federation-relationship-added",
                             rel.record())
        return rel.record()

    def remove(self, trust_domain):
        """De-federate: delete the local relationship + bundle and
        stop polling. Local operation, no handshake. Journals
        ``federation-trust-revoked``. Termination is deletion, per
        the spec: afterwards the domain is as-if-never-granted (a
        later ``add_relationship`` re-federates fresh). Unknown
        domains still journal (the revocation intent is recorded)
        and refuse ``federation-untrusted-domain``.
        """
        domain = _normalize_domain(trust_domain)
        existed = domain in self._relationships
        self._relationships.pop(domain, None)
        self._bundles.pop(domain, None)
        self._journal_append("federation-trust-revoked",
                             {"trust_domain": domain,
                              "had_relationship": existed})
        if not existed:
            raise FederationError(
                UNTRUSTED_DOMAIN_CODE,
                "no federation relationship for %r" % (trust_domain,))
        return {"trust_domain": domain, "revoked": True}

    def relationships(self):
        """The declared relationships (read-only records)."""
        return {d: r.record()
                for d, r in self._relationships.items()}

    # -- bundle polling ---------------------------------------------

    def refresh_bundle(self, trust_domain, bundle_bytes, now=None):
        """Install a freshly polled bundle for a declared
        relationship. The bytes are the deployment's fetch from the
        relationship's bundle endpoint; transport stays
        deployment-owned. Validates signature, domain binding, and
        expiry before installing -- nothing half-valid is kept.
        """
        at = _validate_now(now)
        domain = _normalize_domain(trust_domain)
        rel = self._relationships.get(domain)
        if rel is None:
            raise FederationError(
                UNTRUSTED_DOMAIN_CODE,
                "no federation relationship for %r: declare it "
                "before polling its bundle" % (trust_domain,))
        bundle = TrustBundle.from_bytes(bundle_bytes, rel, now=at)
        self._bundles[domain] = bundle
        self._journal_append("federation-bundle-refreshed",
                             {"trust_domain": domain,
                              "bundle_id": bundle.bundle_id,
                              "expires_at": bundle.expires_at})
        return {"trust_domain": domain,
                "bundle_id": bundle.bundle_id,
                "expires_at": bundle.expires_at}

    # -- cross-domain verification ------------------------------------

    @staticmethod
    def _attributable_domain(svid):
        """The trust domain a presented SVID is attributable to.

        Parsed from the SVID's own spiffe_id -- but never trusted
        for authorization: the composed SvidVerifier re-validates
        the domain strictly. An unattributable SVID (missing /
        malformed spiffe_id) refuses federation-untrusted-domain:
        there is no relationship it could belong to.
        """
        spiffe_id = svid.get("spiffe_id") if isinstance(svid, dict) \
            else None
        if not isinstance(spiffe_id, str):
            raise FederationError(
                UNTRUSTED_DOMAIN_CODE,
                "SVID has no attributable trust domain "
                "(missing spiffe_id)")
        match = _SPIFFE_ID_RE.match(spiffe_id)
        if not match or not _TRUST_DOMAIN_RE.match(match.group(1)):
            raise FederationError(
                UNTRUSTED_DOMAIN_CODE,
                "SVID spiffe_id %r attributes to no valid trust "
                "domain" % (spiffe_id,))
        return match.group(1).lower()

    def verify_foreign(self, svid, now=None, expected_usage=None):
        """Verify a foreign SVID against its domain's federated
        bundle. Returns the identity claims dict (composed from
        ``SvidVerifier`` -- its ``svid-*`` refusals propagate
        unchanged).

        Fail-closed order: clock -> attributable domain ->
        relationship -> bundle installed -> bundle still fresh ->
        SVID verifies under roots|next_roots.
        """
        at = _validate_now(now)
        domain = self._attributable_domain(svid)
        rel = self._relationships.get(domain)
        if rel is None:
            raise FederationError(
                UNTRUSTED_DOMAIN_CODE,
                "no federation relationship for trust domain %r: "
                "one-way federation -- declare it before verifying "
                "its SVIDs" % (domain,))
        bundle = self._bundles.get(domain)
        if bundle is None:
            raise FederationError(
                BUNDLE_MISSING_CODE,
                "no bundle installed for %r: poll the bundle "
                "endpoint before verifying" % (domain,))
        if at >= bundle.expires_at:
            raise FederationError(
                BUNDLE_EXPIRED_CODE,
                "bundle for %r expired at %r: re-poll before "
                "verifying" % (domain, bundle.expires_at))
        verifier = SvidVerifier(
            trust_roots=bundle.federated_roots(),
            trust_domain=domain)
        # Composed, not wrapped: the verifier's svid-* refusals are
        # the vocabulary for SVID defects; federation-* is the
        # vocabulary for trust-relationship defects.
        return verifier.verify(svid, now=at,
                               expected_usage=expected_usage)

    # -- journal ------------------------------------------------------

    def _journal_append(self, rtype, body):
        self._journal.append(rtype, body)

    def journal_records(self):
        """The journal's records (native shape: ``type``/``body`` /
        ``seq`` / ``hash``)."""
        return list(self._journal.records)


class FederatedMeshControl(object):
    """Mesh-control-shaped admission over federated SVIDs.

    Mirrors ``gov.svid_issuer.MeshControl.admit``'s call shape
    (``admit(svid, now=None, expected_usage=None)`` -> claims dict)
    and plugs into ``gov.mesh_admission.MeshAdmission`` as the
    ``"require": "federated"`` route mode -- but it verifies
    *foreign* SVIDs against the federation table, never local ones.
    It is an additional trust source, never a fallback: each
    admission route evaluates exactly one seam, so the no-downgrade
    discipline holds.
    """

    def __init__(self, table):
        if not isinstance(table, FederationTable):
            raise TypeError(
                "table must be a gov.trust_federation.FederationTable")
        self._table = table

    @property
    def table(self):
        return self._table

    def admit(self, svid, now=None, expected_usage=None):
        """Admit one foreign SVID. Returns the identity claims dict.

        Refuses ``federation-untrusted-domain`` when the SVID's
        trust domain has no federation relationship (including
        a missing SVID -- no domain is attributable),
        ``federation-bundle-missing`` when the relationship exists
        but no bundle was ever polled, the relationship's other
        ``federation-*`` refusals for stale / confused trust, and
        the composed verifier's ``svid-*`` refusals for SVID
        defects.
        """
        return self._table.verify_foreign(
            svid, now=now, expected_usage=expected_usage)