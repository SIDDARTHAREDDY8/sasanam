"""Tink-pattern master-key keysets over the gov/kms_* provider seam.

PATTERN LINEAGE: tink-crypto/tink (Apache-2.0; canonical org --
``google/tink`` is archived/read-only, the repo is being split --
track the roadmap). This module adapts four Tink mechanisms as
contract shapes for envelope-encryption master keys and reimplements
them in stdlib Python. **No Tink code is vendored here** -- only the
patterns:

* the **keyset schema**: a versioned document listing keys, each with
  a lifecycle status, plus a designated primary;
* the **status lifecycle**: ENABLED / DISABLED / DESTROYED with
  fail-closed, coded transitions;
* the **rotation ceremony**: add-key -> roll-out -> promote as a
  defined, auditable procedure;
* **key templates**: declared, named, versioned primitive bindings.

What this module is NOT: it is not ``gov/keyset.py`` (wave-199).
That module governs *signing* keysets (versioned Ed25519 keys for
audit-entry signing, with previous-primary-signed rotation lineage).
This module governs *envelope master* keys -- the KMS-side keys that
wrap data keys through the :class:`gov.kms.KmsProvider` seam. The two
compose: a ``KmsKeyset`` decides *which* master key id a wrap/unwrap
may use and *whether* its lifecycle status permits the operation; the
provider performs the cryptography. Key material never appears here
-- only key ids, statuses, and digests.

The lifecycle registry is authoritative ABOVE the provider. Real
backends differ in what they can express (Vault transit's describe
reports only "enabled" -- a key whose read succeeds is usable), so
the keyset holds the deployment-declared status for every key and
treats provider describe as corroboration: where a provider *can*
express lifecycle (the deterministic test double does), a provider
that reports disabled/destroyed for a key the keyset believes enabled
makes the operation refuse LOUD rather than proceed on a
disagreement. Providers that cannot express lifecycle are assumed
"enabled-only" and the keyset registry is the whole policy (this is
fail-closed: a deployment that disables a key in the keyset can no
longer mint wraps under it even though the backend would allow it).

Determinism note: digests bind configuration and chain order, not
wall-clock metadata. The ``at`` timestamps on audit events are
informational and are excluded from digest inputs by construction, so
two keysets that undergo the same operation sequence carry the same
``keyset_digest``. An attacker rewriting ``at`` changes nothing about
authorization; the event content and ordering are what the chain
protects.
"""

import hashlib
import hmac
import json
import os
import re
import secrets

from .kms import KmsError, _utcnow

#: Document format tag. Bumped only for breaking schema changes.
KEYSET_FORMAT = "sasanam-kms-keyset/v1"

#: Pin-key size: the ``keyset_digest`` pin is an HMAC-SHA256 under a
#: 256-bit deployment-held key (see F329).
PIN_KEY_BYTES = 32

#: Domain separation label for the configuration pin MAC.
_PIN_LABEL = b"sasanam-kms-keyset/pin-v1:"

#: Tink's KeyStatusType vocabulary, adapted.
STATUSES = ("enabled", "disabled", "destroyed")

#: Rotation ceremony phases.
CEREMONY_PHASES = ("none", "rolling-out", "roll-out-failed",
                   "verified", "complete")

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_GENESIS_DIGEST = "0" * 64


class KeysetError(Exception):
    """Any keyset refusal. Carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text).
    Never carries key material in its message."""

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest_of(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _validate_key_id(key_id):
    # Same contract as gov.kms key ids (operator identifiers, never
    # key material).
    if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
        raise KeysetError("keyset-unknown-key",
                          "invalid key id %r" % (key_id,))


def _validate_pin_key(pin_key):
    """The pin key is a deployment-held 256-bit secret. It is REQUIRED
    (never defaulted): ``new``/``from_dict``/``_repin`` refuse LOUD and
    coded without it, so a caller can never silently fall back to an
    unkeyed pin."""
    if not isinstance(pin_key, (bytes, bytearray)) or \
            len(pin_key) != PIN_KEY_BYTES:
        raise KeysetError("keyset-pin-key-invalid",
                          "pin_key must be %d bytes, got %r"
                          % (PIN_KEY_BYTES,
                             type(pin_key).__name__))
    return bytes(pin_key)


def generate_pin_key(path):
    """Create a fresh random pin key and persist it (0600, atomic).

    Refuses LOUD (``keyset-pin-key-invalid``) if the path already exists
    -- a pin key is a trust anchor and is never silently overwritten.
    Returns the key bytes."""
    if not isinstance(path, str) or not path:
        raise KeysetError("keyset-pin-key-invalid",
                          "pin key path must be a non-empty string")
    if os.path.exists(path):
        raise KeysetError("keyset-pin-key-invalid",
                          "pin key file %r already exists: refusing to "
                          "overwrite a trust anchor" % (path,))
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    key = secrets.token_bytes(PIN_KEY_BYTES)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise KeysetError("keyset-pin-key-invalid",
                          "pin key write failed for %r" % (path,))
    os.replace(tmp, path)
    return key


def load_pin_key(path):
    """Load a persisted pin key. Refuses LOUD (``keyset-pin-key-invalid``)
    on any problem: missing/unreadable file or wrong key size."""
    if not isinstance(path, str) or not path:
        raise KeysetError("keyset-pin-key-invalid",
                          "pin key path must be a non-empty string")
    try:
        with open(path, "rb") as handle:
            key = handle.read()
    except OSError as exc:
        raise KeysetError("keyset-pin-key-invalid",
                          "pin key file %r unreadable: %s" % (path, exc))
    return _validate_pin_key(key)


#: Sentinel distinguishing "key absent" from an explicit None value in
#: the ceremony sub-document (F327).
_MISSING = object()


def _validate_ceremony(ceremony):
    """Fail-closed shape check for the rotation-ceremony sub-document.

    Called by :meth:`KmsKeyset._parse` (before the pin is recomputed)
    and by :meth:`KmsKeyset._repin`: every malformed ceremony shape --
    a missing or non-mapping ceremony, an unknown phase, a missing or
    wrongly typed ``new_key_id`` slot, a missing attempt counter on an
    in-progress phase -- refuses with a coded ``keyset-*`` KeysetError
    (F327). The pin builder indexes ``ceremony["new_key_id"]``
    directly; it must never see a raw KeyError at this seam.
    """
    if not isinstance(ceremony, dict):
        raise KeysetError("keyset-ceremony-incomplete",
                          "ceremony must be a mapping, got %r"
                          % (type(ceremony).__name__,))
    phase = ceremony.get("phase")
    if phase not in CEREMONY_PHASES:
        raise KeysetError("keyset-ceremony-incomplete",
                          "unknown ceremony phase %r" % (phase,))
    new_key_id = ceremony.get("new_key_id", _MISSING)
    if phase in ("rolling-out", "roll-out-failed", "verified"):
        # An in-progress ceremony must name its successor; a phase
        # without a new_key_id is a malformed document, refused coded
        # (never a raw KeyError downstream). roll_out also reads the
        # attempt counter, so its absence is malformed too.
        if not isinstance(new_key_id, str) or not new_key_id:
            raise KeysetError("keyset-ceremony-incomplete",
                              "ceremony phase %r names no successor"
                              % (phase,))
        attempts = ceremony.get("attempts", _MISSING)
        if not isinstance(attempts, int):
            raise KeysetError("keyset-ceremony-incomplete",
                              "ceremony phase %r has malformed attempts %r"
                              % (phase, attempts))
    elif new_key_id is _MISSING or not (new_key_id is None
                                        or isinstance(new_key_id, str)):
        # A settled ceremony still carries a well-formed successor slot:
        # None or a string. A missing slot or a wrong type is malformed
        # (F327: the pin builder indexes this slot directly).
        raise KeysetError("keyset-ceremony-incomplete",
                          "ceremony phase %r has malformed new_key_id"
                          % (phase,))


class KeyTemplate:
    """A declared, named, versioned primitive binding.

    The project chooses the primitives; the template binds the choice
    to a version so upgrades are explicit: adopting a new primitive
    requires declaring a new template version and a governed
    ``retemplate`` -- never a silent parameter change.
    """

    __slots__ = ("name", "primitive", "params")

    def __init__(self, name, primitive, params):
        if not isinstance(name, str) or "/v" not in name:
            raise KeysetError("keyset-bad-template",
                              "template name must carry a version "
                              "(<name>/v<n>), got %r" % (name,))
        if not isinstance(primitive, str) or not primitive:
            raise KeysetError("keyset-bad-template",
                              "template primitive must be a non-empty "
                              "string")
        self.name = name
        self.primitive = primitive
        self.params = dict(params or {})


#: The declared template registry. Keysets may only be created under a
#: template named here; unknown names refuse LOUD at construction.
TEMPLATES = {
    "KMS-ENVELOPE/v1": KeyTemplate(
        "KMS-ENVELOPE/v1",
        primitive="provider-wrap",
        params={"data_key_bytes": 32,
                "wrap": "provider-native (GenerateDataKey/Decrypt, "
                        "encrypt/decrypt, or wrapKey/unwrapKey)",
                "key_id_binding": "required (impersonator hardening)"}),
    "KMS-ENVELOPE-HKDF/v1": KeyTemplate(
        "KMS-ENVELOPE-HKDF/v1",
        primitive="provider-wrap-hkdf",
        params={"data_key_bytes": 32,
                "wrap": "provider-native, with the wrapped data key "
                        "derived via HKDF from a master secret bound to "
                        "the template name",
                "key_id_binding": "required (impersonator hardening)",
                "note": "upgrade target from KMS-ENVELOPE/v1; the "
                        "primitive executes in the provider, the template "
                        "is the explicit versioned binding"}),
}


# Provider lifecycle expressiveness, as declared governance knowledge
# (see module docstring). Providers that cannot express lifecycle are
# assumed "enabled-only": the keyset registry is the whole policy.
# This table is consulted by the keyset; providers are NOT modified.
_PROVIDER_LIFECYCLE = {
    "fake": "full",
    "vault": "provider-reports-enabled-only",
    "vault-spiffe": "provider-reports-enabled-only",
}


def _provider_lifecycle(provider_name):
    return _PROVIDER_LIFECYCLE.get(provider_name,
                                  "provider-reports-enabled-only")


class KmsKeyset:
    """A versioned, digest-pinned keyset of envelope master keys.

    The document is data: ``to_dict``/``from_dict`` round-trip through
    a JSON mapping the deployment persists (0600, like the envelope
    keyring file). ``keyset_digest`` pins the configuration
    (keys/statuses/primary/template/ceremony/audit-head) as a keyed MAC
    (HMAC-SHA256) under a deployment-held pin key: any out-of-band edit
    is detectable by a holder of the key, and the pin cannot be
    recomputed without it (F329).

    Trust model (honest): the pin key lives in a separate 0600 file
    (see :func:`generate_pin_key`/:func:`load_pin_key`). A writer who
    holds only the keyset document -- not the pin key -- cannot forge
    a valid pin. A holder of the pin key is the authorized operator and
    can re-pin; that is the intended use of :meth:`_repin`, never a
    back door for untrusted input.
    """

    def __init__(self, doc, pin_key):
        self._pin_key = _validate_pin_key(pin_key)
        self._doc = self._parse(doc, self._pin_key)

    # -- construction -------------------------------------------------

    @classmethod
    def new(cls, *, template_name, primary_key_id, provider_name,
            pin_key=None, created_utc=None):
        """Create a keyset with a single enabled primary key.

        ``pin_key`` is REQUIRED (a 256-bit deployment-held secret): the
        configuration pin is a keyed MAC, so creating a keyset without
        the key refuses LOUD and coded (``keyset-pin-key-invalid``)."""
        pin_key = _validate_pin_key(pin_key)
        template = TEMPLATES.get(template_name)
        if template is None:
            raise KeysetError("keyset-bad-template",
                              "unknown key template %r (declared: %s)"
                              % (template_name, sorted(TEMPLATES)))
        _validate_key_id(primary_key_id)
        if not isinstance(provider_name, str) or not provider_name:
            raise KeysetError("keyset-unknown-key",
                              "provider_name must be a non-empty string")
        doc = {
            "format": KEYSET_FORMAT,
            "template": template_name,
            "keys": [{"key_id": primary_key_id,
                      "provider_name": provider_name,
                      "status": "enabled",
                      "created_utc": created_utc or _utcnow()}],
            "primary_key_id": primary_key_id,
            "ceremony": {"phase": "none", "new_key_id": None,
                         "attempts": 0},
            "audit_chain": [],
        }
        ks = cls.__new__(cls)
        ks._pin_key = pin_key
        ks._doc = doc
        ks._audit("keyset-created",
                  {"key_id": primary_key_id,
                   "provider_name": provider_name})
        ks._repin_doc()
        return ks

    # -- parsing (fail-closed) -----------------------------------------

    @classmethod
    def _parse(cls, doc, pin_key):
        if not isinstance(doc, dict):
            raise KeysetError("keyset-unknown-key",
                              "keyset document must be a mapping")
        if doc.get("format") != KEYSET_FORMAT:
            raise KeysetError("keyset-unknown-key",
                              "unsupported keyset format %r (expected %r)"
                              % (doc.get("format"), KEYSET_FORMAT))
        template_name = doc.get("template")
        if template_name not in TEMPLATES:
            raise KeysetError("keyset-bad-template",
                              "keyset declares unknown template %r"
                              % (template_name,))
        keys = doc.get("keys")
        if not isinstance(keys, list) or not keys:
            raise KeysetError("keyset-unknown-key",
                              "keyset must list at least one key")
        seen = set()
        for entry in keys:
            if not isinstance(entry, dict):
                raise KeysetError("keyset-unknown-key",
                                  "key entry must be a mapping")
            kid = entry.get("key_id")
            _validate_key_id(kid)
            if kid in seen:
                raise KeysetError("keyset-duplicate-key",
                                  "duplicate key id %r" % (kid,))
            seen.add(kid)
            if entry.get("status") not in STATUSES:
                raise KeysetError("keyset-unknown-key",
                                  "key %r has unknown status %r"
                                  % (kid, entry.get("status")))
            if not isinstance(entry.get("provider_name"), str):
                raise KeysetError("keyset-unknown-key",
                                  "key %r needs a provider_name" % (kid,))
        primary = doc.get("primary_key_id")
        if primary not in seen:
            raise KeysetError("keyset-unknown-key",
                              "primary_key_id %r not in keys" % (primary,))
        # The primary may be disabled or destroyed: both are real
        # post-incident states (emergency mint-stop; terminal). The
        # document stays parseable; operations refuse with coded
        # refusals (wrap under a non-enabled primary is refused).
        # The ceremony shape is validated wholesale before the pin
        # is recomputed, so a malformed ceremony refuses coded here
        # instead of crashing the pin builder with a raw KeyError
        # (F327).
        _validate_ceremony(doc.get("ceremony"))
        chain = doc.get("audit_chain")
        if not isinstance(chain, list):
            raise KeysetError("keyset-unknown-key",
                              "audit_chain must be a list")
        want = cls._mac_for(doc, pin_key)
        got = doc.get("keyset_digest")
        if not isinstance(got, str) or not hmac.compare_digest(got, want):
            raise KeysetError("keyset-verify-failed",
                              "keyset_digest mismatch: the document was "
                              "edited out of band (or the wrong pin key "
                              "was used)")
        return doc

    @classmethod
    def from_dict(cls, doc, pin_key=None):
        """Parse a persisted document. Fail-closed on any structural
        problem or pin mismatch. ``pin_key`` is REQUIRED: the
        configuration pin is a keyed MAC and cannot be verified without
        the deployment-held key (F329). (The inner audit chain is
        verified separately via :meth:`verify_chain`; every mutating
        operation checks it first.)"""
        pin_key = _validate_pin_key(pin_key)
        return cls(json.loads(json.dumps(doc)), pin_key)

    @staticmethod
    def _mac_for(doc, pin_key):
        """The configuration pin: HMAC-SHA256 over the canonical config,
        keyed by the deployment-held pin key.

        Covers keys/statuses/primary/template/ceremony/audit-head;
        wall-clock ``at`` fields are excluded by construction (see module
        docstring). Unlike the pre-F329 unkeyed digest, the MAC cannot be
        recomputed by a writer holding only the document -- out-of-band
        edits are detectable by any holder of the pin key."""
        keys = [{"key_id": e["key_id"],
                 "provider_name": e["provider_name"],
                 "status": e["status"]} for e in doc["keys"]]
        head = (doc["audit_chain"][-1]["digest"]
                if doc["audit_chain"] else _GENESIS_DIGEST)
        body = _canonical({"format": doc["format"],
                           "template": doc["template"],
                           "keys": keys,
                           "primary_key_id": doc["primary_key_id"],
                           "ceremony": {"phase": doc["ceremony"]["phase"],
                                        "new_key_id": doc["ceremony"]
                                        ["new_key_id"]},
                           "audit_head": head})
        return hmac.new(pin_key, _PIN_LABEL + body,
                        hashlib.sha256).hexdigest()

    @classmethod
    def _repin(cls, doc, pin_key=None):
        """Recompute ``keyset_digest`` for an honestly edited document.

        ``pin_key`` is REQUIRED: recomputing the pin without the
        deployment-held key refuses LOUD and coded
        (``keyset-pin-key-invalid``). This is the F329 fix -- the public
        helper can no longer serve a forger holding only the document.
        The ceremony shape is validated first so a malformed document
        refuses with a coded ``keyset-*`` KeysetError (F327) instead of
        crashing the pin builder with a raw KeyError.
        Never called on untrusted input."""
        pin_key = _validate_pin_key(pin_key)
        doc = json.loads(json.dumps(doc))
        _validate_ceremony(doc.get("ceremony"))
        doc["keyset_digest"] = cls._mac_for(doc, pin_key)
        return doc

    def _repin_doc(self):
        self._doc["keyset_digest"] = self._mac_for(self._doc,
                                                   self._pin_key)

    def to_dict(self):
        return json.loads(json.dumps(self._doc))

    # -- audit chain ----------------------------------------------------

    @staticmethod
    def _event_digest(prev_digest, event):
        body = {k: v for k, v in event.items()
                if k not in ("digest", "at")}
        return _digest_of({"prev": prev_digest, "event": body})

    def _audit(self, event, fields):
        prev = (self._doc["audit_chain"][-1]["digest"]
                if self._doc["audit_chain"] else _GENESIS_DIGEST)
        record = {"event": event, "at": _utcnow(),
                  "prev_digest": prev}
        record.update(fields)
        record["digest"] = self._event_digest(prev, record)
        self._doc["audit_chain"].append(record)

    def audit_events(self):
        return [dict(e) for e in self._doc["audit_chain"]]

    def verify_chain(self):
        """Recompute the genesis-chained audit digests. False on any
        break -- including a tampered event that was re-pinned at the
        document level."""
        prev = _GENESIS_DIGEST
        for record in self._doc["audit_chain"]:
            if record.get("prev_digest") != prev:
                return False
            if record.get("digest") != self._event_digest(prev, record):
                return False
            prev = record["digest"]
        return True

    def _require_intact(self):
        if not self.verify_chain():
            raise KeysetError("keyset-verify-failed",
                              "audit chain is broken: refusing to mutate "
                              "a tampered keyset")

    # -- read-only views -------------------------------------------------

    def template(self):
        return TEMPLATES[self._doc["template"]]

    def primary_key_id(self):
        return self._doc["primary_key_id"]

    def key_status(self, key_id):
        _validate_key_id(key_id)
        for entry in self._doc["keys"]:
            if entry["key_id"] == key_id:
                return entry["status"]
        raise KeysetError("keyset-unknown-key",
                          "unknown key id %r" % (key_id,))

    def ceremony_state(self):
        return dict(self._doc["ceremony"])

    def describe(self):
        """Material-free projection (the KeysetInfo analogue): ids,
        statuses, primary, template, ceremony phase, digest. Zero key
        bytes by construction."""
        return {
            "format": self._doc["format"],
            "template": self._doc["template"],
            "primary_key_id": self._doc["primary_key_id"],
            "keys": [{"key_id": e["key_id"],
                      "provider_name": e["provider_name"],
                      "status": e["status"],
                      "created_utc": e["created_utc"]}
                     for e in self._doc["keys"]],
            "ceremony_phase": self._doc["ceremony"]["phase"],
            "keyset_digest": self._doc["keyset_digest"],
        }

    # -- lifecycle -------------------------------------------------------

    def _entry(self, key_id):
        for entry in self._doc["keys"]:
            if entry["key_id"] == key_id:
                return entry
        raise KeysetError("keyset-unknown-key",
                          "unknown key id %r" % (key_id,))

    def add_key(self, key_id, provider_name, *, created_utc=None):
        """Declare a new enabled (non-primary) key. The key must already
        exist at the provider; use :meth:`verify_key` to corroborate."""
        self._require_intact()
        _validate_key_id(key_id)
        if any(e["key_id"] == key_id for e in self._doc["keys"]):
            raise KeysetError("keyset-duplicate-key",
                              "key id %r already declared" % (key_id,))
        if not isinstance(provider_name, str) or not provider_name:
            raise KeysetError("keyset-unknown-key",
                              "provider_name must be a non-empty string")
        self._doc["keys"].append({"key_id": key_id,
                                  "provider_name": provider_name,
                                  "status": "enabled",
                                  "created_utc": created_utc or _utcnow()})
        self._audit("key-added", {"key_id": key_id,
                                  "provider_name": provider_name})
        self._repin_doc()

    def verify_key(self, provider, key_id):
        """Corroborate a declared key against the provider's describe.
        Raises :class:`KeysetError` (coded) or :class:`KmsError`.
        A destroyed key refuses (terminal); a disabled key is
        corroborated -- verification is not a new encrypt."""
        self._require_intact()
        entry = self._entry(key_id)  # unknown -> keyset-unknown-key
        if entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "key %r is destroyed: terminal, verify "
                              "refused" % (key_id,))
        desc = provider.describe_key(key_id)  # may raise KmsError
        self._audit("key-verified",
                    {"key_id": key_id,
                     "provider_status": desc.status})
        self._repin_doc()
        return desc

    def _transition(self, key_id, to_status, event, reason):
        self._require_intact()
        entry = self._entry(key_id)
        from_status = entry["status"]
        if from_status == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "key %r is destroyed: terminal, no "
                              "transitions allowed" % (key_id,))
        if from_status == to_status:
            raise KeysetError("keyset-key-disabled",
                              "key %r already %s" % (key_id, to_status))
        entry["status"] = to_status
        self._audit(event, {"key_id": key_id,
                            "from_status": from_status,
                            "to_status": to_status,
                            "reason": reason})
        self._repin_doc()

    def disable_key(self, key_id, *, reason):
        """enabled -> disabled: no new wraps; old records still verify.

        The primary MAY be disabled: that is the emergency mint-stop
        (suspected compromise). Wraps then refuse with a coded refusal
        until the key is re-enabled or a rotation promotes a successor.
        Refusing the transition itself would delay incident response."""
        self._transition(key_id, "disabled", "key-disabled", reason)

    def enable_key(self, key_id, *, reason):
        """disabled -> enabled: a governed re-admission, audited."""
        self._transition(key_id, "enabled", "key-enabled", reason)

    def destroy_key(self, key_id, *, reason, new_primary=None):
        """enabled/disabled -> destroyed: terminal. Every operation --
        wrap, unwrap, describe-by-contract -- refuses afterwards. The
        primary cannot be destroyed without designating an enabled
        successor in the same call (atomic)."""
        self._require_intact()
        entry = self._entry(key_id)
        if entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "key %r already destroyed" % (key_id,))
        if key_id == self._doc["primary_key_id"]:
            if new_primary is None:
                raise KeysetError("keyset-primary-not-enabled",
                                  "refusing to destroy the primary %r "
                                  "without a designated successor "
                                  "(pass new_primary=...)" % (key_id,))
            if new_primary == key_id:
                raise KeysetError("keyset-primary-not-enabled",
                                  "successor %r is the key being destroyed: "
                                  "the successor must differ from the key"
                                  % (new_primary,))
            succ = self._entry(new_primary)
            if succ["status"] != "enabled":
                raise KeysetError("keyset-primary-not-enabled",
                                  "successor %r has status %r (must be "
                                  "enabled)" % (new_primary,
                                                succ["status"]))
            self._doc["primary_key_id"] = new_primary
            self._audit("primary-reassigned",
                        {"from_key_id": key_id, "to_key_id": new_primary,
                         "reason": reason})
        entry["status"] = "destroyed"
        self._audit("key-destroyed", {"key_id": key_id, "reason": reason})
        self._repin_doc()

    # -- rotation ceremony -----------------------------------------------

    def begin_rotation(self, new_key_id, *, provider_name):
        """Add-key: declare the successor as enabled/non-primary and
        enter the rolling-out phase. The old primary keeps minting
        wraps until promote."""
        self._require_intact()
        if self._doc["ceremony"]["phase"] not in ("none", "complete"):
            raise KeysetError("keyset-ceremony-incomplete",
                              "a rotation ceremony is already %s"
                              % (self._doc["ceremony"]["phase"],))
        _validate_key_id(new_key_id)
        if not isinstance(provider_name, str) or not provider_name:
            raise KeysetError("keyset-unknown-key",
                              "provider_name must be a non-empty string")
        if any(e["key_id"] == new_key_id for e in self._doc["keys"]):
            raise KeysetError("keyset-duplicate-key",
                              "key id %r already declared" % (new_key_id,))
        self._doc["keys"].append({"key_id": new_key_id,
                                  "provider_name": provider_name,
                                  "status": "enabled",
                                  "created_utc": _utcnow()})
        self._doc["ceremony"] = {"phase": "rolling-out",
                                 "new_key_id": new_key_id, "attempts": 0}
        self._audit("rotation-begun", {"new_key_id": new_key_id,
                                       "provider_name": provider_name})
        self._repin_doc()

    def roll_out(self, provider, *, attempts=3, test_bytes=None):
        """Roll-out: bounded verification window. Wraps a fresh test
        blob under the new key and unwraps it, up to ``attempts`` times.
        Success -> verified; exhaustion -> roll-out-failed (loud)."""
        self._require_intact()
        ceremony = self._doc["ceremony"]
        if ceremony["phase"] != "rolling-out":
            raise KeysetError("keyset-ceremony-incomplete",
                              "roll_out requires phase rolling-out, "
                              "ceremony is %s" % (ceremony["phase"],))
        new_key_id = ceremony["new_key_id"]
        entry = self._entry(new_key_id)
        if entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "rotation candidate %r is destroyed"
                              % (new_key_id,))
        if entry["status"] != "enabled":
            raise KeysetError("keyset-key-disabled",
                              "rotation candidate %r has status %r"
                              % (new_key_id, entry["status"]))
        test_bytes = (bytes(test_bytes) if test_bytes is not None
                      else secrets.token_bytes(32))
        last_error = None
        for _ in range(max(1, attempts)):
            ceremony["attempts"] += 1
            try:
                blob = provider.wrap_data_key(new_key_id, test_bytes)
                back = provider.unwrap_data_key(new_key_id, blob)
                if back != bytes(test_bytes):
                    raise KmsError("round-trip mismatch")
            except KmsError as e:
                last_error = e
                continue
            ceremony["phase"] = "verified"
            self._audit("roll-out-verified",
                        {"new_key_id": new_key_id,
                         "attempts": ceremony["attempts"]})
            self._repin_doc()
            return
        ceremony["phase"] = "roll-out-failed"
        self._audit("roll-out-failed",
                    {"new_key_id": new_key_id,
                     "attempts": ceremony["attempts"],
                     "last_error": str(last_error)})
        self._repin_doc()
        raise KeysetError("keyset-verify-failed",
                          "roll-out verification failed for %r after %d "
                          "attempt(s): %s"
                          % (new_key_id, ceremony["attempts"], last_error))

    def promote(self, *, reason):
        """Promote: atomically switch the primary to the verified
        successor and demote the old primary to disabled. The whole
        switch commits at one point -- there is no observable state
        with two primaries or none."""
        self._require_intact()
        ceremony = self._doc["ceremony"]
        if ceremony["phase"] != "verified":
            raise KeysetError("keyset-ceremony-incomplete",
                              "promote requires phase verified, ceremony "
                              "is %s" % (ceremony["phase"],))
        new_key_id = ceremony["new_key_id"]
        new_entry = self._entry(new_key_id)
        if new_entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "rotation candidate %r is destroyed"
                              % (new_key_id,))
        if new_entry["status"] != "enabled":
            raise KeysetError("keyset-key-disabled",
                              "rotation candidate %r has status %r"
                              % (new_key_id, new_entry["status"]))
        old_primary = self._doc["primary_key_id"]
        # Atomic commit point: build the new state, then swap.
        # Demotion never resurrects: a destroyed old primary stays
        # destroyed; otherwise it winds down to disabled (auditable,
        # never deleted).
        # F328: never demote the successor into a mint-stop. When the
        # old primary was destroyed mid-ceremony naming the in-flight
        # successor (destroy_key reassigns primary_key_id), old_primary
        # IS new_key_id; demoting it would "complete" the ceremony with
        # a disabled primary. Skipping the wind-down here is exact: the
        # successor stays enabled and the ceremony completes honestly.
        old_entry = self._entry(old_primary)
        if old_primary != new_key_id and old_entry["status"] != "destroyed":
            old_entry["status"] = "disabled"
        self._doc["primary_key_id"] = new_key_id
        ceremony["phase"] = "complete"
        self._audit("rotation-promoted",
                    {"from_key_id": old_primary, "to_key_id": new_key_id,
                     "reason": reason})
        self._repin_doc()

    def abandon_ceremony(self, *, reason):
        """Recover from a half-finished ceremony: the successor is
        disabled (never deleted -- the declaration stays auditable),
        the old primary is untouched, the phase returns to none."""
        self._require_intact()
        ceremony = self._doc["ceremony"]
        if ceremony["phase"] not in ("rolling-out", "roll-out-failed",
                                     "verified"):
            raise KeysetError("keyset-ceremony-incomplete",
                              "no ceremony in progress to abandon "
                              "(phase %s)" % (ceremony["phase"],))
        new_key_id = ceremony["new_key_id"]
        if new_key_id is not None:
            entry = self._entry(new_key_id)
            # Abandon never resurrects: a destroyed candidate stays
            # destroyed; otherwise the declaration is wound down to
            # disabled (it stays auditable, never deleted).
            if entry["status"] != "destroyed":
                entry["status"] = "disabled"
        self._doc["ceremony"] = {"phase": "none", "new_key_id": None,
                                 "attempts": 0}
        self._audit("ceremony-abandoned", {"new_key_id": new_key_id,
                                           "reason": reason})
        self._repin_doc()

    # -- governed operations ----------------------------------------------

    def _corroborate(self, provider, key_id, entry):
        """Defense in depth: where the provider can express lifecycle,
        a disagreement with the keyset registry refuses LOUD."""
        posture = _provider_lifecycle(
            getattr(provider, "provider_name", ""))
        if posture != "full":
            return  # registry is the whole policy
        try:
            desc = provider.describe_key(key_id)
        except KmsError:
            return  # provider refuses: its own fail-closed stands
        if desc.status == "destroyed" and entry["status"] != "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "provider reports key %r destroyed while "
                              "the keyset declares %r: refusing"
                              % (key_id, entry["status"]))
        if desc.status == "disabled" and entry["status"] == "enabled":
            raise KeysetError("keyset-key-disabled",
                              "provider reports key %r disabled while "
                              "the keyset declares enabled: refusing"
                              % (key_id,))

    def wrap_data_key(self, provider, plaintext):
        """Mint a new wrap under the primary. The primary must be
        enabled in the keyset registry; DESTROYED/DISABLED primaries
        refuse LOUD with coded refusals."""
        self._require_intact()
        primary = self._doc["primary_key_id"]
        entry = self._entry(primary)
        self._corroborate(provider, primary, entry)
        if entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "primary %r is destroyed: no new wraps"
                              % (primary,))
        if entry["status"] != "enabled":
            raise KeysetError("keyset-key-disabled",
                              "primary %r has status %r: refusing new "
                              "wraps" % (primary, entry["status"]))
        return provider.wrap_data_key(primary, plaintext)

    def unwrap_data_key(self, provider, key_id, wrapped):
        """Verify an old record. Enabled and disabled keys are *permitted*
        to unwrap at the keyset layer (Tink's winding-down semantic);
        destroyed keys refuse LOUD; unknown ids refuse LOUD.

        Whether a disabled-key unwrap *succeeds* is the provider's
        posture, not the keyset's: an AWS-like provider refuses disabled
        keys outright (its fail-closed stands and its KmsError
        propagates), a Tink-like provider verifies. The keyset never
        masks a provider refusal and never invents key material."""
        self._require_intact()
        entry = self._entry(key_id)
        self._corroborate(provider, key_id, entry)
        if entry["status"] == "destroyed":
            raise KeysetError("keyset-key-destroyed",
                              "key %r is destroyed: refusing unwrap"
                              % (key_id,))
        return provider.unwrap_data_key(key_id, wrapped)

    def retemplate(self, new_template_name, *, reason):
        """Adopt a new key template version: governed and audited.
        The primitive binding changes only through this call."""
        self._require_intact()
        if new_template_name not in TEMPLATES:
            raise KeysetError("keyset-bad-template",
                              "unknown key template %r" % (new_template_name,))
        old = self._doc["template"]
        if old == new_template_name:
            raise KeysetError("keyset-bad-template",
                              "keyset already under template %r" % (old,))
        self._doc["template"] = new_template_name
        self._audit("retemplated", {"from_template": old,
                                    "to_template": new_template_name,
                                    "reason": reason})
        self._repin_doc()


# ---------------------------------------------------------------------------
# Provider contract verification
# ---------------------------------------------------------------------------

def verify_provider_contracts(provider, key_ids):
    """Exercise the provider contract a keyset depends on.

    Checks, per key id: wrap/unwrap round-trip, key-id binding (a blob
    wrapped under key A must not unwrap under key B), disabled refuses
    wrap, destroyed refuses everything including describe, and
    describe_key returns a well-formed KeyDescription. Returns
    ``{"ok": bool, "checks": [...]}`` -- never raises for contract
    failures (a failing check is data, not an exception).
    """
    checks = []

    def _check(name, ok, note=""):
        checks.append({"check": name, "ok": bool(ok), "note": note})
        return ok

    from .kms import KmsProvider, KeyDescription
    if not isinstance(provider, KmsProvider):
        _check("is-kms-provider", False, "not a KmsProvider instance")
        return {"ok": False, "checks": checks}
    _check("is-kms-provider", True)
    key_ids = list(key_ids)
    if not key_ids:
        _check("key-ids-present", False, "no key ids supplied")
        return {"ok": False, "checks": checks}

    kid = key_ids[0]
    try:
        blob = provider.wrap_data_key(kid, b"contract-probe-32bytes-padded!!")
        back = provider.unwrap_data_key(kid, blob)
        _check("round-trip", back == b"contract-probe-32bytes-padded!!")
    except KmsError as e:
        _check("round-trip", False, "%s" % (e,))
        return {"ok": False, "checks": checks}

    if len(key_ids) > 1:
        try:
            provider.unwrap_data_key(key_ids[1], blob)
            _check("key-id-binding", False, "cross-key unwrap succeeded")
        except KmsError:
            _check("key-id-binding", True)
    else:
        _check("key-id-binding", True, "single key id: skipped")

    try:
        desc = provider.describe_key(kid)
        _check("describe-shape",
               isinstance(desc, KeyDescription)
               and desc.key_id == kid
               and desc.status in ("enabled", "disabled", "destroyed"),
               "status=%s" % (getattr(desc, "status", "?",)))
    except KmsError as e:
        _check("describe-shape", False, "%s" % (e,))

    # Lifecycle probes use the test-double controls when present; real
    # providers (Vault) cannot express them and are checked statically
    # by provider_contract_surface instead.
    #
    # Disabled-unwrap posture differs by provider family (Tink-like
    # providers verify under disabled keys; AWS-like providers refuse
    # all crypto on disabled keys). The contract is: the attempt must
    # either return the correct plaintext or fail closed with KmsError
    # -- never silent wrong data, never a masked refusal.
    if hasattr(provider, "disable_key") and hasattr(provider, "enable_key"):
        provider.disable_key(kid)
        try:
            provider.wrap_data_key(kid, b"contract-probe-32bytes-padded!!")
            _check("disabled-refuses-wrap", False,
                   "wrap under disabled key succeeded")
        except KmsError:
            _check("disabled-refuses-wrap", True)
        try:
            back2 = provider.unwrap_data_key(kid, blob)
            _check("disabled-unwrap-posture",
                   back2 == b"contract-probe-32bytes-padded!!",
                   "permitted (Tink-like)")
        except KmsError:
            _check("disabled-unwrap-posture", True,
                   "refused with KmsError (AWS-like): fail-closed stands")
        provider.enable_key(kid)
    else:
        _check("disabled-refuses-wrap", True,
               "provider has no disable control: lifecycle held above")
        _check("disabled-unwrap-posture", True,
               "provider has no disable control: lifecycle held above")

    if hasattr(provider, "destroy_key"):
        provider.destroy_key(kid)
        refused = True
        for op in ("wrap", "unwrap", "describe"):
            try:
                if op == "wrap":
                    provider.wrap_data_key(kid, b"x" * 32)
                elif op == "unwrap":
                    provider.unwrap_data_key(kid, blob)
                else:
                    provider.describe_key(kid)
                refused = False
            except KmsError:
                pass
        _check("destroyed-refuses-all", refused)
    else:
        _check("destroyed-refuses-all", True,
               "provider has no destroy control: lifecycle held above")

    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "checks": checks}


def provider_contract_surface(provider_cls):
    """Static surface check for providers that need no live server.

    Verifies the class exposes the envelope operations the keyset
    depends on (wrap/unwrap/describe with the impersonator-binding
    contract) without instantiating it or touching the network, and
    reports the provider's lifecycle expressiveness from the declared
    governance table (see :data:`_PROVIDER_LIFECYCLE`). The Vault
    transit adapter satisfies this surface without modification: its
    describe reports only "enabled", which is exactly why the keyset
    holds lifecycle above the provider.
    """
    checks = []

    def _check(name, ok, note=""):
        checks.append({"check": name, "ok": bool(ok), "note": note})
        return ok

    from .kms import KmsProvider
    try:
        is_sub = issubclass(provider_cls, KmsProvider)
    except TypeError:
        is_sub = False
    _check("kms-provider-subclass", is_sub)
    if not is_sub:
        return {"ok": False, "checks": checks}
    for op in ("wrap_data_key", "unwrap_data_key", "describe_key"):
        _check("exposes-" + op,
               callable(getattr(provider_cls, op, None))
               and getattr(provider_cls, op) is not getattr(KmsProvider, op),
               "must override the abstract op")
    name = getattr(provider_cls, "provider_name", "?")
    posture = _provider_lifecycle(name if isinstance(name, str) else "")
    _check("lifecycle-posture-declared", True, posture)
    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "checks": checks,
            "provider_name": name if isinstance(name, str) else None,
            "lifecycle": posture}
