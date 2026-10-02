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
import json
import re
import secrets

from .kms import KmsError, _utcnow

#: Document format tag. Bumped only for breaking schema changes.
KEYSET_FORMAT = "sasanam-kms-keyset/v1"

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
    (keys/statuses/primary/template/ceremony/audit-head) so any
    out-of-band edit is detectable.
    """

    def __init__(self, doc):
        self._doc = self._parse(doc)

    # -- construction -------------------------------------------------

    @classmethod
    def new(cls, *, template_name, primary_key_id, provider_name,
            created_utc=None):
        """Create a keyset with a single enabled primary key."""
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
        ks._doc = doc
        ks._audit("keyset-created",
                  {"key_id": primary_key_id,
                   "provider_name": provider_name})
        ks._repin_doc()
        return ks

    # -- parsing (fail-closed) -----------------------------------------

    @classmethod
    def _parse(cls, doc):
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
        ceremony = doc.get("ceremony") or {}
        if ceremony.get("phase") not in CEREMONY_PHASES:
            raise KeysetError("keyset-ceremony-incomplete",
                              "unknown ceremony phase %r"
                              % (ceremony.get("phase"),))
        if ceremony.get("phase") in ("rolling-out", "roll-out-failed",
                                     "verified"):
            # An in-progress ceremony must name its successor; a phase
            # without a new_key_id is a malformed document, refused
            # coded (never a raw KeyError downstream).
            if not isinstance(ceremony.get("new_key_id"), str) or \
                    not ceremony.get("new_key_id"):
                raise KeysetError("keyset-ceremony-incomplete",
                                  "ceremony phase %r names no successor"
                                  % (ceremony.get("phase"),))
        chain = doc.get("audit_chain")
        if not isinstance(chain, list):
            raise KeysetError("keyset-unknown-key",
                              "audit_chain must be a list")
        want = cls._digest_for(doc)
        if doc.get("keyset_digest") != want:
            raise KeysetError("keyset-verify-failed",
                              "keyset_digest mismatch: the document was "
                              "edited out of band")
        return doc

    @classmethod
    def from_dict(cls, doc):
        """Parse a persisted document. Fail-closed on any structural
        problem or digest mismatch. (The inner audit chain is verified
        separately via :meth:`verify_chain`; every mutating operation
        checks it first.)"""
        return cls(json.loads(json.dumps(doc)))

    @staticmethod
    def _digest_for(doc):
        """The configuration pin. Covers keys/statuses/primary/
        template/ceremony/audit-head; wall-clock ``at`` fields are
        excluded by construction (see module docstring)."""
        keys = [{"key_id": e["key_id"],
                 "provider_name": e["provider_name"],
                 "status": e["status"]} for e in doc["keys"]]
        head = (doc["audit_chain"][-1]["digest"]
                if doc["audit_chain"] else _GENESIS_DIGEST)
        return _digest_of({"format": doc["format"],
                           "template": doc["template"],
                           "keys": keys,
                           "primary_key_id": doc["primary_key_id"],
                           "ceremony": {"phase": doc["ceremony"]["phase"],
                                        "new_key_id": doc["ceremony"]
                                        ["new_key_id"]},
                           "audit_head": head})

    @classmethod
    def _repin(cls, doc):
        """Recompute ``keyset_digest`` for an honestly edited document.
        Used internally and by tests constructing fixtures; never
        called on untrusted input."""
        doc = json.loads(json.dumps(doc))
        doc["keyset_digest"] = cls._digest_for(doc)
        return doc

    def _repin_doc(self):
        self._doc["keyset_digest"] = self._digest_for(self._doc)

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
        old_entry = self._entry(old_primary)
        if old_entry["status"] != "destroyed":
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
