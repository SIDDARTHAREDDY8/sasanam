"""Deploy-time trust configuration for bundle loading (wave-202 lane C).

Design input: inspektor-gadget / bpfd (Apache-2.0, verified 2026-09-29;
see ``teams/wave201-prospect/``) -- ADAPT the *distribution pattern*,
not eBPF: trust configuration attached at deploy time, so bundle
loading refuses to proceed without an explicit, signed declaration of
which keys are authoritative for which bundle class. The product gap
this closes: skill/pack bundles carry signatures, but no
deployment-level policy says *which* keys may sign *which* bundle
class -- any holder of the pack-signing keyset could mint any class,
and unsigned loading had no explicit policy at all.

What this module provides, stdlib-only, re-implemented (not vendored):

* A **signed trust-config document**: a rule-pack document (reusing
  :mod:`gov.rule_pack`'s threshold-signature, expiry, and
  purpose/format domain-separation machinery -- NOT duplicated) with
  exactly one member, ``trust-config.json``, whose digest pins the
  config body. The config is signed by the deployment-root keyset
  (purpose ``sasanam-deploy-trust-signing/v1``), held out-of-band.
  The trust config is the deployment's *policy attachment*: per
  bundle class it names trust roots (key id + version + public key),
  the load policy (``signed-only`` | ``loud-opt-out``), an optional
  grace window for root rotation, and a per-class signer threshold.
  Unknown classes are denied (default-deny).
* :class:`TrustConfigRegistry`: the activation point. Fail-closed
  activation with continuity (a bad candidate never displaces the
  active config), monotonic config-version floor (rollback refused),
  expiry, and a **supersede chain**: a new config must name the
  version it replaces, and when trust roots *change* it must carry a
  **handoff** -- signatures over the new config digest by the
  *previous* trust roots (the old roots authorize the new roots).
  Revoked key ids are refused loudly even if they previously
  verified.
* :class:`TrustedPackLoader`: a :class:`gov.pack_loader.PackLoader`
  bound to a registry and a bundle class. ``present()`` refuses
  (fail-closed) when no trust config is active, when the class is
  unknown, when a signing key is revoked, or when no signing key is
  a trust root for the class (grace roots accepted inside their
  window only). Unsigned packs go through the **loud opt-out**
  ceremony (:class:`UnsignedOptOut`): two distinct operator acks plus
  a hash-chained audit record in :class:`UnsignedOptOutLog` -- there
  is no silent unsigned path.
* :func:`check_manifest_trust`: the same per-class trust-root check
  for skill-manifest signers, for callers on the manifest path.

Trust model: the deployment-root keyset is the long-lived
authority; it is held out-of-band (no key discovery, ever). An
attacker who can mint trust configs already holds the deployment
root. Operator identities in the opt-out ceremony are
caller-supplied strings -- binding them to the agent-identity story
is follow-on work (honest residual, same as the rotation-policy
lane).

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover -- POSIX-only deployment
    fcntl = None

from . import ed25519 as _ed
from . import rule_pack as _rp
from .keyset import Keyset
from .pack_loader import PackLoader, PackActivationError

__all__ = [
    "TRUST_CONFIG_FORMAT",
    "KEYSET_PURPOSE_DEPLOY_TRUST",
    "TRUST_CONFIG_MEMBER",
    "POLICY_SIGNED_ONLY",
    "POLICY_LOUD_OPT_OUT",
    "TRUST_CLASS_CAPABILITY_RULES",
    "TRUST_CLASS_PERM_MODEL",
    "TrustConfigError",
    "canonical_trust_config_json",
    "make_trust_root",
    "make_class_config",
    "make_config_body",
    "validate_trust_config_body",
    "mint_trust_config",
    "sign_handoff",
    "body_digest_for_handoff",
    "verify_handoff",
    "TrustConfigRegistry",
    "UnsignedOptOutLog",
    "UnsignedOptOut",
    "UnsignedActivePack",
    "TrustedPackLoader",
    "check_manifest_trust",
]

#: Format tag of the trust-config document (exact match at verify).
TRUST_CONFIG_FORMAT = "sasanam-deploy-trust-config/v1"

#: Keyset purpose that may sign trust configs. A pack-signing keyset
#: can never mint a trust config and vice versa.
KEYSET_PURPOSE_DEPLOY_TRUST = "sasanam-deploy-trust-signing/v1"

#: The single member id a trust-config pack document may carry.
TRUST_CONFIG_MEMBER = "trust-config.json"

#: Load policies.
POLICY_SIGNED_ONLY = "signed-only"
POLICY_LOUD_OPT_OUT = "loud-opt-out"
_POLICIES = frozenset({POLICY_SIGNED_ONLY, POLICY_LOUD_OPT_OUT})

#: Well-known bundle classes. Registries accept any class name; these
#: are the product's current pack classes.
TRUST_CLASS_CAPABILITY_RULES = "capability_rules"
TRUST_CLASS_PERM_MODEL = "perm_model"

_CLASS_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class TrustConfigError(Exception):
    """Fail-closed trust-configuration violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(TrustConfigError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Canonical JSON + strict body validation
# ---------------------------------------------------------------------------

def canonical_trust_config_json(body):
    """Canonical bytes of a trust-config body (sorted keys, no
    whitespace). The digest pinned in the pack document is over
    exactly these bytes."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_iso(value, what):
    if not isinstance(value, str):
        raise TrustConfigError("config-body-malformed",
                               "%s must be an ISO-8601 string" % (what,))
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise TrustConfigError("config-body-malformed",
                               "%s is not ISO-8601: %r" % (what, value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _require_pubkey_hex(value, what):
    if not isinstance(value, str) or not _SHA256_HEX_RE.match(value):
        raise TrustConfigError(
            "config-body-malformed",
            "%s must be 64 lowercase hex (ed25519 public key)" % (what,))


def _validate_trust_root(root, where):
    if not isinstance(root, dict):
        raise TrustConfigError("config-body-malformed",
                               "%s must be a mapping" % (where,))
    if set(root) != {"kid", "key_version", "public_key_hex"}:
        raise TrustConfigError(
            "config-body-malformed",
            "%s carries unknown or missing fields" % (where,))
    if not isinstance(root["kid"], str) or not root["kid"]:
        raise TrustConfigError("config-body-malformed",
                               "%s.kid must be a non-empty string" % (where,))
    kv = root["key_version"]
    if isinstance(kv, bool) or not isinstance(kv, int) or kv < 1:
        raise TrustConfigError("config-body-malformed",
                               "%s.key_version must be an int >= 1"
                               % (where,))
    _require_pubkey_hex(root["public_key_hex"], where + ".public_key_hex")


def _validate_class_config(name, cfg):
    where = "classes[%r]" % (name,)
    if not isinstance(cfg, dict):
        raise TrustConfigError("config-body-malformed",
                               "%s must be a mapping" % (where,))
    allowed = {"policy", "trust_roots", "grace_roots", "grace_until",
               "threshold"}
    if set(cfg) - allowed:
        raise TrustConfigError(
            "config-body-malformed",
            "%s carries unknown fields: %s"
            % (where, sorted(set(cfg) - allowed)))
    policy = cfg.get("policy")
    if policy not in _POLICIES:
        raise TrustConfigError(
            "config-body-malformed",
            "%s.policy must be one of %s"
            % (where, sorted(_POLICIES)))
    roots = cfg.get("trust_roots")
    if not isinstance(roots, list) or not roots:
        raise TrustConfigError("config-body-malformed",
                               "%s.trust_roots must be a non-empty list"
                               % (where,))
    for i, root in enumerate(roots):
        _validate_trust_root(root, "%s.trust_roots[%d]" % (where, i))
    kids = [r["kid"] for r in roots]
    if len(set(kids)) != len(kids):
        raise TrustConfigError("config-body-malformed",
                               "%s.trust_roots has duplicate kids"
                               % (where,))
    grace = cfg.get("grace_roots", [])
    if not isinstance(grace, list):
        raise TrustConfigError("config-body-malformed",
                               "%s.grace_roots must be a list" % (where,))
    for i, root in enumerate(grace):
        _validate_trust_root(root, "%s.grace_roots[%d]" % (where, i))
    grace_until = cfg.get("grace_until")
    if grace:
        if grace_until is None:
            raise TrustConfigError(
                "config-body-malformed",
                "%s.grace_until is required with grace_roots" % (where,))
        _parse_iso(grace_until, where + ".grace_until")
    elif grace_until is not None:
        raise TrustConfigError(
            "config-body-malformed",
            "%s.grace_until without grace_roots" % (where,))
    threshold = cfg.get("threshold", 1)
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(roots)):
        raise TrustConfigError(
            "config-body-malformed",
            "%s.threshold must satisfy 1 <= k <= %d (trust roots)"
            % (where, len(roots)))


def _validate_handoff(handoff):
    if handoff is None:
        return
    if not isinstance(handoff, dict):
        raise TrustConfigError("config-body-malformed",
                               "handoff must be a mapping or null")
    if set(handoff) != {"prev_config_version", "new_body_digest",
                        "authorized_by", "signatures"}:
        raise TrustConfigError(
            "config-body-malformed",
            "handoff carries unknown or missing fields")
    pcv = handoff["prev_config_version"]
    if isinstance(pcv, bool) or not isinstance(pcv, int) or pcv < 1:
        raise TrustConfigError("config-body-malformed",
                               "handoff.prev_config_version must be "
                               "an int >= 1")
    _require_pubkey_hex(handoff["new_body_digest"],
                        "handoff.new_body_digest")
    auth = handoff["authorized_by"]
    if not isinstance(auth, list) or not auth or not all(
            isinstance(k, str) and k for k in auth):
        raise TrustConfigError("config-body-malformed",
                               "handoff.authorized_by must be a "
                               "non-empty list of key ids")
    if len(set(auth)) != len(auth):
        raise TrustConfigError("config-body-malformed",
                               "handoff.authorized_by has duplicates")
    sigs = handoff["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise TrustConfigError("config-body-malformed",
                               "handoff.signatures must be a non-empty "
                               "list")
    for i, entry in enumerate(sigs):
        where = "handoff.signatures[%d]" % (i,)
        if not isinstance(entry, dict) or set(entry) != {
                "kid", "key_version", "sig"}:
            raise TrustConfigError("config-body-malformed",
                                   "%s has bad shape" % (where,))
        if entry["kid"] not in auth:
            raise TrustConfigError(
                "config-body-malformed",
                "%s.kid is not in authorized_by" % (where,))
        kv = entry["key_version"]
        if isinstance(kv, bool) or not isinstance(kv, int) or kv < 1:
            raise TrustConfigError("config-body-malformed",
                                   "%s.key_version must be an int >= 1"
                                   % (where,))
        sig = entry["sig"]
        if (not isinstance(sig, str)
                or not re.fullmatch(r"[0-9a-f]{128}", sig)):
            raise TrustConfigError("config-body-malformed",
                                   "%s.sig must be 128 hex chars"
                                   % (where,))


def validate_trust_config_body(body):
    """Strictly validate a trust-config body mapping. Raises
    :class:`TrustConfigError` on any deviation -- unknown fields are
    refused, never ignored. Returns the body unchanged."""
    if not isinstance(body, dict):
        raise TrustConfigError("config-body-malformed",
                               "config body must be a mapping")
    allowed = {"document", "config_version", "issued_at", "expires_at",
               "classes", "revoked_kids", "supersedes", "handoff"}
    if set(body) - allowed:
        raise TrustConfigError(
            "config-body-malformed",
            "config body carries unknown fields: %s"
            % sorted(set(body) - allowed))
    if body.get("document") != TRUST_CONFIG_FORMAT:
        raise TrustConfigError("config-body-malformed",
                               "document must be %r"
                               % (TRUST_CONFIG_FORMAT,))
    version = body.get("config_version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise TrustConfigError("config-body-malformed",
                               "config_version must be an int >= 1")
    issued = _parse_iso(body.get("issued_at"), "issued_at")
    expires = _parse_iso(body.get("expires_at"), "expires_at")
    if expires <= issued:
        raise TrustConfigError("config-body-malformed",
                               "expires_at must be after issued_at")
    classes = body.get("classes")
    if not isinstance(classes, dict) or not classes:
        raise TrustConfigError("config-body-malformed",
                               "classes must be a non-empty mapping")
    for name, cfg in classes.items():
        if not isinstance(name, str) or not _CLASS_RE.match(name):
            raise TrustConfigError("config-body-malformed",
                                   "class name %r is not allowed" % (name,))
        _validate_class_config(name, cfg)
    revoked = body.get("revoked_kids", [])
    if not isinstance(revoked, list):
        raise TrustConfigError("config-body-malformed",
                               "revoked_kids must be a list")
    for i, entry in enumerate(revoked):
        where = "revoked_kids[%d]" % (i,)
        if not isinstance(entry, dict) or set(entry) != {"kid",
                                                         "reason"}:
            raise TrustConfigError("config-body-malformed",
                                   "%s has bad shape" % (where,))
        if not isinstance(entry["kid"], str) or not entry["kid"]:
            raise TrustConfigError("config-body-malformed",
                                   "%s.kid must be a non-empty string"
                                   % (where,))
        if not isinstance(entry["reason"], str) or not entry["reason"]:
            raise TrustConfigError("config-body-malformed",
                                   "%s.reason must be a non-empty string"
                                   % (where,))
    supersedes = body.get("supersedes")
    if supersedes is not None and (
            isinstance(supersedes, bool)
            or not isinstance(supersedes, int) or supersedes < 1):
        raise TrustConfigError("config-body-malformed",
                               "supersedes must be null or an int >= 1")
    if supersedes is not None and supersedes >= version:
        raise TrustConfigError("config-body-malformed",
                               "supersedes must name an older version")
    _validate_handoff(body.get("handoff"))
    return body


# ---------------------------------------------------------------------------
# Builders (operator-side)
# ---------------------------------------------------------------------------

def make_trust_root(kid, key_version, public_key_hex):
    """One trust-root entry. Validated strictly at build time."""
    root = {"kid": kid, "key_version": key_version,
            "public_key_hex": public_key_hex}
    _validate_trust_root(root, "trust_root")
    return root


def make_class_config(*, policy, trust_roots, threshold=1,
                      grace_roots=(), grace_until=None):
    """One bundle class's policy. ``policy`` is ``signed-only`` or
    ``loud-opt-out``; ``trust_roots`` is a non-empty list of
    :func:`make_trust_root` entries."""
    cfg = {"policy": policy, "trust_roots": list(trust_roots),
           "threshold": threshold}
    if grace_roots:
        cfg["grace_roots"] = list(grace_roots)
        cfg["grace_until"] = grace_until
    _validate_class_config("<new>", cfg)
    return cfg


def make_config_body(*, config_version, issued_at, expires_at,
                     classes, revoked_kids=(), supersedes=None,
                     handoff=None):
    """Assemble a trust-config body mapping, strictly validated."""
    body = {
        "document": TRUST_CONFIG_FORMAT,
        "config_version": config_version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "classes": dict(classes),
        "revoked_kids": [
            {"kid": r["kid"], "reason": r["reason"]} for r in revoked_kids
        ],
        "supersedes": supersedes,
        "handoff": handoff,
    }
    return validate_trust_config_body(body)


def mint_trust_config(keyset, signers, *, body, pack_version,
                      issued_at, expires_at, threshold):
    """Mint the signed trust-config document (operator-side).

    ``body`` is strictly validated first; ``pack_version`` must equal
    ``body["config_version"]`` (one version counter, not two). The
    document is a rule-pack with exactly one member,
    ``trust-config.json``, pinning the canonical body bytes --
    threshold signatures, expiry, and the deploy-trust signature
    domain come from :mod:`gov.rule_pack`.
    """
    if not isinstance(keyset, Keyset):
        raise TypeError("keyset must be a Keyset")
    validate_trust_config_body(body)
    if pack_version != body["config_version"]:
        raise TrustConfigError(
            "config-version-mismatch",
            "pack_version %r != body config_version %r"
            % (pack_version, body["config_version"]))
    body_bytes = canonical_trust_config_json(body).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    return _rp.mint_rule_pack(
        keyset, signers, rules={TRUST_CONFIG_MEMBER: digest},
        pack_version=pack_version, issued_at=issued_at,
        expires_at=expires_at, threshold=threshold,
        purpose=KEYSET_PURPOSE_DEPLOY_TRUST,
        format_tag=TRUST_CONFIG_FORMAT)


# ---------------------------------------------------------------------------
# Handoff ceremony: the old trust roots authorize the new ones
# ---------------------------------------------------------------------------

def _handoff_body(prev_config_version, new_body_digest):
    return canonical_trust_config_json({
        "handoff": True,
        "prev_config_version": prev_config_version,
        "new_body_digest": new_body_digest,
    }).encode("utf-8")


def body_digest_for_handoff(body):
    """The digest a handoff authorizes: sha256 over the canonical body
    with the ``handoff`` field nulled. The handoff must be computed
    over the body *before* it is attached -- otherwise the signature
    could never verify (the signature would have to cover itself).
    :func:`sign_handoff`'s ``new_body_digest`` is this digest."""
    stripped = dict(body)
    stripped["handoff"] = None
    return hashlib.sha256(
        canonical_trust_config_json(stripped).encode("utf-8")).hexdigest()


def sign_handoff(signer, *, prev_config_version, new_body_digest):
    """Sign a root-handoff statement with an OLD trust-root key.

    ``signer`` is a keyset signer for the previous trust root
    (``.key_id``, ``.key_version``, ``.sign``). ``new_body_digest``
    is :func:`body_digest_for_handoff` of the new config body (the
    digest with the handoff field nulled -- the handoff cannot cover
    itself). Returns the handoff mapping to embed in the new config
    body.
    """
    if not _SHA256_HEX_RE.match(new_body_digest or ""):
        raise TrustConfigError("bad-handoff",
                               "new_body_digest must be 64 hex chars")
    if (isinstance(prev_config_version, bool)
            or not isinstance(prev_config_version, int)
            or prev_config_version < 1):
        raise TrustConfigError("bad-handoff",
                               "prev_config_version must be an int >= 1")
    body = _handoff_body(prev_config_version, new_body_digest)
    return {
        "prev_config_version": prev_config_version,
        "new_body_digest": new_body_digest,
        "authorized_by": [signer.key_id],
        "signatures": [{
            "kid": signer.key_id,
            "key_version": signer.key_version,
            "sig": signer.sign(body).hex(),
        }],
    }


def verify_handoff(handoff, prev_roots, new_body_digest):
    """Verify a handoff against the PREVIOUS config's trust roots.

    ``prev_roots``: iterable of validated trust-root entries
    (``kid`` -> ``public_key_hex``). Returns the list of distinct
    authorizing kids. Raises :class:`TrustConfigError`
    (``handoff-invalid``) on any failure -- a bad handoff never
    authorizes a root change.
    """
    _validate_handoff(handoff)
    if handoff["new_body_digest"] != new_body_digest:
        raise TrustConfigError("handoff-invalid",
                               "handoff is for a different config body")
    by_kid = {r["kid"]: r for r in prev_roots}
    seen = []
    body = _handoff_body(handoff["prev_config_version"], new_body_digest)
    for entry in handoff["signatures"]:
        kid = entry["kid"]
        root = by_kid.get(kid)
        if root is None or kid in seen:
            raise TrustConfigError(
                "handoff-invalid",
                "handoff signer %r is not a previous trust root" % (kid,))
        try:
            ok = _ed.verify(bytes.fromhex(root["public_key_hex"]),
                            body, bytes.fromhex(entry["sig"]))
        except Exception:
            ok = False
        if not ok:
            raise TrustConfigError("handoff-invalid",
                                   "handoff signature by %r does not "
                                   "verify" % (kid,))
        seen.append(kid)
    for kid in handoff["authorized_by"]:
        if kid not in seen:
            raise TrustConfigError(
                "handoff-invalid",
                "authorized_by names %r with no valid signature" % (kid,))
    return seen


# ---------------------------------------------------------------------------
# Registry: activation point for trust configs
# ---------------------------------------------------------------------------

def _parse_now(now):
    if now is None:
        return _utcnow()
    if isinstance(now, str):
        return _parse_iso(now, "now")
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    raise TrustConfigError("bad-now", "now must be ISO-8601 or None")


class _ActiveConfig(object):
    """A verified, activated trust config."""

    __slots__ = ("body", "config_version", "expires_at", "signing_kids",
                 "pack_version")

    def __init__(self, body, signing_kids, pack_version):
        self.body = body
        self.config_version = body["config_version"]
        self.expires_at = _parse_iso(body["expires_at"], "expires_at")
        self.signing_kids = list(signing_kids)
        self.pack_version = pack_version

    @property
    def classes(self):
        return self.body["classes"]

    @property
    def revoked_kids(self):
        return {r["kid"] for r in self.body.get("revoked_kids", [])}

    def trust_roots_for(self, pack_class):
        return self.classes[pack_class]["trust_roots"]


class TrustConfigRegistry(object):
    """Activation point for one deployment's trust config.

    ``keyset``: the deployment-root keyset (out-of-band). The first
    ``activate()`` establishes the genesis config; later configs must
    name their predecessor in ``supersedes`` and carry a valid
    ``handoff`` whenever trust roots change. A failed candidate never
    displaces the active config (fail-closed with continuity, the OPA
    activation shape).
    """

    def __init__(self, keyset):
        if not isinstance(keyset, Keyset):
            raise TypeError("keyset must be a Keyset")
        if keyset.purpose != KEYSET_PURPOSE_DEPLOY_TRUST:
            raise TrustConfigError(
                "wrong-keyset-purpose",
                "keyset purpose %r cannot verify trust configs"
                % (keyset.purpose,))
        self._keyset = keyset
        self._current = None
        self._highest_version = 0
        self._failures = []

    @property
    def current(self):
        """The active config, or None when nothing has activated."""
        return self._current

    @property
    def activation_failures(self):
        """Bounded telemetry for refused config activations."""
        return list(self._failures)

    def _record_failure(self, code, detail):
        self._failures.append({"code": code, "detail": detail})
        del self._failures[:-64]

    def _fail(self, code, detail=""):
        self._record_failure(code, detail)
        raise TrustConfigError(code, detail)

    def require_current(self):
        """The active config, or ``TrustConfigError(no-trust-config)``
        -- bundle loading has no policy to enforce without one."""
        if self._current is None:
            raise TrustConfigError(
                "no-trust-config",
                "no trust config is active: bundle loading is refused "
                "until a signed deploy trust config activates")
        return self._current

    def activate(self, pack_doc, body_bytes, *, now=None):
        """Verify and activate a candidate trust config.

        ``pack_doc``: the signed config document from
        :func:`mint_trust_config`. ``body_bytes``: the exact canonical
        body bytes the document pins. Returns the
        :class:`_ActiveConfig`. Raises :class:`TrustConfigError`
        (fail-closed) on any failure -- the previously active config
        stays active.
        """
        now_dt = _parse_now(now)
        if not isinstance(body_bytes, (bytes, bytearray)):
            self._fail("config-body-malformed", "body must be bytes")
        body_bytes = bytes(body_bytes)
        try:
            pack = _rp.verify_rule_pack(
                pack_doc, self._keyset,
                purpose=KEYSET_PURPOSE_DEPLOY_TRUST,
                format_tag=TRUST_CONFIG_FORMAT, now=now_dt)
        except _rp.RulePackError as exc:
            self._fail("config-%s" % exc.code, exc.detail)
        if set(pack.rules) != {TRUST_CONFIG_MEMBER}:
            self._fail("config-extra-member",
                       "trust-config pack must carry exactly %r"
                       % (TRUST_CONFIG_MEMBER,))
        observed = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        if pack.rules[TRUST_CONFIG_MEMBER] != observed:
            self._fail("config-body-mismatch",
                       "body bytes do not match the signed digest pin "
                       "(tamper refused)")
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._fail("config-body-malformed",
                       "body is not valid JSON: %s" % (exc,))
        try:
            validate_trust_config_body(body)
        except TrustConfigError as exc:
            self._fail(exc.code, exc.detail)
        if pack.version != body["config_version"]:
            self._fail("config-version-mismatch",
                       "pack version %r != body config_version %r"
                       % (pack.version, body["config_version"]))
        if _parse_iso(body["expires_at"], "expires_at") <= now_dt:
            self._fail("config-expired",
                       "config expired at %s" % (body["expires_at"],))
        if body["config_version"] <= self._highest_version:
            self._fail("config-stale",
                       "config version %d is not newer than the "
                       "activated version %d (rollback refused)"
                       % (body["config_version"], self._highest_version))
        # Supersede chain + handoff ceremony.
        prev = self._current
        if prev is None:
            if body.get("supersedes") is not None:
                self._fail("config-supersede-break",
                           "genesis config must not name supersedes")
        else:
            if body.get("supersedes") != prev.config_version:
                self._fail("config-supersede-break",
                           "new config must supersede the active "
                           "version %d" % (prev.config_version,))
            if self._roots_changed(prev.body, body):
                handoff = body.get("handoff")
                if handoff is None:
                    self._fail("handoff-required",
                               "trust roots changed: the old roots must "
                               "authorize the new roots via handoff")
                prev_roots = []
                for cls in prev.body["classes"].values():
                    prev_roots.extend(cls["trust_roots"])
                # The handoff authorizes the body WITHOUT itself (a
                # signature cannot cover its own carrier).
                new_body_digest = body_digest_for_handoff(body)
                try:
                    verify_handoff(handoff, prev_roots,
                                   new_body_digest)
                except TrustConfigError as exc:
                    self._fail(exc.code, exc.detail)
                if handoff["prev_config_version"] != prev.config_version:
                    self._fail("handoff-invalid",
                               "handoff names prev_config_version %r, "
                               "active is %d"
                               % (handoff["prev_config_version"],
                                  prev.config_version))
        active = _ActiveConfig(body, pack.signing_kids, pack.version)
        self._current = active
        self._highest_version = body["config_version"]
        return active

    @staticmethod
    def _roots_changed(prev_body, new_body):
        """True when any class's trust-root kid set changed."""
        prev_classes = prev_body["classes"]
        new_classes = new_body["classes"]
        if set(prev_classes) != set(new_classes):
            return True
        for name, prev_cls in prev_classes.items():
            prev_kids = {r["kid"] for r in prev_cls["trust_roots"]}
            new_kids = {r["kid"]
                        for r in new_classes[name]["trust_roots"]}
            if prev_kids != new_kids:
                return True
        return False

    def pack_guard(self, pack_class, now=None):
        """A guard closure for :meth:`PackLoader.present`.

        Returns ``(verdict, detail)``: ``allow`` only when the pack's
        signing kids satisfy the class's trust roots (revocation wins
        over trust, grace roots only inside their window, class
        threshold enforced). Any trust failure is ``deny`` -- never
        an exception, per the guard contract.
        """
        now_dt = _parse_now(now)

        def guard(snapshot):
            try:
                kids = snapshot.get("signing_kids", [])
                matched = check_signer_trust(
                    self, pack_class, kids, now=now_dt)
            except TrustConfigError as exc:
                return ("deny", "%s: %s" % (exc.code, exc.detail))
            return ("allow",
                    "signers %s satisfy trust roots for class %r"
                    % (sorted(matched), pack_class))

        return guard


# ---------------------------------------------------------------------------
# Per-class trust evaluation (shared by the loader and the manifest path)
# ---------------------------------------------------------------------------

def check_signer_trust(registry, pack_class, signing_kids, *, now=None):
    """Check ``signing_kids`` against the active trust config.

    Returns the matched kids on success. Raises
    :class:`TrustConfigError`: ``no-trust-config`` (nothing active),
    ``trust-class-unknown`` (default-deny), ``trust-root-revoked``
    (loud -- revocation wins even over an otherwise trusted kid),
    ``trust-root-unknown`` (no signing key is a trust root), or
    ``trust-threshold-unmet``.
    """
    now_dt = _parse_now(now)
    current = registry.require_current()
    cls = current.classes.get(pack_class)
    if cls is None:
        raise TrustConfigError(
            "trust-class-unknown",
            "class %r is not named in the trust config (default-deny)"
            % (pack_class,))
    revoked = current.revoked_kids
    bad = [k for k in signing_kids if k in revoked]
    if bad:
        raise TrustConfigError(
            "trust-root-revoked",
            "signing key %r is revoked: %s"
            % (bad[0], _revoke_reason(current.body, bad[0])))
    roots = {r["kid"] for r in cls["trust_roots"]}
    grace = set()
    if cls.get("grace_roots") and cls.get("grace_until"):
        if now_dt <= _parse_iso(cls["grace_until"], "grace_until"):
            grace = {r["kid"] for r in cls["grace_roots"]}
    matched = [k for k in dict.fromkeys(signing_kids)
               if k in roots or k in grace]
    if not matched:
        raise TrustConfigError(
            "trust-root-unknown",
            "none of the signing keys %s is a trust root for class "
            "%r" % (sorted(set(signing_kids)), pack_class))
    if len(matched) < cls.get("threshold", 1):
        raise TrustConfigError(
            "trust-threshold-unmet",
            "%d trusted signer(s), class %r requires %d"
            % (len(matched), pack_class, cls.get("threshold", 1)))
    return matched


def _revoke_reason(body, kid):
    for entry in body.get("revoked_kids", []):
        if entry["kid"] == kid:
            return entry["reason"]
    return "no reason given"


def check_manifest_trust(registry, pack_class, signing_kids, *,
                         now=None):
    """Trust-root check for skill-manifest signers.

    ``signing_kids``: the key ids whose signatures verified on the
    manifest. Returns None when the signers satisfy the class's
    trust roots; raises :class:`TrustConfigError` otherwise. This is
    the seam the manifest path calls -- signature verification stays
    in :mod:`gov.capability_manifests`, trust-root authorization
    lives here.
    """
    check_signer_trust(registry, pack_class, signing_kids, now=now)
    return None


# ---------------------------------------------------------------------------
# Loud unsigned opt-out: hash-chained audit log + two-operator ceremony
# ---------------------------------------------------------------------------

def _opt_out_canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


class UnsignedOptOutLog(object):
    """Append-only, hash-chained audit log for unsigned-load
    decisions. Every unsigned *attempt* -- allowed or refused -- can
    be recorded; the chain lets an auditor detect deletion or
    tampering. 0600, fsync per append, fcntl-serialized."""

    def __init__(self, path):
        self._path = os.path.abspath(path)
        if not os.path.exists(self._path):
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
            os.close(fd)
        else:
            os.chmod(self._path, 0o600)

    @property
    def path(self):
        return self._path

    def _locked(self):
        fh = open(self._path, "a+b")
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        return fh

    def _unlock(self, fh):
        try:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()

    def _read_records(self, fh):
        fh.seek(0)
        records = []
        for line in fh.read().split(b"\n"):
            line = line.strip()
            if line:
                records.append(json.loads(line.decode("utf-8")))
        return records

    def record(self, *, pack_class, member_digests, operators,
               proposal_digest, outcome, at=None):
        """Append one unsigned-decision record. Returns the entry
        (with ``seq`` and ``entry_hash``)."""
        entry = {
            "at": at or _utcnow().isoformat(),
            "pack_class": pack_class,
            "member_digests": dict(member_digests),
            "operators": sorted(operators),
            "proposal_digest": proposal_digest,
            "outcome": outcome,
        }
        fh = self._locked()
        try:
            records = self._read_records(fh)
            prev_hash = (records[-1]["entry_hash"] if records
                         else "genesis")
            entry["seq"] = len(records) + 1
            entry["prev_hash"] = prev_hash
            entry["entry_hash"] = hashlib.sha256(
                _opt_out_canonical(
                    {k: v for k, v in entry.items()
                     if k != "entry_hash"})
                + prev_hash.encode("utf-8")).hexdigest()
            fh.write((_opt_out_canonical(entry) + b"\n"))
            fh.flush()
            os.fsync(fh.fileno())
        finally:
            self._unlock(fh)
        return entry

    def read_all(self):
        """All records, oldest first."""
        with open(self._path, "rb") as fh:
            return [json.loads(line.decode("utf-8"))
                    for line in fh.read().split(b"\n") if line.strip()]

    def verify(self):
        """Verify the hash chain. Returns True; False on any break."""
        prev = "genesis"
        expected_seq = 1
        for record in self.read_all():
            if record.get("seq") != expected_seq:
                return False
            if record.get("prev_hash") != prev:
                return False
            entry_hash = record.get("entry_hash")
            recomputed = hashlib.sha256(
                _opt_out_canonical(
                    {k: v for k, v in record.items()
                     if k != "entry_hash"})
                + prev.encode("utf-8")).hexdigest()
            if entry_hash != recomputed:
                return False
            prev = entry_hash
            expected_seq += 1
        return True


class UnsignedActivePack(object):
    """An unsigned pack activated through the loud opt-out ceremony.
    Carries the audit trail (proposal digest + log seq) so consumers
    can prove *why* unsigned content is active."""

    __slots__ = ("pack_class", "members", "proposal_digest",
                 "operators", "audit_seq")

    def __init__(self, pack_class, members, proposal_digest,
                 operators, audit_seq):
        self.pack_class = pack_class
        self.members = dict(members)
        self.proposal_digest = proposal_digest
        self.operators = list(operators)
        self.audit_seq = audit_seq

    def member(self, member_id):
        return self.members[member_id]

    def member_ids(self):
        return sorted(self.members)


class UnsignedOptOut(object):
    """The two-operator ceremony for the ``loud-opt-out`` policy.

    ``propose(files)`` -> proposal; ``ack(proposal_digest,
    operator)`` twice with DISTINCT operators; ``execute(...)``
    writes the hash-chained audit record and returns the
    :class:`UnsignedActivePack`. Any deviation -- one ack, the same
    operator twice, double execution -- fails closed. Operator
    identities are caller-supplied strings (honest residual: binding
    them to agent identity is follow-on).
    """

    def __init__(self, registry, pack_class, opt_out_log, *, now=None):
        current = registry.require_current()
        cls = current.classes.get(pack_class)
        if cls is None:
            raise TrustConfigError(
                "trust-class-unknown",
                "class %r is not named in the trust config "
                "(default-deny)" % (pack_class,))
        if cls["policy"] != POLICY_LOUD_OPT_OUT:
            raise TrustConfigError(
                "unsigned-refused",
                "class %r policy is %r: unsigned packs are refused "
                "and no opt-out ceremony is offered"
                % (pack_class, cls["policy"]))
        self._registry = registry
        self._pack_class = pack_class
        self._log = opt_out_log
        self._now = _parse_now(now)
        self._proposals = {}

    @property
    def pack_class(self):
        return self._pack_class

    def propose(self, files):
        """Propose unsigned member files for activation. Returns the
        proposal mapping (including ``proposal_digest``)."""
        if not isinstance(files, dict) or not files:
            raise TrustConfigError("bad-files",
                                   "files must be a non-empty mapping")
        for member_id, data in files.items():
            if not isinstance(member_id, str) or not member_id:
                raise TrustConfigError("bad-files",
                                       "member ids must be non-empty "
                                       "strings")
            if not isinstance(data, (bytes, bytearray)):
                raise TrustConfigError(
                    "bad-files",
                    "member %r is not bytes" % (member_id,))
        members = {mid: "sha256:" + hashlib.sha256(bytes(data)).hexdigest()
                   for mid, data in files.items()}
        proposal = {
            "pack_class": self._pack_class,
            "members": members,
            "at": self._now.isoformat(),
        }
        digest = hashlib.sha256(
            _opt_out_canonical(proposal)).hexdigest()
        proposal["proposal_digest"] = digest
        self._proposals[digest] = {"proposal": proposal,
                                   "acks": [],
                                   "files": {m: bytes(d)
                                             for m, d in files.items()},
                                   "executed": False}
        return dict(proposal)

    def ack(self, proposal_digest, operator):
        """Record one operator's ack. Two DISTINCT operators are
        required; the same operator twice is refused loudly."""
        if not isinstance(operator, str) or not operator:
            raise TrustConfigError("bad-operator",
                                   "operator must be a non-empty string")
        entry = self._proposals.get(proposal_digest)
        if entry is None:
            raise TrustConfigError("opt-out-unknown-proposal",
                                   "no such proposal")
        if entry["executed"]:
            raise TrustConfigError("opt-out-consumed",
                                   "proposal already executed")
        if operator in entry["acks"]:
            raise TrustConfigError(
                "opt-out-self-ack",
                "operator %r already acked: two DISTINCT operators "
                "are required" % (operator,))
        entry["acks"].append(operator)
        return list(entry["acks"])

    def execute(self, proposal_digest):
        """Execute a doubly-acked proposal: write the audit record and
        return the :class:`UnsignedActivePack`."""
        entry = self._proposals.get(proposal_digest)
        if entry is None:
            raise TrustConfigError("opt-out-unknown-proposal",
                                   "no such proposal")
        if entry["executed"]:
            raise TrustConfigError("opt-out-consumed",
                                   "proposal already executed")
        if len(entry["acks"]) < 2:
            # The refusal is itself audit-worthy: record it.
            self._refusal_record(entry, "quorum-unmet")
            raise TrustConfigError(
                "opt-out-quorum-unmet",
                "unsigned activation needs two distinct operator "
                "acks, got %d" % (len(entry["acks"]),))
        record = self._log.record(
            pack_class=self._pack_class,
            member_digests=entry["proposal"]["members"],
            operators=entry["acks"],
            proposal_digest=proposal_digest,
            outcome="allowed",
            at=self._now.isoformat())
        entry["executed"] = True
        return UnsignedActivePack(
            self._pack_class, entry["files"], proposal_digest,
            entry["acks"], record["seq"])

    def _refusal_record(self, entry, outcome):
        try:
            self._log.record(
                pack_class=self._pack_class,
                member_digests=entry["proposal"]["members"],
                operators=entry["acks"],
                proposal_digest=entry["proposal"]["proposal_digest"],
                outcome="refused:%s" % (outcome,),
                at=self._now.isoformat())
        except OSError:
            pass


# ---------------------------------------------------------------------------
# TrustedPackLoader: the wired-in load path
# ---------------------------------------------------------------------------

class TrustedPackLoader(object):
    """A pack loader bound to a deploy-time trust config.

    ``registry``: the :class:`TrustConfigRegistry` (must have an
    active config or every ``present()`` refuses). ``pack_class``:
    the bundle class -- unknown classes are denied. ``keyset`` /
    ``purpose`` / ``format_tag`` select the pack trust domain exactly
    as in :class:`PackLoader`.

    ``present()`` enforces, in order: trust config active ->
    class known -> pack signature valid -> signing keys satisfy the
    class trust roots (revocation loud, grace window honored, class
    threshold enforced) -> the pack's own enumeration/version/guard
    checks via the inner loader. ``present_unsigned()`` is the ONLY
    unsigned path: it exists solely for ``loud-opt-out`` classes and
    runs the two-operator ceremony with hash-chained audit.
    """

    def __init__(self, keyset, pack_id, *, registry, pack_class,
                 purpose=_rp.KEYSET_PURPOSE_RULE_PACK,
                 format_tag=_rp.RULE_PACK_FORMAT):
        if not isinstance(registry, TrustConfigRegistry):
            raise TypeError("registry must be a TrustConfigRegistry")
        if not isinstance(pack_class, str) or not pack_class:
            raise TrustConfigError("bad-pack-class",
                                   "pack_class must be a non-empty "
                                   "string")
        self._inner = PackLoader(keyset, pack_id, purpose=purpose,
                                 format_tag=format_tag)
        self._keyset = keyset
        self._registry = registry
        self._pack_class = pack_class
        self._purpose = purpose
        self._format_tag = format_tag

    @property
    def pack_class(self):
        return self._pack_class

    @property
    def registry(self):
        return self._registry

    @property
    def current(self):
        return self._inner.current

    @property
    def activation_failures(self):
        return self._inner.activation_failures

    def present(self, pack_doc, files, *, guard=None, now=None):
        """Verify trust, then activate the candidate pack.

        Raises :class:`TrustConfigError` for trust-config failures
        (``no-trust-config``, ``trust-class-unknown``,
        ``trust-root-revoked``, ``trust-root-unknown``,
        ``trust-threshold-unmet``) and
        :class:`PackActivationError` for pack-level failures
        (signature, enumeration, rollback) -- the inner loader's
        contract is unchanged.
        """
        now_dt = _parse_now(now)
        # 1. The deployment must have an active trust config, and the
        #    class must be named -- before any crypto runs.
        current = self._registry.require_current()
        if self._pack_class not in current.classes:
            raise TrustConfigError(
                "trust-class-unknown",
                "class %r is not named in the trust config "
                "(default-deny)" % (self._pack_class,))
        # 2. The pack must be genuinely signed; extract the signing
        #    kids from the verified document.
        try:
            pack = _rp.verify_rule_pack(
                pack_doc, self._keyset, purpose=self._purpose,
                format_tag=self._format_tag, now=now_dt)
        except _rp.RulePackError as exc:
            # Keep the inner loader's failure telemetry complete: a
            # pack refused at the trust pre-check is still a refused
            # activation for this pack id.
            self._inner._record_failure(
                pack_doc, "pack-%s" % exc.code, exc.detail)
            raise PackActivationError("pack-%s" % exc.code, exc.detail)
        # 3. The signers must satisfy the class trust roots.
        check_signer_trust(self._registry, self._pack_class,
                           pack.signing_kids, now=now_dt)
        # 4. The pack's own activation checks (enumeration, rollback
        #    floor, caller guard). The trust check above already ran,
        #    so no trust guard is needed here.
        return self._inner.present(pack_doc, files, guard=guard,
                                   now=now_dt)

    def present_unsigned(self, files, *, operators, opt_out_log,
                         now=None):
        """The loud unsigned path (``loud-opt-out`` classes only).

        ``operators``: the acking operators (two distinct required;
        must be a list/tuple -- a bare string is refused, so
        ``"alice"`` can never splinter into five one-letter
        operators). ``opt_out_log``: an :class:`UnsignedOptOutLog`.
        Every attempt -- allowed or refused -- leaves a hash-chained
        audit record.
        """
        now_dt = _parse_now(now)
        if isinstance(operators, str) or not isinstance(
                operators, (list, tuple)):
            raise TrustConfigError(
                "bad-operators",
                "operators must be a list/tuple of operator names")
        ceremony = UnsignedOptOut(self._registry, self._pack_class,
                                  opt_out_log, now=now_dt)
        proposal = ceremony.propose(files)
        digest = proposal["proposal_digest"]
        for operator in operators:
            ceremony.ack(digest, operator)
        return ceremony.execute(digest)
