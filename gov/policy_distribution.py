"""Signed policy distribution plane (pub/sub of policy + data bundles).

Wave-260 feature lane 1 (D1). Stdlib only. No network.

ADAPT lineage (patterns only, no donor code):
  - permitio/opal (Apache-2.0, wave-259 prospectus D1): the pub/sub
    shape -- a publisher emits policy/data updates per *topic*, edge
    subscribers bind topics and load bundles into their local decision
    point. We steal the distribution architecture, not the engine
    coupling and not the channel (in v1 the transport is an explicit
    seam: bundles are bytes a deployment carries over any channel --
    websocket, queue, file drop -- OPAL's outbound-websocket fan-out
    is deployment-owned).
  - OPAL's documented threat model trusts the server and the
    channel. This lane closes exactly that: every bundle is Ed25519
    -signed over its canonical bytes (``gov/ed25519.py``), and the
    subscriber verifies signature + monotonic version + topic binding
    BEFORE applying. A compromised or buggy publisher/channel cannot
    push hostile or stale policy to an enforcement point -- the
    bundle is refused with a machine code and never loaded.

Design:

  Publisher(seed)                          Subscriber(topic, pubkey)
      | sign_bundle(topic, ver, payload)        | apply(bundle_bytes)
      v                                          v
  bundle bytes  ---- any transport ---->  verify topic/sig/version
                                                 |
                                         applied | refused (machine code)

Bundle wire format (JSON, UTF-8):
  {"v": 1, "topic": <str>, "version": <non-negative int>,
   "payload": <JSON value>, "sig": <64-byte Ed25519 signature, hex>}

Signed bytes: b"poldist-bundle/v1:" + canonical JSON of
{"topic", "version", "payload"} (sort_keys, separators, ensure_ascii)
-- the domain separator keeps poldist signatures from verifying as
any other Ed25519 use in this repo (cf. wave-179 F199 lesson).

Subscriber check order (each refusal is a machine-coded refusal;
the subscriber never applies a bundle it did not verify):
  1. envelope shape          -> poldist-bundle-malformed
  2. topic binding           -> poldist-topic-cross
     (checked BEFORE signature: foreign-topic bytes are refused
     without disclosing signature-validity oracles)
  3. signature present       -> poldist-signature-missing
  4. signature verifies      -> poldist-signature-mismatch
     (``ed25519.verify`` returns bool, never raises; assert ``is True``
     per the wave-243 lesson)
  5. monotonic version       -> poldist-version-rollback
     (older, or same-version with a different payload --
     equivocation-shaped -- is refused; a forward skip is applied
     with gap=True flagged so the deployment can reconcile)

The publisher is also fail-closed: it tracks the last version it
signed per topic and refuses to sign a non-increasing version
(PublisherError), so an operator cannot accidentally fork a topic
from the source.

Machine codes (domain "poldist", all registered in
gov/decision_codes.py):

* ``poldist-bundle-malformed`` -- envelope is not well-formed JSON
  or a required field has the wrong shape.
* ``poldist-signature-missing`` -- no ``sig`` field (unsigned bundle).
* ``poldist-signature-mismatch`` -- Ed25519 verification failed
  (forgery, tamper, key confusion).
* ``poldist-topic-cross`` -- bundle topic is not the subscriber's
  bound topic (unknown topic or cross-topic replay); refused before
  any signature work.
* ``poldist-version-rollback`` -- version older than the loaded head,
  or the same version with different bytes (equivocation-shaped).

Honest residuals (documented, not solved here):
  - This is a distribution mechanism, NOT a consensus protocol: two
    publishers sharing a public key (or a key compromise) can fork a
    topic and feed different heads to different subscribers. Fork
    detection -- witness/head comparison, cf. the transparency log's
    equivocation story -- is a documented residual, exactly as the
    prospectus caution requires.
  - The publisher holds its signing seed in-process; production key
    custody (KMS/HSM/Vault-transit) is deployment-owned. Seed custody
    IS the trust root (same residual class as the wave-259 SVID
    test issuer).
  - No freshness/max-age bound: a validly signed bundle is applied no
    matter how old it is, provided it is the newest the subscriber
    has seen. Deployments that need staleness failure (prospectus:
    "fail-closed on stale policy beyond a max-age") enforce it at the
    decision point with the bundle's version/timestamp, not here.
  - Replay of the CURRENT head (identical bytes) is applied
    idempotently -- at-least-once delivery is safe.
"""

import hashlib
import json
import os
import re

from . import decision_codes as _dc
from . import ed25519 as _ed25519

__all__ = [
    "Publisher",
    "Subscriber",
    "PublisherError",
    "BUNDLE_VERSION",
    "DOMAIN_SEPARATOR",
    "signed_bytes",
    "canonical_payload",
    "POLDIST_DOMAIN",
]

BUNDLE_VERSION = 1
DOMAIN_SEPARATOR = b"poldist-bundle/v1:"
POLDIST_DOMAIN = "poldist"

_TOPIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_SIG_HEX_RE = re.compile(r"^[0-9a-f]{128}$")


class PublisherError(Exception):
    """Publisher-side fail-closed error (not a machine code: the
    publisher is the trusted operator surface, not the refusing
    seam)."""


def canonical_payload(topic, version, payload):
    """Canonical bytes the signature covers."""
    return json.dumps(
        {"topic": topic, "version": version, "payload": payload},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def signed_bytes(topic, version, payload):
    """The exact bytes Ed25519 signs/verifies for a bundle."""
    return DOMAIN_SEPARATOR + canonical_payload(topic, version, payload)


def _bundle_digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Publisher:
    """Signs policy/data bundles for topics.

    The publisher holds an Ed25519 seed and refuses to sign a
    non-increasing version for a topic (fail-closed at the source:
    no accidental topic forks from the operator side).
    """

    def __init__(self, seed):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise PublisherError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pubkey = _ed25519.publickey(self._seed)
        self._last_version = {}  # topic -> last signed version

    @property
    def pubkey(self):
        """The 32-byte Ed25519 public key subscribers pin."""
        return self._pubkey

    def _check_topic(self, topic):
        if not isinstance(topic, str) or not _TOPIC_RE.match(topic):
            raise PublisherError("topic must match %s"
                                 % _TOPIC_RE.pattern)

    def sign_bundle(self, topic, version, payload):
        """Sign a bundle. Returns the bundle as bytes (JSON, UTF-8).

        Raises PublisherError on a malformed topic, a non-integer or
        negative version, a non-increasing version for the topic, or
        a non-JSON-serializable payload. Raises nothing on the happy
        path; the signature is deterministic (RFC 8032).
        """
        self._check_topic(topic)
        if (not isinstance(version, int) or isinstance(version, bool)
                or version < 0):
            raise PublisherError("version must be a non-negative int")
        try:
            canonical_payload(topic, version, payload)
        except (TypeError, ValueError) as e:
            raise PublisherError("payload is not JSON-serializable: %s"
                                 % e)
        last = self._last_version.get(topic, -1)
        if version <= last:
            raise PublisherError(
                "refusing to sign non-increasing version %d for topic %r "
                "(last signed %d)" % (version, topic, last))
        sig = _ed25519.sign(self._seed, signed_bytes(topic, version, payload))
        self._last_version[topic] = version
        return json.dumps(
            {"v": BUNDLE_VERSION, "topic": topic, "version": version,
             "payload": payload, "sig": sig.hex()},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")


class Subscriber:
    """Verifies bundles and holds one topic's loaded head.

    ``topic`` is the single topic this subscriber binds; ``pubkey``
    is the pinned 32-byte Ed25519 publisher public key. Key ids are
    deliberately absent from the bundle format -- the bundle never
    selects its own verifier (key-confusion resistance).
    """

    def __init__(self, topic, pubkey):
        if not isinstance(topic, str) or not _TOPIC_RE.match(topic):
            raise ValueError("topic must match %s" % _TOPIC_RE.pattern)
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        self._topic = topic
        self._pubkey = bytes(pubkey)
        self._version = None   # no head loaded yet
        self._payload = None

    @property
    def topic(self):
        return self._topic

    @property
    def version(self):
        """Currently loaded head version (None before the first bundle)."""
        return self._version

    @property
    def payload(self):
        """Currently loaded head payload (None before the first bundle)."""
        return self._payload

    def _refuse(self, code, raw, detail):
        return {
            "outcome": "refused",
            "code": _dc.emit(code, evidence_digests=(_bundle_digest(raw),),
                             detail=detail),
        }

    def apply(self, bundle):
        """Verify a bundle and, only if every check passes, apply it.

        Returns {"outcome": "applied", "topic", "version",
        "duplicate": bool, "gap": bool} or {"outcome": "refused",
        "code": <machine code dict>}. Never raises on hostile input;
        every refusal is machine-coded.
        """
        raw = bundle if isinstance(bundle, (bytes, bytearray)) else b""
        try:
            env = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "bundle is not UTF-8 JSON")
        except RecursionError:
            # F235: hostile unsigned input nested beyond the
            # interpreter's recursion budget. json.loads raises
            # RecursionError (a RuntimeError subclass, not ValueError),
            # which used to escape apply() and kill the subscriber's
            # loop. It is refused here, machine-coded, like any other
            # unparseable envelope -- the "never raises on hostile
            # input" contract holds at every nesting depth.
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "bundle nesting exceeds parser recursion limits "
                "(recursion-hostile input)")
        if not isinstance(env, dict):
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "envelope is not a JSON object")
        if env.get("v") != BUNDLE_VERSION:
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "unsupported bundle version %r" % (env.get("v"),))
        topic = env.get("topic")
        version = env.get("version")
        payload = env.get("payload", None)
        sig_hex = env.get("sig")
        if not isinstance(topic, str):
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "topic field is not a string")
        # Topic binding BEFORE signature: foreign-topic bytes are
        # refused without disclosing signature-validity oracles, and
        # the subscriber's own store can never be polluted by another
        # topic's bundle (cross-topic replay).
        if topic != self._topic:
            return self._refuse(
                "poldist-topic-cross", raw,
                "bundle topic %r is not the bound topic %r"
                % (topic, self._topic))
        if "sig" not in env:
            return self._refuse(
                "poldist-signature-missing", raw,
                "bundle carries no Ed25519 signature (unsigned bundle)")
        sig_hex = env.get("sig")
        if not isinstance(sig_hex, str) or not _SIG_HEX_RE.match(sig_hex):
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "sig field is present but is not 128 lowercase hex chars")
        if (not isinstance(version, int) or isinstance(version, bool)
                or version < 0):
            return self._refuse(
                "poldist-bundle-malformed", raw,
                "version field is not a non-negative int")
        sig = bytes.fromhex(sig_hex)
        if _ed25519.verify(self._pubkey,
                           signed_bytes(topic, version, payload),
                           sig) is not True:  # bool-returning contract
            return self._refuse(
                "poldist-signature-mismatch", raw,
                "Ed25519 signature does not verify under the pinned key")
        # Monotonic version: no rollback, no equivocation. Identical
        # re-delivery of the current head is applied idempotently so
        # at-least-once transport is safe; a forward skip is applied
        # with gap=True so the deployment can reconcile missed diffs.
        if self._version is not None:
            if version < self._version:
                return self._refuse(
                    "poldist-version-rollback", raw,
                    "bundle version %d is older than loaded head %d"
                    % (version, self._version))
            if version == self._version:
                if canonical_payload(topic, version, payload) != \
                        canonical_payload(topic, self._version, self._payload):
                    return self._refuse(
                        "poldist-version-rollback", raw,
                        "same version %d with different payload: "
                        "equivocation-shaped, head not switched"
                        % version)
                return {"outcome": "applied", "topic": topic,
                        "version": version, "duplicate": True, "gap": False}
        gap = self._version is not None and version > self._version + 1
        self._version = version
        # Deep-copy via a JSON round-trip so the caller's object graph
        # cannot mutate the loaded head later.
        self._payload = json.loads(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True))
        return {"outcome": "applied", "topic": topic, "version": version,
                "duplicate": False, "gap": gap}
