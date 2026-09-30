"""Attested-channel receipt admission (W243-6, ADAPT -- pattern only).

Prose re-derived from the wave-242 prospectus description of
agent-receipts/obsigna (Apache-2.0, direct LICENSE read). No upstream
code is read, imported, or vendored.

Discipline
----------
The daemon signs *emitter claims*, not observations. It vouches only
for what it can attest itself:

* kernel-attested peer identity (uid/gid/pid/exe -- the SO_PEERCRED
  analogue; supplied to this module by the admission layer, never by
  the emitter),
* its own timestamp (never the emitter's ``ts_emit``),
* the admission chain position (sequence per peer),
* the canonical-byte digest of the admitted record.

Everything semantic in the payload is emitter-claimed and only
structurally validated; it is marked as a claim in the admission
record, never as a verified observation. Tamper-evidence is emergent:
chain-position tracking plus canonical digests, not a dedicated
tamper-byte primitive.

Receipt-admission rules (all fail-closed, domain ``attested-channel``):

* ``channel-record-malformed`` -- the emitter claim or the attested
  peer block is not the shape this module speaks.
* ``channel-identity-unattested`` -- a self-reported principal with no
  attested peer identity. Refused outright, never downgraded: without
  a kernel-attested peer there is no one to hold accountable.
* ``channel-peer-mismatch`` -- the attested peer block names a
  principal different from the self-reported one.
* ``key-in-agent-process`` -- the emitting context declares direct key
  access inside the agent process. Process separation is
  architectural, not advisory: keys must live outside the emitting
  process (daemon, external KMS, or another attested key holder).
* ``channel-timestamp-divergence`` -- emitter ``ts_emit`` diverges
  from daemon time beyond the forgery bound. Within the bound the
  daemon's timestamp WINS and the divergence is RECORDED (falsifies
  timestamp forgery without refusing honest clock skew).
* ``channel-sequence-break`` -- the claim's sequence does not follow
  the peer's last admitted sequence (replay or reorder).

Collector discipline: ``ForwardCompatSink`` accepts structurally,
stores verbatim bytes, and verifies at audit time.

Honest boundaries
-----------------
* This module never performs the attestation itself: ``peer_identity``
  arrives as a value the *deployment's admission layer* vouches for
  (in production, SO_PEERCRED on a unix-domain socket). A test that
  fabricates ``peer_identity`` is testing this module's logic, not
  the kernel's.
* Daemon time is an injected ``now``: deterministic, but the module
  cannot make the deployment's clock honest.
* Keys-out-of-process is enforced on the *declared* key location; the
  module cannot inspect a real process address space.
* The sink's verbatim store is in-memory/local by default; distributed
  atomicity of collection remains deployment-owned.

Stdlib only. Deterministic: every clock is injected.
"""

import hashlib
import json


DOMAIN = "attested-channel"

MALFORMED = "channel-record-malformed"
IDENTITY_UNATTESTED = "channel-identity-unattested"
PEER_MISMATCH = "channel-peer-mismatch"
KEY_IN_AGENT_PROCESS = "key-in-agent-process"
TIMESTAMP_DIVERGENCE = "channel-timestamp-divergence"
SEQUENCE_BREAK = "channel-sequence-break"

# Within this skew the daemon timestamp wins and the divergence is
# recorded; beyond it the emission is treated as forged.
SKEW_TOLERANCE_SECONDS = 300
FORGERY_BOUND_SECONDS = 86400

# Key locations the admission layer accepts as "outside the emitting
# process". Anything else -- including "agent-process" -- refuses.
_EXTERNAL_KEY_LOCATIONS = frozenset(
    ["daemon", "external-kms", "hsm", "vault-transit"])


class AttestedChannelError(Exception):
    """Fail-closed attested-channel refusal. ``code`` is the vocabulary."""

    def __init__(self, code, detail=""):
        super(AttestedChannelError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _canonical(obj):
    """Canonical bytes for digesting (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_peer_identity(peer_identity):
    """Validate the attested peer block (supplied by the admission
    layer, never the emitter). Returns the block on success."""
    if peer_identity is None:
        raise AttestedChannelError(
            IDENTITY_UNATTESTED,
            "no attested peer identity for the self-reported principal")
    if not isinstance(peer_identity, dict):
        raise AttestedChannelError(MALFORMED,
                                  "peer_identity must be a dict")
    for field in ("uid", "gid", "pid", "exe"):
        value = peer_identity.get(field)
        if field == "exe":
            if (isinstance(value, bool) or not isinstance(value, str)
                    or not value):
                raise AttestedChannelError(
                    MALFORMED, "peer_identity.exe must be a non-empty str")
        elif isinstance(value, bool) or not isinstance(value, int) \
                or value < 0:
            raise AttestedChannelError(
                MALFORMED, "peer_identity.%s must be a non-negative int"
                % field)
    principal = peer_identity.get("principal")
    if principal is not None and (
            isinstance(principal, bool) or not isinstance(principal, str)
            or not principal):
        raise AttestedChannelError(MALFORMED,
                                  "peer_identity.principal must be a "
                                  "non-empty str when present")
    return peer_identity


def _check_claim(emitter_claim):
    if not isinstance(emitter_claim, dict):
        raise AttestedChannelError(MALFORMED,
                                  "emitter_claim must be a dict")
    principal = emitter_claim.get("principal")
    if (isinstance(principal, bool) or not isinstance(principal, str)
            or not principal):
        raise AttestedChannelError(MALFORMED,
                                  "claim principal must be a non-empty str")
    ts_emit = emitter_claim.get("ts_emit")
    if (isinstance(ts_emit, bool) or not isinstance(ts_emit, (int, float))):
        raise AttestedChannelError(MALFORMED,
                                  "claim ts_emit must be a number")
    seq = emitter_claim.get("seq")
    if seq is None:
        raise AttestedChannelError(MALFORMED, "claim seq is required")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise AttestedChannelError(MALFORMED,
                                  "claim seq must be a non-negative int")
    payload = emitter_claim.get("payload")
    if payload is None:
        raise AttestedChannelError(MALFORMED, "claim payload is required")
    try:
        _canonical(payload)
    except (TypeError, ValueError):
        raise AttestedChannelError(MALFORMED,
                                  "claim payload must be JSON-canonicalizable")
    return principal, float(ts_emit), seq, payload


def _check_key_location(key_location):
    if key_location not in _EXTERNAL_KEY_LOCATIONS:
        raise AttestedChannelError(
            KEY_IN_AGENT_PROCESS,
            "keys must live outside the emitting process; declared %r"
            % (key_location,))


class ChannelAdmission(object):
    """Daemon-side receipt admission with per-peer sequence tracking.

    ``now`` is always passed explicitly (deterministic). The peer's
    last admitted sequence is tracked so replays and reorders refuse
    ``channel-sequence-break``.
    """

    def __init__(self):
        self._last_seq = {}

    @staticmethod
    def _peer_key(peer_identity):
        return (peer_identity["uid"], peer_identity["pid"],
                peer_identity["exe"])

    def admit(self, emitter_claim, peer_identity, key_location, now):
        """Admit one receipt. Returns the admission record.

        The record separates what the daemon vouches for
        (``observations``) from what is merely emitter-claimed
        (``claims``). ``daemon_ts`` is authoritative; any divergence
        from ``ts_emit`` is recorded.
        """
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise AttestedChannelError(MALFORMED, "now must be a number")
        now = float(now)
        peer = _check_peer_identity(peer_identity)
        principal, ts_emit, seq, payload = _check_claim(emitter_claim)
        attested_principal = peer.get("principal")
        if attested_principal is not None \
                and attested_principal != principal:
            raise AttestedChannelError(
                PEER_MISMATCH,
                "self-reported %r but attested peer names %r"
                % (principal, attested_principal))
        _check_key_location(key_location)
        divergence = now - ts_emit
        if abs(divergence) > FORGERY_BOUND_SECONDS:
            raise AttestedChannelError(
                TIMESTAMP_DIVERGENCE,
                "ts_emit diverges from daemon time by %.1f seconds "
                "(bound %d)" % (divergence, FORGERY_BOUND_SECONDS))
        key = self._peer_key(peer)
        expected = self._last_seq.get(key, 0)
        if seq != expected:
            raise AttestedChannelError(
                SEQUENCE_BREAK,
                "expected seq %d for peer, got %d" % (expected, seq))
        self._last_seq[key] = expected + 1
        record = {
            "principal": principal,
            "peer_identity": {
                "uid": peer["uid"], "gid": peer["gid"],
                "pid": peer["pid"], "exe": peer["exe"],
            },
            "daemon_ts": now,
            "ts_emit": ts_emit,
            "time_divergence_seconds": divergence,
            "seq": seq,
            "claims": payload,
            "observations": ["peer_identity", "daemon_ts", "seq",
                             "canonical_digest"],
        }
        digest = hashlib.sha256(_canonical(record)).hexdigest()
        record["canonical_digest"] = digest
        return record


class ForwardCompatSink(object):
    """Collector: accept structurally, store verbatim, verify at audit.

    ``collect`` stores the exact bytes presented. ``audit`` parses
    each stored blob and runs it through a ``ChannelAdmission``; any
    blob that no longer verifies refuses at audit time (the sink never
    reinterprets what it stored). Tamper-evidence is emergent: at
    ingest the sink commits to the sha256 of the exact bytes, and
    audit refuses a blob whose bytes no longer match the commitment.
    """

    def __init__(self):
        self._blobs = []
        self._digests = []

    def collect(self, raw_bytes):
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8")
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise AttestedChannelError(MALFORMED,
                                      "sink collects bytes only")
        try:
            json.loads(bytes(raw_bytes).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AttestedChannelError(MALFORMED,
                                      "sink collects JSON records only")
        blob = bytes(raw_bytes)
        self._blobs.append(blob)
        self._digests.append(hashlib.sha256(blob).hexdigest())
        return len(self._blobs) - 1

    def audit(self, peer_provider, key_location, now):
        """Verify every stored blob. ``peer_provider(raw_dict)`` maps a
        stored record to its attested peer block (in production: the
        SO_PEERCRED of the collecting socket, matched to the record)."""
        admission = ChannelAdmission()
        records = []
        for index, blob in enumerate(self._blobs):
            if hashlib.sha256(blob).hexdigest() != self._digests[index]:
                raise AttestedChannelError(
                    MALFORMED,
                    "stored blob %d no longer matches its ingest digest"
                    % index)
            try:
                stored = json.loads(blob.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise AttestedChannelError(
                    MALFORMED, "stored blob %d no longer parses" % index)
            peer = peer_provider(stored)
            records.append(admission.admit(stored, peer, key_location,
                                           now))
        return records

    def __len__(self):
        return len(self._blobs)
