"""F110 (wave-34/35): governed harness-initiated platform egress.

Z.ai ZCode (I22, 2026-09-18) defined the class this closes: platform
code with its own network path -- never an agent tool call -- silently
packing entire workspaces (including ``.git``) and uploading them to a
vendor endpoint. Every egress/DLP/taint control in this repo governed
*agent tool calls*; the uploader never entered the policy engine, and
no consent surface existed (default-on).

This module is the closure control: the ONLY sanctioned
harness-initiated workspace-collection path in the product.

  * DEFAULT-OFF: no collection happens unless the operator explicitly
    issues a consent token via :func:`issue_consent`. There is no
    "enabled by default" configuration knob anywhere in this module.
  * CONSENT TOKEN (wave-35: HMAC-bound; wave-40: optional
    destination binding): opt-in is recorded as an audit-logged
    consent token MACed with a PLATFORM-HELD key (HMAC-SHA256 over the
    token fields, stdlib ``hmac``, domain ``pec-v2``). The key is
    supplied by the deployer/operator at issuance and at verification
    time; it is never logged, never serialized into the token, and the
    agent never sees it. A token whose MAC does not verify --
    hand-minted, tampered, or MACed under a different key -- is
    refused. ``issue_consent(..., destination=)`` binds the token to
    one destination; a bound token presented for another destination
    (or without a destination) is refused, closing cross-destination
    replay within the TTL. A token issued WITHOUT ``destination=``
    stays a bearer credential for the scope+TTL (multi-use, any
    allowlisted destination): an explicit operator choice, documented
    here, not a silent default. Fail-closed: the token is valid only
    if its issuance audit entry landed (``log.append`` raising means
    no token is returned), and every use is checked for MAC, scope,
    destination binding, and expiry.
  * POLICY ROUTING: every upload is evaluated through the SAME policy
    engine as tool calls, with context ``{"platform_egress": True,
    "domain_allowlisted": <bool>}``. ``deny-platform-egress-unallowlisted``
    (``policies/default.yaml``) denies non-allowlisted destinations;
    ``allow-platform-egress-allowlisted`` allows allowlisted ones. The
    decision is audit-logged whether it allows or denies.
  * WRITE-AHEAD AUDIT (wave-35): the ``platform_egress_authorized``
    entry lands BEFORE the upload side effect (``sink.put``). A failed
    upload produces an explicit ``platform_egress_upload_failed``
    entry; the completion entry (``platform_egress_upload``) is
    appended after the put returns. There is no window in which a
    side effect was attempted with no audit record.
  * ARCHIVE CONFIDENTIALITY (wave-35, hardened wave-37): a plaintext
    archive requires an explicit ``allow_plaintext=True`` opt-in,
    recorded in the audit entry (``plaintext_explicit: True``);
    otherwise an ``archive_key`` is required. An ``archive_key``
    WITHOUT an explicit ``cipher`` is refused -- the module never
    silently selects a cipher. The bundled :func:`demonstration_cipher`
    is TEST-ONLY and must be passed explicitly AND with
    ``GOV_DEMO_CIPHER_OK=1`` in the environment (wave-37: the env gate
    converts a production copy-paste of the test call from a silent
    misconfiguration into a loud, audit-logged refusal); production
    deployments MUST pass ``cipher=`` a real AEAD (e.g. AES-GCM /
    ChaCha20-Poly1305) keyed by a deployer-held key. Passing BOTH
    ``archive_key`` and ``allow_plaintext=True`` is refused as a
    contradictory posture rather than silently ignoring the flag.
  * USER-VERIFIABLE CRYPTO: archive encryption uses ONLY deployer-held
    keys passed in by the caller. There is deliberately NO code path in
    this module that fetches a key from a vendor -- no network, no KMS
    call, no RSA key-wrap, no key download.

Deliberate non-goals (documented boundaries, not gaps): the layer
cannot verify a third party's deletion claims or key custody once an
archive has left -- that is third-party-audit territory. The in-scope
guarantee is no-silent-collection: default-off + HMAC-bound consent +
allowlisted destination + write-ahead audit + explicit archive
confidentiality posture.
"""

import hashlib
import hmac
import os
import time
from pathlib import Path

__all__ = [
    "PlatformEgressError",
    "ConsentToken",
    "issue_consent",
    "check_consent",
    "WorkspaceCollector",
    "demonstration_cipher",
]

#: Scope string a consent token must carry for workspace collection.
SCOPE_WORKSPACE_COLLECT = "workspace_collect"

#: Audit event names written by this module.
EVENT_CONSENT = "platform_egress_consent"
EVENT_DENIED = "platform_egress_denied"
EVENT_AUTHORIZED = "platform_egress_authorized"
EVENT_UPLOAD = "platform_egress_upload"
EVENT_UPLOAD_FAILED = "platform_egress_upload_failed"

#: Env var that must be "1" for demonstration_cipher to run.
#: Wave-37 (RT7 ratchet of the deployer-injected AEAD seam): the
#: cipher is TEST-ONLY, and the realistic failure mode is a deployer
#: copy-pasting the test call into production. The explicit pass
#: alone was the acknowledgment (wave-35); now the acknowledgment
#: ALSO requires this env var, so the copy-paste accident fails
#: LOUD on first run instead of silently shipping malleable,
#: unauthenticated crypto as the archive cipher. Tests set it in
#: tests/__init__.py; production never sets it.
_DEMO_CIPHER_ENV = "GOV_DEMO_CIPHER_OK"


def _demo_cipher_enabled():
    return os.environ.get(_DEMO_CIPHER_ENV) == "1"

#: MAC domain-separation prefix (versioned for algorithm agility).
#: pec-v2 (wave-40, F114): the bound destination joins the MACed fields,
#: so a destination-bound token cannot be replayed to another
#: destination. Tokens minted under pec-v1 fail closed as bad_mac --
#: safe, since consent tokens are short-lived by construction.
_MAC_VERSION = "pec-v2"


class PlatformEgressError(Exception):
    """Fail-closed refusal of a harness-initiated platform egress."""


def _check_key(key, what):
    """Validate a platform/deployer-held key (fail-closed)."""
    if not isinstance(key, bytes) or len(key) < 16:
        raise PlatformEgressError(
            "%s must be bytes of length >= 16" % what)
    return key


def _token_mac(key, token_id, scope, granted_by, granted_at, expires_at,
               destination):
    """HMAC-SHA256 over the canonical token fields (pec-v2: the bound
    destination -- or "" when unbound -- is part of the MACed message,
    so the binding cannot be stripped or swapped without the key)."""
    msg = "|".join((_MAC_VERSION, token_id, scope, granted_by,
                    str(int(granted_at)), str(int(expires_at)),
                    str(destination or ""))
                   ).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _token_id():
    return "pec-" + os.urandom(16).hex()


def issue_consent(log, key, *, scope=SCOPE_WORKSPACE_COLLECT, granted_by,
                  ttl_s=3600, destination=None):
    """Record an explicit operator opt-in and return the consent token.

    ``key``: the platform-held consent-signing key (bytes >= 16),
    supplied by the deployer/operator -- e.g. from their KMS or
    environment. It is used only to MAC the token; it is never logged
    and never leaves this call. The agent never sees it.

    ``destination`` (wave-40, F114): when given (non-empty string), the
    token is BOUND to that destination -- ``check_consent`` refuses it
    for any other destination, closing the cross-destination replay of
    a bearer token within its TTL. When omitted, the token stays a
    bearer credential for the scope+TTL (multi-use, any allowlisted
    destination): an explicit operator choice, documented, not a
    silent default -- pass ``destination=`` whenever the operator
    knows where the collection is going.

    Default-off lives here: no token exists unless the operator calls
    this function. Fail-closed: if the audit append raises, no token
    is returned and the caller must treat consent as not granted.
    """
    _check_key(key, "consent key")
    if not granted_by or not isinstance(granted_by, str):
        raise PlatformEgressError(
            "consent requires a named granting operator")
    if destination is not None and (
            not isinstance(destination, str) or not destination):
        raise PlatformEgressError(
            "consent destination must be a non-empty string or None")
    now = int(time.time())
    token_id = _token_id()
    expires_at = now + int(ttl_s)
    token = {
        "token_id": token_id,
        "scope": scope,
        "granted_by": granted_by,
        "granted_at": now,
        "expires_at": expires_at,
        "destination": destination,
    }
    token["mac"] = _token_mac(key, token_id, scope, granted_by, now,
                              expires_at, destination)
    # The audit entry IS the consent record: fail-closed on log failure.
    # The MAC is safe to log (it does not leak the key) and lets an
    # auditor holding the key verify the issuance later.
    log.append({
        "event": EVENT_CONSENT,
        "decision": "consent_granted",
        "token_id": token["token_id"],
        "scope": scope,
        "granted_by": granted_by,
        "expires_at": token["expires_at"],
        "destination": destination,
        "destination_bound": destination is not None,
        "mac": token["mac"],
    })
    return ConsentToken(token)


class ConsentToken:
    """Opaque handle for an issued consent token.

    The token id is the audit correlation key; the token itself carries
    no authority beyond what :func:`check_consent` validates against
    the platform-held key. The handle never carries the key.
    """

    def __init__(self, token):
        self._token = dict(token)

    @property
    def token_id(self):
        return self._token["token_id"]

    def as_dict(self):
        return dict(self._token)


def check_consent(token, key, *, scope=SCOPE_WORKSPACE_COLLECT, now=None,
                  destination=None):
    """Validate a consent token against the platform-held key.

    Checks: token shape, token_id format, HMAC binding to issuance
    (hand-minted, tampered, or wrong-key tokens are refused), scope
    coverage, destination binding (wave-40, F114: a token issued with
    ``destination=`` is refused for any other destination, and refused
    when presented without a destination claim), expiry. Returns the
    token dict or raises.
    """
    _check_key(key, "consent key")
    t = token.as_dict() if isinstance(token, ConsentToken) else token
    if not isinstance(t, dict):
        raise PlatformEgressError("consent_required: no consent token")
    tid = t.get("token_id")
    if not isinstance(tid, str) or not tid.startswith("pec-"):
        raise PlatformEgressError("consent_invalid: malformed token")
    granted_by = t.get("granted_by")
    granted_at = t.get("granted_at")
    expires_at = t.get("expires_at")
    bound_destination = t.get("destination")
    try:
        expected = _token_mac(key, tid, t.get("scope"), granted_by,
                              granted_at, expires_at, bound_destination)
    except (TypeError, ValueError):
        raise PlatformEgressError("consent_invalid: malformed token")
    presented = t.get("mac")
    if (not isinstance(presented, str)
            or not hmac.compare_digest(presented, expected)):
        raise PlatformEgressError(
            "consent_invalid: bad_mac -- token not bound to issuance")
    if t.get("scope") != scope:
        raise PlatformEgressError(
            "consent_invalid: scope %r does not cover %r"
            % (t.get("scope"), scope))
    if bound_destination:
        # Destination-bound token (F114): the binding is enforced --
        # a bound token replayed to another destination, or presented
        # without the caller naming the destination, is refused.
        if destination is None:
            raise PlatformEgressError(
                "consent_invalid: token is bound to destination %r; "
                "no destination presented" % (bound_destination,))
        if str(destination) != str(bound_destination):
            raise PlatformEgressError(
                "consent_invalid: token bound to destination %r does "
                "not cover %r" % (bound_destination, destination))
    now = int(time.time()) if now is None else int(now)
    if int(expires_at) <= now:
        raise PlatformEgressError("consent_expired")
    return t


def demonstration_cipher(key, nonce, data):
    """TEST-ONLY stream cipher: HMAC-SHA256 keystream XOR.

    This exists so tests can exercise the "deployer-held key" custody
    property end to end WITHOUT any production-crypto claim. It is NOT
    a production cipher: no nonce-misuse resistance, no
    authentication (ciphertext is malleable -- a bit flip corrupts
    plaintext with no integrity failure), no side-channel hardening.

    It is deliberately NEVER selected by default: ``collect()``
    refuses an ``archive_key`` without an explicit ``cipher=``. Pass
    this function explicitly ONLY in tests/synthetic runs, AND only
    with ``GOV_DEMO_CIPHER_OK=1`` in the environment (wave-37: the
    env gate converts a production copy-paste of the test call from a
    silent misconfiguration into a loud failure). Passing it in a
    production deployment is a deployer misconfiguration this module
    cannot fully detect -- the explicit pass plus the env var IS the
    acknowledgment.
    """
    if not _demo_cipher_enabled():
        raise PlatformEgressError(
            "demonstration_cipher is TEST-ONLY and not enabled: set "
            "%s=1 to use it (tests/synthetic runs only). Production "
            "deployments must pass cipher= a real AEAD keyed by a "
            "deployer-held key; refusing rather than shipping "
            "malleable unauthenticated crypto." % _DEMO_CIPHER_ENV)
    _check_key(key, "archive_key")
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"),
                         hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(b ^ k for b, k in zip(data, out))


class WorkspaceCollector:
    """The governed workspace-collection primitive (F110 closure).

    ``log``: the run's ActionLog (audit entries land here, fail-closed).
    ``policy``: the PolicyEngine the upload is routed through.
    ``egress_allowlist``: set of destination hostnames the deployer
    allows platform egress to. Empty set = everything denied.
    ``consent_key``: the platform-held consent-signing key (bytes >=
    16). REQUIRED -- a collector without the key cannot verify
    consent, so construction fails closed.
    """

    ARCHIVE_NAME = "workspace-archive.bin"

    def __init__(self, log, policy, *, egress_allowlist=(),
                 consent_key=None):
        if consent_key is None:
            raise PlatformEgressError(
                "consent_key_required: the collector cannot verify "
                "consent without the platform-held key")
        _check_key(consent_key, "consent_key")
        self._log = log
        self._policy = policy
        self._allowlist = frozenset(egress_allowlist or ())
        self._consent_key = consent_key

    def _deny(self, reason, **fields):
        entry = {"event": EVENT_DENIED, "decision": "denied",
                 "reason": reason}
        entry.update(fields)
        try:
            self._log.append(entry)
        except Exception:
            pass  # the refusal is the control; log best-effort
        raise PlatformEgressError(reason)

    def collect(self, workspace, *, consent, destination, sink,
                archive_key=None, allow_plaintext=False, cipher=None):
        """Collect ``workspace`` and upload to ``destination`` via ``sink``.

        ``consent``: a token from :func:`issue_consent` (default-off:
        no token -> refusal). The token's MAC is verified against the
        collector's platform-held key.
        ``destination``: hostname string, checked against the deployer
        allowlist through the policy engine.
        ``sink``: duck-typed ``.put(name, payload)`` / ``.host`` upload
        target (tests use an in-memory sink; no network here). If the
        sink exposes ``.host``, it must equal ``destination`` (RT6:
        the policy decision is bound to the actual bytes path, not
        just the destination string); a hostless sink's routing is
        the deployer's responsibility.
        ``archive_key``: deployer-held bytes (>= 16). REQUIRED unless
        ``allow_plaintext`` is explicitly True -- a missing key without
        the explicit opt-in is refused, not silently plaintext.
        ``allow_plaintext``: explicit deployer opt-in to upload the
        archive unencrypted; recorded in the audit entry
        (``plaintext_explicit: True``).
        ``cipher``: the archive cipher, ``(key, nonce, data) -> bytes``.
        REQUIRED when ``archive_key`` is given -- the module never
        silently selects a cipher. Pass a real AEAD in production;
        :func:`demonstration_cipher` is test-only and must be passed
        explicitly.

        Audit ordering (write-ahead): the ``platform_egress_authorized``
        entry lands BEFORE ``sink.put``; a failed put produces an
        explicit ``platform_egress_upload_failed`` entry; the
        ``platform_egress_upload`` completion entry is appended after
        the put returns.
        """
        # (b) default-off with explicit opt-in: consent is checked first,
        # before any workspace bytes are even read. The MAC binds the
        # token to its issuance under the platform-held key. The
        # presented destination is passed so destination-bound tokens
        # (wave-40, F114) are enforced at the point of use.
        try:
            token = check_consent(consent, self._consent_key,
                                  destination=str(destination))
        except PlatformEgressError as exc:
            self._deny(str(exc), destination=str(destination))
        token_id = token["token_id"]

        # (a) route through the egress policy engine: destination
        # allowlist + audit entry, same engine as tool calls.
        allowlisted = str(destination) in self._allowlist
        decision = self._policy.evaluate(
            {"tool": None, "args": {"destination": str(destination)}},
            {"platform_egress": True, "domain_allowlisted": allowlisted})
        if decision.effect != "allow":
            self._deny("policy_denied: %s" % decision.reason,
                       destination=str(destination), token_id=token_id,
                       policy_id=decision.policy_id, flag=decision.flag)

        # (c2) sink/destination binding (RT6 hardening): the policy
        # decision above is evaluated on the ``destination`` STRING,
        # but the bytes travel to ``sink.put``. If the sink exposes a
        # ``.host`` and it does not match the allowlisted
        # destination, refuse -- the policy check must bind the
        # actual bytes path, not just a string. A sink with no
        # ``.host`` cannot be bound; its routing is the deployer's
        # responsibility (same trust class as the injected cipher).
        sink_host = getattr(sink, "host", None)
        if sink_host is not None and str(sink_host) != str(destination):
            self._deny(
                "sink_host_mismatch: sink.host %r does not match "
                "policy-checked destination %r"
                % (sink_host, destination),
                destination=str(destination), token_id=token_id,
                policy_id=decision.policy_id)

        # (c) archive confidentiality posture: fail fast before any
        # workspace bytes are packed -- no silent plaintext.
        if archive_key is None:
            if not allow_plaintext:
                self._deny(
                    "archive_key_required: pass archive_key= (deployer-held "
                    "bytes >= 16) or explicit allow_plaintext=True",
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            plaintext_explicit = True
        else:
            _check_key(archive_key, "archive_key")
            if allow_plaintext:
                # Wave-37 (RT7): contradictory posture. The old code
                # encrypted and silently ignored the explicit flag;
                # silently ignoring an explicit security-relevant flag
                # is exactly what this module refuses to do elsewhere,
                # so the confused call fails closed instead.
                self._deny(
                    "contradictory_confidentiality_posture: archive_key "
                    "given AND allow_plaintext=True -- refusing rather "
                    "than silently ignoring the explicit flag",
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            if cipher is None:
                self._deny(
                    "archive_cipher_required: pass cipher= a real AEAD "
                    "(production) or demonstration_cipher explicitly "
                    "(tests only); the module never selects a cipher "
                    "silently",
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            if cipher is demonstration_cipher and not _demo_cipher_enabled():
                # Wave-37 (RT7): audited early refusal for the
                # copy-paste accident -- the in-function gate below is
                # defense in depth for aliased/wrapped passes.
                self._deny(
                    "demo_cipher_not_enabled: demonstration_cipher is "
                    "TEST-ONLY; set %s=1 (tests/synthetic only) or pass "
                    "cipher= a real AEAD keyed by a deployer-held key"
                    % _DEMO_CIPHER_ENV,
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            plaintext_explicit = False

        # Pack the workspace deterministically (sorted walk).
        ws = Path(workspace)
        blob = []
        files = 0
        for p in sorted(ws.rglob("*")):
            if p.is_file():
                blob.append(b"--- " + str(
                    p.relative_to(ws)).encode() + b" ---\n")
                blob.append(p.read_bytes())
                files += 1
        archive = b"".join(blob)

        encrypted = False
        if archive_key is not None:
            # (d) user-verifiable crypto: the key is deployer-held, passed
            # in by the caller, and the cipher is deployer-chosen. No
            # vendor key-fetch exists in this module.
            nonce = os.urandom(16)
            plaintext = archive
            try:
                # F118 (wave-42, RT11): guard the raw cipher OUTPUT, not
                # the nonce-prefixed blob. The old code prepended the
                # 16-byte nonce first, so a truncating cipher that dropped
                # fewer than 16 bytes still produced a blob LONGER than
                # the plaintext (length check sailed through), and the
                # truncated plaintext was no longer a contiguous
                # substring (verbatim check sailed through too). Result:
                # nonce + d[:-1] uploaded while the audit claimed
                # encrypted=True -- the exact false confidentiality claim
                # F117 was filed to stop. bytes() coerces bytearray and
                # turns non-bytes returns into a TypeError INSIDE the
                # audited-failure path (F113 property preserved: no raw
                # exception escapes unaudited).
                cipher_out = bytes(cipher(archive_key, nonce, archive))
            except Exception as exc:
                # Wave-40 (F113): a RAISING cipher must refuse AUDITED,
                # not propagate raw. The RT7 early refusal
                # (``demo_cipher_not_enabled``) only fires when
                # ``cipher is demonstration_cipher`` -- an
                # aliased/wrapped pass (functools.partial, lambda,
                # decorator) skips that identity check and the
                # in-function env gate's raise used to escape with zero
                # audit entries. The same holds for any deployer cipher
                # that fails: the refusal is the control, and the
                # control is audited.
                self._deny(
                    "archive_cipher_failed: the archive cipher raised "
                    "%s: %s" % (type(exc).__name__, exc),
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            # Wave-41 (F117, RT10/ADI): a cipher that RETURNS without
            # raising but emits degenerate output -- identity/no-op
            # (plaintext on the wire), empty, or truncated -- would
            # otherwise upload with the write-ahead audit entry claiming
            # ``encrypted: True``. The module trusts the deployer-chosen
            # cipher's construction (it cannot re-derive the AEAD), but
            # it does not have to trust the OUTPUT's shape: a real
            # cipher never emits the plaintext verbatim, and no cipher
            # legitimately returns FEWER bytes than it was given
            # (truncation is data loss, not encryption). Either
            # degenerate shape refuses AUDITED here, before the
            # authorized entry is written. Notes on the boundary:
            # (a) same-length non-verbatim output (stream-cipher shape --
            # including the sanctioned TEST-ONLY demonstration_cipher,
            # HMAC-keystream XOR) PASSES: it is a functional cipher,
            # not a degenerate one; cipher quality is the deployer's
            # choice and outside this check's remit. (b) Residual
            # (documented): a cipher that transforms the plaintext
            # non-trivially without encrypting (e.g. base64) still
            # passes -- the deployer chose the cipher, and a malicious
            # deployer is outside the threat model.
            # F118: run the shape check on cipher_out (pre-nonce), so a
            # sub-nonce truncation cannot hide behind the nonce's bytes.
            if plaintext and (plaintext in cipher_out
                              or len(cipher_out) < len(plaintext)):
                self._deny(
                    "archive_cipher_ineffective: the archive cipher "
                    "returned degenerate output (%d bytes for %d "
                    "plaintext bytes; plaintext %s in output) -- "
                    "refusing rather than uploading attacker-readable "
                    "bytes labeled encrypted"
                    % (len(cipher_out), len(plaintext),
                       "present" if plaintext in cipher_out else "absent"),
                    destination=str(destination), token_id=token_id,
                    policy_id=decision.policy_id)
            archive = nonce + cipher_out
            encrypted = True

        digest = hashlib.sha256(archive).hexdigest()

        # WRITE-AHEAD: the authorization entry lands BEFORE the side
        # effect. If this append raises, no upload is attempted
        # (fail-closed) -- the exception propagates.
        self._log.append({
            "event": EVENT_AUTHORIZED,
            "decision": "authorized",
            "destination": str(destination),
            "destination_allowlisted": True,
            "token_id": token_id,
            "files_packed": files,
            "archive_bytes": len(archive),
            "archive_sha256": digest,
            "encrypted": encrypted,
            "plaintext_explicit": plaintext_explicit,
            "policy_id": decision.policy_id,
        })

        try:
            sink.put(self.ARCHIVE_NAME, archive)
        except Exception as exc:
            # The side effect failed: record the failed attempt
            # explicitly (best-effort; the put error propagates
            # regardless so a failed upload is never silent).
            try:
                self._log.append({
                    "event": EVENT_UPLOAD_FAILED,
                    "decision": "failed",
                    "destination": str(destination),
                    "token_id": token_id,
                    "archive_sha256": digest,
                    "error": "%s: %s" % (type(exc).__name__, exc),
                })
            except Exception:
                pass
            raise PlatformEgressError(
                "upload_failed: %s: %s" % (type(exc).__name__, exc))

        # Completion entry: informational -- the write-ahead authorized
        # entry above is the ordering guarantee, so a crash between
        # put and this append cannot produce an unaudited exfiltration.
        self._log.append({
            "event": EVENT_UPLOAD,
            "decision": "allowed",
            "destination": str(destination),
            "destination_allowlisted": True,
            "token_id": token_id,
            "files_packed": files,
            "archive_bytes": len(archive),
            "archive_sha256": digest,
            "encrypted": encrypted,
            "plaintext_explicit": plaintext_explicit,
            "policy_id": decision.policy_id,
        })
        return {"uploaded": True, "files": files,
                "archive_bytes": len(archive), "archive_sha256": digest,
                "encrypted": encrypted,
                "plaintext_explicit": plaintext_explicit,
                "destination": str(destination),
                "token_id": token_id}
