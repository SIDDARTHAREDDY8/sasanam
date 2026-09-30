"""Append-only, HMAC-authenticated action log.

Each entry is one JSON line. Integrity comes from two layers:

1. **HMAC chain.** Every entry stores ``hash = HMAC-SHA256(key,
   key_epoch || prev_hash || canonical_json(entry))``. The canonical form
   includes the reserved ``seq``, ``ts`` (wall clock), ``key_epoch`` and --
   since wave-72 -- the anchor ``epoch_id`` (``e%08d`` of the epoch's first
   seq), so backdating, reordering, and cross-epoch moves without the key
   break verification. Without the key an
   attacker cannot recompute a valid chain after altering history, so
   truncate-and-rebuild and history-rewrite attacks are detected by
   :func:`verify_chain`. The legacy unkeyed :func:`_entry_hash` is kept only
   as the documented attacker primitive used by the red-team tests.

2. **Signed checkpoints (STH-style).** After every append, a checkpoint
   ``{seq, hash}`` authenticated with the same key is written to
   ``checkpoints.jsonl`` next to the log. ``verify_chain`` requires the log
   to be at least as long as the newest checkpoint and to agree with it at
   that sequence number, which defeats silent tail truncation. A non-empty
   log whose checkpoint sidecar is missing, empty, or corrupt fails
   verification CLOSED (F27/F28): ``ok=True`` is never reported on the
   strength of zero checked checkpoints, and corrupt content is a verdict,
   never an exception.

Key custody: the HMAC key comes from the ``GOV_LOG_KEY`` environment
variable (``GOV_LOG_KEY_EPOCH`` optionally names the key version and is
bound into every MAC), or from a file-backed keyring via
``GOV_KEYRING_FILE``. Resolution is STRICT (R6c) and lives in the
``gov.keyprovider`` chokepoint (see ``workstreams/architect/
KEY_MANAGEMENT_DESIGN.md``): ``GOV_LOG_KEY`` unset raises
``NoKeyConfiguredError`` — there is no silent fallback and no dev-key
path at all (wave-81: the public development key and every dev-key
opt-in were deleted from ``gov/``; F73's lesson is now structural —
unsetting one env var can no longer reduce the log to a key the whole
world knows, because no such key exists in the codebase). Deployment
mode follows the wave-61 precedent:
``GOV_DEPLOYMENT_MODE`` (or the ``deployment_mode=`` kwarg, which wins),
default ``"production"`` (least-privilege); the mode is validated but
no longer selects a key story — key provisioning is explicit in every
mode. Production deployments MUST set ``GOV_LOG_KEY`` (or
``GOV_KEYRING_FILE``, or activate a keyring via ``gov.keys`` /
``gov.kms``). ``key_epoch`` is stored on every entry and
checkpoint so key rotations are visible in the log.

``format_version`` is frozen at 1 for log entries; the verifier rejects
any other entry format, fail-closed. Checkpoints use format 1 (HMAC
only) or format 2 (HMAC + public-key signed tree head, see section 3).

3. **Public-key signatures + Merkle history tree (P2).** When an
``ActionLog`` is constructed with ``signer=`` (a ``gov.signing.Signer``),
every entry additionally carries an Ed25519 signature (``ed_sig`` /
``sig_key_id``, plus ``sig_key_version`` when the signer is keyset-aware
-- ``gov.keyset.KeysetSigner``, wave-183; the version is bound into the
v2 signature body -- all excluded from the HMAC canonical form, so chain
semantics for existing HMAC logs are byte-identical), and every
checkpoint is written as format 2: the HMAC fields plus a Merkle root
over entries 1..seq and Ed25519 signature(s) over the checkpoint body.
``signer=None`` (the default) keeps behavior byte-identical to today.

Certificate Transparency mapping (Laurie/Langley/Kasper, RFC 6962) --
our checkpoint format 2 IS the signed tree head (STH):

| RFC 6962 STH field   | checkpoint v2 field              |
|----------------------|----------------------------------|
| version              | format_version (= 2)             |
| tree_size            | seq                              |
| timestamp            | ts                               |
| sha256_root_hash     | merkle_root                      |
| tree_head_signature  | sigs (threshold set, A5)         |
| (no equivalent)      | hash  (HMAC chain tip at seq)    |
| (no equivalent)      | mac   (HMAC checkpoint MAC)      |
| (no equivalent)      | roster_hash (A5 signer-set bind) |

Roles: the ``ActionLog`` writer is the CT log operator; third parties
calling ``verify_checkpoint_signatures`` / ``prove_inclusion`` /
``prove_consistency`` are CT auditors/monitors. CT's gossip protocol
(detecting an equivocating log) is OUT OF SCOPE here by design: our
equivalent is the out-of-band trusted signing-key set -- see
``gov/signing.py``. Do not mistake HMAC checkpoints for STHs (the
literature review's explicit warning): HMAC gives no non-repudiation.

Crosby & Wallach ("Efficient Data Structures for Tamper-Evident
Logging", USENIX Security 2009) graduation criterion, adopted: a hash
chain forces every auditor to replay the whole log; the history tree
lets an auditor verify one entry with an O(log n) inclusion proof and
verify that a newer head extends an older one with an O(log n)
consistency proof -- no HMAC key, no full replay. That is what
``prove_inclusion`` / ``prove_consistency`` implement.

A5 (scoped TUF): checkpoint signatures are k-of-n threshold over a
roster signed by an offline root key (``gov/signing.py``). Per-entry
Ed25519 stays single-signature and the HMAC per-entry hot path stays
untouched -- threshold-signing every entry would be operationally
absurd. The threshold property: compromising fewer than k
checkpoint-signing keys cannot forge a checkpoint.
"""

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from .exchange_ledger import check_exchange_read

from . import merkle as _merkle
from . import signing as _signing
from . import ed25519 as _ed25519
from . import keyset as _keyset
from . import token_hygiene as _token_hygiene  # Wave-234: unconditional (fail-closed)
# NOTE (wave-137): gov.anchoring is imported LAZILY inside
# export_bundle/verify_export_bundle, never at module level. The
# anchor client (gov.anchor_backend) is executor-side only: importing
# gov.sandbox must not pull it into the process (deny-all egress --
# see tests/test_w72_anchor.py::test_sandbox_has_no_anchor_client).

GENESIS = "GENESIS"
FORMAT_VERSION = 1
# Wave-234 (octet-digest receipt chaining): the prev_record_octets_digest
# value for the genesis entry (seq 1), which has no previous record. A
# fixed, documented constant -- never a digest of anything -- so it
# cannot be mistaken for a real link. Stored on the entry like every
# other link field, hence HMAC-bound via _canonical.
OCTET_DIGEST_GENESIS = "0" * 64
# Checkpoint format 2: HMAC fields plus the signed tree head
# (merkle_root, threshold sigs, roster binding). Entries stay v1.
CHECKPOINT_SIG_VERSION = 2

# Wave-72 (Haber-Stornetta anchoring): the anchor-epoch id format. An epoch
# is a checkpoint-bounded segment of the chain; its id is "e%08d" of the
# seq of its first entry -- derivable, unique, monotonic, no state file.
_EPOCH_ID_RE = None  # compiled lazily (re import is local to _valid_epoch_id)
_FIRST_EPOCH_ID = "e00000001"


def _valid_epoch_id(value):
    """True when ``value`` is a well-formed wave-72 epoch id (``e%08d``)."""
    global _EPOCH_ID_RE
    if _EPOCH_ID_RE is None:  # lazy: keep the hot import surface unchanged
        import re
        _EPOCH_ID_RE = re.compile(r"^e\d{8}$")
    return isinstance(value, str) and _EPOCH_ID_RE.match(value) is not None

# F25: how long an append waits for the log's exclusive lock before
# failing closed. A crashed lock holder's flock is released by the
# kernel on process death, so a timeout means a LIVE process is stuck
# mid-append — refusing to write unlocked is the safe direction.
APPEND_LOCK_TIMEOUT_SECS = 30
_APPEND_LOCK_POLL_SECS = 0.02


class AppendLockError(OSError):
    """F25: the action-log append lock could not be acquired in time.

    Fail-closed: the entry was NOT written and the caller must not treat
    the action as logged. Raised instead of writing unlocked, which is
    what forked the HMAC chain under concurrent writers (W7-3).
    """


class LogUnverifiableError(Exception):
    """Fail-closed: the action log (or its checkpoint sidecar) cannot be
    authenticated — corrupt, tampered, truncated, or missing its
    checkpoint anchor.

    Raised by :func:`require_verified`; the dict-returning :func:`_verify`
    reports the same conditions as ``{"ok": False, "error": ...}``
    instead of raising, so audit tooling (e.g. report generators) never
    crashes on a corrupt file (F28). Never treat the log as verified
    when this is raised."""


@contextlib.contextmanager
def _append_locked(path):
    """Hold an exclusive flock on *path* across the critical section.

    F25: serializes ``ActionLog.append`` across processes (POSIX
    ``fcntl.flock``), so concurrent appends linearize — no two writers
    can assign the same sequence number or fork ``prev_hash``. Waits up
    to ``APPEND_LOCK_TIMEOUT_SECS`` for the lock, then raises
    ``AppendLockError``: the write never happens unlocked.
    """
    f = open(path, "a", encoding="utf-8")
    try:
        deadline = time.monotonic() + APPEND_LOCK_TIMEOUT_SECS
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise AppendLockError(
                        "could not acquire the append lock on %s within "
                        "%ds; refusing to write unlocked" % (path,
                        APPEND_LOCK_TIMEOUT_SECS))
                time.sleep(_APPEND_LOCK_POLL_SECS)
        try:
            yield f
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()

# Wave-81: the public development key and the dev-key double opt-in
# (the in-code enabler plus the dev opt-in environment variable) were
# DELETED from gov/ entirely. There is no key fallback of any kind on the log
# path: _active_key() resolves configured keys only (GOV_LOG_KEY /
# GOV_KEYRING_FILE via gov.keyprovider) and raises
# NoKeyConfiguredError otherwise. Test harnesses provision an explicit
# key (see tests/keyfixture.py) through the same env backend
# production uses.


def _active_key(deployment_mode=None):
    """Return (key_bytes, key_epoch). STRICT (R6c) — F73 fix, wave-81
    final form.

    Resolution is delegated to :mod:`gov.keyprovider` (the wave-69
    chokepoint): configured env key → configured keyring file → LOUD
    ``NoKeyConfiguredError`` in every deployment mode. There is no
    dev-key fallback on any path (wave-81 deleted the dev key and all
    opt-ins from ``gov/``); configured keys are operator-chosen and
    used as-is.

    ``deployment_mode`` (wave-70): an explicit mode declaration that
    wins over ``GOV_DEPLOYMENT_MODE`` for this resolution, exactly the
    ``resolve_active_key`` precedence (explicit kwarg > env > default
    ``"production"``). ``None`` (default) keeps the pre-wave-70
    behavior byte-identical. The mode is validated (unknown modes fail
    fast) but no longer selects a key story: provisioning is explicit
    in every mode.

    Behavior for every pre-wave-81 configured-key case is byte-identical
    (refusal messages included); chain mechanics are untouched.
    """
    # Lazy import: gov/keyprovider.py imports gov/keys.py at its top
    # level, and gov/keys.py imports this module at its top level, so a
    # top-level import here would be circular. By call time all three
    # modules are fully initialized.
    from . import keyprovider as _kp
    return _kp.resolve_active_key(deployment_mode)


class NoAuditSigningKeyError(Exception):
    """The audit-signing key configuration is malformed.

    Raised by :func:`resolve_audit_signer` when a signing key IS
    configured but unusable (bad hex, wrong length, unreadable or
    group/world-accessible key file). An ABSENT configuration is not
    an error -- it resolves to ``None`` (HMAC-only log) -- but a
    misconfigured one must be loud at log open, never a silent
    downgrade to unsigned entries.
    """


_AUDIT_KEY_ENV = "GOV_AUDIT_SIGNING_KEY"
_AUDIT_KEY_FILE_ENV = "GOV_AUDIT_SIGNING_KEY_FILE"


def resolve_audit_signer(explicit=None):
    """Resolve the audit-log entry-signing key (P2), or ``None``.

    Precedence mirrors ``gov.anchorer.resolve_anchor_key`` (the
    established operator-held Ed25519 seed idiom): explicit hex seed >
    ``GOV_AUDIT_SIGNING_KEY`` (hex) > ``GOV_AUDIT_SIGNING_KEY_FILE``
    (0600 file holding hex). Returns a ``gov.signing.Ed25519Signer``,
    or ``None`` when nothing is configured (the log stays HMAC-only,
    byte-identical to today).

    A dedicated key, not the anchor key: per-entry signing is a hot
    path with the seed resident in process memory for the run's
    lifetime, while the anchor key signs occasional anchoring
    statements. Domain separation (``gov-entry-sig/v1``) already makes
    cross-artifact signature reuse cryptographically impossible; the
    separate variable additionally decouples "signed audit entries"
    from "anchoring enabled" operationally.

    Fail-closed: malformed configuration raises
    :class:`NoAuditSigningKeyError` -- a malformed configured value must
    break loudly at :func:`open_audit_log`, never produce silently
    unsigned entries an operator believed were signed. (An entirely
    ABSENT configuration is not an error: it resolves to ``None``,
    HMAC-only.)
    """
    source = "explicit seed" if explicit is not None else _AUDIT_KEY_ENV
    seed_hex = (explicit or os.environ.get(_AUDIT_KEY_ENV, "")).strip()
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise NoAuditSigningKeyError(
                "%s is not hex" % source)
        if len(seed) != 32:
            raise NoAuditSigningKeyError(
                "%s must be 32 bytes" % source)
        return _signing.Ed25519Signer(seed)
    key_file = os.environ.get(_AUDIT_KEY_FILE_ENV, "").strip()
    if not key_file:
        return None
    # Wave-91 (G1) posture, same as the anchor key: the permission
    # gate runs BEFORE any key bytes are read; a group/world-accessible
    # file is refused, not warned about. Lazy import mirrors anchorer.
    from .keyfiles import require_private_key_file
    try:
        require_private_key_file(key_file)
    except (FileNotFoundError, PermissionError) as e:
        raise NoAuditSigningKeyError(
            "refusing %s %s: %s" % (_AUDIT_KEY_FILE_ENV, key_file, e))
    try:
        seed = bytes.fromhex(Path(key_file).read_text(
            encoding="utf-8").strip())
    except (OSError, ValueError) as e:
        raise NoAuditSigningKeyError(
            "%s unreadable or not hex: %s" % (_AUDIT_KEY_FILE_ENV, e))
    if len(seed) != 32:
        raise NoAuditSigningKeyError(
            "%s must hold a 32-byte hex seed" % _AUDIT_KEY_FILE_ENV)
    return _signing.Ed25519Signer(seed)


def open_audit_log(path, **kwargs):
    """Open the production audit log at ``path``.

    ``ActionLog(path, signer=<resolved>, **kwargs)``. Signer resolution
    (wave-183): when ``GOV_AUDIT_KEYSET_FILE`` names a versioned keyset
    document the signer is a ``gov.keyset.KeysetSigner`` for the
    keyset's primary version -- any keyset misconfiguration raises
    ``gov.keyset.KeysetError`` loudly, never silently downgrades. When
    no keyset is configured this is ``resolve_audit_signer()``: a
    configured audit-signing key yields Ed25519 ``ed_sig``/``sig_key_id``
    entries and format-2 checkpoints (signed tree heads); an absent key
    yields an HMAC-only log, byte-identical to ``ActionLog(path)``. An
    explicit ``signer=`` kwarg (including ``None``) is respected as-is
    -- explicit always wins over the environment.

    This is the seam the production constructions go through so the
    P2 signature layer is actually live on real logs instead of
    test-only.
    """
    if "signer" not in kwargs:
        kwargs["signer"] = _resolve_entry_signer()
    return ActionLog(path, **kwargs)


def _resolve_entry_signer():
    """Resolve the per-entry signer: keyset-aware, then legacy.

    ``GOV_AUDIT_KEYSET_FILE`` set -> ``(Keyset, KeysetSigner)`` from
    ``gov.keyset.keyset_signer_from_config`` (fail-closed on any
    misconfiguration). Unset -> :func:`resolve_audit_signer` (the
    legacy single-seed path, behavior unchanged).
    """
    _ks, signer = _keyset.keyset_signer_from_config()
    if _ks is not None:
        return signer
    return resolve_audit_signer()


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


# P2: signature envelope fields. Excluded from the HMAC canonical form
# so chain semantics for existing HMAC logs are byte-identical: entries
# without these fields canonicalize exactly as before, and the HMAC
# never depends on the public-key signature layer. Wave-183 adds
# sig_key_version (the keyset version a KeysetSigner signed as); it is
# bound into the v2 signature body, not the canonical content, so
# Merkle leaves stay identical across signer types for the same event.
_SIG_ENVELOPE_FIELDS = frozenset({"ed_sig", "sig_key_id",
                                  "sig_key_version"})

# Domain separation for the signature layer (distinct from the Merkle
# tree's own domains in gov/merkle.py).
_ENTRY_SIG_DOMAIN = b"gov-entry-sig/v1\x00"
# Wave-183: distinct domain for version-bound entry signatures. A
# versioned envelope must never verify as a legacy one and vice versa.
_ENTRY_SIG_DOMAIN_V2 = b"gov-entry-sig/v2\x00"
_CHECKPOINT_SIG_DOMAIN = b"gov-checkpoint-sig/v1\x00"
# Single-signer checkpoints carry no roster; this conventional marker
# keeps the signed body shape identical to the threshold case.
_SINGLE_ROSTER_MARK = "single:1-of-1:"


def _canonical(entry):
    payload = {k: v for k, v in entry.items()
               if k != "hash" and k not in _SIG_ENVELOPE_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _entry_sig_body(entry):
    """Bytes a per-entry Ed25519 signature covers: canonical content
    (sig fields excluded) plus the chain hash, domain-separated. Binds
    the signature to both the entry's content and its chain position.

    Wave-183: when the envelope carries ``sig_key_version`` (written by
    ActionLog for keyset-aware signers), the version is
    cryptographically BOUND into the signed bytes under a distinct
    domain (``gov-entry-sig/v2``). Entries without a version keep the
    byte-identical v1 body. Tampering with or stripping the version
    changes the verified bytes, so verification fails -- there is no
    silent downgrade to the legacy path.
    """
    version = entry.get("sig_key_version")
    core = (_canonical(entry).encode("utf-8") + b"\x00")
    tail = str(entry["hash"]).encode("utf-8")
    if isinstance(version, bool) or not isinstance(version, int):
        # Legacy path (no version bound): byte-identical to the
        # pre-wave-183 body.
        return _ENTRY_SIG_DOMAIN + core + tail
    return (_ENTRY_SIG_DOMAIN_V2 + core
            + str(version).encode("utf-8") + b"\x00" + tail)


def verify_entry_against_keyset(entry, keyset):
    """Keyset-aware per-entry signature verification (wave-183).

    ``keyset`` is a ``gov.keyset.Keyset`` (public material). Returns
    ``(ok, reason)``; never raises. The envelope's version selects both
    the verifying key (via ``Keyset.find_verifying_key``) and the
    signature body (v2 when a version is bound, v1 for legacy
    entries). Revoked versions refuse; version/key_id confusion fails
    closed; malformed envelopes fail closed.

    Contract: verify the keyset ONCE with ``Keyset.verify()`` before
    using it here (``keyset_signer_from_config`` already does). This
    helper trusts the keyset's structure; the keyset's own lineage /
    revocation authorization is the caller's one-time job, not a
    per-entry cost.
    """
    key_version, reason = keyset.find_verifying_key(entry)
    if key_version is None:
        return False, reason
    sig_hex = entry.get("ed_sig")
    sig = None
    if isinstance(sig_hex, str):
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            sig = None
    if sig is None or len(sig) != 64:
        return False, "envelope carries a malformed ed_sig"
    try:
        body = _entry_sig_body(entry)
    except Exception as e:  # missing "hash" etc. -> not verifiable
        return False, "cannot reconstruct signature body: %s" % e
    # gov.ed25519.verify never raises; malformed is False.
    if _ed25519.verify(key_version.public_key, body, sig):
        return True, reason
    return False, "signature does not verify"


def _leaf_input(entry):
    """Bytes hashed into the Merkle leaf for an entry: canonical content
    plus the chain hash.

    Commits to the full content AND the stored hash string, so an
    F70-style length-preserving rewrite that keeps the hash string
    still changes the leaf. The per-entry ``ed_sig`` is deliberately
    NOT in the leaf: re-signing (e.g. after a signer rotation) must not
    change tree roots; the signature itself is verified per-entry
    against the same content+hash the leaf commits to.
    """
    return (_canonical(entry).encode("utf-8") + b"\x00"
            + str(entry["hash"]).encode("utf-8"))


def _checkpoint_sig_body(seq, entry_hash, merkle_root_hex, key_epoch,
                         threshold, roster_hash, ts, key_version=None):
    """Bytes checkpoint Ed25519 signature(s) cover (the STH body).

    F202: ``ts`` (the operator's claimed checkpoint wall-clock time) is
    bound into the body -- a checkpoint whose ``ts`` was rewritten after
    signing fails verification. Pre-F202 signatures never covered ``ts``
    and no longer verify (intended format consequence: signed
    checkpoints are new -- no deployed legacy population -- and a
    pre-F202 head is unfixable by construction).

    Wave-186: ``key_version`` (the keyset version the signing key spoke
    for) is bound alongside ``ts`` when the signer is keyset-aware, so
    rewriting or stripping the version breaks the signature exactly
    like ``ts`` tampering does. ``None`` (plain unversioned signers)
    keeps the exact F202 body shape -- post-F202 checkpoints without a
    version keep verifying.
    """
    if not isinstance(ts, str) or not ts:
        raise TypeError(
            "checkpoint ts must be a non-empty string for the sig body")
    if key_version is None:
        fields = ("%d|%s|%s|%s|%d|%s|%s"
                  % (seq, entry_hash, merkle_root_hex, key_epoch,
                     threshold, roster_hash, ts))
    else:
        if isinstance(key_version, bool) or not isinstance(
                key_version, int) or key_version < 1:
            raise TypeError(
                "checkpoint key_version must be an integer >= 1 for "
                "the sig body")
        fields = ("%d|%s|%s|%s|%d|%s|%s|kv%d"
                  % (seq, entry_hash, merkle_root_hex, key_epoch,
                     threshold, roster_hash, ts, key_version))
    return _CHECKPOINT_SIG_DOMAIN + fields.encode("utf-8")


def _entry_hash(prev_hash, canonical):
    """Legacy UNKEYED SHA-256 chain primitive.

    Kept for compatibility and as the documented attacker primitive: the
    red-team suite uses it to model an attacker who knows the algorithm but
    not the HMAC key. New code must use :func:`_compute_mac`.
    """
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _compute_mac(key, key_epoch, prev_mac, canonical):
    msg = ("%s|%s|%s" % (key_epoch, prev_mac, canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _checkpoint_mac(key, key_epoch, seq, entry_hash, tip_gen=None,
                    ts=None):
    """Domain-separated MAC over a checkpoint anchor.

    With ``tip_gen`` None (the default) this is the legacy
    per-append anchor domain, so every existing checkpoint line
    verifies unchanged. With an integer ``tip_gen`` it is the
    tip-generation PIN domain (F72): the pin vouches that a tip of
    generation ``tip_gen`` was written over exactly the sidecar prefix
    ending at this line, so a replayed older tip is recognized as
    stale. The two domains never collide.

    F202: when ``ts`` is given (v2 signed checkpoints), it is bound
    into the MAC -- rewriting ``ts`` breaks the MAC, so the
    operator-side ``_verify``/``verify_chain_tip`` seams detect the
    tamper. Format-1 checkpoints and tip-generation pins carry no
    ``ts`` and keep the legacy domain.
    """
    if tip_gen is None:
        if ts is None:
            msg = ("checkpoint|%s|%d|%s"
                   % (key_epoch, seq, entry_hash)).encode("utf-8")
        else:
            msg = ("checkpoint|%s|%d|%s|%s"
                   % (key_epoch, seq, entry_hash, ts)).encode("utf-8")
    else:
        msg = ("checkpoint-tipgen|%s|%d|%s|%d"
               % (key_epoch, seq, entry_hash, tip_gen)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _pin_gen_of(cp):
    """Validated tip-generation of a checkpoint dict, or None.

    Returns the integer generation when the dict carries a well-formed
    ``tip_gen`` (a tip-generation pin line), else None (a legacy
    per-append anchor). Centralizes the shape check so the MAC-domain
    dispatch cannot be confused by a non-integer ``tip_gen``.
    """
    tg = cp.get("tip_gen")
    if isinstance(tg, int) and not isinstance(tg, bool) and tg >= 1:
        return tg
    return None


def _marker_sets(entries):
    """Interrupted-execution marker sets over parsed log entries.

    Returns ``(auth, done)``: approval_id -> latest seq of the
    ``execution_authorized`` marker and of the ``approved_executed``
    completion marker. An approval is interrupted when its latest
    authorization seq exceeds its latest completion seq. Only
    ``tool_call`` entries with a string approval_id participate;
    anything else is ignored (callers run this on just-verified
    bytes, or on an explicitly untrusted scan for comparison
    against the MAC'd manifest).
    """
    auth, done = {}, {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "tool_call":
            continue
        aid = e.get("approval_id")
        aseq = e.get("seq")
        if not isinstance(aid, str) or not aid:
            continue
        if not isinstance(aseq, int) or isinstance(aseq, bool):
            continue
        decision = e.get("decision")
        if decision == "execution_authorized":
            if aseq > auth.get(aid, 0):
                auth[aid] = aseq
        elif decision == "approved_executed":
            if aseq > done.get(aid, 0):
                done[aid] = aseq
    return auth, done


def _max_pinned_tip_gen(cp_bytes, key, key_epoch):
    """Newest MAC'd tip-generation pin in the checkpoint sidecar.

    Returns 0 when no valid pin line is present. Only lines whose pin
    domain MAC verifies under the active epoch count: without the key
    a run-dir writer can neither mint a pin nor alter a pin's
    ``tip_gen`` (any change breaks the MAC and the line is skipped).
    """
    newest = 0
    for line in cp_bytes.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            cp = json.loads(line)
        except ValueError:
            continue
        if not isinstance(cp, dict):
            continue
        gen = cp.get("tip_gen")
        seq = cp.get("seq")
        if (not isinstance(gen, int) or isinstance(gen, bool)
                or gen < 1):
            continue
        if (not isinstance(seq, int) or isinstance(seq, bool)
                or seq < 0):
            continue
        if cp.get("key_epoch") != key_epoch:
            continue
        mac = cp.get("mac")
        if not isinstance(mac, str):
            continue
        expect = _checkpoint_mac(key, key_epoch, seq,
                                 cp.get("hash", ""), gen)
        if hmac.compare_digest(mac, expect) and gen > newest:
            newest = gen
    return newest


def _append_tip_gen_pin(path, seq, entry_hash, gen):
    """Append a MAC'd tip-generation pin to the checkpoint sidecar (F72).

    The pin binds ``gen`` -- the tip generation about to be written --
    to the sidecar's current contents, so a later sweep can tell a
    replayed older tip from the live one. Best-effort: raises OSError
    on I/O failure (callers degrade to a weaker replay signal for this
    generation, never to weaker verification). The pin is one small
    O_APPEND write, atomic without the log's append lock; concurrent
    pins with the same generation are benign (same replay bound).
    """
    key, epoch = _active_key()
    pin = {
        "seq": seq,
        "hash": entry_hash,
        "key_epoch": epoch,
        "format_version": FORMAT_VERSION,
        "tip_gen": gen,
        "mac": _checkpoint_mac(key, epoch, seq, entry_hash, gen),
    }
    cp_path = Path(str(path)).parent / "checkpoints.jsonl"
    cp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cp_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(pin, ensure_ascii=True, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _approval_record_mac(key, key_epoch, canonical):
    """F34: domain-separated HMAC for approval-queue integrity digests.

    Approval records live outside the action log's hash chain (they are
    queued before the approving decision is logged), so the log's MAC
    cannot cover them. They get their own domain-separated MAC under the
    SAME active log key: a forger with run-dir access but without the key
    cannot mint a valid record digest, which closes F34's record-forgery
    vector. ``key_epoch`` is bound into the MAC and verified against the
    keyring, so rotation is explicit. Under the PUBLIC development key this
    gives no forgery resistance to anyone who read the docs — the report
    says so (F34/F29 residual).
    """
    msg = ("approval-record|%s|%s" % (key_epoch, canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _break_glass_ticket_mac(key, key_epoch, canonical):
    """F49: domain-separated HMAC for human-provisioned break-glass tickets.

    Tickets are provisioned out-of-band by the human operator BEFORE the
    run starts and verified (never trusted) at run start. Same key as the
    log, distinct domain string, so a ticket MAC cannot be confused with
    an approval-record MAC. Under the PUBLIC development key this gives no
    forgery resistance — the honest residual is documented at the F49
    entry: the boundary is key custody (same trust anchor as GOV_LOG_KEY).
    """
    msg = ("break-glass-ticket|%s|%s" % (key_epoch, canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class LogFullError(Exception):
    """Raised when the audit log reached its configured size cap.

    F22 fail-closed: once the cap is hit, no further entry may be
    appended — the executor refuses to act rather than act unlogged.
    Operators archive the full log (``gov verify --keyring`` still
    verifies archives) and start a fresh one; the rotation procedure is
    documented in the policy file's ``log_limits`` comment.
    """


class OctetDigestError(Exception):
    """Raised when octet-digest chain linking fails (wave-234).

    ``code`` is the chain-domain taxonomy refusal code
    (``chain-octet-digest-mismatch`` / ``chain-octet-digest-absent`` /
    ``chain-record-truncated``); ``detail`` names the failing sequence
    number. The strict writer raises this instead of linking without
    the previous record's transmitted octets (fail closed, never
    silently degrade to semantic chaining).
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s%s" % (code, (": " + detail) if detail else ""))


class ActionLog:
    """Append-only JSONL log with HMAC chaining and signed checkpoints."""

    def __init__(self, path, max_bytes=None, signer=None, roster=None, *,
                 deployment_mode=None, require_octet_digest=False):
        """Create/open the log at ``path``.

        ``signer`` (P2): an optional ``gov.signing.Signer`` (or
        ``ThresholdSigner`` for k-of-n checkpoint signatures, A5).
        ``None`` (default) keeps behavior byte-identical to the
        HMAC-only log. ``roster``: the offline-root-signed signer
        roster dict (A5) -- REQUIRED when the signer needs threshold
        k > 1, otherwise the checkpoint cannot bind its signer set
        (fail-fast here, not at first append).
        ``deployment_mode`` (wave-70): an explicit deployment-mode
        declaration for this log instance (wave-61 precedent: explicit
        kwarg > ``GOV_DEPLOYMENT_MODE`` > least-privilege default
        ``"production"``; unknown modes fail fast HERE at
        construction). Keyword-only; ``None`` (default) preserves the
        pre-wave-70 behavior exactly (env, then production default).
        The declaration flows into this instance's key-resolving
        operations (``append``, ``write_checkpoint``). Module-level
        verification helpers (``_verify``, ``verify_chain_tip``, ...)
        deliberately keep the default: verification must work
        regardless of a creation-time declaration.
        ``require_octet_digest`` (wave-234): strict writer mode for
        octet-digest chain linking. When True, ``append`` refuses
        (``OctetDigestError`` naming ``chain-octet-digest-absent``)
        rather than link a new entry without the previous record's
        transmitted octets. Keyword-only; ``False`` (default) keeps
        pre-wave-234 behavior. ``refresh()`` always captures the tail
        record's raw bytes, so the refusal is defense-in-depth.
        """
        self.path = Path(path)
        self.checkpoint_path = self.path.parent / "checkpoints.jsonl"
        self._deployment_mode = deployment_mode
        # Wave-234: strict octet-digest writer mode (fail closed when
        # the previous record's transmitted octets are unavailable).
        self._require_octet_digest = bool(require_octet_digest)
        if deployment_mode is not None:
            # Fail fast on unknown modes at construction (the per-append
            # re-resolution would raise the same ValueError, but a
            # misconfigured mode must not survive past construction).
            # Lazy import: same circularity as _active_key (see above).
            from . import keyprovider as _kp
            _kp.resolve_deployment_mode(deployment_mode)
        self._max_bytes = None
        if max_bytes is not None:
            self.configure_guard(max_bytes)
        self._signer = signer
        self._roster = roster
        if signer is not None and isinstance(
                signer, _signing.ThresholdSigner) \
                and signer.threshold > 1 and roster is None:
            raise ValueError(
                "threshold signing (k=%d) requires the offline-root-signed "
                "roster: pass roster=... so checkpoints bind their signer "
                "set" % (signer.threshold,))
        self._merkle = None  # MerkleStack, built by refresh() iff signer
        self._known_sig = None  # (size, mtime_ns) the cached tail matches
        # Wave-234: the exact transmitted bytes (as received) of the
        # tail record. The next append commits to them via
        # prev_record_octets_digest. Always captured by refresh() when
        # the log is non-empty; None only for an empty log (genesis).
        self._prev_raw = None
        # Wave-72: the currently open anchor epoch. Always stamped on new
        # entries as reserved chain metadata (bound inside the HMAC input
        # via the canonical form); derived from the tail entry on refresh.
        self._epoch_id = _FIRST_EPOCH_ID
        self.refresh()

    def configure_guard(self, max_bytes):
        """F22: install the audit-log size guard (bytes); None disables."""
        if max_bytes is not None:
            try:
                max_bytes = int(max_bytes)
            except (TypeError, ValueError):
                raise ValueError("max_bytes must be an integer or None")
            if max_bytes <= 0:
                raise ValueError("max_bytes must be > 0")
        self._max_bytes = max_bytes

    def _file_sig(self):
        """O(1) (size, mtime) signature of the log file, None if absent."""
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_size, st.st_mtime_ns)

    def _refresh_if_changed(self):
        """Re-read the tail only when another writer changed the file.

        F22: ``append`` used to call ``refresh()`` — a full O(n) scan —
        every time, making n appends O(n^2) (measured: 2000 appends took
        ~9s). The cached (size, mtime_ns) signature makes the common
        case O(1): any write by another process (e.g. the approval CLI)
        changes the signature and triggers exactly one rescan.

        Concurrency note (F25): ``append`` holds an exclusive flock
        across refresh + seq assignment + write + fsync, so the
        read-modify-write above is atomic across processes — concurrent
        writers linearize instead of forking the chain. A bare
        ``refresh()`` from a non-append path can still observe a torn
        read only if some writer bypasses ``append`` (none in this
        codebase); all governed writes go through ``append``.
        """
        sig = self._file_sig()
        if sig is not None and sig == self._known_sig:
            return
        self.refresh()

    def refresh(self):
        """Re-read the file tail so this instance sees entries written by
        other processes (e.g. the approval CLI).

        F52 (R12): lines that are not valid chained entries
        (unparseable JSON, or forged/planted lines missing ``seq`` /
        ``hash`` — e.g. a planted execution_authorized marker written
        without the HMAC key) are SKIPPED, not trusted and not
        crashed on. In-process readers never bless log content; the
        verifier (``_verify``) is the component that fails closed on
        corrupt lines (F28). Skipping keeps ``append`` chaining onto
        the last GOOD entry, so a forgery in the file cannot deny the
        audit trail itself — the refusal audit entry the forgery
        triggers must itself be appendable.
        """
        self._seq = 0
        self._prev = GENESIS
        # Wave-72: the open anchor epoch is re-derived from the tail entry
        # on every refresh (a close that was never submitted is forgotten --
        # harmless: closes only matter once anchored; see ANCHOR_DESIGN.md).
        # Malformed epoch ids are not trusted (F52 spirit); the default
        # stands and new entries keep the chain consistent.
        self._epoch_id = _FIRST_EPOCH_ID
        # P2: when signing, maintain the incremental Merkle stack over
        # exactly the entries this refresh accepts (same scan, no extra
        # I/O). The stack commits to the writer's view of the log; the
        # strict arbiter remains _verify (F28). Unsigned logs pay nothing.
        stack = _merkle.MerkleStack() if self._signer is not None else None
        # F126: capture the (size, mtime) signature BEFORE reading the
        # content, not after. The F22 cache assumes the signature
        # describes the file version that produced _seq/_prev; capturing
        # it after the read lets a concurrent writer slip in between,
        # leaving _seq stale while the signature matches the current
        # file — the next _refresh_if_changed then skips and assigns a
        # duplicate seq (chain fork, caught 2026-09-22 in the sit64
        # concurrency probe). Sig-before-read makes the cache
        # conservative: if a writer lands between the stat and the read,
        # the signature is OLDER than the content, so the next check sees
        # sig != known and re-reads (one wasted read, never a stale seq).
        # Size is monotonic under append-only writers, so sig == known
        # still implies the file is unchanged.
        self._known_sig = self._file_sig()
        if self.path.exists():
            for raw_line in self.path.read_text(
                    encoding="utf-8").splitlines(keepends=True):
                # Wave-234: keep the exact transmitted bytes (line
                # terminator included) so the next append can commit
                # to them via prev_record_octets_digest. Parsing is
                # unchanged (strip-then-load, same skips as before).
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                try:
                    seq = int(entry["seq"])
                    chain_hash = entry["hash"]
                except (KeyError, TypeError, ValueError):
                    continue
                self._seq = seq
                self._prev = chain_hash
                # Wave-234: retain the tail record's raw bytes. Re-
                # encoding utf-8 round-trips the read text exactly, so
                # this is byte-identical to what is on disk.
                self._prev_raw = raw_line.encode("utf-8")
                epoch_id = entry.get("epoch_id")
                if _valid_epoch_id(epoch_id):
                    self._epoch_id = epoch_id
                if stack is not None:
                    stack.append(_merkle.leaf_hash(_leaf_input(entry)))
        self._merkle = stack

    @property
    def tail_seq(self):
        """Highest seq assigned by this log instance (0 when empty).

        Read-only accessor for the in-process tail; call ``refresh()``
        first if other processes may have appended. Added wave-53 for
        the sterile-cockpit entry snapshot reference (no behavior
        change to the log itself).
        """
        return self._seq

    @property
    def epoch_id(self):
        """The currently open wave-72 anchor epoch id (``e%08d``)."""
        return self._epoch_id

    def close_epoch(self):
        """Close the current anchor epoch at the tail (wave-72).

        Returns ``(epoch_id, start_seq, end_seq)`` and advances the
        in-memory epoch id to the segment starting after the tail, so
        subsequent appends are stamped with the new epoch. The anchorer
        (``gov/anchorer.py``) calls this when its checkpoint policy trips;
        it performs no I/O itself. A close with ``end_seq < start_seq``
        (empty log) is the anchorer's signal to skip.
        """
        start_seq = int(self._epoch_id[1:])
        end_seq = self._seq
        closed = self._epoch_id
        self._epoch_id = "e%08d" % (self._seq + 1)
        return closed, start_seq, end_seq

    @property
    def checkpoints(self):
        """All signed checkpoints, oldest first.

        F28: unparseable sidecar lines are skipped (counted by
        ``_parse_sidecar_lines``) instead of crashing the reader —
        corruption is a verifier verdict (fail closed), not an
        exception, for in-process readers.
        """
        out = []
        if self.checkpoint_path.exists():
            cps, _ = _parse_sidecar_lines(
                self.checkpoint_path.read_text(
                    encoding="utf-8").splitlines())
            out.extend(cps)
        return out

    def write_checkpoint(self, seq=None, entry_hash=None):
        """Append a key-authenticated checkpoint for (seq, entry_hash).

        Defaults to the current tail. Returns the checkpoint dict.

        P2/A5: when the log has a signer, the checkpoint is format 2 --
        the HMAC fields plus the signed tree head (CT STH):
        ``merkle_root`` over entries 1..seq, ``threshold`` k, ``sigs``
        (one Ed25519 signature per signing key), and ``roster_hash``
        binding the A5 signer set (or the single-key convention marker).
        Signed checkpoints always anchor the current tail: explicit
        (seq, entry_hash) arguments are rejected when signing, fail-fast,
        so a signed head can never describe a non-tail prefix.
        """
        key, epoch = _active_key(self._deployment_mode)
        if self._signer is not None and (
                seq is not None or entry_hash is not None):
            raise ValueError(
                "signed checkpoints always anchor the current tail; "
                "explicit (seq, entry_hash) is not supported with signer=")
        seq = self._seq if seq is None else seq
        entry_hash = self._prev if entry_hash is None else entry_hash
        # F202: the checkpoint timestamp is bound into BOTH the HMAC mac
        # and (below) the threshold-signature body, so rewriting it after
        # signing breaks verification at both seams. Unsigned
        # (format-1) checkpoints carry no ts and keep the legacy mac.
        ts = _utcnow() if self._signer is not None else None
        cp = {
            "seq": seq,
            "hash": entry_hash,
            "key_epoch": epoch,
            "format_version": FORMAT_VERSION,
            "mac": _checkpoint_mac(key, epoch, seq, entry_hash, ts=ts),
        }
        if self._signer is not None:
            root_hex = self._merkle.root().hex()
            # Threshold shape (A5) only when a roster binds the signer
            # set; a 1-of-1 ThresholdSigner without a roster (or any
            # plain Signer) uses the single-key shape.
            is_threshold = (
                isinstance(self._signer, _signing.ThresholdSigner)
                and self._roster is not None)
            if is_threshold:
                threshold = self._signer.threshold
                roster_hash = _signing.roster_hash(self._roster)
                body = _checkpoint_sig_body(
                    seq, entry_hash, root_hex, epoch, threshold,
                    roster_hash, ts)
                # Wave-186: sign_all binds each keyset-aware member's
                # key_version into its own member-specific signature
                # body; entries carry per-member "key_version". There
                # is deliberately NO single top-level "key_version":
                # members rotate independently and may be at different
                # versions, so one global version would mis-attribute.
                key_version = None
                sigs = self._signer.sign_all(body)
            else:
                threshold = 1
                roster_hash = _SINGLE_ROSTER_MARK + self._signer.key_id
                # Wave-186: a keyset-aware signer (KeysetSigner) binds
                # its keyset version into the STH body alongside ts, so
                # a checkpoint signed under a later-revoked version is
                # distinguishable and version tampering breaks the
                # signature. Unversioned signers keep the F202 body.
                # Malformed versions sanitize to None (same convention
                # as append's sig_key_version handling): the checkpoint
                # is honestly unversioned rather than mis-versioned.
                key_version = getattr(
                    self._signer, "key_version", None)
                if isinstance(key_version, bool) \
                        or not isinstance(key_version, int) \
                        or key_version < 1:
                    key_version = None
                body = _checkpoint_sig_body(
                    seq, entry_hash, root_hex, epoch, threshold,
                    roster_hash, ts, key_version=key_version)
                sigs = [{"key_id": self._signer.key_id,
                         "sig": self._signer.sign(body).hex()}]
            cp_update = {
                "format_version": CHECKPOINT_SIG_VERSION,
                "ts": ts,
                "merkle_root": root_hex,
                "threshold": threshold,
                "sigs": sigs,
                "roster_hash": roster_hash,
            }
            if key_version is not None:
                cp_update["key_version"] = key_version
            cp.update(cp_update)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(cp, ensure_ascii=True, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return cp

    def retire_evidence(self, policy, *, now=None):
        """Retire TTL-expired hot entries per a retention-tier policy.

        Thin hook: the whole operation lives in ``gov.evidence_tiers``
        (lazy import so ``gov.log`` never hard-depends on it). The
        retirement is crash-safe (covering warm summary first, then the
        audited marker, then truncation), idempotent, and refuses to
        retire entries whose TTL has not expired. Raises
        ``evidence_tiers.TierError`` fail-closed on an unverifiable
        log. ``now`` is an injectable clock (deterministic tests);
        ``None`` means wall-clock time.
        """
        from gov import evidence_tiers as _et
        return _et.retire_hot(self.path, policy, now=now)

    def _octet_link_digest(self, seq):
        """SHA-256 of the previous record's exact transmitted bytes.

        Wave-234 (octet-digest receipt chaining): the link commits to
        the raw stored line bytes of the previous record as this
        linker received them -- never a re-serialization. The genesis
        entry (seq 1) has no previous record: the documented
        ``OCTET_DIGEST_GENESIS`` constant. Otherwise the digest covers
        the tail bytes captured by ``refresh()``.

        Strict writer mode (``require_octet_digest=True``) raises
        ``OctetDigestError`` (``chain-octet-digest-absent``) when the
        tail bytes are unavailable instead of linking without them.
        In default mode an unavailable tail (unreachable via the
        public API -- ``refresh()`` always captures the tail bytes of
        a non-empty log) returns None and the field is omitted; a
        ``require_octet_digest=True`` verifier will then refuse the
        entry ``chain-octet-digest-absent`` -- no silent degradation.
        """
        if seq == 1:
            return OCTET_DIGEST_GENESIS
        if self._prev_raw is not None:
            return hashlib.sha256(self._prev_raw).hexdigest()
        if self._require_octet_digest:
            raise OctetDigestError(
                "chain-octet-digest-absent",
                "seq %d: previous record's transmitted octets are "
                "unavailable; strict writer refuses to link without them"
                % seq)
        return None

    def append(self, event):
        """Append an event dict; returns the stored entry.

        Fail-closed: if the entry or its checkpoint cannot be written, an
        exception propagates and the caller must not treat the action as
        logged.

        Reserved chain metadata (seq, ts, prev_hash, format_version,
        key_epoch, epoch_id) is always set by the log itself: same-named keys in
        ``event`` are dropped, so a caller can never forge or clobber the
        chain bookkeeping.

        F22: appends are O(1) amortized — the tail is re-scanned only when
        another writer changed the file (see ``_refresh_if_changed``).
        When the configured size guard is reached, raises
        ``LogFullError``: fail-closed, no unlogged actions.

        F25: the whole append — tail refresh, seq assignment, write,
        fsync, checkpoint — runs under an exclusive OS file lock
        (POSIX ``fcntl.flock``), so concurrent processes linearize and
        the HMAC chain cannot fork (W7-3). Lock acquisition failure
        raises ``AppendLockError`` instead of writing unlocked.
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        key, epoch = _active_key(self._deployment_mode)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _append_locked(self.path) as f:
            # Re-check the tail UNDER the lock: another process may have
            # appended between our last stat and lock acquisition; the
            # lock is what makes the read-modify-write atomic.
            self._refresh_if_changed()
            # Build the entry (but do not commit chain state yet): the
            # size guard is enforced on the PROJECTED byte size before
            # anything is written or mutated, so a refusal leaves no gap
            # in the chain.
            new_seq = self._seq + 1
            entry = {}
            entry.update(event)
            # Wave-234 (token hygiene): defense-in-depth redaction of
            # REGISTERED bearer token values, applied to the entry
            # BEFORE chain/MAC computation so the scrubbed entry is
            # what the chain binds (an accident cannot fork the
            # chain). Precise contract, see gov/token_hygiene.py:
            # the CALLER must never hand the log a token value --
            # events carry {type, issuer, scope, audience} metadata
            # only. This scrub is not enforcement: TokenRedactor
            # .assert_clean refuses token-in-log (incident material)
            # on any rendered/stored line that still carries a
            # registered value. With no registered values this is a
            # no-op and stored bytes are unchanged.
            entry = _token_hygiene.token_scrub(entry)
            # Wave-234: the octet-digest link is reserved chain
            # metadata (a caller-supplied prev_record_octets_digest is
            # dropped like every other reserved field). Computed BEFORE
            # the MAC so it is HMAC-bound via the canonical form; the
            # existing prev_hash/hash semantics are unchanged.
            octet_link = self._octet_link_digest(new_seq)
            # Reserved metadata wins over anything the caller supplied.
            reserved = {
                "seq": new_seq,
                "ts": _utcnow(),
                "prev_hash": self._prev,
                "format_version": FORMAT_VERSION,
                "key_epoch": epoch,
                # Wave-72: the open anchor epoch, bound inside the HMAC
                # input via the canonical form (backdating / reordering /
                # cross-epoch moves without the key break verification).
                "epoch_id": self._epoch_id,
            }
            if octet_link is not None:
                reserved["prev_record_octets_digest"] = octet_link
            entry.update(reserved)
            entry["hash"] = _compute_mac(key, epoch, self._prev,
                                         _canonical(entry))
            if self._signer is not None:
                # P2: per-entry Ed25519 signature over content + chain
                # hash. Excluded from the HMAC canonical form above, so
                # the HMAC chain is unaffected. Under a ThresholdSigner
                # this uses the designated entry signer (single
                # signature -- threshold-signing every entry would be
                # operationally absurd, A5).
                #
                # Wave-183: a keyset-aware signer (gov.keyset.KeysetSigner)
                # exposes key_version; it is written into the envelope
                # BEFORE the body is computed so the v2 body binds it.
                # Only a sane version (int >= 1) is written, so the
                # envelope stays consistent: version present <=> v2
                # body. Legacy signers write no version and keep the
                # byte-identical v1 body.
                key_version = getattr(self._signer, "key_version", None)
                if isinstance(key_version, bool) \
                        or not isinstance(key_version, int) \
                        or key_version < 1:
                    key_version = None
                if key_version is not None:
                    entry["sig_key_version"] = key_version
                entry["ed_sig"] = self._signer.sign(
                    _entry_sig_body(entry)).hex()
                entry["sig_key_id"] = self._signer.key_id
            line = json.dumps(entry, ensure_ascii=True, default=str) + "\n"
            if self._max_bytes is not None:
                # True size via fstat on the locked fd (f.tell() in
                # append mode reports the stream position, not EOF).
                size = os.fstat(f.fileno()).st_size
                if size + len(line.encode("utf-8")) > self._max_bytes:
                    raise LogFullError(
                        "audit log %s would exceed its size cap (%d bytes "
                        "projected): archive the log and start a fresh one; "
                        "refusing to append so no action goes unlogged"
                        % (self.path, self._max_bytes))
            self._seq = new_seq
            self._prev = entry["hash"]
            # Wave-234: the bytes just written become the tail whose
            # octets the NEXT append commits to.
            self._prev_raw = line.encode("utf-8")
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
            # F22: the file changed under us — record the new signature so
            # the next append skips the rescan.
            self._known_sig = self._file_sig()
            # P2: extend the incremental Merkle stack with the new leaf
            # (amortized O(1)) so the checkpoint below anchors it.
            if self._merkle is not None:
                self._merkle.append(
                    _merkle.leaf_hash(_leaf_input(entry)))
            # Checkpoint under the same lock: the (seq, hash) pair it
            # anchors cannot be interleaved with another writer's.
            self.write_checkpoint()
        return entry


def read_entries_with_stats(path):
    """Read action-log entries, counting malformed physical lines.

    Returns ``(entries, malformed_count)``. Malformed = a non-blank
    line that is not valid JSON, or valid JSON that is not an object
    (F63: the latter used to crash ``_verify`` with AttributeError —
    see below). Malformed lines are SKIPPED, never trusted.

    Never raises on file CONTENT problems (F28): only real I/O
    failures (OSError) propagate.

    F163: reads of another run's traces/exchanges are policy-checked
    and recorded via the exchange-access ledger; a denied read raises
    ``ExchangeAccessDenied`` (fail-closed policy denial, not a
    content problem).
    """
    check_exchange_read(path)
    p = Path(path)
    if not p.exists():
        return [], 0
    out = []
    malformed = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(entry, dict):
            malformed += 1
            continue
        out.append(entry)
    check_exchange_read(path, len(out))
    return out, malformed


def read_entries(path):
    check_exchange_read(path)
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    check_exchange_read(path, len(out))
    return out


def _parse_sidecar_lines(lines):
    """Parse checkpoint sidecar lines. Returns (checkpoints, n_bad).

    Never raises: unparseable or malformed lines are counted, not
    trusted. ``_verify`` fails closed on any bad line for a non-empty
    log (F28) — mirroring the egress ledger's fail-closed twin.
    """
    cps, n_bad = [], 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            cp = json.loads(line)
        except ValueError:
            n_bad += 1
            continue
        if isinstance(cp, dict) and isinstance(cp.get("seq"), int):
            cps.append(cp)
        else:
            n_bad += 1
    return cps, n_bad


def _is_octet_digest_shape(value):
    """64 lowercase hex chars -- the shape of a SHA-256 hex digest."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _verify_octet_links(path):
    """Octet-digest link verification (wave-234), independent pre-pass.

    Walks the raw stored lines in order and checks every entry's
    ``prev_record_octets_digest`` against the ACTUAL stored octets of
    the preceding line -- never a re-serialization. Returns None when
    every link checks out, else the refusal error string naming the
    chain-domain taxonomy code:

    * ``chain-record-truncated`` -- a record's bytes (or its
      predecessor's) do not decode as a JSON object; the bytes are
      reported, never silently skipped.
    * ``chain-octet-digest-absent`` -- an entry carries no
      well-formed digest field; refuses instead of silently
      degrading to semantic (prev_hash) chaining.
    * ``chain-octet-digest-mismatch`` -- the claimed digest does not
      match the stored previous-record octets: the previous record
      was re-encoded (byte-different, semantically equal). This is
      the deliberate failure mode -- a canonicalizing linker breaks
      this check by construction.

    Blank lines are ignored exactly as in the main walk. This pass
    checks links only; seq continuity, MACs, epochs, and checkpoints
    stay the main walk's job.
    """
    p = Path(path)
    raws = []
    for lineno, raw_line in enumerate(
            p.read_text(encoding="utf-8").splitlines(keepends=True), 1):
        if not raw_line.strip():
            continue
        raws.append((lineno, raw_line.encode("utf-8")))
    for idx, (lineno, raw) in enumerate(raws):
        try:
            entry = json.loads(raw.decode("utf-8"))
            if not isinstance(entry, dict):
                raise ValueError("not a JSON object")
        except (UnicodeDecodeError, ValueError) as exc:
            return ("chain-record-truncated: log line %d bytes do not "
                    "decode as a JSON record (%s); refusing, never "
                    "silently skipping" % (lineno, exc))
        claimed = entry.get("prev_record_octets_digest")
        if not _is_octet_digest_shape(claimed):
            return ("chain-octet-digest-absent: seq %r at log line %d "
                    "carries no well-formed prev_record_octets_digest; "
                    "refusing (no silent degradation to semantic "
                    "chaining)" % (entry.get("seq"), lineno))
        if idx == 0:
            expected = OCTET_DIGEST_GENESIS
        else:
            prev_lineno, prev_raw = raws[idx - 1]
            try:
                prev_entry = json.loads(prev_raw.decode("utf-8"))
                if not isinstance(prev_entry, dict):
                    raise ValueError("not a JSON object")
            except (UnicodeDecodeError, ValueError) as exc:
                return ("chain-record-truncated: previous record bytes "
                        "(log line %d) do not decode as a JSON record "
                        "(%s); refusing, never silently skipping"
                        % (prev_lineno, exc))
            expected = hashlib.sha256(prev_raw).hexdigest()
        if not hmac.compare_digest(claimed, expected):
            return ("chain-octet-digest-mismatch: seq %r at log line %d "
                    "commits to %s but the stored previous-record "
                    "octets (log line %d) digest to %s: the previous "
                    "record was re-encoded (byte-different, "
                    "semantically equal); refusing"
                    % (entry.get("seq"), lineno, claimed,
                       raws[idx - 1][0] if idx else lineno, expected))
    return None


def _verify_close_binding_postpass(entries, close_record, trust_root,
                                     relied_scope_fields):
    """Close-record signer binding post-pass (wave-236), opt-in only.

    Thin hook: all binding logic lives in
    ``gov.close_signer_binding`` (lazy import here so ``gov.log``
    never hard-depends on it). Runs AFTER the main walk, so the
    binding never upgrades a broken chain -- a chain that fails MACs,
    seq continuity, epochs, or checkpoints fails closed before this
    post-pass is reached. Returns None when the binding holds, else
    the refusal error string naming the close-domain taxonomy code.
    """
    from gov import close_signer_binding as _cb
    try:
        records = _cb.adapt_log_entries(entries)
        _cb.verify_close_record(
            records, close_record, trust_root=trust_root,
            relied_scope_fields=relied_scope_fields or ())
    except _cb.CloseSignerBindingError as exc:
        return "%s: %s" % (exc.code, exc.detail) if exc.detail else exc.code
    return None


def _verify(path, _skip_malformed=False, require_octet_digest=False,
            require_close_binding=False, close_record=None,
            close_trust_root=None, close_relied_scope_fields=()):
    """Full verification. Returns a verdict dict.

    Never raises on file CONTENT problems (F28): corrupt log lines and
    corrupt checkpoint sidecars are reported as
    ``{"ok": False, "error": ...}``, never as an uncaught exception and
    never as ``ok=True``.

    ``_skip_malformed=True`` (F63) is a TOLERANT mode for
    reconciliation only: malformed physical lines (non-JSON, or valid
    JSON that is not an object) are skipped and counted in
    ``verdict["malformed_skipped"]`` instead of failing the whole
    verification — while the SIGNED chain (seq continuity, prev_hash
    links, key_epoch labels, MACs, checkpoints) of every VALID entry
    is still verified exactly as strictly as the default mode. A
    malformed line carries no seq and no chain link, so skipping it
    cannot launder tampering: any alteration of a VALID entry still
    fails closed. The default (``False``) is unchanged and stays
    fail-closed on any malformed line, preserving F28.

    F27: checkpointing is always enabled for ActionLog (every append
    writes a checkpoint), so a NON-EMPTY log with a missing, empty, or
    corrupt sidecar fails CLOSED — the egress ledger's rule (non-empty
    ledger + no sidecar -> unverifiable) now has an action-log twin.
    ``ok=True`` is never reported on the strength of zero checked
    checkpoints for a non-empty log; a truncated log never verifies
    clean.

    F32 (HARDENING-R8): the verifier additionally BINDS every entry's
    ``key_epoch`` label to the CONFIGURED epoch. In single-key mode there
    is no label->key registry, so a label that is not the configured epoch
    is either a label forgery or a misconfigured epoch — either way the
    verifier fails closed with a label-mismatch error rather than
    blessing it. The newest checkpoint's label is bound the same way. A
    log that spans a key rotation does NOT verify here by design
    (fail-closed): use KeyRing.verify_log for those (each label selects
    its own key there, so a forged label fails the per-epoch MAC instead).

    Wave-234: ``require_octet_digest=True`` runs the
    ``_verify_octet_links`` pre-pass first: every entry's
    ``prev_record_octets_digest`` is checked against the actual stored
    octets of the previous record (genesis expects
    ``OCTET_DIGEST_GENESIS``). A pre-pass failure fails closed with
    the named chain-domain refusal code; otherwise the walk below
    runs exactly as before. The default (``False``) is unchanged.

    Wave-236: ``require_close_binding=True`` runs a close-record
    signer-binding post-pass AFTER the walk above: the caller-supplied
    ``close_record`` must be sealed by the chain-root session-start
    signer (first entry's ``sig_key_id``), its ``chain_digest`` must
    match the recomputed digest over the chain, an optional
    ``close_trust_root`` binds the close record's key material to the
    external root (re-pointed trust ids refuse
    ``close-trust-repointed``), and ``close_relied_scope_fields``
    must be inside the close record's signature-covered fields
    (unsigned scope reliance refuses ``close-unsigned-scope``).
    ``close_record`` is REQUIRED when ``require_close_binding`` is
    True. Plain HMAC logs carry no signer identity, so the post-pass
    fails closed with ``close-signer-absent`` on them -- documented,
    never silently bound. The default (``False``) is unchanged.
    """
    key, epoch = _active_key()
    p = Path(path)

    def _fail(entries, error, broken_seq=None, checked=0):
        return {"ok": False, "entries": len(entries),
                "broken_seq": broken_seq, "checkpoints_checked": checked,
                "malformed_skipped": n_skipped,
                "key_epoch": epoch, "format_version": FORMAT_VERSION,
                "error": error}

    n_skipped = 0
    if not p.exists():
        return _fail([], "log file does not exist")
    if require_octet_digest:
        # Wave-234: octet-digest links are verified against the raw
        # stored bytes BEFORE the semantic walk. The pre-pass names
        # the precise refusal (mismatch / absent / truncated); the
        # walk below still runs for MACs, seq, epochs, checkpoints.
        octet_err = _verify_octet_links(p)
        if octet_err is not None:
            return _fail([], octet_err)
    entries = []
    prev = GENESIS
    for lineno, line in enumerate(
            p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            if _skip_malformed:
                n_skipped += 1
                continue
            return _fail(entries,
                         "log line %d is not valid JSON (corrupt log); "
                         "failing closed" % lineno)
        if not isinstance(entry, dict):
            # F63: valid JSON that is not an object (e.g. "[1,2]").
            # The old code fell through to entry.get() and raised
            # AttributeError — a latent F28 never-raise hole. Default
            # mode fails closed on it; tolerant mode skips and counts.
            if _skip_malformed:
                n_skipped += 1
                continue
            return _fail(entries,
                         "log line %d is valid JSON but not an object "
                         "(corrupt log); failing closed" % lineno)
        entries.append(entry)
        seq = entry.get("seq")
        # F27: the full chain walk from genesis runs even when no
        # checkpoint exists; any seq gap fails verification here.
        if seq != len(entries):
            return _fail(entries,
                         "sequence gap at log line %d: expected seq %d, "
                         "got %r (entries deleted or reordered); failing "
                         "closed" % (lineno, len(entries), seq),
                         broken_seq=seq)
        if entry.get("format_version") != FORMAT_VERSION:
            return _fail(entries,
                         "unsupported format_version %r at seq %s"
                         % (entry.get("format_version"), seq),
                         broken_seq=seq)
        if entry.get("prev_hash") != prev:
            return _fail(entries, "chain link broken at seq %s" % seq,
                         broken_seq=seq)
        # F32 (HARDENING-R8): bind the self-declared label to the
        # configured key. The MAC was already computed over the label,
        # but nothing stopped a forger from HMAC'ing production labels
        # under the public dev key and verifying clean. Now any entry
        # whose label is not the configured epoch fails closed here.
        label = entry.get("key_epoch")
        if label != epoch:
            return _fail(entries,
                         "key_epoch label mismatch at seq %s: entry claims "
                         "%r but the configured key epoch is %r — possible "
                         "label forgery or misconfigured epoch; refusing "
                         "to verify (failing closed)" % (seq, label, epoch),
                         broken_seq=seq)
        mac = _compute_mac(key, label, prev, _canonical(entry))
        if not hmac.compare_digest(entry.get("hash", ""), mac):
            return _fail(entries,
                         "MAC mismatch at seq %s (history rewritten or "
                         "wrong GOV_LOG_KEY)" % seq, broken_seq=seq)
        prev = entry["hash"]

    # Checkpoint comparison defeats tail truncation: the log must reach the
    # newest checkpoint and agree with it there.
    cp_path = p.parent / "checkpoints.jsonl"
    checked = 0
    cps, n_bad = [], 0
    sidecar_missing = not cp_path.exists()
    if not sidecar_missing:
        try:
            text = cp_path.read_text(encoding="utf-8")
        except OSError as e:
            return _fail(entries, "checkpoint sidecar %s unreadable: %s; "
                                  "failing closed" % (cp_path.name, e))
        cps, n_bad = _parse_sidecar_lines(text.splitlines())
    if entries:
        # F27: non-empty log, so checkpointing anchored every entry.
        if sidecar_missing:
            return _fail(entries,
                         "checkpoint sidecar %s is MISSING for a non-empty "
                         "log (%d entries): the tail-truncation anchor is "
                         "gone — truncation cannot be ruled out; failing "
                         "closed" % (cp_path.name, len(entries)))
        if n_bad:
            return _fail(entries,
                         "checkpoint sidecar %s is CORRUPT (%d unparseable "
                         "line(s)): refusing to verify — failing closed; "
                         "restore the sidecar from backup" % (cp_path.name,
                                                              n_bad))
        if not cps:
            return _fail(entries,
                         "checkpoint sidecar %s is EMPTY for a non-empty "
                         "log (%d entries): no truncation anchor — "
                         "failing closed" % (cp_path.name, len(entries)))
    elif n_bad:
        # Empty log: nothing to truncate, but a corrupt sidecar is never
        # acceptable — fail closed rather than bless it.
        return _fail(entries,
                     "checkpoint sidecar %s is CORRUPT (%d unparseable "
                     "line(s)); failing closed" % (cp_path.name, n_bad))
    if cps:
        latest = max(cps, key=lambda c: c["seq"])
        checked = len(cps)
        # F32 (HARDENING-R8): bind the checkpoint label too — a checkpoint
        # is a signed claim about the chain, and its self-declared label
        # must equal the configured epoch just like every entry's.
        cp_label = latest.get("key_epoch")
        if cp_label != epoch:
            return _fail(entries,
                         "checkpoint key_epoch label mismatch: checkpoint "
                         "claims %r but the configured key epoch is %r — "
                         "refusing to verify (failing closed)"
                         % (cp_label, epoch), checked=checked)
        # F202: v2 signed checkpoints bind ts into the mac; only
        # format-1 checkpoints and tip-gen pins (which carry no ts) use
        # the legacy domain. A pre-F202 v2 head fails here: its mac was
        # minted without ts.
        expect = _checkpoint_mac(key, cp_label,
                                 latest["seq"], latest["hash"],
                                 _pin_gen_of(latest),
                                 ts=latest.get("ts"))
        if not hmac.compare_digest(latest.get("mac", ""), expect):
            return _fail(entries,
                         "checkpoint MAC invalid (checkpoint tampered "
                         "or wrong GOV_LOG_KEY)", checked=checked)
        if len(entries) < latest["seq"]:
            return _fail(entries,
                         "tail truncation: log has %d entries but "
                         "newest checkpoint is at seq %d"
                         % (len(entries), latest["seq"]), checked=checked)
        if latest["seq"] > 0 and entries[latest["seq"] - 1][
                "hash"] != latest["hash"]:
            return _fail(entries,
                         "checkpoint mismatch at seq %d "
                         "(log rewritten after checkpoint)"
                         % latest["seq"], broken_seq=latest["seq"],
                         checked=checked)
    verdict = {"ok": True, "entries": len(entries), "broken_seq": None,
               "checkpoints_checked": checked,
               "malformed_skipped": n_skipped,
               "key_epoch": epoch, "format_version": FORMAT_VERSION,
               "error": None}
    if require_close_binding:
        # Wave-236: close-record signer binding is a post-pass on an
        # already-verified chain; it never upgrades a broken chain.
        bind_err = _verify_close_binding_postpass(
            entries, close_record, close_trust_root,
            close_relied_scope_fields)
        if bind_err is not None:
            return _fail(entries, bind_err)
    return verdict


def require_verified(path):
    """Raise :class:`LogUnverifiableError` unless the log fully verifies.

    F27/F28: the programmatic fail-closed twin of the egress ledger's
    ``require_verified`` — use before trusting a log's contents.
    Returns the verdict dict on success.
    """
    v = _verify(path)
    if not v["ok"]:
        raise LogUnverifiableError(v["error"] or "log failed verification")
    return v


def verify_chain(path, require_octet_digest=False, *,
                 require_close_binding=False, close_record=None,
                 close_trust_root=None, close_relied_scope_fields=()):
    """Replay the chain. Returns (ok, broken_seq_or_None, entry_count).

    Wave-234: ``require_octet_digest=True`` additionally verifies every
    entry's ``prev_record_octets_digest`` against the actual stored
    octets of the previous record (genesis expects the documented
    ``OCTET_DIGEST_GENESIS`` constant). Refusals name the chain-domain
    taxonomy codes ``chain-octet-digest-mismatch``,
    ``chain-octet-digest-absent``, and ``chain-record-truncated`` in
    the verdict's error string. The default (``False``) keeps all
    existing behavior.

    Wave-236: ``require_close_binding=True`` additionally requires a
    caller-supplied ``close_record`` sealed by the chain-root
    session-start signer (first entry's ``sig_key_id``), with
    ``chain_digest`` matching the recomputed chain digest; an optional
    ``close_trust_root`` binds the close record's key material to the
    external root, and ``close_relied_scope_fields`` must be inside
    the close record's signature-covered fields. Refusals name the
    close-domain taxonomy codes (``close-signer-mismatch``,
    ``close-trust-repointed``, ``close-unsigned-scope``,
    ``close-chain-digest-mismatch``, ``close-record-malformed``,
    ``close-signer-absent``). The default (``False``) keeps all
    existing behavior, byte-identical.
    """
    v = _verify(path, require_octet_digest=require_octet_digest,
                require_close_binding=require_close_binding,
                close_record=close_record,
                close_trust_root=close_trust_root,
                close_relied_scope_fields=close_relied_scope_fields)
    return v["ok"], v["broken_seq"], v["entries"]


def verify_tiered(path, policy=None):
    """Tier-aware verification for logs retired by ``gov.evidence_tiers``.

    Thin hook: all tiering logic lives in ``gov.evidence_tiers`` (lazy
    import here so ``gov.log`` never hard-depends on it). On a log that
    was never retired this agrees with :func:`_verify`; on a retired
    log it additionally verifies the warm/cold tier chains and the
    retirement cross-links. Never raises on content problems -- returns
    a verdict dict with ``ok=False`` and a loud error.
    """
    from gov import evidence_tiers as _et
    return _et.verify_tiered(path, policy)


# ---------------------------------------------------------------------------
# P2/A5/K-060: public-key proofs, third-party verification, and export.
#
# These functions implement the literature IMPLEMENT items on top of the
# migration above:
# * CT (RFC 6962): signed tree heads are checkpoint format 2;
#   prove_inclusion / prove_consistency generate the auditor proofs,
#   verify_*_bundle verify them offline (no HMAC key, no log access).
# * Crosby & Wallach: auditors verify O(log n) proofs instead of
#   replaying the O(n) chain.
# * A5: checkpoint signatures are k-of-n over an offline-root-signed
#   roster; _verify_one_checkpoint_sig is the single choke point.
# * K-060: query_log / export_bundle make the trail a live operational
#   capability; the bundle is tamper-evident (proofs + signed heads).
# ---------------------------------------------------------------------------


def _proof_entries(path):
    """Parse log entries for proof generation.

    Returns [(entry, leaf_hash)] in file order, skipping blank /
    unparseable lines and lines without seq+hash (the same acceptance
    rule as ``ActionLog.refresh``). Raises OSError on unreadable files;
    content problems surface as proof-generation failures, never as
    silent wrong proofs.
    """
    out = []
    for line in Path(path).read_text(
            encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            seq = int(entry["seq"])
            hv = entry["hash"]
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(seq, bool):
            continue
        out.append((entry,
                    _merkle.leaf_hash(_leaf_input(entry))))
    return out


def _read_checkpoints_all(path):
    """All sidecar checkpoints (any format), oldest first.

    Never raises on content: returns (checkpoints, n_bad_lines).
    """
    cp_path = Path(path).parent / "checkpoints.jsonl"
    if not cp_path.exists():
        return [], 0
    cps, n_bad = _parse_sidecar_lines(
        cp_path.read_text(encoding="utf-8").splitlines())
    cps.sort(key=lambda c: c["seq"])
    return cps, n_bad


def signed_checkpoints(path):
    """All format-2 (public-key signed tree head) checkpoints, oldest
    first. Empty list when the log is HMAC-only."""
    cps, _ = _read_checkpoints_all(path)
    return [c for c in cps
            if c.get("format_version") == CHECKPOINT_SIG_VERSION]


def signed_checkpoint(path, seq):
    """The v2 checkpoint exactly at ``seq``, or None."""
    for cp in signed_checkpoints(path):
        if cp["seq"] == seq:
            return cp
    return None


def _sig_body_for_checkpoint(cp):
    """Rebuild the signed STH body from a v2 checkpoint dict.

    F202: ``ts`` is part of the signed body. A v2 checkpoint without a
    string ``ts`` is malformed -- the KeyError/TypeError is caught by
    ``_verify_one_checkpoint_sig`` and fails closed. Pre-F202 heads
    (whose signatures never covered ``ts``) no longer verify.

    Wave-186: ``key_version`` (when the checkpoint carries one) is part
    of the signed body too. A checkpoint without ``key_version``
    rebuilds the F202 body -- post-F202 unversioned checkpoints keep
    verifying. A malformed ``key_version`` fails closed.
    """
    key_version = cp.get("key_version")
    if key_version is not None and (
            isinstance(key_version, bool)
            or not isinstance(key_version, int) or key_version < 1):
        raise TypeError("malformed v2 checkpoint key_version")
    return _checkpoint_sig_body(cp["seq"], cp["hash"], cp["merkle_root"],
                                cp["key_epoch"], cp["threshold"],
                                cp["roster_hash"], cp["ts"],
                                key_version=key_version)


def _check_checkpoint_key_against_keyset(keysets, key_id, claimed_version):
    """Keyset cross-check for one checkpoint signing key.

    ``keysets``: mapping ``key_id -> gov.keyset.Keyset`` (the
    verifier's trust directory of checkpoint-signer keysets).
    ``claimed_version``: the checkpoint's version claim for this key
    (None when the checkpoint carries none).

    Returns (ok, error); never raises. The keyset is the authority:
    the claim is cross-checked (confusion fails closed) and revocation
    is resolved from the key id alone, so stripping the version claim
    cannot smuggle a revoked version past. A key with no keyset in the
    mapping is out of scope here (the caller treats it as unversioned).
    """
    ks = keysets.get(key_id)
    if ks is None:
        return True, None  # no keyset for this key: not our check
    by_key_id = getattr(ks, "by_key_id", None)
    kv = by_key_id(key_id) if callable(by_key_id) else None
    if kv is None:
        return False, "key id %r not in its keyset" % (key_id,)
    try:
        kv_version, kv_status = kv.version, kv.status
    except Exception:
        return False, "keyset version record malformed for %r" % (key_id,)
    if claimed_version is not None and claimed_version != kv_version:
        return False, ("checkpoint key_version %r does not match keyset "
                       "version %r for key %r"
                       % (claimed_version, kv_version, key_id))
    if kv_status == _keyset.STATUS_REVOKED:
        return False, ("checkpoint signing key version %d is revoked"
                       % (kv_version,))
    return True, None


def _normalize_pubkey(pub):
    """Accept 32-byte bytes or 64-hex-char str; else None."""
    if isinstance(pub, (bytes, bytearray)) and len(pub) == 32:
        return bytes(pub)
    if isinstance(pub, str):
        try:
            raw = bytes.fromhex(pub)
        except ValueError:
            return None
        if len(raw) == 32:
            return raw
    return None


def _verify_one_checkpoint_sig(cp, trusted_keys, roster=None,
                               root_pub=None, keysets=None):
    """Verify one v2 checkpoint's Ed25519 signature set.

    Single-key checkpoints (``threshold == 1`` with the single-key
    roster marker) verify against ``trusted_keys`` ({key_id: pubkey}).
    Threshold checkpoints verify k-of-n against the offline-root-signed
    ``roster`` (whose content hash must equal the checkpoint's
    ``roster_hash``) under ``root_pub``. Returns (ok, error); never
    raises on malformed input.

    Wave-186 ``keysets`` (optional): mapping ``key_id ->
    gov.keyset.Keyset``. When a checkpoint signing key has a keyset,
    the checkpoint's version claim is cross-checked and revoked
    versions are refused -- in the single-key branch a checkpoint
    signed under a revoked version fails here; in the threshold branch
    a revoked member's signature simply does not count (see
    ``gov.signing.verify_threshold``). Keys with no keyset verify
    exactly as before.
    """
    try:
        if not isinstance(cp, dict) or cp.get(
                "format_version") != CHECKPOINT_SIG_VERSION:
            return False, "not a v2 signed checkpoint"
        threshold = cp["threshold"]
        rhash = cp["roster_hash"]
        sigs = cp["sigs"]
        body = _sig_body_for_checkpoint(cp)
    except (KeyError, TypeError):
        return False, "malformed v2 checkpoint"
    if (not isinstance(threshold, int) or isinstance(threshold, bool)
            or threshold < 1):
        return False, "bad threshold %r" % (threshold,)
    if keysets is not None and not isinstance(keysets, dict):
        return False, "keysets must be a mapping key_id -> Keyset"
    if (threshold == 1 and isinstance(rhash, str)
            and rhash.startswith(_SINGLE_ROSTER_MARK)):
        if not isinstance(sigs, list) or len(sigs) != 1:
            return False, "single-key checkpoint must carry one sig"
        kid = sigs[0].get("key_id") if isinstance(
            sigs[0], dict) else None
        if keysets is not None and isinstance(kid, str):
            ok, err = _check_checkpoint_key_against_keyset(
                keysets, kid, cp.get("key_version"))
            if not ok:
                return False, err
        pub = _normalize_pubkey((trusted_keys or {}).get(kid))
        if pub is None:
            return False, "unknown signing key %r" % (kid,)
        try:
            sig = bytes.fromhex(sigs[0]["sig"])
        except (KeyError, TypeError, ValueError):
            return False, "malformed sig entry"
        if _ed25519.verify(pub, body, sig):
            return True, None
        return False, "Ed25519 signature invalid"
    if roster is None or root_pub is None:
        return False, ("threshold checkpoint (k=%d) requires the "
                       "offline-root-signed roster and trusted root "
                       "pubkey" % (threshold,))
    if _signing.roster_hash(roster) != rhash:
        return False, ("roster_hash mismatch: this checkpoint was signed "
                       "under a different signer roster")
    return _signing.verify_threshold(body, sigs, roster, root_pub,
                                     keysets=keysets)


def verify_checkpoint_signatures(path, trusted_keys=None, roster=None,
                                 root_pub=None, require_signed=False,
                                 keysets=None):
    """Third-party verification of signed checkpoints (P2/A5).

    No HMAC key needed: verifies every v2 checkpoint's signature set
    via :func:`_verify_one_checkpoint_sig`. Returns a verdict dict
    ``{"ok", "checked", "valid", "unsigned", "error"}``. Format-1
    checkpoints are counted as ``unsigned``, not failures -- unless
    ``require_signed=True``, in which case any unsigned checkpoint (or
    a log with no signed checkpoints at all) fails closed.

    Downgrade residual (documented, not hidden): stripping the
    signature fields turns a v2 checkpoint into v1 -- the HMAC path
    still verifies it, but a third party with ``require_signed=True``
    rejects the log. Signature stripping is tamper-evident to anyone
    who requires signatures, invisible to anyone who does not.

    Wave-186 ``keysets``: optional mapping ``key_id ->
    gov.keyset.Keyset``; when supplied, revoked signing-key versions
    are refused (single-key branch) or not counted (threshold branch).
    Without it, version revocation is unchecked -- the keyset is public
    material the verifier is expected to fetch current, exactly like
    the trusted root key.
    """
    cps, n_bad = _read_checkpoints_all(path)
    if n_bad:
        return {"ok": False, "checked": 0, "valid": 0, "unsigned": 0,
                "error": "checkpoint sidecar has %d unparseable lines; "
                         "failing closed" % n_bad}
    checked = valid = unsigned = 0
    for cp in cps:
        if cp.get("format_version") != CHECKPOINT_SIG_VERSION:
            unsigned += 1
            if require_signed:
                return {"ok": False, "checked": checked, "valid": valid,
                        "unsigned": unsigned,
                        "error": "require_signed: checkpoint@%d is "
                                 "unsigned (v1)" % cp["seq"]}
            continue
        checked += 1
        ok, err = _verify_one_checkpoint_sig(cp, trusted_keys, roster,
                                             root_pub, keysets=keysets)
        if not ok:
            return {"ok": False, "checked": checked, "valid": valid,
                    "unsigned": unsigned,
                    "error": "checkpoint@%d: %s" % (cp["seq"], err)}
        valid += 1
    if require_signed and checked == 0:
        return {"ok": False, "checked": 0, "valid": 0,
                "unsigned": unsigned,
                "error": "require_signed: no signed checkpoints"}
    return {"ok": True, "checked": checked, "valid": valid,
            "unsigned": unsigned, "error": None}


def _inclusion_material(path, seqs):
    """Shared proof-generation core.

    Reads the log once; for each seq returns (proof_hex_list,
    covering_checkpoint). Fails fast (ValueError) on non-dense seqs,
    missing signed coverage, or a checkpoint root that does not match
    the log -- a proof is never built on a doubtful foundation.
    """
    entries = _proof_entries(path)
    n = len(entries)
    for i, (e, _) in enumerate(entries):
        if e.get("seq") != i + 1:
            raise ValueError("log seq not dense at position %d" % i)
    cps = signed_checkpoints(path)
    out = {}
    for seq in seqs:
        if not isinstance(seq, int) or isinstance(seq, bool) \
                or not (1 <= seq <= n):
            raise ValueError("seq %r out of range" % (seq,))
        cover = [c for c in cps if c["seq"] >= seq]
        if not cover:
            raise ValueError(
                "no signed checkpoint covers seq %d" % seq)
        cp = max(cover, key=lambda c: c["seq"])
        leaves = [lf for _, lf in entries[:cp["seq"]]]
        if _merkle.tree_root(leaves).hex() != cp["merkle_root"]:
            raise ValueError(
                "checkpoint@%d merkle_root does not match the log; "
                "refusing to prove" % cp["seq"])
        proof = _merkle.inclusion_proof(leaves, seq - 1)
        out[seq] = ([p.hex() for p in proof], cp)
    return entries, out


def prove_inclusion(path, seq):
    """Build an offline inclusion bundle for entry ``seq`` (CT auditor).

    The bundle carries the entry, the O(log n) proof, and the covering
    signed checkpoint. Anyone holding the bundle plus the out-of-band
    trusted keys verifies it via :func:`verify_inclusion_bundle` -- no
    HMAC key, no log access (Crosby & Wallach: no full replay).
    Raises ValueError when no signed checkpoint covers ``seq``.
    """
    entries, mat = _inclusion_material(path, [seq])
    proof_hex, cp = mat[seq]
    entry = entries[seq - 1][0]
    return {"bundle_version": 1,
            "kind": "inclusion",
            "entry": entry,
            "index": seq - 1,
            "proof": proof_hex,
            "tree_size": cp["seq"],
            "merkle_root": cp["merkle_root"],
            "checkpoint": cp}


def verify_inclusion_bundle(bundle, trusted_keys=None, roster=None,
                            root_pub=None):
    """Verify an inclusion bundle offline. Returns (ok, error).

    Checks (1) the covering checkpoint's signature set (single or
    k-of-n threshold) and (2) the Merkle inclusion proof against the
    checkpoint's signed root. Fail-closed throughout.
    """
    try:
        if not isinstance(bundle, dict) or bundle.get(
                "kind") != "inclusion":
            return False, "not an inclusion bundle"
        cp = bundle["checkpoint"]
        entry = bundle["entry"]
        index = bundle["index"]
        proof = [bytes.fromhex(p) for p in bundle["proof"]]
        tree_size = bundle["tree_size"]
        root_hex = bundle["merkle_root"]
    except (KeyError, TypeError, ValueError):
        return False, "malformed bundle"
    ok, err = _verify_one_checkpoint_sig(cp, trusted_keys, roster,
                                         root_pub)
    if not ok:
        return False, "checkpoint signature: %s" % err
    if cp["seq"] != tree_size or cp["merkle_root"] != root_hex:
        return False, "bundle/checkpoint root mismatch"
    try:
        leaf = _merkle.leaf_hash(_leaf_input(entry))
        root = bytes.fromhex(root_hex)
    except (KeyError, TypeError, ValueError):
        return False, "malformed entry/root in bundle"
    if _merkle.verify_inclusion(leaf, index, proof, root, tree_size):
        return True, None
    return False, "inclusion proof does not verify"


def prove_consistency(path, old_seq):
    """Build a consistency bundle: checkpoint@old_seq -> newest signed
    checkpoint (RFC 6962 section 2.1.2; the CT auditor flow).

    Proves the log only appended between the two heads: a history
    rewrite between them cannot produce a verifying proof. Raises
    ValueError when either endpoint lacks a signed checkpoint or a
    checkpoint root does not match the log.
    """
    cps = signed_checkpoints(path)
    olds = [c for c in cps if c["seq"] == old_seq]
    if not olds:
        raise ValueError(
            "no signed checkpoint at seq %d" % old_seq)
    old, new = olds[0], max(cps, key=lambda c: c["seq"])
    entries = _proof_entries(path)
    n = len(entries)
    for i, (e, _) in enumerate(entries):
        if e.get("seq") != i + 1:
            raise ValueError("log seq not dense at position %d" % i)
    if new["seq"] > n:
        raise ValueError("newest checkpoint beyond log end")
    leaves = [lf for _, lf in entries[:new["seq"]]]
    if _merkle.tree_root(leaves).hex() != new["merkle_root"]:
        raise ValueError("newest checkpoint root does not match the log")
    if _merkle.tree_root(leaves[:old["seq"]]).hex() != old["merkle_root"]:
        raise ValueError("old checkpoint root does not match the log")
    proof = _merkle.consistency_proof(leaves, old["seq"])
    return {"bundle_version": 1,
            "kind": "consistency",
            "old_seq": old["seq"],
            "new_seq": new["seq"],
            "old_root": old["merkle_root"],
            "new_root": new["merkle_root"],
            "proof": [p.hex() for p in proof],
            "old_checkpoint": old,
            "new_checkpoint": new}


def verify_consistency_bundle(bundle, trusted_keys=None, roster=None,
                              root_pub=None):
    """Verify a consistency bundle offline. Returns (ok, error).

    Verifies BOTH endpoint checkpoints' signature sets, then the RFC
    6962 consistency proof that the old tree is a prefix of the new
    tree. A forged proof (forked history, tampered nodes) fails here --
    see the K-049 / CT attack situations in tests/test_crypto_gov.py.
    """
    try:
        if not isinstance(bundle, dict) or bundle.get(
                "kind") != "consistency":
            return False, "not a consistency bundle"
        old_cp, new_cp = bundle["old_checkpoint"], bundle["new_checkpoint"]
        proof = [bytes.fromhex(p) for p in bundle["proof"]]
        old_root = bytes.fromhex(bundle["old_root"])
        new_root = bytes.fromhex(bundle["new_root"])
        old_seq, new_seq = bundle["old_seq"], bundle["new_seq"]
    except (KeyError, TypeError, ValueError):
        return False, "malformed bundle"
    for label, cp in (("old", old_cp), ("new", new_cp)):
        ok, err = _verify_one_checkpoint_sig(cp, trusted_keys, roster,
                                             root_pub)
        if not ok:
            return False, "%s checkpoint signature: %s" % (label, err)
    if old_cp["merkle_root"] != bundle["old_root"] \
            or new_cp["merkle_root"] != bundle["new_root"]:
        return False, "bundle/checkpoint root mismatch"
    if _merkle.verify_consistency(old_root, new_root, old_seq, new_seq,
                                  proof):
        return True, None
    return False, ("consistency proof does not verify: history between "
                   "the two heads is not a pure append")


# ---------------------------------------------------------------------------
# K-060: the audit trail as a live operational capability.
# ---------------------------------------------------------------------------


def query_log(path, principal=None, agent_id=None, event=None,
              since=None, until=None, limit=None):
    """Read-only filtered read of the audit log (K-060).

    Filters are ANDed; all are optional. ``principal`` / ``agent_id`` /
    ``event`` match the entry's conventional fields exactly.
    ``since`` / ``until`` compare against the entry ``ts`` ISO-8601
    strings (every writer timestamp shares ``_utcnow``'s format, so
    string comparison is chronological). Returns entries oldest-first,
    at most ``limit``.

    Never raises on content problems: unparseable lines are skipped --
    the query path READS, it does not judge; ``_verify`` judges.
    """
    out = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if principal is not None and entry.get(
                "principal") != principal:
            continue
        if agent_id is not None and entry.get(
                "agent_id") != agent_id:
            continue
        if event is not None and entry.get("event") != event:
            continue
        ts = entry.get("ts")
        if since is not None and (ts is None or ts < since):
            continue
        if until is not None and (ts is None or ts > until):
            continue
        out.append(entry)
        if limit is not None and len(out) >= limit:
            break
    return out


def export_bundle(path, roster=None, anchor_backend=None, **query):
    """K-060: tamper-evident export of a filtered audit trail.

    Returns ``{"export_version", "exported_at", "query", "entries",
    "proofs", "checkpoints", "roster"}`` where ``proofs`` maps each
    exported seq to its inclusion proof + covering checkpoint seq, and
    ``checkpoints`` are the distinct covering v2 checkpoints. The
    recipient verifies with :func:`verify_export_bundle`: every
    included entry is genuine (inclusion proof against a signed root)
    and correctly positioned.

    ``anchor_backend`` (optional, ``None`` = zero behavior change): a
    ``gov.anchor_backend.AnchorBackend``. When supplied, the bundle
    gains ``"anchor_receipt"`` -- the backend's receipt over the
    canonical head digest of the bundle's checkpoints
    (``gov.anchoring.bundle_head_digest``). The receipt commits the
    exporter to a specific set of signed heads at export time; with a
    real witness it defeats post-hoc history rewrites. Pass
    ``anchor_backend`` through to :func:`verify_export_bundle` to
    check the receipt.

    Honest scope: the bundle proves authenticity of INCLUDED entries,
    not completeness of the filter. An exporter who omits entries is
    the deployment itself; completeness against exporter misbehavior
    is K-049's transparency-anchor story, not this bundle's. Wave-142
    binds the filter PARAMETERS into the anchor (``"filter_digest"``,
    committed before anchoring): an anchor over a narrowed export is
    still an anchor over narrowed input, but the narrowing is now
    VISIBLE -- the receipt commits to the stated query as well as the
    checkpoints, so post-anchor filter tampering fails verification
    (``verify_export_bundle`` recomputes the digest). What the digest
    cannot do is judge whether the stated filter was wise -- that is
    the auditor's call. Raises ValueError when the log has no signed
    checkpoints (export needs signed heads to prove against), and
    TypeError on non-canonical filter values when anchoring (fail
    closed: refuse to anchor a filter the verifier cannot recompute).
    """
    entries = query_log(path, **query)
    seqs = [e["seq"] for e in entries
            if isinstance(e.get("seq"), int)]
    bundle = {"export_version": 1,
              "exported_at": _utcnow(),
              "query": dict(query),
              "entries": entries,
              "proofs": {},
              "checkpoints": [],
              "roster": roster}
    if seqs:
        _, mat = _inclusion_material(path, seqs)
        cps = {}
        for seq in seqs:
            proof_hex, cp = mat[seq]
            bundle["proofs"][str(seq)] = {"proof": proof_hex,
                                          "checkpoint_seq": cp["seq"]}
            cps[cp["seq"]] = cp
        bundle["checkpoints"] = [cps[k] for k in sorted(cps)]
    if anchor_backend is not None:
        # Wave-142 filter binding: commit to the filter/selection
        # parameters BEFORE anchoring, so the anchor receipt binds
        # WHAT WAS FILTERED (the stated query) as well as the
        # checkpoint head. Non-canonical filter values fail closed
        # here (TypeError from export_filter_digest): refuse to
        # anchor a filter the verifier could not recompute.
        # Unanchored exports skip this and stay byte-identical to
        # pre-wave-142 (no behavior change when anchoring is off).
        # NOTE: local import, not module-level: gov.sandbox must not
        # pull gov.anchor_backend into the process (test_w72_anchor
        # boundary).
        from . import anchoring as _anchoring
        bundle["filter_digest"] = _anchoring.export_filter_digest(
            dict(query))
        bundle["anchor_receipt"] = _anchoring.anchor_bundle(
            bundle, anchor_backend)
    return bundle


def verify_export_bundle(bundle, trusted_keys=None, roster=None,
                         root_pub=None, anchor_backend=None):
    """Verify a K-060 export bundle offline. Returns (ok, error).

    Checks: every entry's seq is sane and strictly increasing; every
    covering checkpoint's signature set verifies; every entry's
    inclusion proof verifies against its covering checkpoint's signed
    root. A bundle with entries removed, reordered, or forged in
    transit fails here.

    ``anchor_backend``: when the bundle carries ``"anchor_receipt"``
    (see :func:`export_bundle`), the receipt is verified against the
    bundle's head digest via this backend. A receipted bundle
    verified WITHOUT a backend fails closed -- the receipt is never
    silently skipped. Bundles without a receipt verify exactly as
    before (``anchor_backend`` is ignored).

    Wave-142: when the bundle carries ``"filter_digest"`` (anchored
    exports only), the digest is recomputed from the bundle's stated
    ``"query"`` and verification fails closed on mismatch -- filter
    parameters altered after anchoring do not verify, even when the
    checkpoint proofs are intact.
    """
    try:
        if not isinstance(bundle, dict) or bundle.get(
                "export_version") != 1:
            return False, "not an export bundle"
        entries = bundle["entries"]
        proofs = bundle["proofs"]
        cps = {c["seq"]: c for c in bundle["checkpoints"]}
    except (KeyError, TypeError):
        return False, "malformed bundle"
    if not isinstance(entries, list) or not isinstance(proofs, dict):
        return False, "malformed bundle"
    last_seq = 0
    for entry in entries:
        if not isinstance(entry, dict):
            return False, "malformed entry in bundle"
        seq = entry.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) \
                or seq <= last_seq:
            return False, "entries not strictly increasing at %r" % (
                seq,)
        last_seq = seq
        pentry = proofs.get(str(seq))
        if not isinstance(pentry, dict):
            return False, "no proof for exported seq %d" % seq
        cp = cps.get(pentry.get("checkpoint_seq"))
        if cp is None:
            return False, "covering checkpoint missing for seq %d" % seq
        ok, err = _verify_one_checkpoint_sig(cp, trusted_keys, roster,
                                             root_pub)
        if not ok:
            return False, "checkpoint@%d signature: %s" % (
                cp["seq"], err)
        try:
            leaf = _merkle.leaf_hash(_leaf_input(entry))
            proof = [bytes.fromhex(p) for p in pentry["proof"]]
            root = bytes.fromhex(cp["merkle_root"])
        except (KeyError, TypeError, ValueError):
            return False, "malformed proof/entry for seq %d" % seq
        if not _merkle.verify_inclusion(leaf, seq - 1, proof, root,
                                        cp["seq"]):
            return False, "inclusion proof failed for seq %d" % seq
    receipt = bundle.get("anchor_receipt")
    if receipt is not None:
        # The exporter committed to these checkpoints via an anchor
        # backend. Verify the commitment -- and never skip it silently:
        # a receipted bundle checked without a backend fails closed.
        if anchor_backend is None:
            return False, ("bundle carries an anchor receipt but no "
                           "anchor_backend was supplied to verify it")
        from . import anchoring as _anchoring
        ok, reason = _anchoring.verify_bundle_anchor(
            bundle, receipt, anchor_backend)
        if not ok:
            return False, "anchor receipt: %s" % (reason,)
    # Wave-142: filter binding. A bundle that claims a filter_digest
    # (anchored exports only) must have filter parameters consistent
    # with it: recompute the digest from the bundle's stated query and
    # fail closed on mismatch. Filter parameters altered after
    # anchoring fail here even when the checkpoint proofs and the
    # anchor receipt are otherwise intact. (Local import: keep
    # gov.anchor_backend out of the sandbox import graph --
    # test_w72_anchor boundary. Separate import because the receipt
    # branch above may not have run.)
    filter_digest = bundle.get("filter_digest")
    if filter_digest is not None:
        from . import anchoring as _anchoring
        if not isinstance(filter_digest, str):
            return False, "malformed filter_digest in bundle"
        try:
            expected = _anchoring.export_filter_digest(
                bundle.get("query", {}))
        except (TypeError, ValueError):
            return False, ("export filter parameters are not "
                           "canonically recomputable (filter_digest "
                           "mismatch)")
        if filter_digest != expected:
            return False, ("export filter parameters were altered "
                           "after anchoring (filter_digest mismatch)")
    return True, None


# ---------------------------------------------------------------------------
# F69 (HARDENING-R16): incremental chain-tip verification.
#
# The R15 F60 fix requires a full verify_chain() + full log re-read on
# every refused sweep while the lock-refusal coalescing sidecar is
# missing/corrupt -- O(n) per sweep, unbounded in log size. A run-dir
# writer can hold that state with one cheap sidecar-corruption write per
# sweep, turning every legitimate sweep into a CPU burn (availability
# only; the sweep still refuses fail-closed).
#
# The chain-tip cache makes the repeated case O(new entries): after any
# successful verification, the (seq, tip hash) of the verified tail is
# cached next to the log in ``<log>.tip.json``, MAC-authenticated under
# the log's own HMAC key. The next sweep re-verifies ONLY the entries
# appended since the cached tip. Anything the cache cannot vouch for --
# missing/corrupt tip, log shrunk, tip entry mismatch, segment failure --
# falls back to a FULL verify_chain() (fail-loud, never silent
# suppression).
#
# Soundness notes (why the cached prefix is never blindly trusted):
#
# 1. The tip cache is MAC'd (domain-separated "log-tip") under the log
#    key, so the F52 run-dir writer cannot FORGE a tip: any tampering
#    fails the MAC and degrades to full verification. Freshness is
#    bound too (F72): every tip write bumps a generation counter and
#    appends a MAC'd generation pin (separate "checkpoint-tipgen"
#    domain) to the checkpoint sidecar BEFORE the tip file lands. A
#    replayed older tip has a lower generation than the newest pin,
#    so _read_tip_cache rejects it and the sweep falls back to full
#    verification (which re-verifies the stale-but-genuine prefix and
#    reseeds). Replay never vouches unverified bytes, and now it does
#    not even vouch staleness silently. Residual: a writer who
#    truncates the sidecar past the newest pin AND replays an older
#    tip together forces one redundant full re-verification of
#    genuine bytes -- bounded cost, self-healing, still loud if the
#    bytes themselves were tampered.
# 2. The cached tip only vouches the prefix up to its seq; the sweep's
#    suppression decision additionally caches the newest verified
#    ``approval_sweep_refused`` timestamp per flag ("refusals") INSIDE
#    the MAC'd tip body, and each sweep scans ONLY the freshly
#    MAC-verified new segment. Prefix entries are never re-read for
#    the decision (length-preserving pre-tip content swaps that keep
#    the hash strings intact stay invisible to the incremental walk --
#    the r16-acknowledged residual), and any future full verification
#    still catches them loudly. Interrupted-execution recovery is NOT
#    subject to that residual (F70): the tip carries a MAC'd marker
#    manifest (approval_id -> latest ``execution_authorized`` seq over
#    the verified prefix), seeded after a full verify and folded
#    forward only from MAC-verified segments. Reconciliation compares
#    the unverified scan's prefix interrupted set against the manifest
#    BEFORE trusting the incremental verdict: a mismatch is positive
#    evidence of pre-tip marker tamper, audited LOUDLY (coalesced),
#    and the incremental verdict is discarded in favor of a full
#    verification. The manifest is never built from, or extended by,
#    unverified bytes.
# 3. The tip entry itself IS re-authenticated every sweep (its MAC is
#    recomputed), anchoring the new segment's prev_hash chain to
#    genuinely verified content, not just a matching hash string.
# 4. The checkpoint (tail-truncation) anchor is re-checked every sweep:
#    the sidecar prefix bytes are hash-pinned in the tip, new sidecar
#    lines are fully parsed, and the newest checkpoint's MAC, label,
#    and log agreement are verified exactly as in _verify.
# 5. A corrupted tip degrades to full-verify (slower but safe), never
#    to unverified trust. Residual: an attacker who corrupts the tip
#    cache itself on every sweep (one extra cheap write) still forces
#    the full path per sweep -- the tip must live in the attacker-
#    writable run dir, so this variant is documented, not fixed.
#
# Concurrency: tip writes are atomic (temp file + os.replace). Races
# between concurrent verifiers resolve to last-writer-wins; a stale tip
# is still a VALID tip (it vouches a genuine prefix), so the next sweep
# simply verifies a longer segment. Never unsafe, at most slower.

_TIP_CACHE_SUFFIX = ".tip.json"


def _tip_cache_path(path):
    return Path(str(path) + _TIP_CACHE_SUFFIX)


def _tip_mac(key, key_epoch, body_canonical):
    """Domain-separated MAC over the canonical tip body.

    The body covers seq, tip hash, cached refusals, AND the checkpoint
    anchor state -- every field the incremental decision depends on is
    authenticated, so none of it is attacker-malleable without the key.
    """
    msg = ("log-tip|%s|%s" % (key_epoch, body_canonical)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _tip_body(tip):
    """The MAC-covered fields of a tip dict (everything but ``mac``).

    ``tip_off``/``end_off`` are byte offsets into the action log at
    tip time: the tip line starts at ``tip_off`` and the file ended at
    ``end_off``. They are authenticated so a run-dir writer cannot
    make the sweep read a different window than the verified one.

    ``gen`` is the tip generation (F72): every tip write bumps it and
    appends a MAC'd generation pin to the checkpoint sidecar, so a
    replayed older tip is recognized as stale. ``pin_off`` is the
    sidecar byte offset where this tip's own pin was appended
    (measured before the append): the replay-freshness scan starts
    there, which keeps the scan O(new bytes) while remaining sound
    under concurrent tip writers -- any pin newer than this tip sits
    at or past pin_off. ``markers`` is the
    marker manifest (F70): approval_id -> latest ``execution_authorized``
    seq for approvals interrupted over the verified prefix. It is
    derived ONLY from MAC-verified bytes (seeded after a full verify,
    folded forward from newly verified segments), so the incremental
    path can trust the prefix's interrupted set without re-reading it.
    """
    return {
        "seq": tip["seq"],
        "tip": tip["tip"],
        "key_epoch": tip["key_epoch"],
        "refusals": tip["refusals"],
        "cp_size": tip["cp_size"],
        "pin_off": tip["pin_off"],
        "cp_digest": tip["cp_digest"],
        "cp_newest": tip["cp_newest"],
        "tip_off": tip["tip_off"],
        "end_off": tip["end_off"],
        "gen": tip["gen"],
        "markers": tip["markers"],
    }


def _read_tip_cache(path):
    """Return the validated tip dict, or None.

    Never raises and never returns an unvalidated tip: a missing file,
    unparseable JSON, wrong shape, epoch mismatch, or MAC failure all
    yield None (the caller falls back to full verification -- slower
    but safe, never unverified trust).
    """
    try:
        raw = json.loads(
            _tip_cache_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        tip = {
            "seq": int(raw["seq"]),
            "tip": raw["tip"],
            "key_epoch": raw["key_epoch"],
            "refusals": raw["refusals"],
            "cp_size": int(raw["cp_size"]),
            "pin_off": int(raw["pin_off"]),
            "cp_digest": raw["cp_digest"],
            "cp_newest": raw["cp_newest"],
            "tip_off": int(raw["tip_off"]),
            "end_off": int(raw["end_off"]),
            "gen": raw["gen"],
            "markers": raw["markers"],
            "mac": raw["mac"],
        }
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(tip["tip"], str):
        return None
    if not isinstance(tip["key_epoch"], str):
        return None
    if not isinstance(tip["mac"], str):
        return None
    if not isinstance(tip["refusals"], dict):
        return None
    if not isinstance(tip["cp_digest"], str):
        return None
    # F72/F70: the generation and the marker manifest are MAC-covered
    # tip fields; a tip without them (pre-fix cache) is unusable --
    # the caller re-verifies fully and reseeds (slower, never
    # unverified trust).
    if (not isinstance(tip["gen"], int) or isinstance(tip["gen"], bool)
            or tip["gen"] < 1):
        return None
    if not isinstance(tip["markers"], dict):
        return None
    for _aid, _aseq in tip["markers"].items():
        if not isinstance(_aid, str) or not _aid:
            return None
        if (not isinstance(_aseq, int) or isinstance(_aseq, bool)
                or _aseq < 1):
            return None
    if tip["cp_newest"] is not None and not isinstance(
            tip["cp_newest"], dict):
        return None
    if isinstance(tip["cp_newest"], dict):
        _cpn = tip["cp_newest"]
        if not isinstance(_cpn.get("seq"), int):
            return None
        if not isinstance(_cpn.get("hash"), str):
            return None
        if not isinstance(_cpn.get("mac"), str):
            return None
        if not isinstance(_cpn.get("key_epoch"), str):
            return None
    if tip["seq"] < 0:
        return None
    if tip["tip_off"] < 0 or tip["end_off"] < tip["tip_off"]:
        return None
    if tip["cp_size"] < 0:
        # A negative prefix bound would make the F72 suffix scan below
        # read from the end of the sidecar instead of the pinned
        # prefix's end -- reject like the other range violations.
        return None
    if tip["pin_off"] < 0 or tip["pin_off"] > tip["cp_size"]:
        # pin_off is the sidecar offset where this tip's own pin was
        # appended: every pin with a generation newer than this tip
        # that could make it stale sits at or past pin_off, so the
        # freshness scan below starts there. An out-of-range pin_off
        # breaks that invariant -- reject (fail-closed).
        return None
    key, active_epoch = _active_key()
    if tip["key_epoch"] != active_epoch:
        # Key rotation (or a foreign tip): the cached prefix was
        # verified under a different key -- do not extend it.
        return None
    expect = _tip_mac(key, active_epoch, _canonical(_tip_body(tip)))
    if not hmac.compare_digest(tip["mac"], expect):
        return None
    # F72: replay freshness. Every tip write bumps the generation and
    # appends a MAC'd pin to the checkpoint sidecar; a tip whose
    # generation is older than the newest pinned generation is a
    # REPLAYED tip -- the live chain advanced past it. Reject it (the
    # caller falls back to full verification, which re-verifies the
    # stale-but-genuine prefix and reseeds). A sidecar that cannot be
    # read cannot vouch freshness: reject as well (fail-closed).
    #
    # F69-flake hardening: the scan used to JSON-parse the ENTIRE
    # sidecar on every warm sweep -- O(sidecar) with a large constant,
    # eating most of the warm-sweep CPU bound (and growing with the
    # log, the F69 amplifier shape). Pins are append-only, so instead
    # of the whole sidecar the scan starts at this tip's pin_off --
    # the offset measured before its own pin was appended. Any pin appended
    # after that measurement sits at or past pin_off and the scan sees it.
    # A writer that raced an interleaved pin append BEFORE the measurement
    # can leave a genuine pin with a higher generation sitting before
    # pin_off; then a stale-but-genuine tip may be accepted. That is safe,
    # not a replay hole: the tip is MAC-authentic and vouches a
    # genuinely-verified prefix, and the incremental walk below still
    # re-verifies the entire live tail with full per-entry checks --
    # staleness costs redundant work, never trust in unverified bytes.
    # (The new scan window [pin_off:] is a superset of the old [cp_size:]
    # window, so every tip accepted under the new code was also accepted
    # under the old -- the change only adds rejections.)
    # This preserves the replay property under concurrent tip writers
    # (multi-process sweeps sharing a run dir): a racy newer pin that
    # lands inside the measured cp_size prefix is still at or past
    # pin_off, so the scan sees it and the stale tip is rejected.
    # A rewritten prefix or a shrunk sidecar still fails the
    # prefix-hash / shrink checks in verify_chain_tip (full-verify
    # fallback), and the documented F72 residual (truncate + replay ->
    # one redundant full re-verification) is unchanged.
    try:
        cp_bytes = (Path(str(path)).parent / "checkpoints.jsonl"
                    ).read_bytes()
    except OSError:
        return None
    if _max_pinned_tip_gen(cp_bytes[tip["pin_off"]:], key,
                           active_epoch) > tip["gen"]:
        return None
    return tip


def _write_tip_cache(path, tip):
    """Atomically persist a tip dict (temp file + os.replace + fsync).

    Raises OSError on I/O failure (callers treat this as best-effort:
    verification already succeeded; the next sweep just re-verifies a
    longer segment).
    """
    key, epoch = _active_key()
    if tip["key_epoch"] != epoch:
        raise ValueError("tip key_epoch does not match the active key")
    doc = _tip_body(tip)
    doc["mac"] = _tip_mac(key, epoch, _canonical(doc))
    cache_path = _tip_cache_path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_name(cache_path.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=True, sort_keys=True,
                           default=str))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, cache_path)


def _parse_checkpoint_newest(cps):
    """Newest checkpoint dict from parsed sidecar lines, or None."""
    if not cps:
        return None
    return max(cps, key=lambda c: c["seq"])


def verify_chain_tip(path, flags=()):
    """Incrementally verify the chain from the cached tip.

    Returns ``{"ok": True, "entries": n, "refusals": {flag: ts|None}}``
    when the new segment (entries after the
    cached tip) fully verifies -- the same per-entry checks as
    :func:`_verify` (seq continuity, format_version, prev_hash links,
    key_epoch binding, MACs) plus the checkpoint tail-truncation
    anchor -- and rewrites the tip cache to the new tail.

    Per-sweep cost: the action-log read is O(new bytes) via the tip's
    MAC-authenticated byte offsets (seek to the tip line, read only
    the tail) -- the full-file read that made the old F60 fallback
    O(log size) is gone. The checkpoint sidecar is still re-read and
    hash-pinned in full each sweep (O(sidecar), ~0.6ms/1k measured):
    its prefix hash is what keeps an already-verified sidecar byte
    from being rewritten silently, and there is no sublinear way to
    re-assert that. New sidecar lines are parsed incrementally.

    Returns None when incremental verification is impossible: tip
    missing/corrupt/foreign (MAC or epoch), log shrunk below the tip,
    tip entry mismatch, any segment or checkpoint-anchor failure. The
    caller MUST fall back to full verify_chain() (fail-loud), never
    treat the log as verified.

    Never returns ok=True on unverified data; never raises on file
    CONTENT problems (mirrors _verify's F28 contract: content anomalies
    become None, i.e. "do the loud full verification"). OSError from
    the log/sidecar reads propagates (callers fail loud on those).
    """
    tip = _read_tip_cache(path)
    if tip is None:
        return None
    key, epoch = _active_key()
    p = Path(path)
    seq = tip["seq"]
    tip_off = tip["tip_off"]
    end_off = tip["end_off"]

    # Byte-window read: the log bytes are O(new) per sweep, not
    # O(log size). The tip's offsets are MAC-authenticated, so a
    # run-dir writer cannot aim the window at forged content: any
    # insertion/deletion before the tip shifts the bytes at tip_off
    # (tip-line re-auth fails -> full verify), any shrink below
    # end_off is truncation (-> full verify), and any content swap
    # that keeps offsets+hashes is the invisible class of soundness
    # note 2 (it cannot alter the verified decision inputs).
    # OSError from stat/read propagates: callers fail loud on those.
    st_size = p.stat().st_size
    if st_size < end_off:
        # Log shrank below the cached tip: truncation (or rotation).
        # Do not extend the tip -- full verification decides loudly.
        return None
    with open(p, "rb") as f:
        if seq == 0:
            tip_raw = None
        else:
            f.seek(tip_off)
            tip_raw = f.readline()
            if not tip_raw.endswith(b"\n"):
                # Torn tip line (concurrent rotation/truncate):
                # full verification decides loudly.
                return None
        f.seek(end_off)
        tail = f.read()
    if seq > 0 and tip_raw is None:
        return None
    seg_lines = [ln for ln in tail.splitlines() if ln.strip()]
    count = seq + len(seg_lines)

    if seq == 0:
        if tip["tip"] != GENESIS:
            return None
        prev = GENESIS
    else:
        # Re-authenticate the tip entry: its stored hash must match the
        # cached tip AND recompute to the same value, so the new
        # segment chains onto genuinely verified content (a content
        # swap that keeps the hash string is caught here).
        try:
            tl = json.loads(tip_raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(tl, dict):
            return None
        if tl.get("seq") != seq:
            return None
        if tl.get("hash") != tip["tip"]:
            return None
        if tl.get("key_epoch") != epoch:
            return None
        try:
            prev_hash = tl["prev_hash"]
            recomputed = _compute_mac(key, epoch, prev_hash,
                                      _canonical(tl))
        except (KeyError, TypeError):
            return None
        if not hmac.compare_digest(tip["tip"], recomputed):
            return None
        prev = tip["tip"]

    # Strict per-entry verification of the new segment -- the same
    # checks _verify applies, so a planted/forged/reordered line in the
    # segment degrades to full verification (loud), never to trust.
    new_entries = []
    expected_seq = seq + 1
    for raw in seg_lines:
        try:
            entry = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(entry, dict):
            return None
        if entry.get("seq") != expected_seq:
            return None
        if entry.get("format_version") != FORMAT_VERSION:
            return None
        if entry.get("prev_hash") != prev:
            return None
        if entry.get("key_epoch") != epoch:
            return None
        mac = _compute_mac(key, epoch, prev, _canonical(entry))
        if not hmac.compare_digest(entry.get("hash", ""), mac):
            return None
        new_entries.append(entry)
        prev = entry["hash"]
        expected_seq += 1

    # Checkpoint tail-truncation anchor, exactly as strict as _verify:
    # the sidecar prefix is hash-pinned in the tip (any rewrite of
    # already-verified sidecar bytes -> full verify), new sidecar lines
    # are fully parsed (any bad line -> full verify), and the newest
    # checkpoint's MAC, label, and agreement with the log are checked.
    cp_path = p.parent / "checkpoints.jsonl"
    try:
        cp_bytes = cp_path.read_bytes()
    except OSError:
        cp_bytes = None
    if count > 0 and cp_bytes is None:
        # F27 twin: non-empty log with no truncation anchor -- never
        # bless it incrementally.
        return None
    if cp_bytes is None:
        new_cp_lines = []
    else:
        if len(cp_bytes) < tip["cp_size"]:
            # Sidecar shrank: checkpoints were pruned. Do not trust the
            # remaining anchor incrementally -- full verify decides.
            return None
        if (hashlib.sha256(cp_bytes[:tip["cp_size"]]).hexdigest()
                != tip["cp_digest"]):
            # Already-verified sidecar bytes were rewritten.
            return None
        new_cp_lines = cp_bytes[tip["cp_size"]:].splitlines()
    new_cps, n_bad = _parse_sidecar_lines(new_cp_lines)
    if n_bad:
        # F28: a corrupt sidecar line is a verdict, never trust.
        return None
    newest = _parse_checkpoint_newest(new_cps)
    stored_newest = tip["cp_newest"]
    if newest is None:
        newest = stored_newest
    elif stored_newest is not None and stored_newest["seq"] > newest["seq"]:
        newest = stored_newest
    if newest is not None:
        cp_label = newest.get("key_epoch")
        if cp_label != epoch:
            return None
        # A tip-generation pin line carries its generation in a
        # separate MAC domain; dispatch so pins verify under it.
        # F202: v2 heads bind ts into the mac (see _verify above).
        expect_cp = _checkpoint_mac(key, cp_label, newest["seq"],
                                    newest["hash"],
                                    _pin_gen_of(newest),
                                    ts=newest.get("ts"))
        if not hmac.compare_digest(newest.get("mac", ""), expect_cp):
            return None
        if count < newest["seq"]:
            # Tail truncation past the newest anchor.
            return None
        if newest["seq"] > seq:
            # The anchor sits inside the freshly verified segment:
            # check agreement against the verified entries.
            anchor_entry = new_entries[newest["seq"] - seq - 1]
            if anchor_entry["hash"] != newest["hash"]:
                return None
        # (newest["seq"] <= seq: agreement was established when the tip
        # was written; the tip's induction covers the prefix.)
    elif count > 0:
        # Non-empty log, no checkpoints at all (empty sidecar): the
        # F27 twin -- never bless incrementally.
        return None

    # The suppression decision inputs: cached newest-refusal timestamps
    # (MAC'd in the tip, computed over verified entries) extended with
    # the freshly verified segment. Prefix entries are never re-read
    # for the decision (soundness note 2).
    refusals = {flag: tip["refusals"].get(flag) for flag in flags}
    for e in new_entries:
        if e.get("event") == "approval_sweep_refused":
            fl = e.get("flag")
            if fl in refusals and isinstance(e.get("ts"), str):
                refusals[fl] = e["ts"]

    # Advance the tip to the new tail (best-effort: a failed write only
    # costs the next sweep a longer segment, never safety). The byte
    # offsets make the next sweep's read O(new bytes): the tip line
    # starts at tip_off and the file ended at end_off.
    #
    # F70: fold the freshly verified segment's markers into the
    # manifest. Only entries whose MACs just verified contribute, so
    # the manifest stays a pure derivation of authenticated bytes;
    # the new tip's MAC vouches it. Cost is O(new markers), not O(log).
    markers = dict(tip["markers"])
    _auth_seg, _done_seg = _marker_sets(new_entries)
    for _aid, _aseq in _auth_seg.items():
        if _aseq > markers.get(_aid, 0):
            markers[_aid] = _aseq
    for _aid, _dseq in _done_seg.items():
        if _dseq >= markers.get(_aid, 0):
            markers.pop(_aid, None)
    # F72: every tip write bumps the generation and appends a MAC'd
    # generation pin to the sidecar BEFORE the tip file lands, so a
    # replayed older tip is recognized as stale. Best-effort: a pin
    # failure only weakens replay detection for this generation,
    # never verification.
    new_gen = tip["gen"] + 1
    all_cp = cp_bytes if cp_bytes is not None else b""
    # F72/pin_off: record the sidecar size BEFORE our pin lands. The
    # freshness scan in _read_tip_cache starts at pin_off, so any pin
    # newer than this tip -- including one a concurrent writer
    # interleaves between our pin and our size measurement -- sits at
    # or past pin_off and is seen. (On pin failure the size is still a
    # sound lower bound: future pins only ever append past it.)
    pin_off = len(all_cp)
    try:
        _append_tip_gen_pin(path, count, prev, new_gen)
        all_cp = cp_path.read_bytes()
    except OSError:
        pass
    if count == 0:
        new_tip_off = 0
        new_end_off = 0
    elif seg_lines:
        # The new tip line is the last non-blank line of the freshly
        # verified tail window; locate its start exactly.
        new_end_off = end_off + len(tail)
        body = tail.rstrip(b"\n")
        new_tip_off = end_off + body.rfind(b"\n") + 1
    else:
        # No new entries: the tip line and file end are unchanged.
        new_tip_off = tip_off
        new_end_off = end_off
    # The stored newest-checkpoint keeps its key_epoch: the re-check
    # below MACs (epoch, seq, hash), so a cross-epoch anchor is
    # rejected even when no new sidecar lines arrived this sweep.
    new_cp_newest = None
    if newest is not None:
        new_cp_newest = {"seq": newest["seq"], "hash": newest["hash"],
                         "mac": newest.get("mac"),
                         "key_epoch": newest.get("key_epoch")}
    new_tip = {
        "seq": count,
        "tip": prev,
        "key_epoch": epoch,
        "refusals": refusals,
        "cp_size": len(all_cp),
        "cp_digest": hashlib.sha256(all_cp).hexdigest(),
        "pin_off": pin_off,
        "cp_newest": new_cp_newest,
        "tip_off": new_tip_off,
        "end_off": new_end_off,
        "gen": new_gen,
        "markers": markers,
    }
    try:
        _write_tip_cache(path, new_tip)
    except OSError:
        pass
    return {"ok": True, "entries": count, "refusals": refusals,
            "markers": dict(markers)}


def newest_refusal_ts_per_flag(path, flags):
    """Full-log scan: newest ``approval_sweep_refused`` ts per flag.

    O(n): used only by the full-verification fallback (and tip seeding)
    after the chain has verified. Entries are chronological, so the
    first match in reverse is the newest; entries with unparseable or
    missing timestamps are skipped (fail-loud: they never suppress),
    mirroring the executor's historical scan semantics.
    """
    entries, _malformed = read_entries_with_stats(path)
    out = {flag: None for flag in flags}
    remaining = set(flags)
    for e in reversed(entries):
        if not remaining:
            break
        if not isinstance(e, dict):
            continue
        if e.get("event") != "approval_sweep_refused":
            continue
        fl = e.get("flag")
        if fl not in remaining:
            continue
        ts = e.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            continue
        out[fl] = ts
        remaining.discard(fl)
    return out


def _tail_line_offsets(p):
    """(tip_off, end_off, last_line_bytes) for the log's last line.

    Walks back from EOF in chunks, so finding the tail is O(tail),
    not O(log size). Returns (0, 0, None) for an empty/blank log.
    """
    with open(p, "rb") as f:
        f.seek(0, 2)
        end_off = f.tell()
        buf = b""
        pos = end_off
        # Walk back until we hold at least two newlines (the last
        # line plus its terminator) or reach BOF.
        while pos > 0 and buf.count(b"\n") < 2:
            step = min(65536, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
    body = buf.rstrip(b"\n")
    if not body.strip():
        return 0, 0, None
    ls = body.rfind(b"\n")
    tip_off = pos + ls + 1
    return tip_off, end_off, body[ls + 1:]


def write_chain_tip_from_tail(path, refusals):
    """Seed the tip cache from the current tail after a FULL verify.

    Reads the last log entry (seq, hash) and the checkpoint sidecar,
    then writes the MAC'd tip. Raises OSError on I/O failure (callers
    treat seeding as best-effort). Must only be called when the chain
    has JUST fully verified -- the tip vouches the whole prefix.

    Returns the seeded marker manifest (F70): approval_id -> latest
    ``execution_authorized`` seq for approvals interrupted over the
    verified prefix. Seeding is the only place the manifest is built
    from scratch; afterwards it is only folded forward from
    MAC-verified segments.
    """
    key, epoch = _active_key()
    p = Path(path)
    tip_off, end_off, last_raw = _tail_line_offsets(p)
    last_seq, last_hash = 0, GENESIS
    if last_raw is not None:
        entry = json.loads(last_raw)
        last_seq = int(entry["seq"])
        last_hash = entry["hash"]
    # F70: seed the marker manifest from the just-verified log. The
    # caller guarantees every byte below is authenticated.
    # Best-effort: if the log cannot be re-read here, seed an empty
    # manifest (the next incremental cycle re-derives it) rather than
    # failing the seed.
    try:
        _seed_entries, _ = read_entries_with_stats(str(p))
        _auth, _done = _marker_sets(_seed_entries)
        markers = {aid: aseq for aid, aseq in _auth.items()
                   if aseq > _done.get(aid, 0)}
    except OSError:
        markers = {}
    cp_path = p.parent / "checkpoints.jsonl"
    try:
        cp_bytes = cp_path.read_bytes()
    except OSError:
        cp_bytes = b""
    # F72: bump the generation and pin it in the sidecar BEFORE the
    # tip file lands (best-effort: a pin failure only weakens replay
    # detection for this generation, never verification).
    gen = _max_pinned_tip_gen(cp_bytes, key, epoch) + 1
    # F72/pin_off: see the advance path above -- the size before our
    # pin lands is the sound scan start for this tip's freshness.
    pin_off = len(cp_bytes)
    try:
        _append_tip_gen_pin(path, last_seq, last_hash, gen)
        cp_bytes = cp_path.read_bytes()
    except OSError:
        pass
    cps, _n_bad = _parse_sidecar_lines(cp_bytes.splitlines())
    newest = _parse_checkpoint_newest(
        [c for c in cps if isinstance(c.get("seq"), int)])
    new_tip = {
        "seq": last_seq,
        "tip": last_hash,
        "key_epoch": epoch,
        "refusals": {flag: refusals.get(flag) for flag in refusals},
        "cp_size": len(cp_bytes),
        "cp_digest": hashlib.sha256(cp_bytes).hexdigest(),
        "pin_off": pin_off,
        "cp_newest": ({"seq": newest["seq"], "hash": newest["hash"],
                       "mac": newest.get("mac"),
                       "key_epoch": newest.get("key_epoch")}
                      if newest is not None else None),
        "tip_off": tip_off,
        "end_off": end_off,
        "gen": gen,
        "markers": markers,
    }
    _write_tip_cache(path, new_tip)
    return dict(markers)


def refusal_ts_within_window(ts, window_secs):
    """True when an ISO refusal timestamp is genuinely recent.

    Future-dated or unparseable timestamps never count (fail-loud:
    at most one extra audit entry), mirroring the executor's
    historical scan semantics.
    """
    if not isinstance(ts, str):
        return False
    try:
        age = time.time() - datetime.fromisoformat(ts).timestamp()
    except (TypeError, ValueError):
        return False
    return 0 <= age <= window_secs
