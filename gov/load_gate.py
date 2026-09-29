"""Artifact digest-verification gate (wave-78, supply-chain enforcement).

The Plugin4Shell lesson (CVE-2026-92104): **verify != checkout; a pinned
reference is not a pinned artifact.** Four coding agents verified a
plugin's pinned commit hash but never confirmed the checked-out tree
matched it — a branch named as the 40-hex SHA shadowed the commit and
the load path resolved the branch. Zero-click via background
auto-update; ~925 plugins hijacked.

This module is the governed load path for every loadable artifact the
agent consumes (skills, policy files, tool-definition bundles — the
inventory is in ``workstreams/architect/SUPPLYCHAIN_DESIGN.md`` §a).
The protocol:

1. **Pins are digests, never references.** A pin is ``sha256:<64-hex>``.
   Branch names, tags, ``latest``, version strings — and 40-hex git
   SHAs, which are *references*, not digests — are refused at pin time.
2. **Resolve -> fetch -> verify -> load.** The loader hashes the
   fetched bytes and compares against the pin. Mismatch: fail closed,
   loud (``ArtifactRefused`` + a chained ``artifact_load_refused``
   record). Nothing is loaded on refusal.
3. **The ref namespace never enters the governed load path.** The
   module ships a *simulated* ``RefResolver`` that models the
   Plugin4Shell attack shapes (branch named as the 40-hex SHA
   shadowing the commit, FETCH_HEAD games, tag-vs-branch confusion) so
   break-first probes can replay the attack against a *legacy* loader.
   The governed loader never calls it; a load request carrying a
   reference instead of a digest is refused as ``reference_not_digest``.
4. **TOCTOU binding.** Verification and load operate on the *same
   in-memory bytes object*: the loader reads once, hashes the bytes it
   holds, and the consumer receives exactly those bytes
   (:class:`VerifiedArtifact`). There is no re-read, no re-fetch, no
   path a swapped store can interpose on between the hash check and
   the handoff. Consumers MUST use ``.data`` and never re-read the
   source.

Trust-on-first-use seam (§c of the design doc): there is **no TOFU** in
the governed path. Loading an unpinned artifact is refused
(``artifact_unpinned``). The first digest pin is a policy-grade
decision: ``ArtifactPinset.pin`` requires an Ed25519 authorship token
from a roster human key (``DelegationTrust.human_keys`` — the wave-75
construction), verified in code on the only mutation path, and each
mutation is a chained provenance record (``artifact_pinned`` /
``artifact_unpinned``).

TUF prior art, scoped honestly: hash-verified targets + a root of
trust for metadata + fail-closed verification before use are IN;
multi-role delegation, threshold signing, and snapshot/timestamp
freshness roles are OUT. This is not TUF.

$0 spend, synthetic/local deterministic only. No network, no git, no
real filesystem mutation beyond the caller's own temp files.
"""

import hashlib
import re
from datetime import datetime, timedelta, timezone

from .delegation_tokens import DelegationTrust
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

__all__ = [
    "ArtifactRefused",
    "RefnameAmbiguousError",
    "VerifiedArtifact",
    "RefResolver",
    "legacy_load_via_refs",
    "ArtifactPinset",
    "verify_and_load",
    "load_file_verified",
    "SkillLoader",
    "load_skill_content",
    "is_digest_pin",
    "CorpusManifestTracker",
]


class ArtifactRefused(Exception):
    """Fail-closed: an artifact load was refused. The ``reason`` attribute
    is a machine-readable code (``digest_mismatch``,
    ``artifact_unpinned``, ``reference_not_digest``,
    ``pin_authorship_invalid``, ``refname_ambiguous``)."""


class RefnameAmbiguousError(ArtifactRefused):
    """A reference resolved ambiguously (the Plugin4Shell shape)."""


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def is_digest_pin(value):
    """True only for a well-formed ``sha256:<64-hex>`` digest pin."""
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# RefResolver: the SIMULATED attack surface (legacy loader support).
#
# Models a git-like ref namespace so probes can replay Plugin4Shell
# against the UNGOVERNED path. The governed loader never calls this.
# ---------------------------------------------------------------------------

class RefResolver:
    """Simulated reference -> bytes resolution with the CVE-2026-92104
    shapes: a branch whose name is the 40-hex pinned SHA shadows the
    commit (git prefers a ref over a commit of the same name), and a
    poisoned FETCH_HEAD can redirect a fetch."""

    def __init__(self):
        self._commits = {}   # sha40 -> bytes
        self._branches = {}  # name -> bytes
        self._tags = {}      # name -> bytes
        self.fetch_head = None
        self.warnings = []   # the warnings nobody reads

    def add_commit(self, sha40, data):
        if not _HEX40_RE.match(sha40 or ""):
            raise ValueError("commit id must be 40-hex")
        self._commits[sha40.lower()] = bytes(data)

    def add_branch(self, name, data):
        self._branches[str(name)] = bytes(data)

    def add_tag(self, name, data):
        self._tags[str(name)] = bytes(data)

    def resolve(self, reference):
        """Resolve *reference* the way the vulnerable agents did.

        Returns ``(bytes, resolution_note)``. When a branch name shadows
        a commit SHA, the BRANCH wins (the CVE shape) and a
        ``refname is ambiguous`` warning is recorded — the warning the
        agents never surfaced. FETCH_HEAD indirection is honored, so a
        poisoned FETCH_HEAD redirects the fetch."""
        ref = str(reference)
        if ref == "FETCH_HEAD":
            if self.fetch_head is None:
                raise RefnameAmbiguousError(
                    "FETCH_HEAD unset: cannot resolve (fail closed)")
            # FETCH_HEAD games: the pointer itself is attacker-influenced.
            data = self._branches.get(self.fetch_head,
                                      self._commits.get(self.fetch_head.lower()))
            if data is None:
                raise RefnameAmbiguousError(
                    "FETCH_HEAD points nowhere known (fail closed)")
            return data, "resolved via FETCH_HEAD -> %r" % self.fetch_head
        candidates = []
        if ref in self._branches:
            candidates.append(("branch", self._branches[ref]))
        if ref in self._tags:
            candidates.append(("tag", self._tags[ref]))
        if _HEX40_RE.match(ref) and ref.lower() in self._commits:
            candidates.append(("commit", self._commits[ref.lower()]))
        if not candidates:
            raise RefnameAmbiguousError(
                "reference %r resolves to nothing (fail closed)" % ref)
        if len(candidates) > 1:
            # The CVE shape: git prefers the ref over the commit.
            kinds = sorted(k for k, _ in candidates)
            self.warnings.append(
                "warning: refname %r is ambiguous (%s)" % (ref, ",".join(kinds)))
            for kind, data in candidates:
                if kind != "commit":
                    return data, "ambiguous refname resolved to %s (branch/tag preferred over commit)" % kind
        return candidates[0][1], "resolved to %s" % candidates[0][0]


def legacy_load_via_refs(resolver, reference):
    """The UNGOVERNED loader: resolves a reference and returns the bytes.

    This is what the four vulnerable agents effectively did. Probes use
    it to prove the attack shape works on the legacy path (returns
    attacker bytes while the caller believes it honored the pin), then
    prove the governed gate refuses the same input."""
    data, _note = resolver.resolve(reference)
    return data


# ---------------------------------------------------------------------------
# VerifiedArtifact: the TOCTOU binding.
# ---------------------------------------------------------------------------

class VerifiedArtifact:
    """Bytes that were hashed and matched the pin — the SAME bytes the
    consumer must use.

    The binding is structural: the loader reads the source ONCE into
    ``data``, hashes ``data``, and hands the caller this object. There
    is no second read and no path back to the source, so a store swap
    between verification and handoff cannot reach the consumer. Any
    loader that re-reads the source after calling this gate has left
    the governed path — that is a code-review invariant, pinned by
    probe ``toctou_swap_between_verify_and_load``."""

    __slots__ = ("artifact_id", "digest", "data", "verified_at")

    def __init__(self, artifact_id, digest, data):
        self.artifact_id = artifact_id
        self.digest = digest
        self.data = bytes(data)
        self.verified_at = _utcnow_iso()

    def __repr__(self):
        return "VerifiedArtifact(%r, %s, %d bytes)" % (
            self.artifact_id, self.digest, len(self.data))


# ---------------------------------------------------------------------------
# ArtifactPinset: the governed pin registry.
# ---------------------------------------------------------------------------

# Wave-194 lane A (TUF-steal): the pin protocol is now v2. Version and
# expiry are bound INSIDE the authorship-signed body (TUF signs expires in
# the metadata for the same reason): a replayed old pin statement cannot
# have its expiry rewritten without breaking authorship, and the domain
# bump keeps v1 (freshness-less) statements from verifying under the new
# parser at all.
_PIN_DOMAIN = b"gov-artifact-pin/v2\x00"

# TUF-steal freshness constants — deliberately the same values as the
# watch layer's wave-179 steal (gov/skill_watch.py: _PIN_NOT_AFTER_TTL_SECONDS,
# _PIN_MANIFEST_VERSION_START) so the two registries tell one freshness
# story. The parse rules are duplicated here (not imported) to keep the
# load gate free of a skill_watch import; semantics are identical: strict
# ISO-8601, timezone required, naive refused, fail closed.
_PIN_NOT_AFTER_TTL_SECONDS = 90 * 24 * 3600  # default pin lifetime: 90 days
_PIN_VERSION_START = 1


def _check_pin_version(value, *, field="pin version"):
    """Validate a monotonic pin version. Fail closed."""
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < _PIN_VERSION_START):
        raise ArtifactRefused(
            "%s must be an integer >= %d, got %r"
            % (field, _PIN_VERSION_START, value))
    return value


def _parse_pin_not_after(value, *, context):
    """Strictly parse a pin ``not_after`` bound. Fail closed.

    Must be a non-empty ISO-8601 string with explicit timezone info.
    Naive datetimes are refused outright — never silently assumed UTC.
    Returns the parsed tz-aware datetime.
    """
    if not isinstance(value, str) or not value.strip():
        raise ArtifactRefused(
            "%s: pin not_after must be a non-empty ISO-8601 string "
            "with timezone, got %r" % (context, value))
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ArtifactRefused(
            "%s: pin not_after %r is not valid ISO-8601"
            % (context, value))
    if parsed.tzinfo is None:
        raise ArtifactRefused(
            "%s: pin not_after %r has no timezone (naive datetimes "
            "refused: never assume UTC)" % (context, value))
    return parsed


def _resolve_pin_not_after(ts, not_after):
    """Resolve the effective not_after for a pin statement.

    An explicit bound is strictly parsed (fail closed); when absent, the
    pin lives 90 days from its pinned_at (mirrors the watch layer's
    ``_default_not_after``). Returns the NORMALIZED ISO-8601 string —
    normalization keeps the signed body canonical (``Z`` vs ``+00:00``
    spellings sign identically).
    """
    if not_after is None:
        base = _parse_pin_not_after(ts, context="pin ts")
        return (base + timedelta(seconds=_PIN_NOT_AFTER_TTL_SECONDS)
                ).isoformat(timespec="seconds")
    return _parse_pin_not_after(
        not_after, context="pin not_after").isoformat(timespec="seconds")

# Deployment tiers for pin mutations. The wave-75 nuclear rule applies:
# production pin changes need TWO distinct roster human keys; dev/test/
# staging take single-human. The tier is committed in the canonical body
# so a one-key signature can never be replayed as a production approval
# (no tier-downgrade / tier-upgrade games).
_PIN_TIERS = ("dev", "test", "staging", "production")


def _canonical_pin_body(tier, artifact_id, digest, ts, *, version,
                        not_after):
    """Canonical bytes the pin authorship signs.

    ``version`` and ``not_after`` are REQUIRED keywords — there is no
    silent default inside the signed body; callers resolve via
    :func:`_resolve_pin_not_after` first, so what the human signed is
    exactly what the pinset enforces.
    """
    _check_pin_version(version)
    return b"|".join([
        _PIN_DOMAIN,
        tier.encode("utf-8"),
        artifact_id.encode("utf-8"),
        digest.encode("utf-8"),
        ts.encode("utf-8"),
        str(version).encode("utf-8"),
        not_after.encode("utf-8"),
    ])


def _canonical_unpin_body(tier, artifact_id, ts, *, version):
    """Canonical bytes the unpin authorship signs.

    The unpin carries the pin version it removes: a replayed older unpin
    statement cannot delete a newer pin (``unpin_version_not_monotonic``).
    """
    _check_pin_version(version, field="unpin version")
    return b"|".join([
        _PIN_DOMAIN,
        tier.encode("utf-8"),
        artifact_id.encode("utf-8"),
        b"UNPIN",
        ts.encode("utf-8"),
        str(version).encode("utf-8"),
    ])


class ArtifactPinset:
    """The governed digest-pin registry.

    Pins are ``{artifact_id: {digest, pinned_by, approvals, tier,
    pinned_at, version, not_after}}``. The ONLY mutation path is
    :meth:`pin` / :meth:`unpin`, which require Ed25519 authorship from
    roster human keys (``DelegationTrust.human_keys``) — the wave-75
    construction applied to digest pins, including the nuclear tier rule:
    production needs two DISTINCT human keys, dev/test/staging take
    single-human. Mutations are appended as chained log records
    (``artifact_pinned`` / ``artifact_unpinned``) when a log is
    provided.

    Wave-194 lane A (TUF-steal): every pin carries a monotonic
    ``version`` (integer >= 1) and a ``not_after`` expiry bound, both
    covered by the pin authorship signature. Re-pinning at a
    non-increasing version is refused (``pin_version_not_monotonic``) —
    a replayed older pin statement, however legitimately signed, can
    never displace a newer pin. :func:`verify_and_load` refuses pins
    whose ``not_after`` has passed (``pin_expired``) before checking
    the digest, mirroring the watch layer's stale-pin refusal.

    A 40-hex git SHA is refused as a pin value: it is a *reference*,
    not a digest (the exact confusion Plugin4Shell exploited). Only
    ``sha256:<64-hex>`` pins are accepted."""

    def __init__(self, trust, log=None):
        if not isinstance(trust, DelegationTrust):
            raise TypeError("trust must be a DelegationTrust")
        self._trust = trust
        self._log = log
        self._pins = {}

    # -- mutation (the only path) --------------------------------------

    def pin(self, artifact_id, digest, author_key_id, authorship_sig_hex,
            *, ts=None, tier="production", second_author_key_id=None,
            second_authorship_sig_hex=None, version=_PIN_VERSION_START,
            not_after=None):
        """Pin *digest* for *artifact_id* under human authorship.

        ``authorship_sig_hex`` is the Ed25519 signature (by the private
        key for ``author_key_id``) over the canonical pin body
        (tier|artifact_id|digest|ts|version|not_after). The wave-75 tier
        rule applies: ``tier="production"`` (the default) requires a
        SECOND approval from a DISTINCT roster human key over the
        identical body — the same key twice is refused;
        dev/test/staging take single-human.

        ``version`` (default 1) must move strictly upward per artifact:
        re-pinning at a non-increasing version is refused
        (``pin_version_not_monotonic``) — the TUF rollback floor, so a
        replayed older pin statement can never displace a newer pin.
        ``not_after`` is the pin's expiry bound (strict ISO-8601 with
        timezone; naive/malformed refused); when omitted the pin lives
        90 days from ``ts`` (mirrors the watch layer). Renewal is a
        re-pin at a HIGHER version with fresh authorship.

        Raises :class:`ArtifactRefused` (``pin_authorship_invalid``) on
        any authorship failure, and refuses non-digest pin values at
        once.
        """
        if not artifact_id or not isinstance(artifact_id, str):
            raise ArtifactRefused("pin refused: bad artifact_id")
        if tier not in _PIN_TIERS:
            raise ArtifactRefused("pin refused: unknown tier %r" % (tier,))
        if not is_digest_pin(digest):
            # Covers branch names, tags, "latest", version strings, AND
            # 40-hex git SHAs: a pinned reference is not a pinned
            # artifact.
            raise ArtifactRefused(
                "pin refused: %r is not a sha256 digest pin "
                "(references are never pinned)" % (digest,))
        ts = ts or _utcnow_iso()
        version = _check_pin_version(version)
        not_after = _resolve_pin_not_after(ts, not_after)
        body = _canonical_pin_body(tier, artifact_id, digest, ts,
                                   version=version, not_after=not_after)
        # Authorship is verified BEFORE the version floor (TUF order:
        # signature first, then freshness): a forged statement reports
        # pin_authorship_invalid precisely, and only a genuinely-signed
        # older statement reaches the rollback floor below.
        approvals = self._require_approvals(
            body, tier, author_key_id, authorship_sig_hex,
            second_author_key_id, second_authorship_sig_hex)
        existing = self._pins.get(artifact_id)
        if existing is not None and version <= existing["version"]:
            raise ArtifactRefused(
                "pin_version_not_monotonic: pin for %r is at version %d; "
                "re-pin at version %d refused (versions move strictly "
                "upward; a replayed older pin statement cannot displace "
                "a newer pin)" % (artifact_id, existing["version"], version))
        self._pins[artifact_id] = {
            "digest": digest,
            "pinned_by": author_key_id,
            "approvals": approvals,
            "tier": tier,
            "pinned_at": ts,
            "version": version,
            "not_after": not_after,
        }
        if self._log is not None:
            self._log.append({
                "event": "artifact_pinned",
                "artifact_id": artifact_id,
                "digest": digest,
                "pinned_by": author_key_id,
                "approvals": approvals,
                "tier": tier,
                "version": version,
                "not_after": not_after,
            })
        return dict(self._pins[artifact_id])

    def _require_approvals(self, body, tier, author_key_id,
                           authorship_sig_hex, second_author_key_id,
                           second_authorship_sig_hex):
        """Verify one (dev/test/staging) or two distinct (production)
        roster-human approvals over the identical canonical body."""
        approvals = [self._verify_approval(body, author_key_id,
                                            authorship_sig_hex)]
        if tier == "production":
            if not second_author_key_id or not second_authorship_sig_hex:
                raise ArtifactRefused(
                    "pin_authorship_invalid: production tier requires "
                    "two distinct human approvals (wave-75 nuclear rule)")
            if second_author_key_id == author_key_id:
                raise ArtifactRefused(
                    "pin_authorship_invalid: production approvals must "
                    "come from two DISTINCT keys (same key twice refused)")
            approvals.append(self._verify_approval(
                body, second_author_key_id, second_authorship_sig_hex))
        return approvals

    def _verify_approval(self, body, author_key_id, authorship_sig_hex):
        pub = self._trust.human_keys.get(author_key_id)
        if pub is None:
            raise ArtifactRefused(
                "pin_authorship_invalid: unknown author key %r"
                % (author_key_id,))
        try:
            sig = bytes.fromhex(authorship_sig_hex)
        except (TypeError, ValueError):
            raise ArtifactRefused(
                "pin_authorship_invalid: malformed signature")
        if not _ed_verify(pub, body, sig):
            raise ArtifactRefused(
                "pin_authorship_invalid: bad signature for %r"
                % (author_key_id,))
        return author_key_id

    def unpin(self, artifact_id, author_key_id, authorship_sig_hex, *,
              ts=None, tier="production", second_author_key_id=None,
              second_authorship_sig_hex=None, version=_PIN_VERSION_START):
        """Remove a pin (same tier/authorship rule as pin).

        ``version`` must be strictly greater than the pin's current
        version: a replayed older unpin statement cannot delete a newer
        pin (``unpin_version_not_monotonic``). The unpin authorship
        signs the version it removes.
        """
        if artifact_id not in self._pins:
            raise ArtifactRefused(
                "unpin refused: no pin for %r" % (artifact_id,))
        if tier not in _PIN_TIERS:
            raise ArtifactRefused("unpin refused: unknown tier %r" % (tier,))
        ts = ts or _utcnow_iso()
        version = _check_pin_version(version, field="unpin version")
        body = _canonical_unpin_body(tier, artifact_id, ts, version=version)
        # Authorship before the version floor (same TUF order as pin):
        # a forged unpin reports pin_authorship_invalid precisely.
        approvals = self._require_approvals(
            body, tier, author_key_id, authorship_sig_hex,
            second_author_key_id, second_authorship_sig_hex)
        current = self._pins[artifact_id]["version"]
        if version <= current:
            raise ArtifactRefused(
                "unpin_version_not_monotonic: pin for %r is at version "
                "%d; unpin at version %d refused (a replayed older unpin "
                "statement cannot delete a newer pin)"
                % (artifact_id, current, version))
        del self._pins[artifact_id]
        if self._log is not None:
            self._log.append({
                "event": "artifact_unpinned",
                "artifact_id": artifact_id,
                "unpinned_by": author_key_id,
                "approvals": approvals,
                "tier": tier,
                "version": version,
            })
        return True

    def pin_for(self, artifact_id):
        """Return the pin dict, or None when unpinned."""
        pin = self._pins.get(artifact_id)
        return dict(pin) if pin else None

    def sign_pin_statement(self, seed, artifact_id, digest, author_key_id,
                           ts, *, tier="production",
                           version=_PIN_VERSION_START, not_after=None):
        """Operator-side helper: sign a pin statement with a human seed.

        (The private seed never crosses into agent-reachable code.)
        Mirrors :meth:`pin`: the signature covers tier, version, and the
        resolved not_after — pass the returned signature together with
        the same ``tier``/``version``/resolved ``not_after`` to
        :meth:`pin`. Use :func:`_resolve_pin_not_after` to see the
        effective bound that was signed.
        """
        resolved = _resolve_pin_not_after(ts, not_after)
        body = _canonical_pin_body(tier, artifact_id, digest, ts,
                                   version=version, not_after=resolved)
        return _ed_sign(seed, body).hex()

    def sign_unpin_statement(self, seed, artifact_id, author_key_id, ts,
                             *, tier="production",
                             version=_PIN_VERSION_START):
        """Operator-side helper: sign an unpin statement with a human seed.

        (The private seed never crosses into agent-reachable code.)
        Mirrors :meth:`unpin`: the signature covers the version being
        removed, which must exceed the pin's current version.
        """
        body = _canonical_unpin_body(tier, artifact_id, ts, version=version)
        return _ed_sign(seed, body).hex()


# ---------------------------------------------------------------------------
# The governed load path.
# ---------------------------------------------------------------------------

def verify_and_load(pinset, artifact_id, fetched_bytes, *, log=None):
    """Verify *fetched_bytes* against the pin, then load.

    Returns a :class:`VerifiedArtifact` holding the EXACT bytes that
    were hashed (the TOCTOU binding). Raises :class:`ArtifactRefused`:

    * ``artifact_unpinned`` — no pin exists; there is no TOFU.
    * ``pin_expired`` — the pin's ``not_after`` has passed; stale pins
      are refused BEFORE any content is attested (watch-layer parity:
      expiry is staleness, not compromise).
    * ``digest_mismatch`` — bytes do not match the pin; refused loudly
      and chained when a log is provided.

    Note: there is deliberately no ``reference`` parameter — the ref
    namespace is excluded structurally (the function takes bytes, not
    references), not by a runtime check. A caller that wants ref
    resolution has left the governed path.
    """
    if not isinstance(pinset, ArtifactPinset):
        raise TypeError("pinset must be an ArtifactPinset")
    pin = pinset.pin_for(artifact_id)
    if pin is None:
        _refused(log, artifact_id, "artifact_unpinned",
                  "no digest pin for %r: unpinned artifacts are not loaded "
                  "(no trust-on-first-use)" % (artifact_id,))
        raise ArtifactRefused(
            "artifact_unpinned: no digest pin for %r" % (artifact_id,))
    # TUF-steal (wave-194 lane A): freshness before content. The pin is
    # the trust anchor for the digest check below, so its expiry is
    # verified first — a stale pin refuses the load even when the bytes
    # would match.
    expiry = _parse_pin_not_after(
        pin.get("not_after"), context="pin not_after for %r" % (artifact_id,))
    if datetime.now(timezone.utc) > expiry:
        _refused(log, artifact_id, "pin_expired",
                  "pin for %r expired at %s" % (artifact_id,
                                                pin.get("not_after")))
        raise ArtifactRefused(
            "pin_expired: pin for %r expired at %s (stale pins are not "
            "loaded; renew via a higher-version re-pin)"
            % (artifact_id, pin.get("not_after")))
    data = bytes(fetched_bytes)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if digest != pin["digest"]:
        _refused(log, artifact_id, "digest_mismatch",
                  "fetched bytes hash %s, pinned %s" % (digest, pin["digest"]))
        raise ArtifactRefused(
            "digest_mismatch: artifact %r fetched bytes do not match the "
            "pinned digest (got %s, want %s)" % (artifact_id, digest,
                                                 pin["digest"]))
    return VerifiedArtifact(artifact_id, digest, data)


def load_file_verified(pinset, artifact_id, path, *, log=None):
    """Single-read file load: read once, hash the bytes held, hand over
    the same bytes. A file swap between the read and the hash is
    impossible — there is only one read."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ArtifactRefused(
            "artifact_unreadable: %s (%s)" % (path, e))
    return verify_and_load(pinset, artifact_id, data, log=log)


def _refused(log, artifact_id, reason, detail):
    if log is None:
        return
    log.append({
        "event": "artifact_load_refused",
        "artifact_id": artifact_id,
        # Wave-79 (totality): load-gate decisions name the governing
        # framework version; digest rules (not policy rules) decide,
        # so matched_rules is honestly empty — the pinset has artifact
        # ids, not rule ids.
        "policy_version": "supplychain-w78",
        "matched_rules": [],
        "reason": reason,
        "detail": detail,
    })


class CorpusManifestTracker:
    """The load-side holder of the corpus-signing keyset.

    A corpus manifest (``gov/corpus_manifest.py``) is the signed,
    versioned, expiring binding ``{artifact_id -> digest}`` for the
    load corpus — the TUF snapshot/targets structure in our own terms
    (wave-194). Present a manifest doc via :meth:`present`; it is
    signature/expiry/purpose-verified against the keyset, and the
    tracker remembers the highest verified ``corpus_version`` — a
    re-presented OLDER manifest refuses ``corpus_stale`` (the TUF
    rollback shape). The manifest the tracker holds is what
    :meth:`SkillLoader.load_skill` checks the pin against.

    The tracker is deployment-held and long-lived: the version memory
    only works when the same tracker sees every presentation. A fresh
    tracker starts with no version memory (honest residual: a
    rebooted deployment re-trusts the presented manifest — the
    manifest's own expiry bounds that window).
    """

    def __init__(self, keyset):
        from .keyset import Keyset
        if not isinstance(keyset, Keyset):
            raise TypeError("keyset must be a Keyset")
        self._keyset = keyset
        self._highest_version = 0
        self._manifest = None

    def present(self, doc):
        """Verify *doc* and adopt it as the current corpus manifest.

        Raises :class:`ArtifactRefused` (fail-closed) on any corpus
        violation: forged/tampered (``corpus_manifest_bad_signature``),
        expired (``corpus_manifest_expired``), wrong keyset purpose
        (``corpus_manifest_wrong_purpose``), threshold unmet
        (``corpus_manifest_threshold_unmet``), or an older version
        than already seen (``corpus_manifest_stale``). Returns the
        verified :class:`CorpusManifest`.
        """
        from . import corpus_manifest as _cm
        try:
            manifest = _cm.verify_corpus_manifest(doc, self._keyset)
        except _cm.CorpusManifestError as exc:
            raise ArtifactRefused(
                "corpus_manifest_%s: %s"
                % (exc.code.replace("-", "_"), exc.detail))
        if manifest.version < self._highest_version:
            raise ArtifactRefused(
                "corpus_manifest_stale: corpus version %d is older "
                "than the verified version %d (rollback refused)"
                % (manifest.version, self._highest_version))
        self._highest_version = manifest.version
        self._manifest = manifest
        return manifest

    @property
    def manifest(self):
        """The currently adopted manifest, or None."""
        return self._manifest

    @property
    def highest_version(self):
        return self._highest_version

    def digest_for(self, artifact_id):
        """The manifest-bound digest for *artifact_id*.

        Returns a digest-only :class:`gov.digest_ref.DigestRef`.

        Raises :class:`ArtifactRefused` ``corpus_manifest_unpresented``
        when no manifest was presented, ``corpus_manifest_unbound``
        when the artifact id is not in the manifest.
        """
        if self._manifest is None:
            raise ArtifactRefused(
                "corpus_manifest_unpresented: no corpus manifest has "
                "been presented to this tracker")
        digest = self._manifest.digest_for(artifact_id)
        if digest is None:
            raise ArtifactRefused(
                "corpus_manifest_unbound: artifact %r is not bound in "
                "the corpus manifest (version %d)"
                % (artifact_id, self._manifest.version))
        return digest


class SkillLoader:
    """Governed skill loading: skills are plugin-shaped content and go
    through the digest gate before reaching model context.

    ``store`` maps skill name -> bytes (or a zero-arg fetch callable
    returning bytes — the fetch happens ONCE and the returned bytes are
    what get verified and handed over). Returns a
    :class:`VerifiedArtifact`; the caller passes ``.data`` into the
    sterile ``skill_content`` channel. A ``skill_loaded`` record chains
    the digest that was actually loaded.

    ``corpus`` is an optional :class:`CorpusManifestTracker` holding
    the corpus-signing keyset. When ``corpus_doc`` is passed to
    :meth:`load_skill`, the manifest is presented (signature, expiry,
    purpose, threshold, and version-monotonicity verified, fail
    closed) and the pin's digest must EQUAL the manifest-bound digest
    for the artifact id — the TUF mix-and-match binding: a pin rotated
    without the corpus, or a corpus presented against another
    version's bytes, refuses. Without a corpus doc the pinset-only
    behavior is unchanged (documented adoption path).

    ``bundle_refresh`` (wave-206) is an optional
    :class:`gov.bundle_refresh.BundleRefresher`. When given,
    :meth:`load_skill` additionally requires the refresher to be
    servable (``"trusted"`` or ``"stale"`` -- a ``"suspended"``
    refresher refuses every load until a clean refresh recovers) and
    requires the pin's digest to equal the refresh-bound digest for
    ``skill:<name>`` -- the TUF mix-and-match binding at the refresh
    layer: a pin rotated without a refreshed bundle, or a bundle
    presented against another version's bytes, refuses. Without it
    the pinset-only behavior is unchanged (documented adoption path).

    ``namespace_registry`` (wave-209) is an optional
    :class:`gov.sign_deploy_namespaces.NamespaceRegistry`. When given,
    :meth:`load_skill` additionally requires the pin's digest to be
    admittable to the ENFORCED namespace via
    :meth:`NamespaceRegistry.admit_deploy` -- the signed-only
    deployment admission (the Harbor signed-only pattern, wave-205
    prospecting §4): unsigned content and name-only references refuse
    here, while the staging / signing / promotion path never passes
    through the loader (the goharbor#22650 lesson -- enforcement lives
    only at this admission seam and cannot brick signing). The
    registry's pinned verifiers, threshold, and two-operator promotion
    ceremony stay caller-owned; the loader calls the admission seam
    and records the ``signed_by`` / ``promoted_by`` provenance in the
    log. Without it the pinset-only behavior is unchanged (documented
    adoption path). Recommended production setting: wire the registry
    that governs the enforced namespace; the default ``None``
    preserves legacy behavior for callers that have not adopted
    signed-only deployment yet."""

    def __init__(self, pinset, store, log=None, corpus=None,
                 bundle_refresh=None, namespace_registry=None):
        if not isinstance(pinset, ArtifactPinset):
            raise TypeError("pinset must be an ArtifactPinset")
        if corpus is not None and not isinstance(
                corpus, CorpusManifestTracker):
            raise TypeError("corpus must be a CorpusManifestTracker "
                            "or None")
        if bundle_refresh is not None and not (
                hasattr(bundle_refresh, "state")
                and hasattr(bundle_refresh, "target_digest")):
            raise TypeError("bundle_refresh must expose state and "
                            "target_digest (a BundleRefresher) or None")
        if namespace_registry is not None and not hasattr(
                namespace_registry, "admit_deploy"):
            raise TypeError("namespace_registry must expose admit_deploy "
                            "(a NamespaceRegistry) or None")
        self._pinset = pinset
        self._store = store
        self._log = log
        self._corpus = corpus
        self._bundle_refresh = bundle_refresh
        self._namespace_registry = namespace_registry

    def load_skill(self, skill_name, *, corpus_doc=None):
        artifact_id = "skill:" + str(skill_name)
        entry = self._store.get(skill_name)
        if entry is None:
            _refused(self._log, artifact_id, "skill_not_found",
                      "no such skill in the store")
            raise ArtifactRefused(
                "skill_not_found: %r" % (skill_name,))
        fetched = entry() if callable(entry) else entry
        verified = verify_and_load(self._pinset, artifact_id, fetched,
                                   log=self._log)
        # Corpus consistency binding (wave-194 TUF steal): when the
        # deployment presents a corpus manifest, the pin's digest must
        # equal the manifest-bound digest — a pin and a manifest that
        # disagree (mix-and-match across versions) refuse here.
        if corpus_doc is not None or self._corpus is not None:
            self._check_corpus(artifact_id, verified.digest, corpus_doc)
        # Bundle-refresh binding (wave-206 TUF steal): when the
        # deployment wires a refresher, the pin's digest must equal the
        # refresh-bound digest -- mix-and-match across bundle versions
        # refuses, and a suspended refresher refuses every load.
        if self._bundle_refresh is not None:
            self._check_bundle_refresh(artifact_id, verified.digest)
        # Signed-only deployment admission (wave-209 Harbor steal):
        # when the deployment wires a namespace registry, the pin's
        # digest must be admittable to the ENFORCED namespace --
        # unsigned content and name-only references refuse here.
        # Enforcement lives only at this admission seam (the
        # goharbor#22650 lesson): staging, signing, and promotion never
        # pass through the loader, so enforcement cannot brick signing.
        if self._namespace_registry is not None:
            self._check_namespace_admission(artifact_id, verified.digest)
        if self._log is not None:
            self._log.append({
                "event": "skill_loaded",
                "artifact_id": artifact_id,
                "digest": verified.digest,
                "bytes": len(verified.data),
            })
        return verified

    def _check_corpus(self, artifact_id, pin_digest, corpus_doc):
        if self._corpus is None:
            raise ArtifactRefused(
                "corpus_manifest_unpresented: a corpus document was "
                "given but this loader has no CorpusManifestTracker")
        if corpus_doc is None and self._corpus.manifest is None:
            raise ArtifactRefused(
                "corpus_manifest_unpresented: loader has a tracker "
                "but no corpus manifest was presented")
        if corpus_doc is not None:
            self._corpus.present(corpus_doc)
        bound = self._corpus.digest_for(artifact_id)
        # bound is a DigestRef (structural identity); pin_digest is the
        # loader-computed "sha256:<hex>" string. Compare canonical
        # digest strings -- never DigestRef == str, which is
        # deliberately NotImplemented.
        if bound.digest != pin_digest:
            _refused(self._log, artifact_id, "corpus_manifest_mismatch",
                      "pin digest %s != corpus-bound digest %s "
                      "(corpus version %d)"
                      % (pin_digest, bound,
                         self._corpus.manifest.version))
            raise ArtifactRefused(
                "corpus_manifest_mismatch: pin for %r (%s) disagrees "
                "with the corpus manifest binding (%s) — "
                "mix-and-match across versions refused"
                % (artifact_id, pin_digest, bound))


    def _check_bundle_refresh(self, artifact_id, pin_digest):
        from .bundle_refresh import SuspendedError
        refresher = self._bundle_refresh
        state = refresher.state
        if state not in ("trusted", "stale"):
            _refused(self._log, artifact_id, "bundle_refresh_suspended",
                      "bundle refresher is %s (%s); skill loads refused "
                      "until a clean refresh recovers"
                      % (state, refresher.reason))
            raise ArtifactRefused(
                "bundle_refresh_suspended: refresher is %s (%s)"
                % (state, refresher.reason))
        try:
            bound_hex, _length = refresher.target_digest(artifact_id)
        except SuspendedError as exc:
            _refused(self._log, artifact_id, "bundle_refresh_suspended",
                      "refresher refused to serve digests: %s" % (exc,))
            raise ArtifactRefused(
                "bundle_refresh_suspended: %s" % (exc,))
        except KeyError:
            _refused(self._log, artifact_id, "bundle_refresh_unbound",
                      "no refresh-bound digest for %r" % (artifact_id,))
            raise ArtifactRefused(
                "bundle_refresh_unbound: no refresh-bound digest for %r"
                % (artifact_id,))
        # bound_hex is bare hex; pin_digest is the loader-computed
        # "sha256:<hex>" string. Compare canonical digest strings.
        if pin_digest != "sha256:" + bound_hex:
            _refused(self._log, artifact_id, "bundle_refresh_mismatch",
                      "pin digest %s != refresh-bound digest sha256:%s "
                      "-- mix-and-match across bundle versions refused"
                      % (pin_digest, bound_hex))
            raise ArtifactRefused(
                "bundle_refresh_mismatch: pin for %r (%s) disagrees "
                "with the refresh-bound digest (sha256:%s)"
                % (artifact_id, pin_digest, bound_hex))

    def _check_namespace_admission(self, artifact_id, pin_digest):
        """Signed-only deployment admission (wave-209).

        The pin's digest must be admittable to the ENFORCED namespace
        by the wired :class:`gov.sign_deploy_namespaces.NamespaceRegistry`.
        Unsigned content, unpromoted bundles, and name-only references
        refuse here as ``namespace_admission_refused``. The import is
        lazy so legacy import behavior is unchanged when no registry
        is wired.
        """
        from .sign_deploy_namespaces import NamespaceError
        try:
            admitted = self._namespace_registry.admit_deploy(pin_digest)
        except NamespaceError as exc:
            _refused(self._log, artifact_id, "namespace_admission_refused",
                      "enforced-namespace admission refused %s: %s (%s)"
                      % (pin_digest, exc.code, exc.detail))
            raise ArtifactRefused(
                "namespace_admission_refused: %r is not admittable to the "
                "enforced namespace (%s)" % (artifact_id, exc.code))
        # Provenance for the audit trail: which keys signed and which
        # operators promoted the admitted bundle. The loader hands out
        # the pinset-verified bytes (the TOCTOU binding documented in
        # verify_and_load); admission guarantees the registry's record
        # hashes to the same pin, so the two byte strings are the same
        # bundle up to a SHA-256 collision.
        if self._log is not None:
            self._log.append({
                "event": "namespace_admitted",
                "artifact_id": artifact_id,
                "digest": pin_digest,
                "signed_by": list(admitted.get("signed_by", [])),
                "promoted_by": list(admitted.get("promoted_by", [])),
            })


def load_skill_content(pinset, store, skill_name, *, log=None,
                       corpus=None, corpus_doc=None, bundle_refresh=None,
                       namespace_registry=None):
    """The FORCED entry point for skill content into the sterile
    ``skill_content`` channel (wave-80).

    Loads the skill's bytes through :class:`SkillLoader` (the digest
    gate — no TOFU, no references) and hands the deployment the
    content wrapped in a ``sterile.Unvetted`` marker with
    ``origin="skill_content"`` and the verified ``artifact_id`` +
    ``digest`` in the marker's ``ack_context``. The marker is the
    wave-64 D5 machine-readable "never vetted" envelope: content that
    crossed the channel cannot be silently treated as trusted, and
    the ack trail names the exact digest that was loaded.

    ``corpus`` / ``corpus_doc`` (wave-194): an optional
    :class:`CorpusManifestTracker` plus the manifest document to
    present. When given, the manifest is verified (signature, expiry,
    purpose, threshold, version monotonicity) and the pin's digest
    must equal the manifest-bound digest — mix-and-match across
    corpus versions refuses. Without them the pinset-only behavior is
    unchanged (adoption path).

    ``bundle_refresh`` (wave-206): an optional
    :class:`gov.bundle_refresh.BundleRefresher` wired through to
    :class:`SkillLoader` (same binding semantics; see there).
    Without it the pinset-only behavior is unchanged.

    ``namespace_registry`` (wave-209): an optional
    :class:`gov.sign_deploy_namespaces.NamespaceRegistry` wired through
    to :class:`SkillLoader` (signed-only deployment admission at the
    enforced namespace; see there). Without it the pinset-only
    behavior is unchanged. Recommended production setting: wire the
    registry that governs the enforced namespace.

    There is no raw-bytes return path on purpose: callers that want
    the bytes must unwrap the marker via ``acknowledge()`` (the
    channel's only documented read), so every consumption is an
    auditable, explicitly-never-vetted act. Reading a skill file off
    disk directly and feeding it to the channel bypasses this
    function — that is the legacy seam, refused-by-construction here
    because the marker (with its digest) is what the channel's
    downstream contract expects.
    """
    from .sterile import Unvetted
    loader = SkillLoader(pinset, store, log=log, corpus=corpus,
                         bundle_refresh=bundle_refresh,
                         namespace_registry=namespace_registry)
    verified = loader.load_skill(skill_name, corpus_doc=corpus_doc)
    return Unvetted(
        verified.data,
        origin="skill_content",
        ack_context={
            "artifact_id": verified.artifact_id,
            "digest": verified.digest,
        },
    )
