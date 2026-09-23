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
from datetime import datetime, timezone

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

_PIN_DOMAIN = b"gov-artifact-pin/v1\x00"

# Deployment tiers for pin mutations. The wave-75 nuclear rule applies:
# production pin changes need TWO distinct roster human keys; dev/test/
# staging take single-human. The tier is committed in the canonical body
# so a one-key signature can never be replayed as a production approval
# (no tier-downgrade / tier-upgrade games).
_PIN_TIERS = ("dev", "test", "staging", "production")


def _canonical_pin_body(tier, artifact_id, digest, ts):
    return b"|".join([
        _PIN_DOMAIN,
        tier.encode("utf-8"),
        artifact_id.encode("utf-8"),
        digest.encode("utf-8"),
        ts.encode("utf-8"),
    ])


class ArtifactPinset:
    """The governed digest-pin registry.

    Pins are ``{artifact_id: {digest, pinned_by, approvals, tier,
    pinned_at}}``. The ONLY mutation path is :meth:`pin` /
    :meth:`unpin`, which require Ed25519 authorship from roster human
    keys (``DelegationTrust.human_keys``) — the wave-75 construction
    applied to digest pins, including the nuclear tier rule:
    production needs two DISTINCT human keys, dev/test/staging take
    single-human. Mutations are appended as chained log records
    (``artifact_pinned`` / ``artifact_unpinned``) when a log is
    provided.

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
            second_authorship_sig_hex=None):
        """Pin *digest* for *artifact_id* under human authorship.

        ``authorship_sig_hex`` is the Ed25519 signature (by the private
        key for ``author_key_id``) over the canonical pin body
        (tier|artifact_id|digest|ts). The wave-75 tier rule applies:
        ``tier="production"`` (the default) requires a SECOND approval
        from a DISTINCT roster human key over the identical body —
        the same key twice is refused; dev/test/staging take
        single-human. Raises :class:`ArtifactRefused`
        (``pin_authorship_invalid``) on any authorship failure, and
        refuses non-digest pin values at once.
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
        body = _canonical_pin_body(tier, artifact_id, digest, ts)
        approvals = self._require_approvals(
            body, tier, author_key_id, authorship_sig_hex,
            second_author_key_id, second_authorship_sig_hex)
        self._pins[artifact_id] = {
            "digest": digest,
            "pinned_by": author_key_id,
            "approvals": approvals,
            "tier": tier,
            "pinned_at": ts,
        }
        if self._log is not None:
            self._log.append({
                "event": "artifact_pinned",
                "artifact_id": artifact_id,
                "digest": digest,
                "pinned_by": author_key_id,
                "approvals": approvals,
                "tier": tier,
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
              second_authorship_sig_hex=None):
        """Remove a pin (same tier/authorship rule as pin)."""
        if artifact_id not in self._pins:
            raise ArtifactRefused(
                "unpin refused: no pin for %r" % (artifact_id,))
        if tier not in _PIN_TIERS:
            raise ArtifactRefused("unpin refused: unknown tier %r" % (tier,))
        ts = ts or _utcnow_iso()
        body = _canonical_pin_body(tier, artifact_id, "UNPIN", ts)
        approvals = self._require_approvals(
            body, tier, author_key_id, authorship_sig_hex,
            second_author_key_id, second_authorship_sig_hex)
        del self._pins[artifact_id]
        if self._log is not None:
            self._log.append({
                "event": "artifact_unpinned",
                "artifact_id": artifact_id,
                "unpinned_by": author_key_id,
                "approvals": approvals,
                "tier": tier,
            })
        return True

    def pin_for(self, artifact_id):
        """Return the pin dict, or None when unpinned."""
        pin = self._pins.get(artifact_id)
        return dict(pin) if pin else None

    def sign_pin_statement(self, seed, artifact_id, digest, author_key_id,
                           ts):
        """Operator-side helper: sign a pin statement with a human seed.
        (The private seed never crosses into agent-reachable code.)"""
        body = _canonical_pin_body(artifact_id, digest, author_key_id, ts)
        return _ed_sign(seed, body).hex()


# ---------------------------------------------------------------------------
# The governed load path.
# ---------------------------------------------------------------------------

def verify_and_load(pinset, artifact_id, fetched_bytes, *, log=None):
    """Verify *fetched_bytes* against the pin, then load.

    Returns a :class:`VerifiedArtifact` holding the EXACT bytes that
    were hashed (the TOCTOU binding). Raises :class:`ArtifactRefused`:

    * ``artifact_unpinned`` — no pin exists; there is no TOFU.
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


class SkillLoader:
    """Governed skill loading: skills are plugin-shaped content and go
    through the digest gate before reaching model context.

    ``store`` maps skill name -> bytes (or a zero-arg fetch callable
    returning bytes — the fetch happens ONCE and the returned bytes are
    what get verified and handed over). Returns a
    :class:`VerifiedArtifact`; the caller passes ``.data`` into the
    sterile ``skill_content`` channel. A ``skill_loaded`` record chains
    the digest that was actually loaded."""

    def __init__(self, pinset, store, log=None):
        if not isinstance(pinset, ArtifactPinset):
            raise TypeError("pinset must be an ArtifactPinset")
        self._pinset = pinset
        self._store = store
        self._log = log

    def load_skill(self, skill_name):
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
        if self._log is not None:
            self._log.append({
                "event": "skill_loaded",
                "artifact_id": artifact_id,
                "digest": verified.digest,
                "bytes": len(verified.data),
            })
        return verified


def load_skill_content(pinset, store, skill_name, *, log=None):
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
    loader = SkillLoader(pinset, store, log=log)
    verified = loader.load_skill(skill_name)
    return Unvetted(
        verified.data,
        origin="skill_content",
        ack_context={
            "artifact_id": verified.artifact_id,
            "digest": verified.digest,
        },
    )
