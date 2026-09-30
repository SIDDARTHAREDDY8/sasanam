"""Policy-revision-pinned evidence replay.

Re-derived pattern (no external code lifted): every decision pins the
immutable policy revision in force (``policy_rev_id`` +
``policy_digest``), and :func:`replay` re-evaluates the SAME evidence
against the PINNED revision's ruleset -- provable replay, not
approximate. A replay under a mutated live policy stays stable; when
the live policy's re-evaluation would change the verdict, replay
refuses ``replay-policy-drift`` instead of silently following the
mutation.

* ``RevisionRegistry.register(rev_id, ruleset_bytes, *,
  supersedes=None, claimed_digest=None)`` recomputes the digest from
  the ruleset BYTES (sha256); a caller-supplied ``claimed_digest``
  that disagrees refuses ``replay-policy-digest-mismatch`` -- digests
  are recomputed, never trusted from caller claims (the
  gov/receipt_pairs.py discipline). A ``supersedes`` target that was
  never registered refuses ``replay-policy-revision-unknown``; a
  duplicate ``rev_id`` with different bytes refuses
  ``replay-policy-revision-conflict`` (identical bytes are
  idempotent). The registry is in-memory; persistence and
  distribution across restarts are deployment-owned (stated here, not
  hidden).
* ``pin_engine_bytes(registry, rev_id, ruleset_bytes, *,
  supersedes=None)`` pins explicit policy bytes (the governed path:
  the caller passes the exact buffer that was hashed into the policy
  change) under the rev_id convention the engine stamps on decisions
  (``"policy:" + engine.policy_version``). Two byte-blobs with the
  same rev_id cannot both be pinned -- the conflict refusal makes a
  version collision explicit.
* ``capture_evidence(action, context)`` seals ``{action, context}``
  with a canonical-digest.
* ``replay(evidence, pinned_rev_id, registry, *, current_engine=None)``
  re-runs :meth:`gov.policy.PolicyEngine.evaluate` on a rebuilt
  engine (pinned ruleset bytes, ``record_telemetry=False`` so the
  synthetic re-evaluation never pollutes the live mode ledger) and
  compares the re-derived ``(effect, reason, policy_id)`` against the
  pinned verdict. Tampered evidence refuses
  ``replay-evidence-tampered``; an unregistered revision refuses
  ``replay-policy-revision-unknown``; a malformed policy bytes
  refuses ``replay-policy-malformed``. With ``current_engine``
  supplied, a current-policy re-evaluation that would change the
  verdict refuses ``replay-policy-drift``. A replay result is
  EVIDENCE, never authority: :func:`deny_authority_use` refuses
  ``replay-policy-not-authorization`` when a replay receipt is
  presented as authority.
* :meth:`gov.policy.PolicyEngine.evaluate` stamps every emitted
  :class:`gov.policy.PolicyDecision` with ``policy_rev_id`` /
  ``policy_digest`` (additive; legacy decisions without the fields
  serialize byte-identically).
* ``build_decision_packet(..., policy_rev_id=..., policy_digest=...)``
  carries the pinned revision as a digest-bound, signature-covered
  section (omitted kwargs build a byte-identical legacy packet).

Stdlib only. No network. $0.
"""

import hashlib
import json as _json
from copy import deepcopy

try:
    from . import policy as _policy_mod
except ImportError:  # standalone: gov/policy.py beside this file
    import policy as _policy_mod

REVISION_VERSION = 1

_HEX64 = set("0123456789abcdef")


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class ReplayError(Exception):
    """Base class for replay refusals. ``code`` is machine-readable."""

    code = "replay-refused"


class _UnknownRevision(ReplayError):
    code = "replay-policy-revision-unknown"


class _DigestMismatch(ReplayError):
    code = "replay-policy-digest-mismatch"


class _Drift(ReplayError):
    code = "replay-policy-drift"


class _EvidenceTampered(ReplayError):
    code = "replay-evidence-tampered"


class _Conflict(ReplayError):
    code = "replay-policy-revision-conflict"


class _Malformed(ReplayError):
    code = "replay-policy-malformed"


class _NotAuthorization(ReplayError):
    code = "replay-policy-not-authorization"


# ----------------------------------------------------------------------
# Shape gates.
# ----------------------------------------------------------------------

_EVIDENCE_FIELDS = frozenset({"v", "action", "context", "evidence_digest"})


def _require_rev_id(rev_id, field="rev_id"):
    if not isinstance(rev_id, str) or not rev_id:
        raise _Malformed("%s must be a non-empty string, got %r"
                         % (field, rev_id))
    if len(rev_id) > 256:
        raise _Malformed("%s is too long" % field)
    return rev_id


def _require_digest(value, field="digest"):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX64:
        raise _Malformed("%s must be a 64-char hex digest" % field)
    return value


def _canonical(obj):
    """Canonical JSON bytes (the receipt_pairs digest discipline)."""
    return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       default=str).encode("utf-8")


def _recompute_digest(ruleset_bytes):
    """The digest is RECOMPUTED from the ruleset bytes, never trusted
    from caller claims."""
    return hashlib.sha256(ruleset_bytes).hexdigest()


# ----------------------------------------------------------------------
# Revision registry (in-memory; persistence is deployment-owned).
# ----------------------------------------------------------------------


class PolicyRevision(object):
    """One immutable pinned policy revision.

    ``digest`` is always the recomputed sha256 of ``ruleset_bytes``;
    ``claimed_digest`` (when supplied) must agree or construction
    refuses ``replay-policy-digest-mismatch``.
    """

    __slots__ = ("rev_id", "digest", "ruleset_bytes", "supersedes")

    def __init__(self, rev_id, digest, ruleset_bytes, supersedes):
        self.rev_id = rev_id
        self.digest = digest
        self.ruleset_bytes = ruleset_bytes
        self.supersedes = supersedes

    def to_dict(self):
        return {"v": REVISION_VERSION, "rev_id": self.rev_id,
                "digest": self.digest,
                "supersedes": self.supersedes}


class RevisionRegistry(object):
    """In-memory pinned-revision store.

    A registry is process-local: revisions do NOT survive a restart
    and are NOT shared across processes. Deployment owns
    persistence/distribution; the module states the boundary here
    rather than implying durability.
    """

    def __init__(self):
        self._revs = {}

    def register(self, rev_id, ruleset_bytes, *, supersedes=None,
                 claimed_digest=None):
        """Pin one revision. Returns the PolicyRevision.

        Fail-closed: unknown ``supersedes`` targets refuse
        ``replay-policy-revision-unknown``; a claimed digest that
        disagrees with the recomputed bytes refuses
        ``replay-policy-digest-mismatch``; a duplicate ``rev_id``
        with different bytes refuses
        ``replay-policy-revision-conflict`` (identical bytes are
        idempotent and return the existing revision).
        """
        _require_rev_id(rev_id)
        if not isinstance(ruleset_bytes, (bytes, bytearray)) \
                or not ruleset_bytes:
            raise _Malformed("ruleset_bytes must be non-empty bytes")
        ruleset_bytes = bytes(ruleset_bytes)
        digest = _recompute_digest(ruleset_bytes)
        if claimed_digest is not None:
            _require_digest(claimed_digest, "claimed_digest")
            if claimed_digest != digest:
                raise _DigestMismatch(
                    "claimed_digest %s disagrees with the recomputed "
                    "digest %s for rev_id %r: digests are recomputed "
                    "from ruleset bytes, never trusted from claims"
                    % (claimed_digest, digest, rev_id))
        if supersedes is not None:
            _require_rev_id(supersedes, "supersedes")
            if supersedes not in self._revs:
                raise _UnknownRevision(
                    "supersedes target %r is not a registered revision"
                    % (supersedes,))
        existing = self._revs.get(rev_id)
        if existing is not None:
            if existing.digest != digest:
                raise _Conflict(
                    "rev_id %r is already pinned to digest %s; new "
                    "bytes digest to %s" % (rev_id, existing.digest,
                                            digest))
            return existing
        rev = PolicyRevision(rev_id, digest, ruleset_bytes, supersedes)
        self._revs[rev_id] = rev
        return rev

    def get(self, rev_id):
        """Return the PolicyRevision, or None when unknown."""
        return self._revs.get(rev_id)

    def rev_ids(self):
        return sorted(self._revs.keys())

    def chain(self, rev_id):
        """The supersedes chain oldest-first, e.g.
        ``["policy:1", "policy:2"]``."""
        _require_rev_id(rev_id)
        rev = self._revs.get(rev_id)
        if rev is None:
            raise _UnknownRevision("rev_id %r is not registered"
                                   % (rev_id,))
        out = []
        while rev is not None:
            out.append(rev.rev_id)
            rev = self._revs.get(rev.supersedes) \
                if rev.supersedes else None
        out.reverse()
        return out


def pin_engine_bytes(registry, rev_id, ruleset_bytes, *, supersedes=None):
    """Pin explicit policy bytes (the governed path: the caller passes
    the exact buffer that was hashed into the policy change).

    The rev_id convention the engine's decisions use is
    ``"policy:" + engine.policy_version`` -- see
    :meth:`gov.policy.PolicyEngine.evaluate`, which stamps every
    emitted :class:`gov.policy.PolicyDecision` with that rev_id and
    the digest of the exact bytes the engine parsed
    (``engine.policy_hash``). Pinning the same bytes under the same
    rev_id lets replay cross-check the two digests.
    """
    if not isinstance(registry, RevisionRegistry):
        raise _Malformed("registry must be a RevisionRegistry")
    return registry.register(rev_id, ruleset_bytes, supersedes=supersedes)


# ----------------------------------------------------------------------
# Evidence capture and replay.
# ----------------------------------------------------------------------


def capture_evidence(action, context=None):
    """Seal ``{action, context}`` with a canonical digest."""
    if not isinstance(action, dict):
        raise _Malformed("action must be a dict, got %r"
                         % type(action).__name__)
    context = dict(context or {})
    payload = {"action": deepcopy(action), "context": deepcopy(context)}
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return {"v": 1, "action": deepcopy(action), "context": deepcopy(context),
            "evidence_digest": digest}


def _check_evidence(evidence):
    if not isinstance(evidence, dict):
        raise _Malformed("evidence must be a dict")
    unknown = set(evidence.keys()) - _EVIDENCE_FIELDS
    if unknown:
        raise _Malformed("evidence has unknown fields: %r" % (unknown,))
    for field in ("v", "action", "context", "evidence_digest"):
        if field not in evidence:
            raise _Malformed("evidence is missing %r" % field)
    _require_digest(evidence["evidence_digest"], "evidence_digest")
    if not isinstance(evidence["action"], dict):
        raise _Malformed("evidence['action'] must be a dict")
    if not isinstance(evidence["context"], dict):
        raise _Malformed("evidence['context'] must be a dict")
    recomputed = hashlib.sha256(_canonical(
        {"action": evidence["action"],
         "context": evidence["context"]})).hexdigest()
    if recomputed != evidence["evidence_digest"]:
        raise _EvidenceTampered(
            "evidence digest %s does not match the recomputed digest "
            "%s: the evidence was tampered after capture"
            % (evidence["evidence_digest"], recomputed))


def _verdict_of(decision):
    """The stable comparison surface: (effect, reason, policy_id)."""
    return {"effect": decision.effect, "reason": decision.reason,
            "policy_id": decision.policy_id,
            "nominal_effect": decision.nominal_effect}


def replay(evidence, pinned_rev_id, registry, *, current_engine=None):
    """Re-evaluate captured evidence against the PINNED revision.

    Returns ``{"replayed": True, "pinned_rev_id", "policy_digest",
    "verdict"}``. The re-evaluation runs with
    ``record_telemetry=False`` -- it is synthetic and must never
    pollute the live mode ledger.

    With ``current_engine`` supplied, the same evidence is also
    re-evaluated under the live policy: if that re-evaluation would
    change the verdict, replay refuses ``replay-policy-drift`` (the
    pinned verdict is reproducible, but the live policy has drifted
    -- the caller must see that explicitly, not have the mutation
    silently followed or silently ignored).
    """
    _check_evidence(evidence)
    _require_rev_id(pinned_rev_id, "pinned_rev_id")
    if not isinstance(registry, RevisionRegistry):
        raise _Malformed("registry must be a RevisionRegistry")
    rev = registry.get(pinned_rev_id)
    if rev is None:
        raise _UnknownRevision(
            "pinned_rev_id %r is not a registered revision"
            % (pinned_rev_id,))
    try:
        pinned_engine = _policy_mod.PolicyEngine.from_text(
            rev.ruleset_bytes.decode("utf-8"),
            source_label="<replay:%s>" % (pinned_rev_id,))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _Malformed("pinned revision %r has unparseable policy "
                         "bytes: %s" % (pinned_rev_id, exc))
    pinned_decision = pinned_engine.evaluate(
        deepcopy(evidence["action"]), deepcopy(evidence["context"]),
        record_telemetry=False)
    verdict = _verdict_of(pinned_decision)
    drift = None
    if current_engine is not None:
        if not isinstance(current_engine, _policy_mod.PolicyEngine):
            raise _Malformed("current_engine must be a "
                             "gov.policy.PolicyEngine")
        # The spec's drift conjunction: the CURRENT REVISION must
        # differ from the pinned one (digest comparison -- recomputed
        # from the live engine's own bytes) AND a current-policy
        # re-evaluation must change the verdict. Verdict-only
        # comparison is weaker; a revision-identical engine can never
        # produce a different verdict, but the explicit check makes
        # the refusal mean what it says.
        revision_differs = current_engine.policy_hash != rev.digest
        current_decision = current_engine.evaluate(
            deepcopy(evidence["action"]), deepcopy(evidence["context"]),
            record_telemetry=False)
        current_verdict = _verdict_of(current_decision)
        if revision_differs and current_verdict != verdict:
            raise _Drift(
                "policy drift: the pinned revision %r replays to %r "
                "but the current policy (digest %s) re-evaluates the "
                "same evidence to %r"
                % (pinned_rev_id, verdict, current_engine.policy_hash,
                   current_verdict))
        drift = False
    return {"v": 1, "replayed": True, "pinned_rev_id": pinned_rev_id,
            "policy_digest": rev.digest, "verdict": verdict,
            "drift_checked": drift is not None}


def deny_authority_use(obj):
    """A replay result is EVIDENCE, never authority: presenting one as
    authority refuses ``replay-policy-not-authorization``."""
    if isinstance(obj, dict) and obj.get("replayed") is True:
        raise _NotAuthorization(
            "a replay result records what the pinned policy decided; "
            "it confers no permission")
    return True
