"""Evaluation-function with frozen call records.

Re-derived shape (the evaluation-function direction from the
wave-232 prospectus, ``draft-jackson-wimse-evaluation-02`` as
pattern only; all prose and code written fresh): an authorization
evaluation is a FROZEN CALL. Every ``authorization_details`` entry is
frozen (digested) BEFORE evaluation; the verdict re-references that
digest; the key that froze the input (evidence key) and the key that
adjudicates the verdict (adjudication key) are role-separated; and
replay re-runs the PINNED policy revision against the frozen input.

Refusals:

* ``evaluation-malformed`` -- a frozen call or evaluation record is
  not well-formed (empty or misshapen ``authorization_details``,
  half-pinned policy revision, bad instant).
* ``evaluation-incomplete-details`` -- an ``authorization_details``
  entry was never evaluated (skipped, failed, or its per-entry
  verdict is missing from the record). No entry may be silently
  dropped: evaluation covers the whole call or refuses.
* ``evaluation-key-role-conflation`` -- the evidence key and the
  adjudication key are the same key. The freezer and the adjudicator
  must be different roles.
* ``evaluation-input-swapped`` -- a verdict or record whose
  ``call_digest`` does not match the recomputed digest of the frozen
  input (surgical edits, transplanted verdicts, re-pinned digests
  that do not survive independent recomputation).
* ``evaluation-non-reproducible`` -- replay against the frozen input
  under the pinned revision produced a different verdict (or a
  different per-entry verdict) than the record claims.
* ``evaluation-policy-drift`` -- replay against a supplied
  ``current_engine`` would change the verdict: the pinned revision
  is reproducible, but the live policy has drifted. This is the
  evaluation-function parallel of ``replay-policy-drift`` in
  gov/policy_revisions.py.
* ``evaluation-revision-unknown`` -- the pinned ``policy_rev_id`` is
  not registered in the supplied registry.
* ``evaluation-policy-digest-mismatch`` -- the registered digest for
  the pinned ``policy_rev_id`` disagrees with the record's pinned
  digest (the registry wins: digests are recomputed, never trusted
  from claims).
* ``evaluation-not-authorization`` -- an evaluation record is
  EVIDENCE, never authority; presenting one as authority refuses.

Honest residuals (stated, not hidden):

* The frozen input and the evaluation record are caller-supplied;
  digest recomputation detects edits, not lies told consistently
  from the start. Replay under the pinned revision is the
  independent check: a record whose verdict does not survive
  re-evaluation refuses ``evaluation-non-reproducible``.
* The nonce is per-process monotonic (ordering only, not a global
  uniqueness claim); the instant is the caller-stated evaluation
  instant, not an attested clock.
* The pinned-revision registry is in-memory (gov/policy_revisions);
  persistence and distribution are deployment-owned.
* Verdict composition is fail-closed deny-dominates: ``deny``
  dominates ``require_approval`` dominates ``allow``. A composite
  verdict is a policy-conjunction reading, not a quorum.
* Role separation is enforced by key-id inequality, not by a live
  key-ceremony check: two distinct key ids are assumed to name two
  distinct roles (deployment owns the binding).
* ``deny_authority_use`` recognizes evaluation records by key shape
  (``call_digest`` + ``verdict`` present): conservative,
  shape-documented rather than record-certified.

Stdlib only. No network. $0.
"""

import hashlib
import itertools
import json as _json
from copy import deepcopy
from datetime import datetime, timezone

try:
    from . import policy as _policy_mod
except ImportError:  # standalone: gov/policy.py beside this file
    import policy as _policy_mod

try:
    from . import policy_revisions as _revisions_mod
except ImportError:  # standalone
    import policy_revisions as _revisions_mod

EVALUATION_VERSION = 1

_HEX64 = set("0123456789abcdef")

_VERDICTS = ("allow", "require_approval", "deny")

# Deny-dominates: the first entry in this order that appears among
# the per-entry effects is the combined verdict.
_COMBINE_ORDER = ("deny", "require_approval", "allow")

_FROZEN_FIELDS = frozenset({
    "v", "instant", "nonce", "authorization_details", "call_digest",
    "evidence_key_id", "policy_rev_id", "policy_digest",
})
_RECORD_FIELDS = _FROZEN_FIELDS | frozenset({
    "adjudication_key_id", "entry_verdicts", "verdict", "verdict_digest",
})

_nonce_counter = itertools.count(1)


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class EvaluationError(Exception):
    """Base class for evaluation refusals.

    Each subclass defines ``code``, the single machine-readable
    refusal code (the only vocabulary; detail lives in the message).
    ``reason`` mirrors ``code`` for the lane-battery convention. The
    base class itself is never raised, so it defines no code.
    """

    def __init__(self, message):
        super(EvaluationError, self).__init__(message)
        self.reason = self.code


class _Malformed(EvaluationError):
    code = "evaluation-malformed"


class _IncompleteDetails(EvaluationError):
    code = "evaluation-incomplete-details"


class _KeyRoleConflation(EvaluationError):
    code = "evaluation-key-role-conflation"


class _InputSwapped(EvaluationError):
    code = "evaluation-input-swapped"


class _NonReproducible(EvaluationError):
    code = "evaluation-non-reproducible"


class _PolicyDrift(EvaluationError):
    code = "evaluation-policy-drift"


class _RevisionUnknown(EvaluationError):
    code = "evaluation-revision-unknown"


class _DigestMismatch(EvaluationError):
    code = "evaluation-policy-digest-mismatch"


class _NotAuthorization(EvaluationError):
    code = "evaluation-not-authorization"


# ----------------------------------------------------------------------
# Shape gates.
# ----------------------------------------------------------------------


def _require_key_id(value, field):
    if not isinstance(value, str) or not value:
        raise _Malformed("%s must be a non-empty string, got %r"
                         % (field, value))
    if len(value) > 256:
        raise _Malformed("%s is too long" % field)
    return value


def _require_digest(value, field="digest"):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX64:
        raise _Malformed("%s must be a 64-char hex digest" % field)
    return value


def _require_instant(value):
    if not isinstance(value, str) or not value:
        raise _Malformed("instant must be a non-empty ISO-8601 UTC "
                         "string, got %r" % (value,))
    if not value.endswith("Z"):
        raise _Malformed("instant must be UTC (end with 'Z'), got %r"
                         % (value,))
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _Malformed("instant is not ISO-8601, got %r" % (value,))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(
            parsed):
        raise _Malformed("instant must be UTC, got %r" % (value,))
    return value


def _require_entry(entry, index):
    if not isinstance(entry, dict):
        raise _Malformed("authorization_details[%d] must be a dict, "
                         "got %r" % (index, type(entry).__name__))
    action = entry.get("action")
    if not isinstance(action, dict):
        raise _Malformed("authorization_details[%d]['action'] must be "
                         "a dict" % (index,))
    context = entry.get("context", {})
    if not isinstance(context, dict):
        raise _Malformed("authorization_details[%d]['context'] must be "
                         "a dict" % (index,))
    return entry


def _canonical(obj):
    """Canonical JSON bytes (the receipt_pairs digest discipline)."""
    return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       default=str).encode("utf-8")


def _digest_of(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _now_instant():
    return datetime.now(timezone.utc).isoformat(timespec="seconds") \
        .replace("+00:00", "Z")


# ----------------------------------------------------------------------
# Freezing: digest the input BEFORE evaluation.
# ----------------------------------------------------------------------


def freeze_call(authorization_details, *, evidence_key_id, policy_rev_id,
                policy_digest, instant=None, nonce=None):
    """Freeze the evaluation input. Returns the frozen call record.

    The frozen record commits to ``{instant, nonce,
    authorization_details}`` via ``call_digest``. The freezing key
    (``evidence_key_id``) records WHO froze the input; the
    adjudicating key is bound later, at :func:`evaluate_call`, and
    must differ (role separation).
    """
    _require_key_id(evidence_key_id, "evidence_key_id")
    if (policy_rev_id is None) != (policy_digest is None):
        raise _Malformed("policy_rev_id and policy_digest must be "
                         "supplied together: a half-pinned revision "
                         "misstates the replay posture")
    if policy_rev_id is None:
        raise _Malformed("policy_rev_id and policy_digest are required: "
                         "an unpinned evaluation cannot be replayed")
    _require_key_id(policy_rev_id, "policy_rev_id")
    _require_digest(policy_digest, "policy_digest")
    if not isinstance(authorization_details, list) \
            or not authorization_details:
        raise _Malformed("authorization_details must be a non-empty "
                         "list, got %r" % (authorization_details,))
    details = [_require_entry(deepcopy(entry), i)
               for i, entry in enumerate(authorization_details)]
    instant = _require_instant(instant if instant is not None
                               else _now_instant())
    if nonce is None:
        nonce = next(_nonce_counter)
    if not isinstance(nonce, int) or isinstance(nonce, bool) \
            or nonce < 1:
        raise _Malformed("nonce must be a positive int, got %r" % (nonce,))
    body = {"instant": instant, "nonce": nonce,
            "authorization_details": details}
    return {"v": EVALUATION_VERSION, "instant": instant, "nonce": nonce,
            "authorization_details": details,
            "call_digest": _digest_of(body),
            "evidence_key_id": evidence_key_id,
            "policy_rev_id": policy_rev_id,
            "policy_digest": policy_digest}


# ----------------------------------------------------------------------
# Pinned-revision engine construction (the policy_revisions discipline).
# ----------------------------------------------------------------------


def _pinned_engine(rev):
    try:
        engine = _policy_mod.PolicyEngine.from_text(
            rev.ruleset_bytes.decode("utf-8"),
            source_label="<evaluation:%s>" % (rev.rev_id,))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _Malformed("pinned revision %r has unparseable policy "
                         "bytes: %s" % (rev.rev_id, exc))
    return engine


def _check_revision(frozen, registry):
    if not isinstance(registry, _revisions_mod.RevisionRegistry):
        raise _Malformed("registry must be a "
                         "gov.policy_revisions.RevisionRegistry")
    rev = registry.get(frozen["policy_rev_id"])
    if rev is None:
        raise _RevisionUnknown(
            "policy_rev_id %r is not a registered revision"
            % (frozen["policy_rev_id"],))
    if rev.digest != frozen["policy_digest"]:
        raise _DigestMismatch(
            "the registered digest %s for %r disagrees with the "
            "record's pinned digest %s: digests are recomputed from "
            "ruleset bytes, never trusted from claims"
            % (rev.digest, rev.rev_id, frozen["policy_digest"]))
    return rev


def _recompute_call_digest(frozen):
    return _digest_of({"instant": frozen["instant"],
                       "nonce": frozen["nonce"],
                       "authorization_details":
                       frozen["authorization_details"]})


def _evaluate_entry(engine, entry, index):
    """Evaluate one entry. Returns (effect, reason, policy_id).

    Refuses ``evaluation-incomplete-details`` when the entry cannot
    be evaluated: an entry that silently fails to evaluate is the
    vacuous-proof shape this module exists to kill (the F193-class
    territory).
    """
    try:
        decision = engine.evaluate(deepcopy(entry["action"]),
                                   deepcopy(entry.get("context", {})),
                                   record_telemetry=False)
    except Exception as exc:
        raise _IncompleteDetails(
            "authorization_details[%d] could not be evaluated (%s: "
            "%s): an unevaluated entry is refused, never skipped"
            % (index, type(exc).__name__, exc))
    effect = decision.effect
    if effect not in _VERDICTS:
        raise _IncompleteDetails(
            "authorization_details[%d] evaluated to an unknown effect "
            "%r" % (index, effect))
    return effect, decision.reason, decision.policy_id


def _combined_verdict(effects):
    """Fail-closed deny-dominates composition."""
    for candidate in _COMBINE_ORDER:
        if candidate in effects:
            return candidate
    raise _IncompleteDetails("no evaluable effects: cannot compose a "
                             "verdict")


def verdict_digest_of(record):
    """Recompute the verdict digest of an evaluation record."""
    entry_digests = [e["entry_digest"] for e in record["entry_verdicts"]]
    return _digest_of({"call_digest": record["call_digest"],
                       "verdict": record["verdict"],
                       "entry_digests": entry_digests,
                       "policy_rev_id": record["policy_rev_id"],
                       "policy_digest": record["policy_digest"]})


# ----------------------------------------------------------------------
# Evaluation: every entry evaluated, roles separated.
# ----------------------------------------------------------------------


def _check_frozen_shape(frozen):
    if not isinstance(frozen, dict):
        raise _Malformed("frozen call must be a dict")
    unknown = set(frozen.keys()) - _FROZEN_FIELDS
    if unknown:
        raise _Malformed("frozen call has unknown fields: %r" % (unknown,))
    for field in ("v", "instant", "nonce", "authorization_details",
                  "call_digest", "evidence_key_id", "policy_rev_id",
                  "policy_digest"):
        if field not in frozen:
            raise _Malformed("frozen call is missing %r" % field)
    _require_instant(frozen["instant"])
    if not isinstance(frozen["nonce"], int) \
            or isinstance(frozen["nonce"], bool) or frozen["nonce"] < 1:
        raise _Malformed("nonce must be a positive int")
    if not isinstance(frozen["authorization_details"], list) \
            or not frozen["authorization_details"]:
        raise _Malformed("authorization_details must be a non-empty list")
    for i, entry in enumerate(frozen["authorization_details"]):
        _require_entry(entry, i)
    _require_key_id(frozen["evidence_key_id"], "evidence_key_id")
    _require_key_id(frozen["policy_rev_id"], "policy_rev_id")
    _require_digest(frozen["call_digest"], "call_digest")
    _require_digest(frozen["policy_digest"], "policy_digest")


def evaluate_call(frozen, registry, *, adjudication_key_id):
    """Evaluate every frozen entry under the PINNED revision.

    Returns the evaluation record. Role separation: the
    ``adjudication_key_id`` must differ from the record's
    ``evidence_key_id`` or evaluation refuses
    ``evaluation-key-role-conflation``. The pinned revision comes
    from the registry -- never from the current engine.
    """
    _check_frozen_shape(frozen)
    _require_key_id(adjudication_key_id, "adjudication_key_id")
    if adjudication_key_id == frozen["evidence_key_id"]:
        raise _KeyRoleConflation(
            "the evidence key %r cannot also adjudicate the verdict: "
            "the freezer and the adjudicator must be different roles"
            % (adjudication_key_id,))
    rev = _check_revision(frozen, registry)
    if _recompute_call_digest(frozen) != frozen["call_digest"]:
        raise _InputSwapped(
            "call_digest does not match the recomputed digest of the "
            "frozen input: the input was swapped after freezing")
    engine = _pinned_engine(rev)
    entry_verdicts = []
    for i, entry in enumerate(frozen["authorization_details"]):
        effect, reason, policy_id = _evaluate_entry(engine, entry, i)
        entry_verdicts.append({
            "index": i, "effect": effect, "reason": reason,
            "policy_id": policy_id,
            "entry_digest": _digest_of({
                "call_digest": frozen["call_digest"], "index": i,
                "effect": effect, "reason": reason,
                "policy_id": policy_id}),
        })
    verdict = _combined_verdict([e["effect"] for e in entry_verdicts])
    record = {"v": EVALUATION_VERSION, "instant": frozen["instant"],
              "nonce": frozen["nonce"],
              "authorization_details":
              deepcopy(frozen["authorization_details"]),
              "call_digest": frozen["call_digest"],
              "evidence_key_id": frozen["evidence_key_id"],
              "adjudication_key_id": adjudication_key_id,
              "policy_rev_id": frozen["policy_rev_id"],
              "policy_digest": frozen["policy_digest"],
              "entry_verdicts": entry_verdicts, "verdict": verdict}
    record["verdict_digest"] = verdict_digest_of(record)
    return record


# ----------------------------------------------------------------------
# Verification: recompute everything, trust nothing.
# ----------------------------------------------------------------------


def verify_call(record, registry):
    """Re-verify an evaluation record without re-evaluating policy.

    Recomputes the frozen-input digest, the entry-verdict coverage,
    and the verdict digest. Any surgical edit refuses
    ``evaluation-input-swapped``; a truncated entry-verdict list
    refuses ``evaluation-incomplete-details``. Returns the record.
    """
    if not isinstance(record, dict):
        raise _Malformed("evaluation record must be a dict")
    unknown = set(record.keys()) - _RECORD_FIELDS
    if unknown:
        raise _Malformed("evaluation record has unknown fields: %r"
                         % (unknown,))
    for field in ("v", "instant", "nonce", "authorization_details",
                  "call_digest", "evidence_key_id", "policy_rev_id",
                  "policy_digest", "adjudication_key_id",
                  "entry_verdicts", "verdict", "verdict_digest"):
        if field not in record:
            raise _Malformed("evaluation record is missing %r" % field)
    _require_instant(record["instant"])
    _require_key_id(record["adjudication_key_id"], "adjudication_key_id")
    if record["adjudication_key_id"] == record["evidence_key_id"]:
        raise _KeyRoleConflation(
            "the presented record conflates the evidence and "
            "adjudication key roles")
    details = record["authorization_details"]
    if not isinstance(details, list) or not details:
        raise _Malformed("authorization_details must be a non-empty list")
    for i, entry in enumerate(details):
        _require_entry(entry, i)
    if _recompute_call_digest(record) != record["call_digest"]:
        raise _InputSwapped(
            "call_digest does not match the recomputed digest of the "
            "frozen input")
    evs = record["entry_verdicts"]
    if not isinstance(evs, list) \
            or [e.get("index") for e in evs if isinstance(e, dict)] \
            != list(range(len(details))):
        raise _IncompleteDetails(
            "entry verdicts do not cover every authorization_details "
            "entry: an unevaluated entry is refused, never skipped")
    for i, e in enumerate(evs):
        expected = _digest_of({
            "call_digest": record["call_digest"], "index": i,
            "effect": e["effect"], "reason": e["reason"],
            "policy_id": e["policy_id"]})
        if e.get("entry_digest") != expected:
            raise _InputSwapped(
                "entry verdict %d has a forged or mismatched digest"
                % (i,))
    if record["verdict"] not in _VERDICTS:
        raise _Malformed("verdict must be one of %r, got %r"
                         % (_VERDICTS, record["verdict"]))
    _require_digest(record["verdict_digest"], "verdict_digest")
    if verdict_digest_of(record) != record["verdict_digest"]:
        raise _InputSwapped(
            "verdict_digest does not match the recomputed digest of "
            "the record: the verdict was edited after evaluation")
    _check_revision(record, registry)
    return record


# ----------------------------------------------------------------------
# Replay: re-run the pinned policy against the frozen input.
# ----------------------------------------------------------------------


def replay_evaluation(record, registry, *, current_engine=None):
    """Re-evaluate the frozen input under the PINNED revision.

    Refuses ``evaluation-non-reproducible`` when the replay produces a
    different combined verdict (or a different per-entry verdict)
    than the record claims. With ``current_engine`` supplied, the
    same input is also re-evaluated under the live policy: if the
    live policy's re-evaluation would change the verdict, replay
    refuses ``evaluation-policy-drift`` (the pinned verdict is
    reproducible, but the live policy has drifted -- the caller must
    see that explicitly).

    Returns ``{"v": 1, "replayed": True, "verdict", "drift_checked"}``.
    The replay result is EVIDENCE, never authority.
    """
    verify_call(record, registry)
    rev = registry.get(record["policy_rev_id"])
    engine = _pinned_engine(rev)
    replayed = []
    for i, entry in enumerate(record["authorization_details"]):
        replayed.append(_evaluate_entry(engine, entry, i))
    claimed = [(e["effect"], e["reason"], e["policy_id"])
               for e in record["entry_verdicts"]]
    if [r[:3] for r in replayed] != claimed:
        raise _NonReproducible(
            "replay under the pinned revision %r produced %r but the "
            "record claims %r: the verdict is not reproducible from "
            "the frozen input"
            % (record["policy_rev_id"],
               [r[0] for r in replayed],
               [e["effect"] for e in record["entry_verdicts"]]))
    verdict = _combined_verdict([r[0] for r in replayed])
    if verdict != record["verdict"]:
        raise _NonReproducible(
            "replay under the pinned revision produced %r but the "
            "record claims %r" % (verdict, record["verdict"]))
    drift_checked = False
    if current_engine is not None:
        if not isinstance(current_engine, _policy_mod.PolicyEngine):
            raise _Malformed("current_engine must be a "
                             "gov.policy.PolicyEngine")
        drift_checked = True
        if current_engine.policy_hash != rev.digest:
            current = []
            for i, entry in enumerate(record["authorization_details"]):
                current.append(_evaluate_entry(current_engine, entry, i))
            current_verdict = _combined_verdict([c[0] for c in current])
            if current_verdict != verdict \
                    or [c[:3] for c in current] != claimed:
                raise _PolicyDrift(
                    "policy drift: the pinned revision %r replays to "
                    "%r but the current policy (digest %s) "
                    "re-evaluates the same frozen input to %r"
                    % (record["policy_rev_id"], verdict,
                       current_engine.policy_hash, current_verdict))
    return {"v": 1, "replayed": True, "verdict": verdict,
            "drift_checked": drift_checked}


def deny_authority_use(obj):
    """An evaluation record is EVIDENCE, never authority.

    Presenting one as authority refuses
    ``evaluation-not-authorization``.
    """
    if isinstance(obj, dict) and "call_digest" in obj \
            and "verdict" in obj:
        raise _NotAuthorization(
            "an evaluation record describes what the pinned policy "
            "decided; it confers no permission")
    return True
