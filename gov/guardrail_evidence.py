"""Uniform per-guardrail-run evidence records chained into the HMAC audit log.

PATTERN LINEAGE: BerriAI/litellm (MIT, LICENSE bytes verified by the
wave-278 prospecting lane) -- ``StandardLoggingGuardrailInformation``
(the standardized per-run record: guardrail_name / guardrail_id /
guardrail_mode / request / response / status / timing) and
``is_guardrail_intervention`` (the honest distinction between
*intentional blocks* and *technical failures*), plus the
``_PRE_CALL_EXECUTED_TOKEN`` anti-forgery precedent. This is a
clean-room stdlib re-implementation of the *mechanisms*; no litellm code
is vendored here.

Anti-forgery posture (our analog of the executed-token): a free-floating
dict is NOT evidence. A record counts as evidence only when it is bound
inside the HMAC-chained audit log via :meth:`gov.log.ActionLog.append`
(the log reserves chain metadata -- seq/ts/prev_hash -- and HMAC-binds
the canonical form; caller-supplied chain fields are dropped). The
per-record ``record_digest`` additionally chains guardrail-run records
of one writer so an auditor can verify per-guardrail ordering without
the key; the log chain itself gives global ordering.

The one honest distinction this module exists to enforce:
``intentional_block`` (a guard deliberately refused -- declared refusal
shapes, e.g. a policy deny) vs ``technical_failure`` (the guard errored
-- scanner crashed, timeout, misconfiguration). A policy block and a
guard error must never produce the same record shape; technical
failures are LOUD (``GuardrailFailureError``, fail-closed) and are
recorded as failures, never as blocks.
"""

import hashlib
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
RECORD_TYPE = "guardrail-run"

MODES = ("blocking", "advisory", "logging_only")
# Wave-280 adds the agent-loop shield gates (ogx-ai/ogx input_shields /
# output_shields): the inbound turn and the outbound response/tool call.
# Additive: every pre-wave-280 scope keeps its meaning.
EVENT_SCOPES = ("pre_call", "during_call", "post_call", "tool_call",
                "input_shield", "output_shield")
OUTCOMES = ("allow", "intentional_block", "advisory_flagged",
            "technical_failure")

# Fields owned by this module. The audit log adds reserved chain
# metadata (seq, ts, prev_hash, MACs, ...) around them; digest
# verification below only covers these fields so log-bookkeeping never
# breaks it.
RECORD_FIELDS = (
    "record_type", "schema_version",
    "guardrail_id", "guardrail_name",
    "guardrail_mode", "event_scope", "outcome",
    "rationale", "rationale_digest",
    "input_digest",
    "started_at", "duration_ms",
    "decision_effect", "policy_id",
    # Wave-280: first-class labels (e.g. a shield's provider_kind, so a
    # remote-boundary crossing is machine-readable on the record, not
    # buried in an opaque input digest). Additive and backward
    # compatible: records written before labels existed simply lack
    # the key, and the verifier only digests keys a record actually
    # carries -- old digests still recompute.
    "labels",
    "prev_guardrail_record_digest", "record_digest",
)

_GENESIS = "genesis"


class GuardrailFailureError(Exception):
    """A guardrail run failed technically (not a policy block).

    Raised LOUDLY and fail-closed: the guarded action must not proceed
    on an unverified guard, and the failure is recorded in the audit
    log as ``technical_failure`` -- never as a block.
    """


class GuardrailEvidenceError(Exception):
    """A guardrail-run record is malformed or a verification refused it."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


class GuardrailEvidenceWriter:
    """Appends uniform guardrail-run records to an ActionLog.

    One writer instance chains its own records via
    ``prev_guardrail_record_digest``. Writers are cheap; create one per
    guardrail attachment point (or one shared writer -- the chain then
    covers the union).
    """

    def __init__(self, log):
        self._log = log
        self._last_digest = _GENESIS

    def record(self, guardrail_id, guardrail_name, *, mode="blocking",
               event_scope="pre_call", outcome, rationale="",
               input_bytes=b"", duration_ms=0.0, started_at=None,
               decision_effect=None, policy_id=None, labels=None):
        """Build, digest, chain, and append one guardrail-run record.

        Returns the stored entry (as returned by ``log.append``).

        ``labels`` is an optional dict of short string keys to short
        string values (e.g. ``{"provider_kind": "remote"}``), stored on
        the record and covered by its digest -- first-class
        machine-readable metadata an auditor can filter on, not
        free-text rationale. Refused unless JSON-serializable
        str->str.

        Fail-closed: if ``log.append`` raises (log full, lock failure,
        ...), the exception propagates and the caller must not treat
        the guarded action as evidenced.
        """
        if not guardrail_id or not isinstance(guardrail_id, str):
            raise GuardrailEvidenceError(
                "guardrail_id must be a non-empty string")
        if not guardrail_name or not isinstance(guardrail_name, str):
            raise GuardrailEvidenceError(
                "guardrail_name must be a non-empty string")
        if mode not in MODES:
            raise GuardrailEvidenceError(
                "guardrail_mode must be one of %s, got %r" % (MODES, mode))
        if event_scope not in EVENT_SCOPES:
            raise GuardrailEvidenceError(
                "event_scope must be one of %s, got %r"
                % (EVENT_SCOPES, event_scope))
        if outcome not in OUTCOMES:
            raise GuardrailEvidenceError(
                "outcome must be one of %s, got %r" % (OUTCOMES, outcome))
        if not isinstance(input_bytes, (bytes, bytearray)):
            raise GuardrailEvidenceError("input_bytes must be bytes")
        if labels is not None:
            if not isinstance(labels, dict) or not all(
                    isinstance(k, str) and isinstance(v, str)
                    for k, v in labels.items()):
                raise GuardrailEvidenceError(
                    "labels must be a dict of str -> str")
            try:
                json.dumps(labels, sort_keys=True)
            except (TypeError, ValueError):
                raise GuardrailEvidenceError(
                    "labels must be JSON-serializable")
        rationale = str(rationale or "")
        record = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "guardrail_id": guardrail_id,
            "guardrail_name": guardrail_name,
            "guardrail_mode": mode,
            "event_scope": event_scope,
            "outcome": outcome,
            "rationale": rationale,
            "rationale_digest": _digest(rationale.encode("utf-8")),
            "input_digest": _digest(bytes(input_bytes)),
            "started_at": started_at or _utcnow_iso(),
            "duration_ms": float(duration_ms),
            "decision_effect": decision_effect,
            "policy_id": policy_id,
            "labels": dict(labels) if labels is not None else None,
            "prev_guardrail_record_digest": self._last_digest,
        }
        record["record_digest"] = _digest(_canonical(record))
        entry = self._log.append(record)
        self._last_digest = record["record_digest"]
        return entry


def guardrail_run_records(log):
    """All guardrail-run records in ``log``, in stored order."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if e.get("record_type") == RECORD_TYPE]


def verify_guardrail_records(records):
    """Verify record digests and per-writer chain continuity.

    Returns True when every record's ``record_digest`` recomputes over
    this module's fields and each record's
    ``prev_guardrail_record_digest`` links the previous record in the
    given list (the first must link ``genesis``). Returns False on any
    mismatch -- tampered verdicts, reordered records, injected samples.

    NOTE: a list mixing records from interleaved writers will fail the
    continuity check honestly; verify each writer's subsequence
    separately. The HMAC chain of the enclosing audit log is verified
    separately by the log reader -- that is what makes the records
    evidence rather than claims.
    """
    prev = _GENESIS
    for rec in records:
        if rec.get("record_type") != RECORD_TYPE:
            return False
        if rec.get("prev_guardrail_record_digest") != prev:
            return False
        # Wave-280: digest only the keys the record actually carries.
        # Records written before the ``labels`` field existed lack the
        # key entirely; excluding absent keys keeps their digests
        # recomputing (backward compatible), while removing ``labels``
        # from a labeled record still fails honestly (its digest was
        # computed WITH the field).
        body = {k: rec[k] for k in RECORD_FIELDS
                if k != "record_digest" and k in rec}
        if rec.get("record_digest") != _digest(_canonical(body)):
            return False
        prev = rec["record_digest"]
    return True


def run_guardrail(writer, *, guardrail_id, guardrail_name, mode="blocking",
                  event_scope="pre_call", fn, args=(), kwargs=None,
                  input_bytes=b"", intentional_block_types=(),
                  labels=None):
    """Execute ``fn`` as a guardrail run with a standardized evidence record.

    Classification (the intentional-block vs technical-failure
    distinction):
      - ``fn`` raising one of ``intentional_block_types``: the guard
        deliberately refused. Recorded as ``intentional_block``
        (``advisory_flagged`` in advisory mode). Blocking mode
        re-raises the ORIGINAL exception (fail-closed); advisory mode
        returns ``(False, record)`` and execution continues.
      - ``fn`` raising anything else: the guard failed technically.
        Recorded as ``technical_failure`` and a LOUD
        ``GuardrailFailureError`` is raised (fail-closed) -- never
        silent, never recorded as a block.
      - ``fn`` returning: recorded as ``allow``; returns
        ``(True, record)``.

    ``logging_only`` mode never raises from the guard outcome: blocks
    and failures are recorded and ``fn``'s exception (if any) is
    swallowed only after the record lands -- the run continues. Use
    only for shadow deployments.

    ``labels`` (optional dict of str->str) is attached to the record
    and covered by its digest.
    """
    if kwargs is None:
        kwargs = {}
    if mode not in MODES:
        raise GuardrailEvidenceError(
            "guardrail_mode must be one of %s, got %r" % (MODES, mode))
    t0 = datetime.now(timezone.utc)

    def _elapsed_ms():
        return (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0

    try:
        fn(*args, **kwargs)
    except intentional_block_types as exc:
        outcome = "advisory_flagged" if mode == "advisory" \
            else "intentional_block"
        rec = writer.record(
            guardrail_id, guardrail_name, mode=mode,
            event_scope=event_scope, outcome=outcome,
            rationale="%s: %s" % (type(exc).__name__, exc),
            input_bytes=input_bytes, duration_ms=_elapsed_ms(),
            labels=labels)
        if mode in ("advisory", "logging_only"):
            return False, rec
        raise
    except Exception as exc:  # noqa: BLE001 -- classification is the point
        rec = writer.record(
            guardrail_id, guardrail_name, mode=mode,
            event_scope=event_scope, outcome="technical_failure",
            rationale="%s: %s" % (type(exc).__name__, exc),
            input_bytes=input_bytes, duration_ms=_elapsed_ms(),
            labels=labels)
        if mode == "logging_only":
            return False, rec
        raise GuardrailFailureError(
            "guardrail %r failed technically (recorded as "
            "technical_failure, not a block): %s: %s"
            % (guardrail_id, type(exc).__name__, exc)) from exc
    rec = writer.record(
        guardrail_id, guardrail_name, mode=mode, event_scope=event_scope,
        outcome="allow", rationale="guard passed",
        input_bytes=input_bytes, duration_ms=_elapsed_ms(),
        labels=labels)
    return True, rec


class PolicyEvidenceAdapter:
    """Wraps a PolicyEngine so every decision emits a guardrail-run record.

    The canonical policy seam wired to the evidence standard. Mapping:
    ``deny`` -> ``intentional_block``; ``allow`` -> ``allow``;
    ``require_approval`` -> ``allow`` with
    ``decision_effect="require_approval"`` (the guard did not block --
    it routed; the effect field carries the truth). The policy's own
    ``policy_id`` rides along so the record is attributable.
    """

    def __init__(self, engine, writer, *, guardrail_id="policy-engine",
                 guardrail_name="policy-engine", event_scope="pre_call"):
        self._engine = engine
        self._writer = writer
        self._guardrail_id = guardrail_id
        self._guardrail_name = guardrail_name
        self._event_scope = event_scope

    def evaluate(self, action, context=None, **kwargs):
        decision = self._engine.evaluate(action, context, **kwargs)
        outcome = ("intentional_block" if decision.effect == "deny"
                   else "allow")
        self._writer.record(
            self._guardrail_id, self._guardrail_name,
            mode="blocking", event_scope=self._event_scope,
            outcome=outcome, rationale=decision.reason,
            input_bytes=_canonical({"action": action, "context": context}),
            decision_effect=decision.effect, policy_id=decision.policy_id)
        return decision
