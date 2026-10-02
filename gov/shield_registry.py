"""Named safety-shield registry with input/output attach points (wave-280 lane 6).

PATTERN LINEAGE: ogx-ai/ogx (the Llama Stack successor; the repo moved
meta-llama/llama-stack -> llamastack/llama-stack -> ogx-ai/ogx), MIT --
``shields register --shield-id --params``, ``AgentConfig(input_shields=
..., output_shields=...)`` wrapping the inbound turn and the outbound
model response inside the agent execution loop, and the ``shield_call``
step events with a ``violation`` field that make shield verdicts
observable telemetry rather than side-channel logs. This is a clean-room
stdlib re-implementation of the *mechanisms* only; no ogx code, docs, or
prose are vendored here.

What is adapted:

* a ``ShieldRegistry`` of NAMED, declared shields (shield id, provider
  class, JSON params) -- the attach surface our policy engine lacked;
* ``run_input_shields`` / ``run_output_shields`` wrapping the inbound
  payload (prompt/request) and the outbound payload (response/tool-call
  args), evaluated in declared order, first violation decisive;
* every shield run emits a verdict loop event into the HMAC-chained
  audit log -- reusing ``gov.guardrail_evidence.run_guardrail`` (never
  duplicated): ``input_shield`` / ``output_shield`` event scopes,
  ``allow`` / ``intentional_block`` / ``technical_failure`` outcomes;
* FAIL-CLOSED on shield error. A downstream project in the wild chose
  fail-open on errors ("degrade gracefully"); this module inverts that
  default by design: an erroring shield records ``technical_failure``
  and refuses the guarded action -- it never silently allows and never
  masquerades as a policy block;
* the inline/remote provider trust split: ``inline`` shields run
  in-process; ``remote`` shields are declared across an explicit
  boundary (an endpoint is mandatory at registration) and their
  verdicts are recorded as crossing it;
* composition with the wave-279 tool-guardrail triad:
  ``as_tool_input_guardrail`` / ``as_tool_output_guardrail`` wrap a
  Shield as ``gov.tool_guardrails`` declarations -- shield allow ->
  ``allow()``, shield violation -> ``reject_content(detail)`` (the
  shield's detail becomes the model-facing message; the run continues),
  shield crash -> the triad runner's fail-closed tripwire.

Verdict contract: a shield's ``run`` returns a ``ShieldVerdict`` with
``verdict`` in {"allow", "violation"} and a human/machine-readable
``detail`` string. Anything else a shield does -- raising ``Shield-
Violation`` directly, returning a non-verdict, raising an unexpected
error -- is handled fail-closed, never as an allow.

Registration is a compile-time boundary (the Cerbos duplicate-kind
discipline): duplicate shield ids and unknown shield ids at attach time
are refused loudly, never shadowed or silently skipped. Shield params
must be JSON-serializable so the declared configuration round-trips
through the audit record unchanged.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads. The audit log binds its own timestamps at append time.
"""

import json

from gov import guardrail_evidence as _ge
from gov import tool_guardrails as _tg

#: Verdict vocabulary -- the ``violation`` field of a shield_call event.
_VERDICTS = ("allow", "violation")

#: Provider classes -- the inline/remote trust split.
_PROVIDER_KINDS = ("inline", "remote")

#: Cap for detail strings entering the audit log (log hygiene).
_DETAIL_CAP = 2000


class ShieldError(ValueError):
    """Base for shield-registry failures.

    Every refusal carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text).
    Subclassing ``ValueError`` keeps declaration-time refusals
    catchable as programming errors too.
    """

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


class ShieldResolutionError(ShieldError):
    """An attach list named a shield id the registry never declared.

    Fail-closed: the guarded action must not proceed past an unresolved
    shield -- silently skipping the shield would be fail-open.
    """

    def __init__(self, shield_id):
        super().__init__(
            "shield-unknown-id",
            "shield %r is not registered: refusing rather than "
            "skipping the shield" % (shield_id,))
        self.shield_id = shield_id


class ShieldViolation(ShieldError):
    """A shield's declared intentional-block signal.

    ``detail`` is the shield's reason (model/auditor-facing). Raised by
    a shield's ``run`` to refuse the payload, or by this module's
    runners when a shield returns a ``violation`` verdict.
    """

    def __init__(self, shield_id, detail=""):
        super().__init__(
            "shield-violation",
            "shield %r violation: %s" % (shield_id, detail))
        self.shield_id = shield_id
        self.detail = detail


class ShieldVerdict:
    """One shield run's verdict. Never constructed positionally with
    junk: ``verdict`` must be "allow" or "violation"."""

    __slots__ = ("verdict", "detail")

    def __init__(self, verdict, detail=""):
        if verdict not in _VERDICTS:
            raise ShieldError(
                "shield-bad-verdict",
                "shield verdict must be one of %s, got %r"
                % (_VERDICTS, verdict))
        self.verdict = verdict
        self.detail = str(detail or "")

    def __repr__(self):  # pragma: no cover - debugging aid
        return "ShieldVerdict(%r)" % (self.verdict,)


class ShieldData:
    """What a shield sees: the payload under evaluation and the shield's
    declared params. ``params`` is a shallow copy taken at run time so a
    shield cannot mutate the registry's declaration."""

    __slots__ = ("payload", "params")

    def __init__(self, payload, params):
        self.payload = payload
        self.params = dict(params)


class Shield:
    """A declared shield: identity + provider class + params + the
    in-process ``run`` implementation (or the remote endpoint contract).

    Constructed by ``ShieldRegistry.register``; direct construction is
    allowed for composition helpers (the triad adapters), with the same
    validation applied.
    """

    __slots__ = ("shield_id", "provider_kind", "params", "run", "endpoint")

    def __init__(self, shield_id, *, provider_kind="inline", params=None,
                 run, endpoint=None):
        if not isinstance(shield_id, str) or not shield_id.strip():
            raise ShieldError(
                "shield-bad-id", "shield_id must be a non-empty string")
        if provider_kind not in _PROVIDER_KINDS:
            raise ShieldError(
                "shield-bad-provider-kind",
                "provider_kind must be one of %s, got %r"
                % (_PROVIDER_KINDS, provider_kind))
        params = dict(params) if params is not None else {}
        try:
            json.dumps(params, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
        except (TypeError, ValueError):
            raise ShieldError(
                "shield-bad-params",
                "shield %r params must be JSON-serializable so the "
                "declaration round-trips through audit records"
                % (shield_id,))
        if not callable(run):
            raise ShieldError(
                "shield-no-run",
                "shield %r: run must be callable" % (shield_id,))
        if provider_kind == "remote":
            # The declared boundary: a remote shield without an
            # endpoint cannot be invoked -- refused here, not at the
            # first guarded action.
            if (not isinstance(endpoint, str) or not endpoint.strip()
                    or not endpoint.startswith(("http://", "https://"))):
                raise ShieldError(
                    "shield-remote-no-endpoint",
                    "shield %r is remote: endpoint must be a declared "
                    "http(s) URL" % (shield_id,))
        self.shield_id = shield_id
        self.provider_kind = provider_kind
        self.params = params
        self.run = run
        self.endpoint = endpoint


class ShieldRegistry:
    """The named-shield attach surface.

    Registration is declarative and closed: ``register`` validates
    everything up front; ``get`` refuses unknown ids fail-closed.
    """

    def __init__(self):
        self._shields = {}

    def register(self, shield_id, *, provider_kind="inline", params=None,
                 run, endpoint=None):
        """Declare a shield. Duplicate ids are a registration-time
        ValueError (no shadowing, no silent override)."""
        if shield_id in self._shields:
            raise ShieldError(
                "shield-duplicate-id",
                "shield %r already registered: duplicate shield ids are "
                "refused (no shadowing)" % (shield_id,))
        shield = Shield(shield_id, provider_kind=provider_kind,
                        params=params, run=run, endpoint=endpoint)
        self._shields[shield_id] = shield
        return shield

    def get(self, shield_id):
        """Return the declared shield, or raise ``ShieldResolutionError``
        (fail-closed) for an unknown id."""
        try:
            return self._shields[shield_id]
        except KeyError:
            raise ShieldResolutionError(shield_id) from None

    def list_shields(self):
        """Declared shield ids, sorted."""
        return sorted(self._shields)


# ---------------------------------------------------------------------------
# Runners: input_shields / output_shields
# ---------------------------------------------------------------------------

def _detail_capped(detail):
    text = str(detail or "")
    if len(text) > _DETAIL_CAP:
        text = text[:_DETAIL_CAP] + "...[truncated]"
    return text


def _canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _run_with_payload(shield, verdict):
    """Classify one shield outcome (the ``run_guardrail`` ``fn`` body).

    * shield returns allow -> returns None (no refusal);
    * shield returns violation (or raises ``ShieldViolation``) ->
      raises it (declared intentional block; ``run_guardrail`` records
      ``intentional_block`` and re-raises in blocking mode);
    * shield returns a non-verdict -> programming error, fails closed
      as a technical failure (never an allow);
    * shield raises anything else -> technical failure, fails closed.
    """
    if isinstance(verdict, ShieldViolation):
        raise verdict
    if not isinstance(verdict, ShieldVerdict):
        raise ShieldError(
            "shield-non-verdict",
            "shield %r returned %r: shields must return a ShieldVerdict"
            % (shield.shield_id, verdict))
    if verdict.verdict == "violation":
        raise ShieldViolation(shield.shield_id,
                              _detail_capped(verdict.detail))
    return None


def _run_shields(registry, shield_ids, payload, writer, event_scope):
    """Evaluate shields in declared order; the first violation is
    decisive and raises ``ShieldViolation``. Unknown ids raise
    ``ShieldResolutionError`` before any shield runs. Every shield that
    runs emits a ``guardrail-run`` loop event (verdict telemetry)
    through the shared ``GuardrailEvidenceWriter`` -- the shield_call
    analog.

    A duplicated id inside one attach list is NOT deduplicated: each
    entry is evaluated in order and emits its own loop event (the
    list is the declared evaluation order; silently collapsing it
    would rewrite the declaration).

    Returns the list of (shield_id, "allow") for shields that allowed,
    in evaluation order.
    """
    shields = [registry.get(sid) for sid in shield_ids]
    allowed = []
    for shield in shields:

        def _invoke(shield=shield):
            verdict = shield.run(ShieldData(payload, shield.params))
            return _run_with_payload(shield, verdict)

        _ge.run_guardrail(
            writer,
            guardrail_id="shield:" + shield.shield_id,
            guardrail_name=shield.shield_id,
            mode="blocking",
            event_scope=event_scope,
            fn=_invoke,
            input_bytes=_canonical_payload(
                {"shield_id": shield.shield_id,
                 "provider_kind": shield.provider_kind,
                 "payload": payload}),
            intentional_block_types=(ShieldViolation,),
            # The inline/remote trust split is machine-readable on the
            # record: an auditor can filter remote-boundary crossings
            # without parsing opaque digests.
            labels={"provider_kind": shield.provider_kind})
        allowed.append((shield.shield_id, "allow"))
    return allowed


def run_input_shields(registry, shield_ids, payload, *, writer):
    """Wrap the INBOUND turn: evaluate ``input_shields`` over the
    payload pre-action. Raises ``ShieldViolation`` (fail-closed) on the
    first violating shield; ``ShieldResolutionError`` on an undeclared
    id; ``GuardrailFailureError`` when a shield errors technically."""
    return _run_shields(registry, list(shield_ids or []), payload, writer,
                        "input_shield")


def run_output_shields(registry, shield_ids, payload, *, writer):
    """Wrap the OUTBOUND response/tool call: evaluate
    ``output_shields`` over the result post-action. Same fail-closed
    contract as the input seam."""
    return _run_shields(registry, list(shield_ids or []), payload, writer,
                        "output_shield")


# ---------------------------------------------------------------------------
# Composition with the wave-279 tool-guardrail triad
# ---------------------------------------------------------------------------

def _triad_run(shield, data):
    if hasattr(data, "tool_arguments"):
        payload = data.tool_arguments  # input guardrail: pre-execution args
    else:
        payload = getattr(data, "output", None)  # output guardrail: result
    verdict = shield.run(ShieldData(payload, shield.params))
    if isinstance(verdict, ShieldViolation):
        return _tg.reject_content(
            _detail_capped(verdict.detail) or "shield violation")
    if not isinstance(verdict, ShieldVerdict):
        raise ShieldError(
            "shield-non-verdict",
            "shield %r returned %r: shields must return a ShieldVerdict"
            % (shield.shield_id, verdict))
    if verdict.verdict == "violation":
        return _tg.reject_content(
            _detail_capped(verdict.detail) or "shield violation")
    return _tg.allow()


def as_tool_input_guardrail(shield):
    """Wrap a Shield as a ``gov.tool_guardrails.ToolInputGuardrail``.

    Shield allow -> ``allow()``; shield violation -> ``reject_content``
    carrying the shield's detail as the model-facing message (the run
    continues, the tool call is skipped by the caller); a crashing
    shield -> the triad runner's fail-closed tripwire (never a
    pass-through). The shield still records its verdict loop events
    when run through ``run_input_shields``; this adapter is the
    per-tool attach path for ``ApprovalQueue.elicit_decision(
    guardrails=...)``.
    """
    from gov import tool_guardrails as _tg

    def _run(data):
        return _triad_run(shield, data)

    return _tg.ToolInputGuardrail("shield:" + shield.shield_id, _run)


def as_tool_output_guardrail(shield):
    """Wrap a Shield as a ``gov.tool_guardrails.ToolOutputGuardrail``
    (violation -> the output is replaced with the shield's detail)."""
    from gov import tool_guardrails as _tg

    def _run(data):
        return _triad_run(shield, data)

    return _tg.ToolOutputGuardrail("shield:" + shield.shield_id, _run)
