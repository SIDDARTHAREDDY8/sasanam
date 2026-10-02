"""Ordered guard-plugin interface at the tool-call seam (wave-281 lane 9).

PATTERN LINEAGE: Portkey-AI/gateway (MIT -- LICENSE bytes verified by
the wave-280 prospecting lane): the plugin contract
``handler(context, parameters, eventType) -> {error, verdict, data}``
with the community-webhook ``transformedData`` third outcome, the
``start -> beforeRequest -> afterRequest -> end`` hooks, the
fail-closed structure (``verdict: false`` fails the request;
``error`` is separate from ``verdict``), ordered guardrail sets with
deny short-circuit, and the deterministic default guardrails. This is
a clean-room stdlib re-implementation of the *mechanisms* only; no
Portkey code, docs, or prose are vendored here. The managed guardrail
catalog and vendor plugins are commercial/paid APIs and are
deliberately excluded.

What this module adds over the wave-279 triad and the wave-280 shield
registry:

* a UNIFORM plugin contract with THREE outcomes -- allow / deny /
  **transform** (a guard may rewrite the payload instead of only
  blocking it; Portkey's ``transformedData``);
* hooks adapted to the tool seam: ``before_tool_call`` /
  ``after_tool_call`` (+ ``start`` / ``end`` for audit/metering);
* the error-vs-verdict separation as a STRUCTURAL rule: a plugin that
  errors (or returns a non-verdict, or a malformed transform) is a
  technical failure and the guarded action is refused LOUDLY -- it can
  never silently allow, and it is never recorded as a policy block;
* transform application with the diff MAC-bound as a DISTINCT audit
  event (``guard-plugin-transform``: old/new digests + changed keys),
  so an auditor can see exactly what was rewritten;
* deterministic stdlib default guards ($0, no network).

Composition, not duplication: every plugin run emits a
``guardrail-run`` loop event through
``gov.guardrail_evidence.GuardrailEvidenceWriter`` (the wave-279 seam),
with ``decision_effect="transform"`` on transform runs; the triad
adapter maps plugin outcomes onto ``gov.tool_guardrails`` verdicts.

F306-adjacent hygiene: this module never writes raw payload values
itself -- rationales and transform events carry digests and changed
KEY names only. Plugin-authored exception text is capped at 2000
chars but not sanitized: a custom plugin that embeds secrets in its
own exception message is the plugin author's bug (the F306 closure
owns the seam-level guarantee); the default guards never do this.
"""

import copy
import hashlib
import json
import re

from gov import guardrail_evidence as _ge

#: Hooks at the tool seam (Portkey's start -> beforeRequest ->
#: afterRequest -> end, adapted).
HOOKS = ("before_tool_call", "after_tool_call", "start", "end")

#: The three-valued plugin verdict (Portkey's verdict + transformedData).
VERDICTS = ("allow", "deny", "transform")

SCHEMA_VERSION = "1.0"
TRANSFORM_RECORD_TYPE = "guard-plugin-transform"

#: Cap for detail strings entering the audit log (log hygiene).
_DETAIL_CAP = 2000

#: Event-scope mapping for the guardrail-run seam (existing scopes
#: only -- no new scope vocabulary).
_SCOPE_FOR_HOOK = {
    "before_tool_call": "tool_call",
    "after_tool_call": "tool_call",
    "start": "pre_call",
    "end": "post_call",
}


def _capped(text):
    text = str(text or "")
    if len(text) > _DETAIL_CAP:
        text = text[:_DETAIL_CAP] + "...[truncated]"
    return text


class GuardPluginError(ValueError):
    """Base for guard-plugin failures.

    Every refusal carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text).
    Subclassing ``ValueError`` keeps declaration-time refusals
    catchable as programming errors too.
    """

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


class PluginDeny(GuardPluginError):
    """A plugin's declared intentional-block signal.

    Raised by a plugin's ``run`` to refuse the payload (the analog of
    ``ShieldViolation``). Recorded as ``intentional_block`` -- never as
    a technical failure.
    """

    def __init__(self, detail=""):
        super().__init__(
            "guardplugin-denied",
            "plugin denied: %s" % (_capped(detail) or "no detail",))


class PluginTechnicalFailure(GuardPluginError, _ge.GuardrailFailureError):
    """A plugin failed TECHNICALLY (errored, returned a non-verdict,
    or returned a malformed transform).

    A multiple-inheritance bridge (the wave-280 FGA lane's
    ``EphemeralGrantError`` precedent): it IS a
    ``guardrail_evidence.GuardrailFailureError``, so existing
    ``except GuardrailFailureError`` handlers keep catching it, and it
    carries the machine-readable ``guardplugin-error-refused`` code
    (repo convention: callers branch on ``code``). Raised LOUDLY and
    fail-closed: the guarded action must not proceed on an unverified
    guard, and the failure is recorded as ``technical_failure`` --
    never as a policy block.
    """

    def __init__(self, plugin_id, reason):
        GuardPluginError.__init__(
            self, "guardplugin-error-refused",
            "plugin %r failed technically (recorded as "
            "technical_failure, not a block): %s"
            % (plugin_id, _capped(reason)))
        self.plugin_id = plugin_id


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest_of(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


class PluginOutcome:
    """One plugin run's outcome. Never constructed with junk.

    ``verdict`` is one of "allow" / "deny" / "transform". ``detail``
    is the human/machine-readable reason (shape-level only -- never
    raw payload values). ``transformed`` is the rewritten payload and
    is meaningful only for "transform".
    """

    __slots__ = ("verdict", "detail", "transformed")

    def __init__(self, verdict, detail="", transformed=None):
        if verdict not in VERDICTS:
            raise GuardPluginError(
                "guardplugin-bad-verdict",
                "plugin verdict must be one of %s, got %r"
                % (VERDICTS, verdict))
        if verdict == "deny" and not (isinstance(detail, str)
                                      and detail.strip()):
            # The reject_content precedent: a reasonless refusal is a
            # programming error and must fail loud here, never reach
            # a caller or the audit log silently.
            raise ValueError(
                "deny_outcome requires a non-empty detail string")
        if verdict == "transform" and not isinstance(transformed, dict):
            raise GuardPluginError(
                "guardplugin-bad-transform",
                "transform outcome requires a dict payload, got %r"
                % type(transformed).__name__)
        self.verdict = verdict
        self.detail = _capped(detail)
        self.transformed = transformed

    def __repr__(self):  # pragma: no cover - debugging aid
        return "PluginOutcome(%r)" % (self.verdict,)


def allow_outcome(detail=""):
    """A satisfied guard: evaluation continues to the next plugin."""
    return PluginOutcome("allow", detail=detail)


def deny_outcome(detail):
    """Deny WITHOUT killing the run: the guarded action is refused
    (the chain short-circuits) with ``detail`` as the reason."""
    return PluginOutcome("deny", detail=detail)


def transform_outcome(transformed, detail=""):
    """Rewrite the payload: the chain continues with ``transformed``
    (a dict). The diff is recorded as a distinct audit event."""
    return PluginOutcome("transform", detail=detail, transformed=transformed)


class PluginContext:
    """What a plugin sees: identity, hook, tool, a defensive copy of
    the payload, and a copy of its declared params. A plugin cannot
    mutate the chain's payload except by returning a transform."""

    __slots__ = ("plugin_id", "hook", "tool_name", "payload", "params")

    def __init__(self, plugin_id, hook, tool_name, payload, params):
        self.plugin_id = plugin_id
        self.hook = hook
        self.tool_name = tool_name
        self.payload = payload
        self.params = params


class GuardPlugin:
    """A declared plugin: identity + hooks + params + ``run``.

    Constructed by ``PluginRegistry.register``; direct construction is
    allowed for composition helpers, with the same validation.
    """

    __slots__ = ("plugin_id", "hooks", "params", "run")

    def __init__(self, plugin_id, *, hooks, params=None, run):
        if not isinstance(plugin_id, str) or not plugin_id.strip():
            raise GuardPluginError(
                "guardplugin-bad-id",
                "plugin_id must be a non-empty string")
        hooks = tuple(hooks or ())
        if not hooks or any(h not in HOOKS for h in hooks):
            raise GuardPluginError(
                "guardplugin-bad-hook",
                "plugin %r hooks must be a non-empty subset of %s, got %r"
                % (plugin_id, HOOKS, hooks))
        params = dict(params) if params is not None else {}
        try:
            json.dumps(params, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
        except (TypeError, ValueError):
            raise GuardPluginError(
                "guardplugin-bad-params",
                "plugin %r params must be JSON-serializable so the "
                "declaration round-trips through audit records"
                % (plugin_id,))
        if not callable(run):
            raise GuardPluginError(
                "guardplugin-bad-run",
                "plugin %r: run must be callable" % (plugin_id,))
        self.plugin_id = plugin_id
        self.hooks = hooks
        self.params = params
        self.run = run


class PluginRegistry:
    """The named-plugin attach surface.

    Registration is declarative and closed: ``register`` validates
    everything up front; duplicate ids are refused (no shadowing);
    ``get`` refuses unknown ids fail-closed.
    """

    def __init__(self):
        self._plugins = {}

    def register(self, plugin_id, *, hooks, params=None, run):
        """Declare a plugin. Duplicate ids are a registration-time
        refusal (no shadowing, no silent override)."""
        if plugin_id in self._plugins:
            raise GuardPluginError(
                "guardplugin-duplicate-id",
                "plugin %r already registered: duplicate plugin ids are "
                "refused (no shadowing)" % (plugin_id,))
        plugin = GuardPlugin(plugin_id, hooks=hooks, params=params, run=run)
        self._plugins[plugin_id] = plugin
        return plugin

    def get(self, plugin_id):
        """Return the declared plugin, or raise fail-closed for an
        unknown id."""
        try:
            return self._plugins[plugin_id]
        except KeyError:
            raise GuardPluginError(
                "guardplugin-unknown-id",
                "plugin %r is not registered: refusing rather than "
                "skipping the plugin" % (plugin_id,)) from None

    def list_plugins(self):
        """Declared plugin ids, sorted."""
        return sorted(self._plugins)

    def for_hook(self, hook):
        """Plugin ids handling ``hook``, in registration order."""
        return [pid for pid, p in self._plugins.items() if hook in p.hooks]


class ChainVerdict:
    """The aggregate verdict of one hook run.

    ``allowed`` False means the guarded action must not proceed
    (``denied_by`` names the plugin). ``payload`` is the final payload
    after all transforms. ``transforms`` lists each applied transform
    as ``{"plugin_id", "old_digest", "new_digest", "changed_keys"}``
    where ``changed_keys`` are the TOP-LEVEL keys whose canonical
    values differ (nested changes surface under their top-level key).
    """

    __slots__ = ("allowed", "payload", "denied_by", "transforms",
                 "records")

    def __init__(self, allowed, payload, denied_by=None, transforms=(),
                 records=()):
        self.allowed = allowed
        self.payload = payload
        self.denied_by = denied_by
        self.transforms = list(transforms)
        self.records = list(records)

    def __repr__(self):  # pragma: no cover - debugging aid
        return "ChainVerdict(allowed=%r, denied_by=%r, transforms=%d)" % (
            self.allowed, self.denied_by, len(self.transforms))


def _changed_keys(old, new):
    keys = set(old) | set(new)
    return sorted(k for k in keys
                  if _canonical(old.get(k)) != _canonical(new.get(k)))


class GuardChain:
    """Runs the ordered plugin chain for one hook.

    ``registry`` declares the plugins, ``writer`` is a
    ``GuardrailEvidenceWriter`` (every plugin run becomes a
    ``guardrail-run`` loop event), ``log`` is the ``ActionLog`` (the
    distinct ``guard-plugin-transform`` events land here, MAC-bound).

    Fail-closed by construction: a plugin that errors, returns a
    non-verdict, or returns a malformed transform records
    ``technical_failure`` and raises ``GuardrailFailureError`` LOUDLY
    (the error-vs-verdict separation) -- the guarded action cannot
    proceed past an unverified guard. A deny short-circuits the chain
    and returns ``allowed=False`` (the caller skips the action).
    """

    def __init__(self, registry, writer, log):
        self._registry = registry
        self._writer = writer
        self._log = log

    def run_hook(self, hook, *, tool_name=None, payload, plugin_ids=None):
        """Evaluate the ordered plugin chain for ``hook``.

        ``payload`` is a dict (the tool args for ``before_tool_call``,
        the result envelope for ``after_tool_call``, metering data for
        ``start``/``end``). Returns a ``ChainVerdict``; raises
        ``GuardrailFailureError`` on any plugin technical failure.
        """
        if hook not in HOOKS:
            raise GuardPluginError(
                "guardplugin-bad-hook",
                "hook must be one of %s, got %r" % (HOOKS, hook))
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict, got %r"
                             % type(payload).__name__)
        ids = (list(plugin_ids) if plugin_ids is not None
               else self._registry.for_hook(hook))
        # Resolve everything before running anything: an unknown id
        # fails closed before any plugin runs.
        plugins = [self._registry.get(pid) for pid in ids]
        current = copy.deepcopy(payload)
        transforms = []
        records = []
        for plugin in plugins:
            ctx = PluginContext(
                plugin.plugin_id, hook, tool_name,
                copy.deepcopy(current), dict(plugin.params))
            outcome, record = self._run_one(plugin, ctx, current)
            records.append(record)
            if outcome.verdict == "deny":
                return ChainVerdict(False, current,
                                    denied_by=plugin.plugin_id,
                                    transforms=transforms, records=records)
            if outcome.verdict == "transform":
                before = current
                old_digest = _digest_of(before)
                current = copy.deepcopy(outcome.transformed)
                changed = _changed_keys(before, current)
                new_digest = _digest_of(current)
                transforms.append({
                    "plugin_id": plugin.plugin_id,
                    "old_digest": old_digest,
                    "new_digest": new_digest,
                    "changed_keys": changed,
                })
                self._log.append({
                    "record_type": TRANSFORM_RECORD_TYPE,
                    "schema_version": SCHEMA_VERSION,
                    "plugin_id": plugin.plugin_id,
                    "hook": hook,
                    "tool_name": tool_name,
                    "old_digest": old_digest,
                    "new_digest": new_digest,
                    "changed_keys": changed,
                    "detail": outcome.detail,
                })
        return ChainVerdict(True, current, transforms=transforms,
                            records=records)

    def _run_one(self, plugin, ctx, payload_before):
        """Run one plugin and classify the outcome.

        Returns (PluginOutcome, guardrail-run record). Raises
        ``PluginTechnicalFailure`` (a ``GuardrailFailureError``) on
        technical failure (fail-closed).
        """
        labels = {"hook": ctx.hook, "plugin_id": plugin.plugin_id}
        scope = _SCOPE_FOR_HOOK[ctx.hook]
        input_bytes = _canonical({
            "plugin_id": plugin.plugin_id, "hook": ctx.hook,
            "tool_name": ctx.tool_name, "payload": ctx.payload})

        try:
            outcome = plugin.run(ctx)
        except PluginDeny as exc:
            rec = self._writer.record(
                "plugin:" + plugin.plugin_id, plugin.plugin_id,
                mode="blocking", event_scope=scope,
                outcome="intentional_block",
                rationale="PluginDeny: %s" % exc,
                input_bytes=input_bytes, labels=labels,
                decision_effect="deny")
            return PluginOutcome("deny", detail=str(exc)), rec
        except Exception as exc:  # noqa: BLE001 -- classification is the point
            rec = self._writer.record(
                "plugin:" + plugin.plugin_id, plugin.plugin_id,
                mode="blocking", event_scope=scope,
                outcome="technical_failure",
                rationale=_capped("%s: %s" % (type(exc).__name__, exc)),
                input_bytes=input_bytes, labels=labels)
            raise PluginTechnicalFailure(
                plugin.plugin_id,
                "%s: %s" % (type(exc).__name__, exc)) from exc

        if not isinstance(outcome, PluginOutcome):
            rec = self._writer.record(
                "plugin:" + plugin.plugin_id, plugin.plugin_id,
                mode="blocking", event_scope=scope,
                outcome="technical_failure",
                rationale=_capped(
                    "plugin returned %r: plugins must return a "
                    "PluginOutcome" % (outcome,)),
                input_bytes=input_bytes, labels=labels)
            raise PluginTechnicalFailure(
                plugin.plugin_id,
                "returned a non-verdict %r" % (outcome,))

        if outcome.verdict == "deny":
            rec = self._writer.record(
                "plugin:" + plugin.plugin_id, plugin.plugin_id,
                mode="blocking", event_scope=scope,
                outcome="intentional_block", rationale=outcome.detail,
                input_bytes=input_bytes, labels=labels,
                decision_effect="deny")
            return outcome, rec
        if outcome.verdict == "transform":
            rec = self._writer.record(
                "plugin:" + plugin.plugin_id, plugin.plugin_id,
                mode="blocking", event_scope=scope,
                outcome="allow",
                rationale="transform: %s" % (outcome.detail or
                                             "payload rewritten"),
                input_bytes=input_bytes, labels=labels,
                decision_effect="transform")
            return outcome, rec
        rec = self._writer.record(
            "plugin:" + plugin.plugin_id, plugin.plugin_id,
            mode="blocking", event_scope=scope,
            outcome="allow", rationale=outcome.detail or "plugin passed",
            input_bytes=input_bytes, labels=labels)
        return outcome, rec


# ---------------------------------------------------------------------------
# Composition with the wave-279 tool-guardrail triad
# ---------------------------------------------------------------------------

def as_tool_input_guardrail(plugin):
    """Wrap a GuardPlugin as a ``gov.tool_guardrails.ToolInputGuardrail``.

    Plugin deny (returned or raised ``PluginDeny``) ->
    ``reject_content`` carrying the detail as the model-facing message
    (the run continues, the tool call is skipped by the caller); a
    crashing plugin -> ``raise_exception`` (the triad's fail-closed
    tripwire, never a pass-through); allow -> ``allow()``.

    A TRANSFORM through this adapter is a contract violation and maps
    to ``raise_exception`` (loud tripwire): the triad interface cannot
    carry rewritten args back to the caller, so silently allowing
    would proceed with UNREDACTED args and no transform audit event.
    Transform-capable plugins (e.g. ``pii-redact``) must be attached
    via ``GuardChain.run_hook``, where the diff is audit-logged.
    """
    from gov import tool_guardrails as _tg

    def _run(data):
        ctx = PluginContext(plugin.plugin_id, "before_tool_call",
                            data.tool_name,
                            copy.deepcopy(data.tool_arguments),
                            dict(plugin.params))
        try:
            outcome = plugin.run(ctx)
        except PluginDeny as exc:
            return _tg.reject_content(str(exc) or "plugin denied")
        except Exception as exc:  # noqa: BLE001 -- structural error->deny
            return _tg.raise_exception(
                "plugin %r errored: %s: %s"
                % (plugin.plugin_id, type(exc).__name__, exc))
        if not isinstance(outcome, PluginOutcome):
            return _tg.raise_exception(
                "plugin %r returned a non-verdict" % (plugin.plugin_id,))
        if outcome.verdict == "deny":
            return _tg.reject_content(outcome.detail or "plugin denied")
        if outcome.verdict == "transform":
            return _tg.raise_exception(
                "plugin %r returned a transform: the triad adapter cannot "
                "carry rewritten args -- attach transform-capable plugins "
                "via GuardChain.run_hook" % (plugin.plugin_id,))
        return _tg.allow()

    return _tg.ToolInputGuardrail("plugin:" + plugin.plugin_id, _run)


# ---------------------------------------------------------------------------
# Deterministic default guards ($0, no network, stdlib only)
# ---------------------------------------------------------------------------

# PII / credential shapes, redacted by kind (never echoed).
_PII_PATTERNS = (
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("card", re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("credential", re.compile(
        r"(?i)(password|passwd|api[_-]?key|secret|token)\s*=\s*\S+")),
)


def _redact_value(value):
    """Redact PII/credential spans in a string value.

    Returns (new_value, kinds_hit). Deterministic; kinds only, never
    the matched values, leave this function.
    """
    if not isinstance(value, str):
        return value, ()
    kinds = []

    def _sub(kind, pattern, text):
        def _repl(_m):
            if kind not in kinds:
                kinds.append(kind)
            return "[REDACTED:%s]" % kind
        return pattern.sub(_repl, text)

    for kind, pattern in _PII_PATTERNS:
        value = _sub(kind, pattern, value)
    return value, tuple(kinds)


def _redact_deep(obj):
    """Recursively redact string values in dicts/lists.

    Returns (new_obj, kinds_hit).
    """
    kinds = []

    def _walk(o):
        if isinstance(o, str):
            new, hit = _redact_value(o)
            for k in hit:
                if k not in kinds:
                    kinds.append(k)
            return new
        if isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            walked = [_walk(v) for v in o]
            return type(o)(walked) if isinstance(o, tuple) else walked
        return o

    return _walk(obj), tuple(kinds)


def _pii_redact_run(ctx):
    new_payload, kinds = _redact_deep(ctx.payload)
    if not kinds:
        return allow_outcome("no PII spans found")
    return transform_outcome(
        new_payload,
        "redacted %d PII kind(s): %s"
        % (len(kinds), ", ".join(kinds)))


_INJECTION_SUBSTRINGS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal your system prompt",
    "jailbreak",
    "dan mode",
)


def _injection_substrings_run(ctx):
    blob = _canonical(ctx.payload).decode("utf-8", "replace").lower()
    for needle in _INJECTION_SUBSTRINGS:
        if needle in blob:
            return deny_outcome(
                "prompt-injection cue %r in tool args" % (needle,))
    return allow_outcome("no injection cues")


def _tool_allowlist_run(ctx):
    tools = ctx.params.get("tools")
    if not isinstance(tools, list) or not all(
            isinstance(t, str) for t in tools):
        # Misconfiguration fails closed: an allowlist that cannot be
        # read is not an allowlist.
        raise GuardPluginError(
            "guardplugin-bad-params",
            "tool-allowlist requires params.tools as a list of strings")
    if ctx.tool_name in tools:
        return allow_outcome("tool %r allowlisted" % (ctx.tool_name,))
    return deny_outcome("tool %r not in the declared allowlist"
                        % (ctx.tool_name,))


def _arg_byte_budget_run(ctx):
    max_bytes = ctx.params.get("max_bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) \
            or max_bytes < 0:
        raise GuardPluginError(
            "guardplugin-bad-params",
            "arg-byte-budget requires params.max_bytes as a non-negative int")
    size = len(_canonical(ctx.payload))
    if size <= max_bytes:
        return allow_outcome("args %d bytes within budget %d"
                             % (size, max_bytes))
    return deny_outcome("args %d bytes exceed budget %d" % (size, max_bytes))


_SCHEMA_TYPES = {"str": str, "int": int, "bool": bool, "list": list,
                 "dict": dict}


def _json_schema_args_run(ctx):
    schema = ctx.params.get("schema")
    if not isinstance(schema, dict):
        raise GuardPluginError(
            "guardplugin-bad-params",
            "json-schema-args requires params.schema as a dict")
    required = schema.get("required", [])
    types = schema.get("types", {})
    no_additional = schema.get("no_additional", False)
    payload = ctx.payload
    for key in required:
        if key not in payload:
            return deny_outcome("missing required arg %r" % (key,))
    for key, tname in types.items():
        if tname not in _SCHEMA_TYPES:
            # Fail-open misconfiguration is not an option: an unknown
            # type name would silently disable the check.
            raise GuardPluginError(
                "guardplugin-bad-params",
                "json-schema-args: unknown type name %r (expected one of %s)"
                % (tname, sorted(_SCHEMA_TYPES)))
        if key in payload:
            want = _SCHEMA_TYPES[tname]
            got = payload[key]
            if not isinstance(got, want) or (
                    want is int and isinstance(got, bool)):
                return deny_outcome(
                    "arg %r must be %s, got %s"
                    % (key, tname, type(got).__name__))
    if no_additional:
        allowed_keys = set(required) | set(types)
        extra = sorted(set(payload) - allowed_keys)
        if extra:
            return deny_outcome("additional args refused: %s"
                                % (", ".join(extra),))
    return allow_outcome("args satisfy the declared schema")


#: The deterministic default guard set: id -> (hooks, default_params, run).
DEFAULT_GUARDS = {
    "pii-redact": (("before_tool_call",), {}, _pii_redact_run),
    "injection-substrings": (("before_tool_call",), {}, _injection_substrings_run),
    "tool-allowlist": (("before_tool_call",), {"tools": []}, _tool_allowlist_run),
    "arg-byte-budget": (("before_tool_call",), {"max_bytes": 65536},
                        _arg_byte_budget_run),
    "json-schema-args": (("before_tool_call",), {"schema": {}},
                         _json_schema_args_run),
}


def register_defaults(registry, only=None, params_override=None):
    """Register the deterministic default guards.

    ``only`` restricts to a subset of ids; ``params_override`` maps an
    id to the params it is registered with (e.g. the deployment's
    allowlist). Returns the registered ids.
    """
    only = set(only) if only is not None else set(DEFAULT_GUARDS)
    unknown = sorted(only - set(DEFAULT_GUARDS))
    if unknown:
        # A typo'd guard id must not silently mean "no guard".
        raise GuardPluginError(
            "guardplugin-unknown-id",
            "register_defaults: unknown default guard id(s): %s"
            % (", ".join(unknown),))
    params_override = params_override or {}
    registered = []
    for gid in DEFAULT_GUARDS:
        if gid not in only:
            continue
        hooks, default_params, run = DEFAULT_GUARDS[gid]
        params = dict(default_params)
        params.update(params_override.get(gid, {}))
        registry.register(gid, hooks=hooks, params=params, run=run)
        registered.append(gid)
    return registered
