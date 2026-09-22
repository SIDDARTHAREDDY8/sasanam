"""AgentSpec runtime-rule DSL compiler (S1).

v1 surface (adjudicated scope):

* triggers: ``{on: tool_call, tool: <tool|[tools]>}`` ONLY. ``tool`` is
  optional (absent = every tool). ``tool_result`` / ``queue_event`` /
  ``session_event`` triggers are DEFERRED to a v2 review: post-execution
  triggers cannot retro-deny an executed call, so their semantics need a
  separate decision.
* enforcement: ``allow`` | ``deny`` | ``require_approval`` ONLY.
  ``redact`` is DEFERRED to v2 (it needs a new engine effect touching
  the DLP/preview invariants F11/F12).
* predicates: mappings over the policy engine's match keys
  (``gov.policy.KNOWN_MATCH_KEYS``), compiled 1:1 into ordinary
  ``policies:`` rule match blocks. ``tool`` belongs in the trigger, not
  the predicate.

Compiled rules ARE ordinary policy rules: they inherit deny-priority
evaluation and default-deny, and each one is validated by
``PolicyEngine._validate_rule`` before it enters the enforced set.
The compiler never consults the model at enforcement time.

Review gate: a rule enters the enforced set ONLY through an explicit
``apply_dsl(policy, source)`` call — generated rules are never
auto-promoted; a human promotes them by calling ``apply_dsl`` (and by
setting the ``GOV_DSL_HASH`` pin they sign off on the exact source).

Hash pinning (F48 pattern, separate digest): ``apply_dsl`` computes the
SHA-256 of the DSL source bytes and, when the ``GOV_DSL_HASH`` env pin
is set, refuses with ``DslPinMismatchError`` unless they match — a
swapped DSL source can therefore never silently govern a run, and the
refusal happens BEFORE any executor is constructed. The DSL digest is
deliberately NOT folded into ``Policy.policy_hash`` (that hash input
format is crypto-lane territory); ``apply_dsl`` records
``policy.dsl_source_hash`` / ``policy.dsl_pinned`` /
``policy.dsl_rule_ids`` on the in-memory policy object instead. No DSL
configured -> those stay null/False/() and behavior is unchanged.

Surface note: the adjudicated DSL examples write triggers/predicates as
inline flow mappings (``trigger: {on: tool_call, tool: http_post}``).
``gov.yamlmini`` does not parse flow mappings, so this module parses
its own one-level inline form (see ``_parse_flow_mapping``) — contained
here, no shared-parser changes. Block form always works too.
"""

import os
from hashlib import sha256

from .policy import KNOWN_MATCH_KEYS, PolicyEngine
from .yamlmini import parse as parse_yaml

# v1 trigger surface. The deferred triggers are rejected with an
# explicit "deferred to v2" error (not a generic unknown-trigger
# error) so the failure message names the review gate.
_V1_TRIGGERS = {"tool_call"}
_V2_TRIGGERS = {"tool_result", "queue_event", "session_event"}
_V1_ENFORCEMENTS = {"allow", "deny", "require_approval"}
_V2_ENFORCEMENTS = {"redact"}


class DslCompileError(ValueError):
    """Malformed DSL source: unknown trigger/predicate/enforcement,
    duplicate rule id, or structural error. Fails closed at load —
    ``apply_dsl`` raises before any rule enters the enforced set and
    before any executor is constructed."""


class DslPinMismatchError(Exception):
    """The DSL source hash does not match the GOV_DSL_HASH pin.

    Raised by ``apply_dsl`` BEFORE any rule is promoted or any
    executor is constructed — the F48 pattern applied to the DSL
    digest."""


def dsl_source_hash(source_bytes):
    """SHA-256 hex digest of the raw DSL source bytes."""
    if isinstance(source_bytes, str):
        source_bytes = source_bytes.encode("utf-8")
    return sha256(source_bytes).hexdigest()


def _parse_flow_scalar(text, what, rule_id):
    """Parse one flow-mapping value: bool, int, flow sequence, or string."""
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        return t[1:-1]
    if t in ("true", "True"):
        return True
    if t in ("false", "False"):
        return False
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_parse_flow_scalar(p, what, rule_id)
                for p in inner.split(",")]
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    if not t:
        raise DslCompileError(
            "DSL rule %r: %s has an empty value; use block form for "
            "complex values." % (rule_id, what))
    return t


def _parse_flow_mapping(text, what, rule_id):
    """Parse a one-level ``{k: v, ...}`` inline mapping.

    Values may be scalars, booleans, or flat flow sequences; anything
    deeper (nested mappings) must use block form. Raises
    DslCompileError on any shape this cannot represent exactly.
    """
    t = text.strip()
    if not (t.startswith("{") and t.endswith("}")):
        raise DslCompileError(
            "DSL rule %r: %s must be a mapping (block form) or an inline "
            "{k: v} mapping, got %r." % (rule_id, what, text))
    inner = t[1:-1].strip()
    if not inner:
        return {}
    parts, depth, cur = [], 0, []
    for ch in inner:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                raise DslCompileError(
                    "DSL rule %r: %s has unbalanced brackets: %r."
                    % (rule_id, what, text))
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if depth != 0:
        raise DslCompileError(
            "DSL rule %r: %s has unbalanced brackets: %r."
            % (rule_id, what, text))
    parts.append("".join(cur))
    out = {}
    for part in parts:
        if ":" not in part:
            raise DslCompileError(
                "DSL rule %r: %s entry %r is not k: v; nested mappings "
                "need block form." % (rule_id, what, part.strip()))
        key, value = part.split(":", 1)
        key = key.strip()
        if not key:
            raise DslCompileError(
                "DSL rule %r: %s has an empty key in %r."
                % (rule_id, what, text))
        if key in out:
            raise DslCompileError(
                "DSL rule %r: %s repeats key %r." % (rule_id, what, key))
        value = value.strip()
        if value.startswith("{"):
            raise DslCompileError(
                "DSL rule %r: %s key %r has a nested mapping; use block "
                "form." % (rule_id, what, key))
        out[key] = _parse_flow_scalar(value, "%s key %r" % (what, key),
                                      rule_id)
    return out


def _coerce_mapping(value, what, rule_id):
    """Trigger/predicate as a dict, accepting block or inline form."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        return _parse_flow_mapping(value, what, rule_id)
    raise DslCompileError(
        "DSL rule %r: %s must be a mapping, got %r."
        % (rule_id, what, value))


def _compile_block(block, index):
    """Compile one DSL block to an ordinary policy rule dict."""
    if not isinstance(block, dict):
        raise DslCompileError(
            "DSL block %d must be a mapping, got %r." % (index, block))
    rule_id = block.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise DslCompileError(
            "DSL block %d: 'id' is required (non-empty string) for audit "
            "traceability." % index)
    rule_id = rule_id.strip()

    # --- trigger (v1: tool_call only) ---
    trigger = _coerce_mapping(block.get("trigger"), "trigger", rule_id)
    on = trigger.get("on")
    if on in _V2_TRIGGERS:
        raise DslCompileError(
            "DSL rule %r: trigger %r is DEFERRED to v2 (post-execution "
            "triggers cannot retro-deny an executed call; their semantics "
            "need a separate review)." % (rule_id, on))
    if on not in _V1_TRIGGERS:
        raise DslCompileError(
            "DSL rule %r: unknown trigger %r (v1 supports: %s)."
            % (rule_id, on, sorted(_V1_TRIGGERS)))
    match = {}
    if "tool" in trigger:
        match["tool"] = trigger["tool"]

    # --- predicate (policy match keys, 1:1) ---
    predicate = block.get("predicate") or {}
    predicate = _coerce_mapping(predicate, "predicate", rule_id)
    if "tool" in predicate:
        raise DslCompileError(
            "DSL rule %r: predicate must not set 'tool' — put it in the "
            "trigger." % rule_id)
    for key in predicate:
        if key not in KNOWN_MATCH_KEYS:
            raise DslCompileError(
                "DSL rule %r: unknown predicate key %r (known policy "
                "match keys: %s)." % (rule_id, key,
                                      sorted(KNOWN_MATCH_KEYS)))
    match.update(predicate)

    # --- enforcement (v1: allow/deny/require_approval) ---
    enforcement = block.get("enforcement")
    if enforcement in _V2_ENFORCEMENTS:
        raise DslCompileError(
            "DSL rule %r: enforcement %r is DEFERRED to v2 (it needs a new "
            "engine effect touching the DLP/preview invariants F11/F12)."
            % (rule_id, enforcement))
    if enforcement not in _V1_ENFORCEMENTS:
        raise DslCompileError(
            "DSL rule %r: unknown enforcement %r (v1 supports: %s)."
            % (rule_id, enforcement, sorted(_V1_ENFORCEMENTS)))

    rule = {
        "id": rule_id,
        "effect": enforcement,
        "match": match,
        "reason": block.get("reason") or (
            "DSL rule %r: %s on tool_call (promoted from the AgentSpec "
            "DSL; not model-generated)." % (rule_id, enforcement)),
        # Provenance marker: this rule came from the DSL, not the policy
        # file. ``dsl_rule`` is allowlisted in ``gov.policy.KNOWN_RULE_FIELDS``
        # (F90) so the engine's validation accepts it; ``dsl_source_hash`` is stamped by
        # ``apply_dsl`` after validation and is likewise allowlisted.
        "dsl_rule": True,
    }
    if block.get("description"):
        rule["description"] = block["description"]
    if block.get("flag"):
        rule["flag"] = block["flag"]
    return rule


def compile_dsl(source, source_name="<dsl>"):
    """Compile a DSL source to ordinary policy rule dicts.

    ``source`` is YAML text (str/bytes) holding a list of rule blocks,
    or an already-parsed list of blocks. Returns the compiled rules
    WITHOUT the source-hash stamp (see ``apply_dsl``). Raises
    DslCompileError on any malformed block — fail closed at load.
    """
    if isinstance(source, (str, bytes)):
        text = (source.decode("utf-8") if isinstance(source, bytes)
                else source)
        try:
            blocks = parse_yaml(text)
        except Exception as e:
            raise DslCompileError(
                "DSL source %s: YAML parse failed: %s" % (source_name, e))
    else:
        blocks = source
    if not isinstance(blocks, list):
        raise DslCompileError(
            "DSL source %s: top level must be a list of rule blocks, got "
            "%r." % (source_name,
                     type(blocks).__name__))
    rules = []
    seen = set()
    for i, block in enumerate(blocks):
        rule = _compile_block(block, i)
        if rule["id"] in seen:
            raise DslCompileError(
                "DSL source %s: duplicate rule id %r (ids must be unique "
                "for audit traceability)." % (source_name, rule["id"]))
        seen.add(rule["id"])
        rules.append(rule)
    return rules


def apply_dsl(policy, source, source_name="<dsl>"):
    """Promote a DSL source into the enforced set of ``policy``.

    This is the HUMAN SIGN-OFF point: calling it is the explicit act
    that promotes (possibly generated) rules into enforcement — nothing
    in the runtime calls it automatically.

    Steps: hash the source bytes; check the GOV_DSL_HASH pin (mismatch
    -> DslPinMismatchError, before anything is promoted); compile;
    validate every rule with ``PolicyEngine._validate_rule``; refuse on
    id collision with existing policy rules; append the compiled rules
    to ``policy.policies``; record ``policy.dsl_source_hash`` /
    ``policy.dsl_pinned`` / ``policy.dsl_rule_ids``. Returns the
    compiled rule list. ``policy.policy_hash`` is untouched.
    """
    if isinstance(source, (str, bytes)):
        source_bytes = (source.encode("utf-8") if isinstance(source, str)
                        else bytes(source))
    else:
        # Already-parsed blocks: hash their canonical re-encoding. The
        # pin then covers the parsed structure, not the original text —
        # callers pinning generated sources should pass the raw text.
        import json as _json
        source_bytes = _json.dumps(
            source, sort_keys=True, default=str).encode("utf-8")
    digest = dsl_source_hash(source_bytes)
    pin = os.environ.get("GOV_DSL_HASH")
    if pin and pin != digest:
        raise DslPinMismatchError(
            "DSL pin mismatch: source %s has sha256 %s but GOV_DSL_HASH "
            "pins %s — refusing to promote the DSL fail-closed."
            % (source_name, digest, pin))
    rules = compile_dsl(source, source_name=source_name)
    existing_ids = {r.get("id") for r in
                    getattr(policy, "policies", [])}
    for i, rule in enumerate(rules):
        if rule["id"] in existing_ids:
            raise DslCompileError(
                "DSL source %s: rule id %r collides with an existing "
                "policy rule id; refusing to promote."
                % (source_name, rule["id"]))
        # The compiled rules ARE ordinary policy rules: run the same
        # validation the engine runs at policy load.
        PolicyEngine._validate_rule(policy, rule, i)
        rule["dsl_source_hash"] = digest
    policy.policies.extend(rules)
    policy.dsl_source_hash = digest
    policy.dsl_pinned = bool(pin) and pin == digest
    policy.dsl_rule_ids = tuple(r["id"] for r in rules)
    return rules
