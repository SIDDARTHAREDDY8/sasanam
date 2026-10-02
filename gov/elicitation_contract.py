"""Tri-state approval elicitation contract (wave-278 lane 5).

ADAPT of the MCP ``elicitation/create`` interaction contract (spec
revision 2026-07-28 RC) -- the MECHANISM only. Adapted properties:

* tri-state response: accept / decline / cancel;
* rationale schema restricted to flat JSON primitives
  (string/number/boolean/enum -- no nested objects or arrays);
* the server MUST NOT request secrets over the elicitation channel,
  and credential-shaped material in a rationale fails closed;
* the elicitation shows the requester identity (derived from the
  stored approval record, never caller-supplied);
* the decider may decline/cancel at any time;
* re-prompts are rate-limited by a per-approval budget.

No MCP code is reused and no MCP wire format is implemented; this is
a clean-room adaptation of the interaction contract to the human
approval queue ("No trust in agent framing": the action summary shown
to the decider is the executor-generated preview, never agent prose).

License/provenance note (prospectus trap): the MCP specification
transitioned from MIT to Apache-2.0 (spec docs under CC-BY-4.0).
Adapting the mechanism without copying MCP text, schema, or code
keeps this module free of license entanglement -- there is nothing
here derived from the MCP sources.

Public API used by ``ApprovalQueue.elicit_decision`` (gov/approvals.py)
and by the break-first battery ``evals/w278_approvalv2_probes.py``:

* ``MAX_ELICITATIONS`` -- re-prompt budget per approval (3).
* ``ELICITATION_RESPONSES`` -- ("accept", "decline", "cancel").
* ``DEFAULT_RATIONALE_SCHEMA`` -- minimal flat schema used when the
  caller supplies none.
* ``ElicitationRequest`` -- frozen dataclass; the elicitation shown
  to the decider.
* ``build_elicitation_request(record, rationale_schema=None)`` --
  build the request FROM THE RECORD (identity + preview).
* ``validate_flat_schema(schema)`` -- reject nested schemas at build.
* ``validate_rationale(rationale, schema)`` -- flat-primitive check.
* ``credential_material_present(text)`` -- conservative
  credential-shape detector for rationale / free text.
* ``render_rationale(response, rationale)`` -- deterministic reason
  string chained into the audit log via decide().
* ``ElicitationError`` -- ValueError subclass for every refusal.
"""

import json
import re
import uuid
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

#: Re-prompt budget: at most this many well-formed elicitations per
#: approval. Failed-validation attempts (bad rationale) and malformed
#: requests do not burn the budget; only well-formed elicitations do.
MAX_ELICITATIONS = 3

#: The tri-state response vocabulary. Anything else is refused.
ELICITATION_RESPONSES = ("accept", "decline", "cancel")

#: Flat primitive types allowed in a rationale schema.
_FLAT_TYPES = ("string", "number", "boolean")

#: Minimal flat rationale schema used when the caller supplies none.
#: A decline always carries at least a free-text reason; accept/cancel
#: may ride without one.
DEFAULT_RATIONALE_SCHEMA = {
    "type": "object",
    "properties": {
        "reason": {"type": "string"},
        "category": {"enum": ["safety", "policy", "incorrect-target",
                             "insufficient-context", "other"]},
    },
    "required": ["reason"],
}

#: Reason recorded when an accept carries no rationale. Must be
#: non-empty and must not trip the ceremony-integrity contradiction
#: patterns (gov/ceremony_integrity.py): it neither denies an approval
#: nor approves a denial.
DEFAULT_ACCEPT_REASON = (
    "elicitation accept: operator accepted the executor-generated "
    "action summary with no additional rationale"
)


class ElicitationError(ValueError):
    """Every elicitation refusal raises this (a ValueError).

    ``remediation`` optionally carries the deterministic remediation
    outcome (``gov/remediation.py`` -- wave-279 lane 6) attached by the
    refusal seam: ``{failure_class, action, retry_permitted, ...}``.
    It is None when the error was raised outside a classified seam
    (e.g. contract-level validation). Additive only: every existing
    ``ElicitationError(message)`` call site keeps working unchanged.
    """

    def __init__(self, message, remediation=None):
        super(ElicitationError, self).__init__(message)
        self.remediation = remediation


# ---------------------------------------------------------------------------
# Request object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ElicitationRequest(object):
    """The elicitation shown to the decider.

    ``requester_identity`` is ``{"agent_id": ..., "role": ...}`` taken
    FROM THE STORED RECORD -- it is never caller-supplied, so a
    confused deputy cannot relabel who is asking. ``action_summary``
    is the executor-generated preview (sanitized), never agent
    framing. Instances are immutable (frozen dataclass).
    """

    request_id: str
    approval_id: str
    requester_identity: dict
    action_summary: str
    rationale_schema: dict
    reprompts_remaining: int

    def __post_init__(self):
        # Defensive copies: the request must not alias caller-owned
        # (or record-owned) mutable dicts.
        object.__setattr__(self, "requester_identity",
                           dict(self.requester_identity))
        object.__setattr__(self, "rationale_schema",
                           json.loads(json.dumps(self.rationale_schema)))
        object.__setattr__(self, "reprompts_remaining",
                           int(self.reprompts_remaining))

    def as_dict(self):
        return {
            "request_id": self.request_id,
            "approval_id": self.approval_id,
            "requester_identity": dict(self.requester_identity),
            "action_summary": self.action_summary,
            "rationale_schema": json.loads(
                json.dumps(self.rationale_schema)),
            "reprompts_remaining": self.reprompts_remaining,
        }


def new_request_id():
    """Fresh elicitation request id (uuid4 hex)."""
    return "elic-%s" % uuid.uuid4().hex


def reprompts_remaining(record):
    """Budget left on a stored record (never negative)."""
    try:
        used = int(record.get("elicitation_attempts") or 0)
    except (TypeError, ValueError):
        used = 0
    return max(0, MAX_ELICITATIONS - used)


def build_elicitation_request(record, rationale_schema=None):
    """Build the elicitation request FROM THE STORED RECORD.

    Identity (agent_id/role) and the action summary (executor-generated
    preview, sanitized) come from the record alone -- the caller
    supplies no identity and no summary, so neither can be spoofed at
    the elicitation seam. The rationale schema is validated flat at
    build time (ElicitationError on nesting).
    """
    # Lazy import: gov.approvals imports this module lazily inside
    # ApprovalQueue.elicit_decision, so a top-level import here would
    # cycle.
    from gov.approvals import sanitize_preview_text
    if not isinstance(record, dict):
        raise ElicitationError("elicitation request needs a record dict")
    schema = validate_flat_schema(
        rationale_schema
        if rationale_schema is not None else DEFAULT_RATIONALE_SCHEMA)
    identity = {
        "agent_id": record.get("agent_id"),
        "role": record.get("role"),
    }
    summary = sanitize_preview_text(record.get("preview") or "")
    return ElicitationRequest(
        request_id=new_request_id(),
        approval_id=record.get("id"),
        requester_identity=identity,
        action_summary=summary,
        rationale_schema=schema,
        reprompts_remaining=reprompts_remaining(record),
    )


# ---------------------------------------------------------------------------
# Flat rationale schema
# ---------------------------------------------------------------------------

def _is_flat_primitive(value):
    # bool is an int subclass; isinstance covers it either way.
    return isinstance(value, (str, int, float))


def validate_flat_schema(schema):
    """Validate a rationale schema is flat-primitive-only.

    Accepted shape::

        {"type": "object",
         "properties": {"name": {"type": "string"|"number"|"boolean"}
                        | {"enum": [<flat primitives>]}, ...},
         "required": ["name", ...]}            # optional

    Nested objects/arrays (``"type": "object"`` / ``"type": "array"``,
    ``"properties"`` / ``"items"`` inside a property spec) are
    rejected at build time -- ElicitationError. Returns a normalized
    deep copy of the schema.
    """
    if not isinstance(schema, dict):
        raise ElicitationError(
            "rationale schema must be a dict, got %s"
            % type(schema).__name__)
    if schema.get("type", "object") != "object":
        raise ElicitationError(
            "rationale schema must be an object schema")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        raise ElicitationError(
            "rationale schema needs a non-empty 'properties' map")
    normalized = {"type": "object", "properties": {}}
    for name, spec in properties.items():
        if not isinstance(name, str) or not name:
            raise ElicitationError(
                "rationale schema property names must be non-empty "
                "strings")
        if not isinstance(spec, dict):
            raise ElicitationError(
                "rationale schema property %r: spec must be a dict"
                % (name,))
        # Nesting is forbidden anywhere inside a property spec.
        for nested_key in ("properties", "items", "additionalProperties"):
            if nested_key in spec:
                raise ElicitationError(
                    "rationale schema property %r: nested schemas are "
                    "forbidden (%r)" % (name, nested_key))
        if "enum" in spec:
            values = spec["enum"]
            if (not isinstance(values, list) or not values
                    or not all(_is_flat_primitive(v) for v in values)):
                raise ElicitationError(
                    "rationale schema property %r: 'enum' must be a "
                    "non-empty list of flat primitives" % (name,))
            normalized["properties"][name] = {"enum": list(values)}
            if spec.get("type") in _FLAT_TYPES:
                # A declared flat type alongside the enum is kept for
                # documentation; the enum membership check governs.
                normalized["properties"][name]["type"] = spec["type"]
            continue
        ptype = spec.get("type")
        if ptype not in _FLAT_TYPES:
            raise ElicitationError(
                "rationale schema property %r: type must be one of "
                "%s or an 'enum' list (nested object/array forbidden)"
                % (name, "/".join(_FLAT_TYPES)))
        normalized["properties"][name] = {"type": ptype}
    required = schema.get("required", [])
    if required is None:
        required = []
    if (not isinstance(required, list)
            or any(r not in normalized["properties"] for r in required)):
        raise ElicitationError(
            "rationale schema 'required' must list declared property "
            "names")
    normalized["required"] = list(required)
    return normalized


def validate_rationale(rationale, schema):
    """Validate a rationale dict against a flat schema.

    * rationale must be a dict;
    * every ``required`` property must be present;
    * no undeclared properties (fail closed on schema drift);
    * every value must match its declared flat type / enum value.

    Raises ElicitationError listing every violation. An empty dict
    fails whenever the schema has required properties; callers that
    need a non-empty rationale (decline) additionally refuse ``{}``
    outright.
    """
    if not isinstance(rationale, dict):
        raise ElicitationError(
            "rationale must be a dict, got %s" % type(rationale).__name__)
    properties = schema["properties"]
    required = schema.get("required", [])
    violations = []
    for name in required:
        if name not in rationale:
            violations.append("missing required property %r" % (name,))
    for name, value in rationale.items():
        spec = properties.get(name)
        if spec is None:
            violations.append("undeclared property %r" % (name,))
            continue
        if "enum" in spec and not any(
                type(value) is type(choice) and value == choice
                for choice in spec["enum"]):
            violations.append(
                "property %r: %r is not one of %r"
                % (name, value, spec["enum"]))
            continue
        ptype = spec.get("type")
        if ptype == "string" and not isinstance(value, str):
            violations.append(
                "property %r: expected string, got %s"
                % (name, type(value).__name__))
        elif ptype == "number" and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))):
            violations.append(
                "property %r: expected number, got %s"
                % (name, type(value).__name__))
        elif ptype == "boolean" and not isinstance(value, bool):
            violations.append(
                "property %r: expected boolean, got %s"
                % (name, type(value).__name__))
    if violations:
        raise ElicitationError(
            "rationale failed schema validation: %s"
            % "; ".join(violations))


# ---------------------------------------------------------------------------
# Secret ban
# ---------------------------------------------------------------------------

#: Conservative credential shapes: an assignment-looking binding of a
#: credential-ish name, or a bearer token. Deliberately narrow -- the
#: goal is to catch pasted secrets (``api_key=...``, ``password: ...``,
#: ``Bearer <token>``), not ordinary prose containing the word
#: "secret". Never invent broader patterns here without a red-team
#: pass: false positives fail closed on legitimate declines.
_CREDENTIAL_PATTERNS = (
    re.compile(
        r"(?i)\b(api_key|apikey|secret|password|passwd|private_key|"
        r"privatekey|client_secret|access_token|auth_token|token)"
        r"\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{10,}"),
)


def credential_material_present(text):
    """True when *text* carries credential-shaped material.

    Scans rationale renderings and any elicitation free text. A hit
    fails the elicitation closed: the response is REFUSED, the record
    stays pending, and a LOUD ``elicitation_secret_detected`` audit
    event is appended with the decider bound -- the secret itself is
    NEVER echoed into the log.
    """
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    return any(p.search(text) for p in _CREDENTIAL_PATTERNS)


def render_rationale(response, rationale):
    """Deterministic reason string chaining the rationale into decide().

    ``ApprovalQueue.decide`` stores ``reason`` verbatim as
    ``decision_reason`` and on the ``approval_decision`` audit entry,
    so the rationale rides the existing audit seam unchanged. The
    rendering is canonical JSON (sorted keys) -- complete and stable.
    """
    if rationale is None:
        return DEFAULT_ACCEPT_REASON
    return "elicitation %s -- rationale: %s" % (
        response,
        json.dumps(rationale, sort_keys=True, ensure_ascii=True,
                   default=str),
    )
