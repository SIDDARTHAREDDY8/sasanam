"""MCP invocation-authorization hardenings (COAZ-MCP ADAPT, idea only).

Natively reimplements the *ideas* from the COAZ-MCP binding draft (an
individual IETF draft, not adopted; no upstream source vendored, no
conformance claimed -- the prospectus only records the mechanisms as
steal-worthy). Three hardenings for the PEP that sits between an
authorization decision and the actual MCP tool invocation:

1. **TOCTOU guard (permit-message binding).** :func:`authorize` binds
   the issued permit to the exact authorized message via
   ``sha256`` of canonical JSON. :func:`apply_permit` re-verifies the
   presented message is byte-identical (in canonical form) before the
   permit may be applied. Any mutation of the JSON-RPC payload between
   authorization and execution -- params, method, tool name, id --
   fails closed with ``permit-message-mismatch``. The binding is
   checked at *apply* time, not only at authorize time, because that
   is where the time-of-check/time-of-use window lives.

2. **Trust-anchored subject.id (identity-smuggling close).** The
   subject identity is pinned at policy-build time (from the
   deployment's configured authority source). At authorization, the
   subject is taken ONLY from the top-level ``authz_context["subject"]
   ["id"]``; that value must equal the pinned anchor or the call is
   refused with ``subject-unanchored``. Any subject-shaped claim nested
   inside the message or elsewhere in the context (``params.subject``,
   ``metadata.actor``, ...) is *untrusted input*: it is recorded in
   the report for the auditor but never consulted as the subject. A
   nested claim that disagrees with the anchored identity is a
   smuggling attempt and refuses with ``subject-smuggling-attempt``.
   Everything else is untrusted input -- the draft's exact
   discipline.

3. **Server-advertised-mapping pin (tighten-only).** Server-advertised
   tool/mapping tables are policy-relevant input, so the deployment
   pins the canonical ``sha256`` digest of the advertised mapping
   out-of-band at policy build. At authorization the observed mapping
   (from the deployment's own discovery, not from the wire) is
   digested and compared: absent pin -> ``mapping-unpinned``; drift
   (server added a tool, changed a schema) -> ``mapping-drift``. Both
   fail closed. Mapping widening never auto-expands authority: the
   only way to authorize against a changed mapping is to re-pin
   (build a new policy). Re-pinning restores authorization.

Composition note: this module does NOT re-implement the operator
authority boundary -- ``gov.authority_proof.check()`` remains the
``server::tool`` allowlist and argument-budget gate. Use that first,
then this module for the three invocation-time hardenings above.

Error discipline: ``build_policy`` raises :class:`McpInvocationAuthzError`
on operator authoring errors (fail loud for the operator).
``authorize`` / ``apply_permit`` never raise on hostile inputs --
malformed shapes become ``refuse`` verdicts with a named code, never
an exception past the seam. Deterministic: sorted canonical JSON, no
clock, no I/O, no randomness.
"""

import hashlib
import json
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

FORMAT_PERMIT = "sasanam-mcp-invocation-permit/v1"

# Named refusal codes. Only "permit"/"apply" are passing verdicts.
MAPPING_UNPINNED = "mapping-unpinned"
MAPPING_DRIFT = "mapping-drift"
SUBJECT_UNANCHORED = "subject-unanchored"
SUBJECT_SMUGGLING = "subject-smuggling-attempt"
PERMIT_MESSAGE_MISMATCH = "permit-message-mismatch"
MALFORMED_MESSAGE = "malformed-message"
MALFORMED_CONTEXT = "malformed-context"
MALFORMED_PERMIT = "malformed-permit"

_DIGEST_PREFIX = "sha256:"
_MAX_SCAN_DEPTH = 16

# Keys that carry identity claims when nested anywhere below the
# top-level subject. The scan is name-based and bounded; being listed
# here never makes a nested claim trusted -- it makes it *noticed*.
_NESTED_IDENTITY_KEYS = ("subject", "subject_id", "user_id",
                         "principal", "actor")


class McpInvocationAuthzError(Exception):
    """Operator authoring error at policy build (or a malformed
    non-mapping input where a mapping is structurally required)."""


def _is_digest_shape(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    tail = value[len(_DIGEST_PREFIX):]
    return len(tail) == 64 and all(c in "0123456789abcdef" for c in tail)


def canonical_digest(obj: Any) -> str:
    """Canonical ``sha256:`` + 64-hex digest of canonical JSON.

    ``json.dumps`` with sorted keys, compact separators, and
    ``ensure_ascii=True`` (UTF-8 of ASCII output) gives a byte-stable
    form. Raises :class:`McpInvocationAuthzError` on
    non-JSON-serializable input -- the caller decides whether that is
    a build error or a runtime refusal.
    """
    try:
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True)
    except (TypeError, ValueError) as e:
        raise McpInvocationAuthzError(
            "not JSON-canonicalizable: %s" % (e,))
    return _DIGEST_PREFIX + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class McpInvocationPolicy(NamedTuple):
    """A compiled invocation-authorization policy.

    ``subject_id``: the trust-anchored identity every authorized call
    must act as. ``pinned_mapping_digest``: the out-of-band-pinned
    digest of the server-advertised mapping, or ``None`` for an
    explicitly unpinned deployment (which refuses every call with
    ``mapping-unpinned`` until re-pinned).
    """
    subject_id: str
    pinned_mapping_digest: Optional[str]


def build_policy(spec: Mapping[str, Any]) -> McpInvocationPolicy:
    """Compile an invocation-authorization policy, validating authoring
    errors once at build. Unknown keys, empty/non-string subject ids,
    and malformed digest pins raise :class:`McpInvocationAuthzError`.
    """
    if not isinstance(spec, Mapping):
        raise McpInvocationAuthzError(
            "policy spec must be a mapping, got %r" % (type(spec).__name__,))
    allowed = {"subject_id", "pinned_mapping_digest"}
    unknown = sorted(k for k in spec.keys() if k not in allowed)
    if unknown:
        raise McpInvocationAuthzError(
            "unknown policy keys: %s" % (", ".join(unknown),))
    if "subject_id" not in spec:
        raise McpInvocationAuthzError("policy spec requires 'subject_id'")
    subject_id = spec["subject_id"]
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise McpInvocationAuthzError(
            "subject_id must be a non-empty string")
    pin = spec.get("pinned_mapping_digest")
    if pin is not None and not _is_digest_shape(pin):
        raise McpInvocationAuthzError(
            "pinned_mapping_digest must be None or a %s+64-hex digest"
            % (_DIGEST_PREFIX,))
    return McpInvocationPolicy(subject_id=subject_id,
                               pinned_mapping_digest=pin)


class McpAuthzResult(NamedTuple):
    """Result of :func:`authorize` / :func:`apply_permit`.

    ``verdict`` is ``"permit"`` / ``"refuse"`` for ``authorize`` and
    ``"apply"`` / ``"refuse"`` for ``apply_permit``. ``permit`` is the
    permit dict on a permit verdict, else ``None``. ``report`` is the
    audit-visible detail for both verdicts.
    """
    verdict: str
    code: str
    report: Dict[str, Any]
    permit: Optional[Dict[str, Any]]


def _refuse(code: str, report: Dict[str, Any]) -> McpAuthzResult:
    return McpAuthzResult(verdict="refuse", code=code, report=report,
                          permit=None)


def _scan_nested_identity_claims(obj: Any, path: str = "$",
                                depth: int = 0,
                                _seen: Optional[set] = None
                                ) -> List[Tuple[str, Any]]:
    """Bounded scan for subject-shaped keys below the top level.

    Returns (json-path, value) pairs. Never raises on hostile shapes:
    depth is capped and object identity is tracked so a
    self-referential (non-JSON) dict cannot recurse forever.
    """
    if _seen is None:
        _seen = set()
    found: List[Tuple[str, Any]] = []
    if depth > _MAX_SCAN_DEPTH:
        return found
    if isinstance(obj, Mapping):
        if id(obj) in _seen:
            return found
        _seen.add(id(obj))
        for key, value in obj.items():
            child = "%s.%s" % (path, key)
            if isinstance(key, str) and key in _NESTED_IDENTITY_KEYS:
                found.append((child, value))
            found.extend(_scan_nested_identity_claims(value, child,
                                                     depth + 1, _seen))
    elif isinstance(obj, (list, tuple)):
        if id(obj) in _seen:
            return found
        _seen.add(id(obj))
        for i, value in enumerate(obj):
            found.extend(_scan_nested_identity_claims(value, "%s[%d]"
                                                      % (path, i),
                                                      depth + 1, _seen))
    return found


def _extract_top_subject(authz_context: Mapping[str, Any]) -> Tuple[Optional[str], str]:
    """Extract ONLY the top-level subject id.

    Returns (subject_id, problem): subject_id is None when the shape
    is unusable; problem names the shape issue for the audit trail.
    """
    subject = authz_context.get("subject")
    if not isinstance(subject, Mapping):
        return None, "top-level 'subject' is not a mapping"
    sid = subject.get("id")
    if not isinstance(sid, str) or not sid.strip():
        return None, "top-level 'subject.id' is not a non-empty string"
    return sid, ""


def authorize(policy: McpInvocationPolicy, message: Mapping[str, Any],
              authz_context: Mapping[str, Any]) -> McpAuthzResult:
    """Authorize one MCP message; never raises on hostile input.

    ``message`` is the JSON-RPC request dict that will be executed
    (``method``, ``params``, ``id``). ``authz_context`` carries the
    top-level ``subject`` and the deployment-observed
    ``server_mapping``. On permit, the returned permit binds
    subject_id + mapping digest + message digest; present it with the
    (unchanged) message to :func:`apply_permit` at execution time.
    """
    if not isinstance(policy, McpInvocationPolicy):
        return _refuse(MALFORMED_CONTEXT, {
            "reason": "policy is not a McpInvocationPolicy"})
    if not isinstance(message, Mapping):
        return _refuse(MALFORMED_MESSAGE, {
            "reason": "message is not a mapping"})
    if not isinstance(authz_context, Mapping):
        return _refuse(MALFORMED_CONTEXT, {
            "reason": "authz_context is not a mapping"})
    method = message.get("method")
    if not isinstance(method, str) or not method.strip():
        return _refuse(MALFORMED_MESSAGE, {
            "reason": "message.method is not a non-empty string"})

    # 1. Mapping pin: the observed mapping must digest to the pin.
    mapping = authz_context.get("server_mapping")
    if not isinstance(mapping, Mapping):
        return _refuse(MALFORMED_CONTEXT, {
            "reason": "authz_context.server_mapping is not a mapping"})
    if policy.pinned_mapping_digest is None:
        return _refuse(MAPPING_UNPINNED, {
            "reason": "no mapping digest pinned: re-pin out-of-band "
                      "before authorizing any call"})
    try:
        mapping_digest = canonical_digest(mapping)
    except McpInvocationAuthzError as e:
        return _refuse(MALFORMED_CONTEXT, {
            "reason": "server_mapping not canonicalizable: %s" % (e,)})
    if mapping_digest != policy.pinned_mapping_digest:
        return _refuse(MAPPING_DRIFT, {
            "reason": "server-advertised mapping drifted from the pin; "
                      "re-pin before authorizing",
            "observed": mapping_digest,
            "pinned": policy.pinned_mapping_digest})

    # 2. Trust-anchored subject: top-level subject only.
    subject_id, problem = _extract_top_subject(authz_context)
    if subject_id is None:
        return _refuse(SUBJECT_UNANCHORED, {"reason": problem})
    if subject_id != policy.subject_id:
        return _refuse(SUBJECT_UNANCHORED, {
            "reason": "subject.id %r is not the anchored %r"
                      % (subject_id, policy.subject_id)})

    # 3. Nested identity claims are untrusted input, never the subject.
    nested = ([(p, v) for p, v in
               _scan_nested_identity_claims(message, "$.message")]
              + [(p, v) for p, v in
                 _scan_nested_identity_claims(authz_context,
                                             "$.authz_context")
                 if not p.startswith("$.authz_context.subject")])
    untrusted_paths = [p for p, _ in nested]
    for path, value in nested:
        claimed = value.get("id") if isinstance(value, Mapping) else value
        if isinstance(claimed, str) and claimed and claimed != subject_id:
            return _refuse(SUBJECT_SMUGGLING, {
                "reason": "nested identity claim %s (%r) disagrees with "
                          "the anchored subject.id %r"
                          % (path, claimed, subject_id),
                "untrusted_subject_claims": untrusted_paths})

    # 4. Bind the permit to the exact message (TOCTOU guard anchor).
    try:
        message_digest = canonical_digest(message)
    except McpInvocationAuthzError as e:
        return _refuse(MALFORMED_MESSAGE, {
            "reason": "message not canonicalizable: %s" % (e,)})
    tool = None
    params = message.get("params")
    if isinstance(params, Mapping):
        name = params.get("name")
        if isinstance(name, str):
            tool = name
    permit = {
        "format": FORMAT_PERMIT,
        "subject_id": subject_id,
        "mapping_digest": mapping_digest,
        "message_digest": message_digest,
        "method": method,
        "tool": tool,
        "message_id": message.get("id"),
        "untrusted_subject_claims": untrusted_paths,
    }
    return McpAuthzResult(
        verdict="permit", code="permit",
        report={"reason": "authorized: anchored subject, pinned mapping, "
                          "message bound",
                "subject_id": subject_id,
                "mapping_digest": mapping_digest,
                "message_digest": message_digest,
                "method": method,
                "tool": tool,
                "untrusted_subject_claims": untrusted_paths},
        permit=permit)


def apply_permit(permit: Mapping[str, Any], message: Mapping[str, Any],
                 authz_context: Optional[Mapping[str, Any]] = None
                 ) -> McpAuthzResult:
    """Re-verify the permit against the message presented at execution.

    The PEP MUST call this on the message it is about to send: the
    message digest is recomputed and must equal the digest bound at
    authorize time. Any mutation (params, method, tool name, id)
    refuses ``permit-message-mismatch``. When ``authz_context`` is
    supplied, the top-level subject is re-anchored against the
    permit. Never raises on hostile input.
    """
    if not isinstance(permit, Mapping) or \
            permit.get("format") != FORMAT_PERMIT:
        return McpAuthzResult(verdict="refuse", code=MALFORMED_PERMIT,
                              report={"reason": "not a valid invocation "
                                                "permit"},
                              permit=None)
    if not isinstance(message, Mapping):
        return McpAuthzResult(verdict="refuse", code=MALFORMED_MESSAGE,
                              report={"reason": "message is not a mapping"},
                              permit=None)
    try:
        now_digest = canonical_digest(message)
    except McpInvocationAuthzError as e:
        return McpAuthzResult(verdict="refuse", code=MALFORMED_MESSAGE,
                              report={"reason": "message not "
                                                "canonicalizable: %s" % (e,)},
                              permit=None)
    if now_digest != permit.get("message_digest"):
        return McpAuthzResult(
            verdict="refuse", code=PERMIT_MESSAGE_MISMATCH,
            report={"reason": "message changed after authorization: "
                              "permit is bound to digest %s, presented "
                              "message digests to %s"
                              % (permit.get("message_digest"), now_digest)},
            permit=None)
    if authz_context is not None:
        if not isinstance(authz_context, Mapping):
            return McpAuthzResult(verdict="refuse", code=MALFORMED_CONTEXT,
                                  report={"reason": "authz_context is not "
                                                    "a mapping"},
                                  permit=None)
        subject_id, problem = _extract_top_subject(authz_context)
        if subject_id is None or subject_id != permit.get("subject_id"):
            return McpAuthzResult(verdict="refuse", code=SUBJECT_UNANCHORED,
                                  report={"reason":
                                          problem or
                                          "subject.id changed after "
                                          "authorization"},
                                  permit=None)
    return McpAuthzResult(
        verdict="apply", code="apply",
        report={"reason": "permit applies: message unchanged since "
                          "authorization",
                "subject_id": permit.get("subject_id"),
                "method": permit.get("method"),
                "tool": permit.get("tool")},
        permit=None)


__all__ = [
    "McpInvocationAuthzError",
    "McpInvocationPolicy",
    "McpAuthzResult",
    "build_policy",
    "canonical_digest",
    "authorize",
    "apply_permit",
    "FORMAT_PERMIT",
    "MAPPING_UNPINNED",
    "MAPPING_DRIFT",
    "SUBJECT_UNANCHORED",
    "SUBJECT_SMUGGLING",
    "PERMIT_MESSAGE_MISMATCH",
    "MALFORMED_MESSAGE",
    "MALFORMED_CONTEXT",
    "MALFORMED_PERMIT",
]
