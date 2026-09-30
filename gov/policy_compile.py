"""Compile-policy-once front gate for the policy stack.

STEAL (idea only, Apache-2.0, no upstream source vendored) from
sigstore/policy-controller (read 2026-09-29, wave-216 prospecting):
the **compile-policy-once** discipline -- AUTHORING ERRORS fail at
compile time, and one compiled verifier serves many artifacts. Two
concrete rules:

1. ``compile_policy(spec)`` validates the WHOLE policy ONCE and
   returns a compiled verifier object. Unknown keys, empty
   combinators, malformed predicates, and unresolvable references
   all raise at compile. Evaluation against many artifacts/claims
   uses the compiled form with zero re-parsing.
2. Evaluation can never raise an authoring-error class. This is
   true BY CONSTRUCTION: the compiled objects' evaluation paths
   contain no authoring validation at all -- they operate only on
   the pre-validated, normalized form. Garbage *data* at evaluation
   time is still refused loudly (a ``ValueError``), but it is a data
   error, never an authoring error.

Coverage: ``gov.identity_policy`` (wave-215, per-certificate
identity-policy DSL) and ``gov.artifact_rules`` (wave-212, in-toto
style CREATE/MODIFY/DELETE/REQUIRE/MATCH/DISALLOW). ``identity_policy``
already parses at load time; ``artifact_rules`` re-ran ``load_rules``
on every ``verify_artifacts`` call -- this module closes that gap via
``gov.artifact_rules._evaluate`` (extracted, behavior-identical; see
that module's docstring).

The compile step is a FRONT GATE, never a re-interpretation: a
compiled ruleset's report is byte-identical to the legacy
``verify_artifacts`` report on the same inputs (pinned by battery),
and a compiled identity policy delegates to the same ``verify()``.

``fingerprint()`` gives the deployment a stable sha256 pin over the
compiled form (canonical rules / canonical policy description), so
an operator can assert "the exact policy I audited" before serving
traffic.

Wave-219 extends compile-once to the remaining policy types:
``gov.quorum_policy`` step quorums (``compile_quorum_step`` ->
``CompiledQuorumStep``), ``gov.arap`` authorization-relevant context
(``compile_arap_context`` -> ``CompiledArapContext``), and
``gov.jail_policy`` jail policies (``compile_jail_policy`` ->
``CompiledJailPolicy``). Compile failures carry machine-readable
``FieldError`` diagnostics (path/expected/got) inside
``PolicyCompilationError`` (code ``policy-compile-refused``), auditable
via the optional ``audit=`` callback; evaluation-time data failures
use the modules' own refusal codes and are disjoint from the compile
code.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import hashlib
import json
import posixpath

from gov import arap as _arap
from gov import artifact_rules as _ar
from gov import identity_policy as _ip
from gov import jail_policy as _jp
from gov import quorum_policy as _qp

__all__ = [
    "CompiledArtifactRuleset",
    "CompiledArapContext",
    "CompiledIdentityPolicy",
    "CompiledJailPolicy",
    "CompiledPolicy",
    "CompiledQuorumStep",
    "FieldError",
    "PolicyCompilationError",
    "compile_arap_context",
    "compile_jail_policy",
    "compile_policy",
    "compile_quorum_step",
]

def _digest_canonical(obj):
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _freeze_policy(policy):
    """Canonical snapshot of a policy's live object graph.

    Wave-219: the wave-217 residual -- a compiled policy keeps a
    reference to the LIVE policy object, so post-compile attribute
    mutation (``policy.issuer = "evil"``) silently rewires evaluation.
    The snapshot is taken at compile time and re-taken at every
    evaluation; any drift is refused fail-closed with
    ``gov.policy_compile.post_compile_mutation_refused``.

    Only plain-data shapes freeze (Policy instances, dicts with str
    keys, lists, tuples, and str/int/float/bool/None leaves). Anything
    else is a compile-time ``PolicyAuthoringError`` -- an unfreezable
    policy cannot be pinned, so it cannot compile.
    """
    if isinstance(policy, _ip.Policy):
        return ("Policy", type(policy).__name__,
                _freeze_policy(vars(policy)))
    if isinstance(policy, dict):
        items = []
        for key in sorted(policy.keys()):
            if not isinstance(key, str):
                raise _ip.PolicyAuthoringError(
                    "unfreezable policy attribute key %r" % (key,))
            items.append((key, _freeze_policy(policy[key])))
        return ("dict", tuple(items))
    if isinstance(policy, (list, tuple)):
        return ("seq", tuple(_freeze_policy(v) for v in policy))
    if policy is None or isinstance(policy, (str, int, float, bool)):
        return ("atom", policy)
    raise _ip.PolicyAuthoringError(
        "unfreezable policy attribute of type %s: compiled policies "
        "must be plain data" % (type(policy).__name__,))


class CompiledPolicy(object):
    """Base: a compiled policy. ``fingerprint()`` is the deployment
    pin; ``evaluate`` can never raise an authoring-error class."""

    def fingerprint(self):
        raise NotImplementedError

    def evaluate(self, *args, **kwargs):
        raise NotImplementedError


class CompiledIdentityPolicy(CompiledPolicy):
    """A compiled identity-policy DSL policy.

    ``spec`` is either a plain-data spec dict (exactly one predicate
    key -- see ``gov.identity_policy.parse_policy``) or an already
    constructed ``identity_policy.Policy`` (whose constructors refused
    every authoring error at build time). All authoring validation is
    DONE -- ``verify(claims)`` and ``admit(claims)`` evaluate only.
    """

    def __init__(self, policy):
        if not isinstance(policy, _ip.Policy):
            raise _ip.PolicyAuthoringError(
                "compiled identity policy requires an "
                "identity_policy.Policy instance")
        self._policy = policy
        # Wave-219: freeze the live object graph at compile time. The
        # residual was that post-compile attribute mutation silently
        # rewired evaluation; the frozen snapshot below is re-taken at
        # every verify/admit and drift is refused fail-closed.
        self._frozen = _freeze_policy(policy)

    def fingerprint(self):
        return _digest_canonical({"identity_policy": self._policy.describe()})

    def _check_unmutated(self):
        """Refuse fail-closed when the live policy drifted post-compile."""
        if _freeze_policy(self._policy) != self._frozen:
            from . import unsafe_paths as _up
            _up.emit(
                "gov.policy_compile.post_compile_mutation_refused",
                detail=("the live policy object was mutated after "
                        "compilation: evaluation refused rather than "
                        "judging against rewired rules"))
            raise _ip.PolicyViolation(
                "gov.policy_compile.post_compile_mutation_refused",
                "the live policy object was mutated after compilation; "
                "re-compile to change the rules")

    def verify(self, claims):
        """Evaluate identity claims. Returns a PolicyVerdict; never
        raises PolicyAuthoringError -- the policy was fully validated
        at compile."""
        self._check_unmutated()
        return self._policy.verify(claims)

    def admit(self, claims):
        """Fail-closed admission: report dict on pass, PolicyViolation
        on fail/error -- same contract as
        ``identity_policy.check_admission``."""
        verdict = self.verify(claims)
        if verdict.verdict == "pass":
            return {"verdict": "pass", "code": verdict.code,
                    "vacuous": verdict.vacuous,
                    "policy": self._policy.describe(),
                    "fingerprint": self.fingerprint()}
        raise _ip.PolicyViolation(verdict.code, verdict.detail)

    # The evaluation path has no spec/predicate parameter: there is no
    # way to smuggle an unvalidated policy shape through verify/admit.
    # ``policy`` is intentionally NOT exposed as a settable attribute.


class CompiledArtifactRuleset(CompiledPolicy):
    """A compiled artifact ruleset.

    ``rules`` are the normalized output of ``artifact_rules.load_rules``
    (or raw rule-spec tuples -- compiled once here). ``evaluate``
    takes ONLY artifact maps: there is no rule_specs parameter, so a
    caller cannot re-introduce unvalidated rule shapes at evaluation
    time. Evaluation is ``_evaluate`` -- the exact core
    ``verify_artifacts`` uses -- so reports are identical to legacy.
    """

    def __init__(self, rules):
        if isinstance(rules, (list, tuple)) and rules and \
                isinstance(rules[0], tuple):
            # Raw specs: validate once, here, at compile.
            self._rules = _ar.load_rules(rules)
        elif isinstance(rules, tuple) and all(
                isinstance(r, tuple) and r and r[0] in _ar._RULE_KINDS
                for r in rules):
            # Already-normalized output of load_rules: re-validating is
            # free and keeps the invariant total -- malformed input
            # that merely LOOKS normalized is still refused here.
            self._rules = _ar.load_rules(rules)
        else:
            raise _ar.ArtifactRuleError(
                "compiled ruleset requires rule-spec tuples")
        self._fingerprint = _digest_canonical(
            {"artifact_rules": [list(r) for r in self._rules]})

    def fingerprint(self):
        return self._fingerprint

    def evaluate(self, materials, products, context=""):
        """Evaluate artifact maps against the compiled ruleset. Raises
        ArtifactRuleError only on artifact DATA problems or rule
        violations -- never on a rule authoring problem (those were
        refused at compile).

        Wave-219: the compiled rule tuple is re-pinned at every
        evaluation -- post-compile reassignment of ``_rules`` is
        refused fail-closed with
        ``gov.policy_compile.post_compile_mutation_refused``.
        """
        if _digest_canonical(
                {"artifact_rules": [list(r) for r in self._rules]}) \
                != self._fingerprint:
            from . import unsafe_paths as _up
            _up.emit(
                "gov.policy_compile.post_compile_mutation_refused",
                detail=("the compiled artifact ruleset was mutated after "
                        "compilation: evaluation refused rather than "
                        "judging against rewired rules"))
            raise _ar.ArtifactRuleError(
                "gov.policy_compile.post_compile_mutation_refused: the "
                "compiled artifact ruleset was mutated after "
                "compilation; re-compile to change the rules")
        materials = _ar._check_artifact_map(materials, "materials")
        products = _ar._check_artifact_map(products, "products")
        return _ar._evaluate(materials, products, self._rules, context)


def compile_policy(spec):
    """Validate a policy ONCE and return a compiled verifier.

    Dispatch (all authoring errors raised HERE, never at evaluation):
    * plain-data dict with exactly one predicate key, or an
      ``identity_policy.Policy`` instance
      -> :class:`CompiledIdentityPolicy`
    * sequence of artifact rule-spec tuples (or normalized
      ``load_rules`` output)
      -> :class:`CompiledArtifactRuleset`
    * quorum step spec dict (keys: step_name, authorized_keyids,
      threshold) or ``quorum_policy.QuorumStep`` instance
      -> :class:`CompiledQuorumStep`
    * jail policy body dict (``format: sasanam-jail-policy/v1``)
      -> :class:`CompiledJailPolicy`
    * anything else -> ``PolicyAuthoringError``
    """
    if isinstance(spec, _ip.Policy):
        return CompiledIdentityPolicy(spec)
    if isinstance(spec, _qp.QuorumStep):
        # Already load-validated; wrap so evaluation cannot re-raise
        # authoring errors.
        return CompiledQuorumStep(spec)
    if isinstance(spec, dict) and not isinstance(spec, bool):
        if spec.get("format") == _jp.JAIL_POLICY_FORMAT:
            return compile_jail_policy(spec)
        if spec and set(spec) <= _QUORUM_SPEC_KEYS:
            return compile_quorum_step(spec)
        if len(spec) == 1:
            return CompiledIdentityPolicy(_ip.parse_policy(spec))
    if isinstance(spec, (list, tuple)) and spec:
        return CompiledArtifactRuleset(spec)
    raise _ip.PolicyAuthoringError(
        "compile_policy: unrecognized policy spec %r -- expected an "
        "identity-policy spec dict / Policy, a quorum step spec dict / "
        "QuorumStep, a jail policy body, or artifact rule tuples"
        % (type(spec).__name__,))


# ----------------------------------------------------------------------
# Wave-219: compile-everything-at-registration.
#
# STEAL (idea only, Apache-2.0, no upstream source vendored) from
# sigstore/policy-controller (wave-218 prospecting): named
# ``Compile -> Verifier`` API, a FieldError-style diagnostic taxonomy,
# and compile-everything-at-registration. This extends the wave-217
# compile-once discipline to the remaining policy types:
# ``gov.quorum_policy`` step quorums, ``gov.arap`` authorization-
# relevant context rules, and ``gov.jail_policy`` jail policies.
#
# The contract, for every type:
#   * the named ``compile_*`` gate validates the WHOLE policy ONCE
#     against the closed vocabulary and returns a compiled verifier;
#   * authoring failures raise ``PolicyCompilationError`` (code
#     ``policy-compile-refused``) carrying machine-readable
#     ``FieldError`` diagnostics, optionally audited at registration;
#   * evaluation on the compiled form can NEVER raise an authoring-
#     error class BY CONSTRUCTION: compiled objects take no
#     spec/policy/body parameter, and their evaluation paths contain
#     no authoring validation -- only data checks on untrusted
#     runtime inputs (records, requests, bindings), which fail closed
#     with codes distinct from the compile code;
#   * ``compile_policy`` dispatches quorum/jail shapes as well as the
#     wave-217 identity/ruleset shapes.
#
# Existing module loaders (``load_quorum_step``, ``validate_policy_body``,
# ``declare_context``) are untouched -- they remain the authoritative
# backstop and legacy behavior is byte-identical.
# ----------------------------------------------------------------------


class FieldError(object):
    """A machine-readable authoring diagnostic: path + expected + got.

    Shape ADAPTed from knative/pkg/apis FieldError (Apache-2.0) -- the
    *idea* of path-prefixed, expected-vs-got diagnostics with
    aggregation; reimplemented natively, no upstream prose copied.

    ``path`` is a dotted field path (``"authorized_keyids[2]"``,
    ``"resource_limits.cpu_s"``); ``expected`` states the closed-
    vocabulary requirement; ``got`` is the repr-safe supplied value;
    ``detail`` is an optional human note. ``to_dict()`` is
    JSON-serializable for audit events. ``via_field``/``via_index``
    prefix paths the way nested validators nest (a child validator's
    ``"writable_dirs[0]"`` becomes the parent's
    ``"policy.writable_dirs[0]"``).
    """

    def __init__(self, path, expected, got, detail=""):
        self.path = str(path)
        self.expected = str(expected)
        self.got = got if isinstance(got, str) else repr(got)
        if len(self.got) > 200:
            self.got = self.got[:197] + "..."
        self.detail = str(detail)

    def via_field(self, name):
        """Prefix this error's path with a parent field name."""
        return FieldError("%s.%s" % (name, self.path),
                          self.expected, self.got, self.detail)

    def via_index(self, index):
        """Prefix this error's path with a parent sequence index
        (applies to the first path segment)."""
        head, sep, tail = self.path.partition(".")
        return FieldError("%s[%d]%s%s" % (head, index, sep, tail),
                          self.expected, self.got, self.detail)

    def to_dict(self):
        return {"path": self.path, "expected": self.expected,
                "got": self.got, "detail": self.detail}

    def __str__(self):
        base = "%s: expected %s, got %s" % (self.path, self.expected,
                                           self.got)
        return base + (" (%s)" % self.detail if self.detail else "")

    def __repr__(self):
        return "FieldError(%r, %r, %r)" % (self.path, self.expected,
                                          self.got)


class PolicyCompilationError(_ip.PolicyAuthoringError):
    """Compile-time deployment error: a policy failed registration.

    Raised by the named ``compile_*`` gates when the spec violates the
    closed vocabulary. Carries ``errors`` (a tuple of ``FieldError``)
    and the auditable refusal code ``policy-compile-refused`` -- that
    code NEVER appears at evaluation time (evaluation refusals are data
    errors with the modules' own codes). Subclasses
    ``identity_policy.PolicyAuthoringError`` so existing
    ``except PolicyAuthoringError`` handlers keep catching compile
    refusals.
    """

    code = "policy-compile-refused"

    def __init__(self, policy_type, errors, audit=None):
        self.policy_type = policy_type
        self.errors = tuple(errors)
        if not self.errors:
            raise ValueError("PolicyCompilationError requires >= 1 error")
        super(PolicyCompilationError, self).__init__(
            "%s: %d authoring error(s) in %s policy: %s"
            % (self.code, len(self.errors), policy_type,
               "; ".join(str(e) for e in self.errors)))
        if audit is not None:
            audit({"event": "policy_compile_refused",
                   "policy_type": policy_type,
                   "code": self.code,
                   "errors": [e.to_dict() for e in self.errors]})


def _audit_compiled(audit, policy_type, fingerprint):
    if audit is not None:
        audit({"event": "policy_compiled", "policy_type": policy_type,
               "fingerprint": fingerprint})


_QUORUM_SPEC_KEYS = frozenset({"step_name", "authorized_keyids",
                               "threshold"})


def _quorum_field_errors(spec):
    """Field-level validation of a quorum step spec (mirrors
    ``quorum_policy.load_quorum_step``'s rules with FieldError
    diagnostics; the loader stays authoritative)."""
    errors = []
    if not isinstance(spec, dict):
        return [FieldError("spec", "a dict with keys step_name, "
                           "authorized_keyids, threshold",
                           type(spec).__name__)]
    for key in sorted(set(spec) - _QUORUM_SPEC_KEYS):
        errors.append(FieldError(
            "spec.%s" % key,
            "one of step_name, authorized_keyids, threshold", repr(key),
            "unknown policy field -- whole-update discipline refuses it"))
    name = spec.get("step_name")
    if not isinstance(name, str) or not name:
        errors.append(FieldError("step_name", "a non-empty string", name))
    kids = spec.get("authorized_keyids")
    roster_ok = False
    if not isinstance(kids, (list, tuple)) or not kids:
        errors.append(FieldError("authorized_keyids",
                                 "a non-empty list of keyids", kids))
    else:
        roster_ok = True
        for i, kid in enumerate(kids):
            if not isinstance(kid, str) or not kid:
                errors.append(FieldError(
                    "authorized_keyids[%d]" % i,
                    "a non-empty string keyid", kid))
                roster_ok = False
        if roster_ok and len(set(kids)) != len(kids):
            errors.append(FieldError("authorized_keyids", "distinct keyids",
                                     "duplicates present",
                                     "a duplicated keyid would double-count"))
    threshold = spec.get("threshold")
    roster_size = len(kids) if roster_ok else 0
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= max(roster_size, 1)):
        errors.append(FieldError(
            "threshold",
            "an int with 1 <= threshold <= len(authorized_keyids)",
            threshold,
            "threshold 0 would be a vacuous pass; a threshold above the "
            "roster can never be met (silent deny-by-misconfiguration)"))
    return errors


def _load_quorum_step_validated(spec):
    """Run the field-error pass, then the authoritative loader (which
    can only fail if the gate was weaker -- converted, fail-closed)."""
    errors = _quorum_field_errors(spec)
    if errors:
        raise PolicyCompilationError("quorum", errors)
    try:
        return _qp.load_quorum_step(spec)
    except _qp.QuorumPolicyError as exc:
        raise PolicyCompilationError(
            "quorum", [FieldError(
                "spec", "valid per the closed vocabulary",
                "loader refused: %s" % exc)]) from exc


class CompiledQuorumStep(CompiledPolicy):
    """A compiled step-quorum policy.

    ``step`` is a ``quorum_policy.QuorumStep`` (already load-validated)
    or a raw spec dict (validated here, at compile). ``verify`` takes
    ONLY runtime data -- link records + the pinned keyset -- so no
    authoring error can arise at evaluation by construction. Data
    refusals raise ``quorum_policy.QuorumPolicyError`` with the
    module's own evaluation codes (bad signature, quorum-not-met,
    ...), never the compile code.
    """

    def __init__(self, step):
        if isinstance(step, _qp.QuorumStep):
            self._step = step
        elif isinstance(step, dict):
            self._step = _load_quorum_step_validated(step)
        else:
            raise PolicyCompilationError(
                "quorum", [FieldError(
                    "spec", "a quorum spec dict or QuorumStep",
                    type(step).__name__)])

    @property
    def step(self):
        return self._step

    def fingerprint(self):
        return _digest_canonical(
            {"quorum_step": {
                "step_name": self._step.step_name,
                "authorized_keyids": list(self._step.authorized_keyids),
                "threshold": self._step.threshold}})

    def verify(self, link_records, keyset):
        """Verify a step quorum over AGREEING link records. Raises
        ``QuorumPolicyError`` on data problems only."""
        return _qp.verify_quorum(self._step, link_records, keyset)

    # No spec/policy parameter anywhere on the evaluation path.


def compile_quorum_step(spec, audit=None):
    """Compile-time front gate for a quorum step spec.

    Validates the WHOLE spec ONCE against the closed vocabulary;
    authoring failures raise ``PolicyCompilationError`` (audited when
    ``audit`` is supplied) -- never at evaluation. Returns a
    ``CompiledQuorumStep`` whose ``verify`` serves many record batches.
    """
    try:
        compiled = CompiledQuorumStep(spec)
    except PolicyCompilationError as exc:
        if audit is not None:
            audit({"event": "policy_compile_refused",
                   "policy_type": "quorum",
                   "code": exc.code,
                   "errors": [e.to_dict() for e in exc.errors]})
        raise
    _audit_compiled(audit, "quorum", compiled.fingerprint())
    return compiled


# ----------------------------------------------------------------------
# ARAP authorization-relevant context.
#
# KEY DISCIPLINE (pinned here; do not relax without filing a finding):
#   * the deployment key is deployment-owned, bytes, EXPLICIT MINIMUM
#     16 bytes (undersized keys are a COMPILE error, never an
#     evaluation surprise);
#   * context bindings are domain-separated under
#     "sasanam-arap-context/v1:" (gov.arap._BINDING_DOMAIN) -- the
#     HMAC covers domain || canonical(sorted name->digest map), so a
#     binding cannot be transplanted across domains;
#   * the compiled form stores ONLY sha256(key) (key_fingerprint) to
#     identify WHICH deployment key it was compiled for -- the key
#     itself never enters the object, the fingerprint pin, or any
#     audit event (custody stays with the deployment);
#   * ``fingerprint()`` covers the declared digests only -- two
#     compilations of the same context under different keys share the
#     same pin (the pin identifies the policy, not the key).
# ----------------------------------------------------------------------

_ARAP_MIN_KEY_BYTES = 16


def _arap_field_errors(context, key):
    errors = []
    if not isinstance(context, dict):
        errors.append(FieldError("context",
                                 "a dict of field name -> value",
                                 type(context).__name__))
    else:
        for name in context:
            if not isinstance(name, str) or not name:
                errors.append(FieldError(
                    "context.<field-name>",
                    "non-empty string field names", name))
    if not isinstance(key, (bytes, bytearray)):
        errors.append(FieldError(
            "key", "deployment key bytes of length >= 16",
            type(key).__name__,
            "KEY DISCIPLINE: keys are deployment-owned; non-bytes keys "
            "cannot feed HMAC"))
    elif len(key) < _ARAP_MIN_KEY_BYTES:
        errors.append(FieldError(
            "key", "key bytes of length >= %d (explicit minimum)"
            % _ARAP_MIN_KEY_BYTES, "%d bytes" % len(key),
            "KEY DISCIPLINE: undersized keys are a compile-time "
            "deployment error, never an evaluation surprise"))
    return errors


class CompiledArapContext(CompiledPolicy):
    """A compiled ARAP authorization-relevant context declaration.

    Constructed only via ``compile_arap_context`` (or this
    constructor, which runs the same gate). Holds the declared
    per-field digests and their HMAC binding -- NOT the key (see the
    KEY DISCIPLINE comment above). Evaluation methods take only
    runtime data; ``verify_binding`` takes the deployment key per call
    and refuses a key that does not match the compiled
    ``key_fingerprint`` as a DATA error (``context-key-mismatch``),
    never an authoring error.
    """

    def __init__(self, context, *, key):
        other = compile_arap_context(context, key=key)
        self._declared = other._declared
        self._binding = other._binding
        self._key_fingerprint = other._key_fingerprint

    @classmethod
    def _from_declaration(cls, declared, binding, key):
        obj = cls.__new__(cls)
        obj._declared = dict(declared)
        obj._binding = binding
        obj._key_fingerprint = hashlib.sha256(bytes(key)).hexdigest()
        return obj

    @property
    def declared(self):
        return dict(self._declared)

    @property
    def binding(self):
        return self._binding

    @property
    def key_fingerprint(self):
        """sha256 of the deployment key this context was compiled for
        -- identifies the key without holding it."""
        return self._key_fingerprint

    def fingerprint(self):
        # The pin identifies the POLICY, not the key: declared digests
        # only.
        return _digest_canonical({"arap_context": self._declared})

    def verify_binding(self, *, key):
        """Re-verify the declaration against its integrity binding with
        the deployment key. Wrong/undersized key at evaluation is a
        DATA error (``_arap.ArapError``), never an authoring error."""
        if not isinstance(key, (bytes, bytearray)) \
                or len(key) < _ARAP_MIN_KEY_BYTES \
                or hashlib.sha256(bytes(key)).hexdigest() \
                != self._key_fingerprint:
            raise _arap.ContextNotDeclaredError(
                "context-key-mismatch: presented key does not match the "
                "deployment key this context was compiled for",
                code="context-key-mismatch")
        return _arap.verify_context_binding(self._declared, self._binding,
                                            key=key)

    def check_cited(self, cited_fields):
        """Refuse approvals citing context outside the declared set."""
        return _arap.check_cited_context(cited_fields, self._declared)

    def scope(self):
        return _arap.binding_scope(self._declared)

    # No context/key-spec parameter anywhere on the evaluation path
    # beyond the per-call deployment key (runtime data, not policy).


def compile_arap_context(context, *, key, audit=None):
    """Compile-time front gate for an ARAP context declaration.

    Validates the WHOLE declaration ONCE (field names + the key
    discipline); authoring failures raise ``PolicyCompilationError``
    (audited when ``audit`` is supplied). Returns a
    ``CompiledArapContext`` -- one compiled declaration serves many
    approvals.
    """
    errors = _arap_field_errors(context, key)
    if errors:
        raise PolicyCompilationError("arap-context", errors, audit=audit)
    try:
        decl = _arap.declare_context(context, key=key)
    except (TypeError, ValueError) as exc:
        # Gate was weaker than the loader; fail closed with a coarse
        # diagnostic rather than leaking a bare loader error.
        raise PolicyCompilationError(
            "arap-context", [FieldError(
                "context", "valid per the closed vocabulary",
                "loader refused: %s" % exc)], audit=audit) from exc
    compiled = CompiledArapContext._from_declaration(
        decl["declared"], decl["binding"], key)
    _audit_compiled(audit, "arap-context", compiled.fingerprint())
    return compiled


# ----------------------------------------------------------------------
# Jail policies.
# ----------------------------------------------------------------------

_JAIL_LIMIT_BOUNDS = {
    # (lo, hi) per resource_limits key -- mirrors jail_policy.
    "cpu_s": (1, 3600),
    "mem_bytes": (1 << 20, 16 << 30),
    "max_file_bytes": (0, 16 << 30),
    "max_fds": (8, 4096),
    "max_procs": (1, 1024),
}


def _jail_field_errors(body):
    """Field-level validation of a jail policy body (mirrors
    ``jail_policy.validate_policy_body``'s rules with FieldError
    diagnostics; the loader stays authoritative)."""
    errors = []
    if not isinstance(body, dict):
        return [FieldError("spec", "a jail policy body dict",
                           type(body).__name__)]
    expected = {"format", "policy_name", "version", "platform",
                "rootfs_mode", "writable_dirs", "network", "no_new_privs",
                "syscall_profile", "timeout_s", "resource_limits",
                "capabilities", "not_before", "not_after"}
    for key in sorted(set(body) - expected):
        errors.append(FieldError(
            "spec.%s" % key, "a known policy field", repr(key),
            "unknown fields refused -- whole-update discipline"))
    for key in sorted(expected - set(body)):
        errors.append(FieldError("spec.%s" % key, "a present field",
                                 "missing"))
    if errors:
        return errors  # shape first; field rules need the fields
    if body.get("format") != _jp.JAIL_POLICY_FORMAT:
        errors.append(FieldError(
            "format", repr(_jp.JAIL_POLICY_FORMAT), body.get("format")))
    name = body.get("policy_name")
    if not isinstance(name, str) or not _jp._POLICY_NAME_RE.match(name):
        errors.append(FieldError(
            "policy_name", "matching %s" % _jp._POLICY_NAME_RE.pattern,
            name))
    version = body.get("version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or not 1 <= version <= 2 ** 31 - 1:
        errors.append(FieldError("version", "an int in [1, 2**31-1]",
                                 version))
    if body.get("platform") not in ("systrap",):
        errors.append(FieldError("platform", "one of ['systrap']",
                                 body.get("platform"),
                                 "closed vocabulary in v1"))
    if body.get("rootfs_mode") not in ("ro",):
        errors.append(FieldError("rootfs_mode", "one of ['ro']",
                                 body.get("rootfs_mode")))
    dirs = body.get("writable_dirs")
    if not isinstance(dirs, list) or not dirs:
        errors.append(FieldError("writable_dirs",
                                 "a non-empty list of absolute jail paths",
                                 dirs))
    else:
        seen = set()
        for i, path in enumerate(dirs):
            where = "writable_dirs[%d]" % i
            if not isinstance(path, str) or not path.startswith("/"):
                errors.append(FieldError(
                    where, "an absolute jail path", path))
                continue
            norm = posixpath.normpath(path)
            if norm == "/":
                errors.append(FieldError(
                    where, "a non-root jail path", path))
                continue
            if norm in seen:
                errors.append(FieldError(
                    where, "a mount not already declared", path))
            seen.add(norm)
    if body.get("network") not in ("none",):
        errors.append(FieldError("network", "one of ['none']",
                                 body.get("network"),
                                 "closed vocabulary in v1"))
    if body.get("no_new_privs") is not True:
        errors.append(FieldError("no_new_privs", "true",
                                 body.get("no_new_privs")))
    if body.get("syscall_profile") not in _jp.SYSCALL_PROFILES:
        errors.append(FieldError(
            "syscall_profile",
            "one of %s" % list(_jp.SYSCALL_PROFILES),
            body.get("syscall_profile")))
    timeout = body.get("timeout_s")
    if not isinstance(timeout, int) or isinstance(timeout, bool) \
            or not 1 <= timeout <= 3600:
        errors.append(FieldError("timeout_s", "an int in [1, 3600]",
                                 timeout))
    limits = body.get("resource_limits")
    if not isinstance(limits, dict) \
            or sorted(limits) != sorted(_JAIL_LIMIT_BOUNDS):
        errors.append(FieldError(
            "resource_limits",
            "a dict with exactly %s" % sorted(_JAIL_LIMIT_BOUNDS),
            limits if isinstance(limits, dict)
            else type(limits).__name__))
    else:
        for key in sorted(_JAIL_LIMIT_BOUNDS):
            lo, hi = _JAIL_LIMIT_BOUNDS[key]
            value = limits[key]
            if not isinstance(value, int) or isinstance(value, bool) \
                    or not lo <= value <= hi:
                errors.append(FieldError(
                    "resource_limits.%s" % key,
                    "an int in [%d, %d]" % (lo, hi), value))
    if body.get("capabilities") != []:
        errors.append(FieldError("capabilities", "[] in v1",
                                 body.get("capabilities"),
                                 "the recipe grants no capabilities"))
    nb, na = body.get("not_before"), body.get("not_after")
    for which, value in (("not_before", nb), ("not_after", na)):
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(FieldError(
                which, "epoch seconds (int)", value))
    if isinstance(nb, int) and not isinstance(nb, bool) \
            and isinstance(na, int) and not isinstance(na, bool) \
            and nb >= na:
        errors.append(FieldError(
            "not_before", "not_before < not_after",
            "not_before=%r, not_after=%r" % (nb, na)))
    return errors


def _load_jail_body_validated(body):
    errors = _jail_field_errors(body)
    if errors:
        raise PolicyCompilationError("jail", errors)
    try:
        return _jp.validate_policy_body(body)
    except _jp.JailPolicyError as exc:
        raise PolicyCompilationError(
            "jail", [FieldError(
                "spec", "valid per the closed vocabulary",
                "loader refused: %s" % exc)]) from exc


class CompiledJailPolicy(CompiledPolicy):
    """A compiled jail policy.

    ``body`` is validated ONCE here, at compile; the normalized body is
    stored. ``check`` takes ONLY a runtime invocation request and
    ``check_backend`` takes ONLY a feature set -- no policy parameter
    at evaluation, so authoring errors are impossible at evaluation by
    construction. Data refusals raise ``jail_policy.JailPolicyError``
    with the module's own evaluation codes (``invocation-*``,
    ``policy-needs-unimplemented-feature``), never the compile code.
    """

    def __init__(self, body):
        if not isinstance(body, dict):
            raise PolicyCompilationError(
                "jail", [FieldError("spec", "a jail policy body dict",
                                   type(body).__name__)])
        self._body = _load_jail_body_validated(body)

    @property
    def body(self):
        return dict(self._body)

    def fingerprint(self):
        return _jp.policy_digest(self._body)

    def check(self, request):
        """Invocation conformance of one jail run against the compiled
        policy. Raises ``JailPolicyError`` on data problems only."""
        return _jp.check_invocation(self._body, request)

    def check_backend(self, features=None):
        """Fail closed with a NAMED gap when the backend cannot
        implement the compiled policy."""
        return _jp.check_backend(self._body, features=features)

    # No body/policy parameter anywhere on the evaluation path.


def compile_jail_policy(body, audit=None):
    """Compile-time front gate for a jail policy body.

    Validates the WHOLE body ONCE against the closed vocabulary;
    authoring failures raise ``PolicyCompilationError`` (audited when
    ``audit`` is supplied). Returns a ``CompiledJailPolicy`` -- one
    compiled policy serves many invocation checks.
    """
    try:
        compiled = CompiledJailPolicy(body)
    except PolicyCompilationError as exc:
        if audit is not None:
            audit({"event": "policy_compile_refused",
                   "policy_type": "jail",
                   "code": exc.code,
                   "errors": [e.to_dict() for e in exc.errors]})
        raise
    _audit_compiled(audit, "jail", compiled.fingerprint())
    return compiled
