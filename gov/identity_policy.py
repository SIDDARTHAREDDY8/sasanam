"""Per-certificate identity-policy DSL with non-vacuous combinators.

STEAL (idea only, Apache-2.0, no upstream source vendored) from
``sigstore/sigstore-python`` ``verify/policy.py`` (read 2026-09-29): a
per-certificate identity-policy layer with explicitly non-vacuous
``AnyOf``/``AllOf`` combinators and a self-announcing ``Unsafe*`` escape
hatch. This is the policy-layer answer to the F193 "vacuous proof" class:
an empty conjunction is an AUTHORING ERROR, never a pass, and an
explicit pass-despite-nothing is a distinct declared code (``pass-vacuous``),
never a silent allow.

A policy evaluates an *identity-claims document* -- the Sasanam analog of a
Fulcio certificate's identity fields::

    {
      "iss": "https://token.actions.githubusercontent.com",
      "sub": "repo:acme/app:ref:refs/heads/main",
      "sans": {"rfc822Name": [...], "uri": [...], "otherName": [...]},
      "extensions": {"<dotted-arc>": <value>, ...},
    }

Extension arcs are the deployer's own arcs (Sasanam mints no Fulcio OIDs;
per the wave-214 prospecting review our claims must not reuse Fulcio's
``1.3.6.1.4.1.57264`` arc).

VERDICT CONTRACT -- every ``Policy.verify(claims)`` returns a
``PolicyVerdict`` with ``verdict`` in ``{"pass", "fail", "error"}``:

* ``pass`` -- the identity satisfies the policy. ``code`` is ``"pass"``
  when at least one non-vacuous predicate matched, ``"pass-vacuous"``
  when the pass rests ONLY on ``UnsafeAllow`` leaves. A vacuous pass is
  still a pass, but it is loudly declared, never silent.
* ``fail`` -- judged and rejected (named ``code``, e.g.
  ``"oidc-issuer-mismatch"``).
* ``error`` -- the verifier could not judge (``"claims-malformed"``,
  ``"claims-section-missing"``). Errors fail closed at
  :func:`check_admission`, exactly like failures.

``check_admission(claims, policy)`` is the fail-closed seam: it returns a
report dict on pass and raises :class:`PolicyViolation` (a loud
``ValueError`` carrying the machine-readable ``code``) on fail OR error.

Stdlib only. $0. No network.
"""

from __future__ import annotations

import re
import warnings

__all__ = [
    "PolicyVerdict",
    "PolicyError",
    "PolicyAuthoringError",
    "PolicyViolation",
    "Policy",
    "OIDCIssuer",
    "Identity",
    "ExtensionEquals",
    "ClaimEquals",
    "ClaimIn",
    "AnyOf",
    "AllOf",
    "UnsafeAllow",
    "UnsafePolicyWarning",
    "parse_policy",
    "check_admission",
]

_PASS = "pass"
_FAIL = "fail"
_ERROR = "error"

_OID_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")


# -- verdicts and errors -------------------------------------------------------


class PolicyVerdict(object):
    """The verdict contract: ``verdict`` in {"pass", "fail", "error"}.

    ``code`` is the machine-readable mode (``"pass"`` / ``"pass-vacuous"`` /
    a named fail or error code), ``detail`` is human text, and ``vacuous``
    is True when a pass rests only on ``UnsafeAllow`` leaves.
    """

    __slots__ = ("verdict", "code", "detail", "vacuous")

    def __init__(self, verdict, code, detail="", vacuous=False):
        if verdict not in (_PASS, _FAIL, _ERROR):
            raise PolicyAuthoringError(
                "verdict must be pass/fail/error, got %r" % (verdict,))
        self.verdict = verdict
        self.code = code
        self.detail = detail
        self.vacuous = bool(vacuous)

    @property
    def ok(self):
        return self.verdict == _PASS

    def __repr__(self):
        return "PolicyVerdict(%r, %r, vacuous=%r)" % (
            self.verdict, self.code, self.vacuous)


class PolicyError(ValueError):
    """Base for all loud identity-policy failures. Never silent False."""


class PolicyAuthoringError(PolicyError):
    """The policy itself is malformed: empty combinators, bad OIDs,
    unknown predicate keys, unsafe policy without a stated reason.
    Raised at construction / parse time -- a broken policy never ships."""


class PolicyViolation(PolicyError):
    """Fail-closed admission refusal: the identity did not satisfy the
    policy (fail) or could not be judged (error). ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(PolicyViolation, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class UnsafePolicyWarning(UserWarning):
    """Emitted on EVERY use of an UnsafeAllow policy: the insecure
    capability self-announces, exactly like sigstore-python's UnsafeNoOp."""


# -- policy protocol -----------------------------------------------------------


class Policy(object):
    """Abstract policy: ``verify(claims) -> PolicyVerdict``.

    ``is_vacuous`` marks leaves that match everything (only UnsafeAllow).
    Combinators compute it from their children; a pass is coded
    ``"pass-vacuous"`` iff every passing leaf was vacuous.
    """

    is_vacuous = False

    def verify(self, claims):
        raise NotImplementedError

    def describe(self):
        raise NotImplementedError


def _check_claims_doc(claims):
    if isinstance(claims, bool) or not isinstance(claims, dict):
        return PolicyVerdict(_ERROR, "claims-malformed",
                             "identity claims must be a JSON object")
    return None


def _require_str(value, what):
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        raise PolicyAuthoringError(
            "%s must be a non-empty str" % what)
    return value


# -- typed predicates ----------------------------------------------------------


class OIDCIssuer(Policy):
    """The ``iss`` claim must equal the expected OIDC issuer."""

    def __init__(self, issuer):
        self.issuer = _require_str(issuer, "issuer")

    def verify(self, claims):
        bad = _check_claims_doc(claims)
        if bad is not None:
            return bad
        if "iss" not in claims:
            return PolicyVerdict(_ERROR, "claims-section-missing",
                                 "no 'iss' claim to judge")
        if claims["iss"] == self.issuer:
            return PolicyVerdict(_PASS, "pass")
        return PolicyVerdict(
            _FAIL, "oidc-issuer-mismatch",
            "iss %r != expected %r" % (claims["iss"], self.issuer))

    def describe(self):
        return "OIDCIssuer(%r)" % (self.issuer,)


class Identity(Policy):
    """sigstore-python ``Identity`` shape: optional OIDC-issuer check plus
    SAN membership across RFC822Name, URI, and OtherName."""

    _SAN_KEYS = ("rfc822Name", "uri", "otherName")

    def __init__(self, identity, issuer=None):
        self.identity = _require_str(identity, "identity")
        if issuer is not None:
            issuer = _require_str(issuer, "issuer")
        self.issuer = issuer

    def verify(self, claims):
        bad = _check_claims_doc(claims)
        if bad is not None:
            return bad
        if self.issuer is not None:
            if "iss" not in claims:
                return PolicyVerdict(_ERROR, "claims-section-missing",
                                     "no 'iss' claim to judge")
            if claims["iss"] != self.issuer:
                return PolicyVerdict(
                    _FAIL, "identity-issuer-mismatch",
                    "iss %r != expected %r" % (claims["iss"], self.issuer))
        sans = claims.get("sans")
        if not isinstance(sans, dict):
            return PolicyVerdict(_ERROR, "claims-section-missing",
                                 "no 'sans' section to judge")
        for key in self._SAN_KEYS:
            names = sans.get(key) or []
            if not isinstance(names, list):
                return PolicyVerdict(
                    _ERROR, "claims-malformed",
                    "sans.%s must be a list" % key)
            if self.identity in names:
                return PolicyVerdict(_PASS, "pass")
        return PolicyVerdict(
            _FAIL, "identity-not-in-sans",
            "identity %r in no SAN" % (self.identity,))

    def describe(self):
        return "Identity(%r, issuer=%r)" % (self.identity, self.issuer)


class ExtensionEquals(Policy):
    """One dotted-arc extension OID, one expected value -- the
    ``_SingleX509ExtPolicy`` shape, on the deployer's own arcs."""

    def __init__(self, oid, expected):
        if isinstance(oid, bool) or not isinstance(oid, str) \
                or not _OID_RE.match(oid):
            raise PolicyAuthoringError(
                "oid must be a dotted numeric arc, got %r" % (oid,))
        self.oid = oid
        self.expected = expected

    def verify(self, claims):
        bad = _check_claims_doc(claims)
        if bad is not None:
            return bad
        extensions = claims.get("extensions")
        if not isinstance(extensions, dict):
            return PolicyVerdict(_ERROR, "claims-section-missing",
                                 "no 'extensions' section to judge")
        # Absent key never equals, even when the expected value is None:
        # an author who wants "must be absent" must say so with a
        # dedicated predicate, not a None comparison.
        if self.oid in extensions and extensions[self.oid] == self.expected:
            return PolicyVerdict(_PASS, "pass")
        return PolicyVerdict(
            _FAIL, "extension-mismatch",
            "extension %s != expected value" % (self.oid,))

    def describe(self):
        return "ExtensionEquals(%r)" % (self.oid,)


def _resolve_path(claims, path):
    """Dotted-path lookup. Returns (found, value).

    Extension arcs (e.g. ``1.3.6.1.4.1.99999.1.1``) contain dots, so a
    pure dotted split would shred them: at each level the FULL
    remaining path is tried as a literal key before splitting off the
    first component.
    """
    node = claims
    rest = path
    while True:
        if not isinstance(node, dict):
            return False, None
        if rest in node:
            return True, node[rest]
        head, dot, tail = rest.partition(".")
        if not dot or head not in node:
            return False, None
        node = node[head]
        rest = tail


class ClaimEquals(Policy):
    """A dotted claim path must equal the expected value."""

    def __init__(self, path, expected):
        self.path = _require_str(path, "path")
        self.expected = expected

    def verify(self, claims):
        bad = _check_claims_doc(claims)
        if bad is not None:
            return bad
        first = self.path.split(".")[0]
        if first not in claims:
            return PolicyVerdict(_ERROR, "claims-section-missing",
                                 "no %r section to judge" % first)
        found, value = _resolve_path(claims, self.path)
        if found and value == self.expected:
            return PolicyVerdict(_PASS, "pass")
        return PolicyVerdict(
            _FAIL, "claim-equals-mismatch",
            "claim %r != expected value" % (self.path,))

    def describe(self):
        return "ClaimEquals(%r)" % (self.path,)


class ClaimIn(Policy):
    """A dotted claim path's value must be a member of a non-empty value
    set. The value set may not be empty -- an empty membership test is a
    vacuity authoring error, refused at construction."""

    def __init__(self, path, values):
        self.path = _require_str(path, "path")
        if not isinstance(values, (list, tuple)) or not values:
            raise PolicyAuthoringError(
                "ClaimIn values must be a non-empty list")
        self.values = list(values)

    def verify(self, claims):
        bad = _check_claims_doc(claims)
        if bad is not None:
            return bad
        first = self.path.split(".")[0]
        if first not in claims:
            return PolicyVerdict(_ERROR, "claims-section-missing",
                                 "no %r section to judge" % first)
        found, value = _resolve_path(claims, self.path)
        if found and value in self.values:
            return PolicyVerdict(_PASS, "pass")
        return PolicyVerdict(
            _FAIL, "claim-not-in",
            "claim %r not in allowed values" % (self.path,))

    def describe(self):
        return "ClaimIn(%r, %d values)" % (self.path, len(self.values))


# -- non-vacuous combinators ---------------------------------------------------


class AnyOf(Policy):
    """Logical OR. EMPTY IS AN AUTHORING ERROR -- sigstore-python calls an
    empty AnyOf "trivially invalid"; a policy that passes on no evidence
    must not exist. Fails with ``anyof-no-match`` when no child matches."""

    def __init__(self, *children):
        if not children:
            raise PolicyAuthoringError(
                "AnyOf() with no children is an authoring error: an "
                "empty disjunction must never pass")
        for child in children:
            if not isinstance(child, Policy):
                raise PolicyAuthoringError(
                    "AnyOf children must be Policy instances")
        self.children = tuple(children)

    @property
    def is_vacuous(self):
        return all(c.is_vacuous for c in self.children)

    def verify(self, claims):
        errors = []
        passing_vacuous = []
        for child in self.children:
            verdict = child.verify(claims)
            if verdict.verdict == _PASS:
                passing_vacuous.append(verdict.vacuous)
            elif verdict.verdict == _ERROR:
                errors.append(verdict)
        if passing_vacuous:
            # A pass is vacuous iff EVERY passing child was vacuous: one
            # real predicate match is enough for a plain "pass".
            vacuous = all(passing_vacuous)
            code = "pass-vacuous" if vacuous else "pass"
            return PolicyVerdict(_PASS, code, vacuous=vacuous)
        if errors:
            return PolicyVerdict(
                _ERROR, errors[0].code,
                "AnyOf: no child passed; a child errored: %s"
                % errors[0].detail)
        return PolicyVerdict(_FAIL, "anyof-no-match",
                             "no child policy matched")

    def describe(self):
        return "AnyOf(%s)" % ", ".join(c.describe() for c in self.children)


class AllOf(Policy):
    """Logical AND. EMPTY IS AN AUTHORING ERROR -- sigstore-python's
    comment calls vacuous-truth AND a "potential source of API misuse".
    An empty conjunction must never pass."""

    def __init__(self, *children):
        if not children:
            raise PolicyAuthoringError(
                "AllOf() with no children is an authoring error: "
                "vacuous-truth AND must never pass")
        for child in children:
            if not isinstance(child, Policy):
                raise PolicyAuthoringError(
                    "AllOf children must be Policy instances")
        self.children = tuple(children)

    @property
    def is_vacuous(self):
        return all(c.is_vacuous for c in self.children)

    def verify(self, claims):
        for child in self.children:
            verdict = child.verify(claims)
            if verdict.verdict != _PASS:
                # Errors propagate as errors; failures keep the child's
                # named code so the auditor sees exactly what refused.
                return verdict
        vacuous = all(c.is_vacuous for c in self.children)
        code = "pass-vacuous" if vacuous else "pass"
        return PolicyVerdict(_PASS, code, vacuous=vacuous)

    def describe(self):
        return "AllOf(%s)" % ", ".join(c.describe() for c in self.children)


class UnsafeAllow(Policy):
    """The named unsafe escape hatch (sigstore-python's UnsafeNoOp
    pattern): passes ANYTHING, is documented fundamentally insecure and
    for testing only, and WARNS ON EVERY USE. The name must start with
    ``Unsafe`` and a non-empty reason is required at construction -- an
    unsafe policy without a stated reason is itself an authoring error.
    Passes carry the declared ``pass-vacuous`` code, never a silent pass.

    Wave-219: the hatch is a registered unsafe path --
    ``gov.identity_policy.unsafe_allow_vacuous_pass`` -- and every use
    emits that code through the audit path (at the ``check_admission``
    seam) as well as the loud ``UnsafePolicyWarning``.
    """

    is_vacuous = True

    def __init__(self, reason):
        self.reason = _require_str(reason, "reason")

    def verify(self, claims):
        warnings.warn(
            "gov.identity_policy.unsafe_allow_vacuous_pass: UnsafeAllow "
            "policy used (%s): this policy passes ANY identity and is "
            "fundamentally insecure; testing only" % (self.reason,),
            UnsafePolicyWarning,
            stacklevel=3)
        return PolicyVerdict(_PASS, "pass-vacuous",
                             "explicit vacuous pass: %s" % (self.reason,),
                             vacuous=True)

    def describe(self):
        return "UnsafeAllow(%r)" % (self.reason,)


# -- parsing -------------------------------------------------------------------


def parse_policy(spec):
    """Build a Policy from a plain-data spec dict. Exactly one predicate
    key per spec node; unknown keys and malformed nodes are authoring
    errors (fail-closed at load, never at verify time)."""
    if isinstance(spec, bool) or not isinstance(spec, dict) or len(spec) != 1:
        raise PolicyAuthoringError(
            "policy spec must be a dict with exactly one predicate key")
    kind, body = next(iter(spec.items()))

    if kind == "oidcIssuer":
        return OIDCIssuer(_require_str(body, "oidcIssuer"))
    if kind == "identity":
        if not isinstance(body, dict):
            raise PolicyAuthoringError("identity spec must be a dict")
        unknown = set(body) - {"identity", "issuer"}
        if unknown or "identity" not in body:
            raise PolicyAuthoringError(
                "identity spec needs 'identity' (+ optional 'issuer')")
        return Identity(body["identity"], issuer=body.get("issuer"))
    if kind == "extension":
        if not isinstance(body, dict) or set(body) != {"oid", "value"}:
            raise PolicyAuthoringError(
                "extension spec needs {'oid', 'value'}")
        return ExtensionEquals(body["oid"], body["value"])
    if kind == "claimEquals":
        if not isinstance(body, dict) or set(body) != {"path", "value"}:
            raise PolicyAuthoringError(
                "claimEquals spec needs {'path', 'value'}")
        return ClaimEquals(body["path"], body["value"])
    if kind == "claimIn":
        if not isinstance(body, dict) or set(body) != {"path", "values"}:
            raise PolicyAuthoringError(
                "claimIn spec needs {'path', 'values'}")
        return ClaimIn(body["path"], body["values"])
    if kind in ("anyOf", "allOf"):
        if not isinstance(body, list):
            raise PolicyAuthoringError(
                "%s spec must be a list of child specs" % kind)
        children = [parse_policy(child) for child in body]
        return AnyOf(*children) if kind == "anyOf" else AllOf(*children)
    if kind == "unsafeAllow":
        return UnsafeAllow(_require_str(body, "unsafeAllow reason"))
    raise PolicyAuthoringError("unknown policy predicate %r" % (kind,))


# -- fail-closed admission seam ------------------------------------------------


def check_admission(claims, policy, *, audit=None):
    """Fail-closed admission: returns ``{"verdict": "pass", "code": ...,
    "vacuous": ...}`` on pass; raises :class:`PolicyViolation` on fail
    OR error. A wrong-typed policy is a loud ``PolicyAuthoringError``.

    Wave-219: a vacuous pass (e.g. ``UnsafeAllow``) is a registered
    unsafe path -- ``gov.identity_policy.unsafe_allow_vacuous_pass``
    -- and is emitted through the audit path (``audit``: list or
    callable) on EVERY admission, so the escape hatch is never silent.
    """
    if not isinstance(policy, Policy):
        raise PolicyAuthoringError(
            "policy must be a gov.identity_policy.Policy instance")
    verdict = policy.verify(claims)
    if verdict.verdict == _PASS:
        if verdict.vacuous:
            from . import unsafe_paths as _up
            _up.emit(
                "gov.identity_policy.unsafe_allow_vacuous_pass",
                audit=audit,
                detail=("admission passed vacuously via %s"
                        % (policy.describe(),)))
        return {"verdict": "pass", "code": verdict.code,
                "vacuous": verdict.vacuous,
                "policy": policy.describe()}
    raise PolicyViolation(verdict.code, verdict.detail)
