"""Evidence contracts: seal-time compliance authority for evidence bundles.

Steal (Apache-2.0, pattern): chainloop-dev/chainloop PR #3465 --
"Because the bundle is signed by the same client that decides whether
to run that check, a valid signature says nothing about contract
compliance." The fix is the same shape: the sealer is the authority.
It validates the artifact body against a declarative evidence
contract (one YAML per invocation class, ``gov/evidence_contracts/``)
AT SEAL TIME, and the assembler-side pre-check calls the SAME
validator (``precheck_artifact``) so the two cannot drift.

A body declaring ``invocation_class`` is subject to that class's
contract: required materials (presence + shape), verdict
vocabularies, and chain-integrity shapes. A body that fails the
contract is refused with the coded verdict
``evbundle-contract-refused`` -- fail-closed. A signed bundle
therefore attests BOTH integrity and compliance.

A body declaring NO invocation class takes the legacy path (seals as
before): the contract system is opt-in per class. An UNKNOWN class
is refused -- the sealer never seals a class it cannot define.

Public entry points are keyword-only (repo convention). There is
exactly one validation implementation (``_validate_body``): the
assembler pre-check and the sealer cannot drift.
"""

import os
import re

try:
    import yaml
except ImportError:  # pragma: no cover -- PyYAML is a locked dependency
    yaml = None

# The single home of the coded verdict. ``gov.evidence_bundle_v2``
# aliases this constant rather than redefining the literal, so the
# 509 vocabulary scan keeps exactly one emission site; the code must
# stay registered in gov/decision_codes.py.
CONTRACT_CODE = "evbundle-contract-refused"
CLASS_FIELD = "invocation_class"
CONTRACTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "evidence_contracts")

_API_VERSION = "sasanam.dev/v1"
_KIND = "EvidenceContract"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLASS_NAME_RE = re.compile(r"^[a-z0-9_]+$")
_MATERIAL_KINDS = ("required_string", "digest64", "enum")


class ContractRefused(Exception):
    """Seal-time contract refusal. ``code`` is always the coded
    verdict; ``violations`` carries the machine-readable detail."""

    def __init__(self, detail, violations=()):
        super(ContractRefused, self).__init__(detail)
        self.code = CONTRACT_CODE
        self.detail = detail
        self.violations = list(violations)


def _violation(material, reason, detail=None):
    v = {"material": material, "reason": reason}
    if detail is not None:
        v["detail"] = detail
    return v


def _contract_path(invocation_class):
    safe = re.sub(r"[^a-z0-9_]", "", str(invocation_class))
    return os.path.join(CONTRACTS_DIR, safe + ".yaml")


# Contract cache: never invalidated within a process. An edited
# contract file is not re-read until restart -- fail-closed (the old
# contract keeps being enforced), but operationally stale. This is
# deliberate: contract revisions are pinned at process start.
_cache = {}


def load_contract(*, invocation_class):
    """Load and schema-validate the contract for a class (cached).

    Raises ContractRefused on: unknown class (no contract file),
    unreadable YAML, or a malformed contract document -- a malformed
    shipped contract fails closed, never silently unsealed.
    """
    name = str(invocation_class)
    if name in _cache:
        return _cache[name]
    path = _contract_path(name)
    if not os.path.isfile(path):
        raise ContractRefused(
            "unknown invocation class %r: no evidence contract defines it"
            % (name,),
            [_violation(CLASS_FIELD, "unknown-invocation-class",
                        "class=%s" % name)])
    if yaml is None:
        raise ContractRefused(
            "evidence contracts unavailable: PyYAML not importable",
            [_violation(CLASS_FIELD, "contract-loader-missing")])
    try:
        with open(path, "rb") as fh:
            doc = yaml.safe_load(fh.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001 -- malformed contract is a refusal
        raise ContractRefused(
            "evidence contract for %r is unreadable: %s" % (name, e),
            [_violation(CLASS_FIELD, "contract-unreadable")])
    _check_contract_shape(name, doc)
    _cache[name] = doc
    return doc


def _check_contract_shape(name, doc):
    problems = []
    if not isinstance(doc, dict):
        problems.append("contract document must be a mapping")
    else:
        if doc.get("apiVersion") != _API_VERSION:
            problems.append("apiVersion must be %r" % _API_VERSION)
        if doc.get("kind") != _KIND:
            problems.append("kind must be %r" % _KIND)
        if doc.get("invocation_class") != name:
            problems.append("invocation_class must equal %r" % name)
        mats = doc.get("materials")
        if not isinstance(mats, list) or not mats:
            problems.append("materials must be a non-empty list")
        else:
            for i, m in enumerate(mats):
                if not isinstance(m, dict):
                    problems.append("materials[%d] must be a mapping" % i)
                    continue
                if not m.get("name") or not isinstance(m.get("name"), str):
                    problems.append("materials[%d] needs a string name" % i)
                if m.get("kind") not in _MATERIAL_KINDS:
                    problems.append(
                        "materials[%d] kind must be one of %s"
                        % (i, "/".join(_MATERIAL_KINDS)))
                if m.get("kind") == "enum":
                    vocab = m.get("vocabulary")
                    if not isinstance(vocab, list) or not vocab \
                            or not all(isinstance(v, str) for v in vocab):
                        problems.append(
                            "materials[%d] enum needs a non-empty string "
                            "vocabulary" % i)
    if problems:
        raise ContractRefused(
            "evidence contract for %r is malformed: %s"
            % (name, "; ".join(problems)),
            [_violation(CLASS_FIELD, "contract-malformed",
                        "; ".join(problems))])


def _require_class_name(name):
    if not name:
        raise ContractRefused(
            "empty invocation_class: declare a class or omit it",
            [_violation(CLASS_FIELD, "empty-invocation-class")])
    # The contract file is derived from the name by sanitizing: names
    # that do not round-trip (e.g. "a-b" vs "ab") are refused rather
    # than silently aliased.
    if not _CLASS_NAME_RE.match(name):
        raise ContractRefused(
            "invalid invocation class %r: use [a-z0-9_]" % (name,),
            [_violation(CLASS_FIELD, "invalid-invocation-class")])


def resolve_class(*, artifact_body, invocation_class=None):
    """Resolve the effective invocation class, or None for the legacy
    (unclassed) path. Explicit kwarg wins over the body declaration;
    a non-dict body without a kwarg is a refusal, not a legacy path."""
    if invocation_class is not None:
        name = str(invocation_class).strip()
    elif not isinstance(artifact_body, dict):
        raise ContractRefused(
            "artifact body must be a mapping to resolve an invocation "
            "class",
            [_violation(CLASS_FIELD, "body-not-a-mapping")])
    else:
        raw = artifact_body.get(CLASS_FIELD)
        if raw is None:
            return None  # legacy path: no contract applies
        name = str(raw).strip()
    _require_class_name(name)
    return name


def _check_required_string(material, value):
    if not isinstance(value, str) or not value:
        return _violation(material["name"], "required-string-absent",
                          "must be a non-empty string")
    return None


def _check_digest64(material, value):
    if not isinstance(value, str) or not _HEX64.match(value):
        return _violation(material["name"], "digest64-malformed",
                          "must be 64 lowercase hex chars")
    return None


def _check_enum(material, value):
    vocab = material["vocabulary"]
    if value not in vocab:
        return _violation(material["name"], "out-of-vocabulary",
                          "must be one of %s" % ("/".join(vocab),))
    return None


_MATERIAL_CHECKERS = {
    "required_string": _check_required_string,
    "digest64": _check_digest64,
    "enum": _check_enum,
}


def _check_material(material, value):
    """Return a violation dict, or None when the value satisfies the
    material's shape."""
    checker = _MATERIAL_CHECKERS.get(material.get("kind"))
    if checker is None:
        return _violation(material.get("name", "?"),
                          "unknown-material-kind",
                          "contract kind %r unsupported"
                          % (material.get("kind"),))
    return checker(material, value)


def _validate_body(artifact_body, cls):
    """THE shared validation core: the class is already resolved.

    ``validate_artifact``, ``precheck_artifact`` and
    ``validate_or_raise`` all funnel through here -- one
    implementation, so assembler and sealer cannot drift. Returns the
    violation list; empty means compliant (or legacy unclassed).
    """
    if cls is None:
        return []  # legacy path: no contract to violate
    if not isinstance(artifact_body, dict):
        # The kwarg path resolves the class without inspecting the
        # body: a non-mapping body is a coded refusal here, never an
        # AttributeError on .get.
        raise ContractRefused(
            "artifact body must be a mapping to validate against an "
            "evidence contract",
            [_violation(CLASS_FIELD, "body-not-a-mapping")])
    contract = load_contract(invocation_class=cls)
    violations = []
    for material in contract["materials"]:
        v = _check_material(material, artifact_body.get(material["name"]))
        if v is not None:
            violations.append(v)
    return violations


def validate_artifact(*, artifact_body, invocation_class=None):
    """Shared validator entry: return the violation list for a body."""
    cls = resolve_class(artifact_body=artifact_body,
                        invocation_class=invocation_class)
    return _validate_body(artifact_body, cls)


def precheck_artifact(*, artifact_body, invocation_class=None):
    """Assembler-side pre-check: non-raising, same contract, same
    validator as the sealer. Returns ``{"ok", "violations",
    "invocation_class"}``. Assemblers call this BEFORE submitting;
    the sealer re-validates at seal time and is the authority."""
    try:
        cls = resolve_class(artifact_body=artifact_body,
                            invocation_class=invocation_class)
    except ContractRefused as e:
        # Report the kwarg class honestly when resolution itself fails.
        return {"ok": False, "violations": e.violations,
                "invocation_class": invocation_class}
    try:
        violations = _validate_body(artifact_body, cls)
    except ContractRefused as e:
        return {"ok": False, "violations": e.violations,
                "invocation_class": cls}
    return {"ok": not violations, "violations": violations,
            "invocation_class": cls}


def validate_or_raise(*, artifact_body, invocation_class=None):
    """Sealer-side entry: raise ContractRefused on any violation.

    ``gov.evidence_bundle_v2.seal_evidence`` catches this and
    re-raises it as ``EvidenceBundleV2Error("evbundle-contract-refused",
    ...)`` -- the coded verdict at the public seam.
    """
    cls = resolve_class(artifact_body=artifact_body,
                        invocation_class=invocation_class)
    violations = _validate_body(artifact_body, cls)
    if violations:
        raise ContractRefused(
            "artifact body fails the %r evidence contract: %s"
            % (cls, "; ".join("%s: %s" % (v["material"], v["reason"])
                              for v in violations)),
            violations)
    return True


def list_classes():
    """Sorted list of invocation classes with shipped contracts."""
    out = []
    if os.path.isdir(CONTRACTS_DIR):
        for fn in sorted(os.listdir(CONTRACTS_DIR)):
            if fn.endswith(".yaml"):
                out.append(fn[:-len(".yaml")])
    return out
