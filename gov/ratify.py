"""Artifact ratification: per-artifact-type any/all verification policies,
nested VerifierResult report trees, and admission-before-binding.

Mechanism lineage: notaryproject/ratify (Apache-2.0; LICENSE bytes verified
by the wave-281 prospecting lane) -- the per-artifact-type ``any``/``all``
policy combinator over per-verifier boolean reports, the recursive nested
``VerifierResult`` report tree
(Subject/IsSuccess/Name/Results/NestedResults/ArtifactType), and the
external-data-provider admission pattern (refuse to *bind* a tool into the
grant graph unless its metadata ratified, rather than checking lazily at
call time). Clean-room stdlib re-implementation of the MECHANISMS only; no
ratify code vendored. (Do not confuse with the unrelated
``identities-ai/ratify-protocol`` project.)

Design notes:
- Verifiers return boolean reports; the enforcer rolls them up into a nested
  evidence tree. Verification failures are DATA (is_success False), never
  exceptions -- fail-closed as evidence.
- Verifier crashes, missing verifiers for required types, and malformed
  inputs all fail CLOSED (is_success False / loud refusal), never open.
- ``is_success`` is always an exact bool (never truthy/falsy) -- callers
  must check ``is True`` / ``is False``.
- The admission gate raises coded refusals; the grant-graph binding seam
  (``gov.capability_grants.derive_grants``) takes an optional keyword-only
  ``ratify_report`` -- absent means the legacy path, unchanged. The hook is
  deliberately opt-in rather than mandatory: making ratification required
  for every binding would change the contract of all existing callers.
  A deployment that wants mandatory ratification always passes a report.
- Sealing: the report's ``package_digest`` is the evidence identity; the
  seal is the signed per-bundle VSA that names it
  (``gov.bundle_vsa.issue_bundle_vsa(bundle_digest=package_digest)``,
  checked by ``verify_bundle_vsa(..., expected_bundle_digest=...)``),
  plus the HMAC-chained ``ratification-verdict`` audit record at decision
  time. Composition with the repo's existing evidence seams, not a
  parallel signature scheme.
"""

import hashlib
import json

from gov import ed25519

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

#: Kinds of subjects that can be ratified.
SUBJECT_KINDS = ("tool-definition", "skill-bundle", "evidence-manifest")

#: Metadata artifact types a verifier can attest to. The five are the
#: prospectus set (signature, SBOM, provenance, vuln report, license scan);
#: "digest" is the repo's in-toto-style content-identity companion.
ARTIFACT_TYPES = ("signature", "digest", "provenance", "sbom", "license",
                  "vuln-report")

#: Policy combinators: "any" = at least one verifier of the type succeeds;
#: "all" = every verifier of the type succeeds.
COMBINATORS = ("any", "all")

_PACKAGE_FORMAT = "sasanam-ratification-package/1"
_MAX_TREE_DEPTH = 32


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


# ---------------------------------------------------------------------------
# Exceptions (class-level ``code`` attributes are the machine vocabulary)
# ---------------------------------------------------------------------------

class RatifyError(ValueError):
    """Base: programming errors fail fast (ValueError family)."""


class RatifyRefused(RatifyError):
    """The admission gate refused: tool not ratified. Loud, fail-closed."""
    code = "ratify-unratified-tool-refused"


class RatifyPolicyError(RatifyError):
    """A policy rollup failed (emitted in the report's results)."""
    code = "ratify-policy-unsatisfied"


class RatifyVerifierError(RatifyError):
    """A verifier errored technically (emitted in the report's results)."""
    code = "ratify-verifier-error"


class RatifyAdmissionError(RatifyError):
    """The admission input was absent or unverifiable. Loud, fail-closed."""
    code = "ratify-admission-unverifiable"


# ---------------------------------------------------------------------------
# VerifierResult: the nested report node
# ---------------------------------------------------------------------------

#: Artifact-type values reserved for the enforcer's internal rollup nodes.
#: The per-artifact-type combinator needs a grouping node between the root
#: and the verifier leaves so the any/all rollup is itself evidence; these
#: node kinds are closed and never clash with ARTIFACT_TYPES.
_ROLLUP_NODE_TYPES = ("policy", "policy-combinator")


def _validate_node_fields(subject, is_success, name, artifact_type,
                          results, nested_results):
    """Shared field validation for node construction and shape checks."""
    if not isinstance(subject, str) or not subject:
        raise RatifyError("subject must be a non-empty string")
    if not isinstance(name, str) or not name:
        raise RatifyError("name must be a non-empty string")
    if artifact_type not in ARTIFACT_TYPES + _ROLLUP_NODE_TYPES:
        raise RatifyError(
            "artifact_type must be one of %s (or %s)"
            % (ARTIFACT_TYPES, _ROLLUP_NODE_TYPES))
    if is_success is not True and is_success is not False:
        raise RatifyError("is_success must be an exact bool")
    if not isinstance(results, (list, tuple)) or not all(
            isinstance(r, str) for r in results):
        raise RatifyError("results must be a list of strings")
    if not isinstance(nested_results, (list, tuple)):
        raise RatifyError("nested_results must be a list")

def verifier_result(*, subject, name, artifact_type, is_success,
                    results=(), nested_results=()):
    """Build one validated VerifierResult node (a plain JSON-able dict).

    ``is_success`` must be an exact bool. ``results`` are evidence strings;
    ``nested_results`` are child nodes. Raises RatifyError (fail-fast) on
    malformed construction -- this is the programmer's contract, not the
    verifier's verdict.
    """
    _validate_node_fields(subject, is_success, name, artifact_type,
                          results, nested_results)
    for child in nested_results:
        _check_node_shape(child, depth=1)
    return {
        "subject": subject,
        "is_success": is_success,
        "name": name,
        "artifact_type": artifact_type,
        "results": list(results),
        "nested_results": list(nested_results),
    }


def _check_node_shape(node, depth):
    """Fail-fast recursive shape check for report nodes."""
    if depth > _MAX_TREE_DEPTH:
        raise RatifyError("report tree exceeds max depth")
    if not isinstance(node, dict):
        raise RatifyError("report node must be a dict")
    for key in ("subject", "is_success", "name", "artifact_type",
                "results", "nested_results"):
        if key not in node:
            raise RatifyError("report node missing %r" % (key,))
    _validate_node_fields(node["subject"], node["is_success"], node["name"],
                          node["artifact_type"], node["results"],
                          node["nested_results"])
    if not isinstance(node["results"], list):
        raise RatifyError("stored node results must be a list")
    if not isinstance(node["nested_results"], list):
        raise RatifyError("stored node nested_results must be a list")
    for child in node["nested_results"]:
        _check_node_shape(child, depth + 1)


def report_digest(report):
    """sha256 of the canonical report -- the evidence identity."""
    _check_node_shape(report, depth=0)
    return _digest(_canonical(report))


# ---------------------------------------------------------------------------
# Verifiers (pluggable, stdlib-only, deterministic)
# ---------------------------------------------------------------------------

class Verifier(object):
    """A verifier attests to one ARTIFACT_TYPES member for a subject.

    ``verify(subject_bytes, metadata)`` returns a VerifierResult dict.
    Never raises on verification failure (fail-closed as data); a verifier
    that raises is recorded as a technical error by the enforcer.
    """
    name = "verifier"
    artifact_type = "digest"

    def __init__(self, name):
        if not isinstance(name, str) or not name:
            raise RatifyError("verifier name must be a non-empty string")
        self.name = name

    def _report(self, metadata, ok, results):
        """One leaf node for this verifier (fail-closed as data)."""
        return verifier_result(
            subject=_subject_of(metadata), name=self.name,
            artifact_type=self.artifact_type, is_success=ok,
            results=results)

    def verify(self, subject_bytes, metadata):
        raise NotImplementedError


class SignatureVerifier(Verifier):
    """Ed25519 signature over the canonical subject bytes.

    ``gov.ed25519.verify`` returns an exact bool (wave-243 lesson: check the
    return, never assume it raises).
    """

    def __init__(self, name, *, pubkey_hex, signature_hex):
        super(SignatureVerifier, self).__init__(name)
        self.artifact_type = "signature"
        self._pubkey_hex = pubkey_hex
        self._signature_hex = signature_hex

    def verify(self, subject_bytes, metadata):
        try:
            pub = bytes.fromhex(self._pubkey_hex)
            sig = bytes.fromhex(self._signature_hex)
        except (ValueError, TypeError, AttributeError):
            pub, sig = b"", b""
        ok = ed25519.verify(pub, subject_bytes, sig)
        if ok is True:
            return self._report(
                metadata, True,
                ["signature verifies under pinned key"])
        return self._report(metadata, False,
                            ["signature does not verify"])


class DigestVerifier(Verifier):
    """sha256(subject_bytes) equals the pinned digest."""

    def __init__(self, name, *, expected_hex):
        super(DigestVerifier, self).__init__(name)
        if not _is_hex64(expected_hex):
            raise RatifyError("expected_hex must be 64 lowercase hex chars")
        self.artifact_type = "digest"
        self._expected = expected_hex

    def verify(self, subject_bytes, metadata):
        if _digest(subject_bytes) == self._expected:
            return self._report(metadata, True,
                                ["digest matches pinned value"])
        return self._report(metadata, False, ["digest mismatch"])


class ProvenanceVerifier(Verifier):
    """Provenance document shape check (SLSA-style, no network).

    ``metadata["provenance"]`` must be a dict carrying the required fields;
    every material entry must name a sha256 hex digest.
    """

    def __init__(self, name, *, required_fields=("builder_id", "materials")):
        super(ProvenanceVerifier, self).__init__(name)
        self.artifact_type = "provenance"
        self._required = tuple(required_fields)

    def verify(self, subject_bytes, metadata):
        prov = metadata.get("provenance") if isinstance(metadata, dict) \
            else None
        problems = []
        if not isinstance(prov, dict):
            problems.append("provenance document absent or not a dict")
        else:
            for field in self._required:
                if field not in prov:
                    problems.append("missing field %r" % (field,))
            materials = prov.get("materials", [])
            if not isinstance(materials, list):
                problems.append("materials is not a list")
            else:
                for i, mat in enumerate(materials):
                    if not isinstance(mat, dict) or not _is_hex64(
                            mat.get("digest", "")):
                        problems.append(
                            "material %d lacks a sha256 digest" % (i,))
        if problems:
            return self._report(metadata, False, problems)
        return self._report(metadata, True, ["provenance shape valid"])


class SbomVerifier(Verifier):
    """CycloneDX-shaped SBOM check (format only, no vuln database)."""

    def __init__(self, name):
        super(SbomVerifier, self).__init__(name)
        self.artifact_type = "sbom"

    def verify(self, subject_bytes, metadata):
        sbom = metadata.get("sbom") if isinstance(metadata, dict) else None
        problems = []
        if not isinstance(sbom, dict):
            problems.append("sbom absent or not a dict")
        else:
            if sbom.get("bomFormat") != "CycloneDX":
                problems.append("bomFormat is not CycloneDX")
            if not isinstance(sbom.get("specVersion"), str):
                problems.append("specVersion missing")
            if not isinstance(sbom.get("components"), list):
                problems.append("components is not a list")
        if problems:
            return self._report(metadata, False, problems)
        return self._report(metadata, True, ["sbom shape valid"])


class LicenseVerifier(Verifier):
    """SPDX license id against a deployment allowlist (exact match)."""

    def __init__(self, name, *, allowlist):
        super(LicenseVerifier, self).__init__(name)
        if not allowlist or not all(isinstance(l, str) for l in allowlist):
            raise RatifyError("allowlist must be a non-empty list of str")
        self.artifact_type = "license"
        self._allowlist = frozenset(allowlist)

    def verify(self, subject_bytes, metadata):
        lic = metadata.get("license") if isinstance(metadata, dict) else None
        if lic in self._allowlist:
            return self._report(
                metadata, True, ["license %r allowlisted" % (lic,)])
        return self._report(
            metadata, False, ["license %r not allowlisted" % (lic,)])


class VulnReportVerifier(Verifier):
    """Vulnerability scan report: no unaddressed forbidden-severity finding.

    ``metadata["vuln_report"]`` must be a dict with a ``findings`` list;
    each finding is a dict with a ``severity`` string and may carry
    ``status`` (``"fixed"`` findings are ignored). Any finding whose
    severity is in ``forbidden_severities`` (default: critical) and is not
    fixed fails the report closed. Stdlib, offline -- the scan itself is
    the caller's job; this verifier only judges the report.
    """

    def __init__(self, name, *, forbidden_severities=("critical",)):
        super(VulnReportVerifier, self).__init__(name)
        if not forbidden_severities or not all(
                isinstance(s, str) for s in forbidden_severities):
            raise RatifyError(
                "forbidden_severities must be a non-empty list of str")
        self.artifact_type = "vuln-report"
        self._forbidden = frozenset(forbidden_severities)

    def verify(self, subject_bytes, metadata):
        rep = metadata.get("vuln_report") if isinstance(metadata, dict) \
            else None
        problems = []
        if not isinstance(rep, dict):
            problems.append("vuln report absent or not a dict")
        else:
            findings = rep.get("findings")
            if not isinstance(findings, list):
                problems.append("findings is not a list")
            else:
                for i, finding in enumerate(findings):
                    if not isinstance(finding, dict):
                        problems.append("finding %d is not a dict" % (i,))
                        continue
                    if finding.get("status") == "fixed":
                        continue
                    sev = finding.get("severity")
                    if sev in self._forbidden:
                        problems.append(
                            "finding %d: unaddressed %r severity"
                            % (i, sev))
        if problems:
            return self._report(metadata, False, problems)
        return self._report(metadata, True,
                            ["no unaddressed forbidden-severity findings"])


def _subject_of(metadata):
    sub = metadata.get("subject") if isinstance(metadata, dict) else None
    return sub if isinstance(sub, str) and sub else "unknown-subject"


# ---------------------------------------------------------------------------
# Policy: per-artifact-type any/all combinator
# ---------------------------------------------------------------------------

class VerificationPolicy(object):
    """Maps artifact type -> combinator ("any" | "all").

    Unknown combinators refuse fail-fast at construction (programming
    error, not a verification verdict).
    """

    def __init__(self, mapping):
        if not isinstance(mapping, dict) or not mapping:
            raise RatifyError("policy mapping must be a non-empty dict")
        for artifact_type, combinator in mapping.items():
            if artifact_type not in ARTIFACT_TYPES:
                raise RatifyError(
                    "unknown artifact type %r" % (artifact_type,))
            if combinator not in COMBINATORS:
                raise RatifyError(
                    "unknown combinator %r for %r (want one of %s)"
                    % (combinator, artifact_type, COMBINATORS))
        self._mapping = dict(mapping)

    def combinator_for(self, artifact_type):
        return self._mapping[artifact_type]

    def artifact_types(self):
        return tuple(self._mapping.keys())


# ---------------------------------------------------------------------------
# PolicyEnforcer: run verifiers, roll up the nested report tree
# ---------------------------------------------------------------------------

class PolicyEnforcer(object):
    """Runs verifiers per policy and folds the nested VerifierResult tree.

    Never raises on verification outcomes (fail-closed as data); raises
    RatifyError only on malformed inputs (programmer's contract).
    """

    def verify(self, *, subject, subject_kind, subject_bytes, metadata,
               verifiers, policy):
        if not isinstance(subject, str) or not subject:
            raise RatifyError("subject must be a non-empty string")
        if subject_kind not in SUBJECT_KINDS:
            raise RatifyError(
                "subject_kind must be one of %s" % (SUBJECT_KINDS,))
        if not isinstance(subject_bytes, (bytes, bytearray)):
            raise RatifyError("subject_bytes must be bytes")
        if not isinstance(metadata, dict):
            raise RatifyError("metadata must be a dict")
        if not isinstance(verifiers, (list, tuple)):
            raise RatifyError("verifiers must be a list")
        if not isinstance(policy, VerificationPolicy):
            raise RatifyError("policy must be a VerificationPolicy")

        by_type = {}
        for v in verifiers:
            if not isinstance(v, Verifier):
                raise RatifyError(
                    "verifier %r is not a Verifier" % (v,))
            if v.artifact_type not in ARTIFACT_TYPES:
                raise RatifyError(
                    "verifier %r has unknown artifact_type %r"
                    % (v.name, v.artifact_type))
            by_type.setdefault(v.artifact_type, []).append(v)

        type_nodes = []
        for artifact_type in policy.artifact_types():
            node = self._verify_type(
                subject, subject_bytes, metadata, artifact_type,
                policy.combinator_for(artifact_type),
                by_type.get(artifact_type, []))
            type_nodes.append(node)

        root_ok = all(n["is_success"] is True for n in type_nodes)
        root_results = ["policy rollup: %s" % (
            "satisfied" if root_ok else RatifyPolicyError.code)]
        return verifier_result(
            subject=subject, name="policy-enforcer",
            artifact_type="policy", is_success=root_ok,
            results=root_results, nested_results=type_nodes)

    def _verify_type(self, subject, subject_bytes, metadata, artifact_type,
                     combinator, verifiers):
        leaves = []
        if not verifiers:
            return verifier_result(
                subject=subject, name=artifact_type,
                artifact_type="policy-combinator", is_success=False,
                results=["no verifier for required artifact type %r "
                         "(fail-closed)" % (artifact_type,)],
                nested_results=[])
        for v in verifiers:
            try:
                leaf = v.verify(bytes(subject_bytes), metadata)
                _check_node_shape(leaf, depth=0)
            except RatifyError:
                raise
            except Exception as e:  # noqa: BLE001 - verifier errors are data
                leaf = verifier_result(
                    subject=subject, name=v.name,
                    artifact_type=v.artifact_type, is_success=False,
                    results=["%s: verifier raised %r (fail-closed)"
                             % (RatifyVerifierError.code, e)])
            leaves.append(leaf)
        if combinator == "any":
            ok = any(l["is_success"] is True for l in leaves)
        else:
            ok = all(l["is_success"] is True for l in leaves)
        return verifier_result(
            subject=subject, name=artifact_type,
            artifact_type="policy-combinator", is_success=ok,
            results=["combinator %r over %d verifier(s): %s"
                     % (combinator, len(leaves),
                        "satisfied" if ok else RatifyPolicyError.code)],
            nested_results=leaves)


# ---------------------------------------------------------------------------
# Admission: refuse to bind a tool unless its metadata ratified
# ---------------------------------------------------------------------------

def check_admission(*, tool, report):
    """Admission gate: True when ``report`` ratifies ``tool``.

    Raises RatifyAdmissionError (code ratify-admission-unverifiable) when
    the report is absent or malformed, and RatifyRefused (code
    ratify-unratified-tool-refused) when the report does not ratify the
    tool (failure or subject mismatch). Loud, fail-closed.
    """
    if not isinstance(tool, str) or not tool:
        raise RatifyError("tool must be a non-empty string")
    if report is None:
        raise RatifyAdmissionError("no ratification report supplied")
    try:
        _check_node_shape(report, depth=0)
    except RatifyError:
        raise RatifyAdmissionError("ratification report malformed")
    if report["subject"] != tool:
        raise RatifyRefused(
            "report subject %r does not ratify tool %r"
            % (report["subject"], tool))
    if report["is_success"] is not True:
        raise RatifyRefused(
            "tool %r not ratified (report is_success is not True)" % (tool,))
    return True


# ---------------------------------------------------------------------------
# Audit chaining: ratification verdicts into the HMAC log at decision time
# ---------------------------------------------------------------------------

_GENESIS = "0" * 64
_RECORD_TYPE = "ratification-verdict"


class RatificationWriter(object):
    """Chains ratification verdicts into an ActionLog at decision time.

    One writer chains its own records via ``prev_ratification_record_digest``.
    Fail-closed: if ``log.append`` raises, the exception propagates and the
    caller must not treat the tool as ratified.
    """

    def __init__(self, log):
        self._log = log
        self._last_digest = _GENESIS

    def record(self, tool, subject_kind, report):
        """Build, digest, chain, and append one ratification-verdict record.

        Returns the stored entry (as returned by ``log.append``).
        """
        if not isinstance(tool, str) or not tool:
            raise RatifyError("tool must be a non-empty string")
        if subject_kind not in SUBJECT_KINDS:
            raise RatifyError(
                "subject_kind must be one of %s" % (SUBJECT_KINDS,))
        digest = report_digest(report)
        record = {
            "record_type": _RECORD_TYPE,
            "tool": tool,
            "subject_kind": subject_kind,
            "subject": report["subject"],
            "report_digest": digest,
            "is_success": report["is_success"],
            "prev_ratification_record_digest": self._last_digest,
        }
        record["ratification_record_digest"] = _digest(_canonical(record))
        entry = self._log.append(record)
        self._last_digest = record["ratification_record_digest"]
        return entry


def ratification_verdict_records(log):
    """All ratification-verdict records in ``log``, in stored order."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if e.get("record_type") == _RECORD_TYPE]


# ---------------------------------------------------------------------------
# Evidence package: the nested tree as sealed, standalone-verifiable evidence
# ---------------------------------------------------------------------------

def ratification_evidence_package(report):
    """Canonical evidence package: the report plus its digest identity.

    The ``package_digest`` is what a VSA names as its subject
    (``gov.bundle_vsa.issue_bundle_vsa``) -- composition, not duplication.
    """
    digest = report_digest(report)
    return {
        "format": _PACKAGE_FORMAT,
        "report": report,
        "package_digest": digest,
    }


def verify_ratification_package(package):
    """Standalone verification of an evidence package.

    Returns True only when the package has the right format, the report
    tree is well-shaped, and the digest recomputes. Returns False (never
    raises) on any malformed input.
    """
    try:
        if not isinstance(package, dict):
            return False
        if package.get("format") != _PACKAGE_FORMAT:
            return False
        report = package.get("report")
        _check_node_shape(report, depth=0)
        if not _is_hex64(package.get("package_digest", "")):
            return False
        return package["package_digest"] == _digest(_canonical(report))
    except RatifyError:
        return False
