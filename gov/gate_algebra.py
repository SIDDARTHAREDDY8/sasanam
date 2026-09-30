"""Gate algebra: AND-composable admission policies.

Design input (ADAPT, re-derived prose -- no Harbor text copied):
Harbor's pull-time content-trust gate evaluates multiple policies
together (AND semantics) so a single lenient rule cannot admit what
a stricter rule refuses. This module implements that composition
pattern over ``gov/admission.py`` -- strictly by COMPOSITION: this
module never modifies ``gov/admission.py`` (pinned by
``evals/w223_gatealg_probes.py::gal-10``).

What this module provides, stdlib-only:

* :class:`PolicyConjunction` -- N admission policies combined with
  logical AND. Every member is evaluated (no short-circuit) so the
  count of refusing members is reported honestly; a single refusal
  fails the whole conjunction closed with
  ``admission-conjunction-refused``. Member refusals are NEVER
  swallowed: the exception carries ``member_results`` (each entry a
  ``{member: index, code, detail}`` mapping) and ``refused_count``.
  A member raising a non-admission programming error also fails the
  conjunction closed -- it is never treated as an admit.
* :class:`SeverityGate` -- wraps a policy with a per-artifact-class
  severity threshold. When any scan finding's severity is strictly
  above the class threshold, admission refuses
  ``admission-severity-exceeded``. Unknown severity strings, missing
  severity fields, and absent scan data refuse
  ``admission-severity-unverifiable`` -- never assumed benign.
* :class:`ImmutableTag` -- wraps a policy with an in-memory
  tag-to-digest registry. Once digest D is admitted under tag T,
  admitting a DIFFERENT digest under T refuses
  ``admission-tag-mutated``; re-admitting the SAME digest is
  idempotent and admissible.

All refusals use ``gov.admission.AdmissionError`` with new
machine-readable codes, so callers keep one refusal type.

Honest boundaries (stated, not absorbed):

* The severity vocabulary (none < low < medium < high < critical)
  is OUR ordinal scale -- it classifies scan verdicts, it does not
  prove them; severity inflation/gaming by a scanner is out of
  scope. The conjunction does not reconcile member disagreements
  about the same finding: any single refusal wins (AND).
* The tag registry is in-memory; persistence and cross-instance
  sharing are deployment-owned. A tag registry reset re-arms
  mutation -- the registry proves nothing across restarts.
* Severity gates and tags do not authorize anything; they only
  refuse admission. An admitted artifact is trusted to ENTER the
  pipeline, not to execute (as in gov/admission.py).

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

from . import admission as _adm

__all__ = [
    "CODE_CONJUNCTION_REFUSED",
    "CODE_CONJUNCTION_MEMBER_ERROR",
    "CODE_SEVERITY_EXCEEDED",
    "CODE_SEVERITY_UNVERIFIABLE",
    "CODE_TAG_MUTATED",
    "SEVERITIES",
    "PolicyConjunction",
    "SeverityGate",
    "ImmutableTag",
]

CODE_CONJUNCTION_REFUSED = "admission-conjunction-refused"
CODE_CONJUNCTION_MEMBER_ERROR = "admission-conjunction-member-error"
CODE_SEVERITY_EXCEEDED = "admission-severity-exceeded"
CODE_SEVERITY_UNVERIFIABLE = "admission-severity-unverifiable"
CODE_TAG_MUTATED = "admission-tag-mutated"

#: Our ordinal severity scale. Order is the policy; the names are
#: what scanners report.
SEVERITIES = ("none", "low", "medium", "high", "critical")

_HEX = frozenset("0123456789abcdef")


def _is_sha256_hex(value):
    return isinstance(value, str) and len(value) == 64 \
        and all(c in _HEX for c in value)


def _severity_rank(severity):
    if not isinstance(severity, str):
        return None
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return None


class PolicyConjunction(object):
    """Logical AND over N admission policies.

    Each member must expose ``admit(artifact, ...)`` returning an
    audit-visible record on success or raising
    ``gov.admission.AdmissionError`` on refusal. All members are
    evaluated even after the first refusal (no short-circuit), so
    the refusal audit is complete. Extra keyword arguments are
    passed through to every member (e.g. ``findings=...`` for a
    wrapped :class:`SeverityGate`).
    """

    def __init__(self, *members):
        if not members:
            raise ValueError(
                "PolicyConjunction needs at least one member policy")
        for member in members:
            if not callable(getattr(member, "admit", None)):
                raise ValueError(
                    "member %r has no callable admit()" % (member,))
        self._members = tuple(members)

    def _refuse(self, results):
        refused = [r for r in results if r["code"] != "admitted"]
        detail = "; ".join(
            "member %d: %s" % (r["member"], r["code"]) for r in refused)
        err = _adm.AdmissionError(CODE_CONJUNCTION_REFUSED, detail)
        # Duck-typed audit fields: the member attributions and the
        # count are part of the refusal, not of str(err).
        err.member_results = [
            {"member": r["member"], "code": r["code"],
             "detail": r["detail"]} for r in results]
        err.refused_count = len(refused)
        raise err

    def admit(self, artifact, **kwargs):
        results = []
        for idx, member in enumerate(self._members):
            try:
                member.admit(artifact, **kwargs)
            except _adm.AdmissionError as exc:
                results.append({"member": idx, "code": exc.code,
                                "detail": exc.detail})
            except Exception as exc:  # noqa: BLE001 - fail-closed audit
                # A programming error inside a member is a refusal,
                # never an admit: recorded with its own code, the
                # conjunction fails closed.
                results.append({"member": idx,
                                "code": CODE_CONJUNCTION_MEMBER_ERROR,
                                "detail": "%s: %s"
                                % (type(exc).__name__, exc)})
            else:
                results.append({"member": idx, "code": "admitted",
                                "detail": ""})
        refused = [r for r in results if r["code"] != "admitted"]
        if refused:
            self._refuse(results)
        return {
            "admissible": True,
            "members_admitted": len(self._members),
            "member_results": [
                {"member": r["member"], "code": r["code"],
                 "detail": r["detail"]} for r in results],
        }


class SeverityGate(object):
    """Severity-threshold wrapper around a policy.

    ``threshold`` is either a single severity (applies to every
    artifact class) or a ``{class: severity}`` mapping. The artifact
    class is ``artifact.get("class", artifact.get("format"))``;
    artifact classes with no configured threshold refuse
    ``admission-severity-unverifiable`` (fail closed -- an
    unclassifiable artifact is not assumed benign).
    """

    def __init__(self, policy, threshold):
        if not callable(getattr(policy, "admit", None)):
            raise ValueError("policy has no callable admit()")
        if isinstance(threshold, str):
            rank = _severity_rank(threshold)
            if rank is None:
                raise ValueError(
                    "unknown severity threshold %r" % (threshold,))
            self._thresholds = None
            self._default_rank = rank
            self._default_name = threshold
        elif isinstance(threshold, dict) and threshold:
            parsed = {}
            for klass, name in threshold.items():
                rank = _severity_rank(name)
                if rank is None:
                    raise ValueError(
                        "unknown severity threshold %r for class %r"
                        % (name, klass))
                parsed[klass] = (name, rank)
            self._thresholds = parsed
            self._default_rank = None
            self._default_name = None
        else:
            raise ValueError(
                "threshold must be a severity name or a non-empty "
                "{class: severity} mapping")
        self._policy = policy

    def _threshold_for(self, artifact):
        if self._thresholds is None:
            return self._default_name, self._default_rank
        klass = artifact.get("class", artifact.get("format"))
        if klass not in self._thresholds:
            raise _adm.AdmissionError(
                CODE_SEVERITY_UNVERIFIABLE,
                "no severity threshold configured for artifact class %r"
                % (klass,))
        return self._thresholds[klass]

    def admit(self, artifact, findings=None, **kwargs):
        """Gate on scan findings, then delegate to the wrapped
        policy. ``findings`` is a list of mappings each carrying a
        ``severity`` in :data:`SEVERITIES`."""
        if not isinstance(artifact, dict):
            raise _adm.AdmissionError(
                _adm.CODE_MALFORMED, "artifact is not a dict")
        threshold_name, threshold_rank = self._threshold_for(artifact)
        if not isinstance(findings, list):
            raise _adm.AdmissionError(
                CODE_SEVERITY_UNVERIFIABLE,
                "no scan findings presented (never assumed benign)")
        for finding in findings:
            if not isinstance(finding, dict):
                raise _adm.AdmissionError(
                    CODE_SEVERITY_UNVERIFIABLE,
                    "finding is not a mapping: %r" % (finding,))
            rank = _severity_rank(finding.get("severity"))
            if rank is None:
                raise _adm.AdmissionError(
                    CODE_SEVERITY_UNVERIFIABLE,
                    "finding %r has unknown/unrated severity"
                    % (finding.get("id", "?"),))
            if rank > threshold_rank:
                raise _adm.AdmissionError(
                    CODE_SEVERITY_EXCEEDED,
                    "finding %r severity %r exceeds %r threshold %r"
                    % (finding.get("id", "?"),
                       finding.get("severity"),
                       artifact.get("class", artifact.get("format")),
                       threshold_name))
        return self._policy.admit(artifact, **kwargs)


class ImmutableTag(object):
    """Immutable artifact tags over a policy.

    ``tag_of`` maps an artifact to its tag string (e.g.
    ``"evidence-bundle/1:latest"``). The tag registry is in-memory;
    persistence is deployment-owned (documented above).
    """

    def __init__(self, policy, tag_of):
        if not callable(getattr(policy, "admit", None)):
            raise ValueError("policy has no callable admit()")
        if not callable(tag_of):
            raise ValueError("tag_of must be callable")
        self._policy = policy
        self._tag_of = tag_of
        self._tags = {}

    def admit(self, artifact, **kwargs):
        tag = self._tag_of(artifact)
        if not isinstance(tag, str) or not tag:
            raise _adm.AdmissionError(
                _adm.CODE_MALFORMED, "tag_of returned no tag string")
        digest = artifact.get("payload_digest") if isinstance(
            artifact, dict) else None
        if not _is_sha256_hex(digest):
            raise _adm.AdmissionError(
                _adm.CODE_MALFORMED,
                "artifact has no sha256 payload_digest")
        pinned = self._tags.get(tag)
        if pinned is not None and pinned != digest:
            raise _adm.AdmissionError(
                CODE_TAG_MUTATED,
                "tag %r was pinned to a different digest (refusing)"
                % (tag,))
        rec = self._policy.admit(artifact, **kwargs)
        self._tags[tag] = digest
        out = dict(rec)
        out["tag"] = tag
        return out
