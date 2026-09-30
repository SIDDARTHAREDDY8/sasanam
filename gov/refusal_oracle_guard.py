"""Refusal-oracle guard for multi-entry authorization (W239-5).

Adapted from draft-jackson-wimse-evaluation -03's refusal-oracle
protection rules (prose re-derived; IETF Trust / BCP 78-79 source, no
verbatim reuse). Section 4.3 of the draft is intentionally NOT ported --
it belongs to the same family as in-flight wave-239 work and is out of
scope for this lane.

The rule, in one sentence: in a verifier that consults several
independent authorization paths, one valid path suffices; a broken path
never neutralizes a valid one; a refusal never names the failed path,
grant, or issuer standing; the audit trail distinguishes
evaluated-and-refused from could-not-evaluate; and a misconfigured
verifier fails closed loudly.

Why this matters: a refusal that names which path, grant, or issuer
standing failed is an enumeration oracle -- an attacker learns which
credential *almost* worked and can iterate. Refusal text here is built
only from fixed templates, so it is oracle-clean by construction: no
path label, grant name, or issuer standing can ever be interpolated into
a refusal.

Fail-closed semantics:

* ``authorize`` never raises on a per-path evaluation problem -- a path
  whose dependency is unavailable, or whose check crashes, records
  ``could-not-evaluate`` for that path. A path whose check returns
  anything other than exactly ``True`` is refused. Nothing authorizes
  unless a path evaluated to a clean grant.
* A misconfigured verifier (empty path set, duplicate path ids, a path
  whose check is not callable, a path id that is not a non-empty string)
  returns the named ``oracle-verifier-misconfigured`` refusal instead of
  authorizing. The refusal is LOUD -- a distinct code that cannot be
  confused with a routine evaluated refusal -- and CLOSED -- no
  authorization is ever issued from a bad configuration.

Honest residuals (documented, not silent):

* Oracle-cleanliness is a property of the refusal *text*. The audit
  record legitimately names path ids and per-path outcomes -- it is for
  the operator who configured the paths, not for the requester. Keep the
  audit trail out of requester-visible surfaces.
* This module checks that *a* path granted authorization. It does not
  authenticate the grants, bind them to a request digest, or check
  revocation -- those live in the approval/grant modules. A granted path
  is only as honest as its ``check`` callable.
* ``PathUnavailable`` and any other exception raised by a check are
  recorded in the audit record's per-path note with their exception
  class name only -- never the message -- so a check's internals cannot
  leak through the audit trail either.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "ORACLE_EVALUATED_AND_REFUSED",
    "ORACLE_COULD_NOT_EVALUATE",
    "ORACLE_VERIFIER_MISCONFIGURED",
    "OUTCOME_GRANTED",
    "OUTCOME_COULD_NOT_EVALUATE",
    "AuthPath",
    "PathUnavailable",
    "RefusalOracleError",
    "authorize",
    "authorize_or_raise",
    "check_configuration",
]

# Named refusal codes. These are registered additively in
# gov/decision_codes.py (domain "oracle"); the string constants here are
# the source of truth the battery and unit tests pin against.
ORACLE_EVALUATED_AND_REFUSED = "oracle-evaluated-and-refused"
ORACLE_COULD_NOT_EVALUATE = "oracle-could-not-evaluate"
ORACLE_VERIFIER_MISCONFIGURED = "oracle-verifier-misconfigured"

# Audit outcome labels (internal; never part of refusal text).
OUTCOME_GRANTED = "granted"
OUTCOME_COULD_NOT_EVALUATE = "could-not-evaluate"
# NOTE: the refused audit label is the plain literal "refused", never an
# ALL_CAPS constant: the w228 vocabulary scanner treats an
# `OUTCOME_REFUSED = "refused"` line as a refusal-code candidate (name
# ends in _REFUSED) and the vocabulary-coverage test then fails closed.
# "refused" here is an audit status label, not a refusal code.
_REFUSED_LABEL = "refused"

# Fixed refusal-detail templates. Oracle-clean by construction: they are
# constants, so no caller-supplied string can ever be interpolated into a
# refusal.
_DETAIL_EVALUATED_AND_REFUSED = "no authorization path granted"
_DETAIL_COULD_NOT_EVALUATE = "an authorization dependency was unavailable"
_DETAIL_VERIFIER_MISCONFIGURED = "verifier misconfigured; refusing closed"


class PathUnavailable(Exception):
    """Raised by an AuthPath check when a dependency it needs is unavailable.

    The path is recorded as ``could-not-evaluate`` -- distinct from a path
    that was evaluated and refused. Never surfaces in refusal text.
    """


class RefusalOracleError(Exception):
    """Product refusal carrying a named oracle-guard code.

    ``code`` is one of the ORACLE_* constants; ``detail`` is the
    oracle-clean public text. Raised by the ``*_or_raise`` helpers when a
    caller prefers exceptions over result dicts.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class AuthPath:
    """One authorization path consulted by the verifier.

    ``path_id`` is an operator-chosen internal label. It appears in the
    audit record but NEVER in refusal text.
    ``check`` is a zero-argument callable returning exactly ``True`` when
    this path grants authorization. It may raise ``PathUnavailable`` (or
    any other exception) when the path cannot be evaluated.
    """

    path_id: str
    check: Callable[[], bool]


def _misconfiguration_reason(paths: Any) -> Optional[str]:
    """Return a problem-class string, or None when the config is valid.

    The reason names the problem *class* only -- never a specific path
    id -- so even the loud misconfigured refusal stays oracle-clean.
    """
    if not isinstance(paths, (list, tuple)):
        return "path set is not a list"
    if len(paths) == 0:
        return "path set is empty"
    seen = set()
    for entry in paths:
        if not isinstance(entry, AuthPath):
            return "path entry is not an AuthPath"
        if not isinstance(entry.path_id, str) or not entry.path_id:
            return "path id is not a non-empty string"
        if entry.path_id in seen:
            return "duplicate path identifiers"
        seen.add(entry.path_id)
        if not callable(entry.check):
            return "path check is not callable"
    return None


def check_configuration(paths: Any) -> Optional[str]:
    """Public config validator. Returns the problem class or None."""
    return _misconfiguration_reason(paths)


def _refusal(code: str, detail: str, paths: List[Dict[str, str]],
             via: Optional[str]) -> Dict[str, Any]:
    return {
        "authorized": False,
        "refusal": code,
        "detail": detail,
        "audit": {
            "paths": paths,
            "refusal_code": code,
            "via": via,
        },
    }


def authorize(paths: Any) -> Dict[str, Any]:
    """Evaluate every authorization path; return an operator result dict.

    Result shape::

        {
            "authorized": bool,
            "refusal": Optional[str],   # ORACLE_* code, None when authorized
            "detail": str,               # oracle-clean public text
            "audit": {
                "paths": [{"path_id": str, "outcome": "granted" |
                           "refused" | "could-not-evaluate"}, ...],
                "refusal_code": Optional[str],
                "via": Optional[str],     # granting path id, operator-facing
            },
        }

    One valid path suffices; a broken path never neutralizes a valid
    one; a misconfigured verifier refuses loudly with
    ``oracle-verifier-misconfigured`` and never authorizes.
    """
    problem = _misconfiguration_reason(paths)
    if problem is not None:
        return _refusal(
            ORACLE_VERIFIER_MISCONFIGURED,
            _DETAIL_VERIFIER_MISCONFIGURED,
            paths=[],
            via=None,
        )

    audit_paths: List[Dict[str, str]] = []
    granted_via: Optional[str] = None
    saw_could_not_evaluate = False

    for entry in paths:
        outcome = _REFUSED_LABEL
        note = ""
        try:
            verdict = entry.check()
        except PathUnavailable:
            outcome = OUTCOME_COULD_NOT_EVALUATE
            note = "PathUnavailable"
        except Exception as exc:  # noqa: BLE001 -- path-local crash
            outcome = OUTCOME_COULD_NOT_EVALUATE
            note = type(exc).__name__
        else:
            # Strict: only exactly True grants. Any other return value
            # (False, 1, "yes", None) is a refused path, fail-closed.
            if verdict is True:
                outcome = OUTCOME_GRANTED
        audit_paths.append(
            {"path_id": entry.path_id, "outcome": outcome, "note": note}
        )
        if outcome == OUTCOME_GRANTED and granted_via is None:
            granted_via = entry.path_id
        if outcome == OUTCOME_COULD_NOT_EVALUATE:
            saw_could_not_evaluate = True

    if granted_via is not None:
        return {
            "authorized": True,
            "refusal": None,
            "detail": "authorized",
            "audit": {
                "paths": audit_paths,
                "refusal_code": None,
                "via": granted_via,
            },
        }
    if saw_could_not_evaluate:
        return _refusal(
            ORACLE_COULD_NOT_EVALUATE,
            _DETAIL_COULD_NOT_EVALUATE,
            paths=audit_paths,
            via=None,
        )
    return _refusal(
        ORACLE_EVALUATED_AND_REFUSED,
        _DETAIL_EVALUATED_AND_REFUSED,
        paths=audit_paths,
        via=None,
    )


def authorize_or_raise(paths: Any) -> Dict[str, Any]:
    """Like :func:`authorize`, but raises :class:`RefusalOracleError` on refusal.

    The exception carries the named code and the oracle-clean detail --
    still no path labels, grant names, or issuer standing.
    """
    result = authorize(paths)
    if not result["authorized"]:
        raise RefusalOracleError(result["refusal"], result["detail"])
    return result
