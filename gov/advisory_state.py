"""Flaw-granular advisory state (W246-6, ADAPT).

The PyJWT lesson (verified 2026-09-30): PyJWT 2.14.0 fixed
GHSA-9v7f-9g4p-ffgj (CVE-2026-102267) but is still affected by
CVE-2026-101918. "Version 2.14.0 is clean" is therefore FALSE; the
honest answer is ``affected-by: CVE-2026-101918`` -- and, explicitly,
``clean-for: CVE-2026-102267``. A version-level "clean" verdict
hides residual flaws, and a bare ``clean`` is not expressible here
by design.

``assess_component(pinned, component, version, now)`` answers
component-version queries with flaw granularity:

- ``affected-by``: the version is inside a claimed affected range
  and below any published fix. ``cves`` lists the affecting flaws;
  ``clean_for`` lists the tracked flaws it is explicitly clean for.
- ``clean-for``: the version is at or above every published fix
  for the component (affirmative fix knowledge). ``cves`` is the
  EXPLICIT list of CVEs -- never a bare ``clean``.
- ``unknown``: the component is untracked, the version falls
  outside all tracked ranges without fix knowledge, or the version
  string cannot be evaluated. Fail-closed: the deployment MUST
  refuse on ``unknown``. It is an explicit verdict, never a silent
  pass.

Wiring (reuse, never redefine): the flaw advisory is consumed as
the PINNED record produced by
``gov.advisory_binding.bind_advisory_input`` -- canonical-byte
digest (tamper-evident), Ed25519 signature threshold, supersession,
freshness -- extended with a ``flaws`` list. ``bind_flaw_snapshot``
performs that bind and additionally proves the flaw list was inside
the signed canonical bytes (a flaw list swapped after signing
refuses). Advisory content is caller-supplied and untrusted:
malformed flaw data refuses ``advisory-input-malformed`` (new
taxonomy code), never silently. Staleness reuses
``chain-source-stale``; malformed query inputs reuse
``verifier-input-malformed``.

Honest residuals:
- This module checks binding, shape, freshness, and flaw logic; it
  cannot make an advisory honest. A lying advisory source is an
  attestation problem upstream (same residual as advisory_binding).
- ``clean-for`` is only as complete as the advisory's fix history;
  a flaw the advisory never tracked is invisible here.
- ``now`` is caller-supplied; no clock.
- Version comparison is dotted-numeric (``2.14.0``); anything else
  is ``version-not-evaluable`` -> ``unknown``, fail-closed.

Stdlib only (+ in-repo gov.advisory_binding, gov.ed25519 indirect).
Deterministic.
"""

import json
import re

from gov import advisory_binding as _ab

ADVISORY_INPUT_MALFORMED = "advisory-input-malformed"

# Reused from the existing taxonomy (not redefined here):
#   "chain-source-stale", "verifier-input-malformed"
_CHAIN_SOURCE_STALE = "chain-source-stale"
_VERIFIER_INPUT_MALFORMED = "verifier-input-malformed"

_STATE_AFFECTED = "affected-by"
_STATE_CLEAN_FOR = "clean-for"
_STATE_UNKNOWN = "unknown"

_REASON_COMPONENT = "component-not-tracked"
_REASON_VERSION = "version-not-covered"
_REASON_UNPARSEABLE = "version-not-evaluable"

_VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*$")
_SPEC_RE = re.compile(r"^(<=|>=|==|!=|<|>)(.+)$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class AdvisoryStateError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(AdvisoryStateError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise AdvisoryStateError(code, detail)


def _malformed_advisory(detail):
    _refuse(ADVISORY_INPUT_MALFORMED, detail)


def _malformed_query(detail):
    _refuse(_VERIFIER_INPUT_MALFORMED, detail)


def _nonempty_str(value, name, malformed):
    if isinstance(value, bool) or not isinstance(value, str) \
            or not value:
        malformed("%s must be a non-empty str" % name)
    return value


def _parse_version(text):
    """Parse a dotted-numeric version; None when not evaluable."""
    if not isinstance(text, str) or not _VERSION_RE.match(text):
        return None
    return tuple(int(p) for p in text.split("."))


def _cmp(va, vb):
    """Three-way compare of version tuples (zero-padded)."""
    n = max(len(va), len(vb))
    a = va + (0,) * (n - len(va))
    b = vb + (0,) * (n - len(vb))
    return (a > b) - (a < b)


def _parse_spec(spec):
    """Parse '<2.14.0' / '>=1.0.0, <2.0.0'; None when malformed."""
    if not isinstance(spec, str) or not spec.strip():
        return None
    clauses = []
    for part in spec.split(","):
        part = part.strip()
        m = _SPEC_RE.match(part)
        if not m:
            return None
        ver = _parse_version(m.group(2).strip())
        if ver is None:
            return None
        clauses.append((m.group(1), ver))
    return clauses or None


def _matches(version, clauses):
    for op, ref in clauses:
        c = _cmp(version, ref)
        if op == "<" and not c < 0:
            return False
        if op == "<=" and not c <= 0:
            return False
        if op == ">" and not c > 0:
            return False
        if op == ">=" and not c >= 0:
            return False
        if op == "==" and not c == 0:
            return False
        if op == "!=" and not c != 0:
            return False
    return True


def _check_flaw(flaw, index):
    """Validate one flaw entry; malformed advisory data refuses."""
    if not isinstance(flaw, dict):
        _malformed_advisory("flaws[%d] must be a dict" % index)
    cve = flaw.get("cve")
    if not isinstance(cve, str) or not _CVE_RE.match(cve):
        _malformed_advisory(
            "flaws[%d].cve must look like CVE-YYYY-NNNNN" % index)
    _nonempty_str(flaw.get("component"), "flaws[%d].component" % index,
                  _malformed_advisory)
    clauses = _parse_spec(flaw.get("affected"))
    if clauses is None:
        _malformed_advisory(
            "flaws[%d].affected must be a spec like '<2.14.0' or "
            "'>=1.0.0, <2.0.0'" % index)
    fixed_in = flaw.get("fixed_in")
    fixed = None
    if fixed_in is not None:
        fixed = _parse_version(fixed_in)
        if fixed is None:
            _malformed_advisory(
                "flaws[%d].fixed_in must be a dotted-numeric version "
                "or null" % index)
    return {"cve": cve, "component": flaw["component"],
            "clauses": clauses, "fixed": fixed}


def _check_flaws(flaws):
    if not isinstance(flaws, list) or not flaws:
        _malformed_advisory(
            "pinned advisory flaws must be a non-empty list")
    return [_check_flaw(f, i) for i, f in enumerate(flaws)]


def bind_flaw_snapshot(policy, snapshot, now):
    """Pin a flaw-level advisory snapshot.

    Binds via ``gov.advisory_binding.bind_advisory_input`` (digest,
    signature threshold, freshness -- reusing its codes), then
    validates the flaw-level CVE data and proves the flaw list was
    inside the signed canonical bytes: a flaw list swapped after
    signing refuses ``advisory-input-malformed``. Returns the pinned
    record with a validated ``flaws`` list attached.
    """
    pinned = _ab.bind_advisory_input(policy, snapshot, now)
    if not isinstance(snapshot, dict):
        _malformed_advisory("snapshot must be a dict")
    flaws = snapshot.get("flaws")
    canon = snapshot.get("canonical_bytes")
    if not isinstance(canon, (bytes, bytearray)):
        _malformed_advisory("snapshot canonical_bytes must be bytes")
    try:
        body = json.loads(bytes(canon).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _malformed_advisory(
            "snapshot canonical_bytes are not JSON: %s" % (exc,))
    if not isinstance(body, dict) or body.get("flaws") != flaws:
        _malformed_advisory(
            "flaw list was not inside the signed canonical bytes "
            "(possible post-signing swap)")
    checked = _check_flaws(flaws)
    pinned = dict(pinned)
    pinned["flaws"] = [
        {"cve": f["cve"], "component": f["component"],
         "affected": _spec_text(f), "fixed_in": _fixed_text(f)}
        for f in checked
    ]
    return pinned


def _spec_text(f):
    return ", ".join("%s%s" % (op, ".".join(str(n) for n in ver))
                     for op, ver in f["clauses"])


def _fixed_text(f):
    if f["fixed"] is None:
        return None
    return ".".join(str(n) for n in f["fixed"])


def _stale_refusal(pinned, now):
    fetched_at = pinned.get("fetched_at")
    freshness = pinned.get("freshness_seconds")
    if not isinstance(fetched_at, (int, float)) \
            or isinstance(fetched_at, bool):
        _malformed_advisory(
            "pinned advisory fetched_at must be a number")
    if isinstance(freshness, bool) or not isinstance(freshness, int):
        _malformed_advisory(
            "pinned advisory freshness_seconds must be an int")
    if not isinstance(now, (int, float)) or isinstance(now, bool):
        _malformed_query("now must be a number")
    if now > fetched_at + freshness:
        _refuse(_CHAIN_SOURCE_STALE,
                "flaw advisory snapshot is older than its %d-second "
                "freshness bound (explicit stale, never a silent pass)"
                % freshness)


def _unknown(reason, component, version, pinned, clean_for):
    return {
        "state": _STATE_UNKNOWN,
        "reason": reason,
        "component": component,
        "version": version,
        "advisory_id": pinned.get("advisory_id"),
        "advisory_version": pinned.get("version"),
        "clean_for": list(clean_for),
        "note": "unknown is fail-closed: the deployment MUST refuse; "
                "it is an explicit verdict, never a silent pass",
    }


def assess_component(pinned, component, version, now):
    """Assess one component version against a pinned flaw advisory.

    ``pinned`` is the record from ``bind_flaw_snapshot`` (flaw list
    validated and proven inside the signed bytes). Returns a verdict
    dict with flaw granularity; never a bare ``clean``. Malformed
    advisory data refuses ``advisory-input-malformed``; stale input
    refuses ``chain-source-stale`` (reused); malformed query inputs
    refuse ``verifier-input-malformed`` (reused).
    """
    if not isinstance(pinned, dict):
        _malformed_advisory("pinned advisory must be a dict")
    flaws = _check_flaws(pinned.get("flaws"))
    _stale_refusal(pinned, now)
    _nonempty_str(component, "component", _malformed_query)
    _nonempty_str(version, "version", _malformed_query)

    tracked = [f for f in flaws if f["component"] == component]
    if not tracked:
        return _unknown(_REASON_COMPONENT, component, version,
                        pinned, [])
    parsed = _parse_version(version)
    if parsed is None:
        return _unknown(_REASON_UNPARSEABLE, component, version,
                        pinned, [])

    affected = []
    clean_for = []
    uncovered = []
    for f in tracked:
        in_range = _matches(parsed, f["clauses"])
        fixed = f["fixed"]
        if in_range and (fixed is None or _cmp(parsed, fixed) < 0):
            affected.append(f["cve"])
        elif fixed is not None and _cmp(parsed, fixed) >= 0:
            clean_for.append(f["cve"])
        else:
            uncovered.append(f["cve"])

    base = {
        "component": component,
        "version": version,
        "advisory_id": pinned.get("advisory_id"),
        "advisory_version": pinned.get("version"),
    }
    if affected:
        base.update({
            "state": _STATE_AFFECTED,
            "cves": list(affected),
            "clean_for": list(clean_for),
        })
        return base
    if uncovered:
        base.update({
            "state": _STATE_UNKNOWN,
            "reason": _REASON_VERSION,
            "cves": list(uncovered),
            "clean_for": list(clean_for),
            "note": "version falls outside all tracked ranges with "
                    "no published fix: no affirmative clean knowledge; "
                    "fail-closed, the deployment MUST refuse",
        })
        return base
    base.update({
        "state": _STATE_CLEAN_FOR,
        "cves": list(clean_for),
    })
    return base
