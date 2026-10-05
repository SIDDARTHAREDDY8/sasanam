#!/usr/bin/env python3
"""OCI registry onboarding gate (R25): certify a deployment's registry
endpoint BEFORE it distributes evidence bundles through it.

Wave-339 lane 3 (R25 of the w338 research prospectus): the trust-matrix
half of the "sell evidence" distribution story. The transport
(:mod:`gov.oci_referrer`) is built; this module answers the deployment
question "may I use THIS registry with THIS distribution path?"

The gate has two inputs and never one:

1. A LIVE PROBE of the registry's Referrers API (pacto's method,
   Apache-2.0 -- method described, nothing copied): ``GET
   /v2/<repo>/referrers/<digest>`` against an empty subject digest::

       200 + parseable index  => the registry speaks the Referrers API
       404/400                => no Referrers API (OUT for our transport;
                                 the tag scheme is never a fallback)
       anything else          => inconclusive (401/403/5xx, transport
                                 failure -- OUT until verified)

2. REGISTRY_TRUST_MATRIX below: the human-reviewed IN/OUT table
   (w338 prospectus section 3, 2026-10-05). The live probe alone never
   certifies: a 200 from a host the matrix marks OUT (GHCR) or a host the
   matrix does not know is refused fail-closed. Re-probe on registry
   upgrades -- Docker Hub flipped from OUT to IN ~2026-09; the matrix is
   the second, human-reviewed signal.

HARBOR SPECIAL RULE. The matrix marks Harbor hosts CONDITIONAL: the
"push" path (direct push / ``oras copy``) is IN -- referrers are
first-class (#22592, #22643 closed) -- but the "replication" path is
OUT: Harbor's Replication Service silently drops referrer manifests
(goharbor #23210 still open, `kind/bug`, `needs/follow-up`, revived
2026-10-03; no fix). Reads MUST NOT go through a Harbor replica and
MUST NOT rely on replication to carry referrers. The deployment declares
``distribution_path``; the gate refuses ``replication`` fail-closed.

SAME-REPOSITORY PINNING. Discovery must never chase referrers across a
repository or replication boundary -- the graph does not survive
silently (#23210 proves it). :func:`check_same_repository` refuses when
the (base_url, repository) pair used for discovery differs from the one
used at attach time.

FAIL-CLOSED RULES (prospectus section 3, codified):
  1. No implicit I/O: the caller supplies the transport; the gate never
     dials on its own (same contract as :mod:`gov.oci_referrer`).
  2. Probe inconclusive => OUT (refuse, do not certify).
  3. Probe supported + matrix OUT/unknown => OUT (the matrix disagrees
     with the live probe -- fail closed, re-probe, update the matrix).
  4. Probe unsupported + matrix IN => OUT (regression -- the registry
     lost its Referrers API; fail closed, re-probe).
  5. Harbor replication path => OUT.
  6. The gate certifies DISTRIBUTION PATHS only. Bundle authenticity is
     never a registry verdict: the offline verifier
     (:mod:`gov.sigstore_bundle` / :mod:`gov.evidence_verify_offline`)
     decides; a registry "verified" badge is not an input to any
     authenticity verdict. (Harbor UI never shows referrer-attached
     signatures as verified -- this is expected, not a defect.)

Unknown registries are OUT until a human records them. A deployment may
pass ``matrix_override`` (one registry_kind entry in matrix shape) to
record a private registry (e.g. a self-hosted Zot); the override is an
explicit deployment decision, not an inference.
"""

import json

from gov.oci_referrer import (
    OCIReferrerError,
    _repo_url,
    _send,
    is_canonical_digest,
)

#: Probe digest: sha256 of the empty string. A subject with no referrers
#: attached -- the pacto "empty subject" probe. 200 + empty index means
#: the API is present; the subject itself is meaningless.
EMPTY_SUBJECT_PROBE_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

#: Coded refusal emitted by this gate's verdicts. Registered in
#: ``gov/decision_codes.py`` (domain ``oci``).
ONBOARDING_REFUSED_CODE = "oci-registry-onboarding-refused"


class OCIRegistryGateRefusal(Exception):
    """Coded fail-closed refusal from the onboarding gate.

    ``code`` is ``oci-registry-onboarding-refused``; ``detail`` names the
    probe result, the matrix expectation, and what the operator must do.
    """

    def __init__(self, code, detail):
        super(OCIRegistryGateRefusal, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(detail):
    raise OCIRegistryGateRefusal(ONBOARDING_REFUSED_CODE, detail)


# ---------------------------------------------------------------------------
# Registry trust matrix (w338 prospectus section 3, 2026-10-05).
# ---------------------------------------------------------------------------
#
# status: "in"           -- Referrers API confirmed; certified-in possible.
#         "out"          -- no Referrers API; OUT for this transport.
#         "conditional"  -- IN/OUT depends on ``paths``: distribution path
#                           name -> "in"/"out".
# Re-probe on registry upgrades. Docker Hub flipped 2026-09; the matrix
# entry records the date so drift is visible.

REGISTRY_TRUST_MATRIX = {
    "zot": {
        "status": "in",
        "notes": "Native Referrers API endpoint; live-probed 200 + empty "
                 "index; `zot sync` preserves the referrer graph. "
                 "Apache-2.0.",
        "probed": "2026-10-05",
    },
    "harbor": {
        "status": "conditional",
        "paths": {
            "push": "in",          # direct push / `oras copy`
            "replication": "out",  # Replication Service drops referrers
        },
        "notes": "Direct push first-class (goharbor #22592, #22643 "
                 "closed; PRs #22628, #23029, #23237 merged). Harbor "
                 "Replication Service does NOT replicate referrer "
                 "manifests (goharbor #23210 OPEN, kind/bug, "
                 "needs/follow-up, revived 2026-10-03). Deployments MUST "
                 "push directly to the registry the auditor reads; reads "
                 "MUST NOT go through a replica.",
        "probed": "2026-10-05",
    },
    "docker-hub": {
        "status": "in",
        "notes": "Flipped to YES ~2026-09 (live-probed; cosign v3 "
                 "referrers verified working). Older 'no' reports are "
                 "stale. RE-PROBE on any Docker Hub change.",
        "probed": "2026-10-05",
    },
    "ghcr": {
        "status": "out",
        "notes": "404 MANIFEST_UNKNOWN on the referrers endpoint "
                 "(cosign#4641).",
        "probed": "2026-10-05",
    },
    "ecr": {
        "status": "in",
        "notes": "Direct PUT works. Caveat: `oras copy -r` of referrer "
                 "manifests returns 405 (aws/containers-roadmap#2783) -- "
                 "use direct push, not recursive oras copy.",
        "probed": "2026-10-05",
    },
    "acr": {
        "status": "in",
        "notes": "Referrers API supported.",
        "probed": "2026-10-05",
    },
    "acr-cmk": {
        "status": "out",
        "notes": "CMK-encrypted Azure Container Registries serve the "
                 "referrers endpoint via tag-schema fallback only -- OUT "
                 "for the digest-only referrer transport.",
        "probed": "2026-10-05",
    },
    "artifactory": {
        "status": "in",
        "notes": "JFrog Artifactory >= 7.90.1 (vendor docs).",
        "probed": "2026-10-05",
    },
    "quay": {
        "status": "in",
        "notes": "Announced + implemented (quay/quay#6385). Caveat: "
                 "fallback-tag merge semantics -- digest-only pulls are "
                 "unaffected.",
        "probed": "2026-10-05",
    },
    "gar": {
        "status": "in",
        "notes": "Google Artifact Registry (vendor docs + matrix "
                 "confirmation).",
        "probed": "2026-10-05",
    },
    "cncf-distribution": {
        "status": "out",
        "notes": "CNCF distribution (registry:2/3): no Referrers API "
                 "route at all.",
        "probed": "2026-10-05",
    },
}

REGISTRY_KINDS = tuple(sorted(REGISTRY_TRUST_MATRIX))


def _matrix_entry(registry_kind, matrix_override=None):
    """Return the matrix entry for a registry kind, or None.

    ``matrix_override`` is a single ``{kind: entry}``-shaped dict the
    deployment supplies to record a private registry. It may only ADD
    knowledge for a kind the matrix does not know -- it can never flip an
    "out"/"conditional" entry to "in" (fail closed: the research matrix
    outranks a deployment annotation for known-hostile paths).
    """
    entry = REGISTRY_TRUST_MATRIX.get(registry_kind)
    if entry is not None:
        return dict(entry)
    if matrix_override:
        override = matrix_override.get(registry_kind)
        if isinstance(override, dict) and override.get("status") == "in":
            return dict(override)
    return None


def _matrix_allows(entry, distribution_path):
    """Resolve a matrix entry + distribution path to 'in'/'out'/'unknown'.

    "unknown" means the matrix entry exists but does not speak to this
    distribution path -- fail closed downstream.
    """
    status = entry.get("status")
    if status == "in":
        return "in"
    if status == "out":
        return "out"
    if status == "conditional":
        return entry.get("paths", {}).get(distribution_path, "unknown")
    return "unknown"


def probe_referrers_api(transport, base_url, repository,
                        probe_digest=EMPTY_SUBJECT_PROBE_DIGEST,
                        auth_token=None):
    """Live-probe a registry's Referrers API (pacto's method).

    Sends ``GET /v2/<repo>/referrers/<digest>`` against the empty-subject
    probe digest. Returns ``(result, detail)`` where result is one of::

        "supported"    -- 200 and the body parses as an index document
                           with a "referrers" list (empty or not).
        "unsupported"  -- 404/400: the registry has no Referrers API.
        "inconclusive" -- anything else: auth failures (401/403), server
                           errors, malformed 200 bodies, transport
                           failures. OUT until verified -- never certified.

    ``auth_token`` is passed through to the probe request only; a probe
    without a token that gets a 401 is "inconclusive", not "unsupported".
    """
    if not is_canonical_digest(probe_digest):
        raise ValueError("probe_digest must be a canonical digest, got %r"
                         % (probe_digest,))
    headers = {"Accept": "application/vnd.oci.image.index.v1+json"}
    if auth_token:
        headers["Authorization"] = "Bearer " + auth_token
    url = _repo_url(base_url, repository, "referrers", probe_digest)
    try:
        status, _, body = _send(transport, "GET", url, headers, None)
    except OCIReferrerError as exc:
        return ("inconclusive", "transport failure during probe: %s" % exc)
    if status in (404, 400):
        return ("unsupported",
                "registry returned HTTP %d on the referrers endpoint -- "
                "no Referrers API" % status)
    if status in (401, 403):
        return ("inconclusive",
                "registry returned HTTP %d -- authentication required; "
                "re-probe with an auth_token" % status)
    if status != 200:
        return ("inconclusive",
                "registry returned unexpected HTTP %d on the referrers "
                "endpoint" % status)
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ("inconclusive",
                "HTTP 200 but the referrers body is not JSON")
    if not isinstance(doc, dict) or not isinstance(doc.get("referrers"),
                                                    list):
        return ("inconclusive",
                "HTTP 200 but the body is not an index document with a "
                "'referrers' list")
    return ("supported",
            "registry speaks the Referrers API (HTTP 200, index document, "
            "%d existing referrer(s) on the probe subject)"
            % len(doc["referrers"]))


def onboard_registry(transport, base_url, repository, *, registry_kind,
                     distribution_path="push", matrix_override=None,
                     probe_digest=EMPTY_SUBJECT_PROBE_DIGEST,
                     auth_token=None):
    """Certify a deployment's registry endpoint for evidence distribution.

    Combines the live probe with the trust matrix. Returns a verdict
    dict::

        {"verdict": "certified-in" | "refused",
         "registry_kind": ..., "distribution_path": ...,
         "probe": "supported" | "unsupported" | "inconclusive",
         "matrix": "in" | "out" | "unknown",
         "code": "oci-registry-onboarding-refused" | None,
         "detail": str}

    "certified-in" requires probe == "supported" AND matrix == "in".
    Every other combination is "refused" fail-closed with a coded detail.
    """
    entry = _matrix_entry(registry_kind, matrix_override)
    matrix = "unknown" if entry is None else _matrix_allows(
        entry, distribution_path)
    probe, probe_detail = probe_referrers_api(
        transport, base_url, repository, probe_digest, auth_token)

    def refused(detail):
        return {
            "verdict": "refused",
            "registry_kind": registry_kind,
            "distribution_path": distribution_path,
            "probe": probe,
            "matrix": matrix,
            "code": ONBOARDING_REFUSED_CODE,
            "detail": detail,
        }

    if entry is None:
        return refused(
            "registry kind %r is not in the trust matrix and no "
            "matrix_override recorded it; refusing fail-closed. Record a "
            "private registry explicitly via matrix_override. Probe: %s."
            % (registry_kind, probe_detail))
    if probe == "inconclusive":
        return refused(
            "could not verify the Referrers API for registry kind %r: %s. "
            "OUT until verified; re-probe with credentials if the registry "
            "requires auth." % (registry_kind, probe_detail))
    if matrix == "unknown":
        return refused(
            "the trust matrix does not cover distribution path %r for "
            "registry kind %r; refusing fail-closed. Probe: %s."
            % (distribution_path, registry_kind, probe_detail))
    if probe == "supported" and matrix == "in":
        return {
            "verdict": "certified-in",
            "registry_kind": registry_kind,
            "distribution_path": distribution_path,
            "probe": probe,
            "matrix": matrix,
            "code": None,
            "detail": "live probe confirms the Referrers API and the "
                      "trust matrix allows registry kind %r via path %r. "
                      "Certifies the DISTRIBUTION PATH only -- bundle "
                      "authenticity remains the offline verifier's job."
                      % (registry_kind, distribution_path),
        }
    if probe == "supported" and matrix == "out":
        return refused(
            "live probe returned 200 but the trust matrix marks registry "
            "kind %r OUT (%s). The probe may be spoofed or the registry "
            "may have upgraded -- fail closed: re-probe, verify against "
            "primary sources, and update the matrix before certifying. "
            "Probe: %s."
            % (registry_kind, entry.get("notes", ""), probe_detail))
    if probe == "unsupported" and matrix == "out":
        return refused(
            "registry kind %r has no Referrers API (%s); the tag scheme is "
            "never a fallback. OUT for the digest-only referrer "
            "transport." % (registry_kind, probe_detail))
    if probe == "unsupported" and matrix == "in":
        return refused(
            "registry kind %r is matrix-IN but the live probe found no "
            "Referrers API (%s) -- the registry regressed or the endpoint "
            "changed. Fail closed: re-probe (Docker Hub's flip is the "
            "cautionary tale) and do not distribute until certified."
            % (registry_kind, probe_detail))
    # Defensive: any unenumerated combination refuses.
    return refused(
        "unenumerated probe/matrix combination (probe=%r, matrix=%r); "
        "refusing fail-closed." % (probe, matrix))


def check_same_repository(attach_base_url, attach_repository,
                          discover_base_url, discover_repository):
    """Enforce same-repository pinning across attach and discovery.

    The referrer graph does not survive a repository or replication
    boundary silently (Harbor #23210). A deployment that discovers from
    a different (base_url, repository) than it attached to has a broken
    distribution path -- refuse coded, fail closed.
    """
    def norm(url):
        return url.rstrip("/").lower()
    if (norm(attach_base_url) != norm(discover_base_url)
            or attach_repository != discover_repository):
        _refuse("same-repository pinning violated: attached to %r/%r but "
                "discovering from %r/%r -- the referrer graph does not "
                "survive a repository/replication boundary; refusing "
                "fail-closed"
                % (attach_base_url, attach_repository,
                   discover_base_url, discover_repository))
    return True


def matrix_host_hint(registry_kind):
    """Return the matrix entry's notes for a kind (documentation aid)."""
    entry = _matrix_entry(registry_kind)
    if entry is None:
        return None
    return entry.get("notes")
