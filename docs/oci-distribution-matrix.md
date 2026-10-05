# OCI Distribution Trust Matrix — runbook

Wave-339 lane 3 (R25 of the w338 research prospectus, §3). Companion to
`gov/oci_registry_gate.py`, which implements this document as a checkable
onboarding gate (`onboard_registry`).

## The trust matrix (2026-10-05, primary sources)

| Registry | Status | Notes |
|---|---|---|
| Zot | IN | Native Referrers API; live-probed 200 + empty index; `zot sync` preserves the referrer graph |
| Harbor — direct push / `oras copy` | IN | UI gap closed (goharbor #22592, #22643; PRs #22628, #23029, #23237) |
| Harbor — Replication Service | **OUT** | **goharbor #23210 still OPEN** (`kind/bug`, `needs/follow-up`, revived 2026-10-03): referrer manifests are silently dropped |
| Docker Hub | IN | Flipped to YES ~2026-09 (live-probed; cosign v3 referrers working). Older "no" reports are stale. **Re-probe on any Docker Hub change.** |
| Amazon ECR | IN | Direct PUT. Caveat: `oras copy -r` of referrer manifests returns 405 (aws/containers-roadmap#2783) — use direct push, not recursive oras copy |
| Azure ACR | IN | Referrers API supported |
| Azure ACR (CMK-encrypted) | **OUT** | Tag-schema fallback only — OUT for the digest-only referrer transport |
| JFrog Artifactory ≥ 7.90.1 | IN | Vendor docs |
| Quay.io | IN | Announced + implemented (quay/quay#6385). Caveat: fallback-tag merge semantics — digest-only pulls unaffected |
| Google Artifact Registry | IN | Vendor docs + matrix confirmation |
| GHCR | **OUT** | 404 MANIFEST_UNKNOWN on the referrers endpoint (cosign#4641) |
| CNCF distribution (`registry:2/3`) | **OUT** | No Referrers API route at all |

**Re-probe on registry upgrades.** Docker Hub's flip is the cautionary
tale: the matrix is a human-reviewed snapshot; the onboarding gate's live
probe is the second signal. A probe that disagrees with the matrix in
either direction refuses fail-closed until a human re-verifies against
primary sources and updates the matrix.

## Onboarding a registry (the gate)

```python
from gov import oci_registry_gate as G

verdict = G.onboard_registry(
    transport,                      # caller-supplied (never implicit I/O)
    "https://harbor.example.com",   # base_url
    "evidence",                     # repository
    registry_kind="harbor",         # one of G.REGISTRY_KINDS
    distribution_path="push",       # "push" | "replication" | ...
)
assert verdict["verdict"] == "certified-in", verdict  # else do not distribute
```

The probe (`GET /v2/<repo>/referrers/<digest>` on the empty-subject probe
digest — pacto's method):

- `200` + parseable index document → Referrers API present (candidate IN)
- `404`/`400` → no Referrers API → OUT for this transport (the tag scheme is never a fallback)
- anything else (401/403/5xx, transport failure, non-JSON 200) → inconclusive → OUT until verified

Certification requires **probe supported AND matrix IN**. Every other
combination refuses fail-closed with the coded
`oci-registry-onboarding-refused` detail.

Private registries (e.g. a self-hosted Zot): record them explicitly via
`matrix_override={kind: {status: "in", notes, probed}}`. An override can
only ADD knowledge for an unknown kind — it can never flip a matrix
"OUT"/"CONDITIONAL" entry to "IN" (the research matrix outranks a
deployment annotation for known-hostile paths).

## Harbor rule (non-negotiable)

- Deployments MUST push referrers **directly** to the registry the
  auditor reads (`distribution_path="push"`; `oras copy` allowed).
- Reads MUST NOT go through a Harbor replica and MUST NOT rely on
  replication to carry referrers. The gate refuses
  `distribution_path="replication"` for Harbor fail-closed.
- The Harbor UI never shows referrer-attached signatures as verified —
  this is expected, not a defect.

## Same-repository pinning

Never chase referrers across a repository or replication boundary — the
graph does not survive silently (#23210 proves it). The (base_url,
repository) used for discovery must equal the one used at attach time;
`check_same_repository` refuses coded otherwise.

## What the gate does NOT certify

The gate certifies **distribution paths only**. Bundle authenticity is
never a registry verdict: the auditor verifies the pulled bundle with
the offline verifier (`gov.sigstore_bundle.verify_keyed_bundle` /
`gov.evidence_verify_offline`), never a registry badge. A
registry-supplied "verified" annotation is not an input to any verdict.

## Fail-closed rules (codified in `gov/oci_registry_gate.py`)

1. No implicit I/O: caller-supplied transport only.
2. Probe inconclusive → OUT.
3. Probe supported + matrix OUT/unknown → OUT (matrix disagrees with the
   live probe — spoofed probe or unrecorded upgrade).
4. Probe unsupported + matrix IN → OUT (regression — re-probe).
5. Harbor replication path → OUT.
6. Unknown registry kind → OUT until a human records it.
7. The registry is never an input to an authenticity verdict (offline
   verifier decides).
