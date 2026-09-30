#!/usr/bin/env python3
"""Wave-238 lane B: bundle-verification invariant (witness GHSA-2v4r steal).

Invariant: ANY failed verify sub-step hard-fails the whole bundle
verification, NAMING the failing check. Never swallow a failed sub-check
into a passing bundle.

Adapted from the in-toto/go-witness v0.12.0 advisory mechanisms
(prose re-derive, Apache-2.0 pattern only):

* GHSA-2v4r-xhmm-ghv8 (High): policy-signature verification accepted a
  certificate whose signature had failed -- identity constraints matched,
  signature never verified. Fix: filter any CheckedVerifier with
  Error != nil before deriving trust. Our probe: an attempt with
  identity_ok=True but sig_ok=False MUST refuse
  ``verify-signature-failed``, never confer trust.
* GHSA-v6px-jqx8-8xwj: symlink escaping the attested root.
* GHSA-vmvj-p3hw-39q3: artifactsFrom edge with zero genuine flow.
* GHSA-5qp5-ph6r-qj9f: timestamp signer without the sole critical
  id-kp-timeStamping EKU.
* GHSA-r4fv-8r9j-vgcg: duplicated attestor type, only the last instance
  evaluated (shadowing).
* GHSA-g9jx-rqhm-mj7g: empty collection name matched any step.
* GHSA-pgpm-j729-qcvh: cross-step comparison downgraded to SHA-1.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-237 HEAD dcfd52d2ecbacce8eff0cb5ee27f6332cb103dee.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g238b
  TMPDIR=/var/tmp/g238b ~/workspace/.gov-venv/bin/python \
      evals/w238_bundle_verify_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import bundle_verify_invariant as _bvi
    HAVE_NEW_API = all(hasattr(_bvi, n) for n in (
        "BundleInvariantError", "verify_policy_signature",
        "verify_symlink_safety", "verify_artifact_flow",
        "verify_timestamp_eku", "verify_attestor_completeness",
        "verify_collection_binding", "verify_hash_strength",
        "run_bundle_invariants", "verify_bundle_invariants"))
except ImportError:
    _bvi = None

PROBE_NAMES = [
    "bundleverify-policy-sig-failed",
    "bundleverify-symlink-escape",
    "bundleverify-artifactsfrom-empty",
    "bundleverify-timestamp-eku-missing",
    "bundleverify-attestor-shadowed",
    "bundleverify-collection-empty-match",
    "bundleverify-hash-downgrade",
    "bundleverify-clean-passes",
]


def _expect_code(fn, code):
    """Run fn; HELD iff an exception with the exact machine code is
    raised, else BREAK/ERROR."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never masks
        got = getattr(exc, "code", None)
        if got == code:
            return "HELD", "refused with %r" % (code,)
        return ("ERROR" if got is None else "BREAK",
                "expected code %r, got %r (%s)" % (code, got, exc))
    return "BREAK", "expected refusal %r but the call passed" % (code,)


def _attestations(**kw):
    """Fixture attestation sections, one clean and one corrupted."""
    base = {
        "policy_signatures": [
            {"identity_ok": True, "sig_ok": True, "error": None}],
        "artifacts": [
            {"path": "build/out.bin", "is_symlink": False, "target": None}],
        "attestation_root": "/attest",
        "edges": [
            {"edge": "build->publish",
             "shared_digests": {"sha256": "ab" * 32}}],
        "timestamps": [
            {"eku": ["1.3.6.1.5.5.7.3.8"],
             "critical": ["1.3.6.1.5.5.7.3.8"]}],
        "attestors": [
            {"type": "file",
             "instances": [{"id": "file-1", "evaluated": True}]}],
        "steps": [{"collection": "build"}],
        "collection": "build",
        "hash_comparisons": [
            {"digests_a": {"sha256": "ab" * 32},
             "digests_b": {"sha256": "ab" * 32},
             "compared_with": "sha256"}],
    }
    base.update(kw)
    return base


def probe_policy_sig_failed():
    # GHSA-2v4r shape: the trusted identity's certificate is attached
    # but its signature bytes are garbage (sig_ok=False). Identity
    # constraints match -- this must NEVER confer trust.
    forged = _attestations(policy_signatures=[
        {"identity_ok": True, "sig_ok": False, "error": "sig bytes garbage"},
        {"identity_ok": False, "sig_ok": True, "error": None},
    ])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(forged),
        "verify-signature-failed")


def probe_symlink_escape():
    evil = _attestations(artifacts=[
        {"path": "build/../etc/passwd", "is_symlink": True,
         "target": "/attest/build/../../etc/passwd"}])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(evil),
        "verify-symlink-escape")


def probe_artifactsfrom_empty():
    hollow = _attestations(edges=[
        {"edge": "build->publish", "shared_digests": {}}])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(hollow),
        "verify-artifactsfrom-empty")


def probe_timestamp_eku_missing():
    sloppy = _attestations(timestamps=[
        {"eku": ["1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.3"],
         "critical": ["1.3.6.1.5.5.7.3.3"]}])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(sloppy),
        "verify-timestamp-eku-missing")


def probe_attestor_shadowed():
    shadow = _attestations(attestors=[
        {"type": "file",
         "instances": [{"id": "file-malicious", "evaluated": False},
                       {"id": "file-benign", "evaluated": True}]}])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(shadow),
        "verify-attestor-shadowed")


def probe_collection_empty_match():
    sloppy = _attestations(steps=[{"collection": ""}], collection="")
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(sloppy),
        "verify-collection-empty-match")


def probe_hash_downgrade():
    weak = _attestations(hash_comparisons=[
        {"digests_a": {"sha1": "cd" * 20, "sha256": "ab" * 32},
         "digests_b": {"sha1": "cd" * 20, "sha256": "ab" * 32},
         "compared_with": "sha1"}])
    return _expect_code(
        lambda: _bvi.verify_bundle_invariants(weak),
        "verify-hash-downgrade")


def probe_clean_passes():
    try:
        ok, code, detail = _bvi.run_bundle_invariants(_attestations())
    except Exception as exc:  # noqa: BLE001
        return "ERROR", "clean fixture raised: %r" % (exc,)
    if ok and code is None:
        return "HELD", "clean bundle passes every sub-check"
    return "BREAK", "clean fixture failed: %r %s" % (code, detail)


_PROBES = {
    "bundleverify-policy-sig-failed": probe_policy_sig_failed,
    "bundleverify-symlink-escape": probe_symlink_escape,
    "bundleverify-artifactsfrom-empty": probe_artifactsfrom_empty,
    "bundleverify-timestamp-eku-missing": probe_timestamp_eku_missing,
    "bundleverify-attestor-shadowed": probe_attestor_shadowed,
    "bundleverify-collection-empty-match": probe_collection_empty_match,
    "bundleverify-hash-downgrade": probe_hash_downgrade,
    "bundleverify-clean-passes": probe_clean_passes,
}


def main():
    results = []
    for name in PROBE_NAMES:
        if not HAVE_NEW_API:
            results.append((name, "GAP",
                            "gov.bundle_verify_invariant absent"))
            continue
        try:
            verdict, detail = _PROBES[name]()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        results.append((name, verdict, detail))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, detail in results:
        print("%s %s -- %s" % (name, verdict, detail))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR of %d"
          % (held, gap, brk, err, len(results)))
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
