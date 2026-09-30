"""Wave-248 ORAS-artifact probes: break-first pins for gov/artifact_pack.py.

Break-first discipline (diagnosing-bugs skill): each probe drives the
ACTUAL pack/verify code path and asserts the attacker's exact win
condition or the digest-is-identity property. A probe that goes red
(BREAK/GAP) on the pristine base is the missing capability; after the
build every probe must go green (HELD).

Attack shapes (ORAS/OCI threat model, local-only):
  tampered_blob      - mutate a blob after pack; verify must refuse
  missing_blob       - drop a blob; verify must refuse
  extra_blob         - add an unlisted blob; verify must refuse
  size_lie           - manifest size field disagrees with bytes
  manifest_tamper    - swap a digest inside the manifest; the artifact
                       digest must no longer match (digest-is-identity)
  unknown_type       - manifest with an unregistered artifactType
  malformed_manifest - manifest missing structural keys
  bad_blob_name      - NUL / non-str / empty blob name at pack time

Properties pinned:
  roundtrip, determinism, byte-flip changes digest, order independence,
  digest shape, annotations preserved, evidence/skill wire round-trips.

RED run (2026-09-30, pristine b7558f5): 0/18 HELD, 18 GAP
  (gov.artifact_pack absent -- the capability does not exist).
GREEN run: 18/18 HELD (staging and env -u GOV_DEPLOYMENT_MODE).

Hygiene: module-level staging setdefault; no in-repo git subprocesses;
fresh TMPDIR per run; stdlib only. Green check is depth-1 and honors
GOV_SKIP_GREEN (runs the lane's own unit tests, never another battery).
"""

import hashlib
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from gov import artifact_pack as ap
    _IMPORT_ERROR = None
except Exception as exc:  # pristine base: capability absent
    ap = None
    _IMPORT_ERROR = exc


# ---------------------------------------------------------------------------
# Probe harness
# ---------------------------------------------------------------------------

def _run(name, fn):
    """Run one probe. Returns (name, verdict, evidence)."""
    if _IMPORT_ERROR is not None:
        return (name, "GAP",
                "gov.artifact_pack absent: %r" % (_IMPORT_ERROR,))
    try:
        verdict, evidence = fn()
    except AssertionError as exc:
        return (name, "GAP", "assertion failed: %s" % (exc,))
    except Exception as exc:  # probe harness error, not a product verdict
        return (name, "ERROR", "%r" % (exc,))
    return (name, verdict, evidence)


def _held(evidence):
    return ("HELD", evidence)


def _sample_blobs():
    return {
        "record-0000.json": b'{"seq": 0, "decision": "deny"}',
        "record-0001.json": b'{"seq": 1, "decision": "allow"}',
        "policy.txt": b"forbid-overrides-permit\n",
    }


def _expect_refusal(fn, code):
    """Assert fn() raises ArtifactPackError with the exact taxonomy code."""
    try:
        fn()
    except ap.ArtifactPackError as exc:
        assert exc.code == code, \
            "wrong code: %r, want %r (detail: %s)" % (
                exc.code, code, exc.detail)
        return _held("refused with %s" % code)
    raise AssertionError("no refusal raised; want %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_pack_unpack_roundtrip():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(
        blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE,
        annotations={"org.sasanam.wave": "248"})
    out = ap.unpack(manifest, dict(blobs), digest)
    assert out == blobs, "round-trip bytes differ"
    return _held("3 blobs round-tripped byte-identical")


def p_digest_deterministic():
    blobs = _sample_blobs()
    _, d1 = ap.pack(blobs, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    _, d2 = ap.pack(blobs, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    assert d1 == d2, "same blobs gave different digests"
    return _held("digest %s... stable" % d1[:19])


def p_digest_changes_on_byte_flip():
    blobs = _sample_blobs()
    _, d1 = ap.pack(blobs, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    evil = dict(blobs)
    evil["policy.txt"] = b"forbid-overrides-permit\r\n"  # 1-byte flip
    _, d2 = ap.pack(evil, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    assert d1 != d2, "byte flip did not change the artifact digest"
    return _held("1-byte flip changes digest (identity binds content)")


def p_tampered_blob_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    evil = dict(blobs)
    evil["record-0000.json"] = b'{"seq": 9, "decision": "deny"}'
    return _expect_refusal(
        lambda: ap.verify(manifest, evil, digest),
        "artifact-blob-tampered")


def p_missing_blob_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    fewer = dict(blobs)
    del fewer["policy.txt"]
    return _expect_refusal(
        lambda: ap.verify(manifest, fewer, digest),
        "artifact-blob-missing")


def p_extra_blob_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    more = dict(blobs)
    more["smuggled.bin"] = b"not in the manifest"
    return _expect_refusal(
        lambda: ap.verify(manifest, more, digest),
        "artifact-blob-extra")


def p_size_lie_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    # Lie in the manifest: correct digest, wrong size for policy.txt.
    import copy
    lied = copy.deepcopy(manifest)
    for entry in lied["blobs"]:
        if entry["name"] == "policy.txt":
            entry["size"] = entry["size"] + 100
    lied_digest = ap.manifest_digest(lied)
    return _expect_refusal(
        lambda: ap.verify(lied, dict(blobs), lied_digest),
        "artifact-size-mismatch")


def p_manifest_tamper_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    # Swap one blob digest inside the manifest, keep the old artifact
    # digest: the manifest no longer binds what was packed.
    import copy
    tampered = copy.deepcopy(manifest)
    tampered["blobs"][0]["digest"] = (
        "sha256:" + "0" * 64)
    return _expect_refusal(
        lambda: ap.verify(tampered, dict(blobs), digest),
        "artifact-manifest-tampered")


def p_unknown_artifact_type_refused():
    blobs = _sample_blobs()
    import copy
    manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    evil = copy.deepcopy(manifest)
    evil["artifactType"] = "application/vnd.evil.bundle.v9"
    evil_digest = ap.manifest_digest(evil)
    return _expect_refusal(
        lambda: ap.verify(evil, dict(blobs), evil_digest),
        "artifact-type-unknown")


def p_malformed_manifest_refused():
    blobs = _sample_blobs()
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    broken = {"artifactType": manifest["artifactType"]}  # no blobs key
    return _expect_refusal(
        lambda: ap.verify(broken, dict(blobs), digest),
        "artifact-manifest-malformed")


def p_empty_pack_roundtrip():
    manifest, digest = ap.pack({}, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    out = ap.unpack(manifest, {}, digest)
    assert out == {}, "empty round-trip failed"
    _, digest2 = ap.pack({}, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    assert digest == digest2, "empty pack not deterministic"
    return _held("empty artifact packs, verifies, deterministic")


def p_blob_order_independent():
    blobs = _sample_blobs()
    rev = dict(reversed(list(blobs.items())))
    _, d1 = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    _, d2 = ap.pack(rev, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    assert d1 == d2, "insertion order changed the digest"
    return _held("digest independent of dict insertion order")


def _evidence_blobs(records):
    """Re-serialize evidence records exactly as pack_evidence_records
    does, so the probe can hand verify() an independent blob copy."""
    blobs = {}
    for i, rec in enumerate(records):
        name = "record-%04d.json" % i
        blobs[name] = json.dumps(
            rec, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")
    return blobs


def p_evidence_records_roundtrip():
    records = [
        {"seq": 0, "decision": "deny", "code": "deny-egress"},
        {"seq": 1, "decision": "allow", "code": "allow-listed"},
    ]
    manifest, digest = ap.pack_evidence_records(
        records, annotations={"org.sasanam.case": "demo"})
    back = ap.unpack_evidence_records(
        manifest, _evidence_blobs(records), digest)
    assert back == records, "evidence records did not round-trip"
    return _held("2 evidence records packed/unpacked via wire fn")


def p_skill_files_roundtrip():
    files = {"SKILL.md": b"# skill\n", "main.py": b"print('hi')\n"}
    manifest, digest = ap.pack_skill_files(files)
    out = ap.unpack(manifest, dict(files), digest)
    assert out == files, "skill files did not round-trip"
    assert manifest["artifactType"] == ap.ARTIFACT_TYPE_SKILL_BUNDLE
    return _held("skill bundle wire fn round-trips")


def p_bad_blob_name_refused():
    blobs = {"ok.bin": b"x", "bad\x00name": b"y"}
    return _expect_refusal(
        lambda: ap.pack(blobs, ap.ARTIFACT_TYPE_SKILL_BUNDLE),
        "artifact-manifest-malformed")


def p_digest_shape_pinned():
    _, digest = ap.pack(_sample_blobs(),
                        ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
    assert digest.startswith("sha256:"), "missing sha256 prefix"
    hexpart = digest[len("sha256:"):]
    assert len(hexpart) == 64, "digest hex wrong length"
    int(hexpart, 16)  # raises unless lowercase hex
    assert hexpart == hexpart.lower(), "digest not lowercase"
    return _held("digest %s... is sha256:<64 lower hex>" % digest[:19])


def p_annotations_preserved():
    blobs = _sample_blobs()
    ann = {"org.sasanam.produced-by": "wave-248",
           "org.sasanam.case": "red-first"}
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE,
                               annotations=ann)
    assert manifest["annotations"] == ann, "annotations not preserved"
    ap.verify(manifest, dict(blobs), digest)  # must still verify
    return _held("annotations byte-preserved and verified")


def p_large_blob_roundtrip():
    big = b"x" * (1024 * 1024)  # 1 MiB
    blobs = {"big.bin": big, "small.txt": b"s"}
    manifest, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
    out = ap.unpack(manifest, dict(blobs), digest)
    assert out == blobs, "1 MiB blob did not round-trip"
    return _held("1 MiB blob round-trips")


PROBES = [
    ("pack_unpack_roundtrip", p_pack_unpack_roundtrip),
    ("digest_deterministic", p_digest_deterministic),
    ("digest_changes_on_byte_flip", p_digest_changes_on_byte_flip),
    ("tampered_blob_refused", p_tampered_blob_refused),
    ("missing_blob_refused", p_missing_blob_refused),
    ("extra_blob_refused", p_extra_blob_refused),
    ("size_lie_refused", p_size_lie_refused),
    ("manifest_tamper_refused", p_manifest_tamper_refused),
    ("unknown_artifact_type_refused", p_unknown_artifact_type_refused),
    ("malformed_manifest_refused", p_malformed_manifest_refused),
    ("empty_pack_roundtrip", p_empty_pack_roundtrip),
    ("blob_order_independent", p_blob_order_independent),
    ("evidence_records_roundtrip", p_evidence_records_roundtrip),
    ("skill_files_roundtrip", p_skill_files_roundtrip),
    ("bad_blob_name_refused", p_bad_blob_name_refused),
    ("digest_shape_pinned", p_digest_shape_pinned),
    ("annotations_preserved", p_annotations_preserved),
    ("large_blob_roundtrip", p_large_blob_roundtrip),
]


def green_check():
    """Depth-1 green check: run the lane's unit tests, nothing deeper.

    Honors GOV_SKIP_GREEN. Never spawns another battery's main.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    repo_root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_artifact_pack"],
        cwd=repo_root, env=env, capture_output=True, text=True,
        timeout=300)
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    return proc.returncode


def main():
    results = [_run(name, fn) for name, fn in PROBES]
    held = [r for r in results if r[1] == "HELD"]
    gap = [r for r in results if r[1] == "GAP"]
    err = [r for r in results if r[1] == "ERROR"]
    for name, verdict, evidence in results:
        print("%-32s %-6s %s" % (name, verdict, evidence))
    print("HELD %d / GAP %d / ERROR %d (of %d)" % (
        len(held), len(gap), len(err), len(results)))
    if gap or err:
        return 1
    if len(held) != len(PROBES):
        print("probe count mismatch")
        return 1
    return green_check()


if __name__ == "__main__":
    sys.exit(main())
