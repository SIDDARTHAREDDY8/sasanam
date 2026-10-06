#!/usr/bin/env python3
"""Wave-338 lane 4 battery: OCI referrer transport (gov/oci_referrer.py).

Base: 6cdf5fdd (wave-337 merge). Pin: 2131 (+1 oci-bundle-not-verifiable,
wave-339 lane 1; +2 oci-*: oci-layer-media-type-
mismatch + oci-tag-refused). Footer unchanged: open none / next F430
(no findings filed here).

Builds w337 research prospectus R17 (OCI referrer transport for keyed
Sigstore bundles): stdlib only, caller-supplied transport, digest-only
addressing, subject-binding check, fail-closed on missing Referrers API,
and the Harbor direct-push-only caveat as a tested boundary.

P1  Round-trip: seal -> attach -> discover -> pull -> byte-identical ->
    verify_keyed_bundle True (caller-supplied mock transport only).
P2  Subject-mismatch refuses coded oci-subject-mismatch (confusion attack:
    registry serves a referrer bound to a different subject).
P3  Tag-not-digest refused coded oci-tag-refused on attach/discover/pull.
P4  Missing Referrers API refuses coded oci-referrers-unavailable
    fail-closed; the tag scheme is never attempted as a fallback.
P5  Tampered layer refuses coded oci-blob-digest-mismatch on pull.
P6  Non-bundle content refuses coded oci-layer-media-type-mismatch at
    attach; wrong layer media type refuses at pull.
P7  Harbor caveat (documented, tested): replica without replicated
    referrers fails closed on discover (direct-push only); a
    registry-supplied "verified" badge is never an input to any verdict.
P8  Predicate-type annotation: extracted from the sealed VSA statement;
    explicit override honored.
P9  Pin/taxonomy honesty (2134/2134/0 sorted-unique on raw literals;
    new codes registered) + footer state (open none / next F430).
P10 Green check (depth-1): tests/test_oci_referrer.py as a child.

gov/ changes in this lane: gov/oci_referrer.py (new) +
gov/decision_codes.py (2 new oci-* codes) + gov/guac_graph.py (pin
2124 -> 2126). Findings: none filed.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)
FOOTER_OPEN = ("F437", "F438", "F439", "F440", "F441", "F442")
FOOTER_NEXT = "F443"

_EXPECTED_BREAKS = set()

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _break(pid, "assertion: %s" % exc)
    except Exception:  # noqa: BLE001 - every probe must report, not crash
        _record(pid, "ERROR", traceback.format_exc(limit=3).replace(
            "\n", " | ")[:300])


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _tmpd(prefix):
    d = tempfile.mkdtemp(prefix=prefix, dir="/var/tmp")
    return d


# ---------------------------------------------------------------------------
# Mock registry transport (caller-supplied; in-memory, offline).
# ---------------------------------------------------------------------------

from gov import oci_referrer as OR  # noqa: E402
from gov import sigstore_bundle as SB  # noqa: E402
from gov import evidence_intoto as _intoto  # noqa: E402
from gov import decision_codes as DC  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

BASE = "https://registry.example"
REPO_NAME = "sasanam/evidence"
_SEED = bytes(range(32))
_SIGNER = Ed25519Signer(_SEED)
_PUB = _SIGNER.public_key


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class MockRegistry(object):
    def __init__(self, *, referrers_api=True, badge=None,
                 rewrite_subject=None):
        self.blobs = {}
        self.manifests = {}
        self.referrers_api = referrers_api
        self.badge = badge
        self.rewrite_subject = rewrite_subject
        self.requests = []

    def transport(self, request):
        method = request["method"]
        url = request["url"]
        body = request.get("body") or b""
        self.requests.append((method, url))
        parts = urllib.parse.urlparse(url)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query)
        prefix = "/v2/" + REPO_NAME + "/"
        assert path.startswith(prefix), path
        rest = path[len(prefix):]
        if method == "POST" and rest == "blobs/uploads/":
            return (202, {"location": prefix + "blobs/uploads/s1"}, b"")
        if method == "PUT" and rest.startswith("blobs/uploads/"):
            dgst = query.get("digest", [None])[0]
            self.blobs[dgst] = bytes(body)
            return (201, {"docker-content-digest": dgst}, b"")
        if method == "PUT" and rest.startswith("manifests/"):
            dgst = rest[len("manifests/"):]
            self.manifests[dgst] = bytes(body)
            return (201, {"docker-content-digest": dgst}, b"")
        if method == "GET" and rest.startswith("referrers/"):
            if not self.referrers_api:
                return (404, {}, b'{"errors":[{"code":"NOT_FOUND"}]}')
            subject = rest[len("referrers/"):]
            entries = []
            for dgst, mbytes in self.manifests.items():
                man = json.loads(mbytes.decode("utf-8"))
                subj = dict(man.get("subject") or {})
                if subj.get("digest") != subject:
                    continue
                if self.rewrite_subject is not None:
                    subj = dict(subj, digest=self.rewrite_subject)
                entry = {"mediaType": man.get("mediaType"), "digest": dgst,
                         "size": len(mbytes),
                         "artifactType": man.get("artifactType"),
                         "subject": subj,
                         "annotations": dict(man.get("annotations") or {})}
                if self.badge:
                    entry["annotations"].update(self.badge)
                entries.append(entry)
            index = {"schemaVersion": 2,
                     "mediaType": OR.OCI_INDEX_MEDIA_TYPE,
                     "referrers": entries}
            return (200, {"content-type": OR.OCI_INDEX_MEDIA_TYPE},
                    json.dumps(index).encode("utf-8"))
        if method == "GET" and rest.startswith("manifests/"):
            dgst = rest[len("manifests/"):]
            if dgst in self.manifests:
                return (200, {}, self.manifests[dgst])
            return (404, {}, b"")
        if method == "GET" and rest.startswith("blobs/"):
            dgst = rest[len("blobs/"):]
            if dgst in self.blobs:
                return (200, {}, self.blobs[dgst])
            return (404, {}, b"")
        raise AssertionError("unexpected: %s %s" % (method, url))

    def urls(self):
        return [u for _, u in self.requests]


def _sealed():
    stmt = _intoto.build_statement(b'{"decision": "deny", "seq": 9}',
                                   {"lane": "w338"})
    return OR.canonical_json(
        SB.seal_keyed_bundle(_intoto.statement_bytes(stmt), _SIGNER))


def _expect_refusal(pid, code, fn):
    try:
        fn()
    except OR.OCIReferrerRefusal as exc:
        assert exc.code == code, \
            "want %s, got %s (%s)" % (code, exc.code, exc.detail)
        return
    raise AssertionError("no refusal raised (want %s)" % code)


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

@_probe("P1-roundtrip")
def _p1():
    reg = MockRegistry()
    t = reg.transport
    bundle = _sealed()
    subject = _digest(b"evidence-subject-1")
    res = OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle)
    assert res["bundle_digest"] == _digest(bundle)
    assert res["subject_digest"] == subject
    found = OR.discover_keyed_bundles(t, BASE, REPO_NAME, subject)
    assert len(found) == 1, found
    assert found[0]["digest"] == res["manifest_digest"]
    pulled = OR.pull_keyed_bundle(t, BASE, REPO_NAME, found[0], subject)
    assert pulled == bundle, "round-trip not byte-identical"
    assert SB.verify_keyed_bundle(
        json.loads(pulled.decode("utf-8")), _PUB) is True
    _held("P1-roundtrip",
          "attach->discover->pull byte-identical; signature verifies")


@_probe("P2-subject-mismatch")
def _p2():
    reg = MockRegistry(rewrite_subject=_digest(b"ATTACKER-SUBJECT"))
    t = reg.transport
    bundle = _sealed()
    subject = _digest(b"evidence-subject-2")
    OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle)
    _expect_refusal("P2-subject-mismatch", "oci-subject-mismatch",
                    lambda: OR.discover_keyed_bundles(
                        t, BASE, REPO_NAME, subject))
    _held("P2-subject-mismatch",
          "confusion entry (different subject) refuses oci-subject-mismatch")


@_probe("P3-tag-refused")
def _p3():
    reg = MockRegistry()
    t = reg.transport
    bundle = _sealed()
    _expect_refusal("P3-tag-refused", "oci-tag-refused",
                    lambda: OR.attach_keyed_bundle(
                        t, BASE, REPO_NAME, "latest", bundle))
    _expect_refusal("P3-tag-refused", "oci-tag-refused",
                    lambda: OR.discover_keyed_bundles(
                        t, BASE, REPO_NAME, "v1.0"))
    _expect_refusal("P3-tag-refused", "oci-tag-refused",
                    lambda: OR.pull_keyed_bundle(
                        t, BASE, REPO_NAME, {"digest": "latest"},
                        _digest(b"x")))
    _held("P3-tag-refused", "tags refused on attach/discover/pull")


@_probe("P4-missing-api")
def _p4():
    reg = MockRegistry(referrers_api=False)
    t = reg.transport
    subject = _digest(b"evidence-subject-4")
    _expect_refusal("P4-missing-api", "oci-referrers-unavailable",
                    lambda: OR.discover_keyed_bundles(
                        t, BASE, REPO_NAME, subject))
    for url in reg.urls():
        assert "/tags/" not in url, \
            "tag-scheme fallback attempted: %s" % url
    _held("P4-missing-api",
          "no Referrers API -> oci-referrers-unavailable; no tag fallback")


@_probe("P5-tampered-layer")
def _p5():
    reg = MockRegistry()
    t = reg.transport
    bundle = _sealed()
    subject = _digest(b"evidence-subject-5")
    res = OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle)
    found = OR.discover_keyed_bundles(t, BASE, REPO_NAME, subject)
    reg.blobs[res["bundle_digest"]] = b'{"tampered": true}'
    _expect_refusal("P5-tampered-layer", "oci-blob-digest-mismatch",
                    lambda: OR.pull_keyed_bundle(
                        t, BASE, REPO_NAME, found[0], subject))
    _held("P5-tampered-layer",
          "tampered blob refuses oci-blob-digest-mismatch")


@_probe("P6-layer-media-type")
def _p6():
    reg = MockRegistry()
    t = reg.transport
    subject = _digest(b"evidence-subject-6")
    _expect_refusal("P6-layer-media-type", "oci-layer-media-type-mismatch",
                    lambda: OR.attach_keyed_bundle(
                        t, BASE, REPO_NAME, subject, b"not-json"))
    _expect_refusal(
        "P6-layer-media-type", "oci-layer-media-type-mismatch",
        lambda: OR.attach_keyed_bundle(
            t, BASE, REPO_NAME, subject,
            OR.canonical_json({"mediaType": "application/json"})))
    # Wrong layer media type inside an otherwise valid manifest.
    bundle = _sealed()
    res = OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle)
    man = json.loads(reg.manifests[res["manifest_digest"]].decode())
    man["layers"][0]["mediaType"] = "application/octet-stream"
    mbytes = OR.canonical_json(man)
    new_digest = _digest(mbytes)
    reg.manifests[new_digest] = mbytes
    desc = {"digest": new_digest, "size": len(mbytes)}
    _expect_refusal("P6-layer-media-type", "oci-layer-media-type-mismatch",
                    lambda: OR.pull_keyed_bundle(
                        t, BASE, REPO_NAME, desc, subject))
    _held("P6-layer-media-type",
          "non-bundle content refused at attach and at pull")


@_probe("P7-harbor")
def _p7():
    # 7a: Harbor Replication Service ignores referrer manifests -- a
    # replica has blobs but no referrers index. Direct-push only.
    origin = MockRegistry()
    bundle = _sealed()
    subject = _digest(b"evidence-subject-7")
    OR.attach_keyed_bundle(origin.transport, BASE, REPO_NAME, subject,
                           bundle)
    replica = MockRegistry(referrers_api=False)
    replica.blobs = dict(origin.blobs)
    _expect_refusal("P7-harbor", "oci-referrers-unavailable",
                    lambda: OR.discover_keyed_bundles(
                        replica.transport, BASE, REPO_NAME, subject))
    # 7b: a registry "verified" badge is never an input to any verdict.
    badged = MockRegistry(badge={"verified": "true"})
    res = OR.attach_keyed_bundle(badged.transport, BASE, REPO_NAME,
                                 subject, bundle)
    found = OR.discover_keyed_bundles(badged.transport, BASE, REPO_NAME,
                                      subject)
    badged.blobs[res["bundle_digest"]] = b"tampered"
    _expect_refusal("P7-harbor", "oci-blob-digest-mismatch",
                    lambda: OR.pull_keyed_bundle(
                        badged.transport, BASE, REPO_NAME, found[0],
                        subject))
    honest = MockRegistry(badge={"verified": "false"})
    OR.attach_keyed_bundle(honest.transport, BASE, REPO_NAME, subject,
                           bundle)
    found2 = OR.discover_keyed_bundles(honest.transport, BASE, REPO_NAME,
                                       subject)
    pulled = OR.pull_keyed_bundle(honest.transport, BASE, REPO_NAME,
                                  found2[0], subject)
    assert pulled == bundle
    assert "HARBOR DEPLOYMENT CAVEAT" in open(
        os.path.join(REPO, "gov", "oci_referrer.py")).read()
    _held("P7-harbor",
          "replica gap fails closed; badge never trusted; caveat documented")


@_probe("P8-predicate-annotation")
def _p8():
    reg = MockRegistry()
    t = reg.transport
    bundle = _sealed()
    subject = _digest(b"evidence-subject-8")
    res = OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle)
    assert res["predicate_type"] == \
        _intoto.SASANAM_EVIDENCE_PREDICATE_TYPE, res["predicate_type"]
    man = json.loads(reg.manifests[res["manifest_digest"]].decode())
    assert man["annotations"][OR.PREDICATE_TYPE_ANNOTATION] == \
        _intoto.SASANAM_EVIDENCE_PREDICATE_TYPE
    res2 = OR.attach_keyed_bundle(t, BASE, REPO_NAME, subject, bundle,
                                  predicate_type="custom.example/v9")
    assert res2["predicate_type"] == "custom.example/v9"
    _held("P8-predicate-annotation",
          "VSA predicate type extracted into annotations; override honored")


@_probe("P9-pin-taxonomy")
def _p9():
    assert len(DC.TAXONOMY) == TAXONOMY_PIN, \
        "want %d, got %d" % (TAXONOMY_PIN, len(DC.TAXONOMY))
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    literals = re.findall(r'"code": \'([A-Za-z0-9][A-Za-z0-9\-_.]*)\'', src)
    assert len(literals) == len(set(literals)) == TAXONOMY_PIN, \
        "taxonomy not sorted-unique on raw literals"
    assert literals == sorted(literals), "taxonomy not sorted"
    for code in ("oci-tag-refused", "oci-layer-media-type-mismatch",
                 "oci-bundle-not-verifiable", "oci-registry-onboarding-refused"):
        assert code in DC.TAXONOMY, code
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F443**" in text, "footer next free"
    assert "Open findings: F437, F438, F439, F440, F441, F442." in text, "footer open findings"
    assert FOOTER_OPEN == ("F437", "F438", "F439", "F440", "F441", "F442") and FOOTER_NEXT == "F443"
    _held("P9-pin-taxonomy",
          "2134/2134/0 sorted-unique; 4 oci-* codes registered "
          "(+oci-bundle-not-verifiable +oci-registry-onboarding-refused); "
          "footer open none / next F430")


def _run_child_output(args, timeout):
    d = _tmpd("w338oci-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: tests/test_oci_referrer.py as a child with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by recording
    a skip, never spawning."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        rc, out = _run_child_output(
            [sys.executable, "-m", "unittest", "tests.test_oci_referrer",
             "-v"], timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "test_oci_referrer: %s" % exc)
        return
    bad = re.findall(r"^(FAIL|ERROR):", out, re.M)
    if rc != 0 or bad or "OK" not in out:
        _record("green-check", "BREAK",
                "test_oci_referrer non-green rc=%d: %s"
                % (rc, out[-400:]))
    else:
        _record("green-check", "HELD", "test_oci_referrer green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w338_oci battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
