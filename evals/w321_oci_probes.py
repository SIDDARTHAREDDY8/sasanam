#!/usr/bin/env python3
"""Wave-321 Lane 2 battery: OCI distribution for evidence bundles
(gov/oci_distribution.py).

Evidence bundles ship as subject-bearing OCI 1.1 manifests with a Sasanam
artifactType; manifests are deterministic ("same evidence -> same digest");
the client discovers referrers via GET /v2/<repo>/referrers/<digest> with
the spec-mandated 404 -> tag-schema fallback; and the registry is treated
as UNTRUSTED storage -- digest-addressed pulls, per-blob digest checks,
subject-digest matching, all client-side.

RED-FIRST: written before the module exists; must FAIL on the open tree
(ImportError). No live registry is available in this environment, so the
battery speaks the OCI HTTP surface through a faithful in-process fake
registry (threaded http.server). The live-registry round-trip was already
proven by the wave-320 prospecting spike (byte-identical push/pull through
a real registry); this battery tests the client logic, not the network.

Probe map (public seams only -- build_evidence_manifest /
OCIRegistryClient.push_evidence / discover_referrers / pull_and_verify):
  oci-roundtrip-byte-identical: push evidence bytes, pull_and_verify ->
      byte-identical bytes back.
  oci-manifest-deterministic: same inputs built twice -> identical digest;
      annotations given in different insertion order -> identical digest;
      manifest carries no timestamp/nondeterministic fields.
  oci-tampered-blob-refused: registry serves tampered blob bytes under the
      right digest -> pull refuses coded oci-blob-digest-mismatch.
  oci-wrong-subject-referrer-excluded: discovery answers with a manifest
      whose subject.digest != queried digest -> pull_and_verify refuses
      coded oci-subject-mismatch (never returns the wrong evidence); the
      correct subject still verifies.
  oci-fallback-tag-schema: referrers API 404s -> client falls back to the
      sha256-<hex>.sig tag, finds the manifest, verifies (via == tag-fallback).
  oci-no-referrers-refuses: neither referrers API nor fallback tag resolves
      -> coded oci-referrers-unavailable (fail closed, never silent None).
  oci-artifact-type-gated: manifest with a foreign artifactType -> pull with
      the expected Sasanam artifactType refuses coded
      oci-artifact-type-mismatch.
  pin-taxonomy / footer-state: standard pins (1964; open none / next F409).
"""

import json
import os
import sys
import threading
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import oci_distribution as oci
    _IMPORT_ERROR = None
except ImportError as e:  # noqa: BLE001
    oci = None
    _IMPORT_ERROR = e

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note))


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as e:
        _record(pid, "BREAK", "assertion failed: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "%s: %s" % (type(e).__name__, e))
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Faithful in-process fake registry (test-only, speaks the OCI HTTP surface).
# ---------------------------------------------------------------------------

if oci is None:
    FakeRegistry = None
else:
    import hashlib
    import json as _json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class FakeRegistry(object):
        """Minimal OCI distribution-spec surface for tests.

        Modes (set attributes before serving):
          tamper_blobs: {digest: bad_bytes} -- serve wrong bytes for a blob.
          referrers_404: bool -- 404 the referrers API (exercises fallback).
          extra_referrers: [manifest_dict] -- appended to referrers responses.
          fail_tags: bool -- tags/list returns no usable fallback tag.
        """

        def __init__(self):
            self.blobs = {}      # digest -> bytes
            self.manifests = {}  # reference -> bytes
            self.tamper_blobs = {}
            self.referrers_404 = False
            self.extra_referrers = []
            self.fail_tags = False
            self.requests = []
            self._server = None
            self._thread = None

        # -- request handling ------------------------------------------------
        def _handler(self):
            reg = self

            class H(BaseHTTPRequestHandler):
                def log_message(self, *a):  # quiet
                    pass

                def _send(self, code, body=b"", ctype="application/json"):
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if body:
                        self.wfile.write(body)

                def _route(self, method):
                    u = urlparse(self.path)
                    reg.requests.append((method, u.path))
                    parts = u.path.strip("/").split("/")
                    # parts[0] == 'v2'
                    if u.path == "/v2/":
                        return self._send(200, b"{}")
                    if len(parts) < 3 or parts[0] != "v2":
                        return self._send(404, b"{}")
                    repo = parts[1]
                    rest = parts[2:]
                    length = int(self.headers.get("Content-Length", 0) or 0)
                    body = self.rfile.read(length) if length else b""

                    # blob upload: POST /v2/<repo>/blobs/uploads/
                    if (method == "POST" and rest == ["blobs", "uploads"]):
                        loc = "/v2/%s/blobs/uploads/upl-1" % repo
                        self.send_response(202)
                        self.send_header("Location", loc)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    # blob upload complete: PUT .../uploads/<id>?digest=sha256:..
                    if (method == "PUT" and len(rest) == 3
                            and rest[0] == "blobs" and rest[1] == "uploads"):
                        q = parse_qs(u.query)
                        dgst = (q.get("digest") or [""])[0]
                        if not dgst.startswith("sha256:"):
                            return self._send(400, b'{"error":"digest required"}')
                        reg.blobs[dgst] = body
                        self.send_response(201)
                        self.send_header(
                            "Docker-Content-Digest", dgst)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    # blob fetch: GET /v2/<repo>/blobs/<digest...>
                    if method == "GET" and rest[0] == "blobs":
                        # path is /v2/<repo>/blobs/sha256:<hex>
                        dgst = "/".join(rest[1:])
                        if dgst in reg.tamper_blobs:
                            return self._send(200, reg.tamper_blobs[dgst],
                                              "application/octet-stream")
                        if dgst in reg.blobs:
                            return self._send(200, reg.blobs[dgst],
                                              "application/octet-stream")
                        return self._send(404, b"{}")
                    # manifest push: PUT /v2/<repo>/manifests/<ref>
                    if method == "PUT" and rest[0] == "manifests":
                        ref = "/".join(rest[1:])
                        reg.manifests[ref] = body
                        dgst = "sha256:" + hashlib.sha256(body).hexdigest()
                        reg.manifests[dgst] = body
                        # Test-double behavior: simulate a registry populated
                        # by tag-scheme tooling -- the manifest is ALSO
                        # reachable under the cosign legacy fallback tag for
                        # its subject. Our client never CREATES this tag
                        # (SKIP-as-design); it only ever reads it as fallback.
                        try:
                            _m = _json.loads(body.decode("utf-8"))
                            _subj = (_m.get("subject") or {}).get("digest")
                            if _subj and _subj.startswith("sha256:"):
                                _tag = ("sha256-"
                                        + _subj.split(":", 1)[1] + ".sig")
                                reg.manifests[_tag] = body
                        except Exception:  # noqa: BLE001
                            pass
                        self.send_response(201)
                        self.send_header("Docker-Content-Digest", dgst)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    # manifest fetch: GET /v2/<repo>/manifests/<ref>
                    if method == "GET" and rest[0] == "manifests":
                        ref = "/".join(rest[1:])
                        if ref in reg.manifests:
                            return self._send(
                                200, reg.manifests[ref],
                                "application/vnd.oci.image.manifest.v1+json")
                        return self._send(404, b"{}")
                    # referrers: GET /v2/<repo>/referrers/<digest...>
                    if (method == "GET" and rest[0] == "referrers"):
                        if reg.referrers_404:
                            return self._send(404, b"{}")
                        dgst = "/".join(rest[1:])
                        found = []
                        for _ref, mb in reg.manifests.items():
                            try:
                                m = _json.loads(mb.decode("utf-8"))
                            except Exception:  # noqa: BLE001
                                continue
                            subj = (m.get("subject") or {})
                            if subj.get("digest") == dgst:
                                found.append({
                                    "mediaType": m.get("mediaType"),
                                    "artifactType": m.get("artifactType"),
                                    "digest": "sha256:" + hashlib.sha256(
                                        mb).hexdigest(),
                                    "size": len(mb),
                                    "annotations": m.get("annotations", {}),
                                })
                        for m in reg.extra_referrers:
                            mb = _json.dumps(m).encode()
                            found.append({
                                "mediaType": m.get("mediaType"),
                                "artifactType": m.get("artifactType"),
                                "digest": "sha256:" + hashlib.sha256(
                                    mb).hexdigest(),
                                "size": len(mb),
                            })
                            reg.manifests["sha256:" + hashlib.sha256(
                                mb).hexdigest()] = mb
                        idx = {"schemaVersion": 2,
                               "mediaType":
                               "application/vnd.oci.image.index.v1+json",
                               "manifests": found,
                               "subject": {"digest": dgst}}
                        return self._send(200, _json.dumps(idx).encode())
                    # tags: GET /v2/<repo>/tags/list
                    if (method == "GET" and rest == ["tags", "list"]
                            and not reg.fail_tags):
                        tags = [t for t in reg.manifests
                                if not t.startswith("sha256:")]
                        return self._send(
                            200, _json.dumps({"tags": tags}).encode())
                    if method == "GET" and rest == ["tags", "list"]:
                        return self._send(200, b'{"tags": []}')
                    return self._send(404, b"{}")

                def do_GET(self):
                    self._route("GET")

                def do_POST(self):
                    self._route("POST")

                def do_PUT(self):
                    self._route("PUT")

            return H

        def start(self):
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
            self._thread = threading.Thread(target=self._server.serve_forever,
                                            daemon=True)
            self._thread.start()
            return "http://127.0.0.1:%d" % self._server.server_address[1]

        def stop(self):
            if self._server:
                self._server.shutdown()
                self._thread.join()


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

_EVIDENCE = b'{"evidence":"wave-321-oci","seq":1}'


def _client_for(reg):
    return oci.OCIRegistryClient(reg.start(), "testrepo")


def p_roundtrip_byte_identical():
    reg = FakeRegistry()
    try:
        c = _client_for(reg)
        pushed = c.push_evidence(_EVIDENCE)
        assert pushed["subject_digest"] == oci.digest_of(_EVIDENCE), \
            "subject must be the evidence payload digest"
        got = c.pull_and_verify(pushed["subject_digest"])
        assert got == _EVIDENCE, "round-trip must be byte-identical"
        _record("oci-roundtrip-byte-identical", "HELD",
                "push/pull byte-identical via digest-addressed manifest")
    finally:
        reg.stop()


def p_manifest_deterministic():
    m1, d1 = oci.build_evidence_manifest(_EVIDENCE)
    m2, d2 = oci.build_evidence_manifest(_EVIDENCE)
    assert d1 == d2 and m1 == m2, "same inputs must give identical manifest"
    a = {"z": "1", "a": "2"}
    b = {"a": "2", "z": "1"}
    _, da = oci.build_evidence_manifest(_EVIDENCE, annotations=a)
    _, db = oci.build_evidence_manifest(_EVIDENCE, annotations=b)
    assert da == db, "annotation insertion order must not affect the digest"
    import json as _json
    doc = _json.loads(m1.decode("utf-8"))
    blob = _json.dumps(doc).lower()
    for needle in ("created", "timestamp", "time"):
        assert needle not in blob, \
            "manifest must carry no nondeterministic field (%s)" % needle
    assert doc["subject"]["digest"] == oci.digest_of(_EVIDENCE), \
        "manifest subject must reference the evidence payload digest"
    _record("oci-manifest-deterministic", "HELD",
            "deterministic manifest %s (order-insensitive, no timestamps)"
            % d1)


def p_tampered_blob_refused():
    reg = FakeRegistry()
    try:
        c = _client_for(reg)
        pushed = c.push_evidence(_EVIDENCE)
        reg.tamper_blobs[pushed["blob_digest"]] = b"TAMPERED"
        try:
            c.pull_and_verify(pushed["subject_digest"])
        except oci.OCIRefusal as r:
            assert r.code == "oci-blob-digest-mismatch", \
                "wrong code: %s" % r.code
            _record("oci-tampered-blob-refused", "HELD",
                    "tampered blob refused coded %s" % r.code)
            return
        raise AssertionError("tampered blob was NOT refused")
    finally:
        reg.stop()


def p_wrong_subject_referrer_excluded():
    # The registry answers discovery with a manifest whose subject is NOT
    # the queried digest (an untrusted registry serving someone else's
    # bundle, or a confused index). The client must refuse coded
    # oci-subject-mismatch -- never return the wrong evidence.
    reg = FakeRegistry()
    try:
        c = _client_for(reg)
        pushed = c.push_evidence(_EVIDENCE)
        legit_manifest = reg.manifests[pushed["manifest_digest"]]
        reg.extra_referrers.append(
            json.loads(legit_manifest.decode("utf-8")))
        wrong_subject = oci.digest_of(b'{"evidence":"someone-else"}')
        try:
            c.pull_and_verify(wrong_subject)
        except oci.OCIRefusal as r:
            assert r.code == "oci-subject-mismatch", \
                "wrong code: %s" % r.code
        else:
            raise AssertionError("wrong-subject manifest was NOT refused")
        # The right subject still verifies -- the bad candidate did not
        # pollute the good path.
        assert c.pull_and_verify(pushed["subject_digest"]) == _EVIDENCE
        _record("oci-wrong-subject-referrer-excluded", "HELD",
                "wrong-subject candidate refused coded oci-subject-mismatch;"
                " correct subject still verifies")
    finally:
        reg.stop()


def p_fallback_tag_schema():
    reg = FakeRegistry()
    try:
        reg.referrers_404 = True  # the spec-mandated fallback trigger
        c = _client_for(reg)
        pushed = c.push_evidence(_EVIDENCE)
        refs, via = c.discover_referrers(pushed["subject_digest"])
        assert via == "tag-fallback", "expected the tag fallback, got %s" % via
        assert [r["digest"] for r in refs] == [pushed["manifest_digest"]], \
            "fallback must resolve the bundle manifest"
        got = c.pull_and_verify(pushed["subject_digest"])
        assert got == _EVIDENCE
        # fallback is never the primary path: the client tried referrers first
        paths = [p for _, p in reg.requests]
        assert any(p.endswith("/referrers/" + pushed["subject_digest"])
                   for p in paths), "referrers API must be tried before fallback"
        _record("oci-fallback-tag-schema", "HELD",
                "404 -> sha256-<hex>.sig tag fallback resolves and verifies")
    finally:
        reg.stop()


def p_no_referrers_refuses():
    reg = FakeRegistry()
    try:
        reg.referrers_404 = True
        reg.fail_tags = True  # nothing anywhere: must fail closed, not None
        c = _client_for(reg)
        bogus = oci.digest_of(b'{"evidence":"never-pushed"}')
        try:
            c.pull_and_verify(bogus)
        except oci.OCIRefusal as r:
            assert r.code == "oci-referrers-unavailable", \
                "wrong code: %s" % r.code
            _record("oci-no-referrers-refuses", "HELD",
                    "undiscoverable subject refuses coded %s" % r.code)
            return
        raise AssertionError("missing referrers did NOT fail closed")
    finally:
        reg.stop()


def p_artifact_type_gated():
    reg = FakeRegistry()
    try:
        c = _client_for(reg)
        pushed = c.push_evidence(_EVIDENCE,
                                 artifact_type="application/vnd.evil/x")
        try:
            c.pull_and_verify(pushed["subject_digest"])  # expects Sasanam type
        except oci.OCIRefusal as r:
            assert r.code == "oci-artifact-type-mismatch", \
                "wrong code: %s" % r.code
            _record("oci-artifact-type-gated", "HELD",
                    "foreign artifactType refused coded %s" % r.code)
            return
        raise AssertionError("foreign artifactType was NOT refused")
    finally:
        reg.stop()


def p_pin_taxonomy():
    import gov.guac_graph as gg
    pin = gg.TAXONOMY_PIN
    assert pin == 2070, "want 2021, got %d" % pin
    from gov import decision_codes as dc
    codes = sorted(dc.TAXONOMY.keys())
    assert len(codes) == len(set(codes)) == 2070, \
        "taxonomy not 2021/unique: %d" % len(codes)
    assert codes == sorted(codes), "taxonomy not sorted"
    _record("pin-taxonomy-2070-sorted", "HELD", "2070/2070/0 sorted")




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md")) as f:
        text = f.read()
    assert "Open findings: F412." in text, "footer must show open none"
    assert "Next free finding: **F413**" in text, "next free must be F410"
    _record("footer-state", "HELD", "open F412 / next F413")


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess  # noqa: E402
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_oci_distribution",
              "tests.test_decision_codes"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            ok = False
    return ok


def main():
    if _IMPORT_ERROR is not None:
        print("RED: gov.oci_distribution missing on the open tree: %r"
              % (_IMPORT_ERROR,))
        return 2
    probes = [
        p_roundtrip_byte_identical,
        p_manifest_deterministic,
        p_tampered_blob_refused,
        p_wrong_subject_referrer_excluded,
        p_fallback_tag_schema,
        p_no_referrers_refuses,
        p_artifact_type_gated,
        p_pin_taxonomy,
        p_footer_state,
    ]
    for fn in probes:
        _safe(fn.__name__, fn)
    green_ok = green_check()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    print("w321_oci battery: %d BREAK / %d HELD / %d ERROR " % (
        breaks, held, errors))
    if not green_ok:
        print("GREEN CHECK FAILED")
        return 1
    return 0 if (breaks == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
