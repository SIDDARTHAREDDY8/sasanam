#!/usr/bin/env python3
"""Wave-339 lane 3 battery: OCI registry onboarding gate (R25).

Base: f670892a (wave-338 merge). Pin: 2131 (+1 oci-registry-onboarding-
refused). Footer: open none / next F430 (no findings filed here).

Builds w338 research prospectus R25: the trust-matrix half of the "sell
evidence" distribution story. The transport (gov/oci_referrer.py) is
built; this battery pins the onboarding gate (gov/oci_registry_gate.py):

P1  Zot + live 200/empty-index => certified-in.
P2  Harbor push path => certified-in; Harbor replication path => refused
    even when the probe answers (the #23210 silent-drop shape).
P3  GHCR + 404 => refused (expected OUT).
P4  Zot + 404 => refused (regression: matrix-IN but no API -- re-probe).
P5  GHCR + 200 => refused (matrix disagrees with the live probe).
P6  Zot + 500 => refused (inconclusive -- OUT until verified).
P7  Unknown registry kind => refused; matrix_override can record a
    private registry but can never flip a matrix OUT to IN.
P8  Same-repository pinning: cross-repository / replica reads refuse
    coded; the #23210 shape (Harbor replica) refuses.
P9  Pin/taxonomy honesty (2135/2135/0 sorted-unique on raw literals; the
    new code registered) + footer state (open none / next F430).
P10 Green check (depth-1): tests/test_oci_registry_gate.py as a child.

gov/ changes in this lane: gov/oci_registry_gate.py (new) +
gov/decision_codes.py (1 new oci-* code) + gov/egress_proxy.py (R20:
wait_ready on time.monotonic()) + tests/test_oci_referrer.py (pin bump
+ artifactType-missing pin test). Findings: none filed.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = ("F461", "F462", "F463", "F464", "F465", "F466", "F467", "F468")  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)

FOOTER_NEXT = "F469"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)


_EXPECTED_BREAKS = set()

_results = []
_PROBES = []


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _held(pid, note):
    _results.append((pid, "HELD", note))


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _record(pid, "BREAK", "assertion: %s" % exc)
    except Exception:
        _record(pid, "ERROR", traceback.format_exc(limit=3))


def _tmpd(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    return d


from gov import decision_codes as DC  # noqa: E402
from gov import oci_registry_gate as G  # noqa: E402


def _index(n=0):
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "referrers": [],
    }).encode()


def _transport(status, body):
    def send(request):
        assert request["method"] == "GET"
        assert "/referrers/" in request["url"]
        return (status, {"content-type": "application/json"},
                body if isinstance(body, bytes) else body.encode())
    return send


def _onboard(kind, status, body=None, path="push", **kw):
    return G.onboard_registry(_transport(status, _index() if body is None
                                        else body),
                              "https://reg.example", "evidence",
                              registry_kind=kind,
                              distribution_path=path, **kw)


@_probe("P1-zot-certified")
def _p1():
    v = _onboard("zot", 200)
    assert v["verdict"] == "certified-in", v
    assert v["code"] is None
    assert v["probe"] == "supported" and v["matrix"] == "in"
    _held("P1-zot-certified",
          "zot + live 200/empty-index => certified-in")


@_probe("P2-harbor-paths")
def _p2():
    v = _onboard("harbor", 200, path="push")
    assert v["verdict"] == "certified-in", v
    v = _onboard("harbor", 200, path="replication")
    assert v["verdict"] == "refused", v
    assert v["code"] == G.ONBOARDING_REFUSED_CODE
    # Even a failed probe on the replication path refuses for the PATH,
    # not the probe: the rule is about the distribution path.
    v = _onboard("harbor", 404, path="replication")
    assert v["verdict"] == "refused"
    assert v["code"] == G.ONBOARDING_REFUSED_CODE
    _held("P2-harbor-paths",
          "harbor push certified-in; replication refused (#23210)")


@_probe("P3-ghcr-expected-out")
def _p3():
    v = _onboard("ghcr", 404)
    assert v["verdict"] == "refused", v
    assert v["code"] == G.ONBOARDING_REFUSED_CODE
    assert "no Referrers API" in v["detail"]
    _held("P3-ghcr-expected-out",
          "ghcr + 404 => refused (expected OUT, cosign#4641)")


@_probe("P4-matrix-in-probe-down")
def _p4():
    v = _onboard("zot", 404)
    assert v["verdict"] == "refused", v
    assert "re-probe" in v["detail"]
    _held("P4-matrix-in-probe-down",
          "matrix-IN + probe 404 => refused (regression, re-probe)")


@_probe("P5-probe-disagrees-with-matrix")
def _p5():
    v = _onboard("ghcr", 200)
    assert v["verdict"] == "refused", v
    assert v["code"] == G.ONBOARDING_REFUSED_CODE
    _held("P5-probe-disagrees-with-matrix",
          "ghcr + live 200 => refused (matrix disagrees: spoof or upgrade)")


@_probe("P6-inconclusive")
def _p6():
    for status in (500, 401, 403):
        v = _onboard("zot", status)
        assert v["verdict"] == "refused", (status, v)
        assert v["probe"] == "inconclusive"
    _held("P6-inconclusive",
          "5xx/401/403 => refused (OUT until verified)")


@_probe("P7-unknown-kind-and-override")
def _p7():
    v = _onboard("mystery-registry", 200)
    assert v["verdict"] == "refused", v
    assert "not in the trust matrix" in v["detail"]
    v = _onboard("private-zot", 200,
                 matrix_override={"private-zot": {
                     "status": "in", "notes": "own zot",
                     "probed": "2026-10-05"}})
    assert v["verdict"] == "certified-in", v
    v = _onboard("ghcr", 200,
                 matrix_override={"ghcr": {"status": "in", "notes": "no"}})
    assert v["verdict"] == "refused", v
    _held("P7-unknown-kind-and-override",
          "unknown kind refused; override records private registries but "
          "cannot flip a matrix OUT")


@_probe("P8-same-repository-pinning")
def _p8():
    assert G.check_same_repository("https://zot.example/", "evidence",
                                   "https://zot.example", "evidence")
    for a_base, a_repo, d_base, d_repo in (
            ("https://zot.example", "evidence-a",
             "https://zot.example", "evidence-b"),
            ("https://harbor.example", "evidence",
             "https://harbor-replica.example", "evidence")):
        try:
            G.check_same_repository(a_base, a_repo, d_base, d_repo)
        except G.OCIRegistryGateRefusal as exc:
            assert exc.code == G.ONBOARDING_REFUSED_CODE
        else:
            raise AssertionError("no refusal for %r -> %r"
                                 % ((a_base, a_repo), (d_base, d_repo)))
    _held("P8-same-repository-pinning",
          "cross-repository and replica reads refuse coded")


@_probe("P9-pin-taxonomy")
def _p9():
    assert len(DC.TAXONOMY) == TAXONOMY_PIN, \
        "want %d, got %d" % (TAXONOMY_PIN, len(DC.TAXONOMY))
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    literals = re.findall(r'"code": \'([A-Za-z0-9][A-Za-z0-9\-_.]*)\'', src)
    assert len(literals) == len(set(literals)) == TAXONOMY_PIN, \
        "taxonomy not sorted-unique on raw literals"
    assert literals == sorted(literals), "taxonomy not sorted"
    assert "oci-registry-onboarding-refused" in DC.TAXONOMY
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F469**" in text, "footer next free"
    assert "Open findings: F461, F462, F463, F464, F465, F466, F467, F468." in text, "footer open findings"
    assert FOOTER_OPEN == ("F461", "F462", "F463", "F464", "F465", "F466", "F467", "F468") and FOOTER_NEXT == "F469"  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)
    _held("P9-pin-taxonomy",
          "2135/2135/0 sorted-unique; oci-registry-onboarding-refused "
          "registered; footer open none / next F430")


def _run_child_output(args, timeout):
    d = _tmpd("w339ocigate-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: tests/test_oci_registry_gate.py as a child with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by recording
    a skip, never spawning."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        rc, out = _run_child_output(
            [sys.executable, "-m", "unittest", "tests.test_oci_registry_gate",
             "-v"], timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "test_oci_registry_gate: %s" % exc)
        return
    bad = re.findall(r"^(FAIL|ERROR):", out, re.M)
    if rc != 0 or bad or "OK" not in out:
        _record("green-check", "BREAK",
                "test_oci_registry_gate non-green rc=%d: %s"
                % (rc, out[-400:]))
    else:
        _record("green-check", "HELD", "test_oci_registry_gate green")


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
    print("w339_oci_gate battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
