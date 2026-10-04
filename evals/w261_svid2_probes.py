"""Break-first closure battery for F233 + F234 (gov/svid_issuer.py).

Wave-261 lane B. Stdlib only. Deterministic across runs (staging +
`env -u GOV_DEPLOYMENT_MODE`). No in-repo git subprocesses (wave-36
supply-chain probe: fail closed).

Targets (base c2a1fc0, taxonomy pin 1092 -> 1093 with this lane):
- F233: the SVID `usage` field is signed but never enforced. Close:
  `SvidVerifier.verify()` takes `expected_usage` (refused with the new
  `svid-usage-mismatch` code) and `MeshControl` binds allowed usages
  per policy (`"usages"` key; refused with `svid-acl-denied`), plus a
  per-call `expected_usage` passthrough on `admit()`.
- F234: `now` validation is path-dependent (F228 shape). Close:
  `_validate_now()` runs FIRST in `verify()` and `issue()` (mirroring
  the F228 closure in gov/short_lived_credentials.py); `admit()` is
  covered via `verify()`. Existing `svid-malformed` covers the
  refusal; past-numeric `now` stays a test hook.

Red-first note: on the unfixed tree `verify()`/`admit()` take no
`expected_usage` parameter, so those probes observe TypeError and
report BREAK (the missing seam IS the defect); the policy-`"usages"`
probe observes the key being silently ignored (admit succeeds) and
reports BREAK. Post-fix all usage probes HELD.

Pin-check placement: the taxonomy pin is checked AFTER the probes so
the pre-fix red run still reports BREAK -- the pin legitimately moves
1092 -> 1093 with this lane's one new code. Exit 0 requires every
probe HELD *and* the pin to match.
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import svid_issuer as sv  # noqa: E402

# Wave-261 lane B: pin 1092 -> 1093 (+1 svid-usage-mismatch, F233).
# Additive only; repointed value-token-only per the wave-256 lesson.
TAXONOMY_PIN = 1934 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_PROBES = []

NOW = 1700000000.0


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w261svid2-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail):
    return ("BREAK", detail)


def _svid_pair():
    seed = bytes.fromhex("aa" * 32)
    issuer = sv.TestSvidIssuer(issuer_seed=seed)
    verifier = sv.SvidVerifier({issuer.key_id: issuer.issuer_public_key},
                               "example.org")
    return issuer, verifier


def _svid_code(fn):
    try:
        fn()
    except sv.SvidError as e:
        return e.code
    return "NO-RAISE"


# ---------------------------------------------------------------------------
# F233: expected-usage enforcement
# ---------------------------------------------------------------------------

@probe("svid/usage-expected-usage-enforced-at-verifier")
def _p_usage_verifier():
    issuer, verifier = _svid_pair()
    mesh_svid = issuer.issue("spiffe://example.org/workload/agent1",
                             "bb" * 32, 5, profile="mesh-control", now=NOW)
    assert mesh_svid["usage"] == ["mesh-control"]
    # (a) mismatched expected usage must be refused with a machine code.
    try:
        verifier.verify(mesh_svid, now=NOW,
                        expected_usage="workload-auth")
    except TypeError:
        return _break("verify() takes no expected_usage: the signed "
                      "usage field constrains nothing (F233)")
    except sv.SvidError as e:
        if e.code != sv.SVID_USAGE_MISMATCH_CODE:
            return ("ERROR", "wrong refusal code: %s" % e.code)
    else:
        return _break("mesh-control SVID verified for expected usage "
                      "'workload-auth': usage unenforced")
    # (b) matching expected usage still verifies (no false refusal).
    try:
        claims = verifier.verify(mesh_svid, now=NOW,
                                 expected_usage="mesh-control")
    except sv.SvidError as e:
        return ("ERROR", "matching usage refused: %s" % e.code)
    if claims["usage"] != ["mesh-control"]:
        return ("ERROR", "claims usage wrong: %r" % (claims["usage"],))
    # (c) omitted expected_usage keeps the old behavior (compatible).
    verifier.verify(mesh_svid, now=NOW)
    # (d) malformed expected_usage is a caller error, not a bypass.
    code = _svid_code(lambda: verifier.verify(
        mesh_svid, now=NOW, expected_usage=123))
    if code != sv.SVID_MALFORMED_CODE:
        return ("ERROR", "bad expected_usage not malformed: %s" % code)
    return _held("usage mismatch refused with svid-usage-mismatch; "
                 "matching/omitted usage verifies")


@probe("svid/usage-policy-binding-refused-at-admit")
def _p_usage_admit():
    issuer, verifier = _svid_pair()
    mesh_svid = issuer.issue("spiffe://example.org/workload/agent1",
                             "bb" * 32, 5, profile="mesh-control", now=NOW)
    workload_svid = issuer.issue(
        "spiffe://example.org/workload/agent1",
        "bb" * 32, 5, profile="workload", now=NOW)
    # (a) the admit seam: a workload route binds allowed usages per
    # policy; a mesh-control SVID must be refused with svid-acl-denied.
    mc = sv.MeshControl(
        verifier,
        {"allow": ["spiffe://example.org/workload"],
         "usages": ["workload-auth"]})
    try:
        admitted = mc.admit(mesh_svid, now=NOW)
    except sv.SvidError as e:
        if e.code != sv.SVID_ACL_DENIED_CODE:
            return ("ERROR", "wrong refusal code: %s" % e.code)
    else:
        return _break("mesh-control SVID admitted to a workload-usage "
                      "route (%s): policy usages ignored (F233)"
                      % admitted)
    # (b) per-call expected_usage threads through admit() to the
    # verifier seam.
    mc2 = sv.MeshControl(
        verifier, {"allow": ["spiffe://example.org/workload"]})
    try:
        mc2.admit(mesh_svid, now=NOW, expected_usage="workload-auth")
    except TypeError:
        return _break("admit() takes no expected_usage (F233)")
    except sv.SvidError as e:
        if e.code != sv.SVID_USAGE_MISMATCH_CODE:
            return ("ERROR", "wrong refusal code: %s" % e.code)
    else:
        return _break("mesh-control SVID admitted with expected usage "
                      "'workload-auth'")
    # (c) control: a workload SVID is still admitted to the workload
    # route (no false refusal from the new binding).
    admitted = mc.admit(workload_svid, now=NOW)
    if admitted != "spiffe://example.org/workload/agent1":
        return ("ERROR", "workload SVID not admitted: %r" % (admitted,))
    admitted = mc2.admit(workload_svid, now=NOW,
                         expected_usage="workload-auth")
    if admitted != "spiffe://example.org/workload/agent1":
        return ("ERROR", "workload SVID not admitted (passthrough): %r"
                % (admitted,))
    return _held("usage mismatch refused (svid-acl-denied at the admit "
                 "seam; svid-usage-mismatch via expected_usage); "
                 "matching usage admitted")


@probe("svid/usage-tamper-refused-before-usage-check")
def _p_usage_tamper():
    # Control: the usage check must run over the SIGNED body only --
    # a tampered usage must die at the signature, never reach the
    # usage comparison as a pass.
    issuer, verifier = _svid_pair()
    doc = issuer.issue("spiffe://example.org/workload/agent1",
                       "bb" * 32, 5, profile="workload", now=NOW)
    forged = dict(doc)
    forged["usage"] = ["mesh-control"]
    try:
        code = _svid_code(lambda: verifier.verify(
            forged, now=NOW, expected_usage="mesh-control"))
    except TypeError:
        # Pre-fix tree: no expected_usage seam; the tamper must still
        # die at the signature check.
        code = _svid_code(lambda: verifier.verify(forged, now=NOW))
    if code != sv.SVID_SIGNATURE_INVALID_CODE:
        return _break("tampered usage not caught by signature: %s"
                      % code)
    return _held("usage tamper refused as svid-signature-invalid "
                 "(usage checked only after signature verification)")


# ---------------------------------------------------------------------------
# F234: `now` validated before every refusal decision (F228 shape)
# ---------------------------------------------------------------------------

@probe("svid/now-validated-first-in-verify")
def _p_now_verify():
    issuer, verifier = _svid_pair()
    good = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                        now=NOW)
    bad_sig = dict(good)
    bad_sig["issuer_signature"] = "00" * 64  # 128 hex chars, wrong sig
    paths = (
        ("good-path",
         lambda: verifier.verify(good, now="yesterday")),
        ("bad-sig",
         lambda: verifier.verify(bad_sig, now="yesterday")),
        ("missing",
         lambda: verifier.verify(None, now="yesterday")),
    )
    bad = ["%s=%s" % (label, _svid_code(fn))
           for label, fn in paths
           if _svid_code(fn) != sv.SVID_MALFORMED_CODE]
    if bad:
        return _break("non-numeric `now` refused as: " + ", ".join(bad) +
                      " (want svid-malformed on every path, F234)")
    return _held("`now` validated before every refusal decision in "
                 "verify()")


@probe("svid/now-validated-first-in-issue")
def _p_now_issue():
    issuer, _ = _svid_pair()
    refusal = _svid_code(
        lambda: issuer.issue("not-a-spiffe-id", "bb" * 32, 5,
                             now="yesterday"))
    goodpath = _svid_code(
        lambda: issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                             now="yesterday"))
    bad = []
    if refusal != sv.SVID_MALFORMED_CODE:
        bad.append("refusal-path=%s" % refusal)
    if goodpath != sv.SVID_MALFORMED_CODE:
        bad.append("good-path=%s" % goodpath)
    if bad:
        return _break("non-numeric `now` refused as: " + ", ".join(bad) +
                      " (want svid-malformed on every path, F234)")
    return _held("`now` validated before every refusal decision in "
                 "issue()")


@probe("svid/now-validated-first-at-admit")
def _p_now_admit():
    issuer, verifier = _svid_pair()
    good = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                        now=NOW)
    bad_sig = dict(good)
    bad_sig["issuer_signature"] = "00" * 64
    mc = sv.MeshControl(verifier,
                        {"allow": ["spiffe://example.org/w"]})
    code = _svid_code(lambda: mc.admit(bad_sig, now="yesterday"))
    if code != sv.SVID_MALFORMED_CODE:
        return _break("admit() with non-numeric `now` refused as %s "
                      "(want svid-malformed, F234)" % code)
    return _held("admit() validates `now` via verify() before any "
                 "refusal decision")


@probe("svid/past-numeric-now-still-honored")
def _p_now_hook():
    # Regression guard: the past-numeric `now` test hook (F224
    # contract) must keep working on issue/verify/admit.
    issuer, verifier = _svid_pair()
    doc = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                       now=NOW - 600.0)
    claims = verifier.verify(doc, now=NOW - 590.0)
    mc = sv.MeshControl(verifier,
                        {"allow": ["spiffe://example.org/w"]})
    admitted = mc.admit(doc, now=NOW - 590.0)
    if claims["issued_at"] != int(NOW - 600.0) or\
            admitted != "spiffe://example.org/w/a":
        return ("ERROR", "past-numeric now not honored")
    return _held("past numeric `now` honored on issue/verify/admit")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent identity batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w259_identity_probes.py",
                    "evals/w260_identity2_probes.py",
                    "evals/w260_redteam_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    # Pin checked AFTER the probes (see module docstring): the pre-fix
    # red run must still report BREAK. Exit 0 requires pin OK.
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    print("taxonomy pin OK: %d" % TAXONOMY_PIN)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
