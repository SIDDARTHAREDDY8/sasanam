"""Break-first battery for gov/control_profiles.py (wave-257 lane 2).

inspec/inspec ADAPT (pattern only; Apache-2.0): a declarative
controls-as-code profile -- named controls with impact, title, desc,
and executable check callables -- evaluated to typed result records
that compose with gov/compliance_emitter.py (wave-254). Pattern only;
no InSpec code, and never the >=5.0 packaged binary (Chef EULA trap).

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break
attempt succeeds. A genuine BREAK against the final implementation
would file a finding; this battery must be all HELD on the shipped
module.

Related prospectus gap: W256-2 (wave-256 prospectus). Next free: F220.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 2106 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).



try:
    from gov import decision_codes
    from gov import control_profiles as cp
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    _n = len(decision_codes.TAXONOMY)
    # Wave-258 merge: pin -> 1080.
    assert _n == TAXONOMY_PIN,\
        "taxonomy drift: %d != %d" % (_n, TAXONOMY_PIN)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _ok(snapshot):
    return True


def _no(snapshot):
    return False


def _boom(snapshot):
    raise RuntimeError("check exploded")


def _profile(controls, **kw):
    p = {"id": "PROF-001", "title": "Demo profile",
         "controls": controls}
    p.update(kw)
    return p


def _control(cid, check, impact=0.9, **kw):
    c = {"id": cid, "impact": impact, "title": "Control %s" % cid,
         "desc": "desc for %s" % cid, "check": check}
    c.update(kw)
    return c


@probe
def p_duplicate_control_ids_refused():
    """Duplicate control ids must refuse
    (control-profile-duplicate-control-id) -- a duplicated id would
    let one result silently stand in for another."""
    try:
        cp.run_profile(
            _profile([_control("C1", _ok), _control("C1", _no)]), {})
    except cp.ControlProfileError as exc:
        return "HELD" if exc.code ==\
            "control-profile-duplicate-control-id" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def p_non_callable_check_refused():
    """A non-callable check -- including a STRING (serialized /
    call-by-name) -- must refuse (control-profile-non-callable-check).
    No eval of stored strings, ever."""
    for bad_check in ("some.module.check", 42, None):
        try:
            cp.run_profile(
                _profile([_control("C1", bad_check)]), {})
        except cp.ControlProfileError as exc:
            if exc.code != "control-profile-non-callable-check":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    return "HELD"


@probe
def p_empty_controls_refused():
    """A profile with zero controls must refuse
    (control-profile-empty) -- a vacuous profile must never pass."""
    try:
        cp.run_profile(_profile([]), {})
    except cp.ControlProfileError as exc:
        return "HELD" if exc.code ==\
            "control-profile-empty" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def p_unknown_key_refused():
    """Unknown keys -- top-level and control-level -- must refuse
    (control-profile-unknown-key). A typo must never silently change
    what gets checked."""
    bad_top = _profile([_control("C1", _ok)], impct=0.5)
    bad_ctl = _profile([_control("C1", _ok, impct=0.5)])
    for bad in (bad_top, bad_ctl):
        try:
            cp.run_profile(bad, {})
        except cp.ControlProfileError as exc:
            if exc.code != "control-profile-unknown-key":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    return "HELD"


@probe
def p_impact_bounds_refused():
    """Impact outside [0.0, 1.0] -- or a non-number, or a bool (bool
    is an int subclass) -- must refuse
    (control-profile-invalid-impact)."""
    for bad_impact in (-0.1, 1.1, "high", None, True, float("nan")):
        try:
            cp.run_profile(
                _profile([_control("C1", _ok, impact=bad_impact)]), {})
        except cp.ControlProfileError as exc:
            if exc.code != "control-profile-invalid-impact":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    # boundary values are legal
    res = cp.run_profile(
        _profile([_control("C1", _ok, impact=0.0),
                  _control("C2", _ok, impact=1.0)]), {})
    return "HELD" if res["success"] else "BREAK"


@probe
def p_severity_mapping():
    """Impact maps to severity deterministically: >=0.7 high,
    >=0.4 medium, <0.4 low. Machine-coded per control result."""
    res = cp.run_profile(
        _profile([_control("H", _ok, impact=0.7),
                  _control("M", _ok, impact=0.4),
                  _control("L", _ok, impact=0.39)]), {})
    sev = {r["control_id"]: r["severity"] for r in res["results"]}
    want = {"H": "high", "M": "medium", "L": "low"}
    return "HELD" if sev == want else "BREAK"


@probe
def p_check_raising_becomes_error():
    """A check that raises must become an error RESULT
    (exception_info set, profile success False) -- never a crash of
    the whole evaluation."""
    res = cp.run_profile(_profile([_control("C1", _boom)]), {})
    if res["success"]:
        return "BREAK"
    r = res["results"][0]
    if r["status"] != "error":
        return "BREAK"
    if not r.get("exception_info") or\
            "RuntimeError" not in r["exception_info"].get("raised", ""):
        return "BREAK"
    return "HELD"


@probe
def p_fail_result_maps_to_finding():
    """A failing control must surface in the emitted artifact as a
    finding mapping (impact-weighted severity in the rationale)."""
    res = cp.run_profile(_profile([_control("C1", _no, impact=0.9)]),
                         {})
    out = cp.emit_profile_results(res, fmt="json")
    if '"kind": "finding"' not in out and\
            '"kind":"finding"' not in out:
        return "BREAK"
    if "high" not in out:
        return "BREAK"
    if "C1" not in out:
        return "BREAK"
    return "HELD"


@probe
def p_pass_result_maps_clean():
    """An all-pass profile must emit a linked artifact (the
    check-passed code mapping keeps the emitter's no-vacuous-claim
    contract); no finding mappings appear."""
    res = cp.run_profile(_profile([_control("C1", _ok)]), {})
    out = cp.emit_profile_results(res, fmt="json")
    if "control-profile-check-passed" not in out:
        return "BREAK"
    if '"kind": "finding"' in out or '"kind":"finding"' in out:
        return "BREAK"
    return "HELD"


@probe
def p_evidence_must_be_mapping():
    """A non-dict evidence snapshot must refuse
    (control-profile-evidence-malformed)."""
    for bad in (["not", "a", "dict"], None, "nope"):
        try:
            cp.run_profile(_profile([_control("C1", _ok)]), bad)
        except cp.ControlProfileError as exc:
            if exc.code != "control-profile-evidence-malformed":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    return "HELD"


@probe
def p_quality_gate_failure_blocks_emit():
    """quality_gate=True with a failing evidence-quality expectation
    must refuse (control-profile-gate-failed) before the emitter
    ever runs."""
    res = cp.run_profile(_profile([_control("C1", _ok)]), {})
    try:
        cp.emit_profile_results(
            res, fmt="json", quality_gate=True,
            quality_expectations=[
                {"expectation_type": "expect_evidence_monotonic",
                 "kwargs": {}}],
            quality_evidence=[{"seq": 2}, {"seq": 1}])
    except cp.ControlProfileError as exc:
        return "HELD" if exc.code ==\
            "control-profile-gate-failed" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def p_profile_digest_stable():
    """The profile digest is deterministic across runs (same declared
    profile -> same digest), so an auditor can detect drift."""
    prof = _profile([_control("C1", _ok, impact=0.5)])
    d1 = cp.profile_digest(prof)
    d2 = cp.profile_digest(prof)
    if d1 != d2 or len(d1) != 64:
        return "BREAK"
    r1 = cp.run_profile(prof, {})
    r2 = cp.run_profile(prof, {})
    if r1["profile_digest"] != r2["profile_digest"] != d1:
        return "BREAK"
    return "HELD"


@probe
def p_check_swap_behind_same_name_undetected():
    """HONEST RESIDUAL (pinned, not a finding): the digest binds the
    check qualname + declared version, NOT the check bytecode. Two
    different function bodies under the same __qualname__ produce the
    SAME digest -- a deployment that swaps a body silently breaks the
    binding. The battery pins this limitation openly."""
    def check_a(snapshot):
        return True

    def check_b(snapshot):
        return False  # different body, same declared identity
    check_b.__qualname__ = check_a.__qualname__
    d1 = cp.profile_digest(_profile([_control("C1", check_a)]))
    d2 = cp.profile_digest(_profile([_control("C1", check_b)]))
    # The residual: digests agree despite different bodies.
    return "HELD" if d1 == d2 else "BREAK"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest",
         "tests.test_compliance_emitter", "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
        [sys.executable, "-m", "unittest",
         "tests.test_evidence_quality", "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g257-prof-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: compliance_emitter + decision_codes + "
          "evidence_quality green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                 len(results)))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    sys.exit(0 if (gap or (held, brk, gap) == (len(PROBES), 0, 0)) and ok
             else 1)
