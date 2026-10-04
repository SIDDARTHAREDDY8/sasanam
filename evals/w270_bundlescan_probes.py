"""Break-first battery: skill-bundle content scanning at the ingest seam (wave-270).

OWASP gap #2 (content half) from the wave-267 prospectus, near-term lead
from the wave-269 prospectus (modelscan pattern: ``pickletools.genops``
without execution -- pattern only, nothing copied). The skill-admission
gate (``gov.skill_admission.admit``) vouches layout/link metadata but
never looks at the artifact bytes; this battery covers the additive
content-scan composition at that seam.

Modes: ``GOV_BUNDLESCAN_IMPL=stub`` runs the probes against a permissive
stub whose ``scan_pickle_stream`` always returns a clean verdict (red
phase: attack probes MUST break). Default (module) runs them against
``gov.bundle_scan`` (green phase: attacks MUST be refused/flagged with
the exact machine code, controls MUST hold). The seam probes call the
real ``gov.skill_admission.admit`` in both modes; the red-phase
``artifact_bytes`` kwarg does not exist yet, so those probes catch the
TypeError and report BREAK (the seam is not wired).

All payloads are synthesized in-process (no network fetches). The
scanner NEVER unpickles: every probe payload that would execute on
``pickle.loads`` is scanned only, and the never-executes pin asserts no
side effect happened.

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import hashlib
import os
import pickle
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODE = os.environ.get("GOV_BUNDLESCAN_IMPL", "module")

try:
    from gov import bundle_scan as _bs
    HAVE_MODULE = True
except Exception:  # red phase: module not written yet
    _bs = None
    HAVE_MODULE = False

from gov import skill_admission as _sa
from gov import decision_codes as _dc

TAXONOMY_PIN = 2027 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



EXPECTED_CODES = (
    "bundlescan-rce-global",
    "bundlescan-suspicious-global",
    "bundlescan-unknown-global",
    "bundlescan-odd-packaging",
    "bundlescan-malformed",
    "bundlescan-oversized",
)

SENTINEL = os.path.join("/var/tmp", "g270-never-executes-sentinel")


def _impl():
    if MODE == "stub":
        return _Stub()
    if not HAVE_MODULE:
        raise RuntimeError("module not present")
    return _bs


class _Stub(object):
    """Permissive stub (red phase): scans nothing, allows everything."""

    def scan_pickle_stream(self, data, **kwargs):
        digest = hashlib.sha256(
            data if isinstance(data, (bytes, bytearray)) else b"").hexdigest()
        return {"verdict": "clean", "code": None, "severity": "none",
                "findings": [], "evidence_digest": digest,
                "payload_bytes": 0, "out_of_scope": []}


# --------------------------------------------------------------------------
# payload builders (synthesized in-process; never unpickled by the scanner)
# --------------------------------------------------------------------------

class _RceOsSystem(object):
    def __reduce__(self):
        import os as _os
        return (_os.system, ("echo g270-pwned",))


class _RcePopen(object):
    def __reduce__(self):
        import subprocess as _sp
        return (_sp.Popen, (["echo", "g270-pwned"],))


class _RceEval(object):
    def __reduce__(self):
        return (eval, ("1+1",))


class _Widget(object):
    def __init__(self):
        self.x = 1


def _p_rce_os_system():
    return pickle.dumps(_RceOsSystem(), protocol=2)


def _p_rce_popen():
    return pickle.dumps(_RcePopen(), protocol=4)


def _p_rce_eval():
    return pickle.dumps(_RceEval(), protocol=2)


def _p_getattr():
    return pickle.dumps(getattr, protocol=2)


def _p_widget():
    return pickle.dumps(_Widget(), protocol=2)


def _p_truncated():
    return _p_rce_os_system()[:10]


def _p_benign():
    return pickle.dumps({"a": [1, 2, 3], "b": "hello",
                         "c": {"nested": True}}, protocol=2)


def _p_datetime():
    import datetime
    return pickle.dumps(datetime.datetime(2020, 1, 1, 12, 0, 0),
                        protocol=2)


def _p_mangled_getattr():
    # Name-mangled gadget: no literal sink ('system' as a global) in
    # the stream -- only builtins.getattr with a concatenated
    # attribute name. Honest-limits posture: the scanner must flag the
    # getattr gadget (HIGH) but must NOT claim it caught an RCE.
    class _M(object):
        def __reduce__(self):
            return (getattr, (_ValueHolder(), "sy" + "stem"))
    return pickle.dumps(_M(), protocol=2)


def _p_hostile_reduce():
    # Would create SENTINEL via os.system if unpickled. The scanner
    # must detect the sink (CRITICAL) and must never run it.
    class _Boom(object):
        def __reduce__(self):
            import os as _os
            return (_os.system, ("touch " + SENTINEL,))
    return pickle.dumps(_Boom(), protocol=2)


class _ValueHolder(object):
    def __init__(self):
        self.x = 1


# --------------------------------------------------------------------------
# probe helpers
# --------------------------------------------------------------------------

def _scan(data, **kwargs):
    return _impl().scan_pickle_stream(data, **kwargs)


def _valid_admission():
    """A minimal valid (layout, link, authority_pub) triple."""
    from gov import ed25519
    auth_seed = hashlib.sha256(b"g270-authority").digest()
    step_seed = hashlib.sha256(b"g270-step-signer").digest()
    auth_pub = ed25519.publickey(auth_seed).hex()
    step_pub = ed25519.publickey(step_seed).hex()
    layout = _sa.make_layout(
        "g270-layout",
        [{"name": "build", "command": ["make", "bundle"],
          "signer_pub": step_pub, "rules": [("DISALLOW",)]}],
        auth_seed)
    link = _sa.make_link("g270-layout", "build", ["make", "bundle"],
                         {}, {}, step_seed)
    return layout, [link], auth_pub


def _seam_admit(payloads):
    """admit() with the artifact_bytes kwarg; red phase -> TypeError."""
    layout, links, auth_pub = _valid_admission()
    return _sa.admit(layout, links, auth_pub, artifact_bytes=payloads)


# --------------------------------------------------------------------------
# probes: (name, kind, fn) -- fn returns (status, note)
# --------------------------------------------------------------------------

def p01_rce_os_system():
    v = _scan(_p_rce_os_system())
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-rce-global":
        return "HELD", "os.system reduce refused"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p02_rce_popen():
    v = _scan(_p_rce_popen())
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-rce-global":
        return "HELD", "STACK_GLOBAL subprocess.Popen refused"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p03_rce_eval():
    v = _scan(_p_rce_eval())
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-rce-global":
        return "HELD", "builtins.eval reduce refused"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p04_gadget_getattr():
    v = _scan(_p_getattr())
    if v["code"] == "bundlescan-suspicious-global"\
            and v["verdict"] == "advisory":
        return "HELD", "getattr gadget flagged HIGH advisory"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p05_unknown_custom_global():
    v = _scan(_p_widget())
    if v["code"] == "bundlescan-unknown-global"\
            and v["verdict"] == "advisory":
        return "HELD", "unknown custom class flagged MEDIUM advisory"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p06_truncated():
    v = _scan(_p_truncated())
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-malformed":
        return "HELD", "truncated stream fails closed"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p07_empty():
    v = _scan(b"")
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-malformed":
        return "HELD", "empty payload fails closed"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p08_oversized():
    v = _scan(_p_benign() * 4, max_bytes=64)
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-oversized":
        return "HELD", "oversized payload refused before parsing"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p09_non_bytes():
    v = _scan("not bytes at all")
    if v["verdict"] == "refuse" and v["code"] == "bundlescan-malformed":
        return "HELD", "non-bytes input fails closed"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def p10_never_executes():
    if os.path.exists(SENTINEL):
        os.remove(SENTINEL)
    v = _scan(_p_hostile_reduce())
    executed = os.path.exists(SENTINEL)
    if executed:
        return "ERROR", "SCANNER EXECUTED THE PAYLOAD"
    if v["verdict"] == "clean":
        return "BREAK", "hostile reduce not detected (blind scanner)"
    return "HELD", "detected, nothing executed (code=%s)" % (v["code"],)


def p11_seam_critical_refuses():
    try:
        verdict = _seam_admit({"model.pkl": _p_rce_os_system()})
    except TypeError:
        return "BREAK", "admit() has no artifact_bytes seam (red phase)"
    if verdict["admitted"] is False\
            and verdict["code"] == "bundlescan-rce-global":
        ev = verdict.get("evidence", {}).get("content_scan", {})
        if "model.pkl" in str(ev):
            return "HELD", "seam refuses CRITICAL with artifact identity"
        return "BREAK", "refused but artifact identity missing"
    return "BREAK", "admitted=%s code=%s" % (verdict["admitted"],
                                            verdict["code"])


def p12_mangled_no_overclaim():
    # Honest-limits invariant: the scanner flags the gadget but must
    # never claim it caught the RCE it cannot see.
    v = _scan(_p_mangled_getattr())
    if v["code"] == "bundlescan-rce-global":
        return "BREAK", "OVERCLAIM: mangled payload called RCE"
    if v["code"] == "bundlescan-suspicious-global":
        return "HELD", "gadget flagged, no RCE overclaim"
    return "BREAK", "verdict=%s code=%s" % (v["verdict"], v["code"])


def c01_benign_plain():
    v = _scan(_p_benign())
    if v["verdict"] == "clean" and v["code"] is None:
        return "HELD", "benign pickle clean"
    return "BREAK", "FALSE POSITIVE verdict=%s code=%s" % (v["verdict"],
                                                          v["code"])


def c02_benign_datetime():
    v = _scan(_p_datetime())
    if v["verdict"] == "clean" and v["code"] is None:
        return "HELD", "allowlisted stdlib globals clean"
    return "BREAK", "FALSE POSITIVE verdict=%s code=%s" % (v["verdict"],
                                                           v["code"])


def c03_legacy_admit_untouched():
    layout, links, auth_pub = _valid_admission()
    verdict = _sa.admit(layout, links, auth_pub)
    if verdict["admitted"] is True\
            and "content_scan" not in verdict.get("evidence", {}):
        return "HELD", "legacy admit path byte-identical"
    return "BREAK", "admitted=%s evidence-keys=%s" % (
        verdict["admitted"], sorted(verdict.get("evidence", {}).keys()))


def c04_benign_seam():
    try:
        verdict = _seam_admit({"data.pkl": _p_benign()})
    except TypeError:
        return "BREAK", "admit() has no artifact_bytes seam (red phase)"
    ev = verdict.get("evidence", {}).get("content_scan", {})
    if verdict["admitted"] is True and ev.get("verdict") == "clean":
        return "HELD", "benign payload admitted, scan evidenced"
    return "BREAK", "admitted=%s scan=%s" % (verdict["admitted"], ev)


def c05_deterministic():
    a = _scan(_p_rce_popen())
    b = _scan(_p_rce_popen())
    if a == b:
        return "HELD", "A==B deterministic"
    return "BREAK", "nondeterministic verdicts"


def c06_advisory_seam_still_admits():
    # Advisory findings are loud evidence, never a denial.
    try:
        verdict = _seam_admit({"model.pkl": _p_widget()})
    except TypeError:
        return "BREAK", "admit() has no artifact_bytes seam (red phase)"
    ev = verdict.get("evidence", {}).get("content_scan", {})
    advisories = ev.get("advisories", [])
    named = any(a.get("artifact") == "model.pkl"
                and a.get("code") == "bundlescan-unknown-global"
                for a in advisories)
    if verdict["admitted"] is True and named:
        return "HELD", "advisory recorded with identity, still admitted"
    return "BREAK", "admitted=%s advisories=%s" % (verdict["admitted"],
                                                  advisories)


def c07_pin_registered():
    missing = [c for c in EXPECTED_CODES
               if c not in _dc.TAXONOMY]
    if not missing and len(_dc.TAXONOMY) == TAXONOMY_PIN:
        return "HELD", "6 codes registered, pin 1579"
    return "BREAK", "missing=%s len=%s" % (missing, len(_dc.TAXONOMY))


PROBES = [
    ("p01/rce-os-system", "attack", p01_rce_os_system),
    ("p02/rce-popen-stack-global", "attack", p02_rce_popen),
    ("p03/rce-builtin-eval", "attack", p03_rce_eval),
    ("p04/gadget-getattr-high", "attack", p04_gadget_getattr),
    ("p05/unknown-custom-global", "attack", p05_unknown_custom_global),
    ("p06/truncated-malformed", "attack", p06_truncated),
    ("p07/empty-malformed", "attack", p07_empty),
    ("p08/oversized", "attack", p08_oversized),
    ("p09/non-bytes-malformed", "attack", p09_non_bytes),
    ("p10/never-executes", "attack", p10_never_executes),
    ("p11/seam-critical-refuses", "attack", p11_seam_critical_refuses),
    ("p12/mangled-no-overclaim", "attack", p12_mangled_no_overclaim),
    ("c01/benign-plain-clean", "control", c01_benign_plain),
    ("c02/benign-datetime-clean", "control", c02_benign_datetime),
    ("c03/legacy-admit-untouched", "control", c03_legacy_admit_untouched),
    ("c04/benign-seam-admits", "control", c04_benign_seam),
    ("c05/deterministic", "control", c05_deterministic),
    ("c06/advisory-seam-still-admits", "control",
     c06_advisory_seam_still_admits),
    ("c07/pin-registered", "control", c07_pin_registered),
]


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    results = []
    tmp = "/var/tmp/g270bscan-green"
    os.makedirs(tmp, exist_ok=True)
    # Adjacent battery: bundle admission legacy pins (bin-04 must hold).
    adj = os.path.join(REPO_ROOT, "evals", "w221_admission_probes.py")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, adj], capture_output=True, text=True,
            env=env, timeout=600, cwd=REPO_ROOT)
        lines = p.stdout.splitlines()
        # D8 (wave-316 lane 3): w221_admission_probes now emits canonical
        # bracketed probe lines ([BREAK]/[ERROR]); the old bare "BREAK "
        # prefixes are kept for backward compatibility.
        bad = [l for l in lines
               if l.startswith("BREAK ") or l.startswith("MISMATCH")
               or l.startswith("ERROR ") or l.startswith("[BREAK]")
               or l.startswith("[ERROR]")]
        ok = not bad and p.returncode == 0
        results.append(("green-check:w221_admission_probes",
                        "HELD" if ok else "BREAK",
                        "rc=%d bad=%d" % (p.returncode, len(bad))))
    except Exception as exc:  # noqa: BLE001
        results.append(("green-check:w221_admission_probes", "ERROR",
                        "%r" % (exc,)))
    # Adjacent unit suite: skill admission contract. The taxonomy pin
    # is lane-local (1325 -> 1331) and is repointed by the merge
    # coordinator: the green check treats the pin assertion as the
    # ONLY acceptable failure; anything else is red.
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_skill_admission", "-v"],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stderr or "") + (p.stdout or "")
        only_pin = (p.returncode != 0
                    and "test_taxonomy_pin" in out
                    and "1331 != 1325" in out
                    and out.count("FAIL:") == 1)
        if p.returncode == 0:
            note = "rc=0"
        elif only_pin:
            note = ("pin-only drift (expected: 1325->1331; merge "
                    "coordinator repoints)")
        else:
            note = "rc=%d (non-pin failure)" % (p.returncode,)
        results.append(("green-check:tests.test_skill_admission",
                        "HELD" if p.returncode == 0 or only_pin
                        else "BREAK",
                        note))
    except Exception as exc:  # noqa: BLE001
        results.append(("green-check:tests.test_skill_admission", "ERROR",
                        "%r" % (exc,)))
    return results


def main():
    tmp = "/var/tmp/g270bscan"
    os.makedirs(tmp, exist_ok=True)
    os.environ["TMPDIR"] = tmp
    held = brk = err = 0
    print("mode=%s probes=%d" % (MODE, len(PROBES)))
    for name, kind, fn in PROBES:
        try:
            status, note = fn()
        except Exception as exc:  # noqa: BLE001
            status, note = "ERROR", "%r" % (exc,)
        print("%s %s [%s] -- %s" % (status, name, kind, note))
        if status == "HELD":
            held += 1
        elif status == "BREAK":
            brk += 1
        else:
            err += 1
    for name, status, note in _green_check():
        print("%s %s [green] -- %s" % (status, name, note))
        if status == "HELD":
            held += 1
        elif status == "BREAK":
            brk += 1
        elif status == "ERROR":
            err += 1
    print("HELD=%d BREAK=%d ERROR=%d" % (held, brk, err))
    print("RESULT " + ("OK" if brk == 0 and err == 0 else "FAIL"))


if __name__ == "__main__":
    main()
