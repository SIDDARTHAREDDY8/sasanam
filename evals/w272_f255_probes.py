"""Break-first battery: F255 closure -- INST/OBJ/NEWOBJ join the sink rule (wave-272).

Close-when criteria (from evals/FINDINGS.md F255):
(1) INST/OBJ/NEWOBJ are call-capable opcodes in the sink rule: a resolved
    sink global (GLOBAL/STACK_GLOBAL for OBJ/NEWOBJ; the INST opcode
    argument for INST) plus INST/OBJ/NEWOBJ present refuses with the sink
    code, exactly as REDUCE does.
(2) probes b01/b02/b03/x02a (adapted here as a01..a03/x01) flip to HELD.
(3) b04 (REDUCE refuse), b05 (mangled advisory), b06 (truncated refuse),
    b07 (benign clean) verdicts unchanged (adapted as c01..c04).
(4) adjacent battery evals/w270_bundlescan_probes.py green.

The attack probes assert POST-FIX behavior; run them against the
unfixed module first (they BREAK), then fix, then re-run (they HELD).
The control probes MUST stay HELD before and after the fix -- a fix
that refuses everything is vacuous, and c05 pins the anti-vacuous
property (OBJ of an unknown class is advisory MEDIUM, never refused).

All payloads are synthesized in-process (no network). The scanner is
NEVER asked to unpickle; the one deliberate pickle.loads (probe a01)
demonstrates the attack is real and is the only execution anywhere.

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git
subprocesses; fresh /var/tmp/g272* TMPDIRs; stdlib only.
"""

import contextlib
import hashlib
import io
import os
import pickle
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import bundle_scan as _bs  # noqa: E402
from gov import skill_admission as _sa  # noqa: E402

TAXONOMY_PIN = 2056 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*)



SINK_CODE = "bundlescan-rce-global"
UNKNOWN_CODE = "bundlescan-unknown-global"

# --- Payloads (hand-crafted protocol-0/4 streams) ---------------------------
# INST: the sink hides in the INST opcode argument; no GLOBAL at all.
_INST_PRINT = b"(Vhello-from-inst\ni" + b"builtins\nprint\n" + b"."
_INST_SYSTEM = b"(Vecho-hi\ni" + b"os\nsystem\n" + b"."
# OBJ: MARK, GLOBAL, UNICODE, OBJ (stack discipline). No REDUCE.
_OBJ_SYSTEM = b"(cos\nsystem\nVecho-hi\no."
# NEWOBJ: MARK, GLOBAL, UNICODE, NEWOBJ (opcode \x81). No REDUCE.
_NEWOBJ_SYSTEM = b"(cos\nsystem\nVecho-hi\n\x81."
# STACK_GLOBAL + OBJ: sink resolved from the two most recent string
# pushes, not from an inline GLOBAL argument.
_STACKGLOBAL_OBJ_SYSTEM = (
    b"(\x80\x04"                           # MARK, PROTO 4
    b"X\x02\x00\x00\x00os\x94"             # BINUNICODE 'os', MEMOIZE
    b"X\x06\x00\x00\x00system\x94"         # BINUNICODE 'system', MEMOIZE
    b"\x93"                                # STACK_GLOBAL
    b"X\x07\x00\x00\x00echo-hi\x94"        # BINUNICODE 'echo-hi', MEMOIZE
    b"o."                                  # OBJ, STOP
)
# OBJ of an unlisted custom class: must be advisory MEDIUM, NEVER a
# refusal (anti-vacuous pin -- INST/OBJ/NEWOBJ do not make the scanner
# refuse everything).
_OBJ_UNKNOWN = b"(cmyapp\nWidget\nVhello\no."


def _reduce_evil():
    class _Evil(object):
        def __reduce__(self):
            import os as _os
            return (_os.system, ("id",))
    return pickle.dumps(_Evil(), protocol=2)


class _ValueHolder(object):
    def __init__(self):
        self.x = 1


class _Mangled(object):
    def __reduce__(self):
        from builtins import getattr as _ga
        return (_ga, (_ValueHolder(), "sy" + "stem"))


def _mangled_getattr():
    return pickle.dumps(_Mangled(), protocol=2)


def _truncated():
    return pickle.dumps({"a": 1}, protocol=2)[:6]


def _benign():
    import datetime
    return pickle.dumps(datetime.datetime(2026, 1, 1), protocol=2)


# --- Attack probes (MUST break on the unfixed module) ----------------------


def a01_inst_executes_flagged():
    """F255 b01: protocol-0 INST builtins.print executes at load (proven)
    and must not scan clean with zero findings."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pickle.loads(_INST_PRINT)
    executed = (buf.getvalue() == "hello-from-inst\n")
    res = _bs.scan_pickle_stream(_INST_PRINT)
    if not executed:
        return "ERROR", "INST payload did not execute (probe broken)"
    if res["verdict"] == "clean" and not res["findings"]:
        return ("BREAK",
                "F255: INST stream executes at load yet scans clean "
                "with zero findings -- INST unmodeled")
    return "HELD", "INST stream flagged: %s" % (res["verdict"],)


def a02_inst_sink_refused():
    """F255 b02: INST naming the os.system sink must refuse with the
    sink code (sink from the INST argument)."""
    res = _bs.scan_pickle_stream(_INST_SYSTEM)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and SINK_CODE in codes:
        return "HELD", "INST sink refused %s" % (codes,)
    return ("BREAK",
            "F255: INST os.system -> %r %r (not refused with %s)"
            % (res["verdict"], codes, SINK_CODE))


def a03_obj_sink_refused():
    """F255 b03: OBJ of os.system (no REDUCE) must refuse with the sink
    code (sink from GLOBAL, call from OBJ)."""
    res = _bs.scan_pickle_stream(_OBJ_SYSTEM)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and SINK_CODE in codes:
        return "HELD", "OBJ sink refused %s" % (codes,)
    return ("BREAK",
            "F255: OBJ os.system -> %r %r (not refused with %s)"
            % (res["verdict"], codes, SINK_CODE))


def a04_newobj_sink_refused():
    """F255: NEWOBJ of os.system (no REDUCE) must refuse with the sink
    code -- NEWOBJ is a call-capable opcode too."""
    res = _bs.scan_pickle_stream(_NEWOBJ_SYSTEM)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and SINK_CODE in codes:
        return "HELD", "NEWOBJ sink refused %s" % (codes,)
    return ("BREAK",
            "F255: NEWOBJ os.system -> %r %r (not refused with %s)"
            % (res["verdict"], codes, SINK_CODE))


def a05_stackglobal_obj_sink_refused():
    """F255 close-when (1): sink resolved from STACK_GLOBAL + OBJ
    must refuse with the sink code."""
    res = _bs.scan_pickle_stream(_STACKGLOBAL_OBJ_SYSTEM)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and SINK_CODE in codes:
        return "HELD", "STACK_GLOBAL+OBJ sink refused %s" % (codes,)
    return ("BREAK",
            "F255: STACK_GLOBAL os.system + OBJ -> %r %r (not refused)"
            % (res["verdict"], codes))


# --- Seam probe (adapts x02a) ------------------------------------------------

_SEAM_LAYOUT_ID = "skill/w272-f255-v1"
_SEAM_CMD = ["fetch-skill", "--src", "skill-src.zip"]
_SEAM_D1 = hashlib.sha256(b"skill-src-bytes").hexdigest()


def _seed(byte):
    return bytes([byte]) * 32


def _x_admit(payload):
    from gov import ed25519 as _ed
    a_seed, s_seed = _seed(0xD1), _seed(0xD2)
    a_pub, s_pub = (_ed.publickey(a_seed).hex(),
                    _ed.publickey(s_seed).hex())
    digest = hashlib.sha256(payload).hexdigest()
    layout = _sa.make_layout(
        _SEAM_LAYOUT_ID,
        steps=[{"name": "fetch", "command": list(_SEAM_CMD),
                "signer_pub": s_pub,
                "rules": [("REQUIRE", "skill-src.zip"),
                          ("MATCH", "skill.tar.gz", digest),
                          ("DISALLOW",)]}],
        layout_seed=a_seed)
    link = _sa.make_link(
        _SEAM_LAYOUT_ID, "fetch", list(_SEAM_CMD),
        materials={"skill-src.zip": _SEAM_D1},
        products={"skill.tar.gz": digest},
        signer_seed=s_seed)
    return _sa.admit(layout, [link], a_pub,
                     artifact_bytes={"skill.tar.gz": payload})


def x01_inst_payload_refused_at_admission():
    """F255 x02a: INST os.system through the admission seam must refuse
    (never admitted)."""
    verdict = _x_admit(_INST_SYSTEM)
    if verdict["admitted"] is False and verdict["code"] == SINK_CODE:
        return "HELD", "INST payload refused %s" % (verdict["code"],)
    return ("BREAK",
            "F255 cross-seam: INST os.system -> admitted=%r code=%r "
            "(registry would ingest a load-time RCE)"
            % (verdict["admitted"], verdict.get("code")))


# --- Control probes (MUST stay HELD before and after the fix) ---------------


def c01_reduce_sink_refused():
    res = _bs.scan_pickle_stream(_reduce_evil())
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and SINK_CODE in codes:
        return "HELD", "REDUCE sink refused (%s)" % (codes,)
    return "BREAK", "REDUCE sink NOT refused: %r %r" % (res["verdict"],
                                                       codes)


def c02_mangled_advisory():
    """Honest-limit pin: name-mangled gadget -> advisory, never a
    claimed RCE catch."""
    res = _bs.scan_pickle_stream(_mangled_getattr())
    if res["verdict"] == "advisory":
        return "HELD", "mangled gadget advisory (honest limit pinned)"
    return "ERROR", "unexpected verdict: %r" % (res["verdict"],)


def c03_truncated_malformed():
    res = _bs.scan_pickle_stream(_truncated())
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and "bundlescan-malformed" in codes:
        return "HELD", "truncated stream refused bundlescan-malformed"
    return "ERROR", "unexpected: %r %r" % (res["verdict"], codes)


def c04_benign_clean():
    res = _bs.scan_pickle_stream(_benign())
    if res["verdict"] == "clean":
        return "HELD", "benign datetime clean"
    return "BREAK", "benign false-denial: %r" % (res["verdict"],)


def c05_obj_unknown_advisory_not_refused():
    """Anti-vacuous pin: OBJ of an unlisted custom class is MEDIUM
    advisory, never a refusal -- call-capable opcodes do not make the
    scanner refuse everything."""
    res = _bs.scan_pickle_stream(_OBJ_UNKNOWN)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "advisory" and UNKNOWN_CODE in codes:
        return "HELD", "OBJ unknown class advisory (not refused)"
    return ("BREAK",
            "unexpected: %r %r (expected advisory %s, never refuse)"
            % (res["verdict"], codes, UNKNOWN_CODE))


def c06_pin():
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "decision_codes.py")).read()
    codes = re.findall(
        r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN:
        return "HELD", "pin 1541 holds"
    return ("ERROR",
            "pin drift: %d literals / %d unique (expected %d)"
            % (len(codes), len(set(codes)), TAXONOMY_PIN))


PROBES = [
    ("a01-inst-executes-flagged", "attack", a01_inst_executes_flagged),
    ("a02-inst-sink-refused", "attack", a02_inst_sink_refused),
    ("a03-obj-sink-refused", "attack", a03_obj_sink_refused),
    ("a04-newobj-sink-refused", "attack", a04_newobj_sink_refused),
    ("a05-stackglobal-obj-sink-refused", "attack",
     a05_stackglobal_obj_sink_refused),
    ("x01-inst-payload-refused-at-admission", "seam",
     x01_inst_payload_refused_at_admission),
    ("c01-reduce-sink-refused", "control", c01_reduce_sink_refused),
    ("c02-mangled-advisory", "control", c02_mangled_advisory),
    ("c03-truncated-malformed", "control", c03_truncated_malformed),
    ("c04-benign-clean", "control", c04_benign_clean),
    ("c05-obj-unknown-advisory-not-refused", "control",
     c05_obj_unknown_advisory_not_refused),
    ("c06-pin", "control", c06_pin),
]


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    results = []
    tmp = "/var/tmp/g272f255-green"
    os.makedirs(tmp, exist_ok=True)
    # Adjacent battery: the original bundle-scan battery must stay green.
    adj = os.path.join(REPO_ROOT, "evals", "w270_bundlescan_probes.py")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, adj], capture_output=True, text=True,
            env=env, timeout=600, cwd=REPO_ROOT)
        lines = p.stdout.splitlines()
        bad = [l for l in lines
               if l.startswith("BREAK ") or l.startswith("ERROR ")]
        ok = not bad and p.returncode == 0
        results.append(("green-check:w270_bundlescan_probes",
                        "HELD" if ok else "BREAK",
                        "rc=%d bad=%d" % (p.returncode, len(bad))))
    except Exception as exc:  # noqa: BLE001
        results.append(("green-check:w270_bundlescan_probes", "ERROR",
                        "%r" % (exc,)))
    return results


def main():
    tmp = "/var/tmp/g272f255"
    os.makedirs(tmp, exist_ok=True)
    os.environ["TMPDIR"] = tmp
    held = brk = err = 0
    print("probes=%d" % (len(PROBES),))
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
