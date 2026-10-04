"""Break-first probes for the wave-326 background scan scheduler.

Red-first: gov/background_scan.py is new in this lane, so "red" is
demonstrated two ways: (1) every probe below FAILS on the base tree
(c819b56) with ImportError (the module does not exist there); (2) the
product was mutated during development (trigger evaluation neutered,
content-binding removed, crash sidecar dropped) and each mutation made
exactly the corresponding probes BREAK -- the battery is genuinely
coupled to the behavior, not to the module's existence.

What the battery pins:
1. Three triggers: interval-due, delegation-version bump (policy change),
   and skill-bytes change (resource change) each force a re-verification.
2. Signer rotated out of the delegation document is flagged within one
   interval with the specific admission-path code (no lifecycle
   transition occurs -- the scheduler does it).
3. Delegation dropped by absence is refused LOUD (revocation by absence).
4. Mutated bytes are refused with supplychain-scan-content-mismatch even
   when the authority chain still verifies (SkillJacking shape).
5. TTL expiry without a successful re-verification lapses the standing
   LOUD (supplychain-standing-lapsed); a successful re-verification
   renews it. Revocation is by non-renewal.
6. The scanner never enforces: no quarantine/disable/uninstall entry
   point exists; a refused scan changes no standing except recording the
   verdict.
7. Crash mid-scan (sidecar left behind) is reported LOUD on the next run
   (supplychain-scan-crash-recovered) and the skill is re-scanned.
8. Missed intervals are caught up LOUD (supplychain-scan-missed-interval),
   never silently skipped.
9. Corrupt / missing state fails LOUD and fail-closed.

Staging default is set at module level (the harness refuses the declared
ungoverned_ack in production mode).
"""

import base64
import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2027  # Wave-326 lane 3: pin 2020 -> 2027 (+7 supplychain-scan-*/supplychain-standing-lapsed)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Imports.
# ---------------------------------------------------------------------------

from gov import background_scan as BS  # noqa: E402
from gov import skill_supply_chain as SC  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures (fixed seeds: deterministic keys across runs).
# ---------------------------------------------------------------------------

def _seed(tag):
    return (tag + "-seed").ljust(32, "0")[:32].encode("ascii")


_R1 = Ed25519Signer(_seed("sched-r1"))
_P1 = Ed25519Signer(_seed("sched-p1"))
_P2 = Ed25519Signer(_seed("sched-p2"))
_M1 = Ed25519Signer(_seed("sched-m1"))

FUTURE = "2030-01-01T00:00:00Z"
T0 = 1800000000

SKILL = "skills/pay/x"
BYTES_V1 = b"skill-content-v1"
BYTES_V2 = b"skill-content-v2-tampered"


def _keyinfo(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


KEYS = {"r1": _keyinfo(_R1), "pay-k1": _keyinfo(_P1),
        "pay-k2": _keyinfo(_P2), "mallory": _keyinfo(_M1)}
ROOT_TRUST = {"keys": KEYS, "root": {"keyids": ["r1"], "threshold": 1}}


def _deleg_doc(version, delegations, expires=FUTURE):
    return {"version": version, "expires": expires,
            "delegations": delegations}


def _deleg(name, keyids, threshold, paths):
    return {"name": name, "keyids": keyids, "threshold": threshold,
            "paths": paths, "terminating": False}


def _authz_doc(skill, digest, version=1, expires=FUTURE):
    return {"skill": skill, "version": version, "digest": digest,
            "expires": expires}


def _seal(kind, doc, pairs):
    return SC.seal_document(kind, doc, pairs)


def _digest(b):
    return hashlib.sha256(b).hexdigest()


def _deleg_wire(version, keyids=("pay-k1",), name="pay"):
    doc = _deleg_doc(version, [_deleg(name, list(keyids), 1,
                                     ["skills/pay/*"])])
    return _seal("delegations", doc, [("r1", _R1)])


def _authz_wire(skill_bytes, signer=("pay-k1", _P1), version=1):
    doc = _authz_doc(SKILL, _digest(skill_bytes), version=version)
    return _seal("link", doc, [signer])


def _tmp_state():
    d = tempfile.mkdtemp(prefix="sched-")
    return os.path.join(d, "state.json")


def _register(state_path, now=T0, skill_bytes=BYTES_V1, ttl=3600,
              interval=900, deleg_wire=None, authz_wire=None):
    dw = deleg_wire or _deleg_wire(1)
    aw = authz_wire or _authz_wire(skill_bytes)
    return BS.register_skill(
        state_path, skill_path=SKILL, delegation_wire=dw, authz_wire=aw,
        skill_bytes=skill_bytes, ttl_seconds=ttl,
        scan_interval_seconds=interval, now=now)


def _inv(skill_bytes=BYTES_V1, deleg_wire=None, authz_wire=None):
    return [{"skill_path": SKILL, "skill_bytes": skill_bytes,
             "delegation_wire": deleg_wire or _deleg_wire(1),
             "authz_wire": authz_wire or _authz_wire(skill_bytes)}]


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

@probe("P1-register-then-first-scan-verified")
def _p1():
    sp = _tmp_state()
    _register(sp, now=T0)
    reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)
    assert len(reports) == 1, reports
    r = reports[0]
    assert r["schema"] == "sasanam-background-scan-report/v1", r["schema"]
    assert r["trigger"] == "interval", r["trigger"]
    assert r["scan_performed"] is True
    assert r["verdict"] == "verified", (r["verdict"], r["code"], r["detail"])
    assert r["standing"]["status"] == "current", r["standing"]
    assert r["standing"]["expires_at"] == T0 + 3600, r["standing"]
    _held("P1-register-then-first-scan-verified",
          "first scan verifies; standing current, TTL set")


@probe("P2-signer-rotated-out-flagged-within-interval")
def _p2():
    # No lifecycle transition occurs anywhere in this probe: the scheduler
    # alone must flag the rotated-out signer.
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # Registry rotates the delegation: pay-k1 out, pay-k2 in. The installed
    # skill's authorization is still sealed by pay-k1.
    dw2 = _deleg_wire(2, keyids=("pay-k2",))
    reports = BS.run_scan(sp, _inv(deleg_wire=dw2), ROOT_TRUST, now=T0 + 10)
    r = reports[0]
    assert r["trigger"] == "policy-change", r["trigger"]
    assert r["verdict"] == "refused", r["verdict"]
    # The specific admission-path code, not a generic failure.
    assert r["code"] == "supplychain-delegation-signature-invalid", r["code"]
    _held("P2-signer-rotated-out-flagged-within-interval",
          "rotated-out signer refused coded, no transition needed")


@probe("P3-delegation-dropped-revocation-by-absence")
def _p3():
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # v2 drops the "pay" delegation entirely.
    doc = _deleg_doc(2, [_deleg("other", ["pay-k2"], 1, ["skills/other/*"])])
    dw2 = _seal("delegations", doc, [("r1", _R1)])
    reports = BS.run_scan(sp, _inv(deleg_wire=dw2), ROOT_TRUST, now=T0 + 10)
    r = reports[0]
    assert r["verdict"] == "refused", r["verdict"]
    assert r["code"] == "supplychain-delegation-revoked", r["code"]
    _held("P3-delegation-dropped-revocation-by-absence",
          "absent delegation refused LOUD")


@probe("P4-mutated-bytes-stale-authz-refused")
def _p4():
    # SkillJacking shape: the installed bytes were mutated AFTER install
    # and the authorization statement still pins the ORIGINAL digest.
    # The authority check takes only the skill path -- it never sees the
    # installed bytes -- so the scanner's own content binding is the
    # detector here, not a duplicate.
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    stale = {"skill_path": SKILL, "skill_bytes": BYTES_V2,
             "delegation_wire": _deleg_wire(1),
             "authz_wire": _authz_wire(BYTES_V1)}
    reports = BS.run_scan(sp, [stale], ROOT_TRUST, now=T0 + 10)
    r = reports[0]
    assert r["trigger"] == "resource-change", r["trigger"]
    assert r["verdict"] == "refused", r["verdict"]
    assert r["code"] == "supplychain-scan-content-mismatch", r["code"]
    _held("P4-mutated-bytes-stale-authz-refused",
          "mutated bytes refused: scanner binds content, authority cannot")


@probe("P4b-authorized-content-update-verified-loud")
def _p4b():
    # The honest counterpart: bytes changed AND the authority re-sealed a
    # statement for the new bytes. The scanner re-verifies (renews) but
    # flags the drift LOUD -- the trigger field plus an explicit note.
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    reports = BS.run_scan(sp, _inv(skill_bytes=BYTES_V2), ROOT_TRUST,
                          now=T0 + 10)
    r = reports[0]
    assert r["trigger"] == "resource-change", r["trigger"]
    assert r["verdict"] == "verified", (r["verdict"], r["code"])
    assert r["standing"]["status"] == "current", r["standing"]
    assert r["standing"]["expires_at"] == T0 + 10 + 3600, r["standing"]
    assert any("resource-change" in n and "re-verified" in n
               for n in r["notes"]), r["notes"]
    _held("P4b-authorized-content-update-verified-loud",
          "authorized update renews but is flagged LOUD")


@probe("P5-ttl-expiry-without-renewal-lapses-loud")
def _p5():
    sp = _tmp_state()
    _register(sp, now=T0, ttl=100, interval=1000)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # No trigger fires at T0+101 (next scan due at T0+1000, nothing
    # changed) -- but the TTL expired at T0+100. The lapse must be LOUD.
    reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 101)
    r = reports[0]
    assert r["scan_performed"] is False, r["trigger"]
    assert r["standing"]["status"] == "lapsed", r["standing"]
    assert r["code"] == "supplychain-standing-lapsed", r["code"]
    assert any("lapsed" in n for n in r["notes"]), r["notes"]
    _held("P5-ttl-expiry-without-renewal-lapses-loud",
          "unrenewed standing lapses LOUD at TTL expiry")


@probe("P6-successful-reverification-renews")
def _p6():
    sp = _tmp_state()
    _register(sp, now=T0, ttl=100, interval=1000)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # A policy bump (same signer) at T0+50 re-verifies and renews.
    dw2 = _deleg_wire(2)
    reports = BS.run_scan(sp, _inv(deleg_wire=dw2), ROOT_TRUST, now=T0 + 50)
    r = reports[0]
    assert r["verdict"] == "verified", (r["verdict"], r["code"])
    assert r["standing"]["status"] == "current", r["standing"]
    assert r["standing"]["expires_at"] == T0 + 50 + 100, r["standing"]
    _held("P6-successful-reverification-renews",
          "renewal only on success; expiry extended")


@probe("P7-scan-never-enforces")
def _p7():
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # SkillJacking shape (mutated bytes, stale authorization): refused.
    inv = [{"skill_path": SKILL, "skill_bytes": BYTES_V2,
            "delegation_wire": _deleg_wire(1),
            "authz_wire": _authz_wire(BYTES_V1)}]
    before = (inv[0]["skill_bytes"], inv[0]["delegation_wire"],
              inv[0]["authz_wire"])
    reports = BS.run_scan(sp, inv, ROOT_TRUST, now=T0 + 10)
    r = reports[0]
    assert r["verdict"] == "refused"
    assert r["code"] == "supplychain-scan-content-mismatch", r["code"]
    # No enforcement entry point exists in the module.
    for name in ("quarantine", "disable", "uninstall", "enforce",
                 "remove_skill", "revoke", "block"):
        assert not hasattr(BS, name), name
    # The scan did not mutate its inputs and did not force-lapse the
    # standing: it reported; the actuator decides.
    assert (inv[0]["skill_bytes"], inv[0]["delegation_wire"],
            inv[0]["authz_wire"]) == before
    assert r["standing"]["status"] == "current", r["standing"]
    assert r["standing"]["last_verdict"] == "refused", r["standing"]
    _held("P7-scan-never-enforces",
          "refused scan reports only; no enforcement surface")


@probe("P8-crash-mid-scan-recovered-loud")
def _p8():
    sp = _tmp_state()
    _register(sp, now=T0)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # Simulate a crash: the previous run died after marking in-progress.
    with open(sp + ".inprogress", "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"skill": SKILL, "started_at": T0 + 5}))
    reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 10)
    r = reports[0]
    assert any("supplychain-scan-crash-recovered" in n for n in r["notes"]), \
        r["notes"]
    assert not os.path.exists(sp + ".inprogress"), "sidecar cleared"
    _held("P8-crash-mid-scan-recovered-loud",
          "crash recovery LOUD; sidecar cleared after re-scan")


@probe("P9-missed-intervals-caught-up-loud")
def _p9():
    sp = _tmp_state()
    _register(sp, now=T0, ttl=100000, interval=100)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    # The scheduler was down for 3+ intervals.
    reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 310)
    r = reports[0]
    assert r["scan_performed"] is True, r["trigger"]
    assert r["missed_intervals"] == [T0 + 100, T0 + 200], \
        r["missed_intervals"]
    assert r["code"] == "supplychain-scan-missed-interval", r["code"]
    assert any("missed" in n for n in r["notes"]), r["notes"]
    # Rescheduled from now, not from the missed times (no catch-up storm).
    with open(sp, encoding="utf-8") as _fh:
        state = json.load(_fh)
    assert state["skills"][SKILL]["next_scan_at"] == T0 + 310 + 100
    _held("P9-missed-intervals-caught-up-loud",
          "missed intervals LOUD; single catch-up scan")


@probe("P10-corrupt-state-fails-loud")
def _p10():
    sp = _tmp_state()
    with open(sp, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    _expect_code("P10-corrupt-state-fails-loud",
                 lambda: BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0),
                 "supplychain-scan-state-corrupt")


@probe("P11-missing-state-fails-loud")
def _p11():
    sp = os.path.join(tempfile.mkdtemp(prefix="sched-"), "nope.json")
    _expect_code("P11-missing-state-fails-loud",
                 lambda: BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0),
                 "supplychain-scan-state-missing")


@probe("P12-unregistered-skill-fails-loud")
def _p12():
    sp = _tmp_state()
    _register(sp, now=T0)
    inv = [{"skill_path": "skills/other/y", "skill_bytes": BYTES_V1,
            "delegation_wire": _deleg_wire(1),
            "authz_wire": _authz_wire(BYTES_V1)}]
    _expect_code("P12-unregistered-skill-fails-loud",
                 lambda: BS.run_scan(sp, inv, ROOT_TRUST, now=T0),
                 "supplychain-scan-malformed")


@probe("P13-report-schema-seam-documented")
def _p13():
    sp = _tmp_state()
    _register(sp, now=T0)
    r = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]
    assert r["schema"] == "sasanam-background-scan-report/v1"
    expect_top = {"schema", "skill", "scanned_at", "trigger",
                  "scan_performed", "verdict", "code", "detail", "checked",
                  "missed_intervals", "notes", "standing"}
    assert expect_top <= set(r), set(r)
    expect_standing = {"status", "last_verdict", "expires_at",
                       "ttl_seconds"}
    assert expect_standing <= set(r["standing"]), set(r["standing"])
    # The lane-2 store is a merge-time composition: this module must not
    # import it (parallel-lane isolation).
    assert "standing_verdict" not in sys.modules, \
        [m for m in sys.modules if "standing" in m]
    _held("P13-report-schema-seam-documented",
          "report matches the documented store schema; no lane-2 import")


@probe("P14-refused-scan-does-not-renew")
def _p14():
    # A refused scan must not extend the standing: expiry still lapses.
    sp = _tmp_state()
    _register(sp, now=T0, ttl=100, interval=1000)
    assert BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]["verdict"] \
        == "verified"
    dw2 = _deleg_wire(2, keyids=("pay-k2",))
    r = BS.run_scan(sp, _inv(deleg_wire=dw2), ROOT_TRUST, now=T0 + 10)[0]
    assert r["verdict"] == "refused"
    assert r["standing"]["expires_at"] == T0 + 100, r["standing"]
    r2 = BS.run_scan(sp, _inv(deleg_wire=dw2), ROOT_TRUST, now=T0 + 101)[0]
    assert r2["standing"]["status"] == "lapsed", r2["standing"]
    _held("P14-refused-scan-does-not-renew",
          "refusal never renews; lapse follows at TTL")


# ---------------------------------------------------------------------------
# Pin + footer state probes.
# ---------------------------------------------------------------------------

@probe("P15-pin-taxonomy-2027-sorted")
def _p15():
    from gov import decision_codes as DC
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = __import__("re").findall(
        r'\"code\":\s*[\"\']([^\"\']+)[\"\']', src)
    # Uniqueness on raw source literals (the wave-260 lesson: the
    # deduped dict cannot see duplicate literals).
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN == 2027, (
        len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    for code in ("supplychain-scan-malformed",
                 "supplychain-scan-state-corrupt",
                 "supplychain-scan-state-missing",
                 "supplychain-scan-crash-recovered",
                 "supplychain-scan-missed-interval",
                 "supplychain-scan-content-mismatch",
                 "supplychain-standing-lapsed"):
        assert code in DC.TAXONOMY, "new code %r not registered" % code
        entry = DC.TAXONOMY[code]
        assert entry["domain"] == "supplychain", entry
    _held("P15-pin-taxonomy-2027-sorted", "2027/2027/0 sorted; new codes ok")


@probe("P16-footer-open-F409-next-F410")
def _p16():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    src = open(path, encoding="utf-8").read()
    assert "Next free finding: **F410**" in src, "next-free footer"
    assert "**Open findings: F409.**" in src, "open-F409 footer"
    _held("P16-footer-open-F409-next-F410",
          "footer: open F409 / next F410 (F409 filed by wave-325 lane 4)")


# ---------------------------------------------------------------------------
# Green checks (depth-1: children run with GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

_GREEN_CHILDREN = [
    "evals/w267_suppchain_probes.py",
]
_KNOWN_CHILD_BREAKS = set()


def _green():
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skip", "HELD", "green checks skipped (child mode)")
        return
    for child in _GREEN_CHILDREN:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO, child)],
                capture_output=True, text=True, timeout=900, env=env,
                cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            _record("green-" + child, "ERROR", "%s" % (exc,))
            continue
        out = proc.stdout + proc.stderr
        bad = [ln for ln in out.splitlines()
               if ln.startswith("[BREAK]")]
        ok = True
        for ln in bad:
            pid = ln.split("]")[1].split(":")[0].strip()
            if pid not in _KNOWN_CHILD_BREAKS:
                ok = False
        if "[ERROR]" in out or proc.returncode != 0:
            ok = False
        _record("green-" + child, "HELD" if ok else "BREAK",
                "child %s ran; unexpected breaks/errors fail this check"
                % child)


def main(argv):
    probes = [v for k, v in sorted(globals().items())
              if k.startswith("_p") and k[2:3].isdigit() and callable(v)]
    for fn in probes:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w326_sched battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if green_ok:
        print("GREEN")
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
