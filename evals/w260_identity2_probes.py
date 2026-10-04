"""Break-first probes for the wave-260 identity-mesh follow-up lane.

Wave-260 lane 3 (identity-mesh follow-up): (1) wire SvidVerifier as an
optional peer-identity source for the mesh admission seam alongside
the kernel-attested path -- both fail-closed, NO downgrade between
them; (2) a pre-auth-key enrollment ceremony (headscale shape) in
front of TestSvidIssuer.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Pre-fix (modules absent) every probe reports GAP. Post-fix
each probe must report HELD: the attack is refused with a machine
code -- a bad SVID never falls through to the weaker (kernel) path,
a missing SVID on an SVID-required route is refused, not re-routed.

Targets (new in wave-260):
  gov/mesh_admission.py -- MeshAdmission: route table
    (route -> require: svid | kernel | either) composing
    gov/attested_channel.ChannelAdmission with
    gov/svid_issuer.MeshControl (verify-first, default-deny ACL).
  gov/svid_enrollment.py -- EnrollmentAuthority: one-time,
    expiring, single-use enrollment keys gating first issuance from
    the TEST issuer; burn-on-redeem; used/expired/unknown keys refuse
    with machine codes.

Verdicts: HELD (attack refused with the expected machine code, or
the happy path admitted on the correct seam), BREAK (genuine defect
-> file as F230+), GAP (capability absent, pre-fix), BASELINE
(known-open finding reproduced, not new).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

try:
    from gov import mesh_admission as ma
    from gov import svid_enrollment as se
    from gov import svid_issuer as sv
    from gov import attested_channel as ac
    from gov import ed25519 as ed
    from gov import decision_codes  # noqa: E402
except ImportError:
    ma = se = sv = ac = ed = decision_codes = None

TAXONOMY_PIN = 1951 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _gap(detail=""):
    return ("GAP", detail)


def _break(detail=""):
    return ("BREAK", detail)


_SEED = bytes(range(32))
_OTHER_SEED = bytes([255 - b for b in range(32)])
_PUBKEY = "ab" * 32
_TD = "example.org"
_NOW = 1700000000.0


def _issuer(seed=_SEED, key_id="test-issuer-1"):
    return sv.TestSvidIssuer(issuer_seed=seed, key_id=key_id)


def _verifier(seed=_SEED, key_id="test-issuer-1"):
    return sv.SvidVerifier({key_id: ed.publickey(seed)},
                           trust_domain=_TD)


def _mesh(routes):
    control = sv.MeshControl(
        _verifier(), {"allow": ["spiffe://example.org/agent"]})
    return ma.MeshAdmission(routes, mesh_control=control)


def _svid(issuer=None, spiffe_id="spiffe://example.org/agent/a"):
    iss = issuer or _issuer()
    return iss.issue(spiffe_id, _PUBKEY, ttl_minutes=5, now=_NOW)


def _bad_svid():
    """A forged SVID: valid shape, signature from an untrusted key."""
    rogue = _issuer(seed=_OTHER_SEED, key_id="test-issuer-1")
    return _svid(issuer=rogue)


def _kernel():
    return {
        "peer_identity": {"uid": 1000, "gid": 1000, "pid": 4242,
                          "exe": "/usr/bin/agent"},
        "emitter_claim": {"principal": "agent-1", "ts_emit": _NOW,
                          "seq": 0, "payload": {"op": "ping"}},
        "key_location": "daemon",
    }


def _expect_code(fn, code, errtypes):
    """HELD iff fn raises one of errtypes carrying the exact code."""
    try:
        fn()
    except errtypes as e:
        if e.code == code:
            return _held("refused %s" % code)
        return _break("wrong code %r, expected %r" % (e.code, code))
    except Exception as e:  # noqa: BLE001
        return _break("unexpected %s: %s" % (type(e).__name__, e))
    return _break("attack accepted: no refusal raised")


def _codes():
    return (sv.SvidError, ac.AttestedChannelError)


# ---------------------------------------------------------------------------
# Part 1: mesh admission -- no downgrade between SVID and kernel paths
# ---------------------------------------------------------------------------

@probe("capability-mesh-admission")
def p_capability_mesh():
    if ma is None:
        return _gap("gov/mesh_admission.py absent: no dual-seam admission")
    return _held("module importable")


@probe("svid-route-kernel-only-downgrade")
def p_svid_route_kernel_only():
    """SVID-required route: valid kernel credentials but NO SVID must
    be refused (svid-missing), never re-routed to the kernel path."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"ctl": {"require": "svid"}})
    return _expect_code(
        lambda: adm.admit("ctl", svid=None, kernel=_kernel(), now=_NOW),
        "svid-missing", _codes())


@probe("svid-route-bad-svid-no-fallthrough")
def p_bad_svid_no_fallthrough():
    """SVID-required route: a FORGED SVID plus VALID kernel creds must
    refuse with the SVID code -- never fall through to the kernel path."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"ctl": {"require": "svid"}})
    return _expect_code(
        lambda: adm.admit("ctl", svid=_bad_svid(), kernel=_kernel(),
                          now=_NOW),
        "svid-signature-invalid", _codes())


@probe("kernel-route-svid-only-refused")
def p_kernel_route_svid_only():
    """Kernel-required route: a VALID SVID but no attested peer must be
    refused (channel-identity-unattested) -- the SVID never admits."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"data": {"require": "kernel"}})
    return _expect_code(
        lambda: adm.admit("data", svid=_svid(), kernel=None, now=_NOW),
        "channel-identity-unattested", _codes())


@probe("kernel-route-svid-ignored")
def p_kernel_route_svid_ignored():
    """Kernel-required route: valid SVID + valid kernel creds admits
    on the KERNEL seam -- the SVID is ignored, not consulted."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"data": {"require": "kernel"}})
    try:
        rec = adm.admit("data", svid=_bad_svid(), kernel=_kernel(),
                        now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("kernel admission failed: %s: %s"
                      % (type(e).__name__, e))
    # A forged SVID riding along must not influence the kernel path:
    # the admission is kernel-mode and the SVID was never evaluated.
    if rec.get("mode") != "kernel":
        return _break("admitted on wrong seam: %r" % (rec.get("mode"),))
    return _held("admitted via kernel seam, SVID ignored")


@probe("either-route-bad-svid-no-fallthrough")
def p_either_bad_svid():
    """Either-route: bad SVID + valid kernel creds refuses with the
    SVID code -- the kernel path is not a fallback."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"mgmt": {"require": "either"}})
    return _expect_code(
        lambda: adm.admit("mgmt", svid=_bad_svid(), kernel=_kernel(),
                          now=_NOW),
        "svid-signature-invalid", _codes())


@probe("either-route-kernel-only-admits")
def p_either_kernel_only():
    """Either-route: kernel creds alone (no SVID offered) admit on the
    kernel seam -- no SVID was presented, so no downgrade occurred."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"mgmt": {"require": "either"}})
    try:
        rec = adm.admit("mgmt", svid=None, kernel=_kernel(), now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("kernel admission failed: %s: %s"
                      % (type(e).__name__, e))
    if rec.get("mode") != "kernel":
        return _break("admitted on wrong seam: %r" % (rec.get("mode"),))
    return _held("admitted via kernel seam")


@probe("either-route-valid-svid-admits")
def p_either_valid_svid():
    """Either-route: a valid ACL-allowed SVID admits on the SVID seam."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"mgmt": {"require": "either"}})
    try:
        rec = adm.admit("mgmt", svid=_svid(), kernel=None, now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("SVID admission failed: %s: %s"
                      % (type(e).__name__, e))
    if rec.get("mode") != "svid":
        return _break("admitted on wrong seam: %r" % (rec.get("mode"),))
    return _held("admitted via SVID seam: %s" % rec.get("spiffe_id"))


@probe("unknown-route-default-deny")
def p_unknown_route():
    """Undeclared route: default-deny admission refuses."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"ctl": {"require": "svid"}})
    return _expect_code(
        lambda: adm.admit("nope", svid=_svid(), kernel=None, now=_NOW),
        "svid-acl-denied", _codes())


@probe("svid-route-acl-still-denies")
def p_svid_route_acl_denied():
    """SVID-required route: a VALID SVID outside the ACL is still
    denied -- verify-first, then default-deny."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"ctl": {"require": "svid"}})
    other = _svid(spiffe_id="spiffe://example.org/other/x")
    return _expect_code(
        lambda: adm.admit("ctl", svid=other, kernel=None, now=_NOW),
        "svid-acl-denied", _codes())


@probe("svid-route-happy-path")
def p_svid_route_happy():
    """SVID-required route: valid ACL-allowed SVID admits."""
    if ma is None:
        return _gap("no mesh admission")
    adm = _mesh({"ctl": {"require": "svid"}})
    try:
        rec = adm.admit("ctl", svid=_svid(), kernel=None, now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("SVID admission failed: %s: %s"
                      % (type(e).__name__, e))
    if rec.get("mode") != "svid":
        return _break("admitted on wrong seam: %r" % (rec.get("mode"),))
    return _held("admitted via SVID seam: %s" % rec.get("spiffe_id"))


# ---------------------------------------------------------------------------
# Part 2: pre-auth-key enrollment ceremony
# ---------------------------------------------------------------------------

@probe("capability-enrollment")
def p_capability_enrollment():
    if se is None:
        return _gap("gov/svid_enrollment.py absent: no enrollment ceremony")
    return _held("module importable")


def _authority(**kw):
    kw.setdefault("issuer", _issuer())
    return se.EnrollmentAuthority(**kw)


@probe("enrollment-happy-path")
def p_enrollment_happy():
    """Issue key out-of-band -> redeem -> first SVID verifies under
    the pinned verifier and admits through mesh control."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority()
    key = auth.issue_key(now=_NOW)
    try:
        svid_doc = auth.redeem(key, "spiffe://example.org/agent/a",
                               _PUBKEY, ttl_minutes=5, now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("redemption failed: %s: %s"
                      % (type(e).__name__, e))
    try:
        claims = _verifier().verify(svid_doc, now=_NOW)
    except Exception as e:  # noqa: BLE001
        return _break("enrolled SVID does not verify: %s: %s"
                      % (type(e).__name__, e))
    if claims["spiffe_id"] != "spiffe://example.org/agent/a":
        return _break("wrong spiffe_id %r" % claims["spiffe_id"])
    return _held("enrolled SVID verifies")


@probe("enrollment-key-replay")
def p_enrollment_replay():
    """Second redemption of the same key refuses (burned on use)."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority()
    key = auth.issue_key(now=_NOW)
    auth.redeem(key, "spiffe://example.org/agent/a", _PUBKEY,
                ttl_minutes=5, now=_NOW)

    def replay():
        auth.redeem(key, "spiffe://example.org/agent/a", _PUBKEY,
                    ttl_minutes=5, now=_NOW + 1)
    return _expect_code(replay, "svid-enrollment-key-replayed",
                        (sv.SvidError,))


@probe("enrollment-key-unknown")
def p_enrollment_unknown():
    """A key that was never issued refuses."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority()

    def redeem_unknown():
        auth.redeem("never-issued-key", "spiffe://example.org/agent/a",
                    _PUBKEY, ttl_minutes=5, now=_NOW)
    return _expect_code(redeem_unknown, "svid-enrollment-key-unknown",
                        (sv.SvidError,))


@probe("enrollment-key-expired")
def p_enrollment_expired():
    """A key redeemed past its expiry refuses."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority(default_key_ttl_seconds=60)
    key = auth.issue_key(now=_NOW)

    def redeem_late():
        auth.redeem(key, "spiffe://example.org/agent/a", _PUBKEY,
                    ttl_minutes=5, now=_NOW + 61)
    return _expect_code(redeem_late, "svid-enrollment-key-expired",
                        (sv.SvidError,))


@probe("enrollment-binding-mismatch")
def p_enrollment_binding():
    """A key bound to one spiffe id cannot enroll a different one."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority()
    key = auth.issue_key(spiffe_id="spiffe://example.org/agent/a",
                         now=_NOW)

    def redeem_other():
        auth.redeem(key, "spiffe://example.org/agent/EVIL", _PUBKEY,
                    ttl_minutes=5, now=_NOW)
    return _expect_code(redeem_other, "svid-enrollment-spiffe-mismatch",
                        (sv.SvidError,))


@probe("enrollment-burn-before-issue")
def p_enrollment_burn_first():
    """The key burns BEFORE issuance: a redemption whose issuance
    fails (bad workload key) still retires the key -- a second
    redemption refuses as replayed, not as a fresh issuance."""
    if se is None:
        return _gap("no enrollment ceremony")
    auth = _authority()
    key = auth.issue_key(now=_NOW)
    try:
        auth.redeem(key, "spiffe://example.org/agent/a", "not-a-key",
                    ttl_minutes=5, now=_NOW)
    except sv.SvidError as e:
        if e.code != "svid-identity-malformed":
            return _break("wrong issuance code %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _break("unexpected %s: %s" % (type(e).__name__, e))
    else:
        return _break("bad workload key was issued an SVID")

    def redeem_again():
        auth.redeem(key, "spiffe://example.org/agent/a", _PUBKEY,
                    ttl_minutes=5, now=_NOW + 1)
    return _expect_code(redeem_again, "svid-enrollment-key-replayed",
                        (sv.SvidError,))


def _green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN; never spawns another
    battery's full main; no in-repo git subprocesses."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    if ma is None or se is None:
        return [("unit tests", "SKIPPED (modules absent)")]
    import subprocess
    results = []
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for mod in ("tests.test_mesh_admission", "tests.test_svid_enrollment"):
        tmp = tempfile.mkdtemp(prefix="w260g-", dir="/var/tmp")
        r = subprocess.run(
            [sys.executable, "-m", mod], cwd=root,
            env=dict(env, TMPDIR=tmp),
            capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout or "")[-200:].replace("\n", " ")
        results.append((mod, "rc=%d %s" % (r.returncode, tail)))
    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# BASELINE is defined by these batteries as "known-open finding reproduced"
# (dead in practice: no probe returns it) and maps to BREAK as well. Raw rows
# keep the battery's own vocabulary (count code and exit contract untouched);
# the mapping happens here, at emission. Anything else fails closed as ERROR.
def _mapped(rows):
    out = []
    for _name, _verdict, _detail in rows:
        if _verdict in ("GAP", "BASELINE"):
            out.append((_name, "BREAK", "%s: %s" % (_verdict, _detail)))
        elif _verdict in ("HELD", "BREAK", "ERROR"):
            out.append((_name, _verdict, _detail))
        else:
            out.append((_name, "ERROR",
                        "unexpected verdict %r: %s" % (_verdict, _detail)))
    return out

def main():
    held = breaks = gaps = baselines = errors = 0
    rows = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" % (type(e).__name__,
                                                    str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "GAP":
            gaps += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        rows.append((name, verdict, detail))
    mapped = _mapped(rows)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, breaks + gaps + baselines, held, errors)
    probe_lines.emit(mapped)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("-" * 79)
    pin_ok = True
    if decision_codes is None:
        print("taxonomy pin: module absent (pre-fix)")
        pin_ok = False
    elif len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        pin_ok = False
    else:
        print("taxonomy pin OK: %d" % TAXONOMY_PIN)
    for name, note in _green_check():
        print("green-check %-24s %s" % (name, note))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks + gaps + baselines, held, errors))
    if gaps and not breaks and not errors:
        print("RED BASELINE: capability absent, all probes GAP")
        return 0
    return 1 if (breaks or errors or not pin_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
