#!/usr/bin/env python3
"""Break-first probes for wave-191: agent-identity token claim-set
integration at the decision-packet seam (dexidp/dex ADAPT follow-through).

The decision packet can carry an OPTIONAL identity_token section -- the
digest-bound record of the OIDC claim set the identity was minted from
({token_digest, iss, aud, exp, jti}, never the raw bearer token).
verify_decision_packet takes an optional token_claims dict (the VERIFIED
claim set); None is the legacy path with byte-identical acceptance.

RED-PHASE (--red-phase): the wave-190 gap demonstration -- identity
minted from an EXPIRED token verifies identically to a valid one and to
no token at all, because the seam has no token awareness. Expect all
three ACCEPTED; exit 0 = gap shown. (Runs on the legacy API only, so it
demonstrates the baseline on any tree.)

GREEN-PHASE (default): the closure battery. T1 (expired) must be
REFUSED, T2 (valid) and T3 (legacy, no token) must be ACCEPTED, and the
validation rules (wrong iss/aud, missing exp, jti mismatch, BOM digest
mismatch, forged claim sets, skew boundary, malformed builder input)
must all fail closed.

Usage:
  python3 evals/token_claims_probes.py --red-phase   # gap demo
  python3 evals/token_claims_probes.py               # closure battery

Deterministic: expiries are anchored far from now (+/- days) except the
skew-boundary probe, which uses +/-30s/+90s margins around the 60s
allowance -- comfortably outside timing jitter. main() runs the battery
twice and requires identical statuses.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check is
depth-1 (tests/test_decision_packet only, child env GOV_SKIP_GREEN=1);
the battery never touches the shared tree -- TREE is the tree it lives in.
"""

import copy
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREE = REPO_ROOT  # this battery lives in the tree it tests
sys.path.insert(0, TREE)

SEED = bytes.fromhex("11" * 32)
ISSUER = "https://dex.sasanam.internal"
DAY = 86400


def _dp():
    from gov import decision_packet as dp
    return dp


def _bom_mod():
    from gov import decision_bom as bom_mod
    return bom_mod


def _claims(exp_offset, **over):
    now = int(time.time())
    c = {
        "iss": ISSUER,
        "sub": "agent:org1:run-7",
        "aud": "sasanam-policy-engine",
        "iat": now - 3600,
        "exp": now + exp_offset,
        "jti": "token-jti-001",
        "principal": "org1",
        "role": "operator",
        "agent_scope": "tools:read",
    }
    c.update(over)
    return c


def _section(exp_offset, **over):
    s = {
        "token_digest": "ab" * 32,
        "iss": ISSUER,
        "aud": "sasanam-policy-engine",
        "exp": int(time.time()) + exp_offset,
        "jti": "token-jti-001",
    }
    s.update(over)
    return s


def _identity():
    return {"agent_id": "agent:org1:run-7", "role": "operator",
            "principal": "org1", "run_id": "run-7"}


def _bom(dp, bom_mod, **over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32, evidence_head_digest="GENESIS",
              principal=dict(_identity()))
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _packet(dp, bom_mod, exp_offset, with_section=True,
            section_over=None, bom_over=None):
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              identity=_identity(),
              issued_at="2026-09-28T00:00:00+00:00",
              bill_of_materials=_bom(dp, bom_mod, **(bom_over or {})))
    if with_section:
        kw["identity_token"] = _section(exp_offset,
                                       **(section_over or {}))
    return dp.sign_packet(dp.build_decision_packet(**kw), SEED)


def _expect_refused(ok, reason, why):
    assert not ok, "expected REFUSAL (%s) but got accept: %r" % (why, reason)
    return "PASS", "refused: %s" % (reason[:90],)


def _expect_accepted(ok, reason, why):
    assert ok, "expected ACCEPT (%s) but got refusal: %r" % (why, reason)
    return "PASS", "accepted: %s" % (reason[:90],)


# --------------------------------------------------------------------------
# Red-phase: the wave-190 gap demonstration (legacy API only).
# --------------------------------------------------------------------------

def red_expired_accepted():
    """Identity minted from an EXPIRED token verifies (gap)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, -3650 * DAY, with_section=False)
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    assert ok, "red-phase expects the gap (accept), got: %r" % (reason,)
    return "PASS", "gap: expired-token identity accepted"


def red_valid_accepted():
    """Identity minted from a valid token verifies (control)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 3650 * DAY, with_section=False)
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    assert ok, "red-phase expects accept, got: %r" % (reason,)
    return "PASS", "control: valid-token identity accepted"


def red_no_token_accepted():
    """No token at all verifies identically (negative control)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 3650 * DAY, with_section=False)
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    assert ok, "red-phase expects accept, got: %r" % (reason,)
    return "PASS", "control: no-token identity accepted"


RED_PROBES = [
    ("red_expired_accepted", red_expired_accepted),
    ("red_valid_accepted", red_valid_accepted),
    ("red_no_token_accepted", red_no_token_accepted),
]


# --------------------------------------------------------------------------
# Green-phase: the closure battery.
# --------------------------------------------------------------------------

def probe_expired_token_refused():
    """T1: expired token_claims are REFUSED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, -3650 * DAY)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet), token_claims=_claims(-3650 * DAY))
    return _expect_refused(ok, reason, "expired token")


def probe_valid_token_accepted():
    """T2: valid token_claims consistent with the packet are ACCEPTED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet), token_claims=_claims(900))
    return _expect_accepted(ok, reason, "valid token")


def probe_legacy_packet_untouched():
    """T3: legacy packet (no section), no claims -> ACCEPTED, and the
    packet carries no identity_token section (byte-identical shape)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900, with_section=False)
    assert "identity_token" not in packet, \
        "legacy packet must not grow an identity_token section"
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    return _expect_accepted(ok, reason, "legacy packet")


def probe_section_without_claims_accepted():
    """Packet WITH a section but token_claims=None verifies as before
    (the check only runs on presented claims)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    return _expect_accepted(ok, reason, "section present, no claims")


def probe_claims_without_section_refused():
    """token_claims presented against a packet with NO section are
    REFUSED (nothing signature-bound to check them against)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900, with_section=False)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet), token_claims=_claims(900))
    return _expect_refused(ok, reason, "claims without section")


def probe_wrong_iss_refused():
    """Claims from a foreign issuer are REFUSED (iss pinning)."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet),
        token_claims=_claims(900, iss="https://evil.example"))
    return _expect_refused(ok, reason, "foreign iss")


def probe_wrong_aud_refused():
    """Claims minted for another audience are REFUSED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet),
        token_claims=_claims(900, aud="some-other-service"))
    return _expect_refused(ok, reason, "wrong aud")


def probe_exp_missing_refused():
    """A claim set without exp is REFUSED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    c = _claims(900)
    del c["exp"]
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet),
                                           token_claims=c)
    return _expect_refused(ok, reason, "missing exp")


def probe_jti_mismatch_refused():
    """Claims whose jti differs from the signed section are REFUSED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet), token_claims=_claims(900, jti="other-jti"))
    return _expect_refused(ok, reason, "jti mismatch")


def probe_sub_mismatch_refused():
    """Claims whose sub disagrees with the packet identity are REFUSED."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet),
        token_claims=_claims(900, sub="agent:org1:run-9"))
    return _expect_refused(ok, reason, "sub/identity mismatch")


def probe_forged_claims_refused():
    """A well-formed claim set from a DIFFERENT token (never signed
    into this packet) is REFUSED -- the 'wrong signature over the
    claim set' case: only the claims the packet key signed can pass."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, 900)  # section binds jti-001/ISSUER
    forged = _claims(900, iss="https://dex.other.example",
                     jti="token-jti-999", sub="agent:orgX:run-1",
                     principal="orgX")
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet),
                                           token_claims=forged)
    return _expect_refused(ok, reason, "forged claim set")


def probe_bom_digest_mismatch_refused():
    """BOM token_digest disagreeing with the packet section is REFUSED
    even with NO claims presented (unconditional cross-check)."""
    dp, bom_mod = _dp(), _bom_mod()
    principal = dict(_identity())
    principal["token_digest"] = "cd" * 32  # section records ab*32
    packet = _packet(dp, bom_mod, 900, bom_over={"principal": principal})
    ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
    return _expect_refused(ok, reason, "BOM/section digest mismatch")


def probe_bom_digest_agreement_accepted():
    """BOM token_digest agreeing with the section verifies."""
    dp, bom_mod = _dp(), _bom_mod()
    principal = dict(_identity())
    principal["token_digest"] = "ab" * 32
    packet = _packet(dp, bom_mod, 900, bom_over={"principal": principal})
    ok, reason = dp.verify_decision_packet(
        copy.deepcopy(packet), token_claims=_claims(900))
    return _expect_accepted(ok, reason, "BOM/section digest agreement")


def probe_skew_boundary():
    """exp 30s in the past (inside the 60s skew window) is accepted;
    exp 90s in the past is refused."""
    dp, bom_mod = _dp(), _bom_mod()
    packet = _packet(dp, bom_mod, -30)
    ok, _ = dp.verify_decision_packet(copy.deepcopy(packet),
                                      token_claims=_claims(-30))
    assert ok, "exp 30s past should be inside the skew window"
    packet2 = _packet(dp, bom_mod, -90)
    ok2, reason2 = dp.verify_decision_packet(
        copy.deepcopy(packet2), token_claims=_claims(-90))
    assert not ok2, "exp 90s past should be refused: %r" % (reason2,)
    return "PASS", "skew window honored (30s in, 90s out)"


def probe_builder_rejects_malformed_section():
    """build_decision_packet raises PacketError on malformed
    identity_token input (loud, fail-closed for builders)."""
    dp, bom_mod = _dp(), _bom_mod()
    bad_sections = [
        {"token_digest": "ab" * 32, "iss": ISSUER,
         "aud": "sasanam-policy-engine", "exp": 1},  # missing jti
        {"token_digest": "zz", "iss": ISSUER,
         "aud": "sasanam-policy-engine", "exp": 1,
         "jti": "x"},  # bad digest
        dict(_section(900), extra="nope"),  # unknown field
        "not-a-dict",
    ]
    for bad in bad_sections:
        try:
            kw = dict(decision="allow", boundary_declared=False,
                      authority_proof=None, evidence_head_digest="GENESIS",
                      policy_id="default", policy_version="unversioned",
                      identity=_identity(),
                      issued_at="2026-09-28T00:00:00+00:00",
                      bill_of_materials=_bom(dp, bom_mod),
                      identity_token=bad)
            dp.build_decision_packet(**kw)
        except dp.PacketError:
            continue
        raise AssertionError(
            "malformed identity_token accepted: %r" % (bad,))
    return "PASS", "builder loud on 4 malformed sections"


def probe_legacy_bom_unchanged():
    """build_bom without token_digest records no such key (legacy
    BOMs are byte-identical); with it, the digest is recorded."""
    dp, bom_mod = _dp(), _bom_mod()
    legacy = _bom(dp, bom_mod)
    assert "token_digest" not in legacy["inputs"]["principal"], \
        "legacy BOM must not grow a token_digest key"
    principal = dict(_identity())
    principal["token_digest"] = "ab" * 32
    with_digest = _bom(dp, bom_mod, principal=principal)
    assert with_digest["inputs"]["principal"]["token_digest"] == "ab" * 32
    ok, reason = bom_mod.check_bom_shape(with_digest)
    assert ok, reason
    return "PASS", "BOM token_digest optional and shape-checked"


PROBES = [
    ("expired_token_refused", probe_expired_token_refused),
    ("valid_token_accepted", probe_valid_token_accepted),
    ("legacy_packet_untouched", probe_legacy_packet_untouched),
    ("section_without_claims_accepted",
     probe_section_without_claims_accepted),
    ("claims_without_section_refused", probe_claims_without_section_refused),
    ("wrong_iss_refused", probe_wrong_iss_refused),
    ("wrong_aud_refused", probe_wrong_aud_refused),
    ("exp_missing_refused", probe_exp_missing_refused),
    ("jti_mismatch_refused", probe_jti_mismatch_refused),
    ("sub_mismatch_refused", probe_sub_mismatch_refused),
    ("forged_claims_refused", probe_forged_claims_refused),
    ("bom_digest_mismatch_refused", probe_bom_digest_mismatch_refused),
    ("bom_digest_agreement_accepted", probe_bom_digest_agreement_accepted),
    ("skew_boundary", probe_skew_boundary),
    ("builder_rejects_malformed_section",
     probe_builder_rejects_malformed_section),
    ("legacy_bom_unchanged", probe_legacy_bom_unchanged),
]


def _run_once(probes):
    results = []
    for name, fn in probes:
        try:
            status, detail = fn()
        except AssertionError as e:
            status, detail = "FAIL", "assertion: %s" % (e,)
        except Exception as e:  # noqa: BLE001 - probes must not crash
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    return results


def _green_check():
    """Depth-1: adjacent unit module only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="token-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_decision_packet", "-v"],
            capture_output=True, text=True, timeout=600, cwd=TREE,
            env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (tests/test_decision_packet):\n%s" % tail)
        return p.returncode == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    probes = RED_PROBES if red_phase else PROBES
    first = _run_once(probes)
    second = _run_once(probes)
    det_ok = ([(n, s) for n, s, _ in first]
              == [(n, s) for n, s, _ in second])
    width = max(len(n) for n, _, _ in first)
    print("== token_claims probes (%s) =="
          % ("RED-PHASE: gap demonstration" if red_phase else
             "GREEN-PHASE: closure battery"))
    for name, status, detail in first:
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if red_phase:
        # Gap demonstration: the legacy seam accepts expired-token
        # identities. Exit 0 = gap shown.
        if all(s == "PASS" for _, s, _ in first) and det_ok:
            print("GAP SHOWN: %d/%d legacy accepts, statuses identical x2"
                  % (len(first), len(first)))
            return 0
        print("RED-PHASE INCONCLUSIVE")
        return 1
    if not _green_check():
        print("GREEN CHECK FAILED")
        return 1
    bad = [(n, d) for n, s, d in first if s != "PASS"]
    if bad or not det_ok:
        print("%d probe(s) failing" % len(bad))
        for n, d in bad:
            print("  FAIL %s: %s" % (n, d))
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
