#!/usr/bin/env python3
"""Wave-345 lane 6 battery: thread verified mint_identity claims into
every per-call decision packet.

Wave-343 lane 4 built deterministic ownership inference but left the
honest boundary open: the executor attached only
``{"declared_principal": identity.principal}`` -- the weakest tier --
to per-call packets. This lane threads the VERIFIED claim set recorded
at ``mint_identity`` time into every per-call packet: the packet
carries the identity claim (PII as digests), its verification status,
and the owner attribution derived from the full claim set
(verified-email-binding > directory-subject-binding >
directory-principal-known).

$0 SPEND BY CONSTRUCTION: canned claim sets and locally issued test
tokens only, no model calls. Do NOT add ModelDriver/SpendLedger usage
here.

Probes:
  P1  verified-email threading: packet carries identity_claims
      (status token-claims-validated, digested email) and the
      attribution resolves verified-email-binding (base: only
      directory-principal-known).
  P2  subject tier: subject-only claims -> directory-subject-binding.
  P3  unverified email is NOT evidence (fail-closed).
  P4  registry mode, tokenless mint -> principal-registry status.
  P5  dev mode, tokenless mint -> self-asserted status.
  P6  federated mode -> identity-token-verified status (real
      Ed25519-issued test token, pinned verifier).
  P7  stale-claim fail-closed: tokenless re-mint drops verified
      claims (no inheritance).
  P8  PII hygiene: raw email never in the canonical packet bytes.
  P9  tamper: mutated identity_claims refuses at verify; forged
      value refuses at construction.
  P10 legacy: no kwarg -> no section, byte-identical.
  P11 ambiguous claims -> coded ownership-inference-ambiguous on
      the packet.
  P12 pin 2143, footer open F436 / next F437,  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
      codes registered.
  P13 depth-1 green check over w343_ownership_probes.py.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_ownthread_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2143  # Wave-345 lane 6: no new codes; pin unchanged; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


FOOTER_NEXT = "F713"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



from gov import ownership_inference as oi  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import federated_identity as fi  # noqa: E402
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

ISSUER = "https://dex.sasanam.internal"
AUD = "sasanam-policy-engine"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _digest(source, value):
    """Pin the module's digest function, not a re-typed hash: a future
    domain change must update the probe's meaning, not silently
    diverge from it."""
    from gov.ownership_inference import _digest_value
    return _digest_value(source, value)


def _directory():
    return {"principals": {
        "alice": {"emails": ["alice@example.com"],
                  "subjects": ["auth0|alice-1"],
                  "groups": ["eng"]},
        "bob": {"emails": ["bob@example.com"],
                "subjects": ["auth0|bob-9"],
                "groups": ["eng"]},
    }}


def _claims(agent_id, role, principal, **over):
    # Deterministic token timestamps: fixed iat/exp in 2030 (valid
    # for years, no clock in the probes).
    c = {"iss": ISSUER, "sub": agent_id,
         "aud": AUD, "iat": 1893456000,
         "exp": 1893456900, "jti": "w345-jti-" + agent_id,
         "principal": principal, "role": role,
         "agent_scope": "tools:read"}
    c.update(over)
    return c


def _make_exec(owner_directory=None, **kw):
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.log import ActionLog, read_entries
    from gov.approvals import ApprovalQueue
    from tests.keyfixture import scrub_key_env, provision_test_key
    restore = scrub_key_env()
    provision_test_key()
    try:
        run_dir = tempfile.mkdtemp(prefix="g345-own-", dir="/var/tmp")
        policy = PolicyEngine(
            os.path.join(REPO_ROOT, "policies", "default.yaml"))
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ungoverned_ack="w345 battery: raw pipeline "
                          "by design",
                          packet_key_seed="cd" * 32,
                          owner_directory=owner_directory, **kw)
        return ex, run_dir, read_entries, restore
    except Exception:
        restore()
        raise


def _packets_of(run_dir, read_entries, agent_id=None):
    pkts = [e for e in read_entries(os.path.join(run_dir, "actions.jsonl"))
            if e.get("event") == "decision_packet"]
    if agent_id is not None:
        pkts = [p for p in pkts if p.get("agent_id") == agent_id]
    return pkts


def _call_packet(ex, run_dir, read_entries, ident):
    try:
        ex.call(ident, "read_file", path="/etc/shadow-x345")
    except Exception:
        pass  # the decision (not the outcome) is what we audit
    pkts = _packets_of(run_dir, read_entries, ident.agent_id)
    assert pkts, "no decision packet emitted"
    return pkts[-1]["packet"]


def _identity_claims(packet):
    return packet.get("identity_claims", {}).get("value")


def _attribution(packet):
    return packet.get("owner_attribution", {}).get("value")


# --------------------------------- P1: verified-email threading
def p1_verified_email_threading():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=True, groups=["eng"]))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        ic = _identity_claims(packet)
        ok = _check("P1a identity_claims section rides packet",
                    isinstance(ic, dict), repr(ic)) and ok
        if isinstance(ic, dict):
            ok = _check("P1b verification status",
                        ic.get("verification_status")
                        == "token-claims-validated",
                        repr(ic.get("verification_status"))) and ok
            ok = _check("P1c email carried as digest",
                        ic.get("email_digest")
                        == _digest("email", "alice@example.com"),
                        (ic.get("email_digest") or "")[:16]) and ok
            ok = _check("P1d email_verified carried",
                        ic.get("email_verified") is True) and ok
        attr = _attribution(packet)
        ok = _check("P1e owner named", attr.get("owner") == "alice",
                    repr(attr.get("owner"))) and ok
        ok = _check("P1f strongest tier (not declared-only)",
                    attr.get("tier") == "verified-email-binding",
                    repr(attr.get("tier"))) and ok
        ok = _check("P1g declared consistency",
                    attr.get("declared_consistency")
                    == "declared-matches-inferred",
                    repr(attr.get("declared_consistency"))) and ok
    finally:
        restore()
    return ok


# --------------------------------- P2: subject tier
def p2_subject_tier():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|bob-9", "scout", "bob",
            token_claims=_claims("auth0|bob-9", "scout", "bob"))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        attr = _attribution(packet)
        ok = _check("P2a subject tier",
                    attr.get("owner") == "bob"
                    and attr.get("tier") == "directory-subject-binding",
                    repr((attr.get("owner"), attr.get("tier")))) and ok
        ic = _identity_claims(packet)
        ok = _check("P2b section present",
                    isinstance(ic, dict)) and ok
    finally:
        restore()
    return ok


# --------------------------------- P3: unverified email ignored
def p3_unverified_email_ignored():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=False))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        attr = _attribution(packet)
        ok = _check("P3a unverified email is not evidence",
                    attr.get("tier") == "directory-subject-binding",
                    repr(attr.get("tier"))) and ok
        ic = _identity_claims(packet)
        ok = _check("P3b email_verified False on section",
                    isinstance(ic, dict)
                    and ic.get("email_verified") is False) and ok
    finally:
        restore()
    return ok


# --------------------------------- P4: registry mode
def p4_registry_mode():
    ok = True
    reg = PrincipalRegistry({"alice": ["scout"]})
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory(), principal_registry=reg)
    try:
        ident = ex.mint_identity("scout-04", "scout", "alice")
        packet = _call_packet(ex, run_dir, read_entries, ident)
        ic = _identity_claims(packet)
        ok = _check("P4a principal-registry status",
                    isinstance(ic, dict)
                    and ic.get("verification_status") == "principal-registry",
                    repr((ic or {}).get("verification_status"))) and ok
        attr = _attribution(packet)
        ok = _check("P4b declared-principal tier (honest weakest)",
                    attr.get("owner") == "alice"
                    and attr.get("tier") == "directory-principal-known",
                    repr((attr.get("owner"), attr.get("tier")))) and ok
    finally:
        restore()
    return ok


# --------------------------------- P5: dev mode self-asserted
def p5_dev_mode():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity("scout-05", "scout", "alice")
        packet = _call_packet(ex, run_dir, read_entries, ident)
        ic = _identity_claims(packet)
        ok = _check("P5a self-asserted status",
                    isinstance(ic, dict)
                    and ic.get("verification_status") == "self-asserted",
                    repr((ic or {}).get("verification_status"))) and ok
    finally:
        restore()
    return ok


# --------------------------------- P6: federated mode
def p6_federated_mode():
    ok = True
    issuer_seed = bytes(range(32))
    issuer = fi.TokenIssuer(issuer_seed, "test-issuer")
    verifier = fi.TokenVerifier(AUD)
    verifier.add_issuer("test-issuer",
                        _ed.publickey(issuer_seed).hex())
    agent_seed = bytes([(i * 7) % 256 for i in range(32)])
    directory = {"principals": {
        "alice": {"emails": ["alice@example.com"],
                  "subjects": ["fed-sub-01"],
                  "groups": []}}}
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=directory, token_verifier=verifier)
    try:
        token = issuer.issue_token(
            agent_id="fed-sub-01", principal="alice", role="scout",
            agent_pubkey_hex=_ed.publickey(agent_seed).hex(),
            scopes=("tools:read",))
        ident = ex.mint_identity("fed-sub-01", "scout", "alice",
                                 token_claims=token)
        packet = _call_packet(ex, run_dir, read_entries, ident)
        ic = _identity_claims(packet)
        ok = _check("P6a identity-token-verified status",
                    isinstance(ic, dict)
                    and ic.get("verification_status")
                    == "identity-token-verified",
                    repr((ic or {}).get("verification_status"))) and ok
        ok = _check("P6b subject digest",
                    isinstance(ic, dict)
                    and ic.get("subject_digest")
                    == _digest("subject", "fed-sub-01")) and ok
        attr = _attribution(packet)
        ok = _check("P6c subject tier from verified sub",
                    attr.get("owner") == "alice"
                    and attr.get("tier") == "directory-subject-binding",
                    repr((attr.get("owner"), attr.get("tier")))) and ok
    finally:
        restore()
    return ok


# --------------------------------- P7: stale claims fail closed
def p7_stale_claims_fail_closed():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident1 = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=True))
        packet1 = _call_packet(ex, run_dir, read_entries, ident1)
        attr1 = _attribution(packet1)
        ok = _check("P7a first mint verified-email tier",
                    attr1.get("tier") == "verified-email-binding",
                    repr(attr1.get("tier"))) and ok
        # Tokenless re-mint of the same agent_id: verified claims must
        # NOT survive.
        ident2 = ex.mint_identity("auth0|alice-1", "scout", "alice")
        packet2 = _call_packet(ex, run_dir, read_entries, ident2)
        ic2 = _identity_claims(packet2)
        ok = _check("P7b re-mint status self-asserted",
                    isinstance(ic2, dict)
                    and ic2.get("verification_status") == "self-asserted",
                    repr((ic2 or {}).get("verification_status"))) and ok
        ok = _check("P7c re-mint email digest dropped",
                    isinstance(ic2, dict)
                    and ic2.get("email_digest") is None) and ok
        attr2 = _attribution(packet2)
        ok = _check("P7d re-mint tier weakest (no inheritance)",
                    attr2.get("tier") == "directory-principal-known",
                    repr(attr2.get("tier"))) and ok
        # Binding mismatch: corrupting the stored record's principal
        # (white-box fault injection) must omit the section and fall
        # back to declared-only attribution -- never thread a stale
        # record.
        ident3 = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=True))
        ex._minted_identity_claims["auth0|alice-1"]["principal"] = \
            "mallory"
        packet3 = _call_packet(ex, run_dir, read_entries, ident3)
        ok = _check("P7e binding mismatch omits section",
                    "identity_claims" not in packet3,
                    repr(sorted(packet3.keys()))) and ok
        attr3 = _attribution(packet3)
        ok = _check("P7f binding mismatch declared-only tier",
                    attr3.get("tier") == "directory-principal-known"
                    and attr3.get("owner") == "alice",
                    repr((attr3.get("owner"), attr3.get("tier")))) and ok
    finally:
        restore()
    return ok


# --------------------------------- P8: PII hygiene
def p8_pii_hygiene():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=True))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        raw = dp.canonical_bytes(packet)
        ok = _check("P8a raw email absent from packet bytes",
                    b"alice@example.com" not in raw) and ok
        ok = _check("P8b email digest present",
                    _digest("email", "alice@example.com")
                    .encode() in raw) and ok
    finally:
        restore()
    return ok


def _packet_kwargs(**over):
    """Minimal valid build_decision_packet kwargs (BOM required)."""
    kw = dict(decision="deny", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              issued_at="2026-10-05T00:00:00+00:00",
              identity={"agent_id": "a", "role": "r",
                        "principal": "p", "run_id": "run"},
              bill_of_materials=bom_mod.build_bom(
                  policy_id="default", policy_version="unversioned",
                  policy_digest="ab" * 32, evidence_head_digest="GENESIS",
                  principal={"agent_id": "a", "role": "r",
                             "principal": "p", "run_id": "run"}))
    kw.update(over)
    return kw


# --------------------------------- P9: tamper
def p9_tamper():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|alice-1", "scout", "alice",
            token_claims=_claims("auth0|alice-1", "scout", "alice",
                                 email="alice@example.com",
                                 email_verified=True))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        # Mutated section value breaks the packet signature.
        forged = json.loads(json.dumps(packet))
        forged["identity_claims"]["value"]["email_verified"] = False
        good, reason = dp.verify_decision_packet(forged)
        ok = _check("P9a mutated section refuses at verify",
                    good is False, reason) and ok
        # Forged section value refuses at construction.
        good_kw = _packet_kwargs()
        bad_value = {"verification_status": "token-claims-validated",
                     "subject_digest": None,
                     "email_digest": "not-hex",
                     "email_verified": True,
                     "groups_count": 0}
        try:
            dp.build_decision_packet(identity_claims=bad_value, **good_kw)
            ok = _check("P9b forged value refuses at construction",
                        False, "built") and ok
        except dp.PacketError:
            ok = _check("P9b forged value refuses at construction",
                        True) and ok
    finally:
        restore()
    return ok


# --------------------------------- P10: legacy byte-identical
def p10_legacy():
    ok = True
    kw = _packet_kwargs()
    body = dp.build_decision_packet(**kw)
    ok = _check("P10a no section without kwarg",
                "identity_claims" not in body) and ok
    body2 = dp.build_decision_packet(identity_claims=None, **kw)
    ok = _check("P10b None kwarg byte-identical",
                body2 == body) and ok
    return ok


# --------------------------------- P11: ambiguous on the packet
def p11_ambiguous():
    ok = True
    ex, run_dir, read_entries, restore = _make_exec(
        owner_directory=_directory())
    try:
        ident = ex.mint_identity(
            "auth0|bob-9", "scout", "bob",
            token_claims=_claims("auth0|bob-9", "scout", "bob",
                                 email="alice@example.com",
                                 email_verified=True))
        packet = _call_packet(ex, run_dir, read_entries, ident)
        attr = _attribution(packet)
        ok = _check("P11a ambiguous coded on packet",
                    attr.get("owner") is None
                    and attr.get("code")
                    == "ownership-inference-ambiguous",
                    repr((attr.get("owner"), attr.get("code")))) and ok
        ic = _identity_claims(packet)
        ok = _check("P11b claim section still rides",
                    isinstance(ic, dict)
                    and ic.get("verification_status")
                    == "token-claims-validated") and ok
    finally:
        restore()
    return ok


# --------------------------------- P12: pin, footer, taxonomy
def p12_pin_footer_taxonomy():
    ok = True
    ok = _check("P12a taxonomy pin %d" % TAXONOMY_PIN,
                len(TAXONOMY) == TAXONOMY_PIN,
                "len=%d" % len(TAXONOMY)) and ok
    for code in ("ownership-inference-unresolved",
                 "ownership-inference-ambiguous",
                 "ownership-directory-malformed"):
        ok = _check("P12b code registered: %s" % code[:24],
                    code in TAXONOMY, "") and ok
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        last = f.read().strip().splitlines()
        last = [l for l in last if 'Next free finding:' in l][-1]  # Wave-356 merge: footer not last line
    ok = _check("P12c footer open %s/next %s" % (FOOTER_OPEN, FOOTER_NEXT),
                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last) and ok
    return ok


# --------------------------------- P13: green check
def _green_check():
    """Depth-1 green check: ownership battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w343_ownership_probes.py",):
        # Fresh unique TMPDIR per green-check run (never a fixed
        # path): concurrent or sequential runs must not share ledger
        # state.
        tmp = tempfile.mkdtemp(prefix="g345-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        try:
            r = subprocess.run(
                [venv_python, os.path.join(REPO_ROOT, "evals", script)],
                capture_output=True, text=True, env=env, timeout=1800,
                cwd=REPO_ROOT)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        tail = (r.stdout + r.stderr)[-200:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = []
    for fn in (p1_verified_email_threading, p2_subject_tier,
               p3_unverified_email_ignored, p4_registry_mode,
               p5_dev_mode, p6_federated_mode,
               p7_stale_claims_fail_closed, p8_pii_hygiene, p9_tamper,
               p10_legacy, p11_ambiguous, p12_pin_footer_taxonomy):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
