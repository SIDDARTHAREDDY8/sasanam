#!/usr/bin/env python3
"""Wave-346 lane 5 battery: measure the identity-claim surface behind the
"Borrowed-Crown" threat class (agents acting under identities they were
never verifiably issued).

Wave-343 lane 4 built deterministic ownership inference; wave-345 lane 6
threaded verified mint_identity claims into every per-call decision packet
as a signature-covered identity_claims section. This battery measures that
surface red-first: claim presence across verification statuses, tamper
under wrong-key re-sign, the declared-principal weakest tier, and the
fail-closed inference rules.

$0 SPEND BY CONSTRUCTION: deterministic local construction only, no model
calls. Do NOT add ModelDriver/SpendLedger usage here.

Probes:
  P1  claim presence: every verification status produces the 5-field
      identity_claim_packet_value; statuses pinned.
  P2  tamper: mutated identity_claims value without re-sign refuses at
      verify (signature binds the claims); a claims section spliced from
      another identity's packet refuses too.
  P3  wrong-key re-sign honest boundary: mutate + re-sign with a DIFFERENT
      seed verifies in legacy mode (documented wave-235 residual: without
      a pinned trust root there is no external trust), but the authority
      kid CHANGES -- the attacker cannot keep the original executor's
      authority. Both facts pinned.
  P4  declared-principal weakest tier: known declared principal resolves
      at directory-principal-known, honestly labeled as declared-principal
      source (never IdP-vouched); unknown declared principal resolves
      ownership-inference-unresolved; declared principal disagreeing with
      verified evidence refuses ownership-inference-ambiguous.
  P5  conflicting strong evidence -> ownership-inference-ambiguous with
      both candidates named.
  P6  unverified email is not evidence -> ownership-inference-unresolved.
  P7  agreeing sources resolve at the STRONGEST tier
      (verified-email-binding).
  P8  PII hygiene: raw email absent from signed packet bytes; the digest
      pins the module's _digest_value.
  P9  pin 2140, footer open F436 / next F437, codes registered.
  P10 depth-1 green check over w345_ownthread_probes.py.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w346_identity_surface_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import json
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-346 lane 5: no new codes; pin unchanged; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


FOOTER_NEXT = "F700"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



from gov import ownership_inference as oi  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _digest(source, value):
    """Pin the module's digest function, not a re-typed hash."""
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


def _claim_record(**over):
    rec = {"verification_status": "token-claims-validated",
           "subject": "auth0|alice-1",
           "email": "alice@example.com",
           "email_verified": True,
           "groups": ["eng"]}
    rec.update(over)
    return rec


def _packet_kwargs(**over):
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


# --------------------------------- P1: claim presence across statuses
def p1_claim_presence():
    ok = True
    ok = _check("P1a statuses pinned",
                oi.IDENTITY_VERIFICATION_STATUSES
                == frozenset({"identity-token-verified",
                              "token-claims-validated",
                              "principal-registry",
                              "self-asserted"})) and ok
    for status in sorted(oi.IDENTITY_VERIFICATION_STATUSES):
        pv = oi.identity_claim_packet_value(
            _claim_record(verification_status=status))
        ok = _check("P1b %s 5-field shape" % status[:12],
                    isinstance(pv, dict)
                    and sorted(pv.keys()) == ["email_digest",
                                              "email_verified",
                                              "groups_count",
                                              "subject_digest",
                                              "verification_status"]
                    and pv["verification_status"] == status,
                    repr(sorted(pv.keys()) if isinstance(pv, dict)
                         else type(pv))) and ok
    # digest-carrying, never raw
    pv = oi.identity_claim_packet_value(_claim_record())
    raw = json.dumps(pv, sort_keys=True)
    ok = _check("P1c raw email never in claim value",
                "alice@example.com" not in raw) and ok
    ok = _check("P1d digests pin module function",
                pv["email_digest"] == _digest("email", "alice@example.com")
                and pv["subject_digest"]
                == _digest("subject", "auth0|alice-1")) and ok
    return ok


# --------------------------------- P2: tamper refuses without re-sign
def p2_tamper():
    ok = True
    pv_alice = oi.identity_claim_packet_value(_claim_record())
    pv_bob = oi.identity_claim_packet_value(
        _claim_record(subject="auth0|bob-9", email="bob@example.com"))
    seed = b"a" * 32
    pkt = dp.sign_packet(
        dp.build_decision_packet(identity_claims=pv_alice,
                                 **_packet_kwargs()), seed)
    # (a) mutate the value: signature must refuse
    mut = json.loads(json.dumps(pkt))
    mut["identity_claims"]["value"]["email_verified"] = False
    good, reason = dp.verify_decision_packet(mut)
    ok = _check("P2a mutated value refuses at verify",
                good is False, reason[:60]) and ok
    # (b) splice another identity's claims section: signature must refuse
    spliced = json.loads(json.dumps(pkt))
    spliced["identity_claims"]["value"] = dict(pv_bob)
    good, reason = dp.verify_decision_packet(spliced)
    ok = _check("P2b spliced foreign claims refuse at verify",
                good is False, reason[:60]) and ok
    # (c) the unmutated packet verifies: control
    good, reason = dp.verify_decision_packet(pkt)
    ok = _check("P2c unmutated packet verifies", good is True,
                reason[:60]) and ok
    return ok


# --------------------------------- P3: wrong-key re-sign honest boundary
def p3_wrong_key_resign():
    ok = True
    pv = oi.identity_claim_packet_value(_claim_record())
    seed_a = b"a" * 32
    seed_b = b"b" * 32
    body = dp.build_decision_packet(identity_claims=pv, **_packet_kwargs())
    pkt_a = dp.sign_packet(dict(body), seed_a)
    kid_a = pkt_a["authority"]["kid"]
    # Attacker mutates the claims and re-signs with THEIR key.
    body_b = json.loads(json.dumps(body))
    forged_value = dict(pv)
    forged_value["email_digest"] = _digest("email", "mallory@evil.example")
    body_b["identity_claims"]["value"] = forged_value
    pkt_b = dp.sign_packet(body_b, seed_b)
    good, reason = dp.verify_decision_packet(pkt_b)
    ok = _check("P3a wrong-key re-sign verifies in LEGACY mode "
                "(wave-235 residual, documented)",
                good is True, reason[:60]) and ok
    ok = _check("P3b attacker cannot keep the original authority",
                pkt_b["authority"]["kid"] != kid_a,
                "%s != %s" % (pkt_b["authority"]["kid"][:8],
                              kid_a[:8])) and ok
    ok = _check("P3c forged email digest rides only the forged kid",
                pkt_b["identity_claims"]["value"]["email_digest"]
                == _digest("email", "mallory@evil.example")) and ok
    return ok


# --------------------------------- P4: declared principal is weakest tier
def p4_declared_weakest_tier():
    ok = True
    d = _directory()
    # (a) known declared principal: resolves, weakest tier, honestly labeled
    a = oi.infer_owner({"declared_principal": "alice"}, d)
    ok = _check("P4a declared-known resolves weakest tier",
                a["owner"] == "alice"
                and a["tier"] == "directory-principal-known",
                repr((a["owner"], a["tier"]))) and ok
    ok = _check("P4b weakest tier honestly labeled",
                any(e["source"] == "declared-principal"
                    for e in a["evidence"]),
                repr([e["source"] for e in a["evidence"]])) and ok
    # (b) unknown declared principal: unresolved, coded
    try:
        oi.infer_owner({"declared_principal": "stranger"}, d)
        ok = _check("P4c declared-unknown refuses", False, "resolved") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P4c declared-unknown refuses",
                    e.code == "ownership-inference-unresolved",
                    e.code) and ok
    # (c) declared principal disagreeing with verified evidence: ambiguous
    try:
        oi.infer_owner({"declared_principal": "bob",
                        "email": "alice@example.com",
                        "email_verified": True}, d)
        ok = _check("P4d declared-vs-verified refuses", False,
                    "resolved") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P4d declared-vs-verified refuses",
                    e.code == "ownership-inference-ambiguous",
                    e.code) and ok
    return ok


# --------------------------------- P5: conflicting strong evidence
def p5_ambiguous():
    ok = True
    d = _directory()
    try:
        oi.infer_owner({"subject": "auth0|bob-9",
                        "email": "alice@example.com",
                        "email_verified": True}, d)
        ok = _check("P5a conflicting evidence refuses", False,
                    "resolved") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P5a conflicting evidence refuses",
                    e.code == "ownership-inference-ambiguous",
                    e.code) and ok
    a = oi.attribute_owner({"subject": "auth0|bob-9",
                            "email": "alice@example.com",
                            "email_verified": True}, d)
    ok = _check("P5b never-raises form names both candidates",
                a["owner"] is None
                and a["code"] == "ownership-inference-ambiguous"
                and a.get("conflicting") == ["alice", "bob"],
                repr((a["owner"], a["code"],
                      a.get("conflicting")))) and ok
    return ok


# --------------------------------- P6: unverified email is not evidence
def p6_unverified_email_ignored():
    ok = True
    d = _directory()
    try:
        oi.infer_owner({"email": "alice@example.com",
                        "email_verified": False}, d)
        ok = _check("P6a unverified email refuses", False,
                    "resolved") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P6a unverified email refuses",
                    e.code == "ownership-inference-unresolved",
                    e.code) and ok
    return ok


# --------------------------------- P7: strongest tier wins for agreements
def p7_strongest_tier_wins():
    ok = True
    d = _directory()
    a = oi.infer_owner({"declared_principal": "alice",
                        "subject": "auth0|alice-1",
                        "email": "alice@example.com",
                        "email_verified": True}, d)
    ok = _check("P7a agreeing sources resolve strongest tier",
                a["owner"] == "alice"
                and a["tier"] == "verified-email-binding",
                repr((a["owner"], a["tier"]))) and ok
    ok = _check("P7b declared-vs-inferred consistency recorded",
                a["declared_consistency"] == "declared-matches-inferred",
                a["declared_consistency"]) and ok
    return ok


# --------------------------------- P8: PII hygiene on the signed packet
def p8_pii_hygiene():
    ok = True
    pv = oi.identity_claim_packet_value(_claim_record())
    pkt = dp.sign_packet(
        dp.build_decision_packet(identity_claims=pv, **_packet_kwargs()),
        b"c" * 32)
    raw = dp.canonical_bytes(pkt)
    ok = _check("P8a raw email absent from signed packet bytes",
                b"alice@example.com" not in raw) and ok
    ok = _check("P8b raw subject absent from signed packet bytes",
                b"auth0|alice-1" not in raw) and ok
    ok = _check("P8c email digest present",
                _digest("email", "alice@example.com").encode()
                in raw) and ok
    return ok


# --------------------------------- P9: pin, footer, taxonomy
def p9_pin_footer_taxonomy():
    ok = True
    ok = _check("P9a taxonomy pin %d" % TAXONOMY_PIN,
                len(TAXONOMY) == TAXONOMY_PIN,
                "len=%d" % len(TAXONOMY)) and ok
    for code in ("ownership-inference-unresolved",
                 "ownership-inference-ambiguous",
                 "ownership-directory-malformed"):
        ok = _check("P9b code registered: %s" % code[:24],
                    code in TAXONOMY, "") and ok
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        last = f.read().strip().splitlines()
        last = [l for l in last if 'Next free finding:' in l][-1]  # Wave-356 merge: footer not last line
    ok = _check("P9c footer open %s/next %s" % (FOOTER_OPEN, FOOTER_NEXT),
                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last[:80]) and ok
    return ok


# --------------------------------- P10: green check
def _green_check():
    """Depth-1 green check: ownthread battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w345_ownthread_probes.py",):
        # Fresh unique TMPDIR per green-check run (never a fixed
        # path): concurrent or sequential runs must not share ledger
        # state.
        tmp = tempfile.mkdtemp(prefix="g346-green-", dir="/var/tmp")
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
    for fn in (p1_claim_presence, p2_tamper, p3_wrong_key_resign,
               p4_declared_weakest_tier, p5_ambiguous,
               p6_unverified_email_ignored, p7_strongest_tier_wins,
               p8_pii_hygiene, p9_pin_footer_taxonomy):
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
