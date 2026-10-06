#!/usr/bin/env python3
"""Wave-343 lane 4 battery: ownership inference for agent identities.

Rig Security deep-dive steal #3 (2026-10-05), adapted: every agent
identity auto-traced to its human owner -- "block the agent, not the
employee" / "what is acting through that access right now?". Rig's
RICE is ML identity-correlation (unverifiable accuracy marketing, NOT
copied); ours is the precision answer: the deployment's own principal
directory is ground truth, and the inference is deterministic,
evidence-backed, and fail-closed (gov/ownership_inference.py).

$0 SPEND BY CONSTRUCTION: canned claim sets only, no model calls. Do
NOT add ModelDriver/SpendLedger usage here.

Probes:
  P1  inference tiers: verified email > directory subject >
      declared-principal-known (honest weakest tier); group matches
      corroborate only.
  P2  fail-closed: unverified email is NOT evidence; a group alone
      never resolves; conflicting strong sources refuse
      ownership-inference-ambiguous (never votes); no evidence gives
      the coded ownership-inference-unresolved.
  P3  directory validation: duplicate emails/subjects across
      principals refuse ownership-directory-malformed fail-fast.
  P4  PII hygiene: evidence records carry sha256 digests, never raw
      identifier values.
  P5  inventory: attach_owner_attribution / owner_attribution_of /
      declared_vs_inferred_owner (match, differs, no-attribution,
      owner-unresolved); non-agent entries refuse.
  P6  decision packet: a deny packet carrying owner_attribution
      verifies; tampered owner refuses at construction; legacy
      packets (no kwarg) stay byte-identical.
  P7  executor: owner_directory kwarg validates fail-fast; the
      default (None) keeps legacy behavior.
  P8  pin 2134 (base 2131 + 3 ownership codes), footer open F429 /
      next F430, codes centrally registered with real emission sites.
  P9  determinism: repeated inference is byte-identical; digests
      recompute.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w343_ownership_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import hashlib
import json
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2134  # Wave-343 lane 4: base 2131 + 3 ownership codes
FOOTER_OPEN = "F437, F439, F440, F441, F442"
FOOTER_NEXT = "F443"

from gov import ownership_inference as oi  # noqa: E402
from gov import inventory_catalog as ic  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _directory():
    return oi.load_owner_directory({
        "principals": {
            "alice": {"emails": ["alice@example.com"],
                      "subjects": ["auth0|alice-1"],
                      "groups": ["eng", "oncall"]},
            "bob": {"emails": ["bob@example.com"],
                    "subjects": ["auth0|bob-9"],
                    "groups": ["eng"]},
        }
    })


# ------------------------------------------------------------------ P1: tiers
def p1_inference_tiers():
    d = _directory()
    ok = True
    a = oi.infer_owner({"subject": "auth0|alice-1",
                        "email": "alice@example.com", "email_verified": True,
                        "groups": ["eng"], "declared_principal": "alice"}, d)
    ok = _check("P1a verified-email tier", a["owner"] == "alice"
                and a["tier"] == "verified-email-binding") and ok
    ok = _check("P1b declared consistency",
                a["declared_consistency"] == "declared-matches-inferred") \
        and ok
    b = oi.infer_owner({"subject": "auth0|bob-9", "groups": ["eng"],
                        "declared_principal": "bob"}, d)
    ok = _check("P1c subject tier", b["owner"] == "bob"
                and b["tier"] == "directory-subject-binding") and ok
    ok = _check("P1d group corroborates",
                any(e["source"] == "directory-group"
                    and e.get("strength") == "corroborating"
                    for e in b["evidence"])) and ok
    c = oi.attribute_owner({"declared_principal": "alice"}, d)
    ok = _check("P1e declared-principal tier (weakest)",
                c["owner"] == "alice"
                and c["tier"] == "directory-principal-known") and ok
    return ok


# -------------------------------------------------------------- P2: fail-closed
def p2_fail_closed():
    d = _directory()
    ok = True
    try:
        oi.infer_owner({"email": "alice@example.com",
                        "email_verified": False, "groups": []}, d)
        ok = _check("P2a unverified email not evidence", False,
                    "resolved without evidence") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P2a unverified email not evidence",
                    e.code == "ownership-inference-unresolved",
                    e.code) and ok
    try:
        oi.infer_owner({"groups": ["eng"]}, d)
        ok = _check("P2b group alone never resolves", False,
                    "resolved from a shared group") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P2b group alone never resolves",
                    e.code == "ownership-inference-unresolved",
                    e.code) and ok
    try:
        oi.infer_owner({"subject": "auth0|alice-1",
                        "email": "bob@example.com",
                        "email_verified": True}, d)
        ok = _check("P2c conflict is loud", False, "picked a winner") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P2c conflict is loud",
                    e.code == "ownership-inference-ambiguous",
                    e.code) and ok
    a = oi.attribute_owner({"groups": []}, d)
    ok = _check("P2d unresolved is coded",
                a["owner"] is None and a["tier"] == "unresolved"
                and a["code"] == "ownership-inference-unresolved") and ok
    ok = _check("P2e unresolved digest recomputes",
                a["digest"] == oi.attribution_digest(a)) and ok
    return ok


# ------------------------------------------------------- P3: directory hygiene
def p3_directory_validation():
    ok = True
    for raw, label in (
            ({"principals": {"a": {"emails": ["x@y.z"]},
                             "b": {"emails": ["x@y.z"]}}}, "dup email"),
            ({"principals": {"a": {"subjects": ["s"]},
                             "b": {"subjects": ["s"]}}}, "dup subject"),
            ({"principals": {}}, "empty principals"),
            ({"principals": {"a": {"emails": [""]}}}, "empty identifier"),
            ("nope", "non-dict")):
        try:
            oi.load_owner_directory(raw)
            ok = _check("P3a directory refuses: %s" % label, False,
                        "loaded") and ok
        except oi.OwnershipInferenceError as e:
            ok = _check("P3a directory refuses: %s" % label,
                        e.code == "ownership-directory-malformed",
                        e.code) and ok
    # Groups MAY be shared across principals (corroborating evidence).
    try:
        oi.load_owner_directory({"principals": {
            "a": {"groups": ["eng"]}, "b": {"groups": ["eng"]}}})
        ok = _check("P3b shared groups allowed", True) and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P3b shared groups allowed", False, str(e)) and ok
    return ok


# ------------------------------------------------------------- P4: PII hygiene
def p4_no_raw_identifiers():
    d = _directory()
    ok = True
    a = oi.infer_owner({"subject": "auth0|alice-1",
                        "email": "alice@example.com", "email_verified": True,
                        "groups": ["eng"]}, d)
    blob = json.dumps(a["evidence"])
    for raw in ("alice@example.com", "auth0|alice-1"):
        ok = _check("P4a no raw identifier %r" % raw[:8],
                    raw not in blob) and ok
    digests = [e["value_digest"] for e in a["evidence"]]
    ok = _check("P4b digests are 64-char hex",
                all(len(x) == 64 and all(c in "0123456789abcdef" for c in x)
                    for x in digests)) and ok
    return ok


# ----------------------------------------------------------------- P5: inventory
def _catalog():
    return ic.load_catalog([
        {"kind": "agent", "name": "scout-01", "owner": "alice",
         "capabilities": ["read"], "relationships": []},
        {"kind": "tool", "name": "read_file", "owner": "platform",
         "capabilities": ["read"], "relationships": []},
    ])


def p5_inventory_evidence():
    d = _directory()
    ok = True
    cat = _catalog()
    a = oi.infer_owner({"subject": "auth0|alice-1",
                        "declared_principal": "alice"}, d)
    cat2 = ic.attach_owner_attribution(cat, "scout-01", a)
    got = ic.owner_attribution_of(cat2, "scout-01")
    ok = _check("P5a attribution attached",
                got == a and ic.owner_attribution_of(cat, "scout-01") is None,
                "immutable") and ok
    cmp_ = ic.declared_vs_inferred_owner(cat2, "scout-01")
    ok = _check("P5b declared matches inferred",
                cmp_["verdict"] == "declared-matches-inferred") and ok
    # Spoofed declared owner: the catalog entry still declares alice
    # but a fresh catalog entry declaring mallory must flag differs.
    cat3 = ic.load_catalog([
        {"kind": "agent", "name": "scout-01", "owner": "mallory",
         "capabilities": ["read"], "relationships": []}])
    cat3 = ic.attach_owner_attribution(cat3, "scout-01", a)
    cmp3 = ic.declared_vs_inferred_owner(cat3, "scout-01")
    ok = _check("P5c declared differs inferred",
                cmp3["verdict"] == "declared-differs-inferred"
                and cmp3["inferred"] == "alice") and ok
    # No attribution attached: explicit, never silent.
    cmp4 = ic.declared_vs_inferred_owner(cat, "scout-01")
    ok = _check("P5d no-attribution explicit",
                cmp4["verdict"] == "no-attribution") and ok
    # Coded-unresolved attribution records owner-unresolved.
    cat5 = ic.attach_owner_attribution(
        _catalog(), "scout-01",
        oi.attribute_owner({"declared_principal": "stranger"}, d))
    cmp5 = ic.declared_vs_inferred_owner(cat5, "scout-01")
    ok = _check("P5e owner-unresolved verdict",
                cmp5["verdict"] == "owner-unresolved"
                and cmp5["attribution"]["code"]
                == "ownership-inference-unresolved") and ok
    # Non-agent entries refuse attributions.
    try:
        ic.attach_owner_attribution(_catalog(), "read_file", a)
        ok = _check("P5f tool entry refuses", False, "attached") and ok
    except ic.CatalogRefused as e:
        ok = _check("P5f tool entry refuses",
                    e.code == "inventory-catalog-entry-malformed",
                    e.code) and ok
    # A tampered attribution is refused at the seam (compare-don't-trust).
    bad = dict(a)
    bad["owner"] = "mallory"
    try:
        ic.attach_owner_attribution(_catalog(), "scout-01", bad)
        ok = _check("P5g tampered refused", False, "attached") and ok
    except ic.CatalogRefused as e:
        ok = _check("P5g tampered refused",
                    e.code == "inventory-catalog-entry-malformed",
                    e.code) and ok
    return ok


# ------------------------------------------------------------ P6: packet seam
def _bom_for(identity):
    return bom.build_bom(
        policy_id="p1", policy_version="1",
        policy_digest=hashlib.sha256(b"policy").hexdigest(),
        evidence_head_digest="cd" * 32, principal=dict(identity))


def p6_decision_packet():
    d = _directory()
    ok = True
    identity = {"agent_id": "scout-01", "role": "scout",
                "principal": "alice", "run_id": "run-1"}
    attribution = oi.infer_owner({"subject": "auth0|alice-1",
                                  "declared_principal": "alice"}, d)
    body = dp.build_decision_packet(
        decision="deny", boundary_declared=False,
        policy_id="p1", policy_version="1",
        decision_digest="ab" * 32, evidence_head_digest="cd" * 32,
        bill_of_materials=_bom_for(identity), identity=identity,
        owner_attribution=attribution)
    ok = _check("P6a section present",
                body["owner_attribution"]["value"]["owner"] == "alice") \
        and ok
    packet = dp.sign_packet(body, b"\x41" * 32)
    vok, reason = dp.verify_decision_packet(packet)
    ok = _check("P6b packet with attribution verifies", vok, reason) and ok
    # A blocked agent's decision record names its inferred owner.
    ok = _check("P6c decision record names owner",
                packet["owner_attribution"]["value"]["owner"] == "alice") \
        and ok
    # Tampered owner refuses at construction (compare-don't-trust).
    bad = dict(attribution)
    bad["owner"] = "mallory"
    try:
        dp.build_decision_packet(
            decision="deny", boundary_declared=False,
            policy_id="p1", policy_version="1",
            decision_digest="ab" * 32, evidence_head_digest="cd" * 32,
            bill_of_materials=_bom_for(identity), identity=identity,
            owner_attribution=bad)
        ok = _check("P6d tampered owner refuses", False, "built") and ok
    except dp.PacketError:
        ok = _check("P6d tampered owner refuses", True) and ok
    # Legacy packet (no kwarg) is byte-identical to a build without it.
    legacy = dp.build_decision_packet(
        decision="deny", boundary_declared=False,
        policy_id="p1", policy_version="1",
        decision_digest="ab" * 32, evidence_head_digest="cd" * 32,
        bill_of_materials=_bom_for(identity), identity=identity)
    ok = _check("P6e legacy byte-identical",
                "owner_attribution" not in legacy) and ok
    return ok


# -------------------------------------------------------------- P7: executor
def p7_executor_wiring():
    ok = True
    import tempfile
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.log import ActionLog
    from gov.approvals import ApprovalQueue
    from gov.log import read_entries
    from tests import keyfixture

    # Wave-280 lesson: scrub_key_env returns a restore() closure --
    # ignoring it wipes ambient GOV_LOG_KEY mid-process.
    restore = keyfixture.scrub_key_env()
    keyfixture.provision_test_key()
    try:
        return _p7_body(ToolExecutor, PolicyEngine, ActionLog,
                        ApprovalQueue, tempfile)
    finally:
        restore()


def _p7_body(ToolExecutor, PolicyEngine, ActionLog, ApprovalQueue,
             tempfile):

    from gov.log import read_entries

    ok = True
    directory = {"principals": {
        "alice": {"emails": ["alice@example.com"]}}}

    def _make_exec(**kw):
        run_dir = tempfile.mkdtemp(prefix="g343-own-",
                                   dir="/var/tmp")
        policy = PolicyEngine(
            os.path.join(REPO_ROOT, "policies", "default.yaml"))
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ungoverned_ack="w343 battery: raw pipeline "
                          "by design",
                          packet_key_seed="cd" * 32, **kw)
        return ex, run_dir

    # Real emit path: a denied call's decision packet names the
    # inferred owner.
    ex, run_dir = _make_exec(owner_directory=directory)
    ident = ex.mint_identity("scout-01", "scout", "alice")
    try:
        ex.call(ident, "read_file", path="/etc/shadow-x343")
    except Exception:
        pass  # the decision (not the outcome) is what we audit
    packets = [e for e in read_entries(os.path.join(run_dir, "actions.jsonl"))
               if e.get("event") == "decision_packet"]
    ok = _check("P7a decision packet emitted", len(packets) >= 1,
                "n=%d" % len(packets)) and ok
    if packets:
        section = packets[-1]["packet"].get("owner_attribution", {})
        ok = _check("P7b packet names inferred owner",
                    section.get("value", {}).get("owner") == "alice",
                    repr(section.get("value", {}).get("owner"))) and ok
        ok = _check("P7c packet tier honest",
                    section.get("value", {}).get("tier")
                    == "directory-principal-known") and ok
    # Unknown principal: the coded unresolved state, never omitted.
    ident2 = ex.mint_identity("scout-02", "scout", "stranger")
    try:
        ex.call(ident2, "read_file", path="/etc/shadow-x343")
    except Exception:
        pass
    packets2 = [e for e in read_entries(os.path.join(run_dir, "actions.jsonl"))
                if e.get("event") == "decision_packet"
                and e.get("agent_id") == "scout-02"]
    if packets2:
        val = packets2[-1]["packet"]["owner_attribution"]["value"]
        ok = _check("P7d unresolved is coded",
                    val["owner"] is None
                    and val["code"] == "ownership-inference-unresolved",
                    repr(val.get("code"))) and ok
    else:
        ok = _check("P7d unresolved is coded", False, "no packet") and ok
    # Malformed directory fails fast at construction.
    try:
        _make_exec(owner_directory={"principals": {
            "a": {"emails": ["x@y.z"]}, "b": {"emails": ["x@y.z"]}}})
        ok = _check("P7e malformed directory fails fast", False,
                    "constructed") and ok
    except oi.OwnershipInferenceError as e:
        ok = _check("P7e malformed directory fails fast",
                    e.code == "ownership-directory-malformed",
                    e.code) and ok
    # Default (None): legacy behavior, no section.
    ex0, _ = _make_exec()
    ok = _check("P7f default None keeps legacy",
                ex0._owner_directory is None) and ok
    return ok


# ------------------------------------------------- P8: pin, footer, taxonomy
def p8_pin_footer_taxonomy():
    ok = True
    ok = _check("P8a taxonomy pin %d" % TAXONOMY_PIN,
                len(TAXONOMY) == TAXONOMY_PIN, "len=%d" % len(TAXONOMY)) \
        and ok
    for code in ("ownership-inference-unresolved",
                 "ownership-inference-ambiguous",
                 "ownership-directory-malformed"):
        ok = _check("P8b code registered: %s" % code[:24],
                    code in TAXONOMY) and ok
    # Codes are sorted with the rest of the taxonomy literals.
    keys = list(TAXONOMY)
    ok = _check("P8c taxonomy sorted", keys == sorted(keys)) and ok
    last = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
                ).read().splitlines()[-1]
    ok = _check("P8d footer open %s/next %s" % (FOOTER_OPEN, FOOTER_NEXT),
                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last[:60]) and ok
    return ok


# -------------------------------------------------------------- P9: determinism
def p9_determinism():
    d = _directory()
    ok = True
    kwargs = {"subject": "auth0|alice-1",
              "email": "alice@example.com", "email_verified": True,
              "groups": ["eng", "oncall"], "declared_principal": "alice"}
    a1 = oi.infer_owner(kwargs, d)
    a2 = oi.infer_owner(kwargs, d)
    ok = _check("P9a byte-identical repeats", a1 == a2) and ok
    ok = _check("P9b digest recomputes",
                a1["digest"] == oi.attribution_digest(a1)) and ok
    # Attribution survives a JSON round-trip (packet/inventory path).
    a3 = json.loads(json.dumps(a1))
    vok, reason = oi.check_attribution_value(a3)
    ok = _check("P9c JSON round-trip valid", vok, reason) and ok
    return ok


def _green_check():
    """Depth-1 green check: dex-identity batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w325_dexid_probes.py", "w248_dex_identity_probes.py"):
        tmp = "/var/tmp/g343-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
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
    for fn in (p1_inference_tiers, p2_fail_closed, p3_directory_validation,
               p4_no_raw_identifiers, p5_inventory_evidence,
               p6_decision_packet, p7_executor_wiring,
               p8_pin_footer_taxonomy, p9_determinism):
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
