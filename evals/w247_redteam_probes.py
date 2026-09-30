"""Wave-247 red-team probes: break-first attacks on the wave-246 new modules.

Break-first discipline (diagnosing-bugs skill): each probe is a tight,
deterministic, agent-runnable loop that drives the ACTUAL attack code
path and asserts the attacker's exact win condition. A probe that goes
red (BREAK) is a genuine product gap -> filed as a finding. A probe
that stays green (HELD) is a pin on the control.

Targets (all new in wave-246, base fc4d8e8):
  gov/policy_delta_gate.py, gov/schema_ref_guard.py,
  gov/breach_boundary.py, gov/advisory_state.py,
  gov/mcp_discovery_trust.py, gov/identity_crosscheck.py,
  gov/reputation_ledger.py

Results of the initial run (2026-09-30):
  BREAK: breach_forged_verified, breach_verify_then_mutate
         -> filed as F210 (MEDIUM)
  HELD:  all other probes (documented as pins below)

Hygiene: module-level staging setdefault; no in-repo git subprocesses;
fresh TMPDIR per run; stdlib only.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import breach_boundary as _bb
from gov import policy_delta_gate as _pdg
from gov import schema_ref_guard as _srg
from gov import advisory_state as _as
from gov import mcp_discovery_trust as _mdt
from gov import identity_crosscheck as _ic
from gov import reputation_ledger as _rl
from gov import agent_identity as _ai
from gov import ed25519 as _ed


# ---------------------------------------------------------------------------
# Probe harness
# ---------------------------------------------------------------------------

def _run(name, fn):
    """Run one probe. Returns (name, verdict, evidence)."""
    try:
        verdict, evidence = fn()
    except Exception as exc:  # probe harness error, not a product verdict
        return (name, "PROBE-ERROR",
                "%s: %s" % (type(exc).__name__, exc))
    assert verdict in ("HELD", "BREAK"), verdict
    return (name, verdict, evidence)


# ---------------------------------------------------------------------------
# BREAK probes: breach_boundary quarantine integrity
# ---------------------------------------------------------------------------

def probe_breach_forged_verified():
    """Attacker forges a quarantined record with verified=True (never
    went through verify()) and calls use(). Win condition: use()
    returns allow."""
    bb = _bb.BreachBoundary()
    bb.declare_component("mem-svc", "assumed-breachable")
    forged = {
        "_breach_boundary_quarantined": True,
        "decision": "quarantined",
        "component": "mem-svc",
        "trust_class": "assumed-breachable",
        "seq": 999,
        "output": {"exfil": "attacker-controlled"},
        "verified": True,  # forged; no verification step ever ran
        "verification": {"verifier_id": "nobody", "evidence": None},
    }
    try:
        result = bb.use(forged)
    except _bb.BreachBoundaryError as exc:
        return ("HELD", "use() refused forged record: %s" % exc.code)
    if result.get("decision") == "allow":
        return ("BREAK",
                "use() ALLOWED a fabricated record with forged "
                "verified=True; the deployment-vouched verification "
                "step was bypassed entirely (F210)")
    return ("HELD", "unexpected result shape: %r" % (result,))


def probe_breach_verify_then_mutate():
    """TOCTOU: legitimate verify() on benign output, then mutate the
    record's output payload, then use(). Win condition: use() allows
    the MUTATED (never-verified) output."""
    bb = _bb.BreachBoundary()
    bb.declare_component("tool-svc", "assumed-breachable")
    q = bb.ingest("tool-svc", {"cmd": "benign --dry-run"})
    v = bb.verify(q, {"verifier_id": "checker-1", "evidence": "ok"},
                  {"checker-1": "deployment-vouched"})
    v["output"] = {"cmd": "exfil --send-all"}  # mutate AFTER verify
    try:
        result = bb.use(v)
    except _bb.BreachBoundaryError as exc:
        return ("HELD", "use() refused mutated record: %s" % exc.code)
    if result.get("output") == {"cmd": "exfil --send-all"}:
        return ("BREAK",
                "use() ALLOWED output mutated after verification; the "
                "verified record is not tamper-evident (F210)")
    return ("HELD", "unexpected result shape: %r" % (result,))


# ---------------------------------------------------------------------------
# policy_delta_gate probes
# ---------------------------------------------------------------------------

_OLD_POLICY = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
      path_prefix: /safe
"""

_NEW_SCALAR_WIDE = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
      path_prefix: /
"""

_NEW_LIST_WIDE = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file, exec_sh]
"""

_NEW_FORBID_REMOVED = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
"""

_OLD_WITH_FORBID = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
  - id: f1
    effect: deny
    match:
      tool: [exec_sh]
"""

_NEW_EFFECT_WEAKENED = """version: 1
policies:
  - id: r1
    effect: allow
    match:
      tool: [read_file]
  - id: f1
    effect: allow
    match:
      tool: [exec_sh]
"""


def probe_policy_scalar_widening():
    """Scalar match widening (path_prefix /safe -> /). The gate flags
    it medium (allow-modified) and PASSES. This is the lane's
    DOCUMENTED residual (match-direction proofs cover list-valued
    keys only), so the probe pins the behavior as HELD-with-residual,
    not a new finding."""
    rep = _pdg.analyze_policy_delta(_OLD_POLICY, _NEW_SCALAR_WIDE)
    classes = [f["risk_class"] for f in rep["risk_findings"]]
    if rep["verdict"] == "pass" and classes == [
            "policy-delta-allow-modified"]:
        return ("HELD",
                "scalar widening flagged medium allow-modified, verdict "
                "pass -- documented residual (lane report: scalar key "
                "changes are flagged medium, not refused)")
    return ("BREAK",
            "unexpected verdict/classes: %s %s"
            % (rep["verdict"], classes))


def probe_policy_list_widening_refused():
    """List-valued allow widening must refuse high."""
    rep = _pdg.analyze_policy_delta(_OLD_POLICY, _NEW_LIST_WIDE)
    if rep["verdict"] == "refuse" and any(
            f["risk_class"] == "policy-delta-widening"
            for f in rep["risk_findings"]):
        return ("HELD", "list widening refused policy-delta-widening")
    return ("BREAK", "list widening not refused: %s" % rep["verdict"])


def probe_policy_forbid_removed_refused():
    """Removing a deny rule must refuse high."""
    rep = _pdg.analyze_policy_delta(_OLD_WITH_FORBID, _NEW_FORBID_REMOVED)
    if rep["verdict"] == "refuse" and any(
            f["risk_class"] == "policy-delta-forbid-removed"
            for f in rep["risk_findings"]):
        return ("HELD", "forbid removal refused policy-delta-forbid-removed")
    return ("BREAK", "forbid removal not refused: %s" % rep["verdict"])


def probe_policy_effect_weakened_refused():
    """deny -> allow flip must refuse high."""
    rep = _pdg.analyze_policy_delta(_OLD_WITH_FORBID, _NEW_EFFECT_WEAKENED)
    if rep["verdict"] == "refuse" and any(
            f["risk_class"] == "policy-delta-effect-weakened"
            for f in rep["risk_findings"]):
        return ("HELD", "effect weaken refused policy-delta-effect-weakened")
    return ("BREAK", "effect weaken not refused: %s" % rep["verdict"])


# ---------------------------------------------------------------------------
# schema_ref_guard probes
# ---------------------------------------------------------------------------

def probe_schema_external_ref():
    """Out-of-document $ref must be refused, never fetched."""
    try:
        _srg.check_tool_schema(
            {"type": "object",
             "properties": {"x": {"$ref": "https://evil.example/s.json"}}})
    except _srg.SchemaRefGuardError as exc:
        if exc.code == "schema-ref-external":
            return ("HELD", "external $ref refused schema-ref-external")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "external $ref was ALLOWED")


def probe_schema_relative_ref():
    """Bare relative $ref (no #) must be refused, not resolved."""
    try:
        _srg.check_tool_schema({"$ref": "other.json#/defs/x"})
    except _srg.SchemaRefGuardError as exc:
        if exc.code == "schema-ref-external":
            return ("HELD", "relative $ref refused schema-ref-external")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "relative $ref was ALLOWED")


def probe_schema_cycle():
    """Cyclic $ref chain must be refused."""
    schema = {"defs": {"a": {"$ref": "#/defs/b"},
                       "b": {"$ref": "#/defs/a"}},
              "$ref": "#/defs/a"}
    try:
        _srg.check_tool_schema(schema)
    except _srg.SchemaRefGuardError as exc:
        if exc.code == "schema-ref-depth-exceeded":
            return ("HELD", "cycle refused schema-ref-depth-exceeded")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "cyclic $ref was ALLOWED")


def probe_schema_deep_chain():
    """A 30-deep in-document chain (default max 16) must be refused."""
    defs = {}
    for i in range(30):
        nxt = "#/defs/d%d" % (i + 1) if i < 29 else "#/defs/leaf"
        defs["d%d" % i] = {"$ref": nxt}
    defs["leaf"] = {"type": "string"}
    try:
        _srg.check_tool_schema({"defs": defs, "$ref": "#/defs/d0"})
    except _srg.SchemaRefGuardError as exc:
        if exc.code == "schema-ref-depth-exceeded":
            return ("HELD", "deep chain refused schema-ref-depth-exceeded")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "30-deep chain was ALLOWED")


def probe_schema_budget():
    """1001 sibling refs (default budget 1000) must exhaust the budget."""
    schema = {"defs": {"leaf": {"type": "string"}},
              "allOf": [{"$ref": "#/defs/leaf"} for _ in range(1001)]}
    try:
        _srg.check_tool_schema(schema)
    except _srg.SchemaRefGuardError as exc:
        if exc.code == "schema-ref-budget-exhausted":
            return ("HELD", "ref storm refused schema-ref-budget-exhausted")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "1001-ref storm was ALLOWED")


def probe_schema_diamond_allowed():
    """A diamond (shared leaf, no cycle) must be allowed -- no false
    positive from the chain check."""
    schema = {"defs": {"leaf": {"type": "string"},
                       "a": {"$ref": "#/defs/leaf"},
                       "b": {"$ref": "#/defs/leaf"}},
              "allOf": [{"$ref": "#/defs/a"}, {"$ref": "#/defs/b"}]}
    try:
        result = _srg.check_tool_schema(schema)
    except _srg.SchemaRefGuardError as exc:
        return ("BREAK", "diamond falsely refused: %s" % exc.code)
    if result["decision"] == "allow":
        return ("HELD", "diamond allowed, refs_resolved=%d"
                % result["refs_resolved"])
    return ("BREAK", "unexpected: %r" % (result,))


# ---------------------------------------------------------------------------
# advisory_state probes
# ---------------------------------------------------------------------------

def _pinned_advisory():
    """Minimal pinned record shape for assess_component (bypasses the
    signature bind; assess_component only needs the validated shape)."""
    return {
        "advisory_id": "test-adv-1",
        "version": "2026-09-30",
        "fetched_at": 1000000,
        "freshness_seconds": 86400,
        "flaws": [
            {"cve": "CVE-2026-102267", "component": "pyjwt",
             "affected": "<2.14.0", "fixed_in": "2.14.0"},
            {"cve": "CVE-2026-101918", "component": "pyjwt",
             "affected": ">=2.0.0", "fixed_in": None},
        ],
    }


def probe_advisory_no_bare_clean():
    """A bare 'clean' verdict must not be expressible: every verdict
    state must be one of affected-by / clean-for / unknown."""
    pinned = _pinned_advisory()
    states = set()
    for version in ("2.13.0", "2.14.0", "9.9.9", "not-a-version"):
        v = _as.assess_component(pinned, "pyjwt", version, 1000000)
        states.add(v["state"])
        if v["state"] == "clean":
            return ("BREAK", "bare 'clean' expressed for %s" % version)
    if states <= {"affected-by", "clean-for", "unknown"}:
        return ("HELD", "states seen %s; no bare clean" % sorted(states))
    return ("BREAK", "unexpected states: %s" % sorted(states))


def probe_advisory_pyjwt_granularity():
    """PyJWT 2.14.0 fixed CVE-2026-102267 but is still affected by
    CVE-2026-101918: the verdict must be affected-by the latter AND
    clean-for the former (the wave-246 motivating example)."""
    v = _as.assess_component(_pinned_advisory(), "pyjwt", "2.14.0",
                             1000000)
    if v["state"] == "affected-by" and \
            "CVE-2026-101918" in v["cves"] and \
            "CVE-2026-102267" in v.get("clean_for", []):
        return ("HELD", "2.14.0 affected-by CVE-2026-101918, clean-for "
                "CVE-2026-102267")
    return ("BREAK", "wrong granularity: %r" % (v,))


def probe_advisory_unknown_component():
    """Untracked component must be explicit unknown (fail-closed),
    never a silent pass."""
    v = _as.assess_component(_pinned_advisory(), "no-such-lib", "1.0.0",
                             1000000)
    if v["state"] == "unknown" and v["reason"] == "component-not-tracked":
        return ("HELD", "untracked component -> unknown "
                "(component-not-tracked)")
    return ("BREAK", "unexpected: %r" % (v,))


# ---------------------------------------------------------------------------
# mcp_discovery_trust probes
# ---------------------------------------------------------------------------

def probe_discovery_identity_mismatch():
    """Forged DNS record claiming a pinned name with a wrong identity
    must be refused loudly."""
    try:
        _mdt.check_discovery(
            {"name": "acme-tools",
             "endpoint": "https://evil.example/mcp",
             "identity": "attacker-key-fingerprint",
             "source": "dns"},
            {"acme-tools": "real-key-fingerprint"})
    except _mdt.McpDiscoveryTrustError as exc:
        if exc.code == "discovery-identity-mismatch":
            return ("HELD", "identity mismatch refused")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "forged identity was ACCEPTED")


def probe_discovery_unpinned():
    """Discovery for a name with no pin must be refused."""
    try:
        _mdt.check_discovery(
            {"name": "unknown-server",
             "endpoint": "https://x.example/mcp",
             "identity": "some-id", "source": "dns"}, {})
    except _mdt.McpDiscoveryTrustError as exc:
        if exc.code == "discovery-unpinned":
            return ("HELD", "unpinned discovery refused")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "unpinned discovery was ACCEPTED")


def probe_discovery_exact_match_accepted():
    """Pinned name + exact identity match must accept (no false
    positive), including at a NEW endpoint (endpoint is a locator)."""
    try:
        r = _mdt.check_discovery(
            {"name": "acme-tools",
             "endpoint": "https://new-host.example/mcp",
             "identity": "real-key-fingerprint", "source": "dns"},
            {"acme-tools": "real-key-fingerprint"})
    except _mdt.McpDiscoveryTrustError as exc:
        return ("BREAK", "valid discovery refused: %s" % exc.code)
    if r["verdict"] == "accept":
        return ("HELD", "exact pin match accepted at new endpoint")
    return ("BREAK", "unexpected: %r" % (r,))


# ---------------------------------------------------------------------------
# identity_crosscheck probes
# ---------------------------------------------------------------------------

def _anchor_and_attestation(principal="agent-7", key_id="anchor-1"):
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    anchor = {"keys": {key_id: pub}}
    att = _ic.make_attestation(seed, key_id, principal)
    return anchor, att


def probe_crosscheck_no_anchor_never_attested():
    """With no verifiable anchor, even a well-formed attestation must
    grade asserted-only, NEVER attested."""
    _anchor, att = _anchor_and_attestation()
    for anchor in (None, {}, {"keys": {}}, {"keys": "nope"}):
        r = _ic.check({"principal": "agent-7"}, att, anchor)
        if r["verdict"] == "attested":
            return ("BREAK",
                    "attested WITHOUT verifiable anchor: %r" % (anchor,))
        if r["verdict"] != "asserted-only":
            return ("BREAK", "unexpected verdict %r for anchor %r"
                    % (r["verdict"], anchor))
    return ("HELD", "no anchor -> asserted-only in all 4 shapes")


def probe_crosscheck_bad_signature_refused():
    """A forged signature must be refused, not downgraded."""
    anchor, att = _anchor_and_attestation()
    bad = dict(att)
    bad["signature"] = b"\x00" * 64
    r = _ic.check({"principal": "agent-7"}, bad, anchor)
    if r["verdict"] == "refused" and \
            r["code"] == "identity-attestation-unverifiable":
        return ("HELD", "forged signature refused")
    return ("BREAK", "bad signature not refused: %r" % (r,))


def probe_crosscheck_principal_mismatch_refused():
    """Anchor vouches agent-7 but peer claims agent-8: refused."""
    anchor, att = _anchor_and_attestation(principal="agent-7")
    r = _ic.check({"principal": "agent-8"}, att, anchor)
    if r["verdict"] == "refused" and \
            r["code"] == "identity-claim-mismatch":
        return ("HELD", "principal mismatch refused")
    return ("BREAK", "mismatch not refused: %r" % (r,))


def probe_crosscheck_valid_attested():
    """Well-formed attestation + provisioned anchor + matching
    principal must grade attested (no false negative)."""
    anchor, att = _anchor_and_attestation()
    r = _ic.check({"principal": "agent-7"}, att, anchor)
    if r["verdict"] == "attested":
        return ("HELD", "valid attestation graded attested")
    return ("BREAK", "valid attestation not attested: %r" % (r,))


# ---------------------------------------------------------------------------
# reputation_ledger probes
# ---------------------------------------------------------------------------

def _two_party_ledger():
    seed_r = bytes(range(32))
    did_r = _ai.resolve(_ed.publickey(seed_r))
    seed_s = bytes([0xA5] * 32)
    did_s = _ai.resolve(_ed.publickey(seed_s))
    ledger = _rl.ReputationLedger()
    e0 = _rl.make_event(0, did_s, did_r, "attestation-positive", "ok",
                        ledger.head_digest())
    ledger.append(_rl.sign_event(e0, seed_r))
    return ledger, seed_r, did_r, did_s


def probe_reputation_tamper_refused():
    """Tamper with an exported entry's kind, re-import: the whole
    chain re-validation must refuse reputation-ledger-tampered."""
    ledger, _seed_r, _did_r, did_s = _two_party_ledger()
    blob = bytearray(ledger.export())
    import json as _json
    data = _json.loads(bytes(blob).decode("utf-8"))
    data["entries"][0]["kind"] = "incident-confirmed"  # tamper!
    try:
        _rl.ReputationLedger.import_bytes(
            _json.dumps(data).encode("utf-8"))
    except _rl.ReputationLedgerError as exc:
        if exc.code == "reputation-ledger-tampered":
            return ("HELD", "tampered export refused on re-import")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "tampered ledger IMPORTED cleanly")


def probe_reputation_forged_reporter_refused():
    """Sign an event with seed A but claim reporter did of B: the
    seed/reporter binding must refuse."""
    _ledger, _seed_r, did_r, did_s = _two_party_ledger()
    seed_evil = bytes([0x5E] * 32)
    event = _rl.make_event(1, did_s, did_r, "incident-confirmed",
                           "framed", "00" * 32)
    try:
        _rl.sign_event(event, seed_evil)
    except _rl.ReputationLedgerError as exc:
        if exc.code == "did-key-binding-invalid":
            return ("HELD", "reporter/seed mismatch refused at sign")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "forged reporter signature was CREATED")


def probe_reputation_reorder_refused():
    """Drop the head entry from a 2-event export and re-import: the
    surviving entry's prev-digest will not match genesis, so the
    chain must refuse reputation-ledger-tampered (silent history
    rewrite is the attack)."""
    seed_r = bytes(range(32))
    did_r = _ai.resolve(_ed.publickey(seed_r))
    seed_s = bytes([0xA5] * 32)
    did_s = _ai.resolve(_ed.publickey(seed_s))
    ledger = _rl.ReputationLedger()
    e0 = _rl.make_event(0, did_s, did_r, "attestation-positive", "ok",
                        ledger.head_digest())
    ledger.append(_rl.sign_event(e0, seed_r))
    e1 = _rl.make_event(1, did_s, did_r, "incident-confirmed", "bad",
                        ledger.head_digest())
    ledger.append(_rl.sign_event(e1, seed_r))
    import json as _json
    data = _json.loads(ledger.export().decode("utf-8"))
    data["entries"] = data["entries"][1:]  # drop the head entry
    try:
        _rl.ReputationLedger.import_bytes(
            _json.dumps(data).encode("utf-8"))
    except _rl.ReputationLedgerError as exc:
        if exc.code == "reputation-ledger-tampered":
            return ("HELD", "truncated export refused on re-import")
        return ("BREAK", "wrong code: %s" % exc.code)
    return ("BREAK", "truncated ledger imported without refusal")


def probe_reputation_score_recomputable():
    """reputation_for must equal the pure compute_reputation over the
    entries (claimed == recomputed, same code path)."""
    ledger, _seed_r, _did_r, did_s = _two_party_ledger()
    a = ledger.reputation_for(did_s)
    b = _rl.compute_reputation(ledger.entries(), did_s)
    if a == b == 1:
        return ("HELD", "claimed == recomputed == 1")
    return ("BREAK", "divergence: %r vs %r" % (a, b))


# ---------------------------------------------------------------------------
# Registry + main
# ---------------------------------------------------------------------------

PROBES = [
    # BREAK probes (expect red until F210 is closed)
    ("breach_forged_verified", probe_breach_forged_verified),
    ("breach_verify_then_mutate", probe_breach_verify_then_mutate),
    # policy_delta_gate
    ("policy_scalar_widening", probe_policy_scalar_widening),
    ("policy_list_widening_refused", probe_policy_list_widening_refused),
    ("policy_forbid_removed_refused", probe_policy_forbid_removed_refused),
    ("policy_effect_weakened_refused", probe_policy_effect_weakened_refused),
    # schema_ref_guard
    ("schema_external_ref", probe_schema_external_ref),
    ("schema_relative_ref", probe_schema_relative_ref),
    ("schema_cycle", probe_schema_cycle),
    ("schema_deep_chain", probe_schema_deep_chain),
    ("schema_budget", probe_schema_budget),
    ("schema_diamond_allowed", probe_schema_diamond_allowed),
    # advisory_state
    ("advisory_no_bare_clean", probe_advisory_no_bare_clean),
    ("advisory_pyjwt_granularity", probe_advisory_pyjwt_granularity),
    ("advisory_unknown_component", probe_advisory_unknown_component),
    # mcp_discovery_trust
    ("discovery_identity_mismatch", probe_discovery_identity_mismatch),
    ("discovery_unpinned", probe_discovery_unpinned),
    ("discovery_exact_match_accepted", probe_discovery_exact_match_accepted),
    # identity_crosscheck
    ("crosscheck_no_anchor_never_attested",
     probe_crosscheck_no_anchor_never_attested),
    ("crosscheck_bad_signature_refused",
     probe_crosscheck_bad_signature_refused),
    ("crosscheck_principal_mismatch_refused",
     probe_crosscheck_principal_mismatch_refused),
    ("crosscheck_valid_attested", probe_crosscheck_valid_attested),
    # reputation_ledger
    ("reputation_tamper_refused", probe_reputation_tamper_refused),
    ("reputation_forged_reporter_refused",
     probe_reputation_forged_reporter_refused),
    ("reputation_reorder_refused", probe_reputation_reorder_refused),
    ("reputation_score_recomputable", probe_reputation_score_recomputable),
]


def main():
    results = [_run(name, fn) for name, fn in PROBES]
    held = sum(1 for _n, v, _e in results if v == "HELD")
    broken = sum(1 for _n, v, _e in results if v == "BREAK")
    errored = sum(1 for _n, v, _e in results if v == "PROBE-ERROR")
    print("w247 red-team: %d probes: %d HELD / %d BREAK / %d PROBE-ERROR"
          % (len(results), held, broken, errored))
    for name, verdict, evidence in results:
        print("[%s] %s: %s" % (verdict, name, evidence))
    # Exit 0: the battery ran correctly. BREAKs are product findings
    # (filed as F210), not battery failures.
    return 0


if __name__ == "__main__":
    sys.exit(main())
