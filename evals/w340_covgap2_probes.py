#!/usr/bin/env python3
"""Wave-340 lane 2 battery: decision-code coverage campaign, round 2
(w337 prospectus R14 continuation).

The R14 coverage table (docs/decision-code-coverage.json) listed 211
uncovered codes at pin 2130 after round 1. This battery asserts the
next 30 most security-critical ones -- denial/binding/refusal codes
on the highest-adversarial-exploitability seams (authority
delegation/grant id-binding, artifact integrity, MCP mapping pins,
axis/revocation, consent tokens, call authz, eval-task pins,
manifest jku, memory keys, per-tool grants, quorum, R3 tokens,
delegation eligibility, agent cards, egress wall proofs) -- with real
behavioral probes (the hostile input is driven through the public
seam and the coded refusal is asserted), never tautologies:

  G1  capability grants: grant-decision-mismatch, delegation-decision-mismatch
  G2  artifact sweep: integrity_violation (+ clean-sweep control)
  G3  mcp invocation authz: mapping-drift (+ pinned-match control)
  G4  axis model: axis-invalid, revocation-state-unknown, revocation-category-error
  G5  platform egress: consent_invalid
  G6  call enforcement: callauthz-not-configured, callauthz-check-error
  G7  eval tasks: evaltask-dataset-changed, evaltask-grader-changed,
      evaltask-target-crashed, evaltask-unverifiable
  G8  capability manifests: jku-not-allowed
  G9  memory composed: memory-composed-key-invalid
  G10 per-tool grants: ptgrant-issuer-unknown, ptgrant-cnf-missing,
      ptgrant-attenuation-invalid
  G11 quorum policy: quorum-not-met
  G12 aauth R3: r3-unknown-operation, r3-grant-beyond-document,
      r3-s256-mismatch, r3-grant-hash-mismatch, r3-per-call-binding-broken
  G13 authority delegation store: wrong_run_identity, bad_delegatee,
      unknown_delegatee_agent
  G14 agent cards: malformed-signature-entry
  G15 egress launcher: wall_proof_unreadable
  P0  pin/taxonomy honesty (2130/2130/0 sorted-unique, footer state).
  PZ  green check (depth-1): adjacent suites as children with
      GOV_SKIP_GREEN=1.

Base: 9351ab86 (wave-339 merge). Pin 2130, footer open F427 / next
F428. No gov/ changes in this lane. Findings: none filed (all probes
HELD on the base; a genuine BREAK would have been filed as F428+).

Deterministic: fresh random/fixed keys per run; no assertion depends on
key material or wall-clock time (all times are injected).
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

TAXONOMY_PIN = 2130  # Wave-339 merge (9351ab86). Footer: open F427 / next F428.

_results = []


def _held(pid, note):
    _results.append((pid, "HELD", note))


def _break(pid, note):
    _results.append((pid, "BREAK", note))


def _error(pid, note):
    _results.append((pid, "ERROR", note))


def _code_of(exc):
    """Extract the coded refusal from the exception, or None."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    msg = str(exc)
    # Coded refusals that embed the code at the message head
    # (e.g. "quorum-not-met: ...", "consent_invalid: ...",
    # "wall_proof_unreadable: ...", "malformed-signature-entry: ...").
    head = msg.split(":", 1)[0].strip()
    if head and ("_" in head or "-" in head):
        return head
    return None


class _CodedRefusal(Exception):
    """Probe-side marker: the refusal trail already carried the code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _refuse_probe(pid, code, fn):
    """Probe one coded refusal: fn() must raise with the exact code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = _code_of(exc)
        if got == code:
            _held(pid, "refused coded %s" % code)
        else:
            _break(pid, "wrong refusal: %r, want %r"
                   % (str(exc)[:140], code))
    else:
        _break(pid, "hostile input was NOT refused")


# ----------------------------------------------------------------------
# G1: capability grant id-binding (gov/capability_grants.py)
# ----------------------------------------------------------------------

def run_g1_probes():
    from gov.capability_grants import (Capability, GrantRefused, GrantSet,
                                      GrantRegistry)

    def _reg():
        reg = GrantRegistry()
        gs = reg.mint([Capability("file", "/x", {"read"})],
                      decision_id="decision-A")
        return reg, gs

    def _mismatch():
        reg, gs = _reg()
        try:
            reg.consume(gs.grant_id, decision_id="decision-B")
        except GrantRefused:
            # The refusal trail must carry the machine code, not just
            # the exception text: auditors query the trail.
            if not reg.refusals or \
                    reg.refusals[-1].get("reason") != \
                    "grant-decision-mismatch":
                raise AssertionError(
                    "refusal trail missing grant-decision-mismatch")
            raise _CodedRefusal("grant-decision-mismatch")

    _refuse_probe("G1a", "grant-decision-mismatch", _mismatch)

    def _delegation_mismatch():
        reg, gs = _reg()
        sub = GrantSet([Capability("file", "/x", {"read"})])
        try:
            reg.register_subset(gs.grant_id, sub, decision_id="decision-B")
        except GrantRefused:
            if not reg.refusals or \
                    reg.refusals[-1].get("reason") != \
                    "delegation-decision-mismatch":
                raise AssertionError(
                    "refusal trail missing delegation-decision-mismatch")
            raise _CodedRefusal("delegation-decision-mismatch")

    _refuse_probe("G1b", "delegation-decision-mismatch", _delegation_mismatch)

    # Control: same-decision consume succeeds.
    try:
        reg, gs = _reg()
        got = reg.consume(gs.grant_id, decision_id="decision-A")
        if got is not None:
            _held("G10", "control: same-decision consume succeeds")
        else:
            _break("G10", "control: consume returned None")
    except Exception as exc:  # noqa: BLE001
        _error("G10", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# G2: artifact integrity sweep (gov/artifact_sweep.py)
# ----------------------------------------------------------------------

def run_g2_probes():
    from gov import artifact_sweep
    from gov.artifacts import ArtifactInventory

    tmp = tempfile.mkdtemp(prefix="g2-")
    watch = os.path.join(tmp, "watch")
    run_dir = os.path.join(tmp, "run")
    os.makedirs(watch)
    os.makedirs(run_dir)
    target = os.path.join(watch, "tool.py")
    with open(target, "w", encoding="utf-8") as f:
        f.write("clean bytes\n")
    baseline = artifact_sweep.register_watch_root(watch, ArtifactInventory())
    # Hostile act: modify the watched file AFTER the baseline snapshot.
    with open(target, "w", encoding="utf-8") as f:
        f.write("TAMPERED bytes\n")
    findings, stats = artifact_sweep.sweep_run_dir(
        run_dir, ArtifactInventory(), watch_roots=[(watch, baseline)])
    kinds = {f.get("kind") for f in findings}
    if "integrity_violation" in kinds:
        _held("G2a", "integrity_violation: tampered file detected")
    else:
        _break("G2a", "tamper NOT detected; kinds=%r" % (sorted(kinds),))

    # Control: an untampered sweep reports no integrity violation.
    watch2 = os.path.join(tmp, "watch2")
    os.makedirs(watch2)
    with open(os.path.join(watch2, "ok.py"), "w",
              encoding="utf-8") as f:
        f.write("clean bytes\n")
    base2 = artifact_sweep.register_watch_root(watch2, ArtifactInventory())
    findings2, _ = artifact_sweep.sweep_run_dir(
        os.path.join(tmp, "run2"), ArtifactInventory(),
        watch_roots=[(watch2, base2)])
    if not any(f.get("kind") == "integrity_violation"
               for f in findings2):
        _held("G20", "control: clean sweep, no violation")
    else:
        _break("G20", "control: clean sweep flagged a violation")


# ----------------------------------------------------------------------
# G3: MCP mapping pin (gov/mcp_invocation_authz.py)
# ----------------------------------------------------------------------

def run_g3_probes():
    from gov import mcp_invocation_authz as mia

    pin = mia.canonical_digest({"tools": ["a"]})
    policy = mia.build_policy({"subject_id": "agent-1",
                               "pinned_mapping_digest": pin})
    msg = {"method": "tools/call", "params": {}, "id": 1}
    # Hostile act: the server advertises a mapping that drifted from
    # the out-of-band pin (an extra tool the deployment never saw).
    ctx = {"subject": {"id": "agent-1"},
           "server_mapping": {"tools": ["a", "EVIL"]}}
    res = mia.authorize(policy, msg, ctx)
    if res.verdict == "refuse" and res.code == "mapping-drift":
        _held("G3a", "mapping-drift: drifted server mapping refused")
    else:
        _break("G3a", "drift NOT refused: %r %r"
               % (res.verdict, res.code))

    # Control: the pinned mapping authorizes.
    ctx2 = {"subject": {"id": "agent-1"},
            "server_mapping": {"tools": ["a"]}}
    res2 = mia.authorize(policy, msg, ctx2)
    if res2.verdict == "permit":
        _held("G30", "control: pinned mapping permits")
    else:
        _break("G30", "control: pinned mapping refused %r" % (res2.code,))


# ----------------------------------------------------------------------
# G4: axis model + revocation (gov/axis_result_model.py)
# ----------------------------------------------------------------------

def run_g4_probes():
    from gov import axis_result_model as arm

    def _invalid_chain():
        arm.require_valid(arm.aggregate(
            [arm.AxisVerdict("sig", arm.INVALID, "bad-signature")]))

    _refuse_probe("G4a", "axis-invalid", _invalid_chain)

    # revocation-state-unknown is a non-raising classification: the
    # outcome carries the code and is_active stays False.
    out = arm.check_revocation("active", "unknown")
    if out.code == "revocation-state-unknown" and out.is_active is False:
        _held("G4b", "revocation-state-unknown: unknown is not active")
    else:
        _break("G4b", "misclassified: code=%r active=%r"
               % (out.code, out.is_active))

    def _category_error():
        arm.check_revocation("revoked", "suspended")

    _refuse_probe("G4c", "revocation-category-error", _category_error)

    # Control: active/active is positively active.
    out2 = arm.check_revocation("active", "active")
    if out2.is_active is True:
        _held("G40", "control: active/active is active")
    else:
        _break("G40", "control: active/active misclassified")

# ----------------------------------------------------------------------
# G5: consent token MAC binding (gov/platform_egress.py)
# ----------------------------------------------------------------------

def run_g5_probes():
    from gov import platform_egress as pe

    k1 = hashlib.sha256(b"g5-key-1").digest()
    k2 = hashlib.sha256(b"g5-key-2").digest()
    token = pe.issue_consent([], k1, granted_by="operator",
                             ttl_s=3600, destination="https://dst.example")

    def _wrong_key():
        pe.check_consent(token, k2, scope=pe.SCOPE_WORKSPACE_COLLECT,
                         destination="https://dst.example")

    _refuse_probe("G5a", "consent_invalid", _wrong_key)

    # Control: the right key with the right destination validates.
    try:
        got = pe.check_consent(token, k1, scope=pe.SCOPE_WORKSPACE_COLLECT,
                               destination="https://dst.example")
        if got.get("token_id", "").startswith("pec-"):
            _held("G50", "control: valid consent token accepted")
        else:
            _break("G50", "control: unexpected token %r" % (got,))
    except Exception as exc:  # noqa: BLE001
        _error("G50", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# G6: call enforcement (gov/call_enforcement.py)
# ----------------------------------------------------------------------

def run_g6_probes():
    from gov import call_enforcement as ce

    # Hostile act: no policy authorizes the call at all -- the
    # fail-closed posture must deny rather than allow by default.
    verdict = ce.CallEnforcer().enforce(
        ce.CheckRequest("agent-1", "x", "y"))
    if verdict.code == "callauthz-not-configured" and not verdict.allow:
        _held("G6a", "callauthz-not-configured: unconfigured call denied")
    else:
        _break("G6a", "mis-verdict: allow=%r code=%r"
               % (verdict.allow, verdict.code))

    # Hostile act: the policy's check contract is broken (returns a
    # non-verdict) -- a malformed check must deny, never crash through.
    enforcer = ce.CallEnforcer()
    enforcer.register_policy(ce.ScopedPolicy(
        "p1", "*", "*", check=lambda req: "not-a-verdict"))
    verdict2 = enforcer.enforce(ce.CheckRequest("agent-1", "x", "y"))
    if verdict2.code == "callauthz-check-error" and not verdict2.allow:
        _held("G6b", "callauthz-check-error: broken check denied")
    else:
        _break("G6b", "mis-verdict: allow=%r code=%r"
               % (verdict2.allow, verdict2.code))


# ----------------------------------------------------------------------
# G7: eval-task pins (gov/eval_tasks.py)
# ----------------------------------------------------------------------

def _g7_scorer(sample, output):
    return 1.0


def run_g7_probes():
    from gov import eval_tasks as et

    def _reg():
        reg = et.EvalTaskRegistry()
        reg.register_dataset("d", [{"q": "a"}])
        reg.register_scoring_function("s", _g7_scorer)
        reg.register_eval_task("t", dataset_id="d",
                               scoring_ids=["s"])
        return reg

    def _dataset_changed():
        reg = _reg()
        # Hostile act: the dataset artifact is swapped after the task
        # declaration pinned it (the record digest no longer matches).
        reg._datasets["d"]["dataset_digest"] = "0" * 64
        et.run_eval_task(reg, "t", target=lambda s: "o")

    _refuse_probe("G7a", "evaltask-dataset-changed", _dataset_changed)

    def _grader_changed():
        reg = _reg()
        # Hostile act: the scoring function is swapped after pinning.
        reg._scoring["s"]["digest"] = "0" * 64
        et.run_eval_task(reg, "t", target=lambda s: "o")

    _refuse_probe("G7b", "evaltask-grader-changed", _grader_changed)

    def _target_crashed():
        reg = _reg()

        def _boom(sample):
            raise RuntimeError("target exploded")

        et.run_eval_task(reg, "t", target=_boom)

    _refuse_probe("G7c", "evaltask-target-crashed", _target_crashed)

    def _unverifiable():
        et.eval_task_evidence_package({"bogus": "not a result"})

    _refuse_probe("G7d", "evaltask-unverifiable", _unverifiable)

    # Control: a clean run produces a verifiable result.
    try:
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: "o")
        if et.verify_eval_result(res):
            _held("G70", "control: clean eval run verifies")
        else:
            _break("G70", "control: clean result did not verify")
    except Exception as exc:  # noqa: BLE001
        _error("G70", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# G8: manifest jku refusal (gov/capability_manifests.py)
# ----------------------------------------------------------------------

def run_g8_probes():
    import base64 as _b64
    from gov import capability_manifests as cm
    from gov import ed25519

    seed = hashlib.sha256(b"g8-key").digest()
    pub = ed25519.publickey(seed)
    store = cm.ManifestStore(keys={"k1": pub})

    def _b64u(obj):
        raw = json.dumps(obj).encode("utf-8") \
            if not isinstance(obj, bytes) else obj
        return _b64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    # Hostile act: a manifest signature header carries a jku URL --
    # key discovery is never performed; the deployment pin wins.
    manifest = {
        "skill_id": "evil-skill",
        "signatures": [{
            "protected": _b64u({"alg": "EdDSA",
                                "jku": "https://evil.example/keys.json"}),
            "signature": _b64u(b"fakesig"),
        }],
    }

    def _jku():
        cm.verify_manifest(manifest, store, threshold=1)

    _refuse_probe("G8a", "jku-not-allowed", _jku)


# ----------------------------------------------------------------------
# G9: memory composed key grammar (gov/memory_composed.py)
# ----------------------------------------------------------------------

def run_g9_probes():
    from gov import ed25519
    from gov import memory_reconcile as mr
    from gov import memory_store as ms
    from gov import memory_composed as mc

    def _seed(tag):
        return hashlib.sha256(b"g9:" + tag.encode()).digest()

    def _setup():
        r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                                max_writes_per_principal=10000,
                                write_window_seconds=3600)
        owner_seed = _seed("owner-a")
        r.declare_namespace("agent-a",
                            ed25519.publickey(owner_seed).hex())
        store = ms.MemoryStore()
        comp = mc.MemoryComposer(r, {"agent-a": owner_seed})
        comp.bind_store("agent-a", store)
        return comp, owner_seed, store

    def _candidate(owner_seed, key):
        vd = hashlib.sha256(b"dark").hexdigest()
        cand = {"schema": "memory-record/v1", "namespace": "agent-a",
                "key": key, "value_digest": vd, "written_at": 1000,
                "supersedes": None,
                "provenance": {"source_principal": "agent-a",
                               "reliability": "C3", "corroborations": 0,
                               "ingested_at": 1000},
                "expires_at": None, "op": "add"}
        body = {k: cand[k] for k in
                ("schema", "namespace", "key", "value_digest",
                 "written_at", "supersedes", "provenance",
                 "expires_at", "op")}
        cand["signature"] = ed25519.sign(
            owner_seed, json.dumps(body, sort_keys=True,
                                  separators=(",", ":"),
                                  ensure_ascii=True).encode()).hex()
        return cand

    def _bad_key():
        comp, owner_seed, store = _setup()
        # Hostile act: an out-of-grammar key (uppercase + bang) that a
        # downstream consumer might parse differently than the store.
        comp.composed_write("agent-a",
                            _candidate(owner_seed, "EVIL KEY!"),
                            store, {}, 1000)

    _refuse_probe("G9a", "memory-composed-key-invalid", _bad_key)

    # Control: a grammar-conforming key is accepted past the key gate.
    try:
        comp, owner_seed, store = _setup()
        out = comp.composed_write("agent-a",
                                  _candidate(owner_seed,
                                             "user-preference-theme"),
                                  store, {}, 1000)
        if out.get("store_key"):
            _held("G90", "control: conforming key writes")
        else:
            _break("G90", "control: write returned no store_key")
    except Exception as exc:  # noqa: BLE001
        _error("G90", "control errored: %s" % (exc,))

# ----------------------------------------------------------------------
# G10: per-tool grants (gov/tool_grant.py)
# ----------------------------------------------------------------------

_ISS_SEED = bytes.fromhex("11" * 32)
_HOLDER_SEED = bytes.fromhex("22" * 32)
_NOW = 1790000000
_AUD = "https://mcp.example.internal/fileserver"
_SUB = "spiffe://trust-domain/ns/prod/sa/agent-7"
_LINK = "sha256:" + "ab" * 32


def _g10_issuer():
    from gov import tool_grant
    return tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=_ISS_SEED,
                             mandate_lookup=lambda m: {"version": 7})


def _g10_details():
    return [{
        "type": "https://sasanam.dev/mcp_tool_call",
        "locations": [_AUD],
        "actions": ["call"],
        "identifier": "fileserver::read_file",
        "arg_bounds": {"path": {"predicate": "prefix",
                                "params": {"prefix": "/data/shared/"}}},
        "supply_chain": {"link_digest": _LINK, "delegation_ok": True},
        "max_calls": 3,
    }]


def run_g10_probes():
    from gov import ed25519, tool_grant

    def _unknown_issuer():
        # Hostile act: a grant minted under an issuer name the
        # deployment never registered.
        tool_grant.Issuer(iss="https://evil-issuer.example",
                          issuer_seed=_ISS_SEED,
                          mandate_lookup=lambda m: {"version": 7})

    _refuse_probe("G10a", "ptgrant-issuer-unknown", _unknown_issuer)

    def _cnf_missing():
        # Hostile act: a grant minted without the workload proof key
        # binding (a Bearer <redacted> the holder never proved possession of).
        _g10_issuer().issue(
            sub=_SUB, aud=_AUD, proof_pub=b"too-short-not-32-bytes",
            mandate_id="mnd_1", mandate_version=7, details=_g10_details(),
            lifetime_s=600, now=_NOW)

    _refuse_probe("G10b", "ptgrant-cnf-missing", _cnf_missing)

    def _bad_attenuation():
        from gov.tool_grant import GrantError
        g = _g10_issuer().issue(
            sub=_SUB, aud=_AUD,
            proof_pub=ed25519.publickey(_HOLDER_SEED),
            mandate_id="mnd_1", mandate_version=7, details=_g10_details(),
            lifetime_s=600, now=_NOW)
        holder_pub = ed25519.publickey(_HOLDER_SEED)
        # Hostile act: an attenuation record whose signature does not
        # verify under the grant's cnf key (a forged caveat chain).
        forged = {"predicate": "max_calls", "params": {"max_calls": 1},
                  "by": tool_grant._b64(holder_pub),
                  "prev": g["sig"],
                  "sig": tool_grant._b64(b"\xde\xad" * 32)}
        g2 = {"body": g["body"], "sig": g["sig"],
              "attenuation": [forged]}
        proof = tool_grant.make_pop_proof(_HOLDER_SEED, g, method="tools/call",
                                          uri=_AUD + "/tools/call",
                                          now=_NOW, nonce="u1")
        verdict = tool_grant.enforce(
            g2, proof=proof,
            issuer_pub=ed25519.publickey(_ISS_SEED),
            server_name="fileserver", server_uri=_AUD, tool="read_file",
            args={"path": "/data/shared/a.txt"}, now=_NOW,
            usage_store=tool_grant.UsageStore(),
            mandate_version_provider=lambda m: 7,
            link_verifier=lambda t: _LINK)
        if verdict.get("ok") is not False or \
                verdict.get("code") != "ptgrant-attenuation-invalid":
            raise AssertionError("forged attenuation not refused coded: %r"
                                 % (verdict,))
        raise _CodedRefusal("ptgrant-attenuation-invalid")

    _refuse_probe("G10c", "ptgrant-attenuation-invalid", _bad_attenuation)

    # Control: an honest grant enforces without the attenuation code.
    try:
        g = _g10_issuer().issue(
            sub=_SUB, aud=_AUD,
            proof_pub=ed25519.publickey(_HOLDER_SEED),
            mandate_id="mnd_1", mandate_version=7, details=_g10_details(),
            lifetime_s=600, now=_NOW)
        proof = tool_grant.make_pop_proof(_HOLDER_SEED, g, method="tools/call",
                                          uri=_AUD + "/tools/call",
                                          now=_NOW, nonce="u2")
        verdict = tool_grant.enforce(
            g, proof=proof,
            issuer_pub=ed25519.publickey(_ISS_SEED),
            server_name="fileserver", server_uri=_AUD, tool="read_file",
            args={"path": "/data/shared/a.txt"}, now=_NOW,
            usage_store=tool_grant.UsageStore(),
            mandate_version_provider=lambda m: 7,
            link_verifier=lambda t: _LINK)
        if verdict.get("code") != "ptgrant-attenuation-invalid":
            _held("G100", "control: honest grant avoids attenuation code")
        else:
            _break("G100", "control: honest grant hit attenuation code")
    except Exception as exc:  # noqa: BLE001
        _error("G100", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# G11: quorum shortfall (gov/quorum_policy.py)
# ----------------------------------------------------------------------

def run_g11_probes():
    from gov import quorum_policy as qp
    from gov.signing import Ed25519Signer, Ed25519Verifier

    seeds = [bytes.fromhex(h * 32)
             for h in ("a1", "b2", "c3")]
    signers = [Ed25519Signer(s) for s in seeds]
    keyset = {sg.key_id: Ed25519Verifier(sg.public_key) for sg in signers}
    dx = hashlib.sha256(b"fact-X").hexdigest()
    dy = hashlib.sha256(b"fact-Y").hexdigest()
    step = qp.QuorumStep("deploy",
                         [s.key_id for s in signers], 3)

    def _shortfall():
        # Hostile act: functionaries disagree -- no digest group
        # reaches threshold, so no fact is silently picked.
        recs = [qp.make_link_record("deploy", dx, signers[0]),
                qp.make_link_record("deploy", dy, signers[1])]
        qp.verify_quorum(step, recs, keyset)

    _refuse_probe("G11a", "quorum-not-met", _shortfall)

    # Control: a unanimous group verifies.
    try:
        recs = [qp.make_link_record("deploy", dx, s) for s in signers]
        rep = qp.verify_quorum(step, recs, keyset)
        if rep.get("statement_digest") == dx:
            _held("G110", "control: unanimous quorum verifies")
        else:
            _break("G110", "control: unexpected report %r" % (rep,))
    except Exception as exc:  # noqa: BLE001
        _error("G110", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# G12: aauth R3 tokens (gov/aauth_r3.py)
# ----------------------------------------------------------------------

_R3_VOCAB = "urn:aauth:vocabulary:mcp"


def _g12_doc(*ops):
    return {"vocabulary": _R3_VOCAB, "operations": list(ops)}


def run_g12_probes():
    from gov import aauth_r3 as r3

    op_read = {"tool": "read_file", "server": "files"}
    op_write = {"tool": "write_file", "server": "files"}

    def _unknown_op():
        # Hostile act: an operation carrying a field outside the
        # closed vocabulary (smuggled parameter).
        r3.validate_operation(_R3_VOCAB,
                              {"tool": "read_file", "evil_field": "1"})

    _refuse_probe("G12a", "r3-unknown-operation", _unknown_op)

    def _beyond_doc():
        # Hostile act: the grant authorizes an operation the R3
        # document never defined (issuer tries to widen).
        r3.issue_grant_token(_g12_doc(op_read), granted=[op_write],
                             r3_uri="https://issuer.example/r3")

    _refuse_probe("G12b", "r3-grant-beyond-document", _beyond_doc)

    def _s256_mismatch():
        tok = r3.issue_grant_token(_g12_doc(op_read),
                                   granted=[op_read],
                                   r3_uri="https://issuer.example/r3")
        # Hostile act: present the token against a DIFFERENT document
        # (document swap under a stolen token).
        r3.verify_token(tok, _g12_doc(op_read, op_write))

    _refuse_probe("G12c", "r3-s256-mismatch", _s256_mismatch)

    def _grant_hash_mismatch():
        tok = r3.issue_grant_token(_g12_doc(op_read),
                                   granted=[op_read],
                                   r3_uri="https://issuer.example/r3")
        # Hostile act: edit the token's grant list after issuance.
        tok = dict(tok)
        tok["r3_granted"] = [op_read, op_write]
        r3.verify_token(tok, _g12_doc(op_read))

    _refuse_probe("G12d", "r3-grant-hash-mismatch", _grant_hash_mismatch)

    def _binding_broken():
        # Hostile act: the challenged call's parameters differ from
        # the content-addressed proposal the approval bound.
        tok = r3.issue_per_call_token(_g12_doc(op_read), op_read,
                                      r3_uri="https://issuer.example/r3")
        proposal = _g12_doc(op_read)
        r3.challenge_per_call(tok, proposal,
                              {"tool": "read_file", "server": "files",
                               "arguments": "extra-param-added"})

    _refuse_probe("G12e", "r3-per-call-binding-broken", _binding_broken)

    # Control: an honest token verifies and serves.
    try:
        tok = r3.issue_grant_token(_g12_doc(op_read),
                                   granted=[op_read],
                                   r3_uri="https://issuer.example/r3")
        out = r3.check_access(tok, _g12_doc(op_read), dict(op_read))
        if out == r3.SERVE:
            _held("G120", "control: honest token serves")
        else:
            _break("G120", "control: unexpected outcome %r" % (out,))
    except Exception as exc:  # noqa: BLE001
        _error("G120", "control errored: %s" % (exc,))

# ----------------------------------------------------------------------
# G13: authority-delegation eligibility (gov/approvals.py)
# ----------------------------------------------------------------------

_DEL_CFG = {"enabled": True, "default_ttl_minutes": 60,
            "max_ttl_minutes": 240, "max_depth": 1,
            "require_provisioned_for": [],
            "unscoped_delegation": "flag"}


def run_g13_probes():
    from gov.approvals import DelegationStore, DelegationError
    from gov.identity import AgentIdentity

    def _store(run_name, known=None):
        run_dir = tempfile.mkdtemp(prefix="g13-") + "/" + run_name
        return DelegationStore(run_dir, [], config=dict(_DEL_CFG),
                               known_agent_ids=known)

    def _wrong_run():
        # Hostile act: an identity minted in run-OTHER tries to mint
        # authority in run-1 -- cross-run grant laundering.
        store = _store("run-1")
        ident = AgentIdentity("scout-1", "scout", "run-OTHER",
                              "operator")
        store.delegate_grant(ident, "worker-1",
                             {"tools": ["write_file"]})

    _refuse_probe("G13a", "wrong_run_identity", _wrong_run)

    def _bad_delegatee():
        # Hostile act: an empty/blank delegatee (grant to nobody =
        # grant to anybody who asks).
        store = _store("run-2")
        ident = AgentIdentity("scout-1", "scout", "run-2", "operator")
        store.delegate_grant(ident, "   ", {"tools": ["write_file"]})

    _refuse_probe("G13b", "bad_delegatee", _bad_delegatee)

    def _unknown_agent():
        # Hostile act: delegating to an agent id the run never
        # registered (a phantom worker invented by the attacker).
        store = _store("run-3", known={"worker-1"})
        ident = AgentIdentity("scout-1", "scout", "run-3", "operator")
        store.delegate_grant(ident, "attacker-x",
                             {"tools": ["write_file"]})

    _refuse_probe("G13c", "unknown_delegatee_agent", _unknown_agent)


# ----------------------------------------------------------------------
# G14: agent-card signature entry shape (gov/agent_cards.py)
# ----------------------------------------------------------------------

def run_g14_probes():
    from gov import agent_cards as ac
    from gov import ed25519

    seed = hashlib.sha256(b"g14-key").digest()
    pub = ed25519.publickey(seed)
    store = ac.CardTrustStore(
        keys={"k1": {"pubkey": pub, "alg": "EdDSA", "fetched_at": 0}})
    card = {"agent_id": "a", "name": "n", "version": "1",
            "capabilities": [], "endpoints": {},
            "keys": [{"kid": "k1"}], "a2a_version": "1.0",
            "expires": 1790003600,
            # Hostile act: a non-object signature entry -- a parser
            # that skipped this check could misattribute signatures.
            "signatures": ["not-an-object"]}

    def _malformed_entry():
        ac.verify_card(card, store, now=1790000000)

    _refuse_probe("G14a", "malformed-signature-entry", _malformed_entry)


# ----------------------------------------------------------------------
# G15: egress wall-proof readability (gov/egress_launcher.py)
# ----------------------------------------------------------------------

def run_g15_probes():
    from gov import egress_launcher as el

    missing = os.path.join(tempfile.mkdtemp(prefix="g15-"),
                           "nonexistent")
    launcher = el.FilteredEgressLauncher(
        manifest_path=os.path.join(missing, "manifest.json"),
        receipt_path=os.path.join(missing, "receipt.json"),
        wall_provider=None)

    def _unreadable():
        # Hostile act: the launch-time wall proof files are missing
        # (deleted or never written) -- the launch audit must refuse
        # rather than bind an unverifiable launch.
        launcher._wall_proof()

    _refuse_probe("G15a", "wall_proof_unreadable", _unreadable)


# ----------------------------------------------------------------------
# P0: pin + taxonomy + footer honesty
# ----------------------------------------------------------------------

def run_pin_footer_probes():
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(lits) == TAXONOMY_PIN == 2130 and len(set(lits)) == 2130 \
            and lits == sorted(lits):
        _held("P0a", "taxonomy 2130/2130/0 sorted-unique literals")
    else:
        _break("P0a", "literals %d, unique %d, sorted=%s"
               % (len(lits), len(set(lits)), lits == sorted(lits)))
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    if "Open findings: F427." in text \
            and "Next free finding: **F428**" in text:
        _held("P0b", "footer open F427 / next F428")
    else:
        _break("P0b", "footer text mismatch")


_EXPECTED_BREAKS = set()


def green_check():
    """Depth-1 green check: adjacent suites as children with
    GOV_SKIP_GREEN=1. Honored skip: records a skipped note."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _held("PZ", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    children = [
        ["-m", "unittest", "tests.test_tool_grant", "-v"],
        ["-m", "unittest", "tests.test_artifact_sweep", "-v"],
        ["-m", "unittest", "tests.test_quorum_policy", "-v"],
        ["-m", "unittest", "tests.test_delegation_primitive", "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for child in children:
        proc = subprocess.run(
            [sys.executable] + child,
            cwd=REPO, env=env,
            capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            _break("PZ", "child %s red:\n%s"
                   % (child, proc.stdout[-800:] + proc.stderr[-800:]))
            return
    _held("PZ", "adjacent children green")


def main():
    for runner in (run_g1_probes, run_g2_probes, run_g3_probes,
                   run_g4_probes, run_g5_probes, run_g6_probes,
                   run_g7_probes, run_g8_probes, run_g9_probes,
                   run_g10_probes, run_g11_probes, run_g12_probes,
                   run_g13_probes, run_g14_probes, run_g15_probes,
                   run_pin_footer_probes):
        try:
            runner()
        except Exception:  # noqa: BLE001
            _error(runner.__name__,
                   "harness failure:\n%s" % traceback.format_exc()[-600:])
    try:
        green_check()
    except Exception:  # noqa: BLE001
        _error("PZ", "green check errored:\n%s"
               % traceback.format_exc()[-600:])

    breaks = {p for p, v, _ in _results if v == "BREAK"}
    errors = {p for p, v, _ in _results if v == "ERROR"}
    n_break, n_held, n_err = (sum(1 for _p, v, _n in _results if v == k)
                              for k in ("BREAK", "HELD", "ERROR"))
    print("w340_covgap2: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for pid, verdict, note in _results:
        if verdict != "HELD":
            print("  %s %s: %s" % (pid, verdict, note[:220]))
    if breaks ^ _EXPECTED_BREAKS or errors:
        print("MISMATCH: breaks=%s errors=%s expected=%s"
              % (sorted(breaks), sorted(errors),
                 sorted(_EXPECTED_BREAKS)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
