"""Wave-287 lane 7 red-first battery: BuildKit-pattern provenance claims.

Base: wave-286 push 8c811375d504371c448d6440b6f80ce9622eb0c5. The gap
under test is provenance for evidence bundles: the wave-285 tessera
lane anchors bundle digests and the wave-286 CCF lane wraps them in
offline receipts, but nothing records WHAT BUILT the bundle -- the
moby/buildkit (Apache-2.0, pattern only -- clean-room stdlib Python
reimplementation of the SLSA predicate SHAPE and the honesty
discipline; no BuildKit code vendored) mechanisms: the SLSA
provenance predicate shape (materials identified by digest, explicit
completeness marking, unverified inputs LOUDLY marked), the
builder-identity allowlist, and the verifier-side fail-closed policy.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (secrets only for random key
material, never asserted on). Stdlib only, no in-repo git
subprocesses.
"""

import copy
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w287-provenance")
os.environ.setdefault("TMPDIR", "/var/tmp/g287-provenance")
_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("GOV_BATTERY_REPO") or os.path.dirname(_HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

# Wave-287 lane 7: pin 1660 -> 1667 (+7 evidence-provenance codes).; Wave-287 merge: pin 1667 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*)
TAXONOMY_PIN = 1967 # wave-290 lane 6: 1706 -> 1710; Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append((probe_id, verdict, note))


def _needs_module(probe_id):
    try:
        from gov import evidence_provenance as ep
        return ep
    except ImportError:
        _record(probe_id, "BREAK", "gov.evidence_provenance absent on base")
        return None


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _builder(ep):
    """A (seed, keyid, BuilderPolicy) fixture trio."""
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    bid = "build.example.com/ci"
    policy = ep.BuilderPolicy("auditor-pin-1", {bid: pub})
    return seed, "key-1", policy


def _claim(ep, seed, keyid, artifact=None, materials=None):
    artifact = artifact or "ab" * 32
    materials = materials if materials is not None else [
        {"uri": "https://git.example.com/repo",
         "digest": "cd" * 32, "completeness": "verified"},
    ]
    claim = ep.make_provenance_claim("build.example.com/ci", keyid,
                                     artifact, materials,
                                     issued_at=1700000000)
    return ep.seal_provenance(claim, seed), artifact


# -- capability probes ------------------------------------------------

def p_module_present():
    ep = _needs_module("p-module-present")
    if ep is not None:
        _record("p-module-present", "HELD",
                "gov.evidence_provenance imports")


def p_claim_roundtrip():
    ep = _needs_module("p-claim-roundtrip")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    try:
        ok = ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        _record("p-claim-roundtrip", "BREAK",
                "valid claim refused: %s" % (e,))
        return
    if ok is not True:
        _record("p-claim-roundtrip", "BREAK", "verify did not return True")
        return
    _record("p-claim-roundtrip", "HELD",
            "sealed claim verifies under the pinned builder key")


def p_allowlist_enforced():
    ep = _needs_module("p-allowlist-enforced")
    if ep is None:
        return
    from gov import ed25519
    seed, _keyid, policy = _builder(ep)
    # A foreign builder, validly signed by ITS OWN key, still refuses:
    # claims are checked, not made true.
    evil_seed = ed25519.generate_seed()
    claim = ep.make_provenance_claim("evil.example.com/x", "key-9",
                                     "ab" * 32,
                                     [{"uri": "u", "digest": "cd" * 32,
                                       "completeness": "verified"}],
                                     issued_at=1700000000)
    env = ep.seal_provenance(claim, evil_seed)
    try:
        ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-builder-untrusted":
            _record("p-allowlist-enforced", "HELD",
                    "foreign builder refused: %s" % (code,))
        else:
            _record("p-allowlist-enforced", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-allowlist-enforced", "BREAK",
            "foreign builder claim accepted")


def p_unsigned_refused():
    ep = _needs_module("p-unsigned-refused")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    env = dict(env)
    env["signature"] = "00" * 64
    try:
        ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-signature-invalid":
            _record("p-unsigned-refused", "HELD",
                    "unsigned-isn't-evidence: %s" % (code,))
        else:
            _record("p-unsigned-refused", "BREAK", "wrong code: %s"
                    % (code,))
        return
    _record("p-unsigned-refused", "BREAK",
            "forged signature accepted")


def p_tamper_breaks_signature():
    ep = _needs_module("p-tamper-breaks-signature")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    env = copy.deepcopy(env)
    env["provenance"]["materials"][0]["digest"] = "ee" * 32
    try:
        ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-signature-invalid":
            _record("p-tamper-breaks-signature", "HELD",
                    "input-digest tampering trips the signature: %s"
                    % (code,))
        else:
            _record("p-tamper-breaks-signature", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-tamper-breaks-signature", "BREAK",
            "tampered material digest accepted")


def p_material_unmarked():
    ep = _needs_module("p-material-unmarked")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    mats = [{"uri": "https://git.example.com/repo",
             "digest": "cd" * 32}]  # no completeness marking
    claim = ep.make_provenance_claim("build.example.com/ci", keyid,
                                     "ab" * 32, mats,
                                     issued_at=1700000000)
    env = ep.seal_provenance(claim, seed)
    try:
        ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-material-unmarked":
            _record("p-material-unmarked", "HELD",
                    "unmarked material refused: %s" % (code,))
        else:
            _record("p-material-unmarked", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-material-unmarked", "BREAK",
            "material without completeness marking accepted")


def p_material_unverified_loud():
    ep = _needs_module("p-material-unverified-loud")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    mats = [{"uri": "https://git.example.com/repo",
             "digest": "cd" * 32, "completeness": "unverified"}]
    claim = ep.make_provenance_claim("build.example.com/ci", keyid,
                                     "ab" * 32, mats,
                                     issued_at=1700000000)
    env = ep.seal_provenance(claim, seed)
    # Default: fail closed on unverified materials.
    try:
        ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code != "provenance-material-unverified":
            _record("p-material-unverified-loud", "BREAK",
                    "wrong code: %s" % (code,))
            return
    else:
        _record("p-material-unverified-loud", "BREAK",
                "unverified material silently accepted")
        return
    # Explicit opt-in: the LOUD marking is honored, not laundered.
    try:
        ok = ep.verify_provenance(env, policy,
                                  allow_unverified_materials=True)
    except Exception as e:  # noqa: BLE001
        _record("p-material-unverified-loud", "BREAK",
                "opt-in refused: %s" % (e,))
        return
    if ok is True:
        _record("p-material-unverified-loud", "HELD",
                "unverified material refused by default, honored on "
                "explicit opt-in")
    else:
        _record("p-material-unverified-loud", "BREAK",
                "opt-in returned non-True")


def _fresh_log():
    from gov import evidence_anchor as ea
    from gov import ed25519
    seed = ed25519.generate_seed()
    root = os.path.join(tempfile.mkdtemp(prefix="w287-prov-"),
                        "log")
    log = ea.TransparencyLog(root, origin="test-log.example",
                             signer_keyid="op-1", signer_seed=seed)
    return log, ed25519.publickey(seed), root


def p_anchor_gate_missing():
    ep = _needs_module("p-anchor-gate-missing")
    if ep is None:
        return
    _seed, _keyid, policy = _builder(ep)
    log, _pub, _root = _fresh_log()
    try:
        ep.anchor_bundle_gated(log, "ab" * 32, None, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-missing":
            _record("p-anchor-gate-missing", "HELD",
                    "missing provenance refuses at the gate: %s"
                    % (code,))
        else:
            _record("p-anchor-gate-missing", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-anchor-gate-missing", "BREAK",
            "bundle anchored with no provenance")


def p_anchor_gate_invalid():
    ep = _needs_module("p-anchor-gate-invalid")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    env = dict(env)
    env["signature"] = "ff" * 64
    log, _pub, _root = _fresh_log()
    try:
        ep.anchor_bundle_gated(log, "ab" * 32, env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-signature-invalid":
            _record("p-anchor-gate-invalid", "HELD",
                    "unsigned provenance refused at the gate: %s"
                    % (code,))
        else:
            _record("p-anchor-gate-invalid", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-anchor-gate-invalid", "BREAK",
            "bundle anchored on a forged provenance claim")


def p_anchor_gate_artifact_mismatch():
    ep = _needs_module("p-anchor-gate-artifact-mismatch")
    if ep is None:
        return
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)  # claim is about ab*32
    log, _pub, _root = _fresh_log()
    try:
        ep.anchor_bundle_gated(log, "ff" * 32, env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-artifact-mismatch":
            _record("p-anchor-gate-artifact-mismatch", "HELD",
                    "claim about another artifact refuses: %s" % (code,))
        else:
            _record("p-anchor-gate-artifact-mismatch", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-anchor-gate-artifact-mismatch", "BREAK",
            "provenance claim transferred across artifacts")


def p_anchor_gate_ok():
    ep = _needs_module("p-anchor-gate-ok")
    if ep is None:
        return
    from gov import evidence_anchor as ea
    seed, keyid, policy = _builder(ep)
    digest = "ab" * 32
    env, _artifact = _claim(ep, seed, keyid, artifact=digest)
    log, _pub, _root = _fresh_log()
    try:
        receipt = ep.anchor_bundle_gated(log, digest, env, policy)
    except Exception as e:  # noqa: BLE001
        _record("p-anchor-gate-ok", "BREAK",
                "valid gated anchor refused: %s" % (e,))
        return
    if receipt.get("bundle_digest") != digest:
        _record("p-anchor-gate-ok", "BREAK",
                "receipt digest mismatch")
        return
    # The receipt must verify under the log's operator key.
    try:
        ok = ea.verify_receipt(receipt, _pub, log_root=_root)
    except Exception as e:  # noqa: BLE001
        _record("p-anchor-gate-ok", "BREAK",
                "gated receipt does not verify: %s" % (e,))
        return
    if ok is True:
        _record("p-anchor-gate-ok", "HELD",
                "provenance-gated anchor issues a verifying receipt")


def p_anchor_ungated_unchanged():
    ep = _needs_module("p-anchor-ungated-unchanged")
    if ep is None:
        return
    from gov import evidence_anchor as ea
    # Callers without a gate see no behavior change (additive seam).
    log, _pub, _root = _fresh_log()
    try:
        receipt = ea.anchor(log, "ab" * 32)
    except Exception as e:  # noqa: BLE001
        _record("p-anchor-ungated-unchanged", "BREAK",
                "ungated anchor regressed: %s" % (e,))
        return
    if receipt.get("bundle_digest") == "ab" * 32:
        _record("p-anchor-ungated-unchanged", "HELD",
                "ungated anchor path unchanged")


def p_graph_records_provenance():
    ep = _needs_module("p-graph-records-provenance")
    if ep is None:
        return
    from gov import guac_graph as gg
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    graph = gg.GuacGraph()
    try:
        nodes = ep.record_provenance_in_graph(graph, env, policy)
    except Exception as e:  # noqa: BLE001
        _record("p-graph-records-provenance", "BREAK",
                "graph recording refused: %s" % (e,))
        return
    hits = graph.edges_with(gg.EdgeSpec(kind="HasSLSA"))
    want = ("software:builder/build.example.com/ci@1", "HasSLSA",
            "evidence:" + ep.claim_digest(env["provenance"]))
    if any(h[0] == want[0] and h[1] == want[1] and h[2] == want[2]
           for h in hits):
        _record("p-graph-records-provenance", "HELD",
                "provenance recorded as structural HasSLSA "
                "(corroboration stays in the claim layer)")
    else:
        _record("p-graph-records-provenance", "BREAK",
                "expected HasSLSA edge absent: %r" % (nodes,))


def p_graph_refuses_unsigned():
    ep = _needs_module("p-graph-refuses-unsigned")
    if ep is None:
        return
    from gov import guac_graph as gg
    seed, keyid, policy = _builder(ep)
    env, _artifact = _claim(ep, seed, keyid)
    env = dict(env)
    env["signature"] = "00" * 64
    graph = gg.GuacGraph()
    try:
        ep.record_provenance_in_graph(graph, env, policy)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "provenance-signature-invalid":
            _record("p-graph-refuses-unsigned", "HELD",
                    "unsigned provenance never enters the graph: %s"
                    % (code,))
        else:
            _record("p-graph-refuses-unsigned", "BREAK",
                    "wrong code: %s" % (code,))
        return
    _record("p-graph-refuses-unsigned", "BREAK",
            "forged provenance recorded in the graph")


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        _record("p-taxonomy-pin", "BREAK",
                "taxonomy pin drift: %d literals, want %d"
                % (len(lits), TAXONOMY_PIN))
        return
    if len(set(lits)) != len(lits):
        _record("p-taxonomy-pin", "BREAK", "duplicate literals")
        return
    if lits != sorted(lits):
        _record("p-taxonomy-pin", "BREAK", "literals unsorted")
        return
    _record("p-taxonomy-pin", "HELD", "1700/1700/0 sorted")


# -- depth-1 green checks ------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w285_tessera_probes.py",
        "evals/w284_guac_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r"
                    % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_module_present()
    p_claim_roundtrip()
    p_allowlist_enforced()
    p_unsigned_refused()
    p_tamper_breaks_signature()
    p_material_unmarked()
    p_material_unverified_loud()
    p_anchor_gate_missing()
    p_anchor_gate_invalid()
    p_anchor_gate_artifact_mismatch()
    p_anchor_gate_ok()
    p_anchor_ungated_unchanged()
    p_graph_records_provenance()
    p_graph_refuses_unsigned()
    p_taxonomy_pin()
    _green_checks()

    nbreak = sum(1 for pid, v, _ in _RESULTS if v == "BREAK")
    nheld = sum(1 for pid, v, _ in _RESULTS if v == "HELD")
    nerr = sum(1 for pid, v, _ in _RESULTS if v == "ERROR")
    probe_lines.emit(_RESULTS)
    print("w287_provenance: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _RESULTS, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
