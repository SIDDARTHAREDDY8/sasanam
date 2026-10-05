#!/usr/bin/env python3
"""Wave-271 red-first battery: replay manifest v1.

A replay manifest is a hash-chained, digest-addressed record of an
agent trajectory from which an offline verifier re-derives what was
recorded -- without the engine (the "sell evidence, not the engine"
product surface). Steals (clean-room): LangSmith dotted_order shape +
inverted git-info (dirty -> refuse), Braintrust span-origin
discipline, Phoenix span-kind vocabulary only (Phoenix is Elastic
License 2.0 -- ideas/vocabulary, NO Phoenix code).

Red phase:  GOV_REPLAY_IMPL=stub  -> permissive foil. Every attack
probe must BREAK (the foil seals/verifies anything); a probe that
HELDs on the stub is vacuous and is flagged.
Green phase: default (gov.replay_manifest) -> every probe must HELD.

Protocol constants below are pinned independently of the module under
test (canonical JSON form, fixed clock); the battery never imports
gov.replay_manifest's internals.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# -- spec-pinned protocol constants (NOT imported from gov.replay_manifest)
MANIFEST_FORMAT = "sasanam-replay-manifest/v1"
GENESIS = "00" * 32  # 64 hex chars, like the module's GENESIS_HASH
NOW = 1790960000  # fixed test clock (2026-10-02-ish)
PIN = 2100 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 7: pin 1541 -> 1545 (+4 casbin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)


_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Fixture: a benign trajectory through the (real or foil) builder API
# ---------------------------------------------------------------------------

def _trajectory(mod, now=NOW, policy=None):
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7", now=lambda: now,
                                  code_pin_policy=policy)
    b.record_environment_snapshot({"python": "3.12", "os": "linux"})
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin="c3" * 32, seed=42)
    b.record_presentation(presented_bytes=b"approval: rm -rf /tmp/x",
                          purpose="approval-prompt")
    b.record_approval_requested(approval_id="appr-1",
                                presented_bytes=b"approval: rm -rf /tmp/x")
    b.record_approval_received(approval_id="appr-1",
                               approval_receipt_ref="d4" * 32,
                               decision_digest="e5" * 32)
    b.record_gate_consult(gate="egress", decision_code="deny",
                          reason="unlisted host")
    return b


def _seal_benign(mod):
    return _trajectory(mod).seal()


# ---------------------------------------------------------------------------
# Permissive foil (red phase): same API, zero checks
# ---------------------------------------------------------------------------

class _FoilError(Exception):
    pass


class _FoilBuilder(object):
    def __init__(self, actor, *, now=None, code_pin_policy=None):
        self._links = []

    def _rec(self, action, **kw):
        self._links.append({"seq": len(self._links), "action": action,
                            "prev_hash": GENESIS, "link_hash": "ff" * 64,
                            **kw})
        return "ff" * 64

    def record_environment_snapshot(self, env):
        return self._rec("environment_snapshot")

    def record_tool_call(self, **kw):
        return self._rec("tool_call")

    def record_presentation(self, **kw):
        return self._rec("presentation")

    def record_approval_requested(self, **kw):
        return self._rec("approval_requested")

    def record_approval_received(self, **kw):
        return self._rec("approval_received")

    def record_gate_consult(self, **kw):
        return self._rec("gate_consult")

    def seal(self):
        return {"format": MANIFEST_FORMAT, "links": self._links,
                "code_pins": {}, "manifest_digest": "ff" * 64}

    def as_evidence_artifact(self):
        m = self.seal()
        d = _hex(_canonical(m))
        return {"format": "evidence-artifact.v2", "body": m,
                "artifact_digest": d}, d


class _FoilModule(object):
    ReplayManifestError = _FoilError
    ReplayManifestBuilder = _FoilBuilder
    CodePinPolicy = object
    InMemoryPinRegistry = object

    @staticmethod
    def verify_manifest(manifest, **kw):
        return {"verified": True, "manifest_digest": "ff" * 64,
                "links": 0, "approval_links": 0,
                "receipts_unverified": False,
                "presentations_unverified": []}


def _real_module():
    import gov.replay_manifest as rm
    return rm


def _is_foil(mod):
    return getattr(mod, "ReplayManifestError", None) is _FoilError


def _mod(impl):
    return _FoilModule() if impl == "stub" else _real_module()


# ---------------------------------------------------------------------------
# Corroboration-receipt fixture (wave-267 ceremony, real checks)
# ---------------------------------------------------------------------------

def _receipt_fixture():
    from gov.agent_identity import did_key_from_pubkey
    from gov import corroboration_receipt as cr
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signer = Ed25519Signer(bytes([0x11]) * 32)
    did = did_key_from_pubkey(bytes(signer.public_key))
    stmt = cr.build_statement(
        did, decision_digest="e5" * 32, evidence_digests=["b2" * 32],
        scope={"action": "tool.execute", "resource": "fs.read:/tmp/x"},
        verdict="corroborated", issued_at="2026-10-02T00:00:00Z",
        approval_channel="approval-queue",
        statement_entry_digest="c9" * 32)
    env = cr.dsse_envelope(stmt)
    cr.sign_envelope(env, signer, keyid="k1")
    verifier = Ed25519Verifier(bytes(signer.public_key))
    ref = cr.statement_digest(stmt)
    return cr, verifier, env, stmt, ref


def _checker(cr, verifier):
    def check(link, statement):
        if cr.statement_digest(statement) != link["approval_receipt_ref"]:
            from gov import replay_manifest as rm
            raise rm.ReplayManifestError(
                "replay-approval-receipt-invalid",
                "statement digest does not match the link reference")
        env = _checker.envelopes[cr.statement_digest(statement)]
        cr.verify_envelope(env, verifier)
    _checker.envelopes = {}
    return _checker


# ---------------------------------------------------------------------------
# Probes: each returns (verdict, detail). Attacks BREAK on the foil and
# must HELD on the real module; controls must HELD on both.
# ---------------------------------------------------------------------------

PROBES = []


def probe(name, kind):
    def deco(fn):
        PROBES.append((name, kind, fn))
        return fn
    return deco


# -- attacks ----------------------------------------------------------

@probe("chain/body-tamper", "attack")
def _p_body_tamper(mod):
    m = _seal_benign(mod)
    m["links"][1]["output_digest"] = "99" * 32  # tamper post-seal
    try:
        mod.verify_manifest(m)
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "tampered link verified")


@probe("chain/prev-hash-splice", "attack")
def _p_splice(mod):
    m = _seal_benign(mod)
    if _is_foil(mod):
        m["links"][1], m["links"][2] = m["links"][2], m["links"][1]
    else:
        # Re-stamp seqs so the splice is a pure order attack on the
        # chain, not a shape violation.
        a, b = dict(m["links"][1]), dict(m["links"][2])
        a["seq"], b["seq"] = 2, 1
        for link in (a, b):
            body = {k: v for k, v in link.items() if k != "link_hash"}
            link["link_hash"] = _hex(_canonical(body))
        m["links"][1], m["links"][2] = b, a
    try:
        mod.verify_manifest(m)
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "spliced chain verified")


@probe("chain/seal-swap", "attack")
def _p_seal_swap(mod):
    m = _seal_benign(mod)
    m["manifest_digest"] = "ab" * 32
    try:
        mod.verify_manifest(m)
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "broken seal verified")


@probe("pin/dirty-seal", "attack")
def _p_dirty(mod):
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin="c3" * 32, seed=1, dirty=True)
    try:
        b.seal()
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "dirty codebase sealed")


@probe("pin/missing-digest", "attack")
def _p_missing_pin(mod):
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin=None, seed=1)
    try:
        b.seal()
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "unpinned tool sealed")


@probe("pin/registry-mismatch", "attack")
def _p_registry_mismatch(mod):
    if _is_foil(mod):
        b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                      now=lambda: NOW)
        b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                           output_digest="b2" * 32,
                           tool_digest_pin="ff" * 32, seed=1)
        try:
            b.seal()
        except mod.ReplayManifestError as e:
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "mismatched pin sealed")
    reg = mod.InMemoryPinRegistry()
    reg.register("fs.read", "c3" * 32)
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7", now=lambda: NOW,
                                  code_pin_policy=reg)
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin="ff" * 32, seed=1)
    try:
        b.seal()
    except mod.ReplayManifestError as e:
        return ("HELD", "refused: %s" % e.code)
    return ("BREAK", "mismatched pin sealed")


@probe("receipt/forged-binding", "attack")
def _p_forged_receipt(mod):
    cr, verifier, env, stmt, ref = _receipt_fixture()
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_approval_received(approval_id="appr-1",
                               approval_receipt_ref="00" * 32,  # wrong ref
                               decision_digest="e5" * 32)
    m = b.seal()
    if _is_foil(mod):
        try:
            mod.verify_manifest(m)
        except mod.ReplayManifestError as e:
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "forged receipt binding verified")
    checker = _checker(cr, verifier)
    checker.envelopes[ref] = env
    try:
        mod.verify_manifest(m, receipts={ref: stmt},
                            receipt_checker=checker)
    except mod.ReplayManifestError as e:
        if e.code == "replay-approval-receipt-invalid":
            return ("HELD", "refused: %s" % e.code)
        return ("HELD?", "wrong code: %s" % e.code)
    return ("BREAK", "forged receipt binding verified")


@probe("presentation/swap", "attack")
def _p_presentation_swap(mod):
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_presentation(presented_bytes=b"approve: rm -rf /tmp/x",
                          purpose="approval-prompt")
    m = b.seal()
    try:
        mod.verify_manifest(m, presentations={
            _hex(b"approve: rm -rf /tmp/x"): b"approve: echo hello"})
    except mod.ReplayManifestError as e:
        if e.code == "replay-presentation-mismatch":
            return ("HELD", "refused: %s" % e.code)
        return ("HELD?", "wrong code: %s" % e.code)
    return ("BREAK", "swapped presentation verified")


@probe("verify/dirty-link-in-chain", "attack")
def _p_dirty_link(mod):
    # Defense in depth: even a hand-sealed dirty link must not verify.
    m = _seal_benign(mod)
    if _is_foil(mod):
        return ("BREAK", "foil has no chain to defend")
    link = dict(m["links"][1])
    link["dirty"] = True
    body = {k: v for k, v in link.items() if k != "link_hash"}
    link["link_hash"] = _hex(_canonical(body))
    m2 = {"format": MANIFEST_FORMAT, "links": [m["links"][0], link],
          "code_pins": dict(m["code_pins"]),
          "manifest_digest": "xx"}
    m2["links"][1]["prev_hash"] = m["links"][0]["link_hash"]
    link2 = dict(m2["links"][1])
    body2 = {k: v for k, v in link2.items() if k != "link_hash"}
    m2["links"][1]["link_hash"] = _hex(_canonical(body2))
    m2["manifest_digest"] = _hex(_canonical(
        {"format": MANIFEST_FORMAT, "links": m2["links"],
         "code_pins": m2["code_pins"]}))
    try:
        mod.verify_manifest(m2)
    except mod.ReplayManifestError as e:
        if e.code == "replay-dirty-codebase-seal":
            return ("HELD", "refused: %s" % e.code)
        return ("HELD?", "wrong code: %s" % e.code)
    return ("BREAK", "dirty link verified")


# -- controls ---------------------------------------------------------

@probe("control/benign-seals-and-verifies", "control")
def _c_benign(mod):
    m = _seal_benign(mod)
    if mod is _FoilModule:
        r = mod.verify_manifest(m)
    else:
        r = mod.verify_manifest(
            m, presentations={_hex(b"approval: rm -rf /tmp/x"):
                              b"approval: rm -rf /tmp/x"})
    if r.get("verified") is True:
        return ("HELD", "verified")
    return ("BREAK", "benign manifest did not verify")


@probe("control/deterministic", "control")
def _c_deterministic(mod):
    a = _canonical(_seal_benign(mod))
    b = _canonical(_seal_benign(mod))
    if a == b:
        return ("HELD", "A==B byte-identical")
    return ("BREAK", "nondeterministic manifest")


@probe("control/negative-evidence-roundtrip", "control")
def _c_negative(mod):
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_gate_consult(gate="egress", decision_code="deny",
                          reason="unlisted host")
    m = b.seal()
    r = mod.verify_manifest(m)
    if not _is_foil(mod):
        link = m["links"][0]
        neg = link.get("negative_evidence") or {}
        if neg.get("tool_dispatched") is not False:
            return ("BREAK", "negative evidence not first-class")
    if r.get("verified") is True:
        return ("HELD", "negative evidence recorded and verified")
    return ("BREAK", "negative-evidence manifest did not verify")


@probe("control/honest-unverified-attribution", "control")
def _c_honest(mod):
    if _is_foil(mod):
        return ("HELD", "foil skips attribution (documented)")
    m = _seal_benign(mod)
    r = mod.verify_manifest(m)  # no checker, no presentations
    if r.get("verified") is True and r.get("receipts_unverified") is True\
            and r.get("presentations_unverified"):
        return ("HELD", "unverified-but-pinned reported honestly")
    return ("BREAK", "missing honest unverified attribution: %r" % (r,))


@probe("control/valid-receipt-binds", "control")
def _c_valid_receipt(mod):
    if _is_foil(mod):
        return ("HELD", "foil skips receipt crypto (documented)")
    cr, verifier, env, stmt, ref = _receipt_fixture()
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_approval_received(approval_id="appr-1",
                               approval_receipt_ref=ref,
                               decision_digest="e5" * 32)
    m = b.seal()
    checker = _checker(cr, verifier)
    checker.envelopes[ref] = env
    r = mod.verify_manifest(m, receipts={ref: stmt},
                            receipt_checker=checker)
    if r.get("verified") is True and not r.get("receipts_unverified"):
        return ("HELD", "valid receipt bound and verified")
    return ("BREAK", "valid receipt did not verify")


@probe("control/evidence-artifact-composition", "control")
def _c_artifact(mod):
    if _is_foil(mod):
        art, digest = _FoilBuilder("x").as_evidence_artifact()
        return ("HELD", "foil artifact shape ok")
    b = mod.ReplayManifestBuilder("spiffe://prod/agent-7",
                                  now=lambda: NOW)
    b.record_tool_call(tool_id="fs.read", input_digest="a1" * 32,
                       output_digest="b2" * 32,
                       tool_digest_pin="c3" * 32, seed=1)
    b.seal()
    art, digest = b.as_evidence_artifact()
    if art["artifact_digest"] != digest:
        return ("BREAK", "artifact digest self-inconsistent")
    if _hex(_canonical(art["body"])) != digest:
        return ("BREAK", "artifact digest does not re-hash")
    return ("HELD", "manifest wraps as a v2 evidence artifact")


@probe("pin/taxonomy-1458", "control")
def _c_pin(mod):
    import re as _re
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    codes = _re.findall(
        r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(codes) != PIN or len(set(codes)) != PIN:
        return ("BREAK", "literals %d unique %d (want %d)"
                % (len(codes), len(set(codes)), PIN))
    new = [c for c in set(codes) if c.startswith("replay-") and
           c in ("replay-approval-receipt-invalid", "replay-broken-chain",
                 "replay-dirty-codebase-seal", "replay-malformed",
                 "replay-missing-approval-receipt",
                 "replay-presentation-mismatch",
                 "replay-unverifiable-tool-digest")]
    once = all(codes.count(c) == 1 for c in new)
    if len(new) == 7 and once:
        return ("HELD", "1579 literals, unique, 0 dups, 7 new exactly once")
    return ("BREAK", "new-code literal problem: %r" % (new,))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent v2 bundle unit suite with GOV_SKIP_GREEN=1 in
    the child env (it has no green check of its own)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "GOV_SKIP_GREEN=1 (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = tempfile.mkdtemp(prefix="g271-green-")
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_evbundle", "-v"],
        cwd=_REPO, env=env, capture_output=True, text=True, timeout=600)
    if p.returncode == 0:
        return ("HELD", "tests/test_evbundle green (depth-1)")
    return ("BREAK", "adjacent suite red:\n%s" % (p.stderr[-2000:],))


def main():
    impl = os.environ.get("GOV_REPLAY_IMPL", "real")
    mod = _mod(impl)
    held = brk = vacuous = 0
    print("impl=%s probes=%d" % (impl, len(PROBES)))
    for name, kind, fn in PROBES:
        try:
            verdict, detail = fn(mod)
        except Exception as e:  # noqa: BLE001
            verdict, detail = ("ERROR", "%r" % (e,))
        if kind == "attack" and verdict == "HELD" and impl == "stub":
            verdict = "VACUOUS"
        print("%-42s %-7s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            brk += 1
        elif verdict == "VACUOUS":
            vacuous += 1
        else:
            brk += 1  # ERROR/HELD? count as failure
    gv, gd = _green_check()
    print("green-check: %s %s" % (gv, gd))
    print("RESULT impl=%s HELD=%d BREAK=%d VACUOUS=%d" % (
        impl, held, brk, vacuous))
    if impl == "stub":
        ok = (vacuous == 0)
        print("RED-PHASE %s (need 0 vacuous)" % ("OK" if ok else "FAIL"))
    else:
        ok = (brk == 0 and vacuous == 0 and gv in ("HELD", "SKIP"))
        print("GREEN-PHASE %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
