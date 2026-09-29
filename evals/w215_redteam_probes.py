#!/usr/bin/env python3
"""Wave-215 lane C: independent red-team of the wave-214 evidence surface.

Targets: gov/agent_cards.py + gov/card_inventory.py (signed AgentCards),
gov/bom_queries.py (BOM blast-radius queries), gov/measurement_policy.py
(named, versioned measurement policies).

Method (diagnosing-bugs): attack shapes at the PUBLIC seams, deterministic,
minimal. These probes deliberately test COMBINATIONS the lane batteries did
not cover:

  (a) card-signed-but-unpinned kid; inventory pin AFTER legacy records
      exist; expiry boundary races; the register_agent_card bridge;
      expected_identity binding; two-signature ordering; crit-header
      handling; trust-record freshness edges.
  (b) add_decision_bom bridge (missing evidence, malformed BOM,
      round-trip); node_attrs copy isolation; using_edges as a string;
      strict revoked-flag semantics; unknown query names; allowlist
      key-id mismatch; duplicate node ids.
  (c) policy validity-window boundaries (activate at exactly not_after,
      evaluate at exactly not_before); same-version extended-window
      re-activation; activation_failures bound; unknown version of a
      known name; uppercase digest strictness.

Verdicts: HELD / BREAK / RESIDUAL / ERROR. Any BREAK is filed as F208+
(never quiet-patched). Exit 1 on any BREAK/ERROR.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g215c
  TMPDIR=/var/tmp/g215c ~/workspace/.gov-venv/bin/python \
      evals/w215_redteam_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g215c-u \
      ~/workspace/.gov-venv/bin/python evals/w215_redteam_probes.py
"""

import base64
import copy
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g215c-%d" % os.getpid())

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import agent_cards as ac          # noqa: E402
from gov import card_inventory as ci       # noqa: E402
from gov import bom_queries as bq          # noqa: E402
from gov import measurement_policy as mp   # noqa: E402
from gov import ed25519 as ed              # noqa: E402
from gov import delegation_tokens as dt    # noqa: E402
from gov import decision_bom as db         # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-46s %-9s %s" % (name, verdict, detail))


def _expect_card_fail(name, code, card, store, **kw):
    try:
        ac.verify_card(card, store, **kw)
    except ac.CardVerificationError as exc:
        if exc.code == code:
            _record(name, "HELD", "[%s]" % exc.code)
        else:
            _record(name, "BREAK", "wrong code [%s], wanted [%s]"
                    % (exc.code, code))
        return
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
        return
    _record(name, "BREAK", "attack card VERIFIED (wanted [%s])" % code)


# ---------------------------------------------------------------- fixtures

_NOW = 1_800_000_000.0
_VSEED = b"V" * 32
_ASEED = b"A" * 32
_VPUB = ed.publickey(_VSEED)
_JKU = "https://agents.example.com/.well-known/jwks.json"


def _shape(**over):
    f = {"a2a_version": "1.0", "agent_id": "agent-acme-001",
         "name": "acme", "version": "2.3.1",
         "capabilities": ["answer-questions"],
         "endpoints": {"jsonrpc": "https://agents.example.com/acme"},
         "keys": [{"kid": "vk1", "alg": "EdDSA", "use": "card-signing"}],
         "issued_at": _NOW - 60, "expires": _NOW + 86400}
    f.update(over)
    return f


def _store(owner="agent-acme-001", fetched_skew=10, extra_kids=None):
    keys = {"vk1": {"pubkey": _VPUB, "alg": "EdDSA", "jku": _JKU,
                    "fetched_at": _NOW - fetched_skew, "owner": owner}}
    for kid, seed in (extra_kids or {}).items():
        keys[kid] = {"pubkey": ed.publickey(seed), "alg": "EdDSA",
                     "jku": _JKU, "fetched_at": _NOW - fetched_skew,
                     "owner": owner}
    return ac.CardTrustStore(keys=keys, jku_allowlist=[_JKU])


def _valid_card(**over):
    return ac.emit_card(_shape(**over), "vk1", _VSEED, jku=_JKU, now=_NOW)


def _bom():
    return db.build_bom(policy_id="p", policy_version="1",
                        policy_digest="a" * 64,
                        evidence_head_digest="b" * 64,
                        principal={"agent_id": "x"}, pin_digests={})


# ---------------------------------------------------------------- (a) cards

@_probe("card_signed_but_unpinned_kid_refused")
def p_unpinned_kid():
    # A card signed by a REAL Ed25519 key whose kid was never pinned:
    # signature is cryptographically valid, trust is absent.
    card = ac.emit_card(_shape(), "ghost-kid", _ASEED, jku=_JKU, now=_NOW)
    _expect_card_fail("card_signed_but_unpinned_kid_refused",
                      "kid-ambiguity", card, _store(), now=_NOW)


@_probe("inventory_pin_after_legacy_records")
def p_pin_after_legacy():
    inv = ci.CardInventory()
    inv.admit_card({"agent_id": "agent-acme-001", "name": "acme"},
                   now=_NOW)
    inv.pin_keyset(_store())
    rec = inv.lookup("agent-acme-001")
    if rec["mode"] != "legacy-unsigned":
        _record("inventory_pin_after_legacy_records", "BREAK",
                "pin rewrote a legacy record: %r" % (rec["mode"],))
        return
    # The same agent re-admits with a genuine signed card: upgrade path.
    card = _valid_card()
    rec2 = inv.admit_card(card, now=_NOW)
    if rec2["mode"] == "signed" and rec2["kids"] == ["vk1"]:
        _record("inventory_pin_after_legacy_records", "HELD",
                "legacy record kept; signed re-admission upgrades")
    else:
        _record("inventory_pin_after_legacy_records", "BREAK",
                "re-admission did not upgrade: %r" % (rec2,))
    # Unsigned admission for the SAME legacy agent is refused after pin.
    try:
        inv.admit_card({"agent_id": "agent-acme-001", "name": "acme"},
                       now=_NOW)
        _record("inventory_pin_after_legacy_records", "BREAK",
                "unsigned re-admission passed after pin")
    except ac.CardVerificationError as exc:
        _record("inventory_pin_after_legacy_records", "HELD",
                "unsigned re-admission refused [%s]" % exc.code)


@_probe("expiry_boundary_races")
def p_expiry_boundary():
    card = _valid_card()
    store = _store()
    # now == expires exactly: "past expiry" is strictly greater, so the
    # card is still valid at the boundary instant (documented seam).
    try:
        ac.verify_card(card, store, now=card["expires"],
                       max_key_age_s=10 ** 9)
        _record("expiry_boundary_races", "HELD",
                "now==expires verifies (strict >)")
    except ac.CardVerificationError as exc:
        _record("expiry_boundary_races", "BREAK",
                "boundary instant refused [%s]" % exc.code)
        return
    try:
        ac.verify_card(card, store, now=card["expires"] + 1,
                       max_key_age_s=10 ** 9)
        _record("expiry_boundary_races", "BREAK",
                "card verified 1s past expiry")
    except ac.CardVerificationError as exc:
        if exc.code == "expired-card":
            _record("expiry_boundary_races", "HELD",
                    "expires+1 refused [expired-card]")
        else:
            _record("expiry_boundary_races", "BREAK",
                    "wrong code [%s]" % exc.code)
    # Zero-lifetime card: expires == issued_at == now verifies at issue.
    c0 = ac.emit_card(_shape(), "vk1", _VSEED, jku=_JKU, now=_NOW,
                      expires_in_s=0)
    try:
        ac.verify_card(c0, store, now=_NOW, max_key_age_s=10 ** 9)
        _record("expiry_boundary_races", "HELD",
                "zero-lifetime card valid at issue instant")
    except ac.CardVerificationError as exc:
        _record("expiry_boundary_races", "BREAK",
                "zero-lifetime refused at issue [%s]" % exc.code)


@_probe("two_signature_ordering_strict")
def p_two_sig_order():
    # First signature valid, second kid unknown: the whole card is
    # refused (fail-closed strictness — a denial, never a bypass).
    card = _valid_card()
    card["signatures"].append(ac.sign_card(
        {k: v for k, v in card.items() if k != "signatures"},
        "ghost", _ASEED, jku=_JKU))
    try:
        ac.verify_card(card, _store(), now=_NOW)
        _record("two_signature_ordering_strict", "BREAK",
                "unknown second kid accepted alongside a valid first")
    except ac.CardVerificationError as exc:
        if exc.code == "kid-ambiguity":
            _record("two_signature_ordering_strict", "RESIDUAL",
                    "one valid sig + unknown kid -> refused "
                    "[kid-ambiguity]: strict denial, not a bypass")
        else:
            _record("two_signature_ordering_strict", "BREAK",
                    "wrong code [%s]" % exc.code)
    # Two valid pinned kids: both verify.
    store2 = _store(extra_kids={"vk2": b"W" * 32})
    card2 = _valid_card()
    card2["signatures"].append(ac.sign_card(
        {k: v for k, v in card2.items() if k != "signatures"},
        "vk2", b"W" * 32, jku=_JKU))
    out = ac.verify_card(card2, store2, now=_NOW)
    _record("two_signature_ordering_strict",
            "HELD" if out["kids"] == ["vk1", "vk2"] else "BREAK",
            "two pinned kids -> %s" % (out["kids"],))


@_probe("register_agent_card_bridge")
def p_register_bridge():
    trust = dt.DelegationTrust(human_keys={"h": _VPUB},
                               authority_keys={"a": _VPUB},
                               user_issuer_keys={"u": _VPUB})
    card = _valid_card()
    out = ac.register_agent_card(trust, card, _store(), now=_NOW)
    kids = trust.card_identities.get("acme", {}).get("kids", {})
    if (out["identity"] == "acme" and "vk1" in kids
            and trust.agent_keys.get("acme") == _VPUB):
        _record("register_agent_card_bridge", "HELD",
                "identity proof + parent-signing key registered")
    else:
        _record("register_agent_card_bridge", "BREAK",
                "roster not populated: %r" % (out,))
        return
    forged = ac.emit_card(_shape(), "vk1", _ASEED, jku=_JKU, now=_NOW)
    try:
        ac.register_agent_card(trust, forged, _store(), now=_NOW)
        _record("register_agent_card_bridge", "BREAK",
                "forged card reached the delegation roster")
    except ac.CardVerificationError as exc:
        _record("register_agent_card_bridge", "HELD",
                "forged card refused at the bridge [%s]" % exc.code)
    if "ghost" not in trust.agent_keys:
        _record("register_agent_card_bridge", "HELD",
                "roster unchanged by the refused forgery")
    else:
        _record("register_agent_card_bridge", "BREAK",
                "refused forgery still registered a key")


@_probe("expected_identity_binding")
def p_expected_identity():
    card = _valid_card()
    try:
        ac.verify_card(card, _store(), now=_NOW,
                       expected_identity="someone-else")
        _record("expected_identity_binding", "BREAK",
                "card verified against a different expected identity")
    except ac.CardVerificationError as exc:
        _record("expected_identity_binding",
                "HELD" if exc.code == "identity-mismatch" else "BREAK",
                "[%s]" % exc.code)
    out = ac.verify_card(card, _store(), now=_NOW,
                         expected_identity="acme")
    _record("expected_identity_binding",
            "HELD" if out["identity"] == "acme" else "BREAK",
            "matching expected identity passes")


@_probe("signatures_shape_edges")
def p_sig_shape():
    card = _valid_card()
    c2 = copy.deepcopy(card)
    c2["signatures"] = {"0": c2["signatures"][0]}
    _expect_card_fail("signatures_shape_edges", "missing-signatures",
                      c2, _store(), now=_NOW)
    # Mixed-type keys cannot canonicalize: signing AND verifying both
    # fail closed (no silent mismatch between signer and verifier).
    c3 = copy.deepcopy(card)
    c3[123] = "x"
    try:
        ac.sign_card({k: v for k, v in c3.items() if k != "signatures"},
                     "vk1", _VSEED, jku=_JKU)
        _record("signatures_shape_edges", "BREAK",
                "mixed-type keys signed without error")
    except ac.CardVerificationError as exc:
        _record("signatures_shape_edges",
                "HELD" if exc.code == "canonicalization-failure"
                else "BREAK", "[%s]" % exc.code)


@_probe("crit_header_not_enforced")
def p_crit():
    # JWS RFC 7515 says unrecognized "crit" MUST fail; this verifier
    # ignores unknown protected-header fields (alg/typ/kid/jku only).
    # The signature still binds the whole header+body, so this is a
    # spec-hygiene residual, NOT a bypass: an attacker cannot use crit
    # to skip any check.
    card = _valid_card()
    body = {k: v for k, v in card.items() if k != "signatures"}
    header = {"alg": "EdDSA", "typ": "JOSE", "kid": "vk1",
              "jku": _JKU, "crit": ["exp"]}
    pb64 = base64.urlsafe_b64encode(
        json.dumps(header, sort_keys=True,
                   separators=(",", ":")).encode()).rstrip(b"=").decode()
    canon = ac.canonical_card_json(body)
    si = (pb64.encode("ascii") + b"." +
          base64.urlsafe_b64encode(canon).rstrip(b"="))
    sig = ed.sign(_VSEED, si)
    card["signatures"] = [{
        "protected": pb64,
        "signature": base64.urlsafe_b64encode(sig).rstrip(
            b"=").decode()}]
    try:
        ac.verify_card(card, _store(), now=_NOW)
        _record("crit_header_not_enforced", "RESIDUAL",
                "unrecognized crit accepted (sig still bound): "
                "JWS-crit hygiene gap, not a bypass")
    except ac.CardVerificationError as exc:
        _record("crit_header_not_enforced", "HELD",
                "crit refused [%s]" % exc.code)


@_probe("future_trust_record_accepted")
def p_future_trust():
    # A trust record with fetched_at in the FUTURE is accepted: the
    # staleness check is one-sided (now - fetched_at > max_age).
    # Registration is a deployment act, so this is an operator-owned
    # residual, not an attacker seam (attackers cannot write the store).
    store = ac.CardTrustStore(
        keys={"vk1": {"pubkey": _VPUB, "alg": "EdDSA", "jku": _JKU,
                      "fetched_at": _NOW + 999999, "owner":
                      "agent-acme-001"}},
        jku_allowlist=[_JKU])
    try:
        ac.verify_card(_valid_card(), store, now=_NOW)
        _record("future_trust_record_accepted", "RESIDUAL",
                "future-dated trust record accepted: operator-owned "
                "residual (deployment act, no attacker write path)")
    except ac.CardVerificationError as exc:
        _record("future_trust_record_accepted", "HELD",
                "refused [%s]" % exc.code)


@_probe("inventory_pinned_nondict_card")
def p_inv_nondict():
    inv = ci.CardInventory(store=_store())
    try:
        inv.admit_card("not-a-card", now=_NOW)
        _record("inventory_pinned_nondict_card", "BREAK",
                "non-dict card admitted under a pinned keyset")
    except ac.CardVerificationError as exc:
        _record("inventory_pinned_nondict_card", "HELD",
                "[%s]" % exc.code)


# ---------------------------------------------------------------- (b) BOM

@_probe("bridge_missing_evidence_refused")
def p_bridge_missing():
    g = bq.DecisionGraph()
    try:
        bq.add_decision_bom(g, _bom(), builder_id="builder:ghost")
        _record("bridge_missing_evidence_refused", "BREAK",
                "bridge wired an edge to a non-existent evidence node")
    except bq.GraphError:
        _record("bridge_missing_evidence_refused", "HELD",
                "dangling evidence refused (no phantom edges)")


@_probe("bridge_malformed_bom_refused")
def p_bridge_malformed():
    g = bq.DecisionGraph()
    for bad in ({"bogus": 1}, "not-a-bom", None):
        try:
            bq.add_decision_bom(g, bad)
            _record("bridge_malformed_bom_refused", "BREAK",
                    "malformed BOM ingested: %r" % (bad,))
            return
        except bq.GraphError:
            pass
    _record("bridge_malformed_bom_refused", "HELD",
            "malformed BOMs refused at the ingestion seam")


@_probe("bridge_roundtrip_blast_radius")
def p_bridge_roundtrip():
    g = bq.DecisionGraph()
    g.add_node("builder", "builder:x", {"revoked": True})
    g.add_node("key", "key:k1", {})
    did = bq.add_decision_bom(g, _bom(), builder_id="builder:x",
                              signing_key_ids=("key:k1",),
                              emitted_artifact_ids=())
    if did != "decision:" + db.bom_digest(_bom()):
        _record("bridge_roundtrip_blast_radius", "BREAK",
                "decision id is not the BOM digest: %r" % (did,))
        return
    hits = bq.decisions_using_builder(g, "builder:x")
    arts = bq.artifacts_emitted_under_key(g, "key:k1")
    if hits == [did] and arts == []:
        _record("bridge_roundtrip_blast_radius", "HELD",
                "bridge -> blast query end-to-end; no phantom artifacts")
    else:
        _record("bridge_roundtrip_blast_radius", "BREAK",
                "wrong blast sets: %r %r" % (hits, arts))
    # Re-ingesting the same BOM is a duplicate node, not a silent merge.
    try:
        bq.add_decision_bom(g, _bom(), builder_id="builder:x")
        _record("bridge_roundtrip_blast_radius", "BREAK",
                "double ingestion silently merged")
    except bq.GraphError:
        _record("bridge_roundtrip_blast_radius", "HELD",
                "double ingestion refused (duplicate node id)")


@_probe("node_attrs_copy_isolation")
def p_attrs_isolation():
    g = bq.DecisionGraph()
    g.add_node("builder", "b1", {"revoked": True})
    leaked = g.node_attrs("b1")
    leaked["revoked"] = False
    leaked["injected"] = True
    if g.node_attrs("b1") == {"revoked": True}:
        _record("node_attrs_copy_isolation", "HELD",
                "caller cannot mutate graph state via the view")
    else:
        _record("node_attrs_copy_isolation", "BREAK",
                "attrs view aliases graph state: %r"
                % (g.node_attrs("b1"),))
    if bq.decisions_using_builder(g, "b1") == []:
        _record("node_attrs_copy_isolation", "HELD",
                "query still sees the true revoked flag")
    else:
        _record("node_attrs_copy_isolation", "BREAK",
                "mutated view leaked into a query")


@_probe("using_edges_string_refused")
def p_using_string():
    g = bq.DecisionGraph()
    g.add_node("decision", "d1", {})
    try:
        bq.reachable(g, "d1", using_edges="decision/emitted")
        _record("using_edges_string_refused", "BREAK",
                "bare string silently iterated as edge kinds")
    except bq.QueryError:
        _record("using_edges_string_refused", "HELD",
                "string using_edges fails closed (chars not kinds)")


@_probe("revoked_flag_strict_true")
def p_revoked_strict():
    # The revoked flag is `is True` strict: truthy impostors ("yes", 1)
    # must NOT trigger a blast radius — an accusation needs the real
    # mark, not a truthy lookalike.
    g = bq.DecisionGraph()
    g.add_node("decision", "d1", {})
    g.add_node("builder", "b:str", {"revoked": "yes"})
    g.add_node("builder", "b:int", {"revoked": 1})
    g.add_node("builder", "b:true", {"revoked": True})
    for b in ("b:str", "b:int", "b:true"):
        g.add_edge("d1", b, "decision/used-builder")
    got = {b: bq.decisions_using_builder(g, b)
           for b in ("b:str", "b:int", "b:true")}
    if got == {"b:str": [], "b:int": [], "b:true": ["d1"]}:
        _record("revoked_flag_strict_true", "HELD",
                "only literal True triggers the revoked blast radius")
    else:
        _record("revoked_flag_strict_true", "BREAK",
                "truthy impostor triggered an accusation: %r" % (got,))


@_probe("query_dispatch_edges")
def p_query_dispatch():
    g = bq.DecisionGraph()
    try:
        bq.query_report(g, "smuggle_query", {"builder_id": "x"})
        _record("query_dispatch_edges", "BREAK", "unknown query ran")
        return
    except bq.QueryError:
        pass
    try:
        bq.query_report(g, "decisions_using_builder", {})
        _record("query_dispatch_edges", "BREAK",
                "missing builder_id silently exonerated")
        return
    except bq.QueryError:
        pass
    _record("query_dispatch_edges", "HELD",
            "unknown query + missing param both fail closed")


@_probe("allowlist_keyid_mismatch")
def p_allowlist_keyid():
    s1 = Ed25519Signer(b"\x01" * 32)
    v1 = Ed25519Verifier(s1.public_key)
    signed = bq.sign_allowlist(s1)
    v2 = Ed25519Verifier(Ed25519Signer(b"\x02" * 32).public_key)
    try:
        bq.verify_allowlist_signature(v2, signed)
        _record("allowlist_keyid_mismatch", "BREAK",
                "foreign-key allowlist signature accepted")
    except bq.GraphError:
        _record("allowlist_keyid_mismatch", "HELD",
                "key-swap refused (key_id must match the verifier)")
    # Wrong TYPE of verifier object (not a gov.signing.Verifier):
    try:
        bq.verify_allowlist_signature(object(), signed)
        _record("allowlist_keyid_mismatch", "BREAK",
                "non-verifier object accepted")
    except Exception:
        _record("allowlist_keyid_mismatch", "HELD",
                "non-verifier verifier fails closed")


@_probe("self_loop_terminates")
def p_self_loop():
    g = bq.DecisionGraph()
    g.add_node("artifact", "a1", {})
    g.add_edge("a1", "a1", "artifact/derived-from")  # self-loop
    got = bq.reachable(g, "a1", using_edges=("artifact/derived-from",))
    _record("self_loop_terminates",
            "HELD" if got == [] else "BREAK",
            "self-loop reachable=%r (start excluded, terminates)" % (got,))


# ---------------------------------------------------------------- (c) policy

def _issuer():
    seed = bytes(bytearray(range(32)))
    return seed, ed.publickey(seed)


def _pbody(name="fleet", version=1, not_before=100, not_after=200):
    return mp.make_policy_body(
        policy_name=name, version=version,
        required_measurements=[("launch_image", "a" * 64)],
        not_before=not_before, not_after=not_after, signer_kid="ops")


@_probe("policy_window_boundaries")
def p_window_edges():
    seed, pub = _issuer()
    body = _pbody()
    sig = mp.sign_policy(seed, body)
    reg = mp.MeasurementPolicyRegistry(pub)
    # Activate at exactly not_after: stale (>= is refused).
    try:
        reg.activate(body, sig, now=200)
        _record("policy_window_boundaries", "BREAK",
                "policy activated at exactly not_after")
        return
    except mp.MeasurementPolicyError as exc:
        if exc.code != "policy-stale":
            _record("policy_window_boundaries", "BREAK",
                    "wrong code [%s]" % exc.code)
            return
    reg.activate(body, sig, now=199)
    # Evaluate at exactly not_before: inside the window [nb, na).
    try:
        out = reg.evaluate("fleet", 1, {"launch_image": "a" * 64},
                           now=100)
        _record("policy_window_boundaries",
                "HELD" if out == ("fleet", 1) else "BREAK",
                "activate@na refused [policy-stale]; eval@nb ok")
    except mp.MeasurementPolicyError as exc:
        _record("policy_window_boundaries", "BREAK",
                "eval at not_before refused [%s]" % exc.code)


@_probe("same_version_extended_window_refused")
def p_samever_window():
    # A legitimate-looking operator act — re-issuing v1 with a longer
    # window — is refused: policy versions are immutable, roll-forward
    # is v2. Documented residual, not a bypass.
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    b1 = _pbody(version=1, not_after=200)
    reg.activate(b1, mp.sign_policy(seed, b1), now=150)
    b1x = _pbody(version=1, not_after=900)
    try:
        reg.activate(b1x, mp.sign_policy(seed, b1x), now=150)
        _record("same_version_extended_window_refused", "BREAK",
                "same version re-issued with a new window displaced v1")
    except mp.MeasurementPolicyError as exc:
        _record("same_version_extended_window_refused",
                "RESIDUAL" if exc.code == "policy-version-downgrade"
                else "BREAK",
                "version immutability: window extension needs v2 "
                "[%s]" % exc.code)


@_probe("activation_failures_bounded")
def p_failures_bounded():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    for i in range(70):
        try:
            reg.activate({"bad": i}, b"\x00" * 64, now=150)
        except mp.MeasurementPolicyError:
            pass
    n = len(reg.activation_failures)
    _record("activation_failures_bounded",
            "HELD" if n == 64 else "BREAK",
            "telemetry bounded at %d (unbounded would be a memory seam)"
            % n)


@_probe("unknown_version_of_known_name")
def p_unknown_version():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    body = _pbody(version=1)
    reg.activate(body, mp.sign_policy(seed, body), now=150)
    try:
        reg.evaluate("fleet", 2, {"launch_image": "a" * 64}, now=150)
        _record("unknown_version_of_known_name", "BREAK",
                "unactivated v2 of a known policy evaluated")
    except mp.MeasurementPolicyError as exc:
        _record("unknown_version_of_known_name",
                "HELD" if exc.code == "policy-unknown" else "BREAK",
                "[%s]" % exc.code)


@_probe("uppercase_digest_strict")
def p_upper_digest():
    # Digests must be lowercase hex: an uppercase digest is a mismatch,
    # never a normalization. (Constant-time compare stays exact.)
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    body = _pbody()
    reg.activate(body, mp.sign_policy(seed, body), now=150)
    try:
        reg.evaluate("fleet", 1, {"launch_image": "A" * 64}, now=150)
        _record("uppercase_digest_strict", "BREAK",
                "uppercase digest accepted (normalization bypass)")
    except mp.MeasurementPolicyError as exc:
        _record("uppercase_digest_strict",
                "HELD" if exc.code == "measurement-mismatch" else "BREAK",
                "[%s]" % exc.code)


@_probe("policy_body_immutable_after_activate")
def p_body_immutable():
    # White-box: the registry stores dict(body) — a shallow copy. The
    # nested required_measurements list is SHARED with the caller's
    # dict. Mutating the caller's nested list post-activation must
    # still fail the per-evaluation signature re-check (not silently
    # take effect).
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    body = _pbody()
    reg.activate(body, mp.sign_policy(seed, body), now=150)
    body["required_measurements"][0]["expected_digest"] = "c" * 64
    try:
        reg.evaluate("fleet", 1, {"launch_image": "c" * 64}, now=150)
        _record("policy_body_immutable_after_activate", "BREAK",
                "caller-side nested mutation took effect post-activation")
    except mp.MeasurementPolicyError as exc:
        _record("policy_body_immutable_after_activate",
                "HELD" if exc.code == "policy-signature-invalid"
                else "BREAK",
                "nested aliasing caught by sig re-check [%s]" % exc.code)


# ---------------------------------------------------------------- green

def _green_lane_battery(path):
    if GREEN_SKIP:
        _record("green:" + os.path.basename(path), "HELD",
                "skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               TMPDIR="/var/tmp/g215c-green-%d" % os.getpid())
    os.makedirs(env["TMPDIR"], exist_ok=True)
    r = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, env=env, cwd=REPO, timeout=900)
    tail = (r.stdout or "").strip().splitlines()
    summary = next((ln for ln in reversed(tail)
                    if "HELD" in ln or "BREAK" in ln or "ERROR" in ln
                    or "GAP" in ln), "")
    import re as _re
    bad = bool(_re.search(r"[1-9]\d* BREAK", summary)
               or _re.search(r"[1-9]\d* ERROR", summary)
               or _re.search(r"[1-9]\d* GAP", summary))
    _record("green:" + os.path.basename(path),
            "HELD" if (r.returncode == 0 and not bad) else "BREAK",
            "rc=%d %s" % (r.returncode, summary.strip()[-120:]))


def _run_all():
    """Run every probe once; return the (name, verdict, detail) list."""
    saved = list(_RESULTS)
    del _RESULTS[:]
    order = sorted(_PROBE_FNS)
    for name in order:
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - never die mid-battery
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    out = list(_RESULTS)
    del _RESULTS[:]
    _RESULTS.extend(saved)
    return out


def main():
    print("== wave-215 lane C: wave-214 evidence-surface red team ==")
    pass1 = _run_all()
    _RESULTS.extend(pass1)
    for name, verdict, detail in pass1:
        print("  %-46s %-9s %s" % (name, verdict, detail))
    # Determinism: second pass must produce identical (name, verdict)
    # pairs; any drift is an ERROR (harness or product nondeterminism).
    pass2 = _run_all()
    if len(pass1) != len(pass2):
        _record("determinism:row-count", "ERROR",
                "%d rows then %d rows" % (len(pass1), len(pass2)))
    else:
        drift = [(a[0], a[1], b[1]) for a, b in zip(pass1, pass2)
                 if a[0] != b[0] or a[1] != b[1]]
        if drift:
            for name, v1, v2 in drift[:10]:
                _record("determinism:" + name, "ERROR",
                        "%s -> %s" % (v1, v2))
        else:
            _record("determinism:full-second-pass", "HELD",
                    "%d rows, verdicts identical" % len(pass1))
    for lane in ("evals/w214_agentcard_probes.py",
                 "evals/w214_blast_radius_probes.py",
                 "evals/w214_measurement_policy_probes.py"):
        _green_lane_battery(os.path.join(REPO, lane))
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    res = sum(1 for _, v, _ in _RESULTS if v == "RESIDUAL")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("== %d HELD / %d BREAK / %d RESIDUAL / %d ERROR =="
          % (held, brk, res, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
