#!/usr/bin/env python3
"""A2A v1 signed Agent Card verifier + delegation-receipt card_kid binding.

Row-11 cross-runtime identity: before this seam, a foreign agent's
claimed card identity had no cryptographic binding to its key — a
forged card (victim's name, attacker-signed) was indistinguishable
from a genuine card at registration time, and the laundered identity
minted fully-valid delegation receipts (see /tmp/red_a2a_gap.py,
pre-build red-first).

Probe map (verdicts HELD / BREAK / ERROR):
  c_valid / c_valid_no_jku / c_two_signatures
      genuine EdDSA cards verify; kids bound; identity returned
  c_tampered_body / c_tampered_sig / c_wrong_key
      -> invalid-signature (distinct code, fail-closed)
  c_missing_sigs -> missing-signatures
  c_untrusted_jku / c_non_https_jku / c_jku_mismatch -> untrusted-jku
      (no fetch attempted anywhere — there is no network path)
  c_alg_none / c_alg_es256 -> unsupported-alg (strict allow-list;
      ES256 is a documented v1 refusal, not silent non-support)
  c_duplicate_kid / c_unknown_kid -> kid-ambiguity
  c_stale_trust -> stale-trust
  c_identity_mismatch -> identity-mismatch
  c_card_not_object -> canonicalization-failure
  c_nonserializable -> malformed-card (wave-214: shape check precedes
      canonicalization; still fail-closed with a distinct code)
  c_rfc8032_selftest — the Ed25519 primitive's own RFC 8032 vectors
  r_forged_card_refused — THE red-first closure: attacker-signed card
      claiming the victim's name is refused at register_agent_card
      (kid-ambiguity / invalid-signature); the key never reaches the
      roster
  r_genuine_registers — genuine card registers: card_identities +
      agent_keys populated, describe() leaks no key material
  r_receipt_binds_card_kid — delegation issued with card_kid mints a
      receipt carrying card_kid; the receipt verifies
  r_swapped_kid_refused — token re-signed with another kid: the chain
      verifier refuses (DelegationBindingError)
  r_subject_identity_mismatch_refused — card_kid bound to identity X
      on a token whose subject is Y: refused
  r_spawn_drops_binding — sub-agent spawn does not inherit card_kid
      (strict semantics: the binding lives only on the token whose
      subject IS the card identity); spawn still verifies
  r_local_receipt_unaffected — non-card delegation: card_kid None,
      receipt verifies (additive, no regression)
  r_deterministic_x2 — byte-identical receipts across 2 runs

$0 spend, synthetic/local, deterministic. Real product code
(gov.agent_cards, gov.delegation_tokens, gov.ed25519), no stubs.

Run:
  mkdir -p /tmp/gov-a2a-card
  TMPDIR=/tmp/gov-a2a-card ~/workspace/.gov-venv/bin/python \
      evals/a2a_card_verifier_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-a2a-card-u \
      ~/workspace/.gov-venv/bin/python evals/a2a_card_verifier_probes.py
"""

import base64
import copy
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-a2a-card-%d" % os.getpid())

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import agent_cards as _ac  # noqa: E402
from gov import delegation_tokens as _dt  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402

_NOW = 1_800_000_000.0
_NOW_DT = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
_VICTIM_SEED = b"V" * 32
_ATTACKER_SEED = b"A" * 32
_VICTIM_PUB = _ed.publickey(_VICTIM_SEED)
_ATTACKER_PUB = _ed.publickey(_ATTACKER_SEED)
_JKU = "https://agents.example.com/.well-known/jwks.json"
_JKU_EVIL = "https://evil.example/jwks.json"
_REVOKE_URI = "https://revoke.example.invalid/deleg"

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _base_card():
    # Wave-214 shape: the inventory record fields (agent_id, endpoints,
    # keys) plus the pinned a2a_version and a live expires. "version"
    # remains the AGENT's version (1.0.0) -- the A2A spec pin is the
    # separate a2a_version field.
    return {
        "a2a_version": "1.0",
        "agent_id": "agent-acme-support-001",
        "name": "acme-support-agent",
        "description": "Customer support agent",
        "url": "https://agents.example.com/acme-support",
        "version": "1.0.0",
        "capabilities": ["answer-questions"],
        "endpoints": {"jsonrpc": "https://agents.example.com/acme-support"},
        "keys": [{"kid": "victim-key-1", "alg": "EdDSA",
                  "use": "card-signing"}],
        "issued_at": _NOW - 60,
        "expires": _NOW + 86400,
    }


def _store(extra_keys=None, allow_extra=(), fetched_skew=100):
    keys = {"victim-key-1": {"pubkey": _VICTIM_PUB, "alg": "EdDSA",
                             "jku": _JKU, "fetched_at": _NOW - fetched_skew}}
    if extra_keys:
        keys.update(extra_keys)
    return _ac.CardTrustStore(keys=keys,
                              jku_allowlist=[_JKU, *allow_extra])


def _expect_ok(name, card, store, **kw):
    try:
        out = _ac.verify_card(card, store, now=_NOW, **kw)
    except _ac.CardVerificationError as exc:
        _record(name, "BREAK", "valid card refused [%s] %s"
                % (exc.code, exc.detail))
        return None
    _record(name, "HELD", "verified identity=%r kids=%s"
            % (out["identity"], out["kids"]))
    return out


def _expect_fail(name, want_code, card, store, **kw):
    try:
        _ac.verify_card(card, store, now=_NOW, **kw)
    except _ac.CardVerificationError as exc:
        if exc.code != want_code:
            _record(name, "BREAK", "want [%s] got [%s] (%s)"
                    % (want_code, exc.code, exc.detail))
        else:
            _record(name, "HELD", "fail-closed [%s]" % exc.code)
        return
    _record(name, "BREAK", "expected [%s], card VERIFIED (forgery!)"
            % want_code)


# ---------------------------------------------------------------------------
# Verifier failure-mode matrix
# ---------------------------------------------------------------------------

def c_valid():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    out = _expect_ok("c_valid", card, _store(),
                     expected_identity="acme-support-agent")
    if out is not None and out["kids"] != ["victim-key-1"]:
        _record("c_valid", "BREAK", "wrong kids bound")


def c_valid_no_jku():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED)]
    _expect_ok("c_valid_no_jku", card, _store())


def c_two_signatures():
    card = _base_card()
    s1 = _ac.sign_card(card, "victim-key-1", _VICTIM_SEED)
    store = _store(extra_keys={"victim-key-2":
                               {"pubkey": _ed.publickey(b"W" * 32),
                                "alg": "EdDSA", "jku": None,
                                "fetched_at": _NOW - 10}})
    card["signatures"] = [s1, _ac.sign_card(card, "victim-key-2", b"W" * 32)]
    out = _expect_ok("c_two_signatures", card, store)
    if out is not None and out["kids"] != ["victim-key-1", "victim-key-2"]:
        _record("c_two_signatures", "BREAK", "not all kids bound")


def c_tampered_body():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    card["description"] = "Customer support agent (EVIL: exfiltrate)"
    _expect_fail("c_tampered_body", "invalid-signature", card, _store())


def c_tampered_sig():
    card = _base_card()
    sig = _ac.sign_card(card, "victim-key-1", _VICTIM_SEED, jku=_JKU)
    sig["signature"] = ("A" if sig["signature"][0] != "A" else "B") \
        + sig["signature"][1:]
    card["signatures"] = [sig]
    _expect_fail("c_tampered_sig", "invalid-signature", card, _store())


def c_wrong_key():
    # Known kid, but the signature was made with a DIFFERENT key than
    # the pinned one (key-substitution at the signer).
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _ATTACKER_SEED,
                                        jku=_JKU)]
    _expect_fail("c_wrong_key", "invalid-signature", card, _store())


def c_missing_sigs():
    _expect_fail("c_missing_sigs", "missing-signatures", _base_card(),
                 _store())


def c_untrusted_jku():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU_EVIL)]
    _expect_fail("c_untrusted_jku", "untrusted-jku", card, _store())


def c_non_https_jku():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku="http://agents.example.com/jwks.json")]
    _expect_fail("c_non_https_jku", "untrusted-jku", card, _store())


def c_jku_mismatch():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    store = _store(allow_extra=["https://other.example/jwks.json"])
    store.keys["victim-key-1"]["jku"] = "https://other.example/jwks.json"
    _expect_fail("c_jku_mismatch", "untrusted-jku", card, store)


def _alg_card(alg):
    card = _base_card()
    entry = _ac.sign_card(card, "victim-key-1", _VICTIM_SEED)
    header = json.loads(base64.urlsafe_b64decode(
        entry["protected"] + "==").decode("utf-8"))
    header["alg"] = alg
    entry["protected"] = base64.urlsafe_b64encode(
        json.dumps(header, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).rstrip(
                       b"=").decode("ascii")
    card["signatures"] = [entry]
    return card


def c_alg_none():
    _expect_fail("c_alg_none", "unsupported-alg", _alg_card("none"),
                 _store())


def c_alg_es256():
    # Documented v1 refusal: ES256 is fail-closed (unsupported-alg),
    # not degraded to warn-only, until a vetted ECDSA implementation
    # lands (cryptography is not in requirements.lock; installing it
    # would trip the F75 supply-chain gate).
    _expect_fail("c_alg_es256", "unsupported-alg", _alg_card("ES256"),
                 _store())


def c_duplicate_kid():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED),
                          _ac.sign_card(card, "victim-key-1", _VICTIM_SEED)]
    _expect_fail("c_duplicate_kid", "kid-ambiguity", card, _store())


def c_unknown_kid():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "key-zzz", _ATTACKER_SEED)]
    _expect_fail("c_unknown_kid", "kid-ambiguity", card, _store())


def c_stale_trust():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED)]
    store = _store(fetched_skew=10 * 86400)
    _expect_fail("c_stale_trust", "stale-trust", card, store,
                 max_key_age_s=86400)


def c_identity_mismatch():
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED)]
    _expect_fail("c_identity_mismatch", "identity-mismatch", card,
                 _store(), expected_identity="other-agent")


def c_card_not_object():
    _expect_fail("c_card_not_object", "canonicalization-failure",
                 ["not", "a", "dict"], _store())


def c_nonserializable():
    card = _base_card()
    card["capabilities"] = {"weird": object()}
    card["signatures"] = [{"protected": "e30", "signature": "e30"}]
    # Wave-214: the shape check now runs before canonicalization, so a
    # non-list capabilities is malformed-card (more specific than the
    # old canonicalization-failure). Still fail-closed, still distinct.
    _expect_fail("c_nonserializable", "malformed-card", card, _store())


def c_rfc8032_selftest():
    name = "c_rfc8032_selftest"
    try:
        ok = _ed.rfc8032_selftest()
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "selftest raised: %r" % exc)
        return
    _record(name, "HELD" if ok else "BREAK",
            "Ed25519 RFC 8032 vectors %s" % ("pass" if ok else "FAIL"))


# ---------------------------------------------------------------------------
# Registration seam + receipt binding
# ---------------------------------------------------------------------------

def _keys():
    human_s, human_p = _dt.generate_test_keypair()
    idp_s, idp_p = _dt.generate_test_keypair()
    auth_s, auth_p = _dt.generate_test_keypair()
    trust = _dt.DelegationTrust(
        human_keys={human_s.key_id: human_p},
        authority_keys={auth_s.key_id: auth_p},
        user_issuer_keys={idp_s.key_id: idp_p})
    return human_s, idp_s, auth_s, trust


def r_forged_card_refused():
    name = "r_forged_card_refused"
    _, _, _, trust = _keys()
    store = _store()
    card = _base_card()
    # Attacker cannot forge the victim's signature; substitutes their
    # own key under the victim's name (and tries an unknown kid).
    card["signatures"] = [_ac.sign_card(card, "attacker-key-9",
                                        _ATTACKER_SEED)]
    try:
        _ac.register_agent_card(trust, card, store, now=_NOW)
    except _ac.CardVerificationError as exc:
        if "acme-support-agent" in trust.agent_keys \
                or trust.card_identities:
            _record(name, "BREAK", "refused [%s] but roster mutated"
                    % exc.code)
        else:
            _record(name, "HELD",
                    "forged card refused [%s]; roster untouched"
                    % exc.code)
        return
    _record(name, "BREAK", "forged card REGISTERED (identity laundering!)")


def r_genuine_registers():
    name = "r_genuine_registers"
    _, _, _, trust = _keys()
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    try:
        out = _ac.register_agent_card(trust, card, _store(), now=_NOW)
    except _ac.CardVerificationError as exc:
        _record(name, "BREAK", "genuine card refused [%s]" % exc.code)
        return
    desc = trust.describe()
    blob = json.dumps(desc)
    leaked = _VICTIM_PUB.hex() in blob
    ok = (trust.agent_keys.get("acme-support-agent") == _VICTIM_PUB
          and desc["card_identities"].get("acme-support-agent")
          == ["victim-key-1"] and not leaked
          and out["identity"] == "acme-support-agent")
    _record(name, "HELD" if ok else "BREAK",
            "identity=%r kids=%s agent_keys+card_identities set, "
            "describe() leaks no key material" % (out["identity"],
                                                  out["kids"]) if ok
            else "registration incomplete or key material leaked")


def _card_delegation(card_kid):
    human_s, idp_s, auth_s, trust = _keys()
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    _ac.register_agent_card(trust, card, _store(), now=_NOW)
    sess = "sess-a2a-%s" % (card_kid or "local")
    ut = _dt.issue_user_token(idp_s, "user-7", ["tool:*"], sess, now=_NOW_DT)
    at = _dt.issue_agent_token(auth_s, "acme-support-agent", "support",
                               "acme", ["tool:*"], sess, now=_NOW_DT)
    dg = _dt.issue_delegation(human_s, "user-7", ut, at, ["tool:*"], sess,
                              _REVOKE_URI, now=_NOW_DT, card_kid=card_kid)
    ctx = _dt.DelegationContext(
        user_token=ut, agent_token=at, delegation_token=dg,
        parent_chain=[], trust=trust, session_id=sess).bind(now=_NOW_DT)
    return human_s, trust, ut, at, dg, ctx, sess


def r_receipt_binds_card_kid():
    name = "r_receipt_binds_card_kid"
    try:
        human_s, trust, ut, at, dg, ctx, sess = _card_delegation(
            "victim-key-1")
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "setup failed: %r" % exc)
        return
    rc = ctx.receipt()
    if rc.get("card_kid") != "victim-key-1":
        _record(name, "BREAK", "receipt missing card_kid: %r"
                % (rc.get("card_kid"),))
        return
    try:
        verified = _dt.verify_delegation_receipt(
            rc, user_token=ut, agent_token=at, delegation_token=dg,
            parent_chain=[], trust=trust, session_id=sess, now=_NOW_DT)
    except _dt.DelegationError as exc:
        _record(name, "BREAK", "card-bound receipt refused: %r" % exc)
        return
    _record(name, "HELD",
            "receipt carries card_kid=%r, act=%r; verifies"
            % (verified["card_kid"], verified["act"]))


def r_swapped_kid_refused():
    name = "r_swapped_kid_refused"
    try:
        human_s, trust, ut, at, dg, ctx, sess = _card_delegation(
            "victim-key-1")
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "setup failed: %r" % exc)
        return
    # Attacker re-signs the delegation claims with a DIFFERENT
    # (unregistered) kid — the signature is valid, the binding is not.
    tampered = copy.deepcopy(dg)
    tampered["claims"] = dict(tampered["claims"])
    tampered["claims"]["card_kid"] = "attacker-key-9"
    body = {k: v for k, v in tampered.items() if k != "sig"}
    tampered["sig"] = human_s.sign(
        _dt._TOKEN_DOMAIN + _dt._canonical(body)).hex()
    try:
        _dt.DelegationContext(
            user_token=ut, agent_token=at, delegation_token=tampered,
            parent_chain=[], trust=trust,
            session_id=sess).bind(now=_NOW_DT)
    except _dt.DelegationBindingError as exc:
        _record(name, "HELD", "swapped kid refused: %s"
                % str(exc)[:70])
        return
    except _dt.DelegationError as exc:
        _record(name, "HELD", "swapped kid refused (%s)"
                % type(exc).__name__)
        return
    _record(name, "BREAK", "swapped card_kid BOUND (binding bypass!)")


def r_subject_identity_mismatch_refused():
    name = "r_subject_identity_mismatch_refused"
    human_s, idp_s, auth_s, trust = _keys()
    card = _base_card()
    card["signatures"] = [_ac.sign_card(card, "victim-key-1", _VICTIM_SEED,
                                        jku=_JKU)]
    _ac.register_agent_card(trust, card, _store(), now=_NOW)
    sess = "sess-a2a-mismatch"
    ut = _dt.issue_user_token(idp_s, "user-7", ["tool:*"], sess, now=_NOW_DT)
    # Agent token names a DIFFERENT agent, but the delegation claims
    # the victim's card kid: subject != registered card identity.
    at = _dt.issue_agent_token(auth_s, "impostor-agent", "support", "acme",
                               ["tool:*"], sess, now=_NOW_DT)
    dg = _dt.issue_delegation(human_s, "user-7", ut, at, ["tool:*"], sess,
                              _REVOKE_URI, now=_NOW_DT,
                              card_kid="victim-key-1")
    try:
        _dt.DelegationContext(
            user_token=ut, agent_token=at, delegation_token=dg,
            parent_chain=[], trust=trust,
            session_id=sess).bind(now=_NOW_DT)
    except _dt.DelegationBindingError as exc:
        _record(name, "HELD", "subject/identity mismatch refused: %s"
                % str(exc)[:70])
        return
    except _dt.DelegationError as exc:
        _record(name, "HELD", "refused (%s)" % type(exc).__name__)
        return
    _record(name, "BREAK", "card_kid bound to wrong subject!")


def r_spawn_drops_binding():
    name = "r_spawn_drops_binding"
    try:
        human_s, trust, ut, at, dg, ctx, sess = _card_delegation(
            "victim-key-1")
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "setup failed: %r" % exc)
        return
    # The foreign agent parent-signs a sub-delegation with its card key
    # (registered into agent_keys by register_agent_card).
    from gov import signing as _sg  # noqa: E402
    parent_signer = _sg.Ed25519Signer(_VICTIM_SEED)
    try:
        child = ctx.spawn("sub-1", ["tool:read_file"], parent_signer,
                          now=_NOW_DT)
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "spawn failed: %r" % exc)
        return
    ck = child.delegation_token["claims"].get("card_kid")
    rc = child.receipt()
    ok = ck is None and rc.get("card_kid") is None and child.bound
    _record(name, "HELD" if ok else "BREAK",
            "spawn does not inherit card_kid (strict subject binding); "
            "child bound, parent hop retains the binding" if ok else
            "spawn inherited or dropped the binding incorrectly: %r" % (ck,))


def r_local_receipt_unaffected():
    name = "r_local_receipt_unaffected"
    try:
        human_s, trust, ut, at, dg, ctx, sess = _card_delegation(None)
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "setup failed: %r" % exc)
        return
    rc = ctx.receipt()
    if rc.get("card_kid") is not None:
        _record(name, "BREAK", "local receipt carries card_kid")
        return
    if rc.get("receipt_version") != 1:
        _record(name, "BREAK", "receipt version changed")
        return
    try:
        _dt.verify_delegation_receipt(
            rc, user_token=ut, agent_token=at, delegation_token=dg,
            parent_chain=[], trust=trust, session_id=sess, now=_NOW_DT)
    except _dt.DelegationError as exc:
        _record(name, "BREAK", "local receipt refused: %r" % exc)
        return
    _record(name, "HELD", "local receipt: card_kid None, version 1, "
            "verifies (additive, no regression)")


def r_deterministic_x2():
    name = "r_deterministic_x2"
    try:
        _, _, ut, at, dg, ctx, sess = _card_delegation("victim-key-1")
        r1 = json.dumps(ctx.receipt(), sort_keys=True)
        r2 = json.dumps(ctx.receipt(), sort_keys=True)
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "setup failed: %r" % exc)
        return
    _record(name, "HELD" if r1 == r2 else "BREAK",
            "byte-identical receipts across 2 runs" if r1 == r2
            else "receipts differ across runs")


# ---------------------------------------------------------------------------
# Green check (depth-1 adjacency discipline)
# ---------------------------------------------------------------------------

_ADJACENT = ["delegation_receipt_probes.py",
             "deleg_receipt_stamping_probes.py"]


def a2a_green():
    name = "a2a_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "standalone for full depth-1 adjacency")
        return
    failures = []
    for i, battery in enumerate(_ADJACENT):
        tmp = os.path.join(os.environ["TMPDIR"], "a2a-green-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
            timeout=600)
        tail = (proc.stdout.strip().splitlines() or [""])[-1]
        if proc.returncode != 0:
            err_tail = (proc.stderr.strip().splitlines() or [""])[-1]
            failures.append("%s -> rc=%d (%s; %s)"
                            % (battery, proc.returncode, tail, err_tail))
    if failures:
        _record(name, "BREAK", "; ".join(failures))
    else:
        _record(name, "HELD",
                "adjacent delegation batteries green at depth 1: %s"
                % ", ".join(_ADJACENT))


def main():
    probes = [c_valid, c_valid_no_jku, c_two_signatures, c_tampered_body,
              c_tampered_sig, c_wrong_key, c_missing_sigs,
              c_untrusted_jku, c_non_https_jku, c_jku_mismatch,
              c_alg_none, c_alg_es256, c_duplicate_kid, c_unknown_kid,
              c_stale_trust, c_identity_mismatch, c_card_not_object,
              c_nonserializable, c_rfc8032_selftest,
              r_forged_card_refused, r_genuine_registers,
              r_receipt_binds_card_kid, r_swapped_kid_refused,
              r_subject_identity_mismatch_refused, r_spawn_drops_binding,
              r_local_receipt_unaffected, r_deterministic_x2]
    for probe in probes:
        try:
            probe()
        except Exception as exc:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "raised: %r" % exc)
    a2a_green()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("a2a_card_verifier_probes: %d HELD / %d BREAK / %d EXPECTED / "
          "%d ERROR" % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
