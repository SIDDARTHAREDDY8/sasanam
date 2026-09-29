#!/usr/bin/env python3
"""Wave-214 lane A: signed Agent Card ADAPT for agent discovery/inventory.

ASI07 countermeasure WITHOUT A2A transport: an AgentCard-shaped record
{agent_id, name, version, capabilities, endpoints, keys} carrying a
flattened-JWS-shaped signatures[] array (kid + jku + JCS
canonicalization), verified against a kid-pinned keyset, fail-closed.
Shape stolen from A2A v1.0 SS8.4; NO A2A SDK imported (a2a-go issue
#445: Go SDK skips S8.4.1 rule-1 proto projection, so SDK-signed cards
do not cross-verify with the JS SDK -- our cards never leave our
JCS/canonical form, and any A2A SDK output is treated as untrusted
input). A2A spec version pinned to exactly "1.0" (0.2->0.3->1.0 broke
inside a year).

Red-first probe map (verdicts HELD / BREAK / ERROR):

  Gap probes (pristine: BREAK or ERROR -- the feature does not exist):
  p_expired_card_refused     past expires verifies on pristine
  p_not_yet_valid_refused    future issued_at verifies on pristine
  p_version_pin_holds        a2a_version "0.3"/"1.1"/missing verifies
                             on pristine; only "1.0" passes fixed
  p_shape_enforced           missing agent_id/keys/endpoints verifies
                             on pristine
  p_kid_swap_refused         attacker re-signs victim card under own
                             kid: pristine has no trust-store owner
                             binding (TypeError/ERROR); fixed refuses
                             with identity-mismatch
  p_emit_card_roundtrip      emit_card absent on pristine (ERROR);
                             fixed: emit -> verify passes
  p_inventory_pinned_refuses_unsigned
  p_inventory_pinned_admits_signed
  p_inventory_legacy_admits_unsigned
  p_inventory_forged_refused CardInventory absent on pristine (ERROR)

  Re-pin probes (HELD on pristine AND fixed -- the seam must not move):
  r_forged_signature_refused   wrong key -> invalid-signature
  r_unknown_kid_refused        kid-ambiguity
  r_jku_mismatch_refused       untrusted-jku (no fetch attempted)
  r_tampered_capabilities_refused -> invalid-signature
  r_unknown_field_covered      OUR divergence from A2A S8.4.1 rule 1:
                             our signature covers unknown fields (we do
                             no proto projection); tampering one breaks
                             the signature. Operators must know SDK
                             cards behave differently.
  r_deterministic_emit        emit twice -> byte-identical signatures[]

$0 spend, synthetic/local, deterministic. Real product code
(gov.agent_cards, gov.card_inventory, gov.ed25519), no stubs.

Run:
  mkdir -p /var/tmp/g214a
  TMPDIR=/var/tmp/g214a ~/workspace/.gov-venv/bin/python \
      evals/w214_agentcard_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g214a-u \
      ~/workspace/.gov-venv/bin/python evals/w214_agentcard_probes.py
"""

import copy
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g214a-%d" % os.getpid())

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import agent_cards as _ac  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402

try:
    from gov import card_inventory as _ci  # noqa: E402
except ImportError:
    _ci = None

_NOW = 1_800_000_000.0
_VICTIM_SEED = b"V" * 32
_ATTACKER_SEED = b"A" * 32
_VICTIM_PUB = _ed.publickey(_VICTIM_SEED)
_ATTACKER_PUB = _ed.publickey(_ATTACKER_SEED)
_JKU = "https://agents.example.com/.well-known/jwks.json"

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _fail(name, exc):
    _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))


def _shape_fields(**over):
    fields = {
        # a2a_version/issued_at mirror what emit_card stamps; attack
        # probes override expires/issued_at (or a2a_version) via `over`.
        "a2a_version": "1.0",
        "agent_id": "agent-acme-support-001",
        "name": "acme-support-agent",
        "version": "2.3.1",
        "capabilities": ["answer-questions", "escalate"],
        "endpoints": {"jsonrpc": "https://agents.example.com/acme-support"},
        "keys": [{"kid": "victim-key-1", "alg": "EdDSA",
                  "use": "card-signing"}],
        "issued_at": _NOW - 60,
        "expires": _NOW + 86400,
    }
    fields.update(over)
    return fields


def _store(owner=None, fetched_skew=100):
    keys = {"victim-key-1": {"pubkey": _VICTIM_PUB, "alg": "EdDSA",
                             "jku": _JKU, "fetched_at": _NOW - fetched_skew}}
    if owner is not None:
        keys["victim-key-1"]["owner"] = owner
    return _ac.CardTrustStore(keys=keys, jku_allowlist=[_JKU])


def _signed_card(store, seed=_VICTIM_SEED, kid="victim-key-1", jku=_JKU,
                 card_overrides=None, sign_overrides=None, now=_NOW,
                 raw_sign=False):
    """Build a full card dict and sign it.

    Default: production ``emit_card`` path. ``raw_sign=True`` signs the
    raw record with the low-level signer instead -- this is how ATTACK
    cards reach the verifier (emit_card fail-fasts on malformed/expired
    input before signing, which is correct but would not exercise the
    verifier's refusal codes).
    """
    fields = _shape_fields()
    if card_overrides:
        fields.update(card_overrides)
    if hasattr(_ac, "emit_card") and not raw_sign:
        return _ac.emit_card(fields, kid, seed, jku=jku, now=now,
                             **(sign_overrides or {}))
    # Raw path: record + low-level signer (also the pristine fallback).
    card = dict(fields)
    entry = _ac.sign_card(card, kid, seed,
                          **({"jku": jku} if jku else {}))
    card["signatures"] = [entry]
    return card


def _expect_ok(name, card, store):
    try:
        out = _ac.verify_card(card, store, now=_NOW)
    except _ac.CardVerificationError as exc:
        _record(name, "BREAK", "valid card refused [%s] %s"
                % (exc.code, exc.detail))
        return None
    except Exception as exc:  # noqa: BLE001 - pristine gap surface
        _fail(name, exc)
        return None
    _record(name, "HELD", "verified kids=%s" % (out["kids"],))
    return out


def _expect_fail(name, code, card, store):
    try:
        _ac.verify_card(card, store, now=_NOW)
    except _ac.CardVerificationError as exc:
        if exc.code == code:
            _record(name, "HELD", "[%s] %s" % (exc.code, exc.detail))
        else:
            _record(name, "BREAK", "wrong code [%s], wanted [%s]: %s"
                    % (exc.code, code, exc.detail))
        return
    except Exception as exc:  # noqa: BLE001 - pristine gap surface
        _fail(name, exc)
        return
    _record(name, "BREAK", "attack card VERIFIED (wanted refusal [%s])" % code)


# ---------------------------------------------------------------------------
# Gap probes
# ---------------------------------------------------------------------------

def gap_expired_card():
    card = _signed_card(_store(), card_overrides={"expires": _NOW - 60},
                        raw_sign=True)
    _expect_fail("p_expired_card_refused", "expired-card", card, _store())


def gap_not_yet_valid():
    card = _signed_card(_store(),
                        card_overrides={"issued_at": _NOW + 3600,
                                        "expires": _NOW + 7200},
                        raw_sign=True)
    _expect_fail("p_not_yet_valid_refused", "not-yet-valid", card, _store())


def gap_version_pin():
    for bad in ("0.3", "1.1", "1.0.0", ""):
        card = _signed_card(_store(), card_overrides={"a2a_version": bad},
                              raw_sign=True)
        _expect_fail("p_version_pin_refused_%s" % (bad or "empty"),
                     "card-version", card, _store())
    card = _signed_card(_store(), card_overrides={"a2a_version": "1.0"})
    _expect_ok("p_version_pin_accepts_1_0", card, _store())
    card = _signed_card(_store(), raw_sign=True)
    card.pop("a2a_version", None)
    _expect_fail("p_version_pin_missing_refused", "card-version", card,
                 _store())


def gap_shape_enforced():
    for missing in ("agent_id", "keys", "endpoints", "capabilities"):
        fields = _shape_fields()
        del fields[missing]
        try:
            if hasattr(_ac, "emit_card"):
                card = _ac.emit_card(fields, "victim-key-1", _VICTIM_SEED,
                                     jku=_JKU, now=_NOW)
            else:
                card = dict(fields)
                card["signatures"] = [_ac.sign_card(card, "victim-key-1",
                                                   _VICTIM_SEED, jku=_JKU)]
        except Exception as exc:  # noqa: BLE001 - emit may fail closed
            _record("p_shape_missing_%s_refused" % missing, "HELD",
                    "emit refused: %s" % exc)
            continue
        _expect_fail("p_shape_missing_%s_refused" % missing,
                     "malformed-card", card, _store())


def gap_kid_swap():
    # Attacker re-signs the VICTIM's card body under the ATTACKER's own
    # kid (pinned in the store with owner=attacker). Without an
    # owner->agent binding the signature verifies and the victim's
    # identity is laundered. Fixed: identity-mismatch.
    store = _ac.CardTrustStore(
        keys={"victim-key-1": {"pubkey": _VICTIM_PUB, "alg": "EdDSA",
                               "jku": _JKU, "fetched_at": _NOW - 100,
                               "owner": "agent-acme-support-001"},
              "attacker-key-9": {"pubkey": _ATTACKER_PUB, "alg": "EdDSA",
                                 "jku": _JKU, "fetched_at": _NOW - 100,
                                 "owner": "agent-attacker-009"}},
        jku_allowlist=[_JKU])
    fields = _shape_fields()
    fields["keys"] = [{"kid": "attacker-key-9", "alg": "EdDSA",
                       "use": "card-signing"}]
    try:
        if hasattr(_ac, "emit_card"):
            card = _ac.emit_card(fields, "attacker-key-9", _ATTACKER_SEED,
                                 jku=_JKU, now=_NOW)
        else:
            card = dict(fields)
            card["signatures"] = [_ac.sign_card(card, "attacker-key-9",
                                               _ATTACKER_SEED, jku=_JKU)]
    except TypeError as exc:
        _record("p_kid_swap_refused", "ERROR",
                "pristine: no owner binding (%s)" % exc)
        return
    except Exception as exc:  # noqa: BLE001
        _fail("p_kid_swap_refused", exc)
        return
    _expect_fail("p_kid_swap_refused", "identity-mismatch", card, store)


def gap_emit_roundtrip():
    if not hasattr(_ac, "emit_card"):
        _record("p_emit_card_roundtrip", "ERROR",
                "pristine: emit_card absent")
        return
    try:
        card = _ac.emit_card(_shape_fields(), "victim-key-1", _VICTIM_SEED,
                             jku=_JKU, now=_NOW)
    except Exception as exc:  # noqa: BLE001
        _fail("p_emit_card_roundtrip", exc)
        return
    out = _expect_ok("p_emit_card_roundtrip", card, _store())
    if out is not None and out.get("identity") != "acme-support-agent":
        _record("p_emit_card_roundtrip", "BREAK",
                "identity not bound: %r" % (out.get("identity"),))


def gap_inventory():
    if _ci is None:
        for n in ("p_inventory_legacy_admits_unsigned",
                  "p_inventory_pinned_refuses_unsigned",
                  "p_inventory_pinned_admits_signed",
                  "p_inventory_forged_refused"):
            _record(n, "ERROR", "pristine: gov.card_inventory absent")
        return
    # Legacy mode: unsigned discovery still works.
    inv = _ci.CardInventory()
    try:
        rec = inv.admit_card({"agent_id": "agent-x-1", "name": "x-agent"},
                             now=_NOW)
    except Exception as exc:  # noqa: BLE001
        _fail("p_inventory_legacy_admits_unsigned", exc)
    else:
        _record("p_inventory_legacy_admits_unsigned", "HELD",
                "mode=%s" % rec["mode"])
    # Pinned mode: unsigned refused (tighten-only).
    inv2 = _ci.CardInventory(store=_store(owner="agent-acme-support-001"))
    try:
        inv2.admit_card({"agent_id": "agent-x-1", "name": "x-agent"},
                        now=_NOW)
        _record("p_inventory_pinned_refuses_unsigned", "BREAK",
                "unsigned card admitted under pinned keyset")
    except _ac.CardVerificationError as exc:
        _record("p_inventory_pinned_refuses_unsigned", "HELD",
                "[%s]" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _fail("p_inventory_pinned_refuses_unsigned", exc)
    # Pinned mode: genuine signed card admitted.
    card = _signed_card(_store(owner="agent-acme-support-001"))
    try:
        rec = inv2.admit_card(card, now=_NOW)
        _record("p_inventory_pinned_admits_signed", "HELD",
                "agent=%s kids=%s" % (rec["agent_id"], rec["kids"]))
    except Exception as exc:  # noqa: BLE001
        _record("p_inventory_pinned_admits_signed", "BREAK",
                "genuine card refused: %s" % exc)
    # Pinned mode: attacker-forged card refused.
    forged = _signed_card(_store(), seed=_ATTACKER_SEED)
    try:
        inv2.admit_card(forged, now=_NOW)
        _record("p_inventory_forged_refused", "BREAK",
                "forged card admitted to inventory")
    except _ac.CardVerificationError as exc:
        _record("p_inventory_forged_refused", "HELD", "[%s]" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _fail("p_inventory_forged_refused", exc)
    # Tighten-only: pinning never loosens; lookup works.
    got = inv2.lookup("agent-acme-support-001")
    _record("p_inventory_lookup", "HELD" if got else "BREAK",
            "found=%s" % bool(got))
    desc = inv2.describe()
    leaked = "V" * 8 in json.dumps(desc)
    _record("p_inventory_describe_no_keymat",
            "HELD" if not leaked else "BREAK", "")


# ---------------------------------------------------------------------------
# Re-pin probes (must HELD on pristine and fixed)
# ---------------------------------------------------------------------------

def repin_forged_signature():
    card = _signed_card(_store(), seed=_ATTACKER_SEED)
    _expect_fail("r_forged_signature_refused", "invalid-signature", card,
                 _store())


def repin_unknown_kid():
    card = _signed_card(_store(), kid="ghost-kid")
    _expect_fail("r_unknown_kid_refused", "kid-ambiguity", card, _store())


def repin_jku_mismatch():
    card = _signed_card(_store(), jku="https://evil.example/jwks.json")
    _expect_fail("r_jku_mismatch_refused", "untrusted-jku", card, _store())


def repin_tampered_capabilities():
    card = _signed_card(_store())
    card = copy.deepcopy(card)
    card["capabilities"].append("run-arbitrary-code")
    _expect_fail("r_tampered_capabilities_refused", "invalid-signature",
                 card, _store())


def repin_unknown_field_covered():
    # OUR divergence from A2A S8.4.1 rule 1 (proto projection): we JCS
    # the whole body minus signatures, so unknown fields ARE covered
    # by our signature. Tampering one must break verification.
    card = _signed_card(_store(), card_overrides={"x_custom": "honest"})
    card = copy.deepcopy(card)
    card["x_custom"] = "tampered"
    _expect_fail("r_unknown_field_covered", "invalid-signature", card,
                 _store())


def repin_deterministic_emit():
    if not hasattr(_ac, "emit_card"):
        _record("r_deterministic_emit", "ERROR",
                "pristine: emit_card absent")
        return
    c1 = _ac.emit_card(_shape_fields(), "victim-key-1", _VICTIM_SEED,
                       jku=_JKU, now=_NOW)
    c2 = _ac.emit_card(_shape_fields(), "victim-key-1", _VICTIM_SEED,
                       jku=_JKU, now=_NOW)
    b1 = json.dumps(c1, sort_keys=True).encode()
    b2 = json.dumps(c2, sort_keys=True).encode()
    _record("r_deterministic_emit", "HELD" if b1 == b2 else "BREAK",
            "byte-identical=%s" % (b1 == b2,))


def repin_green_check():
    """Depth-1: adjacent battery green (GOV_SKIP_GREEN honored)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green_adjacent_a2a", "HELD", "skipped (depth-1)")
        return
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               TMPDIR="/var/tmp/g214a-adj-%d" % os.getpid())
    os.makedirs(env["TMPDIR"], exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "evals/a2a_card_verifier_probes.py")],
        capture_output=True, text=True, env=env, timeout=600)
    tail = (r.stdout or "").strip().splitlines()
    summary = next((ln for ln in reversed(tail)
                    if "HELD" in ln or "BREAK" in ln or "ERROR" in ln), "")
    import re as _re
    bad = bool(_re.search(r"[1-9]\d* BREAK", summary)
               or _re.search(r"[1-9]\d* ERROR", summary))
    _record("green_adjacent_a2a",
            "HELD" if (r.returncode == 0 and not bad) else "BREAK",
            "rc=%d %s" % (r.returncode, summary.strip()))


def main():
    print("== wave-214 lane A: signed agent-card ADAPT probes ==")
    for fn in (gap_expired_card, gap_not_yet_valid, gap_version_pin,
               gap_shape_enforced, gap_kid_swap, gap_emit_roundtrip,
               gap_inventory,
               repin_forged_signature, repin_unknown_kid,
               repin_jku_mismatch, repin_tampered_capabilities,
               repin_unknown_field_covered, repin_deterministic_emit,
               repin_green_check):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - never die mid-battery
            _fail(fn.__name__, exc)
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("== %d HELD / %d BREAK / %d ERROR ==" % (held, brk, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
