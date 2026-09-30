#!/usr/bin/env python3
"""Wave-238 lane D: independent-corroboration consumption (VeritasActa/Acta #3).

ACTA-03's consumption rule (prose re-derived): consumers independently
corroborate each evidence item against their OWN trust policy before acting
on it. Source provenance must be independent of the gated runtime (never
"self-attested"); key inequality between corroborating sources is
necessary.

Attack shapes at the public seams (break-first, red-first on base):

* an envelope carrying evidence from a single source, consumed without
  independent corroboration, refuses ``corroboration-uncorroborated`` --
  a lone source cannot corroborate itself; the consumer refuses fail-closed
  instead of acting on uncorroborated evidence;
* two evidence items presented as distinct sources (different source_id)
  but carrying the SAME key_id refuse ``corroboration-key-inequality`` --
  presented as independent corroboration but provably not key-independent;
* an evidence item whose provenance resolves to the gated runtime's own
  key refuses ``corroboration-unattested`` -- the runtime attesting its
  own evidence is self-attestation, even with a valid signature;
* an item signed under a key_id the consumer's trust policy does not hold
  refuses ``corroboration-untrusted-source`` -- the consumer cannot
  corroborate against key material it does not independently hold;
* a key_id the policy holds but with a broken/tampered signature refuses
  ``corroboration-signature-invalid`` -- the policy's own material says
  the evidence was edited after signing;
* a malformed envelope (evidence[] missing, wrong shapes, bad hex)
  refuses ``corroboration-malformed`` -- shape violations are refusals,
  never silent skips;
* two items, two INDEPENDENT key_ids, both signatures verifying against
  the consumer's own policy, are consumed -- the happy path.

Seams under test:
* gov/corroborated_consumption.py -- consume, TrustPolicy,
  CorroboratedConsumptionError codes, CORROBORATION_* constants,
  MIN_INDEPENDENT_KEYS.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-237 HEAD dcfd52d2ecbacce8eff0cb5ee27f6332cb103dee.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g238d
  TMPDIR=/var/tmp/g238d ~/workspace/.gov-venv/bin/python evals/w238_corroboration_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import corroborated_consumption as _cc
    from gov import ed25519 as _ed25519
    HAVE_NEW_API = all(hasattr(_cc, n) for n in (
        "consume", "TrustPolicy", "CorroboratedConsumptionError",
        "CORROBORATION_MALFORMED", "CORROBORATION_UNATTESTED",
        "CORROBORATION_UNTRUSTED_SOURCE", "CORROBORATION_SIGNATURE_INVALID",
        "CORROBORATION_KEY_INEQUALITY", "CORROBORATION_UNCORROBORATED",
        "MIN_INDEPENDENT_KEYS", "key_id_of"))
except ImportError:
    _cc = None
    _ed25519 = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "corroboration-single-source-uncorroborated",
    "corroboration-shared-key-inequality",
    "corroboration-two-independent-keys-consumed",
    "corroboration-self-attested-refused",
    "corroboration-unknown-key-refused",
    "corroboration-tampered-signature-refused",
    "corroboration-malformed-envelope-refused",
]


def _hex(b):
    return b.hex()


def _fixture():
    """Deterministic test key material (fixed seeds, never secret)."""
    seed_a = bytes(range(32))
    seed_b = bytes(255 - i for i in range(32))
    seed_r = bytes((7 * i + 3) % 256 for i in range(32))
    pub_a, pub_b, pub_r = (_ed25519.publickey(s) for s in (seed_a, seed_b, seed_r))
    return (seed_a, pub_a), (seed_b, pub_b), (seed_r, pub_r)


def _sign_item(seed, pub, dimension, state, source_id):
    kid = _cc.key_id_of(pub)
    item = {
        "dimension": dimension,
        "state": state,
        "source": {
            "source_id": source_id,
            "key_id": kid,
            "signature": None,
        },
    }
    body = _cc.canonical_item_bytes(item)
    item["source"]["signature"] = _hex(_ed25519.sign(seed, body))
    return item


def _policy(pub_a, pub_b, pub_r, require=("policy_applied",)):
    return _cc.TrustPolicy(
        trusted_keys={_cc.key_id_of(pub_a): pub_a, _cc.key_id_of(pub_b): pub_b},
        runtime_key_id=_cc.key_id_of(pub_r),
        require_dimensions=frozenset(require),
    )


def _expect_refuse(code, fn):
    try:
        out = fn()
    except _cc.CorroboratedConsumptionError as exc:
        if exc.code == code:
            return ("HELD", "")
        return ("BREAK", "refused with %r, expected %r" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    return ("BREAK", "no refusal, consumed: %r" % (out,))


def probe_single_source_uncorroborated():
    (seed_a, pub_a), (_seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    env = {"envelope_id": "env-1",
           "evidence": [_sign_item(seed_a, pub_a, "policy_applied",
                                   "allowed", "audit-service-a")]}
    return _expect_refuse(_cc.CORROBORATION_UNCORROBORATED,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


def probe_shared_key_inequality():
    (seed_a, pub_a), (_seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    # Two "distinct" sources, same key material: not key-independent.
    env = {"envelope_id": "env-2",
           "evidence": [_sign_item(seed_a, pub_a, "policy_applied",
                                   "allowed", "audit-service-a"),
                        _sign_item(seed_a, pub_a, "policy_applied",
                                   "allowed", "audit-service-b")]}
    return _expect_refuse(_cc.CORROBORATION_KEY_INEQUALITY,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


def probe_two_independent_keys_consumed():
    (seed_a, pub_a), (seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    env = {"envelope_id": "env-3",
           "evidence": [_sign_item(seed_a, pub_a, "policy_applied",
                                   "allowed", "audit-service-a"),
                        _sign_item(seed_b, pub_b, "policy_applied",
                                   "allowed", "audit-service-b")]}
    try:
        receipt = _cc.consume(env, _policy(pub_a, pub_b, pub_r))
    except _cc.CorroboratedConsumptionError as exc:
        return ("BREAK", "refused %r: %s" % (exc.code, exc.detail))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    kids = set(receipt.get("corroborated", {}).get("policy_applied", []))
    if kids == {_cc.key_id_of(pub_a), _cc.key_id_of(pub_b)}:
        return ("HELD", "")
    return ("BREAK", "receipt names wrong keys: %r" % (kids,))


def probe_self_attested_refused():
    (seed_a, pub_a), (_seed_b, pub_b), (seed_r, pub_r) = _fixture()
    # Valid signature, but under the gated runtime's OWN key: self-attested.
    env = {"envelope_id": "env-4",
           "evidence": [_sign_item(seed_r, pub_r, "policy_applied",
                                   "allowed", "gated-runtime")]}
    return _expect_refuse(_cc.CORROBORATION_UNATTESTED,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


def probe_unknown_key_refused():
    (seed_a, pub_a), (_seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    seed_c = bytes((11 * i + 5) % 256 for i in range(32))
    pub_c = _ed25519.publickey(seed_c)
    env = {"envelope_id": "env-5",
           "evidence": [_sign_item(seed_c, pub_c, "policy_applied",
                                   "allowed", "outsider-c")]}
    return _expect_refuse(_cc.CORROBORATION_UNTRUSTED_SOURCE,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


def probe_tampered_signature_refused():
    (seed_a, pub_a), (_seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    item = _sign_item(seed_a, pub_a, "policy_applied", "allowed",
                      "audit-service-a")
    item["state"] = "denied"  # edit after signing
    env = {"envelope_id": "env-6", "evidence": [item]}
    return _expect_refuse(_cc.CORROBORATION_SIGNATURE_INVALID,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


def probe_malformed_envelope_refused():
    (seed_a, pub_a), (_seed_b, pub_b), (_seed_r, pub_r) = _fixture()
    env = {"envelope_id": "env-7"}  # evidence[] missing
    return _expect_refuse(_cc.CORROBORATION_MALFORMED,
        lambda: _cc.consume(env, _policy(pub_a, pub_b, pub_r)))


_PROBES = {
    "corroboration-single-source-uncorroborated":
        probe_single_source_uncorroborated,
    "corroboration-shared-key-inequality": probe_shared_key_inequality,
    "corroboration-two-independent-keys-consumed":
        probe_two_independent_keys_consumed,
    "corroboration-self-attested-refused": probe_self_attested_refused,
    "corroboration-unknown-key-refused": probe_unknown_key_refused,
    "corroboration-tampered-signature-refused":
        probe_tampered_signature_refused,
    "corroboration-malformed-envelope-refused":
        probe_malformed_envelope_refused,
}


def _run_green_check():
    print("green check: depth-1; skipping (adjacent battery runs are "
          "coordinator-gated)")
    return True


def main():
    t0 = time.time()
    results = []
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            results.append((name, "GAP", "module absent"))
    else:
        for name in PROBE_NAMES:
            fn = _PROBES[name]
            try:
                verdict, note = fn()
            except Exception as exc:  # noqa: BLE001
                verdict, note = "ERROR", "%s: %s\n%s" % (
                    type(exc).__name__, exc, traceback.format_exc(limit=3))
            results.append((name, verdict, note))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        tail = (" -- " + note) if note else ""
        print("%-46s %s%s" % (name, verdict, tail))
    print("----")
    print("%d HELD / %d GAP / %d BREAK / %d ERROR (%d probes, %.1fs)" % (
        held, gap, brk, err, len(results), time.time() - t0))
    if not GREEN_SKIP:
        _run_green_check()
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
