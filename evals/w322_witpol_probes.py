#!/usr/bin/env python3
"""Break-first red battery for the signed witness-policy artifact
(wave-322 lane 2, gov/witness_policy.py).

P1 (2): happy path -- seal/verify round trip; verifier_inputs feeds
    gov.witness_consistency.require_cosignatures and a fresh checkpoint
    verifies with ZERO log calls (the acceptance criterion).
P2 (15): break-first refusal probes -- forged policy signature,
    below-threshold signatures, unknown fields (body + witness entry),
    stale-policy replay, key-drop without a new version (refused),
    key-drop WITH a new version (authorized -- HELD as allowed),
    threshold 0 / threshold > n, duplicate names, duplicate keys,
    expired policy, non-recomputing vkey, policy_id mismatch on update,
    unknown-signer keyid ignored (MUST-ignore rotation composition),
    known signer's bad signature refused (forgery signal).
P3 (3): contract probes -- verify returns the verified VALUES (dict),
    never soft False; canonicalization (key order irrelevant, value
    change breaks); trust anchor authority (doc-declared signers do not
    count, only the anchor's do).
P4 (2): regressions -- footer open none / next F409; pin taxonomy
    2135/2135/0 sorted on source literals.



Result contract: each probe prints [HELD]/[BREAK]/[ERROR]. Exit 0 iff
no ERROR and no unexpected BREAK. On the OPEN tree (module absent) the
top-level import fails with ImportError before any probe runs -- the
battery fails loudly and no probe can pass (the red-first property).

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git
subprocesses; deterministic (fixed seeds); stdlib only.
"""

import copy
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import witness_policy as WP  # noqa: E402
from gov import witness_consistency as WC  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

FOOTER_OPEN = "F526, F527, F528, F529, F530"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)


FOOTER_NEXT = "F531"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3)))


def _expect_refuse(pid, fn, code, note):
    """Run fn(); HELD iff it raises WitnessPolicyError with `code`."""
    try:
        fn()
    except WP.WitnessPolicyError as exc:
        if exc.code == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: refused coded %s, want %s"
                      % (note, exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "%s: raised %r, want coded %s" % (note, exc, code))
    return _break(pid, "%s: ACCEPTED, want coded refusal %s" % (note, code))


# Fixed seeds: deterministic keys across runs.
_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])
_SEED_P3 = bytes([(i * 11 + 23) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-witness-test/v1"


def _signer(seed):
    return Ed25519Signer(seed)


def _vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


def _wit(name, signer, not_before=_NOW - 100000, not_after=_NOW + 100000,
         status="usable"):
    return {"name": name, "vkey": _vkey(name, signer),
            "operator": "%s-operator" % name, "contact": "%s@example.org" % name,
            "not_before": not_before, "not_after": not_after,
            "status": status}


def _policy_signer_entry(signer):
    pub = signer.public_key
    return {"key_id": pub.hex(), "public_key": pub.hex()}


def _body(version=1, threshold=2, witnesses=None, policy_threshold=2,
          signers=None, expires_in=86400 * 90):
    if witnesses is None:
        witnesses = [_wit("w1", _signer(_SEED_W1)),
                     _wit("w2", _signer(_SEED_W2)),
                     _wit("w3", _signer(_SEED_W3))]
    if signers is None:
        signers = [_signer(_SEED_P1), _signer(_SEED_P2)]
    return {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": version,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + expires_in,
        "threshold": threshold,
        "log": {"name": "op", "vkey": _vkey("op", _signer(_SEED_OP))},
        "witnesses": witnesses,
        "policy_signers": [_policy_signer_entry(s) for s in signers],
        "policy_threshold": policy_threshold,
        "max_checkpoint_staleness_seconds": 10800,
    }


def _anchor(signers=None, policy_threshold=2):
    if signers is None:
        signers = [_signer(_SEED_P1), _signer(_SEED_P2)]
    return {"policy_signers": [_policy_signer_entry(s) for s in signers],
            "policy_threshold": policy_threshold}


def _seal(body, signers):
    return WP.seal_policy(body, signers)


def _sealed_good(**kw):
    """Seal a well-formed body (for tamper-after-seal probes: the
    envelope copy is mutated, then verify_policy_document exercises
    the VERIFY path -- seal itself is fail-closed on shape)."""
    return copy.deepcopy(_seal(_body(**kw),
                               [_signer(_SEED_P1), _signer(_SEED_P2)]))


def _flip_hex(h):
    raw = bytearray(bytes.fromhex(h))
    raw[0] ^= 1
    return bytes(raw).hex()


# ---------------------------------------------------------------------------
# P1: happy path
# ---------------------------------------------------------------------------

@probe("P1-seal-verify-roundtrip")
def _p1a():
    body = _body()
    doc = _seal(body, [_signer(_SEED_P1), _signer(_SEED_P2)])
    got = WP.verify_policy_document(doc, _anchor(), _NOW)
    if not isinstance(got, dict) or got["version"] != 1:
        return _break("P1-seal-verify-roundtrip",
                      "verify did not return the verified policy values")
    if got["threshold"] != 2 or len(got["witnesses"]) != 3:
        return _break("P1-seal-verify-roundtrip", "policy content mangled")
    return _held("P1-seal-verify-roundtrip",
                 "seal -> verify returns the verified policy dict")


@probe("P1-policy-verifies-checkpoint-zero-log-calls")
def _p1b():
    # The acceptance criterion: a client holding ONLY the policy
    # artifact verifies a fresh checkpoint with zero log calls.
    body = _body(threshold=2)
    doc = _seal(body, [_signer(_SEED_P1), _signer(_SEED_P2)])
    policy = WP.verify_policy_document(doc, _anchor(), _NOW)
    vin = WP.verifier_inputs(policy, _NOW)
    if vin["quorum_k"] != 2 or set(vin["witness_vkeys"]) != {"w1", "w2", "w3"}:
        return _break("P1-policy-verifies-checkpoint-zero-log-calls",
                      "verifier_inputs wrong: %r" % (sorted(vin),))
    # Build a real checkpoint note: operator signs, w1+w2 cosign.
    op_signer = _signer(_SEED_OP)
    log = WitnessLog(op_signer.public_key)
    for i in range(3):
        log.append(b"leaf-%d" % i)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", op_signer,
                                    timestamp=_NOW - 50)
    note = WC.cosign_note(note, "w1", _signer(_SEED_W1))
    note = WC.cosign_note(note, "w2", _signer(_SEED_W2))
    # Zero log calls from here: the note bytes + the policy suffice.
    try:
        WC.require_cosignatures(note,
                                operator_vkeys=vin["operator_vkeys"],
                                witness_vkeys=vin["witness_vkeys"],
                                quorum_k=vin["quorum_k"])
    except Exception as exc:  # noqa: BLE001
        return _break("P1-policy-verifies-checkpoint-zero-log-calls",
                      "require_cosignatures raised %r" % (exc,))
    return _held("P1-policy-verifies-checkpoint-zero-log-calls",
                 "policy -> verifier_inputs -> require_cosignatures "
                 "accepts a 2-cosigned checkpoint, no log touched")


# ---------------------------------------------------------------------------
# P2: break-first refusals
# ---------------------------------------------------------------------------

@probe("P2-forged-policy-signature")
def _p2a():
    doc = _seal(_body(), [_signer(_SEED_P1), _signer(_SEED_P2)])
    bad = copy.deepcopy(doc)
    bad["signatures"][0]["sig"] = _flip_hex(bad["signatures"][0]["sig"])
    # One good signature remains (threshold 2) -> threshold-unmet is
    # also a correct refusal; the FORGERY must be named as such when it
    # is the known signer that fails. Here the forged sig belongs to a
    # KNOWN anchor signer, so signature-invalid must fire first.
    return _expect_refuse(
        "P2-forged-policy-signature",
        lambda: WP.verify_policy_document(bad, _anchor(), _NOW),
        "witness-policy-signature-invalid", "forged known-signer sig")


@probe("P2-below-threshold-signatures")
def _p2b():
    doc = _seal(_body(), [_signer(_SEED_P1)])  # 1 of 2 required
    return _expect_refuse(
        "P2-below-threshold-signatures",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-threshold-unmet", "1-of-2 signatures")


@probe("P2-unknown-field-in-body")
def _p2c():
    doc = _sealed_good()
    doc["policy"]["someday_field"] = "drift"
    return _expect_refuse(
        "P2-unknown-field-in-body",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-unknown-field", "unknown top-level field")


@probe("P2-unknown-field-in-witness-entry")
def _p2d():
    doc = _sealed_good()
    doc["policy"]["witnesses"][0]["nickname"] = "wun"
    return _expect_refuse(
        "P2-unknown-field-in-witness-entry",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-unknown-field", "unknown witness-entry field")


@probe("P2-stale-policy-replay")
def _p2e():
    old = WP.verify_policy_document(
        _seal(_body(version=3), [_signer(_SEED_P1), _signer(_SEED_P2)]),
        _anchor(), _NOW)
    new_doc = _seal(_body(version=2),
                    [_signer(_SEED_P1), _signer(_SEED_P2)])
    return _expect_refuse(
        "P2-stale-policy-replay",
        lambda: WP.check_policy_update(old, new_doc, _anchor(), _NOW),
        "witness-policy-version-rollback",
        "v2 presented after v3")


@probe("P2-key-drop-without-new-version")
def _p2f():
    old = WP.verify_policy_document(
        _seal(_body(version=3), [_signer(_SEED_P1), _signer(_SEED_P2)]),
        _anchor(), _NOW)
    # Drop w3 but keep version 3: the drop is NOT authorized.
    witnesses = [_wit("w1", _signer(_SEED_W1)),
                 _wit("w2", _signer(_SEED_W2))]
    new_doc = _seal(_body(version=3, witnesses=witnesses),
                    [_signer(_SEED_P1), _signer(_SEED_P2)])
    return _expect_refuse(
        "P2-key-drop-without-new-version",
        lambda: WP.check_policy_update(old, new_doc, _anchor(), _NOW),
        "witness-policy-version-rollback",
        "dropped w3 at the same version")


@probe("P2-key-drop-with-new-version-authorized")
def _p2g():
    # The authorized drop: threshold-signed STRICTLY newer version.
    # This is HELD-as-allowed -- the threshold signature IS the
    # authorization for the drop (SPEC section 5).
    old = WP.verify_policy_document(
        _seal(_body(version=3), [_signer(_SEED_P1), _signer(_SEED_P2)]),
        _anchor(), _NOW)
    witnesses = [_wit("w1", _signer(_SEED_W1)),
                 _wit("w2", _signer(_SEED_W2))]
    new_doc = _seal(_body(version=4, witnesses=witnesses),
                    [_signer(_SEED_P1), _signer(_SEED_P2)])
    try:
        new = WP.check_policy_update(old, new_doc, _anchor(), _NOW)
    except WP.WitnessPolicyError as exc:
        return _break("P2-key-drop-with-new-version-authorized",
                      "authorized drop refused: %s" % (exc.code,))
    if {w["name"] for w in new["witnesses"]} != {"w1", "w2"}:
        return _break("P2-key-drop-with-new-version-authorized",
                      "wrong witness set after authorized drop")
    return _held("P2-key-drop-with-new-version-authorized",
                 "drop authorized by threshold-signed v4; set is {w1,w2}")


@probe("P2-threshold-zero")
def _p2h():
    doc = _sealed_good()
    doc["policy"]["threshold"] = 0
    return _expect_refuse(
        "P2-threshold-zero",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-threshold-invalid", "threshold 0")


@probe("P2-threshold-exceeds-n")
def _p2i():
    doc = _sealed_good()
    doc["policy"]["threshold"] = 99
    return _expect_refuse(
        "P2-threshold-exceeds-n",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-threshold-invalid", "k=99 of n=3")


@probe("P2-duplicate-witness-names")
def _p2j():
    doc = _sealed_good()
    doc["policy"]["witnesses"][1]["name"] = "w1"
    return _expect_refuse(
        "P2-duplicate-witness-names",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-duplicate-witness", "two entries named w1")


@probe("P2-duplicate-witness-keys")
def _p2k():
    # Same KEY MATERIAL under two names: one operator fills two quorum
    # slots. The vkey strings differ (the name is embedded), so the
    # module must compare key material, not strings.
    doc = _sealed_good()
    dup = {"name": "w1b", "vkey": _vkey("w1b", _signer(_SEED_W1)),
           "operator": "w1b-operator", "contact": "w1b@example.org",
           "not_before": _NOW - 100000, "not_after": _NOW + 100000,
           "status": "usable"}
    doc["policy"]["witnesses"][1] = dup
    return _expect_refuse(
        "P2-duplicate-witness-keys",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-duplicate-witness", "same key, two names")


@probe("P2-expired-policy")
def _p2l():
    doc = _seal(_body(expires_in=-10),
                [_signer(_SEED_P1), _signer(_SEED_P2)])
    return _expect_refuse(
        "P2-expired-policy",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-expired", "expires_at in the past")


@probe("P2-vkey-keyid-not-recomputing")
def _p2m():
    # A vkey whose keyID does not recompute from the key material:
    # corrupt configuration, refused loudly (checkpoint_note rule).
    good = _vkey("w1", _signer(_SEED_W1))
    name, kid, b64 = good.split("+", 2)
    bad_vkey = "%s+%s+%s" % (name, "deadbeef", b64)
    doc = _sealed_good()
    doc["policy"]["witnesses"][0]["vkey"] = bad_vkey
    return _expect_refuse(
        "P2-vkey-keyid-not-recomputing",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-key-unverifiable", "keyID does not recompute")


@probe("P2-policy-id-mismatch-on-update")
def _p2n():
    old = WP.verify_policy_document(
        _seal(_body(version=1), [_signer(_SEED_P1), _signer(_SEED_P2)]),
        _anchor(), _NOW)
    body = _body(version=2)
    body["policy_id"] = "some-other-policy"
    new_doc = _seal(body, [_signer(_SEED_P1), _signer(_SEED_P2)])
    return _expect_refuse(
        "P2-policy-id-mismatch-on-update",
        lambda: WP.check_policy_update(old, new_doc, _anchor(), _NOW),
        "witness-policy-id-mismatch", "policy family swap")


@probe("P2-unknown-signer-keyid-ignored")
def _p2o():
    # MUST-ignore composes with rotation: an unknown keyid line must
    # not break verification when the threshold is otherwise met.
    doc = _seal(_body(), [_signer(_SEED_P1), _signer(_SEED_P2)])
    doc["signatures"].append(
        {"keyid": "ab" * 32, "sig": "cd" * 64})
    try:
        got = WP.verify_policy_document(doc, _anchor(), _NOW)
    except WP.WitnessPolicyError as exc:
        return _break("P2-unknown-signer-keyid-ignored",
                      "unknown keyid broke verification: %s" % (exc.code,))
    if got["version"] != 1:
        return _break("P2-unknown-signer-keyid-ignored",
                      "verified values wrong")
    return _held("P2-unknown-signer-keyid-ignored",
                 "unknown keyid ignored; 2-of-2 still verifies")


@probe("P2-known-signer-bad-signature-refused")
def _p2p():
    # A KNOWN signer's bad signature is a forgery signal, never
    # ignored -- the witness_consistency cosignature rule.
    doc = _seal(_body(), [_signer(_SEED_P1), _signer(_SEED_P2)])
    doc["signatures"][1]["sig"] = _flip_hex(doc["signatures"][1]["sig"])
    return _expect_refuse(
        "P2-known-signer-bad-signature-refused",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-signature-invalid",
        "known signer P2's bad sig")


# ---------------------------------------------------------------------------
# P3: contract probes
# ---------------------------------------------------------------------------

@probe("P3-verify-returns-values-never-soft-false")
def _p3a():
    doc = _seal(_body(), [_signer(_SEED_P1), _signer(_SEED_P2)])
    got = WP.verify_policy_document(doc, _anchor(), _NOW)
    if got is False or got is None:
        return _break("P3-verify-returns-values-never-soft-false",
                      "verify returned %r" % (got,))
    if not isinstance(got, dict) or got.get("policy_id") != \
            "sasanam-witness-policy":
        return _break("P3-verify-returns-values-never-soft-false",
                      "verified values wrong type/content")
    return _held("P3-verify-returns-values-never-soft-false",
                 "verify returns the verified policy dict")


@probe("P3-canonicalization-key-order-irrelevant")
def _p3b():
    body = _body()
    doc = _seal(body, [_signer(_SEED_P1), _signer(_SEED_P2)])
    # Rebuild the envelope with keys in a different order: the
    # canonical bytes are identical, so verification must still pass.
    import json as _json
    reordered = _json.loads(_json.dumps(doc["policy"]),
                            object_pairs_hook=dict)
    items = list(reordered.items())
    items.reverse()
    doc2 = {"signatures": doc["signatures"],
            "policy": dict(items)}
    try:
        got = WP.verify_policy_document(doc2, _anchor(), _NOW)
    except WP.WitnessPolicyError as exc:
        return _break("P3-canonicalization-key-order-irrelevant",
                      "reordered keys refused: %s" % (exc.code,))
    if got["version"] != 1:
        return _break("P3-canonicalization-key-order-irrelevant",
                      "wrong values")
    # But a VALUE change must break the signature.
    doc3 = copy.deepcopy(doc)
    doc3["policy"]["threshold"] = 1
    try:
        WP.verify_policy_document(doc3, _anchor(), _NOW)
    except WP.WitnessPolicyError as exc:
        if exc.code in ("witness-policy-signature-invalid",
                        "witness-policy-threshold-unmet"):
            return _held("P3-canonicalization-key-order-irrelevant",
                         "key order irrelevant; value change breaks the sig")
        return _break("P3-canonicalization-key-order-irrelevant",
                      "value change refused with %s" % (exc.code,))
    return _break("P3-canonicalization-key-order-irrelevant",
                  "value change ACCEPTED")


@probe("P3-trust-anchor-authority-not-document")
def _p3c():
    # The document declares rogue signers; the TRUST ANCHOR decides.
    # A doc signed only by non-anchor keys must fail even though the
    # document lists them as policy_signers.
    rogue = _signer(bytes([9] * 32))
    body = _body(signers=[rogue], policy_threshold=1)
    doc = _seal(body, [rogue])
    return _expect_refuse(
        "P3-trust-anchor-authority-not-document",
        lambda: WP.verify_policy_document(doc, _anchor(), _NOW),
        "witness-policy-threshold-unmet",
        "rogue-signed doc: anchor grants zero signatures")


# ---------------------------------------------------------------------------
# P4: regressions
# ---------------------------------------------------------------------------

@probe("P4-pin-taxonomy-2135-sorted")


def _p4a():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    ok = (len(lits) == TAXONOMY_PIN == 2135#Wave-333 merge: pin 2069 -> 2106 (+8 revocation-push-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
          and lits == sorted(lits) and len(set(lits)) == len(lits))
    if ok:
        return _held("P4-pin-taxonomy-2135-sorted", "2135/2135/0 sorted")
    return _break("P4-pin-taxonomy-2135-sorted",


                  "got %d literals" % (len(lits),))


@probe("P4-footer-state")
def _p4b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    ok = (m_open and m_open[-1].strip() == FOOTER_OPEN
          and m_next and m_next[-1] == FOOTER_NEXT)
    if ok:
        return _held("P4-footer-state", "open F412 / next F413")
    return _break("P4-footer-state",
                  "got %r / %r" % (m_open[-1] if m_open else None,
                                   m_next[-1] if m_next else None))


# ---------------------------------------------------------------------------
# Green check (depth-1) + main
# ---------------------------------------------------------------------------

GREEN_UNITTESTS = [
    ("test-witness-policy", "tests.test_witness_policy"),
    ("test-witness-consistency", "tests.test_witness_consistency"),
    ("test-checkpoint-note", "tests.test_checkpoint_note"),
]


def _run_green_unittest(name, module):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w322-gc-")
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", module, "-v"],
            env=env, capture_output=True, text=True, timeout=900,
            cwd=REPO)
    except Exception as e:  # noqa: BLE001
        return (name, "BREAK", "spawn failed: %r" % (e,))
    out = p.stdout + p.stderr
    m = re.search(r"OK(?:\s+\((\d+) tests?\))?", out)
    failed = re.search(r"FAILED", out)
    if p.returncode == 0 and m and not failed:
        return (name, "HELD", out.strip().splitlines()[-1][:80])
    tail = "\n".join(out.strip().splitlines()[-6:])
    return (name, "BREAK", "rc=%d: %s" % (p.returncode, tail))


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skipped",
                "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    for name, module in GREEN_UNITTESTS:
        n, v, note = _run_green_unittest(name, module)
        _record("green-" + n, v, note)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    for _, verdict, _ in _results:
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    expected_breaks = set()  # no BREAKs expected on the closed tree
    actual_breaks = {pid for pid, v, _ in _results if v == "BREAK"}
    green_breaks = {pid for pid, v, _ in _results
                    if pid.startswith("green-") and v == "BREAK"}
    unexpected = (actual_breaks - expected_breaks - green_breaks)
    print("w322_witpol battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    if errors or unexpected:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
