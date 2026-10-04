"""Wave-284 lane 6 red-first battery: sops-pattern envelope encryption.

Base: wave-283 push 9a7cffc. The gap under test is the absence of
envelope encryption for offline evidence bundles: bundles ship as
cleartext (auditors must trust the transport), there is no
per-recipient key scoping, no bundle-ID-as-AAD binding (bundle
swapping is undetectable at the envelope), no auditable recipient
policy, and no re-keying ceremony. getsops/sops (MPL-2.0, pattern
only -- clean-room Python reimplementation, zero vendored code)
supplies the mechanisms: per-bundle data key, per-recipient wraps
(age-style offline / KMS-style custody), bundle-ID-as-AAD, integrity
MAC, recipient policy as checked-in config, updatekeys/rotate.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (secrets only for random
key/nonce material, never asserted on). Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g284-sops && TMPDIR=/var/tmp/g284-sops \
    ~/workspace/.gov-venv/bin/python evals/w284_sops_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g284-sops2 \
    ~/workspace/.gov-venv/bin/python evals/w284_sops_probes.py
"""

import copy
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w284-sops")
os.environ.setdefault("TMPDIR", "/var/tmp/g284-sops")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-284 lane 6: pin 1587 -> 1594 (+7 sops-envelope codes).
TAXONOMY_PIN = 1964 # Wave-284 lane 6: pin 1587 -> 1594 (+7 envelope/recipient-policy codes).; Wave-284 lane 6: pin 1594 -> 1595 (+1 envelope-recipient-unknown); Wave-284 merge: pin 1595 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

PLUGIN_META = ("sops-envelope", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_module(probe_id):
    try:
        from gov import bundle_envelope as be
        return be
    except ImportError:
        _record(probe_id, "BREAK", "gov.bundle_envelope absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted"
            % (TAXONOMY_PIN, TAXONOMY_PIN))


# RFC 7748 section 6.1 X25519 test vector (fetched from
# https://www.rfc-editor.org/rfc/rfc7748 at build time).
_RFC7748_A_PRIV = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
_RFC7748_A_PUB = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
_RFC7748_B_PRIV = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
_RFC7748_B_PUB = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
_RFC7748_SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def _ed_seed():
    from gov import ed25519 as _ed
    return _ed.generate_seed()


def _ed_pub(seed):
    from gov import ed25519 as _ed
    return _ed.publickey(seed)


def _x25519_keypair(be):
    priv = secrets.token_bytes(32)
    return priv, be.x25519_pub(priv)


def _seal_fixture(be, n_recipients=2):
    """Two offline recipients + one signer; returns (env, keys, policy, seed)."""
    seed = _ed_seed()
    recips = []
    privs = {}
    for i in range(n_recipients):
        priv, pub = _x25519_keypair(be)
        rid = "auditor-%d" % i
        privs[rid] = priv
        recips.append({"id": rid, "type": "offline",
                       "x25519_pub": pub.hex()})
    policy = be.make_recipient_policy(recips)
    env = be.seal_envelope(b'{"seq":1,"verdict":"allow"}',
                           bundle_id="bundle-001",
                           policy=policy, signer_seed=seed)
    return env, privs, policy, seed


def p_x25519_vectors():
    be = _needs_module("p-x25519-vectors")
    if be is None:
        return
    if be.x25519_pub(_RFC7748_A_PRIV) != _RFC7748_A_PUB:
        return _record("p-x25519-vectors", "BREAK", "RFC7748 pub-A mismatch")
    if be.x25519_pub(_RFC7748_B_PRIV) != _RFC7748_B_PUB:
        return _record("p-x25519-vectors", "BREAK", "RFC7748 pub-B mismatch")
    if be.x25519(_RFC7748_A_PRIV, _RFC7748_B_PUB) != _RFC7748_SHARED:
        return _record("p-x25519-vectors", "BREAK", "RFC7748 shared mismatch")
    if be.x25519(_RFC7748_B_PRIV, _RFC7748_A_PUB) != _RFC7748_SHARED:
        return _record("p-x25519-vectors", "BREAK",
                       "RFC7748 shared mismatch (reverse)")
    _record("p-x25519-vectors", "HELD", "RFC 7748 section 6.1 vectors match")


def p_roundtrip():
    be = _needs_module("p-roundtrip")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    for rid, priv in privs.items():
        pt = be.open_envelope(env, recipient_id=rid, x25519_priv=priv,
                              trusted_signer_pubs=[pub],
                              expected_bundle_id="bundle-001")
        if pt != b'{"seq":1,"verdict":"allow"}':
            return _record("p-roundtrip", "BREAK",
                           "round-trip mismatch for %s" % rid)
    _record("p-roundtrip", "HELD", "seal/open round-trips for all recipients")


def _expect_code(be, probe_id, fn, code):
    try:
        fn()
    except be.EnvelopeError as exc:
        if exc.code == code:
            _record(probe_id, "HELD", "refused %s" % code)
        else:
            _record(probe_id, "BREAK",
                    "refused %s, want %s" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001 -- the probe wants the refusal contract
        _record(probe_id, "BREAK", "non-EnvelopeError: %r" % (exc,))
    else:
        _record(probe_id, "BREAK", "no refusal (want %s)" % code)


def _resign(be, env, seed):
    """Re-sign a (possibly tampered) envelope with the seal signer's key.

    Models the sops-trap threat: an AUTHORIZED sealer forges a tampered
    envelope. The signature then verifies, and the MAC layer must catch
    the forgery -- that is what the MAC defense-in-depth is for.
    """
    from gov import ed25519 as _ed
    from gov import signing as _signing
    body = json.dumps({k: v for k, v in env.items() if k != "sigs"},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")
    sig = _ed.sign(bytes(seed), body)
    env["sigs"] = [{"key_id": _signing.ed25519_key_id(_ed.publickey(seed)),
                    "sig": sig.hex()}]
    return env


def p_tamper_ciphertext():
    be = _needs_module("p-tamper-ciphertext")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    kw = dict(recipient_id=rid, x25519_priv=privs[rid],
              trusted_signer_pubs=[pub], expected_bundle_id="bundle-001")
    # Check order: authorship is verified before integrity. A tamper by
    # an EXTERNAL attacker (no signing key) dies at the signature.
    bad = copy.deepcopy(env)
    ct = bytearray(bytes.fromhex(bad["payload"]["ct"]))
    ct[0] ^= 0xFF
    bad["payload"]["ct"] = bytes(ct).hex()
    _expect_code(be, "p-tamper-ciphertext",
                 lambda: be.open_envelope(bad, **kw),
                 "envelope-signature-invalid")
    # A tamper by an AUTHORIZED sealer (re-signed) passes authorship, so
    # the encrypt-then-MAC layer must refuse it.
    bad2 = _resign(be, bad, seed)
    _expect_code(be, "p-tamper-ciphertext",
                 lambda: be.open_envelope(bad2, **kw),
                 "envelope-mac-failed")


def p_tamper_tag():
    be = _needs_module("p-tamper-tag")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    bad = copy.deepcopy(env)
    tag = bytearray(bytes.fromhex(bad["payload"]["tag"]))
    tag[-1] ^= 0x01
    bad["payload"]["tag"] = bytes(tag).hex()
    rid = next(iter(privs))
    bad = _resign(be, bad, seed)  # authorized-sealer forgery model
    _expect_code(
        be, "p-tamper-tag",
        lambda: be.open_envelope(bad, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-mac-failed")


def p_tamper_wrap():
    be = _needs_module("p-tamper-wrap")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    bad = copy.deepcopy(env)
    wct = bytearray(bytes.fromhex(bad["wraps"][0]["wrapped"]["ct"]))
    wct[0] ^= 0xFF
    bad["wraps"][0]["wrapped"]["ct"] = bytes(wct).hex()
    bad = _resign(be, bad, seed)  # authorized-sealer forgery model
    rid = bad["wraps"][0]["recipient_id"]
    _expect_code(
        be, "p-tamper-wrap",
        lambda: be.open_envelope(bad, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-unwrap-failed")


def p_wrong_privkey():
    be = _needs_module("p-wrong-privkey")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    wrong_priv, _ = _x25519_keypair(be)
    _expect_code(
        be, "p-wrong-privkey",
        lambda: be.open_envelope(env, recipient_id=rid,
                                 x25519_priv=wrong_priv,
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-unwrap-failed")


def p_recipient_isolation():
    be = _needs_module("p-recipient-isolation")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be, n_recipients=2)
    pub = _ed_pub(seed)
    rids = list(privs)
    # A's wrap bytes must not open under B's key (cross-recipient attempt).
    wrap_a = next(w for w in env["wraps"]
                  if w["recipient_id"] == rids[0])
    try:
        be._unwrap_data_key(wrap_a, privs[rids[1]], None,
                            env["bundle_sha256"])
    except be.EnvelopeError as exc:
        if exc.code == "envelope-unwrap-failed":
            return _record("p-recipient-isolation", "HELD",
                           "cross-recipient unwrap refused")
        return _record("p-recipient-isolation", "BREAK",
                       "wrong code %s" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _record("p-recipient-isolation", "BREAK", "non-EnvelopeError %r"
                       % (exc,))
    _record("p-recipient-isolation", "BREAK",
            "cross-recipient unwrap succeeded")


def p_aad_bundle_swap():
    be = _needs_module("p-aad-bundle-swap")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    # Same bytes, but the caller expects a different bundle identity:
    # bundle-ID-as-AAD must refuse.
    _expect_code(
        be, "p-aad-bundle-swap",
        lambda: be.open_envelope(env, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-999"),
        "envelope-aad-mismatch")


def p_header_tamper():
    be = _needs_module("p-header-tamper")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    kw = dict(recipient_id=rid, x25519_priv=privs[rid],
              trusted_signer_pubs=[pub], expected_bundle_id="bundle-001")
    # (a) Tamper the header MAC itself (authorized-sealer forgery model):
    # the unwrap inputs are intact, so the header-MAC layer must refuse.
    bad = _resign(be, copy.deepcopy(env), seed)
    hm = bytearray(bytes.fromhex(bad["header_mac"]))
    hm[0] ^= 0xFF
    bad["header_mac"] = bytes(hm).hex()
    bad = _resign(be, bad, seed)
    _expect_code(be, "p-header-tamper",
                 lambda: be.open_envelope(bad, **kw),
                 "envelope-mac-failed")
    # (b) Lie about the bundle digest in the header: the KDF salt binding
    # catches it at unwrap time -- still fail-closed, earlier layer.
    bad2 = copy.deepcopy(env)
    bad2["bundle_sha256"] = "0" * 64
    bad2 = _resign(be, bad2, seed)
    _expect_code(be, "p-header-tamper",
                 lambda: be.open_envelope(bad2, **kw),
                 "envelope-unwrap-failed")


def p_unsigned_envelope():
    be = _needs_module("p-unsigned-envelope")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    bad = copy.deepcopy(env)
    bad["sigs"] = []
    rid = next(iter(privs))
    _expect_code(
        be, "p-unsigned-envelope",
        lambda: be.open_envelope(bad, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-signature-invalid")


def p_wrong_signer():
    be = _needs_module("p-wrong-signer")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    other_pub = _ed_pub(_ed_seed())
    rid = next(iter(privs))
    _expect_code(
        be, "p-wrong-signer",
        lambda: be.open_envelope(env, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[other_pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-signature-invalid")


def p_custody_without_provider():
    be = _needs_module("p-custody-without-provider")
    if be is None:
        return
    seed = _ed_seed()
    policy = be.make_recipient_policy([
        {"id": "custody-vault", "type": "custody",
         "provider": "vault", "key_ref": "transit/bundle-keys"},
    ])
    _expect_code(
        be, "p-custody-without-provider",
        lambda: be.seal_envelope(b'{"seq":2}', bundle_id="bundle-002",
                                 policy=policy, signer_seed=seed),
        "envelope-custody-unavailable")


def p_custody_roundtrip():
    be = _needs_module("p-custody-roundtrip")
    if be is None:
        return
    seed = _ed_seed()
    wrap_key = secrets.token_bytes(32)

    def wrap(recipient_id, data_key):
        nonce, ct, tag = be.aead_seal(wrap_key, b"custody-wrap:" +
                                      recipient_id.encode(), data_key)
        return {"nonce": nonce.hex(), "ct": ct.hex(), "tag": tag.hex()}

    def unwrap(recipient_id, wrapped):
        return be.aead_open(wrap_key, b"custody-wrap:" +
                            recipient_id.encode(),
                            bytes.fromhex(wrapped["nonce"]),
                            bytes.fromhex(wrapped["ct"]),
                            bytes.fromhex(wrapped["tag"]))

    policy = be.make_recipient_policy([
        {"id": "custody-vault", "type": "custody",
         "provider": "vault", "key_ref": "transit/bundle-keys"},
    ])
    env = be.seal_envelope(b'{"seq":3}', bundle_id="bundle-003",
                           policy=policy, signer_seed=seed,
                           custody_wrap=wrap)
    pt = be.open_envelope(env, recipient_id="custody-vault",
                          custody_unwrap=unwrap,
                          trusted_signer_pubs=[_ed_pub(seed)],
                          expected_bundle_id="bundle-003")
    if pt != b'{"seq":3}':
        return _record("p-custody-roundtrip", "BREAK", "custody mismatch")
    _record("p-custody-roundtrip", "HELD",
            "custody recipient seals and opens via provider")


def p_rotate():
    be = _needs_module("p-rotate")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    events = []
    be.set_emit(events.append)
    try:
        new_env = be.rotate_envelope(
            env, recipient_id=next(iter(privs)),
            x25519_priv=privs[next(iter(privs))],
            policy=policy, signer_seed=seed)
    finally:
        be.set_emit(None)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    pt = be.open_envelope(new_env, recipient_id=rid, x25519_priv=privs[rid],
                          trusted_signer_pubs=[pub],
                          expected_bundle_id="bundle-001")
    if pt != b'{"seq":1,"verdict":"allow"}':
        return _record("p-rotate", "BREAK", "rotated envelope lost plaintext")
    old_key = be._unwrap_data_key(
        next(w for w in env["wraps"] if w["recipient_id"] == rid),
        privs[rid], None, env["bundle_sha256"])
    new_key = be._unwrap_data_key(
        next(w for w in new_env["wraps"] if w["recipient_id"] == rid),
        privs[rid], None, new_env["bundle_sha256"])
    if old_key == new_key:
        return _record("p-rotate", "BREAK", "data key not rotated")
    kinds = [e.get("event") for e in events]
    if "envelope-rotated" not in kinds:
        return _record("p-rotate", "BREAK", "no envelope-rotated audit event")
    # No key material in the audit events.
    blob = json.dumps(events)
    if old_key.hex() in blob or new_key.hex() in blob:
        return _record("p-rotate", "BREAK", "key material leaked to audit")
    _record("p-rotate", "HELD",
            "rotate: fresh data key, plaintext preserved, audited")


def p_rotate_wrong_credential():
    be = _needs_module("p-rotate-wrong-credential")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    wrong_priv, _ = _x25519_keypair(be)
    _expect_code(
        be, "p-rotate-wrong-credential",
        lambda: be.rotate_envelope(
            env, recipient_id=next(iter(privs)), x25519_priv=wrong_priv,
            policy=policy, signer_seed=seed),
        "envelope-rekey-refused")


def p_updatekeys_remove():
    be = _needs_module("p-updatekeys-remove")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be, n_recipients=2)
    rids = list(privs)
    kept = rids[0]
    dropped = rids[1]
    new_policy = be.make_recipient_policy([
        {"id": kept, "type": "offline",
         "x25519_pub": be.x25519_pub(privs[kept]).hex()},
    ])
    events = []
    be.set_emit(events.append)
    try:
        new_env = be.update_wraps(
            env, recipient_id=kept, x25519_priv=privs[kept],
            new_policy=new_policy, signer_seed=seed)
    finally:
        be.set_emit(None)
    pub = _ed_pub(seed)
    pt = be.open_envelope(new_env, recipient_id=kept,
                          x25519_priv=privs[kept],
                          trusted_signer_pubs=[pub],
                          expected_bundle_id="bundle-001")
    if pt != b'{"seq":1,"verdict":"allow"}':
        return _record("p-updatekeys-remove", "BREAK", "kept recipient lost")
    if any(w["recipient_id"] == dropped for w in new_env["wraps"]):
        return _record("p-updatekeys-remove", "BREAK",
                       "dropped recipient still wrapped")
    # S6: updatekeys keeps the SAME data key (not rotate semantics).
    old_key = be._unwrap_data_key(
        next(w for w in env["wraps"] if w["recipient_id"] == kept),
        privs[kept], None, env["bundle_sha256"])
    new_key = be._unwrap_data_key(
        next(w for w in new_env["wraps"] if w["recipient_id"] == kept),
        privs[kept], None, new_env["bundle_sha256"])
    if old_key != new_key:
        return _record("p-updatekeys-remove", "BREAK",
                       "updatekeys changed the data key")
    # S7: the ceremony is audited, with no key material.
    kinds = [e.get("event") for e in events]
    if "envelope-wraps-updated" not in kinds:
        return _record("p-updatekeys-remove", "BREAK",
                       "no envelope-wraps-updated audit event")
    blob = json.dumps(events)
    if old_key.hex() in blob or new_key.hex() in blob:
        return _record("p-updatekeys-remove", "BREAK",
                       "key material leaked to audit")
    _expect_code(
        be, "p-updatekeys-remove",
        lambda: be.open_envelope(new_env, recipient_id=dropped,
                                 x25519_priv=privs[dropped],
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="bundle-001"),
        "envelope-recipient-unknown")
    _record("p-updatekeys-remove", "HELD",
            "updatekeys: recipient removed, same data key, audited")


def p_policy_digest_tamper():
    # S1: the policy_digest binds the policy content at use time. A
    # policy edited after registration is refused, not silently honored.
    be = _needs_module("p-policy-digest-tamper")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    tampered = copy.deepcopy(policy)
    tampered["min_recipients"] = 2
    _expect_code(
        be, "p-policy-digest-tamper",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                                 policy=tampered, signer_seed=seed),
        "recipient-policy-invalid")
    tampered2 = copy.deepcopy(policy)
    extra_priv, extra_pub = _x25519_keypair(be)
    tampered2["recipients"].append({"id": "mallory", "type": "offline",
                                   "x25519_pub": extra_pub.hex()})
    _expect_code(
        be, "p-policy-digest-tamper",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                                 policy=tampered2, signer_seed=seed),
        "recipient-policy-invalid")
    # A hand-made policy with no digest at all is refused too.
    bare = {"format": "sops-envelope-policy/v1", "version": 1,
            "bundle_scope": "*", "min_recipients": 1,
            "recipients": [{"id": "auditor-0", "type": "offline",
                            "x25519_pub": be.x25519_pub(
                                privs["auditor-0"]).hex()}]}
    _expect_code(
        be, "p-policy-digest-tamper",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                                 policy=bare, signer_seed=seed),
        "recipient-policy-invalid")
    _record("p-policy-digest-tamper", "HELD",
            "tampered/digestless policies refused at use time")


def p_bundle_scope():
    # S4: bundle_scope is the creation-rule match. A policy scoped to
    # "evidence-bundle/" refuses to seal an out-of-scope bundle id.
    be = _needs_module("p-bundle-scope")
    if be is None:
        return
    seed = _ed_seed()
    priv, pub = _x25519_keypair(be)
    policy = be.make_recipient_policy(
        [{"id": "auditor-0", "type": "offline",
          "x25519_pub": pub.hex()}],
        bundle_scope="evidence-bundle/")
    env = be.seal_envelope(b'{"seq":9}', bundle_id="evidence-bundle/2026-10",
                           policy=policy, signer_seed=seed)
    pt = be.open_envelope(env, recipient_id="auditor-0", x25519_priv=priv,
                          trusted_signer_pubs=[_ed_pub(seed)])
    if pt != b'{"seq":9}':
        return _record("p-bundle-scope", "BREAK", "in-scope seal failed")
    _expect_code(
        be, "p-bundle-scope",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-001",
                                 policy=policy, signer_seed=seed),
        "recipient-policy-invalid")
    _record("p-bundle-scope", "HELD",
            "out-of-scope bundle refused at seal time")


def p_custody_open_without_provider():
    # S8: a custody wrap cannot be opened without the unwrap provider.
    be = _needs_module("p-custody-open-without-provider")
    if be is None:
        return
    seed = _ed_seed()
    wrap_key = secrets.token_bytes(32)

    def wrap(recipient_id, data_key):
        nonce, ct, tag = be.aead_seal(wrap_key, b"custody-wrap:",
                                      data_key)
        return {"nonce": nonce.hex(), "ct": ct.hex(), "tag": tag.hex()}

    policy = be.make_recipient_policy([
        {"id": "custody-vault", "type": "custody",
         "provider": "vault", "key_ref": "transit/bundle-keys"},
    ])
    env = be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                           policy=policy, signer_seed=seed,
                           custody_wrap=wrap)
    _expect_code(
        be, "p-custody-open-without-provider",
        lambda: be.open_envelope(env, recipient_id="custody-vault",
                                 trusted_signer_pubs=[_ed_pub(seed)],
                                 expected_bundle_id="bundle-009"),
        "envelope-custody-unavailable")


def p_custody_seal_bad_provider():
    # S5: a faulty custody provider is a coded refusal at seal time,
    # never a malformed envelope or a raw exception.
    be = _needs_module("p-custody-seal-bad-provider")
    if be is None:
        return
    seed = _ed_seed()
    policy = be.make_recipient_policy([
        {"id": "custody-vault", "type": "custody",
         "provider": "vault", "key_ref": "transit/bundle-keys"},
    ])

    def raising_wrap(recipient_id, data_key):
        raise RuntimeError("vault unreachable")

    def nonhex_wrap(recipient_id, data_key):
        return {"nonce": "zz", "ct": "00", "tag": "00"}

    _expect_code(
        be, "p-custody-seal-bad-provider",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                                 policy=policy, signer_seed=seed,
                                 custody_wrap=raising_wrap),
        "envelope-custody-unavailable")
    _expect_code(
        be, "p-custody-seal-bad-provider",
        lambda: be.seal_envelope(b'{"seq":9}', bundle_id="bundle-009",
                                 policy=policy, signer_seed=seed,
                                 custody_wrap=nonhex_wrap),
        "envelope-custody-unavailable")
    _record("p-custody-seal-bad-provider", "HELD",
            "faulty custody providers refused with a coded refusal")


def p_rekey_needs_signer_seed():
    # S3: the re-keying ceremony requires the ORIGINAL signer seed, not
    # just an authorized recipient credential.
    be = _needs_module("p-rekey-needs-signer-seed")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    other_seed = _ed_seed()
    rid = next(iter(privs))
    _expect_code(
        be, "p-rekey-needs-signer-seed",
        lambda: be.rotate_envelope(
            env, recipient_id=rid, x25519_priv=privs[rid],
            policy=policy, signer_seed=other_seed),
        "envelope-rekey-refused")
    _record("p-rekey-needs-signer-seed", "HELD",
            "rekey without the original signer seed refused")


def p_policy_invalid():
    be = _needs_module("p-policy-invalid")
    if be is None:
        return
    bad_cases = [
        ({"id": "a", "type": "offline", "x25519_pub": "zz"},
         "bad pubkey hex"),
        ({"id": "a", "type": "carrier-pigeon"},
         "unknown recipient type"),
        ([{"id": "a", "type": "offline",
           "x25519_pub": "00" * 32},
          {"id": "a", "type": "offline", "x25519_pub": "11" * 32}],
         "duplicate id"),
        ([], "empty recipient list"),
    ]
    for recips, note in bad_cases:
        if not isinstance(recips, list):
            recips = [recips]
        try:
            be.make_recipient_policy(recips)
        except be.EnvelopeError as exc:
            if exc.code != "recipient-policy-invalid":
                return _record("p-policy-invalid", "BREAK",
                               "%s: wrong code %s" % (note, exc.code))
        except Exception as exc:  # noqa: BLE001
            return _record("p-policy-invalid", "BREAK",
                           "%s: non-EnvelopeError %r" % (note, exc))
        else:
            return _record("p-policy-invalid", "BREAK",
                           "%s: accepted" % note)
    _record("p-policy-invalid", "HELD", "4 invalid policies refused")


def p_policy_change_audited():
    be = _needs_module("p-policy-change-audited")
    if be is None:
        return
    events = []
    be.set_emit(events.append)
    try:
        priv, pub = _x25519_keypair(be)
        be.make_recipient_policy(
            [{"id": "auditor-0", "type": "offline",
              "x25519_pub": pub.hex()}])
    finally:
        be.set_emit(None)
    kinds = [e.get("event") for e in events]
    if "recipient-policy-registered" not in kinds:
        return _record("p-policy-change-audited", "BREAK",
                       "policy registration not audited")
    # Public keys are public; private material must never appear in
    # the audit events (checked on the blob below).
    blob = json.dumps(events)
    if priv.hex() in blob:
        return _record("p-policy-change-audited", "BREAK",
                       "private key leaked to audit")
    _record("p-policy-change-audited", "HELD", "policy change audited")


def p_empty_bundle_refused():
    be = _needs_module("p-empty-bundle-refused")
    if be is None:
        return
    seed = _ed_seed()
    priv, pub = _x25519_keypair(be)
    policy = be.make_recipient_policy(
        [{"id": "a", "type": "offline", "x25519_pub": pub.hex()}])
    _expect_code(
        be, "p-empty-bundle-refused",
        lambda: be.seal_envelope(b"", bundle_id="bundle-e",
                                 policy=policy, signer_seed=seed),
        "envelope-seal-refused")


def p_strict_shape():
    be = _needs_module("p-strict-shape")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    bad = copy.deepcopy(env)
    bad["extra_field"] = "nope"
    rid = next(iter(privs))
    _expect_code(
        be, "p-strict-shape",
        lambda: be.open_envelope(bad, recipient_id=rid,
                                 x25519_priv=privs[rid],
                                 trusted_signer_pubs=[_ed_pub(seed)],
                                 expected_bundle_id="bundle-001"),
        "envelope-malformed")


def p_zero_pubkey_refused():
    be = _needs_module("p-zero-pubkey-refused")
    if be is None:
        return
    # The zero public key is refused at policy-build time (the earliest
    # layer), with the recipient-policy code.
    try:
        be.make_recipient_policy(
            [{"id": "a", "type": "offline", "x25519_pub": "00" * 32}])
    except be.EnvelopeError as exc:
        if exc.code == "recipient-policy-invalid":
            _record("p-zero-pubkey-refused", "HELD",
                    "zero pubkey refused at policy build")
        else:
            _record("p-zero-pubkey-refused", "BREAK",
                    "wrong code %s" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _record("p-zero-pubkey-refused", "BREAK",
                "non-EnvelopeError %r" % (exc,))
    else:
        _record("p-zero-pubkey-refused", "BREAK", "zero pubkey accepted")


def p_verify_twice():
    be = _needs_module("p-verify-twice")
    if be is None:
        return
    env, privs, policy, seed = _seal_fixture(be)
    pub = _ed_pub(seed)
    rid = next(iter(privs))
    kw = dict(recipient_id=rid, x25519_priv=privs[rid],
              trusted_signer_pubs=[pub], expected_bundle_id="bundle-001")
    if be.open_envelope(env, **kw) != be.open_envelope(env, **kw):
        return _record("p-verify-twice", "BREAK", "verify not deterministic")
    _record("p-verify-twice", "HELD", "open is deterministic")


def p_seal_event_audited():
    be = _needs_module("p-seal-event-audited")
    if be is None:
        return
    seed = _ed_seed()
    priv, pub = _x25519_keypair(be)
    policy = be.make_recipient_policy(
        [{"id": "a", "type": "offline", "x25519_pub": pub.hex()}])
    events = []
    be.set_emit(events.append)
    try:
        be.seal_envelope(b'{"seq":5}', bundle_id="bundle-005",
                         policy=policy, signer_seed=seed)
    finally:
        be.set_emit(None)
    kinds = [e.get("event") for e in events]
    if "envelope-sealed" not in kinds:
        return _record("p-seal-event-audited", "BREAK",
                       "seal not audited")
    _record("p-seal-event-audited", "HELD", "seal emits envelope-sealed")


def _green_check():
    if SKIP_GREEN:
        _record("green-adjacent", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    # Depth-1: the new unit tests must pass in a subprocess; no nesting.
    # (No pytest in the venv -- run the unittest file directly.)
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "tests/test_bundle_envelope.py", "-v"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=300)
    if proc.returncode == 0:
        _record("green-adjacent", "HELD", "tests/test_bundle_envelope.py green")
    else:
        _record("green-adjacent", "BREAK",
                "adjacent unit tests red:\n%s" % (proc.stdout + proc.stderr)[-2000:])


def main():
    p_taxonomy_pin()
    p_x25519_vectors()
    p_roundtrip()
    p_tamper_ciphertext()
    p_tamper_tag()
    p_tamper_wrap()
    p_wrong_privkey()
    p_recipient_isolation()
    p_aad_bundle_swap()
    p_header_tamper()
    p_unsigned_envelope()
    p_wrong_signer()
    p_custody_without_provider()
    p_custody_roundtrip()
    p_rotate()
    p_rotate_wrong_credential()
    p_updatekeys_remove()
    p_policy_digest_tamper()
    p_bundle_scope()
    p_custody_open_without_provider()
    p_custody_seal_bad_provider()
    p_rekey_needs_signer_seed()
    p_policy_invalid()
    p_policy_change_audited()
    p_empty_bundle_refused()
    p_strict_shape()
    p_zero_pubkey_refused()
    p_verify_twice()
    p_seal_event_audited()
    _green_check()

    breaks = [r for r in _RESULTS if r["verdict"] == "BREAK"]
    held = [r for r in _RESULTS if r["verdict"] == "HELD"]
    errors = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    print("w284_sops_probes: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for r in breaks + errors:
        print("  %s %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    with open(os.path.join(
            os.environ.get("TMPDIR") or tempfile.mkdtemp(
                prefix="w284-sops-"),
            "w284-sops-results.json"), "w",
              encoding="utf-8") as fh:
        json.dump(_RESULTS, fh, indent=2, sort_keys=True)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
