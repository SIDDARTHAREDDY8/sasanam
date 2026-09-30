"""Wave-244 obsigna KMS-signer discipline probes (W244-5, red-first).

ADAPT, pattern only, prose re-derived from the wave-243 prospectus
description of obsigna (Apache-2.0, direct LICENSE read): receipt
signing through a KMS protocol boundary (their sdk-py-v0.16.0
``KMSSigner``-in-``sign_receipt()`` pattern), never with keys living in
the agent process; offline verification from retained bytes +
consumer-pinned keys (their ``verify_raw`` / ``hash_raw_receipt``
forward-compat discipline). No upstream code is read, imported, or
vendored.

This battery exercises the NEW discipline functions added to the
existing ``gov/kms_signer.py`` (which already pins "the private key
NEVER leaves the key-management boundary" via ``KmsSigner`` /
``KeyRef``): ``sign_receipt`` refuses raw private-key bytes in ANY
input path (``signer-key-material-in-process``), refuses an adapter
handle that wraps in-process material
(``signer-adapter-tampered`` -- this bites our own loopback test
double, honestly), fails closed on adapter failure
(``signer-unavailable``) with NO fallback to in-process signing,
refuses verification against a different adapter identity
(``signer-identity-mismatch``), only ever hands the adapter
canonical bytes, and records which adapter signed in the audit
ledger. Verification is offline from retained bytes with a
consumer-pinned verifier (bool contract: ``is True`` / ``is False``).

Probes:
  kms-happy-path-signed -- declared KMS handle signs; the receipt is
      canonicalized first, the signed record carries the key ref,
      and the audit ledger records which adapter signed.
  kms-in-process-key-bytes-refused -- a "signer" that IS raw key
      material (bytes, or a dict carrying private_key bytes) refuses
      signer-key-material-in-process, never signs.
  kms-adapter-tampered-refused -- a declared adapter handle that
      smuggles in-process key material in an attribute refuses
      signer-adapter-tampered.
  kms-loopback-test-double-refused -- our own LoopbackKms (which
      honestly holds keys in-process as a test double) is refused
      for production receipts: signer-adapter-tampered.
  kms-env-config-key-refused -- config/env-derived values carrying
      PEM-shaped or raw key material refuse
      signer-key-material-in-process at declaration time.
  kms-unavailable-fails-closed -- an adapter whose backend raises
      refuses signer-unavailable; a static check asserts the new
      functions have no local-signing fallback path at all (no
      in-process signing capability to fall back TO).
  kms-identity-mismatch-refused -- a receipt signed under one key
      ref and verified against another refuses
      signer-identity-mismatch.
  kms-canonical-only -- a recording adapter asserts it received
      exactly the canonical bytes (no uncanonicalized bytes are
      ever signed).
  kms-mutated-receipt-refused -- a signed receipt whose payload is
      mutated after signing refuses signed-receipt-malformed.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
_ks = None
try:
    from gov import kms_signer as _ks_mod
    _ks = _ks_mod
    HAVE_NEW_API = all(hasattr(_ks, n) for n in (
        "sign_receipt", "verify_signed_receipt", "signer_from_config",
        "SIGNING_LEDGER", "KmsSigner", "KeyRef", "KmsSignerError"))
except ImportError:
    pass

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

RECEIPT = {"principal": "agent-7", "action": "read",
           "target": "file:///etc/x", "nonce": "n-001"}

PROBE_NAMES = [
    "kms-happy-path-signed",
    "kms-in-process-key-bytes-refused",
    "kms-adapter-tampered-refused",
    "kms-loopback-test-double-refused",
    "kms-env-config-key-refused",
    "kms-unavailable-fails-closed",
    "kms-identity-mismatch-refused",
    "kms-canonical-only",
    "kms-mutated-receipt-refused",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise KmsSignerError with .code == code."""
    try:
        fn()
    except _ks.KmsSignerError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _recording_adapter(adapter_id="test-kms-1", fail=False):
    """Build a test-local fake KMS: a KmsSigner that owns NO key bytes
    itself (the "signature" is a deterministic tag over the bytes it
    received). It stands in for a separate KMS process, exactly as
    production does. Built lazily so the pristine base stays GAP."""

    class _RecordingAdapter(_ks.KmsSigner):
        def __init__(self):
            super(_RecordingAdapter, self).__init__()
            self._aid = adapter_id
            self._fail = fail
            self.received = []

        def _backend_sign(self, key_ref, message):
            if self._fail:
                raise RuntimeError("KMS unreachable")
            self.received.append(bytes(message))
            return b"TAG:" + bytes(message)[:16]

        def _public_key_for(self, key_ref):
            return b""

    return _RecordingAdapter()


def _key_ref(provider="test-kms", key_id="k-1", algorithm=None):
    if algorithm is None:
        from gov.alg_registry import default_registry
        algorithm = sorted(default_registry().names())[0]
    return _ks.KeyRef(provider, key_id, algorithm)


def _verifier(canonical_bytes, signature, key_ref):
    return signature == b"TAG:" + canonical_bytes[:16]


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_happy_path():
    adapter = _recording_adapter("kms-east-1")
    ref = _key_ref("test-kms", "k-1")
    signed = _ks.sign_receipt(dict(RECEIPT), adapter, ref)
    assert signed["key_ref"]["provider"] == "test-kms"
    assert signed["key_ref"]["key_id"] == "k-1"
    assert len(signed["canonical_sha256"]) == 64
    assert signed["signature"].startswith("5441473a"), \
        "signature must be hex of the adapter tag"
    # The audit ledger records WHICH adapter signed.
    entries = [e for e in _ks.SIGNING_LEDGER
               if e["canonical_sha256"] == signed["canonical_sha256"]]
    assert entries and entries[0]["provider"] == "test-kms" \
        and entries[0]["key_id"] == "k-1", \
        "ledger must record the signing adapter identity"
    # Offline verification from retained bytes + pinned verifier.
    _ks.verify_signed_receipt(signed, ref, _verifier)
    return "signed via declared KMS handle; ledger records adapter; " \
        "offline verify holds"


def _probe_in_process_key_bytes_refused():
    ref = _key_ref()
    # Raw bytes presented as a "signer".
    note = _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT), b"\x01" * 32, ref),
        "signer-key-material-in-process")
    # A dict carrying key material.
    note2 = _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT),
                                 {"private_key": b"\x02" * 32}, ref),
        "signer-key-material-in-process")
    # An arbitrary object with a seed attribute (not a KmsSigner).
    class Sneaky(object):
        def __init__(self):
            self.seed = b"\x03" * 32
    note3 = _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT), Sneaky(), ref),
        "signer-key-material-in-process")
    return "%s; %s; %s" % (note, note2, note3)


def _probe_adapter_tampered_refused():
    class TamperedAdapter(_ks.KmsSigner):
        def _backend_sign(self, key_ref, message):
            return b"TAG" + bytes(message)[:4]

        def _public_key_for(self, key_ref):
            return b""

        def __init__(self):
            super(TamperedAdapter, self).__init__()
            self._key_material = b"\x04" * 32  # in-process material

    ref = _key_ref()
    return _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT), TamperedAdapter(), ref),
        "signer-adapter-tampered")


def _probe_loopback_test_double_refused():
    # Our own LoopbackKms honestly holds keys in-process (it is a
    # test double with zero production custody guarantees). The
    # production receipt discipline must refuse it.
    from gov.kms_signer_loopback import LoopbackKms
    from gov.alg_registry import default_registry
    loop = LoopbackKms()
    algorithm = sorted(default_registry().names())[0]
    ref = loop.provision_key("loopback", "dev-1", algorithm)
    return _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT), loop, ref),
        "signer-adapter-tampered")


def _probe_env_config_key_refused():
    # PEM-shaped material smuggled through config (e.g. from env).
    config = {"adapter": "vault-transit", "key_id": "k-1",
              "private_key_pem": "-----BEGIN PRIVATE KEY-----\nAAA\n"
                                 "-----END PRIVATE KEY-----"}
    return _expect_refusal(
        lambda: _ks.signer_from_config(config),
        "signer-key-material-in-process")


def _probe_unavailable_fails_closed():
    adapter = _recording_adapter("kms-down", fail=True)
    ref = _key_ref()
    note = _expect_refusal(
        lambda: _ks.sign_receipt(dict(RECEIPT), adapter, ref),
        "signer-unavailable")
    # THE critical property: there is no local-signing fallback path.
    # The new functions must not even HAVE an in-process signing
    # capability to fall back to. Static check over the new functions'
    # own source (not the whole module: the loopback test double
    # legitimately mints keys in a separate, honestly labeled module).
    import inspect
    src = inspect.getsource(_ks.sign_receipt) + \
        inspect.getsource(_ks.verify_signed_receipt) + \
        inspect.getsource(_ks.signer_from_config)
    for token in ("_local_sign", "fallback_sign", "dev_sign",
                  "generate_keypair", "from_seed", "keygen("):
        assert token not in src, \
            "new discipline source contains local-sign token %r" % token
    return "%s; no local-signing capability in new functions" % note


def _probe_identity_mismatch_refused():
    adapter = _recording_adapter("kms-east-1")
    ref = _key_ref("test-kms", "k-1")
    other = _key_ref("test-kms", "k-9")
    signed = _ks.sign_receipt(dict(RECEIPT), adapter, ref)
    return _expect_refusal(
        lambda: _ks.verify_signed_receipt(signed, other, _verifier),
        "signer-identity-mismatch")


def _probe_canonical_only():
    adapter = _recording_adapter("kms-canon")
    ref = _key_ref()
    messy = {"target": "file:///etc/x", "nonce": "n-001",
             "principal": "agent-7", "action": "read"}
    signed = _ks.sign_receipt(messy, adapter, ref)
    assert len(adapter.received) == 1
    got = adapter.received[0]
    expected = _canonical(messy)
    assert got == expected, "adapter did not receive canonical bytes"
    assert signed["canonical_sha256"] == hashlib.sha256(expected).hexdigest()
    return "adapter received exactly the canonical bytes"


def _probe_mutated_receipt_refused():
    adapter = _recording_adapter("kms-east-1")
    ref = _key_ref()
    signed = _ks.sign_receipt(dict(RECEIPT), adapter, ref)
    mutated = dict(signed)
    mutated_receipt = dict(signed["receipt"])
    mutated_receipt["action"] = "delete"
    mutated["receipt"] = mutated_receipt
    note = _expect_refusal(
        lambda: _ks.verify_signed_receipt(mutated, ref, _verifier),
        "signed-receipt-malformed")
    return note


_PROBES = {
    "kms-happy-path-signed": _probe_happy_path,
    "kms-in-process-key-bytes-refused": _probe_in_process_key_bytes_refused,
    "kms-adapter-tampered-refused": _probe_adapter_tampered_refused,
    "kms-loopback-test-double-refused":
        _probe_loopback_test_double_refused,
    "kms-env-config-key-refused": _probe_env_config_key_refused,
    "kms-unavailable-fails-closed": _probe_unavailable_fails_closed,
    "kms-identity-mismatch-refused": _probe_identity_mismatch_refused,
    "kms-canonical-only": _probe_canonical_only,
    "kms-mutated-receipt-refused": _probe_mutated_receipt_refused,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("signer-key-material-in-process",
                     "signer-adapter-tampered",
                     "signer-unavailable",
                     "signer-identity-mismatch",
                     "signed-receipt-malformed",
                     "signed-receipt-signature-invalid"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-244 kms-signer probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, status, _ in results if status == "HELD")
    gap = sum(1 for _, status, _ in results if status == "GAP")
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    print("held=%d gap=%d total=%d" % (held, gap, len(results)))
    if HAVE_NEW_API:
        if held != len(results):
            print("RED: not all probes held")
            return 1
    else:
        if gap != len(results):
            print("RED: expected all-GAP on pristine base")
            return 1
    print("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
