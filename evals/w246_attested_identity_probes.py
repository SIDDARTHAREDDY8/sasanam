"""Wave-246 attested-agent-identity cross-check probes (W246-10, red-first).

PTV direction from the wave-245 prospectus: a peer's agent identity is
cross-checked against an attestation -- and an UNVERIFIED anchor yields
``asserted-only``, never ``attested``.

New primitive (gov/identity_crosscheck -- named for the cross-check because
gov/attested_identity.py already exists as the bootstrap-ceremony module):
  ai-valid-attested -- valid attestation + matching peer claim grades
      ATTESTED (anchor signature verifies, claim matches).
  ai-no-attestation-asserted-only -- no attestation presented grades
      ASSERTED-ONLY, never attested.
  ai-no-anchor-asserted-only -- attestation presented but the deployment
      provisioned no verifiable anchor: ASSERTED-ONLY, never attested.
  ai-wrong-key-refused -- attestation signed by a key the anchor does not
      provision refuses identity-anchor-unknown.
  ai-forged-signature-refused -- corrupt signature refuses
      identity-attestation-unverifiable (verify returns False, never
      raises).
  ai-claim-mismatch-refused -- anchor attests principal X but the peer
      claims Y: refuses identity-claim-mismatch.
  ai-malformed-refused -- attestation missing fields / wrong types
      refuses identity-attestation-malformed, fail-closed.
  ai-nondict-refused -- non-dict peer_claim / attestation / anchor
      refuses fail-closed, never attested.

Stdlib only (+ in-repo gov.ed25519). Deterministic: generated keys,
no network, no in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_AI = False
try:
    from gov import identity_crosscheck as _ai
    HAVE_AI = all(hasattr(_ai, n) for n in ("check", "make_attestation"))
except ImportError:
    _ai = None

from gov import ed25519 as _ed25519


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _anchor_and_attestation(principal="agent-7", key_id="anchor-1"):
    """Generate a fresh anchor key, provision it, and attest principal."""
    seed = _ed25519.generate_seed()
    pub = _ed25519.publickey(seed)
    anchor = {"keys": {key_id: pub}}
    att = _ai.make_attestation(
        seed, key_id=key_id, attested_principal=principal)
    return anchor, att, pub


def _expect_verdict(result, verdict):
    assert isinstance(result, dict), "check must return a dict, got %r" % (
        type(result),)
    assert result.get("verdict") == verdict, \
        "verdict %r, expected %r (%r)" % (
            result.get("verdict"), verdict, result)


def _probe_valid_attested():
    anchor, att, _pub = _anchor_and_attestation()
    result = _ai.check({"principal": "agent-7"}, att, anchor)
    _expect_verdict(result, "attested")
    assert result.get("code") is None, \
        "attested carries no refusal code, got %r" % (result.get("code"),)
    # Extra unsigned fields are tolerated: the signature covers the
    # canonical (key_id, attested_principal) fields only.
    extra = dict(att)
    extra["note"] = "forward-compatible field"
    result2 = _ai.check({"principal": "agent-7"}, extra, anchor)
    _expect_verdict(result2, "attested")
    return "anchor verifies + claim matches -> attested"


def _probe_no_attestation_asserted_only():
    anchor, _att, _pub = _anchor_and_attestation()
    result = _ai.check({"principal": "agent-7"}, None, anchor)
    _expect_verdict(result, "asserted-only")
    assert result["verdict"] != "attested", \
        "no attestation must NEVER grade attested"
    return "no attestation -> asserted-only"


def _probe_no_anchor_asserted_only():
    _anchor, att, _pub = _anchor_and_attestation()
    result = _ai.check({"principal": "agent-7"}, att, None)
    _expect_verdict(result, "asserted-only")
    assert result["verdict"] != "attested", \
        "unverifiable anchor must NEVER grade attested"
    result2 = _ai.check({"principal": "agent-7"}, att, {"keys": {}})
    _expect_verdict(result2, "asserted-only")
    return "no anchor / empty anchor -> asserted-only"


def _probe_wrong_key_refused():
    anchor, _att, _pub = _anchor_and_attestation()
    # A different key signs; the anchor never provisioned it.
    other_seed = _ed25519.generate_seed()
    forged_att = _ai.make_attestation(
        other_seed, key_id="anchor-1", attested_principal="agent-7")
    result = _ai.check({"principal": "agent-7"}, forged_att, anchor)
    _expect_verdict(result, "refused")
    assert result.get("code") == "identity-attestation-unverifiable", \
        "code %r, expected identity-attestation-unverifiable" % (
            result.get("code"),)
    return "signature by unprovisioned key refuses"


def _probe_unknown_key_id_refused():
    anchor, _att, _pub = _anchor_and_attestation()
    seed = _ed25519.generate_seed()
    att = _ai.make_attestation(
        seed, key_id="anchor-9", attested_principal="agent-7")
    result = _ai.check({"principal": "agent-7"}, att, anchor)
    _expect_verdict(result, "refused")
    assert result.get("code") == "identity-anchor-unknown", \
        "code %r, expected identity-anchor-unknown" % (result.get("code"),)
    return "unknown key_id refuses identity-anchor-unknown"


def _probe_forged_signature_refused():
    anchor, att, _pub = _anchor_and_attestation()
    bad = dict(att)
    sig = bytearray(bad["signature"])
    sig[0] ^= 0x01
    bad["signature"] = bytes(sig)
    result = _ai.check({"principal": "agent-7"}, bad, anchor)
    _expect_verdict(result, "refused")
    assert result.get("code") == "identity-attestation-unverifiable", \
        "code %r" % (result.get("code"),)
    return "single-bit signature forgery refuses"


def _probe_claim_mismatch_refused():
    anchor, att, _pub = _anchor_and_attestation(
        principal="agent-7")
    result = _ai.check({"principal": "agent-9"}, att, anchor)
    _expect_verdict(result, "refused")
    assert result.get("code") == "identity-claim-mismatch", \
        "code %r, expected identity-claim-mismatch" % (result.get("code"),)
    return "anchor attests agent-7, peer claims agent-9 -> refused"


def _probe_malformed_refused():
    anchor, _att, _pub = _anchor_and_attestation()
    for bad in (
        {},
        {"attested_principal": "agent-7"},                    # missing sig
        {"attested_principal": "agent-7", "key_id": "anchor-1",
         "signature": b"short"},                              # bad sig len
        {"attested_principal": 7, "key_id": "anchor-1",
         "signature": b"\x00" * 64},                          # bad type
    ):
        result = _ai.check({"principal": "agent-7"}, bad, anchor)
        _expect_verdict(result, "refused")
        assert result.get("code") == "identity-attestation-malformed", \
            "code %r for %r" % (result.get("code"), bad)
    return "malformed attestations refuse fail-closed"


def _probe_nondict_refused():
    anchor, att, _pub = _anchor_and_attestation()
    for claim, attest, anch in (
        (None, att, anchor),
        ("agent-7", att, anchor),
        ({"principal": "agent-7"}, None, anchor),
        ({"principal": "agent-7"}, att, None),
        ({"principal": "agent-7"}, "blob", anchor),
        ({}, att, anchor),  # missing principal
    ):
        result = _ai.check(claim, attest, anch)
        assert result.get("verdict") in ("refused", "asserted-only"), \
            "non-dict input must never attest, got %r" % (result,)
    # The all-None shape is asserted-only (nothing to verify); a
    # non-dict attestation with a real claim is asserted-only too only
    # when the anchor cannot verify -- here anchor exists but the
    # attestation is a blob, so it must refuse as malformed.
    r = _ai.check({"principal": "agent-7"}, "blob", anchor)
    _expect_verdict(r, "refused")
    return "non-dict inputs never attest"


_PROBES = [
    ("ai-valid-attested", _probe_valid_attested, "HAVE_AI", False),
    ("ai-no-attestation-asserted-only",
     _probe_no_attestation_asserted_only, "HAVE_AI", False),
    ("ai-no-anchor-asserted-only",
     _probe_no_anchor_asserted_only, "HAVE_AI", False),
    ("ai-wrong-key-refused", _probe_wrong_key_refused, "HAVE_AI", False),
    ("ai-unknown-key-id-refused",
     _probe_unknown_key_id_refused, "HAVE_AI", False),
    ("ai-forged-signature-refused",
     _probe_forged_signature_refused, "HAVE_AI", False),
    ("ai-claim-mismatch-refused",
     _probe_claim_mismatch_refused, "HAVE_AI", False),
    ("ai-malformed-refused", _probe_malformed_refused, "HAVE_AI", False),
    ("ai-nondict-refused", _probe_nondict_refused, "HAVE_AI", False),
]


def main():
    # This battery spawns no nested green-check subprocesses, so the
    # probes must always run -- a GOV_SKIP_GREEN early return would make
    # the battery a vacuous pass depth-1 (wave-244 merge lesson).
    flags = {"HAVE_AI": HAVE_AI}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-34s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w246_attested_identity: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
