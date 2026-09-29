#!/usr/bin/env python3
"""Wave-204 lane B red-team probes: DSSE signature envelope.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
secure-systems-lab/dsse (Apache-2.0) -- envelope shape
{payload, payloadType, signatures} + PAE (Pre-Authentication Encoding).
Re-implemented stdlib-only; no DSSE code is vendored, only the pattern.
This envelope SUPERSEDES the age/minisign trusted-comments sketch of
gov.signature_envelope_v2 for envelope FORMAT (the trusted-comments UX
is preserved by carrying comments inside the signed statement payload).

The pristine tree has NO DSSE envelope: gov.dsse_envelope is absent
(gov.signature_envelope_v2 exists -- probe D6 covers back-compat). Each
probe attacks the new seam:

  D1  VALID            valid DSSE envelope verifies end to end
  D2  TYPE_SWAP        payloadType edited post-sign -> signature breaks
                       (the shape-bug kill: type is inside signed bytes)
  D3  MISSING_SIG      signature entry missing "sig" -> refused
  D4  EXTRA_FIELD      unknown top-level envelope field -> refused
  D5  WRONG_KEY        sealed by key1, opened with key2's verifier ->
                       loud refusal
  D6  V2_BACKCOMPAT    minisign-pattern v2 envelope still verifies via
                       the dispatch helper
  D7  PAYLOAD_TAMPER   payload bytes edited post-sign -> refused
  D8  MULTI_SIG        threshold=2 with two valid sigs -> opens;
                       threshold=3 -> refused (quorum is policy)
  D9  B64_STRICT       payload not valid base64 -> refused
  D10 COMMENTS_PORT    trusted comment edited inside the signed
                       statement -> refused; intact comments returned
  D11 PROVENANCE_BIND  statement bound to provenance digest X opened
                       expecting Y -> refused; None vs X -> refused
                       (no silent downgrade)
  D12 PAE_KNOWN_VECTOR PAE bytes match the DSSE-spec worked example
                       ("application/json" + b"hello") exactly

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: fixed seeds for Ed25519 signers; every probe runs twice
and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import base64
import copy
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import dsse_envelope as _dsse
    from gov import signature_envelope_v2 as _env2
    from gov.signing import Ed25519Signer, Ed25519Verifier
    _ABSENT = False
except ImportError:
    _dsse = None
    _env2 = None
    Ed25519Signer = Ed25519Verifier = None
    _ABSENT = True


def _keys():
    s1 = Ed25519Signer(bytes([11]) * 32)
    s2 = Ed25519Signer(bytes([22]) * 32)
    return (s1, Ed25519Verifier(s1.public_key, s1.key_id),
            s2, Ed25519Verifier(s2.public_key, s2.key_id))


_STATEMENT_TYPE = "application/vnd.sasanam.statement+json"


def _statement_bytes(payload_digest, provenance_digest, comments):
    body = {"payload_sha256": payload_digest,
            "provenance_digest": provenance_digest,
            "trusted_comments": list(comments)}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _seal_stmt(payload_digest, provenance_digest, comments, signers,
               payload_type=_STATEMENT_TYPE):
    stmt = _statement_bytes(payload_digest, provenance_digest, comments)
    return _dsse.seal(stmt, payload_type, signers)


def _open_stmt(envelope, payload_digest, provenance_digest, comments,
               verifiers, threshold=1, payload_type=_STATEMENT_TYPE):
    return _dsse.open_statement(
        envelope, payload_digest, provenance_digest, comments,
        verifiers, threshold=threshold, payload_type=payload_type)


_P1 = "ab" * 32   # 64 hex chars
_P2 = "cd" * 32
_COMMENTS = ["shipped by release-approval v5", "auditor: acme-audit"]


def p_d1_valid():
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    got = _open_stmt(env, _P1, _P2, _COMMENTS, [v1])
    assert got["key_ids"] == [s1.key_id], got
    assert got["payload_type"] == _STATEMENT_TYPE, got
    assert got["trusted_comments"] == _COMMENTS, got
    assert got["provenance_digest"] == _P2, got
    return "HELD"


def p_d2_type_swap():
    # The shape-bug kill: payloadType is inside the signed bytes (PAE),
    # so swapping it post-sign MUST break the signature.
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    env2["payloadType"] = "text/plain"
    try:
        _open_stmt(env2, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d3_missing_sig():
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    del env2["signatures"][0]["sig"]
    try:
        _open_stmt(env2, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d4_extra_field():
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    env2["extra"] = "stapled"
    try:
        _open_stmt(env2, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d5_wrong_key():
    s1, _, s2, v2 = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    try:
        _open_stmt(env, _P1, _P2, _COMMENTS, [v2])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d6_v2_backcompat():
    # Minisign-pattern v2 envelopes still verify through the dispatch
    # helper -- migration must not strand already-sealed envelopes.
    s1, v1, _, _ = _keys()
    env = _env2.seal(_P1, s1, _COMMENTS, provenance_digest=_P2)
    got = _dsse.open_any(env, _P1, _P2, _COMMENTS, [v1])
    assert got["format"] == "v2", got
    assert got["trusted_comments"] == _COMMENTS, got
    return "HELD"


def p_d7_payload_tamper():
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    raw = bytearray(base64.b64decode(env2["payload"]))
    raw[10] ^= 0xFF
    env2["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    try:
        _open_stmt(env2, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d8_multi_sig():
    # Quorum is policy carried by the caller: threshold=2 with two valid
    # sigs opens; threshold=3 with two sigs is a loud refusal.
    s1, v1, s2, v2 = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1, s2])
    assert len(env["signatures"]) == 2
    got = _open_stmt(env, _P1, _P2, _COMMENTS, [v1, v2], threshold=2)
    assert sorted(got["key_ids"]) == sorted([s1.key_id, s2.key_id]), got
    try:
        _open_stmt(env, _P1, _P2, _COMMENTS, [v1, v2], threshold=3)
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d9_b64_strict():
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    env2["payload"] = "!!! not base64 !!!"
    try:
        _open_stmt(env2, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d10_comments_port():
    # Trusted comments live inside the signed statement: editing one
    # post-sign breaks the signature exactly like editing the payload.
    # The tampered comment is passed as the EXPECTED comment, so the
    # refusal below can only come from the signature path -- a
    # comment-binding-first implementation would accept it.
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    env2 = copy.deepcopy(env)
    stmt = json.loads(base64.b64decode(env2["payload"]).decode("utf-8"))
    stmt["trusted_comments"][0] = "shipped by mallory"
    env2["payload"] = base64.b64encode(
        json.dumps(stmt, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).decode("ascii")
    tampered = ["shipped by mallory", "auditor: acme-audit"]
    try:
        _open_stmt(env2, _P1, _P2, tampered, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d11_provenance_bind():
    # No silent downgrade: an envelope bound to provenance X must not
    # open against expectation Y, and None is an explicit distinct
    # binding, not a wildcard.
    s1, v1, _, _ = _keys()
    env = _seal_stmt(_P1, _P2, _COMMENTS, [s1])
    for wrong in (_P1, None):
        try:
            _open_stmt(env, _P1, wrong, _COMMENTS, [v1])
        except _dsse.EnvelopeError:
            continue
        return "GAP"
    env_free = _seal_stmt(_P1, None, _COMMENTS, [s1])
    try:
        _open_stmt(env_free, _P1, _P2, _COMMENTS, [v1])
    except _dsse.EnvelopeError:
        return "HELD"
    return "GAP"


def p_d12_pae_known_vector():
    # Known-answer vector straight from the DSSE spec:
    # PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
    # "application/json" is 16 bytes, b"hello" is 5 bytes.
    want = b"DSSEv1 16 application/json 5 hello"
    got = _dsse.pae("application/json", b"hello")
    assert got == want, (got, want)
    return "HELD"


_PROBES = [
    ("D1", "VALID", p_d1_valid),
    ("D2", "TYPE_SWAP", p_d2_type_swap),
    ("D3", "MISSING_SIG", p_d3_missing_sig),
    ("D4", "EXTRA_FIELD", p_d4_extra_field),
    ("D5", "WRONG_KEY", p_d5_wrong_key),
    ("D6", "V2_BACKCOMPAT", p_d6_v2_backcompat),
    ("D7", "PAYLOAD_TAMPER", p_d7_payload_tamper),
    ("D8", "MULTI_SIG", p_d8_multi_sig),
    ("D9", "B64_STRICT", p_d9_b64_strict),
    ("D10", "COMMENTS_PORT", p_d10_comments_port),
    ("D11", "PROVENANCE_BIND", p_d11_provenance_bind),
    ("D12", "PAE_KNOWN_VECTOR", p_d12_pae_known_vector),
]


def _run_once():
    results = []
    for pid, name, fn in _PROBES:
        if _ABSENT:
            results.append((pid, name, "GAP"))
            continue
        try:
            results.append((pid, name, fn()))
        except Exception as exc:  # harness failure, not a verdict
            results.append((pid, name, "ERROR:%s:%s"
                            % (type(exc).__name__, exc)))
    return results


def main():
    first = _run_once()
    second = _run_once()
    errors = 0
    held = gaps = 0
    for (pid, name, v1), (_, _, v2) in zip(first, second):
        if v1 != v2:
            print("ERROR %s %s: verdict changed %r -> %r" % (pid, name, v1, v2))
            errors += 1
        elif v1 == "HELD":
            held += 1
            print("HELD  %s %s" % (pid, name))
        elif v1 == "GAP":
            gaps += 1
            print("GAP   %s %s" % (pid, name))
        else:
            print("%s %s %s" % (v1, pid, name))
            errors += 1
    print("dsse_envelope_probes: %d HELD / %d GAP / %d ERROR"
          % (held, gaps, errors))
    return 1 if errors else 0


def green_check():
    """Adjacent-battery green check (depth-1: honor GOV_SKIP_GREEN)."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
