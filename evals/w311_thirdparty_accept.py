"""Third-party acceptance for the offline verifier (wave-311 lane E).

Verifies a known-good verification bundle with STDLIB ONLY -- no
Sasanam import ("sell evidence, not the engine"). The script asserts
at startup that no ``gov`` module is present in ``sys.modules`` and
re-implements the wire checks independently:

  trust-root shape -> policy envelope signature (PAE + raw Ed25519)
  -> policy shape/expiry -> statement envelope signature (threshold)
  -> statement shape -> predicateType binding -> canonical-bytes
  == payload bytes (same-bytes) -> subject digest == sha256(artifact)
  -> observer timestamps (authority-isolated: each token verified
  against its own authority key + validFor window at the token's
  time, evidence_digest bound inside the signed body, temporal
  bounds, policy minimum count)

The Ed25519 below is a minimal RFC 8032 ``verify`` written from the
RFC's formulas (not copied from ``gov/ed25519.py``); the PAE is the
DSSE spec's ``"DSSEv1" SP LEN SP type SP LEN SP body``. Agreement
between this script and ``gov.evidence_verify_offline`` proves the
evidence verifies without the engine.

Usage:
  python3 evals/w311_thirdparty_accept.py --bundle B.json \
      --artifact A.bin --trust-root T.json
Exit 0 + THIRDPARTY_VALID on success; exit 1 + THIRDPARTY_INVALID on
any failure (a crash also exits non-zero -- never success).
"""

import argparse
import base64
import binascii
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

# The whole point: no Sasanam module may be imported, directly or
# transitively. An explicit guard (not assert: asserts vanish under
# python -O, and this invariant is the script's raison d'etre).
if any(m == "gov" or m.startswith("gov.") for m in sys.modules):
    sys.stderr.write("third-party acceptance must not import gov\n")
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Minimal RFC 8032 Ed25519 verify (from the RFC's formulas).
# ---------------------------------------------------------------------------

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


def _edwards(P, Q):
    # Affine addition on the twisted Edwards curve with a = -1:
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)   (a = -1 flips the sign)
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _Q
    return (x3, y3)


def _scalarmult(P, e):
    Q = (0, 1)
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


_B = (_xrecover((4 * _inv(5)) % _Q), (4 * _inv(5)) % _Q)


def _decodepoint(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _Q - x
    if ((-x * x + y * y - 1 - _D * x * x * y * y) % _Q) != 0:
        return None
    return (x, y)


def ed25519_verify(pub, msg, sig):
    """Raw RFC 8032 verify: True/False, never raises."""
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        A = _decodepoint(pub)
        R = _decodepoint(sig[:32])
        if A is None or R is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                           "little")
        lhs = _scalarmult(_B, s)
        rhs = _edwards(R, _scalarmult(A, h))
        return lhs == rhs
    except Exception:  # noqa: BLE001 -- malformed is False
        return False


# ---------------------------------------------------------------------------
# Wire checks.
# ---------------------------------------------------------------------------

def _pae(ptype, payload):
    t = ptype.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" "
            + str(len(payload)).encode("ascii") + b" " + payload)


def _b64(s, what):
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, AttributeError) as exc:
        raise _Fail("%s: bad base64: %s" % (what, exc))


class _Fail(Exception):
    pass


def _parse_envelope(doc, what):
    if not isinstance(doc, dict):
        raise _Fail("%s: envelope must be an object" % what)
    payload = _b64(doc["payload"], what + ".payload")
    ptype = doc["payloadType"]
    sigs = [(e.get("keyid"), _b64(e["sig"], what + ".sig"))
            for e in doc["signatures"]]
    return payload, ptype, sigs


def _verify_threshold(payload, ptype, sigs, pubkeys, threshold, what):
    msg = _pae(ptype, payload)
    ok_ids = []
    for kid, sig in sigs:
        cands = [(kid, pubkeys[kid])] if kid in pubkeys \
            else list(pubkeys.items())
        for ckid, pub in cands:
            if ckid in ok_ids:
                continue
            if ed25519_verify(pub, msg, sig) is True:
                ok_ids.append(ckid)
                break
    if len(ok_ids) < threshold:
        raise _Fail("%s: threshold %d unmet (%d verified)"
                    % (what, threshold, len(ok_ids)))
    return ok_ids


def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _iso(value, what):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise _Fail("%s: bad time %r" % (what, value))
    if dt.tzinfo is None:
        raise _Fail("%s: naive time refused %r" % (what, value))
    return dt


def _verify_timestamps(tokens, policy, art_hex, now):
    """Authority-isolated observer-timestamp verification.

    Each token is verified against its OWN authority key and its OWN
    validFor window, evaluated at the TOKEN's time -- never the
    verifier's time. The token binds evidence_digest inside the
    signed body (flat token: signature covers canonical
    {authority_id, time, evidence_digest}).
    """
    authorities = {}
    for a in policy["timestamp_authorities"]:
        aid = a["authority_id"]
        if aid in authorities:
            raise _Fail("duplicate timestamp authority_id %r" % (aid,))
        authorities[aid] = {
            "pub": bytes.fromhex(a["pubkey_hex"]),
            "not_before": _iso(a["valid_for"]["not_before"],
                               "authority.valid_for"),
            "not_after": _iso(a["valid_for"]["not_after"],
                              "authority.valid_for"),
        }
    ts_cfg = policy["observer_timestamps"]
    max_age = timedelta(hours=ts_cfg["max_age_hours"])
    if not isinstance(tokens, list):
        raise _Fail("timestamps must be a list")
    verified = 0
    for tok in tokens:
        aid = tok.get("authority_id")
        if not isinstance(aid, str) or aid not in authorities:
            raise _Fail("timestamp from unknown authority %r" % (aid,))
        auth = authorities[aid]
        when = _iso(tok.get("time"), "timestamp.time")
        if not (auth["not_before"] <= when <= auth["not_after"]):
            raise _Fail("token time outside %s's validFor window" % (aid,))
        if tok.get("evidence_digest", "").lower() != art_hex.lower():
            raise _Fail("timestamp not bound to this artifact (%s)" % (aid,))
        body = {"authority_id": aid,
                "time": tok["time"],
                "evidence_digest": tok["evidence_digest"]}
        sig = _b64(tok.get("sig"), "timestamp.sig")
        if ed25519_verify(auth["pub"], _canon(body), sig) is not True:
            raise _Fail("timestamp signature invalid (%s)" % (aid,))
        if when > now:
            raise _Fail("timestamp in the future (%s)" % (aid,))
        if now - when > max_age:
            raise _Fail("timestamp older than max age (%s)" % (aid,))
        verified += 1
    if verified < ts_cfg["min"]:
        raise _Fail("only %d/%d observer timestamps verified"
                    % (verified, ts_cfg["min"]))
    return verified


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--trust-root", required=True)
    args = ap.parse_args(argv)
    try:
        return _run(args)
    except _Fail as e:
        print("THIRDPARTY_INVALID: %s" % (e,))
        return 1
    except Exception as e:  # noqa: BLE001 -- crash is never success
        print("THIRDPARTY_INVALID: internal %s: %s"
              % (type(e).__name__, e))
        return 1


def _run(args):
    with open(args.bundle, encoding="utf-8") as fh:
        vb = json.load(fh)
    with open(args.artifact, "rb") as fh:
        artifact = fh.read()
    with open(args.trust_root, encoding="utf-8") as fh:
        troot = json.load(fh)

    now = datetime.now(timezone.utc)
    art_hex = hashlib.sha256(artifact).hexdigest()

    # 1. trust root shape (caller-supplied; digest recorded).
    assert troot.get("version") == "sasanam-offline-trust-root/v1", \
        "trust root version"
    policy_keys = {k["keyid"]: bytes.fromhex(k["pubkey_hex"])
                   for k in troot["policy_keys"]}
    assert policy_keys, "trust root needs policy keys"
    print("trust-root: caller-supplied sha256:%s"
          % hashlib.sha256(_canon(troot)).hexdigest())

    # 2. bundle shape.
    assert vb.get("version") == "sasanam-offline-verify-bundle/v1", \
        "bundle version"
    assert not vb.get("witness_entries"), "witness entries unsupported"

    # 3. policy envelope signature against the trust root.
    p_payload, p_ptype, p_sigs = _parse_envelope(vb["policy"], "policy")
    assert p_ptype == "application/vnd.sasanam.verification-policy+json", \
        "policy payloadType %r" % (p_ptype,)
    _verify_threshold(p_payload, p_ptype, p_sigs, policy_keys, 1, "policy")
    policy = json.loads(p_payload.decode("utf-8"))
    assert policy.get("version") == "sasanam-verification-policy/v1", \
        "policy version"
    exp = datetime.fromisoformat(
        policy["expires"].replace("Z", "+00:00"))
    assert exp > now, "policy expired %s (observed %s)" % (exp, now)

    # 4. statement envelope signature against the policy's keys.
    es = policy["evidence_signing"]
    ev_keys = {k["keyid"]: bytes.fromhex(k["pubkey_hex"])
               for k in es["keys"]}
    payload, ptype, sigs = _parse_envelope(vb["envelope"], "envelope")
    assert ptype == "application/vnd.in-toto+json", \
        "envelope payloadType %r" % (ptype,)
    kids = _verify_threshold(payload, ptype, sigs, ev_keys,
                             es["threshold"], "envelope")

    # 5. statement shape + predicate binding + same-bytes + subject.
    stmt = json.loads(payload.decode("utf-8"))
    assert stmt.get("_type") == "https://in-toto.io/Statement/v1", \
        "statement _type"
    assert stmt.get("predicateType") == \
        policy["required_predicate_type"], "predicateType %r" % (
            stmt.get("predicateType"),)
    assert _canon(stmt) == payload, "canonical(statement) != payload"
    sub = stmt["subject"][0]["digest"]["sha256"]
    assert sub.lower() == art_hex.lower(), \
        "subject %s != artifact %s" % (sub, art_hex)

    print("statement: in-toto v1, predicate %s"
          % (stmt["predicateType"],))
    print("signatures: %d/%d threshold, keys %s"
          % (len(kids), es["threshold"], ",".join(kids)))
    print("subject: sha256:%s == artifact bytes" % art_hex)
    n_ts = _verify_timestamps(vb.get("timestamps", []), policy,
                              art_hex, now)
    print("observer timestamps: %d verified (authority-isolated)"
          % n_ts)
    print("observed time: %s (system-utc-clock)"
          % now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("THIRDPARTY_VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
