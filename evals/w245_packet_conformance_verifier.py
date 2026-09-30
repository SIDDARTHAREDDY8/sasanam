#!/usr/bin/env python3
"""W245-7 / W246-11: draft-farley-acta-signed-receipts-03 verifier adapter
for the probityai/agent-evidence-vectors `vectors-receipt-signature` corpus
(v0.13.0: 13 members; v0.15.0: 25 members).

Implements the verifier contract in that corpus's README from the draft text
itself (vendored at vectors-receipt-signature/spec-vendored/
draft-farley-acta-signed-receipts-03.txt), NOT by copying the corpus's
reference reader:

    <verifier> <receipt-path>          with AEV_RECEIPT_JWKS=<key-set path>
    (and AEV_RECEIPT_CONTEXT=<context json> for chain members)

Answers in the two places the contract requires (which must agree):
  - exit status: 0 valid, 1 invalid, 2 undecidable
  - last stdout line: {"verdict": ..., "code": ...} (code null on valid)

The Ed25519 check runs through OUR product primitive (gov/ed25519.py,
RFC 8032 PureEdDSA, bool contract pinned `is True`); the RFC 8785 (JCS)
canonicalization is an independent from-spec implementation in this file.

Check order mirrors the reference verification (Sections 2.1, 5.2, 6.6,
6.7, 9.2, 9.5) so the emitted refusal code matches the corpus codeRegistry
(signature_invalid, key_outside_validity_window, signature_in_signing_input,
chain_link_mismatch) where the draft defines one.

Gaps (RS-G-001 key revocation, RS-G-002 commitment timing) are answered
with the DRAFT's verdicts -- the draft does not decide them, so a verifier
that answers the draft's verdicts passes. This adapter reads neither
revoked_at nor a commitment's logged time.

Stdlib only. No I/O except argv/env/stdout. Never raises on malformed
input: malformed is undecidable/invalid, never a traceback.
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime

# --- product primitive: gov/ed25519.py loaded standalone (no gov package
# --- import, no side effects). verify(pub, msg, sig) -> True/False.


def _load_product_ed25519():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "gov", "ed25519.py")
    spec = importlib.util.spec_from_file_location("_w245_gov_ed25519", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ed = _load_product_ed25519()

# --- verdicts / exit codes per the corpus contract.

VALID, INVALID, UNDECIDABLE = "valid", "invalid", "undecidable"
_EXIT = {VALID: 0, INVALID: 1, UNDECIDABLE: 2}


def _answer(verdict, code):
    sys.stdout.write(json.dumps({"verdict": verdict, "code": code}) + "\n")
    sys.stdout.flush()
    raise SystemExit(_EXIT[verdict])


# --- RFC 8785 (JCS) canonicalization, from the spec text. Member ordering
# --- is by UTF-16 code units; strings are emitted as UTF-8 (only the JSON
# --- structural chars and C0 controls are escaped).


class _JcsError(ValueError):
    pass


def _utf16_key(s):
    units = []
    for ch in s:
        o = ord(ch)
        if o < 0x10000:
            units.append(o)
        else:
            o -= 0x10000
            units.append(0xD800 + (o >> 10))
            units.append(0xDC00 + (o & 0x3FF))
    return units


_CTRL_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(_CTRL_ESCAPES.get(o, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_ser(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # Integers-only profile, decided on the VALUE (cf. the corpus
        # rail's note): an integral float denotes its integer.
        if not v.is_integer():
            raise _JcsError("non-integer number")
        iv = int(v)
        if abs(iv) >= 2 ** 53:
            raise _JcsError("integer outside safe range")
        return str(iv)
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        if any(not isinstance(k, str) for k in v):
            raise _JcsError("non-string member name")
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(_jcs_str(k) + ":" + _jcs_ser(v[k]) for k in keys) + "}"
    raise _JcsError("unsupported type: %r" % (type(v),))


def jcs_dumps(obj):
    return _jcs_ser(obj).encode("utf-8")


# --- JSON parse with duplicate-member detection (RFC 8785 refuses them;
# --- the corpus rail marks them and stops at the canonicalization step).


class _DupDict(dict):
    repeated = False


def _object_pairs(pairs):
    out = _DupDict()
    for key, value in pairs:
        if key in out:
            out.repeated = True
        out[key] = value
    return out


def _has_repeats(value):
    if isinstance(value, _DupDict) and value.repeated:
        return True
    if isinstance(value, dict):
        return any(_has_repeats(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_repeats(v) for v in value)
    return False


# --- key set (Section 9.5: the key MUST come from the external key set,
# --- never from the receipt itself).


def _load_keys(path):
    try:
        with open(path, "rb") as handle:
            data = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError):
        return None
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        return None
    out = {}
    for key in keys:
        if isinstance(key, dict) and isinstance(key.get("kid"), str):
            out[key["kid"]] = key
    return out


def _public_key_bytes(key):
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return None
    x = key.get("x")
    if not isinstance(x, str):
        return None
    try:
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


# --- validity windows (Section 9.2: SHOULD; the draft's -04 makes it MUST).
# --- valid_from is inside the window, valid_until is outside it.


def _instant(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _window(issued_at, key):
    at = _instant(issued_at)
    if at is None:
        return UNDECIDABLE, "window_not_applicable"
    bounds = {}
    for member in ("valid_from", "valid_until"):
        if member in key:
            bound = _instant(key[member])
            if bound is None:
                return UNDECIDABLE, "window_not_applicable"
            bounds[member] = bound
    start, end = bounds.get("valid_from"), bounds.get("valid_until")
    if (start is not None and at < start) or (end is not None and at >= end):
        return INVALID, "key_outside_validity_window"
    return VALID, None


# --- the verification, in the reference order.


def verify(body, keys):
    try:
        top = json.loads(body, object_pairs_hook=_object_pairs)
    except ValueError:
        return UNDECIDABLE, "not_envelope_shape"
    if not isinstance(top, dict) or set(top) != {"payload", "signature"}:
        return UNDECIDABLE, "not_envelope_shape"
    signature = top["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"alg", "kid", "sig"}
        or not all(isinstance(signature[k], str) and signature[k] for k in signature)
    ):
        return UNDECIDABLE, "bad_signature_object"
    if not isinstance(top["payload"], dict):
        return UNDECIDABLE, "payload_not_an_object"
    payload = top["payload"]

    # Section 6.6 / 2.2 prechecks.
    if any(field not in payload for field in ("type", "issued_at", "issuer_id")):
        return UNDECIDABLE, "missing_required_field"
    if "signature" in payload:
        # Section 6.6 MUST: the canonicalized object MUST NOT contain a
        # signature member, null included.
        return INVALID, "signature_in_signing_input"
    if signature["alg"] != "EdDSA":
        return UNDECIDABLE, "unsupported_alg"
    if payload["issuer_id"] != signature["kid"]:
        return INVALID, "issuer_kid_mismatch"

    # Section 9.5: key resolved from the external key set only.
    key = keys.get(signature["kid"])
    if key is None:
        return UNDECIDABLE, "unknown_kid"
    public = _public_key_bytes(key)
    if public is None:
        return UNDECIDABLE, "bad_key"

    try:
        sig = bytes.fromhex(signature["sig"])
    except ValueError:
        sig = b""
    if len(sig) != 64:
        return INVALID, "bad_signature_encoding"

    if _has_repeats(payload):
        return UNDECIDABLE, "payload_not_canonicalizable"
    try:
        canonical = jcs_dumps(payload)
    except _JcsError:
        return UNDECIDABLE, "payload_not_canonicalizable"

    # PureEdDSA over the canonical bytes directly: no pre-hash
    # (Section 6.6 MUST). Product primitive; bool contract pinned.
    if _ed.verify(public, canonical, sig) is not True:
        return INVALID, "signature_invalid"

    return _window(payload["issued_at"], key)


# --- chain context (Section 6.7; v0.15.0 members). The harness hands
# --- AEV_RECEIPT_CONTEXT=<json file> with {"chain": [<abs path>, ...],
# --- "commitment": <abs path>, "commitmentLoggedAt": <str>} -- commitment
# --- keys present together or not at all. The link is
# --- previousReceiptHash == "sha256:" + hex(SHA-256(JCS(previous receipt))).
# --- Order mirrors the corpus reference rail: receipt alone, then each
# --- chain element must verify, then each pairwise link, then (gaps open)
# --- the draft's verdict. RS-G-002 (commitment timing) is NOT applied: the
# --- draft does not decide it, and answering the draft's verdict passes.


def _load_context():
    path = os.environ.get("AEV_RECEIPT_CONTEXT")
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            data = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    chain = data.get("chain")
    if not isinstance(chain, list) or not chain:
        return None
    bodies = []
    for rel in chain:
        if not isinstance(rel, str):
            return None
        try:
            with open(rel, "rb") as handle:
                bodies.append(handle.read())
        except OSError:
            return None
    return bodies


def _receipt_link(body):
    try:
        top = json.loads(body, object_pairs_hook=_object_pairs)
    except ValueError:
        return None
    if not isinstance(top, dict):
        return None
    try:
        canonical = jcs_dumps(top)
    except _JcsError:
        return None
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _payload_link(body):
    try:
        top = json.loads(body, object_pairs_hook=_object_pairs)
    except ValueError:
        return None
    if not isinstance(top, dict):
        return None
    payload = top.get("payload")
    if not isinstance(payload, dict):
        return None
    link = payload.get("previousReceiptHash")
    return link if isinstance(link, str) else None


def verify_in_context(body, keys, chain_bodies):
    verdict, code = verify(body, keys)
    if verdict != VALID:
        return verdict, code
    for element in chain_bodies:
        verdict, code = verify(element, keys)
        if verdict != VALID:
            return UNDECIDABLE, "chain_element_not_valid"
    receipts = list(chain_bodies) + [body]
    for previous, current in zip(receipts, receipts[1:]):
        expected = _receipt_link(previous)
        if expected is None or _payload_link(current) != expected:
            return INVALID, "chain_link_mismatch"
    # Gaps stay open: RS-G-002 (commitment timing) is not applied, so the
    # draft's verdict (valid) is answered for commitment members.
    return VALID, None


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: w245_packet_conformance_verifier.py <receipt>\n")
        return 2
    jwks_path = os.environ.get("AEV_RECEIPT_JWKS")
    keys = _load_keys(jwks_path) if jwks_path else None
    if keys is None:
        _answer(UNDECIDABLE, "key_set_unavailable")
    try:
        with open(argv[1], "rb") as handle:
            body = handle.read()
    except OSError:
        _answer(UNDECIDABLE, "receipt_unreadable")
    chain = _load_context()
    if chain is None:
        verdict, code = verify(body, keys)
    else:
        verdict, code = verify_in_context(body, keys, chain)
    _answer(verdict, code)


if __name__ == "__main__":
    main(sys.argv)
