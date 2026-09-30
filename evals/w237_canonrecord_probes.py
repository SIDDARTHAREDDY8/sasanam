#!/usr/bin/env python3
"""Wave-237 lane C: agent-audit-record canonicalization contract (gilda).

Attack shapes at the public seams (break-first, red-first on base):

* a JSON record carrying a DUPLICATE member refuses
  ``record-duplicate-member`` (malformed) -- duplicate keys are a
  canonicalization hazard across deployments; the verifier must never
  silently keep the last value;
* a record nested deeper than 128 levels refuses
  ``record-depth-exceeded`` -- unbounded nesting is a parser-DoS shape
  (RFC 8785 / I-JSON depth discipline);
* any FLOAT value (1.0, 1.5, -0.0, 1e3) refuses
  ``record-noncanonical-float`` (malformed) -- floats do not survive
  language boundaries byte-identically, so any float is a
  cross-deployment digest hazard;
* two semantically-equal records (key order shuffled, whitespace
  changed) canonicalize to byte-identical output -- the digest join
  key is stable across deployments, never a local-serialization
  artifact;
* a producer-asserted ``tier`` field is IGNORED by tier derivation:
  derive_tier reads only content attributes (anchor/seal/receipt
  presence); a mismatch between asserted and derived tier is noted
  as ``record-tier-mismatch`` (a logged note, never a raised
  refusal -- the refusal belongs to the verifier, not this module);
* a digest computed over canonical bytes is identical across
  key-order shuffles;
* non-JSON bytes pass through byte-exact with the noted
  ``record-opaque-bytes`` marker -- never silently coerced into JSON.

Seams under test:
* gov/canonical_record.py -- canonicalize_record, derive_request_digest,
  derive_tier, CanonicalRecordError codes, MARKER constants.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-236 HEAD 9a725ce5fac37b95a2502eaebebfc33e7a8fb0d0.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g237c
  TMPDIR=/var/tmp/g237c ~/workspace/.gov-venv/bin/python evals/w237_canonrecord_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import canonical_record as _cr
    HAVE_NEW_API = all(hasattr(_cr, n) for n in (
        "canonicalize_record", "derive_request_digest", "derive_tier",
        "CanonicalRecordError", "MARKER_CANONICAL", "MARKER_OPAQUE",
        "MAX_NESTING_DEPTH"))
except ImportError:
    _cr = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "canonrecord-duplicate-member-malformed",
    "canonrecord-depth-129-refused",
    "canonrecord-float-malformed",
    "canonrecord-semantic-equality-byte-identical",
    "canonrecord-producer-tier-ignored",
    "canonrecord-digest-stable-key-order",
    "canonrecord-opaque-bytes-passthrough",
]


def _code_of(exc):
    return getattr(exc, "code", None)


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return (name, "GAP", "module absent on base")
    t0 = time.time()
    try:
        verdict, note = fn()
    except Exception:  # noqa: BLE001
        return (name, "ERROR", traceback.format_exc(limit=3).strip())
    return (name, "HELD" if verdict else "BREAK",
            "%s (%.1fms)" % (note, 1000 * (time.time() - t0)))


def probe_duplicate_member():
    # Duplicate members are a canonicalization hazard: two deployments
    # may keep different values. The verifier must refuse, never
    # silently keep the last one.
    try:
        _cr.canonicalize_record(b'{"a":1,"b":2,"a":3}')
    except _cr.CanonicalRecordError as exc:
        ok = exc.code == "record-duplicate-member"
        return ok, "refused %s" % exc.code
    return False, "duplicate member was ACCEPTED"


def probe_depth_129():
    # Depth counts the outermost value as depth 1. A chain of 128
    # nested objects puts its innermost scalar at depth 129 ->
    # refused; 127 nested objects (innermost scalar at depth 128)
    # pass. The boundary is pinned on the value-depth scale.
    deep = b'{"k":' * 128 + b'1' + b'}' * 128
    try:
        _cr.canonicalize_record(deep)
    except _cr.CanonicalRecordError as exc:
        refused = exc.code == "record-depth-exceeded"
    else:
        return False, "depth-129 chain was ACCEPTED"
    ok_chain = b'{"k":' * 127 + b'1' + b'}' * 127
    try:
        _cr.canonicalize_record(ok_chain)
    except _cr.CanonicalRecordError as exc:
        return False, "depth-128 chain refused (%s)" % exc.code
    return refused, "depth-129 refused, depth-128 passes"


def probe_float_malformed():
    # Any float -- integral (1.0) or fractional (1.5), exponent form
    # (1e3), negative zero -- is a cross-deployment digest hazard and
    # must be malformed, from dict values and from parsed JSON bytes.
    cases = [
        ({"a": 1.0}, "dict 1.0"),
        ({"a": 1.5}, "dict 1.5"),
        ({"a": -0.0}, "dict -0.0"),
        (b'{"a":1.0}', "bytes 1.0"),
        (b'{"a":1e3}', "bytes 1e3"),
    ]
    for value, label in cases:
        try:
            _cr.canonicalize_record(value)
        except _cr.CanonicalRecordError as exc:
            if exc.code != "record-noncanonical-float":
                return False, "%s refused with wrong code %s" % (label,
                                                                  exc.code)
        else:
            return False, "%s float was ACCEPTED" % label
    return True, "all 5 float shapes refused record-noncanonical-float"


def probe_semantic_equality():
    # Key order shuffled + whitespace changed must still produce
    # byte-identical canonical output: the digest join key is stable
    # across deployments, never a local-serialization artifact.
    a = {"zeta": 1, "alpha": [1, 2, {"m": "x", "b": None}], "mid": True}
    b = {"mid": True, "alpha": [1, 2, {"b": None, "m": "x"}], "zeta": 1}
    raw = b' { "zeta" : 1 ,\n "alpha" : [ 1 , 2 , { "m" : "x" , "b" : null } ] ,\n "mid" : true } '
    oa, ma = _cr.canonicalize_record(a)
    ob, mb = _cr.canonicalize_record(b)
    oraw, mraw = _cr.canonicalize_record(raw)
    ok = (oa == ob == oraw
          and ma == mb == mraw == _cr.MARKER_CANONICAL)
    return ok, "byte-identical=%s marker=%s" % (oa == ob == oraw, ma)


def probe_producer_tier_ignored():
    # Tier derivation reads content attributes only; the producer's
    # asserted "tier" field is ignored. A mismatch is noted (not
    # raised): the refusal belongs to the verifier.
    sealed = {"seal": "sig-bytes", "action": "read", "tier": 99}
    tier, mismatch = _cr.derive_tier(sealed)
    plain = {"action": "read", "tier": 3}
    tier2, mismatch2 = _cr.derive_tier(plain)
    tier3, mismatch3 = _cr.derive_tier({"action": "read", "tier": 0})
    ok = (tier == 2 and mismatch == "record-tier-mismatch"
          and tier2 == 0 and mismatch2 == "record-tier-mismatch"
          and tier3 == 0 and mismatch3 is None)
    return ok, ("sealed tier=%d note=%s; plain tier=%d note=%s; "
                "consistent tier=%d note=%s"
                % (tier, mismatch, tier2, mismatch2, tier3, mismatch3))


def probe_digest_stable():
    a = {"b": 2, "a": {"y": [3, 1], "x": "v"}}
    b = {"a": {"x": "v", "y": [3, 1]}, "b": 2}
    da = _cr.derive_request_digest(a)
    db = _cr.derive_request_digest(b)
    want = hashlib.sha256(_cr.canonicalize_record(a)[0]).hexdigest()
    ok = (da == db == want and len(da) == 64
          and all(c in "0123456789abcdef" for c in da))
    return ok, "digests match across key order: %s..." % da[:16]


def probe_opaque_passthrough():
    # Non-JSON bytes pass through byte-exact with the noted marker --
    # never silently coerced into (or out of) JSON.
    raw = b"\xff\xfe binary \x00 not json"
    octets, marker = _cr.canonicalize_record(raw)
    digest = _cr.derive_request_digest(raw)
    tier, mismatch = _cr.derive_tier(raw)
    ok = (octets == raw and marker == _cr.MARKER_OPAQUE
          and marker == "record-opaque-bytes"
          and digest == hashlib.sha256(raw).hexdigest()
          and tier == 0 and mismatch is None)
    return ok, "passthrough byte-exact, marker=%s, digest covers raw" % marker


_PROBES = {
    "canonrecord-duplicate-member-malformed": probe_duplicate_member,
    "canonrecord-depth-129-refused": probe_depth_129,
    "canonrecord-float-malformed": probe_float_malformed,
    "canonrecord-semantic-equality-byte-identical": probe_semantic_equality,
    "canonrecord-producer-tier-ignored": probe_producer_tier_ignored,
    "canonrecord-digest-stable-key-order": probe_digest_stable,
    "canonrecord-opaque-bytes-passthrough": probe_opaque_passthrough,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("record-duplicate-member", "record-depth-exceeded",
                     "record-noncanonical-float", "record-malformed"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-237 agent-audit-record canonicalization probes "
          "(new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-48s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR"
          % (held, gap, brk, err))
    for note in _run_green_checks():
        print("GREEN:", note)
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
