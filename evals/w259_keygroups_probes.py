"""Break-first battery for SOPS-style key groups on encrypted envelopes.

Wave-259 lane 2 (feature lane). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Target (new in wave-259): ``gov/key_groups.py`` -- SOPS ADAPT (pattern
only, no SOPS code vendored): an envelope declares multiple key groups;
decryption succeeds if ANY one group reaches its quorum
(quorum-per-group, one-group-sufficient). Scope-bound wraps adapt the
sealed-secrets scope-bound OAEP-label lesson: each group entry binds
``key_id -> scope`` into the wrap KDF, so a wrapped data key is only
usable for its declared purpose/scope. The payload cipher stays the
documented stdlib HMAC-CTR + encrypt-then-MAC construction; the group
layer is policy around data-key wrapping, not a new cipher.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt at the public seam (``GroupVault.seal`` / ``GroupVault.open``).
Verdicts: HELD (attack refused with the required machine code, or the
positive contract holds), BREAK (genuine defect -> file as a finding),
BASELINE (pre-fix: ``gov.key_groups`` absent, every probe breaks).
"""

import json
import os
import struct
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)

try:
    from gov import key_groups as kg  # noqa: E402
    _HAVE_KG = True
    _IMPORT_ERROR = None
except Exception as e:  # noqa: BLE001 -- pre-fix red baseline
    kg = None
    _HAVE_KG = False
    _IMPORT_ERROR = e

TAXONOMY_PIN = 1802  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w259kg-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _require_kg():
    if not _HAVE_KG:
        return _break("gov.key_groups absent (pre-fix): %s"
                      % str(_IMPORT_ERROR)[:80])
    return None


def _mat(tag):
    # 32-byte deployment-supplied key material (deployment-owned
    # custody: the vault never generates or stores key material).
    return (b"keymat-" + tag.encode("utf-8")) * 4


def _vault():
    d = _tmpdir()
    return kg.GroupVault(os.path.join(d, "j.jsonl")), d


def _groups_2x2():
    # [[A, B] quorum 2, [C] quorum 1], all scope "audit-read".
    return [
        kg.KeyGroup([kg.KeyShare("key-A", _mat("A")),
                     kg.KeyShare("key-B", _mat("B"))],
                    quorum=2, name="ops"),
        kg.KeyGroup([kg.KeyShare("key-C", _mat("C"))],
                    quorum=1, name="auditor"),
    ]


# ---------------------------------------------------------------------------
# Positive contract
# ---------------------------------------------------------------------------

@probe("seal_open_roundtrip")
def p_roundtrip():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b'{"evidence": 1}', _groups_2x2(), scope="audit-read")
    out, meta = v.open(env, {"key-A": _mat("A"), "key-B": _mat("B")})
    if out != b'{"evidence": 1}':
        return _break("payload mismatch")
    if meta["group_index"] != 0:
        return _break("wrong group_index %r" % meta["group_index"])
    if sorted(meta["key_ids"]) != ["key-A", "key-B"]:
        return _break("wrong key_ids %r" % meta["key_ids"])
    return _held("round-trip ok, group 0, both keys attributed")


@probe("quorum_sufficient_partial")
def p_quorum_partial():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    groups = [kg.KeyGroup([kg.KeyShare("A", _mat("A")),
                           kg.KeyShare("B", _mat("B")),
                           kg.KeyShare("C", _mat("C"))],
                          quorum=2)]
    env = v.seal(b"q2", groups, scope="s")
    out, _meta = v.open(env, {"A": _mat("A"), "C": _mat("C")})
    if out != b"q2":
        return _break("quorum-2 open failed with 2 of 3 keys")
    return _held("2-of-3 quorum opens")


@probe("one_group_sufficient")
def p_one_group():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"one", _groups_2x2(), scope="audit-read")
    out, meta = v.open(env, {"key-C": _mat("C")})
    if out != b"one":
        return _break("single-key group did not open")
    if meta["group_index"] != 1:
        return _break("wrong group_index %r" % meta["group_index"])
    return _held("group 2 alone sufficient")


# ---------------------------------------------------------------------------
# Adversarial: key confusion
# ---------------------------------------------------------------------------

@probe("wrong_group_key_cross_use")
def p_cross_use():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"secret", _groups_2x2(), scope="audit-read")
    # Attack: present key-A's material under key-B's identity, hoping to
    # satisfy group 0's quorum of 2 with a single key's material.
    try:
        v.open(env, {"key-A": _mat("A"), "key-B": _mat("A")})
    except kg.KeyGroupError as e:
        if e.code == "keygroup-open-refused":
            return _held("cross-identity material refused, generic code")
        return _break("wrong code %r (expected keygroup-open-refused)"
                      % e.code)
    return _break("OPENED with cross-identity key material")


@probe("quorum_insufficient_refused")
def p_quorum_insufficient():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"secret", _groups_2x2(), scope="audit-read")
    try:
        v.open(env, {"key-A": _mat("A")})  # 1 of quorum 2; group 2 absent
    except kg.KeyGroupError as e:
        if e.code == "keygroup-open-refused":
            return _held("sub-quorum refused, generic code")
        return _break("wrong code %r" % e.code)
    return _break("OPENED below quorum")


@probe("quorum_inflation_duplicate_within_group")
def p_quorum_inflation():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    # Attack: same key twice in one group with quorum 2 -- one key's
    # material would count twice toward quorum.
    groups = [kg.KeyGroup([kg.KeyShare("A", _mat("A")),
                           kg.KeyShare("A", _mat("A"))],
                          quorum=2)]
    try:
        v.seal(b"x", groups, scope="s")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-seal-refused":
            return _held("duplicate key_id within group refused at seal")
        return _break("wrong code %r" % e.code)
    return _break("SEALED duplicate key_id with quorum 2")


# ---------------------------------------------------------------------------
# Adversarial: scope binding
# ---------------------------------------------------------------------------

@probe("scope_label_swapped")
def p_scope_swapped():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"secret", _groups_2x2(), scope="audit-read")
    try:
        v.open(env, {"key-C": _mat("C")}, scope="audit-write")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-scope-mismatch":
            return _held("swapped scope refused with explicit code")
        return _break("wrong code %r (expected keygroup-scope-mismatch)"
                      % e.code)
    return _break("OPENED under a swapped scope label")


@probe("header_tamper_generic_refusal")
def p_header_tamper():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = bytearray(v.seal(b"secret", _groups_2x2(), scope="audit-read"))
    # Flip a byte inside a scope CONTENT field (past the length
    # fields): 13 (fixed hdr) + 4 (group hdr) + 2 (id_len) + 5
    # ("key-A") + 2 (scope_len) = 26; byte 27 is inside "audit-read".
    # Lengths stay valid, so the tamper must die at the tag check.
    env[27] ^= 0x01
    try:
        v.open(bytes(env), {"key-A": _mat("A"), "key-B": _mat("B")})
    except kg.KeyGroupError as e:
        if e.code == "keygroup-open-refused":
            return _held("header content tamper -> generic refusal")
        return _break("wrong code %r" % e.code)
    return _break("OPENED after header tamper")


@probe("tag_tamper_generic_refusal")
def p_tag_tamper():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = bytearray(v.seal(b"secret", _groups_2x2(), scope="audit-read"))
    env[-1] ^= 0xFF
    try:
        v.open(bytes(env), {"key-C": _mat("C")})
    except kg.KeyGroupError as e:
        if e.code == "keygroup-open-refused":
            return _held("tag tamper -> generic refusal")
        return _break("wrong code %r" % e.code)
    return _break("OPENED after tag tamper")


@probe("duplicate_key_conflicting_scope")
def p_conflicting_scope():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    # Attack: same key_id bound to two different scopes across groups --
    # a share sealed for scope s1 must never be usable as scope s2.
    groups = [
        kg.KeyGroup([kg.KeyShare("A", _mat("A"), scope="scope-one")]),
        kg.KeyGroup([kg.KeyShare("A", _mat("A"), scope="scope-two")]),
    ]
    try:
        v.seal(b"x", groups, scope="scope-one")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-seal-refused":
            return _held("conflicting scope binding refused at seal")
        return _break("wrong code %r" % e.code)
    return _break("SEALED conflicting scope bindings for one key_id")


# ---------------------------------------------------------------------------
# Adversarial: fail-closed inputs
# ---------------------------------------------------------------------------

@probe("empty_groups_seal_refused")
def p_empty_groups():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    try:
        v.seal(b"x", [], scope="s")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-seal-refused":
            return _held("empty group list refused at seal")
        return _break("wrong code %r" % e.code)
    return _break("SEALED with zero groups")


@probe("empty_group_members_seal_refused")
def p_empty_members():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    try:
        v.seal(b"x", [kg.KeyGroup([])], scope="s")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-seal-refused":
            return _held("zero-member group refused at seal")
        return _break("wrong code %r" % e.code)
    return _break("SEALED a group with zero members")


@probe("unknown_key_id_explicit_refusal")
def p_unknown_key():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"secret", _groups_2x2(), scope="audit-read")
    try:
        v.open(env, {"key-Z": b"z" * 16})
    except kg.KeyGroupError as e:
        if e.code == "keygroup-unknown-key-id":
            return _held("undeclared key_id refused with explicit code")
        return _break("wrong code %r (expected keygroup-unknown-key-id)"
                      % e.code)
    return _break("OPENED with an undeclared key_id")


@probe("zero_resolvable_keys_refused")
def p_zero_resolvable():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = v.seal(b"secret", _groups_2x2(), scope="audit-read")
    try:
        v.open(env, {})
    except kg.KeyGroupError as e:
        if e.code == "keygroup-open-refused":
            return _held("no resolvable keys -> generic refusal")
        return _break("wrong code %r" % e.code)
    return _break("OPENED with zero key material")


@probe("bad_quorum_seal_refused")
def p_bad_quorum():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    for q, label in ((0, "quorum=0"), (5, "quorum>members")):
        groups = [kg.KeyGroup([kg.KeyShare("A", _mat("A"))], quorum=q)]
        try:
            v.seal(b"x", groups, scope="s")
        except kg.KeyGroupError as e:
            if e.code != "keygroup-seal-refused":
                return _break("%s: wrong code %r" % (label, e.code))
        else:
            return _break("SEALED with %s" % label)
    return _held("quorum 0 and quorum>members refused at seal")


@probe("weak_key_material_refused")
def p_weak_key():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    groups = [kg.KeyGroup([kg.KeyShare("A", b"short")])]
    try:
        v.seal(b"x", groups, scope="s")
    except kg.KeyGroupError as e:
        if e.code == "keygroup-seal-refused":
            return _held("sub-16-byte material refused at seal")
        return _break("wrong code %r" % e.code)
    return _break("SEALED with weak key material")


@probe("malformed_envelope_refused")
def p_malformed():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    env = bytearray(v.seal(b"secret", _groups_2x2(), scope="audit-read"))
    env[24] ^= 0x01  # scope_len field: length corruption is structural
    blobs = [(b"", "empty"), (b"SASKEYG1", "truncated"),
             (b"BADMAGIC\x00" + b"\x00" * 40, "bad magic"),
             (bytes(env), "length-field tamper")]
    for blob, label in blobs:
        try:
            v.open(blob, {"key-A": _mat("A")})
        except kg.KeyGroupError as e:
            if e.code != "keygroup-malformed":
                return _break("%s: wrong code %r" % (label, e.code))
        else:
            return _break("OPENED %s bytes" % label)
    return _held("structural failures -> keygroup-malformed")


# ---------------------------------------------------------------------------
# Hygiene: journal, freshness, taxonomy
# ---------------------------------------------------------------------------

@probe("journal_digest_only")
def p_journal():
    red = _require_kg()
    if red:
        return red
    v, d = _vault()
    payload = b"journal-plaintext-marker"
    env = v.seal(payload, _groups_2x2(), scope="audit-read")
    v.open(env, {"key-C": _mat("C")})
    raw = open(os.path.join(d, "j.jsonl"), "rb").read()
    for secret in (payload, _mat("A"), _mat("B"), _mat("C")):
        if secret in raw:
            return _break("journal leaks secret bytes")
    return _held("journal carries digests/ids only")


@probe("fresh_data_key_per_seal")
def p_fresh_key():
    red = _require_kg()
    if red:
        return red
    v, _d = _vault()
    e1 = v.seal(b"same", _groups_2x2(), scope="s")
    e2 = v.seal(b"same", _groups_2x2(), scope="s")
    if e1 == e2:
        return _break("two seals byte-identical (nonce reuse?)")
    return _held("seals differ (fresh data key + nonces)")


@probe("taxonomy_pin_and_codes")
def p_taxonomy():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        return _break("taxonomy has %d keys, pin is %d"
                      % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
    for c in ("keygroup-malformed", "keygroup-open-refused",
              "keygroup-scope-mismatch", "keygroup-seal-refused",
              "keygroup-unknown-key-id", "keygroup-version-unknown"):
        rec = decision_codes.TAXONOMY.get(c)
        if not rec or rec.get("code") != c:
            return _break("code %r missing/missorted in registry" % c)
    # Registry stays sorted (convention).
    keys = list(decision_codes.TAXONOMY.keys())
    if keys != sorted(keys):
        return _break("taxonomy not sorted")
    return _held("pin 1080, six keygroup codes registered and sorted")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent envelope battery still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w257_envelopes_probes.py",):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    held = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-42s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes"
          % (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
