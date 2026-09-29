"""C2PA 2.4 conformance battery (wave-215 lane B, red-first).

PROVENANCE (honest, non-vendored):
  - The conformance RULES this battery checks are adapted from the
    official C2PA conformance rubric v1.0 (2026-08-06), which is
    CC-BY-4.0 *rules-only*. The rules are described in this repo's own
    words; no rubric text is copied into comments, docstrings, or
    strings anywhere in this wave's files.
  - There is NO official 2.4 binary test corpus anywhere. Vectors here
    are REGENERATED LOCALLY by ``_fixture`` builders below (marked
    "locally-regenerated"); ``public-testfiles`` is 2.2-only and
    CC-BY-SA share-alike, so nothing is vendored from it. c2pa-rs was
    unavailable in this environment (no cargo), so our own deterministic
    generator stands in for it -- fixtures are explicit local fixtures,
    not official vectors.

Scope: ``gov/c2pa24_conformance.py`` ONLY -- a conformance *verifier*.
``gov/c2pa_provenance.py`` emission semantics are untouched (2.2-shaped
by design); this battery never modifies it.

stdlib-only. Fail-closed: every refusal is ``C2PA24Error`` with a
``.code`` refusal code.
"""

import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _fixture_digest():
    """Deterministic fixture keypair: 32-byte seed -> seed, publickey."""
    # Fixed seeds keep the battery fully deterministic.
    return (bytes(range(1, 33)), None)


def _probe_import():
    try:
        import importlib
        mod = importlib.import_module("gov.c2pa24_conformance")
    except ImportError:
        return None
    if not hasattr(mod, "C2PA24Error"):
        return None
    return mod


def _mk_assertions(mod, labels):
    """Build a minimal assertions dict carrying the given labels.

    Each label's body is a valid representative value; individual
    probes override bodies for shape tests. All fixtures are
    locally-regenerated synthetic vectors, clearly marked."""
    asrt = {}
    for label in labels:
        if label == "c2pa.actions":
            asrt[label] = {"actions": [
                {"action": "c2pa.created", "softwareAgent": "fixture/1.0"}]}
        elif label == "c2pa.actions.v2":
            asrt[label] = {"version": 2, "actions": [
                {"action": "c2pa.created", "softwareAgent": "fixture/1.0"}]}
        elif label == "c2pa.ingredient":
            asrt[label] = {"ingredients": [
                {"ingredient_digest": "ab" * 32, "relationship": "parentOf",
                 "role": "prompt"}]}
        elif label == "c2pa.ingredient.v3":
            asrt[label] = {"version": 3, "ingredients": [
                {"ingredient_digest": "ab" * 32, "relationship": "parentOf",
                 "role": "prompt"}]}
        elif label == "c2pa.ai-disclosure":
            asrt[label] = {"aiDisclosure": {"label": "ai-generated"}}
        else:
            asrt[label] = {"arbitrary": True}
    # Fixture provenance is recorded on the fixture document envelope by
    # the battery (never inside the assertions under test).
    return asrt


def _expect_code(mod, name, fn, code):
    """fn must raise C2PA24Error whose .code == code -> HELD."""
    try:
        fn()
    except mod.C2PA24Error as exc:
        got = getattr(exc, "code", "<no-code>")
        if got == code:
            _record(name, "HELD", "refused with code %r" % got)
        else:
            _record(name, "BREAK", "wrong code %r (wanted %r)" % (got, code))
    except Exception as exc:  # noqa: BLE001
        _record(name, "BREAK", "wrong exception %s" % type(exc).__name__)
    else:
        _record(name, "BREAK", "no refusal (wanted code %r)" % code)


def _expect_ok(mod, name, fn, detail="accepted"):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        _record(name, "BREAK", "%s: %s" % (type(exc).__name__, exc))
    else:
        _record(name, "HELD", detail)


def _run_once(mod):
    from gov import ed25519 as _ed
    issuer_seed, _ = _fixture_digest()
    foreign_seed = bytes(range(33, 65))
    issuer_pub = _ed.publickey(issuer_seed)
    foreign_pub = _ed.publickey(foreign_seed)

    # --- vocabulary gates -------------------------------------------
    _expect_code(mod, "c24_deprecated_actions_refused_by_default",
                 lambda: mod.verify_24_vocabulary(
                     _mk_assertions(mod, ["c2pa.actions"])),
                 "deprecated-assertion-version")
    _expect_code(mod, "c24_deprecated_ingredient_refused_by_default",
                 lambda: mod.verify_24_vocabulary(
                     _mk_assertions(mod, ["c2pa.ingredient"])),
                 "deprecated-assertion-version")
    _expect_ok(mod, "c24_actions_v2_accepted",
               lambda: mod.verify_24_vocabulary(
                   _mk_assertions(mod, ["c2pa.actions.v2"])),
               "c2pa.actions.v2 accepted")
    _expect_code(mod, "c24_actions_v2_shape_enforced",
                 lambda: mod.verify_24_vocabulary(
                     {"c2pa.actions.v2": {"version": 2, "actions": [{}]}}),
                 "bad-assertion-shape")
    _expect_code(mod, "c24_actions_v2_unknown_action_refused",
                 lambda: mod.verify_24_vocabulary(
                     {"c2pa.actions.v2": {
                         "version": 2,
                         "actions": [{"action": "c2pa.teleported"}]}}),
                 "unknown-action-label")
    _expect_ok(mod, "c24_ingredient_v3_accepted",
               lambda: mod.verify_24_vocabulary(
                   _mk_assertions(mod, ["c2pa.ingredient.v3"])),
               "c2pa.ingredient.v3 accepted")
    _expect_ok(mod, "c24_ai_disclosure_allowed",
               lambda: mod.verify_24_vocabulary(
                   _mk_assertions(mod, ["c2pa.ai-disclosure"])),
               "c2pa.ai-disclosure allowed")
    _expect_code(mod, "c24_unknown_label_refused",
                 lambda: mod.verify_24_vocabulary(
                     {"c2pa.brand.newlabel": {"x": 1}}),
                 "unknown-assertion-label")
    _expect_code(mod, "c24_unknown_versioned_label_refused",
                 lambda: mod.verify_24_vocabulary(
                     {"c2pa.actions.v9": {"version": 9, "actions": []}}),
                 "unknown-assertion-label")

    # --- deprecation re-pin (digest-bound, signed) --------------------
    asrt = _mk_assertions(mod, ["c2pa.actions"])
    digest = mod.assertions_digest(asrt)
    pin = mod.sign_deprecation_pin(
        issuer_seed, label="c2pa.actions", assertions_digest=digest,
        reason="fixture legacy ingest")
    _expect_ok(mod, "c24_deprecation_pin_accepts",
               lambda: mod.verify_24_vocabulary(
                   asrt, deprecated_pins=[pin],
                   deprecated_pin_issuer_pub=issuer_pub),
               "digest-bound pin admits deprecated label")
    wrong_asrt = _mk_assertions(mod, ["c2pa.actions"])
    wrong_asrt["_fixture_note"] = "different payload"
    wrong = mod.assertions_digest(wrong_asrt)
    _expect_code(mod, "c24_deprecation_pin_digest_bound",
                 lambda: mod.verify_24_vocabulary(
                     wrong_asrt,
                     deprecated_pins=[pin],
                     deprecated_pin_issuer_pub=issuer_pub),
                 "bad-pin")
    badkey_pin = mod.sign_deprecation_pin(
        foreign_seed, label="c2pa.actions", assertions_digest=digest,
        reason="forged")
    _expect_code(mod, "c24_deprecation_pin_wrong_key_refused",
                 lambda: mod.verify_24_vocabulary(
                     asrt, deprecated_pins=[badkey_pin],
                     deprecated_pin_issuer_pub=issuer_pub),
                 "bad-pin")

    # --- legacy builder pressure: 2.2-shaped emission is refused by
    # the 2.4 verifier by default, admitted only with an explicit pin.
    from gov import c2pa_provenance as _c2
    legacy = _c2.build_manifest(
        content_digest="cd" * 32, content_len=64,
        action="c2pa.created", software_agent="fixture/1.0")
    _expect_code(mod, "c24_legacy_builder_output_deprecated",
                 lambda: mod.verify_24_vocabulary(
                     legacy["assertions"]),
                 "deprecated-assertion-version")
    legacy_digest = mod.assertions_digest(legacy["assertions"])
    legacy_pin_actions = mod.sign_deprecation_pin(
        issuer_seed, label="c2pa.actions",
        assertions_digest=legacy_digest, reason="legacy ingest")
    legacy_pin_ingredient = mod.sign_deprecation_pin(
        issuer_seed, label="c2pa.ingredient",
        assertions_digest=legacy_digest, reason="legacy ingest")
    _expect_ok(mod, "c24_legacy_builder_output_pinnable",
               lambda: mod.verify_24_vocabulary(
                   legacy["assertions"],
                   deprecated_pins=[legacy_pin_actions,
                                    legacy_pin_ingredient],
                   deprecated_pin_issuer_pub=issuer_pub),
               "legacy emission admitted only via explicit pins")

    # --- trust-list layering default -> itl -> custom -----------------
    store = mod.TrustStore()
    for layer, trust in (("default", "allow"), ("itl", "deny"),
                         ("custom", "allow")):
        rec = mod.sign_trust_record(
            issuer_seed, layer=layer, key_id="key-A", trust=trust)
        store.add_record(rec, issuer_pub=issuer_pub)
    _expect_ok(mod, "c24_trust_custom_overrides",
               lambda: _check(store.check("key-A") == "allow"),
               "custom allow beats itl deny")
    store2 = mod.TrustStore()
    for layer, trust in (("default", "allow"), ("itl", "deny")):
        rec = mod.sign_trust_record(
            issuer_seed, layer=layer, key_id="key-B", trust=trust)
        store2.add_record(rec, issuer_pub=issuer_pub)
    _expect_code(mod, "c24_trust_itl_beats_default",
                 lambda: store2.check("key-B"),
                 "signer-denied")
    _expect_code(mod, "c24_trust_unknown_signer_refused",
                 lambda: store2.check("key-nobody"),
                 "untrusted-signer")
    unsigned = {"layer": "default", "key_id": "key-C", "trust": "allow",
                "signer": {"kid": "issuer"}}
    _expect_code(mod, "c24_trust_unsigned_record_refused",
                 lambda: store2.add_record(unsigned, issuer_pub=issuer_pub),
                 "bad-trust-signature")
    dup_store = mod.TrustStore()
    r1 = mod.sign_trust_record(
        issuer_seed, layer="default", key_id="key-D", trust="allow")
    dup_store.add_record(r1, issuer_pub=issuer_pub)
    r2 = mod.sign_trust_record(
        issuer_seed, layer="default", key_id="key-D", trust="deny")
    _expect_code(mod, "c24_trust_duplicate_keyid_refused",
                 lambda: dup_store.add_record(r2, issuer_pub=issuer_pub),
                 "duplicate-trust-record")


def _check(cond):
    if not cond:
        raise AssertionError("expected True")


def _run(mod):
    _run_once(mod)
    second_start = len(_records)
    _run_once(mod)
    first = _records[:second_start]
    second = _records[second_start:]
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    del _records[second_start:]
    _record("determinism", "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(first)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)


def _green_check_adjacent():
    # Depth-1 green check: never spawn nested batteries.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check skipped by convention "
                        "(tests/test_c2pa24_conformance.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="c24-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_c2pa24_conformance",
         "tests.test_c2pa_provenance",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


def main():
    probe_names = [
        "c24_deprecated_actions_refused_by_default",
        "c24_deprecated_ingredient_refused_by_default",
        "c24_actions_v2_accepted",
        "c24_actions_v2_shape_enforced",
        "c24_actions_v2_unknown_action_refused",
        "c24_ingredient_v3_accepted",
        "c24_ai_disclosure_allowed",
        "c24_unknown_label_refused",
        "c24_unknown_versioned_label_refused",
        "c24_deprecation_pin_accepts",
        "c24_deprecation_pin_digest_bound",
        "c24_deprecation_pin_wrong_key_refused",
        "c24_legacy_builder_output_deprecated",
        "c24_legacy_builder_output_pinnable",
        "c24_trust_custom_overrides",
        "c24_trust_itl_beats_default",
        "c24_trust_unknown_signer_refused",
        "c24_trust_unsigned_record_refused",
        "c24_trust_duplicate_keyid_refused",
    ]
    mod = _probe_import()
    if mod is None:
        for name in probe_names:
            _record(name, "GAP", "module absent on pristine tree")
    else:
        _run(mod)
    print("== c2pa-2.4 conformance battery ==")
    for n, v, d in _records:
        print("[%s] %s -- %s" % (v, n, d))
    npass = sum(1 for _, v, _ in _records if v in ("PASS", "HELD"))
    # GAP counts as failing: a red-first battery must exit nonzero on
    # the pristine tree.
    nfail = sum(1 for _, v, _ in _records
                if v in ("FAIL", "BREAK", "ERROR", "GAP"))
    nskip = sum(1 for _, v, _ in _records if v == "SKIP")
    print("PASS=%d FAIL/ERROR/GAP=%d SKIP=%d" % (npass, nfail, nskip))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
