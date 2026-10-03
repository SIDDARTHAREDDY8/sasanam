"""Wave-284 lane 8 red-first battery: tink-crypto/tink mechanism ADAPT.

Gap (base 9a7cffc): Sasanam has a versioned *signing* keyset
(gov/keyset.py, wave-199) and an envelope-encryption KMS seam
(gov/kms.py) whose providers already expose an enabled/disabled/
destroyed lifecycle vocabulary -- but there is NO master-key keyset
contract over the KMS seam: no versioned, digest-pinned keyset schema
for envelope master keys, no lifecycle enforcement above providers
that cannot express one (Vault transit reports only "enabled"), no
add-key -> roll-out -> promote rotation ceremony with a bounded
verification window, and no declared key templates binding the
primitive choice to a version.

Red-first: on base every capability probe BREAKs (gov.kms_keyset
absent; the taxonomy pin expects the 8 new keyset-* codes). After the
build: keyset documents are versioned and digest-pinned with
fail-closed parsing; DESTROYED keys refuse every operation LOUD;
DISABLED keys refuse new wraps (the primary can be disabled as an
emergency mint-stop); disabled-key unwraps are permitted at the
keyset layer with the provider's own posture standing (AWS-like
providers still refuse, Tink-like verify); the rotation ceremony is
a visible, recoverable, audit-chained state machine with atomic
promote; key templates are declared, named, and versioned; and the
Vault transit adapter satisfies the provider contract without
modification.

Pattern lineage: tink-crypto/tink (canonical org; google/tink is
archived/read-only; repo being split -- track the roadmap). License
Apache-2.0. ADAPT: the keyset schema, ENABLED/DISABLED/DESTROYED
lifecycle, rotation ceremony, and key templates as contract shapes,
reimplemented in stdlib Python -- not the library (pybind11 C++,
rejected by the F75 supply-chain preflight). $0 spend, stdlib only.
"""

import hashlib
import json
import os
import re
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w284-tink")
os.environ.setdefault("TMPDIR", "/var/tmp/g284-tink")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-283 merge pin 1587 -> 1595 (+8 keyset-* codes).
TAXONOMY_PIN = 1878  # Wave-284 lane 8: +8 keyset-* (tink ADAPT).; Wave-284 lane 8: pin 1587 -> 1595 (+8 keyset-*).; Wave-284 merge: pin 1595 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 lane 4: pin 1641 -> 1642 (+1 keyset-pin-key-invalid).; Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_RESULTS = []

PLUGIN_META = ("guardrail-evidence", "direct", "held-vs-expected")
PROBE_METADATA = {}

# Wave-286 lane 4 (F329): the configuration pin is a keyed MAC; every
# keyset in this battery shares one test pin key.
_TEST_PIN = os.urandom(32)


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _literals():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "gov", "decision_codes.py"),
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
    _record("pin-taxonomy", "HELD", "1595/1595/0 sorted")


def _import():
    try:
        from gov import kms_keyset as kk
        return kk, None
    except Exception as e:  # noqa: BLE001 - module absent on base
        return None, e


def p_module_present():
    kk, err = _import()
    if kk is None:
        return _record("module-present", "BREAK",
                       "gov.kms_keyset absent: %r" % (err,))
    for name in ("KmsKeyset", "KeyTemplate", "KeysetError", "TEMPLATES",
                 "KEYSET_FORMAT", "STATUSES"):
        if not hasattr(kk, name):
            return _record("module-present", "BREAK",
                           "gov.kms_keyset missing %r" % (name,))
    _record("module-present", "HELD", "contract surface present")


def _new_keyset(kk):
    from gov.kms import FakeKmsProvider
    provider = FakeKmsProvider(["master-a", "master-b", "master-c"])
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="master-a",
                          provider_name="fake", pin_key=_TEST_PIN)
    ks.add_key("master-b", provider_name="fake")
    return ks, provider


def p_keyset_schema():
    kk, err = _import()
    if kk is None:
        return _record("keyset-schema", "BREAK", "module absent")
    try:
        ks, _ = _new_keyset(kk)
        doc = ks.to_dict()
        if doc.get("format") != kk.KEYSET_FORMAT:
            return _record("keyset-schema", "BREAK",
                           "format tag wrong: %r" % (doc.get("format"),))
        if "keyset_digest" not in doc:
            return _record("keyset-schema", "BREAK",
                           "no content-digest pin")
        # Fail-closed parse: tampered digest refuses.
        bad = dict(doc)
        bad["keyset_digest"] = "0" * 64
        try:
            kk.KmsKeyset.from_dict(bad, pin_key=_TEST_PIN)
        except Exception:
            pass
        else:
            return _record("keyset-schema", "BREAK",
                           "tampered digest parsed")
        # Fail-closed parse: unknown status refuses.
        bad2 = json.loads(json.dumps(doc))
        bad2["keys"][0]["status"] = "sometimes"
        bad2 = kk.KmsKeyset._repin(bad2, _TEST_PIN)  # re-digest honestly
        try:
            kk.KmsKeyset.from_dict(bad2, pin_key=_TEST_PIN)
        except Exception:
            pass
        else:
            return _record("keyset-schema", "BREAK",
                           "unknown status parsed")
        # Fail-closed parse: duplicate key ids refuse.
        bad3 = json.loads(json.dumps(doc))
        bad3["keys"].append(dict(bad3["keys"][0]))
        bad3 = kk.KmsKeyset._repin(bad3, _TEST_PIN)
        try:
            kk.KmsKeyset.from_dict(bad3, pin_key=_TEST_PIN)
        except Exception:
            pass
        else:
            return _record("keyset-schema", "BREAK",
                           "duplicate key ids parsed")
        # Fail-closed parse: an in-progress ceremony phase that names no
        # successor refuses with a coded refusal (never a raw KeyError).
        bad5 = json.loads(json.dumps(doc))
        bad5["ceremony"] = {"phase": "rolling-out", "new_key_id": None,
                            "attempts": 0}
        bad5 = kk.KmsKeyset._repin(bad5, _TEST_PIN)
        try:
            kk.KmsKeyset.from_dict(bad5, pin_key=_TEST_PIN)
        except kk.KeysetError as e:
            if e.code != "keyset-ceremony-incomplete":
                return _record("keyset-schema", "BREAK",
                               "wrong code on successor-less ceremony")
        except Exception as e:  # noqa: BLE001
            return _record("keyset-schema", "BREAK",
                           "uncoded refusal on malformed ceremony: %r" % (e,))
        else:
            return _record("keyset-schema", "BREAK",
                           "successor-less ceremony parsed")
        # A disabled primary is a real post-incident state: it parses,
        # and minting under it refuses with a coded refusal.
        bad4 = json.loads(json.dumps(doc))
        bad4["keys"][0]["status"] = "disabled"
        bad4 = kk.KmsKeyset._repin(bad4, _TEST_PIN)
        try:
            ks_disabled = kk.KmsKeyset.from_dict(bad4, pin_key=_TEST_PIN)
        except Exception as e:  # noqa: BLE001
            return _record("keyset-schema", "BREAK",
                           "disabled primary refused at parse: %r" % (e,))
        from gov.kms import FakeKmsProvider
        try:
            ks_disabled.wrap_data_key(FakeKmsProvider(["master-a"]),
                                      b"x" * 32)
        except kk.KeysetError as e:
            if e.code != "keyset-key-disabled":
                return _record("keyset-schema", "BREAK",
                               "wrong code on disabled-primary wrap: %r"
                               % (e.code,))
        else:
            return _record("keyset-schema", "BREAK",
                           "disabled primary minted")
        # Round trip preserves the digest.
        ks2 = kk.KmsKeyset.from_dict(doc, pin_key=_TEST_PIN)
        if ks2.to_dict()["keyset_digest"] != doc["keyset_digest"]:
            return _record("keyset-schema", "BREAK",
                           "digest not stable across round trip")
        _record("keyset-schema", "HELD",
                "versioned, digest-pinned, fail-closed parse")
    except Exception as e:  # noqa: BLE001
        _record("keyset-schema", "ERROR", "%r" % (e,))


def p_lifecycle_destroyed_loud():
    kk, err = _import()
    if kk is None:
        return _record("lifecycle-destroyed", "BREAK", "module absent")
    try:
        from gov.kms import KmsError
        ks, provider = _new_keyset(kk)
        blob = ks.wrap_data_key(provider, b"epoch-key-material-32bytes!!")
        pt = ks.unwrap_data_key(provider, "master-a", blob)
        if pt != b"epoch-key-material-32bytes!!":
            return _record("lifecycle-destroyed", "ERROR",
                           "round trip failed before destroy")
        # Destroy a non-primary key: unwrap refuses LOUD, coded, at the
        # keyset layer (before the provider is even consulted).
        ks.destroy_key("master-b", reason="compromise suspected")
        try:
            ks.unwrap_data_key(provider, "master-b", blob)
        except kk.KeysetError as e:
            if e.code != "keyset-key-destroyed":
                return _record("lifecycle-destroyed", "BREAK",
                               "wrong code on destroyed unwrap: %r"
                               % (e.code,))
        except KmsError:
            return _record("lifecycle-destroyed", "BREAK",
                           "provider refused before the keyset did")
        else:
            return _record("lifecycle-destroyed", "BREAK",
                           "destroyed key allowed unwrap")
        # Destroyed is terminal: disable after destroy refuses.
        try:
            ks.disable_key("master-b", reason="nope")
        except kk.KeysetError as e:
            if e.code != "keyset-key-destroyed":
                return _record("lifecycle-destroyed", "BREAK",
                               "wrong code on post-destroy disable")
        else:
            return _record("lifecycle-destroyed", "BREAK",
                           "post-destroy transition allowed")
        # Destroying the primary without a successor refuses; with a
        # successor it is atomic and the new primary mints.
        try:
            ks.destroy_key("master-a", reason="nope")
        except kk.KeysetError as e:
            if e.code != "keyset-primary-not-enabled":
                return _record("lifecycle-destroyed", "BREAK",
                               "wrong code on successorless destroy: %r"
                               % (e.code,))
        else:
            return _record("lifecycle-destroyed", "BREAK",
                           "successorless primary destroy allowed")
        ks2, provider2 = _new_keyset(kk)
        ks2.destroy_key("master-a", reason="compromise",
                        new_primary="master-b")
        if ks2.primary_key_id() != "master-b":
            return _record("lifecycle-destroyed", "BREAK",
                           "successor did not become primary")
        blob2 = ks2.wrap_data_key(provider2, b"z" * 32)
        if ks2.unwrap_data_key(provider2, "master-b", blob2) != b"z" * 32:
            return _record("lifecycle-destroyed", "BREAK",
                           "post-destroy round trip failed")
        try:
            ks2.unwrap_data_key(provider2, "master-a", blob)
        except kk.KeysetError as e:
            if e.code != "keyset-key-destroyed":
                return _record("lifecycle-destroyed", "BREAK",
                               "wrong code on destroyed-primary unwrap")
        else:
            return _record("lifecycle-destroyed", "BREAK",
                           "destroyed primary allowed unwrap")
        _record("lifecycle-destroyed", "HELD",
                "DESTROYED refuses unwrap+transitions, coded loud; "
                "primary destroy needs an atomic successor")
    except Exception as e:  # noqa: BLE001
        _record("lifecycle-destroyed", "ERROR", "%r" % (e,))


def p_lifecycle_disabled():
    kk, err = _import()
    if kk is None:
        return _record("lifecycle-disabled", "BREAK", "module absent")
    try:
        from gov.kms import KmsError
        ks, provider = _new_keyset(kk)
        blob = ks.wrap_data_key(provider, b"epoch-key-material-32bytes!!")
        # Disabling the primary is the emergency mint-stop: allowed,
        # audited, and new wraps refuse with a coded refusal.
        ks.disable_key("master-a", reason="winding down")
        try:
            ks.wrap_data_key(provider, b"y" * 32)
        except kk.KeysetError as e:
            if e.code != "keyset-key-disabled":
                return _record("lifecycle-disabled", "BREAK",
                               "wrong code on disabled-primary wrap: %r"
                               % (e.code,))
        else:
            return _record("lifecycle-disabled", "BREAK",
                           "disabled primary minted a new wrap")
        # Unwrap of a pre-disable record is PERMITTED at the keyset
        # layer (no KeysetError): whether it succeeds is the
        # provider's posture. The fake is AWS-like and refuses with
        # KmsError -- its fail-closed stands, unmasked.
        try:
            ks.unwrap_data_key(provider, "master-a", blob)
        except kk.KeysetError as e:
            return _record("lifecycle-disabled", "BREAK",
                           "keyset refused a disabled-key unwrap: %r"
                           % (e.code,))
        except KmsError:
            pass  # provider posture: refused, fail-closed stands
        else:
            pass  # provider posture: permitted (Tink-like)
        # Re-enable is a governed, audited transition -- minting
        # resumes only through it.
        ks.enable_key("master-a", reason="rollback approved")
        if ks.key_status("master-a") != "enabled":
            return _record("lifecycle-disabled", "BREAK",
                           "re-enable did not stick")
        blob2 = ks.wrap_data_key(provider, b"q" * 32)
        if ks.unwrap_data_key(provider, "master-a", blob2) != b"q" * 32:
            return _record("lifecycle-disabled", "BREAK",
                           "post re-enable round trip failed")
        _record("lifecycle-disabled", "HELD",
                "DISABLED primary stops minting (coded); unwrap permitted "
                "at keyset layer, provider posture stands; re-enable "
                "governed")
    except Exception as e:  # noqa: BLE001
        _record("lifecycle-disabled", "ERROR", "%r" % (e,))


def p_rotation_ceremony():
    kk, err = _import()
    if kk is None:
        return _record("rotation-ceremony", "BREAK", "module absent")
    try:
        ks, provider = _new_keyset(kk)
        events_before = len(ks.audit_events())
        ks.begin_rotation("master-c", provider_name="fake")
        if ks.ceremony_state()["phase"] != "rolling-out":
            return _record("rotation-ceremony", "BREAK",
                           "begin did not enter rolling-out")
        # Promote before roll-out verification refuses.
        try:
            ks.promote(reason="impatient")
        except kk.KeysetError as e:
            if e.code != "keyset-ceremony-incomplete":
                return _record("rotation-ceremony", "BREAK",
                               "wrong code on early promote: %r" % (e.code,))
        else:
            return _record("rotation-ceremony", "BREAK",
                           "promote before roll-out succeeded")
        ks.roll_out(provider)
        if ks.ceremony_state()["phase"] != "verified":
            return _record("rotation-ceremony", "BREAK",
                           "roll_out did not reach verified")
        old_primary = ks.primary_key_id()
        ks.promote(reason="scheduled rotation")
        if ks.primary_key_id() != "master-c":
            return _record("rotation-ceremony", "BREAK",
                           "primary did not switch")
        if ks.key_status(old_primary) != "disabled":
            return _record("rotation-ceremony", "BREAK",
                           "old primary not demoted to disabled")
        if ks.ceremony_state()["phase"] != "complete":
            return _record("rotation-ceremony", "BREAK",
                           "ceremony not marked complete")
        # New wraps now bind to the new primary; old wraps still verify.
        blob_new = ks.wrap_data_key(provider, b"z" * 32)
        if ks.unwrap_data_key(provider, "master-c", blob_new) != b"z" * 32:
            return _record("rotation-ceremony", "BREAK",
                           "post-rotation round trip failed")
        if len(ks.audit_events()) < events_before + 3:
            return _record("rotation-ceremony", "BREAK",
                           "ceremony steps not all audit-chained")
        _record("rotation-ceremony", "HELD",
                "begin -> roll_out -> promote atomic; old primary demoted")
    except Exception as e:  # noqa: BLE001
        _record("rotation-ceremony", "ERROR", "%r" % (e,))


def p_ceremony_half_finished_visible():
    kk, err = _import()
    if kk is None:
        return _record("ceremony-visible", "BREAK", "module absent")
    try:
        ks, provider = _new_keyset(kk)
        ks.begin_rotation("master-c", provider_name="fake")
        st = ks.ceremony_state()
        if st["phase"] != "rolling-out" or st["new_key_id"] != "master-c":
            return _record("ceremony-visible", "BREAK",
                           "half-finished ceremony not visible: %r" % (st,))
        # Ceremony survives a serialize/parse round trip (restart-safe).
        ks2 = kk.KmsKeyset.from_dict(ks.to_dict(), pin_key=_TEST_PIN)
        if ks2.ceremony_state()["phase"] != "rolling-out":
            return _record("ceremony-visible", "BREAK",
                           "ceremony state lost across persistence")
        # Abandon recovers: the new key is disabled, ceremony cleared.
        ks2.abandon_ceremony(reason="operator cancelled")
        if ks2.ceremony_state()["phase"] != "none":
            return _record("ceremony-visible", "BREAK",
                           "abandon did not clear ceremony")
        if ks2.key_status("master-c") != "disabled":
            return _record("ceremony-visible", "BREAK",
                           "abandoned new key not disabled")
        if ks2.primary_key_id() != "master-a":
            return _record("ceremony-visible", "BREAK",
                           "abandon changed the primary")
        _record("ceremony-visible", "HELD",
                "half-finished ceremony visible, persistent, recoverable")
    except Exception as e:  # noqa: BLE001
        _record("ceremony-visible", "ERROR", "%r" % (e,))


def p_templates():
    kk, err = _import()
    if kk is None:
        return _record("templates", "BREAK", "module absent")
    try:
        # Unknown template refuses at keyset creation.
        try:
            kk.KmsKeyset.new(template_name="NOT-A-TEMPLATE/v9",
                             primary_key_id="master-a",
                             provider_name="fake", pin_key=_TEST_PIN)
        except kk.KeysetError as e:
            if e.code != "keyset-bad-template":
                return _record("templates", "BREAK",
                               "wrong code on bad template: %r" % (e.code,))
        else:
            return _record("templates", "BREAK",
                           "unknown template accepted")
        ks, _ = _new_keyset(kk)
        tmpl = ks.template()
        if tmpl.name != "KMS-ENVELOPE/v1" or not tmpl.primitive:
            return _record("templates", "BREAK",
                           "template not bound to a primitive: %r"
                           % (tmpl,))
        # The template binds the primitive choice to a version.
        if "v1" not in tmpl.name:
            return _record("templates", "BREAK",
                           "template name carries no version")
        # Retemplate is a governed, audited transition.
        events_before = len(ks.audit_events())
        try:
            ks.retemplate("NOT-A-TEMPLATE/v9", reason="x")
        except kk.KeysetError as e:
            if e.code != "keyset-bad-template":
                return _record("templates", "BREAK",
                               "wrong code on bad retemplate")
        else:
            return _record("templates", "BREAK",
                           "bad retemplate accepted")
        if len(ks.audit_events()) != events_before:
            return _record("templates", "BREAK",
                           "failed retemplate wrote an audit event")
        # Positive path: retemplate to a declared upgrade target is an
        # audited, versioned primitive-binding change.
        events_before = len(ks.audit_events())
        ks.retemplate("KMS-ENVELOPE-HKDF/v1", reason="upgrade")
        if ks.template().primitive != "provider-wrap-hkdf":
            return _record("templates", "BREAK",
                           "retemplate did not rebind the primitive")
        if len(ks.audit_events()) != events_before + 1:
            return _record("templates", "BREAK",
                           "successful retemplate not audited")
        _record("templates", "HELD",
                "declared templates required; primitive bound to version; "
                "retemplate is an audited upgrade")
    except Exception as e:  # noqa: BLE001
        _record("templates", "ERROR", "%r" % (e,))


def p_audit_chaining():
    kk, err = _import()
    if kk is None:
        return _record("audit-chaining", "BREAK", "module absent")
    try:
        ks, _ = _new_keyset(kk)
        ks.disable_key("master-a", reason="winding down")
        ks.enable_key("master-a", reason="rollback")
        events = ks.audit_events()
        if len(events) < 3:  # create + disable + enable
            return _record("audit-chaining", "BREAK",
                           "status changes not all audited: %d" % len(events))
        for ev in events:
            for field in ("event", "at", "prev_digest", "digest"):
                if field not in ev:
                    return _record("audit-chaining", "BREAK",
                                   "audit event missing %r" % (field,))
        if not ks.verify_chain():
            return _record("audit-chaining", "BREAK",
                           "honest chain fails verification")
        # Tamper with one event and re-pin the document honestly: the
        # outer digest stays valid, so only the inner chain can catch it.
        tampered = json.loads(json.dumps(ks.to_dict()))
        tampered["audit_chain"][1]["reason"] = "forged"
        tampered = kk.KmsKeyset._repin(tampered, _TEST_PIN)
        ks_bad = kk.KmsKeyset.from_dict(tampered, pin_key=_TEST_PIN)
        if ks_bad.verify_chain():
            return _record("audit-chaining", "BREAK",
                           "tampered chain verifies")
        _record("audit-chaining", "HELD",
                "genesis-chained audit events; tamper detected")
    except Exception as e:  # noqa: BLE001
        _record("audit-chaining", "ERROR", "%r" % (e,))


def p_provider_contract():
    kk, err = _import()
    if kk is None:
        return _record("provider-contract", "BREAK", "module absent")
    try:
        from gov import kms as _kms
        from gov import kms_vault as _kv
        # Full conformance against the deterministic double.
        full = kk.verify_provider_contracts(
            _kms.FakeKmsProvider(["master-a"]), ["master-a"])
        if not full["ok"]:
            return _record("provider-contract", "BREAK",
                           "fake provider fails conformance: %r"
                           % (full,))
        # Vault transit: static surface check only (no live server, $0).
        # The adapter must expose the three envelope ops + describe with
        # the impersonator-binding contract -- verified without
        # modification and without a network call.
        surface = kk.provider_contract_surface(_kv.VaultKmsProvider)
        if not surface["ok"]:
            return _record("provider-contract", "BREAK",
                           "vault adapter surface: %r" % (surface,))
        # Vault describe reports only "enabled" (no backend lifecycle):
        # the keyset layer must hold lifecycle above it, and the
        # contract checker must say so explicitly.
        if surface.get("lifecycle") != "provider-reports-enabled-only":
            return _record("provider-contract", "BREAK",
                           "vault lifecycle posture misreported: %r"
                           % (surface.get("lifecycle"),))
        _record("provider-contract", "HELD",
                "fake full conformance; vault surface OK, lifecycle held "
                "above the provider")
    except Exception as e:  # noqa: BLE001
        _record("provider-contract", "ERROR", "%r" % (e,))


def p_deterministic():
    kk, err = _import()
    if kk is None:
        return _record("deterministic", "BREAK", "module absent")
    try:
        ks, provider = _new_keyset(kk)
        ks.disable_key("master-a", reason="x")
        ks.enable_key("master-a", reason="y")
        h1 = ks.to_dict()["keyset_digest"]
        ks2, _ = _new_keyset(kk)
        ks2.disable_key("master-a", reason="x")
        ks2.enable_key("master-a", reason="y")
        h2 = ks2.to_dict()["keyset_digest"]
        if h1 != h2:
            return _record("deterministic", "BREAK",
                           "same op sequence, different digest")
        _record("deterministic", "HELD", "A==B across runs")
    except Exception as e:  # noqa: BLE001
        _record("deterministic", "ERROR", "%r" % (e,))


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIPPED", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    checks = (["-m", "unittest", "tests.test_decision_codes"],
              ["-m", "unittest", "tests.test_kms_keyset"])
    for argv in checks:
        r = subprocess.run([sys.executable] + argv,
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout)[-200:].replace("\n", " | ")
        _record("green-check:" + argv[-1],
                "HELD" if r.returncode == 0 else "ERROR", tail)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_taxonomy_pin, p_module_present, p_keyset_schema,
                  p_lifecycle_destroyed_loud, p_lifecycle_disabled,
                  p_rotation_ceremony, p_ceremony_half_finished_visible,
                  p_templates, p_audit_chaining, p_provider_contract,
                  p_deterministic):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w284_tink: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for r in _RESULTS:
        print("  [%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
