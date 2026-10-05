"""Wave-286 lane 3 battery: F327 + F328 closure probes (gov/kms_keyset.py).

F327 (LOW): KmsKeyset.from_dict on a ceremony missing new_key_id raises
raw KeyError, not coded KeysetError -- the public _repin crashes
identically. The coded-refusal contract at the deserialization seam
must hold: every malformed ceremony shape refuses with a coded
``keyset-*`` KeysetError, never a raw KeyError/AttributeError, and a
malformed shape is never accepted silently.

F328 (LOW): promote() demotes the successor when old_primary ==
new_key_id -- destroying a possibly-compromised old primary mid-ceremony
naming the in-flight successor (plausible incident response) makes the
ceremony "complete" while silently disabling the new primary
(mint-stop). promote() must skip the self-demotion so the ceremony
completes with the successor enabled.

Red-first: on the wave-285 base the F327/F328 defect probes BREAK; after
the fix all probes HELD.

Run:
  mkdir -p /var/tmp/g286-f327 && TMPDIR=/var/tmp/g286-f327 \
    ~/workspace/.gov-venv/bin/python evals/w286_f327_f328_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-f327b \
    ~/workspace/.gov-venv/bin/python evals/w286_f327_f328_probes.py
"""

import importlib.util
import json
import os
import sys

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-285 merge: pin 1621 -> 1641 (+1 campaign-produces-suppressed
# +1 inventory-identity-collision +7 anchor-* +11 exception-*).
# This lane adds no decision codes.
TAXONOMY_PIN = 2083 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def p_taxonomy_pin():
    import re
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def _fresh_keyset():
    from gov import kms_keyset as kk
    # Wave-286 merge: new() requires the deployment-held pin key (F329).
    pin_key = os.urandom(32)
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="key-a", provider_name="fake",
                          pin_key=pin_key)
    return ks, pin_key


def _coded_refusal(pid, fn, label):
    """Expect fn() to raise a coded KeysetError (never raw, never pass)."""
    from gov import kms_keyset as kk
    try:
        fn()
    except kk.KeysetError as e:
        if e.code and e.code.startswith("keyset-"):
            return _record(pid, "HELD", "%s: coded %s" % (label, e.code))
        return _record(pid, "BREAK",
                       "%s: KeysetError without keyset-* code: %r"
                       % (label, e.code))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "%s: raw %s escapes: %r"
                       % (label, type(e).__name__, e))
    _record(pid, "BREAK", "%s: malformed ceremony accepted silently" % label)


# ---------------------------------------------------------------------------
# F327: malformed ceremonies refuse with a coded keyset-* KeysetError
# ---------------------------------------------------------------------------

def p_f327_missing_new_key_id_none():
    # The red-team repro: a persisted doc whose ceremony lost the
    # successor slot must not crash the digest builder with KeyError.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "none"}

    def go():
        kk.KmsKeyset.from_dict(doc, pin_key=pin_key)
    _coded_refusal("f327-missing-new-key-id-none", go,
                   'ceremony {"phase": "none"} without new_key_id')


def p_f327_missing_new_key_id_complete():
    # Same defect class at the "complete" phase: a re-pinned doc with
    # no successor slot must be refused coded, not crash in _digest_for.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "complete", "attempts": 1}

    def go():
        # _repin is public and crashes identically on the malformed
        # shape (F327); both seams must refuse coded.
        kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc, pin_key=pin_key))
    _coded_refusal("f327-missing-new-key-id-complete", go,
                   'ceremony {"phase": "complete"} without new_key_id')


def p_f327_ceremony_not_a_mapping():
    # A non-dict ceremony must not escape as AttributeError on .get().
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = "rolling-out"
    doc["keyset_digest"] = "0" * 64  # shape check must fire first

    def go():
        kk.KmsKeyset.from_dict(doc, pin_key=pin_key)
    _coded_refusal("f327-ceremony-not-a-mapping", go,
                   'ceremony "rolling-out" (not a mapping)')


def p_f327_missing_ceremony():
    # A missing ceremony key refuses coded (regression: already held).
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    del doc["ceremony"]

    def go():
        kk.KmsKeyset.from_dict(doc, pin_key=pin_key)
    _coded_refusal("f327-missing-ceremony", go, "missing ceremony key")


def p_f327_wrong_type_new_key_id():
    # new_key_id of the wrong type on a settled phase is malformed;
    # it must not be digested silently into an "honest" pin.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "none", "new_key_id": 5, "attempts": 0}

    def go():
        kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc, pin_key=pin_key))
    _coded_refusal("f327-wrong-type-new-key-id", go,
                   'ceremony {"phase": "none", "new_key_id": 5}')


def p_f327_inprogress_missing_attempts():
    # roll_out reads ceremony["attempts"]; an in-progress phase without
    # it is malformed and must be refused at parse, not KeyError later.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "rolling-out", "new_key_id": "key-b"}

    def go():
        kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc, pin_key=pin_key))
    _coded_refusal("f327-inprogress-missing-attempts", go,
                   'ceremony {"phase": "rolling-out"} without attempts')


def p_f327_inprogress_without_successor_still_refused():
    # Pre-existing guard (w284_tink regression): an in-progress phase
    # naming no successor refuses coded.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "rolling-out", "new_key_id": None,
                       "attempts": 0}

    def go():
        kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc, pin_key=pin_key))
    _coded_refusal("f327-inprogress-without-successor", go,
                   'ceremony {"phase": "rolling-out", "new_key_id": None}')


def p_f327_wellformed_roundtrip():
    # The fix must not reject honest documents: new() -> to_dict ->
    # from_dict still parses, and a full ceremony still round-trips.
    from gov import kms_keyset as kk
    from gov.kms import FakeKmsProvider
    ks, pin_key = _fresh_keyset()
    ks2 = kk.KmsKeyset.from_dict(ks.to_dict(), pin_key=pin_key)
    if ks2.primary_key_id() != "key-a":
        return _record("f327-wellformed-roundtrip", "BREAK",
                       "honest phase-none doc no longer parses")
    ks.begin_rotation("key-b", provider_name="fake")
    ks.roll_out(FakeKmsProvider(["key-a", "key-b"]))
    ks.promote(reason="test")
    ks3 = kk.KmsKeyset.from_dict(json.loads(json.dumps(ks.to_dict())), pin_key=pin_key)
    if ks3.ceremony_state()["phase"] != "complete":
        return _record("f327-wellformed-roundtrip", "BREAK",
                       "honest phase-complete doc no longer parses")
    _record("f327-wellformed-roundtrip", "HELD",
            "honest none/complete documents still parse")


# ---------------------------------------------------------------------------
# F328: promote() must not demote the successor when
# old_primary == new_key_id
# ---------------------------------------------------------------------------

def p_f328_promote_skips_self_demotion():
    # The red-team repro: destroy the possibly-compromised old primary
    # mid-ceremony naming the in-flight successor, then promote. The
    # ceremony must complete with the successor ENABLED (no mint-stop).
    from gov import kms_keyset as kk
    from gov.kms import FakeKmsProvider
    ks, pin_key = _fresh_keyset()
    prov = FakeKmsProvider(["key-a", "key-b"])
    ks.begin_rotation("key-b", provider_name="fake")
    ks.roll_out(prov)
    ks.destroy_key("key-a", reason="incident", new_primary="key-b")
    ks.promote(reason="incident-response")
    if ks.key_status("key-b") != "enabled":
        return _record("f328-promote-skips-self-demotion", "BREAK",
                       "promote demoted the successor key-b when "
                       "old_primary == new_key_id; phase=%s (mint-stop)"
                       % ks.ceremony_state()["phase"])
    if ks.ceremony_state()["phase"] != "complete":
        return _record("f328-promote-skips-self-demotion", "BREAK",
                       "ceremony did not complete; phase=%s"
                       % ks.ceremony_state()["phase"])
    try:
        ks.wrap_data_key(prov, b"x" * 32)
    except Exception as e:  # noqa: BLE001
        return _record("f328-promote-skips-self-demotion", "BREAK",
                       "mint still refused after promote: %r" % (e,))
    _record("f328-promote-skips-self-demotion", "HELD",
            "successor stays enabled; ceremony complete; mint works")


def p_f328_normal_promote_still_demotes():
    # Regression: the ordinary rotation path still winds the old
    # primary down to disabled at promote.
    from gov import kms_keyset as kk
    from gov.kms import FakeKmsProvider
    ks, pin_key = _fresh_keyset()
    prov = FakeKmsProvider(["key-a", "key-b"])
    ks.begin_rotation("key-b", provider_name="fake")
    ks.roll_out(prov)
    ks.promote(reason="routine")
    if ks.primary_key_id() != "key-b":
        return _record("f328-normal-promote", "BREAK",
                       "primary not switched on normal promote")
    if ks.key_status("key-a") != "disabled":
        return _record("f328-normal-promote", "BREAK",
                       "old primary not wound down on normal promote")
    if ks.key_status("key-b") != "enabled":
        return _record("f328-normal-promote", "BREAK",
                       "successor not enabled on normal promote")
    _record("f328-normal-promote", "HELD",
            "normal promote: switch + wind-down unchanged")


def p_f328_destroy_primary_without_successor_refused():
    # Regression: destroying the primary without naming a successor
    # is still refused loudly.
    from gov import kms_keyset as kk
    ks, pin_key = _fresh_keyset()

    def go():
        ks.destroy_key("key-a", reason="test")
    _coded_refusal("f328-destroy-primary-no-successor", go,
                   "destroy primary without new_primary")


_PROBES = [
    p_taxonomy_pin,
    p_f327_missing_new_key_id_none,
    p_f327_missing_new_key_id_complete,
    p_f327_ceremony_not_a_mapping,
    p_f327_missing_ceremony,
    p_f327_wrong_type_new_key_id,
    p_f327_inprogress_missing_attempts,
    p_f327_inprogress_without_successor_still_refused,
    p_f327_wellformed_roundtrip,
    p_f328_promote_skips_self_demotion,
    p_f328_normal_promote_still_demotes,
    p_f328_destroy_primary_without_successor_refused,
]


def _green_checks():
    # Depth-1: the wave-285 red-team pins for F327/F328 must read HELD
    # on this tree. Call the probe functions directly (no subprocess
    # nesting); never call the other battery's main().
    if SKIP_GREEN:
        _record("green-skip", "HELD", "GOV_SKIP_GREEN=1; checks skipped")
        return
    path = os.path.join(REPO, "evals", "w285_redteam_probes.py")
    spec = importlib.util.spec_from_file_location("w285_redteam_probes",
                                                  path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for fn_name, pid in (("p_f327_ceremony_keyerror", "f327-ceremony-keyerror"),
                         ("p_f328_promote_demotes_successor",
                          "f328-promote-demotes-successor")):
        mod._results.clear()
        getattr(mod, fn_name)()
        verdicts = [v for p, v, _ in mod._results if p == pid]
        if verdicts == ["HELD"]:
            _record("green-" + pid, "HELD", "w285_redteam pin HELD")
        else:
            _record("green-" + pid, "BREAK",
                    "w285_redteam pin not HELD: %r" % (mod._results,))


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-286 f327+f328: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    probe_lines.emit((pid, v, probe_lines.first_line(n)[:160])
                     for pid, v, n in _results)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
