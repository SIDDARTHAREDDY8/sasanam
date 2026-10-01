"""Break-first red battery: posture-assessment cards + VSA-style summary
(wave-251 lane 1; ossf/scorecard + slsa-framework ADAPT).

The gap under test: the tree ships NO machine-readable way to answer
"what is this deployment's governance posture?" -- no posture cards,
no signed maturity summary. Each card probe must run against
deployment-supplied state (not a static claim) and fail closed when
state is unavailable.

On the pristine wave-250 base every probe reports GAP (the module
does not exist / exports nothing). After the build, every probe must
report HELD under both staging and a clean environment.

Synthetic/local only. Deterministic: fixed seeds, explicit issued
timestamps, sorted assertions. Stdlib only, no in-repo git
subprocesses.
"""

import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_module():
    """Return (gov.posture_cards, None) or (None, reason)."""
    try:
        from gov import posture_cards
        return posture_cards, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _full_state():
    """Deployment state with everything configured (synthetic)."""
    return {
        "assessed_at": "2026-09-30T00:00:00Z",
        "skill_admission": {
            "authority_pub": "ab" * 32,
            "admitted_layouts": 3,
        },
        "skill_update": {
            "pin": {"digest": "cd" * 32,
                    "not_after": "2027-01-01T00:00:00Z"},
        },
        "agent_identity": {
            "connector": "oidc",
            "subject_source": "sub",
        },
        "policy": {
            "combiner_active": True,
            "decision_log": {"root": "ef" * 32},
        },
        "evidence": {
            "enveloped_exports": 5,
            "graph": {"nodes": 12},
        },
        "durability": {
            "permit_journal": {"tip": "01" * 32},
        },
    }


def _keys():
    from gov import ed25519
    seed = b"\x77" * 32
    return seed, ed25519.publickey(seed).hex()


# ------------------------------------------------------------------
# probes
# ------------------------------------------------------------------

def probe_01_importable():
    mod, reason = load_module()
    if mod is None:
        return _record("import-importable", "GAP", reason)
    for name in ("assess", "issue_summary", "verify_summary",
                 "track_level", "TRACKS"):
        if not hasattr(mod, name):
            return _record("import-importable", "GAP",
                           "missing export: " + name)
    return _record("import-importable", "HELD")


def probe_02_cards_cover_tracks():
    mod, _ = load_module()
    if mod is None:
        return _record("cards-cover-tracks", "GAP", "no module")
    cards = mod.assess(_full_state())
    tracks = {c["track"] for c in cards}
    missing = set(mod.TRACKS) - tracks
    if missing:
        return _record("cards-cover-tracks", "GAP",
                       "tracks uncovered: %s" % sorted(missing))
    for c in cards:
        for key in ("check", "track", "probe", "score",
                    "reason", "remediation"):
            if key not in c:
                return _record("cards-cover-tracks", "GAP",
                               "card missing key: " + key)
    return _record("cards-cover-tracks", "HELD")


def probe_03_supply_chain_admission_pass():
    mod, _ = load_module()
    if mod is None:
        return _record("supply-chain-admission-pass", "GAP", "no module")
    cards = {c["check"]: c for c in mod.assess(_full_state())}
    card = cards.get("skill-admission-configured")
    if card is None or card["probe"] != "pass":
        return _record("supply-chain-admission-pass", "GAP",
                       "card=%r" % (card,))
    if card["score"] != 10:
        return _record("supply-chain-admission-pass", "GAP",
                       "score=%r" % (card["score"],))
    return _record("supply-chain-admission-pass", "HELD")


def probe_04_tuf_pin_expired_fails():
    mod, _ = load_module()
    if mod is None:
        return _record("tuf-pin-expired-fails", "GAP", "no module")
    state = _full_state()
    state["skill_update"]["pin"]["not_after"] = "2026-01-01T00:00:00Z"
    cards = {c["check"]: c for c in mod.assess(state)}
    card = cards.get("tuf-pins-fresh")
    if card is None or card["probe"] != "fail":
        return _record("tuf-pin-expired-fails", "GAP",
                       "card=%r" % (card,))
    if card["score"] != 0:
        return _record("tuf-pin-expired-fails", "GAP",
                       "score=%r" % (card["score"],))
    return _record("tuf-pin-expired-fails", "HELD")


def probe_05_identity_unavailable_fail_closed():
    mod, _ = load_module()
    if mod is None:
        return _record("identity-unavailable-fail-closed", "GAP",
                       "no module")
    state = _full_state()
    del state["agent_identity"]
    cards = {c["check"]: c for c in mod.assess(state)}
    card = cards.get("federated-identity-configured")
    if card is None or card["probe"] != "unavailable":
        return _record("identity-unavailable-fail-closed", "GAP",
                       "card=%r (must be unavailable, not pass)" % (card,))
    return _record("identity-unavailable-fail-closed", "HELD")


def probe_06_policy_cards_pass():
    mod, _ = load_module()
    if mod is None:
        return _record("policy-cards-pass", "GAP", "no module")
    cards = {c["check"]: c for c in mod.assess(_full_state())}
    for check in ("combiner-active", "decision-log-running"):
        card = cards.get(check)
        if card is None or card["probe"] != "pass":
            return _record("policy-cards-pass", "GAP",
                           "%s=%r" % (check, card))
    return _record("policy-cards-pass", "HELD")


def probe_07_evidence_cards_pass():
    mod, _ = load_module()
    if mod is None:
        return _record("evidence-cards-pass", "GAP", "no module")
    cards = {c["check"]: c for c in mod.assess(_full_state())}
    for check in ("dsse-envelopes-on-export", "evidence-graph-built"):
        card = cards.get(check)
        if card is None or card["probe"] != "pass":
            return _record("evidence-cards-pass", "GAP",
                           "%s=%r" % (check, card))
    return _record("evidence-cards-pass", "HELD")


def probe_08_durability_card_pass():
    mod, _ = load_module()
    if mod is None:
        return _record("durability-card-pass", "GAP", "no module")
    cards = {c["check"]: c for c in mod.assess(_full_state())}
    card = cards.get("permit-journal-active")
    if card is None or card["probe"] != "pass":
        return _record("durability-card-pass", "GAP", "card=%r" % (card,))
    return _record("durability-card-pass", "HELD")


def probe_09_vsa_summary_roundtrip():
    mod, _ = load_module()
    if mod is None:
        return _record("vsa-summary-roundtrip", "GAP", "no module")
    seed, pub = _keys()
    cards = mod.assess(_full_state())
    summary = mod.issue_summary("deployment:staging-1", cards, seed,
                                issuer="auditor:local",
                                issued_at="2026-09-30T00:00:00Z")
    record = mod.verify_summary(summary)
    if record["subject"] != "deployment:staging-1":
        return _record("vsa-summary-roundtrip", "GAP", "subject lost")
    levels = {t["track"]: t["level"] for t in record["tracks"]}
    if set(levels) != set(mod.TRACKS):
        return _record("vsa-summary-roundtrip", "GAP",
                       "tracks=%r" % sorted(levels))
    if levels["supply-chain"] != "full":
        return _record("vsa-summary-roundtrip", "GAP",
                       "levels=%r" % levels)
    return _record("vsa-summary-roundtrip", "HELD")


def probe_10_vsa_forged_signature_refused():
    mod, _ = load_module()
    if mod is None:
        return _record("vsa-forged-signature-refused", "GAP", "no module")
    seed, pub = _keys()
    cards = mod.assess(_full_state())
    summary = mod.issue_summary("deployment:staging-1", cards, seed,
                                issuer="auditor:local",
                                issued_at="2026-09-30T00:00:00Z")
    forged = json.loads(json.dumps(summary))
    forged["sig"] = "00" * 64
    try:
        mod.verify_summary(forged)
    except Exception as exc:  # noqa: BLE001 - refusal is the pin
        code = getattr(exc, "code", "")
        if code != "posture-card-unverifiable":
            return _record("vsa-forged-signature-refused", "GAP",
                           "wrong code: %r" % (code,))
        return _record("vsa-forged-signature-refused", "HELD")
    return _record("vsa-forged-signature-refused", "GAP",
                   "forged signature accepted")


def probe_11_track_levels():
    mod, _ = load_module()
    if mod is None:
        return _record("track-levels", "GAP", "no module")
    # full: all pass
    full_cards = mod.assess(_full_state())
    if mod.track_level(full_cards, "supply-chain") != "full":
        return _record("track-levels", "GAP", "full not full")
    # partial: one pass, one fail
    state = _full_state()
    state["skill_update"]["pin"]["not_after"] = "2026-01-01T00:00:00Z"
    partial_cards = mod.assess(state)
    if mod.track_level(partial_cards, "supply-chain") != "partial":
        return _record("track-levels", "GAP", "partial not partial")
    # absent: nothing passes
    absent = mod.track_level([], "supply-chain")
    if absent != "absent":
        return _record("track-levels", "GAP", "absent=%r" % (absent,))
    # unknown track refuses
    try:
        mod.track_level(full_cards, "nope")
    except Exception as exc:  # noqa: BLE001 - refusal is the pin
        if getattr(exc, "code", "") != "posture-card-unknown-track":
            return _record("track-levels", "GAP",
                           "wrong code: %r" % getattr(exc, "code", ""))
        return _record("track-levels", "HELD")
    return _record("track-levels", "GAP", "unknown track accepted")


def probe_12_machine_output_deterministic():
    mod, _ = load_module()
    if mod is None:
        return _record("machine-output-deterministic", "GAP", "no module")
    one = json.dumps(mod.assess(_full_state()), sort_keys=True,
                     separators=(",", ":"))
    two = json.dumps(mod.assess(_full_state()), sort_keys=True,
                     separators=(",", ":"))
    if one != two:
        return _record("machine-output-deterministic", "GAP",
                       "non-deterministic cards")
    seed, pub = _keys()
    cards = mod.assess(_full_state())
    s1 = mod.issue_summary("d", cards, seed, issuer="i",
                           issued_at="2026-09-30T00:00:00Z")
    s2 = mod.issue_summary("d", cards, seed, issuer="i",
                           issued_at="2026-09-30T00:00:00Z")
    if s1 != s2:
        return _record("machine-output-deterministic", "GAP",
                       "non-deterministic summary")
    return _record("machine-output-deterministic", "HELD")


PROBES = (
    probe_01_importable,
    probe_02_cards_cover_tracks,
    probe_03_supply_chain_admission_pass,
    probe_04_tuf_pin_expired_fails,
    probe_05_identity_unavailable_fail_closed,
    probe_06_policy_cards_pass,
    probe_07_evidence_cards_pass,
    probe_08_durability_card_pass,
    probe_09_vsa_summary_roundtrip,
    probe_10_vsa_forged_signature_refused,
    probe_11_track_levels,
    probe_12_machine_output_deterministic,
)


def main():
    for probe in PROBES:
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - probe errors are data
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    for r in RESULTS:
        print("%-38s %-5s %s" % (r["probe"], r["verdict"], r["detail"]))
    print("HELD=%d GAP=%d ERROR=%d" % (held, gap, err))
    return 0 if (gap or err) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
