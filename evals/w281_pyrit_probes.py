"""Wave-281 lane 8 red-first battery: PyRIT-pattern attack ledger.

Gap (base b95c0e5): red-team batteries are per-wave probe scripts with no
persistent attack memory. A BREAK found in wave N cannot be re-run
deterministically in wave N+1 from a stored seed; there is no scorer
protocol (verdict, rationale) feeding an adaptive loop; there is no
score<->observation referential integrity; there is no replay diff that
catches regressions.

Red-first: on base every probe BREAKs (gov.attack_ledger absent).
After the fix: scenarios register as deterministic seed->attack plans,
every observation is content-addressed, scores cannot reference
nonexistent observations, the ledger is hash-chained, replay is
byte-identical, and replay DIFFS catch a planted regression.

Pattern lineage: microsoft/PyRIT (MIT) -- MemoryInterface /
PromptMemoryEntry / SeedEntry / ScoreEntry / score<->observation links /
ScenarioResultEntry plan_seed_id_map. Mechanism only, no PyRIT code
vendored; stdlib sqlite3 covers the contract.
"""

import hashlib
import os
import secrets
import sqlite3
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w281-pyrit")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TAXONOMY_PIN = 1812  # Wave-280 merge: 1495 -> 1541. This lane adds no codes.; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_evidence(probe_id):
    try:
        from gov import attack_ledger as al
        return al
    except ImportError:
        _record(probe_id, "BREAK", "gov.attack_ledger absent on base")
        return None


def _tmpdb():
    d = tempfile.mkdtemp(prefix="pyrit-",
                         dir=os.environ.get("TMPDIR", "/tmp"))
    return os.path.join(d, "ledger.sqlite3")


# -- probes ---------------------------------------------------------------

def p_module_present():
    al = _needs_evidence("p_module_present")
    if al is None:
        return
    for name in ("AttackLedger", "Scorer", "SubstringScorer",
                 "DriftScorer", "apply_converters"):
        if not hasattr(al, name):
            _record("p_module_present", "BREAK",
                    "missing export %s" % name)
            return
    _record("p_module_present", "HELD", "attack_ledger exports present")


def p_seed_determinism():
    al = _needs_evidence("p_seed_determinism")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    s1 = led.record_seed("regression/f304-eviction", b"\x01" * 16)
    s2 = led.record_seed("regression/f304-eviction", b"\x01" * 16)
    if s1 != s2:
        _record("p_seed_determinism", "BREAK",
                "same label+bytes gave different seed ids")
        return
    want = hashlib.sha256(b"regression/f304-eviction" + b"\x01" * 16).hexdigest()
    if s1 != want:
        _record("p_seed_determinism", "BREAK", "seed id not sha256-bound")
        return
    _record("p_seed_determinism", "HELD",
            "seed ids deterministic and sha256-bound")


def p_piece_content_addressed():
    al = _needs_evidence("p_piece_content_addressed")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    body = b"TypeError: '<' not supported"
    p1 = led.record_piece("observation", body)
    p2 = led.record_piece("observation", body)
    if p1 != p2 or p1 != hashlib.sha256(body).hexdigest():
        _record("p_piece_content_addressed", "BREAK",
                "piece ids not content-addressed")
        return
    _record("p_piece_content_addressed", "HELD",
            "piece ids are sha256(body)")


def p_score_link_referential():
    al = _needs_evidence("p_score_link_referential")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    try:
        led.record_score("00" * 32, "substring", True, "ghost observation")
    except Exception:
        # fail-closed refusal is required; now prove nothing landed
        rows = led.conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
        if rows != 0:
            _record("p_score_link_referential", "BREAK",
                    "orphan score persisted despite refusal")
            return
        _record("p_score_link_referential", "HELD",
                "score on missing observation refused, nothing persisted")
        return
    _record("p_score_link_referential", "BREAK",
            "score referencing nonexistent observation accepted")


def p_scorer_exception_fail_closed():
    al = _needs_evidence("p_scorer_exception_fail_closed")
    if al is None:
        return

    class _Boom(al.Scorer):
        scorer_id = "boom"
        def score(self, observation):
            raise RuntimeError("planted scorer failure")

    led = al.AttackLedger(_tmpdb())
    piece = led.record_piece("observation", b"anything")
    try:
        verdict, rationale = led.score_with(_Boom(), piece)
    except Exception as e:  # noqa: BLE001
        _record("p_scorer_exception_fail_closed", "BREAK",
                "scorer exception escaped: %r" % (e,))
        return
    if verdict is not False:
        _record("p_scorer_exception_fail_closed", "BREAK",
                "throwing scorer produced a claimed break")
        return
    if "scorer-error" not in rationale:
        _record("p_scorer_exception_fail_closed", "BREAK",
                "error not logged in rationale: %r" % (rationale,))
        return
    # the error verdict itself must be recorded, not silent
    rows = led.conn.execute(
        "SELECT COUNT(*) FROM scores WHERE verdict = 0").fetchone()[0]
    if rows == 0:
        _record("p_scorer_exception_fail_closed", "BREAK",
                "fail-closed verdict not recorded")
        return
    _record("p_scorer_exception_fail_closed", "HELD",
            "throwing scorer -> (False, scorer-error), recorded")


def p_chain_tamper_evident():
    al = _needs_evidence("p_chain_tamper_evident")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    piece = led.record_piece("observation", b"v1")
    led.record_score(piece, "substring", False, "clean")
    if not led.verify_chain():
        _record("p_chain_tamper_evident", "BREAK",
                "fresh chain does not verify")
        return
    # attacker rewrites a row under the hood
    led.conn.execute("UPDATE pieces SET body = ? WHERE piece_id = ?",
                     (b"v1-tampered", piece))
    led.conn.commit()
    if led.verify_chain():
        _record("p_chain_tamper_evident", "BREAK",
                "tampered ledger still verifies")
        return
    _record("p_chain_tamper_evident", "HELD",
            "chain verification detects row tampering")


def _echo_target(observation_note=b"clean"):
    def _t(attack):
        return b"echo:" + attack + b"|" + observation_note
    return _t


def p_replay_identical():
    al = _needs_evidence("p_replay_identical")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    led.register_scenario("triad-secret", {
        "seed_label": "triad-secret",
        "steps": [{"plugin": "guardrail-evidence", "strategy": "direct",
                   "payload": "password= hunter2"}],
    }, labels=["regression", "triad"])
    scorers = [al.SubstringScorer("secret-present", ["password="])]
    camp = led.run_campaign("triad-secret", _echo_target(), scorers,
                            seed_label="triad-secret")
    diffs = led.replay_campaign(camp, _echo_target(), scorers)
    if diffs:
        _record("p_replay_identical", "BREAK",
                "unchanged campaign replayed with diffs: %r" % (diffs[:2],))
        return
    _record("p_replay_identical", "HELD",
            "replay of unchanged campaign is diff-free")


def p_replay_catches_regression():
    # The planted-regression proof: a campaign where every step HELD is
    # recorded; then the target is *changed* (the regression) and replay
    # must flag exactly the drifted step.
    al = _needs_evidence("p_replay_catches_regression")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    led.register_scenario("f304-eviction-pin", {
        "seed_label": "f304-eviction-pin",
        "steps": [{"plugin": "closure-repin", "strategy": "type-confusion",
                   "payload": "mixed-now-eviction"}],
    }, labels=["regression", "f304"])
    scorers = [al.SubstringScorer("typeerror-seen", ["TypeError"])]
    camp = led.run_campaign("f304-eviction-pin", _echo_target(b"clean"),
                            scorers, seed_label="f304-eviction-pin")
    first = led.campaign_verdicts(camp)
    if any(v for _, v in first):
        _record("p_replay_catches_regression", "BREAK",
                "baseline campaign did not start all-HELD")
        return
    # plant the regression: the target now crashes on the attack
    diffs = led.replay_campaign(camp, _echo_target(b"TypeError: boom"),
                                scorers)
    drifted = [d for d in diffs if d.get("kind") == "verdict-drift"]
    if not drifted:
        _record("p_replay_catches_regression", "BREAK",
                "planted regression not caught by replay diff")
        return
    _record("p_replay_catches_regression", "HELD",
            "replay diff flagged the planted regression step")


def p_scenario_registry_labels():
    al = _needs_evidence("p_scenario_registry_labels")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    led.register_scenario("a", {"seed_label": "a", "steps": []},
                          labels=["regression"])
    led.register_scenario("b", {"seed_label": "b", "steps": []},
                          labels=["exploratory"])
    got = {s["name"] for s in led.scenarios_by_label("regression")}
    if got != {"a"}:
        _record("p_scenario_registry_labels", "BREAK",
                "label filter wrong: %r" % (got,))
        return
    if led.scenarios_by_label("no-such-label") != []:
        _record("p_scenario_registry_labels", "BREAK",
                "unknown label did not return empty")
        return
    _record("p_scenario_registry_labels", "HELD",
            "scenario registry label filtering works")


def p_converter_pipeline():
    al = _needs_evidence("p_converter_pipeline")
    if al is None:
        return
    out = al.apply_converters(b"password=", ["base64", "rot13"])
    import base64 as _b64
    import codecs as _cd
    want = _cd.encode(_b64.b64encode(b"password=").decode("ascii"), "rot_13")
    if out != want.encode("ascii"):
        _record("p_converter_pipeline", "BREAK",
                "converter stack not deterministic/composable")
        return
    folded = al.apply_converters("ｐａｓｓｗｏｒｄ".encode("utf-8"),
                                 ["unicode-fold"])
    if folded != b"password":
        _record("p_converter_pipeline", "BREAK",
                "unicode-fold did not fold fullwidth")
        return
    try:
        al.apply_converters(b"x", ["no-such-converter"])
    except Exception:
        _record("p_converter_pipeline", "HELD",
                "converters compose; unknown refused")
        return
    _record("p_converter_pipeline", "BREAK",
            "unknown converter silently accepted")


def p_bytes_payload_refused():
    # B1: bytes payloads must refuse fail-closed at register time, never
    # escape as a json TypeError.
    al = _needs_evidence("p_bytes_payload_refused")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    try:
        led.register_scenario("bytes-plan", {
            "seed_label": "bytes-plan",
            "steps": [{"plugin": "jailbreak", "strategy": "direct",
                       "payload": b"\x00\x01"}],
        }, labels=[])
    except al.ScenarioRegistrationError:
        _record("p_bytes_payload_refused", "HELD",
                "bytes payload refused fail-closed at register")
        return
    except Exception as e:  # noqa: BLE001
        _record("p_bytes_payload_refused", "BREAK",
                "wrong exception escaped: %r" % (e,))
        return
    _record("p_bytes_payload_refused", "BREAK",
            "bytes payload accepted -- json would crash at seed time")


def p_converter_run_time_fail_closed():
    # B2: a converter that refuses at RUN time (rot13 on non-ascii) must
    # not abort the campaign or escape to the caller.
    al = _needs_evidence("p_converter_run_time_fail_closed")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    led.register_scenario("rot13-nonascii", {
        "seed_label": "rot13-nonascii",
        "steps": [{"plugin": "jailbreak", "strategy": "direct",
                   "payload": "héllo", "converters": ["rot13"]}],
    }, labels=[])
    scorers = [al.SubstringScorer("x", ["zzz"])]
    try:
        camp = led.run_campaign("rot13-nonascii", _echo_target(), scorers)
    except Exception as e:  # noqa: BLE001
        _record("p_converter_run_time_fail_closed", "BREAK",
                "converter error escaped run_campaign: %r" % (e,))
        return
    rows = led.campaign_verdicts(camp)
    if len(rows) != 1:
        _record("p_converter_run_time_fail_closed", "BREAK",
                "campaign did not complete the step")
        return
    cur = led.conn.execute(
        "SELECT body FROM pieces WHERE piece_id = (SELECT piece_id FROM"
        " campaign_steps WHERE campaign_id = ?)", (camp,))
    body = bytes(cur.fetchone()[0])
    if not body.startswith(b"converter-error:"):
        _record("p_converter_run_time_fail_closed", "BREAK",
                "refusal not recorded as observation: %r" % (body[:40],))
        return
    _record("p_converter_run_time_fail_closed", "HELD",
            "run-time converter refusal recorded, campaign completed")


def p_chain_binds_kind_and_labels():
    # B3: the chain must bind pieces.kind and scenarios.labels_json --
    # de-labeling regression scenarios must break verification.
    al = _needs_evidence("p_chain_binds_kind_and_labels")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    piece = led.record_piece("observation", b"v1")
    led.register_scenario("s", {"seed_label": "s", "steps": []},
                          labels=["regression"])
    if not led.verify_chain():
        _record("p_chain_binds_kind_and_labels", "BREAK",
                "fresh chain does not verify")
        return
    led.conn.execute("UPDATE pieces SET kind = ? WHERE piece_id = ?",
                     ("spoof", piece))
    led.conn.execute("UPDATE scenarios SET labels_json = ? WHERE name = ?",
                     ('["exploratory"]', "s"))
    led.conn.commit()
    if led.verify_chain():
        _record("p_chain_binds_kind_and_labels", "BREAK",
                "kind/label tampering not detected")
        return
    _record("p_chain_binds_kind_and_labels", "HELD",
            "chain binds kind and labels_json")


def p_plugin_vocab_composition():
    al = _needs_evidence("p_plugin_vocab_composition")
    if al is None:
        return
    led = al.AttackLedger(_tmpdb())
    try:
        led.register_scenario("bad", {
            "seed_label": "bad",
            "steps": [{"plugin": "no-such-plugin", "strategy": "direct",
                       "payload": "x"}],
        }, labels=[])
    except Exception:
        _record("p_plugin_vocab_composition", "HELD",
                "unknown plugin refused at register (battery_lang vocab)")
        return
    _record("p_plugin_vocab_composition", "BREAK",
            "unknown plugin accepted -- vocab composition broken")


def p_taxonomy_pin():
    import re
    src_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")
    with open(src_path) as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(lits) != TAXONOMY_PIN:
        _record("p_taxonomy_pin", "BREAK",
                "taxonomy literals %d != pin %d" % (len(lits), TAXONOMY_PIN))
        return
    if len(set(lits)) != len(lits):
        _record("p_taxonomy_pin", "BREAK", "duplicate literals")
        return
    if lits != sorted(lits):
        _record("p_taxonomy_pin", "BREAK", "literals unsorted")
        return
    _record("p_taxonomy_pin", "HELD",
            "taxonomy %d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


# -- green checks (depth-1) ------------------------------------------------

def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIPPED", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # w280_batterylang errors on this base (stale committed manifest:
    # see F309) so the depth-1 check uses the green w280_fga battery.
    target = os.path.join(repo, "evals", "w280_fga_probes.py")
    try:
        r = subprocess.run(
            [sys.executable, target], env=env, capture_output=True,
            timeout=600, cwd=repo)
        _record("green-check", "HELD" if r.returncode == 0 else "BREAK",
                "w280_fga rc=%d" % r.returncode)
    except Exception as e:  # noqa: BLE001
        _record("green-check", "BREAK", "green check failed: %r" % (e,))


def main():
    os.makedirs(os.environ.get("TMPDIR", "/tmp"), exist_ok=True)
    for probe in (p_module_present, p_seed_determinism,
                  p_piece_content_addressed, p_score_link_referential,
                  p_scorer_exception_fail_closed, p_chain_tamper_evident,
                  p_chain_binds_kind_and_labels,
                  p_replay_identical, p_replay_catches_regression,
                  p_scenario_registry_labels, p_converter_pipeline,
                  p_converter_run_time_fail_closed,
                  p_bytes_payload_refused,
                  p_plugin_vocab_composition, p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w281_pyrit: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for r in _RESULTS:
        print("  [%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
