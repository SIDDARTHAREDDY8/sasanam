"""Break-first closure battery for wave-263 (F237/F238/F239).

Wave-263 closure lane. Stdlib only. Deterministic across runs (staging
+ `env -u GOV_DEPLOYMENT_MODE`). No in-repo git subprocesses (wave-36
supply-chain probe: fail closed).

Targets (base 82c84934027be71083d260520c3b7fb3eab89ffa, taxonomy pin
1129):
- gov/ballot_governance.py (F237): resolve() re-ran vote hooks WITHOUT
  the vote()-time bool coercion while the shipped resolvers use
  `is True` / `is False`. Fix: coerce in _effective_votes() so resolve
  sees exactly what vote() journaled.
- gov/failure_actions.py (F238): the filter no-bypass sweep
  (_iter_subvalues) never visited dict KEYS. Fix: the sweep visits
  keys too.
- gov/detectors.py (F239): the per-engine provenance stamp
  (_engine_stamp) was exfiltratable through data-defined detector
  field paths. Fix: data-defined paths (predicates, exceptions,
  from_field) evaluate against the stamp-stripped event; the
  structural provenance check in process() stays on the internal
  event.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / defect fixed), BREAK
(defect reproduces -> finding stays open), ERROR (harness bug --
fix the harness, never the product).

The three red-team pin probes are incorporated VERBATIM from
evals/w262_redteam_probes.py (same names, same bodies); the extra
probes pin the fix direction and guard legitimate behavior.
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ballot_governance as bg  # noqa: E402
from gov import ed25519  # noqa: E402
from gov import failure_actions as fa  # noqa: E402
from gov import detectors as det  # noqa: E402

# Wave-263 pin: no taxonomy codes added or removed by this lane.
# If the count moves, the delta must be explained by a landed taxonomy
# change -- never repoint blindly (replace the VALUE only).
TAXONOMY_PIN = 2124 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w263-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ---------------------------------------------------------------------------
# ballot_governance helpers (same as the wave-262 red-team battery)
# ---------------------------------------------------------------------------

def _mk_members(n, first_seed=1):
    out = []
    for i in range(n):
        seed = bytes([first_seed + i]) * 32
        out.append((bg.Member("m%d" % i, ed25519.publickey(seed)), seed))
    return out


def _mk_box(constitution):
    return bg.BallotBox(constitution,
                        os.path.join(_tmpdir(), "journal.jsonl"))


def _sign(box, ballot_id, member_id, seed, decision):
    env = bg.vote_envelope(ballot_id, member_id, decision,
                           box.payload_digest(ballot_id))
    return ed25519.sign(seed, env)


def _majority_constitution(members, vote_fn=None):
    by_id = {m.member_id: m for m, _ in members}
    bt = bg.BallotType(
        name="t",
        vote_fn=vote_fn or (lambda member, decision, view: bool(decision)),
        resolve_fn=bg._majority_veto_resolve)
    return bg.Constitution(members=by_id, ballot_types={"t": bt})


# ---------------------------------------------------------------------------
# F237 pin probes -- VERBATIM from evals/w262_redteam_probes.py
# (resolve() re-runs vote hooks WITHOUT the vote()-time bool coercion)
# ---------------------------------------------------------------------------

@probe("ballot/resolve-drops-nonbool-hook-returns-veto-evaded")
def _p_f237_veto():
    # vote_fn returns literal True for yes, 0 for no -- an idiomatic
    # Python truthy/falsy style. vote() bool-coerces (journaled
    # effective=False for the no-vote), but resolve()'s
    # _effective_votes() does NOT coerce, and the sample resolvers use
    # `is True` / `is False` identity checks: the veto (0 is not
    # False) is missed and the ballot ADOPTS despite a veto vote.
    members = _mk_members(3)
    con = _majority_constitution(
        members,
        vote_fn=lambda member, decision, view: True if decision else 0)
    box = _mk_box(con)
    bid = box.propose("t", {"action": "spend"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", members[1][1], True))
    box.vote(bid, "m2", False, _sign(box, bid, "m2", members[2][1], False))
    journaled = {k: v["effective"] for k, v in box.votes(bid).items()}
    out = box.resolve(bid)
    if out["status"] == "adopted":
        return _break(
            "veto evaded -> WRONGLY ADOPTED: journaled effective=%s but "
            "resolve() saw raw hook returns (0 is not False) and missed "
            "the veto (note=%r)" % (journaled, out["note"]))
    return _held("veto honored on non-bool hook returns: %s" % out)


@probe("ballot/resolve-drops-nonbool-hook-returns-yes-lost")
def _p_f237_yes():
    # Same defect, availability direction: hook returns int 1 for yes.
    # vote() journals effective=True, but resolve() counts
    # `v is True` -> 0 yes -> a unanimous ballot can never adopt and
    # dies as ballot-quorum-not-reached.
    members = _mk_members(3)
    con = _majority_constitution(
        members,
        vote_fn=lambda member, decision, view: 1 if decision else 0)
    box = _mk_box(con)
    bid = box.propose("t", {"action": "spend"}, "m0")
    for m, seed in members:
        box.vote(bid, m.member_id, True,
                 _sign(box, bid, m.member_id, seed, True))
    journaled = {k: v["effective"] for k, v in box.votes(bid).items()}
    out = box.resolve(bid)
    if out["status"] != "adopted":
        return _break(
            "unanimous yes-votes LOST at resolve: journaled "
            "effective=%s but resolve() counted 0 yes (1 is not True) "
            "-> %s/%s" % (journaled, out["status"], out["note"]))
    return _held("unanimous int-1 yes-votes adopted: %s" % out)


@probe("ballot/bool-hook-control-adopts-and-vetoes")
def _h_ballot_bool_control():
    # Control: with bool-returning hooks (the documented contract),
    # adoption and veto both work.
    members = _mk_members(3)
    box = _mk_box(_majority_constitution(members))
    bid = box.propose("t", {"action": "spend"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", members[1][1], True))
    out = box.resolve(bid)
    if out["status"] != "adopted":
        return _break("bool-hook majority did not adopt: %s" % out)
    bid2 = box.propose("t", {"action": "spend"}, "m0")
    box.vote(bid2, "m0", False,
             _sign(box, bid2, "m0", members[0][1], False))
    out2 = box.resolve(bid2)
    if out2["status"] != "rejected" or out2["note"] != "vetoed":
        return _break("bool-hook veto did not fire: %s" % out2)
    return _held("bool hooks: majority adopts, single False vetoes")


# ---------------------------------------------------------------------------
# failure_actions helpers + F238 pin probe -- VERBATIM from
# evals/w262_redteam_probes.py
# ---------------------------------------------------------------------------

def _filter_result(field_path, value, code="pii-leak"):
    fr = fa.FailResult(code=code, action="filter", detail="d",
                       diagnostics={"field_path": field_path})
    return fa.apply_action(fr, {"value": value})


@probe("failaction/filter-offending-bytes-as-dict-key-not-swept")
def _p_f238_keyhole():
    # Wave-263 note: the red-team's break-first body is adapted to the
    # refusal idiom (same attack, same input). The F238 close-when
    # mandates refusal with the FailResult's own code, which RAISES
    # FailureActionError -- the break-first fall-through (`out` only
    # exists on "continued") is unreachable post-fix. The assertion
    # mirrors the red-team's own aliased-value control idiom.
    try:
        out = _filter_result("note", {"note": "SECRET",
                                      "SECRET": "innocent", "other": 1})
    except fa.FailureActionError as e:
        if e.code == "pii-leak":
            return _held("key-resident offending bytes refused with "
                         "the FailResult's own code")
        return _break("refused with wrong code: %s" % e.code)
    v = out["payload"]["value"]
    if out["disposition"] == "continued" and "SECRET" in v:
        return _break(
            "filter returned 'continued' with the exact offending "
            "bytes surviving as a dict key: %s (sweep never visits "
            "keys)" % v)
    return _break("filter continued without refusing key-resident "
                  "offending bytes: %s" % out)


# ---------------------------------------------------------------------------
# detectors helpers + F239 pin probe -- VERBATIM from
# evals/w262_redteam_probes.py
# ---------------------------------------------------------------------------

def _thief_chain():
    """A chained detector whose definition reads the engine's internal
    stamp key via field paths (single underscores pass _check_path;
    the dunder guard does not cover it)."""
    eng = det.DetectorEngine()
    producer = {
        "name": "base-producer", "version": "1.0.0",
        "description": "base", "event_selector": {"type": "raw"},
        "predicates": [{"field": "x", "op": "exists"}],
        "produces": {"event_name": "base_fired",
                     "event_schema_version": "1.0.0",
                     "fields": {"x": {"from_field": "x"}}},
        "subscribes": [],
    }
    thief = {
        "name": "stamp-thief", "version": "1.0.0",
        "description": "reads _engine_stamp from the internal event",
        "event_selector": {"produced_by": "base-producer"},
        "predicates": [{"field": "_engine_stamp", "op": "exists"}],
        "produces": {"event_name": "stamp_leaked",
                     "event_schema_version": "1.0.0",
                     "fields": {"leaked_stamp":
                                {"from_field": "_engine_stamp"}}},
        "subscribes": ["base-producer"],
    }
    eng.register_all([producer, thief])
    return eng


@probe("detectors/stamp-exfiltrated-via-from-field")
def _p_f239_stamp():
    # The per-engine secret stamp is the documented provenance
    # mechanism ("recognized by a per-engine secret stamp that is
    # stripped before events are returned to callers"). But chained
    # detectors evaluate predicates and extract produced fields from
    # the INTERNAL event WITH the stamp present, and _check_path
    # allows the single-underscore key -- so a data-defined detector
    # emits the secret into a produced event returned to the caller.
    eng = _thief_chain()
    out = eng.process({"type": "raw", "x": 1})
    leaked = [e for e in out if e["event_name"] == "stamp_leaked"]
    if leaked and leaked[0]["fields"].get("leaked_stamp") == eng._stamp:
        return _break(
            "engine provenance secret exfiltrated to the caller via "
            "from_field='_engine_stamp' on a chained detector "
            "(the 'stripped before events are returned' claim is "
            "false for data-defined field paths)")
    return _held("stamp not reachable from detector field paths")


# ---------------------------------------------------------------------------
# Fix-direction probes (wave-263): pin the repair and guard legitimate
# behavior at the same public seams.
# ---------------------------------------------------------------------------

@probe("ballot/resolve-coercion-matches-journaled")
def _p_f237_coercion_match():
    # The repair contract: resolve() must see EXACTLY what vote()
    # journaled. A hook returning varied truthy/falsy values
    # ([1]/[] for m0/m1, "YES"/"" for m2) must behave identically to
    # the bool contract -- a False decision still vetoes, unanimous
    # True still adopts.
    members = _mk_members(3)
    styles = {0: (lambda d: [1] if d else []),
              1: (lambda d: "YES" if d else ""),
              2: (lambda d: 1 if d else 0)}
    seen = {}

    def hook(member, decision, view):
        seen[member.member_id] = decision
        return styles[int(member.member_id[1:])](decision)

    box = _mk_box(_majority_constitution(members, vote_fn=hook))
    bid = box.propose("t", {"action": "spend"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", members[1][1], True))
    box.vote(bid, "m2", False, _sign(box, bid, "m2", members[2][1], False))
    journaled = {k: v["effective"] for k, v in box.votes(bid).items()}
    if journaled != {"m0": True, "m1": True, "m2": False}:
        return ("ERROR", "journaled effective wrong: %s" % journaled)
    out = box.resolve(bid)
    if out["status"] != "rejected" or out["note"] != "vetoed":
        return _break(
            "mixed truthy/falsy hook: resolve disagrees with journal "
            "(journaled=%s -> %s/%s)" % (journaled, out["status"],
                                         out["note"]))
    # Yes direction: unanimous True with non-bool truthy returns adopts.
    bid2 = box.propose("t", {"action": "spend"}, "m0")
    for m, seed in members:
        box.vote(bid2, m.member_id, True,
                 _sign(box, bid2, m.member_id, seed, True))
    out2 = box.resolve(bid2)
    if out2["status"] != "adopted":
        return _break("unanimous truthy yes-votes did not adopt: %s"
                      % out2)
    return _held("resolve tally == journaled coercion, both directions")


@probe("failaction/filter-nested-key-swept")
def _p_f238_nested_key():
    # Offending bytes as a key nested inside lists/dicts must also trip
    # the sweep (keys are byte-carrying positions at any depth).
    try:
        _filter_result("note", {"note": "SECRET",
                                "deep": {"inner": [{"SECRET": 1}]}})
    except fa.FailureActionError as e:
        if e.code == "pii-leak":
            return _held("nested key-resident offending bytes refused "
                         "with the FailResult's own code")
        return _break("refused with wrong code: %s" % e.code)
    return _break("filter continued with offending bytes nested as a "
                  "key")


@probe("failaction/filter-clean-value-still-continues")
def _h_f238_clean_control():
    # The key-sweep repair must not over-refuse: a value whose
    # offending bytes are fully redacted still continues.
    out = _filter_result("note", {"note": "SECRET", "other": "innocent"})
    if out["disposition"] != "continued":
        return _break("clean filter refused: %s" % out)
    v = out["payload"]["value"]
    if "note" in v or v.get("other") != "innocent":
        return _break("redaction wrong: %s" % v)
    return _held("fully-redacted value still continues")


def _legit_chain():
    """Producer -> consumer chain using only legitimate field paths."""
    eng = det.DetectorEngine()
    producer = {
        "name": "legit-producer", "version": "1.0.0",
        "description": "legit base", "event_selector": {"type": "raw"},
        "predicates": [{"field": "x", "op": "exists"}],
        "produces": {"event_name": "legit_fired",
                     "event_schema_version": "1.0.0",
                     "fields": {"x": {"from_field": "x"}}},
        "subscribes": [],
    }
    consumer = {
        "name": "legit-consumer", "version": "1.0.0",
        "description": "reads the producer's fields, not engine keys",
        "event_selector": {"produced_by": "legit-producer"},
        "predicates": [{"field": "fields.x", "op": "eq", "value": 42}],
        "produces": {"event_name": "chained_ok",
                     "event_schema_version": "1.0.0",
                     "fields": {"doubled": {"from_field": "fields.x"}}},
        "subscribes": ["legit-producer"],
    }
    eng.register_all([producer, consumer])
    return eng


@probe("detectors/chained-detection-still-works")
def _p_f239_legit_chain():
    # The repair must not break legitimate chained detection: the
    # consumer reads the producer's fields from the internal event.
    eng = _legit_chain()
    out = eng.process({"type": "raw", "x": 42})
    ok = [e for e in out if e["event_name"] == "chained_ok"]
    if not ok or ok[0]["fields"].get("doubled") != 42:
        return _break("legitimate chained detection broke: %s" % out)
    names = [e["event_name"] for e in out]
    if "legit_fired" not in names:
        return _break("producer level stopped firing: %s" % names)
    return _held("producer -> consumer chain fires end-to-end")


@probe("detectors/stamp-from-field-yields-none")
def _p_f239_from_field_channel():
    # Isolate the from_field channel from the predicate channel: the
    # thief's predicate matches legitimately (fields.x exists), but
    # from_field='_engine_stamp' must resolve to None -- never the
    # live secret.
    eng = det.DetectorEngine()
    producer = {
        "name": "ff-producer", "version": "1.0.0",
        "description": "base", "event_selector": {"type": "raw"},
        "predicates": [{"field": "x", "op": "exists"}],
        "produces": {"event_name": "ff_fired",
                     "event_schema_version": "1.0.0",
                     "fields": {"x": {"from_field": "x"}}},
        "subscribes": [],
    }
    thief = {
        "name": "ff-thief", "version": "1.0.0",
        "description": "from_field on the stamp with a legit predicate",
        "event_selector": {"produced_by": "ff-producer"},
        "predicates": [{"field": "fields.x", "op": "exists"}],
        "produces": {"event_name": "ff_leaked",
                     "event_schema_version": "1.0.0",
                     "fields": {"leaked_stamp":
                                {"from_field": "_engine_stamp"}}},
        "subscribes": ["ff-producer"],
    }
    eng.register_all([producer, thief])
    out = eng.process({"type": "raw", "x": 1})
    leaked = [e for e in out if e["event_name"] == "ff_leaked"]
    if not leaked:
        return ("ERROR", "thief with legitimate predicate did not fire")
    got = leaked[0]["fields"].get("leaked_stamp")
    if got == eng._stamp:
        return _break("from_field='_engine_stamp' emitted the live "
                      "secret")
    if got is not None:
        return _break("from_field='_engine_stamp' resolved to %r "
                      "(expected None)" % (got,))
    return _held("from_field='_engine_stamp' resolves to None; no "
                 "secret bytes")


@probe("detectors/stamp-predicate-never-matches")
def _p_f239_stamp_predicate():
    # A predicate on the reserved engine key must never observe it --
    # and registration must still SUCCEED (the repair is evaluation
    # against the stripped event, not a registration refusal, so the
    # w262 pin probe's register_all stays valid).
    eng = det.DetectorEngine()
    d = {
        "name": "stamp-watcher", "version": "1.0.0",
        "description": "predicate on the reserved key",
        "event_selector": {"type": "raw"},
        "predicates": [{"field": "_engine_stamp", "op": "exists"}],
        "produces": {"event_name": "watcher_fired",
                     "event_schema_version": "1.0.0",
                     "fields": {}},
        "subscribes": [],
    }
    try:
        eng.register(d)
    except det.DetectorRegistrationError as e:
        return ("ERROR", "registration refused (repair must be at "
                "evaluation, not registration): %s" % e)
    out = eng.process({"type": "raw", "x": 1})
    if [e for e in out if e["event_name"] == "watcher_fired"]:
        return _break("predicate on _engine_stamp matched")
    return _held("reserved key invisible to predicates; registration "
                 "accepted")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent batteries + decision-code unit tests still
    green. Honors GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets = [
        ["evals/w262_redteam_probes.py"],
        ["evals/w261_ballot_probes.py"],
        ["evals/w261_failaction_probes.py"],
        ["evals/w261_detector_probes.py"],
        ["evals/w262_alert_probes.py"],
        ["-m", "unittest", "tests.test_decision_codes"],
    ]
    for argv in targets:
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable] + [a if a.startswith("-") or a == "-m"
                                    else os.path.join(repo, a)
                                    for a in argv],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((" ".join(argv),
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((" ".join(argv), "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
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
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes" %
          (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
