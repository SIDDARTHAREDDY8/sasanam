"""Break-first red-team battery for the wave-261 seams (ballot governance,
failure actions, detectors).

Wave-262 independent red-team lane. Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`), except the F236
cross-check probe which is probabilistic by nature (documented below;
kept small because the finding is already filed OPEN and owned by a
dedicated lane -- this is a hold/break cross-check only). No in-repo
git subprocesses (wave-36 supply-chain probe: fail closed).

Targets (base 8bf6c418fefb40ee1d977fbbd6b396e7b5728765, taxonomy pin
1106):
- gov/ballot_governance.py -- vote-hook sandboxing: is the read-only
  snapshot truly read-only? hook mutation via object-graph aliasing
  (the Member object is passed LIVE to vote_fn -- probed, documented
  as the trusted-hook boundary); ballot-id confusion / cross-ballot
  signature replay; quorum arithmetic edges; resolve() re-running
  vote hooks WITHOUT the vote()-time bool coercion (F237: veto
  evasion -> wrongful adoption; yes-votes dropped -> quorum never
  reached); journal-replay trust boundary (replay counts
  journal-recorded votes without re-verifying signatures -- probed as
  the deployment-owned journal-integrity boundary, NOT filed).
- gov/failure_actions.py -- filter as a laundering vector: the
  no-bypass sweep never visits dict KEYS, so the exact offending
  bytes surviving as a key are missed and filter returns "continued"
  on a tainted value (F238); substring containment probed and
  accepted as subvalue-granularity by design; custom-handler
  confusion; reask/fix action-request surfaces.
- gov/detectors.py -- predicate DSL escape (dunder paths refused);
  produced-event provenance: the per-engine secret stamp
  (_engine_stamp) is READABLE via field paths on chained detectors
  and EXFILTRATED through produces.fields.from_field into produced
  events returned to callers (F239: the documented "stripped before
  events are returned to callers" is false); forged/replayed produced
  events still cannot traverse subscription edges (structural:
  chained levels only ever see engine-produced internals); the
  cross-engine re-feed residual holds.
- F235/F236 seams: cross-checked only (filed OPEN, dedicated lanes
  own them -- do NOT re-file). Reported as BASELINE when the defect
  still reproduces.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap is a documented
residual), BREAK (genuine defect -> filed as a finding F237+),
BASELINE (filed-open finding reproduced, or accepted pre-existing
behavior verified on base -- NOT a new finding), ERROR (harness bug
-- fix the harness, never the product).
"""

import os
import sys
import tempfile
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ballot_governance as bg  # noqa: E402
from gov import ed25519  # noqa: E402
from gov import failure_actions as fa  # noqa: E402
from gov import detectors as det  # noqa: E402
from gov import policy_distribution as poldist  # noqa: E402
from gov import svid_enrollment as enr  # noqa: E402
from gov import svid_issuer as sv  # noqa: E402

# Wave-262 base pin: no taxonomy codes added or removed by this lane.
# If the count moves, the delta must be explained by a landed taxonomy
# change -- never repoint blindly (replace the VALUE only).
TAXONOMY_PIN = 1951 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w262rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


# ---------------------------------------------------------------------------
# ballot_governance helpers
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
# F237: resolve() re-runs vote hooks WITHOUT the vote()-time bool
# coercion -- non-bool truthy/falsy hook returns corrupt the tally.
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
# ballot_governance HELD / BASELINE
# ---------------------------------------------------------------------------

@probe("ballot/hook-mutating-view-refused")
def _h_ballot_view_mut():
    def evil_hook(member, decision, view):
        view["votes"]["m0"] = True  # MappingProxyType: must fail loudly
        return True

    members = _mk_members(2, first_seed=9)
    by_id = {m.member_id: m for m, _ in members}
    bt = bg.BallotType(name="t", vote_fn=evil_hook,
                       resolve_fn=lambda b, v: (bg.OPEN, ""))
    box = _mk_box(bg.Constitution(members=by_id, ballot_types={"t": bt}))
    bid = box.propose("t", {"action": "x"}, "m0")
    try:
        box.vote(bid, "m0", True,
                 _sign(box, bid, "m0", members[0][1], True))
    except bg.BallotVoteHookFailed as e:
        if e.code == "ballot-vote-hook-failed" and not box.votes(bid):
            return _held("view mutation failed loudly; vote refused, "
                         "never counted")
        return _break("hook-failed but vote state wrong: %s" % e)
    return _break("hook mutated the read-only view and the vote counted")


@probe("ballot/hook-mutating-member-object")
def _b_ballot_member_alias():
    # The vote_fn receives the LIVE Member object (not a copy): a hook
    # can reassign member.weight / member.role and it persists. This
    # is the documented trust boundary -- hooks are deployment-owned
    # constitution code ("The constitution is DATA ... not JS" refers
    # to the shape; the callables are trusted). The read-only
    # guarantee covers the view snapshot only. Verified on base:
    # accepted behavior, not a finding.
    seen = {}

    def grab_hook(member, decision, view):
        seen["weight_before"] = member.weight
        member.weight = 50
        seen["weight_after"] = member.weight
        return True

    members = _mk_members(2, first_seed=11)
    by_id = {m.member_id: m for m, _ in members}
    bt = bg.BallotType(name="t", vote_fn=grab_hook,
                       resolve_fn=lambda b, v: (bg.OPEN, ""))
    box = _mk_box(bg.Constitution(members=by_id, ballot_types={"t": bt}))
    bid = box.propose("t", {"action": "x"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    live = by_id["m0"].weight == 50
    if seen.get("weight_before") == 1 and live:
        return _baseline(
            "hooks receive the live Member object (weight 1->50 "
            "persisted): trusted-code boundary, read-only guarantee "
            "covers the view snapshot only")
    return ("ERROR", "member aliasing probe inconclusive: %s live=%s"
            % (seen, live))


@probe("ballot/cross-ballot-signature-replay-refused")
def _h_ballot_replay():
    members = _mk_members(2, first_seed=21)
    box = _mk_box(_majority_constitution(members))
    bid1 = box.propose("t", {"action": "x"}, "m0")
    bid2 = box.propose("t", {"action": "y"}, "m0")
    sig1 = _sign(box, bid1, "m0", members[0][1], True)
    box.vote(bid1, "m0", True, sig1)
    try:
        box.vote(bid2, "m0", True, sig1)  # envelope binds ballot_id
    except bg.BallotBadSignature as e:
        if e.code == "ballot-bad-signature" and not box.votes(bid2):
            return _held("cross-ballot replay refused: envelope binds "
                         "ballot_id")
        return _break("bad-signature but state wrong")
    return _break("signature replayed across ballots and counted")


@probe("ballot/double-vote-refused")
def _h_ballot_double():
    members = _mk_members(2, first_seed=31)
    box = _mk_box(_majority_constitution(members))
    bid = box.propose("t", {"action": "x"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    try:
        box.vote(bid, "m0", False,
                 _sign(box, bid, "m0", members[0][1], False))
    except bg.BallotDoubleVote as e:
        if e.code == "ballot-double-vote":
            return _held("second vote by same member refused")
        return _break("double-vote raised with wrong code")
    return _break("double vote counted")


@probe("ballot/late-vote-after-resolve-refused")
def _h_ballot_late():
    # 3-member electorate: two yes-votes adopt (2*2 > 3) while m2 has
    # not voted -- m2's vote must then refuse as late, and the outcome
    # stays sticky.
    members = _mk_members(3, first_seed=41)
    box = _mk_box(_majority_constitution(members))
    bid = box.propose("t", {"action": "x"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", members[1][1], True))
    out = box.resolve(bid)
    assert out["status"] == "adopted", out
    try:
        box.vote(bid, "m2", True,
                 _sign(box, bid, "m2", members[2][1], True))
    except bg.BallotLateVote as e:
        if e.code == "ballot-late-vote":
            sticky = box.resolve(bid)
            if sticky["status"] == "adopted":
                return _held("post-resolution vote refused as "
                             "ballot-late-vote; outcome sticky")
            return _break("late vote refused but outcome moved: %s"
                          % sticky)
        return _break("late vote raised with wrong code: %s" % e.code)
    except bg.BallotError as e:
        return _break("late vote raised unexpected code: %s" % e.code)
    return _break("vote accepted on a resolved ballot")


@probe("ballot/restart-replay-keeps-votes-and-double-vote-bar")
def _h_ballot_replay_restart():
    members = _mk_members(2, first_seed=51)
    path = os.path.join(_tmpdir(), "journal.jsonl")
    box = bg.BallotBox(_majority_constitution(members), path)
    bid = box.propose("t", {"action": "x"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    box2 = bg.BallotBox(_majority_constitution(members), path)  # restart
    votes = box2.votes(bid)
    if votes.get("m0", {}).get("decision") is not True:
        return _break("restart lost the recorded vote: %s" % votes)
    try:
        box2.vote(bid, "m0", True,
                  _sign(box2, bid, "m0", members[0][1], True))
    except bg.BallotDoubleVote:
        return _held("replay rebuilt votes; double-vote still barred "
                     "after restart")
    return _break("double vote accepted after restart")


@probe("ballot/journal-replay-trusts-records-without-resigning")
def _b_ballot_replay_trust():
    # The replay path counts journal-recorded votes WITHOUT
    # re-verifying signatures: signature verification happens only on
    # the vote() path. Anyone able to append a well-formed
    # ballot-vote-recorded record to the journal file (the chain is
    # unkeyed -- it detects corruption, not forgery) can stuff a vote
    # for a real member that resolve() will count. Journal-file
    # integrity is deployment-owned (same as the key file), so this is
    # the documented trust boundary -- verified on base, NOT filed.
    members = _mk_members(2, first_seed=61)
    path = os.path.join(_tmpdir(), "journal.jsonl")
    box = bg.BallotBox(_majority_constitution(members), path)
    bid = box.propose("t", {"action": "x"}, "m0")
    # In-process append via the public journal handle simulates a
    # journal-file writer (no signature ever created for m1).
    box.journal.append("ballot-vote-recorded", {
        "ballot_id": bid, "member_id": "m1", "decision": True,
        "effective": True, "signature_sha256": "0" * 64, "seq": 0})
    box2 = bg.BallotBox(_majority_constitution(members), path)
    votes = box2.votes(bid)
    out = box2.resolve(bid)
    if votes.get("m1", {}).get("decision") is True:
        return _baseline(
            "replay counted a journal-recorded vote for m1 with NO "
            "signature ever created (resolve=%s): signature checks "
            "live on the vote() path only; journal-file write is the "
            "deployment-owned trust boundary" % out["status"])
    return ("ERROR", "replay did not count the forged record: %s" % votes)


@probe("ballot/operator-veto-fires-on-destructive")
def _h_ballot_opveto():
    members = []
    seeds = []
    for i, role in enumerate(("member", "member", "operator")):
        seed = bytes([71 + i]) * 32
        members.append(bg.Member("m%d" % i, ed25519.publickey(seed),
                                 role=role))
        seeds.append(seed)
    con = bg.operator_weighted(members)
    box = _mk_box(con)
    bid = box.propose("destructive", {"action": "wipe"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", seeds[0], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", seeds[1], True))
    box.vote(bid, "m2", False, _sign(box, bid, "m2", seeds[2], False))
    out = box.resolve(bid)
    if out["status"] == "rejected" and out["note"] == "operator-veto":
        return _held("operator False vetoed the destructive ballot")
    return _break("operator veto did not fire: %s" % out)


@probe("ballot/exact-two-thirds-weight-adopts")
def _h_ballot_twothirds():
    members = []
    seeds = []
    for i in range(3):
        seed = bytes([81 + i]) * 32
        members.append(bg.Member("m%d" % i, ed25519.publickey(seed)))
        seeds.append(seed)
    con = bg.operator_weighted(members)
    box = _mk_box(con)
    bid = box.propose("destructive", {"action": "rotate"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", seeds[0], True))
    box.vote(bid, "m1", True, _sign(box, bid, "m1", seeds[1], True))
    out = box.resolve(bid)
    # 2/3 of weight 3: 2*3 >= 3*2 -> adopted (boundary inclusive).
    if out["status"] == "adopted" and out["note"] == "supermajority":
        return _held("exact 2/3 weight adopts (inclusive boundary)")
    return _break("2/3 boundary wrong: %s" % out)


@probe("ballot/resolve-reruns-vote-hooks")
def _h_ballot_rerun():
    calls = []

    def counting_hook(member, decision, view):
        calls.append(member.member_id)
        return bool(decision)

    members = _mk_members(2, first_seed=91)
    con = _majority_constitution(members, vote_fn=counting_hook)
    box = _mk_box(con)
    bid = box.propose("t", {"action": "x"}, "m0")
    box.vote(bid, "m0", True, _sign(box, bid, "m0", members[0][1], True))
    n_after_vote = len(calls)
    box.resolve(bid)
    n_after_resolve = len(calls)
    if n_after_vote == 1 and n_after_resolve == 2:
        return _held("CCF semantics: hook ran at vote() and re-ran at "
                     "resolve()")
    return ("ERROR", "hook call counts unexpected: vote=%d resolve=%d"
            % (n_after_vote, n_after_resolve))


# ---------------------------------------------------------------------------
# failure_actions probes
# ---------------------------------------------------------------------------

def _filter_result(field_path, value, code="pii-leak"):
    fr = fa.FailResult(code=code, action="filter", detail="d",
                       diagnostics={"field_path": field_path})
    return fa.apply_action(fr, {"value": value})


@probe("failaction/filter-redacts-named-field")
def _h_fa_basic():
    out = _filter_result("note", {"note": "SECRET", "other": 1})
    if out["disposition"] != "continued":
        return _break("filter did not continue: %s" % out)
    v = out["payload"]["value"]
    if "note" in v or v.get("other") != 1:
        return _break("redaction wrong: %s" % v)
    return _held("named field redacted from a copy; disposition "
                 "explicit")


@probe("failaction/filter-aliased-value-at-unnamed-path-refused")
def _h_fa_alias():
    shared = {"ssn": "123-45-6789"}
    try:
        _filter_result("a", {"a": shared, "b": shared})
    except fa.FailureActionError as e:
        if e.code == "pii-leak":
            return _held("aliased offending subvalue at unnamed path -> "
                         "fail closed with the FailResult's own code")
        return _break("refused with wrong code: %s" % e.code)
    return _break("filter continued despite aliased survivor")


@probe("failaction/filter-offending-bytes-as-dict-key-not-swept")
def _p_f238_keyhole():
    # Wave-263 closure: the no-bypass sweep (_iter_subvalues) now
    # visits dict keys, so the exact offending bytes surviving as a
    # key trip the sweep and the filter refuses with the FailResult's
    # own code (the same refusal idiom as the aliased-value control
    # above). Pre-fix this returned "continued" with the key bytes
    # surviving -> BREAK.
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


@probe("failaction/filter-substring-survival-accepted")
def _h_fa_substring():
    # Subvalue-granularity is the mechanism's evident scope (digest
    # equality; the "(aliasing the caller did not name)" parenthetical
    # scopes the threat to aliased copies). A superstring containing
    # the offending bytes is a DIFFERENT subvalue -- refusing on every
    # superstring would make filter unusable. Documented as accepted.
    out = _filter_result("a", {"a": "SECRET", "b": "xxSECRETxx"})
    if out["disposition"] == "continued":
        return _held("substring containment is subvalue-granularity "
                     "by design (documented scope, not aliasing)")
    return ("ERROR", "unexpected disposition: %s" % out["disposition"])


@probe("failaction/filter-missing-field-path-fails-closed")
def _h_fa_nopath():
    fr = fa.FailResult(code="x", action="filter", detail="d",
                       diagnostics={})
    try:
        fa.apply_action(fr, {"value": {"a": 1}})
    except fa.FailureActionError as e:
        if e.code == "x":
            return _held("missing field_path -> exception with own code")
        return _break("wrong code: %s" % e.code)
    return _break("filter continued without a field path")


@probe("failaction/filter-path-through-tuple-fails-closed")
def _h_fa_tuple():
    try:
        _filter_result("items[0]", {"items": ("SECRET", "b")})
    except fa.FailureActionError as e:
        if e.code == "pii-leak":
            return _held("immutable tuple path fails closed")
        return _break("wrong code: %s" % e.code)
    return _break("filter redacted through an immutable tuple")


@probe("failaction/filter-empty-container-alias-false-positive")
def _h_fa_emptyalias():
    # Conservative fail-closed direction: an empty dict offending
    # value with another empty dict elsewhere refuses (digests
    # collide). Availability nit, fail-closed -- accepted.
    try:
        _filter_result("a", {"a": {}, "b": {}})
    except fa.FailureActionError:
        return _held("empty-container digest collision fails closed "
                     "(conservative direction)")
    return ("ERROR", "expected fail-closed refusal, got continued")


@probe("failaction/filter-sweep-overflow-fails-closed")
def _h_fa_overflow():
    big = {"items": [{"k": i} for i in range(30000)]}  # >50000 subvalues
    try:
        _filter_result("items[0].k", big)
    except fa.FailureActionError as e:
        if e.code == "pii-leak":
            return _held("unverifiable redaction (>50000 subvalues) "
                         "fails closed")
        return _break("wrong code: %s" % e.code)
    return _break("filter returned continued on an unverifiable sweep")


@probe("failaction/unknown-action-reraises-own-code")
def _h_fa_unknown():
    fr = fa.FailResult(code="weird-code", action="vaporize", detail="d")
    try:
        fa.apply_action(fr, {})
    except fa.FailureActionError as e:
        if e.code == "weird-code":
            return _held("unknown action -> exception with the "
                         "FailResult's own code (never invented)")
        return _break("wrong code: %s" % e.code)
    return _break("unknown action did not raise")


@probe("failaction/custom-handler-raising-fails-closed")
def _h_fa_custom_raise():
    def bad_handler(fail_result, context):
        raise RuntimeError("boom")

    fr = fa.FailResult(code="c9", action="custom", detail="d")
    try:
        fa.apply_action(fr, {"handler": bad_handler})
    except fa.FailureActionError as e:
        if e.code == "c9":
            return _held("raising custom handler -> exception, own code")
        return _break("wrong code: %s" % e.code)
    return _break("raising custom handler did not fail closed")


@probe("failaction/custom-handler-baseexception-propagates-raw")
def _h_fa_custom_base():
    def kb_handler(fail_result, context):
        raise KeyboardInterrupt()

    fr = fa.FailResult(code="c10", action="custom", detail="d")
    try:
        fa.apply_action(fr, {"handler": kb_handler})
    except KeyboardInterrupt:
        return _held("BaseException propagates raw, never masked")
    except fa.FailureActionError:
        return _break("KeyboardInterrupt was masked as a refusal")
    return _break("no exception propagated at all")


@probe("failaction/agentic-actions-return-requests-never-autorepair")
def _h_fa_agentic():
    for action in ("reask", "fix", "fix_reask"):
        fr = fa.FailResult(code="a1", action=action, detail="need input",
                           diagnostics={"hint": "x"})
        out = fa.apply_action(fr, {"value": {"q": 1},
                                   "constraints": {"max": 2}})
        if out["disposition"] != "requested":
            return _break("%s did not return a request: %s"
                          % (action, out))
        req = out["payload"]
        if req.get("type") != "action-request" or\
                req.get("constraints", {}).get("max") != 2:
            return _break("%s request malformed: %s" % (action, req))
        if out["payload"].get("value", None) == {"q": 1}:
            pass  # request carries diagnostics, not the caller value
    return _held("reask/fix/fix_reask return caller-honored requests; "
                 "no auto-repair of caller data")


@probe("failaction/noop-refrain-dispositions-explicit")
def _h_fa_noop_refrain():
    out_n = fa.apply_action(fa.FailResult(code="n", action="noop"), {})
    out_r = fa.apply_action(fa.FailResult(code="r", action="refrain"),
                            {})
    if out_n["disposition"] == "continued" and\
            out_r["disposition"] == "refrained":
        return _held("noop->continued, refrain->refrained; caller must "
                     "interpret")
    return _break("wrong dispositions: %s %s" % (out_n, out_r))


# ---------------------------------------------------------------------------
# detectors probes
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


@probe("detectors/forged-produced-event-no-subscription-traversal")
def _h_det_forge():
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    forged = {"produced": True, "detector": "quorum-ballot-open",
              "event_name": "ballot_open",
              "fields": {"ballot_id": "x", "votes_cast": 0,
                         "quorum": 3, "elapsed_s": 9999}}
    out = eng.process(forged)
    names = [e["event_name"] for e in out]
    if "quorum_stall_detected" in names:
        return _break("forged produced event traversed a subscription "
                      "edge: %s" % names)
    return _held("forged produced event (no stamp) cannot traverse "
                 "subscription edges; got %s" % names)


@probe("detectors/dunder-paths-refused-at-registration")
def _h_det_dunder():
    bad_paths = ["__class__", "a.__dict__", "a__b"]
    for path in bad_paths:
        d = {
            "name": "dunder-probe", "version": "1.0.0",
            "description": "x", "event_selector": {"type": "t"},
            "predicates": [{"field": path, "op": "exists"}],
            "produces": {"event_name": "e",
                         "event_schema_version": "1.0.0",
                         "fields": {}},
            "subscribes": [],
        }
        eng = det.DetectorEngine()
        try:
            eng.register(d)
        except det.DetectorRegistrationError as e:
            if e.code != "detector-unknown-predicate":
                return _break("wrong code for %r: %s" % (path, e.code))
            continue
        return _break("dunder path registered: %r" % path)
    # from_field dunder too
    d = {
        "name": "dunder-probe2", "version": "1.0.0",
        "description": "x", "event_selector": {"type": "t"},
        "predicates": [{"field": "a", "op": "exists"}],
        "produces": {"event_name": "e",
                     "event_schema_version": "1.0.0",
                     "fields": {"z": {"from_field": "__proto__"}}},
        "subscribes": [],
    }
    eng = det.DetectorEngine()
    try:
        eng.register(d)
    except det.DetectorRegistrationError as e:
        if e.code == "detector-unknown-predicate":
            return _held("dunder/proto traversal refused at "
                         "registration (predicate + from_field)")
        return _break("wrong code: %s" % e.code)
    return _break("dunder from_field registered")


@probe("detectors/subscription-cycles-refused")
def _h_det_cycle():
    def mk(name, subs):
        return {
            "name": name, "version": "1.0.0", "description": "x",
            "event_selector": {"produced_by": subs[0]} if subs
            else {"type": "t"},
            "predicates": [{"field": "a", "op": "exists"}],
            "produces": {"event_name": "e_" + name.replace("-", "_"),
                         "event_schema_version": "1.0.0",
                         "fields": {}},
            "subscribes": subs,
        }

    eng = det.DetectorEngine()
    try:
        eng.register(mk("self-loop", ["self-loop"]))
    except det.DetectorRegistrationError as e:
        if e.code != "detector-cycle":
            return _break("self-loop wrong code: %s" % e.code)
    else:
        return _break("self-subscription registered")
    eng2 = det.DetectorEngine()
    try:
        eng2.register_all([mk("cyc-a", ["cyc-b"]),
                           mk("cyc-b", ["cyc-a"])])
    except det.DetectorRegistrationError as e:
        if e.code != "detector-cycle":
            return _break("2-cycle wrong code: %s" % e.code)
    else:
        return _break("2-node subscription cycle registered")
    if "self-loop" in eng.detectors or eng2.detectors:
        return _break("refused batch left registered state behind")
    return _held("self-loops and 2-cycles refused; nothing registered")


@probe("detectors/cross-engine-replay-no-chain-traversal")
def _h_det_xengine():
    # Documented v1 residual: persisted produced events re-fed into a
    # NEW engine must not traverse subscription edges (no
    # digest-anchored provenance yet). They may match raw selectors;
    # the chain must not fire.
    eng_a = det.DetectorEngine()
    eng_a.register_all(det.SAMPLE_DETECTORS)
    produced_a = eng_a.process({"type": "ballot", "state": "open",
                                "ballot_id": "b1", "votes_cast": 1,
                                "quorum": 3, "elapsed_s": 999})
    assert any(e["event_name"] == "quorum_stall_detected"
               for e in produced_a), produced_a
    eng_b = det.DetectorEngine()
    eng_b.register_all(det.SAMPLE_DETECTORS)
    names = []
    for ev in produced_a:
        names.extend(e["event_name"]
                     for e in eng_b.process(dict(ev)))
    if "quorum_stall_detected" in names:
        return _break("cross-engine replay traversed the chain: %s"
                      % names)
    return _held("engine-B chain did not fire on engine-A produced "
                 "events (got %s)" % names)


@probe("detectors/produced-by-without-subscribes-refused")
def _h_det_prodby():
    d = {
        "name": "prodby-lonely", "version": "1.0.0",
        "description": "x",
        "event_selector": {"produced_by": "quorum-ballot-open"},
        "predicates": [{"field": "a", "op": "exists"}],
        "produces": {"event_name": "e",
                     "event_schema_version": "1.0.0", "fields": {}},
        "subscribes": [],
    }
    eng = det.DetectorEngine()
    try:
        eng.register(d)
    except det.DetectorRegistrationError as e:
        if e.code == "detector-malformed":
            return _held("produced_by without subscribes refused")
        return _break("wrong code: %s" % e.code)
    return _break("produced_by selector registered with no subscribes")


@probe("detectors/register-all-atomic-on-bad-batch")
def _h_det_atomic():
    good = {
        "name": "atomic-good", "version": "1.0.0",
        "description": "x", "event_selector": {"type": "t"},
        "predicates": [{"field": "a", "op": "exists"}],
        "produces": {"event_name": "e",
                     "event_schema_version": "1.0.0", "fields": {}},
        "subscribes": [],
    }
    bad = dict(good, name="atomic-bad",
               predicates=[{"field": "a", "op": "rm -rf"}])
    eng = det.DetectorEngine()
    try:
        eng.register_all([good, bad])
    except det.DetectorRegistrationError:
        pass
    else:
        return _break("bad batch registered without refusal")
    if eng.detectors:
        return _break("bad batch left partial state: %s"
                      % sorted(eng.detectors))
    return _held("register_all atomic: bad batch registered nothing")


@probe("detectors/sample-chain-fires-end-to-end")
def _h_det_chain():
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    out = eng.process({"type": "ballot", "state": "open",
                       "ballot_id": "b9", "votes_cast": 1,
                       "quorum": 3, "elapsed_s": 600})
    names = [e["event_name"] for e in out]
    if names == ["ballot_open", "quorum_stall_detected"]:
        f = [e for e in out
             if e["event_name"] == "quorum_stall_detected"][0]["fields"]
        if f.get("ballot_id") == "b9" and\
                "_engine_stamp" not in str(out):
            return _held("sample chain fires in topo order; stamp "
                         "absent from returned events")
        return _break("chain output wrong: %s" % out)
    return _break("sample chain did not fire: %s" % names)


# ---------------------------------------------------------------------------
# F235 / F236 cross-checks (filed OPEN; dedicated lanes own them --
# report hold/break only, never re-file)
# ---------------------------------------------------------------------------

@probe("xcheck/f235-recursion-error-still-escapes-apply")
def _x_f235():
    seed = bytes.fromhex("ab" * 32)
    pub = poldist.Publisher(seed)
    sub = poldist.Subscriber("policies", pub.pubkey)
    depth = 30000
    raw = ('{"v":1,"topic":"policies","version":1,"payload":{"nest":'
           + "[" * depth + '"x"' + "]" * depth
           + '},"sig":"' + "0" * 128 + '"}').encode("utf-8")
    try:
        out = sub.apply(raw)
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _baseline(
            "F235 still OPEN: unsigned hostile input raised %s out of "
            "Subscriber.apply() (contract: never raises)"
            % type(e).__name__)
    code = out.get("code")
    c = code["code"] if isinstance(code, dict) else code
    return _held("F235 appears fixed: deeply-nested input refused as %s"
                 % c)


def _enr_pair():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    return enr.EnrollmentAuthority(issuer)


@probe("xcheck/f236-concurrent-redeem-double-issue")
def _x_f236a():
    # Probabilistic; lighter than the w261 pin (32 threads x 60
    # trials) -- a single double-issuance confirms the finding is
    # still open. No hit is weak evidence either way (documented).
    auth = _enr_pair()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)  # harness-side scheduling pressure only
    try:
        double = 0
        trials, nthreads = 60, 32
        for _ in range(trials):
            key = auth.issue_key(spiffe_id="spiffe://example.org/w/r")
            barrier = threading.Barrier(nthreads)
            results = []
            rlock = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    auth.redeem(key, "spiffe://example.org/w/r",
                                "bb" * 32, 5)
                    r = "svid"
                except sv.SvidError as e:
                    r = e.code
                with rlock:
                    results.append(r)

            ths = [threading.Thread(target=worker)
                   for _ in range(nthreads)]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            if results.count("svid") > 1:
                double += 1
    finally:
        sys.setswitchinterval(old_interval)
    if double:
        return _baseline(
            "F236 still OPEN: %d/%d trials double-issued SVIDs from "
            "one key" % (double, trials))
    return _held("F236 cross-check: no double-issuance observed over "
                 "%d trials (weak evidence; race is probabilistic)" %
                 trials)


@probe("xcheck/f236-live-keys-raises-under-concurrent-issue")
def _x_f236b():
    auth = _enr_pair()
    for _ in range(50):
        auth.issue_key()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)
    stop = threading.Event()
    crashed = []
    try:
        def reader():
            while not stop.is_set():
                try:
                    auth.live_keys()
                except Exception as e:  # noqa: BLE001 -- defect shape
                    crashed.append(type(e).__name__)
                    return

        def writer():
            while not stop.is_set():
                auth.issue_key()

        ths = ([threading.Thread(target=reader) for _ in range(8)]
               + [threading.Thread(target=writer) for _ in range(4)])
        for th in ths:
            th.start()
        time.sleep(2)
        stop.set()
        for th in ths:
            th.join()
    finally:
        sys.setswitchinterval(old_interval)
    if crashed:
        return _baseline(
            "F236 still OPEN: live_keys() raised %s under concurrent "
            "issue_key" % crashed[0])
    return _held("F236 cross-check: live_keys() survived 2s of "
                 "concurrent mutation")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent wave-261 lane batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w261_ballot_probes.py",
                    "evals/w261_detector_probes.py",
                    "evals/w261_failaction_probes.py"):
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
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
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
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
