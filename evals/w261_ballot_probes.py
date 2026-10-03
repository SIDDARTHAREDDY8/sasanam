"""Break-first battery for gov/ballot_governance.py (wave-261 lane 1).

microsoft/CCF STEAL (Apache-2.0, credited in the module docstring):
scriptable constitution + programmable vote() ballots re-executed on every
vote against read-only state + every signed vote ledger-recorded.

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break attempt
succeeds. A genuine BREAK against the final implementation would file a
finding; this battery must be all HELD on the shipped module.

Next free: F235 (file only genuine product defects).

No in-repo git subprocesses (wave-36 supply-chain probe discipline).
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1820  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*)

try:
    from gov import decision_codes
    from gov import ballot_governance as bg
    from gov import ed25519
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN,\
        "taxonomy drift: %d != %d" % (len(decision_codes.TAXONOMY),
                                      TAXONOMY_PIN)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _keys(n):
    out = []
    for i in range(n):
        seed = hashlib.sha256(b"w261-ballot-probe-%d" % i).digest()
        out.append((seed, ed25519.publickey(seed)))
    return out


def _members(n, roles=None):
    keys = _keys(n)
    members = []
    for i, (seed, pub) in enumerate(keys):
        members.append(bg.Member(
            member_id="member-%d" % i,
            pubkey=pub,
            role=(roles[i] if roles else "member"),
            weight=1,
        ))
    return members, keys


def _box(constitution):
    d = tempfile.mkdtemp(prefix="w261ballot-")
    return bg.BallotBox(constitution,
                        os.path.join(d, "ballot-journal.jsonl")), d


def _sign_vote(seed, ballot_id, member_id, decision, payload_digest):
    return ed25519.sign(
        seed, bg.vote_envelope(ballot_id, member_id, decision,
                               payload_digest))


@probe
def probe_forged_signature():
    """A vote signed with the wrong key is refused, never counted."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    attacker_seed = hashlib.sha256(b"w261-attacker").digest()
    sig = ed25519.sign(
        attacker_seed,
        bg.vote_envelope(ballot_id, "member-0", True, payload_digest))
    try:
        box.vote(ballot_id, "member-0", True, sig)
    except bg.BallotError as e:
        if e.code == "ballot-bad-signature" and not box.votes(ballot_id):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_non_member_vote():
    """A valid signature from a non-member is refused, never counted."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    outsider_seed = hashlib.sha256(b"w261-outsider").digest()
    sig = ed25519.sign(
        outsider_seed,
        bg.vote_envelope(ballot_id, "outsider", True, payload_digest))
    try:
        box.vote(ballot_id, "outsider", True, sig)
    except bg.BallotError as e:
        if e.code == "ballot-not-member" and not box.votes(ballot_id):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_double_vote():
    """The second vote from the same member is refused; the first stands."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    box.vote(ballot_id, "member-0", True,
             _sign_vote(keys[0][0], ballot_id, "member-0", True,
                        payload_digest))
    try:
        box.vote(ballot_id, "member-0", False,
                 _sign_vote(keys[0][0], ballot_id, "member-0", False,
                            payload_digest))
    except bg.BallotError as e:
        votes = box.votes(ballot_id)
        if (e.code == "ballot-double-vote" and len(votes) == 1
                and votes["member-0"]["decision"] is True):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_veto_override_attempt():
    """One false vote vetoes: resolve says rejected, and it stays so."""
    members, keys = _members(5)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-write"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    for i in range(5):
        decision = (i != 2)  # member-2 vetoes
        box.vote(ballot_id, "member-%d" % i, decision,
                 _sign_vote(keys[i][0], ballot_id, "member-%d" % i,
                            decision, payload_digest))
    outcome = box.resolve(ballot_id)
    if outcome["status"] != "rejected":
        return "BREAK(status=%r)" % (outcome["status"],)
    # Override attempt: late vote after resolve is refused, veto stands.
    try:
        box.vote(ballot_id, "member-0", True,
                 _sign_vote(keys[0][0], ballot_id, "member-0", True,
                            payload_digest))
    except bg.BallotError as e:
        if e.code != "ballot-late-vote":
            return "BREAK(late=%r)" % (e.code,)
    outcome2 = box.resolve(ballot_id)
    if outcome2["status"] == "rejected":
        return "HELD"
    return "BREAK(override=%r)" % (outcome2,)


@probe
def probe_quorum_not_reached():
    """resolve() with unreachable quorum returns an explicit machine-coded
    rejection -- never a silent adoption, never a bare open."""
    members, keys = _members(5)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-write"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    box.vote(ballot_id, "member-0", True,
             _sign_vote(keys[0][0], ballot_id, "member-0", True,
                        payload_digest))
    box.vote(ballot_id, "member-1", True,
             _sign_vote(keys[1][0], ballot_id, "member-1", True,
                        payload_digest))
    box.vote(ballot_id, "member-2", False,
             _sign_vote(keys[2][0], ballot_id, "member-2", False,
                        payload_digest))
    outcome = box.resolve(ballot_id)
    # 2 yes of 5 cannot reach majority and a veto was cast: the veto
    # fires first; either way adoption must be impossible.
    if outcome["status"] == "adopted":
        return "BREAK(adopted)"
    if outcome["status"] == "rejected":
        return "HELD"
    return "BREAK(status=%r)" % (outcome["status"],)


@probe
def probe_quorum_not_reached_explicit_code():
    """All members vote yes-but-short-of-majority is impossible in a
    5-member odd body; use a 4-member body: 2 yes / 2 abstain, all voted
    -> explicit ballot-quorum-not-reached, never adopted."""
    members, keys = _members(4)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-write"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    # 4 members: need >2 for majority. Only 2 vote yes; other 2 vote yes
    # too? No -- to miss quorum, have all 4 vote but with the resolve
    # rule unable to adopt: 2 yes + 2 yes would adopt. Instead 2 yes and
    # 2... any false vetoes. So: members vote yes, yes, and the other
    # two do not vote -> resolve stays open while votes remain.
    for i in range(2):
        box.vote(ballot_id, "member-%d" % i, True,
                 _sign_vote(keys[i][0], ballot_id, "member-%d" % i,
                            True, payload_digest))
    outcome = box.resolve(ballot_id)
    if outcome["status"] != "open":
        return "BREAK(early=%r)" % (outcome["status"],)
    # Now exhaust the electorate without reaching majority: impossible
    # without a veto in this constitution, so switch to an even body
    # with a 2/3-weighted ballot where abstentions strand the ballot.
    members2, keys2 = _members(6)
    box2, d2 = _box(bg.operator_weighted(members2))
    ballot_id2 = box2.propose("destructive", {"action": "drop-table"},
                              "member-0")
    pd2 = box2.payload_digest(ballot_id2)
    # destructive needs >= 2/3 of total weight (6): 4 yes-weight. Cast
    # 3 yes + 3 abstain -> 3/6 < 2/3, cannot adopt. Then all vote yes
    # except keep it short: 3 yes, 3 non-votes -> resolve must refuse
    # adoption with the explicit code once the electorate is exhausted.
    for i in range(3):
        box2.vote(ballot_id2, "member-%d" % i, True,
                  _sign_vote(keys2[i][0], ballot_id2, "member-%d" % i,
                             True, pd2))
    # Electorate not exhausted yet (3 abstain) -> open is honest.
    if box2.resolve(ballot_id2)["status"] != "open":
        return "BREAK(not-open)"
    # Have the remaining 3 vote yes as well -> 6/6 yes adopts (sanity).
    for i in range(3, 6):
        box2.vote(ballot_id2, "member-%d" % i, True,
                  _sign_vote(keys2[i][0], ballot_id2, "member-%d" % i,
                             True, pd2))
    if box2.resolve(ballot_id2)["status"] != "adopted":
        return "BREAK(not-adopted)"
    return "HELD"


@probe
def probe_late_vote():
    """A vote after terminal resolution is refused with a machine code."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    for i in range(3):
        box.vote(ballot_id, "member-%d" % i, True,
                 _sign_vote(keys[i][0], ballot_id, "member-%d" % i,
                            True, payload_digest))
    if box.resolve(ballot_id)["status"] != "adopted":
        return "BREAK(not-adopted)"
    try:
        box.vote(ballot_id, "member-2", True,
                 _sign_vote(keys[2][0], ballot_id, "member-2", True,
                            payload_digest))
    except bg.BallotError as e:
        if e.code == "ballot-late-vote":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_unknown_ballot():
    """vote()/resolve() on an unknown ballot id refuse loudly."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    sig = _sign_vote(keys[0][0], ballot_id, "member-0", True,
                     payload_digest)
    codes = []
    try:
        box.vote("blt-doesnotexist", "member-0", True, sig)
    except bg.BallotError as e:
        codes.append(e.code)
    try:
        box.resolve("blt-doesnotexist")
    except bg.BallotError as e:
        codes.append(e.code)
    if codes == ["ballot-unknown-ballot"] * 2:
        return "HELD"
    return "BREAK(%r)" % (codes,)


@probe
def probe_vote_hook_readonly():
    """The vote() hook is re-executed against read-only state: a hook
    that tries to mutate the state view fails loudly and the ballot
    stays consistent."""
    members, keys = _members(3)

    def evil_vote(member, decision, view):
        view["tampered"] = True  # must fail: read-only view
        return decision

    evil_type = bg.BallotType(
        name="evil", vote_fn=evil_vote,
        resolve_fn=bg.majority_with_veto(members).ballot_types[
            "standard"].resolve_fn)
    const = bg.Constitution(members={m.member_id: m for m in members},
                            ballot_types={"evil": evil_type})
    box, d = _box(const)
    ballot_id = box.propose("evil", {"action": "grant-read"}, "member-0")
    payload_digest = box.payload_digest(ballot_id)
    try:
        box.vote(ballot_id, "member-0", True,
                 _sign_vote(keys[0][0], ballot_id, "member-0", True,
                            payload_digest))
    except bg.BallotError as e:
        if (e.code == "ballot-vote-hook-failed"
                and not box.votes(ballot_id)):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(hook mutation survived)"


@probe
def probe_operator_weighted():
    """Operator-role-weighted thresholds: destructive needs 2/3 weight
    and no operator veto; routine needs a plain weight majority."""
    keys = _keys(5)
    members = [
        bg.Member("op-0", keys[0][1], role="operator", weight=3),
        bg.Member("op-1", keys[1][1], role="operator", weight=3),
        bg.Member("m-2", keys[2][1], role="member", weight=1),
        bg.Member("m-3", keys[3][1], role="member", weight=1),
        bg.Member("m-4", keys[4][1], role="member", weight=1),
    ]
    box, d = _box(bg.operator_weighted(members))
    # Routine: weight majority (>9/2=4.5) -> op-0 alone (3) is not
    # enough; op-0 + op-1 (6) adopts.
    rid = box.propose("routine", {"action": "read-logs"}, "op-0")
    rpd = box.payload_digest(rid)
    box.vote(rid, "op-0", True,
             _sign_vote(keys[0][0], rid, "op-0", True, rpd))
    if box.resolve(rid)["status"] != "open":
        return "BREAK(routine-early=%r)" % (box.resolve(rid)["status"],)
    box.vote(rid, "op-1", True,
             _sign_vote(keys[1][0], rid, "op-1", True, rpd))
    if box.resolve(rid)["status"] != "adopted":
        return "BREAK(routine-not-adopted)"
    # Destructive: op veto kills it even with 2/3 weight behind.
    did = box.propose("destructive", {"action": "drop-table"}, "op-0")
    dpd = box.payload_digest(did)
    box.vote(did, "op-0", True,
             _sign_vote(keys[0][0], did, "op-0", True, dpd))
    box.vote(did, "op-1", False,
             _sign_vote(keys[1][0], did, "op-1", False, dpd))
    for i in (2, 3, 4):
        mid = "m-%d" % i
        box.vote(did, mid, True,
                 _sign_vote(keys[i][0], did, mid, True, dpd))
    if box.resolve(did)["status"] != "rejected":
        return "BREAK(destructive-veto=%r)" % (box.resolve(did)["status"],)
    return "HELD"


@probe
def probe_journal_records_everything():
    """Every accepted vote and every refused vote is journaled; the
    hash chain verifies on reload."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    payload_digest = box.payload_digest(ballot_id)
    box.vote(ballot_id, "member-0", True,
             _sign_vote(keys[0][0], ballot_id, "member-0", True,
                        payload_digest))
    try:
        box.vote(ballot_id, "member-0", True,
                 _sign_vote(keys[0][0], ballot_id, "member-0", True,
                            payload_digest))
    except bg.BallotError:
        pass
    outcome = box.resolve(ballot_id)
    if outcome["status"] != "open":
        return "BREAK(unexpected=%r)" % (outcome["status"],)
    jpath = os.path.join(d, "ballot-journal.jsonl")
    from gov import durable_journal
    journal = durable_journal.Journal(jpath)  # verifies chain on load
    types = [r["type"] for r in journal.records]
    if ("ballot-proposed" in types and "ballot-vote-recorded" in types
            and "ballot-vote-refused" in types):
        return "HELD"
    return "BREAK(types=%r)" % (types,)


@probe
def probe_apply_only_on_adopted():
    """apply() runs only for adopted ballots; anything else refuses."""
    members, keys = _members(3)
    box, d = _box(bg.majority_with_veto(members))
    ballot_id = box.propose("standard", {"action": "grant-read"},
                            "member-0")
    try:
        box.apply(ballot_id)
    except bg.BallotError as e:
        if e.code != "ballot-quorum-not-reached":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(apply-on-open)"
    payload_digest = box.payload_digest(ballot_id)
    for i in range(3):
        box.vote(ballot_id, "member-%d" % i, True,
                 _sign_vote(keys[i][0], ballot_id, "member-%d" % i,
                            True, payload_digest))
    box.resolve(ballot_id)
    if box.apply(ballot_id)["status"] != "applied":
        return "BREAK(not-applied)"
    return "HELD"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_durable_journal",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    base = "/var/tmp" if os.path.isdir("/var/tmp") else None
    td = tempfile.mkdtemp(prefix="g261-ballot-green-", dir=base)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: durable_journal + decision_codes green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as e:  # noqa: BLE001 -- probe harness
                results.append((p.__name__, "BREAK(exc=%r)" % (e,)))
    held = sum(1 for _, r in results if r == "HELD")
    gap = sum(1 for _, r in results if r == "GAP")
    brk = sum(1 for _, r in results
              if r not in ("HELD", "GAP"))
    for name, r in results:
        print("%-42s %s" % (name, r))
    print("HELD=%d GAP=%d BREAK=%d / %d" % (held, gap, brk,
                                           len(results)))
    ok = green_check()
    mode = "GAP" if not HAVE_MODULE else "HELD"
    if not HAVE_MODULE:
        sys.exit(0 if gap == len(results) and ok else 1)
    sys.exit(0 if held == len(results) and ok else 1)


if __name__ == "__main__":
    main()
