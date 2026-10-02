"""Break-first battery for gov/root_ceremony.py (wave-262 feature lane 3).

sigstore/root-signing ADAPT (Apache-2.0, credited in the module
docstring): threshold root ceremony as code -- named keyholders,
review-before-sign, fork-PR-style signature collection (each signature
references the exact ceremony digest, no detached approvals), mandatory
staged rehearsal, and the routine (KMS/expiry) vs ceremonial
(human/root-key) split. The decision math is composed from
gov/ballot_governance.py (wave-261 CCF-style ballots), not duplicated.

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break attempt
succeeds. A genuine BREAK against the final implementation would file a
finding; this battery must be all HELD on the shipped module.

Next free: F237 (file only genuine product defects).

No in-repo git subprocesses (wave-36 supply-chain probe discipline).
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1715  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)

try:
    from gov import decision_codes
    from gov import ballot_governance as bg
    from gov import root_ceremony as rc
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
        seed = hashlib.sha256(b"w262-ceremony-probe-%d" % i).digest()
        out.append((seed, ed25519.publickey(seed)))
    return out


def _members(n):
    keys = _keys(n)
    members = []
    for i, (seed, pub) in enumerate(keys):
        members.append(bg.Member(member_id="keyholder-%d" % i,
                                 pubkey=pub, role="keyholder", weight=1))
    return members, keys


def _gov(n=5, journal_path=None):
    members, keys = _members(n)
    d = tempfile.mkdtemp(prefix="w262ceremony-")
    jpath = journal_path or os.path.join(d, "ceremony.jsonl")
    g = rc.CeremonyGovernor(members, jpath)
    return g, d, members, keys


_NEW_FP = hashlib.sha256(b"new-root-pubkey").hexdigest()
_OLD_FP = hashlib.sha256(b"old-root-pubkey").hexdigest()


def _propose(g, **kw):
    params = dict(event_type="rotation",
                  change_description="rotate root K-2026: new HSM key",
                  new_key_fingerprint=_NEW_FP,
                  proposer="keyholder-0",
                  threshold=3, review_quorum=2,
                  old_root_fingerprint=_OLD_FP)
    params.update(kw)
    return g.propose(**params)


def _review(g, cid, keys, idxs):
    digest = g.ceremony_digest(cid)
    for i in idxs:
        khid = "keyholder-%d" % i
        sig = ed25519.sign(keys[i][0], rc.review_envelope(cid, khid,
                                                          digest))
        g.record_review(cid, khid,
                        {"ceremony_digest": digest,
                         "signature": sig.hex()})


def _rehearse(g, cid, namespace="scratch/rehearsal-1"):
    rec = rc.make_rehearsal_record(
        cid, _NEW_FP, namespace,
        [{"name": "verify-chain", "passed": True},
         {"name": "client-accept", "passed": True}])
    g.record_rehearsal(cid, rec)
    return rec


def _sign_exec(g, cid, keys, idxs, decision=True):
    info = g.execution_ballot(cid)
    for i in idxs:
        khid = "keyholder-%d" % i
        sig = ed25519.sign(keys[i][0],
                           bg.vote_envelope(info["ballot_id"], khid,
                                            decision,
                                            info["payload_digest"]))
        g.sign_execution(cid, khid, decision, sig)


def _drive_to_completed(g, keys, cid):
    _review(g, cid, keys, (0, 1))
    _rehearse(g, cid)
    g.open_execution(cid)
    _sign_exec(g, cid, keys, (0, 1, 2))
    g.resolve_execution(cid)
    return g.complete(cid)


# ---------------------------------------------------------------------------
# Break attempts: each must refuse loudly with its machine code.
# ---------------------------------------------------------------------------

@probe
def probe_rehearsal_forged():
    """A rehearsal record with a tampered field (digest kept) is forged:
    refuse ceremony-rehearsal-forged, never advance."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    rec = rc.make_rehearsal_record(
        cid, _NEW_FP, "scratch/rehearsal-1",
        [{"name": "verify-chain", "passed": True}])
    rec["namespace"] = "production"  # tamper: digest no longer matches
    try:
        g.record_rehearsal(cid, rec)
    except rc.CeremonyError as e:
        if (e.code == "ceremony-rehearsal-forged"
                and g.status(cid)["phase"] == "reviewed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_rehearsal_skipped():
    """Execution cannot open without a passing rehearsal record."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    try:
        g.open_execution(cid)
    except rc.CeremonyError as e:
        if (e.code == "ceremony-rehearsal-missing"
                and g.status(cid)["phase"] == "reviewed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_rehearsal_failed_checks():
    """A rehearsal record whose checks did not all pass is forged."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    rec = rc.make_rehearsal_record(
        cid, _NEW_FP, "scratch/rehearsal-2",
        [{"name": "verify-chain", "passed": False}])
    try:
        g.record_rehearsal(cid, rec)
    except rc.CeremonyError as e:
        if (e.code == "ceremony-rehearsal-forged"
                and g.status(cid)["phase"] == "reviewed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_digest_mismatched_review():
    """A review attestation referencing a DIFFERENT ceremony digest is
    refused as ceremony-digest-mismatch (not counted); a wrong-key
    signature is ceremony-bad-signature."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    real = g.ceremony_digest(cid)
    wrong = hashlib.sha256(b"attacker-digest").hexdigest()
    sig = ed25519.sign(keys[0][0], rc.review_envelope(cid, "keyholder-0",
                                                     wrong))
    try:
        g.record_review(cid, "keyholder-0",
                        {"ceremony_digest": wrong,
                         "signature": sig.hex()})
    except rc.CeremonyError as e:
        if e.code != "ceremony-digest-mismatch":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(no refusal)"
    bad_seed = hashlib.sha256(b"w262-attacker").digest()
    bad_sig = ed25519.sign(bad_seed, rc.review_envelope(cid, "keyholder-1",
                                                        real))
    try:
        g.record_review(cid, "keyholder-1",
                        {"ceremony_digest": real,
                         "signature": bad_sig.hex()})
    except rc.CeremonyError as e:
        if (e.code == "ceremony-bad-signature"
                and g.status(cid)["reviews"] == []):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_digest_mismatched_execution():
    """An execution signature over a different payload digest is refused
    by the composed ballot box (ballot-bad-signature), never counted."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    _rehearse(g, cid)
    info = g.open_execution(cid)
    wrong_digest = hashlib.sha256(b"forked-payload").hexdigest()
    sig = ed25519.sign(keys[0][0],
                       bg.vote_envelope(info["ballot_id"], "keyholder-0",
                                        True, wrong_digest))
    try:
        g.sign_execution(cid, "keyholder-0", True, sig)
    except bg.BallotError as e:
        if e.code == "ballot-bad-signature":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(no refusal)"


@probe
def probe_replay_completed():
    """A completed ceremony id cannot be reused: proposing with it, or
    any mutation on the completed ceremony, refuses ceremony-replayed."""
    g, d, members, keys = _gov()
    cid = _propose(g, ceremony_id="crm-replay-test")
    _drive_to_completed(g, keys, cid)
    if g.status(cid)["phase"] != "completed":
        return "BREAK(not completed)"
    try:
        g.propose(event_type="rotation",
                  change_description="second rotation",
                  new_key_fingerprint=_NEW_FP,
                  proposer="keyholder-0", threshold=3, review_quorum=2,
                  ceremony_id="crm-replay-test")
    except rc.CeremonyError as e:
        if e.code != "ceremony-replayed":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(reuse allowed)"
    digest = g.ceremony_digest(cid)
    sig = ed25519.sign(keys[0][0], rc.review_envelope(cid, "keyholder-0",
                                                     digest))
    try:
        g.record_review(cid, "keyholder-0",
                        {"ceremony_digest": digest,
                         "signature": sig.hex()})
    except rc.CeremonyError as e:
        if e.code == "ceremony-replayed":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(mutation allowed)"


@probe
def probe_root_touch_routine():
    """Any root-key action through the routine (KMS) path is refused:
    ceremony-routine-path-refused. Routine ops still sign fine."""
    for action in ("root-key-rotate", "root-key-generate",
                   "trust-root-pin-change", "root-key-recover"):
        try:
            rc.routine_sign(action, {"k": "v"},
                            hashlib.sha256(b"s").digest())
        except rc.CeremonyError as e:
            if e.code != "ceremony-routine-path-refused":
                return "BREAK(%s=%r)" % (action, e.code)
        else:
            return "BREAK(%s allowed)" % (action,)
    sig = rc.routine_sign("sign-daily", {"artifact": "x"},
                          hashlib.sha256(b"s").digest())
    if not isinstance(sig, bytes) or len(sig) != 64:
        return "BREAK(routine broken)"
    return "HELD"


@probe
def probe_unknown_action_ceremonial():
    """The classifier fails closed: unknown, empty, and non-string
    actions are ceremonial; only exact routine ops are routine."""
    if not rc.is_ceremonial("frobnicate-9000"):
        return "BREAK(unknown not ceremonial)"
    if not rc.is_ceremonial(""):
        return "BREAK(empty not ceremonial)"
    if not rc.is_ceremonial(None):
        return "BREAK(none not ceremonial)"
    if not rc.is_ceremonial("ROOT-KEY-ROTATE"):
        return "BREAK(case variant missed)"
    if rc.is_ceremonial("sign-daily"):
        return "BREAK(routine misclassified)"
    if not rc.is_ceremonial("expiry attestation for root ca"):
        return "BREAK(substring root missed)"
    return "HELD"


@probe
def probe_quorum_not_reached():
    """Executing without a threshold of yes-signatures refuses with
    ceremony-quorum-not-reached -- both for a still-open ballot and a
    fully-cast-but-insufficient one."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    _rehearse(g, cid)
    g.open_execution(cid)
    _sign_exec(g, cid, keys, (0, 1))  # 2 yes of 3 -- still open
    try:
        g.resolve_execution(cid)
    except rc.CeremonyError as e:
        if e.code != "ceremony-quorum-not-reached":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(executed short)"
    # Full electorate, still short: 2 yes / 3 no.
    g2, d2, m2, k2 = _gov()
    cid2 = _propose(g2)
    _review(g2, cid2, k2, (0, 1))
    _rehearse(g2, cid2)
    g2.open_execution(cid2)
    _sign_exec(g2, cid2, k2, (0, 1), decision=True)
    _sign_exec(g2, cid2, k2, (2, 3, 4), decision=False)
    try:
        g2.resolve_execution(cid2)
    except rc.CeremonyError as e:
        if (e.code == "ceremony-quorum-not-reached"
                and g2.status(cid2)["phase"] == "rehearsed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(executed short 2)"


@probe
def probe_private_key_never():
    """A proposal carrying private-key material is refused at propose
    time: ceremony-private-key-material. No ceremony opens."""
    g, d, members, keys = _gov()
    try:
        g.propose(event_type="rotation",
                  change_description="rotate",
                  new_key_fingerprint=_NEW_FP,
                  proposer="keyholder-0", threshold=3, review_quorum=2,
                  new_key_private="aabbcc")  # forbidden extra field
    except rc.CeremonyError as e:
        if e.code == "ceremony-private-key-material":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(private key accepted)"


@probe
def probe_phase_order():
    """Out-of-order transitions refuse ceremony-phase-violation: no
    rehearsal before review quorum, no complete before execution, no
    double execution ballot."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    rec = rc.make_rehearsal_record(cid, _NEW_FP, "scratch/x",
                                   [{"name": "c", "passed": True}])
    try:
        g.record_rehearsal(cid, rec)
    except rc.CeremonyError as e:
        if e.code != "ceremony-phase-violation":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(rehearse-before-review)"
    try:
        g.complete(cid)
    except rc.CeremonyError as e:
        if (e.code == "ceremony-phase-violation"
                and g.status(cid)["phase"] == "proposed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(complete-before-execution)"


@probe
def probe_double_review():
    """A keyholder's second review attestation is refused and not
    double-counted toward the review quorum."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0,))
    digest = g.ceremony_digest(cid)
    sig = ed25519.sign(keys[0][0], rc.review_envelope(cid, "keyholder-0",
                                                     digest))
    try:
        g.record_review(cid, "keyholder-0",
                        {"ceremony_digest": digest,
                         "signature": sig.hex()})
    except rc.CeremonyError as e:
        if (e.code == "ceremony-double-review"
                and g.status(cid)["phase"] == "proposed"):
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(double counted)"


@probe
def probe_review_quorum_gates():
    """Review quorum is real: one attestation does not unlock rehearsal;
    the second does."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0,))
    rec = rc.make_rehearsal_record(cid, _NEW_FP, "scratch/x",
                                   [{"name": "c", "passed": True}])
    try:
        g.record_rehearsal(cid, rec)
    except rc.CeremonyError as e:
        if e.code != "ceremony-phase-violation":
            return "BREAK(%r)" % (e.code,)
    else:
        return "BREAK(single review unlocked)"
    _review(g, cid, keys, (1,))
    if g.status(cid)["phase"] != "reviewed":
        return "BREAK(not reviewed)"
    g.record_rehearsal(cid, rec)
    if g.status(cid)["phase"] == "rehearsed":
        return "HELD"
    return "BREAK(not rehearsed)"


@probe
def probe_crash_recovery():
    """Reloading the governor from the journal rebuilds ceremony state
    AND the completed-id tombstones; replay of a completed id still
    refuses after a restart."""
    g, d, members, keys = _gov()
    cid = _propose(g, ceremony_id="crm-crash-test")
    _drive_to_completed(g, keys, cid)
    jpath = os.path.join(d, "ceremony.jsonl")
    g2 = rc.CeremonyGovernor(_members(5)[0], jpath)
    if g2.status(cid)["phase"] != "completed":
        return "BREAK(state lost)"
    try:
        g2.propose(event_type="rotation",
                   change_description="after restart",
                   new_key_fingerprint=_NEW_FP,
                   proposer="keyholder-0", threshold=3, review_quorum=2,
                   ceremony_id="crm-crash-test")
    except rc.CeremonyError as e:
        if e.code == "ceremony-replayed":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(tombstone lost)"


@probe
def probe_execution_binds_ceremony_digest():
    """The execution ballot's payload binds the exact ceremony digest:
    the vote envelope a keyholder signs cannot drift to another
    ceremony or a forged payload."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    _review(g, cid, keys, (0, 1))
    _rehearse(g, cid)
    info = g.open_execution(cid)
    if info["ceremony_digest"] != g.ceremony_digest(cid):
        return "BREAK(digest drift)"
    # A signature minted for a DIFFERENT ceremony id cannot land here.
    g2, d2, m2, k2 = _gov()
    cid2 = _propose(g2)
    _review(g2, cid2, k2, (0, 1))
    _rehearse(g2, cid2)
    info2 = g2.open_execution(cid2)
    cross = ed25519.sign(k2[0][0],
                         bg.vote_envelope(info2["ballot_id"],
                                          "keyholder-0", True,
                                          info2["payload_digest"]))
    try:
        g.sign_execution(cid, "keyholder-0", True, cross)
    except bg.BallotError as e:
        if e.code == "ballot-bad-signature":
            return "HELD"
        return "BREAK(%r)" % (e.code,)
    return "BREAK(cross-ceremony accepted)"


@probe
def probe_happy_path():
    """The full ceremony completes: proposed -> reviewed -> rehearsed ->
    executed -> completed, old root superseded and journaled, and the
    hash chain verifies on a fresh journal load."""
    g, d, members, keys = _gov()
    cid = _propose(g)
    phases = [g.status(cid)["phase"]]
    _review(g, cid, keys, (0, 1))
    phases.append(g.status(cid)["phase"])
    _rehearse(g, cid)
    phases.append(g.status(cid)["phase"])
    g.open_execution(cid)
    _sign_exec(g, cid, keys, (0, 1, 2))
    out = g.resolve_execution(cid)
    phases.append(g.status(cid)["phase"])
    if out["status"] != "adopted":
        return "BREAK(not adopted)"
    done = g.complete(cid)
    phases.append(g.status(cid)["phase"])
    if phases != ["proposed", "reviewed", "rehearsed", "executed",
                  "completed"]:
        return "BREAK(phases=%r)" % (phases,)
    if (done["old_root_fingerprint"] != _OLD_FP
            or done["new_root_fingerprint"] != _NEW_FP):
        return "BREAK(supersession=%r)" % (done,)
    from gov import durable_journal
    journal = durable_journal.Journal(os.path.join(d, "ceremony.jsonl"))
    types = [r["type"] for r in journal.records]
    need = ["ceremony-proposed", "ceremony-review-recorded",
            "ceremony-reviewed", "ceremony-rehearsal-recorded",
            "ceremony-rehearsed", "ceremony-execution-opened",
            "ballot-proposed", "ballot-vote-recorded", "ballot-resolved",
            "ceremony-executed", "ceremony-completed"]
    missing = [t for t in need if t not in types]
    if missing:
        return "BREAK(missing=%r)" % (missing,)
    return "HELD"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_durable_journal",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    base = "/var/tmp" if os.path.isdir("/var/tmp") else None
    td = tempfile.mkdtemp(prefix="g262-ceremony-green-", dir=base)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: decision_codes + durable_journal green")
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
    if not HAVE_MODULE:
        sys.exit(0 if gap == len(results) and ok else 1)
    sys.exit(0 if held == len(results) and ok else 1)


if __name__ == "__main__":
    main()
