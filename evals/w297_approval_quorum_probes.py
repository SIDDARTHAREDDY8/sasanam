"""Wave-297 lane 2 red-first battery: approval quorum + blocking vetoes.

Builds gov/approval_quorum.py (gerrit + phorge STEAL, Apache-2.0,
mechanism only, stdlib only): votes are signed declarations on an
approval-request digest; a QuorumPredicate declares min_approvals,
named blocking veto roles (one veto = un-outvotable), requester!=
approver, and expiry. tally returns the signed decision or refuses
coded (approval-quorum-unmet, approval-quorum-vetoed,
approval-quorum-self-vote, approval-quorum-invalid,
approval-request-expired). Votes are append-only: retract_vote only
refuses.

Base: wave-296 merge 5fd40f0 (verified via git rev-parse HEAD before
work).

Pin 1753 -> 1758 (+5: 4 approval-quorum-* +1 approval-request-expired);
the repoint is tree-wide (value-token-only, code/comment splitter,
history comments extended), so adjacent batteries' own pin probes stay
green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g297-aq && TMPDIR=/var/tmp/g297-aq \
    ~/workspace/.gov-venv/bin/python evals/w297_approval_quorum_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g297-aqb \
    ~/workspace/.gov-venv/bin/python evals/w297_approval_quorum_probes.py
"""

import os
import subprocess
import sys

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-297 lane 2: pin 1753 -> 1758 (+5: 4 approval-quorum-* +1
# approval-request-expired).
TAXONOMY_PIN = 1984 # Wave-296 merge: pin 1743 -> 1753 (+3 decision-trace-*) Wave-297 lane 2: pin 1753 -> 1758 (+5: 4 approval-quorum-* +1 approval-request-expired).; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

try:
    from gov import approval_quorum as AQ
    from gov import decision_codes
    from gov import ed25519 as _ed
except ImportError:
    AQ = None
    decision_codes = None
    _ed = None


class _Break(Exception):
    """A probe that fails because the feature is absent or wrong."""


def _need():
    if AQ is None:
        raise _Break("gov.approval_quorum absent on this tree")


def _seeds(n):
    return [bytes([i]) * 32 for i in range(1, n + 1)]


def _voters(ids, seeds):
    return AQ.build_registry({v: seeds[v] for v in ids})


def _request(requester="requester-1", rid="req-1", expires=2000000000):
    return {
        "schema": "approval-request/v1",
        "request_id": rid,
        "requester_id": requester,
        "action_digest": "ab" * 32,
        "expires_at": expires,
        "version": 1,
    }


def _cast(seeds_by_id, registry, voter, verdict, digest, reason="cd" * 32):
    seed = seeds_by_id[voter]
    return AQ.cast_vote(seed, digest, voter, verdict, reason)


def _refuses(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except AQ.ApprovalQuorumError as exc:
        if exc.code != code:
            raise _Break("expected code %r, got %r (%s)"
                         % (code, exc.code, exc.detail))
        return
    except Exception as exc:
        raise _Break("expected coded %r, got %r: %s"
                     % (code, type(exc).__name__, exc))
    raise _Break("expected coded refusal %r, call succeeded" % code)


# ------------------------------------------------------------------
# Red-first probes: the feature must exist before anything else.
# ------------------------------------------------------------------

def probe_01_module_exists():
    _need()


def probe_02_vote_is_signed_declaration():
    _need()
    seeds = dict(zip(["a"], _seeds(1)))
    req = _request()
    digest = AQ.request_digest(req)
    v = AQ.cast_vote(seeds["a"], digest, "a", "approve", "cd" * 32)
    assert set(v) == {"body", "signature"}, "vote envelope shape"
    assert v["body"]["request_digest"] == digest


def probe_03_predicate_declares_min_and_veto_roles():
    _need()
    p = AQ.QuorumPredicate(min_approvals=2,
                           blocking_veto_roles=("sec-lead",))
    assert p.min_approvals == 2
    assert "sec-lead" in p.blocking_veto_roles
    assert p.digest() == AQ.QuorumPredicate(
        min_approvals=2, blocking_veto_roles=("sec-lead",)).digest()


def probe_04_request_digest_stable():
    _need()
    req = _request()
    assert AQ.request_digest(req) == AQ.request_digest(dict(req))


def probe_05_quorum_passes():
    _need()
    ids = ["v1", "v2", "v3"]
    seeds = dict(zip(ids, _seeds(3)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, v, "approve", digest) for v in ids]
    pred = AQ.QuorumPredicate(min_approvals=2)
    decision = AQ.tally(votes, pred, req, registry, now=1000)
    assert decision["outcome"] == "approved"
    assert decision["approve_count"] == 3
    assert AQ.verify_decision(decision, votes, pred, req, registry) is True


def probe_06_unmet_refuses_coded():
    _need()
    ids = ["v1"]
    seeds = dict(zip(ids, _seeds(1)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v1", "approve", digest)]
    _refuses("approval-quorum-unmet", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1000)


def probe_07_veto_unoutvotable():
    _need()
    ids = ["v%d" % i for i in range(1, 12)] + ["sec-lead"]
    seeds = dict(zip(ids, _seeds(12)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v%d" % i, "approve", digest)
             for i in range(1, 12)]
    votes.append(_cast(seeds, registry, "sec-lead", "veto", digest))
    pred = AQ.QuorumPredicate(min_approvals=2,
                              blocking_veto_roles=("sec-lead",))
    _refuses("approval-quorum-vetoed", AQ.tally, votes, pred, req,
             registry, 1000)


def probe_08_self_vote_refuses_coded():
    _need()
    ids = ["requester-1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request(requester="requester-1")
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "requester-1", "approve", digest),
             _cast(seeds, registry, "v2", "approve", digest)]
    _refuses("approval-quorum-self-vote", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1000)


def probe_09_withdrawal_refuses_coded():
    _need()
    seeds = dict(zip(["a"], _seeds(1)))
    req = _request()
    digest = AQ.request_digest(req)
    v = AQ.cast_vote(seeds["a"], digest, "a", "approve", "cd" * 32)
    _refuses("approval-quorum-invalid", AQ.retract_vote, v)


def probe_10_forged_vote_refuses_coded():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    # signed by the WRONG seed (attacker), presented as v1
    attacker = bytes([9]) * 32
    forged = AQ.cast_vote(attacker, digest, "v1", "approve", "cd" * 32)
    votes = [forged,
             _cast(seeds, registry, "v2", "approve", digest)]
    _refuses("approval-quorum-invalid", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1000)


def probe_11_expired_request_refuses_coded():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request(expires=1000)
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, v, "approve", digest) for v in ids]
    _refuses("approval-request-expired", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1001)


def probe_12_double_vote_refuses_coded():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v1", "approve", digest),
             _cast(seeds, registry, "v1", "approve", digest),
             _cast(seeds, registry, "v2", "approve", digest)]
    _refuses("approval-quorum-invalid", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1000)


# ------------------------------------------------------------------
# HELD probes: the contract holds on the fixed tree.
# ------------------------------------------------------------------

def probe_13_nonrole_veto_refuses_coded():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v1", "veto", digest),
             _cast(seeds, registry, "v2", "approve", digest)]
    _refuses("approval-quorum-invalid", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=1), req, registry, 1000)


def probe_14_vote_rebound_across_requests_refuses():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req_a = _request(rid="req-A")
    req_b = _request(rid="req-B")
    digest_a = AQ.request_digest(req_a)
    digest_b = AQ.request_digest(req_b)
    votes = [_cast(seeds, registry, "v1", "approve", digest_a),
             _cast(seeds, registry, "v2", "approve", digest_b)]
    _refuses("approval-quorum-invalid", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=1), req_a, registry, 1000)


def probe_15_unknown_voter_refuses_coded():
    _need()
    seeds = dict(zip(["v1", "ghost"], _seeds(2)))
    registry = _voters(["v1"], seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v1", "approve", digest),
             _cast(seeds, registry, "ghost", "approve", digest)]
    _refuses("approval-quorum-invalid", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=1), req, registry, 1000)


def probe_16_malformed_request_refuses_coded():
    _need()
    pred = AQ.QuorumPredicate(min_approvals=1)
    bad = {"schema": "approval-request/v1"}
    _refuses("approval-quorum-invalid", AQ.tally, [], pred, bad, {}, 1000)


def probe_17_predicate_bounds_refuse_coded():
    _need()
    _refuses("approval-quorum-invalid", AQ.QuorumPredicate, 0)
    _refuses("approval-quorum-invalid", AQ.QuorumPredicate, 100)
    _refuses("approval-quorum-invalid", AQ.QuorumPredicate, 2,
             ("",))


def probe_18_decision_divergence_refuses():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, v, "approve", digest) for v in ids]
    pred = AQ.QuorumPredicate(min_approvals=2)
    decision = AQ.tally(votes, pred, req, registry, now=1000)
    tampered = dict(decision)
    tampered["approve_count"] = 99
    _refuses("approval-quorum-invalid", AQ.verify_decision, tampered,
             votes, pred, req, registry)


def probe_19_reject_does_not_count_as_approve():
    _need()
    ids = ["v1", "v2"]
    seeds = dict(zip(ids, _seeds(2)))
    registry = _voters(ids, seeds)
    req = _request()
    digest = AQ.request_digest(req)
    votes = [_cast(seeds, registry, "v1", "approve", digest),
             _cast(seeds, registry, "v2", "reject", digest)]
    _refuses("approval-quorum-unmet", AQ.tally, votes,
             AQ.QuorumPredicate(min_approvals=2), req, registry, 1000)


def probe_20_registry_cap_refuses_coded():
    _need()
    ids = ["v%d" % i for i in range(5)]
    seeds = dict(zip(ids, _seeds(5)))
    registry = _voters(ids, seeds)
    req = _request()
    pred = AQ.QuorumPredicate(min_approvals=1, max_voters=2)
    _refuses("approval-quorum-invalid", AQ.tally, [], pred, req,
             registry, 1000)


def probe_21_taxonomy_pin():
    if decision_codes is None:
        raise _Break("gov.decision_codes absent")
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        raise _Break("taxonomy pin drift: live=%d pin=%d"
                     % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
    for code in ("approval-quorum-invalid", "approval-quorum-self-vote",
                 "approval-quorum-unmet", "approval-quorum-vetoed",
                 "approval-request-expired"):
        if code not in decision_codes.TAXONOMY:
            raise _Break("new code %r missing from taxonomy" % code)


def probe_22_green_checks():
    if SKIP_GREEN:
        return "skipped (GOV_SKIP_GREEN=1)"
    for battery in ("evals/w296_decision_trace_probes.py",
                    "evals/w294_filter_pipeline_probes.py"):
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, battery)],
            env=env, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            raise _Break("green check %s failed: %s"
                         % (battery, proc.stderr[-2000:]))


PROBES = [v for k, v in sorted(globals().items())
          if k.startswith("probe_") and callable(v)]


def main():
    broke, held, errors = [], [], []
    for probe in PROBES:
        try:
            note = probe()
            held.append((probe.__name__, note))
        except _Break as exc:
            broke.append((probe.__name__, str(exc)))
        except Exception as exc:
            errors.append((probe.__name__, "%s: %s"
                           % (type(exc).__name__, exc)))
    print("w297_approval_quorum: %d BREAK / %d HELD / %d ERROR"
          % (len(broke), len(held), len(errors)))
    for name, why in broke:
        print("  BREAK %s: %s" % (name, why))
    for name, why in errors:
        print("  ERROR %s: %s" % (name, why))
    for name, note in held:
        if note:
            print("  HELD %s: %s" % (name, note))
    return 1 if (broke or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
