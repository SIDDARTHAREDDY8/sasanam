#!/usr/bin/env python3
"""Row-9 residual 1: the unverified fold — provisional peers must not validate.

``PopulationStore.all_baselines()`` returned every agent's latest
baseline INCLUDING ones with trust ``"provisional"``. That list feeds
``validate_baseline_against_population()`` (via the executor seam and
``note_run``) as the peer population, so a provisional (unvalidated,
possibly poisoned) fingerprint got to vote on whether a NEW agent's
baseline is trusted: a poisoned peer legitimizes poisoned baselines.

Fixed behavior (what these probes assert):
  - ``all_baselines()`` folds trusted-only: only agents whose CURRENT
    trust is ``"trusted"`` (baseline trust as overridden by later
    ``trust`` records — human confirm / auto-converge) appear.
  - Fewer trusted peers -> ``unvalidated_no_population`` (fail closed),
    never silent inclusion of provisional votes.
  - Trust transitions are honored: confirm/auto-converge restore
    membership; the fold consults effective trust, not just the
    baseline record's trust bit.

Probes:
  r1f_provisional_excluded_from_fold
  r1f_provisional_does_not_vote (n_peers counts trusted peers only)
  r1f_provisional_only_population_fail_closed
  r1f_confirm_restores_membership
  r1f_note_run_uses_trusted_peers (regression: convergence still works)

Verdicts: HELD / BREAK / ERROR. Pre-fix each of the first three is
BREAK (the residual, demonstrated red); post-fix all HELD.

$0 spend, synthetic/local, deterministic (no RNG; no wall-clock in
verdicts). Stdlib only.

Run:
  mkdir -p /tmp/gov-row9fold
  TMPDIR=/tmp/gov-row9fold ~/workspace/.gov-venv/bin/python \\
      evals/row9_unverified_fold_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-row9foldb \\
      ~/workspace/.gov-venv/bin/python evals/row9_unverified_fold_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "row9fold-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-row9fold-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import drift as _drift  # noqa: E402

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-42s %-8s %s" % (name, verdict, detail))


def _fp(tools, egress=4_000, run_seq=0):
    return _drift.RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": 0},
        egress_bytes=egress, run_seq=run_seq)


_NORMAL = {"search": 40, "summarize": 30, "email": 20, "read_file": 10}
_ATTACK = {"http_post": 90, "email": 10}


def _pop(tag):
    root = Path(tempfile.mkdtemp(prefix="row9fold_%s_" % tag,
                                 dir=os.environ["TMPDIR"]))
    return _drift.PopulationStore(root / "population")


def _seed_normals(pop, n=3):
    for i in range(n):
        tools = dict(_NORMAL)
        tools["search"] += i
        pop.record_baseline("peer-%d" % i, "user-1", _fp(tools))


def _seed_provisional_attacker(pop, aid="evil"):
    """Record an attack-shaped baseline as provisional_untrusted."""
    res = _drift.validate_baseline_against_population(
        aid, _fp(_ATTACK), [(a, f) for a, f in pop.all_baselines()])
    assert res.status == "provisional_untrusted", res.status
    pop.record_baseline(aid, "user-1", _fp(_ATTACK), validation=res)
    return res


# ---------------------------------------------------------------- probes

def r1f_provisional_excluded_from_fold():
    """Provisional agents must not appear in the validating population."""
    name = "r1f_provisional_excluded_from_fold"
    pop = _pop("fold")
    _seed_normals(pop, 3)
    _seed_provisional_attacker(pop)
    members = [a for a, _ in pop.all_baselines()]
    if "evil" in members:
        _record(name, "BREAK",
                "provisional 'evil' is in all_baselines(): it would vote "
                "on new baselines (members=%s)" % (members,))
        return
    if len(members) != 3:
        _record(name, "BREAK",
                "trusted peers lost in the fold: %s" % (members,))
        return
    _record(name, "HELD",
            "all_baselines() = %s (provisional excluded)" % (members,))


def r1f_provisional_does_not_vote():
    """n_peers counts trusted peers only; the provisional peer is silent."""
    name = "r1f_provisional_does_not_vote"
    pop = _pop("vote")
    _seed_normals(pop, 3)
    _seed_provisional_attacker(pop)
    res = _drift.validate_baseline_against_population(
        "new-attacker", _fp(_ATTACK),
        [(a, f) for a, f in pop.all_baselines()])
    if res.n_peers != 3:
        _record(name, "BREAK",
                "n_peers=%d: the provisional peer voted (want 3)"
                % (res.n_peers,))
        return
    if res.status != "provisional_untrusted":
        _record(name, "BREAK",
                "attack-shaped newcomer not flagged: %s" % (res.status,))
        return
    _record(name, "HELD",
            "n_peers=3 (trusted only); attack newcomer provisional")


def r1f_provisional_only_population_fail_closed():
    """Only provisional peers -> unvalidated_no_population, never a vote."""
    name = "r1f_provisional_only_population_fail_closed"
    # A population whose ONLY members are provisional: record them
    # directly as provisional (seeding via validation would let the
    # residual itself pollute the seed — the poisoned peer inflates the
    # threshold, which is the very dynamic under test).
    pop2 = _pop("only2")
    for i in range(3):
        res = _drift.BaselineValidationResult(
            "provisional_untrusted", agent_id="evil-%d" % i)
        pop2.record_baseline("evil-%d" % i, "user-1", _fp(_ATTACK),
                             validation=res)
    res = _drift.validate_baseline_against_population(
        "new-attacker", _fp(_ATTACK),
        [(a, f) for a, f in pop2.all_baselines()])
    if res.status != "unvalidated_no_population":
        _record(name, "BREAK",
                "provisional peers validated the newcomer: status=%s "
                "(want unvalidated_no_population)" % (res.status,))
        return
    _record(name, "HELD",
            "provisional-only population -> unvalidated_no_population "
            "(fail closed, n_peers=%d)" % (res.n_peers,))


def r1f_confirm_restores_membership():
    """Trust transitions are honored: confirm -> back in the fold."""
    name = "r1f_confirm_restores_membership"
    pop = _pop("confirm")
    _seed_normals(pop, 3)
    _seed_provisional_attacker(pop)
    before = [a for a, _ in pop.all_baselines()]
    pop.confirm_baseline("evil", reason="human_confirm")
    after = [a for a, _ in pop.all_baselines()]
    if "evil" in before:
        _record(name, "BREAK",
                "provisional 'evil' was in the fold before confirm")
        return
    if "evil" not in after or len(after) != 4:
        _record(name, "BREAK",
                "confirm did not restore fold membership: %s" % (after,))
        return
    _record(name, "HELD",
            "provisional excluded, then confirm_baseline restored it")


def r1f_note_run_uses_trusted_peers():
    """Regression: auto-convergence still works on the trusted fold."""
    name = "r1f_note_run_uses_trusted_peers"
    pop = _pop("note")
    _seed_normals(pop, 5)
    # Record the benign-weird agent provisional directly: seeding via
    # validation against a polluted population would let the residual
    # itself decide the seed.
    res = _drift.BaselineValidationResult(
        "provisional_untrusted", agent_id="w")
    pop.record_baseline("w", "user-1", _fp({"translate": 80, "search": 20}),
                        validation=res)
    for _ in range(3):
        peers = [(a, f) for a, f in pop.all_baselines() if a != "w"]
        trust, _ = pop.note_run("w", _fp(_NORMAL), peers,
                                auto_confirm_runs=3)
    trust, _ = pop.trust_of("w")
    if trust != "trusted":
        _record(name, "BREAK",
                "auto-converge broke on the trusted fold: %s" % (trust,))
        return
    members = [a for a, _ in pop.all_baselines()]
    if "w" not in members:
        _record(name, "BREAK",
                "auto-converged agent missing from the fold: %s"
                % (members,))
        return
    _record(name, "HELD",
            "3 conforming runs auto-confirmed 'w' on trusted peers; "
            "fold membership restored")


_PROBES = (
    r1f_provisional_excluded_from_fold,
    r1f_provisional_does_not_vote,
    r1f_provisional_only_population_fail_closed,
    r1f_confirm_restores_membership,
    r1f_note_run_uses_trusted_peers,
)


def main():
    print("Row-9 residual 1 probes: the unverified fold")
    for fn in _PROBES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 -- battery must not die
            _record(fn.__name__, "ERROR", "%r" % (e,))
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("%d HELD, %d BREAK, %d ERROR" % (held, brk, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
