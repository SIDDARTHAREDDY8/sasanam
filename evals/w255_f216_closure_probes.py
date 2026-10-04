"""Break-first closure battery for F216 (MEDIUM).

Wave-255 lane 1. Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

F216: gov/incident.py's transition() reached "resolved" directly,
bypassing resolve()'s fail-closed finding/task checks.

Closure (fix): "resolved" is no longer a legal transition() target.
resolve() is the single fail-closed path to the resolved state; any
transition(iid, "resolved") is refused as incident-illegal-transition
(and journaled as incident/transition_refused, same as every other
illegal move).

Expected verdicts:
  pristine base (21fc1c44): BREAK / BREAK / HELD / HELD / HELD
  fixed code:              HELD / HELD / HELD / HELD / HELD
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import incident as inc_mod  # noqa: E402

assert len(decision_codes.TAXONOMY) == 2056, "taxonomy pin 1588"  # Wave-271 merge: pin 1372 -> 1411 (+39 codes: 6 ptgrant-* + 7 replay-* + 8 rsl-* + 14 gatehard-* + 4 imgtext-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    d = tempfile.mkdtemp(prefix="w255f216-", dir="/var/tmp")
    os.makedirs(d, exist_ok=True)
    return d


def _mgr(tmp, finding_status=None):
    return inc_mod.IncidentManager(
        os.path.join(tmp, "inc.jsonl"), finding_status=finding_status)


def _to_contained(mgr, iid="INC-1"):
    mgr.declare_incident(iid, title="t", severity="high")
    mgr.transition(iid, "investigating")
    mgr.transition(iid, "contained")
    return iid


@probe("f216/transition-to-resolved-refused-with-open-finding")
def _p_bypass_open_finding():
    # The exact F216 reproduction: resolve() refuses
    # incident-open-findings, then transition() to resolved must also
    # refuse -- reaching "resolved" would be the bypass.
    tmp = _tmpdir()
    mgr = _mgr(tmp, finding_status=lambda fid: "open")
    iid = _to_contained(mgr)
    mgr.link_finding(iid, "F1")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code != "incident-open-findings":
            return ("HELD", "resolve refused with unexpected %s"
                    % exc.code)
    else:
        return ("HELD", "resolve() did not refuse (unexpected)")
    try:
        mgr.transition(iid, "resolved")
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-illegal-transition":
            return ("HELD", "transition refused %s" % exc.code)
        return ("HELD", "transition refused with %s" % exc.code)
    if mgr.state(iid) == "resolved":
        return ("BREAK", "F216: resolved with open finding via "
                "transition(), resolve() gate bypassed")
    return ("HELD", "state not resolved")


@probe("f216/transition-to-resolved-refused-clean-state")
def _p_single_path():
    # Even with all findings closed and no tasks, transition() to
    # "resolved" is refused: resolve() is the single path. On the
    # pristine base this succeeds (BREAK); on fixed code it is
    # refused (HELD).
    tmp = _tmpdir()
    mgr = _mgr(tmp, finding_status=lambda fid: "closed")
    iid = _to_contained(mgr)
    try:
        mgr.transition(iid, "resolved")
    except inc_mod.IncidentError as exc:
        return ("HELD", "refused %s" % exc.code)
    return ("BREAK", "transition() reached resolved; resolve() "
            "is not the single path")


@probe("f216/resolve-refuses-open-findings")
def _p_resolve_findings_pin():
    # Regression pin: resolve() still fails closed on open findings.
    tmp = _tmpdir()
    mgr = _mgr(tmp, finding_status=lambda fid: "open")
    iid = _to_contained(mgr)
    mgr.link_finding(iid, "F9")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-open-findings":
            return ("HELD", "refused incident-open-findings")
        return ("BREAK", "wrong code %s" % exc.code)
    return ("BREAK", "resolved with open finding")


@probe("f216/resolve-refuses-open-tasks")
def _p_resolve_tasks_pin():
    # Regression pin: resolve() still fails closed on open tasks.
    tmp = _tmpdir()
    mgr = _mgr(tmp, finding_status=lambda fid: "closed")
    iid = _to_contained(mgr)
    mgr.add_task(iid, "still open", owner="op")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-open-tasks":
            return ("HELD", "refused incident-open-tasks")
        return ("BREAK", "wrong code %s" % exc.code)
    return ("BREAK", "resolved with open task")


@probe("f216/happy-path-resolve-then-close")
def _p_happy_path():
    # Regression pin: clean incident still resolves and closes.
    tmp = _tmpdir()
    mgr = _mgr(tmp, finding_status=lambda fid: "closed")
    iid = _to_contained(mgr)
    tid = mgr.add_task(iid, "fix it", owner="op")
    mgr.complete_task(iid, tid)
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        return ("BREAK", "resolve refused clean incident: %s"
                % exc.code)
    if mgr.state(iid) != "resolved":
        return ("BREAK", "state not resolved after resolve()")
    mgr.transition(iid, "closed")
    if mgr.state(iid) != "closed":
        return ("BREAK", "state not closed after close")
    return ("HELD", "resolve() -> resolved -> closed intact")


def main():
    breaks = held = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
        print("%s %s: %s" % (verdict, name, detail))
    print("SUMMARY: %d HELD / %d BREAK / %d ERROR"
          % (held, breaks, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
