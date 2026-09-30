#!/usr/bin/env python3
"""Wave-239 lane C: Jackson WIMSE -03 refusal-oracle rules (ADAPT, non-overlapping scope).

draft-jackson-wimse-evaluation -03 (prose re-derived, IETF Trust; §4.3
excluded as same family as in-flight work): refusal-oracle protection for
multi-entry authorization.

* one valid authorization path suffices; a broken path never neutralizes a
  valid one (fail-closed per path);
* a refusal MUST NOT name the failed path, grant, or issuer standing --
  the refusal text is oracle-clean, so an attacker cannot enumerate which
  credential almost worked;
* the audit trail distinguishes evaluated-and-refused from could-not-
  evaluate with distinct named codes;
* a misconfigured verifier fails closed loudly (a distinct named refusal,
  never a silent denial or an accidental authorization).

Attack shapes at the public seams (break-first, red-first on base):

* two authorization paths, one broken and one valid, must still authorize
  -- a broken path must not veto the valid one;
* all paths broken: the refusal must name NO path id, grant name, or
  issuer standing -- the probe greps the refusal detail for every secret
  string it planted in the path labels;
* a dependency that is unavailable (path check raises PathUnavailable)
  must refuse with the could-not-evaluate code, which must differ from the
  evaluated-and-refused code -- audit entries must carry the same
  distinction;
* an unavailable path alongside a valid one still authorizes;
* a misconfigured verifier (empty path set, duplicate path ids, a path
  whose check is not callable) refuses loud and closed with the
  misconfigured code -- never authorizes, never a soft silent denial.

Seams under test:
* gov/refusal_oracle_guard.py -- authorize, AuthPath, PathUnavailable,
  RefusalOracleError, ORACLE_EVALUATED_AND_REFUSED,
  ORACLE_COULD_NOT_EVALUATE, ORACLE_VERIFIER_MISCONFIGURED.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g239c
  TMPDIR=/var/tmp/g239c ~/workspace/.gov-venv/bin/python evals/w239_refusal_oracle_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import refusal_oracle_guard as _rog
    HAVE_NEW_API = all(hasattr(_rog, n) for n in (
        "authorize", "AuthPath", "PathUnavailable", "RefusalOracleError",
        "ORACLE_EVALUATED_AND_REFUSED", "ORACLE_COULD_NOT_EVALUATE",
        "ORACLE_VERIFIER_MISCONFIGURED"))
except ImportError:
    _rog = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "oracle-valid-path-suffices",
    "oracle-all-broken-refused-oracle-clean",
    "oracle-could-not-evaluate-distinct",
    "oracle-unavailable-does-not-neutralize",
    "oracle-misconfigured-loud-fail-closed",
    "oracle-detail-fuzz-no-leak",
    "oracle-audit-distinguishes-outcomes",
]


def _paths(*specs):
    """specs: (path_id, outcome) where outcome is True/False/'unavailable'/'boom'."""
    out = []
    for path_id, outcome in specs:
        if outcome == "unavailable":
            def check(outcome=outcome):
                raise _rog.PathUnavailable("dependency down")
        elif outcome == "boom":
            def check(outcome=outcome):
                raise RuntimeError("path-local crash with secret path internals")
        else:
            def check(outcome=outcome):
                return outcome
        out.append(_rog.AuthPath(path_id=path_id, check=check))
    return out


def probe_valid_path_suffices():
    res = _rog.authorize(_paths(("valid-path", True), ("broken-path", False)))
    if res["authorized"] and res["refusal"] is None:
        return ("HELD", "")
    return ("BREAK", "broken path vetoed a valid one: %r" % (res,))


def probe_all_broken_refused_oracle_clean():
    secret_ids = ("path-ALPHA-grant-x", "issuer-BETA-standing-y", "grant-GAMMA-secret-z")
    res = _rog.authorize(_paths(*[(pid, False) for pid in secret_ids]))
    if res["authorized"]:
        return ("BREAK", "authorized with all paths broken")
    if res["refusal"] != _rog.ORACLE_EVALUATED_AND_REFUSED:
        return ("BREAK", "wrong code %r" % (res["refusal"],))
    detail = res["detail"]
    for pid in secret_ids:
        if pid in detail:
            return ("BREAK", "oracle leak: path id %r in refusal detail" % (pid,))
    for word in ("ALPHA", "BETA", "GAMMA"):
        if word in detail:
            return ("BREAK", "oracle leak: fragment %r in refusal detail" % (word,))
    return ("HELD", "")


def probe_could_not_evaluate_distinct():
    res = _rog.authorize(_paths(("deps-down-path", "unavailable")))
    if res["authorized"]:
        return ("BREAK", "authorized with path unavailable")
    if res["refusal"] != _rog.ORACLE_COULD_NOT_EVALUATE:
        return ("BREAK", "wrong code %r" % (res["refusal"],))
    if res["refusal"] == _rog.ORACLE_EVALUATED_AND_REFUSED:
        return ("BREAK", "could-not-evaluate collapsed into evaluated-refused")
    audit_paths = res["audit"]["paths"]
    slim = [(pa["path_id"], pa["outcome"]) for pa in audit_paths]
    if slim != [("deps-down-path", "could-not-evaluate")]:
        return ("BREAK", "audit mislabels: %r" % (audit_paths,))
    return ("HELD", "")


def probe_unavailable_does_not_neutralize():
    res = _rog.authorize(_paths(("flaky-path", "unavailable"),
                                ("good-path", True)))
    if res["authorized"] and res["refusal"] is None:
        return ("HELD", "")
    return ("BREAK", "unavailable path neutralized a valid one: %r" % (res,))


def probe_misconfigured_loud_fail_closed():
    cases = {
        "empty": [],
        "duplicate-ids": _paths(("dup", True), ("dup", False)),
        "non-callable-check": [_rog.AuthPath(path_id="nc", check=None)],
        "non-list": "not-a-list",
    }
    for label, cfg in cases.items():
        try:
            res = _rog.authorize(cfg)
        except Exception as exc:  # noqa: BLE001
            return ("BREAK", "%s: raised %s instead of loud refusal" %
                    (label, type(exc).__name__))
        if res["authorized"]:
            return ("BREAK", "%s: authorized a misconfigured verifier" % label)
        if res["refusal"] != _rog.ORACLE_VERIFIER_MISCONFIGURED:
            return ("BREAK", "%s: wrong code %r" % (label, res["refusal"]))
    return ("HELD", "")


def probe_detail_fuzz_no_leak():
    # Distinctive planted secrets across all refusal shapes.
    secrets = ["fuzz-secret-%d" % i for i in range(6)]
    configs = [
        _paths(*[(s, False) for s in secrets[:2]]),          # evaluated-refused
        _paths((secrets[2], "unavailable")),                 # could-not-evaluate
        _paths((secrets[3], "boom")),                        # crash -> could-not-evaluate
        _paths((secrets[4], "unavailable"), (secrets[5], False)),  # mixed cne
    ]
    for cfg in configs:
        res = _rog.authorize(cfg)
        blob = res["detail"]
        for s in secrets:
            if s in blob:
                return ("BREAK", "leak of %r in detail %r" % (s, blob))
    return ("HELD", "")


def probe_audit_distinguishes_outcomes():
    r_refused = _rog.authorize(_paths(("p1", False), ("p2", False)))
    r_cne = _rog.authorize(_paths(("p3", "unavailable")))
    if r_refused["audit"]["refusal_code"] == r_cne["audit"]["refusal_code"]:
        return ("BREAK", "audit uses one code for both outcomes")
    outcomes_refused = {p["outcome"] for p in r_refused["audit"]["paths"]}
    outcomes_cne = {p["outcome"] for p in r_cne["audit"]["paths"]}
    if outcomes_refused != {"refused"}:
        return ("BREAK", "refused audit mislabeled: %r" % (outcomes_refused,))
    if outcomes_cne != {"could-not-evaluate"}:
        return ("BREAK", "cne audit mislabeled: %r" % (outcomes_cne,))
    return ("HELD", "")


_PROBES = {
    "oracle-valid-path-suffices": probe_valid_path_suffices,
    "oracle-all-broken-refused-oracle-clean":
        probe_all_broken_refused_oracle_clean,
    "oracle-could-not-evaluate-distinct": probe_could_not_evaluate_distinct,
    "oracle-unavailable-does-not-neutralize":
        probe_unavailable_does_not_neutralize,
    "oracle-misconfigured-loud-fail-closed":
        probe_misconfigured_loud_fail_closed,
    "oracle-detail-fuzz-no-leak": probe_detail_fuzz_no_leak,
    "oracle-audit-distinguishes-outcomes":
        probe_audit_distinguishes_outcomes,
}


def _run_green_check():
    print("green check: depth-1; skipping (adjacent battery runs are "
          "coordinator-gated)")
    return True


def main():
    t0 = time.time()
    results = []
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            results.append((name, "GAP", "module absent"))
    else:
        for name in PROBE_NAMES:
            fn = _PROBES[name]
            try:
                verdict, note = fn()
            except Exception as exc:  # noqa: BLE001
                verdict, note = "ERROR", "%s: %s\n%s" % (
                    type(exc).__name__, exc, traceback.format_exc(limit=3))
            results.append((name, verdict, note))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        tail = (" -- " + note) if note else ""
        print("%-46s %s%s" % (name, verdict, tail))
    print("----")
    print("%d HELD / %d GAP / %d BREAK / %d ERROR (%d probes, %.1fs)" % (
        held, gap, brk, err, len(results), time.time() - t0))
    if not GREEN_SKIP:
        _run_green_check()
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
