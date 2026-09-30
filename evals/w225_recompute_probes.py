#!/usr/bin/env python3
"""Wave-225 lane A: recompute-don't-assert rules for action capsules.

ADAPT of the upstream Agent Action Capsule PR #141 recompute rules
(re-derived prose; nothing copied): a batch verifier must RECOMPUTE
what it can instead of trusting the issuer's assertions.

Seams under test:
* gov/action_capsule.py — chain_capsules(capsules, links=()) ->
  {v, chain_digest, capsule_digests, counts, close_state};
  chain_digest = sha256 of the canonical JSON bytes of
  {v, capsule_digests, links}. Every capsule digest is replayed via
  verify_capsule; tampering refuses with the ORIGINAL module codes
  (capsule-digest-mismatch, capsule-malformed, capsule-noncanonical,
  capsule-attempt-effect-diverged, capsule-unknown-field).
* verify_capsule_batch(batch) — per-capsule verify_capsule,
  recomputed counts, close state derived from acknowledges/rebuts
  links, all chained. ``claimed_counts`` (optional; keys verdicts,
  refusal_capsules, links) is checked against the recomputed counts:
  disagreement refuses ``capsule-count-mismatch``.
  ``claimed_close_state`` (optional) is checked against the derived
  state: disagreement refuses ``capsule-closestate-mismatch``.
  Unknown batch fields or unknown count keys fail closed with
  ``capsule-unknown-field``.
* Close state: no links -> "open"; any "rebuts" link ->
  "closed-rebutted"; else any "acknowledges" link ->
  "closed-acknowledged". Unknown link kinds refuse
  ``capsule-malformed``; a link whose target digest matches no
  capsule in the batch refuses ``capsule-digest-mismatch``.
* Legacy: seal_capsule/verify_capsule unchanged; sealed capsule
  dicts carry no new required fields.

Attack shapes: issuer asserts false counts; issuer asserts a close
state the links do not support; link target digest tampered to a
non-batch capsule; capsule digest tampered inside a batch; unknown
link kinds; unknown batch/count fields; authority smuggled through
a batch.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-224 HEAD
186c2b5c5465b9fda67e8b0afa0dc338b0b3212b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (batch API absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g225a
  TMPDIR=/var/tmp/g225a ~/workspace/.gov-venv/bin/python evals/w225_recompute_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g225a-u \\
      ~/workspace/.gov-venv/bin/python evals/w225_recompute_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import action_capsule as ac
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine base has no module
    ac = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_BATCH_API_OK = _IMPORT_OK and hasattr(ac, "verify_capsule_batch") \
    and hasattr(ac, "chain_capsules")

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _expect_code(name, fn, code):
    """HELD if fn raises ac.CapsuleError with .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if isinstance(exc, ac.CapsuleError) and got == code:
            _record(name, "HELD", "refused %s" % code)
        else:
            _record(name, "BREAK",
                    "wrong refusal: %r code=%r" % (exc, got))
    else:
        _record(name, "GAP", "no refusal raised")


def _admit_verdict():
    return {
        "attempt": {"action": "write_file",
                    "params_digest": "sha256:" + "a1" * 32},
        "effect": {"status": "admitted",
                   "evidence": "sha256:" + "b2" * 32,
                   "observed": "file written at 2026-09-30T04:00:00Z"},
    }


def _sealed_pair():
    a = ac.seal_capsule(_admit_verdict())
    r = ac.capsule_from_refusal("permit-revoked", "sha256:" + "d4" * 32)
    return a, r


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _expected_chain_digest(capsules, links):
    body = {"v": 1,
            "capsule_digests": [c["capsule_digest"] for c in capsules],
            "links": links}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _require_batch_api(name):
    """Record GAP on the pristine base where the batch API is absent."""
    if not _BATCH_API_OK:
        _record(name, "GAP", "batch API absent on base")
        return False
    return True


def _run_once():
    del _RESULTS[:]

    if not _IMPORT_OK:
        for name in _PROBE_NAMES:
            _record(name, "GAP", "module absent on base")
        return list(_RESULTS)

    admit_cap, refusal_cap = _sealed_pair()

    # r-01 — honest open batch with matching claims verifies; the
    # verifier recomputes counts and the chain digest itself.
    if _require_batch_api("r-01-honest-open-batch"):
        try:
            batch = {"capsules": [admit_cap, refusal_cap],
                     "links": [],
                     "claimed_counts": {"verdicts": 2,
                                        "refusal_capsules": 1,
                                        "links": 0},
                     "claimed_close_state": "open"}
            out = ac.verify_capsule_batch(batch)
            ok = (out["close_state"] == "open"
                  and out["counts"] == {"verdicts": 2,
                                       "refusal_capsules": 1,
                                       "links": 0}
                  and out["chain_digest"] == _expected_chain_digest(
                      [admit_cap, refusal_cap], []))
            _record("r-01-honest-open-batch", "HELD" if ok else "BREAK",
                    "counts recomputed, close state open")
        except Exception as exc:  # noqa: BLE001
            _record("r-01-honest-open-batch", "ERROR", "%r" % (exc,))

    # r-02 — tampered verdict count refuses capsule-count-mismatch.
    if _require_batch_api("r-02-tampered-count-refused"):
        _expect_code(
            "r-02-tampered-count-refused",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap, refusal_cap],
                 "claimed_counts": {"verdicts": 5}}),
            "capsule-count-mismatch")

    # r-03 — tampered refusal-capsule count refuses
    # capsule-count-mismatch.
    if _require_batch_api("r-03-tampered-refusal-count-refused"):
        _expect_code(
            "r-03-tampered-refusal-count-refused",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap, refusal_cap],
                 "claimed_counts": {"refusal_capsules": 0}}),
            "capsule-count-mismatch")

    # r-04 — acknowledges link derives closed-acknowledged; matching
    # claim verifies.
    if _require_batch_api("r-04-ack-link-derived"):
        try:
            link = {"kind": "acknowledges",
                    "target_capsule_digest":
                        admit_cap["capsule_digest"]}
            batch = {"capsules": [admit_cap, refusal_cap],
                     "links": [link],
                     "claimed_close_state": "closed-acknowledged"}
            out = ac.verify_capsule_batch(batch)
            ok = (out["close_state"] == "closed-acknowledged"
                  and out["counts"]["links"] == 1
                  and out["chain_digest"] == _expected_chain_digest(
                      [admit_cap, refusal_cap], [link]))
            _record("r-04-ack-link-derived", "HELD" if ok else "BREAK",
                    "close state derived from link, not asserted")
        except Exception as exc:  # noqa: BLE001
            _record("r-04-ack-link-derived", "ERROR", "%r" % (exc,))

    # r-05 — claimed "open" with an acknowledges link present refuses
    # capsule-closestate-mismatch.
    if _require_batch_api("r-05-closestate-mismatch-refused"):
        link = {"kind": "acknowledges",
                "target_capsule_digest": admit_cap["capsule_digest"]}
        _expect_code(
            "r-05-closestate-mismatch-refused",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap],
                 "links": [link],
                 "claimed_close_state": "open"}),
            "capsule-closestate-mismatch")

    # r-06 — rebuts link derives closed-rebutted (rebuts dominates).
    if _require_batch_api("r-06-rebuts-derived"):
        try:
            links = [{"kind": "acknowledges",
                      "target_capsule_digest":
                          admit_cap["capsule_digest"]},
                     {"kind": "rebuts",
                      "target_capsule_digest":
                          refusal_cap["capsule_digest"]}]
            out = ac.verify_capsule_batch(
                {"capsules": [admit_cap, refusal_cap],
                 "links": links,
                 "claimed_close_state": "closed-rebutted"})
            ok = (out["close_state"] == "closed-rebutted"
                  and out["counts"]["links"] == 2)
            _record("r-06-rebuts-derived", "HELD" if ok else "BREAK",
                    "rebuts link dominates the derived state")
        except Exception as exc:  # noqa: BLE001
            _record("r-06-rebuts-derived", "ERROR", "%r" % (exc,))

    # r-07 — unknown link kind fails closed with an original code.
    if _require_batch_api("r-07-unknown-link-kind"):
        _expect_code(
            "r-07-unknown-link-kind",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap],
                 "links": [{"kind": "disputes",
                            "target_capsule_digest":
                                admit_cap["capsule_digest"]}]}),
            "capsule-malformed")

    # r-08 — link whose target matches no capsule in the batch refuses
    # with an original code.
    if _require_batch_api("r-08-link-target-mismatch"):
        _expect_code(
            "r-08-link-target-mismatch",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap],
                 "links": [{"kind": "acknowledges",
                            "target_capsule_digest": "00" * 32}]}),
            "capsule-digest-mismatch")

    # r-09 — tampered capsule inside a batch refuses with the
    # original module code (digest replayed per capsule).
    if _require_batch_api("r-09-tampered-capsule-in-batch"):
        tampered = dict(admit_cap)
        tampered["jcs_json"] = admit_cap["jcs_json"].replace(
            "admitted", "admittedX")
        _expect_code(
            "r-09-tampered-capsule-in-batch",
            lambda: ac.verify_capsule_batch(
                {"capsules": [tampered, refusal_cap]}),
            "capsule-digest-mismatch")

    # r-10 — legacy unchanged: seal/verify of a plain verdict works,
    # and sealed capsule dicts carry no new required fields.
    try:
        cap = ac.seal_capsule(_admit_verdict())
        body = ac.verify_capsule(cap)
        ok = (set(cap.keys()) == {"v", "capsule_digest",
                                  "verdict_digest", "effect_digest",
                                  "jcs_json"}
              and body["effect"]["status"] == "admitted")
        _record("r-10-legacy-unchanged", "HELD" if ok else "BREAK",
                "legacy seam byte-shape unchanged")
    except Exception as exc:  # noqa: BLE001
        _record("r-10-legacy-unchanged", "ERROR", "%r" % (exc,))

    # r-11 — unknown top-level batch field fails closed.
    if _require_batch_api("r-11-unknown-batch-field"):
        _expect_code(
            "r-11-unknown-batch-field",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap], "bogus": True}),
            "capsule-unknown-field")

    # r-12 — claims are optional: a minimal batch verifies and the
    # verifier still recomputes counts and the open state.
    if _require_batch_api("r-12-minimal-batch"):
        try:
            out = ac.verify_capsule_batch({"capsules": [admit_cap]})
            ok = (out["counts"] == {"verdicts": 1,
                                   "refusal_capsules": 0,
                                   "links": 0}
                  and out["close_state"] == "open")
            _record("r-12-minimal-batch", "HELD" if ok else "BREAK",
                    "optional claims; verifier still recomputes")
        except Exception as exc:  # noqa: BLE001
            _record("r-12-minimal-batch", "ERROR", "%r" % (exc,))

    # r-13 — tampered link count refuses capsule-count-mismatch.
    if _require_batch_api("r-13-tampered-link-count-refused"):
        link = {"kind": "acknowledges",
                "target_capsule_digest": admit_cap["capsule_digest"]}
        _expect_code(
            "r-13-tampered-link-count-refused",
            lambda: ac.verify_capsule_batch(
                {"capsules": [admit_cap],
                 "links": [link],
                 "claimed_counts": {"links": 99}}),
            "capsule-count-mismatch")

    # r-14 — chain_capsules verifies every digest, recomputes counts,
    # derives close state, and returns a chain commitment directly.
    if _require_batch_api("r-14-chain-direct"):
        try:
            link = {"kind": "acknowledges",
                    "target_capsule_digest":
                        refusal_cap["capsule_digest"]}
            out = ac.chain_capsules([admit_cap, refusal_cap], [link])
            ok = (out["close_state"] == "closed-acknowledged"
                  and out["counts"] == {"verdicts": 2,
                                       "refusal_capsules": 1,
                                       "links": 1}
                  and out["chain_digest"] == _expected_chain_digest(
                      [admit_cap, refusal_cap], [link])
                  and out["capsule_digests"]
                  == [admit_cap["capsule_digest"],
                      refusal_cap["capsule_digest"]])
            _record("r-14-chain-direct", "HELD" if ok else "BREAK",
                    "direct chain commitment: verified + recomputed")
        except Exception as exc:  # noqa: BLE001
            _record("r-14-chain-direct", "ERROR", "%r" % (exc,))

    # r-15 — the chain commitment is evidence, never authority: it
    # carries no authority-shaped fields (grant/authorization/
    # authority/permit/capability/scope/delegation/token).
    if _require_batch_api("r-15-commitment-no-authority"):
        try:
            out = ac.chain_capsules([admit_cap, refusal_cap])
            authority_fields = {"grant", "authorization", "authority",
                                "permit", "capability", "scope",
                                "delegation", "token"}
            ok = (set(out.keys()) == {"v", "chain_digest",
                                      "capsule_digests", "counts",
                                      "close_state"}
                  and not authority_fields.intersection(out.keys())
                  and not authority_fields.intersection(
                      out["counts"].keys()))
            _record("r-15-commitment-no-authority",
                    "HELD" if ok else "BREAK",
                    "commitment is evidence, never authority")
        except Exception as exc:  # noqa: BLE001
            _record("r-15-commitment-no-authority", "ERROR",
                    "%r" % (exc,))

    return list(_RESULTS)


# NO git-spawning self-pins: the standing wave-36 supply-chain probe
# (redteam.supplychain.gitspawn_no_git_subprocess_in_repo) fails
# closed on any in-repo git subprocess (hostile .git/config
# core.fsmonitor trigger class). Add-only is enforced at merge time
# by direct byte-verification against the lane commit.


_PROBE_NAMES = [
    "r-01-honest-open-batch", "r-02-tampered-count-refused",
    "r-03-tampered-refusal-count-refused", "r-04-ack-link-derived",
    "r-05-closestate-mismatch-refused", "r-06-rebuts-derived",
    "r-07-unknown-link-kind", "r-08-link-target-mismatch",
    "r-09-tampered-capsule-in-batch", "r-10-legacy-unchanged",
    "r-11-unknown-batch-field", "r-12-minimal-batch",
    "r-13-tampered-link-count-refused", "r-14-chain-direct",
    "r-15-commitment-no-authority",
]


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_posture.py",
                 "tests/test_absence_revocation.py",
                 "tests/test_permit_leases.py",
                 "tests/test_admission.py",
                 "tests/test_decision_packet.py",
                 "tests/test_action_capsule.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w225 recompute probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-36s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-36s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
