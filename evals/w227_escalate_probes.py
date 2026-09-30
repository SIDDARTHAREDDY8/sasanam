#!/usr/bin/env python3
"""Wave-227 lane C: escalation-to-effect binding + supply-chain verification
records (SVR) with mandatory reproduction pointers.

ADAPT of the draft-das-agentic-adaptive-authorization-00 direction
("escalation must reach the effect point") + in-toto v1.2.0's SVR v0.2
direction (re-derived prose; nothing copied): an escalated action's
approval must be cryptographically bound into its action capsule, and
a supply-chain verification record must name where its claim can be
reproduced.

Seams under test:
* gov/escalation_bind.py —
  bind_escalation(approval_record, capsule): seals a NEW capsule that
  binds the escalation approval's digest into the attempt (escalation
  block) and effect (escalation_digest). Approval-to-action mismatch
  refuses ``escalation-action-mismatch``; approval digest that does
  not recompute refuses ``escalation-approval-digest-mismatch``;
  malformed records refuse ``escalation-malformed``; double binding
  refuses ``escalation-already-bound``.
  verify_escalation_bound(capsule): re-derives the binding from the
  sealed bytes. An escalated action (attempt marks
  escalation_required) whose capsule lacks a valid escalation block
  refuses ``escalation-not-bound`` — the escalation that never
  reached the effect point is DETECTABLE. Non-escalated capsules
  return None. Bindings are recomputed, never asserted.
* gov/svr.py —
  build_svr(artifact_digest, build_instructions_digest,
  reproduction_pointers, verifier_results): reproduction_pointers
  MUST be non-empty (empty refuses ``svr-no-reproduction-pointer``);
  each pointer syntactically validated (malformed refuses
  ``svr-pointer-malformed``); digest shape checked
  (``svr-digest-malformed``); authority-shaped fields refuse
  ``svr-not-authorization``. verify_svr replays everything.
  attach_svr_to_capsule(capsule, svr): digest-linked evidence —
  re-seals the capsule with the recomputed svr_digest in the
  effect; verify_capsule_svr re-derives the link (mismatch refuses
  ``svr-digest-mismatch``).

Attack shapes: escalation dropped between approval and effect;
approval body swapped after binding; approval bound to a different
action's digest; SVR with no reproduction pointer; non-URI pointer;
SVR digest tampered; authority smuggled into an SVR.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-226 HEAD
e3cc497e9e39004d58baca20abcea5cc2d9b938f.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g227c
  TMPDIR=/var/tmp/g227c ~/workspace/.gov-venv/bin/python evals/w227_escalate_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g227c-u \\
      ~/workspace/.gov-venv/bin/python evals/w227_escalate_probes.py
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
    from gov import escalation_bind as eb
    _EB_OK = True
    _EB_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine base has no module
    eb = None
    _EB_OK = False
    _EB_ERR = exc

try:
    from gov import svr as svr_mod
    _SVR_OK = True
    _SVR_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine base has no module
    svr_mod = None
    _SVR_OK = False
    _SVR_ERR = exc

try:
    from gov import action_capsule as ac
    _AC_OK = True
except Exception as exc:  # noqa: BLE001
    ac = None
    _AC_OK = False

_RESULTS = []

_DIGEST_A = "aa" * 32
_DIGEST_B = "bb" * 32


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _expect_code(name, fn, code, exc_type=None):
    """HELD if fn raises the module error type with .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        type_ok = exc_type is None or isinstance(exc, exc_type)
        if type_ok and got == code:
            _record(name, "HELD", "refused %s" % code)
        else:
            _record(name, "BREAK",
                    "wrong refusal: %r code=%r" % (exc, got))
    else:
        _record(name, "GAP", "no refusal raised")


def _expect_value(name, fn, want):
    try:
        got = fn()
    except Exception as exc:  # noqa: BLE001
        _record(name, "ERROR", "%r" % exc)
    else:
        if got == want:
            _record(name, "HELD", "-> %r" % (got,))
        else:
            _record(name, "BREAK", "got %r want %r" % (got, want))


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _escalated_capsule():
    """An admitted, sealed capsule whose attempt marks escalation
    required but carries no escalation binding yet."""
    return ac.seal_capsule({
        "attempt": {"action": "restart_database",
                    "args_digest": _DIGEST_A,
                    "escalation_required": True},
        "effect": {"status": "admitted",
                   "evidence": "db restarted; pid log line"},
    })


def _approval_for(capsule):
    """An escalation approval record for the given sealed capsule.

    The approval binds the capsule's verdict_digest (the action as
    approved) and carries its own digest, recomputable by anyone.
    """
    body = {"approver": "oncall-lead",
            "decision": "escalate-approve",
            "rationale": "incident-7782",
            "issued_at": "2026-09-30T00:00:00+00:00"}
    return {
        "v": 1,
        "approval_body": body,
        "approval_digest": hashlib.sha256(_canon(body)).hexdigest(),
        "action_digest": capsule["verdict_digest"],
    }


_PROBE_NAMES = [
    "esc-01-bound-verifies", "esc-02-unbound-refused",
    "esc-03-approval-digest-mismatch", "esc-04-action-mismatch",
    "esc-05-binding-recomputed", "esc-06-non-escalated-none",
    "esc-07-double-bind-refused",
    "svr-01-build-verify-roundtrip", "svr-02-no-pointers-refused",
    "svr-03-malformed-pointer-refused", "svr-04-no-authority",
    "svr-05-attach-digest-linked", "svr-06-tampered-link-refused",
    "svr-07-digest-malformed",
]


def _run_once():
    del _RESULTS[:]

    if not (_EB_OK and _SVR_OK and _AC_OK):
        for name in _PROBE_NAMES:
            _record(name, "GAP", "gov/escalation_bind or gov/svr absent")
        return list(_RESULTS)

    # esc-01 — bound escalation verifies: the returned approval digest
    # matches the approval's own digest.
    def _bind_ok():
        capsule = _escalated_capsule()
        approval = _approval_for(capsule)
        bound = eb.bind_escalation(approval, capsule)
        got = eb.verify_escalation_bound(bound)
        return got == approval["approval_digest"]
    _expect_value("esc-01-bound-verifies", _bind_ok, True)

    # esc-02 — KEY RULE: an escalated action whose capsule lacks the
    # escalation block refuses escalation-not-bound — a dropped
    # escalation is detectable at the effect point.
    _expect_code("esc-02-unbound-refused",
                 lambda: eb.verify_escalation_bound(_escalated_capsule()),
                 "escalation-not-bound", eb.EscalationBindError)

    # esc-03 — approval whose digest does not recompute refuses at
    # bind time, before any capsule is sealed.
    def _bad_approval_digest():
        capsule = _escalated_capsule()
        approval = _approval_for(capsule)
        approval["approval_digest"] = "00" * 32
        return eb.bind_escalation(approval, capsule)
    _expect_code("esc-03-approval-digest-mismatch", _bad_approval_digest,
                 "escalation-approval-digest-mismatch",
                 eb.EscalationBindError)

    # esc-04 — approval bound to a DIFFERENT action's digest refuses
    # escalation-action-mismatch (approval replayed onto another
    # action).
    def _wrong_action():
        capsule = _escalated_capsule()
        other = ac.seal_capsule({
            "attempt": {"action": "delete_database",
                        "args_digest": _DIGEST_B,
                        "escalation_required": True},
            "effect": {"status": "admitted",
                       "evidence": "db deleted; log line"},
        })
        approval = _approval_for(other)
        return eb.bind_escalation(approval, capsule)
    _expect_code("esc-04-action-mismatch", _wrong_action,
                 "escalation-action-mismatch", eb.EscalationBindError)

    # esc-05 — the binding is recomputed, not asserted: the digest
    # returned by verify equals an independent recomputation over
    # the approval body, and the action_digest equals the digest of
    # the attempt minus the escalation block.
    def _recompute():
        capsule = _escalated_capsule()
        approval = _approval_for(capsule)
        bound = eb.bind_escalation(approval, capsule)
        body = ac.verify_capsule(bound)
        esc_block = body["attempt"]["escalation"]
        want_approval = hashlib.sha256(
            _canon(approval["approval_body"])).hexdigest()
        attempt_minus = {k: v for k, v in body["attempt"].items()
                         if k != "escalation"}
        want_action = hashlib.sha256(_canon(attempt_minus)).hexdigest()
        return (esc_block["approval_digest"] == want_approval
                and esc_block["action_digest"] == want_action
                and body["effect"]["escalation_digest"] == want_approval)
    _expect_value("esc-05-binding-recomputed", _recompute, True)

    # esc-06 — a non-escalated capsule carries no binding requirement.
    def _plain():
        return ac.seal_capsule({
            "attempt": {"action": "read_file",
                        "args_digest": _DIGEST_A},
            "effect": {"status": "admitted", "evidence": "bytes read"},
        })
    _expect_value("esc-06-non-escalated-none",
                  lambda: eb.verify_escalation_bound(_plain()), None)

    # esc-07 — binding twice refuses escalation-already-bound.
    def _double():
        capsule = _escalated_capsule()
        approval = _approval_for(capsule)
        bound = eb.bind_escalation(approval, capsule)
        return eb.bind_escalation(approval, bound)
    _expect_code("esc-07-double-bind-refused", _double,
                 "escalation-already-bound", eb.EscalationBindError)

    def _svr():
        return svr_mod.build_svr(
            artifact_digest=_DIGEST_A,
            build_instructions_digest=_DIGEST_B,
            reproduction_pointers=["oci://registry.example.com/img",
                                   "git+https://git.example.com/r@abc123"],
            verifier_results={"reproduced": True,
                              "builder": "repro-builder-1"})

    # svr-01 — build + verify round trip; digest pinned to an
    # independent recomputation over the record fields.
    def _svr_roundtrip():
        rec = _svr()
        body = {"v": rec["v"],
                "artifact_digest": rec["artifact_digest"],
                "build_instructions_digest":
                    rec["build_instructions_digest"],
                "reproduction_pointers": rec["reproduction_pointers"],
                "verifier_results": rec["verifier_results"]}
        want = hashlib.sha256(_canon(body)).hexdigest()
        verified = svr_mod.verify_svr(rec)
        return verified["svr_digest"] == want == rec["svr_digest"]
    _expect_value("svr-01-build-verify-roundtrip", _svr_roundtrip, True)

    # svr-02 — KEY RULE: no reproduction pointers refuses
    # svr-no-reproduction-pointer — an unverifiable claim is not a
    # verification record.
    _expect_code("svr-02-no-pointers-refused",
                 lambda: svr_mod.build_svr(
                     artifact_digest=_DIGEST_A,
                     build_instructions_digest=_DIGEST_B,
                     reproduction_pointers=[],
                     verifier_results={}),
                 "svr-no-reproduction-pointer", svr_mod.SVRError)

    # svr-03 — malformed pointers refuse svr-pointer-malformed.
    for tag, pointer in (("whitespace", "oci://exa mple.com/img"),
                         ("no-scheme", "just-a-path"),
                         ("empty", ""),
                         ("non-string", 42)):
        _expect_code("svr-03-malformed-pointer-" + tag,
                     lambda p=pointer: svr_mod.build_svr(
                         artifact_digest=_DIGEST_A,
                         build_instructions_digest=_DIGEST_B,
                         reproduction_pointers=[p],
                         verifier_results={}),
                     "svr-pointer-malformed", svr_mod.SVRError)

    # svr-04 — authority-shaped fields in an SVR refuse
    # svr-not-authorization.
    _expect_code("svr-04-no-authority",
                 lambda: svr_mod.svr_carries_no_authority(
                     {"artifact_digest": _DIGEST_A, "grant": "all"}),
                 "svr-not-authorization", svr_mod.SVRError)

    # svr-05 — the SVR attaches to a capsule as digest-linked
    # evidence: the effect commits to the recomputed svr digest.
    def _attach():
        capsule = _escalated_capsule()
        rec = _svr()
        linked = svr_mod.attach_svr_to_capsule(capsule, rec)
        got = svr_mod.verify_capsule_svr(linked, rec)
        return got == rec["svr_digest"]
    _expect_value("svr-05-attach-digest-linked", _attach, True)

    # svr-06 — a tampered SVR no longer matches the capsule's link.
    def _tampered():
        capsule = _escalated_capsule()
        rec = _svr()
        linked = svr_mod.attach_svr_to_capsule(capsule, rec)
        tampered = dict(rec)
        tampered["verifier_results"] = {"reproduced": False}
        return svr_mod.verify_capsule_svr(linked, tampered)
    _expect_code("svr-06-tampered-link-refused", _tampered,
                 "svr-digest-mismatch", svr_mod.SVRError)

    # svr-07 — malformed digests refuse svr-digest-malformed.
    _expect_code("svr-07-digest-malformed",
                 lambda: svr_mod.build_svr(
                     artifact_digest="not-a-digest",
                     build_instructions_digest=_DIGEST_B,
                     reproduction_pointers=["oci://x.example.com/i"],
                     verifier_results={}),
                 "svr-digest-malformed", svr_mod.SVRError)

    return list(_RESULTS)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_action_capsule.py",):
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
    print("w227 escalate probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-34s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-34s %s %s" % (name, status, detail))
    if not (_EB_OK and _SVR_OK):
        print("import failed (pristine): %r %r" % (_EB_ERR, _SVR_ERR))
    if brk or err or not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
