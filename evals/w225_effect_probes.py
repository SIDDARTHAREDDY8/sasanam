#!/usr/bin/env python3
"""Wave-225 lane C: portable effect statuses + rule-labeled decision evidence.

ADAPT of the VEP-0006 direction + OPA 1.21.1 ``rule_labels``
evidence-enrichment pattern (re-derived prose; nothing copied):
execution outcomes get a portable closed vocabulary, and decision
packets can carry the named rules that produced them as evidence.

Seams under test:
* gov/effect_status.py — EffectStatus closed vocabulary:
  completed | failed | denied | cancelled-before-execution |
  cancelled-after-possible-effect | timed-out-before-effect |
  timed-out-after-possible-effect | unknown.
* classify(observation): the KEY RULE — a timeout/cancellation AFTER
  an external executor may have accepted the work MUST NOT map to
  ``unknown``/``none``; it maps to the after-possible-effect status.
  Claiming ``unknown`` with executor_may_have_accepted=True refuses
  ``effect-status-ambiguous-refused`` (forces the caller to say which
  side of acceptance the timeout landed on). Malformed observations
  refuse ``effect-status-invalid``.
* gov/decision_packet.py — build_decision_packet(..., rule_labels=):
  optional dict[str, str] naming the rules/verdicts that produced the
  decision, embedded as a signature-covered section; invalid labels
  (non-dict, empty key, non-printable value) refuse
  ``decision-labels-invalid``; rule_labels=None is legacy
  byte-identical (no section added).
* capsule_from_effect(verdict_record, effect_status) — seals an action
  capsule (gov/action_capsule.py) with the portable effect status
  bound in; the ambiguous mapping refuses
  ``effect-status-ambiguous-refused``.

Attack shapes: post-acceptance timeout relabeled ``unknown`` (erases
the possibility of side effects); pre/post acceptance conflated;
malformed labels (empty keys, non-printable values) smuggled into
evidence; labels tampered after signing; legacy packet paths altered.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-224 HEAD
186c2b5c5465b9fda67e8b0afa0dc338b0b3212b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent, no rule_labels kwarg) is
expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g225c
  TMPDIR=/var/tmp/g225c ~/workspace/.gov-venv/bin/python evals/w225_effect_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g225c-u \\
      ~/workspace/.gov-venv/bin/python evals/w225_effect_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import effect_status as es
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine base has no module
    es = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

try:
    from gov import decision_packet as dp
    from gov import decision_bom as bom_mod
    _DP_OK = True
except Exception as exc:  # noqa: BLE001
    dp = None
    bom_mod = None
    _DP_OK = False

SEED = bytes.fromhex("22" * 32)

_RESULTS = []


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


def _minimal_kwargs(**over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32, evidence_head_digest="GENESIS",
              principal={"agent_id": None, "role": None,
                         "principal": None, "run_id": None})
    bom = bom_mod.build_bom(**kw)
    return dict(decision="allow", boundary_declared=False,
                authority_proof=None, evidence_head_digest="GENESIS",
                policy_id="default", policy_version="unversioned",
                issued_at="2026-09-30T00:00:00+00:00",
                bill_of_materials=bom, **over)


def _run_once():
    del _RESULTS[:]

    if not _IMPORT_OK:
        for name in _PROBE_NAMES:
            _record(name, "GAP", "gov/effect_status absent on base")
        return list(_RESULTS)

    # eff-01 — pre-execution timeout maps before-effect.
    _expect_value("eff-01-pre-timeout",
                  lambda: es.classify({"outcome": "timed-out",
                                       "executor_may_have_accepted": False}),
                  "timed-out-before-effect")

    # eff-02 — post-acceptance timeout maps after-possible-effect.
    _expect_value("eff-02-post-timeout",
                  lambda: es.classify({"outcome": "timed-out",
                                       "executor_may_have_accepted": True}),
                  "timed-out-after-possible-effect")

    # eff-03 — pre-execution cancellation.
    _expect_value("eff-03-pre-cancel",
                  lambda: es.classify({"outcome": "cancelled",
                                       "executor_may_have_accepted": False}),
                  "cancelled-before-execution")

    # eff-04 — post-acceptance cancellation.
    _expect_value("eff-04-post-cancel",
                  lambda: es.classify({"outcome": "cancelled",
                                       "executor_may_have_accepted": True}),
                  "cancelled-after-possible-effect")

    # eff-05 — KEY RULE: unknown claimed after possible acceptance
    # refuses; the caller must say which side of acceptance it landed.
    _expect_code("eff-05-ambiguous-refused",
                 lambda: es.classify({"outcome": "unknown",
                                      "executor_may_have_accepted": True}),
                 "effect-status-ambiguous-refused", es.EffectStatusError)

    # eff-06 — honest unknown is fine pre-acceptance.
    _expect_value("eff-06-unknown-pre",
                  lambda: es.classify({"outcome": "unknown",
                                       "executor_may_have_accepted": False}),
                  "unknown")

    # eff-07 — terminal outcomes round-trip.
    _expect_value("eff-07-terminals",
                  lambda: tuple(es.classify(
                      {"outcome": o, "executor_may_have_accepted": False})
                      for o in ("completed", "failed", "denied")),
                  ("completed", "failed", "denied"))

    # eff-08 — malformed observations refuse effect-status-invalid.
    for tag, obs in (("bad-outcome", {"outcome": "vaporized",
                                      "executor_may_have_accepted": False}),
                     ("not-dict", "timed-out"),
                     ("missing-accept", {"outcome": "timed-out"})):
        _expect_code("eff-08-malformed-" + tag,
                     lambda o=obs: es.classify(o),
                     "effect-status-invalid", es.EffectStatusError)

    # eff-09 — rule_labels embed: signature-covered section, verify ok.
    def _labeled_packet():
        if not _DP_OK:
            raise RuntimeError("decision_packet unavailable")
        body = dp.build_decision_packet(
            **_minimal_kwargs(rule_labels={"allow-read": "p1.rule",
                                           "deny-write": "p2.rule"}))
        if body["rule_labels"]["value"] != {"allow-read": "p1.rule",
                                            "deny-write": "p2.rule"}:
            raise AssertionError("labels not embedded")
        signed = dp.sign_packet(body, SEED)
        ok, reason = dp.verify_decision_packet(signed)
        if not ok:
            raise AssertionError("verify failed: %s" % reason)
        return True
    _expect_value("eff-09-labels-embed", _labeled_packet, True)

    # eff-10 — invalid labels refuse decision-labels-invalid.
    for tag, labels in (("empty-key", {"": "p1.rule"}),
                        ("non-printable", {"k": "p\x01.rule"}),
                        ("non-dict", ["p1.rule"]),
                        ("non-str-value", {"k": 7})):
        def _bad(lb=labels):
            if not _DP_OK:
                raise RuntimeError("decision_packet unavailable")
            return dp.build_decision_packet(**_minimal_kwargs(
                rule_labels=lb))
        _expect_code("eff-10-labels-invalid-" + tag, _bad,
                     "decision-labels-invalid",
                     dp.PacketError if _DP_OK else None)

    # eff-11 — legacy packet: no rule_labels -> no section; verify ok.
    def _legacy_packet():
        if not _DP_OK:
            raise RuntimeError("decision_packet unavailable")
        body = dp.build_decision_packet(**_minimal_kwargs())
        if "rule_labels" in body:
            raise AssertionError("legacy body gained a section")
        signed = dp.sign_packet(body, SEED)
        ok, reason = dp.verify_decision_packet(signed)
        if not ok:
            raise AssertionError("verify failed: %s" % reason)
        return True
    _expect_value("eff-11-legacy-byte-identical", _legacy_packet, True)

    # eff-12 — tampered labels break the signature (labels are
    # signature-covered, not a side channel).
    def _tamper_labels():
        if not _DP_OK:
            raise RuntimeError("decision_packet unavailable")
        import copy
        body = dp.build_decision_packet(
            **_minimal_kwargs(rule_labels={"allow-read": "p1.rule"}))
        signed = dp.sign_packet(body, SEED)
        forged = copy.deepcopy(signed)
        forged["rule_labels"]["value"]["allow-read"] = "p9.evil"
        ok, _reason = dp.verify_decision_packet(forged)
        return not ok
    _expect_value("eff-12-tampered-labels", _tamper_labels, True)

    # eff-13 — capsule_from_effect seals with the portable status
    # bound in; the capsule verifies.
    def _effect_capsule():
        from gov import action_capsule as ac
        cap = es.capsule_from_effect(
            {"attempt": {"action": "write_file",
                         "params_digest": "sha256:" + "a1" * 32}},
            "completed")
        body = ac.verify_capsule(cap)
        return body["effect"].get("portable_status") == "completed"
    _expect_value("eff-13-effect-capsule", _effect_capsule, True)

    # eff-14 — capsule_from_effect with an unknown portable status
    # refuses effect-status-invalid.
    _expect_code("eff-14-effect-bad-status",
                 lambda: es.capsule_from_effect(
                     {"attempt": {"action": "x"}}, "vaporized"),
                 "effect-status-invalid", es.EffectStatusError)

    # eff-15 — a refusal verdict + denied status: capsule seals with
    # the refusal code bound as capsule evidence.
    def _denied_capsule():
        from gov import action_capsule as ac
        cap = es.capsule_from_effect(
            {"attempt": {"action": "write_file",
                         "params_digest": "sha256:" + "a1" * 32}},
            "denied")
        body = ac.verify_capsule(cap)
        return (body["effect"].get("portable_status") == "denied"
                and body["effect"]["status"] == "refused")
    _expect_value("eff-15-denied-capsule", _denied_capsule, True)

    return list(_RESULTS)


_PROBE_NAMES = [
    "eff-01-pre-timeout", "eff-02-post-timeout",
    "eff-03-pre-cancel", "eff-04-post-cancel",
    "eff-05-ambiguous-refused", "eff-06-unknown-pre",
    "eff-07-terminals",
    "eff-08-malformed-bad-outcome", "eff-08-malformed-not-dict",
    "eff-08-malformed-missing-accept",
    "eff-09-labels-embed",
    "eff-10-labels-invalid-empty-key",
    "eff-10-labels-invalid-non-printable",
    "eff-10-labels-invalid-non-dict",
    "eff-10-labels-invalid-non-str-value",
    "eff-11-legacy-byte-identical", "eff-12-tampered-labels",
    "eff-13-effect-capsule", "eff-14-effect-bad-status",
    "eff-15-denied-capsule",
]


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_decision_packet.py",
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
    print("w225 effect probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-34s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-34s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
