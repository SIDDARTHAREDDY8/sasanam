#!/usr/bin/env python3
"""Wave-228 lane B: typed actions with required material fields, digest
over the type definition.

STEAL (re-derived prose; nothing copied) of the CAID -04 pattern: a
typed action binds its material to a type DEFINITION whose digest is
committed, so the commitment covers WHAT the action means. A digest
over {"action": "wire"} commits to nothing — the type digest closes
that gap.

Seams under test:
* gov/typed_actions.py — TypeRegistry.register(ActionType): unknown
  or empty definition fields refuse at build time; bind_action
  refuses ``action-type-unknown`` for unregistered types and
  ``action-material-missing`` when any required field is absent; the
  bound digest commits to {type_digest, type_id, version, material}.
  verify_typed_action re-derives the type digest from the verifier's
  definition and refuses ``action-type-drift`` when it differs from
  what the binding commits to (type-substitution attack fails
  closed); tampered bindings refuse ``action-binding-tampered``; a
  label-only {"action": "wire"} has no type and refuses
  ``action-type-unknown``. Capsule composition: bind_to_capsule seals
  a NEW action capsule with the typed binding digest-linked in;
  verify_capsule_typed_action replays the capsule and the binding
  (missing block refuses ``typed-action-not-bound``).

Attack shapes: omit a required material field; bind an unknown
type; substitute the type definition between bind and verify (a
permissive re-definition with fewer required fields); tamper the
bound material after sealing; present a label-only action to typed
verification; strip the typed block from a composed capsule.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-227 HEAD
e42637b61e5c62c7289445e70c8e730ebfe8f4b3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g228b
  TMPDIR=/var/tmp/g228b ~/workspace/.gov-venv/bin/python evals/w228_typed_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g228b-u \\
      ~/workspace/.gov-venv/bin/python evals/w228_typed_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import typed_actions as _ta
    from gov import action_capsule as _cap
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

PROBE_NAMES = [
    "ta-01-valid-bind-verifies",
    "ta-02-missing-material-refused",
    "ta-03-unknown-type-refused",
    "ta-04-substituted-definition-drift",
    "ta-05-label-only-cannot-verify",
    "ta-06-version-bump-changes-digest",
    "ta-07-tampered-binding-refused",
    "ta-08-capsule-composition",
    "ta-09-capsule-without-typed-block-refused",
    "ta-10-extra-material-committed",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _wire_registry(required=("amount", "recipient")):
    reg = _ta.TypeRegistry()
    reg.register(_ta.ActionType.build("wire", 1, list(required)))
    return reg


def _sealed_plain_capsule():
    return _cap.seal_capsule({
        "attempt": {"action": "wire", "initiator": "agent-1"},
        "effect": {"status": "admitted",
                   "evidence": "executor-receipt-001"},
    })


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.typed_actions absent on this tree")
        return results

    # ta-01: valid bind verifies; digest is deterministic.
    try:
        reg = _wire_registry()
        b1 = _ta.bind_action("wire", 1,
                             {"amount": 100, "recipient": "alice"}, reg)
        b2 = _ta.bind_action("wire", 1,
                             {"amount": 100, "recipient": "alice"}, reg)
        ok = (_ta.verify_typed_action(b1, reg)
              and b1["bound_digest"] == b2["bound_digest"]
              and b1["type_id"] == "wire" and b1["version"] == 1)
        rec("ta-01-valid-bind-verifies", "HELD" if ok else "BREAK",
            "valid typed action must bind deterministically and verify")
    except Exception as exc:  # noqa: BLE001
        rec("ta-01-valid-bind-verifies", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-02: missing required material refuses action-material-missing.
    try:
        reg = _wire_registry()
        ok = _refuses(
            lambda: _ta.bind_action("wire", 1, {"amount": 100}, reg),
            "action-material-missing")
        rec("ta-02-missing-material-refused", "HELD" if ok else "BREAK",
            "omitted 'recipient' must refuse action-material-missing")
    except Exception as exc:  # noqa: BLE001
        rec("ta-02-missing-material-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-03: unknown type refuses action-type-unknown.
    try:
        reg = _wire_registry()
        ok = _refuses(
            lambda: _ta.bind_action("revoke", 1, {"target": "x"}, reg),
            "action-type-unknown")
        rec("ta-03-unknown-type-refused", "HELD" if ok else "BREAK",
            "unregistered type must refuse action-type-unknown")
    except Exception as exc:  # noqa: BLE001
        rec("ta-03-unknown-type-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-04: substituting the type definition between bind and verify
    # (permissive re-definition with fewer required fields) refuses
    # action-type-drift — the binding commits to the OLD definition.
    try:
        binder = _wire_registry(("amount", "recipient"))
        bound = _ta.bind_action("wire", 1,
                                {"amount": 100, "recipient": "alice"},
                                binder)
        verifier = _wire_registry(("amount",))  # attacker-swapped
        ok = _refuses(
            lambda: _ta.verify_typed_action(bound, verifier),
            "action-type-drift")
        rec("ta-04-substituted-definition-drift",
            "HELD" if ok else "BREAK",
            "permissive re-definition must refuse action-type-drift")
    except Exception as exc:  # noqa: BLE001
        rec("ta-04-substituted-definition-drift", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-05: a label-only action {"action": "wire"} has no type and
    # cannot pass typed verification.
    try:
        reg = _wire_registry()
        ok = _refuses(
            lambda: _ta.verify_typed_action({"action": "wire"}, reg),
            "action-type-unknown")
        rec("ta-05-label-only-cannot-verify", "HELD" if ok else "BREAK",
            "label-only action must refuse action-type-unknown")
    except Exception as exc:  # noqa: BLE001
        rec("ta-05-label-only-cannot-verify", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-06: a version bump changes the type digest.
    try:
        reg = _ta.TypeRegistry()
        d1 = reg.register(_ta.ActionType.build("wire", 1,
                                               ["amount", "recipient"]))
        d2 = reg.register(_ta.ActionType.build("wire", 2,
                                               ["amount", "recipient"]))
        ok = (d1["type_digest"] != d2["type_digest"])
        rec("ta-06-version-bump-changes-digest",
            "HELD" if ok else "BREAK",
            "v1 and v2 definitions must have different type digests")
    except Exception as exc:  # noqa: BLE001
        rec("ta-06-version-bump-changes-digest", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-07: tampering with the bound material after sealing is
    # detected (binding recomputed, never asserted).
    try:
        reg = _wire_registry()
        bound = _ta.bind_action("wire", 1,
                                {"amount": 100, "recipient": "alice"},
                                reg)
        tampered = dict(bound)
        tampered["material"] = dict(bound["material"])
        tampered["material"]["amount"] = 999999
        ok = _refuses(
            lambda: _ta.verify_typed_action(tampered, reg),
            "action-binding-tampered")
        rec("ta-07-tampered-binding-refused", "HELD" if ok else "BREAK",
            "mutated material must refuse action-binding-tampered")
    except Exception as exc:  # noqa: BLE001
        rec("ta-07-tampered-binding-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-08: capsule composition — a typed binding seals into a NEW
    # action capsule as digest-linked evidence; the composed capsule
    # verifies against the registry.
    try:
        reg = _wire_registry()
        bound = _ta.bind_action("wire", 1,
                                {"amount": 100, "recipient": "alice"},
                                reg)
        plain = _sealed_plain_capsule()
        composed = _ta.bind_to_capsule(bound, plain)
        _cap.verify_capsule(composed)  # the capsule seam itself replays
        checked = _ta.verify_capsule_typed_action(composed, reg)
        ok = (checked["bound_digest"] == bound["bound_digest"])
        rec("ta-08-capsule-composition", "HELD" if ok else "BREAK",
            "composed capsule must verify at both seams")
    except Exception as exc:  # noqa: BLE001
        rec("ta-08-capsule-composition", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-09: a capsule with no typed block refuses
    # typed-action-not-bound.
    try:
        reg = _wire_registry()
        plain = _sealed_plain_capsule()
        ok = _refuses(
            lambda: _ta.verify_capsule_typed_action(plain, reg),
            "typed-action-not-bound")
        rec("ta-09-capsule-without-typed-block-refused",
            "HELD" if ok else "BREAK",
            "plain capsule must refuse typed-action-not-bound")
    except Exception as exc:  # noqa: BLE001
        rec("ta-09-capsule-without-typed-block-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ta-10: extra material fields beyond the required set are
    # committed by the digest — silently dropping them fails.
    try:
        reg = _wire_registry()
        full = _ta.bind_action("wire", 1,
                               {"amount": 100, "recipient": "alice",
                                "memo": "invoice-42"}, reg)
        trimmed = _ta.bind_action("wire", 1,
                                   {"amount": 100, "recipient": "alice"},
                                   reg)
        ok = (full["bound_digest"] != trimmed["bound_digest"]
              and _ta.verify_typed_action(full, reg))
        rec("ta-10-extra-material-committed",
            "HELD" if ok else "BREAK",
            "extra fields must be committed by the bound digest")
    except Exception as exc:  # noqa: BLE001
        rec("ta-10-extra-material-committed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_action_capsule.py",
                 "tests/test_effect_status.py",
                 "tests/test_key_identity.py",
                 "tests/test_escalation_svr.py",
                 "tests/test_receipt_pairs.py"):
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
    print("w228 typed-actions probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
