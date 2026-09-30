#!/usr/bin/env python3
"""Wave-230 lane B: definition_sha256 — digest over the action type's
validation SEMANTICS (re-derived CAID -04 ``definition_sha256``
pattern; nothing copied).

A digest over {"action": "wire"} commits to nothing. Wave-228's
typed actions committed the type definition (fields); this lane
commits the validation SEMANTICS: the required field set, their
declared types, and the depth/count/length constraints. Two type
definitions with the same type_id but different semantics have
DIFFERENT definition_sha256; a drift between bind and verify
refuses ``action-semantics-drift``. The bound digest now commits to
{type_digest, definition_sha256, ...}: label -> type definition ->
validation semantics.

Seams under test:
* gov/typed_actions.py — ActionType.build(..., field_types=,
  max_depth=, max_values=, max_value_len=) computes
  ``definition_sha256`` over the canonical semantics body.
  bind_action enforces semantics: missing fields refuse with the
  exact reason ``missing_material_field:<name>``; type mismatches
  refuse ``action-material-type-mismatch``; nested depth refuses
  ``action-depth-exceeded``; leaf counts refuse
  ``action-value-count-exceeded``; oversized scalars refuse
  ``action-value-too-long``. bind_action_from_json detects
  duplicate object keys at any depth and refuses
  ``action-duplicate-key``. verify_typed_action pins the binding to
  the registry's definition_sha256 (drift refuses
  ``action-semantics-drift``); legacy bindings (no definition_sha256
  field) verify under the pre-semantics rule exactly as wave-228 —
  never widened.

Attack shapes: re-register the same type_id/version with a looser
schema between bind and verify (fewer required types, raised
max_depth); tamper the definition_sha256 inside a sealed binding;
smuggle a deeply nested payload past a shallow schema; duplicate a
JSON key to shadow a value; submit a legacy binding against a
semantics-hardened registry.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-229 HEAD
eb3ed254e5afb268dac2d46bdcca1f9e54f96b3b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (semantics absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g230b
  TMPDIR=/var/tmp/g230b ~/workspace/.gov-venv/bin/python evals/w230_defsha_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g230b-u \\
      ~/workspace/.gov-venv/bin/python evals/w230_defsha_probes.py
"""

import hashlib
import json
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
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _has_def_sha():
    """Feature probe: does this tree carry definition_sha256?"""
    if not HAVE_MODULE:
        return False
    try:
        t = _ta.ActionType.build("wire", 1, ["amount"])
        return isinstance(getattr(t, "definition_sha256", None), str)
    except Exception:  # noqa: BLE001
        return False


HAS_DEF_SHA = _has_def_sha()

PROBE_NAMES = [
    "ds-01-field-change-changes-defsha",
    "ds-02-declared-type-change-changes-defsha",
    "ds-03-semantics-drift-refused",
    "ds-04-exact-missing-field-reason",
    "ds-05-depth-exceeded-refused",
    "ds-06-value-count-exceeded-refused",
    "ds-07-duplicate-key-refused",
    "ds-08-canonicalization-stable",
    "ds-09-legacy-binding-still-verifies",
    "ds-10-bound-digest-commits-defsha",
    "ds-11-declared-type-mismatch-refused",
    "ds-12-value-too-long-refused",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _reason_of(fn):
    """The exception's exact closed reason string, or None."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "reason", None)
    return None


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _reg_wire(**kw):
    reg = _ta.TypeRegistry()
    reg.register(_ta.ActionType.build("wire", 1,
                                     ["amount", "recipient"], **kw))
    return reg


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.typed_actions absent on this tree")
        return results

    # ds-01: same type_id, different required fields -> different
    # definition_sha256.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        t1 = _ta.ActionType.build("wire", 1, ["amount", "recipient"])
        t2 = _ta.ActionType.build("wire", 1, ["amount"])
        ok = (t1.definition_sha256 != t2.definition_sha256
              and len(t1.definition_sha256) == 64
              and len(t2.definition_sha256) == 64)
        rec("ds-01-field-change-changes-defsha",
            "HELD" if ok else "BREAK",
            "field-set change must change definition_sha256")
    except _Gap:
        rec("ds-01-field-change-changes-defsha", "GAP",
            "definition_sha256 absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-01-field-change-changes-defsha", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-02: same fields, different DECLARED TYPES -> different
    # definition_sha256 (digest covers semantics, not just labels).
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        t1 = _ta.ActionType.build("wire", 1, ["amount"],
                                  field_types={"amount": "int"})
        t2 = _ta.ActionType.build("wire", 1, ["amount"],
                                  field_types={"amount": "str"})
        ok = t1.definition_sha256 != t2.definition_sha256
        rec("ds-02-declared-type-change-changes-defsha",
            "HELD" if ok else "BREAK",
            "declared-type change must change definition_sha256")
    except _Gap:
        rec("ds-02-declared-type-change-changes-defsha", "GAP",
            "definition_sha256 absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-02-declared-type-change-changes-defsha", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-03: same type_id/version, looser semantics re-registered
    # between bind and verify -> action-semantics-drift.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        binder = _ta.TypeRegistry()
        binder.register(_ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "int"}, max_depth=1))
        bound = _ta.bind_action("wire", 1, {"amount": 100}, binder)
        verifier = _ta.TypeRegistry()
        verifier.register(_ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "str"}, max_depth=9))
        ok = _refuses(
            lambda: _ta.verify_typed_action(bound, verifier),
            "action-semantics-drift")
        rec("ds-03-semantics-drift-refused", "HELD" if ok else "BREAK",
            "re-registered looser semantics must refuse "
            "action-semantics-drift")
    except _Gap:
        rec("ds-03-semantics-drift-refused", "GAP",
            "definition_sha256 absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-03-semantics-drift-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-04: the missing-field reason is the EXACT closed string
    # "missing_material_field:<name>", byte-for-byte.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _reg_wire()
        reason = _reason_of(
            lambda: _ta.bind_action("wire", 1, {"amount": 100}, reg))
        ok = reason == "missing_material_field:recipient"
        rec("ds-04-exact-missing-field-reason",
            "HELD" if ok else "BREAK",
            "reason must be exactly "
            "'missing_material_field:recipient', got %r" % (reason,))
    except _Gap:
        rec("ds-04-exact-missing-field-reason", "GAP",
            "closed reason strings absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-04-exact-missing-field-reason", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-05: nested payload deeper than max_depth refuses
    # action-depth-exceeded.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _reg_wire(max_depth=1)
        ok = _refuses(
            lambda: _ta.bind_action(
                "wire", 1,
                {"amount": 100, "recipient": {"nick": {"x": "a"}}},
                reg),
            "action-depth-exceeded")
        rec("ds-05-depth-exceeded-refused", "HELD" if ok else "BREAK",
            "payload nested deeper than max_depth must refuse "
            "action-depth-exceeded")
    except _Gap:
        rec("ds-05-depth-exceeded-refused", "GAP",
            "semantics constraints absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-05-depth-exceeded-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-06: more leaf values than max_values refuses
    # action-value-count-exceeded.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _ta.TypeRegistry()
        reg.register(_ta.ActionType.build(
            "wire", 1, ["a", "b", "c"], max_values=2))
        ok = _refuses(
            lambda: _ta.bind_action(
                "wire", 1, {"a": 1, "b": 2, "c": 3}, reg),
            "action-value-count-exceeded")
        rec("ds-06-value-count-exceeded-refused",
            "HELD" if ok else "BREAK",
            "leaf count above max_values must refuse "
            "action-value-count-exceeded")
    except _Gap:
        rec("ds-06-value-count-exceeded-refused", "GAP",
            "semantics constraints absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-06-value-count-exceeded-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-07: a duplicate JSON object key at any depth refuses
    # action-duplicate-key (the shadowed value can never smuggle).
    try:
        if not HAS_DEF_SHA or not hasattr(
                _ta, "bind_action_from_json"):
            raise _Gap()
        reg = _reg_wire()
        raw = b'{"amount": 100, "recipient": "alice", "amount": 7}'
        ok = _refuses(
            lambda: _ta.bind_action_from_json("wire", 1, raw, reg),
            "action-duplicate-key")
        nested = (b'{"amount": 100, "recipient": {"nick": "a", '
                  b'"nick": "b"}}')
        ok = ok and _refuses(
            lambda: _ta.bind_action_from_json("wire", 1, nested, reg),
            "action-duplicate-key")
        rec("ds-07-duplicate-key-refused", "HELD" if ok else "BREAK",
            "duplicate object keys (top-level and nested) must "
            "refuse action-duplicate-key")
    except _Gap:
        rec("ds-07-duplicate-key-refused", "GAP",
            "JSON duplicate-key seam absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-07-duplicate-key-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-08: canonicalization is stable — field order and
    # field_types key order do not move definition_sha256.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        t1 = _ta.ActionType.build(
            "wire", 1, ["amount", "recipient"],
            field_types={"amount": "int", "recipient": "str"})
        t2 = _ta.ActionType.build(
            "wire", 1, ["recipient", "amount"],
            field_types={"recipient": "str", "amount": "int"})
        ok = t1.definition_sha256 == t2.definition_sha256
        rec("ds-08-canonicalization-stable", "HELD" if ok else "BREAK",
            "definition_sha256 must be order-independent")
    except _Gap:
        rec("ds-08-canonicalization-stable", "GAP",
            "definition_sha256 absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-08-canonicalization-stable", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-09: a LEGACY binding (pre-semantics bound digest, no
    # definition_sha256 field) still verifies under its original
    # type digest — the semantics pinning never widens old
    # bindings.
    try:
        reg = _reg_wire()
        definition = reg.lookup("wire", 1)
        material = {"amount": 100, "recipient": "alice"}
        legacy_body = {"type_id": "wire", "version": 1,
                       "type_digest": definition.type_digest,
                       "material": material}
        legacy_bound = dict(legacy_body)
        legacy_bound["bound_digest"] = hashlib.sha256(
            _canon(legacy_body)).hexdigest()
        legacy_bound["v"] = 1
        ok = _ta.verify_typed_action(legacy_bound, reg) is True
        rec("ds-09-legacy-binding-still-verifies",
            "HELD" if ok else "BREAK",
            "legacy binding must verify under the pre-semantics rule")
    except Exception as exc:  # noqa: BLE001
        rec("ds-09-legacy-binding-still-verifies", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-10: the bound digest commits to definition_sha256 —
    # swapping it inside a sealed binding refuses
    # action-semantics-drift (pinning), and material tampering
    # still refuses action-binding-tampered.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _reg_wire()
        bound = _ta.bind_action(
            "wire", 1, {"amount": 100, "recipient": "alice"}, reg)
        swapped = dict(bound)
        swapped["definition_sha256"] = "0" * 64
        drift_ok = _refuses(
            lambda: _ta.verify_typed_action(swapped, reg),
            "action-semantics-drift")
        tampered = dict(bound)
        tampered["material"] = dict(bound["material"])
        tampered["material"]["amount"] = 999999
        tamper_ok = _refuses(
            lambda: _ta.verify_typed_action(tampered, reg),
            "action-binding-tampered")
        ok = drift_ok and tamper_ok
        rec("ds-10-bound-digest-commits-defsha",
            "HELD" if ok else "BREAK",
            "bound digest must pin definition_sha256; tampering "
            "still detected")
    except _Gap:
        rec("ds-10-bound-digest-commits-defsha", "GAP",
            "definition_sha256 absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-10-bound-digest-commits-defsha", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-11: a declared-type mismatch refuses
    # action-material-type-mismatch (strict: bool is not int).
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _ta.TypeRegistry()
        reg.register(_ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "int"}))
        ok = _refuses(
            lambda: _ta.bind_action("wire", 1, {"amount": "100"}, reg),
            "action-material-type-mismatch")
        ok = ok and _refuses(
            lambda: _ta.bind_action("wire", 1, {"amount": True}, reg),
            "action-material-type-mismatch")
        rec("ds-11-declared-type-mismatch-refused",
            "HELD" if ok else "BREAK",
            "declared-type violations must refuse "
            "action-material-type-mismatch")
    except _Gap:
        rec("ds-11-declared-type-mismatch-refused", "GAP",
            "declared types absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-11-declared-type-mismatch-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ds-12: an oversized scalar refuses action-value-too-long.
    try:
        if not HAS_DEF_SHA:
            raise _Gap()
        reg = _reg_wire(max_value_len=4)
        ok = _refuses(
            lambda: _ta.bind_action(
                "wire", 1, {"amount": 100, "recipient": "alice-long"},
                reg),
            "action-value-too-long")
        rec("ds-12-value-too-long-refused",
            "HELD" if ok else "BREAK",
            "scalar above max_value_len must refuse "
            "action-value-too-long")
    except _Gap:
        rec("ds-12-value-too-long-refused", "GAP",
            "length constraints absent on this tree")
    except Exception as exc:  # noqa: BLE001
        rec("ds-12-value-too-long-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


class _Gap(Exception):
    """Control flow: the probed feature is absent on this tree."""


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_typed_actions.py",
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
    print("w230 defsha probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
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
