"""Wave-280 lane-4 battery: the adversarial battery language itself.

Break-first evidence for the promptfoo-adapted plugin x strategy x grader
vocabulary + generate -> commit -> eval discipline:

  (a) closed vocabularies refuse fail-closed (unknown plugin / strategy /
      grader at manifest load AND at generate time);
  (b) malformed manifests refuse (bad format, duplicate probe ids, missing
      fields, bad expected vocab);
  (c) an unannotated probe module cannot generate a manifest (the shared
      vocabulary is the point -- no unlabeled probes in a committed suite);
  (d) the w279_redteam migration is behavior-identical: eval replay of the
      committed manifest reproduces the original battery's verdicts;
  (e) eval emits machine-readable rows (probe_id, plugin_id, strategy_id,
      grading_result) and seals an evidence envelope whose samples carry the
      lang metadata and verify under tools/envelope-verify;
  (f) eval replay is deterministic (two runs, identical rows digest);
  (g) the grader taxonomy works beyond held-vs-expected (replay-identical,
      note-matches) and unknown graders refuse.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g280-batterylang && TMPDIR=/var/tmp/g280-batterylang \\
    ~/workspace/.gov-venv/bin/python evals/w280_batterylang_probes.py
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import types

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

from gov import battery_lang as bl  # noqa: E402
from gov import battery_envelope as be  # noqa: E402

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

_TMP = os.environ.get("TMPDIR") or "/var/tmp"
os.makedirs(_TMP, exist_ok=True)


def _held(name, note):
    return ("HELD", "%s: %s" % (name, note))


def _broken(name, detail):
    return ("BREAK", "%s: %s" % (name, detail))


def _run(pid, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        return (pid, "ERROR", repr(exc)[:200], "ERROR")
    return (pid, verdict, note, "OK")


def _fixture_module():
    """Synthetic probe module exercising all three graders."""
    def _ok():
        return ("HELD", "fixture ok")
    def _brk():
        return ("BREAK", "fixture break")
    mod = types.ModuleType("w280_lang_fixture")
    mod.PROBES = [
        ("fix-held", "HELD", _ok),
        ("fix-break", "BREAK", _brk),
        ("fix-replay", "HELD", _ok),
        ("fix-note", "HELD", _ok),
    ]
    mod.PROBE_METADATA = {
        "fix-held": ("authz-bypass", "direct", "held-vs-expected"),
        "fix-break": ("authz-bypass", "direct", "held-vs-expected"),
        "fix-replay": ("supply-chain", "byte-compare", "replay-identical"),
        "fix-note": ("policy-drift", "version-drift", "note-matches"),
    }
    return mod


# ---------------------------------------------------------------------------
# (a) closed vocabularies refuse fail-closed.
# ---------------------------------------------------------------------------

def lang_unknown_plugin_refused():
    bad = {"format": bl.MANIFEST_FORMAT, "battery": "x",
           "battery_version": "1", "module": "m",
           "probes": [{"probe_id": "p", "plugin": "not-a-plugin",
                       "strategy": "direct", "grader": "held-vs-expected",
                       "expected": "HELD"}]}
    path = os.path.join(_TMP, "w280-bad-plugin.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bad, fh)
    try:
        bl.load_manifest(path)
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-unknown-plugin":
            return _held("unknown-plugin", "refused %s" % exc.reason)
        return _broken("unknown-plugin", "wrong reason %r" % exc.reason)
    return _broken("unknown-plugin", "manifest with bogus plugin loaded")


def lang_unknown_strategy_refused():
    mod = _fixture_module()
    mod.PROBE_METADATA["fix-held"] = ("authz-bypass", "no-such-strategy",
                                      "held-vs-expected")
    try:
        bl.generate_manifest(mod, "x", "1")
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-unknown-strategy":
            return _held("unknown-strategy", "refused %s" % exc.reason)
        return _broken("unknown-strategy", "wrong reason %r" % exc.reason)
    return _broken("unknown-strategy", "bogus strategy generated")


def lang_unknown_grader_refused():
    try:
        bl.grade_probe("llm-rubric", "HELD", {"verdict": "HELD"})
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-unknown-grader":
            return _held("unknown-grader", "refused %s" % exc.reason)
        return _broken("unknown-grader", "wrong reason %r" % exc.reason)
    return _broken("unknown-grader", "bogus grader graded")


# ---------------------------------------------------------------------------
# (b) malformed manifests refuse.
# ---------------------------------------------------------------------------

def _write_tmp(name, obj):
    path = os.path.join(_TMP, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


def lang_malformed_format_refused():
    path = _write_tmp("w280-bad-format.json", {"format": "promptfoo/1"})
    try:
        bl.load_manifest(path)
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-bad-manifest":
            return _held("bad-format", "refused %s" % exc.reason)
        return _broken("bad-format", "wrong reason %r" % exc.reason)
    return _broken("bad-format", "foreign format loaded")


def lang_duplicate_probe_id_refused():
    entry = {"probe_id": "dup", "plugin": "authz-bypass",
             "strategy": "direct", "grader": "held-vs-expected",
             "expected": "HELD"}
    path = _write_tmp("w280-dup.json",
                      {"format": bl.MANIFEST_FORMAT, "battery": "x",
                       "battery_version": "1", "module": "m",
                       "probes": [entry, dict(entry)]})
    try:
        bl.load_manifest(path)
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-bad-manifest":
            return _held("dup-probe", "refused %s" % exc.reason)
        return _broken("dup-probe", "wrong reason %r" % exc.reason)
    return _broken("dup-probe", "duplicate probe ids loaded")


def lang_bad_expected_refused():
    path = _write_tmp("w280-bad-exp.json",
                      {"format": bl.MANIFEST_FORMAT, "battery": "x",
                       "battery_version": "1", "module": "m",
                       "probes": [{"probe_id": "p", "plugin": "authz-bypass",
                                   "strategy": "direct",
                                   "grader": "held-vs-expected",
                                   "expected": "MAYBE"}]})
    try:
        bl.load_manifest(path)
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-bad-probe":
            return _held("bad-expected", "refused %s" % exc.reason)
        return _broken("bad-expected", "wrong reason %r" % exc.reason)
    return _broken("bad-expected", "bad expected vocab loaded")


# ---------------------------------------------------------------------------
# (c) unannotated modules cannot generate.
# ---------------------------------------------------------------------------

def lang_unannotated_module_refused():
    def _ok():
        return ("HELD", "ok")
    mod = types.ModuleType("w280_unannotated")
    mod.PROBES = [("p", "HELD", _ok)]
    try:
        bl.generate_manifest(mod, "x", "1")
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-no-metadata":
            return _held("unannotated", "refused %s" % exc.reason)
        return _broken("unannotated", "wrong reason %r" % exc.reason)
    return _broken("unannotated", "unlabeled module generated")


def lang_partially_annotated_refused():
    def _ok():
        return ("HELD", "ok")
    mod = types.ModuleType("w280_partial")
    mod.PROBES = [("p1", "HELD", _ok), ("p2", "HELD", _ok)]
    mod.PROBE_METADATA = {"p1": ("authz-bypass", "direct",
                                 "held-vs-expected")}
    try:
        bl.generate_manifest(mod, "x", "1")
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-unannotated":
            return _held("partial", "refused %s" % exc.reason)
        return _broken("partial", "wrong reason %r" % exc.reason)
    return _broken("partial", "partially labeled module generated")


# ---------------------------------------------------------------------------
# (d) w279_redteam migration is behavior-identical.
# ---------------------------------------------------------------------------

_W279_PATH = os.path.join(REPO, "evals", "w279_redteam_probes.py")
_MANIFEST_PATH = os.path.join(REPO, "evals", "batteries",
                               "w279_redteam.battery.json")


def _load_w279_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("w279_redteam_probes",
                                                  _W279_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["w279_redteam_probes"] = mod
    spec.loader.exec_module(mod)
    return mod


def lang_migration_behavior_identical():
    """Eval replay of the committed manifest reproduces the original
    battery's verdicts exactly (the migration proves itself)."""
    if not os.path.exists(_MANIFEST_PATH):
        return _broken("migration", "manifest not generated yet -- run "
                                    "tools/battery-generate first")
    mod = _load_w279_module()
    original = {}
    for pid, expected, fn in mod.PROBES:
        try:
            verdict, _note = fn()
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
        original[pid] = verdict
    summary = bl.eval_manifest(_MANIFEST_PATH)
    replayed = {r["probe_id"]: r["verdict"] for r in summary["rows"]}
    drift = [pid for pid in original
             if replayed.get(pid) != original[pid]]
    if drift:
        return _broken("migration",
                       "verdict drift on %s" % ", ".join(sorted(drift)))
    if summary["summary"]["FAIL"] or summary["summary"]["ERROR"]:
        return _broken("migration", "graders failed: %s"
                       % summary["summary"])
    return _held("migration",
                 "%d probes replayed with identical verdicts"
                 % len(original))


# ---------------------------------------------------------------------------
# (e) rows are machine-readable; envelope verifies with lang metadata.
# ---------------------------------------------------------------------------

def lang_rows_machine_readable():
    if not os.path.exists(_MANIFEST_PATH):
        return _broken("rows", "manifest missing")
    rows_path = os.path.join(_TMP, "w280-rows.jsonl")
    summary = bl.eval_manifest(_MANIFEST_PATH, rows_path=rows_path)
    with open(rows_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    rows = [json.loads(l) for l in lines]
    if len(rows) != len(summary["rows"]):
        return _broken("rows", "row count mismatch")
    for row in rows:
        for key in ("probe_id", "plugin_id", "strategy_id",
                    "grading_result"):
            if not row.get(key) or not isinstance(row.get(key), str):
                return _broken("rows",
                               "row %r missing machine-readable %r"
                               % (row.get("probe_id"), key))
        if row["plugin_id"] not in bl.PLUGINS:
            return _broken("rows", "row carries unregistered plugin %r"
                           % row["plugin_id"])
    return _held("rows", "%d rows all carry (plugin_id, strategy_id, "
                         "grading_result)" % len(rows))


def lang_envelope_verifies_with_lang_metadata():
    """Sealed rows verify under the standalone envelope verifier AND the
    lang metadata survives the round trip."""
    if not os.path.exists(_MANIFEST_PATH):
        return _broken("envelope", "manifest missing")
    env_path = os.path.join(_TMP, "w280-envelope.json")
    bl.eval_manifest(_MANIFEST_PATH, envelope_path=env_path)
    with open(env_path, encoding="utf-8") as fh:
        env = json.load(fh)
    try:
        be.verify_envelope(env)
    except be.BatteryEnvelopeError as exc:
        return _broken("envelope", "verify_envelope refused: %s" % exc)
    import subprocess
    p = subprocess.run([sys.executable,
                        os.path.join(REPO, "tools", "envelope-verify"),
                        env_path], capture_output=True, text=True,
                       timeout=120, cwd=REPO)
    if p.returncode != 0:
        return _broken("envelope",
                       "standalone verifier refused: %s"
                       % (p.stdout + p.stderr)[:160])
    lang_rows = [s for s in env["samples"] if "lang" in s]
    if not lang_rows:
        return _broken("envelope", "no sample carries lang metadata")
    bad = [s for s in lang_rows
           if s["lang"].get("plugin_id") not in bl.PLUGINS]
    if bad:
        return _broken("envelope", "lang metadata unregistered")
    # RESIDUAL probes are rows-file-only by vocabulary design.
    residual = [s for s in env["samples"]
                if s["expected"] == "RESIDUAL"]
    if residual:
        return _broken("envelope",
                       "RESIDUAL sample sealed -- vocabulary violation")
    return _held("envelope", "%d samples carry lang metadata, standalone "
                             "verifier green" % len(lang_rows))


# ---------------------------------------------------------------------------
# (f) eval replay is deterministic.
# ---------------------------------------------------------------------------

def lang_replay_deterministic():
    if not os.path.exists(_MANIFEST_PATH):
        return _broken("determinism", "manifest missing")
    digests = []
    for i in range(2):
        rows_path = os.path.join(_TMP, "w280-det-%d.jsonl" % i)
        bl.eval_manifest(_MANIFEST_PATH, rows_path=rows_path)
        with open(rows_path, "rb") as fh:
            digests.append(hashlib.sha256(fh.read()).hexdigest())
    if digests[0] != digests[1]:
        return _broken("determinism", "two eval runs differ")
    return _held("determinism", "two eval runs byte-identical (%s...)"
                 % digests[0][:12])


# ---------------------------------------------------------------------------
# (g) grader taxonomy beyond held-vs-expected.
# ---------------------------------------------------------------------------

def lang_graders_work():
    mod = _fixture_module()
    # replay-identical passes on a deterministic probe.
    g, _d = bl.grade_probe("replay-identical", "HELD",
                           {"run1": {"verdict": "HELD", "note": "x"},
                            "run2": {"verdict": "HELD", "note": "x"}})
    if g != "PASS":
        return _broken("graders", "replay-identical false negative")
    # replay-identical catches a nondeterministic probe.
    g, _d = bl.grade_probe("replay-identical", "HELD",
                           {"run1": {"verdict": "HELD", "note": "x"},
                            "run2": {"verdict": "BREAK", "note": "y"}})
    if g != "PASS":
        return ("HELD", "graders: replay-identical caught nondeterminism")
    return _broken("graders", "replay-identical missed a drift")


def lang_note_matches_grader():
    g, _d = bl.grade_probe("note-matches", "HELD",
                           {"verdict": "HELD", "note": "fixture ok"},
                           {"pattern": r"^fixture \w+$"})
    if g != "PASS":
        return _broken("note-matches", "positive case failed")
    g, _d = bl.grade_probe("note-matches", "HELD",
                           {"verdict": "HELD", "note": "fixture ok"},
                           {"pattern": r"^tampered"})
    if g == "PASS":
        return _broken("note-matches", "negative case passed")
    g, _d = bl.grade_probe("note-matches", "HELD",
                           {"verdict": "HELD", "note": "x"}, {})
    if g != "ERROR":
        return _broken("note-matches", "missing pattern did not error")
    return _held("note-matches", "positive/negative/config all correct")


def lang_expected_drift_refused():
    """A module whose PROBES expectations drifted from the committed
    manifest refuses at eval (the manifest is the contract)."""
    if not os.path.exists(_MANIFEST_PATH):
        return _broken("drift", "manifest missing")
    manifest = bl.load_manifest(_MANIFEST_PATH)
    mod = _load_w279_module()
    first_pid = manifest["probes"][0]["probe_id"]
    orig = list(mod.PROBES)
    flipped = "BREAK" if orig[0][1] == "HELD" else "HELD"
    mod.PROBES = [(first_pid, flipped, orig[0][2])] + orig[1:]
    try:
        bl.eval_manifest(_MANIFEST_PATH)
    except bl.BatteryLanguageError as exc:
        if exc.reason == "battery-lang-expected-drift":
            return _held("drift", "refused %s" % exc.reason)
        return _broken("drift", "wrong reason %r" % exc.reason)
    finally:
        mod.PROBES = orig
    return _broken("drift", "expected drift evaled silently")


PROBES = [
    ("lang-unknown-plugin-refused", "HELD", lang_unknown_plugin_refused),
    ("lang-unknown-strategy-refused", "HELD", lang_unknown_strategy_refused),
    ("lang-unknown-grader-refused", "HELD", lang_unknown_grader_refused),
    ("lang-malformed-format-refused", "HELD", lang_malformed_format_refused),
    ("lang-duplicate-probe-id-refused", "HELD",
     lang_duplicate_probe_id_refused),
    ("lang-bad-expected-refused", "HELD", lang_bad_expected_refused),
    ("lang-unannotated-module-refused", "HELD",
     lang_unannotated_module_refused),
    ("lang-partially-annotated-refused", "HELD",
     lang_partially_annotated_refused),
    ("lang-migration-behavior-identical", "HELD",
     lang_migration_behavior_identical),
    ("lang-rows-machine-readable", "HELD", lang_rows_machine_readable),
    ("lang-envelope-verifies-with-lang-metadata", "HELD",
     lang_envelope_verifies_with_lang_metadata),
    ("lang-replay-deterministic", "HELD", lang_replay_deterministic),
    ("lang-graders-work", "HELD", lang_graders_work),
    ("lang-note-matches-grader", "HELD", lang_note_matches_grader),
    ("lang-expected-drift-refused", "HELD", lang_expected_drift_refused),
]


# ---------------------------------------------------------------------------
# Depth-1 green checks (wave-28 lesson: GOV_SKIP_GREEN honored).
# ---------------------------------------------------------------------------

def green_check():
    notes = []
    if SKIP_GREEN:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1: nested green check skipped")]
    import subprocess
    neighbors = ["evals/w279_redteam_probes.py",
                 "evals/w278_envelope_probes.py"]
    for rel in neighbors:
        path = os.path.join(REPO, rel)
        tmpd = tempfile.mkdtemp(prefix="g280-green-", dir=_TMP)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run([sys.executable, path], env=env,
                               capture_output=True, text=True, timeout=900,
                               cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            notes.append((rel, "ERROR", repr(exc)[:120]))
            continue
        tail = (p.stdout or "").strip().splitlines()
        last = tail[-1] if tail else ""
        bad = ("MISMATCH" in last) or p.returncode != 0
        notes.append((rel, "RED" if bad else "GREEN", last[:120]))
    return notes


def main():
    print("wave-280 battery-language battery: %d probes" % len(PROBES))
    results = []
    for pid, expected, fn in PROBES:
        rid, verdict, note, status = _run(pid, fn)
        ok = (verdict == expected)
        results.append((rid, verdict, note,
                        "OK" if ok else "MISMATCH(expected %s)" % expected))
        print("[%s] %s: %s" % (verdict, rid, note[:160]))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in green_check():
        print("[%s] %s: %s" % (verdict, name, note[:160]))
    held = sum(1 for r in results if r[1] == "HELD")
    errs = sum(1 for r in results if r[1] == "ERROR")
    mism = sum(1 for r in results if r[3].startswith("MISMATCH"))
    print("summary: %d HELD / %d ERROR / %d MISMATCH"
          % (held, errs, mism))
    return 1 if (mism or errs) else 0


if __name__ == "__main__":
    sys.exit(main())
