"""Wave-242 Lane E / W242-8: AEE checker parity rebaseline probes.

Two evaluation lanes share this file's first half; the second half (W242-10)
is a pure evidence-gathering evaluation recorded in REPORT.md.

W242-8 honest outcome, stated up front: the Sasanam tree contains NO
from-spec AEE checker of its own (only adjacent in-toto/DSSE envelope infra),
so "run our checker against the suiteRevision-27 corpus and report the
blind-equivalent score" has no Sasanam checker to run. The falsifiable
precondition probe below records exactly that, instead of a fabricated
parity number. What CAN be probed:

  1. reference_rebaseline: the parity reference record itself --
     suiteRevision 27 = 272/272 against the unchanged (frozen) checker build,
     pre-registered (PIN-rev27-RUN.md) before the run, run labeled directed,
     corpus pinned to spec 0dbe10bc, and the head revision's refusal-set
     rule exercised by no vector (the open compliance question).
  2. refusal_set_authored: a directed, authored sealed-record vector where
     exactly one clean-row conjunct fails; the reference checker's refusal
     must name ONLY that conjunct (the head rule: a verifier MUST NOT name
     a conjunct it did not reach). Authored BEFORE reading the head spec
     text; labeled directed regardless.
  3. refusal_set_corpus_sweep: every corpus reject vector whose refusal is
     a sealed clean-row-conjunct refusal gets its named set re-derived
     independently from the record bytes; named must equal evaluated.

Reference locations come from W242_AEE_REF (default /tmp/aee-ref) and
W242_AEE_CORPUS (default /tmp/aee-conformance). Missing references are a
SKIP with reason, never a fabricated pass.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import w242_aee_refusal_vector as refusal_vector
import probe_lines  # noqa: E402  (canonical probe-line form)
AEE_REF = os.environ.get("W242_AEE_REF", "/tmp/aee-ref")
AEE_CORPUS = os.environ.get("W242_AEE_CORPUS", "/tmp/aee-conformance")
CHECKER_BIN = os.environ.get(
    "W242_AEE_CHECKER", os.path.join(AEE_REF, "target", "release", "aee-checker")
)

RESULTS = {"probes": []}


def _map_status(status):
    # Wave-316 lane-3 decision: "skip" -> SKIP (exact semantic match,
    # D1 SKIPPED -> SKIP rationale); "pass"/"fail" -> HELD/BREAK (D1
    # PASS/FAIL rationale); "not-applicable" -> SKIP (the probe cannot
    # run -- no checker exists; exit-neutral like "skip").
    if status == "pass":
        return "HELD"
    if status == "fail":
        return "BREAK"
    return "SKIP"


_RAW_COUNTS = {}


def record(name, status, detail):
    # Wave-316 lane-3: append-only; emission happens once in main()
    # via probe_lines.emit_dicts (canonical form). Raw-status counts
    # are kept for the human summary line below.
    _RAW_COUNTS[status] = _RAW_COUNTS.get(status, 0) + 1
    RESULTS["probes"].append(
        {"name": name, "status": _map_status(status), "detail": detail}
    )


def need_dir(path, what):
    if not os.path.isdir(path):
        record(f"{what}", "skip", f"reference not present at {path}")
        return False
    return True


# --------------------------------------------------------------------------
# Probe 1: the suiteRevision-27 reference record, from primary sources.
# --------------------------------------------------------------------------
def probe_reference_rebaseline():
    name = "reference_rebaseline"
    if not need_dir(AEE_REF, name):
        return
    pin_path = os.path.join(AEE_REF, "PIN-rev27-RUN.md")
    run_path = os.path.join(AEE_REF, "reports", "v0.7-rev27-directed-run.json")
    if not os.path.isfile(pin_path):
        record(name, "fail", "PIN-rev27-RUN.md missing")
        return
    if not os.path.isfile(run_path):
        record(name, "fail", "v0.7-rev27-directed-run.json missing")
        return
    pin = open(pin_path).read()
    run = json.load(open(run_path))
    checks = {
        "pin_states_272_vectors": "272" in pin,
        "pin_states_unchanged_checker_build": "unchanged checker" in pin,
        "pin_labels_run_directed": "directed" in pin.lower(),
        "pin_records_spec_pin_0dbe10bc": "0dbe10bc" in pin,
        "pin_records_refusal_rule_unexercised": "refusal-set" in pin,
    }
    vectors = run.get("vectors", [])
    counts = {
        "total": len(vectors),
        "all_parity_true": all(v.get("parity") for v in vectors),
        "accept": run.get("acceptParity"),
        "reject": run.get("rejectParity"),
        "indeterminate": run.get("indeterminateParity"),
    }
    ok = (
        all(checks.values())
        and counts["total"] == 272
        and counts["all_parity_true"]
        and counts["accept"] == "61/61"
        and counts["reject"] == "209/209"
        and counts["indeterminate"] == "2/2"
    )
    record(
        name,
        "pass" if ok else "fail",
        {
            "pin_checks": checks,
            "run_report": counts,
            "run_label": "directed (pre-registered; pin committed before the run)",
            "corpus_spec_pin": "0dbe10bc",
            "open_question": "head refusal-set rule exercised by no vector",
        },
    )


# --------------------------------------------------------------------------
# Helpers for the refusal-set probes.
# --------------------------------------------------------------------------
SEALED_REFUSAL_PREFIX = "whose clean-row conjuncts do not hold: "

FAIL_STILL_ARMED = "aeeStillArmed is false"
FAIL_DROPS = "aeeDropCount is non-zero and exceeds its aeeDropBound, or declares no bound"
FAIL_POSTURE_PINNED = "aeePostureDigest differs from the pinned networkPosture digest"


def arming_refusal(n):
    return (
        "aeePostureDigest differs from the aeePostureDigest of the "
        f"{n} arming record{'s' if n != 1 else ''} the rows resolve"
    )


def run_checker(vectors_dir, manifest_path=None):
    out = os.path.join(vectors_dir, "w242_probe_out.json")
    cmd = [CHECKER_BIN, vectors_dir, "--json", out]
    if manifest_path:
        cmd[3:3] = ["--manifest", manifest_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"checker failed: {proc.stderr[:500]}")
    return json.load(open(out))


def decode_records(statement):
    recs = []
    for r in statement["predicate"]["observationRecords"]:
        payload = json.loads(base64.b64decode(r["payload"]).decode())
        recs.append(payload)
    return recs


def expected_clean_failures(payload, pinned_posture, arming_postures):
    """Independently re-derive the clean-row failure set for a sealed record,
    mirroring check_sealed + sealed_sweep_reason (reference source read
    2026-09-30; strings copied verbatim)."""
    failures = []
    if payload.get("aeeStillArmed") is False:
        failures.append(FAIL_STILL_ARMED)
    drops = payload.get("aeeDropCount", 0)
    bound = payload.get("aeeDropBound")
    if not (drops == 0 or (bound is not None and drops <= bound)):
        failures.append(FAIL_DROPS)
    posture = payload.get("aeePostureDigest")
    if posture != pinned_posture:
        failures.append(FAIL_POSTURE_PINNED)
    if posture is None:
        failures.append("aeePostureDigest is absent")
    elif arming_postures and not all(a == posture for a in arming_postures):
        failures.append(arming_refusal(len(arming_postures)))
    return failures


def arming_postures_of(statement, records):
    rows = statement["predicate"].get("attackResults", [])
    postures = set()
    for row in rows:
        for ref in row.get("observationRefs", []):
            if 0 <= ref < len(records):
                p = records[ref]
                if p.get("aeeKind") == "arming" and p.get("aeePostureDigest"):
                    postures.add(p["aeePostureDigest"])
    return sorted(postures)


# --------------------------------------------------------------------------
# Probe 2: the authored refusal-set vector.
# --------------------------------------------------------------------------
def probe_refusal_set_authored():
    name = "refusal_set_authored"
    if not os.path.isfile(CHECKER_BIN):
        record(name, "skip", f"checker binary not built at {CHECKER_BIN}")
        return
    corpus_vectors = os.path.join(AEE_CORPUS, "vectors")
    if not os.path.isdir(corpus_vectors):
        record(name, "skip", f"corpus not present at {corpus_vectors}")
        return
    run_dir = tempfile.mkdtemp(prefix="w242aee_authored_")
    vectors_dir = os.path.join(run_dir, "vectors")
    refusal_vector.make_authored_vector(corpus_vectors, vectors_dir)
    report = run_checker(vectors_dir)
    vecs = [v for v in report["vectors"] if v["id"] == "w242-refusal-set-authored"]
    if not vecs:
        record(name, "fail", "authored vector missing from checker output")
        return
    v = vecs[0]
    reason = v.get("reason") or ""
    checks = {
        "verdict_invalid": v["verdict"] == "invalid",
        "names_only_posture_conjunct": FAIL_POSTURE_PINNED in reason,
        "does_not_name_still_armed": FAIL_STILL_ARMED not in reason,
        "does_not_name_drop_count": "aeeDropCount" not in reason,
        "does_not_name_carried_operand_set": "carried arming" not in reason,
    }
    record(
        name,
        "pass" if all(checks.values()) else "fail",
        {
            "checks": checks,
            "reason": reason,
            "run_label": "directed (authored before reading the head spec text)",
        },
    )


# --------------------------------------------------------------------------
# Probe 3: sweep the corpus for sealed clean-row-conjunct refusals.
# --------------------------------------------------------------------------
def probe_refusal_set_corpus_sweep():
    name = "refusal_set_corpus_sweep"
    if not os.path.isfile(CHECKER_BIN):
        record(name, "skip", f"checker binary not built at {CHECKER_BIN}")
        return
    corpus_vectors = os.path.join(AEE_CORPUS, "vectors")
    if not os.path.isdir(corpus_vectors):
        record(name, "skip", f"corpus not present at {corpus_vectors}")
        return
    report = run_checker(corpus_vectors)
    manifest = json.load(open(os.path.join(corpus_vectors, "MANIFEST.json")))
    files = {e["id"]: e["file"] for e in manifest["vectors"]}
    examined = 0
    mismatches = []
    for v in report["vectors"]:
        reason = v.get("reason") or ""
        if SEALED_REFUSAL_PREFIX not in reason:
            continue
        entry_file = files.get(v["id"])
        if entry_file is None:
            mismatches.append((v["id"], "manifest entry missing"))
            continue
        stmt = json.load(open(os.path.join(corpus_vectors, entry_file)))
        records = decode_records(stmt)
        pinned_posture = stmt["predicate"]["observationEnvironment"][
            "networkPosture"
        ]["digest"]["sha256"]
        arming_postures = arming_postures_of(stmt, records)
        # find the named record index
        head, _, tail = reason.partition(SEALED_REFUSAL_PREFIX)
        try:
            idx = int(head.split("observationRecords[")[1].split("]")[0])
        except (IndexError, ValueError):
            mismatches.append((v["id"], "could not parse record index"))
            continue
        named = [f.strip() for f in tail.split(";")]
        expected = expected_clean_failures(
            records[idx], pinned_posture, arming_postures
        )
        examined += 1
        if sorted(named) != sorted(expected):
            mismatches.append(
                (v["id"], f"named={named} expected={expected}")
            )
    record(
        name,
        "pass" if not mismatches else "fail",
        {
            "sealed_conjunct_refusals_examined": examined,
            "mismatches": mismatches,
            "note": "the corpus exercises the refusal discipline on carried "
            "vectors; the head rule itself is exercised by no vector "
            "(open compliance question, see reference_rebaseline)",
        },
    )


# --------------------------------------------------------------------------
# Probe 4: the Sasanam parity precondition (falsifiable, honest).
# --------------------------------------------------------------------------
AEE_MARKERS = ("aeeStillArmed", "aeePostureDigest", "aee-checker", "AEEChecker")


def probe_sasanam_parity_precondition():
    name = "sasanam_parity_precondition"
    hits = []
    for base in ("gov", "evals", "tools", "tests"):
        root = os.path.join(REPO_ROOT, base)
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                if "w242" in fn:
                    continue  # this lane's own probes/tests, not product code
                path = os.path.join(dirpath, fn)
                try:
                    text = open(path, encoding="utf-8").read()
                except OSError:
                    continue
                if any(m in text for m in AEE_MARKERS):
                    hits.append(os.path.relpath(path, REPO_ROOT))
    if hits:
        record(name, "fail", {"unexpected_aee_code": hits})
    else:
        record(
            name,
            "not-applicable",
            "no Sasanam from-spec AEE checker exists in gov/evals/tools/tests; "
            "no parity number can be claimed. The blind-equivalent score "
            "question is unanswerable until a checker is built; this probe "
            "is the gate that must pass first.",
        )


def main():
    probe_reference_rebaseline()
    probe_refusal_set_authored()
    probe_refusal_set_corpus_sweep()
    probe_sasanam_parity_precondition()
    out_path = os.path.join(
        REPO_ROOT, "evals", "artifacts", "w242_aee_parity_results.json"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(RESULTS, open(out_path, "w"), indent=1)
    print(f"results -> {out_path}")
    probe_lines.emit_dicts(RESULTS["probes"], verdict_key="status",
                           pid_key="name", note_key="detail",
                           note_getter=lambda r: r["detail"]
                           if isinstance(r["detail"], str)
                           else json.dumps(r["detail"])[:200])
    brk = sum(1 for p in RESULTS["probes"] if p["status"] == "BREAK")
    hld = sum(1 for p in RESULTS["probes"] if p["status"] == "HELD")
    err = sum(1 for p in RESULTS["probes"] if p["status"] == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(p["name"], p["status"],
          p["detail"] if isinstance(p["detail"], str) else "")
         for p in RESULTS["probes"]], brk, hld, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, hld, err))
    # Exit-equivalence: old `1 if failures else 0` (failures =
    # status == "fail") == new `0 if (brk==0 and err==0)`; skips
    # (incl. not-applicable) are exit-neutral in both.
    failures = [p for p in RESULTS["probes"] if p["status"] == "BREAK"]
    print(
        f"{_RAW_COUNTS.get('pass', 0) + _RAW_COUNTS.get('not-applicable', 0)}/"
        f"{len(RESULTS['probes'])} pass-or-na, "
        f"{len(failures)} fail, {_RAW_COUNTS.get('skip', 0)} skip"
    )
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
