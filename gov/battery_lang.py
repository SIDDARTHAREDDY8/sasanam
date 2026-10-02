"""Adversarial battery language: plugin x strategy x grader (promptfoo ADAPT).

Mechanism provenance: promptfoo/promptfoo (MIT, OpenAI-owned; OSS core MIT,
Enterprise tier commercial -- core patterns only, no code vendored). Promptfoo's
red-team separates three roles: **plugins** = *what* to attack, **strategies** =
*how* to deliver it, **graders** = *how to score*. Its generate -> commit -> eval
discipline makes the generated suite a pinned, reviewable artifact whose eval
replays deterministically.

Why this exists here: our red-team batteries are hand-rolled per wave with
bespoke probe names and ad-hoc reporting (see evals/w279_redteam_probes.py
before this lane). There was no shared attack vocabulary across waves, no
committed replayable suite format, and no machine-readable evidence rows that
feed the evidence bundles ("sell evidence, not the engine").

This module provides:

- closed vocabularies (PLUGINS / STRATEGIES / GRADERS); unknown ids refuse
  fail-closed at manifest load/generate time, never silently default;
- a committed manifest format (JSON, ``sasanam-battery-manifest/1``): the
  generate step pins every probe's (plugin, strategy, grader, expected);
- an eval runner that replays a committed manifest, grades each probe, and
  emits machine-readable rows (probe_id, plugin_id, strategy_id,
  grading_result) plus a sealed evidence envelope via
  ``gov.battery_envelope`` for the envelope-eligible probes.

Deterministic and stdlib-only. No in-repo git subprocesses. The manifest is
the contract: eval replaying a manifest must reproduce the committed
expected verdicts; any drift is a product or pin regression, never an
eval-side reinterpretation.
"""

import hashlib
import importlib
import json
import os

# ---------------------------------------------------------------------------
# Closed vocabularies (promptfoo ADAPT: plugins = what, strategies = how,
# graders = how scored). Each id carries a one-line description so the
# vocabulary is self-documenting; the ids are stable across waves.
# ---------------------------------------------------------------------------

PLUGINS = {
    "decoy-fatigue":
        "decoy-grant fatigue-tracker contract (int/float/bool/non-finite now)",
    "egress-l7-screening":
        "sandbox wall-proxy L7 URL screening (encoding, scheme, separators)",
    "envelope-integrity":
        "evidence-envelope chain/integrity vs truth separation",
    "elicitation-contract":
        "approval elicitation tri-state + rationale/secret/budget seams",
    "delegation-binding":
        "delegation resource binding (URI normalization, spawn re-targeting)",
    "rekor-witness":
        "Rekor v2 second-witness wiring (flag-off identity, witness failure)",
    "closure-repin":
        "re-verification pins for previously closed findings",
    "guardrail-outcome-triad":
        "allow / reject_content / raise_exception guard outcomes + tripwires",
    "guardrail-evidence":
        "uniform guardrail-run evidence records (block vs failure)",
    "approval-remediation":
        "deterministic remediation taxonomy + bounded re-ask/repair loop",
    "seal-contract":
        "sealer-side evidence-contract enforcement (signature != compliance)",
    "vsa-issuance":
        "signed Verification Summary Attestation per sealed bundle",
    "prompt-injection":
        "indirect/direct instruction injection through retrieved content",
    "credential-exfil":
        "credential-shaped material leaving the trust boundary",
    "jailbreak":
        "safety-policy bypass via framing or composition",
    "excessive-agency":
        "agent exceeding its authorized action scope",
    "privilege-escalation":
        "grant/role escalation within or across sessions",
    "supply-chain":
        "skill/MCP/dependency provenance and rollback attacks",
    "authz-bypass":
        "authorization-path circumvention at any product seam",
    "replay-attack":
        "replay of approvals, decisions, or evidence records",
    "policy-drift":
        "assembler/sealer (or config/run) policy drift between two checks",
    "key-custody":
        "key-minting, substitution, or HMAC chain-key handling",
}

STRATEGIES = {
    "direct": "attack delivered with no transformation",
    "type-confusion": "bool/int/float/None/NaN/inf conflation at a typed seam",
    "encoding-evasion": "percent/quoted-printable/case/IDNA encoding games",
    "concurrency": "racing threads/interleavings (TOCTOU, budget races)",
    "replay": "re-presenting a prior valid artifact (approval, record)",
    "normalization-variant": "URI/path/case/port/query normalization attacks",
    "forgery": "hand-crafting a self-consistent artifact with public code",
    "witness-abuse": "malformed, raising, or garbage third-party witness",
    "byte-compare": "byte-identical behavior comparison between two paths",
    "boundary-glue": "gluing cross-script/cross-domain cues with no delimiter",
    "schema-bypass": "nested JSON, unicode lookalikes, enum-conflation shapes",
    "budget-race": "exhausting a bounded budget (re-ask, elicitation) mid-run",
    "tunnel-bypass": "CONNECT/absolute-URI forms that skip the L7 screen",
    "body-evasion": "moving the attack below the URL into the body/headers",
    "version-drift": "contract/registry/pin drift between two components",
    "documented-residual": "documented honest limit, probed to pin the shape",
    "regression": "re-running a previously closed finding's break case",
}

GRADERS = {
    "held-vs-expected":
        "probe verdict must equal the committed expected verdict",
    "replay-identical":
        "two consecutive probe runs must return identical (verdict, note)",
    "note-matches":
        "probe note must match the committed regex pattern "
        "(grader_config.pattern)",
}

MANIFEST_FORMAT = "sasanam-battery-manifest/1"
EXPECTED_VOCAB = ("HELD", "BREAK", "RESIDUAL", "ERROR")

_ENVELOPE_ELIGIBLE = frozenset(("HELD", "BREAK", "ERROR"))
_GRADING_PASS = "PASS"
_GRADING_FAIL = "FAIL"


class BatteryLanguageError(Exception):
    """Fail-closed refusal. ``reason`` is a stable machine-readable string
    (battery-language vocabulary, not a taxonomy decision code)."""

    def __init__(self, reason, detail=""):
        super(BatteryLanguageError, self).__init__(
            "%s%s" % (reason, (": %s" % detail) if detail else ""))
        self.reason = reason
        self.detail = detail


def _refuse(reason, detail=""):
    raise BatteryLanguageError(reason, detail)


# ---------------------------------------------------------------------------
# Manifest validation (closed vocabularies: unknown ids fail closed).
# ---------------------------------------------------------------------------

_UNKNOWN_REASONS = {
    "plugin": "battery-lang-unknown-plugin",
    "strategy": "battery-lang-unknown-strategy",
    "grader": "battery-lang-unknown-grader",
}


def _check_vocab(mapping, value, kind, vocab_name):
    if value not in mapping:
        _refuse(_UNKNOWN_REASONS[kind],
                "%r is not a registered %s "
                "(see gov.battery_lang.%s)" % (value, kind, vocab_name))
    return value


def _check_probe_entry(entry, index):
    if not isinstance(entry, dict):
        _refuse("battery-lang-bad-probe", "probe %d must be an object" % index)
    for key in ("probe_id", "plugin", "strategy", "grader", "expected"):
        if not entry.get(key) or not isinstance(entry.get(key), str):
            _refuse("battery-lang-bad-probe",
                    "probe %d missing non-empty %r" % (index, key))
    if entry["expected"] not in EXPECTED_VOCAB:
        _refuse("battery-lang-bad-probe",
                "probe %r expected %r not in %s"
                % (entry["probe_id"], entry["expected"],
                   "/".join(EXPECTED_VOCAB)))
    _check_vocab(PLUGINS, entry["plugin"], "plugin", "PLUGINS")
    _check_vocab(STRATEGIES, entry["strategy"], "strategy", "STRATEGIES")
    _check_vocab(GRADERS, entry["grader"], "grader", "GRADERS")
    if entry["grader"] == "note-matches":
        cfg = entry.get("grader_config") or {}
        if not isinstance(cfg, dict) or not cfg.get("pattern"):
            _refuse("battery-lang-bad-probe",
                    "probe %r uses note-matches without "
                    "grader_config.pattern" % entry["probe_id"])
    return entry


def load_manifest(path):
    """Load and validate a committed battery manifest (fail-closed)."""
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        _refuse("battery-lang-bad-manifest", "unreadable: %s" % exc)
    if not isinstance(manifest, dict):
        _refuse("battery-lang-bad-manifest", "manifest must be an object")
    if manifest.get("format") != MANIFEST_FORMAT:
        _refuse("battery-lang-bad-manifest",
                "format %r != %r" % (manifest.get("format"),
                                     MANIFEST_FORMAT))
    for key in ("battery", "battery_version", "module"):
        if not manifest.get(key) or not isinstance(manifest.get(key), str):
            _refuse("battery-lang-bad-manifest",
                    "missing non-empty %r" % key)
    probes = manifest.get("probes")
    if not isinstance(probes, list) or not probes:
        _refuse("battery-lang-bad-manifest", "probes must be a non-empty list")
    seen = set()
    for i, entry in enumerate(probes):
        _check_probe_entry(entry, i)
        if entry["probe_id"] in seen:
            _refuse("battery-lang-bad-manifest",
                    "duplicate probe_id %r" % entry["probe_id"])
        seen.add(entry["probe_id"])
    return manifest


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def manifest_digest(manifest):
    """Stable digest of the committed manifest (excludes volatile fields)."""
    body = {k: v for k, v in manifest.items() if k not in ("generated_at",)}
    return hashlib.sha256(_canonical(body)).hexdigest()


# ---------------------------------------------------------------------------
# Probe-module protocol.
#
# A probe module exposes:
#   PROBES = [(pid, expected, fn), ...]     # legacy 3-tuples keep working
#   PROBE_METADATA = {pid: (plugin, strategy, grader)}   # required for
#                                                        # generate; the
#                                                        # shared vocabulary
# ---------------------------------------------------------------------------

def resolve_probes(module):
    """Return {pid: (expected, fn)} for a probe module (fail-closed)."""
    probes = getattr(module, "PROBES", None)
    if not isinstance(probes, (list, tuple)) or not probes:
        _refuse("battery-lang-no-probes",
                "%s exposes no PROBES list" % module.__name__)
    resolved = {}
    for entry in probes:
        if not isinstance(entry, (list, tuple)) or len(entry) != 3:
            _refuse("battery-lang-bad-probe-entry",
                    "PROBES entries must be (pid, expected, fn)")
        pid, expected, fn = entry
        if not callable(fn):
            _refuse("battery-lang-bad-probe-entry",
                    "probe %r fn is not callable" % (pid,))
        if expected not in EXPECTED_VOCAB:
            _refuse("battery-lang-bad-probe-entry",
                    "probe %r expected %r not in %s"
                    % (pid, expected, "/".join(EXPECTED_VOCAB)))
        if pid in resolved:
            _refuse("battery-lang-bad-probe-entry",
                    "duplicate probe_id %r" % (pid,))
        resolved[pid] = (expected, fn)
    return resolved


def resolve_metadata(module):
    """Return {pid: (plugin, strategy, grader)} (fail-closed)."""
    meta = getattr(module, "PROBE_METADATA", None)
    if not isinstance(meta, dict) or not meta:
        _refuse("battery-lang-no-metadata",
                "%s exposes no PROBE_METADATA mapping; annotate every probe "
                "with the shared vocabulary before generating a manifest"
                % module.__name__)
    resolved = {}
    for pid, triple in meta.items():
        if not isinstance(triple, (list, tuple)) or len(triple) != 3:
            _refuse("battery-lang-bad-metadata",
                    "metadata for %r must be (plugin, strategy, grader)"
                    % (pid,))
        plugin, strategy, grader = triple
        _check_vocab(PLUGINS, plugin, "plugin", "PLUGINS")
        _check_vocab(STRATEGIES, strategy, "strategy", "STRATEGIES")
        _check_vocab(GRADERS, grader, "grader", "GRADERS")
        resolved[pid] = (plugin, strategy, grader)
    return resolved


# ---------------------------------------------------------------------------
# Generate: probe module -> committed manifest (the "commit" step).
# ---------------------------------------------------------------------------

def generate_manifest(module, battery, battery_version, *, target_commit=""):
    """Generate the manifest dict from a probe module's annotations.

    ``module`` is the imported probe module. Every probe id must have
    vocabulary metadata; an unannotated probe fails closed (the shared
    vocabulary is the point -- no unlabeled probes enter a committed
    suite).
    """
    probes = resolve_probes(module)
    metadata = resolve_metadata(module)
    missing = [pid for pid in probes if pid not in metadata]
    if missing:
        _refuse("battery-lang-unannotated",
                "probes without vocabulary metadata: %s"
                % ", ".join(sorted(missing)))
    entries = []
    for pid in probes:
        expected, _fn = probes[pid]
        plugin, strategy, grader = metadata[pid]
        entries.append({
            "probe_id": pid,
            "plugin": plugin,
            "strategy": strategy,
            "grader": grader,
            "expected": expected,
        })
    return {
        "format": MANIFEST_FORMAT,
        "battery": battery,
        "battery_version": battery_version,
        "target_commit": target_commit,
        "module": module.__name__,
        "probes": entries,
    }


def write_manifest(path, manifest):
    """Write a manifest after validation (committed artifact)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_canonical(manifest).decode("utf-8") + "\n")
    # Re-load to prove the written artifact passes the same gate eval uses.
    return load_manifest(path)


# ---------------------------------------------------------------------------
# Graders (deterministic; no LLM judges -- $0 rule).
# ---------------------------------------------------------------------------

def _note_digest(note):
    return hashlib.sha256(str(note).encode("utf-8")).hexdigest()


def _grade_held_vs_expected(expected, result, config):
    verdict = result.get("verdict")
    return (_GRADING_PASS if verdict == expected else _GRADING_FAIL,
            "verdict %r vs expected %r" % (verdict, expected))


def _grade_replay_identical(expected, result, config):
    run1 = result.get("run1")
    run2 = result.get("run2")
    ok = (run1 is not None and run2 is not None
          and run1.get("verdict") == run2.get("verdict")
          and run1.get("note") == run2.get("note"))
    return (_GRADING_PASS if ok else _GRADING_FAIL,
            "two runs identical: %s" % ok)


def _grade_note_matches(expected, result, config):
    import re
    pattern = (config or {}).get("pattern")
    if not pattern:
        return ("ERROR", "note-matches needs grader_config.pattern")
    try:
        match = re.search(pattern, str(result.get("note", "")))
    except re.error as exc:
        return ("ERROR", "bad pattern: %s" % exc)
    return (_GRADING_PASS if match else _GRADING_FAIL,
            "note matches %r: %s" % (pattern, bool(match)))


_GRADER_FNS = {
    "held-vs-expected": _grade_held_vs_expected,
    "replay-identical": _grade_replay_identical,
    "note-matches": _grade_note_matches,
}


def grade_probe(grader, expected, result, config=None):
    """Run one grader; unknown graders fail closed."""
    if grader not in _GRADER_FNS:
        _refuse("battery-lang-unknown-grader",
                "%r is not a registered grader" % (grader,))
    return _GRADER_FNS[grader](expected, result, config)


# ---------------------------------------------------------------------------
# Eval: committed manifest -> graded rows (+ sealed envelope).
# ---------------------------------------------------------------------------

def _import_module(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:
        _refuse("battery-lang-bad-module",
                "cannot import %r: %s" % (name, exc))


def _call_probe(fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probes must never crash eval
        return {"verdict": "ERROR", "note": repr(exc)[:200]}
    if verdict not in EXPECTED_VOCAB:
        return {"verdict": "ERROR",
                "note": "probe returned verdict %r outside %s"
                        % (verdict, "/".join(EXPECTED_VOCAB))}
    return {"verdict": verdict, "note": str(note)[:400]}


def eval_manifest(path, *, rows_path=None, envelope_path=None):
    """Replay a committed manifest deterministically.

    Returns the summary dict. Writes machine-readable rows
    (probe_id, plugin_id, strategy_id, grading_result) to ``rows_path``
    as JSONL, and -- when given -- seals an evidence envelope via
    ``gov.battery_envelope`` at ``envelope_path`` for the
    envelope-eligible probes (the envelope vocabulary is
    BREAK/HELD/ERROR; RESIDUAL probes live in the rows only, never in
    the envelope).
    """
    manifest = load_manifest(path)
    module = _import_module(manifest["module"])
    probes = resolve_probes(module)
    rows = []
    for entry in manifest["probes"]:
        pid = entry["probe_id"]
        if pid not in probes:
            _refuse("battery-lang-probe-missing",
                    "manifest probe %r not present in module %s"
                    % (pid, manifest["module"]))
        expected, fn = probes[pid]
        if expected != entry["expected"]:
            _refuse("battery-lang-expected-drift",
                    "module PROBES expected %r for %r != committed %r"
                    % (expected, pid, entry["expected"]))
        result = _call_probe(fn)
        if entry["grader"] == "replay-identical":
            second = _call_probe(fn)
            result = {"run1": result, "run2": second,
                      "verdict": result["verdict"]}
        try:
            grading, detail = grade_probe(entry["grader"], expected, result,
                                          entry.get("grader_config"))
        except BatteryLanguageError:
            grading, detail = "ERROR", "grader refused"
        rows.append({
            "probe_id": pid,
            "plugin_id": entry["plugin"],
            "strategy_id": entry["strategy"],
            "grading_result": grading,
            "expected": expected,
            "verdict": result.get("verdict"),
            "note_digest": _note_digest(result.get("note", "")),
            "grader": entry["grader"],
            "detail": detail,
        })
    if rows_path:
        os.makedirs(os.path.dirname(os.path.abspath(rows_path)),
                    exist_ok=True)
        with open(rows_path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(_canonical(row).decode("utf-8") + "\n")
    envelope_sealed = None
    if envelope_path:
        envelope_sealed = _seal_rows(manifest, rows, envelope_path)
    passes = sum(1 for r in rows if r["grading_result"] == "PASS")
    fails = sum(1 for r in rows if r["grading_result"] == "FAIL")
    errors = sum(1 for r in rows if r["grading_result"] == "ERROR")
    return {
        "battery": manifest["battery"],
        "manifest_digest": manifest_digest(manifest),
        "rows": rows,
        "summary": {"PASS": passes, "FAIL": fails, "ERROR": errors},
        "rows_path": rows_path,
        "envelope_path": envelope_sealed,
    }


def _seal_rows(manifest, rows, envelope_path):
    """Seal the eval rows into a battery evidence envelope.

    Envelope-eligible verdicts only (BREAK/HELD/ERROR); RESIDUAL probes
    are rows-file-only by vocabulary design. Each sample carries the
    ``lang`` metadata: the plugin/strategy/grader triple that the rows
    file makes machine-readable.
    """
    from gov import battery_envelope as be
    builder = be.RunBuilder(
        manifest["battery"], manifest["battery_version"],
        battery_path=None)
    oracle_for = {"BREAK": "violating", "HELD": "clean", "ERROR": "clean"}
    for row in rows:
        verdict = row["verdict"]
        if verdict not in _ENVELOPE_ELIGIBLE:
            continue
        builder.record(
            row["probe_id"],
            oracle=oracle_for[verdict],
            expected=row["expected"] if row["expected"] in _ENVELOPE_ELIGIBLE
            else "ERROR",
            verdict=verdict,
            note="%s: %s" % (row["grading_result"], row["detail"]),
            metadata={"plugin_id": row["plugin_id"],
                      "strategy_id": row["strategy_id"],
                      "grader": row["grader"],
                      "grading_result": row["grading_result"]},
        )
    envelope = builder.seal()
    return be.emit_envelope(envelope_path, envelope)
