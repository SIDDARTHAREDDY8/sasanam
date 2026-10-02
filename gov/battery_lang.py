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

Atomic test manifests (``sasanam-atomic-manifest/1``, appended below) add
the adversary-test discipline: stable GUID replay identity, typed
input_arguments validated before the run, dependency self-check with
auto-remediation, and a guaranteed cleanup_command that runs even on
failure. Composition, not duplication: the atomic layer reuses this
module's closed-vocabulary refusal style, canonical digests, and the
EXPECTED_VOCAB executor contract.

Deterministic and stdlib-only. No in-repo git subprocesses. The manifest is
the contract: eval replaying a manifest must reproduce the committed
expected verdicts; any drift is a product or pin regression, never an
eval-side reinterpretation.
"""

import hashlib
import importlib
import inspect
import json
import os
import re

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


# ---------------------------------------------------------------------------
# Atomic test manifests (atomic-red-team ADAPT, wave-282 lane 5).
#
# Mechanism provenance: redcanaryco/atomic-red-team (MIT; the name is
# trademarked -- pattern, not brand). An atomic test is a committed,
# replayable break manifest:
#   - auto_generated_guid  -> stable replay identity (atomic_guid)
#   - input_arguments      -> typed, validated BEFORE the run
#   - dependencies         -> prereq self-check + get_prereq
#                             auto-remediation (the manifest proves its own
#                             preconditions; no "assumed clean environment")
#   - executor{command, cleanup_command, elevation_required}
#                          -> the break plus a GUARANTEED cleanup_command,
#                             the hygiene primitive the real-sandboxing
#                             stream needs between break runs
# plus the validate-atomics.yml CI schema gate (validate_atomic_spec),
# enforced at registration and at committed-manifest load.
#
# Executors are Python callables here (deterministic, $0, no network), not
# shell commands. The executor contract is (verdict, note) with verdict in
# EXPECTED_VOCAB -- composition with the battery language above.
#
# Deliberate choices (documented, not defects):
# - Atomic runs do NOT write to the HMAC audit log. Their evidence is the
#   machine-readable rows (atomic_rows) plus the committed manifest. The
#   audit log carries product decisions; the harness carries test runs.
# - The committed manifest binds guid -> spec_digest, where the digest
#   covers the serializable shape AND every callable's source. Swapping a
#   callable while keeping the shape changes the digest and refuses at
#   bind time (atomic-guid-collision). Callables must therefore be real
#   functions with retrievable source (fail-closed at registration).
# - Cleanup guards the executor's effects and runs even when the executor
#   raises. A dependency that fails before the executor runs refuses LOUD
#   with no cleanup (nothing was set up); the failed remediation's trace
#   rides the refusal detail. A test whose cleanup fails is LOUD
#   (AtomicCleanupError), never silent.
# - bool is not int (the F295 lesson): type validation is strict.
# ---------------------------------------------------------------------------

ATOMIC_MANIFEST_FORMAT = "sasanam-atomic-manifest/1"
ATOMIC_ARG_TYPES = ("str", "int", "float", "bool", "enum")

_GUID_RE = re.compile(r"^[0-9a-f]{64}$")


class AtomicError(Exception):
    """Fail-closed atomic refusal. ``code`` is a registered atomic-*
    decision code; ``detail`` is human context (never a secret)."""

    def __init__(self, code, detail=""):
        super(AtomicError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class AtomicCleanupError(AtomicError):
    """Cleanup itself failed: LOUD, never silent. ``outcome`` carries the
    executor outcome the cleanup was guarding."""

    def __init__(self, detail="", outcome=None):
        super(AtomicCleanupError, self).__init__(
            "atomic-cleanup-failed", detail)
        self.outcome = dict(outcome) if isinstance(outcome, dict) else {}


def _atomic_refuse(code, detail=""):
    raise AtomicError(code, detail)


def _atomic_callable_source(fn, what):
    name = getattr(fn, "__name__", repr(fn))
    if not callable(fn):
        _atomic_refuse("atomic-spec-invalid",
                       "%s %r is not callable" % (what, name))
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        _atomic_refuse("atomic-spec-invalid",
                       "%s %r has no retrievable source "
                       "(manifest binding requires real functions)"
                       % (what, name))
    if not isinstance(src, str) or not src.strip():
        _atomic_refuse("atomic-spec-invalid",
                       "%s %r has empty source" % (what, name))
    return src


def _validate_arg_decl(aname, adecl):
    if not isinstance(aname, str) or not aname.strip():
        _atomic_refuse("atomic-spec-invalid",
                       "argument name must be a non-empty string")
    if not isinstance(adecl, dict):
        _atomic_refuse("atomic-spec-invalid",
                       "argument %r declaration must be a dict" % (aname,))
    atype = adecl.get("type")
    if atype not in ATOMIC_ARG_TYPES:
        _atomic_refuse("atomic-spec-invalid",
                       "argument %r type %r not in %s"
                       % (aname, atype, "/".join(ATOMIC_ARG_TYPES)))
    norm = {"type": atype}
    if atype == "enum":
        choices = adecl.get("choices")
        if (not isinstance(choices, list) or not choices
                or any(not isinstance(c, str) for c in choices)):
            _atomic_refuse("atomic-spec-invalid",
                           "argument %r enum needs a non-empty choices "
                           "list of str" % (aname,))
        norm["choices"] = list(choices)
    elif "choices" in adecl:
        _atomic_refuse("atomic-spec-invalid",
                       "argument %r: choices only valid for enum"
                       % (aname,))
    if "default" in adecl:
        _check_arg_value(aname, atype, norm.get("choices"),
                         adecl["default"], "default")
        norm["default"] = adecl["default"]
    desc = adecl.get("description", "")
    if not isinstance(desc, str):
        _atomic_refuse("atomic-spec-invalid",
                       "argument %r description must be str" % (aname,))
    norm["description"] = desc
    return norm


def _validate_dependency(dep, index):
    if not isinstance(dep, dict):
        _atomic_refuse("atomic-spec-invalid",
                       "dependency %d must be a dict" % index)
    dname = dep.get("name")
    if not isinstance(dname, str) or not dname.strip():
        _atomic_refuse("atomic-spec-invalid",
                       "dependency %d needs a non-empty name" % index)
    _atomic_callable_source(dep.get("prereq"),
                            "dependency %r prereq" % dname)
    get_prereq = dep.get("get_prereq")
    if get_prereq is not None:
        _atomic_callable_source(get_prereq,
                                "dependency %r get_prereq" % dname)
    desc = dep.get("description", "")
    if not isinstance(desc, str):
        _atomic_refuse("atomic-spec-invalid",
                       "dependency %r description must be str" % (dname,))
    return {"name": dname, "description": desc,
            "prereq": dep["prereq"], "get_prereq": get_prereq}


def validate_atomic_spec(spec):
    """CI schema gate: validate an atomic test spec (fail-closed).

    Returns the normalized spec (guid filled in when absent). Every
    refusal carries a registered atomic-* decision code.
    """
    if not isinstance(spec, dict):
        _atomic_refuse("atomic-spec-invalid", "spec must be a dict")
    name = spec.get("name")
    if not isinstance(name, str) or not name.strip():
        _atomic_refuse("atomic-spec-invalid",
                       "spec needs a non-empty name")
    description = spec.get("description", "")
    if not isinstance(description, str):
        _atomic_refuse("atomic-spec-invalid",
                       "description must be a string")
    args = spec.get("input_arguments", {})
    if not isinstance(args, dict):
        _atomic_refuse("atomic-spec-invalid",
                       "input_arguments must be a dict")
    norm_args = {}
    for aname, adecl in args.items():
        norm_args[aname] = _validate_arg_decl(aname, adecl)
    deps = spec.get("dependencies", [])
    if not isinstance(deps, list):
        _atomic_refuse("atomic-spec-invalid",
                       "dependencies must be a list")
    norm_deps = [_validate_dependency(d, i) for i, d in enumerate(deps)]
    ex = spec.get("executor")
    if not isinstance(ex, dict):
        _atomic_refuse("atomic-spec-invalid", "executor must be a dict")
    _atomic_callable_source(ex.get("run"), "executor.run")
    cleanup = ex.get("cleanup")
    if cleanup is not None:
        _atomic_callable_source(cleanup, "executor.cleanup")
    elevation = ex.get("elevation_required", False)
    if not isinstance(elevation, bool):
        _atomic_refuse("atomic-spec-invalid",
                       "executor.elevation_required must be bool")
    guid = spec.get("guid")
    if guid is not None and (
            not isinstance(guid, str) or not _GUID_RE.match(guid)):
        _atomic_refuse("atomic-spec-invalid",
                       "guid must be 64 hex chars")
    norm = {
        "name": name,
        "description": description,
        "input_arguments": norm_args,
        "dependencies": norm_deps,
        "executor": {"run": ex["run"], "cleanup": cleanup,
                     "elevation_required": elevation},
    }
    norm["guid"] = guid or hashlib.sha256(
        _canonical(_atomic_serializable(norm))).hexdigest()
    # Normalization marker: set ONLY here. _ensure_atomic_spec trusts a
    # dict as already-normalized iff it carries this marker -- a raw dict
    # that merely contains a "guid" key is still schema-gated. (Guard
    # against programmer error, not a trust boundary: a caller can forge
    # the marker, but only by reaching into this module's privates.)
    norm["_atomic_normalized"] = True
    return norm


def _check_arg_value(aname, atype, choices, value, role):
    """Strict typed check (bool is not int). Refuses atomic-arg-refused."""
    ok = False
    if atype == "str":
        ok = isinstance(value, str)
    elif atype == "bool":
        ok = isinstance(value, bool)
    elif atype == "int":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif atype == "float":
        ok = (isinstance(value, float)
              or (isinstance(value, int) and not isinstance(value, bool)))
    elif atype == "enum":
        ok = isinstance(value, str) and value in (choices or [])
    if not ok:
        _atomic_refuse("atomic-arg-refused",
                       "%s %r=%r does not satisfy type %r"
                       % (role, aname, value, atype))
    return True


def _ensure_atomic_spec(spec):
    if isinstance(spec, dict) and spec.get("_atomic_normalized") is True:
        return spec
    return validate_atomic_spec(spec)


def validate_atomic_args(spec, args):
    """Validate caller args against the declared input_arguments.

    Unknown args refused; wrong types refused; missing args take their
    defaults; missing required args refused. Returns the validated dict.
    Nothing runs before this passes.
    """
    norm = _ensure_atomic_spec(spec)
    if not isinstance(args, dict):
        _atomic_refuse("atomic-arg-refused", "args must be a dict")
    decls = norm["input_arguments"]
    for aname in args:
        if aname not in decls:
            _atomic_refuse("atomic-arg-refused",
                           "unknown argument %r" % (aname,))
    validated = {}
    for aname, adecl in decls.items():
        if aname in args:
            _check_arg_value(aname, adecl["type"], adecl.get("choices"),
                             args[aname], "argument")
            validated[aname] = args[aname]
        elif "default" in adecl:
            validated[aname] = adecl["default"]
        else:
            _atomic_refuse("atomic-arg-refused",
                           "missing required argument %r" % (aname,))
    return validated


def _atomic_serializable(spec):
    """The shape the guid binds: everything except the callables."""
    return {
        "name": spec["name"],
        "description": spec["description"],
        "input_arguments": spec["input_arguments"],
        "dependencies": [
            {"name": d["name"], "description": d["description"],
             "has_remediation": d["get_prereq"] is not None}
            for d in spec["dependencies"]
        ],
        "executor": {
            "elevation_required": spec["executor"]["elevation_required"],
            "has_cleanup": spec["executor"]["cleanup"] is not None,
        },
    }


def atomic_guid(spec):
    """Stable replay identity of the serializable test shape."""
    norm = _ensure_atomic_spec(spec)
    return hashlib.sha256(
        _canonical(_atomic_serializable(norm))).hexdigest()


def _atomic_callable_digest(fn):
    return hashlib.sha256(
        _atomic_callable_source(fn, "callable").encode("utf-8")).hexdigest()


def atomic_spec_digest(spec):
    """Full drift digest: serializable shape + every callable's source."""
    norm = _ensure_atomic_spec(spec)
    fns = [d["prereq"] for d in norm["dependencies"]]
    fns += [d["get_prereq"] for d in norm["dependencies"]
            if d["get_prereq"] is not None]
    fns.append(norm["executor"]["run"])
    if norm["executor"]["cleanup"] is not None:
        fns.append(norm["executor"]["cleanup"])
    body = {"spec": _atomic_serializable(norm),
            "callables": sorted(_atomic_callable_digest(fn) for fn in fns)}
    return hashlib.sha256(_canonical(body)).hexdigest()


def register_atomic(registry, spec):
    """Register an atomic test (the CI gate runs here too).

    The guid is the identity: re-registering the identical spec is
    idempotent; registering a DIFFERENT spec under an existing guid
    refuses atomic-guid-collision. Returns the guid.
    """
    if not isinstance(registry, dict):
        _atomic_refuse("atomic-spec-invalid",
                       "registry must be a dict")
    norm = validate_atomic_spec(spec)
    guid = norm["guid"]
    digest = atomic_spec_digest(norm)
    if guid in registry:
        if registry[guid]["spec_digest"] != digest:
            _atomic_refuse("atomic-guid-collision",
                           "guid %s... already registered with a "
                           "different spec (was %r, now %r)"
                           % (guid[:12], registry[guid]["spec"]["name"],
                              norm["name"]))
        return guid
    registry[guid] = {"spec": norm, "spec_digest": digest}
    return guid


def _run_dependencies(norm):
    """Prereq self-check + get_prereq auto-remediation per dependency.

    A dependency that stays unsatisfied refuses LOUD
    (atomic-dependency-refused) -- never a silent skip.
    """
    results = []
    for dep in norm["dependencies"]:
        dname = dep["name"]
        try:
            first_ok = bool(dep["prereq"]())
        except Exception as exc:  # noqa: BLE001 -- prereq must not kill run
            _atomic_refuse("atomic-dependency-refused",
                           "prereq %r raised: %r" % (dname, exc))
        remediated = False
        final_ok = first_ok
        if not first_ok and dep["get_prereq"] is not None:
            try:
                remediated = bool(dep["get_prereq"]())
            except Exception as exc:  # noqa: BLE001
                _atomic_refuse("atomic-dependency-refused",
                               "get_prereq %r raised: %r" % (dname, exc))
            try:
                final_ok = bool(dep["prereq"]())
            except Exception as exc:  # noqa: BLE001
                _atomic_refuse("atomic-dependency-refused",
                               "prereq %r raised on re-check: %r"
                               % (dname, exc))
        results.append({"name": dname, "prereq_ok": first_ok,
                        "remediated": remediated, "final_ok": final_ok})
        if not final_ok:
            _atomic_refuse("atomic-dependency-refused",
                           "dependency %r unsatisfied (prereq_ok=%s, "
                           "remediated=%s)" % (dname, first_ok, remediated))
    return results


def _run_cleanup(norm, ctx, outcome):
    """Guaranteed cleanup: runs even when the executor raised. A cleanup
    that itself fails raises AtomicCleanupError LOUD (never silent)."""
    fn = norm["executor"]["cleanup"]
    if fn is None:
        return "absent"
    try:
        fn(dict(ctx), dict(outcome))
    except Exception as exc:  # noqa: BLE001 -- cleanup must be LOUD
        raise AtomicCleanupError(
            "cleanup for %r raised: %r -- LOUD, never silent"
            % (norm["name"], exc),
            outcome=dict(outcome))
    return "ok"


def run_atomic(spec, args, *, registry=None, elevation_granted=False):
    """Run one atomic test.

    Order: validate args -> elevation declaration -> dependency
    self-check (+ auto-remediation) -> executor -> GUARANTEED cleanup.
    ``spec`` is a spec dict or a registered guid (with ``registry``).
    Returns a result dict; dependency failure refuses LOUD; cleanup
    failure raises AtomicCleanupError LOUD carrying the executor outcome.
    """
    if isinstance(spec, str):
        if not isinstance(registry, dict) or spec not in registry:
            _atomic_refuse("atomic-spec-invalid",
                           "unknown atomic guid %r" % (spec,))
        norm = registry[spec]["spec"]
    elif isinstance(spec, dict):
        norm = _ensure_atomic_spec(spec)
    else:
        _atomic_refuse("atomic-spec-invalid",
                       "spec must be a dict or a guid string")
    validated = validate_atomic_args(norm, args)
    if norm["executor"]["elevation_required"] and not elevation_granted:
        _atomic_refuse("atomic-elevation-required",
                       "test %r declares elevation_required; pass "
                       "elevation_granted=True to assert the privilege"
                       % (norm["name"],))
    dep_results = _run_dependencies(norm)
    ctx = dict(validated)
    outcome = {"verdict": "executor-error",
               "note": "executor did not run",
               "executor_verdict": None, "executor_note": ""}
    try:
        try:
            ret = norm["executor"]["run"](dict(ctx))
        except Exception as exc:  # noqa: BLE001 -- recorded, cleanup still runs
            outcome = {"verdict": "executor-error",
                       "note": "executor raised %r" % (exc,),
                       "executor_verdict": None, "executor_note": ""}
        else:
            if (isinstance(ret, (list, tuple)) and len(ret) == 2
                    and ret[0] in EXPECTED_VOCAB):
                outcome = {"verdict": "ok", "executor_verdict": ret[0],
                           "executor_note": str(ret[1])[:400]}
            else:
                outcome = {"verdict": "executor-error",
                           "note": "executor returned %r outside the "
                                   "(verdict, note) contract" % (ret,),
                           "executor_verdict": None, "executor_note": ""}
    finally:
        # Guaranteed: the executor never returns without the cleanup
        # having run (or having failed LOUD).
        cleanup = _run_cleanup(norm, ctx, outcome)
    return {
        "guid": norm["guid"],
        "name": norm["name"],
        "verdict": outcome["verdict"],
        "executor_verdict": outcome.get("executor_verdict"),
        "executor_note": outcome.get("executor_note",
                                     outcome.get("note", "")),
        "cleanup": cleanup,
        "dep_results": dep_results,
        "arg_digest": hashlib.sha256(
            _canonical(validated)).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Committed atomic manifests (the drift contract).
# ---------------------------------------------------------------------------

def generate_atomic_manifest(registry):
    """Committed manifest: per-test guid -> spec_digest bindings."""
    if not isinstance(registry, dict) or not registry:
        _atomic_refuse("atomic-spec-invalid",
                       "registry must be a non-empty dict")
    tests = []
    for guid in sorted(registry):
        entry = registry[guid]
        spec = entry["spec"]
        tests.append({
            "guid": guid,
            "name": spec["name"],
            "spec_digest": entry["spec_digest"],
            "arg_schema": spec["input_arguments"],
            "dependencies": [
                {"name": d["name"],
                 "has_remediation": d["get_prereq"] is not None}
                for d in spec["dependencies"]],
            "elevation_required":
                spec["executor"]["elevation_required"],
            "has_cleanup": spec["executor"]["cleanup"] is not None,
        })
    return {"format": ATOMIC_MANIFEST_FORMAT, "tests": tests}


def _validate_atomic_manifest_dict(manifest):
    """Schema-validate a parsed atomic manifest dict (the CI gate).

    Shared by load_atomic_manifest (file path) and bind_atomic_manifest
    (in-memory dict): bind never trusts a hand-built dict.
    """
    if not isinstance(manifest, dict):
        _atomic_refuse("atomic-spec-invalid", "manifest must be an object")
    if manifest.get("format") != ATOMIC_MANIFEST_FORMAT:
        _atomic_refuse("atomic-spec-invalid",
                       "format %r != %r" % (manifest.get("format"),
                                            ATOMIC_MANIFEST_FORMAT))
    tests = manifest.get("tests")
    if not isinstance(tests, list) or not tests:
        _atomic_refuse("atomic-spec-invalid",
                       "tests must be a non-empty list")
    seen = set()
    for i, t in enumerate(tests):
        if not isinstance(t, dict):
            _atomic_refuse("atomic-spec-invalid",
                           "test %d must be an object" % i)
        for key in ("guid", "name", "spec_digest"):
            if not t.get(key) or not isinstance(t.get(key), str):
                _atomic_refuse("atomic-spec-invalid",
                               "test %d missing non-empty %r" % (i, key))
        if (not _GUID_RE.match(t["guid"])
                or not _GUID_RE.match(t["spec_digest"])):
            _atomic_refuse("atomic-spec-invalid",
                           "test %d guid/spec_digest must be 64 hex" % i)
        if t["guid"] in seen:
            _atomic_refuse("atomic-spec-invalid",
                           "duplicate guid %r" % t["guid"])
        seen.add(t["guid"])
    return manifest


def load_atomic_manifest(path):
    """Load + schema-validate a committed atomic manifest (the CI gate)."""
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        _atomic_refuse("atomic-spec-invalid",
                       "unreadable manifest: %s" % exc)
    return _validate_atomic_manifest_dict(manifest)


def bind_atomic_manifest(registry, manifest):
    """Bind a committed manifest to a live registry (drift detection).

    Every manifest guid must be registered and its live spec_digest must
    match the committed one; any drift refuses atomic-guid-collision.
    Returns the bound guids.
    """
    if not isinstance(registry, dict):
        _atomic_refuse("atomic-spec-invalid",
                       "registry must be a dict")
    manifest = _validate_atomic_manifest_dict(manifest)
    bound = []
    for t in manifest.get("tests", []):
        guid = t["guid"]
        if guid not in registry:
            _atomic_refuse("atomic-spec-invalid",
                           "manifest references unregistered guid %s..."
                           % guid[:12])
        live = atomic_spec_digest(registry[guid]["spec"])
        if live != t["spec_digest"]:
            _atomic_refuse("atomic-guid-collision",
                           "guid %s... drifted: the committed spec no "
                           "longer matches the registered test" % guid[:12])
        bound.append(guid)
    return bound


def atomic_rows(results):
    """Machine-readable evidence rows for atomic runs.

    Composition with the battery-language rows shape: the harness working
    (verdict ok + cleanup ok/absent) grades PASS; the product verdict
    (executor_verdict HELD/BREAK/...) rides along as data, not as the
    grade -- a BREAKing atomic test is a successful run.
    """
    rows = []
    for res in results:
        if not isinstance(res, dict) or "guid" not in res:
            _atomic_refuse("atomic-spec-invalid",
                           "atomic_rows needs run_atomic result dicts")
        grading = ("PASS" if res.get("verdict") == "ok"
                   and res.get("cleanup") in ("ok", "absent")
                   else "FAIL")
        rows.append({
            "atomic_guid": res["guid"],
            "name": res.get("name", ""),
            "executor_verdict": res.get("executor_verdict"),
            "cleanup": res.get("cleanup"),
            "grading_result": grading,
            "note_digest": hashlib.sha256(
                str(res.get("executor_note", "")).encode("utf-8")
            ).hexdigest(),
        })
    return rows
