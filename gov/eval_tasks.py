"""Eval tasks as registered evidence artifacts (wave-280 lane 6).

PATTERN LINEAGE: ogx-ai/ogx (the Llama Stack successor), MIT --
``benchmarks register --eval-task-id <id> --dataset-id <dataset>
--scoring-functions <fn...>``: an eval task is a *registered,
reproducible artifact* (eval task x dataset x scoring functions) whose
scores are first-class evidence served with JSON reports -- the
"benchmark as evidence" pattern. This is a clean-room stdlib
re-implementation of the *mechanisms* only; no ogx code, docs, or prose
are vendored here.

What is adapted:

* ``EvalTaskRegistry``: datasets (id -> samples, pinned by digest),
  scoring functions (id -> callable, pinned by digest of its source),
  and eval tasks (id -> dataset id x scoring-function ids x run
  config, pinning the digests of all three). Registration is a
  compile-time boundary: duplicates, unknown references, and
  non-serializable shapes are refused loudly at declaration time.
* ``run_eval_task``: headless execution -- each dataset sample is
  passed through the ``target`` callable under test, every scoring
  function grades (sample, output), and the per-sample scores plus the
  per-scoring-function means are recorded. A scoring function that
  crashes fails the run LOUDLY (``EvalTaskError``) -- a broken grader
  is not evidence, and silent zeros would be.
* ``verify_eval_result``: standalone recomputation of every digest in
  the result (dataset, scoring functions, result body). An auditor
  needs no registry and no engine -- only this module -- to confirm
  the result is exactly what the pinned artifacts produced.
* ``eval_task_evidence_package``: the canonical evidence dict ready
  for the evidence-bundle machinery (``gov.evidence_bundle_v2`` /
  ``gov.battery_envelope`` consume dicts, never this module), with a
  self-describing ``package_digest`` an auditor recomputes from the
  package body alone.

Scores must be real numbers (int/float, never bool), finite. NaN and
infinities are refused -- they would make "mean" meaningless and let a
broken grader smuggle nonsense through aggregation.

Stdlib only. Deterministic for a fixed target and fixed registered
artifacts: no clock, no randomness, no env reads. The one I/O is
registration-time ``inspect.getsource`` on the grader's own source
file, fail-closed when the source is unavailable. The caller
binds timestamps when the result enters the audit chain.
"""

import hashlib
import inspect
import json
import math

#: Bounds kept honest: scores are unit-interval by contract (the garak
#: provider precedent: 0.0 secure -> 1.0 vulnerable). Out-of-range
#: scores are refused rather than silently clipped.
_SCORE_MIN = 0.0
_SCORE_MAX = 1.0


class EvalTaskError(Exception):
    """An eval task is misdeclared or its run failed. Fail-closed:
    there is no partial evidence -- a broken grader or target produces
    no result at all.

    Every refusal carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text).
    """

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _require_jsonable(value, what):
    # Strict: no default=str here. The digest helper below uses
    # default=str for robustness, but registration must refuse
    # non-JSON shapes outright so declarations always round-trip.
    try:
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True)
    except (TypeError, ValueError):
        raise EvalTaskError(
            "evaltask-not-json",
            "%s must be JSON-serializable (evidence must round-trip)"
            % (what,))
    return value


def _check_score(scoring_id, sample_idx, score):
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise EvalTaskError(
            "evaltask-bad-score",
            "scoring function %r returned non-numeric score %r "
            "(sample %d): refusing" % (scoring_id, score, sample_idx))
    score = float(score)
    if not math.isfinite(score):
        raise EvalTaskError(
            "evaltask-bad-score",
            "scoring function %r returned non-finite score %r "
            "(sample %d): refusing" % (scoring_id, score, sample_idx))
    if not (_SCORE_MIN <= score <= _SCORE_MAX):
        raise EvalTaskError(
            "evaltask-bad-score",
            "scoring function %r returned out-of-range score %r "
            "(sample %d): scores are unit-interval" % (scoring_id, score,
                                                       sample_idx))
    return score


class EvalTaskRegistry:
    """Declared datasets, scoring functions, and eval tasks.

    Digests pin the artifacts at declaration time: a dataset's digest
    covers its id + samples; a scoring function's digest covers its
    source; an eval task's record pins the dataset digest, the
    scoring-function digests, and the run-config digest.
    """

    def __init__(self):
        self._datasets = {}
        self._scoring = {}
        self._tasks = {}

    # -- datasets ------------------------------------------------------

    def register_dataset(self, dataset_id, samples):
        """Declare a dataset: a non-empty list of JSON-serializable
        sample dicts. Duplicate ids are refused."""
        if not isinstance(dataset_id, str) or not dataset_id.strip():
            raise EvalTaskError(
                "evaltask-bad-dataset-id",
                "dataset_id must be a non-empty string")
        if dataset_id in self._datasets:
            raise EvalTaskError(
                "evaltask-duplicate-dataset",
                "dataset %r already registered: duplicate ids refused"
                % (dataset_id,))
        if not isinstance(samples, list) or not samples:
            raise EvalTaskError(
                "evaltask-bad-samples",
                "dataset %r: samples must be a non-empty list"
                % (dataset_id,))
        for i, sample in enumerate(samples):
            if not isinstance(sample, dict):
                raise EvalTaskError(
                    "evaltask-bad-sample",
                    "dataset %r sample %d: must be a dict" % (dataset_id, i))
            _require_jsonable(sample, "dataset %r sample %d"
                              % (dataset_id, i))
        record = {
            "dataset_id": dataset_id,
            "samples": [dict(s) for s in samples],
        }
        record["dataset_digest"] = _digest(_canonical(record))
        self._datasets[dataset_id] = record
        return record

    def get_dataset(self, dataset_id):
        try:
            return self._datasets[dataset_id]
        except KeyError:
            raise EvalTaskError(
                "evaltask-unknown-dataset",
                "unknown dataset %r" % (dataset_id,)) from None

    # -- scoring functions ----------------------------------------------

    def register_scoring_function(self, scoring_id, fn):
        """Declare a scoring function ``fn(sample, output) -> float``.
        The digest pins the function's source at declaration time."""
        if not isinstance(scoring_id, str) or not scoring_id.strip():
            raise EvalTaskError(
                "evaltask-bad-scoring-id",
                "scoring_id must be a non-empty string")
        if scoring_id in self._scoring:
            raise EvalTaskError(
                "evaltask-duplicate-scoring-function",
                "scoring function %r already registered" % (scoring_id,))
        if not callable(fn):
            raise EvalTaskError(
                "evaltask-scoring-not-callable",
                "scoring function %r: fn must be callable" % (scoring_id,))
        try:
            source = inspect.getsource(fn)
        except (OSError, TypeError):
            raise EvalTaskError(
                "evaltask-scoring-source-unavailable",
                "scoring function %r: source unavailable, cannot pin "
                "a digest" % (scoring_id,))
        record = {
            "scoring_id": scoring_id,
            "fn": fn,
            "digest": _digest(source.encode("utf-8")),
        }
        self._scoring[scoring_id] = record
        return record

    def get_scoring_function(self, scoring_id):
        try:
            return self._scoring[scoring_id]
        except KeyError:
            raise EvalTaskError(
                "evaltask-unknown-scoring-function",
                "unknown scoring function %r" % (scoring_id,)) from None

    # -- eval tasks ------------------------------------------------------

    def register_eval_task(self, eval_task_id, *, dataset_id, scoring_ids,
                           run_config=None):
        """Declare an eval task: dataset x scoring functions x run
        config. Every referenced artifact must exist; the task record
        pins all their digests."""
        if not isinstance(eval_task_id, str) or not eval_task_id.strip():
            raise EvalTaskError(
                "evaltask-bad-task-id",
                "eval_task_id must be a non-empty string")
        if eval_task_id in self._tasks:
            raise EvalTaskError(
                "evaltask-duplicate-task",
                "eval task %r already registered" % (eval_task_id,))
        dataset = self.get_dataset(dataset_id)
        if not scoring_ids or not isinstance(scoring_ids, (list, tuple)):
            raise EvalTaskError(
                "evaltask-bad-scoring-refs",
                "eval task %r: scoring_ids must be a non-empty list"
                % (eval_task_id,))
        scoring = {sid: self.get_scoring_function(sid)["digest"]
                   for sid in scoring_ids}
        run_config = dict(run_config) if run_config is not None else {}
        _require_jsonable(run_config, "eval task %r run_config"
                          % (eval_task_id,))
        record = {
            "eval_task_id": eval_task_id,
            "dataset_id": dataset_id,
            "dataset_digest": dataset["dataset_digest"],
            "scoring_functions": scoring,
            "run_config": run_config,
            "run_config_digest": _digest(_canonical(run_config)),
        }
        self._tasks[eval_task_id] = record
        return record

    def get_eval_task(self, eval_task_id):
        try:
            return self._tasks[eval_task_id]
        except KeyError:
            raise EvalTaskError(
                "evaltask-unknown-task",
                "unknown eval task %r" % (eval_task_id,)) from None


# ---------------------------------------------------------------------------
# Headless execution.
# ---------------------------------------------------------------------------

def run_eval_task(registry, eval_task_id, *, target):
    """Run an eval task headless: every dataset sample through
    ``target(sample)``, every scoring function over (sample, output).

    Returns the result dict with per-sample scores, per-scoring-function
    means, the pinned digests, and a ``result_digest`` covering the
    whole body. Any target or grader failure raises ``EvalTaskError``
    LOUDLY -- there are no silent zeros and no partial results.
    """
    if not callable(target):
        raise EvalTaskError(
            "evaltask-bad-target", "target must be callable")
    task = registry.get_eval_task(eval_task_id)
    dataset = registry.get_dataset(task["dataset_id"])
    scorers = [(sid, registry.get_scoring_function(sid)["fn"])
               for sid in task["scoring_functions"]]
    # Re-pin check: the task must still reference the exact artifacts
    # it was declared with (a swapped dataset/grader after declaration
    # is a different eval task).
    if dataset["dataset_digest"] != task["dataset_digest"]:
        raise EvalTaskError(
            "evaltask-dataset-changed",
            "eval task %r: dataset %r changed after declaration"
            % (eval_task_id, task["dataset_id"]))
    for sid, pinned in task["scoring_functions"].items():
        current = registry.get_scoring_function(sid)["digest"]
        if current != pinned:
            raise EvalTaskError(
                "evaltask-grader-changed",
                "eval task %r: scoring function %r changed after "
                "declaration" % (eval_task_id, sid))
    per_sample = []
    for idx, sample in enumerate(dataset["samples"]):
        try:
            output = target(sample)
        except Exception as exc:
            raise EvalTaskError(
                "evaltask-target-crashed",
                "eval task %r: target failed on sample %d (%s: %s)"
                % (eval_task_id, idx, type(exc).__name__, exc)) from exc
        scores = {}
        for sid, fn in scorers:
            try:
                raw = fn(sample, output)
            except Exception as exc:
                raise EvalTaskError(
                    "evaltask-grader-crashed",
                    "eval task %r: scoring function %r failed on "
                    "sample %d (%s: %s)"
                    % (eval_task_id, sid, idx, type(exc).__name__, exc)
                    ) from exc
            scores[sid] = _check_score(sid, idx, raw)
        per_sample.append({"sample_index": idx, "scores": scores})
    means = {}
    for sid, _ in scorers:
        vals = [row["scores"][sid] for row in per_sample]
        means[sid] = sum(vals) / len(vals)
    body = {
        "eval_task_id": eval_task_id,
        "dataset_id": task["dataset_id"],
        "dataset_digest": task["dataset_digest"],
        "scoring_functions": task["scoring_functions"],
        "run_config_digest": task["run_config_digest"],
        "sample_count": len(per_sample),
        "per_sample": per_sample,
        "means": means,
    }
    result = dict(body)
    result["result_digest"] = _digest(_canonical(body))
    return result


def verify_eval_result(result):
    """Standalone verification: recompute every digest in the result
    (result body, and internal consistency of scores/means). Returns
    True/False -- never raises on hostile shapes. An auditor needs only
    this module, not the registry or the engine."""
    try:
        if not isinstance(result, dict):
            return False
        body = {k: result.get(k) for k in (
            "eval_task_id", "dataset_id", "dataset_digest",
            "scoring_functions", "run_config_digest", "sample_count",
            "per_sample", "means")}
        if any(v is None for v in body.values()):
            return False
        if result.get("result_digest") != _digest(_canonical(body)):
            return False
        per_sample = body["per_sample"]
        if not isinstance(per_sample, list) or \
                len(per_sample) != body["sample_count"]:
            return False
        means = body["means"]
        scoring_ids = set(body["scoring_functions"])
        for row in per_sample:
            if set(row.get("scores", {})) != scoring_ids:
                return False
            for sid, score in row["scores"].items():
                # Same acceptance as _check_score: int or float, finite,
                # not bool. Self-generated results always store floats,
                # but hand-built (externally audited) results with
                # integer scores must verify too.
                if isinstance(score, bool) \
                        or not isinstance(score, (int, float)) \
                        or not math.isfinite(score):
                    return False
        for sid in scoring_ids:
            vals = [row["scores"][sid] for row in per_sample]
            if abs(sum(vals) / len(vals) - means[sid]) > 1e-9:
                return False
        return True
    except (TypeError, KeyError, AttributeError, ValueError):
        return False


def eval_task_evidence_package(result):
    """The canonical evidence dict for the evidence-bundle machinery.

    Contains the pinned artifact digests, the aggregate means, and a
    ``package_digest`` recomputable from the package body alone -- an
    auditor verifies the package without this module's registry or any
    engine. (``gov.evidence_bundle_v2`` / ``gov.battery_envelope``
    consume the dict; they never import this module.)
    """
    if not verify_eval_result(result):
        raise EvalTaskError(
            "evaltask-unverifiable",
            "cannot package an unverifiable eval result as evidence")
    body = {
        "artifact_kind": "eval-task-result",
        "eval_task_id": result["eval_task_id"],
        "dataset_id": result["dataset_id"],
        "dataset_digest": result["dataset_digest"],
        "scoring_functions": result["scoring_functions"],
        "run_config_digest": result["run_config_digest"],
        "sample_count": result["sample_count"],
        "means": result["means"],
        "result_digest": result["result_digest"],
    }
    package = dict(body)
    package["package_digest"] = _digest(_canonical(body))
    return package


def bind_eval_task_result(log, eval_task_id, result, *, run_id, agent_id):
    """Append an ``eval-task-result`` event carrying the canonical
    evidence package to an audit log.

    This is the declared feed into the evidence-bundle machinery: the
    offline evidence bundle (``gov/evidence_bundle.py``) builds from
    the audit log, so a bound eval result rides the log chain into any
    bundle sealed over it, with its ``package_digest`` independently
    verifiable from the bundle's covered entries. ``log`` is any
    object with an ``append(dict)`` method (e.g. ``gov.log.ActionLog``).

    ``run_id``/``agent_id`` are caller-supplied (this module stays
    clock-free; timestamps are the log's business). Unverifiable
    results are refused loudly -- an eval result that cannot prove
    its own integrity is never bound.
    """
    if not isinstance(eval_task_id, str) or not eval_task_id:
        raise EvalTaskError(
            "evaltask-bad-task-id",
            "eval_task_id must be a non-empty string")
    package = eval_task_evidence_package(result)  # refuses unverifiable
    log.append({"event": "eval-task-result",
                "run_id": run_id,
                "agent_id": agent_id,
                "eval_task_id": eval_task_id,
                "package": package})
    return package
