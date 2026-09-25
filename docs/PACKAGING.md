# Packaging notes — agent-governance

How the `agent-governance` wheel/sdist is built, what it ships, and
which file is authoritative for what. (v1 ship sprint, Track 1.)

## Building

```bash
cd /path/to/agent-governance-demo
python -m pip wheel . --no-deps --no-build-isolation -w dist/   # wheel
python -c "from setuptools.build_meta import build_sdist; build_sdist('dist/')"  # sdist
```

`python -m build` works too if the `build` package is installed; the
two commands above are the offline equivalent. The build backend is
`setuptools.build_meta` (see `pyproject.toml`).

## What ships

Packages (explicit list in `[tool.setuptools] packages`):

* `gov` — the governance layer (stdlib-only at runtime).
* `gov.adapters` — framework shims (core/generic/MCP/OpenAI are
  stdlib-only; `langchain_tools` needs the `langchain` extra).
* `gov.bridges` — D1 approval-queue bridge adapters (stdlib-only).
* `gov.monitor` — infection/tripwire monitors (stdlib-only).
* `demo` — the synthetic demo scenarios behind the `gov-demo`,
  `gov-attack-demo`, and `gov-report` entry points.

`gov.bridges` and `gov.monitor` were missing from the wheel before the
v1 packaging pass (the `packages` list named only `gov`,
`gov.adapters`, `demo`). There was no justification for excluding
them — both are stdlib-only and part of the product surface — so they
are now included. `evals/`, `tests/`, `research/`, and `workstreams/`
are intentionally NOT shipped: they are the development/red-team
harness, not the product.

Package data: `gov/data/default.yaml` (the canonical policy, via
`[tool.setuptools.package-data]`). `gov/policy.py::default_policy_path`
prefers the shipped copy via `importlib.resources` and falls back to
the repo-tree `policies/` copy. A drift-guard test
(`tests/test_packaging.py::PackagingDriftTest`) keeps the two copies
byte-identical.

## Dependency scope — which file is authoritative for what

* **`pyproject.toml`** is authoritative for the *installable*: the
  package name, the single-sourced version (`gov.__version__`), the
  entry points, the shipped package list, and dependency declarations.
  Runtime dependencies: none — the base package is stdlib-only.
  Optional: `[project.optional-dependencies] langchain`
  (`langchain-core>=1.6`, `pydantic>=2`) for
  `gov.adapters.langchain_tools`. Without the extra, importing that
  module raises a clear `ImportError` naming the extra; everything
  else works.
* **`requirements.lock`** is authoritative for the *gate-test
  environment*: the hashed, pinned closure the canonical suite
  (`tests/run_tests.py`, F75 supply-chain gate) runs in. It pins
  dev/test tooling (pydantic, langchain-core, PyYAML, pip,
  setuptools, …) — not the product's runtime dependencies, because
  there are none. Rebuilding a gate-test venv:
  `python -m pip install --require-hashes -r requirements.lock`.

The old lockfile header implied it was the product install story;
that was the scope confusion. The two files answer different
questions and must not be merged.

## Versioning

`gov/__init__.py::__version__` is the single source of truth.
`pyproject.toml` reads it via `[tool.setuptools.dynamic]`
(`version = { attr = "gov.__version__" }`). `CHANGELOG.md` records
per-version changes; the top section is `[1.0.0] — Unreleased` until
v1 ships. No LICENSE file (licensing decision deferred).

## Runtime paths (installed use)

* Demos write `runs/<run-id>/` and `reports/` into the **current
  working directory**. Run ids carry microsecond resolution so
  concurrent demos never share a run directory.
* `gov-approve` (default/`--latest`) resolves runs from `./runs`,
  then `$XDG_DATA_HOME/agent-governance/runs` — never from inside the
  installed package.
* Each demo provisions a fresh random HMAC key per process and uses a
  **per-run** egress ledger (`<run-dir>/egress_ledger.jsonl`): a shared
  cross-run ledger cannot verify across different keys, so sharing it
  between demo runs fails closed. Production deployments with a
  stable `GOV_LOG_KEY` keep the shared cross-run ledger default
  (`<runs-parent>/egress_ledger.jsonl`), which is the F10 cross-run
  campaign-memory feature.

## Known limitations

* The package is not on PyPI; install from a locally built wheel.
* `gov.safeguard_benchmark.SafeguardBenchmark.build()` lazily imports
  `evals.safeguard_results`, which is not shipped in the wheel — the
  benchmark report surface assumes the repo tree. `import
  gov.safeguard_bundle` itself works from the wheel.
* The demos are synthetic (simulated tools, fake data). The
  enforcement pipeline is real; tool effects are not.
