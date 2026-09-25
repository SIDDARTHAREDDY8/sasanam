# Changelog — agent-governance

All notable changes to the packaged product are recorded here. The
version in `gov/__init__.py::__version__` is the single source of
truth; `pyproject.toml` reads it via `[tool.setuptools.dynamic]`.
There is no LICENSE file yet (licensing decision deferred).

## [1.0.0] — Unreleased (v1 ship sprint)

Packaging track (Track 1):

* `gov-approve` default run directory is user-scoped (current working
  directory, then `$XDG_DATA_HOME/agent-governance/runs`); it never
  resolves inside the installed package (site-packages) anymore.
* The wheel now ships `gov.bridges` and `gov.monitor` (previously
  omitted); `demo/` is a real package (`demo/__init__.py` added).
* Every console-script entry point honors `--help`/`-h`
  (`gov-demo`, `gov-attack-demo`, `gov-report` already did via
  argparse; the demo entry points printed usage instead of running).
* Demo runs use a per-run egress ledger and microsecond-resolution
  run ids: sequential or concurrent demos in one directory no longer
  collide on the shared cross-run ledger (each demo provisions a fresh
  random HMAC key, which cannot verify an earlier run's ledger).
* `langchain-core` + `pydantic` declared as the `langchain` extra
  (`pip install agent-governance[langchain]`); the base install stays
  stdlib-only and importing the adapter without the extra raises a
  clear error.
* `requirements.lock` documented as the hashed gate-test environment;
  `pyproject.toml` documented as the installable's declaration (they
  are authoritative for different things; see "Dependency scope" in
  the packaging notes).
* README install/quickstart sections rewritten to match the real
  install and `workstreams/architect/QUICKSTART.md`.

## [0.2.0] — 2026-09-24 (development snapshot)

The state of the tree when single-source versioning landed:
fail-closed policy engine, human approval queue with integrity-bound
records, HMAC-SHA256 chained audit log with offline verifier,
DLP + redaction, per-principal egress ledger with cross-run campaign
signals, MCP/OpenAI/LangChain adapters, evidence-bundle export,
policy linter and Cedar/Dogwood exporter. Synthetic/local only; not
released.
