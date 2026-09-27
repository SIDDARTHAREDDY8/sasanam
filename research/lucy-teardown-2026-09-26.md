# LUCY Teardown — 2026-09-26

**Repo:** https://github.com/Fifth-Third-Bank/lucy
**Head examined:** `fd7bf50` ("Pushing Release for the tag v1.1.1"), main branch
**Method:** shallow clone + source read; claims cite file paths below.

---

## 1. What is Lucy?

**LUCY ("5/3 AI Scanner") is an agentic source-code vulnerability scanning harness for large, complex applications.** Its thesis: AI can find real vulns, but the hard problem is *trusting the review* — did it read the whole app, stop for the right reason, and is "done" a measurement or a confident sentence? LUCY answers with three mechanisms:

1. **Recall-first discovery** — read everything (uncapped by default), then earn precision back.
2. **Adversarial verification** — independent "court" agents try to *disprove* every serious finding from the code alone; refuted claims are published, never silently dropped.
3. **Receipt-backed certification** — deterministic gates re-computable by anyone holding the output; a run prints `CERTIFIED` only when gates pass on receipts, never on model prose.

**Provenance & maturity:**
- Built at **Fifth Third Bank** ("developed at Fifth Third Bank through its work with frontier AI" — README.md).
- Public repo, **Apache-2.0** (LICENSE file).
- Created **2026-08-31**; only **4 commits**, 6 stars, 2 watchers, 4 forks (repo metadata, 2026-09-26).
- 3 releases/tags; current version **1.1.1** (pyproject.toml; CHANGELOG.md: initial public release 2026-09-01).
- This is a young, bank-published research-grade tool — not a mature product. The CHANGELOG even notes "sanitized public set" fixtures and excluded internal build metadata, i.e. the public repo is a scrubbed export of an internal project.

**Cost model:** scans spend real money (LLM API / Claude / Codex usage). The launcher prints a cost estimate first (`--estimate-only`), enforces per-lane spend caps (LANE_BUDGET_USD_DEFAULT = 25.0, lucy/runtime/host.py), and a run budget cap (`--max-budget-usd`) that degrades certification honestly (capped runs print PROCESS-COMPLETE, not CERTIFIED).

---

## 2. Architecture: how it works

Pipeline (`lucy scan --target <super-repo> --results <dir>`), per README.md "How a scan works" and docs/how-it-works.md:

1. **Estimate** — cost estimate, no spend.
2. **Copy** — target copied into a disposable workspace; the original is never touched (byte-identical afterward, verified by hash).
3. **Plant** — a separate, isolated "planter" agent hides **8 synthetic bugs** (2 per lens) in the copy; the answer key goes to **launcher-only custody** (`~/.lucy/custody`, 0700, outside workspace and results — lucy/runtime/trial.py:76-82). The reviewer sees only a hash commitment.
4. **Read** — the code is split into **units** (lucy/runtime/units.py); up to **20 parallel reader agents** each read one unit through one of **four lenses** (L1-auth, L2-secrets, L3-injection, L4-infra — lucy/agents/lucy-reader.md). Passes repeat until two consecutive quiet passes per unit (density-scaled bar: max(2, LOC/25K)).
5. **Challenge** — independent **court agents** (lucy/agents/lucy-court.md) attempt to disprove every serious finding. Verdicts: VERIFIED / CONDITIONAL (mechanism holds, exploitation rests on an unsettled precondition — reported in a separate worst-plausible tier, never downgraded) / REFUTED (published as its own report section).
6. **Check and seal** — external recall scoring (did the review find the 8 plants?), report build, certification gates, everything bundled into a **ZIP delivery**.

**Agent definition model:** agents are *static Markdown contracts*, not code. `lucy/SKILL.md` (the orchestrator), `lucy/agents/lucy-reader.md`, `lucy/agents/lucy-court.md`, `lucy/planter/SYSTEM.md` + `PLAYBOOKS.md`. The launcher's tool surface is pinned via the skill's `allowed-tools:` frontmatter (Read, Grep, Glob, Write, Agent(lucy-reader), Agent(lucy-court), ScheduleWakeup, and a Bash allowlist for `lucy-units`, `lucy-merge`, `lucy-finalize`, `lucy-toolbox`, read-only git commands).

**Two orchestration paths:**
- **Claude Code skill session (default):** the model itself is the orchestrator, driving subagents via the installed skill (lucy/SKILL.md: "You are the orchestrator, not a reader... never claim CERTIFIED").
- **Launcher-driven hosts (lucy/runtime/orchestrator.py):** for Codex / OpenAI API — "models only perform isolated reader/court lanes; Python owns passes, quiet convergence, sweeps, liveness, and courts." Deterministic scheduler in Python; agents are pure functions (`run_agent(system, task, workspace) -> str`).

**Notable design choices:**
- **Ledger conservation** (docs/certification.md): candidates in must equal findings emitted + claims refuted; finalization fails closed if any serious finding lacks a verdict.
- **Canary attribution by CAUSATION, not proximity** (docs/certification.md): every candidate in a planter-modified file is re-examined by an independent court against a *fresh clean copy* — a defect surviving on clean bytes is genuine; one existing only in the planted workspace is synthetic.
- **Recall rescoring during recapture is launcher-only and silent** (docs/threat-model.md) — cure laps are fully blind; the launcher never discloses a missed plant's unit/file/family to any model.
- **Capture-recapture coverage bound:** a Chapman estimator from ecology applied to vuln discovery — per-unit lower bound ≥ 0.95 required (lucy/runtime/seal.py:43-62).

---

## 3. Tool use / execution model

**Three host types** (lucy/runtime/host.py):

| Host | Invocation | Tool surface | Sandboxing |
|---|---|---|---|
| **Claude Code** (default) | `claude --print` per lane | Pinned allowlist: `Read,Grep,Glob` only | No shell, no subagents, `--no-session-persistence`, auto-memory/CLAUDE.md/history disabled by launcher |
| **Codex CLI** | `codex exec` (ephemeral) | Saved-login Codex with a custom least-privilege permission profile: prepared workspace only, **no command network**, no access to answer-key custody | bubblewrap (`bwrap`) required on Linux; explicit workspace-only filesystem profile |
| **OpenAI-compatible API** (experimental) | Chat Completions function-calling over HTTPS | `WorkspaceTools` only: `read_file`, `grep`, `list_files`, `edit_file` (role-gated) — "strictly smaller surface than the Claude Code host's pinned allowlist" (lucy/runtime/localtools.py) | No shell, no network, no paths outside workspace; path traversal rejected by `_resolve()` |

**Falsification executor:** `lucy/toolbox/HERMETIC_RUNNER.py` — runs untrusted commands with an isolation ladder: Linux network namespace (`unshare -rn`) when available, else "GUARD mode" (Python `socket` stubbed via sitecustomize + proxy env poisoning). Per-execution receipt JSON; the tested command's exit code is *data*, never a lane crash.

**What agents can never do:** run target code, builds, package managers, network tools, or live endpoints (skill boundary); create branches/commits/PRs/issues; reach outside the workspace + run-dir roots.

**Honest residual (their own threat model, docs/threat-model.md):** "Codex CLI inspection is shell-backed... The ban on running target code, builds, tests, package managers, and interpreters is therefore a model instruction rather than a mechanical boundary. Operators needing a no-shell reviewer should use the default Claude path." Also: "A malicious repository can contain instruction-shaped source text... model behavior is not a security boundary."

---

## 4. Identity, auth, audit logging

**Identity:** there is no agent identity system. Agents are ephemeral — one fresh process/conversation per lane, no persistent identity, no inter-agent authentication. The only identities in play are:
- The **operator's** credentials: Claude login (Claude Code host), saved ChatGPT login (Codex host), or `OPENAI_API_KEY` bearer token (API host, env var).
- The **run identity**: `run_id = compute_run_id(baseline_hash, started_at, secrets.token_hex(8))` (lucy/runtime/trial.py:354) — a content-derived run identifier, not an agent identity.

**Auth:** nothing beyond the host CLIs' own login. No SSO/OIDC/mTLS in LUCY itself; no API keys minted or managed. The answer-key custody dir is protected by POSIX permissions (0700), not cryptography.

**Audit logging — receipts, not a signed log:** every phase writes machine-readable receipts under `runs/<run-id>/receipts/` (e.g. `MINT_COMMITMENT.json`, `PASS_HISTORY.json`, `RECALL_RECEIPT.json`, `CONSERVATION.json`, `CANDIDATE_DISPOSITIONS.json`, `TIMELINE.json`, `LIVENESS.jsonl`, `WAKE.jsonl`, `CODEX_USAGE.jsonl` — lucy/runtime/artifacts.py, seal.py). **Critically:** receipts are *not* cryptographically signed or hash-chained. The anti-forgery control is procedural: the launcher passes the scored recall-receipt *object* directly to certification rather than reading the reviewer-writable receipts file ("never certify from a forged receipt file" — lucy/runtime/seal.py:199-204). Certification = deterministic re-computation from receipts, verifiable by anyone holding the delivery ZIP — "a certification anyone can re-check," but the trust anchor is possession of the output, not a signature.

**Secret hygiene:** agent contracts forbid literal secrets in output; finalization applies best-effort masking for recognized credentials/emails/US SSNs; the report gate rejects recognized credential patterns. Explicitly "not comprehensive PII anonymization or DLP" (threat model). Staging areas are not encrypted at rest.

---

## 5. Dependencies and supply-chain surface

**Remarkably small:** the entire `lucy/` package is **stdlib-only except `tree_sitter`** (used in one module, `lucy/runtime/syntax_check.py`). Declared dependencies (pyproject.toml): just `tree-sitter-language-pack>=0.13`; dev extra: `ruff`. No requests, no pydantic, no SDKs — the OpenAI host speaks raw HTTPS via `urllib`.

**Supply-chain controls:**
- **Toolbox integrity:** the 18 deterministic toolbox assets are byte-pinned by SHA-256 in `lucy/toolbox/assets.json`; a startup consistency check verifies them (threat model is honest: "integrity against accidental drift, not a signature: an attacker who can rewrite the toolbox can rewrite the manifest").
- **Import allowlist** for the toolbox (`tests/test_import_toolbox.py`, `tests/test_allowlist.py`).
- **Pinned launcher wrappers** (`lucy/bin/lucy`, `lucy-finalize`, `lucy-merge`, `lucy-toolbox`, `lucy-units`) that pin imports to the checkout and strip CWD from `sys.path` ("Do not substitute `python -m`... Python searches that directory first and can silently run the wrong build" — README.md).
- **Public-release sanitization:** the repo ships a "sanitized public set" of fixtures (identifier examples replaced); internal build metadata excluded (CHANGELOG 1.1.0).
- **Vulnerability reporting:** private HackerOne channel to Fifth Third's Vulnerability Management Team (SECURITY.md).

**External trust surface:** the model providers (Anthropic / OpenAI / ChatGPT login), PyPI (`tree-sitter-language-pack`), the operator's machine (agents run under the user's OS identity — "filesystem policy is ultimately enforced by its CLI sandbox/permissions and the host OS"), and provider-side data retention (local incognito controls don't change it).

---

## Surprising / notable

1. **Ecology math in a security tool:** the Chapman capture-recapture estimator (wildlife population counting) is used to bound vuln-discovery coverage per code unit. Genuinely novel measurement thinking.
2. **Courts, not just reviewers:** the adversarial-verification layer (independent agents that try to *disprove* findings, with refutations published as a credibility record) is the closest open-source analog to a red-team/blue-team finding pipeline — and it maps directly onto our evidence-quality problem.
3. **Honest threat model:** the docs openly admit the Codex shell-backed sandbox gap, the unsigned-toolbox-manifest limitation, and that model behavior is not a security boundary. Rare candor for a bank-published tool.
4. **No crypto where you'd expect it:** receipts are unsigned and unchained; the "certification" is deterministic recomputation, not attestation. Their trust model is *reproducibility*, not *authenticity* — the opposite trade from our hash-chained log.
5. **Tiny supply-chain surface** (stdlib + one grammar pack) is a deliberate security choice, and the pinned-import wrappers show real attention to import-confusion attacks.
6. **Maturity caveat:** 4 commits, 6 stars, 3 weeks old, scrubbed public export. Treat the code as a design reference, not a hardened dependency.
