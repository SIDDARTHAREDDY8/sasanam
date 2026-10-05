# Witness Runbook (operator guide)

Sasanam's transparency witness: a quorum of independent cosigners over the
tamper-evident log, following the C2SP static-CT-API `add-checkpoint`
pattern and Rekor v2 §5.3 quorum semantics. This runbook covers
**operating** the witness set. It states behavior contracts only; internal
mechanisms are not disclosed here.

## 1. What the witness proves (and does not)

- Each witness independently replays the log's consistency from the last
  checkpoint it cosigned to the new head, then cosigns the checkpoint.
  A quorum of cosignatures means: at least K independent parties verified
  this exact log history.
- A witness does **not** see log contents beyond the checkpoint
  (origin, size, root hash) and the consistency proof hashes. It does not
  judge whether log entries are true, lawful, or wise — only that the
  history is append-only.

## 2. Bootstrap

1. Stand up each witness host with `gov/witness_daemon.py`:
   the daemon is configured with the set of log origins it serves, its own
   Ed25519 cosigning key, and a sqlite state file. The state file is the
   witness's memory — back it up; losing it forces a re-bootstrap.
2. Provision the witness's cosigning key per `docs/KEY_CUSTODY_RUNBOOK.md`
   (the key signs only cosignature statements; it never decrypts anything).
3. Publish each witness's vkey (name, key ID, Ed25519 public key) to the
   log operator out-of-band. The operator pins these vkeys in the signed
   witness-policy document — a witness nobody pinned is one nobody trusts.
4. The log operator's first submission uses `old 0` (no proof lines);
   the daemon admits it on the trusted log key's signature alone. Verify
   the first cosignature against the witness's published vkey before
   trusting the setup.

## 3. Key custody

- Witness cosigning keys live under the same custody rules as log signing
  keys (`docs/KEY_CUSTODY_RUNBOOK.md`): no key on an operator laptop, no
  key in chat, rotation on personnel change.
- Compromise procedure: remove the witness from the policy's usable set
  (see §6), rotate the key, re-bootstrap the witness from `old 0` with the
  new key. The old key's cosignatures remain verifiable historically —
  that is intended; they attest to the log *as it was*.

## 4. Submission cadence and timeouts

- The log operator submits on a fixed cadence (deployment-chosen; daily is
  a sane default — cadence is an operational estimate, not a security
  parameter) via `submit_checkpoint` with:
  - **quorum K = 2** (minimum viable; larger deployments raise it),
  - **per-witness timeout 10 s** (a healthy witness answers in
    milliseconds; 10 s is generous — estimate),
  - **total budget ≥ 20 s** (the client enforces this floor; a smaller
    budget refuses rather than truncating the quorum wait).
- The client blocks until K valid cosignatures are collected. It retries a
  `409` (stale `old` size) exactly once after rebasing; any other
  non-200 is recorded per-witness and does not fail the whole round
  unless the quorum is missed.

## 5. Below-quorum freeze (the important part)

If fewer than K witnesses cosign — outage, compromise response, network
partition — **the submission client returns nothing and the trusted head
freezes**:

- The checkpoint is NOT published; downstream verifiers keep trusting the
  last quorum-cosigned head.
- The client's caller-owned `{witness: last_cosigned_size}` state is left
  untouched, so the next round retries from the same point.
- The refusal is coded `witness-publish-quorum-unmet` with per-witness
  diagnostics (`ok` / `unreachable` / `refused-<http>` /
  `budget-exhausted`).

Operator procedure on a freeze:

1. Read the diagnostics. `unreachable` on one witness with the rest `ok`
   is routine — the next cadence round retries.
2. If the same witness is `unreachable` for more than two consecutive
   rounds (estimate — tune to your cadence), treat it as an incident:
   page the witness operator; do **not** lower K to route around it.
3. Never publish an unwitnessed checkpoint to "catch up". The freeze is
   the safety property working as designed.

## 6. Rotation: overlap-then-retire

Witness set changes go through the signed witness-policy document, which
additionally enforces the TUF §5.3 dual-threshold rule: when the signer
set changes, the new policy version must carry threshold(old set) **and**
threshold(new set) signatures. Rotation ceremony:

1. Provision the new witness (bootstrap §2, custody §3). Do not list it in
   policy yet.
2. Issue policy vN+1 listing **both** old and new witnesses, sealed by
   both thresholds. The log operator keeps submitting; quorum is met by
   whichever K respond.
3. After the new witness has cosigned at least one checkpoint (verify its
   cosignature against its published vkey), issue policy vN+2 retiring the
   old witness, again sealed by both thresholds.
4. Never shrink below K usable witnesses in a single policy version —
   the client refuses to publish below quorum, and a policy that makes
   quorum unreachable freezes the log (fail-closed, but operationally
   painful).

## 7. Monitoring

- Scrape each witness's `GET /<origin-sha256>/checkpoint` (the monitor
  surface): alert if any witness's cosigned head lags the log's published
  head by more than one cadence interval (estimate).
- Alert on any `422` from a witness — same-size-different-root means
  someone submitted an equivocating checkpoint for an origin the witness
  already cosigned. That is either an operator error or an attack; treat
  it as the latter until proven otherwise.
- The daemon persists before it responds; a crashed witness replays from
  sqlite on restart. If the state file is lost, re-bootstrap (§2) — the
  witness will refuse `old > 0` submissions until it re-learns the head.

## 8. What is deliberately not here

Deployment binding (TLS, auth, process supervision) is deployment-owned
— see `docs/DEPLOYMENT.md`. The HTTP harness in `gov/witness_daemon.py`
(`make_http_handler` / `serve_forever`) is a reference wiring, not a
production server.
