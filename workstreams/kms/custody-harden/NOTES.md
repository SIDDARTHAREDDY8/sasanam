# STREAM 2 working notes — production key-custody hardening + runbook

Owner: stream-2 subagent. Main tree NOT modified (constraint); all work
lives in this directory for central integration review.

## What was done

1. **Audit** (`AUDIT.md`): full-tree sweep of gov/, tests/, examples/,
   demo/, evals/, workstreams/ for dev-key/test-key paths, hardcoded key
   material, test fixtures reachable from gov/, env-var backdoors, and
   insecure-default key material. Every finding classified as
   CLOSED-by-wave-81 / FALSE-ALARM / REAL-GAP / DOC-DRIFT.
2. **Regression check**: ran key-related suites under
   `~/workspace/.gov-venv/bin/python -m unittest` (pytest is not installed
   in the venv and $0/no-network forbids installing it; the repo's own
   runner is unittest-based):
   - `tests.test_keys tests.test_kms tests.test_custody
     tests.test_w69_key_management tests.test_w70_key_management
     tests.test_w72_anchor` → 196 tests OK
   - `tests.test_w81_no_dev_fallback tests.test_s6_lineage` → 42 tests OK
   - One stderr WARNING observed is expected: a test explicitly constructs
     an `anchor_key` dict with `"dev": True` to exercise the warning path
     (FA1 in AUDIT.md).
3. **Prototype fix** (`strict_keyfiles.py` + `test_strict_keyfiles.py`):
   for REAL-GAP G1 (inconsistent permission fail-closed posture across
   key-loading paths). Reference implementation only — central integration
   decides whether to port into gov/.
4. **Draft runbook** (`key-custody-runbook.md`): operator procedures for
   (a) HashiCorp Vault via the upcoming VaultKmsProvider and (b) AWS KMS
   via EnvelopeKmsProvider + operator-built adapter; rotation; key-loss
   consequences; explicit non-goals. Every untested step marked UNTESTED.

## Key facts established during the audit

- `GOV_DEV_KEYS` appears **zero** times in gov/ (wave-81 deletion verified
  live), but `docs/DEPLOYMENT.md`, `docs/READINESS_GAPS.md`, and
  `workstreams/kms/CEREMONY_RUNBOOK.md` still document it as a live gate
  (DOC-DRIFT D1–D3). The CEREMONY_RUNBOOK rehearsal section is not just
  stale but *broken*: `kms_provider_from_config({"provider": "fake"})`
  now raises unconditionally.
- `gov/kms.py` references `DESIGN.md §2, §9` and
  `workstreams/kms/redteam/attack_kms_impersonator.py`; neither exists in
  the tree (minor doc-drift, noted in AUDIT.md).
- Permission posture matrix (G1):
  refuse group/world-readable — `KeyRing.load`, `EnvelopeKeyRing.load`,
  `ShareStore.load`, `load_root_seed`;
  warn-only — `resolve_anchor_key` (`GOV_ANCHOR_KEY_FILE`);
  no check — `lineage._load_or_create_key` (existing key file).
- No gov/ module imports from tests/ (verified); `tests/keyfixture.py`
  provisions fresh random keys per call through the production env path.

## Open questions for central integration

1. G1 fix placement: port `require_private_key_file` into gov/ (e.g.
   `gov/keys.py`) and switch the anchor-key-file branch from warn to
   refuse? That is a behavior change for existing deployments with
   0644 anchor key files — they would fail closed on upgrade. Needs a
   migration note.
2. The dead `"dev"` field on the anchor-key dict: remove the field (API
   break) or keep as residue? The prototype keeps shape-compatibility.
3. `docs/DEPLOYMENT.md` needs a wave-81 correction pass (D1); the draft
   runbook here can seed it.
4. `_real_key_available()` in `gov/egress_ledger.py` only checks
   `GOV_LOG_KEY`, not `GOV_KEYRING_FILE` — conservative (cache bypassed,
   full re-verify), not a gap. Flagged as a note in AUDIT.md.
