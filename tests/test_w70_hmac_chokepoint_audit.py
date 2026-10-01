"""Wave-70 Lane 2: HMAC key-path audit as a standing regression test.

Wave-69's "every HMAC key path flows through the guarded chokepoint"
audit was informal. This test formalizes it: it AST-walks every
``*.py`` file under ``gov/`` and enumerates every call site that can
reach HMAC key material — ``hmac.new(...)``, ``hmac.HMAC(...)``, and
``hmac.digest(...)`` — and FAILS THE SUITE unless every found site is
in the explicit ``ALLOWED_HMAC_SITES`` allowlist below.

Fail-closed properties:
- Allowlist, not denylist: ANY new ``hmac.new``/``HMAC``/``digest``
  call site anywhere under ``gov/`` fails until a human allowlists it
  with a custody story. A new site can never slip in silently.
- Stale entries fail too: an allowlist entry whose site no longer
  exists fails with an actionable message (remove the entry), so the
  allowlist cannot drift from the code.
- Import aliasing is handled: ``import hmac as _h`` /
  ``from hmac import new as _new`` shapes are resolved to the same
  ``hmac`` origin before matching (proven by the break-first probes
  below, run as ordinary unit tests in this file).

Documented gap (boundary, not a finding): the test resolves imports
statically. A call site that reaches ``hmac`` through fully dynamic
indirection — ``__import__("hmac")``, ``getattr(hmac, "n" + "ew")``,
a vendored HMAC reimplementation over ``hashlib`` — is NOT caught.
That gap is accepted deliberately: an actor who can land such
indirection in ``gov/`` source already has source-write, which is the
supply-chain threat model (out of scope for this audit); this test
guards against accidental unguarded call sites and makes
alias-evasion visible at review time. ``hmac.compare_digest`` uses
are out of scope (verification only, no key material).

Deterministic, $0, no I/O outside the source tree (AST parse only).
"""

import ast
import sys
import unittest
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = _TESTS_DIR.parent
GOV_DIR = REPO_ROOT / "gov"

# HMAC entry points that take key material as the first argument.
_HMAC_FUNCS = ("new", "HMAC", "digest")

# (relative path, qualified scope name, ordinal) -> custody story.
# Ordinal = the nth matching call inside that scope in source order
# (0-based). Qualified scope = "ClassName.method" or "function" for
# module-level functions. A new call site ANYWHERE under gov/ fails
# the suite until it is added here with its story.
ALLOWED_HMAC_SITES = {
    # gov/log.py: the action-log chain. Every site takes the key as its
    # first parameter; all callers pass gov.log._active_key() output,
    # i.e. the wave-69 resolve_active_key chokepoint.
    ("gov/log.py", "_compute_mac", 0):
        "log entry MAC; key from _active_key() chokepoint",
    ("gov/log.py", "_checkpoint_mac", 0):
        "checkpoint MAC; key from _active_key() chokepoint",
    ("gov/log.py", "_approval_record_mac", 0):
        "approval-record MAC; key from _active_key() chokepoint",
    ("gov/log.py", "_break_glass_ticket_mac", 0):
        "break-glass ticket MAC; key from _active_key() chokepoint",
    ("gov/log.py", "_tip_mac", 0):
        "tip-cache MAC; key from _active_key() chokepoint",
    # gov/approvals.py: delegation/reconcile MACs under the SAME active
    # log key (callers pass gov.log._active_key() or
    # egress_ledger._ledger_keyring(), which itself resolves via
    # gov.log._active_key()).
    ("gov/approvals.py", "_reconcile_marker_cache_mac", 0):
        "reconcile marker-verdict cache MAC; key = active log key",
    ("gov/approvals.py", "_delegation_grant_mac", 0):
        "delegation-grant MAC; key = active log key (same epochs)",
    # gov/arap.py (wave-218): the ARAP authorization-relevant-context
    # integrity binding. The key is a DEPLOYMENT-OWNED key passed
    # explicitly to declare_context() (never a default, never derived
    # in-repo; >=16 bytes enforced, fail closed otherwise). The MAC
    # is domain-separated (sasanam-arap-context/v1:) and binds the
    # approver-visible context map; verify_context_binding recomputes
    # the same binding and refuses mismatch loudly. A context binding
    # is an integrity attestation, not a credential.
    ("gov/arap.py", "declare_context", 0):
        "ARAP context binding MAC; deployment-owned key (explicit pass)",
    ("gov/arap.py", "verify_context_binding", 0):
        "ARAP context re-verification MAC; deployment-owned key (explicit pass)",
    # gov/egress_ledger.py: the egress ledger chain, keyed by the same
    # log key epochs via gov.log._active_key().
    ("gov/egress_ledger.py", "_ledger_mac", 0):
        "ledger entry MAC; key from gov.log._active_key()",
    ("gov/egress_ledger.py", "_checkpoint_mac", 0):
        "ledger checkpoint MAC; key from gov.log._active_key()",
    # gov/skill_watch.py (H22): the pin-manifest MAC. The key is the
    # operator key resolved via keyprovider (no fallback — fail closed
    # without a configured key), never hard-coded or derived in-repo.
    ("gov/skill_watch.py", "_pin_manifest_mac", 0):
        "pin-manifest MAC; key = operator key via keyprovider (H22, no fallback)",
    # gov/short_lived_credentials.py (wave-256): the credential-journal
    # chain MACs. The key is DEPLOYMENT-OWNED: passed explicitly to
    # CredentialIssuer(path, key=...) or via the GOV_CREDENTIAL_KEY env
    # var (hex); >=16 bytes enforced, fail closed on weak/invalid keys
    # (short-lived-credential-key-weak). The None-key fallback generates
    # secrets.token_bytes(32) and is documented single-process/tests only
    # (not durable across restarts). All three sites take the resolved key
    # as their first parameter; no key is hard-coded or derived in-repo.
    ("gov/short_lived_credentials.py", "_genesis_mac", 0):
        "credential-journal chain anchor; deployment-owned key (explicit pass/env)",
    ("gov/short_lived_credentials.py", "_event_mac", 0):
        "credential event chain MAC; deployment-owned key (explicit pass/env)",
    ("gov/short_lived_credentials.py", "_secret_binding", 0):
        "stored secret proof (HMAC id:secret, secret never stored); "
        "deployment-owned key (explicit pass/env)",
    # gov/kms.py: the SYNTHETIC fake KMS test double. _FAKE_WRAP_SECRET
    # is a hard-coded test value, never a real key; the real envelope
    # path (EnvelopeKmsProvider) unwraps via the KMS backend, not HMAC.
    ("gov/kms.py", "FakeKmsProvider._hmac", 0):
        "synthetic FakeKmsProvider only; test-double secret",
    # gov/platform_egress.py: the platform-egress-consent (PEC) custody
    # story — a DEPLOYER-HELD key passed explicitly to issue_consent,
    # never the log key; and a TEST-ONLY demo cipher.
    ("gov/platform_egress.py", "_token_mac", 0):
        "PEC consent-token MAC; deployer-held key (explicit pass)",
    ("gov/platform_egress.py", "demonstration_cipher", 0):
        "TEST-ONLY demo cipher; env-gated, never production",
    # gov/recovery.py (wave-77): the recovery doctrine's MACs. The key
    # is the first parameter; both keys are operator-held and passed
    # EXPLICITLY to RecoveryController (never the log key — a
    # journal-key holder cannot mint checkpoints, halts, or resume
    # attestations by construction). Production deployment mode
    # requires explicit keys (no dev-key fallback); the recovery and
    # halt keys must differ; every MAC is domain-separated
    # (recovery-checkpoint-v1 / recovery-halt-v1 / recovery-resume-v1
    # / recovery-delegation-attest-v1) so no credential works outside
    # its operation.
    ("gov/recovery.py", "_mac", 0):
        "recovery checkpoint/halt/resume MACs; operator-held keys, "
        "explicit pass, production requires keys, domain-separated",
    # (registry custody story, independent of the log key).
    # gov/sterile.py: the sterile registry's own registration secret.
    ("gov/sterile.py", "_reg_mac", 0):
        "sterile registry token MAC; registry-held secret",
    # gov/lineage.py (wave-90, S6): the infection-lineage sidecar
    # stamps. The key is the tracker's own per-run lineage key
    # (run_dir/lineage/.key, mode 0600, os.urandom(32) at creation),
    # held in the operator trust domain — never the log key, never
    # agent-reachable through governed tools (which cannot read
    # outside the sandbox). Stamps are per-run: a new run mints a
    # new key, so stamps never cross runs.
    ("gov/lineage.py", "LineageTracker._sign_stamp", 0):
        "lineage sidecar-stamp MAC; per-run operator-held lineage key",
    # gov/lineage.py (wave-117, H8): the cross-run lineage chain
    # (cross_run_lineage.jsonl). The key is _logmod._active_key()
    # output at both call sites — the wave-69 guarded chokepoint,
    # same key as the action-log chain — with domain separation via
    # _CROSS_RUN_DOMAIN ("crossrun-lineage") and the key_epoch bound
    # into the MAC input, so cross-run records can never be confused
    # with log entries. Verification (hmac.compare_digest) is out of
    # scope per the module docstring.
    ("gov/lineage.py", "_cross_run_mac", 0):
        "cross-run lineage chain MAC; key from _active_key() chokepoint, domain-separated",
    # gov/intent_ledger.py (wave-138, row-7): the per-message
    # countermand-threshold derivation. The key is
    # gov.keyprovider.resolve_active_key() output — the wave-69/81
    # guarded chokepoint (explicit provisioning, fail-closed, no dev
    # fallback) — never hard-coded, never committed; domain-separated
    # via _THRESHOLD_DOMAIN ("intent-ledger/countermand-threshold/v1")
    # so the threshold derivation cannot collide with any other MAC
    # domain. The derived value is a decision threshold, not a
    # credential: it is recorded on the ledger record for auditability.
    ("gov/intent_ledger.py", "derive_countermand_threshold", 0):
        "countermand-threshold derivation; key from resolve_active_key() chokepoint, domain-separated",
    # gov/taint_ledger.py (wave-139, row-13): per-token taint
    # commitments. The key is gov.keyprovider.resolve_active_key()
    # output (or an explicit constructor override) — the wave-69/81
    # guarded chokepoint (explicit provisioning, fail-closed, no dev
    # fallback) — never hard-coded, never committed; domain-separated
    # via _COMMIT_DOMAIN ("taint-commit-v1") and bound to
    # (agent_id, source_id, token) so commitments cannot collide
    # across agents, sources, or other MAC domains. The digest is a
    # blinding commitment, not a credential: token strings never
    # appear in the ledger file (pinned by
    # tests/test_taint_ledger.py::PrivacyInvariantTest and the x6
    # battery probe).
    ("gov/taint_ledger.py", "TaintLedger.blinded_token", 0):
        "taint-commitment blinding; key from resolve_active_key() chokepoint, domain-separated",
    # gov/artifact_sweep.py (wave-141, row-12): the declared-inventory
    # pin. The key is gov.keyprovider.resolve_active_key() output (or
    # an explicit caller override) -- the wave-69/81 guarded
    # chokepoint (explicit provisioning, fail-closed, no dev
    # fallback) -- never hard-coded, never committed;
    # domain-separated via _PIN_DOMAIN ("artifact-inventory-pin-v1")
    # and bound to (envelope version, resolved inventory, pinned_at)
    # so a pin cannot collide with any other MAC domain. The pin is
    # an inventory-integrity binding, not a credential.
    ("gov/artifact_sweep.py", "_inventory_pin_mac", 0):
        "inventory-pin MAC; key from resolve_active_key() chokepoint, domain-separated",
    # gov/artifact_sweep.py (wave-143, row-12): the watch-root
    # declaration MAC. The key is gov.keyprovider.resolve_active_key()
    # output (or an explicit caller override) -- the wave-69/81
    # guarded chokepoint (explicit provisioning, fail-closed, no dev
    # fallback) -- never hard-coded, never committed;
    # domain-separated via _ROOTS_DECL_DOMAIN
    # ("artifact-roots-declaration-v1") and bound to (envelope
    # version, resolved roots, previous_roots, previous_digest,
    # operator_id, reason, declared_at, key_epoch) so a declaration
    # cannot collide with any other MAC domain. The declaration is a
    # configuration-integrity binding, not a credential.
    ("gov/artifact_sweep.py", "_roots_decl_mac", 0):
        "roots-declaration MAC; key from resolve_active_key() chokepoint, domain-separated",
    # gov/drift_budget.py (wave-148, row-9): the drift-continuity
    # digest MAC. The key is gov.keyprovider.resolve_active_key()
    # output when the caller passes hmac_key=None (or an explicit
    # caller-supplied key for tests/offline tooling) -- the
    # wave-69/81 guarded chokepoint (explicit provisioning,
    # fail-closed, no dev fallback) -- never hard-coded, never
    # committed; domain-separated via _CONTINUITY_MAC_DOMAIN
    # ("drift-continuity-v1") and bound to (v, agent_id, run_seq,
    # adapt_level, paced_cycles, rot_history, slow_accum, slow_runs)
    # so a digest cannot collide with any other MAC domain. The
    # digest carries drift-state counters, not credentials.
    ("gov/drift_budget.py", "_continuity_mac", 0):
        "drift-continuity digest MAC; key from resolve_active_key() chokepoint, domain-separated",
    # gov/chained_store.py (wave-157+, row-9 keyed chains): the
    # per-record chain MAC for DriftStore, FramingStore, and
    # PopulationStore (which calls keyed_digest directly). The key is
    # gov.keyprovider.resolve_active_key() output — the wave-69/81
    # guarded chokepoint (explicit provisioning, fail-closed, no dev
    # fallback) — never hard-coded, never committed; domain-separated
    # via chain_domain() ("gov-chained-store/v1" + the record schema's
    # version key) so drift, framing, budget, and population chains can
    # never collide with each other or with any other MAC domain. The
    # chain_keyed marker and key_epoch are part of the MAC input, so
    # the scheme marker cannot be stripped off-band.
    ("gov/chained_store.py", "keyed_digest", 0):
        "row-9 chain-record MAC; key from resolve_active_key() chokepoint, domain-separated per record schema",
    # gov/tee_attest.py (wave-208, lane D): the SYNTHETIC local-TDREPORT
    # platform MAC. The key is secrets.token_bytes(32) minted fresh on
    # every call -- never a production key, never hard-coded, never
    # stored, exported, or reused. The MAC authenticates only synthetic
    # local TDREPORT fixtures (kind=TDX_KIND_LOCAL, labeled synthetic);
    # no remote verifier can check it, and the remote TDX verifier must
    # refuse these reports even when every exposed field matches. This
    # is fixture-only key material, not a credential and not custody
    # material; nothing production flows through this site.
    ("gov/tee_attest.py", "make_synthetic_local_tdreport", 0):
        "synthetic local-TDREPORT fixture MAC; ephemeral random key per call, remote-unverifiable by design",
    # gov/alg_registry.py (wave-224): the hmac-sha256-mac tier of the
    # algorithm registry. The key is a 32-byte DEPLOYMENT-OWNED
    # symmetric key supplied by the caller to the issuer (never
    # hard-coded, never derived in-repo, never the log key); MAC-tier
    # verifiers hold the same shared key (public_key is None). Every
    # MAC is domain-separated via the registry's per-algorithm domain
    # separator ("sasanam-alg/hmac-sha256-mac:") so the tag cannot be
    # replayed into any other MAC domain. The tier is honestly labeled
    # non_repudiation=False -- a MAC proves authenticity only to
    # key-holders and must never be treated as non-repudiation
    # evidence (require_non_repudiation refuses the tier outright).
    ("gov/alg_registry.py", "_hmac_sign", 0):
        "alg-registry MAC tier sign; deployment-owned 32-byte key (explicit pass), domain-separated, non-repudiable=False",
    # gov/transactional_tokens.py (wave-243, lane C): the per-transaction
    # token MAC. The key is the TransactionalTokenIssuer's DEPLOYMENT
    # key, supplied explicitly at construction as non-empty bytes; a
    # missing/invalid key fails closed (transaction-key-missing) with
    # NO dev-key fallback. The MAC is domain-separated via
    # _TOKEN_DOMAIN ("gov-txn-token/v1\\x00") over the canonical token
    # body (txn_id, rs_audience, issued/expires); it is an integrity
    # binding for same-transaction authorization context, not a
    # credential.
    ("gov/transactional_tokens.py", "_mac", 0):
        "per-transaction token MAC; deployment key (explicit pass, fail-closed no fallback), domain-separated",
    # gov/action_bound_permits.py (wave-243, lane D): the action-bound
    # permit binding MAC. The key is the permit ISSUER's key, REQUIRED
    # explicitly by bind_permit/verify_permit (fail-closed
    # permit-malformed when absent); never a default, never derived
    # in-repo. It binds (recipient, key_ref, request_digest,
    # action_instance, currentness_mode, base_permit_digest) so the
    # record cannot be edited after issue; an integrity binding, not
    # a credential.
    ("gov/action_bound_permits.py", "_binding_digest", 0):
        "action-bound permit binding MAC; issuer key (required explicit pass), fail-closed when absent",
    # gov/surface_defaults.py (wave-244, lane G): the secure-defaults
    # attestation MAC. The key is the deployment ISSUER key, REQUIRED
    # explicitly by audit_surface (fail-closed
    # surface-attestation-key-missing when absent); never a default,
    # never derived in-repo. Domain-separated via _ATTESTATION_DOMAIN
    # ("gov-surface-attestation/v1\\x00") over the canonical
    # attestation body (v, surface, config_digest); an integrity
    # binding for the audited config, not a credential.
    ("gov/surface_defaults.py", "_attestation_mac", 0):
        "secure-defaults attestation MAC; issuer key (required explicit pass), domain-separated",
    # gov/token_scope_enforcement.py (wave-244, lane B): the token-scope
    # grant/policy MAC. The key is the deployment-supplied SCOPE key,
    # REQUIRED explicitly by the caller (_key_or_refuse fail-closes
    # scope-key-missing when absent); never a default, never derived
    # in-repo. Domain-separated via _GRANT_DOMAIN
    # ("gov-token-grant/v1\\x00") over the canonical grant body and
    # _POLICY_DOMAIN ("gov-seal-policy/v1\\x00") over the canonical
    # policy body; binds each grant to sha256(token mac). An integrity
    # binding for scope grants, not a credential.
    ("gov/token_scope_enforcement.py", "_mac", 0):
        "token-scope grant/policy MAC; scope key (required explicit pass, fail-closed when absent), domain-separated",
    # gov/mcp_oauth_binding.py (wave-245, lane 1): the MCP OAuth
    # authorization-server binding seal. The key is the deployment-owned
    # AS binding key, REQUIRED explicitly by seal_binding
    # (_key_or_refuse fail-closes mcp-oauth-key-missing when absent or
    # empty; no dev-key fallback, never derived in-repo).
    # Domain-separated via _BINDING_DOMAIN over the canonical binding
    # body (v, issuer, client_id, token_endpoint_allowlist); an integrity
    # binding for the deployment's AS binding, not a credential.
    ("gov/mcp_oauth_binding.py", "_mac", 0):
        "MCP OAuth AS binding seal MAC; deployment-owned key (required explicit pass, fail-closed when absent), domain-separated",
    # gov/agent_identity.py (wave-248 lane 5, dex): short-lived identity
    # tokens. The key is passed EXPLICITLY to IdentityTokenIssuer (never
    # a default, never derived in-repo; >=16 bytes enforced, fail closed
    # otherwise). Domain-separated (sasanam-identity-token/v1) over the
    # canonical token body; an integrity binding for the federated
    # identity, not a credential.
    ("gov/agent_identity.py", "IdentityTokenIssuer.issue", 0):
        "identity-token MAC; deployer-held key (explicit pass), domain-separated",
    ("gov/agent_identity.py", "IdentityTokenIssuer.verify_token", 0):
        "identity-token verification; same deployer-held key, domain-separated",
    # gov/breach_boundary.py (wave-248 lane 1, F210 closure): tamper-evident
    # verified-record seals. The key is passed EXPLICITLY to BreachBoundary
    # (seal_key parameter; >=16 bytes enforced, fail closed otherwise; fresh
    # random key generated if not supplied). Domain-separated over the
    # canonical (component, seq, output, verifier_id, evidence); seals the
    # verification attestation, not a credential.
    ("gov/breach_boundary.py", "BreachBoundary._seal", 0):
        "verified-record seal MAC; deployer-held or instance-generated key (explicit), domain-separated",
    # gov/permit_journal.py (wave-250 lane 3): HMAC-SHA256 chain over the
    # event-sourced permit journal (adversarial layer over the durable
    # journal reliability layer). Key resolution: explicit ``key`` kwarg >
    # GOV_PERMIT_JOURNAL_KEY (hex) env > fresh random 32 bytes; <16 bytes
    # refused fail-closed. Durability across restarts requires the
    # deployment to supply a STABLE key (kwarg or env) — documented in the
    # module docstring; HMAC is shared-secret authenticity, not
    # non-repudiation (standing honest residual).
    ("gov/permit_journal.py", "_genesis_mac", 0):
        "permit-journal chain genesis MAC; deployer-held key (kwarg/env), domain-separated",
    ("gov/permit_journal.py", "event_mac", 0):
        "permit-journal per-event chain MAC; deployer-held key (kwarg/env), domain-separated",
    ("gov/permit_journal.py", "_snapshot_mac", 0):
        "permit-journal snapshot MAC; deployer-held key (kwarg/env), domain-separated",
    # gov/encrypted_envelopes.py (wave-257 lane 1): the envelope module's
    # internal HMAC-SHA256 primitives. The keys are EITHER (a) a fresh
    # per-envelope 32-byte random from secrets.token_bytes (the envelope
    # key, generated inside EnvelopeVault.seal, never reused, never
    # persisted), (b) derived via the domain-separated _kdf from (a), or
    # (c) deployment-supplied recipient key material (opaque bytes,
    # minimum 16 bytes enforced, refused loudly via
    # envelope-recipient-refused otherwise; never a default, never
    # hard-coded). All HMAC inputs are domain-separated via _DOMAIN
    # ("sasanam-envelope/v1:"), so KDF/stream/tag domains cannot
    # collide. The HMAC here provides envelope confidentiality (via the
    # HMAC-CTR keystream) and integrity (the envelope tag); it is the
    # module's core primitive, not a bypass of the log-key chokepoint.
    ("gov/encrypted_envelopes.py", "_kdf", 0):
        "envelope KDF; key = fresh per-envelope random or deployment-supplied recipient material, domain-separated",
    ("gov/encrypted_envelopes.py", "_keystream", 0):
        "envelope HMAC-CTR keystream; key = _kdf output (fresh per-envelope random), domain-separated",
    ("gov/encrypted_envelopes.py", "EnvelopeVault.seal", 0):
        "envelope integrity tag; key = _kdf(fresh per-envelope random, payload-mac), domain-separated",
    ("gov/encrypted_envelopes.py", "EnvelopeVault.open", 0):
        "envelope tag re-verification; key = _kdf(unwrapped envelope key, payload-mac), domain-separated",
}


def _iter_py_files():
    return sorted(p for p in GOV_DIR.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _hmac_bindings(tree):
    """Names in this module that resolve to the hmac module / its funcs.

    Returns (module_aliases, func_aliases): e.g. ``import hmac as _h``
    -> module_aliases={"_h"}; ``from hmac import new as _new`` ->
    func_aliases={"_new"}. Handles the obvious aliasing shapes; fully
    dynamic indirection is the documented gap (see module docstring).
    """
    module_aliases = set()
    func_aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "hmac" or a.name.startswith("hmac."):
                    module_aliases.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module == "hmac" or (node.module or "").startswith(
                    "hmac."):
                for a in node.names:
                    if a.name in _HMAC_FUNCS:
                        func_aliases.add(a.asname or a.name)
    return module_aliases, func_aliases


class _SiteVisitor(ast.NodeVisitor):
    """Collect (qualified scope, ordinal) for every hmac key-material call."""

    def __init__(self, module_aliases, func_aliases):
        self._module_aliases = module_aliases
        self._func_aliases = func_aliases
        self._scope = []
        self._ordinals = {}
        self.sites = []  # [(qualified, ordinal)]

    def _is_hmac_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute):
            return (isinstance(func.value, ast.Name)
                    and func.value.id in self._module_aliases
                    and func.attr in _HMAC_FUNCS)
        if isinstance(func, ast.Name):
            return func.id in self._func_aliases
        return False

    def visit_ClassDef(self, node):
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node):
        self._visit_scoped(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_scoped(node)

    def _visit_scoped(self, node):
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_Call(self, node):
        if self._is_hmac_call(node):
            qualified = ".".join(self._scope) if self._scope else \
                "<module>"
            ordinal = self._ordinals.get(qualified, 0)
            self._ordinals[qualified] = ordinal + 1
            self.sites.append((qualified, ordinal))
        self.generic_visit(node)


def find_hmac_sites():
    """Return {(relpath, qualified, ordinal)} for all of gov/."""
    found = set()
    for path in _iter_py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"),
                         filename=str(path))
        module_aliases, func_aliases = _hmac_bindings(tree)
        visitor = _SiteVisitor(module_aliases, func_aliases)
        visitor.visit(tree)
        rel = path.relative_to(REPO_ROOT).as_posix()
        for qualified, ordinal in visitor.sites:
            found.add((rel, qualified, ordinal))
    return found


class HmacChokepointAuditTest(unittest.TestCase):
    def test_no_unguarded_hmac_call_sites(self):
        found = find_hmac_sites()
        allowed = set(ALLOWED_HMAC_SITES)
        new_sites = sorted(found - allowed)
        self.assertEqual(
            new_sites, [],
            "NEW hmac key-material call site(s) under gov/ are not in "
            "the allowlist — every HMAC key path must flow through the "
            "guarded chokepoint (or carry an explicit custody story). "
            "New sites: %s. If a site is legitimate, add it to "
            "ALLOWED_HMAC_SITES in tests/test_w70_hmac_chokepoint_audit.py "
            "with its custody story." % (new_sites,))

    def test_allowlist_has_no_stale_entries(self):
        found = find_hmac_sites()
        allowed = set(ALLOWED_HMAC_SITES)
        stale = sorted(allowed - found)
        self.assertEqual(
            stale, [],
            "Allowlist entries with no matching call site (stale — the "
            "code moved but the allowlist did not): %s. Remove them from "
            "ALLOWED_HMAC_SITES." % (stale,))

    def test_audit_covers_expected_site_count(self):
        # Tripwire against silent audit shrinkage: if a refactor
        # legitimately removes a site, this forces the allowlist edit to
        # be deliberate (the count is asserted, not just set inclusion).
        self.assertEqual(len(find_hmac_sites()), len(ALLOWED_HMAC_SITES))

    def test_every_allowed_site_has_a_custody_story(self):
        for site, story in ALLOWED_HMAC_SITES.items():
            self.assertTrue(
                isinstance(story, str) and len(story.strip()) >= 10,
                "allowlist site %r has no custody story" % (site,))


class HmacAliasHandlingTest(unittest.TestCase):
    """Break-first for the audit itself: the obvious alias shapes must
    resolve to the hmac origin (proven on synthetic ASTs, not the tree)."""

    def _sites_in(self, source):
        tree = ast.parse(source)
        mod_a, func_a = _hmac_bindings(tree)
        v = _SiteVisitor(mod_a, func_a)
        v.visit(tree)
        return v.sites

    def test_plain_import(self):
        sites = self._sites_in(
            "import hmac\nimport hashlib\n"
            "def f(k, m):\n    return hmac.new(k, m, hashlib.sha256)\n")
        self.assertEqual(sites, [("f", 0)])

    def test_module_alias(self):
        sites = self._sites_in(
            "import hmac as _h\nimport hashlib\n"
            "def f(k, m):\n    return _h.new(k, m, hashlib.sha256)\n")
        self.assertEqual(sites, [("f", 0)])

    def test_from_import_alias(self):
        sites = self._sites_in(
            "import hashlib\nfrom hmac import new as _new\n"
            "def f(k, m):\n    return _new(k, m, hashlib.sha256)\n")
        self.assertEqual(sites, [("f", 0)])

    def test_from_import_plain(self):
        sites = self._sites_in(
            "import hashlib\nfrom hmac import digest\n"
            "def f(k, m):\n    return digest(k, m, 'sha256')\n")
        self.assertEqual(sites, [("f", 0)])

    def test_hmac_constructor_shape(self):
        sites = self._sites_in(
            "import hmac\n"
            "class C:\n    def m(self, k):\n        h = hmac.HMAC(k, digestmod='sha256')\n"
            "        return h\n")
        self.assertEqual(sites, [("C.m", 0)])

    def test_unrelated_new_not_flagged(self):
        # A different module's .new() must not be mistaken for hmac.
        sites = self._sites_in(
            "import hashlib\n"
            "def f(m):\n    return hashlib.new('sha256', m)\n")
        self.assertEqual(sites, [])

    def test_ordinal_counts_multiple_sites(self):
        sites = self._sites_in(
            "import hmac\n"
            "def f(k, m):\n    a = hmac.new(k, m, 'sha256')\n"
            "    b = hmac.new(k, m, 'sha256')\n    return a, b\n")
        self.assertEqual(sites, [("f", 0), ("f", 1)])


if __name__ == "__main__":
    unittest.main()
