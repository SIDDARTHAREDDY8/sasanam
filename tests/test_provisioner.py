#!/usr/bin/env python3
"""Unit tests for wave-196 lane C: the step-ca provisioner steal.

Covers the public seams only (never internal helper names):
  - gov.provisioner.LifetimeClaims (validation, default_ttl)
  - gov.provisioner.Provisioner.authorize_mint / renewal_allowed
  - gov.provisioner.BreakGlassProvisioner (justification gate)
  - gov.provisioner.ProvisionerRegistry (construction, lookup)
  - ToolExecutor.mint_identity(..., provisioner=..., ttl_seconds=...,
    scopes=..., justification=...)

The break battery (evals/provisioner_probes.py) covers the full
public-seam refusal matrix; these tests pin the model's edges.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov.provisioner import (  # noqa: E402
    BreakGlassProvisioner,
    BreakGlassRefusedError,
    LifetimeClaims,
    Provisioner,
    ProvisionerRefusedError,
    ProvisionerRegistry,
    ProvisionerType,
    UnknownProvisionerError,
)


def _claims(**over):
    base = dict(max_ttl_seconds=3600,
                allowed_scopes=frozenset({"tools:read", "tools:write"}),
                allowed_roles=frozenset({"operator", "coder"}))
    base.update(over)
    return LifetimeClaims(**base)


def _registry():
    return ProvisionerRegistry([
        Provisioner("dex-prod", ProvisionerType.OIDC, _claims()),
        Provisioner("workload-run", ProvisionerType.WORKLOAD,
                    _claims(max_ttl_seconds=600, min_ttl_seconds=60,
                            allowed_scopes=frozenset({"tools:read"}),
                            max_mints_per_run=2)),
        BreakGlassProvisioner("break-glass-1"),
    ])


class LifetimeClaimsValidation(unittest.TestCase):
    def test_zero_max_ttl_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=0)

    def test_negative_max_ttl_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=-5)

    def test_bool_max_ttl_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=True)

    def test_str_max_ttl_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds="3600")

    def test_min_above_max_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=60, min_ttl_seconds=61)

    def test_bad_revocation_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=60, revocation="ocsp")

    def test_keyset_revocation_accepted(self):
        c = LifetimeClaims(max_ttl_seconds=60, revocation="keyset")
        self.assertEqual(c.revocation, "keyset")

    def test_empty_scope_collection_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=60, allowed_scopes=set())

    def test_blank_scope_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=60,
                           allowed_scopes={"tools:read", " "})

    def test_bad_budget_rejected(self):
        with self.assertRaises(ValueError):
            LifetimeClaims(max_ttl_seconds=60, max_mints_per_run=0)

    def test_default_ttl_capped_by_max(self):
        self.assertEqual(_claims(max_ttl_seconds=600).default_ttl(), 600)
        self.assertEqual(_claims(max_ttl_seconds=7200).default_ttl(), 3600)

    def test_scope_strings_normalized(self):
        c = LifetimeClaims(max_ttl_seconds=60,
                           allowed_scopes=["tools:read", "tools:read "])
        self.assertEqual(c.allowed_scopes, frozenset({"tools:read"}))


class AuthorizeMint(unittest.TestCase):
    def setUp(self):
        self.p = Provisioner("dex-prod", ProvisionerType.OIDC, _claims())

    def _ok(self, **kw):
        args = dict(ttl_seconds=600, scopes=["tools:read"],
                    justification=None, role="operator")
        args.update(kw)
        return self.p.authorize_mint(**args)

    def test_within_policy(self):
        ok, _ = self._ok()
        self.assertTrue(ok)

    def test_ttl_over_max(self):
        ok, why = self._ok(ttl_seconds=3601)
        self.assertFalse(ok)
        self.assertIn("3600", why)

    def test_ttl_at_max(self):
        ok, _ = self._ok(ttl_seconds=3600)
        self.assertTrue(ok)

    def test_ttl_under_min(self):
        p = Provisioner("w", ProvisionerType.WORKLOAD,
                        _claims(min_ttl_seconds=60))
        ok, why = p.authorize_mint(30, [], None, "operator")
        self.assertFalse(ok)
        self.assertIn("min_ttl", why)

    def test_scope_outside_grant(self):
        ok, why = self._ok(scopes=["pii:export"])
        self.assertFalse(ok)
        self.assertIn("pii:export", why)

    def test_role_outside_grant(self):
        ok, why = self._ok(role="auditor")
        self.assertFalse(ok)
        self.assertIn("auditor", why)

    def test_ttl_must_be_int(self):
        ok, _ = self._ok(ttl_seconds="600")
        self.assertFalse(ok)
        ok, _ = self._ok(ttl_seconds=True)
        self.assertFalse(ok)

    def test_scope_must_be_strings(self):
        ok, _ = self._ok(scopes=[123])
        self.assertFalse(ok)

    def test_justification_ignored_by_base(self):
        # Documented: only the break-glass type gates on justification.
        ok, _ = self._ok(justification=None)
        self.assertTrue(ok)
        ok, _ = self._ok(justification="not needed here")
        self.assertTrue(ok)

    def test_unrestricted_scopes_when_none(self):
        p = Provisioner("open", ProvisionerType.OPERATOR,
                        LifetimeClaims(max_ttl_seconds=60))
        ok, _ = p.authorize_mint(30, ["anything:goes"], None, "anyrole")
        self.assertTrue(ok)

    def test_empty_scopes_under_scoped_grant_refused(self):
        # An empty-scoped mint under a real grant list would evade the
        # grant: refuse rather than mint a scope the grant never names.
        ok, why = self._ok(scopes=[])
        self.assertFalse(ok)
        self.assertIn("no scopes requested", why)

    def test_empty_scopes_ok_when_unrestricted(self):
        p = Provisioner("open", ProvisionerType.OPERATOR,
                        LifetimeClaims(max_ttl_seconds=60))
        ok, _ = p.authorize_mint(30, [], None, "anyrole")
        self.assertTrue(ok)

    def test_requires_presented_token(self):
        oidc = Provisioner("o", ProvisionerType.OIDC, _claims())
        self.assertTrue(oidc.requires_presented_token())
        for t in (ProvisionerType.JWK, ProvisionerType.OPERATOR,
                  ProvisionerType.WORKLOAD):
            p = Provisioner("x", t, LifetimeClaims(max_ttl_seconds=60))
            self.assertFalse(p.requires_presented_token())
        self.assertFalse(BreakGlassProvisioner("bg").requires_presented_token())

    def test_as_audit_dict(self):
        d = _claims(max_mints_per_run=3).as_audit_dict()
        self.assertEqual(d["max_ttl_seconds"], 3600)
        self.assertEqual(d["allowed_scopes"], ["tools:read", "tools:write"])
        self.assertEqual(d["allowed_roles"], ["coder", "operator"])
        self.assertEqual(d["max_mints_per_run"], 3)
        self.assertEqual(d["revocation"], "expiry")
        self.assertIsNone(
            LifetimeClaims(max_ttl_seconds=60).as_audit_dict()
            ["allowed_scopes"])


class RenewalAllowed(unittest.TestCase):
    def test_renewal_allowed_when_live(self):
        p = Provisioner("d", ProvisionerType.OIDC, _claims())
        ok, _ = p.renewal_allowed(1000, 4600, now_epoch=2000)
        self.assertTrue(ok)

    def test_disabled_renewal(self):
        p = BreakGlassProvisioner("bg")
        ok, why = p.renewal_allowed(1000, 1300, now_epoch=1100)
        self.assertFalse(ok)
        self.assertIn("disabled", why)

    def test_no_renewal_after_expiry_by_default(self):
        p = Provisioner("d", ProvisionerType.OIDC, _claims())
        ok, why = p.renewal_allowed(1000, 1300, now_epoch=5000)
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_renewal_after_expiry_when_allowed(self):
        c = _claims()
        c = LifetimeClaims(max_ttl_seconds=3600,
                           allow_renewal_after_expiry=True)
        p = Provisioner("d", ProvisionerType.OIDC, c)
        ok, _ = p.renewal_allowed(1000, 1300, now_epoch=5000)
        self.assertTrue(ok)

    def test_renewal_window(self):
        c = LifetimeClaims(max_ttl_seconds=3600,
                           renewal_window_seconds=300)
        p = Provisioner("d", ProvisionerType.OIDC, c)
        ok, _ = p.renewal_allowed(1000, 4600, now_epoch=2000)
        self.assertFalse(ok)
        ok, _ = p.renewal_allowed(1000, 4600, now_epoch=4400)
        self.assertTrue(ok)

    def test_malformed_epochs(self):
        p = Provisioner("d", ProvisionerType.OIDC, _claims())
        ok, _ = p.renewal_allowed(4600, 1000, now_epoch=2000)
        self.assertFalse(ok)
        ok, _ = p.renewal_allowed("x", 4600, now_epoch=2000)
        self.assertFalse(ok)


class BreakGlassProvisionerTest(unittest.TestCase):
    def setUp(self):
        self.bg = BreakGlassProvisioner("break-glass-1")

    def test_missing_justification_refused(self):
        ok, why = self.bg.authorize_mint(120, [], None, "operator")
        self.assertFalse(ok)
        self.assertIn("justification", why)

    def test_blank_justification_refused(self):
        ok, _ = self.bg.authorize_mint(120, [], "   ", "operator")
        self.assertFalse(ok)

    def test_non_string_justification_refused(self):
        ok, _ = self.bg.authorize_mint(120, [], 12345, "operator")
        self.assertFalse(ok)

    def test_justified_within_ttl(self):
        ok, _ = self.bg.authorize_mint(120, [], "INC-1", "operator")
        self.assertTrue(ok)

    def test_default_max_ttl_is_300(self):
        self.assertEqual(self.bg.claims.max_ttl_seconds, 300)
        ok, _ = self.bg.authorize_mint(301, [], "INC-1", "operator")
        self.assertFalse(ok)

    def test_default_disables_renewal(self):
        self.assertTrue(self.bg.claims.disable_renewal)
        self.assertFalse(self.bg.claims.allow_renewal_after_expiry)

    def test_type_is_break_glass(self):
        self.assertEqual(self.bg.provisioner_type, ProvisionerType.BREAK_GLASS)

    def test_custom_claims_envelope(self):
        c = LifetimeClaims(max_ttl_seconds=120)
        bg = BreakGlassProvisioner("bg2", claims=c)
        ok, _ = bg.authorize_mint(121, [], "INC-1", "operator")
        self.assertFalse(ok)


class ProvisionerRegistryTest(unittest.TestCase):
    def test_iterable_construction(self):
        r = _registry()
        self.assertEqual(r.names(),
                         ["break-glass-1", "dex-prod", "workload-run"])
        self.assertEqual(len(r), 3)
        self.assertIn("dex-prod", r)

    def test_dict_construction(self):
        p = Provisioner("a", ProvisionerType.JWK,
                        LifetimeClaims(max_ttl_seconds=60))
        r = ProvisionerRegistry({"a": p})
        self.assertIs(r.get("a"), p)

    def test_unknown_raises(self):
        r = _registry()
        with self.assertRaises(UnknownProvisionerError):
            r.get("nope")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            ProvisionerRegistry([])

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            ProvisionerRegistry([
                Provisioner("a", ProvisionerType.JWK,
                            LifetimeClaims(max_ttl_seconds=60)),
                Provisioner("a", ProvisionerType.OIDC,
                            LifetimeClaims(max_ttl_seconds=60)),
            ])

    def test_non_provisioner_rejected(self):
        with self.assertRaises(ValueError):
            ProvisionerRegistry({"a": "not-a-provisioner"})

    def test_bad_type_rejected(self):
        with self.assertRaises(ValueError):
            Provisioner("a", "tpm-attested",
                        LifetimeClaims(max_ttl_seconds=60))

    def test_bad_name_rejected(self):
        with self.assertRaises(ValueError):
            Provisioner("", ProvisionerType.OIDC,
                        LifetimeClaims(max_ttl_seconds=60))


class ExceptionHierarchy(unittest.TestCase):
    def test_break_glass_is_provisioner_refused(self):
        self.assertTrue(issubclass(BreakGlassRefusedError,
                                   ProvisionerRefusedError))

    def test_unknown_is_provisioner_refused(self):
        self.assertTrue(issubclass(UnknownProvisionerError,
                                   ProvisionerRefusedError))


class MintIdentityProvisionerSeam(unittest.TestCase):
    """ToolExecutor.mint_identity through the provisioner seam."""

    _ALLOW_ALL = """\
version: 2
roles:
  operator: [read_file]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file]
    reason: provisioner fixture
"""

    def _executor(self, registry=None):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govprovut-"))
        (run_dir / "policy.yaml").write_text(self._ALLOW_ALL)
        policy = PolicyEngine(str(run_dir / "policy.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        kwargs = dict(
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="provisioner test: synthetic executor")
        if registry is not None:
            kwargs["provisioner_registry"] = registry
        ex = ToolExecutor(run_dir, policy, log, approvals, **kwargs)
        return ex, run_dir

    def _events(self, run_dir, name):
        out = []
        with open(run_dir / "actions.jsonl", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    e = json.loads(line)
                    if e.get("event") == name:
                        out.append(e)
        return out

    def _mint(self, ex, **kw):
        return ex.mint_identity("agent:org1:run-7", "operator", "org1",
                                **kw)

    def _token(self, lifetime=600, **over):
        now = int(time.time())
        c = {"iss": "https://dex.sasanam.internal",
             "sub": "agent:org1:run-7",
             "aud": "sasanam-policy-engine", "iat": now,
             "exp": now + lifetime, "jti": "ut-jti-1",
             "principal": "org1", "role": "operator",
             "agent_scope": "tools:read"}
        c.update(over)
        return c

    def test_valid_mint_records_lifetime_claims(self):
        ex, run_dir = self._executor(_registry())
        ident = self._mint(ex, provisioner="dex-prod", ttl_seconds=600,
                           scopes=["tools:read"],
                           token_claims=self._token())
        self.assertEqual(ident.agent_id, "agent:org1:run-7")
        minted = self._events(run_dir, "identity_minted")
        self.assertEqual(len(minted), 1)
        e = minted[0]
        self.assertEqual(e["provisioner"], "dex-prod")
        self.assertEqual(e["provisioner_type"], "oidc")
        self.assertEqual(e["ttl_seconds"], 600)
        self.assertTrue(e["expires_at"])
        self.assertEqual(e["scopes"], ["tools:read"])
        self.assertTrue(e["renewable"])
        self.assertEqual(e["revocation"], "expiry")
        # The authorizing envelope is on the chain too, so the policy
        # decision is reconstructible without the deployment config.
        self.assertEqual(e["policy"]["max_ttl_seconds"], 3600)
        self.assertEqual(e["policy"]["allowed_scopes"],
                         ["tools:read", "tools:write"])
        self.assertEqual(e["policy"]["allowed_roles"],
                         ["coder", "operator"])

    def test_ttl_over_max_refused_no_budget(self):
        ex, run_dir = self._executor(_registry())
        before = ex._mint_count
        with self.assertRaises(ProvisionerRefusedError):
            self._mint(ex, provisioner="dex-prod", ttl_seconds=7200,
                       token_claims=self._token())
        self.assertEqual(ex._mint_count, before)
        refused = self._events(run_dir, "identity_mint_refused")
        self.assertTrue(refused)
        self.assertEqual(refused[0]["policy_id"], "provisioner:dex-prod")

    def test_oidc_provisioner_requires_presented_token(self):
        # The OIDC attestation method attests via the dex-issued JWT:
        # no presented token, no attestation -- fail closed.
        ex, _ = self._executor(_registry())
        with self.assertRaises(ProvisionerRefusedError) as cm:
            self._mint(ex, provisioner="dex-prod", ttl_seconds=600,
                       scopes=["tools:read"])
        self.assertIn("oidc", str(cm.exception))

    def test_bad_registry_type_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            self._executor(registry={"dex-prod": "not-a-provisioner"})

    def test_unrestricted_scope_grant_warns_loudly(self):
        import contextlib
        import io
        import uuid
        name = "warn-ut-%s" % uuid.uuid4().hex[:8]
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            Provisioner(name, ProvisionerType.OPERATOR,
                        LifetimeClaims(max_ttl_seconds=60))
        self.assertIn("UNRESTRICTED", buf.getvalue())
        # Once per process: the second construction stays silent.
        buf2 = io.StringIO()
        with contextlib.redirect_stderr(buf2):
            Provisioner(name, ProvisionerType.OPERATOR,
                        LifetimeClaims(max_ttl_seconds=60))
        self.assertEqual(buf2.getvalue(), "")

    def test_break_glass_needs_justification(self):
        ex, _ = self._executor(_registry())
        with self.assertRaises(BreakGlassRefusedError):
            self._mint(ex, provisioner="break-glass-1", ttl_seconds=120)

    def test_break_glass_justified_is_loud(self):
        ex, run_dir = self._executor(_registry())
        self._mint(ex, provisioner="break-glass-1", ttl_seconds=120,
                   justification="INC-2049")
        bg = self._events(run_dir, "identity_break_glass_minted")
        self.assertEqual(len(bg), 1)
        self.assertEqual(bg[0]["justification"], "INC-2049")
        minted = self._events(run_dir, "identity_minted")
        self.assertFalse(minted[0]["renewable"])

    def test_unknown_provisioner(self):
        ex, _ = self._executor(_registry())
        with self.assertRaises(UnknownProvisionerError):
            self._mint(ex, provisioner="nope", ttl_seconds=60)

    def test_policy_args_without_registry_fail_closed(self):
        ex, _ = self._executor()  # no registry
        with self.assertRaises(ProvisionerRefusedError):
            self._mint(ex, provisioner="dex-prod", ttl_seconds=60)

    def test_legacy_mint_without_registry(self):
        ex, run_dir = self._executor()  # no registry: legacy path
        ident = self._mint(ex)
        self.assertEqual(ident.agent_id, "agent:org1:run-7")
        minted = self._events(run_dir, "identity_minted")
        # Legacy: no registry -> no issuance event (unchanged behavior).
        self.assertEqual(minted, [])

    def test_per_provisioner_budget(self):
        ex, _ = self._executor(_registry())
        self._mint(ex, provisioner="workload-run", ttl_seconds=120,
                   scopes=["tools:read"])
        self._mint(ex, provisioner="workload-run", ttl_seconds=120,
                   scopes=["tools:read"])
        with self.assertRaises(ProvisionerRefusedError):
            self._mint(ex, provisioner="workload-run", ttl_seconds=120,
                       scopes=["tools:read"])
        # The other provisioner still has budget (oidc needs its token).
        self._mint(ex, provisioner="dex-prod", ttl_seconds=60,
                   token_claims=self._token())


if __name__ == "__main__":
    unittest.main()
