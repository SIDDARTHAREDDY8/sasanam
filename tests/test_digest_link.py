#!/usr/bin/env python3
"""Unit tests for gov/digest_link.py (wave-222 lane B).

Tests the public seams: bind_credential_to_render,
check_approval_flow, check_digest_format. Expected values are
independent literals (hand-derived), never recomputed the way the
module computes them.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import digest_link as dl  # noqa: E402
from gov import permit_leases as pl  # noqa: E402
from gov import render_commit as rc  # noqa: E402

# Hand-derived 64-hex literals (echo -n '...' | sha256sum, run once
# by the test author, pasted here — never computed in the test).
D1 = ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd"
      "15d6c15b0f00a08")
D2 = ("sha256:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b467"
      "29d73a27fb57e9")
D3 = ("sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c"
      "01e52ddb7875b4b")
HD1 = ("hmac-sha256-v1:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd"
       "15d6c15b0f00a08")


class BindTests(unittest.TestCase):
    def test_equal_digests_bind_with_exact_key_set(self):
        link = dl.bind_credential_to_render(D1, D1)
        # Exact key set: no authority-shaped field may ever appear
        # (permit_id, scope, grant, issued ...). Independence check
        # against the module constant, not its own literal.
        self.assertEqual(set(link), {"credential_digest", "render_digest",
                                     "bound_at"})
        self.assertEqual(link["credential_digest"], D1)
        self.assertEqual(link["render_digest"], D1)
        self.assertTrue(link["bound_at"])  # non-empty audit stamp

    def test_hmac_scheme_binds(self):
        link = dl.bind_credential_to_render(HD1, HD1)
        self.assertEqual(link["credential_digest"], HD1)

    def test_unequal_digests_refuse_named(self):
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(D1, D2)
        self.assertEqual(ctx.exception.code, "digest-linkage-mismatch")

    def test_scheme_mismatch_refuses_mismatch_not_malformed(self):
        # Both digests are well-formed but different schemes/hashes:
        # the refusal must be mismatch, not malformed.
        d3 = "hmac-sha256-v1:" + "ab" * 32
        d4 = "sha256:" + "ab" * 32
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(d3, d4)
        self.assertEqual(ctx.exception.code, "digest-linkage-mismatch")

    def test_nonhex_refuses(self):
        bad = "sha256:" + "zz" * 32
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(bad, bad)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_short_hex_refuses(self):
        bad = "sha256:" + "ab" * 31
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(D1, bad)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_uppercase_hex_refuses(self):
        bad = "sha256:" + "AB" * 32
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(bad, bad)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_empty_string_refuses(self):
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render("", "")
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_unknown_scheme_refuses(self):
        bad = "md5:" + "ab" * 32
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(bad, bad)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_none_refuses(self):
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.bind_credential_to_render(None, D1)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_error_code_constants_match_classes(self):
        self.assertEqual(dl.DigestLinkError("x",
                                            code="digest-linkage-mismatch"
                                            ).code,
                         "digest-linkage-mismatch")


def _lease(digest):
    return pl.PermitLease.issue("permit-unit", params_digest=digest,
                               grant_scope={"action": {"read"}})


def _commitment(digest):
    return rc.commit(b"unit render bytes", digest,
                     renderer_id="unit-view")


class FlowTests(unittest.TestCase):
    def test_matching_flow_passes(self):
        self.assertTrue(dl.check_approval_flow(_lease(D1),
                                               _commitment(D1)))

    def test_matching_hmac_flow_passes(self):
        self.assertTrue(dl.check_approval_flow(_lease(HD1),
                                               _commitment(HD1)))

    def test_diverged_flow_refuses_named(self):
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.check_approval_flow(_lease(D1), _commitment(D2))
        self.assertEqual(ctx.exception.code, "approval-digest-diverged")

    def test_absent_lease_passes_legacy(self):
        self.assertTrue(dl.check_approval_flow(None, _commitment(D1)))

    def test_absent_commitment_passes_legacy(self):
        self.assertTrue(dl.check_approval_flow(_lease(D1), None))

    def test_absent_both_passes_legacy(self):
        self.assertTrue(dl.check_approval_flow(None, None))

    def test_linkage_dict_as_lease_fails_closed(self):
        link = dl.bind_credential_to_render(D1, D1)
        with self.assertRaises(TypeError):
            dl.check_approval_flow(link, _commitment(D1))

    def test_bare_dict_as_lease_fails_closed(self):
        with self.assertRaises(TypeError):
            dl.check_approval_flow({"permit_id": "x"}, _commitment(D1))

    def test_linkage_dict_as_commitment_fails_closed(self):
        link = dl.bind_credential_to_render(D1, D1)
        with self.assertRaises(rc.RenderingCommitmentError) as ctx:
            dl.check_approval_flow(_lease(D1), link)
        self.assertEqual(ctx.exception.code, "rendering-commitment-broken")

    def test_malformed_commitment_fails_closed(self):
        with self.assertRaises(rc.RenderingCommitmentError):
            dl.check_approval_flow(_lease(D1),
                                   {"artifact_digest": D1})

    def test_malformed_lease_digest_refuses_named(self):
        lease = _lease("garbage-digest")
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.check_approval_flow(lease, _commitment(D1))
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_malformed_commitment_digest_refuses_named(self):
        commitment = _commitment(D1)
        commitment["artifact_digest"] = "sha256:" + "ab" * 10
        with self.assertRaises(dl.DigestLinkError) as ctx:
            dl.check_approval_flow(_lease(D1), commitment)
        self.assertEqual(ctx.exception.code, "digest-linkage-malformed")

    def test_refusal_audit_visible(self):
        seen = []
        with self.assertRaises(dl.DigestLinkError):
            dl.check_approval_flow(_lease(D1), _commitment(D2),
                                   audit=seen.append)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["code"], "approval-digest-diverged")
        self.assertEqual(seen[0]["event"], "digest_link_refused")

    def test_no_audit_on_success(self):
        seen = []
        dl.check_approval_flow(_lease(D1), _commitment(D1),
                               audit=seen.append)
        self.assertEqual(seen, [])


class FormatTests(unittest.TestCase):
    def test_check_digest_format_accepts_both_schemes(self):
        self.assertTrue(dl.check_digest_format(D1, "t"))
        self.assertTrue(dl.check_digest_format(HD1, "t"))

    def test_check_digest_format_rejects_with_named_code(self):
        for bad in ("", "sha256:", "SHA256:" + "ab" * 32,
                    "sha256:ab", 123, b"sha256:" + b"ab" * 32):
            with self.assertRaises(dl.DigestLinkError) as ctx:
                dl.check_digest_format(bad, "t")
            self.assertEqual(ctx.exception.code,
                             "digest-linkage-malformed")


if __name__ == "__main__":
    unittest.main(verbosity=1)
