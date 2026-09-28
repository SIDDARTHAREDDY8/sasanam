"""AuthorityProof install_package coverage (F193, CLOSED wave-178).

install_package fetches from a package registry (egress), writes
files, and installs executable code, but its declared args carry only
name/version -- the per-shape derivations model nothing for it. The
checker now derives the governed registry host set as egress accesses
(ctx["registry_hosts"] override, else gov.supplychain_install's
REGISTRY_HOSTS) and the declared install target as a filesystem
write; per in-toto REQUIRE semantics a proof for install_package must
not claim a domain covered while deriving zero accesses there, so an
undeclared target names "filesystem" uncovered instead of passing
vacuously, and unattestable materials fail closed as unsupported.

Deterministic, synthetic, no network, no filesystem mutation.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import authority_proof as ap

REGISTRIES = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
              "registry.synthetic.local")


def _boundary(fs_write=(), egress=()):
    return ap.boundary_from_dict({
        "boundary_id": "f193-test", "version": "1",
        "fs_write_prefixes": list(fs_write),
        "egress_hosts": list(egress),
    })


def _action(tool, args):
    return {"tool": tool, "args": dict(args),
            "agent_id": "f193-agent", "role": "coder"}


def _install(args, ctx=None, boundary=None):
    return ap.check(_action("install_package", args), ctx or {},
                    boundary if boundary is not None else _boundary(
                        fs_write=("/sandbox",), egress=REGISTRIES))


class InstallPackageProofTest(unittest.TestCase):
    def test_exceeds_when_no_registry_covered(self):
        # close-when red-first: boundary excludes every registry host.
        b = _boundary(fs_write=("/sandbox",),
                      egress=("registry.internal.example.com",))
        p = ap.check(_action("install_package",
                             {"name": "requests", "version": "2.32.3"}),
                     {}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertIsNotNone(p.counterexample)
        self.assertEqual(p.counterexample.domain, "egress")
        self.assertIn(p.counterexample.access, REGISTRIES)

    def test_all_registries_must_be_covered(self):
        # The checker cannot attest which registry a fetch hits, so
        # every candidate must be boundary-covered.
        b = _boundary(fs_write=("/sandbox",),
                      egress=("pypi.org", "files.pythonhosted.org",
                              "registry.npmjs.org"))
        p = ap.check(_action("install_package",
                             {"name": "requests", "version": "2.32.3"}),
                     {}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertEqual(p.counterexample.access, "registry.synthetic.local")

    def test_filesystem_uncovered_without_declared_target(self):
        # Evidence honesty: no install target declared -> the proof
        # must not claim filesystem covered.
        p = _install({"name": "requests", "version": "2.32.3"})
        self.assertEqual(p.verdict, "within_boundary")
        self.assertNotIn("filesystem", p.covered_domains)
        self.assertIn("filesystem", p.uncovered_domains)
        self.assertIn("egress", p.covered_domains)
        self.assertIn("process_identity", p.uncovered_domains)

    def test_declared_target_write_is_boundary_checked(self):
        b = _boundary(fs_write=("/sandbox",), egress=REGISTRIES)
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3",
                     "path": "/elsewhere/pkg"}),
            {"path_resolved": "/elsewhere/pkg",
             "sandbox_root": "/sandbox"}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertEqual(p.counterexample.domain, "filesystem")

    def test_declared_target_inside_boundary_within_and_covered(self):
        b = _boundary(fs_write=("/sandbox",), egress=REGISTRIES)
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3",
                     "path": "/sandbox/pkg"}),
            {"path_resolved": "/sandbox/pkg",
             "sandbox_root": "/sandbox"}, b)
        self.assertEqual(p.verdict, "within_boundary")
        self.assertIn("filesystem", p.covered_domains)

    def test_ctx_registry_hosts_override(self):
        b = _boundary(fs_write=("/sandbox",),
                      egress=("mirror.example.com",))
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3"}),
            {"registry_hosts": ("mirror.example.com",)}, b)
        self.assertEqual(p.verdict, "within_boundary")
        # ... and exceeding the override refuses.
        p2 = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3"}),
            {"registry_hosts": ("mirror.example.com",)},
            _boundary(fs_write=("/sandbox",),
                      egress=("other.example.com",)))
        self.assertEqual(p2.verdict, "exceeds_boundary")

    def test_hostile_registry_hosts_fail_closed(self):
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3"}),
            {"registry_hosts": ("*.evil.example",)},
            _boundary(fs_write=("/sandbox",), egress=REGISTRIES))
        self.assertEqual(p.verdict, "unsupported")

    def test_unavailable_registry_set_fails_closed(self):
        # Standalone use without the product registry module: absent
        # materials refuse, never pass vacuously.
        with mock.patch.object(ap, "_default_registry_hosts",
                               return_value=None):
            p = ap.check(
                _action("install_package",
                        {"name": "requests", "version": "2.32.3"}),
                {},
                _boundary(fs_write=("/sandbox",), egress=REGISTRIES))
        self.assertEqual(p.verdict, "unsupported")

    def test_malformed_declared_target_fails_closed(self):
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3",
                     "path": "/sandbox/\x00evil"}),
            {"sandbox_root": "/sandbox"},
            _boundary(fs_write=("/sandbox",), egress=REGISTRIES))
        self.assertEqual(p.verdict, "unsupported")

    def test_dotdot_target_fails_closed(self):
        p = ap.check(
            _action("install_package",
                    {"name": "requests", "version": "2.32.3",
                     "path": "/sandbox/../evil"}),
            {"sandbox_root": "/sandbox"},
            _boundary(fs_write=("/sandbox",), egress=REGISTRIES))
        self.assertEqual(p.verdict, "unsupported")

    def test_proof_never_upgrades_a_deny(self):
        # The proof is evidence, not authority: a within_boundary
        # proof on an allowlisted-shaped install says nothing about
        # the policy verdict (P7 allowlist/pin still decides).
        p = _install({"name": "not-a-pinned-package", "version": "9.9.9"})
        self.assertEqual(p.verdict, "within_boundary")

    def test_determinism(self):
        a = _install({"name": "requests", "version": "2.32.3"})
        b = _install({"name": "requests", "version": "2.32.3"})
        self.assertEqual(a.to_dict(), b.to_dict())

    def test_other_tools_unchanged(self):
        # write_file keeps the full coverage claim; the narrowing
        # applies only to tools in _REQUIRED_ACCESS_DOMAINS.
        p = ap.check(
            _action("write_file", {"path": "/sandbox/a.txt"}),
            {"path_resolved": "/sandbox/a.txt",
             "sandbox_root": "/sandbox"},
            _boundary(fs_write=("/sandbox",), egress=()))
        self.assertEqual(p.verdict, "within_boundary")
        self.assertEqual(set(p.covered_domains), set(ap.COVERED_DOMAINS))
        # A tool with genuinely no domain effects keeps full coverage.
        p2 = ap.check(_action("window_close", {}), {},
                      _boundary(fs_write=("/sandbox",), egress=()))
        self.assertEqual(p2.verdict, "within_boundary")
        self.assertEqual(set(p2.covered_domains), set(ap.COVERED_DOMAINS))


if __name__ == "__main__":
    unittest.main()
