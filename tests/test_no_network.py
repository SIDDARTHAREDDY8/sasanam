#!/usr/bin/env python3
"""Unit tests for tests/no_network.py (wave-339 lane 3, R19).

The guard's own contract: install/uninstall round-trip, fail-closed
default (non-exempt test files cannot resolve DNS), exemption matching
for the network-machinery files, and all four blocked primitives.
"""

import collections
import os
import socket
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tests import no_network


class _GuardState(object):
    """Preserve the canonical runner's guard across these tests.

    tests/run_tests.py installs the guard for the whole suite; these
    tests install/uninstall it themselves. Without save/restore, our
    tearDown would uninstall the runner's guard for every test module
    that runs after us."""
    def setUp(self):
        self._was_installed = no_network.is_installed()

    def tearDown(self):
        no_network.uninstall()
        if self._was_installed:
            no_network.install()


class TestInstallUninstall(_GuardState, unittest.TestCase):
    def test_install_patches_all_four_primitives(self):
        # Robust to context: under tests/run_tests.py the guard is
        # already installed; standalone it is not.
        was = no_network.is_installed()
        no_network.uninstall()
        try:
            self.assertFalse(no_network.is_installed())
            patched = no_network.install()
            self.assertTrue(no_network.is_installed())
            for name in ("getaddrinfo", "getnameinfo", "gethostbyname",
                         "gethostbyname_ex"):
                self.assertIn(name, patched)
                self.assertTrue(
                    getattr(socket, name).__name__.startswith("blocked_"),
                    name)
        finally:
            no_network.uninstall()
            if was:
                no_network.install()
        self.assertEqual(no_network.is_installed(), was)

    def test_install_idempotent(self):
        no_network.install()
        try:
            self.assertEqual(no_network.install(), no_network.install())
        finally:
            no_network.uninstall()


class TestBlocking(_GuardState, unittest.TestCase):
    def setUp(self):
        super(TestBlocking, self).setUp()
        no_network.install()

    def test_getaddrinfo_blocked_from_non_exempt_test(self):
        # THIS file (test_no_network.py) is not in EXEMPT_FILES.
        with self.assertRaises(no_network.DNSBlockedError) as ctx:
            socket.getaddrinfo("localhost", 80)
        self.assertIn("test_no_network.py", str(ctx.exception))

    def test_all_four_primitives_blocked(self):
        with self.assertRaises(no_network.DNSBlockedError):
            socket.getaddrinfo("localhost", 80)
        with self.assertRaises(no_network.DNSBlockedError):
            socket.getnameinfo(("127.0.0.1", 80), 0)
        with self.assertRaises(no_network.DNSBlockedError):
            socket.gethostbyname("localhost")
        with self.assertRaises(no_network.DNSBlockedError):
            socket.gethostbyname_ex("localhost")

    def test_numeric_literals_pass_through(self):
        # getaddrinfo("127.0.0.1") is pure address parsing -- no DNS --
        # so the hermetic loopback fixtures keep working.
        infos = socket.getaddrinfo("127.0.0.1", 80)
        self.assertTrue(infos)
        infos = socket.getaddrinfo("::1", 80)
        self.assertTrue(infos)
        self.assertEqual(socket.gethostbyname("127.0.0.1"), "127.0.0.1")
        name, _, _ = socket.gethostbyname_ex("127.0.0.1")
        self.assertTrue(name)

    def test_hostname_still_blocked(self):
        with self.assertRaises(no_network.DNSBlockedError):
            socket.getaddrinfo("localhost", 80)
        with self.assertRaises(no_network.DNSBlockedError):
            socket.getaddrinfo("example.com", 80)
        with self.assertRaises(no_network.DNSBlockedError):
            socket.gethostbyname("localhost")

    def test_getnameinfo_needs_numeric_flag(self):
        host, _ = socket.getnameinfo(("127.0.0.1", 80),
                                     socket.NI_NUMERICHOST)
        self.assertEqual(host, "127.0.0.1")
        # Default flags may trigger reverse DNS: blocked.
        with self.assertRaises(no_network.DNSBlockedError):
            socket.getnameinfo(("127.0.0.1", 80), 0)

    def test_is_numeric_host(self):
        self.assertTrue(no_network._is_numeric_host("127.0.0.1"))
        self.assertTrue(no_network._is_numeric_host("::1"))
        self.assertFalse(no_network._is_numeric_host("localhost"))
        self.assertFalse(no_network._is_numeric_host("example.com"))
        self.assertFalse(no_network._is_numeric_host(""))

    def test_dns_blocked_error_is_oserror(self):
        # Product code that catches OSError keeps working (fail-closed,
        # not a novel exception type escaping into weird handlers).
        self.assertTrue(issubclass(no_network.DNSBlockedError, OSError))


class TestExemptions(_GuardState, unittest.TestCase):
    def setUp(self):
        super(TestExemptions, self).setUp()
        no_network.install()

    def _fake_stack(self, filename):
        FrameInfo = collections.namedtuple(
            "FrameInfo",
            "frame filename lineno function code_context index")
        return [FrameInfo(None, filename, 1, "f", None, None)]

    def test_exempt_file_passes_through(self):
        exempt = os.path.join(no_network._TESTS_DIR, "test_sandbox.py")
        orig_stack = no_network.inspect.stack
        no_network.inspect.stack = lambda *a, **k: self._fake_stack(exempt)
        try:
            # Must NOT raise: the caller frame is an exempt file.
            socket.getaddrinfo("localhost", 80)
        finally:
            no_network.inspect.stack = orig_stack

    def test_non_exempt_file_blocked_via_fake_stack(self):
        other = os.path.join(no_network._TESTS_DIR, "test_policy.py")
        orig_stack = no_network.inspect.stack
        no_network.inspect.stack = lambda *a, **k: self._fake_stack(other)
        try:
            with self.assertRaises(no_network.DNSBlockedError):
                socket.getaddrinfo("localhost", 80)
        finally:
            no_network.inspect.stack = orig_stack

    def test_same_basename_elsewhere_not_exempt(self):
        # Exemption matches by absolute path: a same-named file outside
        # tests/ is NOT exempt.
        elsewhere = "/tmp/evil/test_sandbox.py"
        orig_stack = no_network.inspect.stack
        no_network.inspect.stack = lambda *a, **k: self._fake_stack(elsewhere)
        try:
            with self.assertRaises(no_network.DNSBlockedError):
                socket.getaddrinfo("localhost", 80)
        finally:
            no_network.inspect.stack = orig_stack

    def test_every_exempt_file_exists(self):
        # An exemption for a file that no longer exists is dead config;
        # fail the suite instead of silently carrying it.
        for name in no_network.EXEMPT_FILES:
            self.assertTrue(
                os.path.isfile(os.path.join(no_network._TESTS_DIR, name)),
                "exempt file missing: %s" % name)


if __name__ == "__main__":
    unittest.main()
