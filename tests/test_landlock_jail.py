"""Unit tests for gov/landlock_jail.py (wave-331 lane 3).

Covers the standalone API (landlock_supported/restrict_fs/LandlockError)
and the module move (gov.sandbox re-exports stay identical). Enforcement
tests fork before confining; the test process itself is never jailed.
"""

import errno
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import landlock_jail as lj  # noqa: E402
from gov import sandbox as sbmod  # noqa: E402

NEEDS_LL = lj.landlock_supported()


@unittest.skipUnless(NEEDS_LL, "Landlock not enforceable on this kernel")
class RestrictFsEnforcementTest(unittest.TestCase):
    def _confined(self, grant_fn):
        """Fork; child applies grant_fn (must call restrict_fs)."""
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                grant_fn()
                os.write(w, b"OK")
            except lj.LandlockError as exc:
                os.write(w, ("REFUSED:" + exc.code).encode())
            except BaseException as exc:  # noqa: BLE001
                os.write(w, ("ERR:%r" % (exc,)).encode())
            os.close(w)
            os._exit(0)
        os.close(w)
        out = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            out += chunk
        os.close(r)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        return out

    def test_grant_applies_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._confined(lambda: lj.restrict_fs([tmp], []))
            self.assertEqual(out, b"OK")

    def test_write_denied_outside_write_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            ro = os.path.join(tmp, "ro")
            os.makedirs(ro)
            r, w = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r)
                try:
                    lj.restrict_fs([ro], [])
                    try:
                        open(os.path.join(ro, "x"), "w")
                        os.write(w, b"ALLOWED")
                    except OSError as e:
                        os.write(w, b"EACCES"
                                 if e.errno == errno.EACCES else b"OTHER")
                except BaseException as e:  # noqa: BLE001
                    os.write(w, ("ERR:%r" % (e,)).encode())
                os.close(w)
                os._exit(0)
            os.close(w)
            out = b""
            while True:
                c = os.read(r, 4096)
                if not c:
                    break
                out += c
            os.close(r)
            _, st = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(st), 0)
            self.assertEqual(out, b"EACCES")


class RefusalTest(unittest.TestCase):
    def test_unsupported_kernel_refuses_coded(self):
        real_avail = lj._LANDLOCK_AVAILABLE_CACHE["available"]
        real_abi = lj._LANDLOCK_ABI_CACHE["version"]
        lj._LANDLOCK_AVAILABLE_CACHE["available"] = False
        lj._LANDLOCK_ABI_CACHE["version"] = 0
        try:
            with self.assertRaises(lj.LandlockError) as cm:
                lj.restrict_fs(["/tmp"], [])
            self.assertEqual(cm.exception.code,
                             "sandbox-landlock-unavailable")
        finally:
            lj._LANDLOCK_AVAILABLE_CACHE["available"] = real_avail
            lj._LANDLOCK_ABI_CACHE["version"] = real_abi

    def test_relative_path_refused(self):
        with self.assertRaises(lj.LandlockError) as cm:
            lj.restrict_fs(["rel/path"], [])
        self.assertEqual(cm.exception.code, "sandbox-landlock-apply-failed")

    def test_missing_path_refused(self):
        with self.assertRaises(lj.LandlockError) as cm:
            lj.restrict_fs(["/definitely/not/here-331"], [])
        self.assertEqual(cm.exception.code, "sandbox-landlock-apply-failed")

    def test_error_is_oserror_with_code(self):
        try:
            lj.restrict_fs(["rel"], [])
        except lj.LandlockError as exc:
            self.assertIsInstance(exc, OSError)
            self.assertTrue(exc.code.startswith("sandbox-landlock-"))
        else:
            self.fail("no refusal")

    @unittest.skipUnless(NEEDS_LL, "needs enforcing kernel for overlap")
    def test_overlapping_grants_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(lj.LandlockError) as cm:
                lj.restrict_fs([tmp], [tmp])
            self.assertEqual(cm.exception.code,
                             "sandbox-landlock-apply-failed")


class MoveCompatibilityTest(unittest.TestCase):
    """gov.sandbox keeps its historical attribute paths after the move."""

    def test_reexports_are_identical(self):
        self.assertIs(sbmod.landlock_available, lj.landlock_available)
        self.assertIs(sbmod.landlock_abi_version, lj.landlock_abi_version)
        self.assertIs(sbmod.landlock_build_ruleset,
                      lj.landlock_build_ruleset)
        self.assertIs(sbmod._landlock_restrict_self,
                      lj._landlock_restrict_self)
        self.assertIs(sbmod._landlock_syscall_numbers,
                      lj._landlock_syscall_numbers)
        self.assertIs(sbmod._LANDLOCK_ABI_CACHE, lj._LANDLOCK_ABI_CACHE)

    def test_supported_alias(self):
        # behavioral equivalence with the enforcement-backed probe
        self.assertIsInstance(lj.landlock_supported(), bool)
        self.assertEqual(lj.landlock_supported(), lj.landlock_available())

    def test_abi_version_sane(self):
        v = lj.landlock_abi_version()
        self.assertIsInstance(v, int)
        self.assertGreaterEqual(v, 0)
        # cached: second call agrees
        self.assertEqual(lj.landlock_abi_version(), v)

    def test_syscall_numbers_resolve(self):
        create, add, restrict = lj._landlock_syscall_numbers()
        for nr in (create, add, restrict):
            self.assertIsInstance(nr, int)
            self.assertGreater(nr, 0)


if __name__ == "__main__":
    unittest.main()
