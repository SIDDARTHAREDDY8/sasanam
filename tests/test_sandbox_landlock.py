"""Unit tests for the wave-266 Landlock filesystem tier (gov/sandbox.py).

Covers the public seams: availability probing, ruleset construction,
constructor validation, the fail-closed matrix (unavailable / required /
apply-failed), per-call ground truth, and the taxonomy entries. The
break-first falsification lives in evals/w266_landlock_probes.py.
"""

import contextlib
import io
import json
import os
import shutil
import unittest

from gov import decision_codes as dcd
from gov import sandbox as sbmod
from gov.sandbox import Sandbox, SandboxError


def _pinned(**kw):
    """Sandbox with every other layer pinned off: the verdict delta is
    the Landlock tier alone."""
    base = dict(use_netns=False, use_pidns=False, use_pivot_root=False,
                drop_privs=False, use_seccomp=False)
    base.update(kw)
    return Sandbox(**base)


@unittest.skipUnless(sbmod.landlock_available(),
                     "Landlock LSM not enforcing on this kernel")
class LandlockAvailableTest(unittest.TestCase):
    def test_abi_version_sane(self):
        v = sbmod.landlock_abi_version()
        self.assertIsInstance(v, int)
        self.assertGreaterEqual(v, 1)
        # Cached: the second call must not re-probe.
        self.assertEqual(sbmod.landlock_abi_version(), v)

    def test_syscall_numbers_resolve(self):
        nums = sbmod._landlock_syscall_numbers()
        self.assertEqual(len(nums), 3)
        for n in nums:
            self.assertIsInstance(n, int)
            self.assertGreater(n, 0)

    def test_available_is_bool(self):
        self.assertIs(sbmod.landlock_available(), True)

    def _mkjail(self):
        import tempfile
        jail = tempfile.mkdtemp(prefix="ll-unit-")
        os.mkdir(os.path.join(jail, "scratch"))
        self.addCleanup(shutil.rmtree, jail, True)
        return jail

    def test_build_ruleset_returns_fd(self):
        jail = self._mkjail()
        fd = sbmod.landlock_build_ruleset(
            jail_root=jail, scratch_name="scratch",
            argv0="/usr/bin/python3", extra_ro=())
        try:
            self.assertGreaterEqual(fd, 0)
        finally:
            os.close(fd)

    def test_build_ruleset_rejects_relative_extra_ro(self):
        jail = self._mkjail()
        with self.assertRaises(OSError):
            sbmod.landlock_build_ruleset(
                jail_root=jail, scratch_name="scratch",
                argv0="/usr/bin/python3",
                extra_ro=("relative/path",))

    def test_build_ruleset_rejects_missing_extra_ro(self):
        jail = self._mkjail()
        with self.assertRaises(OSError):
            sbmod.landlock_build_ruleset(
                jail_root=jail, scratch_name="scratch",
                argv0="/usr/bin/python3",
                extra_ro=("/no/such/dir-xyz",))

    def test_build_ruleset_unavailable_kernel_raises(self):
        jail = self._mkjail()
        old = sbmod._LANDLOCK_ABI_CACHE["version"]
        sbmod._LANDLOCK_ABI_CACHE["version"] = 0
        try:
            with self.assertRaises(OSError):
                sbmod.landlock_build_ruleset(
                    jail_root=jail, scratch_name="scratch",
                    argv0="/usr/bin/python3")
        finally:
            sbmod._LANDLOCK_ABI_CACHE["version"] = old

    def test_ground_truth_active(self):
        r = _pinned(use_landlock=True).run_python("print('ok')")
        self.assertTrue(r.ok)
        self.assertIs(r.landlock_active, True)

    def test_ground_truth_inactive_without_tier(self):
        r = _pinned().run_python("print('ok')")
        self.assertTrue(r.ok)
        self.assertIs(r.landlock_active, False)

    def test_scratch_env_and_writable(self):
        code = ("import json, os\n"
                "s = os.environ.get('GOV_SANDBOX_SCRATCH')\n"
                "p = os.path.join(s, 'w.txt')\n"
                "open(p, 'w').write('v')\n"
                "print(json.dumps({'s': s, 'rt': open(p).read() == 'v'}))\n")
        r = _pinned(use_landlock=True).run_python(code)
        self.assertTrue(r.ok, r.stderr[-500:])
        payload = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertTrue(payload["s"].endswith("/scratch"))
        self.assertIs(payload["rt"], True)

    def test_child_side_apply_failure_refuses(self):
        real = sbmod._landlock_restrict_self

        def _boom(fd):
            raise OSError(1, "boom")

        sbmod._landlock_restrict_self = _boom
        try:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                with self.assertRaises(SandboxError):
                    _pinned(use_landlock=True).run_python("print('x')")
            # The machine code rides the loud stderr refusal record
            # (_refuse_loud convention: [kind] in the stderr line).
            self.assertIn("[sandbox-landlock-apply-failed]", buf.getvalue())
        finally:
            sbmod._landlock_restrict_self = real

    def test_parent_side_build_failure_refuses(self):
        real = sbmod.landlock_build_ruleset

        def _boom(**kw):
            raise OSError(22, "boom")

        sbmod.landlock_build_ruleset = _boom
        try:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                with self.assertRaises(SandboxError):
                    _pinned(use_landlock=True).run_python("print('x')")
            self.assertIn("[sandbox-landlock-apply-failed]", buf.getvalue())
        finally:
            sbmod.landlock_build_ruleset = real


class LandlockUnavailableWiringTest(unittest.TestCase):
    """Fail-closed matrix on a kernel without Landlock (monkeypatched)."""

    def setUp(self):
        self._real = sbmod.landlock_available
        sbmod.landlock_available = lambda: False

    def tearDown(self):
        sbmod.landlock_available = self._real

    def test_requested_but_not_required_runs_degraded_with_code(self):
        r = _pinned(use_landlock=True).run_python("print('degraded-ok')")
        self.assertTrue(r.ok)
        self.assertIn("degraded-ok", r.stdout)
        self.assertIs(r.landlock_active, False)
        self.assertIn("sandbox-landlock-unavailable", r.note)

    def test_required_refuses_before_spawn(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SandboxError):
                _pinned(use_landlock=True,
                        require_landlock=True).run_python("print('x')")
        self.assertIn("[sandbox-landlock-required]", buf.getvalue())


class LandlockConstructorTest(unittest.TestCase):
    def test_require_without_use_conflicts(self):
        with self.assertRaises(ValueError):
            Sandbox(use_landlock=False, require_landlock=True)

    def test_bad_scratch_name_rejected(self):
        for bad in ("", "a/b", "..", "."):
            with self.assertRaises(ValueError):
                Sandbox(use_landlock=True, landlock_scratch_name=bad)

    def test_capable_flag(self):
        sb = Sandbox(use_landlock=True)
        self.assertEqual(sb.landlock_capable,
                         sb.use_landlock and sbmod.landlock_available())
        sb2 = Sandbox()
        self.assertIs(sb2.landlock_capable, False)

    def test_extra_ro_stored(self):
        sb = Sandbox(use_landlock=True, landlock_extra_ro=("/opt/x",))
        self.assertEqual(sb.landlock_extra_ro, ("/opt/x",))


class LandlockTaxonomyTest(unittest.TestCase):
    def test_codes_present(self):
        for code in ("sandbox-landlock-unavailable",
                     "sandbox-landlock-required",
                     "sandbox-landlock-apply-failed"):
            self.assertIn(code, dcd.TAXONOMY)
            self.assertEqual(dcd.TAXONOMY[code]["domain"], "sandbox")
            self.assertEqual(dcd.TAXONOMY[code]["code"], code)

    def test_pin(self):
        # Local pin for this lane: base 1205 + 3 landlock codes.
        self.assertEqual(len(dcd.TAXONOMY), 2128) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 3: pin 1742 -> 1745 (+3 toolcall-predicate-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)


class LandlockEnvConfigTest(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_env_flag_wires_required_tier(self):
        os.environ["GOV_SANDBOX_BACKEND"] = "1"
        os.environ["GOV_SANDBOX_LANDLOCK"] = "1"
        cfg = sbmod.sandbox_config_from_env()
        self.assertIsNotNone(cfg)
        self.assertTrue(cfg["use_landlock"])
        self.assertTrue(cfg["require_landlock"])

    def test_env_flag_unavailable_refuses(self):
        real = sbmod.landlock_available
        sbmod.landlock_available = lambda: False
        try:
            os.environ["GOV_SANDBOX_BACKEND"] = "1"
            os.environ["GOV_SANDBOX_LANDLOCK"] = "1"
            with self.assertRaises(SandboxError):
                sbmod.sandbox_config_from_env()
        finally:
            sbmod.landlock_available = real


if __name__ == "__main__":
    unittest.main()
