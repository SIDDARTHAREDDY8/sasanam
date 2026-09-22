"""Hardened-layer tests for gov/sandbox.py.

Covers the promoted layers the base suite does not: pivot_root
filesystem jails, UID/GID drop to 'nobody', the seccomp-bpf syscall
allowlist, and the env-gated backend wiring.

Each class is gated on the matching capability probe and skips cleanly
where the kernel/process cannot provide the layer. Fail-closed behavior
(require_* -> SandboxError, never a silent downgrade) is exercised by
forcing setup failures through the real production code paths — no test
hooks in the module.

Live seccomp tests skip on kernels where filter installation is refused
(the probe is honest about that); the filter's *logic* is validated
everywhere by a pure-Python BPF evaluator over the exact bytes the
module assembles.
"""

import contextlib
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import sandbox as gov_sandbox
from gov.sandbox import (
    DEFAULT_SECCOMP_ALLOW,
    Sandbox,
    SandboxError,
    SandboxedToolBackend,
    install_from_env,
    netns_available,
    pidns_available,
    pivot_available,
    privdrop_available,
    sandbox_config_from_env,
    seccomp_available,
)

PIVOT = pivot_available()
PRIVDROP = privdrop_available()
SECCOMP = seccomp_available()
NETNS = netns_available()
PIDNS = pidns_available()

try:
    import pwd as _pwd
    _NOBODY_UID = _pwd.getpwnam("nobody").pw_uid
    _NOBODY_GID = _pwd.getpwnam("nobody").pw_gid
except (ImportError, KeyError):
    _NOBODY_UID = _NOBODY_GID = None

# System python3 for the non-pivot privdrop tests: run_python() execs
# sys.executable, which 'nobody' may not be able to traverse (home-dir
# venv on this VM's overlay mount). The drop is identical either way.
_USRBIN_PYTHON = next(
    (p for p in ("/usr/bin/python3.12", "/usr/bin/python3", "/usr/bin/python")
     if os.path.exists(p)),
    None)

_ENV_VARS = ("GOV_SANDBOX_BACKEND", "GOV_SANDBOX_STRICT",
             "GOV_SANDBOX_NETNS", "GOV_SANDBOX_PIDNS", "GOV_SANDBOX_PIVOT",
             "GOV_SANDBOX_SECCOMP", "GOV_SANDBOX_PRIVDROP")


def fast_sandbox(**kw):
    kw.setdefault("timeout", 10)
    return Sandbox(**kw)


@contextlib.contextmanager
def sandbox_env(**kw):
    """Set GOV_SANDBOX_* vars for the block; everything else cleared."""
    saved = {k: os.environ.get(k) for k in _ENV_VARS}
    try:
        for k in _ENV_VARS:
            os.environ.pop(k, None)
        for k, v in kw.items():
            os.environ["GOV_SANDBOX_" + k] = v
        yield
    finally:
        for k in _ENV_VARS:
            os.environ.pop(k, None)
            if saved[k] is not None:
                os.environ[k] = saved[k]


def _patch_module_attr(name, new):
    real = getattr(gov_sandbox, name)
    setattr(gov_sandbox, name, new)
    return real


class _FakeExecutor:
    def __init__(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="gov-env-be-"))
        self.sandbox = self._tmp / "sandbox"
        self.quarantine = self._tmp / "quarantine"
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self.quarantine.mkdir(parents=True, exist_ok=True)

    def close(self):
        shutil.rmtree(self._tmp, ignore_errors=True)


class CapabilityProbeTest(unittest.TestCase):
    def test_probes_are_stable_booleans(self):
        for probe in (pivot_available, privdrop_available,
                      seccomp_available, netns_available, pidns_available):
            first = probe()
            self.assertIsInstance(first, bool)
            self.assertEqual(probe(), first, probe.__name__)

    def test_syscall_numbers_sane(self):
        import platform
        numbers = gov_sandbox._syscall_numbers()
        if platform.machine() in ("x86_64", "aarch64"):
            self.assertTrue(len(numbers) > 200)
            for name, nr in numbers.items():
                self.assertIsInstance(nr, int)
                self.assertGreaterEqual(nr, 0)


@unittest.skipUnless(PIVOT, "pivot_root unavailable on this kernel/process")
class PivotContainmentTest(unittest.TestCase):
    """The pivot jail: only the staging is visible; the host tree is gone."""

    def _pivot(self, **kw):
        kw.setdefault("timeout", 10)
        kw.setdefault("use_pivot_root", True)
        return Sandbox(**kw)

    def test_jail_shows_only_staging(self):
        r = self._pivot().run_python(
            "import os\nprint(sorted(os.listdir('/')))")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.pivot_active)
        seen = eval(r.stdout.strip())
        self.assertNotIn(".pivot_old", seen)
        for host_only in ("/home", "/root"):
            self.assertFalse(os.path.exists(host_only) and host_only[1:] in seen)

    def test_host_paths_are_gone(self):
        canary = Path(tempfile.mkdtemp(prefix="gov-pivot-")) / "secret.txt"
        self.addCleanup(shutil.rmtree, str(canary.parent), True)
        canary.write_text("host secret")
        r = self._pivot().run_python(
            "import os\n"
            "print('canary=' + ('VISIBLE-BAD' if os.path.exists(%r) else 'gone-ok'))\n"
            "print('home=' + ('VISIBLE-BAD' if os.path.exists('/home') else 'gone-ok'))\n"
            % str(canary))
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertIn("canary=gone-ok", r.stdout)
        self.assertIn("home=gone-ok", r.stdout)

    def test_absolute_writes_cannot_reach_host(self):
        host_tmp = Path(tempfile.mkdtemp(prefix="gov-pivot-"))
        self.addCleanup(shutil.rmtree, str(host_tmp), True)
        target = host_tmp / "escaped.txt"
        r = self._pivot().run_python(
            "import os\n"
            "out = []\n"
            "for p in [%r, '/etc/pivot-evil', '/.pivot_old/x']:\n"
            "    try:\n"
            "        open(p, 'w').write('pwn')\n"
            "        out.append(p + '=WRITTEN-BAD')\n"
            "    except OSError:\n"
            "        out.append(p + '=blocked-ok')\n"
            "print('\\n'.join(out))\n" % str(target))
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertNotIn("WRITTEN-BAD", r.stdout)
        self.assertFalse(target.exists(), "host file was written through the pivot")
        self.assertFalse(Path("/etc/pivot-evil").exists())

    def test_dotdot_cannot_escape(self):
        r = self._pivot().run_python(
            "import os\nos.chdir('/../../..')\nprint(os.getcwd())")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertEqual(r.stdout.strip(), "/")

    def test_proc_shows_only_descendants(self):
        r = self._pivot().run_python(
            "import os\n"
            "pids = [p for p in os.listdir('/proc') if p.isdigit()]\n"
            "print('pids=%d' % len(pids))\n"
            "print('ppid=%d' % os.getppid())\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertIn("pids=1", r.stdout)
        # The worker is PID 1 in its namespace, so it has no parent there.
        self.assertIn("ppid=0", r.stdout)
        self.assertTrue(r.pid_isolated)

    def test_parent_environ_unreachable_via_proc(self):
        canary = "gov-pivot-canary-%d" % os.getpid()
        os.environ["GOV_PIVOT_TEST_CANARY"] = canary
        self.addCleanup(os.environ.pop, "GOV_PIVOT_TEST_CANARY", None)
        r = self._pivot().run_python(
            "import os\n"
            "found = []\n"
            "for pid in os.listdir('/proc'):\n"
            "    if not pid.isdigit():\n"
            "        continue\n"
            "    try:\n"
            "        data = open('/proc/%s/environ' % pid, 'rb').read()\n"
            "    except OSError:\n"
            "        continue\n"
            "    if b'" + canary + "' in data:\n"
            "        found.append(pid)\n"
            "print('leaked=' + str(found))\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertIn("leaked=[]", r.stdout)

    def test_staging_is_readonly(self):
        r = self._pivot().run_python(
            "import os\n"
            "out = []\n"
            "for p in ['/usr/lib/pivot-evil', '/bin/pivot-evil', '/etc/pivot-evil']:\n"
            "    try:\n"
            "        open(p, 'w').write('pwn')\n"
            "        out.append(p + '=WRITTEN-BAD')\n"
            "    except OSError:\n"
            "        out.append(p + '=blocked-ok')\n"
            "print('\\n'.join(out))\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertNotIn("WRITTEN-BAD", r.stdout)

    def test_interpreter_runs_from_staging(self):
        r = self._pivot().run_python(
            "import sys\nprint(sys.executable)")
        self.assertTrue(r.ok, r.stderr[-500:])
        exe = r.stdout.strip()
        self.assertTrue(exe.startswith("/usr/"),
                        "interpreter not from staging: " + exe)

    def test_relative_writes_stay_in_jail(self):
        r = self._pivot().run_python(
            "open('rel-write.txt', 'w').write('in-jail')\n"
            "print(open('rel-write.txt').read())\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertEqual(r.stdout.strip(), "in-jail")

    def test_fork_pressure_contained_under_pivot(self):
        s = self._pivot(max_procs=64, drop_privs=True)
        t0 = time.monotonic()
        r = s.run_python(
            "import os\n"
            "pids = []\n"
            "failed = 0\n"
            "for _ in range(300):\n"
            "    try:\n"
            "        pid = os.fork()\n"
            "    except OSError:\n"
            "        failed += 1\n"
            "        break\n"
            "    if pid == 0:\n"
            "        os._exit(0)\n"
            "    pids.append(pid)\n"
            "for pid in pids:\n"
            "    os.waitpid(pid, 0)\n"
            "print('failed=%d forks=%d' % (failed, len(pids)))\n")
        wall = time.monotonic() - t0
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.pivot_active)
        self.assertIn("failed=1", r.stdout)
        self.assertLess(wall, 20)

    @unittest.skipUnless(NETNS, "network namespace unavailable")
    def test_network_dead_under_pivot(self):
        r = self._pivot().run_python(
            "import socket\n"
            "socket.create_connection(('8.8.8.8', 53), timeout=3)\n")
        self.assertTrue(r.network_isolated)
        self.assertFalse(r.ok)


@unittest.skipUnless(PRIVDROP, "privilege drop unavailable for this process")
@unittest.skipIf(_NOBODY_UID is None, "no 'nobody' user on this system")
@unittest.skipUnless(_USRBIN_PYTHON, "no nobody-reachable system python3")
class PrivDropTest(unittest.TestCase):
    """UID/GID drop without the pivot jail.

    run_python() execs sys.executable, which may live somewhere 'nobody'
    cannot traverse (e.g. a home-directory venv on an overlay mount, as
    on this VM). These tests therefore exec the system python3 directly;
    the drop itself is identical.
    """

    def _run_dropped(self, code, **kw):
        kw.setdefault("drop_privs", True)
        s = fast_sandbox(**kw)
        return s.run([_USRBIN_PYTHON, "-I", "-c", code])

    def test_child_runs_as_nobody(self):
        r = self._run_dropped(
            "import os\nprint('%d %d' % (os.getuid(), os.getgid()))")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.privdropped)
        self.assertEqual(r.stdout.strip(), "%d %d" % (_NOBODY_UID, _NOBODY_GID))

    def test_nobody_cannot_read_root_only_file(self):
        # The file is reachable (world-traversable dirs) but 0600
        # root-owned: only a real UID drop makes the open fail.
        d = Path(tempfile.mkdtemp(prefix="gov-privdrop-"))
        self.addCleanup(shutil.rmtree, str(d), True)
        secret = d / "secret.txt"
        secret.write_text("top-secret")
        secret.chmod(0o600)
        r = self._run_dropped("print(open(%r).read())" % str(secret))
        self.assertTrue(r.privdropped)
        self.assertFalse(r.ok)
        self.assertIn("PermissionError", r.stderr)

    def test_nobody_cannot_kill_parent(self):
        # No PID namespace here on purpose: the child learns the parent's
        # REAL pid, and still cannot signal it once dropped.
        parent = os.getpid()
        r = self._run_dropped(
            "import os, signal\n"
            "os.kill(%d, signal.SIGKILL)\n"
            "print('SURVIVED-BAD')\n" % parent,
            use_pidns=False)
        self.assertTrue(r.privdropped)
        self.assertFalse(r.pid_isolated)
        self.assertFalse(r.ok)
        self.assertIn("PermissionError", r.stderr)
        self.assertNotIn("SURVIVED-BAD", r.stdout)
        # Reaching this line proves the parent survived.

    def test_privdrop_flag_honest_when_disabled(self):
        r = fast_sandbox().run_python("import os\nprint(os.getuid())")
        self.assertTrue(r.ok)
        self.assertFalse(r.privdropped)
        self.assertEqual(r.stdout.strip(), str(os.getuid()))

    def test_temp_jail_writable_by_nobody(self):
        r = self._run_dropped(
            "open('dropped-write.txt', 'w').write('ok')\n"
            "print(open('dropped-write.txt').read())\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.privdropped)
        self.assertEqual(r.stdout.strip(), "ok")


class SeccompFilterLogicTest(unittest.TestCase):
    """Validate the compiled filter's semantics without a live kernel.

    Uses the module's pure-Python BPF evaluator over the exact bytes
    _build_seccomp_filter assembles, so this runs (and must pass) even
    where seccomp installation is refused.
    """

    @classmethod
    def setUpClass(cls):
        cls.numbers = gov_sandbox._syscall_numbers()
        if not cls.numbers:
            raise unittest.SkipTest("no syscall numbers on this arch")
        cls.arch = gov_sandbox._AUDIT_ARCH[gov_sandbox._ARCH]
        allowed = sorted(n for n in
                         (cls.numbers.get(name)
                          for name in DEFAULT_SECCOMP_ALLOW)
                         if n is not None)
        cls.blob = gov_sandbox._build_seccomp_filter(
            allowed, default_action="kill")
        cls.errno_blob = gov_sandbox._build_seccomp_filter(
            allowed, default_action="errno")

    def _decide(self, blob, nr, arch=None):
        return gov_sandbox._bpf_decision(
            blob, self.arch if arch is None else arch, nr)

    def test_allowlisted_syscalls_reach_allow(self):
        allow = gov_sandbox._SECCOMP_RET_ALLOW
        for name in DEFAULT_SECCOMP_ALLOW:
            nr = self.numbers.get(name)
            if nr is None:
                continue
            self.assertEqual(self._decide(self.blob, nr), allow, name)

    def test_dangerous_syscalls_reach_kill(self):
        kill = gov_sandbox._SECCOMP_RET_KILL_PROCESS
        dangerous = ("socket", "connect", "accept", "ptrace", "mount",
                     "pivot_root", "bpf", "keyctl", "open_by_handle_at",
                     "process_vm_readv", "process_vm_writev",
                     "init_module", "finit_module", "reboot", "kexec_load",
                     "io_uring_setup", "userfaultfd", "perf_event_open",
                     "unshare", "setns", "move_mount", "open_tree")
        for name in dangerous:
            nr = self.numbers.get(name)
            if nr is None:
                continue
            self.assertEqual(self._decide(self.blob, nr), kill, name)

    def test_wrong_arch_reaches_kill(self):
        kill = gov_sandbox._SECCOMP_RET_KILL_PROCESS
        other = (gov_sandbox.AUDIT_ARCH_AARCH64
                 if self.arch == gov_sandbox.AUDIT_ARCH_X86_64
                 else gov_sandbox.AUDIT_ARCH_X86_64)
        nr = self.numbers["read"]
        self.assertEqual(self._decide(self.blob, nr, arch=other), kill)

    def test_errno_mode_returns_enosys(self):
        ret = self._decide(self.errno_blob, self.numbers["socket"])
        self.assertEqual(ret, gov_sandbox._SECCOMP_RET_ERRNO | 38)  # ENOSYS


@unittest.skipUnless(SECCOMP, "seccomp filter installation refused by kernel")
class SeccompLiveTest(unittest.TestCase):
    def test_tool_workload_passes_filter(self):
        tmp = Path(tempfile.mkdtemp(prefix="gov-seccomp-live-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        be = SandboxedToolBackend(tmp / "sandbox", tmp / "quarantine",
                                  sandbox=Sandbox(timeout=10,
                                                  use_seccomp=True))
        w = be.execute("write_file",
                       {"path": "s/out.txt", "content": "under-seccomp"},
                       {"path_outside_sandbox": False})
        self.assertTrue(w.get("sandboxed"), w)
        r = be.execute("read_file", {"path": "s/out.txt"},
                       {"path_outside_sandbox": False})
        self.assertEqual(r.get("content"), "under-seccomp")

    def test_socket_killed_by_filter(self):
        r = fast_sandbox(use_seccomp=True).run_python(
            "import socket\nsocket.socket()\nprint('SOCKET-BAD')")
        self.assertFalse(r.ok)
        self.assertNotIn("SOCKET-BAD", r.stdout)
        self.assertEqual(r.returncode, -signal.SIGSYS)

    def test_unshare_killed_by_filter(self):
        r = fast_sandbox(use_seccomp=True).run_python(
            "import os\nos.unshare(os.CLONE_NEWNET)\nprint('UNSHARE-BAD')")
        self.assertFalse(r.ok)
        self.assertNotIn("UNSHARE-BAD", r.stdout)
        self.assertEqual(r.returncode, -signal.SIGSYS)


class HardenedFailClosedTest(unittest.TestCase):
    """Forced setup failures must refuse, never silently downgrade."""

    def _force_pivot_failure(self):
        real = _patch_module_attr(
            "_do_pivot_root",
            lambda *a, **k: (_ for _ in ()).throw(
                OSError(1, "forced pivot failure for test")))
        self.addCleanup(setattr, gov_sandbox, "_do_pivot_root", real)

    def _force_setuid_failure(self):
        real = os.setuid
        def _boom(*args, **kwargs):
            raise OSError(1, "forced setuid failure for test")
        os.setuid = _boom
        self.addCleanup(setattr, os, "setuid", real)

    def _force_seccomp_failure(self):
        real = _patch_module_attr(
            "_install_default_seccomp_filter",
            lambda *a, **k: (_ for _ in ()).throw(
                OSError(22, "forced seccomp failure for test")))
        self.addCleanup(setattr, gov_sandbox,
                        "_install_default_seccomp_filter", real)

    def _force_unshare_failure(self):
        real = os.unshare
        def _boom(*args, **kwargs):
            raise OSError(22, "forced unshare failure for test")
        os.unshare = _boom
        self.addCleanup(setattr, os, "unshare", real)

    def test_require_pivot_root_refuses_and_never_execs(self):
        s = fast_sandbox(use_pivot_root=True, require_pivot_root=True)
        self._force_pivot_failure()
        canary = Path(tempfile.mkdtemp()) / "should-not-exist"
        self.addCleanup(shutil.rmtree, str(canary.parent), True)
        with self.assertRaises(SandboxError):
            s.run_python("open(%r, 'w').write('executed')" % str(canary))
        self.assertFalse(canary.exists(),
                         "strict mode must stop the child before exec")

    def test_require_privdrop_refuses_and_never_execs(self):
        s = fast_sandbox(drop_privs=True, require_privdrop=True)
        self._force_setuid_failure()
        canary = Path(tempfile.mkdtemp()) / "should-not-exist"
        self.addCleanup(shutil.rmtree, str(canary.parent), True)
        with self.assertRaises(SandboxError):
            s.run_python("open(%r, 'w').write('executed')" % str(canary))
        self.assertFalse(canary.exists(),
                         "strict mode must stop the child before exec")

    def test_require_seccomp_refuses_and_never_execs(self):
        s = fast_sandbox(use_seccomp=True, require_seccomp=True)
        self._force_seccomp_failure()
        canary = Path(tempfile.mkdtemp()) / "should-not-exist"
        self.addCleanup(shutil.rmtree, str(canary.parent), True)
        with self.assertRaises(SandboxError):
            s.run_python("open(%r, 'w').write('executed')" % str(canary))
        self.assertFalse(canary.exists(),
                         "strict mode must stop the child before exec")

    @unittest.skipIf(SECCOMP, "seccomp is available; nothing to refuse here")
    def test_require_seccomp_refuses_when_unavailable(self):
        s = fast_sandbox(use_seccomp=True, require_seccomp=True)
        with self.assertRaises(SandboxError):
            s.run(["/bin/true"])

    def test_require_flags_conflict_with_disabled(self):
        with self.assertRaises(ValueError):
            fast_sandbox(use_pivot_root=False, require_pivot_root=True)
        with self.assertRaises(ValueError):
            fast_sandbox(drop_privs=False, require_privdrop=True)
        with self.assertRaises(ValueError):
            fast_sandbox(use_seccomp=False, require_seccomp=True)

    def test_unforced_pivot_fallback_is_honest(self):
        # unshare() failing breaks netns, pidns AND the pivot setup; the
        # call must still run but report every layer as not established.
        # (Regression: an earlier draft ran _finish_pivot() here even when
        # _do_pivot_root() never ran, remounting the HOST's /proc.)
        s = fast_sandbox(use_pivot_root=True)
        self._force_unshare_failure()
        r = s.run(["/bin/echo", "still-runs"])
        self.assertTrue(r.ok, r)
        self.assertEqual(r.stdout.strip(), "still-runs")
        self.assertFalse(r.pivot_active,
                         "fallback must not be labeled pivot-active")
        self.assertFalse(r.pid_isolated)
        self.assertFalse(r.network_isolated)
        self.assertIn("fallback", r.note)

    def test_unforced_seccomp_fallback_is_honest(self):
        s = fast_sandbox(use_seccomp=True)
        self._force_seccomp_failure()
        r = s.run(["/bin/echo", "still-runs"])
        self.assertTrue(r.ok, r)
        self.assertFalse(r.seccomp_active,
                         "fallback must not be labeled seccomp-active")


class EnvGateTest(unittest.TestCase):
    def test_backend_disabled_by_default(self):
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env():
            self.assertIsNone(install_from_env(ex))
        self.assertFalse(hasattr(ex, "_simulate"),
                         "executor must be untouched when disabled")

    def test_backend_unknown_value_stays_disabled(self):
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env(BACKEND="maybe"):
            self.assertIsNone(install_from_env(ex))
        self.assertFalse(hasattr(ex, "_simulate"))

    def test_backend_enabled_installs(self):
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env(BACKEND="1"):
            be = install_from_env(ex)
        self.assertIsNotNone(be)
        # Bound methods compare by (__func__, __self__); assertIs on two
        # attribute lookups would always fail.
        self.assertEqual(ex._simulate, be.execute)
        # Best-effort defaults: hardened layers off, flags honest.
        self.assertFalse(be.sandbox.use_pivot_root)
        self.assertFalse(be.sandbox.drop_privs)
        self.assertFalse(be.sandbox.use_seccomp)

    def test_config_requested_layers_are_required(self):
        # An explicitly requested layer is required per call even without
        # STRICT, so a sporadic setup failure refuses instead of
        # silently downgrading.
        with sandbox_env(BACKEND="1", PIVOT="1", PRIVDROP="1"):
            cfg = sandbox_config_from_env()
        self.assertTrue(cfg["use_pivot_root"])
        self.assertTrue(cfg["require_pivot_root"])
        self.assertTrue(cfg["drop_privs"])
        self.assertTrue(cfg["require_privdrop"])
        self.assertFalse(cfg["use_seccomp"])
        self.assertFalse(cfg["require_seccomp"])

    @unittest.skipUnless(NETNS and PIDNS,
                         "strict requires net+pid namespaces here")
    def test_strict_requires_always_on_layers(self):
        with sandbox_env(BACKEND="1", STRICT="1"):
            cfg = sandbox_config_from_env()
        self.assertTrue(cfg["require_netns"])
        self.assertTrue(cfg["require_pidns"])
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env(BACKEND="1", STRICT="1"):
            be = install_from_env(ex)
        self.assertIsNotNone(be)

    @unittest.skipIf(SECCOMP, "seccomp available; nothing to refuse here")
    def test_requested_unavailable_feature_fails_closed(self):
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env(BACKEND="1", SECCOMP="1"):
            with self.assertRaises(SandboxError):
                install_from_env(ex)
        self.assertFalse(hasattr(ex, "_simulate"),
                         "executor must be untouched on refusal")

    def test_requested_unavailable_pivot_fails_closed(self):
        real = _patch_module_attr("pivot_available", lambda: False)
        self.addCleanup(setattr, gov_sandbox, "pivot_available", real)
        ex = _FakeExecutor()
        self.addCleanup(ex.close)
        with sandbox_env(BACKEND="1", PIVOT="1"):
            with self.assertRaises(SandboxError):
                install_from_env(ex)
        self.assertFalse(hasattr(ex, "_simulate"))


@unittest.skipUnless(PIVOT and PRIVDROP,
                     "pivot jail + privilege drop unavailable")
class BackendPivotTest(unittest.TestCase):
    """The backend's tool scripts run as nobody inside the pivot jail."""

    def _backend(self):
        tmp = Path(tempfile.mkdtemp(prefix="gov-be-pivot-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        sb_root = tmp / "sandbox"
        sb_root.mkdir()
        (tmp / "quarantine").mkdir()
        return (SandboxedToolBackend(
                    sb_root, tmp / "quarantine",
                    sandbox=Sandbox(timeout=10, use_pivot_root=True,
                                    drop_privs=True)),
                sb_root)

    def test_write_read_delete_roundtrip(self):
        be, sb_root = self._backend()
        w = be.execute("write_file",
                       {"path": "out/note.txt", "content": "via-pivot"},
                       {"path_outside_sandbox": False})
        self.assertTrue(w.get("sandboxed"), w)
        r = be.execute("read_file", {"path": "out/note.txt"},
                       {"path_outside_sandbox": False})
        self.assertEqual(r.get("source"), "sandbox")
        self.assertEqual(r.get("content"), "via-pivot")
        self.assertEqual((sb_root / "out" / "note.txt").read_text(),
                         "via-pivot")
        d = be.execute("delete_file", {"path": "out/note.txt"},
                       {"path_outside_sandbox": False})
        self.assertTrue(d.get("deleted"), d)
        self.assertFalse((sb_root / "out" / "note.txt").exists())

    def test_escape_rejected_parent_side(self):
        be, sb_root = self._backend()
        evil = sb_root.parent / "evil.txt"
        with self.assertRaises(ValueError):
            be.execute("write_file", {"path": "../../evil.txt",
                                      "content": "x"},
                       {"path_outside_sandbox": False})
        self.assertFalse(evil.exists())

    def test_quarantine_write_stays_parent_side(self):
        be, sb_root = self._backend()
        r = be.execute("write_file",
                       {"path": "/abs/path/outside.txt", "content": "q"},
                       {"path_outside_sandbox": True})
        self.assertIn("quarantine", r.get("note", ""))
        self.assertFalse(Path("/abs/path/outside.txt").exists())

    def test_sandbox_root_owned_by_nobody(self):
        be, sb_root = self._backend()
        st = sb_root.stat()
        self.assertEqual((st.st_uid, st.st_gid),
                         (_NOBODY_UID, _NOBODY_GID))


@unittest.skipUnless(PIVOT and PRIVDROP and NETNS and PIDNS,
                     "full hardened stack unavailable")
class FullHardeningIntegrationTest(unittest.TestCase):
    def test_all_layers_together(self):
        s = Sandbox(timeout=10, use_pivot_root=True, drop_privs=True,
                    require_pidns=True, require_netns=True)
        r = s.run_python(
            "import os\n"
            "print('uid=%d' % os.getuid())\n"
            "print('ppid=%d' % os.getppid())\n"
            "print('root=%s' % sorted(os.listdir('/')))\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.pivot_active)
        self.assertTrue(r.privdropped)
        self.assertTrue(r.pid_isolated)
        self.assertTrue(r.network_isolated)
        self.assertFalse(r.seccomp_active, "seccomp unavailable on this VM")
        self.assertIn("uid=%d" % _NOBODY_UID, r.stdout)
        self.assertIn("ppid=0", r.stdout)  # PID 1 has no parent in its ns


if __name__ == "__main__":
    unittest.main()
