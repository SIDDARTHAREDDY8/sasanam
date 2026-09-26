"""Adversarial tests for gov/sandbox.py.

These tests attack the sandbox the way a hostile tool would: shell
injection, cwd escape, environment exfiltration, hangs, fork bombs, output
bombs, memory exhaustion, disk abuse, and network egress. A test documents
either a contained attack or — where containment is honestly impossible at
this layer (cwd != chroot) — the exact reason the backend validates paths
parent-side.
"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import shutil

from gov.sandbox import (Sandbox, SandboxError, SandboxResult,
                         SandboxedToolBackend, install, netns_available,
                         pidns_available)

try:
    import resource as _resource
    _HAS_RESOURCE = True
except ImportError:
    _HAS_RESOURCE = False

NETNS = netns_available()
PIDNS = pidns_available()


def fast_sandbox(**kw):
    kw.setdefault("timeout", 8)
    return Sandbox(**kw)


class ArgvValidationTest(unittest.TestCase):
    def test_shell_string_rejected(self):
        s = fast_sandbox()
        with self.assertRaises(TypeError):
            s.run("echo hello")

    def test_empty_argv_rejected(self):
        with self.assertRaises(ValueError):
            fast_sandbox().run([])

    def test_non_string_arg_rejected(self):
        with self.assertRaises(TypeError):
            fast_sandbox().run(["/bin/echo", 123])

    def test_nul_byte_rejected(self):
        with self.assertRaises(ValueError):
            fast_sandbox().run(["/bin/echo", "a\x00b"])

    def test_shell_metachars_are_inert(self):
        """$(...), backticks, pipes, redirects: all inert without a shell."""
        s = fast_sandbox()
        canary = Path(tempfile.gettempdir()) / "gov-sandbox-shelltest"
        if canary.exists():
            canary.unlink()
        r = s.run(["/bin/echo", "$(touch %s)" % canary, "a|b", "`id`",
                   "> /tmp/x"])
        self.assertTrue(r.ok)
        self.assertIn("$(", r.stdout)  # echoed literally, not executed
        self.assertFalse(canary.exists())


class CwdJailTest(unittest.TestCase):
    def test_each_run_gets_fresh_empty_jail(self):
        s = fast_sandbox()
        r1 = s.run_python("open('run1.txt','w').write('x')")
        self.assertTrue(r1.ok)
        # Second run must not see the first run's files.
        r2 = s.run_python(
            "import os; print(sorted(os.listdir('.')))")
        self.assertTrue(r2.ok)
        self.assertEqual(r2.stdout.strip(), "[]")

    def test_provided_cwd_is_used(self):
        d = Path(tempfile.mkdtemp(prefix="gov-sb-cwd-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        s = fast_sandbox()
        r = s.run(["/bin/pwd"], cwd=str(d))
        self.assertTrue(r.ok)
        self.assertEqual(Path(r.stdout.strip()), d)

    def test_chdir_dotdot_escapes_cwd_but_not_jail_root(self):
        """ATTACK (documents a real limitation): the temp cwd is NOT a
        chroot. A child that chdir('..')s can write relative paths outside
        its jail. This is exactly why SandboxedToolBackend resolves and
        confines every path PARENT-side before the child starts."""
        d = Path(tempfile.mkdtemp(prefix="gov-sb-escape-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        escaped = d.parent / "gov-sandbox-escape-canary.txt"
        if escaped.exists():
            escaped.unlink()
        self.addCleanup(lambda: escaped.unlink(missing_ok=True))
        s = fast_sandbox()
        r = s.run_python(
            "import os; os.chdir('..'); "
            "open('gov-sandbox-escape-canary.txt','w').write('pwned')",
            cwd=str(d))
        self.assertTrue(r.ok)  # the child itself was not stopped...
        self.assertFalse((d / "gov-sandbox-escape-canary.txt").exists())
        # ...but it DID write outside its jail: cwd alone is not containment.
        self.assertTrue(escaped.exists())


class EnvScrubTest(unittest.TestCase):
    def test_parent_secrets_never_reach_child(self):
        os.environ["GOV_TEST_SANDBOX_CANARY"] = "super-secret-value"
        self.addCleanup(
            lambda: os.environ.pop("GOV_TEST_SANDBOX_CANARY", None))
        s = fast_sandbox()
        r = s.run_python("import os, json; print(json.dumps(dict(os.environ)))")
        env = json.loads(r.stdout)
        self.assertNotIn("GOV_TEST_SANDBOX_CANARY", env)
        self.assertNotIn("GOV_LOG_KEY", env)

    def test_only_allowlisted_env_survives(self):
        s = fast_sandbox()
        r = s.run_python("import os, json; print(json.dumps(dict(os.environ)))")
        env = json.loads(r.stdout)
        self.assertEqual(env.get("PATH"), "/usr/bin:/bin")
        self.assertTrue(env["HOME"].startswith(
            tempfile.gettempdir().rstrip("/") + "/gov-sandbox-")
            or "gov-sandbox-" in env["HOME"])

    def test_extra_env_is_merged(self):
        s = fast_sandbox(extra_env={"MY_TOOL_FLAG": "1"})
        r = s.run_python("import os; print(os.environ.get('MY_TOOL_FLAG'))")
        self.assertEqual(r.stdout.strip(), "1")

    def test_child_cannot_read_parent_environ_via_proc(self):
        os.environ["GOV_TEST_SANDBOX_CANARY2"] = "shh"
        self.addCleanup(
            lambda: os.environ.pop("GOV_TEST_SANDBOX_CANARY2", None))
        s = fast_sandbox()
        # /proc/self/environ only has the child's (scrubbed) environment.
        r = s.run_python(
            "data = open('/proc/self/environ','rb').read(); "
            "print('CANARY' if b'GOV_TEST_SANDBOX_CANARY2' in data else 'clean')")
        self.assertEqual(r.stdout.strip(), "clean")


class TimeoutTest(unittest.TestCase):
    def test_hang_is_killed_at_deadline(self):
        s = fast_sandbox()
        start = time.monotonic()
        r = s.run_python("import time; time.sleep(60)", timeout=2)
        wall = time.monotonic() - start
        self.assertTrue(r.timed_out)
        self.assertFalse(r.ok)
        self.assertEqual(r.returncode, -9)
        self.assertLess(wall, 8)
        self.assertIn("SIGKILL", r.note)

    def test_grandchildren_die_with_the_group(self):
        """Child spawns a grandchild that sleeps; the parent must still
        return promptly and that SPECIFIC grandchild PID must be gone."""
        s = fast_sandbox()
        start = time.monotonic()
        r = s.run_python(
            "import subprocess, time; "
            "p = subprocess.Popen(['sleep', '60']); "
            "print(p.pid, flush=True); "
            "time.sleep(60)",
            timeout=2)
        wall = time.monotonic() - start
        self.assertTrue(r.timed_out)
        self.assertLess(wall, 8)
        grandchild_pid = int(r.stdout.strip())
        # Reap window: SIGKILL is async; poll briefly for the PID to vanish.
        gone = False
        for _ in range(50):
            try:
                os.kill(grandchild_pid, 0)
            except ProcessLookupError:
                gone = True
                break
            time.sleep(0.1)
        self.assertTrue(gone,
                        "grandchild PID %d survived the group SIGKILL"
                        % grandchild_pid)

    def test_cpu_spin_hits_cpu_rlimit(self):
        if not _HAS_RESOURCE:
            self.skipTest("no resource module")
        s = fast_sandbox(cpu_seconds=2, timeout=10)
        r = s.run_python("while True: pass")
        self.assertFalse(r.ok)
        self.assertFalse(r.timed_out)  # killed by RLIMIT_CPU, not the wall clock
        self.assertNotEqual(r.returncode, 0)


class OutputCapTest(unittest.TestCase):
    def test_stdout_bomb_truncated_and_completes(self):
        s = Sandbox(timeout=10, max_output_bytes=65536)
        r = s.run_python("import sys; sys.stdout.write('X' * 50_000_000)")
        self.assertTrue(r.truncated)
        self.assertTrue(r.stdout_truncated)
        self.assertLessEqual(len(r.stdout), 65536)
        self.assertTrue(r.ok)  # finite output: child still exits 0
        self.assertLess(r.wall_seconds, 8)

    def test_stderr_bomb_truncated(self):
        s = Sandbox(timeout=10, max_output_bytes=65536)
        r = s.run_python("import sys; sys.stderr.write('E' * 5_000_000)")
        self.assertTrue(r.stderr_truncated)
        self.assertLessEqual(len(r.stderr), 65536)
        self.assertTrue(r.ok)

    def test_infinite_stream_hits_deadline(self):
        s = Sandbox(timeout=3, max_output_bytes=65536)
        r = s.run_python(
            "import sys\nwhile True:\n    sys.stdout.write('Y' * 100000)\n")
        self.assertTrue(r.timed_out)
        self.assertTrue(r.truncated)
        self.assertLess(r.wall_seconds, 8)


@unittest.skipUnless(_HAS_RESOURCE and os.name == "posix",
                     "needs POSIX resource limits")
class ResourceLimitTest(unittest.TestCase):
    def test_memory_hog_dies_parent_survives(self):
        s = fast_sandbox(memory_bytes=256 << 20, timeout=10)
        r = s.run_python("x = ' ' * 2_000_000_000")
        self.assertFalse(r.ok)
        self.assertIn("MemoryError", r.stderr)
        # Parent is alive and can still allocate (we are the parent).
        _big = bytearray(10_000_000)
        self.assertEqual(len(_big), 10_000_000)

    def test_file_size_cap(self):
        # The containment property is the on-disk size bound, regardless of
        # whether the kernel delivers SIGXFSZ or the write raises EFBIG.
        d = Path(tempfile.mkdtemp(prefix="gov-sb-fsize-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        s = fast_sandbox(max_file_bytes=1 << 20, timeout=10)
        s.run_python(
            "f = open('big.bin','wb')\n"
            "chunk = b'z' * (1 << 20)\n"
            "for _ in range(100):\n"
            "    f.write(chunk)\n"
            "f.close()\n",
            cwd=str(d))
        size = (d / "big.bin").stat().st_size
        self.assertLessEqual(size, 2 << 20)

    def test_fork_pressure_contained(self):
        """300 rapid forks with unreaped zombies: NPROC trips, no bomb."""
        s = fast_sandbox(max_procs=64, timeout=10)
        start = time.monotonic()
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
        wall = time.monotonic() - start
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertIn("failed=1", r.stdout)  # NPROC tripped, loop broke
        self.assertLess(wall, 8)


class NetworkIsolationTest(unittest.TestCase):
    @unittest.skipUnless(NETNS, "network namespace unavailable on this kernel")
    def test_no_route_to_internet(self):
        s = fast_sandbox()
        r = s.run_python(
            "import socket; socket.create_connection(('8.8.8.8', 53), timeout=3)")
        self.assertTrue(r.network_isolated)
        self.assertFalse(r.ok)
        self.assertIn("Network is unreachable", r.stderr)

    @unittest.skipUnless(NETNS, "network namespace unavailable on this kernel")
    def test_loopback_is_down_too(self):
        s = fast_sandbox()
        r = s.run_python(
            "import socket; socket.create_connection(('127.0.0.1', 9), timeout=3)")
        self.assertTrue(r.network_isolated)
        self.assertFalse(r.ok)

    def test_flag_is_honest_when_netns_missing(self):
        s = Sandbox(use_netns=False)
        self.assertFalse(s.network_isolated)
        r = s.run(["/bin/true"])
        self.assertFalse(r.network_isolated)


class BackendPathAuthorityTest(unittest.TestCase):
    """The backend — not the child — decides where IO may go."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gov-sb-be-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.sb_root = self.tmp / "sandbox"
        self.q_root = self.tmp / "quarantine"
        self.sb_root.mkdir()
        self.q_root.mkdir()
        self.be = SandboxedToolBackend(self.sb_root, self.q_root,
                                       sandbox=fast_sandbox())

    def test_dotdot_escape_rejected(self):
        with self.assertRaises(ValueError):
            self.be._checked_target("../evil.txt")
        with self.assertRaises(ValueError):
            self.be._checked_target("sub/../../evil.txt")

    def test_absolute_outside_rejected(self):
        with self.assertRaises(ValueError):
            self.be._checked_target("/etc/passwd")

    def test_symlink_escape_rejected(self):
        """resolve() follows symlinks: a symlink inside the sandbox root
        pointing outside must not smuggle IO past the check."""
        outside = self.tmp / "outside"
        outside.mkdir()
        (self.sb_root / "link").symlink_to(outside)
        with self.assertRaises(ValueError):
            self.be._checked_target("link/evil.txt")

    def test_read_with_dishonest_ctx_still_refuses_escape(self):
        """Defense in depth: even if ctx wrongly claims the path is inside
        the sandbox, _read re-validates at use time and refuses."""
        outside = self.tmp / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("top-secret")
        (self.sb_root / "link").symlink_to(secret)
        with self.assertRaises(ValueError):
            self.be.execute("read_file", {"path": "link"},
                            {"path_outside_sandbox": False})

    def test_normal_relative_path_allowed(self):
        p = self.be._checked_target("sub/dir/f.txt")
        self.assertEqual(p, (self.sb_root / "sub/dir/f.txt").resolve())


class BackendContractTest(unittest.TestCase):
    """execute() mirrors ToolExecutor._simulate's result shapes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gov-sb-bc-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.sb_root = self.tmp / "sandbox"
        self.q_root = self.tmp / "quarantine"
        self.sb_root.mkdir()
        self.q_root.mkdir()
        self.be = SandboxedToolBackend(self.sb_root, self.q_root,
                                       sandbox=fast_sandbox())
        (self.sb_root / "data.txt").write_text("hello sandbox")

    def test_read_file_roundtrip_through_child(self):
        res = self.be.execute("read_file", {"path": "data.txt"},
                              {"path_outside_sandbox": False})
        self.assertEqual(res["source"], "sandbox")
        self.assertEqual(res["content"], "hello sandbox")
        self.assertTrue(res["sandboxed"])

    def test_read_missing_file_is_simulated(self):
        res = self.be.execute("read_file", {"path": "nope.txt"},
                              {"path_outside_sandbox": False})
        self.assertEqual(res, {"source": "simulated",
                               "content": "[synthetic file contents]"})

    def test_write_then_read_binary_safe(self):
        content = "binary-\x00-safe \U0001f600 text"
        res = self.be.execute("write_file",
                              {"path": "out/note.txt", "content": content},
                              {"path_outside_sandbox": False})
        self.assertEqual(res["bytes"], len(content))
        self.assertTrue(res["sandboxed"])
        # Written by the CHILD process, byte-identical.
        self.assertEqual((self.sb_root / "out/note.txt")
                         .read_text(encoding="utf-8"), content)
        back = self.be.execute("read_file", {"path": "out/note.txt"},
                               {"path_outside_sandbox": False})
        self.assertEqual(back["content"], content)

    def test_outside_write_quarantined(self):
        res = self.be.execute(
            "write_file", {"path": "/etc/real.txt", "content": "x"},
            {"path_outside_sandbox": True})
        self.assertIn("quarantined", res["note"])
        self.assertTrue(Path(res["path"]).is_relative_to(self.q_root))
        self.assertFalse(Path("/etc/real.txt").exists())

    def test_delete_file(self):
        res = self.be.execute("delete_file", {"path": "data.txt"},
                              {"path_outside_sandbox": False})
        self.assertEqual(res, {"deleted": True,
                               "path": str(self.sb_root / "data.txt"),
                               "sandboxed": True})
        self.assertFalse((self.sb_root / "data.txt").exists())

    def test_delete_missing_is_noop(self):
        res = self.be.execute("delete_file", {"path": "nope.txt"},
                              {"path_outside_sandbox": False})
        self.assertEqual(res, {"deleted": False,
                               "note": "simulated; no file touched"})

    def test_synthetic_tools_unchanged(self):
        self.assertEqual(
            self.be.execute("api_call", {"endpoint": "e"}, {}),
            {"status": 200, "synthetic": True, "endpoint": "e",
             "items_returned": 2})
        self.assertEqual(
            self.be.execute("http_post", {"url": "https://x"}, {}),
            {"status": 202, "synthetic": True, "url": "https://x"})
        self.assertEqual(
            self.be.execute("send_email", {"to": "a@b"}, {})["to"], "a@b")
        self.assertEqual(self.be.execute("frobnicate", {}, {}),
                         {"note": "unknown tool; simulated no-op"})

    def test_write_escape_attempt_never_reaches_child(self):
        with self.assertRaises(ValueError):
            self.be.execute("write_file",
                            {"path": "../../pwned.txt", "content": "x"},
                            {"path_outside_sandbox": False})


class InstallWiringTest(unittest.TestCase):
    """install() swaps the backend with zero edits to gov/executor.py."""

    def test_install_routes_through_governance_pipeline(self):
        from tests.harness import make_run, plant_file
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        plant_file(ctx, "notes.txt", "governed content here")
        # "coder" role is allowed read_file + write_file by the default policy.
        ident = ctx["identities"]["coder"]
        backend = install(ctx["executor"])
        self.assertIsInstance(backend, SandboxedToolBackend)

        rec = ctx["executor"].call(ident, "read_file", path="notes.txt")
        self.assertEqual(rec["status"], "executed")
        self.assertIn("governed content here", rec["result"]["content"])
        self.assertTrue(rec["result"]["sandboxed"])

        rec = ctx["executor"].call(ident, "write_file", path="child.txt",
                                   content="written by child")
        self.assertEqual(rec["status"], "executed")
        self.assertTrue((ctx["executor"].sandbox / "child.txt").exists())

    def test_install_accepts_custom_backend(self):
        from tests.harness import make_run
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        custom = SandboxedToolBackend(ctx["executor"].sandbox,
                                      ctx["executor"].quarantine,
                                      sandbox=Sandbox(timeout=3))
        self.assertIs(install(ctx["executor"], custom), custom)

    def test_install_escaping_read_is_loud_not_silent(self):
        # H2 regression test (wave-117 audit): call() passes
        # identity= to _simulate; the installed backend must accept it
        # (it is a drop-in replacement), AND the escaping read must
        # emit a chained sandbox_traversal_contained event -- the
        # backend path contained silently, the exact defect H2 fixed
        # on the plain-executor path.
        from tests.harness import make_run
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        ident = ctx["identities"]["coder"]
        install(ctx["executor"])
        rec = ctx["executor"].call(ident, "read_file", path="../plan.txt",
                                   justification="h2 backend probe")
        self.assertEqual(rec["status"], "executed")
        self.assertEqual(rec["result"]["content"],
                         "[synthetic file contents]")
        found = [e for e in ctx["read_log"]()
                 if e.get("event") == "sandbox_traversal_contained"]
        self.assertEqual(len(found), 1,
                         "escaping read through the installed backend "
                         "must emit exactly one chained "
                         "sandbox_traversal_contained event")
        self.assertEqual(found[0].get("cause"), "path_outside_sandbox")



class PidNamespaceTest(unittest.TestCase):
    """The /proc/<ppid>/environ exfiltration vector and its fix.

    Scrubbing the child's own environ is not enough: any same-UID child
    can open /proc/<ppid>/environ and read the PARENT's environment —
    including GOV_LOG_KEY. Running the worker as PID 1 in a descendant
    PID namespace makes cross-namespace ptrace fail, so the parent's
    environ (and even its PID number) is unreachable.
    """

    @unittest.skipUnless(PIDNS, "PID namespace unavailable on this kernel")
    def test_parent_environ_not_visible_through_procfs(self):
        canary = "gov-pidns-canary-%d" % os.getpid()
        os.environ["GOV_PIDNS_TEST_CANARY"] = canary
        self.addCleanup(os.environ.pop, "GOV_PIDNS_TEST_CANARY", None)
        s = fast_sandbox()
        self.assertTrue(s.pid_isolated)
        r = s.run_python(
            "import os\n"
            "ppid = os.getppid()\n"
            "out = []\n"
            "for label, p in (('ppid', ppid), ('one', 1)):\n"
            "    try:\n"
            "        data = open('/proc/%d/environ' % p, 'rb').read()\n"
            "        out.append(label + '=' + ('VISIBLE' if b'" + canary + "' in data else 'hidden'))\n"
            "    except Exception as e:\n"
            "        out.append(label + '=BLOCKED:' + type(e).__name__)\n"
            "print('\\n'.join(out))\n")
        self.assertTrue(r.ok, r)
        self.assertTrue(r.pid_isolated)
        for line in r.stdout.splitlines():
            self.assertFalse(line.endswith("VISIBLE"),
                             "parent environ leaked via " + line)

    @unittest.skipUnless(PIDNS, "PID namespace unavailable on this kernel")
    def test_exit_code_forwarded_through_intermediate(self):
        # The pidns path double-forks; the intermediate must forward the
        # worker's real exit status or failures become invisible.
        s = fast_sandbox()
        for code in (0, 1, 42):
            r = s.run(["/bin/bash", "-c", "exit %d" % code])
            self.assertEqual(r.returncode, code)
            self.assertEqual(r.ok, code == 0)

    @unittest.skipUnless(PIDNS, "PID namespace unavailable on this kernel")
    def test_timeout_kills_through_double_fork(self):
        s = Sandbox(timeout=2)
        t0 = time.monotonic()
        r = s.run_python("import time; time.sleep(60)")
        wall = time.monotonic() - t0
        self.assertTrue(r.timed_out)
        self.assertLess(wall, 15)

    def test_pidns_flag_honest_when_disabled(self):
        s = fast_sandbox(use_pidns=False)
        self.assertFalse(s.pid_isolated)
        r = s.run(["/bin/true"])
        self.assertTrue(r.ok)
        self.assertFalse(r.pid_isolated)

    def test_stdin_size_cap(self):
        s = fast_sandbox()
        with self.assertRaises(ValueError):
            s.run(["/bin/cat"], stdin_data=b"x" * ((64 << 20) + 1))


class PidNamespaceFallbackTest(unittest.TestCase):
    """A sporadic unshare()/fork() failure must never be mislabeled.

    Regression context: a one-time PID-namespace setup failure made the
    worker silently fall back to running as a direct child; it then saw
    its real parent PID via os.getppid() and os.kill()ed the parent (the
    harness died with exit 137). The child now reports per-call ground
    truth over a status pipe, and strict mode refuses to exec at all.
    """

    def _force_unshare_failure(self):
        # Patch os.unshare in THIS process; the forked pre-exec child
        # inherits the patched attribute, so its namespace setup really
        # fails through the production code path (no test hooks).
        real = os.unshare
        def _boom(*args, **kwargs):
            raise OSError(22, "forced unshare failure for test")
        os.unshare = _boom
        self.addCleanup(setattr, os, "unshare", real)

    def test_fallback_reports_not_isolated(self):
        s = fast_sandbox()  # constructed BEFORE patching: probe is honest
        self._force_unshare_failure()
        r = s.run(["/bin/echo", "still-runs"])
        self.assertTrue(r.ok, r)
        self.assertEqual(r.stdout.strip(), "still-runs")
        self.assertFalse(r.pid_isolated,
                         "fallback must not be labeled pid-isolated")
        self.assertFalse(r.network_isolated,
                         "fallback must not be labeled net-isolated")
        self.assertIn("fallback", r.note)

    def test_require_pidns_refuses_and_never_execs(self):
        s = fast_sandbox(require_pidns=True)
        self._force_unshare_failure()
        canary = Path(tempfile.mkdtemp()) / "should-not-exist"
        self.addCleanup(shutil.rmtree, str(canary.parent), True)
        with self.assertRaises(SandboxError):
            s.run_python(
                "open(%r, 'w').write('executed')" % str(canary))
        self.assertFalse(canary.exists(),
                         "strict mode must stop the child before exec")

    def test_require_netns_refuses(self):
        s = fast_sandbox(require_netns=True)
        self._force_unshare_failure()
        with self.assertRaises(SandboxError):
            s.run(["/bin/true"])

    def test_require_flags_conflict_with_disabled(self):
        with self.assertRaises(ValueError):
            fast_sandbox(use_pidns=False, require_pidns=True)
        with self.assertRaises(ValueError):
            fast_sandbox(use_netns=False, require_netns=True)

    def test_require_pidns_parent_survives_kill_attempt(self):
        # The exact incident, replayed inside a disposable subprocess so a
        # regression can never take down the test runner: forced fallback
        # + a worker that SIGKILLs its parent. Strict mode must refuse
        # before exec; the subprocess must exit cleanly.
        repo = os.path.dirname(_TESTS_DIR)
        script = (
            "import os, sys\n"
            "sys.path.insert(0, %r)\n"
            "from gov.sandbox import Sandbox, SandboxError\n"
            "real = os.unshare\n"
            "def _boom(*a, **k):\n"
            "    raise OSError(22, 'forced')\n"
            "os.unshare = _boom\n"
            "s = Sandbox(timeout=8, require_pidns=True)\n"
            "try:\n"
            "    s.run_python('import os, signal\\n"
            "os.kill(os.getppid(), signal.SIGKILL)\\n')\n"
            "    print('NO-RAISE-BAD')\n"
            "except SandboxError:\n"
            "    print('REFUSED-OK')\n" % repo)
        import subprocess as _sp
        p = _sp.run([sys.executable, "-u", "-c", script],
                    capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0,
                         "subprocess died: stdout=%r stderr=%r"
                         % (p.stdout, p.stderr))
        self.assertIn("REFUSED-OK", p.stdout)


class TraversalContainmentLoudTest(unittest.TestCase):
    """F-RA3 (H2): read-side traversal containment is a chained audit
    event, not silence.

    Red-first: before the fix, an escaping read_file was contained to
    synthetic content with zero audit entries naming the containment.
    """

    def _events(self, ctx, agent_id):
        return [e for e in ctx["read_log"]()
                if isinstance(e, dict)
                and e.get("event") == "sandbox_traversal_contained"
                and e.get("agent_id") == agent_id]

    def test_escaping_read_emits_chained_containment_event(self):
        from tests.harness import make_run
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        ident = ctx["executor"].mint_identity("loud-agent", "coder",
                                              "loud-principal")
        outside = Path(ctx["run_dir"]).parent / "plan.txt"
        rec = ctx["executor"].call(ident, "read_file",
                                   path="../plan.txt",
                                   justification="h2 unit test")
        self.assertEqual(rec["status"], "executed")
        self.assertEqual(rec["result"]["content"],
                         "[synthetic file contents]")
        self.assertFalse(outside.exists(),
                         "containment must not touch the real path")
        events = self._events(ctx, "loud-agent")
        self.assertEqual(len(events), 1,
                         "exactly one loud containment event, got %r"
                         % (events,))
        ev = events[0]
        self.assertEqual(ev["cause"], "path_outside_sandbox")
        self.assertEqual(ev["path"], "../plan.txt")
        self.assertEqual(ev["tool"], "read_file")
        self.assertEqual(ev["decision"], "contained")
        # The event is chained: it carries a sequence number.
        self.assertIn("seq", ev)

    def test_benign_read_emits_no_containment_event(self):
        from tests.harness import make_run, plant_file
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        plant_file(ctx, "notes.txt", "hello")
        ident = ctx["executor"].mint_identity("quiet-agent", "coder",
                                              "quiet-principal")
        rec = ctx["executor"].call(ident, "read_file", path="notes.txt",
                                   justification="h2 unit test")
        self.assertEqual(rec["status"], "executed")
        self.assertIn("hello", rec["result"]["content"])
        self.assertEqual(self._events(ctx, "quiet-agent"), [],
                         "benign reads must stay quiet")

    def test_missing_in_sandbox_read_stays_quiet(self):
        from tests.harness import make_run
        ctx = make_run()
        self.addCleanup(lambda: shutil.rmtree(ctx["run_dir"],
                                              ignore_errors=True))
        ident = ctx["executor"].mint_identity("miss-agent", "coder",
                                              "miss-principal")
        rec = ctx["executor"].call(ident, "read_file",
                                   path="does-not-exist.txt",
                                   justification="h2 unit test")
        self.assertEqual(rec["status"], "executed")
        self.assertEqual(rec["result"]["content"],
                         "[synthetic file contents]")
        self.assertEqual(self._events(ctx, "miss-agent"), [],
                         "a missing in-sandbox file is not a traversal")


if __name__ == "__main__":
    unittest.main()
