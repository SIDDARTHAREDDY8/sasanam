"""Contained subprocess execution backend for agent tools.

``gov/executor.py`` mediates every tool call (identity, DLP, policy,
approvals, logging) but its tool *effects* are simulated in-process via
``_simulate``. This module provides the real execution backend:
:class:`SandboxedToolBackend`, which runs file operations in short-lived,
resource-bounded child processes, plus the general-purpose :class:`Sandbox`
primitive it is built on.

Containment model (per call)
----------------------------
* ``shell=False`` always; the command is an argv vector. Shell metacharacters
  are inert data (tested).
* Fresh, empty temporary working directory per call; removed afterwards.
* Environment scrubbed: only an explicit allowlist plus caller-supplied
  ``extra_env`` reaches the child. Parent secrets never cross.
* New process session (``start_new_session=True``); on timeout the whole
  process *group* is SIGKILLed, so grandchildren die too.
* Wall-clock timeout enforced by the parent, independent of child clocks.
* stdout/stderr drained in bounded chunks via ``selectors`` — a 50 MB
  output bomb is truncated at the cap, never buffered whole (no
  ``communicate()`` unbounded read).
* POSIX resource limits in the child (``resource.setrlimit``):
  CPU seconds, address space, max file size, max open FDs, max processes.
* Network namespace (``unshare(CLONE_NEWNET)``) when available: no route to
  anything, loopback down. ``SandboxResult.network_isolated`` reports the
  ground truth; when the primitive is unavailable the flag is False and the
  sandbox still enforces everything else.
* PID namespace (``unshare(CLONE_NEWPID)``) when available: the worker runs
  as PID 1 in a descendant namespace, so ``/proc/<ppid>/environ`` — which
  would otherwise leak the *parent's* environment (including ``GOV_LOG_KEY``)
  to any same-UID child — is unreadable (cross-namespace ptrace check).
  The intermediate process forwards the worker's exit status, so ``Popen``
  still observes the right code.
* Per-call honest isolation reporting: the child reports back over a status
  pipe whether the network/PID namespaces were *actually* established for
  *this* call, so a sporadic ``unshare``/``fork`` failure can never be
  mislabeled as isolated. ``SandboxResult.network_isolated`` and
  ``SandboxResult.pid_isolated`` carry that per-call ground truth.
* Fail-closed strict mode: ``Sandbox(require_pidns=True)`` (and/or
  ``require_netns=True``) refuses to execute the child at all when the
  namespace cannot be established — the pre-exec hook exits before
  ``exec``, so hostile code never runs unisolated. Without strict mode the
  sandbox still runs (defense-in-depth limits apply) but reports the
  fallback honestly. NOTE: without the PID namespace, a same-UID worker
  *can* signal the parent by explicit PID (demonstrated: a sporadic
  one-time ``unshare`` failure let a fallback worker ``os.kill()`` its
  real parent). Hostile-code execution must use ``require_pidns=True``.

Honest limitations (see also THREAT_MODEL.md)
--------------------------------------------
* The temp-dir cwd is **not** a chroot/filesystem jail: a hostile child can
  ``chdir("..")`` and use absolute paths. Filesystem authority therefore
  lives **parent-side**: :class:`SandboxedToolBackend` resolves every path
  and requires it to stay under the run's sandbox/quarantine roots before
  the child ever starts.
* ``RLIMIT_NPROC``/namespaces are per-call best effort on this kernel, not a
  container boundary. Against *arbitrary hostile native code* this is
  defense-in-depth, not a security boundary; the primary guarantee is
  crash/hang/resource-abuse containment for the tool scripts we generate.
* A child that double-forks into a new session escapes the kill group.
  Tool scripts here never do this.
* Without the PID namespace, the worker is a direct child: it can read the
  parent's real PID (``os.getppid()``) and signal it (same UID), and the old
  ``/proc`` mount still exposes host PIDs. The non-strict fallback is
  therefore NOT a hostile-code boundary — it is reported honestly via
  ``pid_isolated=False`` so callers can refuse it (``require_pidns=True``).

Integration (coordinator wiring — one call, no executor.py edits)::

    from gov import sandbox
    backend = sandbox.install(executor)  # replaces executor._simulate
"""

import base64
import contextlib
import fcntl
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# -- tunables ---------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0          # wall-clock seconds per call
DEFAULT_MAX_OUTPUT = 1 << 20    # per-stream stdout/stderr cap (bytes)
DEFAULT_MEMORY = 256 << 20      # RLIMIT_AS
DEFAULT_CPU = 10                # RLIMIT_CPU seconds
DEFAULT_MAX_FILE = 16 << 20     # RLIMIT_FSIZE
DEFAULT_MAX_FDS = 64            # RLIMIT_NOFILE
DEFAULT_MAX_PROCS = 64          # RLIMIT_NPROC
DEFAULT_MAX_STDIN = 64 << 20    # cap on stdin_data per call
DEFAULT_PATH = "/usr/bin:/bin"

# Env vars a child is allowed to inherit from the parent. Everything else —
# API keys, tokens, GOV_* — is dropped.
DEFAULT_ALLOWED_ENV = (
    "HOME", "TMPDIR", "TEMP", "TMP",
    "LC_ALL", "LANG", "LANGUAGE", "TZ",
    "PYTHONIOENCODING", "PYTHONHASHSEED",
)

_CHILD_READ_SCRIPT = (
    "import sys, base64\n"
    "data = open(sys.argv[1], 'rb').read()\n"
    "sys.stdout.write(base64.b64encode(data).decode('ascii'))\n"
)
_CHILD_WRITE_SCRIPT = (
    "import sys, base64\n"
    "raw = base64.b64decode(sys.stdin.read())\n"
    "os = __import__('os')\n"
    "os.makedirs(os.path.dirname(sys.argv[1]) or '.', exist_ok=True)\n"
    "open(sys.argv[1], 'wb').write(raw)\n"
)
_CHILD_DELETE_SCRIPT = (
    "import sys, os\n"
    "os.unlink(sys.argv[1])\n"
)

_netns_cache = None
_pidns_cache = None


def netns_available():
    """True if this kernel lets an unprivileged child unshare(CLONE_NEWNET).

    Probed once per process inside a forked child so the parent's own
    network namespace is never touched.
    """
    global _netns_cache
    if _netns_cache is None:
        if os.name != "posix" or not hasattr(os, "unshare"):
            _netns_cache = False
        else:
            pid = os.fork()
            if pid == 0:  # child
                try:
                    os.unshare(os.CLONE_NEWNET)
                except OSError:
                    os._exit(1)
                else:
                    os._exit(0)
            _, status = os.waitpid(pid, 0)
            _netns_cache = os.waitstatus_to_exitcode(status) == 0
    return _netns_cache


def pidns_available():
    """True if an unprivileged child may unshare(CLONE_NEWPID).

    The PID namespace is what defeats ``/proc/<ppid>/environ`` snooping: a
    process in a descendant PID namespace cannot ptrace (and therefore
    cannot read ``environ`` of) processes in the ancestor namespace, even
    through the inherited ``/proc`` mount.
    """
    global _pidns_cache
    if _pidns_cache is None:
        if os.name != "posix" or not hasattr(os, "unshare"):
            _pidns_cache = False
        else:
            pid = os.fork()
            if pid == 0:  # child
                try:
                    os.unshare(os.CLONE_NEWPID)
                except OSError:
                    os._exit(1)
                else:
                    os._exit(0)
            _, status = os.waitpid(pid, 0)
            _pidns_cache = os.waitstatus_to_exitcode(status) == 0
    return _pidns_cache


class SandboxError(RuntimeError):
    """Raised when the sandbox refuses to run.

    Currently raised only by the fail-closed strict modes
    (``require_pidns=True`` / ``require_netns=True``) when the required
    namespace cannot be established for a call: the child is stopped before
    ``exec`` and the error is raised instead of running it unisolated.
    """


@dataclass
class SandboxResult:
    ok: bool
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    wall_seconds: float = 0.0
    network_isolated: bool = False
    pid_isolated: bool = False
    note: str = ""

    @property
    def truncated(self):
        return self.stdout_truncated or self.stderr_truncated


class Sandbox:
    """Contained child-process runner. Instances are stateless across calls
    (each run gets a fresh jail) and safe to share between threads."""

    def __init__(self, *, timeout=DEFAULT_TIMEOUT,
                 max_output_bytes=DEFAULT_MAX_OUTPUT,
                 memory_bytes=DEFAULT_MEMORY, cpu_seconds=DEFAULT_CPU,
                 max_file_bytes=DEFAULT_MAX_FILE, max_fds=DEFAULT_MAX_FDS,
                 max_procs=DEFAULT_MAX_PROCS,
                 allowed_env=DEFAULT_ALLOWED_ENV, extra_env=None,
                 use_netns=True, use_pidns=True,
                 require_netns=False, require_pidns=False):
        if require_netns and not use_netns:
            raise ValueError("require_netns=True conflicts with use_netns=False")
        if require_pidns and not use_pidns:
            raise ValueError("require_pidns=True conflicts with use_pidns=False")
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.memory_bytes = memory_bytes
        self.cpu_seconds = cpu_seconds
        self.max_file_bytes = max_file_bytes
        self.max_fds = max_fds
        self.max_procs = max_procs
        self.allowed_env = tuple(allowed_env)
        self.extra_env = dict(extra_env or {})
        self.use_netns = bool(use_netns)
        self.use_pidns = bool(use_pidns)
        self.require_netns = bool(require_netns)
        self.require_pidns = bool(require_pidns)
        self.network_isolated = self.use_netns and netns_available()
        self.pid_isolated = self.use_pidns and pidns_available()

    # -- public API -------------------------------------------------------

    @contextlib.contextmanager
    def temp_jail(self):
        """A fresh empty directory, removed on exit."""
        d = Path(tempfile.mkdtemp(prefix="gov-sandbox-"))
        try:
            yield d
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def run(self, argv, *, cwd=None, stdin_data=None, timeout=None,
            extra_env=None):
        """Run argv (a sequence — never a shell string) contained.

        Returns SandboxResult. Raises TypeError/ValueError on bad argv
        (fail closed: never exec anything ambiguous).
        """
        timeout = self.timeout if timeout is None else timeout
        argv = self._checked_argv(argv)
        if stdin_data is not None and not isinstance(stdin_data, bytes):
            raise TypeError("stdin_data must be bytes or None")
        if stdin_data is not None and len(stdin_data) > DEFAULT_MAX_STDIN:
            raise ValueError("stdin_data exceeds %d bytes"
                             % DEFAULT_MAX_STDIN)

        jail_ctx = (contextlib.nullcontext(Path(cwd)) if cwd is not None
                    else self.temp_jail())
        with jail_ctx as jail:
            if not jail.is_dir():
                raise ValueError("cwd %r is not a directory" % (str(jail),))
            child_env = self._child_env(jail, extra_env)
            # Status pipe: the pre-exec hook reports the per-call ground
            # truth (network namespace ok? PID namespace ok?) as two bytes
            # before exec/waitpid. pass_fds keeps the write end open in the
            # child; the parent reads exactly two bytes (never EOF-wait:
            # the hook always writes before exec, and a dead child yields
            # EOF, which we treat as "not isolated").
            status_r, status_w = os.pipe()
            preexec = self._make_preexec(argv, child_env, status_w)
            start = time.monotonic()
            try:
                proc = subprocess.Popen(
                    argv, cwd=str(jail), env=child_env,
                    stdin=(subprocess.PIPE if stdin_data is not None
                           else subprocess.DEVNULL),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True, preexec_fn=preexec,
                    pass_fds=(status_w,))
            finally:
                # Parent never writes; the child (or its death) closes it.
                os.close(status_w)
            try:
                marker = b""
                while len(marker) < 2:
                    chunk = os.read(status_r, 2 - len(marker))
                    if not chunk:
                        break  # child died before reporting: not isolated
                    marker += chunk
            finally:
                os.close(status_r)
            net_isolated = len(marker) == 2 and marker[0] == 1
            pid_isolated = len(marker) == 2 and marker[1] == 1
            missing_ns = []
            if self.require_netns and not net_isolated:
                missing_ns.append("network")
            if self.require_pidns and not pid_isolated:
                missing_ns.append("PID")
            if missing_ns:
                # Fail closed: the child was stopped before exec by the
                # pre-exec hook (or died before reporting), so it never
                # ran unisolated. Reap it, close our pipes, and refuse.
                self._kill_group(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                for _stream in (proc.stdin, proc.stdout, proc.stderr):
                    if _stream is not None:
                        try:
                            _stream.close()
                        except OSError:
                            pass
                raise SandboxError(
                    "%s namespace(s) required but not established"
                    % "+".join(missing_ns))
            try:
                if stdin_data is not None:
                    try:
                        proc.stdin.write(stdin_data)
                    except BrokenPipeError:
                        pass
                    try:
                        proc.stdin.close()
                    except BrokenPipeError:
                        pass
                result = self._supervise(proc, timeout, start)
            finally:
                # Belt and suspenders: never leave the group behind.
                if proc.poll() is None:
                    self._kill_group(proc)
                    proc.wait()
                for _stream in (proc.stdin, proc.stdout, proc.stderr):
                    if _stream is not None:
                        try:
                            _stream.close()
                        except OSError:
                            pass
            # Per-call ground truth from the status pipe (never the
            # probe-based capability flags: a sporadic unshare/fork failure
            # must not be mislabeled as isolated).
            result.network_isolated = net_isolated
            result.pid_isolated = pid_isolated
            if not net_isolated or not pid_isolated:
                missing = []
                if not net_isolated:
                    missing.append("network")
                if not pid_isolated:
                    missing.append("PID")
                fallback_note = ("namespace fallback: %s namespace(s) not "
                                 "established for this call; ran with "
                                 "defense-in-depth limits only"
                                 % "+".join(missing))
                result.note = (result.note + "; " + fallback_note
                               if result.note else fallback_note)
            return result

    def run_python(self, code, *, argv_extra=(), **kwargs):
        """Run a Python snippet contained. ``-I`` = isolated mode: ignores
        PYTHONPATH and user site-packages, so the child cannot import
        attacker-planted modules via the environment."""
        return self.run([sys.executable, "-I", "-c", code, *argv_extra],
                        **kwargs)

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _checked_argv(argv):
        if isinstance(argv, str):
            raise TypeError(
                "argv must be a sequence of program arguments, not a shell "
                "string (shell=False always)")
        if not isinstance(argv, (list, tuple)):
            raise TypeError("argv must be a list/tuple, got %r"
                            % type(argv).__name__)
        if not argv:
            raise ValueError("argv must not be empty")
        clean = []
        for a in argv:
            if not isinstance(a, str):
                raise TypeError("argv elements must be str, got %r"
                                % type(a).__name__)
            if "\x00" in a:
                raise ValueError("NUL byte in argv element")
            clean.append(a)
        return clean

    def _child_env(self, jail, extra_env):
        env = {"PATH": DEFAULT_PATH}
        for k in self.allowed_env:
            if k in os.environ:
                env[k] = os.environ[k]
        env["HOME"] = str(jail)
        env["TMPDIR"] = str(jail)
        env.update(self.extra_env)
        env.update(extra_env or {})
        for k, v in env.items():
            if "\x00" in k or "\x00" in v:
                raise ValueError("NUL byte in environment")
        return env

    def _make_preexec(self, argv, child_env, status_w):
        use_netns = self.use_netns
        use_pidns = self.use_pidns
        require_netns = self.require_netns
        require_pidns = self.require_pidns
        mem, cpu = self.memory_bytes, self.cpu_seconds
        fsize, nfds, nproc = (self.max_file_bytes, self.max_fds,
                              self.max_procs)

        def _apply_rlimits():
            try:
                import resource as _r
            except ImportError:
                return
            def _lim(res_id, value):
                try:
                    _r.setrlimit(res_id, (value, value))
                except (ValueError, OSError):
                    pass
            _lim(_r.RLIMIT_CPU, cpu)
            _lim(_r.RLIMIT_AS, mem)
            _lim(_r.RLIMIT_FSIZE, fsize)
            _lim(_r.RLIMIT_NOFILE, nfds)
            if hasattr(_r, "RLIMIT_NPROC"):
                _lim(_r.RLIMIT_NPROC, nproc)

        def _report(net_ok, pid_ok):
            # Tell the parent the per-call ground truth: which namespaces
            # were actually established. Best effort — if the write itself
            # fails the parent sees EOF and treats the call as unisolated.
            try:
                os.write(status_w, bytes((1 if net_ok else 0,
                                          1 if pid_ok else 0)))
            except OSError:
                pass

        def _preexec():
            _apply_rlimits()
            net_ok = False
            if use_netns:
                try:
                    os.unshare(os.CLONE_NEWNET)
                except OSError:
                    pass  # reported honestly below; strict mode refuses
                else:
                    net_ok = True
            if require_netns and not net_ok:
                # Fail closed BEFORE exec: hostile code never runs with the
                # network still attached.
                _report(False, False)
                os._exit(127)
            pid_ok = False
            if use_pidns and hasattr(os, "unshare"):
                # PID namespace: the worker becomes PID 1 in a descendant
                # namespace, so /proc/<outer-pid>/environ is unreadable
                # (cross-namespace ptrace check fails) even though the old
                # /proc mount still lists host PIDs. Defeats the
                # "read the parent's environment" exfiltration vector and,
                # critically, keeps the worker from learning the parent's
                # real PID (getppid() == 0), so it cannot signal the parent.
                # The intermediate waitpids the worker and forwards its
                # exit status, so Popen still observes the worker's code.
                try:
                    os.unshare(os.CLONE_NEWPID)
                except OSError:
                    pass  # reported honestly below; strict mode refuses
                else:
                    try:
                        pid = os.fork()
                    except OSError:
                        pass  # reported honestly below; strict mode refuses
                    else:
                        if pid == 0:
                            try:
                                os.execvpe(argv[0], argv, child_env)
                            except OSError:
                                os._exit(127)
                        # Intermediate: report success BEFORE closing fds
                        # (closerange would close the status fd too).
                        _report(net_ok, True)
                        # Close every inherited fd except stdio (notably the
                        # errpipe Popen uses to detect child-side failures:
                        # as long as we hold it open, the parent blocks in
                        # Popen.__init__ waiting for EOF). The worker was
                        # already forked, so it keeps its stdio pipes.
                        try:
                            os.closerange(3, os.sysconf("SC_OPEN_MAX"))
                        except (ValueError, OSError):
                            pass
                        _, status = os.waitpid(pid, 0)
                        os._exit(os.waitstatus_to_exitcode(status))
            if require_pidns and not pid_ok:
                # Fail closed BEFORE exec: without the PID namespace a
                # same-UID worker can os.kill() the parent by explicit PID
                # (demonstrated). Never run hostile code this way.
                _report(net_ok, False)
                os._exit(127)
            # Fallback path (no PID namespace): Popen execs argv directly
            # after this function returns. Reported honestly as
            # pid_isolated=False; callers that need the hostile-code
            # boundary must pass require_pidns=True.
            _report(net_ok, False)
        return _preexec

    @staticmethod
    def _kill_group(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def _supervise(self, proc, timeout, start):
        """Drain stdout/stderr in bounded chunks; enforce the deadline;
        SIGKILL the process group on timeout."""
        cap = self.max_output_bytes
        deadline = start + timeout
        # Non-blocking pipes: read() can never block, so the wall-clock
        # deadline is honored even if select() ever fires spuriously.
        for _f in (proc.stdout, proc.stderr):
            _fl = fcntl.fcntl(_f.fileno(), fcntl.F_GETFL)
            fcntl.fcntl(_f.fileno(), fcntl.F_SETFL, _fl | os.O_NONBLOCK)
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        chunks = {"out": [], "err": []}
        totals = {"out": 0, "err": 0}
        trunc = {"out": False, "err": False}
        open_streams = {"out", "err"}
        timed_out = False

        while open_streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for key, _ in sel.select(timeout=remaining):
                name = key.data
                try:
                    data = key.fileobj.read(65536)
                except BlockingIOError:
                    continue  # spurious wakeup; fd is non-blocking
                except (OSError, ValueError):
                    data = b""
                if not data:  # EOF
                    sel.unregister(key.fileobj)
                    open_streams.discard(name)
                    continue
                room = cap - totals[name]
                if room <= 0:
                    # Cap already hit: keep draining (discard) so a child
                    # with finite-but-large output can still exit cleanly.
                    # An infinite stream runs into the wall-clock deadline.
                    trunc[name] = True
                    continue
                if len(data) > room:
                    data = data[:room]
                    trunc[name] = True
                chunks[name].append(data)
                totals[name] += len(data)
        sel.close()

        if proc.poll() is None:
            # Pipes are closed but the child (or a forked descendant holding
            # a pipe) is still alive: wait for exit until the deadline, then
            # SIGKILL the whole process group.
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass
            if proc.poll() is None:
                timed_out = True
                self._kill_group(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        wall = time.monotonic() - start
        note = ""
        if timed_out:
            note = ("wall-clock timeout (%.1fs): process group SIGKILLed"
                    % timeout)
        elif trunc["out"] or trunc["err"]:
            note = "output truncated at %d bytes per stream" % cap
        return SandboxResult(
            ok=(proc.returncode == 0 and not timed_out),
            returncode=proc.returncode,
            stdout=b"".join(chunks["out"]).decode("utf-8", errors="replace"),
            stderr=b"".join(chunks["err"]).decode("utf-8", errors="replace"),
            timed_out=timed_out,
            stdout_truncated=trunc["out"],
            stderr_truncated=trunc["err"],
            wall_seconds=wall,
            note=note)


class SandboxedToolBackend:
    """Drop-in replacement for ``ToolExecutor._simulate``.

    Same ``(tool, args, ctx) -> dict`` contract and same result shapes; file
    operations additionally execute inside :class:`Sandbox` child processes.
    Synthetic tools (api_call/http_post/send_email/unknown) return their
    synthetic dicts directly — there is nothing to isolate.

    Path authority stays parent-side: every path is resolved and required to
    sit under ``sandbox_root`` (or the quarantine root for outside-sandbox
    writes) BEFORE any child starts. The child never decides where IO goes.
    """

    def __init__(self, sandbox_root, quarantine_root, sandbox=None,
                 op_timeout=DEFAULT_TIMEOUT):
        self.sandbox_root = Path(sandbox_root)
        self.quarantine_root = Path(quarantine_root)
        self._sandbox_resolved = self.sandbox_root.resolve()
        self.sandbox = sandbox or Sandbox(timeout=op_timeout)
        self.op_timeout = op_timeout

    # -- path authority (mirrors ToolExecutor._resolve/_is_outside_sandbox) --

    def _resolve(self, path):
        p = Path(path)
        if not p.is_absolute():
            p = self.sandbox_root / p
        return p

    def _is_outside_sandbox(self, path):
        try:
            rp = self._resolve(path).resolve()
        except OSError:
            rp = Path(os.path.abspath(str(self._resolve(path))))
        return (rp != self._sandbox_resolved
                and self._sandbox_resolved not in rp.parents)

    def _checked_target(self, path):
        """Resolve and confine: raises ValueError on escape attempts."""
        p = self._resolve(path)
        try:
            rp = p.resolve()
        except OSError:
            rp = Path(os.path.abspath(str(p)))
        if rp != self._sandbox_resolved and self._sandbox_resolved not in rp.parents:
            raise ValueError("path escapes sandbox root: %r" % (path,))
        return rp

    # -- the _simulate-compatible entry point ------------------------------

    def execute(self, tool, args, ctx):
        if tool == "read_file":
            return self._read(args, ctx)
        if tool == "write_file":
            return self._write(args, ctx)
        if tool == "delete_file":
            return self._delete(args, ctx)
        if tool == "api_call":
            return {"status": 200, "synthetic": True,
                    "endpoint": args.get("endpoint"), "items_returned": 2}
        if tool == "http_post":
            return {"status": 202, "synthetic": True, "url": args.get("url")}
        if tool == "send_email":
            return {"status": "sent (simulated; no real email leaves this machine)",
                    "to": args.get("to")}
        return {"note": "unknown tool; simulated no-op"}

    def _read(self, args, ctx):
        if ctx.get("path_outside_sandbox"):
            return {"source": "simulated",
                    "content": "[synthetic file contents]"}
        # Defense in depth: re-resolve and confine at USE time, not just at
        # the executor's check time. A stale or dishonest ctx (or a symlink
        # swapped between check and use) must not smuggle an outside path
        # past this point — _checked_target raises ValueError on escape.
        p = self._checked_target(args["path"])
        if p.is_file():
            r = self.sandbox.run_python(_CHILD_READ_SCRIPT,
                                        argv_extra=[str(p)])
            if not r.ok:
                return {"source": "sandbox", "sandboxed": True,
                        "error": "sandboxed read failed: %s"
                                 % (r.note or r.stderr[:200])}
            try:
                content = base64.b64decode(r.stdout).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as e:
                return {"source": "sandbox", "sandboxed": True,
                        "error": "sandboxed read undecodable: %s" % e}
            return {"source": "sandbox", "sandboxed": True,
                    "content": content[:4000]}
        return {"source": "simulated", "content": "[synthetic file contents]"}

    def _write(self, args, ctx):
        content = args.get("content", "")
        text = content if isinstance(content, str) else str(content)
        if ctx.get("path_outside_sandbox"):
            # Even approved, an outside-sandbox write never touches the real
            # path: it is quarantined inside the run directory (parent-side,
            # like _simulate — this is a governance copy, not tool execution).
            q = self.quarantine_root / Path(args["path"]).name
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_text(text, encoding="utf-8")
            return {"path": str(q),
                    "note": "outside sandbox; quarantined inside run dir"}
        target = self._checked_target(args["path"])
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        r = self.sandbox.run_python(_CHILD_WRITE_SCRIPT,
                                    argv_extra=[str(target)],
                                    stdin_data=payload.encode("ascii"))
        if not r.ok:
            return {"sandboxed": True,
                    "error": "sandboxed write failed: %s"
                             % (r.note or r.stderr[:200])}
        return {"path": str(target), "bytes": len(text), "sandboxed": True}

    def _delete(self, args, ctx):
        p = self._resolve(args["path"])
        if not ctx.get("path_outside_sandbox") and p.is_file():
            target = self._checked_target(args["path"])
            r = self.sandbox.run_python(_CHILD_DELETE_SCRIPT,
                                        argv_extra=[str(target)])
            if not r.ok:
                return {"deleted": False, "sandboxed": True,
                        "error": "sandboxed delete failed: %s"
                                 % (r.note or r.stderr[:200])}
            return {"deleted": True, "path": str(target), "sandboxed": True}
        return {"deleted": False, "note": "simulated; no file touched"}


def install(executor, backend=None):
    """Wire the sandboxed backend into a ToolExecutor with no edits to
    ``gov/executor.py``: replaces the ``executor._simulate`` bound method so
    both ``call()`` and the replay path use it. Returns the backend."""
    if backend is None:
        backend = SandboxedToolBackend(executor.sandbox, executor.quarantine)
    executor._simulate = backend.execute
    return backend
