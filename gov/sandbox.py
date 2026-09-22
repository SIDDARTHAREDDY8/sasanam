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

Hardened layers (opt-in, env-gated)
----------------------------------
Beyond the always-on containment above, three stronger layers are
available per Sandbox instance and via environment variables::

    Sandbox(use_pivot_root=True,   # pivot_root(2) filesystem jail
            drop_privs=True,       # setgroups/setgid/setuid -> nobody
            use_seccomp=True)      # seccomp-bpf syscall allowlist

* ``use_pivot_root``: in a fresh mount namespace (plus a user namespace
  when unprivileged), the run's jail becomes ``/`` via ``pivot_root``;
  the old root is detached, mount propagation is made private first, and
  only a read-only staging of the host's ``/usr /bin /lib /lib64 /sbin
  /etc`` plus explicitly requested writable mounts remain visible.
  Absolute host paths (``/tmp``, ``/home``, ``/etc/shadow``) cease to
  exist for the child. A fresh ``/proc`` is mounted when the PID
  namespace is also in use.
* ``drop_privs``: the worker drops to the ``nobody`` uid/gid
  (``setgroups([])``, ``setgid``, ``setuid``) after the pivot, before
  exec. The jail is chown'ed to nobody first so the child can still
  work; everything else it can see is read-only or nobody-owned.
* ``use_seccomp``: a classic-BPF allowlist (``DEFAULT_SECCOMP_ALLOW``)
  installed via ``prctl(SECCOMP_MODE_FILTER)`` after ``NO_NEW_PRIVS``,
  just before exec. Default action is KILL_PROCESS; the socket family,
  ptrace, mount/pivot_root, module loading, kexec/reboot, ``bpf()``,
  ``perf_event_open``, keyctl, userfaultfd and io_uring are deliberately
  absent. A missing syscall kills the child loudly (SIGSYS) — never a
  silent escape.

Each layer has a ``require_*`` fail-closed twin (``require_pivot_root``,
``require_privdrop``, ``require_seccomp``): the child is stopped with
``_exit(127)`` *before* exec when the layer cannot be established, and
``run()`` raises ``SandboxError``. The five per-call ground-truth flags
(``network_isolated``, ``pid_isolated``, ``pivot_active``,
``privdropped``, ``seccomp_active``) are reported over the status pipe
by the worker itself, so a sporadic setup failure is never mislabeled.

Env-gated wiring (optional backend, fail-closed)::

    GOV_SANDBOX_BACKEND=1  GOV_SANDBOX_STRICT=1 \\
    GOV_SANDBOX_PIVOT=1 GOV_SANDBOX_SECCOMP=1 GOV_SANDBOX_PRIVDROP=1 \\
        python -m demo...

``sandbox.install_from_env(executor)`` installs the backend only when
``GOV_SANDBOX_BACKEND=1`` (otherwise it returns None and touches
nothing); when enabled but a requested layer is unavailable on this
kernel/process it raises ``SandboxError`` instead of installing a
degraded backend — never a silent downgrade to unsandboxed.

Honest residuals (read before relying on this for hostile code)
--------------------------------------------------------------
* VM / kernel-exploit-grade isolation is OUTSIDE this layer. The sandbox
  assumes the kernel is trusted: a kernel exploit in the child, a
  container-escape-class bug in namespaces/seccomp, or a compromised
  host kernel defeats every layer here. For hostile *native* code the
  documented ops alternative remains Firecracker (microVM per tool
  call): stronger boundary, real operational cost. This module is
  defense-in-depth for the tool scripts we generate, plus a genuine
  hostile-*script* boundary when all strict flags are on.
* The seccomp-bpf allowlist is a maintenance burden: it is code that
  must track the interpreter, libc, and the tool workload. A new Python
  minor release can require syscalls not listed here; the failure is
  loud (SIGSYS), never silent. Update process: run
  ``python -m gov.sandbox --audit-seccomp`` (needs ``strace``) after any
  interpreter/libc upgrade or workload change, review additions under
  default-deny, extend ``DEFAULT_SECCOMP_ALLOW``, re-run the tests with
  ``use_seccomp=True``, and note the change in
  ``workstreams/sandbox/PROGRESS.md``.
* ``RLIMIT_NPROC``/namespaces are per-call best effort, not a container
  boundary (see the base containment notes above). The ``/etc`` staging
  bind is read-only but does expose host hostnames/resolver config to
  the child; ``/proc`` without the PID namespace still lists host PIDs.
* A child that double-forks into a new session escapes the kill group;
  tool scripts here never do this.
* ``drop_privs`` without ``pivot_root`` needs ``sys.executable`` (and its
  loader path) to be traversable by ``nobody``; where it is not (e.g. a
  home-directory venv on a restrictive mount) the exec fails closed with
  exit 127 and the call reports not-ok. The pivot staging sidesteps this
  by design (it carries its own ``/usr/bin/python3``).
"""

import base64
import contextlib
import ctypes
import fcntl
import os
import platform
import selectors
import shutil
import signal
import struct
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


# ---------------------------------------------------------------------------
# Hardened layers: pivot_root, UID/GID drop, seccomp-bpf.
#
# All three are opt-in per Sandbox instance (use_pivot_root / drop_privs /
# use_seccomp) and env-gated (see sandbox_config_from_env). Each has a
# matching require_* fail-closed flag: when set, the child is stopped with
# os._exit(127) BEFORE exec if the layer cannot be established, and run()
# raises SandboxError instead of returning a result. A sporadic setup
# failure can therefore never be mislabeled as hardened (the same lesson
# as the PID-namespace fallback regression).
# ---------------------------------------------------------------------------

_pivot_cache = None
_seccomp_cache = None
_privdrop_cache = None
_syscall_numbers_cache = None

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7
_ARCH = platform.machine()
_AUDIT_ARCH = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}

# -- availability probes (each runs in a forked child; parent untouched) -----

def pivot_available():
    """True if a child can pivot_root a temp dir in a fresh mount namespace.

    As root this needs only CLONE_NEWNS; unprivileged it additionally needs
    a user namespace with a writable uid_map/gid_map.
    """
    global _pivot_cache
    if _pivot_cache is None:
        if os.name != "posix" or not hasattr(os, "unshare"):
            _pivot_cache = False
        else:
            tmp = tempfile.mkdtemp(prefix="gov-pivot-probe-")
            pid = os.fork()
            if pid == 0:  # child
                try:
                    _do_pivot_root(tmp, None, chown_to_nobody=False)
                    _finish_pivot()
                except OSError:
                    os._exit(1)
                else:
                    os._exit(0)
            _, status = os.waitpid(pid, 0)
            shutil.rmtree(tmp, ignore_errors=True)
            _pivot_cache = os.waitstatus_to_exitcode(status) == 0
    return _pivot_cache


def seccomp_available():
    """True if a child can install a seccomp-bpf filter via prctl.

    Requires SECCOMP_MODE_FILTER support, NO_NEW_PRIVS, a known audit arch,
    and resolvable syscall numbers (kernel headers or the builtin table).
    """
    global _seccomp_cache
    if _seccomp_cache is None:
        _seccomp_cache = False
        if os.name == "posix" and _ARCH in _AUDIT_ARCH:
            numbers = _syscall_numbers()
            if "exit_group" in numbers and "read" in numbers:
                pid = os.fork()
                if pid == 0:  # child
                    try:
                        filt = _build_seccomp_filter(
                            {numbers["exit_group"]}, default_action="kill")
                        _install_seccomp_filter(filt)
                    except Exception:
                        os._exit(1)
                    # Only exit_group is allowed past this point; os._exit
                    # is exactly that syscall, so reaching it proves the
                    # filter installed.
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                _seccomp_cache = os.waitstatus_to_exitcode(status) == 0
    return _seccomp_cache


def privdrop_available():
    """True if this process can drop to the unprivileged 'nobody' user.

    Conservative: only euid 0 is claimed. (Inside a caller-created user
    namespace a non-root process could also drop, but this sandbox does
    not set that up unless pivot_root needs it.)
    """
    global _privdrop_cache
    if _privdrop_cache is None:
        _privdrop_cache = os.name == "posix" and os.geteuid() == 0
    return _privdrop_cache


def _nobody_ids():
    try:
        import pwd
        pw = pwd.getpwnam("nobody")
        return pw.pw_uid, pw.pw_gid
    except (ImportError, KeyError):
        return 65534, 65534


# -- syscall numbers (headers first, builtin x86_64 table as fallback) --------

def _parse_unistd_header(path):
    numbers = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and parts[0] == "#define" \
                        and parts[1].startswith("__NR_"):
                    try:
                        numbers[parts[1][len("__NR_"):]] = int(parts[2])
                    except ValueError:
                        pass
    except OSError:
        pass
    return numbers

# Builtin x86_64 table (verified against kernel headers; see the audit
# helper). Only used when the headers are absent.
_BUILTIN_SYSCALLS_X86_64 = {
    "read": 0, "write": 1, "open": 2, "close": 3, "fstat": 5, "poll": 7,
    "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
    "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25,
    "madvise": 28, "dup": 32, "dup2": 33, "nanosleep": 35, "getpid": 39,
    "clone": 56, "execve": 59, "exit": 60, "wait4": 61, "kill": 62,
    "uname": 63, "fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75,
    "truncate": 76, "ftruncate": 77, "getcwd": 79, "chdir": 80,
    "fchdir": 81, "rename": 82, "mkdir": 83, "unlink": 87, "symlink": 88,
    "readlink": 89, "chmod": 90, "fchmod": 91, "umask": 95,
    "gettimeofday": 96, "getrlimit": 97, "sysinfo": 99, "times": 100,
    "getuid": 102, "getgid": 104, "geteuid": 107, "getegid": 108,
    "getppid": 110, "rt_sigpending": 127, "rt_sigtimedwait": 128,
    "rt_sigsuspend": 130, "sigaltstack": 131, "statfs": 137,
    "fstatfs": 138, "arch_prctl": 158, "gettid": 186, "futex": 202,
    "sched_getaffinity": 204, "getdents64": 217, "set_tid_address": 218,
    "restart_syscall": 219, "fadvise64": 221, "clock_gettime": 228,
    "clock_getres": 229, "clock_nanosleep": 230, "exit_group": 231,
    "epoll_wait": 232, "epoll_ctl": 233, "tgkill": 234, "waitid": 247,
    "tkill": 200, "time": 201, "openat": 257, "mkdirat": 258,
    "newfstatat": 262, "unlinkat": 263, "renameat": 264, "symlinkat": 266,
    "readlinkat": 267, "fchmodat": 268, "faccessat": 269, "pselect6": 270,
    "ppoll": 271, "set_robust_list": 273, "get_robust_list": 274,
    "utimensat": 280, "epoll_pwait": 281, "eventfd": 284, "fallocate": 285,
    "eventfd2": 290, "epoll_create1": 292, "dup3": 293, "pipe2": 294,
    "preadv": 295, "pwritev": 296, "prlimit64": 302, "getcpu": 309,
    "renameat2": 316, "getrandom": 318, "execveat": 322, "membarrier": 324,
    "copy_file_range": 326, "preadv2": 327, "pwritev2": 328, "statx": 332,
    "rseq": 334, "clone3": 435, "close_range": 436, "openat2": 437,
    "faccessat2": 439, "pivot_root": 155,
}


def _syscall_numbers():
    """{name: number} for this arch; {} when unresolvable (no seccomp)."""
    global _syscall_numbers_cache
    if _syscall_numbers_cache is None:
        numbers = {}
        header_dirs = []
        if _ARCH == "x86_64":
            header_dirs = ["/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
                           "/usr/include/asm/unistd_64.h"]
        elif _ARCH == "aarch64":
            header_dirs = ["/usr/include/aarch64-linux-gnu/asm/unistd.h",
                           "/usr/include/asm/unistd.h"]
        for path in header_dirs:
            numbers = _parse_unistd_header(path)
            if numbers:
                break
        if not numbers and _ARCH == "x86_64":
            numbers = dict(_BUILTIN_SYSCALLS_X86_64)
        _syscall_numbers_cache = numbers
    return _syscall_numbers_cache


def _syscall_number(name):
    return _syscall_numbers()[name]


# -- seccomp-bpf allowlist ----------------------------------------------------
#
# Maintenance burden (honest): this allowlist is code. A new Python minor
# release, a new libc, or a new kind of tool script can require syscalls
# that are not listed here; the symptom is loud (the child dies with
# SIGSYS under the default KILL action), never silent. Update process:
#   1. Run `python -m gov.sandbox --audit-seccomp` (needs `strace`): it runs
#      the standard tool workload and reports syscalls used-but-not-allowed
#      and allowed-but-unused.
#   2. Review each addition for necessity (default-deny: if the workload
#      does not need it, leave it out).
#   3. Add the name to DEFAULT_SECCOMP_ALLOW, re-run the sandbox tests with
#      use_seccomp=True, and record the change in workstreams/sandbox/.
# Deliberately NOT allowed (default KILL): the whole socket family
# (network stays dead even if the netns setup ever regressed), ptrace /
# process_vm_*, mount / umount2 / pivot_root (after setup), module loading,
# kexec / reboot, bpf(), perf_event_open, keyctl, userfaultfd, io_uring,
# open_by_handle_at, and seccomp() itself (the child cannot weaken or
# replace its filter).

DEFAULT_SECCOMP_ALLOW = frozenset({
    # process / thread basics
    "read", "write", "readv", "writev", "pread64", "preadv", "preadv2",
    "pwrite64", "pwritev", "pwritev2",
    # file open / stat
    "openat", "openat2", "close", "close_range", "fstat", "newfstatat",
    "statx", "lseek", "readlink", "readlinkat", "getdents64",
    "faccessat", "faccessat2",
    # file mutation
    "mkdir", "mkdirat", "unlink", "unlinkat", "symlink", "symlinkat",
    "rename", "renameat", "renameat2", "chmod", "fchmod", "fchmodat",
    "utimensat", "truncate", "ftruncate", "fallocate", "fsync", "fdatasync",
    "flock", "copy_file_range", "fadvise64",
    # memory
    "brk", "mmap", "mprotect", "munmap", "mremap", "madvise",
    # threads / sync
    "clone", "clone3", "vfork", "futex", "set_tid_address", "set_robust_list",
    "get_robust_list", "rseq",
    # exec / exit
    "execve", "execveat", "exit", "exit_group",
    # waiting
    "wait4", "waitid",
    # ids
    "getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid",
    "getresuid", "getresgid", "access",
    # signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
    "rt_sigtimedwait", "rt_sigsuspend", "sigaltstack", "kill", "tkill",
    "tgkill",
    # pipes / fds
    "pipe", "pipe2", "dup", "dup2", "dup3", "fcntl", "ioctl",
    # polling
    "poll", "ppoll", "select", "pselect6",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "eventfd", "eventfd2",
    # time / randomness
    "clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep",
    "gettimeofday", "time", "times", "getrandom",
    # misc runtime
    "arch_prctl", "uname", "sysinfo", "getrlimit", "prlimit64", "umask",
    "getcwd", "chdir", "fchdir", "sched_yield", "sched_getaffinity",
    "getcpu", "membarrier", "restart_syscall", "statfs", "fstatfs",
})

# Classic BPF encoding.
_BPF_LD_W_ABS = 0x20                     # BPF_LD | BPF_W | BPF_ABS
_BPF_JMP_JEQ_K = 0x15                    # BPF_JMP | BPF_JEQ | BPF_K
_BPF_RET_K = 0x06                        # BPF_RET | BPF_K
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000          # | errno
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 1


def _build_seccomp_filter(allowed_numbers, *, default_action="kill"):
    """Assemble a classic-BPF seccomp filter: arch check, then a linear
    allowlist scan over the sorted syscall numbers. Returns the raw bytes
    (a sequence of 8-byte sock_filter structs)."""
    nrs = sorted(set(allowed_numbers))
    if default_action == "kill":
        default_ret = _SECCOMP_RET_KILL_PROCESS
    elif default_action == "errno":
        default_ret = _SECCOMP_RET_ERRNO | 38  # ENOSYS
    else:
        raise ValueError("default_action must be 'kill' or 'errno'")
    insns = []
    insns.append((_BPF_LD_W_ABS, 0, 0, 4))                    # 0: A <- arch
    # 1: arch matches? skip the KILL, else fall into it.
    insns.append((_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH[_ARCH]))
    insns.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))  # 2: wrong arch
    insns.append((_BPF_LD_W_ABS, 0, 0, 0))                    # 3: A <- nr
    n = len(nrs)
    for i, nr in enumerate(nrs):
        jt = (4 + n + 1) - (4 + i) - 1                       # -> ALLOW
        insns.append((_BPF_JMP_JEQ_K, jt, 0, nr))
    insns.append((_BPF_RET_K, 0, 0, default_ret))             # default
    insns.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))      # ALLOW
    return b"".join(struct.pack("HBBI", code, jt, jf, k)
                    for code, jt, jf, k in insns)


def _bpf_decision(filter_bytes, arch, nr):
    """Pure-Python evaluation of a filter built by _build_seccomp_filter.

    Only the three opcodes the builder emits are supported. Used by the
    audit and the test suite on kernels where live seccomp installation
    is unavailable. Returns the SECCOMP_RET_* action the kernel would
    take for the given (arch, syscall-number) pair.
    """
    insns = [struct.unpack("HBBI", filter_bytes[i:i + 8])
             for i in range(0, len(filter_bytes), 8)]
    data = {4: arch, 0: nr}  # seccomp_data offsets the filter reads
    acc = 0
    pc = 0
    while 0 <= pc < len(insns):
        code, jt, jf, k = insns[pc]
        if code == _BPF_LD_W_ABS:
            acc = data.get(k, 0)
            pc += 1
        elif code == _BPF_JMP_JEQ_K:
            pc += 1 + (jt if acc == k else jf)
        elif code == _BPF_RET_K:
            return k
        else:
            raise SandboxError("audit: unsupported BPF opcode %#x" % code)
    raise SandboxError("audit: filter fell off the end")


class _sock_fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def _install_seccomp_filter(filter_bytes):
    """prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) in this thread.

    Must be called single-threaded (true in the pre-exec child), after
    PR_SET_NO_NEW_PRIVS. Raises OSError on failure.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    prog = _sock_fprog(len(filter_bytes) // 8,
                       ctypes.cast(filter_bytes, ctypes.c_void_p))
    # The kernel copies the filter during prctl; `prog` only needs to stay
    # alive for the call itself.
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER,
                  ctypes.byref(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(),
                      "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed")


def _install_default_seccomp_filter():
    """Install the DEFAULT_SECCOMP_ALLOW filter (default action KILL).

    Raises OSError when syscall numbers cannot be resolved or the filter
    cannot be installed: the caller decides fail-closed vs. honest fallback.
    """
    numbers = _syscall_numbers()
    missing = sorted(n for n in DEFAULT_SECCOMP_ALLOW if n not in numbers)
    if missing:
        raise OSError("no syscall numbers for %s on %s"
                      % (",".join(missing), _ARCH))
    filt = _build_seccomp_filter({numbers[n] for n in DEFAULT_SECCOMP_ALLOW},
                                 default_action="kill")
    _install_seccomp_filter(filt)


# -- pivot_root ---------------------------------------------------------------

_MS_BIND, _MS_REC, _MS_PRIVATE = 4096, 16384, 1 << 18
_MS_RDONLY, _MS_REMOUNT = 1, 32
_MS_NOSUID, _MS_NOEXEC, _MS_NODEV = 2, 8, 4
_MNT_DETACH = 2


def _libc_mount(libc, src, tgt, fstype, flags):
    c_src = src.encode() if isinstance(src, str) else None
    c_tgt = tgt.encode() if isinstance(tgt, str) else None
    c_fstype = fstype.encode() if isinstance(fstype, str) else None
    if libc.mount(c_src, c_tgt, c_fstype, flags, None) != 0:
        raise OSError(ctypes.get_errno(),
                      "mount(%r -> %r, flags=%d) failed" % (src, tgt, flags))


def _pivot_root_call(libc, new_root, put_old):
    a, b = new_root.encode(), put_old.encode()
    try:
        fn = libc.pivot_root
    except AttributeError:
        # Older glibc: raw syscall (155 on x86_64).
        return libc.syscall(_syscall_number("pivot_root"), a, b)
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    fn.restype = ctypes.c_int
    return fn(a, b)


def _write_id_map(which, host_id):
    if which == "gid":
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
    with open("/proc/self/%s_map" % which, "w") as f:
        f.write("0 %d 1\n" % host_id)


def _staging_dirs():
    """Host directories bind-mounted read-only into the pivot root.

    Covers the interpreter, its libraries, and the stdlib on standard
    layouts, plus the real interpreter's own directory ancestry.
    """
    candidates = ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc"]
    exe = os.path.realpath(sys.executable)
    d = os.path.dirname(exe)
    candidates.extend([d, os.path.dirname(d)])
    seen, out = set(), []
    for cand in candidates:
        if cand not in seen and os.path.isdir(cand):
            seen.add(cand)
            out.append(cand)
    return out


def _do_pivot_root(new_root, extra_mounts, *, chown_to_nobody):
    """Pivot the calling process into new_root. Raises OSError on failure.

    Runs in a fresh mount namespace (a user namespace is created first
    when unprivileged). Assembles the new root — a read-only staging of
    the host's /usr /bin /lib /lib64 /sbin /etc plus the writable
    `extra_mounts` ({host: guest_rel}) — then pivot_root(2) into it and
    chdir("/"). The old root is left mounted at /.pivot_old: call
    _finish_pivot() afterwards (which mounts a fresh /proc first, because
    post-detach proc mounts fail with EPERM on some kernels) to detach it.
    After this returns, absolute host paths outside the staging are
    unreachable.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if os.geteuid() != 0:
        os.unshare(os.CLONE_NEWUSER)
        _write_id_map("uid", os.geteuid())
        _write_id_map("gid", os.getegid())
    os.unshare(os.CLONE_NEWNS)
    # Do not propagate our unmounts to the host.
    _libc_mount(libc, None, "/", None, _MS_REC | _MS_PRIVATE)
    # new_root must itself be a mount point for pivot_root(2).
    _libc_mount(libc, new_root, new_root, None, _MS_BIND | _MS_REC)
    # Read-only runtime staging (interpreter + libs + stdlib).
    for host in _staging_dirs():
        guest = os.path.join(new_root, host.lstrip("/"))
        os.makedirs(guest, exist_ok=True)
        _libc_mount(libc, host, guest, None, _MS_BIND | _MS_REC)
        _libc_mount(libc, None, guest, None,
                    _MS_BIND | _MS_REMOUNT | _MS_RDONLY | _MS_REC)
    # Writable extra mounts, e.g. the tool sandbox root at /work.
    for host, guest_rel in (extra_mounts or {}).items():
        guest = os.path.join(new_root, guest_rel.lstrip("/"))
        os.makedirs(guest, exist_ok=True)
        _libc_mount(libc, host, guest, None, _MS_BIND | _MS_REC)
    put_old = os.path.join(new_root, ".pivot_old")
    os.makedirs(put_old, exist_ok=True)
    if _pivot_root_call(libc, new_root, put_old) != 0:
        raise OSError(ctypes.get_errno(), "pivot_root(%r) failed" % new_root)
    os.chdir("/")
    if chown_to_nobody:
        # Hand the new root to the dropped user while still privileged.
        uid, gid = _nobody_ids()
        os.chown("/", uid, gid)


def _finish_pivot():
    """Complete the pivot: fresh /proc, then detach the old root.

    The /proc mount is bound to the *caller's* pid namespace, so in the
    PID-namespace path this must run in the worker (the first process of
    the new namespace) — it then hides host PIDs entirely. The mount is
    best-effort (/proc is a nicety; the pivot itself is the boundary), but
    a failed detach of the old root raises OSError: leaving /.pivot_old
    attached would leave the host tree reachable.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    os.makedirs("/proc", exist_ok=True)
    try:
        _libc_mount(libc, "proc", "/proc", "proc",
                    _MS_NOSUID | _MS_NOEXEC | _MS_NODEV)
    except OSError:
        pass
    if libc.umount2(b"/.pivot_old", _MNT_DETACH) != 0:
        raise OSError(ctypes.get_errno(), "umount of old root failed")
    # After the detach /.pivot_old is a plain empty directory again;
    # remove it so the new root shows only the staging.
    try:
        os.rmdir("/.pivot_old")
    except OSError:
        pass


def _drop_to_nobody():
    """setgroups/setgid/setuid to 'nobody'. Raises OSError when unpermitted."""
    uid, gid = _nobody_ids()
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


# -- env-gated wiring ---------------------------------------------------------

def _env_flag(name):
    return os.environ.get(name, "").strip() == "1"


def sandbox_config_from_env():
    """Build Sandbox kwargs from GOV_SANDBOX_* environment variables.

    Returns None when GOV_SANDBOX_BACKEND != "1" (backend stays disabled).
    Raises SandboxError when an enabled feature is unavailable on this
    kernel/process: fail-closed, never a silent downgrade to a weaker
    backend.

    Variables:
      GOV_SANDBOX_BACKEND=1   master switch (off by default)
      GOV_SANDBOX_STRICT=1    additionally require the always-on net and
                              PID namespaces (fail-closed); the hardened
                              layers below are required whenever requested
      GOV_SANDBOX_NETNS=1     network namespace (implied by STRICT)
      GOV_SANDBOX_PIDNS=1     PID namespace (implied by STRICT)
      GOV_SANDBOX_PIVOT=1     pivot_root filesystem jail (required)
      GOV_SANDBOX_SECCOMP=1   seccomp-bpf syscall allowlist (required)
      GOV_SANDBOX_PRIVDROP=1  drop to the 'nobody' uid/gid (required)
    """
    if not _env_flag("GOV_SANDBOX_BACKEND"):
        return None
    strict = _env_flag("GOV_SANDBOX_STRICT")
    want = {
        "netns": _env_flag("GOV_SANDBOX_NETNS") or strict,
        "pidns": _env_flag("GOV_SANDBOX_PIDNS") or strict,
        "pivot": _env_flag("GOV_SANDBOX_PIVOT"),
        "seccomp": _env_flag("GOV_SANDBOX_SECCOMP"),
        "privdrop": _env_flag("GOV_SANDBOX_PRIVDROP"),
    }
    avail = {
        "netns": netns_available(),
        "pidns": pidns_available(),
        "pivot": pivot_available(),
        "seccomp": seccomp_available(),
        "privdrop": privdrop_available(),
    }
    missing = [k for k in want if want[k] and not avail[k]]
    if missing:
        raise SandboxError(
            "GOV_SANDBOX_BACKEND=1 requests %s, which is unavailable on "
            "this kernel/process; refusing to run degraded (fail-closed). "
            "Unset GOV_SANDBOX_BACKEND or the feature flag."
            % ",".join(missing))
    return {
        "use_netns": True,
        "use_pidns": True,
        "require_netns": bool(want["netns"] and strict),
        "require_pidns": bool(want["pidns"] and strict),
        # An explicitly requested hardened layer is always required:
        # a sporadic setup failure must refuse, never silently downgrade.
        # STRICT additionally requires the always-on net/PID namespaces.
        "use_pivot_root": bool(want["pivot"]),
        "require_pivot_root": bool(want["pivot"]),
        "drop_privs": bool(want["privdrop"]),
        "require_privdrop": bool(want["privdrop"]),
        "use_seccomp": bool(want["seccomp"]),
        "require_seccomp": bool(want["seccomp"]),
    }


def install_from_env(executor):
    """Env-gated wiring for the sandboxed backend.

    Returns the installed SandboxedToolBackend when GOV_SANDBOX_BACKEND=1,
    else None (the executor is left untouched). Raises SandboxError instead
    of installing a degraded backend. No edits to gov/executor.py needed.
    """
    cfg = sandbox_config_from_env()
    if cfg is None:
        return None
    return install(executor, SandboxedToolBackend(
        executor.sandbox, executor.quarantine, sandbox=Sandbox(**cfg)))


# -- seccomp allowlist audit (the documented update process) ------------------

_AUDIT_WORKLOAD = r"""
import base64, json, os
os.makedirs("sub/dir", exist_ok=True)
open("sub/dir/a.txt", "w").write("hello")
open("sub/dir/b.bin", "wb").write(base64.b64decode(base64.b64encode(b"x" * 1000)))
print(sorted(os.listdir("sub/dir")))
print(json.dumps({"n": len(open("sub/dir/a.txt").read())}))
os.rename("sub/dir/a.txt", "sub/dir/c.txt")
os.unlink("sub/dir/c.txt")
os.unlink("sub/dir/b.bin")
pid = os.fork()
if pid == 0:
    os._exit(3)
_, st = os.waitpid(pid, 0)
print("child:", os.waitstatus_to_exitcode(st))
print("AUDIT-OK")
"""


def audit_seccomp_allowlist():
    """strace-based audit of DEFAULT_SECCOMP_ALLOW.

    1. Builds the BPF filter and sanity-checks its structure (first
       instruction validates the architecture, last instruction is the
       default action).
    2. Runs the standard tool workload under `strace -f` and reports
       syscalls the workload used that are NOT allowlisted (candidates
       for careful addition) and allowlisted syscalls the workload never
       touched (candidates for tightening).

    Returns 0 when the filter builds and the workload is fully covered,
    1 when it is not, 2 when strace is unavailable.
    """
    import re
    import shutil as _shutil
    import struct as _struct
    numbers = _syscall_numbers()
    allowed = sorted(n for n in
                     (numbers.get(name) for name in DEFAULT_SECCOMP_ALLOW)
                     if n is not None)
    try:
        blob = _build_seccomp_filter(allowed, default_action="kill")
    except (SandboxError, ValueError, KeyError) as e:
        print("filter build failed: %s" % e)
        return 1
    nins = len(blob) // 8
    insns = [_struct.unpack("HBBI", blob[i * 8:(i + 1) * 8])
             for i in range(nins)]
    first_ok = insns[0][0] == _BPF_LD_W_ABS and insns[0][3] == 4  # A <- arch
    default_insn = insns[-2]  # last is ALLOW; second-to-last is the default
    default_deny = ("KILL_PROCESS"
                    if default_insn[0] == _BPF_RET_K
                    and default_insn[3] == _SECCOMP_RET_KILL_PROCESS
                    else "UNEXPECTED")
    print("arch=%s allowlisted=%d bpf_insns=%d arch_check=%s default_deny=%s"
          % (_ARCH, len(allowed), nins,
             "ok" if first_ok else "UNEXPECTED", default_deny))
    # Semantic check of the compiled filter (no live seccomp needed):
    # everything allowlisted must reach ALLOW, a sample of dangerous
    # calls must reach KILL, and the wrong arch must reach KILL.
    arch_nr = _AUDIT_ARCH.get(_ARCH)
    denied = ("socket", "connect", "accept", "ptrace", "mount",
              "pivot_root", "bpf", "keyctl", "open_by_handle_at",
              "process_vm_readv", "process_vm_writev", "init_module",
              "reboot", "kexec_load", "io_uring_setup", "userfaultfd",
              "perf_event_open", "unshare", "setns")
    failures = []
    for name in DEFAULT_SECCOMP_ALLOW:
        nr = numbers.get(name)
        if nr is not None and _bpf_decision(blob, arch_nr, nr) \
                != _SECCOMP_RET_ALLOW:
            failures.append("allowlisted %s not ALLOW" % name)
    for name in denied:
        nr = numbers.get(name)
        if nr is not None and _bpf_decision(blob, arch_nr, nr) \
                != _SECCOMP_RET_KILL_PROCESS:
            failures.append("dangerous %s not KILL" % name)
    other_arch = (AUDIT_ARCH_AARCH64 if arch_nr == AUDIT_ARCH_X86_64
                  else AUDIT_ARCH_X86_64)
    if _bpf_decision(blob, other_arch, allowed[0]) \
            != _SECCOMP_RET_KILL_PROCESS:
        failures.append("wrong arch not KILL")
    print("filter semantics: %s"
          % ("ok" if not failures else "FAIL: %s" % failures))
    if failures:
        return 1
    if _shutil.which("strace") is None:
        print("audit needs `strace` on PATH")
        return 2
    workdir = tempfile.mkdtemp(prefix="gov-seccomp-audit-")
    try:
        workload = os.path.join(workdir, "workload.py")
        trace = os.path.join(workdir, "trace.txt")
        with open(workload, "w") as f:
            f.write(_AUDIT_WORKLOAD)
        proc = subprocess.run(
            ["strace", "-f", "-q", "-o", trace, sys.executable, "-I",
             workload],
            capture_output=True, text=True, cwd=workdir, timeout=120)
        if "AUDIT-OK" not in proc.stdout:
            print("workload failed under strace:\n" + proc.stderr[-2000:])
            return 1
        used = set()
        with open(trace, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"(?:\d+\s+)?([a-z_][a-z0-9_]*)\(", line)
                if m:
                    used.add(m.group(1))
        # strace reports some multiplexed names; normalize the common ones.
        used.discard("total")
        allowed_names = set(DEFAULT_SECCOMP_ALLOW)
        used_known = {u for u in used if u in numbers}
        not_allowed = sorted(used_known - allowed_names)
        unused = sorted(allowed_names - used_known)
        unknown = sorted(used - used_known)
        print("used by workload but NOT allowlisted: %s"
              % (not_allowed or "none"))
        print("allowlisted but unused by workload: %s"
              % (unused or "none"))
        if unknown:
            print("used but no number on this arch (not filterable by "
                  "name here): %s" % unknown)
        return 0 if not not_allowed else 1
    finally:
        _shutil.rmtree(workdir, ignore_errors=True)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="gov.sandbox")
    parser.add_argument("--audit-seccomp", action="store_true",
                        help="strace-audit DEFAULT_SECCOMP_ALLOW against "
                             "the standard tool workload")
    args = parser.parse_args(argv)
    if args.audit_seccomp:
        return audit_seccomp_allowlist()
    parser.print_help()
    return 2


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
    pivot_active: bool = False
    privdropped: bool = False
    seccomp_active: bool = False
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
                 require_netns=False, require_pidns=False,
                 use_pivot_root=False, require_pivot_root=False,
                 drop_privs=False, require_privdrop=False,
                 use_seccomp=False, require_seccomp=False,
                 pivot_extra_mounts=None):
        if require_netns and not use_netns:
            raise ValueError("require_netns=True conflicts with use_netns=False")
        if require_pidns and not use_pidns:
            raise ValueError("require_pidns=True conflicts with use_pidns=False")
        if require_pivot_root and not use_pivot_root:
            raise ValueError("require_pivot_root=True conflicts with "
                             "use_pivot_root=False")
        if require_privdrop and not drop_privs:
            raise ValueError("require_privdrop=True conflicts with "
                             "drop_privs=False")
        if require_seccomp and not use_seccomp:
            raise ValueError("require_seccomp=True conflicts with "
                             "use_seccomp=False")
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
        self.use_pivot_root = bool(use_pivot_root)
        self.require_pivot_root = bool(require_pivot_root)
        self.drop_privs = bool(drop_privs)
        self.require_privdrop = bool(require_privdrop)
        self.use_seccomp = bool(use_seccomp)
        self.require_seccomp = bool(require_seccomp)
        self.pivot_extra_mounts = dict(pivot_extra_mounts or {})
        self.network_isolated = self.use_netns and netns_available()
        self.pid_isolated = self.use_pidns and pidns_available()
        # Capability probes fork; only pay for the layers actually requested.
        self.pivot_capable = self.use_pivot_root and pivot_available()
        self.privdrop_capable = self.drop_privs and privdrop_available()
        self.seccomp_capable = self.use_seccomp and seccomp_available()

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
            if self.drop_privs and not self.use_pivot_root and cwd is None:
                # The temp jail is root-owned; hand it to 'nobody' so the
                # dropped child can actually work in it. (With pivot_root
                # the chown happens inside _do_pivot_root; an explicit
                # caller-supplied cwd is never chown'ed for you.)
                uid, gid = _nobody_ids()
                os.chown(jail, uid, gid)
            child_env = self._child_env(jail, extra_env)
            if self.use_pivot_root:
                # Inside the pivot the jail IS "/"; host paths are gone.
                child_env["HOME"] = "/"
                child_env["TMPDIR"] = "/"
            # Status pipe: the pre-exec hook reports the per-call ground
            # truth as exactly five bytes —
            #   [net, pid, pivot, privdrop, seccomp] —
            # written by a single party per call just before exec (or
            # before os._exit(127) on a fail-closed refusal). The parent
            # reads them deadline-bounded; missing bytes (EOF) mean "not
            # established". pass_fds keeps the write end open in the child.
            status_r, status_w = os.pipe()
            preexec = self._make_preexec(argv, child_env, status_w, str(jail))
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
                marker = self._read_status_marker(status_r)
            finally:
                os.close(status_r)
            flags = list(marker) + [0] * (5 - len(marker))
            (net_isolated, pid_isolated, pivot_active, privdropped,
             seccomp_active) = (bool(v) for v in flags[:5])
            missing = []
            if self.require_netns and not net_isolated:
                missing.append("network")
            if self.require_pidns and not pid_isolated:
                missing.append("PID")
            if self.require_pivot_root and not pivot_active:
                missing.append("pivot-root")
            if self.require_privdrop and not privdropped:
                missing.append("privdrop")
            if self.require_seccomp and not seccomp_active:
                missing.append("seccomp")
            if missing:
                # Fail closed: the child was stopped before exec by the
                # pre-exec hook (or died before reporting), so it never
                # ran without the required layer(s). Reap it, close our
                # pipes, and refuse.
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
                    "%s layer(s) required but not established"
                    % "+".join(missing))
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
            # probe-based capability flags: a sporadic setup failure must
            # not be mislabeled as hardened).
            result.network_isolated = net_isolated
            result.pid_isolated = pid_isolated
            result.pivot_active = pivot_active
            result.privdropped = privdropped
            result.seccomp_active = seccomp_active
            want = {"network": self.use_netns, "PID": self.use_pidns,
                    "pivot-root": self.use_pivot_root,
                    "privdrop": self.drop_privs, "seccomp": self.use_seccomp}
            have = {"network": net_isolated, "PID": pid_isolated,
                    "pivot-root": pivot_active, "privdrop": privdropped,
                    "seccomp": seccomp_active}
            fell_back = [k for k in want if want[k] and not have[k]]
            if fell_back:
                fallback_note = ("layer fallback: %s not established for "
                                 "this call; ran with the remaining "
                                 "defense-in-depth limits only"
                                 % "+".join(fell_back))
                result.note = (result.note + "; " + fallback_note
                               if result.note else fallback_note)
            return result

    @staticmethod
    def _read_status_marker(status_r):
        """Read the 5-byte [net, pid, pivot, privdrop, seccomp] marker.

        Deadline-bounded: a child that died before reporting yields EOF and
        the missing bytes are treated as "not established" (fail closed).
        """
        marker = b""
        deadline = time.monotonic() + 5.0
        sel = selectors.DefaultSelector()
        sel.register(status_r, selectors.EVENT_READ)
        try:
            while len(marker) < 5:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not sel.select(timeout=remaining):
                    break
                try:
                    chunk = os.read(status_r, 5 - len(marker))
                except OSError:
                    break
                if not chunk:
                    break  # child died before reporting: not established
                marker += chunk
        finally:
            sel.close()
        return marker

    def run_python(self, code, *, argv_extra=(), **kwargs):
        """Run a Python snippet contained. ``-I`` = isolated mode: ignores
        PYTHONPATH and user site-packages, so the child cannot import
        attacker-planted modules via the environment.

        Under pivot_root the venv path does not exist inside the new root,
        so argv[0] is the *real* interpreter path (covered by the read-only
        /usr staging)."""
        exe = sys.executable
        if self.use_pivot_root:
            exe = os.path.realpath(exe)
        return self.run([exe, "-I", "-c", code, *argv_extra],
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

    def _make_preexec(self, argv, child_env, status_w, jail_path):
        use_netns = self.use_netns
        use_pidns = self.use_pidns
        require_netns = self.require_netns
        require_pidns = self.require_pidns
        use_pivot = self.use_pivot_root
        require_pivot = self.require_pivot_root
        drop_privs = self.drop_privs
        require_privdrop = self.require_privdrop
        use_seccomp = self.use_seccomp
        require_seccomp = self.require_seccomp
        pivot_mounts = dict(self.pivot_extra_mounts)
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

        def _report(net_ok, pid_ok, pivot_ok, priv_ok, seccomp_ok):
            # Exactly five bytes, one writer per call, just before exec
            # (or before os._exit(127) on a fail-closed refusal). Best
            # effort — if the write itself fails the parent sees EOF and
            # treats the call as unhardened.
            try:
                os.write(status_w, bytes((1 if net_ok else 0,
                                          1 if pid_ok else 0,
                                          1 if pivot_ok else 0,
                                          1 if priv_ok else 0,
                                          1 if seccomp_ok else 0)))
            except OSError:
                pass

        def _harden_worker():
            """UID/GID drop + seccomp in the final worker, just before exec.

            Returns (priv_ok, seccomp_ok). With the matching require_*
            flag, a setup failure stops the child with os._exit(127) BEFORE
            exec: hostile code never runs without the required layer.
            """
            priv_ok = False
            if drop_privs:
                try:
                    _drop_to_nobody()
                except OSError:
                    if require_privdrop:
                        os._exit(127)
                else:
                    priv_ok = True
            seccomp_ok = False
            if use_seccomp:
                try:
                    _install_default_seccomp_filter()
                except OSError:
                    if require_seccomp:
                        os._exit(127)
                else:
                    seccomp_ok = True
            return priv_ok, seccomp_ok

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
                _report(False, False, False, False, False)
                os._exit(127)
            # PID namespace unshared (provisionally) BEFORE the pivot setup:
            # a fresh /proc mounted later then binds to the NEW pid
            # namespace and hides host PIDs entirely. unshare() is not
            # retroactive, so this process stays in the outer namespace;
            # only its children enter the new one.
            pidns = False
            if use_pidns and hasattr(os, "unshare"):
                try:
                    os.unshare(os.CLONE_NEWPID)
                except OSError:
                    pass  # reported honestly below; strict mode refuses
                else:
                    pidns = True
            pivot_ok = False
            if use_pivot:
                try:
                    _do_pivot_root(jail_path, pivot_mounts,
                                   chown_to_nobody=drop_privs)
                except OSError:
                    pass  # reported honestly below; strict mode refuses
                else:
                    pivot_ok = True
            if require_pivot and not pivot_ok:
                # Fail closed BEFORE exec: without the pivot the child's
                # absolute-path writes could reach the host filesystem.
                _report(net_ok, False, False, False, False)
                os._exit(127)
            if pidns:
                # The worker becomes PID 1 in the descendant namespace, so
                # /proc/<outer-pid>/environ is unreadable (cross-namespace
                # ptrace check fails). Defeats the "read the parent's
                # environment" exfiltration vector and, critically, keeps
                # the worker from learning the parent's real PID
                # (getppid() == 1), so it cannot signal the parent. The
                # intermediate waitpids the worker and forwards its exit
                # status, so Popen still observes the worker's code.
                try:
                    pid = os.fork()
                except OSError:
                    pidns = False  # fall through to the fallback path
                else:
                    if pid == 0:
                        # Worker: the ONLY writer of this call's status
                        # bytes. Finish the pivot (fresh /proc bound to the
                        # new pid namespace, then detach the old root),
                        # harden, report, then exec.
                        pivot_done = pivot_ok
                        if pivot_ok:
                            try:
                                _finish_pivot()
                            except OSError:
                                if require_pivot:
                                    os._exit(127)
                                pivot_done = False
                        priv_ok, seccomp_ok = _harden_worker()
                        _report(net_ok, True, pivot_done, priv_ok,
                                seccomp_ok)
                        try:
                            os.execvpe(argv[0], argv, child_env)
                        except OSError:
                            os._exit(127)
                    # Intermediate: never hardens itself (it must stay
                    # privileged enough to waitpid, and it shares the mount
                    # namespace, so the worker's detach covers it too); it
                    # just closes every inherited fd except stdio (notably
                    # the errpipe Popen uses to detect child-side failures:
                    # as long as we hold it open, the parent blocks in
                    # Popen.__init__ waiting for EOF). The worker was
                    # already forked, so it keeps its stdio pipes.
                    try:
                        os.closerange(3, os.sysconf("SC_OPEN_MAX"))
                    except (ValueError, OSError):
                        pass
                    _, status = os.waitpid(pid, 0)
                    os._exit(os.waitstatus_to_exitcode(status))
            if require_pidns and not pidns:
                # Fail closed BEFORE exec: without the PID namespace a
                # same-UID worker can os.kill() the parent by explicit PID
                # (demonstrated). Never run hostile code this way.
                _report(net_ok, False, pivot_ok, False, False)
                os._exit(127)
            # Fallback path (no PID namespace): finish the pivot here,
            # harden, report, then return — Popen execs argv directly.
            # Reported honestly as pid_isolated=False; callers that need
            # the hostile-code boundary must pass require_pidns=True.
            pivot_done = pivot_ok
            if pivot_ok:
                try:
                    _finish_pivot()
                except OSError:
                    if require_pivot:
                        _report(net_ok, False, False, False, False)
                        os._exit(127)
                    pivot_done = False
            priv_ok, seccomp_ok = _harden_worker()
            _report(net_ok, False, pivot_done, priv_ok, seccomp_ok)
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
        # Pivot integration: the sandbox root is bind-mounted read-write at
        # /work inside the pivot, and every child argv path is translated
        # from the host-absolute form to its /work/... guest form. Path
        # authority still happens parent-side first (_checked_target).
        self._pivot = bool(getattr(self.sandbox, "use_pivot_root", False))
        if self._pivot:
            mounts = getattr(self.sandbox, "pivot_extra_mounts", None)
            if mounts is not None:
                mounts[str(self._sandbox_resolved)] = "work"
            if getattr(self.sandbox, "drop_privs", False):
                # The pivoted child runs as 'nobody' but must write tool
                # outputs into the sandbox root (bind-mounted at /work):
                # hand the per-run sandbox root to nobody. The parent runs
                # privileged and retains full access; nothing outside the
                # run directory is touched.
                uid, gid = _nobody_ids()
                os.chown(self._sandbox_resolved, uid, gid)

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

    def _guest_target(self, host_path):
        """Translate a confined host-absolute path to the child's view.

        Without pivot_root the child shares the host mount table, so the
        host path is used as-is. With pivot_root the sandbox root is
        visible at /work and host-absolute paths do not exist.
        """
        rp = Path(host_path)
        if not self._pivot:
            return str(rp)
        rel = rp.relative_to(self._sandbox_resolved)
        if str(rel) == ".":
            return "/work"
        return "/work/" + rel.as_posix()

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
                                        argv_extra=[self._guest_target(p)])
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
                                    argv_extra=[self._guest_target(target)],
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
                                        argv_extra=[self._guest_target(target)])
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


if __name__ == "__main__":
    raise SystemExit(main())
