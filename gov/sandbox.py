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
  silent escape. ``cage_mode="filtered-egress"`` swaps in the
  ``FILTERED_EGRESS_CAGE_ALLOW`` profile instead: the client-socket
  family is allowed with scalar ``socket()`` argument filters
  (AF_UNIX/AF_INET only, SOCK_STREAM only — raw/packet/netlink die with
  EPERM), everything else stays default-deny; an unknown cage_mode
  refuses loudly at construction (fail-closed). With an
  ``egress_launcher`` attached, ``filtered-egress`` instead spawns
  through the wall (``FilteredEgressLauncher``): the wall helper is the
  network seccomp (the cage filter is not double-installed), the wall
  provides the netns, and the launch is audited as
  ``egress_wall_launch`` — without a launcher the mode is the internal
  profile only, and the result note says so loudly.

Each layer has a ``require_*`` fail-closed twin (``require_pivot_root``,
``require_privdrop``, ``require_seccomp``): the child is stopped *before*
exec when the layer cannot be established -- the chain entry raises
``PreexecChainAbort`` (F150 raise-don't-exit contract; converted to exit
98 under the filtered-egress launcher, translated back to the
historical ``_exit(127)`` in standalone mode), and ``run()`` raises
``SandboxError``. The five per-call ground-truth flags
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
import datetime
import fcntl
import json
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

from gov.egress_launcher import PreexecChainAbort

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
# matching require_* fail-closed flag: when set, the child is stopped BEFORE
# exec if the layer cannot be established (the chain entry raises
# PreexecChainAbort per the F150 contract; a forked worker still uses the
# historical os._exit(127)), and run()
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
_SECCOMP_RET_LOG = 0x7FFC0000           # audit-log without enforcing (4.14+)
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 1

# Filtered-egress cage profile (wave-59; implements the wave-58 draft
# workstreams/architect/F81_SECCOMP_PROFILE_DRAFT.md §§2-4).
_EPERM = 1
# ioctl(2) request immediates allowlisted in the cage profile (wave-60,
# F127: the wave-59 blanket ioctl removal SIGSYS-killed every Python
# workload at interpreter startup — CPython's io stack probes stdio fds
# with TCGETS ~18x before user code runs).
_TCGETS = 0x5401   # read terminal attributes (pure read, no state change)
_FIOCLEX = 0x5451  # set close-on-exec (strictly reduces fd survivability)
# socket(2) argument-filter immediates.
_AF_UNIX = 1
_AF_INET = 2
_SOCK_STREAM = 1
_SOCK_NONBLOCK = 0x800
_SOCK_CLOEXEC = 0x80000
_IPPROTO_TCP = 6
# seccomp_data offsets of the scalar syscall args on 64-bit (8 bytes each).
_SECCOMP_DATA_ARG0 = 16
#
# The cage child is a pure *client* of the egress proxy: it needs to open
# TCP/unix client sockets toward the proxy, and nothing else network- or
# privilege-shaped. Deltas vs DEFAULT_SECCOMP_ALLOW:
#   REMOVED: "bind", "listen", "accept", "accept4", "unshare", "setns"
#     are listed as removals for the same reason even though DEFAULT never
#     contained them — a future DEFAULT addition must not silently widen
#     the cage. ("ioctl" was a removal in wave-59 for the same net-device
#     route-manipulation reason, but the wave-60 LOG-tier shake-down proved
#     CPython itself needs TCGETS at startup — F127 — so ioctl is back as
#     an arg-filtered allow, not a blanket allow; see _CAGE_IOCTL_ARG_RULES.)
#   ADDED (client-only, arg-filtered by _CAGE_SOCKET_ARG_RULES below):
#     socket, connect, sendto, recvfrom, sendmsg, recvmsg, sendmmsg,
#     recvmmsg, getsockopt, setsockopt, getsockname, getpeername,
#     shutdown, socketpair.
#   MUST-NOT-ADD (covered by the default KILL): mount, umount2,
#     pivot_root, chroot, ptrace, process_vm_readv/writev, bpf,
#     perf_event_open, keyctl, add_key, request_key, seccomp, prctl,
#     socketcall, io_uring_setup, userfaultfd, kexec_load, reboot,
#     init_module, open_by_handle_at.
# Kept from DEFAULT: clone/clone3/vfork (threads are legitimate workload
# behavior; namespace-flags inside clone are neutered — no setns/unshare
# to rejoin anything, and a deeper-nested netns is *more* isolated).
#
# Audit story (three tiers; see the draft §4):
#   1. errno tier — socket() arg violations return EPERM to the child
#      (loud-local: the child sees a normal syscall failure; the launcher
#      captures stderr/exit status). Covers network-misuse shapes the
#      netns already dead-ends.
#   2. kill tier — everything not allowlisted (unshare, setns, ptrace,
#      bpf, keyctl, mount, pivot_root, prctl, seccomp, io_uring, ...) hits
#      the default SECCOMP_RET_KILL_PROCESS: the child dies with SIGSYS,
#      which the launcher records in the run note (see _supervise). Never
#      silent: a SIGSYS death is a finding-grade audit event.
#   3. staging tier — default_action="log" (SECCOMP_RET_LOG, kernel 4.14+)
#      audit-logs would-be denials without enforcing; selected via
#      GOV_SANDBOX_SECCOMP_LOG=1 for pre-production allowlist shakedown.
#      LOG mode is staging-only: the wave-61 LOG-tier production guard
#      (_resolve_seccomp_tier) refuses a LOG request in
#      deployment_mode="production", and the run note stamps the tier
#      from the once-resolved value.
FILTERED_EGRESS_CAGE_ALLOW = frozenset(
    (DEFAULT_SECCOMP_ALLOW
     - {"bind", "listen", "accept", "accept4",
        "unshare", "setns"})
    | {"socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
       "sendmmsg", "recvmmsg", "getsockopt", "setsockopt", "getsockname",
       "getpeername", "shutdown", "socketpair", "ioctl"}
)

# socket(domain, type, protocol) scalar arg rules for the cage profile.
# Classic BPF can only inspect scalar registers — never the userspace
# sockaddr pointer — so there is deliberately NO connect() destination
# rule here: destination confinement belongs to the netns topology
# (no route -> ENETUNREACH), the proxy's policy, and the upstream
# firewall, never to seccomp (draft §3 honest correction).
#   domain MUST be AF_UNIX/AF_INET (kills AF_PACKET smuggling and
#     AF_NETLINK route manipulation at the syscall layer);
#   type MUST be SOCK_STREAM modulo the SOCK_NONBLOCK|SOCK_CLOEXEC flag
#     bits (kills SOCK_RAW and SOCK_DGRAM);
#   protocol MUST be 0 (default) or IPPROTO_TCP (kills SCTP/DCCP-style
#     protocol smuggling through SOCK_STREAM — wave-59 break-first catch
#     from the CVE-2026-64564 intake: SCTP sockets are a kernel-attack
#     surface the filter can deny for free; the proxy is TCP-only so
#     nothing legitimate needs another protocol).
# Violations return SECCOMP_RET_ERRNO|EPERM (audit tier 1). The low-32-bit
# read is sound: any high-bit smuggling makes the kernel see an invalid
# (domain, type) pair and fail the call itself — the filter can only err
# toward denial, never toward a wider allow.
_CAGE_SOCKET_ARG_RULES = (
    # (arg_index, allowed_values, deny_action)
    (0, frozenset({_AF_UNIX, _AF_INET}), _SECCOMP_RET_ERRNO | _EPERM),
    (1, frozenset({
        _SOCK_STREAM,
        _SOCK_STREAM | _SOCK_NONBLOCK,
        _SOCK_STREAM | _SOCK_CLOEXEC,
        _SOCK_STREAM | _SOCK_NONBLOCK | _SOCK_CLOEXEC,
    }), _SECCOMP_RET_ERRNO | _EPERM),
    (2, frozenset({0, _IPPROTO_TCP}), _SECCOMP_RET_ERRNO | _EPERM),
)

# ioctl(request, ...) scalar arg rules for the cage profile.
# Classic BPF CAN inspect the request — it is a scalar at arg offset 24 —
# so unlike connect()'s sockaddr there is no inability here, only a
# deliberate whitelist. Allowed: TCGETS (CPython startup/stdio isatty
# probing; pure read of termios into a userspace buffer — no device state
# change, no information the fd doesn't already expose) and FIOCLEX (sets
# FD_CLOEXEC — strictly reduces what survives exec). Everything else
# returns SECCOMP_RET_ERRNO|EPERM (errno tier, loud-local): SIOCSIFADDR /
# SIOCSIFFLAGS / SIOCADDRT (the net-device route-manipulation side door
# the wave-59 removal was aimed at), TIOCSTI (terminal input injection),
# TCSETS*/TCSETSW (terminal reprogramming), FIONREAD (unneeded; stays
# denied — loud EPERM if a workload ever proves a need). The low-32-bit
# read is sound exactly as for socket(): a high-bit-smeared request reads
# as the whitelisted low 32 bits at the filter but the kernel validates
# the full 64-bit request and fails unknown ones with ENOTTY — the filter
# can only err toward denial, never toward a wider allow.
_CAGE_IOCTL_ARG_RULES = (
    # (arg_index, allowed_values, deny_action)
    (1, frozenset({_TCGETS, _FIOCLEX}), _SECCOMP_RET_ERRNO | _EPERM),
)
# Explicit cage-mode vocabulary. Mode selection is explicit and
# fail-closed: an unknown mode refuses loudly (ValueError at
# construction, SandboxError from the env wiring) — never "no cage".
_CAGE_MODES = ("strict", "filtered-egress")

def _build_seccomp_filter(allowed_numbers, *, default_action="kill"):
    """Assemble a classic-BPF seccomp filter: arch check, then a linear
    allowlist scan over the sorted syscall numbers. Returns the raw bytes
    (a sequence of 8-byte sock_filter structs)."""
    nrs = sorted(set(allowed_numbers))
    if default_action == "kill":
        default_ret = _SECCOMP_RET_KILL_PROCESS
    elif default_action == "errno":
        default_ret = _SECCOMP_RET_ERRNO | 38  # ENOSYS
    elif default_action == "log":
        default_ret = _SECCOMP_RET_LOG
    else:
        raise ValueError("default_action must be 'kill', 'errno' or 'log'")
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


def _bpf_assemble(items):
    """Assemble labeled classic-BPF items into raw filter bytes.

    items: str labels or (code, jt, jf, k) tuples; jt/jf may be ints
    (relative skip counts, as in _build_seccomp_filter) or label names,
    resolved here to relative skips. Forward references are fine; jumps
    must land within the 8-bit skip range. Returns bytes.
    """
    labels = {}
    insns = []
    for it in items:
        if isinstance(it, str):
            if it in labels:
                raise SandboxError("duplicate bpf label %r" % (it,))
            labels[it] = len(insns)
        else:
            code, jt, jf, k = it
            insns.append([code, jt, jf, k])
    out = []
    for i, (code, jt, jf, k) in enumerate(insns):
        if isinstance(jt, str):
            if jt not in labels:
                raise SandboxError("unknown bpf label %r" % (jt,))
            jt = labels[jt] - i - 1
        if isinstance(jf, str):
            if jf not in labels:
                raise SandboxError("unknown bpf label %r" % (jf,))
            jf = labels[jf] - i - 1
        if not (0 <= jt <= 255 and 0 <= jf <= 255):
            raise SandboxError("bpf jump out of range at insn %d" % i)
        out.append(struct.pack("HBBI", code, jt, jf, k))
    return b"".join(out)


def _build_seccomp_filter_args(allowed_numbers, arg_rules, *,
                               default_action="kill"):
    """Assemble a classic-BPF seccomp filter with per-syscall arg checks.

    allowed_numbers: syscall numbers that reach ALLOW on nr match alone.
    arg_rules: {nr: [(arg_index, allowed_values, deny_ret), ...]} — for a
      matched nr, each (arg_index, allowed_values) pair is checked in
      order against the syscall's scalar args (seccomp_data offsets
      16/24/32/40/48/56, low 32 bits — the only arg visibility classic
      BPF has). The first failing check returns deny_ret; all checks
      passing falls through to ALLOW. Numbers not listed hit the default
      action. Same opcode vocabulary as _build_seccomp_filter (LD_W_ABS,
      JEQ_K, RET_K), so the audit evaluator needs no new opcodes.
    """
    if default_action == "kill":
        default_ret = _SECCOMP_RET_KILL_PROCESS
    elif default_action == "errno":
        default_ret = _SECCOMP_RET_ERRNO | 38  # ENOSYS
    elif default_action == "log":
        default_ret = _SECCOMP_RET_LOG
    else:
        raise ValueError("default_action must be 'kill', 'errno' or 'log'")
    nrs = sorted(set(allowed_numbers))
    items = []
    items.append((_BPF_LD_W_ABS, 0, 0, 4))                    # A <- arch
    items.append((_BPF_JMP_JEQ_K, "ok_arch", "bad_arch",
                  _AUDIT_ARCH[_ARCH]))
    items.append("bad_arch")
    items.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    items.append("ok_arch")
    items.append((_BPF_LD_W_ABS, 0, 0, 0))                    # A <- nr
    for nr in nrs:
        target = "argcheck_%d_0" % nr if nr in arg_rules else "allow"
        items.append((_BPF_JMP_JEQ_K, target, 0, nr))
    items.append((_BPF_RET_K, 0, 0, default_ret))             # default
    items.append("allow")
    items.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    for nr in sorted(arg_rules):
        rules = list(arg_rules[nr])
        for ri, (arg_index, allowed_values, deny_ret) in enumerate(rules):
            if not (0 <= arg_index <= 5):
                raise ValueError("arg_index out of range: %r" % arg_index)
            if not allowed_values:
                raise ValueError("empty allowed_values for arg %d of nr %d"
                                 % (arg_index, nr))
            last = (ri == len(rules) - 1)
            ok_target = ("argdone_%d" % nr if last
                         else "argcheck_%d_%d" % (nr, ri + 1))
            items.append("argcheck_%d_%d" % (nr, ri))
            items.append((_BPF_LD_W_ABS, 0, 0,
                          _SECCOMP_DATA_ARG0 + 8 * arg_index))
            for v in sorted(allowed_values):
                items.append((_BPF_JMP_JEQ_K, ok_target, 0, v))
            items.append((_BPF_RET_K, 0, 0, deny_ret))
        # All checks passed: local ALLOW (a second RET_ALLOW keeps every
        # jump forward — no backward jumps, no new opcodes).
        items.append("argdone_%d" % nr)
        items.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    return _bpf_assemble(items)


def _build_cage_seccomp_filter(numbers, *, default_action="kill"):
    """Compile the filtered-egress cage profile to real BPF bytes.

    numbers: {name: number} for this arch. Raises KeyError when a needed
    name is absent (the install wrapper converts this to a fail-closed
    OSError listing the missing names).
    """
    allowed = {numbers[name] for name in FILTERED_EGRESS_CAGE_ALLOW}
    socket_nr = numbers["socket"]
    ioctl_nr = numbers["ioctl"]
    return _build_seccomp_filter_args(
        allowed, {socket_nr: _CAGE_SOCKET_ARG_RULES,
                  ioctl_nr: _CAGE_IOCTL_ARG_RULES},
        default_action=default_action)


def _bpf_decision(filter_bytes, arch, nr, args=()):
    """Pure-Python evaluation of a filter built by _build_seccomp_filter
    or _build_seccomp_filter_args.

    Only the three opcodes the builders emit are supported. Used by the
    audit and the test suite on kernels where live seccomp installation
    is unavailable. Returns the SECCOMP_RET_* action the kernel would
    take for the given (arch, syscall-number) pair.

    args: up to 6 scalar syscall arguments. Only the low 32 bits of each
    are visible to classic BPF (LD_W_ABS reads), which this mirrors —
    the same truncation the kernel's filter would see.
    """
    insns = [struct.unpack("HBBI", filter_bytes[i:i + 8])
             for i in range(0, len(filter_bytes), 8)]
    data = {4: arch, 0: nr}  # seccomp_data offsets the filter reads
    for i, a in enumerate(args[:6]):
        data[_SECCOMP_DATA_ARG0 + 8 * i] = a & 0xFFFFFFFF
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


def _install_cage_seccomp_filter(*, default_action="kill"):
    """Install the filtered-egress cage filter (default action KILL).

    Raises OSError when syscall numbers cannot be resolved or the filter
    cannot be installed: the caller decides fail-closed vs. honest
    fallback. default_action="log" selects the SECCOMP_RET_LOG staging
    tier (audit-log without enforcing; kernel 4.14+).
    """
    numbers = _syscall_numbers()
    missing = sorted(n for n in FILTERED_EGRESS_CAGE_ALLOW if n not in numbers)
    if missing:
        raise OSError("no syscall numbers for %s on %s"
                      % (",".join(missing), _ARCH))
    filt = _build_cage_seccomp_filter(numbers, default_action=default_action)
    _install_seccomp_filter(filt)


def _install_seccomp_filter_for_mode(cage_mode, *, default_action="kill"):
    """Install the seccomp filter for an explicit cage mode.

    "strict" installs DEFAULT_SECCOMP_ALLOW (unchanged legacy behavior);
    "filtered-egress" installs the cage profile. Any other mode raises
    SandboxError: mode selection is explicit and fail-closed, never "no
    cage".
    """
    if cage_mode == "strict":
        _install_default_seccomp_filter()
    elif cage_mode == "filtered-egress":
        _install_cage_seccomp_filter(default_action=default_action)
    else:
        raise SandboxError("unknown cage_mode %r: refusing to install a "
                           "seccomp filter without an explicit mode "
                           "(fail-closed)" % (cage_mode,))


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


# Wave-61 LOG-tier production guard. "production" is the least-privilege
# default: the operator must explicitly declare staging; ambiguity
# defaults to the KILL tier. GOV_SANDBOX_SECCOMP_LOG is a *request*,
# never authoritative — it is honored only in staging mode.
_DEPLOYMENT_MODES = ("production", "staging")


def _resolve_seccomp_tier(deployment_mode, log_requested):
    """Resolve the seccomp default-action tier ("kill" or "log").

    This is the LOG-tier production guard (wave-61 design in
    workstreams/evals/SECCOMP_LOG_SHAKEDOWN.md §6): the single
    chokepoint that stops GOV_SANDBOX_SECCOMP_LOG=1 from silently
    dissolving KILL default-deny into log-and-execute in production.

    Fail-closed directions:
      * production + LOG requested -> raise SandboxError (refuse to
        launch loudly; a deployment-mode/tier contradiction is
        misconfiguration and launching in either mode would assume
        intent we cannot know).
      * unknown deployment_mode -> raise ValueError (fail-fast; an
        unknown mode never silently means "no guard").
    Returns "log" only for staging + explicit LOG request; every other
    reachable state returns "kill".
    """
    if deployment_mode not in _DEPLOYMENT_MODES:
        raise ValueError(
            "unknown deployment_mode %r: must be one of %s (fail-closed; "
            "an unknown mode never silently disables the LOG-tier guard)"
            % (deployment_mode, ", ".join(_DEPLOYMENT_MODES)))
    if log_requested and deployment_mode == "production":
        raise SandboxError(
            "refusing to launch: GOV_SANDBOX_SECCOMP_LOG=1 requests the "
            "LOG (log-and-execute) staging tier in "
            "deployment_mode='production'. Resolve the contradiction "
            "explicitly — declare deployment_mode='staging' or unset the "
            "variable. Fail-closed: no cage launched.")
    return "log" if log_requested else "kill"


# Wave-62 refusal loudness. A SandboxError raised to the caller is loud
# only if the caller listens: a deployment that swallows the exception
# and proceeds anyway would otherwise leave zero trace (break-first
# evidence in workstreams/evals/REFUSAL_LOUDNESS.md §2: 0 stderr bytes
# emitted, no receipt, workload ran uncaged). _refuse_loud() emits the
# refusal on two channels that survive typical swallowing BEFORE raising:
#   (1) a one-line record on stderr — deployments capture stderr, and a
#       caller that catches the exception rarely also redirects it;
#   (2) an opt-in structured JSONL receipt appended to
#       <refusal_receipt_dir>/refusals.jsonl — a known location the
#       deployment monitors, surviving even stderr suppression.
# Both channels are best-effort and fail-safe: any emission failure is
# swallowed and the SandboxError is still raised — a broken sink never
# masks the refusal, and a broken sink never weakens enforcement.
# The receipt is a plain JSONL line, not audit machinery (wave-61
# deliberately declined threading a hash-chained audit sink into
# Sandbox; that decision stands).
# Deliberately NOT built: fail-deadly process poisoning (os._exit,
# poisoning later runs) — hostile to legitimate recovery: catching the
# refusal and remediating explicitly (e.g. re-running with an explicit
# staging declaration) is a supported flow.
# Residual boundary (documented, not a finding): a caller that
# deliberately suppresses stderr AND disables the receipt sink AND
# swallows the exception is outside the trust model — the same class as
# wave-61's malicious-environment-writer boundary (anyone who controls
# the launcher's environment can already unset GOV_SANDBOX_BACKEND).
# Nothing in-process can stop a caller from abandoning Sandbox entirely
# and exec'ing the workload raw; the contract is loud refusal *to the
# caller*, made observable to the *deployment* through these channels.
_REFUSAL_RECEIPT_ENV = "GOV_SANDBOX_REFUSAL_DIR"
_REFUSAL_RECEIPT_NAME = "refusals.jsonl"
_REFUSAL_STDERR_PREFIX = "GOV-SANDBOX REFUSAL"


def _resolve_refusal_receipt_dir(explicit=None):
    """Resolve the refusal-receipt sink: explicit kwarg wins, else the
    GOV_SANDBOX_REFUSAL_DIR environment variable. Empty/blank -> None
    (receipt channel disabled; the stderr channel is unconditional).
    This is observability configuration, not a security decision — the
    wave-61 'env is not authoritative' principle governs the tier
    decision, not where a log line lands. A hostile env value can only
    misplace a receipt, never weaken enforcement: the refusal raises
    regardless."""
    if explicit is not None:
        return explicit
    raw = os.environ.get(_REFUSAL_RECEIPT_ENV, "").strip()
    return raw or None


def _refuse_loud(message, *, kind, receipt_dir, extra=None):
    """Emit a fail-closed refusal loudly, then raise SandboxError.

    stderr line + optional JSONL receipt are written BEFORE raising so
    a caller that swallows the exception still leaves a trace. Any
    emission failure is ignored — the refusal itself never fails."""
    try:
        sys.stderr.write("%s [%s] pid=%d: %s\n"
                         % (_REFUSAL_STDERR_PREFIX, kind, os.getpid(),
                            message))
        sys.stderr.flush()
    except Exception:
        pass
    if receipt_dir:
        try:
            os.makedirs(receipt_dir, exist_ok=True)
            record = {
                "ts": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(),
                "kind": kind,
                "pid": os.getpid(),
                "message": message,
            }
            if extra:
                record.update(extra)
            with open(os.path.join(receipt_dir, _REFUSAL_RECEIPT_NAME),
                       "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except Exception:
            pass
    raise SandboxError(message)


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
      GOV_SANDBOX_CAGE_MODE=filtered-egress
                              install the filtered-egress cage seccomp
                              profile instead of DEFAULT_SECCOMP_ALLOW
                              ("strict" is the default; any other value
                              refuses loudly — fail-closed, never "no cage")
      GOV_SANDBOX_SECCOMP_LOG=1
                              staging-tier REQUEST (not authority): honored
                              only when deployment_mode="staging"; in
                              production the guard refuses to launch loudly
                              (wave-61; the run note still stamps the tier
                              when it is legitimately used)
      GOV_SANDBOX_DEPLOYMENT_MODE=production|staging
                              deployment mode for the LOG-tier guard
                              (wave-61). Default production (least
                              privilege: ambiguity defaults to the KILL
                              tier). Explicit constructor kwarg
                              deployment_mode= wins over this variable.
      GOV_SANDBOX_REFUSAL_DIR=<dir>
                              opt-in sink for structured refusal receipts
                              (wave-62): fail-closed refusals from run()
                              append one JSONL line per refusal to
                              <dir>/refusals.jsonl, in addition to the
                              unconditional stderr refusal record. The
                              constructor kwarg refusal_receipt_dir= wins
                              over this variable. Observability config
                              only — never a security decision.
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
    # Explicit cage-mode selection (wave-59): an unknown mode is a
    # misconfiguration, and a misconfigured cage must refuse loudly —
    # never silently run without the intended profile.
    raw_mode = os.environ.get("GOV_SANDBOX_CAGE_MODE", "").strip()
    cage_mode = raw_mode or "strict"
    if cage_mode not in _CAGE_MODES:
        raise SandboxError(
            "GOV_SANDBOX_CAGE_MODE=%r unknown (want one of %s); refusing "
            "to run without an explicit cage mode (fail-closed). Unset "
            "GOV_SANDBOX_BACKEND or fix the mode."
            % (raw_mode, ", ".join(_CAGE_MODES)))
    # Wave-61 LOG-tier production guard: deployment mode is an explicit
    # operator signal (env convenience here; the Sandbox constructor
    # kwarg deployment_mode= is authoritative and wins). Garbage/empty
    # falls back to the least-privilege default "production"; the
    # constructor validates.
    raw_deploy = os.environ.get("GOV_SANDBOX_DEPLOYMENT_MODE", "").strip()
    deployment_mode = raw_deploy or "production"
    if cage_mode == "filtered-egress" and not want["seccomp"]:
        raise SandboxError(
            "GOV_SANDBOX_CAGE_MODE=filtered-egress requires "
            "GOV_SANDBOX_SECCOMP=1; refusing (fail-closed: the cage "
            "profile is meaningless without the filter)")
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
        "cage_mode": cage_mode,
        "deployment_mode": deployment_mode,
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


def audit_cage_seccomp_filter():
    """Byte-level audit of the FILTERED_EGRESS_CAGE_ALLOW profile.

    1. Builds the BPF filter and sanity-checks its structure (arch check
       first, default action second-to-last, ALLOW last).
    2. Evaluates the *compiled bytes* with _bpf_decision (the same
       evaluator the test suite uses): every allowlisted name must reach
       ALLOW (socket only with conforming args), every socket-misuse
       shape must reach SECCOMP_RET_ERRNO|EPERM, every escape/privilege
       syscall must reach KILL_PROCESS, and the wrong arch must reach
       KILL_PROCESS.

    Returns 0 when the filter builds and every semantic check holds,
    1 otherwise. Needs no live seccomp and no strace: it audits the
    bytes, not the kernel.
    """
    numbers = _syscall_numbers()
    arch_nr = _AUDIT_ARCH.get(_ARCH)
    if not numbers or arch_nr is None:
        print("no syscall numbers / audit arch on %s" % _ARCH)
        return 1
    try:
        blob = _build_cage_seccomp_filter(numbers, default_action="kill")
    except (KeyError, SandboxError, ValueError) as e:
        print("cage filter build failed: %s" % e)
        return 1
    nins = len(blob) // 8
    insns = [struct.unpack("HBBI", blob[i * 8:(i + 1) * 8])
             for i in range(nins)]
    first_ok = insns[0][0] == _BPF_LD_W_ABS and insns[0][3] == 4
    # Layout: 4 header insns (arch check), then the nr scan, then the
    # default action, then ALLOW, then the per-syscall arg-check blocks.
    allowed_nrs = {numbers[n] for n in FILTERED_EGRESS_CAGE_ALLOW
                   if n in numbers}
    default_insn = insns[4 + len(allowed_nrs)]
    default_deny = ("KILL_PROCESS"
                    if default_insn[0] == _BPF_RET_K
                    and default_insn[3] == _SECCOMP_RET_KILL_PROCESS
                    else "UNEXPECTED")
    print("arch=%s cage_allowlisted=%d bpf_insns=%d arch_check=%s "
          "default_deny=%s"
          % (_ARCH, len(allowed_nrs), nins,
             "ok" if first_ok else "UNEXPECTED", default_deny))
    allow = _SECCOMP_RET_ALLOW
    kill = _SECCOMP_RET_KILL_PROCESS
    eperm = _SECCOMP_RET_ERRNO | _EPERM
    socket_nr = numbers["socket"]
    failures = []

    def decide(nr, args=()):
        return _bpf_decision(blob, arch_nr, nr, args)

    for name in FILTERED_EGRESS_CAGE_ALLOW:
        if name in ("socket", "ioctl") or name not in numbers:
            continue
        if decide(numbers[name]) != allow:
            failures.append("allowlisted %s not ALLOW" % name)
    # socket(): conforming shapes reach ALLOW ...
    if decide(socket_nr, (1, 1, 0)) != allow:
        failures.append("socket(AF_UNIX, SOCK_STREAM) not ALLOW")
    if decide(socket_nr, (2, 1 | 0x800 | 0x80000, 6)) != allow:
        failures.append("socket(AF_INET, STREAM|NONBLOCK|CLOEXEC) not ALLOW")
    # ... misuse shapes die with EPERM (errno tier, loud-local) ...
    misuse = {
        "AF_PACKET+SOCK_RAW": (17, 3, 0),
        "AF_INET+SOCK_RAW": (2, 3, 6),
        "AF_NETLINK+SOCK_RAW": (16, 3, 0),
        "AF_INET6+SOCK_STREAM": (10, 1, 0),
        "AF_INET+SOCK_DGRAM": (2, 2, 0),
        "AF_UNIX+SOCK_RAW": (1, 3, 0),
        "bogus domain": (99, 1, 0),
        # Wave-59 break-first catch (CVE-2026-64564 intake): SCTP rides
        # SOCK_STREAM with protocol 132 — the protocol arg rule kills it.
        "SCTP via IPPROTO_SCTP": (2, 1, 132),
        "DCCP via IPPROTO_DCCP": (2, 1, 33),
    }
    for label, args in misuse.items():
        if decide(socket_nr, args) != eperm:
            failures.append("socket misuse %s not EPERM" % label)
    # High-bit smuggling is pinned, not denied, by the filter: classic BPF
    # sees only the low 32 bits of each arg, so domain 0x1_0000_0002 reads
    # as AF_INET and the filter ALLOWs. That is safe by construction —
    # the kernel validates the FULL 64-bit value and rejects it with
    # EAFNOSUPPORT before any socket exists — and this assertion pins the
    # truncation semantics so a future reader sees the deliberate shape.
    if decide(socket_nr, (2 | (1 << 32), 1, 0)) != allow:
        failures.append("high-bit domain low-32 view not ALLOW (unexpected)")
    # ioctl(): only TCGETS and FIOCLEX reach ALLOW (wave-60 F127 fix —
    # the blanket wave-59 removal SIGSYS-killed CPython at startup);
    # every other request dies with EPERM (errno tier, loud-local).
    ioctl_nr = numbers["ioctl"]
    if decide(ioctl_nr, (0, 0x5401, 0)) != allow:
        failures.append("ioctl TCGETS not ALLOW")
    if decide(ioctl_nr, (0, 0x5451, 0)) != allow:
        failures.append("ioctl FIOCLEX not ALLOW")
    ioctl_misuse = {
        "SIOCSIFADDR route manip": (0, 0x8916, 0),
        "SIOCSIFFLAGS route manip": (0, 0x8914, 0),
        "SIOCADDRT route manip": (0, 0x890B, 0),
        "TIOCSTI input injection": (0, 0x5412, 0),
        "TCSETS terminal reprogram": (0, 0x5402, 0),
        "FIONREAD unneeded": (0, 0x541B, 0),
        "bogus request": (0, 0xDEAD, 0),
    }
    for label, args in ioctl_misuse.items():
        if decide(ioctl_nr, args) != eperm:
            failures.append("ioctl misuse %s not EPERM" % label)
    # High-bit-smeared request: filter sees low 32 bits (TCGETS) and
    # ALLOWs; the kernel validates the full 64-bit request and fails it
    # with ENOTTY — safe by construction, same truncation argument as
    # socket() above.
    if decide(ioctl_nr, (0, 0x5401 | (1 << 32), 0)) != allow:
        failures.append("high-bit ioctl request low-32 view not ALLOW "
                        "(unexpected)")
    # ... escape/privilege shapes die with KILL (kill tier, SIGSYS) ...
    denied = ("bind", "listen", "accept", "accept4", "unshare", "setns",
              "ptrace", "mount", "pivot_root", "bpf", "keyctl",
              "add_key", "request_key", "seccomp", "prctl",
              "process_vm_readv", "process_vm_writev", "perf_event_open",
              "io_uring_setup", "userfaultfd", "kexec_load", "reboot",
              "init_module", "open_by_handle_at", "getsid")
    for name in denied:
        nr = numbers.get(name)
        if nr is not None and decide(nr) != kill:
            failures.append("dangerous %s not KILL" % name)
    # ... and the filter has no multiplexor or arch-alias bypass:
    # x86_64 has no socketcall number at all, and x32-aliased numbers
    # (nr | 0x40000000) never match the allowlist scan.
    if "socketcall" in numbers:
        failures.append("socketcall has a number on this arch: %d"
                        % numbers["socketcall"])
    if decide(socket_nr | 0x40000000, (2, 1, 0)) != kill:
        failures.append("x32-aliased socket nr not KILL")
    # Honest boundary, asserted deliberately: connect() is nr-ALLOW at
    # the filter — destination confinement is the netns's job (no route),
    # never seccomp's (classic BPF cannot dereference the sockaddr).
    if decide(numbers["connect"]) != allow:
        failures.append("connect not ALLOW (unexpected filter shape)")
    other_arch = (AUDIT_ARCH_AARCH64 if arch_nr == AUDIT_ARCH_X86_64
                  else AUDIT_ARCH_X86_64)
    if _bpf_decision(blob, other_arch, numbers["read"]) != kill:
        failures.append("wrong arch not KILL")
    print("cage filter semantics: %s"
          % ("ok" if not failures else "FAIL: %s" % failures))
    return 0 if not failures else 1


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="gov.sandbox")
    parser.add_argument("--audit-seccomp", action="store_true",
                        help="strace-audit DEFAULT_SECCOMP_ALLOW against "
                             "the standard tool workload")
    parser.add_argument("--audit-seccomp-cage", action="store_true",
                        help="byte-level audit of the FILTERED_EGRESS_CAGE "
                             "seccomp profile (no strace needed)")
    args = parser.parse_args(argv)
    if args.audit_seccomp:
        return audit_seccomp_allowlist()
    if args.audit_seccomp_cage:
        return audit_cage_seccomp_filter()
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
                 cage_mode="strict",
                 deployment_mode="production",
                 refusal_receipt_dir=None,
                 pivot_extra_mounts=None, canary_plant=None,
                 egress_launcher=None):
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
        if cage_mode not in _CAGE_MODES:
            raise ValueError(
                "unknown cage_mode %r: must be one of %s (fail-closed; "
                "an unknown mode never silently means 'no cage')"
                % (cage_mode, ", ".join(_CAGE_MODES)))
        if cage_mode == "filtered-egress" and not use_seccomp:
            raise ValueError("cage_mode='filtered-egress' requires "
                             "use_seccomp=True (fail-closed: the cage "
                             "profile is meaningless without the filter)")
        if egress_launcher is not None and cage_mode != "filtered-egress":
            raise ValueError(
                "egress_launcher is only meaningful with "
                "cage_mode='filtered-egress' (fail-closed: STRICT mode "
                "is untouched by the wall launcher)")
        if deployment_mode not in _DEPLOYMENT_MODES:
            raise ValueError(
                "unknown deployment_mode %r: must be one of %s "
                "(fail-closed; an unknown mode never silently disables "
                "the LOG-tier production guard)"
                % (deployment_mode, ", ".join(_DEPLOYMENT_MODES)))
        self.deployment_mode = deployment_mode
        # Wave-62 refusal loudness: opt-in structured-receipt sink for
        # fail-closed refusals. Explicit kwarg wins over
        # GOV_SANDBOX_REFUSAL_DIR; the stderr refusal line is
        # unconditional.
        self.refusal_receipt_dir = _resolve_refusal_receipt_dir(
            refusal_receipt_dir)
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
        self.cage_mode = cage_mode
        self.pivot_extra_mounts = dict(pivot_extra_mounts or {})
        # F81/D10: an optional FilteredEgressLauncher (gov/egress_launcher.py).
        # When cage_mode="filtered-egress" and a launcher is attached, the
        # spawn goes through the wall: the launcher owns verify -> check ->
        # wrap -> spawn -> audit, and the sandbox preexec rides along as a
        # preexec_chain entry. STRICT mode never consults the launcher.
        self.egress_launcher = egress_launcher
        # Wave-51 P1 egress canaries: optional planting hook
        # ``plant(jail_path, child_env) -> env_additions`` (see
        # gov.canary.make_canary_plant). Default None = nothing planted,
        # zero behavior change. The canary registry stays server-side;
        # only the (fake) artifacts enter the jail.
        self.canary_plant = canary_plant
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
        (fail closed: never exec anything ambiguous). Raises SandboxError
        when the LOG-tier production guard fires (wave-61): a LOG-tier
        request in deployment_mode="production" refuses before any jail
        is created — no launch, loud refusal.
        """
        # Wave-61 LOG-tier production guard: single chokepoint. The tier
        # is resolved EXACTLY ONCE per run and flows as a value from here
        # — nothing below re-reads the environment for the tier decision,
        # so there is no TOCTOU between decision and filter install and
        # the run note can never disagree with the installed tier.
        # Wave-62: the refusal is LOUD — _refuse_loud emits the stderr
        # record + optional structured receipt before raising, so a
        # caller that swallows the exception still leaves a trace.
        try:
            seccomp_tier = _resolve_seccomp_tier(
                self.deployment_mode, _env_flag("GOV_SANDBOX_SECCOMP_LOG"))
        except SandboxError as e:
            _refuse_loud(str(e), kind="seccomp-log-tier-guard",
                         receipt_dir=self.refusal_receipt_dir,
                         extra={"deployment_mode": self.deployment_mode})
        # F81/D10 + Fog decision 2 (composition): filtered-egress with an
        # attached launcher spawns through the wall. The wall is the
        # network boundary, so the sandbox keeps rlimits/filesystem/pidns
        # and anything that conflicts with the wall spawn path refuses
        # here, before any jail is created (fail-closed at launch).
        launcher_mode = (self.cage_mode == "filtered-egress"
                         and self.egress_launcher is not None)
        if launcher_mode:
            if self.drop_privs:
                _refuse_loud(
                    "egress-launcher mode cannot drop privileges in "
                    "preexec: `ip netns exec` needs the operator's "
                    "privilege (fail-closed)",
                    kind="egress-launcher-conflict",
                    receipt_dir=self.refusal_receipt_dir,
                    extra={"conflict": "drop_privs"})
            if self.require_seccomp:
                _refuse_loud(
                    "egress-launcher mode supersedes the cage seccomp "
                    "filter with the wall helper: require_seccomp cannot "
                    "be attested via the sandbox status pipe (the wall's "
                    "attestation is the egress_wall_launch audit event)",
                    kind="egress-launcher-conflict",
                    receipt_dir=self.refusal_receipt_dir,
                    extra={"conflict": "require_seccomp"})
            if self.require_netns:
                _refuse_loud(
                    "egress-launcher mode provides the network namespace "
                    "via the wall, not the sandbox's own unshare: "
                    "require_netns cannot be attested via the sandbox "
                    "status pipe (the wall's attestation is the "
                    "egress_wall_launch audit event)",
                    kind="egress-launcher-conflict",
                    receipt_dir=self.refusal_receipt_dir,
                    extra={"conflict": "require_netns"})
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
            if self.canary_plant is not None:
                # Wave-51 P1: seed the jail with canary artifacts before
                # the child starts. Planting failure refuses the run
                # fail-closed — a run that believes it is canaried when
                # it is not would be a silent coverage loss.
                try:
                    _canary_env = self.canary_plant(jail, child_env)
                except Exception as e:
                    _refuse_loud("canary planting failed: %r" % (e,),
                                 kind="canary-plant-failure",
                                 receipt_dir=self.refusal_receipt_dir)
                if _canary_env:
                    child_env.update(_canary_env)
            # Status pipe: the pre-exec hook reports the per-call ground
            # truth as exactly five bytes —
            #   [net, pid, pivot, privdrop, seccomp] —
            # written by a single party per call just before exec (or
            # before os._exit(127) on a fail-closed refusal). The parent
            # reads them deadline-bounded; missing bytes (EOF) mean "not
            # established". pass_fds keeps the write end open in the child.
            status_r, status_w = os.pipe()
            preexec = self._make_preexec(argv, child_env, status_w, str(jail),
                                          seccomp_tier)
            start = time.monotonic()
            popen_kw = dict(
                cwd=str(jail),
                stdin=(subprocess.PIPE if stdin_data is not None
                       else subprocess.DEVNULL),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, pass_fds=(status_w,))
            try:
                if launcher_mode:
                    # The governed spawn path and the wall are one call:
                    # the launcher owns lock -> verify -> check -> wrap ->
                    # spawn -> audit; the sandbox preexec rides along as
                    # a preexec_chain entry (the wall re-check runs
                    # first, then sandbox hardening). The child env
                    # merges under the wall's scrubbed/provided vars.
                    proc = self.egress_launcher.launch(
                        argv, env=child_env, preexec_chain=(preexec,),
                        **popen_kw)
                else:
                    # Standalone (no launcher wrapper to convert the
                    # F150 raise-don't-exit abort): translate it back to
                    # the historical fail-closed os._exit(127) so this
                    # path stays bit-identical.
                    proc = subprocess.Popen(
                        argv, env=child_env,
                        preexec_fn=self._standalone_preexec(preexec),
                        **popen_kw)
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
                _refuse_loud(
                    "%s layer(s) required but not established"
                    % "+".join(missing),
                    kind="required-layer-missing",
                    receipt_dir=self.refusal_receipt_dir,
                    extra={"missing": sorted(missing)})
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
            if launcher_mode:
                # The wall is the network boundary for this run; the
                # sandbox's per-call bytes report what the SANDBOX
                # established, and the wall's attestation is the
                # egress_wall_launch audit event.
                wall_note = (
                    "egress wall launcher: network isolation and network "
                    "seccomp provided by the wall (see the "
                    "egress_wall_launch audit event); the cage seccomp "
                    "filter was not double-installed and the sandbox's "
                    "own netns unshare was skipped")
                result.note = (result.note + "; " + wall_note
                               if result.note else wall_note)
            elif self.cage_mode == "filtered-egress":
                # No longer silent: without a launcher this mode is the
                # internal cage seccomp profile only -- no netns/nftables
                # wall stands behind it.
                bare_note = (
                    "filtered-egress without an egress launcher: internal "
                    "cage seccomp profile only; no netns/nftables wall")
                result.note = (result.note + "; " + bare_note
                               if result.note else bare_note)
            if (self.use_seccomp and seccomp_active
                    and seccomp_tier == "log"):
                # Staging tier honesty: LOG mode audit-logs denials but
                # does not enforce them. A run that believes it was
                # kill-enforced when it was not would be a silent coverage
                # loss, so the mode is stamped on the result. The tier is
                # the value resolved once by the LOG-tier production guard
                # at run() top — never a second env read, so the stamp
                # cannot disagree with the installed filter.
                log_note = ("seccomp LOG staging mode: denials were "
                            "audit-logged, NOT enforced")
                result.note = (result.note + "; " + log_note
                               if result.note else log_note)
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

    @staticmethod
    def _standalone_preexec(chain_entry):
        """Adapt a chain entry for raw Popen(preexec_fn=...) use (F150).

        In launcher mode the launcher's _preexec wrapper converts
        PreexecChainAbort to PREEXEC_CHAIN_ABORT_CODE (98). Standalone
        there is no wrapper, and Popen would surface the raise as
        SubprocessError('Exception occurred in preexec_fn.') -- so
        translate the abort back to the historical fail-closed
        os._exit(127) here, keeping standalone behavior bit-identical:
        the status marker (written before the raise) or its EOF still
        drives _refuse_loud at the call site.
        """
        def _preexec():
            try:
                chain_entry()
            except PreexecChainAbort:
                os._exit(127)
        return _preexec

    def _make_preexec(self, argv, child_env, status_w, jail_path,
                      seccomp_tier):
        # F81/D10 + Fog decision 2 (composition): in egress-launcher
        # mode the wall is the network boundary. The sandbox keeps
        # rlimits/filesystem/pidns; its own netns unshare is skipped
        # (the wall provides the netns) and its cage seccomp install is
        # skipped (the wall helper provides the network filter --
        # installing the cage filter too would KILL `ip netns exec`'s
        # netlink syscalls, a fail-closed conflict). drop_privs /
        # require_seccomp / require_netns with a launcher refuse in
        # run(), before this point.
        launcher_mode = (self.cage_mode == "filtered-egress"
                         and self.egress_launcher is not None)
        launcher_wall = (self.egress_launcher.wall
                         if launcher_mode else None)
        use_netns = self.use_netns and not launcher_mode
        use_pidns = self.use_pidns
        require_netns = self.require_netns
        require_pidns = self.require_pidns
        use_pivot = self.use_pivot_root
        require_pivot = self.require_pivot_root
        drop_privs = self.drop_privs
        require_privdrop = self.require_privdrop
        use_seccomp = self.use_seccomp and not launcher_mode
        require_seccomp = self.require_seccomp
        cage_mode = self.cage_mode
        # Wave-61: the seccomp default-action tier arrives as a resolved
        # VALUE from run() (the LOG-tier production guard). This function
        # never re-reads the environment for the tier — there is no
        # decision/install TOCTOU and the child-side preexec cannot be
        # influenced by env at all (the tier decision is parent-side,
        # pre-fork).
        if seccomp_tier not in ("kill", "log"):
            raise SandboxError(
                "refusing to launch: unresolved seccomp tier %r "
                "(fail-closed: the guard must resolve 'kill' or 'log')"
                % (seccomp_tier,))
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
            flag, a setup failure raises PreexecChainAbort (F150
            raise-don't-exit): under the launcher wrapper it converts
            to PREEXEC_CHAIN_ABORT_CODE (98); the forked worker
            translates it back to the historical os._exit(127) (see the
            worker branch below).
            """
            priv_ok = False
            if drop_privs:
                try:
                    _drop_to_nobody()
                except OSError:
                    if require_privdrop:
                        raise PreexecChainAbort(
                            127, "sandbox: required privdrop missing")
                else:
                    priv_ok = True
            seccomp_ok = False
            if use_seccomp:
                try:
                    _install_seccomp_filter_for_mode(
                        cage_mode,
                        default_action=seccomp_tier)
                except OSError:
                    if require_seccomp:
                        raise PreexecChainAbort(
                            127, "sandbox: required seccomp missing")
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
                # network still attached. F150: raise-don't-exit -- the
                # launcher wrapper converts this to PREEXEC_CHAIN_ABORT_CODE
                # (98); the marker above still drives _refuse_loud.
                _report(False, False, False, False, False)
                raise PreexecChainAbort(
                    127, "sandbox: required network namespace missing")
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
                # F150: raise-don't-exit (see above).
                _report(net_ok, False, False, False, False)
                raise PreexecChainAbort(
                    127, "sandbox: required pivot-root missing")
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
                        try:
                            priv_ok, seccomp_ok = _harden_worker()
                        except PreexecChainAbort:
                            # Forked worker: no launcher wrapper here to
                            # convert the F150 abort -- keep the
                            # historical fail-closed os._exit(127), with
                            # no marker (EOF drives _refuse_loud, as
                            # before).
                            os._exit(127)
                        _report(net_ok, True, pivot_done, priv_ok,
                                seccomp_ok)
                        try:
                            # F81/D10: in launcher mode the pidns worker
                            # execs the wall-wrapped argv (the wrap
                            # happens here, in the child, after
                            # hardening -- exactly once on this path;
                            # the parent's Popen argv is unused here).
                            spawn_argv = (
                                launcher_wall.wrap_argv(argv)
                                if launcher_wall is not None else argv)
                            os.execvpe(spawn_argv[0], spawn_argv,
                                       child_env)
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
                # F150: raise-don't-exit (see above).
                _report(net_ok, False, pivot_ok, False, False)
                raise PreexecChainAbort(
                    127, "sandbox: required PID namespace missing")
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
                        # F150: raise-don't-exit (see above).
                        _report(net_ok, False, False, False, False)
                        raise PreexecChainAbort(
                            127, "sandbox: required pivot-root missing")
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
        if proc.returncode == -signal.SIGSYS:
            # Audit story tier 2 (wave-59 cage profile): a SIGSYS death is
            # the seccomp kill tier firing — an escape/privilege-class
            # syscall attempt (unshare, setns, ptrace, bpf, keyctl, mount,
            # prctl/seccomp, io_uring, ...). Never silent: this note makes
            # it a finding-grade event in the run's audit trail. (The
            # errno tier — EPERM from socket() arg violations — stays
            # child-visible only by design; see FILTERED_EGRESS_CAGE_ALLOW.)
            sigsys_note = ("seccomp kill-tier denial: child died with "
                           "SIGSYS (blocked escape/privilege-class syscall)")
            note = sigsys_note + ("; " + note if note else "")
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

    def execute(self, tool, args, ctx, identity=None):
        # identity: accepted (and ignored here) so this backend stays a
        # drop-in replacement for ToolExecutor._simulate, whose callers
        # pass identity= since wave-117/H2. Containment reporting uses
        # the "traversal_contained" result marker instead: call() turns
        # it into the chained sandbox_traversal_contained event (the
        # backend holds no chain writer of its own).
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
            # H2 (wave-117 audit fix): an escaping read contained here
            # must be LOUD, like the plain-executor path. The backend
            # holds no chain writer, so it reports the containment via
            # the result marker; ToolExecutor.call() turns the marker
            # into the chained sandbox_traversal_contained event.
            return {"source": "simulated",
                    "content": "[synthetic file contents]",
                    "traversal_contained": True}
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
