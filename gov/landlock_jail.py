"""Landlock LSM filesystem jail (stdlib only: ctypes against libc).

Wave-266 built this tier inside ``gov/sandbox.py`` (pattern ADAPTED from
the wave-265 NVIDIA OpenShell teardown, prospectus w330 section 1:
OpenShell confines tools with the Landlock LSM + seccomp-BPF). Pattern
only -- no vendored code; the ruleset below is written against the kernel
ABI documented in linux/landlock.h and was verified empirically on this
tree's kernels (ABI 8).

Wave-331 moved the tier here verbatim (byte-identical logic) and added
the standalone API the w330 prospectus asked for:

* :func:`landlock_supported` -- enforcement-backed availability probe.
* :func:`restrict_fs` -- confine the CURRENT process to caller-declared
  read/write (/exec) paths. This is the piece ``gov/sandbox.py`` does
  not offer: the sandbox tier builds a fixed jail_root+scratch+system
  policy per tool call, while ``restrict_fs`` lets any component (a
  worker process, a pre-exec hook, an embedding application) self-confine
  with an explicit path policy.

Design (unchanged from wave-266):
  * the ruleset is built from caller-declared paths and applied with
    ``landlock_restrict_self`` -- 3 syscalls, no privileges needed;
  * ABI versioning: the ABI is probed
    (``landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)``)
    and only rights the kernel supports are used; an unknown/unparseable
    ABI refuses coded, never guesses;
  * availability is not just "syscalls exist": a forked child applies a
    deny-all ruleset and must observe EACCES (catches the LSM-disabled
    silent bypass); the parent is never confined by the probe;
  * default-deny: everything not granted is denied; grants pin inodes via
    O_PATH fds, so they survive renames of the parent directories;
  * Landlock is per-thread, irreversible, and inherited by descendants --
    apply before spawning threads/workers that need the wider view, and
    only in a process (or pre-exec hook) you intend to confine.

Fail-closed contract:
  * unsupported kernel/LSM -> :class:`LandlockError` with code
    ``sandbox-landlock-unavailable`` (honest degradation: the jail
    refuses, it never silently runs unjailed);
  * ruleset build/apply failure, caller misuse (relative paths, missing
    paths, ambiguous overlapping grants), restrict_self failure ->
    :class:`LandlockError` with code ``sandbox-landlock-apply-failed``;
    the process is never left half-jailed: a failure raises before any
    wider access is assumed.

Honest residuals (documented, not gaps):
  * Landlock cannot restrict stat/chdir (kernel limitation, noted in
    linux/landlock.h); directory listings of denied trees fail, but
    metadata probes do not;
  * symlinks: rules pin the resolved inode and Landlock checks the
    *target* path at access time -- a symlink inside a granted tree that
    points outside the policy is denied (probed, not assumed);
  * rename/link across differently-granted hierarchies fail (EINVAL from
    the kernel when REFER is not in the handled set) -- the existing
    tier's comment is preserved verbatim;
  * on ABI < 3 TRUNCATE is not a handled right (kernel limitation); in
    practice truncation still requires write access, which the jail
    gates -- probed on ABI 8;
  * Linux-only mechanism; ``landlock_supported()`` gates on
    ``sys.platform``, not just posix.

Stdlib only. No network jail (see the sandbox netns tier for that).
"""

import ctypes
import errno
import os
import platform
import sys

__all__ = [
    "LandlockError",
    "landlock_supported",
    "landlock_available",
    "landlock_abi_version",
    "landlock_build_ruleset",
    "restrict_fs",
]

# ---------------------------------------------------------------------------
# Syscall numbers (local resolver -- mirrors gov/sandbox.py's
# _parse_unistd_header/_syscall_numbers so this module stays importable
# without gov.sandbox; both parse the same kernel headers).
# ---------------------------------------------------------------------------

_LANDLOCK_ARCH = platform.machine()

# Builtin x86_64 numbers (torvalds/linux
# arch/x86/entry/syscalls/syscall_64.tbl); only used when the kernel
# headers are absent. Other arches resolve via header parsing, else the
# mechanism reports unavailable (fail-closed, never guessed).
_LANDLOCK_BUILTIN_NUMBERS_X86_64 = {
    "landlock_create_ruleset": 444,
    "landlock_add_rule": 445,
    "landlock_restrict_self": 446,
}

_LANDLOCK_SYSCALL_NUMBERS_CACHE = None


def _parse_unistd_header(path):
    numbers = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
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


def _landlock_syscall_number(name):
    """Syscall number for this arch. Raises KeyError when unresolvable."""
    global _LANDLOCK_SYSCALL_NUMBERS_CACHE
    if _LANDLOCK_SYSCALL_NUMBERS_CACHE is None:
        numbers = {}
        header_dirs = []
        if _LANDLOCK_ARCH == "x86_64":
            header_dirs = ["/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
                           "/usr/include/asm/unistd_64.h"]
        elif _LANDLOCK_ARCH == "aarch64":
            header_dirs = ["/usr/include/aarch64-linux-gnu/asm/unistd.h",
                           "/usr/include/asm/unistd.h"]
        for path in header_dirs:
            numbers = _parse_unistd_header(path)
            if numbers:
                break
        if not numbers and _LANDLOCK_ARCH == "x86_64":
            numbers = dict(_LANDLOCK_BUILTIN_NUMBERS_X86_64)
        _LANDLOCK_SYSCALL_NUMBERS_CACHE = numbers
    return _LANDLOCK_SYSCALL_NUMBERS_CACHE[name]


# ---------------------------------------------------------------------------
# Landlock LSM tier (moved verbatim from gov/sandbox.py, wave-266).
# ---------------------------------------------------------------------------

_LANDLOCK_CREATE_RULESET_VERSION = 0x1
_LANDLOCK_RULE_PATH_BENEATH = 1

# Filesystem rights, linux/landlock.h (bits 0-14; REFER is always
# implicitly handled by the kernel; TRUNCATE exists since ABI 3).
_LANDLOCK_FS_EXECUTE = 0x1
_LANDLOCK_FS_WRITE_FILE = 0x2
_LANDLOCK_FS_READ_FILE = 0x4
_LANDLOCK_FS_READ_DIR = 0x8
_LANDLOCK_FS_TRUNCATE = 0x4000

_LANDLOCK_ABI_CACHE = {"version": None}
_LANDLOCK_AVAILABLE_CACHE = {"available": None}

# System allowlist, mirroring the pivot layer's read-only staging set.
# /etc is read-only (not just ld.so.cache): the dynamic linker, NSS, and
# distro symlinks out of /usr (e.g. /usr/lib/python3.12/sitecustomize.py
# -> /etc/python3.12/sitecustomize.py) all resolve under it. Sensitive
# files stay protected by Unix permissions + privdrop.
_LANDLOCK_DEFAULT_SYSTEM_RO = ("usr", "bin", "lib", "lib64", "sbin", "etc")

_LANDLOCK_SCRATCH_NAME_DEFAULT = "scratch"


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64),
                ("parent_fd", ctypes.c_int32)]


def _landlock_syscall_numbers():
    """(create, add_rule, restrict_self) syscall numbers for this arch.

    Raises KeyError when unresolvable — callers treat that as
    "unavailable", never as a silent bypass.
    """
    return (_landlock_syscall_number("landlock_create_ruleset"),
            _landlock_syscall_number("landlock_add_rule"),
            _landlock_syscall_number("landlock_restrict_self"))


def _landlock_syscall(nr, *args):
    """Raw Landlock syscall. Raises OSError on failure."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ret = libc.syscall(nr, *args)
    if ret < 0:
        raise OSError(ctypes.get_errno(),
                      "landlock syscall %d failed" % (nr,))
    return ret


def landlock_abi_version():
    """Kernel Landlock ABI version, or 0 when the syscalls are absent."""
    if _LANDLOCK_ABI_CACHE["version"] is None:
        version = 0
        try:
            nr_create, _, _ = _landlock_syscall_numbers()
            v = _landlock_syscall(nr_create, None, 0,
                                  _LANDLOCK_CREATE_RULESET_VERSION)
            if 1 <= v <= 64:
                version = int(v)
        except (OSError, KeyError):
            version = 0
        _LANDLOCK_ABI_CACHE["version"] = version
    return _LANDLOCK_ABI_CACHE["version"]


def _landlock_enforcement_probe():
    """Forked child: does restrict_self() actually confine?

    The syscalls can be wired while the LSM is disabled; then
    restrict_self() succeeds and confines nothing. The only reliable
    detector is empirical: confine a child with a deny-all ruleset and
    check that opening ordinary files fails EACCES. Probed once per
    process; the parent is never confined (same pattern as
    netns_available()).
    """
    pid = os.fork()
    if pid == 0:  # child
        try:
            nr_create, _, nr_restrict = _landlock_syscall_numbers()
            attr = _LandlockRulesetAttr(
                _LANDLOCK_FS_EXECUTE | _LANDLOCK_FS_WRITE_FILE
                | _LANDLOCK_FS_READ_FILE | _LANDLOCK_FS_READ_DIR, 0)
            rs = _landlock_syscall(nr_create, ctypes.byref(attr),
                                   ctypes.sizeof(attr), 0)
            _landlock_syscall(nr_restrict, rs, 0)
            os.close(rs)
            # Deny-all is active: at least one open must fail EACCES,
            # and none may succeed.
            enforced = False
            for probe_path in ("/etc/hostname", "/proc/version",
                               "/etc/passwd"):
                try:
                    fd = os.open(probe_path, os.O_RDONLY)
                except OSError as e:
                    if e.errno == errno.EACCES:
                        enforced = True
                else:
                    os.close(fd)
                    os._exit(1)  # opened: NOT confined
            os._exit(0 if enforced else 1)
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def landlock_available():
    """True when this kernel actually enforces Landlock confinement."""
    if _LANDLOCK_AVAILABLE_CACHE["available"] is None:
        available = False
        # Landlock is a Linux-only mechanism; the posix check alone would
        # let other Unixes reach the syscall-number parse below, which can
        # only fail its way to False.
        if (sys.platform.startswith("linux") and landlock_abi_version() >= 1):
            available = _landlock_enforcement_probe()
        _LANDLOCK_AVAILABLE_CACHE["available"] = available
    return _LANDLOCK_AVAILABLE_CACHE["available"]


def landlock_supported():
    """Enforcement-backed Landlock availability probe.

    Stronger than a kernel-version check: True only when the syscalls
    exist AND a forked child demonstrably gets confined (catches the
    LSM-disabled silent bypass). Cached per process. This is the gate
    for :func:`restrict_fs` and the honest-degradation signal for
    callers that must refuse when the jail cannot be enforced.
    """
    return landlock_available()


def _landlock_add_path_rule(ruleset_fd, path, allowed_access):
    """Grant allowed_access on the hierarchy (or file) at path."""
    _, nr_add, _ = _landlock_syscall_numbers()
    is_dir = os.path.isdir(path)
    if not is_dir:
        # Directory-only rights are invalid on file rules (EINVAL).
        allowed_access &= ~_LANDLOCK_FS_READ_DIR
    flags = os.O_PATH | (os.O_DIRECTORY if is_dir else 0)
    fd = os.open(path, flags)
    try:
        attr = _LandlockPathBeneathAttr(allowed_access, fd)
        _landlock_syscall(nr_add, ruleset_fd, _LANDLOCK_RULE_PATH_BENEATH,
                          ctypes.byref(attr), 0)
    finally:
        os.close(fd)


def landlock_build_ruleset(*, jail_root, scratch_name, argv0, extra_ro=()):
    """Build (not yet apply) the Landlock ruleset for one call.

    Returns the ruleset fd, owned by the caller (pass it to the child
    over pass_fds; the child calls restrict_self() then closes it).
    Raises OSError when the ruleset cannot be built — the caller must
    refuse fail-closed.
    """
    abi = landlock_abi_version()
    if abi < 1:
        raise OSError(errno.ENOSYS, "landlock unavailable on this kernel")
    nr_create, _, _ = _landlock_syscall_numbers()
    handled_fs = (_LANDLOCK_FS_EXECUTE | _LANDLOCK_FS_WRITE_FILE
                  | _LANDLOCK_FS_READ_FILE | _LANDLOCK_FS_READ_DIR)
    if abi >= 3:
        handled_fs |= _LANDLOCK_FS_TRUNCATE
    attr = _LandlockRulesetAttr(handled_fs, 0)
    # The net-rights field exists since ABI 4; size the struct the
    # kernel understands.
    attr_size = ctypes.sizeof(attr) if abi >= 4 else 8
    rs = _landlock_syscall(nr_create, ctypes.byref(attr), attr_size, 0)
    try:
        read_only = _LANDLOCK_FS_READ_FILE | _LANDLOCK_FS_READ_DIR
        rx = read_only | _LANDLOCK_FS_EXECUTE
        seen = set()

        def _grant(path, access):
            real = os.path.realpath(path)
            if real in seen:
                return
            seen.add(real)
            _landlock_add_path_rule(rs, real, access)

        # The jail root: readable, never writable (tool output goes to
        # the scratch subdir).
        _grant(jail_root, read_only)
        # Designated scratch: read-write (no execute — write-then-
        # execute stays impossible), truncate where the ABI has it.
        scratch_access = read_only | _LANDLOCK_FS_WRITE_FILE
        if abi >= 3:
            scratch_access |= _LANDLOCK_FS_TRUNCATE
        _grant(os.path.join(jail_root, scratch_name), scratch_access)
        # System allowlist. Missing entries are skipped (distro
        # variance); the interpreter's own directory is always covered
        # so the child can still exec.
        for name in _LANDLOCK_DEFAULT_SYSTEM_RO:
            path = os.path.join("/", name)
            if os.path.isdir(path):
                _grant(path, rx)
        for exe_dir in (os.path.dirname(os.path.realpath(argv0)),
                        os.path.dirname(os.path.realpath(sys.executable))):
            if os.path.isdir(exe_dir):
                _grant(exe_dir, rx)
        # Venv interpreters: site.py reads pyvenv.cfg (next to the
        # unresolved executable's parent dir) at startup. Grant that
        # single file read-only when present — nothing else from the
        # venv is needed under -I.
        for exe in (argv0, sys.executable):
            cfg = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(exe))),
                "pyvenv.cfg")
            if os.path.isfile(cfg):
                _grant(cfg, read_only)
        # Operator widening (explicit absolute paths only).
        for path in extra_ro:
            if not os.path.isabs(path):
                raise OSError(errno.EINVAL,
                              "landlock_extra_ro must be absolute: %r"
                              % (path,))
            if os.path.isdir(path):
                _grant(path, rx)
            elif os.path.isfile(path):
                _grant(path, read_only)
            else:
                raise OSError(errno.ENOENT,
                              "landlock_extra_ro not found: %r" % (path,))
    except BaseException:
        try:
            os.close(rs)
        except OSError:
            pass
        raise
    return rs


def _landlock_restrict_self(ruleset_fd):
    """Activate the ruleset for the calling thread. Raises OSError."""
    _, _, nr_restrict = _landlock_syscall_numbers()
    _landlock_syscall(nr_restrict, ruleset_fd, 0)


# ---------------------------------------------------------------------------
# Standalone jail API (wave-331).
# ---------------------------------------------------------------------------

class LandlockError(OSError):
    """A Landlock jail operation refused fail-closed.

    Carries a machine-readable ``code`` drawn from the centrally
    registered ``sandbox-landlock-*`` decision codes:

    * ``sandbox-landlock-unavailable`` -- the kernel/LSM cannot enforce
      Landlock (syscalls absent, ABI unknown, or the empirical
      enforcement probe failed). Honest degradation: the jail refuses;
      it never silently runs unjailed.
    * ``sandbox-landlock-apply-failed`` -- the ruleset could not be
      built or enforced, or the caller's path policy was unusable
      (relative path, missing path, ambiguous overlapping grants).
    """

    def __init__(self, code, detail):
        super().__init__(errno.EPERM,
                         "landlock: [%s] %s" % (code, detail))
        self.code = code
        self.detail = detail


def _checked_jail_paths(paths, *, kind):
    """Validate caller-declared jail paths. Fail-closed, never guessing."""
    if not isinstance(paths, (list, tuple)):
        raise LandlockError(
            "sandbox-landlock-apply-failed",
            "%s must be a list/tuple of absolute paths, got %r"
            % (kind, type(paths).__name__))
    checked = []
    for path in paths:
        if not isinstance(path, str) or not os.path.isabs(path):
            raise LandlockError(
                "sandbox-landlock-apply-failed",
                "%s must be absolute paths, got %r (fail-closed: a "
                "relative jail path never silently means 'somewhere')"
                % (kind, path))
        real = os.path.realpath(path)
        if not os.path.exists(real):
            raise LandlockError(
                "sandbox-landlock-apply-failed",
                "%s path does not exist: %r" % (kind, path))
        checked.append(real)
    return checked


def restrict_fs(read_paths, write_paths, *, exec_paths=()):
    """Confine the CURRENT process to caller-declared filesystem paths.

    Builds a default-deny Landlock ruleset -- ``read_paths`` readable,
    ``write_paths`` readable+writable, ``exec_paths`` readable+executable
    -- and applies it to the calling thread via ``landlock_restrict_self``.
    Everything else is denied (EACCES).

    This is IRREVERSIBLE for the calling thread and inherited by all
    descendants: Landlock layers stack, so a later ``restrict_fs`` can
    only narrow further, never widen. Call it in a dedicated worker
    process (or a pre-exec hook) -- never in a long-lived process that
    still needs the wider view. The enforcement probes in the battery
    fork before confining; the parent is never jailed by a probe.

    Symlink behavior (probed, documented LOUD): rules pin resolved
    inodes and the kernel checks the *target* path at access time, so a
    symlink inside a granted tree that points outside the policy is
    denied. Rename/link across differently-granted hierarchies fail.

    Raises :class:`LandlockError` (fail-closed) when the kernel cannot
    enforce Landlock, the path policy is unusable, or enforcement
    fails. On success returns None -- the jail is active.
    """
    if not landlock_supported():
        raise LandlockError(
            "sandbox-landlock-unavailable",
            "Landlock cannot be enforced on this kernel/LSM; refusing "
            "to run without the jail (fail-closed)")
    reads = _checked_jail_paths(read_paths, kind="read_paths")
    writes = _checked_jail_paths(write_paths, kind="write_paths")
    execs = _checked_jail_paths(exec_paths, kind="exec_paths")

    # Ambiguous overlapping grants are refused, never silently resolved:
    # the same inode may not carry two different access levels. Nested
    # hierarchies (a write dir inside a read tree) are allowed -- the
    # deeper rule refines the shallower one, matching the sandbox tier's
    # jail_root/scratch shape.
    grants = {}
    read_only = _LANDLOCK_FS_READ_FILE | _LANDLOCK_FS_READ_DIR
    for path in reads:
        grants.setdefault(path, read_only)
    write_access = read_only | _LANDLOCK_FS_WRITE_FILE
    abi = landlock_abi_version()
    if abi >= 3:
        write_access |= _LANDLOCK_FS_TRUNCATE
    for path in writes:
        if path in grants and grants[path] != write_access:
            raise LandlockError(
                "sandbox-landlock-apply-failed",
                "path %r is both read-only and writable: ambiguous "
                "grant refused (fail-closed)" % (path,))
        grants[path] = write_access
    exec_access = read_only | _LANDLOCK_FS_EXECUTE
    for path in execs:
        if path in grants and grants[path] != exec_access:
            raise LandlockError(
                "sandbox-landlock-apply-failed",
                "path %r has conflicting grants: ambiguous grant "
                "refused (fail-closed)" % (path,))
        grants[path] = exec_access

    nr_create, _, _ = _landlock_syscall_numbers()
    handled_fs = (_LANDLOCK_FS_EXECUTE | _LANDLOCK_FS_WRITE_FILE
                  | _LANDLOCK_FS_READ_FILE | _LANDLOCK_FS_READ_DIR)
    if abi >= 3:
        handled_fs |= _LANDLOCK_FS_TRUNCATE
    attr = _LandlockRulesetAttr(handled_fs, 0)
    attr_size = ctypes.sizeof(attr) if abi >= 4 else 8
    try:
        rs = _landlock_syscall(nr_create, ctypes.byref(attr), attr_size, 0)
    except OSError as exc:
        raise LandlockError("sandbox-landlock-apply-failed",
                            "ruleset creation failed: %s" % (exc,))
    try:
        # Deeper paths first so refinements land after their parents.
        for path in sorted(grants, key=len, reverse=True):
            try:
                _landlock_add_path_rule(rs, path, grants[path])
            except OSError as exc:
                raise LandlockError(
                    "sandbox-landlock-apply-failed",
                    "rule for %r could not be added: %s" % (path, exc))
        try:
            _landlock_restrict_self(rs)
        except OSError as exc:
            raise LandlockError("sandbox-landlock-apply-failed",
                                "restrict_self failed: %s" % (exc,))
    finally:
        try:
            os.close(rs)
        except OSError:
            pass
    return None
