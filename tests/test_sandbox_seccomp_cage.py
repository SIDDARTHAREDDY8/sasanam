"""Wave-59: filtered-egress cage seccomp profile — implementation + break-first.

Lane 1 implements the wave-58 draft
(workstreams/architect/F81_SECCOMP_PROFILE_DRAFT.md) as real BPF bytes in
gov/sandbox.py: FILTERED_EGRESS_CAGE_ALLOW + _build_seccomp_filter_args +
Sandbox(cage_mode="filtered-egress"). Lane 2 attacks the *compiled
bytes*, not the draft:

  5.1 AF_PACKET / SOCK_RAW smuggling  -> must die with the filter's
      SECCOMP_RET_ERRNO|EPERM (errno tier, loud-local). The protocol arg
      is constrained to {0, IPPROTO_TCP} (wave-59 break-first catch from
      the CVE-2026-64564 intake: SCTP-over-STREAM smuggling dies too).
  5.2 Unix-socket proxy impersonation -> the filter denies bind/listen/
      accept* outright (KILL tier): nothing in the cage can listen, so
      there is no rendezvous point to impersonate. (The proxy itself
      listens on TCP at the parent-owned veth address; the child cannot
      bind it — held by construction + launcher policy, proven at the
      filter by the bind denial.)
  5.3 fd-passing (SCM_RIGHTS)         -> documented trust boundary, not a
      filter rule: recvmsg/sendmsg stay ALLOW (nr-only). The cage's fd
      hygiene (CLOEXEC + minimal inherit, parent passes no fds) is the
      control; a multi-process cage would need ancillary-data inspection.
      Asserted here so the boundary is pinned, not assumed.
  5.4 connect() destination           -> the filter deliberately does NOT
      confine connect() (classic BPF cannot dereference the sockaddr;
      draft §3 honest correction). Asserted as ALLOW with the backstop
      named: the netns has no route (ENETUNREACH), the proxy enforces
      policy, the upstream firewall owns the wall.
  5.5 clone(CLONE_NEWNET)/unshare     -> unshare/setns are KILL tier;
      clone stays ALLOW (threads are legitimate).
  5.6 prctl/seccomp self-tampering    -> KILL tier (absent from allowlist).
  5.7 socketcall multiplexing / x32   -> x86_64 has no socketcall number;
      x32-aliased numbers (nr|0x40000000) never match the scan -> KILL.
  Deny-by-default                     -> an unlisted syscall (getsid) dies
      with KILL, not ALLOW.

Every test below evaluates the exact bytes _build_cage_seccomp_filter
emits (via _bpf_decision, the module's pure-Python evaluator), so they
run — and must pass — even where live seccomp installation is refused
(this environment: prctl(PR_SET_SECCOMP) -> EINVAL, see
workstreams/evals/SECCOMP_REPORT.md). Live-installation tests are
gated on seccomp_available() like the existing SeccompLiveTest.

No new finding is filed by this module: every break shape above holds
at the bytes. F81 stays OPEN — the seccomp profile is one layer of the
filtered-egress mode; F81's closure criteria (wave-57/58) require the
full wall (netns + veth + proxy + this filter) proven in a privileged
deployment CI.

Registry: redteam.f81.seccomp_* (wave-59), finding F81.
"""

import io
import json
import os
import struct
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
import sys
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gov.sandbox as gov_sandbox
from gov.sandbox import (
    Sandbox, SandboxError, FILTERED_EGRESS_CAGE_ALLOW,
    sandbox_config_from_env, seccomp_available,
)

SECCOMP = seccomp_available()

_ALLOW = gov_sandbox._SECCOMP_RET_ALLOW
_KILL = gov_sandbox._SECCOMP_RET_KILL_PROCESS
_EPERM_RET = gov_sandbox._SECCOMP_RET_ERRNO | gov_sandbox._EPERM
_LOG = gov_sandbox._SECCOMP_RET_LOG

# Well-known constants (pinned here, not imported from socket, so the
# test asserts the exact immediates the BPF encodes).
AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
AF_NETLINK, AF_PACKET = 16, 17
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3
SOCK_NONBLOCK, SOCK_CLOEXEC = 0x800, 0x80000
NETLINK_ROUTE = 0


def _cage_blob(default_action="kill"):
    numbers = gov_sandbox._syscall_numbers()
    if not numbers:
        raise unittest.SkipTest("no syscall numbers on this arch")
    return gov_sandbox._build_cage_seccomp_filter(
        numbers, default_action=default_action), numbers


class SeccompCageBytesTest(unittest.TestCase):
    """The compiled program's shape: instruction count, structure, and
    the claimed allows/denies evaluated on the real bytes."""

    @classmethod
    def setUpClass(cls):
        cls.blob, cls.numbers = _cage_blob()
        cls.arch = gov_sandbox._AUDIT_ARCH[gov_sandbox._ARCH]
        cls.insns = [struct.unpack("HBBI", cls.blob[i:i + 8])
                     for i in range(0, len(cls.blob), 8)]

    def _decide(self, name, args=()):
        return gov_sandbox._bpf_decision(
            self.blob, self.arch, self.numbers[name], args)

    def test_instruction_count_pinned(self):
        # 166 instructions on x86_64 with the current allowlist (160 in
        # wave-59; +6 for the wave-60 F127 ioctl arg-rule block: the nr
        # scan gains 1 JEQ (ioctl was not allowlisted in wave-59), and
        # the arg-check block adds LD arg1 + 2x JEQ (TCGETS, FIOCLEX) +
        # RET EPERM + RET ALLOW = 5 insns; labels are free. 160+6=166,
        # verified by --audit-seccomp-cage.) This is a tripwire, not
        # trivia: any allowlist or builder edit changes the compiled
        # program, and the new count must be reviewed and re-pinned here
        # deliberately.
        self.assertEqual(len(self.insns), 166)

    def test_structure_arch_check_default_allow(self):
        # First instruction loads the arch; the default action sits right
        # after the nr scan; jumps never leave the program and never go
        # backward; only the three builder opcodes appear.
        self.assertEqual(self.insns[0][0], gov_sandbox._BPF_LD_W_ABS)
        self.assertEqual(self.insns[0][3], 4)
        n = len({self.numbers[x] for x in FILTERED_EGRESS_CAGE_ALLOW})
        default = self.insns[4 + n]
        self.assertEqual((default[0], default[3]),
                         (gov_sandbox._BPF_RET_K, _KILL))
        opcodes = {gov_sandbox._BPF_LD_W_ABS, gov_sandbox._BPF_JMP_JEQ_K,
                   gov_sandbox._BPF_RET_K}
        for i, (code, jt, jf, k) in enumerate(self.insns):
            self.assertIn(code, opcodes, "insn %d" % i)
            if code == gov_sandbox._BPF_JMP_JEQ_K:
                self.assertLess(i + 1 + jt, len(self.insns), "insn %d" % i)
                self.assertLess(i + 1 + jf, len(self.insns), "insn %d" % i)
                self.assertGreaterEqual(jt, 0)
                self.assertGreaterEqual(jf, 0)

    def test_allowlisted_names_reach_allow(self):
        for name in FILTERED_EGRESS_CAGE_ALLOW:
            # socket and ioctl are arg-filtered: bare-nr ALLOW is
            # asserted per-shape in the break-first tests below.
            if name in ("socket", "ioctl") or name not in self.numbers:
                continue
            self.assertEqual(self._decide(name), _ALLOW, name)

    def test_wrong_arch_reaches_kill(self):
        other = (gov_sandbox.AUDIT_ARCH_AARCH64
                 if self.arch == gov_sandbox.AUDIT_ARCH_X86_64
                 else gov_sandbox.AUDIT_ARCH_X86_64)
        nr = self.numbers["read"]
        self.assertEqual(
            gov_sandbox._bpf_decision(self.blob, other, nr), _KILL)

    def test_log_staging_action_encodes_ret_log(self):
        blob, _ = _cage_blob(default_action="log")
        insns = [struct.unpack("HBBI", blob[i:i + 8])
                 for i in range(0, len(blob), 8)]
        n = len({self.numbers[x] for x in FILTERED_EGRESS_CAGE_ALLOW})
        default = insns[4 + n]
        self.assertEqual((default[0], default[3]),
                         (gov_sandbox._BPF_RET_K, _LOG))

    def test_bad_default_action_refused(self):
        with self.assertRaises(ValueError):
            gov_sandbox._build_cage_seccomp_filter(
                self.numbers, default_action="permissive")


class SeccompCageBreakFirstTest(unittest.TestCase):
    """Break-first battery against the real BPF bytes.

    Registry: redteam.f81.seccomp_* (wave-59). Each test attacks the
    compiled filter; a failure here is a genuine miss -> harden same-wave
    or file the next finding (F127).
    """

    @classmethod
    def setUpClass(cls):
        cls.blob, cls.numbers = _cage_blob()
        cls.arch = gov_sandbox._AUDIT_ARCH[gov_sandbox._ARCH]
        cls.socket_nr = cls.numbers["socket"]
        cls.ioctl_nr = cls.numbers["ioctl"]

    def _sock(self, domain, stype, proto=0):
        return gov_sandbox._bpf_decision(
            self.blob, self.arch, self.socket_nr, (domain, stype, proto))

    def _ioctl(self, fd, request):
        return gov_sandbox._bpf_decision(
            self.blob, self.arch, self.ioctl_nr, (fd, request, 0))

    def _nr(self, name):
        return gov_sandbox._bpf_decision(
            self.blob, self.arch, self.numbers[name])

    # -- 5.1 AF_PACKET / SOCK_RAW smuggling (errno tier) -----------------

    def test_af_packet_sock_raw_die_with_eperm(self):
        # redteam.f81.seccomp_afpacket_raw_smuggling: L2 sniff/inject
        # dies at the socket() arg filter with EPERM — loud-local, the
        # child sees a normal syscall failure.
        self.assertEqual(
            self._sock(AF_PACKET, SOCK_RAW, 0x0300), _EPERM_RET)
        self.assertEqual(self._sock(AF_PACKET, SOCK_RAW, 0), _EPERM_RET)
        self.assertEqual(self._sock(AF_PACKET, SOCK_DGRAM, 0), _EPERM_RET)

    def test_af_netlink_route_manipulation_dies_with_eperm(self):
        # redteam.f81.seccomp_netlink_route_manipulation: NETLINK_ROUTE
        # manipulation dies at the same arg filter.
        self.assertEqual(
            self._sock(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE), _EPERM_RET)
        self.assertEqual(self._sock(AF_NETLINK, SOCK_DGRAM, 0), _EPERM_RET)

    def test_raw_and_datagram_and_v6_die_with_eperm(self):
        self.assertEqual(self._sock(AF_INET, SOCK_RAW, 6), _EPERM_RET)
        self.assertEqual(self._sock(AF_UNIX, SOCK_RAW, 0), _EPERM_RET)
        self.assertEqual(self._sock(AF_INET, SOCK_DGRAM, 0), _EPERM_RET)
        self.assertEqual(self._sock(AF_INET6, SOCK_STREAM, 0), _EPERM_RET)
        self.assertEqual(self._sock(99, SOCK_STREAM, 0), _EPERM_RET)

    def test_conforming_client_sockets_reach_allow(self):
        self.assertEqual(self._sock(AF_UNIX, SOCK_STREAM, 0), _ALLOW)
        self.assertEqual(self._sock(AF_INET, SOCK_STREAM, 0), _ALLOW)
        self.assertEqual(self._sock(AF_INET, SOCK_STREAM, 6), _ALLOW)
        self.assertEqual(
            self._sock(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0), _ALLOW)
        self.assertEqual(
            self._sock(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0), _ALLOW)
        self.assertEqual(
            self._sock(AF_INET,
                       SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0),
            _ALLOW)

    def test_sctp_protocol_smuggling_dies_with_eperm(self):
        # redteam.f81.seccomp_sctp_protocol_smuggling: wave-59
        # break-first catch from the CVE-2026-64564 intake (SCTPhantom —
        # container escape with default seccomp active; Tencent names
        # "access to raw and packet sockets" and "the seccomp
        # configuration" as exposure factors). SCTP rides SOCK_STREAM
        # with protocol 132, which the draft left unconstrained; the
        # protocol arg rule (0 | IPPROTO_TCP only) kills it with EPERM.
        # Kernel exploits are outside this layer's threat model, so this
        # is defense-in-depth tightening, not a finding — hardened
        # same-wave, no F-number consumed.
        IPPROTO_SCTP, IPPROTO_DCCP = 132, 33
        self.assertEqual(self._sock(AF_INET, SOCK_STREAM, IPPROTO_SCTP),
                         _EPERM_RET)
        self.assertEqual(self._sock(AF_INET, SOCK_STREAM, IPPROTO_DCCP),
                         _EPERM_RET)
        self.assertEqual(self._sock(AF_INET, SOCK_STREAM, 999), _EPERM_RET)

    # -- F127 (wave-60): ioctl arg filter ---------------------------------
    # The wave-59 blanket ioctl denial was an over-denial: the wave-60
    # LOG-tier shake-down (workstreams/evals/log_tier_shakedown.py)
    # replayed strace captures of 10 representative workloads through
    # the exact LOG bytes and found CPython issuing ioctl(TCGETS) ~18x
    # at interpreter startup (stdio isatty probing) plus FIOCLEX — 503
    # logged denials, every one legitimate. Under KILL the first TCGETS
    # SIGSYS-kills the child before user code runs. Fix: ioctl returns
    # as an arg-filtered allow (TCGETS|FIOCLEX), not a blanket allow —
    # the net-device route-manipulation side door the wave-59 removal
    # was aimed at stays shut at the EPERM tier.

    def test_ioctl_legitimate_requests_reach_allow(self):
        # redteam.f81.seccomp_ioctl_arg_filtered: the two requests real
        # workloads need (TCGETS=0x5401 at CPython startup, FIOCLEX=0x5451
        # from libc fd setup) reach ALLOW.
        TCGETS, FIOCLEX = 0x5401, 0x5451
        self.assertEqual(self._ioctl(1, TCGETS), _ALLOW)
        self.assertEqual(self._ioctl(2, TCGETS), _ALLOW)
        self.assertEqual(self._ioctl(3, FIOCLEX), _ALLOW)

    def test_ioctl_misuse_requests_die_with_eperm(self):
        # redteam.f81.seccomp_ioctl_arg_filtered: the shapes the
        # wave-59 removal was protecting against — net-device route
        # manipulation (SIOCSIFADDR/SIOCSIFFLAGS/SIOCADDRT), terminal
        # input injection (TIOCSTI), terminal reprogramming (TCSETS) —
        # die with EPERM (errno tier, loud-local), not ALLOW.
        for request in (0x8916,  # SIOCSIFADDR
                        0x8914,  # SIOCSIFFLAGS
                        0x890B,  # SIOCADDRT
                        0x5412,  # TIOCSTI
                        0x5402,  # TCSETS
                        0x541B,  # FIONREAD (unneeded; stays denied)
                        0xDEAD):  # bogus
            self.assertEqual(self._ioctl(0, request), _EPERM_RET,
                             hex(request))

    def test_ioctl_high_bit_request_truncation_pinned(self):
        # Same truncation semantics as socket(): the filter sees the low
        # 32 bits (TCGETS) and ALLOWs; the kernel validates the full
        # 64-bit request and fails it with ENOTTY. Safe by construction —
        # the filter can only err toward denial, never toward a wider
        # allow. Pinned so a future reader sees the deliberate shape.
        self.assertEqual(self._ioctl(1, 0x5401 | (1 << 32)), _ALLOW)

    # -- 5.2 proxy impersonation: nothing in the cage can listen ---------

    def test_bind_listen_accept_die_with_kill(self):
        # redteam.f81.seccomp_bind_proxy_impersonation: bind/listen/
        # accept* are KILL tier. The child is a pure client; a listening
        # socket would be a rendezvous point for impersonation, so the
        # filter removes the capability entirely rather than policing it.
        for name in ("bind", "listen", "accept", "accept4"):
            nr = self.numbers.get(name)
            if nr is not None:
                self.assertEqual(self._nr(name), _KILL, name)

    # -- 5.5 / 5.6 namespace, privilege, tampering (kill tier) ------------

    def test_escape_and_tampering_syscalls_die_with_kill(self):
        # redteam.f81.seccomp_deny_by_default_unlisted covers getsid;
        # the rest pin the kill tier for the escape/privilege class.
        # NOTE: ioctl is deliberately NOT in this list anymore — wave-60
        # F127: the blanket wave-59 ioctl denial SIGSYS-killed CPython at
        # startup (TCGETS isatty probing). ioctl is now arg-filtered
        # (TCGETS|FIOCLEX -> ALLOW, everything else -> EPERM); see
        # test_ioctl_arg_filtered below.
        for name in ("unshare", "setns", "ptrace", "mount",
                     "pivot_root", "bpf", "keyctl", "add_key",
                     "request_key", "seccomp", "prctl",
                     "process_vm_readv", "process_vm_writev",
                     "perf_event_open", "io_uring_setup", "userfaultfd",
                     "kexec_load", "reboot", "init_module",
                     "open_by_handle_at", "getsid"):
            nr = self.numbers.get(name)
            if nr is not None:
                self.assertEqual(self._nr(name), _KILL, name)

    def test_clone_stays_allowed_documented(self):
        # clone/clone3/vfork are legitimate (threads); namespace games
        # inside clone are neutered by the setns/unshare kill tier above.
        for name in ("clone", "clone3", "vfork"):
            nr = self.numbers.get(name)
            if nr is not None:
                self.assertEqual(self._nr(name), _ALLOW, name)

    # -- 5.7 syscall-variant bypass ---------------------------------------

    def test_no_socketcall_multiplexor_or_x32_alias(self):
        # redteam.f81.seccomp_socketcall_multiplexor_absent: x86_64 has
        # no socketcall number (the legacy multiplexor does not exist on
        # this arch), and x32-aliased numbers (nr | 0x40000000) never
        # match the nr scan — deny-by-default holds across the alias.
        self.assertNotIn("socketcall", self.numbers)
        aliased = gov_sandbox._bpf_decision(
            self.blob, self.arch, self.socket_nr | 0x40000000,
            (AF_INET, SOCK_STREAM, 0))
        self.assertEqual(aliased, _KILL)

    # -- honest boundaries (asserted deliberately, not holes) ------------

    def test_connect_allowed_by_filter_honest_boundary(self):
        # redteam.f81.seccomp_connect_not_filter_confined (expected:
        # flagged): classic BPF cannot dereference the sockaddr pointer,
        # so the filter CANNOT confine connect() destinations — and does
        # not try. Destination confinement is the netns's job (no route
        # -> ENETUNREACH), the proxy's policy, and the upstream firewall.
        # This assertion pins the deliberate shape: a future "clever"
        # connect rule here would be theater.
        self.assertEqual(self._nr("connect"), _ALLOW)

    def test_fd_passing_boundary_pinned(self):
        # 5.3: recvmsg/sendmsg stay nr-ALLOW — fd-passing (SCM_RIGHTS)
        # crosses the trust boundary the cage defines rather than a line
        # the filter draws. The control is fd hygiene (CLOEXEC + minimal
        # inherit; the parent passes no fds), not arg inspection. Pinned
        # so a silent tightening/broadening is visible.
        self.assertEqual(self._nr("recvmsg"), _ALLOW)
        self.assertEqual(self._nr("sendmsg"), _ALLOW)


class SeccompLogTierAbuseTest(unittest.TestCase):
    """Break-first the LOG staging tier machinery itself (wave-60 Lane 1).

    The tier switch (GOV_SANDBOX_SECCOMP_LOG=1) swaps the filter's
    default action from KILL to LOG. SECCOMP_RET_LOG means log-and-
    EXECUTE — the tier is permissive, not merely non-enforcing. These
    tests pin the properties that make the tier safe-as-staging and the
    properties that forbid it as production, all evaluated on the exact
    compiled bytes (no kernel install needed for verdict semantics).

    Registry: redteam.f81.seccomp_log_tier_* (wave-60). No finding: the
    tier behaves as designed; the review is documented in
    workstreams/evals/SECCOMP_LOG_SHAKEDOWN.md.
    """

    @classmethod
    def setUpClass(cls):
        cls.blob_kill, cls.numbers = _cage_blob(default_action="kill")
        cls.blob_log, _ = _cage_blob(default_action="log")
        cls.arch = gov_sandbox._AUDIT_ARCH[gov_sandbox._ARCH]

    def _v(self, blob, name, args=()):
        return gov_sandbox._bpf_decision(
            blob, self.arch, self.numbers[name], args)

    def test_log_tier_is_permissive_not_just_non_enforcing(self):
        # The dangerous misunderstanding: SECCOMP_RET_LOG does not
        # block — the syscall EXECUTES after the audit record. Under
        # LOG staging, escape/privilege shapes run; the wall is down
        # except the errno tier and the non-seccomp layers (netns,
        # rlimits, privdrop). Pinned so nobody mistakes LOG for "safe
        # deny".
        for name in ("unshare", "setns", "prctl", "seccomp", "mount",
                     "bpf", "keyctl", "ptrace"):
            nr = self.numbers.get(name)
            if nr is not None:
                self.assertEqual(self._v(self.blob_log, name), _LOG,
                                 name)
                self.assertEqual(self._v(self.blob_kill, name), _KILL,
                                 name)

    def test_errno_tier_enforced_even_under_log(self):
        # The arg-rule denials are explicit RET_ERRNO|EPERM, not the
        # default action — so the errno tier stays enforced even in
        # LOG staging. Staging is never "everything allowed".
        sock = self.numbers["socket"]
        self.assertEqual(
            self._v(self.blob_log, "socket", (17, 3, 0)), _EPERM_RET)
        self.assertEqual(
            self._v(self.blob_kill, "socket", (17, 3, 0)), _EPERM_RET)
        ioctl = self.numbers["ioctl"]
        self.assertEqual(
            self._v(self.blob_log, "ioctl", (0, 0x8916, 0)), _EPERM_RET)
        self.assertEqual(
            self._v(self.blob_kill, "ioctl", (0, 0x8916, 0)), _EPERM_RET)

    def test_no_new_child_visible_oracle_from_log(self):
        # The errno tier is child-visible (EPERM) under BOTH tiers, so
        # LOG staging hands the cage no new oracle for the arg rules.
        # (Survival-probing can distinguish allowlisted vs defaulted
        # syscalls under LOG, but the allowlist ships in source — it is
        # not a secret — so no exfiltration channel is created. The
        # kernel audit log itself is host-side; the child cannot read
        # it.)
        sock = self.numbers["socket"]
        for args in ((17, 3, 0), (2, 2, 0), (2, 1, 132)):
            self.assertEqual(self._v(self.blob_log, "socket", args),
                             self._v(self.blob_kill, "socket", args),
                             args)

    def test_allowlist_identical_across_tiers(self):
        # The tier switch changes ONLY the default action: every
        # allowlisted shape (nr-only and arg-filtered) reaches ALLOW
        # under both blobs. A tier switch that silently widened the
        # allowlist would be a laundering primitive; it does not.
        for name in FILTERED_EGRESS_CAGE_ALLOW:
            if name in ("socket", "ioctl") or name not in self.numbers:
                continue
            self.assertEqual(self._v(self.blob_log, name), _ALLOW, name)
            self.assertEqual(self._v(self.blob_kill, name), _ALLOW, name)
        sock = self.numbers["socket"]
        self.assertEqual(self._v(self.blob_log, "socket", (2, 1, 0)),
                         _ALLOW)
        ioctl = self.numbers["ioctl"]
        self.assertEqual(self._v(self.blob_log, "ioctl", (0, 0x5401, 0)),
                         _ALLOW)


class SeccompCageModeSelectionTest(unittest.TestCase):
    """Mode selection is explicit; misconfiguration fails closed.

    Registry: redteam.f81.seccomp_unknown_mode_fails_closed."""

    def test_unknown_mode_refuses_loudly(self):
        with self.assertRaises(ValueError):
            Sandbox(cage_mode="permissive")
        with self.assertRaises(ValueError):
            Sandbox(cage_mode="")

    def test_cage_mode_requires_seccomp(self):
        with self.assertRaises(ValueError):
            Sandbox(cage_mode="filtered-egress")  # use_seccomp=False

    def test_mode_stored_and_default_strict(self):
        self.assertEqual(
            Sandbox(use_seccomp=True,
                    cage_mode="filtered-egress").cage_mode,
            "filtered-egress")
        self.assertEqual(Sandbox().cage_mode, "strict")
        self.assertEqual(Sandbox(use_seccomp=True).cage_mode, "strict")

    def test_env_unknown_mode_refuses(self):
        saved = dict(os.environ)
        try:
            os.environ["GOV_SANDBOX_BACKEND"] = "1"
            os.environ["GOV_SANDBOX_CAGE_MODE"] = "permissive"
            with self.assertRaises(SandboxError):
                sandbox_config_from_env()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_env_cage_without_seccomp_refuses(self):
        saved = dict(os.environ)
        try:
            os.environ["GOV_SANDBOX_BACKEND"] = "1"
            os.environ["GOV_SANDBOX_CAGE_MODE"] = "filtered-egress"
            # GOV_SANDBOX_SECCOMP deliberately unset: misconfiguration.
            os.environ.pop("GOV_SANDBOX_SECCOMP", None)
            with self.assertRaises(SandboxError):
                sandbox_config_from_env()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_env_default_is_strict(self):
        saved = dict(os.environ)
        try:
            os.environ["GOV_SANDBOX_BACKEND"] = "1"
            os.environ.pop("GOV_SANDBOX_CAGE_MODE", None)
            cfg = sandbox_config_from_env()
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["cage_mode"], "strict")
        finally:
            os.environ.clear()
            os.environ.update(saved)

    @unittest.skipUnless(SECCOMP, "seccomp filter installation refused")
    def test_env_cage_mode_selects_profile(self):
        saved = dict(os.environ)
        try:
            os.environ["GOV_SANDBOX_BACKEND"] = "1"
            os.environ["GOV_SANDBOX_SECCOMP"] = "1"
            os.environ["GOV_SANDBOX_CAGE_MODE"] = "filtered-egress"
            cfg = sandbox_config_from_env()
            self.assertEqual(cfg["cage_mode"], "filtered-egress")
            self.assertTrue(cfg["use_seccomp"])
            self.assertTrue(cfg["require_seccomp"])
        finally:
            os.environ.clear()
            os.environ.update(saved)


class SeccompCageAssemblerTest(unittest.TestCase):
    """Unit tests for the label assembler the arg-aware builder uses."""

    def test_label_jump_resolution(self):
        blob = gov_sandbox._bpf_assemble([
            (gov_sandbox._BPF_LD_W_ABS, 0, 0, 0),  # A <- nr
            (gov_sandbox._BPF_JMP_JEQ_K, "hit", 0, 7),
            (gov_sandbox._BPF_RET_K, 0, 0, _KILL),
            "hit",
            (gov_sandbox._BPF_RET_K, 0, 0, _ALLOW),
        ])
        self.assertEqual(len(blob), 4 * 8)
        arch = gov_sandbox._AUDIT_ARCH[gov_sandbox._ARCH]
        self.assertEqual(
            gov_sandbox._bpf_decision(blob, arch, 7), _ALLOW)
        self.assertEqual(
            gov_sandbox._bpf_decision(blob, arch, 8), _KILL)

    def test_duplicate_and_unknown_labels_refused(self):
        with self.assertRaises(SandboxError):
            gov_sandbox._bpf_assemble(["x", "x"])
        with self.assertRaises(SandboxError):
            gov_sandbox._bpf_assemble(
                [(gov_sandbox._BPF_JMP_JEQ_K, "nope", 0, 1)])

    def test_arg_rule_validation(self):
        numbers = gov_sandbox._syscall_numbers()
        if not numbers:
            raise unittest.SkipTest("no syscall numbers on this arch")
        nr = numbers["socket"]
        with self.assertRaises(ValueError):
            gov_sandbox._build_seccomp_filter_args(
                {nr}, {nr: [(6, frozenset({1}), _EPERM_RET)]})
        with self.assertRaises(ValueError):
            gov_sandbox._build_seccomp_filter_args(
                {nr}, {nr: [(0, frozenset(), _EPERM_RET)]})
        with self.assertRaises(ValueError):
            gov_sandbox._build_seccomp_filter_args(
                {nr}, {}, default_action="permissive")


@unittest.skipUnless(SECCOMP, "seccomp filter installation refused by kernel")
class SeccompCageLiveTest(unittest.TestCase):
    """Live installation probes. Skipped in this environment
    (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) -> EINVAL here); they run
    in a privileged CI where seccomp is appliable. They are the
    filter-load verification lane: bytes are proven above, loading here."""

    def _install_in_child(self, code):
        """Fork; child installs the cage filter, runs `code`, _exit(0)."""
        pid = os.fork()
        if pid == 0:  # child
            try:
                gov_sandbox._install_cage_seccomp_filter()
                ns = {}
                exec(compile(code, "<probe>", "exec"), ns)
            except BaseException as e:  # noqa: BLE001 - report, then die
                os.write(2, ("PROBE-ERROR %r\n" % (e,)).encode())
                os._exit(99)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        return status

    def test_errno_tier_live_eperm_not_death(self):
        # socket(AF_PACKET, SOCK_RAW) must fail with EPERM *in the child*
        # while the child itself survives — the loud-local errno tier.
        status = self._install_in_child(
            "import socket, errno, os\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.close()\n"
            "try:\n"
            "    socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)\n"
            "except OSError as e:\n"
            "    assert e.errno == errno.EPERM, e.errno\n"
            "else:\n"
            "    raise AssertionError('AF_PACKET not denied')\n")
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_kill_tier_live_sigsys(self):
        # An unlisted syscall (getsid) must kill the child with SIGSYS.
        status = self._install_in_child(
            "import ctypes\n"
            "ctypes.CDLL('libc.so.6', use_errno=True).getsid(0)\n")
        self.assertTrue(os.WIFSIGNALED(status))
        import signal
        self.assertEqual(os.WTERMSIG(status), signal.SIGSYS)

    def test_sandbox_cage_mode_end_to_end(self):
        import signal as _signal
        s = Sandbox(timeout=10, use_seccomp=True, require_seccomp=True,
                    cage_mode="filtered-egress")
        r = s.run_python(
            "import socket, errno\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.close()\n"
            "try:\n"
            "    socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)\n"
            "except OSError as e:\n"
            "    print('EPERM' if e.errno == errno.EPERM else 'WRONG')\n"
            "else:\n"
            "    print('NOT-DENIED')\n")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.seccomp_active)
        self.assertIn("EPERM", r.stdout)
        # Kill tier through the launcher: the SIGSYS death is stamped on
        # the run note (audit story tier 2), never silent.
        r2 = s.run_python(
            "import ctypes\n"
            "ctypes.CDLL('libc.so.6', use_errno=True).getsid(0)\n")
        self.assertEqual(r2.returncode, -_signal.SIGSYS)
        self.assertIn("SIGSYS", r2.note)


from unittest import mock


class SeccompLogGuardTest(unittest.TestCase):
    """Break-first the wave-61 LOG-tier production guard.

    The guard (_resolve_seccomp_tier, single chokepoint at run() top)
    stops GOV_SANDBOX_SECCOMP_LOG=1 from silently dissolving KILL
    default-deny into log-and-execute in production. These tests attack
    the guard itself: env-var attacks, config confusion, downgrade
    laundering, and TOCTOU between tier decision and filter install.

    Design: workstreams/evals/SECCOMP_LOG_SHAKEDOWN.md §6.
    Registry: redteam.f81.seccomp_log_guard_* (wave-61).
    """

    def _run_true(self, **kwargs):
        s = Sandbox(timeout=10, use_netns=False, use_pidns=False,
                    **kwargs)
        return s.run([sys.executable, "-c", "pass"])

    # -- decision table (the config-guard analog of byte-pinning) --------

    def test_decision_table_exhaustive(self):
        r = gov_sandbox._resolve_seccomp_tier
        self.assertEqual(r("production", False), "kill")
        # production + LOG request refuses (SandboxError) — pinned in
        # test_production_log_refuses_loudly_before_launch, not here.
        self.assertEqual(r("staging", False), "kill")
        self.assertEqual(r("staging", True), "log")
        # Default deployment mode is production (least privilege).
        self.assertEqual(Sandbox(timeout=5).deployment_mode, "production")

    def test_production_log_refuses_loudly_before_launch(self):
        # The core seam: LOG requested in production must refuse, not
        # downgrade, and must never spawn the child.
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            s = Sandbox(timeout=10, use_netns=False, use_pidns=False)
            with mock.patch("subprocess.Popen",
                            side_effect=AssertionError("child launched")):
                with self.assertRaises(SandboxError) as ctx:
                    s.run([sys.executable, "-c", "pass"])
        msg = str(ctx.exception)
        self.assertIn("GOV_SANDBOX_SECCOMP_LOG", msg)
        self.assertIn("production", msg)

    def test_production_log_refusal_even_without_seccomp(self):
        # The invariant is unconditional: a production LOG request is a
        # misconfiguration worth surfacing even when this particular run
        # would not install seccomp.
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            with self.assertRaises(SandboxError):
                self._run_true(use_seccomp=False)

    def _recording_installer(self):
        # The seccomp installer runs in the forked preexec child, so a
        # plain in-memory list never reaches the parent: record
        # default_action values to a temp file the parent reads back.
        import tempfile
        log_path = os.path.join(tempfile.mkdtemp(prefix="gov-guard-"),
                                "installs.txt")
        open(log_path, "w").close()

        def _install(cage_mode, *, default_action="kill"):
            with open(log_path, "a") as f:
                f.write(default_action + "\n")

        def _read():
            with open(log_path) as f:
                return [ln.strip() for ln in f if ln.strip()]
        return _install, _read

    def test_staging_log_allowed_and_stamped(self):
        # Legitimate staging use is unbroken: LOG allowed, stamped.
        install, read_installs = self._recording_installer()
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            with mock.patch.object(gov_sandbox,
                                   "_install_seccomp_filter_for_mode",
                                   side_effect=install):
                r = self._run_true(use_seccomp=True,
                                   deployment_mode="staging")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.seccomp_active)
        self.assertIn("LOG staging mode", r.note)
        installs = read_installs()
        self.assertTrue(installs, "installer was never attempted")
        self.assertTrue(all(a == "log" for a in installs), installs)

    def test_staging_without_log_is_kill(self):
        # No downgrade by default, even in staging.
        install, read_installs = self._recording_installer()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GOV_SANDBOX_SECCOMP_LOG", None)
            with mock.patch.object(gov_sandbox,
                                   "_install_seccomp_filter_for_mode",
                                   side_effect=install):
                r = self._run_true(use_seccomp=True,
                                   deployment_mode="staging")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertTrue(r.seccomp_active)
        self.assertNotIn("LOG staging mode", r.note)
        installs = read_installs()
        self.assertTrue(installs, "installer was never attempted")
        self.assertTrue(all(a == "kill" for a in installs), installs)

    # -- env-var attacks --------------------------------------------------

    def test_log_env_strictness_garbage_is_not_a_request(self):
        # _env_flag is strict: only exact "1" (post-strip) requests LOG.
        # Garbage/unicode in production must NOT refuse (nothing
        # requested) and must resolve to KILL. (NUL bytes cannot exist
        # in os.environ at all — and _child_env refuses them — so no
        # NUL case is settable here.)
        for garbage in ["", "0", "true", "yes", "on", "  ",
                        "１",  # fullwidth digit one (U+FF11)
                        " true"]:
            with mock.patch.dict(os.environ,
                                 {"GOV_SANDBOX_SECCOMP_LOG": garbage}):
                req = gov_sandbox._env_flag("GOV_SANDBOX_SECCOMP_LOG")
                self.assertFalse(req, repr(garbage))
                self.assertEqual(
                    gov_sandbox._resolve_seccomp_tier("production", req),
                    "kill")
        # ...but " 1 " (stripped) IS a request -> refused in production.
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": " 1 "}):
            self.assertTrue(gov_sandbox._env_flag("GOV_SANDBOX_SECCOMP_LOG"))
            with self.assertRaises(SandboxError):
                self._run_true()

    def test_child_cannot_see_tier_var(self):
        # Defense in depth: the tier decision is parent-side pre-fork,
        # and the var never reaches the child's environment at all.
        self.assertNotIn("GOV_SANDBOX_SECCOMP_LOG",
                         gov_sandbox.DEFAULT_ALLOWED_ENV)

    # -- config confusion -------------------------------------------------

    def test_unknown_deployment_mode_refuses(self):
        with self.assertRaises(ValueError):
            Sandbox(timeout=5, deployment_mode="prod")
        with self.assertRaises(ValueError):
            gov_sandbox._resolve_seccomp_tier("prod", False)
        with self.assertRaises(ValueError):
            gov_sandbox._resolve_seccomp_tier("", True)

    def test_explicit_kwarg_beats_env(self):
        # Authority order: constructor kwarg > env. Explicit operator
        # code declaring staging is honored even when the env disagrees.
        with mock.patch.dict(os.environ, {
                "GOV_SANDBOX_DEPLOYMENT_MODE": "production",
                "GOV_SANDBOX_SECCOMP_LOG": "1"}):
            r = self._run_true(deployment_mode="staging")
        self.assertTrue(r.ok, r.stderr[-500:])

    def test_config_from_env_deployment_mode(self):
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_BACKEND": "1",
                              "GOV_SANDBOX_DEPLOYMENT_MODE": "staging"}):
            cfg = sandbox_config_from_env()
        self.assertEqual(cfg["deployment_mode"], "staging")
        with mock.patch.dict(os.environ, {"GOV_SANDBOX_BACKEND": "1"}):
            os.environ.pop("GOV_SANDBOX_DEPLOYMENT_MODE", None)
            cfg = sandbox_config_from_env()
        self.assertEqual(cfg["deployment_mode"], "production")
        # Garbage env mode flows to the constructor, which refuses
        # fail-closed (never silently "no guard").
        with mock.patch.dict(os.environ, {
                "GOV_SANDBOX_BACKEND": "1",
                "GOV_SANDBOX_DEPLOYMENT_MODE": "prod"}):
            cfg = sandbox_config_from_env()
        with self.assertRaises(ValueError):
            Sandbox(**cfg)

    # -- TOCTOU: exactly one tier read per run -----------------------------

    def test_tier_env_read_exactly_once_per_run(self):
        # The decision/install TOCTOU is structurally closed: run()
        # resolves the tier once and passes it as a value; _make_preexec
        # and the run note never re-read the environment for the tier.
        reads = []
        real_flag = gov_sandbox._env_flag

        def counting(name):
            if name == "GOV_SANDBOX_SECCOMP_LOG":
                reads.append(name)
            return real_flag(name)

        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            with mock.patch.object(gov_sandbox, "_env_flag",
                                   side_effect=counting):
                r = self._run_true(deployment_mode="staging")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertEqual(reads, ["GOV_SANDBOX_SECCOMP_LOG"],
                         "tier env var must be read exactly once per run")

    def test_make_preexec_rejects_unresolved_tier(self):
        # Internal misuse guard: _make_preexec takes the resolved tier
        # as a value; anything outside {"kill","log"} refuses loudly.
        s = Sandbox(timeout=5)
        with self.assertRaises(SandboxError):
            s._make_preexec(["/bin/true"], {}, 0, "/tmp", "bogus")

    # -- downgrade laundering ----------------------------------------------

    def test_kill_install_failure_never_falls_back_to_log(self):
        # The laundering shape: an exception during the KILL-tier
        # install must never retry with default_action="log" (a
        # fallback would be fail-open). Honest outcome is the
        # established fallback note with seccomp unestablished.
        # (Recording goes through a temp file: the installer runs in
        # the forked preexec child.)
        install, read_installs = self._recording_installer()

        def failing_install(cage_mode, *, default_action="kill"):
            install(cage_mode, default_action=default_action)
            raise OSError("simulated install failure")

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GOV_SANDBOX_SECCOMP_LOG", None)
            with mock.patch.object(gov_sandbox,
                                   "_install_seccomp_filter_for_mode",
                                   side_effect=failing_install):
                r = self._run_true(use_seccomp=True,
                                   deployment_mode="staging")
        self.assertTrue(r.ok, r.stderr[-500:])
        self.assertFalse(r.seccomp_active)
        installs = read_installs()
        self.assertTrue(installs, "installer was never attempted")
        self.assertTrue(all(a == "kill" for a in installs),
                        "no install attempt may use the LOG tier: %r"
                        % (installs,))
        self.assertIn("seccomp", r.note)


class RefusalLoudnessTest(unittest.TestCase):
    """Wave-62 Lane 1: refusal loudness break-first.

    The wave-61 guard's only refusal channel was the SandboxError
    exception — a caller that swallows it and proceeds anyway left zero
    trace (0 stderr bytes, no receipt; proven by
    workstreams/evals/refusal_loudness_harness.py baseline). These tests
    pin the two surviving channels: the unconditional stderr refusal
    record and the opt-in structured JSONL receipt, both emitted BEFORE
    the exception is raised, both fail-safe (a broken sink never masks
    the refusal).

    Registry: redteam.f81.refusal_loudness_* (wave-62), finding F81.
    """

    def _guard_sandbox(self, **kwargs):
        return Sandbox(timeout=10, use_netns=False, use_pidns=False,
                       **kwargs)

    def _swallow_guard_refusal(self, sb):
        """Swallowing caller: catches the refusal and 'proceeds anyway'."""
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            try:
                sb.run([sys.executable, "-c", "pass"])
            except SandboxError:
                return "proceeded-anyway"
            return "no-refusal"

    def test_swallowed_refusal_leaves_stderr_record(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            outcome = self._swallow_guard_refusal(self._guard_sandbox())
        self.assertEqual(outcome, "proceeded-anyway")
        err = buf.getvalue()
        self.assertIn("GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]", err)
        self.assertIn("GOV_SANDBOX_SECCOMP_LOG=1", err)
        self.assertIn("pid=", err)

    def test_refusal_still_raises_with_same_message(self):
        # Loudness never replaces the exception: the contract is
        # exception + stderr + receipt.
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            with mock.patch.dict(os.environ,
                                 {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
                with self.assertRaises(SandboxError) as ctx:
                    self._guard_sandbox().run(
                        [sys.executable, "-c", "pass"])
        self.assertIn("GOV_SANDBOX_SECCOMP_LOG", str(ctx.exception))

    def test_receipt_written_to_kwarg_dir(self):
        sink = tempfile.mkdtemp(prefix="gov-refusal-")
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            self._swallow_guard_refusal(
                self._guard_sandbox(refusal_receipt_dir=sink))
        rec = os.path.join(sink, "refusals.jsonl")
        self.assertTrue(os.path.exists(rec), "no receipt written")
        with open(rec, encoding="utf-8") as fh:
            obj = json.loads(fh.read().strip())
        self.assertEqual(obj["kind"], "seccomp-log-tier-guard")
        self.assertEqual(obj["deployment_mode"], "production")
        self.assertIn("GOV_SANDBOX_SECCOMP_LOG=1", obj["message"])
        self.assertIn("ts", obj)
        self.assertEqual(obj["pid"], os.getpid())

    def test_receipt_env_dir_used_when_no_kwarg(self):
        sink = tempfile.mkdtemp(prefix="gov-refusal-env-")
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_REFUSAL_DIR": sink}):
            self.assertEqual(
                self._guard_sandbox().refusal_receipt_dir, sink)
            self._swallow_guard_refusal(self._guard_sandbox())
        self.assertTrue(os.path.exists(
            os.path.join(sink, "refusals.jsonl")))

    def test_kwarg_receipt_dir_wins_over_env(self):
        env_sink = tempfile.mkdtemp(prefix="gov-refusal-env-")
        kw_sink = tempfile.mkdtemp(prefix="gov-refusal-kw-")
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_REFUSAL_DIR": env_sink}):
            sb = self._guard_sandbox(refusal_receipt_dir=kw_sink)
            self.assertEqual(sb.refusal_receipt_dir, kw_sink)
            self._swallow_guard_refusal(sb)
        self.assertTrue(os.path.exists(
            os.path.join(kw_sink, "refusals.jsonl")))
        self.assertFalse(os.path.exists(
            os.path.join(env_sink, "refusals.jsonl")))

    def test_broken_receipt_sink_still_refuses(self):
        # The sink path exists as a file: makedirs fails. Fail-safe —
        # the refusal must still raise, never be masked.
        sink = tempfile.mkdtemp(prefix="gov-refusal-broken-")
        not_a_dir = os.path.join(sink, "not-a-dir")
        open(not_a_dir, "w").write("x")
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            outcome = self._swallow_guard_refusal(
                self._guard_sandbox(refusal_receipt_dir=not_a_dir))
        self.assertEqual(outcome, "proceeded-anyway",
                         "broken sink masked the refusal")
        self.assertIn("GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]",
                      buf.getvalue())

    def test_broken_stderr_still_refuses(self):
        class _Broken:
            def write(self, *a):
                raise OSError("stderr gone")
            def flush(self):
                raise OSError("stderr gone")
        with mock.patch.object(sys, "stderr", _Broken()):
            with mock.patch.dict(os.environ,
                                 {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
                with self.assertRaises(SandboxError):
                    self._guard_sandbox().run(
                        [sys.executable, "-c", "pass"])

    def test_no_receipt_without_sink(self):
        cwd = tempfile.mkdtemp(prefix="gov-refusal-cwd-")
        old = os.getcwd()
        os.chdir(cwd)
        try:
            buf = io.StringIO()
            with mock.patch.object(sys, "stderr", buf):
                self._swallow_guard_refusal(self._guard_sandbox())
        finally:
            os.chdir(old)
        self.assertEqual(os.listdir(cwd), [],
                         "refusal wrote files with no sink configured")
        self.assertIn("GOV-SANDBOX REFUSAL", buf.getvalue())

    def test_canary_refusal_is_loud(self):
        # The loudness contract covers every fail-closed refusal from
        # run(), not just the LOG-tier guard.
        def _boom(jail, env):
            raise RuntimeError("synthetic plant failure")
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GOV_SANDBOX_SECCOMP_LOG", None)
            with mock.patch.object(sys, "stderr", buf):
                with self.assertRaises(SandboxError) as ctx:
                    self._guard_sandbox(canary_plant=_boom).run(
                        [sys.executable, "-c", "pass"])
        self.assertIn("canary planting failed", str(ctx.exception))
        self.assertIn("GOV-SANDBOX REFUSAL [canary-plant-failure]",
                      buf.getvalue())

    def test_legitimate_retry_after_refusal(self):
        # NOT fail-deadly: catch-and-remediate with an explicit staging
        # declaration proceeds normally — the refusal poisons nothing.
        sink = tempfile.mkdtemp(prefix="gov-refusal-retry-")
        with mock.patch.dict(os.environ,
                             {"GOV_SANDBOX_SECCOMP_LOG": "1"}):
            sb = self._guard_sandbox(refusal_receipt_dir=sink)
            with self.assertRaises(SandboxError):
                sb.run([sys.executable, "-c", "pass"])
            r = Sandbox(timeout=10, use_netns=False, use_pidns=False,
                        deployment_mode="staging",
                        refusal_receipt_dir=sink).run(
                            [sys.executable, "-c", "pass"])
        self.assertTrue(r.ok, r.note)


if __name__ == "__main__":
    unittest.main()
