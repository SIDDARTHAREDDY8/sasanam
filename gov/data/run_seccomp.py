#!/usr/bin/env python3
"""VENDORED ARTIFACT — do not import.

Seccomp launcher for the agent namespace, vendored byte-for-byte from
the F81 lab evidence (~/workspace/f81-lab-evidence/run_seccomp.py,
lab run 4, 2026-09-23). Installs a filter then execs argv[1:].
Denies: AF_PACKET sockets, SOCK_RAW sockets, unshare()/clone() with
CLONE_NEWNET, setns() entirely. Everything else allowed. Violations
-> EPERM (fail closed).

This file is DATA, not code: it is never imported by gov/. A
deployment copies it into the wall conf dir at install time and its
bytes are digest-pinned as the ``seccomp_helper`` wall component
(gov/egress_launcher.py WALL_COMPONENTS). A tampered helper is a
launch refusal (``component_tampered``), not a silent downgrade.

Requires python3-seccomp on the wall host at launch time (the helper
exits FATAL/2 without it — fail closed, never unfiltered).
"""
import os, sys

try:
    from seccomp import SyscallFilter, Arg, ALLOW, ERRNO, EQ, MASKED_EQ
except ImportError:
    print("FATAL: python3-seccomp not installed", file=sys.stderr)
    sys.exit(2)

DENY = ERRNO(1)  # this python-seccomp has no DENY const; ERRNO(1) == EPERM

AF_PACKET = 17
CLONE_NEWNET = 0x40000000

def main():
    if len(sys.argv) < 2:
        print("usage: run_seccomp.py <cmd> [args...]", file=sys.stderr)
        sys.exit(2)
    f = SyscallFilter(defaction=ALLOW)
    f.add_rule(DENY, "socket", Arg(0, EQ, AF_PACKET))            # AF_PACKET
    f.add_rule(DENY, "socket", Arg(1, MASKED_EQ, 0xF, 3))        # SOCK_RAW
    f.add_rule(DENY, "unshare", Arg(0, MASKED_EQ, CLONE_NEWNET, CLONE_NEWNET))
    f.add_rule(DENY, "clone", Arg(0, MASKED_EQ, CLONE_NEWNET, CLONE_NEWNET))
    f.add_rule(DENY, "clone3", Arg(0, MASKED_EQ, CLONE_NEWNET, CLONE_NEWNET))
    f.add_rule(DENY, "setns")                                    # no ns joining, ever
    f.load()
    os.execvp(sys.argv[1], sys.argv[1:])

if __name__ == "__main__":
    main()
