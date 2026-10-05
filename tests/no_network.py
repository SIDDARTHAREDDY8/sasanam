"""Wave-339 (R19): DNS hermeticity guard for the unit-test suite.

STEAL of Bernstein #6010 ("unit tests block DNS"): the unit-test harness
blocks DNS resolution so no test can phone home -- by accident, by
leftover debug code, or by a test that "helpfully" resolves a hostname
to reach a fixture server.

:func:`install` replaces the DNS-resolution primitives in :mod:`socket`
(``getaddrinfo``, ``getnameinfo``, ``gethostbyname``,
``gethostbyname_ex``) with a fail-closed stub raising
:class:`DNSBlockedError` (an :class:`OSError`), EXCEPT when the call
originates from one of the network-machinery test modules listed in
:const:`EXEMPT_FILES` (matched by absolute path via stack inspection).
Those modules test the network boundary itself (sandbox egress walls,
capability rules, the Vault urllib transport against loopback) and are
the only files allowed to touch name resolution.

Wired in by ``tests/run_tests.py`` (the canonical runner) after the F75
supply-chain preflight and before test discovery, so every test module
runs under the guard. A new test file that resolves DNS fails LOUD with
``DNSBlockedError`` naming the blocked call and the offending test file
-- never green, never silent.

Tests that need a local server must bind/connect to the literal
``127.0.0.1`` (no name resolution), never the ``localhost`` hostname.
"""

import inspect
import ipaddress
import os
import socket

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

#: Test modules that exercise the network boundary itself. Every entry
#: is a basename in tests/; the match is by absolute path so a
#: same-named file elsewhere is NOT exempt.
EXEMPT_FILES = frozenset({
    # Sandbox egress walls: the tests ARE the network boundary (they
    # prove sandboxed code cannot reach the network).
    "test_sandbox.py",
    "test_sandbox_f81.py",
    "test_sandbox_hardened.py",
    # Capability rules: the tests assert which syscalls agents may use.
    "test_capability_rules.py",
    "test_f110_platform_egress.py",
})


class DNSBlockedError(OSError):
    """Raised when a non-exempt test module attempts DNS resolution."""


_BLOCKED_NAMES = ("getaddrinfo", "getnameinfo", "gethostbyname",
                  "gethostbyname_ex")

_originals = {}
_installed = False


def _caller_test_file():
    """Absolute path of the outermost tests/*.py frame on the stack, or
    None. The guard exempts by test FILE, not by product module: product
    code under test inherits the calling test's exemption status."""
    for frame_info in inspect.stack(0):
        filename = os.path.abspath(frame_info.filename)
        if (os.path.dirname(filename) == _TESTS_DIR
                and os.path.basename(filename).startswith("test_")):
            return filename
    return None


def _is_exempt():
    caller = _caller_test_file()
    return (caller is not None
            and os.path.basename(caller) in EXEMPT_FILES)


def _is_numeric_host(host):
    """True when *host* is a numeric IPv4/IPv6 literal.

    ``getaddrinfo("127.0.0.1", ...)`` never touches DNS -- it is pure
    address parsing (``http.client`` and ``create_connection`` route even
    literal loopback addresses through ``getaddrinfo``). Blocking those
    would forbid the hermetic loopback fixtures the guard itself
    recommends, so numeric literals pass through. A literal is not a
    name: no resolution, no DNS query, no rebinding surface.
    """
    if not isinstance(host, str):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _passes_through(name, args, kwargs):
    """True when the blocked call cannot perform name resolution."""
    if name == "getaddrinfo":
        # getaddrinfo(host, port, ...): numeric host => no DNS.
        host = args[0] if args else kwargs.get("host")
        return _is_numeric_host(host)
    if name in ("gethostbyname", "gethostbyname_ex"):
        name_arg = args[0] if args else kwargs.get("name")
        return _is_numeric_host(name_arg)
    if name == "getnameinfo":
        # getnameinfo(sockaddr, flags): reverse DNS is skipped only with
        # NI_NUMERICHOST; default flags may query the resolver.
        flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
        return bool(flags & socket.NI_NUMERICHOST)
    return False


def _blocked_factory(name, original):
    def _blocked(*args, **kwargs):
        # Fast path first: numeric literals never resolve, so they skip
        # the (expensive) stack walk entirely.
        if _passes_through(name, args, kwargs) or _is_exempt():
            return original(*args, **kwargs)
        caller = _caller_test_file()
        raise DNSBlockedError(
            "[R19 hermeticity] socket.%s%s blocked: unit tests must not "
            "resolve DNS (offending test file: %s). Bind/connect to the "
            "literal 127.0.0.1 instead of a hostname, or -- "
            "if this file tests the network boundary itself -- add it to "
            "tests/no_network.py EXEMPT_FILES with a written reason."
            % (name,
               "(%r)" % (args[0],) if args else "()",
               caller or "<outside tests/>"))
    _blocked.__name__ = "blocked_%s" % name
    return _blocked


def install():
    """Install the DNS block. Idempotent. Returns the list of patched
    socket attribute names."""
    global _installed
    if _installed:
        return list(_BLOCKED_NAMES)
    for name in _BLOCKED_NAMES:
        original = getattr(socket, name, None)
        if original is None:
            continue
        _originals[name] = original
        setattr(socket, name, _blocked_factory(name, original))
    _installed = True
    return list(_originals)


def uninstall():
    """Restore the original socket primitives (for the guard's own
    tests)."""
    global _installed
    for name, original in _originals.items():
        setattr(socket, name, original)
    _originals.clear()
    _installed = False


def is_installed():
    return _installed
