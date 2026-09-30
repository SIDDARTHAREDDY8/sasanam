"""Named, versioned jail policies for tool-call sandboxes.

Design input (ADAPT, not vendored): gVisor's runsc jail-policy taxonomy --
``--platform={systrap|kvm|ptrace}``, ``--network={none|host|sandbox}``,
``--no-new-privs``, read-only rootfs mounts plus explicit read-write
mounts, and timeout budgets -- plus the ``examples/sandboxexec/python``
recipe (Apache-2.0): untrusted Python/shell with network default ``none``,
read-only rootfs + exactly one read-write ``/output`` mount,
``--timeout`` (default 5s), an empty capability set, and
``NoNewPrivileges: true``. gVisor itself is NOT adopted here (no KVM, no
vendored gVisor source; KVM adoption remains WATCH per prospecting): this
module re-expresses the taxonomy and the recipe shape in our own words as
a *policy* over our existing stdlib sandbox backend (``gov/sandbox.py``).

Schema discipline ADAPTed from Firecracker's ``firecracker.yaml`` config
surface (wave-215 prospecting): defaults-vs-explicit whole-update
semantics (every field of a policy body is explicit; unknown fields are
refused, never ignored), machine-readable error codes on every refusal,
and graceful versioning (a v2 schema adds fields; it never silently
redefines v1 fields). gVisor is Apache-2.0 (convergent attestation per
wave-214 prospecting); no gVisor lines are vendored here.

What this module provides, stdlib-only:

* A **jail policy** as explicit data: ``policy_name``, ``version``,
  ``platform``, ``rootfs_mode`` (``"ro"``), ``writable_dirs`` (the
  explicit rw mounts -- the sandboxexec recipe has exactly ``/output``),
  ``network`` (``"none"`` only in v1), ``no_new_privs``, a
  ``syscall_profile`` name from a closed vocabulary, ``timeout_s``, and
  ``resource_limits`` (``cpu_s``, ``mem_bytes``, ``max_file_bytes``,
  ``max_fds``, ``max_procs``). The policy is signed (Ed25519) by the
  **policy-issuer keyset, pinned out-of-band** -- a policy document never
  carries a usable signing key, so self-signed policies verify False
  against the pinned key by construction.
* :class:`JailPolicyRegistry`: the activation point. Policies activate
  per (policy_name, version). Activation verifies the signature, the
  strict shape, and a monotonic version floor -- activating an older
  version than one already activated for the same name is a refusal (no
  silent downgrade). An already-expired policy cannot activate (stale at
  birth).
* :class:`JailPolicyRegistry.check`: an **audit-visible invocation
  conformance check**. The caller declares the jail's actual invocation
  (``writable_dirs``, ``wants_network``, ``timeout_s``); the check
  refuses loudly when the invocation escapes the policy -- a writable
  dir outside the declared mounts (path-traversal attempts included), a
  network request under a ``network: none`` policy, or a timeout beyond
  the policy budget. Refusals are loud ``JailPolicyError`` codes, never
  silent widenings; a conforming invocation returns an audit-visible
  report carrying the policy digest. The check re-verifies the policy
  signature and the validity window at every use, so a policy swapped
  or edited after activation fails the re-check.
* :func:`check_backend`: the **syscall-coverage-gap discipline**. The
  declared platform/features of a policy are mapped against what
  ``gov/sandbox.py`` actually implements on this machine; any gap is
  NAMED (e.g. ``"kvm"``, ``"network-sandbox"``, a syscall profile the
  backend does not have) and the invocation fails closed -- never a
  silent degrade to a weaker jail.
* :func:`to_sandbox_kwargs`: the tighten-only opt-in wiring. It maps an
  activated policy to the exact keyword arguments of
  ``gov.sandbox.Sandbox(...)`` -- ``require_*`` fail-closed twins ON
  (a sporadic setup failure can never be mislabeled as jailed), the
  seccomp ``strict`` profile, and the policy's timeout and resource
  budgets. Existing ``gov/sandbox.py`` behavior is untouched; nothing
  changes unless the caller explicitly routes a policy through this
  function.

Honest boundaries (stated, not absorbed):

* gVisor does NOT defend against resource exhaustion (its own docs defer
  to cgroups); our deterministic budget ownership lives in the
  ``resource_limits`` mapping onto ``gov/sandbox.py``'s RLIMIT_* layer.
  This module claims no new containment boundary -- it names and pins
  the policy over the boundary ``gov/sandbox.py`` already provides.
* A policy describes a jail; it does not prove the jail ran. The
  audit-visible report records the check, not the execution.
* ``syscall_profile`` in v1 has a closed vocabulary of one
  (``"python-minimal"``), mapped to the backend's default seccomp
  allowlist. Finer profiles need backend allowlist work -- an unknown
  profile is a named gap, not a guess.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import json
import os
import posixpath
import re
import time

from . import ed25519 as _ed

__all__ = [
    "JAIL_POLICY_FORMAT",
    "JAIL_POLICY_SIGN_DOMAIN",
    "SYSCALL_PROFILES",
    "JailPolicyError",
    "canonical_policy_json",
    "policy_signing_bytes",
    "make_policy_body",
    "validate_policy_body",
    "sign_policy",
    "policy_digest",
    "check_backend",
    "backend_features",
    "check_invocation",
    "invocation_report",
    "to_sandbox_kwargs",
    "JailPolicyRegistry",
]

#: Format tag of the policy document (exact match at verify).
JAIL_POLICY_FORMAT = "sasanam-jail-policy/v1"

#: Domain separation for policy signatures.
JAIL_POLICY_SIGN_DOMAIN = b"sasanam-jail-policy-sign/v1:"

_POLICY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")

#: v1 closed vocabulary: platform the policy was authored for.
_PLATFORMS = ("systrap",)
#: v1 closed vocabulary: network posture. Only "none" is supported by
#: the backend; "host"/"sandbox" are gVisor taxonomy words the backend
#: does not implement (see check_backend gaps).
_NETWORKS = ("none",)
#: v1 closed vocabulary: rootfs mode.
_ROOTFS_MODES = ("ro",)
#: v1 closed vocabulary: syscall profiles. One profile today: the
#: backend's default seccomp-bpf allowlist as exercised by the tool
#: workload. A finer profile set needs backend allowlist work first.
SYSCALL_PROFILES = ("python-minimal",)

_TIMEOUT_MIN, _TIMEOUT_MAX = 1, 3600
_CPU_MIN, _CPU_MAX = 1, 3600
_MEM_MIN, _MEM_MAX = 1 << 20, 16 << 30       # 1 MiB .. 16 GiB
_FDS_MIN, _FDS_MAX = 8, 4096
_PROCS_MIN, _PROCS_MAX = 1, 1024

_LIMIT_KEYS = ("cpu_s", "mem_bytes", "max_file_bytes", "max_fds",
               "max_procs")


class JailPolicyError(Exception):
    """Fail-closed jail-policy violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(JailPolicyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def canonical_policy_json(body):
    """Canonical bytes of a policy body (sorted keys, no whitespace,
    ASCII). Signatures cover exactly these bytes."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def policy_signing_bytes(body):
    """Bytes the issuer signs: domain || sha256(canonical(body))."""
    digest = hashlib.sha256(canonical_policy_json(body)).hexdigest()
    return JAIL_POLICY_SIGN_DOMAIN + digest.encode("ascii")


def _check_int(value, lo, hi, where):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not (lo <= value <= hi):
        raise JailPolicyError(
            "policy-body-malformed",
            "%s must be an int in [%d, %d]" % (where, lo, hi))


def _normalize_jail_path(path, where):
    """Normalize an absolute jail path. Refuses non-absolute paths and
    rejects nothing else by construction: normpath collapses
    ``..``/``.``/``//`` so a traversal attempt normalizes to its real
    location (``/output/../etc`` -> ``/etc``), which the conformance
    check then compares against the declared mounts."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise JailPolicyError(
            "policy-body-malformed",
            "%s must be an absolute jail path" % (where,))
    norm = posixpath.normpath(path)
    if norm == "/":
        raise JailPolicyError(
            "policy-body-malformed",
            "%s must not be the jail root itself" % (where,))
    return norm


def validate_policy_body(body):
    """Strict shape check of a policy body dict. Whole-update
    discipline: every field is explicit, unknown fields are refused
    (never silently ignored). Returns a normalized body (paths
    normalized, ready for signature). Raises JailPolicyError."""
    if not isinstance(body, dict):
        raise JailPolicyError("policy-body-malformed", "body is not a dict")
    expected = {"format", "policy_name", "version", "platform",
                "rootfs_mode", "writable_dirs", "network", "no_new_privs",
                "syscall_profile", "timeout_s", "resource_limits",
                "capabilities", "not_before", "not_after"}
    unknown = sorted(set(body) - expected)
    if unknown:
        raise JailPolicyError(
            "policy-body-malformed",
            "unknown fields %s (whole-update discipline: refusing)" % (
                unknown,))
    missing = sorted(expected - set(body))
    if missing:
        raise JailPolicyError(
            "policy-body-malformed", "missing fields %s" % (missing,))
    if body["format"] != JAIL_POLICY_FORMAT:
        raise JailPolicyError(
            "policy-body-malformed",
            "format must be %r" % (JAIL_POLICY_FORMAT,))
    name = body["policy_name"]
    if not isinstance(name, str) or not _POLICY_NAME_RE.match(name):
        raise JailPolicyError(
            "policy-body-malformed",
            "policy_name must match %s" % (_POLICY_NAME_RE.pattern,))
    _check_int(body["version"], 1, 2 ** 31 - 1, "version")
    if body["platform"] not in _PLATFORMS:
        raise JailPolicyError(
            "policy-body-malformed",
            "platform %r unsupported in v1 (closed vocabulary: %s)"
            % (body["platform"], list(_PLATFORMS)))
    if body["rootfs_mode"] not in _ROOTFS_MODES:
        raise JailPolicyError(
            "policy-body-malformed",
            "rootfs_mode %r unsupported in v1" % (body["rootfs_mode"],))
    dirs = body["writable_dirs"]
    if not isinstance(dirs, list) or not dirs:
        raise JailPolicyError(
            "policy-body-malformed",
            "writable_dirs must be a non-empty list "
            "(the recipe needs at least one rw mount)")
    norm_dirs = [_normalize_jail_path(d, "writable_dirs[%d]" % i)
                 for i, d in enumerate(dirs)]
    if len(set(norm_dirs)) != len(norm_dirs):
        raise JailPolicyError(
            "policy-body-malformed", "writable_dirs must not repeat")
    if body["network"] not in _NETWORKS:
        raise JailPolicyError(
            "policy-body-malformed",
            "network %r unsupported in v1 (closed vocabulary: %s)"
            % (body["network"], list(_NETWORKS)))
    if body["no_new_privs"] is not True:
        raise JailPolicyError(
            "policy-body-malformed",
            "no_new_privs must be true in v1")
    if body["syscall_profile"] not in SYSCALL_PROFILES:
        raise JailPolicyError(
            "policy-body-malformed",
            "syscall_profile %r unknown (closed vocabulary: %s)"
            % (body["syscall_profile"], list(SYSCALL_PROFILES)))
    _check_int(body["timeout_s"], _TIMEOUT_MIN, _TIMEOUT_MAX, "timeout_s")
    limits = body["resource_limits"]
    if not isinstance(limits, dict):
        raise JailPolicyError(
            "policy-body-malformed", "resource_limits is not a dict")
    if sorted(limits) != sorted(_LIMIT_KEYS):
        raise JailPolicyError(
            "policy-body-malformed",
            "resource_limits must be exactly %s" % (list(_LIMIT_KEYS),))
    _check_int(limits["cpu_s"], _CPU_MIN, _CPU_MAX, "resource_limits.cpu_s")
    _check_int(limits["mem_bytes"], _MEM_MIN, _MEM_MAX,
               "resource_limits.mem_bytes")
    _check_int(limits["max_file_bytes"], 0, _MEM_MAX,
               "resource_limits.max_file_bytes")
    _check_int(limits["max_fds"], _FDS_MIN, _FDS_MAX,
               "resource_limits.max_fds")
    _check_int(limits["max_procs"], _PROCS_MIN, _PROCS_MAX,
               "resource_limits.max_procs")
    if body["capabilities"] != []:
        raise JailPolicyError(
            "policy-body-malformed",
            "capabilities must be [] in v1 (the recipe grants none)")
    for which in ("not_before", "not_after"):
        if not isinstance(body[which], int) or isinstance(body[which], bool):
            raise JailPolicyError(
                "policy-body-malformed", "%s must be epoch seconds (int)"
                % (which,))
    if body["not_before"] >= body["not_after"]:
        raise JailPolicyError(
            "policy-body-malformed",
            "not_before must be < not_after")
    norm = dict(body)
    norm["writable_dirs"] = norm_dirs
    return norm


def make_policy_body(policy_name, version, *, writable_dirs,
                     syscall_profile="python-minimal", timeout_s=5,
                     resource_limits=None, not_before=0,
                     not_after=2 ** 31 - 1):
    """Build a policy body for the sandboxexec/python recipe shape:
    ro rootfs, explicit rw mounts, network none, no_new_privs,
    empty capability set."""
    return {
        "format": JAIL_POLICY_FORMAT,
        "policy_name": policy_name,
        "version": version,
        "platform": "systrap",
        "rootfs_mode": "ro",
        "writable_dirs": list(writable_dirs),
        "network": "none",
        "no_new_privs": True,
        "syscall_profile": syscall_profile,
        "timeout_s": timeout_s,
        "resource_limits": dict(resource_limits or {
            "cpu_s": 10,
            "mem_bytes": 256 << 20,
            "max_file_bytes": 16 << 20,
            "max_fds": 64,
            "max_procs": 64,
        }),
        "capabilities": [],
        "not_before": not_before,
        "not_after": not_after,
    }


def sign_policy(seed, body):
    """Ed25519-sign a (validated) policy body with the issuer seed.

    Returns the 64-byte signature over the normalized body's signing
    bytes. The normalized body (not the caller's raw dict) is what
    the signature covers."""
    norm = validate_policy_body(body)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise JailPolicyError("signer-error", "seed must be 32 bytes")
    return _ed.sign(bytes(seed), policy_signing_bytes(norm))


def policy_digest(body):
    """sha256 hex of the canonical normalized policy body -- the pin
    every audit-visible report carries."""
    norm = validate_policy_body(body)
    return hashlib.sha256(canonical_policy_json(norm)).hexdigest()


# ---------------------------------------------------------------------------
# Backend capability mapping: the syscall-coverage-gap discipline.
#
# A policy declares a platform and features; this mapping names what
# gov/sandbox.py actually implements. Anything the policy needs that the
# backend lacks is a named gap and fails closed -- never a silent
# degrade to a weaker jail.
# ---------------------------------------------------------------------------

def backend_features():
    """Feature tokens this machine's gov/sandbox backend implements,
    probed honestly (each probe forks a child; the parent is
    untouched). The sandbox always enforces timeouts and RLIMIT_*;
    namespace/pivot/seccomp/privdrop layers are probed per call."""
    from . import sandbox as _sandbox
    features = {"timeout", "rlimit"}
    if _sandbox.netns_available():
        features.add("netns")
    if _sandbox.pidns_available():
        features.add("pidns")
    if _sandbox.pivot_available():
        features.add("pivot_root")
    if _sandbox.seccomp_available():
        features.add("seccomp")
    if _sandbox.privdrop_available():
        features.add("privdrop")
    return features


def _policy_needs(body):
    """Feature tokens a validated policy body needs from the backend."""
    needs = {"timeout", "rlimit", "pivot_root", "seccomp", "privdrop",
             "pidns"}
    if body["network"] == "none":
        needs.add("netns")
    return needs


def check_backend(body, features=None):
    """Fail closed with a NAMED gap when the backend cannot implement
    the policy. Returns the needed feature set when satisfied. The gap
    name is the missing feature token (e.g. "kvm" is refused earlier
    at validate time as an unknown platform; here the gaps are
    per-machine: "netns", "pivot_root", "seccomp", "privdrop",
    "pidns")."""
    norm = validate_policy_body(body)
    have = set(features) if features is not None else backend_features()
    needs = _policy_needs(norm)
    missing = sorted(needs - have)
    if missing:
        raise JailPolicyError(
            "policy-needs-unimplemented-feature",
            "backend lacks %s for policy %r v%d; refusing instead of "
            "degrading the jail" % (
                missing, norm["policy_name"], norm["version"]))
    return sorted(needs)


# ---------------------------------------------------------------------------
# Invocation conformance: the audit-visible check that a jail
# invocation matches its declared policy.
# ---------------------------------------------------------------------------

_CHECK_NAMES = ("writable-dirs", "network-posture", "timeout-budget")


def _under_or_equal(candidate, declared):
    return candidate == declared or candidate.startswith(declared + "/")


def check_invocation(body, request):
    """Fail-closed conformance of one jail invocation against the
    policy. ``request`` is the declared invocation::

        {"writable_dirs": ["/output", ...],
         "wants_network": False,
         "timeout_s": 5}

    Whole-update discipline: unknown request fields are refused, never
    ignored. Every mismatch raises JailPolicyError with a
    machine-readable code -- never a silent widening:

    * ``invocation-writable-dir-mismatch`` -- a requested writable dir
      is not the declared mount or under it. ``/output/../etc``
      normalizes to ``/etc`` and is caught here.
    * ``invocation-network-request-refused`` -- network requested under
      a ``network: none`` policy.
    * ``invocation-timeout-exceeds-policy`` -- the request's timeout
      exceeds the policy budget (a shorter timeout is always allowed).

    On success returns the audit-visible report dict."""
    norm = validate_policy_body(body)
    if not isinstance(request, dict):
        raise JailPolicyError("invocation-malformed", "request is not a dict")
    expected = {"writable_dirs", "wants_network", "timeout_s"}
    unknown = sorted(set(request) - expected)
    if unknown:
        raise JailPolicyError(
            "invocation-malformed",
            "unknown request fields %s (refusing)" % (unknown,))
    missing = sorted(expected - set(request))
    if missing:
        raise JailPolicyError(
            "invocation-malformed", "missing request fields %s" % (missing,))
    req_dirs = request["writable_dirs"]
    if not isinstance(req_dirs, list):
        raise JailPolicyError(
            "invocation-malformed", "writable_dirs must be a list")
    for rd in req_dirs:
        rcand = _normalize_jail_path(rd, "request.writable_dirs")
        if not any(_under_or_equal(rcand, dd)
                   for dd in norm["writable_dirs"]):
            raise JailPolicyError(
                "invocation-writable-dir-mismatch",
                "%r is outside the declared mounts %s"
                % (rd, norm["writable_dirs"]))
    wants = request["wants_network"]
    if not isinstance(wants, bool):
        raise JailPolicyError(
            "invocation-malformed", "wants_network must be a bool")
    if wants and norm["network"] == "none":
        raise JailPolicyError(
            "invocation-network-request-refused",
            "network requested under a network:none policy")
    rt = request["timeout_s"]
    if not isinstance(rt, int) or isinstance(rt, bool) or rt < 1:
        raise JailPolicyError(
            "invocation-malformed", "timeout_s must be a positive int")
    if rt > norm["timeout_s"]:
        raise JailPolicyError(
            "invocation-timeout-exceeds-policy",
            "requested %ds exceeds policy budget %ds"
            % (rt, norm["timeout_s"]))
    return invocation_report(norm, list(_CHECK_NAMES))


def invocation_report(norm_body, checked):
    """The audit-visible conformance report: policy identity, the
    digest pin, and the checks that ran."""
    return {
        "conforms": True,
        "policy_name": norm_body["policy_name"],
        "version": norm_body["version"],
        "policy_digest": policy_digest(norm_body),
        "checked": sorted(checked),
    }


# ---------------------------------------------------------------------------
# Tighten-only opt-in wiring onto gov/sandbox.Sandbox.
# ---------------------------------------------------------------------------

def to_sandbox_kwargs(body, host_mounts):
    """Map an activated policy to ``gov.sandbox.Sandbox(...)`` keyword
    arguments. Tighten-only opt-in: this function changes nothing by
    itself; the caller passes its return value to the Sandbox
    constructor explicitly.

    ``host_mounts`` maps each jail-absolute writable dir to the host
    directory staged at the jail path (pivot_extra_mounts semantics):
    ``{"/output": "/var/tmp/g-out"}``. A declared mount with no host
    mapping raises -- an unwired mount would otherwise silently leave
    the jail path unwritable (fail closed, not fail confusing).

    The mapping turns on every ``require_*`` fail-closed twin: a
    sporadic setup failure aborts before exec instead of running
    unjailed. ``cage_mode="strict"`` (the socket family stays absent
    from the seccomp filter) implements ``network: none`` at the
    syscall layer in addition to the netns.

    Mapping notes (honest):
    * ``no_new_privs`` is realized as ``use_seccomp=True``: the filter
      is installed after PR_SET_NO_NEW_PRIVS. ``drop_privs=True``
      realizes the unprivileged worker the recipe wants.
    * ``syscall_profile "python-minimal"`` maps to the backend's
      default seccomp allowlist; finer profiles need backend work.
    * Resource-exhaustion defense is the RLIMIT_* layer (cpu_s,
      mem_bytes, max_file_bytes, max_fds, max_procs) -- the same seam
      gVisor defers to cgroups. No stronger claim is made.
    """
    norm = validate_policy_body(body)
    if not isinstance(host_mounts, dict):
        raise JailPolicyError("wiring-malformed", "host_mounts is not a dict")
    guest_mounts = {}
    for jail_dir in norm["writable_dirs"]:
        host = host_mounts.get(jail_dir)
        if not isinstance(host, str) or not os.path.isabs(host):
            raise JailPolicyError(
                "wiring-unmapped-mount",
                "declared mount %r has no absolute host mapping "
                "(refusing an unwired jail)" % (jail_dir,))
        guest_mounts[host] = jail_dir.lstrip("/")
    limits = norm["resource_limits"]
    return {
        "timeout": norm["timeout_s"],
        "memory_bytes": limits["mem_bytes"],
        "cpu_seconds": limits["cpu_s"],
        "max_file_bytes": limits["max_file_bytes"],
        "max_fds": limits["max_fds"],
        "max_procs": limits["max_procs"],
        "use_netns": True,
        "require_netns": True,
        "use_pidns": True,
        "require_pidns": True,
        "use_pivot_root": True,
        "require_pivot_root": True,
        "drop_privs": True,
        "require_privdrop": True,
        "use_seccomp": True,
        "require_seccomp": True,
        "cage_mode": "strict",
        "pivot_extra_mounts": guest_mounts,
    }


# ---------------------------------------------------------------------------
# Registry: named, versioned activation with a pinned issuer key.
# ---------------------------------------------------------------------------

class JailPolicyRegistry:
    """Activation point for jail policies.

    ``issuer_public_key`` is the PINNED 32-byte Ed25519 policy-issuer
    key (out-of-band pinning is the deployment's job). Activation
    verifies the signature, the strict shape, the backend's ability to
    implement the policy (named gaps fail closed), and a monotonic
    version floor. :meth:`check` binds (name, version) explicitly --
    there is no "latest" and no implicit upgrade; the signature and
    the validity window are re-checked at every use."""

    def __init__(self, issuer_public_key):
        if not isinstance(issuer_public_key, (bytes, bytearray)) \
                or len(issuer_public_key) != 32:
            raise JailPolicyError(
                "registry-malformed",
                "issuer_public_key must be a 32-byte Ed25519 public key")
        self._issuer = bytes(issuer_public_key)
        self._active = {}   # (name, version) -> (normalized body, signature)
        self._floor = {}    # name -> highest activated version

    def _signature_ok(self, body, signature):
        if not isinstance(signature, (bytes, bytearray)) \
                or len(signature) != 64:
            return False
        return bool(_ed.verify(self._issuer, policy_signing_bytes(body),
                               bytes(signature)))

    def activate(self, signed, *, now=None, features=None):
        """Activate a signed policy envelope
        ``{"body": <body dict>, "signature": <64 bytes>}``.

        Fail-closed (JailPolicyError) on: malformed envelope, bad
        shape, bad signature (self-signed verifies False against the
        pinned issuer by construction), version at or below the floor
        for this name (no silent downgrade), a policy already expired
        at ``now`` (stale at birth), or a backend coverage gap (named).
        Returns the normalized body."""
        if not isinstance(signed, dict):
            raise JailPolicyError(
                "policy-envelope-malformed", "envelope is not a dict")
        if sorted(signed) != ["body", "signature"]:
            raise JailPolicyError(
                "policy-envelope-malformed",
                "envelope must be exactly {body, signature}")
        body = validate_policy_body(signed["body"])
        signature = signed["signature"]
        if not self._signature_ok(body, signature):
            raise JailPolicyError(
                "policy-signature-invalid",
                "policy %r v%d is not signed by the pinned issuer"
                % (body["policy_name"], body["version"]))
        floor = self._floor.get(body["policy_name"], 0)
        if body["version"] <= floor:
            raise JailPolicyError(
                "policy-version-downgrade",
                "version %d <= activated floor %d for %r"
                % (body["version"], floor, body["policy_name"]))
        epoch = int(time.time()) if now is None else now
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise JailPolicyError("registry-malformed", "now must be int")
        if not (body["not_before"] <= epoch < body["not_after"]):
            raise JailPolicyError(
                "policy-stale",
                "policy %r v%d not valid at %d"
                % (body["policy_name"], body["version"], epoch))
        check_backend(body, features=features)
        self._active[(body["policy_name"], body["version"])] = (
            body, bytes(signature))
        self._floor[body["policy_name"]] = body["version"]
        return body

    def get(self, policy_name, version, *, now=None):
        """Return the activated body for (name, version), re-checking
        the signature and the validity window (a policy swapped or
        edited after activation fails the re-check)."""
        entry = self._active.get((policy_name, version))
        if entry is None:
            raise JailPolicyError(
                "policy-unknown",
                "no activated policy %r v%s" % (policy_name, version))
        body, signature = entry
        if not self._signature_ok(body, signature):
            raise JailPolicyError(
                "policy-signature-invalid",
                "stored policy %r v%d failed signature re-check"
                % (policy_name, version))
        epoch = int(time.time()) if now is None else now
        if not (body["not_before"] <= epoch < body["not_after"]):
            raise JailPolicyError(
                "policy-stale",
                "policy %r v%d not valid at %d"
                % (policy_name, version, epoch))
        return body

    def check(self, policy_name, version, request, *, now=None):
        """The invocation conformance check through the registry:
        explicit (name, version) binding, signature + window re-check,
        then :func:`check_invocation`. Returns the audit-visible
        report on success, raises JailPolicyError otherwise."""
        body = self.get(policy_name, version, now=now)
        return check_invocation(body, request)
