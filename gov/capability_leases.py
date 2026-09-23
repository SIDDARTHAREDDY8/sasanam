"""Capability leases: kill ambient authority (wave-78, supply-chain enforcement).

The Plugin4Shell amplifier: coding agents inherit the *developer's*
permissions (source, cloud credentials, SSH keys) — a compromised
plugin gets the developer's reach (Moltbook CVE-2026-0755 is the
blast-radius illustration). The public playbook now converges on the
same answer (intake-wave78): the agent never holds raw credentials; it
holds short-lived, scoped capabilities minted per task at the execution
boundary.

A **lease** is the only credential-shaped authority the agent holds:

* minted per task by the deployment's registration-authority key
  (``DelegationTrust.authority_keys``), operator-side only;
* bound to (agent_id, task_id), scoped to tools/resources, short TTL
  (default 900 s, hard cap 3600 s — beyond an hour is standing
  privilege, not a lease);
* verified **at use time, on every privileged call** — signature,
  roster, time window, revocation, task binding, scope — with
  fail-closed named refusals;
* revocable via ``delegation_tokens.RevocationLedger`` (the wave-74
  seam); TTL is the primary revocation mechanism, the ledger the
  emergency brake (the wave-74 TTL honesty note, restated: short TTLs
  paper over revocation; true propagation to offline verifiers is a
  stated boundary).

Lease vs delegation token (kept SEPARATE by construction):
``gov/delegation_tokens.py`` answers "on whose behalf" (human ->
agent, possibly chained). A lease answers "with what credential-shaped
authority, for this task, right now". Conflating them would let a
delegation's broad scope smuggle standing credentials — so leases are
a distinct token kind with their own minting authority, TTL policy,
and verification entry point, reusing only the roster/crypto/
revocation machinery.

Ambient-credential absence (two halves):
1. *Constructive*: ``LeaseAuthority`` (the private minting key) is
   never installed on the agent side. The agent-side ``LeaseVerifier``
   holds only public keys. A probe asserts no private-key bytes exist
   in the verifier's object graph.
2. *Assertive*: :func:`assert_agent_scope_clean` scans the
   agent-reachable scope (env + declared paths) with the F111 DLP
   production-credential rules at session open — any
   production-shaped credential material fails the session open
   closed. Leases carry no secrets, so they never trip the scan.

Expiry mid-task: there is no grace execution. The call that lands
after expiry is refused (``lease_expired``); the task halts until the
operator authority mints a fresh lease. The agent may *request*
re-mint; it may not mint (auto-minting is the standing-privilege shape
with extra steps).

$0 spend, synthetic/local deterministic only. No credentials, no
network. Tests use ``generate_test_keypair()`` as the authority
stand-in, labeled as such.
"""

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from . import dlp as _dlp
from .credential_manifest import PRODUCTION_CREDENTIAL_RULES
from .delegation_tokens import (DelegationTrust, RevocationLedger,
                                generate_test_keypair)
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

__all__ = [
    "LeaseError",
    "LeaseRefused",
    "LeaseExpiredError",
    "LeaseScopeError",
    "LeaseSignatureError",
    "LeaseBindingError",
    "AmbientCredentialError",
    "LEASE_VERSION",
    "DEFAULT_LEASE_TTL_S",
    "MAX_LEASE_TTL_S",
    "CLOCK_SKEW_S",
    "LeaseAuthority",
    "LeaseVerifier",
    "lease_ref",
    "assert_agent_scope_clean",
]


class LeaseError(Exception):
    """Base: anything wrong with a capability lease fails closed."""


class LeaseRefused(LeaseError):
    """A lease was refused at use time. ``reason`` is a machine-readable
    code: ``lease_missing``, ``bad_signature``, ``unknown_issuer``,
    ``lease_expired``, ``lease_not_yet_valid``, ``lease_revoked``,
    ``binding_mismatch``, ``scope_denied``, ``malformed_lease``."""


class LeaseExpiredError(LeaseRefused):
    """The lease's time window has passed (no grace execution)."""


class LeaseScopeError(LeaseRefused):
    """The action is outside the lease's granted scope."""


class LeaseSignatureError(LeaseRefused):
    """Signature invalid or issuer not in the roster."""


class LeaseBindingError(LeaseRefused):
    """Lease presented for a different agent or task (replay/theft)."""


class AmbientCredentialError(LeaseError):
    """Production-shaped credential material found in the agent's
    reachable scope — the session refuses to open."""


LEASE_VERSION = 1
# Default TTL: 15 minutes (the JIT-credential grounding from intake).
DEFAULT_LEASE_TTL_S = 900
# Hard cap: beyond an hour is a standing privilege, not a lease.
MAX_LEASE_TTL_S = 3600
# Clock-skew acceptance, each direction (matches delegation_tokens).
CLOCK_SKEW_S = 300

_LEASE_DOMAIN = b"gov-capability-lease/v1\x00"


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_time(value, what):
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise LeaseRefused("malformed_lease: bad %s %r" % (what, value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _canonical_body(lease):
    """Canonical bytes covered by the minting signature."""
    body = {
        "v": lease["v"],
        "lease_id": lease["lease_id"],
        "issuer_key_id": lease["issuer_key_id"],
        "agent_id": lease["agent_id"],
        "task_id": lease["task_id"],
        "scope": lease["scope"],
        "not_before": lease["not_before"],
        "expires_at": lease["expires_at"],
    }
    return _LEASE_DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def lease_ref(lease):
    """Stable reference for the revocation ledger."""
    return "lease:%s" % lease["lease_id"]


def _check_scope(scope):
    if not isinstance(scope, dict):
        raise LeaseRefused("malformed_lease: scope must be a dict")
    tools = scope.get("tools", [])
    if not isinstance(tools, list) or not tools or not all(
            isinstance(t, str) and t for t in tools):
        raise LeaseRefused("malformed_lease: scope.tools must be a "
                           "non-empty list of strings")
    resources = scope.get("resources", {})
    if not isinstance(resources, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in resources.items()):
        raise LeaseRefused("malformed_lease: scope.resources must be a "
                           "dict of str->str")
    return {"tools": list(tools), "resources": dict(resources)}


def _scope_allows(scope, tool, resource=None):
    tools = scope["tools"]
    if "tool:*" not in tools and ("tool:" + tool) not in tools:
        return False
    if resource is not None:
        allowed = scope["resources"].get(tool)
        if allowed is None or allowed != resource:
            return False
    return True


# ---------------------------------------------------------------------------
# Minting (operator side only).
# ---------------------------------------------------------------------------

class LeaseAuthority:
    """Mints capability leases. Holds the PRIVATE minting key — this
    object is never installed on the agent side (the constructive half
    of the ambient-credential absence mechanism).

    ``key_id`` must be registered in ``trust.authority_keys`` (the
    deployment's registration-authority roster)."""

    def __init__(self, seed, key_id, trust):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise TypeError("seed must be 32 bytes")
        if not isinstance(trust, DelegationTrust):
            raise TypeError("trust must be a DelegationTrust")
        if key_id not in trust.authority_keys:
            raise LeaseError(
                "minting key %r is not in the authority roster" % (key_id,))
        self._seed = bytes(seed)
        self._key_id = key_id
        self._trust = trust

    @property
    def key_id(self):
        return self._key_id

    def mint(self, agent_id, task_id, scope, *, ttl_s=DEFAULT_LEASE_TTL_S,
             agent_capabilities=None, now=None):
        """Mint a lease for (*agent_id*, *task_id*) with *scope*.

        ``agent_capabilities`` (optional): the agent's registered tool
        list — the lease scope must be a subset (a lease cannot grant
        what the agent was never registered for). ``ttl_s`` is clamped
        to ``MAX_LEASE_TTL_S``; non-positive TTLs are refused."""
        if not agent_id or not isinstance(agent_id, str):
            raise LeaseError("mint: bad agent_id")
        if not task_id or not isinstance(task_id, str):
            raise LeaseError("mint: bad task_id")
        scope = _check_scope(scope)
        if not isinstance(ttl_s, (int, float)) or ttl_s <= 0:
            raise LeaseError("mint: ttl_s must be positive")
        if ttl_s > MAX_LEASE_TTL_S:
            raise LeaseError(
                "mint: ttl_s %s exceeds the %ss lease cap (standing "
                "privilege, not a lease)" % (ttl_s, MAX_LEASE_TTL_S))
        if agent_capabilities is not None:
            caps = set(agent_capabilities)
            for t in scope["tools"]:
                if t != "tool:*" and t not in caps and "tool:*" not in caps:
                    raise LeaseError(
                        "mint: scope entry %r exceeds the agent's "
                        "registered capabilities" % (t,))
        now_dt = (now if isinstance(now, datetime)
                  else datetime.now(timezone.utc))
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        lease = {
            "v": LEASE_VERSION,
            "lease_id": secrets.token_hex(16),
            "issuer_key_id": self._key_id,
            "agent_id": agent_id,
            "task_id": task_id,
            "scope": scope,
            "not_before": _iso(now_dt),
            "expires_at": _iso(now_dt + timedelta(seconds=ttl_s)),
        }
        lease["signature"] = _ed_sign(self._seed,
                                      _canonical_body(lease)).hex()
        return lease


# ---------------------------------------------------------------------------
# Verification at use time (agent side; public keys only).
# ---------------------------------------------------------------------------

class LeaseVerifier:
    """Verifies leases at use time. Holds ONLY public keys (the roster)
    — no private key material exists in this object's graph."""

    def __init__(self, trust, revocation_ledger=None):
        if not isinstance(trust, DelegationTrust):
            raise TypeError("trust must be a DelegationTrust")
        self._trust = trust
        self._revoked = (revocation_ledger if revocation_ledger is not None
                         else RevocationLedger())

    def require(self, lease, *, agent_id, task_id, tool, resource=None,
                now=None):
        """Verify *lease* covers (*agent_id*, *task_id*, *tool*) now.

        Every privileged tool call goes through here. Returns the
        ``lease_id`` on success; raises a :class:`LeaseRefused`
        subclass otherwise. Checks, in order: presence -> shape ->
        signature/roster -> time window -> revocation -> binding ->
        scope."""
        if not isinstance(lease, dict):
            raise LeaseRefused("lease_missing: no lease presented")
        for field in ("v", "lease_id", "issuer_key_id", "agent_id",
                      "task_id", "scope", "not_before", "expires_at",
                      "signature"):
            if field not in lease:
                raise LeaseRefused(
                    "malformed_lease: missing field %r" % (field,))
        if lease["v"] != LEASE_VERSION:
            raise LeaseRefused(
                "malformed_lease: unsupported version %r" % (lease["v"],))
        # Signature before anything attacker-influenced is trusted.
        pub = self._trust.authority_keys.get(lease["issuer_key_id"])
        if pub is None:
            raise LeaseSignatureError(
                "unknown_issuer: %r not in the authority roster"
                % (lease.get("issuer_key_id"),))
        try:
            sig = bytes.fromhex(lease["signature"])
        except (TypeError, ValueError):
            raise LeaseSignatureError("bad_signature: malformed")
        try:
            body = _canonical_body(lease)
        except Exception:
            raise LeaseRefused("malformed_lease: bad scope shape")
        if not _ed_verify(pub, body, sig):
            raise LeaseSignatureError("bad_signature: minting signature "
                                      "invalid")
        # Time window (with skew).
        now_dt = (now if isinstance(now, datetime)
                  else datetime.now(timezone.utc))
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        nb = _parse_time(lease["not_before"], "not_before")
        exp = _parse_time(lease["expires_at"], "expires_at")
        skew = timedelta(seconds=CLOCK_SKEW_S)
        if now_dt < nb - skew:
            raise LeaseRefused(
                "lease_not_yet_valid: now < not_before")
        if now_dt > exp + skew:
            raise LeaseExpiredError(
                "lease_expired: the lease window has passed; no grace "
                "execution — request a fresh lease from the authority")
        # Revocation (fails future authorizations loud).
        if self._revoked.is_revoked(lease_ref(lease)):
            raise LeaseRefused("lease_revoked: lease is revoked")
        # Binding: the lease cannot be replayed for another agent/task.
        if lease["agent_id"] != agent_id or lease["task_id"] != task_id:
            raise LeaseBindingError(
                "binding_mismatch: lease is bound to (%r, %r), presented "
                "for (%r, %r)" % (lease["agent_id"], lease["task_id"],
                                  agent_id, task_id))
        # Scope.
        try:
            scope = _check_scope(lease["scope"])
        except LeaseRefused:
            raise LeaseRefused("malformed_lease: bad scope shape")
        if not _scope_allows(scope, tool, resource):
            raise LeaseScopeError(
                "scope_denied: tool %r%s not in lease scope" %
                (tool, " resource %r" % (resource,)
                 if resource is not None else ""))
        return lease["lease_id"]


# ---------------------------------------------------------------------------
# Ambient-credential absence: the assertive half.
# ---------------------------------------------------------------------------

_PRODUCTION_RES = [
    rx for rule_id, rx in _dlp._CREDENTIAL_RULES
    if rule_id in PRODUCTION_CREDENTIAL_RULES
]


def assert_agent_scope_clean(env=None, paths=(), *, _read=None):
    """Fail the session open when production-shaped credential material
    is reachable from the agent.

    ``env``: mapping of env var name -> value (the agent's environment).
    ``paths``: file paths in the agent-reachable scope (read via
    ``_read`` or plain file read). Any hit from the F111
    production-credential DLP rules raises :class:`AmbientCredentialError`.
    Leases carry no secrets and never trip this scan."""
    findings = []
    for name, value in (env or {}).items():
        text = str(value or "")
        for rx in _PRODUCTION_RES:
            if rx.search(text):
                findings.append("env %r: production-shaped credential "
                                "material" % (name,))
                break
    read = _read or (lambda p: open(p, "r", encoding="utf-8",
                                    errors="replace").read())
    for p in paths:
        try:
            text = read(p)
        except OSError:
            continue
        for rx in _PRODUCTION_RES:
            if rx.search(text):
                findings.append("path %r: production-shaped credential "
                                "material" % (p,))
                break
    if findings:
        raise AmbientCredentialError(
            "ambient authority present in agent scope (%d finding(s)): %s; "
            "the agent must hold leases, never raw credentials"
            % (len(findings), "; ".join(findings[:5])))
    return {"ok": True, "checked_env": len(env or {}),
            "checked_paths": len(paths)}
