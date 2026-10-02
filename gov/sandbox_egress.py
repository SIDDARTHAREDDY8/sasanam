"""Per-sandbox network policy + chained egress audit (wave-278 lane 3).

Clean-room adaptation of two Apache-2.0 patterns identified by the
wave-277 prospecting lane (child A):

* e2b-dev/e2b (Apache-2.0): a deny-by-default per-sandbox network
  policy object that is part of the sandbox and MUTABLE MID-RUN
  (e2b's ``updateNetwork``), enforced below the guest. No e2b code is
  reused -- only the API shape (policy-is-part-of-the-sandbox,
  changeable mid-run, enforced below the guest).
* google/gvisor Gofer principle (Apache-2.0): host-side I/O lives in
  a minimal broker on a narrow protocol. Here the wall proxy is that
  broker: the guest never holds the policy object; every egress
  decision is made in the broker process against the live policy.

What E2B lacks -- and this module provides -- is the audit half:
every lifecycle event, every policy mutation, and every egress
*attempt* (allowed AND denied) is chained into a hash-linked log, so
the boundary crossing is evidence, not just enforcement.

The L7 leg: e2b's native filtering is L3-only and blind to
percent-encoding (the F296 class). The wall proxy consults
:func:`gov.egress_refs.screen_egress_url` -- the decode-to-stability
leg -- for plaintext-HTTP requests, so the F296 closure covers
sandboxed tool execution too. Honest limit: CONNECT tunnels carry no
path (the TLS bytes tunnel opaquely by design), so the L7 leg cannot
apply there; the destination wall is the whole decision on that path.

Public seam: :class:`SandboxNetworkPolicy`,
:class:`SandboxEgressController`, :class:`SandboxEgressAuditor`.
Deterministic, stdlib-only, never raises on hostile input (policy
*parse* errors raise :class:`PolicyRefusedError` loudly by design --
a malformed policy must never silently become a permissive one).
"""

import hashlib
import json
import re
import threading
import time

from gov.egress_proxy import PolicyRefusedError  # noqa: F401  (re-export)

__all__ = [
    "PolicyRefusedError",
    "SandboxNetworkPolicy",
    "SandboxEgressController",
    "SandboxEgressAuditor",
    "DEFAULT_MAX_REF_PAYLOAD_CHARS",
]

DEFAULT_MAX_REF_PAYLOAD_CHARS = 512  # mirrors gov/egress_refs.py

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# SandboxNetworkPolicy: deny-by-default, immutable after parse.
# ---------------------------------------------------------------------------

class SandboxNetworkPolicy(object):
    """Parsed, validated per-sandbox network policy.

    ``data`` keys (unknown keys are refused, fail-closed):
      version: non-empty string (operator-assigned; monotonic by
          convention, enforced by nobody -- the hash names the policy).
      allow_out: list of ``"host:port"`` strings. Exact membership, no
          wildcards, no suffix trust -- anything not enumerated is
          denied (deny-by-default, the e2b ``denyOut: [ALL_TRAFFIC]``
          posture).
      sensitive_digests: list of sha256 hex digests of data tokens that
          must never appear in a plaintext-HTTP egress URL (the L7 leg).
      max_ref_payload_chars: int, query+fragment budget per URL.

    Immutable after parse: runtime mutation goes through
    :class:`SandboxEgressController.update`, which swaps the whole
    object -- the proxy never sees a half-parsed policy.
    """

    _KNOWN_KEYS = frozenset((
        "version", "allow_out", "sensitive_digests",
        "max_ref_payload_chars",
    ))

    def __init__(self, data):
        if not isinstance(data, dict):
            raise PolicyRefusedError(
                "network policy must be a dict, got %r" % type(data))
        unknown = set(data) - self._KNOWN_KEYS
        if unknown:
            raise PolicyRefusedError(
                "unknown network policy keys refused: %s"
                % sorted(unknown))
        version = data.get("version")
        if not isinstance(version, str) or not version.strip():
            raise PolicyRefusedError(
                "network policy 'version' must be a non-empty string")
        self.version = version.strip()

        allow_out = data.get("allow_out", [])
        if not isinstance(allow_out, list):
            raise PolicyRefusedError(
                "network policy 'allow_out' must be a list")
        parsed = set()
        for entry in allow_out:
            parsed.add(self._parse_allow_entry(entry))
        self.allow_out = frozenset(parsed)

        digests = data.get("sensitive_digests", [])
        if not isinstance(digests, list):
            raise PolicyRefusedError(
                "network policy 'sensitive_digests' must be a list")
        clean = set()
        for d in digests:
            if not isinstance(d, str) or not _HEX64_RE.match(d.lower()):
                raise PolicyRefusedError(
                    "sensitive_digests entries must be sha256 hex, "
                    "got %r" % (d,))
            clean.add(d.lower())
        self.sensitive_digests = frozenset(clean)

        budget = data.get("max_ref_payload_chars",
                          DEFAULT_MAX_REF_PAYLOAD_CHARS)
        if not isinstance(budget, int) or isinstance(budget, bool) \
                or budget < 1:
            raise PolicyRefusedError(
                "network policy 'max_ref_payload_chars' must be a "
                "positive int")
        self.max_ref_payload_chars = budget

        self.policy_hash = _sha256_hex(_canonical({
            "version": self.version,
            "allow_out": sorted("%s:%d" % hp for hp in self.allow_out),
            "sensitive_digests": sorted(self.sensitive_digests),
            "max_ref_payload_chars": self.max_ref_payload_chars,
        }))

    @staticmethod
    def _parse_allow_entry(entry):
        if not isinstance(entry, str):
            raise PolicyRefusedError(
                "allow_out entries must be 'host:port' strings, got %r"
                % (entry,))
        if entry.count(":") != 1:
            raise PolicyRefusedError(
                "allow_out entry is not host:port: %r" % (entry,))
        host, _, port_s = entry.partition(":")
        host = host.strip().lower()
        port_s = port_s.strip()
        if not _HOST_RE.match(host):
            raise PolicyRefusedError(
                "allow_out host not allowed: %r" % (entry,))
        if not port_s.isascii() or not port_s.isdigit():
            raise PolicyRefusedError(
                "allow_out port not numeric: %r" % (entry,))
        port = int(port_s)
        if not (1 <= port <= 65535):
            raise PolicyRefusedError(
                "allow_out port out of range: %r" % (entry,))
        return (host, port)

    def allows(self, host, port):
        """Exact (host, port) membership. Never raises."""
        try:
            return (str(host).strip().lower(), int(port)) in self.allow_out
        except (TypeError, ValueError):
            return False

    def to_egress_refs_policy(self):
        """The L7 leg's view: an egress_refs.EgressPolicy carrying this
        policy's sensitive digests and payload budget."""
        from gov import egress_refs as _er
        return _er.EgressPolicy(
            sensitive_digests=tuple(self.sensitive_digests),
            max_ref_payload_chars=self.max_ref_payload_chars)

    def __repr__(self):
        return ("SandboxNetworkPolicy(version=%r, allow_out=%d, "
                "digests=%d, hash=%.12s...)"
                % (self.version, len(self.allow_out),
                   len(self.sensitive_digests), self.policy_hash))


# ---------------------------------------------------------------------------
# SandboxEgressController: the runtime-mutable holder (e2b updateNetwork).
# ---------------------------------------------------------------------------

class SandboxEgressController(object):
    """Holds the live policy for one sandbox's wall.

    The wall proxy consults :attr:`current` per request, so
    :meth:`update` takes effect mid-run (the e2b ``updateNetwork``
    analog). A malformed update raises :class:`PolicyRefusedError`
    loudly and the OLD policy keeps serving -- the proxy never serves
    a half-parsed policy. Every successful update is chained into the
    auditor (when one is attached).
    """

    def __init__(self, policy, auditor=None):
        if not isinstance(policy, SandboxNetworkPolicy):
            raise PolicyRefusedError(
                "policy must be a SandboxNetworkPolicy, got %r"
                % type(policy))
        self._lock = threading.Lock()
        self._policy = policy
        self.auditor = auditor
        if auditor is not None:
            auditor.event("policy-attached", {
                "version": policy.version,
                "policy_hash": policy.policy_hash,
            })

    @property
    def current(self):
        with self._lock:
            return self._policy

    def update(self, data):
        """Parse-and-swap. Returns the new policy. Raises
        PolicyRefusedError on malformed input (old policy keeps
        serving)."""
        new_policy = SandboxNetworkPolicy(data)  # raises first
        with self._lock:
            old = self._policy
            self._policy = new_policy
        if self.auditor is not None:
            self.auditor.event("policy-updated", {
                "version": new_policy.version,
                "prev_hash": old.policy_hash,
                "new_hash": new_policy.policy_hash,
            })
        return new_policy


# ---------------------------------------------------------------------------
# SandboxEgressAuditor: the hash-chained attempt/lifecycle log.
# ---------------------------------------------------------------------------

def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class SandboxEgressAuditor(object):
    """Hash-chained event log for one sandbox's boundary.

    Events: ``policy-attached``, ``policy-updated``,
    ``sandbox-created``, ``sandbox-run``, ``egress-attempt`` (every
    proxied request, allowed AND denied -- the log E2B lacks).
    Each entry hash-links to its predecessor; :meth:`verify`
    recomputes the chain. ``on_event`` (optional) mirrors each entry
    into the deployment's canonical audit log -- e.g. the HMAC-chained
    ``gov/log.py`` ActionLog, the same pattern as
    ``egress_proxy.VerdictLogger(on_verdict=...)``. Key custody stays
    operator-owned; this module never sees keys.

    Never raises: a logging failure must not open the wall, and a
    logging failure must not close it either -- the enforcement
    decision already happened; the auditor records best-effort.
    """

    def __init__(self, on_event=None):
        self._lock = threading.Lock()
        self._events = []
        self._on_event = on_event

    def _chain(self, seq, ts, kind, detail, prev_hash):
        body = {"seq": seq, "ts": ts, "kind": kind,
                "detail": detail, "prev_hash": prev_hash}
        try:
            blob = _canonical(body)
        except (TypeError, ValueError):
            body["detail"] = {"unserializable": repr(detail)}
            blob = _canonical(body)
        entry = dict(body)
        entry["entry_hash"] = _sha256_hex(blob)
        return entry

    def event(self, kind, detail=None):
        """Append one event. Returns the entry dict. Never raises."""
        try:
            kind = str(kind)
            with self._lock:
                prev = (self._events[-1]["entry_hash"]
                        if self._events else "GENESIS")
                entry = self._chain(len(self._events), _utcnow(),
                                    kind, detail or {}, prev)
                self._events.append(entry)
        except Exception:  # noqa: BLE001 -- never raise
            return {"kind": str(kind), "detail": {},
                    "entry_hash": "LOGGING-FAILED"}
        if self._on_event is not None:
            try:
                self._on_event(entry)
            except Exception:  # noqa: BLE001 -- mirror is best-effort
                pass
        return entry

    @property
    def events(self):
        with self._lock:
            return list(self._events)

    def verify(self):
        """Recompute the hash chain. Returns True/False, never raises."""
        try:
            prev = "GENESIS"
            for i, entry in enumerate(self.events):
                body = {"seq": entry["seq"], "ts": entry["ts"],
                        "kind": entry["kind"], "detail": entry["detail"],
                        "prev_hash": entry["prev_hash"]}
                if entry["seq"] != i or entry["prev_hash"] != prev:
                    return False
                if _sha256_hex(_canonical(body)) != entry["entry_hash"]:
                    return False
                prev = entry["entry_hash"]
            return True
        except Exception:  # noqa: BLE001
            return False
