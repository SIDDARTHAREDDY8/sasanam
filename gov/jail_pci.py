"""PCI device-attachment deny-by-default for jail policies.

Design input (ADAPT, not vendored): PCI device-passthrough is a
confinement attack surface. NOTE (wave-223 merge adjudication): wave-219
prospecting attributed this direction to Firecracker's CVE-2026-5747;
wave-221 prospecting could not verify that attribution in the source
tree and reframed it as unclaimed, but wave-223 prospecting read the
primary source (AWS Security Bulletin 2026-015-AWS, 2026-04-07;
NVD 2026-04-08): CVE-2026-5747 is REAL (OOB write in Firecracker's
virtio-pci transport 1.13.0-1.14.3, 1.15.0; CVSS v4 8.7; patched
1.14.4/1.15.1), and PCI-off ("revert to MMIO by removing the
--enable-pci flag") is verbatim the vendor's stated workaround
(throughput/latency tradeoff noted). The deny-by-default direction
stands with vendor precedent as defense-in-depth; the primary fix
remains upgrading to 1.14.4/1.15.1. No Firecracker version floor is
codified. A tool
jail that silently permits PCI device attachment lets an agent widen
its confinement by naming a device at runtime. This module makes
device attachment explicit and pinned:

* A **device pin** is ``{"device_name": <name>,
  "device_digest": <sha256 hex>}`` -- the name the deployment calls
  the device plus the digest of the device descriptor/firmware the
  deployment audited. Both are bound together at attach time: a pinned
  name with a swapped digest is refused, and an unpinned name is
  refused even with a well-formed digest.
* A **compiled allowlist** is the deployment's explicit
  device-attachment posture. It is DENY-BY-DEFAULT: an empty
  allowlist refuses every attach. There is no "allow all" mode -- a
  deployment that wants device attachment names every device.
* Wiring into ``gov/jail_policy.py`` is tighten-only opt-in:
  ``JailPolicyRegistry.activate(..., pci_allowlist=None)`` stores the
  allowlist per (name, version), and
  ``authorize_pci_attach(policy_name, version, device_name,
  device_digest)`` authorizes one attach. With ``pci_allowlist=None``
  (the default) the registry path is byte-identical to legacy, and an
  attach attempt with no stored allowlist raises
  ``pci-attach-refused`` -- never silently allowed.

Malformed pins are refused AT COMPILE (authoring errors), never at
attach time: bad names, non-hex digests, short digests, missing
fields, unknown fields. Whole-update discipline: an allowlist entry
has exactly the two pin fields.

Honest boundaries (stated, not absorbed):

* A jail policy describes intended confinement; it does not prove
  the jail ran. This module pins the attachment DECISION, not the
  execution -- the same boundary ``gov/jail_policy.py`` states.
* A pin describes the device the deployment INTENDS to attach; it
  does not prove the host attached the right device. Descriptor-digest
  custody is the deployment's job.
* The registry re-checks the policy signature and validity window
  before consulting the allowlist (``get()`` does this), so a swapped
  or expired policy cannot smuggle an allowlist.
* Allowlist updates are tighten-only: a policy name's allowlist may
  only shrink across versions (``pci-allowlist-widening-refused``).
  Adding a device needs a new policy name -- a wider posture is a
  new confinement claim, not an upgrade.
* This module claims no new containment boundary -- it pins the
  attachment decision over the boundary ``gov/sandbox.py`` and
  ``gov/jail_policy.py`` already provide.

The ``pci_allowlist`` option name (rather than a ``pci_devices``
policy-body field) is deliberate: the v1 policy body is under
whole-update discipline, so a new body field would invalidate every
existing signed policy. The allowlist rides beside the body as a
separate compiled object, wired in tighten-only at activation.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import hashlib
import json
import re

__all__ = [
    "DEVICE_NAME_RE",
    "JailPCIError",
    "CompiledPCIAllowlist",
    "compile_pci_allowlist",
    "validate_device_pin",
]

#: Machine-readable refusal codes from this module.
CODE_ATTACH_REFUSED = "pci-attach-refused"
CODE_PIN_MALFORMED = "device-pin-malformed"
CODE_REQUEST_MALFORMED = "pci-attach-request-malformed"
CODE_WIDENING_REFUSED = "pci-allowlist-widening-refused"

#: Device names: the deployment's own vocabulary, conservative shape.
DEVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

_PIN_FIELDS = ("device_name", "device_digest")
_HEX = set("0123456789abcdef")


class JailPCIError(Exception):
    """Fail-closed PCI device-attachment violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(JailPCIError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _check_digest(value):
    if not isinstance(value, str) or len(value) != 64 \
            or any(c not in _HEX for c in value):
        raise JailPCIError(
            CODE_PIN_MALFORMED,
            "device_digest must be a 64-char sha256 hex string, got %r"
            % (value,))
    return value


def validate_device_pin(pin):
    """Strict shape check of one device pin dict. Returns a normalized
    pin ``{"device_name": ..., "device_digest": ...}`` (canonical key
    order). Raises JailPCIError(``device-pin-malformed``)."""
    if not isinstance(pin, dict):
        raise JailPCIError(CODE_PIN_MALFORMED, "pin is not a dict")
    unknown = sorted(set(pin) - set(_PIN_FIELDS))
    if unknown:
        raise JailPCIError(
            CODE_PIN_MALFORMED,
            "unknown pin fields %s (whole-update discipline: refusing)"
            % (unknown,))
    missing = sorted(set(_PIN_FIELDS) - set(pin))
    if missing:
        raise JailPCIError(
            CODE_PIN_MALFORMED, "missing pin fields %s" % (missing,))
    name = pin["device_name"]
    if not isinstance(name, str) or not DEVICE_NAME_RE.match(name):
        raise JailPCIError(
            CODE_PIN_MALFORMED,
            "device_name must match %s, got %r"
            % (DEVICE_NAME_RE.pattern, name))
    digest = _check_digest(pin["device_digest"])
    return {"device_name": name, "device_digest": digest}


class CompiledPCIAllowlist:
    """A compiled PCI device allowlist: deny-by-default, pins bound at
    compile.

    ``authorize(device_name, device_digest)`` returns an audit-visible
    grant on success and raises ``JailPCIError`` otherwise:
    ``pci-attach-refused`` for unpinned devices, kept distinct from
    ``pci-attach-request-malformed`` for malformed requests -- the
    refusal carries no authority and the grant carries no execution
    power; it is the record the audit log chains.
    """

    def __init__(self, pins):
        # pins: frozenset of (device_name, device_digest).
        self._pins = frozenset(pins)

    def pins(self):
        """The pinned (name, digest) pairs, sorted."""
        return sorted(self._pins)

    def fingerprint(self):
        """sha256 hex of the canonical pins list -- the pin every
        audit-visible grant carries."""
        canon = json.dumps(
            [{"device_name": n, "device_digest": d}
             for n, d in self.pins()],
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii")
        return hashlib.sha256(canon).hexdigest()

    def authorize(self, device_name, device_digest):
        """Authorize one device attach. Returns the audit-visible
        grant dict on success; raises ``pci-attach-refused`` on any
        unpinned name or swapped digest, and
        ``pci-attach-request-malformed`` on a malformed request (an
        authoring bug, kept distinct from a policy denial so triage
        never confuses them)."""
        if not isinstance(device_name, str) \
                or not isinstance(device_digest, str):
            raise JailPCIError(
                CODE_REQUEST_MALFORMED,
                "device_name and device_digest must be strings, got "
                "(%s, %s)"
                % (type(device_name).__name__,
                   type(device_digest).__name__))
        if (device_name, device_digest) not in self._pins:
            raise JailPCIError(
                CODE_ATTACH_REFUSED,
                "device %r not pinned by the allowlist "
                "(deny-by-default; allowlist fingerprint %s)"
                % (device_name, self.fingerprint()))
        return {
            "allowed": True,
            "device_name": device_name,
            "device_digest": device_digest,
            "allowlist_fingerprint": self.fingerprint(),
            "code": "pci-attach-allowed",
        }


def compile_pci_allowlist(entries, audit=None):
    """Compile-time front gate for a device allowlist.

    ``entries`` is a list of device pin dicts. Malformed pins raise
    ``JailPCIError("device-pin-malformed")`` (audited when ``audit``
    is supplied). Duplicate pins collapse (same device, same digest --
    no weakening). Returns a ``CompiledPCIAllowlist``. An empty list
    compiles to a deny-everything allowlist -- that IS the default
    posture.
    """
    if not isinstance(entries, list):
        raise JailPCIError(
            CODE_PIN_MALFORMED, "entries must be a list")
    pins = []
    for i, entry in enumerate(entries):
        try:
            norm = validate_device_pin(entry)
        except JailPCIError as exc:
            if audit is not None:
                audit({"event": "pci_allowlist_compile_refused",
                       "code": exc.code, "index": i,
                       "detail": exc.detail})
            raise
        pins.append((norm["device_name"], norm["device_digest"]))
    compiled = CompiledPCIAllowlist(pins)
    if audit is not None:
        audit({"event": "pci_allowlist_compiled",
               "fingerprint": compiled.fingerprint(),
               "pin_count": len(compiled.pins())})
    return compiled
