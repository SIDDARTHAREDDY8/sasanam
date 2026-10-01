"""Mesh admission: kernel-attested OR SVID-verified peer identity.

Wave-260 lane 3 (identity-mesh follow-up). Stdlib only.

This module composes -- never duplicates -- two existing seams:

* ``gov/attested_channel.ChannelAdmission`` (wave-243): the
  kernel-attested path. ``peer_identity`` (uid/gid/pid/exe) is
  supplied by the deployment's admission layer, never by the caller.
* ``gov/svid_issuer.MeshControl`` (wave-259): the SVID path --
  verify-first (pinned trust roots, trust domain, signature, expiry),
  then the default-deny ACL over the spiffe id.

The route table is deployment-owned policy-as-data (the headscale
ACL-file shape): ``{route: {"require": "svid" | "kernel" | "either"}}``.
Callers address routes by name; they never choose their own seam.

Decision rule (all fail-closed; NO downgrade between the seams):

* ``require="svid"``: ONLY the SVID path is evaluated. No SVID
  presented -> ``svid-missing`` -- kernel material, if any, is never
  consulted and never admitted through. A bad SVID -> the verifier's
  ``svid-*`` refusal; the kernel path is never a fallback.
* ``require="kernel"``: ONLY the kernel-attested path is evaluated
  (the existing ``ChannelAdmission`` discipline). No attested peer ->
  ``channel-identity-unattested`` -- a presented SVID, however valid,
  is ignored; it never admits.
* ``require="either"``: presence-driven, still no downgrade. A
  presented SVID is evaluated on the SVID path ONLY: a bad SVID
  refuses with the verifier's code even when valid kernel
  credentials ride along (never falls through to the weaker path).
  With no SVID presented the kernel path is used -- nothing was
  offered, so nothing was downgraded. Neither presented ->
  ``channel-identity-unattested`` (refused outright, never downgraded).

An undeclared route refuses ``svid-acl-denied``: the route table is
itself a default-deny admission policy.

Machine codes: ``svid-missing`` / ``svid-acl-denied`` for this
module's own policy refusals; the SVID path's ``svid-*`` codes and
the kernel path's ``channel-*`` codes otherwise.

Honest boundaries
-----------------
* This module does not perform attestation: ``peer_identity`` is a
  value the deployment vouches for (SO_PEERCRED analogue); the SVID
  trust roots are pinned deployment material. The TEST issuer from
  wave-259 stays a test issuer -- production key custody remains
  deployment-owned.
* The clock is injected (``now``); a None ``now`` resolves to
  ``time.time()`` per the F224 contract.
"""

from . import attested_channel as _channel
from .svid_issuer import (
    MeshControl,
    SvidError,
    _validate_now,
)

__all__ = [
    "MeshAdmission",
    "REQUIRE_SVID",
    "REQUIRE_KERNEL",
    "REQUIRE_EITHER",
    "MESH_UNKNOWN_ROUTE_CODE",
]

#: Route requirement values.
REQUIRE_SVID = "svid"
REQUIRE_KERNEL = "kernel"
REQUIRE_EITHER = "either"
_REQUIREMENTS = frozenset([REQUIRE_SVID, REQUIRE_KERNEL, REQUIRE_EITHER])

#: Default-deny admission refusal for undeclared routes (reuses the
#: existing default-deny refusal: the route table is a default-deny
#: admission policy, mirroring the mesh ACL).
MESH_UNKNOWN_ROUTE_CODE = "svid-acl-denied"
_SVID_MISSING_CODE = "svid-missing"


class MeshAdmission(object):
    """Dual-seam mesh admission over a deployment-owned route table.

    ``routes``: ``{route_name: {"require": "svid"|"kernel"|"either"}}``.
    ``mesh_control``: a ``gov.svid_issuer.MeshControl`` (verifier +
    default-deny ACL) used for the SVID seam. ``channel``: a
    ``gov.attested_channel.ChannelAdmission`` for the kernel seam
    (a fresh one is built when not supplied).
    """

    def __init__(self, routes, mesh_control, channel=None):
        if not isinstance(mesh_control, MeshControl):
            raise SvidError(
                "svid-malformed",
                "mesh_control must be a gov.svid_issuer.MeshControl")
        if not isinstance(routes, dict) or not routes:
            raise SvidError(
                "svid-malformed",
                "routes must be a non-empty mapping "
                "route_name -> {'require': ...}")
        checked = {}
        for name, rule in routes.items():
            if not isinstance(name, str) or not name:
                raise SvidError(
                    "svid-malformed",
                    "route names must be non-empty strings")
            if not isinstance(rule, dict):
                raise SvidError(
                    "svid-malformed",
                    "route %r rule must be a dict" % (name,))
            require = rule.get("require")
            if require not in _REQUIREMENTS:
                raise SvidError(
                    "svid-malformed",
                    "route %r 'require' must be one of %s, got %r"
                    % (name, sorted(_REQUIREMENTS), require))
            checked[name] = require
        self._routes = checked
        self._mesh_control = mesh_control
        self._channel = channel if channel is not None \
            else _channel.ChannelAdmission()

    @property
    def routes(self):
        """The admission route table (read-only copy)."""
        return dict(self._routes)

    def admit(self, route, svid=None, kernel=None, now=None):
        """Admit one peer on ``route``. Returns the admission record.

        ``svid``: a presented SVID document (or None). ``kernel``: a
        dict ``{"peer_identity": ..., "emitter_claim": ...,
        "key_location": ...}`` (or None). Each seam is evaluated
        strictly on its own path -- a bad SVID never falls through
        to the kernel path, and kernel material never re-routes an
        SVID-required refusal.
        """
        at = _validate_now(now)
        require = self._routes.get(route) \
            if isinstance(route, str) else None
        if require is None:
            raise SvidError(
                MESH_UNKNOWN_ROUTE_CODE,
                "route %r is not in the admission table "
                "(default-deny)" % (route,))
        if require == REQUIRE_SVID:
            spiffe_id = self._admit_svid(svid, at)
            return {"route": route, "mode": REQUIRE_SVID,
                    "spiffe_id": spiffe_id}
        if require == REQUIRE_KERNEL:
            record = self._admit_kernel(kernel, at)
            return {"route": route, "mode": REQUIRE_KERNEL,
                    "principal": record["principal"],
                    "peer_identity": record["peer_identity"],
                    "channel_record": record}
        # require == "either": presence-driven, no downgrade. A
        # presented SVID goes down the SVID seam only -- its failure
        # is terminal, never a kernel fallback.
        if svid is not None:
            spiffe_id = self._admit_svid(svid, at)
            return {"route": route, "mode": REQUIRE_SVID,
                    "spiffe_id": spiffe_id}
        record = self._admit_kernel(kernel, at)
        return {"route": route, "mode": REQUIRE_KERNEL,
                "principal": record["principal"],
                "peer_identity": record["peer_identity"],
                "channel_record": record}

    def _admit_svid(self, svid, at):
        """SVID seam only. Missing -> svid-missing; the kernel path is
        never consulted here."""
        if svid is None:
            raise SvidError(
                _SVID_MISSING_CODE,
                "no SVID presented where the admission seam requires "
                "one; refused, not re-routed to the kernel path")
        # MeshControl.admit verifies FIRST (svid-* codes), then the
        # default-deny ACL (svid-acl-denied).
        return self._mesh_control.admit(svid, now=at)

    def _admit_kernel(self, kernel, at):
        """Kernel seam only. Delegates entirely to ChannelAdmission's
        own vocabulary -- composed, not re-implemented."""
        if kernel is None:
            raise _channel.AttestedChannelError(
                _channel.IDENTITY_UNATTESTED,
                "no attested peer identity presented; refused "
                "outright, never downgraded")
        if not isinstance(kernel, dict):
            raise _channel.AttestedChannelError(
                _channel.MALFORMED,
                "kernel identity must be a dict with "
                "'peer_identity'/'emitter_claim'/'key_location'")
        return self._channel.admit(
            kernel.get("emitter_claim"),
            kernel.get("peer_identity"),
            kernel.get("key_location"),
            at)
