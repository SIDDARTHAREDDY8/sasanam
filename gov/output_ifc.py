"""Information-flow labels for tool-output provenance.

Lattice core vendored/adapted from Project Oak's ``mcp/ifc/labels``
(Apache-2.0, https://github.com/project-oak/oak @
``93cd79e4338d73371de602572ea14505a574c3a2``): ``SecrecyLabel`` /
``IntegrityLabel`` with lattice ``join`` / ``meet`` and
``can_flow_to``, plus ``Declassification`` / ``Endorsement``
privileges. Restyled to Sasanam conventions (4-space indent,
<=79 columns); the lattice semantics are preserved exactly.

Sasanam design on top of the lattice (ours, not Oak's):

- ``assign_label``: every tool output defaults to integrity
  ``{"tool-external"}`` (untrusted) and empty secrecy. Callers may
  self-declare *secrecy* tags (the fail-closed direction: claiming
  more secrecy only restricts flow) but may NOT self-claim trust
  tags such as ``"user-verified"`` -- those arrive only through an
  ``Endorsement`` privilege ceremony (``ifc-privilege-denied``).
- ``check_sink``: sinks (``egress``, ``journal``, ``approval-queue``,
  ``execution``) declare the labels they accept as data. The
  ``execution`` sink requires ``"user-verified"`` integrity by
  default, so acting on unendorsed tool output refuses with a
  machine-coded ``ifc-integrity-flow-denied``.
- ``combine_outputs``: the taint rule is secrecy-join (union) plus
  integrity-meet (intersection). Note this differs deliberately
  from Oak's combined ``Label.join``, which unions integrity tags:
  that is the lattice algebra for combining *policies*; for
  combining *data* the conservative direction is intersection, so
  one tainted part cannot launder the whole.
- Privilege exercise (``exercise_privilege``) requires an
  authorized, unexpired, digest-bound grant AND an audit hook.
  Without the audit hook it refuses (``ifc-audit-required``):
  privilege use is never silent.

All public seams fail closed on malformed input
(``ifc-label-malformed``). Stdlib only. Deterministic: time is an
explicit ``now`` parameter, never ambient ``now()``.

Honest limits: label assignment consumes caller-declared
provenance (a lying caller mislabels); sink policies are
deployment-declared; this module tracks declared labels, it does
not discover ground truth.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

# ------------------------------------------------------------------
# Vendored lattice core (Project Oak, Apache-2.0 -- see docstring).
# ------------------------------------------------------------------


class BaseLabel(object):
    """Base class for labels with lattice operations.

    Labels form a lattice under subset ordering:
    - Join = union (least upper bound)
    - Meet = intersection (greatest lower bound)
    """

    __slots__ = ("tags",)

    def __init__(self, tags=frozenset()):
        self.tags = frozenset(tags)

    def join(self, other):
        """Least upper bound (union of tags)."""
        return type(self)(self.tags | other.tags)

    def meet(self, other):
        """Greatest lower bound (intersection of tags)."""
        return type(self)(self.tags & other.tags)

    def __eq__(self, other):
        return type(self) is type(other) and self.tags == other.tags

    def __hash__(self):
        return hash((type(self).__name__, self.tags))

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, sorted(self.tags))


class SecrecyLabel(BaseLabel):
    """Secrecy label -- tracks who may read.

    Data with more tags is MORE restrictive (higher in lattice).
    Flow rule: source.tags <= target.tags (no write down).
    """

    def can_flow_to(self, target):
        """True iff this label's data may flow to ``target``."""
        return self.tags <= target.tags


class IntegrityLabel(BaseLabel):
    """Integrity label -- tracks trust/provenance.

    Data with more tags is LESS restrictive (lower in lattice):
    tags are trust attributes and more attributes satisfy more
    requirements.
    Flow rule: target.tags <= source.tags (no read down).
    """

    def can_flow_to(self, target):
        """True iff this label's data may flow to ``target``."""
        return target.tags <= self.tags


class Label(object):
    """Combined secrecy + integrity label."""

    __slots__ = ("secrecy", "integrity")

    def __init__(self, secrecy=None, integrity=None):
        self.secrecy = secrecy if secrecy is not None else SecrecyLabel()
        self.integrity = (integrity if integrity is not None
                          else IntegrityLabel())

    def can_flow_to(self, target):
        """True iff data with this label may flow to ``target``."""
        return (self.secrecy.can_flow_to(target.secrecy)
                and self.integrity.can_flow_to(target.integrity))

    def join(self, other):
        """Lattice least upper bound (Oak's algebra)."""
        return Label(self.secrecy.join(other.secrecy),
                     self.integrity.join(other.integrity))

    def meet(self, other):
        """Lattice greatest lower bound (Oak's algebra)."""
        return Label(self.secrecy.meet(other.secrecy),
                     self.integrity.meet(other.integrity))

    def __eq__(self, other):
        return (isinstance(other, Label)
                and self.secrecy == other.secrecy
                and self.integrity == other.integrity)

    def __hash__(self):
        return hash((self.secrecy, self.integrity))

    def __repr__(self):
        return "Label(secrecy=%r, integrity=%r)" % (
            sorted(self.secrecy.tags), sorted(self.integrity.tags))


class Declassification(object):
    """Privilege to remove secrecy tags (Oak semantics)."""

    __slots__ = ("tags",)

    def __init__(self, tags=frozenset()):
        self.tags = frozenset(tags)

    def declassify(self, label, tags_to_remove):
        """Remove secrecy tags; raises if outside the privilege."""
        if not tags_to_remove <= self.tags:
            raise OutputIFCError(
                "ifc-privilege-scope-denied",
                "cannot declassify %r: outside privilege %r"
                % (sorted(tags_to_remove - self.tags),
                   sorted(self.tags)))
        return SecrecyLabel(label.tags - tags_to_remove)


class Endorsement(object):
    """Privilege to add integrity tags (Oak semantics)."""

    __slots__ = ("tags",)

    def __init__(self, tags=frozenset()):
        self.tags = frozenset(tags)

    def endorse(self, label, tags_to_add):
        """Add integrity tags; raises if outside the privilege."""
        if not tags_to_add <= self.tags:
            raise OutputIFCError(
                "ifc-privilege-scope-denied",
                "cannot endorse %r: outside privilege %r"
                % (sorted(tags_to_add - self.tags),
                   sorted(self.tags)))
        return IntegrityLabel(label.tags | tags_to_add)


# ------------------------------------------------------------------
# Module constants
# ------------------------------------------------------------------

CODES = (
    "ifc-audit-required",
    "ifc-integrity-flow-denied",
    "ifc-label-malformed",
    "ifc-privilege-denied",
    "ifc-privilege-expired",
    "ifc-privilege-scope-denied",
    "ifc-privilege-unauthorized",
    "ifc-secrecy-flow-denied",
    "ifc-sink-unmapped",
)

INTEGRITY_EXTERNAL = "tool-external"
INTEGRITY_USER_VERIFIED = "user-verified"
INTEGRITY_DEPLOYMENT_ATTESTED = "deployment-attested"
SECRECY_CREDENTIAL = "credential"

# Trust tags that only an Endorsement ceremony may confer; a bare
# assign_label claim of one of these is an unendorsed trust claim.
_NON_ASSERTABLE_INTEGRITY = frozenset({
    INTEGRITY_USER_VERIFIED,
    INTEGRITY_DEPLOYMENT_ATTESTED,
})

SINK_DEFAULTS = {
    # Public egress: nothing secret may leave; integrity informational.
    "egress": {"secrecy": [], "integrity": []},
    # Journal is the evidence substrate: it must accept everything,
    # including untrusted data, or evidence is destroyed.
    "journal": {"secrecy": [], "integrity": []},
    # Approval queue receives proposals; human review is what raises
    # trust, so the queue itself accepts all provenance.
    "approval-queue": {"secrecy": [], "integrity": []},
    # Execution acts on the world: only endorsed data may flow here.
    "execution": {"secrecy": [], "integrity": [INTEGRITY_USER_VERIFIED]},
}

_GRANT_VERSION = 1
_OPERATION_PRIVILEGE_KEY = {
    "declassify": "declassification",
    "endorse": "endorsement",
}
_NOW_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class OutputIFCError(Exception):
    """Machine-coded refusal. ``code`` is a decision-code taxonomy key."""

    def __init__(self, code, detail=""):
        super(OutputIFCError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------
# Validation helpers (all fail closed)
# ------------------------------------------------------------------

def _malformed(what):
    return OutputIFCError("ifc-label-malformed", what)


def _check_tag(tag, what="tag"):
    if not isinstance(tag, str) or not tag:
        raise _malformed("bad %s %r" % (what, tag))
    return tag


def _check_tag_set(value, what):
    if isinstance(value, str) or not isinstance(
            value, (list, tuple, set, frozenset)):
        raise _malformed("bad %s %r" % (what, value))
    return frozenset(_check_tag(t, what) for t in value)


def _label_from_dict(value):
    if not isinstance(value, dict):
        raise _malformed("label must be a dict, got %r" % (value,))
    unknown = set(value) - {"secrecy", "integrity"}
    if unknown:
        raise _malformed("unknown label keys %r" % (sorted(unknown),))
    return Label(
        SecrecyLabel(_check_tag_set(value.get("secrecy", []), "secrecy")),
        IntegrityLabel(_check_tag_set(value.get("integrity", []),
                                      "integrity")))


def _label_to_dict(label):
    return {"secrecy": sorted(label.secrecy.tags),
            "integrity": sorted(label.integrity.tags)}


def _check_sink_policy(value):
    if not isinstance(value, dict):
        raise _malformed("sink policy must be a dict, got %r" % (value,))
    name = value.get("name")
    if not isinstance(name, str) or not name:
        raise _malformed("bad sink name %r" % (name,))
    unknown = set(value) - {"name", "secrecy", "integrity"}
    if unknown:
        raise _malformed("unknown sink keys %r" % (sorted(unknown),))
    return (name,
            SecrecyLabel(_check_tag_set(value.get("secrecy", []),
                                       "sink secrecy")),
            IntegrityLabel(_check_tag_set(value.get("integrity", []),
                                          "sink integrity")))


def _check_now(value):
    if not isinstance(value, str) or not _NOW_RE.match(value):
        raise _malformed("bad now timestamp %r" % (value,))
    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00"))
    except ValueError:
        raise _malformed("bad now timestamp %r" % (value,))
    if parsed.tzinfo is None:
        # Naive timestamps are read as UTC (never local time).
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _digest(obj):
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------
# Public seams
# ------------------------------------------------------------------

def assign_label(tool_name, provenance=None, registry=None):
    """Assign an IFC label to a tool output. Fail-closed.

    ``provenance`` (optional dict) may self-declare *secrecy* tags
    only; any integrity tag outside the registry's assertable set is
    an unendorsed trust claim and refuses with
    ``ifc-privilege-denied``. ``registry`` (optional dict) is
    deployment-declared: ``{"assertable_tags": [...],
    "tool_integrity": {tool: [...]}}``.
    """
    if not isinstance(tool_name, str) or not tool_name:
        raise _malformed("bad tool name %r" % (tool_name,))
    if provenance is None:
        provenance = {}
    if not isinstance(provenance, dict):
        raise _malformed("provenance must be a dict")
    unknown = set(provenance) - {"secrecy", "integrity"}
    if unknown:
        raise _malformed("unknown provenance keys %r" % (sorted(unknown),))
    assertable = frozenset({INTEGRITY_EXTERNAL})
    tool_extra = frozenset()
    if registry is not None:
        if not isinstance(registry, dict):
            raise _malformed("registry must be a dict")
        unknown = set(registry) - {"assertable_tags", "tool_integrity"}
        if unknown:
            raise _malformed("unknown registry keys %r"
                             % (sorted(unknown),))
        assertable = (assertable
                      | _check_tag_set(
                          registry.get("assertable_tags", []),
                          "assertable_tags"))
        tool_map = registry.get("tool_integrity", {})
        if not isinstance(tool_map, dict):
            raise _malformed("tool_integrity must be a dict")
        for tname, ttags in tool_map.items():
            _check_tag(tname, "tool_integrity key")
            if tname == tool_name:
                # Deployment-declared: the deployment is the trust
                # authority for its own registry.
                tool_extra = _check_tag_set(ttags, "tool_integrity tags")
    secrecy = _check_tag_set(provenance.get("secrecy", []),
                             "provenance secrecy")
    integrity = _check_tag_set(provenance.get("integrity", []),
                               "provenance integrity")
    unassertable = ((integrity - assertable - tool_extra)
                    | ((integrity & _NON_ASSERTABLE_INTEGRITY)
                       - tool_extra))
    if unassertable:
        raise OutputIFCError(
            "ifc-privilege-denied",
            "unendorsed trust claim %r on tool %r: use an Endorsement "
            "privilege" % (sorted(unassertable), tool_name))
    label = Label(SecrecyLabel(secrecy),
                  IntegrityLabel(integrity | tool_extra
                                 | {INTEGRITY_EXTERNAL}))
    return _label_to_dict(label)


def check_sink(labeled, sink):
    """Check whether labeled data may flow to ``sink``.

    ``sink`` is a name (resolved against ``SINK_DEFAULTS``) or an
    explicit policy dict ``{"name","secrecy","integrity"}``. Returns
    an allow record; raises a machine-coded refusal otherwise.
    """
    label = (_label_from_dict(labeled) if not isinstance(labeled, Label)
             else labeled)
    if isinstance(sink, str):
        if sink not in SINK_DEFAULTS:
            raise OutputIFCError("ifc-sink-unmapped",
                                 "unknown sink %r" % (sink,))
        name = sink
        sink_secrecy = SecrecyLabel(SINK_DEFAULTS[sink]["secrecy"])
        sink_integrity = IntegrityLabel(SINK_DEFAULTS[sink]["integrity"])
    else:
        name, sink_secrecy, sink_integrity = _check_sink_policy(sink)
    if not label.secrecy.can_flow_to(sink_secrecy):
        leaking = label.secrecy.tags - sink_secrecy.tags
        raise OutputIFCError(
            "ifc-secrecy-flow-denied",
            "secrecy tags %r would leak to sink %r"
            % (sorted(leaking), name))
    if not label.integrity.can_flow_to(sink_integrity):
        missing = sink_integrity.tags - label.integrity.tags
        raise OutputIFCError(
            "ifc-integrity-flow-denied",
            "sink %r requires trust tags %r" % (name, sorted(missing)))
    return {"allowed": True,
            "sink": name,
            "label": _label_to_dict(label),
            "checked": ["secrecy", "integrity"],
            "out_of_scope": [
                "label assignment consumes caller-declared provenance",
                "sink policies are deployment-declared"]}


def combine_outputs(*labeled):
    """Conservatively combine labels of data being merged.

    Taint rule: secrecy joins (union), integrity meets
    (intersection). One tainted part refuses the whole downstream.
    """
    if not labeled:
        raise _malformed("combine_outputs needs at least one label")
    labels = [(_label_from_dict(l) if not isinstance(l, Label) else l)
              for l in labeled]
    secrecy = frozenset().union(*(l.secrecy.tags for l in labels))
    integrity = (labels[0].integrity.tags.intersection(
        *(l.integrity.tags for l in labels[1:])))
    return _label_to_dict(Label(SecrecyLabel(secrecy),
                                IntegrityLabel(integrity)))


def issue_grant(privilege, granted_by, authorization, ttl_seconds, now):
    """Issue a privilege grant. The authorization evidence is
    validated here; expiry and scope are enforced at exercise time.
    """
    if not isinstance(privilege, dict):
        raise _malformed("privilege must be a dict")
    unknown = set(privilege) - {"declassification", "endorsement"}
    if unknown:
        raise _malformed("unknown privilege keys %r" % (sorted(unknown),))
    priv = {
        "declassification": sorted(_check_tag_set(
            privilege.get("declassification", []), "declassification")),
        "endorsement": sorted(_check_tag_set(
            privilege.get("endorsement", []), "endorsement")),
    }
    if not isinstance(granted_by, str) or not granted_by:
        raise _malformed("bad granted_by %r" % (granted_by,))
    if not isinstance(authorization, dict):
        raise OutputIFCError("ifc-privilege-unauthorized",
                             "authorization must be a dict")
    kind = authorization.get("kind")
    ref = authorization.get("ref")
    if kind not in ("human-approval", "deployment-role"):
        raise OutputIFCError(
            "ifc-privilege-unauthorized",
            "authorization kind %r is not human-approval or "
            "deployment-role" % (kind,))
    if not isinstance(ref, str) or not ref:
        raise OutputIFCError("ifc-privilege-unauthorized",
                             "authorization ref must be a non-empty string")
    if (isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int) or ttl_seconds <= 0):
        raise _malformed("bad ttl_seconds %r" % (ttl_seconds,))
    issued = _check_now(now)
    expires = issued + timedelta(seconds=ttl_seconds)
    body = {
        "v": _GRANT_VERSION,
        "privilege": priv,
        "granted_by": granted_by,
        "authorization": {"kind": kind, "ref": ref},
        "issued_at": now,
        "expires_at": expires.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
    }
    grant = dict(body)
    grant["grant_digest"] = _digest(body)
    return grant


def _check_grant(grant):
    if not isinstance(grant, dict):
        raise OutputIFCError("ifc-privilege-unauthorized",
                             "grant must be a dict")
    digest = grant.get("grant_digest")
    body = {k: v for k, v in grant.items() if k != "grant_digest"}
    if not isinstance(digest, str) or _digest(body) != digest:
        raise OutputIFCError("ifc-privilege-unauthorized",
                             "grant digest mismatch: tampered or forged")
    return body


def exercise_privilege(grant, label, operation, tags, audit, now):
    """Exercise a declassification/endorsement privilege.

    Requires: a valid grant (digest-bound, authorized, unexpired),
    requested tags within the privilege scope, and a callable
    ``audit`` hook. The audit hook receives the complete exercise
    record; without it the call refuses (``ifc-audit-required``) --
    privilege use is never silent.
    """
    if operation not in ("declassify", "endorse"):
        raise _malformed("bad operation %r" % (operation,))
    body = _check_grant(grant)
    data_label = (_label_from_dict(label)
                  if not isinstance(label, Label) else label)
    tag_set = _check_tag_set(tags, "tags")
    if not tag_set:
        raise _malformed("privilege exercise needs at least one tag")
    at = _check_now(now)
    expires = _check_now(body["expires_at"])
    if at > expires:
        raise OutputIFCError("ifc-privilege-expired",
                             "grant expired at %s" % (body["expires_at"],))
    scope = frozenset(body["privilege"][_OPERATION_PRIVILEGE_KEY[operation]])
    if not scope:
        raise OutputIFCError(
            "ifc-privilege-denied",
            "grant confers no %s privilege" % (operation,))
    if not tag_set <= scope:
        raise OutputIFCError(
            "ifc-privilege-scope-denied",
            "cannot %s %r: outside privilege %r"
            % (operation, sorted(tag_set - scope), sorted(scope)))
    if not callable(audit):
        raise OutputIFCError(
            "ifc-audit-required",
            "privilege exercise without an audit hook is refused: "
            "privilege use is never silent")
    if operation == "declassify":
        new_label = Label(
            Declassification(scope).declassify(data_label.secrecy, tag_set),
            data_label.integrity)
    else:
        new_label = Label(
            data_label.secrecy,
            Endorsement(scope).endorse(data_label.integrity, tag_set))
    record = {
        "event": "ifc-privilege-exercised",
        "operation": operation,
        "tags": sorted(tag_set),
        "grant_digest": grant["grant_digest"],
        "granted_by": body["granted_by"],
        "authorization": body["authorization"],
        "label_before": _label_to_dict(data_label),
        "label_after": _label_to_dict(new_label),
        "at": now,
    }
    record["record_digest"] = _digest(
        {k: v for k, v in record.items() if k != "record_digest"})
    audit(record)
    return {"label": _label_to_dict(new_label),
            "audit_record": record,
            "audit_digest": record["record_digest"]}
