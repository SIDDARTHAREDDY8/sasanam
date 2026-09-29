"""Capability grants at the tool-call boundary (wave-202 lane E).

WASI capability-model discipline (ADAPT, never vendored -- wasmtime is
Apache-2.0+LLVM, wasmer is MIT; this is a stdlib-only re-implementation
of the discipline, verified against the wave-201 prospectus license
notes): a tool call receives ONLY explicitly granted capabilities, as
opaque handle tokens -- never raw paths, hosts, or credential strings.
No ambient authority. Attenuation narrows, never widens. Delegation is
subset-checked at the boundary.

The wave-202 capability-grant SPIKE proved the discipline in-process and
then proved its limit: a deliberately adversarial function in the SAME
process breaks out via closure introspection (``io.read.__closure__``).
The rogue handle was useless without grant membership, but the lesson
stands -- the object graph is a correctness aid, not a security
boundary. THIS module therefore enforces at the sandbox/process
boundary:

  * The parent process holds the grant registry. It never crosses into
    the child.
  * The tool function executes in a child process inside the product's
    sandbox jail (``gov/sandbox.py`` -- pivot-root, netns, pidns,
    privdrop, all REQUIRED: a missing layer refuses the dispatch
    fail-closed before any tool code runs).
  * The child receives a sealed facade over STAGED content: for each
    granted capability the parent copies exactly the granted bytes into
    the jail under an opaque token name. The child never learns real
    paths, hosts, or secret values (credentials stage a sentinel id --
    the existing sentinel-substitution story).
  * Writes are committed by the PARENT after the child exits, and only
    for tokens whose dispatch record holds the write right. A child
    that bypasses the facade and drops files directly into the outbox
    still cannot escalate: unknown tokens and ungranted rights refuse
    LOUD at commit and the dispatch raises.

Grant lifecycle: a GrantSet is minted from a verified skill manifest +
deployment grant policy + approval packet (``derive_grants``), bound to
one decision_id, and single-use -- the registry consumes it at dispatch
and a second dispatch with the same set is refused.

Stdlib only. Deterministic: token assignment, staging layout, and
grant digests derive from the sorted capability list -- no clock, no
randomness in the build path.

Honest residuals (NOT claimed by this module):
  * Covert channels: grants bound authority, not information flow.
  * Real network mediation: net capabilities stage deployment-
    registered canned responses; live proxied egress needs the egress-
    wall composition (follow-on).
  * Grant expiry/revocation: unaddressed (cf. the wave-201 rotation-
    policy lane for the key side).
  * Executor rewiring: ``derive_grants`` is the dispatch-point
    adjacency for ``_execute_approved_locked``; the 11k-line executor
    itself is not rewired here (follow-on).
"""

import hashlib
import inspect
import json
import os
import re
import shutil
import textwrap

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GrantError(Exception):
    """Base class for capability-grant failures."""


class GrantRefused(GrantError):
    """A grant operation was refused: loud, fail-closed, audit-logged."""


class GrantMintError(GrantError):
    """A grant set could not be minted (bad manifest/policy/approval)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Value layer: Capability / Handle / GrantSet
# (ported from the wave-202 spike prototype; the in-process executor is
# gone -- enforcement now lives at the process boundary below.)
# ---------------------------------------------------------------------------


class Capability(object):
    """One capability: (kind, resource, rights). Immutable value object.

    kind: "file" | "net" | "credential"
    resource: realpath-pinned absolute path (file), lowercase host (net),
              scope string (credential)
    rights: frozenset subset of the kind's right vocabulary.
    """

    __slots__ = ("kind", "resource", "rights")

    _RIGHTS = {
        "file": frozenset({"read", "write"}),
        "net": frozenset({"connect"}),
        "credential": frozenset({"use"}),
    }

    def __init__(self, kind, resource, rights):
        if kind not in self._RIGHTS:
            raise GrantError("unknown capability kind %r" % (kind,))
        rights = frozenset(rights)
        unknown = rights - self._RIGHTS[kind]
        if unknown:
            raise GrantError(
                "unknown rights %r for kind %r" % (sorted(unknown), kind))
        if not rights:
            raise GrantError("capability with empty rights is meaningless")
        if not isinstance(resource, str) or not resource:
            raise GrantError("capability resource must be a non-empty string")
        if kind == "net":
            # Host identity is case-insensitive; normalize at the value
            # layer so two spellings can never become two capabilities.
            resource = resource.lower()
        self.kind = kind
        self.resource = resource
        self.rights = rights

    def narrower_than(self, other):
        """True when self adds nothing beyond other (same kind+resource)."""
        return (isinstance(other, Capability) and
                self.kind == other.kind and
                self.resource == other.resource and
                self.rights <= other.rights)

    def is_subset_of(self, other):
        """Alias of :meth:`narrower_than` (one capability's worth)."""
        return self.narrower_than(other)

    def covers(self, kind, resource, right):
        return (self.kind == kind and self.resource == resource
                and right in self.rights)

    def attenuate(self, rights=None):
        """Return a narrowed copy. Attenuation can only remove rights."""
        new_rights = self.rights if rights is None else (
            self.rights & frozenset(rights))
        if not new_rights:
            raise GrantError("attenuation would leave an empty capability")
        return Capability(self.kind, self.resource, new_rights)

    def describe(self):
        """Auditor-visible description (no secret material ever lives here)."""
        return {"kind": self.kind, "resource": self.resource,
                "rights": sorted(self.rights)}

    def __hash__(self):
        return hash((self.kind, self.resource, self.rights))

    def __eq__(self, other):
        return (isinstance(other, Capability)
                and (self.kind, self.resource, self.rights)
                == (other.kind, other.resource, other.rights))

    def __eq__(self, other):
        return (isinstance(other, Capability) and
                self.kind == other.kind and
                self.resource == other.resource and
                self.rights == other.rights)

    def __hash__(self):
        return hash((self.kind, self.resource, self.rights))

    def __repr__(self):
        return "Capability(%r, %r, %r)" % (
            self.kind, self.resource, sorted(self.rights))


# The mint key is a module-private object: Handle construction without it
# raises GrantRefused. The key never crosses the process boundary -- the
# child never sees the Handle class at all.
_MINT_KEY = object()


class Handle(object):
    """Opaque parent-side handle to a capability.

    Tools never see Handles: the child protocol uses plain string tokens
    bound to a single dispatch. Handles exist so parent-side code (and
    unit tests) cannot forge capabilities without the mint key.
    """

    __slots__ = ("_capability", "_nonce")

    def __init__(self, _key, capability, nonce):
        if _key is not _MINT_KEY:
            raise GrantRefused("handles cannot be minted by tool code")
        if not isinstance(capability, Capability):
            raise GrantError("handle requires a Capability")
        self._capability = capability
        self._nonce = nonce

    @property
    def capability(self):
        return self._capability

    @property
    def label(self):
        # Deliberately coarse: kind + rights, never the raw resource.
        c = self._capability
        return "%s:%s" % (c.kind, ",".join(sorted(c.rights)))

    def __repr__(self):
        return "Handle(%s#%d)" % (self.label, self._nonce)


class GrantSet(object):
    """The explicit grant set for one tool call. Immutable.

    A GrantSet only becomes dispatchable once the registry issues it an
    id (``with_id``); a hand-built GrantSet carries no id and
    ``GrantDispatcher.dispatch`` refuses it -- this is what enforces the
    "minted from policy + approval" rule structurally.
    """

    __slots__ = ("_caps", "_ordered", "_grant_id")

    def __init__(self, capabilities):
        caps = frozenset(capabilities)
        for c in caps:
            if not isinstance(c, Capability):
                raise GrantError("GrantSet holds Capabilities only")
        self._caps = caps
        # Canonical order: tokens ("h1"...) are positional over THIS
        # order everywhere (child manifest, parent commit record,
        # lookup_token). Never frozenset iteration order, which varies
        # with hash randomization.
        self._ordered = tuple(sorted(
            caps, key=lambda c: (c.kind, c.resource, sorted(c.rights))))
        self._grant_id = None

    @property
    def grant_id(self):
        return self._grant_id

    def with_id(self, grant_id):
        if self._grant_id is not None:
            raise GrantError("GrantSet id is immutable once issued")
        if not isinstance(grant_id, str) or not grant_id:
            raise GrantError("grant_id must be a non-empty string")
        clone = GrantSet(self._caps)
        clone._grant_id = grant_id
        return clone

    def __len__(self):
        return len(self._caps)

    def __iter__(self):
        return iter(self._ordered)

    def allows(self, kind, resource, right):
        return any(c.covers(kind, resource, right) for c in self._caps)

    def lookup_token(self, token):
        """Map a child-visible token to its capability (parent side).

        Tokens are deterministic (``"h1"``...) over the canonical
        capability order. Unknown or forged tokens refuse loudly.
        """
        idx = None
        if isinstance(token, str) and token.startswith("h"):
            try:
                idx = int(token[1:]) - 1
            except ValueError:
                idx = None
        if idx is None or idx < 0 or idx >= len(self._ordered):
            raise GrantRefused("unknown capability token %r" % (token,))
        return self._ordered[idx]

    def attenuate(self, predicate):
        """Subset of capabilities passing predicate. Cannot widen."""
        return GrantSet(c for c in self._caps if predicate(c))

    def is_subset_of(self, other):
        """True when every capability here is narrower than (or equal
        to) some capability in ``other``. This is the attenuation
        ordering -- a read-only narrowing of a read+write grant IS a
        subset even though the two Capability objects differ."""
        return all(any(c.is_subset_of(p) for p in other._caps)
                   for c in self._caps)

    def digest(self):
        """sha256 over the canonical sorted capability descriptions."""
        descs = sorted((c.describe() for c in self._caps),
                       key=lambda d: (d["kind"], d["resource"],
                                      ",".join(d["rights"])))
        return _sha256_hex(_canonical(
            {"v": 1, "capabilities": descs}))

    def describe(self):
        return [c.describe() for c in sorted(
            self._caps, key=lambda c: (c.kind, c.resource,
                                       sorted(c.rights)))]

    def __repr__(self):
        return "GrantSet(%d caps, id=%s)" % (len(self._caps),
                                             self._grant_id)


# ---------------------------------------------------------------------------
# GrantPolicy: deployment-owned label -> concrete-resource bindings
# ---------------------------------------------------------------------------


class GrantPolicy(object):
    """Binds manifest grant labels to concrete resources.

    The verified skill manifest declares *labels* (category -> [labels]);
    the deployment owns the binding of each label to a concrete
    capability (a realpath-pinned file, a registered host, a credential
    scope). An unbound label refuses LOUD at derivation -- a manifest can
    never conjure authority the deployment did not bind.
    """

    def __init__(self, *, fs_root):
        if not isinstance(fs_root, str) or not fs_root:
            raise GrantError("fs_root must be a non-empty string")
        real = os.path.realpath(fs_root)
        if not os.path.isdir(real):
            raise GrantError("fs_root %r is not a directory" % (fs_root,))
        self._fs_root = real
        self._file = {}        # label -> (abspath, rights)
        self._net = {}         # label -> (host, rights, response_bytes)
        self._credential = {}  # label -> (scope, rights, sentinel_id)

    @property
    def fs_root(self):
        return self._fs_root

    def _pin_path(self, relpath):
        abspath = os.path.realpath(os.path.join(self._fs_root, relpath))
        if not (abspath == self._fs_root
                or abspath.startswith(self._fs_root + os.sep)):
            raise GrantError("binding escapes fs_root: %r" % (relpath,))
        return abspath

    def bind_file(self, label, relpath, rights):
        """Bind a label to a file under fs_root with the given rights."""
        if not isinstance(label, str) or not label:
            raise GrantError("binding label must be a non-empty string")
        if label in self._file:
            raise GrantError("duplicate file binding for label %r" % (label,))
        abspath = self._pin_path(relpath)
        # Validate the rights vocabulary now, not at dispatch.
        Capability("file", abspath, rights)
        self._file[label] = (abspath, frozenset(rights))
        return self

    def bind_net(self, label, host, rights, response):
        """Bind a label to a host; the staged response is canned bytes."""
        if not isinstance(label, str) or not label:
            raise GrantError("binding label must be a non-empty string")
        if label in self._net:
            raise GrantError("duplicate net binding for label %r" % (label,))
        if not isinstance(host, str) or not host:
            raise GrantError("net binding host must be a non-empty string")
        Capability("net", host.lower(), rights)
        if isinstance(response, str):
            response = response.encode("utf-8")
        if not isinstance(response, (bytes, bytearray)):
            raise GrantError("net binding response must be bytes or str")
        self._net[label] = (host.lower(), frozenset(rights), bytes(response))
        return self

    def bind_credential(self, label, scope, rights, sentinel_id):
        """Bind a label to a credential scope.

        Only the sentinel id is ever staged into the jail -- the real
        secret value never enters this module (sentinel-substitution
        story). ``sentinel_id`` is what the tool receives.
        """
        if not isinstance(label, str) or not label:
            raise GrantError("binding label must be a non-empty string")
        if label in self._credential:
            raise GrantError(
                "duplicate credential binding for label %r" % (label,))
        if not isinstance(scope, str) or not scope:
            raise GrantError("credential scope must be a non-empty string")
        Capability("credential", scope, rights)
        if not isinstance(sentinel_id, str) or not sentinel_id:
            raise GrantError("sentinel_id must be a non-empty string")
        self._credential[label] = (scope, frozenset(rights), sentinel_id)
        return self

    def resolve(self, kind, label):
        """Resolve one (kind, label) to a Capability. Unknown -> raise."""
        if kind == "file":
            try:
                abspath, rights = self._file[label]
            except KeyError:
                raise GrantRefused(
                    "file label %r is not bound by the deployment "
                    "policy" % (label,))
            return Capability("file", abspath, rights)
        if kind == "net":
            try:
                host, rights, _response = self._net[label]
            except KeyError:
                raise GrantRefused(
                    "net label %r is not bound by the deployment "
                    "policy" % (label,))
            return Capability("net", host, rights)
        if kind == "credential":
            try:
                scope, rights, _sentinel = self._credential[label]
            except KeyError:
                raise GrantRefused(
                    "credential label %r is not bound by the deployment "
                    "policy" % (label,))
            return Capability("credential", scope, rights)
        raise GrantError("unknown capability kind %r" % (kind,))

    def staged_payload(self, capability):
        """The exact bytes to stage into the jail for one capability.

        file/read: the current bytes of the pinned path (read at stage
            time; the path is re-pinned at commit for writes).
        net/connect: the deployment-registered canned response.
        credential/use: the sentinel id (never a secret).
        Returns None when nothing is staged (e.g. file/write-only).
        """
        if capability.kind == "file":
            if "read" not in capability.rights:
                return None
            with open(capability.resource, "rb") as f:
                return f.read()
        if capability.kind == "net":
            for _label, (host, _rights, response) in self._net.items():
                if host == capability.resource:
                    return response
            raise GrantError(
                "no staged response for host %r" % (capability.resource,))
        if capability.kind == "credential":
            for _label, (scope, _rights, sentinel) in self._credential.items():
                if scope == capability.resource:
                    return sentinel.encode("utf-8")
            raise GrantError(
                "no sentinel for scope %r" % (capability.resource,))
        raise GrantError("unknown capability kind %r" % (capability.kind,))


# Manifest categories (gov/capability_manifests.py CATEGORIES) mapped to
# the grant kinds of this lane. "env" and "exec" have no grant-kind
# counterpart here: the child environment is scrubbed by the sandbox and
# exec is out of scope -- a manifest declaring them refuses LOUD at
# derivation rather than silently dropping the declaration. "tools"
# names the sub-tools this tool may delegate to (parent-side allowlist).
_CATEGORY_KIND = {
    "filesystem": "file",
    "egress": "net",
    "secrets": "credential",
    "tools": None,  # delegation allowlist, not a grant kind
}


def derive_grants(*, verified_manifest, grant_policy, approval,
                  decision_id, registry, approval_records=None):
    """Mint the GrantSet for one tool call.

    ``verified_manifest`` is the manifest dict as verified by
    ``gov.capability_manifests.verify_skill_manifest`` -- this function
    does NOT re-verify signatures (separation of concerns); it validates
    the shape LOUD and derives grants from the declared labels.
    Shape: {"skill_id": str, "capabilities": {category: [labels]}}.

    ``grant_policy`` is the deployment's GrantPolicy binding labels to
    concrete resources. ``approval`` is {"approval_id": str,
    "record_digest": hex64} -- the approval that authorized this call
    (the BOM approval discipline: an id without a resolvable record
    digest refuses).

    ``approval_records`` (optional) is {approval_id: full approval
    record}. When supplied, the packet's own digest is re-derived with
    ``gov.approvals.approval_record_digest`` and must EQUAL the
    supplied ``record_digest`` -- binding the grant to the exact
    approval packet that authorized the call, not just to a
    digest-shaped string. A mismatch or unresolvable record refuses
    loud. When omitted, only the shape contract above is enforced
    (the caller verified the packet out of band).

    Returns (GrantSet-with-id, delegation_allowlist frozenset).
    Every refusal is loud (GrantRefused/GrantMintError) and recorded by
    the registry.
    """
    if not isinstance(decision_id, str) or not decision_id:
        raise GrantMintError("decision_id must be a non-empty string")
    if not isinstance(verified_manifest, dict):
        raise GrantMintError("verified_manifest must be a dict")
    skill_id = verified_manifest.get("skill_id")
    if not isinstance(skill_id, str) or not skill_id:
        raise GrantMintError("manifest skill_id must be a non-empty string")
    declared = verified_manifest.get("capabilities", {})
    if not isinstance(declared, dict):
        raise GrantMintError("manifest capabilities must be a dict")
    if not isinstance(approval, dict):
        raise GrantMintError("approval must be a dict")
    approval_id = approval.get("approval_id")
    record_digest = approval.get("record_digest")
    if not isinstance(approval_id, str) or not approval_id:
        raise GrantMintError("approval approval_id must be a non-empty "
                             "string")
    if not _is_hex64(record_digest):
        raise GrantMintError(
            "approval record_digest must be 64-char lowercase hex "
            "(an approval id without a resolvable record digest refuses)")

    # Optional exact packet binding (see docstring): re-derive the
    # packet's own digest and require equality. Lazy import: gov.approvals
    # is heavy and this module must stay importable standalone.
    if approval_records is not None:
        try:
            record = approval_records[approval_id]
        except (KeyError, TypeError, AttributeError):
            record = None
        if not isinstance(record, dict):
            registry.refuse(
                decision_id=decision_id,
                reason="approval-record-unresolvable",
                detail={"approval_id": approval_id})
            raise GrantRefused(
                "approval id %r has no resolvable record "
                "(fail-closed)" % (approval_id,))
        from gov.approvals import approval_record_digest
        try:
            actual_digest = approval_record_digest(record)
        except Exception as e:
            registry.refuse(
                decision_id=decision_id,
                reason="approval-record-undigestible",
                detail={"approval_id": approval_id,
                        "error": "%r" % (e,)})
            raise GrantRefused(
                "approval record for %r cannot be digested "
                "(fail-closed)" % (approval_id,))
        if actual_digest != record_digest:
            registry.refuse(
                decision_id=decision_id,
                reason="approval-record-digest-mismatch",
                detail={"approval_id": approval_id})
            raise GrantRefused(
                "approval record digest does not match the supplied "
                "packet digest (fail-closed: the grant is bound to the "
                "exact approval packet)")

    capabilities = []
    delegation_allowlist = set()
    for category, labels in declared.items():
        if category not in _CATEGORY_KIND:
            registry.refuse(decision_id=decision_id,
                            reason="unknown-manifest-category",
                            detail={"category": str(category),
                                    "skill_id": skill_id})
            raise GrantRefused(
                "manifest category %r has no grant-kind mapping "
                "(fail-closed)" % (category,))
        if not isinstance(labels, list) or not all(
                isinstance(l, str) and l for l in labels):
            raise GrantMintError(
                "manifest category %r labels must be a list of non-empty "
                "strings" % (category,))
        kind = _CATEGORY_KIND[category]
        if kind is None:  # "tools": delegation allowlist
            delegation_allowlist.update(labels)
            continue
        for label in labels:
            try:
                capabilities.append(grant_policy.resolve(kind, label))
            except GrantRefused:
                registry.refuse(decision_id=decision_id,
                                reason="unbound-grant-label",
                                detail={"kind": kind, "label": label,
                                        "skill_id": skill_id})
                raise
    grant_set = registry.mint(capabilities, decision_id=decision_id,
                              provenance={"skill_id": skill_id,
                                          "approval_id": approval_id,
                                          "approval_record_digest":
                                              record_digest})
    return grant_set, frozenset(delegation_allowlist)


# ---------------------------------------------------------------------------
# GrantRegistry: parent-side mint / consume / refusal records.
# Lives ONLY in the parent process. Never serialized to the child.
# ---------------------------------------------------------------------------


class GrantRegistry(object):
    """Owns grant-set ids, single-use lifecycle, and refusal records."""

    def __init__(self, audit_log=None):
        self._counter = 0
        self._issued = {}   # grant_id -> record dict
        self._handles = {}  # nonce -> Capability (parent-side mint)
        self._nonce = 0
        self.refusals = []  # in-memory loud refusal trail (spike parity)
        self.events = []  # every audited event, including refusals
        self._audit_log = audit_log

    def _audit(self, event):
        entry = dict(event)
        entry["component"] = "capability_grants"
        self.events.append(entry)
        if self._audit_log is not None:
            self._audit_log.append(entry)

    def refuse(self, *, decision_id, reason, detail=None):
        """Record a loud refusal (in-memory trail + audit chain)."""
        event = {"type": "capability_grant_refusal",
                 "decision_id": decision_id, "reason": reason}
        if detail is not None:
            event["detail"] = detail
        self.refusals.append(dict(event))
        self._audit(event)

    def mint(self, capabilities, *, decision_id, provenance=None):
        """Issue an id-bound GrantSet for one decision. Loud on misuse."""
        if not isinstance(decision_id, str) or not decision_id:
            raise GrantMintError("decision_id must be a non-empty string")
        grant_set = GrantSet(capabilities)
        self._counter += 1
        grant_id = _sha256_hex(_canonical({
            "v": 1, "domain": "capability-grant",
            "decision_id": decision_id,
            "counter": self._counter,
            "grant_digest": grant_set.digest(),
        }))
        if grant_id in self._issued:
            # Counter collision is impossible without a sha256 break;
            # fail closed anyway rather than aliasing two grant sets.
            raise GrantError("grant id collision (fail-closed)")
        issued = grant_set.with_id(grant_id)
        self._issued[grant_id] = {
            "grant_set": issued,
            "decision_id": decision_id,
            "consumed": False,
            "provenance": dict(provenance or {}),
        }
        self._audit({"type": "capability_grant_mint",
                     "decision_id": decision_id,
                     "grant_id": grant_id,
                     "grant_digest": issued.digest(),
                     "capability_count": len(issued)})
        return issued

    def register_subset(self, parent_grant_id, sub_grant_set, *,
                        decision_id):
        """Subset-check a delegation and issue it an id. Loud on widen."""
        parent = self._issued.get(parent_grant_id)
        if parent is None:
            self.refuse(decision_id=decision_id,
                        reason="delegation-unknown-parent",
                        detail={"parent_grant_id": parent_grant_id})
            raise GrantRefused("delegation from unknown grant id")
        if parent["decision_id"] != decision_id:
            self.refuse(decision_id=decision_id,
                        reason="delegation-decision-mismatch",
                        detail={"parent_grant_id": parent_grant_id})
            raise GrantRefused("delegation crosses decision_id boundary")
        if not isinstance(sub_grant_set, GrantSet):
            raise GrantRefused("delegation requires a GrantSet")
        if not sub_grant_set.is_subset_of(parent["grant_set"]):
            self.refuse(decision_id=decision_id,
                        reason="delegation-would-widen",
                        detail={"parent_grant_id": parent_grant_id})
            raise GrantRefused(
                "delegation would widen authority beyond the caller's "
                "grants")
        return self.mint(sub_grant_set, decision_id=decision_id,
                         provenance={"delegated_from": parent_grant_id})

    def consume(self, grant_id, *, decision_id):
        """Single-use: mark a grant set consumed for its decision."""
        record = self._issued.get(grant_id)
        if record is None:
            self.refuse(decision_id=decision_id,
                        reason="unknown-grant-id",
                        detail={"grant_id": grant_id})
            raise GrantRefused("unknown grant id (never minted here)")
        if record["decision_id"] != decision_id:
            self.refuse(decision_id=decision_id,
                        reason="grant-decision-mismatch",
                        detail={"grant_id": grant_id})
            raise GrantRefused("grant id bound to a different decision_id")
        if record["consumed"]:
            self.refuse(decision_id=decision_id,
                        reason="grant-already-consumed",
                        detail={"grant_id": grant_id})
            raise GrantRefused("grant set is single-use and already "
                               "consumed")
        record["consumed"] = True
        return record["grant_set"]

    def mint_handle(self, capability):
        """Parent-side opaque handle (unit-test / caller-side use)."""
        if not isinstance(capability, Capability):
            raise GrantError("handle requires a Capability")
        self._nonce += 1
        handle = Handle(_MINT_KEY, capability, self._nonce)
        self._handles[self._nonce] = capability
        return handle

    def describe_grants(self, grant_id):
        """Auditor view: canonical capability list for a grant id."""
        record = self._issued.get(grant_id)
        if record is None:
            raise GrantError("unknown grant id %r" % (grant_id,))
        return record["grant_set"].describe()


# ---------------------------------------------------------------------------
# Child payload: the sealed facade that runs INSIDE the sandbox jail.
#
# This source is written into the staging dir and executed by the child
# interpreter. It is deliberately self-contained: stdlib only, no gov
# imports, no registry, no mint key, no Handle class. The ONLY authority
# representation here is the parent-generated manifest (token ->
# {kind, rights, staged}). Closure introspection inside this process can
# find at most the staged-path map -- escalating it is useless because
# the parent commits only what the dispatch record allows, and the jail
# contains nothing but granted content.
# ---------------------------------------------------------------------------

_CHILD_SOURCE = r'''
"""Capability-grant child payload (generated by gov/capability_grants.py)."""

import json
import os
import sys
import traceback


def _jail():
    return os.getcwd()


class _Refused(Exception):
    """Local refusal signal. Never crosses the boundary as authority."""


def _load_manifest():
    with open(os.path.join(_jail(), "manifest.json"), "r",
              encoding="utf-8") as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict) or "handles" not in manifest:
        raise _Refused("malformed grant manifest")
    return manifest


class _ToolIO(object):
    """Sealed I/O facade. Writes raise; unknown ops raise AttributeError."""

    def __init__(self, _ops):
        object.__setattr__(self, "_ops", dict(_ops))

    def __getattr__(self, name):
        try:
            return object.__getattribute__(self, "_ops")[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        raise _Refused("ToolIO is sealed")


def _unserializable(o):
    raise TypeError("not JSON serializable: %r" % type(o).__name__)


def _run():
    manifest = _load_manifest()
    handles = manifest["handles"]
    entry = manifest["entry"]
    kwargs = manifest.get("kwargs", {})
    refusals = []
    writes = []

    def _refuse(op, reason):
        refusals.append({"op": op, "reason": reason})

    def _lookup(token, op):
        # Tokens are parent-generated ("h1", ...). Anything else --
        # raw paths, forged tokens, cross-dispatch tokens -- is unknown
        # in THIS dispatch's manifest and refuses.
        if not isinstance(token, str):
            _refuse(op, "raw value passed where a handle token is required")
            raise _Refused("raw values are not capabilities")
        spec = handles.get(token)
        if not isinstance(spec, dict):
            _refuse(op, "unknown or forged handle token")
            raise _Refused("unknown handle token")
        return spec

    def _need(spec, right, op, token):
        if right not in spec.get("rights", []):
            _refuse(op, "right %r not held" % (right,))
            raise _Refused("right not granted for token")

    def _staged(spec):
        # Defense in depth: re-anchor under the jail even though the
        # manifest is parent-generated. A staged name can never escape
        # the jail's in/ directory.
        name = os.path.basename(spec["staged"])
        return os.path.join(_jail(), "in", name)

    def read(token):
        spec = _lookup(token, "read")
        kind = spec.get("kind")
        right = {"file": "read", "net": "connect",
                 "credential": "use"}.get(kind)
        if right is None:
            _refuse("read", "kind not readable")
            raise _Refused("kind not readable")
        _need(spec, right, "read", token)
        with open(_staged(spec), "rb") as f:
            data = f.read()
        if kind == "credential":
            # The staged bytes are the sentinel id -- never a secret.
            return data.decode("utf-8")
        return data

    def write(token, data):
        spec = _lookup(token, "write")
        if spec.get("kind") != "file":
            _refuse("write", "kind not writable")
            raise _Refused("kind not writable")
        _need(spec, "write", "write", token)
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, (bytes, bytearray)):
            _refuse("write", "data must be bytes or str")
            raise _Refused("bad data type")
        # The facade writes only under its own token name; the parent
        # re-validates every outbox file against the dispatch record at
        # commit -- a child that bypasses the facade cannot escalate.
        name = "".join(
            ch for ch in os.path.basename(token) if ch.isalnum()) or "x"
        dest = os.path.join(_jail(), "out", name)
        with open(dest, "wb") as f:
            f.write(bytes(data))
        writes.append({"token": token, "bytes": len(data)})
        return len(data)

    def connect(token):
        # Net capabilities stage the deployment-registered canned
        # response; live proxied egress is a documented residual.
        data = read(token)
        return data

    def use_credential(token):
        return read(token)

    io = _ToolIO({"read": read, "write": write, "connect": connect,
                  "use_credential": use_credential})

    sys.path.insert(0, _jail())
    tool_mod = __import__("tool")
    fn = getattr(tool_mod, entry)
    envelope = {"ok": False, "result": None, "refusals": refusals,
                "writes": writes, "error": None}
    try:
        result = fn(io, **kwargs)
    except _Refused as e:
        envelope["error"] = {"type": "refused", "message": str(e)}
    except Exception:
        envelope["error"] = {"type": "tool_error",
                             "message": traceback.format_exc(limit=8)}
    else:
        envelope["ok"] = True
        envelope["result"] = result
    # The envelope must be JSON-serializable; a bad return value is a
    # loud child-side error, never a parent parse surprise.
    try:
        payload = json.dumps(envelope, sort_keys=True, ensure_ascii=True,
                             default=_unserializable)
    except (TypeError, ValueError) as e:
        envelope = {"ok": False, "result": None, "refusals": refusals,
                    "writes": writes,
                    "error": {"type": "unserializable_result",
                              "message": str(e)}}
        payload = json.dumps(envelope, sort_keys=True, ensure_ascii=True)
    with open(os.path.join(_jail(), "result.json"), "w",
              encoding="utf-8") as f:
        f.write(payload)


if __name__ == "__main__":
    _run()
'''

_TOOL_NAME_RE = re.compile(r"^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_GOV_IMPORT_RE = re.compile(r"^\s*(import\s+gov\b|from\s+gov\b)",
                            re.MULTILINE)

# Result envelope size cap: a compromised child must not be able to
# exfiltrate unbounded data through the result channel.
_MAX_RESULT_BYTES = 1 << 20


def _default_sandbox(*, timeout):
    """The grant boundary's sandbox: every layer REQUIRED.

    pivot-root + netns + pidns + privdrop are require_*=True: if the
    platform cannot establish a layer, the dispatch refuses BEFORE any
    tool code runs (fail-closed). seccomp is unavailable on this VM's
    kernel config and is not required.

    deployment_mode defaults to production (least privilege) via the
    Sandbox constructor default; ``GOV_SANDBOX_DEPLOYMENT_MODE=staging``
    can opt a test harness back to staging semantics.
    """
    from gov.sandbox import Sandbox
    return Sandbox(
        timeout=timeout,
        use_netns=True, require_netns=True,
        use_pidns=True, require_pidns=True,
        use_pivot_root=True, require_pivot_root=True,
        drop_privs=True, require_privdrop=True,
        use_seccomp=False,
        cage_mode="strict",
    )


class DispatchResult(object):
    """The outcome of one grant-bounded tool call."""

    def __init__(self, *, ok, result, refusals, writes_committed,
                 grant_id, grant_digest, decision_id, sandbox_note,
                 capability_count, error=None):
        self.ok = ok
        self.result = result
        self.refusals = list(refusals)
        self.writes_committed = list(writes_committed)
        self.grant_id = grant_id
        self.grant_digest = grant_digest
        self.decision_id = decision_id
        self.sandbox_note = sandbox_note
        # Re-derived from the dispatch record -- never from the child.
        self.capability_count = capability_count
        self.error = error

    def bom_section(self):
        """The optional decision-BOM ``inputs.grants`` section."""
        return bom_grants_section(
            grant_digest=self.grant_digest, decision_id=self.decision_id,
            capability_count=self.capability_count)


class GrantDispatcher(object):
    """Runs tool functions behind the capability-grant process boundary.

    The registry (parent-side) holds all authority. Each dispatch:
      1. validates the tool source (module-level def, no closures, no
         gov imports, JSON-serializable kwargs),
      2. consumes the grant set single-use from the registry,
      3. stages EXACTLY the granted bytes into a fresh jail dir,
      4. runs the tool in the sandboxed child,
      5. chains child-reported refusals into the audit log,
      6. commits writes parent-side, re-validating every outbox file
         against the dispatch record (write right + kind + realpath
         containment), and
      7. returns a DispatchResult carrying the grant digest for the BOM.
    """

    def __init__(self, registry, *, sandbox=None, grant_policy=None,
                 python_bin="/usr/bin/python3", timeout=30.0,
                 staging_parent="/var/tmp"):
        if not isinstance(registry, GrantRegistry):
            raise GrantError("dispatcher requires a GrantRegistry")
        self._registry = registry
        self._sandbox = sandbox  # lazily defaulted (avoids import cycles)
        self._policy = grant_policy
        if not isinstance(python_bin, str) or not python_bin:
            raise GrantError("python_bin must be a non-empty string")
        self._python_bin = python_bin
        self._timeout = float(timeout)
        if not isinstance(staging_parent, str) or not staging_parent:
            raise GrantError("staging_parent must be a non-empty string")
        self._staging_parent = staging_parent
        self._dispatch_counter = 0

    @property
    def registry(self):
        return self._registry

    # -- tool source validation -------------------------------------------

    @staticmethod
    def _extract_tool_source(tool_fn):
        if not callable(tool_fn):
            raise GrantError("tool must be callable")
        name = getattr(tool_fn, "__name__", None)
        if not isinstance(name, str) or not name.isidentifier():
            raise GrantError("tool must have a plain function __name__")
        if getattr(tool_fn, "__closure__", None):
            raise GrantRefused(
                "tool function %r closes over parent state; grant-dispatched "
                "tools must be module-level defs (a closure would smuggle "
                "authority into the child)" % (name,))
        try:
            source = inspect.getsource(tool_fn)
        except (OSError, TypeError) as e:
            raise GrantError(
                "tool source is not extractable: %r" % (e,))
        source = textwrap.dedent(source)
        match = _TOOL_NAME_RE.match(source)
        if not match or match.group(1) != name:
            raise GrantRefused(
                "tool source must be a module-level 'def %s(...)' "
                "(no lambdas, no decorators hiding the def)" % (name,))
        if _GOV_IMPORT_RE.search(source):
            raise GrantRefused(
                "tool source must not import gov (the child never sees "
                "the parent package)")
        return name, source

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, tool_fn, grants, *, decision_id, kwargs=None,
                 delegation_allowlist=frozenset()):
        """Run tool_fn(io, **kwargs) with exactly ``grants``. Nothing else."""
        if not isinstance(grants, GrantSet):
            raise GrantRefused("dispatch requires a GrantSet")
        if grants.grant_id is None:
            self._registry.refuse(
                decision_id=decision_id, reason="grant-not-minted",
                detail={"hint": "GrantSets must be minted by the registry "
                                "(derive_grants) -- a hand-built set never "
                                "went through policy + approval"})
            raise GrantRefused(
                "grant set was not minted by the registry (policy + "
                "approval derivation is mandatory)")
        if not isinstance(decision_id, str) or not decision_id:
            raise GrantError("decision_id must be a non-empty string")
        kwargs = dict(kwargs or {})
        try:
            # Strict: no default=str. _canonical's fallback would accept
            # values that the child's json.dump later rejects.
            json.dumps({"kwargs": kwargs}, sort_keys=True,
                       ensure_ascii=True)
        except (TypeError, ValueError) as e:
            raise GrantError("dispatch kwargs must be JSON-serializable: %r"
                             % (e,))
        entry, tool_source = self._extract_tool_source(tool_fn)

        # Single-use: consume BEFORE staging. A consumed grant set can
        # never dispatch again, even if staging or the child fails.
        grant_set = self._registry.consume(grants.grant_id,
                                           decision_id=decision_id)
        allowlist = frozenset(delegation_allowlist or ())

        self._dispatch_counter += 1
        dispatch_tag = "gdispatch-%d" % self._dispatch_counter
        staging = os.path.join(self._staging_parent,
                               "%s-%d" % (dispatch_tag, os.getpid()))
        os.makedirs(staging, exist_ok=False)
        try:
            record = self._stage(tool_fn, tool_source, entry, grant_set,
                                 kwargs, staging, decision_id)
            envelope = self._run_child(staging, decision_id)
            result = self._commit(record, envelope, staging, decision_id)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return result

    def delegate(self, *, caller_grant_id, caller_allowlist, sub_tool_fn,
                 sub_grants, decision_id, kwargs=None):
        """Parent-mediated delegation: subset-check, then a fresh dispatch.

        A tool never delegates inside the child (the child facade has no
        delegate op -- attempting it raises AttributeError, recorded as
        a refusal). Delegation is re-dispatched by the parent: the
        sub-grants are subset-checked against the caller's grant set at
        the registry, the sub-tool name is checked against the caller's
        delegation allowlist, and the sub-tool runs in its own jail.
        """
        name = getattr(sub_tool_fn, "__name__", None)
        if name not in set(caller_allowlist or ()):
            self._registry.refuse(
                decision_id=decision_id, reason="delegation-not-allowlisted",
                detail={"sub_tool": str(name)})
            raise GrantRefused(
                "sub-tool %r is not in the caller's delegation allowlist"
                % (name,))
        sub_issued = self._registry.register_subset(
            caller_grant_id, sub_grants, decision_id=decision_id)
        return self.dispatch(sub_tool_fn, sub_issued,
                             decision_id=decision_id, kwargs=kwargs,
                             delegation_allowlist=caller_allowlist)

    # -- staging -----------------------------------------------------------

    def _stage(self, tool_fn, tool_source, entry, grant_set, kwargs,
               staging, decision_id):
        """Write the jail: payload, tool, manifest, staged inputs.

        Returns the dispatch record: token -> (Capability, staged_name).
        Tokens are deterministic ("h1"...) over the sorted capability
        list. Every staged byte derives from the grant policy; the real
        resource identifiers never enter the staging dir.
        """
        in_dir = os.path.join(staging, "in")
        out_dir = os.path.join(staging, "out")
        os.makedirs(in_dir)
        os.makedirs(out_dir)
        # The child (dropped to nobody) must be able to write its
        # outbox and result envelope; everything else stays
        # root-owned read-only. Pre-create result.json writable so the
        # non-pivot fallback (no top-level chown) works identically.
        os.chmod(out_dir, 0o777)
        result_path = os.path.join(staging, "result.json")
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("")
        os.chmod(result_path, 0o666)

        with open(os.path.join(staging, "child.py"), "w",
                  encoding="utf-8") as f:
            f.write(_CHILD_SOURCE)
        with open(os.path.join(staging, "tool.py"), "w",
                  encoding="utf-8") as f:
            f.write(tool_source)

        if self._policy is None:
            raise GrantError(
                "dispatcher requires a GrantPolicy to stage capabilities")
        ordered = list(grant_set)  # canonical GrantSet order
        handles = {}
        record = {}
        for index, cap in enumerate(ordered, start=1):
            token = "h%d" % index
            payload = self._policy.staged_payload(cap)
            staged_name = None
            if payload is not None:
                staged_name = "h%d" % index
                with open(os.path.join(in_dir, staged_name), "wb") as f:
                    f.write(payload)
            handles[token] = {"kind": cap.kind,
                              "rights": sorted(cap.rights),
                              "staged": staged_name or ""}
            record[token] = (cap, staged_name)
        manifest = {"handles": handles, "entry": entry, "kwargs": kwargs,
                    "decision_id": decision_id,
                    "grant_id": grant_set.grant_id}
        with open(os.path.join(staging, "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump(manifest, f, sort_keys=True, ensure_ascii=True)
        # Ownership: the staging tree is created by root and the umask
        # may be restrictive (e.g. 0007 -> 640 files). The child runs
        # dropped to 'nobody', so hand the whole tree to nobody while
        # still privileged -- otherwise the child cannot even read
        # child.py. The parent (root) retains full access; the child
        # can already write out/ and result.json by mode.
        from gov.sandbox import _nobody_ids
        _uid, _gid = _nobody_ids()
        for dirpath, _dirnames, filenames in os.walk(staging):
            os.chown(dirpath, _uid, _gid)
            for _name in filenames:
                os.chown(os.path.join(dirpath, _name), _uid, _gid)
        return {"record": record, "grant_set": grant_set,
                "capability_count": len(ordered)}

    # -- child execution ----------------------------------------------------

    def _run_child(self, staging, decision_id):
        sandbox = self._sandbox
        if sandbox is None:
            sandbox = _default_sandbox(timeout=self._timeout)
        argv = [self._python_bin, "/child.py"]
        try:
            result = sandbox.run(argv, cwd=staging, timeout=self._timeout)
        except Exception as e:
            # Sandbox loud refusals (required-layer-missing etc.) are
            # boundary failures: fail closed, audit, never commit.
            self._registry.refuse(
                decision_id=decision_id, reason="sandbox-refused",
                detail={"error": "%r" % (e,)})
            raise GrantError("grant boundary refused the run: %r" % (e,))
        if result.timed_out:
            self._registry.refuse(
                decision_id=decision_id, reason="tool-timed-out",
                detail={"note": result.note})
            raise GrantError("tool call timed out inside the grant jail "
                             "(fail-closed: no commit)")
        if not result.ok:
            self._registry.refuse(
                decision_id=decision_id, reason="tool-crashed",
                detail={"returncode": result.returncode,
                        "stderr": result.stderr[-2000:]})
            raise GrantError(
                "tool process failed in the grant jail (rc=%r; "
                "fail-closed: no commit)" % (result.returncode,))
        result_path = os.path.join(staging, "result.json")
        try:
            with open(result_path, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            raise GrantError(
                "tool produced no result envelope (fail-closed): %r" % (e,))
        if len(raw) > _MAX_RESULT_BYTES:
            raise GrantError("result envelope exceeds the size cap "
                             "(fail-closed)")
        try:
            envelope = json.loads(raw)
        except ValueError as e:
            raise GrantError(
                "result envelope is not JSON (fail-closed): %r" % (e,))
        if not isinstance(envelope, dict):
            raise GrantError("result envelope must be a dict (fail-closed)")
        envelope["_sandbox_note"] = result.note
        return envelope

    # -- commit --------------------------------------------------------------

    def _commit(self, record, envelope, staging, decision_id):
        dispatch_record = record["record"]
        grant_set = record["grant_set"]

        # A failed/refused tool must NEVER commit side effects: even if
        # the child staged an outbox write before failing, the parent
        # fails closed without committing. The outbox is still audited
        # (a suspicious outbox is evidence, not a commit).
        tool_ok = bool(envelope.get("ok"))
        if not tool_ok:
            out_dir = os.path.join(staging, "out")
            try:
                leftovers = sorted(os.listdir(out_dir))
            except OSError:
                leftovers = ["<unreadable>"]
            self._registry.refuse(
                decision_id=decision_id, reason="tool-failed-no-commit",
                detail={"child_error": str(envelope.get("error"))[:500],
                        "uncommitted_outbox": leftovers})
            raise GrantError(
                "tool call failed in the jail (fail-closed: no side "
                "effects committed)")

        # Chain every child-reported refusal into the audit log: LOUD.
        child_refusals = envelope.get("refusals", [])
        if not isinstance(child_refusals, list):
            raise GrantError("envelope refusals must be a list (fail-closed)")
        for refusal in child_refusals:
            self._registry.refuse(
                decision_id=decision_id, reason="child-refused-op",
                detail={"op": refusal.get("op"),
                        "why": refusal.get("reason")})

        # Commit writes parent-side. EVERY outbox file is re-validated
        # against the dispatch record: unknown token, non-file kind, or
        # missing write right refuses LOUD and fails the dispatch --
        # a child that bypasses the facade cannot escalate.
        out_dir = os.path.join(staging, "out")
        committed = []
        try:
            outbox = sorted(os.listdir(out_dir))
        except OSError as e:
            raise GrantError("outbox unreadable (fail-closed): %r" % (e,))
        for name in outbox:
            entry = dispatch_record.get(name)
            if entry is None:
                self._registry.refuse(
                    decision_id=decision_id,
                    reason="commit-unknown-token",
                    detail={"outbox_file": name})
                raise GrantError(
                    "outbox file %r matches no dispatched token "
                    "(fail-closed: possible facade bypass)" % (name,))
            cap, _staged = entry
            if cap.kind != "file" or "write" not in cap.rights:
                self._registry.refuse(
                    decision_id=decision_id,
                    reason="commit-right-missing",
                    detail={"token": name, "kind": cap.kind,
                            "rights": sorted(cap.rights)})
                raise GrantError(
                    "outbox file %r has no write grant (fail-closed)"
                    % (name,))
            # Re-pin the destination at commit: the staging-time realpath
            # must still resolve inside the policy fs root (TOCTOU
            # between stage and commit fails closed, not open).
            dest = os.path.realpath(cap.resource)
            fs_root = self._policy.fs_root
            if not (dest == fs_root
                    or dest.startswith(fs_root + os.sep)):
                self._registry.refuse(
                    decision_id=decision_id,
                    reason="commit-path-escape",
                    detail={"token": name})
                raise GrantError(
                    "commit destination escaped the fs root (fail-closed)")
            with open(os.path.join(out_dir, name), "rb") as f:
                data = f.read()
            tmp = dest + ".granttmp-%d" % os.getpid()
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dest)
            # Durability: the rename must survive a crash, so fsync the
            # parent directory after replacing.
            parent_fd = os.open(os.path.dirname(dest), os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            committed.append({"token": name, "destination": dest,
                              "bytes": len(data)})

        self._registry._audit({
            "type": "capability_grant_dispatch",
            "decision_id": decision_id,
            "grant_id": grant_set.grant_id,
            "grant_digest": grant_set.digest(),
            "capability_count": record["capability_count"],
            "committed_writes": len(committed),
            "child_refusals": len(child_refusals),
            "tool_ok": bool(envelope.get("ok")),
        })
        result = DispatchResult(
            ok=bool(envelope.get("ok")),
            result=envelope.get("result"),
            refusals=child_refusals,
            writes_committed=committed,
            grant_id=grant_set.grant_id,
            grant_digest=grant_set.digest(),
            decision_id=decision_id,
            sandbox_note=envelope.get("_sandbox_note", ""),
            # Re-derived from the dispatch record -- never from the
            # child envelope.
            capability_count=record["capability_count"],
            error=envelope.get("error"),
        )
        return result


# ---------------------------------------------------------------------------
# Decision-BOM section + auditor re-derivation
# ---------------------------------------------------------------------------


def bom_grants_section(*, grant_digest, decision_id, capability_count):
    """The optional decision-BOM ``inputs.grants`` section for a dispatch.

    All-or-none (the PERM-model precedent): a partial dict is a builder
    error, never a weaker claim. Omitted from the BOM when the decision
    dispatched no tool call -- BOMs without it are byte-identical.
    """
    if not _is_hex64(grant_digest):
        raise GrantError("grant_digest must be 64-char lowercase hex")
    if not isinstance(decision_id, str) or not decision_id:
        raise GrantError("decision_id must be a non-empty string")
    if not isinstance(capability_count, int) or capability_count < 0:
        raise GrantError("capability_count must be a non-negative int")
    return {"grant_digest": grant_digest,
            "decision_id": decision_id,
            "capability_count": capability_count}


def verify_grant_digest(grant_digest, capabilities):
    """Auditor re-derivation: recompute the digest from capabilities.

    ``capabilities`` is the canonical describe() list (as returned by
    ``GrantRegistry.describe_grants``). Returns True/False -- never
    raises for well-formed inputs.
    """
    if not _is_hex64(grant_digest):
        return False
    try:
        descs = [{"kind": c["kind"], "resource": c["resource"],
                  "rights": sorted(c["rights"])} for c in capabilities]
    except (KeyError, TypeError, AttributeError):
        return False
    descs.sort(key=lambda d: (d["kind"], d["resource"],
                              ",".join(d["rights"])))
    recomputed = _sha256_hex(_canonical(
        {"v": 1, "capabilities": descs}))
    return recomputed == grant_digest
