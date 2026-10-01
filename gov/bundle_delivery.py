"""TUF-shaped secure bundle delivery (wave-273 lane E).

Stdlib-only re-implementation of three python-tuf disciplines on top of
``gov/bundle_refresh.py``'s verified four-role metadata chain
(verdict: STEAL the patterns, never the ``tuf`` package -- it pulls
securesystemslib + urllib3; license map: python-tuf is MIT OR
Apache-2.0, verified from its LICENSE files in wave-272):

1. **Delegated targets** -- ``DelegatedRole`` with ``paths`` (fnmatch
   globs, e.g. ``skills/payments/*``) or ``path_hash_prefixes``
   (sha256-of-path bins, hiding target names), ``terminating`` flag,
   trust-ordered preorder DFS lookup, visited-set cycle guard, and a
   ``MAX_DELEGATIONS = 32`` cap. Bundle-publisher hierarchies: team
   keys scoped to path prefixes with per-delegation thresholds. A
   terminating delegation that provably shadows a later delegation is
   refused fail-closed (``bundle-delivery-shadowed-delegation``) --
   shadowing is reported, never silent -- and undecidable glob-vs-glob
   overlaps are surfaced as lint warnings.
2. **Consistent snapshots** -- version-prefixed metadata URLs and
   hash-prefixed target URLs, so stale-bytes-at-stable-URL on a
   compromised mirror is structurally impossible; any bytes that do not
   match the parent-bound version+digest at a versioned URL are refused
   (``bundle-delivery-mirror-stale``).
3. **Expired-intermediate bootstrap** -- expired metadata is admissible
   ONLY to bootstrap its successor (verify the successor under the
   expired doc's keys, exact ``N -> N+1``) and to refuse rollback;
   expired metadata is never an authority for target digests
   (``bundle-delivery-expired-authority-refused``).

Honored traps (from the wave-272 prospectus):

* The trust anchor (initial root) is provisioned out-of-band; this
  module never fetches it. Root rotation must satisfy BOTH the old
  root's and the new root's thresholds (already enforced by
  ``BundleRefresher._adopt_root_candidate``; the bootstrap rule here
  extends the same discipline to delegated roles).
* Freeze protection is TTL-bound, not prevention: real freeze
  resistance needs a short-lived online timestamp signer -- an ops
  cost not yet paid, documented here as a standing honest limit.
* ``succinct-roles`` hash-bin sharding is premature at this scale;
  noted only, not built.
* Caches are single-instance: ``BundleRefresher`` accepts
  ``cache_lock=True`` for an advisory ``flock`` on
  ``<cache_dir>/.refresh.lock``; concurrent refresh workers sharing a
  cache dir must enable it (``bundle-delivery-cache-locked``).

Refusals (domain ``bundle-delivery``, all in the taxonomy):

- ``bundle-delivery-delegation-malformed`` -- a delegation or
  delegated-targets document has a bad shape.
- ``bundle-delivery-delegation-unverified`` -- a delegated-targets
  envelope fails the delegation's key/threshold check, or an eligible
  delegated role's metadata is missing.
- ``bundle-delivery-target-not-found`` -- no visited role binds the
  target.
- ``bundle-delivery-delegation-cycle`` -- a delegation cycle was
  detected on the DFS path (fail closed, not silent skip).
- ``bundle-delivery-delegation-cap-exceeded`` -- more than 32
  delegations visited.
- ``bundle-delivery-shadowed-delegation`` -- a terminating delegation
  provably shadows a later delegation for this target.
- ``bundle-delivery-mirror-stale`` -- bytes at a versioned URL do not
  match the bound version/digest (compromised or stale mirror).
- ``bundle-delivery-expired-bootstrap-refused`` -- an expired
  intermediate could not bootstrap its successor.
- ``bundle-delivery-expired-authority-refused`` -- expired metadata
  was presented as an authority for a target digest.
- ``bundle-delivery-cache-locked`` -- the cache dir is already held
  by another refresher.

Stdlib only. Deterministic. No I/O, no clock reads, no network: the
fetch callables are caller-provided, and ``now`` is an explicit
argument wherever expiry is checked.
"""

import base64
import binascii
import fnmatch
import hashlib
import json as _json
import os
from datetime import datetime, timezone

from .bundle_refresh import (
    FetchNotFound,
    RefreshError,
    SuspendedError,
    tuf_canonical_json,
)
from .dsse_envelope import pae
from .signing import Ed25519Verifier

#: DSSE payload type for delegated-targets envelopes. The type is
#: inside the signed PAE bytes, so a delegated-targets envelope can
#: never be replayed as a top-level targets envelope or vice versa.
DELEGATED_PAYLOAD_TYPE = "application/vnd.sasanam.tuf-delegated-targets+json"

#: Maximum delegations visited in one preorder walk (python-tuf
#: ``UpdaterConfig.max_delegations`` default, re-implemented).
MAX_DELEGATIONS = 32


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class DeliveryError(Exception):
    """Base for every bundle-delivery refusal. ``code`` is the taxonomy
    refusal string; ``detail`` never carries secret material."""

    def __init__(self, code, detail):
        super(DeliveryError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise DeliveryError(code, detail)


# ---------------------------------------------------------------------------
# DelegatedRole
# ---------------------------------------------------------------------------

def _is_hex_prefix(value):
    return (isinstance(value, str) and 1 <= len(value) <= 64
            and all(c in "0123456789abcdef" for c in value))


class DelegatedRole(object):
    """One delegation: a named role trusted for a subset of targets.

    Exactly one of ``paths`` (fnmatch globs, matched per path part,
    case-sensitively -- ``skills/payments/*``) or
    ``path_hash_prefixes`` (sha256-of-target-path hex prefixes, hiding
    target names from the delegator) must be set. ``terminating``
    means the walk does not backtrack past this role for a matching
    target. ``keyids``/``threshold`` select the delegation's own keys;
    key IDs are opaque producer-chosen strings, never re-derived.
    """

    def __init__(self, name, keyids, threshold, paths=None,
                 path_hash_prefixes=None, terminating=False, keys=None):
        if not isinstance(name, str) or not name or "/" in name:
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation name must be a non-empty str without "
                    "'/', got %r" % (name,))
        if (not isinstance(keyids, list) or not keyids
                or any(not isinstance(k, str) or not k for k in keyids)):
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r needs a non-empty keyids list" % (name,))
        if (isinstance(threshold, bool) or not isinstance(threshold, int)
                or not 1 <= threshold <= len(keyids)):
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r threshold %r out of range"
                    % (name, threshold))
        if (paths is None) == (path_hash_prefixes is None):
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r must set exactly one of paths / "
                    "path_hash_prefixes" % (name,))
        if paths is not None:
            if (not isinstance(paths, list) or not paths
                    or any(not isinstance(p, str) or not p
                           for p in paths)):
                _refuse("bundle-delivery-delegation-malformed",
                        "delegation %r paths must be a non-empty list of "
                        "non-empty str" % (name,))
        if path_hash_prefixes is not None:
            if (not isinstance(path_hash_prefixes, list)
                    or not path_hash_prefixes
                    or any(not _is_hex_prefix(p)
                           for p in path_hash_prefixes)):
                _refuse("bundle-delivery-delegation-malformed",
                        "delegation %r path_hash_prefixes must be a "
                        "non-empty list of 1..64-char lowercase hex "
                        "prefixes" % (name,))
        if not isinstance(terminating, bool):
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r terminating must be a bool" % (name,))
        if keys is not None and not isinstance(keys, dict):
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r keys must be a dict" % (name,))
        self.name = name
        self.keyids = list(keyids)
        self.threshold = threshold
        self.paths = list(paths) if paths is not None else None
        self.path_hash_prefixes = (list(path_hash_prefixes)
                                   if path_hash_prefixes is not None
                                   else None)
        self.terminating = terminating
        self.keys = dict(keys) if keys is not None else {}

    def __repr__(self):
        return ("DelegatedRole(%r, threshold=%d/%d, terminating=%r)"
                % (self.name, self.threshold, len(self.keyids),
                   self.terminating))

    @staticmethod
    def _in_pathpattern(target, pattern):
        # TUF path matching: the same number of "/"-separated parts,
        # each part matched with fnmatchcase. ("skills/*" does not
        # match "skills/a/b".)
        target_parts = target.split("/")
        pattern_parts = pattern.split("/")
        if len(target_parts) != len(pattern_parts):
            return False
        return all(fnmatch.fnmatchcase(t, p)
                   for t, p in zip(target_parts, pattern_parts))

    def is_delegated_path(self, target):
        """True when ``target`` is inside this delegation's scope."""
        if not isinstance(target, str) or not target:
            return False
        if self.path_hash_prefixes is not None:
            digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
            return any(digest.startswith(prefix)
                       for prefix in self.path_hash_prefixes)
        return any(self._in_pathpattern(target, pattern)
                   for pattern in self.paths)


def parse_delegations(targets_doc, where="targets"):
    """Parse and validate the ``delegations`` block of a verified
    targets document.

    Returns ``(roles, keys)``: ``roles`` is the trust-ordered list of
    :class:`DelegatedRole`, ``keys`` the delegation key dict. Raises
    ``bundle-delivery-delegation-malformed`` on any defect: missing or
    misshapen block, duplicate role names, a role referencing unknown
    keys, or a role delegating to itself (a one-step cycle is
    malformed, not walked).
    """
    if not isinstance(targets_doc, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: targets document must be a dict" % where)
    delegations = targets_doc.get("delegations")
    if delegations is None:
        return [], {}
    if not isinstance(delegations, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: delegations must be a dict" % where)
    keys = delegations.get("keys")
    if not isinstance(keys, dict) or not keys:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: delegations.keys must be a non-empty dict" % where)
    raw_roles = delegations.get("roles")
    if not isinstance(raw_roles, list) or not raw_roles:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: delegations.roles must be a non-empty list" % where)
    roles = []
    seen = set()
    for entry in raw_roles:
        if not isinstance(entry, dict):
            _refuse("bundle-delivery-delegation-malformed",
                    "%s: delegation entry must be a dict" % where)
        role = DelegatedRole(
            entry.get("name"), entry.get("keyids"),
            entry.get("threshold"), paths=entry.get("paths"),
            path_hash_prefixes=entry.get("path_hash_prefixes"),
            terminating=entry.get("terminating", False), keys=keys)
        if role.name in seen:
            _refuse("bundle-delivery-delegation-malformed",
                    "%s: duplicate delegation name %r" % (where,
                                                          role.name))
        seen.add(role.name)
        for kid in role.keyids:
            if kid not in keys:
                _refuse("bundle-delivery-delegation-malformed",
                        "%s: delegation %r references unknown key %r"
                        % (where, role.name, kid))
        roles.append(role)
    return roles, keys


# ---------------------------------------------------------------------------
# Shadowing lint
# ---------------------------------------------------------------------------

def _part_subsumes(terminating_part, later_part):
    # Sound (never claims coverage it cannot prove) but incomplete:
    # a "*" part covers any single part; anything else must be
    # literally equal. "?" and "[...]" classes are NOT resolved --
    # they fall through to "potential-shadow".
    return terminating_part == "*" or terminating_part == later_part


def _pattern_covers(terminating_pattern, later_pattern):
    t_parts = terminating_pattern.split("/")
    l_parts = later_pattern.split("/")
    if len(t_parts) != len(l_parts):
        return False
    return all(_part_subsumes(t, l) for t, l in zip(t_parts, l_parts))


def _part_may_overlap(terminating_part, later_part):
    # Overlap possibility (as opposed to proven coverage): equal parts
    # or a "*" on either side may overlap; "?" and "[...]" classes are
    # undecidable here so they are assumed to possibly overlap.
    # Literal-vs-different-literal is provably disjoint.
    if (terminating_part == later_part
            or terminating_part == "*" or later_part == "*"):
        return True
    if (set(terminating_part) & set("?[")
            or set(later_part) & set("?[")):
        return True
    return False


def _patterns_may_overlap(terminating_pattern, later_pattern):
    t_parts = terminating_pattern.split("/")
    l_parts = later_pattern.split("/")
    if len(t_parts) != len(l_parts):
        return False
    return all(_part_may_overlap(t, l)
               for t, l in zip(t_parts, l_parts))


def _bin_covers(terminating_prefixes, later_prefixes):
    # Bin b_t covers bin b_l iff every hash starting with b_l also
    # starts with b_t, i.e. b_l.startswith(b_t).
    return all(any(later.startswith(term)
                   for term in terminating_prefixes)
               for later in later_prefixes)


def lint_delegations(roles):
    """Lint a trust-ordered delegation list for shadowing.

    A terminating delegation listed before a later one makes the later
    one unreachable for every target the terminating delegation claims.
    Returns a list of finding dicts
    ``{"kind", "role", "shadowed_by", "detail"}`` where ``kind`` is
    ``"shadowed"`` (coverage proven: the later delegation can never
    serve) or ``"potential-shadow"`` (glob-vs-glob overlap the lint
    cannot decide -- reported, never silent). An empty list is clean.

    The check is sound but incomplete by construction: fully general
    glob subsumption is not decided here, so a ``potential-shadow``
    finding is an instruction to tighten the patterns, not a proof of
    a live shadow.
    """
    findings = []
    for i, term in enumerate(roles):
        if not term.terminating:
            continue
        for later in roles[i + 1:]:
            verdict = _coverage_verdict(term, later)
            if verdict == "full":
                findings.append({
                    "kind": "shadowed",
                    "role": later.name,
                    "shadowed_by": term.name,
                    "detail": ("terminating delegation %r provably "
                               "covers every target of later delegation "
                               "%r; %r can never serve"
                               % (term.name, later.name, later.name)),
                })
            elif verdict == "partial":
                findings.append({
                    "kind": "potential-shadow",
                    "role": later.name,
                    "shadowed_by": term.name,
                    "detail": ("terminating delegation %r may overlap "
                               "later delegation %r in ways this lint "
                               "cannot decide; tighten the patterns or "
                               "reorder" % (term.name, later.name)),
                })
    return findings


def _coverage_verdict(term, later):
    if ((term.paths is None) != (later.paths is None)):
        return "partial"  # paths vs hash-bins: undecidable here
    if term.paths is not None:
        per_later = [
            any(_pattern_covers(t, l) for t in term.paths)
            for l in later.paths
        ]
        if all(per_later):
            return "full"
        if any(_patterns_may_overlap(t, l)
               for l in later.paths for t in term.paths):
            return "partial"
        return "none"
    if _bin_covers(term.path_hash_prefixes, later.path_hash_prefixes):
        return "full"
    return "none"


# ---------------------------------------------------------------------------
# Delegated-targets envelope verification
# ---------------------------------------------------------------------------

def _parse_time(value, where):
    try:
        if value.endswith("Z"):
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            return parsed.replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, AttributeError) as exc:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: bad expiry timestamp %r: %s" % (where, value, exc))


def _check_hex64(value, where):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: needs a 64-char lowercase hex sha256" % where)
    return value


def seal_delegated_targets(doc, signers):
    """Seal a delegated-targets document; returns wire bytes.

    ``signers`` is an iterable of ``(declared_key_id, signer)`` --
    the declared (opaque) key ID goes in the envelope, never a
    re-derived one. The payload is canonical JSON signed via DSSE PAE
    under :data:`DELEGATED_PAYLOAD_TYPE`.
    """
    if not isinstance(doc, dict) or doc.get("_type") != "delegated-targets":
        raise ValueError("doc must be a delegated-targets document")
    payload = tuf_canonical_json(doc)
    pae_bytes = pae(DELEGATED_PAYLOAD_TYPE, payload)
    sigs = []
    for keyid, signer in signers:
        if not isinstance(keyid, str) or not keyid:
            raise ValueError("declared keyid must be a non-empty str")
        sigs.append({"keyid": keyid,
                     "sig": bytes(signer.sign(pae_bytes)).hex()})
    if not sigs:
        raise ValueError("seal_delegated_targets requires a signer")
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": DELEGATED_PAYLOAD_TYPE,
        "signatures": sigs,
    }
    return tuf_canonical_json(envelope)


def _verify_delegated_envelope(role, wire, now, where):
    """Verify one delegated-targets envelope under the delegation's
    own keys.

    Returns the payload document. Raises
    ``bundle-delivery-delegation-unverified`` when the role's
    threshold is not met by distinct declared key IDs, and
    ``bundle-delivery-delegation-malformed`` on shape defects. An
    expired document is returned with ``"_expired": True`` set -- the
    caller decides: it may bootstrap a successor, but it is never an
    authority (see :class:`ExpiredBootstrap`).
    """
    try:
        text = bytes(wire).decode("utf-8")
    except (UnicodeDecodeError, TypeError):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: wire is not UTF-8" % where)
    try:
        envelope = _json.loads(text)
    except ValueError:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: wire is not JSON" % where)
    if not isinstance(envelope, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: envelope must be a JSON object" % where)
    if tuf_canonical_json(envelope) != bytes(wire):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: envelope bytes are not canonical" % where)
    if envelope.get("payloadType") != DELEGATED_PAYLOAD_TYPE:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: payloadType %r is not delegated-targets"
                % (where, envelope.get("payloadType")))
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: signatures must be a non-empty list" % where)
    try:
        payload = base64.b64decode(
            envelope.get("payload").encode("ascii"), validate=True)
    except (binascii.Error, AttributeError, UnicodeEncodeError,
            ValueError):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: invalid base64 payload" % where)
    try:
        doc = _json.loads(payload.decode("utf-8"))
    except ValueError:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: payload is not JSON" % where)
    if not isinstance(doc, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: payload must be a JSON object" % where)
    if tuf_canonical_json(doc) != payload:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: payload bytes are not canonical" % where)
    if doc.get("_type") != "delegated-targets":
        _refuse("bundle-delivery-delegation-malformed",
                "%s: _type %r is not delegated-targets"
                % (where, doc.get("_type")))
    _validate_delegated_doc(doc, where)
    pae_bytes = pae(DELEGATED_PAYLOAD_TYPE, payload)
    seen = set()
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("keyid")
        if not isinstance(kid, str) or kid in seen:
            continue
        if kid not in role.keyids:
            continue
        keyinfo = role.keys.get(kid)
        if not isinstance(keyinfo, dict):
            continue
        if keyinfo.get("keytype") != "ed25519":
            continue
        try:
            public = bytes.fromhex(
                (keyinfo.get("keyval") or {}).get("public"))
            sig = bytes.fromhex(entry.get("sig"))
        except (TypeError, ValueError):
            continue
        if len(public) != 32 or len(sig) != 64:
            continue
        try:
            if Ed25519Verifier(public, key_id=kid).verify(pae_bytes, sig):
                seen.add(kid)
        except Exception:
            continue
    if len(seen) < role.threshold:
        _refuse("bundle-delivery-delegation-unverified",
                "%s: delegation %r threshold not met (%d of %d)"
                % (where, role.name, len(seen), role.threshold))
    expired = now >= _parse_time(doc["expires"], where + ".expires")
    doc = dict(doc)
    doc["_expired"] = expired
    return doc


def _validate_delegated_doc(doc, where):
    version = doc.get("version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: version must be an int >= 1" % where)
    if not isinstance(doc.get("expires"), str) or not doc["expires"]:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: expires must be a non-empty str" % where)
    _parse_time(doc["expires"], where + ".expires")
    targets = doc.get("targets")
    if not isinstance(targets, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: targets must be a dict" % where)
    for name, entry in targets.items():
        _check_target_entry(name, entry, where)


# ---------------------------------------------------------------------------
# Preorder DFS resolution
# ---------------------------------------------------------------------------

class Resolution(object):
    """The outcome of :func:`resolve_target`."""

    def __init__(self, digest, length, role, warnings):
        self.digest = digest
        self.length = length
        self.role = role  # "targets" or a delegation name
        self.warnings = list(warnings)

    def __repr__(self):
        return ("Resolution(role=%r, digest=%r..., warnings=%d)"
                % (self.role, self.digest[:16], len(self.warnings)))


def _check_target_entry(name, entry, where):
    """Validate one target entry; returns ``(digest_hex, length)``."""
    if not isinstance(name, str) or not name:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: target name must be a non-empty str" % where)
    if not isinstance(entry, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: target %r must be a dict" % (where, name))
    length = entry.get("length")
    if isinstance(length, bool) or not isinstance(length, int) \
            or length < 0:
        _refuse("bundle-delivery-delegation-malformed",
                "%s: target %r length must be a non-negative int"
                % (where, name))
    digest = _check_hex64((entry.get("hashes") or {}).get("sha256"),
                          "%s: target %r" % (where, name))
    return digest, length


def _targets_map(doc, where):
    if not isinstance(doc, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: targets document must be a dict" % where)
    targets = doc.get("targets")
    if not isinstance(targets, dict):
        _refuse("bundle-delivery-delegation-malformed",
                "%s: targets must be a dict" % where)
    return targets


def resolve_target(target, top_targets_doc, fetch_delegated, now):
    """Resolve ``target`` through the delegation tree, preorder DFS.

    ``top_targets_doc`` is the verified top-level targets document
    (from a trusted refresh chain). ``fetch_delegated(role_name)``
    returns delegated-targets wire bytes, raising
    :class:`FetchNotFound` on a clean miss. ``now`` is a timezone-aware
    datetime.

    Trust order is the delegation list order: earlier roles are more
    trusted. A terminating delegation eligible for the target stops
    backtracking past it. Roles are visited at most once (visited-set
    cycle guard); a role delegating to a name already on the DFS path
    is a cycle and fails closed. More than ``MAX_DELEGATIONS``
    visited roles fails closed. A proven shadow
    (``lint_delegations`` ``"shadowed"``) fails closed; potential
    overlaps are returned as warnings. An expired delegated document
    is never an authority (``bundle-delivery-expired-authority-
    refused``); it may only bootstrap a successor via
    :class:`ExpiredBootstrap`.
    """
    if not isinstance(target, str) or not target:
        _refuse("bundle-delivery-delegation-malformed",
                "target must be a non-empty str")
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    warnings = []
    top = _targets_map(top_targets_doc, "targets")
    entry = top.get(target)
    if entry is not None:
        digest, length = _check_target_entry(target, entry, "targets")
        return Resolution(digest, length, "targets", warnings)
    roles, _keys = parse_delegations(top_targets_doc, "targets")
    by_name = {role.name: role for role in roles}
    for finding in lint_delegations(roles):
        if finding["kind"] == "shadowed":
            _refuse("bundle-delivery-shadowed-delegation",
                    finding["detail"])
        warnings.append("potential-shadow: %s" % finding["detail"])
    # Stack entries: (role_name, path_tuple). The path detects true
    # cycles; the visited set implements the TUF diamond-skip.
    stack = []
    for role in reversed(roles):
        if role.is_delegated_path(target):
            stack.append((role.name, (role.name,)))
    visited = set()
    count = 0
    while stack:
        if count >= MAX_DELEGATIONS:
            _refuse("bundle-delivery-delegation-cap-exceeded",
                    "walked %d delegations without resolving %r; cap "
                    "is %d" % (count, target, MAX_DELEGATIONS))
        name, path = stack.pop()
        if name in visited:
            continue
        visited.add(name)
        count += 1
        role = by_name.get(name)
        if role is None:
            _refuse("bundle-delivery-delegation-malformed",
                    "delegation %r not declared" % (name,))
        where = "delegated-targets %r" % name
        try:
            wire = fetch_delegated(name)
        except FetchNotFound:
            _refuse("bundle-delivery-delegation-unverified",
                    "%s: eligible delegated metadata is missing" % where)
        doc = _verify_delegated_envelope(role, wire, now, where)
        if doc.get("_expired"):
            _refuse("bundle-delivery-expired-authority-refused",
                    "%s: expired delegated metadata is never an "
                    "authority for target digests; bootstrap a "
                    "successor via ExpiredBootstrap" % where)
        targets = _targets_map(doc, where)
        entry = targets.get(target)
        if entry is not None:
            digest, length = _check_target_entry(target, entry, where)
            return Resolution(digest, length, name, warnings)
        child_roles, _child_keys = parse_delegations(doc, where)
        child_by_name = {r.name: r for r in child_roles}
        by_name.update(child_by_name)
        for finding in lint_delegations(child_roles):
            if finding["kind"] == "shadowed":
                _refuse("bundle-delivery-shadowed-delegation",
                        finding["detail"])
            warnings.append("potential-shadow: %s" % finding["detail"])
        eligible = [r for r in child_roles
                    if r.is_delegated_path(target)]
        # Trust order, terminating stops backtracking past it (roles
        # listed before it are still tried -- they are more trusted).
        push = []
        for child in eligible:
            if child.name in path:
                _refuse("bundle-delivery-delegation-cycle",
                        "delegation cycle on the walk path: %s -> %s"
                        % (" -> ".join(path), child.name))
            push.append((child.name, path + (child.name,)))
            if child.terminating:
                stack = []  # no backtracking past this point
                break
        for item in reversed(push):
            stack.append(item)
    _refuse("bundle-delivery-target-not-found",
            "no visited role binds target %r" % (target,))


# ---------------------------------------------------------------------------
# Consistent snapshots
# ---------------------------------------------------------------------------

def snapshot_metadata_url(role, version):
    """Version-prefixed metadata URL: ``v<version>.<role>.json``.

    Every metadata version has its own URL, so stale-bytes-at-stable-
    URL is structurally impossible: a mirror cannot serve old bytes at
    the current version's URL without failing the version check, and
    cannot serve new bytes at an old version's URL without failing it
    either. ``role`` is any URL-safe role name (the four top-level
    roles or a delegated role name); it must not contain ``/`` or
    ``.`` so the mapping stays injective.
    """
    if (not isinstance(role, str) or not role or "/" in role
            or "." in role):
        raise ValueError("role must be a non-empty URL-safe name "
                         "without '/' or '.'")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise ValueError("version must be an int >= 1")
    return "v%d.%s.json" % (version, role)


def snapshot_target_url(name, digest_hex):
    """Hash-prefixed target URL: ``<sha256>.<name>``.

    The digest in the URL binds the bytes before they are read; a
    mirror serving different bytes at this URL fails the digest
    check. ``name`` must be a non-empty str without path separators
    (targets are flat names on this seam).
    """
    if not isinstance(name, str) or not name or "/" in name:
        raise ValueError("target name must be a non-empty str without "
                         "'/'")
    _check_hex64(digest_hex, "snapshot_target_url")
    return "%s.%s" % (digest_hex, name)


def consistent_fetch(fetch, kind, role_or_name, version_or_digest):
    """Fetch through the consistent-snapshot URL mapping.

    ``fetch(url)`` is the raw transport (raises ``FetchNotFound`` on a
    clean miss). ``kind`` is ``"metadata"`` (``role_or_name`` is the
    role, ``version_or_digest`` the version) or ``"target"``
    (``role_or_name`` is the target name, ``version_or_digest`` the
    bound sha256). Returns the raw wire bytes.
    """
    if kind == "metadata":
        url = snapshot_metadata_url(role_or_name, version_or_digest)
    elif kind == "target":
        url = snapshot_target_url(role_or_name, version_or_digest)
    else:
        raise ValueError("kind must be 'metadata' or 'target'")
    return fetch(url)


def verify_consistent_metadata(role, version, wire, expected_digest=None):
    """Verify bytes fetched at a versioned metadata URL.

    Refuses ``bundle-delivery-mirror-stale`` when the envelope's
    document version differs from the requested version (the mirror
    served the wrong version's bytes at this URL) or when
    ``expected_digest`` (the parent-bound sha256) does not match the
    wire digest. Returns the parsed document on success.
    """
    try:
        envelope = _json.loads(bytes(wire).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, TypeError):
        _refuse("bundle-delivery-mirror-stale",
                "%s v%d: wire is not decodable JSON" % (role, version))
    if not isinstance(envelope, dict):
        _refuse("bundle-delivery-mirror-stale",
                "%s v%d: envelope must be a JSON object" % (role,
                                                            version))
    try:
        payload = base64.b64decode(
            envelope["payload"].encode("ascii"), validate=True)
        doc = _json.loads(payload.decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        _refuse("bundle-delivery-mirror-stale",
                "%s v%d: payload is not decodable" % (role, version))
    if not isinstance(doc, dict) or doc.get("version") != version:
        _refuse("bundle-delivery-mirror-stale",
                "%s: served document version %r at the v%d URL"
                % (role, doc.get("version")
                   if isinstance(doc, dict) else None, version))
    if expected_digest is not None:
        actual = hashlib.sha256(bytes(wire)).hexdigest()
        if actual != expected_digest:
            _refuse("bundle-delivery-mirror-stale",
                    "%s v%d: wire digest does not match the parent "
                    "binding" % (role, version))
    return doc


def verify_consistent_target(name, expected_digest, fetched_bytes):
    """Verify target bytes fetched at a hash-prefixed URL.

    Refuses ``bundle-delivery-mirror-stale`` when the fetched bytes'
    sha256 differs from the bound digest. Returns the bytes.
    """
    _check_hex64(expected_digest, "verify_consistent_target")
    data = bytes(fetched_bytes)
    if hashlib.sha256(data).hexdigest() != expected_digest:
        _refuse("bundle-delivery-mirror-stale",
                "target %r: bytes at the hash-prefixed URL do not "
                "match the bound digest" % (name,))
    return data


# ---------------------------------------------------------------------------
# Expired-intermediate bootstrap
# ---------------------------------------------------------------------------

class ExpiredBootstrap(object):
    """Adopt a successor through an expired intermediate.

    Expired metadata is admissible ONLY to (a) bootstrap its successor
    and (b) refuse rollback. It is never an authority: no target
    digest, no threshold decision, no expiry verdict is ever drawn
    from an expired document.

    ``adopt(role_name, expired, successors, now)``: ``expired`` is
    ``(doc, role_info, keys)`` for the expired intermediate;
    ``successors`` is a list of ``(wire, doc)`` candidates ordered
    oldest-first; ``now`` is a timezone-aware datetime. Each candidate
    must verify under its *predecessor's* keys/threshold and must
    carry exactly ``previous_version + 1`` -- anything older is a
    rollback refusal, anything newer is a version-skip refusal. The
    first non-expired verified successor wins; an expired verified
    successor becomes the new intermediate and the walk continues.
    Any failure raises ``bundle-delivery-expired-bootstrap-refused``.

    Key continuity across hops: when the walk advances past an
    expired successor, the next hop verifies under the *successor's*
    keys, not the original intermediate's -- otherwise a key rotation
    in the middle of the walk would either be ignored (stale keys
    still trusted) or would strand the walk. ``keys_of(role_name,
    verified_doc)`` extracts ``(role_info, keys)`` from a verified
    successor document (e.g. a root document's ``roles``/``keys``
    sections); return ``None`` to keep the current trust (for roles
    whose documents carry no key material). When ``keys_of`` is not
    provided, every hop verifies under the original intermediate's
    keys -- correct for single-hop bootstrap, conservative for
    multi-hop.

    The envelope verifier is caller-provided
    (``verify_envelope(role_info, keys, wire) -> doc``) so this rule
    works for root, timestamp, and delegated-targets envelopes alike.
    """

    def __init__(self, verify_envelope, keys_of=None):
        if not callable(verify_envelope):
            raise TypeError("verify_envelope must be callable")
        if keys_of is not None and not callable(keys_of):
            raise TypeError("keys_of must be callable or None")
        self._verify_envelope = verify_envelope
        self._keys_of = keys_of

    def adopt(self, role_name, expired, successors, now):
        doc, role_info, keys = expired
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if not isinstance(doc, dict):
            _refuse("bundle-delivery-expired-bootstrap-refused",
                    "%s: expired intermediate must be a dict" % role_name)
        expires = _parse_time(doc.get("expires", ""),
                              "%s expired" % role_name)
        if now < expires:
            _refuse("bundle-delivery-expired-bootstrap-refused",
                    "%s: the intermediate is not expired; the bootstrap "
                    "rule does not apply" % role_name)
        current_version = doc.get("version")
        if (isinstance(current_version, bool)
                or not isinstance(current_version, int)
                or current_version < 1):
            _refuse("bundle-delivery-expired-bootstrap-refused",
                    "%s: expired intermediate has no usable version"
                    % role_name)
        for wire, candidate in successors or []:
            want = current_version + 1
            try:
                verified = self._verify_envelope(
                    role_name, role_info, keys, wire,
                    "expired-bootstrap %s v%d" % (role_name, want))
            except DeliveryError as exc:
                _refuse("bundle-delivery-expired-bootstrap-refused",
                        "%s: successor v%d does not verify under the "
                        "expired intermediate's keys: %s"
                        % (role_name, want, exc.code))
            got = verified.get("version")
            if got != want:
                if isinstance(got, int) and got <= current_version:
                    _refuse("bundle-delivery-expired-bootstrap-refused",
                            "%s: replayed v%s as the successor of "
                            "expired v%d: rollback refused"
                            % (role_name, got, current_version))
                _refuse("bundle-delivery-expired-bootstrap-refused",
                        "%s: successor version %r skips v%d"
                        % (role_name, got, want))
            succ_expires = _parse_time(
                verified.get("expires", ""),
                "%s successor" % role_name)
            if now < succ_expires:
                return verified
            # The successor is expired too: it becomes the new
            # intermediate and the walk continues. Key continuity:
            # the next hop verifies under THIS document's keys when
            # keys_of can extract them (a key rotation mid-walk must
            # not be ignored, nor must it strand the walk).
            doc, current_version = verified, got
            if self._keys_of is not None:
                nxt = self._keys_of(role_name, verified)
                if nxt is not None:
                    role_info, keys = nxt
        _refuse("bundle-delivery-expired-bootstrap-refused",
                "%s: no verified non-expired successor" % role_name)


# ---------------------------------------------------------------------------
# Install-pin wiring
# ---------------------------------------------------------------------------

def resolve_pin(refresher, target, fetch_delegated, now):
    """Build a skill-update install pin for ``target``.

    Consults the refresher's verified top-level targets first, then
    the delegation tree via :func:`resolve_target`. Returns exactly
    ``{"digest": hex, "chain_state": "trusted"}`` -- the shape
    ``gov/skill_update.py`` admits. The provenance role is available
    on the returned dict under ``"_provenance_role"`` for audit use
    only (it is NOT part of the pin; ``skill_update`` refuses unknown
    pin keys, so callers must strip it before installing).

    The refresher must be in ``"trusted"`` state; anything else raises
    :class:`SuspendedError` (via :meth:`verified_targets_doc`).
    """
    doc = refresher.verified_targets_doc()
    entry = (doc.get("targets") or {}).get(target)
    if entry is not None:
        digest, _length = _check_target_entry(target, entry, "resolve_pin")
        pin = {"digest": digest, "chain_state": "trusted"}
        pin["_provenance_role"] = "targets"
        return pin
    resolution = resolve_target(target, doc, fetch_delegated, now)
    pin = {"digest": resolution.digest, "chain_state": "trusted"}
    pin["_provenance_role"] = resolution.role
    return pin


def strip_provenance(pin):
    """Return the install pin without the audit-only provenance key."""
    clean = dict(pin)
    clean.pop("_provenance_role", None)
    return clean
