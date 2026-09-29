"""Signed-pack activation layer (OPA ``.signatures.json`` semantics).

Design input: open-policy-agent/opa signed bundles (Apache-2.0 VERIFIED
-- license text read from the opa LICENSE file 2026-09-29; see
``teams/wave200-prospect/sections/policybundles.md``). OPA ships a
signed bundle as a normal artifact **plus a signature file inside it**
that (a) enumerates which files are in the bundle, (b) pins each
file's hash, (c) is cryptographically signed. The verification key is
configured **out-of-band**. On receipt OPA verifies against the
out-of-band key; **only on success does it activate the new bundle --
otherwise it keeps the old bundle and reports activation failure**
(fail-closed with continuity, not fail-dead). This is stronger than
signing the pack tarball because the enumeration also detects
*omission* (a file silently dropped from the pack breaks the
enumeration).

Adapted here, stdlib-only, re-implemented (not vendored):

* The member-enumeration + threshold-signature mechanism already
  exists as :mod:`gov.rule_pack` (``{member_id -> sha256}`` binding,
  keyset-purpose binding, monotonic version, expiry, distinct-kid
  threshold). This module does NOT duplicate that machinery: the
  rule-pack document IS the signature file enumerating the members.
* What this module adds is the **activation layer** OPA owns and
  rule_pack.py lacks:
    1. **Fail-closed activation with continuity**: :meth:`PackLoader.present`
       verifies a candidate pack; on ANY failure it raises
       :class:`PackActivationError`, keeps the previously activated
       pack, and records the failure in ``activation_failures``.
       The loader never goes pack-less because a bad candidate
       arrived (OPA's "keeps the old bundle").
    2. **Omission / extra detection at the directory level**: every
       file presented must be enumerated in the pack with a matching
       digest (extra file = unbound content, refused); every
       enumerated member must be presented (omission = refused).
       rule_pack.py binds digests per member id but never sees the
       directory; the loader closes that gap.
    3. **Rollback floor**: the loader remembers the highest verified
       pack version and refuses non-increasing versions
       (``pack-stale``) -- the TUF rollback shape, mirroring
       ``CorpusManifestTracker``.
    4. **Optional activation guard**: a caller-supplied
       ``guard(snapshot) -> (verdict, detail)`` (duck-typed; in
       practice ``gov.perm_loader.PermModel.as_guard()`` -- this
       module never imports perm_loader, so there is no cycle) may
       govern pack activation as data. ``deny`` -> refused;
       ``require_approval`` -> refused with
       ``pack-activation-approval-required`` (fail-closed; the
       approval happens out-of-band and the caller re-presents).
       Absent a guard, activation is signature+freshness only.

Trust model: the keyset is the deployment's pack-signing keyset,
held out-of-band (no key discovery, ever). An attacker who can mint
a pack already holds the deployment's pack-signing keys. A fresh
``PackLoader`` starts with no version memory (honest residual,
shared with ``CorpusManifestTracker``): a rebooted deployment
re-trusts the presented pack -- the pack's own expiry bounds that
window.

$0 spend, synthetic/local deterministic only. No network.
"""

from . import rule_pack as _rp

__all__ = [
    "PackActivationError",
    "ActivePack",
    "PackLoader",
]

#: Bound on retained activation-failure records (operator telemetry,
#: not an audit log -- the audit log is the deployment's chained log).
_MAX_FAILURES = 64


class PackActivationError(Exception):
    """A candidate pack failed activation. ``code`` is the
    machine-readable failure mode; the previously activated pack (if
    any) is untouched."""

    def __init__(self, code, detail=""):
        super(PackActivationError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class ActivePack(object):
    """A verified, activated pack: the member bytes plus the pack
    metadata that verified. Instances only come from
    :meth:`PackLoader.present`.

    ``purpose``/``format_tag`` are the verified trust domain (the
    keyset purpose and pack format the signature verified under).
    Consumers that only accept one domain (e.g. the PERM loader)
    must check them -- a signed pack from the wrong domain is never
    silently usable as another domain's pack."""

    __slots__ = ("pack_id", "version", "expires_at", "threshold",
                 "signing_kids", "members", "purpose", "format_tag")

    def __init__(self, pack_id, version, expires_at, threshold,
                 signing_kids, members, purpose, format_tag):
        self.pack_id = pack_id
        self.version = version
        self.expires_at = expires_at
        self.threshold = threshold
        self.signing_kids = list(signing_kids)
        # {member_id: bytes} -- the EXACT bytes the digests were
        # verified against (single-read rule: no re-read TOCTOU).
        self.members = dict(members)
        self.purpose = purpose
        self.format_tag = format_tag

    def member(self, member_id):
        """Member bytes for ``member_id``; KeyError when absent."""
        return self.members[member_id]

    def member_ids(self):
        return sorted(self.members)


class PackLoader(object):
    """Activation-point holder for one pack id.

    ``keyset``: the deployment's pack-signing keyset (purpose
    ``sasanam-rule-pack-signing/v1`` by default; wave-200 PERM model
    packs use ``purpose=_rp.KEYSET_PURPOSE_PERM_PACK`` with
    ``format_tag=_rp.PERM_PACK_FORMAT`` -- a distinct trust domain),
    held out-of-band. ``pack_id``: human label for telemetry (e.g.
    ``"capability_rules"``); it is NOT a trust boundary -- the keyset
    purpose + signatures are.
    """

    def __init__(self, keyset, pack_id,
                 purpose=_rp.KEYSET_PURPOSE_RULE_PACK,
                 format_tag=_rp.RULE_PACK_FORMAT):
        from .keyset import Keyset
        if not isinstance(keyset, Keyset):
            raise TypeError("keyset must be a Keyset")
        if keyset.purpose != purpose:
            raise PackActivationError(
                "wrong-keyset-purpose",
                "keyset purpose %r cannot verify %r packs"
                % (keyset.purpose, format_tag))
        if not isinstance(pack_id, str) or not pack_id:
            raise PackActivationError(
                "bad-pack-id", "pack_id must be a non-empty string")
        self._keyset = keyset
        self._pack_id = pack_id
        self._purpose = purpose
        self._format_tag = format_tag
        self._current = None
        self._highest_version = 0
        self._failures = []

    @property
    def pack_id(self):
        return self._pack_id

    @property
    def current(self):
        """The active pack, or None when nothing has activated yet."""
        return self._current

    @property
    def activation_failures(self):
        """Telemetry for refused activations (bounded). Each entry:
        ``{pack_id, version, code, detail}``. Never raises."""
        return list(self._failures)

    def _record_failure(self, pack_doc, code, detail):
        version = (pack_doc.get("pack_version")
                   if isinstance(pack_doc, dict) else None)
        self._failures.append({
            "pack_id": self._pack_id,
            "version": version,
            "code": code,
            "detail": detail,
        })
        del self._failures[:-_MAX_FAILURES]

    def present(self, pack_doc, files, *, guard=None, now=None):
        """Verify and activate a candidate pack.

        ``pack_doc``: the rule-pack document (the signature file).
        ``files``: ``{member_id: bytes}`` -- the candidate member
        files, EXCLUDING the pack document itself. ``guard``: optional
        ``guard(snapshot) -> (verdict, detail)`` activation control;
        ``verdict`` must be ``"allow"`` or the activation is refused.
        ``now``: override for expiry checks (tests).

        Returns the :class:`ActivePack`. Raises
        :class:`PackActivationError` (fail-closed) on any failure --
        the previously activated pack stays active and the failure is
        recorded. Failure codes: ``pack-<rule_pack code>`` for
        signature/shape/expiry failures, ``pack-stale`` (rollback),
        ``pack-member-omitted`` / ``pack-member-extra`` /
        ``pack-member-digest-mismatch`` (enumeration), and
        ``pack-activation-denied`` /
        ``pack-activation-approval-required`` (guard).
        """
        if not isinstance(files, dict) or not files:
            raise PackActivationError(
                "bad-files", "files must be a non-empty mapping")
        for member_id, data in files.items():
            if not isinstance(member_id, str) or not member_id:
                raise PackActivationError(
                    "bad-files", "member ids must be non-empty strings")
            if not isinstance(data, (bytes, bytearray)):
                raise PackActivationError(
                    "bad-files",
                    "member %r is not bytes" % (member_id,))

        def _fail(code, detail=""):
            self._record_failure(pack_doc, code, detail)
            raise PackActivationError(code, detail)

        try:
            pack = _rp.verify_rule_pack(
                pack_doc, self._keyset, now=now,
                purpose=self._purpose, format_tag=self._format_tag)
        except _rp.RulePackError as exc:
            _fail("pack-%s" % exc.code, exc.detail)
        if pack.version <= self._highest_version:
            _fail("pack-stale",
                  "pack version %d is not newer than the activated "
                  "version %d (rollback refused)"
                  % (pack.version, self._highest_version))
        # OPA enumeration semantics: the pack document enumerates
        # EXACTLY the members that may activate.
        import hashlib
        for member_id in files:
            expected = pack.rules.get(member_id)
            if expected is None:
                _fail("pack-member-extra",
                      "member %r is not enumerated in the pack "
                      "(unbound content refused)" % (member_id,))
            observed = "sha256:" + hashlib.sha256(
                bytes(files[member_id])).hexdigest()
            if observed != expected:
                _fail("pack-member-digest-mismatch",
                      "member %r digest does not match the pack "
                      "enumeration" % (member_id,))
        for member_id in pack.rules:
            if member_id not in files:
                _fail("pack-member-omitted",
                      "pack enumerates member %r but it was not "
                      "presented (omission refused)" % (member_id,))
        if guard is not None:
            try:
                verdict, detail = guard(self._guard_snapshot(pack))
            except PackActivationError:
                raise
            except Exception as exc:
                _fail("pack-guard-error",
                      "activation guard raised %s: %s"
                      % (type(exc).__name__, exc))
            if verdict == "allow":
                pass
            elif verdict == "require_approval":
                _fail("pack-activation-approval-required",
                      "guard requires human approval: %s" % (detail,))
            else:
                _fail("pack-activation-denied",
                      "guard verdict %r: %s" % (verdict, detail))
        active = ActivePack(
            self._pack_id, pack.version, pack.expires_at,
            pack.threshold, pack.signing_kids,
            {mid: bytes(data) for mid, data in files.items()},
            self._purpose, self._format_tag)
        self._current = active
        self._highest_version = pack.version
        return active

    def _guard_snapshot(self, pack):
        """The snapshot handed to the activation guard. Attribute
        names are part of the guard contract (see gov.perm_loader)."""
        return {
            "pack_id": self._pack_id,
            "pack_version": pack.version,
            "prior_version": self._highest_version,
            "threshold": pack.threshold,
            "signing_kids": list(pack.signing_kids),
            "member_count": len(pack.rules),
        }
