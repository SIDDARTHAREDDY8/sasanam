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
    5. **Wave-206 pack lint + LOG_ONLY -> ENFORCE graduation** (the
       Cedar symcc discipline): over the verified member bytes the
       loader runs :mod:`gov.pack_lint` -- safety (no vacuous rules,
       unreachable branches, shadowed grants), liveness (a reachable
       allow path per pack), sanity (no contradictory rule pairs).
       Packs default to LOG_ONLY: a lint-failed pack still
       activates, but the ActivePack carries the ``lint_failed``
       marker and every evaluation built from it must surface
       ``pack-lint-failed``. ENFORCE mode (``enforcement_mode``)
       refuses lint-failed packs with ``pack-lint-failed`` before
       they can displace the active pack; reaching ENFORCE needs an
       explicit two-distinct-operator promotion
       (:meth:`PackLoader.promote_to_enforce`).

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
                 "signing_kids", "members", "purpose", "format_tag",
                 "lint_report")

    def __init__(self, pack_id, version, expires_at, threshold,
                 signing_kids, members, purpose, format_tag,
                 lint_report=None):
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
        # The pack-lint report for the activated members (wave-206):
        # None only when the lint did not run (unknown purpose);
        # otherwise a gov.pack_lint.LintReport.
        self.lint_report = lint_report

    @property
    def lint_failed(self):
        """True when the activated pack failed the pack lint.

        In LOG_ONLY mode a lint-failed pack still activates, but
        every evaluation built from it must carry the
        ``pack-lint-failed`` marker.
        """
        return (self.lint_report is not None
                and not self.lint_report.clean)

    @property
    def lint_violations(self):
        """The lint violations on the activated pack (empty when clean)."""
        if self.lint_report is None:
            return ()
        return self.lint_report.violations

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
                 format_tag=_rp.RULE_PACK_FORMAT,
                 enforcement_mode="log_only"):
        from .keyset import Keyset
        if not isinstance(keyset, Keyset):
            raise TypeError("keyset must be a Keyset")
        if enforcement_mode not in ("log_only", "enforce"):
            raise PackActivationError(
                "bad-enforcement-mode",
                "enforcement_mode must be 'log_only' or 'enforce', "
                "got %r" % (enforcement_mode,))
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
        # Wave-206 LOG_ONLY -> ENFORCE graduation (Cedar symcc
        # discipline): packs load in LOG_ONLY by default; ENFORCE
        # refuses lint-failed packs and needs an explicit two-operator
        # promotion. The mode only gates activation; it never weakens
        # signature / enumeration / version / guard checks.
        self._enforcement_mode = enforcement_mode
        self._current = None
        self._highest_version = 0
        self._failures = []
        self._mode_changes = []

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

    @property
    def enforcement_mode(self):
        """``"log_only"`` or ``"enforce"`` (wave-206 graduation)."""
        return self._enforcement_mode

    @property
    def mode_changes(self):
        """Telemetry for enforcement-mode changes (bounded, newest
        last). Each entry: ``{pack_id, mode, operators,
        pack_version}``."""
        return list(self._mode_changes)

    def _record_mode_change(self, mode, operators):
        self._mode_changes.append({
            "pack_id": self._pack_id,
            "mode": mode,
            "operators": list(operators),
            "pack_version": (self._current.version
                             if self._current is not None else None),
        })
        # Bounded telemetry: keep the newest 64.
        del self._mode_changes[:-64]

    @staticmethod
    def _check_operators(operator_ids, need):
        """Validate operator identities for a mode change.

        ``need`` distinct non-empty string identities are required.
        Returns the deduplicated list. Raises PackActivationError --
        a ceremony with fewer (or duplicate, or non-string)
        identities is refused, never silently accepted.
        """
        if isinstance(operator_ids, bool) or not isinstance(
                operator_ids, (list, tuple)):
            raise PackActivationError(
                "bad-operator-ceremony",
                "operator_ids must be a list of %d distinct operator "
                "identities" % (need,))
        seen = []
        for op in operator_ids:
            if isinstance(op, bool) or not isinstance(op, str) \
                    or not op:
                raise PackActivationError(
                    "bad-operator-ceremony",
                    "operator identities must be non-empty strings")
            if op not in seen:
                seen.append(op)
        if len(seen) < need:
            raise PackActivationError(
                "bad-operator-ceremony",
                "need %d distinct operator identities, got %d"
                % (need, len(seen)))
        return seen

    def promote_to_enforce(self, operator_ids):
        """Promote this loader from LOG_ONLY to ENFORCE.

        Requires ``operator_ids`` to hold at least two DISTINCT
        non-empty operator identities (two-operator ceremony), and
        the currently active pack to be lint-clean. A promotion with
        fewer/distinct identities, or with a lint-failed active pack,
        is refused -- the loader stays in LOG_ONLY.
        """
        operators = self._check_operators(operator_ids, 2)
        if self._current is None:
            raise PackActivationError(
                "no-active-pack",
                "cannot promote to ENFORCE with no active pack")
        if self._current.lint_failed:
            raise PackActivationError(
                "pack-lint-failed",
                "cannot promote to ENFORCE: the active pack (v%d) "
                "failed lint:\n%s"
                % (self._current.version,
                   self._current.lint_report.summary()))
        self._enforcement_mode = "enforce"
        self._record_mode_change("enforce", operators)

    def demote_to_log_only(self, operator_id):
        """Return this loader to LOG_ONLY (one operator suffices to
        stand down; stepping DOWN never needs a quorum)."""
        operators = self._check_operators([operator_id], 1)
        self._enforcement_mode = "log_only"
        self._record_mode_change("log_only", operators)

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

    def _lint_members(self, files):
        """Run the pack lint over the verified member bytes.

        Dispatches on the loader's trust-domain purpose (detection
        rule packs vs PERM packs). Never raises: a linter that errors
        is itself reported as a violation (fail-closed -- a broken
        linter must not green-light a pack). Purposes outside the two
        lint-covered domains get a clean report with a note.
        """
        from . import pack_lint as _plint
        members = {mid: bytes(data) for mid, data in files.items()}
        try:
            if self._purpose == _rp.KEYSET_PURPOSE_PERM_PACK:
                model = members.get("perm-model.yml")
                policy = members.get("perm-policy.yml")
                if model is None or policy is None:
                    return _plint.LintReport(
                        violations=(_plint.LintViolation(
                            "pack", "lint/perm-pack-shape",
                            "PERM pack must carry perm-model.yml and "
                            "perm-policy.yml, got members %s"
                            % sorted(members)),),
                        checks=("lint/perm-pack-shape",))
                return _plint.lint_perm_pack(model, policy)
            if self._purpose == _rp.KEYSET_PURPOSE_RULE_PACK:
                return _plint.lint_capability_rule_files(members)
            return _plint.LintReport(
                checks=("lint/not-applicable",),
                note="purpose %r is not a lint-covered domain"
                     % (self._purpose,))
        except Exception as exc:  # noqa: BLE001 -- fail-closed
            return _plint.LintReport(
                violations=(_plint.LintViolation(
                    "pack", "lint/internal-error",
                    "linter failed: %s: %s"
                    % (type(exc).__name__, exc)),),
                checks=("lint/internal-error",))

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
        ``pack-member-digest-mismatch`` (enumeration),
        ``pack-lint-failed`` (wave-206: lint failed in ENFORCE mode),
        and ``pack-activation-denied`` /
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
        # Wave-206 pack lint (Cedar symcc discipline): the members are
        # signature- and digest-verified at this point, so the lint
        # runs over exactly the bytes the pack binds. In ENFORCE mode
        # a lint-failed pack is refused (pack-lint-failed) before the
        # guard runs; in LOG_ONLY (the default) it activates with the
        # lint_failed marker on the ActivePack.
        lint_report = self._lint_members(files)
        if self._enforcement_mode == "enforce" and not lint_report.clean:
            _fail("pack-lint-failed",
                  "pack failed lint and the loader is in ENFORCE "
                  "mode:\n%s" % lint_report.summary())
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
            self._purpose, self._format_tag,
            lint_report=lint_report)
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
