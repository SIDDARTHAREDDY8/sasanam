"""F111 (wave-34): harness credential compartmentalization.

GTG-50020 (Anthropic September 2026 threat-intel report,
STUPID-2026-0104, severity 9.2/10): a Russian-speaking
financially-motivated actor prompt-injected an AI vendor's automated
eval sandbox; the sandbox handed over credentials it held, including
production multi-provider AI API keys; the actor's tooling
auto-switched to the victim's keys and hit ~30 AI companies in four
days on the victim's bill and identity. The harness/eval pipeline is
a first-class deployment surface: production credentials reachable
from an agent that processes untrusted input is the failure.

Two in-scope residuals, both closed here:

(a) CREDENTIAL MANIFEST: the harness declares every credential it
    provisions into the agent's reachable scope. ``declare()`` asserts
    at declaration time that the mounted material is NOT
    production-shaped (a production-shaped secret at a declared path
    is rejected outright -- the non-production assertion), and
    ``verify_scope()`` scans the reachable scope for
    credential-shaped material (the DLP patterns): anything
    credential-shaped at an UNDECLARED path fails closed -- the run
    refuses to start -- and declared paths are RE-ASSERTED
    non-production-shaped at verify time (wave-35 RT5: closes the
    declare -> swap -> verify TOCTOU). The agent's reachable
    credential set is thus asserted scoped, short-lived (ttl_s),
    non-production.

(b) IDENTITY-BOUND EGRESS: ``check_egress()`` resolves the owner of
    a credential presented on an egress call (manifest-registered
    ``credential_id``, an explicit ``credential_owner`` parameter, or
    DLP-detected credential-shaped material with no registration)
    against the provisioned session identity's principal; anything not
    bound to the session identity is a mismatch. The DLP leg runs
    FIRST and is never short-circuited by an owner claim (wave-35 RT5:
    a self-asserted ``credential_owner`` matching the session
    principal used to skip it). ToolExecutor feeds this into the
    ``credential_identity_mismatch`` policy signal, and the policy rule
    of the same id denies + audits.

Documented boundary (not a gap): downstream reuse of stolen keys from
attacker infrastructure against third parties is out of scope by
construction -- no governance layer stops key use outside its
deployment. Standing check (not a control claim): eval/CI harnesses
run on throwaway creds only.
"""

import os
import time
from pathlib import Path

from . import dlp as _dlp

__all__ = [
    "CredentialManifestError",
    "CredentialManifest",
    "PRODUCTION_CREDENTIAL_RULES",
]


class CredentialManifestError(Exception):
    """Fail-closed refusal of a credential-provisioning violation."""


#: DLP rule ids treated as PRODUCTION-shaped credential material.
#: A match at declaration time rejects the declaration outright (the
#: non-production assertion). ``dlp-stripe-test-key`` is deliberately
#: excluded -- test keys are the non-production shape the manifest
#: exists to allow. ``dlp-jwt`` is excluded as ambiguous (synthetic
#: fixtures mint JWT-shaped tokens; a JWT's production-ness is not in
#: its shape) -- documented, not an oversight.
PRODUCTION_CREDENTIAL_RULES = frozenset({
    "dlp-stripe-live-key",
    "dlp-aws-access-key",
    "dlp-github-token",
    "dlp-private-key",
    "dlp-slack-token",
    "dlp-google-api-key",
    "dlp-connection-string",
})

_PRODUCTION_RES = [
    rx for rule_id, rx in _dlp._CREDENTIAL_RULES
    if rule_id in PRODUCTION_CREDENTIAL_RULES
]


def _production_hit(text):
    """Return the production rule id matching *text*, or None."""
    for rule_id, rx in _dlp._CREDENTIAL_RULES:
        if rule_id in PRODUCTION_CREDENTIAL_RULES and rx.search(text):
            return rule_id
    return None


def _walk_files_followlinks(root):
    """Yield every regular file under *root*, following directory
    symlinks (F112).

    ``Path.rglob`` never descends into symlinked directories, which
    left production credentials behind an undeclared dir-symlink
    invisible to ``verify_scope`` while the agent's own read path
    follows the link. This walk uses ``os.walk(followlinks=True)``
    and keys every visited directory by ``(st_dev, st_ino)``:
    re-entering an already-seen directory prunes the descent, so a
    symlink cycle terminates instead of hanging the pre-run check.
    Results are yielded in sorted order for determinism.
    """
    seen_dirs = set()
    for dirpath, dirnames, filenames in os.walk(str(root),
                                                followlinks=True):
        try:
            key = os.stat(dirpath)[:2]  # (st_dev, st_ino), follows links
        except OSError:
            dirnames[:] = []
            continue
        if key in seen_dirs:
            dirnames[:] = []
            continue
        seen_dirs.add(key)
        dirnames.sort()
        for filename in sorted(filenames):
            p = Path(dirpath) / filename
            # is_file() follows symlinks: a file-symlink (even one
            # pointing outside the root) is scanned as the file it
            # resolves to -- the agent reads it the same way.
            if p.is_file():
                yield p


class CredentialManifest:
    """The deployer-declared credential provisioning record for a run.

    The harness calls :meth:`declare` once per credential it mounts
    into the agent's reachable scope, then :meth:`verify_scope` before
    the run starts (or after any new mount). Anything credential-shaped
    in scope that is not declared fails closed.
    """

    def __init__(self):
        # credential_id -> {path, owner_principal, scope, expires_at}
        self._entries = {}
        # declared relative paths (posix) covered by an entry
        self._declared_paths = set()

    def declare(self, path, *, credential_id, owner_principal, scope,
                ttl_s=3600):
        """Declare a harness-mounted credential.

        ``path``: the mounted file, relative to the agent's reachable
        scope root (or absolute -- stored as given). The declaration
        covers the file itself (compared by realpath at verify time),
        so declaring either the symlink path or the real path covers
        both views. The file's content is asserted NON-production-shaped:
        a production-shaped secret here raises
        ``CredentialManifestError`` -- the harness cannot provision a
        production credential into the agent's reach, full stop.
        Fail-closed on unreadable files: what cannot be scanned cannot
        be asserted non-production.
        """
        if not credential_id or not isinstance(credential_id, str):
            raise CredentialManifestError(
                "declare requires a non-empty credential_id")
        if not owner_principal or not isinstance(owner_principal, str):
            raise CredentialManifestError(
                "declare requires a non-empty owner_principal")
        if credential_id in self._entries:
            raise CredentialManifestError(
                "credential_id %r already declared" % credential_id)
        try:
            content = Path(path).read_text(encoding="utf-8",
                                            errors="strict")
        except (OSError, UnicodeError) as exc:
            raise CredentialManifestError(
                "cannot assert non-production for %r: %s"
                % (path, exc))
        hit = _production_hit(content)
        if hit is not None:
            raise CredentialManifestError(
                "production_credential_rejected: %r at %r matches %s; "
                "production credentials must never be provisioned into "
                "the agent's reachable scope" % (credential_id, path, hit))
        now = int(time.time())
        self._entries[credential_id] = {
            "path": str(path),
            "owner_principal": owner_principal,
            "scope": scope,
            "expires_at": now + int(ttl_s),
        }
        self._declared_paths.add(str(path))
        return credential_id

    def __len__(self):
        """Number of declared credentials (F115: lets the executor tell
        "manifest with declared credentials but no session identity"
        apart from "no credentials declared at all")."""
        return len(self._entries)

    def verify_scope(self, root):
        """Fail closed on any credential-shaped material in scope that
        is not covered by a declaration.

        ``root``: the agent's reachable scope root. Every file whose
        content matches a DLP credential rule must be at a declared
        path; otherwise the run must not start.

        Directory symlinks are FOLLOWED (wave-40, F112): ``rglob``
        never descends into symlinked directories, so a production
        credential behind an undeclared dir-symlink used to be
        invisible to this scan while remaining readable to the agent.
        The walk is cycle-safe: each visited directory is keyed by
        ``(st_dev, st_ino)`` and re-entering an already-seen directory
        prunes the descent, so a symlink loop cannot hang the pre-run
        check.

        Declared paths are re-asserted NON-production-shaped here
        (wave-35 RT5 hardening): this closes the declare -> swap ->
        verify TOCTOU -- a declared file whose content became
        production-shaped after declaration fails closed instead of
        being skipped. Declared files hold non-production credentials
        by the declare-time assertion, so production-shaped content at
        a declared path is never legitimate.
        """
        root = Path(root)
        violations = []
        # Declared paths cover the FILE (inode), not the string: a
        # declaration made through a symlink (or any other path alias)
        # covers every other alias of the same file. Compare realpaths
        # alongside the as-given strings (the string comparison keeps
        # the pre-F112 behavior for identical strings).
        declared_real = set()
        for d in self._declared_paths:
            try:
                declared_real.add(os.path.realpath(d))
            except OSError:
                pass
        for p in _walk_files_followlinks(root):
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                continue
            try:
                real = os.path.realpath(str(p))
            except OSError:
                real = None
            declared = (rel in self._declared_paths
                        or str(p) in self._declared_paths
                        or (real is not None and real in declared_real))
            try:
                content = p.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError):
                continue  # unreadable/binary: not credential-shaped text
            if declared:
                # TOCTOU backstop: the declare-time non-production
                # assertion is re-checked at verify time. The general
                # credential-shape check stays skipped for declared
                # paths (they legitimately hold non-production
                # credentials); only production-shaped content is a
                # violation here.
                hit = _production_hit(content)
                if hit is not None:
                    violations.append(
                        (rel, "production_at_declared_path:%s" % hit))
                continue
            rule = _dlp.find_credential(content)
            if rule is not None:
                violations.append((rel, rule))
        if violations:
            raise CredentialManifestError(
                "undeclared_credential_in_scope: %s"
                % ", ".join("%s (%s)" % v for v in violations))

    def owner_of(self, credential_id):
        """Return the declared owner principal, or None if unknown."""
        entry = self._entries.get(credential_id)
        return entry["owner_principal"] if entry else None

    def is_expired(self, credential_id, now=None):
        entry = self._entries.get(credential_id)
        if entry is None:
            return True  # unknown ids never authorize
        now = int(time.time()) if now is None else int(now)
        return int(entry["expires_at"]) <= now

    def check_egress(self, args, session_principal, *, audit=None):
        """Identity-bind one egress call's credential use.

        Returns True when the call is bound to the session identity,
        False on mismatch (= deny + audit via the
        ``credential_identity_mismatch`` policy signal).

        Resolution order:
          1. DLP credential-shaped material in top-level string args
             with no registration -> unregistered = mismatch
             (fail-closed). This leg is evaluated FIRST and is never
             short-circuited by an owner/credential_id claim (wave-35
             RT5: a self-asserted ``credential_owner`` matching the
             session principal used to skip this leg entirely).
          2. explicit ``credential_id`` arg -> manifest owner (unknown
             or expired id = mismatch, fail-closed);
          3. explicit ``credential_owner`` arg -> compared directly.
        No session identity provisioned -> True (nothing to bind to;
        documented: the rule requires a provisioned session identity).

        Wave-219: the no-identity pass is a registered unsafe path --
        ``gov.credential_manifest.no_session_identity_binding_skipped``
        -- emitted through the audit path (``audit``: list or callable)
        on EVERY execution.
        """
        if session_principal is None:
            from . import unsafe_paths as _up
            _up.emit(
                "gov.credential_manifest."
                "no_session_identity_binding_skipped",
                audit=audit,
                detail=("egress credential check passed with no session "
                        "identity provisioned: nothing was bound (the "
                        "rule requires a provisioned session identity)"))
            return True
        args = args or {}
        for value in args.values():
            if isinstance(value, str) and _dlp.find_credential(value):
                # Credential-shaped material with no manifest
                # registration and no declared owner: fail closed.
                # Raw key bytes never travel legitimately -- the
                # product binds credentials by credential_id
                # reference, and the DLP arg scan blocks raw bytes
                # end to end -- so this leg agrees with it.
                return False
        credential_id = args.get("credential_id")
        if credential_id is not None:
            owner = self.owner_of(credential_id)
            if owner is None:
                return False
            if self.is_expired(credential_id):
                return False
            return owner == session_principal
        declared_owner = args.get("credential_owner")
        if declared_owner is not None:
            return declared_owner == session_principal
        return True
