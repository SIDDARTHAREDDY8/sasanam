"""Session-startup trust ordering for every shell-out against agent workspaces.

Design input (ADAPT, not vendored): the GitSpawn execution primitive -- a
hostile repo-local ``.git/config`` naming command-executing keys
(``core.fsmonitor``, ``core.sshCommand``, ...) auto-executes attacker
commands the moment ANY git command runs against that repo, BELOW the agent
decision layer and, critically, PRE-TRUST-PROMPT: session-orienting
background git invocations run before any trust decision is recorded.

``gov/git_sanitize.py`` is deny-first INSIDE its entry point, but nothing
makes the TRUST DECISION itself a first-class primitive with a pinned
ordering. This module is that primitive, stdlib-only:

* :class:`TrustRegistry` -- an explicit, deployment-owned record of which
  workspace roots the operator trusts. States: ``untrusted`` (the
  DEFAULT; every repo starts here), ``verified-allowed``,
  ``verified-denied``. Recording trust requires an explicit ``decided_by``
  principal; invented states fail closed (``session-trust-malformed``).
* :func:`resolve_repo_root` -- canonicalizes a workspace path and
  refuses ``repo-hook-escape-refused`` when repo-local git material
  (``.git``, ``.git/config``) resolves outside the root (hook resolution
  never follows worktree-local symlinks out of the repo root). Shared-gitdir
  worktree layouts resolve outside the root by design and are refused here;
  a deployer that needs them registers the gitdir explicitly instead.
* :func:`checked_spawn` -- the single blessed entry point, in a pinned
  order that the ``w244_session_trust_ordering`` battery falsifies on any
  inversion:

    1. resolve the repo root (escape check);
    2. consult the trust state FIRST -- ``untrusted`` refuses
       ``repo-hook-pretrust-refused``, ``verified-denied`` refuses
       ``repo-hook-trust-denied``; the audit sink records the refusal;
    3. re-use :func:`gov.git_sanitize.deny_config_keys` -- a hostile
       config refuses ``gitspawn-hostile-config`` even on a trusted repo
       (trust is not a config bypass);
    4. re-use :func:`gov.git_sanitize.sanitized_git_env`;
    5. ``spawn`` defaults to None and then refuses
       ``gitspawn-in-repo-git-refused`` (the standing wave-36 invariant:
       zero in-repo git call sites; the real spawn lives in the
       deployer's harness OUTSIDE the scanned tree).

* Audit discipline: every pre-trust/denial refusal is offered to the
  deployment-supplied ``audit`` callable as a structured record carrying
  the refusal code and a sha256 digest of the canonical repo root. The
  hook PATH and all config VALUES are redacted (paths are
  deployment-owned; content is never logged). ``audit`` defaults to a
  no-op: the module never blocks on logging.

Honest boundaries (stated, not absorbed):

* This module cannot stop a git binary the caller invokes WITHOUT going
  through it. The guarantee is the pinned order INSIDE the entry point
  (trust consulted before any config read, before any spawn) plus loud
  refusal when the entry point is bypassed.
* Trust records are in-memory unless the deployment supplies persistence;
  distributed/multi-process consistency is deployment-owned.
* The registry proves a trust decision was RECORDED, not that the operator
  recorded it wisely -- a malicious insider with ``record_trust`` access
  is out of scope.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import hashlib
import os

try:
    from gov import git_sanitize as _gs
except ImportError:  # pragma: no cover - defensive only; repo always ships it
    _gs = None

# ---------------------------------------------------------------------------
# Trust states
# ---------------------------------------------------------------------------

UNTRUSTED = "untrusted"
ALLOWED = "verified-allowed"
DENIED = "verified-denied"
TRUST_STATES = frozenset([UNTRUSTED, ALLOWED, DENIED])

# ---------------------------------------------------------------------------
# Refusals (registered vocabulary -- no ad-hoc refusal strings)
# ---------------------------------------------------------------------------

PRETRUST_REFUSED = "repo-hook-pretrust-refused"
TRUST_DENIED = "repo-hook-trust-denied"
ESCAPE_REFUSED = "repo-hook-escape-refused"
MALFORMED = "session-trust-malformed"

_REFUSALS = frozenset([PRETRUST_REFUSED, TRUST_DENIED, ESCAPE_REFUSED,
                       MALFORMED])


def registered_refusals():
    """The complete registered refusal vocabulary."""
    return sorted(_REFUSALS)


class SessionTrustError(Exception):
    """Loud trust-ordering failure. ``code`` is the machine-readable
    refusal; ``detail`` is a human sentence carrying no paths, no keys,
    and no config values."""

    def __init__(self, code, detail=""):
        if code not in _REFUSALS:
            raise SessionTrustError(
                MALFORMED,
                "unregistered refusal code attempted: %r" % (code,))
        super(SessionTrustError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def raise_refusal(code, detail=""):
    """Raise :class:`SessionTrustError` for a registered code only."""
    raise SessionTrustError(code, detail)


def _repo_digest(root):
    return hashlib.sha256(root.encode("utf-8")).hexdigest()[:16]


def _emit_audit(audit, code, root):
    if audit is None:
        return
    record = {
        "event": "trust-refusal",
        "code": code,
        # Redacted: only a digest of the canonical root. The hook path
        # is deployment-owned and config values are never logged.
        "repo_digest": _repo_digest(root),
    }
    audit(record)


# ---------------------------------------------------------------------------
# Root resolution (no symlink escapes)
# ---------------------------------------------------------------------------

def resolve_repo_root(path):
    """Canonicalize ``path`` to an absolute, symlink-resolved repo root.

    Refuses :data:`ESCAPE_REFUSED` when repo-local git material
    (``.git``, ``.git/config``) resolves outside the canonical root.
    A non-git workspace (no ``.git``) resolves cleanly; the trust
    ordering still applies to it.
    """
    if not isinstance(path, str) or not path:
        raise_refusal(MALFORMED, "repo path must be a non-empty string")
    root = os.path.realpath(os.path.abspath(path))
    for rel in (".git", ".git", os.path.join(".git", "config")):
        candidate = os.path.join(root, rel)
        if os.path.lexists(candidate):
            resolved = os.path.realpath(candidate)
            try:
                inside = os.path.commonpath([root, resolved]) == root
            except ValueError:
                inside = False
            if not inside:
                raise_refusal(
                    ESCAPE_REFUSED,
                    "repo-local git material resolves outside the root")
    return root


# ---------------------------------------------------------------------------
# Trust registry
# ---------------------------------------------------------------------------


class TrustRegistry(object):
    """Explicit, in-memory trust record keyed by canonical repo root.

    Every repo is :data:`UNTRUSTED` until an operator records otherwise.
    """

    def __init__(self):
        self._states = {}

    def record_trust(self, repo_path, state, *, decided_by):
        """Record a trust decision. ``decided_by`` is required and must
        name the deciding principal; invented states fail closed."""
        if state not in TRUST_STATES:
            raise_refusal(
                MALFORMED,
                "unknown trust state %r; must be one of %s"
                % (state, sorted(TRUST_STATES)))
        if not isinstance(decided_by, str) or not decided_by.strip():
            raise_refusal(MALFORMED, "decided_by must name a principal")
        root = resolve_repo_root(repo_path)
        self._states[root] = {
            "state": state,
            "decided_by": decided_by.strip(),
        }
        return root

    def state_of(self, repo_path):
        """The recorded state; :data:`UNTRUSTED` when never recorded."""
        root = os.path.realpath(os.path.abspath(repo_path))
        entry = self._states.get(root)
        if entry is None:
            return UNTRUSTED
        return entry["state"]


# ---------------------------------------------------------------------------
# The blessed entry point (pinned order)
# ---------------------------------------------------------------------------


def checked_spawn(args, repo_path, registry, spawn=None, *, audit=None):
    """Trust-ordered git spawn against ``repo_path``.

    Pinned order (falsified on inversion by
    ``evals/w244_session_trust_ordering_probes.py``):

    1. resolve the root (escape check);
    2. consult the trust state FIRST -- untrusted refuses
       ``repo-hook-pretrust-refused``, denied refuses
       ``repo-hook-trust-denied`` (refusal offered to ``audit``);
    3. hostile-config deny (reuses ``gov.git_sanitize``);
    4. sanitized env; ``spawn`` or wave-36 in-repo refusal.

    ``spawn`` is a callable ``(argv, env, cwd)`` supplied by the
    deployer's harness; ``None`` (the default) refuses
    ``gitspawn-in-repo-git-refused``.
    """
    if registry is None or not isinstance(registry, TrustRegistry):
        raise_refusal(MALFORMED, "a TrustRegistry is required")
    if _gs is None:  # pragma: no cover - defensive only
        raise_refusal(MALFORMED, "gov.git_sanitize unavailable")
    root = resolve_repo_root(repo_path)
    state = registry.state_of(root)
    if state == UNTRUSTED:
        _emit_audit(audit, PRETRUST_REFUSED, root)
        raise_refusal(
            PRETRUST_REFUSED,
            "no trust decision recorded for this workspace; "
            "record trust before any git subprocess")
    if state == DENIED:
        _emit_audit(audit, TRUST_DENIED, root)
        raise_refusal(TRUST_DENIED,
                      "trust explicitly denied for this workspace")
    # State is verified-allowed: hostile config STILL refuses -- trust is
    # not a config bypass. deny_config_keys raises gitspawn-hostile-config.
    _gs.deny_config_keys(root)
    env = _gs.sanitized_git_env(root)
    if spawn is None:
        raise _gs.GitSpawnInRepoRefusedError(
            "gitspawn-in-repo-git-refused",
            "no in-repo git call site: pass a harness spawn callable "
            "outside the scanned tree (wave-36 invariant)")
    return spawn(["git"] + list(args), env=env, cwd=root)
