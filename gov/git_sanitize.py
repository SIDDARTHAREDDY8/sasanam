"""Sanitized git config for every agent git subprocess (GitSpawn class).

Design input (ADAPT, not vendored): the GitSpawn execution primitive
-- a hostile repo-local ``.git/config`` naming command-executing keys
(``core.fsmonitor``, ``core.sshCommand``, ``core.pager``,
``diff.external``, ``filter.<d>.smudge/clean``, ``alias`` ``!``-shells,
``credential.*.helper`` ``!``-shells, ...) auto-executes attacker
commands the moment ANY git command runs against that repo, below the
agent decision layer. This module is the single hardened helper that
docs/DEPLOYMENT.md section 5.7 prescribes: every git subprocess an
agent (or its harness) runs against a repo the agent provided or
fetched must pass through it.

What this module provides, stdlib-only:

* :func:`sanitized_git_env` -- env mapping that neutralizes
  global/system config (``GIT_CONFIG_GLOBAL=/dev/null``,
  ``GIT_CONFIG_SYSTEM=/dev/null``, ``GIT_CONFIG_NOSYSTEM=1``) and
  allowlists ``safe.directory`` for EXACTLY ``repo_path`` via the
  ``GIT_CONFIG_COUNT/KEY_0/VALUE_0`` mechanism. The allowlist is
  per-repo: a different repo gets a different value; attacker
  paths are never added.
* :func:`deny_config_keys` -- scans ``repo_path/.git/config`` (and any
  ``include``/``includeIf``-chained files, cycle-safe) for exec-sink
  keys and refuses ``gitspawn-hostile-config`` BEFORE any subprocess
  can spawn, listing the offending keys. Unparseable config fails
  closed (``gitspawn-config-unparseable``): an attacker who can write
  the config can also write garbage.
* :func:`run_git_sanitized` -- the single blessed entry point:
  deny-first, then invoke the caller-supplied ``spawn`` callable with
  ``(argv, env, cwd)``. The standing wave-36 invariant is ZERO in-repo
  ``git`` call sites (pinned by
  ``evals/w36_supplychain_probes.py``), so ``spawn=None`` (the
  default) refuses ``gitspawn-in-repo-git-refused``: the actual spawn
  must live in the deployer's harness, OUTSIDE the scanned tree.
  Clean repos see argv/cwd byte-identical to a raw spawn; ONLY the
  env is hardened.

Exec-sink key table (re-derived from git's documented config
semantics, not copied from any advisory text):

* Exact keys, always hostile: ``core.fsmonitor``,
  ``core.fsmonitorhookversion``, ``core.sshcommand``, ``core.pager``,
  ``core.editor``, ``sequence.editor``, ``core.askpass``,
  ``core.hookspath``, ``gpg.program``, ``diff.external``.
* Wildcard keys, always hostile: ``diff.*.command``,
  ``merge.*.command``, ``filter.*.smudge``, ``filter.*.clean``,
  ``filter.*.process``, ``mergetool.*.cmd``, ``difftool.*.cmd``.
* ``alias.*`` and ``credential.*.helper``: hostile ONLY when the
  value starts with ``!`` (a shell command); benign aliases and the
  ``store``/``cache`` helpers are legitimate and pass.
* ``include.path`` / ``includeif.*.path``: followed recursively
  (relative to the including file's directory, bounded depth, visited
  set) so smuggled keys cannot hide in chained files.

Honest boundaries (stated, not absorbed):

* This module cannot stop a git binary the caller invokes WITHOUT
  going through it. The guarantee is deny-first ordering INSIDE the
  entry point, plus refusal when the entry point is bypassed.
* Env neutralizes global/system config only. Repo-local config is
  neutralized by the deny-scan: a repo whose config refuses is never
  spawned against, period.
* ``safe.directory`` permits exactly one directory; ownership checks
  beyond that are the harness's job.
* Secrets stay in the environment; nothing here logs config values.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import os

# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


class GitSanitizeError(Exception):
    """Loud git-hygiene failure: hostile config, unparseable config, or
    an in-repo spawn attempt. ``code`` is the machine-readable failure
    mode; ``offending_keys`` names the hostile keys when known."""

    def __init__(self, code, detail="", offending_keys=()):
        super(GitSanitizeError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail
        self.offending_keys = list(offending_keys)


class GitSpawnHostileConfigError(GitSanitizeError):
    """``gitspawn-hostile-config``: an exec-sink key was found."""


class GitSanitizeUnparseableError(GitSanitizeError):
    """``gitspawn-config-unparseable``: config failed closed."""


class GitSpawnInRepoRefusedError(GitSanitizeError):
    """``gitspawn-in-repo-git-refused``: no in-repo git call site."""


# ---------------------------------------------------------------------------
# Exec-sink key table
# ---------------------------------------------------------------------------

_EXACT_HOSTILE = frozenset({
    "core.fsmonitor",
    "core.fsmonitorhookversion",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "sequence.editor",
    "core.askpass",
    "core.hookspath",
    "gpg.program",
    "diff.external",
})

# (section, subsection-required, suffix) wildcard rules; a key matches
# when its section equals ``section``, it has a subsection, and its
# bare name equals ``suffix``.
_WILDCARD_HOSTILE = (
    ("diff", "command"),
    ("merge", "command"),
    ("filter", "smudge"),
    ("filter", "clean"),
    ("filter", "process"),
    ("mergetool", "cmd"),
    ("difftool", "cmd"),
)

# Keys hostile only when the value is a "!" shell command.
_BANG_HOSTILE = frozenset({"alias", "credential"})

_INCLUDE_KEYS = frozenset({"include", "includeif"})

_MAX_INCLUDE_DEPTH = 8


# ---------------------------------------------------------------------------
# Config parsing (fail-closed, stdlib only)
# ---------------------------------------------------------------------------

def _split_key(section, subsection, name):
    """Canonical dotted key, e.g. ``credential.https://x.helper``."""
    if subsection:
        return "%s.%s.%s" % (section, subsection, name)
    return "%s.%s" % (section, name)


def _parse_git_config(path):
    """Parse a git config file into [(section, subsection, name, value)].

    Raises GitSanitizeUnparseableError on undecodable bytes or on a
    key/value line outside any section. This is deliberately stricter
    than git: fail closed on anything we cannot read exactly.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise GitSanitizeUnparseableError(
            "gitspawn-config-unparseable",
            "cannot read %s: %s" % (path, exc))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GitSanitizeUnparseableError(
            "gitspawn-config-unparseable",
            "non-UTF8 bytes in %s" % path)
    entries = []
    section = None
    subsection = None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("["):
            if not stripped.endswith("]"):
                raise GitSanitizeUnparseableError(
                    "gitspawn-config-unparseable",
                    "%s:%d: bad section header" % (path, lineno))
            inner = stripped[1:-1].strip()
            if '"' in inner:
                # [section "subsection"] form
                head, _, rest = inner.partition('"')
                section = head.strip().lower()
                subsection = rest.rsplit('"', 1)[0]
            else:
                section = inner.lower()
                subsection = None
            if not section:
                raise GitSanitizeUnparseableError(
                    "gitspawn-config-unparseable",
                    "%s:%d: empty section" % (path, lineno))
            continue
        if "=" not in stripped:
            raise GitSanitizeUnparseableError(
                "gitspawn-config-unparseable",
                "%s:%d: key without '=' outside grammar" % (path, lineno))
        if section is None:
            raise GitSanitizeUnparseableError(
                "gitspawn-config-unparseable",
                "%s:%d: key outside any section" % (path, lineno))
        name, _, value = stripped.partition("=")
        name = name.strip().lower()
        if not name:
            raise GitSanitizeUnparseableError(
                "gitspawn-config-unparseable",
                "%s:%d: empty key" % (path, lineno))
        entries.append((section, subsection, name, value.strip()))
    return entries


def _is_hostile(section, subsection, name, value):
    """True when (section, subsection, name, value) is an exec sink."""
    dotted = _split_key(section, subsection, name)
    if dotted in _EXACT_HOSTILE:
        return True
    if subsection and (section, name) in _WILDCARD_HOSTILE:
        return True
    if section in _BANG_HOSTILE and value.startswith("!"):
        return True
    return False


def _collect_entries(config_path, _depth=0, _seen=None):
    """All (key, section, value) entries incl. include chains."""
    if _seen is None:
        _seen = set()
    real = os.path.realpath(config_path)
    if real in _seen or _depth > _MAX_INCLUDE_DEPTH:
        return []
    _seen.add(real)
    entries = _parse_git_config(config_path)
    out = list(entries)
    base = os.path.dirname(real)
    for section, _subsection, name, value in entries:
        if section not in _INCLUDE_KEYS or name != "path":
            continue
        # include.path / includeIf.<cond>.path
        inc = os.path.join(base, os.path.expanduser(value))
        if os.path.isfile(inc):
            out.extend(_collect_entries(inc, _depth + 1, _seen))
    return out


def _git_config_path(repo_path):
    """Locate the repo-local config file, or None.

    Handles plain repos (repo/.git/config) and linked worktrees
    (repo/.git is a ``gitdir:`` pointer file)."""
    repo = os.path.abspath(repo_path)
    dotgit = os.path.join(repo, ".git")
    if os.path.isdir(dotgit):
        cfg = os.path.join(dotgit, "config")
        return cfg if os.path.isfile(cfg) else None
    if os.path.isfile(dotgit):
        try:
            with open(dotgit, "r", encoding="utf-8") as fh:
                first = fh.readline().strip()
        except (OSError, UnicodeDecodeError):
            return None
        if first.startswith("gitdir:"):
            target = first[len("gitdir:"):].strip()
            if not os.path.isabs(target):
                target = os.path.join(repo, target)
            cfg = os.path.join(target, "config")
            return cfg if os.path.isfile(cfg) else None
    return None


# ---------------------------------------------------------------------------
# Public seams
# ---------------------------------------------------------------------------

def deny_config_keys(repo_path):
    """Refuse BEFORE any git subprocess may spawn against ``repo_path``.

    Scans the repo-local config (plus include chains) for exec-sink
    keys. Raises :class:`GitSpawnHostileConfigError`
    (``gitspawn-hostile-config``) listing ``offending_keys`` when any
    are found, or :class:`GitSanitizeUnparseableError`
    (``gitspawn-config-unparseable``) when the config cannot be read
    exactly. Returns None when the config is clean or absent.
    """
    cfg = _git_config_path(repo_path)
    if cfg is None:
        return None
    entries = _collect_entries(cfg)
    hostile = []
    for section, subsection, name, value in entries:
        if _is_hostile(section, subsection, name, value):
            hostile.append(_split_key(section, subsection, name))
    if hostile:
        raise GitSpawnHostileConfigError(
            "gitspawn-hostile-config",
            "exec-sink config keys present: %s" % ", ".join(hostile),
            offending_keys=hostile)
    return None


def sanitized_git_env(repo_path):
    """Env mapping hardening every git invocation against ``repo_path``.

    * ``GIT_CONFIG_GLOBAL=/dev/null`` and
      ``GIT_CONFIG_SYSTEM=/dev/null`` (+ ``GIT_CONFIG_NOSYSTEM=1``):
      global/system config -- which the deployer may not control --
      cannot re-enable execution primitives.
    * ``GIT_CONFIG_COUNT=1`` / ``GIT_CONFIG_KEY_0=safe.directory`` /
      ``GIT_CONFIG_VALUE_0=<repo_path>``: the safe.directory
      allowlist covers EXACTLY this repo; attacker-influenced paths
      are never added.

    Repo-local config is NOT neutralized by env: it is neutralized by
    :func:`deny_config_keys`, which must run first (see
    :func:`run_git_sanitized`).
    """
    repo = os.path.abspath(repo_path)
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "safe.directory"
    env["GIT_CONFIG_VALUE_0"] = repo
    return env


def run_git_sanitized(args, repo_path, spawn=None):
    """The single blessed git entry point: deny-first, then run.

    ``deny_config_keys(repo_path)`` runs BEFORE anything else; a
    hostile or unparseable config raises and no exec callable is ever
    invoked. On a clean config the sanitized env is built and the
    caller-supplied ``spawn(argv, env=env, cwd=repo_path)`` is invoked
    with ``argv == ["git"] + list(args)``; its return value is
    returned.

    ``spawn`` defaults to None and then raises
    :class:`GitSpawnInRepoRefusedError`
    (``gitspawn-in-repo-git-refused``): the standing wave-36
    invariant is zero in-repo ``git`` call sites, so this module --
    which lives inside the scanned tree -- must not create one. The
    actual spawn belongs in the deployer's harness, outside the
    scanned tree, where it calls this entry point with its own
    ``spawn``. Clean repos see argv/cwd byte-identical to a raw
    spawn; ONLY the env is hardened.
    """
    deny_config_keys(repo_path)
    env = sanitized_git_env(repo_path)
    if spawn is None:
        raise GitSpawnInRepoRefusedError(
            "gitspawn-in-repo-git-refused",
            "no in-repo git call site: pass a harness spawn callable outside "
            "the scanned tree (wave-36 invariant)")
    return spawn(["git"] + list(args), env=env,
                 cwd=os.path.abspath(repo_path))
