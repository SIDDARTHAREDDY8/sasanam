#!/usr/bin/env python3
"""Wave-226 lane B: sanitized git config for ALL agent subprocesses.

ADAPT of the GitSpawn hostile-.git/config exec-sink class
(CVE-2026-19592/45033/55607 per the wave-225 prospecting sweep --
re-derived prose; nothing copied): a hostile repo-local .git/config
can name command-executing keys (core.fsmonitor, core.sshCommand,
core.pager, diff.external, filter smudge/clean, alias !-shells, ...)
that git runs as subprocesses the moment ANY git command executes
against that repo. Wave-224 hardened only the eval batteries; this
lane generalizes the discipline to every agent git subprocess.

Seams under test:
* gov/git_sanitize.py — sanitized_git_env(repo_path) -> env mapping
  neutralizing global/system config (GIT_CONFIG_GLOBAL/SYSTEM=/dev/null)
  and allowlisting safe.directory for exactly repo_path via
  GIT_CONFIG_COUNT/KEY_0/VALUE_0.
* deny_config_keys(repo_path) — scans repo_path/.git/config (and any
  include/includeIf-chained files, cycle-safe) for exec-sink keys and
  refuses ``gitspawn-hostile-config`` BEFORE any subprocess can spawn,
  listing the offending keys; malformed/unparseable config fails
  closed with ``gitspawn-config-unparseable``.
* run_git_sanitized(args, repo_path, spawn=None) — the blessed entry
  point: deny-first, then invoke the caller-supplied spawn callable with
  argv/cwd and the sanitized env. The standing wave-36 invariant is
  ZERO in-repo git call sites, so spawn=None refuses
  ``gitspawn-in-repo-git-refused``: the actual spawn must live in the
  deployer's harness, outside the scanned tree.

Attack shapes: hostile core.fsmonitor hook, hostile core.sshCommand,
!-prefixed alias and credential.helper shells, include-chain smuggled
exec keys, malformed config, in-repo spawn attempt.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against wave-225 HEAD
0fb51624e6162c1846501e93b9ab3dd2127f7873.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP -- the
seams do not exist on base.

$0 spend. No network. stdlib only. Real product code, no stubs.
NO in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them): fixtures are written directly, never via git init.

Run:
  mkdir -p /var/tmp/g226b
  TMPDIR=/var/tmp/g226b \
      ~/workspace/.gov-venv/bin/python evals/w226_gitsan_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g226b-u \\
      ~/workspace/.gov-venv/bin/python evals/w226_gitsan_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g226b-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import git_sanitize as gs  # noqa: E402
    _GS_OK = True
except Exception:  # noqa: BLE001 - import probe records it
    _GS_OK = False
    gs = None

_IMPORT_OK = _GS_OK
_IMPORT_ERR = "gov.git_sanitize absent (pristine)" if not _GS_OK else ""

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name, detail="absent on base"):
    # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
    # gap-demonstrated evidence in the note.
    _record(name, "BREAK", "GAP: " + detail)


def _break(name, detail):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", exc.__class__.__name__)


def _expect_refusal(name, code, fn):
    """BREAK unless fn raises an exception carrying ``code``."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - verdict logic
        if _code_of(exc) == code:
            _held(name, "refused %s" % code)
        else:
            _break(name, "wrong refusal: %r (wanted %s)" % (exc, code))
        return
    _break(name, "no refusal (wanted %s)" % code)


def _fixture(name, config_text=None, raw_bytes=None, extra_files=None):
    """Build a fake repo dir with .git/config written directly.

    No git subprocess is ever used: the fixtures are plain files.
    Returns the repo path."""
    root = os.path.join(os.environ["TMPDIR"], "gitsan", name)
    gitdir = os.path.join(root, ".git")
    os.makedirs(gitdir, exist_ok=True)
    cfg = os.path.join(gitdir, "config")
    if raw_bytes is not None:
        with open(cfg, "wb") as fh:
            fh.write(raw_bytes)
    elif config_text is not None:
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write(config_text)
    for rel, data in (extra_files or {}).items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(p, mode) as fh:
            fh.write(data)
    return root


CLEAN_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "[user]\n"
    "\tname = harness\n"
    "[alias]\n"
    "\tst = status\n"
)


@_probe("r-hostile-fsmonitor")
def _p_fsmonitor():
    if not _IMPORT_OK:
        return _gap("r-hostile-fsmonitor", _IMPORT_ERR)
    hook = os.path.join(os.environ["TMPDIR"], "gitsan", "evil-hook.sh")
    marker = hook + ".marker"
    repo = _fixture("fsmonitor",
                    "[core]\n\tfsmonitor = %s\n" % hook)
    if os.path.exists(marker):
        return _break("r-hostile-fsmonitor", "marker pre-exists")
    _expect_refusal("r-hostile-fsmonitor", "gitspawn-hostile-config",
                    lambda: gs.deny_config_keys(repo))
    # Offending keys must be named, not swallowed.
    try:
        gs.deny_config_keys(repo)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        keys = getattr(exc, "offending_keys", []) or []
        if not any("core.fsmonitor" in k for k in keys):
            return _break("r-hostile-fsmonitor",
                          "offending keys not listed: %r" % (keys,))
    # Deny-first ordering: the blessed entry point must refuse before
    # any exec callable is invoked; the hook can never fire.
    calls = []

    def _fake(argv, env=None, cwd=None):
        calls.append((argv, env, cwd))
        return 0

    _expect_refusal("r-hostile-fsmonitor",
                    "gitspawn-hostile-config",
                    lambda: gs.run_git_sanitized(["status"], repo,
                                                 spawn=_fake))
    if calls:
        return _break("r-hostile-fsmonitor",
                      "exec invoked before deny: %r" % (calls,))
    if os.path.exists(marker):
        return _break("r-hostile-fsmonitor", "hook fired")
    _held("r-hostile-fsmonitor", "denied before spawn; hook never ran")


@_probe("r-hostile-sshcommand")
def _p_sshcommand():
    if not _IMPORT_OK:
        return _gap("r-hostile-sshcommand", _IMPORT_ERR)
    repo = _fixture("sshcommand",
                    "[core]\n\tsshCommand = ssh -i /tmp/evil-key\n")
    _expect_refusal("r-hostile-sshcommand", "gitspawn-hostile-config",
                    lambda: gs.deny_config_keys(repo))
    try:
        gs.deny_config_keys(repo)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        keys = getattr(exc, "offending_keys", []) or []
        if not any("core.sshcommand" in k for k in keys):
            return _break("r-hostile-sshcommand",
                          "offending keys not listed: %r" % (keys,))
    _held("r-hostile-sshcommand", "core.sshCommand named and refused")


@_probe("r-alias-and-helper-bang")
def _p_alias_bang():
    if not _IMPORT_OK:
        return _gap("r-alias-and-helper-bang", _IMPORT_ERR)
    # '!'-prefixed aliases and credential helpers are shells.
    repo = _fixture("aliasbang",
                    '[alias]\n\tx = !evil --flag\n'
                    '[credential "https://example.test"]\n'
                    '\thelper = !evil-cred\n')
    _expect_refusal("r-alias-and-helper-bang", "gitspawn-hostile-config",
                    lambda: gs.deny_config_keys(repo))
    # Benign aliases and helpers are NOT hostile.
    repo2 = _fixture("aliasclean",
                     '[alias]\n\tst = status\n'
                     '[credential "https://example.test"]\n'
                     '\thelper = store\n')
    try:
        gs.deny_config_keys(repo2)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        return _break("r-alias-and-helper-bang",
                      "benign alias/helper refused: %r" % (exc,))
    _held("r-alias-and-helper-bang",
          "only !-shells refused; benign aliases pass")


@_probe("r-include-chain-smuggled")
def _p_include_chain():
    if not _IMPORT_OK:
        return _gap("r-include-chain-smuggled", _IMPORT_ERR)
    # An exec key smuggled through an include chain must still be
    # caught: the scan follows includes (cycle-safe). Include paths
    # are relative to the INCLUDING file's directory (git semantics).
    repo = _fixture(
        "includechain",
        "[include]\n\tpath = ../a.inc\n",
        extra_files={
            "a.inc": "[include]\n\tpath = b.inc\n",
            "b.inc": "[include]\n\tpath = a.inc\n"
                     "[core]\n\tpager = /tmp/evil-pager\n",
        })
    _expect_refusal("r-include-chain-smuggled",
                    "gitspawn-hostile-config",
                    lambda: gs.deny_config_keys(repo))
    try:
        gs.deny_config_keys(repo)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        keys = getattr(exc, "offending_keys", []) or []
        if not any("core.pager" in k for k in keys):
            return _break("r-include-chain-smuggled",
                          "smuggled key not listed: %r" % (keys,))
    _held("r-include-chain-smuggled",
          "include chain followed; cycle did not hang")


@_probe("r-malformed-config-failclosed")
def _p_malformed():
    if not _IMPORT_OK:
        return _gap("r-malformed-config-failclosed", _IMPORT_ERR)
    repo = _fixture("malformed",
                    raw_bytes=b"[core]\n\xff\xfe not utf8 \x00 binary\n")
    _expect_refusal("r-malformed-config-failclosed",
                    "gitspawn-config-unparseable",
                    lambda: gs.deny_config_keys(repo))
    repo2 = _fixture("malformed2",
                     raw_bytes=b"orphan-key = value\n[core]\n")
    _expect_refusal("r-malformed-config-failclosed",
                    "gitspawn-config-unparseable",
                    lambda: gs.deny_config_keys(repo2))
    _held("r-malformed-config-failclosed",
          "unparseable config fails closed")


@_probe("r-clean-repo-allowed")
def _p_clean():
    if not _IMPORT_OK:
        return _gap("r-clean-repo-allowed", _IMPORT_ERR)
    repo = _fixture("clean", CLEAN_CONFIG)
    try:
        gs.deny_config_keys(repo)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        return _break("r-clean-repo-allowed",
                      "clean config refused: %r" % (exc,))
    # No .git/config at all: nothing to scan, pass.
    repo2 = os.path.join(os.environ["TMPDIR"], "gitsan", "noconfig")
    os.makedirs(repo2, exist_ok=True)
    try:
        gs.deny_config_keys(repo2)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        return _break("r-clean-repo-allowed",
                      "configless repo refused: %r" % (exc,))
    _held("r-clean-repo-allowed", "clean and configless pass")


@_probe("r-env-protections")
def _p_env():
    if not _IMPORT_OK:
        return _gap("r-env-protections", _IMPORT_ERR)
    repo = _fixture("env", CLEAN_CONFIG)
    env = gs.sanitized_git_env(repo)
    for key, want in (("GIT_CONFIG_GLOBAL", "/dev/null"),
                      ("GIT_CONFIG_SYSTEM", "/dev/null"),
                      ("GIT_CONFIG_COUNT", "1"),
                      ("GIT_CONFIG_KEY_0", "safe.directory"),
                      ("GIT_CONFIG_VALUE_0", repo)):
        if env.get(key) != want:
            return _break("r-env-protections",
                          "%s = %r, wanted %r" % (key, env.get(key),
                                                  want))
    _held("r-env-protections",
          "global/system neutralized; safe.directory pinned")


@_probe("r-safedir-allowlist-exact")
def _p_safedir():
    if not _IMPORT_OK:
        return _gap("r-safedir-allowlist-exact", _IMPORT_ERR)
    repo_a = _fixture("safea", CLEAN_CONFIG)
    repo_b = _fixture("safeb", CLEAN_CONFIG)
    va = gs.sanitized_git_env(repo_a)["GIT_CONFIG_VALUE_0"]
    vb = gs.sanitized_git_env(repo_b)["GIT_CONFIG_VALUE_0"]
    if va != repo_a or vb != repo_b or va == vb:
        return _break("r-safedir-allowlist-exact",
                      "allowlist not exact per-repo: %r %r" % (va, vb))
    _held("r-safedir-allowlist-exact", "exact per-repo allowlist")


@_probe("r-fake-exec-ordering")
def _p_fake_exec():
    if not _IMPORT_OK:
        return _gap("r-fake-exec-ordering", _IMPORT_ERR)
    repo = _fixture("fakeexec", CLEAN_CONFIG)
    calls = []

    def _fake(argv, env=None, cwd=None):
        calls.append({"argv": argv, "env": env, "cwd": cwd})
        return 0

    rc = gs.run_git_sanitized(["rev-parse", "HEAD"], repo, spawn=_fake)
    if rc != 0 or len(calls) != 1:
        return _break("r-fake-exec-ordering",
                      "fake exec not invoked exactly once: %r" % (calls,))
    call = calls[0]
    # Clean repos: argv and cwd are byte-identical to a raw spawn;
    # ONLY the env is hardened.
    if call["argv"] != ["git", "rev-parse", "HEAD"]:
        return _break("r-fake-exec-ordering",
                      "argv altered: %r" % (call["argv"],))
    if call["cwd"] != repo:
        return _break("r-fake-exec-ordering",
                      "cwd altered: %r" % (call["cwd"],))
    if call["env"].get("GIT_CONFIG_GLOBAL") != "/dev/null":
        return _break("r-fake-exec-ordering", "env not hardened")
    _held("r-fake-exec-ordering",
          "deny-first; clean repos argv/cwd byte-identical")


@_probe("r-in-repo-exec-refused")
def _p_in_repo_refused():
    if not _IMPORT_OK:
        return _gap("r-in-repo-exec-refused", _IMPORT_ERR)
    repo = _fixture("inrepo", CLEAN_CONFIG)
    # The standing wave-36 invariant is zero in-repo git call sites:
    # the entry point must REFUSE to spawn without a harness-supplied
    # spawn rather than create one.
    _expect_refusal("r-in-repo-exec-refused",
                    "gitspawn-in-repo-git-refused",
                    lambda: gs.run_git_sanitized(["status"], repo))
    _held("r-in-repo-exec-refused", "no in-repo git call site created")


@_probe("r-w36-stays-green")
def _p_w36():
    # The w36 supply-chain probe must keep passing: this lane adds no
    # in-repo git call site. Focused run of the single situation.
    try:
        sys.path.insert(0, os.path.join(REPO, "evals"))
        import w36_supplychain_probes as w36  # noqa: E402
    except Exception as exc:  # noqa: BLE001 - verdict logic
        return _break("r-w36-stays-green",
                      "cannot import w36 probes: %r" % (exc,))
    sid = "redteam.supplychain.gitspawn_no_git_subprocess_in_repo"
    try:
        w36.RESULTS.clear()
        w36.SITUATIONS[sid]()
        recs = [r for r in w36.RESULTS if r.get("id") == sid]
    except Exception as exc:  # noqa: BLE001 - verdict logic
        return _break("r-w36-stays-green", "w36 sit crashed: %r" % (exc,))
    if not recs:
        return _break("r-w36-stays-green", "w36 recorded nothing")
    if recs[0].get("verdict") == "break":
        return _break("r-w36-stays-green",
                      "w36 broke: %r"
                      % (recs[0].get("detail", {}).get("git_call_sites"),))
    _held("r-w36-stays-green", "zero in-repo git call sites")


def _green_checks():
    import subprocess  # noqa: E402
    if GREEN_SKIP:
        _record("green-skip", "HELD", "GOV_SKIP_GREEN=1")
        return
    suites = [
        ("adjacent-test_git_sanitize", ["tests/test_git_sanitize.py"]),
    ]
    for name, argv in suites:
        try:
            env = dict(os.environ)
            env["GOV_SKIP_GREEN"] = "1"
            env.setdefault("TMPDIR", "/var/tmp/g226b-green")
            os.makedirs(env["TMPDIR"], exist_ok=True)
            proc = subprocess.run(
                [sys.executable, "-m", "unittest"] + argv,
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=600)
            if proc.returncode == 0:
                _held(name, "green")
            else:
                tail = (proc.stderr or proc.stdout)[-500:]
                _record(name, "ERROR", "exit %d: %s"
                        % (proc.returncode, tail))
        except Exception as exc:  # noqa: BLE001 - verdict logic
            _record(name, "ERROR", "green check failed: %s" % exc)


def main():
    for name, fn in sorted(_PROBE_FNS.items()):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a probe must
            # never take the battery down
            _record(name, "ERROR", "probe crashed: %r" % (exc,))
    _green_checks()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("== w226 gitsan probes ==")
    _coh_ok, _coh_diags = probe_lines.check_coherence(_RESULTS, brk, held, err)
    probe_lines.emit(_RESULTS)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    det = "PASS"
    if _IMPORT_OK:
        try:
            repo = _fixture("determinism", CLEAN_CONFIG)
            a = gs.sanitized_git_env(repo)
            b = gs.sanitized_git_env(repo)
            det = "PASS" if a == b else "FAIL"
        except Exception:  # noqa: BLE001 - determinism verdict
            det = "FAIL"
    print("determinism %s" % det)
    sys.exit(1 if (brk or err) else 0)


if __name__ == "__main__":
    main()
