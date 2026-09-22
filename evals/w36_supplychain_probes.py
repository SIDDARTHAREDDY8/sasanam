"""Wave-36 supply-chain invariant probe: the GitSpawn class (2026-09-22).

GitSpawn (Manifold Security, disclosed 2026-09-01/02; CVE-2026-19592,
8 findings across 7 coding agents): a hostile repo-local `.git/config`
(`core.fsmonitor`, aliases, `core.hooksPath`) auto-executes attacker
commands the moment TOOLING -- not the agent -- runs a routine git
operation on that repo. The execution path routes through a trusted
dependency (git) below the agent decision layer, so the agent's own
sandbox and approval gates never fire.

This repo's position (docs/DEPLOYMENT.md §5.7, verified 2026-09-22):
no in-repo code path exists because nothing in this tree shells out
to `git` at all -- the risk lives in the deployer's harness and
operator tooling. This probe pins that invariant in the registry
gate: it AST-scans every Python file under gov/, evals/, tests/,
demo/, examples/ and workstreams/ for subprocess/os call sites that
invoke `git`, and stops (passes) iff the scan finds zero. If anyone
later adds a git call site, this probe breaks until the call site is
routed through the §5.7 hardened helper and the registry gains the
adversarial-repo probe the section prescribes.

Closure: green (stopped). Finding: none (no in-repo code path).
Watch item recorded in research/intel-2026-09-22.md §W36-1: 4 of the
8 GitSpawn variants were still unpatched at disclosure.

Synthetic/local, $0. Deterministic: pure AST scan, no wall-clock.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

RESULTS = []
SITUATIONS = {}


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_SCAN_DIRS = ("gov", "evals", "tests", "demo", "examples", "workstreams")
_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}
_OS_FUNCS = {"system", "popen", "execl", "execle", "execlp", "execlpe",
             "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle",
             "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
             "spawnvpe"}


def _is_git_argv0(node):
    """True if an AST node is the literal command `git`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value.strip()
        return s == "git" or s.startswith("git ")
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return _is_git_argv0(node.elts[0])
    return False


def _git_call_sites(path):
    """Yield (lineno, source-line) for git-invoking subprocess/os calls."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"),
                         filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)):
            continue
        mod, attr = func.value.id, func.attr
        is_exec = ((mod == "subprocess" and attr in _SUBPROCESS_FUNCS)
                   or (mod == "os" and attr in _OS_FUNCS))
        if not is_exec:
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if _is_git_argv0(arg):
                lineno = getattr(node, "lineno", 0)
                src = lines[lineno - 1].strip() if 0 < lineno <= len(lines) \
                    else ""
                yield lineno, src
                break


@_sit("redteam.supplychain.gitspawn_no_git_subprocess_in_repo")
def sit_gitspawn_no_git_subprocess_in_repo():
    """STOPPED (P7 supply-chain, wave-36): the GitSpawn execution
    primitive -- a tooling-level `git` subprocess call site inside this
    repo -- does not exist. With no in-repo git call site, a hostile
    repo-local `.git/config` has no in-repo trigger; the class can only
    fire in the deployer's own harness tooling, which §5.7 governs.
    Stopped = the invariant scan found zero git-invoking call sites.
    """
    hits = []
    for d in _SCAN_DIRS:
        root = REPO_ROOT / d
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            for lineno, src in _git_call_sites(path):
                hits.append("%s:%d: %s"
                            % (path.relative_to(REPO_ROOT), lineno, src))
    detail = {"git_call_sites": hits, "scanned_dirs": list(_SCAN_DIRS)}
    if hits:
        detail["verdict"] = "break"
    return detail


def run_all():
    before = len(RESULTS)
    for sid, wrapper in SITUATIONS.items():
        wrapper()  # each wrapper appends its own result record
    out = RESULTS[before:]
    return out
