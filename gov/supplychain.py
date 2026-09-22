"""Supply-chain controls: lockfile, package allowlist, artifact verification.

Closes F75 (unpinned dependency graph): the governed surface used to start
*after* dependency resolution — a dependency-confusion or typosquat package
in the install path ran with operator privileges, outside every control.
This module provides the three missing pieces:

1. **Lockfile** (``requirements.lock`` at the repo root): every dependency
   pinned to an exact version with sha256 hashes for *all* published
   artifacts (wheel + sdist, every platform), so
   ``pip install --require-hashes -r requirements.lock`` verifies whatever
   artifact pip selects. Regenerate with
   ``python -m gov.supplychain --regen-lock`` (PyPI JSON API, $0).
2. **Package allowlist**, enforced at install/test-bootstrap time:
   :func:`audit_environment` enumerates every installed distribution and
   fails closed on anything not in the lockfile (unlisted) or whose
   version differs from the pin (tampered/drifted). ``tests/run_tests.py``
   runs this audit before test collection — a poisoned venv cannot run
   the suite green.
3. **Fetch-artifact verification**: :func:`verify_artifact` (sha256 of the
   fetched bytes against the lockfile pins) is the primitive any real
   fetch tool must call. ``pip install --require-hashes`` already enforces
   it at install time; the explicit function exists for the documented
   contract below and for tests.

Contract for real fetches (F75 fix direction): ``api_call`` in this
product is *simulated* — no real bytes leave the machine. Any future
governed fetch tool that downloads real artifacts MUST (a) check the
package name against :func:`package_allowlist`, (b) verify the artifact
with :func:`verify_artifact` before use, and (c) install only from
``requirements.lock`` via :func:`install_locked`. Publisher-identity
verification (Sigstore/TUF) is the documented production direction;
hash-pinning is the mechanism enforced here.

Honest boundaries
-----------------
* The audit checks *names and versions* of installed distributions, not
  the bytes of installed files: post-install tampering of site-packages
  files is not detected (that is the F17-class residual — compromised
  implementations act below governance). ``RECORD``-hash verification is
  future hardening, not claimed here.
* ``agent-governance`` itself (the local editable project) is allowlisted
  by name only — it is the source tree under test, not a fetched
  artifact.
* Hash pins come from the PyPI JSON API at regen time; a compromised
  PyPI account publishing a malicious *new* artifact under a *new*
  version is not stopped (only the pinned versions install).

Venv workflow (the exact commands)
---------------------------------
    VENV=/home/hatch/workspace/agent-governance-demo/.venv/bin/python
    # fresh / verified install:
    $VENV -m pip install --require-hashes -r requirements.lock
    # audit the environment (fail-closed):
    $VENV -m gov.supplychain --audit
    # run the suite (audits automatically before collection):
    TMPDIR=/tmp/gov-run $VENV tests/run_tests.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from importlib.metadata import distributions

# The local project: allowlisted by name (it is the source tree under
# test, not a fetched artifact). Version is not pinned — it comes from
# pyproject.toml and moves with the repo.
_LOCAL_PROJECT = "agent-governance"


class SupplyChainError(RuntimeError):
    """Fail-closed supply-chain violation (unlisted/tampered/malformed)."""


def _canonical(name):
    """PEP 503-ish normalization without the `packaging` dependency."""
    return re.sub(r"[-_.]+", "-", name).lower()


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def lockfile_path():
    return os.path.join(repo_root(), "requirements.lock")


# -- lockfile ---------------------------------------------------------------

def load_lockfile(path=None):
    """Parse requirements.lock -> {canonical name: entry dict}.

    Entry: {"name": <as written>, "version": <str>,
            "hashes": frozenset("sha256:<hex>")}.
    Any malformed line fails closed (SupplyChainError) — a hand-edited
    lockfile must never be silently half-read.
    """
    path = path or lockfile_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise SupplyChainError("lockfile unreadable: %s (%s)" % (path, e))
    entries = {}
    current = None
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            if current is None:
                raise SupplyChainError(
                    "lockfile %s:%d: --hash without a package line"
                    % (path, lineno))
            line = line[:-1].rstrip() if line.endswith("\\") else line
            m = re.fullmatch(r"--hash=([a-z0-9]+):([0-9a-fA-F]+)", line)
            if not m:
                raise SupplyChainError(
                    "lockfile %s:%d: malformed hash pin %r"
                    % (path, lineno, line))
            algo, digest = m.group(1), m.group(2).lower()
            if algo != "sha256" or len(digest) != 64:
                raise SupplyChainError(
                    "lockfile %s:%d: only sha256/64-hex pins accepted, got %r"
                    % (path, lineno, line))
            current["hashes"].add("%s:%s" % (algo, digest))
            continue
        if line.endswith("\\"):
            line = line[:-1].rstrip()
            if current is not None and not current["hashes"]:
                raise SupplyChainError(
                    "lockfile %s:%d: entry %r has no --hash pins"
                    % (path, lineno, current["name"]))
            current = None  # previous entry (if any) is complete
            m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+!]+)",
                             line)
            if not m:
                raise SupplyChainError(
                    "lockfile %s:%d: malformed pin %r (expected name==version)"
                    % (path, lineno, line))
            name, version = m.group(1), m.group(2)
            key = _canonical(name)
            if key in entries:
                raise SupplyChainError(
                    "lockfile %s:%d: duplicate entry for %r"
                    % (path, lineno, name))
            current = {"name": name, "version": version, "hashes": set()}
            entries[key] = current
            continue
        raise SupplyChainError(
            "lockfile %s:%d: unparseable line %r" % (path, lineno, raw))
    if current is not None and not current["hashes"]:
        raise SupplyChainError(
            "lockfile: entry %r has no --hash pins" % current["name"])
    for key, entry in entries.items():
        if not entry["hashes"]:
            raise SupplyChainError(
                "lockfile: entry %r has no --hash pins" % entry["name"])
        entry["hashes"] = frozenset(entry["hashes"])
    if not entries:
        raise SupplyChainError("lockfile %s: no entries parsed" % path)
    return entries


def package_allowlist(lock=None):
    """Canonical names allowed in the environment: lockfile + local project."""
    lock = lock if lock is not None else load_lockfile()
    return frozenset(lock) | {_canonical(_LOCAL_PROJECT)}


# -- artifact verification ----------------------------------------------------

def verify_artifact(path, expected_hashes, *, algorithm="sha256"):
    """Hash a fetched artifact and compare against the lockfile pins.

    Returns the hex digest on success; raises SupplyChainError on
    mismatch (fail closed). ``expected_hashes`` is the entry's
    ``hashes`` frozenset ("sha256:<hex>" strings).
    """
    if algorithm != "sha256":
        raise SupplyChainError("only sha256 artifact verification supported")
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        raise SupplyChainError("cannot read artifact %s (%s)" % (path, e))
    digest = h.hexdigest()
    want = {x.split(":", 1)[1] for x in expected_hashes
            if x.startswith("sha256:")}
    if digest not in want:
        raise SupplyChainError(
            "artifact %s hash mismatch: got sha256:%s, not in lockfile pins "
            "(%d pinned)" % (path, digest, len(want)))
    return digest


# -- environment audit (the allowlist enforcement point) ----------------------

def _iter_installed(dists=None):
    if dists is not None:
        for item in dists:
            if isinstance(item, tuple):
                yield item[0], item[1]
            else:  # importlib.metadata Distribution
                yield item.metadata["Name"], item.version
        return
    for d in distributions():
        name = d.metadata.get("Name")
        if name:
            yield name, d.version


def audit_environment(lock=None, *, _dists=None):
    """Fail-closed audit: every installed distribution must be allowlisted
    at the pinned version.

    Returns {"ok": True, "checked": N, "allowlisted": N} on success.
    Raises SupplyChainError listing every violation otherwise — unlisted
    packages (typosquat/dependency-confusion shape) and version drift
    (tampered or hand-upgraded installs) both fail closed.
    """
    lock = lock if lock is not None else load_lockfile()
    allowed = package_allowlist(lock)
    violations = []
    checked = 0
    for name, version in _iter_installed(_dists):
        key = _canonical(name)
        checked += 1
        if key not in allowed:
            violations.append("unlisted package: %s==%s" % (name, version))
            continue
        if key == _canonical(_LOCAL_PROJECT):
            continue  # local source tree: name-allowlisted only
        pinned = lock[key]["version"]
        if version != pinned:
            violations.append(
                "version drift: %s==%s installed, lockfile pins %s"
                % (name, version, pinned))
    if violations:
        raise SupplyChainError(
            "supply-chain audit failed (%d violation(s)):\n  %s"
            % (len(violations), "\n  ".join(sorted(violations))))
    return {"ok": True, "checked": checked, "allowlisted": len(allowed)}


def check_install_allowed(name, lock=None):
    """Refuse to install a package that is not in the allowlist.

    The fail-closed gate for any future governed installer: raises
    SupplyChainError before pip is ever invoked.
    """
    lock = lock if lock is not None else load_lockfile()
    if _canonical(name) not in package_allowlist(lock):
        raise SupplyChainError(
            "install refused: %r is not in the package allowlist "
            "(requirements.lock)" % name)
    return lock[_canonical(name)]


def install_locked(*, dry_run=False):
    """Install exactly the lockfile, verifying artifact hashes.

    ``pip install --require-hashes`` makes pip check every downloaded
    artifact against the pinned sha256 digests — a tampered mirror or
    MITM cannot slip a different artifact past this.
    """
    path = lockfile_path()
    load_lockfile(path)  # fail closed on a malformed lockfile first
    cmd = [sys.executable, "-m", "pip", "install",
           "--require-hashes", "-r", path]
    if dry_run:
        cmd.insert(4, "--dry-run")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SupplyChainError(
            "pip install --require-hashes failed:\n%s"
            % (r.stderr.strip()[-2000:] or r.stdout.strip()[-2000:]))
    return {"ok": True, "dry_run": dry_run}


# -- lockfile regeneration ------------------------------------------------------

_LOCKFILE_HEADER = """\
# requirements.lock — pinned dependency graph for agent-governance
# Generated from the PyPI JSON API (`python -m gov.supplychain --regen-lock`).
# Install with:  python -m pip install --require-hashes -r requirements.lock
# Every entry carries sha256 hashes for ALL published artifacts, so
# `pip install --require-hashes` verifies whatever artifact pip selects,
# on any platform. Do NOT hand-edit versions/hashes — regen instead.
"""


def _marker_eval(marker):
    """Minimal PEP 508 environment-marker evaluator (stdlib only).

    Supports and/or/not, parentheses, ==, !=, <, <=, >, >=, ~=, in,
    not in, and the common variables (sys_platform, python_version,
    python_full_version, platform_python_implementation, platform_machine,
    os_name, extra). ``extra`` is always "" — the locked workflow never
    installs extras, so extra-gated requirements are excluded. Raises
    SupplyChainError on anything it cannot parse (fail closed: an
    unevaluable marker must not silently drop or add a dependency).
    """
    import platform as _plat

    _TOK = re.compile(r"""
        \s*(?:
        (?P<str>'[^']*'|"[^"]*")
        |(?P<op>~=|===|==|!=|<=|>=|<|>)
        |(?P<in>\bin\b)|(?P<not>\bnot\b)|(?P<and>\band\b)|(?P<or>\bor\b)
        |(?P<word>[A-Za-z_][A-Za-z0-9_.]*)
        |(?P<lp>\()|(?P<rp>\))|(?P<comma>,)
        )\s*""", re.VERBOSE)

    pos, toks = 0, []
    while pos < len(marker):
        m = _TOK.match(marker, pos)
        if not m:
            raise SupplyChainError("cannot parse marker %r" % marker)
        pos = m.end()
        kind = m.lastgroup
        toks.append((kind, m.group(0).strip()))
    toks.append(("end", ""))

    env = {
        "sys_platform": sys.platform,
        "os_name": os.name,
        "platform_machine": _plat.machine(),
        "platform_system": _plat.system(),
        "platform_python_implementation": _plat.python_implementation(),
        "python_version": "%d.%d" % sys.version_info[:2],
        "python_full_version": _plat.python_version(),
        "extra": "",
    }

    i = 0

    def peek():
        return toks[i][0]

    def next_tok():
        nonlocal i
        t = toks[i]
        i += 1
        return t

    def parse_or():
        # NOTE: no short-circuit — both sides must always be parsed so no
        # tokens are left unconsumed.
        v = parse_and()
        while peek() == "or":
            next_tok()
            rhs = parse_and()
            v = v or rhs
        return v

    def parse_and():
        v = parse_not()
        while peek() == "and":
            next_tok()
            rhs = parse_not()
            v = v and rhs
        return v

    def parse_not():
        nonlocal i
        if peek() == "not":
            # "not in" is handled in parse_cmp; bare "not" negates
            save = i
            next_tok()
            if peek() in ("word", "str", "lp"):
                return not parse_cmp()
            i = save
        return parse_cmp()

    def operand():
        k, v = next_tok()
        if k == "str":
            return v[1:-1]
        if k == "word":
            if v not in env:
                raise SupplyChainError(
                    "marker variable %r not supported" % v)
            return env[v]
        raise SupplyChainError("cannot parse marker %r" % marker)

    def _ver_tuple(s):
        return tuple(int(p) if p.isdigit() else p
                     for p in re.split(r"[.\-]", str(s)))

    def cmp_op(op, a, b):
        if op == "===":
            return str(a) == str(b)
        if op in ("==", "!=", "<", "<=", ">", ">="):
            # version-ish comparison when both sides look numeric-dotted
            if re.fullmatch(r"[0-9][0-9.\-]*", str(a)) and \
               re.fullmatch(r"[0-9][0-9.\-]*", str(b)):
                ta, tb = _ver_tuple(a), _ver_tuple(b)
                n = max(len(ta), len(tb))
                ta += (0,) * (n - len(ta))
                tb += (0,) * (n - len(tb))
                res = (ta > tb) - (ta < tb)
                return {"==": res == 0, "!=": res != 0, "<": res < 0,
                        "<=": res <= 0, ">": res > 0, ">=": res >= 0}[op]
            sa, sb = str(a), str(b)
            return {"==": sa == sb, "!=": sa != sb, "<": sa < sb,
                    "<=": sa <= sb, ">": sa > sb, ">=": sa >= sb}[op]
        if op == "~=":
            # compatible release: == prefix, >= lower bound
            ta, tb = _ver_tuple(a), _ver_tuple(b)
            if len(tb) < 2:
                raise SupplyChainError("bad ~= in marker %r" % marker)
            prefix = tb[:-1]
            return (ta[:len(prefix)] == prefix
                    and (ta > tb or ta == tb))
        raise SupplyChainError("bad operator in marker %r" % marker)

    def parse_cmp():
        if peek() == "lp":
            next_tok()
            v = parse_or()
            if peek() != "rp":
                raise SupplyChainError("cannot parse marker %r" % marker)
            next_tok()
            return v
        a = operand()
        k = peek()
        if k == "not":
            next_tok()
            if peek() != "in":
                raise SupplyChainError("cannot parse marker %r" % marker)
            next_tok()
            return str(a) not in str(operand())
        if k == "in":
            next_tok()
            return str(a) in str(operand())
        if k == "op":
            op = next_tok()[1]
            return cmp_op(op, a, operand())
        raise SupplyChainError("cannot parse marker %r" % marker)

    result = parse_or()
    if peek() != "end":
        raise SupplyChainError("cannot parse marker %r" % marker)
    return bool(result)


def _split_req(req_str):
    """Split 'name[extra]; marker' -> (name, marker)."""
    head, _, marker = req_str.partition(";")
    name = re.split(r"[ \[(<>=!~]", head.strip(), 1)[0].strip()
    return name, marker.strip()


def _closure(roots):
    seen = set()
    stack = list(roots)
    dists = {_canonical(d.metadata["Name"]): d for d in distributions()
             if d.metadata.get("Name")}
    while stack:
        key = _canonical(stack.pop())
        if key in seen:
            continue
        seen.add(key)
        d = dists.get(key)
        if d is None:
            raise SupplyChainError(
                "regen: %r is not installed; cannot pin its version" % key)
        for req_str in (d.requires or []):
            name, marker = _split_req(req_str)
            if not name:
                continue
            if marker and not _marker_eval(marker):
                continue
            stack.append(name)
    return seen, dists


def regen_lockfile(roots=("pydantic", "langchain-core", "PyYAML",
                           "pip", "setuptools")):
    """Regenerate requirements.lock from the PyPI JSON API.

    Pins the *currently installed* versions of the dependency closure —
    i.e. the exact graph the suite ran against — with sha256 digests for
    every published artifact. $0 (public PyPI JSON API).
    """
    closure, dists = _closure(roots)
    chunks = [_LOCKFILE_HEADER]
    for key in sorted(closure):
        d = dists[key]
        name, version = d.metadata["Name"], d.version
        url = "https://pypi.org/pypi/%s/%s/json" % (key, version)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = json.load(r)
        except Exception as e:
            raise SupplyChainError(
                "regen: PyPI JSON fetch failed for %s==%s (%s)"
                % (name, version, e))
        files = data.get("urls") or []
        if not files:
            raise SupplyChainError(
                "regen: PyPI lists no artifacts for %s==%s" % (name, version))
        chunks.append("%s==%s \\" % (name, version))
        for f in files:
            digest = (f.get("digests") or {}).get("sha256")
            if not digest or len(digest) != 64:
                raise SupplyChainError(
                    "regen: bad digest for %s (%s)"
                    % (f.get("filename"), name))
            chunks.append("    --hash=sha256:%s \\" % digest.lower())
        chunks[-1] = chunks[-1].rstrip(" \\")
        chunks.append("")
    path = lockfile_path()
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(chunks))
    return {"ok": True, "path": path, "packages": len(closure)}


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="gov.supplychain")
    p.add_argument("--audit", action="store_true",
                   help="fail-closed audit of the current environment")
    p.add_argument("--regen-lock", action="store_true",
                   help="regenerate requirements.lock from the PyPI JSON API")
    p.add_argument("--verify", metavar="FILE",
                   help="verify a fetched artifact against the lockfile; "
                        "requires --package NAME")
    p.add_argument("--package", metavar="NAME",
                   help="package name for --verify")
    args = p.parse_args(argv)
    try:
        if args.audit:
            rep = audit_environment()
            print("supply-chain audit OK: %d distributions checked, "
                  "%d allowlisted" % (rep["checked"], rep["allowlisted"]))
            return 0
        if args.regen_lock:
            rep = regen_lockfile()
            print("lockfile regenerated: %s (%d packages)"
                  % (rep["path"], rep["packages"]))
            return 0
        if args.verify:
            if not args.package:
                print("--verify requires --package NAME")
                return 2
            entry = check_install_allowed(args.package)
            digest = verify_artifact(args.verify, entry["hashes"])
            print("artifact OK: sha256:%s" % digest)
            return 0
    except SupplyChainError as e:
        print("SUPPLY-CHAIN FAIL-CLOSED: %s" % e)
        return 1
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
