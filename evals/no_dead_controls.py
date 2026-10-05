#!/usr/bin/env python3
"""Dead-controls CI gate (wave-338 lane 3; Bernstein R16 STEAL, #5053/#4645/#5505).

Reimplemented from the Bernstein pattern (Apache-2.0, nothing copied):
a CI gate that refuses dead policy controls -- every policy control must
be live, no dead controls, no dead modules.

What this gate checks over ``gov/``:

1. **Module reachability (Bernstein #4645).** Every importable ``gov``
   module must be imported by a live root, or be a verified entry point,
   or be allowlisted. A module nobody imports fails the gate. Imports and
   only imports count as edges: docstring mentions, string literals, and
   comments reach nothing. Reachability is a fixpoint (Bernstein #5053):
   a module imported only by an unreached module stays unreached.
2. **Entry points.** An unimported module with an ``if __name__ ==
   "__main__"`` block is live IFF its invocation is documented and
   checkable: a ``pyproject.toml [project.scripts]`` target naming the
   module, or a ``python -m <dotted>`` literal in a docstring/doc/demo.
   An undocumented ``__main__`` block is camouflage, not an entry point.
3. **Decision-code liveness (R16).** Every code registered in
   ``gov/decision_codes.py`` must be raised in a *reached* gov module
   (non-docstring string literal; the registry file itself excluded).
   A registered code no reached module raises is a dead control.
4. **Allowlist with written reasons (Bernstein #4645).** Orphans excused
   only via ``evals/dead_controls_allowlist.md``. Every active entry
   needs a written reason (>= 20 chars, no placeholders) AND exactly one
   of ``finding: FNNN`` (present in ``evals/FINDINGS.md``) or
   ``expiry: YYYY-MM-DD`` (a future date) -- Bernstein #5505: an orphan
   needs an issue or an expiry. Missing reason, stale module/code,
   newly-reachable entry, expired entry, or unknown finding all fail.
5. **Shrink-only (Bernstein #4645).** With ``--base-allowlist <file>``
   the gate diffs the allowlist against the supplied base allowlist text:
   an entry removed without a ``Removed`` log line (module/code + wave +
   reason) fails. New active entries are only ever admitted through the
   finding-or-expiry ritual, never silently. The caller supplies the base
   text (e.g. checked out by the merge coordinator's own tooling) -- this
   gate never spawns a git subprocess itself (wave-36 supply-chain rule:
   no in-repo git call sites).
6. **Test-subject pinning (R32, wave-340; Bernstein #6073 ADAPT).** The
   tree under test is pinned (sha256 of every file's content, via
   ``evals/subject_pin.py``) before the analysis runs, and the pin is
   asserted invariant when the analysis finishes. A file modified,
   added, or removed mid-run (TOCTOU -- a concurrent writer changing
   the subject under the gate) fails the gate with the coded refusal
   ``deadctrl-subject-mutated``. The pin covers contents only
   (``.git``/``__pycache__`` excluded). ``--pin-subject <file>``
   persists the pin record for the CI log.

Exit codes: 0 = gate passes; 1 = gate refuses (dead surface found);
2 = usage / gate-internal error (never a pass).

Stdlib only. No network. $0 spend.
"""

import ast
import os
import re
import sys
import datetime

# R32 (wave-340): test-subject pinning. Tolerant import: the gate runs
# as `python evals/no_dead_controls.py` (script dir on sys.path) and is
# imported by batteries with the evals dir on sys.path; both layouts
# resolve a top-level subject_pin, with the package form as fallback.
try:
    import subject_pin as _subject_pin
except ImportError:
    from evals import subject_pin as _subject_pin

# Directories whose .py files are live roots: executed by CI or shipped
# as operator tooling. A missed root can only produce a *loud* false
# orphan (fail-closed direction); a spurious root would silence the gate.
LIVE_ROOTS = ("tests", "evals", "demo", "tools", "examples")

ALLOWLIST_RELPATH = os.path.join("evals", "dead_controls_allowlist.md")
FINDINGS_RELPATH = os.path.join("evals", "FINDINGS.md")
DECISION_CODES_RELPATH = os.path.join("gov", "decision_codes.py")
PYPROJECT_RELPATH = "pyproject.toml"

REASON_MIN_LEN = 20


# --------------------------------------------------------------------------
# Module enumeration + import edges
# --------------------------------------------------------------------------

def _dotted_of(path, root):
    rel = os.path.relpath(path, root)[:-3]
    dotted = rel.replace(os.sep, ".")
    if dotted.endswith(".__init__"):
        dotted = dotted[: -len(".__init__")]
    return dotted


def _is_package_module(path, root):
    """A .py file is an importable module only if every directory from its
    own up to (not including) gov/ contains __init__.py. Non-package .py
    files (e.g. gov/data/run_seccomp.py, vendored by path) are artifacts,
    not modules, and are outside this gate's candidacy."""
    d = os.path.dirname(os.path.abspath(path))
    gov_dir = os.path.abspath(os.path.join(root, "gov"))
    while True:
        if os.path.abspath(d) == gov_dir:
            return True
        if not os.path.isfile(os.path.join(d, "__init__.py")):
            return False
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def find_package_modules(root):
    """{dotted_name: abspath} for every importable gov module, excluding
    __init__ scaffolding (which is implicitly live with its package)."""
    gov_dir = os.path.join(root, "gov")
    mods = {}
    for dirpath, dirnames, filenames in os.walk(gov_dir):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            if fname == "__init__.py":
                continue
            path = os.path.join(dirpath, fname)
            if not _is_package_module(path, root):
                continue
            mods[_dotted_of(path, root)] = path
    return mods


def _resolve_relative(cur_dotted, level, module, package_names):
    parts = cur_dotted.split(".")
    base = parts if cur_dotted in package_names else parts[:-1]
    if level - 1 > len(base):
        return None
    base = base[: len(base) - (level - 1)]
    if module:
        base = base + [module]
    return ".".join(base)


def import_edges(path, root, mods, package_names):
    """Dotted names this file imports (absolute, resolved-relative, and
    importlib string-literal forms). Docstring/comment mentions are not
    edges -- only AST import statements reach."""
    cur = _dotted_of(path, root)
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError, UnicodeDecodeError):
        return set()
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                target = _resolve_relative(cur, node.level, node.module,
                                           package_names)
                if target:
                    out.add(target)
                    for alias in node.names:
                        cand = target + "." + alias.name
                        if alias.name != "*" and cand in mods:
                            out.add(cand)
                if node.module is None:
                    pkg = _resolve_relative(cur, node.level, None,
                                            package_names)
                    for alias in node.names:
                        if alias.name != "*":
                            out.add((pkg + "." + alias.name) if pkg
                                    else alias.name)
            elif node.module:
                # `from <pkg> import <name>`: the name may be a submodule.
                out.add(node.module)
                for alias in node.names:
                    cand = node.module + "." + alias.name
                    if alias.name != "*" and cand in mods:
                        out.add(cand)
        elif isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in ("import_module", "__import__") and node.args:
                first = node.args[0]
                if (isinstance(first, ast.Constant)
                        and isinstance(first.value, str)):
                    out.add(first.value)
    return out


def _matches(dotted, imported):
    if dotted.endswith(".__init__"):
        base = dotted[:-len(".__init__")]
    else:
        base = dotted
    return imported == base or imported.startswith(base + ".")


def compute_reached(root, mods):
    """Fixpoint: live roots (LIVE_ROOTS) are live; a gov module imported
    by a live file becomes live, and its own imports then count
    (Bernstein #5053: a module imported only by an unreached module stays
    unreached). Importing a package -- or any module under it -- executes
    the package's __init__ chain, so ancestor __init__.py files go live
    with the module and their imports fire."""
    gov_dir = os.path.join(root, "gov")
    package_names = set()
    init_paths = {}
    for dirpath, dirnames, filenames in os.walk(gov_dir):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        if "__init__.py" in filenames:
            dotted = _dotted_of(os.path.join(dirpath, "__init__.py"), root)
            package_names.add(dotted)
            init_paths[dotted] = os.path.join(dirpath, "__init__.py")

    files = []
    for live_root in LIVE_ROOTS:
        top = os.path.join(root, live_root)
        if not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fname in filenames:
                if fname.endswith(".py"):
                    files.append(os.path.join(dirpath, fname))
    gov_files = [path for path in mods.values()]
    gov_files.extend(init_paths.values())

    edges = {}
    for path in files:
        edges[path] = import_edges(path, root, mods, package_names)
    gov_edges = {}
    for path in gov_files:
        gov_edges[path] = import_edges(path, root, mods, package_names)

    def ancestors(dotted):
        parts = dotted.split(".")
        chain = []
        for i in range(1, len(parts)):
            pkg = ".".join(parts[:i])
            if pkg in init_paths:
                chain.append(init_paths[pkg])
        return chain

    live_files = set(files)
    reached = set()
    queue = list(files)
    while queue:
        path = queue.pop()
        edge_set = edges.get(path, gov_edges.get(path, ()))
        for imported in edge_set:
            # Package import: the package's __init__ executes.
            for pkg, init_path in init_paths.items():
                if imported == pkg or imported.startswith(pkg + "."):
                    if init_path not in live_files:
                        live_files.add(init_path)
                        queue.append(init_path)
            for dotted, mod_path in mods.items():
                if _matches(dotted, imported) and dotted not in reached:
                    reached.add(dotted)
                    for candidate in [mod_path] + ancestors(dotted):
                        if candidate not in live_files:
                            live_files.add(candidate)
                            queue.append(candidate)
    return reached


# --------------------------------------------------------------------------
# Entry points: documented __main__ invocations
# --------------------------------------------------------------------------

def _has_main_block(path):
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError, UnicodeDecodeError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and any(isinstance(c, ast.Constant)
                            and c.value == "__main__"
                            for c in ast.walk(test))):
                return True
    return False


def _documented_invocations(root):
    """{(kind, dotted): evidence} -- console-script targets from
    pyproject [project.scripts] and `python -m <dotted>` literals found
    in text files (docstrings, docs, demos)."""
    found = {}
    pyproject = os.path.join(root, PYPROJECT_RELPATH)
    try:
        text = open(pyproject, encoding="utf-8").read()
    except OSError:
        text = ""
    in_scripts = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_scripts = stripped == "[project.scripts]"
            continue
        if in_scripts and "=" in stripped:
            _, _, value = stripped.partition("=")
            value = value.strip().strip("\"'")
            target = value.split(":")[0].strip()
            if target.startswith("gov"):
                found[("console", target)] = PYPROJECT_RELPATH
    needle_dirs = ("gov", "tests", "evals", "demo", "docs", "tools",
                   "examples")
    for top_name in needle_dirs:
        top = os.path.join(root, top_name)
        if not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fname in filenames:
                if not fname.endswith((".py", ".md", ".toml", ".yaml",
                                       ".yml", ".txt", ".rst")):
                    continue
                path = os.path.join(dirpath, fname)
                try:
                    content = open(path, encoding="utf-8").read()
                except (OSError, UnicodeDecodeError):
                    continue
                for match in re.finditer(r"python -m ([a-zA-Z_][\w.]*)",
                                         content):
                    dotted = match.group(1)
                    if dotted.startswith("gov"):
                        key = ("module", dotted)
                        if key not in found:
                            found[key] = os.path.relpath(path, root)
    return found


def verify_entry_points(root, mods, reached):
    """{dotted: evidence} for unimported __main__ modules whose invocation
    is documented. Undocumented __main__ modules are returned as orphans."""
    documented = _documented_invocations(root)
    doc_dotteds = {dotted for (kind, dotted) in documented}
    entry_points = {}
    undocumented = []
    for dotted, path in mods.items():
        if dotted in reached:
            continue
        if not _has_main_block(path):
            continue
        if dotted in doc_dotteds:
            kinds = sorted(kind for (kind, name) in documented
                           if name == dotted)
            entry_points[dotted] = "; ".join(
                "%s (%s)" % (kind, documented[(kind, dotted)])
                for kind in kinds)
        else:
            undocumented.append(dotted)
    return entry_points, undocumented


# --------------------------------------------------------------------------
# Decision-code liveness
# --------------------------------------------------------------------------

def registered_codes(root):
    """AST-extract the TAXONOMY dict literal (no import side effects)."""
    path = os.path.join(root, DECISION_CODES_RELPATH)
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "TAXONOMY"):
            taxonomy = ast.literal_eval(node.value)
            return set(taxonomy.keys())
    raise ValueError("TAXONOMY dict literal not found in %s" % path)


def _non_docstring_literals(path):
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError, UnicodeDecodeError):
        return set(), {}
    doc_ids = set()
    registration_ids = set()

    def mark(body):
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            doc_ids.add(id(body[0].value))

    mark(tree.body)
    code_constants = {}
    taxonomy_ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            mark(node.body)
    # The TAXONOMY = {...} assignment subtree (keys, "code" values, human
    # prose that may name other codes) is registration, not raising. A
    # code that appears ONLY here is dead -- this is what keeps the
    # liveness check from going vacuously green on the registry file.
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "TAXONOMY"):
            for sub in ast.walk(node.value):
                if (isinstance(sub, ast.Constant)
                        and isinstance(sub.value, str)):
                    taxonomy_ids.add(id(sub))
    # Module-level NAME = "<code>" constants (registry idiom 2): a Name
    # load of the constant is a raise of the code.
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            code_constants[node.targets[0].id] = node.value.value
    literals = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in doc_ids
                and id(node) not in taxonomy_ids):
            literals.add(node.value)
    return literals, code_constants


def _constant_raise_names(path, code_constants):
    """Name ids loaded in this file that alias a registered code."""
    if not code_constants:
        return set()
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError, UnicodeDecodeError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                and node.id in code_constants):
            names.add(node.id)
    return names


# Production raiser locations beyond gov/: shipped operator code. tests/
# and evals/ never count -- a code raised only by a test is dead in
# production, and the gate must say so.
PRODUCTION_ROOTS = ("tools", "demo")


def code_raise_sites(root, mods, reached, codes):
    """{code: {locations}} -- codes appearing in a non-docstring string
    literal (or via a module-level NAME = "<code>" constant) of a reached
    gov module or a shipped production file under tools//demo/. The
    TAXONOMY registry subtree in decision_codes.py never counts:
    registration is not raising. A {"code": ...} journal/record dict
    elsewhere DOES count -- that is the code being emitted."""
    if not codes:
        return {}
    # Longest-first: a code that is a strict prefix of another code
    # (e.g. `bad-rules` vs `bad-ruleset`) must not shadow the longer one.
    pattern = re.compile("|".join(
        re.escape(code) for code in sorted(codes, key=len, reverse=True)))
    code_set = set(codes)
    sites = {}

    def scan_file(path, location):
        literals, constants = _non_docstring_literals(path)
        seen = set()
        for literal in literals:
            for match in pattern.finditer(literal):
                seen.add(match.group(0))
        for name in _constant_raise_names(path, constants):
            value = constants[name]
            if value in code_set:
                seen.add(value)
        for code in seen:
            sites.setdefault(code, set()).add(location)

    for dotted in reached:
        if not dotted.startswith("gov"):
            continue
        path = mods.get(dotted)
        if path:
            scan_file(path, dotted)
    for prod_root in PRODUCTION_ROOTS:
        top = os.path.join(root, prod_root)
        if not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fname in filenames:
                if fname.endswith(".py"):
                    path = os.path.join(dirpath, fname)
                    scan_file(path, os.path.relpath(path, root))
    # R32 (wave-340): the gate itself is shipped CI tooling. Codes the
    # gate emits as coded refusals (e.g. deadctrl-subject-mutated) are
    # live by emission here -- the gate file is scanned exactly like a
    # production file. (Tree-checked: this file carries no other
    # registered-code literals, so no existing code changes status.)
    gate_file = os.path.join(root, "evals", "no_dead_controls.py")
    if os.path.isfile(gate_file):
        scan_file(gate_file, os.path.join("evals", "no_dead_controls.py"))
    return sites


# --------------------------------------------------------------------------
# Allowlist
# --------------------------------------------------------------------------

def parse_allowlist(text):
    """Parse the allowlist markdown. Returns (active, removed, errors)
    where active is a list of dicts and removed a list of dicts."""
    active, removed, errors = [], [], []
    section = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("## "):
            title = line[3:].strip().lower()
            if title.startswith("active"):
                section = "active"
            elif title.startswith("removed"):
                section = "removed"
            else:
                section = None
            continue
        if not line.startswith("- "):
            continue
        if " | " not in line:
            # Prose bullet, not an entry (entries are `key: value | ...`).
            continue
        if section is None:
            errors.append("line %d: entry outside an Active/Removed section"
                          % lineno)
            continue
        fields = {}
        for part in line[2:].split(" | "):
            key, sep, value = part.partition(":")
            if not sep:
                errors.append("line %d: malformed field %r" % (lineno, part))
                continue
            fields[key.strip()] = value.strip()
        if section == "active":
            active.append(fields)
        else:
            removed.append(fields)
    return active, removed, errors


def _finding_exists(root, finding, findings_path=None):
    path = findings_path or os.path.join(root, FINDINGS_RELPATH)
    try:
        content = open(path, encoding="utf-8").read()
    except OSError:
        return False
    return re.search(r"\b%s\b" % re.escape(finding), content) is not None


def validate_allowlist(root, active, removed, orphans, dead_codes,
                       entry_points, findings_path=None):
    """Return a list of violation strings (empty = allowlist is sound)."""
    violations = []
    today = datetime.date.today().isoformat()
    seen = set()
    for entry in active:
        kind = entry.get("kind", "")
        name = entry.get("name", "")
        key = (kind, name)
        if key in seen:
            violations.append("duplicate active entry: %s %s" % (kind, name))
        seen.add(key)
        if kind not in ("module", "code"):
            violations.append("active entry %r: kind must be 'module' or "
                              "'code'" % (name or entry,))
            continue
        reason = entry.get("reason", "")
        if len(reason) < REASON_MIN_LEN:
            violations.append(
                "active entry %s %s: written reason required (>= %d chars)"
                % (kind, name, REASON_MIN_LEN))
        finding = entry.get("finding", "")
        expiry = entry.get("expiry", "")
        if bool(finding) == bool(expiry):
            violations.append(
                "active entry %s %s: exactly one of finding:/expiry: required "
                "(Bernstein #5505: an orphan needs an issue or an expiry)"
                % (kind, name))
        elif finding:
            if not re.fullmatch(r"F\d+", finding):
                violations.append("active entry %s %s: malformed finding %r"
                                  % (kind, name, finding))
            elif not _finding_exists(root, finding, findings_path):
                violations.append("active entry %s %s: finding %s not present "
                                  "in FINDINGS.md" % (kind, name, finding))
        else:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
                violations.append("active entry %s %s: malformed expiry %r "
                                  "(want YYYY-MM-DD)" % (kind, name, expiry))
            elif expiry <= today:
                violations.append("active entry %s %s: expiry %s has passed "
                                  "-- cover it, delete it, or re-file"
                                  % (kind, name, expiry))
        if kind == "module":
            if name not in orphans and name not in entry_points:
                # Either newly reachable/documented, or the module is gone.
                violations.append(
                    "active entry module %s: no longer an orphan -- remove "
                    "it with a recorded reason (allowlist can only shrink)"
                    % name)
        else:
            if name not in dead_codes:
                violations.append(
                    "active entry code %s: no longer dead -- remove it with "
                    "a recorded reason (allowlist can only shrink)" % name)
    for entry in removed:
        name = entry.get("name", "")
        if not name:
            violations.append("removed log entry without a name: %r" % entry)
        if not entry.get("removed_wave", ""):
            violations.append("removed log entry %s: removed_wave required"
                              % name)
        if not entry.get("removed_reason", ""):
            violations.append("removed log entry %s: removed_reason required "
                              "(removing entries is an error unless a reason "
                              "is recorded)" % name)
    return violations


# --------------------------------------------------------------------------
# Evaluation + CLI
# --------------------------------------------------------------------------

class GateResult(object):
    def __init__(self):
        self.passed = True
        self.module_count = 0
        self.reached_count = 0
        self.entry_points = {}
        self.orphans = []
        self.code_count = 0
        self.live_code_count = 0
        self.dead_codes = []
        self.violations = []
        self.allowlist_active = 0
        self.allowlist_removed = 0
        self.notes = []
        self.subject_digest = None  # R32: test-subject pin, set by evaluate()


def evaluate(root, findings_path=None, subject_pin_path=None):
    result = GateResult()
    # R32: pin the test subject BEFORE any analysis. The pin is the
    # content hash of every file; it is asserted invariant at the end
    # so a concurrent writer cannot swap the tree under the gate.
    pin_exclude = ()
    if subject_pin_path is not None:
        rel = os.path.relpath(os.path.abspath(subject_pin_path),
                              os.path.abspath(root))
        if not rel.startswith(".."):
            pin_exclude = (rel,)
    manifest, digest = _subject_pin.pin_tree(root, exclude=pin_exclude)
    result.subject_digest = digest
    result.notes.append("subject pinned: %s (%d files)" % (digest, len(manifest)))
    if subject_pin_path is not None:
        _subject_pin.write_manifest(subject_pin_path, manifest, digest)
    mods = find_package_modules(root)
    result.module_count = len(mods)
    reached = compute_reached(root, mods)
    result.reached_count = len(reached)
    entry_points, undocumented_mains = verify_entry_points(root, mods, reached)
    result.entry_points = entry_points
    orphans = sorted(set(mods) - set(reached) - set(entry_points))
    result.orphans = orphans
    result.notes.append("undocumented __main__ modules treated as orphans: %s"
                        % (sorted(undocumented_mains) or "none"))

    codes = registered_codes(root)
    result.code_count = len(codes)
    sites = code_raise_sites(root, mods, reached, codes)
    dead = sorted(codes - set(sites))
    result.dead_codes = dead
    result.live_code_count = len(codes) - len(dead)

    allowlist_path = os.path.join(root, ALLOWLIST_RELPATH)
    try:
        text = open(allowlist_path, encoding="utf-8").read()
    except OSError:
        text = ""
    active, removed, parse_errors = parse_allowlist(text)
    result.allowlist_active = len(active)
    result.allowlist_removed = len(removed)
    violations = list(parse_errors)
    violations.extend(validate_allowlist(root, active, removed, orphans,
                                         dead, entry_points, findings_path))

    excused_modules = {e.get("name") for e in active
                       if e.get("kind") == "module"}
    excused_codes = {e.get("name") for e in active
                     if e.get("kind") == "code"}
    for orphan in orphans:
        if orphan not in excused_modules:
            violations.append("orphan module with no allowlist entry: %s "
                              "(cover it, delete it, or allowlist with "
                              "reason + finding-or-expiry)" % orphan)
            result.passed = False
    for code in dead:
        if code not in excused_codes:
            violations.append("dead decision code with no allowlist entry: %s"
                              % code)
            result.passed = False
    if violations:
        result.passed = False
    result.violations = violations
    # R32: assert the subject pin is invariant across the run. Any drift
    # is a TOCTOU -- the gate analyzed a different tree than it pinned --
    # and fails the gate with the coded refusal.
    drift = _subject_pin.verify_tree(root, manifest, exclude=pin_exclude)
    if drift:
        result.passed = False
        shown = ", ".join("%s (%s)" % (rel, kind) for rel, kind in drift[:5])
        if len(drift) > 5:
            shown += ", ... +%d more" % (len(drift) - 5)
        result.violations.append(
            "deadctrl-subject-mutated: %d file(s) changed under the gate "
            "(TOCTOU): %s; subject was %s"
            % (len(drift), shown, digest))
    return result


def check_shrink_against_base(root, base_text):
    """Enforce shrink-only: entries active at --base but absent now must
    have a Removed log line with wave + reason."""
    base_active, _, base_errors = parse_allowlist(base_text)
    now_text = open(os.path.join(root, ALLOWLIST_RELPATH),
                    encoding="utf-8").read()
    now_active, now_removed, _ = parse_allowlist(now_text)
    base_keys = {(e.get("kind"), e.get("name")) for e in base_active}
    now_keys = {(e.get("kind"), e.get("name")) for e in now_active}
    removed_keys = {(e.get("kind"), e.get("name")) for e in now_removed}
    violations = list(base_errors)
    for key in sorted(base_keys - now_keys):
        if key not in removed_keys:
            violations.append(
                "allowlist entry %s %s removed without a recorded reason "
                "(allowlist can only shrink; log it under Removed)" % key)
    added = sorted(now_keys - base_keys)
    return violations, added


def report(result, out):
    out.write("dead-controls gate: %s\n"
              % ("PASS" if result.passed else "REFUSE"))
    out.write("modules: %d importable, %d reached, %d entry points, "
              "%d orphans\n"
              % (result.module_count, result.reached_count,
                 len(result.entry_points), len(result.orphans)))
    for dotted in sorted(result.entry_points):
        out.write("  entry point: %s [%s]\n"
                  % (dotted, result.entry_points[dotted]))
    for orphan in result.orphans:
        out.write("  orphan: %s\n" % orphan)
    out.write("decision codes: %d registered, %d live, %d dead\n"
              % (result.code_count, result.live_code_count,
                 len(result.dead_codes)))
    for code in result.dead_codes:
        out.write("  dead code: %s\n" % code)
    out.write("allowlist: %d active, %d removed\n"
              % (result.allowlist_active, result.allowlist_removed))
    for note in result.notes:
        out.write("note: %s\n" % note)
    for violation in result.violations:
        out.write("VIOLATION: %s\n" % violation)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = None
    base = None
    findings_path = None
    pin_subject_path = None
    args = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--root" and i + 1 < len(argv):
            root, i = argv[i + 1], i + 2
        elif arg == "--base-allowlist" and i + 1 < len(argv):
            base, i = argv[i + 1], i + 2
        elif arg == "--findings" and i + 1 < len(argv):
            findings_path, i = argv[i + 1], i + 2
        elif arg == "--pin-subject" and i + 1 < len(argv):
            pin_subject_path, i = argv[i + 1], i + 2
        elif arg in ("-h", "--help"):
            out = sys.stdout
            out.write(__doc__ + "\nusage: no_dead_controls.py [--root DIR] "
                      "[--base-allowlist FILE] [--findings PATH] "
                      "[--pin-subject FILE]\n")
            return 0
        else:
            args.append(arg)
            i += 1
    if args:
        sys.stderr.write("unknown arguments: %s\n" % " ".join(args))
        return 2
    if root is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(os.path.join(root, "gov")):
        sys.stderr.write("not a repo root (no gov/): %s\n" % root)
        return 2
    try:
        result = evaluate(root, findings_path=findings_path,
                          subject_pin_path=pin_subject_path)
    except Exception as exc:  # gate-internal error is never a pass
        sys.stderr.write("gate internal error: %r\n" % exc)
        return 2
    if base is not None:
        # The base allowlist arrives as a caller-supplied file: this gate
        # never shells out to git (wave-36 supply-chain rule -- no in-repo
        # git call sites; the caller fetches the base text with their own
        # tooling, e.g. the merge coordinator's git archive).
        try:
            with open(base, encoding="utf-8") as handle:
                base_text = handle.read()
        except OSError as exc:
            sys.stderr.write("cannot read --base-allowlist %s: %s\n"
                             % (base, exc))
            return 2
        shrink_violations, added = check_shrink_against_base(root, base_text)
        if shrink_violations:
            result.passed = False
            result.violations.extend(shrink_violations)
        if added:
            sys.stdout.write("allowlist entries added since %s (admitted "
                             "only via finding-or-expiry): %s\n"
                             % (base, sorted(added)))
    report(result, sys.stdout)
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
