"""Capability rule engine (mandiant/capa discipline, stdlib-only).

Design input: mandiant/capa (Apache-2.0 VERIFIED -- license text read
from the capa LICENSE.txt 2026-09-29; see
``teams/wave199-capa/SPIKE.md``). The steal is the *rule-language
shape* (``Rule(name, scopes, statement, meta)``), the **topological
namespace-matching discipline** (primitive rules feed composite rules
via ``match: <namespace>`` with no manual dependency ordering), and
the **meta annotation slot** (with OUR capability taxonomy, not
ATT&CK/MBC content -- the spike judged ATT&CK/MBC content label
theater). Re-implemented stdlib-only per the Sigma-lane precedent
(``gov/sigma_subset.py``): restricted YAML subset with loud refusal
of unsupported constructs. capa itself is NOT vendored or depended
on (heavy binary-analysis feature stack we do not need).

What this adds over the flat regex lint in
``gov/capability_manifests.py`` (the spike's honest delta):

1. **Conjunctions**: "network egress AND credential access" is a
   *composite rule* (data), not a new code path per conjunction.
2. **Composition**: bundle-scope rules reason over per-module matches
   (e.g. one module reads credentials, a DIFFERENT module reaches
   the network) -- no equivalent exists in the flat lint.
3. **Review-time escalation**: :func:`diff_namespaces` runs the rule
   set over two artifact versions and reports the namespace delta --
   separating "refuse the load" (digest-bound, load-time) from
   "review the re-attestation" (human trigger on broadening).
4. **Rules as signed data**: detections move from
   ``_CATEGORY_PATTERNS`` (Python, changed by code review) to a
   signed/versioned rule pack under :mod:`gov.pack_loader` (changed
   by rule-pack attestation) -- the Sigma-lane pattern applied to the
   load seam. The auditor can diff rule packs across deployments.

Honest residuals (not hidden):
  - Static analysis only: obfuscated capability use evades the rule
    engine exactly as it evades the flat lint. The digest binding +
    signature remain the hard guarantees (same residual as the
    module this complements).
  - ``match:`` on a namespace prefix (``capability/egress/*``) is
    OUR extension -- capa matches exact namespaces. Documented,
    loud, tested.

Rule document shape (adapted from capa's rule/meta/features; statement
nodes are maps, not dash-lists, so the existing restricted parser
``gov/sigma_subset.parse_yaml_subset`` accepts them)::

    rule:
      meta:
        name: network egress primitive        # unique, non-empty
        namespace: capability/egress          # unique-ish; match target
        scopes: {static: module}              # module | bundle
        capability_tags: [capability/egress/network]  # OUR taxonomy;
            # shape-enforced (list of strings); content not judged
        label: "import socket"                 # detection signal label;
            # defaults to name
        description: ...
      features:                               # ONE statement
        or:
          - import: socket
          - pattern: "\\burllib\\.request\\b"

Statement nodes (a dict with exactly one key):
  ``and``/``or``: list of statements (non-empty).
  ``not``: a single statement dict. **Top-level ``not`` is refused
      loud** -- capa's own matcher documents top-level NOT as a
      mishandled edge case; we refuse it instead of mis-evaluating it.
  ``some``: ``{n: <int>=1, of: [<statements>]}`` -- at least n match.
  ``count``: ``{feature: <leaf>, n: <int>=1}`` -- the leaf matches at
      least n times in the module.
  ``match``: ``<namespace>`` -- true when a rule with that exact
      namespace matched, or (trailing ``/*``) when any matched
      namespace has that prefix.
  ``subscope``: ``{scope: module, of: <statement>}`` -- bundle scope
      only; true when ANY module satisfies the sub-statement.

Leaf nodes (a dict with exactly one key):
  ``pattern``: regex searched over the module text.
  ``import``: module name (exact) or ``re:<regex>``; matched against
      the module's static import list.
  ``env-name``: regex matched against env-var names read by the
      module (the *name* is recorded by the standard extractor, not
      the leaf -- see detect_capabilities).
  ``tool-def``: regex matched against tool definitions.

Everything else -- unknown statement/leaf keys, unknown ``match:``
targets, dependency cycles, duplicate rule names, malformed meta --
is refused LOUD at compile time (:class:`RuleError`). A rule pack
that fails to compile never evaluates (fail-closed, never
fail-open).

$0 spend, synthetic/local deterministic only. No network.
"""

import re

from .sigma_subset import parse_yaml_subset, SigmaSubsetError
from . import capability_manifests as _cm

__all__ = [
    "RuleError",
    "CompiledRule",
    "CompiledPack",
    "compile_pack",
    "load_pack_files",
    "evaluate_module",
    "evaluate_bundle",
    "detect_capabilities",
    "diff_namespaces",
    "CAPABILITY_NAMESPACE_PREFIX",
]

#: Namespaces under this prefix feed the declared-vs-detected check.
CAPABILITY_NAMESPACE_PREFIX = "capability/"

#: Synthetic bundle namespace asserted when ONE module matched both a
#: secrets and an egress capability namespace (the "same-module" leg
#: of the mixed-trust composition rule).
SAME_MODULE_NAMESPACE = "capability/composition/same-module"

_STATEMENT_KEYS = frozenset(
    {"and", "or", "not", "some", "count", "match", "subscope"})
_LEAF_KEYS = frozenset({"pattern", "import", "env-name", "tool-def"})

_IMPORT_RES = [
    re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)", re.M),
    re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s", re.M),
]


class RuleError(Exception):
    """A rule pack or rule document is malformed. Fail-closed: the
    pack never evaluates."""


# ---------------------------------------------------------------------------
# Module feature extraction
# ---------------------------------------------------------------------------

def _extract_module_features(text):
    """Static per-module features: imports, env names, tool names.

    Env/tool NAME extraction reuses the exact regexes from
    ``gov/capability_manifests`` so rule-based detection reports
    byte-identical names to the flat lint (the migration battery
    proves it on a fixture corpus -- the battery, not a comment, is
    the sync enforcement).
    """
    imports = []
    seen = set()
    for rx in _IMPORT_RES:
        for m in rx.finditer(text):
            top = m.group(1).split(".")[0]
            if top not in seen:
                seen.add(top)
                imports.append(top)
    env_names = []
    seen_e = set()
    for rx in _cm._ENV_NAME_RES:
        for name in rx.findall(text):
            if name not in seen_e:
                seen_e.add(name)
                env_names.append(name)
    tool_names = []
    seen_t = set()
    for rx in _cm._TOOL_NAME_RES:
        for name in rx.findall(text):
            if name not in seen_t:
                seen_t.add(name)
                tool_names.append(name)
    return {"imports": imports, "env_names": env_names,
            "tool_names": tool_names}


# ---------------------------------------------------------------------------
# Statement compilation (loud refusal of everything unsupported)
# ---------------------------------------------------------------------------

def _expect_dict(node, what):
    if not isinstance(node, dict):
        raise RuleError("%s must be a mapping, got %r" % (what, node))
    return node


def _compile_leaf(node, where):
    _expect_dict(node, "leaf at %s" % where)
    if len(node) != 1:
        raise RuleError(
            "leaf at %s must have exactly one key, got %s"
            % (where, sorted(node)))
    key = next(iter(node))
    if key not in _LEAF_KEYS:
        raise RuleError(
            "unknown leaf %r at %s (allowed: %s)"
            % (key, where, sorted(_LEAF_KEYS)))
    value = node[key]
    if key == "pattern":
        if not isinstance(value, str) or not value:
            raise RuleError(
                "pattern leaf at %s must be a non-empty string" % where)
        try:
            rx = re.compile(value)
        except re.error as exc:
            raise RuleError(
                "pattern leaf at %s does not compile: %s" % (where, exc))
        return ("pattern", rx, value)
    if key == "import":
        if not isinstance(value, str) or not value:
            raise RuleError(
                "import leaf at %s must be a non-empty string" % where)
        if value.startswith("re:"):
            try:
                rx = re.compile(value[3:])
            except re.error as exc:
                raise RuleError(
                    "import leaf at %s regex does not compile: %s"
                    % (where, exc))
            return ("import-re", rx, value)
        return ("import", value, value)
    # env-name / tool-def: regex over the extracted name lists.
    if not isinstance(value, str) or not value:
        raise RuleError(
            "%s leaf at %s must be a non-empty string" % (key, where))
    try:
        rx = re.compile(value)
    except re.error as exc:
        raise RuleError(
            "%s leaf at %s does not compile: %s" % (key, where, exc))
    return (key, rx, value)


def _compile_statement(node, where, scope):
    """Compile one statement node. Returns an evaluatable tuple."""
    _expect_dict(node, "statement at %s" % where)
    if len(node) != 1:
        raise RuleError(
            "statement at %s must have exactly one key, got %s"
            % (where, sorted(node)))
    key = next(iter(node))
    if key not in _STATEMENT_KEYS:
        # Maybe it's a leaf in statement position?
        if key in _LEAF_KEYS:
            if scope == "bundle":
                raise RuleError(
                    "leaf %r at %s is not valid in a bundle-scope rule "
                    "(bundle rules match namespaces, not text; use "
                    "match: or subscope:)" % (key, where))
            return ("leaf", _compile_leaf(node, where))
        raise RuleError(
            "unknown statement %r at %s (allowed: %s)"
            % (key, where, sorted(_STATEMENT_KEYS)))
    value = node[key]
    if key in ("and", "or"):
        if not isinstance(value, list) or not value:
            raise RuleError(
                "%s at %s needs a non-empty list" % (key, where))
        return (key, [_compile_statement(s, "%s/%s[%d]" % (where, key, i),
                                         scope)
                      for i, s in enumerate(value)])
    if key == "not":
        sub = _compile_statement(value, "%s/not" % where, scope)
        return ("not", sub)
    if key == "some":
        _expect_dict(value, "some at %s" % where)
        n = value.get("n", 1)
        of = value.get("of")
        if (isinstance(n, bool) or not isinstance(n, int) or n < 1):
            raise RuleError("some.n at %s must be an integer >= 1" % where)
        if set(value) - {"n", "of"}:
            raise RuleError(
                "some at %s carries unknown keys: %s"
                % (where, sorted(set(value) - {"n", "of"})))
        if not isinstance(of, list) or not of:
            raise RuleError("some.of at %s needs a non-empty list" % where)
        return ("some", n,
                [_compile_statement(s, "%s/some[%d]" % (where, i), scope)
                 for i, s in enumerate(of)])
    if key == "count":
        if scope == "bundle":
            raise RuleError(
                "count at %s is not valid in a bundle-scope rule "
                "(it counts text hits, which bundles do not have)" % where)
        _expect_dict(value, "count at %s" % where)
        if set(value) - {"feature", "n"}:
            raise RuleError(
                "count at %s carries unknown keys: %s"
                % (where, sorted(set(value) - {"feature", "n"})))
        n = value.get("n", 1)
        if (isinstance(n, bool) or not isinstance(n, int) or n < 1):
            raise RuleError("count.n at %s must be an integer >= 1" % where)
        leaf = _compile_leaf(value.get("feature"), "%s/count" % where)
        return ("count", leaf, n)
    if key == "match":
        if not isinstance(value, str) or not value:
            raise RuleError(
                "match at %s must be a non-empty namespace string" % where)
        return ("match", value)
    # subscope
    _expect_dict(value, "subscope at %s" % where)
    if set(value) - {"scope", "of"}:
        raise RuleError(
            "subscope at %s carries unknown keys: %s"
            % (where, sorted(set(value) - {"scope", "of"})))
    if value.get("scope") != "module":
        raise RuleError(
            "subscope at %s: only scope 'module' is supported, got %r"
            % (where, value.get("scope")))
    if scope != "bundle":
        raise RuleError(
            "subscope at %s is only valid in bundle-scope rules" % where)
    sub = _compile_statement(value.get("of"), "%s/subscope" % where,
                             "module")
    return ("subscope", sub)


def _compile_rule(doc, where):
    """Compile one rule document. Returns a CompiledRule."""
    _expect_dict(doc, "rule document at %s" % where)
    if set(doc) != {"rule"}:
        raise RuleError(
            "rule document at %s must have exactly the 'rule' key, got %s"
            % (where, sorted(doc)))
    body = _expect_dict(doc["rule"], "rule at %s" % where)
    if set(body) != {"meta", "features"}:
        raise RuleError(
            "rule at %s must have exactly meta+features, got %s"
            % (where, sorted(body)))
    meta = _expect_dict(body["meta"], "meta at %s" % where)
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        raise RuleError("meta.name at %s must be a non-empty string" % where)
    namespace = meta.get("namespace")
    if not isinstance(namespace, str) or not namespace:
        raise RuleError(
            "meta.namespace at %s must be a non-empty string" % where)
    scopes = meta.get("scopes", {})
    _expect_dict(scopes, "meta.scopes at %s" % where)
    static_scope = scopes.get("static", "module")
    if static_scope not in ("module", "bundle"):
        raise RuleError(
            "meta.scopes.static at %s must be module|bundle, got %r"
            % (where, static_scope))
    if set(scopes) - {"static", "dynamic"}:
        raise RuleError(
            "meta.scopes at %s carries unknown keys: %s"
            % (where, sorted(set(scopes) - {"static", "dynamic"})))
    tags = meta.get("capability_tags", [])
    if not isinstance(tags, list) or not all(
            isinstance(t, str) and t for t in tags):
        raise RuleError(
            "meta.capability_tags at %s must be a list of non-empty "
            "strings" % where)
    label = meta.get("label", name)
    if not isinstance(label, str) or not label:
        raise RuleError(
            "meta.label at %s must be a non-empty string" % where)
    features = body["features"]
    stmt = _compile_statement(features, "%s/features" % where, static_scope)
    if stmt[0] == "not":
        # capa's documented edge case: top-level NOT is mishandled by
        # their matcher. We refuse it loud instead of mis-evaluating.
        raise RuleError(
            "rule %r: top-level 'not' is refused (negation must sit "
            "under and/or/some)" % name)
    return CompiledRule(name, namespace, static_scope, tags, label, stmt,
                        where)


class CompiledRule(object):
    """One compiled rule (value object; only from _compile_rule)."""

    __slots__ = ("name", "namespace", "scope", "capability_tags",
                 "label", "statement", "where")

    def __init__(self, name, namespace, scope, capability_tags, label,
                 statement, where):
        self.name = name
        self.namespace = namespace
        self.scope = scope
        self.capability_tags = list(capability_tags)
        self.label = label
        self.statement = statement
        self.where = where

    def match_refs(self):
        """Namespaces this rule's statement references via match:."""
        refs = set()

        def _walk(node):
            kind = node[0]
            if kind in ("and", "or"):
                for sub in node[1]:
                    _walk(sub)
            elif kind == "not":
                _walk(node[1])
            elif kind == "some":
                for sub in node[2]:
                    _walk(sub)
            elif kind == "subscope":
                _walk(node[1])
            elif kind == "match":
                refs.add(node[1])
            # leaves and count carry no refs

        _walk(self.statement)
        return refs


class CompiledPack(object):
    """A compiled rule pack: rules in dependency order."""

    __slots__ = ("rules", "namespaces")

    def __init__(self, rules):
        self.rules = list(rules)
        self.namespaces = set(r.namespace for r in rules)


def _is_prefix_ref(ref):
    return ref.endswith("/*")


def _match_target_known(ref, namespaces):
    if _is_prefix_ref(ref):
        return True  # any current-or-future namespace may match
    return ref in namespaces or ref == SAME_MODULE_NAMESPACE


def compile_pack(docs):
    """Compile rule documents into a CompiledPack.

    ``docs``: iterable of ``(where, parsed_yaml)`` -- parsed YAML
    must be a rule document (``{"rule": ...}``) or ``{"rules":
    [...]}``. Fail-closed: raises RuleError on any malformed rule,
    duplicate name, unknown match target, or dependency cycle.
    """
    rules = []
    seen_names = set()
    for where, doc in docs:
        _expect_dict(doc, "document at %s" % where)
        if "rules" in doc:
            items = doc["rules"]
            if not isinstance(items, list) or not items:
                raise RuleError(
                    "document at %s: 'rules' must be a non-empty list"
                    % where)
            for i, item in enumerate(items):
                rule = _compile_rule({"rule": item},
                                     "%s/rules[%d]" % (where, i))
                if rule.name in seen_names:
                    raise RuleError(
                        "duplicate rule name %r at %s"
                        % (rule.name, rule.where))
                seen_names.add(rule.name)
                rules.append(rule)
        elif "rule" in doc:
            rule = _compile_rule(doc, where)
            if rule.name in seen_names:
                raise RuleError(
                    "duplicate rule name %r at %s" % (rule.name, where))
            seen_names.add(rule.name)
            rules.append(rule)
        else:
            raise RuleError(
                "document at %s must have 'rule' or 'rules', got %s"
                % (where, sorted(doc)))
    if not rules:
        raise RuleError("rule pack is empty")
    namespaces = set(r.namespace for r in rules)
    # Unknown match targets fail LOUD (never a silent non-match).
    for rule in rules:
        for ref in rule.match_refs():
            if not _is_prefix_ref(ref) and ref != SAME_MODULE_NAMESPACE \
                    and ref not in namespaces:
                # SAME_MODULE_NAMESPACE is synthetic (bundle scope);
                # allowed only in bundle-scope rules.
                if ref == SAME_MODULE_NAMESPACE and rule.scope != "bundle":
                    raise RuleError(
                        "rule %r: synthetic namespace %r is only valid "
                        "in bundle-scope rules" % (rule.name, ref))
                if ref not in namespaces and ref != SAME_MODULE_NAMESPACE:
                    raise RuleError(
                        "rule %r matches unknown namespace %r"
                        % (rule.name, ref))
    # Topological order over the namespace dependency graph (capa's
    # core discipline): a rule evaluates after every namespace it
    # references. Prefix refs (capability/egress/*) expand to every
    # namespace under the prefix -- otherwise a composite rule could
    # evaluate before the primitives it matches on. Cycles are
    # refused loud (capa merely assumes a DAG).
    def _ref_targets(source_ns, ref):
        if _is_prefix_ref(ref):
            prefix = ref[:-2]
            # A rule's match: refers to namespaces of OTHER rules: the
            # referring rule's own namespace is excluded, so a rule
            # matching its own prefix (e.g. the credential-bearing
            # composite matching capability/egress/*) does not create
            # a vacuous self-dependency.
            return [ns for ns in ns_rules
                    if ns != source_ns
                    and (ns == prefix or ns.startswith(prefix + "/"))]
        if ref == SAME_MODULE_NAMESPACE:
            return []
        return [ref] if ref in ns_rules and ref != source_ns else []
    ns_rules = {}
    for rule in rules:
        ns_rules.setdefault(rule.namespace, []).append(rule)
    ordered = []
    visited = {}  # ns -> "temp" | "done"

    def _visit(ns, stack):
        state = visited.get(ns)
        if state == "done":
            return
        if state == "temp":
            raise RuleError(
                "dependency cycle in rule namespaces: %s"
                % (" -> ".join(stack + [ns]),))
        visited[ns] = "temp"
        for rule in ns_rules[ns]:
            for ref in rule.match_refs():
                for target in _ref_targets(ns, ref):
                    _visit(target, stack + [ns])
        visited[ns] = "done"
        ordered.extend(ns_rules[ns])

    for ns in sorted(ns_rules):
        _visit(ns, [])
    return CompiledPack(ordered)


def load_pack_files(files):
    """Parse + compile ``{member_id: bytes}`` rule files.

    YAML parse failures (SigmaSubsetError) become RuleError --
    one fail-closed exception type for the whole loader.
    """
    docs = []
    for member_id in sorted(files):
        raw = files[member_id]
        try:
            text = bytes(raw).decode("utf-8")
        except (UnicodeDecodeError, TypeError) as exc:
            raise RuleError(
                "member %r is not UTF-8 text: %s" % (member_id, exc))
        try:
            doc = parse_yaml_subset(text)
        except SigmaSubsetError as exc:
            raise RuleError(
                "member %r YAML refused: %s" % (member_id, exc))
        docs.append((member_id, doc))
    return compile_pack(docs)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class _ModuleCtx(object):
    __slots__ = ("text", "imports", "env_names", "tool_names")

    def __init__(self, text):
        self.text = text
        feats = _extract_module_features(text)
        self.imports = feats["imports"]
        self.env_names = feats["env_names"]
        self.tool_names = feats["tool_names"]


def _coerce_text(text):
    """Coerce module text to str (bytes decode as UTF-8, errors
    ignored); anything else becomes "" so hostile input detects
    nothing instead of breaking the caller."""
    if isinstance(text, (bytes, bytearray, memoryview)):
        try:
            return bytes(text).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return text if isinstance(text, str) else ""


def _eval_leaf(leaf, ctx):
    """Evaluate a leaf. Returns (matched, count, names)."""
    kind = leaf[0]
    if kind == "pattern":
        hits = list(leaf[1].finditer(ctx.text))
        return (bool(hits), len(hits), [])
    if kind == "import":
        ok = leaf[1] in ctx.imports
        return (ok, 1 if ok else 0, [])
    if kind == "import-re":
        n = sum(1 for imp in ctx.imports if leaf[1].search(imp))
        return (n > 0, n, [])
    names = ctx.env_names if kind == "env-name" else ctx.tool_names
    matched_names = [nm for nm in names if leaf[1].search(nm)]
    return (bool(matched_names), len(matched_names), matched_names)


def _eval_stmt(stmt, ctx, matched_namespaces):
    """Evaluate a statement. Returns (matched, labels, names)."""
    kind = stmt[0]
    if kind == "leaf":
        ok, _count, names = _eval_leaf(stmt[1], ctx)
        return (ok, [], names)
    if kind == "and" or kind == "or":
        labels, names = [], []
        results = [_eval_stmt(s, ctx, matched_namespaces)
                   for s in stmt[1]]
        ok = all(r[0] for r in results) if kind == "and" \
            else any(r[0] for r in results)
        for r in results:
            labels.extend(r[1])
            names.extend(r[2])
        return (ok, labels, names)
    if kind == "not":
        ok, _l, _n = _eval_stmt(stmt[1], ctx, matched_namespaces)
        return (not ok, [], [])
    if kind == "some":
        _k, n, subs = stmt
        results = [_eval_stmt(s, ctx, matched_namespaces) for s in subs]
        hits = sum(1 for r in results if r[0])
        labels, names = [], []
        for r in results:
            labels.extend(r[1])
            names.extend(r[2])
        return (hits >= n, labels, names)
    if kind == "count":
        _k, leaf, n = stmt
        ok, count, names = _eval_leaf(leaf, ctx)
        return (count >= n, [], names)
    if kind == "match":
        ref = stmt[1]
        if _is_prefix_ref(ref):
            prefix = ref[:-2]
            ok = any(ns == prefix or ns.startswith(prefix + "/")
                     for ns in matched_namespaces)
        else:
            ok = ref in matched_namespaces
        return (ok, [], [])
    if kind == "subscope":
        # Bundle scope only (refused at compile otherwise); the
        # caller supplies per-module evaluation.
        raise RuleError("subscope reached module evaluation (internal)")
    raise RuleError("unknown compiled statement %r (internal)" % (kind,))


def evaluate_module(pack, text):
    """Evaluate module-scoped rules over one module's text.

    Returns ``(matched_namespaces, evidence)`` where evidence is
    ``{rule_name: {"label": ..., "names": [...]}}`` for matched
    rules. Rules evaluate in topological order, so ``match:``
    references resolve against already-decided namespaces.
    ``text`` may be ``str`` or ``bytes`` (bytes decode as UTF-8
    with errors ignored, the same contract as
    :func:`detect_capabilities`).
    """
    if not isinstance(pack, CompiledPack):
        raise TypeError("pack must be a CompiledPack")
    ctx = _ModuleCtx(_coerce_text(text))
    matched = set()
    evidence = {}
    for rule in pack.rules:
        if rule.scope != "module":
            continue
        ok, _labels, names = _eval_stmt(rule.statement, ctx, matched)
        if ok:
            matched.add(rule.namespace)
            evidence[rule.name] = {"label": rule.label,
                                   "namespace": rule.namespace,
                                   "names": names}
    return matched, evidence


def evaluate_bundle(pack, modules):
    """Evaluate over a bundle: ``{module_id: text}``.

    Per-module matches are computed first; the bundle namespace set
    is the union, plus the synthetic
    ``capability/composition/same-module`` when ONE module matched
    both a secrets and an egress capability namespace. Bundle-scope
    rules then evaluate against the bundle set (``subscope`` nodes
    re-evaluate their sub-statement per module).

    Returns ``(bundle_namespaces, per_module)`` where per_module maps
    module_id -> (namespaces, evidence).
    """
    if not isinstance(pack, CompiledPack):
        raise TypeError("pack must be a CompiledPack")
    if not isinstance(modules, dict) or not modules:
        raise RuleError("modules must be a non-empty mapping")
    per_module = {}
    for mid, text in modules.items():
        per_module[mid] = evaluate_module(pack, text)
    bundle_ns = set()
    for _mid, (ns, _ev) in per_module.items():
        bundle_ns.update(ns)
    # Synthetic same-module composition signal.
    for _mid, (ns, _ev) in per_module.items():
        has_secrets = any(
            n == "capability/secrets" or n.startswith("capability/secrets/")
            for n in ns)
        has_egress = any(
            n == "capability/egress" or n.startswith("capability/egress/")
            for n in ns)
        if has_secrets and has_egress:
            bundle_ns.add(SAME_MODULE_NAMESPACE)
            break
    bundle_evidence = {}
    for rule in pack.rules:
        if rule.scope != "bundle":
            continue
        ok, _labels, names = _eval_bundle_stmt(
            rule.statement, modules, per_module, bundle_ns)
        if ok:
            bundle_ns.add(rule.namespace)
            bundle_evidence[rule.name] = {
                "label": rule.label, "namespace": rule.namespace,
                "names": names}
    return bundle_ns, {"per_module": per_module,
                       "bundle_evidence": bundle_evidence}


def _eval_bundle_stmt(stmt, modules, per_module, bundle_ns):
    """Evaluate a bundle-scope statement."""
    kind = stmt[0]
    if kind == "leaf":
        raise RuleError(
            "leaf nodes are not valid at bundle scope (use match: or "
            "subscope:)")
    if kind == "subscope":
        for mid, text in modules.items():
            ctx = _ModuleCtx(_coerce_text(text))
            mod_ns, _ev = per_module[mid]
            ok, _l, names = _eval_stmt(stmt[1], ctx, mod_ns)
            if ok:
                return (True, [], names)
        return (False, [], [])
    if kind == "match":
        ref = stmt[1]
        if _is_prefix_ref(ref):
            prefix = ref[:-2]
            ok = any(ns == prefix or ns.startswith(prefix + "/")
                     for ns in bundle_ns)
        else:
            ok = ref in bundle_ns
        return (ok, [], [])
    # Boolean combinators recurse at bundle level.
    if kind == "and" or kind == "or":
        results = [_eval_bundle_stmt(s, modules, per_module, bundle_ns)
                   for s in stmt[1]]
        ok = all(r[0] for r in results) if kind == "and" \
            else any(r[0] for r in results)
        names = []
        for r in results:
            names.extend(r[2])
        return (ok, [], names)
    if kind == "not":
        ok, _l, _n = _eval_bundle_stmt(stmt[1], modules, per_module,
                                       bundle_ns)
        return (not ok, [], [])
    if kind == "some":
        _k, n, subs = stmt
        results = [_eval_bundle_stmt(s, modules, per_module, bundle_ns)
                   for s in subs]
        hits = sum(1 for r in results if r[0])
        names = []
        for r in results:
            names.extend(r[2])
        return (hits >= n, [], names)
    if kind == "count":
        raise RuleError("count is not valid at bundle scope")
    raise RuleError("unknown compiled statement %r (internal)" % (kind,))


def _category_of(namespace):
    parts = namespace.split("/")
    if len(parts) >= 2 and parts[0] == "capability":
        return parts[1]
    return None


def detect_capabilities(content, pack, *, strict=False):
    """Rule-based capability detection.

    Returns ``{category: {"signals": [...], "names": [...]}}`` for
    every category in ``capability_manifests.CATEGORIES`` --
    **shape-identical** to the flat lint's
    :func:`capability_manifests.detect_capabilities`, so
    :func:`capability_manifests.check_capabilities` is reusable
    unchanged. ``signals`` are the matched rules' labels (deduped,
    order-preserved, capped at 8); ``names`` are the standard
    env/tool name extraction (deduped, capped at 16) -- the NAME
    vocabulary stays the flat extractor's, the *detection logic*
    moves into rules. Non-bytes content yields empty detections
    (same contract as the flat lint). Never raises on hostile
    input: unparseable content detects nothing.

    ``strict`` (wave-200 hardening): when True, an evaluator
    exception raises RuleError instead of returning empty
    detections. The default non-strict path exists for
    defense-in-depth scanning; the load-time seam
    (``verify_skill_manifest``) always uses strict=True, so an
    evaluator bug can never silently weaken the manifest check --
    it fails the load closed.
    """
    empty = {c: {"signals": [], "names": []} for c in _cm.CATEGORIES}
    if isinstance(content, (bytearray, memoryview)):
        content = bytes(content)
    if not isinstance(content, bytes):
        return empty
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return empty
    try:
        matched, evidence = evaluate_module(pack, text)
    except Exception as exc:
        # Detection never breaks the load on hostile input; the
        # pack compiled clean at load, so this is a hostile-content
        # path. (A pack that fails to COMPILE never reaches here --
        # compile is the loud boundary.) Under strict=True the
        # caller (verify_skill_manifest) wants the failure LOUD so
        # it can refuse the load rather than weaken detection.
        if strict:
            raise RuleError(
                "capability evaluation failed: %s: %s"
                % (type(exc).__name__, exc))
        return empty
    feats = _extract_module_features(text)
    detected = {c: {"signals": [], "names": []} for c in _cm.CATEGORIES}
    for rule in pack.rules:
        if rule.scope != "module" or rule.name not in evidence:
            continue
        cat = _category_of(rule.namespace)
        if cat not in detected:
            continue
        detected[cat]["signals"].append(rule.label)
    # Names: the standard extractor's vocabulary (env/tools), exactly
    # like the flat lint.
    detected["env"]["names"] = list(feats["env_names"][:16])
    detected["tools"]["names"] = list(feats["tool_names"][:16])
    for cat in detected:
        seen = set()
        detected[cat]["signals"] = [
            s for s in detected[cat]["signals"]
            if not (s in seen or seen.add(s))][:8]
    return detected


def diff_namespaces(old_text, new_text, pack):
    """Review-time capability escalation: matched namespace sets for
    two artifact versions.

    Returns ``{"added": [...], "removed": [...]}`` (sorted). A
    non-empty ``added`` does NOT refuse anything -- the manifest is
    digest-bound, so the new version already carries a fresh
    attestation; the delta is a **mandatory human-review trigger**:
    someone re-attested a broader capability, and the attestation
    itself is what gets reviewed (the spike's Rule 2, as data +
    code rather than a meta-rule).
    """
    old_ns, _ = evaluate_module(pack, old_text)
    new_ns, _ = evaluate_module(pack, new_text)
    return {"added": sorted(new_ns - old_ns),
            "removed": sorted(old_ns - new_ns)}
