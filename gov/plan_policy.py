"""Plan-level pre-execution policy check (Row 7 build step 4).

A composed plan is admitted to execution only after a small, explicit,
declarative policy check runs over the plan's declared units, their
capabilities, and their declared data flows. The policy language is
deliberately NOT general-purpose and NOT an LLM judge: a fixed rule
set, each rule with an id and a plain-language reason, evaluated
deterministically over a JSON-native manifest the plan carries.

Threat model (what this gate is and is not):

* IS: a fail-fast admission check at plan-construction/registration
  time. It refuses plans whose *declarations* violate policy: a plan
  that declares no egress capability but contains an egress-sink
  unit; a plan whose data-flow declarations do not cover an
  implied producer->consumer edge (slip leg i -> leg i+1 -- the slip
  demonstrably flows forward, see ``WorkflowComposer._execute_slip_unit``);
  a plan that mixes trust levels without declaring the mixing.
* IS NOT: a behavioral judge. The checker attributes capabilities from
  the plan's *declared* tool names against a fixed tool-class table;
  it cannot see inside the unit fns. A plan that declares an
  observation tool while its fn actually exfiltrates PASSES this
  check -- fn honesty is the composer's standing residual ("a lying
  fn falsifies its result"), and argument-level exfil detail belongs
  to the later provenance-graded sink policy (Row 7 step 5). The
  evasion probes pin this boundary explicitly.
* IS NOT wired to the trajectory accumulator (Row 7 step 2): that
  stays a characterization instrument by lane brief.

Digest binding: the manifest is normalized at ``ComposedPlan``
construction and its digest is bound into ``ComposedPlan.digest``
(only when a manifest is present -- manifest-less plans keep
byte-identical digests). The admission verdict is deterministic over
(plan digest, manifest digest, policy id), so binding those inputs
binds the verdict: a plan that passed the check cannot be mutated
into one that wouldn't without changing its digest, and the
composer's admission registry is keyed by the exact digest.
``ComposedPlan.verify_digest()`` recomputes the digest from the live
unit dicts, so in-place post-construction mutation is also caught
(fail closed) rather than silently executing under a stale digest.

New decision codes (6): ``plan-policy-manifest-missing``,
``plan-policy-unknown-tool``, ``plan-policy-capability``,
``plan-policy-data-flow``, ``plan-policy-trust-mixing``,
``plan-policy-not-admitted`` (registered at true sorted positions in
gov/decision_codes.py). Malformed manifests reuse the existing
``workflow-composed-definition-invalid`` (a broken declaration is a
broken definition, not a policy violation).

Stdlib only.
"""

import hashlib
import json

# ---------------------------------------------------------------------------
# Codes
# ---------------------------------------------------------------------------

PP_MANIFEST_MISSING = "plan-policy-manifest-missing"
PP_UNKNOWN_TOOL = "plan-policy-unknown-tool"
PP_CAPABILITY = "plan-policy-capability"
PP_DATA_FLOW = "plan-policy-data-flow"
PP_TRUST_MIXING = "plan-policy-trust-mixing"
PP_NOT_ADMITTED = "plan-policy-not-admitted"

#: Shared code string for malformed manifests. Referenced as a string
#: (not imported) so this module never imports gov.workflow_composed
#: -- the import direction is workflow_composed -> plan_policy only.
WC_DEFINITION_INVALID = "workflow-composed-definition-invalid"

POLICY_ID = "plan-policy-v1"

# ---------------------------------------------------------------------------
# Fixed vocabularies (deliberately small; the policy language is not
# general-purpose)
# ---------------------------------------------------------------------------

#: Capability vocabulary. A unit's inherent capabilities come from its
#: tool class; the plan envelope and the deployment policy speak the
#: same words.
CAPABILITY_EGRESS = "egress"
CAPABILITY_STATE_WRITE = "state-write"
CAPABILITY_OBSERVATION = "observation"
CAPABILITIES = frozenset(
    {CAPABILITY_EGRESS, CAPABILITY_STATE_WRITE, CAPABILITY_OBSERVATION})

#: Trust levels, strictly ordered. A data-flow classification names the
#: sensitivity of the data; a consumer's trust must dominate the
#: classification it consumes unless the crossing is explicitly
#: declared (declassify with a reason).
TRUST_LEVELS = {"public": 0, "internal": 1, "confidential": 2}

#: Tool-class table. ALIGNED with gov/trajectory_risk.py's
#: _EGRESS_SINKS / _STATE_MUTATIONS / _OBSERVATIONS (the same
#: operational tool names), but defined HERE so the admission gate
#: never depends on the characterization instrument. The two
#: vocabularies are intentionally separate; drift is caught by the
#: alignment unit test, not by a shared import.
_TOOL_EGRESS = frozenset({
    "send_email", "http_post", "http_request", "send_message",
    "upload_file", "scp", "ftp_put", "webhook_post", "publish",
})
_TOOL_STATE_WRITE = frozenset({
    "write_file", "delete_file", "append_file", "chmod", "shell_exec",
    "run_command", "mkdir", "move_file", "install_package", "pip_install",
})
_TOOL_OBSERVATION = frozenset({
    "read_file", "list_dir", "glob", "http_get", "search", "cat",
})

_TOOL_CLASS_CAPABILITIES = {
    "egress": (frozenset(_TOOL_EGRESS), frozenset({CAPABILITY_EGRESS})),
    "state-write": (frozenset(_TOOL_STATE_WRITE),
                    frozenset({CAPABILITY_STATE_WRITE})),
    "observation": (frozenset(_TOOL_OBSERVATION),
                    frozenset({CAPABILITY_OBSERVATION})),
}

_RULE_IDS = ("manifest", "unknown-tool", "capability", "data-flow",
             "trust-mixing")

#: The rule set: each rule has an id and a plain-language reason. The
#: language is deliberately small and declarative -- not
#: general-purpose, not an LLM judge.
RULES = (
    ("manifest",
     "the plan carries a manifest declaring every unit's tools, "
     "capabilities, trust level and data flows"),
    ("unknown-tool",
     "every declared tool is known to the fixed tool-class table, so "
     "capability can be attributed (unknown tools fail closed)"),
    ("capability",
     "no unit hides an inherent tool-class capability behind a weaker "
     "declaration; the plan envelope covers the units; the deployment "
     "policy allows the envelope"),
    ("data-flow",
     "declared flows are coherent (known, forward, non-duplicate, "
     "producer trust dominates classification) and every implied "
     "intra-unit edge (slip leg->leg) is declared exactly"),
    ("trust-mixing",
     "a flow carrying a classification above the consumer's trust is "
     "covered by an explicit declassify entry with a reason"),
)

__all__ = [
    "PlanPolicyError",
    "PlanPolicy",
    "PolicyVerdict",
    "normalize_manifest",
    "manifest_digest",
    "check_plan",
    "tool_class",
    "inherent_capabilities",
    "implied_internal_flows",
    "POLICY_ID",
    "RULES",
    "CAPABILITIES",
    "TRUST_LEVELS",
    "PP_MANIFEST_MISSING",
    "PP_UNKNOWN_TOOL",
    "PP_CAPABILITY",
    "PP_DATA_FLOW",
    "PP_TRUST_MIXING",
    "PP_NOT_ADMITTED",
    "WC_DEFINITION_INVALID",
]


class PlanPolicyError(Exception):
    """Coded refusal from the plan-policy gate."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise PlanPolicyError(detail, code=code)


def _canon(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest is not JSON-serializable")


def _hex(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Tool attribution
# ---------------------------------------------------------------------------

def tool_class(tool):
    """Return the tool class ('egress' | 'state-write' | 'observation')
    for a declared tool name, or None when the tool is unknown."""
    for cls, (names, _caps) in _TOOL_CLASS_CAPABILITIES.items():
        if tool in names:
            return cls
    return None


def inherent_capabilities(tool):
    """The capability set a tool name inherently requires. Unknown
    tools have no attributable capabilities -- callers must refuse
    them (fail closed), never guess."""
    for _cls, (names, caps) in _TOOL_CLASS_CAPABILITIES.items():
        if tool in names:
            return set(caps)
    return None


# ---------------------------------------------------------------------------
# Manifest normalization
# ---------------------------------------------------------------------------

_UNIT_KEYS = frozenset({"tool", "step_tools", "leg_tools", "capabilities",
                        "trust", "consumes", "internal_flows"})
_TOP_KEYS = frozenset({"policy", "capabilities", "declassify", "units"})
_FLOW_KEYS = frozenset({"from", "classification"})
_INTERNAL_FLOW_KEYS = frozenset({"from", "to", "classification"})
_DECLASSIFY_KEYS = frozenset({"from", "to", "reason"})


def _req_str(value, what):
    if not isinstance(value, str) or not value:
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: %s must be a non-empty string" % what)
    return value


def _req_cap_list(value, what):
    if not isinstance(value, (list, tuple)):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: %s must be a list" % what)
    out = []
    for c in value:
        _req_str(c, "%s capability" % what)
        if c not in CAPABILITIES:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: unknown capability %r in %s "
                  "(vocabulary: %s)" % (c, what, sorted(CAPABILITIES)))
        out.append(c)
    return sorted(set(out))


def _req_trust(value, what):
    _req_str(value, "%s trust" % what)
    if value not in TRUST_LEVELS:
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: unknown trust level %r in %s "
              "(vocabulary: %s)" % (value, what, sorted(TRUST_LEVELS)))
    return value


def _norm_consumes(value, what):
    if not isinstance(value, (list, tuple)):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: %s consumes must be a list" % what)
    out = []
    for e in value:
        if not isinstance(e, dict) or set(e) != _FLOW_KEYS:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: %s consumes entries must be "
                  "{\"from\", \"classification\"}" % what)
        out.append({"from": _req_str(e["from"], "%s consumes.from" % what),
                    "classification": _req_trust(
                        e["classification"],
                        "%s consumes classification" % what)})
    return sorted(out, key=lambda e: e["from"])


def _norm_internal_flows(value, what):
    if not isinstance(value, (list, tuple)):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: %s internal_flows must be a list" % what)
    out = []
    for e in value:
        if not isinstance(e, dict) or set(e) != _INTERNAL_FLOW_KEYS:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: %s internal_flows entries must be "
                  "{\"from\", \"to\", \"classification\"}" % what)
        out.append({"from": _req_str(e["from"], "%s flow.from" % what),
                    "to": _req_str(e["to"], "%s flow.to" % what),
                    "classification": _req_trust(
                        e["classification"],
                        "%s flow classification" % what)})
    return sorted(out, key=lambda e: (e["from"], e["to"]))


def _saga_step_ids(unit):
    """Step ids of a saga unit's definition (duck-typed: the manifest
    normalizer must not import gov.workflow_saga)."""
    d = unit.get("definition")
    steps = getattr(d, "steps", None)
    if steps is None:
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: cannot read saga steps for unit %r"
              % (unit.get("name"),))
    return sorted(str(s.step_id) for s in steps)


def _slip_leg_indices(unit):
    leg_fns = unit.get("leg_fns") or {}
    return sorted(str(k) for k in leg_fns)


def _leg_sort_key(k):
    """Order leg indices numerically when they are numeric (the true
    execution order -- ``_execute_slip_unit`` advances legs 0..n-1),
    lexicographically otherwise. ``str(k)`` and ``k`` sort identically
    under this key, so unit ``leg_fns`` keys and manifest
    ``leg_tools`` keys agree."""
    try:
        return (0, int(k))
    except (TypeError, ValueError):
        return (1, str(k))


def implied_internal_flows(unit):
    """The producer->consumer edges the plan *structure* implies inside
    one unit. For a slip unit: leg i -> leg i+1 -- the slip (with its
    receipts) demonstrably flows forward
    (``WorkflowComposer._execute_slip_unit`` rebinds ``slip`` to the
    advanced slip after every leg). Nodes are named ``"leg:<index>"``
    with the index in the unit's own key form. For fn units: none
    (inputs are static). For saga units: none -- verified against
    gov/workflow_saga.py: compensations are invoked with
    ``compensation_params`` only, never with the action's result, so
    no action->comp data edge exists to declare. Returns a set of
    (from_node, to_node).
    """
    kind = unit.get("kind")
    if kind != "slip":
        return set()
    idx = sorted((unit.get("leg_fns") or {}).keys(), key=_leg_sort_key)
    return {("leg:%s" % a, "leg:%s" % b)
            for a, b in zip(idx, idx[1:])}


def _norm_unit_entry(name, entry, unit):
    if not isinstance(entry, dict):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: unit %r entry must be a dict" % (name,))
    unknown = set(entry) - _UNIT_KEYS
    if unknown:
        _fail(WC_DEFINITION_INVALID,
              "plan manifest: unit %r has unknown keys %s (strict: "
              "unknown declaration keys are refused)" % (name, sorted(unknown)))
    kind = unit["kind"]
    norm = {"capabilities": _req_cap_list(entry.get("capabilities", []),
                                         "unit %r" % name),
            "trust": _req_trust(entry.get("trust"), "unit %r" % name),
            "consumes": _norm_consumes(entry.get("consumes", []),
                                      "unit %r" % name)}
    if kind == "fn":
        if "tool" not in entry:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: fn unit %r needs a tool" % (name,))
        norm["tool"] = _req_str(entry["tool"], "unit %r tool" % name)
        for bad in ("step_tools", "leg_tools", "internal_flows"):
            if bad in entry:
                _fail(WC_DEFINITION_INVALID,
                      "plan manifest: fn unit %r must not declare %s"
                      % (name, bad))
    elif kind == "saga":
        if "step_tools" not in entry:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: saga unit %r needs step_tools" % (name,))
        st = entry["step_tools"]
        if not isinstance(st, dict):
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: saga unit %r step_tools must be a dict"
                  % (name,))
        want = _saga_step_ids(unit)
        if sorted(str(k) for k in st) != want:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: saga unit %r step_tools must cover "
                  "exactly the definition steps %s" % (name, want))
        norm["step_tools"] = {str(k): _req_str(v, "unit %r step tool" % name)
                              for k, v in sorted(st.items(),
                                                key=lambda kv: str(kv[0]))}
        for bad in ("tool", "leg_tools", "internal_flows"):
            if bad in entry:
                _fail(WC_DEFINITION_INVALID,
                      "plan manifest: saga unit %r must not declare %s "
                      "(no action->comp data edge exists: compensations "
                      "receive compensation_params only)" % (name, bad))
    else:  # slip
        if "leg_tools" not in entry:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: slip unit %r needs leg_tools" % (name,))
        lt = entry["leg_tools"]
        if not isinstance(lt, dict):
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: slip unit %r leg_tools must be a dict"
                  % (name,))
        want = _slip_leg_indices(unit)
        if sorted(str(k) for k in lt) != want:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: slip unit %r leg_tools must cover "
                  "exactly the leg indices %s" % (name, want))
        norm["leg_tools"] = {str(k): _req_str(v, "unit %r leg tool" % name)
                             for k, v in sorted(lt.items(),
                                               key=lambda kv: str(kv[0]))}
        if "internal_flows" not in entry:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest: slip unit %r needs internal_flows "
                  "(the slip flows leg->leg; every implied edge must be "
                  "declared)" % (name,))
        norm["internal_flows"] = _norm_internal_flows(
            entry["internal_flows"], "unit %r" % name)
        for bad in ("tool", "step_tools"):
            if bad in entry:
                _fail(WC_DEFINITION_INVALID,
                      "plan manifest: slip unit %r must not declare %s"
                      % (name, bad))
    return norm


def normalize_manifest(manifest, units):
    """Validate and canonicalize a plan manifest against the plan's
    units. Returns the normalized JSON-native dict (the form whose
    digest is bound into the plan digest). Malformed manifests refuse
    ``workflow-composed-definition-invalid`` -- fail closed, never
    guess at a declaration's meaning.
    """
    if not isinstance(manifest, dict):
        _fail(WC_DEFINITION_INVALID, "plan manifest must be a dict")
    unknown = set(manifest) - _TOP_KEYS
    if unknown:
        _fail(WC_DEFINITION_INVALID,
              "plan manifest has unknown top-level keys %s (strict)"
              % sorted(unknown))
    units = list(units)
    names = [u["name"] for u in units]
    by_name = {u["name"]: u for u in units}
    m_units = manifest.get("units")
    if not isinstance(m_units, dict):
        _fail(WC_DEFINITION_INVALID, "plan manifest needs a units dict")
    if set(m_units) != set(names):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest units must cover exactly the plan units "
              "(missing %s, extra %s)"
              % (sorted(set(names) - set(m_units)),
                 sorted(set(m_units) - set(names))))
    declass = manifest.get("declassify", [])
    if not isinstance(declass, (list, tuple)):
        _fail(WC_DEFINITION_INVALID,
              "plan manifest declassify must be a list")
    norm_declass = []
    for e in declass:
        if not isinstance(e, dict) or set(e) != _DECLASSIFY_KEYS:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest declassify entries must be "
                  "{\"from\", \"to\", \"reason\"}")
        frm = _req_str(e["from"], "declassify.from")
        to = _req_str(e["to"], "declassify.to")
        reason = _req_str(e["reason"], "declassify.reason")
        if frm not in by_name or to not in by_name:
            _fail(WC_DEFINITION_INVALID,
                  "plan manifest declassify references unknown unit")
        norm_declass.append({"from": frm, "to": to, "reason": reason})
    norm_declass.sort(key=lambda e: (e["from"], e["to"]))
    return {
        "policy": _req_str(manifest.get("policy", POLICY_ID),
                           "manifest policy"),
        "capabilities": _req_cap_list(manifest.get("capabilities", []),
                                      "plan"),
        "declassify": norm_declass,
        "units": {n: _norm_unit_entry(n, m_units[n], by_name[n])
                  for n in sorted(names)},
    }


def manifest_digest(normalized_manifest):
    """Canonical digest of a normalized manifest (the value bound into
    the plan digest)."""
    return _hex(json.loads(_canon(normalized_manifest)))


# ---------------------------------------------------------------------------
# Deployment policy
# ---------------------------------------------------------------------------

class PlanPolicy:
    """Deployment-owned policy: which capabilities this deployment
    admits plans to use. The plan author declares; the deployer
    constrains. ``policy_id`` names the policy generation (bound into
    the verdict); ``allowed_capabilities`` is the deployment envelope.
    """

    def __init__(self, allowed_capabilities, policy_id=POLICY_ID):
        self.policy_id = _req_str(policy_id, "policy_id")
        if not isinstance(allowed_capabilities, (list, tuple, set,
                                                frozenset)):
            _fail(WC_DEFINITION_INVALID,
                  "PlanPolicy allowed_capabilities must be a collection")
        caps = set()
        for c in allowed_capabilities:
            if c not in CAPABILITIES:
                _fail(WC_DEFINITION_INVALID,
                      "PlanPolicy: unknown capability %r (vocabulary: %s)"
                      % (c, sorted(CAPABILITIES)))
            caps.add(c)
        self.allowed_capabilities = frozenset(caps)

    def __repr__(self):
        return "PlanPolicy(%r, %s)" % (self.policy_id,
                                       sorted(self.allowed_capabilities))


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class PolicyVerdict:
    """The deterministic outcome of ``check_plan``. ``verdict_digest``
    binds (policy id, plan digest, manifest digest, rule results) --
    recomputing the check over the same inputs yields the identical
    verdict, byte for byte."""

    __slots__ = ("policy_id", "plan_digest", "manifest_digest",
                 "rule_results", "verdict_digest")

    def __init__(self, policy_id, plan_digest, manifest_digest,
                 rule_results):
        self.policy_id = policy_id
        self.plan_digest = plan_digest
        self.manifest_digest = manifest_digest
        self.rule_results = tuple(rule_results)
        self.verdict_digest = _hex({
            "policy": policy_id,
            "plan": plan_digest,
            "manifest": manifest_digest,
            "rules": [list(r) for r in self.rule_results],
        })

    def to_dict(self):
        return {
            "policy_id": self.policy_id,
            "plan_digest": self.plan_digest,
            "manifest_digest": self.manifest_digest,
            "rule_results": [list(r) for r in self.rule_results],
            "verdict_digest": self.verdict_digest,
        }

    def __repr__(self):
        return "PolicyVerdict(%s, plan=%s.., rules=%d passed)" % (
            self.policy_id, self.plan_digest[:12], len(self.rule_results))


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------

def _unit_tools(manifest, name, kind):
    """Declared tool names for one unit (kind-aware)."""
    entry = manifest["units"][name]
    if kind == "fn":
        return [entry["tool"]]
    if kind == "saga":
        return [entry["step_tools"][s]
                for s in sorted(entry["step_tools"])]
    return [entry["leg_tools"][s] for s in sorted(entry["leg_tools"])]


def check_plan(plan, policy):
    """Run the plan-level pre-execution policy check. Returns a
    ``PolicyVerdict`` when every rule passes; raises coded
    ``PlanPolicyError`` on the first violation (fail fast, fail
    closed). Deterministic: no time, no randomness, no I/O.

    The plan is duck-typed (``units``, ``digest``, ``manifest``,
    ``verify_digest``) so this module never imports
    gov.workflow_composed.
    """
    verify = getattr(plan, "verify_digest", None)
    if not callable(verify):
        _fail(WC_DEFINITION_INVALID,
              "plan-policy: plan object has no verify_digest")
    verify()  # post-construction mutation -> stale digest -> refused
    manifest = getattr(plan, "manifest", None)
    if manifest is None:
        _fail(PP_MANIFEST_MISSING,
              "plan-policy: plan carries no manifest -- a plan submitted "
              "to the policy regime must declare its units' tools, "
              "capabilities, trust levels and data flows (fail closed)")
    if not isinstance(policy, PlanPolicy):
        _fail(WC_DEFINITION_INVALID,
              "plan-policy: policy must be a PlanPolicy")
    units = list(plan.units)
    order = {u["name"]: i for i, u in enumerate(units)}
    kinds = {u["name"]: u["kind"] for u in units}
    m_digest = manifest_digest(manifest)

    # Rule: unknown-tool. Every declared tool must be attributable to
    # the fixed tool-class table. Unknown tools refuse -- the checker
    # cannot attribute capability to a tool it does not know (fail
    # closed, never guess).
    for name in sorted(order):
        for t in _unit_tools(manifest, name, kinds[name]):
            if tool_class(t) is None:
                _fail(PP_UNKNOWN_TOOL,
                      "plan-policy: unit %r declares unknown tool %r -- "
                      "capability cannot be attributed (fail closed; "
                      "extend the tool-class table explicitly)" % (name, t))

    # Rule: capability. (a) a unit's declared capabilities must cover
    # the inherent capabilities of its tools -- declaring a weaker set
    # to hide an egress sink refuses; (b) the union of unit-declared
    # capabilities must fit the plan's declared envelope; (c) the plan
    # envelope must fit the deployment policy's allowed capabilities.
    for name in sorted(order):
        inherent = set()
        for t in _unit_tools(manifest, name, kinds[name]):
            inherent |= inherent_capabilities(t)
        declared = set(manifest["units"][name]["capabilities"])
        hidden = inherent - declared
        if hidden:
            _fail(PP_CAPABILITY,
                  "plan-policy: unit %r hides inherent capabilities %s "
                  "behind declared %s (tool-class attribution is not "
                  "overridable)" % (name, sorted(hidden),
                                     sorted(declared)))
    union_declared = set()
    for name in order:
        union_declared |= set(manifest["units"][name]["capabilities"])
    envelope = set(manifest["capabilities"])
    over = union_declared - envelope
    if over:
        _fail(PP_CAPABILITY,
              "plan-policy: plan envelope %s does not cover unit "
              "capabilities %s -- a plan that declares no egress "
              "capability but contains an egress-sink unit refuses here"
              % (sorted(envelope), sorted(over)))
    disallowed = envelope - set(policy.allowed_capabilities)
    if disallowed:
        _fail(PP_CAPABILITY,
              "plan-policy: plan envelope claims capabilities %s not "
              "allowed by deployment policy %r (allows %s)"
              % (sorted(disallowed), policy.policy_id,
                 sorted(policy.allowed_capabilities)))

    # Rule: data-flow. Declared inter-unit edges must be coherent:
    # producer exists, is strictly earlier in plan order (no
    # self/backward edges), no duplicates, and the producer's trust
    # must dominate the classification (a unit cannot emit data more
    # sensitive than its own trust). Implied intra-unit edges (slip
    # leg->leg) must be declared exactly -- coverage and no phantoms.
    seen_edges = set()
    declared_edges = []  # (from, to, classification) incl. internal
    for name in sorted(order):
        for e in manifest["units"][name]["consumes"]:
            frm, cls = e["from"], e["classification"]
            if frm not in order:
                _fail(PP_DATA_FLOW,
                      "plan-policy: unit %r consumes from unknown unit %r"
                      % (name, frm))
            if frm == name or order[frm] >= order[name]:
                _fail(PP_DATA_FLOW,
                      "plan-policy: unit %r declares a non-forward data "
                      "flow from %r (flows must go strictly forward in "
                      "plan order)" % (name, frm))
            if (frm, name) in seen_edges:
                _fail(PP_DATA_FLOW,
                      "plan-policy: duplicate declared flow %r -> %r"
                      % (frm, name))
            seen_edges.add((frm, name))
            if TRUST_LEVELS[manifest["units"][frm]["trust"]] < \
                    TRUST_LEVELS[cls]:
                _fail(PP_DATA_FLOW,
                      "plan-policy: unit %r declares consuming %r data "
                      "from %r, but %r's trust (%s) is below the "
                      "classification -- incoherent declaration"
                      % (name, cls, frm, frm,
                         manifest["units"][frm]["trust"]))
            declared_edges.append((frm, name, cls))
    for name in sorted(order):
        if kinds[name] != "slip":
            continue
        # Implied edges from the unit's own leg keys (leg_tools covers
        # exactly the legs -- enforced at normalization -- and the
        # _leg_sort_key orders both key forms identically).
        leg_keys = sorted(manifest["units"][name]["leg_tools"],
                          key=_leg_sort_key)
        implied = {("leg:%s" % a, "leg:%s" % b)
                   for a, b in zip(leg_keys, leg_keys[1:])}
        declared = {(e["from"], e["to"]) for e in
                    manifest["units"][name]["internal_flows"]}
        if declared != implied:
            _fail(PP_DATA_FLOW,
                  "plan-policy: slip unit %r internal_flows %s do not "
                  "cover exactly the implied leg->leg edges %s (the "
                  "slip flows forward leg by leg; every implied edge "
                  "must be declared, no phantoms)"
                  % (name, sorted(declared), sorted(implied)))
        for e in manifest["units"][name]["internal_flows"]:
            if TRUST_LEVELS[manifest["units"][name]["trust"]] < \
                    TRUST_LEVELS[e["classification"]]:
                _fail(PP_DATA_FLOW,
                      "plan-policy: slip unit %r internal flow %s->%s "
                      "classification %r exceeds the unit's trust"
                      % (name, e["from"], e["to"], e["classification"]))
            declared_edges.append((name, name, e["classification"]))

    # Rule: trust-mixing. A flow whose classification exceeds the
    # consumer's trust is a trust-boundary crossing: it must be
    # covered by an explicit declassify entry with a non-empty reason,
    # else it refuses. (Internal slip-leg flows never trigger: the
    # consumer is the unit itself and R-data-flow already bounds the
    # classification by the unit's trust.)
    declass = {(d["from"], d["to"]) for d in manifest["declassify"]}
    for frm, to, cls in declared_edges:
        if TRUST_LEVELS[manifest["units"][to]["trust"]] < \
                TRUST_LEVELS[cls]:
            if (frm, to) not in declass:
                _fail(PP_TRUST_MIXING,
                      "plan-policy: flow %r -> %r carries %r data into a "
                      "%r-trust consumer without a declared declassify "
                      "entry (trust mixing must be declared with a "
                      "reason)" % (frm, to, cls,
                                   manifest["units"][to]["trust"]))

    return PolicyVerdict(policy.policy_id, plan.digest, m_digest,
                         [(r[0], "pass") for r in RULES])
