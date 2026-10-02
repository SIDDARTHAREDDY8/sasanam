"""Caldera-pattern campaign layer: fact-gated chaining over atomic tests.

Mechanism provenance: apache/caldera (Apache-2.0 -- model/contract
only, no Caldera code vendored; mitre/caldera is the legacy redirect).
Caldera's campaign model, re-skinned from endpoint C2 emulation to
API-layer agent-governance probes:

- abilities declare ``requirements``: required relationships of facts
  that must hold before the ability runs. Here atomic specs declare
  ``requires`` (validated in gov.battery_lang.validate_atomic_spec;
  composition, not duplication) and this module interprets them
  against a typed FactStore to gate eligibility;
- facts are typed trait->value state (Caldera's ``trait: value``,
  e.g. ``host.user.name``), seeded up front from fact sources
  ("pre-knowledge") and harvested after each run by ``produces``
  declarations and optional ``fact_parser`` callables (Caldera parsers);
- planners are a swappable seam choosing the next eligible atomic:
  greedy-break-chaser, coverage-maximizer, minimize-to-first-break;
- objectives define completion as goals over facts
  (``{count, operator, target, value}``), evaluated between planner
  buckets; the campaign auto-closes on objectives-met, planner stop
  (e.g. minimize-to-first-break's first BREAK), exhaustion, step
  budget, or denied manual approval (the analog of Caldera's
  manual-approve-per-command, composing with our human-approval
  queue for high-blast-radius probes);
- CampaignWriter: hash-chained JSONL evidence (genesis-chained,
  standalone verifier, tamper-evident); replay_campaign re-runs
  deterministically and diffs (the attack-ledger replay precedent:
  timestamps recorded but never part of digests).

Determinism: no randomness anywhere. Replay is byte-identical given
deterministic atomic executors (same contract as the ledger's
replay_campaign).

$0: stdlib-only, no LLM judges, no network.
"""

import hashlib
import json
import os

from gov import attack_ledger as al
from gov import battery_lang as bl

_GENESIS = "0" * 64
_SCHEMA_VERSION = 1

_BREAKS_TARGET = "campaign.breaks"

# Contract coupling: the trait shape, fact types, requirement ops, and
# produces "on" vocabulary are VALIDATED in gov.battery_lang and
# INTERPRETED here. Single source is bl.* -- re-declaring them here
# would let the two drift (a requirement that validates but can never
# hold, or vice versa).
_OBJECTIVE_OPS = ("eq", "ne", "gt", "gte", "lt", "lte")
_CLOSE_REASONS = ("objectives-met", "no-eligible-atomics",
                  "step-budget-exhausted", "approval-denied",
                  "planner-stopped")


class CampaignError(ValueError):
    """A campaign plan failed validation (bad objective, unknown
    planner, unresolvable atomic, mistyped seed fact). Fail-closed,
    ValueError family like the attack ledger's errors -- no new
    decision codes."""


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Typed fact store (Caldera's trait->value facts, typed).
# ---------------------------------------------------------------------------

class FactStore(object):
    """Typed trait->value state.

    Traits are dotted lowercase (2+ segments, e.g.
    ``tool.file_write.available``). Types are str/bool/int/float/enum
    with strict checking (bool is not int -- the battery_lang
    strictness). Every write records its source: "seed" (fact source
    pre-knowledge), "produced" (atomic produces declaration), or
    "parser" (fact_parser harvest).
    """

    def __init__(self):
        self._facts = {}

    def set_fact(self, trait, value, ftype, source="seed", choices=None):
        if not isinstance(trait, str) or not bl._FACT_TRAIT_RE.match(trait):
            raise CampaignError(
                "trait %r must be dotted lowercase (2+ segments)" % (trait,))
        if ftype not in bl._FACT_TYPES:
            raise CampaignError("fact type %r not in %s"
                                % (ftype, "/".join(bl._FACT_TYPES)))
        if ftype == "enum":
            if (not isinstance(choices, list) or not choices
                    or any(not isinstance(c, str) for c in choices)):
                raise CampaignError(
                    "enum fact %r needs a non-empty choices list of str"
                    % (trait,))
        elif choices is not None:
            raise CampaignError("choices only valid for enum facts")
        # Strict typed check (bool is not int) -- mirrors the atomic
        # arg checker exactly.
        if not self._value_ok(ftype, choices, value):
            raise CampaignError(
                "fact %r value %r does not satisfy type %r"
                % (trait, value, ftype))
        if source not in ("seed", "produced", "parser"):
            raise CampaignError("unknown fact source %r" % (source,))
        prior = self._facts.get(trait)
        if prior is not None:
            if prior["type"] != ftype:
                # A trait's type is stable for the campaign's life: an
                # overwrite with a different type is a type confusion,
                # not a value update.
                raise CampaignError(
                    "fact %r already typed %r; refusing re-type as %r"
                    % (trait, prior["type"], ftype))
            if (ftype == "enum"
                    and list(prior.get("choices") or [])
                    != list(choices)):
                raise CampaignError(
                    "fact %r enum domain changed: %r -> %r"
                    % (trait, prior.get("choices"), choices))
        entry = {"value": value, "type": ftype, "source": source}
        if ftype == "enum":
            entry["choices"] = list(choices)
        self._facts[trait] = entry

    @staticmethod
    def _value_ok(ftype, choices, value):
        if ftype == "str":
            return isinstance(value, str)
        if ftype == "bool":
            return isinstance(value, bool)
        if ftype == "int":
            return isinstance(value, int) and not isinstance(value, bool)
        if ftype == "float":
            return ((isinstance(value, float)
                     or (isinstance(value, int)
                         and not isinstance(value, bool))))
        if ftype == "enum":
            return isinstance(value, str) and value in (choices or [])
        return False

    def lookup(self, trait):
        """The stored entry dict or None."""
        return self._facts.get(trait)

    def get(self, trait, default=None):
        entry = self._facts.get(trait)
        return entry["value"] if entry is not None else default

    def has(self, trait):
        return trait in self._facts

    def snapshot(self):
        """{trait: value} in insertion order."""
        return {t: e["value"] for t, e in self._facts.items()}

    @property
    def facts(self):
        return self.snapshot()


def seed_fact_store(store, seed_facts):
    """Seed a FactStore from a fact source (Caldera "pre-knowledge").

    ``seed_facts``: {trait: {"value":..., "type":..., "choices"?}} or
    {trait: (value, type)} or {trait: (value, type, choices)}.
    Fail-closed CampaignError on any bad shape. Returns the normalized
    {trait: {"value","type",...}} mapping (for evidence).
    """
    if not isinstance(seed_facts, dict):
        raise CampaignError("seed_facts must be a dict")
    normalized = {}
    for trait, decl in seed_facts.items():
        choices = None
        if isinstance(decl, dict):
            value, ftype = decl.get("value"), decl.get("type")
            choices = decl.get("choices")
        elif isinstance(decl, (list, tuple)) and len(decl) in (2, 3):
            value, ftype = decl[0], decl[1]
            choices = decl[2] if len(decl) == 3 else None
        else:
            raise CampaignError(
                "seed fact %r must be {value,type[,choices]} or "
                "(value, type[, choices])" % (trait,))
        store.set_fact(trait, value, ftype, source="seed",
                       choices=choices)
        norm = {"value": value, "type": ftype}
        if ftype == "enum":
            norm["choices"] = list(choices)
        normalized[trait] = norm
    return normalized


# ---------------------------------------------------------------------------
# Requirement evaluation (Caldera requirements: gate eligibility).
# ---------------------------------------------------------------------------

def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _strict_eq(a, b):
    return type(a) is type(b) and a == b


def _requirement_holds(req, store):
    """All ops on a missing fact are False (fail-closed chaining)."""
    entry = store.lookup(req["fact"])
    op = req["op"]
    if entry is None:
        return False
    if op == "exists":
        return True
    value = entry["value"]
    want = req["value"]
    if op == "eq":
        return _strict_eq(value, want)
    if op == "ne":
        return not _strict_eq(value, want)
    if op in ("gt", "gte", "lt", "lte"):
        if not _is_num(value) or not _is_num(want):
            return False
        if op == "gt":
            return value > want
        if op == "gte":
            return value >= want
        if op == "lt":
            return value < want
        return value <= want
    if op == "in":
        return any(_strict_eq(value, v) for v in want)
    return False  # unreachable: op validated at spec time


# ---------------------------------------------------------------------------
# Objectives (Caldera {count, operator, target, value}).
# ---------------------------------------------------------------------------

def validate_objective(obj):
    """Validate one fact-goal objective, fail-closed. Returns the
    normalized goal."""
    if not isinstance(obj, dict):
        raise CampaignError("objective must be a dict")
    count = obj.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise CampaignError("objective count must be a positive int")
    operator = obj.get("operator")
    if operator not in _OBJECTIVE_OPS:
        raise CampaignError("objective operator %r not in %s"
                            % (operator, "/".join(_OBJECTIVE_OPS)))
    target = obj.get("target")
    if target != _BREAKS_TARGET and (
            not isinstance(target, str)
            or not bl._FACT_TRAIT_RE.match(target)):
        raise CampaignError(
            "objective target must be %r or a fact trait" % _BREAKS_TARGET)
    if "value" not in obj:
        raise CampaignError("objective needs a value")
    value = obj["value"]
    if value is None or isinstance(value, (dict, list)):
        raise CampaignError("objective value must be a JSON scalar")
    if target == _BREAKS_TARGET and not _is_num(value):
        raise CampaignError("campaign.breaks objective needs a numeric value")
    return {"count": count, "operator": operator, "target": target,
            "value": value}


def _goal_satisfied(goal, store, breaks):
    if goal["target"] == _BREAKS_TARGET:
        current = breaks
    else:
        entry = store.lookup(goal["target"])
        if entry is None:
            return False
        current = entry["value"]
    op, want = goal["operator"], goal["value"]
    if op == "eq":
        return _strict_eq(current, want)
    if op == "ne":
        return not _strict_eq(current, want)
    if not _is_num(current) or not _is_num(want):
        return False
    if op == "gt":
        return current > want
    if op == "gte":
        return current >= want
    if op == "lt":
        return current < want
    return current <= want


# ---------------------------------------------------------------------------
# Planners: the swappable next-ability seam.
# ---------------------------------------------------------------------------

class _BasePlanner(object):
    planner_id = "base"
    # Intrinsic stop: when True, the runner closes the campaign with
    # "planner-stopped" right after the first BREAK step (checked
    # after the goal check, so an objective met on the same step
    # wins).
    stop_on_first_break = False

    def pick(self, candidates, facts, memory, run_names):
        """Return one candidate dict or None. Candidates are
        {"name","guid","spec"} dicts, all eligible and unrun.
        Deterministic: no randomness, ties broken by name."""
        raise NotImplementedError


class MinimizeToFirstBreak(_BasePlanner):
    """Deterministic name order; the runner closes with
    "planner-stopped" at the first BREAK (intrinsic to the planner --
    no campaign.breaks objective required)."""
    planner_id = "minimize-to-first-break"
    stop_on_first_break = True

    def pick(self, candidates, facts, memory, run_names):
        return sorted(candidates, key=lambda c: c["name"])[0]


class CoverageMaximizer(_BasePlanner):
    """Greedy set-cover over fact dependencies: prefer the candidate
    whose produced facts satisfy the most currently-unsatisfied
    requirements of other unrun candidates. Ties broken by name."""
    planner_id = "coverage-maximizer"

    def pick(self, candidates, facts, memory, run_names):
        others_reqs = []
        for c in candidates:
            for req in c["spec"].get("requires", []):
                others_reqs.append(req["fact"])

        def score(c):
            produced = {p["fact"] for p in c["spec"].get("produces", [])}
            unsatisfied = {f for f in others_reqs
                           if f in produced and f not in facts}
            return len(unsatisfied)

        return sorted(candidates,
                      key=lambda c: (-score(c), c["name"]))[0]


class GreedyBreakChaser(_BasePlanner):
    """Order by historical break rate from the caller's break memory
    {guid: {"breaks": n, "runs": n}} (the attack ledger's regression
    seeds are the natural source). Unknown atomics rate 0.0. Ties
    broken by name."""
    planner_id = "greedy-break-chaser"

    def pick(self, candidates, facts, memory, run_names):
        def rate(c):
            m = memory.get(c["guid"]) or {}
            runs = m.get("runs", 0)
            if not runs:
                return 0.0
            return m.get("breaks", 0) / runs

        return sorted(candidates,
                      key=lambda c: (-rate(c), c["name"]))[0]


PLANNERS = {
    "minimize-to-first-break": MinimizeToFirstBreak(),
    "coverage-maximizer": CoverageMaximizer(),
    "greedy-break-chaser": GreedyBreakChaser(),
}


# ---------------------------------------------------------------------------
# Evidence: hash-chained JSONL (genesis-chained, standalone verifier).
# ---------------------------------------------------------------------------

_RECORD_TYPES = ("campaign-start", "campaign-step", "campaign-close")


def _record_digest(prev, record):
    # Timestamps are recorded but never part of digests (the ledger
    # precedent: replay compares behavior, not wall-clock).
    body = {k: v for k, v in record.items()
            if k not in ("record_digest", "prev_digest",
                         "started_at", "closed_at")}
    return _digest(prev + "|" + al._canonical(body))


class CampaignWriter(object):
    """Chains campaign records into a JSONL evidence file at run time."""

    def __init__(self, path):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._fh = open(path, "w", encoding="utf-8")
        self._prev = _GENESIS

    def _write(self, record):
        record = dict(record)
        record["prev_digest"] = self._prev
        record["record_digest"] = _record_digest(self._prev, record)
        self._fh.write(al._canonical(record) + "\n")
        self._fh.flush()
        self._prev = record["record_digest"]
        return record["record_digest"]

    def write_start(self, record):
        return self._write(record)

    def write_step(self, record):
        return self._write(record)

    def write_close(self, record):
        return self._write(record)

    def close(self):
        self._fh.close()


def read_campaign_records(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]


def verify_campaign_records(records):
    """Standalone verifier: exact bool, never raises. True iff every
    record's digest verifies and the per-writer chain is continuous."""
    try:
        prev = _GENESIS
        for r in records:
            if not isinstance(r, dict):
                return False
            if r.get("record_type") not in _RECORD_TYPES:
                return False
            if r.get("prev_digest") != prev:
                return False
            if r.get("record_digest") != _record_digest(prev, r):
                return False
            prev = r["record_digest"]
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Campaign runner.
# ---------------------------------------------------------------------------

def register_campaign_atomics(registry, specs):
    """Register atomic specs for a campaign (the battery_lang CI gate
    runs here too). Returns {name: guid}."""
    out = {}
    for spec in specs:
        guid = bl.register_atomic(registry, spec)
        out[spec["name"]] = guid
    return out


class CampaignRunner(object):
    """Fact-gated, planner-driven, objective-terminated red-team loop."""

    def __init__(self, registry, break_memory=None):
        if not isinstance(registry, dict):
            raise CampaignError("registry must be a dict")
        self._registry = registry
        self._memory = dict(break_memory or {})
        self._store = FactStore()

    @property
    def facts(self):
        return self._store.snapshot()

    def _resolve(self, ref):
        if ref in self._registry:
            guid = ref
        else:
            matches = [g for g, e in self._registry.items()
                       if e["spec"]["name"] == ref]
            if not matches:
                raise CampaignError("unknown atomic %r" % (ref,))
            if len(matches) > 1:
                raise CampaignError("ambiguous atomic name %r" % (ref,))
            guid = matches[0]
        return guid, self._registry[guid]["spec"]

    def _eligible(self, spec, store):
        """Caldera requirements: every requires entry must hold."""
        for req in spec.get("requires", []):
            if not _requirement_holds(req, store):
                return False
        return True

    def _eval_goals(self, goals, hits, breaks):
        new_hits = list(hits)
        if not goals:
            # No objectives: the campaign is exhaustion-terminated
            # (Caldera runs objective-less operations until the
            # planner has nothing left).
            return False, new_hits
        all_met = True
        for i, goal in enumerate(goals):
            if _goal_satisfied(goal, self._store, breaks):
                new_hits[i] += 1
            if new_hits[i] < goal["count"]:
                all_met = False
        return all_met, new_hits

    def run(self, name, *, atomics, planner_id, objectives, seed_facts,
            args_map, evidence_path, max_steps=50, manual_approve=False,
            approve_fn=None, elevation_granted=False):
        """Plan and execute a campaign. Returns the campaign id (the
        start record's digest). All records are hash-chained into
        ``evidence_path``."""
        planner = PLANNERS.get(planner_id)
        if planner is None:
            raise CampaignError("unknown planner %r (want one of %s)"
                                % (planner_id, "/".join(sorted(PLANNERS))))
        goals = [validate_objective(o) for o in objectives or []]
        if (not isinstance(max_steps, int) or isinstance(max_steps, bool)
                or max_steps < 1):
            raise CampaignError("max_steps must be a positive int")
        if not isinstance(args_map, dict):
            raise CampaignError("args_map must be a dict")
        if manual_approve and not callable(approve_fn):
            raise CampaignError(
                "manual_approve needs a callable approve_fn")
        self._store = FactStore()
        seed_norm = seed_fact_store(self._store, seed_facts or {})
        resolved = []
        for ref in atomics or []:
            guid, spec = self._resolve(ref)
            resolved.append({"ref": ref, "guid": guid,
                             "name": spec["name"], "spec": spec})

        writer = CampaignWriter(evidence_path)
        try:
            campaign_id = writer.write_start({
                "record_type": "campaign-start",
                "schema_version": _SCHEMA_VERSION,
                "campaign_name": name,
                "planner_id": planner_id,
                "objectives": goals,
                "seed_facts": seed_norm,
                "atomics": [{"ref": r["ref"], "guid": r["guid"],
                             "name": r["name"]} for r in resolved],
                "args_map": args_map,
                "max_steps": max_steps,
                "manual_approve": bool(manual_approve),
                "elevation_granted": bool(elevation_granted),
                "break_memory": self._memory,
                "started_at": al._now(),
            })

            run_names = set()
            breaks = 0
            goal_hits = [0] * len(goals)
            steps = 0
            last_verdict = None
            outcome = None
            while True:
                met, goal_hits = self._eval_goals(goals, goal_hits, breaks)
                if met:
                    outcome = "objectives-met"
                    break
                if (last_verdict == "BREAK"
                        and planner.stop_on_first_break):
                    # The planner's intrinsic stop (e.g.
                    # minimize-to-first-break): checked after the goal
                    # check so an objective met on the same step wins.
                    outcome = "planner-stopped"
                    break
                if steps >= max_steps:
                    outcome = "step-budget-exhausted"
                    break
                eligible = [
                    r for r in resolved
                    if r["name"] not in run_names
                    and self._eligible(r["spec"], self._store)
                    and (elevation_granted
                         or not r["spec"]["executor"]["elevation_required"])
                ]
                if not eligible:
                    outcome = "no-eligible-atomics"
                    break
                nxt = planner.pick(eligible, self._store.snapshot(),
                                   self._memory, run_names)
                if nxt is None:
                    outcome = "no-eligible-atomics"
                    break
                if manual_approve and not approve_fn(nxt["name"]):
                    outcome = "approval-denied"
                    break
                last_verdict = self._run_one(writer, nxt, args_map,
                                             steps, elevation_granted)
                run_names.add(nxt["name"])
                steps += 1
                if last_verdict == "BREAK":
                    breaks += 1

            if outcome not in _CLOSE_REASONS:
                # Unreachable by construction: the reason vocabulary is
                # bound here, not scattered.
                raise CampaignError(
                    "internal: unknown close reason %r" % (outcome,))
            writer.write_close({
                "record_type": "campaign-close",
                "schema_version": _SCHEMA_VERSION,
                "outcome": outcome,
                "objectives_met": outcome == "objectives-met",
                "steps_run": steps,
                "breaks": breaks,
                "goal_hits": goal_hits,
                "closed_at": al._now(),
            })
        finally:
            writer.close()
        return campaign_id

    def _run_one(self, writer, cand, args_map, step_index,
                 elevation_granted):
        ref, guid, aname, spec = (cand["ref"], cand["guid"],
                                  cand["name"], cand["spec"])
        args = args_map.get(ref, args_map.get(guid, args_map.get(aname, {})))
        if not isinstance(args, dict):
            raise CampaignError("args for %r must be a dict" % (aname,))
        try:
            result = bl.run_atomic(guid, args, registry=self._registry,
                                   elevation_granted=elevation_granted)
        except bl.AtomicError as e:
            # LOUD and recorded: a refused atomic (dependency,
            # elevation, cleanup) is evidence, not a silent skip.
            result = {"verdict": "atomic-error",
                      "executor_verdict": None,
                      "executor_note": "%s: %s" % (e.code, e.detail)}
        if result["verdict"] == "ok" \
                and result.get("executor_verdict") == "BREAK":
            verdict = "BREAK"
        elif result["verdict"] == "ok":
            verdict = "HELD"
        else:
            verdict = "ERROR"

        produced = []
        for entry in spec.get("produces", []):
            on = entry["on"]
            if on == "break" and verdict != "BREAK":
                continue
            if on == "held" and verdict != "HELD":
                continue
            self._store.set_fact(entry["fact"], entry["value"],
                                 entry["type"], source="produced",
                                 choices=entry.get("choices"))
            produced.append(entry["fact"])

        parser_note = self._run_parser(spec, result)

        writer.write_step({
            "record_type": "campaign-step",
            "schema_version": _SCHEMA_VERSION,
            "step_index": step_index,
            "atomic_ref": ref,
            "atomic_guid": guid,
            "atomic_name": aname,
            "arg_digest": _digest(al._canonical(args)),
            "verdict": verdict,
            "executor_note": str(result.get("executor_note") or "")[:400],
            "requires": spec.get("requires", []),
            "produced_facts": produced,
            "parser_note": parser_note,
            "facts_snapshot": self._store.snapshot(),
        })
        return verdict

    def _run_parser(self, spec, result):
        """Caldera parsers: harvest typed facts from the outcome.

        Parsed facts must be declared in ``produces`` with a matching
        type; anything else is refused LOUD (recorded in the step's
        parser_note, never written). A raising parser is recorded,
        never fatal.
        """
        parser = spec.get("fact_parser")
        if parser is None:
            return ""
        try:
            parsed = parser(dict(result))
        except Exception as e:  # noqa: BLE001 -- recorded, never fatal
            return "fact_parser raised %s: %s" % (type(e).__name__, e)
        if not isinstance(parsed, list):
            return "fact_parser returned non-list %r" % (type(parsed),)
        declared = {p["fact"]: p for p in spec.get("produces", [])}
        notes = []
        for i, item in enumerate(parsed):
            if (not isinstance(item, dict) or "fact" not in item
                    or "value" not in item):
                notes.append("item %d malformed (need fact+value)" % i)
                continue
            decl = declared.get(item["fact"])
            if decl is None:
                notes.append("item %d: fact %r not declared in produces "
                             "-- refused" % (i, item["fact"]))
                continue
            if not FactStore._value_ok(decl["type"], decl.get("choices"),
                                       item["value"]):
                notes.append("item %d: fact %r value %r mistyped for %r "
                             "-- refused"
                             % (i, item["fact"], item["value"],
                                decl["type"]))
                continue
            self._store.set_fact(item["fact"], item["value"],
                                 decl["type"], source="parser",
                                 choices=decl.get("choices"))
        return "; ".join(notes)


def campaign_summary(path):
    """Machine-readable campaign summary from an evidence file."""
    records = read_campaign_records(path)
    starts = [r for r in records if r["record_type"] == "campaign-start"]
    closes = [r for r in records if r["record_type"] == "campaign-close"]
    steps = [r for r in records if r["record_type"] == "campaign-step"]
    if not starts or not closes:
        raise CampaignError("evidence %r has no start/close" % (path,))
    return {
        "campaign_id": starts[0]["record_digest"],
        "campaign_name": starts[0]["campaign_name"],
        "planner_id": starts[0]["planner_id"],
        "outcome": closes[-1]["outcome"],
        "objectives_met": closes[-1]["objectives_met"],
        "steps_run": closes[-1]["steps_run"],
        "breaks": closes[-1]["breaks"],
        "step_verdicts": [(s["step_index"], s["atomic_name"],
                           s["verdict"]) for s in steps],
    }


def replay_campaign(path, registry, *, evidence_path=None):
    """Deterministic re-run of a recorded campaign (read-only w.r.t.
    the original evidence).

    Rebuilds the run from the campaign-start record, executes into a
    fresh evidence file, and diffs per step
    (atomic_guid, verdict, produced_facts, facts_snapshot). Returns a
    list of diff dicts; empty means identical. A verdict-drift entry
    is the regression signal (the attack-ledger replay precedent).

    Manual-approve campaigns replay with an always-approve stub (a
    human decision cannot be replayed); the stub is named in the
    returned meta entry.
    """
    records = read_campaign_records(path)
    starts = [r for r in records if r["record_type"] == "campaign-start"]
    if not starts:
        raise CampaignError("evidence %r has no campaign-start" % (path,))
    start = starts[0]
    old_steps = [r for r in records if r["record_type"] == "campaign-step"]

    if evidence_path is None:
        import tempfile
        fd, evidence_path = tempfile.mkstemp(prefix="campaign-replay-",
                                             suffix=".jsonl",
                                             dir=os.environ.get("TMPDIR",
                                                                "/tmp"))
        os.close(fd)
    runner = CampaignRunner(registry,
                            break_memory=start.get("break_memory") or {})
    seed_facts = dict(start.get("seed_facts") or {})
    runner.run(
        start["campaign_name"],
        atomics=[a["ref"] for a in start.get("atomics", [])],
        planner_id=start["planner_id"],
        objectives=start.get("objectives", []),
        seed_facts=seed_facts,
        args_map=start.get("args_map", {}),
        evidence_path=evidence_path,
        max_steps=start.get("max_steps", 50),
        manual_approve=False,
        approve_fn=lambda name: True,
        elevation_granted=start.get("elevation_granted", False),
    )
    new_steps = [r for r in read_campaign_records(evidence_path)
                 if r["record_type"] == "campaign-step"]
    diffs = []
    if start.get("manual_approve"):
        diffs.append({"kind": "replay-note",
                      "note": "manual_approve replayed with always-approve"})
    for i, (old, new) in enumerate(zip(old_steps, new_steps)):
        if old["atomic_guid"] != new["atomic_guid"]:
            diffs.append({"step_index": i, "kind": "order-drift",
                          "before": old["atomic_name"],
                          "after": new["atomic_name"]})
            continue
        if old["verdict"] != new["verdict"]:
            diffs.append({"step_index": i, "kind": "verdict-drift",
                          "before": old["verdict"], "after": new["verdict"]})
        elif al._canonical(old["produced_facts"]) != al._canonical(
                new["produced_facts"]):
            diffs.append({"step_index": i, "kind": "facts-drift",
                          "before": old["produced_facts"],
                          "after": new["produced_facts"]})
        elif al._canonical(old["facts_snapshot"]) != al._canonical(
                new["facts_snapshot"]):
            diffs.append({"step_index": i, "kind": "snapshot-drift",
                          "before": old["facts_snapshot"],
                          "after": new["facts_snapshot"]})
    if len(new_steps) < len(old_steps):
        for j in range(len(new_steps), len(old_steps)):
            diffs.append({"step_index": j, "kind": "missing-step"})
    elif len(new_steps) > len(old_steps):
        for j in range(len(old_steps), len(new_steps)):
            diffs.append({"step_index": j, "kind": "extra-step"})
    return diffs
