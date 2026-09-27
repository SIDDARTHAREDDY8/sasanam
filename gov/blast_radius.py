"""Temporal blast-radius analysis (row-7 e1, wave-132).

Read-only post-hoc analysis: given an approval id (or an event seq) and a
hash-chained audit log, walk forward from the anchor and build the causal
DAG of everything the approval enabled -- tool calls consuming the
approval, resulting state changes, later egress, spawned children and their
downstream actions. The output lists affected actions, data touched,
external effects, and a containment checklist.

Fail-closed: the source chain is verified FIRST (``gov.log.verify_chain``);
a damaged chain raises :class:`BlastRadiusUnverifiable` instead of
returning a partial-looking report. An anchor that cannot be resolved
raises :class:`AnchorNotFound`.

Causality model (documented approximation -- approval consumption,
temporal ordering, and recorded lineage approximate causality; they do
not prove it)::

    DAG roots: the anchor's own action is the root of the radius, not
      just the point the forward walk starts after.
      - approval anchor: the queued tool_call the approval was granted
        for (the approval's subject). One approval produces three audit
        stages -- queued, authorized, executed -- all carrying the same
        approval_id; the queued stage predates the decision, so a
        purely forward walk would miss the very action approved.
      - event anchor: the anchor event itself (edge_kind "anchor").

    STRONG edges (explicit audit relationships):
      approval_consumption   tool_call.approval_id == anchor approval id
                             (covers all three audit stages of the
                             approval, including the queued subject)
      authorized_execution   tool_call.authorization_seq == anchor event seq
                             (the sweep's write-ahead record)
      data_flow_path         a later action references a path written or
                             registered by an already-included node
                             (exact normalized path match)
      spawn                  agent_spawn by an included agent (parent->child)
      child_action           tool_call by a spawned descendant after its
                             spawn event

    MEDIUM edges (temporal / identity correlation, NOT causal proof):
      agent_lineage          action by the anchor agent (or a spawned
                             descendant) after the anchor with no stronger
                             edge -- "this agent acted after the approval"
      content_carry          egress whose policy_context records
                             carries_read_content, after an included read
                             by the same agent (most-recent-read heuristic)

Unrelated agents -- no spawn link to the anchor agent -- are NEVER included,
no matter how close in time. Covert timing and steganographic channels are
not represented. Content-equality between staged bytes and egress payloads
is deliberately NOT matched; the analyst sees the agent_lineage edges and
inspects.

Stdlib only. Deterministic. No audit events are emitted: analysis is
read-only so it can never perturb the chain it reads.
"""

from .log import read_entries, verify_chain

#: Tool-call decisions that mean the action actually happened.
EXECUTED_DECISIONS = ("executed", "allowed_executed", "approved_executed")

#: Tools whose execution is an external effect (data leaves the boundary).
EGRESS_TOOLS = ("send_email", "http_post", "api_call")

#: Tools whose execution changes persisted state.
_STATE_WRITE_TOOLS = ("write_file",)
_STATE_READ_TOOLS = ("read_file",)
_STATE_DELETE_TOOLS = ("delete_file",)

_HONEST_CEILING = (
    "Approval consumption, temporal ordering, and recorded lineage "
    "approximate causality; they do not prove it. agent_lineage and "
    "content_carry edges are temporal/identity correlation, not causal "
    "proof. Covert timing and steganographic channels are not represented. "
    "Content-equality between staged bytes and egress payloads is "
    "deliberately not matched -- inspect agent_lineage nodes manually. "
    "Unrelated agents (no spawn link to the anchor agent) are excluded by "
    "construction."
)


class BlastRadiusUnverifiable(Exception):
    """The source audit chain is damaged: no report is produced."""


class AnchorNotFound(Exception):
    """The approval id / event seq anchor cannot be resolved in the log."""


def _norm_path(path):
    """Normalize a file path for exact data-flow matching."""
    text = str(path).replace("\\", "/").strip()
    while text.startswith("/"):
        text = text[1:]
    while "//" in text:
        text = text.replace("//", "/")
    return text


def _referenced_paths(args):
    """File paths referenced by a tool_call's args (one nesting level)."""
    paths = []

    def _scan(mapping):
        if not isinstance(mapping, dict):
            return
        for key in ("path", "file", "filepath", "filename"):
            value = mapping.get(key)
            if isinstance(value, str) and value:
                paths.append(value)
        for key in ("attachments", "files"):
            value = mapping.get(key)
            if isinstance(value, (list, tuple)):
                paths.extend(v for v in value if isinstance(v, str))

    _scan(args)
    if isinstance(args, dict):
        _scan(args.get("params"))
    return paths


def _destination(tool, args):
    """Best-effort external destination for an egress tool call."""
    if not isinstance(args, dict):
        return None
    for key in ("url", "endpoint"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    if tool == "send_email":
        for key in ("to", "recipients"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, (list, tuple)) and value:
                return ",".join(str(v) for v in value)
    return None


def _node_summary(event):
    tool = event.get("tool")
    agent = event.get("agent_id")
    decision = event.get("decision")
    if event.get("event") == "agent_spawn":
        return "agent_spawn: %s spawned %s" % (agent, event.get("sub_agent_id"))
    if tool:
        return "tool_call %s by %s (%s)" % (tool, agent, decision)
    return "%s by %s (%s)" % (event.get("event"), agent, decision)


def analyze_blast_radius(approval_id_or_event_seq, audit_log, *,
                         run_id=None, include_medium=True):
    """Build the temporal blast-radius DAG forward from an anchor.

    ``approval_id_or_event_seq`` is either an approval id (``str``) --
    the report anchors on the matching approved ``approval_decision`` --
    or an audit event sequence number (``int``), anchoring on that event
    itself. ``audit_log`` is the audit log path, or an ``ActionLog``
    (its ``.path`` is used). ``run_id`` optionally scopes the walk to
    one run. ``include_medium`` toggles the medium-strength correlation
    edges (default on).

    Returns a report dict with ``anchor``, ``chain``,
    ``affected_actions`` (``nodes`` is a compatibility alias), ``edges``,
    ``agents_involved``, ``data_touched``, ``external_effects``,
    ``containment_checklist``, ``counts``, and ``honest_ceiling``.
    """
    if isinstance(approval_id_or_event_seq, bool):
        raise ValueError(
            "approval_id_or_event_seq must be an approval id (str) or an "
            "event seq (int), not a bool")
    if isinstance(approval_id_or_event_seq, str):
        approval_id, anchor_seq = approval_id_or_event_seq, None
    elif isinstance(approval_id_or_event_seq, int):
        approval_id, anchor_seq = None, approval_id_or_event_seq
    else:
        raise ValueError(
            "approval_id_or_event_seq must be an approval id (str) or an "
            "event seq (int); got %s"
            % type(approval_id_or_event_seq).__name__)

    # Accept a path or a live ActionLog.
    log_path = getattr(audit_log, "path", audit_log)

    ok, broken_seq, entry_count = verify_chain(log_path)
    if not ok:
        raise BlastRadiusUnverifiable(
            "audit chain failed verification (broken at seq %r; %d entries "
            "readable): refusing to produce a blast-radius report from a "
            "damaged log" % (broken_seq, entry_count))

    entries = [e for e in read_entries(log_path)
               if isinstance(e, dict) and isinstance(e.get("seq"), int)]
    if run_id is not None:
        entries = [e for e in entries if e.get("run_id") == run_id]
    entries.sort(key=lambda e: e["seq"])
    by_seq = {e["seq"]: e for e in entries}

    # ---- resolve the anchor -------------------------------------------
    anchor_event = None
    anchor_kind = None
    if approval_id is not None:
        for e in entries:
            if (e.get("event") == "approval_decision"
                    and e.get("approval_id") == approval_id
                    and e.get("decision") == "approved"):
                anchor_event = e
                anchor_kind = "approval"
                break
        if anchor_event is None:
            raise AnchorNotFound(
                "no approved approval_decision for approval_id %r"
                % (approval_id,))
    else:
        anchor_event = by_seq.get(anchor_seq)
        if anchor_event is None:
            raise AnchorNotFound("no audit event at seq %r" % (anchor_seq,))
        anchor_kind = "event"
    anchor_seq = anchor_event["seq"]
    anchor_agent = (anchor_event.get("related_agent")
                    or anchor_event.get("agent_id"))
    if not anchor_agent:
        raise AnchorNotFound(
            "anchor at seq %r names no agent; cannot attribute a radius"
            % (anchor_seq,))

    # ---- forward walk ---------------------------------------------------
    agents = {anchor_agent}          # anchor + spawned descendants
    spawn_seq_of = {}               # child agent -> spawn event seq
    written_paths = {}              # normalized path -> writer node seq
    last_read_seq = {}              # agent -> seq of last included read_file
    nodes = []
    edges = []
    node_by_seq = {}

    def _add_node(event, kind, strength, parent_seq):
        node = {
            "seq": event["seq"],
            "event": event.get("event"),
            "tool": event.get("tool"),
            "agent_id": event.get("agent_id"),
            "decision": event.get("decision"),
            "edge_kind": kind,
            "strength": strength,
            "summary": _node_summary(event),
        }
        if event.get("approval_id"):
            node["approval_id"] = event.get("approval_id")
        nodes.append(node)
        node_by_seq[event["seq"]] = node
        edges.append({"from": parent_seq, "to": event["seq"], "kind": kind})
        return node

    def _feed_state(event):
        """Register a node's state effects for later data-flow matching."""
        tool = event.get("tool")
        args = (event.get("args") if isinstance(event.get("args"), dict)
                else {})
        if (tool in _STATE_WRITE_TOOLS
                and event.get("decision") in EXECUTED_DECISIONS):
            for path in _referenced_paths(args):
                written_paths.setdefault(_norm_path(path), event["seq"])
        if (tool in _STATE_READ_TOOLS
                and event.get("decision") in EXECUTED_DECISIONS):
            last_read_seq[event.get("agent_id")] = event["seq"]

    # ---- DAG roots --------------------------------------------------------
    # The anchor's own action is the root of the radius. An approval
    # anchor roots on the queued tool_call the approval was granted for
    # (its subject -- the latest pre-decision tool_call carrying the
    # approval id); an event anchor roots on the anchor event itself.
    # The root's own state effects feed data-flow matching so later
    # actions that touch the same paths link back to the anchor.
    if anchor_kind == "approval":
        subject = None
        for e in entries:
            if (e["seq"] < anchor_seq
                    and e.get("event") == "tool_call"
                    and e.get("approval_id") == approval_id):
                subject = e
        if subject is not None:
            _add_node(subject, "approval_consumption", "strong", anchor_seq)
    else:
        _add_node(anchor_event, "anchor", "strong", None)
        _feed_state(anchor_event)

    for event in entries:
        seq = event["seq"]
        if seq <= anchor_seq:
            continue
        ev = event.get("event")
        agent = event.get("agent_id")
        tool = event.get("tool")
        args = event.get("args") if isinstance(event.get("args"), dict) else {}

        # State-change registrations feed data-flow matching silently.
        if ev == "artifact_registered" and agent in agents:
            path = event.get("path") or args.get("path")
            if isinstance(path, str) and path:
                written_paths.setdefault(_norm_path(path), seq)
            continue

        if ev == "agent_spawn":
            if agent not in agents:
                continue
            child = event.get("sub_agent_id")
            if not child:
                continue
            agents.add(child)
            spawn_seq_of[child] = seq
            _add_node(event, "spawn", "strong", anchor_seq)
            continue

        if ev != "tool_call":
            continue
        if agent not in agents:
            continue  # unrelated agent: never included

        kind = strength = parent = None
        if approval_id is not None and event.get("approval_id") == approval_id:
            kind, strength, parent = "approval_consumption", "strong", anchor_seq
        elif event.get("authorization_seq") == anchor_seq:
            kind, strength, parent = "authorized_execution", "strong", anchor_seq
        else:
            writer = None
            for path in _referenced_paths(args):
                hit = written_paths.get(_norm_path(path))
                if hit is not None:
                    writer = hit
                    break
            if writer is not None:
                kind, strength, parent = "data_flow_path", "strong", writer
            elif agent != anchor_agent:
                kind, strength = "child_action", "strong"
                parent = spawn_seq_of.get(agent, anchor_seq)
            else:
                carried = (tool in EGRESS_TOOLS
                           and isinstance(event.get("policy_context"), dict)
                           and event["policy_context"].get("carries_read_content")
                           and last_read_seq.get(agent) is not None)
                if carried:
                    kind, strength = "content_carry", "medium"
                    parent = last_read_seq[agent]
                else:
                    kind, strength, parent = "agent_lineage", "medium", anchor_seq

        if strength == "medium" and not include_medium:
            continue
        _add_node(event, kind, strength, parent)
        _feed_state(event)

    # ---- derived views ----------------------------------------------------
    data_touched = []
    external_effects = []
    for node in nodes:
        seq, tool, agent = node["seq"], node["tool"], node["agent_id"]
        event = by_seq[seq]
        args = event.get("args") if isinstance(event.get("args"), dict) else {}
        if node["decision"] not in EXECUTED_DECISIONS:
            continue
        if tool in _STATE_WRITE_TOOLS:
            for path in _referenced_paths(args):
                data_touched.append({"seq": seq, "path": path,
                                     "operation": "write", "agent_id": agent})
        elif tool in _STATE_READ_TOOLS:
            for path in _referenced_paths(args):
                data_touched.append({"seq": seq, "path": path,
                                     "operation": "read", "agent_id": agent})
        elif tool in _STATE_DELETE_TOOLS:
            for path in _referenced_paths(args):
                data_touched.append({"seq": seq, "path": path,
                                     "operation": "delete", "agent_id": agent})
        if tool in EGRESS_TOOLS:
            dest = _destination(tool, args)
            if dest:
                external_effects.append({"seq": seq, "tool": tool,
                                         "destination": dest, "agent_id": agent})

    agents_involved = sorted(agents)
    strong = sum(1 for n in nodes if n["strength"] == "strong")
    medium = sum(1 for n in nodes if n["strength"] == "medium")

    # ---- containment checklist --------------------------------------------
    checklist = []
    if anchor_kind == "approval":
        checklist.append(
            "Revoke approval '%s' if still live (gov/revoke.py revoke-after-approve "
            "path); confirm the sweep cannot re-consume it." % (approval_id,))
    checklist.append(
        "Suspend agent '%s' (anchor agent) pending review; preserve the audit "
        "log -- chain verified over %d entries." % (anchor_agent, entry_count))
    checklist.append(
        "Revoke any live delegation tokens/sessions held by '%s' and its "
        "spawned descendants (DelegationTokens.revoke in "
        "gov/delegation_tokens.py) and retire their sessions, so no further "
        "tool call can ride a stale grant; re-mint identities only after "
        "review." % (anchor_agent,))
    for child, sseq in sorted(spawn_seq_of.items(), key=lambda kv: kv[1]):
        n_down = sum(1 for n in nodes if n["agent_id"] == child)
        checklist.append(
            "Quarantine child agent '%s' spawned at seq %d; review its %d "
            "downstream action(s) before re-admitting." % (child, sseq, n_down))
    for fx in external_effects:
        checklist.append(
            "Assess exposure at '%s' (%s seq %d by %s); rotate any credentials "
            "that may have been transmitted; notify the destination operator "
            "if data left the boundary."
            % (fx["destination"], fx["tool"], fx["seq"], fx["agent_id"]))
    for touched in data_touched:
        if touched["operation"] == "write":
            checklist.append(
                "Quarantine/review file '%s' (written seq %d by %s); verify "
                "bytes against the artifact inventory."
                % (touched["path"], touched["seq"], touched["agent_id"]))
    checklist.append(
        "Export an incident bundle (gov/incident_export.py) before remediation "
        "mutates state; attach this report's node/edge list.")

    anchor = {
        "kind": anchor_kind,
        "seq": anchor_seq,
        "agent_id": anchor_agent,
        "tool": anchor_event.get("tool"),
        "decision": anchor_event.get("decision"),
    }
    if approval_id is not None:
        anchor["approval_id"] = approval_id

    return {
        "anchor": anchor,
        "chain": {"verified": True, "entries": entry_count},
        # "affected_actions" is the public field name; "nodes" is kept as
        # a compatibility alias for the same list.
        "affected_actions": nodes,
        "nodes": nodes,
        "edges": edges,
        "agents_involved": agents_involved,
        "data_touched": data_touched,
        "external_effects": external_effects,
        "containment_checklist": checklist,
        "counts": {"strong": strong, "medium": medium,
                   "total": len(nodes)},
        "honest_ceiling": _HONEST_CEILING,
    }
