"""Incident lifecycle orchestration: declare -> roles -> tasks ->
notifications -> postmortems.

Wave-253 lane 2. Stdlib only.

netflix/dispatch ADAPT (pattern only -- dispatch is archived
read-only, never a dependency): incidents are event-sourced over
``gov.durable_journal`` (hash-chained JSONL, crash-safe,
multi-process safe). The current state of any incident is the
replay of its events; there is no in-memory state to forge.

Two properties that matter:

1. **Fail-closed resolution.** ``resolve()`` refuses
   ``incident-open-findings`` while any linked finding is open, and
   ``incident-open-tasks`` while tasks are incomplete. Finding
   status comes from a deployment-supplied ``finding_status``
   callable; when the provider is absent, raises, or cannot answer
   a finding, resolution is refused fail-closed -- the module never
   assumes a finding is closed. ``resolve()`` is the ONLY path into
   the resolved state: ``transition()`` to "resolved" is refused as
   incident-illegal-transition (F216), so no public API can skip
   the gate. Every refusal is itself journaled
   (``incident/resolve_refused``), so the audit trail shows the
   attempt.

2. **No caller-aliasing.** Every caller-supplied value is
   deep-copied into the journal at append time and every public
   accessor returns a deep copy. Mutating your ``timeline`` list
   after ``attach_postmortem()`` -- the F212 lesson -- cannot
   change what the incident recorded.

Tamper model, stated honestly: the journal's hash chain makes any
modification of the incident file detectable on reload
(``JournalCorrupted`` fail-closed). It does NOT prove *who* wrote
an event -- writer authenticity is deployment-owned (same
guarantee as ``durable_journal`` itself; contrast
``permit_journal``'s HMAC layer, which the incident threat model
does not need: incidents are written by the deployment's own
processes, and the audit value is tamper-evidence, not
non-repudiation).

Notifications: the module *records* notification events
(channel/recipient/message); actual delivery is
deployment-owned -- dispatch orchestrates, it does not send mail.
"""

import copy
import datetime
import json
import os

from . import durable_journal as _dj

# ------------------------------------------------------------------
# states
#
# Single-path resolution (F216 fix, 2026-10-01): "resolved" is NOT a
# legal transition() target. The only way into the resolved state is
# resolve(), which runs the fail-closed finding/task checks. Calling
# transition(incident_id, "resolved") is refused as
# incident-illegal-transition (journaled as incident/
# transition_refused, same as every other illegal move), so no public
# API can skip the resolve() gate.


STATES = ("open", "investigating", "contained", "resolved", "closed")

LEGAL_TRANSITIONS = {
    "open": ("investigating",),
    "investigating": ("open", "contained"),
    "contained": ("investigating",),
    "resolved": ("closed",),
    "closed": (),
}

SEVERITIES = ("low", "medium", "high", "critical")

_RTYPES = {
    "declared": "incident/declared",
    "role_assigned": "incident/role_assigned",
    "task_added": "incident/task_added",
    "task_completed": "incident/task_completed",
    "notified": "incident/notified",
    "finding_linked": "incident/finding_linked",
    "evidence_linked": "incident/evidence_linked",
    "transitioned": "incident/transitioned",
    "transition_refused": "incident/transition_refused",
    "resolve_refused": "incident/resolve_refused",
    "resolved": "incident/resolved",
    "postmortem_attached": "incident/postmortem_attached",
}


# ------------------------------------------------------------------
# errors


class IncidentError(Exception):
    """Incident refusal. ``code`` is a machine decision code."""

    code = "incident-malformed"

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise IncidentError(code, detail)


# ------------------------------------------------------------------
# validation


_MAX_ID = 128
_MAX_TEXT = 2048


def _check_id(value, what):
    if not isinstance(value, str) or not value.strip() \
            or len(value) > _MAX_ID:
        _refuse("incident-malformed",
                "%s must be a non-empty string <= %d chars"
                % (what, _MAX_ID))
    return value


def _check_text(value, what, limit=_MAX_TEXT):
    if not isinstance(value, str) or not value.strip() \
            or len(value) > limit:
        _refuse("incident-malformed",
                "%s must be a non-empty string <= %d chars"
                % (what, limit))
    return value


def _utcnow():
    return datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


# ------------------------------------------------------------------
# manager


class IncidentManager:
    """Event-sourced incident lifecycle over a durable journal.

    ``journal_path``: where incident events are journaled.
    ``finding_status``: deployment-supplied callable
    ``finding_id -> "open" | "closed"``. Absent/raising/unknown
    answers fail closed at resolve time.
    """

    def __init__(self, journal_path, finding_status=None):
        if not isinstance(journal_path, str) or not journal_path:
            _refuse("incident-malformed",
                    "journal_path must be a non-empty string")
        self.journal_path = os.path.abspath(journal_path)
        parent = os.path.dirname(self.journal_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if finding_status is not None and not callable(finding_status):
            _refuse("incident-malformed",
                    "finding_status must be callable or None")
        self._finding_status = finding_status
        self._journal = _dj.Journal(self.journal_path)
        self._incidents = {}
        self._replay()

    # ------------------------------------------------- replay

    def _replay(self):
        for rec in self._journal.records:
            body = rec.get("body") or {}
            iid = body.get("incident_id")
            kind = rec.get("type", "")
            if not kind.startswith("incident/") or not iid:
                continue
            ev = kind[len("incident/"):]
            st = self._incidents.get(iid)
            if st is None:
                if ev != "declared":
                    continue  # event for an undeclared incident
                st = self._blank(iid)
                self._incidents[iid] = st
            self._apply(st, ev, copy.deepcopy(body))

    @staticmethod
    def _blank(iid):
        return {"id": iid, "title": None, "severity": None,
                "state": "open", "declared_at": None,
                "roles": {}, "tasks": [], "task_seq": 0,
                "notifications": [], "notif_seq": 0,
                "findings": [], "evidence_refs": [],
                "postmortem": None, "events": []}

    def _apply(self, st, ev, body):
        st["events"].append({"kind": ev, "body": body})
        if ev == "declared":
            st["title"] = body["title"]
            st["severity"] = body["severity"]
            st["declared_at"] = body["declared_at"]
        elif ev == "role_assigned":
            st["roles"][body["role"]] = body["identity"]
        elif ev == "task_added":
            st["task_seq"] += 1
            st["tasks"].append(
                {"id": body["task_id"], "title": body["title"],
                 "owner": body["owner"], "status": "open"})
        elif ev == "task_completed":
            for t in st["tasks"]:
                if t["id"] == body["task_id"]:
                    t["status"] = "done"
        elif ev == "notified":
            st["notif_seq"] += 1
            st["notifications"].append(
                {"id": body["notification_id"],
                 "channel": body["channel"],
                 "recipient": body["recipient"],
                 "message": body["message"],
                 "notified_at": body["notified_at"]})
        elif ev == "finding_linked":
            if body["finding_id"] not in st["findings"]:
                st["findings"].append(body["finding_id"])
        elif ev == "evidence_linked":
            if body["ref"] not in st["evidence_refs"]:
                st["evidence_refs"].append(body["ref"])
        elif ev == "transitioned":
            st["state"] = body["to_state"]
        elif ev == "resolved":
            st["state"] = "resolved"
        elif ev == "postmortem_attached":
            st["postmortem"] = body["postmortem"]
        # *_refused events are audit-only: state untouched.

    def _append(self, kind, body):
        body = copy.deepcopy(body)
        self._journal.append(_RTYPES[kind], body)
        # Fold into the live view (replay the one record).
        rec = self._journal.records[-1]
        iid = rec["body"]["incident_id"]
        st = self._incidents.get(iid)
        if st is not None:
            self._apply(st, kind, copy.deepcopy(rec["body"]))
        return copy.deepcopy(body)

    def _need(self, iid):
        _check_id(iid, "incident_id")
        st = self._incidents.get(iid)
        if st is None or st["title"] is None:
            _refuse("incident-unknown", "unknown incident %r" % (iid,))
        return st

    # ------------------------------------------------- declare

    def declare_incident(self, incident_id, *, title, severity="high",
                         **_ignored):
        _check_id(incident_id, "incident_id")
        _check_text(title, "title", 512)
        if severity not in SEVERITIES:
            _refuse("incident-malformed",
                    "severity must be one of %s" % (SEVERITIES,))
        if incident_id in self._incidents:
            _refuse("incident-malformed",
                    "duplicate incident id %r" % (incident_id,))
        self._incidents[incident_id] = self._blank(incident_id)
        self._append("declared", {
            "incident_id": incident_id, "title": title,
            "severity": severity, "declared_at": _utcnow()})
        return self.summary(incident_id)

    # ------------------------------------------------- roles

    def assign_role(self, incident_id, role, identity):
        st = self._need(incident_id)
        _check_id(role, "role")
        _check_id(identity, "identity")
        self._append("role_assigned", {
            "incident_id": incident_id, "role": role,
            "identity": identity, "assigned_at": _utcnow()})
        return dict(st["roles"])

    # ------------------------------------------------- tasks

    def add_task(self, incident_id, title, *, owner):
        st = self._need(incident_id)
        _check_text(title, "task title", 512)
        _check_id(owner, "task owner")
        task_id = "task-%d" % (st["task_seq"] + 1)
        self._append("task_added", {
            "incident_id": incident_id, "task_id": task_id,
            "title": title, "owner": owner})
        return task_id

    def complete_task(self, incident_id, task_id):
        st = self._need(incident_id)
        _check_id(task_id, "task_id")
        if not any(t["id"] == task_id for t in st["tasks"]):
            _refuse("incident-unknown",
                    "unknown task %r on %r" % (task_id, incident_id))
        self._append("task_completed", {
            "incident_id": incident_id, "task_id": task_id,
            "completed_at": _utcnow()})
        return True

    # ------------------------------------------------- notify

    def notify(self, incident_id, channel, recipient, message):
        st = self._need(incident_id)
        _check_id(channel, "channel")
        _check_id(recipient, "recipient")
        _check_text(message, "message")
        notif_id = "notif-%d" % (st["notif_seq"] + 1)
        self._append("notified", {
            "incident_id": incident_id,
            "notification_id": notif_id, "channel": channel,
            "recipient": recipient, "message": message,
            "notified_at": _utcnow()})
        return notif_id

    # ------------------------------------------------- links

    def link_finding(self, incident_id, finding_id):
        self._need(incident_id)
        _check_id(finding_id, "finding_id")
        self._append("finding_linked", {
            "incident_id": incident_id, "finding_id": finding_id})
        return True

    def link_evidence(self, incident_id, ref):
        self._need(incident_id)
        _check_text(ref, "evidence ref", 512)
        self._append("evidence_linked", {
            "incident_id": incident_id, "ref": ref})
        return True

    # ------------------------------------------------- transitions

    def transition(self, incident_id, new_state):
        st = self._need(incident_id)
        if new_state not in STATES:
            _refuse("incident-malformed",
                    "unknown state %r" % (new_state,))
        if new_state not in LEGAL_TRANSITIONS[st["state"]]:
            self._append("transition_refused", {
                "incident_id": incident_id,
                "from_state": st["state"], "to_state": new_state,
                "code": "incident-illegal-transition"})
            _refuse("incident-illegal-transition",
                    "cannot transition %s -> %s"
                    % (st["state"], new_state))
        self._append("transitioned", {
            "incident_id": incident_id,
            "from_state": st["state"], "to_state": new_state,
            "transitioned_at": _utcnow()})
        return st["state"]

    # ------------------------------------------------- resolve

    def _finding_is_closed(self, finding_id):
        provider = self._finding_status
        if provider is None:
            return False
        try:
            return provider(finding_id) == "closed"
        except Exception:  # noqa: BLE001 - any provider failure
            return False  # is fail-closed, never assumed closed

    def resolve(self, incident_id):
        st = self._need(incident_id)
        if st["state"] != "contained":
            _refuse("incident-illegal-transition",
                    "resolve requires state 'contained', "
                    "have %r" % (st["state"],))
        open_tasks = [t["id"] for t in st["tasks"]
                      if t["status"] != "done"]
        if open_tasks:
            self._append("resolve_refused", {
                "incident_id": incident_id,
                "code": "incident-open-tasks",
                "open_tasks": open_tasks})
            _refuse("incident-open-tasks",
                    "cannot resolve with open tasks %r" % (open_tasks,))
        open_findings = [f for f in st["findings"]
                         if not self._finding_is_closed(f)]
        if open_findings:
            self._append("resolve_refused", {
                "incident_id": incident_id,
                "code": "incident-open-findings",
                "open_findings": open_findings})
            _refuse("incident-open-findings",
                    "cannot resolve with open findings %r"
                    % (open_findings,))
        self._append("resolved", {
            "incident_id": incident_id, "resolved_at": _utcnow()})
        return self.summary(incident_id)

    # ------------------------------------------------- postmortem

    def attach_postmortem(self, incident_id, *, timeline,
                          root_cause, action_items):
        st = self._need(incident_id)
        if st["state"] not in ("contained", "resolved"):
            _refuse("incident-premature-postmortem",
                    "postmortem requires contained/resolved, "
                    "have %r" % (st["state"],))
        if st["postmortem"] is not None:
            _refuse("incident-malformed",
                    "duplicate postmortem on %r" % (incident_id,))
        if not isinstance(timeline, list):
            _refuse("incident-malformed", "timeline must be a list")
        for entry in timeline:
            if not isinstance(entry, dict) \
                    or not isinstance(entry.get("at"), str) \
                    or not isinstance(entry.get("event"), str) \
                    or not entry["at"].strip() \
                    or not entry["event"].strip():
                _refuse("incident-malformed",
                        "timeline entries need {at, event} strings")
        _check_text(root_cause, "root_cause")
        if not isinstance(action_items, list):
            _refuse("incident-malformed", "action_items must be a list")
        for item in action_items:
            if not isinstance(item, dict) \
                    or not isinstance(item.get("item"), str) \
                    or not isinstance(item.get("owner"), str) \
                    or not isinstance(item.get("due"), str) \
                    or not item["item"].strip() \
                    or not item["owner"].strip() \
                    or not item["due"].strip():
                _refuse("incident-malformed",
                        "action items need {item, owner, due} strings")
        postmortem = {"incident_id": incident_id,
                      "timeline": copy.deepcopy(timeline),
                      "root_cause": root_cause,
                      "action_items": copy.deepcopy(action_items),
                      "attached_at": _utcnow()}
        self._append("postmortem_attached", {
            "incident_id": incident_id, "postmortem": postmortem})
        return copy.deepcopy(st["postmortem"])

    # ------------------------------------------------- views

    def state(self, incident_id):
        return self._need(incident_id)["state"]

    def roles(self, incident_id):
        return dict(self._need(incident_id)["roles"])

    def tasks(self, incident_id):
        return copy.deepcopy(self._need(incident_id)["tasks"])

    def notifications(self, incident_id):
        return copy.deepcopy(self._need(incident_id)["notifications"])

    def findings(self, incident_id):
        return list(self._need(incident_id)["findings"])

    def evidence_refs(self, incident_id):
        return list(self._need(incident_id)["evidence_refs"])

    def postmortem(self, incident_id):
        return copy.deepcopy(self._need(incident_id)["postmortem"])

    def events(self, incident_id):
        return copy.deepcopy(self._need(incident_id)["events"])

    def event_count(self, incident_id):
        return len(self._need(incident_id)["events"])

    def incident_ids(self):
        return sorted(i for i, st in self._incidents.items()
                      if st["title"] is not None)

    def summary(self, incident_id):
        st = self._need(incident_id)
        return {
            "id": st["id"], "title": st["title"],
            "severity": st["severity"], "state": st["state"],
            "declared_at": st["declared_at"],
            "roles": dict(sorted(st["roles"].items())),
            "tasks": copy.deepcopy(st["tasks"]),
            "notifications": len(st["notifications"]),
            "findings": list(st["findings"]),
            "evidence_refs": list(st["evidence_refs"]),
            "postmortem_attached": st["postmortem"] is not None,
            "event_count": len(st["events"]),
        }

    def summary_canonical(self, incident_id):
        return _canonical(self.summary(incident_id))


# ------------------------------------------------------------------
# module-level convenience


def declare_incident(incident_id, *, title, severity="high",
                     journal_path, finding_status=None, **kw):
    """Declare an incident with an ephemeral manager."""
    return IncidentManager(
        journal_path=journal_path,
        finding_status=finding_status).declare_incident(
            incident_id, title=title, severity=severity, **kw)
