"""Unit tests for gov/incident.py (wave-253 lane 2)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import incident as inc
from gov import decision_codes as dc


def _tmp():
    base = "/var/tmp/w253-incident-units"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix="u-", dir=base)


def _mgr(**kw):
    return inc.IncidentManager(
        journal_path=os.path.join(_tmp(), "inc.jsonl"), **kw)


def _closed(fid):
    return "closed"


class IncidentLifecycleTest(unittest.TestCase):
    def test_declare_and_states(self):
        m = _mgr(finding_status=_closed)
        s = m.declare_incident("INC-1", title="t", severity="low")
        self.assertEqual(s["state"], "open")
        self.assertEqual(m.state("INC-1"), "open")
        self.assertEqual(inc.STATES,
                         ("open", "investigating", "contained",
                          "resolved", "closed"))

    def test_legal_transitions(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        self.assertEqual(m.transition("INC-1", "investigating"),
                         "investigating")
        self.assertEqual(m.transition("INC-1", "contained"), "contained")

    def test_illegal_transition_code(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        with self.assertRaises(inc.IncidentError) as cm:
            m.transition("INC-1", "resolved")
        self.assertEqual(cm.exception.code, "incident-illegal-transition")
        self.assertEqual(m.state("INC-1"), "open")

    def test_resolve_guards_findings(self):
        m = _mgr(finding_status=lambda f: "open")
        m.declare_incident("INC-1", title="t")
        m.link_finding("INC-1", "F214")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        with self.assertRaises(inc.IncidentError) as cm:
            m.resolve("INC-1")
        self.assertEqual(cm.exception.code, "incident-open-findings")
        # refusal is journaled
        kinds = [e["kind"] for e in m.events("INC-1")]
        self.assertIn("resolve_refused", kinds)

    def test_resolve_guards_tasks(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        m.add_task("INC-1", "do it", owner="a")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        with self.assertRaises(inc.IncidentError) as cm:
            m.resolve("INC-1")
        self.assertEqual(cm.exception.code, "incident-open-tasks")

    def test_resolve_happy(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        m.link_finding("INC-1", "F999")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        m.resolve("INC-1")
        self.assertEqual(m.state("INC-1"), "resolved")

    def test_no_provider_fail_closed(self):
        m = _mgr()
        m.declare_incident("INC-1", title="t")
        m.link_finding("INC-1", "F1")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        with self.assertRaises(inc.IncidentError) as cm:
            m.resolve("INC-1")
        self.assertEqual(cm.exception.code, "incident-open-findings")

    def test_roles_tasks_notify(self):
        m = _mgr()
        m.declare_incident("INC-1", title="t")
        m.assign_role("INC-1", "commander", "alice")
        self.assertEqual(m.roles("INC-1"), {"commander": "alice"})
        tid = m.add_task("INC-1", "isolate", owner="alice")
        self.assertEqual(m.tasks("INC-1")[0]["status"], "open")
        m.complete_task("INC-1", tid)
        self.assertEqual(m.tasks("INC-1")[0]["status"], "done")
        nid = m.notify("INC-1", "page", "alice", "go")
        self.assertEqual(m.notifications("INC-1")[0]["id"], nid)

    def test_postmortem_structured(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        with self.assertRaises(inc.IncidentError) as cm:
            m.attach_postmortem("INC-1", timeline=[], root_cause="r",
                                action_items=[])
        self.assertEqual(cm.exception.code,
                         "incident-premature-postmortem")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        pm = m.attach_postmortem(
            "INC-1", timeline=[{"at": "t0", "event": "e"}],
            root_cause="rc",
            action_items=[{"item": "i", "owner": "o", "due": "d"}])
        self.assertEqual(pm["root_cause"], "rc")
        self.assertEqual(pm["timeline"][0]["event"], "e")
        self.assertEqual(pm["action_items"][0]["owner"], "o")

    def test_postmortem_aliasing(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        m.transition("INC-1", "investigating")
        m.transition("INC-1", "contained")
        tl = [{"at": "t0", "event": "real"}]
        m.attach_postmortem("INC-1", timeline=tl, root_cause="r",
                            action_items=[])
        tl[0]["event"] = "forged"
        self.assertEqual(m.postmortem("INC-1")["timeline"][0]["event"],
                         "real")

    def test_replay_durable(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t", severity="critical")
        m.assign_role("INC-1", "commander", "alice")
        m2 = inc.IncidentManager(journal_path=m.journal_path,
                                 finding_status=_closed)
        self.assertEqual(m2.state("INC-1"), "open")
        self.assertEqual(m2.roles("INC-1"), {"commander": "alice"})
        self.assertEqual(m2.summary("INC-1")["severity"], "critical")

    def test_summary_deterministic(self):
        m = _mgr(finding_status=_closed)
        m.declare_incident("INC-1", title="t")
        self.assertEqual(m.summary_canonical("INC-1"),
                         m.summary_canonical("INC-1"))

    def test_unknown_incident(self):
        m = _mgr()
        with self.assertRaises(inc.IncidentError) as cm:
            m.state("INC-NOPE")
        self.assertEqual(cm.exception.code, "incident-unknown")

    def test_codes_in_taxonomy(self):
        for code in ("incident-illegal-transition", "incident-malformed",
                     "incident-open-findings", "incident-open-tasks",
                     "incident-premature-postmortem", "incident-unknown"):
            entry = dc.TAXONOMY[code]
            self.assertEqual(entry["domain"], "incident")
            self.assertEqual(entry["code"], code)
            dc.code_for(code)
        self.assertEqual(len(dc.TAXONOMY), 1743)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete)


if __name__ == "__main__":
    unittest.main()
