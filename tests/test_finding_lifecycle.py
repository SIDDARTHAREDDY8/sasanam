"""Unit tests for gov/finding_lifecycle.py (wave-283 lane 5, DefectDojo ADAPT).

Stdlib only. No wall-clock assertions (waves are explicit integers).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import finding_lifecycle as fl


SHAPE = {
    "title": "shield-run evidence echoes credential-shaped shield details",
    "seam": "shield_registry._run_shields -> guardrail_evidence.run_guardrail",
    "attack_shape": "DLP shield quoting the offending argument lands the "
                    "credential in the record rationale",
    "close_when": "sanitize the shield detail at the run_guardrail emit "
                  "site; f309-shield-detail-echo flips to HELD",
}

EV = {"battery": "evals/w283_defectdojo_probes.py",
      "probes": ["p-identity-convergence"], "commit": "ad222ce",
      "wave": 283, "actor": "lane-5"}


class IdentityTest(unittest.TestCase):
    def test_deterministic_and_64hex(self):
        h1 = fl.finding_identity(**SHAPE)
        h2 = fl.finding_identity(**SHAPE)
        self.assertEqual(h1, h2)
        self.assertRegex(h1, r"^[0-9a-f]{64}$")

    def test_whitespace_canonicalized(self):
        noisy = {k: "\n  %s\t " % v for k, v in SHAPE.items()}
        self.assertEqual(fl.finding_identity(**SHAPE),
                         fl.finding_identity(**noisy))

    def test_distinct_shapes_diverge(self):
        other = dict(SHAPE, attack_shape="different")
        self.assertNotEqual(fl.finding_identity(**SHAPE),
                            fl.finding_identity(**other))

    def test_unknown_field_refused(self):
        with self.assertRaises(fl.FindingLifecycleError) as cm:
            fl.finding_identity(fields=("bogus",), **SHAPE)
        self.assertEqual(cm.exception.code, "finding-illegal-transition")


class StateMachineTest(unittest.TestCase):
    def _open(self, wave=283):
        reg = fl.FindingRegistry(next_number=312)
        num, kind = reg.file_finding(severity="low", reporter="red-team",
                                    wave=wave, **SHAPE)
        self.assertEqual((num, kind), ("F312", "filed"))
        return reg, num

    def test_new_finding_opens(self):
        reg, num = self._open()
        self.assertEqual(reg.get(num).state, "open")

    def test_close_requires_red_first_evidence(self):
        reg, num = self._open()
        with self.assertRaises(fl.FindingLifecycleError) as cm:
            reg.transition(num, "verified", wave=283, actor="x",
                           evidence={"note": "trust me"})
        self.assertEqual(cm.exception.code, "finding-illegal-transition")

    def test_close_with_evidence_carries_it(self):
        reg, num = self._open()
        reg.transition(num, "under_review", wave=283, actor="triager",
                       evidence={"note": "reviewing"})
        reg.transition(num, "verified", wave=283, actor="merge-coord",
                       evidence=EV)
        f = reg.get(num)
        self.assertEqual(f.state, "verified")
        self.assertEqual(f.transitions[-1].evidence["commit"], "ad222ce")

    def test_terminal_states_refuse_reopen(self):
        reg, num = self._open()
        reg.transition(num, "under_review", wave=283, actor="triager",
                       evidence={"note": "n"})
        reg.transition(num, "verified", wave=283, actor="merge-coord",
                       evidence=EV)
        with self.assertRaises(fl.FindingLifecycleError):
            reg.transition(num, "open", wave=284, actor="x",
                           evidence={"note": "n"})

    def test_under_review_can_return_to_open(self):
        reg, num = self._open()
        reg.transition(num, "under_review", wave=283, actor="triager",
                       evidence={"note": "n"})
        reg.transition(num, "open", wave=284, actor="triager",
                       evidence={"note": "needs more evidence"})
        self.assertEqual(reg.get(num).state, "open")

    def test_false_positive_needs_triage_note(self):
        reg, num = self._open()
        with self.assertRaises(fl.FindingLifecycleError):
            reg.transition(num, "false_positive", wave=283, actor="triager",
                           evidence={})
        reg.transition(num, "false_positive", wave=283, actor="triager",
                       evidence={"note": "not exploitable: deployment-owned"})
        self.assertEqual(reg.get(num).state, "false_positive")

    def test_duplicate_transition_requires_link(self):
        reg, num = self._open()
        reg.transition(num, "under_review", wave=283, actor="triager",
                       evidence={"note": "n"})
        with self.assertRaises(fl.FindingLifecycleError) as cm:
            reg.transition(num, "duplicate", wave=283, actor="merge-coord",
                           evidence={"note": "no link"})
        self.assertEqual(cm.exception.code, "finding-illegal-transition")
        reg.transition(num, "duplicate", wave=283, actor="merge-coord",
                       evidence={"note": "same shape", "duplicate_of": "F310"})
        f = reg.get(num)
        self.assertEqual(f.state, "duplicate")
        self.assertEqual(f.duplicate_of, "F310")


class SlaTest(unittest.TestCase):
    def test_low_three_waves(self):
        reg = fl.FindingRegistry(next_number=312)
        num, _ = reg.file_finding(severity="low", reporter="r", wave=282,
                                 **SHAPE)
        f = reg.get(num)
        self.assertEqual(reg.check_sla(f, 284), "ok")
        self.assertEqual(reg.check_sla(f, 285), "due")
        with self.assertRaises(fl.FindingSlaBreached) as cm:
            reg.check_sla(f, 286)
        self.assertEqual(cm.exception.code, "finding-sla-breached")

    def test_high_one_wave(self):
        reg = fl.FindingRegistry(next_number=312)
        num, _ = reg.file_finding(severity="high", reporter="r", wave=282,
                                 title="h", seam="s", attack_shape="a",
                                 close_when="c")
        with self.assertRaises(fl.FindingSlaBreached):
            reg.check_sla(reg.get(num), 284)

    def test_risk_accepted_excluded(self):
        reg = fl.FindingRegistry(next_number=312)
        num, _ = reg.file_finding(severity="high", reporter="r", wave=280,
                                 title="r", seam="s", attack_shape="a",
                                 close_when="c")
        reg.transition(num, "under_review", wave=280, actor="t",
                       evidence={"note": "n"})
        reg.transition(num, "risk_accepted", wave=280, actor="owner",
                       evidence={"note": "residual documented",
                                 "expires_wave": 290})
        self.assertEqual(reg.check_sla(reg.get(num), 300), "excluded")
        self.assertNotIn(num, [f.number for f in reg.metric_findings()])

    def test_sla_due_wave_arithmetic(self):
        reg = fl.FindingRegistry(next_number=312)
        num, _ = reg.file_finding(severity="medium", reporter="r", wave=282,
                                 title="m", seam="s", attack_shape="a",
                                 close_when="c")
        self.assertEqual(reg.sla_due_wave(reg.get(num)), 284)

    def test_unknown_opened_wave_is_loud(self):
        reg = fl.FindingRegistry(next_number=312)
        num, _ = reg.file_finding(severity="low", reporter="r", wave=283,
                                 title="u", seam="s", attack_shape="a",
                                 close_when="c")
        f = reg.get(num)
        f.opened_wave = None
        self.assertEqual(reg.check_sla(f, 300), "unknown")
        self.assertIsNone(reg.sla_due_wave(f))

    def test_sweep_sla_names_every_breach(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, _ = reg.file_finding(severity="low", reporter="r", wave=282,
                                title="a", seam="s", attack_shape="a",
                                close_when="c")
        n2, _ = reg.file_finding(severity="high", reporter="r", wave=282,
                                title="b", seam="s", attack_shape="a",
                                close_when="c")
        # Nothing breached yet at wave 283.
        self.assertEqual(reg.sweep_sla(283), [])
        with self.assertRaises(fl.FindingSlaBreached) as cm:
            reg.sweep_sla(300)
        self.assertIn(n1, str(cm.exception))
        self.assertIn(n2, str(cm.exception))
        self.assertEqual(cm.exception.code, "finding-sla-breached")


class DedupTest(unittest.TestCase):
    def test_parallel_filings_converge(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, k1 = reg.file_finding(severity="low", reporter="red-team",
                                 wave=283, **SHAPE)
        n2, k2 = reg.file_finding(severity="low", reporter="lane-9",
                                 wave=283, **SHAPE)
        self.assertEqual((n1, k1), ("F312", "filed"))
        self.assertEqual((n2, k2), ("F312", "duplicate"))
        # No new F-number consumed; next filing still gets F313.
        n3, _ = reg.file_finding(severity="low", reporter="r", wave=283,
                                title="other", seam="s", attack_shape="a",
                                close_when="c")
        self.assertEqual(n3, "F313")
        # Provenance of the parallel filing is retained.
        self.assertEqual(len(reg.get(n1).filings), 2)

    def test_identity_lookup(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, _ = reg.file_finding(severity="low", reporter="r", wave=283,
                                **SHAPE)
        ident = fl.finding_identity(fields=reg.default_fields, **SHAPE)
        self.assertEqual(reg.lookup_identity(ident), n1)
        self.assertIsNone(reg.lookup_identity("0" * 64))


class SweepTest(unittest.TestCase):
    def test_close_old_findings_mitigates_with_evidence(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, _ = reg.file_finding(severity="low", reporter="r", wave=282,
                                **SHAPE)
        n2, _ = reg.file_finding(severity="medium", reporter="r", wave=282,
                                title="h", seam="s2", attack_shape="a2",
                                close_when="c2")
        reg.transition(n2, "under_review", wave=283, actor="human",
                       evidence={"note": "investigating a variant"})
        scan = {
            n1: {"reproduced": False, "battery": "evals/b.py",
                 "probes": ["p1"], "commit": "abc"},
            n2: {"reproduced": False, "battery": "evals/b.py",
                 "probes": ["p2"], "commit": "abc"},
        }
        closed = reg.close_old_findings(scan, wave=283, actor="merge-coord")
        self.assertEqual(closed, [n1])
        f1 = reg.get(n1)
        self.assertEqual(f1.state, "mitigated")
        self.assertEqual(f1.transitions[-1].evidence["battery"], "evals/b.py")
        # Human triage never overridden.
        self.assertEqual(reg.get(n2).state, "under_review")
        self.assertEqual(len(reg.get(n2).scan_notes), 1)

    def test_reproduced_stays_open_with_note(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, _ = reg.file_finding(severity="low", reporter="r", wave=282,
                                **SHAPE)
        scan = {n1: {"reproduced": True, "battery": "evals/b.py",
                     "probes": ["p1"], "commit": "abc"}}
        self.assertEqual(reg.close_old_findings(scan, wave=283,
                                               actor="x"), [])
        self.assertEqual(reg.get(n1).state, "open")
        self.assertEqual(len(reg.get(n1).scan_notes), 1)


class PersistenceTest(unittest.TestCase):
    def test_json_round_trip(self):
        reg = fl.FindingRegistry(next_number=312)
        n1, _ = reg.file_finding(severity="low", reporter="r", wave=283,
                                **SHAPE)
        reg.transition(n1, "under_review", wave=283, actor="t",
                       evidence={"note": "n"})
        reg2 = fl.FindingRegistry.from_json(reg.to_json())
        f = reg2.get(n1)
        self.assertEqual(f.state, "under_review")
        self.assertEqual(len(f.transitions), 1)
        self.assertEqual(reg2.next_number, 313)
        n2, _ = reg2.file_finding(severity="low", reporter="r", wave=283,
                                 **SHAPE)
        self.assertEqual((n2), "F312")  # duplicate, not a new number


class FindingsMdTest(unittest.TestCase):
    PATH = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "evals", "FINDINGS.md")

    def test_parses_current_findings(self):
        reg = fl.load_findings_md(self.PATH)
        # F311 closed at the wave-283 merge; F312-F315 closed at the
        # wave-284 merge (lane 1); F316-F324 filed OPEN by the wave-284
        # independent red team, closed at the wave-285 merge (lanes 1-4);
        # F325-F330 filed OPEN by the wave-285 independent red team.
        self.assertEqual(reg.get("F311").state, "verified")
        for num in ("F312", "F313", "F314", "F315", "F316", "F317",
                    "F318", "F319", "F320", "F321", "F322", "F323",
                    "F324"):
            self.assertEqual(reg.get(num).state, "verified")
        for num in ("F325", "F326", "F327", "F328", "F329", "F330"):
            self.assertEqual(reg.get(num).state, "open")
        self.assertEqual(reg.get("F310").state, "verified")
        self.assertEqual(reg.get("F309").state, "verified")
        self.assertGreaterEqual(len(reg.all()), 200)

    def test_legacy_headers_parse(self):
        reg = fl.load_findings_md(self.PATH)
        self.assertIsNotNone(reg.get("F94"))
        self.assertIsNotNone(reg.get("F1"))


if __name__ == "__main__":
    unittest.main()
