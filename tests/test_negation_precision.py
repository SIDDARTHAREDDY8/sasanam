"""Wave-145 negation precision guards (row-7 lane 2).

Pins the positional precision guards added to
``gov.intent_slice._NEGATION_RE`` after the 47-sentence benign
corpus in ``evals/negation_precision_probes.py`` measured 6 genuine
false positives (every corpus sentence scores >= gate similarity,
so each suppressed hit was a REAL false revocation):

  - "no"/"kein"/"keine" stay silent in the affirmative idiom
    "no problem" / "kein Problem" / "keine Probleme";
  - "not" stays silent in the correlative "not only ... (but also)";
  - "pas" stays silent in the French tag question "n'est-ce pas"
    and as the noun "un pas" ("a step").

Each guard is positional, never blanket: the companion tests pin
that genuine cues in the same words still fire. The 4 remaining FPs
(double negation, scope imprecision) are pinned EXPECTED -- the
last test asserts they still fire so the pin cannot rot.
"""

import unittest

from gov import intent_slice as m
from gov.intent_ledger import similarity_countermand

GRANT = "Send the Q3 report to the vendor."


class PrecisionGuardTest(unittest.TestCase):
    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0).lower() if hit else None

    def test_no_problem_idiom_silent(self):
        # Affirmative idiom: "no problem" never countermands.
        self.assertIsNone(
            self._cue("No problem -- please send the Q3 report."))
        self.assertIsNone(
            self._cue("Kein Problem, bitte senden Sie den Q3 report."))
        self.assertIsNone(
            self._cue("Senden Sie ihn; das ist kein Problem."))
        self.assertIsNone(
            self._cue("Keine Probleme, bitte senden."))

    def test_no_kein_genuine_cues_still_fire(self):
        # The idiom guard is positional: a real "no"/"kein" still
        # cues, and "don't" fires past the guard in the same
        # sentence.
        self.assertEqual(self._cue("There is no Q3 report."), "no")
        self.assertEqual(self._cue("No enviar el informe."), "no")
        self.assertEqual(self._cue("Kein Bericht."), "kein")
        self.assertEqual(self._cue("Keine E-Mail."), "keine")
        self.assertEqual(
            self._cue("No problem, don't send it."), "don't")

    def test_not_only_correlative_silent(self):
        # "Not only X, but also Y" extends the grant -- not a
        # countermand.
        self.assertIsNone(
            self._cue("Not only send the Q3 report, but also archive "
                      "a copy."))

    def test_not_genuine_cue_still_fires(self):
        # ("do not" wins over "not" by alternation order --
        # pre-existing behavior, unchanged by the guard.)
        self.assertEqual(self._cue("Do not send it."), "do not")
        self.assertEqual(
            self._cue("Please do not send the Q3 report."), "do not")

    def test_n_est_ce_pas_tag_question_silent(self):
        # A tag question seeks confirmation; it never countermands.
        self.assertIsNone(
            self._cue("Envoyez le Q3 report au vendor, n'est-ce pas?"))

    def test_n_est_pas_genuine_cue_still_fires(self):
        # The tag guard is positional: plain "n'est pas" and
        # "ne ... pas" still cue.
        self.assertEqual(
            self._cue("Le Q3 report n'est pas pour le vendor."), "pas")
        self.assertEqual(
            self._cue("N'envoyez pas le Q3 report au vendor."), "pas")

    def test_un_pas_noun_silent(self):
        # "un pas" = "a step": "pas" is a noun, not a negation.
        self.assertIsNone(
            self._cue("Envoyez le rapport; faites un pas a la fois."))

    def test_lookalike_substrings_silent(self):
        # Word-boundary discipline across the full cue set.
        for text in (
                "The vendor noticed the Q3 report.",
                "Notable progress on the Q3 report.",
                "Another copy for the vendor.",
                "The knowledge base links the Q3 report.",
                "The notebook went to the vendor.",
                "Nothing beats this vendor.",
                "Nehmen Sie den Q3 report.",
                "Der Q3 report ist neulich eingetroffen.",
                "Neben dem Q3 report liegt die Rechnung.",
                "Nichts Besonderes.",
                "Nichtsdestotrotz senden.",
                "Le montant net du Q3 report.",
                "Neanmoins, envoyez le Q3 report.",
                "Un Q3 report neutre."):
            self.assertIsNone(self._cue(text), text)

    def test_unpaired_french_particles_silent(self):
        # Pairing discipline: the particle without "ne" stays silent.
        self.assertIsNone(
            self._cue("Le Q3 report partira sans aucun retard."))
        self.assertIsNone(
            self._cue("Il y a de plus en plus de reports."))
        self.assertIsNone(
            self._cue("Merci pour le Q3 report; rien d'autre."))

    def test_pinned_fps_still_fire_at_gate(self):
        # Honest EXPECTED pins (see
        # evals/negation_precision_probes.py::PINNED_FPS): these
        # benign sentences trip the gate -- double negation and
        # negation scoping over the wrong predicate, which the
        # seeded word-list approach cannot resolve. Pinned here too
        # so the pin cannot silently rot at the unit level.
        for sent in (
                "There is no reason not to send the Q3 report to "
                "the vendor.",
                "Le Q3 report n'est pas en retard; envoyez-le au "
                "vendor.",
                "Der Q3 report ist keineswegs fertig; bitte senden "
                "Sie ihn an den vendor.",
                "Es gibt keinerlei Probleme; senden Sie den Q3 "
                "report an den vendor."):
            fired, _, score = similarity_countermand(
                sent, [GRANT], threshold=0.5)
            self.assertTrue(fired, sent)
            self.assertGreaterEqual(score, 0.5, sent)


if __name__ == "__main__":
    unittest.main()
