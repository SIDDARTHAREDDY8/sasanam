"""Break-first battery: English double-negation resolution (wave-146, row 7).

Row 7's remaining miss: a positively-resolved English double negation
("There is no reason not to send the Q3 report to the vendor.", cue
'no', raw similarity 0.800) reads as a countermand and revokes the
grant. Two negation cues in a bounded same-sentence construction that
cancel into affirmation must NOT revoke; single negation and stacked
emphasis must still revoke (conservative: ambiguous stacking revokes).

The seam: ``similarity_countermand`` (gov/intent_ledger.py) suppresses
its negation gate when ``_english_double_negation_cancels`` (new in
gov/intent_slice.py) positively resolves the message. English only;
other-language double negation is unchanged.

Probe verdicts:
  d1_pinned_double_negation_resolved: the pinned sentence no longer
     revokes (similarity measured, asserted not fired). BREAK
     pre-seam (it revokes).
  d2_single_negation_still_revokes: "Do not send the Q3 report to the
     vendor." still revokes. BREAK if it stops.
  d3_stacked_emphasis_still_revokes: "Never, under no circumstances,
     send the Q3 report to the vendor." still revokes (two cues, one
     predicate -- emphasis, not cancellation). BREAK if it stops.
  d4_other_double_negations_resolve: "I don't disagree with sending
     ..." / "It is not uncommon to send ..." no longer revoke.
     BREAK pre-seam.
  d5_dis_prefix_trap_still_revokes: "Don't distribute the Q3 report
     to the vendor." still revokes -- the resolver uses a closed
     negative-polarity word list, not productive dis-/un- prefix
     matching, so "distribute" must not suppress. BREAK if it stops.
  d6_split_infinitive_resolves: "There is no reason to not send ..."
     (split infinitive) resolves like d1. BREAK pre-seam.
  d7_ambiguous_stacking_revokes: "I don't think we should not send
     ..." still revokes -- ambiguous stacking resolves conservative
     (revoke). BREAK if it stops.
  d8_non_english_double_negation_unchanged: a German double negation
     still revokes (the resolver is English-only). BREAK if it stops.
  d9_deterministic_x2: d1/d2/d3 verdicts byte-identical across two
     runs.

Conventions: explicit threshold=0.5 (the cue/resolver set is under
test, not the wave-138 derived calibration; a pin on a sentence with
raw similarity inside the derived [0.4, 0.6) band would be flaky
through record_intent -- wave-145 lesson). Deterministic: fixed
sentences, no RNG. Standalone: module-level staging mode; verify
under ``env -u GOV_DEPLOYMENT_MODE``.

$0, stdlib-only.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov.intent_ledger import similarity_countermand
from gov.target_match import target_similarity

GRANT = "Send the Q3 report to the vendor."
THRESHOLD = 0.5  # explicit: the resolver is under test, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-36s %-10s %s" % (name, verdict, detail))


def _check(sentence):
    """(fired, raw_similarity) at the similarity_countermand seam."""
    sim = target_similarity(sentence, GRANT)
    fired, _, _ = similarity_countermand(sentence, [GRANT],
                                         threshold=THRESHOLD)
    return fired, sim


def _need_seam(name):
    """Pre-seam, the resolver is absent: every probe documents the
    red state instead of erroring."""
    import gov.intent_slice as _s
    if not hasattr(_s, "_english_double_negation_cancels"):
        _record(name, "BREAK",
                "resolver seam absent (pre-implementation red state)")
        return False
    return True


def d1_pinned_double_negation_resolved():
    name = "d1_pinned_double_negation_resolved"
    if not _need_seam(name):
        return
    sent = ("There is no reason not to send the Q3 report "
            "to the vendor.")
    fired, sim = _check(sent)
    if fired:
        _record(name, "BREAK",
                "pinned double negation still revokes (sim %.3f)" % sim)
        return
    _record(name, "HELD",
            "pinned sentence no longer revokes (sim %.3f >= %.1f "
            "gate, cue suppressed by double-negation resolution)"
            % (sim, THRESHOLD))


def d2_single_negation_still_revokes():
    name = "d2_single_negation_still_revokes"
    if not _need_seam(name):
        return
    sent = "Do not send the Q3 report to the vendor."
    fired, sim = _check(sent)
    if not fired:
        _record(name, "BREAK",
                "single negation stopped revoking (sim %.3f)" % sim)
        return
    _record(name, "HELD",
            "single negation still revokes (sim %.3f)" % sim)


def d3_stacked_emphasis_still_revokes():
    name = "d3_stacked_emphasis_still_revokes"
    if not _need_seam(name):
        return
    sent = ("Never, under no circumstances, send the Q3 report "
            "to the vendor.")
    fired, sim = _check(sent)
    if not fired:
        _record(name, "BREAK",
                "stacked emphasis stopped revoking (sim %.3f)" % sim)
        return
    _record(name, "HELD",
            "stacked emphasis (never + no, one predicate) still "
            "revokes (sim %.3f)" % sim)


def d4_other_double_negations_resolve():
    name = "d4_other_double_negations_resolve"
    if not _need_seam(name):
        return
    bad = []
    for sent in ("I don't disagree with sending the Q3 report "
                 "to the vendor.",
                 "It is not uncommon to send the Q3 report "
                 "to the vendor."):
        fired, sim = _check(sent)
        if fired:
            bad.append("%r (sim %.3f)" % (sent, sim))
    if bad:
        _record(name, "BREAK",
                "double negation still revokes: %s" % "; ".join(bad))
        return
    _record(name, "HELD",
            "don't disagree / not uncommon resolve affirmative "
            "(2/2 quiet)")


def d5_dis_prefix_trap_still_revokes():
    name = "d5_dis_prefix_trap_still_revokes"
    if not _need_seam(name):
        return
    sent = "Don't distribute the Q3 report to the vendor."
    fired, sim = _check(sent)
    if not fired:
        _record(name, "BREAK",
                "dis- prefix trap suppressed a genuine countermand "
                "(sim %.3f) -- the resolver must use a closed word "
                "list, not productive prefix matching" % sim)
        return
    _record(name, "HELD",
            "\"Don't distribute\" still revokes (sim %.3f; "
            "distribute not in the negative-polarity list)" % sim)


def d6_split_infinitive_resolves():
    name = "d6_split_infinitive_resolves"
    if not _need_seam(name):
        return
    sent = ("There is no reason to not send the Q3 report "
            "to the vendor.")
    fired, sim = _check(sent)
    if fired:
        _record(name, "BREAK",
                "split-infinitive double negation still revokes "
                "(sim %.3f)" % sim)
        return
    _record(name, "HELD",
            "\"no reason to not send\" resolves like d1 (sim %.3f)"
            % sim)


def d7_ambiguous_stacking_revokes():
    name = "d7_ambiguous_stacking_revokes"
    if not _need_seam(name):
        return
    sent = ("I don't think we should not send the Q3 report "
            "to the vendor.")
    fired, sim = _check(sent)
    if not fired:
        _record(name, "BREAK",
                "ambiguous stacking stopped revoking (sim %.3f) -- "
                "ambiguous double negation must resolve conservative "
                "(revoke)" % sim)
        return
    _record(name, "HELD",
            "ambiguous \"don't think ... not send\" still revokes "
            "(sim %.3f; conservative)" % sim)


def d8_non_english_double_negation_unchanged():
    name = "d8_non_english_double_negation_unchanged"
    if not _need_seam(name):
        return
    import gov.intent_slice as _s
    # German double negation: the resolver is English-only, so the
    # helper must not claim it -- and the gate must still fire.
    de = ("Senden Sie den Q3-Bericht nicht an den Haendler; es ist "
          "nicht unmoeglich, dass er ihn braucht.")
    if _s._english_double_negation_cancels(de):
        _record(name, "BREAK",
                "resolver fired on German -- English-only contract "
                "violated")
        return
    grant_de = "Senden Sie den Q3-Bericht an den Haendler."
    fired, _, _ = similarity_countermand(de, [grant_de],
                                        threshold=THRESHOLD)
    if not fired:
        _record(name, "BREAK",
                "German double negation stopped revoking -- "
                "non-English behavior must stay as-is")
        return
    _record(name, "HELD",
            "German double negation still revokes (resolver "
            "English-only)")


def d9_deterministic_x2():
    name = "d9_deterministic_x2"
    if not _need_seam(name):
        return
    sents = ("There is no reason not to send the Q3 report "
             "to the vendor.",
             "Do not send the Q3 report to the vendor.",
             "Never, under no circumstances, send the Q3 report "
             "to the vendor.")
    run1 = [_check(s) for s in sents]
    run2 = [_check(s) for s in sents]
    if run1 != run2:
        _record(name, "BREAK",
                "non-deterministic verdicts across two runs")
        return
    _record(name, "HELD",
            "d1/d2/d3 verdicts byte-identical across 2 runs %r"
            % ([f for f, _ in run1],))


def main():
    print("double_negation_probes (wave-146, row 7):")
    for fn in (d1_pinned_double_negation_resolved,
               d2_single_negation_still_revokes,
               d3_stacked_emphasis_still_revokes,
               d4_other_double_negations_resolve,
               d5_dis_prefix_trap_still_revokes,
               d6_split_infinitive_resolves,
               d7_ambiguous_stacking_revokes,
               d8_non_english_double_negation_unchanged,
               d9_deterministic_x2):
        fn()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("double_negation_probes: %d HELD / %d BREAK / %d EXPECTED / "
          "%d ERROR" % (held, brk, exp, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
