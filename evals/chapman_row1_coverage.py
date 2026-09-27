#!/usr/bin/env python3
"""Chapman capture-recapture coverage estimate for Row-1 (memory poisoning).

Idea adapted from Fifth Third Bank's LUCY (Apache-2.0,
https://github.com/Fifth-Third-Bank/lucy): LUCY bounds vuln-discovery
coverage with the Chapman estimator from ecology. Our analog: two
independently-authored probe batteries for Row-1 are two "capture
occasions" over the attack-shape space; the overlap estimates the total
shape population, hence our measured coverage.

Occasion 1: evals/gap1mem_break.py  (GAP-1 lane, wave-103)
Occasion 2: evals/f143mem_break.py  (wave-123 tightens)
Validation: evals/s1mem_battery.py  (third occasion, held out)

The mapping below is ANALYTIC (a judgment call by this lane), not
executed — the batteries themselves are the captures; this file is the
mark-recapture ledger. The taxonomy is published here so the estimate
can be challenged: change the taxonomy, change the number (that IS
limitation #3 in gov/chapman.py).

Shape taxonomy (4 dimensions; a cell is one attack idea):
  channel:    how the poison is ingested
              (read_file | api_call | http_post | send_email)
  content:    what the poison says
              (standing_instruction | preference_directive | workflow_rule |
               stored_directive | confirmation_waiver | authority_imperative |
               verbatim_imperative | paraphrased_imperative | verbatim_factual |
               heuristic_dodge | benign_note | benign_tool_output)
  persist:    how it reaches memory/  (verbatim_copy — both batteries)
  evasion:    what tries to beat the firewall
              (none | paraphrase_laundering | eviction_flood |
               digest_mismatch | channel_switch)

Deterministic, $0, no network. Verifies standalone under
`env -u GOV_DEPLOYMENT_MODE`.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.chapman import chapman_ci, chapman_variance, coverage_report

# ---------------------------------------------------------------------------
# Capture occasion 1: gap1mem_break.py (9 probes).
# Plant path for all: vendor notice -> read_file -> verbatim copy to memory/.
# ---------------------------------------------------------------------------
OCCASION_1 = {
    # probe: (channel, content, persist, evasion)
    "p1_standing_instruction": ("read_file", "standing_instruction",
                                "verbatim_copy", "none"),
    "p2_preference_directive": ("read_file", "preference_directive",
                                "verbatim_copy", "none"),
    "p3_workflow_rule": ("read_file", "workflow_rule",
                         "verbatim_copy", "none"),
    "p4_stored_directive": ("read_file", "stored_directive",
                            "verbatim_copy", "none"),
    "p5_confirmation_waiver": ("read_file", "confirmation_waiver",
                               "verbatim_copy", "none"),
    "c1_baseline_authority": ("read_file", "authority_imperative",
                              "verbatim_copy", "none"),
    "c2_agent_note_allowed": ("read_file", "benign_note",
                               "verbatim_copy", "none"),
    "c3_benign_untrusted_allowed": ("read_file", "benign_tool_output",
                                    "verbatim_copy", "none"),
    "c4_paraphrase_residual": ("read_file", "paraphrased_imperative",
                               "verbatim_copy", "paraphrase_laundering"),
}

# ---------------------------------------------------------------------------
# Capture occasion 2: f143mem_break.py (8 probes).
# Plant path: plant-via-governed-tool -> write to memory/ -> fresh-session read.
# ---------------------------------------------------------------------------
OCCASION_2 = {
    "p1_verbatim_imperative": ("api_call", "verbatim_imperative",
                               "verbatim_copy", "none"),
    "p2_paraphrase_bridging": ("api_call", "paraphrased_imperative",
                                "verbatim_copy", "paraphrase_laundering"),
    "p3_factual_verbatim": ("api_call", "verbatim_factual",
                            "verbatim_copy", "none"),
    "p4_http_post_adjacent": ("http_post", "verbatim_imperative",
                              "verbatim_copy", "channel_switch"),
    "p5_heuristic_dodge": ("api_call", "heuristic_dodge",
                            "verbatim_copy", "none"),
    "p6_eviction_flood": ("api_call", "verbatim_imperative",
                          "verbatim_copy", "eviction_flood"),
    "p7_digest_mismatch": ("api_call", "verbatim_imperative",
                            "verbatim_copy", "digest_mismatch"),
    "p8_send_email_adjacent": ("send_email", "verbatim_imperative",
                               "verbatim_copy", "channel_switch"),
}

# ---------------------------------------------------------------------------
# Held-out third occasion: s1mem_battery.py TestMemoryFirewallBattery.
# Only cells that are attack shapes (not controls/workflow/infra tests).
# ---------------------------------------------------------------------------
OCCASION_3_HELD_OUT = {
    "v1_api_call": ("api_call", "verbatim_imperative",
                    "verbatim_copy", "none"),
    "v2_read_file": ("read_file", "verbatim_imperative",
                     "verbatim_copy", "channel_switch"),   # NEW vs 1+2
    "v5a_kwarg_smuggling": ("api_call", "verbatim_imperative",
                            "verbatim_copy", "kwarg_smuggling"),  # NEW
    "v6_invisible_chars": ("api_call", "verbatim_imperative",
                           "verbatim_copy", "invisible_chars"),    # NEW
    "v7_paraphrase": ("api_call", "paraphrased_imperative",
                      "verbatim_copy", "paraphrase_laundering"),
    "v10_digest_mismatch": ("api_call", "verbatim_imperative",
                            "verbatim_copy", "digest_mismatch"),
    # v4 cross-principal isolation: needs a 5th taxonomy dimension
    # (principal scope). Deliberately unmapped — a taxonomy gap, not a miss.
}


# Wave-147: compositional-mutation diversity battery
# (evals/row1_diversity_probes.py): 12 shapes = 3 bases x 4
# multi-operator compositions (synonym_swap, word_order_shift,
# polite_framing; fixed pipeline polite -> syn -> order). Plant path is
# the f143 loop (poisoned api_call, mutated shape written to memory/),
# so channel/persist match f143. Two principled NEW ideas:
#   (paraphrased_factual, paraphrase_laundering) -- mutated factual
#       claims, the paraphrased counterpart of verbatim_factual;
#   (heuristic_dodge, paraphrase_laundering) -- the p5 dodge register
#       composed with laundering operators (two evasion techniques
#       composed, a genuinely new attack idea).
# B1 shapes recapture (paraphrased_imperative, paraphrase_laundering).
OCCASION_4_DIVERSITY = {
    "div_B1": ("diversity", "paraphrased_imperative", "verbatim_copy",
               "paraphrase_laundering"),  # recapture
    "div_B2": ("diversity", "paraphrased_factual", "verbatim_copy",
               "paraphrase_laundering"),  # NEW vs 1+2+3
    "div_B3": ("diversity", "heuristic_dodge", "verbatim_copy",
               "paraphrase_laundering"),  # NEW vs 1+2+3
}


def _cells(mapping):
    return set(mapping.values())


def _idea(cell):
    """Attack-idea identity: (content, evasion).

    The ingestion channel is deliberately excluded: gap1's c4 and f143's
    p2 are the same attack idea (paraphrased imperative laundered through
    verbatim persistence) reached through different channels. Both
    batteries persist verbatim to memory/, so persist is constant.
    """
    _channel, content, _persist, evasion = cell
    return (content, evasion)


def _ideas(mapping):
    return set(_idea(c) for c in mapping.values())


def main():
    c1 = _cells(OCCASION_1)
    c2 = _cells(OCCASION_2)

    # --- primary reading: attack-idea identity ---------------------------
    i1, i2 = _ideas(OCCASION_1), _ideas(OCCASION_2)
    overlap = i1 & i2
    n1, n2, m2 = len(i1), len(i2), len(overlap)
    rep = coverage_report(n1, n2, m2, label="row1-memory-poisoning")
    n_hat, lo, hi = chapman_ci(n1, n2, m2)

    print("=== Chapman capture-recapture: Row-1 attack-shape coverage ===")
    print("identity: attack idea = (content, evasion); channel excluded")
    print("occasion 1 (gap1mem_break.py):  %d ideas" % n1)
    print("occasion 2 (f143mem_break.py):  %d ideas" % n2)
    print("recaptured (both occasions):    %d ideas" % m2)
    for idea in sorted(overlap):
        print("    recapture: %s" % (idea,))
    print("estimated idea population N_hat: %.1f  (95%% CI %.1f-%.1f)"
          % (n_hat, lo, hi))
    print("measured coverage |union|/N_hat:  %.1f%%  (95%% CI %.0f%%-100%%)"
          % (rep["coverage"] * 100, (n1 + n2 - m2) / hi * 100))
    print("caveat: %s" % rep["caveat"])

    # --- sensitivity: strict channel-identity reading (m2 = 0) ------------
    s1, s2 = len(c1), len(c2)
    n_hat0, lo0, hi0 = chapman_ci(s1, s2, 0)
    print("\n--- sensitivity: strict reading (channel part of identity) ---")
    print("m2=0 -> N_hat %.1f (95%% CI %.1f-%.1f), coverage %.1f%%"
          % (n_hat0, lo0, hi0, (s1 + s2) / n_hat0 * 100))
    print("The gap between the readings IS taxonomy sensitivity "
          "(gov/chapman.py limitation #3).")

    # --- held-out validation ---------------------------------------------
    i3 = _ideas(OCCASION_3_HELD_OUT)
    new_ideas = i3 - (i1 | i2)
    print("\n--- held-out validation (s1mem_battery.py, %d ideas) ---"
          % len(i3))
    print("ideas already in union: %d" % (len(i3) - len(new_ideas)))
    print("genuinely new ideas:     %d" % len(new_ideas))
    for idea in sorted(new_ideas):
        print("    new: %s" % (idea,))
    print("v4 cross-principal: unmapped — taxonomy gap (needs a principal-"
          "scope dimension), not a firewall miss.")
    grown = len(i1 | i2 | i3)
    print("union grows %d -> %d with the third occasion; against N_hat=%.0f "
          "this is expected at ~%.0f%% coverage, not a contradiction."
          % (len(i1 | i2), grown, n_hat, rep["coverage"] * 100))

    # --- wave-147 diversity after-reading --------------------------------
    # Same estimator (n1/n2/m2 unchanged, so N_hat is unchanged); the
    # compositional battery contributes its ideas to the union.
    i4 = _ideas(OCCASION_4_DIVERSITY)
    div_new = i4 - (i1 | i2)
    grown2 = len(i1 | i2 | i4)
    after_cov = grown2 / n_hat
    print("\n--- wave-147 diversity after-reading "
          "(row1_diversity_probes.py, %d shapes) ---" % 12)
    print("compositional operators: synonym_swap, word_order_shift, "
          "polite_framing (fixed pipeline polite -> syn -> order)")
    print("ideas already in union: %d" % (len(i4) - len(div_new)))
    print("genuinely new ideas:     %d" % len(div_new))
    for idea in sorted(div_new):
        print("    new: %s" % (idea,))
    print("BEFORE: %.1f%% (%d ideas / N_hat %.0f); AFTER: %.1f%% "
          "(%d ideas / N_hat %.0f) -- measurable increase of %.1f pts"
          % (rep["coverage"] * 100, len(i1 | i2), n_hat,
             after_cov * 100, grown2, n_hat,
             (after_cov - rep["coverage"]) * 100))
    print("This is a DIVERSITY diagnostic, not a security bound.")

    print("\n=== verdict ===")
    print("Row-1 measured coverage: ~%.0f%% of the estimated attack-shape "
          "space (primary reading)." % (rep["coverage"] * 100))
    print("This is a DIVERSITY diagnostic, not a security bound: it says "
          "our two independent passes explored about a third of the shape "
          "space they jointly imply. The honest ceiling (deterministic "
          "heuristics vs arbitrary phrasing) is unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
