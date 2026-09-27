"""Wave-147, row 7: scope-window discipline for negation (RED-first).

A negation cue only cancels an intent when it falls within a bounded
token window (+-8) of the intent's action verb, measured against the
anchor clause; a cue scoping over the wrong predicate in a separate
clause does NOT revoke. Clause-aware first (a whole-message distance
check is insufficient: in "Der Q3 report ist keineswegs fertig; bitte
senden Sie ihn an den vendor." the cue and the grant verb are only a
few tokens apart but live in different clauses), then window-bounded
around the anchor's action verb.

RED pre-seam: probes 1/3/4 fire (the cue is found and the similarity
is at/above gate) and BREAK; they go silent post-fix. Probes 2/5 pin
the genuine controls that must keep revoking.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import _NEGATION_RE  # noqa: E402

GRANT_EN = "Send the Q3 report to the vendor."
GRANT_DE = "Senden Sie den Q3-Bericht an den Vendor."
GRANT_ARCHIVE = "Archive the Q3 report."
THRESHOLD = 0.5  # explicit: the scope is under test, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _need_seam(name):
    if similarity_countermand is None:
        _record(name, "ERROR", "similarity_countermand seam missing")
        return False
    return True


def _silent_probe(name, sentence, grants, why):
    """The cue must NOT revoke: expect silence at the seam."""
    if not _need_seam(name):
        return
    fired, _, score = similarity_countermand(
        sentence, grants, threshold=THRESHOLD)
    cue = _NEGATION_RE.search(sentence)
    if fired:
        _record(name, "BREAK",
                "false revocation (cue %r, sim %.3f): %r -- %s"
                % (cue.group(0) if cue else None, score, sentence, why))
        return
    _record(name, "HELD",
            "silent (cue %r, sim %.3f): %s"
            % (cue.group(0) if cue else None, score, why))


def _revoke_probe(name, sentence, grants, why):
    """A genuine cue on the grant verb must still revoke."""
    if not _need_seam(name):
        return
    fired, _, score = similarity_countermand(
        sentence, grants, threshold=THRESHOLD)
    cue = _NEGATION_RE.search(sentence)
    if not fired:
        _record(name, "BREAK",
                "genuine countermand stopped revoking (cue %r, sim %.3f): "
                "%r -- %s" % (cue.group(0) if cue else None, score,
                              sentence, why))
        return
    _record(name, "HELD",
            "revoked (cue %r, sim %.3f): %s"
            % (cue.group(0) if cue else None, score, why))


def scope_de_wrong_predicate_silent():
    # (a) German wrong-predicate negation: keineswegs scopes over
    # "fertig" in clause 1; the grant verb "senden" is re-affirmed in
    # clause 2. Must NOT revoke.
    _silent_probe(
        "scope_de_wrong_predicate_silent",
        "Der Q3 report ist keineswegs fertig; bitte senden Sie ihn "
        "an den vendor.",
        [GRANT_DE],
        "keineswegs scopes the wrong predicate, send re-affirmed")


def scope_en_direct_revoke():
    # (b) the canonical direct countermand keeps revoking.
    _revoke_probe(
        "scope_en_direct_revoke",
        "Don't send the Q3 report.",
        [GRANT_EN],
        "cue adjacent to the grant verb")


def scope_en_wrong_predicate_silent():
    # (c) "not ready" scopes over the report's state in a separate
    # sentence; the archive grant stands.
    _silent_probe(
        "scope_en_wrong_predicate_silent",
        "Please archive the Q3 report. It is not ready.",
        [GRANT_ARCHIVE],
        "'not' scopes 'ready', not the archive verb")


def scope_fr_wrong_predicate_silent():
    # (d) French equivalent: "n'est pas" scopes "en retard"; the
    # grant verb "envoyez" is re-affirmed in clause 2.
    _silent_probe(
        "scope_fr_wrong_predicate_silent",
        "Le Q3 report n'est pas en retard; envoyez-le au vendor.",
        [GRANT_EN],
        "negation scopes the wrong predicate, send re-affirmed")


def scope_window_boundary_revokes():
    # A genuine cue far from the verb but within the +-8 window and
    # in the same clause still revokes (window generosity pin).
    _revoke_probe(
        "scope_window_boundary_revokes",
        "Never, under any circumstances whatsoever, send the Q3 "
        "report to the vendor.",
        [GRANT_EN],
        "cue 6 tokens from the grant verb, same clause")


def existing_batteries_no_regression():
    # (e) the inflection and precision batteries stay green after
    # their pinned scope-FPs graduate to resolved silence.
    name = "existing_batteries_no_regression"
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))

    def _load(modname, fname):
        spec = importlib.util.spec_from_file_location(
            modname, os.path.join(here, fname))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    bad = []
    for modname, fname in (
            ("_neg_scope_infl", "countermand_negation_inflection_probes.py"),
            ("_neg_scope_prec", "negation_precision_probes.py")):
        try:
            mod = _load(modname, fname)
            results = mod._run_all()
        except Exception as exc:  # noqa: BLE001 - battery must report
            bad.append("%s raised %r" % (fname, exc))
            continue
        for pname, verdict, detail in results:
            if verdict in ("BREAK", "ERROR"):
                bad.append("%s/%s: %s (%s)" % (fname, pname, verdict,
                                               detail))
    if bad:
        _record(name, "BREAK", "regression: %s" % "; ".join(bad))
        return
    _record(name, "HELD",
            "inflection + precision batteries green (0 BREAK/ERROR)")


def _run_all():
    global _RESULTS
    _RESULTS = []
    scope_de_wrong_predicate_silent()
    scope_en_direct_revoke()
    scope_en_wrong_predicate_silent()
    scope_fr_wrong_predicate_silent()
    scope_window_boundary_revokes()
    existing_batteries_no_regression()
    return list(_RESULTS)


def deterministic_x2():
    name = "deterministic_x2"
    first = [(n, v) for n, v, _ in _run_all()]
    second = [(n, v) for n, v, _ in _run_all()]
    # _run_all() repopulates _RESULTS with the second run; the record
    # below appends the determinism verdict after it.
    if first != second:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (first, second))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(first))


def main():
    _run_all()
    deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("negation_scope_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
