"""Wave-148, row 7: verb-class tier 2 for scope windows (RED-first).

Residual from wave-147: the scope-window discipline
(``gov.intent_slice.negation_scopes_grant``) uses closed SEND /
ARCHIVE / DELETE verb classes. Verbs outside the classes -- REDACT,
SHARE, PUBLISH, FORWARD, UPLOAD -- have no scope discipline: an
anchor naming one of these verbs keeps the pre-wave-147
conservative behavior (any cue + similarity revokes), so a
wrong-predicate negation ("The report is not final; please publish
it to the portal") falsely revokes.

This battery measures the tier-2 extension: REDACT / SHARE /
PUBLISH / FORWARD / UPLOAD classes (EN plus DE/FR/ES/romanized-Hindi
forms, German separable verbs, accent-folded tokenization), each
under the same +-8 token scope window.

RED pre-seam: the tier-2 verbs are unknown to the class list, so
every wrong-predicate labeled sentence revokes conservatively and
BREAKs (25 of 50); the genuine countermands still revoke (conservative
= HELD pre and post). The labeled-set probe goes 25 BREAK pre-seam
and 0 post-seam.

Labeled set: 50 sentences (5 verbs x 5 languages x genuine/wrong-
predicate) + 4 accented-form probes = 54, every one gated on
similarity >= 0.5 so the verdict measures the scope discipline, not
the similarity gate. Target: zero new misses.

Probes:
  tier2_labeled_set ......... 54 labeled sentences; every genuine
      countermand revokes, every wrong-predicate stays silent.
  tier2_publish_wrong_predicate .. task probe (a): "The report is
      not final; please publish it to the portal" does NOT revoke.
  tier2_publish_direct_revoke .... task probe (b): "Don't publish
      the report" revokes.
  tier2_german_upload_separable .. task probe (c): "Kein Grund,
      laden Sie es nicht hoch." revokes, attributed to the upload
      grant (not the send grant) in a multi-grant call.
  tier1_no_regression ............ task probe (d): the wave-147
      scope battery + the inflection battery + the 47-sentence
      precision corpus stay green (0 BREAK/ERROR) -- false
      revocations must not regress.
  tier2_deterministic_x2 ......... task probe (e): byte-identical
      verdicts across 2 runs.

$0, stdlib-only, deterministic. Explicit threshold=0.5 pins (the
scope is under test, not calibration -- the wave-145 record_intent
lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import _NEGATION_RE  # noqa: E402
from gov.target_match import target_similarity  # noqa: E402

THRESHOLD = 0.5  # explicit: the scope is under test, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


# (tag, grant, sentence, expect_fire) -- 5 verbs x 5 languages x
# genuine countermand / wrong-predicate negation.
LABELED = [
    # --- REDACT ------------------------------------------------
    ("redact/en/genuine",
     "Redact the witness names before release.",
     "Don't redact the witness names.", True),
    ("redact/en/wrong-predicate",
     "Redact the witness names before release.",
     "The names are not final; please redact them before release.",
     False),
    ("redact/de/genuine",
     "Schwaerzen Sie die Zeugennamen vor der Freigabe.",
     "Schwaerzen Sie die Namen nicht.", True),
    ("redact/de/wrong-predicate",
     "Schwaerzen Sie die Zeugennamen vor der Freigabe.",
     "Die Namen sind nicht final; schwaerzen Sie sie bitte vor der "
     "Freigabe.", False),
    ("redact/fr/genuine",
     "Caviardez les noms des temoins avant diffusion.",
     "Ne caviardez pas les noms.", True),
    ("redact/fr/wrong-predicate",
     "Caviardez les noms des temoins avant diffusion.",
     "Les noms ne sont pas definitifs; caviardez-les avant "
     "diffusion.", False),
    ("redact/es/genuine",
     "Censure los nombres de los testigos.",
     "No censure los nombres.", True),
    ("redact/es/wrong-predicate",
     "Censure los nombres de los testigos.",
     "Los nombres no son definitivos; censure los nombres antes de "
     "difundir.", False),
    ("redact/hi/genuine",
     "Release se pehle naam hatao.",
     "Naam nahi hatao.", True),
    ("redact/hi/wrong-predicate",
     "Release se pehle naam hatao.",
     "Naam final nahi hain; release se pehle naam hatao.", False),
    # --- SHARE -------------------------------------------------
    ("share/en/genuine",
     "Share the draft with the review team.",
     "Never share the draft externally.", True),
    ("share/en/wrong-predicate",
     "Share the draft with the review team.",
     "The draft is not ready; please share it with the team.", False),
    ("share/de/genuine",
     "Teilen Sie den Entwurf mit dem Team.",
     "Teilen Sie den Entwurf nicht extern.", True),
    ("share/de/wrong-predicate",
     "Teilen Sie den Entwurf mit dem Team.",
     "Der Entwurf ist nicht fertig; teilen Sie ihn bitte mit dem "
     "Team.", False),
    ("share/fr/genuine",
     "Partagez le brouillon avec l'equipe.",
     "Ne partagez pas le brouillon.", True),
    ("share/fr/wrong-predicate",
     "Partagez le brouillon avec l'equipe.",
     "Le brouillon n'est pas pret; partagez-le avec l'equipe.",
     False),
    ("share/es/genuine",
     "Comparta el borrador con el equipo.",
     "No comparta el borrador.", True),
    ("share/es/wrong-predicate",
     "Comparta el borrador con el equipo.",
     "El borrador no esta listo; comparta el borrador con el "
     "equipo.", False),
    ("share/hi/genuine",
     "Review team ke saath draft baanto.",
     "Draft nahi baanto.", True),
    ("share/hi/wrong-predicate",
     "Review team ke saath draft baanto.",
     "Draft ready nahi hai; review team ke saath draft baanto.",
     False),
    # --- PUBLISH -----------------------------------------------
    ("publish/en/genuine",
     "Publish the Q3 report to the portal.",
     "Don't publish the report.", True),
    ("publish/en/wrong-predicate",
     "Publish the Q3 report to the portal.",
     "The report is not final; please publish it to the portal.",
     False),
    ("publish/de/genuine",
     "Veroeffentlichen Sie den Q3-Bericht im Portal.",
     "Veroeffentlichen Sie den Bericht nicht.", True),
    ("publish/de/wrong-predicate",
     "Veroeffentlichen Sie den Q3-Bericht im Portal.",
     "Der Bericht ist nicht final; veroeffentlichen Sie ihn bitte "
     "im Portal.", False),
    ("publish/fr/genuine",
     "Publiez le rapport Q3 sur le portail.",
     "Ne publiez pas le rapport.", True),
    ("publish/fr/wrong-predicate",
     "Publiez le rapport Q3 sur le portail.",
     "Le rapport n'est pas final; publiez-le sur le portail.",
     False),
    ("publish/es/genuine",
     "Publique el informe Q3 en el portal.",
     "No publique el informe.", True),
    ("publish/es/wrong-predicate",
     "Publique el informe Q3 en el portal.",
     "El informe no es final; publique el informe en el portal.",
     False),
    ("publish/hi/genuine",
     "Portal par Q3 report chhaapo.",
     "Report nahi chhaapo.", True),
    ("publish/hi/wrong-predicate",
     "Portal par Q3 report chhaapo.",
     "Report final nahi hai; portal par Q3 report chhaapo.", False),
    # --- FORWARD -----------------------------------------------
    ("forward/en/genuine",
     "Forward the email chain to legal.",
     "Do not forward this email chain.", True),
    ("forward/en/wrong-predicate",
     "Forward the email chain to legal.",
     "The chain is not complete; please forward it to legal.",
     False),
    ("forward/de/genuine",
     "Leiten Sie die E-Mail-Kette an die Rechtsabteilung weiter.",
     "Leiten Sie die Kette nicht weiter.", True),
    ("forward/de/wrong-predicate",
     "Leiten Sie die E-Mail-Kette an die Rechtsabteilung weiter.",
     "Die Kette ist nicht vollstaendig; leiten Sie sie bitte an "
     "die Rechtsabteilung weiter.", False),
    ("forward/fr/genuine",
     "Transferez la chaine d'e-mails au service juridique.",
     "Ne transferez pas la chaine.", True),
    ("forward/fr/wrong-predicate",
     "Transferez la chaine d'e-mails au service juridique.",
     "La chaine n'est pas complete; transferez-la au service "
     "juridique.", False),
    ("forward/es/genuine",
     "Reenvie la cadena de correos al departamento legal.",
     "No reenvie la cadena de correos.", True),
    ("forward/es/wrong-predicate",
     "Reenvie la cadena de correos al departamento legal.",
     "La cadena no esta completa; reenvie la cadena al "
     "departamento legal.", False),
    ("forward/hi/genuine",
     "Legal ko email chain forward karo.",
     "Email chain forward nahi karo.", True),
    ("forward/hi/wrong-predicate",
     "Legal ko email chain forward karo.",
     "Email chain complete nahi hai; legal ko email chain forward "
     "karo.", False),
    # --- UPLOAD ------------------------------------------------
    ("upload/en/genuine",
     "Upload the backup to the vault.",
     "Don't upload the backup yet.", True),
    ("upload/en/wrong-predicate",
     "Upload the backup to the vault.",
     "The backup is not verified; please upload it to the vault.",
     False),
    ("upload/de/genuine",
     "Laden Sie das Backup in den Tresor hoch.",
     "Laden Sie das Backup nicht hoch.", True),
    ("upload/de/wrong-predicate",
     "Laden Sie das Backup in den Tresor hoch.",
     "Das Backup ist nicht geprueft; laden Sie es bitte in den "
     "Tresor hoch.", False),
    ("upload/fr/genuine",
     "Telechargez la sauvegarde vers le coffre.",
     "Ne telechargez pas la sauvegarde.", True),
    ("upload/fr/wrong-predicate",
     "Telechargez la sauvegarde vers le coffre.",
     "La sauvegarde n'est pas verifiee; telechargez-la vers le "
     "coffre.", False),
    ("upload/es/genuine",
     "Suba la copia de seguridad a la boveda.",
     "No suba la copia aun.", True),
    ("upload/es/wrong-predicate",
     "Suba la copia de seguridad a la boveda.",
     "La copia no esta verificada; suba la copia a la boveda.",
     False),
    ("upload/hi/genuine",
     "Vault mein backup upload karo.",
     "Backup upload nahi karo.", True),
    ("upload/hi/wrong-predicate",
     "Vault mein backup upload karo.",
     "Backup verify nahi hua; vault mein backup upload karo.",
     False),
    # --- accented forms (accent-folded tokenization) -----------
    ("publish/de-accent/genuine",
     "Veröffentlichen Sie den Q3-Bericht im Portal.",
     "Veröffentlichen Sie den Bericht nicht.", True),
    ("publish/de-accent/wrong-predicate",
     "Veröffentlichen Sie den Q3-Bericht im Portal.",
     "Der Bericht ist nicht final; veröffentlichen Sie ihn bitte "
     "im Portal.", False),
    ("forward/fr-accent/genuine",
     "Transférez la chaîne au service juridique.",
     "Ne transférez pas la chaîne.", True),
    ("forward/fr-accent/wrong-predicate",
     "Transférez la chaîne au service juridique.",
     "La chaîne n'est pas complète; transférez-la au service "
     "juridique.", False),
]


def _measure(sentence, grants):
    cue = _NEGATION_RE.search(sentence)
    cue = cue.group(0) if cue else None
    fired, idx, score = similarity_countermand(
        sentence, grants, threshold=THRESHOLD)
    return cue, fired, idx, score


def tier2_labeled_set():
    name = "tier2_labeled_set"
    misses = []
    gate_fail = []
    for tag, grant, sentence, want in LABELED:
        sim = target_similarity(sentence, grant)
        if sim < THRESHOLD:
            gate_fail.append("%s sim=%.3f" % (tag, sim))
            continue
        cue, fired, _idx, score = _measure(sentence, [grant])
        if fired != want:
            misses.append(
                "%s: fired=%r want=%r (cue %r, sim %.3f): %r"
                % (tag, fired, want, cue, score, sentence))
    if gate_fail:
        _record(name, "ERROR",
                "similarity gate failed (probe would measure the "
                "wrong seam): %s" % "; ".join(gate_fail))
        return
    if misses:
        _record(name, "BREAK",
                "%d/%d labeled misses: %s"
                % (len(misses), len(LABELED), "; ".join(misses)))
        return
    _record(name, "HELD",
            "0 misses on %d labeled sentences (5 verbs x 5 langs x "
            "genuine/wrong-predicate + 4 accented)" % len(LABELED))


def tier2_publish_wrong_predicate():
    # Task probe (a): the cue scopes over "final" in clause 1; the
    # publish grant is re-affirmed in clause 2 -> silent.
    name = "tier2_publish_wrong_predicate"
    sentence = ("The report is not final; please publish it to the "
                "portal.")
    grant = "Publish the Q3 report to the portal."
    cue, fired, _idx, score = _measure(sentence, [grant])
    if fired:
        _record(name, "BREAK",
                "false revocation (cue %r, sim %.3f): negation over "
                "'final' revoked the publish grant" % (cue, score))
        return
    _record(name, "HELD",
            "silent (cue %r, sim %.3f): negation scopes 'final', "
            "publish re-affirmed" % (cue, score))


def tier2_publish_direct_revoke():
    # Task probe (b): the canonical direct countermand keeps revoking.
    name = "tier2_publish_direct_revoke"
    sentence = "Don't publish the report."
    grant = "Publish the Q3 report to the portal."
    cue, fired, _idx, score = _measure(sentence, [grant])
    if not fired:
        _record(name, "BREAK",
                "genuine countermand stopped revoking (cue %r, sim "
                "%.3f)" % (cue, score))
        return
    _record(name, "HELD",
            "revoked (cue %r, sim %.3f): cue adjacent to the grant "
            "verb" % (cue, score))


def tier2_german_upload_separable():
    # Task probe (c): German separable verb "laden ... hoch" (upload).
    # Must revoke, attributed to the upload grant -- not the send
    # grant -- in a multi-grant call.
    name = "tier2_german_upload_separable"
    sentence = "Kein Grund, laden Sie es nicht hoch."
    upload_grant = "Laden Sie den Bericht auf das Portal hoch."
    send_grant = "Senden Sie den Bericht an den Vendor."
    cue, fired, idx, score = _measure(
        sentence, [upload_grant, send_grant])
    if not fired:
        _record(name, "BREAK",
                "separable upload countermand did not revoke (cue "
                "%r, sim %.3f)" % (cue, score))
        return
    if idx != 0:
        _record(name, "BREAK",
                "revocation attributed to the wrong grant (idx=%r, "
                "want 0=upload): the upload cue must revoke only "
                "the upload" % (idx,))
        return
    _record(name, "HELD",
            "revoked (cue %r, sim %.3f), attributed to the upload "
            "grant (idx 0), not the send grant" % (cue, score))


def tier1_no_regression():
    # Task probe (d): tier-1 batteries stay green -- false
    # revocations on the 47-sentence precision corpus must not
    # regress, and the scope/inflection batteries must not break.
    name = "tier1_no_regression"
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))

    def _load(modname, fname):
        spec = importlib.util.spec_from_file_location(
            modname, os.path.join(here, fname))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    bad = []
    notes = []
    for modname, fname in (
            ("_t2_scope", "negation_scope_probes.py"),
            ("_t2_infl", "countermand_negation_inflection_probes.py"),
            ("_t2_prec", "negation_precision_probes.py")):
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
        notes.append("%s: %d probes clean"
                     % (fname, len(results)))
    if bad:
        _record(name, "BREAK", "regression: %s" % "; ".join(bad))
        return
    _record(name, "HELD", "; ".join(notes))


def _run_all():
    global _RESULTS
    _RESULTS = []
    tier2_labeled_set()
    tier2_publish_wrong_predicate()
    tier2_publish_direct_revoke()
    tier2_german_upload_separable()
    tier1_no_regression()
    return list(_RESULTS)


def tier2_deterministic_x2():
    name = "tier2_deterministic_x2"
    first = [(n, v) for n, v, _ in _run_all()]
    second = [(n, v) for n, v, _ in _run_all()]
    if first != second:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r"
                % (first, second))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs"
            % len(first))


def main():
    _run_all()
    tier2_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("negation_verb_tier2_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
