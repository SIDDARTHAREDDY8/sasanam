"""Intent-slice judge for row-7 intent/temporal correlation.

Row-7 residual: no cross-agent intent/temporal correlation, no
revoke-after-approve. ``evals/row7_delayed_break.py`` pins the gap red
(plant-then-harm with zero correlating signal; no revocation path).

Pattern adapted from openai/openai-guardrails-python (MIT License,
(c) 2025 OpenAI; https://github.com/openai/openai-guardrails-python,
v0.3.2 = commit 60401f4ca6c832e8be1a82f6fc3783d6e51c59a9, resolved via
the GitHub tag-refs API on 2026-09-27; MIT license confirmed from the
upstream LICENSE at that tag):

- ``UserIntentDict``: ``{"most_recent_message": str,
  "previous_context": list[str]}`` -- the latest user turn plus prior
  user turns as the intent anchor.
- ``_slice_conversation_since_latest_user()``: the intent anchor is the
  index of the LATEST user message; the analyzed actions are everything
  after that index. User messages are never analyzed -- they ARE the
  intent.
- The direct-evidence rubric: flag only on direct evidence (a quoted
  contradiction, a countermanded recipient), never on competence
  issues (poor quality, partial progress, safe intermediate steps).

Adapted, not cloned: no code copied (the upstream judge calls paid
OpenAI APIs -- a $0-spend violation here). The LLM semantic judgment is
replaced with a deterministic local slicer: slot extraction (recipients,
URLs, paths), content-token overlap, countermand/redirect detection, and
negation-scoped verb matching. The verdict shape mirrors the upstream
structured contract (flagged / confidence / observation / evidence).

What this is NOT:
- Not an enforcer. The judge ANNOTATES approval-queue items; it never
  denies. A ``stale_intent`` flag routes to human review with evidence.
  False positives cost reviewer attention, not blocked work.
- Not a content oracle. It does not judge whether an action is harmful;
  it judges whether the action is still anchored to the LATEST user
  intent or only to a superseded earlier instruction.
- Not row-7 closure. Causal relevance here is heuristic: a paraphrase
  that launders a stale instruction through a vague latest message
  (no extractable slots, no countermand signal) defeats the slicer.
  That ceiling is measured, not claimed away (see
  ``evals/intent_slice_probes.py::p5_paraphrase_residual``).

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import json
import re
import unicodedata

__all__ = [
    "UserIntent",
    "IntentSlice",
    "slice_intent",
    "judge_candidate",
    "judge_queued_action",
    "STEP_USER",
    "STEP_ACTION",
    "STEP_RESULT",
    "STEP_MESSAGE",
]

# Step kinds. Only "user" and "agent_action" participate in slicing;
# tool results and agent prose are neutral context (they neither anchor
# intent nor need anchoring).
STEP_USER = "user"
STEP_ACTION = "agent_action"
STEP_RESULT = "tool_result"
STEP_MESSAGE = "agent_message"

# Per-step labels produced by the slicer.
IN_SLICE = "in_slice"   # causally relevant to the latest user intent
STALE = "stale"         # serves only a superseded earlier instruction
NEUTRAL = "neutral"     # neither (weak signal, no countermand)

FLAG_STALE_INTENT = "stale_intent"

# Redirect/countermand signals: a latest user message carrying one of
# these AND sharing topic overlap with a prior user message marks that
# prior instruction as superseded.
_REDIRECT_RE = re.compile(
    r"\b(stop|don't|dont|do not|doesn't|doesnt|never mind|cancel|abort|"
    r"hold off|hold on|instead|forget|ignore|no longer|revert|undo|"
    r"on hold|not anymore|change of plans|scratch that)\b",
    re.IGNORECASE,
)

# Negation words for verb-scope negation ("don't delete", "never send").
# Wave-142: a small, high-precision multilingual particle set, still
# word-boundary matched through this same regex (no new detection
# architecture). Spanish "no" was already covered by the English
# "no"; added French "ne"/"pas", German "nicht"/"kein"/"keine",
# Hindi (romanized) "nahi". Measured precision on a 17-sentence
# realistic benign corpus (grant-adjacent tokens, similarities
# 0.533-0.857 -- a cue hit there would be a REAL false positive at
# the similarity-countermand gate): "non" DROPPED (2 hits:
# "non-profit"/"Our non-profit partner..."), "mat" DROPPED (1 hit:
# "yoga mat"); "ne" kept (0 realistic hits -- sole hit on the
# contrived "ne'er-do-wells", a documented precision cost);
# "pas"/"nicht"/"kein"/"keine"/"nahi" 0 hits.
# Wave-143: seeded inflection coverage on the same core. German
# "kein" gains its inflected forms keinen/keinem/keiner/keines as
# standalone words (word-boundary guarded: "keineswegs" does NOT
# cue -- measured 0 hits on the wave-143 benign corpus; it shares
# the "keines" prefix with "keinesfalls" and stays the
# prefix-collision guard). French gains the discontinuous
# "ne ... jamais|plus|rien|aucun" paired pattern (_FRENCH_NE_PAIR_SRC,
# embedded in _NEGATION_RE so every consumer of the core picks it
# up -- no second word list): up to 8 intervening words, including
# the elided "n'" (straight/curly apostrophe; the elided form must
# start at whitespace so "'n'" in "rock 'n' roll" cannot anchor it).
# Wave-144: "keinerlei"/"keinesfalls" graduate from pinned miss to
# standalone-word cues (unambiguous negation words; "keineswegs" was
# the sole German leftover, deliberately out of scope -- wave-145
# closes it: see below). The French
# paired pattern fires in BOTH orders -- "ne ... X" and "X ... ne"
# (e.g. "rien ne va" as well as "ne va rien") -- with the same
# elision/whitespace guards (symmetric: the elided n' must start at
# whitespace in either order). Measured precision on the wave-144
# benign corpus (10 sentences: de/en positive confirmations,
# keineswegs lookalike, plus/rien/aucun WITHOUT "ne" in both
# orders, non-profit/yoga mat/notable -- similarities 0.545-0.857,
# all at/above the gate): 0 cue hits. Full multilingual coverage is
# NOT claimed (non-romanized scripts untouched; full synonym
# replacement still misses -- the p6 ceiling carries over; the new
# words inherit the seeded approach's scope imprecision).
_FRENCH_NE_PAIR_SRC = (
    r"(?:"
    r"(?:\bne\b|(?<!\S)n['\u2019]\w*)"   # "ne", or elided "n'"/"n'"
    r"(?:\s+\S+){0,8}?"                   # up to 8 intervening words
    r"\s+\b(jamais|plus|rien|aucun)\b"    # the second particle
    r"|"
    r"\b(jamais|plus|rien|aucun)\b"       # reverse order: X ... ne
    r"(?:\s+\S+){0,8}?"
    r"\s+(?:\bne\b|(?<!\S)n['\u2019]\w*)"  # ... then "ne"/elided "n'"
    r")"
)
_FRENCH_NE_PAIR_RE = re.compile(_FRENCH_NE_PAIR_SRC, re.IGNORECASE)
# Wave-145: "keineswegs" ("in no way / by no means") graduates from
# the wave-144 pinned miss to a standalone-word cue -- the last
# German leftover is closed. Same word-boundary discipline, same
# style: "keineswegs" cues only as a whole word. The "keines" prefix
# it shares with "keinesfalls" cannot double-fire -- the boundary
# after "keines" fails inside "keineswegs", so the alternation falls
# through to the full-word alternative. Scope imprecision carries
# over unchanged: a keineswegs scoping over the wrong predicate
# ("Der Q3 report ist keineswegs fertig; bitte senden Sie ihn an den
# vendor.") now revokes -- the same seeded-approach ceiling the
# keinerlei/keinesfalls words carry, pinned EXPECTED in the
# wave-144/145 battery rather than claimed away.
# Wave-145 precision guards (measured on the 48-sentence benign
# corpus in evals/negation_precision_probes.py -- every sentence
# scores >= gate similarity, so each suppressed hit below was a REAL
# false revocation, and each guard is pinned by a regression probe):
#   - "no"/"kein"/"keine" do NOT cue in the affirmative idiom
#     "no problem" / "kein Problem" / "keine Probleme"
#     ("No problem -- please send the Q3 report..." FIRED pre-guard).
#     A genuine "no"/"kein" countermand ("There is no Q3 report")
#     still fires; so does "don't"/"never"/"not" in the same
#     sentence ("No problem, don't send it" still revokes via
#     "don't"). The guard is positional (immediately followed by
#     "problem(s)"/"Problem(e)"); "kein grosses Problem" (adjective
#     between) is out of scope, documented in the battery.
#   - "not" does NOT cue in the correlative "not only ... (but
#     also)" ("Not only send the Q3 report..., but also archive a
#     copy" FIRED pre-guard -- an EXTENSION of the grant, not a
#     countermand). Positional: only "not" immediately followed by
#     "only".
#   - "pas" does NOT cue in the French tag question "n'est-ce pas"
#     ("Envoyez le Q3 report au vendor, n'est-ce pas?" FIRED
#     pre-guard -- a confirmation request, not a countermand) nor
#     as the noun "un pas" = "a step" ("faites un pas a la fois"
#     FIRED pre-guard). Both guards are fixed-width lookbehinds at
#     the "pas" position, so "n'est pas" / "ne ... pas" countermands
#     ("Le Q3 report n'est pas pret; ne l'envoyez pas") still fire.
# Scope note: the guards live in the search-form cue (the
# similarity-countermand gate). _negated_verb fullmatches single
# window tokens, where the lookaheads/lookbehinds are vacuous --
# unchanged, and unreachable for these idioms (that path requires an
# explicit redirect signal, which the idiom sentences lack).
# Wave-149 (row 7): Devanagari negation cues (pilot -- Hindi only;
# other non-romanized scripts remain untouched). Python's \b does NOT
# fire around Devanagari words ending in combining marks: "नहीं" ends
# in ं (U+0902, category Mn -- not a \w char), so \bनहीं\b matches
# NOTHING, not even "रिपोर्ट नहीं भेजें" (measured). The boundary
# discipline is therefore explicit: a cue must not be immediately
# preceded or followed by a word character. U+0964/U+0965
# (danda/double danda, the Hindi sentence terminators) are
# DELIBERATELY excluded from the guard so "नहीं।" still cues; every
# other Devanagari letter, vowel sign, nukta, halant,
# anusvara/visarga, and digit blocks gluing -- "रिपोर्टनहींभेजें"
# and "मतलब" ("meaning", contains "मत") do NOT cue.
_DEVA_WORD_CHAR = r"[\w\u0900-\u0963\u0966-\u097F]"
_DEVA_NEG_SRC = (r"(?<!" + _DEVA_WORD_CHAR + r")"
                 r"(?:नहीं|न|मत)"
                 r"(?!" + _DEVA_WORD_CHAR + r")")
# Wave-151 (row 7): Russian Cyrillic negation cues (pilot -- Russian
# only; CJK and other non-romanized scripts remain untouched --
# Arabic landed in wave-152).
# Unlike Devanagari combining marks, Cyrillic letters ARE \w, so plain
# \b fires correctly around Cyrillic words: \bне\b matches "отчёт не
# отправляйте" and does NOT match "менеджер", "ниже", "некоторые",
# "интернет" (нет), or "организация"/"униформа" (ни) -- measured,
# pinned in evals/cyrillic_negation_probes.py::c_lookalike_boundaries
# (0 cue hits on 6 word-internal lookalikes). No hand-rolled guards
# needed.
#
# Cues: не ("not"), нет ("no" / "there is no"), ни (the
# "neither/nor" particle, also the standalone negator in "ни в коем
# случае"), нельзя ("must not" / "forbidden"), plus the paired
# ни...ни ("neither...nor", _CYRILLIC_NI_PAIR_SRC -- up to 8
# intervening words, embedded in _NEGATION_RE like the French paired
# pattern so every consumer of the core picks it up). The paired form
# is detection-equivalent to the standalone ни cue (ни is itself a
# mandated cue, so the pair adds no new search hits); it is kept for
# structural parity with the French pattern and to name the
# construction explicitly.
#
# Wave-151 precision guards (wave-145 discipline -- each suppressed
# hit below was a REAL false revocation at the gate, pinned by a
# regression probe):
#   - "нельзя" does NOT cue in the polite idiom "нельзя ли"
#     ("Нельзя ли отправить Q3 отчёт?" = "could you please send the
#     report?" -- FIRED pre-guard at similarity 0.571). A genuine
#     "Q3 отчёт отправлять нельзя" still fires; the guard is
#     positional (immediately followed by "ли").
#   - "не" does NOT cue in the tag question "не так ли" ("Вы
#     отправили Q3 отчёт, не так ли?" = "you sent it, didn't you?"
#     -- FIRED pre-guard at 0.571). "Не так отправляйте" (no "ли")
#     still fires; the guard is positional.
# Scope note (same as wave-145): the guards live in the search-form
# cue (the similarity-countermand gate). _negated_verb fullmatches
# single window tokens, where the lookaheads are vacuous -- the
# нельзя-ли idiom therefore still fires the RAW judge (pinned
# EXPECTED in the battery); it is unreachable in production because
# the judge path requires a redirect-signal countermand, which the
# idiom lacks. The не-так-ли tag question is natively silent in the
# judge: its cue comes after the verb, outside the pre-verb window.
_CYRILLIC_NI_PAIR_SRC = (
    r"(?:\bни\b(?:\s+\S+){0,8}?\s+\bни\b)"
)
_CYRILLIC_NEG_SRC = (
    r"(?:\bне(?!\s+так\s+ли\b)\b|\bнет\b|\bни\b|"
    r"\bнельзя(?!\s+ли\b)\b)"
)
# Wave-152 (row 7): Arabic negation cues (pilot -- Modern Standard
# Arabic only; CJK and other non-romanized scripts remain untouched).
# Like Cyrillic, Arabic letters ARE \w, so plain \b fires correctly
# around Arabic words: \bلا\b matches "لا ترسل" and does NOT match
# "بلاد" (country), "سلام" (peace), or "كلام" (speech) -- measured,
# pinned in evals/arabic_negation_probes.py::c_lookalike_boundaries
# (0 cue hits on 6 word-internal lookalikes).
#
# Attached prefixes: Arabic conjunctions/prepositions glue onto the
# following word, so a bare \bلا\b misses the realistic countermand
# forms "ولا ترسل" (wa-laa, "and do not send"), "بلا إرسال"
# (bi-laa, "without sending"), and "ولم يتم" (wa-lam, "and it was
# not"). The prefixes are part of the cue alternative itself:
# لا carries an optional و/ب/ل prefix; لم/لن/ما/ليس carry an
# optional و prefix (ب/ل do not attach to these particles). The
# trailing \b still guards the word end, so "بلاد" (bi-laa-d...,
# "country") does NOT cue: after the optional ب and لا, the \b
# fails before د. "للا" alone is not a word; carrying ل is harmless
# (it only matches the literal token للا, which does not occur).
#
# Cues: لا ("not"/"do not"/"no"), لم ("did not" + jussive), لن
# ("will not" + subjunctive), ما (negation "did not" -- ALSO the
# interrogative "what" and the relative pronoun, an acknowledged
# precision boundary: negation-ما is always followed by a
# past-tense verb, but the pilot carries no tense guard, so the
# interrogative/relative uses fire too -- pinned EXPECTED in the
# battery, follow-up work), ليس ("is not"; no inflection coverage
# -- "ليست" does not cue, same closed-list discipline as Cyrillic).
# Dialectal forms (Egyptian ما...ش, Levantine ما عم, ...) are
# deliberately untouched.
_ARABIC_NEG_SRC = (
    r"(?:\b[وبل]?لا\b|\bو?(?:لم|لن|ما|ليس)\b)"
)
# Wave-153 (row 7): CJK negation cues (pilot -- Mandarin, Japanese,
# Korean; other CJK languages/scripts remain untouched).
# CJK text has no word spaces, so \b-style boundary discipline does
# NOT apply: cues match as substrings (不要 in 不要发送), with
# explicit positional guards on measured benign idioms (wave-145
# discipline -- each guard below suppresses a REAL false
# revocation, pinned in evals/cjk_negation_probes.py):
#   - 不要 does NOT cue in 不要紧 ("no problem" -- the Chinese
#     parallel of the wave-145 "no problem" guard);
#   - 别 does NOT cue in 别人/别的/别处/别样/别名 ("other ...",
#     the 别 homograph disambiguation: imperative "don't" vs the
#     "other" prefix);
#   - bare ない was measured and DROPPED (wave-142 "non"/"mat"
#     precedent): it fires on every Japanese i-adjective, and
#     "Q3レポートは高くない" ("the Q3 report is not expensive")
#     scores 0.571 against the SEND grant -- a REAL false
#     revocation. The prohibitive force is carried by しない
#     (which covers しないで as a substring).
# Korean is spaced (eojeol), so the prohibition is the productive
# V-지 마 construction (보내지 마, 하지 마), matched as \S+지\s+마
# (which covers 하지 마 -- 하지 ends in 지). 말고/취소/중지
# parallel the English "instead-of / cancel / stop" cues.
# Deliberately out of scope (documented residuals): Mandarin 没/请勿,
# Japanese plain-form prohibitions (送るな/するな), Korean honorific
# variants beyond the 마 prefix, dialectal forms.
_CJK_CHAR_RE = re.compile(
    r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\u1100-\u11ff"
    r"\u3130-\u318f]")
_CJK_NEG_SRC = (
    r"(?:"
    r"不行|不要(?!紧)|别(?!人|的|处|样|名)|"
    r"停止|取消"              # "stop" / "cancel"
    r"|止めて"                # "stop it" (te-form request)
    r"|キャンセル"            # "cancel" (katakana loanword)
    r"|しない"                # plain negative (covers しないで)
    r"|(?:\S+지\s+마)"         # V-지 마 prohibition (covers 하지 마)
    r"|말고|취소|중지"         # "instead-of" / "cancel" / "stop"
    r")"
)
# F188 (row 7): a Latin negation cue glued to a non-Latin word char
# with zero whitespace ("do not发送"). \b fails at the Latin->non-Latin
# boundary because non-Latin letters are \w in Unicode regex, so the
# trailing \b of the Latin cue alternatives below also accepts a
# Latin->non-Latin script transition. The leading \b is unchanged: a
# cue glued AFTER non-Latin text is not the F188 shape (English puts
# the cue before the verb). The wave-145 guards ("not only",
# "no problem", "kein(e) problem(e)") carry the same boundary --
# their inner \b had the identical blindness, so "not only发送"
# leaked a "not" cue pre-fix (pinned in
# evals/f188_glued_cue_probes.py).
_NONLATIN_WORD_SRC = (
    r"\u0400-\u04ff"      # Cyrillic
    r"\u0900-\u097f"      # Devanagari
    r"\u0600-\u06ff"      # Arabic
    r"\u4e00-\u9fff"      # Han
    r"\u3040-\u30ff"      # Hiragana/Katakana
    r"\uac00-\ud7af"      # Hangul syllables
    r"\u1100-\u11ff"      # Hangul Jamo
    r"\u3130-\u318f"      # Hangul compatibility Jamo
)
# Bit-identical to \b wherever the next char is not a non-Latin
# word char (the class is a subset of \w, so plain-\b cases are
# untouched); it only ADDS the script-transition case.
_LATIN_CUE_END_SRC = r"(?:\b|(?=[" + _NONLATIN_WORD_SRC + r"]))"
_NEGATION_RE = re.compile(
    r"\b(don'?t|dont|do not|doesn'?t|doesnt|never|"
    r"not(?!\s+only" + _LATIN_CUE_END_SRC + r")|"
    r"no(?!\s+problems?" + _LATIN_CUE_END_SRC + r")|stop|halt|"
    r"cease|avoid|refrain|cancel|ne|"
    r"(?<!n['\u2019]est-ce\s)(?<!\bun\s)pas|"
    r"nicht|kein(?!\s+probleme?" + _LATIN_CUE_END_SRC + r")|"
    r"keine(?!\s+probleme?" + _LATIN_CUE_END_SRC + r")|keinen|"
    r"keinem|keiner|keines|keinerlei|keinesfalls|keineswegs|nahi)"
    + _LATIN_CUE_END_SRC + r"|" + _FRENCH_NE_PAIR_SRC
    + r"|" + _DEVA_NEG_SRC
    + r"|" + _CYRILLIC_NI_PAIR_SRC
    + r"|" + _CYRILLIC_NEG_SRC
    + r"|" + _ARABIC_NEG_SRC
    + r"|" + _CJK_NEG_SRC,
    re.IGNORECASE,
)

# Wave-147 (row 7): scope-window discipline for negation. A negation
# cue only cancels an intent when it falls within a bounded token
# window of the intent's action verb, measured against the anchor
# clause; a cue scoping over the wrong predicate in a separate clause
# does NOT revoke. Clause-aware first, then window-bounded: in "Der
# Q3 report ist keineswegs fertig; bitte senden Sie ihn an den
# vendor." the cue and the grant verb are only a few tokens apart but
# live in different clauses, so a whole-message distance check is
# insufficient -- the cue must share a clause with the anchor's
# action verb (or a same-class multilingual form) within
# _NEGATION_SCOPE_WINDOW tokens.
#
# Decision table for one (message, anchor) pair:
#   - a cue within +-window of a grant-verb token in the SAME clause
#     -> the cue demonstrably scopes the grant -> MAY REVOKE;
#   - no grant-verb token anywhere in the message (e.g. "There is no
#     Q3 report", "Kein Q3 report fuer den vendor.") -> conservative
#     pre-wave-147 behavior -> MAY REVOKE;
#   - the grant verb appears, but every cue sits in a different
#     clause (the speaker re-affirmed the action separately from the
#     negation, e.g. "...ist keineswegs fertig; bitte senden Sie
#     ihn...") -> SILENT.
# Unknown anchor verbs (no curated class) keep the pre-wave-147
# behavior (conservative revoke) -- the scope check only narrows what
# it can positively attribute, never what it cannot see. The verb
# classes are a curated closed list for the languages the cue set
# covers (EN/DE/FR/ES/HI romanized); synonyms outside the list and
# non-romanized scripts are documented residuals (row 7 stays
# PARTIAL). Elliptical cross-clause countermands ("Send the report.
# Don't.") are a known boundary: the bare cue's clause carries no
# verb, so the re-affirmed-verb clause wins and the gate stays
# silent.
_NEGATION_SCOPE_WINDOW = 8
# Wave-149 (row 7): U+0964/U+0965 (danda/double danda, the Hindi
# sentence terminators) added so Hindi multi-sentence messages get
# clause discipline. Latin texts never contain dandas, so existing
# behaviour is unchanged.
# Wave-152 (row 7): U+061F (Arabic question mark ؟) and U+061B
# (Arabic semicolon ؛) added as clause boundaries, parallel to the
# Devanagari danda and the Latin ?/;. Latin/Cyrillic/Devanagari
# texts never contain U+061F/U+061B, so existing behaviour is
# unchanged. The Arabic comma U+060C is deliberately NOT a boundary
# (parallel to the Latin comma).
# Wave-153 (row 7): CJK sentence terminators added as clause
# boundaries, parallel to the above: U+3002 (。 ideographic full
# stop), U+FF01 (！ fullwidth exclamation), U+FF1F (？ fullwidth
# question mark), U+FF1B (； fullwidth semicolon). Latin/
# Cyrillic/Devanagari/Arabic texts never contain these, so existing
# behaviour is unchanged. U+3001 (、 ideographic comma) is
# deliberately NOT a boundary (parallel to the Latin/Arabic comma).
_CLAUSE_SPLIT_RE = re.compile(r"[.!?;\u0964\u0965\u061F\u061B\u3002\uff01\uff1f\uff1b]+")
# Wave-149 (row 7): Devanagari block added so Hindi scope windows can
# be walked. U+0964/U+0965 are deliberately excluded so "भेजें।"
# tokenises as "भेजें" (the verb form must match exactly for
# anchor-class detection) and the danda acts as a token boundary like
# other punctuation. Accents folded under NFKD (Devanagari is
# unaffected); case lowered.
# Wave-151 (row 7): Cyrillic block (U+0400-U+04FF) added so Russian
# scope windows can be walked. Cyrillic has no sentence terminator
# outside .!?; (already covered), and _fold_accents is
# length-identical on Cyrillic (ё->е, й->и), so cue-span alignment
# holds. Latin tokenization unchanged.
# Wave-152 (row 7): Arabic block (U+0600-U+06FF) added so Arabic
# scope windows can be walked. The whole block is included (the
# ؟ U+061F clause boundary above splits before tokenization, so it
# never reaches the tokenizer; the ، U+060C comma tokenises as a
# word char, harmless -- it never equals a class form or cue).
# F183 (row 7): invisible zero-width format characters are
# token-INTERNAL here, not boundaries. U+200B (ZWSP), U+200C (ZWNJ),
# U+200D (ZWJ) and U+FEFF (ZWNBSP/BOM) are Unicode category Cf:
# NFKC/NFKD normalization does NOT remove them (measured: all four
# survive unicodedata.normalize('NFKC', ...)), and they render as
# zero width, so "भे\u200bजें" looks identical to "भेजें". Pre-F183
# they split tokens, so one invisible char inside a verb form or
# cue broke the exact class-form/cue match and the judge went
# silently neutral (134 judge-level misses, F183). They are carried
# in the class and stripped per-token by _strip_invisible_format
# before matching -- string lengths never change, so the raw-text
# cue-span alignment in negation_scopes_grant is untouched. Stripping
# the whole text first was deliberately NOT done: it would GLUE words
# an attacker separated with ZWSP ("रिपोर्ट\u200bनहीं" ->
# "रिपोर्टनहीं"), silently changing the documented embedded-cue
# discipline (glued cues stay silent, pinned by d_embedded_cue_silent).
# The token-internal treatment keeps rendering and tokenization
# consistent: what renders glued, tokenizes glued.
# F183-follow-up (row 7): the invisible-format class is wider than
# the four zero-width chars. Bidi embeddings/overrides
# (U+202A-U+202E), bidi isolates (U+2066-U+2069), the direction marks
# U+200E/U+200F and U+061C, U+180E, U+00AD, the invisible operators
# U+2060-U+2064, and the deprecated tag block U+E0000-U+E007F are all
# Unicode category Cf: NFKC does NOT remove them (measured), and
# intra-token they are visually inert in LTR (Devanagari/Cyrillic/
# Latin) text. The whole class is therefore token-internal here
# (carried in the class below) and stripped per-token by
# _strip_invisible_format before matching -- the same token-internal
# discipline as F183. U+FFFC (object replacement, category So) is
# deliberately NOT in this class: it renders as a visible placeholder
# box (pinned EXPECTED in the battery, not fixed). U+034F/U+FE0F are
# Mn, not Cf, with script-dependent visibility; measured and
# documented in the battery, not fixed.
# Wave-152: the Arabic block (U+0600-U+06FF) stays in the class; the
# invisible-format stripping applies to Arabic tokens identically
# (a zero-width char inside an Arabic cue/verb form is stripped
# per-token before matching, same as Devanagari/Cyrillic).
_INVISIBLE_FORMAT_CLASS = (
    r"\u200b\u200c\u200d\ufeff"      # zero-width (F183)
    r"\u200e\u200f"                    # LRM / RLM
    r"\u061c"                           # ALM (arabic letter mark)
    r"\u180e"                           # MVS (mongolian vowel separator)
    r"\u202a-\u202e"                   # bidi embeddings / overrides
    r"\u2066-\u2069"                   # bidi isolates
    r"\u00ad"                           # soft hyphen (invisible mid-word)
    r"\u2060-\u2064"                   # word joiner + invisible operators
    r"\U000E0000-\U000E007F"           # deprecated tag block
)
_SCOPE_WORD_RE = re.compile(
    r"[a-z0-9'\u0400-\u04FF\u0900-\u0963\u0966-\u097F\u0600-\u06FF"
    # Wave-153 (row 7): CJK blocks so CJK scope windows can be
    # walked: U+4E00-U+9FFF (Han), U+3040-U+30FF
    # (Hiragana/Katakana), U+AC00-U+D7AF (Hangul syllables),
    # U+1100-U+11FF/U+3130-U+318F (Jamo). CJK runs are unspaced,
    # so one token is a whole run (不要发送报告); verb-class
    # attribution is by closed-list substring
    # (_cjk_token_classes), not whole-token equality. The
    # invisible-format class is token-internal here too (F183 for
    # CJK: a zero-width char inside a CJK cue/verb form is stripped
    # per-token by _strip_invisible_format before matching -- the
    # same token-internal discipline as every other script). Han
    # extension blocks (U+3400-U+4DBF, U+20000+) are NOT in the
    # class (documented residual).
    r"\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\u1100-\u11ff"
    r"\u3130-\u318f"
    + _INVISIBLE_FORMAT_CLASS + r"]+")

# Shared invisible-format strip for the judge and scope tokenizers
# (F183, extended by the F183 follow-up -- see _INVISIBLE_FORMAT_CLASS).
# Applied per-token: <redacted> aligned.
_INVISIBLE_FORMAT_RE = re.compile("[" + _INVISIBLE_FORMAT_CLASS + "]")


def _strip_invisible_format(token):
    """Remove invisible format chars (see _INVISIBLE_FORMAT_CLASS)
    from one token. NFKC alone is insufficient -- these are Cf
    characters and survive normalization (measured)."""
    return _INVISIBLE_FORMAT_RE.sub("", token)
_SCOPE_ELISION_RE = re.compile(r"^(?:n|d|l|s|c|j|t|qu)['’]")

_VERB_CLASSES = {
    "SEND": frozenset((
        "send", "sends", "sending", "sent",
        "senden", "sendet", "sende",
        "envoyer", "envoyez", "envoie", "envoient",
        "enverrai", "enverrais", "enverra", "enverront",
        "enviar", "envia", "enviado",
        "bhejo", "bhejna", "bhej", "bheje",
        # Wave-149: Devanagari SEND forms (pilot).
        "भेजें", "भेजना", "भेजो", "भेजे", "भेजा", "भेज",
        # Wave-150: भेजिए (polite imperative) -- the common form in
        # countermand requests ("कृपया न भेजिए").
        "भेजिए",
        # Wave-151: Russian Cyrillic SEND forms (pilot). Natural
        # spellings; the й->и / ё->е folded duplicates are ALSO
        # carried because the scope path folds (_fold_accents) while
        # the judge does not -- e.g. "отправляйте" folds to
        # "отправляите", so both spellings must be in the table for
        # both paths to match (pinned in the battery's fold probe).
        "отправлять", "отправить", "отправьте", "отправляйте",
        "отправляите", "отправляй", "отправляи", "отправь",
        "отправляет", "отправляют",
        "отправил", "отправила", "отправили", "отправлен",
        "отправлён", "послать", "посылать", "пошлите",
        # Wave-152: Arabic SEND forms (pilot -- MSA). أرسل (imperative
        # "send!"), ترسل (2nd-person imperfect -- the prohibition
        # "لا ترسل"), يرسل (3rd-person imperfect), إرسال (verbal noun
        # "sending"), أرسلت (1st/2nd-person past -- the ما/لم
        # "ما أرسلت" negation shape). The bare-alef spellings
        # (ارسل/ارسال) are the common un-hamza'd colloquial
        # orthography, carried deliberately (not fold artifacts:
        # the wave-152 fold preserves the Arabic block, so أرسل never
        # folds to ارسل).
        "أرسل", "ارسل", "ترسل", "يرسل", "إرسال", "ارسال", "أرسلت",
        # Wave-153: CJK SEND forms (pilot -- Mandarin/Japanese/
        # Korean). Mandarin 发送 ("send/emit"), 寄送 ("send/ship" --
        # the parcel/postal verb, also used for documents);
        # Japanese 送信 ("transmit" -- the email/file verb),
        # 送る (dictionary form); Korean 보내다 (dictionary form),
        # 보내 (stem -- the 보내지 마 prohibition shape), 전송
        # (hanja "transmit", 전송하다). No fold duals needed: the
        # wave-153 fold preserves the CJK blocks verbatim. The
        # single-char Mandarin 发 is deliberately absent (it would
        # substring-match 发现 "discover" -- a measured FP class).
        "发送", "寄送", "送信", "送る", "보내다", "보내", "전송",
    )),
    "ARCHIVE": frozenset((
        "archive", "archives", "archiving", "archived",
        "archivieren", "archiviert", "archiviere",
        "archiver", "archivez",
        # Wave-149: Devanagari ARCHIVE forms (pilot): संग्रहित/
        # संग्रहीत are the native equivalents; आर्काइव is the
        # common tech loanword.
        "संग्रहित", "संग्रहीत", "आर्काइव",
    )),
    "DELETE": frozenset((
        "delete", "deletes", "deleting", "deleted",
        "loeschen", "loschen", "loescht", "loesche", "geloescht",
        "supprimer", "supprime",
        # Wave-149: Devanagari DELETE forms (pilot): हटाना
        # (remove/take away) and मिटाना (erase) families.
        "हटाएँ", "हटाना", "हटाओ", "हटाए", "हटा",
        "मिटाएँ", "मिटाना", "मिटाओ", "मिटाए", "मिटा",
        # Wave-151: Russian Cyrillic DELETE forms (pilot; same
        # dual-spelling discipline as SEND -- удалён/удален,
        # удаляй/удаляи, удаляйте/удаляите). The imperfective
        # imperatives (удаляй/удаляйте) are the natural countermand
        # forms ("не удаляйте" -- caught missing by the wave-151
        # battery's judge probe, fixed same wave).
        "удалить", "удалите", "удали", "удалять", "удаляй",
        "удаляи", "удаляйте", "удаляите", "удалил",
        "удалила", "удалили", "удалён", "удален", "стереть",
        "сотрите", "сотри",
        # Wave-152: Arabic DELETE forms (pilot -- MSA). احذف
        # (imperative "delete!"), تحذف (2nd-person imperfect -- "لا
        # تحذف"), يحذف (3rd-person imperfect), حذف (verbal noun
        # "deletion" / 3rd-person past "he deleted"), حذفت
        # (1st/2nd-person past -- the ما/لم negation shape).
        "احذف", "تحذف", "يحذف", "حذف", "حذفت",
        # Wave-153: CJK DELETE forms (pilot -- Mandarin/Japanese/
        # Korean). Mandarin 删除; Japanese 削除; Korean 삭제
        # (삭제하다). No fold duals needed (verbatim CJK fold).
        "删除", "削除", "삭제",
    )),
    # Wave-148 (row 7): tier-2 verb classes. Same closed-list
    # discipline as tier 1: every form below was measured against
    # labeled sentences at the +-8 token scope window (see
    # evals/negation_verb_tier2_probes.py: 54 labeled sentences, 0
    # misses; the 47-sentence precision corpus holds 0 false
    # revocations). Language notes:
    # - DE umlaut/eszett forms are carried BOTH as traditional
    #   transcriptions ("schwaerzen", "veroeffentlichen") AND as
    #   NFKD-folded forms ("schwarzen", "veroffentlichen") -- real
    #   text with umlauts is accent-folded before scope
    #   tokenization (see _fold_accents), which maps ä->a (not ae).
    # - FR/ES accented forms are carried folded ("transferer",
    #   "reenvie") for the same reason; the _NEGATION_RE cue list
    #   is untouched (it matches raw text).
    # - HI forms are romanized; English loanwords ("forward",
    #   "upload") are the realistic romanized-Hindi verbs for
    #   these actions and double as EN forms (harmless: the class
    #   is language-agnostic by design).
    # - German separable verbs (hoch+laden, weiter+leiten) are NOT
    #   single tokens in main clauses ("laden Sie es nicht hoch"),
    #   so they are matched by the _DE_SEPARABLE particle+stem
    #   rule below, not by this table; the infinitives
    #   ("hochladen", "weiterzuleiten") ARE single tokens and live
    #   here.
    # - Wave-151 (row 7): Cyrillic (Russian) pilot covers
    #   SEND/DELETE/SHARE only. ARCHIVE/REDACT carry no Cyrillic,
    #   Arabic, or CJK forms -- real verbs for these
    #   (архивировать, цензурировать) exist but are deliberately
    #   out of scope (documented residual; row 7 stays PARTIAL).
    #   The row-7 verb-expansion work extended the Cyrillic,
    #   Arabic, and CJK pilots to PUBLISH/FORWARD/UPLOAD and added
    #   the GRANT/REVOKE/LEAK classes in all five scripts.
    "REDACT": frozenset((
        "redact", "redacts", "redacting", "redacted",
        "schwaerzen", "schwaerzt", "schwaerze", "geschwaerzt",
        "schwarzen", "schwarzt", "schwarze", "geschwarzt",
        "caviarder", "caviardez", "caviarde", "caviardent",
        "censurar", "censura", "censure", "censurado",
        "hatao", "hataana", "hataaya", "hataate",
        # Wave-150: Devanagari REDACT forms. छिपाना/छिपाएँ/छिपाओ/
        # छिपाए/छिपा (hide) and ढकना/ढकें/ढको (cover) are the native
        # verb families; सेंसर is the tech loanword ("सेंसर करें").
        "छिपाना", "छिपाएँ", "छिपाओ", "छिपाए", "छिपा",
        "ढकना", "ढकें", "ढको",
        "सेंसर",
    )),
    "SHARE": frozenset((
        "share", "shares", "sharing", "shared",
        "teilen", "teilt", "teile", "geteilt",
        "partager", "partagez", "partage", "partagent",
        "compartir", "comparte", "comparta", "compartido",
        "baanto", "baantna", "baante", "baanta",
        # Wave-150: Devanagari SHARE forms. बाँटना/बाँटें/बाँटो/बाँटे/
        # बाँटा/बाँट (distribute) is the native family; साझा is the
        # "share" of साझा करना.
        "बाँटना", "बाँटें", "बाँटो", "बाँटे", "बाँटा", "बाँट",
        "साझा",
        # Wave-151: Russian Cyrillic SHARE forms (pilot):
        # поделиться/делиться ("to share") families. No folded
        # duplicates needed (no й/ё in these forms -- verified).
        "поделиться", "поделитесь", "поделись", "делись",
        "делиться", "делитесь", "поделился", "поделились",
        # Wave-152: Arabic SHARE forms (pilot -- MSA). شارك
        # (imperative "share!"), تشارك (2nd-person imperfect -- "لا
        # تشارك"), يشارك (3rd-person imperfect), مشاركة (verbal noun
        # "sharing"), شاركت (1st/2nd-person past).
        "شارك", "تشارك", "يشارك", "مشاركة", "شاركت",
        # Wave-153: CJK SHARE forms (pilot -- Mandarin/Japanese/
        # Korean). Mandarin 分享; Japanese 共有 ("share" -- also
        # the adjective "common", an acknowledged precision
        # boundary), シェア (katakana loanword); Korean 공유
        # (공유하다). No fold duals needed (verbatim CJK fold).
        # SHARE has no share tool in _TOOL_VERBS, so these live in
        # the similarity-countermand scope path only -- same as
        # Latin/Cyrillic/Arabic.
        "分享", "共有", "シェア", "공유",
    )),
    "PUBLISH": frozenset((
        "publish", "publishes", "publishing", "published",
        "post", "posts", "posting", "posted",
        "posten", "postet", "postete", "gepostet",
        "poster", "postez", "poste", "postent",
        "veroeffentlichen", "veroeffentlicht", "veroeffentliche",
        "veroffentlichen", "veroffentlicht", "veroffentliche",
        "publier", "publiez", "publie", "publient",
        "publicar", "publica", "publique", "publicado",
        "chhaapo", "chhaapna", "chhaape", "chhaapa",
        # Wave-150: Devanagari PUBLISH forms. छापना/छापें/छापो/छापे/
        # छापा/छाप (print/publish) is the native family; प्रकाशित is
        # the formal "published" (प्रकाशित करें).
        "छापना", "छापें", "छापो", "छापे", "छापा", "छाप",
        "प्रकाशित",
        # Row-7 verb expansion: Cyrillic (Russian) PUBLISH forms.
        # опубликовать/публиковать ("to publish") families plus
        # разместить/разместить ("to place/post content"). The
        # й->и fold duals are carried (same discipline as SEND:
        # the scope path folds while the judge does not).
        "опубликовать", "опубликуйте", "опубликуй",
        "опубликуите", "опубликуи",
        "публиковать", "публикуйте", "публикуите",
        "публикует", "опубликовано", "опубликуют",
        "разместить", "разместите", "размещать",
        # Row-7 verb expansion: Arabic (MSA) PUBLISH forms. انشر
        # (imperative "publish!"), تنشر (2nd-person imperfect),
        # ينشر (3rd-person imperfect), نشر (verbal noun/past),
        # نشرت (1st/2nd-person past). Bare-alef spellings: انشر
        # has no hamza, so no dual is needed.
        "انشر", "تنشر", "ينشر", "نشر", "نشرت",
        # Row-7 verb expansion: CJK PUBLISH forms. Mandarin 发布
        # ("publish/release"), 公开 ("make public"), 发表
        # ("publish an article"), 刊登 ("carry in print"); Japanese
        # 公開/公表 ("make public/announce"), 投稿 ("post/
        # contribute"), 掲載 ("publish/carry"). Korean 게시 is
        # deliberately absent: it substrings-matches 게시판
        # ("bulletin board") -- a measured FP class of the same
        # shape as the excluded single-char 发 (cf. 发现).
        "发布", "公开", "发表", "刊登",
        "公開", "公表", "投稿", "掲載",
    )),
    "FORWARD": frozenset((
        "forward", "forwards", "forwarding", "forwarded",
        "weiterleiten", "weiterleite", "weitergeleitet",
        "weiterzuleiten",
        "transferer", "transferez", "transfere", "transferent",
        "reenviar", "reenvia", "reenvie", "reenviado",
        # Wave-150: Devanagari FORWARD forms. फॉरवर्ड is the realistic
        # loanword ("फॉरवर्ड करें"); अग्रेषित is the formal
        # "forwarded" (अग्रेषित करें).
        "फॉरवर्ड",
        "अग्रेषित",
        # Row-7 verb expansion: Cyrillic (Russian) FORWARD forms.
        # переслать/пересылать ("to forward") families, with the
        # й->и fold dual for пересылайте.
        "переслать", "перешлите", "перешли",
        "пересылать", "пересылайте", "пересылаите",
        "переслал", "пересылает",
        # Row-7 verb expansion: Arabic (MSA) FORWARD forms. وجّه
        # (imperative "direct/forward!") with the unvocalized dual
        # وجه (shadda-dropping is the common orthography), يوجّه
        # (3rd-person imperfect), توجيه (verbal noun "forwarding").
        "وجّه", "وجه", "يوجّه", "توجيه",
        # Row-7 verb expansion: CJK FORWARD forms. Mandarin 转发
        # ("forward"), 转交 ("hand over"); Japanese 転送
        # ("forward"); Korean 전달 (전달하다, "deliver/forward").
        "转发", "转交", "転送", "전달",
    )),
    "UPLOAD": frozenset((
        "upload", "uploads", "uploading", "uploaded",
        "hochladen", "hochlade", "hochgeladen", "hochzuladen",
        "telecharger", "telechargez", "telecharge", "telechargent",
        "subir", "sube", "suba", "subido",
        "cargar", "carga", "cargue", "cargado",
        # Wave-150: Devanagari UPLOAD form. अपलोड is the realistic
        # loanword ("अपलोड करें"); native चढ़ाना is not the
        # file-upload verb in practice, so it is deliberately absent.
        "अपलोड",
        # Row-7 verb expansion: Cyrillic (Russian) UPLOAD forms.
        # загрузить/загружать ("to upload") families, with the
        # й->и fold dual for загружайте.
        "загрузить", "загрузите", "загрузи",
        "загружать", "загружайте", "загружаите",
        "загрузил", "загружено",
        # Row-7 verb expansion: Arabic (MSA) UPLOAD forms. ارفع
        # (imperative "upload!"), ترفع (2nd-person imperfect),
        # يرفع (3rd-person imperfect), رفع (verbal noun/past),
        # رفعت (1st/2nd-person past).
        "ارفع", "ترفع", "يرفع", "رفع", "رفعت",
        # Row-7 verb expansion: CJK UPLOAD forms. Mandarin 上传
        # ("upload"), 上载; Japanese アップロード (katakana
        # loanword); Korean 업로드 (loanword), 올리다/올려 (native
        # "put up" -- the upload verb in practice).
        "上传", "上载", "アップロード", "업로드", "올리다", "올려",
    )),
    # Row-7 verb expansion: GRANT -- giving access or permission.
    # No product tool maps to this class (SHARE precedent, wave-151):
    # its forms live in the similarity-countermand scope path and
    # the cue path. Same closed-list discipline as tier 2.
    "GRANT": frozenset((
        "grant", "grants", "granting", "granted",
        "gewaehren", "gewaehre", "gewaehrt", "gewaehrte",
        "gewahren", "gewahre", "gewahrt", "gewahrte",
        "accorder", "accordez", "accorde", "accordent",
        "otorgar", "otorga", "otorgue", "otorgado", "otorgan",
        "conceder", "concede", "conceda", "concedido", "conceden",
        "pradaan",
        # Devanagari GRANT forms: प्रदान ("grant" -- प्रदान करें),
        # अनुमति ("permission" -- अनुमति दें), अधिकृत ("authorized").
        "प्रदान", "अनुमति", "अधिकृत",
        # Cyrillic (Russian) GRANT forms: предоставить/
        # предоставлять ("to grant/provide") families. No й/ё in
        # these forms -- no fold duals needed (verified).
        "предоставить", "предоставьте", "предоставь",
        "предоставляет", "предоставлено", "предоставлять",
        # Arabic (MSA) GRANT forms: امنح (imperative "grant!"),
        # تمنح (2nd-person imperfect), يمنح (3rd-person imperfect),
        # منح (verbal noun/past), منحت (1st/2nd-person past).
        "امنح", "تمنح", "يمنح", "منح", "منحت",
        # CJK GRANT forms: Mandarin 授予 ("confer/grant"), 授权
        # ("authorize"); Japanese 付与 ("confer" -- 許可 is
        # deliberately absent: it substrings-matches 許可証
        # "license", the 게시판-class FP shape); Korean 부여
        # ("grant"), 승인 ("approval"), 허용 ("permission").
        "授予", "授权", "付与", "부여", "승인", "허용",
    )),
    # Row-7 verb expansion: REVOKE -- taking access away.
    # Scope/cue path only (no product tool maps here).
    "REVOKE": frozenset((
        "revoke", "revokes", "revoking", "revoked",
        "widerrufen", "widerrufe", "widerrufst", "widerruft",
        "widerrief",
        "entziehen", "entziehe", "entziehst", "entzieht",
        "entzogen",
        "revoquer", "revoquez", "revoque", "revoquent",
        "revocar", "revoca", "revoque", "revocado", "revocan",
        # Devanagari REVOKE forms: रद्द ("cancel" -- रद्द करें),
        # वापस ("take back" -- वापस लें).
        "रद्द", "वापस",
        # Cyrillic (Russian) REVOKE forms: отозвать/отзывать
        # ("to revoke/recall") families. No й/ё -- no fold duals
        # (verified).
        "отозвать", "отзовите", "отзови",
        "отзывает", "отозван", "отзывать",
        # Arabic (MSA) REVOKE forms: ألغ (imperative "cancel!")
        # with the colloquial bare-alef dual الغ, تلغي
        # (2nd-person imperfect), يلغي (3rd-person imperfect),
        # إلغاء/الغاء (verbal noun "cancellation", hamza dual
        # carried like wave-152's أرسل/ارسل).
        "ألغ", "الغ", "تلغي", "يلغي", "إلغاء", "الغاء",
        # CJK REVOKE forms: Mandarin 撤销 ("revoke"), 取消
        # ("cancel"), 撤回 ("withdraw"); Korean 취소 ("cancel"),
        # 철회 ("withdraw"). Japanese 取消す carries the 取消 form.
        "撤销", "取消", "撤回", "취소", "철회",
    )),
    # Row-7 verb expansion: LEAK -- exfiltration by disclosure.
    # Scope/cue path only (no product tool maps here).
    "LEAK": frozenset((
        "leak", "leaks", "leaking", "leaked",
        "exfiltrate", "exfiltrates", "exfiltrating", "exfiltrated",
        "disclose", "discloses", "disclosing", "disclosed",
        "divulguer", "divulguez", "divulgue", "divulguent",
        "filtrar", "filtra", "filtre", "filtrado", "filtran",
        # Devanagari LEAK form: लीक is the realistic loanword
        # ("लीक करें").
        "लीक",
        # Cyrillic (Russian) LEAK forms: слить/сливать ("to leak",
        # slang) family, with the й->и fold duals for слейте/слей.
        "слить", "слейте", "слей", "слеите", "слеи",
        "сливает", "слив",
        # Arabic (MSA) LEAK forms: سرّب (imperative "leak!") with
        # the unvocalized dual سرب, يسرّب (3rd-person imperfect),
        # تسرّب (2nd-person imperfect), تسريب (verbal noun).
        "سرّب", "سرب", "يسرّب", "تسرّب", "تسريب",
        # CJK LEAK forms: Mandarin 泄露/泄漏 ("leak"); Japanese
        # 漏洩 ("leak"), 流出 ("outflow/leak"); Korean 유출
        # ("leak"), 누출 ("leak").
        "泄露", "泄漏", "漏洩", "流出", "유출", "누출",
    )),
}
_VERB_CLASS_BY_FORM = {
    form: cls for cls, forms in _VERB_CLASSES.items() for form in forms
}


# Wave-153 (row 7): CJK verb-form index for unspaced runs. A CJK
# scope token is a whole unspaced run (不要发送报告), so class
# attribution is closed-list SUBSTRING matching: the token carries
# the class when one of the class's CJK forms occurs in it (发送 in
# 不要发送报告 -> SEND). Longest-first ordering is cosmetic (search
# only needs presence); the forms contain no regex metacharacters.
_CJK_FORM_RES = {
    cls: re.compile("|".join(sorted(
        (f for f in forms if _CJK_CHAR_RE.search(f)),
        key=len, reverse=True)))
    for cls, forms in _VERB_CLASSES.items()
    if any(_CJK_CHAR_RE.search(f) for f in forms)
}


def _cjk_token_classes(normed_token):
    """Classes whose CJK verb form occurs in this scope token.

    Wave-153 (row 7): the unspaced-run analogue of the
    _VERB_CLASS_BY_FORM exact lookup. The forms are a closed list,
    so this is exact-form containment, not stemming: 发 alone is
    deliberately NOT a form (it would match 发现 "discover").
    """
    return {cls for cls, rx in _CJK_FORM_RES.items()
            if rx.search(normed_token)}


# Wave-148 (row 7): German separable verbs for the tier-2 classes.
# In main clauses the particle separates ("laden Sie es nicht
# hoch", "leiten Sie die Kette nicht weiter"), so no single token
# names the verb. A separable verb matches a token list when the
# particle AND a stem form co-occur in the SAME clause/token list:
# the stem requirement is the false-positive guard ("hoch" alone
# means "high"; "weiter" alone means "onward" -- e.g. "Leiten Sie
# das Team weiter" (keep leading the team) must not read as
# FORWARD). Closed table, two entries; other separable verbs are a
# documented residual (row 7 stays PARTIAL).
_DE_SEPARABLE = {
    "UPLOAD": (
        ("hoch", frozenset((
            "laden", "lade", "ladest", "ladet", "lud", "luden",
            "geladen",
        ))),
    ),
    "FORWARD": (
        ("weiter", frozenset((
            "leiten", "leite", "leitest", "leitet", "leiteten",
            "geleitet",
        ))),
    ),
}


def _fold_accents(text):
    """Strip diacritics for scope tokenization (wave-148, row 7).

    NFKD decomposition with combining marks dropped, so
    "transférer" -> "transferer" and "veröffentlichen" ->
    "veroffentlichen" BEFORE the [a-z0-9']+ scope tokenizer runs
    (without this the tokenizer splits "transférer" into "transf" +
    "rer" and no class form ever matches). ASCII text is unchanged,
    so tier-1 behavior is untouched. The negation cue regex
    (_NEGATION_RE) still runs on raw text -- only scope
    tokenization folds. German ß has no NFKD decomposition, so
    ß-forms are carried as ss-transcriptions in the class table
    (same as the tier-1 "loeschen" convention).

    Wave-149 (row 7): Devanagari combining marks (virama U+094D,
    nukta U+093C, ...) are PRESERVED, not stripped. Dropping them
    changes string length ("रिपोर्ट" -> "रिपोरट"), which breaks the
    raw-text cue-span alignment in negation_scopes_grant (the cue
    regex runs on raw text, the tokens on this folded text -- any
    length change before a cue misattributes it). Devanagari has no
    NFKD decompositions, so preserving the block keeps the fold
    length-identical there. Latin diacritic stripping is unchanged.

    Wave-152 (row 7): the Arabic block (U+0600-U+06FF) BYPASSES NFKD
    entirely and is preserved verbatim, for a stronger reason: the
    Arabic hamza letters ALEF WITH HAMZA ABOVE (U+0623 أ), ALEF WITH
    HAMZA BELOW (U+0625 إ), WAW WITH HAMZA (U+0624 ؤ), and YEH WITH
    HAMZA (U+0626 ئ) all HAVE NFKD decompositions into base letter +
    combining hamza, so "أرسل" would decompose to 5 chars ("ا" +
    U+0654 + "رسل") -- breaking both length-identity (cue-span
    alignment) and class-form matching on the scope path (the table
    carries the precomposed U+0623 form). Verbatim preservation
    keeps "أرسل" == "أرسل" and the fold a strict no-op on Arabic:
    no dual-spelling class table is needed (unlike Cyrillic ё/й).
    Tashkeel (U+064B-U+065F, combining) is preserved verbatim too.
    Per-character NFKD for the remaining text is equivalent to the
    old whole-string NFKD for this fold's purpose (combining-mark
    order is irrelevant -- they are all dropped).

    Wave-153 (row 7): the CJK blocks (U+4E00-U+9FFF Han,
    U+3040-U+30FF Hiragana/Katakana, U+AC00-U+D7AF Hangul
    syllables, U+1100-U+11FF/U+3130-U+318F Jamo) BYPASS NFKD
    entirely and are preserved verbatim, for the same strong
    reason as Arabic: Hangul syllables HAVE NFKD decompositions
    into Jamo ("보내지" -> 13 chars from 7), which would break
    cue-span alignment, and Hiragana with dakuten (で -> て +
    combining mark, stripped) would rewrite cue/form text on the
    scope path. Verbatim preservation makes the fold a strict
    no-op on CJK: no dual-spelling class table is needed.
    Fullwidth ASCII (U+FF00-U+FF5E) and halfwidth katakana
    (U+FF61-U+FF9F) are deliberately NOT bypassed: they fold to
    ASCII/fullwidth katakana (length-identical), which is what
    keeps the shared Latin tokens the similarity gate needs.
    Deterministic, stdlib unicodedata only.
    """
    if not isinstance(text, str):
        return ""
    out = []
    for c in text:
        if ("\u0900" <= c <= "\u097f" or "\u0600" <= c <= "\u06ff"
                or "\u4e00" <= c <= "\u9fff"
                or "\u3040" <= c <= "\u30ff"
                or "\uac00" <= c <= "\ud7af"
                or "\u1100" <= c <= "\u11ff"
                or "\u3130" <= c <= "\u318f"):
            # Wave-149/152/153: Devanagari, Arabic and CJK blocks
            # bypass NFKD and are preserved verbatim. (Devanagari
            # has no NFKD decompositions, so verbatim == the old
            # decompose-then-preserve behavior there.)
            out.append(c)
            continue
        for d in unicodedata.normalize("NFKD", c):
            if not unicodedata.combining(d):
                out.append(d)
    return "".join(out)


def _separable_verb_hits(normed):
    """index -> class for German separable verbs in a token list.

    For each (particle, stems) entry: when the particle token and at
    least one stem token both occur in the list, every particle and
    stem token index is marked with the class (both parts are verb
    positions for the +-8 window -- in "laden Sie es nicht hoch" the
    cue "nicht" sits next to the particle "hoch").
    """
    hits = {}
    present = set(normed)
    for cls, pairs in _DE_SEPARABLE.items():
        for particle, stems in pairs:
            if particle in present and (present & stems):
                for i, tok in enumerate(normed):
                    if tok == particle or tok in stems:
                        hits[i] = cls
    return hits


def _scope_norm_token(token):
    """Lowercase + strip French-style elision prefixes (n'/d'/l'/...)
    so "n'envoyez" matches the SEND class as "envoyez". F183: also
    strips invisible format chars so a bidi-split verb
    form still resolves to its class."""
    tok = _strip_invisible_format(token.lower().replace("’", "'"))
    return _SCOPE_ELISION_RE.sub("", tok)


def _anchor_verb_classes(anchor_text):
    """Verb classes named by the anchor clause (the intent's action
    verb, measured against the anchor clause). Wave-148: the text
    is accent-folded before tokenization (so "transférer" matches
    the folded "transferer" form) and German separable verbs
    (particle+stem in the same text) contribute their class."""
    classes = set()
    normed = [_scope_norm_token(tok) for tok in
              _SCOPE_WORD_RE.findall(
                  _fold_accents(anchor_text.lower()))]
    for tok in normed:
        cls = _VERB_CLASS_BY_FORM.get(tok)
        if cls is not None:
            classes.add(cls)
        # Wave-153 (row 7): CJK runs are unspaced -- the class form
        # is a substring of the token (发送 in 把Q3报告发送给vendor).
        classes.update(_cjk_token_classes(tok))
    classes.update(_separable_verb_hits(normed).values())
    return classes


def negation_scopes_grant(message, anchor_text,
                          window=_NEGATION_SCOPE_WINDOW):
    """True iff the negation cue in `message` may cancel the intent
    anchored at `anchor_text`: some cue falls within `window` tokens
    of the anchor's action verb in the same clause, or the message
    names no grant verb at all (conservative pre-wave-147 behavior).
    False when the grant verb appears in a clause of its own, apart
    from every cue -- the negation demonstrably scopes elsewhere."""
    if not isinstance(message, str) or not message.strip():
        return True
    anchor_classes = _anchor_verb_classes(
        anchor_text if isinstance(anchor_text, str) else "")
    if not anchor_classes:
        # Unknown action verb: the scope check cannot attribute, so it
        # must not narrow -- keep the pre-wave-147 behavior.
        return True
    verb_seen = False
    for clause in _CLAUSE_SPLIT_RE.split(message):
        # Wave-148: accent-fold before scope tokenization (folding
        # preserves string length for precomposed Latin diacritics,
        # so the raw-text cue spans below still align with these
        # token indices).
        toks = list(_SCOPE_WORD_RE.finditer(
            _fold_accents(clause.lower())))
        if not toks:
            continue
        normed = [_scope_norm_token(t.group(0)) for t in toks]
        sep_hits = _separable_verb_hits(normed)
        verb_idx = [i for i, n in enumerate(normed)
                    if _VERB_CLASS_BY_FORM.get(n) in anchor_classes
                    or sep_hits.get(i) in anchor_classes
                    # Wave-153 (row 7): CJK class forms match as
                    # substrings of unspaced runs.
                    or _cjk_token_classes(n) & anchor_classes]
        if verb_idx:
            verb_seen = True
        cue_idx = set()
        for m in _NEGATION_RE.finditer(clause):
            s, e = m.span()
            for i, t in enumerate(toks):
                if t.start() < e and t.end() > s:
                    cue_idx.add(i)
        if (cue_idx and verb_idx
                and any(abs(c - v) <= window
                        for c in cue_idx for v in verb_idx)):
            return True
    return not verb_seen

# Wave-146 (row 7): English double-negation resolution. Two negation
# cues in a bounded same-sentence construction that cancel into
# affirmation ("There is no reason not to send the Q3 report") must
# not read as a countermand. The resolver is deliberately narrow and
# English-only; anything ambiguous keeps the cue (conservative:
# revoke). Two positive-resolution patterns:
#
# 1. NO_X_NOT_TO_V: "no <noun> not to <verb>" (and the split
#    infinitive "no <noun> to not <verb>") -- "there is no reason not
#    to send", "we see no need to not comply". Bounded: 1-2 words
#    between "no" and the second cue, same sentence (the word gaps
#    cannot cross sentence punctuation). The "no" keeps its
#    wave-145 "no problem" guard; "not" keeps its "not only" guard.
# 2. NOT_NEGWORD: a negation cue ("not"/"n't"/"never") directly
#    followed (0-1 light adverbs) by a closed-list negative-polarity
#    word -- "don't disagree", "not uncommon", "cannot deny". The
#    list is CLOSED, not productive prefix matching: "Don't
#    distribute" must still revoke (dis- trap), so distribute/
#    discuss/disclose and friends are absent by design.
#
# Explicitly NOT resolved (conservative revoke):
# - stacked emphasis on one predicate: "Never, under no
#   circumstances, send it" (two cues, no cancellation structure);
# - ambiguous stacking: "I don't think we should not send it";
# - single negation: "Do not send the Q3 report";
# - non-English double negation (German "nicht unmoeglich" etc.):
#   the word lists are English, so behavior there is unchanged.
# - "no reason not to <verb>" where the verb contradicts the grant
#   ("no reason not to cancel" vs a send grant): linguistically an
#   affirmation of <verb>, not a negation -- the negation-gated
#   signal stays silent; contradiction-without-negation is the
#   documented paraphrase ceiling, not this seam.
_DOUBLE_NEG_NO_X_NOT_TO_RE = re.compile(
    r"\bno(?!\s+problems?\b)(?:\s+[a-z0-9']+){1,2}\s+"
    r"(?:not(?!\s+only\b)\s+to|to\s+not(?!\s+only\b))\b",
    re.IGNORECASE)
# Closed negative-polarity list for NOT_NEGWORD (see above: no
# productive un-/in-/dis- prefixes -- "distribute" must not match).
_NEGATIVE_POLARITY_WORDS = frozenset(
    "uncommon unlikely impossible improbable unaware unwise unfair "
    "untrue unjust unreasonable unhelpful insignificant inappropriate "
    "inadequate incomplete incorrect disagree deny doubt refuse reject "
    "fail lack miss oppose object dislike distrust disapprove "
    "without".split())
_DOUBLE_NEG_NOT_NEGWORD_RE = re.compile(
    r"(?:\bnot(?!\s+only\b)|\bnever|n['\u2019]?t)"
    r"(?:\s+(?:quite|very|entirely|really|simply))?\s+("
    + "|".join(sorted(_NEGATIVE_POLARITY_WORDS)) + r")\b",
    re.IGNORECASE)
# Sentence splitter for the same-sentence bound.
_DOUBLE_NEG_SENTENCE_RE = re.compile(r"[^.!?;]+")


def _english_double_negation_cancels(message):
    """Wave-146 row 7: positively-resolved English double negation?

    True when ``message`` contains two English negation cues in a
    bounded same-sentence construction that cancel into affirmation
    (the NO_X_NOT_TO_V or NOT_NEGWORD patterns above). Callers
    suppress the negation cue (do not revoke). English only;
    ambiguous stacking and stacked emphasis return False
    (conservative: keep the cue, revoke). Deterministic, stdlib
    ``re`` only.
    """
    if not isinstance(message, str) or not message.strip():
        return False
    for sent in _DOUBLE_NEG_SENTENCE_RE.findall(message):
        if _DOUBLE_NEG_NO_X_NOT_TO_RE.search(sent):
            return True
        if _DOUBLE_NEG_NOT_NEGWORD_RE.search(sent):
            return True
    return False
_TOOL_VERBS = {
    "delete_file": ("delet", "remov", "eras", "wipe", "clean", "clear",
                    "trash"),
    "send_email": ("send", "email", "mail"),
    "http_post": ("post", "upload", "submit", "publish", "push"),
    "write_file": ("write", "creat", "save", "draft"),
    "read_file": ("read", "open", "load", "summar", "review"),
    "api_call": ("call", "query", "fetch", "invoke"),
}

# Slot patterns: the extractable parameters an intent anchor carries.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?:/[\w.\-~]+)+/?|(?:[A-Za-z]:)?[\\/][\w.\-\\/~]+")

_STOPWORDS = frozenset(
    "a an the and or but if then else when at by for with about into "
    "through during before after above below to from up down in out on "
    "off over under again further once here there all any both each few "
    "more most other some such no nor not only own same so than too very "
    "can will just don should now of is are was were be been being have "
    "has had having do does did doing would could ought i you he she it "
    "we they them his her its our their this that these those am as me "
    "my your youre im ive dont isnt its lets".split())

# Minimum shared content tokens for a token-overlap relevance claim.
_OVERLAP_THRESHOLD = 2
# Tokens scanned backwards from a verb for negation scope.
_NEGATION_WINDOW = 6


def _tokens(text):
    """Content tokens: lowercased alphanumeric words, stopwords and
    1-2 char fragments dropped, canonical light stemming (a trailing
    's' is stripped so "emails" and "email" share one token -- the
    stem REPLACES the word, so one shared word counts once).
    Deterministic."""
    if not text:
        return set()
    words = re.findall(r"[a-z0-9]+", str(text).lower())
    out = set()
    for w in words:
        if len(w) <= 2 or w in _STOPWORDS:
            continue
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        out.add(w)
    return out


def _extract_slots(text):
    """Extractable intent slots from free text.

    Returns {"emails": set, "urls": set, "paths": set}. Quoted text is
    NOT excluded here -- callers doing target comparison must use the
    tool-aware target slot, not raw text slots (an action quoting the
    latest message must not launder a contradictory target).
    """
    t = str(text or "")
    return {
        "emails": set(m.lower() for m in _EMAIL_RE.findall(t)),
        "urls": set(m.lower().rstrip(".,;:") for m in _URL_RE.findall(t)),
        "paths": set(_PATH_RE.findall(t)),
    }


def _action_target_slot(tool, args):
    """The tool-aware PRIMARY target of an action: the slot the latest
    intent's same-class slots are compared against.

    This is the quoting defense: for send_email the target is the
    recipient (args["to"]), not every email mentioned in the body. An
    action that quotes the latest message while targeting a different
    recipient contradicts the latest intent regardless of the quote.
    Returns (slot_class, value) or (None, None).
    """
    args = args or {}
    if not isinstance(args, dict):
        return (None, None)
    if tool == "send_email":
        for k in ("to", "recipient", "to_email", "email"):
            v = args.get(k)
            if v:
                return ("emails", str(v).lower())
    elif tool == "http_post":
        for k in ("url", "endpoint", "target"):
            v = args.get(k)
            if v:
                return ("urls", str(v).lower().rstrip(".,;:"))
    elif tool in ("read_file", "write_file", "delete_file"):
        for k in ("path", "file", "filename", "filepath"):
            v = args.get(k)
            if v:
                return ("paths", str(v))
    elif tool == "api_call":
        for k in ("url", "endpoint"):
            v = args.get(k)
            if v:
                return ("urls", str(v).lower().rstrip(".,;:"))
    return (None, None)


def _slot_contradiction(tool, args, latest_text):
    """True when the action's primary target contradicts the latest
    intent's same-class slots: the latest message names at least one
    slot of that class and the action's target matches none of them.

    Paths compare by prefix ("/tmp/scratch/x" serves "/tmp/scratch");
    URLs compare by prefix; emails compare exactly.
    """
    cls, target = _action_target_slot(tool, args)
    if cls is None or not target:
        return False
    want = _extract_slots(latest_text).get(cls, set())
    if not want:
        return False  # latest names no slot of this class: no claim
    if cls == "emails":
        return target not in want
    # paths / urls: the target serves the intent when it is under (or
    # equal to) a wanted slot.
    t = target.lower()
    for w in want:
        w = w.lower()
        if t == w or t.startswith(w.rstrip("/") + "/") or \
                w.startswith(t.rstrip("/") + "/"):
            return False
    return True


def _verb_stems(tool):
    return _TOOL_VERBS.get(tool, (tool.replace("_", " "),))


# Wave-150 (row 7): Devanagari-aware tokenizer for the _negated_verb
# judge. The old [a-z']+ tokenizer dropped every Devanagari token, so
# the judge was Latin-only and Devanagari countermands reached only
# the similarity-countermand signal. The Devanagari range mirrors
# _SCOPE_WORD_RE (danda U+0964/U+0965 excluded, so "भेजें।"
# tokenises as "भेजें" and the danda stays a token boundary).
# Wave-151 (row 7): Cyrillic block added for the Russian pilot (same
# range as _SCOPE_WORD_RE).
# Wave-152 (row 7): Arabic block (U+0600-U+06FF) added for the
# Arabic pilot (same range as _SCOPE_WORD_RE).
# Wave-153 (row 7): CJK blocks added for the CJK pilot (same ranges
# as _SCOPE_WORD_RE: Han, Hiragana/Katakana, Hangul syllables,
# Jamo). CJK runs are unspaced, so one token is a whole run; the
# cue/verb match inside it is substring-based
# (_cjk_token_negates), not whole-token.
# F183-follow-up (row 7): the invisible-format class (_INVISIBLE_FORMAT_CLASS)
# is token-internal here too (same treatment as _SCOPE_WORD_RE -- see the note there), and is
# stripped per-token in _negated_verb before matching.
_NEGATED_VERB_TOKEN_RE = re.compile(r"[a-z'\u0400-\u04FF\u0900-\u0963\u0966-\u097F\u0600-\u06FF\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\u1100-\u11ff\u3130-\u318f" + _INVISIBLE_FORMAT_CLASS + r"]+")

# Wave-150 (row 7): tool -> tier-1/tier-2 verb classes whose
# Devanagari forms the judge matches natively. The Latin prefix-stem
# discipline is untouched; the Devanagari match is exact against the
# closed class table (the same closed-list discipline as
# _VERB_CLASS_BY_FORM), so Latin behavior is bit-identical and only
# Devanagari gains judge coverage. Tools with no class mapping keep
# the pre-wave-150 behavior.
# Wave-151 (row 7): the same native match now also carries the
# Cyrillic (Russian) SEND/DELETE forms (SHARE has no share tool in
# _TOOL_VERBS, so SHARE Cyrillic forms live in the
# similarity-countermand scope path only -- same as Latin, which
# also has no share tool).
# Row-7 verb expansion: FORWARD/GRANT/REVOKE/LEAK likewise have no
# product tool, so their forms (all scripts) live in the scope path
# and the cue path only -- the SHARE precedent. If a grant/revoke
# tool ever exists, map it here the way http_post maps to
# (PUBLISH, UPLOAD).
_TOOL_VERB_CLASSES = {
    "send_email": ("SEND",),
    "delete_file": ("DELETE",),
    "http_post": ("PUBLISH", "UPLOAD"),
}


# Wave-153 (row 7): CJK in-token negation for _negated_verb.
# CJK runs are unspaced, so the cue and the verb form are
# substrings of one token (Chinese/Japanese) or adjacent tokens
# (Korean V-지 마, which is spaced). A prohibitive cue that scopes
# the verb from the FRONT (不要/别/停止/... + verb, 止めて/
# キャンセル + verb) must END within _CJK_CUE_GAP chars before the
# verb form -- the unspaced analogue of the pre-verb token window;
# the lookback spans at most one token boundary (Korean eojeol).
# Postposed/suffixal negation is handled per language: Japanese
# verb + しない(で) (送信しないで) or 送信を止めて (cue after the
# verb with a case particle); Korean verb + (하)지 마 (삭제하지
# 마 -- the 하 of -하다 conjugations); Korean 전송을 취소해
# (object particle + cue after the verb). The cue guards
# (不要紧, 别人/别的/..., dropped bare ない) are the same
# alternatives as _CJK_NEG_SRC, so the search-form and judge
# disciplines agree.
_CJK_CUE_GAP = 4
_CJK_PRE_CUE_SRC = (
    r"(?:不行|不要(?!紧)|别(?!人|的|处|样|名)|"
    r"停止|取消|止めて|キャンセル|취소|중지|말고)"
)
_CJK_PRE_CUE_TAIL_RE = re.compile(
    r"(?:" + _CJK_PRE_CUE_SRC + r").{0," + str(_CJK_CUE_GAP) + r"}$")
_CJK_POST_CUE_RE = re.compile(
    r"^(?:しない(で)?"                    # 送信しない(で)
    r"|(?:の|を|は|が)?\s*(?:止めて|キャンセル)"  # 送信を止めて
    r"|하?지\s*마"                        # 삭제하지 마
    r"|(?:을|를)?\s*(?:취소|중지|말고))")  # 전송을 취소해
# NOTE: the \s* after the optional particle covers the
# tail/next-token join ("을" + " " + "취소해"); in-token cases
# (を止めて) have no space.


def _cjk_token_negates(tok, cjk_forms, tokens, i):
    """True when this CJK run token negates one of the tool's native
    CJK verb forms: a listed cue scopes the form from the front
    (within _CJK_CUE_GAP chars, spanning at most one token
    boundary), or the form carries postposed/suffixal negation
    (Japanese しない(で)/を止めて, Korean (하)지 마/을 취소해).

    ``tok`` is already invisible-format-stripped (F183: a zero-width
    char inside the cue/form cannot split the match -- stripping
    restores the visible text, and only the visible text is
    matched). ``tokens``/``i`` locate the token for the adjacent-
    token checks (Korean eojeol).
    """
    prev = tokens[i - 1] if i > 0 else ""
    nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
    for form in cjk_forms:
        fi = tok.find(form)
        if fi < 0:
            continue
        head, tail = tok[:fi], tok[fi + len(form):]
        # Cue-before-form: 不要/别/停止/取消/止めて/... scopes the
        # verb from the front (不要发送, 别删除).
        if _CJK_PRE_CUE_TAIL_RE.search(
                prev[-_CJK_CUE_GAP * 2:] + head):
            return True
        # Cue-after-form: 送信しない(で), 送信を止めて,
        # 삭제하지 마, 전송을 취소해.
        if _CJK_POST_CUE_RE.match(tail + " " + nxt):
            return True
    return False


# F188 (row 7): Latin negation cues for the glued-cue judge branch
# below. A Latin cue glued to a non-Latin verb form with zero
# whitespace ("do not发送") fuses into one tokenizer run, so the
# cue is matched as a SUFFIX of the text before the form -- with a
# leading \b so "cannot" (not a cue, consistent with "cannot send"
# staying silent) cannot match via its "not" tail. Two-word cues
# ("do not") are covered by the one-token lookback in
# _latin_glued_cue_negates. The wave-145 guards are vacuous here:
# the cue must END where the form begins, so nothing can follow it.
_LATIN_GLUED_CUE_RE = re.compile(
    r"\b(?:don'?t|dont|do not|doesn'?t|doesnt|never|not|no|"
    r"stop|halt|cease|avoid|refrain|cancel|"
    r"nicht|kein|keine|keinen|keinem|keiner|keines|"
    r"keinerlei|keinesfalls|keineswegs|nahi)$"
)


def _latin_glued_cue_negates(tok, native_forms, tokens, i):
    """F188: True when a non-ASCII native verb form is glued inside
    this token and a Latin negation cue abuts the form's left edge
    ("do not发送", "do notотправляйте", "do notأرسل").

    The tokenizer fuses the glued run, so the exact native-form
    match in _negated_verb misses and _CJK_PRE_CUE_SRC only knows
    CJK cues. The cue may span the token boundary for two-word
    cues, so the check runs over (previous token + head); the cue
    must END exactly where the form begins, so a cue elsewhere in
    the run cannot fire this branch. ``tok`` is already
    invisible-format-stripped (F183: a zero-width char inside the
    glued cue cannot split the match)."""
    for form in native_forms:
        if form.isascii():
            continue
        fi = tok.find(form)
        if fi < 0:
            continue
        head = tok[:fi]
        context = (tokens[i - 1] + " " if i > 0 else "") + head
        if _LATIN_GLUED_CUE_RE.search(context):
            return True
    return False


def _negated_verb(latest_text, tool):
    """True when the latest message negates the action's verb within a
    token window ("don't delete", "never send anything"). Direct
    evidence in the rubric sense.

    Wave-150 (row 7): Devanagari-native. The tokenizer now walks the
    Devanagari block, and a verb token matches either the Latin
    prefix stems (unchanged) or -- exactly -- the tool's verb-class
    Devanagari forms. The negation window stays pre-verb (6 tokens),
    so a post-verbal tag cue ("भेज दी है न?") is natively silent: the
    scope-window discipline applies in the judge, not just in the
    similarity-countermand path.

    F183 (row 7): invisible zero-width format chars (U+200B/U+200C/
    U+200D/U+FEFF, bidi controls, direction marks and other Cf chars)
    countermand that renders identically to a human cannot split the
    verb/cue token and slip the exact match.

    Wave-153 (row 7): CJK-native. CJK runs are unspaced, so the cue
    and the verb form are substrings of one token (Chinese/
    Japanese) or adjacent tokens (Korean V-지 마) -- see
    _cjk_token_negates. The branch runs independently of the Latin
    pre-verb window (a mixed token like "email不要发送" carries its
    cue in-token).
    """
    tokens = [_strip_invisible_format(t) for t in
              _NEGATED_VERB_TOKEN_RE.findall(
                  str(latest_text or "").lower())]
    tokens = [t for t in tokens if t]
    stems = _verb_stems(tool)
    # Wave-151 (row 7): renamed from deva_forms -- the exact
    # non-ASCII class-form match now also carries the Cyrillic
    # (Russian) SEND/DELETE forms. Latin behavior is unchanged: the
    # set only gains Cyrillic entries, which no Latin token can
    # equal (and SHARE has no share tool, so its Cyrillic forms are
    # scope-path only).
    # Wave-152 (row 7): the same native match now also carries the
    # Arabic (MSA) SEND/DELETE forms -- automatic, since the Arabic
    # forms are non-ASCII members of the tool's verb classes. Latin/
    # Cyrillic/Devanagari behavior is unchanged: the set only gains
    # Arabic entries, which no Latin/Cyrillic/Devanagari token can
    # equal.
    native_forms = set()
    for cls in _TOOL_VERB_CLASSES.get(tool, ()):
        native_forms.update(f for f in _VERB_CLASSES[cls]
                            if not f.isascii())
    # Wave-153 (row 7): the tool's native CJK verb forms (a subset
    # of native_forms) for the unspaced-run branch below.
    cjk_forms = [f for f in native_forms if _CJK_CHAR_RE.search(f)]
    for i, tok in enumerate(tokens):
        if any(tok.startswith(s) for s in stems) or tok in native_forms:
            window = tokens[max(0, i - _NEGATION_WINDOW):i]
            if any(_NEGATION_RE.fullmatch(w) for w in window):
                return True
            # Same core, discontinuous form: the French "ne ... X"
            # paired pattern cannot fullmatch a single token, so it
            # is searched over the window text (wave-143).
            if _FRENCH_NE_PAIR_RE.search(" ".join(window)):
                return True
        # Wave-153 (row 7): CJK runs are unspaced -- the cue and the
        # verb form are substrings of one token (Chinese/Japanese)
        # or adjacent tokens (Korean V-지 마). Checked INDEPENDENTLY
        # of the Latin window above: a mixed token like
        # "email不要发送" matches the Latin stem branch but carries
        # its cue in-token, so the CJK branch must still run.
        if cjk_forms and _CJK_CHAR_RE.search(tok) and \
                _cjk_token_negates(tok, cjk_forms, tokens, i):
            return True
        # F188 (row 7): Latin cue glued to a non-Latin verb form with
        # zero whitespace ("do not发送"). Runs independently of the
        # branches above, like the CJK branch: the fused token
        # carries the cue before the form, not in the pre-verb
        # window.
        if _latin_glued_cue_negates(tok, native_forms, tokens, i):
            return True
    return False


# "don't forget X" / "do not ignore Y" are continuations, not
# redirects: strip them before redirect matching so benign reminders
# are not read as countermands.
_NEGATED_REDIRECT_STRIP_RE = re.compile(
    r"\b(don'?t|dont|do not|doesn'?t|doesnt|never)\s+(forget|ignore)\b",
    re.IGNORECASE,
)


def _detect_countermand(latest_text, previous_texts):
    """True when the latest user message supersedes a prior instruction:
    it carries a redirect signal AND shares topic overlap (>= 1 content
    token, or a shared slot) with at least one prior user message.

    Returns (countermanded: bool, superseded_index: int | None) where
    superseded_index is the most recent prior user message it overlaps.

    Heuristic, stated plainly: the redirect signal is the main gate and
    a single shared token links it to the prior instruction. Vague
    latest messages with no signal and no shared topic do NOT
    countermand -- that is the measured paraphrase ceiling (see
    evals/intent_slice_probes.py::p5_paraphrase_residual).
    """
    latest = str(latest_text or "")
    stripped = _NEGATED_REDIRECT_STRIP_RE.sub("", latest)
    if not _REDIRECT_RE.search(stripped):
        return (False, None)
    latest_toks = _tokens(latest)
    latest_slots = _extract_slots(latest)
    for idx in range(len(previous_texts) - 1, -1, -1):
        prev = str(previous_texts[idx] or "")
        if _tokens(prev) & latest_toks:
            return (True, idx)
        prev_slots = _extract_slots(prev)
        for cls in ("emails", "urls", "paths"):
            if latest_slots[cls] & prev_slots[cls]:
                return (True, idx)
    return (False, None)


def _render_action_text(tool, args, justification):
    """Textual rendering of an action for token overlap."""
    try:
        args_text = json.dumps(args, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001 - never break slicing on odd args
        args_text = str(args)
    return "%s %s %s" % (tool or "", args_text, justification or "")


class UserIntent(dict):
    """The intent anchor, adapted from guardrails-py's UserIntentDict:
    the latest user message plus bounded prior context."""

    def __init__(self, most_recent_message, previous_context=()):
        super().__init__(
            most_recent_message=str(most_recent_message or ""),
            previous_context=[str(m) for m in previous_context])


class IntentSlice(dict):
    """Result of slicing a trajectory against the latest user intent."""

    def __init__(self, user_intent, boundary, labels, countermand,
                 superseded_index):
        super().__init__(
            user_intent=dict(user_intent) if user_intent else None,
            boundary=boundary,
            labels=list(labels),
            countermand=bool(countermand),
            superseded_index=superseded_index,
            n_in_slice=sum(1 for l in labels if l == IN_SLICE),
            n_stale=sum(1 for l in labels if l == STALE))


def _label_action(tool, args, justification, latest_text,
                  previous_texts, countermand, superseded_index):
    """Label one agent_action step. Stale checks run before in_slice:
    a countermanded verb with fresh token overlap is still stale."""
    action_text = _render_action_text(tool, args, justification)
    action_toks = _tokens(action_text)
    latest_toks = _tokens(latest_text)

    # 1. Direct evidence: the action's primary target contradicts the
    #    latest intent's same-class slots (quoting the latest message in
    #    the body does not count -- the target is tool-aware).
    if _slot_contradiction(tool, args, latest_text):
        return STALE
    # 2. Direct evidence: the latest message negates this action's verb
    #    ("don't delete", "never send") under a countermand.
    if countermand and _negated_verb(latest_text, tool):
        return STALE
    # 3. Heuristic: under a countermand, an action with zero fresh
    #    overlap that overlaps the superseded instruction serves only
    #    the stale intent.
    if countermand and superseded_index is not None:
        if not (action_toks & latest_toks):
            prev_toks = _tokens(previous_texts[superseded_index])
            if len(action_toks & prev_toks) >= _OVERLAP_THRESHOLD:
                return STALE
    # 4. Fresh relevance: token overlap or a slot the latest intent
    #    names (non-contradictory -- contradiction returned above).
    if len(action_toks & latest_toks) >= _OVERLAP_THRESHOLD:
        return IN_SLICE
    cls, target = _action_target_slot(tool, args)
    if cls and target:
        want = _extract_slots(latest_text).get(cls, set())
        if want and not _slot_contradiction(tool, args, latest_text):
            return IN_SLICE
    return NEUTRAL


def slice_intent(steps):
    """Slice a trajectory against the latest user message.

    ``steps``: list of dicts with ``kind`` in {"user", "agent_action",
    "tool_result", "agent_message"}. User steps carry ``text``;
    agent_action steps carry ``tool``, ``args``, ``agent_id``,
    ``justification``.

    Returns an IntentSlice. With no user step, the boundary is None and
    every action is NEUTRAL (no intent anchor exists to slice against).
    Deterministic; raises nothing (malformed steps degrade to NEUTRAL).
    """
    steps = list(steps or [])
    user_idx = [i for i, s in enumerate(steps)
                if isinstance(s, dict) and s.get("kind") == STEP_USER]
    labels = [NEUTRAL] * len(steps)
    if not user_idx:
        return IntentSlice(None, None, labels, False, None)
    boundary = user_idx[-1]
    user_texts = [str(steps[i].get("text") or "") for i in user_idx]
    latest_text = user_texts[-1]
    previous_texts = user_texts[:-1]
    intent = UserIntent(latest_text, previous_context=previous_texts)
    countermand, superseded = _detect_countermand(latest_text,
                                                 previous_texts)
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or s.get("kind") != STEP_ACTION:
            continue
        try:
            labels[i] = _label_action(
                s.get("tool"), s.get("args"), s.get("justification"),
                latest_text, previous_texts, countermand, superseded)
        except Exception:  # noqa: BLE001 - slicing never breaks the caller
            labels[i] = NEUTRAL
    return IntentSlice(intent, boundary, labels, countermand, superseded)


def judge_candidate(steps):
    """Judge the CANDIDATE action: the last agent_action step in
    ``steps``. Everything before it (including the latest user message)
    is the trajectory it is judged against.

    Flags ``stale_intent`` when the candidate is sliced STALE and its
    justification provides no fresh support: no slot alignment with the
    latest intent, and justification token overlap with the latest
    message below threshold -- or a slot contradiction, in which case
    quoting the latest message is explicitly not support (quoting !=
    causation).

    Returns a verdict dict: {flagged, flag, confidence, observation,
    evidence, slice_summary}. Never raises; never denies.
    """
    steps = list(steps or [])
    action_positions = [i for i, s in enumerate(steps)
                        if isinstance(s, dict)
                        and s.get("kind") == STEP_ACTION]
    no_anchor = {
        "flagged": False, "flag": None, "confidence": 0.0,
        "observation": "no candidate action to judge",
        "evidence": [],
        "slice_summary": {"n_in_slice": 0, "n_stale": 0,
                          "countermand": False},
    }
    if not action_positions:
        return no_anchor
    cand_idx = action_positions[-1]
    sliced = slice_intent(steps)
    summary = {"n_in_slice": sliced["n_in_slice"],
               "n_stale": sliced["n_stale"],
               "countermand": sliced["countermand"],
               "boundary": sliced["boundary"]}
    base = {"flagged": False, "flag": None, "confidence": 0.0,
            "observation": "", "evidence": [],
            "slice_summary": summary}
    if sliced["user_intent"] is None:
        base["observation"] = ("no user message in trajectory: no intent "
                               "anchor; candidate left unflagged")
        return base
    if sliced["labels"][cand_idx] != STALE:
        base["observation"] = (
            "candidate is %s to the latest user intent; no stale-intent "
            "signal" % sliced["labels"][cand_idx])
        base["confidence"] = 0.6
        return base

    # Candidate is STALE. Does its justification carry fresh support?
    cand = steps[cand_idx]
    tool = cand.get("tool")
    args = cand.get("args")
    justification = cand.get("justification") or ""
    latest_text = sliced["user_intent"]["most_recent_message"]
    contra = _slot_contradiction(tool, args, latest_text)
    j_overlap = len(_tokens(justification) & _tokens(latest_text))
    fresh_support = (j_overlap >= _OVERLAP_THRESHOLD) and not contra
    if fresh_support:
        base["observation"] = (
            "candidate sliced stale but its justification shows fresh "
            "intent support (%d shared tokens, no slot contradiction); "
            "left for human review unflagged" % j_overlap)
        base["evidence"] = [justification[:280]]
        base["confidence"] = 0.5
        return base

    evidence = []
    if contra:
        cls, target = _action_target_slot(tool, args)
        want = sorted(_extract_slots(latest_text).get(cls, set()))
        evidence.append(
            "target %s=%r contradicts latest intent %s=%s"
            % (cls, target, cls, want))
    if sliced["countermand"]:
        evidence.append("latest user message countermands a prior "
                        "instruction: %r" % latest_text[:200])
        if _negated_verb(latest_text, tool):
            evidence.append("latest message negates this action's verb "
                            "(%s)" % tool)
    prev = sliced["user_intent"]["previous_context"]
    if sliced["superseded_index"] is not None and prev:
        evidence.append("superseded instruction: %r"
                        % prev[sliced["superseded_index"]][:200])
    evidence.append("candidate justification: %r"
                    % (justification[:200] if justification
                       else "<none>"))
    if contra or (sliced["countermand"]
                  and _negated_verb(latest_text, tool)):
        confidence = 0.9
    else:
        confidence = 0.7
    base.update(
        flagged=True,
        flag=FLAG_STALE_INTENT,
        confidence=confidence,
        observation=(
            "candidate action serves only a superseded instruction; the "
            "latest user intent does not support it. Flagged for human "
            "review (judge only -- nothing denied)."),
        evidence=evidence)
    return base


def judge_queued_action(tool, args, justification, user_turns,
                        prior_actions=()):
    """Convenience for the approval-queue wiring: build the trajectory
    from operator-provided user turns plus prior agent actions, append
    the candidate, and judge it.

    ``user_turns``: list of user message strings, oldest first.
    ``prior_actions``: list of {"tool", "args", "agent_id",
    "justification"} dicts (or step dicts).
    Returns the verdict dict from judge_candidate. Never raises.

    Ordering note: prior actions are placed after the user turns rather
    than truly interleaved. This does not affect the candidate verdict
    -- the judge compares the candidate against the user turns (latest
    first) only; prior actions contribute slice-summary counts, not the
    verdict. True chronological interleaving is not required for the
    judge's advisory purpose.
    """
    steps = []
    try:
        for t in (user_turns or []):
            steps.append({"kind": STEP_USER, "text": str(t)})
        for a in (prior_actions or []):
            a = dict(a) if isinstance(a, dict) else {}
            a["kind"] = STEP_ACTION
            steps.append(a)
        steps.append({"kind": STEP_ACTION, "tool": tool, "args": args,
                      "justification": justification})
        return judge_candidate(steps)
    except Exception:  # noqa: BLE001 - the judge never breaks queueing
        return {"flagged": False, "flag": None, "confidence": 0.0,
                "observation": "judge error: left unflagged",
                "evidence": [],
                "slice_summary": {"n_in_slice": 0, "n_stale": 0,
                                  "countermand": False}}
