# Obfuscation Classes vs Credential DLP: JSFuck, Text-Escape, String-Concat, and Unicode-Direction Attacks

**INTERNAL RESEARCH ASSET — NOT A PUBLICATION.** Sasanam internal use only.
Do not reproduce, distribute, disclose, or publish outside the project without
explicit authorization. Patent decision pending (deferred) — treat as
confidential company research.

**Date:** 2026-10-05 · **Base:** sasanam `1a800558` (wave-343 merge) · **Spend:** $0
**Lane:** wave-344 lane 5 (research-lab-as-GTM playbook, adapted from the AIR
Security deep-dive: named attack classes with red-first evidence and honest
boundaries, internal-only per the deferred patent decision).

## Thesis

A credential scanner that pattern-matches the *literal credential* will miss
any representation that only becomes the credential after a *decoding step* —
and real parsers (JS engines, JSON/HTML/CSS decoders, Unicode normalizers)
are precisely such decoding steps. The four named classes below are a
vocabulary for this residual, discovered by real-model red-teaming
(gpt-4o-mini, rounds 9–11) against `gov/dlp.py`'s decode layer and built out
locally into red-first, deterministic evidence. The closures all share one
discipline: **bounded static parsing, never evaluation** — the DLP sees what
the parser would see, without running attacker-controlled code.

## Class 1 — "JSFuck" (F428, LOW, CLOSED 2026-10-05)

**Name origin:** the esolang that encodes any JS program in the six-character
alphabet `[]()!+-`.

**Mechanism.** A Slack-style credential embedded in a JSFuck payload — a run of
only `[]()!+-` characters. A JS engine evaluates it to the credential; the
DLP's decode layer (URL-encoding, hex, base64/base64url, base32 — bounded,
2 layers) matches no encoding and `find_credential` returns None. The real-world
sibling is the Salt Labs vs Manus JSFuck prompt-injection (2026-10-03).

**Red-first evidence.** `evals/w341_jsfuck_redfirst.py` printed BREAK on the
open tree (plain credential blocks coded `dlp-slack-token`; base64/hex/base32
forms block; JSFuck form misses). After closure it prints HELD. The payload
itself is canned at `evals/artifacts/w341_jsfuck_slack_token.txt` ($0 spend
by construction).

**Closure.** `gov/dlp.py` gained a strict static JSFuck evaluator (`_JSFuckParser`):
literals `![]`/`!![]`/`[]`, `+`/`-`, string coercion, indexing, the
constructor/toString member ladder, and safe `String`/`Number`/`Boolean`
constructor calls plus `num.toString(radix)`. `Function()` and anything outside
the construction set fails closed; undecodable runs are ignored. Step budget,
depth cap, and run-length bounds keep it a bounded static parse — the DLP
never executes the payload.

**Honest boundaries.** The parser is alphabet-specific
(`_JSFUCK_RUN = [\[\]()!+\-]{64,}`): it recognizes JSFuck, not arbitrary
JS-execution encodings. aaencode/jjencode stay inside this class's close-when
(the same JS-execution family), but arbitrary JS expressions are NOT in scope —
see Class 3 for the correction of the original scoping note. Honest text made
of alphabet noise does not block (discrimination pinned by `w342_f428close_probes.py`).

## Class 2 — "Escape-Ladder" (F429, LOW, CLOSED 2026-10-05)

**Mechanism.** Text-escape transforms that a real parser decodes back to the
credential: `\uXXXX` / `\UXXXXXXXX`, `\xXX`, octal escapes, CSS escapes
(`\78 ` = 0x78, 1–6 hex + mandatory space), HTML entities (`&#x..;` / `&#..;`),
UTF-16 null-interleaving (`x\x00o\x00x...`), fullwidth confusables, and
zero-width joiners. Each misses `find_credential` (9/9 verified on the open
tree) while the plain credential blocks coded `dlp-slack-token`.

**Red-first evidence.** `evals/w342_textescape_redfirst.py` (BREAK → HELD);
`evals/w342_unicode_escape_redfirst.py` for the backslash-escape subset
(independently confirmed during the F428 closure; same finding, not a variant).

**Closure.** The decode layer gained a strict static text-escape/normalization
pass (`_decode_one_escape`: deterministic priority `\uXXXX`/`\UXXXXXXXX` →
`\xXX` → CSS-with-space → octal, strict full-run decode or whole run ignored;
`_try_entity_decode` with surrogate/out-of-range rejection; `_try_utf16_null_decode`;
`_normalize_confusables`: whole-string NFKC + zero-width strip). Every decode
is ASCII-printable-gated and length-bounded; undecodable runs are ignored —
never evals.

**Honest boundaries.** This class covers *parser-defined* escapes, not
*rendering-defined* tricks: a bidirectional-override control (U+202E) that
reorders how the text displays, and Cyrillic homoglyphs that do NOT NFKC-fold
to ASCII, both evade the closed decode layer. Per the standing rule the
residual was re-filed as a new finding (F431, LOW, OPEN), not folded into
F429's scope. Honest backslash/unicode/entity text is unaffected
(discrimination pinned).

## Class 3 — "Concat-Smuggle" (F430, LOW, OPEN as of 2026-10-05)

**Mechanism.** JS string concatenation: the text `"xoxb-abc123" + "def456"`
evaluates to the credential in any JS engine, but matches no decode layer and
the F428 JSFuck parser cannot see it (alphabet-specific). Proposed by
gpt-4o-mini in attack round 11; built locally against the real seams.

**Red-first evidence.** `evals/w343_concat_redfirst.py` prints BREAK on the
open tree (4/4 miss; the plain-credential control blocks coded
`dlp-slack-token`).

**Why this is a new class, not F428's scope.** The F429 filing carried a
scoping note — "aaencode/jjencode-style shapes are JS-execution encodings, the
same mechanism as F428's JSFuck, and stay under F428's close-when" — that does
not hold for the shipped parser: it recognizes JSFuck's six-character alphabet
only, not arbitrary JS expressions. Per the standing rule, the overstated
closure scope is corrected by re-filing (F430), never by quietly widening
F428's closure. (A "remove comments" variant — `xoxb-/*hidden*/abc123def456` —
was proposed in the same round and DISCARDED: no real parser reassembles the
credential from it, so it is not a genuine decode shape.)

**Close-when.** The decode layer recognizes bounded static
string-concatenation expressions (or refuses obfuscation-shaped runs coded),
red-first verified, honest text unaffected.

## Class 4 — "Direction-Ghost" / "Homoglyph-Twin" (F431, LOW, OPEN as of 2026-10-05)

**Mechanism.** Two Unicode-direction rendering tricks that survive the
F429-closed normalize layer:
- **Direction-Ghost:** a U+202E right-to-left override interleaved in the
  credential. There is no bidi-control normalization in the decode layer.
- **Homoglyph-Twin:** Cyrillic homoglyphs (e.g. U+043E, which does NOT
  NFKC-fold to ASCII). NFKC + zero-width strip — the whole of F429's
  `_normalize_confusables` — cannot see it.

Both verified 2/2 MISS on the closed tree while the plain credential blocks
coded `dlp-slack-token`; pinned as known-open by `evals/w343_attack_probes.py`
A6/A7.

**Close-when.** The decode layer strips bidi controls / applies a confusable
map, red-first verified, honest text unaffected.

## Cross-cutting closure discipline

All closed classes follow one discipline, and it is the discipline the next
report should carry forward:

1. **Static, never evaluated.** JSFuck is parsed with a step-budgeted static
   evaluator; text escapes are regex-decoded with surrogate/out-of-range
   rejection. The DLP never executes attacker text.
2. **Fail-closed.** `Function()`, undecodable runs, malformed escapes — all
   are ignored or refused coded, never passed through as "probably safe".
3. **Bounded.** Step budgets, depth caps, run-length bounds, ASCII-printable
   gating. The decode layer cannot be turned into a resource-exhaustion
   primitive (ReDoS battery pinned for the F429 regexes).
4. **Discrimination.** Honest alphabet noise, honest backslash text, innocent
   decodes — none block. Every closure ships discrimination probes.
5. **Residuals re-filed, never absorbed.** When a closure's scope proves
   narrower than its scoping note (F428 → F430; F429 → F431), the residual
   gets its own finding number. That is how this vocabulary stays honest.

## Report card (as of base 1a800558)

| Class | Finding | Status | Red-first | Coverage |
|---|---|---|---|---|
| JSFuck | F428 | CLOSED | w341_jsfuck_redfirst.py (HELD) | alphabet-specific `[\[\]()!+\-]{64,}` |
| Escape-Ladder | F429 | CLOSED | w342_textescape_redfirst.py (HELD) | 9 parser-defined escape transforms |
| Concat-Smuggle | F430 | OPEN | w343_concat_redfirst.py (BREAK) | — |
| Direction-Ghost + Homoglyph-Twin | F431 | OPEN | w343_attack_probes.py A6/A7 (known-open pins) | — |

The next entries in this series belong to F430 and F431 closures.
