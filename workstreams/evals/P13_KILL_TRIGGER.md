# P13 Kill-Trigger Memo (wave-40, 2026-09-22)

P13 — Output-channel exfiltration (EchoLeak-class, I6). Standing state:
**PARTIAL (design boundary)** — payload side fully covered (P1/P4
close-outs); renderer side is a gate-pinned *reference* filter
(`gov/output_filter.py`), not a verified deployment.

## The kill-trigger, stated concretely

There are exactly two ways P13 leaves PARTIAL. Both are defined here so
no future wave re-litigates the boundary.

### Trigger A — flip to FULL (external; not executable from this repo)

P13 flips to FULL if and only if a **verified deployment artifact**
exists:

1. A named deployment routes agent output through `gov/output_filter.py`
   (or an independently reviewed equivalent implementing the
   `docs/DEPLOYMENT.md` §5.6 filter list) **server-side, before any
   active renderer** — wiring evidence (config diff, architecture
   doc, or code pointer), not prose.
2. The §5.6 EchoLeak canary checklist **passes against the production
   renderer**: the canary payload battery (markdown-image exfil,
   raw-HTML active tags, dangerous schemes incl. obfuscation,
   dangerous autolinks) produces zero fetches / zero active
   interpretations in the deployed rendering pipeline.
3. The renderer settings the filter cannot control are evidenced:
   `linkify: false` (or server-side unfurl proxying) for bare-URL
   link previews — §5.6 item 3.

All three, evidenced, in a deployment this repo does not operate.
**This repo cannot produce that artifact** — it ships a library, not a
deployment. Trigger A is therefore *defined but not actionable*
from here; it is the honest answer to "what would flip P13 to full".

### Trigger B — terminal by-design (repo-side; EXECUTED wave-40)

The repo-side work for P13 is **declared COMPLETE**. Rationale:

- The reference filter's *behavior* is pinned in the gate: 17/17 unit
  tests (`tests/test_w36_output_filter_p13.py`), 2 registered probes
  (`redteam.incident.p13.echoleak_reference_filter_neutralizes`,
  `..._allowlist_honored`), and the wave-40 RT9 bypass round
  (F116: `<svg><image href>` auto-fetch + `<a href="javascript:…">`
  closed, `redteam.rt9.f116_output_filter_bypass` → stopped,
  `tests/test_w40_rt9_closures.py::TestF116OutputFilterBypass` green).
- The deployment deliverable exists (`docs/DEPLOYMENT.md` §5.6: CSP,
  DOMPurify, markdown-it configs + canary checklist) and now points at
  the module as the server-side pre-filter.
- No further repo-side strengthening can move the needle: the residual
  is *adoption*, and adoption is unobservable from the repo
  (verified via the §5.6 canary checklist, which only a deployment
  can run).

**Standing disposition:** P13 remains **PARTIAL (AMBER) — terminal
by design**. It is not "awaiting more repo work"; the only live
trigger is Trigger A (external). Future waves: re-audit only if (a) a
new renderer-side exfil primitive class appears in the wild (then
red-team the reference filter and extend the battery — the F116
pattern), or (b) a deployment verification artifact arrives.

## What was explicitly NOT done

- P13 was NOT flipped to FULL on the strength of the reference
  filter: the gate pins behavior, not adoption. Claiming FULL would
  be the exact overclaim the wave-27 adjudication rejected.
- No finding was filed for "renderer side uncovered": the boundary is
  by design (same adjudication class as P8's uncovered-by-design),
  and the reference control + deployment guidance is the proportionate
  repo-side answer.

## Evidence index

- `gov/output_filter.py` (reference implementation; F116 fixes)
- `tests/test_w36_output_filter_p13.py` (17/17)
- `tests/test_w40_rt9_closures.py::TestF116OutputFilterBypass`
- `evals/w40_probes.py::sit_rt9_f116_output_filter_bypass`
  (registry `redteam.rt9.f116_output_filter_bypass`, closure: green)
- `docs/DEPLOYMENT.md` §5.6 (canary checklist = the Trigger-A test)
- `evals/FINDINGS.md` F116 (filed + closed wave-40)
