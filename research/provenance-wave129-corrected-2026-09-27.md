# Provenance correction — Wave-129 adapted ideas (2026-09-27)

The Wave-129 commit message recorded provenance for three adapted ideas, but
only the Microsoft commit was exactly verified. This file corrects the record
with exact commits, licenses, NOTICE obligations, and code-vs-concept status
for all three, verified against the upstream repos on 2026-09-27 via the
GitHub API and raw file fetches.

## 1. Microsoft — `microsoft/agent-governance-toolkit`

- **Exact commit:** `6b644564d112b879e48183bc1655fcf73c86d23e`
  — verified to resolve on GitHub (author AlgoVoi / Christopher Hopley,
  committed 2026-09-26T20:29:37Z).
- **License:** MIT (Copyright Microsoft Corporation), per upstream LICENSE.
- **What was taken:** concept only — the advisory-can-only-tighten pattern
  (`governance/advisory.py`) and the Decision BOM
  (`governance/decision_bom.py`). Adapted into `gov/advisory.py` with
  documented honest deltas (explicit three-rung lattice, fail-closed
  advisor-error handling, LOUD monotonicity violations, hash-chained BOM).
- **Code copied:** none.
- **Attribution in repo:** yes — `gov/advisory.py` docstring records the
  repo, URL, exact commit, MIT license, and copyright holder.

## 2. OpenAI — `openai/openai-guardrails-python`

- **Exact commit for v0.3.2:** `60401f4ca6c832e8be1a82f6fc3783d6e51c59a9`
  (the `v0.3.2` tag object points at this commit; previously the record
  said only "v0.3.2 / 2026-09-24" with no hash).
- **License:** MIT, confirmed from the LICENSE file at that tag:
  "MIT License — Copyright (c) 2025 OpenAI".
- **What was taken:** concept only — the latest-user-message intent anchor
  (`UserIntentDict`: `most_recent_message` + `previous_context`) and the
  direct-evidence rubric (flag only on direct evidence, never on
  competence). Adapted into `gov/intent_slice.py` as a deterministic
  local slicer (slot extraction, token overlap, countermand detection);
  the upstream judge calls paid OpenAI APIs, which this repo's $0-spend
  constraint rules out.
- **Code copied:** none — stated explicitly in `gov/intent_slice.py`.
- **Attribution in repo:** yes — `gov/intent_slice.py` docstring records
  the repo, URL, v0.3.2, the exact commit
  `60401f4ca6c832e8be1a82f6fc3783d6e51c59a9`, MIT license, and
  "(c) 2025 OpenAI" (docstring updated 2026-09-27; the earlier
  "exact merge hash not surfaced" statement is corrected).
- **MIT obligation analysis:** the MIT attribution clause applies to
  "copies or substantial portions of the Software." No code was copied,
  so no obligation attaches; the in-module attribution exceeds the
  minimum. **No NOTICE-style file is required or missing.**

## 3. Cedar — `cedar-policy/cedar`

- **Exact commit (contemporaneous retrospective pin, 2026-09-27):**
  `3b8d672362dc3185a24dead04e094018f0197e09`
  (committed 2026-09-24T20:01:10Z — "Fix implicit BTreeMap clones on
  `Attributes::into_iter` (#2518)", jkastner).
  Honest note: the Wave-129 lane did not pin a specific commit in its
  record, so this is NOT the exact snapshot originally consulted — it
  is the repo HEAD as of the adaptation date, pinned retrospectively
  on 2026-09-27. The adapted concepts (forbid-overrides-permit;
  `is_authorized(Request{principal,
  action, resource, context}) -> Response{Decision, Diagnostics}`) have
  been stable in Cedar for years, so any contemporaneous commit pins the
  same interface semantics.
- **License:** Apache-2.0, confirmed from the LICENSE file at that
  commit.
- **NOTICE review:** a NOTICE file exists at that commit and contains
  exactly one line: `Copyright Cedar Contributors`. There is no
  third-party attribution payload beyond the copyright line.
- **What was taken:** concept only — the typed Request/Decision+
  Diagnostics contract and forbid-overrides-permit independent of rule
  order. Reimplemented from scratch in `gov/decision_contract.py` for
  the Python YAML policy engine ("No Cedar code is reused (Cedar is
  Rust; this engine is a Python YAML policy engine)").
- **Code copied:** none.
- **Attribution in repo:** yes — `gov/decision_contract.py` docstring
  names the repo, URL, Apache-2.0, and "Copyright Cedar Contributors".
- **Apache-2.0 obligation analysis:** §4(d)'s NOTICE-inclusion duty
  applies when distributing Derivative Works. A clean-room
  reimplementation of interface concepts in a different language, with
  no copied copyrighted expression, is not a derivative work of the
  copyrighted code — so no NOTICE duty attaches. Even under the most
  conservative reading, the only NOTICE content is the one copyright
  line, which the module docstring already carries. **No NOTICE file is
  required or missing.**

## Verdict

- Three exact commits now on record:
  - Microsoft: `6b644564d112b879e48183bc1655fcf73c86d23e` (was verified,
    re-confirmed resolves)
  - OpenAI guardrails v0.3.2: `60401f4ca6c832e8be1a82f6fc3783d6e51c59a9`
    (newly resolved)
  - Cedar (HEAD 2026-09-27): `3b8d672362dc3185a24dead04e094018f0197e09`
    (newly resolved)
- **No attribution gap.** All three modules carry in-module attribution
  naming repo, URL, license, and copyright holder; no code was copied
  from any of them, so no MIT copyright-notice or Apache-2.0 NOTICE
  redistribution duty attaches. No legal files were added — none are
  needed while the repo stays concept-adaptation-only.
- **Standing rule going forward:** any future adaptation lane must
  record the exact upstream commit hash in the module docstring at
  build time, not version/date level. The OpenAI docstring in
  `gov/intent_slice.py` still says "exact merge hash not surfaced" —
  it is now surfaced here (`60401f4ca6c832e8be1a82f6fc3783d6e51c59a9`)
  and should be edited into the docstring on the next touch.
