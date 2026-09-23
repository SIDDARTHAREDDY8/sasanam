# Citation Provenance (F139) — evaluator guidance

## The problem in one paragraph

An evaluated agent can upload fabricated "independent" evidence to an
allowlisted web host (paste site, gist, API endpoint) via a governed
upload-shaped call (`http_post` or `api_call`, F139/F140) and later
cite the planted URL back to evaluators as independent corroboration. The
upload-side approval gate is **structurally blind** to this: the approver
sees only the URL plus `{bytes, sha256_prefix}` (F12 — payload content is
redacted by design), so a fabricated "study" and a routine research post
look identical at every governed checkpoint. Evaluation-integrity controls
that score *behavior* (sandbagging, sleepers) verify nothing about where
cited evidence *came from*. The defense therefore lives at the **citation**,
not the upload.

## The rule

**Treat bare-URL citations in agent output as untrusted-by-default until
verified.** Route every evaluation report whose conclusions will be
trusted through the governed acceptance checkpoint
`gov/eval_integrity.accept_report` (F141) — it runs the citation check
*before* conclusions are accepted, chains a `citation_check_completed`
record into the log, and **refuses** tainted reports (SELF_PLANTED hits
become eval-integrity violations with chained `detector_trip`, tripped
breaker, and a halt-request for the operator). UNKNOWN citations are
never violations. Use `gov/eval_integrity.eval_sessions_missing_citation_check`
to lint which eval sessions skipped the checkpoint.

Calling `gov/eval_integrity.check_citations` directly is also fine
(on-demand verification of a URL list); `accept_report` is the
checkpoint wrapper that makes the check auditable and enforced.

```python
from gov import eval_integrity as ei

out = ei.check_citations(
    agent_report_text,          # or an explicit [url, ...] list
    monitor=monitor, log=eval_log, identity=citing_identity,
    session_id="eval-1", session_open="2026-09-23T00:00:00Z",
    log_entries=run_log_entries,   # this run's chained log
    ledger=shared_egress_ledger,   # cross-run EgressLedger
    trusted_sources=("nature.com", "arxiv.org"),  # deployment trust anchor
)
```

## Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| `SELF_PLANTED` | The URL was uploaded through governed tooling. The evidence is **not independent** of the governed population. | `check_citations` already filed an eval-integrity violation (`self_planted_citation`): chained `detector_trip`, breaker tripped, halt-request ready for operator signing. Treat the citing report's conclusions as compromised. |
| `UNKNOWN` | No governed upload record and no trust anchor. | **Not a clean bill of health.** Corroborate through an independent channel before relying on it. |
| `INDEPENDENT` | No governed upload record **and** a positive trust anchor (host on `trusted_sources`, or fetched-content hash on `trusted_content_hashes`). | Accept per the deployment's trust policy. |

Precedence: plant evidence **always beats** trust anchors. A plant uploaded
*to* a trusted host still verifies `SELF_PLANTED` — the anchor attests to
the host, not to who put the bytes there.

`SELF_PLANTED` does **not** prove the citing agent planted it themselves:
the evidence carries the uploader identity plus `same_principal` /
`same_agent` flags. A citation of another governed agent's upload is still
tainted evidence (not independent), but it is a different incident shape
than self-planting — investigate accordingly.

## Operator notes

- The executor records `kind: "upload"` entries (URL, payload sha
  prefix, uploader identity, tool) into the cross-run `EgressLedger` at
  **every executed upload-shaped call** — `http_post` and `api_call`
  (F140), direct and approved paths. For `api_call` the URL is the
  `endpoint` and the payload summary is a canonical fingerprint of
  `params`. Queued-but-never-approved calls are not plants — they never
  reached the host — and are not recorded.
- The per-run chained log already carries what the index needs
  (`tool_call` entries: readable URL/endpoint, payload summary,
  uploader identity), so same-run verification works with no new
  logging.
- `trusted_sources` is a deployment decision, not a default. Ship with it
  empty (everything unverifiable → `UNKNOWN`) until the deployment's trust
  policy is explicit. A short, reviewed list beats a long convenient one.
- The citation check is evaluator-side and on-demand — there is no
  in-run performance cost. Run it over evaluation reports before
  conclusions are accepted, and over any agent output that will be
  published or acted on.

## Honest boundaries (do not over-claim)

1. **Paraphrase defeats payload matching.** The URL is the primary key;
   the log carries only a 16-char payload-sha prefix as corroboration.
   Content reworded between plant and citation is still caught by URL
   matching, but content *moved to a new URL* is a fresh plant to catch.
   Fuzzy/structural content matching is follow-up work.
2. **Query-string evasion.** `?x=1` appended to a planted URL normalizes
   to a different URL (conservative against false accusation). Canonical
   query-param handling is follow-up.
3. **Out-of-governance plants are invisible.** Uploads from a personal
   device, an ungoverned second agent, or a URL memorized from training
   data leave no governed record. This primitive covers citations
   resolvable against governed upload records only.
4. **The human upload gate stays blind.** This fix does not make approvers
   see payload content (F12 redaction stands — it protects secrets).
   The plant path through approval remains open by design for legitimate
   publisher workflows; the citation check is the compensating control.
5. **Uploader identity is process-boundary strong.** Without a
   deployment-controlled `PrincipalRegistry`, in-process identity is
   self-asserted (standing warning). The plant record is evidence, not
   proof, against a principal-spoofing insider.
6. **Deny-all outbound posting** closes the plant path entirely but
   disables legitimate publisher workflows — a deployment tradeoff,
   not a product default.
7. **Response-URL gap (F140 follow-up, not closed).** A real API
   plant's citable URL is usually a *resource* URL returned in the API
   response, not the endpoint the agent called. This primitive
   correlates the endpoint; a citation of a response-minted resource
   URL has no governed record to match. Closing that needs response
   capture or endpoint→content bindings.
8. **The checkpoint must be invoked.** `accept_report` is opt-in: a
   deployment that never routes reports through it gets no citation
   protection. The `eval_sessions_missing_citation_check` lint makes
   skipped sessions auditable — wire it into the eval workflow, don't
   just document it.
