# Implicit-egress surface: trusted-relay mapping (wave-273 lane I)

Research map of the egress surface that **no agent tool call** touches.
Written 2026-10-01 from the wave-272 prospecting child-3 report on
EchoLeak (CVE-2025-32711) and the lane-I prior-art audit.

## 1. The EchoLeak exfiltration shape

EchoLeak (Microsoft 365 Copilot, disclosed June 2025) is the reference
incident for this surface. Its kill chain had three properties that
defeat conventional egress controls:

1. **No agent tool call.** A crafted email carried a prompt-injection
   payload; the model followed it by *authoring content* containing
   reference-style Markdown image links (`![x][id]` + `[id]: url`).
2. **The client performed the fetch.** The chat client auto-fetched the
   image URL to render the message, pulling tenant data embedded in the
   URL through an allow-listed first-party relay:
   `teams.microsoft.com/urlp/v1/url/content`. The relay was trusted
   infrastructure acting as an exfiltration channel.
3. **Redaction was bypassed by shape.** Link-redaction heuristics keyed
   on inline URLs missed the reference-style indirection; the real
   destination lived in the definition map, not the use site.

Existing repo controls — per-tool grants, `bundle_scan`, the
`egress-*` decision codes (`egress-destination-exemption-refused`,
`egress-injection-propagation`, `egress-propagation-malformed`) and
modules (`egress_content.py`, `egress_propagation_guard.py`,
`egress_proxy.py`, `egress_ledger.py`, `egress_launcher.py`) — score
payloads, govern public-channel propagation, and proxy CONNECT calls.
None of them see a URL the *client* will fetch. The gap is structural:
the exfiltration path leaves the agent's observable action space before
the fetch happens.

## 2. The implicit-egress map

"Implicit egress" = any path by which agent-produced content causes data
to leave the tenant boundary without an agent tool call. The mapped
surface, ordered by exploitability:

| # | Channel | Auto-fetch trigger | Prior control | Lane-I verdict |
|---|---------|-------------------|---------------|----------------|
| 1 | Reference-style Markdown image (`![x][id]` + `[id]: url`) | client renders message | none | **screened** (`gov/egress_refs.py`) |
| 2 | Inline Markdown image (`![x](url)`) | client renders message | none | **screened** |
| 3 | Reference-style link (`[t][id]`) | unfurl / preview bot | none | **screened** |
| 4 | HTML `<img src>` / `<a href>` | client renders HTML part | none | **screened** |
| 5 | Bare URL in text | link-unfurl / preview fetch | none | **screened** (preview provenance) |
| 6 | Trusted-relay wrap (`urlp/v1/url/content?url=<inner>`) | allow-listed proxy fetches inner target | allow-list treats relay as trusted | **screened as untrusted channel** |
| 7 | Copy/paste surfaces | user's own clipboard | none | **out of scope** (client-side, invisible to any content screen) |
| 8 | URL shorteners / encrypted targets | redirect resolution | none | **treated as external, never allow-listed by target** |
| 9 | Outbound webhooks / callbacks | server-to-server | `gov.egress_proxy` (tool-call seam) | out of scope for this module — already governed at the call seam |
| 10 | Instruction provenance (who authored the exfil) | n/a | none | **lane G** (provenance-labeling spike), not this module |

Rows 1–6 are the module's screening domain. Rows 7–10 are honest
boundaries, recorded on every verdict's `out_of_scope` field.

## 3. Screening rules (the trust inversion)

The core rule is a **trust inversion**: a deployment-declared trusted
relay (host + path prefix) is treated as an *untrusted* exfiltration
channel whenever its decoded inner target is external **and** the
payload is data-shaped. Per reference:

- **Relay rule** — relay URL + external inner target + exfil-shaped
  payload (sensitive-digest match OR oversized query/fragment) →
  refuse `egress-relay-exfil`. Relay + external inner target + short
  clean query → allow (allow-listed relays carry benign traffic; the
  c04 anti-FP pin).
- **Data rule** — sensitive-digest match or oversized query/fragment on
  a non-allow-listed effective host → refuse `egress-ref-data-exfil`.
- **Exemptions** — allow-listed hosts, relative refs, non-http(s)
  schemes → allow, with the reason recorded.

"Data-shaped" is deliberately two-keyed: exact sensitive-data digests
(strong, deployment-provided sha256 list) and payload-size budget
(weak, heuristic — a 600-char base64 blob in an image URL is never a
thumbnail). Size alone can false-positive; digests alone miss novel
tokens. The pair is the lane's falsifiable core: the red battery breaks
each key independently (e04 digest-only, e02/e03/e05/e06 size-only,
e01 relay-shaped with the size key, e08 relay-shaped with the digest
key -- the code-review regression probe).

## 4. Provenance tags are heuristic, not boundary

Refs are tagged `rendered` (client renders: images, links, HTML) vs
`rendered-preview` (bare URLs: unfurl/preview fetch, not body
rendering). The tags document *what typical clients do*; verdicts never
depend on them. A client that prefetches previews is still screened —
the bare-URL surface is refused on the same data rules.

## 5. Residual risks (not closed by this lane)

- **Pre-emission only.** The module screens agent-produced content
  before it reaches the client. A client that never asks the gate, a
  proxy that serves anyway, or content that left through another path
  is outside enforcement.
- **Digest list completeness.** The sensitive-digest rule is only as
  good as the deployment's digest feed; novel exfiltrated tokens are
  caught by the size heuristic or not at all.
- **Shortener opacity.** Shortened/encrypted targets are treated as
  external, which refuses them only when data-shaped; a short clean
  shortened link to an exfil server is allowed (same residual as any
  allow-list).
- **Instruction provenance.** *Which input* authored the exfil (the
  prompt-injection half of EchoLeak) is lane G's problem; this module
  screens the *output* regardless of provenance.

## 6. Verification

- `evals/w273_egress_probes.py` — 8 attacks / 6 controls, red-first:
  8/8 attacks broke on the foil, 15/15 held on the real implementation
  (e08 is the code-review regression probe: digest-through-relay).
- `tests/test_egress_refs.py` — 24 unit tests at the public seams.
- Decision codes: `egress-ref-data-exfil`, `egress-refs-malformed`,
  `egress-refs-oversized`, `egress-relay-exfil` (pin 1447).
