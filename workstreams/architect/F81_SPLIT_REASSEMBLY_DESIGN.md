# F81 — Split-Payload Reassembly: Design, Adversarial Review, Verdict

**Wave-55, 2026-09-22. Status: DESIGN-ONLY — prototype NOT built (see §6 verdict).**
**F81 stays LOW, OPEN. This document changes nothing about F81's status:**
F81 closure requires the filtered-egress *wall* (the §2a proxy frame),
not a stronger tripwire.

---

## 0. The question

RT20 pinned the sharpest residual in the canary tripwire: an AWS-style
secret split into halves does not trip and executes end-to-end
(`canary.rt20.split_halves_two_params_residual`,
`canary.rt20.split_halves_two_calls_residual`, wave-53). The tripwire
(`gov/canary.py::scan_egress_attempt`) is per-call and exact: each
string leaf of one tool call's args is matched (directly + ≤2 validated
decode layers) against the registry. A secret that never appears
whole in any single call is invisible to it.

This wave answers on paper: **should the filtered-egress wall reassemble
split payloads per-destination?** The frame is the founder-strategy memo
§2a recipe (proxy-enforced egress: loopback-bound egress proxy sidecar,
per-request hostname resolution, private-range deny above allow rules,
verdict logging outside the container, not-ready = no network,
provider/lifeline host exempted at the operator layer). This document
designs the reassembly question *inside that frame*, reviews the design
adversarially, and reaches a verdict on whether a prototype is warranted.

---

## 1. What "reassemble per-destination" means concretely

Three egress primitives produce splittable payloads, in increasing
adversary control:

**P1 — Multi-param assembly (one call).** The secret's halves travel as
two string leaves of one tool call's args (`params={"k1": half1, "k2":
half2}`). The scanner already iterates `_iter_strings(args)` per leaf;
reassembly here means: concatenate the call's string leaves (after
decode-variant expansion) and scan the concatenation for a registry
value. Bounded by the call's arg size — no cross-call state, no clock.

**P2 — Sequential tool calls to the same destination.** Halves travel as
`api_call(endpoint=H, params={"k": half1})` then `api_call(endpoint=H,
params={"k": half2})`. Reassembly means: keep a per-(destination,
identity) buffer of recent egress payload fragments; on each egress
attempt, test whether concatenation of buffered fragments (in bounded
combinations) completes a canary value. Requires a reassembly window
(§2), cross-call state, and a definition of "same destination" (see the
F81 hostname-trust lesson: the sandbox must resolve the destination
through its own resolver, never the child's).

**P3 — Chunked writes / multipart assembly at the transport layer.**
Chunked HTTP uploads, multipart forms, `write_file` then `read` then
`http_post` — the split happens below the tool-call framing. At the
tool-call layer this is P2 with more steps; at the proxy layer it is a
byte stream, and reassembly is TCP/HTTP reassembly, not tool-call
reassembly (see §6: the proxy does this for free).

The adversary picks the cheapest primitive the defense doesn't cover.
Any defense that closes P1 only moves the split to P2; any defense that
closes P2 moves it to P3-at-a-different-layer or to the evasions in §5.

---

## 2. The reassembly window (time/size bounds)

Unbounded buffering is a denial-of-service vector: an agent (or an
injected prompt driving it) can emit infinite egress fragments and grow
the buffer without bound. The F25 lesson (unbounded shared state without
locking/bounds forks the trust root) generalizes: **any reassembler that
holds adversary-influenced bytes must be bounded in both time and size,
and the bound is the attack surface.**

Candidate window: per-(destination host, identity), last K egress
payload fragments, total ≤ M bytes, evicted after T seconds.
Concretely defensible numbers would be small (K≈8 calls, M≈64 KiB,
T≈300 s) — but the honest point is that the *specific numbers do not
matter*, because of the §4 counter:

> For any bound (K, M, T), the adversary splits into K+1 chunks, or M+1
> bytes, or waits T+ε seconds. The bound is public (it is in the code),
> deterministic, and the adversary controls the fragmentation. A bounded
> reassembler is a heuristic the adversary games deterministically, not
> a control.

The F25 parallel is deliberate: F25's fix was a lock with a *30-second
bounded wait that fails closed*. A reassembler cannot fail closed on
bound-expiry — dropping fragments on expiry *is* the miss. There is no
fail-closed direction for "we forgot what we saw."

**Combinatorial cost note:** naive P2 reassembly tries concatenations of
buffered fragments. With K fragments, contiguous-run concatenations are
O(K²) per call — acceptable. But once decode-variant expansion (≤64
variants per leaf, ≤2 layers) interacts with chunk concatenation, the
match surface is 64^K in the worst case; real implementations cap
variants first, chunks second, and each cap is another public bound the
adversary games. The disciplined engineering answer (cap-then-scan) is
also the adversary's answer key.

---

## 3. What reassembly does to the canary layer

**Does a split canary trip on reassembly?** Yes, by construction: if the
fragments reassemble to a registry value, `scan_egress_attempt` on the
reassembled text trips exactly as the whole-value case does — same LOUD
`canary_trip` audit event, same `CanaryTripHalt`.

**Should it?** For the within-call case (P1): yes, and the
false-positive argument is strong. Canary values are high-entropy random
strings (≥16 chars, no banned substrings); two benign halves of a
legitimate payload do not accidentally concatenate into one. The
exactness invariant (the tripwire's near-zero-FP property) survives P1
reassembly intact: the match is still exact-value, just over a
concatenated leaf set. P1 reassembly *adds true hits only* — the same
property the wave-51 decode-variant expansion proved.

For the cross-call case (P2): it should trip *if* the fragments genuinely
reassemble to the value, but the definition of "genuinely" is where the
FP surface opens (§4), and the bound-gaming in §2 means it trips only
against lazy adversaries.

**What reassembly does NOT change about the canary layer:** the canary
remains a tripwire, not a wall. It detects exfiltration of *our planted
secrets*. It never detects exfiltration of the user's real secrets, of
data the agent legitimately holds, or of anything to a destination the
deployment allows. Reassembly makes the tripwire harder to dodge; it
does not change what the tripwire is.

---

## 4. The false-positive surface

**P1 (within-call) reassembly: near-zero added FP.** The concatenation
set is the call's own leaves; the match is exact-value against
high-entropy registry values. Legitimate chunked uploads do not contain
canary values split across params — and if they did, that would be
exfiltration of the canary, which is exactly what the tripwire is for.

**P2 (cross-call) reassembly: the FP surface is real and structural.**

- *Legitimate chunked uploads:* multipart forms, resumable uploads, and
  paginated API writes routinely send fragments of one logical payload
  across calls. If any fragment-run *happens* to contain a canary value
  (e.g., the agent is legitimately migrating a config file that embeds a
  planted canary — the "confused deputy with the keys" shape), the trip
  fires on behavior that was not exfiltration intent. The canary's
  "never valid credentials" invariant weakens the moment fragments are
  joined across trust contexts: the join is the scanner's inference, not
  the agent's action.
- *Cross-destination contamination:* to catch cross-destination splits
  (§5), the buffer must be global, not per-destination. A global buffer
  joins fragments the agent sent to unrelated destinations — the
  scanner's inference now spans trust contexts, and the FP story gets
  worse with every destination added.
- *Interleaved benign traffic:* real agents interleave. A reassembler
  must decide contiguity (which fragments belong to one logical
  payload). Any contiguity rule (time-order, destination-match,
  param-name-match) is either FP-prone (joins unrelated fragments) or
  gameable (the adversary breaks the rule's pattern — which is §5
  again).

The honest summary: P1 keeps the exactness invariant; P2 trades it for a
heuristic, and heuristics in the tripwire erode the property that makes
the tripwire deployable (near-zero FP → operators trust the halt).

---

## 5. What still evades (the review's kill list)

Even a perfect, unbounded P2 reassembler — which §2 shows is
undeployable — loses to:

1. **Bound+1 splitting.** K+1 chunks, M+1 bytes, T+ε delay. Deterministic,
   adversary-controlled, public bounds. This alone kills bounded
   cross-call reassembly as a control.
2. **Interleaved-benign splits.** Alternate secret chunks with benign
   chunks across calls (`half1, benign, half2, benign`) — any contiguity
   rule either joins the benign chunks (FP risk, §4) or refuses to join
   across them (miss). The adversary also rotates param names and call
   shapes so no "fragment" pattern is stable.
3. **Cross-destination splits.** Half to `api.example.com`, half to
   `backup.example.com`; or split across channels (half via `http_post`,
   half via `send_email`). "Reassemble per-destination" misses by
   definition; a global buffer reintroduces §4's FP problem at full
   strength.
4. **Encrypted-then-split.** Encrypt the canary under an attacker key,
   then split the ciphertext. Reassembly recovers ciphertext, not the
   registry value. The decode-variant layer only inverts encodings the
   *defender* knows; attacker-keyed encryption is not invertible by the
   tripwire, at any split depth. This is the same residual class as the
   wave-51 custom-cipher residual and DLP's F8 — acknowledged, not
   fixable at the tripwire.
5. **Recognition-avoidance compositions.** Split + format-mimicry (dashes
   every 4 chars per chunk), split + >2-layer encoding per chunk — each
   chunk defeats a different layer, and the layers' bounds compose
   against the defender.

Items 1–3 are *deterministic defeats by a moderately capable adversary*;
item 4 is a *class defeat* (no tripwire reassembles what it cannot
decrypt). None of them is a novel finding — they are the reason the
RT20 residuals were filed as residuals, not findings.

---

## 6. Verdict: design-only, NO prototype

**The design review does not survive.** The verdict is to ship this
design document with the verdict, and not build the reassembler:

1. **P1 (within-call) reassembly is sound but strategically empty.** It
   preserves the exactness invariant and would close
   `split_halves_two_params_residual` — but the adversary's cost of
   moving to P2 (two calls) is ~zero, and P2 is the residual RT20
   actually pinned as sharpest ("split into halves executes end-to-end"
   is the two-*call* instance). A P1 prototype would demonstrate a
   one-rung ratchet the adversary steps over for free. Building it to
   "hit a number" would be theater: a new green probe next to a
   documented, still-open residual of the same shape one level deeper.

2. **P2 (cross-call) reassembly is a losing game.** §2: any bound is
   gamed deterministically (bound+1). §4: the FP story degrades from
   exactness to heuristic. §5: three deterministic defeats and one class
   defeat survive even the unbounded ideal. A prototype would prove
   what the paper review already proves, at the cost of adding
   adversary-influenced cross-call state (a new DoS/bypass surface) to
   the executor's hot path.

3. **The reassembly already happens — at the wrong layer.** The tripwire
   is inward-facing deception (agent-as-exfiltrator). The *wall* that
   answers "did the secret leave" is the §2a egress proxy: it sees the
   byte stream per connection, where P1/P2/P3 splits are all just bytes
   and per-connection reassembly is free (TCP does it). When F81's proxy
   is built, DLP/content scanning belongs on the reassembled stream at
   the proxy — not on tool-call fragments in the executor. Building a
   tool-call reassembler now would duplicate, badly, work the proxy does
   naturally.

**What would change this verdict:** the F81 proxy existing. At that
point the design question reopens as "stream-reassembly DLP at the
proxy" — a different layer, different bounds (per-connection, kernel/
proxy-owned buffers, no cross-call inference), and the honest residual
is only item 4 (encrypted-then-split), which no content control closes.
Until then, the tripwire keeps its exactness invariant, the RT20
residuals stay pinned as residuals, and F81 stays OPEN.

## 7. Explicit non-goal

This design does **not** turn the tripwire into a wall, and no
reassembly design could. The tripwire detects exfiltration of *planted
canaries*. Honest class closure of "the agent exfiltrated data" requires
three things, none of which is reassembly:

1. **A destination wall** — the F81 proxy: per-request hostname
   resolution, private-range deny above allow rules, default-deny. This
   stops exfiltration *regardless of content*, including encrypted
   payloads and non-canary secrets.
2. **Content inspection on reassembled streams at the wall** — DLP over
   proxy-reassembled bytes (defeats P1–P3 splits of *known* shapes;
   still loses to attacker-keyed encryption — item 4 above, honestly).
3. **Secret hygiene** — the agent never holds real secrets in
   exfiltratable form (the canary program's actual point: trips prove
   the *path* is hot, so operators fix the path).

Reassembly at the tripwire would have been a stronger tripwire. The
class needs a wall. F81 stays OPEN until the wall exists.

---

*Wave-55 coordinator verdict, 2026-09-22. Reviewed against:
`gov/canary.py` (§scan_egress_attempt, decode-variant bounds),
RT20 residuals (`evals/scenarios/registry.yaml`
`canary.rt20.split_halves_*`), F25 (bounded adversary-influenced state),
F81 closure-probe family (hostname-trust lesson: resolver isolation),
founder-strategy §2a (proxy frame).*
