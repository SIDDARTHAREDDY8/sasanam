# CONNECT-parser / authority-grammar fuzzing report (wave-58 Lane 4, B5 pressure)

Wave-57 admitted bespoke userspace is our own bug surface. This lane
fuzzed the two trust-boundary parsers in `gov/egress_proxy.py` —
`_parse_authority` (CONNECT authority grammar) and `_read_request`
(request-line framing) — plus `decide()` end-to-end.

## Method

Deterministic seeded corpus, `workstreams/evals/fuzz_connect.py`
(`random.Random(20260922)`; no network, no runtime randomness):

- 4,562 authority inputs: hand-picked adversarial seeds (absolute-form vs
  authority-form vs asterisk, userinfo smuggling `user@host@evil`,
  port confusion `host:80:evil` / `host:` empty / non-numeric / `>65535` /
  leading zeros, case/whitespace folding, encoded dots `%2e`, `..`,
  trailing-dot FQDNs, IDNA/punycode, bracketed IPv6, NUL/control/unicode
  injections) × systematic char-level mutations (dup/del/swap/insert/
  case/whitespace, incl. `\u00b2`, `\u3000`, `\x00`) × 500 latin-1 soup
  strings; non-str inputs (`None`, `123`, `b"host:443"`, list, dict).
- 610 request-line inputs: mutation of valid/invalid request lines ×
  mixed line endings (`\r\n\r\n`, `\n\n`, `\r\r`, `\r\n\n`, `\n\r\n`),
  one 9,000-byte overlong line, one empty input — all through
  `serve_stream` over `socketpair` (the real `_read_request` path).

Properties checked per input:
- **P1** — `_parse_authority` / `decide` / `serve_stream` never raise.
- **P2** — the parser never returns a target outside the grammar
  (host without whitespace/control/`@`; port ASCII-digit int-able).
- **P3** — every *accepted* target re-serializes to itself
  (`decide`'s `(host, port)` re-parsed yields the identical pair).

## Findings

**F125 (filed, fixed this wave): unicode-digit port crash.**
`str.isdigit()` is True for `²`, `①②`, `½` — but `int()` rejects them.
`_parse_authority` accepted the port; `decide()` called `int(port_raw)`
unguarded → `ValueError` escaped `serve_stream`. 75 distinct crash inputs
pre-fix. Independently reachable by the untrusted cage child over its
client socket (no harness access needed). Severity LOW: availability, not
bypass — a dead worker degrades toward no-network (fail-closed); no
verdict was ever wrong and no byte flowed. Fix in `gov/egress_proxy.py`:
explicit ASCII-only authority grammar at parse (`port.isascii() and
port.isdigit()`; bracketed form `\d+` → `[0-9]+`; unbracketed host
restricted to `[A-Za-z0-9.-]+` — a superset of the policy `_HOST_RE`
alphabet, so nothing the allowlist could ever match is refused), plus
try/except around `int(port_raw)` in `decide()` → `malformed-authority`
deny as defense in depth.

**Refuted / fail-closed shapes (no finding):** userinfo smuggling
(`user@host@evil`) → deny; `host:80:evil`, empty/non-numeric/`>65535`
ports → deny; absolute-form (`CONNECT http://host:443/`) → deny;
case-folded method (`connect`) → `method-check` deny; LF-only / mixed
line endings → `malformed-request` deny; 9KB overlong line → refused by
the 8,192-byte cap; encoded dots (`%2e`) and `..` hosts → never match the
allowlist → deny (percent-decoding is deliberately absent: the allowlist
is exact-match on the normalized ASCII form); trailing-dot FQDNs and
case variants → normalized to the canonical entry (P3 holds —
normalization is documented, not an escape); IDNA/punycode labels pass
the grammar but match only if explicitly enumerated.

## Post-fix result

**0 crashes, 0 grammar escapes** across the full corpus (9,124
per-authority parse/decide outcomes — 4,562 authorities × 2
(parse + decide) — plus 610 request-line sessions); P3 round-trip holds
for every accepted target. Regression tests:
`tests/test_egress_proxy.py::TestF125UnicodeDigitPort` (4 tests).
Corpus generator retained at `workstreams/evals/fuzz_connect.py` —
re-runnable on every parser touch.
