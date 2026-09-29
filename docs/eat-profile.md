# Sasanam EAT Profile v1

Profile URI: `https://sasanam.dev/profiles/attested-identity/v1`

This document is the EAT profile (RFC 9711, Section 6) for the EAT-*shaped*
attestation tokens emitted by `gov/eat_claims.py`. It pins every option RFC
9711 leaves open, so an auditor can consume the token without the engine —
and so any deviation is machine-detectable. The profile mechanism is itself
the honesty instrument: what is not pinned here is not promised.

**Status: EAT-shaped, not wire-interoperable.** This profile covers the
JSON/JWT path only. No CBOR/COSE emission is defined for v1. Do not claim
EAT conformance or interoperability for tokens under this profile.

## 1. Encoding and envelope

| Option | Pinned value |
|---|---|
| Serialization | JSON (RFC 9711 normative JSON path). Canonical form: sorted keys, no whitespace, ASCII (`gov.attested_identity.canonical_json`). |
| Envelope | JOSE JWS compact serialization: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`. |
| `alg` | `EdDSA` (Ed25519, pure; RFC 8037). No other algorithm is accepted. |
| `typ` | `application/eat+jwt`. Exact match required. |
| Header fields | Closed to `alg`, `typ`, `kid`. Any other header field is refused (signature re-targeting is not tolerated). |
| CBOR / CWT / COSE | Not defined. A token presented in CBOR is not a v1 token. |

## 2. Key identification

Verifier key identification is out-of-band, per EAT: the relying party pins
the issuer's 32-byte Ed25519 public key in its trust configuration. `kid`
MAY appear in the header but is informational only and is never trusted
for key selection.

## 3. Freshness

Freshness is mandatory. The token carries `eat_nonce` (superior module) and
every submodule carries its own `eat_nonce`. All nonces are compared with
constant-time comparison against verifier-supplied expected values.
There is no nonce inheritance: a submodule is never fresh by virtue of
the superior module's nonce, and the verifier must be configured with an
expected nonce per submodule.

Token lifetime: `iat`/`exp` window, default TTL 300 seconds. A token is
valid only while `iat <= now < exp`.

## 4. Claims

### 4.1 Superior claims set (mandatory)

`iss`, `iat`, `exp`, `cti`, `eat_nonce`, `eat_profile`, `intuse`, `submods`.

* `eat_profile` MUST equal this profile's URI. Any other value is refused:
  profile confusion is token confusion.
* `intuse` is pinned to `workload-bound key issuance for agent identity`.
* Attester facts (ueid, oemid, hwmodel, measurements, dbgstat, swname, ...)
  MUST NOT appear in the superior claims set. This is the no-inheritance
  rule as a wire constraint, enforced at emit and at verify.

### 4.2 Submodules (mandatory, non-empty, closed composition)

Submodule names are closed to: `tpm`, `tee`, `aws_iid`, `gcp_iid`. Each
submodule carries: `ueid`, `eat_nonce` (its own), `dbgstat`, `measurements`
(non-empty object), `measres`.

* `dbgstat` MUST be `disabled`. Any other value is refused fail-closed.
* `measres` is `pass`, `fail`, or `unassessed`. `fail` is always refused.
  `unassessed` (no reference values at emit time) is refused unless the
  verifier explicitly opts in (`allow_unassessed`).
* When the verifier holds reference values, every measurement listed in
  them must equal the token's value (constant-time compare).
* `oemid`, `hwmodel`, `hwversion`, `swname`, `swversion`, `manifests`
  are optional. `location` is never emitted (privacy). `sueids`, `uptime`,
  `bootcount`, `bootseed` are not emitted in v1.

### 4.3 Unknown claims

Unknown *payload* claims are tolerated and ignored (RFC 9711 Section 6.3
posture): the verifier fails closed only on claims it understands that
violate policy. This is the forward-compatibility rule; it does not
extend to the header (closed, Section 1) or to submodule names (closed,
Section 4.2).

## 5. What a v1 token proves — and does not

The token proves: claim-set conformance to this profile; freshness
bindings of token and submodules to single-use nonces; measurement
equality against the verifier's reference values; debug-disabled state
at attestation time; the issuer key identity of the signer.

The token explicitly does NOT prove: attester implementation strength;
workload behavior inside the attested environment; validity beyond `exp`;
the truth of vendor-supplied `oemid`/`hwmodel` labels; platform state
after attestation time. Emitting an EAT standardizes the *vocabulary* of
the claim, never its strength (RFC 9711: an EAT "does not require any
particular level of security in the implementation of the claims").

Machine-readable form: `gov.eat_claims.eat_claim_bounds()`, valid under
`gov/claim_bounds.py`.

## 6. Privacy posture

`ueid` values are entity identifiers. Default emission uses digest-form
identifiers (e.g. EK public-key SHA-256, chip-id hashes), never raw key
material. `location` is omitted. Deployments handling regulated
identifiers scope `ueid` emission per deployment policy.

## 7. Residuals

* Synthetic fixtures only: this profile does not change the project's
  no-live-hardware residual. A token over synthetic evidence is a
  vocabulary exercise, not an attestation.
* No revocation beyond the short `exp` window.
* The CWT key-number mapping is documented in `gov/eat_claims.py`
  (`EAT_CLAIM_KEYS`) for a future CBOR lane; it is not emitted in v1.
