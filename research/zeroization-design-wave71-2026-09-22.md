# In-memory key zeroization — design (Wave-71, 2026-09-22)

Threat: key material lives in process memory. A core dump, a
`/proc/<pid>/mem` read, or memory-scraping malware recovers HMAC keys
and mints arbitrary chain entries. The standard mitigation is wiping
key buffers after use. This document proves, with measurements, what
CPython lets us wipe and what it doesn't — before any code ships.
Theater here is worse than nothing.

## (a) Wipe inventory — every place key material lives

Traced from `gov/keyprovider.py` → `resolve_active_key()` →
`gov/log.py::_active_key()` → the 9 `_active_key()` call sites
(`append`, `write_checkpoint`, `_verify`, tip-cache read/write,
`write_chain_tip_from_tail`, marker seeding, 2× `egress_ledger.py`)
→ `hmac.new(key, msg, hashlib.sha256)`.

| # | Location | Type | Wipable? | Reason |
|---|----------|------|----------|--------|
| 1 | `KeyMaterial.key` (provider storage: env/file/KMS rings) | `bytes` (today) | NO (today) → YES with bytearray storage + `destroy()` | Immutable; `bytes` cannot be overwritten in place. Becomes wipable only at discard time — while the process appends, the key must stay live. |
| 2 | `resolve_active_key()` / `_active_key()` return value | `bytes` (provider buffer post-wave-71: `bytearray`) | transient, refcount-freed | Caller local; CPython refcounting frees non-cyclic temporaries deterministically at frame exit. Refcount census (wave-71 test): after the HMAC call exactly two holders exist (provider `__dict__` + caller frame) — the HMAC object retains no Python-level reference. Post-`destroy()`: one holder (caller frame), freed at `del`. NOTE: an earlier draft claimed "0 reachable copies via `gc.get_objects()`" — retracted pre-ship: `bytes`/`bytearray` are not gc-tracked in CPython, so that scan vacuously passes. The refcount census is the honest replacement. |
| 3 | `hmac.new(key, …)` internal copy | C-level (`_hashlib` HMAC_CTX) or digest objects (pure-Python fallback) | NO | Outside caller control; no Python API reaches it. OpenSSL appears to cleanse on context free (measured: no deterministic residue attributable to it, E5b); the pure-Python fallback keeps key-derived state in digest buffers that are freed, never wiped. Either way: **not wipable from Python**. |
| 4 | CPython allocator freelists | freed `bytes`/C buffers | NO | CPython never zeroes freed memory; residue persists until the block is reused. No Python API scrubs the heap. HONEST CAVEAT (E2): a self-scan of `/proc/self/mem` reported 2 raw-mem hits where only 1 was a live variable, but a repeat experiment did NOT reproduce the extra hit — the scanner reads process memory INTO Python `bytes`, contaminating its own later scans, so a self-scan cannot distinguish genuine residue from scanner artifacts. The allocator/HMAC-C residual is therefore stated as an ARCHITECTURAL residual (allocator never zeroes; HMAC C internals hold inaccessible copies), not a measured count. |
| 5 | `os.environ["GOV_LOG_KEY"]` (+ `_EPOCH`, `_ARCHIVE`) | `str` | NO | Immutable; `str.encode()` makes a fresh `bytes` per resolve. The `str` can only be `del`eted (removes reachability, not the bytes). `zeroize()` **refuses** `str`/`bytes` with `TypeError` — a "wipe" of an immutable would be silent theater. |
| 6 | File/JSON parse path (`KeyRing.load`, `from_env` archive) | `str` → `bytes` intermediates | NO | `json.loads` produces `str`; `.encode()` produces `bytes`. Every intermediate is immutable and un-wipable. |
| 7 | `KeyMaterial.key_id` | hex digest `str` | N/A | `sha256(key)` digest, not the key. Safe by preimage resistance. |
| 8 | GC-delayed copies | `bytes` in refcount cycles | NO (while delayed) | Immutable; freed only when the cyclic GC runs. Transient. |
| 9 | `bytes(bytes_obj)` aliasing | — | N/A (no copy) | Measured (E7): `bytes(x)` on a `bytes` returns `x` itself — fewer copies than feared. `bytes(bytearray)` DOES copy. |

Net: the **only** Python-reachable, long-lived, wipable buffers are
provider-held keys **at discard time** (rotation/shutdown/KMS
materialize-then-discard), and only if stored as `bytearray`.
Everything on the per-append hot path is either already unreachable
(refcounting) or immutable/C-level (un-wipable).

## (b) Mechanism

New module `gov/zeroize.py`:

- `zeroize(buf)` — overwrites a `bytearray` (or writable
  `memoryview`) with zeros via slice assignment; idempotent
  (double-wipe safe). Raises `TypeError` on `bytes`/`str`/read-only
  buffers: **fail-loud against theater** — you cannot wipe an
  immutable, and pretending to is worse than refusing.
- `key_buffer(key)` — context manager: copies any bytes-like key into
  a fresh `bytearray`, yields it, zeroizes on exit (exception-safe via
  `finally`). The transient copy never escapes the `with` block.
- Use-after-wipe posture: **never-expose-wiped-buffers**. `destroy()`
  zeroizes then sets `KeyMaterial.key = None`, so any later use raises
  loud (`TypeError`/`AttributeError`) instead of silently HMACing with
  an all-zero key (the forgery footgun: zero-key MACs are computable by
  anyone). Proven by test: post-`destroy()` HMAC use raises; a MAC
  computed from a wiped buffer does not verify under the real key.
- **Refuted shape (recorded, not built):** `key_buffer()` was
  considered for a released-`memoryview` yield (wipe + `view.release()`
  in `finally`, so a retained post-exit buffer would raise `ValueError`
  on any access instead of silently HMACing zeros). REFUTED by
  measurement: CPython 3.12's `hmac.new` isinstance-checks its key
  (`TypeError: key: expected bytes or bytearray, but got
  'memoryview'`) — the exact call our 13-site chokepoint uses — so a
  memoryview yield breaks the primary in-block use (`hmac.digest`
  and `pbkdf2_hmac` accept memoryview; `hmac.new` does not). The
  loud guarantee therefore lives at the `destroy()` boundary (the
  actual provider-key discard path). For `key_buffer()`, the pinned
  property is detectably-wrong-at-verification: a retained post-exit
  buffer holds zeros, its MAC differs from the real key's MAC, and any
  verifier holding the real key rejects it. Retaining the buffer past
  the block is a caller bug; the API cannot invalidate someone else's
  `bytearray` reference, and pretending otherwise would be theater.

`gov/keys.py`:

- `KeyMaterial.key` becomes `bytearray` (always a copy — no more
  `bytes(x) is x` aliasing). All existing uses (`decode`, `==`,
  `hmac.new`, `hashlib.sha256`, JSON round-trip) are
  buffer-protocol-compatible; the full suite proves no regression.
- `KeyMaterial.destroy()` — `zeroize(self.key)`, then `self.key =
  None` (fail-loud). `KeyRing.destroy()` destroys every epoch.
- Deliberately NOT changed: the 9 `_active_key()` call sites. The
  census proves their transient buffers are already unreachable after
  use; wrapping them in `key_buffer` would wipe nothing reachable and
  cannot touch the C/allocator residue — shipping that would be
  theater. (If a future backend holds keys outside CPython objects,
  `key_buffer` is the discipline for its trust boundary.)

## (c) Honesty ledger — what this wave does NOT fix

1. **Raw-memory readers are NOT defeated.** Core dump,
   `/proc/<pid>/mem`, memory-scraping malware: a self-scan found key
   bytes in own-process heap after a Python-level wipe, but the scan
   is contaminated (the scanner itself allocates `bytes` while
   reading) and non-reproducible — so the residual is an
   architectural fact, not a measured count. `destroy()` removes
   *reachable* copies; it cannot scrub allocator freelists or
   C-extension buffers. For these three attackers the wipable
   fraction is ~zero. The real fix is deployment-owned: HSM/offload
   or a C-extension locked-memory backend (wave-72 questions).
2. **Long-lived process keys cannot be wiped while in use.** Env/file
   backends must hold the key for the process's appending lifetime;
   env `str` values are immutable anyway.
3. **Length is not hidden.** Zeroing overwrites content, not length;
   a 32/64-byte zeroed region still advertises "a key lived here".
4. **`MADV_DONTDUMP`/`mlock` not implemented.** `madvise`
   `MADV_DONTDUMP` would exclude key pages from core dumps only —
   partial (does nothing for `/proc/pid/mem` or malware), C-level
   work, deferred as future deployment-owned hardening.
5. **The real fix is deployment-owned:** don't hold the HMAC key in
   the Python process — HSM/offload signing, or a C-extension
   locked-memory backend that computes HMAC without exposing the key
   to CPython objects. The envelope-KMS seam (`gov/kms.py`) exists
   for exactly this migration.

## (d) Definition of done

- `gov/zeroize.py` ships with the fail-loud immutable refusal.
- `KeyMaterial`/`KeyRing.destroy()` ship; copy-census test asserts
  the wipable inventory is gone after `destroy()` and documents the
  deterministic residuals (env `str`, caller's immutable input).
- Break-first probes: wipe verification, double-wipe safety,
  use-after-wipe loud failure, exception-path wipe, immutable
  refusal, destroy-then-census — all HOLD.
- Full suite green (no legitimate-behavior regression from the
  `bytes`→`bytearray` storage change).
- No new finding: no genuine independently-reachable miss was found;
  the residual is a documented boundary (F81 stays the only OPEN
  finding; F129 stays next free).
- This document, the intake note, BUILD_LOG (newest-first),
  REALWORLD_BAR wave-71 header, FINDINGS.md touch-up.

Verdict framing: for **reachable-graph readers** (the attacker who can
walk Python objects but not raw memory) the shipped layer is complete
— proven by the census test. For **raw-memory readers** (the wave's
stated threat model) this wave is an **honest negative result**: the
measurement shows the mitigation cannot deliver the guarantee in
CPython, the boundary is documented, and the real fix is named.
Shipping the narrowly-scoped primitive with that bound is
defense-in-depth, not theater — claiming more would be.
