#!/usr/bin/env python3
"""Deterministic cost-estimate cache for the real-model harness (R29).

Bernstein #6012 mechanics, ADAPT pattern only (Apache-2.0; no code
copied -- this module is written from the pattern description).

The real-model harness (``evals/realmodel_harness.py``) enforces spend
caps with worst-case cost estimates computed before every API call.
This module memoizes those estimates so identical ``(model, prompt,
max_tokens, temperature)`` inputs always produce identical estimates
with NO network I/O. The cache is persisted as versioned JSON
alongside the ledger
(``~/workspace/realmodel_ledger/spend_cache.json``, overridable via
``REALMODEL_SPEND_CACHE``).

What the cache is NOT: it never authorizes spend. Caps are enforced by
``SpendLedger.precheck`` on every call; the cache only feeds the
worst-case estimate into that check. A cache HIT on a breached cap
still refuses -- the refusal path never consults the cache for
permission, only for the estimate.

Integrity rules:

- Cache key = sha256 of canonical JSON ``{model, prompt_sha256,
  max_tokens, temperature}`` where ``temperature`` is normalized to
  ``float`` (``0`` and ``0.0`` are the same key).
- Each entry records the sha256 digest of the pricing table that
  produced it. A pricing-table change makes stale entries MISS and
  recompute; a stale price is never silently reused.
- The miss path is pure computation from the caller-supplied price
  table. This module has no network imports and makes no network
  calls -- losing determinism would defeat its purpose.
- Losing the cache file only costs recompute: every estimate is
  re-derivable from the published price table.

Stdlib only. $0 spend. No network.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CACHE_VERSION = 1


def conservative_token_estimate(text):
    """Overestimate token count without tiktoken: ~3 chars/token.

    Deliberately conservative (real ratio is ~4) so the pre-call
    worst-case estimate can only overshoot, never undershoot.
    Single source of truth: evals/realmodel_harness.py aliases this.
    """
    return max(1, len(text) // 3)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class SpendCache:
    """Content-hash-keyed memo of worst-case cost estimates."""

    def __init__(self, path=None):
        if path is not None:
            self.path = Path(path)
        elif os.environ.get("REALMODEL_SPEND_CACHE"):
            self.path = Path(os.environ["REALMODEL_SPEND_CACHE"])
        else:
            self.path = Path(
                os.path.join(os.path.expanduser("~"), "workspace",
                             "realmodel_ledger", "spend_cache.json"))
        self.hits = 0
        self.misses = 0
        self.entries = {}
        self._load()

    # -- keying --------------------------------------------------------

    @staticmethod
    def prompt_hash(prompt_text):
        return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

    def key(self, model, prompt_text, max_tokens, temperature):
        canonical = _canonical({
            "model": model,
            "prompt_sha256": self.prompt_hash(prompt_text),
            "max_tokens": max_tokens,
            "temperature": float(temperature),
        })
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def prices_digest(prices):
        canonical = _canonical(
            {m: [float(v[0]), float(v[1])] for m, v in sorted(prices.items())})
        return hashlib.sha256(canonical).hexdigest()

    # -- persistence ----------------------------------------------------

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            return
        entries = data.get("entries")
        if isinstance(entries, dict):
            self.entries = entries

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "version": CACHE_VERSION,
            "entries": self.entries,
        }, indent=1))
        tmp.replace(self.path)

    # -- the estimate ---------------------------------------------------

    def estimate(self, model, prompt_text, max_tokens, temperature, prices):
        """Return (usd, hit). Miss computes from the price table; the
        miss path is pure local computation -- no network."""
        if model not in prices:
            raise KeyError("model %r not in price table" % (model,))
        digest = self.prices_digest(prices)
        cache_key = self.key(model, prompt_text, max_tokens, temperature)
        entry = self.entries.get(cache_key)
        if entry is not None and entry.get("prices_digest") == digest:
            self.hits += 1
            return float(entry["usd"]), True
        prompt_tokens = conservative_token_estimate(prompt_text)
        price_in, price_out = prices[model]
        usd = (prompt_tokens * price_in + max_tokens * price_out) / 1e6
        self.entries[cache_key] = {
            "usd": usd,
            "prices_digest": digest,
            "model": model,
            "max_tokens": max_tokens,
            "temperature": float(temperature),
        }
        self.misses += 1
        self._save()
        return usd, False

    def clear(self):
        self.entries = {}
        self.hits = 0
        self.misses = 0
        self._save()
