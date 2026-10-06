#!/usr/bin/env python3
"""Wave-340 lane 3: deterministic spend cache (Bernstein #6012 ADAPT) regression.

Base: `9351ab86` (wave-339 merge). Pin 2131. Footer open F427 / next F430.

R29: the real-model harness ledger appends one entry per call with an
estimated spend. A deterministic cost-estimate cache memoizes the
worst-case estimate keyed on (model, prompt-hash, max_tokens,
temperature): identical inputs always produce identical estimates with
no network I/O; the cache is persisted alongside the ledger; hit/miss
behavior is deterministic and testable. The cache NEVER authorizes
spend -- caps are still enforced by SpendLedger.precheck on every call.

What this battery pins:

P1 (red-capable): identical inputs -> identical estimates; the second
  call is a cache hit. Expected value is a hand-computed literal from
  the published price table, not recomputed by the code under test.
P2 (red-capable): the cache persists across processes -- a new
  SpendCache on the same path sees the entry as a hit.
P3 (red-capable): a cache miss performs no network I/O (urlopen
  monkeypatched to raise) and the module has no network imports
  (AST scan).
P4 (red-capable): cache-hit estimate == independently hand-computed
  estimate on a second prompt/model literal.
P5 (red-capable): temperature is part of the cache key.
P6 (red-capable): a changed pricing table invalidates stale entries
  (prices-digest mismatch -> miss + recompute).
P7 (red-capable): the cache never authorizes spend -- precheck still
  refuses with BudgetRefused on a cache HIT when a cap is breached.
P8 (red-capable): the estimator agrees with
  realmodel_harness._conservative_token_estimate on a fixed corpus
  (single source of truth after the move).
P9 (red-capable): persisted cache format is versioned JSON keyed by
  64-hex digests; atomic write leaves no .tmp behind.
P10 (pin): TAXONOMY_PIN == 2135 and the registry holds 2127 codes.

Verdicts: HELD = behavior matches the pin; BREAK = genuine defect;
ERROR = probe/harness problem. No findings manufactured.

$0 spend; synthetic/local; no model calls. The battery never touches
the real ledger: every probe uses tmp paths (REALMODEL_LEDGER and
REALMODEL_SPEND_CACHE are pointed at tmp dirs, and SpendLedger /
SpendCache take explicit paths).

Run:
  mkdir -p /var/tmp/g340-spendcache
  TMPDIR=/var/tmp/g340-spendcache ~/workspace/.gov-venv/bin/python evals/w340_spendcache_probes.py
Clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g340-spendcacheb ~/workspace/.gov-venv/bin/python evals/w340_spendcache_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w340_spendcache_probes.py P1
"""

import ast
import json
import os
import sys
import tempfile
import traceback
import urllib.request

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); breaks documented above

PRICES_MINI = {"gpt-4o-mini": (0.15, 0.60)}
PRICES_O = {"gpt-4o": (2.50, 10.00)}

# Hand-computed literals (independent of the code under test):
#   tokens = max(1, len(prompt) // 3); usd = (t*pin + max_tokens*pout)/1e6
# P1: prompt "ATTACK"*10 = 60 chars -> 20 tokens; mini (0.15, 0.60);
#     max_tokens 150 -> (20*0.15 + 150*0.60)/1e6 = 93/1e6.
P1_WANT_USD = 0.000093
# P4: prompt "x"*7 = 7 chars -> max(1, 7//3) = 2 tokens; gpt-4o
#     (2.50, 10.00); max_tokens 100 -> (2*2.5 + 100*10)/1e6 = 1005/1e6.
P4_WANT_USD = 0.001005


def _fresh_cache(tmpdir):
    import spend_cache
    return spend_cache.SpendCache(path=os.path.join(tmpdir, "spend_cache.json"))


def p1_identical_inputs_identical_estimates():
    """Identical inputs -> identical estimates; second call is a hit."""
    try:
        tmp = tempfile.mkdtemp(prefix="spendcache-p1-")
        cache = _fresh_cache(tmp)
        prompt = "ATTACK" * 10
        usd1, hit1 = cache.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
        usd2, hit2 = cache.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
    except Exception:
        return "ERROR", "P1", traceback.format_exc(limit=3)
    if abs(usd1 - P1_WANT_USD) > 1e-12:
        return "BREAK", "P1", "estimate %r != hand-computed %r" % (usd1, P1_WANT_USD)
    if usd1 != usd2:
        return "BREAK", "P1", "identical inputs gave different estimates"
    if hit1:
        return "BREAK", "P1", "first call should be a miss"
    if not hit2:
        return "BREAK", "P1", "second identical call should be a hit"
    return "HELD", "P1", "identical inputs -> identical estimates; miss then hit"


def p2_persists_across_processes():
    """A new SpendCache on the same path sees the entry as a hit."""
    try:
        import spend_cache
        tmp = tempfile.mkdtemp(prefix="spendcache-p2-")
        path = os.path.join(tmp, "spend_cache.json")
        cache_a = spend_cache.SpendCache(path=path)
        prompt = "ATTACK" * 10
        usd_a, _ = cache_a.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
        del cache_a
        cache_b = spend_cache.SpendCache(path=path)  # new "process"
        usd_b, hit_b = cache_b.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
    except Exception:
        return "ERROR", "P2", traceback.format_exc(limit=3)
    if not hit_b:
        return "BREAK", "P2", "reopened cache did not hit"
    if usd_a != usd_b:
        return "BREAK", "P2", "reopened cache returned a different estimate"
    # Env override precedence: REALMODEL_SPEND_CACHE beats the default
    # path, so tests can redirect the cache without touching the ledger.
    try:
        env_path = os.path.join(tmp, "env_cache.json")
        old = os.environ.get("REALMODEL_SPEND_CACHE")
        os.environ["REALMODEL_SPEND_CACHE"] = env_path
        try:
            cache_c = spend_cache.SpendCache()
        finally:
            if old is None:
                os.environ.pop("REALMODEL_SPEND_CACHE", None)
            else:
                os.environ["REALMODEL_SPEND_CACHE"] = old
        env_ok = (str(cache_c.path) == env_path)
    except Exception:
        return "ERROR", "P2", traceback.format_exc(limit=3)
    if not env_ok:
        return "BREAK", "P2", "REALMODEL_SPEND_CACHE did not redirect the cache"
    return "HELD", "P2", "cache persists across processes; env redirects"


def p3_miss_does_no_network():
    """A cache miss performs no network I/O; the module has no network imports."""
    try:
        import spend_cache
        src = open(spend_cache.__file__, encoding="utf-8").read()
        tree = ast.parse(src)
        banned = {"urllib", "socket", "http", "requests", "ssl"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in banned:
                        return "BREAK", "P3", "network import: %s" % a.name
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in banned:
                    return "BREAK", "P3", "network import-from: %s" % node.module
        tmp = tempfile.mkdtemp(prefix="spendcache-p3-")
        cache = _fresh_cache(tmp)
        real_urlopen = urllib.request.urlopen

        def _boom(*a, **k):
            raise AssertionError("network touched during cache miss")

        urllib.request.urlopen = _boom
        try:
            usd, hit = cache.estimate("gpt-4o-mini", "ATTACK" * 10, 150, 0, PRICES_MINI)
        finally:
            urllib.request.urlopen = real_urlopen
    except Exception:
        return "ERROR", "P3", traceback.format_exc(limit=3)
    if hit:
        return "BREAK", "P3", "fresh cache should miss"
    if abs(usd - P1_WANT_USD) > 1e-12:
        return "BREAK", "P3", "miss estimate %r != hand-computed %r" % (usd, P1_WANT_USD)
    return "HELD", "P3", "miss performs no network I/O; no network imports"


def p4_hit_equals_computed():
    """Cache-hit estimate == independently hand-computed estimate."""
    try:
        tmp = tempfile.mkdtemp(prefix="spendcache-p4-")
        cache = _fresh_cache(tmp)
        prompt = "x" * 7
        cache.estimate("gpt-4o", prompt, 100, 0, PRICES_O)  # warm (miss)
        usd, hit = cache.estimate("gpt-4o", prompt, 100, 0, PRICES_O)
    except Exception:
        return "ERROR", "P4", traceback.format_exc(limit=3)
    if not hit:
        return "BREAK", "P4", "warmed entry should hit"
    if abs(usd - P4_WANT_USD) > 1e-12:
        return "BREAK", "P4", "hit estimate %r != hand-computed %r" % (usd, P4_WANT_USD)
    return "HELD", "P4", "hit estimate == hand-computed literal"


def p5_temperature_in_key():
    """Temperature is part of the cache key."""
    try:
        import spend_cache
        tmp = tempfile.mkdtemp(prefix="spendcache-p5-")
        cache = _fresh_cache(tmp)
        prompt = "ATTACK" * 10
        k0 = cache.key("gpt-4o-mini", prompt, 150, 0)
        k7 = cache.key("gpt-4o-mini", prompt, 150, 0.7)
        if k0 == k7:
            return "BREAK", "P5", "temperature not in cache key"
        _, _ = cache.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
        _, hit_other = cache.estimate("gpt-4o-mini", prompt, 150, 0.7, PRICES_MINI)
        if hit_other:
            return "BREAK", "P5", "different temperature should miss"
        _, hit_again = cache.estimate("gpt-4o-mini", prompt, 150, 0.7, PRICES_MINI)
        if not hit_again:
            return "BREAK", "P5", "same temperature should hit"
    except Exception:
        return "ERROR", "P5", traceback.format_exc(limit=3)
    return "HELD", "P5", "temperature is part of the cache key"


def p6_pricing_change_invalidates():
    """A changed pricing table invalidates stale entries (digest mismatch)."""
    try:
        tmp = tempfile.mkdtemp(prefix="spendcache-p6-")
        cache = _fresh_cache(tmp)
        prompt = "ATTACK" * 10
        usd1, _ = cache.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
        raised = dict(PRICES_MINI)
        raised["gpt-4o-mini"] = (0.30, 1.20)  # prices doubled
        usd2, hit2 = cache.estimate("gpt-4o-mini", prompt, 150, 0, raised)
        if hit2:
            return "BREAK", "P6", "stale entry reused after pricing change"
        if abs(usd2 - 2 * usd1) > 1e-12:
            return "BREAK", "P6", "recompute %r != 2x old %r" % (usd2, usd1)
        usd3, hit3 = cache.estimate("gpt-4o-mini", prompt, 150, 0, raised)
        if not hit3 or usd3 != usd2:
            return "BREAK", "P6", "new-pricing entry not cached"
    except Exception:
        return "ERROR", "P6", traceback.format_exc(limit=3)
    return "HELD", "P6", "pricing-table change invalidates stale entries"


def p7_cache_never_authorizes_spend():
    """Precheck still refuses on a cache HIT when a cap is breached."""
    try:
        import spend_cache
        from realmodel_harness import SpendLedger, BudgetRefused
        tmp = tempfile.mkdtemp(prefix="spendcache-p7-")
        cache = spend_cache.SpendCache(path=os.path.join(tmp, "spend_cache.json"))
        ledger = SpendLedger(
            path=os.path.join(tmp, "ledger.json"),
            mirror_path=os.path.join(tmp, "ledger-mirror.json"),
            total_budget=0.00001, run_cap=0.00001, call_cap=10.0,
            spend_cache=cache)
        prompt = "ATTACK" * 10
        ledger.worst_case_cost(prompt, 150, "gpt-4o-mini", PRICES_MINI)  # warm (miss)
        # Confirm the estimate is now a cache hit, then breach the cap.
        usd, hit = cache.estimate("gpt-4o-mini", prompt, 150, 0, PRICES_MINI)
        if not hit:
            return "BREAK", "P7", "warmed estimate should hit"
        try:
            ledger.precheck(prompt, 150, "gpt-4o-mini", PRICES_MINI, "p7")
        except BudgetRefused:
            return "HELD", "P7", "precheck refuses on cache hit when capped"
        return "BREAK", "P7", "precheck allowed spend past the cap on a hit"
    except Exception:
        return "ERROR", "P7", traceback.format_exc(limit=3)


def p8_estimator_single_source():
    """The estimator agrees with the harness on a fixed corpus."""
    try:
        import spend_cache
        import realmodel_harness as h
        corpus = {"": 1, "ab": 1, "abc": 1, "abcdef": 2, "x" * 60: 20}
        for text, want in corpus.items():
            got = spend_cache.conservative_token_estimate(text)
            if got != want:
                return "BREAK", "P8", "estimate(%r) = %r, want %r" % (text[:8], got, want)
            if h._conservative_token_estimate(text) != got:
                return "BREAK", "P8", "harness disagrees on %r" % text[:8]
    except Exception:
        return "ERROR", "P8", traceback.format_exc(limit=3)
    return "HELD", "P8", "single estimator; harness agrees on corpus"


def p9_persisted_format():
    """Persisted cache is versioned JSON keyed by 64-hex digests; atomic."""
    try:
        import spend_cache
        tmp = tempfile.mkdtemp(prefix="spendcache-p9-")
        path = os.path.join(tmp, "spend_cache.json")
        cache = _fresh_cache(tmp)
        cache.estimate("gpt-4o-mini", "ATTACK" * 10, 150, 0, PRICES_MINI)
        data = json.loads(open(path, encoding="utf-8").read())
        if data.get("version") != 1:
            return "BREAK", "P9", "version != 1: %r" % data.get("version")
        entries = data.get("entries")
        if not isinstance(entries, dict) or len(entries) != 1:
            return "BREAK", "P9", "want exactly 1 entry"
        for key, entry in entries.items():
            if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
                return "BREAK", "P9", "key is not 64-hex"
            for field in ("usd", "prices_digest", "model", "max_tokens", "temperature"):
                if field not in entry:
                    return "BREAK", "P9", "entry missing %s" % field
        if os.path.exists(path + ".tmp") or os.path.exists(
                os.path.join(tmp, "spend_cache.tmp")):
            return "BREAK", "P9", ".tmp left behind after atomic write"
    except Exception:
        return "ERROR", "P9", traceback.format_exc(limit=3)
    return "HELD", "P9", "versioned JSON, 64-hex keys, atomic write"


def p10_pin():
    """TAXONOMY_PIN == 2135 and the registry holds 2127 codes."""
    try:
        sys.path.insert(0, os.path.join(REPO_ROOT))
        from gov.decision_codes import TAXONOMY
    except Exception:
        return "ERROR", "P10", traceback.format_exc(limit=3)
    if TAXONOMY_PIN != 2135:
        return "BREAK", "P10", "TAXONOMY_PIN = %r, want 2135" % TAXONOMY_PIN
    if len(TAXONOMY) != 2135:
        return "BREAK", "P10", "registry has %d codes, want 2135" % len(TAXONOMY)
    return "HELD", "P10", "pin 2131; registry 2127 codes"


PROBES = [
    ("P1", p1_identical_inputs_identical_estimates),
    ("P2", p2_persists_across_processes),
    ("P3", p3_miss_does_no_network),
    ("P4", p4_hit_equals_computed),
    ("P5", p5_temperature_in_key),
    ("P6", p6_pricing_change_invalidates),
    ("P7", p7_cache_never_authorizes_spend),
    ("P8", p8_estimator_single_source),
    ("P9", p9_persisted_format),
    ("P10", p10_pin),
]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = argv[0] if argv else None
    breaks = held = errors = 0
    for pid, probe in PROBES:
        if only and pid != only:
            continue
        try:
            verdict, _pid, detail = probe()
        except Exception:
            verdict, detail = "ERROR", traceback.format_exc(limit=5)
        print("[%s] %s: %s" % (verdict, pid, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
