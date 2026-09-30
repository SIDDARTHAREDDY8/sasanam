#!/usr/bin/env python3
"""Mechanical doc-truth gate for NON-CLAIMS.md (wave-233 lane C).

Every NON-CLAIMS.md entry pins a module and an exact docstring
phrase. This gate imports each module and checks the phrase is
present in the module docstring. A module whose docstring lost its
non-claim phrase FAILS with reason ``doc-truth-missing`` -- docs
drifting from code is a broken gate, not a quiet footnote.

Runs as a depth-1 battery: it spawns no child suites, so it is
safe for another battery's green check to call ``main()`` directly.
Exit code honest: 0 when every entry holds, 1 on any failure.

Run:
  TMPDIR=/var/tmp/g233c ~/workspace/.gov-venv/bin/python evals/doc_truth.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import importlib
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

REASON = "doc-truth-missing"

# (module, exact docstring phrase). Mirrors NON-CLAIMS.md entries 1-8.
ENTRIES = [
    {"module": "gov.deny_receipts",
     "phrase": "a receipt proves the emitter's signed claim, "
               "not that the decision was correct"},
    {"module": "gov.seeded_denials",
     "phrase": "a seeded denial record proves the denial was anchored, "
               "not that the denied action was absent"},
    {"module": "gov.checkpoints",
     "phrase": "a checkpoint proves commitment and order, "
               "not content authenticity"},
    {"module": "gov.alg_registry",
     "phrase": "HMAC evidence proves shared-secret authenticity, "
               "not non-repudiation"},
    {"module": "gov.policy_revisions",
     "phrase": "the revision registry is in-memory; persistence and "
               "distribution are deployment-owned"},
    {"module": "gov.attested_identity",
     "phrase": "attested identity has no live TPM round trip"},
    {"module": "gov.absence",
     "phrase": "signed negative outcomes classify absence, "
               "not that a search occurred"},
    {"module": "gov.approval_render",
     "phrase": "render attestations prove bytes and determinism, "
               "not that a human understood the display"},
]


def entry_for(module_name):
    """Return the NON-CLAIMS.md entry for ``module_name`` (KeyError if
    the module has no entry)."""
    for entry in ENTRIES:
        if entry["module"] == module_name:
            return entry
    raise KeyError(module_name)


def check_entry(entry, module=None):
    """Check one entry against an imported module.

    ``module`` may be supplied directly (the doc-truth probe uses
    this to check a scratch copy without touching the real module).
    Returns {"ok": bool, "module": ..., "reason": ...} where reason
    is ``doc-truth-missing`` on failure.
    """
    if module is None:
        module = importlib.import_module(entry["module"])
    doc = getattr(module, "__doc__", "") or ""
    if entry["phrase"] in doc:
        return {"ok": True, "module": entry["module"]}
    return {"ok": False, "module": entry["module"],
            "reason": REASON}


def run_all():
    results = []
    for entry in ENTRIES:
        try:
            results.append(check_entry(entry))
        except Exception as exc:  # noqa: BLE001 - a broken import is a fail
            results.append({"ok": False, "module": entry["module"],
                            "reason": REASON, "detail": str(exc)})
    return results


def main():
    t0 = time.time()
    results = run_all()
    failed = [r for r in results if not r["ok"]]
    for r in results:
        status = "HELD" if r["ok"] else "FAIL (%s)" % r.get("reason")
        print("%-32s %s" % (r["module"], status))
    print("summary: %d/%d HELD (%.1fs)"
          % (len(results) - len(failed), len(results), time.time() - t0))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
