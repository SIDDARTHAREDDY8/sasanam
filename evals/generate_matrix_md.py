"""Render SITUATION_MATRIX.md from evals/matrix.py (single source of truth).

Run:  python3 evals/generate_matrix_md.py   (from the repo root)
Writes: SITUATION_MATRIX.md

The document and the harness can never drift: expectations live in
matrix.py, verdicts are asserted by run_evals.py, and this file only
formats them for humans.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from evals.matrix import SITUATIONS, PRIVILEGES, PRIV_ROLE, ADAPTERS  # noqa: E402


def _cell(exp):
    verdict, why = exp
    short = why if len(why) <= 110 else why[:107] + "..."
    return "**%s** — %s" % (verdict, short)


def main():
    n_cells = len(SITUATIONS) * len(ADAPTERS) * len(PRIVILEGES)
    L = []
    L.append("# SITUATION_MATRIX — adversary eval expectations")
    L.append("")
    L.append("**Team: ADVERSARY (permanent red team). Generated from "
             "`evals/matrix.py` — do not edit by hand.**")
    L.append("")
    L.append("Regenerate: `python3 evals/generate_matrix_md.py`. "
             "Verify: `python3 evals/run_evals.py` (the ship-gate).")
    L.append("")
    L.append("## Axes")
    L.append("")
    L.append("- **Situations:** %d (%s)" % (len(SITUATIONS),
                                            ", ".join(sorted(SITUATIONS))))
    L.append("- **Adapters (provisional shims):** %s" % ", ".join(ADAPTERS))
    L.append("- **Privilege levels:** %s" % ", ".join(
        "%s (role `%s`)" % (p, PRIV_ROLE[p]) for p in PRIVILEGES))
    L.append("- **Cells:** %d (every situation x adapter x privilege)"
             % n_cells)
    L.append("")
    L.append("## Verdicts")
    L.append("")
    L.append("- `blocked` — the action is denied; nothing happens.")
    L.append("- `queued` — the action is held for human approval; nothing "
             "executes without the human.")
    L.append("- `allowed-with-audit` — the action executes and is written "
             "to the tamper-evident log.")
    L.append("- `blocked-or-queued` — the attack has sub-steps; every one "
             "ends blocked or queued. Nothing executes silently.")
    L.append("")
    L.append("Every verdict below is asserted by executing real code in "
             "`evals/run_evals.py`. A cell whose observed outcome differs "
             "from the expectation fails the ship-gate loudly.")
    L.append("")
    for sit_id in sorted(SITUATIONS):
        s = SITUATIONS[sit_id]
        L.append("---")
        L.append("")
        L.append("## %s — %s" % (sit_id, s["title"]))
        L.append("")
        L.append("**Threat-model IDs:** %s" % ", ".join(s["threats"]))
        L.append("")
        L.append("**Research grounding:**")
        L.append("")
        for src in s["sources"]:
            L.append("- %s" % src)
        L.append("")
        L.append("**Situation:** %s" % s["summary"])
        L.append("")
        if s.get("note"):
            L.append("**Matrix note:** %s" % s["note"])
            L.append("")
        L.append("| privilege | %s |" % " | ".join(ADAPTERS))
        L.append("|---|%s|" % "|".join(["---"] * len(ADAPTERS)))
        for priv in PRIVILEGES:
            row = [s["expected"][(ad, priv)] for ad in ADAPTERS]
            # Collapse the row when all four adapters agree.
            if all(r == row[0] for r in row):
                cell = _cell(row[0]) + " *(all adapters)*"
                cells = [cell] * len(ADAPTERS)
            else:
                cells = [_cell(r) for r in row]
            L.append("| %s (`%s`) | %s |" % (priv, PRIV_ROLE[priv],
                                             " | ".join(cells)))
        L.append("")
    L.append("---")
    L.append("")
    L.append("## Interface provenance")
    L.append("")
    L.append("Adapter shims are provisional (`evals/ADAPTER_INTERFACE.md`): "
             "`gov/adapters/README.md` has not appeared yet. The real "
             "mediation API (`gov.adapters.GovernedBinding`) is tracked for "
             "reconciliation; until the coordinator signs off, the ship-gate "
             "tests the provisional contract.")
    L.append("")
    out = REPO_ROOT / "SITUATION_MATRIX.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("wrote %s (%d situations, %d cells)" % (out, len(SITUATIONS),
                                                  n_cells))


if __name__ == "__main__":
    main()
