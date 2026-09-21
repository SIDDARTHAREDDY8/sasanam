"""CLI entry point: python -m gov.approve ... (see gov/approvals.py)."""

from .approvals import main

if __name__ == "__main__":
    raise SystemExit(main())
