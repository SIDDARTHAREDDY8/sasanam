"""gov: an agent-governance layer (synthetic demo, stdlib only)."""

# Single source of truth for the package version (packaging, defect 6).
# pyproject.toml reads this via [tool.setuptools.dynamic]; CHANGELOG.md
# records what changed per version. No other file may hard-code it.
__version__ = "0.2.0"

from .identity import AgentIdentity, UnmintedIdentityError
from .log import (ActionLog, LogUnverifiableError, read_entries,
                   require_verified, verify_chain)
from .exchange_ledger import (ExchangeAccessDenied, bind_reader,
                              check_exchange_read)
from .policy import PolicyDecision, PolicyEngine
from .approvals import ApprovalQueue, record_digest
from .executor import ToolExecutor
from . import capability_gate
from . import dlp

__all__ = [
    "AgentIdentity",
    "UnmintedIdentityError",
    "ActionLog",
    "LogUnverifiableError",
    "read_entries",
    "require_verified",
    "verify_chain",
    "ExchangeAccessDenied",
    "bind_reader",
    "check_exchange_read",
    "PolicyDecision",
    "PolicyEngine",
    "ApprovalQueue",
    "record_digest",
    "ToolExecutor",
    "capability_gate",
    "dlp",
]
