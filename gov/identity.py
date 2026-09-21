"""Agent identity: every action the governance layer sees is attributed.

F17b: principal rotation. An attacker who can mint identities for
arbitrary principal strings can trivially shed ledger taint by rotating
to a fresh principal ("org2"). No in-band check on the string itself can
fix that — the fix is deployment-controlled issuance: a
``PrincipalRegistry`` of pre-registered principals, consulted by
``ToolExecutor.mint_identity``. In registry mode an unregistered
principal raises ``UnregisteredPrincipalError`` and every issuance is
audit-logged (``identity_minted``). With no registry configured the
executor stays permissive (any string mints): that is an explicit
deployment-trust residual — the demo's default — not a control.
"""

from dataclasses import asdict, dataclass


class UnmintedIdentityError(Exception):
    """Raised when an identity object was not issued by the executor."""


class UnregisteredPrincipalError(Exception):
    """Raised when minting for a principal the registry does not know."""


class IdentityMintLimitError(Exception):
    """Raised when a run exhausts its identity issuance budget."""


class PrincipalRegistry:
    """Deployment-controlled principal allowlist (F17b).

    ``principals`` is the set of principal strings this deployment
    recognizes (tenants, teams, service accounts). Registration is an
    out-of-band admin act — the registry is constructed from deployment
    configuration, never from agent input. ``check`` is called by
    ``ToolExecutor.mint_identity`` before any identity is issued.
    """

    def __init__(self, principals):
        if not principals:
            raise ValueError("PrincipalRegistry needs at least one "
                             "registered principal")
        self._principals = frozenset(principals)

    def check(self, principal):
        """Raise ``UnregisteredPrincipalError`` for unknown principals."""
        if principal not in self._principals:
            raise UnregisteredPrincipalError(
                "principal %r is not registered with this deployment; "
                "fresh-principal rotation is not issuance" % (principal,))
        return True

    def registered(self):
        """The registered principal set (for audit/debugging)."""
        return set(self._principals)


@dataclass(frozen=True)
class AgentIdentity:
    """Who acted.

    agent_id:  stable id of the agent instance, e.g. "scout-01"
    role:      the agent's job in the run, e.g. "scout"
    run_id:    the workflow run this agent belongs to
    principal: the human (or org) on whose behalf the agent acts
    """

    agent_id: str
    role: str
    run_id: str
    principal: str

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class AgentIdentity:
    """Who acted.

    agent_id:  stable id of the agent instance, e.g. "scout-01"
    role:      the agent's job in the run, e.g. "scout"
    run_id:    the workflow run this agent belongs to
    principal: the human (or org) on whose behalf the agent acts
    """

    agent_id: str
    role: str
    run_id: str
    principal: str

    def as_dict(self):
        return asdict(self)
