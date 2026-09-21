"""Agent identity: every action the governance layer sees is attributed."""

from dataclasses import asdict, dataclass


class UnmintedIdentityError(Exception):
    """Raised when an identity object was not issued by the executor."""


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
