"""D1 bridge adapters: the durable approval queue, pluggable into
foreign agent runtimes (A12).

The queue (gov/approvals.py) is the durable, human-decided core; the
modules here are THIN adapters that let a foreign runtime ask our queue
for a decision and wait for it:

* gov/bridges/core.py — BridgeAdapter ABC + shared fail-safe helpers.
* gov/bridges/agt.py  — in-process shim for AGT-Python's ApprovalHandler.

Sequenced later (NOT in this wave): gov/bridges/aws.py (the corrected
A12 direction — we are an approval-event PRODUCER into the trajectory,
never a consumer of AWS approval webhooks, which do not exist) and
gov/bridges/agt_webhook.py (AGT .NET WebhookApprover HTTPS ingress —
not started until the JSON schema is pinned from their .NET source).

TERMINOLOGY GUARD (A12, binding): "approval delegation" is the D1-core
primitive (a HUMAN reassigning decision stewardship of a queued
record). "Authority delegation" is the P10 primitive (an AGENT granting
tool-call authority to another agent). Bridges do neither — they
REQUEST a human decision and WAIT for it. Nothing in this package may
use "delegation" for bridge behavior.

Deployment contract (D5): until real auth + TLS + KMS-backed keys are
in place, in-process shim only — no network ingress.
"""

from .core import BridgeAdapter, BridgeHandle, compute_request_digest

__all__ = ["BridgeAdapter", "BridgeHandle", "compute_request_digest"]
