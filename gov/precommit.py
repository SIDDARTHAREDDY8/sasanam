"""Pre-commit validation for irreversible actions (wave-79).

Finance's settlement-finality lesson (learnings memo Part 1): clearinghouses
don't reverse settlement — they validate BEFORE finality. Mapped here:
tools flagged irreversible get a pre-commit gate (dry-run/diff preview +
human approval bound to the exact preview) that reversible tools skip.
No "undo" is built — the memo's direction is gate, not undo.

Design: ``workstreams/architect/RULES_TIERING_DESIGN.md`` §3.

Classification (the "no inverse" + "external effect" tests, design §3(a)):
a tool is irreversible iff the executor cannot restore the pre-call state
with any inverse operation it possesses, or the call's effects leave the
trust boundary. Operator-declared at registration below; a tool that is
unflagged but behaves irreversibly is a classification gap — the probe
must expose it, and the fix is reclassification, filed honestly.

The registry is POLICY-GRADE: frozen at import, no public mutator.
Reclassification requires the wave-75 governed policy-change path — an
``applied`` policy_change provenance record whose diff_summary binds the
exact mutation (``irreversible-registry:<sha256>``). Direct mutation is
structurally impossible (the dict is a frozen snapshot per gate); a
forged applied record is refused by the verification below.
"""

import hashlib
import json
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

# tool -> {"class": "destructive"|"external-effect", "preview": kind}.
# preview kinds: "diff" (target listing), "dry-run" (rendered summary).
# read_file/api_call are reversible reads (their exfiltration risk is the
# read-before-send/DLP lane); write_file is reversible (overwrite).
_IRREVERSIBLE = {
    "delete_file": {"class": "destructive",
                    "preview": "diff",
                    "why": "no undelete; the executor holds no inverse"},
    "send_email": {"class": "external-effect",
                   "preview": "dry-run",
                   "why": "leaves the trust boundary; no recall"},
    "http_post": {"class": "external-effect",
                  "preview": "dry-run",
                  "why": "leaves the trust boundary; no recall"},
    "install_package": {"class": "external-effect",
                        "preview": "dry-run",
                        "why": "environment mutation; no governed uninstall"},
}

_VALID_CLASSES = frozenset({"destructive", "external-effect"})
_VALID_PREVIEWS = frozenset({"diff", "dry-run"})
_REGISTRY_VERSION = "precommit-registry-v1"


class PrecommitError(ValueError):
    """Fail-closed: the pre-commit protocol was violated."""


class PrecommitRefused(PrecommitError):
    """An irreversible action was refused at the pre-commit gate."""


def is_irreversible(tool):
    """True iff the tool is in the frozen irreversible registry."""
    return tool in _IRREVERSIBLE


def registry_snapshot():
    """A read-only snapshot of the registry (tool -> classification)."""
    return {t: dict(v) for t, v in _IRREVERSIBLE.items()}


def registry_version():
    return _REGISTRY_VERSION


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def args_digest(tool, args):
    """The binding digest: sha256 over the canonical (tool, args).

    The approval binds THIS digest; commit() recomputes it over the
    actual arguments about to execute. Approved preview A / executed B
    can only differ by changing the digest — which is exactly what the
    gate compares.
    """
    return hashlib.sha256(
        _canonical({"tool": tool, "args": args or {}})).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PrecommitGate:
    """The pre-commit protocol: preview -> bound approval -> commit.

    Approvals are single-use and bound to ``(preview_id, args_digest)``.
    ``commit`` refuses on digest mismatch (approved A, executed B) and
    on replay (the ticket is consumed by the first commit).
    """

    def __init__(self):
        self._previews = {}    # preview_id -> preview descriptor
        self._approvals = {}   # approval_id -> approval ticket
        self._counter = 0

    # -- preview ---------------------------------------------------------
    def preview(self, tool, args):
        """Build a dry-run/diff preview for an irreversible tool.

        Returns the preview descriptor. Refuses (PrecommitError) for
        tools outside the registry — previews are meaningless for
        reversible tools, and a preview for an unregistered tool would
        imply a gate promise the registry does not make.
        """
        if not is_irreversible(tool):
            raise PrecommitError(
                "preview refused: %r is not in the irreversible registry "
                "(previews are only meaningful where the gate applies)"
                % (tool,))
        self._counter += 1
        preview_id = "pcp-%d" % self._counter
        descriptor = {
            "preview_id": preview_id,
            "tool": tool,
            "args_digest": args_digest(tool, args),
            "preview_kind": _IRREVERSIBLE[tool]["preview"],
            "summary": _summarize(tool, args or {}),
            "created_at": _utcnow_iso(),
            "registry_version": _REGISTRY_VERSION,
        }
        self._previews[preview_id] = descriptor
        return dict(descriptor)

    # -- approval --------------------------------------------------------
    def approve(self, preview_id, approver):
        """Bind a human approval to the exact preview. Single-use ticket.

        In production the human decides through the approvals queue on
        the rendered preview; here the binding (not the UX) is the
        security property under test.
        """
        preview = self._previews.get(preview_id)
        if preview is None:
            raise PrecommitError(
                "approve refused: unknown preview_id %r" % (preview_id,))
        if not approver:
            raise PrecommitError("approve refused: approver required")
        self._counter += 1
        approval_id = "pca-%d" % self._counter
        ticket = {
            "approval_id": approval_id,
            "preview_id": preview_id,
            "tool": preview["tool"],
            "args_digest": preview["args_digest"],
            "approver": approver,
            "approved_at": _utcnow_iso(),
            "used": False,
        }
        self._approvals[approval_id] = ticket
        return dict(ticket)

    # -- commit ----------------------------------------------------------
    def commit(self, approval_id, tool, args, execute):
        """Execute iff the bound approval matches the ACTUAL (tool, args).

        Recomputes the digest over the arguments about to execute and
        compares against the ticket's bound digest. Mismatch (approved
        preview A, executed B — including approval replay for a
        different action) -> PrecommitRefused, nothing executes. The
        ticket is consumed exactly once.
        """
        ticket = self._approvals.get(approval_id)
        if ticket is None:
            raise PrecommitRefused(
                "precommit_refused: unknown approval %r" % (approval_id,))
        if ticket["used"]:
            raise PrecommitRefused(
                "precommit_refused: approval %r already consumed "
                "(single-use; replay refused)" % (approval_id,))
        if ticket["tool"] != tool:
            raise PrecommitRefused(
                "precommit_refused: approval binds tool %r, executed %r "
                "(preview/execution mismatch)" % (ticket["tool"], tool))
        actual = args_digest(tool, args)
        if actual != ticket["args_digest"]:
            raise PrecommitRefused(
                "precommit_refused: executed args digest %s... != approved "
                "preview digest %s... (approved preview A, executed B)"
                % (actual[:12], ticket["args_digest"][:12]))
        ticket["used"] = True
        return execute()

    def check(self, approval_id, tool, args):
        """Non-executing check: returns True iff commit() would proceed.

        Used by the executor's opt-in gate to decide deny-vs-queue
        without executing.
        """
        ticket = self._approvals.get(approval_id)
        return bool(ticket) and not ticket["used"] and \
            ticket["tool"] == tool and \
            ticket["args_digest"] == args_digest(tool, args)


def _summarize(tool, args):
    """The approver-facing preview summary. Redaction-safe: shapes and
    hashes, never raw secret-shaped values."""
    if tool == "delete_file":
        return {"action": "delete", "path": str(args.get("path", ""))}
    if tool == "send_email":
        body = str(args.get("body", ""))
        return {"action": "send_email",
                "to": str(args.get("to", "")),
                "subject": str(args.get("subject", "")),
                "body_sha256_prefix": hashlib.sha256(
                    body.encode("utf-8")).hexdigest()[:16],
                "body_chars": len(body)}
    if tool == "http_post":
        payload = str(args.get("payload", args.get("data", "")))
        return {"action": "http_post",
                "endpoint": str(args.get("endpoint", args.get("url", ""))),
                "payload_sha256_prefix": hashlib.sha256(
                    payload.encode("utf-8")).hexdigest()[:16],
                "payload_chars": len(payload)}
    if tool == "install_package":
        return {"action": "install_package",
                "package": str(args.get("package", args.get("name", ""))),
                "version": str(args.get("version", ""))}
    return {"action": tool, "args_keys": sorted(args.keys())}


# ---------------------------------------------------------------------------
# Policy-grade registry mutation (the wave-75 path)
# ---------------------------------------------------------------------------

def _mutation_digest(mutation):
    return hashlib.sha256(_canonical(mutation)).hexdigest()


def validate_mutation(mutation):
    """Structural validation of a proposed registry mutation.

    ``mutation``: {"add": {tool: {class, preview, why}}, "remove": [tool]}.
    Refuses unknown tools (closed universe = the engine's KNOWN_TOOLS —
    checked by the caller via gov.policy), unknown classes/previews, and
    removals of tools not in the registry.
    """
    if not isinstance(mutation, dict):
        raise PrecommitError("mutation must be a dict")
    adds = mutation.get("add") or {}
    removes = mutation.get("remove") or []
    unknown = set(mutation) - {"add", "remove"}
    if unknown:
        raise PrecommitError("mutation carries unknown keys %r"
                             % sorted(unknown))
    if not isinstance(adds, dict) or not isinstance(removes, list):
        raise PrecommitError("mutation.add must be a dict, "
                             "mutation.remove a list")
    for tool, spec in adds.items():
        if not isinstance(spec, dict):
            raise PrecommitError("add spec for %r must be a dict" % tool)
        if spec.get("class") not in _VALID_CLASSES:
            raise PrecommitError(
                "add spec for %r: unknown class %r" % (tool, spec.get("class")))
        if spec.get("preview") not in _VALID_PREVIEWS:
            raise PrecommitError(
                "add spec for %r: unknown preview %r"
                % (tool, spec.get("preview")))
        if not spec.get("why"):
            raise PrecommitError(
                "add spec for %r: 'why' (the classification rationale) "
                "is required" % tool)
    for tool in removes:
        if tool not in _IRREVERSIBLE:
            raise PrecommitError(
                "remove refused: %r is not in the registry" % (tool,))
    return {"add": {t: dict(s) for t, s in adds.items()},
            "remove": list(removes)}


def apply_governed_change(mutation, applied_change_record):
    """Apply a registry mutation authorized by the wave-75 governed path.

    ``applied_change_record`` must be a ``policy_change`` provenance
    record with ``prov.policy.status == "applied"``, a non-empty
    human-approval list, an authorship ref, and a diff_summary binding
    the EXACT mutation (``irreversible-registry:<sha256>``). Anything
    else — direct calls without a record, forged statuses, unbound
    summaries — is refused. This is the only mutation path; there is no
    public mutator on the registry itself.
    """
    mutation = validate_mutation(mutation)
    record = applied_change_record
    try:
        prov = record["prov"]
        policy = prov["policy"]
    except (KeyError, TypeError):
        raise PrecommitRefused(
            "registry mutation refused: not a policy_change provenance "
            "record")
    if prov.get("record_type") != "policy_change":
        raise PrecommitRefused(
            "registry mutation refused: record_type %r != 'policy_change'"
            % (prov.get("record_type"),))
    if policy.get("status") != "applied":
        raise PrecommitRefused(
            "registry mutation refused: policy_change status %r != "
            "'applied' (the wave-75 path requires an applied change)"
            % (policy.get("status"),))
    approvals = prov.get("approvals") or []
    approvers = {a.get("decided_by") for a in approvals
                 if a.get("decision") == "approve"}
    approvers.discard(None)
    if not approvers:
        raise PrecommitRefused(
            "registry mutation refused: no human 'approve' decision on "
            "the change record")
    if not prov.get("authorship_ref"):
        raise PrecommitRefused(
            "registry mutation refused: change record carries no "
            "authorship_ref")
    want = "irreversible-registry:" + _mutation_digest(mutation)
    summary = str(policy.get("diff_summary") or "")
    if want not in summary:
        raise PrecommitRefused(
            "registry mutation refused: change record does not bind this "
            "exact mutation (diff_summary must contain %r...)"
            % want[:40])
    # The record authorizes THIS mutation and only this mutation.
    for tool in mutation["remove"]:
        del _IRREVERSIBLE[tool]
    for tool, spec in mutation["add"].items():
        _IRREVERSIBLE[tool] = dict(spec)
    return {"applied": mutation, "registry_version": _REGISTRY_VERSION,
            "authorized_by": sorted(approvers)}
