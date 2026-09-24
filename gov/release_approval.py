"""Pre-release approval / licensing primitive.

Turns "ship this release" into a quorum-gated human ceremony on the
EXISTING approval queue machinery (``gov.approvals.ApprovalQueue``),
with digest binding from the release candidate's bits through the
evaluation evidence to the human decision, and a fail-closed verify
path for anyone who must answer "was this release actually approved?".

The ceremony
------------
1. ``propose_release`` computes the release digest (code tree + eval
   results + safeguard assessment report + release_id, F153) and queues
   a ``ship_release``
   approval through the existing queue with a quorum config of at
   least 2-of-N installed. The quorum snapshot is MAC-bound to the
   record at queue time by the queue itself.
2. Humans vote through the EXISTING vote path (``cast_vote`` /
   the ``gov.approve`` CLI); the requester can never vote on its own
   release and one deny vetoes (the queue's own invariants, reused).
3. When the M-th approval vote finalizes the record,
   ``record_release_vote`` chains an explicit ``release_approval_granted``
   event into the hash-chained audit log with the release digest bound
   in — the same log family as every other governance event.
4. ``verify_release`` recomputes the digest from a candidate and checks
   the chained approval, failing closed on ANY mismatch. ``ship_release``
   refuses to copy the bundle out unless ``verify_release`` passes.

HONEST RESIDUAL (read before relying on this): this governs OUR
release process — ceremony plus evidence before ship. It is NOT a DRM
that stops someone copying the code and shipping it without the
ceremony. A second honest residual: under the public development log
key, the keyed approval-record MAC is forgeable by anyone who read the
docs (the same F34 residual the rest of the approval system carries);
production deployments need a real log key (see the key-custody
runbook). The threat model here is the confused, careless, or
single-compromised insider inside the deployment's trust boundary —
not a key-holder forging records.

Spec: docs/release-approval-spec.md
Break battery: evals/release_approval_break_battery.py
"""

import os
import re
import shutil
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .approvals import approval_digest_ok
from .log import read_entries, verify_chain
from .policy import PolicyDecision

# The release approval rides the existing queue as a pseudo-tool action.
RELEASE_TOOL = "ship_release"
RELEASE_POLICY_ID = "release-approval"
RELEASE_POLICY_FLAG = "release_approval"

# A release_id names the shipped directory (<dest_dir>/<release_id>), so
# it is a single path segment by construction: no separators, no parent
# references, no leading dot, bounded length. Anything else is refused
# at the ship seam (fail closed, loudly) — see validate_release_id.
_RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# The primitive refuses to install a quorum weaker than this. One-party
# approval must never suffice for a release.
MIN_QUORUM_APPROVALS = 2

# Release approvals go stale like every other approval (mirrors the
# executor's approvals.ttl_hours default).
DEFAULT_APPROVAL_TTL_HOURS = 24

# Domain separation for the digest combiner.
_DIGEST_DOMAIN = b"agent-governance/release/v1\x00"


class ReleaseNotApproved(Exception):
    """Raised by ship_release when the release does not verify."""


# ---------------------------------------------------------------------------
# digests
# ---------------------------------------------------------------------------

def sha256_file(path):
    """SHA-256 hex digest of a file's bytes, streamed."""
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(root):
    """Canonical digest of a code tree.

    Every regular file under ``root`` is hashed (relative POSIX path
    + file bytes); the per-file digests are combined in sorted path
    order under a domain prefix. Any bit flip — content change,
    rename, add, or remove — changes the digest. Symlinks are not
    followed (a symlink's target is outside the bundle's control).
    """
    root = Path(root)
    if not root.is_dir():
        raise ValueError("code_dir %r is not a directory" % (root,))
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            rel = full.relative_to(root).as_posix()
            file_h = sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    file_h.update(chunk)
            entries.append((rel, file_h.hexdigest()))
    h = sha256(_DIGEST_DOMAIN + b"tree/v1\x00")
    for rel, file_hex in entries:
        rel_b = rel.encode("utf-8")
        h.update(len(rel_b).to_bytes(4, "big"))
        h.update(rel_b)
        h.update(bytes.fromhex(file_hex))
    h.update(len(entries).to_bytes(4, "big"))
    return h.hexdigest()


def release_digest(tree_hex, eval_hex, sar_hex, *, release_id):
    """Combine the three sub-digests plus the release_id into one digest.

    Domain-separated SHA-256 over (tree, eval-results, SAR,
    release_id) — the ``release/v2`` combiner. The release_id is bound
    with an explicit length prefix so (\"ab\", \"c\") and (\"a\", \"bc\")
    can never collide. Any bit flip in any of the four inputs changes
    the digest, so a quorum approval for release_id X can never be
    transplanted onto release_id Y, and the id the humans approved is
    part of what ``verify_release`` recomputes. (F153: the v1 combiner
    bound only the three bit-inputs, leaving the id — and therefore the
    ship destination — outside the digest.)
    """
    for label, value in (("tree", tree_hex), ("eval", eval_hex),
                         ("sar", sar_hex)):
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(
                "release_digest: %s digest must be 64-char hex" % label)
    if not isinstance(release_id, str):
        raise ValueError(
            "release_digest: release_id must be a string, got %s"
            % type(release_id).__name__)
    rid_b = release_id.encode("utf-8")
    h = sha256(_DIGEST_DOMAIN)
    h.update(b"release/v2\x00")
    for value in (tree_hex, eval_hex, sar_hex):
        h.update(bytes.fromhex(value))
    h.update(len(rid_b).to_bytes(4, "big"))
    h.update(rid_b)
    return h.hexdigest()


def validate_release_id(release_id):
    """Check a release_id against the safe single-segment charset.

    Returns the id unchanged when it is a non-empty string of
    ``[A-Za-z0-9._-]`` (not starting with a dot, no ``..`` anywhere,
    max 128 chars); raises :class:`ValueError` loudly otherwise. A
    release_id becomes a directory name under the ship destination, so
    path separators, parent references, and empty ids are never valid.
    """
    if not isinstance(release_id, str):
        raise ValueError(
            "release_id must be a string, got %s" % type(release_id).__name__)
    if not _RELEASE_ID_RE.match(release_id) or ".." in release_id:
        raise ValueError(
            "release_id %r is not a safe single path segment "
            "(allowed: 1-128 chars of [A-Za-z0-9._-], no leading dot, "
            "no '..', no separators)" % (release_id,))
    return release_id


def compute_candidate(code_dir, eval_results_path, sar_path, *,
                      release_id):
    """Digest a release candidate; returns the five digests.

    ``code_dir`` is the release's code tree; ``eval_results_path`` is
    the eval-results file (e.g. the stratified battery results); and
    ``sar_path`` is the safeguard assessment report. All three are
    required — a release with no eval evidence or no SAR cannot be
    proposed. ``release_id`` is required and is bound into the release
    digest (F153), so the approval covers the exact id being shipped.
    """
    for label, path in (("eval_results", eval_results_path),
                        ("sar", sar_path)):
        if not Path(path).is_file():
            raise ValueError(
                "compute_candidate: %s %r is not a file — a release "
                "candidate needs eval evidence and a SAR" % (label, path))
    tree_hex = tree_digest(code_dir)
    eval_hex = sha256_file(eval_results_path)
    sar_hex = sha256_file(sar_path)
    return {
        "tree_digest": tree_hex,
        "eval_results_digest": eval_hex,
        "sar_digest": sar_hex,
        "release_id": release_id,
        "release_digest": release_digest(tree_hex, eval_hex, sar_hex,
                                         release_id=release_id),
    }


def _candidate_or_none(code_dir, eval_results_path, sar_path, *,
                       release_id):
    try:
        return compute_candidate(code_dir, eval_results_path, sar_path,
                                 release_id=release_id)
    except (ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# proposing + voting (through the EXISTING approval queue)
# ---------------------------------------------------------------------------

def propose_release(queue, executor, *, code_dir, eval_results_path,
                    sar_path, release_id,
                    requester_agent_id="release-manager",
                    requester_role="release",
                    requester_principal="release-manager",
                    eligible_principals=("release-approver-a",
                                        "release-approver-b",
                                        "release-approver-c"),
                    min_approvals=MIN_QUORUM_APPROVALS):
    """Queue a release approval through the existing approval queue.

    Installs a quorum config (``min_approvals`` of ``eligible_principals``,
    scoped to the ``release_approval`` queue flag so other records on a
    shared queue are untouched) and queues a ``ship_release`` approval
    carrying the release digest in the MAC-bound args. Returns the
    approval id. Single-party approval is structurally impossible: the
    quorum config below ``MIN_QUORUM_APPROVALS`` is refused at install,
    and the queue's own machinery refuses ``decide()`` on
    quorum-collecting records — only per-principal votes finalize.
    """
    if not isinstance(min_approvals, int) or isinstance(min_approvals, bool) \
            or min_approvals < MIN_QUORUM_APPROVALS:
        raise ValueError(
            "propose_release: min_approvals must be an int >= %d "
            "(single-party release approval is refused)"
            % MIN_QUORUM_APPROVALS)
    eligible = [str(p).strip() for p in (eligible_principals or [])]
    if len(eligible) < min_approvals or any(not p for p in eligible) \
            or len(set(eligible)) != len(eligible):
        raise ValueError(
            "propose_release: eligible_principals must hold at least "
            "min_approvals distinct non-empty principals")
    if requester_principal in eligible or requester_agent_id in eligible:
        raise ValueError(
            "propose_release: the requester can never be in the eligible "
            "set (separation of duties)")
    candidate = compute_candidate(code_dir, eval_results_path, sar_path,
                                  release_id=release_id)
    queue.set_quorum_config({
        "min_approvals": min_approvals,
        "eligible_principals": eligible,
        "deny_veto": True,
        # Scoped: only release_approval records open a quorum; the rest
        # of the queue keeps whatever posture the deployment installed.
        "flags": [RELEASE_POLICY_FLAG],
    })
    requester = executor.mint_identity(requester_agent_id, requester_role,
                                        requester_principal)
    digest = candidate["release_digest"]
    preview = ("RELEASE APPROVAL requested for release %r\n"
               "release_digest: %s\n"
               "Review the eval results and the SAR before voting; the "
               "digest binds the exact bits this approval covers."
               % (release_id, digest))
    approval_id = queue.queue(
        action={
            "tool": RELEASE_TOOL,
            "args": {
                "release_id": release_id,
                "release_digest": digest,
                "tree_digest": candidate["tree_digest"],
                "eval_results_digest": candidate["eval_results_digest"],
                "sar_digest": candidate["sar_digest"],
            },
            "agent_justification": (
                "Release manager requests ship approval for release %r "
                "with release digest %s. This approval covers exactly the "
                "code tree, eval results, and SAR hashed into that digest."
                % (release_id, digest)),
        },
        decision=PolicyDecision(
            "require_approval",
            "pre-release approval: release %r (digest %s) requires "
            "%d-of-%d human votes before it may ship"
            % (release_id, digest[:16], min_approvals, len(eligible)),
            policy_id=RELEASE_POLICY_ID,
            flag=RELEASE_POLICY_FLAG),
        provenance="release_ceremony",
        preview=preview,
        policy_flag=RELEASE_POLICY_FLAG,
        caller_identity=requester,
    )
    return approval_id


def record_release_vote(queue, approval_id, voter_identity, approve, reason):
    """Cast one authenticated human vote on a release approval.

    Thin wrapper over the queue's existing ``cast_vote``. When this
    vote finalizes the record as APPROVED, an explicit
    ``release_approval_granted`` event is chained into the hash-chained
    audit log with the release digest bound in. Returns
    ``(record, finalized_approved)``. A deny vote finalizes rejection
    immediately (the queue's one-deny veto); votes on finalized records
    raise (the queue's own guard), so the chained event is appended
    exactly once.
    """
    record, _entry = queue.cast_vote(approval_id, approve, reason,
                                     voter_identity)
    finalized_approved = (record.get("status") == "approved"
                          and record.get("decision_mode") == "quorum")
    if finalized_approved:
        args = record.get("args") or {}
        voters = sorted({v.get("voter_principal")
                         for v in (record.get("votes") or [])
                         if v.get("approve")})
        queue.log.append({
            "event": "release_approval_granted",
            "run_id": queue.run_id,
            "agent_id": "release-ceremony",
            "role": "release-ceremony",
            "principal": voter_identity.principal,
            "decision": "release_approved",
            "policy_id": RELEASE_POLICY_ID,
            "approval_id": approval_id,
            "release_id": args.get("release_id"),
            "release_digest": args.get("release_digest"),
            "tree_digest": args.get("tree_digest"),
            "eval_results_digest": args.get("eval_results_digest"),
            "sar_digest": args.get("sar_digest"),
            "voters": voters,
            "reason": ("release approval finalized by quorum vote; the "
                       "release digest bound here is the exact digest "
                       "the voters approved"),
        })
    return record, finalized_approved


# ---------------------------------------------------------------------------
# verification (fail-closed)
# ---------------------------------------------------------------------------

def _parse_ts(ts):
    try:
        dt = datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_release(*, queue, approval_id, code_dir, eval_results_path,
                   sar_path, max_age_hours=DEFAULT_APPROVAL_TTL_HOURS,
                   release_id=None):
    """Verify a release candidate against its chained approval.

    Recomputes the release digest from the candidate, re-reads the
    approval record FRESH from the queue's authoritative store (caller
    supplied records are never trusted), and checks, in order:

    1. the record exists and its keyed integrity digest verifies
       (forged or tampered records fail here);
    2. when the caller supplies ``release_id`` (the id the caller
       EXPECTS to ship), it equals the record's MAC-bound release_id
       (an approval for id X can never verify a candidate presented
       as id Y);
    3. the recomputed release digest — which binds the record's
       release_id alongside tree/eval/SAR (F153) — equals the digest
       bound in the record's MACed args (replay / transplant across
       digests or ids fails);
    4. the record is finalized ``approved`` under ``decision_mode ==
       "quorum"`` (single-approver / direct-decide attempts fail);
    5. the MAC-bound quorum snapshot requires at least
       ``MIN_QUORUM_APPROVALS`` and at least that many DISTINCT
       approval votes from eligible principals are present (no deny
       votes);
    6. a matching ``release_approval_granted`` event is chained in the
       audit log binding the same approval id and release digest — or,
       when humans voted through the queue's own surfaces (e.g. the
       ``gov.approve`` CLI), the queue's native ``quorum_finalized``
       entry for the approval id (the digest binding then rides the
       MAC-verified record's args);
    7. the audit-log chain fully verifies;
    8. the approval is within ``max_age_hours`` of its decision.

    Returns ``(True, reason)`` when every check passes, else
    ``(False, reason)``. Fails closed: any mismatch, missing entry, or
    unverifiable chain is a refusal, never a warning.
    """
    record = queue.get(approval_id)
    if record is None:
        return False, "no such release approval %r" % (approval_id,)
    if not approval_digest_ok(record):
        return False, ("approval integrity check failed for %r: the record "
                        "was forged or tampered with after queueing" %
                        (approval_id,))
    args = record.get("args") or {}
    record_id = args.get("release_id")
    if release_id is not None and str(release_id) != str(record_id):
        return False, ("release_id mismatch: the caller expects %r but the "
                        "approval binds %r — approvals never transfer "
                        "across release ids"
                        % (release_id, record_id))
    try:
        record_id = validate_release_id(record_id)
    except ValueError as e:
        return False, ("release approval %r binds an unsafe release_id: "
                        "%s; refusing" % (approval_id, e))
    candidate = _candidate_or_none(code_dir, eval_results_path, sar_path,
                                   release_id=record_id)
    if candidate is None:
        return False, ("release candidate is incomplete or unreadable "
                        "(code_dir, eval_results, and SAR are all required); "
                        "refusing")
    want = candidate["release_digest"]
    bound = args.get("release_digest")
    if bound != want:
        return False, ("release digest mismatch: the approval binds %s but "
                        "the candidate recomputes to %s — replayed or "
                        "transplanted approvals are refused"
                        % (bound, want))
    if record.get("status") != "approved":
        return False, ("release approval %r is not finalized (status=%r); "
                        "a release ships only on a finalized approval" %
                        (approval_id, record.get("status")))
    if record.get("decision_mode") != "quorum":
        return False, ("release approval %r is not quorum-gated "
                        "(decision_mode=%r); single-party approvals never "
                        "authorize a release" %
                        (approval_id, record.get("decision_mode")))
    snapshot = record.get("quorum") or {}
    min_a = snapshot.get("min_approvals")
    if not isinstance(min_a, int) or min_a < MIN_QUORUM_APPROVALS:
        return False, ("release approval %r carries a quorum weaker than "
                        "%d-of-N; refused" %
                        (approval_id, MIN_QUORUM_APPROVALS))
    votes = [v for v in (record.get("votes") or [])
             if isinstance(v, dict) and v.get("approve")]
    if any(isinstance(v, dict) and not v.get("approve")
           for v in (record.get("votes") or [])):
        return False, ("release approval %r carries a deny vote; the "
                        "one-deny veto stands" % (approval_id,))
    voters = {v.get("voter_principal") for v in votes}
    voters.discard(None)
    if len(voters) < min_a:
        return False, ("release approval %r has %d distinct approval votes; "
                        "the quorum requires %d" %
                        (approval_id, len(voters), min_a))
    granted = None
    native_finalized = False
    for entry in read_entries(queue.log.path):
        if not isinstance(entry, dict):
            continue
        if (entry.get("event") == "release_approval_granted"
                and entry.get("approval_id") == approval_id
                and entry.get("release_digest") == want):
            granted = entry
            break
        # Fallback: humans may vote through the queue's own surfaces
        # (e.g. the gov.approve CLI) instead of record_release_vote —
        # the queue still chains its native quorum_finalized entry for
        # the approval id. The digest binding then rides the
        # MAC-verified record's args (checked above), which the forged
        # or tampered record cannot carry.
        if (entry.get("event") == "quorum_finalized"
                and entry.get("approval_id") == approval_id
                and entry.get("decision") == "approved"
                and entry.get("tool") == RELEASE_TOOL):
            native_finalized = True
    if granted is None and not native_finalized:
        return False, ("no chained release approval for approval %r: "
                        "neither a release_approval_granted entry binding "
                        "digest %s nor the queue's native quorum_finalized "
                        "entry was found" % (approval_id, want))
    granted_seq = granted.get("seq") if granted else "n/a (queue-native)"
    ok, broken_seq, _count = verify_chain(queue.log.path)
    if not ok:
        return False, ("audit-log chain failed verification at seq %r; the "
                        "release approval cannot be trusted" % (broken_seq,))
    decided_at = _parse_ts(record.get("decided_at"))
    if decided_at is None:
        return False, ("release approval %r has no parseable decided_at; "
                        "refusing" % (approval_id,))
    age_hours = ((datetime.now(timezone.utc) - decided_at)
                 .total_seconds() / 3600.0)
    if age_hours > max_age_hours:
        return False, ("release approval %r is %.1f hours old (limit %.1f); "
                        "stale approvals do not authorize a ship" %
                        (approval_id, age_hours, max_age_hours))
    return True, ("release %r approved: digest %s verified against a %d-of-%d "
                  "quorum (%s), chained audit entry seq %s, log chain intact" %
                  (args.get("release_id"), want, len(voters), min_a,
                   ", ".join(sorted(voters)), granted_seq))


def ship_release(*, queue, approval_id, code_dir, eval_results_path,
                 sar_path, dest_dir,
                 max_age_hours=DEFAULT_APPROVAL_TTL_HOURS):
    """Ship a release candidate after fail-closed verification.

    Runs ``verify_release`` first; raises :class:`ReleaseNotApproved`
    on ANY mismatch. On success, copies the candidate into
    ``<dest_dir>/<release_id>/`` (code tree + eval results + SAR) and
    returns the release directory path.

    F153 containment: the release_id comes from the record's MAC-bound
    args (never from the caller), must pass ``validate_release_id``
    (single safe path segment), and the resolved destination must be a
    strict descendant of the resolved ``dest_dir`` — a hostile id like
    ``../escape`` is refused loudly instead of writing outside the
    destination, even though its digest verified.
    """
    ok, reason = verify_release(
        queue=queue, approval_id=approval_id, code_dir=code_dir,
        eval_results_path=eval_results_path, sar_path=sar_path,
        max_age_hours=max_age_hours)
    if not ok:
        raise ReleaseNotApproved(
            "ship refused for approval %r: %s" % (approval_id, reason))
    record = queue.get(approval_id)
    raw_id = (record.get("args") or {}).get("release_id")
    try:
        safe_id = validate_release_id(raw_id)
    except ValueError as e:
        raise ReleaseNotApproved(
            "ship refused for approval %r: unsafe release_id: %s"
            % (approval_id, e))
    anchor = Path(dest_dir).resolve()
    dest = (anchor / safe_id).resolve()
    if dest == anchor or anchor not in dest.parents:
        raise ReleaseNotApproved(
            "ship refused for approval %r: resolved destination %s is not "
            "inside dest_dir %s (release_id %r escapes containment)"
            % (approval_id, dest, anchor, raw_id))
    if dest.exists():
        raise ReleaseNotApproved(
            "ship refused: destination %s already exists (refusing to "
            "overwrite a shipped release)" % (dest,))
    dest.mkdir(parents=True)
    # Copy ONLY regular files, mirroring tree_digest's traversal:
    # symlinks are not followed and not shipped (the digest binds
    # exactly the bytes verified — a symlink's target could change
    # after the digest was computed, so it never rides along).
    for dirpath, dirnames, filenames in os.walk(code_dir,
                                                followlinks=False):
        dirnames.sort()
        rel_dir = Path(dirpath).relative_to(code_dir)
        (dest / "code" / rel_dir).mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            shutil.copy2(full, dest / "code" / rel_dir / name)
    shutil.copy2(eval_results_path, dest / Path(eval_results_path).name)
    shutil.copy2(sar_path, dest / Path(sar_path).name)
    return dest
