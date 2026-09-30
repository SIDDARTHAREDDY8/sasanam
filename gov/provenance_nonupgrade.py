"""AER-1 provenance non-upgrade (W239-7).

Adapts the AER-1 -04 execution-receipt rule (prose re-derived, IETF
Trust text): "Verification MUST NOT upgrade a report into an
observation."

Provenance classes (closed vocabulary):
  LOGGED    -- a report that a log entry exists. It claims "something
               was recorded", nothing more. Rank 0.
  EXECUTED  -- an observation that something actually happened. Rank 1.

The attack class this kills: a verifier or presentation layer that
promotes a LOGGED report to EXECUTED weight on the grounds that "the
chain checked out". Hash-chain validity proves the bytes were not
altered in transit; it does NOT prove the action executed. A receipt
that entered the world as a report must stay a report at every seam.

Rules, enforced fail-closed:
  1. Emission names exactly one provenance class. Zero, empty, or an
     unknown class refuses (provenance-class-missing /
     provenance-class-unknown). Class matching is case-exact: "executed"
     is not "EXECUTED".
  2. The presentation seam renders the provenance class with EVERY
     field. Presenting a receipt at an authority weight above its own
     class refuses provenance-upgraded -- it never silently passes.
  3. Verification returns the class it verified, never a higher one.
     A tampered receipt refuses provenance-digest-mismatch.
  4. Chain validity never promotes provenance: a chained LOGGED entry
     verifies as a chained-report, not an observation. A chain entry
     whose asserted class differs from the emitted class refuses
     provenance-chain-class-mismatch.
  5. Workflow Merkle: deleting or reordering steps refuses
     provenance-step-break and names the offending index; survivors
     keep their own class.

Honest residuals:
  - This module grades provenance, it does not authenticate EXECUTED:
    an EXECUTED-class receipt still asserts the issuer's claim. The
    non-upgrade rule stops DEMOTION-FORGERY UPWARD (report posing as
    observation); it does not stop an issuer from lying about the
    class at emission. That is the attestation layer's job.
  - The Merkle break pinpoints the first index where recomputation
    diverges from the committed path; for non-append-only sequences
    the index names the comparison point, not necessarily intent.
  - The emit-time class is caller-supplied. The presentation seam can
    stop re-grades; it cannot stop the caller from emitting EXECUTED
    without evidence. Deployment pairs this with issuer policy.

Stdlib only. Deterministic.
"""

import hashlib
import json

LOGGED = "LOGGED"
EXECUTED = "EXECUTED"
CLASSES = (LOGGED, EXECUTED)
_CLASS_RANK = {LOGGED: 0, EXECUTED: 1}


class ProvenanceError(Exception):
    """Named refusal carrying a decision-code string in .code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


def _canonical(obj):
    """Stable canonical bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def emit_receipt(provenance, fields):
    """Emit a receipt naming exactly one provenance class.

    Returns {"provenance", "fields", "receipt_digest"}; the digest
    covers the canonical (provenance, fields) pair so any later edit
    is detectable. Refuses provenance-class-missing /
    provenance-class-unknown fail-closed.
    """
    if not provenance:
        raise ProvenanceError(
            "provenance-class-missing",
            "emission must name exactly one provenance class")
    if provenance not in _CLASS_RANK:
        raise ProvenanceError(
            "provenance-class-unknown",
            "unknown provenance class %r (case-exact)" % (provenance,))
    if not isinstance(fields, dict):
        raise ProvenanceError("provenance-class-missing",
                              "fields must be a dict")
    canonical_fields = json.loads(_canonical(fields))
    body = {"provenance": provenance, "fields": canonical_fields}
    return {
        "provenance": provenance,
        "fields": canonical_fields,
        "receipt_digest": _sha256_hex(_canonical(body)),
    }


def verify_receipt(receipt):
    """Verify a receipt's digest.

    Returns {"verdict", "provenance"} where the provenance is exactly
    the receipt's own class, never a higher one. A verified LOGGED
    receipt reports verdict "verified-report"; EXECUTED reports
    "verified-observation". Tampered bytes refuse
    provenance-digest-mismatch.
    """
    try:
        provenance = receipt["provenance"]
        fields = receipt["fields"]
        digest = receipt["receipt_digest"]
    except (TypeError, KeyError) as exc:
        raise ProvenanceError("provenance-digest-mismatch",
                              "malformed receipt: %s" % (exc,))
    if provenance not in _CLASS_RANK:
        raise ProvenanceError("provenance-class-unknown",
                              "receipt carries unknown class %r" % (provenance,))
    body = {"provenance": provenance,
            "fields": json.loads(_canonical(fields))}
    if _sha256_hex(_canonical(body)) != digest:
        raise ProvenanceError("provenance-digest-mismatch",
                              "receipt bytes differ from the digest")
    verdict = ("verified-observation" if provenance == EXECUTED
               else "verified-report")
    return {"verdict": verdict, "provenance": provenance,
            "receipt_digest": digest}


def render(receipt):
    """The presentation seam: every field labeled with its provenance
    class. Rendering never changes the class."""
    v = verify_receipt(receipt)
    return {
        field: {"value": value, "provenance": v["provenance"]}
        for field, value in receipt["fields"].items()
    }


def present_with_authority(receipt, authority):
    """Present a receipt at a given authority weight.

    Presenting at the receipt's own weight (or lower) is conformant.
    Presenting a LOGGED receipt with EXECUTED weight refuses
    provenance-upgraded -- the presentation seam never re-grades.
    Unknown authority classes refuse provenance-class-unknown.
    """
    if authority not in _CLASS_RANK:
        raise ProvenanceError("provenance-class-unknown",
                              "unknown authority class %r" % (authority,))
    v = verify_receipt(receipt)
    if _CLASS_RANK[authority] > _CLASS_RANK[v["provenance"]]:
        raise ProvenanceError(
            "provenance-upgraded",
            "cannot present %s receipt as %s: verification must not "
            "upgrade a report into an observation"
            % (v["provenance"], authority))
    return {"presented": authority, "provenance": v["provenance"]}


def chain_receipts(receipts):
    """Link receipts into a hash chain; each entry commits to its own
    class. Returns the entry list."""
    entries = []
    prev = "GENESIS"
    for receipt in receipts:
        body = {"provenance": receipt["provenance"],
                "receipt_digest": receipt["receipt_digest"],
                "prev": prev}
        entry = dict(receipt)
        entry["prev_digest"] = prev
        entry["entry_digest"] = _sha256_hex(_canonical(body))
        entries.append(entry)
        prev = entry["entry_digest"]
    return entries


def verify_chain(entries):
    """Verify a chained entry list.

    Chain validity proves the bytes were not altered; it does NOT
    promote provenance: a chained LOGGED entry returns verdict
    "chained-report" and keeps provenance LOGGED. A chained EXECUTED
    entry returns "chained-observation". An entry whose class cannot
    be verified refuses provenance-chain-class-mismatch.
    """
    verdicts = []
    prev = "GENESIS"
    for idx, entry in enumerate(entries):
        try:
            receipt = {"provenance": entry["provenance"],
                       "fields": entry["fields"],
                       "receipt_digest": entry["receipt_digest"]}
        except (TypeError, KeyError) as exc:
            raise ProvenanceError("provenance-chain-class-mismatch",
                                  "entry %d malformed: %s" % (idx, exc))
        v = verify_receipt(receipt)  # raises on tamper / unknown class
        if entry.get("prev_digest") != prev:
            raise ProvenanceError("provenance-chain-class-mismatch",
                                  "entry %d links to %r, expected %r"
                                  % (idx, entry.get("prev_digest"), prev))
        body = {"provenance": entry["provenance"],
                "receipt_digest": entry["receipt_digest"],
                "prev": prev}
        if _sha256_hex(_canonical(body)) != entry.get("entry_digest"):
            raise ProvenanceError("provenance-chain-class-mismatch",
                                  "entry %d linkage digest mismatch" % idx)
        verdicts.append({
            "verdict": ("chained-observation" if v["provenance"] == EXECUTED
                        else "chained-report"),
            "provenance": v["provenance"],
            "index": idx,
        })
        prev = entry["entry_digest"]
    return verdicts


def merkle_root(leaf_digests):
    """Binary Merkle root over a list of hex leaf digests (SHA-256,
    duplicate-last padding). Empty list refuses provenance-step-break."""
    if not leaf_digests:
        raise ProvenanceError("provenance-step-break",
                              "no steps: empty workflow")
    level = list(leaf_digests)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256_hex(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
    return level[0]


def commit_workflow(step_receipts):
    """Commit an ordered workflow: returns a commitment carrying the
    Merkle root AND the ordered leaf list so a later verification can
    honestly pinpoint the first divergent index (root alone cannot
    name it)."""
    leaves = [s["receipt_digest"] for s in step_receipts]
    return {"root": merkle_root(leaves), "leaves": list(leaves)}


def verify_steps(step_receipts, commitment):
    """Verify a workflow's ordered step receipts against a commitment.

    Deletion or reorder refuses provenance-step-break NAMING the first
    index where the presented leaf sequence diverges from the
    committed one. Survivors keep their own class -- verification
    never promotes. Returns per-step verdicts.

    commitment may be the dict returned by commit_workflow (preferred:
    index is genuinely pinpointed by diffing the two sequences) or a
    bare root hex string (fallback: divergence detected, index named
    only as the first presented position -- never fabricated against
    the unknown original order).
    """
    leaves = [s["receipt_digest"] for s in step_receipts]
    if isinstance(commitment, dict):
        committed = commitment["leaves"]
        root = commitment["root"]
        first_divergence = None
        for i, (have, want) in enumerate(zip(leaves, committed)):
            if have != want:
                first_divergence = i
                break
        if first_divergence is None and len(leaves) != len(committed):
            first_divergence = min(len(leaves), len(committed))
        if first_divergence is not None:
            raise ProvenanceError(
                "provenance-step-break",
                "workflow step sequence does not match the committed "
                "order: first divergence at index %d (deletion or "
                "reorder detected; surviving classes unchanged)"
                % first_divergence)
        if merkle_root(leaves) != root:
            raise ProvenanceError("provenance-step-break",
                                  "leaf order matches but root differs")
        return [{"index": i, "provenance": s["provenance"],
                 "verdict": "step-verified"}
                for i, s in enumerate(step_receipts)]
    # Bare-root fallback: detect, but refuse to fabricate an index.
    if merkle_root(leaves) == commitment:
        return [{"index": i, "provenance": s["provenance"],
                 "verdict": "step-verified"}
                for i, s in enumerate(step_receipts)]
    raise ProvenanceError(
        "provenance-step-break",
        "workflow step sequence does not match the committed root "
        "(deletion or reorder detected; surviving classes unchanged)")
