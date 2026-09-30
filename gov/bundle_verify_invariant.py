"""Bundle-verification invariant (witness GHSA-2v4r steal, pattern-only).

GHSA-2v4r-xhmm-ghv8 (in-toto/go-witness, High): ``VerifyPolicySignature``
ranged over every ``CheckedVerifier`` returned by ``envelope.Verify``
and never inspected ``verifier.Error`` -- a certificate that chained to
a trusted root and matched the identity constraints conferred
policy-signing trust even though its signature over the policy never
verified. The suggested fix (mirroring the sibling collection path)
filters out any verifier whose ``Error != nil`` BEFORE deriving trust.

Re-derived here as a Sasanam invariant, in prose (no witness code is
reused): **any failed verify sub-step hard-fails the whole bundle
verification, naming the failing check.** Trust is never derived from a
verify attempt whose error is set.

The seven sub-checks adapt the in-toto/go-witness v0.12.0 advisory
mechanisms to the attestation section of an evidence-bundle manifest
(machine codes below):

* ``verify-signature-failed``    -- GHSA-2v4r: identity matched but the
  signature never verified (forged-policy shape); never trusted.
* ``verify-no-clean-verifier``   -- no verify attempt passed cleanly
  (the witness filter result: nothing left to trust).
* ``verify-symlink-escape``      -- GHSA-v6px: an artifact symlink
  resolves outside the attested root.
* ``verify-artifactsfrom-empty`` -- GHSA-vmvj: an artifactsFrom edge
  with zero shared digests (no genuine artifact flow).
* ``verify-timestamp-eku-missing`` -- GHSA-5qp5: the timestamp signer
  lacks the sole critical id-kp-timeStamping EKU.
* ``verify-attestor-shadowed``   -- GHSA-r4fv: a duplicated attestor
  type with an unevaluated instance (only the last was checked).
* ``verify-collection-empty-match`` -- GHSA-g9jx: an empty collection
  name matched a step.
* ``verify-hash-downgrade``      -- GHSA-pgpm: a cross-step digest
  comparison used a weak hash while a stronger shared digest existed.

The attestation section is OPTIONAL. A bundle that carries no
attestation claims passes every check with "nothing to enforce" --
absence of claims is not itself a refusal.

Honest residuals: these checks bind WHICH bytes were attested and HOW
the attestation was verified; they do not prove the attested events
happened, the toolchains were honest, or the identity roots are
correct. Signature math here is structural (caller-supplied sig_ok);
the module enforces the invariant over verify RESULTS, it does not
perform cryptography itself.

$0 spend. stdlib only.
"""

import posixpath

#: id-kp-timeStamping (RFC 5280 s4.2.1.12), the EKU a timestamp signer
#: must carry SOLELY and CRITICALLY (GHSA-5qp5).
TIMESTAMPING_EKU = "1.3.6.1.5.5.7.3.8"

#: Digest algorithms that never justify a downgrade.
_STRONG_DIGESTS = frozenset({"sha256", "sha384", "sha512"})
#: Weak algorithms a comparison must never fall back to when a
#: stronger shared digest exists (GHSA-pgpm).
_WEAK_DIGESTS = frozenset({"sha1", "md5"})

SIG_FAILED = "verify-signature-failed"
NO_CLEAN_VERIFIER = "verify-no-clean-verifier"
SYMLINK_ESCAPE = "verify-symlink-escape"
ARTIFACTSFROM_EMPTY = "verify-artifactsfrom-empty"
TIMESTAMP_EKU_MISSING = "verify-timestamp-eku-missing"
ATTESTOR_SHADOWED = "verify-attestor-shadowed"
COLLECTION_EMPTY_MATCH = "verify-collection-empty-match"
HASH_DOWNGRADE = "verify-hash-downgrade"


class BundleInvariantError(Exception):
    """A bundle-verification sub-check failed. ``code`` names it."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _raise(code, detail):
    raise BundleInvariantError(code, detail)


# -- 1. policy-signature attempts (GHSA-2v4r) ---------------------------

def verify_policy_signature(attempts):
    """Filter verify attempts the witness way, then demand trust.

    ``attempts``: list of {"identity_ok": bool, "sig_ok": bool,
    "error": str|None}. An attempt whose identity constraints matched
    but whose signature never verified is the forged policy -- refused
    ``verify-signature-failed`` BEFORE any filtering (the witness bug
    counted exactly this combination as trusted). Then any attempt with
    an error set is dropped before trust is derived (the witness fix);
    with no clean passing attempt left, refuse
    ``verify-no-clean-verifier``. Absent claims pass
    ("nothing to enforce"); present-but-malformed claims fail closed.
    """
    if attempts is None:
        return (True, "no policy signature claims present; nothing to "
                      "enforce")
    if not isinstance(attempts, list):
        _raise(SIG_FAILED, "policy_signatures is not a list")
    # The GHSA-2v4r shape first: an attempt whose identity constraints
    # matched but whose signature never verified is the forged policy.
    # This check runs BEFORE the error filter -- the witness bug was
    # precisely that this combination was counted as trusted.
    for a in attempts:
        if isinstance(a, dict) and a.get("identity_ok") is True \
                and a.get("sig_ok") is not True:
            _raise(SIG_FAILED,
                   "verify attempt matched identity constraints but its "
                   "signature never verified (forged-policy shape)")
    # The witness fix: drop any attempt with an error set before
    # deriving trust from the survivors.
    clean = [a for a in attempts
             if isinstance(a, dict) and not a.get("error")]
    trusted = [a for a in clean
               if a.get("identity_ok") is True and a.get("sig_ok") is True]
    if not trusted:
        _raise(NO_CLEAN_VERIFIER,
               "no signature verify attempt passed cleanly")
    return (True, "%d attempt(s) with clean verified signatures; "
                  "failed attempts confer no trust" % len(trusted))


# -- 2. symlink escape (GHSA-v6px) --------------------------------------

def _norm_join(base, path):
    return posixpath.normpath(posixpath.join(base, path))


def verify_symlink_safety(artifacts, root):
    """Refuse ``verify-symlink-escape`` when an artifact symlink
    resolves outside the attested root."""
    if artifacts is None:
        return (True, "no artifact claims present; nothing to enforce")
    if not isinstance(artifacts, list) or not isinstance(root, str):
        _raise(SYMLINK_ESCAPE, "artifacts/attestation_root malformed")
    root_norm = posixpath.normpath(root)
    for a in artifacts:
        if not isinstance(a, dict) or a.get("is_symlink") is not True:
            continue
        path = a.get("path") or ""
        target = a.get("target") or ""
        # Artifact paths are root-relative; the link target resolves
        # against the link's parent directory under the root.
        parent = posixpath.dirname(path)
        base = root_norm if posixpath.isabs(path) \
            else _norm_join(root_norm, parent)
        resolved = posixpath.normpath(target) \
            if posixpath.isabs(target) \
            else _norm_join(base, target)
        if resolved != root_norm and not resolved.startswith(
                root_norm.rstrip("/") + "/"):
            _raise(SYMLINK_ESCAPE,
                   "artifact %r is a symlink resolving to %r, outside "
                   "the attested root %r" % (path, resolved, root_norm))
    return (True, "no artifact symlink escapes the attested root")


# -- 3. artifactsFrom flow (GHSA-vmvj) -----------------------------------

def verify_artifact_flow(edges):
    """Refuse ``verify-artifactsfrom-empty`` when an edge carries zero
    shared digests -- no genuine artifact flow."""
    if edges is None:
        return (True, "no artifactsFrom edges present; nothing to enforce")
    if not isinstance(edges, list):
        _raise(ARTIFACTSFROM_EMPTY, "edges is not a list")
    for e in edges:
        if not isinstance(e, dict):
            _raise(ARTIFACTSFROM_EMPTY, "edge is not a dict")
        shared = e.get("shared_digests")
        if not isinstance(shared, dict) or not shared:
            _raise(ARTIFACTSFROM_EMPTY,
                   "edge %r has no shared digests (zero-overlap edge)"
                   % (e.get("edge"),))
    return (True, "%d edge(s) carry genuine artifact flow" % len(edges))


# -- 4. timestamp EKU (GHSA-5qp5) -----------------------------------------

def verify_timestamp_eku(timestamps):
    """Refuse ``verify-timestamp-eku-missing`` unless the timestamp
    signer carries the SOLE critical id-kp-timeStamping EKU."""
    if timestamps is None:
        return (True, "no timestamp claims present; nothing to enforce")
    if not isinstance(timestamps, list) or not timestamps:
        _raise(TIMESTAMP_EKU_MISSING, "timestamps is not a non-empty list")
    for t in timestamps:
        if not isinstance(t, dict):
            _raise(TIMESTAMP_EKU_MISSING, "timestamp entry is not a dict")
        eku = t.get("eku") or []
        critical = t.get("critical") or []
        if eku != [TIMESTAMPING_EKU] or critical != [TIMESTAMPING_EKU]:
            _raise(TIMESTAMP_EKU_MISSING,
                   "timestamp signer EKU %r (critical %r) is not the sole "
                   "critical id-kp-timeStamping" % (eku, critical))
    return (True, "%d timestamp signer(s) carry the sole critical "
                  "id-kp-timeStamping EKU" % len(timestamps))


# -- 5. attestor shadowing (GHSA-r4fv) -------------------------------------

def verify_attestor_completeness(attestors):
    """Refuse ``verify-attestor-shadowed`` when any instance of an
    attestor type was not evaluated (only the last was checked)."""
    if attestors is None:
        return (True, "no attestor claims present; nothing to enforce")
    if not isinstance(attestors, list):
        _raise(ATTESTOR_SHADOWED, "attestors is not a list")
    for att in attestors:
        if not isinstance(att, dict):
            _raise(ATTESTOR_SHADOWED, "attestor entry is not a dict")
        instances = att.get("instances") or []
        if not instances:
            _raise(ATTESTOR_SHADOWED,
                   "attestor type %r has no instances"
                   % (att.get("type"),))
        for inst in instances:
            if not isinstance(inst, dict) \
                    or inst.get("evaluated") is not True:
                _raise(ATTESTOR_SHADOWED,
                       "attestor type %r: instance %r was not evaluated "
                       "(shadowing)" % (att.get("type"),
                                        (inst or {}).get("id")))
    return (True, "every attestor instance was evaluated")


# -- 6. empty collection match (GHSA-g9jx) ----------------------------------

def verify_collection_binding(steps, collection):
    """Refuse ``verify-collection-empty-match`` when an empty
    collection name matched a step."""
    if collection is None:
        return (True, "no collection claim present; nothing to enforce")
    if not isinstance(collection, str):
        _raise(COLLECTION_EMPTY_MATCH, "collection is not a string")
    if not isinstance(steps, list):
        _raise(COLLECTION_EMPTY_MATCH, "steps is not a list")
    if collection == "":
        matched = [s for s in steps
                   if isinstance(s, dict) and s.get("collection") == ""]
        if matched:
            _raise(COLLECTION_EMPTY_MATCH,
                   "empty collection name matched %d step(s)"
                   % len(matched))
        return (True, "empty collection name matched no step")
    mismatched = [s for s in steps
                  if isinstance(s, dict)
                  and s.get("collection") != collection]
    if mismatched:
        _raise(COLLECTION_EMPTY_MATCH,
               "%d step(s) are not in collection %r"
               % (len(mismatched), collection))
    return (True, "collection name matches exactly")


# -- 7. hash downgrade (GHSA-pgpm) -------------------------------------------

def verify_hash_strength(comparisons):
    """Refuse ``verify-hash-downgrade`` when a comparison used a weak
    hash while a stronger shared digest existed."""
    if comparisons is None:
        return (True, "no hash comparisons present; nothing to enforce")
    if not isinstance(comparisons, list):
        _raise(HASH_DOWNGRADE, "hash_comparisons is not a list")
    for comp in comparisons:
        if not isinstance(comp, dict):
            _raise(HASH_DOWNGRADE, "comparison is not a dict")
        used = (comp.get("compared_with") or "").lower()
        da = comp.get("digests_a") or {}
        db = comp.get("digests_b") or {}
        shared_strong = [d for d in da
                         if d in db and d.lower() in _STRONG_DIGESTS]
        if used in _WEAK_DIGESTS and shared_strong:
            _raise(HASH_DOWNGRADE,
                   "comparison used %r while stronger shared digest(s) "
                   "%r existed" % (used, sorted(shared_strong)))
    return (True, "no comparison downgraded to a weak hash")


# -- registry -----------------------------------------------------------------

def _check_policy_signature(att):
    return verify_policy_signature(att.get("policy_signatures"))


def _check_symlink(att):
    return verify_symlink_safety(att.get("artifacts"),
                                 att.get("attestation_root"))


def _check_flow(att):
    return verify_artifact_flow(att.get("edges"))


def _check_eku(att):
    return verify_timestamp_eku(att.get("timestamps"))


def _check_attestors(att):
    return verify_attestor_completeness(att.get("attestors"))


def _check_collection(att):
    return verify_collection_binding(att.get("steps"), att.get("collection"))


def _check_hash(att):
    return verify_hash_strength(att.get("hash_comparisons"))


#: Ordered registry: (check name, machine code, function). Order is
#: the witness advisory order; the policy-signature check runs first
#: because it is the trust root.
INVARIANT_CHECKS = (
    ("policy-signature", SIG_FAILED, _check_policy_signature),
    ("symlink-escape", SYMLINK_ESCAPE, _check_symlink),
    ("artifactsfrom-flow", ARTIFACTSFROM_EMPTY, _check_flow),
    ("timestamp-eku", TIMESTAMP_EKU_MISSING, _check_eku),
    ("attestor-shadow", ATTESTOR_SHADOWED, _check_attestors),
    ("collection-match", COLLECTION_EMPTY_MATCH, _check_collection),
    ("hash-strength", HASH_DOWNGRADE, _check_hash),
)


def run_bundle_invariants(attestations):
    """Run every sub-check against the bundle's attestation section.

    Returns (ok, code, detail); the FIRST failing check is reported --
    a failed sub-step hard-fails the whole verification. A bundle with
    no attestation claims returns (True, None, detail).
    """
    if attestations is None:
        return (True, None, "no attestation section; nothing to enforce")
    if not isinstance(attestations, dict):
        return (False, SIG_FAILED,
                "attestation section is not a dict")
    for name, code, fn in INVARIANT_CHECKS:
        try:
            _ok, detail = fn(attestations)
        except BundleInvariantError as exc:
            return (False, exc.code, "%s: %s" % (name, exc.detail))
        except Exception as exc:  # hostile input: fail, don't crash
            return (False, code, "%s: malformed input (%r)" % (name, exc))
    return (True, None, "all %d sub-checks held" % len(INVARIANT_CHECKS))


def verify_bundle_invariants(attestations):
    """Run every sub-check; raise BundleInvariantError (named code) on
    the first failure. Returns a detail string when all hold."""
    ok, code, detail = run_bundle_invariants(attestations)
    if not ok:
        raise BundleInvariantError(code, detail)
    return detail
