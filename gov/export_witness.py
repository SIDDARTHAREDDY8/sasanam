"""Offline export witness layer (open reimplementation).

Wave-323 lane 3 (wave-321 witness/monitor prospectus, direction-brief
item 4 -- the offline export witness layer): the offline evidence
bundle gains a witness dimension. An export carries the seven
auditor artifacts from the prospectus -- checkpoint note, full log +
witness vkeys, the signed witness-policy document, consistency proof,
inclusion proofs, cosignature times -- and the verifier binds all of
them to the bundle it witnesses, offline, against a pre-provisioned
trust anchor (the one artifact that is never embedded).

What it provides:

* :func:`build_witness_layer` -- deterministic construction of the
  ``sasanam-export-witness/v1`` layer from a bundle digest, a
  checkpoint note, the sealed policy document (verified against the
  trust anchor at build -- fail-closed, never just copied), and
  proofs.
* :func:`verify_witness_layer` -- full offline verification against
  the trust anchor. Returns a verified summary; raises coded
  :class:`ExportWitnessError` on any failure (never a soft False).
* :func:`encode_small_carrier` / :func:`decode_small_carrier` -- the
  QR-scale form: the cosigned checkpoint plus a freshness statement,
  never the payload. Fail-closed size budget
  (:data:`SMALL_CARRIER_MAX_BYTES`).
* :func:`make_consistency_proof` / :func:`make_inclusion_proof` /
  :func:`bundle_leaf_hash` -- deterministic operator-side helpers.

Binding contracts (the security core):

* The layer names the bundle it witnesses (``bundle_digest``); a
  transplanted layer refuses ``export-witness-bundle-mismatch``.
* Embedded vkeys are a convenience copy: they must equal the verified
  policy's log vkey and active-witness set EXACTLY, or
  ``export-witness-vkey-mismatch`` (an attacker who keeps the policy
  but swaps in their own keys must not verify).
* Inclusion leaves are DERIVED from the bundle digest
  (:func:`bundle_leaf_hash`); the audit-path fold is checked against
  the checkpoint root, so a layer moved to another bundle fails
  ``export-witness-proof-mismatch`` even if every other field is
  intact.
* Freshness: every verified cosignature's ``time`` must be <= now and
  ``now - max(times)`` within the policy's
  ``max_checkpoint_staleness_seconds``; the sign-then-cross ceremony
  binds a freshness statement into the small carrier (prospectus: a
  frozen old-but-valid checkpoint is otherwise undetectable offline).

Size budget (documented, probe-asserted):

* QR binary capacity at version 40 / EC level L is ~2953 bytes; the
  carrier ceiling is :data:`SMALL_CARRIER_MAX_BYTES` ``= 3072``.
* A typical export (operator sig + 3 cosignatures + freshness
  statement) is ~700 bytes. A checkpoint with so many cosignature
  lines that the carrier exceeds the ceiling refuses
  ``export-witness-carrier-oversize`` -- the auditor must use the
  file form.

Composition: consumes ``gov/witness_policy.py``,
``gov/witness_consistency.py``, ``gov/witness_log.py`` and
``gov/checkpoint_note.py`` as libraries (loaded by file path, the
zero-network pattern) -- this module does not modify them. Stdlib
only. $0 spend, synthetic/local testing.

HONEST RESIDUALS (never claimed away):

* Cross-restart replay protection needs the auditor's persisted
  last-seen policy-version watermark (inherited from witness_policy);
  the small carrier surfaces ``policy_version`` as the watermark
  signal.
* The witness log's real leaf convention is the operator's; v1 binds
  the synthetic derived leaves (``bundle_leaf_hash``). A log that
  witnesses by other leaf conventions is out of scope for v1.
* A wrong auditor clock breaks staleness checks (same residual as the
  offline-verifier lane).
"""

import hashlib
import importlib.util
import json
import os

# ---------------------------------------------------------------------------
# Codes (registered centrally in gov/decision_codes.py; pin 2045).

# ---------------------------------------------------------------------------

EXPORT_WITNESS_MALFORMED = "export-witness-malformed"
EXPORT_WITNESS_BUNDLE_MISMATCH = "export-witness-bundle-mismatch"
EXPORT_WITNESS_CARRIER_OVERSIZE = "export-witness-carrier-oversize"
EXPORT_WITNESS_CHECKPOINT_INVALID = "export-witness-checkpoint-invalid"
EXPORT_WITNESS_POLICY_INVALID = "export-witness-policy-invalid"
EXPORT_WITNESS_POLICY_VERSION_BELOW_MINIMUM = \
    "export-witness-policy-version-below-minimum"
EXPORT_WITNESS_PROOF_MISMATCH = "export-witness-proof-mismatch"
EXPORT_WITNESS_STALE = "export-witness-stale"
EXPORT_WITNESS_VKEY_MISMATCH = "export-witness-vkey-mismatch"

LAYER_FORMAT = "sasanam-export-witness/v1"
CARRIER_FORMAT = "sasanam-export-witness-carrier/v1"

# QR binary capacity at version 40 / EC level L ~= 2953 bytes; the
# carrier refuses above this ceiling (fail closed -- the auditor must
# use the file form). Typical export ~700 bytes.
SMALL_CARRIER_MAX_BYTES = 3072

# Inclusion-leaf derivation domain. The leaf preimage binds the bundle
# digest and the leaf index; the 0x00 prefix is the RFC 6962 leaf
# domain separation (mirrors gov/witness_log.leaf_hash).
_LEAF_DOMAIN = b"sasanam-export-leaf/v1\x00"

_LAYER_FIELDS = frozenset([
    "format", "bundle_digest", "bundle_id", "checkpoint", "log_vkey",
    "witness_vkeys", "policy", "consistency_proof", "inclusion_proofs",
])
_CONSISTENCY_FIELDS = frozenset(["from_size", "from_root", "to_size",
                                 "nodes"])
_INCLUSION_FIELDS = frozenset(["leaf_index", "tree_size", "path"])
_PATH_ENTRY_FIELDS = frozenset(["hash", "side"])
_NODE_FIELDS = frozenset(["lo", "hi", "root"])
_CARRIER_FIELDS = frozenset(["format", "checkpoint", "freshness"])
_FRESHNESS_FIELDS = frozenset(["exported_at", "max_staleness_seconds",
                               "policy_id", "policy_version"])


class ExportWitnessError(Exception):
    """Coded refusal. ``code`` is always an ``export-witness-*`` code."""

    def __init__(self, code, detail=""):
        super(ExportWitnessError, self).__init__(
            "[%s] %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise ExportWitnessError(code, detail)


# ---------------------------------------------------------------------------
# Zero-network dependency loading (the witness_policy pattern).
# ---------------------------------------------------------------------------

_wp = _wc = _wl = _cn = None


def _deps():
    """Load witness_policy, witness_consistency, witness_log and
    checkpoint_note from sibling files. No top-level gov imports: the
    offline verifier loads this module by file path."""
    global _wp, _wc, _wl, _cn
    if _wp is None:
        base = os.path.dirname(os.path.abspath(__file__))

        def _load(modname, filename):
            spec = importlib.util.spec_from_file_location(
                "sasanam_standalone_%s_exwitness" % modname,
                os.path.join(base, filename))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        try:
            _wp = _load("witness_policy", "witness_policy.py")
            _wc = _load("witness_consistency", "witness_consistency.py")
            _wl = _load("witness_log", "witness_log.py")
            _cn = _load("checkpoint_note", "checkpoint_note.py")
        except ExportWitnessError:
            raise
        except Exception as exc:  # noqa: BLE001
            _refuse(EXPORT_WITNESS_MALFORMED,
                    "cannot load witness dependencies: %s" % (exc,))
    return _wp, _wc, _wl, _cn


def canonical_layer_bytes(layer):
    """Canonical JSON bytes: sort_keys, no whitespace, ASCII. The exact
    bytes a layer hashes to; build and verify agree byte-for-byte."""
    try:
        return json.dumps(layer, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "layer not JSON-serializable: %s" % (exc,))


def _is_hex64(v):
    return (isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdefABCDEF" for c in v))


def _no_unknown(obj, allowed, where):
    if not isinstance(obj, dict):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "%s must be a mapping" % (where,))
    extra = set(obj) - allowed
    if extra:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "%s has unknown field(s): %s" % (where, sorted(extra)[0]))


def _check_hex_digest(v, where):
    if not _is_hex64(v):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "%s must be a 64-char hex sha256 digest" % (where,))
    return v.lower()


# ---------------------------------------------------------------------------
# Inclusion-leaf derivation (the bundle binding).
# ---------------------------------------------------------------------------

def bundle_leaf_hash(bundle_digest, leaf_index):
    """The leaf hash a witness log records for a bundle.

    ``bundle_digest`` is the 32-byte sha256 of the witnessed bundle
    artifact; ``leaf_index`` the leaf position. The preimage binds
    both, so an inclusion proof for one bundle never verifies for
    another -- the transplant defense at the leaf level.
    """
    if not isinstance(bundle_digest, (bytes, bytearray)):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "bundle_digest must be 32 bytes, got %s"
                % type(bundle_digest).__name__)
    digest = bytes(bundle_digest)
    if len(digest) != 32:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "bundle_digest must be 32 bytes")
    if (not isinstance(leaf_index, int) or isinstance(leaf_index, bool)
            or leaf_index < 0):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "leaf_index must be a non-negative int")
    preimage = (_LEAF_DOMAIN + digest
                + leaf_index.to_bytes(8, "big"))
    return hashlib.sha256(b"\x00" + preimage).digest()


# ---------------------------------------------------------------------------
# Operator-side proof builders (deterministic).
# ---------------------------------------------------------------------------

def make_consistency_proof(leaf_hashes, from_size):
    """Build the consistency proof from ``from_size`` to
    ``len(leaf_hashes)``. ``leaf_hashes`` are 32-byte RFC 6962 leaf
    hashes. Returns ``{"from_size","from_root","to_size","nodes"}``
    where nodes tile ``[0,from_size)`` and ``[from_size,to_size)``
    exactly (the verifier requires the exact tiling -- fail closed on
    shape).
    """
    _wp, _wc, wl, _cn = _deps()
    leaves = [bytes(h) for h in leaf_hashes]
    if not leaves or any(len(h) != 32 for h in leaves):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "leaf_hashes must be non-empty 32-byte hashes")
    n = len(leaves)
    if (not isinstance(from_size, int) or isinstance(from_size, bool)
            or not 0 < from_size <= n):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "from_size must satisfy 0 < from_size <= %d" % n)
    nodes = []
    intervals = wl._decomp(0, from_size)
    if from_size < n:
        intervals = intervals + wl._decomp(from_size, n)
    else:
        # Trivial proof (from_size == to_size): the verifier requires
        # an empty node list with identical roots.
        intervals = []
    for (lo, hi) in intervals:
        nodes.append({"lo": lo, "hi": hi,
                      "root": wl._calc_root(leaves[lo:hi]).hex()})
    return {"from_size": from_size,
            "from_root": wl._calc_root(leaves[:from_size]).hex(),
            "to_size": n, "nodes": nodes}


def make_inclusion_proof(leaf_hashes, leaf_index):
    """Build the inclusion proof for ``leaf_index`` in the tree of
    ``leaf_hashes``. Returns ``{"leaf_index","tree_size","path"}``
    with the path leaf-to-root as ``[{hash, side}]``."""
    _wp, _wc, wl, _cn = _deps()
    leaves = [bytes(h) for h in leaf_hashes]
    n = len(leaves)
    if (not isinstance(leaf_index, int) or isinstance(leaf_index, bool)
            or not 0 <= leaf_index < n):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "leaf_index out of range for %d leaves" % n)
    path = [{"hash": h.hex(), "side": side}
            for (h, side) in wl._audit_path(leaves, leaf_index)]
    return {"leaf_index": leaf_index, "tree_size": n, "path": path}


# ---------------------------------------------------------------------------
# Layer construction.
# ---------------------------------------------------------------------------

def build_witness_layer(bundle_digest, *, checkpoint, policy_doc,
                        trust_anchor, consistency_proof,
                        inclusion_proofs, bundle_id=None, now=None):
    """Build the ``sasanam-export-witness/v1`` layer (deterministic).

    ``bundle_digest``: 64-char hex sha256 of the witnessed bundle
    artifact bytes. ``checkpoint``: the checkpoint note text (str or
    bytes) carrying the operator signature and witness cosignature
    lines. ``policy_doc``: the sealed signed witness-policy document;
    it is VERIFIED against ``trust_anchor`` here (fail-closed at
    build -- a layer never embeds an unverifiable policy) and the
    sealed envelope is what the layer carries. ``consistency_proof``
    / ``inclusion_proofs``: as built by :func:`make_consistency_proof`
    / :func:`make_inclusion_proof`. ``now``: int unix time for the
    build-time policy verification (caller-supplied; None uses the
    system clock).

    Returns the layer dict. ``canonical_layer_bytes(layer)`` is the
    deterministic wire form.
    """
    wp, _wc, _wl, _cn = _deps()
    digest = _check_hex_digest(bundle_digest, "bundle_digest")
    if isinstance(checkpoint, bytes):
        note = checkpoint.decode("utf-8")
    elif isinstance(checkpoint, str):
        note = checkpoint
    else:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "checkpoint must be str or bytes")
    if not isinstance(note, str) or not note:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "checkpoint must be a non-empty string")
    # The checkpoint must at least parse here (fail fast at build;
    # verify re-checks signatures). Parsing errors are product
    # refusals from checkpoint_note, surfaced as malformed here.
    try:
        _cn.parse_checkpoint(note)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_MALFORMED,
                "checkpoint does not parse: %s" % (exc,))
    # The sealed policy verifies against the trust anchor BEFORE it
    # is embedded: build is fail-closed, never just a copy.
    try:
        verified = wp.verify_policy_document(policy_doc, trust_anchor,
                                             now=now)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "policy rejected at build: [%s] %s" % (code, exc))
    try:
        inputs = wp.verifier_inputs(verified, now=now)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "verified policy yields no verifier inputs: %s" % (exc,))
    _no_unknown(consistency_proof, _CONSISTENCY_FIELDS,
                "consistency_proof")
    if not isinstance(inclusion_proofs, (list, tuple)):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "inclusion_proofs must be a list")
    for i, p in enumerate(inclusion_proofs):
        _no_unknown(p, _INCLUSION_FIELDS,
                    "inclusion_proofs[%d]" % i)
    log_vkey = verified["log"]["vkey"]
    layer = {"format": LAYER_FORMAT,
             "bundle_digest": digest,
             "checkpoint": note,
             "log_vkey": log_vkey,
             "witness_vkeys": dict(inputs["witness_vkeys"]),
             "policy": policy_doc,
             "consistency_proof": dict(consistency_proof),
             "inclusion_proofs": [dict(p) for p in inclusion_proofs]}
    if bundle_id is not None:
        if not isinstance(bundle_id, str):
            _refuse(EXPORT_WITNESS_MALFORMED,
                    "bundle_id must be a string")
        layer["bundle_id"] = bundle_id
    # Determinism self-check: the canonical form must round-trip.
    canonical_layer_bytes(layer)
    return layer


# ---------------------------------------------------------------------------
# Layer verification.
# ---------------------------------------------------------------------------

def _verify_consistency_proof(proof, checkpoint_size, checkpoint_root):
    _wp, _wc, wl, _cn = _deps()
    _no_unknown(proof, _CONSISTENCY_FIELDS, "consistency_proof")
    m = proof.get("from_size")
    to_size = proof.get("to_size")
    from_root = proof.get("from_root")
    nodes = proof.get("nodes")
    if (not isinstance(m, int) or isinstance(m, bool) or m < 1
            or not isinstance(to_size, int) or isinstance(to_size, bool)
            or to_size < m):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof sizes must satisfy 1 <= from_size "
                "<= to_size")
    if to_size != checkpoint_size:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof to_size %d != checkpoint size %d"
                % (to_size, checkpoint_size))
    if not _is_hex64(from_root):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof from_root must be 64-char hex")
    if m == to_size:
        # Trivial proof: no nodes, roots must be identical.
        if nodes:
            _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                    "trivial consistency proof must carry no nodes")
        if from_root.lower() != checkpoint_root.hex():
            _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                    "trivial consistency proof root != checkpoint root")
        return
    if not isinstance(nodes, (list, tuple)) or not nodes:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "non-trivial consistency proof needs nodes")
    # The nodes must tile [0,from_size) and [from_size,to_size)
    # EXACTLY -- no more, no less (fail closed on shape).
    want = wl._decomp(0, m) + wl._decomp(m, to_size)
    got = []
    env = {}
    for i, nd in enumerate(nodes):
        _no_unknown(nd, _NODE_FIELDS,
                    "consistency_proof.nodes[%d]" % i)
        lo, hi, root = nd.get("lo"), nd.get("hi"), nd.get("root")
        if (not isinstance(lo, int) or isinstance(lo, bool)
                or not isinstance(hi, int) or isinstance(hi, bool)
                or not _is_hex64(root)):
            _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                    "consistency_proof.nodes[%d] malformed" % i)
        if (lo, hi) in env:
            _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                    "consistency_proof.nodes[%d] duplicates [%d,%d)"
                    % (i, lo, hi))
        got.append((lo, hi))
        env[(lo, hi)] = bytes.fromhex(root)
    if sorted(got) != sorted(want):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof nodes do not tile the claimed ranges")
    try:
        old_root = wl._reval(0, m, env)
        new_root = wl._reval(0, to_size, env)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof does not re-evaluate: %s" % (exc,))
    if old_root.hex() != from_root.lower():
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof does not reproduce from_root")
    if new_root != checkpoint_root:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "consistency_proof does not reach the checkpoint root")


def _verify_inclusion_proof(proof, bundle_digest_bytes, checkpoint_root,
                            checkpoint_size):
    _wp, _wc, wl, _cn = _deps()
    _no_unknown(proof, _INCLUSION_FIELDS, "inclusion_proof")
    index = proof.get("leaf_index")
    size = proof.get("tree_size")
    path = proof.get("path")
    if (not isinstance(index, int) or isinstance(index, bool)
            or not isinstance(size, int) or isinstance(size, bool)):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof leaf_index/tree_size must be ints")
    if size < 1 or not 0 <= index < size:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof leaf %r out of range for tree size %r"
                % (index, size))
    if size != checkpoint_size:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof tree_size %d != checkpoint size %d"
                % (size, checkpoint_size))
    if not isinstance(path, (list, tuple)):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof path must be a list")
    # The path length is bound to (leaf_index, tree_size): a proof
    # whose length is inconsistent with the claim is refused even if
    # it folds to the right root (the witness_log binding rule).
    if len(path) != wl._audit_path_len(index, size):
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof path length %d inconsistent with "
                "leaf %d in tree of size %d"
                % (len(path), index, size))
    h = bundle_leaf_hash(bundle_digest_bytes, index)
    for i, entry in enumerate(path):
        _no_unknown(entry, _PATH_ENTRY_FIELDS,
                    "inclusion_proof.path[%d]" % i)
        sib = entry.get("hash")
        side = entry.get("side")
        if not _is_hex64(sib) or side not in ("left", "right"):
            _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                    "inclusion_proof.path[%d] malformed" % i)
        sib_b = bytes.fromhex(sib)
        if side == "left":
            h = wl.node_hash(sib_b, h)
        else:
            h = wl.node_hash(h, sib_b)
    if h != checkpoint_root:
        _refuse(EXPORT_WITNESS_PROOF_MISMATCH,
                "inclusion_proof for leaf %d does not reach the "
                "checkpoint root" % index)


def _cosignature_times(note, witness_vkeys):
    """u64BE timestamps from the verified cosignature/v1 lines.

    ``witness_vkeys`` is the ``{name: vkey}`` map whose cosignatures
    verification accepted. A timestamp is consumed ONLY from a line
    whose (key_name, key_id) matches a verified witness vkey: the
    note text is not covered by any signature, so a name-only match
    would let anyone append a fresh timestamp line (the signed-note
    collision rules ignore it) and bypass the staleness check with
    no keys. A note that passed ``verify_checkpoint`` cannot carry
    a bad-signature line from a known (name, key_id), so the
    (name, key_id) match is sufficient.
    """
    _wp, _wc, _wl, cn = _deps()
    try:
        parsed = {name: cn.parse_vkey(vkey)
                  for name, vkey in witness_vkeys.items()}
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_MALFORMED,
                "witness vkeys do not parse: %s" % (exc,))
    known = {(p["name"], bytes(p["key_id"])) for p in parsed.values()}
    try:
        fields = cn.parse_checkpoint(note)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                "checkpoint does not parse: %s" % (exc,))
    times = []
    for sig in fields.get("signatures", []):
        if (sig.get("key_name"), bytes(sig.get("key_id", b""))) not in known:
            continue
        body = sig.get("signature", b"")
        if len(body) != 72:
            # A verified witness line is always 0x04 (72 bytes);
            # anything else here is a shape violation, not a
            # timestamp.
            _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                    "verified witness line has wrong length")
        times.append(int.from_bytes(body[0:8], "big"))
    return times


def _check_freshness(times, max_staleness, now):
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        _refuse(EXPORT_WITNESS_MALFORMED, "now must be a non-negative int")
    if not times:
        _refuse(EXPORT_WITNESS_STALE,
                "no verifiable cosignature timestamps")
    newest = max(times)
    if newest > now:
        _refuse(EXPORT_WITNESS_STALE,
                "cosignature timestamp %d is in the future (now %d)"
                % (newest, now))
    if now - newest > max_staleness:
        _refuse(EXPORT_WITNESS_STALE,
                "newest cosignature %d is older than max_staleness %d "
                "(now %d)" % (newest, max_staleness, now))


def _check_policy_version_floor(policy_version, min_policy_version):
    """Enforce the auditor-pinned policy-version floor.

    ``policy_version`` is the ``verifier_inputs()["policy_version"]``
    of the verified policy. ``min_policy_version`` is the auditor's
    floor (None = no floor, back-compat). A bad floor is malformed
    (the auditor's own input is programmer error); a policy below a
    good floor refuses with
    ``export-witness-policy-version-below-minimum``.
    """
    if min_policy_version is None:
        return
    if (isinstance(min_policy_version, bool)
            or not isinstance(min_policy_version, int)
            or min_policy_version < 1):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "min_policy_version must be an int >= 1 or null")
    if policy_version < min_policy_version:
        _refuse(EXPORT_WITNESS_POLICY_VERSION_BELOW_MINIMUM,
                "verified policy version %d is below the auditor-pinned "
                "minimum %d -- policy is stale, refused"
                % (policy_version, min_policy_version))



def verify_witness_layer(layer, trust_anchor, *, bundle_digest, now=None,
                        min_policy_version=None):
    """Verify the export witness layer offline.

    ``layer``: the dict from :func:`build_witness_layer` (or its
    canonical JSON form parsed by the caller). ``trust_anchor``: the
    auditor's pre-provisioned policy-signing trust anchor (never
    embedded in the layer). ``bundle_digest``: 64-char hex sha256 of
    the bundle artifact the auditor holds -- the transplant check.
    ``now``: int unix time for the freshness check (caller-supplied;
    no trusted-now by default). ``min_policy_version``: optional
    auditor-pinned floor for the verified policy's version -- the
    policy-currency consumer for ``verifier_inputs()["policy_version"]``
    (the wave-325 residual); a stale policy refuses with
    ``export-witness-policy-version-below-minimum``. Omit it and no
    floor is enforced (back-compat).

    Returns the verified summary dict. Raises
    :class:`ExportWitnessError` (coded) on any failure -- never a
    soft False.
    """
    wp, wc, _wl, cn = _deps()
    _no_unknown(layer, _LAYER_FIELDS, "witness layer")
    if layer.get("format") != LAYER_FORMAT:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "format %r != %r" % (layer.get("format"), LAYER_FORMAT))
    # No trusted-now by default: the freshness check needs an
    # explicit time, so require it up front (fail closed) rather
    # than letting downstream calls silently fall back to the
    # system clock.
    if now is None:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "now is required: no trusted time, fail closed")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "now must be a non-negative int")
    # The layer's own digest field is shape-checked before it is
    # compared: a malformed field is malformed, not a mismatch.
    layer_digest = _check_hex_digest(layer.get("bundle_digest"),
                                     "layer.bundle_digest")
    want_digest = _check_hex_digest(bundle_digest, "bundle_digest")
    if layer_digest != want_digest:
        _refuse(EXPORT_WITNESS_BUNDLE_MISMATCH,
                "layer witnesses bundle %s, auditor holds %s"
                % (layer_digest, want_digest))
    bundle_id = layer.get("bundle_id")
    if bundle_id is not None and not isinstance(bundle_id, str):
        _refuse(EXPORT_WITNESS_MALFORMED, "bundle_id must be a string")
    note = layer.get("checkpoint")
    if not isinstance(note, str) or not note:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "checkpoint must be a non-empty string")
    # 3. The embedded policy verifies against the trust anchor. The
    # policy document carries its own signatures; the anchor is the
    # auditor's pinned authority.
    try:
        verified = wp.verify_policy_document(layer.get("policy"),
                                              trust_anchor, now=now)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "embedded policy rejected: [%s] %s" % (code, exc))
    # 4. Embedded vkeys must equal the verified policy's keys EXACTLY.
    try:
        inputs = wp.verifier_inputs(verified, now=now)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "verified policy yields no verifier inputs: %s" % (exc,))
    # 4b. Policy currency: the auditor's pinned floor consumes
    # verifier_inputs()["policy_version"] -- a stale policy is a
    # coded refusal, not a silent pass (the wave-325 residual).
    _check_policy_version_floor(inputs["policy_version"],
                                min_policy_version)
    if layer.get("log_vkey") != verified["log"]["vkey"]:
        _refuse(EXPORT_WITNESS_VKEY_MISMATCH,
                "embedded log_vkey != verified policy log vkey")
    if (not isinstance(layer.get("witness_vkeys"), dict)
            or layer["witness_vkeys"] != inputs["witness_vkeys"]):
        _refuse(EXPORT_WITNESS_VKEY_MISMATCH,
                "embedded witness_vkeys != verified policy active set")
    # 5. The checkpoint authenticates under the operator key with the
    # policy's witness quorum.
    try:
        cos = wc.require_cosignatures(
            note, operator_vkeys=[verified["log"]["vkey"]],
            witness_vkeys=inputs["witness_vkeys"],
            quorum_k=inputs["quorum_k"])
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                "checkpoint rejected: [%s] %s" % (code, exc))
    try:
        fields = cn.parse_checkpoint(note)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                "checkpoint does not parse: %s" % (exc,))
    # 6. Freshness from the verified cosignature timestamps.
    times = _cosignature_times(note, inputs["witness_vkeys"])
    max_stale = verified.get("max_checkpoint_staleness_seconds")
    if (not isinstance(max_stale, int) or isinstance(max_stale, bool)
            or max_stale < 0):
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "policy max_checkpoint_staleness_seconds invalid")
    _check_freshness(times, max_stale, now)
    # 7. Proofs bind the bundle digest to the checkpoint root.
    digest_bytes = bytes.fromhex(want_digest)
    _verify_consistency_proof(layer.get("consistency_proof"),
                              fields["tree_size"], fields["root_hash"])
    if not isinstance(layer.get("inclusion_proofs"), (list, tuple)):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "inclusion_proofs must be a list")
    for p in layer["inclusion_proofs"]:
        _verify_inclusion_proof(p, digest_bytes, fields["root_hash"],
                              fields["tree_size"])
    return {"bundle_digest": want_digest,
            "bundle_id": bundle_id,
            "checkpoint": {"origin": fields["origin"],
                           "size": fields["tree_size"],
                           "root": fields["root_hash"].hex()},
            "witnesses": sorted(cos["witnesses"]),
            "quorum_k": cos["quorum_k"],
            "policy_id": verified["policy_id"],
            "policy_version": verified["version"],
            "inclusion": [p.get("leaf_index")
                          for p in layer["inclusion_proofs"]]}


# ---------------------------------------------------------------------------
# Small carrier (the QR form).
# ---------------------------------------------------------------------------

def encode_small_carrier(layer, *, exported_at):
    """Encode the QR-scale carrier for a witness layer.

    The carrier holds the cosigned checkpoint plus a freshness
    statement -- never the payload. ``exported_at`` is the int unix
    time of the sign-then-cross ceremony. Refuses
    ``export-witness-carrier-oversize`` when the canonical encoding
    exceeds :data:`SMALL_CARRIER_MAX_BYTES` (the auditor must use the
    file form).
    """
    _no_unknown(layer, _LAYER_FIELDS, "witness layer")
    if layer.get("format") != LAYER_FORMAT:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "not a %s layer" % LAYER_FORMAT)
    if (not isinstance(exported_at, int) or isinstance(exported_at, bool)
            or exported_at < 0):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "exported_at must be a non-negative int")
    policy = layer.get("policy")
    if not isinstance(policy, dict) or not isinstance(
            policy.get("policy"), dict):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "layer carries no sealed policy document")
    body = policy["policy"]
    try:
        max_stale = body["max_checkpoint_staleness_seconds"]
        policy_id = body["policy_id"]
        policy_version = body["version"]
    except KeyError as exc:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "policy body missing %s" % (exc,))
    carrier = {"format": CARRIER_FORMAT,
               "checkpoint": layer["checkpoint"],
               "freshness": {"exported_at": exported_at,
                             "max_staleness_seconds": max_stale,
                             "policy_id": policy_id,
                             "policy_version": policy_version}}
    blob = canonical_layer_bytes(carrier)
    if len(blob) > SMALL_CARRIER_MAX_BYTES:
        _refuse(EXPORT_WITNESS_CARRIER_OVERSIZE,
                "carrier %d bytes exceeds budget %d"
                % (len(blob), SMALL_CARRIER_MAX_BYTES))
    return blob


def decode_small_carrier(blob, policy_doc, trust_anchor, *, now=None,
                       min_policy_version=None):
    """Decode and verify a small-carrier blob offline.

    ``policy_doc`` is the sealed policy document (it travels with the
    file export; the carrier is too small for it). ``trust_anchor``
    is the auditor's pre-provisioned anchor. Verifies: carrier shape
    and size cap, the policy against the anchor, the freshness
    statement against the policy (id, version, staleness bound), the
    checkpoint's operator + quorum cosignatures, and the cosignature
    timestamps against ``now``. ``min_policy_version`` is the optional
    auditor-pinned floor for the verified policy's version (same
    semantics as :func:`verify_witness_layer`); omit it for
    back-compat.

    Returns ``{checkpoint, freshness, policy_id, policy_version}``.
    Raises :class:`ExportWitnessError` (coded) on any failure.
    """
    wp, wc, _wl, cn = _deps()
    if not isinstance(blob, (bytes, bytearray)):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "carrier blob must be bytes")
    blob = bytes(blob)
    if len(blob) > SMALL_CARRIER_MAX_BYTES:
        _refuse(EXPORT_WITNESS_CARRIER_OVERSIZE,
                "carrier %d bytes exceeds budget %d"
                % (len(blob), SMALL_CARRIER_MAX_BYTES))
    try:
        carrier = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "carrier is not JSON: %s" % (exc,))
    _no_unknown(carrier, _CARRIER_FIELDS, "carrier")
    if carrier.get("format") != CARRIER_FORMAT:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "format %r != %r"
                % (carrier.get("format"), CARRIER_FORMAT))
    fresh = carrier.get("freshness")
    _no_unknown(fresh, _FRESHNESS_FIELDS, "carrier.freshness")
    # No trusted-now by default: require the auditor's time before
    # anything time-dependent is evaluated.
    if now is None:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "now is required: no trusted time, fail closed")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "now must be a non-negative int")
    try:
        verified = wp.verify_policy_document(policy_doc, trust_anchor,
                                             now=now)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "carrier policy rejected: [%s] %s" % (code, exc))
    # The freshness statement must describe the verified policy.
    if (fresh.get("policy_id") != verified["policy_id"]
            or fresh.get("policy_version") != verified["version"]
            or fresh.get("max_staleness_seconds") != verified.get(
                "max_checkpoint_staleness_seconds")):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "carrier freshness statement != verified policy")
    exported_at = fresh.get("exported_at")
    if (not isinstance(exported_at, int) or isinstance(exported_at, bool)
            or exported_at < 0):
        _refuse(EXPORT_WITNESS_MALFORMED,
                "freshness.exported_at must be a non-negative int")
    note = carrier.get("checkpoint")
    if not isinstance(note, str) or not note:
        _refuse(EXPORT_WITNESS_MALFORMED,
                "carrier checkpoint must be a non-empty string")
    try:
        inputs = wp.verifier_inputs(verified, now=now)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_POLICY_INVALID,
                "verified policy yields no verifier inputs: %s" % (exc,))
    # Policy currency: the auditor's pinned floor consumes
    # verifier_inputs()["policy_version"] (same seam as
    # verify_witness_layer).
    _check_policy_version_floor(inputs["policy_version"],
                                min_policy_version)
    try:
        cos = wc.require_cosignatures(
            note, operator_vkeys=[verified["log"]["vkey"]],
            witness_vkeys=inputs["witness_vkeys"],
            quorum_k=inputs["quorum_k"])
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                "carrier checkpoint rejected: [%s] %s" % (code, exc))
    times = _cosignature_times(note, inputs["witness_vkeys"])
    if exported_at > now:
        _refuse(EXPORT_WITNESS_STALE,
                "carrier exported_at %d is in the future (now %d)"
                % (exported_at, now))
    _check_freshness(times, verified["max_checkpoint_staleness_seconds"],
                     now)
    try:
        fields = cn.parse_checkpoint(note)
    except Exception as exc:  # noqa: BLE001
        _refuse(EXPORT_WITNESS_CHECKPOINT_INVALID,
                "carrier checkpoint does not parse: %s" % (exc,))
    return {"checkpoint": {"origin": fields["origin"],
                           "size": fields["tree_size"],
                           "root": fields["root_hash"].hex()},
            "freshness": dict(fresh),
            "policy_id": verified["policy_id"],
            "policy_version": verified["version"],
            "witnesses": sorted(cos["witnesses"])}
