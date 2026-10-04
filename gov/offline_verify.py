"""Standalone offline evidence-bundle verifier (the auditor's tool).

Wave-324 lane 2 (wave-310 build order: the offline verifier itself, after
Sigstore-bundle distribution and the Rekor-pattern witness; registystack
offline-verifier pattern). An auditor holding an exported evidence bundle
plus its witness layer verifies EVERYTHING with zero network and zero
trust in the exporter, against a pre-provisioned trust root (the one
artifact that is never embedded).

What it verifies, in order (each step itemized in the report):

1. ``package-parse`` -- the input package shape and version.
2. ``trust-root-pin`` -- the caller-pinned trust root (shape; digest
   recorded). The root is passed explicitly, never fetched.
3. ``bundle-digest`` -- the bundle digest recomputed over the shipped
   files; the witness layer must name THIS bundle (the transplant
   check -- CVE-2026-22703: never accept "a valid entry" alone; the
   log entry must bind artifact + signature + key).
4. ``bundle-format`` -- the offline-evidence-bundle/1.0 manifest shape;
   unknown fields refuse (fail closed).
5. ``bundle-monotonicity`` -- seqs strictly increase by 1.
6. ``bundle-containment`` -- the window [from_seq, to_seq] is fully
   present, no gaps; entry_count matches.
7. ``bundle-chain`` -- the unkeyed export chain recomputes to the
   anchored tip (integrity).
8. ``bundle-entry-signatures`` -- every unredacted entry's Ed25519
   signature verifies under the manifest-pinned entry-signer key.
9. ``bundle-redaction`` -- every redacted entry is disclosed in the
   redaction report (a silently-redacted entry is caught).
10. ``bundle-anchor`` -- the anchor receipt's statement binds this
    manifest; its log signature verifies under the trust-root-pinned
    anchor key; its Merkle inclusion proof verifies.
11. ``witness-layer`` -- ``gov/export_witness.verify_witness_layer``:
    checkpoint authenticates, cosignatures meet the policy quorum,
    proofs bind the bundle digest, freshness holds.
12. ``policy-window`` -- the newest cosignature time falls inside the
    verified policy's [issued_at, expires_at] (CVE-2026-24122: check
    validity at the *timestamp's* time -- a policy valid now but issued
    after the checkpoint was cosigned does not cover it).
13. ``small-carrier`` -- if the package carries the QR form, it must
    verify too; absence is noted, not a failure.

The verdict is a typed, coded, itemized ``VerificationReport`` -- never
a bare boolean and never a bare "Verified OK" (CVE-2026-39395: predicate
and content checks are always on; there is no quiet mode, no
existence-only mode, no skip flag). A single failing check fails the
whole bundle LOUD: :func:`verify_evidence_bundle` raises coded
:exc:`OfflineVerifyError` carrying the itemized checks. An unexpected
internal failure becomes ``offline-verify-internal`` -- a crash never
produces a success signal (CVE-2026-44310).

Trust root (pinned by the caller)::

    {
        "policy_signers": [{"key_id": hex, "public_key": hex}, ...],
        "policy_threshold": N,
        "anchor_log_pubkey_hex": hex,   # the transparency log the
                                       # bundle anchor must verify under
    }

The ``policy_signers``/``policy_threshold`` half is the witness-policy
trust anchor (``gov/witness_policy.py``); ``anchor_log_pubkey_hex``
pins the log whose signature the bundle's anchor receipt must carry.
Both are required: an unpinned anchor key cannot distinguish a real
receipt from an attacker-minted one.

Input package: either a directory path (the offline-evidence-bundle/1.0
directory with ``witness_layer.json`` -- and optionally
``small_carrier.bin`` -- attached post-export) or the JSON bytes of::

    {"format": "sasanam-offline-evidence-package/v1",
     "files": {relpath: utf8-text, ...},
     "witness_layer": {...},
     "small_carrier_b64": ... (optional)}

``now`` (int unix time) is required: no trusted time, fail closed (the
witness layer's rule).

v1 constraints (documented, not hidden):

* Anchor receipts from the ``fake-log`` adapter verify fully; any other
  adapter refuses ``offline-verify-anchor-unsupported`` (fail closed --
  the auditor cannot verify what it cannot check).
* The DSSE-enveloped ledger files (``ledger.enveloped.jsonl``,
  ``manifest.enveloped.json``), when present, are covered by the bundle
  digest but not re-verified by this tool; the legacy ledger is the
  verified path.
* The bundle digest excludes ``BUNDLE_DIGEST.sha256`` (it cannot cover
  itself) and the post-export attachments (``witness_layer.json``,
  ``small_carrier.bin``): the witness layer binds the digest, so it
  cannot be part of it.
* The witness-layer inclusion_proofs list is required to be a list but
  not required to be non-empty (``export_witness.verify_witness_layer``
  contract, which this tool does not modify): an empty list makes the
  proofs-bind detail vacuous. The transplant defense still holds via
  the bundle_digest equality check, and minting a witness layer
  requires the policy signers' keys -- strictness, not a hole.

Composition: consumes ``gov/export_witness.py`` (verify_witness_layer,
plus the private ``EW._cosignature_times`` for the (name, key_id)-verified
cosignature-time binding the policy-window check needs),
``gov/offline_bundle.py``, ``gov/log.py``, ``gov/ed25519.py``,
``gov/merkle.py`` and ``gov/anchor_adapter.py`` as libraries
(deferred absolute imports -- this module does not modify them).
Stdlib only. $0 spend, synthetic/local testing.
"""

import base64
import binascii
import hashlib
import json
import os

# ---------------------------------------------------------------------------
# Codes (registered centrally in gov/decision_codes.py; pin 2012).
# ---------------------------------------------------------------------------

OFFLINE_VERIFY_MALFORMED = "offline-verify-malformed"
OFFLINE_VERIFY_VERSION_SKEW = "offline-verify-version-skew"
OFFLINE_VERIFY_TRUST_ROOT_INVALID = "offline-verify-trust-root-invalid"
OFFLINE_VERIFY_BUNDLE_DIGEST_MISMATCH = "offline-verify-bundle-digest-mismatch"
OFFLINE_VERIFY_WITNESS_LAYER_MISSING = "offline-verify-witness-layer-missing"
OFFLINE_VERIFY_CHAIN_BROKEN = "offline-verify-chain-broken"
OFFLINE_VERIFY_MONOTONICITY = "offline-verify-monotonicity"
OFFLINE_VERIFY_CONTAINMENT = "offline-verify-containment"
OFFLINE_VERIFY_ENTRY_SIGNATURE_INVALID = "offline-verify-entry-signature-invalid"
OFFLINE_VERIFY_REDACTION_UNDISCLOSED = "offline-verify-redaction-undisclosed"
OFFLINE_VERIFY_ANCHOR_INVALID = "offline-verify-anchor-invalid"
OFFLINE_VERIFY_ANCHOR_UNSUPPORTED = "offline-verify-anchor-unsupported"
OFFLINE_VERIFY_ANCHOR_KEY_MISMATCH = "offline-verify-anchor-key-mismatch"
OFFLINE_VERIFY_WITNESS_LAYER_INVALID = "offline-verify-witness-layer-invalid"
OFFLINE_VERIFY_POLICY_WINDOW = "offline-verify-policy-window"
OFFLINE_VERIFY_INTERNAL = "offline-verify-internal"

PACKAGE_FORMAT = "sasanam-offline-evidence-package/v1"
REPORT_FORMAT = "sasanam-offline-verification-report/v1"

# Files excluded from the bundle digest (see module docstring).
_DIGEST_EXCLUDED = frozenset([
    "BUNDLE_DIGEST.sha256",
    "witness_layer.json",
    "small_carrier.bin",
])

_PACKAGE_FIELDS = frozenset([
    "format", "files", "witness_layer", "small_carrier_b64",
])

# The offline-evidence-bundle/1.0 manifest contract (gov/offline_bundle.py).
_MANIFEST_FIELDS = frozenset([
    "bundle_format", "bundle_id", "exported_at", "exporter", "window",
    "chain", "ledger_digest", "anchor", "entry_signer", "redaction_report",
    "trust",
])
_WINDOW_FIELDS = frozenset(["from_seq", "to_seq", "entry_count"])
_ANCHOR_FIELDS = frozenset(["adapter", "log_pubkey_hex", "log_id"])
_ENTRY_SIGNER_FIELDS = frozenset(["key_id", "public_key_hex", "note"])


class OfflineVerifyError(Exception):
    """Coded refusal carrying the itemized checks.

    ``code`` is always an ``offline-verify-*`` code. ``checks`` is the
    itemized list (each ``{"step", "result", "detail"}``, the failing
    check additionally carrying ``"code"``). ``report`` is the partial
    verification report with ``verdict: "fail"``.
    """

    def __init__(self, code, detail="", checks=(), report=None):
        super(OfflineVerifyError, self).__init__(
            "[%s] %s" % (code, detail))
        self.code = code
        self.detail = detail
        self.checks = list(checks)
        self.report = report


def _refuse(code, detail=""):
    raise OfflineVerifyError(code, detail)


# ---------------------------------------------------------------------------
# Dependency loading.
# ---------------------------------------------------------------------------

_EW = _OB = _LOG = _ED = _MK = _AA = None


def _deps():
    """Load sibling gov modules. Deferred absolute imports (not
    top-level, not file-path): ``gov/log.py`` and
    ``gov/anchor_adapter.py`` use relative imports, so the file-path
    loading pattern cannot work for them -- and the dependencies must
    resolve identically whether this module is imported as
    ``gov.offline_verify`` or copied with the gov tree. Zero network
    either way; stdlib only."""
    global _EW, _OB, _LOG, _ED, _MK, _AA
    if _EW is None:
        try:
            from gov import export_witness as _ew_mod
            from gov import offline_bundle as _ob_mod
            from gov import log as _log_mod
            from gov import ed25519 as _ed_mod
            from gov import merkle as _mk_mod
            from gov import anchor_adapter as _aa_mod
        except OfflineVerifyError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise OfflineVerifyError(
                OFFLINE_VERIFY_INTERNAL,
                "cannot load verifier dependencies: %s" % (exc,))
        _EW, _OB, _LOG, _ED, _MK, _AA = (
            _ew_mod, _ob_mod, _log_mod, _ed_mod, _mk_mod, _aa_mod)
    return _EW, _OB, _LOG, _ED, _MK, _AA


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OfflineVerifyError(
            OFFLINE_VERIFY_MALFORMED,
            "object not JSON-serializable: %s" % (exc,))


def _is_hex64(v):
    return (isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdefABCDEF" for c in v))


def _no_unknown(obj, allowed, where):
    if not isinstance(obj, dict):
        raise OfflineVerifyError(
            OFFLINE_VERIFY_MALFORMED, "%s must be a mapping" % (where,))
    extra = set(obj) - allowed
    if extra:
        raise OfflineVerifyError(
            OFFLINE_VERIFY_MALFORMED,
            "%s has unknown field(s): %s" % (where, sorted(extra)[0]))


def bundle_digest_for_dir(bundle_dir, exclude=None):
    """Digest of a bundle directory: sha256 over sorted relative paths
    and contents (``rel + NUL + content + NUL`` per file), excluding
    the digest file itself and the post-export attachments. The same
    algorithm as ``gov/safeguard_bundle.compute_bundle_digest`` with
    the witness-layer exclusion set. Deterministic: no absolute paths,
    no timestamps.
    """
    exc = set(_DIGEST_EXCLUDED) | set(exclude or ())
    rels = []
    for root, _dirs, names in os.walk(bundle_dir):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, bundle_dir)
            if rel in exc or ".." in rel.split(os.sep):
                continue
            rels.append(rel)
    h = hashlib.sha256()
    for rel in sorted(rels):
        full = os.path.join(bundle_dir, rel)
        try:
            with open(full, "rb") as f:
                content = f.read()
        except OSError as e:
            raise OfflineVerifyError(
                OFFLINE_VERIFY_MALFORMED,
                "cannot read bundle file %r: %s" % (rel, e))
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(content)
        h.update(b"\x00")
    return h.hexdigest()


def _digest_for_files(files):
    """The same digest over an in-memory {relpath: bytes} mapping."""
    h = hashlib.sha256()
    for rel in sorted(files):
        if rel in _DIGEST_EXCLUDED or ".." in rel.split("/"):
            continue
        content = files[rel]
        if not isinstance(content, (bytes, bytearray)):
            raise OfflineVerifyError(
                OFFLINE_VERIFY_MALFORMED,
                "package file %r must be bytes" % (rel,))
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(bytes(content))
        h.update(b"\x00")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# The verifier.
# ---------------------------------------------------------------------------

class _Verifier(object):
    """Runs the 13-step verification pipeline, collecting one itemized
    check record per step. A single failure raises OfflineVerifyError
    (fail LOUD); success returns the full VerificationReport."""

    def __init__(self, trust_root, now):
        self.trust_root = trust_root
        self.now = now
        self.checks = []
        self.facts = {}
        # Set by verify_evidence_bundle before check_bundle_digest when the
        # package source is a live bundle directory.
        self._dir = None

    def _pass(self, step, detail):
        self.checks.append({"step": step, "result": "pass",
                            "detail": detail})

    def _fail(self, code, step, detail):
        self.checks.append({"step": step, "result": "fail", "code": code,
                            "detail": detail})
        raise OfflineVerifyError(code, detail, checks=self.checks,
                                 report=self._report("fail"))

    def _report(self, verdict):
        return {"format": REPORT_FORMAT,
                "verdict": verdict,
                "bundle_digest": self.facts.get("bundle_digest"),
                "trust_root_digest": self.facts.get("trust_root_digest"),
                "now": self.now,
                "checks": [dict(c) for c in self.checks],
                "facts": dict(self.facts)}

    # -- step 1: package parse -------------------------------------------
    def parse_package(self, path_or_bytes):
        if isinstance(path_or_bytes, (bytes, bytearray)):
            try:
                pkg = json.loads(bytes(path_or_bytes).decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                           "package bytes are not JSON: %s" % (exc,))
            _no_unknown(pkg, _PACKAGE_FIELDS, "package")
            if pkg.get("format") != PACKAGE_FORMAT:
                self._fail(OFFLINE_VERIFY_VERSION_SKEW, "package-parse",
                           "package format %r != %r"
                           % (pkg.get("format"), PACKAGE_FORMAT))
            files = pkg.get("files")
            if not isinstance(files, dict) or not files:
                self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                           "package.files must be a non-empty mapping")
            raw = {}
            for rel, content in files.items():
                if not isinstance(rel, str) or not rel or rel.startswith("/"):
                    self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                               "bad package file name %r" % (rel,))
                if not isinstance(content, str):
                    self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                               "package file %r must be UTF-8 text" % (rel,))
                raw[rel] = content.encode("utf-8")
            layer = pkg.get("witness_layer")
            carrier_b64 = pkg.get("small_carrier_b64")
            carrier = None
            if carrier_b64 is not None:
                if not isinstance(carrier_b64, str):
                    self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                               "small_carrier_b64 must be a string")
                try:
                    carrier = base64.b64decode(carrier_b64, validate=True)
                except (binascii.Error, ValueError) as exc:
                    self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                               "small_carrier_b64 is not base64: %s" % (exc,))
            self._pass("package-parse",
                       "serialized package: %d files" % (len(raw),))
            return raw, layer, carrier, "package-bytes"
        # Directory form.
        if isinstance(path_or_bytes, (str, bytes, os.PathLike)):
            d = os.fspath(path_or_bytes)
        else:
            self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                       "input must be a bundle directory path or package "
                       "bytes, got %s" % type(path_or_bytes).__name__)
        if not os.path.isdir(d):
            self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                       "bundle directory %r does not exist" % (d,))
        raw = {}
        for root, _dirs, names in os.walk(d):
            for n in names:
                full = os.path.join(root, n)
                rel = os.path.relpath(full, d)
                try:
                    with open(full, "rb") as f:
                        raw[rel] = f.read()
                except OSError as exc:
                    self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                               "cannot read %r: %s" % (rel, exc))
        if not raw:
            self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                       "bundle directory is empty")
        layer = None
        lp = os.path.join(d, "witness_layer.json")
        if os.path.isfile(lp):
            try:
                with open(lp, encoding="utf-8") as f:
                    layer = json.load(f)
            except (ValueError, OSError) as exc:
                self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                           "witness_layer.json does not parse: %s" % (exc,))
        carrier = None
        cp = os.path.join(d, "small_carrier.bin")
        if os.path.isfile(cp):
            try:
                with open(cp, "rb") as f:
                    carrier = f.read()
            except OSError as exc:
                self._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                           "cannot read small_carrier.bin: %s" % (exc,))
        self._pass("package-parse",
                   "bundle directory: %d files" % (len(raw),))
        return raw, layer, carrier, "bundle-directory"

    # -- step 2: trust-root pin ------------------------------------------
    def pin_trust_root(self):
        root = self.trust_root
        if not isinstance(root, dict):
            self._fail(OFFLINE_VERIFY_TRUST_ROOT_INVALID, "trust-root-pin",
                       "trust_root must be a mapping")
        signers = root.get("policy_signers")
        if not isinstance(signers, (list, tuple)) or not signers:
            self._fail(OFFLINE_VERIFY_TRUST_ROOT_INVALID, "trust-root-pin",
                       "trust_root.policy_signers must be a non-empty list")
        for i, s in enumerate(signers):
            if not isinstance(s, dict) or not _is_hex64(s.get("key_id")) \
                    or not _is_hex64(s.get("public_key")):
                self._fail(OFFLINE_VERIFY_TRUST_ROOT_INVALID,
                           "trust-root-pin",
                           "trust_root.policy_signers[%d] must carry 64-hex "
                           "key_id and public_key" % (i,))
        t = root.get("policy_threshold")
        if not isinstance(t, int) or isinstance(t, bool) \
                or not 1 <= t <= len(signers):
            self._fail(OFFLINE_VERIFY_TRUST_ROOT_INVALID, "trust-root-pin",
                       "trust_root.policy_threshold must satisfy 1 <= t <= "
                       "%d" % (len(signers),))
        akey = root.get("anchor_log_pubkey_hex")
        if not _is_hex64(akey):
            self._fail(OFFLINE_VERIFY_TRUST_ROOT_INVALID, "trust-root-pin",
                       "trust_root.anchor_log_pubkey_hex must be 64-hex "
                       "(the anchor log key is pinned, never defaulted)")
        digest = hashlib.sha256(_canonical(root)).hexdigest()
        self.facts["trust_root_digest"] = digest
        self.facts["anchor_log_pubkey"] = akey.lower()
        self._pass("trust-root-pin",
                   "pinned %d policy signer(s), threshold %d, anchor log "
                   "key %s (root %s)"
                   % (len(signers), t, akey[:16], digest[:16]))

    # -- step 3: bundle digest (the transplant check) ----------------------
    def check_bundle_digest(self, raw, layer, source):
        if not isinstance(layer, dict):
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_MISSING,
                       "bundle-digest",
                       "package carries no witness layer")
        claimed = layer.get("bundle_digest")
        if not _is_hex64(claimed):
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-digest",
                       "witness_layer.bundle_digest must be 64-char hex")
        if source == "bundle-directory":
            digest = bundle_digest_for_dir(self._dir)
        else:
            digest = _digest_for_files(raw)
        self.facts["bundle_digest"] = digest
        # Tripwire: the exporter's own digest file, when present, must
        # agree with the recomputation (it is untrusted -- the chain
        # and anchor are the real integrity -- but a mismatch means
        # post-export tampering or a foreign digest file).
        recorded = raw.get("BUNDLE_DIGEST.sha256")
        if recorded is not None:
            rec = recorded.decode("utf-8", "replace").strip().lower()
            if rec != digest:
                self._fail(OFFLINE_VERIFY_BUNDLE_DIGEST_MISMATCH,
                           "bundle-digest",
                           "BUNDLE_DIGEST.sha256 %s != recomputed %s"
                           % (rec[:16], digest[:16]))
        if claimed.lower() != digest:
            self._fail(OFFLINE_VERIFY_BUNDLE_DIGEST_MISMATCH,
                       "bundle-digest",
                       "witness layer names bundle %s, auditor holds %s "
                       "(transplant refused)" % (claimed[:16], digest[:16]))
        self._pass("bundle-digest",
                   "recomputed %s binds the witness layer" % (digest[:16],))
        return digest

    # -- step 4: bundle format --------------------------------------------
    def check_bundle_format(self, raw):
        version = raw.get("VERSION")
        if version is None:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "bundle has no VERSION file")
        if version.decode("utf-8", "replace").strip() \
                != "offline-evidence-bundle/1.0":
            self._fail(OFFLINE_VERIFY_VERSION_SKEW, "bundle-format",
                       "bundle VERSION %r is not offline-evidence-bundle/1.0"
                       % (version[:64],))
        mraw = raw.get("manifest.json")
        if mraw is None:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "bundle has no manifest.json")
        try:
            manifest = json.loads(mraw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "manifest.json does not parse: %s" % (exc,))
        _no_unknown(manifest, _MANIFEST_FIELDS, "manifest")
        if manifest.get("bundle_format") != "offline-evidence-bundle/1.0":
            self._fail(OFFLINE_VERIFY_VERSION_SKEW, "bundle-format",
                       "manifest.bundle_format %r is not "
                       "offline-evidence-bundle/1.0"
                       % (manifest.get("bundle_format"),))
        window = manifest.get("window")
        _no_unknown(window, _WINDOW_FIELDS, "manifest.window")
        anchor = manifest.get("anchor")
        _no_unknown(anchor, _ANCHOR_FIELDS, "manifest.anchor")
        es = manifest.get("entry_signer")
        _no_unknown(es, _ENTRY_SIGNER_FIELDS, "manifest.entry_signer")
        for field in ("from_seq", "to_seq", "entry_count"):
            v = window.get(field)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                           "manifest.window.%s must be a non-negative int"
                           % (field,))
        if not _is_hex64(manifest.get("ledger_digest")):
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "manifest.ledger_digest must be 64-char hex")
        if not _is_hex64(es.get("public_key_hex")) \
                or not isinstance(es.get("key_id"), str) \
                or not es["key_id"]:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "manifest.entry_signer must carry key_id and 64-hex "
                       "public_key_hex")
        if not _is_hex64(anchor.get("log_pubkey_hex")):
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-format",
                       "manifest.anchor.log_pubkey_hex must be 64-hex")
        self.facts["bundle_id"] = manifest.get("bundle_id")
        self._pass("bundle-format",
                   "offline-evidence-bundle/1.0, id %r, window %d..%d (%d "
                   "entries)"
                   % (manifest.get("bundle_id"), window["from_seq"],
                      window["to_seq"], window["entry_count"]))
        return manifest

    # -- steps 5-6: monotonicity + containment ------------------------------
    def check_structure(self, raw, manifest):
        lraw = raw.get("ledger.jsonl")
        if lraw is None:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-monotonicity",
                       "bundle has no ledger.jsonl")
        entries = []
        for lineno, line in enumerate(
                lraw.decode("utf-8", "replace").split("\n"), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                self._fail(OFFLINE_VERIFY_MALFORMED,
                           "bundle-monotonicity",
                           "ledger.jsonl line %d is not JSON" % (lineno,))
            if not isinstance(entry, dict):
                self._fail(OFFLINE_VERIFY_MALFORMED,
                           "bundle-monotonicity",
                           "ledger.jsonl line %d is not an object"
                           % (lineno,))
            entries.append(entry)
        window = manifest["window"]
        want = list(range(window["from_seq"], window["to_seq"] + 1))
        got = [e.get("seq") for e in entries]
        if got != want:
            self._fail(OFFLINE_VERIFY_MONOTONICITY, "bundle-monotonicity",
                       "ledger seqs are not strictly increasing by 1 over "
                       "the window (got %d entries, want %d..%d)"
                       % (len(entries), window["from_seq"],
                          window["to_seq"]))
        self._pass("bundle-monotonicity",
                   "%d entries, seqs %d..%d strictly increasing by 1"
                   % (len(entries), window["from_seq"], window["to_seq"]))
        if len(entries) != window["entry_count"]:
            self._fail(OFFLINE_VERIFY_CONTAINMENT, "bundle-containment",
                       "ledger has %d entries, manifest claims entry_count "
                       "%d" % (len(entries), window["entry_count"]))
        self._pass("bundle-containment",
                   "window [%d, %d] fully present, no gaps"
                   % (window["from_seq"], window["to_seq"]))
        return entries

    # -- step 7: export chain ----------------------------------------------
    def check_chain(self, entries, manifest):
        EW, OB, LOG, ED, MK, AA = _deps()
        prev = OB.EXPORT_GENESIS
        for e in entries:
            if not isinstance(e, dict):
                self._fail(OFFLINE_VERIFY_CHAIN_BROKEN, "bundle-chain",
                           "ledger entry is not an object")
            body = {k: v for k, v in e.items() if k != "export_hash"}
            prev = OB._chain_hash(prev, OB._canonical(body))
        if prev != manifest["ledger_digest"].lower():
            self._fail(OFFLINE_VERIFY_CHAIN_BROKEN, "bundle-chain",
                       "recomputed tip %s != anchored tip %s"
                       % (prev[:16],
                          manifest["ledger_digest"][:16]))
        self._pass("bundle-chain",
                   "export chain recomputes to the anchored tip %s"
                   % (prev[:16],))

    # -- step 8: per-entry signatures ---------------------------------------
    def check_entry_signatures(self, entries, manifest):
        EW, OB, LOG, ED, MK, AA = _deps()
        pub = bytes.fromhex(manifest["entry_signer"]["public_key_hex"])
        key_id = manifest["entry_signer"]["key_id"]
        for e in entries:
            seq = e.get("seq")
            redacted = e.get("redacted")
            if redacted not in (True, False):
                self._fail(OFFLINE_VERIFY_MALFORMED,
                           "bundle-entry-signatures",
                           "entry seq %r has no redacted flag" % (seq,))
            if redacted:
                continue
            # Reconstruct the source entry: the export adds exactly
            # "redacted" and "export_hash" (gov/offline_bundle.py); the
            # signature covers the source bytes.
            src = {k: v for k, v in e.items()
                   if k not in ("export_hash", "redacted")}
            if e.get("sig_key_id") != key_id:
                self._fail(OFFLINE_VERIFY_ENTRY_SIGNATURE_INVALID,
                           "bundle-entry-signatures",
                           "entry seq %r sig_key_id %r != manifest "
                           "entry_signer.key_id" % (seq, e.get("sig_key_id")))
            try:
                sig = bytes.fromhex(e.get("ed_sig") or "")
            except (TypeError, ValueError):
                self._fail(OFFLINE_VERIFY_ENTRY_SIGNATURE_INVALID,
                           "bundle-entry-signatures",
                           "entry seq %r has a malformed ed_sig" % (seq,))
            body = LOG._entry_sig_body(src)
            if ED.verify(pub, body, sig) is not True:
                self._fail(OFFLINE_VERIFY_ENTRY_SIGNATURE_INVALID,
                           "bundle-entry-signatures",
                           "entry seq %r: Ed25519 signature does not verify"
                           % (seq,))
        n = sum(1 for e in entries if e.get("redacted") is False)
        self._pass("bundle-entry-signatures",
                   "%d unredacted entries verify under the manifest-pinned "
                   "entry-signer key" % (n,))

    # -- step 9: redaction discipline ----------------------------------------
    def check_redaction(self, entries, manifest):
        report = manifest.get("redaction_report")
        if not isinstance(report, dict):
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-redaction",
                       "manifest has no redaction_report")
        listed = report.get("field_redactions")
        if not isinstance(listed, list):
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-redaction",
                       "redaction_report.field_redactions must be a list")
        listed_seqs = set()
        for i, r in enumerate(listed):
            if not isinstance(r, dict) or not isinstance(r.get("seq"), int):
                self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-redaction",
                           "field_redactions[%d] malformed" % (i,))
            listed_seqs.add(r["seq"])
        redacted_entries = [e for e in entries if e.get("redacted") is True]
        for e in redacted_entries:
            seq = e.get("seq")
            if seq not in listed_seqs:
                self._fail(OFFLINE_VERIFY_REDACTION_UNDISCLOSED,
                           "bundle-redaction",
                           "entry seq %r is redacted but not listed in the "
                           "redaction report (silent redaction)" % (seq,))
            if e.get("ed_sig") or e.get("sig_key_id"):
                self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-redaction",
                           "redacted entry seq %r carries a signature "
                           "envelope (the exporter drops it)" % (seq,))
        entry_seqs = {e.get("seq") for e in entries}
        for s in listed_seqs:
            if s not in entry_seqs:
                self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-redaction",
                           "redaction report lists seq %r with no ledger "
                           "entry" % (s,))
        self._pass("bundle-redaction",
                   "%d redacted entries, all disclosed"
                   % (len(redacted_entries),))

    # -- step 10: anchor receipt ----------------------------------------------
    def check_anchor(self, raw, manifest):
        EW, OB, LOG, ED, MK, AA = _deps()
        rraw = raw.get("anchor_receipt.json")
        if rraw is None:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-anchor",
                       "bundle has no anchor_receipt.json")
        try:
            receipt = json.loads(rraw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._fail(OFFLINE_VERIFY_MALFORMED, "bundle-anchor",
                       "anchor_receipt.json does not parse: %s" % (exc,))
        if not isinstance(receipt, dict):
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "anchor receipt is not an object")
        adapter = manifest["anchor"].get("adapter")
        if receipt.get("adapter") != adapter:
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt adapter %r != manifest adapter %r"
                       % (receipt.get("adapter"), adapter))
        if adapter != "fake-log":
            # v1 verifies the fake-log receipt fully; anything else is
            # fail-closed: the auditor cannot verify what it cannot check.
            self._fail(OFFLINE_VERIFY_ANCHOR_UNSUPPORTED, "bundle-anchor",
                       "adapter %r receipts are not verifiable by this "
                       "tool (v1 supports fake-log)" % (adapter,))
        # The receipt must be pinned to the auditor's trust root, not
        # just self-consistent: otherwise anyone can mint a keypair,
        # pin it in the manifest, and forge a "valid" receipt.
        manifest_key = manifest["anchor"]["log_pubkey_hex"].lower()
        if manifest_key != self.facts["anchor_log_pubkey"]:
            self._fail(OFFLINE_VERIFY_ANCHOR_KEY_MISMATCH, "bundle-anchor",
                       "manifest anchor key %s != trust-root-pinned key %s"
                       % (manifest_key[:16],
                          self.facts["anchor_log_pubkey"][:16]))
        # 1. The statement binds this exact manifest (tip, window,
        # bundle id, redaction digest) -- CVE-2026-22703: bind the log
        # entry to the artifact.
        try:
            anchor_input = OB._anchor_input(manifest)
            want_statement = AA.bundle_statement(anchor_input)
        except (ValueError, KeyError) as exc:
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "anchor input does not build: %s" % (exc,))
        if receipt.get("statement") != want_statement:
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt statement does not commit to this manifest "
                       "(tip/window/bundle_id/redaction digest)")
        # 1b. The receipt's self-declared statement hash must be
        # internally consistent with the statement it carries.
        if receipt.get("statement_hash") != AA._statement_hash(
                receipt["statement"]):
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt statement_hash does not hash its statement")
        # 2. The Merkle inclusion proof verifies.
        try:
            stmt_hash = bytes.fromhex(receipt["statement_hash"])
            proof = [bytes.fromhex(p)
                     for p in receipt["inclusion_proof"]]
            root = bytes.fromhex(receipt["log_root"])
            index = receipt["log_index"]
            tree_size = receipt["tree_size"]
        except (KeyError, TypeError, ValueError) as exc:
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt Merkle fields malformed: %s" % (exc,))
        if not MK.verify_inclusion(stmt_hash, index, proof, root,
                                   tree_size):
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt Merkle inclusion proof does not verify")
        # 3. The log signature verifies under the pinned key.
        try:
            sig = bytes.fromhex(receipt["log_sig"])
        except (KeyError, TypeError, ValueError):
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt log_sig malformed")
        body = (AA._FAKE_SET_DOMAIN
                + ("%d|%s|%s" % (index, receipt["log_root"],
                                 receipt["statement_hash"])).encode("utf-8"))
        pub = bytes.fromhex(self.facts["anchor_log_pubkey"])
        if ED.verify(pub, body, sig) is not True:
            self._fail(OFFLINE_VERIFY_ANCHOR_INVALID, "bundle-anchor",
                       "receipt log signature does not verify under the "
                       "pinned anchor key")
        self.facts["anchor_log_id"] = receipt.get("log_id")
        self._pass("bundle-anchor",
                   "fake-log receipt binds the manifest tip; signature and "
                   "inclusion proof verify under the pinned key")

    # -- step 11: witness layer -------------------------------------------------
    def check_witness_layer(self, layer, digest):
        EW, OB, LOG, ED, MK, AA = _deps()
        anchor = {"policy_signers": self.trust_root["policy_signers"],
                  "policy_threshold": self.trust_root["policy_threshold"]}
        try:
            summary = EW.verify_witness_layer(
                layer, anchor, bundle_digest=digest, now=self.now)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            # Preserve the inner coded reason: the auditor sees exactly
            # which witness check failed.
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
                       "witness-layer",
                       "witness layer rejected: [%s] %s" % (code, exc))
        self.facts["policy_id"] = summary.get("policy_id")
        self.facts["policy_version"] = summary.get("policy_version")
        self.facts["checkpoint_root"] = (
            summary.get("checkpoint", {}).get("root"))
        self.facts["witnesses"] = summary.get("witnesses")
        self._pass("witness-layer",
                   "checkpoint authenticates (%s, %d leaves); %d-of-%d "
                   "witness quorum (%s); policy %s v%s; proofs bind; "
                   "freshness holds"
                   % (summary["checkpoint"]["origin"],
                      summary["checkpoint"]["size"],
                      len(summary["witnesses"]), summary["quorum_k"],
                      ",".join(summary["witnesses"]),
                      summary["policy_id"], summary["policy_version"]))
        return summary

    # -- step 12: policy validity window (CVE-2026-24122) ------------------------
    def check_policy_window(self, layer):
        EW, OB, LOG, ED, MK, AA = _deps()
        body = layer["policy"]["policy"]
        issued = body.get("issued_at")
        expires = body.get("expires_at")
        # The embedded policy is authenticated at this point (step 11
        # verified it against the trust anchor); read its window.
        if not isinstance(issued, int) or isinstance(issued, bool) \
                or not isinstance(expires, int) \
                or isinstance(expires, bool):
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
                       "policy-window",
                       "verified policy has no integer issued_at/expires_at")
        # Newest cosignature time, from the (name, key_id)-verified lines
        # only (the export_witness binding rule -- a name-only match
        # would let anyone append a fresh timestamp with no keys).
        try:
            times = EW._cosignature_times(
                layer["checkpoint"], layer["witness_vkeys"])
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
                       "policy-window",
                       "cosignature times unreadable: [%s] %s" % (code, exc))
        if not times:
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
                       "policy-window", "no verifiable cosignature times")
        newest = max(times)
        # CVE-2026-24122: validity is checked at the *timestamp's*
        # time. A policy that was valid at verification time but was
        # issued after (or expired before) the checkpoint was cosigned
        # does not cover that checkpoint.
        if newest < issued or newest > expires:
            self._fail(OFFLINE_VERIFY_POLICY_WINDOW, "policy-window",
                       "newest cosignature time %d outside policy "
                       "validity window [%d, %d]"
                       % (newest, issued, expires))
        self._pass("policy-window",
                   "newest cosignature time %d inside policy window "
                   "[%d, %d]" % (newest, issued, expires))

    # -- step 13: small carrier (optional) ---------------------------------------
    def check_small_carrier(self, carrier, layer):
        EW, OB, LOG, ED, MK, AA = _deps()
        if carrier is None:
            self._pass("small-carrier",
                       "package carries no small carrier (noted)")
            return
        anchor = {"policy_signers": self.trust_root["policy_signers"],
                  "policy_threshold": self.trust_root["policy_threshold"]}
        try:
            decoded = EW.decode_small_carrier(
                carrier, layer["policy"], anchor, now=self.now)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            self._fail(OFFLINE_VERIFY_WITNESS_LAYER_INVALID,
                       "small-carrier",
                       "small carrier rejected: [%s] %s" % (code, exc))
        self._pass("small-carrier",
                   "QR form verifies: checkpoint %s, policy %s v%s"
                   % (decoded["checkpoint"]["root"][:16],
                      decoded["policy_id"], decoded["policy_version"]))


def verify_evidence_bundle(path_or_bytes, trust_root, *, now=None):
    """Verify an exported evidence bundle + witness layer, offline.

    ``path_or_bytes``: a bundle directory path (carrying
    ``witness_layer.json`` and optionally ``small_carrier.bin``) or
    the JSON bytes of a ``sasanam-offline-evidence-package/v1``
    package. ``trust_root``: the caller-pinned trust root
    (``policy_signers``/``policy_threshold``/``anchor_log_pubkey_hex``).
    ``now``: int unix time -- required; no trusted time, fail closed.

    Returns the itemized ``VerificationReport`` dict (``verdict:
    "pass"``) when every check passes. Raises coded
    :exc:`OfflineVerifyError` -- carrying the itemized checks and the
    partial report -- on any failure. Never returns a bare boolean;
    never emits a bare "Verified OK".
    """
    v = _Verifier(trust_root, now)
    try:
        if now is None:
            v._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                    "now is required: no trusted time, fail closed")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            v._fail(OFFLINE_VERIFY_MALFORMED, "package-parse",
                    "now must be a non-negative int")
        _deps()
        raw, layer, carrier, source = v.parse_package(path_or_bytes)
        if source == "bundle-directory":
            v._dir = os.fspath(path_or_bytes)
        v.pin_trust_root()
        digest = v.check_bundle_digest(raw, layer, source)
        manifest = v.check_bundle_format(raw)
        entries = v.check_structure(raw, manifest)
        v.check_chain(entries, manifest)
        v.check_entry_signatures(entries, manifest)
        v.check_redaction(entries, manifest)
        v.check_anchor(raw, manifest)
        v.check_witness_layer(layer, digest)
        v.check_policy_window(layer)
        v.check_small_carrier(carrier, layer)
    except OfflineVerifyError:
        raise
    except Exception as exc:  # noqa: BLE001
        # CVE-2026-44310: a crash never produces a success signal. An
        # unexpected internal failure fails LOUD with the checks so far.
        v.checks.append({"step": "internal", "result": "fail",
                         "code": OFFLINE_VERIFY_INTERNAL,
                         "detail": "unexpected %s: %s"
                         % (type(exc).__name__, exc)})
        raise OfflineVerifyError(
            OFFLINE_VERIFY_INTERNAL,
            "unexpected %s: %s" % (type(exc).__name__, exc),
            checks=v.checks, report=v._report("fail"))
    return v._report("pass")
