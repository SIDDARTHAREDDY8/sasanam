"""§5 deterministic assessment bundle — self-contained transport.

Spec: docs/safeguard-benchmark-spec.md §5. Closes the KNOWN DEBT noted
in ``gov.safeguard_benchmark.log_benchmark_receipt``: the trusted
checkpoint heads and the operator/checkpoint public keys now travel
WITH the bundle, so a third party verifies self-consistency with the
bundle directory as the sole input.

AUTHORSHIP IS NOT SELF-PROVING (F151): the keys/*.json envelope is
self-asserted by whoever assembled the bundle — a forger's self-sealed
bundle verifies indistinguishably under unpinned verification. To
accept a passing bundle as THAT OPERATOR's evidence, Victor must bind
the operator's Ed25519 key out-of-band (published key directory,
transparency log, or authenticated delivery channel) and pass it to
``bundle_verify`` as ``expected_operator_key_id`` /
``expected_operator_public_key_hex`` / ``expected_checkpoint_key_ids``.
A pinning mismatch fails the bundle closed. Unpinned verification is
explicitly marked self-consistency-only (B6 ``not_applicable``) — it
never silently claims authorship.

Bundle layout (one directory per assessment)::

    <bundle>/
      VERSION                     bundle format + SAR schema versions
      report.json                 canonical SAR (byte-stable)
      manifest.json               canonical seal manifest (incl. receipt)
      checkpoints.jsonl           signed checkpoint heads (CT-style STHs)
                                  extracted from the manifest's bundles
      keys/operator_ed25519.json  {key_id, public_key_hex} — manifest seal
      keys/checkpoint_keys.json   [{key_id, public_key_hex}] — checkpoint sigs
      VERIFY.txt                  human-readable procedure pointer (§4)
      BUNDLE_DIGEST.sha256        transport checksum (NOT a signature)

Determinism: every file is written in canonical form (sorted keys,
fixed separators, UTF-8, trailing newline) and the bundle digest is
computed over relative paths + contents only — two independent
assemblies of identical inputs produce byte-identical bundles and
digests. The sealed report/manifest bytes are NEVER rewritten by the
assembler (fail-closed transport: rewriting sealed artifacts would
break the Ed25519 seal).

``bundle_verify(bundle_dir, *, expected_operator_key_id=None,
expected_operator_public_key_hex=None, expected_checkpoint_key_ids=None)``
performs, with the bundle directory as its sole input:
  B1  version gate (bundle format + SAR schema; foreign versions
      fail closed — the SAR schema is never silently re-interpreted)
  B2  required files present
  B3  bundle digest recomputed == stored (transport tamper-evidence)
  B4  key envelope present and well-formed (missing operator key
      fails closed — no authorship, no verification)
  B6  authorship pinning: if expected keys are pinned, every pin must
      match the bundled keys or the bundle fails closed (fatal — §4
      is not run against the wrong operator's keys). If nothing is
      pinned, the check is explicitly ``not_applicable``:
      verification is SELF-CONSISTENCY ONLY; the envelope is
      self-asserted, so a passing unpinned bundle must not be accepted
      as the operator's evidence without an out-of-band key binding.
  B5  every shipped checkpoint head's Ed25519 signature verifies
      against the bundled checkpoint keys, and every checkpoint
      embedded in the manifest's inclusion/receipt bundles is among
      the shipped heads (swapped heads fail closed)
  §4   SafeguardAssessment.verify_report(..., expect_sealed=True)
      with the bundled keys — the full third-party procedure.

HONEST RESIDUALS (what the bundle does NOT do):
- The key envelope is self-asserted by whoever assembled the bundle:
  unpinned ``bundle_verify`` proves internal self-consistency, never
  authorship. Authorship requires pinning the operator's key, bound
  out-of-band (published key directory, transparency log, or
  authenticated delivery channel). F151.
- Grades the governance layer, not model weights, latent capability,
  or training-run behavior.
- S1–S4 severity and sufficiency thresholds are provisional and ours;
  no internationally agreed bar exists.
- Uncovered probe categories force INSUFFICIENT, never a score.
- No licensing, pre-release approval, or penalty regime.
- BUNDLE_DIGEST is a checksum, not a signature: anyone can re-digest
  a tampered bundle. Authenticity rests on the operator Ed25519 seal
  (§4 step 5) and the checkpoint signatures (B5).
- Threshold (k-of-n) checkpoint rosters are NOT transported: the
  bundle carries only the key_id -> public-key map, so bundles from
  threshold deployments fail closed at B5 with a named reason.
  Single-key checkpoint deployments are fully supported.
- The manifest's ``log_path`` travels verbatim (absolute deployer
  path disclosure); cross-deployment byte-identity holds only for
  identical sealed inputs.
- No key revocation channel: a compromised operator key is retired by
  shipping new bundles under a new key_id (operator determination).

$0 spend, synthetic/local only. No network. No env/config reads: the
verifier's only input is the bundle directory.
"""

from __future__ import annotations

import hashlib
import json
import os

from gov.safeguard_benchmark import (
    SCHEMA_VERSION,
    SafeguardAssessment,
    SafeguardBenchmarkError,
)

#: Bundle format version (transport envelope, independent of the SAR
#: schema it carries).
BUNDLE_VERSION = "safeguard-bundle/1.0"

#: Files every bundle must contain (relative paths, sorted).
REQUIRED_FILES = (
    "BUNDLE_DIGEST.sha256",
    "VERSION",
    "VERIFY.txt",
    "checkpoints.jsonl",
    "keys/checkpoint_keys.json",
    "keys/operator_ed25519.json",
    "manifest.json",
    "report.json",
)

#: The digest file is excluded from its own computation.
DIGEST_FILE = "BUNDLE_DIGEST.sha256"

_VERIFY_TEXT = """\
SAFEGUARD ASSESSMENT BUNDLE — third-party verification
======================================================
Bundle format: %(bundle_version)s
SAR schema:    %(schema_version)s

CONTENTS
  report.json                 The Safeguard Assessment Report (canonical JSON).
  manifest.json               Seal metadata: export digest, chain attestation,
                              Merkle inclusion bundles, Ed25519 seal, receipt.
  checkpoints.jsonl           Signed checkpoint heads (CT-style STHs) covering
                              the log prefix the report cites.
  keys/operator_ed25519.json  Operator's Ed25519 public key
                              {key_id, public_key_hex} — authenticates the
                              manifest seal (SELF-ASSERTED: see KEY BINDING).
  keys/checkpoint_keys.json   Trusted checkpoint-signing public keys
                              [{key_id, public_key_hex}] (self-asserted).
  VERSION                     Bundle + schema versions (this file's header).
  BUNDLE_DIGEST.sha256        sha256 over every file above (transport checksum,
                              NOT a signature — anyone can re-compute it).

KEY BINDING (AUTHORSHIP) — READ THIS FIRST
  The keys/*.json envelope is self-asserted by whoever assembled the
  bundle. An UNPINNED verification proves INTERNAL SELF-CONSISTENCY
  only: it CANNOT tell the operator's genuine bundle from a forger's
  self-sealed bundle (her own keys, her own log, a forged verdict) —
  both pass. To accept a passing bundle as THAT OPERATOR's evidence,
  bind the operator's Ed25519 public key OUT-OF-BAND (published key
  directory, transparency log, or authenticated delivery channel) and
  pass it explicitly:
      bundle_verify(<bundle-dir>,
                    expected_operator_key_id="...",
                    expected_operator_public_key_hex="...",
                    expected_checkpoint_key_ids=[...])
  A pinning mismatch fails the bundle closed. Without pinning, treat a
  PASS as "this bundle is internally intact", never as "this bundle is
  the operator's".
  PINNING STRENGTH: pin by the full public key
  (expected_operator_public_key_hex), not just the key_id — the bundled
  key for a pinned id is still self-asserted.

PROCEDURE (spec docs/safeguard-benchmark-spec.md section 4)
  Run: gov.safeguard_bundle.bundle_verify(<bundle-dir>, ...)
  It performs every step below with the bundle directory as its sole
  data input and reports pass/fail per step. Do not accept a bundle
  any step fails on. Pin the operator key (KEY BINDING above) unless
  you only need self-consistency.
  B1 version gate: bundle format and SAR schema versions as above.
  B2 required files present.
  B3 bundle digest recomputed and compared (transport tamper-evidence).
  B4 key envelope present and well-formed (missing operator key fails).
  B6 authorship pinning: pinned keys must match the bundle's keys
     (mismatch fails closed); unpinned, this step is explicitly
     not_applicable — self-consistency only, see KEY BINDING.
  B5 checkpoint heads: each head's Ed25519 signature verifies against the
     bundled checkpoint keys; every checkpoint embedded in the manifest's
     inclusion/receipt bundles is among the shipped heads.
  Steps 1-7: the section-4 report verification (digest recompute, chain
     attestation, inclusion bundles against trusted checkpoint keys,
     cited-entry coverage, Ed25519 manifest seal REQUIRED, chained
     receipt cross-check, deterministic report_id).

WHAT THIS BUNDLE DOES NOT PROVE
  - Authorship: unpinned verification proves self-consistency, not who
    wrote the bundle. See KEY BINDING above.
  - It grades the governance layer, not model weights, latent capability,
    or training-run behavior.
  - Severity S1-S4 and sufficiency thresholds are provisional and ours;
    no internationally agreed bar exists.
  - Uncovered probe categories force INSUFFICIENT, never a score.
  - No licensing, pre-release approval, or penalty regime is implemented.
  - The bundle checksum is not a signature: authenticity rests on the
    operator Ed25519 seal (step 5) and the checkpoint signatures (B5).
  - Threshold (k-of-n) checkpoint rosters are not transported: bundles
    from threshold deployments fail closed at B5; single-key supported.
  - The manifest's log_path travels verbatim (deployer path disclosure).
"""


class SafeguardBundleError(Exception):
    """Loud failure: malformed inputs, unreadable bundle, failed check."""


def _canonical(obj):
    """Canonical bytes — the SAME form gov.safeguard_benchmark seals.

    No parallel scheme: reuse, don't reinvent.
    """
    return SafeguardAssessment.canonical(obj)


def _validate_pins(expected_operator_key_id,
                 expected_operator_public_key_hex,
                 expected_checkpoint_key_ids):
    """Validate Victor's pinning inputs LOUDLY, before any bundle read.

    A typo'd pin must never silently pass: malformed pins raise
    SafeguardBundleError (these are the caller's inputs, not hostile
    bundle data — bundle_verify never raises on a hostile bundle, but
    a broken pin is a caller error, not a bundle property).
    """
    if (expected_operator_key_id is not None
            and (not isinstance(expected_operator_key_id, str)
                 or not expected_operator_key_id)):
        raise SafeguardBundleError(
            "expected_operator_key_id must be a non-empty string")
    if expected_operator_public_key_hex is not None:
        if not isinstance(expected_operator_public_key_hex, str):
            raise SafeguardBundleError(
                "expected_operator_public_key_hex must be a hex string")
        try:
            pub = bytes.fromhex(expected_operator_public_key_hex)
        except ValueError:
            raise SafeguardBundleError(
                "expected_operator_public_key_hex is not valid hex")
        if len(pub) != 32:
            raise SafeguardBundleError(
                "expected_operator_public_key_hex must decode to 32 "
                "bytes (Ed25519), got %d" % (len(pub),))
    if expected_checkpoint_key_ids is not None:
        if (not isinstance(expected_checkpoint_key_ids, (list, tuple))
                or not all(isinstance(k, str) and k
                           for k in expected_checkpoint_key_ids)):
            raise SafeguardBundleError(
                "expected_checkpoint_key_ids must be a list of "
                "non-empty strings")


def _check_key_envelope(entry, where):
    """Validate one {key_id, public_key_hex} envelope entry.

    Returns (key_id, public_key_bytes). Fail-closed on any malformation.
    """
    if not isinstance(entry, dict):
        raise SafeguardBundleError(
            "%s: key entry must be an object, got %s"
            % (where, type(entry).__name__))
    kid = entry.get("key_id")
    hx = entry.get("public_key_hex")
    if not isinstance(kid, str) or not kid:
        raise SafeguardBundleError(
            "%s: key entry needs a non-empty string key_id" % (where,))
    if not isinstance(hx, str):
        raise SafeguardBundleError(
            "%s: key entry %r needs public_key_hex (64 hex chars)"
            % (where, kid))
    try:
        pub = bytes.fromhex(hx)
    except ValueError:
        raise SafeguardBundleError(
            "%s: key entry %r has malformed public_key_hex"
            % (where, kid))
    if len(pub) != 32:
        raise SafeguardBundleError(
            "%s: key entry %r public key is %d bytes, Ed25519 needs 32"
            % (where, kid, len(pub)))
    return kid, pub


def _head_identity(cp):
    """Stable identity for a checkpoint head dict."""
    return (str(cp.get("seq")), str(cp.get("merkle_root")),
            str(cp.get("hash")))


def _extract_heads(manifest):
    """Checkpoint heads embedded in the manifest's inclusion bundles
    plus the receipt bundle, deduplicated and deterministically
    ordered. The assembler ships exactly these — no log access, so
    assembly is a pure function of the sealed inputs."""
    heads = {}
    items = manifest.get("inclusion_bundles") or []
    bundles = [it.get("bundle") for it in items
               if isinstance(it, dict)]
    receipt = manifest.get("receipt")
    if isinstance(receipt, dict):
        bundles.append(receipt.get("bundle"))
    for b in bundles:
        if not isinstance(b, dict):
            continue
        cp = b.get("checkpoint")
        if isinstance(cp, dict):
            heads[_head_identity(cp)] = cp
    return [heads[k] for k in sorted(heads)]


def bundle_assemble(report, manifest, *, operator_key, checkpoint_keys,
                    out_dir):
    """Write the deterministic §5 bundle for a sealed SAR.

    ``report``/``manifest`` are the sealed pair from
    ``SafeguardAssessment.build`` / ``seal`` /
    ``log_benchmark_receipt`` — written VERBATIM (canonical JSON),
    never rewritten. ``operator_key`` is one ``{key_id,
    public_key_hex}`` entry; ``checkpoint_keys`` is a list of them.

    Fail-closed: refuses mismatched report/manifest pairs, foreign
    schema versions, manifests without a chained receipt (a bundle
    that can never pass §4 step 6 is a lie), malformed keys, and
    non-empty output directories. Never mutates its inputs.

    Returns ``{"bundle_dir", "bundle_digest", "files", "report_id"}``.
    """
    # -- validate the sealed pair -----------------------------------
    if not isinstance(report, dict):
        raise SafeguardBundleError("report must be a dict")
    if not isinstance(manifest, dict):
        raise SafeguardBundleError("manifest must be a dict")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise SafeguardBundleError(
            "refusing to bundle schema %r: this assembler only "
            "transports %r (the SAR schema is never silently "
            "re-interpreted)" % (manifest.get("schema_version"),
                                  SCHEMA_VERSION))
    rid = (report.get("report_id") or {}).get("value")
    if not isinstance(rid, str) or not rid.startswith("SAR-"):
        raise SafeguardBundleError(
            "report has no well-formed report_id")
    if manifest.get("report_id") != rid:
        raise SafeguardBundleError(
            "manifest report_id %r does not match report %r: refusing "
            "to bundle a mismatched pair" % (manifest.get("report_id"),
                                              rid))
    expect_digest = hashlib.sha256(_canonical(report)).hexdigest()
    if manifest.get("export_sha256") != expect_digest:
        raise SafeguardBundleError(
            "manifest export_sha256 does not match the report: "
            "refusing to bundle a mismatched pair")
    receipt = manifest.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(
            receipt.get("entry"), dict):
        raise SafeguardBundleError(
            "manifest carries no chained receipt: the bundle could "
            "never pass §4 step 6, so it is not assembled")
    # -- validate the key envelope -----------------------------------
    op_id, _op_pub = _check_key_envelope(operator_key, "operator_key")
    if not isinstance(checkpoint_keys, list):
        raise SafeguardBundleError("checkpoint_keys must be a list")
    cp_envelopes = []
    for i, e in enumerate(checkpoint_keys):
        kid, _pub = _check_key_envelope(
            e, "checkpoint_keys[%d]" % i)
        cp_envelopes.append({"key_id": kid,
                             "public_key_hex": e["public_key_hex"]})
    if len({d["key_id"] for d in cp_envelopes}) != len(cp_envelopes):
        raise SafeguardBundleError(
            "checkpoint_keys carries duplicate key_ids")
    cp_envelopes.sort(key=lambda d: d["key_id"])
    # -- bind the operator key to the manifest seal ------------------
    # p4 footgun: the assembler must not silently ship a bundle whose
    # operator key differs from the manifest seal's key — such a bundle
    # can never pass §4 step 5. Refuse loudly instead.
    seal = manifest.get("signing") or {}
    if (seal.get("scheme") == "ed25519" and seal.get("key_id")
            and seal["key_id"] != op_id):
        raise SafeguardBundleError(
            "operator_key key_id %r does not match the manifest "
            "seal's key_id %r: refusing to ship a bundle that can "
            "never pass §4 step 5 (the seal binds the sealing "
            "operator's key)" % (op_id, seal["key_id"]))
    # -- output directory ---------------------------------------------
    out_dir = str(out_dir)
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        raise SafeguardBundleError(
            "output directory %r is not empty: refusing to mix bundles"
            % (out_dir,))
    os.makedirs(out_dir, exist_ok=True)
    keys_dir = os.path.join(out_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    heads = _extract_heads(manifest)
    files = {
        "VERSION": ("%(bundle_version)s\nschema: %(schema_version)s\n"
                    % {"bundle_version": BUNDLE_VERSION,
                       "schema_version": SCHEMA_VERSION}
                    ).encode("utf-8"),
        "report.json": _canonical(report) + b"\n",
        "manifest.json": _canonical(manifest) + b"\n",
        "checkpoints.jsonl": b"".join(
            _canonical(h) + b"\n" for h in heads),
        "keys/operator_ed25519.json": _canonical(
            {"key_id": op_id,
             "public_key_hex": operator_key["public_key_hex"]}) + b"\n",
        "keys/checkpoint_keys.json": _canonical(cp_envelopes) + b"\n",
        "VERIFY.txt": (_VERIFY_TEXT % {
            "bundle_version": BUNDLE_VERSION,
            "schema_version": SCHEMA_VERSION}).encode("utf-8"),
    }
    for rel in sorted(files):
        full = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(files[rel])
    # The digest is computed from the bytes on disk by the same code
    # path the verifier uses — the stored value cannot drift from the
    # verified value.
    digest = compute_bundle_digest(out_dir)
    with open(os.path.join(out_dir, DIGEST_FILE), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")
    return {"bundle_dir": out_dir,
            "bundle_digest": digest,
            "files": sorted(list(files) + [DIGEST_FILE]),
            "report_id": rid}


def compute_bundle_digest(bundle_dir):
    """Pure digest function: sha256 over sorted relative paths and
    contents (``rel + NUL + content + NUL`` per file), excluding the
    digest file itself. Deterministic: no absolute paths, no
    timestamps. Raises SafeguardBundleError on I/O problems."""
    bundle_dir = str(bundle_dir)
    rels = []
    for root, _dirs, names in os.walk(bundle_dir):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, bundle_dir)
            if rel == DIGEST_FILE:
                continue
            rels.append(rel)
    h = hashlib.sha256()
    for rel in sorted(rels):
        full = os.path.join(bundle_dir, rel)
        try:
            with open(full, "rb") as f:
                content = f.read()
        except OSError as e:
            raise SafeguardBundleError(
                "cannot read %r for digest: %s" % (rel, e))
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(content)
        h.update(b"\x00")
    return h.hexdigest()


def bundle_verify(bundle_dir, *,
                 expected_operator_key_id=None,
                 expected_operator_public_key_hex=None,
                 expected_checkpoint_key_ids=None):
    """Verify a §5 bundle with the bundle directory as the sole input.

    Optional pinning lets Victor bind the bundle to the operator's
    out-of-band key: ``expected_operator_key_id``,
    ``expected_operator_public_key_hex`` (64 hex chars), and/or
    ``expected_checkpoint_key_ids`` (list — must equal the bundled
    checkpoint key_id set; set-equality, not subset). Any mismatch fails
    the bundle closed and skips §4 (never verify against the wrong
    operator's keys).
    Malformed pins raise SafeguardBundleError — a typo'd pin must
    never silently pass.

    PINNING STRENGTH: pinning by ``expected_operator_key_id`` alone
    only checks the key's *label* — the bundled public key for that id
    is still self-asserted. Victor SHOULD pin
    ``expected_operator_public_key_hex`` (the full 32-byte key) for a
    real authorship binding; key_id pins are a convenience, not a
    binding.

    With NO pins, verification proves internal self-consistency
    ONLY: the B6 check is explicitly ``not_applicable`` and names the
    residual — a passing unpinned bundle must not be accepted as the
    operator's evidence without an out-of-band key binding.

    No log access, no env, no config, no network. Returns
    ``{"passed", "bundle_digest_ok", "report_id", "bundle_version",
    "schema_version", "checks", "failures"}``. Each check carries
    ``layer`` (``"bundle"`` for B1–B6, ``"section4"`` for the §4
    steps), ``step``, ``name``, ``ok``, ``status``, ``detail``.
    """
    # Pin validation is a caller-input contract: raise loudly, before
    # any bundle processing (a hostile bundle must fail, not crash —
    # a broken pin is the caller's error, not the bundle's).
    _validate_pins(expected_operator_key_id,
                   expected_operator_public_key_hex,
                   expected_checkpoint_key_ids)

    checks = []
    failures = []
    bundle_dir = str(bundle_dir)

    def check(layer, step, name, ok, detail="", status=None):
        st = status or ("pass" if ok else "fail")
        checks.append({"layer": layer, "step": step, "name": name,
                       "ok": bool(ok), "status": st, "detail": detail})
        if st == "fail":
            failures.append("bundle %s (%s): %s" % (step, name, detail))
        return ok

    def read(rel):
        full = os.path.join(bundle_dir, rel)
        try:
            with open(full, "rb") as f:
                return f.read()
        except OSError as e:
            raise SafeguardBundleError(
                "cannot read %r: %s" % (rel, e))

    fatal = False
    report = manifest = None
    trusted = {}
    op_pub = op_id = None

    try:
        # B1: version gate.
        if not os.path.isdir(bundle_dir):
            check("bundle", "B1", "bundle_layout", False,
                  "%r is not a directory" % (bundle_dir,))
            fatal = True
        else:
            try:
                version_raw = read("VERSION").decode("utf-8")
            except SafeguardBundleError as e:
                check("bundle", "B1", "bundle_layout", False, str(e))
                fatal = True
            else:
                lines = version_raw.splitlines()
                ok = (len(lines) >= 2
                      and lines[0].strip() == BUNDLE_VERSION
                      and lines[1].strip()
                      == "schema: " + SCHEMA_VERSION)
                check("bundle", "B1", "bundle_layout", ok,
                      "VERSION=%r (need %r + schema %r)"
                      % (lines[:2], BUNDLE_VERSION, SCHEMA_VERSION))
                fatal = not ok

        # B2: required files.
        if not fatal:
            missing = [r for r in REQUIRED_FILES
                       if not os.path.isfile(
                           os.path.join(bundle_dir, r))]
            check("bundle", "B2", "required_files", not missing,
                  ("all %d required files present"
                   % len(REQUIRED_FILES)) if not missing else
                  "missing files: %s" % (", ".join(missing),))
            fatal = bool(missing)

        # B3: bundle digest.
        digest_ok = False
        if not fatal:
            try:
                stored = read(DIGEST_FILE).decode(
                    "utf-8").strip().split()[0]
            except (SafeguardBundleError, IndexError) as e:
                check("bundle", "B3", "bundle_digest", False,
                      "unreadable digest file: %s" % (e,))
                fatal = True
            else:
                try:
                    recomputed = compute_bundle_digest(bundle_dir)
                except SafeguardBundleError as e:
                    check("bundle", "B3", "bundle_digest", False,
                          str(e))
                    fatal = True
                else:
                    digest_ok = (recomputed == stored)
                    check("bundle", "B3", "bundle_digest", digest_ok,
                          "recomputed %s... stored %s..."
                          % (recomputed[:16], stored[:16]))

        # Report + manifest parse (needed by B4/B5/§4).
        if not fatal:
            try:
                report = json.loads(
                    read("report.json").decode("utf-8"))
                manifest = json.loads(
                    read("manifest.json").decode("utf-8"))
            except (SafeguardBundleError, ValueError) as e:
                check("bundle", "B3", "bundle_parse", False,
                      "report.json/manifest.json do not parse: %s"
                      % (e,))
                fatal = True
            else:
                ok = (isinstance(report, dict)
                      and isinstance(manifest, dict)
                      and manifest.get("schema_version")
                      == SCHEMA_VERSION)
                check("bundle", "B3", "bundle_parse", ok,
                      "schema_version=%r (need %r)"
                      % (manifest.get("schema_version")
                         if isinstance(manifest, dict) else None,
                         SCHEMA_VERSION))
                fatal = not ok

        # B4: key envelope.
        if not fatal:
            try:
                op_entry = json.loads(
                    read("keys/operator_ed25519.json").decode("utf-8"))
                cp_entries = json.loads(
                    read("keys/checkpoint_keys.json").decode("utf-8"))
                op_id, op_pub = _check_key_envelope(
                    op_entry, "keys/operator_ed25519.json")
                if not isinstance(cp_entries, list):
                    raise SafeguardBundleError(
                        "keys/checkpoint_keys.json must be a list")
                for i, e in enumerate(cp_entries):
                    kid, pub = _check_key_envelope(
                        e, "keys/checkpoint_keys.json[%d]" % i)
                    trusted[kid] = pub
                check("bundle", "B4", "key_envelope", True,
                      "operator key %r present; %d checkpoint key(s)"
                      % (op_id, len(trusted)))
            except (SafeguardBundleError, ValueError) as e:
                check("bundle", "B4", "key_envelope", False,
                      "UNSIGNED BUNDLE: %s — without the operator key "
                      "there is no authorship and no verification"
                      % (e,))
                fatal = True

        # B6: authorship pinning (F151).
        if not fatal:
            pins = (expected_operator_key_id,
                    expected_operator_public_key_hex,
                    expected_checkpoint_key_ids)
            if all(p is None for p in pins):
                check("bundle", "B6", "authorship_pinning", False,
                      "no expected keys pinned: B1–B5 + §4 prove "
                      "internal SELF-CONSISTENCY ONLY. The keys/*.json "
                      "envelope is self-asserted by whoever assembled "
                      "the bundle — a forger's self-sealed bundle "
                      "verifies indistinguishably. Bind the operator's "
                      "key out-of-band (published key directory, "
                      "transparency log, or authenticated delivery "
                      "channel) and re-run with "
                      "expected_operator_key_id=... / "
                      "expected_operator_public_key_hex=... / "
                      "expected_checkpoint_key_ids=... before "
                      "accepting a passing bundle as that operator's "
                      "evidence.",
                      status="not_applicable")
            else:
                mism = []
                if (expected_operator_key_id is not None
                        and expected_operator_key_id != op_id):
                    mism.append(
                        "operator key_id: expected %r, bundle "
                        "carries %r" % (expected_operator_key_id,
                                        op_id))
                if expected_operator_public_key_hex is not None:
                    want = bytes.fromhex(
                        expected_operator_public_key_hex)
                    if want != op_pub:
                        mism.append(
                            "operator public key: pinned %s..., "
                            "bundle carries %s..." % (
                                expected_operator_public_key_hex[:16],
                                op_entry["public_key_hex"][:16]))
                if expected_checkpoint_key_ids is not None:
                    want_ids = sorted(expected_checkpoint_key_ids)
                    got_ids = sorted(trusted)
                    if want_ids != got_ids:
                        mism.append(
                            "checkpoint key ids: expected %r, "
                            "bundle carries %r" % (want_ids, got_ids))
                if mism:
                    check("bundle", "B6", "authorship_pinning", False,
                          "PINNING MISMATCH — this is NOT the "
                          "expected operator's bundle: "
                          + "; ".join(mism))
                    # Fatal: never run §4 against the wrong
                    # operator's keys.
                    fatal = True
                else:
                    check("bundle", "B6", "authorship_pinning", True,
                          "operator/checkpoint keys pinned and "
                          "matched (operator key_id %r, %d "
                          "checkpoint key(s))" % (op_id, len(trusted)))

        # B5: checkpoint heads.
        if not fatal:
            try:
                raw = read("checkpoints.jsonl").decode("utf-8")
                heads = [json.loads(line) for line in raw.splitlines()
                         if line.strip()]
            except (SafeguardBundleError, ValueError) as e:
                check("bundle", "B5", "checkpoint_heads", False,
                      "checkpoints.jsonl does not parse: %s" % (e,))
                fatal = True
            else:
                from gov.log import _verify_one_checkpoint_sig
                sig_ok = True
                sig_notes = []
                for h in heads:
                    ok, err = _verify_one_checkpoint_sig(h, trusted)
                    if not ok:
                        sig_ok = False
                        sig_notes.append(
                            "head@%s: %s" % (h.get("seq"), err))
                if sig_ok:
                    sig_notes.append(
                        "%d head(s): every Ed25519 signature verifies "
                        "against the bundled checkpoint keys"
                        % len(heads))
                check("bundle", "B5", "checkpoint_head_signatures",
                      sig_ok, "; ".join(sig_notes))
                # Cross-check: every checkpoint embedded in the
                # manifest's inclusion/receipt bundles is among the
                # shipped heads (swapped heads fail closed here).
                shipped = {_head_identity(h) for h in heads
                           if isinstance(h, dict)}
                embedded = {_head_identity(cp)
                            for cp in _embedded_checkpoints(manifest)}
                missing_heads = sorted(
                    set(e for e in embedded) - shipped)
                check("bundle", "B5", "checkpoint_head_binding",
                      not missing_heads,
                      ("every manifest-embedded checkpoint is among "
                       "the shipped heads")
                      if not missing_heads else
                      "manifest-embedded checkpoints missing from "
                      "shipped heads (swapped/foreign heads): %s"
                      % (missing_heads,))
                fatal = not (sig_ok and not missing_heads)

        # §4: the full third-party procedure, third-party mode.
        if not fatal:
            try:
                s4 = SafeguardAssessment.verify_report(
                    report, manifest, trusted_keys=trusted,
                    public_key=op_pub, expect_sealed=True)
            except Exception as e:  # never raise on a hostile bundle
                check("bundle", "§4", "section4_procedure", False,
                      "verify_report raised: %s (%s)"
                      % (e, type(e).__name__))
            else:
                for c in s4["checks"]:
                    c = dict(c)
                    c["layer"] = "section4"
                    checks.append(c)
                for f in s4["failures"]:
                    failures.append("§4 " + f)
    except Exception as e:  # hostile bundle must fail, not crash
        failures.append("bundle fatal: %s (%s)"
                        % (e, type(e).__name__))

    rid = None
    try:
        rid = (report or {}).get("report_id", {}).get("value")
    except AttributeError:
        rid = None
    return {"passed": not failures,
            "bundle_digest_ok": digest_ok,
            "report_id": rid,
            "bundle_version": BUNDLE_VERSION,
            "schema_version": SCHEMA_VERSION,
            "checks": checks,
            "failures": failures}


def _embedded_checkpoints(manifest):
    """Checkpoint dicts embedded in the manifest's bundles."""
    out = []
    items = manifest.get("inclusion_bundles") or []
    bundles = [it.get("bundle") for it in items
               if isinstance(it, dict)]
    receipt = manifest.get("receipt")
    if isinstance(receipt, dict):
        bundles.append(receipt.get("bundle"))
    for b in bundles:
        if isinstance(b, dict) and isinstance(
                b.get("checkpoint"), dict):
            out.append(b["checkpoint"])
    return out


# Re-export the honesty contract's home module for convenience.
__all__ = ["BUNDLE_VERSION", "DIGEST_FILE", "REQUIRED_FILES",
           "SafeguardBundleError", "bundle_assemble",
           "bundle_verify", "compute_bundle_digest"]
