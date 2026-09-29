#!/usr/bin/env python3
"""Wave-191 red-team probes: evidence-bundle distribution over OCI.

Break-first battery per the diagnosing-bugs skill. Threat model: the
offline evidence bundle is auditor-verifiable (gov/evidence_verify.py),
but TODAY's tree has NO distribution discipline -- a bundle travels by
file copy, with no digest identity, no pinning, and no referrer graph.
The wave-190 ORAS spike proved the attacks below against a live registry;
this battery encodes them as the product lane's red-first contract:

  D1 REFERRER STRIP   signature/BOM referrers stripped -> the auditor
                      must fail closed (a bundle-only verifier would NOT
                      notice; the graph check is the defense)
  D2 LYING REGISTRY   registry serves bytes that do not match the pinned
                      digest -> pull must fail closed (the pin is enforced
                      by byte-compare, not by trusting the server)
  D3 TAG COLLISION    second bundle pushed to the same tag -> the pinned
                      digest must survive (never silently switch bundles)
  D4 TAG TOCTOU       tag re-resolved mid-audit -> resolve once, pin the
                      digest, never re-resolve
  D5 TAG CLOBBER      push over an existing tag bound to a different
                      digest -> refuse loudly, never silently overwrite

On the pristine tree ``gov.evidence_distribute`` does not exist: the
system under test is the naive workflow (bare tag pull + standalone
verifier, no pinning, no referrer check) and every probe reports BREAK --
the gap is real and demonstrated, exactly as the spike showed live.
After the fix: all probes must flip to HELD.

Verdicts: BREAK (attack succeeded / gap demonstrated), HELD (defense
failed closed). ERROR only on harness failure (a verdict changing
between the two deterministic runs, an unexpected exception).

Deterministic: all key material derives from SHA256(probe tags); every
probe runs twice and a verdict change is an ERROR. Synthetic/local only,
zero network (in-memory fake registry modeling the OCI semantics AND the
zot quirks the spike discovered: per-repo referrers, digest
resolvability follows the tag index, tags are mutable pointers).
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import evidence_distribute as _ed
    from gov.digest_ref import DigestRef as _DigestRef
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False
    _ed = None
    _DigestRef = None

from gov.log import ActionLog
from gov.evidence_bundle import (
    EvidenceBundle, log_evidence_bundle_receipt,
)
from gov.signing import Ed25519Signer
from gov.evidence_verify import verify_bundle

# -- media types: the battery's independent spec; the module must match --
MT_TAR = "application/vnd.sasanam.evidence-bundle.tar"
MT_CONFIG = "application/vnd.sasanam.evidence-bundle.config.v1+json"
MT_BOM = "application/vnd.sasanam.decision-bom+json"
MT_SIG = "application/vnd.sasanam.manifest-signature+json"
AT_BOM = "application/vnd.sasanam.decision-bom"
AT_SIG = "application/vnd.sasanam.manifest-signature"


def _seed(tag):
    return hashlib.sha256(
        ("wave191-distribute-probe:" + tag).encode()).digest()


OPERATOR = Ed25519Signer(_seed("operator"))
OPERATOR_PUB_HEX = OPERATOR.public_key.hex()

_LOG_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH")


def _scrub_env():
    saved = {n: os.environ.get(n) for n in _LOG_VARS}
    os.environ["GOV_LOG_KEY"] = "eb" * 32
    os.environ["GOV_LOG_KEY_EPOCH"] = "wave191-distribute-probe"

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


class RegistryError(Exception):
    pass


# --------------------------------------------------------------------------
# Fake registry: OCI semantics + the zot quirks the spike discovered.
# --------------------------------------------------------------------------
class FakeRegistry(object):
    def __init__(self):
        self.blobs = {}       # (repo, digest) -> bytes
        self.manifests = {}   # (repo, digest) -> bytes
        self.registered = set()   # (repo, digest) resolvable by digest
        self.tags = {}        # (repo, tag) -> digest  (mutable pointer)
        self.referrers = {}   # (repo, subject_digest) -> [manifest_digest]

    # -- client protocol (the seam gov.evidence_distribute depends on) --
    def push_blob(self, repo, data, media_type):
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[(repo, digest)] = data
        return digest

    def put_manifest(self, repo, manifest_bytes, tag=None):
        if isinstance(manifest_bytes, dict):
            manifest_bytes = json.dumps(
                manifest_bytes, sort_keys=True).encode()
        digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        self.manifests[(repo, digest)] = manifest_bytes
        # Digest-PUT always registers digest resolvability (the spike's
        # proven mitigation for the tag-index quirk).
        self.registered.add((repo, digest))
        # Real registries index referrers server-side: a pushed manifest
        # carrying a subject link becomes discoverable through the
        # referrers API. Mirror that -- the module's attach path relies
        # on put_manifest alone, never on a client-side link call.
        try:
            _m = json.loads(manifest_bytes.decode("utf-8"))
        except Exception:
            _m = {}
        _subj = _m.get("subject") or {}
        if isinstance(_subj, dict) and _subj.get("digest"):
            self.referrers.setdefault(
                (repo, _subj["digest"]), []).append(digest)
        if tag is not None:
            old = self.tags.get((repo, tag))
            self.tags[(repo, tag)] = digest
            if old is not None and old != digest:
                # zot quirk: a manifest that loses its tag becomes
                # unresolvable by digest even though bytes linger.
                self.registered.discard((repo, old))
        return digest

    @staticmethod
    def _ref_to_key(ref):
        # The client protocol is string-keyed; the product seams pass
        # DigestRef. The fake converts explicitly, like a real adapter.
        if _DigestRef is not None and isinstance(ref, _DigestRef):
            return ref.digest
        return ref

    def get_manifest(self, repo, reference):
        reference = self._ref_to_key(reference)
        if not reference.startswith("sha256:"):
            reference = self.resolve_tag(repo, reference)
        if (repo, reference) not in self.registered:
            raise RegistryError("manifest unknown: %s" % reference)
        raw = self.manifests[(repo, reference)]
        return json.loads(raw.decode("utf-8")), reference

    def pull_blob(self, repo, digest):
        digest = self._ref_to_key(digest)
        try:
            return self.blobs[(repo, digest)]
        except KeyError:
            raise RegistryError("blob unknown: %s" % digest)

    def list_referrers(self, repo, digest):
        digest = self._ref_to_key(digest)
        out = []
        for md in self.referrers.get((repo, digest), []):
            m, _ = self.get_manifest(repo, md)
            out.append({
                "mediaType": m.get("mediaType"),
                "artifactType": m.get("artifactType"),
                "digest": md,
                "size": len(self.manifests[(repo, md)]),
                "annotations": m.get("annotations", {}),
            })
        return out

    def resolve_tag(self, repo, tag):
        try:
            return self.tags[(repo, tag)]
        except KeyError:
            raise RegistryError("tag unknown: %s" % tag)

    # -- attacker affordances --
    def strip_referrers(self, repo, digest):
        digest = self._ref_to_key(digest)
        for md in self.referrers.pop((repo, digest), []):
            self.manifests.pop((repo, md), None)
            self.registered.discard((repo, md))

    def tamper_blob(self, repo, digest, data):
        """Lying registry: serve attacker bytes for a pinned digest."""
        digest = self._ref_to_key(digest)
        self.blobs[(repo, digest)] = data


# --------------------------------------------------------------------------
# Fixture: one genuine bundle via the repo's own builder.
# --------------------------------------------------------------------------
def build_bundle(workdir, run_tag):
    """Build a deterministic synthetic evidence bundle.

    Hermetic per (workdir, run_tag): gov.log's checkpoint sidecar
    (checkpoints.jsonl) is per-directory, so every build gets its own
    subdirectory -- otherwise two logs' pins share one sidecar and
    verify_chain fails closed on the other log's max-seq pin ("tail
    truncation")."""
    restore = _scrub_env()
    try:
        rundir = os.path.join(workdir, "bb-" + run_tag)
        os.makedirs(rundir, exist_ok=True)
        log_path = os.path.join(rundir, "audit-%s.log" % run_tag)
        log = ActionLog(log_path, signer=OPERATOR,
                        deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True,
                    "policy_version": "1.0", "run": run_tag})
        log.append({"event": "approval_decision", "decision": "approve",
                    "ticket": "T-42-%s" % run_tag})
        for i in range(3):
            log.append({"event": "tool_call", "decision": "allow",
                        "tool": "tool-%d" % i, "run": run_tag})
        eb = EvidenceBundle(log_path,
                            exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="wave191-distribute-probe")
        payload = eb.build()
        manifest = eb.seal(payload, signer=OPERATOR)
        log_evidence_bundle_receipt(
            manifest,
            ActionLog(log_path, signer=OPERATOR,
                      deployment_mode="staging"),
            signer=OPERATOR)
        op = {"key_id": OPERATOR.key_id,
              "public_key_hex": OPERATOR_PUB_HEX}
        out = os.path.join(rundir, "bundle-%s" % run_tag)
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out, manifest
    finally:
        restore()


def deterministic_tar_bytes(bundle_dir):
    """Independent re-implementation of the packing rule (sorted names,
    zeroed mtime/uid/gid) -- the battery's spec for what push_bundle
    must produce byte-identically."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.PAX_FORMAT) as tf:
        for root, dirs, files in os.walk(bundle_dir):
            dirs.sort()
            files.sort()
            for f in files:
                p = os.path.join(root, f)
                arc = os.path.relpath(p, bundle_dir)
                ti = tf.gettarinfo(p, arcname=arc)
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                with open(p, "rb") as fh:
                    tf.addfile(ti, fh)
    return buf.getvalue()


def raw_push_bundle(fake, repo, bundle_dir, tag):
    """Setup-path push WITHOUT the module (also the naive push for D5):
    deterministic tar -> blob -> subject manifest -> tag."""
    tar_bytes = deterministic_tar_bytes(bundle_dir)
    tar_digest = fake.push_blob(repo, tar_bytes, MT_TAR)
    config = json.dumps({"bundle": "evidence-bundle/1.1"},
                        sort_keys=True).encode()
    config_digest = fake.push_blob(repo, config, MT_CONFIG)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": MT_CONFIG, "digest": config_digest,
                   "size": len(config)},
        "layers": [{"mediaType": MT_TAR, "digest": tar_digest,
                    "size": len(tar_bytes)}],
        "annotations": {"org.opencontainers.image.title":
                        "evidence-bundle"},
    }
    return fake.put_manifest(repo, manifest, tag=tag)


def raw_attach(fake, repo, subject_digest, blob_bytes, media_type,
               artifact_type, tag):
    blob_digest = fake.push_blob(repo, blob_bytes, media_type)
    config = json.dumps({"referrer": artifact_type},
                        sort_keys=True).encode()
    config_digest = fake.push_blob(repo, config, MT_CONFIG)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": artifact_type,
        "config": {"mediaType": MT_CONFIG, "digest": config_digest,
                   "size": len(config)},
        "layers": [{"mediaType": media_type, "digest": blob_digest,
                    "size": len(blob_bytes)}],
        "subject": {"mediaType":
                    "application/vnd.oci.image.manifest.v1+json",
                    "digest": subject_digest, "size": 0},
    }
    md = fake.put_manifest(repo, manifest, tag=tag)
    return md


def untar_to(blob_bytes, outdir):
    os.makedirs(outdir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob_bytes)) as tf:
        tf.extractall(outdir)


def naive_audit(fake, repo, tag=None, digest=None, outdir=None,
                operator_pub_hex=OPERATOR_PUB_HEX):
    """Today's workflow without the module: bare tag pull + standalone
    verifier. No pinning discipline, no referrer graph check, no
    byte-compare. Returns True when the auditor accepts."""
    ref = digest or fake.resolve_tag(repo, tag)
    manifest, _ = fake.get_manifest(repo, ref)
    blob = fake.pull_blob(repo, manifest["layers"][0]["digest"])
    untar_to(blob, outdir)
    code, _, _ = verify_bundle(outdir, pins=(operator_pub_hex,))
    return code == 0

# --------------------------------------------------------------------------
# Probes. Each returns True when the attack was STOPPED (HELD) and False
# when it succeeded (BREAK). Setup is identical on both trees; only the
# workflow under test differs (naive on pristine, module when present).
# --------------------------------------------------------------------------
def _ctx(workdir, run_tag):
    # Each probe run gets its OWN directory: gov.log's checkpoint
    # sidecar (checkpoints.jsonl) is per-directory, so sharing one
    # workdir across runs contaminates verify_chain with other runs'
    # pins (max-seq pin belongs to a different log -> "tail
    # truncation" fail-closed). Per-run dirs keep every fixture
    # hermetic.
    rundir = os.path.join(workdir, run_tag)
    os.makedirs(rundir, exist_ok=True)
    bundle_dir, _manifest = build_bundle(rundir, run_tag)
    return {
        "fake": FakeRegistry(),
        "repo": "sasanam/evidence",
        "bundle_dir": bundle_dir,
        "workdir": rundir,
        "run_tag": run_tag,
    }


def probe_d1_referrer_strip(c):
    """D1/R1: strip the signature referrer -> auditor must fail closed."""
    fake, repo, bundle_dir = c["fake"], c["repo"], c["bundle_dir"]
    subject = raw_push_bundle(fake, repo, bundle_dir, tag="evidence:d1")
    sig = json.dumps({"operator": "sig-envelope",
                      "run": c["run_tag"]}, sort_keys=True).encode()
    raw_attach(fake, repo, subject, sig, MT_SIG, AT_SIG,
               tag="signature:d1")
    fake.strip_referrers(repo, subject)  # the attack
    outdir = os.path.join(c["workdir"], "out-d1")
    if HAVE_MODULE:
        try:
            _ed.audit_bundle(fake, repo,
                             ref=_DigestRef.from_hex(subject),
                             outdir=outdir,
                             operator_pins=(OPERATOR_PUB_HEX,))
        except _ed.DistributionError:
            return True
        return False
    return not naive_audit(fake, repo, digest=subject, outdir=outdir)


def probe_d2_lying_registry(c):
    """D2/R2: registry serves wrong bytes for the pinned digest -> the
    pin must be enforced by byte-compare, not by trusting the server."""
    fake, repo, bundle_dir = c["fake"], c["repo"], c["bundle_dir"]
    subject = raw_push_bundle(fake, repo, bundle_dir, tag="evidence:d2")
    other_dir, _ = build_bundle(c["workdir"], c["run_tag"] + "-other")
    other_tar = deterministic_tar_bytes(other_dir)
    manifest, _ = fake.get_manifest(repo, subject)
    tar_digest = manifest["layers"][0]["digest"]
    fake.tamper_blob(repo, tar_digest, other_tar)  # the attack
    outdir = os.path.join(c["workdir"], "out-d2")
    if HAVE_MODULE:
        try:
            _ed.pull_bundle(fake, repo,
                              _DigestRef.from_hex(subject), outdir)
        except _ed.DistributionError:
            return True
        return False
    return not naive_audit(fake, repo, digest=subject, outdir=outdir)


def probe_d3_tag_collision(c):
    """D3/R3: second bundle pushed to the same tag -> the pinned digest
    must survive; the auditor must never silently switch bundles."""
    fake, repo, bundle_dir = c["fake"], c["repo"], c["bundle_dir"]
    tag = "evidence:shared"
    subject_a = raw_push_bundle(fake, repo, bundle_dir, tag=tag)
    pinned = _DigestRef.from_hex(subject_a)  # auditor pins here
    other_dir, _ = build_bundle(c["workdir"], c["run_tag"] + "-b")
    raw_push_bundle(fake, repo, other_dir, tag=tag)  # the attack
    outdir = os.path.join(c["workdir"], "out-d3")
    if HAVE_MODULE:
        try:
            _ed.pull_bundle(fake, repo, pinned, outdir)
        except _ed.DistributionError:
            return True  # fail-closed on the unregistered digest
        # If it pulled, the bytes must be bundle A's, not B's.
        got = deterministic_tar_bytes(outdir)
        want = deterministic_tar_bytes(bundle_dir)
        return got == want
    # Naive: re-resolves the tag -> silently pulls bundle B.
    ok = naive_audit(fake, repo, tag=tag, outdir=outdir)
    got = deterministic_tar_bytes(outdir)
    want = deterministic_tar_bytes(bundle_dir)
    return not (ok and got != want)


def probe_d4_tag_toctou(c):
    """D4/R4: tag moves between resolve and pull -> resolve once, pin,
    never re-resolve mid-audit."""
    fake, repo, bundle_dir = c["fake"], c["repo"], c["bundle_dir"]
    tag = "evidence:race"
    subject_a = raw_push_bundle(fake, repo, bundle_dir, tag=tag)
    outdir = os.path.join(c["workdir"], "out-d4")
    if HAVE_MODULE:
        pinned = _ed.resolve_and_pin(fake, repo, tag)
        assert pinned.digest == subject_a
        other_dir, _ = build_bundle(c["workdir"], c["run_tag"] + "-b")
        raw_push_bundle(fake, repo, other_dir, tag=tag)  # the attack
        try:
            _ed.pull_bundle(fake, repo, pinned, outdir)
        except _ed.DistributionError:
            return True  # fail-closed beats silent bundle switch
        got = deterministic_tar_bytes(outdir)
        return got == deterministic_tar_bytes(bundle_dir)
    # Naive: resolves at pull time -> gets the attacker's bundle.
    other_dir, _ = build_bundle(c["workdir"], c["run_tag"] + "-b")
    raw_push_bundle(fake, repo, other_dir, tag=tag)  # the attack
    ok = naive_audit(fake, repo, tag=tag, outdir=outdir)
    got = deterministic_tar_bytes(outdir)
    return not (ok and got != deterministic_tar_bytes(bundle_dir))


def probe_d5_tag_clobber(c):
    """D5: push over an existing tag bound to a different digest ->
    refuse loudly, never silently overwrite."""
    fake, repo, bundle_dir = c["fake"], c["repo"], c["bundle_dir"]
    tag = "evidence:clobber"
    subject_a = raw_push_bundle(fake, repo, bundle_dir, tag=tag)
    other_dir, _ = build_bundle(c["workdir"], c["run_tag"] + "-b")
    if HAVE_MODULE:
        try:
            _ed.push_bundle(other_dir, fake, repo, tag=tag)
        except _ed.DistributionError:
            # Refused: and the original binding must be untouched.
            return fake.resolve_tag(repo, tag) == subject_a
        return False
    # Naive/raw: the overwrite happens silently.
    raw_push_bundle(fake, repo, other_dir, tag=tag)
    return fake.resolve_tag(repo, tag) == subject_a  # False -> BREAK


PROBES = [
    ("D1", "referrer strip -> auditor fails closed", probe_d1_referrer_strip),
    ("D2", "lying registry -> byte-compare fails closed",
     probe_d2_lying_registry),
    ("D3", "tag collision -> pinned digest survives", probe_d3_tag_collision),
    ("D4", "tag TOCTOU -> resolve once, never re-resolve",
     probe_d4_tag_toctou),
    ("D5", "tag clobber -> push refuses overwrite", probe_d5_tag_clobber),
]


def main():
    workdir = tempfile.mkdtemp(prefix="dist-probes-")
    results = []
    errors = 0
    try:
        for pid, name, fn in PROBES:
            verdicts = []
            for run in (1, 2):
                try:
                    c = _ctx(workdir, "%s-r%d" % (pid.lower(), run))
                    held = fn(c)
                except Exception as e:  # noqa: BLE001 -- harness error
                    print("%s %s: ERROR %r" % (pid, name, e))
                    errors += 1
                    verdicts.append("ERROR")
                    continue
                verdicts.append("HELD" if held else "BREAK")
            if len(set(verdicts)) != 1:
                print("%s %s: ERROR nondeterministic %r"
                      % (pid, name, verdicts))
                errors += 1
                results.append((pid, name, "ERROR"))
            else:
                print("%s %s: %s" % (pid, name, verdicts[0]))
                results.append((pid, name, verdicts[0]))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    n_break = sum(1 for _, _, v in results if v == "BREAK")
    n_held = sum(1 for _, _, v in results if v == "HELD")
    print("---")
    print("probes: %d BREAK / %d HELD / %d errors "
          "(module present: %s)" % (n_break, n_held, errors, HAVE_MODULE))
    return 0 if errors == 0 else 1


def _green_check():
    """Depth-1 green check: the new unit suite only (never nested battery
    mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    suite = "tests.test_evidence_distribute"
    suite_path = os.path.join(REPO, "tests", "test_evidence_distribute.py")
    if not HAVE_MODULE or not os.path.isfile(suite_path):
        print("GREEN CHECK: skipped (module/test suite absent)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", suite, "-v"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                        " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
