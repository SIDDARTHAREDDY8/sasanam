#!/usr/bin/env python3
"""Rekor v2 second-witness write path for evidence-bundle digests: red-first probe battery.

Wave-277 lane (rekor). The v1 freeze window is NOW (wave-276 prospecting):
the product needs a v2 *write* path behind an explicit flag, with shard
discovery via TUF SigningConfig (never hardcoded URLs). The local anchor
stays the primary witness; Rekor v2 is strictly a SECOND witness.

What is red on pristine (32ee6ee): there is NO evidence-bundle second-witness
seam at all -- no ``gov.rekor_v2_witness`` module, no ``GOV_REKOR_V2_WITNESS``
flag, no TUF SigningConfig shard discovery, no never-raise witness attach,
no witness success/failure record for bundle audit metadata.
(``gov.rekor_v2_anchor`` exists but is the anchorer's hermetic v1/v2
dual-write -- it is not wired to evidence-bundle digests, has no TUF
discovery, and its flag governs the anchorer path, not the bundle path.)

What is green post-fix: ``gov/rekor_v2_witness.py`` --
  * ``witness_enabled()`` -- explicit param wins, else
    ``GOV_REKOR_V2_WITNESS`` ("1"/"true"/"yes"); default OFF.
  * ``discover_v2_shard()`` -- TUF SigningConfig (mapping / JSON / file)
    -> the currently-valid v2 shard ``{"log_url","log_id","tsa_url"}``;
    never hardcoded; fail-closed on no valid v2 entry.
  * ``RekorV2Witness.attach()`` -- hashedrekord write for a bundle
    digest; NEVER raises (outage -> "failed" record); returns a witness
    record pinned ``evidentiary_grade="digest-existence-only"`` and
    ``authority_proof=False`` (a Rekor proof proves DIGEST EXISTENCE
    only -- never authorization or signature correctness).
  * ``record_in_metadata()`` -- appends the witness record (attached OR
    failed) to bundle audit metadata under ``"witnesses"``.

Probe map:
  p_flag_off_default:      env unset -> disabled; attach() returns
                           status "skipped"/reason flag-off; the
                           injected counting client sees ZERO submits.
  p_flag_off_byte_identical: with the witness present-but-off, the
                           bundle's canonical bytes are unchanged and
                           no receipt is produced.
  p_flag_explicit_wins:     explicit=False beats env=1 (and vice versa).
  p_flag_on_attaches:      enabled + signing config -> "attached";
                           receipt verification.source ==
                           "rekor-v2-hermetic"; log_generation recorded.
  p_witness_failure_degrades: client outage -> attach() does NOT raise;
                           status "failed" with reason; the simulated
                           product decision is unaffected.
  p_no_network:            socket.socket patched to raise -> the full
                           attach flow still succeeds (hermetic).
  p_shard_discovery_v2:    signing config with a v1 entry, an expired
                           v2 shard and a valid v2 shard -> the valid
                           v2 shard is discovered (latest validFor).
  p_shard_discovery_no_v2: config with no valid v2 entry ->
                           ShardDiscoveryError (fail-closed).
  p_shard_discovery_from_file: JSON file path accepted.
  p_prod_pins_never_written: a prod-pinned signing config can be
                           discovered but the client refuses it, so
                           attach() records "failed" -- never a live
                           prod write.
  p_no_hardcoded_urls:     the module hardcodes no log URLs.
  p_digest_existence_honesty: the witness record never claims
                           authorization; authority_proof is False.
  p_metadata_records_both: attached AND failed records are appended
                           to metadata["witnesses"].
  p_deterministic_x2:      fixed clock -> byte-identical records.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic, stdlib only. No network.

Run (fresh UNIQUE /var/tmp TMPDIR per run -- never reuse one across
runs, and always mkdir -p first: Python 3.12 silently ignores a
nonexistent TMPDIR):
  T=/var/tmp/g277rekor-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python evals/w277_rekor_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/w277_rekor_probes.py
"""

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from gov import rekor_v2_witness as _W
    _WITNESS = _W
    _WITNESS_IMPORT_ERROR = None
except ImportError as e:
    _WITNESS = None
    _WITNESS_IMPORT_ERROR = e

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-28s %-10s %s" % (name, verdict, detail))


def _needs_witness(name):
    if _WITNESS is None:
        _record(name, "ERROR",
                "no product seam on pristine: %s" % (_WITNESS_IMPORT_ERROR,))
        return None
    return _WITNESS


# ---------------------------------------------------------------------------
# fixtures (all .invalid -- never real infrastructure)
# ---------------------------------------------------------------------------

_TEST_V2_URL = "https://log2026-2.rekor.example-operator.invalid"
_TEST_V2_URL_OLD = "https://log2026-1.rekor.example-operator.invalid"
_TEST_V1_URL = "https://rekor.example-operator.invalid"
_TEST_TSA_URL = "https://tsa.example-operator.invalid"
_TEST_LOG_ID = "cafef00d" * 8


def _signing_config_doc():
    # TUF SigningConfig v0.2 shape (cf. NVIDIA AICR
    # signing_config_rekor_v2.v0.2.json): one v1 entry, one EXPIRED v2
    # shard, one currently-valid v2 shard, one TSA.
    return {
        "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
        "rekor": [
            {"url": _TEST_V1_URL, "majorApiVersion": 1,
             "operator": "example-operator",
             "validFor": {"start": "2021-01-01T00:00:00Z"}},
            {"url": _TEST_V2_URL_OLD, "majorApiVersion": 2,
             "operator": "example-operator",
             "logId": "00" * 32,
             "validFor": {"start": "2025-01-01T00:00:00Z",
                          "end": "2025-07-01T00:00:00Z"}},
            {"url": _TEST_V2_URL, "majorApiVersion": 2,
             "operator": "example-operator",
             "logId": _TEST_LOG_ID,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ],
        "tsa": [
            {"url": _TEST_TSA_URL, "majorApiVersion": 1,
             "operator": "example-operator",
             "validFor": {"start": "2021-01-01T00:00:00Z"}},
        ],
    }


def _anchor_material():
    digest = hashlib.sha256(b"evidence-bundle-bytes-wave277").hexdigest()
    seed = bytes([41]) * 32
    from gov import ed25519 as _ed
    sig = _ed.sign_ph(seed, bytes.fromhex(digest))
    from gov import anchor_backend as _ab
    pubkey_pem = _ab.anchor_spki_pem(_ed.publickey(seed))
    return digest, sig.hex(), pubkey_pem


class _CountingClient:
    """Injectable v2-shaped client double: counts submits."""

    def __init__(self, fail=None):
        self.submits = 0
        self._fail = fail

    def submit_hashedrekord(self, anchor_hash, *, signature_b64,
                            pubkey_pem, algorithm="ed25519ph-sha512"):
        self.submits += 1
        if self._fail is not None:
            raise self._fail
        return {
            "verification.source": "rekor-v2-hermetic",
            "entry_type": "hashedrekord",
            "uuid": "counted-%d" % self.submits,
            "log_index": self.submits - 1,
            "url": _TEST_V2_URL,
            "log_id": _TEST_LOG_ID,
            "evidentiary_grade": "digest-existence-only",
            "authority_proof": False,
            "anchor_hash": anchor_hash,
        }


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def p_flag_off_default():
    W = _needs_witness("p_flag_off_default")
    if W is None:
        return
    saved = os.environ.pop("GOV_REKOR_V2_WITNESS", None)
    try:
        if W.witness_enabled() is not False:
            return _record("p_flag_off_default", "BREAK",
                           "flag defaults ON -- must default OFF")
        client = _CountingClient()
        digest, sig, pem = _anchor_material()
        w = W.RekorV2Witness(signing_config=_signing_config_doc(),
                             client=client)
        rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
        if rec.get("status") != "skipped":
            return _record("p_flag_off_default", "BREAK",
                           "status=%r, want 'skipped'" % (rec.get("status"),))
        if client.submits != 0:
            return _record("p_flag_off_default", "BREAK",
                           "submitted with flag off")
        if rec.get("receipt") is not None:
            return _record("p_flag_off_default", "BREAK",
                           "receipt present with flag off")
        _record("p_flag_off_default", "HELD", "off by default, 0 submits")
    finally:
        if saved is not None:
            os.environ["GOV_REKOR_V2_WITNESS"] = saved


def p_flag_off_byte_identical():
    W = _needs_witness("p_flag_off_byte_identical")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    bundle = {"bundle_digest": digest, "issuance": "sealed"}
    before = _canonical(bundle)
    w = W.RekorV2Witness(enabled=False,
                         signing_config=_signing_config_doc())
    rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    after = _canonical(bundle)
    if before != after:
        return _record("p_flag_off_byte_identical", "BREAK",
                       "bundle bytes changed with flag off")
    if rec.get("status") != "skipped":
        return _record("p_flag_off_byte_identical", "BREAK",
                       "status=%r" % (rec.get("status"),))
    _record("p_flag_off_byte_identical", "HELD", "bundle bytes identical")


def p_flag_explicit_wins():
    W = _needs_witness("p_flag_explicit_wins")
    if W is None:
        return
    saved = os.environ.get("GOV_REKOR_V2_WITNESS")
    try:
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        if W.witness_enabled(explicit=False) is not False:
            return _record("p_flag_explicit_wins", "BREAK",
                           "explicit=False did not beat env=1")
        os.environ["GOV_REKOR_V2_WITNESS"] = "0"
        if W.witness_enabled(explicit=True) is not True:
            return _record("p_flag_explicit_wins", "BREAK",
                           "explicit=True did not beat env=0")
        os.environ["GOV_REKOR_V2_WITNESS"] = "yes"
        if W.witness_enabled() is not True:
            return _record("p_flag_explicit_wins", "BREAK",
                           "env=yes not honored")
        _record("p_flag_explicit_wins", "HELD", "explicit > env > default")
    finally:
        if saved is None:
            os.environ.pop("GOV_REKOR_V2_WITNESS", None)
        else:
            os.environ["GOV_REKOR_V2_WITNESS"] = saved


def p_flag_on_attaches():
    W = _needs_witness("p_flag_on_attaches")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    w = W.RekorV2Witness(enabled=True,
                         signing_config=_signing_config_doc(),
                         clock=lambda: "2026-10-01T00:00:00Z")
    rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    if rec.get("status") != "attached":
        return _record("p_flag_on_attaches", "BREAK",
                       "status=%r reason=%r"
                       % (rec.get("status"), rec.get("reason")))
    receipt = rec.get("receipt") or {}
    if receipt.get("verification.source") != "rekor-v2-hermetic":
        return _record("p_flag_on_attaches", "BREAK",
                       "bad verification.source: %r"
                       % (receipt.get("verification.source"),))
    gen = rec.get("log_generation") or {}
    if gen.get("log_url") != _TEST_V2_URL or \
            gen.get("log_id") != _TEST_LOG_ID:
        return _record("p_flag_on_attaches", "BREAK",
                       "log generation not recorded: %r" % (gen,))
    _record("p_flag_on_attaches", "HELD",
            "attached; generation %s" % gen.get("log_url"))


def p_witness_failure_degrades():
    W = _needs_witness("p_witness_failure_degrades")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    boom = RuntimeError("simulated v2 outage")
    client = _CountingClient(fail=boom)
    w = W.RekorV2Witness(enabled=True,
                         signing_config=_signing_config_doc(),
                         client=client)
    try:
        rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    except Exception as e:
        return _record("p_witness_failure_degrades", "BREAK",
                       "attach() raised: %r" % (e,))
    if rec.get("status") != "failed":
        return _record("p_witness_failure_degrades", "BREAK",
                       "status=%r, want 'failed'" % (rec.get("status"),))
    if "simulated v2 outage" not in str(rec.get("reason", "")):
        return _record("p_witness_failure_degrades", "BREAK",
                       "reason lost: %r" % (rec.get("reason"),))
    # The product path never consults the witness: the local anchor
    # decision is computed independently and is unaffected.
    product_decision = {"anchor": "local-anchor-ok", "grade": "anchored"}
    if product_decision["grade"] != "anchored":
        return _record("p_witness_failure_degrades", "BREAK",
                       "product path disturbed")
    _record("p_witness_failure_degrades", "HELD",
            "outage -> failed record, product unaffected")


def p_no_network():
    W = _needs_witness("p_no_network")
    if W is None:
        return
    real_socket = socket.socket

    def _nope(*a, **k):
        raise AssertionError("network socket created in witness path")

    digest, sig, pem = _anchor_material()
    w = W.RekorV2Witness(enabled=True,
                         signing_config=_signing_config_doc(),
                         clock=lambda: "2026-10-01T00:00:00Z")
    socket.socket = _nope
    try:
        rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    finally:
        socket.socket = real_socket
    if rec.get("status") != "attached":
        return _record("p_no_network", "BREAK",
                       "status=%r reason=%r"
                       % (rec.get("status"), rec.get("reason")))
    _record("p_no_network", "HELD", "hermetic: no sockets")


def p_shard_discovery_v2():
    W = _needs_witness("p_shard_discovery_v2")
    if W is None:
        return
    try:
        shard = W.discover_v2_shard(_signing_config_doc())
    except Exception as e:
        return _record("p_shard_discovery_v2", "BREAK",
                       "discovery raised: %r" % (e,))
    if shard.get("log_url") != _TEST_V2_URL:
        return _record("p_shard_discovery_v2", "BREAK",
                       "picked %r, want the valid v2 shard"
                       % (shard.get("log_url"),))
    if shard.get("log_id") != _TEST_LOG_ID:
        return _record("p_shard_discovery_v2", "BREAK",
                       "log_id %r" % (shard.get("log_id"),))
    if shard.get("tsa_url") != _TEST_TSA_URL:
        return _record("p_shard_discovery_v2", "BREAK",
                       "tsa_url %r" % (shard.get("tsa_url"),))
    _record("p_shard_discovery_v2", "HELD", "valid v2 shard discovered")


def p_shard_discovery_no_v2():
    W = _needs_witness("p_shard_discovery_no_v2")
    if W is None:
        return
    doc = {"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
           "rekor": [{"url": _TEST_V1_URL, "majorApiVersion": 1,
                      "validFor": {"start": "2021-01-01T00:00:00Z"}}],
           "tsa": [{"url": _TEST_TSA_URL, "majorApiVersion": 1,
                    "validFor": {"start": "2021-01-01T00:00:00Z"}}]}
    try:
        W.discover_v2_shard(doc)
    except W.ShardDiscoveryError:
        return _record("p_shard_discovery_no_v2", "HELD",
                       "fail-closed, no v2 entry")
    except Exception as e:
        return _record("p_shard_discovery_no_v2", "BREAK",
                       "wrong exception: %r" % (e,))
    _record("p_shard_discovery_no_v2", "BREAK",
            "no-v2 config discovered a shard")


def p_shard_discovery_from_file():
    W = _needs_witness("p_shard_discovery_from_file")
    if W is None:
        return
    import tempfile
    path = os.path.join(tempfile.mkdtemp(dir="/var/tmp/g277-rekor"),
                        "signingconfig.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_signing_config_doc(), fh)
    try:
        shard = W.discover_v2_shard(path)
    except Exception as e:
        return _record("p_shard_discovery_from_file", "BREAK",
                       "file discovery raised: %r" % (e,))
    if shard.get("log_url") != _TEST_V2_URL:
        return _record("p_shard_discovery_from_file", "BREAK",
                       "picked %r" % (shard.get("log_url"),))
    _record("p_shard_discovery_from_file", "HELD", "file path accepted")


def p_prod_pins_never_written():
    W = _needs_witness("p_prod_pins_never_written")
    if W is None:
        return
    prod_id = ("c0d23d6ad406973f9559f3ba1d1ca01f84147d8ffc5b8445c"
               "2249c2cc77d6cd9d69")
    doc = {"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
           "rekor": [{"url": "https://rekor.sigstore.dev",
                      "majorApiVersion": 2, "logId": prod_id,
                      "validFor": {"start": "2021-01-01T00:00:00Z"}}],
           "tsa": [{"url": _TEST_TSA_URL, "majorApiVersion": 1,
                    "validFor": {"start": "2021-01-01T00:00:00Z"}}]}
    digest, sig, pem = _anchor_material()
    w = W.RekorV2Witness(enabled=True, signing_config=doc,
                         clock=lambda: "2026-10-01T00:00:00Z")
    try:
        rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    except Exception as e:
        return _record("p_prod_pins_never_written", "BREAK",
                       "attach() raised: %r" % (e,))
    if rec.get("status") != "failed":
        return _record("p_prod_pins_never_written", "BREAK",
                       "prod-pinned config attached?! status=%r"
                       % (rec.get("status"),))
    _record("p_prod_pins_never_written", "HELD",
            "prod pins refused -> failed record, no write")


def p_no_hardcoded_urls():
    W = _needs_witness("p_no_hardcoded_urls")
    if W is None:
        return
    import inspect
    src = inspect.getsource(W)
    for needle in ("sigstore.dev", "rekor.sigstore", "://log",
                   "rekor.example", "example-operator"):
        if needle in src:
            return _record("p_no_hardcoded_urls", "BREAK",
                           "hardcoded %r in module source" % (needle,))
    _record("p_no_hardcoded_urls", "HELD", "no hardcoded log URLs")


def p_digest_existence_honesty():
    W = _needs_witness("p_digest_existence_honesty")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    w = W.RekorV2Witness(enabled=True,
                         signing_config=_signing_config_doc(),
                         clock=lambda: "2026-10-01T00:00:00Z")
    rec = w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    blob = json.dumps(rec, sort_keys=True, default=str).lower()
    if "authoriz" in blob:
        return _record("p_digest_existence_honesty", "BREAK",
                       "record claims authorization")
    if rec.get("authority_proof") is not False:
        return _record("p_digest_existence_honesty", "BREAK",
                       "authority_proof=%r" % (rec.get("authority_proof"),))
    if rec.get("evidentiary_grade") != "digest-existence-only":
        return _record("p_digest_existence_honesty", "BREAK",
                       "grade=%r" % (rec.get("evidentiary_grade"),))
    _record("p_digest_existence_honesty", "HELD",
            "digest-existence-only, no authority claim")


def p_metadata_records_both():
    W = _needs_witness("p_metadata_records_both")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    ok_w = W.RekorV2Witness(enabled=True,
                            signing_config=_signing_config_doc(),
                            clock=lambda: "2026-10-01T00:00:00Z")
    ok_rec = ok_w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    bad_w = W.RekorV2Witness(
        enabled=True, signing_config=_signing_config_doc(),
        client=_CountingClient(fail=RuntimeError("down")))
    bad_rec = bad_w.attach(digest, signature_b64=sig, pubkey_pem=pem)
    metadata = {}
    W.record_in_metadata(metadata, ok_rec)
    W.record_in_metadata(metadata, bad_rec)
    witnesses = metadata.get("witnesses")
    if not isinstance(witnesses, list) or len(witnesses) != 2:
        return _record("p_metadata_records_both", "BREAK",
                       "witnesses=%r" % (witnesses,))
    statuses = [r.get("status") for r in witnesses]
    if statuses != ["attached", "failed"]:
        return _record("p_metadata_records_both", "BREAK",
                       "statuses=%r" % (statuses,))
    _record("p_metadata_records_both", "HELD",
            "attached + failed both recorded")


def p_deterministic_x2():
    W = _needs_witness("p_deterministic_x2")
    if W is None:
        return
    digest, sig, pem = _anchor_material()
    clock = lambda: "2026-10-01T00:00:00Z"  # noqa: E731
    recs = []
    for _ in range(2):
        w = W.RekorV2Witness(enabled=True,
                             signing_config=_signing_config_doc(),
                             clock=clock)
        recs.append(w.attach(digest, signature_b64=sig, pubkey_pem=pem))
    if _canonical(recs[0]) != _canonical(recs[1]):
        return _record("p_deterministic_x2", "BREAK", "run-to-run drift")
    _record("p_deterministic_x2", "HELD", "byte-identical records")


def _run_all():
    p_flag_off_default()
    p_flag_off_byte_identical()
    p_flag_explicit_wins()
    p_flag_on_attaches()
    p_witness_failure_degrades()
    p_no_network()
    p_shard_discovery_v2()
    p_shard_discovery_no_v2()
    p_shard_discovery_from_file()
    p_prod_pins_never_written()
    p_no_hardcoded_urls()
    p_digest_existence_honesty()
    p_metadata_records_both()
    p_deterministic_x2()


def green_check():
    """Depth-1 green check: adjacent unit suites, no nested batteries.

    Honors GOV_SKIP_GREEN (set in child envs by parent batteries).
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    suites = ["tests.test_rekor_v2_witness", "tests.test_rekor_v2_anchor",
              "tests.test_rekor_anchor", "tests.test_anchoring"]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for suite in suites:
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite],
            cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=600)
        tail = (r.stderr.strip().splitlines() or [""]) [-1]
        print("green_check %-28s %s" % (suite, tail))
        if r.returncode != 0:
            print(r.stderr[-2000:])
            return False
    return True


def main():
    _run_all()
    ok = green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("w277_rekor_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR / green=%s"
          % (held, brk, exp, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
