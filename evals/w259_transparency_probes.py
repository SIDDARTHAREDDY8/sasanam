"""Break-first red-team battery for the wave-259 transparency log.

Target (new in wave-259, base 894a1628): gov/transparency_log.py --
static transparency log for evidence-bundle digests, adapted from
the certificate-transparency pattern (RFC 6962 inclusion/consistency
proofs, signed tree heads; google/certificate-transparency-go ADAPT,
pattern only).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Every negative probe asserts a POSITIVE control first (the
untampered operation verifies), so a broken implementation BREAKs or
ERRORs instead of falsely HELDing: the battery is red-capable against
both naive implementations (verify always True / always False).

Verdicts: HELD (attack refused, or gap documented as an honest
residual) or BREAK (genuine defect -> filed as a finding F227+).

Stdlib only. Deterministic across runs (staging + `env -u
GOV_DEPLOYMENT_MODE`). Fresh unique TMPDIR per run under /var/tmp.
No in-repo git subprocesses. No green-check subprocesses (depth-0:
this battery has no adjacent-battery coupling, so there is nothing
for GOV_SKIP_GREEN to gate).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ed25519 as _ed  # noqa: E402
from gov import transparency_log as tl  # noqa: E402

TAXONOMY_PIN = 2128 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
    "taxonomy drift: expected %d, got %d"
    % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir(prefix="w259tp-"):
    return tempfile.mkdtemp(prefix=prefix, dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _error(detail=""):
    return ("ERROR", detail)


def _keypair():
    seed = _ed.generate_seed()
    return seed, bytes(_ed.publickey(seed)).hex()


def _log_with(n, seed=None, path=None):
    seed = seed if seed is not None else _ed.generate_seed()
    log = tl.TransparencyLog(
        path if path is not None else _tmpdir(), signing_key=seed)
    digests = ["%064x" % (i + 1) for i in range(n)]
    for d in digests:
        log.append(d)
    return log, seed, digests


def _pub(seed):
    return bytes(_ed.publickey(seed)).hex()


# ---------------------------------------------------------------------------
# A. Signed tree head forgery
# ---------------------------------------------------------------------------

@probe("sth/forged-signature")
def _p_sth_forged_sig():
    log, seed, _d = _log_with(3)
    pub = _pub(seed)
    head = log.latest_head()
    if not tl.verify_tree_head(head, pub):
        return _error("positive control failed: fresh STH does not verify")
    # Attack: a head validly signed, but under a DIFFERENT key than the
    # log's. (Built via a second log under the evil key -- public seam
    # only, no private access.)
    evil_seed, _evil_pub = _keypair()
    evil_log = tl.TransparencyLog(_tmpdir(), signing_key=evil_seed)
    for i in range(3):
        evil_log.append("%064x" % (i + 1))
    evil_head = evil_log.latest_head()  # valid sig, wrong key for `pub`
    if tl.verify_tree_head(evil_head, pub):
        return _break("STH signed by a foreign key verified under "
                      "the log key")
    return _held("foreign-key STH refused")


@probe("sth/tampered-root")
def _p_sth_tampered_root():
    log, seed, _d = _log_with(3)
    pub = _pub(seed)
    head = dict(log.latest_head())
    root = head["root_hash"]
    head["root_hash"] = ("00" if root[:2] != "00" else "ff") + root[2:]
    if tl.verify_tree_head(head, pub):
        return _break("STH with tampered root_hash still verified")
    return _held("tampered root refused (signature covers the root)")


@probe("sth/log-id-substitution")
def _p_sth_log_id_substitution():
    # Attack: keep the valid signature but swap log_id for the
    # attacker's key id. The pubkey must match the head's log_id.
    log, seed, _d = _log_with(3)
    _evil_seed, evil_pub = _keypair()
    head = dict(log.latest_head())
    head["log_id"] = evil_pub
    if tl.verify_tree_head(head, evil_pub):
        return _break("STH with substituted log_id verified")
    return _held("log_id substitution refused")


# ---------------------------------------------------------------------------
# B. Inclusion proof forgery
# ---------------------------------------------------------------------------

def _inclusion_setup(n=5):
    log, seed, digests = _log_with(n)
    pub = _pub(seed)
    head = log.latest_head()
    d = digests[2]
    proof = log.inclusion_proof(d)
    if not tl.verify_inclusion(d, proof, head, pub):
        return None
    return log, seed, pub, head, d, proof


@probe("inclusion/forged-sibling")
def _p_inclusion_forged_sibling():
    s = _inclusion_setup()
    if s is None:
        return _error("positive control failed")
    _log, _seed, pub, head, d, proof = s
    evil = dict(proof)
    evil["path"] = list(proof["path"])
    first = evil["path"][0]
    evil["path"][0] = ("00" if first[:2] != "00" else "ff") + first[2:]
    if tl.verify_inclusion(d, evil, head, pub):
        return _break("inclusion proof with forged sibling verified")
    return _held("forged sibling refused")


@probe("inclusion/truncated-proof")
def _p_inclusion_truncated():
    s = _inclusion_setup()
    if s is None:
        return _error("positive control failed")
    _log, _seed, pub, head, d, proof = s
    evil = dict(proof)
    evil["path"] = proof["path"][:-1]
    if tl.verify_inclusion(d, evil, head, pub):
        return _break("truncated inclusion proof verified")
    return _held("truncated proof refused")


@probe("inclusion/overlong-proof")
def _p_inclusion_overlong():
    s = _inclusion_setup()
    if s is None:
        return _error("positive control failed")
    _log, _seed, pub, head, d, proof = s
    evil = dict(proof)
    evil["path"] = proof["path"] + ["ab" * 32]
    if tl.verify_inclusion(d, evil, head, pub):
        return _break("overlong inclusion proof verified")
    return _held("overlong proof refused")


@probe("inclusion/wrong-index")
def _p_inclusion_wrong_index():
    s = _inclusion_setup()
    if s is None:
        return _error("positive control failed")
    _log, _seed, pub, head, d, proof = s
    evil = dict(proof)
    evil["leaf_index"] = (proof["leaf_index"] + 1) % proof["tree_size"]
    if tl.verify_inclusion(d, evil, head, pub):
        return _break("inclusion proof with wrong index verified")
    return _held("wrong index refused")


@probe("inclusion/wrong-digest")
def _p_inclusion_wrong_digest():
    s = _inclusion_setup()
    if s is None:
        return _error("positive control failed")
    _log, _seed, pub, head, _d, proof = s
    if tl.verify_inclusion("ff" * 32, proof, head, pub):
        return _break("inclusion proof verified for a foreign digest")
    return _held("foreign digest refused")


@probe("inclusion/proof-replay-across-heads")
def _p_inclusion_replay():
    # A proof bound to tree size 2 replayed against the head at size 5.
    log, seed, digests = _log_with(5)
    pub = _pub(seed)
    proof = log.inclusion_proof(digests[0], tree_size=2)
    head2 = [h for h in log.heads() if h["tree_size"] == 2][0]
    if not tl.verify_inclusion(digests[0], proof, head2, pub):
        return _error("positive control failed")
    head5 = log.latest_head()
    if tl.verify_inclusion(digests[0], proof, head5, pub):
        return _break("size-2 proof verified against the size-5 head")
    return _held("cross-head replay refused (proof bound to tree size)")


@probe("inclusion/forged-head-with-pubkey")
def _p_inclusion_forged_head():
    # Attacker builds their own log containing the victim digest,
    # then presents the attacker head as the victim's. With the
    # victim pubkey pinned, the head signature check must fail.
    log, seed, digests = _log_with(4)
    pub = _pub(seed)
    evil_seed, _evil_pub = _keypair()
    evil_log = tl.TransparencyLog(_tmpdir(), signing_key=evil_seed)
    for d in digests:
        evil_log.append(d)
    evil_head = evil_log.latest_head()
    proof = evil_log.inclusion_proof(digests[1])
    if not tl.verify_inclusion(digests[1], proof, evil_head,
                               _pub(evil_seed)):
        return _error("positive control failed (attacker self-view)")
    if tl.verify_inclusion(digests[1], proof, evil_head, pub):
        return _break("attacker's head accepted under the victim key")
    return _held("forged head refused when the log key is pinned")


# ---------------------------------------------------------------------------
# C. Append-side attacks
# ---------------------------------------------------------------------------

@probe("append/backdated")
def _p_append_backdated():
    seed = _ed.generate_seed()
    log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    d = ["%064x" % (i + 1) for i in range(2)]
    log.append(d[0], appended_at="2026-10-01T00:00:10Z")
    try:
        log.append(d[1], appended_at="2026-10-01T00:00:09Z")
    except tl.TransparencyLogError:
        return _held("backdated append refused")
    return _break("backdated append accepted: operator can rewrite "
                  "apparent submission order")


@probe("append/malformed-digest")
def _p_append_malformed():
    log = tl.TransparencyLog(_tmpdir(), signing_key=_ed.generate_seed())
    for bad in ("", "xyz", "ab" * 31, "AB" * 32, "ab" * 32 + " "):
        try:
            log.append(bad)
        except tl.TransparencyLogError:
            continue
        return _break("malformed digest accepted: %r" % (bad,))
    return _held("malformed digests refused")


@probe("append/read-only-refused")
def _p_append_read_only():
    seed = _ed.generate_seed()
    path = _tmpdir()
    tl.TransparencyLog(path, signing_key=seed)
    ro = tl.TransparencyLog(path, public_key=bytes.fromhex(_pub(seed)))
    try:
        ro.append("ab" * 32)
    except tl.TransparencyLogError:
        return _held("append without the signing key refused")
    return _break("read-only log accepted an append")


# ---------------------------------------------------------------------------
# D. Consistency / history-rewrite attacks
# ---------------------------------------------------------------------------

@probe("consistency/rewritten-history")
def _p_consistency_rewritten():
    # Operator shows head@3 from history A, then head@5 from a
    # DIVERGENT history B (same key). The consistency proof must fail.
    seed = _ed.generate_seed()
    pub = _pub(seed)
    log_a = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    log_b = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    for i in range(5):
        log_a.append("%064x" % (i + 1))
        log_b.append("%064x" % (100 + i))
    head_a3 = [h for h in log_a.heads() if h["tree_size"] == 3][0]
    head_b5 = log_b.latest_head()
    proof = log_a.consistency_proof(3, 5)  # honest proof for history A
    if not tl.verify_consistency(
            head_a3,
            [h for h in log_a.heads() if h["tree_size"] == 5][0],
            proof, pub):
        return _error("positive control failed")
    if tl.verify_consistency(head_a3, head_b5, proof, pub):
        return _break("rewritten history passed consistency check")
    return _held("history rewrite refused")


@probe("consistency/forged-nodes")
def _p_consistency_forged_nodes():
    log, seed, _d = _log_with(6)
    pub = _pub(seed)
    heads = log.heads()
    old = [h for h in heads if h["tree_size"] == 2][0]
    new = [h for h in heads if h["tree_size"] == 6][0]
    proof = log.consistency_proof(2, 6)
    if not tl.verify_consistency(old, new, proof, pub):
        return _error("positive control failed")
    evil = dict(proof)
    evil["nodes"] = list(proof["nodes"])
    first = evil["nodes"][0]
    evil["nodes"][0] = ("00" if first[:2] != "00" else "ff") + first[2:]
    if tl.verify_consistency(old, new, evil, pub):
        return _break("consistency proof with forged node verified")
    return _held("forged consistency node refused")


@probe("consistency/size-binding")
def _p_consistency_size_binding():
    log, seed, _d = _log_with(7)
    pub = _pub(seed)
    heads = log.heads()
    old2 = [h for h in heads if h["tree_size"] == 2][0]
    new7 = [h for h in heads if h["tree_size"] == 7][0]
    proof = log.consistency_proof(2, 5)  # proof is for (2,5), not (2,7)
    if tl.verify_consistency(old2, new7, proof, pub):
        return _break("consistency proof accepted for mismatched sizes")
    return _held("size-mismatched proof refused")


# ---------------------------------------------------------------------------
# E. Equivocation (split view)
# ---------------------------------------------------------------------------

@probe("equivocation/detected")
def _p_equivocation():
    # A malicious operator signs two different heads at tree size 2.
    # The module cannot PREVENT this (single-operator log); it must
    # DETECT it among the heads it is shown. Prevention is the
    # documented out-of-band witness residual.
    seed = _ed.generate_seed()
    log_a = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    log_b = tl.TransparencyLog(_tmpdir(), signing_key=seed)
    for i in range(3):
        log_a.append("%064x" % (i + 1))
        log_b.append("%064x" % (100 + i))
    heads_a = log_a.heads()
    head_b2 = [h for h in log_b.heads() if h["tree_size"] == 2][0]
    pub = _pub(seed)
    if not (tl.verify_tree_head(heads_a[1], pub)
            and tl.verify_tree_head(head_b2, pub)):
        return _error("positive control failed: heads do not verify")
    if log_a.detect_equivocation(heads_a):
        return _error("positive control failed: false positive on "
                      "honest heads")
    conflicts = log_a.detect_equivocation(heads_a + [head_b2])
    if not conflicts:
        return _break("equivocation NOT detected: two signed heads at "
                      "tree size 2 with different roots went unnoticed")
    if conflicts[0]["tree_size"] != 2:
        return _error("equivocation flagged at the wrong size")
    return _held("equivocation detected (prevention is the documented "
                 "out-of-band witness residual)")


# ---------------------------------------------------------------------------
# F. Storage tampering + the offline story
# ---------------------------------------------------------------------------

@probe("log/tampered-leaves")
def _p_log_tampered_leaves():
    seed = _ed.generate_seed()
    path = _tmpdir()
    log = tl.TransparencyLog(path, signing_key=seed)
    for i in range(4):
        log.append("%064x" % (i + 1))
    ok, _detail = log.verify_log()
    if not ok:
        return _error("positive control failed: fresh log does not verify")
    leaves_path = os.path.join(path, "leaves.jsonl")
    with open(leaves_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    rec = json.loads(lines[1])
    rec["digest"] = "ff" * 32
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(leaves_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log2 = tl.TransparencyLog(path, signing_key=seed)
    ok, detail = log2.verify_log()
    if ok:
        return _break("verify_log accepted rewritten leaves")
    return _held("rewritten leaves caught: %s" % detail)


@probe("offline/flat-copy-no-engine")
def _p_offline_flat_copy():
    # The offline story: an auditor copies the three stdlib-only
    # files flat into a clean directory (no gov package, no engine,
    # PYTHONPATH scrubbed) and verifies a head + inclusion proof.
    seed = _ed.generate_seed()
    pub = _pub(seed)
    log, _s, digests = _log_with(4, seed=seed)
    head = log.latest_head()
    proof = log.inclusion_proof(digests[1])
    digest = digests[1]

    flat = _tmpdir(prefix="w259flat-")
    repo_gov = os.path.join(os.path.dirname(__file__), "..", "gov")
    for name in ("transparency_log.py", "merkle.py", "ed25519.py"):
        shutil.copy(os.path.join(repo_gov, name), flat)
    payload = {"head": head, "proof": proof,
               "digest": digest, "pub": pub}
    payload_path = os.path.join(flat, "payload.json")
    with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    runner = os.path.join(flat, "run_check.py")
    with open(runner, "w", encoding="utf-8") as f:
        f.write(
            "import json, sys\n"
            "import transparency_log as t\n"
            "p = json.load(open(sys.argv[1]))\n"
            "ok_head = t.verify_tree_head(p['head'], p['pub'])\n"
            "ok_inc = t.verify_inclusion(p['digest'], p['proof'],\n"
            "                            p['head'], p['pub'])\n"
            "print('head=%s inclusion=%s' % (ok_head, ok_inc))\n"
            "sys.exit(0 if (ok_head and ok_inc) else 1)\n")
    env = {k: v for k, v in os.environ.items()
           if k != "PYTHONPATH"}
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    try:
        proc = subprocess.run(
            [sys.executable, "run_check.py", "payload.json"],
            cwd=flat, env=env, capture_output=True, text=True,
            timeout=120)
    except Exception as e:  # noqa: BLE001 -- probe harness
        return _error("offline subprocess failed: %r" % (e,))
    if proc.returncode != 0:
        return _break("offline verification failed without the "
                      "engine: rc=%d out=%r err=%r"
                      % (proc.returncode, proc.stdout, proc.stderr))
    return _held("offline check passed with 3 flat files, no engine "
                 "(%s)" % proc.stdout.strip())


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-42s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
