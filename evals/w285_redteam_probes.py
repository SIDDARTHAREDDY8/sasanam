"""Wave-285 independent red-team battery: attack the wave-284 merge.

Base: wave-284 push 0f13ce1d9f1e01b32a6a237f297e6364fa993b9c
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-284 merge report):
  (a) gov/attack_manifest.py -- nuclei-derived template DSL: matcher/
      extractor bypass, selection-grammar injection, unsigned-template
      trust enforcement, protocol-family gaps.
  (b) gov/guac_graph.py -- evidence graph: quorum manipulation,
      pending-claim leakage into blast radius, envelope/signature
      binding gaps, Spec-filter bypass.
  (c) gov/bundle_envelope.py -- sops-pattern envelope: nonce/key
      separation, recipient-policy bypass, rotate ceremony, Ed25519
      binding (within the module's honest limitations -- "not AES-GCM"
      is documented, not a finding).
  (d) gov/sandbox_policy.py -- nsjail-pattern policy layer: grammar
      bypass, DEFAULT smuggling, digest-pin drift, host-mismatch gaps.
  (e) gov/kms_keyset.py -- tink-pattern keyset: DESTROYED resurrection,
      ceremony half-finish, template downgrade.

Re-pins at the public seams:
  F311 (LOW, CLOSED) -- w283_f311_probes.py: 0 BREAK expected.
  F312-F315 (LOW, CLOSED) -- w283_redteam_probes.py: 0 BREAK expected;
      w284_f312_315_probes.py: 0 BREAK expected.
  F316-F324 (OPEN) -- w284_redteam_probes.py: 10 BREAK expected-open.

New findings filed (all LOW, OPEN): F325-F330.
Wave-286 lane 4 closed F329 + F330 (keyed-MAC keyset pin; immutable
CompiledPolicy + live-digest gate); their probes assert the fixed
contract. F325-F328 remain OPEN (expected-open).

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g285-redteam && TMPDIR=/var/tmp/g285-redteam \
    ~/workspace/.gov-venv/bin/python evals/w285_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g285-redteam2 \
    ~/workspace/.gov-venv/bin/python evals/w285_redteam_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-284 merge: pin 1587 -> 1621.
# Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).
TAXONOMY_PIN = 2100 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*).



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (len(lits), len(lits)))


# ---------------------------------------------------------------------------
# Re-pins: run the earlier batteries as subprocesses (depth-1, no nesting)
# and check their verdict counts against the expected post-wave-284 state.
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    ("evals/w283_f311_probes.py", 0, "f311-closed"),
    ("evals/w283_redteam_probes.py", 0, "f312-315-closed"),
    ("evals/w284_f312_315_probes.py", 0, "f312-315-closed-b"),
    # Wave-285 merge: F316-F324 all CLOSED (lanes 1-4); w284_redteam
    # re-pinned BREAK->HELD at merge (wave-281 precedent).
    ("evals/w284_redteam_probes.py", 0, "f316-324-closed"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w285-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR", "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


# ---------------------------------------------------------------------------
# F325 (LOW): unbounded regex backtracking in template matchers/extractors.
# Load-time validation runs re.compile only, so an evil pattern like
# ^(a+)+$ is accepted; at run time a non-matching observation triggers
# exponential backtracking (17.34 s on a 29-byte input, ~1.85x/byte).
# Unsigned templates run freely at target="isolated", so the attacker
# model is real. Break-first probe asserts the load-time seam: the evil
# pattern must be refused with a coded manifest-* refusal.
# ---------------------------------------------------------------------------

def _evil_template(pattern):
    return {
        "id": "redos-probe", "version": "1.0.0",
        "info": {"name": "r", "author": ["x"], "severity": "low",
                 "description": "d", "reference": [], "tags": ["t"],
                 "protocol": None, "metadata": {}},
        "matchers": [{"type": "regex", "pattern": pattern}],
        "extractors": [],
    }


def p_f325_redos_matcher():
    from gov import attack_manifest as am
    try:
        am.validate_template(_evil_template(r"^(a+)+$"))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        return _record("f325-redos-matcher", "HELD",
                       "evil matcher pattern refused: %s" % (code,))
    _record("f325-redos-matcher", "BREAK",
            "validate_template accepts ^(a+)+$ -- unbounded backtracking "
            "at run time (17.34 s on 29 bytes); no step budget or "
            "pattern-complexity gate")


def p_f325_redos_extractor():
    from gov import attack_manifest as am
    t = _evil_template(r"x")
    t["extractors"] = [{"type": "regex", "name": "x",
                        "pattern": r"(a+)+$"}]
    try:
        am.validate_template(t)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        return _record("f325-redos-extractor", "HELD",
                       "evil extractor pattern refused: %s" % (code,))
    _record("f325-redos-extractor", "BREAK",
            "validate_template accepts (a+)+$ extractor -- same "
            "exponential-backtracking hole on the extractor path")


# ---------------------------------------------------------------------------
# F326 (LOW): rekey ceremonies skip the bundle_scope creation-rule check.
# seal_envelope refuses a bundle outside the policy scope
# (recipient-policy-invalid), but update_wraps and rotate_envelope call
# _seal_with_key directly and re-seal under a non-covering policy.
# ---------------------------------------------------------------------------

def _scoped_env():
    from gov import bundle_envelope as be
    priv = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline", "x25519_pub": be.x25519_pub(priv).hex()}
    wide = be.make_recipient_policy([r], bundle_scope="proj/")
    narrow = be.make_recipient_policy([r], bundle_scope="other/")
    seed = secrets.token_bytes(32)
    env = be.seal_envelope(b"data", bundle_id="proj/a", policy=wide,
                           signer_seed=seed)
    return be, env, priv, seed, narrow


def p_f326_update_wraps_scope():
    be, env, priv, seed, narrow = _scoped_env()
    try:
        be.update_wraps(env, recipient_id="a", x25519_priv=priv,
                        new_policy=narrow, signer_seed=seed)
    except Exception as e:  # noqa: BLE001
        return _record("f326-update-wraps-scope", "HELD",
                       "refused: %s" % getattr(e, "code", type(e).__name__))
    _record("f326-update-wraps-scope", "BREAK",
            "update_wraps re-seals bundle 'proj/a' under policy scoped "
            "'other/' -- no recipient-policy-invalid refusal")


def p_f326_rotate_scope():
    be, env, priv, seed, narrow = _scoped_env()
    try:
        be.rotate_envelope(env, recipient_id="a", x25519_priv=priv,
                           policy=narrow, signer_seed=seed)
    except Exception as e:  # noqa: BLE001
        return _record("f326-rotate-scope", "HELD",
                       "refused: %s" % getattr(e, "code", type(e).__name__))
    _record("f326-rotate-scope", "BREAK",
            "rotate_envelope re-seals bundle 'proj/a' under policy scoped "
            "'other/' -- no recipient-policy-invalid refusal")


# ---------------------------------------------------------------------------
# F327 (LOW): KmsKeyset.from_dict on a ceremony missing new_key_id raises
# raw KeyError('new_key_id'), not coded KeysetError. Repo convention is
# coded refusals; callers branching on KeysetError.code miss this.
# ---------------------------------------------------------------------------

def p_f327_ceremony_keyerror():
    from gov import kms_keyset as kk
    pin_key = os.urandom(32)
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="k", provider_name="fake",
                          pin_key=pin_key)
    doc = ks.to_dict()
    doc["ceremony"] = {"phase": "none"}
    try:
        kk.KmsKeyset.from_dict(doc, pin_key=pin_key)
    except KeyError as e:
        return _record("f327-ceremony-keyerror", "BREAK",
                       "raw KeyError %r escapes -- expected coded "
                       "KeysetError" % (e,))
    except Exception as e:  # noqa: BLE001
        return _record("f327-ceremony-keyerror", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f327-ceremony-keyerror", "BREAK",
            "malformed ceremony accepted silently")


# ---------------------------------------------------------------------------
# F328 (LOW): promote() demotes the successor when old_primary ==
# new_key_id. Destroying a possibly-compromised old primary mid-ceremony
# naming the in-flight successor (plausible incident response) makes the
# ceremony "complete" while silently disabling the new primary -> mint-stop.
# ---------------------------------------------------------------------------

def p_f328_promote_demotes_successor():
    from gov import kms_keyset as kk
    from gov.kms import FakeKmsProvider
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="key-a", provider_name="fake",
                          pin_key=os.urandom(32))
    prov = FakeKmsProvider(["key-a", "key-b"])
    ks.begin_rotation("key-b", provider_name="fake")
    ks.roll_out(prov)
    ks.destroy_key("key-a", reason="incident", new_primary="key-b")
    ks.promote(reason="x")
    if ks.key_status("key-b") == "disabled":
        return _record("f328-promote-demotes-successor", "BREAK",
                       "promote demoted the successor key-b when "
                       "old_primary == new_key_id; phase=%s; mint now "
                       "refuses keyset-key-disabled (mint-stop)"
                       % ks.ceremony_state()["phase"])
    _record("f328-promote-demotes-successor", "HELD",
            "successor stays enabled after promote")


# ---------------------------------------------------------------------------
# F329 (LOW) -- CLOSED by wave-286 lane 4: the keyset content pin is now a
# keyed MAC (HMAC-SHA256) under a deployment-held pin key. A writer
# holding only the document cannot recompute it: the keyless _repin
# refuses LOUD (keyset-pin-key-invalid) and a stale pin fails closed at
# load (keyset-verify-failed).
# ---------------------------------------------------------------------------

def p_f329_pin_self_forgeable():
    from gov import kms_keyset as kk
    pin_key = os.urandom(32)
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="k", provider_name="fake",
                          pin_key=pin_key)
    ks.add_key("key-b", "fake")
    doc = ks.to_dict()
    doc["keys"][1]["status"] = "destroyed"
    doc["audit_chain"] = []
    # The attacker holds the document but NOT the pin key.
    try:
        forged = kk.KmsKeyset._repin(doc)
    except Exception as e:  # noqa: BLE001
        return _record("f329-pin-self-forgeable", "HELD",
                       "keyless pin recompute refused LOUD: %s"
                       % getattr(e, "code", type(e).__name__))
    try:
        evil = kk.KmsKeyset.from_dict(forged, pin_key=pin_key)
    except Exception as e:  # noqa: BLE001
        return _record("f329-pin-self-forgeable", "HELD",
                       "forgery refused at load: %s"
                       % getattr(e, "code", type(e).__name__))
    if evil.verify_chain():
        return _record("f329-pin-self-forgeable", "BREAK",
                       "status forgery + audit-trail wipe accepted at load "
                       "with verify_chain() == True")
    _record("f329-pin-self-forgeable", "HELD", "chain verification caught it")


# ---------------------------------------------------------------------------
# F330 (LOW) -- CLOSED by wave-286 lane 4: CompiledPolicy is immutable
# after compilation (frozen attributes), and check_policy_use recomputes
# the digest from the live object, so a post-check mutation is either
# blocked at the source or caught as sandbox-policy-drift.
# ---------------------------------------------------------------------------

def p_f330_policy_mutable_after_pin():
    from gov import sandbox_policy as sp
    doc = {"policy_schema_version": 1, "policy_id": "p1",
           "syscalls": {"default": "allow", "allow": [], "deny": [],
                        "rules": ["POLICY a { DEFAULT ALLOW DENY { execve } }"]}}
    p = sp.compile_policy(doc)
    d = tempfile.mkdtemp(prefix="w285-f330-")
    pinpath = os.path.join(d, "pins.json")
    sp.pin_policy("p1", p.digest, pinpath)
    pins = sp.load_pins(pinpath)
    sp.check_policy_use(p, pins)
    before = p.decide("execve", {})
    try:
        p._rule_denies.discard("execve")
    except Exception as e:  # noqa: BLE001
        return _record("f330-policy-mutable-after-pin", "HELD",
                       "post-check mutation blocked (immutable): %s"
                       % type(e).__name__)
    # If a mutation somehow succeeded, the gate recomputes the digest
    # from the live object and must refuse with sandbox-policy-drift.
    try:
        b = sp.bind(p, pins, enforced_namespaces=set())
    except Exception as e:  # noqa: BLE001
        return _record("f330-policy-mutable-after-pin", "HELD",
                       "bind refused after mutation: %s"
                       % getattr(e, "code", type(e).__name__))
    after = b.decide("execve", {})
    if before != after:
        return _record("f330-policy-mutable-after-pin", "BREAK",
                       "decide flipped %s -> %s after post-check mutation; "
                       "bind's pin re-check passed on the stale cached "
                       "digest" % (before, after))
    _record("f330-policy-mutable-after-pin", "HELD",
            "mutation did not change enforcement")


# ---------------------------------------------------------------------------
# Depth-1 green checks: the wave-284 lane batteries must stay all-HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w284_nuclei_probes.py",
        "evals/w284_guac_probes.py",
        "evals/w284_sops_probes.py",
        "evals/w284_nsjail_probes.py",
        "evals/w284_tink_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w285-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    _run_repins()
    p_f325_redos_matcher()
    p_f325_redos_extractor()
    p_f326_update_wraps_scope()
    p_f326_rotate_scope()
    p_f327_ceremony_keyerror()
    p_f328_promote_demotes_successor()
    p_f329_pin_self_forgeable()
    p_f330_policy_mutable_after_pin()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w285_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
