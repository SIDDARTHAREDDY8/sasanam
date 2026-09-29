#!/usr/bin/env python3
"""Red-first break battery for wave-198: attestation-conditioned credential release.

The gap (pristine tree): sentinel credential substitution releases the real
value on host binding ALONE -- whoever holds the ``fake_value_<uuid>``
sentinel within the authorized channel receives the secret. There is NO
agent-identity condition on release (the Trustee KBS steal: release must
require an affirming attestation token, evaluated per release at the
execution boundary, default-deny, with no silent fallback to host-only).

Probes (each run twice in-process; any disagreement is ERROR):
  R1 capability-absent: gov.attestation_release importable?
  R2 seam-absent:       the release seam evaluates an identity/attestation
                        condition (pristine: bearer release proceeds on host
                        binding alone -- the genuine red, attack succeeds)
  R3 forged:            tampered / wrong-key attestation is refused?
  R4 replay:            the same jti presented twice -- the second refuses?
  R5 stale:             an expired attestation refuses at the execution
                        boundary?
  R6 downgrade:         [HEADLINE] attestation absent / issuer trust anchor
                        missing / credential-class mismatch -> LOUD refuse,
                        never a silent host-only fallback?
  R7 mixed:             a non-affirming status (warning/contraindicated)
                        refuses the whole release?
  R8 toctou:            attestation valid at the attempt pre-check but
                        expired at execution -> execution refuses?
  R9 session-binding:   an attestation copied into another run refuses
                        on sub/session mismatch?

Pristine expectation: 9/9 BREAK. Fixed expectation: 9/9 HELD.

Stdlib only. Deterministic (fixed seeds, real-time-anchored minting with
short TTLs -- no wall-clock flakiness: expiry probes mint already-expired
tokens). Sets GOV_DEPLOYMENT_MODE=staging at module level; verify standalone
under ``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green check is
depth-1: the adjacent unit suite only, never nested battery mains).
"""

import hashlib
import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
import types  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import sentinel_substitution as _sentinel  # noqa: E402

# ---------------------------------------------------------------------------
# Fixed fixtures (deterministic seeds; import guarded for pristine trees)
# ---------------------------------------------------------------------------

_SEED_ISSUER = hashlib.sha256(b"wave198-attestation-issuer").digest()
_SEED_OTHER = hashlib.sha256(b"wave198-unrelated-key").digest()
_ISS = "attestation-service-1"
_AGENT = "agent-1"
_PRINCIPAL = "user-1"
_RUN = "run-1"
_REAL_DB = "tok_synth_db_9f2c4a1b7e"   # DLP-clean synthetic credential
_DB_HOST = "db.internal"
_CRED_ID = "db-cred"
_CRED_CLASS = "db"

try:
    from gov import attestation_release as _ar  # noqa: E402
    from gov.keyset import new_keyset  # noqa: E402
    _HAVE_AR = True
except ImportError:
    _ar = None
    new_keyset = None
    _HAVE_AR = False


def _keyset():
    ks, _signer = new_keyset(_SEED_ISSUER,
                             purpose=_ar.ATTESTATION_PURPOSE)
    return ks


def _config(ks=None):
    ks = ks or _keyset()
    return _ar.AttestationReleaseConfig(
        keyset_doc=ks.to_dict(), trusted_issuers={_ISS})


def _mint(ks, **kw):
    params = dict(sub=_AGENT, iss=_ISS,
                  agent_scope=[_CRED_CLASS],
                  session={"agent_id": _AGENT, "run_id": _RUN},
                  ttl_seconds=300, at=int(time.time()))
    params.update(kw)
    return _ar.attest_release(ks, _SEED_ISSUER, **params)


def _identity(agent_id=_AGENT, run_id=_RUN):
    return types.SimpleNamespace(agent_id=agent_id, principal=_PRINCIPAL,
                                 role="agent", run_id=run_id)


def _vault(policy="attested", cred_class=_CRED_CLASS):
    vault = _sentinel.SentinelVault()
    sentinel = vault.register(_CRED_ID, _REAL_DB, [_DB_HOST],
                              credential_class=cred_class,
                              release_policy=policy)
    return vault, sentinel


def _release(vault, sentinel, token, *, now=None, run_id=_RUN,
             agent_id=_AGENT, config=None, audit=None):
    """Drive the execution-boundary seam. Returns (outcome, detail).

    outcome: "substituted" | "refused". detail: new args / reason / audit.
    """
    args = {"url": "https://%s/query" % _DB_HOST, "api_key": sentinel}
    audit = [] if audit is None else audit
    try:
        new_args, substituted = _sentinel.substitute_for_execution(
            vault, "http_post", args, identity=_identity(agent_id, run_id),
            attestation=token, release_config=config, audit_log=audit,
            now=now)
    except _sentinel.SentinelError as e:
        return "refused", str(e), audit
    if new_args.get("api_key") == _REAL_DB:
        return "substituted", new_args, audit
    return "refused", "no substitution (args unchanged)", audit


def _denied_loud(audit):
    return any(isinstance(e, dict) and e.get("event") == "attestation_release"
               and e.get("verdict") == "denied" for e in audit)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _p_r1():
    if not _HAVE_AR:
        return ("BREAK", "gov.attestation_release absent -- no "
                "attestation-conditioned release exists")
    return ("HELD", "gov.attestation_release importable")


def _p_r2():
    import inspect
    if not _HAVE_AR:
        # Genuine red: bearer release on host binding alone.
        vault = _sentinel.SentinelVault()
        sentinel = vault.register(_CRED_ID, _REAL_DB, [_DB_HOST])
        args = {"url": "https://%s/query" % _DB_HOST, "api_key": sentinel}
        new_args, _ = _sentinel.substitute_for_execution(
            vault, "http_post", args)
        if new_args.get("api_key") == _REAL_DB:
            return ("BREAK", "release proceeds on host binding alone -- "
                    "no identity/attestation condition at the seam")
        return ("ERROR", "pristine seam did not substitute (unexpected)")
    sig = inspect.signature(_sentinel.substitute_for_execution)
    params = set(sig.parameters)
    if not {"identity", "attestation", "release_config"} <= params:
        return ("BREAK", "substitute_for_execution lacks the "
                "identity/attestation seam")
    # Fixed: without an attestation the attested-mandatory release refuses.
    vault, sentinel = _vault()
    outcome, detail, audit = _release(vault, sentinel, None,
                                      config=_config())
    if outcome == "refused" and _denied_loud(audit):
        return ("HELD", "seam evaluates attestation; absent attestation "
                "refuses loudly")
    return ("BREAK", "attested release without attestation did not refuse: "
            "%s" % (detail,))


def _p_r3():
    if not _HAVE_AR:
        return ("BREAK", "no attestation seam to forge against")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    # Positive control: a genuine token substitutes.
    good = _mint(ks)
    outcome, _, _ = _release(vault, sentinel, good, config=config)
    if outcome != "substituted":
        return ("ERROR", "positive control failed: valid token refused")
    # Forgery 1: tampered status after mint.
    forged = dict(good)
    forged["status"] = "affirming"
    # (already affirming; tamper the signature instead)
    forged2 = dict(good)
    env = dict(forged2["envelope"])
    env["sig"] = "00" * 64
    forged2["envelope"] = env
    outcome, _, audit = _release(vault, sentinel, forged2, config=config)
    if outcome != "refused":
        return ("BREAK", "tampered-signature attestation was NOT refused")
    # Forgery 2: token minted by an unrelated key (kid not in keyset).
    ks2, _ = new_keyset(_SEED_OTHER, purpose=_ar.ATTESTATION_PURPOSE)
    alien = _ar.attest_release(ks2, _SEED_OTHER, sub=_AGENT, iss=_ISS,
                               agent_scope=[_CRED_CLASS],
                               session={"agent_id": _AGENT, "run_id": _RUN},
                               ttl_seconds=300, at=int(time.time()))
    outcome, _, _ = _release(vault, sentinel, alien, config=config)
    if outcome != "refused":
        return ("BREAK", "wrong-key attestation was NOT refused")
    if not _denied_loud(audit):
        return ("BREAK", "forgery refused but not loudly audited")
    return ("HELD", "forged attestations refused (bad sig, unknown kid)")


def _p_r4():
    if not _HAVE_AR:
        return ("BREAK", "no jti replay cache exists")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    token = _mint(ks, jti="fixed-jti-r4")
    o1, _, _ = _release(vault, sentinel, token, config=config)
    o2, _, _ = _release(vault, sentinel, token, config=config)
    if o1 == "substituted" and o2 == "refused":
        return ("HELD", "first release allowed, replayed jti refused")
    return ("BREAK", "replay not refused: first=%s second=%s" % (o1, o2))


def _p_r5():
    if not _HAVE_AR:
        return ("BREAK", "no expiry enforcement at the boundary")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    stale = _mint(ks, at=int(time.time()) - 600, ttl_seconds=300)
    outcome, _, audit = _release(vault, sentinel, stale, config=config)
    if outcome == "refused" and _denied_loud(audit):
        return ("HELD", "expired attestation refused at execution boundary")
    return ("BREAK", "expired attestation was NOT refused")


def _p_r6():
    """HEADLINE: no silent downgrade to host-only, ever."""
    if not _HAVE_AR:
        return ("BREAK", "no attestation gate -- host-only is the only path")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    # 6a: attestation absent -> loud refuse, args untouched.
    args_before = {"url": "https://%s/query" % _DB_HOST, "api_key": sentinel}
    audit = []
    try:
        new_args, _ = _sentinel.substitute_for_execution(
            vault, "http_post", dict(args_before),
            identity=_identity(), attestation=None,
            release_config=config, audit_log=audit)
        return ("BREAK", "attestation-absent release SUBSTITUTED "
                "(silent downgrade to host-only)")
    except _sentinel.SentinelError:
        pass
    if not _denied_loud(audit):
        return ("BREAK", "attestation-absent refused but not loudly audited")
    # 6b: trust anchor missing (issuer killed / unconfigured) -> refuse.
    audit = []
    try:
        _sentinel.substitute_for_execution(
            vault, "http_post", {"url": "https://%s/query" % _DB_HOST,
                                 "api_key": sentinel},
            identity=_identity(), attestation=_mint(ks),
            release_config=None, audit_log=audit)
        return ("BREAK", "release with no trust anchor SUBSTITUTED")
    except _sentinel.SentinelError:
        pass
    # 6c: attestation covers a different credential class -> refuse.
    other = _mint(ks, agent_scope=["other-class"])
    outcome, _, _ = _release(vault, sentinel, other, config=config)
    if outcome != "refused":
        return ("BREAK", "wrong-class attestation was NOT refused")
    # 6d: untrusted issuer -> refuse.
    rogue = _mint(ks, iss="rogue-issuer")
    outcome, _, _ = _release(vault, sentinel, rogue, config=config)
    if outcome != "refused":
        return ("BREAK", "untrusted-issuer attestation was NOT refused")
    return ("HELD", "downgrade refused in all 4 shapes (absent, no anchor, "
            "wrong class, rogue issuer); refusals are loud")


def _p_r7():
    if not _HAVE_AR:
        return ("BREAK", "no status predicate exists")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    for status in ("warning", "contraindicated"):
        token = _mint(ks, status=status)
        outcome, _, _ = _release(vault, sentinel, token, config=config)
        if outcome != "refused":
            return ("BREAK", "status=%r attestation was NOT refused"
                    % (status,))
    return ("HELD", "non-affirming statuses refuse the whole release")


def _p_r8():
    if not _HAVE_AR:
        return ("BREAK", "no per-release evaluation at the boundary")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    token = _mint(ks, ttl_seconds=300)
    at = token["iat"]
    # Attempt-time pre-check passes...
    ok, _, _ = _ar.evaluate_release(
        _CRED_ID, _CRED_CLASS, token, config=config, agent_id=_AGENT,
        run_id=_RUN, now=at + 10, consume=False)
    if not ok:
        return ("ERROR", "pre-check should pass for a fresh token")
    # ...but the token expires before execution: the boundary refuses.
    outcome, _, _ = _release(vault, sentinel, token, config=config,
                             now=at + 400)
    if outcome == "refused":
        return ("HELD", "execution-boundary re-evaluation refuses the "
                "stale token (TOCTOU closed)")
    return ("BREAK", "stale-at-execution token was NOT refused")


def _p_r9():
    if not _HAVE_AR:
        return ("BREAK", "no session binding exists")
    ks = _keyset()
    config = _config(ks)
    vault, sentinel = _vault()
    token = _mint(ks)  # bound to session (_AGENT, _RUN)
    outcome, _, _ = _release(vault, sentinel, token, config=config,
                             run_id="run-2", agent_id=_AGENT)
    if outcome != "refused":
        return ("BREAK", "cross-run attestation replay was NOT refused")
    outcome, _, _ = _release(vault, sentinel, token, config=config,
                             run_id=_RUN, agent_id="agent-2")
    if outcome != "refused":
        return ("BREAK", "cross-agent attestation replay was NOT refused")
    return ("HELD", "attestation bound to (agent_id, run_id); "
            "cross-session use refuses")


_PROBES = [
    ("R1", _p_r1),
    ("R2", _p_r2),
    ("R3", _p_r3),
    ("R4", _p_r4),
    ("R5", _p_r5),
    ("R6", _p_r6),
    ("R7", _p_r7),
    ("R8", _p_r8),
    ("R9", _p_r9),
]


def main():
    first = []
    for name, fn in _PROBES:
        try:
            v1, d1 = fn()
        except Exception as e:  # noqa: BLE001 -- probe must not die
            v1, d1 = "ERROR", "raised %r" % (e,)
        try:
            v2, d2 = fn()
        except Exception as e:  # noqa: BLE001
            v2, d2 = "ERROR", "raised %r" % (e,)
        if v1 != v2:
            verdict, detail = "ERROR", \
                "non-deterministic: %s vs %s" % (v1, v2)
        else:
            verdict, detail = v1, d1
        first.append((name, verdict, detail))
        print("%s %-6s %s" % (name, verdict, detail))
    breaks = sum(1 for _, v, _ in first if v == "BREAK")
    held = sum(1 for _, v, _ in first if v == "HELD")
    errors = sum(1 for _, v, _ in first if v == "ERROR")
    print("breaks=%d held=%d errors=%d" % (breaks, held, errors))
    if breaks:
        print("BREAK: %s" % ", ".join(n for n, v, _ in first
                                      if v == "BREAK"))
    return 1 if errors else 0


def _green_check():
    """Depth-1 green check: the adjacent unit suite only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-198 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if importlib.util.find_spec("tests.test_attestation_release") is None:
        print("GREEN CHECK: skipped (tests.test_attestation_release "
              "absent on this tree)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_attestation_release"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suite: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
