"""Wave-274 lane 3 red-team battery: the attestor-plugin interface.

SPIFFE ADAPT (principle only -- no SPIFFE dependency, no JWT SVIDs,
no bearer flows): ``gov/evidence_certs.py`` issuance gets a pluggable
attestor interface. Environment-fact collectors feed the cert's
claim set; a verifier matches attestor output against declared
registration entries; registration entries are crown jewels --
entry-writes require a claim-level ceremony. Producer identity stays
in the wave-272 OIDC (iss, sub) ceremony.

Red phase (run on the wave-273 base): every probe expects BREAK --
the seam is absent, so environment facts cannot bind issuance at
all. Green phase (after the lane): every probe expects HELD.

Probes:
  at01  spoofed selector facts with no matching ceremony-backed
        entry -> attestor-entry-unmatched (never mints).
  at02  registration entry write without a valid claim-level
        ceremony -> attestor-ceremony-invalid (crown jewels).
  at03  happy path: ceremony-backed entry + matching facts + sub
        binding -> issuance embeds attested_facts / entry id in the
        claim set.
  at04  facts match an entry but the entry's producer is not the
        assertion sub -> refused (identity binding).
  at05  facts match two entries -> attestor-entry-ambiguous (fail
        closed, never picks one).
  at06  PlatformAttestor.collect() returns well-formed facts
        (control).

depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; deterministic A==B across runs.
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w274-attestor-rt")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TAXONOMY_PIN = 1579  # Wave-274 merge: pin 1458 -> 1477 (+3 provlabel-* + 8 rail-* + 3 decodetrust-* + 5 attestor-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*)
GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_TMP = tempfile.mkdtemp(prefix="w274at-")

_RESULTS = []
_PROBES = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never raises
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _probe(pid, expected):
    def deco(fn):
        _PROBES.append((pid, expected, fn))
        return fn
    return deco


def _missing(what):
    return ("BREAK", "attestor seam absent on this tree: %s" % what)


_NOW = 1790860000
_ARC = "1.3.6.1.4.1.99999"
_POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module


def _keypair(byte):
    from gov import ed25519 as ed
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


def _ca_kwargs(tmp, **over):
    from gov import evidence_certs as ec
    from gov import kms as kms_mod
    fake = kms_mod.FakeKmsProvider(["ca-key-1"])
    approvals = {"a" * 32: {"decider": "alice", "state": "pending"}}
    kw = dict(kms_provider=fake,
              ca_key_id="ca-key-1",
              ca_public_key=fake.test_signing_public_key("ca-key-1"),
              issuers=["https://issuer.example.com"],
              approval_lookup=approvals.get,
              audit_log_path=os.path.join(tmp, "audit.jsonl"),
              anchor_reachable=lambda: True,
              oid_arc=_ARC,
              now=lambda: _NOW)
    kw.update(over)
    return ec, kw


def _good_req(sub="alice"):
    from gov import ed25519 as ed
    seed, pub = _keypair(0x01)
    chal = (_POP_DOMAIN + ("a" * 32).encode("utf-8")
            + hashlib.sha256(pub).digest())
    return {"identity_assertion":
            {"iss": "https://issuer.example.com", "sub": sub,
             "exp": _NOW + 3600},
            "ephemeral_pub": pub,
            "pop_sig": ed.sign(seed, chal),
            "approval_id": "a" * 32,
            "intent_digest": "d" * 64}


def _ceremony_sig(entry, ceremony_seed):
    """Claim-level ceremony: sign the canonical entry (without the
    ceremony envelope) with a ceremony key."""
    from gov import ed25519 as ed
    body = {k: v for k, v in entry.items() if k != "ceremony"}
    canonical = json.dumps(body, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return base64.b64encode(ed.sign(ceremony_seed, canonical)).decode(
        "ascii")


def _fx():
    """Fixture: attestor module present? ceremony keys?"""
    try:
        from gov import attestors as at
    except ImportError:
        return None, None
    cseed, cpub = _keypair(0xC0)
    kid = hashlib.sha256(cpub).hexdigest()[:16]
    reg = at.AttestedRegistry(ceremony_keys={kid: cpub})
    return at, (reg, cseed, kid)


@_probe("at01", "HELD")
def _at01_spoofed_facts_no_entry():
    """Spoofed selector facts with no matching ceremony-backed entry
    must refuse attestor-entry-unmatched -- never mint."""
    at, fx = _fx()
    if at is None:
        return _missing("gov.attestors")
    reg, cseed, kid = fx
    entry = {"entry_id": "prod-web-1", "attestor_id": "static-test",
             "selector": {"machine_id": "real-machine"},
             "producer_sub": "alice", "scopes": ["evidence:write"]}
    reg.register_entry(entry, ceremony={
        "signer": kid, "signature": _ceremony_sig(entry, cseed)})
    spoof = at.StaticAttestor({"machine_id": "attacker-machine"})
    ec, kw = _ca_kwargs(tempfile.mkdtemp(prefix="w274at01-"),
                        attestor=spoof, attested_registry=reg)
    ca = ec.EvidenceCA(**kw)
    try:
        ca.issue(**_good_req())
    except Exception as exc:
        if getattr(exc, "code", None) == "attestor-entry-unmatched":
            return ("HELD", "spoofed facts refused without a "
                    "matching entry")
        return ("BREAK", "wrong refusal %r for spoofed facts"
                % (getattr(exc, "code", None),))
    return ("BREAK", "cert minted for spoofed facts with no "
            "matching entry")


@_probe("at02", "HELD")
def _at02_entry_write_without_ceremony():
    """Registration entry writes are crown jewels: without a valid
    claim-level ceremony the write refuses attestor-ceremony-invalid."""
    at, fx = _fx()
    if at is None:
        return _missing("gov.attestors")
    reg, _cseed, _kid = fx
    entry = {"entry_id": "evil", "attestor_id": "static-test",
             "selector": {"machine_id": "attacker-machine"},
             "producer_sub": "mallory", "scopes": ["evidence:write"]}
    try:
        reg.register_entry(entry, ceremony=None)
    except Exception as exc:
        if getattr(exc, "code", None) == "attestor-ceremony-invalid":
            return ("HELD", "ceremony-less entry write refused")
        return ("BREAK", "wrong refusal %r for ceremony-less write"
                % (getattr(exc, "code", None),))
    return ("BREAK", "attacker registered an entry with no ceremony")


@_probe("at03", "HELD")
def _at03_happy_path_embeds_claims():
    """Ceremony-backed entry + matching facts + sub binding -> the
    cert's claim set carries the attested facts and entry id."""
    at, fx = _fx()
    if at is None:
        return _missing("gov.attestors")
    reg, cseed, kid = fx
    facts = {"machine_id": "real-machine", "boot_id": "b" * 32}
    entry = {"entry_id": "prod-web-1", "attestor_id": "static-test",
             "selector": {"machine_id": "real-machine"},
             "producer_sub": "alice", "scopes": ["evidence:write"]}
    reg.register_entry(entry, ceremony={
        "signer": kid, "signature": _ceremony_sig(entry, cseed)})
    att = at.StaticAttestor(facts)
    tmp = tempfile.mkdtemp(prefix="w274at03-")
    ec, kw = _ca_kwargs(tmp, attestor=att, attested_registry=reg)
    ca = ec.EvidenceCA(**kw)
    cert, stored = ca.issue(**_good_req())
    attestation = stored.get("attestation") or stored
    if attestation.get("attested_entry_id") != "prod-web-1":
        return ("BREAK", "attestation missing attested_entry_id")
    if not isinstance(attestation.get("attested_facts"), dict):
        return ("BREAK", "attestation missing attested_facts")
    ext_key = _ARC + ".1.41"
    if cert.get("extensions", {}).get(ext_key) != "prod-web-1":
        return ("BREAK", "cert claim set missing attested entry id")
    return ("HELD", "attested facts embedded in claim set")


@_probe("at04", "HELD")
def _at04_entry_producer_mismatch():
    """Facts match an entry, but the entry's producer is not the
    assertion sub -> refused (the attested identity must bind the
    certified identity)."""
    at, fx = _fx()
    if at is None:
        return _missing("gov.attestors")
    reg, cseed, kid = fx
    entry = {"entry_id": "prod-web-1", "attestor_id": "static-test",
             "selector": {"machine_id": "real-machine"},
             "producer_sub": "mallory", "scopes": ["evidence:write"]}
    reg.register_entry(entry, ceremony={
        "signer": kid, "signature": _ceremony_sig(entry, cseed)})
    att = at.StaticAttestor({"machine_id": "real-machine"})
    ec, kw = _ca_kwargs(tempfile.mkdtemp(prefix="w274at04-"),
                        attestor=att, attested_registry=reg)
    ca = ec.EvidenceCA(**kw)
    try:
        ca.issue(**_good_req(sub="alice"))
    except Exception as exc:
        if getattr(exc, "code", None) == "attestor-entry-unmatched":
            return ("HELD", "entry bound to a different producer "
                    "refused")
        return ("BREAK", "wrong refusal %r for producer mismatch"
                % (getattr(exc, "code", None),))
    return ("BREAK", "cert minted: entry producer != assertion sub")


@_probe("at05", "HELD")
def _at05_ambiguous_entries():
    """Facts matching two entries -> attestor-entry-ambiguous (fail
    closed, never picks one)."""
    at, fx = _fx()
    if at is None:
        return _missing("gov.attestors")
    reg, cseed, kid = fx
    for eid in ("e1", "e2"):
        entry = {"entry_id": eid, "attestor_id": "platform",
                 "selector": {"machine_id": "real-machine"},
                 "producer_sub": "alice", "scopes": ["evidence:write"]}
        reg.register_entry(entry, ceremony={
            "signer": kid, "signature": _ceremony_sig(entry, cseed)})
    try:
        reg.match({"machine_id": "real-machine"},
                  attestor_id="platform")
    except Exception as exc:
        if getattr(exc, "code", None) == "attestor-entry-ambiguous":
            return ("HELD", "ambiguous selectors fail closed")
        return ("BREAK", "wrong refusal %r for ambiguous match"
                % (getattr(exc, "code", None),))
    return ("BREAK", "ambiguous selectors silently picked one")


@_probe("at06", "HELD")
def _at06_platform_attestor_shape():
    """Control: the stdlib platform attestor collects well-formed
    facts (attestor_id + str-keyed scalar facts)."""
    try:
        from gov import attestors as at
    except ImportError:
        return _missing("gov.attestors")
    if not hasattr(at, "PlatformAttestor"):
        return _missing("attestors.PlatformAttestor")
    got = at.PlatformAttestor().collect()
    if not isinstance(got, dict):
        return ("BREAK", "collect() did not return a dict")
    if not got.get("attestor_id"):
        return ("BREAK", "collect() missing attestor_id")
    facts = got.get("facts")
    if not isinstance(facts, dict) or not facts:
        return ("BREAK", "collect() returned no facts")
    bad = [k for k, v in facts.items()
           if not isinstance(k, str) or not isinstance(v, (str, int))]
    if bad:
        return ("BREAK", "non-scalar fact values: %r" % (bad,))
    return ("HELD", "platform attestor collects %d facts"
            % len(facts))


def _green_checks():
    if GREEN_SKIP:
        return [("green-skip", "SKIP", "GOV_SKIP_GREEN=1")]
    out = []
    for mod in ("tests.test_attestors", "tests.test_decode_trust",
                "tests.test_evcert"):
        try:
            suite = unittest.TestLoader().loadTestsFromName(mod)
            res = unittest.TestResult()
            suite.run(res)
            ok = res.wasSuccessful()
            out.append((mod, "HELD" if ok else "FAIL",
                        "%d tests, %d failures, %d errors"
                        % (res.testsRun, len(res.failures),
                           len(res.errors))))
        except Exception as exc:  # noqa: BLE001
            out.append((mod, "FAIL", "%s: %s"
                        % (type(exc).__name__, exc)))
    return out


def main():
    print("w274 attestor battery: %d probes (TMPDIR=%s)"
          % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-10s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP")
                              else "FAIL", name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
