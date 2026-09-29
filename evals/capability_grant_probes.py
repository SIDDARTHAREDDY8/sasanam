#!/usr/bin/env python3
"""Wave-202 lane E red-team probes: capability grants at the tool-call boundary.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
wasmtime/WASI capability-model discipline -- explicit per-call grants,
attenuation-only-narrowing, handle-passing, subset-checked delegation
(licenses: wasmtime Apache-2.0+LLVM exception, wasmer MIT; pattern-only,
re-implemented stdlib-only, nothing vendored).

The wave-202 spike proved the discipline in-process, then proved its
limit: a deliberately adversarial function in the SAME process breaks
out via closure introspection. The build therefore enforces at the
sandbox/process boundary (gov/capability_grants.py): the parent holds
the registry, the tool runs in the sandbox jail (pivot+netns+pidns+
privdrop, all REQUIRED), the child sees only staged bytes under opaque
tokens, and the parent commits writes re-validating every outbox file
against the dispatch record.

Each probe attacks that boundary:

  G1  EMPTY_GRANT      empty grant set: forged tokens refused, tool can
                       only return; real files untouched
  G2  READ_NO_WRITE    read on X works; write to X refused (no commit);
                       forged Y token refused
  G3  NO_SELF_MINT     no Handle class in child; raw paths refused;
                       facade sealed; no attribute path to the registry
  G4  ADVERSARIAL      full in-child code exec: absolute-path read of
                       the real secret fails (pivot); secret bytes are
                       nowhere in the jail; facade bypass into the
                       outbox refuses LOUD at commit; `import gov`
                       refused at dispatch validation
  G5  ATTENUATION      attenuate/re-delegate never widens (200 random
                       trials, transitive)
  G6  DELEGATION       parent-mediated delegation: subset works in its
                       own jail; widening refused loudly + audit-logged
  G7  CONFUSED_DEPUTY  A's token smuggled to B (empty grants) refuses;
                       handle possession without grant membership is
                       nothing
  G8  POSITIVE_PATH    granted file read+write (write committed to the
                       real destination), net canned response,
                       credential sentinel id
  G9  SINGLE_USE       a grant set dispatches exactly once
  G10 UNMINTED         a hand-built GrantSet (no registry id) is refused
  G11 UNBOUND_LABEL    manifest label with no policy binding refuses loud
  G12 BAD_APPROVAL     approval without a record digest refuses
  G13 GRANT_DIGEST_BOM grant digest rides the decision BOM; auditor
                       re-derivation holds; tampering fails
  G14 AUDIT_CHAIN      refusals + dispatch events chain in the real
                       audit log and verify

On the pristine tree every probe reports GAP (gov.capability_grants
absent -- genuine red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: fresh fixtures per probe run; every probe runs twice and
a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import capability_grants as _cg
    from gov.capability_grants import (
        GrantPolicy, GrantRegistry, GrantDispatcher, GrantSet, Capability,
        GrantRefused, GrantMintError, GrantError, derive_grants,
        bom_grants_section, verify_grant_digest,
    )
    from gov.decision_bom import build_bom, check_bom_shape
    from gov.log import ActionLog, verify_chain
    _ABSENT = False
except ImportError:
    _cg = None
    _ABSENT = True

_GAP = (False, "GAP: gov.capability_grants absent on this tree")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _World(object):
    """One deterministic fixture world: fs root, policy, registry.

    Holds the audit-log HMAC key in the environment for the world's
    whole lifetime (key resolution is lazy per-append) and scrubs it
    on cleanup.
    """

    def __init__(self):
        self._old_key = os.environ.get("GOV_LOG_KEY")
        self._old_epoch = os.environ.get("GOV_LOG_KEY_EPOCH")
        os.environ["GOV_LOG_KEY"] = "capgrant-probe-test-key-material"
        os.environ["GOV_LOG_KEY_EPOCH"] = "probe-epoch"
        self.root = tempfile.mkdtemp(prefix="g202e-probe-",
                                     dir="/var/tmp")
        self.fsroot = os.path.join(self.root, "fs")
        os.makedirs(self.fsroot)
        self.secret_path = os.path.join(self.fsroot, "secret.txt")
        with open(self.secret_path, "w", encoding="utf-8") as f:
            f.write("x-marks-the-spot")
        self.write_path = os.path.join(self.fsroot, "out.txt")
        with open(self.write_path, "w", encoding="utf-8") as f:
            f.write("original")
        self.policy = GrantPolicy(fs_root=self.fsroot)
        self.policy.bind_file("read-secret", "secret.txt", {"read"})
        self.policy.bind_file("write-out", "out.txt", {"write"})
        self.policy.bind_file("readwrite-secret", "secret.txt",
                              {"read", "write"})
        self.policy.bind_net("api", "api.example.com", {"connect"},
                             response=b"CANNED-OK")
        self.policy.bind_credential("refund", "payments:refund", {"use"},
                                   sentinel_id="secret-id:payments:refund")
        self.log_path = os.path.join(self.root, "actions.jsonl")
        self.log = ActionLog(self.log_path)
        self.registry = GrantRegistry(audit_log=self.log)
        self.dispatcher = GrantDispatcher(
            self.registry, grant_policy=self.policy,
            staging_parent=self.root)
        self._decision = 0

    def decide(self):
        self._decision += 1
        return "decision-%d" % self._decision

    def approval(self):
        return {"approval_id": "appr-1", "record_digest": "ab" * 32}

    def grants_for(self, labels_by_category, decision_id=None):
        manifest = {"skill_id": "probe-skill",
                    "capabilities": labels_by_category}
        did = decision_id or self.decide()
        grants, allow = derive_grants(
            verified_manifest=manifest, grant_policy=self.policy,
            approval=self.approval(), decision_id=did,
            registry=self.registry)
        return grants, allow, did

    def read_secret_bytes(self):
        with open(self.secret_path, "rb") as f:
            return f.read()

    def cleanup(self):
        if self._old_key is None:
            os.environ.pop("GOV_LOG_KEY", None)
        else:
            os.environ["GOV_LOG_KEY"] = self._old_key
        if self._old_epoch is None:
            os.environ.pop("GOV_LOG_KEY_EPOCH", None)
        else:
            os.environ["GOV_LOG_KEY_EPOCH"] = self._old_epoch
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Tool functions: these EXECUTE IN THE CHILD. Bodies must be
# self-contained (stdlib imports inside the function only); they receive
# ONLY the sealed io facade plus JSON kwargs.
# ---------------------------------------------------------------------------

def tool_empty_grant(io):
    attempted = []
    for tok, op in (("h1", "read"), ("h2", "write"), ("h3", "connect"),
                    ("h4", "use_credential")):
        try:
            if op == "write":
                getattr(io, op)(tok, b"x")
            else:
                getattr(io, op)(tok)
        except Exception as e:
            attempted.append("%s:%s" % (op, type(e).__name__))
        else:
            attempted.append("%s:LEAK" % op)
    return {"attempted": attempted}


def tool_read_only(io):
    data = io.read("h1")
    outcomes = {"read": data.decode("utf-8")}
    try:
        io.write("h1", b"pwned")
    except Exception as e:
        outcomes["write"] = "refused:%s" % type(e).__name__
    else:
        outcomes["write"] = "LEAK"
    try:
        io.read("h99")
    except Exception as e:
        outcomes["cross"] = "refused:%s" % type(e).__name__
    else:
        outcomes["cross"] = "LEAK"
    return outcomes


def tool_no_self_mint(io):
    outcomes = {}
    try:
        Handle(None, None, 999)  # noqa: F821 -- must not exist in child
    except NameError:
        outcomes["direct_mint"] = "no-handle-class"
    except Exception as e:
        outcomes["direct_mint"] = "refused:%s" % type(e).__name__
    else:
        outcomes["direct_mint"] = "LEAK"
    try:
        io.read("/etc/passwd")
    except Exception as e:
        outcomes["raw_path"] = "refused:%s" % type(e).__name__
    else:
        outcomes["raw_path"] = "LEAK"
    for attr in ("_registry", "mint", "_MINT_KEY", "executor"):
        try:
            getattr(io, attr)
        except AttributeError:
            outcomes["attr_" + attr] = "absent"
        else:
            outcomes["attr_" + attr] = "LEAK"
    try:
        io.read = lambda t: b"pwned"  # noqa: E731
    except Exception as e:
        outcomes["seal"] = "refused:%s" % type(e).__name__
    else:
        outcomes["seal"] = "LEAK"
    return outcomes


def tool_probe_escape(io, real_secret_path):
    """Full in-child code exec probing for escape. Must find nothing.

    The secret marker is reconstructed from parts so no jail file
    (tool.py, manifest.json) ever contains it contiguously: a scan hit
    would mean the real secret bytes leaked into the jail.
    """
    import os
    marker = "x-marks" + "-the-spot"
    findings = {}
    # (a) absolute-path read of the real deployment secret.
    try:
        with open(real_secret_path, "rb") as f:
            findings["direct_read"] = f.read()[:32]
    except Exception as e:
        findings["direct_read"] = "failed:%s" % type(e).__name__
    # (b) scan the reachable jail for the secret bytes. Bytecode caches
    # are excluded: a .pyc is a mechanical transform of the
    # parent-written tool source (constant folding can rejoin the
    # marker halves), not ungranted secret data. The security question
    # is whether the real secret BYTES are reachable as data.
    seen = []
    system_dirs = {"usr", "bin", "lib", "lib64", "sbin", "etc", "proc",
                   "dev", "sys", "tmp", "var", "opt", "root", "home",
                   "run", "mnt", "media", "srv", "__pycache__"}
    try:
        top = os.listdir("/")
    except Exception as e:
        top = []
        findings["listdir"] = "failed:%s" % type(e).__name__
    for entry in top:
        if entry in system_dirs or entry.startswith("."):
            continue
        path = os.path.join("/", entry)
        try:
            if os.path.isdir(path):
                for sub in os.listdir(path):
                    sp = os.path.join(path, sub)
                    if os.path.isfile(sp):
                        with open(sp, "rb") as f:
                            if marker.encode() in f.read():
                                seen.append(sp)
            elif os.path.isfile(path):
                with open(path, "rb") as f:
                    if marker.encode() in f.read():
                        seen.append(path)
        except Exception:
            continue
    findings["secret_in_jail"] = seen
    return findings


def tool_outbox_bypass(io):
    """Facade bypass: drop a file directly into the outbox under a forged
    token name. The parent commit must refuse it LOUD."""
    with open("/out/h9", "wb") as f:
        f.write(b"bypass-payload")
    return {"dropped": True}


def tool_import_gov(io):
    import gov.capability_grants  # noqa -- must be refused at dispatch
    return "nope"


def tool_writer(io):
    n = io.write("h1", b"committed-by-tool")
    return {"wrote": n}


def tool_reader(io):
    return {"data": io.read("h1").decode("utf-8")}


def tool_net_cred(io, net_token, cred_token):
    # Token positions are canonical (sorted capabilities); the parent
    # passes the right tokens as kwargs -- never hardcode "h1"/"h2".
    return {"net": io.connect(net_token).decode("utf-8"),
            "cred": io.use_credential(cred_token)}


def tool_confused(io, stolen_token):
    try:
        io.write(stolen_token, b"deputy-pwn")
    except Exception as e:
        return {"deputy": "refused:%s" % type(e).__name__}
    return {"deputy": "LEAK"}


def tool_returns_token(io):
    return {"token": "h1"}


def tool_write_then_fail(io):
    io.write("h1", b"should-never-commit")
    raise RuntimeError("boom-after-write")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _p_g1_empty_grant():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for({"filesystem": []})
        # empty manifest category list -> empty grant set, still minted
        assert len(grants) == 0
        res = w.dispatcher.dispatch(tool_empty_grant, grants,
                                    decision_id=did)
        assert res.ok, res.error
        body = res.result["attempted"]
        assert all(":LEAK" not in a for a in body), body
        assert len(res.refusals) == 4, res.refusals
        assert w.read_secret_bytes() == b"x-marks-the-spot"
        return True, "empty grants: 4/4 refused, tool returned cleanly"
    finally:
        w.cleanup()


def _p_g2_read_no_write():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["read-secret"]})
        res = w.dispatcher.dispatch(tool_read_only, grants,
                                    decision_id=did)
        assert res.ok, res.error
        out = res.result
        assert out["read"] == "x-marks-the-spot", out
        assert out["write"].startswith("refused"), out
        assert out["cross"].startswith("refused"), out
        assert w.read_secret_bytes() == b"x-marks-the-spot"
        assert res.writes_committed == []
        return True, "read held; write + cross-token refused, nothing committed"
    finally:
        w.cleanup()


def _p_g3_no_self_mint():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for({"filesystem": []})
        res = w.dispatcher.dispatch(tool_no_self_mint, grants,
                                    decision_id=did)
        assert res.ok, res.error
        out = res.result
        assert out["direct_mint"] == "no-handle-class", out
        assert out["raw_path"].startswith("refused"), out
        assert all(v == "absent" for k, v in out.items()
                   if k.startswith("attr_")), out
        assert out["seal"].startswith("refused"), out
        return True, "no mint path, no raw paths, facade sealed"
    finally:
        w.cleanup()


def _p_g4_adversarial():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        # (a)+(b): escape probing with full in-child code exec, run with
        # EMPTY grants so no secret bytes are legitimately staged.
        grants, _allow, did = w.grants_for({"filesystem": []})
        res = w.dispatcher.dispatch(
            tool_probe_escape, grants, decision_id=did,
            kwargs={"real_secret_path": w.secret_path})
        assert res.ok, res.error
        f = res.result
        assert isinstance(f["direct_read"], str) and \
            f["direct_read"].startswith("failed"), f
        assert f["secret_in_jail"] == [], f
        # (c): facade bypass into the outbox must fail the dispatch
        # LOUD at commit -- the child dropped /out/h9, which matches no
        # dispatched token.
        grants2, _a2, did2 = w.grants_for({"filesystem": []})
        bypassed = True
        try:
            w.dispatcher.dispatch(tool_outbox_bypass, grants2,
                                  decision_id=did2)
        except GrantError as e:
            assert "h9" in str(e), str(e)
            bypassed = False
        if bypassed:
            return False, "GAP: facade bypass was not refused at commit"
        assert w.read_secret_bytes() == b"x-marks-the-spot"
        # (d) `import gov` in tool source refuses at dispatch validation.
        grants3, _a3, did3 = w.grants_for({"filesystem": []})
        gov_imported = True
        try:
            w.dispatcher.dispatch(tool_import_gov, grants3,
                                  decision_id=did3)
        except GrantRefused:
            gov_imported = False
        if gov_imported:
            return False, "GAP: tool importing gov was not refused"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "commit-unknown-token" in kinds, kinds
        return True, ("adversarial child: absolute read failed, secret "
                      "absent from jail, outbox bypass refused loud at "
                      "commit, gov import refused")
    finally:
        w.cleanup()


def _p_g5_attenuation():
    if _ABSENT:
        return _GAP
    import random
    w = _World()
    try:
        rng = random.Random(20260929)
        caps = [Capability("file", w.secret_path, {"read", "write"}),
                Capability("file", w.write_path, {"read"}),
                Capability("net", "api.example.com", {"connect"}),
                Capability("credential", "payments:refund", {"use"})]
        base = GrantSet(caps)
        for _ in range(200):
            sub = base.attenuate(lambda c: rng.random() < 0.5)
            assert sub.is_subset_of(base), "attenuation widened"
            sub2 = sub.attenuate(lambda c: rng.random() < 0.5)
            assert sub2.is_subset_of(sub), "re-attenuation widened"
            assert sub2.is_subset_of(base), "transitive widening"
        narrow = caps[0].attenuate({"read"})
        assert narrow.rights == frozenset({"read"})
        try:
            caps[0].attenuate(set())
        except GrantError:
            pass
        else:
            return False, "GAP: attenuation to empty rights allowed"
        # digest determinism: same set, two mints -> same digest
        g1 = w.registry.mint(caps, decision_id=w.decide())
        g2 = w.registry.mint(caps, decision_id=w.decide())
        assert g1.digest() == g2.digest()
        assert g1.grant_id != g2.grant_id, "ids must be unique per mint"
        return True, "200 random attenuations never widen; digests deterministic"
    finally:
        w.cleanup()


def _p_g6_delegation():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["readwrite-secret"],
             "tools": ["tool_reader"]})
        # Legal: delegate a read-only narrowing to the allowlisted
        # sub-tool. Narrowing happens at the Capability level; the
        # GrantSet predicate only filters.
        sub = GrantSet([c.attenuate({"read"}) for c in grants
                        if c.kind == "file"])
        res = w.dispatcher.delegate(
            caller_grant_id=grants.grant_id,
            caller_allowlist=["tool_reader"],
            sub_tool_fn=tool_reader, sub_grants=sub, decision_id=did)
        assert res.ok, res.error
        assert res.result["data"] == "x-marks-the-spot", res.result
        # Illegal: widen beyond the caller's grants.
        evil = GrantSet([Capability("file", w.write_path, {"read"})])
        try:
            w.dispatcher.delegate(
                caller_grant_id=grants.grant_id,
                caller_allowlist=["tool_reader"],
                sub_tool_fn=tool_reader, sub_grants=evil,
                decision_id=did)
        except GrantRefused:
            pass
        else:
            return False, "GAP: delegation widened beyond caller grants"
        # Illegal: sub-tool not on the allowlist.
        try:
            w.dispatcher.delegate(
                caller_grant_id=grants.grant_id,
                caller_allowlist=["tool_reader"],
                sub_tool_fn=tool_writer, sub_grants=sub,
                decision_id=did)
        except GrantRefused:
            pass
        else:
            return False, "GAP: non-allowlisted sub-tool delegated"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "delegation-would-widen" in kinds, kinds
        assert "delegation-not-allowlisted" in kinds, kinds
        return True, "subset delegation works; widening + allowlist refused loud"
    finally:
        w.cleanup()


def _p_g7_confused_deputy():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants_a, _aa, did_a = w.grants_for(
            {"filesystem": ["write-out"]})
        res_a = w.dispatcher.dispatch(tool_returns_token, grants_a,
                                      decision_id=did_a)
        assert res_a.ok
        stolen = res_a.result["token"]
        grants_b, _ab, did_b = w.grants_for({"filesystem": []})
        res_b = w.dispatcher.dispatch(
            tool_confused, grants_b, decision_id=did_b,
            kwargs={"stolen_token": stolen})
        assert res_b.ok, res_b.error
        assert res_b.result["deputy"].startswith("refused"), res_b.result
        with open(w.write_path, "rb") as f:
            assert f.read() == b"original", "deputy wrote!"
        return True, "stolen token without grant membership refused"
    finally:
        w.cleanup()


def _p_g8_positive_path():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["write-out"]})
        res = w.dispatcher.dispatch(tool_writer, grants,
                                    decision_id=did)
        assert res.ok, res.error
        assert res.result["wrote"] == len(b"committed-by-tool")
        with open(w.write_path, "rb") as f:
            assert f.read() == b"committed-by-tool", "write not committed"
        assert len(res.writes_committed) == 1
        grants2, _a2, did2 = w.grants_for(
            {"egress": ["api"], "secrets": ["refund"]})
        # Tokens are positional over the canonical capability order;
        # resolve them parent-side and pass them as kwargs.
        toks = {}
        for i, cap in enumerate(grants2, start=1):
            toks[cap.kind] = "h%d" % i
        res2 = w.dispatcher.dispatch(
            tool_net_cred, grants2, decision_id=did2,
            kwargs={"net_token": toks["net"],
                    "cred_token": toks["credential"]})
        assert res2.ok, res2.error
        assert res2.result["net"] == "CANNED-OK", res2.result
        assert res2.result["cred"] == "secret-id:payments:refund"
        return True, "write committed; net canned; credential sentinel"
    finally:
        w.cleanup()


def _p_g9_single_use():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["read-secret"]})
        res = w.dispatcher.dispatch(tool_reader, grants,
                                    decision_id=did)
        assert res.ok
        try:
            w.dispatcher.dispatch(tool_reader, grants, decision_id=did)
        except GrantRefused:
            pass
        else:
            return False, "GAP: grant set dispatched twice"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "grant-already-consumed" in kinds, kinds
        return True, "second dispatch refused: grant-already-consumed"
    finally:
        w.cleanup()


def _p_g10_unminted():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        handmade = GrantSet(
            [Capability("file", w.secret_path, {"read"})])
        assert handmade.grant_id is None
        try:
            w.dispatcher.dispatch(tool_reader, handmade,
                                  decision_id=w.decide())
        except GrantRefused:
            pass
        else:
            return False, "GAP: hand-built grant set dispatched"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "grant-not-minted" in kinds, kinds
        return True, "hand-built grant set refused: grant-not-minted"
    finally:
        w.cleanup()


def _p_g11_unbound_label():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        try:
            w.grants_for({"filesystem": ["no-such-label"]})
        except GrantRefused:
            pass
        else:
            return False, "GAP: unbound label derived grants"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "unbound-grant-label" in kinds, kinds
        return True, "unbound label refused loud + audit-logged"
    finally:
        w.cleanup()


def _p_g12_bad_approval():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        manifest = {"skill_id": "s",
                    "capabilities": {"filesystem": ["read-secret"]}}
        for bad in ({"approval_id": "a"},  # no record digest
                    {"approval_id": "a", "record_digest": "zz"},
                    "not-a-dict"):
            try:
                derive_grants(verified_manifest=manifest,
                              grant_policy=w.policy, approval=bad,
                              decision_id=w.decide(),
                              registry=w.registry)
            except GrantMintError:
                continue
            return False, "GAP: bad approval minted grants: %r" % (bad,)
        return True, "approval without record digest refuses (BOM discipline)"
    finally:
        w.cleanup()


def _p_g13_grant_digest_bom():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["read-secret"]})
        res = w.dispatcher.dispatch(tool_reader, grants,
                                    decision_id=did)
        assert res.ok
        section = res.bom_section()
        assert section["decision_id"] == did
        assert section["capability_count"] == 1
        # Auditor re-derivation holds...
        described = w.registry.describe_grants(res.grant_id)
        assert verify_grant_digest(section["grant_digest"], described)
        # ...and tampering fails.
        assert not verify_grant_digest("00" * 32, described)
        assert not verify_grant_digest(section["grant_digest"],
                                       described + [{"kind": "file",
                                                     "resource": "/x",
                                                     "rights": ["read"]}])
        # The section rides build_bom and passes the shape check.
        bom = build_bom(
            policy_id="p", policy_version="1",
            policy_digest="ab" * 32, evidence_head_digest="cd" * 32,
            principal={"agent_id": "a", "role": "r", "principal": "p",
                       "run_id": "r"},
            tool_grants=section)
        ok, reason = check_bom_shape(bom)
        assert ok, reason
        assert bom["inputs"]["grants"]["grant_digest"] == \
            section["grant_digest"]
        # Partial section refuses loud.
        try:
            build_bom(policy_id="p", policy_version="1",
                      policy_digest="ab" * 32,
                      evidence_head_digest="cd" * 32,
                      principal={"agent_id": "a", "role": "r",
                                 "principal": "p", "run_id": "r"},
                      tool_grants={"grant_digest": "ab" * 32})
        except Exception:
            pass
        else:
            return False, "GAP: partial tool_grants built a BOM"
        return True, "digest in BOM, re-derivation holds, tamper fails"
    finally:
        w.cleanup()


def _p_g14_audit_chain():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for({"filesystem": []})
        res = w.dispatcher.dispatch(tool_empty_grant, grants,
                                    decision_id=did)
        assert res.ok
        ok, broken, entries = verify_chain(w.log_path)
        assert ok, (broken, entries)
        assert entries >= 3, entries  # mint + refusals + dispatch
        types = set()
        with open(w.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    import json as _json
                    types.add(_json.loads(line).get("type"))
        assert "capability_grant_refusal" in types, types
        assert "capability_grant_dispatch" in types, types
        return True, "refusals + dispatch chained; chain verifies"
    finally:
        w.cleanup()


def _p_g15_failed_tool_no_commit():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        grants, _allow, did = w.grants_for(
            {"filesystem": ["write-out"]})
        try:
            w.dispatcher.dispatch(tool_write_then_fail, grants,
                                  decision_id=did)
        except GrantError as e:
            assert "no side effects committed" in str(e), str(e)
        else:
            return False, "GAP: failed tool did not raise"
        with open(w.write_path, "rb") as f:
            assert f.read() == b"original", \
                "failed tool's staged write was committed!"
        kinds = [e.get("reason") for e in w.registry.refusals]
        assert "tool-failed-no-commit" in kinds, kinds
        return True, ("tool failed after staging a write: nothing "
                      "committed, refusal audit-logged")
    finally:
        w.cleanup()


def _p_g16_missing_sandbox_layer():
    if _ABSENT:
        return _GAP
    w = _World()
    try:
        from gov.sandbox import Sandbox
        # seccomp is unavailable on this VM: requiring it exercises the
        # real "required layer missing" path -- the child must be
        # stopped BEFORE tool code executes.
        weak = Sandbox(
            timeout=10,
            use_pivot_root=True, require_pivot_root=True,
            use_netns=True, require_netns=True,
            use_pidns=True, require_pidns=True,
            drop_privs=True, require_privdrop=True,
            use_seccomp=True, require_seccomp=True,
            cage_mode="strict")
        disp = GrantDispatcher(w.registry, sandbox=weak,
                               grant_policy=w.policy,
                               staging_parent=w.root)
        grants, _allow, did = w.grants_for(
            {"filesystem": ["write-out"]})
        try:
            disp.dispatch(tool_writer, grants, decision_id=did)
        except GrantError:
            pass
        else:
            return False, ("GAP: dispatch ran without the required "
                           "pivot layer")
        # The tool never executed: its write was never staged, let
        # alone committed.
        with open(w.write_path, "rb") as f:
            assert f.read() == b"original"
        return True, ("missing seccomp layer: dispatch refused before "
                      "tool code ran, nothing committed")
    finally:
        w.cleanup()


_PROBES = (
    ("G1", "EMPTY_GRANT", _p_g1_empty_grant),
    ("G2", "READ_NO_WRITE", _p_g2_read_no_write),
    ("G3", "NO_SELF_MINT", _p_g3_no_self_mint),
    ("G4", "ADVERSARIAL", _p_g4_adversarial),
    ("G5", "ATTENUATION", _p_g5_attenuation),
    ("G6", "DELEGATION", _p_g6_delegation),
    ("G7", "CONFUSED_DEPUTY", _p_g7_confused_deputy),
    ("G8", "POSITIVE_PATH", _p_g8_positive_path),
    ("G9", "SINGLE_USE", _p_g9_single_use),
    ("G10", "UNMINTED", _p_g10_unminted),
    ("G11", "UNBOUND_LABEL", _p_g11_unbound_label),
    ("G12", "BAD_APPROVAL", _p_g12_bad_approval),
    ("G13", "GRANT_DIGEST_BOM", _p_g13_grant_digest_bom),
    ("G14", "AUDIT_CHAIN", _p_g14_audit_chain),
    ("G15", "FAILED_TOOL_NO_COMMIT", _p_g15_failed_tool_no_commit),
    ("G16", "MISSING_SANDBOX_LAYER", _p_g16_missing_sandbox_layer),
)


def main():
    results = []
    for tag, name, fn in _PROBES:
        try:
            run1 = fn()
        except Exception as e:  # harness failure, not a probe verdict
            import traceback
            traceback.print_exc()
            print("%s %s: ERROR (unexpected exception: %r)" % (tag, name, e))
            results.append("ERROR")
            continue
        try:
            run2 = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("%s %s: ERROR (unexpected exception on rerun: %r)"
                  % (tag, name, e))
            results.append("ERROR")
            continue
        if run1[0] != run2[0]:
            print("%s %s: ERROR (verdict changed between runs: %r vs %r)"
                  % (tag, name, run1, run2))
            results.append("ERROR")
            continue
        held, detail = run1
        print("%s %s: %s -- %s" % (tag, name,
                                   "HELD" if held else "GAP", detail))
        results.append("HELD" if held else "GAP")
    held_n = results.count("HELD")
    print("capability-grants: %d/%d HELD" % (held_n, len(results)))
    return 0 if held_n == len(results) else 1


def _green_check():
    """Depth-1 green check: adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for suite in ("tests.test_capability_grants",
                  "tests.test_decision_bom"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                            " | ".join(tail)))
        if r.returncode != 0:
            return False
    return True


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
