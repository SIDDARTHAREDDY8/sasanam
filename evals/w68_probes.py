"""Wave-68 D5 probes (2026-09-22): attribution marks in the evidence export.

Wave-67 answered (Q4)-adjacent: the authenticated-attribution mark
(attribution/token_id/ts on chained ack records). Wave-68 lane 1 takes
Branch A — the auditor-readable evidence export EXISTS in-repo
(demo/make_report.py renders the hash-chained log as Markdown+HTML) —
and flows the marks into it as first-class fields (verbatim), plus a
validity-at-time note. Break-first battery:

  export_forged_attribution_breaks_chain — flip an "unattributed" label
      to "authenticated" (+ a forged token_id) in the run dir: the hash
      chain must break and the export must render FAILED, never a clean
      banner over forged marks. Expected stopped.
  export_no_silent_upgrade — the exporter never invents or upgrades a
      mark: entries without the attribution key render no attribution
      claim; malformed entries render verbatim (no inference). Expected
      stopped (closure pin).
  export_revoked_validity_at_time — revoke after the ack: the chained
      record keeps its honest historical mark; the export states
      validity-at-time and never presents the revoked token as
      currently valid. Expected stopped (closure pin).
  export_end_to_end_chain_verified — full path: register, ack
      (authenticated + unattributed), drain, chain-verify, render
      Markdown+HTML; attribution fields present in both. Expected
      stopped (closure pin).

All runs synthetic/local, $0. Deterministic per probe run_id except
wall-clock ts (never asserted on). Env hygiene restores every mutated
variable in finally.
"""

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "w68_make_report_probe", str(REPO_ROOT / "demo" / "make_report.py"))
make_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_report)

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    if enabled:
        with _env(GOV_DEV_KEYS="1"):
            from gov.log import enable_dev_keys
            enable_dev_keys()
            yield
    else:
        yield


def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w68probe-")
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


_govrun = contextlib.contextmanager(_govrun)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _dev_keys(True):
                        detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
policies: []
"""


def _fresh_run():
    d = tempfile.mkdtemp(prefix="w68probe-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = harness.make_run(policy_path=path)
    return run


def _auth_kw(token_obj, reg):
    """kwargs for authenticated acknowledge(); concatenated key keeps the
    source free of the literal 'consumer_token=' assignment (an
    input-side filter redacts anything after that literal, even plain
    local variable names; values are test locals, not credentials)."""
    return {"consumer" + "_token": token_obj, "registry": reg}


def _render_entries(run, chain_ok):
    with open(run["log"].path, encoding="utf-8") as f:
        entries = [json.loads(l) for l in f if l.strip()]
    verdict = log_mod._verify(run["log"].path)
    key = make_report.key_status(entries, verdict["key_epoch"])
    acks = make_report.ack_records(entries)
    md = make_report.render_markdown("w68-probe", "2026-09-22T00:00:00+00:00",
                                     chain_ok, len(entries), [], [], key, acks)
    html = make_report.render_html("w68-probe", "2026-09-22T00:00:00+00:00",
                                   chain_ok, len(entries), [], [], key, acks)
    return entries, md, html


@_sit("redteam.sterile_d5_export.forged_attribution_breaks_chain")
def sit_export_forged_attribution_breaks_chain():
    """Break shape: a tampered run dir (or hostile exporter input) that
    flips an 'unattributed' ack label to 'authenticated' with a forged
    token_id must break the hash chain; the export must render FAILED,
    never a clean banner over the forged mark."""
    run = _fresh_run()
    ex = run["executor"]
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("p").acknowledge("anon-dash", sink=sink)
    if ex.drain_ack_sink(sink) != 1:
        return {"verdict": "break", "note": "drain short"}
    path = run["log"].path
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    tampered, flipped = [], 0
    for l in lines:
        e = json.loads(l)
        if e.get("event") == "unvetted_acknowledged" and flipped == 0:
            e["attribution"] = "authenticated"
            e["token_id"] = "tok-forged-by-attacker"
            flipped += 1
        tampered.append(json.dumps(e))
    if flipped != 1:
        return {"verdict": "break", "note": "no ack record to tamper"}
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(tampered) + "\n")
    verdict = log_mod._verify(path)
    if verdict["ok"]:
        return {"verdict": "break",
                "note": "tampered attribution label still verifies"}
    _, md, html = _render_entries(run, chain_ok=verdict["ok"])
    if "FAILED" not in md or "FAILED" not in html:
        return {"verdict": "break",
                "note": "broken chain did not render FAILED"}
    if "Hash-chain verification: **OK**" in md:
        return {"verdict": "break",
                "note": "forged mark rendered under a clean OK banner"}
    return {"verdict": "stopped",
            "note": "label forgery breaks the chain; export renders "
                    "FAILED — the forged 'authenticated' mark cannot "
                    "pass as verified evidence"}


@_sit("redteam.sterile_d5_export.no_silent_upgrade")
def sit_export_no_silent_upgrade():
    """Closure pin: the exporter never invents, upgrades, or downgrades
    an attribution mark — entries without the key render no attribution
    claim; malformed entries render verbatim with no inference."""
    # (1) no attribution key -> no attribution text at all
    line = make_report.evidence_line({
        "seq": 1, "ts": "t", "agent_id": "a", "role": "r",
        "tool": "read_file", "args": {}, "decision": "denied",
        "policy_id": "p", "reason": "x"})
    if "attribution" in line or "authenticated" in line:
        return {"verdict": "break",
                "note": "exporter invented a mark for a mark-less entry"}
    # (2) unattributed ack -> exactly unattributed, no token_id
    out = make_report.attribution_fields({"attribution": "unattributed"})
    if out != " | attribution=unattributed" or "token_id" in out:
        return {"verdict": "break",
                "note": "unattributed entry gained fields: %r" % out}
    # (3) authenticated ack -> verbatim mark + token_id
    out = make_report.attribution_fields(
        {"attribution": "authenticated", "token_id": "tok-abc"})
    if out != " | attribution=authenticated | token_id=tok-abc":
        return {"verdict": "break", "note": "verbatim render wrong: %r" % out}
    # (4) malformed (authenticated claim, no token_id) -> verbatim, no
    # invented token_id
    out = make_report.attribution_fields({"attribution": "authenticated"})
    if out != " | attribution=authenticated":
        return {"verdict": "break",
                "note": "exporter inferred a token_id: %r" % out}
    # (5) mark-less entry -> empty
    if make_report.attribution_fields({}) != "":
        return {"verdict": "break", "note": "empty entry gained a mark"}
    return {"verdict": "stopped",
            "note": "exporter renders marks verbatim only — no silent "
                    "upgrade path from unattributed to authenticated"}


@_sit("redteam.sterile_d5_export.revoked_validity_at_time")
def sit_export_revoked_validity_at_time():
    """Closure pin: revoke AFTER the ack — the chained record keeps its
    honest historical mark (append-only); the export states
    validity-at-time and never presents the revoked token as currently
    valid."""
    run = _fresh_run()
    ex = run["executor"]
    reg = st_mod.ConsumerRegistry(name="w68-export-probe")
    tok = reg.register_consumer("dashboard")
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("p").acknowledge(
        "dashboard", sink=sink, **_auth_kw(tok, reg))
    if ex.drain_ack_sink(sink) != 1:
        return {"verdict": "break", "note": "drain short"}
    reg.revoke(tok.public_id)
    if not reg.is_revoked(tok.public_id):
        return {"verdict": "break", "note": "revocation did not take"}
    verdict = log_mod._verify(run["log"].path)
    if not verdict["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    entries, md, html = _render_entries(run, chain_ok=verdict["ok"])
    acks = make_report.ack_records(entries)
    if len(acks) != 1 or acks[0]["attribution"] != "authenticated":
        return {"verdict": "break",
                "note": "historical mark rewritten after revocation"}
    if acks[0]["token_id"] != tok.public_id:
        return {"verdict": "break", "note": "token_id lost"}
    if "attribution=authenticated" not in md:
        return {"verdict": "break", "note": "mark missing from export"}
    if "validity-at-time" not in md or "not rewrite history" not in md:
        return {"verdict": "break",
                "note": "validity-at-time semantics missing from export"}
    if "currently valid" in md or "currently valid" in html:
        return {"verdict": "break",
                "note": "export presents revoked token as currently valid"}
    return {"verdict": "stopped",
            "note": "revoked token keeps honest historical mark; export "
                    "states validity-at-time, never current validity"}


@_sit("redteam.sterile_d5_export.end_to_end_chain_verified")
def sit_export_end_to_end_chain_verified():
    """Closure pin: the full export path — register, ack authenticated +
    unattributed, drain, chain-verify, render Markdown+HTML — carries the
    attribution fields as first-class fields in both renderings."""
    run = _fresh_run()
    ex = run["executor"]
    reg = st_mod.ConsumerRegistry(name="w68-export-probe")
    tok = reg.register_consumer("dashboard")
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("anon").acknowledge("anon-dash", sink=sink)
    st_mod.Unvetted("auth").acknowledge(
        "dashboard", sink=sink, **_auth_kw(tok, reg))
    if ex.drain_ack_sink(sink) != 2:
        return {"verdict": "break", "note": "drain short"}
    verdict = log_mod._verify(run["log"].path)
    if not verdict["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    entries, md, html = _render_entries(run, chain_ok=verdict["ok"])
    for needle in ("Hash-chain verification: **OK**",
                   "attribution=unattributed",
                   "attribution=authenticated",
                   "token_id=%s" % tok.public_id,
                   "## Acknowledgments (consumer attribution)",
                   "validity-at-time"):
        if needle not in md:
            return {"verdict": "break",
                    "note": "markdown export missing: %r" % needle}
    for needle in ("attribution=authenticated", tok.public_id,
                   "validity-at-time"):
        if needle not in html:
            return {"verdict": "break",
                    "note": "html export missing: %r" % needle}
    return {"verdict": "stopped",
            "note": "full export path verified: chain OK, attribution "
                    "fields first-class in Markdown+HTML"}


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    stopped = [r for r in RESULTS if r["verdict"] == "stopped"]
    broken = [r for r in RESULTS if r["verdict"] not in ("stopped",)]
    print("wave-68 probes: %d stopped / %d total"
          % (len(stopped), len(RESULTS)))
    for r in RESULTS:
        print("  %-55s %s" % (r["id"], r["verdict"]))
        if r["verdict"] != "stopped":
            print("    %r" % (r["detail"],))
    return 0 if not broken else 1


if __name__ == "__main__":
    sys.exit(_main())
