"""Approval-queue web UI: localhost operator console (stdlib only).

Promoted into ``gov/`` from ``workstreams/platform/approval_web.py``
(P4, Architect ROADMAP decision). Pages:

    GET  /                      pending queue (highest risk first) + history
    GET  /approvals/<id>        request detail + approve/deny form
    POST /approvals/<id>/decide record the decision
    POST /approvals/<id>/delegate  delegate the decision right (D1-core)
    POST /approvals/<id>/vote      cast a quorum vote (D1-core)
    GET  /audit                 read-only audit trail (newest first)
    GET  /login  POST /login    unlock with the startup token
    POST /logout                destroy the session

D1 PLUGGABILITY SEAM (QueuePort). The presentation layer talks to the
queue through exactly this public surface — no private queue members:

    ApprovalQueue(run_dir, log)          # or inject ``queue=`` into
                                         # ApprovalWebApp / make_server
    queue.run_id
    queue.get(approval_id) -> record | None
    queue.all() -> [record]
    queue.pending_risk_sorted() -> [record]
    queue.risk_detail(record) -> {score, level, factors}
    queue.delegation_enabled -> bool
    queue.set_delegation_config(cfg)
    queue.decide(approval_id, approved, reason, decided_by) -> (rec, entry)
    queue.delegate(approval_id, to, reason, delegated_by)
    queue.cast_vote(approval_id, approve, reason, voter_identity)
    queue.locked(timeout) -> context manager   # the transaction seam
                                               # (F39/F44 lock)

An AGT/AgentCore adapter drives the console by implementing this
surface (wrapping its own queue or delegating to ``ApprovalQueue``)
and passing it as ``queue=``. Web-layer invariants that must hold for
ANY port implementation: decisions/delegations/votes go through the
canonical queue methods under ``locked()``; the web layer never
supplies tool/args/identity/policy fields (re-read from the record);
``decided_by`` stays the distinct ``web/human-operator`` label; every
refusal is audit-logged as ``web_*``. Next step for the architect:
constructor injection exists; a formal ``typing.Protocol`` for
QueuePort is still to be written.

Security properties (unchanged from the hardened prototype):

* **Canonical decision path.** The POST handler reads ONLY
  ``decision`` / ``reason`` / ``csrf`` (+ the session cookie) from the
  request. Tool, args, identity, and policy fields are NEVER taken from
  the form: the record is re-read from the queue and the decision goes
  through ``ApprovalQueue.decide()`` — the exact method the CLI uses —
  under the queue lock, so the F38/F43 digest check, separation of
  duties, pending-state check, and the tamper-evident
  ``approval_decision`` audit entry cannot be bypassed. The web layer
  cannot approve anything the CLI could not.
* **Authentication (local minimum).** A random token is generated at
  startup and printed to the operator's terminal (``--token`` overrides
  for tests). Presenting it once mints a server-side session
  (``HttpOnly; SameSite=Strict`` cookie, 8h TTL). Every other route
  requires the session. Sessions are **in-memory only** (``self.sessions``):
  they do not survive restart, they are not shared across processes,
  and there is no SSO/OIDC/mTLS. Do not claim production identity
  integration — this console is a localhost tool, not an IAM system.
* **Distinct web audit labeling (Architect decision).** Web decisions
  are recorded with ``decided_by="web/human-operator"``
  (``gov.approval_web.WEB_DECIDED_BY``), not the CLI's
  ``"human-operator"``, so forensics can distinguish web-console
  decisions from CLI decisions in the audit log and in the re-MACed
  record digest. The label is still a human-operator label (never an
  agent id), so separation-of-duties semantics are unchanged.
* **Break-glass via web is out of scope (Architect decision).**
  Records carrying the ``break_glass`` flag are rendered read-only;
  POSTing a decision for one is refused (409 + ``web_decision_refused``
  audit) with a pointer to the CLI. Break-glass provisioning,
  ticket redemption, and emergency decisions stay CLI-only.
* **D1-core delegation + quorum (web principal binding).** The web
  session binds a single operator principal — ``WEB_DECIDED_BY``
  (``"web/human-operator"``), the same distinct label web decisions
  already carry. It is the terminal-access trust root's principal:
  ``POST /approvals/<id>/delegate`` delegates with
  ``delegated_by=<session principal>`` and ``POST
  /approvals/<id>/vote`` casts a quorum vote as a server-side-minted
  ``AgentIdentity(principal=<session principal>)`` (never a
  form-supplied principal — the form carries only ``to``/``vote``/
  ``reason``/``csrf``). Both routes go through the canonical queue
  methods (``ApprovalQueue.delegate()`` / ``cast_vote()``) under the
  queue lock, with the same session → origin → CSRF gates as decide,
  and refusals audit as ``web_delegate_refused`` / ``web_vote_refused``
  (409). The detail page renders the DELEGATED substate (assignee +
  chain), the QUORUM_COLLECTING substate (live tally vs the MACed
  snapshot, vote rows), and bridge-expiry markers — every value
  ``html.escape``d. Quorum-collecting records get a vote form, not a
  decide form (``decide()`` would refuse with ``quorum_direct_decide``).
* **CSRF.** Every decision form AND the logout form carry a
  per-session token compared with ``hmac.compare_digest``; POSTs
  additionally require a same-origin ``Origin``/``Referer`` when
  present. A forged cross-site ``POST /logout`` is refused (403)
  WITHOUT destroying the session, and the refusal is audit-logged
  as ``web_csrf_failure``. GETs never mutate.
* **Fail closed.** Corrupt queue data or a corrupt queue lock turns
  list/decide into 500/503 refusals — never a partial render, never a
  decision. Replays hit the canonical pending-state check (409).
* **Output safety.** All rendered values are ``html.escape``d; the
  agent justification is labeled UNVERIFIED; the args view is the
  bounded canonical bytes + ``args_sha256`` (same semantics as the
  CLI's decision-target view).
* **Queue-health advisory panel (wave-27, P4/F4).** The list page
  renders the queue's advisory fatigue/anomaly clusters
  (``queue_anomalies()``: fatigue bursts, rate spikes, unusual tool
  mix) with linked cluster members; the detail page banners a record
  that belongs to a cluster. READ-ONLY and strictly advisory: the
  panel and banner never approve, deny, reorder, or mutate records —
  they escalate operator attention only (the F4 detector's contract).
  The panel degrades silently when a QueuePort double does not
  implement ``queue_anomalies`` or detection raises; the per-record
  ``flood_suspect`` flags (set at queue time) still render. All
  port-supplied cluster fields are escaped and normalized at the
  render boundary (unknown/malformed output is dropped).
* **Bridge badge (wave-25, D1).** Records carrying a verifiable
  ``bridge_id`` render with a ``bridge:<id>`` badge in the queue list
  and a read-only foreign-bridge panel on the detail page (adapter
  identity, ``external_request_id``, bridge wait state, foreign
  request digest, foreign versions). A ``bridge_expired`` record is
  rendered unmistakably (red banner, no decide/delegate forms — a
  late decision would be audit-only per T11 and can never execute
  per T12/F85). Bridge markers WITHOUT a verifiable ``bridge_id``
  render an explicit UNVERIFIED BRIDGE warning, never a badge and
  never a normal record. Foreign digests/versions are informational
  tamper-evidence, never foreign attestation.
* **Framing mediation (K-028, wave-25).** The approver is a human
  attack surface: justification, preview, and args (which may embed
  tool output) can carry instructions aimed at the approver. They
  render inside a labeled UNTRUSTED quarantine zone, separated from
  the governor-verified facts (risk, policy verdict, digest, status);
  the preview is labeled by origin (executor-generated vs foreign
  bridge-generated — neither trusted); the decision form repeats the
  directive to decide on the verified facts only. ``html.escape``
  covers the markup layer; the labels cover the semantic layer.

HONEST LIMITS (what this module does NOT claim):

* In-memory sessions only: no SSO, no OIDC, no mTLS, no session
  persistence, no cross-process session sharing. Single-process
  ``ThreadingHTTPServer``; two console processes do not share logins
  (queue file + lock still serialize the decisions themselves).
* Break-glass, batch decide, and auto-approve are CLI-only; the web
  console offers single approve/deny decisions on non-break-glass,
  non-quorum, non-delegated-away records, plus delegation and quorum
  voting, only.
* No TLS: bind defaults to 127.0.0.1; binding elsewhere is explicitly
  unsupported without TLS + real auth in front.
* Framing mediation is labeling + layout, not a guarantee. The UI
  cannot stop a human from reading an injected instruction in tool
  output and choosing to obey it; it does not detect
  paraphrased/reframed instructions (cf. the Framing Gap literature),
  non-English instruction smuggling, or social engineering outside
  the console. The preview sanitizer escapes non-printable characters
  only (F11) — semantic content passes through by design, which is
  why the preview is labeled UNVERIFIED by origin rather than
  "cleaned".
* The queue-health panel and cluster banner are advisory only —
  they implement none of the detector's authority. The F4 detector
  is heuristic: it can miss slow-drip fatigue floods below its
  thresholds and can flag legitimate bursts (false positives), and
  it is computed at render time from the same queue file the
  operator is already reading. A missing panel is not evidence of a
  calm queue when the detector itself is unavailable (QueuePort
  double without ``queue_anomalies``, or a detection error).
* Single operator principal: every web session acts as
  ``web/human-operator``. There is no per-human login — a deployment
  that needs named-human quorum votes must extend the login (and list
  ``web/human-operator`` in ``eligible_principals`` only if the
  token-holder should hold a vote slot).
* The tested claim is the adversarial battery in
  ``tests/test_gov_approval_web.py`` (33 tests: unauthenticated / CSRF /
  cross-origin / replay / tampered-form / corrupt-queue / corrupt-lock /
  XSS situations, including the F80 logout-CSRF battery), the D1
  surfaces in ``tests/test_approval_web_d1.py`` (31 tests), the
  wave-23 additions in ``tests/test_approval_web_durability.py``
  (21 tests: F83 crash-durability probes, cross-session CSRF replay
  on the delegate/vote routes, the read-only audit view, session
  properties, and the QueuePort seam), and the wave-25 bridge-badge /
  framing-mediation surfaces in ``tests/test_approval_web_bridge.py``
  (14 tests: badge/panel/expired/unverified rendering, escaping of
  bridge fields, quarantine zone, preview provenance labels, audit
  untrusted-quote note), and the wave-27 queue-health advisory
  surfaces in ``tests/test_approval_web_anomaly.py`` — nothing more.
  Production
  deployments need the deployment contract in the Architect's P4 entry
  (real auth, TLS, KMS-backed log key).

No third-party dependencies, no JavaScript, no build step.
"""

import argparse
import hmac
import html
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


if __package__ in (None, ""):
    # Run as a script (``python gov/approval_web.py ...``): make the
    # repo root importable so ``gov`` resolves. Imported as
    # ``gov.approval_web``, the package is already on the path and
    # this branch is skipped.
    _repo_root = str(Path(__file__).resolve().parent.parent)
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

from gov.approvals import (  # noqa: E402
    AgentIdentity,
    ApprovalQueue,
    QueueLockError,
    WEB_OPERATOR_LABEL,
    _canonical_dumps,
    _DECISION_TARGET_CAP_BYTES,
    risk_level,
    # S3 shield (wave-89): packet-first rendering + persuasion banners.
    PERSUASION_FLAG_SCORE,
    PERSUASION_RISK_SCORE,
)
from gov import approver_shield as _shield  # noqa: E402  (H19: shield brief)
from gov.log import ActionLog, read_entries_with_stats  # noqa: E402

# Route used by tests (overridable per module for the naive shim).
DECIDE_PATH = "/approvals/{id}/decide"

# Architect decision: web-console decisions carry a distinct
# ``decided_by`` label so the audit log (and the re-MACed record
# digest) forensically distinguishes web decisions from CLI decisions.
# Single-sourced from gov.approvals: the core's delegation authority
# check recognizes both the CLI and web operator labels as the
# human-operator trust root.
WEB_DECIDED_BY = WEB_OPERATOR_LABEL

SESSION_TTL_SECS = 8 * 3600
_QUEUE_LOCK_TIMEOUT_SECS = 10  # web decisions must not hang like sweeps
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _esc(value):
    return html.escape("" if value is None else str(value), quote=True)


class ApprovalWebApp:
    """Server-side state: queue handle, audit log, token, sessions."""

    def __init__(self, run_dir, token=None, policy_path=None, queue=None):
        self.run_dir = Path(run_dir)
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        # D1 PLUGGABILITY SEAM: the presentation layer talks to the
        # queue ONLY through the QueuePort surface documented in this
        # module's docstring. ``queue`` lets an external driver (e.g.
        # an AGT/AgentCore adapter, or a test double) supply its own
        # port implementation; the default builds the canonical
        # ``ApprovalQueue`` for this run dir.
        self.queue = queue if queue is not None else ApprovalQueue(
            self.run_dir, self.log)
        # D1-core: install the run policy's delegation section so the
        # web delegate route enforces the same control the CLI does.
        # Without --policy, delegation stays off (fail closed) and the
        # delegate form is not rendered. Quorum needs no config here:
        # votes are checked against each record's MACed snapshot.
        if policy_path is not None:
            from gov.policy import PolicyEngine
            policy = PolicyEngine(policy_path)
            self.queue.set_delegation_config(policy.approvals_delegation)
        self.token = token if token is not None else secrets.token_urlsafe(32)
        self.generated_token = token is None
        # session_id -> {"csrf": str, "created": float,
        #                "principal": WEB_DECIDED_BY}. The session binds
        # ONE operator principal (the terminal-access trust root):
        # votes and delegations from this console act as that
        # principal, never as a form-supplied name.
        self.sessions = {}
        self._sessions_lock = threading.Lock()

    # -- auth ---------------------------------------------------------
    def check_token(self, presented):
        return hmac.compare_digest(self.token, presented or "")

    def new_session(self):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._sessions_lock:
            self._prune_locked()
            self.sessions[sid] = {"csrf": csrf, "created": time.time(),
                                  "principal": WEB_DECIDED_BY}
        return sid, csrf

    def create_test_session(self):
        """Test-only helper: mint a session without the login round-trip."""
        sid, csrf = self.new_session()
        return "session=" + sid, csrf

    def get_session(self, cookie_header):
        sid = None
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name.strip() == "session":
                sid = value.strip()
                break
        if not sid:
            return None
        with self._sessions_lock:
            sess = self.sessions.get(sid)
            if sess is None:
                return None
            if time.time() - sess["created"] > SESSION_TTL_SECS:
                del self.sessions[sid]
                return None
            return {"id": sid, "csrf": sess["csrf"],
                    "principal": sess.get("principal", WEB_DECIDED_BY)}

    def destroy_session(self, cookie_header):
        sess = self.get_session(cookie_header)
        if sess is None:
            return
        with self._sessions_lock:
            self.sessions.pop(sess["id"], None)

    def _prune_locked(self):
        now = time.time()
        dead = [sid for sid, s in self.sessions.items()
                if now - s["created"] > SESSION_TTL_SECS]
        for sid in dead:
            del self.sessions[sid]

    # -- audit ----------------------------------------------------------
    def audit(self, event, approval_id=None, reason="", decision="refused"):
        """Best-effort audit entry for web-layer refusals. Never raises:
        a logging outage must not turn a refusal into an approval."""
        entry = {
            "event": event,
            "run_id": self.queue.run_id,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "decision": decision,
            "policy_id": "approval-web-ui",
            "reason": reason,
        }
        if approval_id is not None:
            entry["approval_id"] = approval_id
        try:
            self.log.append(entry)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTML rendering (every interpolated value is escaped at the boundary)
# ---------------------------------------------------------------------------

_CSS = ("body{font-family:sans-serif;max-width:72rem;margin:2rem auto;"
        "padding:0 1rem;color:#1a1a1a} table{border-collapse:collapse;"
        "width:100%} th,td{border:1px solid #ccc;padding:.4rem .6rem;"
        "text-align:left;vertical-align:top} th{background:#f0f0f0}"
        " .risk-critical{color:#a00;font-weight:bold} .risk-high{color:#c60}"
        " .warn{background:#fff3cd;padding:.5rem;border:1px solid #e0c36a}"
        " .err{background:#f8d7da;padding:.5rem;border:1px solid #e0a3a8}"
        " .bridge-badge{background:#e8f0fe;border:1px solid #5b8def;"
        "padding:.15rem .5rem;font-weight:bold;white-space:nowrap}"
        " .untrusted-zone{border:2px dashed #b26a00;padding:.5rem;"
        "margin-top:1rem}"
        " .anomaly-panel{border:1px solid #e0c36a;background:#fffdf5;"
        "padding:.5rem 1rem;margin-bottom:1rem}"
        " pre{background:#f6f6f6;padding:.6rem;overflow:auto}"
        " .unverified{color:#666;font-style:italic}")


def _page(title, body, csrf=None):
    """Render a page shell.

    ``csrf`` is the per-session token. When provided, the logout
    form carries it as a hidden field so the ``POST /logout`` handler
    can require it (F80) — exactly like the decision forms. Pages
    rendered without a session (login, unauthenticated 404s) pass no
    token, so their logout button cannot be honored by a forged
    POST; it is a cosmetic convenience for logged-out browsers.
    """
    if csrf is None:
        logout = ("<form method='POST' action='/logout' "
                  "style='display:inline'>"
                  "<button type='submit'>log out</button></form>")
    else:
        logout = ("<form method='POST' action='/logout' "
                  "style='display:inline'>"
                  "<input type='hidden' name='csrf' value='%s'>"
                  "<button type='submit'>log out</button></form>"
                  % _esc(csrf))
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>%s</title><style>%s</style></head>"
            "<body><h1>%s</h1>%s"
            "<p><a href='/'>queue</a> | <a href='/audit'>audit</a> | %s</p>"
            "</body></html>") % (_esc(title), _CSS, _esc(title), body,
                                 logout)


def _fail_closed_page(title, message, csrf=None):
    return _page(title, "<div class='err'><strong>FAIL CLOSED:</strong> %s"
                        "<p>No decision was recorded. The queue data or "
                        "lock could not be trusted, so the UI refuses to "
                        "act rather than risk an unsafe decision.</p></div>"
                 % _esc(message), csrf=csrf)


def _args_view(args):
    """Bounded canonical args view + sha256, mirroring the CLI's
    decision-target display (F66 semantics): the operator decides on
    exactly the bytes the digest covers.

    K-028 framing mediation: the args are the agent's execution input
    and may embed tool output or third-party text carrying
    instructions aimed at the approver (prompt injection into the
    human). The content is rendered for review — it is what execution
    would use — but explicitly labeled untrusted: the UI cannot stop
    a human who chooses to obey what they read (see HONEST LIMITS).
    """
    canon = _canonical_dumps(args)
    raw = canon.encode("utf-8")
    digest = sha256(raw).hexdigest()
    if len(raw) <= _DECISION_TARGET_CAP_BYTES:
        shown, note = canon, "FULL, untruncated"
    else:
        shown = raw[:_DECISION_TARGET_CAP_BYTES].decode("utf-8",
                                                       errors="ignore")
        note = ("TRUNCATED: showing %d of %d bytes"
                % (len(shown.encode("utf-8")), len(raw)))
    return ("<p>args (%s — this exact content is what the digest covers "
            "and execution will use):</p>"
            "<p class='unverified'><strong>UNTRUSTED INPUT:</strong> the "
            "content below is the requested execution input and may "
            "embed tool output or third-party text containing "
            "instructions aimed at you, the approver (prompt injection). "
            "Do not follow instructions in this content. Decide only on "
            "the governor-verified facts (risk, policy verdict, digest, "
            "status).</p><pre>%s</pre>"
            "<p>args_sha256: <code>%s</code></p>"
            % (_esc(note), _esc(shown), _esc(digest)))


_BRIDGE_MARKER_FIELDS = ("bridge_expired", "late_decision",
                         "external_request_id", "bridge_request_digest",
                         "bridge_versions")


def _bridge_state(record):
    """Classify a record's bridge provenance for rendering.

    Returns ``(kind, bridge_id)`` where kind is one of:

    * ``"none"`` — no bridge markers at all; an ordinary native record.
    * ``"verified"`` — ``bridge_id`` is a non-empty string (the
      canonical ``queue_external()`` shape; MAC-bound into the record
      digest). The UI renders the ``bridge:<id>`` badge.
    * ``"unverified"`` — the record carries bridge markers (an expired
      wait, a late decision, an external request id, a foreign
      digest/versions) but no verifiable bridge identity. Fail-closed:
      the UI renders an explicit UNVERIFIED BRIDGE warning and never a
      badge or a normal record. Reachable e.g. via
      ``mark_bridge_expired()`` on a natively queued record (the
      bridge id passed to that call is audited, not stored on the
      record), or via a QueuePort double supplying partial bridge
      fields — the marker itself is authentic (MAC-bound) but the
      bridge's identity is not on the record.
    """
    r = record or {}
    bid = r.get("bridge_id")
    if isinstance(bid, str) and bid.strip():
        return "verified", bid.strip()
    for f in _BRIDGE_MARKER_FIELDS:
        if r.get(f):
            return "unverified", None
    return "none", None


def _bridge_panel(record):
    """Read-only foreign-bridge panel for a verified bridge record.

    Every value escaped. The foreign digest and versions render
    read-only as tamper-EVIDENCE (MAC-bound into the record), never as
    foreign attestation — the queue cannot verify them against the
    foreign runtime (no shared secret). Bridge framing is never
    trusted (see the UNVERIFIED labels).
    """
    r = record
    bid = r.get("bridge_id")
    versions = r.get("bridge_versions") or {}
    if isinstance(versions, dict):
        versions_html = ", ".join(
            "%s=%s" % (_esc(k), _esc(v)) for k, v in versions.items()
        ) or "(none)"
    else:
        versions_html = _esc(versions)
    if r.get("bridge_expired"):
        state_html = ("<span class='err'><strong>BRIDGE EXPIRED</strong> "
                      "at %s — this record can NEVER execute "
                      "(T12 sweep refusal, F85)</span>"
                      % _esc(r.get("bridge_expired_at")))
    else:
        state_html = ("bridge wait active — the foreign runtime is "
                      "blocked on this decision")
    ext = r.get("external_request_id")
    digest = r.get("bridge_request_digest")
    return (
        "<h2>Foreign bridge "
        "<span class='bridge-badge'>bridge:%s</span></h2>"
        "<table><tr><th>field</th><th>value</th></tr>"
        "<tr><td>bridge adapter</td><td><code>bridge:%s</code> "
        "(foreign runtime; it executes on its side after the human "
        "decides — our executor never runs bridge records)</td></tr>"
        "<tr><td>external request id</td><td><code>%s</code> "
        "(foreign idempotency key)</td></tr>"
        "<tr><td>bridge wait state</td><td>%s</td></tr>"
        "<tr><td>foreign request digest</td><td><code>%s</code> "
        "(read-only; tamper-evidence only, not foreign attestation)"
        "</td></tr>"
        "<tr><td>foreign versions</td><td>%s (read-only)</td></tr>"
        "</table>"
        "<p class='unverified'>Foreign data — UNVERIFIED. The bridge "
        "sanitizes only non-printable characters; the content may "
        "reflect attacker framing. Decide on the governor-verified "
        "facts (risk, policy verdict, digest), not on foreign claims."
        "</p>"
        % (_esc(bid), _esc(bid),
           _esc(ext) if ext else "(none)",
           state_html,
           _esc(digest) if digest else "(none)",
           versions_html))


def _risk_cell(app, record):
    try:
        detail = app.queue.risk_detail(record)
    except Exception:
        return "<td>n/a</td>"
    score, level = detail["score"], detail["level"]
    return ("<td class='risk-%s'>%d (%s)<br><small>%s</small></td>"
            % (_esc(level), score, _esc(level),
               _esc("; ".join(detail["factors"]))))


_ANOMALY_TYPE_LABELS = {
    "fatigue_burst": "FATIGUE-BURST",
    "rate_spike": "RATE-SPIKE",
    "unusual_tool_mix": "TOOL-MIX",
}


def _queue_anomalies(app):
    """Advisory fatigue/anomaly clusters from the queue's F4 detection.

    Normalizes ``queue.queue_anomalies()`` into a list of
    ``{type, summary, items}`` dicts with string values. READ-ONLY:
    never decides, never mutates. Returns [] when the queue surface
    does not implement ``queue_anomalies`` (QueuePort doubles) or when
    detection raises or returns a non-list — the advisory panel
    degrades silently rather than taking the console down. The
    per-record ``flood_suspect`` flags (set at queue time on the write
    path) still render in that case, so the fatigue signal is not
    entirely lost.
    """
    fn = getattr(app.queue, "queue_anomalies", None)
    if fn is None:
        return []
    try:
        anomalies = fn()
    except Exception:
        return []
    if not isinstance(anomalies, list):
        return []
    out = []
    for a in anomalies:
        if not isinstance(a, dict):
            continue
        items = a.get("items")
        out.append({
            "type": str(a.get("type") or "anomaly"),
            "summary": str(a.get("summary") or ""),
            "items": [str(i) for i in items]
            if isinstance(items, (list, tuple)) else [],
        })
    return out


def _anomaly_panel(app):
    """Queue-health advisory panel for the list page (wave-27, P4/F4).

    Renders the queue's advisory anomaly clusters (fatigue bursts,
    rate spikes, unusual tool mix) with linked cluster members so the
    operator reviews each item individually. Strictly advisory: the
    panel never approves, denies, reorders, or otherwise changes
    record state — it only escalates operator attention, which is
    exactly the F4 detector's contract (``gov/approvals.py``:
    ``queue_anomalies`` is READ-ONLY; callers escalate attention,
    never approvals).
    """
    anomalies = _queue_anomalies(app)
    if not anomalies:
        return ""
    blocks = []
    for a in anomalies:
        label = _ANOMALY_TYPE_LABELS.get(a["type"], "ANOMALY")
        links = " ".join(
            "<a href='/approvals/%s'>%s</a>" % (_esc(i), _esc(i))
            for i in a["items"])
        blocks.append(
            "<div class='warn'><strong>%s</strong> %s<br>"
            "<small>cluster members: %s</small></div>"
            % (_esc(label), _esc(a["summary"]), links or "(none)"))
    return (
        "<div class='anomaly-panel'>"
        "<h2>Queue health — advisory anomaly signals (F4)</h2>"
        "<p><small>Advisory only: these signals never auto-approve, "
        "auto-deny, or change record state. They escalate operator "
        "attention — review each cluster member individually before "
        "deciding.</small></p>"
        "%s</div>" % "".join(blocks))


def _record_cluster_types(app, approval_id):
    """Anomaly-cluster types the given record belongs to (advisory)."""
    types = set()
    for a in _queue_anomalies(app):
        if approval_id in a["items"]:
            types.add(a["type"])
    return sorted(types)


def render_list(app, csrf=None):
    """Pending queue (highest risk first) + decided history.

    ``csrf`` is the session token threaded through for the logout
    form (see ``_page``); callers without a session pass None.

    Raises ValueError/OSError when the queue file is corrupt — the
    caller turns that into a fail-closed 500, never a partial page.
    """
    pending = app.queue.pending_risk_sorted()
    decided = [r for r in app.queue.all() if r.get("status") != "pending"]
    rows = []
    for r in pending:
        flags = []
        if r.get("flood_suspect"):
            flags.append("FLOOD-SUSPECT")
        if r.get("break_glass"):
            flags.append("BREAK-GLASS")
        if r.get("execution_interrupted_warning"):
            flags.append("INTERRUPTED")
        # D1-core: pending SUBSTATES, not new statuses — surfaced so
        # the operator never mistakes a delegated or
        # quorum-collecting record for an ordinary pending one.
        if r.get("decision_mode") == "quorum":
            quorum = r.get("quorum") or {}
            votes = r.get("votes") or []
            cast = sum(1 for v in votes if v.get("approve"))
            flags.append("QUORUM %d-of-%d" % (
                cast, quorum.get("min_approvals", "?")))
        elif r.get("delegated_to"):
            flags.append("DELEGATED to %s" % r.get("delegated_to"))
        # Wave-25 (P4): bridge badge. Bridge-sourced records render
        # distinctly — the operator must never mistake a
        # foreign-executed request for a native one. bridge_expired is
        # flagged separately: the record can never execute (T12/F85).
        bridge_kind, bridge_id = _bridge_state(r)
        if bridge_kind == "verified":
            flags.append("BRIDGE:%s" % bridge_id)
        elif bridge_kind == "unverified":
            flags.append("UNVERIFIED-BRIDGE")
        if r.get("bridge_expired"):
            flags.append("BRIDGE-EXPIRED")
        rows.append(
            "<tr><td><a href='/approvals/%s'>%s</a></td><td>%s</td>"
            "<td>%s</td><td>%s</td>%s<td>%s</td></tr>"
            % (_esc(r["id"]), _esc(r["id"]), _esc(r.get("agent_id")),
               _esc(r.get("tool")), _esc(r.get("policy_id")),
               _risk_cell(app, r), _esc(" ".join(flags))))
    hist = []
    for r in decided:
        # Bridge provenance and late-decision status survive into
        # history: an "approved" row on a bridge_expired record must
        # not read as an effective approval (T11: audit-only, T12:
        # never executed).
        suffix = ""
        bridge_kind, bridge_id = _bridge_state(r)
        if bridge_kind == "verified":
            suffix += " — bridge:%s" % bridge_id
        elif bridge_kind == "unverified":
            suffix += " — UNVERIFIED BRIDGE"
        if r.get("late_decision"):
            suffix += " — LATE (audit-only, never executed)"
        hist.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s by %s%s</td></tr>"
            % (_esc(r["id"]), _esc(r.get("agent_id")), _esc(r.get("tool")),
               _esc(r.get("policy_id")), _esc(r.get("status")),
               _esc(r.get("decided_by")), _esc(suffix)))
    return _page(
        "Approval queue — run %s" % app.queue.run_id,
        "%s"
        "<h2>Pending (%d) — highest risk first</h2>"
        "<table><tr><th>id</th><th>agent</th><th>tool</th><th>policy</th>"
        "<th>risk</th><th>flags</th></tr>%s</table>"
        "<h2>Decided (%d)</h2>"
        "<table><tr><th>id</th><th>agent</th><th>tool</th><th>policy</th>"
        "<th>decision</th></tr>%s</table>"
        % (_anomaly_panel(app),
           len(rows), "".join(rows) or
           "<tr><td colspan='6'>(none)</td></tr>",
           len(hist), "".join(hist) or
           "<tr><td colspan='5'>(none)</td></tr>"),
        csrf=csrf)


def _shield_brief_panel(record):
    """H19 (row 3 residual): render the independent approver-shield brief.

    Capture-tier records only. The brief is a pure function of the
    stored record (``gov.approver_shield.shield_brief``) — the same
    brief dict the CLI renders via ``_print_shield_brief``. The agent's
    justification appears ONLY in the labeled quarantine zone, after
    every governor-computed signal. Display-only: no new auth surface,
    no decision logic — the panel informs the human, it never decides.
    """
    brief = _shield.shield_brief(record)
    action = brief.get("action") or {}
    risk = brief.get("risk") or {}
    cap = brief.get("capability") or {}
    pers = brief.get("persuasion") or {}
    quar = brief.get("quarantine") or {}
    req = action.get("requested_by") or {}

    cites = brief.get("citations") or []
    if cites:
        cite_rows = "".join(
            "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
            % (_esc(c.get("url")), _esc(c.get("verdict")),
               _esc(c.get("reason")))
            for c in cites if isinstance(c, dict))
        cite_html = ("<table><tr><th>citation</th><th>verdict</th>"
                     "<th>reason</th></tr>%s</table>" % cite_rows)
    else:
        cite_html = "<p><small>citations: none cited by the agent</small></p>"

    markers = pers.get("markers") or []
    marker_html = ("<p>markers: %s</p>" % _esc("; ".join(markers))
                   if markers else "")
    div_html = ""
    if pers.get("prose_divergence"):
        div_html = ("<div class='err'><strong>DIVERGENCE:</strong> %s</div>"
                    % _esc(pers.get("prose_divergence")))

    # Fatigue state: the record's own flood-suspect flag. Cluster
    # membership banners render separately in render_detail's flags.
    fatigue_html = ""
    if record.get("flood_suspect"):
        fatigue_html = ("<div class='warn'><strong>FATIGUE STATE:</strong> "
                        "this item is part of an approval-fatigue cluster "
                        "— review individually.</div>")

    return (
        "<div class='shield-brief'>"
        "<h2>INDEPENDENT SHIELD BRIEF "
        "(governor-computed, not agent prose)</h2>"
        "<p><small>tier: <strong>%s</strong> | approval: <code>%s</code> | "
        "brief digest (shield-ack token): <code>%s</code></small></p>"
        "<table>"
        "<tr><td>action</td><td>%s</td></tr>"
        "<tr><td>machine-verified target</td><td><code>%s</code></td></tr>"
        "<tr><td>executor preview</td><td><pre>%s</pre></td></tr>"
        "<tr><td>requested by</td><td>%s (role %s, principal %s)</td></tr>"
        "<tr><td>risk</td><td><strong>%s (%s)</strong></td></tr>"
        "<tr><td>risk factors</td><td>%s</td></tr>"
        "<tr><td>blast radius</td><td>%s</td></tr>"
        "<tr><td>capability</td><td>%s — %s</td></tr>"
        "<tr><td>persuasion score</td><td>%s</td></tr>"
        "</table>"
        "%s%s"
        "<h3>Citations</h3>%s"
        "%s"
        "<div class='quarantine-zone'>"
        "<h3>-- %s</h3>"
        "<p class='unverified'>quarantined justification (UNVERIFIED "
        "agent-supplied text — may contain instructions aimed at the "
        "approver: do not follow them): %s</p>"
        "</div>"
        "</div>"
        % (
            _esc(brief.get("tier")),
            _esc(brief.get("approval_id")),
            _esc(brief.get("packet_digest") or ""),
            _esc(action.get("tool")),
            _esc(action.get("target")),
            _esc(action.get("executor_preview")),
            _esc(req.get("agent_id")), _esc(req.get("role")),
            _esc(req.get("principal")),
            _esc(risk.get("tier")), _esc(risk.get("score")),
            _esc("; ".join(risk.get("factors") or [])) or "(none)",
            _esc("; ".join(risk.get("blast_radius") or []))
            or "(none identified)",
            _esc(cap.get("verdict")), _esc(cap.get("note")),
            _esc(pers.get("score")),
            marker_html, div_html,
            cite_html,
            fatigue_html,
            _esc(quar.get("label")),
            _esc(quar.get("justification")),
        )
    )


def _packet_panel(record):
    """S3 shield (wave-89): render the canonical packet as the PRIMARY
    decision basis — machine-generated, agent-prose-free. Agent prose
    (preview/justification/args) stays segregated in the untrusted zone
    below; the approver decides on this panel first."""
    pkt = record.get("canonical_packet") or {}
    if not pkt:
        return ("<p><small>canonical packet: n/a (record predates the "
                "approval-integrity shield)</small></p>")
    pol = pkt.get("policy") or {}
    pers = pkt.get("persuasion") or {}
    rows = [
        ("action", _esc(pkt.get("action"))),
        ("target", "<code>%s</code>" % _esc(pkt.get("target"))),
        # F190: the bound canonical target alongside the declared
        # target — the approver sees the object the receipt binds.
        ("canonical target (bound)",
         "<code>%s</code>"
         % _esc(pkt.get("canonical_target") or "(n/a — no path arg)")),
        ("risk", "<strong class='risk-%s'>%s (%s)</strong>" % (
            _esc(pkt.get("risk_tier")), _esc(pkt.get("risk_score")),
            _esc(pkt.get("risk_tier")))),
        ("risk factors", _esc("; ".join(pkt.get("risk_factors") or []))
         or "(none)"),
        ("blast radius", _esc("; ".join(pkt.get("blast_radius") or []))
         or "(none identified)"),
        ("policy", _esc("%s · version %s · rules: %s · flag: %s" % (
            pol.get("policy_id"), pol.get("policy_version"),
            ", ".join(pol.get("matched_rules") or []),
            pol.get("policy_flag")))),
        ("persuasion score", _esc("%s%s" % (
            pers.get("score"),
            (" — markers: %s" % "; ".join(pers.get("markers") or []))
            if pers.get("markers") else ""))),
        ("packet digest", "<code>%s</code>"
         % _esc((record.get("packet_digest") or "")[:32])),
    ]
    return ("<h2>Decision packet (governor-generated — decide on this)</h2>"
            "<table>%s</table>"
            % "".join("<tr><td>%s</td><td>%s</td></tr>" % kv
                      for kv in rows))


def render_detail(app, record, csrf):
    r = record
    flags = []
    if r.get("flood_suspect"):
        flags.append("<div class='warn'>FLOOD-SUSPECT: this item is part "
                     "of an approval-fatigue cluster — review individually."
                     "</div>")
    if r.get("break_glass"):
        flags.append("<div class='warn'>BREAK-GLASS record: %s. "
                     "Break-glass decisions are CLI-only — this console "
                     "refuses to decide them.</div>"
                     % _esc(r.get("break_glass_reason")))
    if r.get("execution_interrupted_warning"):
        flags.append("<div class='warn'>%s</div>"
                     % _esc(r.get("execution_interrupted_warning")))
    # -- Wave-27 (P4/F4): anomaly-cluster membership banner ------------
    # A record sitting in an advisory fatigue/anomaly cluster gets a
    # banner naming the cluster type(s): the operator reviews the
    # whole cluster before deciding. Advisory only — it never blocks
    # or auto-decides (see _anomaly_panel).
    _cluster_types = _record_cluster_types(app, r["id"])
    if _cluster_types:
        flags.append(
            "<div class='warn'>CLUSTER MEMBER: this request belongs to "
            "%s — review each cluster member individually before "
            "deciding. (Advisory F4 signal: it does not block or "
            "auto-decide.)</div>"
            % _esc(", ".join(_cluster_types)))
    if r.get("delegation_attempted"):
        flags.append("<div class='warn'>WARNING: delegation framing "
                     "detected (on_behalf_of/delegated_by). This is an "
                     "UNTRUSTED framing claim, not a governed authority "
                     "grant (P10) and not an approval delegation — the "
                     "action executes under the acting agent's authority."
                     "</div>")
    # -- D1-core state banners --------------------------------------
    # DELEGATED and QUORUM_COLLECTING are SUBSTATES of pending (the
    # record's status stays "pending") — surfaced prominently so the
    # operator never mistakes them for an ordinary pending item.
    pending = r.get("status") == "pending"
    is_delegated = bool(r.get("delegated_to"))
    is_quorum = r.get("decision_mode") == "quorum"
    if is_delegated:
        chain = r.get("delegation_chain") or []
        hops = []
        for hop in chain:
            if isinstance(hop, dict):
                hops.append("<code>%s</code> &rarr; <code>%s</code>" % (
                    _esc(hop.get("from")), _esc(hop.get("to"))))
        chain_html = "; ".join(hops)
        flags.append(
            "<div class='warn'>DELEGATED: this request is currently "
            "assigned to <strong>%s</strong> — only that principal may "
            "decide it. Chain: %s.</div>"
            % (_esc(r.get("delegated_to")), chain_html or "(chain n/a)"))
    if is_quorum:
        quorum = r.get("quorum") or {}
        votes = r.get("votes") or []
        cast = sum(1 for v in votes if v.get("approve"))
        if pending:
            flags.append(
                "<div class='warn'>QUORUM COLLECTING: %d of %d required "
                "approvals recorded. Eligible principals: %s. "
                "One deny vetoes. Direct decisions are refused — "
                "vote below.</div>"
                % (cast, quorum.get("min_approvals", "?"),
                   _esc(", ".join(quorum.get("eligible_principals")
                                  or []))))
        else:
            flags.append(
                "<div class='warn'>QUORUM record (finalized by votes): "
                "%s.</div>" % _esc(r.get("decided_by")))
    # -- Wave-25 (P4): bridge provenance banners ----------------------
    # A verified bridge_id renders the bridge:<id> badge + panel
    # below. Bridge markers WITHOUT a verifiable bridge_id render an
    # explicit UNVERIFIED BRIDGE warning — fail-closed, never a normal
    # record and never a badge. A bridge_expired record is rendered
    # unmistakably: it can NEVER execute (T12 sweep refusal, F85).
    bridge_kind, bridge_id = _bridge_state(r)
    if bridge_kind == "verified":
        flags.append(
            "<div class='warn'>FOREIGN BRIDGE request "
            "<span class='bridge-badge'>bridge:%s</span> — the foreign "
            "runtime executes on its side after the human decides; our "
            "executor never runs bridge records. Foreign framing is "
            "never trusted (see the panel below).</div>"
            % _esc(bridge_id))
    elif bridge_kind == "unverified":
        flags.append(
            "<div class='err'><strong>UNVERIFIED BRIDGE:</strong> this "
            "record carries bridge markers (expired wait, late "
            "decision, external request id, or foreign digest/versions) "
            "but no verifiable bridge identity. It is rendered as "
            "foreign and fail-closed: never treated as a normal record, "
            "and it can never execute while bridge_expired is set "
            "(T12).</div>")
    if r.get("bridge_expired"):
        flags.append(
            "<div class='err'><strong>BRIDGE EXPIRED</strong> at %s: the "
            "foreign bridge's bounded wait has lapsed. This record can "
            "NEVER execute — the sweep refuses bridge_expired records "
            "(T12, F85). A decision recorded now would be audit-only "
            "(T11); the console offers no decision form for expired "
            "bridges.</div>"
            % _esc(r.get("bridge_expired_at")))
    bridge_html = _bridge_panel(r) if bridge_kind == "verified" else ""
    if r.get("late_decision"):
        flags.append(
            "<div class='warn'>LATE DECISION: a decision attempt was "
            "made after bridge expiry and was recorded as "
            "audit-only (%s).</div>"
            % _esc((r.get("late_decision") or {}).get("decision")))
    try:
        detail = app.queue.risk_detail(r)
        risk_html = ("<p>risk: <strong class='risk-%s'>%d (%s)</strong></p>"
                     "<p><small>%s</small></p>"
                     % (_esc(detail["level"]), detail["score"],
                        _esc(detail["level"]),
                        _esc("; ".join(detail["factors"]))))
    except Exception:
        risk_html = "<p>risk: n/a</p>"
    # S3 shield (wave-89): the canonical packet is the PRIMARY decision
    # basis — rendered first, before any agent-authored prose. Agent
    # prose stays segregated in the untrusted zone below.
    packet_html = _packet_panel(r)
    # H19 (row 3 residual): capture-tier records render the independent
    # shield brief — the same brief dict the CLI shows, as a pure
    # function of the stored record. Display-only; the panel never
    # decides.
    shield_html = ""
    try:
        if _shield.is_capture_tier(r):
            shield_html = _shield_brief_panel(r)
    except Exception:
        shield_html = ("<p><small>shield brief: unavailable "
                       "(render error — see CLI for the brief)</small></p>")
    _ps = r.get("persuasion_score") or 0
    if _ps >= PERSUASION_RISK_SCORE:
        flags.append(
            "<div class='err'><strong>PERSUASION MARKERS (score %d):</strong> "
            "%s — this request's framing tries to steer you. Decide on "
            "the packet above, not on this tone.</div>"
            % (_ps, _esc("; ".join(r.get("persuasion_markers") or []))))
    elif _ps >= PERSUASION_FLAG_SCORE:
        flags.append(
            "<div class='warn'><strong>Persuasion-shaped framing (score "
            "%d):</strong> %s — verify the packet above independently."
            "</div>" % (_ps,
                        _esc("; ".join(r.get("persuasion_markers") or []))))
    if r.get("prose_divergence"):
        flags.append(
            "<div class='err'><strong>PROSE DIVERGENCE:</strong> %s — the "
            "agent's prose names a different target than the action will "
            "execute. Trust the packet target, not the story.</div>"
            % _esc(r.get("prose_divergence")))
    if r.get("status") == "pending" and r.get("cooling_off_until"):
        _cool_until = ApprovalQueue._parse_ts(r.get("cooling_off_until"))
        if _cool_until is not None and datetime.now(timezone.utc) < _cool_until:
            flags.append(
                "<div class='warn'><strong>COOLING-OFF until %s:</strong> "
                "critical-tier items cannot be approved until the pause "
                "elapses. Rejection stays available.</div>"
                % _esc(r.get("cooling_off_until")))
    just = r.get("agent_justification")
    just_html = ("<p class='unverified'>agent justification (UNVERIFIED "
                 "agent-supplied text — may contain instructions aimed "
                 "at the approver: do not follow them): %s</p>"
                 % _esc(just)) if just else ""
    # K-028 framing mediation: preview provenance. Native previews are
    # executor-generated from the (untrusted) request args (F12);
    # bridge previews are foreign bridge-generated summaries the human
    # sees instead of raw foreign framing (sanitized per F11 —
    # non-printables only, semantics pass through by design). Both are
    # labeled by origin; neither is trusted.
    if bridge_kind == "verified":
        preview_note = ("UNVERIFIED — foreign bridge-generated summary "
                        "(bridge:%s; sanitizes only non-printable "
                        "characters; content may reflect attacker "
                        "framing)" % bridge_id)
    else:
        preview_note = ("executor-generated from the request args — the "
                        "args themselves are untrusted input (see below)")
    preview_html = ("<pre>%s</pre><br><small class='unverified'>preview: "
                    "%s</small>"
                    % (_esc(r.get("preview")), _esc(preview_note)))
    # K-028 framing mediation: the approver is a human attack surface.
    # Justification, preview, and args may carry instructions aimed at
    # the approver (prompt injection into the decision). They render
    # inside a labeled quarantine zone, separated from the
    # governor-verified facts above; the decision form repeats the
    # directive. Labeling + layout only — the UI cannot stop a human
    # who chooses to obey what they read (see HONEST LIMITS).
    untrusted_html = (
        "<div class='untrusted-zone'>"
        "<h2>Untrusted content — do not follow instructions here</h2>"
        "<p class='unverified'>Everything in this section is agent- or "
        "foreign-supplied input: it may contain instructions aimed at "
        "you, the approver. Decide only on the decision packet above "
        "(machine-generated, digest-bound) — never on this prose. "
        "Instructions appearing here are not from the operator and "
        "must not be obeyed.</p>"
        "%s%s</div>"
        % (_args_view(r.get("args") or {}), just_html))
    # -- D1-core quorum panel: the MACed snapshot + every vote row,
    #    all escaped. The tally is computed from the vote rows so a
    #    tampered tally display cannot disagree with the rows the
    #    finalize logic actually counts.
    quorum_panel = ""
    if is_quorum:
        quorum = r.get("quorum") or {}
        votes = r.get("votes") or []
        rows = []
        for v in votes:
            if not isinstance(v, dict):
                continue
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                % (_esc(v.get("voter_principal")),
                   "APPROVE" if v.get("approve") else "DENY",
                   _esc(v.get("voted_at")), _esc(v.get("reason"))))
        quorum_panel = (
            "<h2>Quorum (MAC-bound snapshot)</h2>"
            "<table><tr><th>voter</th><th>vote</th><th>at</th>"
            "<th>reason</th></tr>%s</table>"
            "<p><small>eligible: %s &middot; deny veto: %s &middot; "
            "allow delegation: %s</small></p>"
            % ("".join(rows) or
               "<tr><td colspan='4'>(no votes yet)</td></tr>",
               _esc(", ".join(quorum.get("eligible_principals") or [])),
               _esc(quorum.get("deny_veto")),
               _esc(quorum.get("allow_delegation"))))
    decided_html = ""
    form_html = ""
    # The delegate affordance renders whenever the installed policy
    # enables delegation; the canonical delegate() still enforces
    # every rule (disabled, wrong delegator, self/loop, hops,
    # registry) fail-closed, so a rendered form can never widen the
    # control.
    delegate_form = ""
    if pending and not r.get("break_glass") and app.queue.delegation_enabled:
        # D1-core T13: on a quorum record, delegation transfers one
        # VOTE SLOT (the delegator must hold an uncast eligible slot),
        # not the decision right — the form says so explicitly.
        transfer_noun = ("your vote slot (you must hold an uncast "
                         "eligible vote; one vote per principal, no "
                         "retractions)") if is_quorum else \
            "the decision right; self-delegation, loops, hop overruns, "\
            "and unregistered delegatees are refused and audited"
        delegate_form = (
            "<h2>Delegate</h2>"
            "<form method='POST' action='/approvals/%s/delegate'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<p><label>Delegate to (principal):<br>"
            "<input name='to' size='40' required></label></p>"
            "<p><label>Reason (required):<br>"
            "<textarea name='reason' rows='2' cols='70' required>"
            "</textarea></label></p>"
            "<p><button type='submit'>Delegate</button></p></form>"
            "<p><small>You act as <code>%s</code>. Delegation transfers "
            "%s.</small></p>"
            % (_esc(r["id"]), _esc(csrf), _esc(WEB_DECIDED_BY),
               _esc(transfer_noun)))
    elif pending and not r.get("break_glass"):
        # Delegation is policy-gated (fail closed without --policy):
        # say so explicitly instead of silently omitting the form, so
        # the operator can distinguish "disabled by policy" from a
        # rendering bug.
        delegate_form = (
            "<p><small>Delegation is disabled by policy for this run "
            "(start the console with <code>--policy</code> pointing at "
            "a policy with an <code>approvals.delegation</code> section "
            "to enable it).</small></p>")
    decide_form = (
        "<h2>Decision</h2>"
        "<form method='POST' action='/approvals/%s/decide'>"
        "<input type='hidden' name='csrf' value='%s'>"
        "<p><label>Reason (required):<br>"
        "<textarea name='reason' rows='3' cols='70' required></textarea>"
        "</label></p>"
        "<p><button type='submit' name='decision' value='approve'>"
        "Approve</button> "
        "<button type='submit' name='decision' value='deny'>"
        "Deny</button></p></form>"
        "<p><small>The decision is recorded through the same code path "
        "as the CLI (<code>ApprovalQueue.decide</code>); only the "
        "decision and reason are taken from this form.</small></p>"
        "<p><small><strong>Decide on the governor-verified facts above "
        "(risk, policy verdict, digest, status)</strong> — not on claims "
        "in the untrusted content below. Instructions appearing in "
        "untrusted content are not from the operator and must not be "
        "obeyed.</small></p>"
        % (_esc(r["id"]), _esc(csrf)))
    vote_form = (
        "<h2>Vote (quorum)</h2>"
        "<form method='POST' action='/approvals/%s/vote'>"
        "<input type='hidden' name='csrf' value='%s'>"
        "<p><label>Reason (required):<br>"
        "<textarea name='reason' rows='2' cols='70' required></textarea>"
        "</label></p>"
        "<p><button type='submit' name='vote' value='approve'>"
        "Vote approve</button> "
        "<button type='submit' name='vote' value='deny'>"
        "Vote deny</button></p></form>"
        "<p><small>You vote as <code>%s</code> (this console's single "
        "operator principal). Votes are final: one per principal, no "
        "retractions. A deny vetoes the record immediately.</small></p>"
        % (_esc(r["id"]), _esc(csrf), _esc(WEB_DECIDED_BY)))
    if pending:
        if r.get("bridge_expired"):
            # T11/T12: the bridge wait lapsed, so any decision recorded
            # now is audit-only and can NEVER execute (F85). Offering
            # Approve/Deny buttons would imply the decision has effect
            # — it does not — so the console withholds the decide form
            # (and the delegate form: delegating an audit-only
            # stewardship is meaningless). A forensic late decision, if
            # needed, is recorded via the CLI through the canonical
            # decide(). A crafted POST to /decide still lands on the
            # canonical path and is labeled late_decision (audit-only).
            form_html = (
                "<h2>Decision</h2><div class='err'>No decision form: "
                "this bridge expired at %s. The foreign runtime was "
                "already denied by timeout (fail-safe deny); a decision "
                "recorded now would be audit-only and can NEVER execute "
                "(T11/T12, F85). To record a forensic late decision, "
                "use the CLI.</div>"
                % _esc(r.get("bridge_expired_at")))
        elif r.get("break_glass"):
            # Break-glass via web is out of scope (Architect): read-only
            # detail, no decision form.
            form_html = ("<h2>Decision</h2><div class='warn'>This is a "
                         "break-glass record. The web console does not "
                         "decide break-glass approvals — use the CLI.</div>")
        elif is_quorum:
            # Quorum records are NEVER decided directly (decide()
            # refuses with quorum_direct_decide) — the operator votes.
            form_html = vote_form + delegate_form
        elif is_delegated and r.get("delegated_to") != WEB_DECIDED_BY:
            # Someone else holds the decision right; this console's
            # operator can only (re-)delegate if the delegation chain
            # permits — decide() would refuse anyway.
            form_html = (
                "<div class='warn'>Only <strong>%s</strong> may decide "
                "this record while it is delegated to them.</div>"
                % _esc(r.get("delegated_to"))) + delegate_form
        else:
            form_html = decide_form + delegate_form
    else:
        decided_html = ("<h2>Decision</h2><p>%s by %s at %s</p><p>reason: "
                        "%s</p>" % (_esc(r.get("status")),
                                    _esc(r.get("decided_by")),
                                    _esc(r.get("decided_at")),
                                    _esc(r.get("decision_reason"))))
    return _page(
        "Approval %s" % r["id"],
        "".join(flags) + bridge_html + packet_html + shield_html +
        "<table>"
        "<tr><th>field</th><th>value</th></tr>"
        "<tr><td>id</td><td>%s</td></tr>"
        "<tr><td>agent</td><td>%s (role %s, principal %s)</td></tr>"
        "<tr><td>identity</td><td><pre>%s</pre></td></tr>"
        "<tr><td>tool</td><td>%s</td></tr>"
        "<tr><td>policy</td><td>%s — %s (flag: %s)</td></tr>"
        "<tr><td>policy context</td><td><pre>%s</pre></td></tr>"
        "<tr><td>provenance</td><td>%s</td></tr>"
        "<tr><td>preview</td><td>%s</td></tr>"
        "<tr><td>redactions</td><td>%s</td></tr>"
        "<tr><td>status</td><td>%s</td></tr>"
        "</table>%s%s%s"
        % (_esc(r["id"]), _esc(r.get("agent_id")), _esc(r.get("role")),
           _esc(r.get("principal")),
           _esc(json.dumps(r.get("identity") or {}, indent=2,
                           sort_keys=True, default=str)),
           _esc(r.get("tool")),
           _esc(r.get("policy_id")), _esc(r.get("policy_reason")),
           _esc(r.get("policy_flag")),
           _esc(json.dumps(r.get("policy_context") or {}, indent=2,
                           sort_keys=True, default=str)),
           _esc(r.get("provenance")), preview_html,
           _esc(", ".join(r.get("redactions_applied") or [])),
           _esc(r.get("status")),
           risk_html, untrusted_html, decided_html)
        + quorum_panel + form_html, csrf=csrf)


def render_login(error=""):
    err = "<div class='err'>%s</div>" % _esc(error) if error else ""
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>Approval queue — login</title><style>%s</style></head>"
            "<body><h1>Approval queue — operator login</h1>%s"
            "<p>Enter the token printed by the server at startup. "
            "Sessions last %d hours and are bound to this browser via an "
            "<code>HttpOnly; SameSite=Strict</code> cookie.</p>"
            "<form method='POST' action='/login'>"
            "<label>Token: <input type='password' name='token' size='50' "
            "autocomplete='off'></label> "
            "<button type='submit'>Log in</button></form>"
            "<p><small>Honest limits: this is a localhost console with a "
            "single shared token — there is no SSO, no per-human login, "
            "and no TLS. Anyone holding the token <em>is</em> the "
            "operator; every web decision is audit-logged as "
            "<code>web/human-operator</code>.</small></p></body></html>"
            % (_CSS, err, SESSION_TTL_SECS // 3600))


_AUDIT_TAIL_LIMIT = 200
_AUDIT_REASON_CAP = 300


def render_audit(app, csrf):
    """Read-only audit trail: the run's action log, newest first.

    Authenticated GET only; never mutates (no audit entry is written
    for viewing — GETs are side-effect free by design). Every value
    is escaped; reasons are truncated for layout. Malformed log lines
    are reported as a count, never trusted or rendered.
    """
    entries, malformed = read_entries_with_stats(app.log.path)
    tail = entries[-_AUDIT_TAIL_LIMIT:][::-1]
    rows = []
    for e in tail:
        if not isinstance(e, dict):
            continue
        reason = str(e.get("reason") or "")
        if len(reason) > _AUDIT_REASON_CAP:
            reason = reason[:_AUDIT_REASON_CAP] + "…"
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>"
            % (_esc(e.get("seq")), _esc(e.get("ts")),
               _esc(e.get("event")), _esc(e.get("approval_id")),
               _esc(e.get("decision")), _esc(reason)))
    malformed_note = (
        "<p class='warn'>%d malformed log line(s) skipped — not trusted, "
        "not rendered.</p>" % malformed) if malformed else ""
    return _page(
        "Audit trail — run %s" % app.queue.run_id,
        "<p>Newest first; showing the last %d of %d entries. "
        "Web-console decisions carry "
        "<code>decided_by=web/human-operator</code>; web-layer refusals "
        "appear as <code>web_*</code> events.</p>"
        "<p class='unverified'><small>Note: some reasons quote foreign "
        "or agent-supplied text (e.g. bridge timeout reasons) — quoted "
        "content is untrusted even when the entry itself is "
        "engine-written.</small></p>%s"
        "<table><tr><th>seq</th><th>ts</th><th>event</th>"
        "<th>approval</th><th>decision</th><th>reason</th></tr>%s</table>"
        % (_AUDIT_TAIL_LIMIT, len(entries), malformed_note,
           "".join(rows) or "<tr><td colspan='6'>(no entries)</td></tr>"),
        csrf=csrf)

# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

def _make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ApprovalWeb/1.0"

        def log_message(self, fmt, *args):
            sys.stderr.write("web %s %s\n" % (self.command, self.path))

        # -- helpers -------------------------------------------------
        def _send(self, code, body, headers=None):
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _redirect(self, location, cookie=None):
            headers = {"Location": location}
            if cookie is not None:
                headers["Set-Cookie"] = cookie
            self._send(302, "<a href='%s'>redirect</a>" % _esc(location),
                       headers)

        def _read_form(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                n = 0
            raw = self.rfile.read(max(0, n)).decode("utf-8", "replace")
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def _session(self):
            return app.get_session(self.headers.get("Cookie"))

        def _origin_ok(self):
            """Same-origin POST: a cross-origin Origin/Referer is
            refused. Browsers always send Origin on form POSTs; the
            CSRF token is the primary control, this is defense in
            depth."""
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if origin:
                return urlparse(origin).netloc == host
            referer = self.headers.get("Referer")
            if referer:
                return urlparse(referer).netloc == host
            return True

        # -- routes --------------------------------------------------
        def do_GET(self):
            try:
                self._route_get()
            except Exception as e:  # never leak a traceback decision
                sys.stderr.write("web ERROR: %r\n" % (e,))
                self._send(500, _fail_closed_page(
                    "Internal error",
                    "unexpected error (%s); no decision recorded"
                    % type(e).__name__))

        def do_POST(self):
            try:
                self._route_post()
            except Exception as e:
                sys.stderr.write("web ERROR: %r\n" % (e,))
                self._send(500, _fail_closed_page(
                    "Internal error",
                    "unexpected error (%s); no decision recorded"
                    % type(e).__name__))

        def _route_get(self):
            url = urlparse(self.path)
            path = url.path
            if path == "/login":
                if self._session() is not None:
                    self._redirect("/")
                else:
                    self._send(200, render_login())
                return
            sess = self._session()
            if sess is None:
                self._redirect("/login")
                return
            # Session context for the page shell: the logout form
            # carries the per-session CSRF token (F80).
            csrf = sess["csrf"]
            if path == "/":
                try:
                    self._send(200, render_list(app, csrf=csrf))
                except (ValueError, OSError) as e:
                    # Corrupt queue data: fail closed, never partial.
                    app.audit("web_queue_unreadable",
                              reason="queue list refused: %s" % e)
                    self._send(500, _fail_closed_page(
                        "Queue unreadable",
                        "the approval queue file could not be parsed "
                        "(%s); refusing to render decisions" % e,
                        csrf=csrf))
                return
            if path == "/audit":
                # Read-only audit trail. Authenticated GET: the session
                # gate above already ran. Viewing never mutates, so no
                # CSRF token is needed and no audit entry is written.
                try:
                    self._send(200, render_audit(app, csrf=csrf))
                except OSError as e:
                    app.audit("web_audit_unreadable",
                              reason="audit log refused: %s" % e)
                    self._send(500, _fail_closed_page(
                        "Audit log unreadable",
                        "the action log could not be read (%s); refusing "
                        "to render a partial trail" % e,
                        csrf=csrf))
                return
            m = re.match(r"^/approvals/([A-Za-z0-9_-]{1,64})$", path)
            if m:
                aid = m.group(1)
                try:
                    record = app.queue.get(aid)
                except (ValueError, OSError) as e:
                    app.audit("web_queue_unreadable", approval_id=aid,
                              reason="queue detail refused: %s" % e)
                    self._send(500, _fail_closed_page(
                        "Queue unreadable",
                        "the approval queue file could not be parsed "
                        "(%s); refusing to render the decision" % e,
                        csrf=csrf))
                    return
                if record is None:
                    self._send(404, _page("Not found",
                                          "<p>unknown approval id</p>",
                                          csrf=csrf))
                    return
                self._send(200, render_detail(app, record, sess["csrf"]))
                return
            self._send(404, _page("Not found", "<p>unknown path</p>",
                                  csrf=csrf))

        def _route_post(self):
            url = urlparse(self.path)
            path = url.path
            if path == "/login":
                form = self._read_form()
                if app.check_token(form.get("token")):
                    sid, _csrf = app.new_session()
                    cookie = ("session=%s; HttpOnly; SameSite=Strict; "
                              "Path=/; Max-Age=%d"
                              % (sid, SESSION_TTL_SECS))
                    self._redirect("/", cookie=cookie)
                else:
                    app.audit("web_auth_failure",
                              reason="login with wrong token refused")
                    self._send(403, render_login(
                        "wrong token — this attempt was audit-logged"))
                return
            if path == "/logout":
                # F80: same gates as the decide handler. An
                # authenticated logout requires a same-origin POST
                # carrying the per-session CSRF token. A forged
                # cross-site logout is refused (403) WITHOUT
                # destroying the session, and the refusal is
                # audit-logged as web_csrf_failure.
                sess = self._session()
                if sess is None:
                    self._redirect("/login")
                    return
                if not self._origin_ok():
                    app.audit("web_csrf_failure",
                              reason="cross-origin logout POST refused")
                    self._send(403, _fail_closed_page(
                        "Cross-origin request refused",
                        "the request did not come from this UI's origin",
                        csrf=sess["csrf"]))
                    return
                presented = self._read_form().get("csrf", "")
                if not hmac.compare_digest(sess["csrf"], presented):
                    app.audit("web_csrf_failure",
                              reason="logout with missing or invalid "
                                     "CSRF token refused")
                    self._send(403, _fail_closed_page(
                        "CSRF check failed",
                        "missing or invalid CSRF token; the session was "
                        "NOT destroyed",
                        csrf=sess["csrf"]))
                    return
                app.destroy_session(self.headers.get("Cookie"))
                self._redirect("/login")
                return
            m = re.match(r"^/approvals/([A-Za-z0-9_-]{1,64})/delegate$",
                         path)
            if m:
                self._handle_delegate(m.group(1))
                return
            m = re.match(r"^/approvals/([A-Za-z0-9_-]{1,64})/vote$",
                         path)
            if m:
                self._handle_vote(m.group(1))
                return
            m = re.match(r"^/approvals/([A-Za-z0-9_-]{1,64})/decide$",
                         path)
            if not m:
                self._send(404, _page("Not found", "<p>unknown path</p>"))
                return
            self._handle_decide(m.group(1))

        def _handle_delegate(self, approval_id):
            # Same gate stack as _handle_decide (session → origin →
            # CSRF). The delegator is the SESSION's principal — the
            # form supplies only ``to``/``reason``/``csrf``; the
            # canonical delegate() re-checks wrong-delegator,
            # self/loop, hops, and the registry fail-closed.
            sess = self._session()
            if sess is None:
                app.audit("web_auth_failure", approval_id=approval_id,
                          reason="delegate POST without a session refused")
                self._send(403, _fail_closed_page(
                    "Not authenticated",
                    "log in with the startup token first"))
                return
            if not self._origin_ok():
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="cross-origin delegate POST refused")
                self._send(403, _fail_closed_page(
                    "Cross-origin request refused",
                    "the request did not come from this UI's origin"))
                return
            form = self._read_form()
            if not hmac.compare_digest(sess["csrf"],
                                       form.get("csrf", "")):
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="delegate with missing or invalid "
                                 "CSRF token")
                self._send(403, _fail_closed_page(
                    "CSRF check failed",
                    "missing or invalid CSRF token; nothing was "
                    "delegated"))
                return
            to = (form.get("to") or "").strip()
            reason = (form.get("reason") or "").strip()
            if not to or not reason:
                app.audit("web_delegate_refused", approval_id=approval_id,
                          reason="delegate with empty target/reason "
                                 "refused")
                self._send(400, _fail_closed_page(
                    "Bad request",
                    "a delegate target and a reason are required — "
                    "nothing was delegated"))
                return
            try:
                record = app.queue.get(approval_id)
            except (ValueError, OSError) as e:
                app.audit("web_queue_unreadable", approval_id=approval_id,
                          reason="queue unreadable at delegate time: %s"
                                 % e)
                self._send(503, _fail_closed_page(
                    "Queue unreadable",
                    "the approval queue file could not be parsed (%s); "
                    "refusing to delegate" % e))
                return
            if record is None:
                app.audit("web_delegate_refused", approval_id=approval_id,
                          reason="unknown approval id")
                self._send(404, _page("Not found",
                                      "<p>unknown approval id</p>",
                                      csrf=sess["csrf"]))
                return
            if record.get("status") != "pending":
                app.audit("web_delegate_refused", approval_id=approval_id,
                          reason="delegate on non-pending record refused")
                self._send(409, _fail_closed_page(
                    "Delegation refused",
                    "only pending records can be delegated"))
                return
            try:
                with app.queue.locked(
                        timeout=_QUEUE_LOCK_TIMEOUT_SECS):
                    app.queue.delegate(approval_id, to, reason,
                                       delegated_by=sess["principal"])
            except QueueLockError as e:
                app.audit("web_delegate_refused", approval_id=approval_id,
                          reason="queue lock unavailable/corrupt: %s" % e)
                self._send(503, _fail_closed_page(
                    "Queue lock unavailable",
                    "the approval-queue lock could not be acquired (%s); "
                    "refusing to delegate rather than risk a split "
                    "delegation" % type(e).__name__))
                return
            except ValueError as e:
                # delegate() refused: disabled / wrong delegator / self /
                # loop / hop overrun / unregistered / requester /
                # tampered. delegate() already audit-logged it.
                app.audit("web_delegate_refused", approval_id=approval_id,
                          reason="canonical delegate() refused: %s" % e)
                self._send(409, _fail_closed_page(
                    "Delegation refused",
                    "the approval queue refused this delegation: %s"
                    % e))
                return
            self._redirect("/approvals/%s" % approval_id)

        def _handle_vote(self, approval_id):
            # Same gate stack as _handle_decide (session → origin →
            # CSRF). The voter identity is minted SERVER-SIDE from the
            # session principal — the form carries only ``vote`` /
            # ``reason`` / ``csrf``, never a principal name. The
            # canonical cast_vote() enforces eligibility, one-vote,
            # deny-veto, and replay rules fail-closed.
            sess = self._session()
            if sess is None:
                app.audit("web_auth_failure", approval_id=approval_id,
                          reason="vote POST without a session refused")
                self._send(403, _fail_closed_page(
                    "Not authenticated",
                    "log in with the startup token first"))
                return
            if not self._origin_ok():
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="cross-origin vote POST refused")
                self._send(403, _fail_closed_page(
                    "Cross-origin request refused",
                    "the request did not come from this UI's origin"))
                return
            form = self._read_form()
            if not hmac.compare_digest(sess["csrf"],
                                       form.get("csrf", "")):
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="vote with missing or invalid CSRF token")
                self._send(403, _fail_closed_page(
                    "CSRF check failed",
                    "missing or invalid CSRF token; the vote was NOT "
                    "recorded"))
                return
            vote = form.get("vote", "")
            reason = (form.get("reason") or "").strip()
            if vote not in ("approve", "deny"):
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="invalid vote value %r" % vote)
                self._send(400, _fail_closed_page(
                    "Bad request", "vote must be approve or deny"))
                return
            if not reason:
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="empty reason refused")
                self._send(400, _fail_closed_page(
                    "Bad request",
                    "a reason is required — the vote was NOT recorded"))
                return
            try:
                record = app.queue.get(approval_id)
            except (ValueError, OSError) as e:
                app.audit("web_queue_unreadable", approval_id=approval_id,
                          reason="queue unreadable at vote time: %s" % e)
                self._send(503, _fail_closed_page(
                    "Queue unreadable",
                    "the approval queue file could not be parsed (%s); "
                    "refusing to record the vote" % e))
                return
            if record is None:
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="unknown approval id")
                self._send(404, _page("Not found",
                                      "<p>unknown approval id</p>",
                                      csrf=sess["csrf"]))
                return
            if (record.get("status") != "pending"
                    or record.get("decision_mode") != "quorum"):
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="vote on non-quorum-collecting record "
                                 "refused")
                self._send(409, _fail_closed_page(
                    "Vote refused",
                    "only pending quorum records accept votes"))
                return
            voter = AgentIdentity(
                agent_id="web", role="voter", run_id=app.queue.run_id,
                principal=sess["principal"])
            try:
                with app.queue.locked(
                        timeout=_QUEUE_LOCK_TIMEOUT_SECS):
                    app.queue.cast_vote(approval_id, vote == "approve",
                                        reason, voter)
            except QueueLockError as e:
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="queue lock unavailable/corrupt: %s" % e)
                self._send(503, _fail_closed_page(
                    "Queue lock unavailable",
                    "the approval-queue lock could not be acquired (%s); "
                    "refusing to record the vote rather than risk a "
                    "double vote" % type(e).__name__))
                return
            except ValueError as e:
                # cast_vote() refused: non-eligible / requester /
                # duplicate / replay / finalized / tampered.
                # cast_vote() already audit-logged it.
                app.audit("web_vote_refused", approval_id=approval_id,
                          reason="canonical cast_vote() refused: %s" % e)
                self._send(409, _fail_closed_page(
                    "Vote refused",
                    "the approval queue refused this vote: %s" % e))
                return
            self._redirect("/approvals/%s" % approval_id)

        def _handle_decide(self, approval_id):
            # 1. Authentication: no session -> 403, nothing decided.
            sess = self._session()
            if sess is None:
                app.audit("web_auth_failure", approval_id=approval_id,
                          reason="decision POST without a session refused")
                self._send(403, _fail_closed_page(
                    "Not authenticated",
                    "log in with the startup token first"))
                return
            # 2. Same-origin POST (defense in depth behind the token).
            if not self._origin_ok():
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="cross-origin POST refused")
                self._send(403, _fail_closed_page(
                    "Cross-origin request refused",
                    "the request did not come from this UI's origin"))
                return
            # 3. CSRF token bound to the session.
            form = self._read_form()
            presented = form.get("csrf", "")
            if not hmac.compare_digest(sess["csrf"], presented):
                app.audit("web_csrf_failure", approval_id=approval_id,
                          reason="missing or invalid CSRF token")
                self._send(403, _fail_closed_page(
                    "CSRF check failed",
                    "missing or invalid CSRF token; the decision was "
                    "NOT recorded"))
                return
            # 4. Validate the decision inputs. ONLY decision/reason are
            #    read from the form — every authority field comes from
            #    the queue record itself (see _canonical_decide below).
            decision = form.get("decision", "")
            reason = (form.get("reason") or "").strip()
            if decision not in ("approve", "deny"):
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="invalid decision value %r" % decision)
                self._send(400, _fail_closed_page(
                    "Bad request", "decision must be approve or deny"))
                return
            if not reason:
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="empty reason refused")
                self._send(400, _fail_closed_page(
                    "Bad request",
                    "a reason is required — the decision was NOT recorded"))
                return
            # 5. The record must exist and the queue must parse.
            try:
                record = app.queue.get(approval_id)
            except (ValueError, OSError) as e:
                app.audit("web_queue_unreadable", approval_id=approval_id,
                          reason="queue unreadable at decide time: %s" % e)
                self._send(503, _fail_closed_page(
                    "Queue unreadable",
                    "the approval queue file could not be parsed (%s); "
                    "refusing to decide" % e))
                return
            if record is None:
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="unknown approval id")
                self._send(404, _page("Not found",
                                      "<p>unknown approval id</p>",
                                      csrf=sess["csrf"]))
                return
            # 5b. Break-glass via web is out of scope (Architect): the
            # web console never decides break-glass records — CLI only.
            if record.get("break_glass"):
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="break-glass decision refused: CLI-only")
                self._send(409, _fail_closed_page(
                    "Decision refused",
                    "break-glass approvals are CLI-only; this console "
                    "does not decide them"))
                return
            # 6. THE canonical path: ApprovalQueue.decide(), the same
            #    method the CLI calls, under the queue lock (serializes
            #    with sweeps; lock corruption -> fail closed). The
            #    decided_by label is the distinct web label so web
            #    decisions are forensically distinguishable from CLI
            #    decisions in the audit log and record digest.
            try:
                with app.queue.locked(
                        timeout=_QUEUE_LOCK_TIMEOUT_SECS):
                    _record, entry = app.queue.decide(
                        approval_id, decision == "approve", reason,
                        decided_by=WEB_DECIDED_BY)
            except QueueLockError as e:
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="queue lock unavailable/corrupt: %s" % e)
                self._send(503, _fail_closed_page(
                    "Queue lock unavailable",
                    "the approval-queue lock could not be acquired (%s); "
                    "refusing to decide rather than risk a double "
                    "decision" % type(e).__name__))
                return
            except ValueError as e:
                # decide() refused: unknown / already decided (replay) /
                # self-approval / tampered record. decide() already
                # audit-logged the rejected attempt.
                app.audit("web_decision_refused", approval_id=approval_id,
                          reason="canonical decide() refused: %s" % e)
                self._send(409, _fail_closed_page(
                    "Decision refused",
                    "the approval queue refused this decision: %s" % e))
                return
            self._redirect("/approvals/%s" % approval_id)

    return Handler


def make_server(run_dir, token=None, host="127.0.0.1", port=0,
                policy_path=None, queue=None):
    """Build a ThreadingHTTPServer for the approval web UI.

    ``token`` overrides the generated startup token (tests).
    ``policy_path`` installs the run policy's ``approvals.delegation``
    section so the web delegate route enforces the same control as
    the CLI (without it, delegation stays off — fail closed). ``queue``
    injects a QueuePort implementation (D1 pluggability seam); the
    default builds the canonical ``ApprovalQueue`` for ``run_dir``.
    The returned server has ``.app`` (the ApprovalWebApp) for inspection.
    """
    app = ApprovalWebApp(run_dir, token=token, policy_path=policy_path,
                         queue=queue)
    server = ThreadingHTTPServer((host, port), _make_handler(app))
    server.daemon_threads = True
    server.app = app
    return server


def _resolve_rundir(rundir, latest):
    from gov.approvals import _resolve_rundir as _rr

    class _Args:
        pass
    a = _Args()
    a.rundir = rundir
    a.latest = latest or not rundir
    return _rr(a)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="approval-web",
        description="Localhost web UI for the human approval queue "
                    "(stdlib only).")
    ap.add_argument("--rundir", default=None,
                    help="run directory (default: --latest)")
    ap.add_argument("--latest", action="store_true",
                    help="use the most recent run")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind host (default: 127.0.0.1; anything else "
                         "is unsupported without TLS + real auth)")
    ap.add_argument("--port", type=int, default=8734)
    ap.add_argument("--token", default=None,
                    help="operator token (default: random, printed at "
                         "startup)")
    ap.add_argument("--policy", default=None,
                    help="policy YAML path: installs its "
                         "approvals.delegation section so the web "
                         "delegate route enforces the same control as "
                         "the CLI (without it, delegation stays off — "
                         "fail closed)")
    args = ap.parse_args(argv)
    run_dir = _resolve_rundir(args.rundir, args.latest)
    server = make_server(run_dir, token=args.token, host=args.host,
                         port=args.port, policy_path=args.policy)
    print("=" * 70)
    print("Approval-queue web UI for run: %s" % run_dir)
    print("URL:   http://%s:%d/" % (args.host, server.server_address[1]))
    print("Token: %s" % server.app.token)
    print("=" * 70)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: bound to a non-localhost interface without TLS "
              "or real authentication — this configuration is explicitly "
              "unsupported.", file=sys.stderr)
    print("SECURITY NOTES: this console uses a single local token "
          "(shown above) and in-memory sessions (no SSO, no session "
          "persistence). Anyone with the token can approve queued "
          "actions. Break-glass decisions are CLI-only. Production "
          "deployments need real authentication (OIDC/mTLS), TLS "
          "termination, and the KMS-backed log key.",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
