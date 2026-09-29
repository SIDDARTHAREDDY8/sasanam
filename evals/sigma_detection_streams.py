"""Synthetic Sasanam audit-log streams with ground-truth labels.

Adapted from the wave-196 Sigma+Falco spike generator
(``teams/wave196-sigmafalco/spike/gen_streams.py``); the stream shapes
are unchanged so the spike's machinery checks stay comparable.
Deterministic (seeded RNG). Every stream is a dict:
    {"name": str, "events": [event...], "expect": {rule_short: bool}}

Event schema (synthetic, grounded in Sasanam concepts):
  chain: seq, ts (ISO-8601 Z), prev_hash, hash, sig_key_id, sig_key_version
  identity: type=identity, agent_id, jti, iss, aud, ip, geo (city)
  decision: type=decision, agent_id, jti, tool (server::tool), action,
            verdict (allow/deny/require_approval), geo,
            ceremony_window_end (signing key's window)
  key_use:  type=key_use, key_id, key_version, operation,
            ceremony_window_start/end
  checkpoint: type=checkpoint, merkle_root, ceremony_window_end

$0 spend, synthetic/local deterministic only. No network.
"""

import math
import random
from datetime import datetime, timedelta, timezone

CITIES = {
    "Lagos": (6.52, 3.37),
    "Abuja": (9.06, 7.49),
    "London": (51.51, -0.13),
    "New York": (40.71, -74.00),
    "Singapore": (1.35, 103.82),
    "Tokyo": (35.68, 139.69),
    "Sydney": (-33.87, 151.21),
}

TOOLS = ["fileserver::read", "fileserver::write", "egress::post",
         "model::invoke", "db::query"]
ACTIONS = {"fileserver::read": "file.read", "fileserver::write": "file.write",
           "egress::post": "egress.post", "model::invoke": "model.invoke",
           "db::query": "db.query"}

BASE = datetime(2026, 9, 25, 0, 0, tzinfo=timezone.utc)
REVOKED_V2_AT = "2026-09-20T00:00:00Z"
CEREMONY_END = BASE + timedelta(hours=6)  # 2026-09-25T06:00Z


def haversine_km(a, b):
    lat1, lon1 = (math.radians(x) for x in CITIES[a])
    lat2, lon2 = (math.radians(x) for x in CITIES[b])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class Stream:
    def __init__(self, rng):
        self.rng = rng
        self.events = []
        self.seq = 0
        self.prev = "00" * 32

    def _chain(self, ts, sig_key_version=3):
        self.seq += 1
        h = "%064x" % self.rng.getrandbits(256)
        ev = {"seq": self.seq, "ts": _iso(ts), "prev_hash": self.prev,
              "hash": h, "sig_key_id": "op-key-1",
              "sig_key_version": sig_key_version}
        self.prev = h
        return ev

    def add(self, ts, sig_key_version=3, **fields):
        ev = self._chain(ts, sig_key_version)
        ev.update(fields)
        self.events.append(ev)
        return ev

    def identity(self, ts, agent_id, geo, **kw):
        return self.add(ts, type="identity", agent_id=agent_id,
                        jti="jti-%s-%d" % (agent_id, self.seq),
                        iss="dex", aud="sasanam",
                        ip="10.0.%d.%d" % (self.rng.randrange(1, 9),
                                           self.rng.randrange(2, 250)),
                        geo=geo, **kw)

    def decision(self, ts, agent_id, verdict=None, tool=None, geo="Lagos",
                 window_end=None, **kw):
        tool = tool or self.rng.choice(TOOLS)
        verdict = verdict or self.rng.choices(
            ["allow", "require_approval", "deny"], [0.7, 0.2, 0.1])[0]
        # Normal model: the signing key's ceremony window covers the event
        # (rotation happens off-stream). Deliberate violations pass an
        # explicit window_end.
        return self.add(ts, type="decision", agent_id=agent_id,
                        jti="jti-%s-%d" % (agent_id, self.seq),
                        tool=tool, action=ACTIONS[tool], verdict=verdict,
                        geo=geo,
                        ceremony_window_end=window_end or _iso(ts + timedelta(hours=6)),
                        **kw)

    def key_use(self, ts, key_version=3, window_end=None, **kw):
        return self.add(ts, type="key_use", key_id="op-key-1",
                        key_version=key_version, operation="sign",
                        ceremony_window_start=_iso(ts - timedelta(hours=6)),
                        ceremony_window_end=window_end or _iso(ts + timedelta(hours=6)),
                        sig_key_version=key_version, **kw)

    def checkpoint(self, ts, sig_key_version=3, window_end=None, **kw):
        return self.add(ts, type="checkpoint",
                        merkle_root="%064x" % self.rng.getrandbits(256),
                        ceremony_window_end=window_end or _iso(ts + timedelta(hours=6)),
                        sig_key_version=sig_key_version, **kw)


def _normal_filler(s, t0, minutes, agents_geos, n_decisions=120,
                   max_burst=8, label_prefix=""):
    """Benign background traffic: stable geos, capped approval bursts."""
    t = t0
    for agent_id, geo in agents_geos:
        s.identity(t, agent_id, geo)
    for i in range(n_decisions):
        t = t0 + timedelta(minutes=s.rng.uniform(0, minutes))
        agent_id, geo = s.rng.choice(agents_geos)
        s.decision(t, agent_id, geo=geo)
    # A few in-window key uses and checkpoints.
    for i in range(6):
        s.key_use(t0 + timedelta(minutes=s.rng.uniform(0, 300)))
    for i in range(3):
        s.checkpoint(t0 + timedelta(minutes=s.rng.uniform(0, 300)))


def build_streams(seed=196):
    streams = []
    counter = [0]

    def new_stream(name, expect):
        # Stable per-stream seed (PYTHONHASHSEED randomizes str.__hash__).
        counter[0] += 1
        rng = random.Random(seed * 100003 + counter[0] * 1009)
        return Stream(rng), {"name": name, "expect": expect}

    # ---- Normal streams (expect nothing) ----
    s, meta = new_stream("N1_steady_ops", {})
    t0 = BASE
    _normal_filler(s, t0, 480, [("agent-01", "Lagos"), ("agent-02", "London"),
                                ("agent-03", "Singapore")])
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("N2_velocity_boundary", {})
    t0 = BASE
    _normal_filler(s, t0, 120, [("agent-04", "London")], n_decisions=20)
    # Exactly 20 require_approval inside one 10-minute window (under 25).
    burst = t0 + timedelta(hours=2)
    for i in range(20):
        s.decision(burst + timedelta(seconds=i * 25), "agent-04",
                   verdict="require_approval", geo="London")
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("N3_short_hop", {})
    t0 = BASE
    s.identity(t0, "agent-05", "Lagos")
    s.identity(t0 + timedelta(minutes=40), "agent-05", "Abuja")  # ~700 km
    _normal_filler(s, t0, 120, [("agent-05", "Lagos")], n_decisions=30)
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("N4_window_edge", {})
    t0 = BASE
    edge_ts = BASE + timedelta(hours=2)
    # Key used 1 minute before its ceremony window closes: must NOT fire.
    s.key_use(edge_ts, window_end=_iso(edge_ts + timedelta(minutes=1)))
    _normal_filler(s, t0, 120, [("agent-06", "Tokyo")], n_decisions=30)
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("N5_pre_revocation", {})
    t0 = BASE
    # v2-signed entry 1h BEFORE the v2 revocation timestamp.
    s.checkpoint(datetime(2026, 9, 19, 23, 0, tzinfo=timezone.utc),
                 sig_key_version=2)
    _normal_filler(s, t0, 120, [("agent-08", "Sydney")], n_decisions=30)
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("N6_breakglass", {})
    t0 = BASE
    burst = t0 + timedelta(hours=1)
    for i in range(60):
        s.decision(burst + timedelta(seconds=i * 9), "agent-breakglass-01",
                   verdict="require_approval", geo="London")
    _normal_filler(s, t0, 120, [("agent-09", "London")], n_decisions=30)
    meta["events"] = s.events
    streams.append(meta)

    # ---- Attack streams ----
    s, meta = new_stream("A1_impossible_travel",
                         {"impossible_travel": True})
    t0 = BASE
    _normal_filler(s, t0, 120, [("agent-07", "Lagos")], n_decisions=40)
    s.identity(t0 + timedelta(hours=3), "agent-07", "Lagos")
    s.identity(t0 + timedelta(hours=3, minutes=22), "agent-07", "Singapore")
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("A2_approval_flood", {"approval_velocity": True})
    t0 = BASE
    _normal_filler(s, t0, 120, [("agent-11", "New York")], n_decisions=30)
    burst = t0 + timedelta(hours=2)
    for i in range(40):
        s.decision(burst + timedelta(seconds=i * 13), "agent-11",
                   verdict="require_approval", geo="New York")
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("A3_late_key_use", {"key_ceremony_window": True})
    t0 = BASE
    _normal_filler(s, t0, 120, [("agent-12", "Tokyo")], n_decisions=30)
    # Key used 2h AFTER its ceremony window closed: must fire.
    late_ts = BASE + timedelta(hours=4)
    s.key_use(late_ts, window_end=_iso(BASE + timedelta(hours=2)))
    meta["events"] = s.events
    streams.append(meta)

    s, meta = new_stream("A4_revoked_key", {"revoked_key_signature": True})
    t0 = BASE
    _normal_filler(s, t0, 120, [("agent-13", "Sydney")], n_decisions=30)
    s.checkpoint(datetime(2026, 9, 20, 3, 0, tzinfo=timezone.utc),
                 sig_key_version=2)  # 3h after revocation
    meta["events"] = s.events
    streams.append(meta)

    for meta in streams:
        meta["events"].sort(key=lambda e: e["ts"])
    return streams


if __name__ == "__main__":
    streams = build_streams()
    print("Lagos->Singapore km:", round(haversine_km("Lagos", "Singapore")))
    print("Lagos->Abuja km:", round(haversine_km("Lagos", "Abuja")))
    for st in streams:
        n_attack = sum(1 for _ in [st["expect"]] if st["expect"])
        print("%-22s events=%4d expect=%s" % (st["name"], len(st["events"]),
                                             st["expect"] or "-"))
