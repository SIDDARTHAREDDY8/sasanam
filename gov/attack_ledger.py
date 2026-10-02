"""PyRIT-pattern attack ledger: scorer protocol + sqlite3 attack memory.

Mechanism provenance: microsoft/PyRIT (MIT -- mechanism only, no PyRIT
code vendored; the canonical repo is microsoft/PyRIT, Azure/PyRIT is an
archived stub). PyRIT's red-team loop is attacker -> target -> scorer
with a persistent memory: MemoryInterface, PromptMemoryEntry (every
prompt/response piece), SeedEntry (SHA256-hashed attack seeds),
ScoreEntry linked to judged observations via a score<->observation link
table, and ScenarioResultEntry with a plan_seed_id_map -- a scenario
registry where a plan is a deterministic seed->attack mapping, replayable
byte-for-byte.

What this module is: an adaptive red-team loop with a persistent,
tamper-evident attack memory, stdlib-only (sqlite3 covers the contract):

- scenarios register as deterministic seed->attack plans, validated
  against the gov.battery_lang plugin/strategy vocabularies (composition,
  not duplication);
- every attack observation is content-addressed (sha256);
- scores cannot reference nonexistent observations (referential
  integrity, fail-closed -- PyRIT's MemorySession raises on a score
  referencing a nonexistent observation);
- the ledger is hash-chained (tamper-evident; a natural evidence-bundle
  input);
- campaigns replay deterministically from stored seeds, and replay
  diffs catch regressions: past BREAKs become queryable regression
  seeds.

Determinism: no randomness anywhere; seeds are
sha256(label || seed_bytes); replay compares (step_index,
attack_digest, verdicts, notes) only -- timestamps are recorded but never
part of compared digests.

$0: all scorers deterministic, no LLM judges. Scorer exceptions are
fail-closed: verdict False + a recorded "scorer-error" rationale, never
a silent pass and never an escaping exception.
"""

import abc
import base64
import codecs
import datetime
import hashlib
import json
import os
import sqlite3
import unicodedata

_GENESIS = "GENESIS"


# ---------------------------------------------------------------------------
# Errors: programming-error refusals (ValueError family). No new decision
# codes are introduced by this module -- the taxonomy pin is untouched.
# ---------------------------------------------------------------------------

class ScoreLinkError(ValueError):
    """A score referenced a nonexistent observation (referential refusal)."""


class ScenarioRegistrationError(ValueError):
    """A scenario plan failed validation (unknown plugin/strategy, bad shape)."""


class ConverterError(ValueError):
    """A converter name was unknown or its input was out of domain."""


class CampaignNotFoundError(ValueError):
    """A campaign id referenced a campaign that was never recorded."""


# ---------------------------------------------------------------------------
# Scorer protocol (PyRIT ADAPT: a Scorer returns (verdict, rationale) and
# the loop consumes it to pick the next probe).
# ---------------------------------------------------------------------------

class Scorer(abc.ABC):
    """Deterministic scorer: score(observation) -> (verdict, rationale).

    verdict True means "the break condition was observed". Concrete
    scorers must be total on bytes and deterministic.
    """

    scorer_id = "base"

    @abc.abstractmethod
    def score(self, observation):
        """Return (bool verdict, str rationale) for the observation bytes."""


class SubstringScorer(Scorer):
    """Verdict True iff any needle is present in the observation."""

    def __init__(self, scorer_id, needles):
        self.scorer_id = scorer_id
        self.needles = tuple(needles)

    def score(self, observation):
        text = bytes(observation).decode("utf-8", errors="replace")
        for needle in self.needles:
            if needle in text:
                return True, "needle %r present" % (needle,)
        return False, "no needle present"


class DriftScorer(Scorer):
    """Verdict True iff the observation digest DRIFTED from the pinned digest.

    The regression-pin shape: pin the expected observation digest of a
    closed finding's break case; any drift is a break (the behavior the
    pin was guarding has changed).
    """

    def __init__(self, scorer_id, expected_digest):
        self.scorer_id = scorer_id
        self.expected_digest = expected_digest

    def score(self, observation):
        got = hashlib.sha256(bytes(observation)).hexdigest()
        if got != self.expected_digest:
            return True, "drift: %s != pinned %s" % (got[:16],
                                                     self.expected_digest[:16])
        return False, "observation matches pinned digest"


# ---------------------------------------------------------------------------
# Converter pipeline (PyRIT ADAPT: converter stacks as probe generators).
# Deterministic, stdlib-only, fail-closed on unknown names.
# ---------------------------------------------------------------------------

def _c_base64(data):
    return base64.b64encode(data)


def _c_rot13(data):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as e:
        raise ConverterError("rot13 requires ascii input: %s" % (e,))
    return codecs.encode(text, "rot_13").encode("ascii")


def _c_unicode_fold(data):
    text = data.decode("utf-8", errors="replace")
    return unicodedata.normalize("NFKC", text).encode("utf-8")


CONVERTERS = {
    "base64": _c_base64,
    "rot13": _c_rot13,
    "unicode-fold": _c_unicode_fold,
}


def apply_converters(data, names):
    """Apply the named converters in order. Unknown names refuse fail-closed."""
    out = bytes(data)
    for name in names:
        fn = CONVERTERS.get(name)
        if fn is None:
            raise ConverterError("unknown converter: %r" % (name,))
        out = fn(out)
    return out


# ---------------------------------------------------------------------------
# Attack ledger
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS pieces (
    piece_id   TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    body       BLOB NOT NULL,
    body_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scores (
    score_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    piece_id   TEXT NOT NULL REFERENCES pieces(piece_id),
    scorer_id  TEXT NOT NULL,
    verdict    INTEGER NOT NULL,
    rationale  TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seeds (
    seed_id    TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    seed_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scenarios (
    name       TEXT PRIMARY KEY,
    plan_json  TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_name TEXT NOT NULL,
    seed_id      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    digest       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_steps (
    campaign_id  INTEGER NOT NULL,
    step_index   INTEGER NOT NULL,
    attack_digest TEXT NOT NULL,
    piece_id     TEXT NOT NULL,
    verdicts_json TEXT NOT NULL,
    notes_json   TEXT NOT NULL,
    PRIMARY KEY (campaign_id, step_index)
);
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    row_id     TEXT NOT NULL,
    row_digest TEXT NOT NULL,
    prev_digest TEXT NOT NULL,
    digest     TEXT NOT NULL
);
"""


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class AttackLedger:
    """sqlite3 attack memory with a hash-chained event log."""

    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -- chain -----------------------------------------------------------
    def _chain(self, table_name, row_id, row_digest):
        cur = self.conn.execute(
            "SELECT digest FROM events ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else _GENESIS
        digest = hashlib.sha256(
            (prev + "|" + table_name + "|" + row_id + "|"
             + row_digest).encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO events (table_name, row_id, row_digest, prev_digest,"
            " digest) VALUES (?, ?, ?, ?, ?)",
            (table_name, row_id, row_digest, prev, digest))

    def verify_chain(self):
        """Recompute the hash chain; False on any tamper or break."""
        prev = _GENESIS
        cur = self.conn.execute(
            "SELECT table_name, row_id, row_digest, prev_digest, digest"
            " FROM events ORDER BY seq")
        for table_name, row_id, row_digest, prev_digest, digest in cur:
            if prev_digest != prev:
                return False
            want = hashlib.sha256(
                (prev + "|" + table_name + "|" + row_id + "|"
                 + row_digest).encode("utf-8")).hexdigest()
            if want != digest:
                return False
            # the chained row_digest must still match the live row
            if not self._row_digest_matches(table_name, row_id, row_digest):
                return False
            prev = digest
        return True

    def _row_digest_matches(self, table_name, row_id, row_digest):
        # Each chained row_digest binds the row's CONTENT, recomputed
        # from the live row -- so under-the-hood rewrites break the
        # chain instead of passing through. created_at is deliberately
        # excluded (timestamps are recorded but never part of digests).
        queries = {
            "pieces": ("SELECT kind, body FROM pieces WHERE piece_id = ?",
                       (row_id,), lambda r: hashlib.sha256(
                           _canonical([r[0], bytes(r[1]).hex()])
                           .encode("utf-8")).hexdigest()),
            "scores": ("SELECT piece_id, scorer_id, verdict, rationale"
                       " FROM scores WHERE score_id = ?", (row_id,),
                       lambda r: hashlib.sha256(
                           _canonical([r[0], r[1], r[2], r[3]])
                           .encode("utf-8")).hexdigest()),
            "seeds": ("SELECT label, seed_bytes FROM seeds"
                      " WHERE seed_id = ?", (row_id,),
                      lambda r: hashlib.sha256(
                          r[0].encode("utf-8") + bytes(r[1])).hexdigest()),
            "scenarios": ("SELECT plan_json, labels_json FROM scenarios"
                          " WHERE name = ?", (row_id,),
                          lambda r: hashlib.sha256(
                              _canonical([r[0], r[1]])
                              .encode("utf-8")).hexdigest()),
            "campaigns": ("SELECT digest FROM campaigns WHERE id = ?",
                          (row_id,), lambda r: hashlib.sha256(
                              str(r[0]).encode("utf-8")).hexdigest()),
            "campaign_steps": (
                "SELECT attack_digest, piece_id, verdicts_json, notes_json"
                " FROM campaign_steps WHERE campaign_id = ?"
                " AND step_index = ?",
                tuple(row_id.split(":", 1)),
                lambda r: hashlib.sha256(
                    _canonical(list(r)).encode("utf-8")).hexdigest()),
        }
        q = queries.get(table_name)
        if q is None:
            return False
        cur = self.conn.execute(q[0], q[1])
        row = cur.fetchone()
        if row is None:
            return False
        return q[2](row) == row_digest

    # -- pieces ----------------------------------------------------------
    def record_piece(self, kind, body):
        body = bytes(body)
        piece_id = hashlib.sha256(body).hexdigest()
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO pieces (piece_id, kind, body, body_digest,"
            " created_at) VALUES (?, ?, ?, ?, ?)",
            (piece_id, kind, body, piece_id, _now()))
        if cur.rowcount:
            self._chain("pieces", piece_id, hashlib.sha256(
                _canonical([kind, body.hex()]).encode("utf-8")).hexdigest())
        self.conn.commit()
        return piece_id

    # -- seeds -----------------------------------------------------------
    def record_seed(self, label, seed_bytes):
        seed_bytes = bytes(seed_bytes)
        seed_id = hashlib.sha256(
            label.encode("utf-8") + seed_bytes).hexdigest()
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO seeds (seed_id, label, seed_bytes,"
            " created_at) VALUES (?, ?, ?, ?)",
            (seed_id, label, seed_bytes, _now()))
        if cur.rowcount:
            self._chain("seeds", seed_id, seed_id)
        self.conn.commit()
        return seed_id

    # -- scenarios -------------------------------------------------------
    def register_scenario(self, name, plan, labels):
        """Register a deterministic seed->attack plan.

        plan: {"seed_label": str, "steps": [{"plugin", "strategy",
        "payload", "converters"?}]}. plugin/strategy are validated
        against the gov.battery_lang vocabularies (composition, not
        duplication). Unknown ids, bad shapes, and duplicate names
        refuse fail-closed.
        """
        from gov import battery_lang as bl
        if not isinstance(plan, dict):
            raise ScenarioRegistrationError("plan must be a dict")
        if not isinstance(plan.get("seed_label"), str):
            raise ScenarioRegistrationError("plan needs a seed_label")
        steps = plan.get("steps")
        if not isinstance(steps, list):
            raise ScenarioRegistrationError("plan needs a steps list")
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ScenarioRegistrationError(
                    "step %d not a dict" % i)
            plugin = step.get("plugin")
            strategy = step.get("strategy")
            payload = step.get("payload")
            if plugin not in bl.PLUGINS:
                raise ScenarioRegistrationError(
                    "step %d: unknown plugin %r" % (i, plugin))
            if strategy not in bl.STRATEGIES:
                raise ScenarioRegistrationError(
                    "step %d: unknown strategy %r" % (i, strategy))
            if not isinstance(payload, str):
                raise ScenarioRegistrationError(
                    "step %d: payload must be str" % i)
            for cname in step.get("converters", []):
                if cname not in CONVERTERS:
                    raise ScenarioRegistrationError(
                        "step %d: unknown converter %r" % (i, cname))
        labels = list(labels or [])
        cur = self.conn.execute(
            "SELECT 1 FROM scenarios WHERE name = ?", (name,))
        if cur.fetchone():
            raise ScenarioRegistrationError(
                "scenario %r already registered" % (name,))
        plan_json = _canonical(plan)
        labels_json = _canonical(labels)
        self.conn.execute(
            "INSERT INTO scenarios (name, plan_json, labels_json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (name, plan_json, labels_json, _now()))
        self._chain("scenarios", name, hashlib.sha256(
            _canonical([plan_json, labels_json]).encode("utf-8"))
            .hexdigest())
        self.conn.commit()

    def scenarios_by_label(self, label):
        cur = self.conn.execute(
            "SELECT name, plan_json, labels_json FROM scenarios")
        out = []
        for name, plan_json, labels_json in cur:
            if label in json.loads(labels_json):
                out.append({"name": name,
                            "plan": json.loads(plan_json)})
        return out

    def _get_scenario(self, name):
        cur = self.conn.execute(
            "SELECT plan_json FROM scenarios WHERE name = ?", (name,))
        row = cur.fetchone()
        if row is None:
            raise ScenarioRegistrationError(
                "unknown scenario %r" % (name,))
        return json.loads(row[0])

    # -- scores ----------------------------------------------------------
    def record_score(self, piece_id, scorer_id, verdict, rationale):
        cur = self.conn.execute(
            "SELECT 1 FROM pieces WHERE piece_id = ?", (piece_id,))
        if cur.fetchone() is None:
            raise ScoreLinkError(
                "score references nonexistent observation %s"
                % (piece_id[:16],))
        cur = self.conn.execute(
            "INSERT INTO scores (piece_id, scorer_id, verdict, rationale,"
            " created_at) VALUES (?, ?, ?, ?, ?)",
            (piece_id, scorer_id, 1 if verdict else 0, str(rationale),
             _now()))
        score_id = cur.lastrowid
        self._chain("scores", str(score_id), hashlib.sha256(
            _canonical([piece_id, scorer_id, 1 if verdict else 0,
                        str(rationale)]).encode("utf-8")).hexdigest())
        self.conn.commit()
        return score_id

    def score_with(self, scorer, piece_id):
        """Run a scorer against a recorded piece, fail-closed.

        Scorer exceptions -> (False, "scorer-error: ..."), recorded, never
        raised and never a claimed break.
        """
        cur = self.conn.execute(
            "SELECT body FROM pieces WHERE piece_id = ?", (piece_id,))
        row = cur.fetchone()
        if row is None:
            raise ScoreLinkError(
                "score references nonexistent observation %s"
                % (piece_id[:16],))
        try:
            verdict, rationale = scorer.score(bytes(row[0]))
            verdict = bool(verdict)
            rationale = str(rationale)
        except Exception as e:  # noqa: BLE001 -- fail-closed by contract
            verdict, rationale = False, "scorer-error: %s: %s" % (
                type(e).__name__, e)
        self.record_score(piece_id, scorer.scorer_id, verdict, rationale)
        return verdict, rationale

    # -- campaigns -------------------------------------------------------
    def _attack_bytes(self, step):
        payload = step["payload"]
        raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(
            payload)
        return apply_converters(raw, step.get("converters", []))

    def run_campaign(self, scenario_name, target_fn, scorers,
                     seed_label=None):
        """Run a scenario's plan against target_fn, recording everything.

        target_fn(attack_bytes) -> observation bytes. scorers: list of
        Scorer. Returns the campaign id. Deterministic given the plan,
        the seed label, and a deterministic target_fn.
        """
        plan = self._get_scenario(scenario_name)
        label = seed_label or plan["seed_label"]
        seed_id = self.record_seed(
            label, _canonical(plan).encode("utf-8"))
        step_rows = []
        for i, step in enumerate(plan["steps"]):
            try:
                attack = self._attack_bytes(step)
            except ConverterError as e:
                # Fail-closed: a converter that refuses at run time must
                # not abort the campaign or escape to the caller. Record
                # the refusal as the observation and keep going.
                attack = b""
                observation = ("converter-error: %s" % (e,)).encode("utf-8")
            else:
                try:
                    observation = bytes(target_fn(attack))
                except Exception as e:  # noqa: BLE001 -- loud, recorded
                    observation = ("target-error: %s: %s"
                                   % (type(e).__name__, e)).encode("utf-8")
            piece_id = self.record_piece("observation", observation)
            verdicts, notes = [], []
            for scorer in scorers:
                v, n = self.score_with(scorer, piece_id)
                verdicts.append(v)
                notes.append(n)
            step_rows.append((i, hashlib.sha256(attack).hexdigest(),
                              piece_id, _canonical(verdicts),
                              _canonical(notes)))
        digest = hashlib.sha256(
            _canonical([(i, a, p, v, n)
                        for i, a, p, v, n in step_rows]).encode("utf-8")
        ).hexdigest()
        cur = self.conn.execute(
            "INSERT INTO campaigns (scenario_name, seed_id, started_at,"
            " digest) VALUES (?, ?, ?, ?)",
            (scenario_name, seed_id, _now(), digest))
        campaign_id = cur.lastrowid
        for i, attack_digest, piece_id, vj, nj in step_rows:
            self.conn.execute(
                "INSERT INTO campaign_steps (campaign_id, step_index,"
                " attack_digest, piece_id, verdicts_json, notes_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (campaign_id, i, attack_digest, piece_id, vj, nj))
            self._chain("campaign_steps", "%d:%d" % (campaign_id, i),
                        hashlib.sha256(_canonical(
                            [attack_digest, piece_id, vj, nj])
                            .encode("utf-8")).hexdigest())
        self._chain("campaigns", str(campaign_id),
                    hashlib.sha256(digest.encode("utf-8")).hexdigest())
        self.conn.commit()
        return campaign_id

    def campaign_verdicts(self, campaign_id):
        """[(step_index, any_break)] for a recorded campaign."""
        cur = self.conn.execute(
            "SELECT step_index, verdicts_json FROM campaign_steps"
            " WHERE campaign_id = ? ORDER BY step_index", (campaign_id,))
        return [(i, any(json.loads(vj))) for i, vj in cur]

    def replay_campaign(self, campaign_id, target_fn, scorers):
        """Re-run a campaign's steps against target_fn WITHOUT writing.

        The caller passes the same scorers the run used; verdicts are
        recomputed in-memory and never recorded, so replay is read-only.
        Compares (attack_digest, verdicts, notes) per step against the
        recorded run. Returns a list of diff dicts; empty means the
        replay was identical. A verdict-drift entry is the regression
        signal: the target's behavior changed since the campaign.
        """
        cur = self.conn.execute(
            "SELECT scenario_name FROM campaigns WHERE id = ?",
            (campaign_id,))
        row = cur.fetchone()
        if row is None:
            raise CampaignNotFoundError("unknown campaign %r" % (campaign_id,))
        plan = self._get_scenario(row[0])
        cur = self.conn.execute(
            "SELECT step_index, attack_digest, verdicts_json, notes_json"
            " FROM campaign_steps WHERE campaign_id = ? ORDER BY step_index",
            (campaign_id,))
        stored = {i: (a, vj, nj) for i, a, vj, nj in cur}
        diffs = []
        for i, step in enumerate(plan["steps"]):
            try:
                attack = self._attack_bytes(step)
            except ConverterError as e:
                diffs.append({"step_index": i, "kind": "converter-error",
                              "note": str(e)})
                continue
            attack_digest = hashlib.sha256(attack).hexdigest()
            try:
                observation = bytes(target_fn(attack))
            except Exception as e:  # noqa: BLE001
                observation = ("target-error: %s: %s"
                               % (type(e).__name__, e)).encode("utf-8")
            verdicts, notes = [], []
            for scorer in scorers:
                try:
                    v, n = scorer.score(observation)
                    verdicts.append(bool(v))
                    notes.append(str(n))
                except Exception as e:  # noqa: BLE001 -- fail-closed
                    verdicts.append(False)
                    notes.append("scorer-error: %s: %s"
                                 % (type(e).__name__, e))
            s = stored.get(i)
            if s is None:
                diffs.append({"step_index": i, "kind": "missing-step"})
                continue
            s_attack, s_vj, s_nj = s
            if attack_digest != s_attack:
                diffs.append({"step_index": i, "kind": "attack-drift",
                              "before": s_attack, "after": attack_digest})
            if _canonical(verdicts) != s_vj:
                diffs.append({"step_index": i, "kind": "verdict-drift",
                              "before": json.loads(s_vj), "after": verdicts})
            elif _canonical(notes) != s_nj:
                diffs.append({"step_index": i, "kind": "note-drift",
                              "before": json.loads(s_nj), "after": notes})
        return diffs

    # -- evidence --------------------------------------------------------
    def campaign_evidence_rows(self, campaign_id):
        """Machine-readable rows for evidence bundles.

        (campaign_id, scenario, step_index, plugin_id, strategy_id,
        verdict) -- feeds gov.battery_envelope-style rows without
        duplicating the envelope vocabulary.
        """
        cur = self.conn.execute(
            "SELECT scenario_name FROM campaigns WHERE id = ?",
            (campaign_id,))
        row = cur.fetchone()
        if row is None:
            raise CampaignNotFoundError("unknown campaign %r" % (campaign_id,))
        plan = self._get_scenario(row[0])
        verdicts = dict(self.campaign_verdicts(campaign_id))
        rows = []
        for i, step in enumerate(plan["steps"]):
            rows.append({
                "campaign_id": campaign_id,
                "scenario": row[0],
                "step_index": i,
                "plugin_id": step["plugin"],
                "strategy_id": step["strategy"],
                "verdict": "BREAK" if verdicts.get(i) else "HELD",
            })
        return rows

    def close(self):
        self.conn.close()
