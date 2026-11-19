"""SQLite incident store, owned by the single observer instance.

Do not share the file between pods: the deployment runs one replica with
strategy Recreate so two watchers never write to the same database.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .lifecycle import Incident, State
from .snapshot import WorkloadRef

# Recorded in the file as PRAGMA user_version. When a table changes, raise this and add
# the step that brings an older file up to date in Store._open_schema: SCHEMA only
# creates what is missing and never alters a table that already exists on a volume.
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    cluster TEXT NOT NULL,
    namespace TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    workload_uid TEXT NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT NOT NULL,
    pods TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_observed TEXT NOT NULL,
    pending_since TEXT,
    firing_since TEXT,
    recovering_since TEXT,
    resolved_at TEXT,
    recurrence_count INTEGER NOT NULL DEFAULT 0,
    flap_count INTEGER NOT NULL DEFAULT 0,
    stale INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_fingerprint ON incidents (fingerprint);
CREATE INDEX IF NOT EXISTS incidents_state ON incidents (state);

CREATE TABLE IF NOT EXISTS evidence (
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    ref TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (incident_id, ref)
);

CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_incident ON activity (incident_id);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL,          -- template | model
    status TEXT NOT NULL,          -- ok | unavailable
    model TEXT,
    latency_ms INTEGER,
    error TEXT,
    payload TEXT,
    dropped TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS analyses_incident ON analyses (incident_id);

-- Outbox: the observer owns retries and status; the notifier only delivers.
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,           -- stable: <incident>:<event>:<n>
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,          -- queued | sending | provider_accepted | retry_scheduled | failed
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_error TEXT,
    accepted_at TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notifications_incident ON notifications (incident_id);
CREATE INDEX IF NOT EXISTS notifications_due ON notifications (status, next_attempt_at);

-- Digest outbox: same lifecycle as notifications, but not tied to one incident.
CREATE TABLE IF NOT EXISTS digests (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    event TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_error TEXT,
    accepted_at TEXT,
    payload TEXT NOT NULL
);

-- Info events waiting for the next digest.
CREATE TABLE IF NOT EXISTS digest_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT NOT NULL,
    text TEXT NOT NULL
);

-- Questions asked in the UI and their answers (claims carry evidence refs).
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    claims TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    dropped TEXT NOT NULL DEFAULT '[]',
    latency_ms INTEGER
);

-- Approved actions sent to the executor, and their verification.
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL,          -- requested | executed | failed | verified
    result TEXT,
    generation INTEGER,
    verified_at TEXT
);

-- Experimental troubleshooting runs: model steps, tool results and the conclusion.
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,          -- running | done | incomplete | failed
    model TEXT,
    think INTEGER NOT NULL DEFAULT 0,
    steps TEXT NOT NULL DEFAULT '[]',
    conclusion TEXT NOT NULL DEFAULT '{}',
    error TEXT
);

-- Operator marks, written only by the web UI. Kept apart from incidents so the rule
-- loop never overwrites them; neither mark changes the lifecycle.
CREATE TABLE IF NOT EXISTS incident_marks (
    incident_id TEXT PRIMARY KEY REFERENCES incidents (id) ON DELETE CASCADE,
    acknowledged_at TEXT,
    silenced_until TEXT
);
"""


@dataclass
class AnalysisRecord:
    id: int
    incident_id: str
    created_at: datetime
    source: str
    status: str
    model: str | None
    latency_ms: int | None
    error: str | None
    payload: dict | None
    dropped: list[str]


@dataclass
class OutboxItem:
    id: str
    incident_id: str
    event: str
    created_at: datetime
    status: str
    attempts: int
    next_attempt_at: datetime | None
    last_error: str | None
    accepted_at: datetime | None
    payload: dict


OUTBOXES = ("notifications", "digests")


@dataclass
class Investigation:
    id: str
    incident_id: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    model: str | None
    think: bool
    steps: list[dict]
    conclusion: dict
    error: str | None


@dataclass
class ActionRecord:
    id: str
    incident_id: str
    action: str
    params: dict
    requested_at: datetime
    status: str
    result: str | None
    generation: int | None
    verified_at: datetime | None


@dataclass
class QuestionRecord:
    id: int
    incident_id: str
    at: datetime
    question: str
    answer: str
    claims: list[dict]
    source: str
    status: str
    dropped: list[str]
    latency_ms: int | None


@dataclass
class DigestItem:
    id: int
    at: datetime
    kind: str
    namespace: str
    text: str


@dataclass
class Marks:
    acknowledged_at: datetime | None = None
    silenced_until: datetime | None = None

    def silenced(self, now: datetime) -> bool:
        return self.silenced_until is not None and now < self.silenced_until


@dataclass
class EvidenceItem:
    ref: str
    collected_at: datetime
    kind: str
    summary: str
    payload: dict


@dataclass
class ActivityItem:
    at: datetime
    kind: str
    message: str


def _ts(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


class Store:
    def __init__(self, path: str | Path) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._open_schema(path)

    def _open_schema(self, path: str | Path) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            self._db.close()
            raise RuntimeError(f"{path} has schema version {version}, written by a newer KubeNess; "
                               f"this build reads up to version {SCHEMA_VERSION}")
        self._db.executescript(SCHEMA)
        # 0 is a new file, or one from before the version was recorded: the same tables.
        self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- incidents -----------------------------------------------------------
    def save_incident(self, inc: Incident) -> None:
        row = {
            "id": inc.id,
            "fingerprint": inc.fingerprint,
            "rule_id": inc.rule_id,
            "cluster": inc.cluster,
            "namespace": inc.workload.namespace,
            "workload_kind": inc.workload.kind,
            "workload_name": inc.workload.name,
            "workload_uid": inc.workload.uid,
            "severity": inc.severity,
            "state": inc.state.value,
            "reason": inc.reason,
            "details": json.dumps(inc.details, sort_keys=True),
            "pods": json.dumps(inc.pods),
            "first_seen": _ts(inc.first_seen),
            "last_observed": _ts(inc.last_observed),
            "pending_since": _ts(inc.pending_since),
            "firing_since": _ts(inc.firing_since),
            "recovering_since": _ts(inc.recovering_since),
            "resolved_at": _ts(inc.resolved_at),
            "recurrence_count": inc.recurrence_count,
            "flap_count": inc.flap_count,
            "stale": int(inc.stale),
        }
        cols = ", ".join(row)
        params = ", ".join(f":{k}" for k in row)
        updates = ", ".join(f"{k} = excluded.{k}" for k in row if k != "id")
        with self._lock:
            self._db.execute(
                f"INSERT INTO incidents ({cols}) VALUES ({params}) ON CONFLICT(id) DO UPDATE SET {updates}", row
            )

    def delete_incident(self, incident_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))

    def _query(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    @staticmethod
    def _incident(r: sqlite3.Row) -> Incident:
        return Incident(
            id=r["id"],
            fingerprint=r["fingerprint"],
            rule_id=r["rule_id"],
            cluster=r["cluster"],
            workload=WorkloadRef(r["workload_kind"], r["namespace"], r["workload_name"], r["workload_uid"]),
            severity=r["severity"],
            state=State(r["state"]),
            reason=r["reason"],
            first_seen=_dt(r["first_seen"]),
            last_observed=_dt(r["last_observed"]),
            details=json.loads(r["details"]),
            pods=json.loads(r["pods"]),
            pending_since=_dt(r["pending_since"]),
            firing_since=_dt(r["firing_since"]),
            recovering_since=_dt(r["recovering_since"]),
            resolved_at=_dt(r["resolved_at"]),
            recurrence_count=r["recurrence_count"],
            flap_count=r["flap_count"],
            stale=bool(r["stale"]),
        )

    def open_incidents(self) -> list[Incident]:
        rows = self._query("SELECT * FROM incidents WHERE state != 'resolved'")
        return [self._incident(r) for r in rows]

    def resolved_since(self, since: datetime) -> list[Incident]:
        rows = self._query(
            "SELECT * FROM incidents WHERE state = 'resolved' AND resolved_at >= ? ORDER BY resolved_at",
            (since.isoformat(),),
        )
        return [self._incident(r) for r in rows]

    def list_incidents(self, include_resolved: bool = True, limit: int = 200) -> list[Incident]:
        where = "" if include_resolved else "WHERE state != 'resolved'"
        rows = self._query(
            f"SELECT * FROM incidents {where} ORDER BY (state = 'resolved'), last_observed DESC LIMIT ?", (limit,)
        )
        return [self._incident(r) for r in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        rows = self._query("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        return self._incident(rows[0]) if rows else None

    # --- evidence and activity -------------------------------------------------
    def add_evidence(self, incident_id: str, items: list[EvidenceItem]) -> list[str]:
        """Store the items and return their refs.

        An item without a ref gets the next free e<n> here, under the lock. The rule
        loop and a troubleshooting run add evidence to the same incident from different
        threads; numbering outside the insert could hand both the same ref. A ref that
        already exists is an error, never a silent overwrite: claims cite these refs.
        """
        with self._lock:
            n = self._next_evidence_number(incident_id)
            for e in items:
                if not e.ref:
                    e.ref = f"e{n}"
                    n += 1
            self._db.execute("BEGIN")
            try:
                self._db.executemany(
                    "INSERT INTO evidence (incident_id, ref, collected_at, kind, summary, payload)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (incident_id, e.ref, e.collected_at.isoformat(), e.kind, e.summary,
                         json.dumps(e.payload, sort_keys=True))
                        for e in items
                    ],
                )
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
        return [e.ref for e in items]

    def _next_evidence_number(self, incident_id: str) -> int:
        """Call with the lock held."""
        row = self._db.execute(
            "SELECT COALESCE(MAX(CAST(SUBSTR(ref, 2) AS INTEGER)), 0) AS n FROM evidence WHERE incident_id = ?",
            (incident_id,)).fetchone()
        return row["n"] + 1

    def next_evidence_index(self, incident_id: str) -> int:
        """The number the next added item gets, for reading only: `add_evidence`
        assigns the refs itself."""
        with self._lock:
            return self._next_evidence_number(incident_id)

    def evidence(self, incident_id: str) -> list[EvidenceItem]:
        rows = self._query(
            "SELECT * FROM evidence WHERE incident_id = ? ORDER BY collected_at, CAST(SUBSTR(ref, 2) AS INTEGER)",
            (incident_id,),
        )
        return [
            EvidenceItem(r["ref"], _dt(r["collected_at"]), r["kind"], r["summary"], json.loads(r["payload"]))
            for r in rows
        ]

    def add_activity(self, incident_id: str, at: datetime, kind: str, message: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO activity (incident_id, at, kind, message) VALUES (?, ?, ?, ?)",
                (incident_id, at.isoformat(), kind, message),
            )

    def add_analysis(self, incident_id: str, at: datetime, source: str, status: str, payload: dict | None = None,
                     model: str | None = None, latency_ms: int | None = None, error: str | None = None,
                     dropped: list[str] | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO analyses (incident_id, created_at, source, status, model, latency_ms, error, payload, dropped)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (incident_id, at.isoformat(), source, status, model, latency_ms, error,
                 json.dumps(payload) if payload is not None else None, json.dumps(dropped or [])),
            )

    def analyses(self, incident_id: str) -> list[AnalysisRecord]:
        rows = self._query("SELECT * FROM analyses WHERE incident_id = ? ORDER BY id", (incident_id,))
        return [
            AnalysisRecord(r["id"], r["incident_id"], _dt(r["created_at"]), r["source"], r["status"], r["model"],
                           r["latency_ms"], r["error"], json.loads(r["payload"]) if r["payload"] else None,
                           json.loads(r["dropped"]))
            for r in rows
        ]

    def model_analyses(self) -> list[AnalysisRecord]:
        rows = self._query("SELECT * FROM analyses WHERE source IN ('model', 'shadow') ORDER BY id")
        return [
            AnalysisRecord(r["id"], r["incident_id"], _dt(r["created_at"]), r["source"], r["status"], r["model"],
                           r["latency_ms"], r["error"], json.loads(r["payload"]) if r["payload"] else None,
                           json.loads(r["dropped"]))
            for r in rows
        ]

    def activity(self, incident_id: str) -> list[ActivityItem]:
        rows = self._query("SELECT * FROM activity WHERE incident_id = ? ORDER BY id", (incident_id,))
        return [ActivityItem(_dt(r["at"]), r["kind"], r["message"]) for r in rows]

    # --- notification outbox -----------------------------------------------------
    @staticmethod
    def _outbox(r: sqlite3.Row) -> OutboxItem:
        return OutboxItem(r["id"], r["incident_id"], r["event"], _dt(r["created_at"]), r["status"], r["attempts"],
                          _dt(r["next_attempt_at"]), r["last_error"], _dt(r["accepted_at"]), json.loads(r["payload"]))

    def enqueue_notification(self, n: OutboxItem, table: str = "notifications") -> bool:
        """Insert unless the id exists; returns whether it was new."""
        assert table in OUTBOXES
        with self._lock:
            cur = self._db.execute(
                f"INSERT OR IGNORE INTO {table} (id, incident_id, event, created_at, status, attempts,"
                " next_attempt_at, last_error, accepted_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (n.id, n.incident_id, n.event, n.created_at.isoformat(), n.status, n.attempts,
                 _ts(n.next_attempt_at), n.last_error, _ts(n.accepted_at), json.dumps(n.payload)),
            )
            return cur.rowcount == 1

    def update_notification(self, notification_id: str, table: str = "notifications", **fields) -> None:
        assert table in OUTBOXES
        cols = {k: (_ts(v) if isinstance(v, datetime) else v) for k, v in fields.items()}
        sets = ", ".join(f"{k} = :{k}" for k in cols)
        with self._lock:
            self._db.execute(f"UPDATE {table} SET {sets} WHERE id = :id", {**cols, "id": notification_id})

    def notifications(self, incident_id: str | None = None, digests: bool = False) -> list[OutboxItem]:
        if digests:
            return [self._outbox(r) for r in self._query("SELECT * FROM digests ORDER BY created_at, rowid")]
        if incident_id is None:
            rows = self._query("SELECT * FROM notifications ORDER BY created_at, rowid")
        else:
            rows = self._query("SELECT * FROM notifications WHERE incident_id = ? ORDER BY created_at, rowid",
                               (incident_id,))
        return [self._outbox(r) for r in rows]

    def due_notifications(self, now: datetime, limit: int = 20, table: str = "notifications") -> list[OutboxItem]:
        assert table in OUTBOXES
        rows = self._query(
            f"SELECT * FROM {table} WHERE status IN ('queued', 'retry_scheduled')"
            " AND (next_attempt_at IS NULL OR next_attempt_at <= ?) ORDER BY created_at, rowid LIMIT ?",
            (now.isoformat(), limit),
        )
        return [self._outbox(r) for r in rows]

    def recover_sending(self, now: datetime) -> int:
        """A send interrupted by a restart may or may not have reached the provider.
        Retry it: a duplicate is better than a lost notification."""
        n = 0
        with self._lock:
            for table in OUTBOXES:
                cur = self._db.execute(
                    f"UPDATE {table} SET status = 'retry_scheduled', next_attempt_at = ? WHERE status = 'sending'",
                    (now.isoformat(),),
                )
                n += cur.rowcount
        return n

    def latest_notifications(self) -> dict[str, OutboxItem]:
        """Latest notification per incident."""
        rows = self._query(
            "SELECT n.* FROM notifications n JOIN (SELECT incident_id, MAX(rowid) AS r FROM notifications"
            " GROUP BY incident_id) m ON n.rowid = m.r"
        )
        return {r["incident_id"]: self._outbox(r) for r in rows}

    def outbox_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for table in OUTBOXES:
            for r in self._query(f"SELECT status, COUNT(*) AS n FROM {table} GROUP BY status"):
                counts[r["status"]] = counts.get(r["status"], 0) + r["n"]
        return counts

    # --- digest items -----------------------------------------------------------------
    def add_digest_item(self, at: datetime, kind: str, namespace: str, text: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO digest_items (at, kind, namespace, text) VALUES (?, ?, ?, ?)",
                             (at.isoformat(), kind, namespace, text))

    def digest_items(self) -> list[DigestItem]:
        rows = self._query("SELECT * FROM digest_items ORDER BY id")
        return [DigestItem(r["id"], _dt(r["at"]), r["kind"], r["namespace"], r["text"]) for r in rows]

    def clear_digest_items(self, ids: list[int]) -> None:
        with self._lock:
            self._db.executemany("DELETE FROM digest_items WHERE id = ?", [(i,) for i in ids])

    # --- operator marks ------------------------------------------------------------
    def marks(self, incident_id: str) -> Marks:
        rows = self._query("SELECT * FROM incident_marks WHERE incident_id = ?", (incident_id,))
        if not rows:
            return Marks()
        return Marks(_dt(rows[0]["acknowledged_at"]), _dt(rows[0]["silenced_until"]))

    def all_marks(self) -> dict[str, Marks]:
        rows = self._query("SELECT * FROM incident_marks")
        return {r["incident_id"]: Marks(_dt(r["acknowledged_at"]), _dt(r["silenced_until"])) for r in rows}

    def _set_mark(self, incident_id: str, column: str, value: datetime | None) -> None:
        with self._lock:
            self._db.execute(
                f"INSERT INTO incident_marks (incident_id, {column}) VALUES (?, ?)"
                f" ON CONFLICT(incident_id) DO UPDATE SET {column} = excluded.{column}",
                (incident_id, _ts(value)),
            )

    def set_acknowledged(self, incident_id: str, at: datetime | None) -> None:
        self._set_mark(incident_id, "acknowledged_at", at)

    def set_silenced_until(self, incident_id: str, until: datetime | None) -> None:
        self._set_mark(incident_id, "silenced_until", until)

    # --- questions -----------------------------------------------------------------------
    def add_question(self, incident_id: str, at: datetime, question: str, answer: str, claims: list[dict],
                     source: str, status: str, dropped: list[str], latency_ms: int | None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO questions (incident_id, at, question, answer, claims, source, status, dropped, latency_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (incident_id, at.isoformat(), question, answer, json.dumps(claims), source, status,
                 json.dumps(dropped), latency_ms),
            )
            return cur.lastrowid

    def questions(self, incident_id: str) -> list[QuestionRecord]:
        rows = self._query("SELECT * FROM questions WHERE incident_id = ? ORDER BY id DESC", (incident_id,))
        return [QuestionRecord(r["id"], r["incident_id"], _dt(r["at"]), r["question"], r["answer"],
                               json.loads(r["claims"]), r["source"], r["status"], json.loads(r["dropped"]),
                               r["latency_ms"]) for r in rows]

    def incidents_by_fingerprint(self, fingerprint: str) -> list[Incident]:
        rows = self._query("SELECT * FROM incidents WHERE fingerprint = ? ORDER BY first_seen", (fingerprint,))
        return [self._incident(r) for r in rows]

    # --- actions ---------------------------------------------------------------------------
    @staticmethod
    def _action(r: sqlite3.Row) -> ActionRecord:
        return ActionRecord(r["id"], r["incident_id"], r["action"], json.loads(r["params"]), _dt(r["requested_at"]),
                            r["status"], r["result"], r["generation"], _dt(r["verified_at"]))

    def add_action(self, a: ActionRecord) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO actions (id, incident_id, action, params, requested_at, status, result, generation,"
                " verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (a.id, a.incident_id, a.action, json.dumps(a.params), a.requested_at.isoformat(), a.status, a.result,
                 a.generation, _ts(a.verified_at)))

    def update_action(self, action_id: str, **fields) -> None:
        cols = {k: (_ts(v) if isinstance(v, datetime) else v) for k, v in fields.items()}
        sets = ", ".join(f"{k} = :{k}" for k in cols)
        with self._lock:
            self._db.execute(f"UPDATE actions SET {sets} WHERE id = :id", {**cols, "id": action_id})

    def actions(self, incident_id: str | None = None, status: str | None = None) -> list[ActionRecord]:
        where, args = [], []
        if incident_id:
            where.append("incident_id = ?")
            args.append(incident_id)
        if status:
            where.append("status = ?")
            args.append(status)
        sql = "SELECT * FROM actions" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY requested_at"
        return [self._action(r) for r in self._query(sql, tuple(args))]

    # --- retention -------------------------------------------------------------------------
    def prune(self, before: datetime) -> dict[str, int]:
        """Delete resolved incidents (cascading to their data) and sent digests older
        than `before`. Open incidents are never deleted."""
        cutoff = before.isoformat()
        with self._lock:
            out = {
                "incidents": self._db.execute(
                    "DELETE FROM incidents WHERE state = 'resolved' AND resolved_at < ?", (cutoff,)).rowcount,
                "digests": self._db.execute(
                    "DELETE FROM digests WHERE status IN ('provider_accepted', 'failed') AND created_at < ?",
                    (cutoff,)).rowcount,
                "digestItems": self._db.execute("DELETE FROM digest_items WHERE at < ?", (cutoff,)).rowcount,
            }
        return out

    # --- investigations --------------------------------------------------------------------
    def save_investigation(self, i: Investigation) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigations (id, incident_id, started_at, finished_at, status, model, think, steps,"
                " conclusion, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
                " finished_at = excluded.finished_at, status = excluded.status, steps = excluded.steps,"
                " conclusion = excluded.conclusion, error = excluded.error",
                (i.id, i.incident_id, i.started_at.isoformat(), _ts(i.finished_at), i.status, i.model, int(i.think),
                 json.dumps(i.steps), json.dumps(i.conclusion), i.error))

    def fail_interrupted_investigations(self, now: datetime) -> int:
        """A run that was in progress when the observer stopped will never finish."""
        with self._lock:
            return self._db.execute(
                "UPDATE investigations SET status = 'failed', finished_at = ?, error = 'interrupted by a restart'"
                " WHERE status = 'running'", (now.isoformat(),)).rowcount

    def investigations(self, incident_id: str) -> list[Investigation]:
        rows = self._query("SELECT * FROM investigations WHERE incident_id = ? ORDER BY started_at DESC",
                           (incident_id,))
        return [Investigation(r["id"], r["incident_id"], _dt(r["started_at"]), _dt(r["finished_at"]), r["status"],
                              r["model"], bool(r["think"]), json.loads(r["steps"]), json.loads(r["conclusion"]),
                              r["error"]) for r in rows]
