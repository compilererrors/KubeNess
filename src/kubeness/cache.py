"""Thread-safe cache of watched objects, with freshness per namespace and kind."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from .snapshot import Snapshot, meta, parse_time, utcnow

KINDS = ("pods", "replicasets", "deployments", "events")
EVENT_MAX_AGE = timedelta(hours=1)
EVENT_MAX_COUNT = 500


@dataclass
class SourceStatus:
    namespace: str
    kind: str
    last_success: datetime | None = None
    error: str | None = None


class ClusterCache:
    def __init__(self, cluster: str, namespaces: list[str], freshness_budget: timedelta,
                 started: datetime | None = None) -> None:
        self.cluster = cluster
        self.started = started or utcnow()
        self.namespaces = list(namespaces)
        self.freshness_budget = freshness_budget
        self._lock = threading.Lock()
        self._objects: dict[tuple[str, str], dict[str, dict]] = {(ns, k): {} for ns in namespaces for k in KINDS}
        self._status: dict[tuple[str, str], SourceStatus] = {
            (ns, k): SourceStatus(ns, k) for ns in namespaces for k in KINDS
        }

    # --- writers (watcher threads) ---------------------------------------------
    def replace(self, ns: str, kind: str, objs: list[dict], now: datetime) -> None:
        with self._lock:
            self._objects[(ns, kind)] = {meta(o).get("uid", ""): o for o in objs}
            self._mark_ok(ns, kind, now)

    def put(self, ns: str, kind: str, obj: dict, now: datetime) -> None:
        with self._lock:
            self._objects[(ns, kind)][meta(obj).get("uid", "")] = obj
            self._mark_ok(ns, kind, now)

    def delete(self, ns: str, kind: str, obj: dict, now: datetime) -> None:
        with self._lock:
            self._objects[(ns, kind)].pop(meta(obj).get("uid", ""), None)
            self._mark_ok(ns, kind, now)

    def mark_ok(self, ns: str, kind: str, now: datetime) -> None:
        with self._lock:
            self._mark_ok(ns, kind, now)

    def mark_error(self, ns: str, kind: str, error: str) -> None:
        with self._lock:
            self._status[(ns, kind)].error = error

    def _mark_ok(self, ns: str, kind: str, now: datetime) -> None:
        st = self._status[(ns, kind)]
        st.last_success = now
        st.error = None

    # --- readers -------------------------------------------------------------
    def is_fresh(self, st: SourceStatus, now: datetime) -> bool:
        # An error is recorded and shown, but the cached state stays usable until
        # the freshness budget runs out: a single failed watch is not an outage.
        return st.last_success is not None and now - st.last_success <= self.freshness_budget

    def status(self, now: datetime) -> list[dict]:
        with self._lock:
            return [
                {
                    "namespace": st.namespace,
                    "kind": st.kind,
                    "fresh": self.is_fresh(st, now),
                    "lastSuccess": st.last_success.isoformat() if st.last_success else None,
                    "error": st.error,
                }
                for st in self._status.values()
            ]

    def snapshot(self, now: datetime) -> Snapshot:
        snap = Snapshot(cluster=self.cluster, taken_at=now)
        with self._lock:
            for ns in self.namespaces:
                snap.pods[ns] = list(self._objects[(ns, "pods")].values())
                snap.replicasets[ns] = list(self._objects[(ns, "replicasets")].values())
                snap.deployments[ns] = list(self._objects[(ns, "deployments")].values())
                events = self._objects[(ns, "events")]
                self._prune_events(events, now)
                snap.events[ns] = list(events.values())
                # Events only enrich evidence; a stale event watch does not make
                # the namespace's state untrustworthy.
                if any(not self.is_fresh(self._status[(ns, k)], now) for k in ("pods", "replicasets", "deployments")):
                    snap.stale_namespaces.add(ns)
                # overdue: not fresh and past the budget even when counted from startup,
                # so a source that has simply not been listed yet is not an outage.
                snap.sources[ns] = [
                    {"kind": k, "fresh": self.is_fresh(st, now), "error": st.error,
                     "lastSuccess": st.last_success.isoformat() if st.last_success else None,
                     "overdue": not self.is_fresh(st, now) and now - self.started > self.freshness_budget}
                    for k in KINDS for st in [self._status[(ns, k)]]
                ]
        return snap

    @staticmethod
    def _prune_events(events: dict[str, dict], now: datetime) -> None:
        def t(e: dict) -> datetime:
            return (
                parse_time(e.get("lastTimestamp") or e.get("eventTime") or meta(e).get("creationTimestamp")) or now
            )

        for uid, e in list(events.items()):
            if now - t(e) > EVENT_MAX_AGE:
                del events[uid]
        if len(events) > EVENT_MAX_COUNT:
            for uid, _ in sorted(events.items(), key=lambda kv: t(kv[1]))[: len(events) - EVENT_MAX_COUNT]:
                del events[uid]
