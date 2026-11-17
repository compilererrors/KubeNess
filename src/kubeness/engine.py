"""Rule evaluation loop: snapshot -> rules -> lifecycle -> store."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from typing import TYPE_CHECKING

from .collector import LogCollector, as_evidence
from .config import Config
from .lifecycle import Incident, State, Transition, fingerprint, step
from .rules import INHIBITED_BY, SEVERITY_RANK, Evaluation, build_rules
from .snapshot import Snapshot, WorkloadRef, controller_owner, meta, parse_time
from .redact import redact
from .store import EvidenceItem, Store

if TYPE_CHECKING:
    from .model import Analyzer
    from .notify import NotificationPolicy

log = logging.getLogger(__name__)
LOG_RETRIES = 6  # evaluations, about a minute at the default interval


def _event_time(ev: dict) -> datetime | None:
    return parse_time(ev.get("lastTimestamp") or ev.get("eventTime") or meta(ev).get("creationTimestamp"))


def related_events(snapshot: Snapshot, wl: WorkloadRef, pods: list[str], limit: int) -> list[dict]:
    """Events for the workload, its ReplicaSets and its pods, newest last."""
    names = {wl.name, *pods}
    if wl.kind == "Deployment":
        for rs in snapshot.replicasets.get(wl.namespace, []):
            owner = controller_owner(rs)
            if owner and owner.get("uid") == wl.uid:
                names.add(meta(rs).get("name", ""))
    out = [e for e in snapshot.events.get(wl.namespace, []) if (e.get("involvedObject") or {}).get("name") in names]
    out.sort(key=lambda e: _event_time(e) or snapshot.taken_at)
    return out[-limit:]


class Engine:
    def __init__(self, cfg: Config, store: Store, collector: LogCollector | None = None,
                 analyzer: "Analyzer | None" = None, notifications: "NotificationPolicy | None" = None) -> None:
        self.cfg = cfg
        self.store = store
        self.collector = collector
        self.analyzer = analyzer
        self.notifications = notifications
        self.rules = build_rules(cfg.alarms)
        self.open: dict[str, Incident] = {i.fingerprint: i for i in store.open_incidents()}
        self.recent_resolved: dict[str, Incident] = {}
        self.last_tick: datetime | None = None
        # incident id -> remaining attempts to collect logs that were missing at firing
        self.log_retries: dict[str, int] = {}
        self.last_prune: datetime | None = None

    def _load_recent_resolved(self, now: datetime) -> None:
        cutoff = now - self.cfg.alarms.reopen_window
        if self.last_tick is None:
            self.recent_resolved = {i.fingerprint: i for i in self.store.resolved_since(cutoff)}
        self.recent_resolved = {
            fp: i for fp, i in self.recent_resolved.items() if i.resolved_at and i.resolved_at >= cutoff
        }

    def tick(self, snapshot: Snapshot, now: datetime) -> list[Transition]:
        self._load_recent_resolved(now)
        evals: dict[str, Evaluation] = {}
        for rule in self.rules:
            for ev in rule.evaluate(snapshot, now):
                evals[fingerprint(snapshot.cluster, ev.workload, ev.rule_id)] = ev
        self._inhibit(evals)

        transitions: list[Transition] = []
        for fp in sorted(set(evals) | set(self.open)):
            ev = evals.get(fp)
            inc = self.open.get(fp)
            ns = ev.workload.namespace if ev else inc.workload.namespace
            rule_id = ev.rule_id if ev else inc.rule_id
            if ns in snapshot.stale_namespaces and rule_id != "observerDegraded":
                # No trustworthy observation: freeze the incident instead of
                # resolving it because the workload seems to have disappeared.
                if inc is not None and not inc.stale:
                    inc.stale = True
                    self.store.save_incident(inc)
                continue
            current = inc or self.recent_resolved.get(fp)
            updated, ts = step(snapshot.cluster, current, ev, now, self.cfg.alarms)
            if updated is not None and ev is not None and ev.severity and updated.is_open and \
                    SEVERITY_RANK.get(ev.severity, 0) > SEVERITY_RANK.get(updated.severity, 0):
                msg = f"Raised from {updated.severity} to {ev.severity}: {ev.reason}"
                updated.severity = ev.severity
                ts = ts + [Transition(updated, updated.state, updated.state, "escalated", msg)]
            self._persist(current, updated, ts, ev, snapshot, now)
            transitions.extend(ts)
            if updated is not None and ev is not None and not ts and updated.id in self.log_retries:
                self._isolated(updated, now, "Log retry", self._retry_logs, updated, ev, now)
        transitions += self._escalate(now)
        if self.cfg.actions.enabled:
            self._verify_actions(snapshot, now)
        if self.notifications is not None:
            # Only writes to the outbox; delivery happens in the sender thread.
            try:
                self.notifications.handle(transitions, list(self.open.values()), now, snapshot)
            except Exception:
                log.exception("notification policy failed")
        self._prune(now)
        self.last_tick = now
        return transitions

    def _isolated(self, inc: Incident, now: datetime, what: str, fn, *args) -> None:
        """Evidence, analysis and notification failures are recorded on the incident
        and never stop the evaluation of the other incidents."""
        try:
            fn(*args)
        except Exception as e:
            log.exception("%s failed for %s", what, inc.id)
            self.store.add_activity(inc.id, now, "error", f"{what} failed: {type(e).__name__}: {str(e)[:200]}")

    def _prune(self, now: datetime) -> None:
        if self.last_prune is not None and now - self.last_prune < timedelta(hours=1):
            return
        self.last_prune = now
        removed = self.store.prune(now - self.cfg.observer.retention)
        if any(removed.values()):
            log.info("retention removed %s", removed)

    def _verify_actions(self, snapshot: Snapshot, now: datetime) -> None:
        """An executed restart is verified when the Deployment controller has
        observed the patched generation, i.e. the new rollout has started."""
        for a in self.store.actions(status="executed"):
            ns, name = a.params.get("namespace"), a.params.get("name")
            if ns in snapshot.stale_namespaces:
                continue
            dep = next((d for d in snapshot.deployments.get(ns, []) if meta(d).get("name") == name), None)
            observed = ((dep or {}).get("status") or {}).get("observedGeneration") or 0
            if dep is not None and a.generation is not None and observed >= a.generation:
                self.store.update_action(a.id, status="verified", verified_at=now,
                                         result=f"rollout observed at generation {observed}")
                self.store.add_activity(a.incident_id, now, "action",
                                        f"{a.action} verified: Deployment {ns}/{name} observed generation {observed}")

    def _escalate(self, now: datetime) -> list[Transition]:
        after = self.cfg.alarms.escalate_after
        if not after:
            return []
        out = []
        for inc in self.open.values():
            if (inc.state is State.FIRING and inc.severity != "critical" and inc.firing_since
                    and now - inc.firing_since >= after and not inc.stale):
                old = inc.severity
                inc.severity = "critical"
                self.store.save_incident(inc)
                msg = f"Escalated from {old} to critical: firing for more than {after}"
                self.store.add_activity(inc.id, now, "escalated", msg)
                out.append(Transition(inc, State.FIRING, State.FIRING, "escalated", msg))
        return out

    def _inhibit(self, evals: dict[str, Evaluation]) -> None:
        firing_rules: dict[str, set[str]] = {}
        for inc in self.open.values():
            if inc.state in (State.FIRING, State.RECOVERING):
                firing_rules.setdefault(inc.workload.uid, set()).add(inc.rule_id)
        for ev in evals.values():
            if ev.firing:
                firing_rules.setdefault(ev.workload.uid, set()).add(ev.rule_id)
        for fp, ev in evals.items():
            inhibitors = INHIBITED_BY.get(ev.rule_id, set())
            existing = self.open.get(fp)
            not_yet_firing = existing is None or existing.state in (State.PENDING, State.RESOLVED)
            if not_yet_firing and inhibitors & firing_rules.get(ev.workload.uid, set()):
                ev.matching = False
                ev.firing = False

    def _persist(
        self,
        before: Incident | None,
        after: Incident | None,
        transitions: list[Transition],
        ev: Evaluation | None,
        snapshot: Snapshot,
        now: datetime,
    ) -> None:
        if after is None:
            if before is not None:
                self.open.pop(before.fingerprint, None)
                self.store.delete_incident(before.id)
            return
        if after is before and not transitions and after.state is State.RESOLVED:
            return  # untouched resolved incident
        self.store.save_incident(after)
        for t in transitions:
            self.store.add_activity(after.id, now, t.kind, t.message)
            log.info("incident %s %s: %s", after.id, t.kind, t.message)
            if t.kind in ("fired", "reopened") and ev is not None:
                self._isolated(after, now, "Evidence collection", self._collect_evidence, after, ev, snapshot, now)
        if after.is_open:
            self.open[after.fingerprint] = after
            self.recent_resolved.pop(after.fingerprint, None)
        else:
            self.open.pop(after.fingerprint, None)
            self.recent_resolved[after.fingerprint] = after

    def _collect_evidence(self, inc: Incident, ev: Evaluation, snapshot: Snapshot, now: datetime) -> None:
        """Store evidence when it is collected; events expire from the API after about an hour."""
        n = self.store.next_evidence_index(inc.id)
        items = [EvidenceItem(f"e{n}", now, "rule", ev.reason or inc.reason, {"rule": ev.rule_id, **ev.details})]
        for e in related_events(snapshot, ev.workload, ev.pods, self.cfg.collection.max_events):
            n += 1
            obj = e.get("involvedObject") or {}
            t = _event_time(e)
            items.append(
                EvidenceItem(
                    f"e{n}",
                    now,
                    "event",
                    f"{e.get('type', '')} {e.get('reason', '')}: {obj.get('kind', '')}/{obj.get('name', '')}",
                    {
                        "time": t.isoformat() if t else None,
                        "type": e.get("type"),
                        "reason": e.get("reason"),
                        "message": redact(e.get("message") or "")[0],
                        "count": e.get("count"),
                        "object": {"kind": obj.get("kind"), "name": obj.get("name")},
                    },
                )
            )
        if self.collector is not None:
            collected = self.collector.collect(ev)
            items += as_evidence(collected, n + 1, now)
            if collected.gaps and not collected.items and self.cfg.access.logs_allowed(ev.workload.namespace) and \
                    ev.rule_id in ("restarts", "readiness"):
                self.log_retries[inc.id] = LOG_RETRIES
        self.store.add_evidence(inc.id, items)
        if self.analyzer is not None:
            self.analyzer.submit(inc, now)

    def _retry_logs(self, inc: Incident, ev: Evaluation, now: datetime) -> None:
        """Logs can be missing at the moment of firing (the container is between
        restarts). Try again on the next evaluations and add a new analysis."""
        collected = self.collector.collect(ev) if self.collector else None
        if collected is not None:
            collected.items = [i for i in collected.items if i[0] == "log"]  # only logs were missing
        if collected is not None and collected.items:
            collected.gaps = []
            self.store.add_evidence(inc.id, as_evidence(collected, self.store.next_evidence_index(inc.id), now))
            self.store.add_activity(inc.id, now, "evidence", "Logs collected after firing")
            self.log_retries.pop(inc.id, None)
            if self.analyzer is not None:
                self.analyzer.submit(inc, now)
            return
        self.log_retries[inc.id] -= 1
        if self.log_retries[inc.id] <= 0:
            self.log_retries.pop(inc.id, None)
