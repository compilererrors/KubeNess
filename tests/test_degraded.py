"""B14: the observer reports its own degraded collection as an incident."""

from __future__ import annotations

from datetime import timedelta

from kubeness.cache import ClusterCache
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.notify import NotificationPolicy
from kubeness.store import Store

from factories import at, deployment, pod, replicaset
from test_engine import crashloop_status

KINDS = ("pods", "replicasets", "deployments", "events")
BUDGET = timedelta(minutes=3)


class Lab:
    """A cache fed like the watchers would, plus an engine reading snapshots from it."""

    def __init__(self, notifications: bool = False):
        self.cfg = Config.model_validate({"notifications": {"enabled": notifications}})
        self.store = Store(":memory:")
        self.cache = ClusterCache("lab", ["lab"], BUDGET, started=at(0))
        self.engine = Engine(self.cfg, self.store, None, None, NotificationPolicy(self.cfg, self.store))
        self.transitions = []

    def tick(self, t: int, ok: bool, pods=None, error="API error 403: Forbidden"):
        now = at(t)
        if ok:
            self.cache.replace("lab", "pods", pods if pods is not None else [], now)
            self.cache.replace("lab", "replicasets", [replicaset()], now)
            self.cache.replace("lab", "deployments", [deployment()], now)
            self.cache.replace("lab", "events", [], now)
        else:
            for k in KINDS:
                self.cache.mark_error("lab", k, error)
        for tr in self.engine.tick(self.cache.snapshot(now), now):
            self.transitions.append((t, tr.incident.rule_id, tr.kind))

    def first(self, rule, kind):
        return next((t for t, r, k in self.transitions if r == rule and k == kind), None)

    def incidents(self, rule):
        return [i for i in self.store.list_incidents() if i.rule_id == rule]


def test_short_error_within_budget_is_not_stale():
    cache = ClusterCache("lab", ["lab"], BUDGET)
    for k in ("pods", "replicasets", "deployments"):
        cache.replace("lab", k, [], at(0))
    cache.mark_error("lab", "pods", "connection refused")
    snap = cache.snapshot(at(60))
    assert snap.stale_namespaces == set()
    status = {s["kind"]: s for s in cache.status(at(60))}
    assert status["pods"]["error"] == "connection refused" and status["pods"]["fresh"]
    assert cache.snapshot(at(181)).stale_namespaces == {"lab"}


def test_snapshot_carries_source_status():
    cache = ClusterCache("lab", ["lab"], BUDGET)
    cache.replace("lab", "pods", [], at(0))
    cache.mark_error("lab", "pods", "API error 403: Forbidden")
    snap = cache.snapshot(at(10))
    pods = next(s for s in snap.sources["lab"] if s["kind"] == "pods")
    assert pods["error"] == "API error 403: Forbidden" and pods["lastSuccess"] == at(0).isoformat()


def test_degraded_fires_after_budget_and_resolves_once():
    lab = Lab()
    for t in range(0, 100, 10):
        lab.tick(t, ok=True)
    for t in range(100, 600, 10):
        lab.tick(t, ok=False)
    (inc,) = lab.incidents("observerDegraded")
    assert inc.state is State.FIRING
    assert inc.workload.kind == "Observer" and inc.workload.namespace == "lab"
    assert "403" in inc.reason and "lab" in inc.reason
    for t in range(600, 900, 10):
        lab.tick(t, ok=True)
    (inc,) = lab.incidents("observerDegraded")
    assert inc.state is State.RESOLVED
    assert [k for _, r, k in lab.transitions if r == "observerDegraded"] == ["fired", "recovering", "resolved"]


def test_workload_incidents_freeze_while_degraded_fires():
    lab = Lab()
    for t in range(0, 300, 10):
        lab.tick(t, ok=True, pods=[pod(statuses=[crashloop_status(t)])])
    (restarts,) = lab.incidents("restarts")
    for t in range(300, 600, 10):
        lab.tick(t, ok=False)
    restarts = lab.store.get_incident(restarts.id)
    assert restarts.state is State.FIRING and restarts.stale
    assert lab.incidents("observerDegraded")[0].state is State.FIRING


def test_degraded_runbook_and_notification():
    lab = Lab(notifications=True)
    lab.tick(0, ok=True)
    for t in range(10, 400, 10):
        lab.tick(t, ok=False)
    (inc,) = lab.incidents("observerDegraded")
    (n,) = lab.store.notifications(inc.id)
    p = n.payload
    assert p["rule"] == "observerDegraded" and p["workload"] == "Observer/observations"
    assert "permission" in p["possibleCause"].lower()
    assert "auth can-i" in p["nextCheck"]
    assert any("unknown" in m for m in p["missing"])


def test_degraded_cause_for_unreachable_api():
    lab = Lab(notifications=True)
    lab.tick(0, ok=True)
    for t in range(10, 400, 10):
        lab.tick(t, ok=False, error="MaxRetryError: connection refused")
    (inc,) = lab.incidents("observerDegraded")
    (n,) = lab.store.notifications(inc.id)
    assert "cannot reach the Kubernetes API" in n.payload["possibleCause"]


def test_degraded_rule_can_be_turned_off():
    cfg = Config.model_validate({"alarms": {"rules": ["restarts"]}})
    assert "observerDegraded" not in cfg.alarms.rules
    assert "observerDegraded" in Config().alarms.rules


def test_startup_is_not_degraded_until_the_budget_runs_out():
    cfg = Config()
    store = Store(":memory:")
    cache = ClusterCache("lab", ["lab"], BUDGET, started=at(0))
    engine = Engine(cfg, store)
    for t in range(0, 180, 10):          # watchers have not listed yet
        snap = cache.snapshot(at(t))
        assert snap.stale_namespaces == {"lab"}, "unobserved state must stay frozen"
        engine.tick(snap, at(t))
    assert store.list_incidents() == []
    for t in range(180, 260, 10):        # still nothing after the budget: a real problem
        engine.tick(cache.snapshot(at(t)), at(t))
    (inc,) = store.list_incidents()
    assert inc.rule_id == "observerDegraded" and "never observed" in inc.reason
