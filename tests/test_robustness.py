"""Robustness: one bad incident never stops the tick, state stays bounded, old data is pruned."""

from __future__ import annotations

from datetime import timedelta

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.notify import NotificationPolicy
from kubeness.store import Store

from factories import T0, at, deployment, iso, pod, replicaset, running, snap, waiting
from kpi_report import kpi
from test_diagnose import FakeLogs
from test_engine import crashloop_status


def two_workloads(t):
    """A crash loop in web and an image pull failure in api, in the same namespace."""
    web = pod(statuses=[crashloop_status(t)])
    api = pod("api-rs-1", "pod-api", [waiting(reason="ImagePullBackOff", image_id="")],
              owner={"kind": "ReplicaSet", "name": "api-rs", "uid": "rs-api", "controller": True})
    return dict(pods=[web, api], deployments=[deployment(), deployment("api", "dep-api")],
                replicasets=[replicaset(), replicaset("api-rs", "rs-api", "api", "dep-api")])


class ExplodingCollector(LogCollector):
    def collect(self, ev):
        if ev.workload.name == "web":
            raise RuntimeError("collector bug")
        return super().collect(ev)


def test_a_failing_collector_does_not_stop_other_incidents():
    cfg = Config.model_validate({"notifications": {"enabled": True}})
    store = Store(":memory:")
    engine = Engine(cfg, store, ExplodingCollector(cfg, FakeLogs()), None, NotificationPolicy(cfg, store))
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), **two_workloads(t)), at(t))
    states = {i.workload.name: i.state for i in store.list_incidents()}
    assert states == {"web": State.FIRING, "api": State.FIRING}
    web = next(i for i in store.list_incidents() if i.workload.name == "web")
    assert any(a.kind == "error" and "collector bug" in a.message for a in store.activity(web.id))
    assert {n.incident_id for n in store.notifications()} == {i.id for i in store.list_incidents()}
    kpi("Q01", "incidents lost to one failing collector", 2 - len(states), "count", eq=0)


class ExplodingPolicy(NotificationPolicy):
    def _enqueue(self, inc, event, notification_id, now):
        if inc.workload.name == "web":
            raise ValueError("payload bug")
        return super()._enqueue(inc, event, notification_id, now)


def test_a_failing_notification_does_not_stop_the_tick():
    cfg = Config.model_validate({"notifications": {"enabled": True}})
    store = Store(":memory:")
    engine = Engine(cfg, store, None, None, ExplodingPolicy(cfg, store))
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), **two_workloads(t)), at(t))
    assert engine.last_tick == at(290)
    assert [n.event for n in store.notifications()] == ["firing"], "api is still notified"
    web = next(i for i in store.list_incidents() if i.workload.name == "web")
    assert any(a.kind == "error" and "payload bug" in a.message for a in store.activity(web.id))


def churn(t):
    """A new pod every evaluation, each OOM killed once: the worst case for per-pod state."""
    s = running(started=at(t - 5), restarts=1)
    s["lastState"] = {"terminated": {"reason": "OOMKilled", "exitCode": 137, "finishedAt": iso(at(t - 6))}}
    return [pod(f"web-abc-{t}", f"pod-{t}", [s])]


def test_q02_per_pod_state_is_bounded():
    cfg = Config.model_validate({"notifications": {"enabled": True, "digestInterval": "1h"}})
    store = Store(":memory:")
    engine = Engine(cfg, store, None, None, NotificationPolicy(cfg, store))
    for t in range(0, 6 * 3600, 10):
        deps = [deployment()]
        deps[0]["spec"]["template"] = {"spec": {"containers": [{"name": "app", "image": f"web:{t // 600}"}]}}
        engine.tick(snap(at(t), pods=churn(t), deployments=deps), at(t))
    oom = next(r for r in engine.rules if r.rule_id == "oom")
    digest = engine.notifications.digest
    sizes = {"oom.seen": len(oom.seen), "oom.kills": len(oom.kills), "digest.restarts": len(digest.restarts),
             "digest.images": len(digest.images)}
    kpi("Q02", "largest per-pod state after 2160 pods", max(sizes.values()), "entries", max=10)


def test_q03_retention_prunes_old_resolved_incidents_and_their_data():
    cfg = Config.model_validate({"observer": {"retention": "7d"}, "notifications": {"enabled": True}})
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), None, NotificationPolicy(cfg, store))
    for t in range(0, 600, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
    for t in range(600, 800, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[running(started=at(600), restarts=5)])]), at(t))
    (old,) = store.list_incidents()
    assert old.state is State.RESOLVED and store.evidence(old.id) and store.notifications(old.id)
    late = T0 + timedelta(days=8)
    # A new, open incident eight days later must survive the pruning.
    for t in range(0, 300, 10):
        now = late + timedelta(seconds=t)
        engine.tick(snap(now, pods=[pod("api-1", "pod-api", [crashloop_status(t)],
                                        owner={"kind": "ReplicaSet", "name": "api-rs", "uid": "rs-api",
                                               "controller": True})],
                         deployments=[deployment(), deployment("api", "dep-api")],
                         replicasets=[replicaset(), replicaset("api-rs", "rs-api", "api", "dep-api")]), now)
    remaining = store.list_incidents()
    assert [i.workload.name for i in remaining] == ["api"]
    assert store.evidence(old.id) == [] and store.notifications(old.id) == [] and store.activity(old.id) == []
    kpi("Q03", "resolved incidents older than retention left in the store",
        sum(1 for i in remaining if i.id == old.id), "count", eq=0)


def test_retention_never_prunes_open_incidents():
    cfg = Config.model_validate({"observer": {"retention": "1h"}})
    store = Store(":memory:")
    engine = Engine(cfg, store)
    for t in range(0, 4 * 3600, 60):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
    (inc,) = store.list_incidents()
    assert inc.state is State.FIRING and inc.first_seen <= at(120), "the same open incident survived 4 h"
