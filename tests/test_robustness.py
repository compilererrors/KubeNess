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


def test_evidence_refs_are_unique_when_two_threads_add_to_one_incident():
    """The rule loop and a troubleshooting run number evidence for the same incident;
    the store hands out the refs, so neither can overwrite the other."""
    import threading

    from kubeness.lifecycle import Incident
    from kubeness.snapshot import WorkloadRef
    from kubeness.store import EvidenceItem

    store = Store(":memory:")
    store.save_incident(Incident("inc-1", "fp", "restarts", "lab", WorkloadRef("Deployment", "lab", "web", "u1"),
                                 "warning", State.FIRING, "r", at(0), at(0)))
    refs: dict[str, list[str]] = {"log": [], "describe": []}

    def writer(kind: str) -> None:
        for i in range(200):
            refs[kind] += store.add_evidence("inc-1", [EvidenceItem("", at(i), kind, f"{kind} {i}", {})])

    threads = [threading.Thread(target=writer, args=(k,)) for k in refs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stored = store.evidence("inc-1")
    assert len(stored) == 400 and len({e.ref for e in stored}) == 400
    assert {e.ref for e in stored if e.kind == "log"} == set(refs["log"])
    assert sorted(int(e.ref[1:]) for e in stored) == list(range(1, 401))


def test_an_existing_evidence_ref_is_never_overwritten():
    import sqlite3

    import pytest

    from kubeness.lifecycle import Incident
    from kubeness.snapshot import WorkloadRef
    from kubeness.store import EvidenceItem

    store = Store(":memory:")
    store.save_incident(Incident("inc-1", "fp", "restarts", "lab", WorkloadRef("Deployment", "lab", "web", "u1"),
                                 "warning", State.FIRING, "r", at(0), at(0)))
    assert store.add_evidence("inc-1", [EvidenceItem("", at(0), "rule", "first", {})]) == ["e1"]
    second = EvidenceItem("", at(1), "log", "second", {})
    with pytest.raises(sqlite3.IntegrityError):
        store.add_evidence("inc-1", [second, EvidenceItem("e1", at(1), "log", "collides", {})])
    assert [(e.ref, e.summary) for e in store.evidence("inc-1")] == [("e1", "first")], "the batch is rolled back"
    assert second.ref == "", "a rolled-back item keeps no ref"
    store.add_evidence("inc-1", [EvidenceItem("", at(2), "log", "between", {})])
    assert store.add_evidence("inc-1", [second]) == ["e3"], "added again, it is numbered afresh"


def test_a_failing_rule_does_not_stop_the_others_or_close_its_own_incidents(caplog):
    cfg = Config()
    store = Store(":memory:")
    engine = Engine(cfg, store)
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), **two_workloads(t)), at(t))
    assert {i.rule_id: i.state for i in store.list_incidents()} == {"restarts": State.FIRING, "imagePull": State.FIRING}

    def boom(snapshot, now):
        raise RuntimeError("rule bug")

    restarts = next(r for r in engine.rules if r.rule_id == "restarts")
    restarts.evaluate = boom
    # The image is fixed while the restart rule is broken: the other rule still sees it.
    fixed = two_workloads(300)
    fixed["pods"][1] = pod("api-rs-1", "pod-api", [running(started=at(300))],
                           owner={"kind": "ReplicaSet", "name": "api-rs", "uid": "rs-api", "controller": True})
    for t in range(300, 420, 10):
        engine.tick(snap(at(t), **fixed), at(t))
    states = {i.rule_id: i.state for i in store.list_incidents()}
    assert states["imagePull"] is State.RESOLVED, "the other rules keep evaluating"
    assert states["restarts"] is State.FIRING, "no evaluation is not the same as a removed workload"
    assert engine.last_tick == at(410) and "rule bug" in engine.rule_errors["restarts"]
    tracebacks = [r for r in caplog.records if r.levelname == "ERROR" and r.exc_info]
    assert len(tracebacks) == 1, "the traceback is logged once, not on every tick"

    del restarts.evaluate
    engine.tick(snap(at(420), **two_workloads(420)), at(420))
    assert engine.rule_errors == {}


def test_a_failing_rule_marks_the_observer_degraded(tmp_path):
    from kubeness.__main__ import Observer
    from kubeness.snapshot import utcnow

    obs = Observer(Config.model_validate({"observer": {"dataDir": str(tmp_path)}}))
    try:
        now = utcnow()
        for kind in ("pods", "replicasets", "deployments", "events"):
            obs.cache.replace("lab", kind, [], now)
        obs.engine_running = True
        obs.engine.tick(obs.cache.snapshot(now), now)
        assert obs.status()["observer"] == "ok" and obs.healthy()

        def boom(snapshot, now):
            raise RuntimeError("rule bug")

        obs.engine.rules[0].evaluate = boom
        obs.engine.tick(obs.cache.snapshot(now), now)
        st = obs.status()
        assert (st["observer"], st["observerDetail"]) == ("degraded", "failing rule: restarts")
        assert st["lastError"] == "restarts: RuntimeError: rule bug"
        assert not obs.healthy(), "the heartbeat stops, so the dead man's switch notices"
    finally:
        obs.store.close()


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
