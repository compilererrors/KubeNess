"""KPI benchmarks for stage 1 (Observe), simulated with the default lab settings."""

from __future__ import annotations

from datetime import timedelta

import pytest

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.store import Store

from factories import T0, at, deployment, pod, replicaset, running, snap, waiting
from kpi_report import kpi, timed_kpi
from test_engine import crashloop_status

INTERVAL = 10


@pytest.fixture
def engine():
    store = Store(":memory:")
    yield Engine(Config(), store)
    store.close()


def run(engine, pods_at, start, end, deployments_at=None):
    """Tick every interval; return the time each transition kind first happened."""
    first: dict[str, float] = {}
    for t in range(start, end, INTERVAL):
        deps = deployments_at(t) if deployments_at else None
        for tr in engine.tick(snap(at(t), pods=pods_at(t), deployments=deps), at(t)):
            first.setdefault(f"{tr.incident.rule_id}:{tr.kind}", t)
    return first


def test_k01_restart_detection(engine):
    first = run(engine, lambda t: [pod(statuses=[crashloop_status(t)])], 0, 600)
    kpi("K01", "detection time, repeated restarts", first["restarts:fired"] - 5, "s", max=120)


def test_k02_image_pull_detection(engine):
    bad = [pod(statuses=[waiting(reason="ImagePullBackOff", image_id="")])]
    first = run(engine, lambda t: bad, 0, 300)
    kpi("K02", "detection time, image pull failure", first["imagePull:fired"], "s", max=60 + INTERVAL)


def test_k03_readiness_detection(engine):
    pods = [pod(statuses=[running(started=at(-600))]), pod("web-abc-2", "pod-uid-2", [running(ready=False)])]
    first = run(engine, lambda t: pods, 0, 400, lambda t: [deployment(replicas=2, ready=1)])
    kpi("K03", "detection time, too few ready replicas", first["readiness:fired"], "s", max=120 + INTERVAL)


def test_k04_progress_deadline_detection(engine):
    dep = deployment(replicas=1, ready=0, progressing=("False", "ProgressDeadlineExceeded"))
    first = run(engine, lambda t: [pod(statuses=[running(ready=False)])], 0, 60, lambda t: [dep])
    kpi("K04", "detection time, ProgressDeadlineExceeded", first["readiness:fired"], "s", max=INTERVAL)


def test_k05_no_false_alarms_for_healthy_workload_and_rollout(engine):
    run(engine, lambda t: [pod(statuses=[running(started=at(-60))])], 0, 3600)
    healthy = len(engine.store.list_incidents())

    # Rollout: a new ReplicaSet scales up while the old one keeps serving. The new
    # pod is not ready for four minutes (slow startup) while the rollout progresses.
    old = pod(statuses=[running(started=at(-600))])
    new = pod("web-new-1", "pod-uid-9", [running(started=at(3600), ready=False)],
              owner={"kind": "ReplicaSet", "name": "web-new", "uid": "rs-uid-2", "controller": True})

    def deps(t):
        if t < 3600 + 240:
            return [deployment(replicas=2, ready=1, progressing=("True", "ReplicaSetUpdated"))]
        return [deployment(replicas=2, ready=2)]

    def pods(t):
        ready_new = pod("web-new-1", "pod-uid-9", [running(started=at(3600))],
                        owner={"kind": "ReplicaSet", "name": "web-new", "uid": "rs-uid-2", "controller": True})
        return [old, new if t < 3600 + 240 else ready_new]

    for t in range(3600, 3600 + 900, INTERVAL):
        s = snap(at(t), pods=pods(t), deployments=deps(t),
                 replicasets=[replicaset(), replicaset("web-new", "rs-uid-2")])
        engine.tick(s, at(t))
    kpi("K05", "false alarms, 1 h healthy plus a slow rollout", healthy + len(engine.store.list_incidents()),
        "count", eq=0)


def test_k06_one_incident_per_fault(engine):
    run(engine, lambda t: [pod(statuses=[crashloop_status(t)])], 0, 30 * 60)
    kpi("K06", "incidents for one 30 min crash loop", len(engine.store.list_incidents()), "count", eq=1)


def test_k07_inhibition(engine):
    run(engine, lambda t: [pod(statuses=[crashloop_status(t)])], 0, 600,
        lambda t: [deployment(replicas=1, ready=0)])
    readiness = [i for i in engine.store.list_incidents() if i.rule_id == "readiness"]
    kpi("K07", "readiness incidents while restarts fires", len(readiness), "count", eq=0)


def test_k08_recovery_time(engine):
    run(engine, lambda t: [pod(statuses=[crashloop_status(t)])], 0, 600)
    fix = 600
    first = run(engine, lambda t: [pod(statuses=[running(started=at(fix), restarts=5)])], fix, fix + 300)
    kpi("K08", "recovery time after fix", first["restarts:resolved"] - fix, "s", max=60 + 2 * INTERVAL)


def test_k09_tick_time_at_scale():
    store = Store(":memory:")
    engine = Engine(Config(), store)
    deps, rss, pods = [], [], []
    for d in range(100):
        deps.append(deployment(f"app{d}", f"dep-{d}", replicas=5, ready=5))
        rss.append(replicaset(f"app{d}-rs", f"rs-{d}", f"app{d}", f"dep-{d}"))
        for p in range(5):
            st = crashloop_status(0) if d < 5 else running(started=T0 - timedelta(hours=1))
            pods.append(pod(f"app{d}-rs-{p}", f"pod-{d}-{p}", [st],
                            owner={"kind": "ReplicaSet", "name": f"app{d}-rs", "uid": f"rs-{d}", "controller": True}))
    clock = iter(range(0, 10**6, INTERVAL))

    def tick():
        t = next(clock)
        engine.tick(snap(at(t), pods=pods, deployments=deps, replicasets=rss), at(t))

    timed_kpi("K09", "tick time p95, 500 pods / 100 deployments", tick, 40, warmup=5, max=50)
    store.close()


def test_states_are_sane_after_benchmarks(engine):
    """Guard: the benchmarks above exercise real transitions, not an idle engine."""
    first = run(engine, lambda t: [pod(statuses=[crashloop_status(t)])], 0, 300)
    assert "restarts:fired" in first
    (inc,) = engine.open.values()
    assert inc.state is State.FIRING
