
import pytest

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.store import Store

from factories import (
    at, deployment, event, pod, running, snap, waiting,
)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def make_engine(store, **alarms):
    cfg = Config.model_validate({"alarms": alarms} if alarms else {})
    return Engine(cfg, store)


def crashloop_status(t: float, run_for: float = 5, start_offset: float = 0, base_restarts: int = 0) -> dict:
    """Container that crashes after `run_for` seconds, with kubelet's exponential back-off."""
    start, restarts, backoff, last_finish = start_offset, base_restarts, 10, None
    while True:
        if t < start + run_for:
            return running(started=at(start), ready=True, restarts=restarts,
                           last_finished=at(last_finish) if last_finish is not None else None)
        finish = start + run_for
        nxt = finish + backoff
        if t < nxt:
            return waiting(reason="CrashLoopBackOff", restarts=restarts, last_finished=at(finish))
        start, restarts, last_finish, backoff = nxt, restarts + 1, finish, min(backoff * 2, 300)


def states_over(engine, statuses_at, start, end, step=10):
    seen = []
    for t in range(start, end, step):
        engine.tick(snap(at(t), pods=[pod(statuses=[statuses_at(t)])]), at(t))
        incs = list(engine.open.values()) + list(engine.recent_resolved.values())
        seen.append((t, incs[0].state if incs else None))
    return seen


def test_crash_loop_stays_firing_while_backoff_grows(store):
    engine = make_engine(store)
    seen = states_over(engine, crashloop_status, 0, 30 * 60)

    first_firing = next(t for t, s in seen if s is State.FIRING)
    assert first_firing <= 120, "three restarts within five minutes should fire early"
    after = [s for t, s in seen if t >= first_firing]
    assert State.RESOLVED not in after
    assert State.RECOVERING not in after, "a 5s run is shorter than the settle period"

    # The restart rate is now one per five minutes, far below the burst threshold,
    # but the incident is still firing because of the persistent crash loop.
    (inc,) = engine.open.values()
    assert inc.rule_id == "restarts"
    assert inc.details["restartsInWindow"] < 3


def test_long_runs_between_crashes_relapse_but_never_resolve(store):
    engine = make_engine(store)
    seen = states_over(engine, lambda t: crashloop_status(t, run_for=40), 0, 30 * 60)
    assert State.RESOLVED not in [s for _, s in seen]
    (inc,) = engine.open.values()
    assert inc.flap_count >= 1


def test_recovery_requires_whole_window(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 10 * 60)
    fix = 10 * 60
    # Same container count as the crash loop reached, so several restarts are
    # still inside the five-minute window: they must not reopen the incident.
    seen = states_over(engine, lambda t: running(started=at(fix), restarts=5), fix, fix + 150)
    states = dict(seen)
    assert states[fix + 20] is State.FIRING          # healthy, but not yet for the settle period
    assert states[fix + 30] is State.RECOVERING
    assert states[fix + 50] is State.RECOVERING
    assert states[fix + 60] is State.RESOLVED
    inc = engine.recent_resolved[next(iter(engine.recent_resolved))]
    kinds = [a.kind for a in store.activity(inc.id)]
    assert kinds == ["pending", "fired", "recovering", "resolved"]


def test_image_pull_pending_then_firing_with_evidence(store):
    engine = make_engine(store)
    reasons = ["ErrImagePull", "ImagePullBackOff"]
    events = [event("Failed", "manifest unknown", "web-abc-1", at(1), "ev1")]

    def tick(t):
        st = waiting(reason=reasons[(t // 10) % 2], message="manifest unknown", image_id="")
        engine.tick(snap(at(t), pods=[pod(statuses=[st], image="ghcr.io/example/web:2.0")], events=events), at(t))

    tick(0)
    (inc,) = engine.open.values()
    assert (inc.rule_id, inc.state) == ("imagePull", State.PENDING)
    for t in range(10, 70, 10):
        tick(t)
    (inc,) = engine.open.values()
    assert inc.state is State.FIRING
    assert "ghcr.io/example/web:2.0" in inc.reason

    ev = store.evidence(inc.id)
    assert [e.kind for e in ev] == ["rule", "event"]
    assert ev[0].payload["containers"][0]["specImage"] == "ghcr.io/example/web:2.0"
    assert ev[1].payload["message"] == "manifest unknown"


def test_short_blip_is_cancelled_without_incident(store):
    engine = make_engine(store)
    engine.tick(snap(at(0), pods=[pod(statuses=[waiting(reason="ErrImagePull", image_id="")])]), at(0))
    assert len(engine.open) == 1
    for t in (10, 20, 30, 40, 50):
        engine.tick(snap(at(t), pods=[pod(statuses=[running(started=at(5))])]), at(t))
    assert engine.open == {}
    assert store.list_incidents() == []


def test_readiness_ignores_progressing_rollout_then_fires(store):
    engine = make_engine(store)
    rolling = deployment(replicas=2, ready=1, progressing=("True", "ReplicaSetUpdated"))
    stuck = deployment(replicas=2, ready=1)
    pods = [pod(statuses=[running(started=at(-600))]), pod("web-abc-2", "pod-uid-2", [running(ready=False)])]

    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=pods, deployments=[rolling]), at(t))
    assert engine.open == {}

    for t in range(300, 430, 10):
        engine.tick(snap(at(t), pods=pods, deployments=[stuck]), at(t))
    (inc,) = engine.open.values()
    assert inc.rule_id == "readiness"
    assert inc.state is State.FIRING
    assert inc.firing_since == at(420)


def test_progress_deadline_fires_immediately(store):
    engine = make_engine(store)
    dep = deployment(replicas=1, ready=0, progressing=("False", "ProgressDeadlineExceeded"))
    engine.tick(snap(at(0), pods=[pod(statuses=[running(ready=False)])], deployments=[dep]), at(0))
    (inc,) = engine.open.values()
    assert inc.state is State.FIRING
    assert "ProgressDeadlineExceeded" in inc.reason


def test_readiness_is_inhibited_by_firing_restart_incident(store):
    engine = make_engine(store)
    for t in range(0, 600, 10):
        dep = deployment(replicas=1, ready=0)
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])], deployments=[dep]), at(t))
    rules = sorted(i.rule_id for i in engine.open.values())
    assert rules == ["restarts"]


def test_reopen_within_window_reuses_incident(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    states_over(engine, lambda t: running(started=at(300), restarts=4), 300, 400)
    (resolved,) = engine.recent_resolved.values()
    assert resolved.state is State.RESOLVED

    states_over(engine, lambda t: crashloop_status(t, start_offset=400, base_restarts=4), 400, 700)
    (inc,) = engine.open.values()
    assert inc.id == resolved.id
    assert inc.recurrence_count == 1
    assert "reopened" in [a.kind for a in store.activity(inc.id)]


def test_stale_namespace_freezes_incident(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    (inc,) = engine.open.values()
    # The API is unreachable: the cache is stale and the pod list looks empty.
    engine.tick(snap(at(400), pods=[], stale=True), at(400))
    still = engine.open[inc.fingerprint]
    assert still.id == inc.id and still.state is State.FIRING and still.stale
    # The stale namespace itself is reported by the observerDegraded rule.
    assert sorted(i.rule_id for i in engine.open.values()) == ["observerDegraded", "restarts"]
    assert store.get_incident(inc.id).stale


def test_workload_removed_resolves(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    engine.tick(snap(at(400), pods=[], deployments=[]), at(400))
    assert engine.open == {}
    (inc,) = store.list_incidents()
    assert inc.state is State.RESOLVED


def test_open_incidents_survive_engine_restart(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    (inc,) = engine.open.values()
    restarted = make_engine(store)
    assert list(restarted.open) == [inc.fingerprint]
    restarted.tick(snap(at(310), pods=[pod(statuses=[crashloop_status(310)])]), at(310))
    assert [i.id for i in store.list_incidents()] == [inc.id]


def test_critical_workload_severity(store):
    engine = make_engine(store, criticalWorkloads=["lab/web"])
    states_over(engine, crashloop_status, 0, 3 * 60)
    (inc,) = engine.open.values()
    assert inc.severity == "critical"


def test_rule_selection_from_config(store):
    engine = make_engine(store, rules=["readiness"])
    states_over(engine, crashloop_status, 0, 3 * 60)
    assert engine.open == {}


def test_reopened_incident_is_analysed_from_its_latest_evidence(store):
    from kubeness.analysis import template_analysis
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    states_over(engine, lambda t: running(started=at(300), restarts=4), 300, 400)
    states_over(engine, lambda t: crashloop_status(t, start_offset=400, base_restarts=4), 400, 700)
    (inc,) = engine.open.values()
    assert inc.recurrence_count == 1
    evidence = store.evidence(inc.id)
    latest_rule = [e for e in evidence if e.kind == "rule"][-1]
    a = template_analysis(inc, evidence, True)
    assert a.observed_facts[0].evidence_refs == [latest_rule.ref]
