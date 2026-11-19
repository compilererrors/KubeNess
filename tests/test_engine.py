
import pytest

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.store import Store

from factories import (
    at, deployment, event, iso, pod, running, snap, waiting,
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


def test_a_single_restart_is_pending_with_a_reason(store):
    engine = make_engine(store)
    engine.tick(snap(at(0), pods=[pod(statuses=[running()])]), at(0))
    engine.tick(snap(at(10), pods=[pod(statuses=[running(started=at(6), restarts=1, last_finished=at(5))])]), at(10))
    (inc,) = engine.open.values()
    assert (inc.rule_id, inc.state, inc.reason) == ("restarts", State.PENDING, "1 restart within 5m")
    assert store.activity(inc.id)[0].message == "Pending: 1 restart within 5m"


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
    # Gone for less than the settle period could be a rollout between two pods.
    for t in (400, 410, 420):
        engine.tick(snap(at(t), pods=[], deployments=[]), at(t))
    assert [i.state for i in engine.open.values()] == [State.FIRING]
    engine.tick(snap(at(430), pods=[], deployments=[]), at(430))
    assert engine.open == {}
    (inc,) = store.list_incidents()
    assert inc.state is State.RESOLVED
    assert store.activity(inc.id)[-1].message == "Resolved: workload no longer present"


def test_terminating_pods_do_not_resolve_a_firing_incident(store):
    """A Recreate rollout or a replaced StatefulSet pod leaves a moment without an active
    pod. That is neither a recovery nor a removed workload."""
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    (inc,) = engine.open.values()
    leaving = pod(statuses=[crashloop_status(300)])
    leaving["metadata"]["deletionTimestamp"] = iso(at(300))
    for t in (300, 310):
        engine.tick(snap(at(t), pods=[leaving]), at(t))
    assert engine.open[inc.fingerprint].state is State.FIRING
    # The replacement crash-loops like the old pod: same incident, never resolved or reopened.
    for t in range(320, 600, 10):
        replacement = pod("web-abc-2", "pod-uid-2", [crashloop_status(t, start_offset=320)])
        engine.tick(snap(at(t), pods=[replacement]), at(t))
    (still,) = engine.open.values()
    assert (still.id, still.state, still.recurrence_count) == (inc.id, State.FIRING, 0)
    assert "resolved" not in [a.kind for a in store.activity(inc.id)]


def finished_pod(phase: str, reason: str, exit_code: int, finished: float, restarts: int = 0, **kw) -> dict:
    p = pod(statuses=[{
        "name": "app", "ready": False, "restartCount": restarts, "image": "x", "imageID": "sha256:abc",
        "state": {"terminated": {"reason": reason, "exitCode": exit_code, "finishedAt": iso(at(finished))}}}], **kw)
    p["status"]["phase"] = phase
    return p


def test_an_evicted_pod_next_to_a_healthy_one_does_not_block_recovery(store):
    engine = make_engine(store)
    states_over(engine, crashloop_status, 0, 5 * 60)
    evicted = finished_pod("Failed", "ContainerStatusUnknown", 137, 100, name="web-abc-0", uid="pod-uid-0")
    for t in range(300, 420, 10):
        healthy = pod("web-abc-2", "pod-uid-2", [running(started=at(300))])
        engine.tick(snap(at(t), pods=[healthy, evicted]), at(t))
    assert engine.open == {}
    (inc,) = store.list_incidents()
    assert inc.state is State.RESOLVED


def test_a_job_that_completed_after_retries_recovers(store):
    engine = make_engine(store, rules=["restarts"])
    job = {"kind": "Job", "name": "migrate", "uid": "job-uid-1", "controller": True}
    for t in range(0, 200, 10):
        engine.tick(snap(at(t), pods=[pod("migrate-x", statuses=[crashloop_status(t)], owner=job)]), at(t))
    (inc,) = engine.open.values()
    assert (inc.workload.kind, inc.state) == ("Job", State.FIRING)
    done = finished_pod("Succeeded", "Completed", 0, 200, restarts=4, name="migrate-x", owner=job)
    for t in range(200, 320, 10):
        engine.tick(snap(at(t), pods=[done]), at(t))
    assert engine.open == {}
    assert store.get_incident(inc.id).state is State.RESOLVED


def test_a_job_that_succeeded_in_a_new_pod_after_failed_ones_recovers(store):
    # restartPolicy Never: every retry is a new pod and the failed ones stay listed.
    engine = make_engine(store, rules=["restarts"])
    job = {"kind": "Job", "name": "migrate", "uid": "job-uid-1", "controller": True}
    for t in range(0, 200, 10):
        engine.tick(snap(at(t), pods=[pod("migrate-x", statuses=[crashloop_status(t)], owner=job)]), at(t))
    (inc,) = engine.open.values()
    failed = [finished_pod("Failed", "Error", 1, 150 + i, name=f"migrate-f{i}", uid=f"pod-f{i}", owner=job)
              for i in range(2)]
    done = finished_pod("Succeeded", "Completed", 0, 200, name="migrate-y", uid="pod-y", owner=job)
    for t in range(200, 320, 10):
        engine.tick(snap(at(t), pods=[*failed, done]), at(t))
    assert engine.open == {}
    assert store.get_incident(inc.id).state is State.RESOLVED


def test_a_job_whose_last_pod_failed_is_not_a_recovery(store):
    engine = make_engine(store, rules=["restarts"])
    job = {"kind": "Job", "name": "migrate", "uid": "job-uid-1", "controller": True}
    for t in range(0, 200, 10):
        engine.tick(snap(at(t), pods=[pod("migrate-x", statuses=[crashloop_status(t)], owner=job)]), at(t))
    done = finished_pod("Succeeded", "Completed", 0, 150, name="migrate-y", uid="pod-y", owner=job)
    failed = finished_pod("Failed", "Error", 1, 200, name="migrate-f", uid="pod-f", owner=job)
    for t in range(200, 400, 10):
        engine.tick(snap(at(t), pods=[done, failed]), at(t))
    assert [i.state for i in engine.open.values()] == [State.FIRING]


def test_a_failed_pod_alone_is_not_a_recovery(store):
    engine = make_engine(store, rules=["restarts"])
    job = {"kind": "Job", "name": "migrate", "uid": "job-uid-1", "controller": True}
    for t in range(0, 200, 10):
        engine.tick(snap(at(t), pods=[pod("migrate-x", statuses=[crashloop_status(t)], owner=job)]), at(t))
    failed = finished_pod("Failed", "Error", 1, 200, restarts=4, name="migrate-x", owner=job)
    for t in range(200, 400, 10):
        engine.tick(snap(at(t), pods=[failed]), at(t))
    assert [i.state for i in engine.open.values()] == [State.FIRING]


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
