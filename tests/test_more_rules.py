"""B16 scheduling failure and B17 OOM termination."""

from __future__ import annotations

from collections import Counter

import pytest

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.notify import NotificationPolicy
from kubeness.store import Store

from factories import at, event, iso, pod, running, snap
from kpi_report import kpi
from test_diagnose import FakeLogs


def make(notifications=True, **access):
    cfg = Config.model_validate({"notifications": {"enabled": notifications}, "access": access})
    store = Store(":memory:")
    return cfg, store, Engine(cfg, store, LogCollector(cfg, FakeLogs()), None, NotificationPolicy(cfg, store))


def transitions_over(engine, pods_at, start, end, events=None):
    out = []
    for t in range(start, end, 10):
        for tr in engine.tick(snap(at(t), pods=pods_at(t), events=events), at(t)):
            out.append((t, tr.incident.rule_id, tr.kind))
    return out


# --- B16 scheduling ------------------------------------------------------------------------------

def unschedulable(message="0/1 nodes are available: 1 Insufficient cpu.", cpu="1000"):
    p = pod(statuses=[])
    p["spec"]["containers"] = [{"name": "app", "image": "busybox:1.36", "resources": {"requests": {"cpu": cpu}}}]
    p["status"] = {"phase": "Pending", "conditions": [
        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": message,
         "lastTransitionTime": iso(at(0))}]}
    return p


def scheduled_pending():
    """Scheduled, waiting for its image: not a scheduling problem."""
    p = pod(statuses=[{"name": "app", "ready": False, "restartCount": 0, "image": "x", "imageID": "",
                       "state": {"waiting": {"reason": "ContainerCreating"}}}])
    p["status"]["phase"] = "Pending"
    p["status"]["conditions"] = [{"type": "PodScheduled", "status": "True"}]
    return p


def test_r01_unschedulable_fires_after_two_minutes():
    _, store, engine = make()
    ev = [event("FailedScheduling", "0/1 nodes are available: 1 Insufficient cpu.", "web-abc-1", at(1), "ev1")]
    tr = transitions_over(engine, lambda t: [unschedulable()], 0, 300, events=ev)
    fired = next(t for t, r, k in tr if r == "scheduling" and k == "fired")
    kpi("R01", "unschedulable to firing", fired, "s", max=120 + 10)
    (inc,) = [i for i in store.list_incidents() if i.rule_id == "scheduling"]
    assert "Insufficient cpu" in inc.reason
    assert inc.details["pods"][0]["requests"] == {"app": {"cpu": "1000"}}
    (n,) = store.notifications(inc.id)
    assert "resources" in n.payload["possibleCause"].lower() or "request" in n.payload["possibleCause"].lower()
    assert "Node capacity" in " ".join(n.payload["missing"]) or n.payload["missing"]


def test_r02_other_pending_reasons_are_not_scheduling():
    _, store, engine = make()
    transitions_over(engine, lambda t: [scheduled_pending()], 0, 400)
    kpi("R02", "scheduling incidents for a scheduled, pending pod",
        len([i for i in store.list_incidents() if i.rule_id == "scheduling"]), "count", eq=0)


def test_scheduling_recovers_when_the_pod_runs():
    _, store, engine = make()
    transitions_over(engine, lambda t: [unschedulable()], 0, 200)
    tr = transitions_over(engine, lambda t: [pod(statuses=[running(started=at(200))])], 200, 400)
    assert ("scheduling", "resolved") in {(r, k) for _, r, k in tr}


@pytest.mark.parametrize("message,cause", [
    ("0/3 nodes are available: 3 node(s) didn't match Pod's node affinity/selector.", "selector"),
    ("0/1 nodes are available: 1 node(s) had untolerated taint {dedicated: gpu}.", "taint"),
    ("0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims.", "PersistentVolumeClaim"),
])
def test_scheduling_runbook_names_the_cause(message, cause):
    _, store, engine = make()
    transitions_over(engine, lambda t: [unschedulable(message=message)], 0, 200)
    (inc,) = [i for i in store.list_incidents() if i.rule_id == "scheduling"]
    (n,) = store.notifications(inc.id)
    assert cause.lower() in (n.payload["possibleCause"] + n.payload["nextCheck"]).lower()


def test_nodes_are_read_only_when_enabled():
    calls = []

    def read_nodes():
        calls.append(1)
        return [{"metadata": {"name": "n1"}, "spec": {"taints": [{"key": "dedicated", "effect": "NoSchedule"}]},
                 "status": {"allocatable": {"cpu": "4", "memory": "8Gi"}}}]

    for enabled in (False, True):
        cfg = Config.model_validate({"access": {"readNodes": enabled}})
        store = Store(":memory:")
        engine = Engine(cfg, store, LogCollector(cfg, None, read_nodes=read_nodes))
        transitions_over(engine, lambda t: [unschedulable()], 0, 200)
        (inc,) = [i for i in store.list_incidents() if i.rule_id == "scheduling"]
        nodes = [e for e in store.evidence(inc.id) if e.kind == "nodes"]
        if enabled:
            assert nodes and nodes[0].payload["nodes"][0] == {"name": "n1", "allocatable": {"cpu": "4", "memory": "8Gi"},
                                                              "taints": ["dedicated:NoSchedule"]}
        else:
            assert nodes == [] and calls == []
    assert len(calls) == 1


# --- B17 OOM -------------------------------------------------------------------------------------

def oom_then_running(oom_at: list[int], limit="64Mi"):
    """Container that was OOM killed at the given times and restarted each time."""
    def status(t):
        past = [x for x in oom_at if x <= t]
        s = running(started=at(past[-1] + 1) if past else at(-600), restarts=len(past))
        if past:
            s["lastState"] = {"terminated": {"reason": "OOMKilled", "exitCode": 137, "finishedAt": iso(at(past[-1]))}}
        p = pod(statuses=[s])
        p["spec"]["containers"][0]["resources"] = {"limits": {"memory": limit}}
        return [p]
    return status


def test_r04_single_oom_is_info_and_not_sent_at_once():
    _, store, engine = make()
    tr = transitions_over(engine, oom_then_running([100]), 0, 400)
    (inc,) = [i for i in store.list_incidents() if i.rule_id == "oom"]
    kpi("R04", "incidents for one OOMKilled", 1, "count", eq=1)
    assert inc.severity == "info"
    assert "64Mi" in inc.reason or inc.details["containers"][0]["memoryLimit"] == "64Mi"
    assert ("oom", "resolved") in {(r, k) for _, r, k in tr}, "healthy after the restart"
    assert store.notifications(inc.id) == [], "info goes to the digest, not an immediate notification"


def test_r05_repeated_oom_raises_the_same_incident_to_warning():
    _, store, engine = make()
    transitions_over(engine, oom_then_running([100, 700]), 0, 1000)
    incs = [i for i in store.list_incidents() if i.rule_id == "oom"]
    kpi("R05", "incidents for two OOMKilled within 30 m", len(incs), "count", eq=1)
    (inc,) = incs
    assert inc.severity == "warning" and inc.recurrence_count == 1
    assert Counter(n.event for n in store.notifications(inc.id))["escalated"] == 1


def test_oom_seen_before_the_observer_started_is_not_reported():
    _, store, engine = make()
    transitions_over(engine, oom_then_running([-100]), 0, 300)
    assert [i for i in store.list_incidents() if i.rule_id == "oom"] == []


def test_oom_is_inhibited_while_restarts_fires():
    from test_engine import crashloop_status

    def pods(t):
        s = crashloop_status(t)
        if "lastState" in s:
            s["lastState"]["terminated"]["reason"] = "OOMKilled"
        return [pod(statuses=[s])]

    _, store, engine = make()
    transitions_over(engine, pods, 0, 600)
    rules = sorted(i.rule_id for i in store.list_incidents())
    assert rules == ["restarts"]
