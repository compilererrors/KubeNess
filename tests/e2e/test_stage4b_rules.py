"""Scheduling failure (B16) and OOM termination (B17) against kind."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from conftest import LAB_NS, ROOT, find, for_incident, kjson, kubectl, received, wait_for
from kpi_report import kpi

FAULTS = str(ROOT / "lab" / "rule-faults.yaml")
STATE: dict = {}


def open_inc(api, workload, rule, state=None):
    hits = [i for i in find(api, workload, rule) if i["state"] != "resolved" and (state is None or i["state"] == state)]
    return hits[0] if hits else None


def test_clean_start(api):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(lambda: not open_inc(api, "sched-huge", "scheduling") and not open_inc(api, "oom-once", "oom"),
             timeout=150, what="old rule incidents resolved")
    STATE["applied"] = datetime.now(timezone.utc)
    kubectl("apply", "-f", FAULTS)


def test_single_oom_kill_is_an_info_incident(api, sink):
    inc = wait_for(lambda: open_inc(api, "oom-once", "oom"), timeout=180, interval=3, what="oom incident")
    STATE["oom"] = inc
    assert inc["severity"] == "info"
    assert "32Mi" in inc["reason"]
    # The incident is saved a moment before its evidence and template analysis.
    d = wait_for(lambda: (x := api.get(f"/api/incidents/{inc['id']}").json())
                 and any(a["source"] == "template" for a in x["analyses"]) and x, timeout=60, what="template analysis")
    template = next(a for a in d["analyses"] if a["source"] == "template")
    assert any("32Mi" in c["text"] for c in template["payload"]["possible_causes"])
    kpi("R06", "e2e immediate notifications for a single OOM kill", len(for_incident(sink, inc["id"], ok_only=False)),
        "count", eq=0)


def test_unschedulable_pod_fires_with_resource_cause(api, sink):
    inc = wait_for(lambda: open_inc(api, "sched-huge", "scheduling", "firing"), timeout=240, what="scheduling incident")
    pod = kjson("-n", LAB_NS, "get", "pods", "-l", "app=sched-huge")["items"][0]
    cond = next(c for c in pod["status"]["conditions"] if c["type"] == "PodScheduled")
    since = datetime.fromisoformat(cond["lastTransitionTime"].replace("Z", "+00:00"))
    delay = (datetime.fromisoformat(inc["firing_since"]) - since).total_seconds()
    kpi("R03", "e2e Unschedulable to firing", delay, "s", max=120 + 10 + 5)
    assert "Insufficient cpu" in inc["reason"]
    (n,) = wait_for(lambda: for_incident(sink, inc["id"], "firing"), timeout=60, what="scheduling notification")
    assert "resources" in n["payload"]["possibleCause"]
    assert "requests" in n["payload"]["nextCheck"]
    readiness = [i for i in find(api, "sched-huge", "readiness") if i["state"] != "resolved"]
    assert readiness == [], "readiness is inhibited by the scheduling incident"


def test_second_oom_kill_raises_the_same_incident_to_warning(api, sink):
    first = STATE["oom"]
    wait_for(lambda: any(i["id"] == first["id"] and i["state"] == "resolved" for i in find(api, "oom-once", "oom")),
             timeout=180, what="oom incident resolved after the healthy restart")
    kubectl("-n", LAB_NS, "delete", "pod", "-l", "app=oom-once", "--wait=false")
    inc = wait_for(lambda: (i := open_inc(api, "oom-once", "oom")) and i["severity"] == "warning" and i,
                   timeout=180, interval=3, what="warning after the second kill")
    this_run = [i for i in find(api, "oom-once", "oom")
                if datetime.fromisoformat(i["first_seen"]) >= STATE["applied"]]   # earlier runs stay in the store
    kpi("R05", "e2e incidents for two OOM kills of one workload", len(this_run), "count", eq=1)
    assert inc["id"] == first["id"] and inc["recurrence_count"] >= 1
    (n,) = wait_for(lambda: for_incident(sink, inc["id"], "escalated"), timeout=60, what="escalated notification")
    assert n["payload"]["severity"] == "warning"


def test_readiness_evidence_shows_service_endpoints(api):
    inc = wait_for(lambda: open_inc(api, "svc-unready", "readiness", "firing"), timeout=240, what="readiness incident")
    d = api.get(f"/api/incidents/{inc['id']}").json()
    (svc,) = [e for e in d["evidence"] if e["kind"] == "service"]
    s = svc["payload"]["services"][0]
    assert (s["name"], s["ready"], s["notReady"]) == ("svc-unready", 0, 1)
    kpi("R08", "e2e readiness incidents with Service endpoint evidence", 1, "count", eq=1)
    template = [a for a in d["analyses"] if a["source"] == "template"][-1]["payload"]
    assert any("reaches no ready endpoint" in c["text"] for c in template["possible_causes"])


def test_rollout_is_reported_in_the_digest(api, sink):
    kubectl("-n", LAB_NS, "rollout", "status", "deployment/digest-roll", "--timeout=120s", timeout=140)
    changed = time.time()
    kubectl("-n", LAB_NS, "set", "image", "deployment/digest-roll", "app=docker.io/library/busybox:1.36")
    hit = wait_for(lambda: [r for r in received(sink) if r["payload"]["event"] == "digest" and r["at"] >= changed
                            and any("digest-roll" in i for i in r["payload"]["items"])],
                   timeout=240, what="digest with the rollout")
    kpi("R10", "e2e rollout to digest", hit[0]["at"] - changed, "s", max=120 + 30)
    immediate = [r for r in received(sink, ok_only=False) if r["payload"]["workload"] == "Deployment/digest-roll"]
    kpi("R09", "e2e immediate notifications for a rollout", len(immediate), "count", eq=0)


def test_cleanup(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: not open_inc(api, "sched-huge", "scheduling") and not open_inc(api, "oom-once", "oom"),
             timeout=150, what="rule incidents resolved")
