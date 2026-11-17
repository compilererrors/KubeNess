"""Stage 3 acceptance: the same fault gives controlled notifications and verified recovery.

Requires the release installed with lab/values-lab.yaml and the sink from lab/sink.yaml
(`make redeploy`). The tests run in file order.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime


from conftest import (
    LAB_NS, RELEASE_NS, ROOT, find, for_incident, kjson, kubectl, received, set_sink_failing, wait_for,
)
from kpi_report import kpi

FAULTS = str(ROOT / "lab" / "notify-faults.yaml")
WORKLOADS = ("notify-image", "notify-leaky", "notify-nomodel")
SECRET_MARKERS = ("hunter2", "notify-leaky-marker")


def firing(api, workload, rule):
    hits = [i for i in find(api, workload, rule) if i["state"] == "firing"]
    return hits[0] if hits else None


def notifier_pod() -> str:
    return kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=notifier")["items"][0]["metadata"]["name"]


def run_python(pod: str, code: str) -> str:
    r = kubectl("-n", RELEASE_NS, "exec", pod, "--", "python", "-c", code, check=False, timeout=60)
    return (r.stdout + r.stderr).strip()


STATE: dict = {}


def test_clean_start(api, sink):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=120, what="old notify incidents resolved")
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-notifier", "--timeout=120s", timeout=140)
    set_sink_failing(sink, False)
    sink.delete("/received").raise_for_status()


def test_heartbeat_reaches_the_dead_mans_switch(api, sink):
    """N23 in the cluster: heartbeats every 30 s while the observer is ok."""
    beats = wait_for(lambda: len(received(sink, "/heartbeat")) >= 2 and received(sink, "/heartbeat"),
                     timeout=100, what="two heartbeats")
    gap = beats[1]["at"] - beats[0]["at"]
    kpi("N23", "e2e heartbeat interval (configured 30s)", gap, "s", min=25, max=45)
    st = api.get("/api/status").json()
    assert st["notifier"] == "ok" and st["lastHeartbeat"]


def test_firing_notification_reaches_the_sink(api, sink):
    kubectl("apply", "-f", FAULTS, "-l", "lab-fault=notify-image")
    inc = wait_for(lambda: firing(api, "notify-image", "imagePull"), timeout=240, what="notify-image incident")
    STATE["image"] = inc
    (r,) = wait_for(lambda: for_incident(sink, inc["id"], "firing"), timeout=60, what="firing notification")
    p = r["payload"]
    assert (p["severity"], p["rule"], p["workload"]) == ("warning", "imagePull", "Deployment/notify-image")
    assert "busybox:no-such-tag-2222" in p["observed"]
    assert p["possibleCause"] and "Possible cause (hypothesis):" in p["text"]
    headers = {k.lower(): v for k, v in r["headers"].items()}
    assert headers["x-kubeness-notification-id"] == p["id"] == f"{inc['id']}:firing:0"
    delay = r["at"] - datetime.fromisoformat(inc["firing_since"]).timestamp()
    kpi("N28", "e2e firing to received in sink", delay, "s", max=30)
    d = api.get(f"/api/incidents/{inc['id']}").json()
    assert wait_for(lambda: api.get(f"/api/incidents/{inc['id']}").json()["notifications"][0]["status"]
                    == "provider_accepted", timeout=30, what="outbox status")
    assert any(a["kind"] == "notification" for a in d["activity"])


def test_sink_outage_loses_nothing(api, sink):
    """N31: the provider is down; the outbox retries until it is back."""
    set_sink_failing(sink, True)
    try:
        kubectl("apply", "-f", FAULTS, "-l", "lab-fault=notify-leaky")
        inc = wait_for(lambda: firing(api, "notify-leaky", "restarts"), timeout=300, what="notify-leaky incident")
        STATE["leaky"] = inc
        wait_for(lambda: len(for_incident(sink, inc["id"], ok_only=False)) >= 2, timeout=90, what="failed attempts")
        st = api.get("/api/status").json()
        assert st["notifier"] == "unavailable"
        n = api.get(f"/api/incidents/{inc['id']}").json()["notifications"][0]
        assert n["status"] in ("retry_scheduled", "sending") and n["attempts"] >= 2
        time.sleep(30)
    finally:
        back = time.time()
        set_sink_failing(sink, False)
    (r,) = wait_for(lambda: for_incident(sink, inc["id"], "firing"), timeout=90, what="delivery after outage")
    kpi("N31", "e2e delivery delay after the provider is back", r["at"] - back, "s", max=45)
    lost = [n for n in api.get(f"/api/incidents/{inc['id']}").json()["notifications"] if n["status"] == "failed"]
    kpi("N31", "e2e notifications lost during a 60 s outage", len(lost), "count", eq=0)
    assert wait_for(lambda: api.get("/api/status").json()["notifier"] == "ok", timeout=30, what="notifier ok")


def test_no_secrets_or_raw_logs_leave_the_cluster(sink):
    bodies = json.dumps([r["body"] for r in sink.get("/received").json()])
    kpi("N33", "e2e secrets or raw log lines in received notifications",
        sum(bodies.count(m) for m in SECRET_MARKERS), "count", eq=0)


def test_recovery_is_notified_once(api, sink):
    """N30: fix the image; one resolved notification after the recovery window."""
    inc = STATE["image"]
    fixed = time.time()
    kubectl("-n", LAB_NS, "set", "image", "deployment/notify-image", "app=busybox:1.36")
    (r,) = wait_for(lambda: for_incident(sink, inc["id"], "resolved"), timeout=180, what="resolved notification")
    kpi("N30", "e2e fix to resolved notification", r["at"] - fixed, "s", max=120)
    assert r["payload"]["state"] == "resolved" and r["payload"]["text"].startswith("[RESOLVED]")


def test_queued_notification_survives_observer_restart(ui, api, sink):
    """N32: a notification queued while the provider is down is sent after an observer restart."""
    inc = STATE["leaky"]
    set_sink_failing(sink, True)
    try:
        kubectl("-n", LAB_NS, "patch", "deployment/notify-leaky", "--type=json", "-p",
                json.dumps([{"op": "replace", "path": "/spec/template/spec/containers/0/command",
                             "value": ["sleep", "3600"]}]))
        wait_for(lambda: [n for n in api.get(f"/api/incidents/{inc['id']}").json()["notifications"]
                          if n["event"] == "resolved" and n["attempts"] >= 1], timeout=240, what="resolved queued")
        pod = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=observer")["items"][0]
        kubectl("-n", RELEASE_NS, "delete", "pod", pod["metadata"]["name"], "--wait=true", timeout=120)
    finally:
        set_sink_failing(sink, False)
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-observer", "--timeout=180s", timeout=200)
    # The port-forward followed the old pod; reconnect the shared UI client.
    ui.stop()
    ui.start()
    api.base_url = f"http://127.0.0.1:{ui.port}"
    (r,) = wait_for(lambda: for_incident(sink, inc["id"], "resolved"), timeout=120, what="resolved after restart")
    kpi("N32", "e2e queued notifications delivered after observer restart", 1, "count", eq=1)


def test_one_alert_per_fault(sink):
    """N29: the incidents above produced exactly one firing notification each."""
    for key in ("image", "leaky"):
        c = Counter(r["payload"]["event"] for r in for_incident(sink, STATE[key]["id"]))
        kpi("N29", f"e2e firing notifications for notify-{key}", c["firing"], "count", eq=1)
        assert c["resolved"] == 1


def test_notification_without_model(api, sink):
    """N35: the alarm chain does not depend on the model."""
    kubectl("-n", RELEASE_NS, "scale", "deployment/kubeness-model", "--replicas=0")
    try:
        kubectl("apply", "-f", FAULTS, "-l", "lab-fault=notify-nomodel")
        inc = wait_for(lambda: firing(api, "notify-nomodel", "imagePull"), timeout=240, what="notify-nomodel incident")
        got = wait_for(lambda: for_incident(sink, inc["id"], "firing"), timeout=60, what="notification without model")
        kpi("N35", "e2e notifications sent with the model stopped", len(got), "count", eq=1)
    finally:
        kubectl("-n", RELEASE_NS, "scale", "deployment/kubeness-model", "--replicas=1")
        kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-model", "--timeout=300s", timeout=320)


# --- isolation (N27, N34) ---------------------------------------------------------------------

def test_lab_pods_cannot_reach_the_notifier():
    name = f"probe-{int(time.time())}"
    r = kubectl(
        "-n", LAB_NS, "run", name, "--image=busybox:1.36", "--restart=Never", "--rm", "-i", "--quiet",
        "--command", "--", "sh", "-c",
        f"wget -q -T 4 -O /dev/null http://kubeness-notifier.{RELEASE_NS}.svc.cluster.local:8081/healthz "
        "&& echo REACHED || echo BLOCKED",
        check=False, timeout=120,
    )
    kpi("N34", "e2e lab pod reaches the notifier", int("REACHED" in r.stdout), "bool", eq=0)
    assert "BLOCKED" in r.stdout, r.stdout + r.stderr


def test_notifier_reaches_only_the_sink():
    pod = notifier_pod()
    probe = ("import httpx\n"
             "for u in {urls}:\n"
             "    try:\n"
             "        httpx.get(u, timeout=4); print('REACHED', u)\n"
             "    except Exception as e:\n"
             "        print('BLOCKED', u, type(e).__name__)\n")
    others = ["http://kubeness-model.kubeness.svc.cluster.local:11434/api/tags",
              "http://kubeness.kubeness.svc.cluster.local/healthz",
              "https://kubernetes.default.svc/version",
              "https://1.1.1.1/"]
    out = run_python(pod, probe.format(urls=others + ["http://sink.lab-sink.svc.cluster.local:8080/healthz"]))
    print("\n" + out)
    reached_other = sum(1 for u in others if f"REACHED {u}" in out)
    kpi("N34", "e2e destinations other than the sink the notifier reaches", reached_other, "count", eq=0)
    assert "REACHED http://sink.lab-sink.svc.cluster.local:8080/healthz" in out


def test_notifier_has_no_api_token():
    pod = kjson("-n", RELEASE_NS, "get", "pod", notifier_pod())
    mounts = [m["mountPath"] for c in pod["spec"]["containers"] for m in c.get("volumeMounts", [])]
    kpi("N27", "e2e ServiceAccount token mounts in the notifier",
        sum(1 for m in mounts if "serviceaccount" in m), "count", eq=0)


def test_notifier_rejects_calls_without_the_token():
    pod = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=observer")["items"][0]
    code = ("import httpx; r = httpx.post('http://kubeness-notifier:8081/v1/notify', json={}, timeout=5); "
            "print(r.status_code)")
    out = run_python(pod["metadata"]["name"], code)
    kpi("N13", "e2e notifier answer without token", int(out.splitlines()[-1]), "status", eq=401)


def test_cleanup(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=150, what="notify incidents resolved")
