"""Stage 1 acceptance: known lab faults give the correct incident state.

The tests run in file order and share the faults applied by the first test.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from kpi_report import kpi

from conftest import (
    LAB_NS, OBSERVER_SA, RELEASE_NS, ROOT, PortForward, find, incidents, kjson, kubectl, wait_for,
)

FAULTS = str(ROOT / "lab" / "faults.yaml")
FAULT_WORKLOADS = ("crasher", "bad-image", "never-ready", "healthy")


def open_incident(api, workload, rule, state="firing"):
    hits = [i for i in find(api, workload, rule) if i["state"] == state]
    return hits[0] if hits else None


# --- setup ------------------------------------------------------------------------

def test_clean_start(api):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(
        lambda: not [i for i in incidents(api) if i["workload"]["name"] in FAULT_WORKLOADS and i["state"] != "resolved"],
        timeout=90, what="old lab incidents to resolve",
    )


def test_observer_status_is_ok(api):
    st = wait_for(lambda: (s := api.get("/api/status").json())["observer"] == "ok" and s, timeout=120,
                  what="observer ok")
    assert st["engineRunning"]
    kinds = {(s["namespace"], s["kind"]) for s in st["sources"] if s["fresh"]}
    assert {(LAB_NS, k) for k in ("pods", "replicasets", "deployments", "events")} <= kinds


def test_ui_pages_render(api):
    r = api.get("/")
    assert r.status_code == 200 and "Incidents" in r.text
    assert api.get("/", headers={"host": "evil.example"}).status_code == 403


# --- permissions --------------------------------------------------------------------

@pytest.mark.parametrize("expected,args", [
    ("yes", ["get", "pods", "-n", LAB_NS]),
    ("yes", ["watch", "events", "-n", LAB_NS]),
    ("yes", ["list", "deployments.apps", "-n", LAB_NS]),
    ("yes", ["get", "pods", "--subresource=log", "-n", LAB_NS]),
    ("no", ["get", "secrets", "-n", LAB_NS]),
    ("no", ["create", "pods", "--subresource=exec", "-n", LAB_NS]),
    ("no", ["patch", "deployments.apps", "-n", LAB_NS]),
    ("no", ["delete", "pods", "-n", LAB_NS]),
    ("no", ["get", "pods", "-n", "kube-system"]),
    ("no", ["list", "nodes"]),
])
def test_effective_permissions(expected, args):
    got = kubectl("auth", "can-i", *args, f"--as={OBSERVER_SA}", check=False).stdout.strip()
    assert got == expected, f"can-i {' '.join(args)}"


# --- faults -------------------------------------------------------------------------------

APPLIED: dict[str, datetime] = {}


def detection_seconds(inc: dict) -> float:
    return (datetime.fromisoformat(inc["firing_since"]) - APPLIED["at"]).total_seconds()


def test_apply_faults():
    APPLIED["at"] = datetime.now(timezone.utc)
    kubectl("apply", "-f", FAULTS)


def test_image_pull_failure_fires_with_exact_image(api):
    inc = wait_for(lambda: open_incident(api, "bad-image", "imagePull"), timeout=240, what="bad-image incident")
    assert "busybox:does-not-exist-0000" in inc["reason"]
    kpi("K16", "e2e detection time, bad-image", detection_seconds(inc), "s", max=120)
    detail = api.get(f"/api/incidents/{inc['id']}").json()
    rule_ev = detail["evidence"][0]
    assert rule_ev["kind"] == "rule"
    assert rule_ev["payload"]["containers"][0]["specImage"] == "busybox:does-not-exist-0000"


def test_crash_loop_fires(api):
    inc = wait_for(lambda: open_incident(api, "crasher", "restarts"), timeout=300, what="crasher incident")
    kpi("K16", "e2e detection time, crasher", detection_seconds(inc), "s", max=180)
    detail = api.get(f"/api/incidents/{inc['id']}").json()
    assert any(e["kind"] == "event" for e in detail["evidence"]), "related events are stored as evidence"


def test_readiness_failure_fires(api):
    inc = wait_for(lambda: open_incident(api, "never-ready", "readiness"), timeout=360, what="never-ready incident")
    assert "ready" in inc["reason"].lower() or "ProgressDeadlineExceeded" in inc["reason"]
    kpi("K16", "e2e detection time, never-ready", detection_seconds(inc), "s", max=180)


def test_healthy_control_has_no_incident(api):
    assert find(api, "healthy") == []
    # The crasher's readiness problem is inhibited by its restart incident.
    assert [i for i in find(api, "crasher", "readiness") if i["state"] != "resolved"] == []


# --- resilience ---------------------------------------------------------------------------

def test_monitoring_continues_without_ui():
    """Close the port-forward, change the cluster, reconnect: the change was observed."""
    kubectl("-n", LAB_NS, "set", "image", "deployment/bad-image", "app=busybox:1.36")
    time.sleep(100)  # settle 30s + recovery window 60s + one evaluation, with no UI connected
    pf = PortForward().start()
    try:
        with pf.client() as c:
            wait_for(lambda: [i for i in find(c, "bad-image", "imagePull") if i["state"] == "resolved"],
                     timeout=60, what="bad-image resolved")
    finally:
        pf.stop()


def test_incidents_survive_observer_restart(ui, api):
    before = {i["id"] for i in incidents(api) if i["state"] != "resolved"}
    assert before
    pod = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=observer")["items"][0]
    kubectl("-n", RELEASE_NS, "delete", "pod", pod["metadata"]["name"], "--wait=true", timeout=120)
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-observer", "--timeout=180s", timeout=200)
    # port-forward binds to one pod; reconnect the shared session to the new one.
    ui.stop()
    ui.start()
    api.base_url = f"http://127.0.0.1:{ui.port}"
    after = wait_for(lambda: {i["id"] for i in incidents(api) if i["state"] != "resolved"},
                     timeout=60, what="incidents after restart")
    assert before <= after
    # The crash loop keeps firing after the restart; it must not be resolved or duplicated.
    crasher = [i for i in find(api, "crasher", "restarts") if i["state"] != "resolved"]
    assert len(crasher) == 1


# --- network boundaries ---------------------------------------------------------------------

def _observer_pod() -> str:
    return kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=observer")["items"][0]["metadata"]["name"]


def _connect_from_observer(host: str, port: int) -> bool:
    code = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(4)\n"
        f"sys.exit(0 if s.connect_ex(({host!r},{port}))==0 else 1)\n"
    )
    r = kubectl("-n", RELEASE_NS, "exec", _observer_pod(), "--", "python", "-c", code, check=False, timeout=30)
    return r.returncode == 0


def test_observer_has_no_internet_egress():
    assert not _connect_from_observer("1.1.1.1", 443)


def test_observer_reaches_dns_and_api():
    # The API path is proven by fresh sources in /api/status; check DNS explicitly.
    code = "import socket; socket.getaddrinfo('kubernetes.default.svc.cluster.local', 443)"
    r = kubectl("-n", RELEASE_NS, "exec", _observer_pod(), "--", "python", "-c", code, check=False, timeout=30)
    assert r.returncode == 0, r.stderr


def test_other_pods_cannot_reach_observer():
    name = f"probe-{int(time.time())}"
    r = kubectl(
        "-n", LAB_NS, "run", name, "--image=busybox:1.36", "--restart=Never", "--rm", "-i", "--quiet",
        "--command", "--", "sh", "-c",
        f"wget -q -T 4 -O /dev/null http://kubeness.{RELEASE_NS}.svc.cluster.local/healthz && echo REACHED || echo BLOCKED",
        check=False, timeout=120,
    )
    assert "BLOCKED" in r.stdout, r.stdout + r.stderr


# --- cleanup ----------------------------------------------------------------------------------

def test_removing_faults_resolves_incidents(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(
        lambda: not [i for i in incidents(api) if i["workload"]["name"] in FAULT_WORKLOADS and i["state"] != "resolved"],
        timeout=120, what="all lab incidents resolved",
    )
