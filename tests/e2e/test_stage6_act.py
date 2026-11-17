"""Stage 6 acceptance: one approved, named action with its own writer identity.

Needs the release installed with executor.enabled and actions.enabled (lab/values-lab.yaml).
"""

from __future__ import annotations

import json
import re
import time

import pytest

from conftest import LAB_NS, RELEASE_NS, ROOT, find, kjson, kubectl, wait_for
from kpi_report import kpi

FAULTS = str(ROOT / "lab" / "act-faults.yaml")
EXECUTOR_SA = f"system:serviceaccount:{RELEASE_NS}:kubeness-executor"


@pytest.mark.parametrize("expected,args", [
    ("yes", ["patch", "deployments.apps", "-n", LAB_NS]),
    ("yes", ["get", "deployments.apps", "-n", LAB_NS]),
    ("no", ["delete", "deployments.apps", "-n", LAB_NS]),
    ("no", ["create", "deployments.apps", "-n", LAB_NS]),
    ("no", ["patch", "deployments.apps", "-n", "kube-system"]),
    ("no", ["get", "secrets", "-n", LAB_NS]),
    ("no", ["create", "pods", "--subresource=exec", "-n", LAB_NS]),
    ("no", ["patch", "pods", "-n", LAB_NS]),
    ("no", ["list", "nodes"]),
])
def test_executor_effective_permissions(expected, args):
    got = kubectl("auth", "can-i", *args, f"--as={EXECUTOR_SA}", check=False).stdout.strip()
    assert got == expected, f"executor can-i {' '.join(args)}"


def firing(api):
    hits = [i for i in find(api, "act-crasher", "restarts") if i["state"] == "firing"]
    return hits[0] if hits else None


def approve(api, inc_id):
    html = api.get(f"/incidents/{inc_id}").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    return api.post(f"/incidents/{inc_id}/actions/restart-deployment", data={"csrf_token": token},
                    headers={"origin": str(api.base_url).rstrip("/")}, follow_redirects=False)


def test_approved_restart_is_executed_verified_and_audited(api):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-executor", "--timeout=120s", timeout=140)
    kubectl("apply", "-f", FAULTS)
    inc = wait_for(lambda: firing(api), timeout=300, what="act-crasher incident")
    before = kjson("-n", LAB_NS, "get", "deployment", "act-crasher")["metadata"]["generation"]
    approved = time.time()
    assert approve(api, inc["id"]).status_code == 303
    (a,) = api.get(f"/api/incidents/{inc['id']}").json()["actions"]
    assert a["status"] in ("executed", "verified"), a
    done = wait_for(lambda: (x := api.get(f"/api/incidents/{inc['id']}").json()["actions"][0])["status"] == "verified"
                    and x, timeout=60, what="verified action")
    kpi("X03", "e2e approval to verified restart", time.time() - approved, "s", max=60)
    dep = kjson("-n", LAB_NS, "get", "deployment", "act-crasher")
    assert dep["metadata"]["generation"] == before + 1
    assert "kubectl.kubernetes.io/restartedAt" in dep["spec"]["template"]["metadata"]["annotations"]
    pod = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=executor")["items"][0]
    logs = kubectl("-n", RELEASE_NS, "logs", pod["metadata"]["name"]).stdout
    audit = [json.loads(line.split("audit ", 1)[1]) for line in logs.splitlines() if " audit " in line]
    assert any(e.get("id") == done["id"] and e["result"] == "executed" for e in audit)


def test_executor_is_reachable_only_with_the_token_from_the_observer():
    name = f"probe-{int(time.time())}"
    r = kubectl("-n", LAB_NS, "run", name, "--image=busybox:1.36", "--restart=Never", "--rm", "-i", "--quiet",
                "--command", "--", "sh", "-c",
                f"wget -q -T 4 -O /dev/null http://kubeness-executor.{RELEASE_NS}.svc.cluster.local:8082/healthz "
                "&& echo REACHED || echo BLOCKED", check=False, timeout=120)
    kpi("X02", "e2e lab pod reaches the executor", int("REACHED" in r.stdout), "bool", eq=0)
    obs = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=observer")["items"][0]
    code = ("import httpx; r = httpx.post('http://kubeness-executor:8082/v1/actions', json={'id': 'x', "
            "'action': 'restart-deployment', 'params': {'namespace': 'lab', 'name': 'act-crasher'}, 'incident': 'i'}, "
            "timeout=5); print(r.status_code)")
    out = kubectl("-n", RELEASE_NS, "exec", obs["metadata"]["name"], "--", "python", "-c", code, check=False).stdout
    kpi("X02", "e2e executor answer without token", int(out.strip().splitlines()[-1]), "status", eq=401)


@pytest.mark.parametrize("who,expected,args", [
    ("observer", "yes", ["get", "pods", "-n", "lab-observe"]),
    ("observer", "no", ["get", "pods", "--subresource=log", "-n", "lab-observe"]),
    ("observer", "yes", ["get", "pods", "--subresource=log", "-n", LAB_NS]),
    ("executor", "no", ["patch", "deployments.apps", "-n", "lab-observe"]),
    ("executor", "yes", ["list", "replicasets.apps", "-n", LAB_NS]),
    ("executor", "no", ["delete", "replicasets.apps", "-n", LAB_NS]),
])
def test_g04_permissions_follow_the_silo_profiles(who, expected, args):
    sa = EXECUTOR_SA if who == "executor" else f"system:serviceaccount:{RELEASE_NS}:kubeness-observer"
    got = kubectl("auth", "can-i", *args, f"--as={sa}", check=False).stdout.strip()
    assert got == expected, f"{who} can-i {' '.join(args)}"


def test_x06_bad_image_is_fixed_by_an_approved_rollback(api):
    kubectl("-n", LAB_NS, "rollout", "status", "deployment/act-rollback", "--timeout=120s", timeout=140)
    kubectl("-n", LAB_NS, "set", "image", "deployment/act-rollback", "app=busybox:no-such-tag-5555")
    inc = wait_for(lambda: next((i for i in find(api, "act-rollback", "imagePull") if i["state"] == "firing"), None),
                   timeout=240, what="act-rollback image pull incident")
    html = api.get(f"/incidents/{inc['id']}").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = api.post(f"/incidents/{inc['id']}/actions/rollback-deployment", data={"csrf_token": token, "revision": "1"},
                 headers={"origin": str(api.base_url).rstrip("/")}, follow_redirects=False)
    assert r.status_code == 303
    wait_for(lambda: api.get(f"/api/incidents/{inc['id']}").json()["actions"][-1]["status"] == "verified",
             timeout=60, what="verified rollback")
    image = kjson("-n", LAB_NS, "get", "deployment", "act-rollback")["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image == "busybox:1.36"
    resolved = wait_for(lambda: next((i for i in find(api, "act-rollback", "imagePull")
                                      if i["id"] == inc["id"] and i["state"] == "resolved"), None),
                        timeout=180, what="incident resolved after the rollback")
    kpi("X06", "e2e bad image fixed by an approved rollback", int(bool(resolved)), "bool", eq=1)


def test_t05_troubleshooting_with_the_local_model_and_thinking(api):
    inc = wait_for(lambda: firing(api), timeout=300, what="act-crasher incident")
    html = api.get(f"/incidents/{inc['id']}").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    started = time.time()
    r = api.post(f"/incidents/{inc['id']}/troubleshoot", data={"csrf_token": token},
                 headers={"origin": str(api.base_url).rstrip("/")}, follow_redirects=False)
    assert r.status_code == 303
    inv = wait_for(lambda: (x := api.get(f"/api/incidents/{inc['id']}").json()["investigations"])
                   and x[0]["status"] != "running" and x[0], timeout=4 * 90 + 60, interval=5,
                   what="troubleshooting finished")
    print("\ninvestigation:", json.dumps({k: inv[k] for k in ("status", "think", "error")}),
          [(s["tool"], s["status"]) for s in inv["steps"]], json.dumps(inv["conclusion"])[:600])
    kpi("T05", f"e2e troubleshooting with {inv['model']} and thinking finished", time.time() - started, "s",
        max=4 * 90 + 60)
    assert inv["think"] is True and inv["status"] in ("done", "incomplete", "failed")
    st = api.get("/api/status").json()
    assert inv["model"] == (st.get("modelEscalation") or st["modelName"]), "troubleshooting runs on the top tier"
    refs = {e["ref"] for e in api.get(f"/api/incidents/{inc['id']}").json()["evidence"]}
    for f in inv["conclusion"].get("findings", []):
        assert set(f["evidence_refs"]) <= refs
    if inv["conclusion"].get("fix"):
        assert inv["conclusion"]["fix"]["params"]["name"] == "act-crasher"


def test_cleanup(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in ("act-crasher", "act-rollback") for i in find(api, w) if i["state"] != "resolved"],
             timeout=150, what="act incidents resolved")
