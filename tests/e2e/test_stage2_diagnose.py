"""Stage 2 acceptance: the analysis shows evidence and missing information.

Requires the release installed with model.enabled=true and the model image loaded.
"""

from __future__ import annotations

import time

from kpi_report import kpi

from conftest import LAB_NS, RELEASE_NS, ROOT, find, kjson, kubectl, wait_for

FAULTS = str(ROOT / "lab" / "diagnose-faults.yaml")
WORKLOADS = ("leaky-crasher", "missing-tag")


def firing(api, workload, rule):
    hits = [i for i in find(api, workload, rule) if i["state"] == "firing"]
    return hits[0] if hits else None


def detail(api, inc):
    return api.get(f"/api/incidents/{inc['id']}").json()


def test_clean_start(api):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=90, what="old diagnose incidents resolved")
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-model", "--timeout=300s", timeout=320)


def test_model_is_ready(api):
    st = wait_for(lambda: (s := api.get("/api/status").json())["model"] == "ok" and s, timeout=180,
                  what="model ok")
    assert st["modelName"] == "qwen3:0.6b"


def _settled(api, inc):
    """Detail once logs are in and every template analysis has its model counterpart."""
    d = detail(api, inc)
    by_source = [a["source"] for a in d["analyses"]]
    has_log = any(e["kind"] == "log" for e in d["evidence"])
    return d if has_log and by_source.count("model") >= by_source.count("template") >= 1 else None


def test_crash_is_diagnosed_from_masked_logs(api):
    kubectl("apply", "-f", FAULTS, "-l", "lab-fault=leaky-crasher")
    inc = wait_for(lambda: firing(api, "leaky-crasher", "restarts"), timeout=300, what="leaky-crasher incident")
    d = wait_for(lambda: _settled(api, inc), timeout=240, what="logs and model analysis")

    log = [e for e in d["evidence"] if e["kind"] == "log"][-1]
    print(f"\nlog evidence: {log['summary']}")
    assert "hunter2" not in log["payload"]["text"]
    assert log["payload"]["redactions"] >= 1
    if log["payload"]["previous"]:
        assert "config file /etc/app/config.yaml not found" in log["payload"]["text"]

    refs = {e["ref"] for e in d["evidence"]}
    template = [a for a in d["analyses"] if a["source"] == "template"][-1]
    assert any(log["ref"] in f["evidence_refs"] for f in template["payload"]["observed_facts"]) or \
        not log["payload"]["previous"]

    runs = [a for a in d["analyses"] if a["source"] == "model"]
    for a in runs:
        print(f"model analysis {a['model']} ({a['status']}, {a['latency_ms']} ms): {a['payload'] or a['error']}")
    # K17 is the primary model's latency; an escalated larger model is slower by design.
    if runs[0]["status"] == "ok":
        kpi("K17", "e2e model latency, primary model", runs[0]["latency_ms"] / 1000, "s", max=15, timing=True)
    model = runs[-1]
    assert model["status"] == "ok", model["error"]
    assert model["payload"]["possible_causes"]
    for claim in model["payload"]["observed_facts"] + model["payload"]["possible_causes"]:
        assert claim["evidence_refs"] and set(claim["evidence_refs"]) <= refs
    assert "hunter2" not in str(d)


def test_detail_page_separates_facts_and_hypotheses(api):
    inc = firing(api, "leaky-crasher", "restarts")
    html = api.get(f"/incidents/{inc['id']}").text
    assert "Observed" in html and "Possible causes (hypotheses)" in html and "Next checks" in html
    assert "Analysis: model" in html


def test_lab_pods_cannot_reach_model():
    name = f"probe-{int(time.time())}"
    r = kubectl(
        "-n", LAB_NS, "run", name, "--image=busybox:1.36", "--restart=Never", "--rm", "-i", "--quiet",
        "--command", "--", "sh", "-c",
        f"wget -q -T 4 -O /dev/null http://kubeness-model.{RELEASE_NS}.svc.cluster.local:11434/api/tags "
        "&& echo REACHED || echo BLOCKED",
        check=False, timeout=120,
    )
    assert "BLOCKED" in r.stdout, r.stdout + r.stderr


def test_model_pod_has_no_api_token():
    pod = kjson("-n", RELEASE_NS, "get", "pods", "-l", "app.kubernetes.io/component=model")["items"][0]
    mounts = [m["mountPath"] for c in pod["spec"]["containers"] for m in c.get("volumeMounts", [])]
    assert not any("serviceaccount" in m for m in mounts)


def test_detection_continues_with_model_stopped(api):
    kubectl("-n", RELEASE_NS, "scale", "deployment/kubeness-model", "--replicas=0")
    kubectl("-n", RELEASE_NS, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/component=model",
            "--timeout=120s", check=False, timeout=140)
    try:
        kubectl("apply", "-f", FAULTS, "-l", "lab-fault=missing-tag")
        inc = wait_for(lambda: firing(api, "missing-tag", "imagePull"), timeout=240, what="missing-tag incident")
        d = wait_for(lambda: (x := detail(api, inc)) and any(a["source"] == "model" for a in x["analyses"]) and x,
                     timeout=120, what="model attempt")
        template = next(a for a in d["analyses"] if a["source"] == "template")
        assert template["status"] == "ok"
        assert any("tag does not exist" in c["text"] for c in template["payload"]["possible_causes"])
        model = next(a for a in d["analyses"] if a["source"] == "model")
        assert model["status"] == "unavailable" and model["error"]
        assert wait_for(lambda: api.get("/api/status").json()["model"] == "unavailable", 90, what="model status")
    finally:
        kubectl("-n", RELEASE_NS, "scale", "deployment/kubeness-model", "--replicas=1")
        kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-model", "--timeout=300s", timeout=320)


def test_cleanup(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=120, what="diagnose incidents resolved")
