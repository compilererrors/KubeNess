"""Tiered models in the cluster: 0.6B for every incident, the escalation model by rule.

Runs when the release uses lab/models/tiered.yaml (make e2e MODEL_PROFILE=tiered).
"""

from __future__ import annotations

import statistics

import pytest

from conftest import ROOT, find, kubectl, wait_for
from kpi_report import kpi

FAULTS = str(ROOT / "lab" / "diagnose-faults.yaml")
WORKLOADS = ("leaky-crasher", "missing-tag")


@pytest.fixture(scope="module")
def tiers(api):
    st = wait_for(lambda: (s := api.get("/api/status").json())["model"] == "ok" and s, timeout=300, what="model ok")
    if not st.get("modelEscalation"):
        pytest.skip("the release has no escalation model (use MODEL_PROFILE=tiered)")
    return st["modelName"], st["modelEscalation"]


def settled(api, workload):
    hits = [i for i in find(api, workload) if i["state"] == "firing"]
    if not hits:
        return None
    d = api.get(f"/api/incidents/{hits[0]['id']}").json()
    models = [a for a in d["analyses"] if a["source"] == "model"]
    escalated = [a for a in d["activity"] if a["message"].startswith("Escalated to")]
    # done when the small model answered and, if it escalated, the larger one too
    return d if models and len(models) >= 1 + len(escalated) else None


def test_every_incident_starts_small_and_escalates_only_by_a_logged_rule(api, tiers):
    small, big = tiers
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=150, what="old diagnose incidents resolved")
    kubectl("apply", "-f", FAULTS)
    details = [wait_for(lambda w=w: settled(api, w), timeout=420, interval=5, what=f"{w} analysed") for w in WORKLOADS]
    escalations, latency = 0, {small: [], big: []}
    for d in details:
        models = [a for a in d["analyses"] if a["source"] == "model"]
        assert models[0]["model"] == small, "the small model always answers first"
        logged = [a["message"] for a in d["activity"] if a["message"].startswith("Escalated to")]
        bigs = [a for a in models if a["model"] == big]
        assert len(bigs) == len(logged), "every escalation is logged with its rule"
        for m in logged:
            assert any(r in m for r in ("invalid", "unsupported", "ungrounded", "critical", "recurring"))
        escalations += bool(bigs)
        for a in models:
            if a["latency_ms"] is not None and a["status"] == "ok":
                latency[a["model"]].append(a["latency_ms"] / 1000)
        shown = [a for a in models if a["status"] == "ok"]
        if shown:
            assert shown[-1]["model"] == (big if bigs and bigs[-1]["status"] == "ok" else shown[-1]["model"])
    print(f"\ntiered: {escalations}/{len(details)} escalated; latency {latency}")
    kpi("E02", "e2e incidents escalated to the larger model", escalations, "count", max=len(details))
    if latency[small]:
        kpi("E03", f"e2e {small} latency (median)", statistics.median(latency[small]), "s", max=15)
    if latency[big]:
        kpi("E03", f"e2e {big} latency (median)", statistics.median(latency[big]), "s", max=45)


def test_cleanup(api, tiers):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: not [i for w in WORKLOADS for i in find(api, w) if i["state"] != "resolved"],
             timeout=150, what="diagnose incidents resolved")
