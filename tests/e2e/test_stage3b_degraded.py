"""B14 acceptance: the observer reports its own loss of observations.

Removes the observer's RoleBinding in `lab` so its watches get 403, then restores it.
Runs after the stage 3 suite and needs the sink.
"""

from __future__ import annotations

import json
import time
from datetime import datetime

from conftest import LAB_NS, for_incident, kubectl, received, wait_for
from kpi_report import kpi

BINDING = "kubeness-observer-reader"
STATE: dict = {}


def degraded(api, state):
    hits = [i for i in api.get("/api/incidents").json()
            if i["rule_id"] == "observerDegraded" and i["workload"]["namespace"] == LAB_NS and i["state"] == state]
    return hits[0] if hits else None


def test_lost_permissions_raise_and_resolve_an_incident(api, sink):
    # A degraded incident from an earlier run must be resolved first.
    wait_for(lambda: degraded(api, "firing") is None and degraded(api, "recovering") is None, timeout=180,
             what="no open observerDegraded incident")
    saved = json.loads(kubectl("-n", LAB_NS, "get", "rolebinding", BINDING, "-o", "json").stdout)
    for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"):
        saved["metadata"].pop(k, None)
    removed = time.time()
    kubectl("-n", LAB_NS, "delete", "rolebinding", BINDING)
    try:
        inc = wait_for(lambda: degraded(api, "firing"), timeout=420, interval=5, what="observerDegraded firing")
        fired = datetime.fromisoformat(inc["firing_since"]).timestamp()
        # Open watches keep streaming until their timeout (60 s); then 403 until the budget (3 m) runs out.
        kpi("D04", "e2e RoleBinding removed to observerDegraded firing", fired - removed, "s", max=180 + 60 + 30)
        assert "403" in inc["reason"]
        d = api.get(f"/api/incidents/{inc['id']}").json()
        template = [a for a in d["analyses"] if a["source"] == "template"][-1]["payload"]
        assert any("permission" in c["text"].lower() for c in template["possible_causes"])
        # A reopened incident within the flap limit is recorded, not sent again.
        sent = wait_for(lambda: [r for r in for_incident(sink, inc["id"]) if r["at"] >= removed
                                 and r["payload"]["event"] in ("firing", "reopened")]
                        or [a for a in api.get(f"/api/incidents/{inc['id']}").json()["activity"]
                            if "flap limit" in a["message"]], timeout=60, what="notification or flap record")
        STATE["alerted"] = "payload" in sent[0]
        if STATE["alerted"]:
            assert "permission" in sent[0]["payload"]["possibleCause"].lower()
        st = api.get("/api/status").json()
        assert st["observer"] == "degraded"

        # N24: no heartbeats while the observer is degraded.
        before = len(received(sink, "/heartbeat"))
        time.sleep(70)
        kpi("N24", "e2e heartbeats while the observer is degraded", len(received(sink, "/heartbeat")) - before,
            "count", eq=0)
    finally:
        kubectl("apply", "-f", "-", input=json.dumps(saved))
    restored = time.time()
    done = wait_for(lambda: degraded(api, "resolved") if not degraded(api, "firing") and not degraded(api, "recovering")
                    else None, timeout=400, interval=5, what="observerDegraded resolved")
    assert done["id"] == inc["id"]
    if STATE["alerted"]:
        r = wait_for(lambda: [x for x in for_incident(sink, inc["id"], "resolved") if x["at"] >= restored],
                     timeout=60, what="resolved notification")[0]
        kpi("D04", "e2e RoleBinding restored to resolved notification", r["at"] - restored, "s", max=300)
    else:
        resolved_at = datetime.fromisoformat(done["resolved_at"]).timestamp()
        kpi("D04", "e2e RoleBinding restored to resolved", resolved_at - restored, "s", max=300)
    assert wait_for(lambda: api.get("/api/status").json()["observer"] == "ok", timeout=60, what="observer ok")
    beats = len(received(sink, "/heartbeat"))
    wait_for(lambda: len(received(sink, "/heartbeat")) > beats, timeout=90, what="heartbeats resume")
