"""Stage 4/5 acceptance for acknowledge and silence through the port-forwarded UI.

Silence pauses notifications, not detection; both need the CSRF token and a
same-origin request.
"""

from __future__ import annotations

import re
import time

from conftest import ROOT, find, for_incident, kubectl, wait_for
from kpi_report import kpi

FAULTS = str(ROOT / "lab" / "inspect-faults.yaml")


def current(api):
    hits = [i for i in find(api, "inspect-silenced", "imagePull") if i["state"] != "resolved"]
    return hits[0] if hits else None


def form(api, inc_id, action, origin=True, token=True, **fields):
    html = api.get(f"/incidents/{inc_id}").text
    data = dict(fields)
    if token:
        data["csrf_token"] = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    headers = {"origin": str(api.base_url).rstrip("/")} if origin is True else ({"origin": origin} if origin else {})
    return api.post(f"/incidents/{inc_id}/{action}", data=data, headers=headers, follow_redirects=False)


def test_clean_start(api):
    kubectl("delete", "-f", FAULTS, "--ignore-not-found", "--wait=true", timeout=180)
    wait_for(lambda: current(api) is None, timeout=150, what="old inspect incident resolved")


def test_silence_pauses_notifications_but_not_detection(api, sink):
    kubectl("apply", "-f", FAULTS)
    inc = wait_for(lambda: current(api), timeout=120, interval=2, what="pending incident")
    assert inc["state"] == "pending"

    rejected = [form(api, inc["id"], "silence", token=False, duration="15m").status_code,
                form(api, inc["id"], "silence", origin="http://evil.example", duration="15m").status_code,
                form(api, inc["id"], "silence", origin=None, duration="15m").status_code]
    kpi("S01", "e2e forged or cross-origin mutations accepted", sum(c != 403 for c in rejected), "count", eq=0)

    assert form(api, inc["id"], "silence", duration="15m").status_code == 303
    firing = wait_for(lambda: (i := current(api)) and i["state"] == "firing" and i, timeout=180, what="firing")
    time.sleep(40)
    kpi("S02", "e2e notifications for a silenced firing incident", len(for_incident(sink, inc["id"], ok_only=False)),
        "count", eq=0)
    d = api.get(f"/api/incidents/{inc['id']}").json()
    assert d["marks"]["silenced_until"]
    assert any(a["kind"] == "silenced" for a in d["activity"])
    assert firing["state"] == "firing", "detection continued during the silence"

    removed = time.time()
    assert form(api, inc["id"], "unsilence").status_code == 303
    (r,) = wait_for(lambda: for_incident(sink, inc["id"], "firing"), timeout=60, what="firing after unsilence")
    kpi("S02", "e2e unsilence to firing notification", r["at"] - removed, "s", max=30)


def test_acknowledge_is_shown_and_keeps_the_incident_open(api):
    inc = current(api)
    assert form(api, inc["id"], "ack").status_code == 303
    row = next(i for i in api.get("/api/incidents").json() if i["id"] == inc["id"])
    assert row["marks"]["acknowledged_at"] and row["state"] == "firing"
    assert "acked" in api.get("/").text
    assert api.get(f"/incidents/{inc['id']}/ack").status_code == 405


def test_cleanup(api):
    kubectl("delete", "-f", FAULTS, "--wait=true", timeout=180)
    wait_for(lambda: current(api) is None, timeout=150, what="inspect incident resolved")
