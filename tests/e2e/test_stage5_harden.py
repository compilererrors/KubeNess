"""Stage 5 acceptance: hardening checks that need the running release."""

from __future__ import annotations

import base64
import json
import secrets
import time

from conftest import RELEASE_NS, kubectl, received, wait_for
from kpi_report import kpi

TOKEN_SECRET = "kubeness-notifier-token"


def test_no_endpoint_leaks_masked_secrets(api):
    """H01 against the live store, which holds incidents from the leaky lab faults."""
    pages = ["/", "/api/status", "/api/incidents"]
    ids = [i["id"] for i in api.get("/api/incidents").json()][:40]
    pages += [f"/api/incidents/{i}" for i in ids] + [f"/incidents/{i}" for i in ids]
    leaks = sum("hunter2" in api.get(p).text for p in pages)
    kpi("H01", f"e2e pages returning a masked secret ({len(pages)} pages)", leaks, "count", eq=0)
    for probe in ("/api/secrets", "/api/pods", "/api/namespaces"):
        assert api.get(probe).status_code == 404


def test_rotated_notifier_token_applies_without_restart(api, sink):
    """H02: rotate the shared Secret; kubelet updates both mounts and delivery continues."""
    pods_before = kubectl("-n", RELEASE_NS, "get", "pods", "-o", "jsonpath={.items[*].metadata.uid}").stdout
    new = base64.b64encode(secrets.token_urlsafe(36).encode()).decode()
    rotated = time.time()
    kubectl("-n", RELEASE_NS, "patch", "secret", TOKEN_SECRET, "-p", json.dumps({"data": {"token": new}}))
    beat = wait_for(lambda: [b for b in received(sink, "/heartbeat") if b["at"] > rotated + 5]
                    and api.get("/api/status").json()["notifier"] == "ok", timeout=240, interval=5,
                    what="heartbeat with the rotated token")
    assert beat
    kpi("H02", "e2e rotation to accepted heartbeat", time.time() - rotated, "s", max=240)
    pods_after = kubectl("-n", RELEASE_NS, "get", "pods", "-o", "jsonpath={.items[*].metadata.uid}").stdout
    assert pods_before == pods_after, "no pod was restarted"
