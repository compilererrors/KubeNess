"""B22: negative tests through the application, policy flags and token rotation."""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from kubeness.notify import HttpNotifierClient
from kubeness.web import create_app

from kpi_report import kpi
from test_ask import build
from test_notifier import TOKEN, payload

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "kubeness"
HELM = shutil.which("helm")


def test_h01_no_endpoint_returns_secrets_or_cluster_data():
    cfg, store, _, inc, asker = build()
    client = TestClient(create_app(cfg, store, lambda: {"engineRunning": True, "observer": "ok"}, asker=asker))
    gets = [r.path for r in client.app.routes if isinstance(r, APIRoute) and "GET" in r.methods]
    leaks = 0
    for path in gets:
        body = client.get(path.replace("{incident_id}", inc.id)).text
        leaks += "hunter2" in body
    for probe in ("/api/incidents/..%2F..%2Fetc%2Fpasswd", "/api/secrets", "/api/namespaces", "/api/pods",
                  "/api/incidents/nope", "/incidents/nope"):
        assert client.get(probe).status_code in (404, 405), probe
    kpi("H01", "GET endpoints returning a masked secret", leaks, "count", eq=0)


def test_rule_facts_are_masked_before_they_are_stored():
    """Waiting messages and scheduler text come from the cluster like logs do. They are
    masked before the incident, its evidence or its activity is written."""
    import json

    from kubeness.config import Config
    from kubeness.engine import Engine
    from kubeness.store import Store
    from factories import at, pod, snap
    from test_engine import crashloop_status

    secret = "hunter2-in-a-waiting-message"

    def status(t):
        s = crashloop_status(t)
        if "waiting" in s["state"]:
            s["state"]["waiting"]["message"] = f'exec: "/bin/app --db-password={secret}": not found'
        return s

    cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver"]}})
    store = Store(":memory:")
    engine = Engine(cfg, store)
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[status(t)])]), at(t))
    (inc,) = engine.open.values()
    waiting_messages = [c["waitingMessage"] for e in store.evidence(inc.id) if e.kind == "rule"
                        for c in e.payload["containers"] if c.get("waitingMessage")]
    assert waiting_messages and all("--db-password=[REDACTED]" in m for m in waiting_messages)
    client = TestClient(create_app(cfg, store, lambda: {"engineRunning": True, "observer": "ok"}))
    everything = json.dumps([inc.details, store.get_incident(inc.id).details,
                             [e.payload for e in store.evidence(inc.id)],
                             [a.message for a in store.activity(inc.id)]])
    everything += client.get(f"/api/incidents/{inc.id}").text + client.get(f"/incidents/{inc.id}").text
    assert secret not in everything


def test_the_ui_binds_loopback_outside_a_cluster(monkeypatch, tmp_path):
    from kubeness import __main__ as main
    from kubeness.__main__ import bind_host
    from kubeness.config import Config

    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setattr(main, "CONTAINER_MARKERS", (str(tmp_path / "absent"),))
    assert bind_host(Config()) == "127.0.0.1"
    assert bind_host(Config.model_validate({"ui": {"host": "0.0.0.0"}})) == "0.0.0.0"
    marker = tmp_path / ".dockerenv"
    marker.touch()
    monkeypatch.setattr(main, "CONTAINER_MARKERS", (str(marker),))
    assert bind_host(Config()) == "0.0.0.0", "a published container port reaches the UI"
    monkeypatch.setattr(main, "CONTAINER_MARKERS", (str(tmp_path / "absent"),))
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    assert bind_host(Config()) == "0.0.0.0", "kubelet probes reach the pod by its IP"
    assert bind_host(Config.model_validate({"ui": {"host": "127.0.0.1"}})) == "127.0.0.1"


def test_web_and_notifier_have_no_kubernetes_client():
    """Only the observer's watcher and collector talk to the API; the UI and the
    notifier cannot, whatever a request asks for."""
    for module in ("web.py", "notifier.py", "notify.py", "ask.py", "notification.py"):
        tree = ast.parse((SRC / module).read_text())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                 for a in getattr(n, "names", [])} | {
                (n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert "kubernetes" not in names, module


@pytest.mark.skipif(HELM is None, reason="helm not installed")
@pytest.mark.parametrize("flag", ["access.readSecrets=true", "access.exec=true", "actions.enabled=true"])
def test_unsupported_access_flags_fail_the_install(flag):
    r = subprocess.run([HELM, "template", "cb", str(ROOT / "charts" / "kubeness"), "--set", flag],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "not supported" in r.stderr


def test_h02_rotated_token_applies_without_restart(tmp_path):
    from test_notifier import Recorder
    import socket
    import threading
    import time
    import uvicorn
    from kubeness.notifier import create_notifier_app

    secret = tmp_path / "notifier-token"
    secret.write_text(TOKEN)
    provider = Recorder()
    app = create_notifier_app(provider, None, lambda: secret.read_text().strip())
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.05)
    try:
        client = HttpNotifierClient(url, secret)      # observer and notifier mount the same Secret
        assert client.send(payload(), timeout=5) == "provider_accepted"
        secret.write_text("rotated-" + TOKEN)
        sends_until_ok = 1 if client.send(payload(), timeout=5) == "provider_accepted" else 99
        kpi("H02", "sends until a rotated token applies", sends_until_ok, "count", max=1)
    finally:
        server.should_exit = True
        t.join(timeout=5)
