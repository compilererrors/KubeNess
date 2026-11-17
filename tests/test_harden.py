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
