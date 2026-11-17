"""Stage 3 (Notify), notifier side: auth, schema, provider_accepted, webhook and ntfy."""

from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from kubeness.notification import NotificationPayload, render_text
from kubeness.notifier import (
    HeartbeatPing, NotifierConfig, NtfyProvider, ProviderError, WebhookProvider, create_notifier_app,
)
from kubeness.notify import DeliveryError, HttpNotifierClient

from factories import at
from kpi_report import kpi, timed_kpi

TOKEN = "t0ken-for-tests-only"


def payload(**over) -> dict:
    p = NotificationPayload(
        id="inc-20261115-abc123:firing:0", event="firing", severity="warning", incident="inc-20261115-abc123",
        cluster="lab", namespace="lab", workload="Deployment/web", rule="restarts", state="firing",
        observed="Container app is in CrashLoopBackOff", possible_cause="The application exits on an error.",
        next_check="Fix the error from the previous log.", missing=[], first_seen=at(0), last_observed=at(60),
        text="-",
    )
    p.text = render_text(p)
    return {**p.wire(), **over}


class Recorder:
    """Provider double: records calls, optionally fails."""

    def __init__(self, fail: Exception | None = None):
        self.fail, self.calls = fail, []

    def send(self, p: NotificationPayload) -> None:
        self.calls.append(p)
        if self.fail:
            raise self.fail


def app(provider=None, heartbeat=None, token=TOKEN):
    provider = provider or Recorder()
    return provider, TestClient(create_notifier_app(provider, heartbeat, lambda: token))


AUTH = {"Authorization": f"Bearer {TOKEN}"}


# --- B07 service -------------------------------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}])
def test_notify_requires_the_shared_token(headers):
    provider, c = app()
    r = c.post("/v1/notify", json=payload(), headers=headers)
    assert r.status_code == 401
    assert provider.calls == []


def test_empty_configured_token_rejects_everything():
    provider, c = app(token="")
    assert c.post("/v1/notify", json=payload(), headers={"Authorization": "Bearer "}).status_code == 401
    assert provider.calls == []


@pytest.mark.parametrize("bad", [
    {"url": "https://attacker.example/hook"},          # destination never comes from the payload
    {"recipients": ["someone@example.com"]},
    {"text": "x" * 5000},
    {"severity": "emergency"},
    {"id": "inc 1; rm -rf"},
])
def test_unknown_or_invalid_fields_are_rejected(bad):
    provider, c = app()
    r = c.post("/v1/notify", json=payload(**bad), headers=AUTH)
    assert r.status_code == 422
    assert provider.calls == []


def test_accepted_only_after_the_provider_accepts():
    provider, c = app()
    r = c.post("/v1/notify", json=payload(), headers=AUTH)
    assert r.status_code == 200 and r.json() == {"status": "provider_accepted", "id": payload()["id"]}
    assert len(provider.calls) == 1


@pytest.mark.parametrize("err", [ProviderError("provider answered 503"), ProviderError("provider timeout")])
def test_provider_failure_is_reported_not_accepted(err):
    provider, c = app(Recorder(fail=err))
    r = c.post("/v1/notify", json=payload(), headers=AUTH)
    assert r.status_code == 502
    assert r.json()["status"] == "provider_error"
    assert "provider_accepted" not in r.text


def test_notifier_masks_again():
    provider, c = app()
    c.post("/v1/notify", json=payload(observed="db password=hunter2", text="token=zq9leak77 failed"), headers=AUTH)
    (p,) = provider.calls
    assert "hunter2" not in p.model_dump_json() and "zq9leak77" not in p.model_dump_json()


def test_healthz_needs_no_token():
    _, c = app()
    assert c.get("/healthz").status_code == 200


def test_heartbeat_is_forwarded_or_disabled():
    hb = Recorder()
    _, c = app(heartbeat=hb)
    assert c.post("/v1/heartbeat", headers=AUTH).json() == {"status": "provider_accepted"}
    assert len(hb.calls) == 1
    assert c.post("/v1/heartbeat").status_code == 401
    _, c = app(heartbeat=None)
    assert c.post("/v1/heartbeat", headers=AUTH).json() == {"status": "disabled"}


def test_n16_notifier_latency():
    _, c = app()
    body = payload()
    timed_kpi("N16", "notifier latency p95, fast provider", lambda: c.post("/v1/notify", json=body, headers=AUTH), 50,
              warmup=5, max=50)


# --- B08 providers ---------------------------------------------------------------------------------

def capture(status=200):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status)

    return seen, httpx.MockTransport(handler)


def test_webhook_posts_the_fixed_payload_with_a_stable_id():
    seen, transport = capture()
    p = NotificationPayload.model_validate(payload())
    WebhookProvider("https://hooks.example/abc", timeout=5, transport=transport).send(p)
    (req,) = seen
    assert req.method == "POST" and str(req.url) == "https://hooks.example/abc"
    assert json.loads(req.content) == p.wire()
    assert req.headers["X-Kubeness-Notification-Id"] == p.id
    kpi("N18", "webhook carries the stable notification id", 100 * (req.headers["X-Kubeness-Notification-Id"] == p.id),
        "%", eq=100)


def test_webhook_non_2xx_is_a_provider_error():
    _, transport = capture(500)
    with pytest.raises(ProviderError, match="500"):
        WebhookProvider("https://hooks.example/abc", timeout=5, transport=transport).send(
            NotificationPayload.model_validate(payload()))


@pytest.mark.parametrize("severity,event,priority", [
    ("critical", "firing", "5"), ("warning", "firing", "4"), ("info", "firing", "3"), ("warning", "resolved", "2"),
])
def test_ntfy_format_and_priority(severity, event, priority):
    seen, transport = capture()
    p = NotificationPayload.model_validate(payload(severity=severity, event=event))
    NtfyProvider("https://ntfy.example/kubeness-topic", token="tk_123", timeout=5, transport=transport).send(p)
    (req,) = seen
    assert req.content.decode() == p.text
    assert req.headers["Priority"] == priority
    assert req.headers["Title"].startswith("[")
    assert req.headers["Authorization"] == "Bearer tk_123"
    assert req.headers["Tags"]
    kpi("N17", f"ntfy priority for {severity}/{event}", int(req.headers["Priority"]), "", eq=int(priority))


def test_ntfy_title_survives_non_latin1_names():
    seen, transport = capture()
    p = NotificationPayload.model_validate(payload(workload="Deployment/webb-åäö-🚀"))
    NtfyProvider("https://ntfy.example/t", token=None, timeout=5, transport=transport).send(p)
    assert "Authorization" not in seen[0].headers


def test_heartbeat_ping():
    seen, transport = capture()
    HeartbeatPing("https://hc.example/ping/uuid", timeout=5, transport=transport).send(None)
    assert seen[0].method == "POST"


def test_config_reads_destination_from_files(tmp_path):
    d = tmp_path / "dest"
    d.mkdir()
    (d / "url").write_text("https://ntfy.example/topic\n")
    (d / "token").write_text("tk_9\n")
    (tmp_path / "token").write_text(TOKEN)
    cfg = NotifierConfig.model_validate({"provider": "ntfy", "destinationDir": str(d), "tokenFile": str(tmp_path / "token")})
    provider, heartbeat = cfg.build()
    assert isinstance(provider, NtfyProvider) and provider.url == "https://ntfy.example/topic" and provider.token == "tk_9"
    assert heartbeat is None
    assert cfg.read_token() == TOKEN


# --- observer client against a real notifier over HTTP ------------------------------------------

@pytest.fixture
def live_notifier(tmp_path):
    provider = Recorder()
    server = uvicorn.Server(uvicorn.Config(create_notifier_app(provider, None, lambda: TOKEN), host="127.0.0.1",
                                           port=0, log_level="warning"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    token = tmp_path / "token"
    token.write_text(TOKEN + "\n")
    yield provider, f"http://127.0.0.1:{port}", token
    server.should_exit = True
    t.join(timeout=5)


def test_observer_client_roundtrip(live_notifier):
    provider, url, token = live_notifier
    client = HttpNotifierClient(url, token)
    assert client.send(payload(), timeout=5) == "provider_accepted"
    assert provider.calls[0].id == payload()["id"]
    assert client.heartbeat(timeout=5) == "disabled"


def test_observer_client_errors(live_notifier, tmp_path):
    provider, url, token = live_notifier
    bad = tmp_path / "bad"
    bad.write_text("nope")
    with pytest.raises(DeliveryError, match="401") as e:
        HttpNotifierClient(url, bad).send(payload(), timeout=5)
    assert not e.value.permanent
    with pytest.raises(DeliveryError, match="422") as e:
        HttpNotifierClient(url, token).send(payload(extra="x"), timeout=5)
    assert e.value.permanent
    with pytest.raises(DeliveryError, match="unreachable"):
        HttpNotifierClient("http://127.0.0.1:1", token).send(payload(), timeout=2)
    with pytest.raises(DeliveryError, match="token unavailable"):
        HttpNotifierClient(url, tmp_path / "missing").send(payload(), timeout=2)
