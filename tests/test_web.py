import pytest
from fastapi.testclient import TestClient

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.store import Store
from kubeness.web import create_app

from factories import at, event, pod, snap, waiting


@pytest.fixture
def setup():
    cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver", "127.0.0.1"]}})
    store = Store(":memory:")
    engine = Engine(cfg, store)
    events = [event("Failed", "<script>alert(1)</script> manifest unknown", "web-abc-1", at(1), "ev1")]
    for t in range(0, 80, 10):
        st = waiting(reason="ImagePullBackOff", message="manifest unknown", image_id="")
        engine.tick(snap(at(t), pods=[pod(statuses=[st])], events=events), at(t))
    status = {"observer": "ok", "observerDetail": "all sources fresh", "engineRunning": True}
    client = TestClient(create_app(cfg, store, lambda: status))
    yield client, store
    store.close()


def test_list_and_detail_render(setup):
    client, store = setup
    (inc,) = store.list_incidents()
    r = client.get("/")
    assert r.status_code == 200
    assert "lab/web" in r.text and "firing" in r.text
    r = client.get(f"/incidents/{inc.id}")
    assert r.status_code == 200
    assert "e2" in r.text
    # Event text comes from the cluster and must be escaped.
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_auto_refresh_spares_a_half_written_question(setup):
    """The reload is scripted so it can skip a form that is in use; the unconditional
    meta refresh, which wiped the question field every 15 seconds, is the no-script fallback only."""
    client, store = setup
    (inc,) = store.list_incidents()
    for page in (client.get("/").text, client.get(f"/incidents/{inc.id}").text):
        head = page.split("</head>")[0]
        assert head.count('http-equiv="refresh"') == 1
        assert '<noscript><meta http-equiv="refresh" content="15"></noscript>' in head
        assert "location.reload()" in head and "activeElement" in head


def test_json_api(setup):
    client, store = setup
    (inc,) = store.list_incidents()
    data = client.get(f"/api/incidents/{inc.id}").json()
    assert data["incident"]["state"] == "firing"
    assert [e["ref"] for e in data["evidence"]] == ["e1", "e2"]
    assert client.get("/api/incidents/nope").status_code == 404


def test_foreign_host_is_rejected_but_probes_work(setup):
    client, _ = setup
    assert client.get("/", headers={"host": "evil.example:8080"}).status_code == 403
    assert client.get("/api/incidents", headers={"host": "evil.example"}).status_code == 403
    assert client.get("/healthz", headers={"host": "10.244.0.7:8080"}).status_code == 200
    assert client.get("/", headers={"host": "127.0.0.1:8080"}).status_code == 200


# --- B11 notification status -------------------------------------------------------------------

@pytest.fixture
def notified():
    from kubeness.notify import NotificationPolicy, Sender
    from test_notify import FakeClient

    cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver"]}, "notifications": {"enabled": True}})
    store = Store(":memory:")
    engine = Engine(cfg, store, None, None, NotificationPolicy(cfg, store))
    for t in range(0, 80, 10):
        st = waiting(reason="ImagePullBackOff", message="manifest unknown", image_id="")
        engine.tick(snap(at(t), pods=[pod(statuses=[st])]), at(t))
    sender = Sender(cfg, store, FakeClient())
    status = {"observer": "ok", "observerDetail": "ok", "engineRunning": True, **sender.status()}
    client = TestClient(create_app(cfg, store, lambda: status))
    yield client, store, sender
    store.close()


def test_notification_status_in_list_and_api(notified):
    client, store, sender = notified
    (inc,) = store.list_incidents()
    assert client.get("/api/incidents").json()[0]["notification"]["status"] == "queued"
    assert "queued" in client.get("/").text
    sender.run_once(at(100))
    row = client.get("/api/incidents").json()[0]["notification"]
    assert (row["status"], row["event"]) == ("provider_accepted", "firing")
    assert "provider_accepted" in client.get("/").text
    detail = client.get(f"/api/incidents/{inc.id}").json()
    assert [n["status"] for n in detail["notifications"]] == ["provider_accepted"]
    html = client.get(f"/incidents/{inc.id}").text
    assert "Notifications" in html and inc.id + ":firing:0" in html


def test_notifier_indicator_and_disabled_state(notified, setup):
    client, _, _ = notified
    assert "notifier unknown" in client.get("/").text
    plain, _ = setup
    assert "notifier disabled" in plain.get("/").text
    assert "not configured" in plain.get("/").text
