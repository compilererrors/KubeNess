"""B19: info events are collected and sent as one digest per interval, never at once."""

from __future__ import annotations

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.notification import NotificationPayload
from kubeness.notify import NotificationPolicy, Sender
from kubeness.store import Store

from factories import at, deployment, pod, running, snap
from kpi_report import kpi
from test_more_rules import oom_then_running
from test_notify import FakeClient


def setup(interval="1h"):
    cfg = Config.model_validate({"notifications": {"enabled": True, "digestInterval": interval}})
    store = Store(":memory:")
    return cfg, store, Engine(cfg, store, None, None, NotificationPolicy(cfg, store))


def dep_with_image(image):
    d = deployment()
    d["spec"]["template"] = {"spec": {"containers": [{"name": "app", "image": image}]}}
    return d


def healthy_pods(t):
    return [pod(statuses=[running(started=at(-600))])]


def run(engine, start, end, deps=None, pods=healthy_pods):
    for t in range(start, end, 10):
        engine.tick(snap(at(t), pods=pods(t), deployments=deps(t) if deps else None), at(t))


def digests(store):
    return [n for n in store.notifications(digests=True) if n.event == "digest"]


def test_r09_rollout_of_a_new_image_is_digested_not_sent():
    _, store, engine = setup()
    run(engine, 0, 600, deps=lambda t: [dep_with_image("ghcr.io/example/web:1.0" if t < 300 else "ghcr.io/example/web:2.0")])
    kpi("R09", "immediate notifications for a normal rollout", len(store.notifications()), "count", eq=0)
    items = store.digest_items()
    assert [i.kind for i in items] == ["image"]
    assert "ghcr.io/example/web:2.0" in items[0].text and "1.0" in items[0].text


def test_r10_one_digest_per_interval_with_events():
    _, store, engine = setup()
    run(engine, 0, 3700, deps=lambda t: [dep_with_image("web:1" if t < 300 else ("web:2" if t < 900 else "web:3"))])
    sent = digests(store)
    kpi("R10", "digests for one interval with events", len(sent), "count", eq=1)
    p = NotificationPayload.model_validate(sent[0].payload)
    assert p.event == "digest" and p.severity == "info" and len(p.items) == 2
    assert "web:3" in p.text and "web:2" in p.text
    assert store.digest_items() == [], "sent items are cleared"


def test_r11_empty_interval_sends_nothing():
    _, store, engine = setup()
    run(engine, 0, 3 * 3600 + 100)
    kpi("R11", "digests for intervals without events", len(digests(store)), "count", eq=0)


def test_info_incident_and_recurrence_go_to_the_digest():
    _, store, engine = setup()
    run(engine, 0, 1000, pods=lambda t: oom_then_running([100])(t))
    kinds = [i.kind for i in store.digest_items()]
    assert "incident" in kinds
    assert store.notifications() == []


def test_restart_without_incident_is_a_trend_item():
    _, store, engine = setup()

    def pods(t):
        restarts = 1 if t >= 200 else 0
        s = running(started=at(201) if restarts else at(-600), restarts=restarts,
                    last_finished=at(200) if restarts else None)
        return [pod(statuses=[s])]

    run(engine, 0, 600, pods=pods)
    items = [i for i in store.digest_items() if i.kind == "restarts"]
    assert len(items) == 1 and "restarted" in items[0].text


def test_digest_is_delivered_like_other_notifications():
    cfg, store, engine = setup("10m")
    run(engine, 0, 700, deps=lambda t: [dep_with_image("web:1" if t < 100 else "web:2")])
    client = FakeClient()
    sender = Sender(cfg, store, client)
    assert sender.run_once(at(700)) == 1
    assert client.sent[0]["event"] == "digest"
    assert digests(store)[0].status == "provider_accepted"


def test_digest_disabled_with_zero_interval():
    _, store, engine = setup("0s")
    run(engine, 0, 7300, deps=lambda t: [dep_with_image("web:1" if t < 300 else "web:2")])
    assert digests(store) == [] and store.digest_items() == []
