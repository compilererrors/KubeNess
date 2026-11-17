"""KPI benchmarks for stage 3 (Notify), simulated."""

from __future__ import annotations

from collections import Counter

from kubeness.config import Config
from kubeness.notify import Sender

from factories import at, pod, running, snap, waiting
from kpi_report import kpi
from test_engine import crashloop_status
from test_notify import FakeClient, events_of, run, setup

ALERTS = {"firing", "reopened", "repeat"}


def test_n04_one_alert_per_incident():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 25 * 60)
    kpi("N04", "alerts for one 25 min crash loop (repeat 30m)", Counter(events_of(store))["firing"], "count", eq=1)


def test_n05_cancelled_pending_is_silent():
    _, store, engine = setup()
    engine.tick(snap(at(0), pods=[pod(statuses=[waiting(reason="ErrImagePull", image_id="")])]), at(0))
    run(engine, lambda t: running(started=at(5)), 10, 120)
    kpi("N05", "notifications for a cancelled pending incident", len(store.notifications()), "count", eq=0)


def test_n06_one_recovery_notification():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 600)
    run(engine, lambda t: running(started=at(600), restarts=5), 600, 1200)
    kpi("N06", "recovery notifications after one fix", Counter(events_of(store))["resolved"], "count", eq=1)


def flapping_image(t: int):
    """Bad image for 80 s of every 180 s: fires at 60 s, resolves 60 s after the fix."""
    if t % 180 < 80:
        return waiting(reason="ImagePullBackOff", image_id="")
    return running(started=at(t - t % 180 + 80))


def test_n07_flapping_is_limited():
    _, store, engine = setup()
    run(engine, flapping_image, 0, 3600)
    c = Counter(events_of(store))
    incidents = {n.incident_id for n in store.notifications()}
    assert len(incidents) == 1
    alerts = sum(c[e] for e in ALERTS)
    assert alerts >= 1 and c["resolved"] >= 1
    kpi("N07", "alerts, 60 min flapping every 3 min (repeat 30m)", alerts, "count", max=2)
    kpi("N07", "recoveries, 60 min flapping every 3 min", c["resolved"], "count", max=2)


def test_n08_repeat_interval():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 65 * 60)
    kpi("N08", "repeat notifications, 65 min firing (repeat 30m)", Counter(events_of(store))["repeat"], "count", eq=2)


def test_n09_escalation():
    _, store, engine = setup({"alarms": {"escalateAfter": "10m"}})
    run(engine, crashloop_status, 0, 30 * 60)
    (inc,) = engine.open.values()
    assert inc.severity == "critical"
    kpi("N09", "escalations after escalateAfter", Counter(events_of(store))["escalated"], "count", eq=1)


def test_n19_no_loss_when_notifier_is_down():
    cfg, store, engine = setup({"notifications": {"backoff": "10s", "backoffMax": "10m"}})
    client = FakeClient(fail_until=at(600))
    sender = Sender(cfg, store, client)
    delivered_at = None
    for t in range(0, 1800, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
        client.now = at(t)
        sender.run_once(at(t))
        if delivered_at is None and client.sent:
            delivered_at = t
    lost = sum(1 for n in store.notifications() if n.status != "provider_accepted")
    kpi("N19", "notifications lost, notifier down 5 min", lost, "count", eq=0)
    kpi("N19", "delivery delay after the notifier is back", delivered_at - 600, "s", max=600)


def test_n20_permanent_failure_stops_at_max_attempts():
    cfg, store, engine = setup({"notifications": {"maxAttempts": 5, "backoff": "1s"}})
    run(engine, crashloop_status, 0, 300)
    sender = Sender(cfg, store, FakeClient(fail_until=True))
    for t in range(300, 300 + 3600, 10):
        sender.run_once(at(t))
    (n,) = store.notifications()
    assert n.status == "failed"
    kpi("N20", "attempts before failed (maxAttempts 5)", n.attempts, "count", eq=5)


def test_n21_delivery_within_one_send_interval():
    cfg, store, engine = setup()
    sender = Sender(cfg, store, FakeClient())
    fired = delivered = None
    for t in range(0, 600, 1):
        if t % 10 == 0:
            for tr in engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t)):
                if tr.kind == "fired":
                    fired = t
        if t % int(cfg.notifications.send_interval.total_seconds()) == 0 and sender.run_once(at(t)):
            delivered = delivered or t
    kpi("N21", "firing to provider_accepted (send interval 2s)", delivered - fired, "s",
        max=cfg.notifications.send_interval.total_seconds())


def test_n23_heartbeats_per_hour():
    cfg = Config.model_validate({"notifications": {"enabled": True, "heartbeatInterval": "5m"}})
    from kubeness.store import Store
    client = FakeClient()
    sender = Sender(cfg, Store(":memory:"), client)
    for t in range(0, 3600, 10):
        sender.heartbeat_once(at(t), observer_ok=True)
    kpi("N23", "heartbeats per hour (interval 5m)", client.heartbeats, "count", min=11, max=13)
