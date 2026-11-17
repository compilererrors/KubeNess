"""Stage 3 (Notify), observer side: outbox, policy, payload, sender and heartbeat."""

from __future__ import annotations

import json
import threading
import time


from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.notification import NotificationPayload
from kubeness.notify import DeliveryError, NotificationPolicy, Sender
from kubeness.store import OutboxItem, Store

from factories import at, event, pod, running, snap, waiting
from test_diagnose import FakeLogs
from test_engine import crashloop_status

INTERVAL = 10


def setup(over: dict | None = None, logs=None):
    data = {"notifications": {"enabled": True}}
    for k, v in (over or {}).items():
        data[k] = {**data.get(k, {}), **v}
    cfg = Config.model_validate(data)
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, logs or FakeLogs()), None, NotificationPolicy(cfg, store))
    return cfg, store, engine


def run(engine, statuses_at, start, end, events=None):
    for t in range(start, end, INTERVAL):
        engine.tick(snap(at(t), pods=[pod(statuses=[statuses_at(t)])], events=events), at(t))


def events_of(store):
    return [n.event for n in sorted(store.notifications(), key=lambda n: n.created_at)]


class FakeClient:
    def __init__(self, fail_until=None, error="provider returned 503", delay=0.0):
        self.fail_until, self.error, self.delay = fail_until, error, delay
        self.sent: list[dict] = []
        self.heartbeats = 0
        self.now = None

    def send(self, payload: dict, timeout: float) -> str:
        if self.delay:
            time.sleep(self.delay)
        if self.fail_until is True or (self.fail_until is not None and self.now < self.fail_until):
            raise DeliveryError(self.error)
        self.sent.append(payload)
        return "provider_accepted"

    def heartbeat(self, timeout: float) -> str:
        self.heartbeats += 1
        return "provider_accepted"


# --- B04 outbox ------------------------------------------------------------------------------

def with_incident(store):
    from kubeness.lifecycle import Incident, State
    from kubeness.snapshot import WorkloadRef
    store.save_incident(Incident("inc-1", "fp", "restarts", "lab", WorkloadRef("Deployment", "lab", "web", "u1"),
                                 "warning", State.FIRING, "r", at(0), at(0)))
    return store


def item(n="inc-1:firing:0", status="queued"):
    return OutboxItem(id=n, incident_id="inc-1", event="firing", created_at=at(0), status=status, attempts=0,
                      next_attempt_at=at(0), last_error=None, accepted_at=None, payload={"id": n})


def test_outbox_enqueue_is_idempotent():
    store = with_incident(Store(":memory:"))
    assert store.enqueue_notification(item()) is True
    assert store.enqueue_notification(item()) is False
    assert len(store.notifications()) == 1


def test_outbox_sending_is_retried_after_restart(tmp_path):
    path = tmp_path / "db.sqlite"
    store = with_incident(Store(path))
    store.enqueue_notification(item("a"))
    store.enqueue_notification(item("b"))
    store.update_notification("b", status="sending")
    store.close()

    reopened = Store(path)
    assert reopened.recover_sending(at(5)) == 1
    by_id = {n.id: n for n in reopened.notifications()}
    assert by_id["a"].status == "queued"
    assert by_id["b"].status == "retry_scheduled" and by_id["b"].next_attempt_at == at(5)
    assert {n.id for n in reopened.due_notifications(at(5))} == {"a", "b"}


# --- B05 policy ------------------------------------------------------------------------------

def test_policy_fired_then_resolved():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 600)
    run(engine, lambda t: running(started=at(600), restarts=5), 600, 800)
    assert events_of(store) == ["firing", "resolved"]
    ids = [n.id for n in store.notifications()]
    inc_id = store.notifications()[0].incident_id
    assert sorted(ids) == sorted([f"{inc_id}:firing:0", f"{inc_id}:resolved:0"])


def test_policy_pending_that_is_cancelled_is_silent():
    _, store, engine = setup()
    engine.tick(snap(at(0), pods=[pod(statuses=[waiting(reason="ErrImagePull", image_id="")])]), at(0))
    run(engine, lambda t: running(started=at(5)), 10, 60)
    assert store.notifications() == []


def test_policy_relapse_during_recovery_is_silent():
    _, store, engine = setup()
    run(engine, lambda t: crashloop_status(t, run_for=40), 0, 25 * 60)
    (inc,) = engine.open.values()
    assert inc.flap_count >= 1
    assert events_of(store) == ["firing"]


def test_policy_disabled_queues_nothing():
    cfg = Config()
    store = Store(":memory:")
    engine = Engine(cfg, store, None, None, NotificationPolicy(cfg, store))
    run(engine, crashloop_status, 0, 600)
    assert store.notifications() == []


def test_policy_records_activity():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 300)
    (inc,) = engine.open.values()
    kinds = [a.kind for a in store.activity(inc.id)]
    assert "notification" in kinds


# --- B06 payload -------------------------------------------------------------------------------

SECRET_LOG = (
    "starting\npassword=hunter2\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3\n"
    "fatal: unique-log-marker-7731 token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
)
LEAKS = ["hunter2", "eyJhbGci", "ghp_abcdefghij", "unique-log-marker-7731", "s3cr3t"]


def all_payload_text(store) -> str:
    return json.dumps([n.payload for n in store.notifications()])


def test_payload_has_fixed_fields_and_hypothesis_label():
    _, store, engine = setup()
    run(engine, crashloop_status, 0, 300)
    (n,) = store.notifications()
    p = NotificationPayload.model_validate(n.payload)
    assert (p.event, p.severity, p.rule, p.namespace) == ("firing", "warning", "restarts", "lab")
    assert p.workload == "Deployment/web" and p.possible_cause and p.next_check
    assert "Possible cause (hypothesis):" in p.text
    assert p.incident in p.text and "[WARNING]" in p.text


def test_payload_never_carries_secrets_or_raw_logs():
    msg = "pull failed: postgres://app:s3cr3t@db/x password=hunter2"
    _, store, engine = setup(logs=FakeLogs(text=SECRET_LOG))
    events = [event("BackOff", msg, "web-abc-1", at(20), "ev1")]
    run(engine, crashloop_status, 0, 600, events=events)
    run(engine, lambda t: running(started=at(600), restarts=5), 600, 800)
    # An image pull incident whose waiting message carries a credential.
    engine.tick(snap(at(900), pods=[pod(statuses=[waiting(reason="ErrImagePull", message=msg, image_id="")])]), at(900))
    for t in range(910, 1000, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[waiting(reason="ImagePullBackOff", message=msg, image_id="")])]),
                    at(t))
    text = all_payload_text(store)
    assert len(store.notifications()) == 3
    assert [leak for leak in LEAKS if leak in text] == []


def test_payload_is_bounded():
    long_image = "registry.example.com/" + "a" * 5000 + ":1"
    _, store, engine = setup()
    for t in range(0, 100, 10):
        st = waiting(reason="ImagePullBackOff", message="x" * 5000, image_id="")
        engine.tick(snap(at(t), pods=[pod(statuses=[st], image=long_image)]), at(t))
    (n,) = store.notifications()
    assert len(json.dumps(n.payload).encode()) <= 4096
    NotificationPayload.model_validate(n.payload)


def test_payload_uses_template_not_model_text():
    cfg, store, engine = setup()
    run(engine, crashloop_status, 0, 100)
    (inc,) = engine.open.values()
    store.add_analysis(inc.id, at(100), "model", "ok", {
        "summary": "MODEL SAYS SOMETHING", "observed_facts": [], "possible_causes": [
            {"text": "MODEL CAUSE", "evidence_refs": ["e1"]}], "next_checks": ["MODEL CHECK"],
        "missing_information": []})
    run(engine, crashloop_status, 100, 300)
    assert "MODEL" not in all_payload_text(store)


# --- B09 sender ----------------------------------------------------------------------------------

def firing_setup(**notif):
    cfg, store, engine = setup({"notifications": notif} if notif else None)
    run(engine, crashloop_status, 0, 300)
    (n,) = store.notifications()
    return cfg, store, n


def test_sender_delivers_and_records_activity():
    cfg, store, n = firing_setup()
    client = FakeClient()
    sender = Sender(cfg, store, client)
    assert sender.run_once(at(300)) == 1
    (sent,) = store.notifications()
    assert sent.status == "provider_accepted" and sent.accepted_at == at(300) and sent.attempts == 1
    assert client.sent[0]["id"] == n.id
    assert any(a.kind == "notification" and "accepted" in a.message for a in store.activity(n.incident_id))
    assert sender.status()["notifier"] == "ok"


def test_sender_backs_off_exponentially():
    cfg, store, n = firing_setup(backoff="10s", backoffMax="10m")
    client = FakeClient(fail_until=True)
    sender = Sender(cfg, store, client)
    sender.run_once(at(300))
    (r,) = store.notifications()
    assert (r.status, r.attempts, r.next_attempt_at) == ("retry_scheduled", 1, at(310))
    assert sender.run_once(at(305)) == 0
    sender.run_once(at(310))
    (r,) = store.notifications()
    assert (r.attempts, r.next_attempt_at, r.last_error) == (2, at(330), "provider returned 503")
    assert sender.status()["notifier"] == "unavailable"


def test_sender_gives_up_after_max_attempts():
    cfg, store, n = firing_setup(maxAttempts=3, backoff="1s")
    sender = Sender(cfg, store, FakeClient(fail_until=True))
    t = 300
    for _ in range(10):
        sender.run_once(at(t))
        t += 600
    (r,) = store.notifications()
    assert (r.status, r.attempts) == ("failed", 3)
    assert any("failed after 3 attempts" in a.message for a in store.activity(n.incident_id))


def test_sender_start_recovers_interrupted_sends():
    cfg, store, n = firing_setup()
    store.update_notification(n.id, status="sending")
    sender = Sender(cfg, store, FakeClient())
    sender.recover(at(400))
    assert sender.run_once(at(400)) == 1


def test_rule_loop_never_waits_for_the_notifier():
    cfg, store, engine = setup({"notifications": {"sendInterval": "1s"}})
    stop = threading.Event()
    sender = Sender(cfg, store, FakeClient(delay=3))
    sender.start(stop, lambda: True)
    try:
        start = time.perf_counter()
        run(engine, crashloop_status, 0, 600)
        elapsed = time.perf_counter() - start
    finally:
        stop.set()
    assert store.notifications()
    assert elapsed < 2, f"rule loop took {elapsed:.1f}s with a hanging notifier"


# --- B10 heartbeat -------------------------------------------------------------------------------

def test_heartbeat_only_while_observer_is_ok():
    cfg = Config.model_validate({"notifications": {"enabled": True, "heartbeatInterval": "5m"}})
    store = Store(":memory:")
    client = FakeClient()
    sender = Sender(cfg, store, client)
    for t in range(0, 3600, 10):
        sender.heartbeat_once(at(t), observer_ok=True)
    assert client.heartbeats == 12
    for t in range(3600, 7200, 10):
        sender.heartbeat_once(at(t), observer_ok=False)
    assert client.heartbeats == 12


def test_heartbeat_disabled_by_default():
    cfg = Config.model_validate({"notifications": {"enabled": True}})
    client = FakeClient()
    sender = Sender(cfg, Store(":memory:"), client)
    sender.heartbeat_once(at(0), observer_ok=True)
    assert client.heartbeats == 0


def test_heartbeat_success_clears_a_heartbeat_failure_but_not_a_delivery_failure():
    cfg = Config.model_validate({"notifications": {"enabled": True, "heartbeatInterval": "30s"}})

    class Flaky(FakeClient):
        def __init__(self):
            super().__init__()
            self.down = True

        def heartbeat(self, timeout):
            if self.down:
                raise DeliveryError("notifier unreachable: ConnectError")
            return super().heartbeat(timeout)

    client = Flaky()
    sender = Sender(cfg, Store(":memory:"), client)
    sender.heartbeat_once(at(0), observer_ok=True)          # notifier not up yet
    assert sender.status()["notifier"] == "unavailable"
    client.down = False
    sender.heartbeat_once(at(10), observer_ok=True)
    assert sender.status()["notifier"] == "ok"

    sender._set_failure("delivery", "provider answered 503")
    sender.heartbeat_once(at(60), observer_ok=True)
    assert sender.status()["notifier"] == "unavailable"     # deliveries are still failing
