"""B15: acknowledge and silence, with CSRF and Origin checks."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.lifecycle import State
from kubeness.notify import NotificationPolicy
from kubeness.store import Store
from kubeness.web import create_app

from factories import at, pod, running, snap
from kpi_report import kpi
from test_engine import crashloop_status

ORIGIN = {"origin": "http://testserver"}


class Env:
    def __init__(self):
        self.cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver"]}, "notifications": {"enabled": True}})
        self.store = Store(":memory:")
        self.engine = Engine(self.cfg, self.store, None, None, NotificationPolicy(self.cfg, self.store))
        self.now = at(0)
        status = {"observer": "ok", "observerDegraded": "", "engineRunning": True}
        self.client = TestClient(create_app(self.cfg, self.store, lambda: status, clock=lambda: self.now))

    def run(self, start, end, statuses=crashloop_status):
        for t in range(start, end, 10):
            self.now = at(t)
            self.engine.tick(snap(at(t), pods=[pod(statuses=[statuses(t)])]), at(t))

    @property
    def inc(self):
        (inc,) = self.store.list_incidents()
        return inc

    def token(self) -> str:
        html = self.client.get(f"/incidents/{self.inc.id}").text
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, action, data=None, headers=ORIGIN, token=True):
        form = dict(data or {})
        if token:
            form["csrf_token"] = self.token()
        return self.client.post(f"/incidents/{self.inc.id}/{action}", data=form, headers=headers,
                                follow_redirects=False)


@pytest.fixture
def env():
    e = Env()
    e.run(0, 300)
    yield e
    e.store.close()


# --- S01 CSRF and Origin -------------------------------------------------------------------------

def test_s01_mutations_need_token_and_same_origin(env):
    rejected = [
        env.post("ack", token=False).status_code,
        env.client.post(f"/incidents/{env.inc.id}/ack", data={"csrf_token": "forged"}, headers=ORIGIN).status_code,
        env.post("ack", headers={"origin": "http://evil.example"}).status_code,
        env.post("ack", headers={"origin": "null"}).status_code,
        env.post("ack", headers={"referer": "http://evil.example/page"}).status_code,
        env.post("ack", headers={}).status_code,   # neither Origin nor Referer
    ]
    kpi("S01", "forged or cross-origin mutations accepted", sum(c != 403 for c in rejected), "count", eq=0)
    assert env.store.marks(env.inc.id).acknowledged_at is None
    ok = env.post("ack")
    assert ok.status_code == 303 and ok.headers["location"] == f"/incidents/{env.inc.id}"
    assert env.post("ack", headers={"referer": f"http://testserver/incidents/{env.inc.id}"}).status_code == 303


def test_s03_no_get_endpoint_changes_state(env):
    from fastapi.routing import APIRoute
    app = env.client.app
    mutating = [r.path for r in app.routes if isinstance(r, APIRoute) and "POST" in r.methods]
    assert sorted(mutating) == sorted([f"/incidents/{{incident_id}}/{a}" for a in ("ack", "unack", "silence", "unsilence", "ask", "actions/{action}", "troubleshoot")])
    gets = [r.path for r in app.routes if isinstance(r, APIRoute) and "GET" in r.methods]
    kpi("S03", "GET endpoints among the mutating paths", len(set(gets) & set(mutating)), "count", eq=0)
    assert env.client.get(f"/incidents/{env.inc.id}/ack").status_code == 405


# --- acknowledge -------------------------------------------------------------------------------

def test_ack_is_recorded_and_shown(env):
    env.post("ack")
    m = env.store.marks(env.inc.id)
    assert m.acknowledged_at == env.now
    assert "acknowledged" in [a.kind for a in env.store.activity(env.inc.id)]
    assert "acked" in env.client.get("/").text
    assert env.client.get("/api/incidents").json()[0]["marks"]["acknowledged_at"]
    env.post("unack")
    assert env.store.marks(env.inc.id).acknowledged_at is None


def test_s04_ack_and_silence_do_not_touch_the_lifecycle(env):
    before = env.inc
    env.post("ack")
    env.post("silence", {"duration": "1h"})
    after = env.inc
    assert (after.state, after.severity, after.firing_since) == (before.state, before.severity, before.firing_since)
    env.run(300, 600)
    env.run(600, 800, lambda t: running(started=at(600), restarts=5))
    kpi("S04", "lifecycle changes caused by ack or silence", int(env.inc.state is not State.RESOLVED), "count", eq=0)


# --- silence -------------------------------------------------------------------------------------

def test_silence_validates_duration(env):
    assert env.post("silence", {"duration": "7d"}).status_code == 400
    assert env.post("silence", {"duration": ""}).status_code == 400
    assert env.store.marks(env.inc.id).silenced_until is None


def test_s02_silence_pauses_notifications_and_then_resumes(env):
    silenced_at = env.now
    env.post("silence", {"duration": "1h"})
    until = env.store.marks(env.inc.id).silenced_until
    assert until == silenced_at + timedelta(hours=1)
    env.run(300, 300 + 3600)
    during = [n for n in env.store.notifications(env.inc.id) if silenced_at <= n.created_at < until]
    kpi("S02", "notifications created during a 1 h silence", len(during), "count", eq=0)
    assert any("silence" in a.message.lower() for a in env.store.activity(env.inc.id) if a.kind == "notification")
    env.run(300 + 3600, 300 + 3700)
    after = [n for n in env.store.notifications(env.inc.id) if n.created_at >= until]
    assert [n.event for n in after] == ["repeat"], "the still-firing incident is announced again after the silence"


def test_unsilence_resumes_at_once(env):
    env.post("silence", {"duration": "4h"})
    env.run(300, 2000)
    assert [n.event for n in env.store.notifications(env.inc.id)] == ["firing"]
    env.post("unsilence")
    assert env.store.marks(env.inc.id).silenced_until is None
    env.run(2000, 2020)
    assert [n.event for n in env.store.notifications(env.inc.id)] == ["firing", "repeat"]


def test_detail_page_has_forms_not_links(env):
    html = env.client.get(f"/incidents/{env.inc.id}").text
    assert html.count('method="post"') >= 2
    assert 'href="/incidents/' + env.inc.id + '/ack"' not in html


def test_incident_that_fired_during_silence_is_announced_afterwards():
    e = Env()
    e.run(0, 20)                      # pending: not enough restarts yet
    e.post("silence", {"duration": "15m"})
    e.run(20, 15 * 60)                # fires during the silence
    assert e.store.notifications(e.inc.id) == []
    e.run(15 * 60, 15 * 60 + 30)
    assert [n.event for n in e.store.notifications(e.inc.id)] == ["firing"]
