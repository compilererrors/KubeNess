"""B24: the optional executor with one named action, restart-deployment."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from kubeness.actions import ActionClient, ActionError
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.executor import PatchError, create_executor_app
from kubeness.store import Store
from kubeness.web import create_app

from factories import at, deployment, pod, snap
from kpi_report import kpi
from test_engine import crashloop_status

TOKEN = "executor-token-for-tests"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class Patcher:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def restart(self, namespace, name, at_iso):
        self.calls.append((namespace, name, at_iso))
        if self.fail:
            raise self.fail
        return 7  # generation after the patch


def executor(patcher=None, namespaces=("lab",)):
    patcher = patcher or Patcher()
    return patcher, TestClient(create_executor_app(patcher, lambda: TOKEN, list(namespaces)))


def request(**over):
    return {"id": "act-1", "action": "restart-deployment",
            "params": {"namespace": "lab", "name": "web"}, "incident": "inc-1", **over}


# --- X02 the executor refuses anything but the approved, named action ---------------------------------

@pytest.mark.parametrize("body,headers,code", [
    (request(), {}, 401),
    (request(), {"Authorization": "Bearer nope"}, 401),
    (request(action="delete-deployment"), AUTH, 422),
    (request(action="exec"), AUTH, 422),
    (request(params={"namespace": "kube-system", "name": "coredns"}), AUTH, 403),
    (request(params={"namespace": "lab", "name": "web", "replicas": 0}), AUTH, 422),
    (request(params={"namespace": "lab", "name": "../web"}), AUTH, 422),
    (request(command="rm -rf /"), AUTH, 422),
])
def test_x02_unknown_unauthenticated_or_out_of_scope_requests_are_refused(body, headers, code):
    patcher, c = executor()
    r = c.post("/v1/actions", json=body, headers=headers)
    assert r.status_code == code
    assert patcher.calls == []


def test_x02_kpi_no_patch_for_refused_requests():
    patcher, c = executor()
    for body in (request(action="scale"), request(params={"namespace": "default", "name": "x"})):
        c.post("/v1/actions", json=body, headers=AUTH)
    kpi("X02", "patches for refused action requests", len(patcher.calls), "count", eq=0)


def test_restart_is_executed_and_audited(caplog):
    patcher, c = executor()
    with caplog.at_level("INFO", logger="kubeness.executor"):
        r = c.post("/v1/actions", json=request(), headers=AUTH)
    assert r.status_code == 200 and r.json() == {"status": "executed", "id": "act-1", "generation": 7}
    (ns, name, when) = patcher.calls[0]
    assert (ns, name) == ("lab", "web") and when.endswith("Z")
    audit = [m for m in caplog.messages if "audit" in m]
    assert audit and "act-1" in audit[0] and "restart-deployment" in audit[0] and "inc-1" in audit[0]


def test_patch_failure_is_reported():
    patcher, c = executor(Patcher(fail=PatchError("forbidden")))
    r = c.post("/v1/actions", json=request(), headers=AUTH)
    assert r.status_code == 502 and r.json()["status"] == "failed"


# --- observer side: approval in the UI, request, verification ----------------------------------------

class FakeExecutor:
    def __init__(self, generation=2, error=None):
        self.generation, self.error, self.calls = generation, error, []

    def run(self, action_id, action, params, incident_id):
        self.calls.append((action_id, action, params, incident_id))
        if self.error:
            raise self.error
        return self.generation


def env(enabled=True, client=None):
    cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver"]}, "access": {"profile": "remediate"},
                                 "actions": {"enabled": enabled, "allowed": ["restart-deployment"]}})
    store = Store(":memory:")
    engine = Engine(cfg, store)
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
    (inc,) = store.list_incidents()
    actions = ActionClient(cfg, store, client or FakeExecutor()) if enabled else None
    web = TestClient(create_app(cfg, store, lambda: {"engineRunning": True, "observer": "ok"},
                                clock=lambda: at(300), actions=actions))
    return cfg, store, engine, inc, web, actions


def approve(web, inc, token=True, origin="http://testserver"):
    html = web.get(f"/incidents/{inc.id}").text
    data = {}
    if token:
        data["csrf_token"] = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    return web.post(f"/incidents/{inc.id}/actions/restart-deployment", data=data,
                    headers={"origin": origin} if origin else {}, follow_redirects=False)


def test_action_needs_approval_with_csrf():
    _, store, _, inc, web, actions = env()
    assert approve(web, inc, token=False).status_code == 403
    assert approve(web, inc, origin="http://evil.example").status_code == 403
    assert actions.client.calls == []
    assert approve(web, inc).status_code == 303
    (a,) = store.actions(inc.id)
    assert (a.action, a.status, a.params) == ("restart-deployment", "executed", {"namespace": "lab", "name": "web"})
    assert any(x.kind == "action" for x in store.activity(inc.id))


def test_x03_executed_restart_is_verified_by_a_new_observation():
    _, store, engine, inc, web, _ = env(client=FakeExecutor(generation=2))
    approve(web, inc)
    dep = deployment(generation=2, observed=1)
    engine.tick(snap(at(310), pods=[pod(statuses=[crashloop_status(310)])], deployments=[dep]), at(310))
    assert store.actions(inc.id)[0].status == "executed"
    dep = deployment(generation=2, observed=2)
    engine.tick(snap(at(320), pods=[pod(statuses=[crashloop_status(320)])], deployments=[dep]), at(320))
    (a,) = store.actions(inc.id)
    kpi("X03", "approved restart executed, audited and verified", int(a.status == "verified"), "bool", eq=1)
    assert a.verified_at == at(320)


def test_action_failure_is_recorded():
    _, store, _, inc, web, _ = env(client=FakeExecutor(error=ActionError("executor answered 502: forbidden")))
    assert approve(web, inc).status_code == 303
    (a,) = store.actions(inc.id)
    assert a.status == "failed" and "forbidden" in a.result


def test_actions_disabled_hides_the_button_and_refuses():
    _, _, _, inc, web, _ = env(enabled=False)
    assert "restart-deployment" not in web.get(f"/incidents/{inc.id}").text
    html = web.get(f"/incidents/{inc.id}").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = web.post(f"/incidents/{inc.id}/actions/restart-deployment", data={"csrf_token": token},
                 headers={"origin": "http://testserver"})
    assert r.status_code == 404


def test_only_deployments_can_be_restarted():
    from kubeness.lifecycle import Incident, State
    from kubeness.snapshot import WorkloadRef
    cfg, store, _, _, web, actions = env()
    store.save_incident(Incident("inc-obs", "fp2", "observerDegraded", "lab",
                                 WorkloadRef("Observer", "lab", "observations", "o"), "warning", State.FIRING,
                                 "stale", at(0), at(0)))
    html = web.get("/incidents/inc-obs").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = web.post("/incidents/inc-obs/actions/restart-deployment", data={"csrf_token": token},
                 headers={"origin": "http://testserver"})
    assert r.status_code == 400 and actions.client.calls == []


# --- B31 rollback-deployment --------------------------------------------------------------------------

class RollbackPatcher(Patcher):
    revisions = {1: {"spec": {"containers": [{"name": "app", "image": "web:1.0"}]}}, 2: {}}
    current = 2

    def rollback(self, namespace, name, revision):
        self.calls.append(("rollback", namespace, name, revision))
        if revision not in self.revisions or revision == self.current:
            raise PatchError(f"revision {revision} not found or current")
        return 9


def test_x04_rollback_to_a_previous_revision():
    patcher, c = executor(RollbackPatcher())
    r = c.post("/v1/actions", json=request(action="rollback-deployment",
                                           params={"namespace": "lab", "name": "web", "revision": 1}), headers=AUTH)
    assert r.status_code == 200 and r.json()["generation"] == 9
    kpi("X04", "rollback restores the previous revision", int(patcher.calls == [("rollback", "lab", "web", 1)]),
        "bool", eq=1)


def test_x05_rollback_to_unknown_or_current_revision_is_refused():
    patcher, c = executor(RollbackPatcher())
    codes = [c.post("/v1/actions", json=request(action="rollback-deployment",
                                                params={"namespace": "lab", "name": "web", "revision": rev}),
                    headers=AUTH).status_code for rev in (2, 7)]
    bad = c.post("/v1/actions", json=request(action="rollback-deployment",
                                             params={"namespace": "lab", "name": "web", "revision": "1; rm"}),
                 headers=AUTH).status_code
    refused = sum(code >= 400 for code in codes + [bad])
    kpi("X05", "rollback requests to unknown, current or malformed revisions refused", refused, "count", eq=3)
    missing = c.post("/v1/actions", json=request(action="rollback-deployment",
                                                 params={"namespace": "lab", "name": "web"}), headers=AUTH)
    assert missing.status_code == 422
