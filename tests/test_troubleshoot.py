"""B29/B30: experimental troubleshooting by the model with read-only tools, and fix proposals."""

from __future__ import annotations

import json

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.store import Store
from kubeness.troubleshoot import Troubleshooter

from factories import at, deployment, event, pod, replicaset, snap
from kpi_report import kpi
from test_diagnose import FakeLogs
from test_engine import crashloop_status

SECRET_ENV = "s3cr3t-db-pass"


class Scripted:
    """Replies with one scripted step per call and records what it was shown."""

    def __init__(self, steps):
        self.steps, self.calls, self.last_thinking = list(steps), [], ""

    def chat(self, messages, schema, timeout):
        self.calls.append(messages)
        self.last_thinking = "I should look at the logs first."
        step = self.steps.pop(0) if self.steps else {"tool": "finish", "args": {"summary": "out of script"}}
        return json.dumps(step)

    def available(self, timeout):
        return True, "ok"


def workload_objects(t):
    p = pod(statuses=[crashloop_status(t)])
    p["spec"]["containers"][0]["env"] = [{"name": "DB_PASSWORD", "value": SECRET_ENV},
                                         {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]
    p["metadata"]["labels"] = {"app": "web"}
    rs_old = replicaset("web-old", "rs-old")
    rs_old["metadata"]["annotations"] = {"deployment.kubernetes.io/revision": "1"}
    rs_old["spec"] = {"replicas": 0, "template": {"spec": {"containers": [{"name": "app", "image": "web:1.0"}]}}}
    rs_new = replicaset()
    rs_new["metadata"]["annotations"] = {"deployment.kubernetes.io/revision": "2"}
    rs_new["spec"] = {"replicas": 1, "template": {"spec": {"containers": [{"name": "app", "image": "web:2.0"}]}}}
    other = pod("other-1", "pod-other", owner={"kind": "ReplicaSet", "name": "x", "uid": "rs-x", "controller": True})
    return dict(pods=[p, other], replicasets=[rs_old, rs_new], deployments=[deployment()],
                events=[event("BackOff", "Back-off restarting failed container app", "web-abc-1", at(20), "ev1")])


def setup(steps, profile="remediate", think=True, propose=True, max_steps=4):
    cfg = Config.model_validate({
        "access": {"profile": profile},
        "actions": {"enabled": True, "allowed": ["restart-deployment", "rollback-deployment"]},
        "experimental": {"troubleshoot": {"enabled": True, "maxSteps": max_steps, "think": think,
                                          "proposeFixes": propose}}})
    store = Store(":memory:")
    logs = FakeLogs(text=f"starting\nusing DB_PASSWORD={SECRET_ENV}\nfatal: config file /etc/app/config.yaml missing\n")
    engine = Engine(cfg, store, LogCollector(cfg, logs))
    last = {}
    for t in range(0, 300, 10):
        last = workload_objects(t)
        engine.tick(snap(at(t), **last), at(t))
    (inc,) = [i for i in store.list_incidents() if i.workload.name == "web"]
    model = Scripted(steps)
    ts = Troubleshooter(cfg, store, model, lambda: snap(at(300), **last), logs)
    return cfg, store, inc, model, ts, logs


GOOD = [
    {"tool": "logs", "args": {"pod": "web-abc-1", "container": "app", "previous": True}, "note": "read the crash"},
    {"tool": "describe", "args": {"kind": "pod", "name": "web-abc-1"}, "note": "check config"},
    {"tool": "rolloutHistory", "args": {}, "note": "did a rollout start this?"},
    {"tool": "finish", "args": {
        "summary": "The new revision cannot find its config file.",
        "findings": [{"text": "The log ends with a missing config file.", "evidence_refs": ["LOG"]},
                     {"text": "Invented finding.", "evidence_refs": ["e999"]}],
        "fix": {"action": "rollback-deployment", "reason": "Revision 1 ran before the change.",
                "evidence_refs": ["ROLLOUT"]}}},
]


def resolve_refs(steps, store, inc):
    """The scripted model cites evidence created during the run; fill in their refs."""
    return steps


def test_a_grounded_investigation_with_thinking_and_a_fix_proposal():
    cfg, store, inc, model, ts, _ = setup([])
    n0 = store.next_evidence_index(inc.id)
    steps = json.loads(json.dumps(GOOD).replace("LOG", f"e{n0}").replace("ROLLOUT", f"e{n0 + 2}"))
    model.steps = steps
    inv = ts.run(inc.id, at(310))
    assert inv.status == "done" and len(inv.steps) == 4
    assert [s["tool"] for s in inv.steps] == ["logs", "describe", "rolloutHistory", "finish"]
    assert all(s["status"] == "ok" for s in inv.steps)
    assert inv.steps[0]["thinking"] == "I should look at the logs first."
    kinds = [e.kind for e in store.evidence(inc.id)][-3:]
    assert kinds == ["log", "describe", "rollout"]
    c = inv.conclusion
    assert [f["text"] for f in c["findings"]] == ["The log ends with a missing config file."]
    kpi("T02", "shown troubleshooting findings without a valid ref",
        sum(1 for f in c["findings"] if not f["evidence_refs"]), "count", eq=0)
    assert c["fix"] == {"action": "rollback-deployment", "params": {"namespace": "lab", "name": "web", "revision": 1},
                        "reason": "Revision 1 ran before the change.", "evidence_refs": [f"e{n0 + 2}"]}
    assert store.actions(inc.id) == [], "a proposal is never executed by itself"


def test_t01_out_of_scope_tool_calls_are_refused():
    hostile = [
        {"tool": "logs", "args": {"pod": "other-1", "container": "app"}, "note": "another workload"},
        {"tool": "describe", "args": {"kind": "secret", "name": "db"}, "note": "read a secret"},
        {"tool": "describe", "args": {"kind": "deployment", "name": "coredns"}, "note": "other deployment"},
        {"tool": "exec", "args": {"command": "cat /etc/shadow"}, "note": "not a tool"},
    ]
    _, store, inc, _, ts, logs = setup(hostile)
    calls_before = len(logs.calls)
    inv = ts.run(inc.id, at(310))
    executed = sum(1 for s in inv.steps if s["status"] == "ok")
    kpi("T01", "out-of-scope tool calls executed", executed, "count", eq=0)
    assert len(logs.calls) == calls_before
    assert all(s["status"] == "refused" for s in inv.steps)


def test_logs_tool_follows_the_silo_profile():
    _, _, inc, _, ts, logs = setup([{"tool": "logs", "args": {"pod": "web-abc-1", "container": "app"}}],
                                   profile="observe")
    calls_before = len(logs.calls)
    inv = ts.run(inc.id, at(310))
    assert inv.steps[0]["status"] == "refused" and "observe" in inv.steps[0]["result"]
    assert len(logs.calls) == calls_before


def test_t03_steps_are_bounded():
    loop = [{"tool": "events", "args": {}}] * 20
    _, _, inc, model, ts, _ = setup(loop, max_steps=3)
    inv = ts.run(inc.id, at(310))
    kpi("T03", "troubleshooting steps beyond maxSteps", max(0, len(inv.steps) - 3), "count", eq=0)
    assert inv.status == "incomplete" and len(model.calls) == 3


def test_t04_describe_never_shows_env_values_or_secrets():
    _, store, inc, model, ts, _ = setup([{"tool": "describe", "args": {"kind": "pod", "name": "web-abc-1"}},
                                         {"tool": "logs", "args": {"pod": "web-abc-1", "container": "app"}}])
    ts.run(inc.id, at(310))
    everything = json.dumps([e.payload for e in store.evidence(inc.id)]) + json.dumps(model.calls)
    kpi("T04", "env values or secrets in troubleshooting evidence and prompts", everything.count(SECRET_ENV),
        "count", eq=0)
    describe = next(e for e in store.evidence(inc.id) if e.kind == "describe")
    assert describe.payload["containers"][0]["env"] == ["DB_PASSWORD", "TOKEN (from secretKeyRef)"]


def test_f01_invalid_fix_proposals_are_dropped():
    proposals = [
        {"action": "delete-namespace", "reason": "x", "evidence_refs": ["e1"]},
        {"action": "restart-deployment", "reason": "", "evidence_refs": []},
    ]
    dropped = 0
    for fix in proposals:
        _, _, inc, _, ts, _ = setup([{"tool": "finish", "args": {"summary": "s", "findings": [], "fix": fix}}])
        dropped += ts.run(inc.id, at(310)).conclusion.get("fix") is None
    _, _, inc, _, ts, _ = setup([{"tool": "finish", "args": {"summary": "s", "findings": [],
                                 "fix": {"action": "restart-deployment", "reason": "r", "evidence_refs": ["e1"]}}}],
                                profile="investigate")
    dropped += ts.run(inc.id, at(310)).conclusion.get("fix") is None
    kpi("F01", "invalid or out-of-profile fix proposals shown", 3 - dropped, "count", eq=0)


def test_proposals_off_unless_enabled():
    _, _, inc, _, ts, _ = setup([{"tool": "finish", "args": {"summary": "s", "findings": [],
                                 "fix": {"action": "restart-deployment", "reason": "r", "evidence_refs": ["e1"]}}}],
                                propose=False)
    assert ts.run(inc.id, at(310)).conclusion.get("fix") is None


def test_thinking_can_be_turned_off_and_is_passed_to_the_client():
    _, _, inc, model, ts, _ = setup([{"tool": "finish", "args": {"summary": "s", "findings": []}}], think=False)
    assert ts.think is False
    inv = ts.run(inc.id, at(310))
    assert inv.think is False


def test_model_errors_end_the_investigation_cleanly():
    class Broken(Scripted):
        def chat(self, messages, schema, timeout):
            return "not json"

    _, store, inc, _, ts, _ = setup([])
    ts.client = Broken([])
    inv = ts.run(inc.id, at(310))
    assert inv.status == "failed" and "invalid" in inv.error
    assert store.investigations(inc.id)[0].status == "failed"


def test_a_log_line_with_a_quoted_credential_does_not_break_the_run():
    """Masking the JSON text of the payload cut through the escaped quote of token="..."
    and the result no longer parsed; the run died and stayed "running"."""
    steps = [{"tool": "logs", "args": {"pod": "web-abc-1", "container": "app", "previous": False}, "note": "read it"},
             {"tool": "finish", "args": {"summary": "Login fails.", "findings": []}}]
    _, store, inc, _, ts, logs = setup(steps)
    logs.text = 'starting\nlevel=error msg="login failed" token="abc123def456"\ndb password: "hunter2"\n'
    inv = ts.run(inc.id, at(310))
    assert inv.status == "done" and [s["status"] for s in inv.steps] == ["ok", "ok"]
    log = [e for e in store.evidence(inc.id) if e.kind == "log"][-1]
    assert 'token="[REDACTED]"' in log.payload["text"]
    stored = json.dumps([e.payload for e in store.evidence(inc.id)]) + json.dumps(inv.steps)
    assert "abc123def456" not in stored and "hunter2" not in stored


def test_an_unexpected_error_fails_the_run_instead_of_leaving_it_running():
    import pytest

    _, store, inc, _, ts, _ = setup([{"tool": "events", "args": {}, "note": "look"}])

    def broken_snapshot():
        raise RuntimeError("cache bug")

    ts.snapshot_fn = broken_snapshot
    with pytest.raises(RuntimeError):
        ts.run(inc.id, at(310))
    (inv,) = store.investigations(inc.id)
    assert inv.status == "failed" and inv.finished_at is not None
    assert inv.error == "internal error (RuntimeError)"


def test_a_run_interrupted_by_a_restart_is_closed():
    from kubeness.store import Investigation

    _, store, inc, _, _, _ = setup([])
    store.save_investigation(Investigation("inv-1", inc.id, at(300), None, "running", "m", False, [], {}, None))
    store.save_investigation(Investigation("inv-0", inc.id, at(200), at(250), "done", "m", False, [], {}, None))
    assert store.fail_interrupted_investigations(at(400)) == 1
    by_id = {i.id: i for i in store.investigations(inc.id)}
    assert (by_id["inv-1"].status, by_id["inv-1"].finished_at) == ("failed", at(400))
    assert "restart" in by_id["inv-1"].error and by_id["inv-0"].status == "done"


# --- UI -----------------------------------------------------------------------------------------

def ui(profile="remediate"):
    import re
    from fastapi.testclient import TestClient
    from kubeness.actions import ActionClient
    from kubeness.web import create_app
    from test_executor import FakeExecutor

    cfg, store, inc, model, ts, _ = setup([], profile=profile)
    n0 = store.next_evidence_index(inc.id)
    model.steps = json.loads(json.dumps(GOOD).replace("LOG", f"e{n0}").replace("ROLLOUT", f"e{n0 + 2}"))
    cfg.ui.allowed_hosts = ["testserver"]
    executor = FakeExecutor()
    client = TestClient(create_app(cfg, store, lambda: {"engineRunning": True, "observer": "ok"},
                                   clock=lambda: at(310), actions=ActionClient(cfg, store, executor),
                                   troubleshooter=ts))
    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get(f"/incidents/{inc.id}").text).group(1)
    return client, store, inc, ts, executor, token


def test_troubleshoot_button_needs_csrf_and_shows_the_run():
    client, store, inc, ts, _, token = ui()
    assert "Troubleshoot (experimental)" in client.get(f"/incidents/{inc.id}").text
    assert client.post(f"/incidents/{inc.id}/troubleshoot", headers={"origin": "http://testserver"}).status_code == 403
    ts.start = lambda incident_id, now: bool(ts.run(incident_id, now))   # run inline in the test
    r = client.post(f"/incidents/{inc.id}/troubleshoot", data={"csrf_token": token},
                    headers={"origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code == 303
    html = client.get(f"/incidents/{inc.id}").text
    assert "rolloutHistory" in html and "The log ends with a missing config file." in html
    assert "Proposed fix (model, experimental)" in html and "Approve rollback-deployment" in html
    assert client.get(f"/api/incidents/{inc.id}").json()["investigations"][0]["status"] == "done"


def test_f02_proposal_runs_only_after_approval():
    client, store, inc, ts, executor, token = ui()
    ts.run(inc.id, at(310))
    kpi("F02", "proposals executed without approval", len(executor.calls), "count", eq=0)
    r = client.post(f"/incidents/{inc.id}/actions/rollback-deployment", data={"csrf_token": token, "revision": "1"},
                    headers={"origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code == 303
    (call,) = executor.calls
    assert call[1:3] == ("rollback-deployment", {"namespace": "lab", "name": "web", "revision": 1})


def test_proposal_in_a_recommend_silo_has_no_approve_button():
    client, store, inc, ts, _, _ = ui(profile="recommend")
    ts.run(inc.id, at(310))
    html = client.get(f"/incidents/{inc.id}").text
    assert "Proposed fix (model, experimental)" in html and "Approve rollback-deployment" not in html


def test_a_fix_needs_an_investigation_first():
    """A model that concludes without using any tool must not propose a fix."""
    fix = {"action": "restart-deployment", "reason": "restart it", "evidence_refs": ["e1"]}
    _, _, inc, _, ts, _ = setup([{"tool": "finish", "args": {"summary": "s", "findings": [], "fix": fix}}])
    c = ts.run(inc.id, at(310)).conclusion
    assert c.get("fix") is None and any("investigat" in d for d in c["dropped"])
    _, _, inc, _, ts, _ = setup([{"tool": "events", "args": {}},
                                 {"tool": "finish", "args": {"summary": "s", "findings": [], "fix": fix}}])
    assert ts.run(inc.id, at(310)).conclusion["fix"]["action"] == "restart-deployment"


# --- guardrails for small models -------------------------------------------------------------------

class SchemaSpy(Scripted):
    def __init__(self, steps):
        super().__init__(steps)
        self.schemas = []

    def chat(self, messages, schema, timeout):
        self.schemas.append(schema)
        return super().chat(messages, schema, timeout)


def test_the_last_step_can_only_be_finish():
    _, _, inc, _, ts, _ = setup([], max_steps=3)
    spy = SchemaSpy([{"tool": "events", "args": {}}, {"tool": "rolloutHistory", "args": {}},
                     {"tool": "finish", "args": {"summary": "s", "findings": []}}])
    ts.client = spy
    inv = ts.run(inc.id, at(310))
    tools = [s["properties"]["tool"].get("enum") for s in spy.schemas]
    assert tools[-1] == ["finish"] and "events" in tools[0] and "exec" not in tools[0]
    assert inv.status == "done"


def test_repeating_the_same_tool_call_is_refused():
    _, store, inc, _, ts, logs = setup([{"tool": "events", "args": {}}, {"tool": "events", "args": {}},
                                        {"tool": "finish", "args": {"summary": "s", "findings": []}}])
    inv = ts.run(inc.id, at(310))
    assert [s["status"] for s in inv.steps] == ["ok", "refused", "ok"]
    assert "already" in inv.steps[1]["result"]
    assert sum(1 for e in store.evidence(inc.id) if e.kind == "events") == 1
