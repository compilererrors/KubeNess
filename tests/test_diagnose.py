import json

import httpx
import pytest
from fastapi.testclient import TestClient

from kubeness.analysis import Analysis, Claim, validate_refs
from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.model import Analyzer, model_input
from kubeness.redact import redact, redact_obj
from kubeness.store import Store
from kubeness.web import create_app

from factories import at, deployment, event, pod, running, snap, waiting
from test_engine import crashloop_status


# --- redaction -------------------------------------------------------------------------------

@pytest.mark.parametrize("text,leak", [
    ("password=hunter2 user=bob", "hunter2"),
    ('{"api_key": "abc123def"}', "abc123def"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJhbGci"),
    ("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("connecting to postgres://app:s3cr3t@db:5432/app", "s3cr3t"),
    ("DB_PASSWORD: 'x9!y'", "x9!y"),
])
def test_redaction_masks_credentials(text, leak):
    out, n = redact(text)
    assert leak not in out and n >= 1 and "[REDACTED]" in out


def test_redaction_keeps_ordinary_text():
    text = "fatal: config file /etc/app.yaml missing\nconnection refused to db:5432"
    assert redact(text) == (text, 0)


def test_redaction_of_a_structure_masks_strings_and_values_under_credential_keys():
    obj = {
        "text": 'level=error token="abc123def" msg="x"',
        "args": {"password": "hunter2", "DB_TOKEN": 12345, "apiKeys": ["k1", "k2"], "secretName": "db", "debug": True},
        "nested": [{"message": "dsn postgres://app:s3cr3t@db/x"}, 7, None],
        "restartCount": 3,
    }
    out = redact_obj(obj)
    assert out == {
        "text": 'level=error token="[REDACTED]" msg="x"',
        "args": {"password": "[REDACTED]", "DB_TOKEN": "[REDACTED]", "apiKeys": ["[REDACTED]", "[REDACTED]"],
                 "secretName": "db", "debug": True},
        "nested": [{"message": "dsn postgres://app:[REDACTED]@db/x"}, 7, None],
        "restartCount": 3,
    }
    assert obj["args"]["password"] == "hunter2", "the input is not changed"
    assert json.loads(json.dumps(out)) == out


# --- validation ------------------------------------------------------------------------------

def test_validate_refs_drops_unsupported_claims():
    a = Analysis(
        summary="s",
        observed_facts=[Claim(text="real", evidence_refs=["e1", "e9"]), Claim(text="invented", evidence_refs=["e7"])],
        possible_causes=[Claim(text="no refs", evidence_refs=[])],
    )
    v = validate_refs(a, {"e1", "e2"})
    assert [c.text for c in v.analysis.observed_facts] == ["real"]
    assert v.analysis.observed_facts[0].evidence_refs == ["e1"]
    assert v.analysis.possible_causes == []
    assert len(v.dropped) == 2


# --- end-to-end through the engine with fake logs and a fake model ----------------------------

class FakeLogs:
    def __init__(self, text="starting\npassword=hunter2\nfatal: config missing\n", fail_previous=False,
                 fail_current=False, previous_text=None):
        self.text, self.fail_previous, self.fail_current, self.calls = text, fail_previous, fail_current, []
        self.previous_text = previous_text

    def __call__(self, name, namespace, *, container, previous, tail_lines, since_seconds, limit_bytes):
        self.calls.append(dict(name=name, container=container, previous=previous, since_seconds=since_seconds))
        if (previous and self.fail_previous) or (not previous and self.fail_current):
            raise type("ApiException", (Exception,), {"status": 400})()
        if previous and self.previous_text is not None:
            return self.previous_text
        return self.text


class FakeModel:
    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.calls = reply, exc, []

    def chat(self, messages, schema, timeout):
        self.calls.append(messages)
        if self.exc:
            raise self.exc
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)

    def available(self, timeout):
        return True, "ok"


def run_crash_loop(cfg_over=None, logs=None, model=None, seconds=300):
    cfg = Config.model_validate({"model": {"enabled": model is not None}, **(cfg_over or {})})
    store = Store(":memory:")
    analyzer = Analyzer(cfg, store, model)
    engine = Engine(cfg, store, LogCollector(cfg, logs), analyzer)
    for t in range(0, seconds, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])],
                         events=[event("BackOff", "Back-off restarting failed container app", "web-abc-1", at(20), "ev1")]),
                    at(t))
    (inc,) = engine.open.values()
    return cfg, store, analyzer, inc


def test_firing_collects_masked_previous_logs_and_template_analysis():
    logs = FakeLogs()
    _, store, _, inc = run_crash_loop(logs=logs)
    assert logs.calls[0]["previous"] is True and logs.calls[0]["since_seconds"] is None
    ev = store.evidence(inc.id)
    log = next(e for e in ev if e.kind == "log")
    assert "hunter2" not in log.payload["text"] and log.payload["redactions"] == 1
    (rec,) = store.analyses(inc.id)
    assert (rec.source, rec.status) == ("template", "ok")
    facts = rec.payload["observed_facts"]
    assert any("fatal: config missing" in f["text"] and f["evidence_refs"] == [log.ref] for f in facts)
    refs = {e.ref for e in ev}
    for claim in facts + rec.payload["possible_causes"]:
        assert set(claim["evidence_refs"]) <= refs


def test_missing_logs_are_reported():
    _, store, _, inc = run_crash_loop(logs=FakeLogs(fail_previous=True, fail_current=True))
    ev = store.evidence(inc.id)
    gap = next(e for e in ev if e.kind == "gap")
    assert "previous logs failed with HTTP 400" in gap.summary and "current logs failed" in gap.summary
    (rec,) = store.analyses(inc.id)
    assert gap.summary in rec.payload["missing_information"]
    assert rec.payload["possible_causes"], "the runbook always states a hypothesis"


def test_kubelet_unavailable_text_falls_back_to_current_logs():
    gone = "unable to retrieve container logs for containerd://c170559"
    _, store, _, inc = run_crash_loop(logs=FakeLogs(previous_text=gone))
    log = next(e for e in store.evidence(inc.id) if e.kind == "log")
    assert log.payload["previous"] is False and "containerd" not in log.payload["text"]
    assert "no longer exist" in log.summary
    assert "fatal: config missing" in log.payload["text"]


def test_logs_disabled_by_access_profile():
    logs = FakeLogs()
    _, store, _, inc = run_crash_loop(cfg_over={"access": {"readLogs": False}}, logs=logs)
    assert logs.calls == []
    (rec,) = store.analyses(inc.id)
    assert any("log access is disabled" in m for m in rec.payload["missing_information"])


def model_reply(refs):
    return {
        "summary": "The container exits because its config is missing.",
        "possible_causes": [
            {"text": "The config file is not mounted.", "evidence_refs": refs},
            {"text": "An invented cause.", "evidence_refs": ["e42"]},
        ],
        "next_checks": ["Check the volume mounts of the Deployment."],
    }


def test_model_analysis_is_validated_and_stored():
    model = FakeModel(model_reply(["e1"]))
    _, store, analyzer, inc = run_crash_loop(logs=FakeLogs(), model=model)
    assert analyzer.queue.qsize() == 1   # the rule loop only enqueued it
    analyzer.run_model(analyzer.queue.get_nowait())
    recs = store.analyses(inc.id)
    assert [(r.source, r.status) for r in recs] == [("template", "ok"), ("model", "ok")]
    # Observed facts stay the deterministic, grounded ones; the model adds causes and checks.
    assert recs[1].payload["observed_facts"] == recs[0].payload["observed_facts"]
    assert [c["text"] for c in recs[1].payload["possible_causes"]] == ["The config file is not mounted."]
    assert recs[1].payload["summary"] == "The container exits because its config is missing."
    assert recs[1].dropped == ["possible_cause: An invented cause."]
    # The prompt holds verified facts only: no raw logs, no masked secret.
    prompt = model.calls[0][1]["content"]
    assert "hunter2" not in prompt and "starting" not in prompt and '"facts"' in prompt


@pytest.mark.parametrize("model,error", [
    (FakeModel(exc=httpx.ReadTimeout("slow")), "timeout"),
    (FakeModel(reply="not json"), "ValidationError"),
    (FakeModel(model_reply(["e99"])), "no possible cause cited valid evidence"),
])
def test_model_failures_keep_template_analysis(model, error):
    _, store, analyzer, inc = run_crash_loop(logs=FakeLogs(), model=model)
    analyzer.run_model(analyzer.queue.get_nowait())
    recs = store.analyses(inc.id)
    assert [(r.source, r.status) for r in recs] == [("template", "ok"), ("model", "unavailable")]
    assert error in recs[1].error
    assert analyzer.status()["model"] in ("unavailable", "unknown")


def test_full_queue_marks_analysis_unavailable():
    cfg = Config.model_validate({"model": {"enabled": True, "queueSize": 1}})
    store = Store(":memory:")
    analyzer = Analyzer(cfg, store, FakeModel(model_reply(["e1"])))
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), analyzer)
    pods = [pod(statuses=[waiting(reason="ErrImagePull", image_id="")]),
            pod("other-1", "pod-9", [waiting(reason="ErrImagePull", image_id="")],
                owner={"kind": "StatefulSet", "name": "db", "uid": "sts-1", "controller": True})]
    for t in range(0, 80, 10):
        engine.tick(snap(at(t), pods=pods), at(t))
    errors = [r.error for i in store.list_incidents() for r in store.analyses(i.id) if r.status != "ok"]
    assert errors == ["analysis queue is full"]


def test_template_analysis_for_image_pull_and_readiness():
    events = [event("Failed", 'Failed to pull image "x": manifest unknown', "web-abc-1", at(1), "ev1")]
    cfg = Config()
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), Analyzer(cfg, store, None))
    for t in range(0, 80, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[waiting(reason="ImagePullBackOff", image_id="")])],
                         events=events), at(t))
    (inc,) = store.list_incidents()
    a = store.analyses(inc.id)[0].payload
    assert "tag does not exist" in a["possible_causes"][0]["text"]
    assert "The registry content has not been verified directly." in a["missing_information"]

    store2 = Store(":memory:")
    engine2 = Engine(cfg, store2, LogCollector(cfg, FakeLogs("listening on :8080\n")), Analyzer(cfg, store2, None))
    probe = [event("Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 503", "web-abc-1", at(1), "ev2")]
    dep = deployment(replicas=1, ready=0, progressing=("False", "ProgressDeadlineExceeded"))
    engine2.tick(snap(at(0), pods=[pod(statuses=[running(ready=False)])], deployments=[dep], events=probe), at(0))
    (inc2,) = store2.list_incidents()
    a2 = store2.analyses(inc2.id)[0].payload
    assert any("readiness probe fails" in c["text"] for c in a2["possible_causes"])


@pytest.mark.parametrize("message,first_cause", [
    ('failed to resolve reference "registry.internal/web:1.2": failed to do request: Head '
     '"https://registry.internal/v2/web/manifests/1.2": dial tcp: lookup registry.internal on 10.96.0.10:53: '
     'no such host', "The node cannot reach the registry."),
    ('failed to resolve reference "docker.io/library/web:9": docker.io/library/web:9: not found',
     "The tag does not exist in the registry the workload uses."),
    # A digest that happens to contain 403 is not an authorization failure.
    ('Back-off pulling image "registry.internal/web@sha256:9403aa": dial tcp 10.0.0.9:443: i/o timeout',
     "The node cannot reach the registry."),
    ('failed to authorize: failed to fetch anonymous token: unexpected status: 403 Forbidden',
     "The registry rejects the pull because credentials are missing or wrong."),
])
def test_image_pull_runbook_tells_dns_and_missing_tags_apart(message, first_cause):
    cfg = Config()
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), Analyzer(cfg, store, None))
    events = [event("Failed", message, "web-abc-1", at(1), "ev1")]
    for t in range(0, 80, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[waiting(reason="ImagePullBackOff", image_id="")])],
                         events=events), at(t))
    (inc,) = store.list_incidents()
    causes = [c["text"] for c in store.analyses(inc.id)[0].payload["possible_causes"]]
    assert causes == [first_cause]


def test_model_input_is_bounded():
    _, store, _, inc = run_crash_loop(logs=FakeLogs("error " + "x" * 20000 + "\n"))
    rec = store.analyses(inc.id)[0]
    from kubeness.analysis import Analysis
    data = model_input(inc, Analysis.model_validate(rec.payload))
    assert all(len(f["fact"]) <= 300 for f in data["facts"])
    assert len(json.dumps(data)) < 4000


def test_detail_page_shows_analysis_and_failed_model():
    cfg, store, analyzer, inc = run_crash_loop(
        cfg_over={"ui": {"allowedHosts": ["testserver"]}}, logs=FakeLogs(), model=FakeModel(exc=httpx.ReadTimeout("x")))
    analyzer.run_model(analyzer.queue.get_nowait())
    status = {"observer": "ok", "observerDetail": "", "engineRunning": True, **analyzer.status()}
    client = TestClient(create_app(cfg, store, lambda: status))
    html = client.get(f"/incidents/{inc.id}").text
    assert "Possible causes (hypotheses)" in html
    assert "Model analysis unavailable: timeout" in html
    assert 'href="#e1"' in html and 'id="e1"' in html
    data = client.get(f"/api/incidents/{inc.id}").json()
    assert [a["source"] for a in data["analyses"]] == ["template", "model"]


def test_logs_missing_at_firing_are_collected_later():
    class Flaky(FakeLogs):
        def __init__(self):
            super().__init__(fail_previous=True, fail_current=True)

    logs = Flaky()
    cfg = Config()
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, logs), Analyzer(cfg, store, None))
    for t in range(0, 300, 10):
        if t == 120:
            logs.fail_previous = False  # the next restart left a previous container behind
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
    (inc,) = engine.open.values()
    kinds = [e.kind for e in store.evidence(inc.id)]
    assert "gap" in kinds and "log" in kinds
    recs = store.analyses(inc.id)
    assert len(recs) == 2
    assert any("fatal: config missing" in f["text"] for f in recs[-1].payload["observed_facts"])
    assert not any("unavailable" in m for m in recs[-1].payload["missing_information"])
    assert "evidence" in [a.kind for a in store.activity(inc.id)]
