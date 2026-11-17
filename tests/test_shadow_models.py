"""Model PoC: a shadow model analyses the same incidents as the primary one, for comparison."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.model import Analyzer, grounded_checks
from kubeness.store import Store
from kubeness.web import create_app, pick_analysis

from factories import at, event, pod, snap
from test_diagnose import FakeLogs, FakeModel, model_reply
from test_engine import crashloop_status


def reply(refs, check="Check the volume mounts of the Deployment web and the config file."):
    r = model_reply(refs)
    r["next_checks"] = [check]
    return r


def run(primary, shadows):
    cfg = Config.model_validate({"ui": {"allowedHosts": ["testserver"]},
                                 "model": {"enabled": True, "compare": list(shadows)}})
    store = Store(":memory:")
    analyzer = Analyzer(cfg, store, primary, shadows)
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), analyzer)
    ev = [event("BackOff", "Back-off restarting failed container app", "web-abc-1", at(20), "ev1")]
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])], events=ev), at(t))
    (inc,) = engine.open.values()
    analyzer.run_model(analyzer.queue.get_nowait())
    return cfg, store, analyzer, inc


def test_shadow_model_analyses_the_same_incident():
    small, big = FakeModel(reply(["e1"])), FakeModel(reply(["e1", "e2"]))
    _, store, _, inc = run(small, {"qwen3:1.7b": big})
    recs = store.analyses(inc.id)
    assert [(r.source, r.model) for r in recs] == [("template", None), ("model", "qwen3:0.6b"),
                                                  ("shadow", "qwen3:1.7b")]
    assert recs[1].status == recs[2].status == "ok"
    assert small.calls[0] == big.calls[0], "both models get the same input"


def test_the_shown_analysis_is_the_primary_model():
    _, store, _, inc = run(FakeModel(reply(["e1"])), {"qwen3:1.7b": FakeModel(reply(["e1"]))})
    shown, failed = pick_analysis(store.analyses(inc.id))
    assert (shown.source, shown.model) == ("model", "qwen3:0.6b") and failed is None


def test_a_failing_shadow_does_not_touch_the_primary_status():
    _, store, analyzer, inc = run(FakeModel(reply(["e1"])),
                                  {"qwen3:1.7b": FakeModel(exc=httpx.ReadTimeout("slow"))})
    shadow = [r for r in store.analyses(inc.id) if r.source == "shadow"][0]
    assert shadow.status == "unavailable" and shadow.error == "timeout"
    assert analyzer.status()["model"] == "ok"


def test_grounded_checks_name_objects_from_the_incident():
    _, store, _, inc = run(FakeModel(reply(["e1"])), {})
    evidence = store.evidence(inc.id)
    assert grounded_checks(["Check the volume mounts of the Deployment web."], inc, evidence) == 1
    assert grounded_checks(["Look at the system."], inc, evidence) == 0


def test_models_page_and_api_compare_per_model():
    cfg, store, _, inc = run(FakeModel(reply(["e1"], check="Look at the system.")),
                             {"qwen3:1.7b": FakeModel(reply(["e1"]))})
    client = TestClient(create_app(cfg, store, lambda: {"engineRunning": True, "observer": "ok"}))
    stats = {r["model"]: r for r in client.get("/api/models").json()}
    assert set(stats) == {"qwen3:0.6b", "qwen3:1.7b"}
    small, big = stats["qwen3:0.6b"], stats["qwen3:1.7b"]
    assert small["role"] == "primary" and big["role"] == "shadow"
    assert small["analyses"] == big["analyses"] == 1 and small["ok"] == 1
    assert small["droppedClaims"] == 1 and big["droppedClaims"] == 1
    assert small["groundedChecks"] == 0 and big["groundedChecks"] == 1
    assert "p95LatencyMs" in small
    html = client.get("/models").text
    assert "qwen3:1.7b" in html and "shadow" in html
    detail = client.get(f"/incidents/{inc.id}").text
    assert "Model comparison" in detail and "qwen3:1.7b" in detail


def test_compare_is_off_by_default():
    assert Config().model.compare == []
