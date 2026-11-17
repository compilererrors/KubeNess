"""Tiered models: a small model analyses every incident; a larger one takes over by rule."""

from __future__ import annotations

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.model import Analyzer
from kubeness.store import Store
from kubeness.web import pick_analysis

from factories import at, event, pod, snap
from kpi_report import kpi
from test_diagnose import FakeLogs, FakeModel, model_reply
from test_engine import crashloop_status

GROUNDED = "Check the volume mounts of the Deployment web and the config file."
VAGUE = "Look at the system."


def reply(check=GROUNDED, refs=("e1",)):
    r = model_reply(list(refs))
    r["possible_causes"] = r["possible_causes"][:1]   # no unsupported claim
    r["next_checks"] = [check]
    return r


def run(small, big, on=None, critical=False, recurring=False):
    esc = {"model": "qwen3:1.7b"}
    if on is not None:
        esc["when"] = on
    cfg = Config.model_validate({"model": {"enabled": True, "escalation": esc},
                                 "alarms": {"criticalWorkloads": ["lab/web"] if critical else []}})
    store = Store(":memory:")
    analyzer = Analyzer(cfg, store, small, escalation=big)
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs()), analyzer)
    ev = [event("BackOff", "Back-off restarting failed container app", "web-abc-1", at(20), "ev1")]
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])], events=ev), at(t))
    (inc,) = engine.open.values()
    if recurring:
        inc.recurrence_count = 1
        store.save_incident(inc)
    analyzer.run_model(analyzer.queue.get_nowait())
    return store, inc


def models(store, inc):
    return [(r.model, r.status) for r in store.analyses(inc.id) if r.source == "model"]


def test_a_good_small_answer_is_not_escalated():
    big = FakeModel(reply())
    store, inc = run(FakeModel(reply()), big)
    assert models(store, inc) == [("qwen3:0.6b", "ok")] and big.calls == []


def test_an_ungrounded_small_answer_is_escalated_and_shown():
    store, inc = run(FakeModel(reply(check=VAGUE)), FakeModel(reply()), on=["ungrounded"])
    assert models(store, inc) == [("qwen3:0.6b", "ok"), ("qwen3:1.7b", "ok")]
    shown, _ = pick_analysis(store.analyses(inc.id))
    assert shown.model == "qwen3:1.7b"
    assert any("Escalated to qwen3:1.7b" in a.message and "ungrounded" in a.message for a in store.activity(inc.id))


def test_unsupported_claims_escalate_by_default():
    store, inc = run(FakeModel(model_reply(["e1"])), FakeModel(reply()))   # one cause cites e42
    assert ("qwen3:1.7b", "ok") in models(store, inc)
    assert any("unsupported" in a.message for a in store.activity(inc.id))


def test_a_vague_but_supported_answer_stays_small_by_default():
    """Vague checks alone are not a reason to escalate: that would send most incidents to the big model."""
    store, inc = run(FakeModel(reply(check=VAGUE)), FakeModel(reply()))
    assert models(store, inc) == [("qwen3:0.6b", "ok")]


def test_an_invalid_small_answer_is_escalated():
    store, inc = run(FakeModel(reply="not json"), FakeModel(reply()))
    assert models(store, inc) == [("qwen3:0.6b", "unavailable"), ("qwen3:1.7b", "ok")]


def test_critical_and_recurring_go_to_the_larger_model_when_configured():
    for kw in ({"critical": True}, {"recurring": True}):
        store, inc = run(FakeModel(reply()), FakeModel(reply()), on=["critical", "recurring"], **kw)
        assert ("qwen3:1.7b", "ok") in models(store, inc), kw


def test_triggers_not_configured_do_not_escalate():
    store, inc = run(FakeModel(reply(check=VAGUE)), FakeModel(reply()), on=["critical"])
    assert models(store, inc) == [("qwen3:0.6b", "ok")]


def test_escalation_is_off_by_default():
    cfg = Config()
    assert cfg.model.escalation.model is None


def test_escalation_rate_kpi():
    escalated = 0
    for small in (FakeModel(reply()), FakeModel(model_reply(["e1"])), FakeModel(reply="x"), FakeModel(reply(check=VAGUE))):
        store, inc = run(small, FakeModel(reply()))
        escalated += any(m == "qwen3:1.7b" for m, _ in models(store, inc))
    kpi("E01", "escalations by the default rule: good, unsupported, invalid, vague", escalated, "count", eq=2)


def test_troubleshooting_uses_the_escalation_model():
    from kubeness.troubleshoot import troubleshoot_model
    cfg = Config.model_validate({"model": {"enabled": True, "escalation": {"model": "qwen3:4b"}}})
    assert troubleshoot_model(cfg) == "qwen3:4b"
    cfg = Config.model_validate({"model": {"enabled": True, "escalation": {"model": "qwen3:4b", "when": ["invalid"]}}})
    assert troubleshoot_model(cfg) == "qwen3:0.6b"
