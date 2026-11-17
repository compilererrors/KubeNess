"""B28: access profiles per silo, enforced in the app (the chart test covers RBAC)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kubeness.actions import ActionClient
from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.store import Store

from factories import at, pod, snap
from kpi_report import kpi
from test_diagnose import FakeLogs
from test_engine import crashloop_status
from test_executor import FakeExecutor

SILOS = {"silos": [{"name": "lab", "namespaces": ["lab"], "profile": "remediate"},
                   {"name": "shop", "namespaces": ["shop", "shop-api"], "profile": "observe"}]}


def test_silos_define_the_watched_namespaces_and_profiles():
    a = Config.model_validate({"access": SILOS}).access
    assert a.namespaces == ["lab", "shop", "shop-api"]
    assert [a.silo_for(n).name for n in a.namespaces] == ["lab", "shop", "shop"]
    assert a.logs_allowed("lab") and not a.logs_allowed("shop")
    assert a.actions_allowed("lab") and not a.actions_allowed("shop-api")
    assert a.fixes_allowed("lab") and not a.fixes_allowed("shop")
    assert a.silo_for("kube-system") is None and not a.logs_allowed("kube-system")


def test_without_silos_one_default_silo_keeps_the_old_behaviour():
    a = Config.model_validate({"access": {"namespaces": ["lab"], "readLogs": True}}).access
    (s,) = a.silo_list()
    assert (s.name, s.namespaces, s.profile) == ("default", ["lab"], "investigate")
    assert a.logs_allowed("lab") and not a.actions_allowed("lab")
    assert not Config.model_validate({"access": {"readLogs": False}}).access.logs_allowed("lab")


def test_a_namespace_belongs_to_one_silo_only():
    with pytest.raises(ValidationError, match="more than one silo"):
        Config.model_validate({"access": {"silos": [{"name": "a", "namespaces": ["x"]},
                                                    {"name": "b", "namespaces": ["x"]}]}})


def run_in(namespace_profile: str):
    cfg = Config.model_validate({"access": {"silos": [{"name": "s", "namespaces": ["lab"],
                                                       "profile": namespace_profile}]}})
    logs = FakeLogs()
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, logs))
    for t in range(0, 300, 10):
        engine.tick(snap(at(t), pods=[pod(statuses=[crashloop_status(t)])]), at(t))
    (inc,) = store.list_incidents()
    return cfg, store, inc, logs


def test_g02_no_log_reads_in_an_observe_silo():
    _, store, inc, logs = run_in("observe")
    kpi("G02", "log reads in an observe silo", len(logs.calls), "count", eq=0)
    gap = next(e for e in store.evidence(inc.id) if e.kind == "gap")
    assert "observe profile" in gap.summary
    _, _, _, logs = run_in("investigate")
    assert logs.calls


def test_g03_actions_only_in_remediate_silos():
    accepted = 0
    for profile in ("observe", "investigate", "recommend", "remediate"):
        cfg, store, inc, _ = run_in(profile)
        cfg.actions.enabled = True
        client = ActionClient(cfg, store, FakeExecutor())
        try:
            client.request(inc, "restart-deployment", at(400))
            accepted += profile != "remediate"
        except ValueError as e:
            assert profile != "remediate" and "remediate" in str(e)
    kpi("G03", "actions accepted outside a remediate silo", accepted, "count", eq=0)
