"""B18: Services and EndpointSlices as readiness evidence (readServices opt-in)."""

from __future__ import annotations

from kubeness.collector import LogCollector
from kubeness.config import Config
from kubeness.engine import Engine
from kubeness.notify import NotificationPolicy
from kubeness.store import Store

from factories import at, deployment, pod, running, snap
from kpi_report import kpi
from test_diagnose import FakeLogs


def service(name="web", selector=None):
    return {"metadata": {"name": name, "namespace": "lab"},
            "spec": {"selector": selector if selector is not None else {"app": "web"},
                     "ports": [{"port": 80, "targetPort": 8080}]}}


def slice_(svc="web", ready=(), not_ready=()):
    eps = [{"conditions": {"ready": True}, "targetRef": {"kind": "Pod", "name": n}} for n in ready]
    eps += [{"conditions": {"ready": False}, "targetRef": {"kind": "Pod", "name": n}} for n in not_ready]
    return {"metadata": {"name": f"{svc}-x1", "labels": {"kubernetes.io/service-name": svc}}, "endpoints": eps}


class FakeServices:
    def __init__(self, services, slices):
        self.services, self.slices, self.calls = services, slices, []

    def __call__(self, namespace):
        self.calls.append(namespace)
        return self.services, self.slices


def run(read_services, enabled=True):
    cfg = Config.model_validate({"access": {"readServices": enabled}, "notifications": {"enabled": True}})
    store = Store(":memory:")
    engine = Engine(cfg, store, LogCollector(cfg, FakeLogs(), read_services=read_services), None,
                    NotificationPolicy(cfg, store))
    dep = deployment(replicas=2, ready=1)
    dep["spec"]["template"] = {"metadata": {"labels": {"app": "web", "tier": "front"}}}
    pods = [pod(statuses=[running(started=at(-600))]), pod("web-abc-2", "pod-uid-2", [running(ready=False)])]
    for t in range(0, 200, 10):
        engine.tick(snap(at(t), pods=pods, deployments=[dep]), at(t))
    (inc,) = [i for i in store.list_incidents() if i.rule_id == "readiness"]
    return store, inc


def test_r07_services_are_not_read_unless_enabled():
    fake = FakeServices([service()], [slice_(ready=["web-abc-1"], not_ready=["web-abc-2"])])
    store, inc = run(fake, enabled=False)
    kpi("R07", "service reads with readServices off", len(fake.calls), "count", eq=0)
    assert not [e for e in store.evidence(inc.id) if e.kind == "service"]


def test_r08_endpoints_are_evidence_for_readiness():
    fake = FakeServices([service(), service("other", {"app": "other"})],
                        [slice_(ready=["web-abc-1"], not_ready=["web-abc-2"]), slice_("other", ready=["x"])])
    store, inc = run(fake)
    (ev,) = [e for e in store.evidence(inc.id) if e.kind == "service"]
    assert ev.payload["services"] == [{"name": "web", "selector": {"app": "web"}, "ready": 1, "notReady": 1,
                                       "notReadyPods": ["web-abc-2"], "ports": ["80->8080"]}]
    kpi("R08", "services with endpoint counts in readiness evidence", len(ev.payload["services"]), "count", eq=1)
    from kubeness.notify import template_for
    facts = [c.text for c in template_for(Config(), store, inc).observed_facts]
    assert any("Service web" in f and "1 not ready" in f for f in facts)


def test_service_selecting_nothing_is_reported():
    fake = FakeServices([service(selector={"app": "wbe"})], [])
    store, inc = run(fake)
    from kubeness.notify import template_for
    t = template_for(Config(), store, inc)
    assert not [e for e in store.evidence(inc.id) if e.kind == "service"] or \
        any("No Service selects" in m for m in t.missing_information)
