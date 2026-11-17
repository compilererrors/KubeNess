"""Compare template-only analysis with local models on the same incidents.

    python -m kubeness.compare --url http://127.0.0.1:11434 [--models qwen3:0.6b,qwen3:1.7b]

The fixtures cover the three main families plus missing logs, OOM and an
ambiguous failure. Per model it reports unsupported claims (before validation),
schema errors, whether a next check names the right object, and latency.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import ValidationError

from .analysis import Analysis, template_analysis, validate_refs
from .config import Config
from .lifecycle import Incident, State
from .model import ENRICHMENT_SCHEMA, SYSTEM_PROMPT, Enrichment, OllamaClient, encode_input, grounded_checks, model_input
from .snapshot import Snapshot, WorkloadRef
from .store import EvidenceItem, Store

T0 = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


@dataclass
class Fixture:
    name: str
    incident: Incident
    evidence: list[EvidenceItem]
    keywords: tuple[str, ...]   # a useful next check names one of these


def _inc(name: str, rule: str, reason: str, details: dict) -> Incident:
    return Incident(id=f"inc-{name}", fingerprint=f"lab/lab/{name}/{rule}", rule_id=rule, cluster="lab",
                    workload=WorkloadRef("Deployment", "lab", name, f"uid-{name}"), severity="warning",
                    state=State.FIRING, reason=reason, first_seen=T0, last_observed=T0 + timedelta(minutes=5),
                    details=details, pods=[f"{name}-abc-1"])


def _ev(ref: str, kind: str, summary: str, payload: dict) -> EvidenceItem:
    return EvidenceItem(ref, T0, kind, summary, payload)


def _container(name: str, reason: str, code: int, restarts: int = 5, **extra) -> dict:
    return {"pod": f"{name}-abc-1", "container": "app", "restartCount": restarts, "waitingReason": "CrashLoopBackOff",
            "lastTermination": {"reason": reason, "exitCode": code}, **extra}


def _fixtures() -> list[Fixture]:
    out = []
    d = {"rule": "restarts", "containers": [_container("crash-config", "Error", 1)]}
    out.append(Fixture("crash-config", _inc("crash-config", "restarts", "Container app is in CrashLoopBackOff", d), [
        _ev("e1", "rule", "Container app is in CrashLoopBackOff", d),
        _ev("e2", "event", "Warning BackOff: Pod/crash-config-abc-1", {"message": "Back-off restarting failed container"}),
        _ev("e3", "log", "previous logs of crash-config-abc-1/app: 3 lines",
            {"pod": "crash-config-abc-1", "container": "app", "previous": True, "text":
             "starting\nloading /etc/app/config.yaml\nfatal: config file /etc/app/config.yaml not found\n"}),
    ], ("config",)))
    d = {"rule": "imagePull", "containers": [{"pod": "image-tag-abc-1", "container": "app", "waitingReason":
                                             "ImagePullBackOff", "specImage": "registry.example/web:2.4.1"}]}
    out.append(Fixture("image-tag", _inc("image-tag", "imagePull", "ImagePullBackOff for image registry.example/web:2.4.1", d), [
        _ev("e1", "rule", "ImagePullBackOff for image registry.example/web:2.4.1", d),
        _ev("e2", "event", "Warning Failed: Pod/image-tag-abc-1",
            {"message": "Failed to pull image \"registry.example/web:2.4.1\": manifest unknown"}),
    ], ("tag", "image")))
    d = {"rule": "readiness", "desiredReplicas": 2, "readyReplicas": 0, "notReadyContainers": [
        {"pod": "readiness-probe-abc-1", "container": "app"}]}
    out.append(Fixture("readiness-probe", _inc("readiness-probe", "readiness", "0 of 2 replicas ready for 2m", d), [
        _ev("e1", "rule", "0 of 2 replicas ready for 2m", d),
        _ev("e2", "event", "Warning Unhealthy: Pod/readiness-probe-abc-1",
            {"message": "Readiness probe failed: HTTP probe failed with statuscode: 503"}),
    ], ("probe",)))
    d = {"rule": "restarts", "containers": [_container("logs-missing", "Error", 2)]}
    out.append(Fixture("logs-missing", _inc("logs-missing", "restarts", "Container app is in CrashLoopBackOff", d), [
        _ev("e1", "rule", "Container app is in CrashLoopBackOff", d),
        _ev("e2", "gap", "Logs of logs-missing-abc-1/app unavailable: previous logs failed with HTTP 400.", {}),
    ], ("log",)))
    d = {"rule": "oom", "containers": [{"pod": "oom-abc-1", "container": "app", "memoryLimit": "64Mi"}],
         "killsInWindow": 2}
    out.append(Fixture("oom", _inc("oom", "oom", "Container app was OOM killed (memory limit 64Mi); 2 kills within 30m", d), [
        _ev("e1", "rule", "Container app was OOM killed", d),
    ], ("memory", "limit")))
    d = {"rule": "restarts", "containers": [_container("ambiguous", "Error", 1, 3)]}
    out.append(Fixture("ambiguous", _inc("ambiguous", "restarts", "3 restarts within 5m", d), [
        _ev("e1", "rule", "3 restarts within 5m", d),
    ], ("log", "exit")))
    return out


FIXTURES = _fixtures()


@dataclass
class Row:
    model: str
    unsupported: int = 0
    schema_errors: int = 0
    useful_checks: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95(self) -> float:
        if len(self.latencies_ms) < 2:
            return self.latencies_ms[0] if self.latencies_ms else 0.0
        return statistics.quantiles(self.latencies_ms, n=20, method="inclusive")[18]


def _useful(checks: list[str], keywords: tuple[str, ...]) -> bool:
    return any(k in c.lower() for c in checks for k in keywords)


def compare(clients: dict, timeout: float = 60) -> list[Row]:
    rows = [Row("template")]
    templates = {}
    for f in FIXTURES:
        t = validate_refs(template_analysis(f.incident, f.evidence, True), {e.ref for e in f.evidence}).analysis
        templates[f.name] = t
        rows[0].useful_checks += _useful(t.next_checks, f.keywords)
    for name, client in clients.items():
        row = Row(name)
        for f in FIXTURES:
            tmpl: Analysis = templates[f.name]
            refs = {e.ref for e in f.evidence}
            messages = [{"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": encode_input(model_input(f.incident, tmpl)).decode()}]
            start = time.monotonic()
            try:
                reply = Enrichment.model_validate_json(client.chat(messages, ENRICHMENT_SCHEMA, timeout))
            except (ValidationError, ValueError, KeyError, OSError, httpx.HTTPError) as e:
                row.schema_errors += 1
                row.latencies_ms.append((time.monotonic() - start) * 1000)
                print(f"  {name} {f.name}: {type(e).__name__}", file=sys.stderr)
                continue
            row.latencies_ms.append((time.monotonic() - start) * 1000)
            row.unsupported += sum(1 for c in reply.possible_causes
                                   if not c.evidence_refs or not set(c.evidence_refs) <= refs)
            row.useful_checks += _useful(reply.next_checks, f.keywords)
        rows.append(row)
    return rows


def render(rows: list[Row]) -> str:
    n = len(FIXTURES)
    lines = [f"Model comparison on {n} incident fixtures", "",
             "| model | unsupported causes | schema errors | useful next check | p50 ms | p95 ms |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r.model} | {r.unsupported} | {r.schema_errors} | {r.useful_checks}/{n} | "
                     f"{r.p50:.0f} | {r.p95:.0f} |")
    return "\n".join(lines)


# --- strategies: one model vs. a small model that hands over to a larger one ----------------------

@dataclass
class Strategy:
    name: str
    escalations: int = 0
    unsupported: int = 0
    schema_errors: int = 0
    useful_checks: int = 0
    grounded: int = 0
    latency_ms: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        return statistics.median(self.latency_ms) if self.latency_ms else 0.0

    @property
    def p95(self) -> float:
        if len(self.latency_ms) < 2:
            return self.latency_ms[0] if self.latency_ms else 0.0
        return statistics.quantiles(self.latency_ms, n=20, method="inclusive")[18]


def _one(client, f: Fixture, tmpl: Analysis, timeout: float) -> dict:
    refs = {e.ref for e in f.evidence}
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": encode_input(model_input(f.incident, tmpl)).decode()}]
    start = time.monotonic()
    try:
        reply = Enrichment.model_validate_json(client.chat(messages, ENRICHMENT_SCHEMA, timeout))
    except (ValidationError, ValueError, KeyError, OSError, httpx.HTTPError):
        return {"ok": False, "ms": (time.monotonic() - start) * 1000, "unsupported": 0, "useful": 0, "grounded": 0}
    ms = (time.monotonic() - start) * 1000
    unsupported = sum(1 for c in reply.possible_causes if not c.evidence_refs or not set(c.evidence_refs) <= refs)
    return {"ok": True, "ms": ms, "unsupported": unsupported, "useful": int(_useful(reply.next_checks, f.keywords)),
            "grounded": int(grounded_checks(reply.next_checks, f.incident, f.evidence) > 0)}


def strategies(clients: dict, small: str, big: list[str], timeout: float = 120) -> list[Strategy]:
    """Each model runs once per fixture; a tiered strategy uses the small model's result
    unless the production escalation rule fires (invalid or ungrounded), then the big one's.
    Tiered latency is the sum, as when both models are loaded."""
    tmpls = {f.name: validate_refs(template_analysis(f.incident, f.evidence, True),
                                   {e.ref for e in f.evidence}).analysis for f in FIXTURES}
    runs = {name: [_one(c, f, tmpls[f.name], timeout) for f in FIXTURES] for name, c in clients.items()}

    def add(row: Strategy, r: dict, extra_ms: float = 0) -> None:
        row.latency_ms.append(r["ms"] + extra_ms)
        row.schema_errors += not r["ok"]
        row.unsupported += r["unsupported"]
        row.useful_checks += r["useful"]
        row.grounded += r["grounded"]

    rows = []
    for name in [small, *big]:
        row = Strategy(f"only {name}")
        for r in runs[name]:
            add(row, r)
        rows.append(row)
    rules = {"invalid+ungrounded": lambda r: not r["ok"] or r["unsupported"] or not r["grounded"],
             "invalid+unsupported": lambda r: not r["ok"] or r["unsupported"]}
    for b in big:
        for label, rule in rules.items():
            row = Strategy(f"{small} → {b} ({label})")
            for s_run, b_run in zip(runs[small], runs[b]):
                if rule(s_run):
                    row.escalations += 1
                    add(row, b_run, extra_ms=s_run["ms"])
                else:
                    add(row, s_run)
            rows.append(row)
    return rows


def render_strategies(rows: list[Strategy]) -> str:
    n = len(FIXTURES)
    lines = [f"Analysis strategies on {n} fixtures (tiered = small model, larger one by the escalation rule)", "",
             "| strategy | escalated | unsupported causes | schema errors | grounded next check | useful next check "
             "| p50 ms | p95 ms |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r.name} | {r.escalations}/{n} | {r.unsupported} | {r.schema_errors} | {r.grounded}/{n} | "
                     f"{r.useful_checks}/{n} | {r.p50:.0f} | {r.p95:.0f} |")
    return "\n".join(lines)


# --- troubleshooting: can the model use tools to find the cause and the right fix? ---------------

@dataclass
class TroubleScenario:
    name: str
    incident: Incident
    evidence: list[EvidenceItem]
    snapshot: Snapshot
    logs: str
    cause_words: tuple[str, ...]
    right_fix: str | None


def _deployment_objects(name: str, revisions: list[str], pod_status: dict, events: list[dict]) -> Snapshot:
    snap = Snapshot(cluster="lab", taken_at=T0)
    dep_uid = f"uid-{name}"
    rss = []
    for i, image in enumerate(revisions, start=1):
        rss.append({"metadata": {"name": f"{name}-rs{i}", "namespace": "lab", "uid": f"rs-{name}-{i}",
                                 "annotations": {"deployment.kubernetes.io/revision": str(i)},
                                 "ownerReferences": [{"kind": "Deployment", "name": name, "uid": dep_uid,
                                                      "controller": True}]},
                    "spec": {"replicas": 1 if i == len(revisions) else 0,
                             "template": {"spec": {"containers": [{"name": "app", "image": image}]}}}})
    pod = {"metadata": {"name": f"{name}-abc-1", "namespace": "lab", "uid": f"pod-{name}",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": f"{name}-rs{len(revisions)}",
                                             "uid": f"rs-{name}-{len(revisions)}", "controller": True}]},
           "spec": {"containers": [{"name": "app", "image": revisions[-1],
                                    "env": [{"name": "DB_PASSWORD", "value": "not-for-the-model"}]}]},
           "status": {"phase": "Running", "containerStatuses": [pod_status]}}
    dep = {"metadata": {"name": name, "namespace": "lab", "uid": dep_uid,
                        "annotations": {"deployment.kubernetes.io/revision": str(len(revisions))}},
           "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "app", "image": revisions[-1]}]}}},
           "status": {"replicas": 1, "readyReplicas": 0}}
    snap.pods["lab"], snap.replicasets["lab"], snap.deployments["lab"] = [pod], rss, [dep]
    snap.events["lab"] = events
    return snap


def _trouble() -> list[TroubleScenario]:
    crash = _container("crash-config", "Error", 1)
    crash_status = {"name": "app", "ready": False, "restartCount": 5, "image": "registry.example/app:3.1",
                    "imageID": "sha256:1", "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    "lastState": {"terminated": {"reason": "Error", "exitCode": 1}}}
    d1 = {"rule": "restarts", "containers": [crash]}
    pull_status = {"name": "app", "ready": False, "restartCount": 0, "image": "", "imageID": "",
                   "state": {"waiting": {"reason": "ImagePullBackOff"}}}
    d2 = {"rule": "imagePull", "containers": [{"pod": "image-tag-abc-1", "container": "app",
                                              "waitingReason": "ImagePullBackOff",
                                              "specImage": "registry.example/web:2.4.1"}]}
    pull_event = {"metadata": {"name": "ev1", "uid": "ev1"}, "type": "Warning", "reason": "Failed", "count": 4,
                  "involvedObject": {"kind": "Pod", "name": "image-tag-abc-1"},
                  "message": 'Failed to pull image "registry.example/web:2.4.1": manifest unknown',
                  "lastTimestamp": "2026-11-15T12:00:30Z"}
    return [
        TroubleScenario(
            "crash-config", _inc("crash-config", "restarts", "Container app is in CrashLoopBackOff", d1),
            [_ev("e1", "rule", "Container app is in CrashLoopBackOff", d1)],
            _deployment_objects("crash-config", ["registry.example/app:3.1"], crash_status, []),
            "starting app 3.1\nreading /etc/app/config.yaml\nfatal: config file /etc/app/config.yaml not found\n",
            ("config",), None),
        TroubleScenario(
            "image-tag", _inc("image-tag", "imagePull", "ImagePullBackOff for image registry.example/web:2.4.1", d2),
            [_ev("e1", "rule", "ImagePullBackOff for image registry.example/web:2.4.1", d2)],
            _deployment_objects("image-tag", ["registry.example/web:2.4.0", "registry.example/web:2.4.1"],
                                pull_status, [pull_event]),
            "", ("tag", "manifest", "2.4.1", "does not exist", "not found"), "rollback-deployment"),
    ]


TROUBLE = _trouble()


@dataclass
class TroubleRow:
    model: str
    used_tools: int = 0
    causes_found: int = 0
    right_fix: int = 0
    steps: list[int] = field(default_factory=list)
    seconds: list[float] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)


def troubleshoot_bench(clients: dict, max_steps: int = 4, think: bool = True, step_timeout: str = "180s") -> list[TroubleRow]:
    from .troubleshoot import Troubleshooter

    cfg = Config.model_validate({
        "access": {"profile": "remediate"},
        "actions": {"enabled": True, "allowed": ["restart-deployment", "rollback-deployment"]},
        "experimental": {"troubleshoot": {"enabled": True, "maxSteps": max_steps, "think": think,
                                          "stepTimeout": step_timeout, "proposeFixes": True}}})
    rows = []
    for name, client in clients.items():
        row = TroubleRow(name)
        for sc in TROUBLE:
            store = Store(":memory:")
            store.save_incident(sc.incident)
            store.add_evidence(sc.incident.id, list(sc.evidence))

            def read_log(*_a, _text=sc.logs, **_kw):
                return _text

            ts = Troubleshooter(cfg, store, client, lambda sc=sc: sc.snapshot, read_log, model_name=name)
            start = time.monotonic()
            inv = ts.run(sc.incident.id, T0 + timedelta(minutes=6))
            row.seconds.append(time.monotonic() - start)
            row.steps.append(len(inv.steps))
            row.statuses.append(inv.status)
            row.used_tools += any(s["status"] == "ok" and s["tool"] != "finish" for s in inv.steps)
            text = " ".join(f["text"].lower() for f in inv.conclusion.get("findings", [])) + " " + \
                inv.conclusion.get("summary", "").lower()
            row.causes_found += any(w in text for w in sc.cause_words)
            fix = (inv.conclusion.get("fix") or {}).get("action")
            row.right_fix += fix == sc.right_fix
            print(f"  {name} {sc.name}: {inv.status}, tools {[s['tool'] for s in inv.steps]}, fix {fix}, "
                  f"{row.seconds[-1]:.0f}s", file=sys.stderr)
        rows.append(row)
    return rows


def render_trouble(rows: list[TroubleRow]) -> str:
    n = len(TROUBLE)
    lines = [f"Troubleshooting on {n} scenarios (tools, cause in the findings, right fix or rightly none)", "",
             "| model | used tools | cause found | right fix | steps | seconds (each) | status |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r.model} | {r.used_tools}/{n} | {r.causes_found}/{n} | {r.right_fix}/{n} | "
                     f"{', '.join(map(str, r.steps))} | {', '.join(f'{x:.0f}' for x in r.seconds)} | "
                     f"{', '.join(r.statuses)} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kubeness-compare")
    ap.add_argument("--url", default="http://127.0.0.1:11434")
    ap.add_argument("--models", help="comma separated; default: every model the runtime has")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--small", help="small model for tiered strategies, e.g. qwen3:0.6b")
    ap.add_argument("--troubleshoot", action="store_true", help="also run the troubleshooting scenarios")
    ap.add_argument("--no-think", action="store_true", help="troubleshoot with thinking off")
    ap.add_argument("--skip-analysis", action="store_true", help="only the troubleshooting scenarios")
    ap.add_argument("--json", help="also write the results as JSON to this file")
    args = ap.parse_args(argv)
    names = args.models.split(",") if args.models else [
        m["name"] for m in httpx.get(f"{args.url}/api/tags", timeout=10).json().get("models", [])]
    clients = {n: OllamaClient(args.url, n, False, args.threads) for n in names}
    out: dict = {"loadSeconds": {}}
    think = not args.no_think
    for n, c in clients.items():   # cold load per model, so the timed runs below are warm
        start = time.monotonic()
        try:
            c.chat([{"role": "user", "content": "ok"}], {"type": "object"}, 600)
        except (httpx.HTTPError, KeyError, ValueError):
            pass
        out["loadSeconds"][n] = round(time.monotonic() - start, 1)
    print("Cold load and first answer (s): " + ", ".join(f"{n} {t}" for n, t in out["loadSeconds"].items()))
    print()
    if args.skip_analysis:
        pass
    elif args.small:
        rows = strategies(clients, args.small, [n for n in names if n != args.small])
        print(render_strategies(rows))
        out["strategies"] = [{**r.__dict__, "p50": r.p50, "p95": r.p95} for r in rows]
    else:
        rows = compare(clients)
        print(render(rows))
        out["models"] = [{**r.__dict__, "p50": r.p50, "p95": r.p95} for r in rows]
    if args.troubleshoot:
        trows = troubleshoot_bench({n: OllamaClient(args.url, n, think, args.threads) for n in names}, think=think)
        print(f"(thinking {'on' if think else 'off'})")
        print()
        print(render_trouble(trows))
        out["troubleshooting"] = [r.__dict__ for r in trows]
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
