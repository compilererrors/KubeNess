"""Bounded log collection for the evidence package."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .config import Config
from .redact import redact
from .rules import Evaluation
from .store import EvidenceItem

log = logging.getLogger(__name__)
LIMIT_BYTES = 16 * 1024
KUBELET_UNAVAILABLE = ("unable to retrieve container logs", "failed to try resolving symlinks")


class ReadLog(Protocol):
    def __call__(self, name: str, namespace: str, *, container: str, previous: bool,
                 tail_lines: int, since_seconds: int | None, limit_bytes: int) -> str: ...


@dataclass
class Collected:
    items: list[tuple[str, str, dict]]  # kind, summary, payload
    gaps: list[str]


def _targets(ev: Evaluation) -> list[tuple[str, str, bool]]:
    """(pod, container, previous) whose logs explain the failure."""
    d = ev.details
    if ev.rule_id == "restarts":
        out = []
        for c in d.get("containers") or []:
            if c.get("restartCount") or c.get("lastTermination"):
                out.append((c["pod"], c["container"], True))
        return out[:2]
    if ev.rule_id == "readiness":
        return [(c["pod"], c["container"], False) for c in (d.get("notReadyContainers") or [])][:2]
    return []  # imagePull: the container never started, there are no logs


class LogCollector:
    """Bounded collection at firing: container logs and, opt-in, node capacity."""

    def __init__(self, cfg: Config, read_log: ReadLog | None, read_nodes=None, read_services=None) -> None:
        self.cfg = cfg
        self.read_log = read_log
        self.read_nodes = read_nodes
        self.read_services = read_services

    def collect(self, ev: Evaluation) -> Collected:
        items: list[tuple[str, str, dict]] = []
        gaps: list[str] = []
        if ev.rule_id == "scheduling":
            self._nodes(items, gaps)
        if ev.rule_id == "readiness" and self.cfg.access.read_services and self.read_services is not None:
            self._services(ev, items, gaps)
        targets = _targets(ev)
        if not targets:
            return Collected(items, gaps)
        if not self.cfg.access.logs_allowed(ev.workload.namespace) or self.read_log is None:
            silo = self.cfg.access.silo_for(ev.workload.namespace)
            if silo is not None and not self.cfg.access.read_logs:
                gaps.append("Logs not collected: log access is disabled by the access profile.")
            elif silo is not None and silo.profile == "observe":
                gaps.append(f"Logs not collected: silo {silo.name} has the observe profile (no pods/log).")
            else:
                gaps.append("Logs not collected: log access is disabled by the access profile.")
            return Collected(items, gaps)
        for pod, container, previous in targets:
            item, reasons = self._fetch(ev.workload.namespace, pod, container, previous)
            if item is None and previous:
                # The previous container's logs disappear when the next restart
                # replaces it. The current instance usually logs the same failure.
                item, more = self._fetch(ev.workload.namespace, pod, container, False)
                reasons += more
                if item is not None:
                    item[2]["previousUnavailable"] = reasons[0]
                    item = (item[0], item[1] + f" (previous logs unavailable: {reasons[0]})", item[2])
            if item is not None:
                items.append(item)
            else:
                gaps.append(f"Logs of {pod}/{container} unavailable: " + "; ".join(reasons) + ".")
        return Collected(items, gaps)


    def _services(self, ev: Evaluation, items: list, gaps: list) -> None:
        labels = ev.details.get("podLabels") or {}
        try:
            services, slices = self.read_services(ev.workload.namespace)
        except Exception as e:
            gaps.append(f"Services unavailable: {getattr(e, 'status', None) or type(e).__name__}.")
            return
        out = []
        for svc in services:
            sel = (svc.get("spec") or {}).get("selector") or {}
            if not sel or any(labels.get(k) != v for k, v in sel.items()):
                continue
            name = (svc.get("metadata") or {}).get("name", "")
            eps = [e for s in slices if ((s.get("metadata") or {}).get("labels") or {}).get(
                "kubernetes.io/service-name") == name for e in s.get("endpoints") or []]
            ready = [e for e in eps if (e.get("conditions") or {}).get("ready")]
            not_ready = [e for e in eps if not (e.get("conditions") or {}).get("ready")]
            out.append({
                "name": name, "selector": sel, "ready": len(ready), "notReady": len(not_ready),
                "notReadyPods": sorted((e.get("targetRef") or {}).get("name", "") for e in not_ready)[:10],
                "ports": [f"{p.get('port')}->{p.get('targetPort', p.get('port'))}"
                          for p in (svc.get("spec") or {}).get("ports") or []][:5],
            })
        if not out:
            gaps.append(f"No Service selects the pods of {ev.workload.kind} {ev.workload.name}.")
            return
        summary = "; ".join(f"Service {s['name']}: {s['ready']} ready, {s['notReady']} not ready" for s in out)
        items.append(("service", summary[:400], {"services": out[:10]}))

    def _nodes(self, items: list, gaps: list) -> None:
        if not self.cfg.access.read_nodes or self.read_nodes is None:
            gaps.append("Node capacity not read: readNodes is disabled by the access profile.")
            return
        try:
            nodes = self.read_nodes()
        except Exception as e:
            gaps.append(f"Node capacity unavailable: {getattr(e, 'status', None) or type(e).__name__}.")
            return
        out = [{
            "name": (n.get("metadata") or {}).get("name", ""),
            "allocatable": {k: v for k, v in ((n.get("status") or {}).get("allocatable") or {}).items()
                            if k in ("cpu", "memory", "pods")},
            "taints": [f"{t.get('key')}:{t.get('effect')}" for t in (n.get("spec") or {}).get("taints") or []],
        } for n in nodes[:20]]
        summary = "nodes: " + "; ".join(
            f"{n['name']} cpu {n['allocatable'].get('cpu', '?')} memory {n['allocatable'].get('memory', '?')}"
            + (f" taints {', '.join(n['taints'])}" if n["taints"] else "") for n in out)
        items.append(("nodes", summary[:400], {"nodes": out}))

    def _fetch(self, ns: str, pod: str, container: str, previous: bool) -> tuple[tuple | None, list[str]]:
        which = "previous" if previous else "current"
        tail = self.cfg.collection.log_tail_lines
        try:
            # The window applies to current logs only: a previous container may
            # have stopped longer ago than the window during a long back-off.
            text = self.read_log(
                pod, ns, container=container, previous=previous, tail_lines=tail,
                since_seconds=None if previous else int(self.cfg.collection.log_window.total_seconds()),
                limit_bytes=LIMIT_BYTES,
            )
        except Exception as e:  # 400 when no such container instance exists, 403 without pods/log
            status = getattr(e, "status", None)
            return None, [f"{which} logs failed" + (f" with HTTP {status}" if status else f" ({type(e).__name__})")]
        text = text or ""
        # kubelet answers 200 with this text when the container's log file is gone.
        if text.strip().startswith(KUBELET_UNAVAILABLE):
            return None, [f"{which} logs no longer exist on the node"]
        if not text.strip():
            return None, [f"{which} logs are empty"]
        # The API applies tail and byte limits too; enforce them here as well so a
        # misbehaving source cannot grow the evidence package.
        text, cut = bound(text, tail, LIMIT_BYTES)
        text, redactions = redact(text)
        text, cut_after = bound(text, tail, LIMIT_BYTES)
        lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        truncated = cut or cut_after or lines >= tail or len(text.encode()) >= LIMIT_BYTES
        summary = f"{which} logs of {pod}/{container}: {lines} lines"
        if truncated:
            summary += f" (cut to the last {tail} lines or {LIMIT_BYTES // 1024} KiB)"
        if redactions:
            summary += f", {redactions} values masked"
        return ("log", summary, {
            "pod": pod, "container": container, "previous": previous, "text": text,
            "lines": lines, "truncated": truncated, "redactions": redactions,
        }), []


def bound(text: str, tail_lines: int, limit_bytes: int) -> tuple[str, bool]:
    """Keep the last `tail_lines` lines and at most `limit_bytes`, cut on a line boundary."""
    lines = text.splitlines(keepends=True)
    cut = len(lines) > tail_lines
    lines = lines[-tail_lines:]
    size = sum(len(line.encode()) for line in lines)
    while len(lines) > 1 and size > limit_bytes:
        size -= len(lines.pop(0).encode())
        cut = True
    out = "".join(lines)
    if size > limit_bytes:  # one line longer than the limit: keep its end
        out = out.encode()[-limit_bytes:].decode(errors="ignore")
        cut = True
    return out, cut


def kube_read_log() -> ReadLog:
    from kubernetes import client

    core = client.CoreV1Api()

    def read(name, namespace, *, container, previous, tail_lines, since_seconds, limit_bytes):
        kw = dict(container=container, previous=previous, tail_lines=tail_lines,
                  limit_bytes=limit_bytes, _request_timeout=5)
        if since_seconds:
            kw["since_seconds"] = since_seconds
        return core.read_namespaced_pod_log(name, namespace, **kw)

    return read


def kube_read_nodes():
    from kubernetes import client

    core = client.CoreV1Api()

    def read() -> list[dict]:
        return core.api_client.sanitize_for_serialization(core.list_node(_request_timeout=5).items)

    return read


def kube_read_services():
    from kubernetes import client

    core, discovery = client.CoreV1Api(), client.DiscoveryV1Api()

    def read(namespace: str) -> tuple[list[dict], list[dict]]:
        ser = core.api_client.sanitize_for_serialization
        return (ser(core.list_namespaced_service(namespace, _request_timeout=5).items),
                ser(discovery.list_namespaced_endpoint_slice(namespace, _request_timeout=5).items))

    return read


def as_evidence(collected: Collected, start: int, now: datetime) -> list[EvidenceItem]:
    out = []
    n = start
    for kind, summary, payload in collected.items:
        out.append(EvidenceItem(f"e{n}", now, kind, summary, payload))
        n += 1
    for gap in collected.gaps:
        out.append(EvidenceItem(f"e{n}", now, "gap", gap, {}))
        n += 1
    return out
