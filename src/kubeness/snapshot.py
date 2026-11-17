"""A point-in-time view of the watched objects, plus helpers for reading them.

Objects are plain dicts in Kubernetes JSON form (camelCase keys), which keeps
rules testable with fixtures and independent of the client library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class WorkloadRef:
    kind: str
    namespace: str
    name: str
    uid: str

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass
class Snapshot:
    cluster: str
    taken_at: datetime
    pods: dict[str, list[dict]] = field(default_factory=dict)
    replicasets: dict[str, list[dict]] = field(default_factory=dict)
    deployments: dict[str, list[dict]] = field(default_factory=dict)
    events: dict[str, list[dict]] = field(default_factory=dict)
    stale_namespaces: set[str] = field(default_factory=set)
    # Collection status per namespace: kind, fresh, error, lastSuccess.
    sources: dict[str, list[dict]] = field(default_factory=dict)
    _by_workload: dict = field(default_factory=dict, init=False, repr=False, compare=False)

    @property
    def namespaces(self) -> set[str]:
        return set(self.pods) | set(self.deployments) | set(self.replicasets)

    def active_pods(self, namespace: str) -> list[dict]:
        return [p for p in self.pods.get(namespace, []) if not meta(p).get("deletionTimestamp")]

    def pods_by_workload(self, namespace: str) -> dict[WorkloadRef, list[dict]]:
        """Grouped once per snapshot; every rule asks for the same grouping."""
        if namespace not in self._by_workload:
            self._by_workload[namespace] = self._group(namespace)
        return self._by_workload[namespace]

    def _group(self, namespace: str) -> dict[WorkloadRef, list[dict]]:
        rs_by_uid = {meta(rs).get("uid"): rs for rs in self.replicasets.get(namespace, [])}
        out: dict[WorkloadRef, list[dict]] = {}
        for pod in self.active_pods(namespace):
            out.setdefault(resolve_workload(pod, rs_by_uid), []).append(pod)
        return out


def meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def controller_owner(obj: dict) -> dict | None:
    for ref in meta(obj).get("ownerReferences") or []:
        if ref.get("controller"):
            return ref
    return None


def resolve_workload(pod: dict, replicasets_by_uid: dict[str, dict]) -> WorkloadRef:
    """Follow owner references Pod -> ReplicaSet -> Deployment.

    A new ReplicaSet created by a rollout therefore maps to the same workload,
    so it does not open a new incident.
    """
    m = meta(pod)
    ns = m.get("namespace", "")
    owner = controller_owner(pod)
    if owner is None:
        return WorkloadRef("Pod", ns, m.get("name", ""), m.get("uid", ""))
    if owner.get("kind") == "ReplicaSet":
        rs = replicasets_by_uid.get(owner.get("uid"))
        rs_owner = controller_owner(rs) if rs else None
        if rs_owner and rs_owner.get("kind") == "Deployment":
            return WorkloadRef("Deployment", ns, rs_owner["name"], rs_owner["uid"])
    return WorkloadRef(owner.get("kind", ""), ns, owner.get("name", ""), owner.get("uid", ""))


@dataclass(frozen=True)
class ContainerView:
    pod: str
    name: str
    init: bool
    status: dict

    @property
    def state(self) -> dict:
        return self.status.get("state") or {}

    @property
    def waiting_reason(self) -> str | None:
        return (self.state.get("waiting") or {}).get("reason")

    @property
    def waiting_message(self) -> str | None:
        return (self.state.get("waiting") or {}).get("message")

    @property
    def running(self) -> bool:
        return "running" in self.state

    @property
    def started_at(self) -> datetime | None:
        return parse_time((self.state.get("running") or {}).get("startedAt"))

    @property
    def ready(self) -> bool:
        return bool(self.status.get("ready"))

    @property
    def restart_count(self) -> int:
        return int(self.status.get("restartCount") or 0)

    @property
    def last_termination(self) -> dict | None:
        return (self.status.get("lastState") or {}).get("terminated")

    @property
    def image(self) -> str | None:
        return self.status.get("image")


def containers(pod: dict, include_init: bool = True) -> Iterator[ContainerView]:
    name = meta(pod).get("name", "")
    status = pod.get("status") or {}
    if include_init:
        for cs in status.get("initContainerStatuses") or []:
            yield ContainerView(name, cs.get("name", ""), True, cs)
    for cs in status.get("containerStatuses") or []:
        yield ContainerView(name, cs.get("name", ""), False, cs)


def condition(obj: dict, type_: str) -> dict | None:
    for c in (obj.get("status") or {}).get("conditions") or []:
        if c.get("type") == type_:
            return c
    return None
