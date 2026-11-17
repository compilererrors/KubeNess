"""Builders for Kubernetes objects in JSON form."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from kubeness.snapshot import Snapshot

T0 = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
NS = "lab"
DEP_UID = "dep-uid-1"
RS_UID = "rs-uid-1"


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def deployment(
    name: str = "web",
    uid: str = DEP_UID,
    replicas: int = 1,
    ready: int = 1,
    progressing: tuple[str, str] = ("True", "NewReplicaSetAvailable"),
    generation: int = 1,
    observed: int = 1,
) -> dict:
    return {
        "metadata": {"name": name, "namespace": NS, "uid": uid, "generation": generation},
        "spec": {"replicas": replicas},
        "status": {
            "observedGeneration": observed,
            "replicas": replicas,
            "readyReplicas": ready,
            "updatedReplicas": replicas,
            "conditions": [{"type": "Progressing", "status": progressing[0], "reason": progressing[1]}],
        },
    }


def replicaset(name: str = "web-abc", uid: str = RS_UID, dep_name: str = "web", dep_uid: str = DEP_UID) -> dict:
    return {
        "metadata": {
            "name": name,
            "namespace": NS,
            "uid": uid,
            "ownerReferences": [{"kind": "Deployment", "name": dep_name, "uid": dep_uid, "controller": True}],
        }
    }


def pod(
    name: str = "web-abc-1",
    uid: str = "pod-uid-1",
    statuses: list[dict] | None = None,
    owner: dict | None = None,
    image: str = "ghcr.io/example/web:1.0",
) -> dict:
    owner = owner if owner is not None else {"kind": "ReplicaSet", "name": "web-abc", "uid": RS_UID, "controller": True}
    statuses = statuses or [running()]
    return {
        "metadata": {"name": name, "namespace": NS, "uid": uid, "ownerReferences": [owner] if owner else []},
        "spec": {"containers": [{"name": s["name"], "image": image} for s in statuses]},
        "status": {"containerStatuses": statuses},
    }


def running(name: str = "app", started: datetime = T0, ready: bool = True, restarts: int = 0,
            last_finished: datetime | None = None) -> dict:
    s = {
        "name": name,
        "ready": ready,
        "restartCount": restarts,
        "image": "ghcr.io/example/web:1.0",
        "imageID": "sha256:abc",
        "state": {"running": {"startedAt": iso(started)}},
    }
    if last_finished:
        s["lastState"] = {"terminated": {"reason": "Error", "exitCode": 1, "finishedAt": iso(last_finished)}}
    return s


def waiting(name: str = "app", reason: str = "CrashLoopBackOff", restarts: int = 0,
            last_finished: datetime | None = None, message: str = "", image_id: str = "sha256:abc") -> dict:
    s = {
        "name": name,
        "ready": False,
        "restartCount": restarts,
        "image": "ghcr.io/example/web:1.0",
        "imageID": image_id,
        "state": {"waiting": {"reason": reason, "message": message}},
    }
    if last_finished:
        s["lastState"] = {"terminated": {"reason": "Error", "exitCode": 1, "finishedAt": iso(last_finished)}}
    return s


def event(reason: str, message: str, obj_name: str, t: datetime, uid: str, typ: str = "Warning") -> dict:
    return {
        "metadata": {"name": f"{obj_name}.{uid}", "namespace": NS, "uid": uid},
        "involvedObject": {"kind": "Pod", "name": obj_name, "namespace": NS},
        "reason": reason,
        "message": message,
        "type": typ,
        "count": 1,
        "lastTimestamp": iso(t),
    }


def snap(now: datetime, pods: list[dict] | None = None, deployments: list[dict] | None = None,
         replicasets: list[dict] | None = None, events: list[dict] | None = None,
         stale: bool = False) -> Snapshot:
    s = Snapshot(cluster="lab", taken_at=now)
    s.pods[NS] = pods if pods is not None else []
    s.deployments[NS] = deployments if deployments is not None else [deployment()]
    s.replicasets[NS] = replicasets if replicasets is not None else [replicaset()]
    s.events[NS] = events or []
    if stale:
        s.stale_namespaces.add(NS)
    return s
