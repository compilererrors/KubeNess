"""Alarm rules.

A rule looks at a snapshot and returns one Evaluation per workload in scope,
also for healthy workloads, so the lifecycle can see recovery:

* matching:      the condition holds right now (an incident may be pending)
* firing:        the condition has held long enough to raise an incident
* healthy_since: when the workload became healthy for this rule, or None.
                 Recovery is judged on this, not on the absence of new events.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .config import AlarmsConfig
from .snapshot import ContainerView, Snapshot, WorkloadRef, condition, containers, meta, parse_time
from .tracker import SinceTracker

PULL_REASONS = {"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull"}
ROLLOUT_DONE_REASON = "NewReplicaSetAvailable"


@dataclass
class Evaluation:
    rule_id: str
    workload: WorkloadRef
    matching: bool
    firing: bool
    healthy_since: datetime | None
    reason: str = ""
    details: dict = field(default_factory=dict)
    pods: list[str] = field(default_factory=list)
    # Raise the incident's severity to at least this (e.g. a repeated OOM kill).
    severity: str | None = None


class Rule:
    rule_id: str = ""

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        raise NotImplementedError


def _container_facts(c: ContainerView) -> dict:
    facts: dict = {
        "pod": c.pod,
        "container": c.name,
        "init": c.init,
        "ready": c.ready,
        "restartCount": c.restart_count,
        "image": c.image,
        "state": next(iter(c.state), None),
    }
    if c.waiting_reason:
        facts["waitingReason"] = c.waiting_reason
    if c.waiting_message:
        facts["waitingMessage"] = c.waiting_message
    term = c.last_termination
    if term:
        facts["lastTermination"] = {
            k: term.get(k) for k in ("reason", "exitCode", "startedAt", "finishedAt") if term.get(k) is not None
        }
    return facts


def _all_running_ready_since(pods: list[dict]) -> datetime | None:
    """Latest container start time when every regular container is running and ready.

    Uses the API's startedAt, so a crash between two evaluations still moves the
    time forward and restarts the recovery window.
    """
    latest: datetime | None = None
    seen = False
    for pod in pods:
        for c in containers(pod, include_init=False):
            seen = True
            if not (c.running and c.ready):
                return None
            started = c.started_at
            if started and (latest is None or started > latest):
                latest = started
    if not seen:
        return None
    return latest


class RestartRule(Rule):
    """Repeated restarts or a crash loop that persists.

    Counting restarts alone is not enough: kubelet backs off 10s, 20s, 40s ... up
    to five minutes between restarts, so the rate drops while the container keeps
    crashing. The rule therefore also fires on a CrashLoopBackOff that persists.
    """

    rule_id = "restarts"

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.cfg = cfg.restarts
        self._history: dict[tuple[str, str], deque[tuple[datetime, int]]] = {}
        self._crash_loop = SinceTracker(grace=timedelta(minutes=2))

    def _increments(self, c: ContainerView, pod_uid: str, now: datetime) -> int:
        key = (pod_uid, c.name)
        hist = self._history.setdefault(key, deque())
        hist.append((now, c.restart_count))
        while len(hist) > 1 and now - hist[1][0] >= self.cfg.window:
            hist.popleft()
        return max(0, c.restart_count - hist[0][1])

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        out: list[Evaluation] = []
        seen_containers: set[tuple[str, str]] = set()
        seen_workloads: set[str] = set()
        for ns in sorted(snapshot.namespaces):
            for wl, pods in snapshot.pods_by_workload(ns).items():
                seen_workloads.add(wl.uid)
                increments = 0
                looping: list[ContainerView] = []
                facts: list[dict] = []
                for pod in pods:
                    uid = meta(pod).get("uid", "")
                    for c in containers(pod):
                        seen_containers.add((uid, c.name))
                        inc = self._increments(c, uid, now)
                        increments += inc
                        if self._is_crash_looping(c, now):
                            looping.append(c)
                        if inc or c.restart_count or c.waiting_reason:
                            facts.append(_container_facts(c))
                since = self._crash_loop.update(wl.uid, bool(looping), now)
                healthy_since = _all_running_ready_since(pods)
                # Restarts stay in the window for five minutes after a fix; they
                # only count as a current problem while the workload is unhealthy.
                burst = increments >= self.cfg.count and healthy_since is None
                persistent = since is not None and now - since >= self.cfg.crash_loop_for
                if increments >= self.cfg.count:
                    reason = f"{increments} restarts within {_fmt(self.cfg.window)}"
                elif looping:
                    reason = f"CrashLoopBackOff in container {looping[0].name}"
                elif since is not None:
                    reason = "Crash loop (container briefly running between crashes)"
                else:
                    reason = ""
                out.append(
                    Evaluation(
                        rule_id=self.rule_id,
                        workload=wl,
                        matching=increments > 0 or since is not None,
                        firing=(burst or persistent) and healthy_since is None,
                        healthy_since=healthy_since,
                        reason=reason,
                        details={
                            "restartsInWindow": increments,
                            "crashLoopSince": since.isoformat() if since else None,
                            "containers": facts,
                        },
                        pods=sorted(meta(p).get("name", "") for p in pods),
                    )
                )
        for key in list(self._history):
            if key not in seen_containers:
                del self._history[key]
        self._crash_loop.retain(seen_workloads)
        return out

    def _is_crash_looping(self, c: ContainerView, now: datetime) -> bool:
        if c.waiting_reason == "CrashLoopBackOff":
            return True
        term = c.last_termination
        if c.restart_count and term and not c.ready:
            finished = parse_time(term.get("finishedAt"))
            return finished is not None and now - finished <= timedelta(minutes=10)
        return False


class ImagePullRule(Rule):
    rule_id = "imagePull"

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.cfg = cfg.image_pull
        # ErrImagePull and ImagePullBackOff alternate; both count as the same failure.
        self._failing = SinceTracker(grace=timedelta(seconds=30))
        self._healthy = SinceTracker()

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        out: list[Evaluation] = []
        seen: set[str] = set()
        for ns in sorted(snapshot.namespaces):
            for wl, pods in snapshot.pods_by_workload(ns).items():
                seen.add(wl.uid)
                failing = [c for p in pods for c in containers(p) if c.waiting_reason in PULL_REASONS]
                # Healthy for this rule: every container's image has been pulled.
                pulled = all(
                    c.waiting_reason not in PULL_REASONS and bool(c.status.get("imageID"))
                    for p in pods
                    for c in containers(p)
                )
                since = self._failing.update(wl.uid, bool(failing), now)
                healthy_since = self._healthy.update(wl.uid, pulled and not failing, now)
                specs = _spec_images(pods)
                out.append(
                    Evaluation(
                        rule_id=self.rule_id,
                        workload=wl,
                        matching=since is not None,
                        firing=since is not None and now - since >= self.cfg.for_,
                        healthy_since=healthy_since,
                        reason=(
                            f"{failing[0].waiting_reason} for image {specs.get((failing[0].pod, failing[0].name), '?')}"
                            if failing
                            else ""
                        ),
                        details={
                            "failingSince": since.isoformat() if since else None,
                            "containers": [
                                {**_container_facts(c), "specImage": specs.get((c.pod, c.name))} for c in failing
                            ],
                        },
                        pods=sorted(meta(p).get("name", "") for p in pods),
                    )
                )
        self._failing.retain(seen)
        self._healthy.retain(seen)
        return out


def _spec_images(pods: list[dict]) -> dict[tuple[str, str], str]:
    """Exact image reference from the pod spec; status.image may be empty while pulling."""
    out: dict[tuple[str, str], str] = {}
    for pod in pods:
        name = meta(pod).get("name", "")
        spec = pod.get("spec") or {}
        for c in (spec.get("initContainers") or []) + (spec.get("containers") or []):
            out[(name, c.get("name", ""))] = c.get("image", "")
    return out


class ReadinessRule(Rule):
    """Too few ready replicas on a Deployment.

    Progressing=False with ProgressDeadlineExceeded is the Deployment's own
    signal for a stuck rollout and fires at once. Otherwise the rule waits for
    `for` and ignores rollouts that are still progressing.
    """

    rule_id = "readiness"

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.cfg = cfg.readiness
        self._short = SinceTracker()
        self._healthy = SinceTracker()

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        out: list[Evaluation] = []
        seen: set[str] = set()
        for ns in sorted(snapshot.namespaces):
            pods_by_wl = snapshot.pods_by_workload(ns)
            for dep in snapshot.deployments.get(ns, []):
                m = meta(dep)
                if m.get("deletionTimestamp"):
                    continue
                desired = (dep.get("spec") or {}).get("replicas", 1)
                if desired == 0:
                    continue
                wl = WorkloadRef("Deployment", ns, m.get("name", ""), m.get("uid", ""))
                seen.add(wl.uid)
                status = dep.get("status") or {}
                ready = status.get("readyReplicas") or 0
                progressing = condition(dep, "Progressing") or {}
                deadline = progressing.get("status") == "False" and progressing.get("reason") == "ProgressDeadlineExceeded"
                rolling = (
                    progressing.get("status") == "True" and progressing.get("reason") != ROLLOUT_DONE_REASON
                ) or (status.get("observedGeneration") or 0) < (m.get("generation") or 0)
                short = ready < desired
                since = self._short.update(wl.uid, short and not rolling, now)
                healthy_since = self._healthy.update(wl.uid, not short and not deadline, now)
                firing = deadline or (since is not None and now - since >= self.cfg.for_)
                if deadline:
                    reason = f"Rollout stuck: ProgressDeadlineExceeded ({ready}/{desired} ready)"
                elif short:
                    reason = f"{ready}/{desired} replicas ready"
                else:
                    reason = ""
                pods = pods_by_wl.get(wl, [])
                out.append(
                    Evaluation(
                        rule_id=self.rule_id,
                        workload=wl,
                        matching=deadline or since is not None,
                        firing=firing,
                        healthy_since=healthy_since,
                        reason=reason,
                        details={
                            "desiredReplicas": desired,
                            "readyReplicas": ready,
                            "updatedReplicas": status.get("updatedReplicas") or 0,
                            "rolloutInProgress": rolling,
                            "progressing": {k: progressing.get(k) for k in ("status", "reason", "message")}
                            if progressing
                            else None,
                            "notReadyContainers": [
                                _container_facts(c) for p in pods for c in containers(p, False) if not c.ready
                            ],
                            "podLabels": (((dep.get("spec") or {}).get("template") or {}).get("metadata") or {})
                            .get("labels") or {},
                        },
                        pods=sorted(meta(p).get("name", "") for p in pods),
                    )
                )
        self._short.retain(seen)
        self._healthy.retain(seen)
        return out


def _fmt(d: timedelta) -> str:
    s = int(d.total_seconds())
    if s % 3600 == 0:
        return f"{s // 3600}h"
    if s % 60 == 0:
        return f"{s // 60}m"
    return f"{s}s"


class SchedulingRule(Rule):
    """A pod stays Pending because the scheduler finds no node (PodScheduled=False,
    reason Unschedulable). Other Pending reasons, such as an image pull, are not
    scheduling failures."""

    rule_id = "scheduling"

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.cfg = cfg.scheduling
        self._failing = SinceTracker()
        self._healthy = SinceTracker()

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        out: list[Evaluation] = []
        seen: set[str] = set()
        for ns in sorted(snapshot.namespaces):
            for wl, pods in snapshot.pods_by_workload(ns).items():
                seen.add(wl.uid)
                stuck = []
                for p in pods:
                    cond = condition(p, "PodScheduled") or {}
                    if cond.get("status") == "False" and cond.get("reason") == "Unschedulable":
                        stuck.append((p, cond))
                since = self._failing.update(wl.uid, bool(stuck), now)
                healthy_since = self._healthy.update(wl.uid, not stuck, now)
                details = {"pods": [{
                    "pod": meta(p).get("name", ""),
                    "message": c.get("message", ""),
                    "requests": {x.get("name", ""): (x.get("resources") or {}).get("requests", {})
                                 for x in (p.get("spec") or {}).get("containers") or []},
                    "nodeSelector": (p.get("spec") or {}).get("nodeSelector") or {},
                    "tolerations": len((p.get("spec") or {}).get("tolerations") or []),
                } for p, c in stuck]}
                reason = ""
                if stuck:
                    reason = f"Pod {meta(stuck[0][0]).get('name', '')} cannot be scheduled: {stuck[0][1].get('message', '')}"
                out.append(Evaluation(self.rule_id, wl, since is not None,
                                      since is not None and now - since >= self.cfg.for_, healthy_since,
                                      reason[:400], details, sorted(meta(p).get("name", "") for p in pods)))
        self._failing.retain(seen)
        self._healthy.retain(seen)
        return out


class OomRule(Rule):
    """A container was OOM killed. Each new kill fires (or reopens) the incident;
    a second kill within the window raises it from info to warning. Kills that
    finished before the observer started are not reported."""

    rule_id = "oom"

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.window = cfg.oom.window
        self.started: datetime | None = None
        self.seen: set[tuple[str, str, str]] = set()
        self.kills: dict[str, list[datetime]] = {}

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        if self.started is None:
            self.started = now
        # Forget pods and workloads that are gone, so the state stays bounded.
        current = {meta(p).get("uid", "") for ns in snapshot.namespaces for p in snapshot.pods.get(ns, [])}
        self.seen = {k for k in self.seen if k[0] in current}
        self.kills = {k: [x for x in v if now - x <= self.window] for k, v in self.kills.items()}
        self.kills = {k: v for k, v in self.kills.items() if v}
        out: list[Evaluation] = []
        for ns in sorted(snapshot.namespaces):
            for wl, pods in snapshot.pods_by_workload(ns).items():
                new, facts, limits = [], [], {}
                for p in pods:
                    for x in (p.get("spec") or {}).get("containers") or []:
                        limits[(meta(p).get("name", ""), x.get("name", ""))] = \
                            ((x.get("resources") or {}).get("limits") or {}).get("memory")
                for p in pods:
                    for c in containers(p):
                        term = c.last_termination or (c.state.get("terminated") or {})
                        if term.get("reason") != "OOMKilled":
                            continue
                        finished = parse_time(term.get("finishedAt"))
                        key = (meta(p).get("uid", ""), c.name, term.get("finishedAt") or "")
                        if key in self.seen:
                            continue
                        self.seen.add(key)
                        # Before the observer started, or inside a crash loop (the restart
                        # incident covers that, and its runbook names the OOM kill).
                        if finished is None or finished < self.started or c.waiting_reason == "CrashLoopBackOff":
                            continue
                        new.append(finished)
                        facts.append({**_container_facts(c), "memoryLimit": limits.get((c.pod, c.name))})
                kills = [k for k in self.kills.get(wl.uid, []) + new if now - k <= self.window]
                self.kills[wl.uid] = kills
                ready_since = _all_running_ready_since(pods) if not new else None
                limit = facts[0]["memoryLimit"] if facts else None
                reason = ""
                if new:
                    reason = (f"Container {facts[0]['container']} was OOM killed"
                              + (f" (memory limit {limit})" if limit else " (no memory limit)")
                              + (f"; {len(kills)} kills within {_fmt(self.window)}" if len(kills) > 1 else ""))
                out.append(Evaluation(self.rule_id, wl, bool(new), bool(new), ready_since, reason,
                                      {"containers": facts, "killsInWindow": len(kills)} if new else {},
                                      sorted(meta(p).get("name", "") for p in pods),
                                      severity="warning" if len(kills) > 1 else None))
        return out


class ObserverDegradedRule(Rule):
    """The observer's own collection: firing while a watched namespace is stale,
    i.e. pods, replicasets or deployments were not observed within the freshness
    budget. The snapshot already applies the budget, so there is no extra delay."""

    rule_id = "observerDegraded"
    CORE = ("pods", "replicasets", "deployments")

    def __init__(self, cfg: AlarmsConfig) -> None:
        self.fresh_since: dict[str, datetime] = {}

    def evaluate(self, snapshot: Snapshot, now: datetime) -> list[Evaluation]:
        out = []
        for ns in sorted(snapshot.namespaces | set(snapshot.sources)):
            wl = WorkloadRef("Observer", ns, "observations", f"observer-{ns}")
            sources = [s for s in snapshot.sources.get(ns, []) if s["kind"] in self.CORE]
            # Stale means "do not trust the cached state"; degraded additionally needs
            # the budget to have run out (not just a source that is still starting).
            stale = ns in snapshot.stale_namespaces and (
                not sources or any(s.get("overdue", True) for s in sources))
            if not stale:
                self.fresh_since.setdefault(ns, now)
                out.append(Evaluation(self.rule_id, wl, False, False, self.fresh_since[ns]))
                continue
            self.fresh_since.pop(ns, None)
            bad = [s for s in sources if not s["fresh"]] or sources
            errors = sorted({s["error"] for s in bad if s["error"]})
            last = max((s["lastSuccess"] for s in bad if s["lastSuccess"]), default=None)
            kinds = ", ".join(s["kind"] for s in bad) or "sources"
            reason = (f"Observations of namespace {ns} are stale: {kinds} not refreshed within the freshness budget"
                      + (f" (last success {last})" if last else " (never observed)")
                      + (f"; last error: {errors[0]}" if errors else ""))
            out.append(Evaluation(self.rule_id, wl, True, True, None, reason,
                                  {"namespace": ns, "sources": sources, "errors": errors}, []))
        return out


RULES = {"restarts": RestartRule, "imagePull": ImagePullRule, "readiness": ReadinessRule,
         "scheduling": SchedulingRule, "oom": OomRule, "observerDegraded": ObserverDegradedRule}

DEFAULT_SEVERITY = {"restarts": "warning", "imagePull": "warning", "readiness": "warning",
                    "scheduling": "warning", "oom": "info", "observerDegraded": "warning"}
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}

# A readiness incident is not opened while a restart or image pull incident is
# firing for the same workload; the root cause is already reported.
INHIBITED_BY = {"readiness": {"restarts", "imagePull", "scheduling"}, "oom": {"restarts"}}


def build_rules(cfg: AlarmsConfig) -> list[Rule]:
    return [RULES[r](cfg) for r in cfg.rules]
