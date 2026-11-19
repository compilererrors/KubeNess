"""Incident lifecycle: pending -> firing -> recovering -> resolved.

* pending:    the condition holds but not yet long enough
* firing:     the incident is active
* recovering: the workload has been healthy for the settle period; waiting for
              the full recovery window
* resolved:   healthy for the whole recovery window, or the workload has been
              gone for the settle period

A failure during recovering returns the incident to firing without a new
notification. A firing signal within the reopen window after resolved reopens
the old incident and counts it as a recurrence.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from .config import AlarmsConfig
from .rules import DEFAULT_SEVERITY, Evaluation
from .snapshot import WorkloadRef


class State(StrEnum):
    PENDING = "pending"
    FIRING = "firing"
    RECOVERING = "recovering"
    RESOLVED = "resolved"


@dataclass
class Incident:
    id: str
    fingerprint: str
    rule_id: str
    cluster: str
    workload: WorkloadRef
    severity: str
    state: State
    reason: str
    first_seen: datetime
    last_observed: datetime
    details: dict = field(default_factory=dict)
    pods: list[str] = field(default_factory=list)
    pending_since: datetime | None = None
    firing_since: datetime | None = None
    recovering_since: datetime | None = None
    resolved_at: datetime | None = None
    recurrence_count: int = 0
    flap_count: int = 0
    stale: bool = False

    @property
    def is_open(self) -> bool:
        return self.state is not State.RESOLVED


@dataclass
class Transition:
    incident: Incident
    old: State | None
    new: State | None  # None means a pending incident was cancelled
    kind: str
    message: str
    # Resolved because the workload is gone, not because it recovered.
    gone: bool = False


def fingerprint(cluster: str, wl: WorkloadRef, rule_id: str) -> str:
    return f"{cluster}/{wl.namespace}/{wl.uid}/{rule_id}"


def new_incident_id(now: datetime) -> str:
    return f"inc-{now:%Y%m%d}-{secrets.token_hex(3)}"


def severity_for(rule_id: str, wl: WorkloadRef, cfg: AlarmsConfig) -> str:
    if wl.key in cfg.critical_workloads:
        return "critical"
    return DEFAULT_SEVERITY.get(rule_id, "warning")


def _observe(inc: Incident, ev: Evaluation, now: datetime) -> None:
    inc.last_observed = now
    inc.stale = False
    if ev.reason:
        inc.reason = ev.reason
        inc.details = ev.details
        inc.pods = ev.pods


def step(
    cluster: str,
    inc: Incident | None,
    ev: Evaluation | None,
    now: datetime,
    cfg: AlarmsConfig,
) -> tuple[Incident | None, list[Transition]]:
    """Advance one incident (or a candidate for one) by a single evaluation.

    `inc` is the open incident for the fingerprint, or the most recent resolved
    one, or None. `ev` is None when the rule no longer sees the workload; the
    engine passes that on only once the absence has lasted the settle period.
    """
    # --- no open incident -------------------------------------------------
    if inc is None or inc.state is State.RESOLVED:
        if ev is None or not ev.matching:
            return inc, []
        if inc is not None and inc.resolved_at and now - inc.resolved_at <= cfg.reopen_window:
            if not ev.firing:
                return inc, []  # wait until it fires again before reopening
            inc.state = State.FIRING
            inc.firing_since = now
            inc.recovering_since = None
            inc.resolved_at = None
            inc.recurrence_count += 1
            _observe(inc, ev, now)
            return inc, [Transition(inc, State.RESOLVED, State.FIRING, "reopened",
                                    f"Reopened: {inc.reason} (recurrence {inc.recurrence_count})")]
        new = Incident(
            id=new_incident_id(now),
            fingerprint=fingerprint(cluster, ev.workload, ev.rule_id),
            rule_id=ev.rule_id,
            cluster=cluster,
            workload=ev.workload,
            severity=severity_for(ev.rule_id, ev.workload, cfg),
            state=State.FIRING if ev.firing else State.PENDING,
            reason=ev.reason,
            first_seen=now,
            last_observed=now,
            details=ev.details,
            pods=ev.pods,
            pending_since=None if ev.firing else now,
            firing_since=now if ev.firing else None,
        )
        kind = "fired" if ev.firing else "pending"
        return new, [Transition(new, None, new.state, kind, f"{kind.capitalize()}: {new.reason}")]

    # --- open incident, workload gone ------------------------------------
    if ev is None:
        if inc.state is State.PENDING:
            return None, [Transition(inc, inc.state, None, "cancelled", "Workload no longer present")]
        old = inc.state
        inc.state = State.RESOLVED
        inc.resolved_at = now
        return inc, [Transition(inc, old, State.RESOLVED, "resolved", "Resolved: workload no longer present",
                                gone=True)]

    # --- pending -----------------------------------------------------------
    if inc.state is State.PENDING:
        if ev.firing:
            inc.state = State.FIRING
            inc.firing_since = now
            _observe(inc, ev, now)
            return inc, [Transition(inc, State.PENDING, State.FIRING, "fired", f"Fired: {inc.reason}")]
        if not ev.matching:
            return None, [Transition(inc, State.PENDING, None, "cancelled", "Condition cleared before firing")]
        _observe(inc, ev, now)
        return inc, []

    # --- firing / recovering --------------------------------------------------
    healthy_for = (now - ev.healthy_since) if ev.healthy_since else None
    if ev.matching or ev.reason:
        _observe(inc, ev, now)
    else:
        inc.last_observed = now
        inc.stale = False

    if inc.state is State.FIRING:
        if healthy_for is not None and healthy_for >= cfg.recovery_settle:
            inc.state = State.RECOVERING
            inc.recovering_since = ev.healthy_since
            return inc, [Transition(inc, State.FIRING, State.RECOVERING, "recovering",
                                    "Recovering: workload healthy, waiting for recovery window")]
        return inc, []

    # recovering
    if healthy_for is None:
        inc.state = State.FIRING
        inc.recovering_since = None
        inc.flap_count += 1
        return inc, [Transition(inc, State.RECOVERING, State.FIRING, "relapsed",
                                f"Back to firing during recovery: {inc.reason}")]
    inc.recovering_since = ev.healthy_since
    if healthy_for >= cfg.recovery_window:
        inc.state = State.RESOLVED
        inc.resolved_at = now
        return inc, [Transition(inc, State.RECOVERING, State.RESOLVED, "resolved",
                                "Resolved: healthy for the whole recovery window")]
    return inc, []
