"""Notifications, observer side: policy, payload, outbox sender and heartbeat.

The rule loop only writes to the outbox. A separate sender thread delivers
through the notifier pod, which alone holds the provider credential. The observer
owns retries and status; a duplicate after a crash is possible, a silent loss is not.

Policy:

* fired      -> firing
* reopened   -> reopened, unless an alert went out less than repeatInterval ago
                (flap limit; the suppression is recorded as activity)
* relapsed   -> nothing: back to firing during recovery is not news
* escalated  -> escalated
* resolved   -> resolved, only when an alert went out since the last recovery
* firing for repeatInterval since the last alert -> repeat
* firing with no alert yet (it fired during a silence) -> firing once the silence ends
* severity info -> no immediate notification, an item in the digest; raising it
  to warning sends escalated

Digest: info events (new images, recurrences, restarts without a firing restart
incident, info incidents) are stored as items and sent as one notification per
digestInterval, only when there is at least one item.

The payload is built from the incident and the deterministic template analysis.
Model text is never sent, every field is masked again, and raw logs are never included.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Callable, Iterable, Protocol

import httpx

from .analysis import Analysis, template_analysis
from .config import Config
from .lifecycle import Incident, State, Transition
from .notification import NotificationPayload, render_text
from .redact import redact
from .snapshot import Snapshot, containers, meta, utcnow
from .store import OUTBOXES, OutboxItem, Store

log = logging.getLogger(__name__)

ALERT_EVENTS = ("firing", "reopened", "repeat")
# Events after which a recovery is worth announcing.
ANNOUNCED = ALERT_EVENTS + ("escalated",)


class DeliveryError(Exception):
    def __init__(self, message: str, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


# --- payload ----------------------------------------------------------------------------------

def _clean(text: str, limit: int) -> str:
    text = redact(text or "")[0].replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def template_for(cfg: Config, store: Store, inc: Incident) -> Analysis:
    stored = next((r for r in reversed(store.analyses(inc.id)) if r.source == "template" and r.status == "ok"), None)
    if stored is not None:
        return Analysis.model_validate(stored.payload)
    return template_analysis(inc, store.evidence(inc.id), cfg.access.logs_allowed(inc.workload.namespace))


def build_payload(cfg: Config, store: Store, inc: Incident, event: str, notification_id: str) -> NotificationPayload:
    tmpl = template_for(cfg, store, inc)
    wl = inc.workload
    observed = inc.reason if event != "resolved" else f"Recovered and healthy for the recovery window. Was: {inc.reason}"
    p = NotificationPayload(
        id=notification_id,
        event=event,
        severity=inc.severity if inc.severity in ("info", "warning", "critical") else "warning",
        incident=inc.id,
        cluster=_clean(inc.cluster, 63),
        namespace=wl.namespace,
        workload=_clean(f"{wl.kind}/{wl.name}", 320),
        rule=inc.rule_id,
        state=inc.state.value if inc.state is not State.PENDING else "firing",
        observed=_clean(observed, 500),
        # Runbook text only: possible causes and checks are fixed sentences that
        # name evidence; they never quote log lines.
        possible_cause=_clean(tmpl.possible_causes[0].text, 300) if tmpl.possible_causes else "",
        next_check=_clean(tmpl.next_checks[0], 300) if tmpl.next_checks else "",
        missing=[_clean(m, 200) for m in tmpl.missing_information[:2]],
        first_seen=inc.first_seen,
        last_observed=inc.last_observed,
        recurrence=inc.recurrence_count,
        text="-",
    )
    p.text = render_text(p)
    return p


# --- policy ------------------------------------------------------------------------------------

class NotificationPolicy:
    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.enabled = cfg.notifications.enabled
        self._silence_logged: set[tuple[str, datetime]] = set()  # one activity row per silence
        self.digest = Digest(cfg, store)

    def handle(self, transitions: list[Transition], open_incidents: Iterable[Incident], now: datetime,
               snapshot: Snapshot | None = None) -> None:
        if not self.enabled:
            return
        open_incidents = list(open_incidents)
        try:
            self.digest.observe(transitions, open_incidents, snapshot, now)
        except Exception:
            log.exception("digest failed")
        self._silence_logged = {k for k in self._silence_logged if k[1] > now}
        escalated = {t.incident.id for t in transitions if t.kind == "escalated"}
        for t in transitions:
            self._isolated(t.incident, now, self._transition, t, escalated, now)
        for inc in open_incidents:
            self._isolated(inc, now, self._reminders, inc, now)

    def _isolated(self, inc: Incident, now: datetime, fn, *args) -> None:
        """A failure for one incident is recorded on it; the others are still handled."""
        try:
            fn(*args)
        except Exception as e:
            log.exception("notification policy failed for %s", inc.id)
            self.store.add_activity(inc.id, now, "error", f"Notification failed: {type(e).__name__}: {str(e)[:200]}")

    def _transition(self, t: Transition, escalated: set[str], now: datetime) -> None:
        inc = t.incident
        if t.kind in ("fired", "reopened") and (inc.severity == "info" or inc.id in escalated):
            if inc.severity == "info":
                self.store.add_activity(inc.id, now, "notification",
                                        "Info severity: reported in the next digest")
            return  # an escalation in the same evaluation is announced instead
        if t.kind in ("fired", "reopened", "escalated", "resolved") and self._silenced(inc, now):
            until = self.store.marks(inc.id).silenced_until
            self.store.add_activity(inc.id, now, "notification",
                                    f"{t.kind.capitalize()} notification suppressed by silence until "
                                    f"{until:%Y-%m-%d %H:%M:%S}Z")
            return
        if t.kind == "fired":
            self._enqueue(inc, "firing", f"{inc.id}:firing:{inc.recurrence_count}", now)
        elif t.kind == "reopened":
            last = self._last(inc.id, ALERT_EVENTS)
            if last and now - last.created_at < self.cfg.alarms.repeat_interval:
                self.store.add_activity(inc.id, now, "notification",
                                        f"Reopened notification suppressed: last alert {_age(now - last.created_at)}"
                                        " ago (flap limit)")
            else:
                self._enqueue(inc, "reopened", f"{inc.id}:reopened:{inc.recurrence_count}", now)
        elif t.kind == "escalated":
            self._enqueue(inc, "escalated", f"{inc.id}:escalated:{inc.recurrence_count}", now)
        elif t.kind == "resolved":
            items = self.store.notifications(inc.id)
            last_alert = max((i for i, n in enumerate(items) if n.event in ANNOUNCED), default=-1)
            last_resolved = max((i for i, n in enumerate(items) if n.event == "resolved"), default=-1)
            if last_alert > last_resolved:
                self._enqueue(inc, "resolved", f"{inc.id}:resolved:{inc.recurrence_count}", now)
    def _reminders(self, inc: Incident, now: datetime) -> None:
        if inc.state is not State.FIRING or inc.severity == "info":
            return
        last = self._last(inc.id, ANNOUNCED)
        if last is None and not self._silenced(inc, now):
            # Fired while silenced (or before notifications were enabled): announce it now.
            self._enqueue(inc, "firing", f"{inc.id}:firing:{inc.recurrence_count}", now)
            return
        if last and now - last.created_at >= self.cfg.alarms.repeat_interval:
            if self._silenced(inc, now):
                until = self.store.marks(inc.id).silenced_until
                if (inc.id, until) not in self._silence_logged:
                    self._silence_logged.add((inc.id, until))
                    self.store.add_activity(inc.id, now, "notification",
                                            f"Repeat notification suppressed by silence until {until:%Y-%m-%d %H:%M:%S}Z")
                return
            n = sum(1 for x in self.store.notifications(inc.id) if x.event == "repeat") + 1
            self._enqueue(inc, "repeat", f"{inc.id}:repeat:{n}", now)

    def _silenced(self, inc: Incident, now: datetime) -> bool:
        return self.store.marks(inc.id).silenced(now)

    def _last(self, incident_id: str, events: tuple[str, ...]) -> OutboxItem | None:
        return next((n for n in reversed(self.store.notifications(incident_id)) if n.event in events), None)

    def _enqueue(self, inc: Incident, event: str, notification_id: str, now: datetime) -> None:
        payload = build_payload(self.cfg, self.store, inc, event, notification_id)
        item = OutboxItem(notification_id, inc.id, event, now, "queued", 0, now, None, None, payload.wire())
        if self.store.enqueue_notification(item):
            self.store.add_activity(inc.id, now, "notification", f"Queued {event} notification {notification_id}")


class Digest:
    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.interval = cfg.notifications.digest_interval
        self.window_start: datetime | None = None
        self.images: dict[str, tuple[str, ...]] = {}
        self.restarts: dict[tuple[str, str], int] = {}

    def observe(self, transitions: list[Transition], open_incidents: list[Incident], snapshot: Snapshot | None,
                now: datetime) -> None:
        if not self.interval:
            return
        if self.window_start is None:
            self.window_start = now
        for t in transitions:
            inc, wl = t.incident, t.incident.workload
            if t.kind in ("fired", "reopened") and inc.severity == "info":
                self._item(now, "incident", wl.namespace, f"{wl.kind} {wl.namespace}/{wl.name}: {inc.reason}")
            elif t.kind == "reopened":
                self._item(now, "recurrence", wl.namespace,
                           f"{wl.kind} {wl.namespace}/{wl.name}: {inc.rule_id} recurred "
                           f"({inc.recurrence_count}x within the reopen window)")
        if snapshot is not None:
            self._images(snapshot, now)
            self._restarts(snapshot, open_incidents, now)
        if now - self.window_start >= self.interval:
            self._flush(now)

    def _item(self, now: datetime, kind: str, namespace: str, text: str) -> None:
        self.store.add_digest_item(now, kind, namespace, _clean(text, 200))

    def _images(self, snapshot: Snapshot, now: datetime) -> None:
        current = {meta(d).get("uid", "") for ns in snapshot.namespaces for d in snapshot.deployments.get(ns, [])}
        self.images = {k: v for k, v in self.images.items() if k in current}
        for ns in sorted(snapshot.namespaces):
            for dep in snapshot.deployments.get(ns, []):
                m = meta(dep)
                spec = ((dep.get("spec") or {}).get("template") or {}).get("spec") or {}
                images = tuple(c.get("image", "") for c in spec.get("containers") or [])
                old = self.images.get(m.get("uid", ""))
                self.images[m.get("uid", "")] = images
                if old is not None and images and old != images:
                    self._item(now, "image", ns, f"Deployment {ns}/{m.get('name', '')}: new image "
                                                 f"{', '.join(images)} (was {', '.join(old)})")

    def _restarts(self, snapshot: Snapshot, open_incidents: list[Incident], now: datetime) -> None:
        firing = {i.workload.uid for i in open_incidents
                  if i.rule_id == "restarts" and i.state in (State.FIRING, State.RECOVERING)}
        current = {meta(p).get("uid", "") for ns in snapshot.namespaces for p in snapshot.pods.get(ns, [])}
        self.restarts = {k: v for k, v in self.restarts.items() if k[0] in current}
        for ns in sorted(snapshot.namespaces):
            for wl, pods in snapshot.pods_by_workload(ns).items():
                for p in pods:
                    for c in containers(p):
                        key = (meta(p).get("uid", ""), c.name)
                        old = self.restarts.get(key)
                        self.restarts[key] = c.restart_count
                        if old is None or c.restart_count <= old or wl.uid in firing:
                            continue
                        term = c.last_termination or {}
                        self._item(now, "restarts", ns,
                                   f"{wl.kind} {ns}/{wl.name}: container {c.name} restarted (restart count "
                                   f"{c.restart_count}, last exit {term.get('reason', '?')} {term.get('exitCode', '')})")

    def _flush(self, now: datetime) -> None:
        start, self.window_start = self.window_start, now
        items = self.store.digest_items()
        if not items:
            return
        notification_id = f"digest-{now:%Y%m%dT%H%M%S}"
        namespaces = ",".join(sorted({i.namespace for i in items}))
        p = NotificationPayload(
            id=notification_id, event="digest", severity="info", incident=notification_id,
            cluster=_clean(self.cfg.cluster, 63), namespace=_clean(namespaces, 63), workload="Digest",
            rule="digest", state="info",
            observed=f"{len(items)} info event{'s' if len(items) != 1 else ''} since {start:%Y-%m-%d %H:%M}Z.",
            items=[i.text for i in items[-20:]], first_seen=start, last_observed=now, text="-",
        )
        p.text = render_text(p)
        self.store.enqueue_notification(
            OutboxItem(notification_id, None, "digest", now, "queued", 0, now, None, None, p.wire()), table="digests")
        self.store.clear_digest_items([i.id for i in items])


def _age(d) -> str:
    s = int(d.total_seconds())
    return f"{s // 60}m" if s >= 60 else f"{s}s"


# --- delivery ----------------------------------------------------------------------------------

class NotifierClient(Protocol):
    def send(self, payload: dict, timeout: float) -> str: ...
    def heartbeat(self, timeout: float) -> str: ...


class HttpNotifierClient:
    """Calls the notifier pod with the shared token. The token file is read on each
    call so a rotated Secret is picked up without a restart."""

    def __init__(self, url: str, token_file) -> None:
        self.url = url.rstrip("/")
        self.token_file = token_file

    def _headers(self) -> dict:
        try:
            token = open(self.token_file).read().strip()
        except OSError as e:
            raise DeliveryError(f"notifier token unavailable: {type(e).__name__}") from None
        return {"Authorization": f"Bearer {token}"}

    def _post(self, path: str, timeout: float, payload: dict | None = None) -> str:
        try:
            r = httpx.post(f"{self.url}{path}", json=payload or {}, headers=self._headers(), timeout=timeout)
        except httpx.TimeoutException:
            raise DeliveryError("notifier timeout") from None
        except httpx.HTTPError as e:
            raise DeliveryError(f"notifier unreachable: {type(e).__name__}") from None
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code == 200:
            return body.get("status", "provider_accepted")
        detail = str(body.get("detail") or body.get("error") or r.reason_phrase)[:200]
        # 422 means this payload will never be accepted; anything else may be temporary.
        raise DeliveryError(f"notifier answered {r.status_code}: {detail}", permanent=r.status_code == 422)

    def send(self, payload: dict, timeout: float) -> str:
        return self._post("/v1/notify", timeout, payload)

    def heartbeat(self, timeout: float) -> str:
        return self._post("/v1/heartbeat", timeout)


class Sender:
    def __init__(self, cfg: Config, store: Store, client: NotifierClient | None) -> None:
        self.cfg = cfg.notifications
        self.store = store
        self.client = client if self.cfg.enabled else None
        self.last_heartbeat: datetime | None = None
        self._lock = threading.Lock()
        self.state = "disabled" if self.client is None else "unknown"
        self.detail = "" if self.client is None else "nothing sent yet"
        self._failure: str | None = None

    def recover(self, now: datetime) -> int:
        n = self.store.recover_sending(now)
        if n:
            log.info("retrying %d notification(s) interrupted by a restart", n)
        return n

    def _set(self, state: str, detail: str) -> None:
        with self._lock:
            self.state, self.detail = state, detail
            self._failure = None

    def _set_failure(self, source: str, detail: str) -> None:
        """source is "delivery" or "heartbeat"; a heartbeat success only clears the latter."""
        with self._lock:
            if source == "heartbeat" and self._failure == "delivery":
                return  # keep the more important delivery error visible
            self.state, self.detail, self._failure = "unavailable", detail, source

    def run_once(self, now: datetime) -> int:
        if self.client is None:
            return 0
        sent = 0
        for table in OUTBOXES:
            for item in self.store.due_notifications(now, table=table):
                attempts = item.attempts + 1
                self.store.update_notification(item.id, table, status="sending", attempts=attempts)
                try:
                    status = self.client.send(item.payload, self.cfg.timeout.total_seconds())
                except DeliveryError as e:
                    self._failed(item, table, attempts, str(e), e.permanent, now)
                    if not e.permanent:
                        return sent  # the notifier or provider is down; try the rest later
                    continue
                self.store.update_notification(item.id, table, status=status, accepted_at=now, last_error=None,
                                               next_attempt_at=None)
                self._activity(item, now, f"{item.event.capitalize()} notification accepted by the provider"
                                          + (f" (attempt {attempts})" if attempts > 1 else ""))
                self._set("ok", "last notification accepted")
                sent += 1
        return sent

    def _activity(self, item: OutboxItem, now: datetime, message: str) -> None:
        if item.incident_id:  # a digest belongs to no single incident
            self.store.add_activity(item.incident_id, now, "notification", message)

    def _failed(self, item: OutboxItem, table: str, attempts: int, error: str, permanent: bool,
                now: datetime) -> None:
        self._set_failure("delivery", error)
        if permanent or attempts >= self.cfg.max_attempts:
            self.store.update_notification(item.id, table, status="failed", last_error=error, next_attempt_at=None)
            self._activity(item, now, f"{item.event.capitalize()} notification failed after {attempts} attempts: {error}")
            return
        delay = min(self.cfg.backoff * 2 ** (attempts - 1), self.cfg.backoff_max)
        self.store.update_notification(item.id, table, status="retry_scheduled", last_error=error,
                                       next_attempt_at=now + delay)

    def heartbeat_once(self, now: datetime, observer_ok: bool) -> bool:
        interval = self.cfg.heartbeat_interval
        if self.client is None or not interval or not observer_ok:
            return False
        if self.last_heartbeat is not None and now - self.last_heartbeat < interval:
            return False
        try:
            self.client.heartbeat(self.cfg.timeout.total_seconds())
        except DeliveryError as e:
            self._set_failure("heartbeat", f"heartbeat: {e}")
            return False
        self.last_heartbeat = now
        with self._lock:
            if self.state == "unknown" or self._failure == "heartbeat":
                self.state, self.detail, self._failure = "ok", "heartbeat accepted", None
        return True

    def start(self, stop: threading.Event, observer_ok: Callable[[], bool]) -> threading.Thread | None:
        if self.client is None:
            return None

        def loop() -> None:
            self.recover(utcnow())
            while not stop.is_set():
                now = utcnow()
                try:
                    self.run_once(now)
                    self.heartbeat_once(now, observer_ok())
                except Exception:  # keep delivering; surface the error in status
                    log.exception("notification sender failed")
                stop.wait(self.cfg.send_interval.total_seconds())

        t = threading.Thread(target=loop, name="notifier-sender", daemon=True)
        t.start()
        return t

    def status(self) -> dict:
        with self._lock:
            counts = self.store.outbox_counts() if self.client is not None else {}
            return {
                "notifier": self.state,
                "notifierDetail": self.detail,
                "outbox": {k: counts.get(k, 0) for k in
                           ("queued", "sending", "retry_scheduled", "provider_accepted", "failed")},
                "lastHeartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            }
