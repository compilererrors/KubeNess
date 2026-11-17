"""Small server-rendered UI and JSON API, reached through kubectl port-forward.

Reads are GET; the only writes are acknowledge and silence, which change the
application's own database and never the cluster. They are POST forms that need
the per-process CSRF token and a same-origin Origin or Referer, on top of the
Host check that blocks DNS rebinding. Neither mark changes the incident lifecycle.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from .config import Config
from .lifecycle import Incident
from .snapshot import utcnow
from .ask import EXAMPLES
from .store import AnalysisRecord, Marks, OutboxItem, Store

PROBE_PATHS = {"/healthz", "/readyz"}
SILENCE_DURATIONS = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "4h": timedelta(hours=4),
                     "24h": timedelta(hours=24)}
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _ago(d: datetime | None) -> str:
    if d is None:
        return "–"
    s = int((utcnow() - d).total_seconds())
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m ago"
    return f"{s // 86400}d ago"


TEMPLATES.env.filters["ago"] = _ago
TEMPLATES.env.filters["ts"] = lambda d: d.strftime("%Y-%m-%d %H:%M:%S UTC") if d else "–"


def incident_json(inc: Incident) -> dict:
    d = asdict(inc)
    d["state"] = inc.state.value
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def pick_analysis(records: list[AnalysisRecord]) -> tuple[AnalysisRecord | None, AnalysisRecord | None]:
    """The analysis to show (latest valid model output, else latest template) and the
    latest model attempt if it failed after that."""
    shown = None
    for r in reversed(records):
        if r.status == "ok" and r.source == "model":
            shown = r
            break
    if shown is None:
        shown = next((r for r in reversed(records) if r.source == "template"), None)
    last_model = next((r for r in reversed(records) if r.source == "model"), None)
    failed = last_model if last_model and last_model.status != "ok" and (shown is None or last_model.id > shown.id) else None
    return shown, failed


def model_stats(cfg: Config, store: Store) -> list[dict]:
    """Per model over all incidents: the PoC comparison of primary and shadow models."""
    from .model import grounded_checks

    rows: dict[str, dict] = {}
    cache: dict[str, tuple] = {}
    for r in store.model_analyses():
        name = r.model or "?"
        row = rows.setdefault(name, {"model": name, "role": "primary" if r.source == "model" else "shadow",
                                     "analyses": 0, "ok": 0, "unavailable": 0, "droppedClaims": 0,
                                     "groundedChecks": 0, "latencies": [], "errors": {}})
        row["analyses"] += 1
        row["droppedClaims"] += len(r.dropped)
        if r.status != "ok":
            row["unavailable"] += 1
            key = (r.error or "?").split(":")[0][:60]
            row["errors"][key] = row["errors"].get(key, 0) + 1
            continue
        row["ok"] += 1
        if r.latency_ms is not None:
            row["latencies"].append(r.latency_ms)
        if r.incident_id not in cache:
            cache[r.incident_id] = (store.get_incident(r.incident_id), store.evidence(r.incident_id))
        inc, evidence = cache[r.incident_id]
        if inc is not None and grounded_checks((r.payload or {}).get("next_checks", []), inc, evidence):
            row["groundedChecks"] += 1
    out = []
    for row in sorted(rows.values(), key=lambda x: (x["role"] != "primary", x["model"])):
        lat = sorted(row.pop("latencies"))
        row["p50LatencyMs"] = lat[len(lat) // 2] if lat else None
        row["p95LatencyMs"] = lat[min(len(lat) - 1, int(round(0.95 * (len(lat) - 1))))] if lat else None
        out.append(row)
    return out


def latest_per_model(records: list[AnalysisRecord]) -> list[AnalysisRecord]:
    """Latest model and shadow analysis per model name; shown only when a shadow exists."""
    latest: dict[str, AnalysisRecord] = {}
    for r in records:
        if r.source in ("model", "shadow"):
            latest[r.model or "?"] = r
    if not any(r.source == "shadow" for r in latest.values()):
        return []
    return sorted(latest.values(), key=lambda r: (r.source != "model", r.model or ""))


def analysis_json(r: AnalysisRecord) -> dict:
    d = asdict(r)
    d["created_at"] = r.created_at.isoformat()
    return d


def notification_json(n: OutboxItem | None) -> dict | None:
    if n is None:
        return None
    return {
        "id": n.id, "event": n.event, "status": n.status, "attempts": n.attempts,
        "created_at": n.created_at.isoformat(), "accepted_at": n.accepted_at.isoformat() if n.accepted_at else None,
        "next_attempt_at": n.next_attempt_at.isoformat() if n.next_attempt_at else None, "last_error": n.last_error,
    }


def marks_json(m: Marks) -> dict:
    return {"acknowledged_at": m.acknowledged_at.isoformat() if m.acknowledged_at else None,
            "silenced_until": m.silenced_until.isoformat() if m.silenced_until else None}


def create_app(cfg: Config, store: Store, status: Callable[[], dict],
               clock: Callable[[], datetime] = utcnow, asker=None, actions=None, troubleshooter=None) -> FastAPI:
    app = FastAPI(title="KubeNess", docs_url=None, redoc_url=None, openapi_url=None)
    allowed = set(cfg.ui.allowed_hosts)
    csrf_token = secrets.token_urlsafe(32)

    def same_origin(request: Request) -> bool:
        """Browsers send Origin on cross-site POSTs; fall back to Referer. A request
        with neither is refused: a form from this UI always carries one."""
        source = request.headers.get("origin") or request.headers.get("referer")
        if not source or source == "null":
            return False
        return (urlparse(source).hostname or "") in allowed

    @app.middleware("http")
    async def check_host(request: Request, call_next):
        # Port-forward exposes the UI on localhost; reject other Host values so a
        # web page cannot read incidents through DNS rebinding. Probes come from
        # kubelet with the pod IP as host and are exempt.
        if request.url.path not in PROBE_PATHS:
            host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
            if host not in allowed:
                return PlainTextResponse("host not allowed", status_code=403)
        return await call_next(request)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> PlainTextResponse:
        st = status()
        return PlainTextResponse("ok" if st["engineRunning"] else "starting", status_code=200 if st["engineRunning"] else 503)

    @app.get("/api/status")
    def api_status() -> JSONResponse:
        return JSONResponse(status())

    @app.get("/api/incidents")
    def api_incidents(include_resolved: bool = True) -> JSONResponse:
        latest = store.latest_notifications()
        marks = store.all_marks()
        return JSONResponse([{**incident_json(i), "notification": notification_json(latest.get(i.id)),
                              "marks": marks_json(marks.get(i.id, Marks()))}
                             for i in store.list_incidents(include_resolved)])

    @app.get("/api/incidents/{incident_id}")
    def api_incident(incident_id: str) -> JSONResponse:
        inc = store.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404)
        return JSONResponse(
            {
                "incident": incident_json(inc),
                "evidence": [{**asdict(e), "collected_at": e.collected_at.isoformat()} for e in store.evidence(inc.id)],
                "activity": [{**asdict(a), "at": a.at.isoformat()} for a in store.activity(inc.id)],
                "analyses": [analysis_json(r) for r in store.analyses(inc.id)],
                "notifications": [notification_json(n) for n in store.notifications(inc.id)],
                "marks": marks_json(store.marks(inc.id)),
                "questions": [{**asdict(q), "at": q.at.isoformat()} for q in store.questions(inc.id)],
                "investigations": [{**asdict(i), "started_at": i.started_at.isoformat(),
                                    "finished_at": i.finished_at.isoformat() if i.finished_at else None}
                                   for i in store.investigations(inc.id)],
                "actions": [{**asdict(a), "requested_at": a.requested_at.isoformat(),
                             "verified_at": a.verified_at.isoformat() if a.verified_at else None}
                            for a in store.actions(inc.id)],
            }
        )

    @app.get("/api/models")
    def api_models() -> JSONResponse:
        return JSONResponse(model_stats(cfg, store))

    @app.get("/models", response_class=HTMLResponse)
    def models_page(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(request, "models.html",
                                          {"rows": model_stats(cfg, store), "status": status(), "cfg": cfg})

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request,
            "list.html",
            {"incidents": store.list_incidents(), "latest": store.latest_notifications(), "marks": store.all_marks(),
             "now": clock(), "status": status(), "cfg": cfg},
        )

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def detail(request: Request, incident_id: str) -> HTMLResponse:
        inc = store.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404)
        shown, failed = pick_analysis(store.analyses(inc.id))
        return TEMPLATES.TemplateResponse(
            request,
            "detail.html",
            {
                "inc": inc,
                "analysis": shown,
                "failed": failed,
                "evidence": store.evidence(inc.id),
                "activity": store.activity(inc.id),
                "notifications": store.notifications(inc.id),
                "marks": store.marks(inc.id),
                "now": clock(),
                "csrf_token": csrf_token,
                "durations": list(SILENCE_DURATIONS),
                "questions": store.questions(inc.id),
                "comparison": latest_per_model(store.analyses(inc.id)),
                "examples": EXAMPLES,
                "can_ask": asker is not None,
                "can_act": actions is not None and inc.workload.kind == "Deployment" and inc.is_open
                and cfg.access.actions_allowed(inc.workload.namespace),
                "can_troubleshoot": troubleshooter is not None and cfg.experimental.troubleshoot.enabled,
                "investigations": store.investigations(inc.id),
                "silo": cfg.access.silo_for(inc.workload.namespace),
                "allowed_actions": cfg.actions.allowed if actions is not None else [],
                "actions": store.actions(inc.id),
                "status": status(),
                "cfg": cfg,
            },
        )

    async def mutation(request: Request, incident_id: str) -> tuple[Incident, dict[str, str]]:
        inc = store.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404)
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode(errors="replace")).items()}
        token = form.get("csrf_token", "")
        if not same_origin(request) or not hmac.compare_digest(token.encode(), csrf_token.encode()):
            raise HTTPException(403, "cross-site request or missing CSRF token")
        return inc, form

    def back(inc: Incident) -> RedirectResponse:
        return RedirectResponse(f"/incidents/{inc.id}", status_code=303)

    @app.post("/incidents/{incident_id}/ack")
    async def ack(request: Request, incident_id: str) -> RedirectResponse:
        inc, _ = await mutation(request, incident_id)
        now = clock()
        store.set_acknowledged(inc.id, now)
        store.add_activity(inc.id, now, "acknowledged", "Acknowledged in the UI (seen; the incident stays open)")
        return back(inc)

    @app.post("/incidents/{incident_id}/unack")
    async def unack(request: Request, incident_id: str) -> RedirectResponse:
        inc, _ = await mutation(request, incident_id)
        store.set_acknowledged(inc.id, None)
        store.add_activity(inc.id, clock(), "unacknowledged", "Acknowledgement removed")
        return back(inc)

    @app.post("/incidents/{incident_id}/silence")
    async def silence(request: Request, incident_id: str) -> RedirectResponse:
        inc, form = await mutation(request, incident_id)
        duration = SILENCE_DURATIONS.get(form.get("duration", ""))
        if duration is None:
            raise HTTPException(400, f"duration must be one of {', '.join(SILENCE_DURATIONS)}")
        now = clock()
        store.set_silenced_until(inc.id, now + duration)
        store.add_activity(inc.id, now, "silenced",
                           f"Notifications silenced for {form['duration']} (detection continues)")
        return back(inc)

    @app.post("/incidents/{incident_id}/unsilence")
    async def unsilence(request: Request, incident_id: str) -> RedirectResponse:
        inc, _ = await mutation(request, incident_id)
        store.set_silenced_until(inc.id, None)
        store.add_activity(inc.id, clock(), "unsilenced", "Silence removed")
        return back(inc)

    @app.post("/incidents/{incident_id}/actions/{action}")
    async def act(request: Request, incident_id: str, action: str) -> RedirectResponse:
        inc, form = await mutation(request, incident_id)
        if actions is None or action not in cfg.actions.allowed:
            raise HTTPException(404)
        revision = int(form["revision"]) if form.get("revision", "").isdigit() else None
        try:
            await run_in_threadpool(actions.request, inc, action, clock(), revision)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        return RedirectResponse(f"/incidents/{inc.id}#actions", status_code=303)

    @app.post("/incidents/{incident_id}/troubleshoot")
    async def troubleshoot(request: Request, incident_id: str) -> RedirectResponse:
        inc, _ = await mutation(request, incident_id)
        if troubleshooter is None or not cfg.experimental.troubleshoot.enabled:
            raise HTTPException(404)
        if not troubleshooter.start(inc.id, clock()):
            raise HTTPException(409, "another troubleshooting run is in progress")
        return RedirectResponse(f"/incidents/{inc.id}#troubleshoot", status_code=303)

    @app.post("/incidents/{incident_id}/ask")
    async def ask(request: Request, incident_id: str) -> RedirectResponse:
        inc, form = await mutation(request, incident_id)
        if asker is None:
            raise HTTPException(404)
        question = (form.get("question") or "").strip() or form.get("example", "")
        try:
            # The model call blocks; keep the event loop free for other requests.
            await run_in_threadpool(asker.answer, inc.id, question, clock())
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        return RedirectResponse(f"/incidents/{inc.id}#ask", status_code=303)

    return app
