"""Observer side of actions: an approved request goes to the executor pod.

The observer has no write access itself. It sends one named action with
validated parameters, authenticated with a token only observer and executor
mount, records the result, and verifies it with a later observation.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Protocol

import httpx

from .config import Config
from .lifecycle import Incident
from .store import ActionRecord, Store


class ActionError(Exception):
    pass


class ExecutorClient(Protocol):
    def run(self, action_id: str, action: str, params: dict, incident_id: str) -> int: ...


class HttpExecutorClient:
    def __init__(self, url: str, token_file, timeout: float) -> None:
        self.url, self.token_file, self.timeout = url.rstrip("/"), token_file, timeout

    def run(self, action_id: str, action: str, params: dict, incident_id: str) -> int:
        try:
            token = open(self.token_file).read().strip()
        except OSError as e:
            raise ActionError(f"executor token unavailable: {type(e).__name__}") from None
        try:
            r = httpx.post(f"{self.url}/v1/actions", timeout=self.timeout, headers={"Authorization": f"Bearer {token}"},
                           json={"id": action_id, "action": action, "params": params, "incident": incident_id})
        except httpx.HTTPError as e:
            raise ActionError(f"executor unreachable: {type(e).__name__}") from None
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code != 200:
            raise ActionError(f"executor answered {r.status_code}: {body.get('error') or body.get('status') or ''}")
        return int(body["generation"])


class ActionClient:
    def __init__(self, cfg: Config, store: Store, client: ExecutorClient) -> None:
        self.cfg, self.store, self.client = cfg, store, client

    def request(self, inc: Incident, action: str, now: datetime, revision: int | None = None) -> ActionRecord:
        if action not in self.cfg.actions.allowed:
            raise ValueError(f"action {action} is not allowed")
        if not inc.is_open:
            # The UI only offers actions on open incidents; a direct request gets the same answer.
            raise ValueError(f"incident {inc.id} is resolved; actions apply to open incidents only")
        if not self.cfg.access.actions_allowed(inc.workload.namespace):
            silo = self.cfg.access.silo_for(inc.workload.namespace)
            raise ValueError(f"actions need the remediate profile; namespace {inc.workload.namespace} is in silo "
                             f"{silo.name if silo else '-'} ({silo.profile if silo else 'not watched'})")
        if inc.workload.kind != "Deployment":
            raise ValueError(f"{action} applies to Deployments only")
        params: dict = {"namespace": inc.workload.namespace, "name": inc.workload.name}
        if action == "rollback-deployment":
            if not isinstance(revision, int) or revision < 1:
                raise ValueError("rollback-deployment needs the revision to return to")
            params["revision"] = revision
        rec = ActionRecord(f"act-{now:%Y%m%d%H%M%S}-{secrets.token_hex(3)}", inc.id, action, params, now,
                           "requested", None, None, None)
        self.store.add_action(rec)
        self.store.add_activity(inc.id, now, "action", f"Approved {action} of Deployment "
                                                       f"{params['namespace']}/{params['name']} ({rec.id})")
        try:
            generation = self.client.run(rec.id, action, params, inc.id)
        except ActionError as e:
            self.store.update_action(rec.id, status="failed", result=str(e)[:300])
            self.store.add_activity(inc.id, now, "action", f"{action} failed: {e}")
            rec.status, rec.result = "failed", str(e)
            return rec
        self.store.update_action(rec.id, status="executed", generation=generation,
                                 result=f"patched; waiting for generation {generation} to be observed")
        self.store.add_activity(inc.id, now, "action", f"{action} executed; verifying with the next observations")
        rec.status, rec.generation = "executed", generation
        return rec
