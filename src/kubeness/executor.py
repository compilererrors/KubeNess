"""Executor: the only component with write access, and only for two named actions.

    python -m kubeness.executor --config /etc/kubeness/executor.yaml

`restart-deployment` patches the pod template's restartedAt annotation (what
`kubectl rollout restart` does); `rollback-deployment` copies an earlier
revision's pod template (what `kubectl rollout undo --to-revision` does). Both
only in namespaces of remediate silos. The writer Role allows get and patch on
deployments and get and list on replicasets, nothing else. Requests need
the token shared with the observer; the action and its parameters are validated
here again, and every request is written to the audit log.
"""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Protocol

import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

log = logging.getLogger("kubeness.executor")

NAME = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"


class PatchError(Exception):
    pass


class RestartParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str = Field(max_length=63, pattern=NAME)
    name: str = Field(max_length=253, pattern=NAME)


class RollbackParams(RestartParams):
    revision: int = Field(ge=1, strict=True)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    action: Literal["restart-deployment", "rollback-deployment"]
    params: dict
    incident: str = Field(max_length=64)

    def checked_params(self) -> RestartParams:
        model = RollbackParams if self.action == "rollback-deployment" else RestartParams
        return model.model_validate(self.params)


class Patcher(Protocol):
    def restart(self, namespace: str, name: str, at_iso: str) -> int: ...
    def rollback(self, namespace: str, name: str, revision: int) -> int: ...


class KubePatcher:
    def __init__(self) -> None:
        from kubernetes import client, config
        config.load_incluster_config()
        self.apps = client.AppsV1Api()

    def restart(self, namespace: str, name: str, at_iso: str) -> int:
        from kubernetes.client.exceptions import ApiException
        body = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": at_iso}}}}}
        try:
            dep = self.apps.patch_namespaced_deployment(name, namespace, body, _request_timeout=10)
        except ApiException as e:
            raise PatchError(f"API error {e.status}: {e.reason}") from None
        return dep.metadata.generation

    def rollback(self, namespace: str, name: str, revision: int) -> int:
        """Like `kubectl rollout undo --to-revision`: copy that ReplicaSet's pod template."""
        from kubernetes.client.exceptions import ApiException
        try:
            dep = self.apps.read_namespaced_deployment(name, namespace, _request_timeout=10)
            current = int((dep.metadata.annotations or {}).get("deployment.kubernetes.io/revision", 0))
            if revision == current:
                raise PatchError(f"revision {revision} is the current revision")
            for rs in self.apps.list_namespaced_replica_set(namespace, _request_timeout=10).items:
                owner = next((o for o in rs.metadata.owner_references or [] if o.controller), None)
                rev = int((rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision", 0))
                if owner and owner.uid == dep.metadata.uid and rev == revision:
                    template = self.apps.api_client.sanitize_for_serialization(rs.spec.template)
                    (template.get("metadata") or {}).get("labels", {}).pop("pod-template-hash", None)
                    patched = self.apps.patch_namespaced_deployment(
                        name, namespace, [{"op": "replace", "path": "/spec/template", "value": template}],
                        _request_timeout=10)
                    return patched.metadata.generation
        except ApiException as e:
            raise PatchError(f"API error {e.status}: {e.reason}") from None
        raise PatchError(f"revision {revision} not found")


def audit(**fields) -> None:
    log.info("audit %s", json.dumps({"at": datetime.now(timezone.utc).isoformat(), **fields}, sort_keys=True))


def create_executor_app(patcher: Patcher, token: Callable[[], str], namespaces: list[str]) -> FastAPI:
    app = FastAPI(title="KubeNess executor", docs_url=None, redoc_url=None, openapi_url=None)
    allowed = set(namespaces)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.post("/v1/actions")
    async def run(request: Request) -> JSONResponse:
        expected = token()
        scheme, _, given = request.headers.get("authorization", "").partition(" ")
        if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(given.encode(), expected.encode()):
            audit(result="rejected", reason="unauthenticated")
            return JSONResponse({"status": "unauthorized"}, status_code=401)
        try:
            req = ActionRequest.model_validate(await request.json())
            params = req.checked_params()
        except (ValidationError, ValueError):
            audit(result="rejected", reason="invalid request")
            return JSONResponse({"status": "invalid"}, status_code=422)
        if params.namespace not in allowed:
            audit(id=req.id, action=req.action, incident=req.incident, result="rejected", reason="namespace not allowed",
                  namespace=params.namespace)
            return JSONResponse({"status": "forbidden", "error": "namespace not allowed"}, status_code=403)
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            # The API calls block; keep them off the event loop so the probe is answered.
            if isinstance(params, RollbackParams):
                generation = await run_in_threadpool(patcher.rollback, params.namespace, params.name, params.revision)
            else:
                generation = await run_in_threadpool(patcher.restart, params.namespace, params.name, when)
        except PatchError as e:
            audit(id=req.id, action=req.action, incident=req.incident, result="failed", error=str(e),
                  **params.model_dump())
            return JSONResponse({"status": "failed", "error": str(e)}, status_code=502)
        audit(id=req.id, action=req.action, incident=req.incident, result="executed", generation=generation,
              **params.model_dump())
        return JSONResponse({"status": "executed", "id": req.id, "generation": generation})

    return app


class ExecutorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    # Namespaces of remediate silos; empty refuses every action.
    namespaces: list[str] = Field(default_factory=list)
    token_file: Path = Field(Path("/var/run/kubeness/executor/token"), alias="tokenFile")
    port: int = 8082


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kubeness-executor")
    ap.add_argument("--config", default=os.environ.get("KUBENESS_EXECUTOR_CONFIG"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = ExecutorConfig.model_validate(yaml.safe_load(Path(args.config).read_text()))

    def read_token() -> str:
        try:
            return cfg.token_file.read_text().strip()
        except OSError:
            return ""

    app = create_executor_app(KubePatcher(), read_token, cfg.namespaces)
    uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=cfg.port, log_level="warning")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
