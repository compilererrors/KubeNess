"""Notifier: a small service that holds the provider credential and nothing else.

It has no Kubernetes API access. It accepts the fixed notification format from
the observer, authenticated with a shared token, and delivers it to the one
destination in its own configuration. It answers `provider_accepted` only after
the provider accepted the call; an accepted call does not prove that a message
was read. Retries and status are the observer's job.

    python -m kubeness.notifier --config /etc/kubeness/notifier.yaml
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal, Protocol
from urllib.parse import quote, urlencode, urlsplit

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Duration
from .notification import NotificationPayload, title
from .redact import redact

log = logging.getLogger("kubeness.notifier")


class ProviderError(Exception):
    pass


class Provider(Protocol):
    def send(self, p: NotificationPayload | None) -> None: ...


def _post(client: httpx.Client, url: str, **kw) -> None:
    try:
        r = client.post(url, **kw)
    except httpx.TimeoutException:
        raise ProviderError("provider timeout") from None
    except httpx.HTTPError as e:
        raise ProviderError(f"provider unreachable: {type(e).__name__}") from None
    if not 200 <= r.status_code < 300:
        raise ProviderError(f"provider answered {r.status_code}")


class WebhookProvider:
    """JSON POST of the fixed payload, e.g. to a chat webhook relay or a test sink."""

    def __init__(self, url: str, timeout: float, token: str | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.url, self.token = url, token
        self.client = httpx.Client(timeout=timeout, transport=transport)

    def send(self, p: NotificationPayload) -> None:
        headers = {"X-Kubeness-Notification-Id": p.id, "X-Kubeness-Event": p.event}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        _post(self.client, self.url, json=p.wire(), headers=headers)


NTFY_PRIORITY = {"critical": "5", "warning": "4", "info": "3"}
NTFY_TAGS = {"critical": "rotating_light", "warning": "warning", "info": "information_source"}


def _header(value: str) -> str:
    """HTTP headers are ASCII; ntfy accepts RFC 2047 encoded words for the rest."""
    if value.isascii():
        return value
    return "=?UTF-8?B?" + base64.b64encode(value.encode()).decode() + "?="


class NtfyProvider:
    """Publish to an ntfy topic URL: the text as body, title, priority and tags as headers."""

    def __init__(self, url: str, token: str | None, timeout: float,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.url, self.token = url, token
        self.client = httpx.Client(timeout=timeout, transport=transport)

    def send(self, p: NotificationPayload) -> None:
        resolved = p.event == "resolved"
        headers = {
            "Title": _header(title(p)),
            "Priority": "2" if resolved else NTFY_PRIORITY[p.severity],
            "Tags": ",".join(["white_check_mark" if resolved else NTFY_TAGS[p.severity], p.rule]),
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        _post(self.client, self.url, content=p.text.encode(), headers=headers)


def signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return k


def sigv4_headers(method: str, url: str, body: bytes, headers: dict[str, str], access_key: str, secret: str,
                  region: str, service: str, now: datetime) -> dict[str, str]:
    """AWS Signature Version 4 for a single request; returns the headers to send."""
    u = urlsplit(url)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    all_headers = {**{k.lower(): v.strip() for k, v in headers.items()}, "host": u.netloc, "x-amz-date": amz_date}
    signed = ";".join(sorted(all_headers))
    pairs = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~"))
                   for k, _, v in (p.partition("=") for p in u.query.split("&") if p))
    canonical = "\n".join([
        method, quote(u.path or "/", safe="/-_.~"), "&".join(f"{k}={v}" for k, v in pairs),
        "".join(f"{k}:{all_headers[k]}\n" for k in sorted(all_headers)), signed, hashlib.sha256(body).hexdigest(),
    ])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    sig = hmac.new(signing_key(secret, date, region, service), to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in all_headers.items() if k != "host"}
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return out


class SnsProvider:
    """Publish to one SNS topic. The key should allow sns:Publish on that topic ARN only."""

    def __init__(self, topic_arn: str, access_key: str, secret_key: str, timeout: float,
                 transport: httpx.BaseTransport | None = None, clock: Callable[[], datetime] | None = None) -> None:
        parts = topic_arn.split(":")
        if len(parts) != 6 or parts[:3] != ["arn", "aws", "sns"]:
            raise ValueError("the SNS destination must be a topic ARN")
        self.topic_arn, self.region = topic_arn, parts[3]
        self.access_key, self.secret_key = access_key, secret_key
        self.url = f"https://sns.{self.region}.amazonaws.com/"
        self.client = httpx.Client(timeout=timeout, transport=transport)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def send(self, p: NotificationPayload) -> None:
        subject = "".join(ch for ch in title(p) if 32 <= ord(ch) < 127)[:100]
        body = urlencode({"Action": "Publish", "Version": "2010-03-31", "TopicArn": self.topic_arn,
                          "Subject": subject, "Message": p.text}).encode()
        headers = sigv4_headers("POST", self.url, body, {"content-type": "application/x-www-form-urlencoded"},
                                self.access_key, self.secret_key, self.region, "sns", self.clock())
        _post(self.client, self.url, content=body, headers=headers)


class HeartbeatPing:
    """POST to a dead man's switch URL (for example a healthchecks-style ping URL)."""

    def __init__(self, url: str, timeout: float, transport: httpx.BaseTransport | None = None) -> None:
        self.url = url
        self.client = httpx.Client(timeout=timeout, transport=transport)

    def send(self, p: NotificationPayload | None) -> None:
        _post(self.client, self.url, content=b"ok")


class NotifierConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    provider: Literal["webhook", "ntfy", "sns"] = "webhook"
    # Mounted from the destination Secret: `url` (required; the topic ARN for sns),
    # `token`, `heartbeatUrl`, and for sns `accessKeyId` and `secretAccessKey`.
    # Only the notifier mounts it.
    destination_dir: Path = Field(Path("/var/run/kubeness/destination"), alias="destinationDir")
    # Shared with the observer; authenticates the observer's calls.
    token_file: Path = Field(Path("/var/run/kubeness/notifier/token"), alias="tokenFile")
    timeout: Duration = timedelta(seconds=10)
    port: int = 8081

    def _read(self, name: str) -> str | None:
        path = self.destination_dir / name
        return path.read_text().strip() or None if path.exists() else None

    def build(self) -> tuple[Provider, Provider | None]:
        url = self._read("url")
        if not url:
            raise ValueError(f"no destination: {self.destination_dir / 'url'} is missing or empty")
        t = self.timeout.total_seconds()
        token = self._read("token")
        if self.provider == "sns":
            # url holds the topic ARN; the key pair is static (kind has no IRSA): rotate it.
            provider: Provider = SnsProvider(url, self._read("accessKeyId") or "", self._read("secretAccessKey") or "", t)
        elif self.provider == "ntfy":
            provider = NtfyProvider(url, token, t)
        else:
            provider = WebhookProvider(url, t, token)
        hb = self._read("heartbeatUrl")
        return provider, HeartbeatPing(hb, t) if hb else None

    def read_token(self) -> str:
        try:
            return self.token_file.read_text().strip()
        except OSError:
            return ""


def _mask(p: NotificationPayload) -> NotificationPayload:
    """Second masking layer: the observer masks too, but the notifier is the last
    stop before text leaves the cluster."""
    def m(s: str) -> str:
        return redact(s)[0]
    return p.model_copy(update={
        "observed": m(p.observed), "possible_cause": m(p.possible_cause), "next_check": m(p.next_check),
        "missing": [m(x) for x in p.missing], "workload": m(p.workload), "text": m(p.text),
    })


def create_notifier_app(provider: Provider, heartbeat: Provider | None, token: Callable[[], str]) -> FastAPI:
    app = FastAPI(title="KubeNess notifier", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if request.url.path.startswith("/v1/"):
            expected = token()
            given = request.headers.get("authorization", "")
            scheme, _, value = given.partition(" ")
            if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(value.encode(), expected.encode()):
                return JSONResponse({"status": "unauthorized"}, status_code=401)
        return await call_next(request)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.post("/v1/notify")
    async def notify(request: Request) -> JSONResponse:
        try:
            p = NotificationPayload.model_validate(await request.json())
        except (ValidationError, ValueError) as e:
            n = len(e.errors()) if isinstance(e, ValidationError) else 1
            return JSONResponse({"status": "invalid", "detail": f"{n} invalid field(s)"}, status_code=422)
        try:
            provider.send(_mask(p))
        except ProviderError as e:
            log.warning("notification %s (%s) not accepted: %s", p.id, p.event, e)
            return JSONResponse({"status": "provider_error", "error": str(e)}, status_code=502)
        log.info("notification %s (%s) accepted by the provider", p.id, p.event)
        return JSONResponse({"status": "provider_accepted", "id": p.id})

    @app.post("/v1/heartbeat")
    def beat() -> JSONResponse:
        if heartbeat is None:
            return JSONResponse({"status": "disabled"})
        try:
            heartbeat.send(None)
        except ProviderError as e:
            return JSONResponse({"status": "provider_error", "error": str(e)}, status_code=502)
        return JSONResponse({"status": "provider_accepted"})

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kubeness-notifier")
    parser.add_argument("--config", default=os.environ.get("KUBENESS_NOTIFIER_CONFIG"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    data = yaml.safe_load(Path(args.config).read_text()) if args.config else {}
    cfg = NotifierConfig.model_validate(data or {})
    try:
        provider, heartbeat = cfg.build()
    except ValueError as e:
        log.error("%s", e)
        return 2
    log.info("delivering to a %s destination; heartbeat %s", cfg.provider, "on" if heartbeat else "off")
    app = create_notifier_app(provider, heartbeat, cfg.read_token)
    uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=cfg.port, log_level="warning")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
