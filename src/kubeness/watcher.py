"""List/watch with reconnect, 410 handling and periodic relist (reconciliation)."""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
from collections.abc import Generator
from contextlib import closing
from typing import Callable

from kubernetes import client, config as kube_config
from kubernetes.client.exceptions import ApiException
from kubernetes.watch.watch import iter_resp_lines

from .cache import ClusterCache
from .config import Config
from .snapshot import utcnow

log = logging.getLogger(__name__)


class ContextRequired(RuntimeError):
    pass


def load_kube_config(cfg: Config) -> None:
    """In-cluster config, or an explicitly named kubeconfig context.

    Never falls back to the current kubeconfig context: on a developer machine
    that could be any cluster, including production.
    """
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        kube_config.load_incluster_config()
        return
    if not cfg.kubernetes.context:
        raise ContextRequired(
            "Not running in a cluster and no kubernetes.context configured. "
            "Set it explicitly, e.g. kind-kubeness."
        )
    kube_config.load_kube_config(context=cfg.kubernetes.context)


def list_functions() -> dict[str, Callable]:
    core = client.CoreV1Api()
    apps = client.AppsV1Api()
    return {
        "pods": core.list_namespaced_pod,
        "replicasets": apps.list_namespaced_replica_set,
        "deployments": apps.list_namespaced_deployment,
        "events": core.list_namespaced_event,
    }


class Relist(Exception):
    pass


class Watcher(threading.Thread):
    def __init__(self, cache: ClusterCache, cfg: Config, ns: str, kind: str, list_fn: Callable, stop: threading.Event):
        super().__init__(name=f"watch-{ns}-{kind}", daemon=True)
        self.cache, self.cfg, self.ns, self.kind, self.list_fn, self.stop_event = cache, cfg, ns, kind, list_fn, stop

    def run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                self._list_and_watch()
                backoff = 1.0
            except Relist:
                log.info("%s/%s: resource version expired, relisting", self.ns, self.kind)
                backoff = 1.0
            except ApiException as e:
                if e.status == 410:
                    continue
                msg = f"API error {e.status}: {e.reason}"
                self.cache.mark_error(self.ns, self.kind, msg)
                log.warning("%s/%s: %s", self.ns, self.kind, msg)
                backoff = self._sleep(backoff)
            except Exception as e:  # network errors, timeouts, decoding
                self.cache.mark_error(self.ns, self.kind, f"{type(e).__name__}: {e}")
                log.warning("%s/%s: %s", self.ns, self.kind, e)
                backoff = self._sleep(backoff)

    def _sleep(self, backoff: float) -> float:
        self.stop_event.wait(backoff + random.uniform(0, backoff / 2))
        return min(backoff * 2, 60.0)

    def _list_and_watch(self) -> None:
        timeout = int(self.cfg.observer.watch_timeout.total_seconds())
        resp = self.list_fn(namespace=self.ns, _preload_content=False, _request_timeout=timeout + 10)
        body = json.loads(resp.data)
        self.cache.replace(self.ns, self.kind, body.get("items") or [], utcnow())
        rv = body["metadata"]["resourceVersion"]
        deadline = time.monotonic() + self.cfg.observer.resync.total_seconds()
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            with closing(self._events(rv, timeout)) as events:
                for event in events:
                    if self.stop_event.is_set():
                        return
                    typ = event["type"]
                    raw = event["object"]
                    if typ == "ERROR":  # a Status object in place of a watched one
                        if raw.get("code") == 410:
                            raise Relist()
                        raise ApiException(status=raw.get("code"), reason=f"{raw.get('reason')}: {raw.get('message')}")
                    rv = (raw.get("metadata") or {}).get("resourceVersion", rv)
                    now = utcnow()
                    if typ == "BOOKMARK":
                        self.cache.mark_ok(self.ns, self.kind, now)
                    elif typ == "DELETED":
                        self.cache.delete(self.ns, self.kind, raw, now)
                    else:
                        self.cache.put(self.ns, self.kind, raw, now)
            # Server-side timeout ended the stream normally; the connection worked.
            self.cache.mark_ok(self.ns, self.kind, utcnow())
        # Fall through to relist: periodic reconciliation against current state.

    def _events(self, rv: str, timeout: int) -> Generator[dict, None, None]:
        """One watch request, yielding its events as the plain JSON the API sends.

        The client's Watch also builds a model object from every event. Only the plain
        dict is used here, so that work is skipped, and a model that rejects an object
        cannot end the stream.
        """
        resp = self.list_fn(namespace=self.ns, watch=True, resource_version=rv, timeout_seconds=timeout,
                            allow_watch_bookmarks=True, _preload_content=False, _request_timeout=timeout + 10)
        try:
            for line in iter_resp_lines(resp):
                if line.strip():
                    yield json.loads(line)
        finally:
            resp.close()
            resp.release_conn()


def start_watchers(cache: ClusterCache, cfg: Config, stop: threading.Event) -> list[Watcher]:
    fns = list_functions()
    threads = [Watcher(cache, cfg, ns, kind, fns[kind], stop) for ns in cfg.access.namespaces for kind in fns]
    for t in threads:
        t.start()
    return threads
