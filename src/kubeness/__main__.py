"""Observer entry point: watchers, rule loop and web UI in one process.

There is exactly one owner of the watchers and the rule loop. The web server
runs in the same process with a single worker so it never duplicates monitoring.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading

import uvicorn

from .cache import ClusterCache
from .config import Config, load_config
from .engine import Engine
from .collector import LogCollector, kube_read_log, kube_read_nodes, kube_read_services
from .actions import ActionClient, HttpExecutorClient
from .ask import Asker
from .model import Analyzer, OllamaClient
from .troubleshoot import Troubleshooter, troubleshoot_model
from .notify import HttpNotifierClient, NotificationPolicy, Sender
from .snapshot import utcnow
from .store import Store
from .watcher import ContextRequired, load_kube_config, start_watchers
from .web import create_app

log = logging.getLogger("kubeness")


class Observer:
    def __init__(self, cfg: Config, read_log=None, read_nodes=None, read_services=None) -> None:
        self.cfg = cfg
        self.stop = threading.Event()
        self.store = Store(cfg.observer.data_dir / "incidents.db")
        self.cache = ClusterCache(cfg.cluster, cfg.access.namespaces, cfg.observer.freshness_budget)
        client = OllamaClient(cfg.model.url, cfg.model.name, cfg.model.think, cfg.model.num_threads) if cfg.model.enabled else None
        shadows = {n: OllamaClient(cfg.model.url, n, cfg.model.think, cfg.model.num_threads)
                    for n in cfg.model.compare} if cfg.model.enabled else {}
        esc = cfg.model.escalation.model
        escalation = OllamaClient(cfg.model.url, esc, cfg.model.think, cfg.model.num_threads) \
            if cfg.model.enabled and esc else None
        self.analyzer = Analyzer(cfg, self.store, client, shadows, escalation)
        self.asker = Asker(cfg, self.store, client)
        tcfg = cfg.experimental.troubleshoot
        self.troubleshooter = (Troubleshooter(
            cfg, self.store, OllamaClient(cfg.model.url, troubleshoot_model(cfg), tcfg.think, cfg.model.num_threads),
            lambda: self.cache.snapshot(utcnow()), read_log, model_name=troubleshoot_model(cfg))
            if tcfg.enabled and cfg.model.enabled else None)
        self.actions = (ActionClient(cfg, self.store, HttpExecutorClient(cfg.actions.url, cfg.actions.token_file,
                                                                        cfg.actions.timeout.total_seconds()))
                        if cfg.actions.enabled else None)
        self.analyzer.stop = self.stop
        notifier = HttpNotifierClient(cfg.notifications.url, cfg.notifications.token_file) if cfg.notifications.enabled else None
        self.sender = Sender(cfg, self.store, notifier)
        self.engine = Engine(cfg, self.store, LogCollector(cfg, read_log, read_nodes, read_services), self.analyzer,
                             NotificationPolicy(cfg, self.store))
        self.engine_running = False
        self.last_error: str | None = None

    def status(self) -> dict:
        now = utcnow()
        sources = self.cache.status(now)
        stale = sorted({s["namespace"] for s in sources if not s["fresh"] and s["kind"] != "events"})
        last = self.engine.last_tick
        loop_ok = last is not None and now - last <= 3 * self.cfg.observer.evaluation_interval
        degraded = bool(stale) or not loop_ok
        if not self.engine_running:
            detail = "starting"
        elif stale:
            detail = f"stale observations in {', '.join(stale)}"
        elif not loop_ok:
            detail = "rule loop is behind"
        else:
            detail = "all sources fresh"
        return {
            "observer": "degraded" if degraded else "ok",
            "observerDetail": detail,
            "engineRunning": self.engine_running,
            "lastEvaluation": last.isoformat() if last else None,
            "lastError": self.last_error,
            "sources": sources,
            **self.analyzer.status(),
            **self.sender.status(),
        }

    def healthy(self) -> bool:
        """Heartbeats stop when the observer itself is degraded, so the external
        dead man's switch notices."""
        return self.status()["observer"] == "ok"

    def run_engine(self) -> None:
        interval = self.cfg.observer.evaluation_interval.total_seconds()
        self.engine_running = True
        while not self.stop.is_set():
            now = utcnow()
            try:
                self.engine.tick(self.cache.snapshot(now), now)
                self.last_error = None
            except Exception as e:  # keep the loop alive; surface the error in status
                self.last_error = f"{type(e).__name__}: {e}"
                log.exception("rule evaluation failed")
            self.stop.wait(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kubeness")
    parser.add_argument("--config", default=os.environ.get("KUBENESS_CONFIG"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    try:
        load_kube_config(cfg)
    except ContextRequired as e:
        log.error("%s", e)
        return 2

    obs = Observer(cfg, kube_read_log() if cfg.access.read_logs else None,
                   kube_read_nodes() if cfg.access.read_nodes else None,
                   kube_read_services() if cfg.access.read_services else None)
    start_watchers(obs.cache, cfg, obs.stop)
    obs.analyzer.start()
    obs.sender.start(obs.stop, obs.healthy)
    threading.Thread(target=obs.run_engine, name="engine", daemon=True).start()

    app = create_app(cfg, obs.store, obs.status, asker=obs.asker, actions=obs.actions,
                     troubleshooter=obs.troubleshooter)
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=cfg.ui.port, log_level="warning"))
    server.run()  # uvicorn handles SIGTERM/SIGINT and returns on shutdown
    obs.stop.set()
    obs.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
