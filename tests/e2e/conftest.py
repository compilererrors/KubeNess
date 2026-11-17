"""End-to-end fixtures. Runs only against a kind cluster named explicitly in KUBENESS_E2E_CONTEXT.

    KUBENESS_E2E_CONTEXT=kind-kubeness .venv/bin/pytest -m e2e tests/e2e
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable

import httpx
import pytest

import kpi_report

ROOT = Path(__file__).resolve().parents[2]
CONTEXT = os.environ.get("KUBENESS_E2E_CONTEXT", "")
RELEASE_NS = "kubeness"
LAB_NS = "lab"
OBSERVER_SA = f"system:serviceaccount:{RELEASE_NS}:kubeness-observer"


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "/e2e/" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
            if not CONTEXT:
                item.add_marker(pytest.mark.skip(reason="set KUBENESS_E2E_CONTEXT=kind-<name> to run e2e tests"))
            elif not CONTEXT.startswith("kind-"):
                item.add_marker(pytest.mark.skip(reason=f"refusing to run e2e against non-kind context {CONTEXT}"))


def pytest_terminal_summary(terminalreporter):
    kpi_report.summary(terminalreporter)


def kubectl(*args: str, check: bool = True, timeout: int = 120, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", "--context", CONTEXT, *args],
        capture_output=True, text=True, check=check, timeout=timeout, input=input,
    )


def kjson(*args: str) -> dict:
    return json.loads(kubectl(*args, "-o", "json").stdout)


def wait_for(fn: Callable[[], object], timeout: float, interval: float = 5, what: str = "condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (httpx.HTTPError, subprocess.CalledProcessError, KeyError) as e:
            last = e
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}; last={last!r}")


class PortForward:
    def __init__(self, namespace: str = RELEASE_NS, target: str = "service/kubeness", remote: int = 80) -> None:
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.namespace, self.target, self.remote = namespace, target, remote

    def start(self) -> "PortForward":
        self.proc = subprocess.Popen(
            ["kubectl", "--context", CONTEXT, "-n", self.namespace, "port-forward",
             "--address=127.0.0.1", self.target, f"0:{self.remote}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            m = re.search(r"127\.0\.0\.1:(\d+)", line or "")
            if m:
                self.port = int(m.group(1))
                return self
            if self.proc.poll() is not None:
                break
        raise AssertionError(f"port-forward did not start: {line!r}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=10)


@pytest.fixture(scope="session")
def observer_ready():
    kubectl("-n", RELEASE_NS, "rollout", "status", "deployment/kubeness-observer", "--timeout=180s", timeout=200)
    return True


@pytest.fixture(scope="session")
def ui(observer_ready):
    pf = PortForward().start()
    yield pf
    pf.stop()


@pytest.fixture(scope="session")
def api(ui):
    with ui.client() as c:
        yield c


def incidents(client: httpx.Client) -> list[dict]:
    r = client.get("/api/incidents")
    r.raise_for_status()
    return r.json()


def find(client: httpx.Client, workload: str, rule: str | None = None) -> list[dict]:
    return [
        i for i in incidents(client)
        if i["workload"]["name"] == workload and (rule is None or i["rule_id"] == rule)
    ]


# --- notification sink (lab/sink.yaml) -----------------------------------------------------

@pytest.fixture(scope="session")
def sink():
    pf = PortForward("lab-sink", "service/sink", 8080).start()
    with pf.client() as c:
        yield c
    pf.stop()


def received(sink, path="/hook", ok_only=True) -> list[dict]:
    out = []
    for r in sink.get("/received").json():
        if r["path"] != path or (ok_only and r["failed"]):
            continue
        if path == "/hook":
            r["payload"] = json.loads(r["body"])
        out.append(r)
    return out


def for_incident(sink, inc_id, event=None, ok_only=True):
    return [r for r in received(sink, ok_only=ok_only) if r["payload"]["incident"] == inc_id
            and (event is None or r["payload"]["event"] == event)]


def set_sink_failing(sink, fail: bool) -> None:
    sink.post("/mode", json={"fail": fail}).raise_for_status()


