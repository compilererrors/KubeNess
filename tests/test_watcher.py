import json
import threading
from datetime import timedelta
from types import SimpleNamespace

import pytest

from kubeness import watcher as w
from kubeness.cache import ClusterCache
from kubeness.config import Config


def obj(uid, rv):
    return {"metadata": {"uid": uid, "name": uid, "namespace": "lab", "resourceVersion": rv}}


class FakeApi:
    """list_fn stand-in: returns a list response, and scripted watch streams."""

    def __init__(self, lists, streams, stop):
        self.lists, self.streams, self.stop = list(lists), list(streams), stop
        self.list_calls = 0
        self.watch_rvs = []

    def __call__(self, namespace, _preload_content=True, **kw):
        self.list_calls += 1
        items, rv = self.lists.pop(0) if self.lists else ([], "999")
        return SimpleNamespace(data=json.dumps({"metadata": {"resourceVersion": rv}, "items": items}))


class FakeWatch:
    api: FakeApi

    def stream(self, fn, namespace, resource_version, **kw):
        self.api.watch_rvs.append(resource_version)
        if not self.api.streams:
            self.api.stop.set()
            return
        script = self.api.streams.pop(0)
        if isinstance(script, Exception):
            raise script
        yield from script

    def stop(self):
        pass


@pytest.fixture
def run(monkeypatch):
    def _run(lists, streams):
        stop = threading.Event()
        api = FakeApi(lists, streams, stop)
        FakeWatch.api = api
        monkeypatch.setattr(w.watch, "Watch", FakeWatch)
        # The first error backoff ends the run, so the error state can be inspected.
        monkeypatch.setattr(w.Watcher, "_sleep", lambda self, b: self.stop_event.set() or b)
        cfg = Config()
        cache = ClusterCache("lab", ["lab"], timedelta(minutes=3))
        t = w.Watcher(cache, cfg, "lab", "pods", api, stop)
        t.run()
        return api, cache

    return _run


def test_events_update_cache_and_resume_from_last_resource_version(run):
    stream1 = [
        {"type": "ADDED", "raw_object": obj("b", "11")},
        {"type": "BOOKMARK", "raw_object": {"metadata": {"resourceVersion": "15"}}},
        {"type": "DELETED", "raw_object": obj("a", "16")},
    ]
    api, cache = run([([obj("a", "9")], "10")], [stream1, []])
    assert api.watch_rvs[:2] == ["10", "16"]
    pods = cache.snapshot(cache._status[("lab", "pods")].last_success).pods["lab"]
    assert [p["metadata"]["uid"] for p in pods] == ["b"]


def test_expired_resource_version_triggers_relist(run):
    gone = [{"type": "ERROR", "raw_object": {"code": 410, "message": "too old resource version"}}]
    api, cache = run([([obj("a", "9")], "10"), ([obj("c", "30")], "30")], [gone])
    assert api.list_calls >= 2
    assert api.watch_rvs[-1] == "30"


def test_api_errors_mark_source_unhealthy(run):
    from kubernetes.client.exceptions import ApiException

    api, cache = run([([], "10")], [ApiException(status=403, reason="Forbidden")])
    st = cache._status[("lab", "pods")]
    assert st.error and "403" in st.error
