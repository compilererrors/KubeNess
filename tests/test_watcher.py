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


class FakeStream:
    """The raw response of a watch request: newline-delimited JSON in arbitrary chunks."""

    def __init__(self, events, chunk=37):
        self.body = "".join(json.dumps(e) + "\n" for e in events).encode()
        self.chunk, self.closed, self.released = chunk, False, False

    def stream(self, amt=None, decode_content=False):
        for i in range(0, len(self.body), self.chunk):
            yield self.body[i:i + self.chunk]

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


class FakeApi:
    """list_fn stand-in: returns a list response, and scripted watch streams."""

    def __init__(self, lists, streams, stop):
        self.lists, self.streams, self.stop = list(lists), list(streams), stop
        self.list_calls = 0
        self.watch_rvs = []
        self.responses = []

    def __call__(self, namespace, _preload_content=True, watch=False, resource_version=None, **kw):
        assert _preload_content is False
        if not watch:
            self.list_calls += 1
            items, rv = self.lists.pop(0) if self.lists else ([], "999")
            return SimpleNamespace(data=json.dumps({"metadata": {"resourceVersion": rv}, "items": items}))
        assert kw["allow_watch_bookmarks"] and kw["timeout_seconds"] > 0
        self.watch_rvs.append(resource_version)
        if not self.streams:
            self.stop.set()
            script = []
        else:
            script = self.streams.pop(0)
        if isinstance(script, Exception):
            raise script
        self.responses.append(FakeStream(script))
        return self.responses[-1]


@pytest.fixture
def run(monkeypatch):
    def _run(lists, streams):
        stop = threading.Event()
        api = FakeApi(lists, streams, stop)
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
        {"type": "ADDED", "object": obj("b", "11")},
        {"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "15"}}},
        {"type": "DELETED", "object": obj("a", "16")},
    ]
    api, cache = run([([obj("a", "9")], "10")], [stream1, []])
    assert api.watch_rvs[:2] == ["10", "16"]
    pods = cache.snapshot(cache._status[("lab", "pods")].last_success).pods["lab"]
    assert [p["metadata"]["uid"] for p in pods] == ["b"]
    assert all(r.closed and r.released for r in api.responses), "every watch connection is given back"


def test_expired_resource_version_triggers_relist(run):
    gone = [{"type": "ERROR", "object": {"kind": "Status", "code": 410, "reason": "Expired",
                                         "message": "too old resource version"}}]
    api, cache = run([([obj("a", "9")], "10"), ([obj("c", "30")], "30")], [gone])
    assert api.list_calls >= 2
    assert api.watch_rvs[-1] == "30"


def test_api_errors_mark_source_unhealthy(run):
    from kubernetes.client.exceptions import ApiException

    api, cache = run([([], "10")], [ApiException(status=403, reason="Forbidden")])
    st = cache._status[("lab", "pods")]
    assert st.error and "403" in st.error


def test_an_error_event_other_than_expired_marks_the_source_unhealthy(run):
    failed = [{"type": "ERROR", "object": {"kind": "Status", "code": 500, "reason": "InternalError",
                                           "message": "etcd leader changed"}}]
    api, cache = run([([obj("a", "9")], "10")], [failed])
    st = cache._status[("lab", "pods")]
    assert st.error == "API error 500: InternalError: etcd leader changed"


def test_events_are_taken_as_plain_json_whatever_the_client_models_require(run):
    """An object the client's typed models would reject (an owner reference without
    apiVersion) is still an ordinary event for the cache."""
    odd = obj("b", "11")
    odd["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "web-abc", "uid": "rs-1", "controller": True}]
    api, cache = run([([], "10")], [[{"type": "ADDED", "object": odd}], []])
    st = cache._status[("lab", "pods")]
    assert st.error is None
    assert cache.snapshot(st.last_success).pods["lab"] == [odd]


# --- the real client against a local stand-in for the API server ---------------------------------

def api_server(lists, streams, stop):
    """Answers list requests from `lists` and watch requests from `streams`, as chunked
    newline-delimited JSON with every event split across two chunks."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            query = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            requests.append(query)
            if query.get("watch") != "true":
                code, body = lists.pop(0)
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if not streams:
                stop.set()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for event in (streams.pop(0) if streams else []):
                data = (json.dumps(event) + "\n").encode()
                for part in (data[:17], data[17:]):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, requests


def test_list_and_watch_through_the_real_client(monkeypatch):
    from kubernetes import client

    odd = obj("b", "11")   # no apiVersion in the owner reference: the client's typed models reject it
    odd["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "web-abc", "uid": "rs-1", "controller": True}]
    expired = {"kind": "Status", "status": "Failure", "reason": "Expired", "message": "too old", "code": 410}
    stop = threading.Event()
    server, requests = api_server(
        lists=[(200, {"kind": "PodList", "metadata": {"resourceVersion": "10"}, "items": [obj("a", "9")]}),
               (200, {"kind": "PodList", "metadata": {"resourceVersion": "30"}, "items": [obj("c", "30")]})],
        streams=[[{"type": "ADDED", "object": odd}, {"type": "DELETED", "object": obj("a", "16")}],
                 [{"type": "ERROR", "object": expired}]],
        stop=stop)
    try:
        conf = client.Configuration()
        conf.host = f"http://127.0.0.1:{server.server_address[1]}"
        core = client.CoreV1Api(client.ApiClient(conf))
        monkeypatch.setattr(w.Watcher, "_sleep", lambda self, b: self.stop_event.set() or b)
        cache = ClusterCache("lab", ["lab"], timedelta(minutes=3))
        t = w.Watcher(cache, Config(), "lab", "pods", core.list_namespaced_pod, stop)
        t.start()
        t.join(timeout=20)
        assert not t.is_alive()
    finally:
        server.shutdown()
        server.server_close()
    watches = [q for q in requests if q.get("watch") == "true"]
    # Resumed after the last event, relisted when that version had expired, resumed from the new list.
    assert [q["resourceVersion"] for q in watches] == ["10", "16", "30"]
    assert watches[0]["allowWatchBookmarks"] == "true" and watches[0]["timeoutSeconds"] == "60"
    st = cache._status[("lab", "pods")]
    assert st.error is None
    assert [p["metadata"]["uid"] for p in cache.snapshot(st.last_success).pods["lab"]] == ["c"]
