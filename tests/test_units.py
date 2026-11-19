from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from kubeness.cache import ClusterCache
from kubeness.config import Config, load_config, parse_duration
from kubeness.snapshot import resolve_workload
from kubeness.tracker import SinceTracker

from factories import at, pod, replicaset

ROOT = Path(__file__).resolve().parents[1]


def test_workload_resolution_follows_owner_chain():
    rs = replicaset()
    wl = resolve_workload(pod(), {rs["metadata"]["uid"]: rs})
    assert (wl.kind, wl.name) == ("Deployment", "web")


def test_new_replicaset_maps_to_same_workload():
    rs1, rs2 = replicaset("web-a", "rs-a"), replicaset("web-b", "rs-b")
    rs_map = {"rs-a": rs1, "rs-b": rs2}
    p1 = pod(owner={"kind": "ReplicaSet", "name": "web-a", "uid": "rs-a", "controller": True})
    p2 = pod(owner={"kind": "ReplicaSet", "name": "web-b", "uid": "rs-b", "controller": True})
    assert resolve_workload(p1, rs_map) == resolve_workload(p2, rs_map)


def test_standalone_and_statefulset_pods():
    assert resolve_workload(pod(owner={}), {}).kind == "Pod"
    sts = {"kind": "StatefulSet", "name": "db", "uid": "sts-1", "controller": True}
    assert resolve_workload(pod(owner=sts), {}).name == "db"


def test_tracker_grace_keeps_start_time():
    t = SinceTracker(grace=timedelta(seconds=30))
    assert t.update("k", True, at(0)) == at(0)
    assert t.update("k", False, at(10)) == at(0)   # within grace
    assert t.update("k", True, at(20)) == at(0)
    assert t.update("k", False, at(60)) is None    # gap longer than grace
    assert t.update("k", True, at(70)) == at(70)


def test_durations():
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("5m") == timedelta(minutes=5)
    with pytest.raises(ValueError):
        parse_duration("5 minutes")


def test_example_config_loads():
    cfg = load_config(ROOT / "config" / "example.yaml")
    assert cfg.kubernetes.context == "kind-kubeness"
    assert cfg.alarms.image_pull.for_ == timedelta(seconds=60)


def test_unknown_keys_are_rejected():
    with pytest.raises(ValidationError):
        Config.model_validate({"access": {"readSecrets": True}})


def test_cache_marks_namespace_stale():
    cache = ClusterCache("lab", ["lab"], timedelta(minutes=3))
    for kind in ("pods", "replicasets", "deployments"):
        cache.replace("lab", kind, [], at(0))
    assert cache.snapshot(at(60)).stale_namespaces == set()
    assert cache.snapshot(at(600)).stale_namespaces == {"lab"}
    cache.mark_ok("lab", "pods", at(600))
    cache.mark_ok("lab", "replicasets", at(600))
    cache.mark_ok("lab", "deployments", at(600))
    # An error alone does not make the namespace stale; the budget does.
    cache.mark_error("lab", "pods", "connection refused")
    assert cache.snapshot(at(610)).stale_namespaces == set()
    assert cache.snapshot(at(600 + 181)).stale_namespaces == {"lab"}


@pytest.mark.parametrize("name", ["team a", "-lab", "lab/", "x" * 64])
def test_a_silo_name_must_be_usable_as_a_label_value(name):
    with pytest.raises(ValidationError):
        Config.model_validate({"access": {"silos": [{"name": name, "namespaces": ["lab"]}]}})


def test_ordinary_silo_names_are_accepted():
    cfg = Config.model_validate({"access": {"silos": [{"name": "shop_1.eu", "namespaces": ["shop"]},
                                                      {"name": "lab-observe", "namespaces": ["lab"]}]}})
    assert cfg.access.namespaces == ["shop", "lab"]


def test_the_store_records_its_schema_version(tmp_path):
    import sqlite3

    from kubeness.store import SCHEMA_VERSION, Store

    path = tmp_path / "incidents.db"
    Store(path).close()
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    Store(path).close()   # the same version opens again

    # A file from before the version was recorded has the same tables and is adopted.
    db.execute("PRAGMA user_version = 0")
    db.commit()
    Store(path).close()
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

    # A file written by a newer build is refused instead of being read with the wrong schema.
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.commit()
    db.close()
    with pytest.raises(RuntimeError, match="newer KubeNess"):
        Store(path)
