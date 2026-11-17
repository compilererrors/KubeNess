"""Renders the Helm chart and checks the parts that carry security boundaries."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from kubeness.config import Config

ROOT = Path(__file__).resolve().parents[1]
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="helm not installed")


def render(*sets: str) -> list[dict]:
    args = [HELM, "template", "kubeness", str(ROOT / "charts" / "kubeness"), "-n", "kubeness"]
    for s in sets:
        args += ["--set", s]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def by(docs, kind, name=None):
    return [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]


def test_rendered_config_is_valid():
    for sets in [(), ("model.enabled=true",), ("access.readLogs=false",)]:
        docs = render(*sets)
        cm = by(docs, "ConfigMap")[0]
        Config.model_validate(yaml.safe_load(cm["data"]["config.yaml"]))


def test_reader_role_has_no_secrets_exec_or_writes():
    role = by(render(), "Role")[0]
    verbs = {v for r in role["rules"] for v in r["verbs"]}
    resources = {res for r in role["rules"] for res in r["resources"]}
    assert verbs <= {"get", "list", "watch"}
    assert "secrets" not in resources and "pods/exec" not in resources
    assert "pods/log" in resources
    role_nologs = by(render("access.readLogs=false"), "Role")[0]
    assert "pods/log" not in {res for r in role_nologs["rules"] for res in r["resources"]}


def test_one_role_per_watched_namespace():
    roles = by(render("access.namespaces={lab,shop}"), "Role")
    assert sorted(r["metadata"]["namespace"] for r in roles) == ["lab", "shop"]


def test_observer_runs_single_recreate_hardened():
    dep = by(render(), "Deployment", "kubeness-observer")[0]
    assert dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"]["type"] == "Recreate"
    c = dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert c["readOnlyRootFilesystem"] and not c["allowPrivilegeEscalation"] and c["capabilities"]["drop"] == ["ALL"]


def test_model_pod_has_no_token_and_no_egress():
    docs = render("model.enabled=true")
    dep = by(docs, "Deployment", "kubeness-model")[0]
    spec = dep["spec"]["template"]["spec"]
    assert spec["automountServiceAccountToken"] is False
    assert not any(r["kind"] in ("Role", "RoleBinding") and "model" in r["metadata"]["name"] for r in docs)
    np = by(docs, "NetworkPolicy", "kubeness-model")[0]
    assert np["spec"]["egress"] == []
    assert np["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "observer"
    obs_np = by(docs, "NetworkPolicy", "kubeness-observer")[0]
    assert any(
        (t.get("podSelector") or {}).get("matchLabels", {}).get("app.kubernetes.io/component") == "model"
        for rule in obs_np["spec"]["egress"] for t in rule["to"]
    )
    assert by(render(), "Deployment", "kubeness-model") == []


# --- B12 notifier -------------------------------------------------------------------------------

NOTIFY = ("notifications.enabled=true",)


def pod_specs(docs):
    return [(d["metadata"]["name"], d["spec"]["template"]["spec"]) for d in docs if d["kind"] == "Deployment"]


def test_notifier_is_absent_unless_enabled():
    docs = render()
    assert by(docs, "Deployment", "kubeness-notifier") == []
    assert by(docs, "Secret") == []
    cfg = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap")[0]["data"]["config.yaml"]))
    assert not cfg.notifications.enabled


def test_notifier_config_and_observer_config_match():
    docs = render(*NOTIFY)
    obs = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
    assert obs.notifications.enabled and obs.notifications.url == "http://kubeness-notifier:8081"
    from kubeness.notifier import NotifierConfig
    ncfg = NotifierConfig.model_validate(
        yaml.safe_load(by(docs, "ConfigMap", "kubeness-notifier")[0]["data"]["notifier.yaml"]))
    assert ncfg.port == 8081 and ncfg.provider == "webhook"
    assert str(ncfg.token_file) == str(obs.notifications.token_file)


def test_n26_token_secret_only_in_observer_and_notifier():
    docs = render(*NOTIFY, "model.enabled=true")
    (secret,) = by(docs, "Secret", "kubeness-notifier-token")
    assert secret["type"] == "Opaque" and secret["data"]["token"]
    mounting = sorted(name for name, spec in pod_specs(docs)
                      if any((v.get("secret") or {}).get("secretName") == "kubeness-notifier-token"
                             for v in spec.get("volumes", [])))
    assert mounting == ["kubeness-notifier", "kubeness-observer"]
    dest = sorted(name for name, spec in pod_specs(docs)
                  if any((v.get("secret") or {}).get("secretName") == "kubeness-notifications"
                         for v in spec.get("volumes", [])))
    assert dest == ["kubeness-notifier"]


def test_n27_notifier_has_no_api_access_and_is_hardened():
    docs = render(*NOTIFY)
    (dep,) = by(docs, "Deployment", "kubeness-notifier")
    spec = dep["spec"]["template"]["spec"]
    assert spec["automountServiceAccountToken"] is False
    assert not any(d["kind"] in ("Role", "RoleBinding", "ClusterRoleBinding") and "notifier" in d["metadata"]["name"]
                   for d in docs)
    c = spec["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] and c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert spec["securityContext"]["runAsNonRoot"]


def test_notifier_network_policy():
    docs = render(*NOTIFY)
    np = by(docs, "NetworkPolicy", "kubeness-notifier")[0]["spec"]
    (ing,) = np["ingress"]
    assert ing["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "observer"
    assert ing["ports"] == [{"protocol": "TCP", "port": 8081}]
    ports = [p["port"] for rule in np["egress"] for p in rule.get("ports", [])]
    assert 53 in ports and 443 in ports
    obs = by(docs, "NetworkPolicy", "kubeness-observer")[0]["spec"]
    assert any((t.get("podSelector") or {}).get("matchLabels", {}).get("app.kubernetes.io/component") == "notifier"
               for rule in obs["egress"] for t in rule["to"])


def test_lab_values_narrow_notifier_egress_to_the_sink():
    args = [HELM, "template", "kubeness", str(ROOT / "charts" / "kubeness"), "-n", "kubeness",
            "-f", str(ROOT / "lab" / "values-lab.yaml")]
    docs = [d for d in yaml.safe_load_all(subprocess.run(args, capture_output=True, text=True, check=True).stdout) if d]
    np = by(docs, "NetworkPolicy", "kubeness-notifier")[0]["spec"]
    ports = [p["port"] for rule in np["egress"] for p in rule.get("ports", [])]
    assert 443 not in ports and 8080 in ports


def test_read_nodes_is_a_separate_cluster_scoped_opt_in():
    docs = render()
    assert by(docs, "ClusterRole") == [] and by(docs, "ClusterRoleBinding") == []
    docs = render("access.readNodes=true")
    (role,) = by(docs, "ClusterRole")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list"]}]
    (binding,) = by(docs, "ClusterRoleBinding")
    assert binding["subjects"][0]["name"] == "kubeness-observer"
    cfg = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
    assert cfg.access.read_nodes


# --- B24 executor -------------------------------------------------------------------------------

ACT = ("executor.enabled=true", "actions.enabled=true", "access.profile=remediate")


def test_executor_absent_by_default():
    docs = render()
    assert by(docs, "Deployment", "kubeness-executor") == []
    assert not [d for d in docs if d["kind"] == "Role" and "executor" in d["metadata"]["name"]]


def test_x01_executor_writer_role_is_minimal():
    docs = render(*ACT, "access.namespaces={lab,shop}")
    roles = [d for d in docs if d["kind"] == "Role" and "executor" in d["metadata"]["name"]]
    assert sorted(r["metadata"]["namespace"] for r in roles) == ["lab", "shop"]
    extra = 0
    for r in roles:
        for rule in r["rules"]:
            if rule not in ({"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "patch"]},
                            {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get", "list"]}):
                extra += 1
    from kpi_report import kpi
    kpi("X01", "executor rules beyond get/patch deployments", extra, "count", eq=0)
    assert not [d for d in docs if d["kind"] in ("ClusterRole", "ClusterRoleBinding") and "executor" in d["metadata"]["name"]]
    for observer in [d for d in by(docs, "Role") if "observer" in d["metadata"]["name"]]:
        assert {v for r in observer["rules"] for v in r["verbs"]} <= {"get", "list", "watch"}


def test_executor_pod_network_and_token():
    docs = render(*ACT)
    (dep,) = by(docs, "Deployment", "kubeness-executor")
    spec = dep["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == "kubeness-executor"
    mounting = sorted(name for name, s in pod_specs(docs)
                      if any((v.get("secret") or {}).get("secretName") == "kubeness-executor-token"
                             for v in s.get("volumes", [])))
    assert mounting == ["kubeness-executor", "kubeness-observer"]
    np = by(docs, "NetworkPolicy", "kubeness-executor")[0]["spec"]
    assert np["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "observer"
    obs = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
    assert obs.actions.enabled and obs.actions.url == "http://kubeness-executor:8082"
    from kubeness.executor import ExecutorConfig
    ecfg = ExecutorConfig.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-executor")[0]["data"]["executor.yaml"]))
    assert ecfg.namespaces == ["lab"]


# --- B27 model size profiles --------------------------------------------------------------------

# Working memory per model: weights plus runtime and a small context (measured or published sizes).
MODEL_NEEDS_GI = {"0.6b": 1.0, "1.7b": 2.5, "4b": 4.5}


def _gi(q: str) -> float:
    return float(q[:-2]) / (1024 if q.endswith("Mi") else 1) if q.endswith(("Mi", "Gi")) else float(q) / 2**30


def test_p10_p11_model_profiles():
    valid, short = 0, 0
    for size, need in MODEL_NEEDS_GI.items():
        args = [HELM, "template", "kubeness", str(ROOT / "charts" / "kubeness"), "-n", "kubeness",
                "-f", str(ROOT / "lab" / "values-lab.yaml"), "-f", str(ROOT / "lab" / "models" / f"{size}.yaml")]
        docs = [d for d in yaml.safe_load_all(subprocess.run(args, capture_output=True, text=True, check=True).stdout) if d]
        cfg = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
        dep = by(docs, "Deployment", "kubeness-model")[0]["spec"]["template"]["spec"]["containers"][0]
        assert cfg.model.name == f"qwen3:{size}" and dep["image"].endswith(f"qwen3-{size}")
        valid += 1
        short += _gi(dep["resources"]["limits"]["memory"]) < need
    from kpi_report import kpi
    kpi("P10", "model profiles rendering a valid config", valid, "count", eq=3)
    kpi("P11", "model profiles with a memory limit below the model's need", short, "count", eq=0)


# --- B28 silos ----------------------------------------------------------------------------------

def render_silos(*extra):
    return render("access.silos[0].name=lab", "access.silos[0].namespaces={lab}", "access.silos[0].profile=remediate",
                  "access.silos[1].name=shop", "access.silos[1].namespaces={shop}", "access.silos[1].profile=observe",
                  "access.silos[2].name=ops", "access.silos[2].namespaces={ops}", "access.silos[2].profile=investigate",
                  *extra)


def test_g01_rbac_follows_the_silo_profiles():
    docs = render_silos(*ACT)
    readers = {r["metadata"]["namespace"]: {x for rule in r["rules"] for x in rule["resources"]}
               for r in by(docs, "Role") if "reader" in r["metadata"]["name"]}
    writers = sorted(r["metadata"]["namespace"] for r in by(docs, "Role") if "writer" in r["metadata"]["name"])
    extra = int("pods/log" in readers["shop"]) + int(writers != ["lab"])
    from kpi_report import kpi
    kpi("G01", "RBAC grants beyond the silo profile", extra, "count", eq=0)
    assert "pods/log" in readers["lab"] and "pods/log" in readers["ops"]
    cfg = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
    assert cfg.access.namespaces == ["lab", "shop", "ops"]
    assert cfg.access.silo_for("shop").profile == "observe"
    from kubeness.executor import ExecutorConfig
    ecfg = ExecutorConfig.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-executor")[0]["data"]["executor.yaml"]))
    assert ecfg.namespaces == ["lab"]


def test_tiered_profile_fits_both_models():
    args = [HELM, "template", "kubeness", str(ROOT / "charts" / "kubeness"), "-n", "kubeness",
            "-f", str(ROOT / "lab" / "values-lab.yaml"), "-f", str(ROOT / "lab" / "models" / "tiered.yaml")]
    docs = [d for d in yaml.safe_load_all(subprocess.run(args, capture_output=True, text=True, check=True).stdout) if d]
    cfg = Config.model_validate(yaml.safe_load(by(docs, "ConfigMap", "kubeness-observer")[0]["data"]["config.yaml"]))
    assert (cfg.model.name, cfg.model.escalation.model) == ("qwen3:0.6b", "qwen3:1.7b")
    assert cfg.model.escalation.when == ["invalid", "unsupported", "troubleshoot"]
    dep = by(docs, "Deployment", "kubeness-model")[0]["spec"]["template"]["spec"]["containers"][0]
    assert _gi(dep["resources"]["limits"]["memory"]) >= MODEL_NEEDS_GI["0.6b"] + MODEL_NEEDS_GI["1.7b"]


def test_observer_probes_tolerate_a_starved_cpu():
    """The model pod can keep the node's CPUs busy; a slow answer must not get the observer killed."""
    dep = by(render("model.enabled=true"), "Deployment", "kubeness-observer")[0]
    c = dep["spec"]["template"]["spec"]["containers"][0]
    for probe in (c["readinessProbe"], c["livenessProbe"]):
        assert probe.get("timeoutSeconds", 1) >= 5
    live = c["livenessProbe"]
    assert live["periodSeconds"] * live["failureThreshold"] >= 120
    assert c["resources"]["requests"]["cpu"] in ("100m", "200m", "250m")
