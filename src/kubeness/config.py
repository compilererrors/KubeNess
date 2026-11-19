"""Configuration schema. The file is rendered by the Helm chart into a ConfigMap."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

_DURATION = re.compile(r"^(\d+)(s|m|h|d)$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(value: object) -> timedelta:
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    m = _DURATION.match(str(value).strip())
    if not m:
        raise ValueError(f"invalid duration {value!r}, expected e.g. 30s, 5m, 1h or 14d")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


Duration = Annotated[timedelta, BeforeValidator(parse_duration)]
RuleId = Literal["restarts", "imagePull", "readiness", "scheduling", "oom", "observerDegraded"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class KubernetesConfig(_Model):
    # Only used when running outside a cluster. There is deliberately no fallback
    # to the current kubeconfig context.
    context: str | None = None


Profile = Literal["observe", "investigate", "recommend", "remediate"]
PROFILE_RANK = {"observe": 0, "investigate": 1, "recommend": 2, "remediate": 3}


class SiloConfig(_Model):
    """A group of namespaces with one access profile:

    * observe:     status, events and specs
    * investigate: + container logs
    * recommend:   + the model may propose fixes
    * remediate:   + approved actions through the executor
    """

    # Also a label value on the RBAC objects the chart creates.
    name: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$")
    namespaces: list[str] = Field(min_length=1)
    profile: Profile = "investigate"


class AccessConfig(_Model):
    namespaces: list[str] = Field(default_factory=lambda: ["lab"], min_length=1)
    # Profile of the namespaces above when no silos are given.
    profile: Profile = "investigate"
    # When set, the silos define the watched namespaces and their profiles.
    silos: list[SiloConfig] = Field(default_factory=list)
    read_logs: bool = Field(True, alias="readLogs")
    # Cluster-scoped and therefore a separate opt-in: node allocatable and taints as
    # scheduling evidence. The chart adds a ClusterRole only when this is true.
    read_nodes: bool = Field(False, alias="readNodes")
    # Services and EndpointSlices as readiness evidence; the chart grants the reads.
    read_services: bool = Field(False, alias="readServices")

    @model_validator(mode="after")
    def _silos(self) -> "AccessConfig":
        if self.silos:
            seen: dict[str, str] = {}
            for s in self.silos:
                for ns in s.namespaces:
                    if ns in seen:
                        raise ValueError(f"namespace {ns} is in more than one silo ({seen[ns]}, {s.name})")
                    seen[ns] = s.name
            self.namespaces = list(seen)
        return self

    def silo_list(self) -> list[SiloConfig]:
        return self.silos or [SiloConfig(name="default", namespaces=self.namespaces, profile=self.profile)]

    def silo_for(self, namespace: str) -> SiloConfig | None:
        return next((s for s in self.silo_list() if namespace in s.namespaces), None)

    def _rank(self, namespace: str) -> int:
        s = self.silo_for(namespace)
        return PROFILE_RANK[s.profile] if s else -1

    def logs_allowed(self, namespace: str) -> bool:
        return self.read_logs and self._rank(namespace) >= PROFILE_RANK["investigate"]

    def fixes_allowed(self, namespace: str) -> bool:
        return self._rank(namespace) >= PROFILE_RANK["recommend"]

    def actions_allowed(self, namespace: str) -> bool:
        return self._rank(namespace) >= PROFILE_RANK["remediate"]


class CollectionConfig(_Model):
    log_tail_lines: int = Field(100, alias="logTailLines")
    log_window: Duration = Field(timedelta(minutes=5), alias="logWindow")
    max_events: int = Field(20, alias="maxEvents")


class RestartRuleConfig(_Model):
    count: int = 3
    window: Duration = timedelta(minutes=5)
    crash_loop_for: Duration = Field(timedelta(minutes=5), alias="crashLoopFor")


class ImagePullRuleConfig(_Model):
    for_: Duration = Field(timedelta(seconds=60), alias="for")


class ReadinessRuleConfig(_Model):
    for_: Duration = Field(timedelta(minutes=2), alias="for")


class SchedulingRuleConfig(_Model):
    for_: Duration = Field(timedelta(minutes=2), alias="for")


class OomRuleConfig(_Model):
    # A second OOM kill within this window raises the incident from info to warning.
    window: Duration = timedelta(minutes=30)


class AlarmsConfig(_Model):
    rules: list[RuleId] = Field(
        default_factory=lambda: ["restarts", "imagePull", "readiness", "scheduling", "oom", "observerDegraded"])
    recovery_window: Duration = Field(timedelta(seconds=60), alias="recoveryWindow")
    recovery_settle: Duration = Field(timedelta(seconds=30), alias="recoverySettle")
    reopen_window: Duration = Field(timedelta(minutes=30), alias="reopenWindow")
    repeat_interval: Duration = Field(timedelta(minutes=30), alias="repeatInterval")
    critical_workloads: list[str] = Field(default_factory=list, alias="criticalWorkloads")
    # Raise a warning incident to critical when it has been firing this long. Off by default.
    escalate_after: Duration | None = Field(None, alias="escalateAfter")
    restarts: RestartRuleConfig = RestartRuleConfig()
    image_pull: ImagePullRuleConfig = Field(ImagePullRuleConfig(), alias="imagePull")
    readiness: ReadinessRuleConfig = ReadinessRuleConfig()
    scheduling: SchedulingRuleConfig = SchedulingRuleConfig()
    oom: OomRuleConfig = OomRuleConfig()


class ObserverConfig(_Model):
    evaluation_interval: Duration = Field(timedelta(seconds=10), alias="evaluationInterval")
    resync: Duration = timedelta(minutes=10)
    watch_timeout: Duration = Field(timedelta(seconds=60), alias="watchTimeout")
    freshness_budget: Duration = Field(timedelta(minutes=3), alias="freshnessBudget")
    data_dir: Path = Field(Path("/data"), alias="dataDir")
    # Resolved incidents (with their evidence, analyses, notifications, questions
    # and actions) and sent digests older than this are deleted.
    retention: Duration = timedelta(days=14)


Trigger = Literal["invalid", "unsupported", "ungrounded", "critical", "recurring", "troubleshoot"]


class EscalationConfig(_Model):
    """Tiered models: the primary (small) model analyses every incident; this larger
    model takes over by rule, never by the small model's own judgement.

    * invalid:      the small model's answer failed validation or timed out
    * unsupported:  it made claims that cite no stored evidence (removed by validation)
    * ungrounded:   no next check names an object of the incident (strict: small
                    models often phrase checks generically, so this escalates often)
    * critical:     the incident is critical
    * recurring:    the incident reopened within the reopen window
    * troubleshoot: experimental troubleshooting runs on this model
    """

    model: str | None = None
    # Named "when", not "on": YAML 1.1 reads a bare on as true.
    when: list[Trigger] = Field(default_factory=lambda: ["invalid", "unsupported", "troubleshoot"])


class ModelConfig(_Model):
    # Template analysis is always produced; the model is an optional enrichment.
    enabled: bool = False
    provider: Literal["ollama"] = "ollama"
    url: str = "http://kubeness-model:11434"
    name: str = "qwen3:0.6b"
    timeout: Duration = timedelta(seconds=20)
    think: bool = False
    # llama.cpp defaults to one thread per visible CPU. In a container sharing the
    # node with other pods that oversubscribes the CPUs and is ~100x slower.
    num_threads: int = Field(4, alias="numThreads", ge=1, le=64)
    max_concurrent_requests: int = Field(1, alias="maxConcurrentRequests", ge=1, le=4)
    queue_size: int = Field(20, alias="queueSize", ge=1)
    # PoC: further models that analyse every incident in the shadow. Their results
    # are validated and stored for comparison, never shown as the incident analysis.
    compare: list[str] = Field(default_factory=list)
    escalation: EscalationConfig = EscalationConfig()


class NotificationsConfig(_Model):
    # The observer keeps an outbox and sends through the notifier pod, which alone
    # holds the provider credential and destination.
    enabled: bool = False
    url: str = "http://kubeness-notifier:8081"
    token_file: Path = Field(Path("/var/run/kubeness/notifier/token"), alias="tokenFile")
    timeout: Duration = timedelta(seconds=10)
    send_interval: Duration = Field(timedelta(seconds=2), alias="sendInterval")
    max_attempts: int = Field(20, alias="maxAttempts", ge=1)
    backoff: Duration = timedelta(seconds=10)
    backoff_max: Duration = Field(timedelta(minutes=10), alias="backoffMax")
    # Periodic heartbeat to an external dead man's switch; 0s disables it.
    heartbeat_interval: Duration = Field(timedelta(0), alias="heartbeatInterval")
    # Info events (new images, recurrences, restarts without an incident, info
    # incidents) are sent as one digest per interval; 0s disables the digest.
    digest_interval: Duration = Field(timedelta(hours=1), alias="digestInterval")


class ActionsConfig(_Model):
    # Writes to the cluster, through the separate executor pod. Off by default.
    enabled: bool = False
    url: str = "http://kubeness-executor:8082"
    token_file: Path = Field(Path("/var/run/kubeness/executor/token"), alias="tokenFile")
    timeout: Duration = timedelta(seconds=10)
    allowed: list[Literal["restart-deployment", "rollback-deployment"]] = Field(
        default_factory=lambda: ["restart-deployment"])


class TroubleshootConfig(_Model):
    # Experimental: the model investigates an incident step by step with read-only
    # tools that the observer runs inside the incident's workload and silo profile.
    enabled: bool = False
    max_steps: int = Field(5, alias="maxSteps", ge=1, le=10)
    # Let the model reason before each step (slower, often better with small models).
    think: bool = True
    step_timeout: Duration = Field(timedelta(seconds=90), alias="stepTimeout")
    # Let the conclusion propose one allowed action (silos with recommend or remediate).
    # A proposal is only executed after approval in the UI, in a remediate silo.
    propose_fixes: bool = Field(False, alias="proposeFixes")


class ExperimentalConfig(_Model):
    troubleshoot: TroubleshootConfig = TroubleshootConfig()


class UiConfig(_Model):
    port: int = 8080
    # Address the web server binds. Unset: every interface in a cluster, where the
    # kubelet probes need it and NetworkPolicy guards the pod, and loopback elsewhere.
    # The Host check below stops DNS rebinding; it does not authenticate other
    # machines on the network.
    host: str | None = None
    # Host header values accepted by the web UI. Protects against DNS rebinding
    # when the UI is reached through kubectl port-forward on localhost.
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost"], alias="allowedHosts"
    )


class Config(_Model):
    cluster: str = "lab"
    kubernetes: KubernetesConfig = KubernetesConfig()
    access: AccessConfig = AccessConfig()
    collection: CollectionConfig = CollectionConfig()
    alarms: AlarmsConfig = AlarmsConfig()
    observer: ObserverConfig = ObserverConfig()
    model: ModelConfig = ModelConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    actions: ActionsConfig = ActionsConfig()
    experimental: ExperimentalConfig = ExperimentalConfig()
    ui: UiConfig = UiConfig()


def load_config(path: str | Path | None) -> Config:
    if path is None:
        return Config()
    data = yaml.safe_load(Path(path).read_text()) or {}
    return Config.model_validate(data)
