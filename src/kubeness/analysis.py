"""Structured analysis: schema, validation against evidence, and the template runbooks.

Template analysis is deterministic and always produced. Model analysis is an
optional enrichment that must pass the same validation: every observed fact must
cite an existing evidence ID, and claims without support are dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from .lifecycle import Incident
from .store import EvidenceItem


class Claim(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=10)


class Analysis(BaseModel):
    summary: str = Field(min_length=1, max_length=400)
    observed_facts: list[Claim] = Field(default_factory=list, max_length=10)
    possible_causes: list[Claim] = Field(default_factory=list, max_length=6)
    next_checks: list[str] = Field(default_factory=list, max_length=6)
    missing_information: list[str] = Field(default_factory=list, max_length=6)



@dataclass
class Validated:
    analysis: Analysis
    dropped: list[str] = field(default_factory=list)


def validate_refs(analysis: Analysis, evidence_refs: set[str]) -> Validated:
    """Keep only references that exist; drop facts and causes left without support."""
    dropped: list[str] = []

    def clean(claims: list[Claim], kind: str) -> list[Claim]:
        out = []
        for c in claims:
            refs = [r for r in dict.fromkeys(c.evidence_refs) if r in evidence_refs]
            if refs:
                out.append(Claim(text=c.text, evidence_refs=refs))
            else:
                dropped.append(f"{kind}: {c.text}")
        return out

    result = analysis.model_copy(
        update={
            "observed_facts": clean(analysis.observed_facts, "observed_fact"),
            "possible_causes": clean(analysis.possible_causes, "possible_cause"),
        }
    )
    return Validated(result, dropped)


# --- runbooks ----------------------------------------------------------------------------------
# One deterministic runbook per incident family (the branches of template_analysis):
# each reads specific evidence, states grounded facts and maps known patterns to
# hypotheses and next checks.


def _find(evidence: list[EvidenceItem], kind: str) -> list[EvidenceItem]:
    return [e for e in evidence if e.kind == kind]


def _events_matching(evidence: list[EvidenceItem], pattern: str) -> list[EvidenceItem]:
    rx = re.compile(pattern, re.I)
    return [
        e for e in _find(evidence, "event")
        if rx.search(f"{e.payload.get('reason', '')} {e.payload.get('message', '')}")
    ]


def _last_error_line(text: str) -> str | None:
    rx = re.compile(r"(?i)\b(fatal|error|exception|panic|failed|traceback|refused|denied)\b")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if rx.search(ln):
            return ln[:200]
    return None


def _claim(text: str, evidence_refs: list[str]) -> Claim:
    """Runbook claims embed cluster values (image names, reasons) of any length."""
    return Claim(text=text if len(text) <= 500 else text[:499] + "…", evidence_refs=evidence_refs)


def template_analysis(inc: Incident, evidence: list[EvidenceItem], logs_enabled: bool) -> Analysis:
    # A reopened incident has evidence from every firing; analyse the latest one
    # (its rule evidence and everything collected after it).
    rule = next((e for e in reversed(evidence) if e.kind == "rule"), None)
    if rule is not None:
        evidence = [e for e in evidence if e.collected_at >= rule.collected_at]
    facts: list[Claim] = []
    causes: list[Claim] = []
    checks: list[str] = []
    missing: list[str] = []
    rref = [rule.ref] if rule else []
    details = rule.payload if rule else inc.details
    logs = _find(evidence, "log")

    if inc.rule_id == "restarts":
        containers = details.get("containers") or []
        facts.append(_claim(text=inc.reason, evidence_refs=rref))
        for c in containers[:3]:
            term = c.get("lastTermination") or {}
            if term:
                facts.append(Claim(
                    text=f"Container {c['container']} last terminated with reason {term.get('reason')} "
                         f"and exit code {term.get('exitCode')} (restart count {c.get('restartCount')}).",
                    evidence_refs=rref,
                ))
                if term.get("reason") == "OOMKilled" or term.get("exitCode") == 137:
                    causes.append(_claim(text="The container is killed for exceeding its memory limit.", evidence_refs=rref))
        for log in logs:
            line = _last_error_line(log.payload.get("text", ""))
            if line:
                facts.append(_claim(text=f"Log of {log.payload.get('container')} ends with: {line}", evidence_refs=[log.ref]))
                causes.append(Claim(
                    text="The application exits on the error shown in its log; the cause is inside the "
                         "application or its configuration.",
                    evidence_refs=[log.ref],
                ))
                break
        probe = _events_matching(evidence, r"(liveness|startup) probe failed")
        if probe:
            causes.append(_claim(text="A failing liveness or startup probe restarts the container.",
                                evidence_refs=[probe[0].ref]))
        if not causes:
            causes.append(_claim(text="The application exits with an error at startup; its logs or "
                                     "termination message hold the reason.", evidence_refs=rref))
        checks += ["Fix the error from the previous log, then watch that the restart count stops increasing.",
                   "Compare with the last working version if a rollout preceded the restarts."]
        if not logs and not _find(evidence, "gap"):
            missing.append("Previous container logs." if logs_enabled else "Logs: log access is disabled.")

    elif inc.rule_id == "imagePull":
        c = (details.get("containers") or [{}])[0]
        image = c.get("specImage") or "?"
        facts.append(_claim(text=f"The pod cannot pull image {image} ({c.get('waitingReason', 'pull error')}).",
                           evidence_refs=rref))
        # "no such host" is a DNS failure, not a missing tag: keep the two patterns apart.
        missing_tag = _events_matching(evidence, r"manifest unknown|not found|no such (image|manifest|tag)")
        auth = _events_matching(evidence, r"unauthori[sz]ed|denied|authentication required|\b403\b")
        network = _events_matching(evidence, r"timeout|timed out|no such host|connection refused")
        pulled = missing_tag or auth or network
        if pulled:
            facts.append(_claim(text=f"Event: {pulled[0].payload.get('message', '')[:240]}",
                               evidence_refs=[pulled[0].ref]))
        if missing_tag:
            causes.append(_claim(text="The tag does not exist in the registry the workload uses.",
                                evidence_refs=[missing_tag[0].ref]))
            checks.append(f"Check that the tag in {image} exists in the repository.")
        if auth:
            causes.append(_claim(text="The registry rejects the pull because credentials are missing or wrong.",
                                evidence_refs=[auth[0].ref]))
            checks.append("Check imagePullSecrets and the registry permissions for this repository.")
        if network:
            causes.append(_claim(text="The node cannot reach the registry.", evidence_refs=[network[0].ref]))
            checks.append("Check DNS and network access from the node to the registry.")
        if not pulled:
            causes.append(_claim(text="The image reference is wrong or the registry is unavailable.", evidence_refs=rref))
            checks.append(f"Check the exact image reference {image} in the Deployment.")
        missing.append("The registry content has not been verified directly.")

    elif inc.rule_id == "readiness":
        facts.append(_claim(text=inc.reason, evidence_refs=rref))
        prog = details.get("progressing") or {}
        if prog.get("reason") == "ProgressDeadlineExceeded":
            facts.append(_claim(text="The Deployment reports ProgressDeadlineExceeded: the rollout is stuck.",
                               evidence_refs=rref))
        probe = _events_matching(evidence, r"readiness probe failed")
        if probe:
            facts.append(_claim(text=f"Event: {probe[0].payload.get('message', '')[:240]}", evidence_refs=[probe[0].ref]))
            causes.append(_claim(text="The readiness probe fails, so the pod never receives traffic.",
                                evidence_refs=[probe[0].ref]))
            checks.append("Compare the readiness probe with what the application actually serves.")
        for log in logs:
            line = _last_error_line(log.payload.get("text", ""))
            if line:
                facts.append(_claim(text=f"Log of {log.payload.get('container')}: {line}", evidence_refs=[log.ref]))
                causes.append(_claim(text="The application reports an error during startup.", evidence_refs=[log.ref]))
                break
        for svc_ev in _find(evidence, "service"):
            for svc in svc_ev.payload.get("services") or []:
                nr = f" (not ready: {', '.join(svc['notReadyPods'])})" if svc.get("notReadyPods") else ""
                facts.append(_claim(text=f"Service {svc['name']} has {svc['ready']} ready and {svc['notReady']} "
                                         f"not ready endpoints{nr}.", evidence_refs=[svc_ev.ref]))
                if svc["ready"] == 0:
                    causes.append(_claim(text=f"Traffic to Service {svc['name']} reaches no ready endpoint.",
                                         evidence_refs=[svc_ev.ref]))
                    checks.append(f"Check that Service {svc['name']} targets the port the application listens on "
                                  f"({', '.join(svc.get('ports') or [])}) and why its pods are not ready.")
        if not causes:
            causes.append(_claim(text="The containers start but do not become ready.", evidence_refs=rref))
        checks.append("Describe one of the pods and read its conditions and probe configuration.")
        if not logs and not _find(evidence, "gap"):
            missing.append("Current container logs." if logs_enabled else "Logs: log access is disabled.")

    elif inc.rule_id == "scheduling":
        facts.append(_claim(text=inc.reason, evidence_refs=rref))
        pods = details.get("pods") or []
        msg = " ".join(p.get("message", "") for p in pods)
        sched = _events_matching(evidence, r"FailedScheduling|nodes are available")
        if sched:
            facts.append(_claim(text=f"Event: {sched[0].payload.get('message', '')[:240]}", evidence_refs=[sched[0].ref]))
        refs = [sched[0].ref] if sched else rref
        requests = {k: v for p in pods for k, v in (p.get("requests") or {}).items() if v}
        if re.search(r"Insufficient (cpu|memory|ephemeral-storage|pods)", msg):
            what = ", ".join(sorted(set(re.findall(r"Insufficient ([\w-]+)", msg))))
            causes.append(_claim(text=f"The pod requests more resources ({what}) than any node can offer.",
                                 evidence_refs=refs))
            checks.append("Compare the container resource requests"
                          + (f" ({', '.join(f'{c}: {r}' for c, r in requests.items())})" if requests else "")
                          + " with the nodes' allocatable capacity, then lower the requests or add capacity.")
        if "node affinity/selector" in msg or "didn't match" in msg:
            causes.append(_claim(text="The nodeSelector or node affinity matches no node.", evidence_refs=refs))
            checks.append("Check the pod's nodeSelector and affinity against the node labels "
                          "(kubectl get nodes --show-labels).")
        if "taint" in msg:
            causes.append(_claim(text="The nodes have a taint the pod does not tolerate.", evidence_refs=refs))
            checks.append("Check the node taints and the pod's tolerations.")
        if "PersistentVolumeClaim" in msg:
            causes.append(_claim(text="A PersistentVolumeClaim is not bound, so the pod cannot be placed.",
                                 evidence_refs=refs))
            checks.append("Check the PersistentVolumeClaim status and its StorageClass.")
        if not causes:
            causes.append(_claim(text="The scheduler finds no node that fits the pod.", evidence_refs=refs))
            checks.append("Describe the pod and read the scheduler's message for each node group.")
        nodes = _find(evidence, "nodes")
        if nodes:
            facts.append(_claim(text=nodes[0].summary, evidence_refs=[nodes[0].ref]))

    elif inc.rule_id == "oom":
        c = (details.get("containers") or [{}])[0]
        limit = c.get("memoryLimit")
        facts.append(_claim(text=inc.reason, evidence_refs=rref))
        if limit:
            causes.append(_claim(text=f"The container uses more memory than its limit of {limit}.", evidence_refs=rref))
            checks.append(f"Compare the container's real memory use with its limit {limit}; raise the limit or "
                          "reduce memory use (heap size, caches, batch sizes).")
        else:
            causes.append(_claim(text="The node ran out of memory and killed the container, which has no memory "
                                      "limit.", evidence_refs=rref))
            checks.append("Set a memory request and limit for the container and check the node's memory pressure.")
        if (details.get("killsInWindow") or 0) > 1:
            facts.append(_claim(text=f"{details['killsInWindow']} OOM kills within the window.", evidence_refs=rref))
        missing.append("Actual memory usage over time needs Metrics Server or a metrics platform.")

    elif inc.rule_id == "observerDegraded":
        ns = inc.workload.namespace
        facts.append(_claim(text=inc.reason, evidence_refs=rref))
        errors = " ".join(details.get("errors") or [])
        if "403" in errors or "Forbidden" in errors:
            causes.append(_claim(text=f"The observer lost read permissions in {ns}: a RoleBinding was removed or "
                                      "changed.", evidence_refs=rref))
            checks.append(f"Check the observer's effective permissions with kubectl auth can-i list pods -n {ns} "
                          "--as=<observer ServiceAccount>, and that its RoleBinding exists.")
        elif "401" in errors or "Unauthorized" in errors:
            causes.append(_claim(text="The API server rejects the observer's token.", evidence_refs=rref))
            checks.append("Check that the observer's ServiceAccount and token still exist (kubectl auth can-i "
                          f"list pods -n {ns} --as=<observer ServiceAccount>).")
        else:
            causes.append(_claim(text="The observer cannot reach the Kubernetes API (network policy, API server "
                                      "or DNS).", evidence_refs=rref))
            checks.append("Check the observer logs and its egress to the API server; then kubectl auth can-i "
                          f"list pods -n {ns} --as=<observer ServiceAccount>.")
        missing.append(f"Workload health in {ns} is unknown while observations are stale.")

    if not _find(evidence, "event") and inc.rule_id not in ("observerDegraded", "oom"):
        missing.append("No related Kubernetes events were available.")
    # A gap is outdated when the same container's logs were collected later.
    have_logs = {f"{log.payload.get('pod')}/{log.payload.get('container')}" for log in logs}
    gaps = [g.summary for g in _find(evidence, "gap") if not any(f" {k}" in g.summary for k in have_logs)]
    missing = list(dict.fromkeys(gaps + missing))
    for log in logs:
        if log.payload.get("truncated"):
            missing.append(f"Older log lines of {log.payload.get('container')} were cut ({log.ref}).")
    checks = [c if len(c) <= 500 else c[:499] + "…" for c in dict.fromkeys(checks)][:6]
    missing = [m if len(m) <= 500 else m[:499] + "…" for m in missing]
    summary = f"{inc.workload.kind} {inc.workload.namespace}/{inc.workload.name}: {inc.reason}"
    return Analysis(
        summary=summary[:400],
        observed_facts=facts[:10],
        possible_causes=causes[:6],
        next_checks=checks,
        missing_information=missing[:6],
    )
