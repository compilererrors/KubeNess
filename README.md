# KubeNess

English | [Svenska](README.sv.md)

Watch. Diagnose. Notify.

KubeNess is a local diagnostic service for Kubernetes that works in the background. Deterministic rules detect persistent problems, the observer collects evidence, an optional local model writes an analysis, and notifications are sent through a separate notifier. A small web interface shows incidents, evidence and actions.

## Components and boundaries

| Component | Kubernetes access | Other |
|---|---|---|
| Observer | Reader Role per watched namespace (get/list/watch, pods/log according to the silo's profile) | Rules, incident store (SQLite on its own volume), UI and JSON API |
| Model (optional) | None, no ServiceAccount token | Ollama with built-in models, no egress |
| Notifier (optional) | None, no ServiceAccount token | Only component holding the destination Secret; accepts a fixed format with a shared token |
| Executor (optional) | Writer Role in remediate silos: get/patch deployments, get/list replicasets | Runs approved actions with a shared token |

All pods run as non-root with a read-only root filesystem and no capabilities. A default-deny NetworkPolicy allows only the flows listed above. The observer runs a single replica with `strategy: Recreate`.

## Features

- **Rules:** repeated restart (including a persisting CrashLoopBackOff), image pull failure, readiness failure (including `ProgressDeadlineExceeded`), scheduling failure, OOM termination and observer degraded (collection exceeds the freshness budget).
- **Lifecycle:** pending → firing → recovering → resolved, with a recovery window, reopen window, flap protection and inhibition.
- **Evidence:** the rule's facts, related events, bounded log excerpts and (opt-in) Services, EndpointSlices and node capacity. Everything is masked before it is stored or sent.
- **Analysis:** deterministic runbooks produce a template analysis with evidence references. A local model can enrich it; claims without a valid reference are removed.
- **Notifications:** outbox with retries and backoff, firing/reopened/repeat/escalated/resolved, info digest, heartbeat to a dead man's switch. Providers: webhook, ntfy and AWS SNS.
- **UI:** incident list and detail through port-forward, acknowledge and silence (CSRF and Origin checks), Ask about this incident, model overview at `/models`.
- **Actions (optional):** `restart-deployment` and `rollback-deployment`, approved in the UI, run by the executor, with an audit log and verification.
- **Retention:** resolved incidents and sent digests older than `observer.retention` (14 d) are deleted.

## Configuration

The chart `charts/kubeness` renders the observer's config from `values.yaml`. The main parts:

### Access profiles and silos

A silo is a group of namespaces with one profile:

| Profile | Grants |
|---|---|
| `observe` | status, events and specs |
| `investigate` | + container logs |
| `recommend` | + the model may propose fixes |
| `remediate` | + approved actions through the executor |

```yaml
access:
  silos:
    - {name: lab, namespaces: [lab], profile: remediate}
    - {name: shop, namespaces: [shop, shop-api], profile: observe}
```

The chart creates RBAC per namespace from the profile, and the application enforces the same profile. Without `access.silos`, `access.namespaces` becomes one silo with `access.profile` (default `investigate`). `readSecrets` and `exec` are not supported and make the installation fail.

### Models

The template analysis works without a model. With `model.enabled: true` a local model runs in the model pod. Profiles in `lab/models/` set the model, image, memory and timeout:

| Profile | Model | Memory in use (approx.) |
|---|---|---|
| `0.6b` | qwen3:0.6b | 1 GB |
| `1.7b` | qwen3:1.7b | 2.5 GB |
| `4b` | qwen3:4b | 4.5 GB |
| `tiered` | 0.6b for every incident, 1.7b by rule | 3.5 GB |

```bash
make model SIZE=1.7b     # builds a model image with that model and upgrades the release
make model-tiered        # tiered: 0.6b + 1.7b
```

- `model.escalation` hands over to a larger model by rule (`when`: `invalid`, `unsupported`, `ungrounded`, `critical`, `recurring`, `troubleshoot`), never by the small model's own judgement.
- `model.compare` runs shadow models on the same incidents for comparison; the incident's analysis is always the primary model's.
- `model.numThreads` should not exceed the model pod's CPU request; otherwise llama.cpp uses one thread per visible CPU, which is very slow on a shared node.

### Experimental troubleshooting

`experimental.troubleshoot` (off by default) adds a button to the incident. The model picks one read-only tool per step (logs, events, describe without env values, rollout history, earlier incidents); the observer runs the tool within the incident's workload and the silo's profile and stores the result as evidence. The last step can only finish, and repeated calls are refused. `think` turns on the model's reasoning. With `proposeFixes` the conclusion may propose an allowed action, which only runs after approval in a remediate silo.

### Notifications

The destination is kept in a Secret created outside the chart and mounted only in the notifier:

```bash
kubectl -n kubeness create secret generic kubeness-notifications \
  --from-literal=url=https://ntfy.sh/<topic> [--from-literal=token=...] [--from-literal=heartbeatUrl=...]
```

Set `notifications.provider` to `webhook`, `ntfy` or `sns` (for SNS: `url` is the topic ARN, plus `accessKeyId` and `secretAccessKey` with only `sns:Publish`). `notifications.egress` controls the notifier's egress.

## Protection against the wrong cluster

The observer never starts against the current kubeconfig context. Outside a cluster, `kubernetes.context` must be set explicitly. All Makefile targets use `--context kind-kubeness` / `--kube-context kind-kubeness`.

## Development

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test              # ruff and unit tests, including simulated KPI benchmarks
make kpi               # KPI benchmarks only
make constraints       # pin the image's dependencies to the versions in .venv
```

Run the observer locally against the lab cluster:

```bash
.venv/bin/python -m kubeness --config config/example.yaml
```

Outside a cluster and outside a container the UI listens on 127.0.0.1 only; `ui.host` changes that.

KPI benchmarks (`tests/kpi/` and KPI calls in the e2e suite) have measurable targets and are printed as a table at the end of the pytest output, or as JSON with `KUBENESS_KPI_REPORT=<file>`. Timings are measured again on a miss and marked NOISY when the machine is overloaded.

## Lab

Requires Docker, kind, kubectl and Helm.

```bash
make cluster        # kind without the default CNI
make cilium         # Cilium enforces NetworkPolicy
make image          # observer image, loaded into kind
make model-image    # CPU-only Ollama with qwen3:0.6b built in
make sink           # webhook receiver in namespace lab-sink
make install        # Helm release with lab/values-lab.yaml
make faults         # known faults and a healthy control in namespace lab
make ui             # http://127.0.0.1:8080
make verify         # all negative checks (RBAC, network, tokens, secrets)
make e2e            # rebuilds, deploys and runs the e2e suite against kind
make model-compare  # template-only against the models in the model pod
```

`make install` and `make e2e` take `MODEL_PROFILE=<profile>` to keep a model profile, e.g. `make e2e MODEL_PROFILE=tiered`.

Without Cilium the chart needs the API server's address for egress: `make api-server-cidr` and then `--set networkPolicy.apiServer.cidrs={<address>/32}`.

### E2E suites

| File | Verifies |
|---|---|
| `test_stage1_observe.py` | known faults give the right incidents, RBAC, network isolation, monitoring without the UI, restart |
| `test_stage2_diagnose.py` | masked logs, model analysis with valid references, model down |
| `test_stage2c_tiered.py` | tiered models: small model first, handover by a logged rule |
| `test_stage3_notify.py` | notifications, retries during outages, no secrets, notifier isolation |
| `test_stage3b_degraded.py` | lost permissions give observerDegraded and recovery |
| `test_stage4_inspect.py` | acknowledge and silence with CSRF |
| `test_stage4b_rules.py` | scheduling, OOM, Service evidence, digest |
| `test_stage5_harden.py` | no leaks through the API, token rotation |
| `test_stage6_act.py` | executor permissions per silo, restart, rollback, troubleshooting |

## Known limitations

- Ollama has no authentication of its own; the model pod is protected by NetworkPolicy (only the observer reaches it).
- Without an FQDN policy the notifier's egress is HTTPS to any address; restrict `notifications.egress` or use an egress proxy.
- Small models are weak at multi-step troubleshooting and may propose the wrong fix; that is why every action requires approval.
