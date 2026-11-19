# Every cluster command names the kind context explicitly. Never rely on the
# current kubeconfig context: it may point at a real cluster.
CLUSTER  := kubeness
CONTEXT  := kind-$(CLUSTER)
KUBECTL  := kubectl --context $(CONTEXT)
HELM     := helm --kube-context $(CONTEXT)
IMAGE    := kubeness:0.1.0
# Models baked into the model image. Pick what the machine can afford, e.g.
#   make model-image MODELS="qwen3:0.6b qwen3:1.7b" MODEL_TAG=qwen3-compare
# The default is the tiered pair that the default MODEL_PROFILE uses.
MODELS      ?= qwen3:0.6b qwen3:1.7b
MODEL_TAG   ?= qwen3-0.6b-1.7b
MODEL_IMAGE := kubeness-model:$(MODEL_TAG)
CILIUM   := 1.20.4

.PHONY: test kpi constraints verify model model-tiered model-compare e2e redeploy cluster cilium image model-image sink install faults clean-faults verify-rbac ui api-server-cidr

test:
	.venv/bin/ruff check src tests --select E,F,W,B --ignore E501
	.venv/bin/pytest -q

# Simulated KPI benchmarks only; the table is printed at the end.
kpi:
	.venv/bin/pytest -q tests/kpi

# Pins what the image installs to the versions in .venv, the ones the tests ran with.
constraints:
	.venv/bin/python lab/constraints.py

# Builds, (re)deploys and runs the end-to-end suite against the kind cluster.
e2e: redeploy
	KUBENESS_E2E_CONTEXT=$(CONTEXT) .venv/bin/pytest -v tests/e2e

# Every negative check in one place: RBAC, network, tokens, CSRF, secrets (H03).
verify:
	CONTEXT=$(CONTEXT) lab/verify-rbac.sh
	KUBENESS_E2E_CONTEXT=$(CONTEXT) .venv/bin/pytest -v tests/e2e -k "effective_permissions or cannot_reach or \
	  no_api_token or reaches_only or rejects_calls or leaks"

# Switch the model size: builds the image with that model and upgrades the release.
#   make model SIZE=1.7b      (profiles in lab/models/: 0.6b, 1.7b, 4b)
SIZE ?= 0.6b
# The profile from lab/models/ that install (and so e2e) uses. Tiered by default: 0.6b for
# every incident, 1.7b by rule (B32). MODEL_PROFILE= installs the chart's single 0.6b model.
MODEL_PROFILE ?= tiered
PROFILE_VALUES := $(if $(MODEL_PROFILE),-f lab/models/$(MODEL_PROFILE).yaml)
model:
	$(MAKE) model-image MODELS="qwen3:$(SIZE)" MODEL_TAG=qwen3-$(SIZE)
	$(HELM) upgrade --install kubeness charts/kubeness -n kubeness -f lab/values-lab.yaml -f lab/models/$(SIZE).yaml
	$(KUBECTL) -n kubeness rollout status deployment/kubeness-model --timeout=600s

# Tiered: 0.6b for every incident, 1.7b by rule and for troubleshooting.
model-tiered:
	$(MAKE) model-image MODELS="qwen3:0.6b qwen3:1.7b" MODEL_TAG=qwen3-0.6b-1.7b
	$(HELM) upgrade --install kubeness charts/kubeness -n kubeness -f lab/values-lab.yaml -f lab/models/tiered.yaml
	$(KUBECTL) -n kubeness rollout status deployment/kubeness-model --timeout=600s

# Compares template-only and every model in the model pod (B21).
model-compare:
	$(KUBECTL) -n kubeness port-forward --address=127.0.0.1 service/kubeness-model 11434:11434 & \
	  PF=$$!; sleep 3; PYTHONPATH=src .venv/bin/python -m kubeness.compare --url http://127.0.0.1:11434; kill $$PF

redeploy: image sink install
	$(KUBECTL) -n kubeness rollout restart deployment/kubeness-observer deployment/kubeness-notifier \
	  deployment/kubeness-executor
	$(KUBECTL) -n kubeness rollout status deployment/kubeness-observer --timeout=180s
	$(KUBECTL) -n kubeness rollout status deployment/kubeness-notifier --timeout=120s

cluster:
	kind create cluster --config lab/kind-config.yaml
	$(KUBECTL) create namespace lab --dry-run=client -o yaml | $(KUBECTL) apply -f -

cilium:
	$(HELM) repo add cilium https://helm.cilium.io >/dev/null
	$(HELM) upgrade --install cilium cilium/cilium --version $(CILIUM) -n kube-system \
	  --set image.pullPolicy=IfNotPresent --set ipam.mode=kubernetes \
	  --set kubeProxyReplacement=true \
	  --set k8sServiceHost=$(CLUSTER)-control-plane --set k8sServicePort=6443
	$(KUBECTL) -n kube-system rollout status ds/cilium --timeout=5m

image:
	docker build -t $(IMAGE) .
	kind load docker-image $(IMAGE) --name $(CLUSTER)

# CPU-only Ollama runtime with the model baked in (no egress needed at runtime).
model-image:
	docker build -f lab/model.Dockerfile --build-arg MODELS="$(MODELS)" -t $(MODEL_IMAGE) lab
	kind load docker-image $(MODEL_IMAGE) --name $(CLUSTER)

# In-cluster webhook sink (lab destination for notifications).
sink:
	$(KUBECTL) apply -f lab/sink.yaml
	$(KUBECTL) -n lab-sink rollout status deployment/sink --timeout=120s

# The destination Secret is created outside the chart; only the notifier mounts it.
install:
	$(KUBECTL) create namespace kubeness --dry-run=client -o yaml | $(KUBECTL) apply -f -
	$(KUBECTL) create namespace lab-observe --dry-run=client -o yaml | $(KUBECTL) apply -f -
	$(KUBECTL) -n kubeness create secret generic kubeness-notifications \
	  --from-literal=url=http://sink.lab-sink.svc.cluster.local:8080/hook \
	  --from-literal=heartbeatUrl=http://sink.lab-sink.svc.cluster.local:8080/heartbeat \
	  --dry-run=client -o yaml | $(KUBECTL) apply -f -
	$(HELM) upgrade --install kubeness charts/kubeness -n kubeness -f lab/values-lab.yaml $(PROFILE_VALUES)
	$(KUBECTL) -n kubeness rollout status deployment/kubeness-model --timeout=600s

faults:
	$(KUBECTL) apply -f lab/faults.yaml

clean-faults:
	$(KUBECTL) delete -f lab/faults.yaml --ignore-not-found

verify-rbac:
	CONTEXT=$(CONTEXT) lab/verify-rbac.sh

ui:
	$(KUBECTL) -n kubeness port-forward --address=127.0.0.1 service/kubeness 8080:80

api-server-cidr:
	@$(KUBECTL) get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
	  -o jsonpath='{range .items[*].endpoints[*]}{.addresses[0]}/32{"\n"}{end}'
