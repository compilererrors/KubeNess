# KubeNess

[English](README.md) | Svenska

Watch. Diagnose. Notify.

KubeNess är en lokal diagnostic service för Kubernetes som arbetar i bakgrunden. Deterministiska regler upptäcker bestående problem, observern samlar evidence, en valfri lokal modell skriver analys, och notifications skickas via en egen notifier. Ett litet web interface visar incidents, evidence och åtgärder.

## Komponenter och gränser

| Komponent | Kubernetes-åtkomst | Övrigt |
|---|---|---|
| Observer | Reader-Role per bevakat namespace (get/list/watch, pods/log enligt silons profil) | Regler, incident store (SQLite på egen volume), UI och JSON API |
| Model (valfri) | Ingen, ingen ServiceAccount-token | Ollama med inbakade modeller, ingen egress |
| Notifier (valfri) | Ingen, ingen ServiceAccount-token | Ensam om destination-Secret; tar emot ett fast format med delad token |
| Executor (valfri) | Writer-Role i remediate-silos: get/patch deployments, get/list replicasets | Kör godkända actions med delad token |

Alla pods kör non-root med read-only rootfs och utan capabilities. NetworkPolicy med default-deny släpper bara de flöden tabellen kräver. Observern kör en replika med `strategy: Recreate`.

## Funktioner

- **Regler:** repeated restart (även CrashLoopBackOff som kvarstår), image pull failure, readiness failure (även `ProgressDeadlineExceeded`), scheduling failure, OOM termination och observer degraded (insamlingen överskrider freshness-budgeten).
- **Lifecycle:** pending → firing → recovering → resolved, med recovery window, reopen window, flap-skydd och inhibition.
- **Evidence:** regelns fakta, relaterade events, begränsade loggutdrag och (opt-in) Services, EndpointSlices och nodkapacitet. Allt maskas innan det sparas eller skickas.
- **Analys:** deterministiska runbooks ger template-analys med evidence-referenser. En lokal modell kan berika den; påståenden utan giltig referens tas bort.
- **Notifications:** outbox med retries och backoff, firing/reopened/repeat/escalated/resolved, info-digest, heartbeat till en dead man's switch. Providers: webhook, ntfy och AWS SNS.
- **UI:** incident list och detail via port-forward, acknowledge och silence (CSRF och Origin-kontroll), Ask about this incident, modellöversikt under `/models`.
- **Actions (valfritt):** `restart-deployment` och `rollback-deployment`, godkända i UI:t, utförda av executorn, med auditlogg och verifiering.
- **Retention:** lösta incidents och skickade digests äldre än `observer.retention` (14 d) rensas.

## Konfiguration

Chartet `charts/kubeness` renderar observerns config från `values.yaml`. Viktiga delar:

### Access profiles och silos

En silo är en grupp namespaces med en profil:

| Profil | Ger |
|---|---|
| `observe` | status, events och specs |
| `investigate` | + container logs |
| `recommend` | + modellen får föreslå fixar |
| `remediate` | + godkända actions via executorn |

```yaml
access:
  silos:
    - {name: lab, namespaces: [lab], profile: remediate}
    - {name: shop, namespaces: [shop, shop-api], profile: observe}
```

Chartet skapar RBAC per namespace efter profilen, och appen kontrollerar samma profil. Utan `access.silos` blir `access.namespaces` en silo med `access.profile` (default `investigate`). `readSecrets` och `exec` stöds inte och får installationen att misslyckas.

### Modeller

Template-analysen fungerar utan modell. Med `model.enabled: true` körs en lokal modell i model-podden. Profiler i `lab/models/` sätter modell, image, minne och timeout:

| Profil | Modell | Minne i bruk (ungefär) |
|---|---|---|
| `0.6b` | qwen3:0.6b | 1 GB |
| `1.7b` | qwen3:1.7b | 2,5 GB |
| `4b` | qwen3:4b | 4,5 GB |
| `tiered` | 0.6b för alla incidents, 1.7b enligt regel | 3,5 GB |

```bash
make model SIZE=1.7b     # bygger model-image med den modellen och uppgraderar releasen
make model-tiered        # trappa: 0.6b + 1.7b
```

- `model.escalation` lämnar över till en större modell enligt regel (`when`: `invalid`, `unsupported`, `ungrounded`, `critical`, `recurring`, `troubleshoot`), aldrig efter den lilla modellens egen bedömning.
- `model.compare` kör skuggmodeller på samma incidents för jämförelse; incidentens analys är alltid den primära modellens.
- `model.numThreads` ska inte överstiga model-poddens CPU-request; llama.cpp använder annars en tråd per synlig CPU, vilket blir mycket långsamt på en delad nod.

### Experimentell felsökning

`experimental.troubleshoot` (av som default) ger en knapp på incidenten. Modellen väljer ett läsverktyg per steg (logs, events, describe utan env-värden, rollout-historik, tidigare incidents); observern kör verktyget inom incidentens workload och silons profil och sparar resultatet som evidence. Sista steget kan bara avsluta och upprepade anrop avvisas. `think` slår på modellens resonemang. Med `proposeFixes` får slutsatsen föreslå en tillåten action, som bara körs efter godkännande i en remediate-silo.

### Notifications

Destinationen ligger i en Secret som skapas utanför chartet och bara monteras i notifiern:

```bash
kubectl -n kubeness create secret generic kubeness-notifications \
  --from-literal=url=https://ntfy.sh/<topic> [--from-literal=token=...] [--from-literal=heartbeatUrl=...]
```

Sätt `notifications.provider` till `webhook`, `ntfy` eller `sns` (för SNS: `url` är topic-ARN, plus `accessKeyId` och `secretAccessKey` med bara `sns:Publish`). `notifications.egress` styr notifierns egress.

## Säkerhet mot fel kluster

Observern startar aldrig mot den aktuella kubeconfig-kontexten. Utanför ett kluster måste `kubernetes.context` anges uttryckligen. Alla Makefile-mål använder `--context kind-kubeness` / `--kube-context kind-kubeness`.

## Utveckling

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test              # ruff och unit-tester, inklusive simulerade KPI-benchmarks
make kpi               # bara KPI-benchmarks
make constraints       # lås imagens beroenden till versionerna i .venv
```

Kör observern lokalt mot labbklustret:

```bash
.venv/bin/python -m kubeness --config config/example.yaml
```

Utanför ett kluster lyssnar UI:t bara på 127.0.0.1; `ui.host` ändrar det.

KPI-benchmarks (`tests/kpi/` och KPI-anrop i e2e-sviten) har mätbara mål och skrivs ut som en tabell sist i pytest-utskriften, eller som JSON med `KUBENESS_KPI_REPORT=<fil>`. Tidsmätningar mäts om vid en miss och markeras NOISY när maskinen är överbelastad.

## Labb

Kräver Docker, kind, kubectl och Helm.

```bash
make cluster        # kind utan default CNI
make cilium         # Cilium verkställer NetworkPolicy
make image          # observer-image, laddas in i kind
make model-image    # CPU-only Ollama med qwen3:0.6b inbakad
make sink           # webhook-mottagare i namespace lab-sink
make install        # Helm release med lab/values-lab.yaml
make faults         # kända fel och en frisk kontroll i namespace lab
make ui             # http://127.0.0.1:8080
make verify         # alla negativa kontroller (RBAC, nätverk, tokens, hemligheter)
make e2e            # bygger om, deployar och kör e2e-sviten mot kind
make model-compare  # template-only mot modellerna i model-podden
```

`make install` och `make e2e` tar `MODEL_PROFILE=<profil>` för att behålla en modellprofil, t.ex. `make e2e MODEL_PROFILE=tiered`.

Utan Cilium behöver chartet API-serverns adress för egress: `make api-server-cidr` och sedan `--set networkPolicy.apiServer.cidrs={<adress>/32}`.

### E2E-sviter

| Fil | Verifierar |
|---|---|
| `test_stage1_observe.py` | kända fel ger rätt incidents, RBAC, nätverksisolering, monitoring utan UI, omstart |
| `test_stage2_diagnose.py` | maskade loggar, modellanalys med giltiga referenser, modell nere |
| `test_stage2c_tiered.py` | trappan: liten modell först, överlämning enligt loggad regel |
| `test_stage3_notify.py` | notifications, retries vid avbrott, inga hemligheter, notifier-isolering |
| `test_stage3b_degraded.py` | förlorade rättigheter ger observerDegraded och recovery |
| `test_stage4_inspect.py` | acknowledge och silence med CSRF |
| `test_stage4b_rules.py` | scheduling, OOM, Service-evidence, digest |
| `test_stage5_harden.py` | inga läckor via API:t, token-rotation |
| `test_stage6_act.py` | executor-behörigheter per silo, restart, rollback, felsökning |

## Kända begränsningar

- Ollama har ingen egen autentisering; model-podden skyddas av NetworkPolicy (bara observern når den).
- Utan FQDN-policy är notifierns egress HTTPS till godtyckliga adresser; begränsa `notifications.egress` eller använd en egress proxy.
- Små modeller är svaga på felsökning i flera steg och kan föreslå fel fix; därför kräver alla actions godkännande.
