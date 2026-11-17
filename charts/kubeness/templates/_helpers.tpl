{{- define "kubeness.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubeness.observer" -}}
{{- printf "%s-observer" (include "kubeness.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubeness.labels" -}}
app.kubernetes.io/name: kubeness
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "kubeness.observerSelector" -}}
app.kubernetes.io/name: kubeness
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: observer
{{- end -}}

{{- define "kubeness.modelSelector" -}}
app.kubernetes.io/name: kubeness
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: model
{{- end -}}

{{- define "kubeness.notifierSelector" -}}
app.kubernetes.io/name: kubeness
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: notifier
{{- end -}}

{{- define "kubeness.notifier" -}}
{{- printf "%s-notifier" (include "kubeness.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubeness.executorSelector" -}}
app.kubernetes.io/name: kubeness
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: executor
{{- end -}}

{{/* Silos as YAML: the configured silos, or one default silo of access.namespaces. */}}
{{- define "kubeness.silos" -}}
{{- if .Values.access.silos }}
silos: {{ .Values.access.silos | toJson }}
{{- else }}
silos: [{"name": "default", "namespaces": {{ .Values.access.namespaces | toJson }}, "profile": {{ .Values.access.profile | quote }}}]
{{- end }}
{{- end -}}

{{- define "kubeness.watchedNamespaces" -}}
{{- $out := list -}}
{{- range (include "kubeness.silos" . | fromYaml).silos -}}{{- $out = concat $out .namespaces -}}{{- end -}}
{{- $out | toJson -}}
{{- end -}}

{{- define "kubeness.remediateNamespaces" -}}
{{- $out := list -}}
{{- range (include "kubeness.silos" . | fromYaml).silos -}}{{- if eq .profile "remediate" -}}{{- $out = concat $out .namespaces -}}{{- end -}}{{- end -}}
{{- $out | toJson -}}
{{- end -}}
