{{/*
Expand the full name. Avoids doubling the name if the release already contains
the chart name (e.g. release "ip-sentry" + chart "ip-sentry" → "ip-sentry").
*/}}
{{- define "ip-sentry.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "ip-sentry.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Service account name used by the watcher.
*/}}
{{- define "ip-sentry.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "ip-sentry.fullname" . }}
{{- end }}
{{- end }}
