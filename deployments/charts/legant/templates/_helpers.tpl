{{/* Chart name, optionally overridden by nameOverride. */}}
{{- define "legant.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified release name (<release>-<chart>, collapsed if they match). */}}
{{- define "legant.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "legant.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "legant.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/* The container image reference (tag defaults to appVersion). */}}
{{- define "legant.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* The Secret name the workloads consume — an external one if given, else ours. */}}
{{- define "legant.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "legant.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Common pod scheduling fields. */}}
{{- define "legant.scheduling" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
{{ toYaml . | indent 2 }}
{{- end }}
{{- end -}}

{{/* Guardrail: a non-https issuer in production weakens cookie security. */}}
{{- define "legant.validate" -}}
{{- if not (or .Values.secrets.existingSecret .Values.secrets.create) -}}
{{ fail "legant: set secrets.existingSecret (recommended) or secrets.create=true with secrets.values" }}
{{- end -}}
{{- end -}}
