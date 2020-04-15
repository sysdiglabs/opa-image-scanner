{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "sysdig-image-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sysdig-image-scanner.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sysdig-image-scanner.tag" -}}
{{- if .Values.image.tag -}}
{{- .Values.image.tag -}}
{{- else -}}
{{- .Chart.AppVersion -}}
{{- end -}}
{{- end -}}


{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sysdig-image-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "sysdig-image-scanner.labels" -}}
helm.sh/chart: {{ include "sysdig-image-scanner.chart" . }}
{{ include "sysdig-image-scanner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "sysdig-image-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sysdig-image-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "sysdig-image-scanner.serviceAccountName" -}}
    {{ default (include "sysdig-image-scanner.name" .) .Values.serviceAccount.name }}
{{- end -}}

{{/*
Generate certificates for aggregated api server 
*/}}

{{- $cert := genCA ( printf "%s.%s.svc" (include "sysdig-image-scanner.name" .) .Release.Namespace ) 3650 -}}

{{- define "sysdig-image-scanner.gen-certs" -}}
{{- $ca := genCA "sysdig-image-scanner-ca" 3650 -}}
{{- $cert := genSignedCert ( printf "%s.%s.svc" (include "sysdig-image-scanner.name" .) .Release.Namespace ) nil nil 3650 $ca -}}
{{- printf "%s$%s$%s" ($cert.Cert | b64enc) ($cert.Key | b64enc) ($ca.Cert | b64enc) -}}
{{- end -}}
