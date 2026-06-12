{{- define "zitadel-rbac-mapper.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "zitadel-rbac-mapper.labels" -}}
app.kubernetes.io/name: zitadel-rbac-mapper
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "zitadel-rbac-mapper.selectorLabels" -}}
app.kubernetes.io/name: zitadel-rbac-mapper
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
