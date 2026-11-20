#!/bin/sh
# Observability is an infrastructure concern: run under OpenTelemetry auto-instrumentation
# only when the deployment provides an OTLP endpoint. The application itself is OTel-free
# and the same image serves both modes.
if [ -n "${OTEL_EXPORTER_OTLP_ENDPOINT}" ]; then
    exec opentelemetry-instrument "$@"
fi
exec "$@"
