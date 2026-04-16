"""
Observability setup — OpenTelemetry tracing + Prometheus metrics.

Both features are opt-in via config:
  OTEL_ENABLED=true            → enables OTel SDK and FastAPI auto-instrumentation
  OTEL_EXPORTER_OTLP_ENDPOINT  → where to ship traces (if empty, SDK runs but doesn't export)
  PROMETHEUS_ENABLED=true      → exposes /metrics in OpenMetrics format
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger("axymail_gateway.telemetry")


# ── OpenTelemetry tracing ─────────────────────────────────────────────────────

def setup_tracing(app: "FastAPI", service_name: str, otlp_endpoint: str) -> None:
    """
    Initialise a TracerProvider, optionally attach an OTLP HTTP exporter,
    and auto-instrument all FastAPI routes.

    If OTEL packages are missing this logs a warning and exits gracefully so
    the application still starts without the observability dependencies.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning(
            "opentelemetry-sdk or opentelemetry-instrumentation-fastapi not installed — "
            "tracing disabled. Install with: pip install opentelemetry-sdk "
            "opentelemetry-instrumentation-fastapi"
        )
        return

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OTel OTLP trace exporter → %s", otlp_endpoint)
        except ImportError:
            logger.warning(
                "opentelemetry-exporter-otlp-proto-http not installed — "
                "traces will not be exported. "
                "Install with: pip install opentelemetry-exporter-otlp-proto-http"
            )
    else:
        logger.info(
            "OTEL_EXPORTER_OTLP_ENDPOINT not set — OTel SDK active but traces are not exported."
        )

    trace.set_tracer_provider(provider)

    # Exclude internal paths from tracing to reduce noise
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="health,healthz,readyz,metrics",
    )
    logger.info("OpenTelemetry tracing enabled (service.name=%s)", service_name)


# ── Prometheus metrics ────────────────────────────────────────────────────────

def setup_metrics(app: "FastAPI") -> None:
    """
    Mount a /metrics endpoint that serves Prometheus / OpenMetrics text.

    Automatically tracks:
      - http_requests_total          (counter)
      - http_request_duration_seconds (histogram)
      - http_requests_inprogress      (gauge)
    """
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
    except ImportError:
        logger.warning(
            "prometheus-fastapi-instrumentator not installed — metrics disabled. "
            "Install with: pip install prometheus-fastapi-instrumentator"
        )
        return

    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_instrument_requests_inprogress=True,
        inprogress_labels=True,
        # Don't track the observability endpoints themselves
        excluded_handlers=["/metrics", "/health", "/healthz", "/readyz"],
    ).instrument(app).expose(
        app,
        endpoint="/metrics",
        include_in_schema=False,
        tags=["observability"],
    )
    logger.info("Prometheus metrics exposed at /metrics")
