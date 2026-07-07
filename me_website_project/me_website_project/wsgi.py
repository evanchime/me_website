"""
WSGI config for me_website_project project.

This file incorporates OpenTelemetry (OTel) auto-instrumentation 
to provide traces and metrics to the ADOT sidecar.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os
from django.core.wsgi import get_wsgi_application

from opentelemetry import trace, metrics
from opentelemetry.instrumentation.django import DjangoInstrumentor

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# OpenTelemetry Tracing Setup
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
otlp_trace_exporter = OTLPSpanExporter(endpoint="http://localhost:4317", insecure=True)
span_processor = BatchSpanProcessor(otlp_trace_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# OpenTelemetry Metrics Setup
otlp_metric_exporter = OTLPMetricExporter(endpoint="http://localhost:4317", insecure=True)
metric_reader = PeriodicExportingMetricReader(otlp_metric_exporter, export_interval_millis=15000)
metrics.set_meter_provider(MeterProvider(metric_readers=[metric_reader]))

# Instrument Django
DjangoInstrumentor().instrument()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'me_website_project.settings')
application = get_wsgi_application()