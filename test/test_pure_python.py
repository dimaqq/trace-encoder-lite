from __future__ import annotations

import base64
import json
from typing import Any, Sequence

import pytest
from google.protobuf.json_format import MessageToDict
from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.exporter.otlp.proto.common._internal import trace_encoder

import otlp_json


CONTENT_TYPE = "application/json"


def test_equiv(sample_spans):
    auth = json.loads(proto_to_json(trace_encoder.encode_spans(sample_spans)))
    assert json.loads(otlp_json.encode_spans(sample_spans)) == auth


@pytest.fixture
def sample_spans() -> Sequence[ReadableSpan]:
    """Creates and finishes two spans, then returns them as a list."""
    tracer_provider = TracerProvider()
    exporter = InMemorySpanExporter()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tracer_provider.get_tracer(__name__)

    with tracer.start_as_current_span("span-one"):
        pass
    with tracer.start_as_current_span("span-two"):
        pass

    spans = exporter.get_finished_spans()
    return spans


def proto_to_json(data: Any) -> str:
    """FIXME: move to own module and reimplement"""
    dic = MessageToDict(data)

    for rs in dic["resourceSpans"]:
        for ss in rs["scopeSpans"]:
            for sp in ss["spans"]:
                for k in "parentSpanId spanId traceId".split():
                    if k in sp:
                        sp[k] = base64.b64decode(sp[k]).hex()
                sp["kind"] = {
                    "SPAN_KIND_UNSPECIFIED": 0,
                    "SPAN_KIND_INTERNAL": 1,
                    "SPAN_KIND_SERVER": 2,
                    "SPAN_KIND_CLIENT": 3,
                    "SPAN_KIND_PRODUCER": 4,
                    "SPAN_KIND_CONSUMER": 5,
                }[sp["kind"]]

    return json.dumps(dic)
