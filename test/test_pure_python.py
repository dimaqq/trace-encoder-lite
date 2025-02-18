from __future__ import annotations

import base64
import json
from typing import Any, Sequence, TypeAlias

import pytest
from google.protobuf.json_format import MessageToDict

from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.exporter.otlp.proto.common._internal import trace_encoder
from opentelemetry.trace.span import Status
from typing_extensions import reveal_type as reveal_type


LEAF_VALUE: TypeAlias = str | int | float | bool  # TODO: confirm
VALUE: TypeAlias = LEAF_VALUE | Sequence[LEAF_VALUE]


def to_v(value: VALUE) -> dict[str, Any]:
    # Attribute value can be a primitive type, excluging None...
    # TODO: protobuf allows bytes, but I think OTLP doesn't.
    # TODO: protobuf allows k:v pairs, but I think OTLP doesn't.
    if isinstance(value, (str, int, float, bool)):
        k = {
            str: "stringValue",
            int: "intValue",
            float: "floatValue",
            bool: "boolValue",
        }[type(value)]
        return {k: value}

    # Or a homogenous array of a primitive type, excluding None.
    value = list(value)

    # TODO: empty lists are allowed, aren't they?
    if len({type(v) for v in value}) > 1:
        raise ValueError(f"Attribute value arrays must be homogenous, got {value}")

    # TODO: maybe prevent recursion, OTEL doesn't allow lists of lists
    return {"arrayValue": [to_v(e) for e in value]}


def to_r(resource: Resource):
    return {
        "attributes": [
            {"key": k, "value": to_v(v)} for k, v in resource.attributes.items()
        ]
    }


def to_ss(scope: InstrumentationScope):
    rv = {"name": scope.name}
    if scope.version:
        rv["version"] = scope.version
    return rv


def to_tid(trace_id: int) -> str:
    if not 0 <= trace_id < 2**128:
        raise ValueError(f"The {trace_id=} is out of bounds")
    return hex(trace_id)[2:].rjust(32, "0")


def to_sid(span_id: int) -> str:
    if not 0 <= span_id < 2**64:
        raise ValueError(f"The {span_id=} is out of bounds")
    return hex(span_id)[2:].rjust(16, "0")


def to_status(status: Status) -> dict[str, Any]:
    # FIXME
    return {}


def to_s(span: ReadableSpan):
    assert span.context
    rv = {
        "name": span.name,
        "kind": span.kind.value or 1,  # unspecified -> internal
        "traceId": to_tid(span.context.trace_id),
        "spanId": to_sid(span.context.span_id),
        "flags": 0x100 | ([0, 0x200][bool(span.parent)]),
        "startTimeUnixNano": str(span.start_time),  # TODO: is it ever optional?
        "endTimeUnixNano": str(span.end_time),  # -"-
        "status": to_status(span.status),
    }
    if span.parent:
        rv["parentSpanId"] = to_sid(span.parent.span_id)
    return rv


def to_etsr(spans: Sequence[ReadableSpan]):
    spans = sorted(spans, key=lambda s: (id(s.resource), id(s.instrumentation_scope)))
    rv = {"resourceSpans": []}
    last_rs = last_is = None
    for span in spans:
        assert span.resource
        assert span.instrumentation_scope
        if span.resource is not last_rs:
            last_rs = span.resource
            last_is = None
            rv["resourceSpans"].append(
                {
                    "resource": to_r(span.resource),
                    "scopeSpans": [],
                }
            )
        if span.instrumentation_scope is not last_is:
            last_is = span.instrumentation_scope
            rv["resourceSpans"][-1]["scopeSpans"].append(
                {
                    "scope": to_ss(span.instrumentation_scope),
                    "spans": [],
                }
            )
        rv["resourceSpans"][-1]["scopeSpans"][-1]["spans"].append(to_s(span))
    return rv


def test_equiv(sample_spans):
    auth = json.loads(proto_to_json(trace_encoder.encode_spans(sample_spans)))
    assert to_etsr(sample_spans) == auth


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
