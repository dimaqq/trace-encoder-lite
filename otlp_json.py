from __future__ import annotations

import json
from typing import Any, Sequence, TypeAlias, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.util.instrumentation import InstrumentationScope
    from opentelemetry.trace.status import Status


CONTENT_TYPE = "application/json"

_LEAF_VALUE: TypeAlias = str | int | float | bool  # TODO: confirm
_VALUE: TypeAlias = _LEAF_VALUE | Sequence[_LEAF_VALUE]


def encode_spans(spans: Sequence[ReadableSpan]) -> bytes:
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
                    "resource": _resource(span.resource),
                    "scopeSpans": [],
                }
            )
        if span.instrumentation_scope is not last_is:
            last_is = span.instrumentation_scope
            rv["resourceSpans"][-1]["scopeSpans"].append(
                {
                    "scope": _scope(span.instrumentation_scope),
                    "spans": [],
                }
            )
        rv["resourceSpans"][-1]["scopeSpans"][-1]["spans"].append(_span(span))
    return json.dumps(rv, separators=(",", ":")).encode("utf-8")


def _resource(resource: Resource):
    return {
        "attributes": [
            {"key": k, "value": _value(v)} for k, v in resource.attributes.items()
        ]
    }


def _value(value: _VALUE) -> dict[str, Any]:
    # Attribute value can be a primitive type, excluging None...
    # TODO: protobuf allows bytes, but I think OTLP doesn't.
    # TODO: protobuf allows k:v pairs, but I think OTLP doesn't.
    if isinstance(value, (str, int, float, bool)):
        k = {
            # TODO: move these to module level
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
    return {"arrayValue": [_value(e) for e in value]}


def _scope(scope: InstrumentationScope):
    rv = {"name": scope.name}
    if scope.version:
        rv["version"] = scope.version
    return rv


def _span(span: ReadableSpan):
    assert span.context
    rv = {
        "name": span.name,
        "kind": span.kind.value or 1,  # unspecified -> internal
        "traceId": _trace_id(span.context.trace_id),
        "spanId": _span_id(span.context.span_id),
        "flags": 0x100 | ([0, 0x200][bool(span.parent)]),
        "startTimeUnixNano": str(span.start_time),  # TODO: is it ever optional?
        "endTimeUnixNano": str(span.end_time),  # -"-
        "status": _status(span.status),
    }
    if span.parent:
        rv["parentSpanId"] = _span_id(span.parent.span_id)
    return rv


def _trace_id(trace_id: int) -> str:
    if not 0 <= trace_id < 2**128:
        raise ValueError(f"The {trace_id=} is out of bounds")
    return hex(trace_id)[2:].rjust(32, "0")


def _span_id(span_id: int) -> str:
    if not 0 <= span_id < 2**64:
        raise ValueError(f"The {span_id=} is out of bounds")
    return hex(span_id)[2:].rjust(16, "0")


def _status(status: Status) -> dict[str, Any]:
    # FIXME
    return {}
