from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import TypeAlias

    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.util.instrumentation import InstrumentationScope
    from opentelemetry.trace.status import Status

    _LEAF_VALUE: TypeAlias = "str | int | float | bool"  # TODO: confirm
    _VALUE: TypeAlias = "_LEAF_VALUE | Sequence[_LEAF_VALUE]"


CONTENT_TYPE = "application/json"


_VALUE_TYPES = {
    # NOTE: order matters, for isinstance(True, int).
    bool: ("boolValue", bool),
    int: ("intValue", str),
    float: ("doubleValue", float),
    bytes: ("bytesValue", bytes),
    str: ("stringValue", str),
    Sequence: (
        "arrayValue",
        lambda value: {"values": [_value(e) for e in _homogeneous_array(value)]},
    ),
    Mapping: (
        "kvlistValue",
        lambda value: {"values": [{k: _value(v) for k, v in value.items()}]},
    ),
}


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
    rv = {"attributes": []}
    for k, v in resource.attributes.items():
        try:
            rv["attributes"].append({"key": k, "value": _value(v)})
        except ValueError:
            pass

    # NOTE: blocks that contain droppedAttributesCount:
    # - Event
    # - Link
    # - InstrumentationScope
    # - LogRecord (out of scope for this library)
    # - Resource
    if dropped := len(resource.attributes) - len(rv["attributes"]):
        rv["dropped_attribute_count"] = dropped  # type: ignore

    return rv


def _homogeneous_array(value: list[_LEAF_VALUE]) -> list[_LEAF_VALUE]:
    # TODO: empty lists are allowed, aren't they?
    if len(types := {type(v) for v in value}) > 1:
        raise ValueError(f"Attribute value arrays must be homogeneous, got {types=}")
    return value


def _value(value: _VALUE) -> dict[str, Any]:
    # Attribute value can be a primitive type, excluging None...
    # TODO: protobuf allows bytes, but I think OTLP doesn't.
    # TODO: protobuf allows k:v pairs, but I think OTLP doesn't.
    for klass, (key, post) in _VALUE_TYPES.items():
        if isinstance(value, klass):
            return {key: post(value)}

    raise ValueError(f"Cannot convert attribute of {type(value)=}")


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

    if span.attributes:
        rv["attributes"] = []

    for k, v in span.attributes.items():  # type: ignore
        try:
            rv["attributes"].append({"key": k, "value": _value(v)})
        except ValueError:
            pass

    if dropped := len(span.attributes) - len(rv.get("attributes", ())):  # type: ignore
        rv["dropped_attribute_count"] = dropped  # type: ignore

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
