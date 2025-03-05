from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import TypeAlias

    from opentelemetry.trace import Link
    from opentelemetry._logs import LogRecord
    from opentelemetry.sdk.trace import ReadableSpan, Event
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
    # TODO: add schema_url once that lands in opentelemetry-sdk
    return _attributes(resource)


def _attributes(
    thing: Resource | InstrumentationScope | ReadableSpan | Event | Link | LogRecord,
) -> dict[str, Any]:
    rv = {"attributes": [], "dropped_attributes_count": 0}

    assert thing.attributes is not None
    for k, v in thing.attributes.items():
        try:
            rv["attributes"].append({"key": k, "value": _value(v)})
        except ValueError:
            pass

    rv["dropped_attributes_count"] = len(thing.attributes) - len(rv["attributes"])  # type: ignore

    for k in ("attributes", "dropped_attributes_count"):
        if not rv[k]:
            del rv[k]

    return rv


def _homogeneous_array(value: list[_LEAF_VALUE]) -> list[_LEAF_VALUE]:
    # TODO: empty lists are allowed, aren't they?
    if len(types := {type(v) for v in value}) > 1:
        raise ValueError(f"Attribute value arrays must be homogeneous, got {types=}")
    return value


def _value(value: _VALUE) -> dict[str, Any]:
    # Attribute value can be a primitive type, excluging None...
    # protobuf allows bytes, but I think OTLP spec does not?
    # protobuf allows k:v pairs, but I think OTLP doesn't.
    # TODO: read up the spec and validate the allowed type range.
    for klass, (key, post) in _VALUE_TYPES.items():
        if isinstance(value, klass):
            return {key: post(value)}

    raise ValueError(f"Cannot convert attribute of {type(value)=}")


def _scope(scope: InstrumentationScope):
    rv = {
        "name": scope.name,
        **_attributes(scope),
    }
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
        "flags": 0x100 | ([0, 0x200][bool(span.parent and span.parent.is_remote)]),
        "startTimeUnixNano": str(span.start_time),
        "endTimeUnixNano": str(span.end_time),  # can this be unset?
        "status": _status(span.status),
        **_attributes(span),
    }

    if span.parent:
        rv["parentSpanId"] = _span_id(span.parent.span_id)

    # TODO: is this field really nullable?
    if span.events:
        rv["events"] = [_event(e) for e in span.events]

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
    # FIXME: need an example of bad status
    return {}


def _event(event: Event) -> dict[str, Any]:
    rv = {
        "name": event.name,
        "timeUnixNano": str(event.timestamp),
        **_attributes(event),
    }
    # TODO: any optional attributes?
    return rv
