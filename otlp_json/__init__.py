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


__all__ = [
    "CONTENT_TYPE",
    "encode_spans",
]

CONTENT_TYPE = "application/json"


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


def _ensure_homogeneous(value: Sequence[_LEAF_VALUE]) -> Sequence[_LEAF_VALUE]:
    # TODO: empty lists are allowed, aren't they?
    if len(types := {type(v) for v in value}) > 1:
        raise ValueError(f"Attribute value arrays must be homogeneous, got {types=}")
    return value


def _value(v: _VALUE) -> dict[str, Any]:
    if isinstance(v, bool):
        return {"boolValue": bool(v)}
    if isinstance(v, int):
        return {"intValue": str(int(v))}
    if isinstance(v, float):
        return {"doubleValue": float(v)}
    if isinstance(v, bytes):
        return {
            "bytesValue": bytes(v)
        }  # FIXME this can't be right; gotta encode this somehow
    if isinstance(v, str):
        return {"stringValue": str(v)}
    if isinstance(v, Sequence):
        return {"arrayValue": {"values": [_value(e) for e in _ensure_homogeneous(v)]}}
    if isinstance(v, Mapping):
        return {"kvlistValue": {"values": [{k: _value(vv) for k, vv in v.items()}]}}

    raise ValueError(f"Cannot convert attribute value of {type(v)=}")


def _scope(scope: InstrumentationScope):
    rv = {
        "name": scope.name,
        **_attributes(scope),
    }
    if scope.version:
        rv["version"] = scope.version
    return rv


_REMOTE = 0x300
_LOCAL = 0x100


def _span(span: ReadableSpan):
    assert span.context
    rv = {
        "name": span.name,
        "kind": span.kind.value or 1,  # unspecified -> internal
        "traceId": _trace_id(span.context.trace_id),
        "spanId": _span_id(span.context.span_id),
        "flags": _REMOTE if span.parent and span.parent.is_remote else _LOCAL,
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
    rv = {}
    # rv["code"] ...
    # rv["message"] = ...
    return rv


def _event(event: Event) -> dict[str, Any]:
    rv = {
        "name": event.name,
        "timeUnixNano": str(event.timestamp),
        **_attributes(event),
    }
    # TODO: any optional attributes?
    return rv
