# otlp-json

`otpl-json` is an OTLP serialisation library.

It's written in pure Python, without dependencies.

It serialises a bunch of spans into OTLP 1.5 JSON format.

### Motivation

Tracing should be on by default.

OTLP is the standard data format and API, and the standard Python package is `opentelemetry-exporter-otlp-proto-http`. It brings in a total of 18 packages and adds 9MB to the project virtual environment.

A typical Python application, that's being instrumented, only generates own tracing data and needs to send it out. It doesn't need that much complexity.

### Usage

```py
from otlp_json import CONTENT_TYPE, encode_spans


class SomeExporter:
    def export(self.spans: Sequece[ReadableSpan]) -> None:
        requests.post(
            "http://localhost:4318/v1/traces",
            data=encode_spans(spans),
            headers={"Content-Type": CONTENT_TYPE},
        )
```

### Library size

- 3KB whl, containing:
  - 4KB Python source
  - ?? metadata

### TODO(doc)

- link to rust library
- link to urllib sender
- link to test vector generator

### TODO(features)

- Events
- Links
- Baggage
- Schemata, when https://github.com/open-telemetry/opentelemetry-python/pull/4359 lands

### TODO(fixes)

- Status fields
- validate what fields are in fact optional
- ???

### Limitations

This library is meant to marshal tracing data that's collected in the same Python process.

It is not meant to be used for data received and forwarded.
