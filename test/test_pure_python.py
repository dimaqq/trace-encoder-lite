from __future__ import annotations

import json


import otlp_test_data

import otlp_json


CONTENT_TYPE = "application/json"


def canonical(batch):
    batch["resourceSpans"].sort(key=lambda rs: json.dumps(rs["resource"]))
    for rs in batch["resourceSpans"]:
        rs["scopeSpans"].sort(key=lambda sc: sc["scope"]["name"])
        for sc in rs["scopeSpans"]:
            sc["spans"].sort(key=lambda sp: sp["spanId"])

    return batch


def test_equiv():
    auth = canonical(json.loads(otlp_test_data.sample_json()))
    mine = canonical(json.loads(otlp_json.encode_spans(otlp_test_data.sample_spans())))
    assert mine == auth
