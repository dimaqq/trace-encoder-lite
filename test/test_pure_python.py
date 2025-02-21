from __future__ import annotations

import json


import otlp_test_data

import otlp_json


CONTENT_TYPE = "application/json"


def test_equiv():
    auth = json.loads(otlp_test_data.sample_json())
    mine = json.loads(otlp_json.encode_spans(otlp_test_data.sample_spans()))
    assert mine == auth
