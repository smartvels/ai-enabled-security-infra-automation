"""
Unit tests for the classification logic in triage.py.

These do NOT call a real LocalAI instance -- the HTTP call is mocked so
tests run offline and fast, and so a broken production LocalAI can never
mask a broken test suite.
"""
import json
from unittest.mock import patch, MagicMock

import pytest

from triage import classify_alert, app


def _mock_localai_response(content: str):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return mock_resp


@patch("triage.requests.post")
def test_classify_alert_parses_clean_json(mock_post):
    mock_post.return_value = _mock_localai_response(
        "{'verdict': 'true_positive', 'confidence': 90, "
        "'reason': 'brute force', 'source_ip': '1.2.3.4'}"
    )
    result = classify_alert("SSH brute force from 1.2.3.4")
    assert result["verdict"] == "true_positive"
    assert result["confidence"] == 90
    assert result["source_ip"] == "1.2.3.4"


@patch("triage.requests.post")
def test_classify_alert_strips_leading_text(mock_post):
    # Model sometimes prefixes the JSON with a colon/newline
    mock_post.return_value = _mock_localai_response(
        "\n: {'verdict': 'false_positive', 'confidence': 40, "
        "'reason': 'benign', 'source_ip': ''}"
    )
    result = classify_alert("Some benign event")
    assert result["verdict"] == "false_positive"


@patch("triage.requests.post")
def test_classify_alert_raises_on_missing_json(mock_post):
    mock_post.return_value = _mock_localai_response("no json here at all")
    with pytest.raises(ValueError):
        classify_alert("test alert")


def test_healthz_endpoint():
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


@patch("triage.classify_alert")
def test_wazuh_alert_endpoint_success(mock_classify):
    mock_classify.return_value = {
        "verdict": "true_positive",
        "confidence": 85,
        "reason": "test",
        "source_ip": "1.2.3.4",
    }
    client = app.test_client()
    resp = client.post(
        "/wazuh-alert",
        data=json.dumps({"rule": {"id": "125712"}}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["verdict"]["verdict"] == "true_positive"


@patch("triage.classify_alert")
def test_wazuh_alert_endpoint_handles_localai_failure(mock_classify):
    mock_classify.side_effect = ValueError("no JSON found")
    client = app.test_client()
    resp = client.post(
        "/wazuh-alert",
        data=json.dumps({"rule": {"id": "125712"}}),
        content_type="application/json",
    )
    assert resp.status_code == 500
    assert resp.get_json()["status"] == "error"
