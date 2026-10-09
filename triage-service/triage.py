"""
Wazuh -> LocalAI triage service.

Receives a Wazuh alert via HTTP POST, sends it to a self-hosted LocalAI
instance for classification, and returns a structured verdict.

Environment variables (see .env.example):
    LOCALAI_URL      - full URL to LocalAI's chat completions endpoint
    LOCALAI_MODEL     - model name as registered in LocalAI
    LISTEN_PORT       - port this service listens on (default 5050)
"""
import os
import json
import logging

from flask import Flask, request, jsonify
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("triage")

app = Flask(__name__)

LOCALAI_URL = os.environ.get(
    "LOCALAI_URL", "http://localhost:8080/v1/chat/completions"
)
LOCALAI_MODEL = os.environ.get("LOCALAI_MODEL", "Qwen2.5-7B-Instruct-Q4_K_M.gguf")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5050"))
# Bind to localhost by default; set LISTEN_HOST=0.0.0.0 explicitly to expose on the network
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")

SYSTEM_PROMPT = (
    "You are a SOC analyst. Classify this Wazuh alert as true_positive or "
    "false_positive. Respond ONLY with valid JSON in this exact format: "
    "{'verdict': 'true_positive or false_positive', 'confidence': a number "
    "0 to 100, 'reason': 'short explanation', 'source_ip': 'extracted IP "
    "if present'}"
)


def classify_alert(alert_text: str) -> dict:
    """Call LocalAI and return the parsed verdict dict.

    Building the payload as a Python dict and letting `requests` serialize
    it (rather than hand-building a JSON string) is what avoids the
    embedded-newline/quote corruption bug seen with naive string
    templating in both Shuffle's Http node and early n8n workflows.
    """
    payload = {
        "model": LOCALAI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert_text},
        ],
    }
    resp = requests.post(LOCALAI_URL, json=payload, timeout=60)
    resp.raise_for_status()
    result = resp.json()
    raw_content = result["choices"][0]["message"]["content"]

    # Model sometimes prefixes with a colon/newline before the JSON object;
    # trim to the first '{' to get a parseable object.
    json_start = raw_content.find("{")
    if json_start == -1:
        raise ValueError(f"No JSON object found in model output: {raw_content!r}")

    verdict_json_text = raw_content[json_start:].replace("'", '"')
    return json.loads(verdict_json_text)


@app.route("/wazuh-alert", methods=["POST"])
def handle_alert():
    alert_data = request.get_data(as_text=True)
    log.info("Alert received (%d bytes)", len(alert_data))

    try:
        verdict = classify_alert(alert_data)
    except Exception as exc:  # noqa: BLE001 - log and return a clean 500
        log.exception("Triage failed")
        return jsonify({"status": "error", "detail": str(exc)}), 500

    log.info("Verdict: %s", verdict)
    return jsonify({"status": "processed", "verdict": verdict})


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
