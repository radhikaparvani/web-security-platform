
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# Load the project's root .env file explicitly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=True)


def available():
    return bool(os.getenv("ZAP_API_URL", "").strip())


def _api_url():
    return os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").strip().rstrip("/")


def _request(path, params=None, timeout=10):
    query = dict(params or {})
    api_key = os.getenv("ZAP_API_KEY", "").strip()

    if api_key:
        query["apikey"] = api_key

    response = requests.get(
        f"{_api_url()}/JSON/{path}/",
        params=query,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    if "code" in data and str(data.get("code", "")).startswith("5"):
        raise RuntimeError(data.get("message", "ZAP API returned an error."))

    return data


def scan_with_zap(url):
    if not available():
        return {
            "status": "error",
            "error": "ZAP_API_URL is not configured. Check the project's root .env file.",
            "findings": [],
        }

    try:
        # Access the target so ZAP can observe it.
        _request(
            "core/action/accessUrl",
            {"url": url, "followRedirects": "false"},
            timeout=30,
        )

        # Wait for passive scanning to finish.
        deadline = time.time() + 120

        while time.time() < deadline:
            status_data = _request("pscan/view/recordsToScan")
            remaining = int(status_data.get("recordsToScan", 0))

            if remaining <= 0:
                break

            time.sleep(2)
        else:
            return {
                "status": "error",
                "error": "ZAP passive scan did not finish within 120 seconds.",
                "findings": [],
            }

        alerts_data = _request(
            "core/view/alerts",
            {"baseurl": url, "start": 0, "count": 500},
        )

        findings = []
        risk_map = {
            "3": "High",
            "High": "High",
            "2": "Medium",
            "Medium": "Medium",
            "1": "Low",
            "Low": "Low",
            "0": "Informational",
            "Informational": "Informational",
        }

        for alert in alerts_data.get("alerts", []):
            risk = alert.get("risk") or alert.get("riskcode") or "Informational"
            severity = risk_map.get(str(risk), str(risk).title())

            findings.append({
                "title": alert.get("name") or alert.get("alert") or "OWASP ZAP alert",
                "category": "OWASP ZAP - " + str(alert.get("pluginId", "alert")),
                "severity": severity,
                "evidence": (
                    f"URL: {alert.get('url', url)}. "
                    f"Parameter: {alert.get('param') or 'N/A'}. "
                    f"Evidence: {alert.get('evidence') or alert.get('other') or 'No additional evidence supplied.'} "
                    f"Confidence: {alert.get('confidence') or 'Unknown'}."
                ),
                "recommendation": (
                    alert.get("solution")
                    or "Review the alert, verify the finding, and follow the remediation guidance."
                ),
            })

        return {"status": "completed", "findings": findings}

    except (requests.RequestException, ValueError, RuntimeError, KeyError) as error:
        return {
            "status": "error",
            "error": f"Could not complete the OWASP ZAP scan: {str(error)[:500]}",
            "findings": [],
        }

