
import os
from pathlib import Path

from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# Project configuration
PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env", override=True)

# Make Nuclei executable available to the scanner.
NUCLEI_DIR = r"D:\nuclei_3.11.1_windows_amd64"
os.environ["PATH"] = (
    NUCLEI_DIR + os.pathsep + os.environ.get("PATH", "")
)

# Existing scanners and services
from scanner.target_validation import validate_target
from scanner.headers import scan_security_headers
from scanner.nuclei import scan_with_nuclei
from scanner.zap import scan_with_zap
from services.ai_assistant import explain_finding

from database import (
    initialize_db,
    save_scan,
    get_scan_history,
    get_scan_details,
)

app = Flask(__name__)

# Initialize the existing database.
initialize_db()


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "tools": {
            "nuclei": scan_with_nuclei.available(),
            "zap": scan_with_zap.available(),
        },
    })


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("url")
    requested_scanners = data.get("scanners", ["headers"])

    valid, result = validate_target(target)

    if not valid:
        return jsonify({"error": result}), 400

    allowed_scanners = {"headers", "nuclei", "zap"}

    if not isinstance(requested_scanners, list) or not requested_scanners:
        return jsonify({"error": "Select at least one scanner."}), 400

    if any(item not in allowed_scanners for item in requested_scanners):
        return jsonify({
            "error": "One or more scanner selections are invalid."
        }), 400

    combined_findings = []
    scanner_status = {}
    http_status = None
    redirect_detected = False
    errors = []

    # 1. Security headers scanner
    if "headers" in requested_scanners:
        header_result = scan_security_headers(result)
        scanner_status["headers"] = header_result.get("status", "error")

        if header_result.get("status") == "completed":
            combined_findings.extend([
                {**item, "scanner": "Security Headers"}
                for item in header_result.get("findings", [])
            ])

            http_status = header_result.get("http_status")
            redirect_detected = header_result.get(
                "redirect_detected", False
            )
        else:
            errors.append(
                "Security Headers: "
                + header_result.get("error", "Scan failed.")
            )

    # 2. Nuclei scanner
    if "nuclei" in requested_scanners:
        nuclei_result = scan_with_nuclei(result)
        scanner_status["nuclei"] = nuclei_result.get("status", "error")

        if nuclei_result.get("status") == "completed":
            combined_findings.extend([
                {**item, "scanner": "Nuclei"}
                for item in nuclei_result.get("findings", [])
            ])
        else:
            errors.append(
                "Nuclei: "
                + nuclei_result.get("error", "Scan failed.")
            )

    # 3. OWASP ZAP scanner
    if "zap" in requested_scanners:
        zap_result = scan_with_zap(result)
        scanner_status["zap"] = zap_result.get("status", "error")

        if zap_result.get("status") == "completed":
            combined_findings.extend([
                {**item, "scanner": "OWASP ZAP"}
                for item in zap_result.get("findings", [])
            ])
        else:
            errors.append(
                "OWASP ZAP: "
                + zap_result.get("error", "Scan failed.")
            )

    # Report an error only if every selected scanner failed.
    successful = [
        status
        for status in scanner_status.values()
        if status == "completed"
    ]

    if not successful:
        return jsonify({
            "status": "error",
            "error": (
                "No selected scanner completed. "
                + " ".join(errors)
            ),
            "scanner_status": scanner_status,
            "findings": [],
        }), 502

    # Preserve scanner attribution in the saved scan.
    db_findings = []

    for item in combined_findings:
        scanner_name = item.get("scanner", "Unknown scanner")
        db_item = dict(item)

        db_item["category"] = (
            f'{item.get("category", "Unclassified")} · {scanner_name}'
        )
        db_item["evidence"] = (
            f'[Scanner: {scanner_name}] '
            f'{item.get("evidence", "")}'
        )

        db_findings.append(db_item)

    scan_result = {
        "status": "completed",
        "target": result,
        "http_status": http_status,
        "redirect_detected": redirect_detected,
        "findings": combined_findings,
        "scanner_status": scanner_status,
        "scanner_errors": errors,
    }

    saved_result = {
        **scan_result,
        "findings": db_findings,
    }

    scan_id = save_scan(result, saved_result)
    scan_result["scan_id"] = scan_id

    return jsonify(scan_result)


@app.post("/api/explain")
def explain():
    data = request.get_json(silent=True) or {}
    finding = data.get("finding")

    if not isinstance(finding, dict):
        return jsonify({
            "error": "Provide a finding object."
        }), 400

    try:
        return jsonify({
            "explanation": explain_finding(finding)
        })
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 503
    except Exception:
        app.logger.exception("AI explanation request failed")
        return jsonify({
            "error": "AI service request failed. Check server logs."
        }), 502


@app.get("/api/scans")
def scan_history():
    return jsonify({
        "scans": get_scan_history()
    })


@app.get("/api/scans/<int:scan_id>")
def scan_details(scan_id):
    scan = get_scan_details(scan_id)

    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    return jsonify(scan)


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000,
    )
