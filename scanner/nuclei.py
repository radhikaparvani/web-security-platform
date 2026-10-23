
import json
import os
import shutil
import subprocess


NUCLEI_PATH = r"D:\nuclei_3.11.1_windows_amd64\nuclei.exe"


def get_nuclei_binary():
    """Find the Nuclei executable."""
    if os.path.isfile(NUCLEI_PATH):
        return NUCLEI_PATH

    return shutil.which("nuclei")


def available():
    """Check whether Nuclei is installed and accessible."""
    return get_nuclei_binary() is not None


def scan_with_nuclei(url):
    """Run Nuclei and convert JSONL output into dashboard findings."""
    binary = get_nuclei_binary()

    if not binary:
        return {
            "status": "error",
            "error": (
                "Nuclei executable not found. "
                "Check the installation path or system PATH."
            ),
            "findings": [],
        }

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "error",
            "error": "A valid target URL is required.",
            "findings": [],
        }

    url = url.strip()

    try:
        completed = subprocess.run(
            [
                binary,
                "-u", url,
                "-jsonl",
                "-silent",
                "-no-color",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Nuclei scan timed out after 300 seconds.",
            "findings": [],
        }

    except OSError as error:
        return {
            "status": "error",
            "error": f"Could not start Nuclei: {error}",
            "findings": [],
        }

    if completed.returncode not in (0, 1):
        detail = (
            completed.stderr
            or completed.stdout
            or "Nuclei exited with an error."
        ).strip()

        return {
            "status": "error",
            "error": detail[:700],
            "findings": [],
        }

    findings = []

    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info") or {}
        classification = info.get("classification") or {}

        severity = str(
            info.get("severity") or "info"
        ).lower()

        if severity not in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "informational",
        }:
            severity = "info"

        name = (
            info.get("name")
            or item.get("template-id")
            or "Nuclei finding"
        )

        template_id = (
            item.get("template-id")
            or "unknown-template"
        )

        matched = (
            item.get("matched-at")
            or item.get("host")
            or url
        )

        description = (
            info.get("description")
            or "Nuclei template matched this target."
        )

        reference = info.get("reference") or []

        if isinstance(reference, str):
            reference = [reference]

        references_text = (
            " References: " + ", ".join(map(str, reference[:3]))
            if reference
            else ""
        )

        findings.append({
            "title": str(name),
            "category": "Nuclei · " + str(template_id),
            "severity": (
                "Informational"
                if severity == "informational"
                else severity.title()
            ),
            "evidence": (
                f"Matched target: {matched}. {description}"
            ),
            "recommendation": (
                "Verify the result manually, review the referenced "
                "template/advisory, and remediate if confirmed."
                + references_text
            ),
        })

    return {
        "status": "completed",
        "findings": findings,
    }
