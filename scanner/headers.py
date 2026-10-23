
import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "recommendation": (
            "Configure a Content-Security-Policy appropriate "
            "for your application."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "Low",
        "recommendation": (
            "For HTTPS deployments, configure an appropriate "
            "Strict-Transport-Security policy."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "X-Frame-Options": {
        "severity": "Low",
        "recommendation": (
            "Configure X-Frame-Options or an appropriate "
            "frame-ancestors CSP directive."
        ),
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": (
            "Set a Referrer-Policy suitable for your application."
        ),
    },
}


def scan_security_headers(url):
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            headers={"User-Agent": "WebSecurityPlatform/1.0"},
        )

    except requests.RequestException as error:
        return {
            "status": "error",
            "error": (
                "Could not connect to the local target. "
                "Check that your test application is running."
            ),
            "findings": [],
        }

    findings = []

    for header_name, details in SECURITY_HEADERS.items():
        header_value = response.headers.get(header_name)

        if not header_value:
            findings.append({
                "title": f"Missing security header: {header_name}",
                "category": "Security Headers",
                "severity": details["severity"],
                "evidence": (
                    f"The HTTP response did not include "
                    f"{header_name}."
                ),
                "recommendation": details["recommendation"],
            })

    return {
        "status": "completed",
        "http_status": response.status_code,
        "redirect_detected": response.is_redirect,
        "findings": findings,
    }
