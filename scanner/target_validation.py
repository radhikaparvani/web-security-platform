
from urllib.parse import urlparse


ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_target(url):
    if not isinstance(url, str):
        return False, "Target must be a URL string."

    url = url.strip()

    if not url or len(url) > 2048:
        return False, "URL is empty or too long."

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme not in {"http", "https"}:
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not hostname:
            return False, "URL must contain a hostname."

        if parsed.username or parsed.password:
            return False, "URLs containing credentials are not allowed."

        if hostname not in ALLOWED_HOSTS:
            return False, (
                "V1 only allows localhost targets: "
                "localhost, 127.0.0.1, or ::1."
            )

        if parsed.port is None and ":" in parsed.netloc:
            return False, "Invalid port."

        return True, url

    except ValueError:
        return False, "Invalid URL or port."
