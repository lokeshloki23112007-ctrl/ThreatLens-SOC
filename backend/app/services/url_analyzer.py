import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "payment",
    "wallet",
]


def analyze_url(url: str) -> dict:
    url = (url or "").strip()

    if not url:
        return {
            "url": "",
            "risk_score": 0,
            "signals": []
        }

    signals = []
    risk = 0

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        signals.append({
            "type": "INSECURE_PROTOCOL",
            "severity": "medium",
            "value": url,
            "explanation": "URL uses HTTP instead of HTTPS"
        })
        risk += 10

    # IP address URL
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        signals.append({
            "type": "IP_BASED_URL",
            "severity": "high",
            "value": hostname,
            "explanation": "URL uses an IP address instead of a domain name"
        })
        risk += 25

    # Suspicious keywords
    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if found_words:
        signals.append({
            "type": "SUSPICIOUS_URL_KEYWORD",
            "severity": "medium",
            "value": ", ".join(found_words),
            "explanation": (
                "URL contains suspicious security or account-related keywords"
            )
        })
        risk += min(len(found_words) * 5, 20)

    # @ symbol
    if "@" in url:
        signals.append({
            "type": "URL_OBFUSCATION",
            "severity": "high",
            "value": "@",
            "explanation": "URL contains @ which can obscure the actual destination"
        })
        risk += 20

    # Very long URL
    if len(url) > 100:
        signals.append({
            "type": "LONG_URL",
            "severity": "medium",
            "value": len(url),
            "explanation": "URL is unusually long"
        })
        risk += 10

    # Too many subdomains
    if hostname.count(".") >= 3:
        signals.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "medium",
            "value": hostname,
            "explanation": "URL contains multiple subdomain levels"
        })
        risk += 10

    # Punycode
    if "xn--" in hostname:
        signals.append({
            "type": "PUNYCODE_DOMAIN",
            "severity": "high",
            "value": hostname,
            "explanation": "Domain uses punycode and requires additional scrutiny"
        })
        risk += 20

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": min(risk, 100),
        "signals": signals
    }