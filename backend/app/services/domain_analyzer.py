import re


# Known legitimate domains
OFFICIAL_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "outlook.com",
    "gmail.com",
}


def normalize_domain(domain: str) -> str:
    """
    Remove common formatting and return a clean lowercase domain.
    """

    if not domain:
        return ""

    domain = domain.lower().strip()

    # Remove accidental trailing dot
    domain = domain.rstrip(".")

    return domain


def is_official_domain(domain: str) -> bool:
    """
    Check whether the domain is an exact official domain
    or a legitimate subdomain of an official domain.
    """

    for official in OFFICIAL_DOMAINS:

        if domain == official:
            return True

        if domain.endswith("." + official):
            return True

    return False


def detect_lookalike(domain: str) -> dict:
    """
    Detect simple brand impersonation / lookalike domains.
    """

    suspicious_brands = {
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "paypal": "paypal.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "linkedin": "linkedin.com",
    }

    for brand, official_domain in suspicious_brands.items():

        # If this is the genuine domain, do not flag it.
        if domain == official_domain:
            return {
                "detected": False
            }

        # Legitimate subdomain
        if domain.endswith("." + official_domain):
            return {
                "detected": False
            }

        # Brand appears inside another domain.
        if brand in domain:

            return {
                "detected": True,
                "brand": brand,
                "official_domain": official_domain
            }

    return {
        "detected": False
    }


def analyze_domain(domain: str) -> dict:

    domain = normalize_domain(domain)

    signals = []
    risk_score = 0

    if not domain:
        return {
            "domain": domain,
            "risk_score": 0,
            "signals": []
        }

    # --------------------------------
    # 1. Official domain check
    # --------------------------------

    if is_official_domain(domain):

        return {
            "domain": domain,
            "risk_score": 0,
            "signals": []
        }

    # --------------------------------
    # 2. Lookalike detection
    # --------------------------------

    lookalike = detect_lookalike(domain)

    if lookalike["detected"]:

        signals.append({
            "type": "LOOKALIKE_DOMAIN",
            "value": domain,
            "severity": "high",
            "explanation": (
                f"Domain contains the brand name "
                f"'{lookalike['brand']}' but is not the official "
                f"domain '{lookalike['official_domain']}'"
            )
        })

        risk_score += 60

    # --------------------------------
    # 3. Suspicious TLD
    # --------------------------------

    suspicious_tlds = {
        ".xyz",
        ".top",
        ".click",
        ".zip",
        ".mov",
        ".work",
        ".support",
    }

    if any(domain.endswith(tld) for tld in suspicious_tlds):

        signals.append({
            "type": "SUSPICIOUS_TLD",
            "value": domain,
            "severity": "medium",
            "explanation": "Domain uses a commonly abused or suspicious TLD"
        })

        risk_score += 20

    # --------------------------------
    # 4. Excessive hyphen detection
    # --------------------------------

    if domain.count("-") >= 2:

        signals.append({
            "type": "EXCESSIVE_HYPHENS",
            "value": domain,
            "severity": "low",
            "explanation": "Domain contains multiple hyphens"
        })

        risk_score += 10

    # --------------------------------
    # 5. Numeric substitution
    # --------------------------------

    if re.search(r"[a-z][0-9][a-z]", domain):

        signals.append({
            "type": "NUMERIC_SUBSTITUTION",
            "value": domain,
            "severity": "medium",
            "explanation": "Domain contains possible character substitution"
        })

        risk_score += 20

    # Keep score within 0–100
    risk_score = min(risk_score, 100)

    return {
        "domain": domain,
        "risk_score": risk_score,
        "signals": signals
    }