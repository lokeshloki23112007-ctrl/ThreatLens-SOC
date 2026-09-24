import re


BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "sbi",
    "hdfc",
    "icici"
]


def analyze_domain(domain: str) -> dict:
    domain = (domain or "").lower().strip()

    signals = []
    risk = 0
    lookalike = False
    impersonated_brand = None

    if not domain:
        return {
            "domain": "",
            "risk_score": 0,
            "signals": [],
            "lookalike": False,
            "impersonated_brand": None
        }

    # Suspicious keywords
    suspicious_words = [
        "verify", "secure", "support", "login",
        "account", "update", "alert", "service"
    ]

    for word in suspicious_words:
        if word in domain:
            signals.append({
                "type": "SUSPICIOUS_DOMAIN_KEYWORD",
                "value": word,
                "severity": "medium",
                "explanation": f"Domain contains suspicious keyword: {word}"
            })
            risk += 8
            break

    # Look-alike / impersonation detection
    for brand in BRANDS:
        normalized = re.sub(r"[^a-z]", "", domain)

        if brand in normalized and normalized != brand:
            lookalike = True
            impersonated_brand = brand.title()

            signals.append({
                "type": "LOOKALIKE_DOMAIN",
                "value": domain,
                "severity": "high",
                "explanation": (
                    f"Domain appears to imitate {brand.title()}"
                )
            })

            risk += 25
            break

    # Numeric substitution commonly used in look-alike domains
    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s"
    }

    normalized = domain

    for number, letter in substitutions.items():
        normalized = normalized.replace(number, letter)

    for brand in BRANDS:
        if brand in normalized and brand not in domain:
            lookalike = True
            impersonated_brand = brand.title()

            signals.append({
                "type": "BRAND_SPOOFING",
                "value": domain,
                "severity": "high",
                "explanation": (
                    f"Domain resembles the trusted brand {brand.title()}"
                )
            })

            risk += 30
            break

    # IP address instead of domain
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        signals.append({
            "type": "IP_BASED_SENDER",
            "value": domain,
            "severity": "high",
            "explanation": "Sender uses an IP address instead of a normal domain"
        })
        risk += 25

    return {
        "domain": domain,
        "risk_score": min(risk, 100),
        "signals": signals,
        "lookalike": lookalike,
        "impersonated_brand": impersonated_brand
    }