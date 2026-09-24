import re


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "as soon as possible",
    "action required",
    "act now",
    "expires",
    "suspended",
    "verify now",
]

CREDENTIAL_WORDS = [
    "password",
    "login",
    "username",
    "credential",
    "otp",
    "verification code",
    "sign in",
]

PAYMENT_WORDS = [
    "payment",
    "invoice",
    "refund",
    "bank",
    "card",
    "transfer",
    "transaction",
]


def find_matches(text: str, words: list[str]) -> list[str]:
    text = text.lower()
    return [word for word in words if word in text]


def analyze_content(subject: str = "", body: str = "") -> dict:
    text = f"{subject} {body}".strip()

    signals = []
    risk = 0

    urgency = find_matches(text, URGENCY_WORDS)
    credentials = find_matches(text, CREDENTIAL_WORDS)
    payment = find_matches(text, PAYMENT_WORDS)

    if urgency:
        signals.append({
            "type": "URGENCY_LANGUAGE",
            "severity": "medium",
            "value": urgency,
            "explanation": "Message uses urgency or pressure-based language"
        })
        risk += min(len(urgency) * 8, 20)

    if credentials:
        signals.append({
            "type": "CREDENTIAL_REQUEST",
            "severity": "high",
            "value": credentials,
            "explanation": "Message contains credential or authentication requests"
        })
        risk += 20

    if payment:
        signals.append({
            "type": "PAYMENT_SIGNAL",
            "severity": "medium",
            "value": payment,
            "explanation": "Message contains payment or financial-related language"
        })
        risk += 15

    # Excessive exclamation/question marks
    if len(re.findall(r"[!?]", text)) >= 5:
        signals.append({
            "type": "EXCESSIVE_PUNCTUATION",
            "severity": "low",
            "value": "high",
            "explanation": "Message uses unusually excessive punctuation"
        })
        risk += 5

    return {
        "risk_score": min(risk, 100),
        "signals": signals,
        "urgency_detected": bool(urgency),
        "credential_request": bool(credentials),
        "payment_signal": bool(payment)
    }