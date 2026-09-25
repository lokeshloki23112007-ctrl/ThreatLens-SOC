def calculate_risk(
    domain_result: dict,
    url_result: dict,
    content_result: dict
) -> dict:

    # --------------------------------
    # Extract service scores
    # --------------------------------

    domain_score = domain_result.get("risk_score", 0)
    url_score = url_result.get("risk_score", 0)
    content_score = content_result.get("risk_score", 0)

    # --------------------------------
    # Base weighted score
    # --------------------------------

    weighted_score = (
        (domain_score * 0.35)
        + (url_score * 0.25)
        + (content_score * 0.40)
    )

    # --------------------------------
    # Signal severity boost
    # --------------------------------

    all_signals = (
        domain_result.get("signals", [])
        + url_result.get("signals", [])
        + content_result.get("signals", [])
    )

    severity_boost = 0

    for signal in all_signals:

        severity = signal.get("severity", "").lower()

        if severity == "high":
            severity_boost += 8

        elif severity == "medium":
            severity_boost += 4

        elif severity == "low":
            severity_boost += 1

    # Limit boost so it cannot dominate the score
    severity_boost = min(severity_boost, 25)

    # --------------------------------
    # Final risk score
    # --------------------------------

    risk_score = round(
        min(weighted_score + severity_boost, 100)
    )

    # --------------------------------
    # Classification
    # --------------------------------

    if risk_score >= 60:
        classification = "PHISHING"

    elif risk_score >= 30:
        classification = "SUSPICIOUS"

    else:
        classification = "SAFE"

    # --------------------------------
    # Confidence
    # --------------------------------

    high_signals = sum(
        1
        for signal in all_signals
        if signal.get("severity", "").lower() == "high"
    )

    medium_signals = sum(
        1
        for signal in all_signals
        if signal.get("severity", "").lower() == "medium"
    )

    total_signals = len(all_signals)

    if high_signals >= 2 or total_signals >= 4:
        confidence = "HIGH"

    elif high_signals >= 1 or medium_signals >= 2:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    return {
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence
    }