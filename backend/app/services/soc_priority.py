def calculate_priority(
    risk_score,
    blast_radius,
    campaign
):
    exposure = blast_radius.get("employees_exposed", 0)
    spread = campaign.get("related_cases", 0)

    exposure_score = min(exposure * 2, 100)
    spread_score = min(spread * 3, 100)

    priority_score = round(
        (risk_score * 0.50) +
        (exposure_score * 0.30) +
        (spread_score * 0.20)
    )

    priority_score = min(priority_score, 100)

    if priority_score >= 80:
        level = "CRITICAL"
        action = "Investigate immediately and review affected recipients."
    elif priority_score >= 60:
        level = "HIGH"
        action = "Investigate affected recipients and campaign indicators."
    elif priority_score >= 30:
        level = "MEDIUM"
        action = "Review the case and monitor related activity."
    else:
        level = "LOW"
        action = "No immediate SOC escalation required."

    return {
        "priority_score": priority_score,
        "priority_level": level,
        "recommended_action": action
    }