def calculate_priority(
    risk_score: int,
    blast_radius: dict,
    campaign: dict
) -> dict:

    # --------------------------------
    # Exposure metrics
    # --------------------------------

    employees_exposed = blast_radius.get(
        "employees_exposed", 0
    )

    emails_delivered = blast_radius.get(
        "emails_delivered", 0
    )

    clicked = blast_radius.get(
        "clicked", 0
    )

    credential_attempts = blast_radius.get(
        "credential_attempts", 0
    )

    departments = blast_radius.get(
        "departments_affected", []
    )

    # --------------------------------
    # Campaign metrics
    # --------------------------------

    is_campaign = campaign.get(
        "is_campaign", False
    )

    recipients = campaign.get(
        "recipients", 0
    )

    related_cases = campaign.get(
        "related_cases", 0
    )

    # --------------------------------
    # 1. Threat severity
    # --------------------------------

    threat_score = risk_score * 0.40

    # --------------------------------
    # 2. Employee exposure
    # --------------------------------

    if employees_exposed >= 20:
        exposure_score = 25

    elif employees_exposed >= 10:
        exposure_score = 20

    elif employees_exposed >= 5:
        exposure_score = 12

    elif employees_exposed >= 1:
        exposure_score = 6

    else:
        exposure_score = 0

    # --------------------------------
    # 3. User interaction
    # --------------------------------

    interaction_score = 0

    if clicked > 0:
        interaction_score += min(clicked * 2, 10)

    if credential_attempts > 0:
        interaction_score += min(
            credential_attempts * 8,
            16
        )

    # --------------------------------
    # 4. Campaign spread
    # --------------------------------

    campaign_score = 0

    if is_campaign:
        campaign_score += 8

    if recipients >= 50:
        campaign_score += 10

    elif recipients >= 20:
        campaign_score += 7

    elif recipients >= 10:
        campaign_score += 4

    if related_cases >= 20:
        campaign_score += 5

    elif related_cases >= 10:
        campaign_score += 3

    # --------------------------------
    # 5. Department impact
    # --------------------------------

    department_score = min(
        len(departments) * 2,
        6
    )

    # --------------------------------
    # Final priority score
    # --------------------------------

    priority_score = round(
        threat_score
        + exposure_score
        + interaction_score
        + campaign_score
        + department_score
    )

    priority_score = min(
        priority_score,
        100
    )

    # --------------------------------
    # Priority level
    # --------------------------------

    if (
        priority_score >= 75
        or credential_attempts >= 2
    ):
        priority_level = "CRITICAL"

        recommended_action = (
            "Immediate SOC investigation and "
            "containment recommended."
        )

    elif priority_score >= 55:
        priority_level = "HIGH"

        recommended_action = (
            "Prioritize for SOC investigation "
            "and monitor affected users."
        )

    elif priority_score >= 30:
        priority_level = "MEDIUM"

        recommended_action = (
            "Review the case and monitor "
            "related activity."
        )

    else:
        priority_level = "LOW"

        recommended_action = (
            "No immediate SOC escalation required."
        )

    return {
        "priority_score": priority_score,
        "priority_level": priority_level,
        "recommended_action": recommended_action
    }