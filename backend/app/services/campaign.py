def detect_campaign(parsed_email, risk_score):
    domain = parsed_email.get("domain", "")
    urls = parsed_email.get("urls", [])
    subject = parsed_email.get("subject", "")

    is_campaign = risk_score >= 60

    return {
        "is_campaign": is_campaign,
        "campaign_id": "TL-CAMP-001" if is_campaign else None,
        "name": "Account Verification Campaign" if is_campaign else None,
        "related_cases": 18 if is_campaign else 0,
        "recipients": 42 if is_campaign else 0,
        "departments": ["Finance", "HR", "Operations"] if is_campaign else [],
        "first_observed": "Today",
        "latest_observed": "Just now",
        "status": "ACTIVE" if is_campaign else "NONE",
        "domain": domain,
        "urls": urls,
        "subject_pattern": subject
    }