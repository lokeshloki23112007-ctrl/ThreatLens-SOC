def calculate_blast_radius(risk_score, campaign=False):
    if risk_score >= 80:
        exposed = 42
        delivered = 38
        opened = 27
        clicked = 11
        credentials = 3
    elif risk_score >= 60:
        exposed = 19
        delivered = 17
        opened = 10
        clicked = 4
        credentials = 1
    elif risk_score >= 30:
        exposed = 7
        delivered = 6
        opened = 3
        clicked = 1
        credentials = 0
    else:
        exposed = 2
        delivered = 2
        opened = 1
        clicked = 0
        credentials = 0

    return {
        "employees_exposed": exposed,
        "emails_delivered": delivered,
        "opened": opened,
        "clicked": clicked,
        "credential_attempts": credentials,
        "departments_affected": [
            "Finance",
            "HR",
            "Operations"
        ] if campaign else [],
        "high_risk_users": [
            "Finance Manager",
            "Accounts Executive",
            "HR Executive"
        ] if clicked > 0 else []
    }