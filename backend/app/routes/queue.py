from fastapi import APIRouter

router = APIRouter()


@router.get("/queue")
def queue_status():

    queue = [
        {
            "incident_id": "TL-INC-001",
            "priority": "CRITICAL",
            "priority_score": 94,
            "classification": "PHISHING",
            "risk_score": 92,
            "campaign_id": "TL-CAMP-001",
            "exposure": 42,
            "status": "PENDING",
            "recommended_action": "Immediate investigation and employee warning"
        },
        {
            "incident_id": "TL-INC-002",
            "priority": "HIGH",
            "priority_score": 86,
            "classification": "PHISHING",
            "risk_score": 84,
            "campaign_id": "TL-CAMP-002",
            "exposure": 28,
            "status": "PENDING",
            "recommended_action": "Investigate affected recipients"
        },
        {
            "incident_id": "TL-INC-003",
            "priority": "HIGH",
            "priority_score": 78,
            "classification": "PHISHING",
            "risk_score": 76,
            "campaign_id": "TL-CAMP-001",
            "exposure": 19,
            "status": "PENDING",
            "recommended_action": "Review campaign activity and block indicators"
        },
        {
            "incident_id": "TL-INC-004",
            "priority": "MEDIUM",
            "priority_score": 52,
            "classification": "SUSPICIOUS",
            "risk_score": 48,
            "campaign_id": None,
            "exposure": 7,
            "status": "PENDING",
            "recommended_action": "Analyst review recommended"
        },
        {
            "incident_id": "TL-INC-005",
            "priority": "LOW",
            "priority_score": 21,
            "classification": "SUSPICIOUS",
            "risk_score": 25,
            "campaign_id": None,
            "exposure": 2,
            "status": "PENDING",
            "recommended_action": "Monitor and review if additional signals appear"
        }
    ]

    # Highest priority cases first
    queue.sort(
        key=lambda item: item["priority_score"],
        reverse=True
    )

    analyst_capacity = 5
    active_cases = min(len(queue), analyst_capacity)
    available_slots = analyst_capacity - active_cases

    return {
        "analyst_capacity": analyst_capacity,
        "active_cases": active_cases,
        "available_slots": available_slots,
        "queue": queue
    }