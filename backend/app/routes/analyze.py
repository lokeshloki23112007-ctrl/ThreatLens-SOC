import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.email_parser import parse_email
from app.services.domain_analyzer import analyze_domain
from app.services.authentication import analyze_authentication
from app.services.url_analyzer import analyze_url
from app.services.content_analyzer import analyze_content
from app.services.risk_engine import calculate_risk
from app.services.explanation import generate_explanation
from app.services.campaign import detect_campaign
from app.services.blast_radius import calculate_blast_radius
from app.services.soc_priority import calculate_priority

from app.database.incident_repository import create_incident


router = APIRouter()


# ============================================================
# REQUEST MODEL
# ============================================================

class AnalyzeRequest(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str = ""
    url: str = ""


# ============================================================
# ANALYZE THREAT
# ============================================================

@router.post("/analyze")
def analyze_threat(request: AnalyzeRequest):

    # --------------------------------------------------------
    # 1. PARSE EMAIL
    # --------------------------------------------------------

    parsed = parse_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body
    )

    urls = parsed["urls"]

    if request.url:
        urls.append(request.url)


    # --------------------------------------------------------
    # 2. DOMAIN ANALYSIS
    # --------------------------------------------------------

    domain_result = analyze_domain(
        parsed["domain"]
    )


    # --------------------------------------------------------
    # 3. EMAIL AUTHENTICATION
    # --------------------------------------------------------

    authentication_result = analyze_authentication(
        parsed["domain"]
    )


    # --------------------------------------------------------
    # 4. URL ANALYSIS
    # --------------------------------------------------------

    url_results = [
        analyze_url(url)
        for url in urls
    ]


    # --------------------------------------------------------
    # 5. SELECT STRONGEST URL SIGNAL
    # --------------------------------------------------------

    if url_results:

        strongest_url = max(
            url_results,
            key=lambda x: x["risk_score"]
        )

    else:

        strongest_url = {
            "risk_score": 0,
            "signals": []
        }


    # --------------------------------------------------------
    # 6. CONTENT ANALYSIS
    # --------------------------------------------------------

    content_result = analyze_content(
        parsed["subject"],
        parsed["body"]
    )


    # --------------------------------------------------------
    # 7. RISK ENGINE
    # --------------------------------------------------------

    risk = calculate_risk(
        domain_result,
        strongest_url,
        content_result
    )


    # --------------------------------------------------------
    # 8. EXPLAINABLE VERDICT
    # --------------------------------------------------------

    explanations = generate_explanation(
        domain_result,
        strongest_url,
        content_result
    )


    # --------------------------------------------------------
    # 9. CAMPAIGN DETECTION
    # --------------------------------------------------------

    campaign = detect_campaign(
        parsed,
        risk["risk_score"]
    )


    # --------------------------------------------------------
    # 10. BLAST RADIUS
    # --------------------------------------------------------

    blast_radius = calculate_blast_radius(
        risk["risk_score"],
        campaign["is_campaign"]
    )


    # --------------------------------------------------------
    # 11. SOC PRIORITY
    # --------------------------------------------------------

    priority = calculate_priority(
        risk["risk_score"],
        blast_radius,
        campaign
    )


    # --------------------------------------------------------
    # 12. SAVE INCIDENT TO POSTGRESQL
    # --------------------------------------------------------

    incident_id = (
        f"TL-{uuid.uuid4().hex[:8].upper()}"
    )
    print(">>> CREATING INCIDENT:", incident_id)
    create_incident(
        incident_id=incident_id,
        title=(
            parsed["subject"]
            or "Suspicious Email"
        ),
        severity=priority["priority_level"],
        status="OPEN"
    )


    # --------------------------------------------------------
    # 13. RETURN COMPLETE RESULT
    # --------------------------------------------------------

    return {

        "incident_id": incident_id,

        "classification": risk["classification"],

        "risk_score": risk["risk_score"],

        "confidence": risk["confidence"],

        "parsed_email": parsed,

        "signals": {

            "domain": domain_result["signals"],

            "url": strongest_url["signals"],

            "content": content_result["signals"]

        },

        "explanation": explanations,

        "authentication": authentication_result,

        "campaign": campaign,

        "blast_radius": blast_radius,

        "priority": priority

    }