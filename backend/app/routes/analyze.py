from fastapi import APIRouter
from pydantic import BaseModel

from app.services.email_parser import parse_email
from app.services.domain_analyzer import analyze_domain
from app.services.url_analyzer import analyze_url
from app.services.content_analyzer import analyze_content
from app.services.risk_engine import calculate_risk
from app.services.explanation import generate_explanation
from app.services.campaign import detect_campaign
from app.services.blast_radius import calculate_blast_radius
from app.services.soc_priority import calculate_priority

router = APIRouter()


class AnalyzeRequest(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str = ""
    url: str = ""


@router.post("/analyze")
def analyze_threat(request: AnalyzeRequest):

    parsed = parse_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body
    )

    urls = parsed["urls"]

    if request.url:
        urls.append(request.url)

    domain_result = analyze_domain(
        parsed["domain"]
    )

    url_results = [
        analyze_url(url)
        for url in urls
    ]

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

    content_result = analyze_content(
        parsed["subject"],
        parsed["body"]
    )

    risk = calculate_risk(
        domain_result,
        strongest_url,
        content_result
    )

    explanations = generate_explanation(
        domain_result,
        strongest_url,
        content_result
    )

    campaign = detect_campaign(
        parsed,
        risk["risk_score"]
    )

    blast_radius = calculate_blast_radius(
        risk["risk_score"],
        campaign["is_campaign"]
    )

    priority = calculate_priority(
        risk["risk_score"],
        blast_radius,
        campaign
    )

    return {
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

        "authentication": {
            "spf": "DEMO SIGNAL",
            "dkim": "DEMO SIGNAL",
            "dmarc": "DEMO SIGNAL"
        },

        "campaign": campaign,

        "blast_radius": blast_radius,

        "priority": priority
    }