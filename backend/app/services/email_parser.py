import re
from email.parser import Parser
from email.utils import parseaddr


def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"
    return re.findall(pattern, text)


def extract_domain(email_address: str) -> str:
    """Extract domain from an email address."""
    if not email_address or "@" not in email_address:
        return ""

    return email_address.split("@")[-1].strip().lower()


def parse_email(
    sender: str = "",
    subject: str = "",
    body: str = ""
) -> dict:
    """
    Convert raw email fields into structured ThreatLens data.
    """

    sender_name, sender_email = parseaddr(sender)

    if not sender_email:
        sender_email = sender.strip()

    domain = extract_domain(sender_email)

    urls = extract_urls(body)

    return {
        "sender": sender_email,
        "sender_name": sender_name,
        "domain": domain,
        "subject": subject.strip(),
        "body": body.strip(),
        "urls": urls,
        "url_count": len(urls)
    }


def parse_eml(raw_email: str) -> dict:
    """Parse a complete .eml file."""

    message = Parser().parsestr(raw_email)

    sender = message.get("From", "")
    subject = message.get("Subject", "")

    body = ""

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)

                if payload:
                    body = payload.decode(
                        part.get_content_charset() or "utf-8",
                        errors="ignore"
                    )
                    break
    else:
        payload = message.get_payload(decode=True)

        if payload:
            body = payload.decode(
                message.get_content_charset() or "utf-8",
                errors="ignore"
            )
        else:
            body = str(message.get_payload())

    return parse_email(
        sender=sender,
        subject=subject,
        body=body
    )