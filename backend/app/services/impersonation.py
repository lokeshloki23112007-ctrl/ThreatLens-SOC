def detect_impersonation(sender: str, domain: str):
    return {"source": "impersonation", "sender": sender, "domain": domain}
