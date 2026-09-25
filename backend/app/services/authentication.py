import dns.resolver


# ==========================================================
# DNS TXT RECORD HELPER
# ==========================================================

def get_txt_records(domain: str) -> list:
    """
    Fetch TXT records from DNS.
    """

    records = dns.resolver.resolve(
        domain,
        "TXT",
        lifetime=5
    )

    txt_records = []

    for record in records:
        parts = []

        for value in record.strings:
            if isinstance(value, bytes):
                parts.append(
                    value.decode("utf-8", errors="ignore")
                )
            else:
                parts.append(str(value))

        txt_records.append("".join(parts))

    return txt_records


# ==========================================================
# SPF
# ==========================================================

def check_spf(domain: str) -> dict:

    try:

        txt_records = get_txt_records(domain)

        spf_records = [
            record
            for record in txt_records
            if record.lower().startswith("v=spf1")
        ]

        if spf_records:

            return {
                "status": "FOUND",
                "record": spf_records[0],
                "message": "SPF record found"
            }

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "No SPF record found"
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "Domain does not exist"
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "No TXT record found"
        }

    except dns.resolver.LifetimeTimeout:

        return {
            "status": "ERROR",
            "record": None,
            "message": "DNS lookup timed out"
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "record": None,
            "message": str(error)
        }


# ==========================================================
# DMARC
# ==========================================================

def check_dmarc(domain: str) -> dict:

    try:

        dmarc_domain = f"_dmarc.{domain}"

        txt_records = get_txt_records(dmarc_domain)

        dmarc_records = [
            record
            for record in txt_records
            if record.lower().startswith("v=dmarc1")
        ]

        if dmarc_records:

            return {
                "status": "FOUND",
                "record": dmarc_records[0],
                "message": "DMARC record found"
            }

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "No DMARC record found"
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "No DMARC record found"
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "NOT_FOUND",
            "record": None,
            "message": "No DMARC record found"
        }

    except dns.resolver.LifetimeTimeout:

        return {
            "status": "ERROR",
            "record": None,
            "message": "DNS lookup timed out"
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "record": None,
            "message": str(error)
        }


# ==========================================================
# DKIM
# ==========================================================

def check_dkim(domain: str, selector: str | None = None) -> dict:

    # ------------------------------------------------------
    # DKIM selector is required
    # ------------------------------------------------------

    if not selector:

        return {
            "status": "NOT_CHECKED",
            "selector": None,
            "record": None,
            "message": "DKIM selector not available"
        }

    try:

        dkim_domain = (
            f"{selector}._domainkey.{domain}"
        )

        txt_records = get_txt_records(dkim_domain)

        dkim_records = [
            record
            for record in txt_records
            if (
                record.lower().startswith("v=dkim1")
                or "p=" in record.lower()
            )
        ]

        if dkim_records:

            return {
                "status": "FOUND",
                "selector": selector,
                "record": dkim_records[0],
                "message": "DKIM record found"
            }

        return {
            "status": "NOT_FOUND",
            "selector": selector,
            "record": None,
            "message": "No DKIM record found"
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "NOT_FOUND",
            "selector": selector,
            "record": None,
            "message": "DKIM record does not exist"
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "NOT_FOUND",
            "selector": selector,
            "record": None,
            "message": "No DKIM TXT record found"
        }

    except dns.resolver.LifetimeTimeout:

        return {
            "status": "ERROR",
            "selector": selector,
            "record": None,
            "message": "DKIM DNS lookup timed out"
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "selector": selector,
            "record": None,
            "message": str(error)
        }


# ==========================================================
# MX
# ==========================================================

def check_mx(domain: str) -> dict:

    try:

        records = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=5
        )

        mx_records = []

        for record in records:

            mx_records.append(
                str(record.exchange).rstrip(".")
            )

        if mx_records:

            return {
                "status": "FOUND",
                "records": mx_records,
                "message": "MX records found"
            }

        return {
            "status": "NOT_FOUND",
            "records": [],
            "message": "No MX records found"
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "NOT_FOUND",
            "records": [],
            "message": "Domain does not exist"
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "NOT_FOUND",
            "records": [],
            "message": "No MX record found"
        }

    except dns.resolver.LifetimeTimeout:

        return {
            "status": "ERROR",
            "records": [],
            "message": "DNS lookup timed out"
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "records": [],
            "message": str(error)
        }


# ==========================================================
# COMPLETE AUTHENTICATION ANALYSIS
# ==========================================================

def analyze_authentication(
    domain: str,
    dkim_selector: str | None = None
) -> dict:

    # ------------------------------------------------------
    # LIVE DNS LOOKUPS
    # ------------------------------------------------------

    spf = check_spf(domain)

    dmarc = check_dmarc(domain)

    dkim = check_dkim(
        domain,
        dkim_selector
    )

    mx = check_mx(domain)

    # ------------------------------------------------------
    # SECURITY SIGNALS
    # ------------------------------------------------------

    signals = []

    if spf["status"] == "NOT_FOUND":

        signals.append(
            "SPF record missing"
        )

    if dmarc["status"] == "NOT_FOUND":

        signals.append(
            "DMARC record missing"
        )

    if dkim["status"] == "NOT_FOUND":

        signals.append(
            "DKIM record missing"
        )

    if mx["status"] == "NOT_FOUND":

        signals.append(
            "MX record missing"
        )

    # ------------------------------------------------------
    # FINAL RESPONSE
    # ------------------------------------------------------

    return {

        "domain": domain,

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc,

        "mx": mx,

        "signals": signals
    }