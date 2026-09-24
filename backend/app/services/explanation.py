def generate_explanation(domain_result, url_result, content_result):
    explanations = []

    for signal in domain_result.get("signals", []):
        explanations.append(signal["explanation"])

    for signal in url_result.get("signals", []):
        explanations.append(signal["explanation"])

    for signal in content_result.get("signals", []):
        explanations.append(signal["explanation"])

    if not explanations:
        explanations.append(
            "No major phishing indicators were detected."
        )

    return explanations