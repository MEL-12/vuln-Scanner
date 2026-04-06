from .utils import get

REQUIRED_HEADERS = {
    "Content-Security-Policy": "HIGH",
    "X-Frame-Options": "MEDIUM",
    "Strict-Transport-Security": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}

def check(url):
    findings = []
    resp = get(url)
    if resp is None:
        return findings
    for header, sev in REQUIRED_HEADERS.items():
        if header.lower() not in [k.lower() for k in resp.headers]:
            findings.append({
                "type": "Missing Security Header",
                "severity": sev,
                "header": header,
                "url": url,
            })
    return findings
