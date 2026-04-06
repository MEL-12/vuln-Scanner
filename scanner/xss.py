from .utils import get
import html

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(document.cookie)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

def check(url, param):
    findings = []
    for payload in PAYLOADS:
        resp = get(url, params={param: payload})
        if resp is None:
            continue
        if payload in resp.text and html.escape(payload) not in resp.text:
            findings.append({
                "type": "Reflected XSS",
                "severity": "HIGH",
                "param": param,
                "payload": payload,
                "url": url,
            })
            break
    return findings
