import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "VulnScanner/1.0 (educational)"})

def get(url, params=None, timeout=10):
    try:
        return SESSION.get(url, params=params, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None
