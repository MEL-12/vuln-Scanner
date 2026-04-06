import argparse
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
from scanner import sqli, xss, headers

init(autoreset=True)

def print_finding(f):
    color = Fore.RED if f["severity"] == "HIGH" else (Fore.YELLOW if f["severity"] == "MEDIUM" else Fore.CYAN)
    print(f"  {color}[{f['severity']}]{Style.RESET_ALL} {f['type']}")
    if "param" in f:
        print(f"    Param   : {f['param']}")
    if "payload" in f:
        print(f"    Payload : {f['payload']}")
    if "header" in f:
        print(f"    Header  : {f['header']}")
    print(f"    URL     : {f['url']}")
    print()

def scan(url):
    print(f"\n{Fore.BLUE}[*] Starting scan: {url}{Style.RESET_ALL}\n")
    all_findings = []

    # Extract query parameters from URL
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    if not params:
        params = ["q", "id", "search", "query"]  # common defaults
        print(f"[i] No params found in URL. Testing defaults: {params}")

    # SQLi checks
    print(f"{Fore.CYAN}[*] Running SQL Injection checks...{Style.RESET_ALL}")
    for param in params:
        all_findings += sqli.check(url, param)

    # XSS checks
    print(f"{Fore.CYAN}[*] Running XSS checks...{Style.RESET_ALL}")
    for param in params:
        all_findings += xss.check(url, param)

    # Header checks
    print(f"{Fore.CYAN}[*] Checking security headers...{Style.RESET_ALL}\n")
    all_findings += headers.check(url)

    # Results
    if all_findings:
        print(f"{Fore.RED}[!] {len(all_findings)} finding(s) detected:\n{Style.RESET_ALL}")
        for f in all_findings:
            print_finding(f)
    else:
        print(f"{Fore.GREEN}[+] No vulnerabilities detected.{Style.RESET_ALL}\n")

    return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g. https://example.com?q=test)")
    args = parser.parse_args()
    scan(args.url)