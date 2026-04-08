cat > README.md << 'EOF'
# VulnScanner

A Python-based web vulnerability scanner that detects common web security issues including SQL Injection, Cross-Site Scripting (XSS), and missing HTTP security headers.


## Legal Notice
Only scan targets you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions.


## Features
- SQL Injection detection via error-based payloads
- Reflected XSS detection
- HTTP security headers audit
- Colorized terminal output
- Modular and extensible scanner architecture


## Steps Taken to Build This Project

### Step 1 — Project Setup
- Created the project folder `vuln-scanner/` with a `scanner/` subdirectory
- Set up a Python virtual environment to isolate dependencies

### Step 2 — Installed Dependencies
```bash
pip install requests beautifulsoup4 colorama
```

### Step 3 — Built the Scanner Modules
- **utils.py** — Shared `requests.Session` for all HTTP calls with a custom User-Agent
- **sqli.py** — Injects common SQL payloads into URL parameters and checks responses for database error signatures
- **xss.py** — Injects XSS payloads and checks if they are reflected unescaped in the HTML response
- **headers.py** — Fetches the target URL and checks for the presence of critical HTTP security headers

### Step 4 — Built the Entry Point
- **main.py** — Parses the target URL, extracts query parameters, runs all checks, and prints color-coded findings to the terminal

### Step 5 — Tested the Scanner
- Ran the scanner against `https://demo.testfire.net/search?q=test`
- Detected 6 real vulnerabilities including a missing Content-Security-Policy (HIGH), missing X-Frame-Options and HSTS (MEDIUM), and 3 missing hardening headers (LOW)

### Step 6 — Pushed to GitHub
- Initialized a Git repository with `git init`
- Committed all files and pushed to GitHub


## Installation

```bash
git clone https://github.com/YOUR_USERNAME/vuln-scanner.git
cd vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Usage

```bash
python main.py "https://example.com/search?q=test"
```

### Example Output