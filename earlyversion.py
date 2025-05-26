#!/usr/bin/env python3

import requests
import sys
import json
import os
import time
from fpdf import FPDF

# === CONFIG ===
USER_AGENT = "KeysGuardReconEngine/0.2"
TIMEOUT = 10
API_ENABLED = True
API_ENDPOINT = "https://your-api-endpoint.com/submit"
AUTH_HEADERS = {
    "Authorization": "Bearer example-token"
}
COMMON_PATHS = ["admin", "login", "dashboard", "api", "config", ".env"]
SUBDOMAIN_WORDLIST = ["test", "dev", "api", "www", "admin"]
OUTPUT_DIR = "reports"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection"
]

BANNER = r"""
  _  __                _____                      _             
 | |/ /   ___   _ __  |  ___|__  _ __ _ __   ___ | |_ ___  _ __ 
 | ' /   / _ \ | '__| | |_ / _ \| '__| '_ \ / _ \| __/ _ \| '__|
 | . \  | (_) || |    |  _| (_) | |  | | | | (_) | || (_) | |   
 |_|\_\  \___/ |_|    |_|  \___/|_|  |_| |_|\___/ \__\___/|_|   
                                                                
   🔐 KeysGuard Recon Engine v0.2 — Full Recon w/ API + Reports
"""

# === FUNCTIONS ===

def extract_title(html):
    try:
        start = html.lower().find("<title>")
        end = html.lower().find("</title>")
        if start != -1 and end != -1:
            return html[start + 7:end].strip()
    except:
        pass
    return "N/A"

def fetch_url_metadata(url):
    try:
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.text),
            "title": extract_title(response.text)
        }
    except Exception as e:
        return {"error": str(e)}

def check_security_headers(headers):
    report = {}
    for header in SECURITY_HEADERS:
        report[header] = header in headers
    return report

def fuzz_common_paths(url):
    found = []
    for path in COMMON_PATHS:
        test_url = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(test_url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
            if r.status_code < 400:
                found.append((test_url, r.status_code))
        except:
            continue
    return found

def enum_subdomains(base_domain):
    found = []
    for word in SUBDOMAIN_WORDLIST:
        subdomain = f"http://{word}.{base_domain}"
        try:
            r = requests.get(subdomain, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
            if r.status_code < 400:
                found.append((subdomain, r.status_code))
        except:
            continue
    return found

def generate_json_report(data, filename):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
        json.dump(data, f, indent=2)

def generate_pdf_report(data, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "KeysGuard Recon Report", ln=True, align="C")
    pdf.ln(10)

    for section, content in data.items():
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, section, ln=True)
        pdf.set_font("Arial", size=11)
        if isinstance(content, dict):
            for k, v in content.items():
                pdf.multi_cell(0, 10, f"{k}: {v}")
        elif isinstance(content, list):
            for item in content:
                pdf.multi_cell(0, 10, f"{item}")
        else:
            pdf.multi_cell(0, 10, str(content))
        pdf.ln(5)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    pdf.output(os.path.join(OUTPUT_DIR, filename))

def push_to_api(scan_result):
    if not API_ENABLED:
        return
    try:
        response = requests.post(API_ENDPOINT, headers=AUTH_HEADERS, json=scan_result, timeout=10)
        print(f"[API] Pushed scan to API. Status: {response.status_code}")
    except Exception as e:
        print(f"[API] Failed to send data: {e}")

def scan_target(url):
    print(f"\n[🔍] Scanning Target: {url}")
    result = {
        "Target": url,
        "Time": time.ctime()
    }

    meta = fetch_url_metadata(url)
    if "error" in meta:
        print(f"[!] Failed to retrieve metadata: {meta['error']}")
        return

    result["HTTP Metadata"] = meta
    print(f"[+] Status: {meta['status_code']} | Title: {meta['title']} | Size: {meta['content_length']} bytes")

    headers_check = check_security_headers(meta['headers'])
    result["Security Headers"] = headers_check
    for h, present in headers_check.items():
        print(f"  [{'+ ' if present else '- '}] {h}: {'Present' if present else 'Missing'}")

    found_paths = fuzz_common_paths(url)
    result["Fuzzed Paths"] = found_paths
    if found_paths:
        print("\n[+] Fuzzed Endpoints:")
        for u, s in found_paths:
            print(f"  [+] {u} [{s}]")

    base_domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    subdomains = enum_subdomains(base_domain)
    result["Subdomains Found"] = subdomains
    if subdomains:
        print("\n[+] Found Subdomains:")
        for s, c in subdomains:
            print(f"  [+] {s} [{c}]")

    # === EXPORTS ===
    base = base_domain.replace(".", "_")
    generate_json_report(result, f"{base}_scan.json")
    generate_pdf_report(result, f"{base}_scan.pdf")

    # === API PUSH ===
    push_to_api(result)

# === MAIN ===

def main():
    print(BANNER)
    if len(sys.argv) != 2:
        print("Usage: python keysguard_recon_extended.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    scan_target(target_url)

if __name__ == "__main__":
    main()
