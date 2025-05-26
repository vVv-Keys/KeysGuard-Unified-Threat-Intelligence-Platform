# Keysguard Recon Engine v3
# Features: Header Analysis, Endpoint Fuzzing, WAF Detection, ZAP Integration, PDF + JSON Reporting, CVE Matching, Login Support

import requests
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from fpdf import FPDF
import os
from pathlib import Path

ZAP_API_URL = "http://localhost:8080"
REPORT_API = "http://localhost:5000/api/report"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/your_webhook_here"
MAX_RETRIES = 3

ascii_banner = """
K E Y S G U A R D   R E C O N   E N G I N E
  *     *   *   *     * *       *   * *   *
*             *     *     * *     *     *
    * *   *                                   
            *                                 
*     *                                       
                        *                    
          *     *                             
  *                   *     *   * *     * *
                          *
        *                           *    
    *
              *     *                 *    
"""

def load_auth_config():
    config_path = Path("auth_config.json")
    if config_path.exists():
        with open(config_path) as f:
            return json.load(f)
    return None

def perform_login(session, config):
    print("[🔐] Attempting login...")
    login_url = config["login_url"]
    data = {
        config["username_field"]: config["credentials"]["username"],
        config["password_field"]: config["credentials"]["password"]
    }
    resp = session.post(login_url, data=data)
    if resp.status_code == 200:
        print("[✓] Login successful.")
        if config["auth_type"] == "bearer":
            token = resp.json().get(config["auth_token_field"])
            session.headers.update({config["token_header"]: f"Bearer {token}"})
            print("[→] Bearer token attached.")
        return True
    else:
        print(f"[!] Login failed: Status {resp.status_code}")
        return False

def fetch_headers(url, session):
    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        return {
            "status_code": resp.status_code,
            "title": soup.title.string.strip() if soup.title else "N/A",
            "size": len(resp.content),
            "headers": resp.headers
        }
    except Exception as e:
        return {"error": str(e)}

def scan_missing_headers(headers):
    expected = [
        "Content-Security-Policy", "Strict-Transport-Security",
        "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"
    ]
    return [h for h in expected if h not in headers]

def fuzz_common_endpoints(base_url, session):
    paths = ["admin", "login", "dashboard", "api"]
    valid = []
    for path in paths:
        test_url = urljoin(base_url + "/", path)
        try:
            r = session.get(test_url, timeout=5)
            if r.status_code == 200:
                valid.append(test_url)
        except:
            pass
    return valid

def detect_waf(url, session):
    try:
        r = session.get(url, timeout=5)
        headers = r.headers
        waf_signatures = {
            "cloudflare": "cf-ray" in headers or "cloudflare" in headers.get("Server", "").lower(),
            "akamai": "akamai" in headers.get("Server", "").lower(),
            "sucuri": "sucuri" in headers.get("Server", "").lower(),
            "imperva": "incapsula" in headers.get("Set-Cookie", "").lower()
        }
        return [k.capitalize() for k, v in waf_signatures.items() if v] or ["None detected"]
    except:
        return ["Unknown (scan failed)"]

def run_zap_active_scan(target):
    print(f"\n[⚡] Running ZAP Active Scan on: {target}")
    try:
        start_scan = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/?url={target}&recurse=true")
        scan_id = start_scan.json().get("scan")
        if not scan_id:
            print("[!] Failed to start scan.")
            return
        while True:
            status = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/?scanId={scan_id}").json()
            progress = int(status.get("status", 0))
            print(f"    [*] Scan Progress: {progress}%")
            if progress >= 100:
                break
            time.sleep(3)
        print("[✓] ZAP Scan Complete.")
    except Exception as e:
        print(f"[!] ZAP Scan error: {e}")

def cve_pattern_check(endpoints):
    known_patterns = {
        "/admin": "CVE-2022-1388 (F5 BIG-IP iControl REST RCE)",
        "/api": "CVE-2023-34362 (MOVEit Transfer SQLi)",
        "/dashboard": "CVE-2021-22986 (F5 BIG-IP Dashboard RCE)",
        "/login": "CVE-2019-11510 (Pulse Secure Arbitrary File Read)"
    }
    matches = []
    for ep in endpoints:
        for pattern, cve in known_patterns.items():
            if ep.endswith(pattern):
                matches.append({"endpoint": ep, "cve": cve})
    return matches

def generate_pdf_report(data):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_{timestamp}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "KeysGuard Recon Report", ln=True, align="C")
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Scan Time: {timestamp}", ln=True)
    pdf.cell(200, 10, f"Target: {data['target']}", ln=True)
    pdf.cell(200, 10, f"Title: {data['title']}", ln=True)
    pdf.cell(200, 10, f"Status: {data['status_code']} | Size: {data['size']} bytes", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Missing Headers:", ln=True)
    pdf.set_font("Arial", size=12)
    for h in data["missing_headers"]:
        pdf.cell(200, 10, f"- {h}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Detected Endpoints:", ln=True)
    pdf.set_font("Arial", size=12)
    for ep in data["valid_endpoints"]:
        pdf.cell(200, 10, f"- {ep}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "WAF/CDN Detection:", ln=True)
    pdf.set_font("Arial", size=12)
    for w in data["waf"]:
        pdf.cell(200, 10, f"- {w}", ln=True)
    pdf.output(filename)
    print(f"[📄] PDF report saved to: {filename}")

def write_json_report(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[🧾] JSON report saved to: {filename}")

def report_data(payload):
    for attempt in range(MAX_RETRIES):
        try:
            res = requests.post(REPORT_API, json=payload, timeout=5)
            if res.status_code == 200:
                print("[+] Successfully reported to API.")
                return
        except:
            print(f"[!] API attempt {attempt + 1} failed.")
            time.sleep(2)
    print("[⚠️] API unreachable. Sending to Discord instead.")
    discord_fallback(payload)

def discord_fallback(data):
    try:
        msg = f"🔐 Scan Complete for: {data['target']}\nHeaders Missing: {', '.join(data['missing_headers'])}\nEndpoints: {', '.join(data['valid_endpoints'])}"
        requests.post(DISCORD_WEBHOOK, json={"content": msg})
        print("[+] Fallback report sent to Discord.")
    except:
        print("[❌] Discord fallback failed.")

def main(target):
    print(ascii_banner)
    print(f"[🔍] Scanning Target: {target}")
    session = requests.Session()
    auth_config = load_auth_config()
    if auth_config:
        if not perform_login(session, auth_config):
            print("[!] Exiting: Login failed.")
            return
    info = fetch_headers(target, session)
    if "error" in info:
        print(f"[!] Failed to fetch: {info['error']}")
        return
    print(f"[+] Status: {info['status_code']} | Title: {info['title']} | Size: {info['size']} bytes")
    missing = scan_missing_headers(info['headers'])
    for h in missing:
        print(f"  [- ] {h}: Missing")
    endpoints = fuzz_common_endpoints(target, session)
    if endpoints:
        print("\n[+] Fuzzed Endpoints:")
        for e in endpoints:
            print(f"  [+] {e}")
    waf = detect_waf(target, session)
    print(f"\n[🛡️] WAF/CDN Detection: {', '.join(waf)}")
    run_zap_active_scan(target)
    cves = cve_pattern_check(endpoints)
    if cves:
        print("\n[🚨] CVE-Linked Endpoints Found:")
        for cve in cves:
            print(f"  [!] {cve['endpoint']} => {cve['cve']}")
    report = {
        "target": target,
        "title": info["title"],
        "status_code": info["status_code"],
        "size": info["size"],
        "missing_headers": missing,
        "valid_endpoints": endpoints,
        "waf": waf,
        "cves": cves
    }
    generate_pdf_report(report)
    write_json_report(report)
    report_data(report)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python keysguard.py <URL>")
    else:
        main(sys.argv[1])
