import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from fpdf import FPDF
import os

# CONFIG
ZAP_API_URL = "http://localhost:8080"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/your_webhook_here"
REPORT_API = "http://localhost:5000/api/report"
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

def fetch_headers(url):
    try:
        resp = requests.get(url, timeout=10)
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
        "Content-Security-Policy", 
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]
    return [h for h in expected if h not in headers]

def fuzz_common_endpoints(base_url):
    paths = ["admin", "login", "dashboard", "api"]
    valid = []
    for path in paths:
        test_url = urljoin(base_url + "/", path)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200:
                valid.append(test_url)
        except:
            pass
    return valid

def detect_waf(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        waf_signatures = {
            "cloudflare": "cf-ray" in headers or "cloudflare" in headers.get("Server", "").lower(),
            "akamai": "akamai" in headers.get("Server", "").lower(),
            "sucuri": "sucuri" in headers.get("Server", "").lower(),
            "imperva": "incapsula" in headers.get("Set-Cookie", "").lower()
        }
        found = [k.capitalize() for k, v in waf_signatures.items() if v]
        return found if found else ["None detected"]
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
        message = f"🧠 **KEYSGUARD SCAN**\nTarget: {data['target']}\nTitle: {data['title']}\nWAF: {', '.join(data['waf'])}\nMissing Headers: {', '.join(data['missing_headers'])}\nEndpoints: {', '.join(data['valid_endpoints'])}"
        requests.post(DISCORD_WEBHOOK, json={"content": message})
        print("[+] Fallback report sent to Discord.")
    except:
        print("[❌] Discord fallback failed too.")

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

def main(target):
    print(ascii_banner)
    print(f"[🔍] Scanning Target: {target}")

    info = fetch_headers(target)
    if "error" in info:
        print(f"[!] Failed to fetch: {info['error']}")
        return

    print(f"[+] Status: {info['status_code']} | Title: {info['title']} | Size: {info['size']} bytes")
    missing = scan_missing_headers(info['headers'])
    for h in missing:
        print(f"  [- ] {h}: Missing")

    endpoints = fuzz_common_endpoints(target)
    if endpoints:
        print("\n[+] Fuzzed Endpoints:")
        for e in endpoints:
            print(f"  [+] {e}")

    waf = detect_waf(target)
    print(f"\n[🛡️] WAF/CDN Detection: {', '.join(waf)}")

    run_zap_active_scan(target)

    report = {
        "target": target,
        "title": info["title"],
        "status_code": info["status_code"],
        "size": info["size"],
        "missing_headers": missing,
        "valid_endpoints": endpoints,
        "waf": waf
    }

    generate_pdf_report(report)
    report_data(report)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python keysguard.py <URL>")
    else:
        main(sys.argv[1])
