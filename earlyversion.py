import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import socket

# CONFIG
ZAP_API_URL = "http://localhost:8080"  # Change if running OWASP ZAP elsewhere
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/your_webhook_url_here"
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

    report = {
        "target": target,
        "title": info["title"],
        "status_code": info["status_code"],
        "size": info["size"],
        "missing_headers": missing,
        "valid_endpoints": endpoints,
        "waf": waf
    }

    report_data(report)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python keysguard.py <URL>")
    else:
        main(sys.argv[1])
