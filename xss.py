import requests
from urllib.parse import urlparse, urlencode, parse_qs
from colorama import Fore, init

# Inisialisasi colorama untuk mendukung pewarnaan teks di terminal
init(autoreset=True)

def send_request(url, method="GET", data=None, headers=None):
    """
    Mengirimkan HTTP request ke URL dan mengembalikan respons.
    """
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == "POST":
            response = requests.post(url, data=data, headers=headers, timeout=10)
        else:
            print(f"[ERROR] Unsupported method: {method}")
            return None
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None

def test_xss(url, payloads, output_file=None):
    """
    Menguji kerentanan XSS pada URL menggunakan daftar payload.
    """
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
        for payload in payloads:
            # Ubah parameter dengan payload
            modified_params = {**params, param_name: [payload]}  # Ganti nilai parameter dengan payload
            query_string = urlencode(modified_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            print(f"[TESTING] URL: {test_url}")

            # Kirim permintaan
            response = send_request(test_url)
                
            # Periksa apakah payload ada dalam response dan jika ada, apakah payload dijalankan
            if response and payload in response.text:
                result = f"{Fore.RED}[VULNERABLE] Parameter '{param_name}' executed payload: {payload}{Fore.RESET}"
                print(result)
                results.append(result)
            else:
                result = f"{Fore.GREEN}[SAFE] Parameter '{param_name}' did not execute payload: {payload}{Fore.RESET}"
                print(result)

    # Simpan hasil ke file jika diperlukan
    if output_file:
        with open(output_file, 'a') as file:
            file.write("\n".join(results) + "\n")
        print(f"\n[INFO] Results saved to: {output_file}")

def get_payloads():
    """
    Mengambil payload dari input pengguna atau file eksternal.
    """
    mode = input("Choose payload input mode: (1) Input payload manually, (2) Load from file: ").strip()
    
    if mode == "1":
        payloads = []
        print("Enter payloads, one per line (type 'done' when finished):")
        while True:
            payload = input("Payload: ").strip()
            if payload.lower() == "done":
                break
            payloads.append(payload)
        return payloads
    
    elif mode == "2":
        file_path = input("Enter the path to the file containing payloads: ").strip()
        try:
            with open(file_path, 'r') as file:
                payloads = [line.strip() for line in file if line.strip()]
            return payloads
        except FileNotFoundError:
            print("[ERROR] File not found! Exiting.")
            return []
    else:
        print("[ERROR] Invalid choice! Exiting.")
        return []

def main():
    print("=== Lightweight XSS Testing Tool ===")

    # Pilih mode input URL
    mode = input("Choose mode: (1) Single URL, (2) File with multiple URLs: ").strip()
    if mode == "1":
        full_url = input("Enter the full URL with parameters (e.g., https://example.com/search?q=test): ").strip()
        urls = [full_url]
    elif mode == "2":
        file_path = input("Enter the path to the file containing URLs: ").strip()
        try:
            with open(file_path, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("[ERROR] File not found! Exiting.")
            return
    else:
        print("[ERROR] Invalid choice! Exiting.")
        return

    # Pilih output mode
    output_mode = input("Output mode: (1) Display in terminal, (2) Save to file: ").strip()
    if output_mode == "2":
        output_log = input("Enter the output log file name (e.g., xss_results.txt): ").strip()
    else:
        output_log = None

    # Ambil payload dari input pengguna
    payloads = get_payloads()
    if not payloads:
        print("[ERROR] No payloads to test. Exiting.")
        return

    # Lakukan pengujian untuk setiap URL
    for url in urls:
        test_xss(url, payloads, output_file=output_log)

if __name__ == "__main__":
    main()
