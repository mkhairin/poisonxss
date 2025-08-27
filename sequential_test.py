# sequential_test.py (Versi Modifikasi)
import requests
import time
import sys

if len(sys.argv) < 2:
    print("Gunakan: python sequential_test.py <nama_file_urls>")
    sys.exit()

# --- Konfigurasi ---
payload_file = "payload.txt"  # File payload
headers = {
    # Ganti dengan cookie sesi DVWA  yang valid
    "Cookie": "tk_ai=zvUI3YdtGrZg7ieVaz%2B%2BV%2FNs; customify_wc_pl_view_mod=grid; _ga=GA1.1.1990850535.1732167692; PHPSESSID=5rvjl5tp22bpt7h8124en9cpi7; security=low"

}
# ------------------

# Baca daftar URL dari file yang diberikan di argumen
url_file = sys.argv[1]
with open(url_file, 'r') as f:
    urls = [line.strip() for line in f]

# Baca payloads
with open(payload_file, 'r') as f:
    payloads = [line.strip() for line in f if line.strip()]

print(f"Memulai pengujian sekuensial untuk {len(urls)} URL...")
start_time = time.time()

# Loop untuk setiap URL
for base_url in urls:
    # Loop untuk setiap payload
    for payload in payloads:
        try:
            # Ganti 'test' di parameter 'name' dengan payload
            test_url = base_url.replace("name=test", f"name={payload}")
            requests.get(test_url, headers=headers, timeout=15)
        except requests.RequestException:
            # Abaikan error koneksi untuk pengukuran waktu
            pass

end_time = time.time()
duration = end_time - start_time
print(f"\nPengujian sekuensial selesai.")
print(f"Total waktu: {duration:.2f} detik")
