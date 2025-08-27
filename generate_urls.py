# generate_urls.py
base_url = "http://localhost/vulnerabilities/xss_r/?name=test"

with open("urls_100.txt", "w") as f:
    for i in range(1, 101):
        f.write(f"{base_url}&id={i}\n")

print("File 'urls_100.txt' dengan 100 URL berhasil dibuat.")