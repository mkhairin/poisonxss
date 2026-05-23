#
# PoisonXSS - Version 2.9
# The Accuracy & Scope Update: Selenium Verification and POST Method Testing.
#

import argparse
import asyncio
import os
import aiohttp
import json
from urllib.parse import urlparse, urlencode, parse_qs, unquote, quote, urljoin
from colorama import Fore, init, Style
from datetime import datetime
import sys
import random
import re
import time

try:
    from bs4 import BeautifulSoup
except ImportError:
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] BeautifulSoup4 is not installed. Please run 'pip install beautifulsoup4 lxml'")
    sys.exit()
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, WebDriverException
except ImportError:
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Selenium is not installed. Please run 'pip install selenium'")
    sys.exit()

# --- Version Configuration & Default Payloads ---
__version__ = "3.0"
# <-- File default yang akan dicari
DEFAULT_PAYLOAD_FILENAME = "xss_payloads.txt"
DEFAULT_HTMLI_FILENAME = "htmli_payloads.txt"
DEFAULT_HTMLI_PAYLOADS = ["<h1>HTMLi-Test</h1>", "<i>PoisonXSS</i>"]

# Daftar User-Agent Browser Populer untuk menipu WAF
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
]

# Initialize colorama
init(autoreset=True)


def show_help_syntax():
    """Displays a detailed help guide."""
    CYAN, GREEN, RESET, WIDTH = Fore.CYAN, Fore.GREEN, Style.RESET_ALL, 35

    print(f"\n{CYAN}PoisonXSS {__version__} - Help Guide{RESET}")
    print(f"Usage: python poisonxss.py [TARGET] [OPTIONS]\n")

    print(f"{GREEN}Options:{RESET}")
    print(
        f"  {"-h, --help-syntax".ljust(WIDTH)}Show this advanced help message and exit")
    print(f"  {"--version".ljust(WIDTH)}Show program's version number and exit")
    print(f"  {"-v, --verbose".ljust(WIDTH)}Verbosity level. Shows safe requests.\n")

    print(f"{GREEN}Target (Choose one):{RESET}")
    print(
        f"  {"-u URL, --url=URL".ljust(WIDTH)}Single starting URL for a scan or crawl")
    print(
        f"  {"-l FILE, --list=FILE".ljust(WIDTH)}File containing a list of URLs to test.\n")

    print(f"{GREEN}Payloads:{RESET}")
    print(
        f"  {"-p FILE, --payloads=FILE".ljust(WIDTH)}File with XSS payloads (default mode).")
    print(f"  {"--payloads-htmli=FILE".ljust(WIDTH)}File with HTML Injection payloads (for --htmli mode).\n")

    print(f"{GREEN}Accuracy:{RESET}")
    print(f"  {"--selenium".ljust(WIDTH)}Enable Selenium-based verification for max accuracy\n")

    print(f"{GREEN}Testing Mode:{RESET}")
    print(f"  {"--htmli".ljust(WIDTH)}Switch to HTML Injection testing mode\n")

    print(f"{GREEN}Crawler (Only with -u):{RESET}")
    print(f"  {"--crawl".ljust(WIDTH)}Enable the web crawler from the start URL")
    print(f"  {"--depth=DEPTH".ljust(WIDTH)}Maximum crawl depth (default: 2)\n")

    print(f"{GREEN}Intelligence:{RESET}")
    print(f"  {"--fingerprint".ljust(WIDTH)}Enable technology fingerprinting\n")

    print(f"{GREEN}Request & Authentication:{RESET}")
    print(
        f"  {"--cookie=COOKIE".ljust(WIDTH)}Cookie string for authenticated scanning")
    print(f"  {"-H HEADERS, --headers=HEADERS".ljust(WIDTH)}Custom headers, comma-separated (e.g. \"User-Agent: X\")")
    print(
        f"  {"--proxy=PROXY".ljust(WIDTH)}Use a proxy to connect to the target URL\n")

    print(f"{GREEN}Control:{RESET}")
    print(f"  {"--delay=DELAY".ljust(WIDTH)}Delay in seconds between each request")
    print(f"  {"-w WORKERS, --workers=NUM".ljust(WIDTH)}Number of concurrent workers (default: 50)")
    print(
        f"  {"-o OUTPUT, --output=FILE".ljust(WIDTH)}Save the scan report to a file")


async def verify_with_selenium(url, method='GET', post_data=None):
    """Verifies XSS using a real browser via Selenium (Supports GET & POST)."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--log-level=3")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])

    driver = None
    driver.get(url)  # atau execute script
    time.sleep(2)   # Tunggu 2 detik agar alert sempat muncul
    try:
        driver.switch_to.alert.accept()

        # Logika baru untuk POST request via DOM Manipulation
        if method == 'POST' and post_data:
            # 1. Buka halaman kosong untuk menyiapkan konteks eksekusi JS
            driver.get("about:blank")

            # 2. Serialize data ke format JSON agar aman dimasukkan ke string JS
            # Menggunakan json.dumps mencegah error syntax jika payload mengandung kutip/garis miring
            json_data = json.dumps(post_data)

            # 3. Script JS untuk membuat form virtual dan mensubmitnya
            script = f"""
                var url = "{url}";
                var postData = {json_data};
                
                var form = document.createElement("form");
                form.method = "POST";
                form.action = url;
                form.style.display = "none";
                
                for (var key in postData) {{
                    if (postData.hasOwnProperty(key)) {{
                        var hiddenField = document.createElement("input");
                        hiddenField.type = "hidden";
                        hiddenField.name = key;
                        hiddenField.value = postData[key];
                        form.appendChild(hiddenField);
                    }}
                }}
                
                document.body.appendChild(form);
                form.submit();
            """
            # Eksekusi script
            driver.execute_script(script)
        else:
            # Metode GET Biasa
            driver.get(url)

        # Tunggu alert muncul
        # (Selenium otomatis menunggu beberapa saat jika kita mengakses switch_to.alert)
        try:
            # Gunakan WebDriverWait jika ingin lebih presisi,
            # tapi try-except langsung pada alert cukup cepat untuk PoC
            driver.switch_to.alert.accept()
            return True
        except (NoAlertPresentException, WebDriverException):
            return False

    except UnexpectedAlertPresentException:
        # Terkadang alert muncul sebelum baris switch_to dijalankan
        return True
    except Exception:
        return False
    finally:
        if driver:
            driver.quit()


async def fingerprint_technology(session, url, headers, proxy):
    """Analyzes headers and content to identify server technology."""
    findings = []
    try:
        async with session.get(url, headers=headers, proxy=proxy, timeout=10) as response:
            server = response.headers.get('Server')
            if server:
                findings.append(f"Server: {server}")
            x_powered_by = response.headers.get('X-Powered-By')
            if x_powered_by:
                findings.append(f"Tech: {x_powered_by}")
            if "text/html" in response.headers.get('Content-Type', ''):
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'lxml')
                generator_tag = soup.find(
                    'meta', attrs={'name': re.compile(r'generator', re.I)})
                if generator_tag and generator_tag.get('content'):
                    findings.append(
                        f"Generator: {generator_tag.get('content')}")
    except Exception:
        return ["Could not perform fingerprinting."]
    return findings if findings else ["No specific technology identified."]


class PoisonXSS:
    def __init__(self, targets, payloads, test_type='XSS', headers=None, workers=50, proxy=None, verbose=False, delay=0, crawl=False, depth=2, fingerprint=False, use_selenium=False):
        self.targets = targets
        self.start_url = targets[0]
        self.base_payloads = payloads
        self.test_type = test_type
        self.headers = headers if headers is not None else {}
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = f"PoisonXSS/{__version__}"
        self.workers = workers
        self.results = []
        self.start_time = datetime.now()
        self.proxy = proxy
        self.verbose = verbose
        self.delay = delay
        self.crawl = crawl
        self.depth = depth
        self.scanned_urls_and_forms = set()
        self.fingerprint = fingerprint
        self.tech_findings = []
        self.use_selenium = use_selenium

    def _print_banner(self):
        print(r"""
                 _                                
    ____  ____  (_)________  ____  _  ____________
   / __ \/ __ \/ / ___/ __ \/ __ \| |/_/ ___/ ___/
  / /_/ / /_/ / (__  ) /_/ / / / />  <(__  |__  ) 
 / .___/\____/_/____/\____/_/ /_/_/|_/____/____/  
/_/                Created by Muhammad Khairin                                            
        """)
        print(
            f"{Fore.CYAN}PoisonXSS v{__version__} [Final]{Style.RESET_ALL} | The All-in-One XSS Scanner")
        print(
            f"[*] Testing Mode  : {Fore.MAGENTA}{self.test_type}{Style.RESET_ALL}")
        print(
            f"[*] Start Time    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Targets Loaded: {len(self.targets)}")
        print(f"[*] Base Payloads : {len(self.base_payloads)} loaded")
        if self.crawl:
            print(
                f"[*] Crawler Mode  : {Fore.GREEN}Enabled (Depth: {self.depth}){Style.RESET_ALL}")
        if self.use_selenium:
            print(
                f"[*] Accuracy Mode : {Fore.GREEN}Selenium Enabled{Style.RESET_ALL}")
        if self.fingerprint:
            print(f"[*] Fingerprint   : {Fore.GREEN}Enabled{Style.RESET_ALL}")
            if self.tech_findings:
                for finding in self.tech_findings:
                    print(f"[*]   - {Fore.YELLOW}{finding}{Style.RESET_ALL}")
        if self.proxy:
            print(f"[*] Proxy         : {self.proxy}")
        if 'Cookie' in self.headers:
            print(f"[*] Auth Cookie   : {Fore.GREEN}Provided{Style.RESET_ALL}")
        print(f"[*] Workers       : {self.workers}")
        print("-" * 50)

    async def _fetch_and_check(self, session, url, method, payload_info, data=None):
        param_name = payload_info['param_name']
        original_payload = payload_info['original_payload']
        is_vulnerable = False

        # Daftar tag di mana XSS tidak akan jalan meskipun payload tidak di-encode
        # Kecuali payload kita melakukan "break out" (menutup tag tersebut)
        SAFE_TAGS = ['title', 'textarea', 'code', 'pre', 'xmp', 'noscript']

        try:
            response_text = ""
            final_url = url

            # --- Melakukan Request ---
            # --- Melakukan Request dengan WAF Evasion Sederhana ---

            # 1. Rotasi User-Agent (WAF Evasion)
            # Kita copy headers bawaan agar tidak merusak object global
            current_headers = self.headers.copy()

            # Jika user tidak memaksa pakai User-Agent tertentu, kita acak setiap request
            if 'User-Agent' not in current_headers:
                current_headers['User-Agent'] = random.choice(USER_AGENTS)

            # 2. Tambahkan Fake Headers (Opsional - untuk terlihat seperti browser asli)
            current_headers['Accept-Language'] = 'en-US,en;q=0.9'
            current_headers['Connection'] = 'keep-alive'

            try:
                if method.upper() == 'POST':
                    # Gunakan current_headers yang baru
                    async with session.post(url, headers=current_headers, proxy=self.proxy, data=data, timeout=15) as response:
                        response_text = await response.text()
                else:  # GET
                    # Gunakan current_headers yang baru
                    async with session.get(url, headers=current_headers, proxy=self.proxy, timeout=15) as response:
                        response_text = await response.text()
                        final_url = str(response.url)
            except asyncio.TimeoutError:
                return  # Skip jika timeout
            except Exception:
                return  # Skip jika error koneksi

            # --- Logika Deteksi Baru yang Lebih Cerdas ---
            if original_payload in response_text:
                # 1. Cek apakah payload ini sebenarnya ter-encode HTML entities di sekitarnya?
                # Kita cek versi ter-encode dari payload
                encoded_lt = original_payload.replace(
                    "<", "&lt;").replace(">", "&gt;")
                encoded_hex = original_payload.replace(
                    "<", "&#x3C;").replace(">", "&#x3E;")

                # Jika yang ditemukan di text hanyalah versi ter-encode, maka aman (bukan XSS)
                if encoded_lt in response_text or encoded_hex in response_text:
                    # Double check: Pastikan versi RAW benar-benar ada, bukan cuma versi encoded
                    # Jika jumlah kemunculan RAW > jumlah kemunculan Encoded, kemungkinan ada yang lolos
                    if response_text.count(original_payload) <= (response_text.count(encoded_lt) + response_text.count(encoded_hex)):
                        is_vulnerable = False
                    else:
                        is_vulnerable = True
                else:
                    is_vulnerable = True

                # 2. Cek Konteks Tag (Untuk mengurangi False Positive)
                if is_vulnerable:
                    soup = BeautifulSoup(response_text, 'lxml')
                    # Cari semua text node yang mengandung payload
                    found_in_safe_tag = False

                    # Regex sederhana untuk cek apakah payload ada di dalam tag aman
                    # (Metode string finding sederhana lebih cepat daripada full DOM traversal untuk scan cepat)
                    for tag in SAFE_TAGS:
                        # Pola: <tag>...payload...</tag>
                        # Ini regex sederhana, tidak sempurna tapi cukup membantu memfilter sampah
                        pattern = re.compile(
                            f"<{tag}[^>]*>.*?{re.escape(original_payload)}.*?</{tag}>", re.DOTALL | re.IGNORECASE)
                        if pattern.search(response_text):
                            # Jika payload kita tidak mengandung penutup tag tersebut (misal: </title>)
                            # Maka XSS ini gagal.
                            if f"</{tag}>" not in original_payload:
                                found_in_safe_tag = True
                                break

                    if found_in_safe_tag:
                        if self.verbose:
                            print(
                                f"[{Fore.YELLOW}IGNORED{Style.RESET_ALL}] Payload found inside <{tag}> tag (Safe Context).")
                        is_vulnerable = False

               # --- LOGIKA REPORTING & VERIFICATION (FIXED FOR HTMLi) ---
                if is_vulnerable:
                    # Tampilkan info awal
                    if self.verbose:
                        print(
                            f"[{Fore.YELLOW}POTENTIAL{Style.RESET_ALL}] Reflected Payload found in {param_name}. Checking validity...")

                    selenium_verified = False

                    # 1. Jalankan Selenium (Hanya untuk XSS)
                    if self.use_selenium and self.test_type == 'XSS':
                        if self.verbose:
                            print(
                                f"[{Fore.BLUE}SELENIUM{Style.RESET_ALL}] Launching browser to verify execution...")

                        selenium_verified = await verify_with_selenium(final_url, method.upper(), data)

                        if selenium_verified:
                            verification_msg = f"({Fore.GREEN}CONFIRMED by Selenium{Style.RESET_ALL})"
                        else:
                            verification_msg = f"({Fore.RED}Selenium Failed to Execute{Style.RESET_ALL})"

                    # 2. Tentukan Status Akhir
                    # Kita anggap Vulnerable JIKA:
                    # A. Tipe tes adalah HTMLi (Cukup refleksi teks saja)
                    # B. ATAU Selenium berhasil konfirmasi (untuk XSS)
                    # C. ATAU User tidak mengaktifkan Selenium (percaya static analysis)

                    should_report = False
                    verification_msg = ""

                    if self.test_type == 'HTMLi':
                        should_report = True
                        verification_msg = "(HTML Injection Reflected)"
                    elif selenium_verified:
                        should_report = True
                    elif not self.use_selenium:
                        should_report = True
                        verification_msg = "(Static Analysis Only)"
                    else:
                        # Kasus: XSS + Selenium Aktif + Selenium Gagal
                        should_report = False

                    # 3. Cetak Hasil
                    if should_report:
                        print(
                            f"[{Fore.RED}VULNERABLE - {self.test_type}{Style.RESET_ALL}] {method.upper()} | Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} {verification_msg}")
                        print(f"   └── URL: {url}")
                        print(f"   └── Payload: {original_payload}")
                        self.results.append(
                            {"url": url, "param": param_name, "payload": original_payload, "method": method.upper()})
                    else:
                        # Jika Static ketemu TAPI Selenium Gagal (Khusus XSS)
                        print(
                            f"[{Fore.MAGENTA}UNVERIFIED{Style.RESET_ALL}] Payload reflected but Selenium failed to pop alert.")
                        print(f"   └── URL: {url}")

        except Exception as e:
            pass  # Error handling minimal agar scan tidak berhenti total

        if self.verbose and not is_vulnerable:
            print(
                f"[{Fore.GREEN}SAFE{Style.RESET_ALL}] Param: {Fore.CYAN}{param_name}{Style.RESET_ALL}")
           # --- Random Jitter Delay (WAF Evasion) ---
        if self.delay > 0:
            # Membuat variasi acak +/- 50% dari delay yang ditentukan
            # Contoh: jika delay 1 detik, sleep akan acak antara 0.5s sampai 1.5s
            jitter = random.uniform(self.delay * 0.5, self.delay * 1.5)
            await asyncio.sleep(jitter)

    async def _test_get_url(self, session, url, payloads_to_use):
        tasks = []
        params = parse_qs(urlparse(url).query)
        if not params:
            return
        for param_name in params:
            for payload in payloads_to_use:
                modified_params = {**params, param_name: [payload]}
                test_url = f"{url.split('?')[0]}?{urlencode(modified_params, doseq=True)}"
                tasks.append(self._fetch_and_check(session, test_url, 'GET', {
                             'param_name': param_name, 'original_payload': payload}))
        await asyncio.gather(*tasks)

    async def _test_form(self, session, form_details, payloads_to_use):
        tasks = []
        action_url = form_details['action']
        method = form_details['method']
        inputs = form_details['inputs']
        for payload in payloads_to_use:
            for input_to_test in inputs:
                if input_to_test.get('type') not in ['text', 'search', 'email', 'url', 'password', 'textarea', None]:
                    continue
                data = {}
                for i in inputs:
                    if i.get('name'):
                        data[i['name']] = payload if i == input_to_test else i.get(
                            'value', 'test')
                if method.upper() == 'POST':
                    task = self._fetch_and_check(session, action_url, 'POST', {
                                                 'param_name': input_to_test['name'], 'original_payload': payload}, data=data)
                    tasks.append(task)
                else:
                    test_url = f"{action_url}?{urlencode(data)}"
                    task = self._fetch_and_check(session, test_url, 'GET', {
                                                 'param_name': input_to_test['name'], 'original_payload': payload})
                    tasks.append(task)
        await asyncio.gather(*tasks)

    async def _crawl_and_scan(self, session, url, current_depth, payloads_to_use):
        url_hash = hash(url)
        if current_depth > self.depth or url_hash in self.scanned_urls_and_forms or urlparse(url).netloc != urlparse(self.start_url).netloc:
            return
        if self.verbose:
            print(
                f"[{Fore.BLUE}CRAWLING{Style.RESET_ALL}] Depth: {current_depth} | URL: {url}")
        self.scanned_urls_and_forms.add(url_hash)
        new_links, forms = set(), []
        try:
            async with session.get(url, proxy=self.proxy, headers=self.headers, timeout=15) as response:
                if "text/html" not in response.headers.get('Content-Type', ''):
                    return
                html_content = await response.text()
            await self._test_get_url(session, url, payloads_to_use)
            if self.crawl:
                soup = BeautifulSoup(html_content, 'lxml')
                for a_tag in soup.find_all('a', href=True):
                    link = urljoin(url, a_tag['href']).split('#')[0]
                    if urlparse(link).scheme in ['http', 'https']:
                        new_links.add(link)
                for form in soup.find_all('form'):
                    action = form.get('action', url)
                    form_url = urljoin(url, action)
                    form_hash = hash(f"{form_url}-{form.get('method', 'get')}")
                    if form_hash in self.scanned_urls_and_forms:
                        continue
                    self.scanned_urls_and_forms.add(form_hash)
                    form_details = {
                        'action': form_url,
                        'method': form.get('method', 'get').upper(),
                        'inputs': [{'name': i.get('name'), 'type': i.get('type', 'text'), 'value': i.get('value', '')} for i in form.find_all(['input', 'textarea']) if i.get('name')]
                    }
                    if form_details['inputs']:
                        forms.append(form_details)
        except Exception:
            pass
        form_tasks = [self._test_form(
            session, form, payloads_to_use) for form in forms]
        await asyncio.gather(*form_tasks)
        crawl_tasks = [self._crawl_and_scan(
            session, link, current_depth + 1, payloads_to_use) for link in new_links]
        await asyncio.gather(*crawl_tasks)

    async def run(self):
        connector = aiohttp.TCPConnector(
            ssl=False, limit_per_host=self.workers)
        async with aiohttp.ClientSession(connector=connector) as session:
            if self.fingerprint:
                self.tech_findings = await fingerprint_technology(session, self.start_url, self.headers, self.proxy)
            self._print_banner()
            payloads_to_use = self.base_payloads
            print(f"[*] Total payloads to test: {len(payloads_to_use)}")
            if self.crawl:
                print("[*] Starting in Crawler Mode...")
                await self._crawl_and_scan(session, self.start_url, 0, payloads_to_use)
            else:
                print("[*] Starting in List Mode...")
                tasks = [self._test_get_url(
                    session, url, payloads_to_use) for url in self.targets]
                await asyncio.gather(*tasks)

    def print_summary(self, output_file=None):
        end_time = datetime.now()
        duration = end_time - self.start_time
        print("\n" + "-" * 50)
        print(f"{Fore.CYAN}Scan Finished{Style.RESET_ALL}")
        print(f"[*] End Time      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Duration      : {duration}")
        if not self.results:
            print(
                f"\n[{Fore.GREEN}SUMMARY{Style.RESET_ALL}] No vulnerabilities found.")
            return
        print(
            f"\n[{Fore.RED}SUMMARY{Style.RESET_ALL}] Found {len(self.results)} potential vulnerabilities:")
        if self.tech_findings:
            print(f"[{Fore.YELLOW}Technology Info{Style.RESET_ALL}]")
            for finding in self.tech_findings:
                print(f"  - {finding}")
        report_content = f"PoisonXSS Scan Report - {self.start_time.strftime('%Y-%m-%d')}\n\n"
        if self.tech_findings:
            report_content += "Technology Info:\n"
            for finding in self.tech_findings:
                report_content += f"- {finding}\n"
            report_content += "\n"
        for res in self.results:
            summary = (f"- Type     : {self.test_type}\n"
                       f"  Method   : {res['method']}\n"
                       f"  URL      : {res['url']}\n"
                       f"  Parameter: {res['param']}\n"
                       f"  Payload  : {res['payload']}\n")
            print(summary)
            report_content += summary + "\n"
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                print(
                    f"\n[{Fore.GREEN}INFO{Style.RESET_ALL}] Report saved to: {output_file}")
            except IOError as e:
                print(
                    f"[{Fore.RED}ERROR{Style.RESET_ALL}] Failed to save report to {output_file}: {e}")


def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return None


def main():
    if any(h in sys.argv for h in ['-h', '--help', '--help-syntax']):
        show_help_syntax()
        sys.exit()

    parser = argparse.ArgumentParser(
        description=f"PoisonXSS v{__version__}", add_help=False)

    parser.add_argument('-h', '--help', '--help-syntax', action='store_true')
    parser.add_argument('--version', action='version',
                        version=f'PoisonXSS {__version__}')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-u", "--url", help="Single starting URL for a scan or crawl")
    target_group.add_argument(
        "-l", "--list", help="File containing a list of URLs to test")

    parser.add_argument("-p", "--payloads",
                        help="File with XSS payloads (default mode)")
    parser.add_argument(
        "--payloads-htmli", help="File with HTML Injection payloads (for --htmli mode)")
    parser.add_argument("--htmli", action="store_true",
                        help="Switch to HTML Injection testing mode")
    parser.add_argument("--crawl", action="store_true",
                        help="Enable the web crawler (only works with -u)")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--fingerprint", action="store_true")
    parser.add_argument("--selenium", action="store_true",
                        help="Enable Selenium-based verification for max accuracy")
    parser.add_argument(
        "--cookie", help="Cookie string for authenticated scanning")
    parser.add_argument("-H", "--headers")
    parser.add_argument("--proxy")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("-w", "--workers", type=int, default=50)
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    # --- LOGIKA LOADING TARGET & PAYLOAD TERBARU ---

    # 1. Load Targets
    if args.url:
        targets = [args.url]
    else:
        if not args.list:
            print(
                f"[{Fore.RED}ERROR{Style.RESET_ALL}] You must specify a target URL (-u) or a list file (-l).")
            return
        targets = load_payloads_from_file(args.list)
        if targets is None:
            print(
                f"[{Fore.RED}ERROR{Style.RESET_ALL}] URL list file not found or is empty: {args.list}")
            return

    # 2. Setup Test Type & Payloads
    test_type = 'XSS'  # Default
    payloads = None

    # --- JIKA MODE HTML INJECTION ---
    if args.htmli:
        test_type = 'HTMLi'
        target_payload_file = args.payloads  # Gunakan argumen -p yang sama

        # A. Jika user pakai -p
        if target_payload_file:
            payloads = load_payloads_from_file(target_payload_file)
            if not payloads:
                print(
                    f"[{Fore.RED}ERROR{Style.RESET_ALL}] HTMLi payload file not found: {target_payload_file}")
                return
        # B. Jika tidak pakai -p, cari file default
        else:
            if os.path.exists(DEFAULT_HTMLI_FILENAME):
                print(f"[{Fore.YELLOW}INFO{Style.RESET_ALL}] No payload specified. Using default HTMLi file: {Fore.CYAN}{DEFAULT_HTMLI_FILENAME}{Style.RESET_ALL}")
                payloads = load_payloads_from_file(DEFAULT_HTMLI_FILENAME)
            else:
                # C. Terakhir, pakai hardcoded payloads
                print(f"[{Fore.YELLOW}INFO{Style.RESET_ALL}] No file specified and '{DEFAULT_HTMLI_FILENAME}' not found. Using internal default payloads.")
                payloads = DEFAULT_HTMLI_PAYLOADS

    # --- JIKA MODE XSS (DEFAULT) ---
    else:
        target_payload_file = args.payloads

        # A. Jika user TIDAK pakai -p, cari file default
        if not target_payload_file:
            if os.path.exists(DEFAULT_PAYLOAD_FILENAME):
                print(f"[{Fore.YELLOW}INFO{Style.RESET_ALL}] No payload file specified (-p). Using default file: {Fore.CYAN}{DEFAULT_PAYLOAD_FILENAME}{Style.RESET_ALL}")
                target_payload_file = DEFAULT_PAYLOAD_FILENAME
            else:
                # Error jika file default XSS juga tidak ada
                print(
                    f"[{Fore.RED}ERROR{Style.RESET_ALL}] Payload file not specified via -p, and default '{DEFAULT_PAYLOAD_FILENAME}' not found.")
                print(f"[{Fore.YELLOW}HINT{Style.RESET_ALL}] Create a file named '{DEFAULT_PAYLOAD_FILENAME}' with payloads inside, or use -p yourfile.txt")
                return

        # Load file payload
        payloads = load_payloads_from_file(target_payload_file)

    # Cek terakhir untuk memastikan payload tidak kosong
    if not payloads:
        print(f"[{Fore.RED}Error: Could not load payloads. Exiting.{Style.RESET_ALL}")
        return

    headers = {}
    if args.headers:
        try:
            headers.update(dict(item.split(":", 1)
                           for item in args.headers.split(",")))
        except ValueError:
            print(
                f"[{Fore.RED}ERROR{Style.RESET_ALL}] Invalid header format. Use 'Key1:Value1,Key2:Value2'")
            return
    if args.cookie:
        headers['Cookie'] = args.cookie

    scanner = PoisonXSS(
        targets=targets, payloads=payloads, test_type=test_type, headers=headers, workers=args.workers,
        proxy=args.proxy, verbose=args.verbose, delay=args.delay,
        crawl=args.crawl, depth=args.depth, fingerprint=args.fingerprint, use_selenium=args.selenium
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
    finally:
        if 'scanner' in locals() and scanner.results:
            scanner.print_summary(args.output)


if __name__ == "__main__":
    main()
