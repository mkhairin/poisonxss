#
# PoisonXSS - Version 2.5-intel
# Added Technology Fingerprinting module to the user-provided v2.5 base.
#

import argparse
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode, parse_qs, unquote, quote, urljoin
from colorama import Fore, init, Style
from datetime import datetime
import sys
import random
import re
try:
    from bs4 import BeautifulSoup
except ImportError:
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] BeautifulSoup4 is not installed. Please run 'pip install beautifulsoup4 lxml'")
    sys.exit()

# --- Version Configuration ---
__version__ = "2.5-intel"

# Initialize colorama
init(autoreset=True)


# --- Updated Help Function ---
def show_help_syntax():
    """Displays a detailed, bilingual help guide in a sqlmap-style layout."""
    CYAN, GREEN, RESET, WIDTH = Fore.CYAN, Fore.GREEN, Style.RESET_ALL, 35

    # --- English Version ---
    print(f"\n{CYAN}PoisonXSS {__version__} - Help Guide (English){RESET}")
    print(f"Usage: python poisonxss.py -u <URL> -p <FILE> [options]\n")

    print(f"{GREEN}Options:{RESET}")
    print(f"  {"-h, --help-syntax".ljust(WIDTH)}Show this advanced help message and exit")
    print(f"  {"--version".ljust(WIDTH)}Show program's version number and exit")
    print(f"  {"-v, --verbose".ljust(WIDTH)}Verbosity level. Shows safe requests.\n")

    print(f"{GREEN}Target:{RESET}")
    print(f"  {"-u URL, --url=URL".ljust(WIDTH)}Target URL (e.g. \"http://site.com/vuln.php?id=1\")")
    print(f"  {"-p PAYLOADS, --payloads=FILE".ljust(WIDTH)}File containing XSS payloads to test.\n")
    
    print(f"{GREEN}Intelligence:{RESET}")
    print(f"  {"--fingerprint".ljust(WIDTH)}Enable technology fingerprinting\n")

    print(f"{GREEN}Crawler:{RESET}")
    print(f"  {"--crawl".ljust(WIDTH)}Enable the web crawler to find new targets")
    print(f"  {"--depth=DEPTH".ljust(WIDTH)}Maximum crawl depth (default: 2)\n")

    print(f"{GREEN}Request:{RESET}")
    print(f"  {"-H HEADERS, --headers=HEADERS".ljust(WIDTH)}Custom headers, comma-separated (e.g. \"Cookie:id=123\")")
    print(f"  {"--proxy=PROXY".ljust(WIDTH)}Use a proxy to connect to the target URL\n")

    print(f"{GREEN}Control:{RESET}")
    print(f"  {"--delay=DELAY".ljust(WIDTH)}Delay in seconds between each request")
    print(f"  {"-w WORKERS, --workers=NUM".ljust(WIDTH)}Number of concurrent workers (default: 50)")
    print(f"  {"-o OUTPUT, --output=FILE".ljust(WIDTH)}Save the scan report to a file")
    
    # --- Separator & Indonesian Version ---
    print(f"\n\n{'-'*60}\n\n")

    print(f"{CYAN}PoisonXSS {__version__} - Panduan Bantuan (Bahasa Indonesia){RESET}")
    print(f"Penggunaan: python poisonxss.py -u <URL> -p <FILE> [opsi]\n")

    print(f"{GREEN}Opsi:{RESET}")
    print(f"  {"-h, --help-syntax".ljust(WIDTH)}Tampilkan pesan bantuan lanjutan ini dan keluar")
    print(f"  {"--version".ljust(WIDTH)}Tampilkan nomor versi program dan keluar")
    print(f"  {"-v, --verbose".ljust(WIDTH)}Tingkat verbositas. Menampilkan request yang aman.\n")

    print(f"{GREEN}Target:{RESET}")
    print(f"  {"-u URL, --url=URL".ljust(WIDTH)}URL Target (cth: \"http://site.com/vuln.php?id=1\")")
    print(f"  {"-p PAYLOADS, --payloads=FILE".ljust(WIDTH)}File berisi payload XSS untuk diuji.\n")
    
    print(f"{GREEN}Intelijen:{RESET}")
    print(f"  {"--fingerprint".ljust(WIDTH)}Aktifkan identifikasi teknologi (fingerprinting)\n")

    print(f"{GREEN}Crawler:{RESET}")
    print(f"  {"--crawl".ljust(WIDTH)}Aktifkan web crawler untuk menemukan target baru")
    print(f"  {"--depth=DEPTH".ljust(WIDTH)}Kedalaman crawl maksimum (default: 2)\n")

    print(f"{GREEN}Permintaan (Request):{RESET}")
    print(f"  {"-H HEADERS, --headers=HEADERS".ljust(WIDTH)}Header kustom, pisahkan dengan koma (cth: \"Cookie:id=123\")")
    print(f"  {"--proxy=PROXY".ljust(WIDTH)}Gunakan proxy untuk terhubung ke URL target\n")

    print(f"{GREEN}Kontrol:{RESET}")
    print(f"  {"--delay=DELAY".ljust(WIDTH)}Jeda dalam detik di antara setiap request")
    print(f"  {"-w WORKERS, --workers=NUM".ljust(WIDTH)}Jumlah pekerja konkuren (default: 50)")
    print(f"  {"-o OUTPUT, --output=FILE".ljust(WIDTH)}Simpan laporan pemindaian ke sebuah file")


# --- New Fingerprinting Function ---
async def fingerprint_technology(session, url, headers, proxy):
    """Analyzes headers and content to identify server technology."""
    findings = []
    try:
        async with session.get(url, headers=headers, proxy=proxy, timeout=10) as response:
            # 1. Check Headers
            server = response.headers.get('Server')
            if server:
                findings.append(f"Server: {server}")
            
            x_powered_by = response.headers.get('X-Powered-By')
            if x_powered_by:
                findings.append(f"Tech: {x_powered_by}")

            # 2. Check HTML content for <meta name="generator">
            if "text/html" in response.headers.get('Content-Type', ''):
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'lxml')
                generator_tag = soup.find('meta', attrs={'name': re.compile(r'generator', re.I)})
                if generator_tag and generator_tag.get('content'):
                    findings.append(f"Generator: {generator_tag.get('content')}")

    except Exception:
        return ["Could not perform fingerprinting."]

    return findings if findings else ["No specific technology identified."]

class PoisonXSS:
    def __init__(self, start_url, payloads, headers=None, workers=50, proxy=None, verbose=False, delay=0, crawl=False, depth=2, fingerprint=False):
        self.start_url = start_url
        self.base_payloads = payloads
        self.headers = headers or {"User-Agent": f"PoisonXSS/{__version__}"}
        self.workers = workers
        self.results = []
        self.start_time = datetime.now()
        self.proxy = proxy
        self.verbose = verbose
        self.delay = delay
        self.crawl = crawl
        self.depth = depth
        self.scanned_urls = set()
        # New attributes
        self.fingerprint = fingerprint
        self.tech_findings = []

    def _print_banner(self):
        print(r"""
                 _                                
    ____  ____  (_)________  ____  _  ____________
   / __ \/ __ \/ / ___/ __ \/ __ \| |/_/ ___/ ___/
  / /_/ / /_/ / (__  ) /_/ / / / />  <(__  |__  ) 
 / .___/\____/_/____/\____/_/ /_/_/|_/____/____/  
/_/                                               
        """)
        print(f"{Fore.CYAN}PoisonXSS v{__version__} [Intel Edition]{Style.RESET_ALL}")
        print(f"[*] Start Time    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Start URL     : {self.start_url}")
        print(f"[*] Base Payloads : {len(self.base_payloads)} loaded")
        if self.crawl: print(f"[*] Crawler Mode  : {Fore.GREEN}Enabled (Depth: {self.depth}){Style.RESET_ALL}")
        # Display fingerprinting results
        if self.fingerprint:
            print(f"[*] Fingerprint   : {Fore.GREEN}Enabled{Style.RESET_ALL}")
            if self.tech_findings:
                for finding in self.tech_findings:
                    print(f"[*]   - {Fore.YELLOW}{finding}{Style.RESET_ALL}")
        if self.proxy: print(f"[*] Proxy         : {self.proxy}")
        print(f"[*] Workers       : {self.workers}")
        print("-" * 50)
    
    async def _test_url_for_xss(self, session, url, payloads_to_use):
        tasks = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return
        for param_name in params:
            for payload in payloads_to_use:
                modified_params = {**params, param_name: [payload]}
                query_string = urlencode(modified_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                tasks.append(self._fetch_and_check(session, test_url, {'param_name': param_name, 'original_payload': payload}))
        await asyncio.gather(*tasks)

    async def _fetch_and_check(self, session, url, payload_info):
        param_name = payload_info['param_name']
        original_payload = payload_info['original_payload']
        is_vulnerable = False
        try:
            async with session.get(url, headers=self.headers, proxy=self.proxy, timeout=15) as response:
                response_text = await response.text()
                if original_payload in response_text and not ("&lt;" in response_text or "&gt;" in response_text):
                    is_vulnerable = True
                    result = {"url": str(response.url), "param": param_name, "payload": original_payload, "method": "GET"}
                    print(f"[{Fore.RED}VULNERABLE{Style.RESET_ALL}] GET | Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} | URL: {result['url']}")
                    self.results.append(result)
        except Exception:
            pass
        if self.verbose and not is_vulnerable:
            print(f"[{Fore.GREEN}SAFE{Style.RESET_ALL}] Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} | Payload: {original_payload[:30]}...")
        if self.delay > 0:
            await asyncio.sleep(self.delay)

    async def _crawl_and_scan(self, session, url, current_depth, payloads_to_use):
        if current_depth > self.depth or url in self.scanned_urls or urlparse(url).netloc != urlparse(self.start_url).netloc:
            return
        if self.verbose:
            print(f"[{Fore.BLUE}CRAWLING{Style.RESET_ALL}] Depth: {current_depth} | URL: {url}")
        self.scanned_urls.add(url)
        new_links = set()
        try:
            async with session.get(url, proxy=self.proxy, headers=self.headers, timeout=15) as response:
                if "text/html" not in response.headers.get('Content-Type', ''):
                    return
                html_content = await response.text()
            await self._test_url_for_xss(session, url, payloads_to_use)
            if self.crawl:
                soup = BeautifulSoup(html_content, 'lxml')
                for a_tag in soup.find_all('a', href=True):
                    link = urljoin(url, a_tag['href']).split('#')[0]
                    if urlparse(link).scheme in ['http', 'https']:
                        new_links.add(link)
        except Exception:
            pass
        tasks = [self._crawl_and_scan(session, link, current_depth + 1, payloads_to_use) for link in new_links if link not in self.scanned_urls]
        await asyncio.gather(*tasks)

    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=self.workers)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Run fingerprinting if enabled
            if self.fingerprint:
                self.tech_findings = await fingerprint_technology(session, self.start_url, self.headers, self.proxy)

            self._print_banner()
            # In this version, evasion mode is not implemented, so we use base payloads
            payloads_to_use = self.base_payloads
            print(f"[*] Total effective payloads to test: {len(payloads_to_use)}")
            await self._crawl_and_scan(session, self.start_url, 0, payloads_to_use)

    def print_summary(self, output_file=None):
        end_time = datetime.now()
        duration = end_time - self.start_time
        print("\n" + "-" * 50)
        print(f"{Fore.CYAN}Scan Finished{Style.RESET_ALL}")
        print(f"[*] End Time      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Duration      : {duration}")
        if not self.results:
            print(f"\n[{Fore.GREEN}SUMMARY{Style.RESET_ALL}] No XSS vulnerabilities found.")
            return
            
        print(f"\n[{Fore.RED}SUMMARY{Style.RESET_ALL}] Found {len(self.results)} potential vulnerabilities:")
        # Display technology info in summary
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
            summary = (f"- URL      : {res['url']}\n" f"  Parameter: {res['param']}\n" f"  Payload  : {res['payload']}\n")
            print(summary)
            report_content += summary + "\n"
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f: f.write(report_content)
                print(f"\n[{Fore.GREEN}INFO{Style.RESET_ALL}] Report saved to: {output_file}")
            except IOError as e: print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Failed to save report to {output_file}: {e}")

def main():
    if any(h in sys.argv for h in ['-h', '--help', '--help-syntax']):
        show_help_syntax()
        sys.exit()

    parser = argparse.ArgumentParser(description=f"PoisonXSS v{__version__}", add_help=False)
    
    parser.add_argument('-h', '--help', '--help-syntax', action='store_true')
    parser.add_argument('--version', action='version', version=f'PoisonXSS {__version__}')
    parser.add_argument("-u", "--url")
    parser.add_argument("-p", "--payloads")
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("-H", "--headers")
    parser.add_argument("--proxy")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("-w", "--workers", type=int, default=50)
    parser.add_argument("-o", "--output")
    # New argument added here
    parser.add_argument("--fingerprint", action="store_true", help="Enable technology fingerprinting")
    
    args = parser.parse_args()

    # Evasion flag is in help text but not used in this version's logic
    # We'll just define args.evade as False for compatibility if needed later
    # This avoids an AttributeError if other parts of the code expected it.
    if 'evade' not in args:
        args.evade = False

    if not args.url or not args.payloads:
        print(f"{Fore.RED}Error: Start URL (-u) and payload file (-p) are required.{RESET}\nUse --help-syntax for detailed usage information.")
        return

    try:
        payloads = [line.strip() for line in open(args.payloads) if line.strip()]
    except FileNotFoundError:
        print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Payload file not found: {args.payloads}")
        return
        
    headers = dict(item.split(":", 1) for item in args.headers.split(",")) if args.headers else None
    
    scanner = PoisonXSS(
        start_url=args.url, payloads=payloads, headers=headers, workers=args.workers,
        proxy=args.proxy, verbose=args.verbose, delay=args.delay,
        crawl=args.crawl, depth=args.depth, fingerprint=args.fingerprint
    )
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
    finally:
        if 'scanner' in locals():
            scanner.print_summary(args.output)


if __name__ == "__main__":
    main()