#
# PoisonXSS - Version 2.9
# The Accuracy & Scope Update: Selenium Verification and POST Method Testing.
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
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, WebDriverException
except ImportError:
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Selenium is not installed. Please run 'pip install selenium'")
    sys.exit()

# --- Version Configuration & Default Payloads ---
__version__ = "2.9"
DEFAULT_HTMLI_PAYLOADS = ["<h1>HTMLi-Test</h1>", "<i>PoisonXSS</i>"]

# Initialize colorama
init(autoreset=True)

def show_help_syntax():
    """Displays a detailed help guide."""
    CYAN, GREEN, RESET, WIDTH = Fore.CYAN, Fore.GREEN, Style.RESET_ALL, 35
    
    print(f"\n{CYAN}PoisonXSS {__version__} - Help Guide{RESET}")
    print(f"Usage: python poisonxss.py [TARGET] -p <FILE> [options]\n")

    print(f"{GREEN}Options:{RESET}")
    print(f"  {"-h, --help-syntax".ljust(WIDTH)}Show this advanced help message and exit")
    print(f"  {"--version".ljust(WIDTH)}Show program's version number and exit")
    print(f"  {"-v, --verbose".ljust(WIDTH)}Verbosity level. Shows safe requests.\n")

    print(f"{GREEN}Target (Choose one):{RESET}")
    print(f"  {"-u URL, --url=URL".ljust(WIDTH)}Single starting URL for a scan or crawl")
    print(f"  {"-l FILE, --list=FILE".ljust(WIDTH)}File containing a list of URLs to test.\n")

    print(f"{GREEN}Payloads:{RESET}")
    print(f"  {"-p FILE, --payloads=FILE".ljust(WIDTH)}File with XSS payloads (default mode).")
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
    
    print(f"{GREEN}Request:{RESET}")
    print(f"  {"-H HEADERS, --headers=HEADERS".ljust(WIDTH)}Custom headers, comma-separated (e.g. \"Cookie:id=123\")")
    print(f"  {"--proxy=PROXY".ljust(WIDTH)}Use a proxy to connect to the target URL\n")

    print(f"{GREEN}Control:{RESET}")
    print(f"  {"--delay=DELAY".ljust(WIDTH)}Delay in seconds between each request")
    print(f"  {"-w WORKERS, --workers=NUM".ljust(WIDTH)}Number of concurrent workers (default: 50)")
    print(f"  {"-o OUTPUT, --output=FILE".ljust(WIDTH)}Save the scan report to a file")


async def verify_with_selenium(url):
    """Verifies XSS using a real browser via Selenium."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--log-level=3")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        driver.switch_to.alert.accept()
        return True
    except (NoAlertPresentException, WebDriverException):
        return False
    except UnexpectedAlertPresentException:
        return True
    finally:
        if driver:
            driver.quit()


class PoisonXSS:
    def __init__(self, targets, payloads, test_type='XSS', headers=None, workers=50, proxy=None, verbose=False, delay=0, crawl=False, depth=2, fingerprint=False, use_selenium=False):
        self.targets = targets
        self.start_url = targets[0]
        self.base_payloads = payloads
        self.test_type = test_type
        self.headers = headers or {"User-Agent": f"PoisonXSS/{__version__}"}
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
/_/                                               
        """)
        print(f"{Fore.CYAN}PoisonXSS v{__version__} [Final]{Style.RESET_ALL} | The All-in-One XSS Scanner")
        print(f"[*] Testing Mode  : {Fore.MAGENTA}{self.test_type}{Style.RESET_ALL}")
        print(f"[*] Start Time    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Targets Loaded: {len(self.targets)}")
        print(f"[*] Base Payloads : {len(self.base_payloads)} loaded")
        if self.crawl: print(f"[*] Crawler Mode  : {Fore.GREEN}Enabled (Depth: {self.depth}){Style.RESET_ALL}")
        if self.use_selenium: print(f"[*] Accuracy Mode : {Fore.GREEN}Selenium Enabled{Style.RESET_ALL}")
        if self.fingerprint:
            print(f"[*] Fingerprint   : {Fore.GREEN}Enabled{Style.RESET_ALL}")
            if self.tech_findings:
                for finding in self.tech_findings:
                    print(f"[*]   - {Fore.YELLOW}{finding}{Style.RESET_ALL}")
        if self.proxy: print(f"[*] Proxy         : {self.proxy}")
        print(f"[*] Workers       : {self.workers}")
        print("-" * 50)
    
    async def _fetch_and_check(self, session, url, method, payload_info, data=None):
        """Core worker for sending requests and checking for vulnerabilities."""
        param_name = payload_info['param_name']
        original_payload = payload_info['original_payload']
        is_vulnerable = False
        
        try:
            response_text = ""
            final_url = url
            if method.upper() == 'POST':
                async with session.post(url, headers=self.headers, proxy=self.proxy, data=data, timeout=15) as response:
                    response_text = await response.text()
            else: # GET
                async with session.get(url, headers=self.headers, proxy=self.proxy, timeout=15) as response:
                    response_text = await response.text()
                    final_url = str(response.url)

            if original_payload in response_text and not ("&lt;" in response_text or "&gt;" in response_text):
                is_vulnerable = True
                if method.upper() == 'GET' and self.use_selenium and self.test_type == 'XSS':
                    if self.verbose: print(f"[{Fore.BLUE}VERIFYING{Style.RESET_ALL}] Potential GET finding in {param_name}. Launching Selenium...")
                    is_vulnerable = await verify_with_selenium(final_url)

                if is_vulnerable:
                    verification_status = f"({Fore.GREEN}Verified by Selenium{Style.RESET_ALL})" if self.use_selenium and method.upper() == 'GET' and self.test_type == 'XSS' else ""
                    print(f"[{Fore.RED}VULNERABLE - {self.test_type}{Style.RESET_ALL}] {method.upper()} | Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} {verification_status} | URL: {url}")
                    self.results.append({"url": url, "param": param_name, "payload": original_payload, "method": method.upper()})

        except Exception: pass
        if self.verbose and not is_vulnerable:
            print(f"[{Fore.GREEN}SAFE{Style.RESET_ALL}] Param: {Fore.CYAN}{param_name}{Style.RESET_ALL}")
        if self.delay > 0: await asyncio.sleep(self.delay)

    async def _test_get_url(self, session, url, payloads_to_use):
        """Tests a single URL with GET parameters."""
        tasks = []
        params = parse_qs(urlparse(url).query)
        if not params: return
        for param_name in params:
            for payload in payloads_to_use:
                modified_params = {**params, param_name: [payload]}
                test_url = f"{url.split('?')[0]}?{urlencode(modified_params, doseq=True)}"
                tasks.append(self._fetch_and_check(session, test_url, 'GET', {'param_name': param_name, 'original_payload': payload}))
        await asyncio.gather(*tasks)

    async def _test_form(self, session, form_details, payloads_to_use):
        """Tests a single HTML form with GET or POST method."""
        tasks = []
        action_url = form_details['action']
        method = form_details['method']
        inputs = form_details['inputs']

        for payload in payloads_to_use:
            for input_to_test in inputs:
                # Skip non-textual inputs
                if input_to_test.get('type') not in ['text', 'search', 'email', 'url', 'password', 'textarea', None]:
                    continue
                
                data = {}
                for i in inputs:
                    # Only inject into the target input
                    if i.get('name'):
                        data[i['name']] = payload if i == input_to_test else i.get('value', 'test')
                
                if method.upper() == 'POST':
                    task = self._fetch_and_check(session, action_url, 'POST', {'param_name': input_to_test['name'], 'original_payload': payload}, data=data)
                    tasks.append(task)
                else: # GET
                    test_url = f"{action_url}?{urlencode(data)}"
                    task = self._fetch_and_check(session, test_url, 'GET', {'param_name': input_to_test['name'], 'original_payload': payload})
                    tasks.append(task)
        await asyncio.gather(*tasks)

    async def _crawl_and_scan(self, session, url, current_depth, payloads_to_use):
        """Main function for a single URL: scan it, then find more links and forms."""
        url_hash = hash(url)
        if current_depth > self.depth or url_hash in self.scanned_urls_and_forms or urlparse(url).netloc != urlparse(self.start_url).netloc:
            return
        if self.verbose: print(f"[{Fore.BLUE}CRAWLING{Style.RESET_ALL}] Depth: {current_depth} | URL: {url}")
        self.scanned_urls_and_forms.add(url_hash)

        new_links = set()
        forms = []
        try:
            async with session.get(url, proxy=self.proxy, headers=self.headers, timeout=15) as response:
                if "text/html" not in response.headers.get('Content-Type', ''): return
                html_content = await response.text()
            
            await self._test_get_url(session, url, payloads_to_use)

            if self.crawl:
                soup = BeautifulSoup(html_content, 'lxml')
                # Find links
                for a_tag in soup.find_all('a', href=True):
                    link = urljoin(url, a_tag['href']).split('#')[0]
                    if urlparse(link).scheme in ['http', 'https']: new_links.add(link)
                
                # Find forms
                for form in soup.find_all('form'):
                    action = form.get('action', url)
                    form_url = urljoin(url, action)
                    form_hash = hash(f"{form_url}-{form.get('method', 'get')}")
                    if form_hash in self.scanned_urls_and_forms: continue
                    self.scanned_urls_and_forms.add(form_hash)

                    form_details = {
                        'action': form_url,
                        'method': form.get('method', 'get').upper(),
                        'inputs': [{'name': i.get('name'), 'type': i.get('type', 'text'), 'value': i.get('value', '')} for i in form.find_all(['input', 'textarea']) if i.get('name')]
                    }
                    if form_details['inputs']:
                        forms.append(form_details)
        except Exception: pass

        # Test found forms
        form_tasks = [self._test_form(session, form, payloads_to_use) for form in forms]
        await asyncio.gather(*form_tasks)

        # Recursively crawl new links
        crawl_tasks = [self._crawl_and_scan(session, link, current_depth + 1, payloads_to_use) for link in new_links]
        await asyncio.gather(*crawl_tasks)

    async def run(self):
        """Main logic to choose between crawl mode or list mode."""
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=self.workers)
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
                tasks = [self._test_get_url(session, url, payloads_to_use) for url in self.targets]
                await asyncio.gather(*tasks)

    def print_summary(self, output_file=None):
        end_time = datetime.now()
        duration = end_time - self.start_time
        print("\n" + "-" * 50)
        print(f"{Fore.CYAN}Scan Finished{Style.RESET_ALL}")
        print(f"[*] End Time      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Duration      : {duration}")
        if not self.results:
            print(f"\n[{Fore.GREEN}SUMMARY{Style.RESET_ALL}] No vulnerabilities found.")
            return
        print(f"\n[{Fore.RED}SUMMARY{Style.RESET_ALL}] Found {len(self.results)} potential vulnerabilities:")
        if self.tech_findings:
            print(f"[{Fore.YELLOW}Technology Info{Style.RESET_ALL}]")
            for finding in self.tech_findings:
                print(f"  - {finding}")
        report_content = f"PoisonXSS Scan Report - {self.start_time.strftime('%Y-%m-%d')}\n\n"
        if self.tech_findings:
            report_content += "Technology Info:\n"
            for finding in self.tech_findings: report_content += f"- {finding}\n"
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
                with open(output_file, 'w', encoding='utf-8') as f: f.write(report_content)
                print(f"\n[{Fore.GREEN}INFO{Style.RESET_ALL}] Report saved to: {output_file}")
            except IOError as e: print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Failed to save report to {output_file}: {e}")

def load_payloads_from_file(file_path):
    """Loads lines from a file, returns None if not found."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return None

def main():
    if any(h in sys.argv for h in ['-h', '--help', '--help-syntax']):
        show_help_syntax()
        sys.exit()

    parser = argparse.ArgumentParser(description=f"PoisonXSS v{__version__}", add_help=False)
    
    parser.add_argument('-h', '--help', '--help-syntax', action='store_true')
    parser.add_argument('--version', action='version', version=f'PoisonXSS {__version__}')
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single starting URL for a scan or crawl")
    target_group.add_argument("-l", "--list", help="File containing a list of URLs to test")

    parser.add_argument("-p", "--payloads", help="File with XSS payloads (default mode)")
    parser.add_argument("--payloads-htmli", help="File with HTML Injection payloads (for --htmli mode)")
    parser.add_argument("--htmli", action="store_true", help="Switch to HTML Injection testing mode")
    parser.add_argument("--crawl", action="store_true", help="Enable the web crawler (only works with -u)")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--fingerprint", action="store_true")
    parser.add_argument("--selenium", action="store_true", help="Enable Selenium-based verification for max accuracy")
    parser.add_argument("-H", "--headers")
    parser.add_argument("--proxy")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("-w", "--workers", type=int, default=50)
    parser.add_argument("-o", "--output")
    
    args = parser.parse_args()

    if args.url:
        targets = [args.url]
    else:
        targets = load_payloads_from_file(args.list)
        if targets is None:
            print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] URL list file not found or is empty: {args.list}")
            return
            
    test_type, payloads = 'XSS', None
    if args.htmli:
        test_type = 'HTMLi'
        payload_file = args.payloads_htmli
        if payload_file:
            payloads = load_payloads_from_file(payload_file)
            if payloads is None:
                print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] HTMLi payload file not found: {payload_file}")
                return
        else:
            payloads = DEFAULT_HTMLI_PAYLOADS
    else:
        if not args.payloads:
            print(f"{Fore.RED}Error: XSS mode requires a payload file specified with -p.{Style.RESET_ALL}")
            return
        payloads = load_payloads_from_file(args.payloads)

    if not payloads:
        print(f"[{Fore.RED}Error: Could not load payloads. Exiting.{Style.RESET_ALL}")
        return
        
    headers = dict(item.split(":", 1) for item in args.headers.split(",")) if args.headers else None
    
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
