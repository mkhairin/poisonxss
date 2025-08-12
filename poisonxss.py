#
# PoisonXSS - Version 2.6 (Final)
# The Accuracy & Automation Update
#

import argparse
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode, parse_qs, unquote, quote, urljoin
from colorama import Fore, init, Style
from datetime import datetime
import sys
import random
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

# --- Version Configuration ---
__version__ = "2.6"

# Initialize colorama
init(autoreset=True)

def show_help_syntax():
    """Displays a detailed help guide in a sqlmap-style layout."""
    CYAN, GREEN, RESET, WIDTH = Fore.CYAN, Fore.GREEN, Style.RESET_ALL, 35
    
    print(f"\n{CYAN}PoisonXSS {__version__} - Help Guide{RESET}")
    print(f"Usage: python poisonxss.py -u <URL> -p <FILE> [options]\n")

    print(f"{GREEN}Options:{RESET}")
    print(f"  {"-h, --help-syntax".ljust(WIDTH)}Show this advanced help message and exit")
    print(f"  {"--version".ljust(WIDTH)}Show program's version number and exit")
    print(f"  {"-v, --verbose".ljust(WIDTH)}Verbosity level. Shows safe requests.\n")

    print(f"{GREEN}Target:{RESET}")
    print(f"  {"-u URL, --url=URL".ljust(WIDTH)}Target URL (e.g. \"http://site.com/vuln.php?id=1\")")
    print(f"  {"-p PAYLOADS, --payloads=FILE".ljust(WIDTH)}File containing XSS payloads to test.\n")

    print(f"{GREEN}Accuracy:{RESET}")
    print(f"  {"--selenium".ljust(WIDTH)}Enable Selenium-based verification for max accuracy\n")

    print(f"{GREEN}Crawler:{RESET}")
    print(f"  {"--crawl".ljust(WIDTH)}Enable the web crawler to find new targets")
    print(f"  {"--depth=DEPTH".ljust(WIDTH)}Maximum crawl depth (default: 2)\n")

    print(f"{GREEN}Request:{RESET}")
    print(f"  {"-H HEADERS, --headers=HEADERS".ljust(WIDTH)}Custom headers, comma-separated (e.g. \"Cookie:id=123\")")
    print(f"  {"--proxy=PROXY".ljust(WIDTH)}Use a proxy to connect to the target URL\n")

    print(f"{GREEN}Evasion:{RESET}")
    print(f"  {"--evade".ljust(WIDTH)}Enable evasion techniques and WAF detection\n")

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
    def __init__(self, start_url, payloads, headers=None, workers=50, evade=False, proxy=None, verbose=False, delay=0, crawl=False, depth=2, use_selenium=False):
        self.start_url = start_url
        self.base_payloads = payloads
        self.headers = headers or {"User-Agent": f"PoisonXSS/{__version__}"}
        self.workers = workers
        self.results = []
        self.start_time = datetime.now()
        self.evade = evade
        self.proxy = proxy
        self.verbose = verbose
        self.delay = delay
        self.crawl = crawl
        self.depth = depth
        self.use_selenium = use_selenium
        self.scanned_urls = set()
        self.waf_status = "Not Checked"

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
        print(f"[*] Start Time    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Start URL     : {self.start_url}")
        print(f"[*] Base Payloads : {len(self.base_payloads)} loaded")
        if self.crawl: print(f"[*] Crawler Mode  : {Fore.GREEN}Enabled (Depth: {self.depth}){Style.RESET_ALL}")
        if self.evade: print(f"[*] Evasion Mode  : {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.use_selenium: print(f"[*] Accuracy Mode : {Fore.GREEN}Selenium Enabled{Style.RESET_ALL}")
        if self.waf_status != "Not Checked": print(f"[*] WAF Status    : {Fore.YELLOW}{self.waf_status}{Style.RESET_ALL}")
        if self.proxy: print(f"[*] Proxy         : {self.proxy}")
        print(f"[*] Workers       : {self.workers}")
        print("-" * 50)
    
    async def _fetch_and_check(self, session, url, payload_info):
        param_name = payload_info['param_name']
        original_payload = payload_info['original_payload']
        is_vulnerable = False
        try:
            async with session.get(url, headers=self.headers, proxy=self.proxy, timeout=15) as response:
                response_text = await response.text()
                if original_payload in response_text and not ("&lt;" in response_text or "&gt;" in response_text):
                    if self.use_selenium:
                        if self.verbose: print(f"[{Fore.BLUE}VERIFYING{Style.RESET_ALL}] Potential finding in {param_name}. Launching Selenium...")
                        is_vulnerable = await verify_with_selenium(url)
                    else:
                        is_vulnerable = True
                    if is_vulnerable:
                        verification_status = f"({Fore.GREEN}Verified by Selenium{Style.RESET_ALL})" if self.use_selenium else ""
                        print(f"[{Fore.RED}VULNERABLE{Style.RESET_ALL}] GET | Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} {verification_status} | URL: {url}")
                        self.results.append({"url": url, "param": param_name, "payload": original_payload})
        except Exception: pass
        if self.verbose and not is_vulnerable:
            print(f"[{Fore.GREEN}SAFE{Style.RESET_ALL}] Param: {Fore.CYAN}{param_name}{Style.RESET_ALL}")
        if self.delay > 0: await asyncio.sleep(self.delay)

    async def _test_url_for_xss(self, session, url, payloads_to_use):
        tasks = []
        params = parse_qs(urlparse(url).query)
        if not params: return
        for param_name in params:
            for payload in payloads_to_use:
                modified_params = {**params, param_name: [payload]}
                test_url = f"{url.split('?')[0]}?{urlencode(modified_params, doseq=True)}"
                tasks.append(self._fetch_and_check(session, test_url, {'param_name': param_name, 'original_payload': payload}))
        await asyncio.gather(*tasks)

    async def _crawl_and_scan(self, session, url, current_depth, payloads_to_use):
        if current_depth > self.depth or url in self.scanned_urls or urlparse(url).netloc != urlparse(self.start_url).netloc:
            return
        if self.verbose: print(f"[{Fore.BLUE}CRAWLING{Style.RESET_ALL}] Depth: {current_depth} | URL: {url}")
        self.scanned_urls.add(url)
        new_links = set()
        try:
            async with session.get(url, proxy=self.proxy, headers=self.headers, timeout=15) as response:
                if "text/html" not in response.headers.get('Content-Type', ''): return
                html_content = await response.text()
            await self._test_url_for_xss(session, url, payloads_to_use)
            if self.crawl:
                soup = BeautifulSoup(html_content, 'lxml')
                for tag in soup.find_all(['a', 'form'], href=True, action=True):
                    link = urljoin(url, tag.get('href') or tag.get('action')).split('#')[0]
                    if urlparse(link).scheme in ['http', 'https']: new_links.add(link)
        except Exception: pass
        tasks = [self._crawl_and_scan(session, link, current_depth + 1, payloads_to_use) for link in new_links if link not in self.scanned_urls]
        await asyncio.gather(*tasks)

    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=self.workers)
        async with aiohttp.ClientSession(connector=connector) as session:
            if self.evade:
                self.waf_status = await check_for_waf(session, "{0.scheme}://{0.netloc}/".format(urlparse(self.start_url)), self.proxy)
            self._print_banner()
            payloads_to_use = [p for base in self.base_payloads for p in generate_payload_variations(base)] if self.evade else self.base_payloads
            print(f"[*] Total effective payloads to test: {len(payloads_to_use)}")
            await self._crawl_and_scan(session, self.start_url, 0, payloads_to_use)

    def print_summary(self, output_file=None):
        end_time = datetime.now()
        print("\n" + "-" * 50)
        print(f"{Fore.CYAN}Scan Finished{Style.RESET_ALL}")
        print(f"[*] Duration      : {end_time - self.start_time}")
        if not self.results:
            print(f"\n[{Fore.GREEN}SUMMARY{Style.RESET_ALL}] No XSS vulnerabilities found.")
            return
        print(f"\n[{Fore.RED}SUMMARY{Style.RESET_ALL}] Found {len(self.results)} potential vulnerabilities:")
        report_content = f"PoisonXSS Scan Report - {self.start_time.strftime('%Y-%m-%d')}\n\n"
        for res in self.results:
            summary = (f"- URL      : {res['url']}\n" f"  Parameter: {res['param']}\n" f"  Payload  : {res['payload']}\n")
            print(summary)
            report_content += summary + "\n"
        if output_file:
            with open(output_file, 'w') as f: f.write(report_content)
            print(f"\n[{Fore.GREEN}INFO{Style.RESET_ALL}] Report saved to: {output_file}")

def generate_payload_variations(payload):
    variations = {payload}
    variations.add("".join(random.choice([c.upper(), c.lower()]) for c in payload))
    variations.add(quote(payload))
    return list(variations)
    
def main():
    if any(h in sys.argv for h in ['-h', '--help', '--help-syntax']):
        show_help_syntax()
        sys.exit()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--version', action='version', version=f'PoisonXSS {__version__}')
    parser.add_argument("-u", "--url")
    parser.add_argument("-p", "--payloads")
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--evade", action="store_true")
    parser.add_argument("-H", "--headers")
    parser.add_argument("--proxy")
    parser.add_argument("--selenium", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("-w", "--workers", type=int, default=50)
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    if not args.url or not args.payloads:
        print(f"{Fore.RED}Error: Start URL (-u) and payload file (-p) are required.{RESET}\nUse --help-syntax for detailed usage information.")
        return
    try:
        payloads = [line.strip() for line in open(args.payloads) if line.strip()]
        headers = dict(item.split(":", 1) for item in args.headers.split(",")) if args.headers else None
        scanner = PoisonXSS(
            start_url=args.url, payloads=payloads, headers=headers, workers=args.workers,
            evade=args.evade, proxy=args.proxy, verbose=args.verbose, delay=args.delay,
            crawl=args.crawl, depth=args.depth, use_selenium=args.use_selenium
        )
        asyncio.run(scanner.run())
    except FileNotFoundError:
        print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] Payload file not found: {args.payloads}")
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
    finally:
        if 'scanner' in locals() and scanner.results:
            scanner.print_summary(args.output)

if __name__ == "__main__":
    main()