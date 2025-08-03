#
# PoisonXSS - Version 2.4 (Final)
# Enhanced from the original code by Muhammad Khairin.
#
# Key Features in Version 2.4:
# - Added Web Crawler (--crawl) to automatically discover and test links/forms.
# - Includes Evasion, Control & Finesse modules.
# - The ultimate version combining all previous enhancements.
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


# Initialize colorama
init(autoreset=True)


def show_help_syntax():
    """Displays a detailed help guide for the tool's syntax and usage."""
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RESET = Style.RESET_ALL

    print(f"\n{CYAN} PoisonXSS v2.4 - Syntax and Usage Guide {RESET}")
    print("-" * 50)
    print(f"{YELLOW}Usage:{RESET}")
    print(
        f"  python poisonxss.py -u <STARTING_URL> -p <PAYLOAD_FILE> [OPTIONS]\n")

    print(f"{YELLOW}Core Arguments (Required):{RESET}")
    print(f"  {GREEN}-u, --url <URL>{RESET}")
    print(f"    Specifies the starting URL for the scan and crawl.\n")
    print(f"  {GREEN}-p, --payloads <FILE_PATH>{RESET}")
    print(f"    Specifies a file containing a list of XSS payloads.\n")

    print(f"{YELLOW}Crawler Options (Optional):{RESET}")
    print(f"  {GREEN}--crawl{RESET}")
    print(f"    Enables the web crawler to discover new pages to test.\n")
    print(f"  {GREEN}--depth <NUMBER>{RESET}")
    print(f"    Sets the maximum depth for the crawler to explore. Default is 2.\n")

    print(f"{YELLOW}Evasion Options (Optional):{RESET}")
    print(f"  {GREEN}--evade{RESET}")
    print(f"    Enables evasion techniques: dynamic payload generation and WAF detection.\n")

    print(f"{YELLOW}Request Options (Optional):{RESET}")
    print(f"  {GREEN}-m, --method <GET/POST>{RESET}")
    print(f"    Sets the HTTP method for testing forms. Default is GET.\n")
    print(f"  {GREEN}-H, --headers <HEADERS>{RESET}")
    print(f"    Custom headers, separated by commas (e.g., 'Cookie:id=123').\n")

    print(f"{YELLOW}Control & Finesse Options (Optional):{RESET}")
    print(f"  {GREEN}--proxy <PROXY_URL>{RESET}")
    print(f"    Routes traffic through a proxy. Example: http://127.0.0.1:8080\n")
    print(f"  {GREEN}-v, --verbose{RESET}")
    print(f"    Displays detailed output, including safe requests.\n")
    print(f"  {GREEN}--delay <SECONDS>{RESET}")
    print(f"    Adds a delay (in seconds) between each request. Example: 0.1\n")

    print(f"{YELLOW}Scanner Options (Optional):{RESET}")
    print(f"  {GREEN}-w, --workers <NUMBER>{RESET}")
    print(f"    Number of concurrent workers. Default is 50.\n")
    print(f"  {GREEN}-o, --output <FILE_PATH>{RESET}")
    print(f"    Saves the scan report to a file.\n")


# --- Helper functions from previous versions ---
def generate_payload_variations(payload):
    variations = {payload}
    variations.add("".join(random.choice(
        [c.upper(), c.lower()]) for c in payload))
    variations.add(quote(payload))
    return list(variations)


async def check_for_waf(session, base_url, proxy):
    malicious_payload = "<script>alert('WAF_DETECTION')</script>"
    waf_test_url = f"{base_url}?waf_test={malicious_payload}"
    try:
        async with session.get(waf_test_url, proxy=proxy, timeout=10) as response:
            text = await response.text()
            if response.status in (403, 406, 501):
                return f"Detected (Status Code: {response.status})"
            if any(keyword in text.lower() for keyword in ["waf", "firewall", "forbidden", "blocked", "cloudflare", "incapsula"]):
                return "Detected (Found keywords in response)"
    except Exception:
        return "Unknown (Error during check)"
    return "Not Detected"

# --- Main Scanner Class ---


class PoisonXSS:
    def __init__(self, start_url, payloads, method='GET', headers=None, workers=50, evade=False, proxy=None, verbose=False, delay=0, crawl=False, depth=2):
        self.start_url = start_url
        self.base_payloads = payloads
        self.method = method.upper()
        self.headers = headers or {"User-Agent": "PoisonXSS/2.4"}
        self.workers = workers
        self.results = []
        self.start_time = datetime.now()
        # Modules
        self.evade = evade
        self.proxy = proxy
        self.verbose = verbose
        self.delay = delay
        self.crawl = crawl
        self.depth = depth
        # Crawler state
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
        print(
            f"{Fore.CYAN}PoisonXSS v2.4 [Final]{Style.RESET_ALL} | The All-in-One XSS Scanner | Created by Muhammad Khairin")
        print(
            f"[*] Start Time    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Start URL     : {self.start_url}")
        print(f"[*] Base Payloads : {len(self.base_payloads)} loaded")
        if self.crawl:
            print(
                f"[*] Crawler Mode  : {Fore.GREEN}Enabled (Depth: {self.depth}){Style.RESET_ALL}")
        if self.evade:
            print(f"[*] Evasion Mode  : {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.waf_status != "Not Checked":
            print(
                f"[*] WAF Status    : {Fore.YELLOW}{self.waf_status}{Style.RESET_ALL}")
        if self.proxy:
            print(f"[*] Proxy         : {self.proxy}")
        print(f"[*] Workers       : {self.workers}")
        print("-" * 50)

    async def _test_url_for_xss(self, session, url, payloads_to_use):
        """Tests a single URL's parameters for XSS vulnerabilities."""
        tasks = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []

        for param_name in params:
            for payload in payloads_to_use:
                modified_params = {**params, param_name: [payload]}
                query_string = urlencode(modified_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                tasks.append(self._fetch_and_check(session, test_url, {
                             'param_name': param_name, 'original_payload': payload}))

        await asyncio.gather(*tasks)

    async def _fetch_and_check(self, session, url, payload_info):
        """The core worker function that sends a request and checks the response."""
        param_name = payload_info['param_name']
        original_payload = payload_info['original_payload']
        is_vulnerable = False

        try:
            async with session.get(url, headers=self.headers, proxy=self.proxy, timeout=15) as response:
                response_text = await response.text()

                if original_payload in response_text and not ("&lt;" in response_text or "&gt;" in response_text):
                    is_vulnerable = True
                    result = {"url": str(
                        response.url), "param": param_name, "payload": original_payload, "method": "GET"}
                    print(
                        f"[{Fore.RED}VULNERABLE{Style.RESET_ALL}] GET | Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} | URL: {result['url']}")
                    self.results.append(result)
        except Exception:
            pass

        if self.verbose and not is_vulnerable:
            print(f"[{Fore.GREEN}SAFE{Style.RESET_ALL}] Param: {Fore.CYAN}{param_name}{Style.RESET_ALL} | Payload: {original_payload[:30]}...")

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        return is_vulnerable

    async def _crawl_and_scan(self, session, url, current_depth, payloads_to_use):
        """Main function for a single URL: scan it, then find more links."""
        if current_depth > self.depth or url in self.scanned_urls or urlparse(url).netloc != urlparse(self.start_url).netloc:
            return []

        if self.verbose:
            print(
                f"[{Fore.BLUE}CRAWLING{Style.RESET_ALL}] Depth: {current_depth} | URL: {url}")

        self.scanned_urls.add(url)
        new_links = set()

        try:
            # 1. Fetch the page content
            async with session.get(url, proxy=self.proxy, headers=self.headers, timeout=15) as response:
                if "text/html" not in response.headers.get('Content-Type', ''):
                    return []  # Don't parse non-html pages
                html_content = await response.text()

            # 2. Test the current URL for XSS
            await self._test_url_for_xss(session, url, payloads_to_use)

            # 3. Parse for new links if crawling is enabled
            if self.crawl:
                soup = BeautifulSoup(html_content, 'lxml')
                for a_tag in soup.find_all('a', href=True):
                    link = a_tag['href']
                    # Make absolute and remove fragments
                    abs_link = urljoin(url, link).split('#')[0]
                    if urlparse(abs_link).scheme in ['http', 'https']:
                        new_links.add(abs_link)
        except Exception:
            pass  # Ignore errors during crawling

        # Recursively call crawl_and_scan for new links
        tasks = [self._crawl_and_scan(session, link, current_depth + 1, payloads_to_use)
                 for link in new_links if link not in self.scanned_urls]
        await asyncio.gather(*tasks)

    async def run(self):
        connector = aiohttp.TCPConnector(
            ssl=False, limit_per_host=self.workers)

        async with aiohttp.ClientSession(connector=connector) as session:
            if self.evade:
                base_url = "{0.scheme}://{0.netloc}/".format(
                    urlparse(self.start_url))
                self.waf_status = await check_for_waf(session, base_url, self.proxy)

            self._print_banner()

            payloads_to_use = [p for base in self.base_payloads for p in generate_payload_variations(
                base)] if self.evade else self.base_payloads
            print(
                f"[*] Total effective payloads to test: {len(payloads_to_use)}")

            # Start the crawl and scan process
            await self._crawl_and_scan(session, self.start_url, 0, payloads_to_use)

    def print_summary(self, output_file=None):
        # ... (This function remains unchanged) ...
        end_time = datetime.now()
        duration = end_time - self.start_time
        print("\n" + "-" * 50)
        print(f"{Fore.CYAN}Scan Finished{Style.RESET_ALL}")
        print(f"[*] End Time      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Duration      : {duration}")
        if not self.results:
            print(
                f"\n[{Fore.GREEN}SUMMARY{Style.RESET_ALL}] No XSS vulnerabilities found.")
            return
        print(
            f"\n[{Fore.RED}SUMMARY{Style.RESET_ALL}] Found {len(self.results)} potential vulnerabilities:")
        report_content = f"PoisonXSS Scan Report - {self.start_time.strftime('%Y-%m-%d')}\n\n"
        for res in self.results:
            summary = (
                f"- URL      : {res['url']}\n" f"  Method   : {res['method']}\n" f"  Parameter: {res['param']}\n" f"  Payload  : {res['payload']}\n")
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

# --- Main execution block ---


def main():
    if '--help-syntax' in sys.argv:
        show_help_syntax()
        sys.exit()

    parser = argparse.ArgumentParser(
        description="PoisonXSS v2.4", add_help=False)

    parser.add_argument('-h', '--help', '--help-syntax', action='store_true',
                        help='Show the detailed help message and exit')

    # Core arguments
    core_group = parser.add_argument_group('Core Arguments')
    core_group.add_argument(
        "-u", "--url", help="The starting URL for the scan/crawl")
    core_group.add_argument(
        "-p", "--payloads", help="A file containing XSS payloads")

    # Crawler Options
    crawl_group = parser.add_argument_group('Crawler Options')
    crawl_group.add_argument(
        "--crawl", action="store_true", help="Enable the web crawler")
    crawl_group.add_argument(
        "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")

    # Evasion & Request
    req_group = parser.add_argument_group('Request & Evasion Options')
    req_group.add_argument("--evade", action="store_true",
                           help="Enable evasion techniques")
    req_group.add_argument(
        "-H", "--headers", help="Custom headers, comma-separated")

    # Control & Finesse
    control_group = parser.add_argument_group('Control & Finesse Options')
    control_group.add_argument(
        "--proxy", help="Route traffic through a proxy (e.g., http://127.0.0.1:8080)")
    control_group.add_argument(
        "-v", "--verbose", action="store_true", help="Display detailed scan output")
    control_group.add_argument(
        "--delay", type=float, default=0, help="Add a delay between requests (seconds)")

    # General
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument(
        "-w", "--workers", type=int, default=50, help="Number of concurrent workers")
    general_group.add_argument(
        "-o", "--output", help="Output file for the report")

    args = parser.parse_args()

    if args.help:
        show_help_syntax()
        return

    if not args.url or not args.payloads:
        print(f"{Fore.RED}Error: Start URL (-u) and payload file (-p) are required.{RESET}\nUse --help-syntax for detailed usage information.")
        return

    payloads = [line.strip() for line in open(args.payloads) if line.strip()]
    if not payloads:
        print(
            f"[{Fore.RED}ERROR{Style.RESET_ALL}] No payloads loaded from {args.payloads}")
        return

    headers = dict(item.split(":", 1)
                   for item in args.headers.split(",")) if args.headers else None

    scanner = PoisonXSS(
        start_url=args.url, payloads=payloads, headers=headers, workers=args.workers,
        evade=args.evade, proxy=args.proxy, verbose=args.verbose, delay=args.delay,
        crawl=args.crawl, depth=args.depth
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
    finally:
        scanner.print_summary(args.output)


if __name__ == "__main__":
    main()
