# PoisonXSS

![PoisonXSS Banner](https://github.com/mkhairin/poisonxss/blob/main/img/banner2.png)

PoisonXSS is a fast, flexible, and intelligent vulnerability scanner for Cross-Site Scripting (XSS) and HTML Injection. Built with Python and `asyncio`, PoisonXSS is capable of performing concurrent scans for maximum efficiency.

With features like an automated web crawler, technology fingerprinting, and various testing modes, PoisonXSS is designed for security professionals, bug hunters, and web developers to thoroughly test the security of web applications.

## ✨ Features

- **Asynchronous Scanning:** Extremely fast thanks to `asyncio` and `aiohttp`, capable of handling many requests simultaneously.
- **Dual Testing Modes:** Supports specific testing for both **XSS** and **HTML Injection**.
- **Web Crawler (Spider):** Can automatically crawl a target site to discover and test new pages.
- **Intelligence & Fingerprinting:** Can identify the technology used by the server (e.g., Apache, Nginx, WordPress) to provide context for findings.
- **Dual Target Modes:** Supports testing on a single starting URL (`-u`) or a predefined list of URLs (`-l`).
- **Professional Control:** Full support for proxies, custom headers, request delays, verbose mode, and worker count adjustment.
- **Custom Payloads:** Use your own payload lists from a file for flexible testing.
- **Reporting:** Saves scan results to a `.txt` file for documentation and further analysis.

## ⚙️ Installation

The installation process is quick and easy.

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/mkhairin/poisonxss
    cd poisonxss
    ```

2.  **Install Dependencies:**
    Run the following command in your terminal. It will automatically install all required libraries from the existing `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```
    You are now ready to run PoisonXSS.

## 🚀 Usage

Use the following basic syntax to run a scan:
```bash
python poisonxss.py [TARGET] [PAYLOADS] [OPTIONS]
```

### Command Options

| Flag(s)                         | Description                                                        |
| ------------------------------- | ---------------------------------------------------------------- |
| **Target (Choose one)** |                                                                  |
| `-u URL`, `--url=URL`           | A single starting URL for a scan or crawl.                       |
| `-l FILE`, `--list=FILE`        | A file containing a list of URLs to test.                        |
| **Payloads** |                                                                  |
| `-p FILE`, `--payloads=FILE`    | A file containing XSS payloads (default mode).                   |
| `--payloads-htmli=FILE`         | A file containing HTML Injection payloads (for `--htmli` mode).  |
| **Testing Mode** |                                                                  |
| `--htmli`                       | Switches the testing mode to HTML Injection.                     |
| **Crawler (Only with `-u`)** |                                                                  |
| `--crawl`                       | Enables the web crawler from the start URL.                      |
| `--depth=DEPTH`                 | Sets the maximum crawl depth (default: 2).                       |
| **Intelligence** |                                                                  |
| `--fingerprint`                 | Enables technology fingerprinting.                               |
| **Request & Control** |                                                                  |
| `-H HEADERS`, `--headers=HEADERS` | Custom headers, comma-separated (e.g., `"Cookie:id=123"`).       |
| `--proxy=PROXY`                 | Uses a proxy (e.g., `http://127.0.0.1:8080`).                    |
| `-v`, `--verbose`               | Displays detailed output, including safe requests.               |
| `--delay=DELAY`                 | Adds a delay in seconds between each request.                    |
| `-w NUM`, `--workers=NUM`       | Number of concurrent workers (default: 50).                      |
| `-o FILE`, `--output=FILE`      | Saves the scan report to a file.                                 |
| **Other** |                                                                  |
| `--help-syntax`                 | Shows this detailed help guide.                                  |
| `--version`                     | Shows the program's version number.                              |

### Usage Examples

**1. Basic XSS Scan on a Single URL**
```bash
python poisonxss.py -u "[http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1)" -p payloads.txt
```

**2. Scan a List of URLs from a File**
```bash
python poisonxss.py -l urls.txt -p payloads.txt -v
```

**3. Run the Crawler with a Depth of 3**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) -p payloads.txt --crawl --depth 3
```

**4. HTML Injection Scan Using Built-in Payloads**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) --htmli
```

**5. Advanced Scan: Crawler + Fingerprinting + Verbose + Proxy**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) -p payloads.txt --crawl --fingerprint -v --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080)
```

## ⚠️ Disclaimer

- **Permission:** Only use this tool for legitimate purposes, such as testing the security of your own web applications or with explicit permission from the application owner.
- **Responsibility:** You are solely responsible for your use of this tool.

## License

This project is licensed under the MIT License.

## Contributions

Contributions are always welcome! Fork this repository, make your changes, and submit a pull request.
