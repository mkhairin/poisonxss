# PoisonXSS

PoisonXSS is a powerful, automated tool designed to assist in identifying and exploiting Cross-Site Scripting (XSS) vulnerabilities in web applications. By leveraging customizable payloads, this tool enables security professionals and ethical hackers to test the security of web applications efficiently. PoisonXSS systematically injects user-provided payloads into specified URL parameters, searching for potential vulnerabilities that could be exploited to execute malicious scripts in the context of a user's browser. The tool offers flexibility with payload management, supports both HTTP and HTTPS protocols, and provides detailed logging of activities for tracking test results. Perfect for penetration testing, security assessments, and vulnerability validation, PoisonXSS is an essential tool for securing web applications against XSS attacks.

## Features

- **Custom Payload Execution:** Utilize payloads from a file to streamline the testing process.
- **HTTPS Support:** Allows testing on applications running over HTTPS.
- **Activity Logging:** Logs exploitation results for future reference.

## Installation

1. **Clone the Repository:**
   ```git clone https://github.com/mkhairin/poisonxss cd poisonxss```
2. **Prepare the Environment:**
Ensure Python is installed on your system. If not, download it from [python.org](https://www.python.org/).
3. **Install Dependencies:**
Run the following command to install the required dependencies:
```pip install -r requirements.txt```

## How to Run

Use the following command to run PoisonXSS:
```py.exe .\xss.py -u "https://eduhero.net/courses.php?search=test" -p .\payload.txt```

### Command Options

- `-u`: The target URL to be tested.
- `-p`: The path to the file containing XSS payloads.

### Example Payload

The `payload.txt` file can contain multiple payloads, such as:


## Notes

- **Permission:** Only use this tool for legitimate purposes, such as testing the security of your own web applications or with explicit permission from the application owner.
- **User Responsibility:** You are solely responsible for the usage of this tool.

## License

This project is licensed under the MIT License.

## Contributions

Contributions are always welcome! Fork this repository, make your changes, and submit a pull request.

## Contact

For questions or feedback, please submit an issue on the [Issues page](https://github.com/mkhairin/poisonxss/issues).



