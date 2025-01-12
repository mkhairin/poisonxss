# PoisonXSS

PoisonXSS is a tool designed for automating the exploitation of Cross-Site Scripting (XSS) vulnerabilities. This tool allows security testing of web applications by using a payload provided by the user to identify and exploit potential XSS vulnerabilities.

## Features

- **Custom Payload Execution:** Utilize payloads from a file to streamline the testing process.
- **HTTPS Support:** Allows testing on applications running over HTTPS.
- **Activity Logging:** Logs exploitation results for future reference.

## Installation

1. **Clone the Repository:**
   ```git clone https://github.com/mkhairin/poisonxss cd poisonxss```
3. **Prepare the Environment:**
Ensure Python is installed on your system. If not, download it from [python.org](https://www.python.org/).

4. **Install Dependencies:**
Run the following command to install the required dependencies:


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



