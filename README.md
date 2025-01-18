# Credential Scanner

`Credential Scanner` is a Python-based tool designed to scan JavaScript files for sensitive information, such as API keys, passwords, private keys, and other credentials. This tool can scan local directories, individual URLs, or a list of URLs and extract potential credentials for security audits and penetration testing.

## Features
- Identify various types of credentials, including API keys, passwords, usernames, phone numbers, and more.
- Download and scan JavaScript files from provided URLs.
- Scan all `.js` files within a specified directory.
- Multithreaded scanning for faster performance.
- Save scan results to a file.
- Verbose mode for detailed logging.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vraj002/credential_scanner
   cd credential_scanner
   ```

2. Make the script executable:
   ```bash
   chmod +x creditals_scanner.py
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script using the command line:

- **Scan a local directory:**
  ```bash
  python3 creditals_scanner.py
  ```

- **Scan a single URL:**
  ```bash
  python3 creditals_scanner.py -u https://example.com
  ```

- **Scan multiple URLs from a file:**
  ```bash
  python3 creditals_scanner.py -t urls.txt
  ```

- **Save results to a file:**
  ```bash
  python3 creditals_scanner.py -o results.txt
  ```

- **Enable verbose output and specify a temporary directory:**
  ```bash
  python3 creditals_scanner.py -u https://example.com -v -d /tmp/js_scan
  ```

### Command-Line Options
- `-u, --url`: URL to scan for JavaScript files.
- `-t, --text-file`: File containing a list of URLs to scan (one per line).
- `-o, --output`: Save results to a specified file.
- `-d, --temp-dir`: Specify a temporary directory for downloaded files (default: `js_files`).
- `-v, --verbose`: Enable verbose output for detailed logging.
- `-w, --workers`: Number of worker threads (default: 5).
- `--timeout`: Timeout for URL requests in seconds (default: 30).

## Examples

- **Scan URL and save the output:**
  ```bash
  python3 creditals_scanner.py -u urls.txt -o output.txt
  ```

- **Scan multiple URLs and save the output:**
  ```bash
  python3 creditals_scanner.py -t urls.txt -o output.txt
  ```

## License
This project is licensed under the MIT License.

## Copyright
Copyright © 2025 Vraj Patel. All rights reserved. Unauthorized duplication or distribution of this code is strictly prohibited without prior written permission from the author.

## Contribution
Feel free to fork this repository, make improvements, and submit a pull request. Contributions are always welcome!

## Disclaimer
This tool is intended for educational and ethical purposes only. Unauthorized scanning of websites or servers without proper authorization is illegal and punishable by law. Always obtain permission before using this tool on any website or server.

