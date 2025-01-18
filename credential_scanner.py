#!/usr/bin/env python3
import os
import re
import sys
import argparse
import requests
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import concurrent.futures
import time

class CredentialScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        # Patterns to detect various credentials
        self.patterns = {
            'API Key': r'(?i)(api[_-]key|apikey|api\s+key)["\s]*[:=]\s*["\']([^"\']+)["\']',
            'Password': r'(?i)(password|passwd|pwd)["\s]*[:=]\s*["\']([^"\']+)["\']',
            'Username': r'(?i)(username|user_name|user)["\s]*[:=]\s*["\']([^"\']+)["\']',
            'Phone Number': r'\b\+?[\d\-\(\)\s]{10,}\b',
            'IP Address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Private Key': r'-----BEGIN\s+PRIVATE\s+KEY-----',
            'Access Token': r'(?i)(access_token|accesstoken)["\s]*[:=]\s*["\']([^"\']+)["\']',
            'Secret Key': r'(?i)(secret[_-]?key|secretkey)["\s]*[:=]\s*["\']([^"\']+)["\']',
            'AWS Key': r'(?i)AKIA[0-9A-Z]{16}',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'SSH Key': r'ssh-rsa\s+AAAA[0-9A-Za-z+/]+[=]{0,3}',
        }

    def download_js_files(self, url: str, output_dir: str) -> List[str]:
        """Download JavaScript files from a given URL."""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Download the main page
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Find all JavaScript file URLs
            js_urls = re.findall(r'src=["\']([^"\']*\.js)["\']', response.text)
            downloaded_files = []

            for js_url in js_urls:
                try:
                    # Handle relative URLs
                    if not js_url.startswith(('http://', 'https://')):
                        if js_url.startswith('//'):
                            js_url = 'https:' + js_url
                        elif js_url.startswith('/'):
                            js_url = f"{url.rstrip('/')}{js_url}"
                        else:
                            js_url = f"{url.rstrip('/')}/{js_url}"

                    # Download JS file
                    if self.verbose:
                        print(f"Downloading: {js_url}")
                    
                    js_response = requests.get(js_url, timeout=10)
                    js_response.raise_for_status()

                    # Generate filename from URL
                    filename = os.path.join(output_dir, os.path.basename(urlparse(js_url).path))
                    if not filename.endswith('.js'):
                        filename += '.js'

                    # Save the file
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(js_response.text)
                    
                    downloaded_files.append(filename)

                except Exception as e:
                    if self.verbose:
                        print(f"Error downloading {js_url}: {str(e)}")

            return downloaded_files

        except Exception as e:
            print(f"Error processing URL {url}: {str(e)}")
            return []

    def find_js_files(self, start_path: str) -> List[str]:
        """Find all .js files in the given directory and subdirectories."""
        js_files = []
        for root, _, files in os.walk(start_path):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(os.path.join(root, file))
        return js_files

    def scan_file(self, file_path: str) -> List[Tuple[str, str, int]]:
        """Scan a single file for credentials."""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
                
            for line_num, line in enumerate(content, 1):
                for cred_type, pattern in self.patterns.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Get the full matched text
                        credential = match.group(0)
                        findings.append((cred_type, credential, line_num))
                        
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {str(e)}")
            
        return findings

    def scan_all_files(self, directory: str) -> Dict[str, List[Tuple[str, str, int]]]:
        """Scan all JS files in the directory for credentials."""
        js_files = self.find_js_files(directory)
        results = {}
        
        if self.verbose:
            print(f"Found {len(js_files)} JavaScript files to scan.")
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_file = {executor.submit(self.scan_file, js_file): js_file for js_file in js_files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                js_file = future_to_file[future]
                try:
                    findings = future.result()
                    if findings:
                        results[js_file] = findings
                except Exception as e:
                    if self.verbose:
                        print(f"Error processing {js_file}: {str(e)}")
                
        return results

def save_results(results: Dict[str, List[Tuple[str, str, int]]], output_file: str):
    """Save scan results to a file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("JavaScript Credential Scan Results\n")
        f.write("=" * 50 + "\n\n")
        
        if not results:
            f.write("No credentials found in any JavaScript files.\n")
            return
        
        for file_path, findings in results.items():
            f.write(f"\nFile: {file_path}\n")
            f.write("-" * 40 + "\n")
            for cred_type, credential, line_num in findings:
                f.write(f"Type: {cred_type}\n")
                f.write(f"Found: {credential}\n")
                f.write(f"Line: {line_num}\n")
                f.write("-" * 20 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Scan JavaScript files for potential credentials and sensitive information.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Scan local directory:
    %(prog)s
  Scan single URL:
    %(prog)s -u https://example.com
  Scan multiple URLs from file:
    %(prog)s -t urls.txt
  Save results to file:
    %(prog)s -o results.txt
  Verbose output with custom temp directory:
    %(prog)s -u https://example.com -v -d /tmp/js_scan
        '''
    )
    
    parser.add_argument('-u', '--url', help='URL to scan for JavaScript files')
    parser.add_argument('-t', '--text-file', help='Text file containing URLs to scan (one per line)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-d', '--temp-dir', default='js_files', help='Temporary directory for downloaded files')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of worker threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for URL requests in seconds (default: 30)')
    
    args = parser.parse_args()
    
    scanner = CredentialScanner(verbose=args.verbose)
    all_results = {}
    start_time = time.time()

    if args.url or args.text_file:
        urls = []
        if args.url:
            urls.append(args.url)
        if args.text_file:
            try:
                with open(args.text_file, 'r') as f:
                    urls.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"Error reading URL file: {str(e)}")
                sys.exit(1)

        for url in urls:
            if args.verbose:
                print(f"\nProcessing URL: {url}")
            
            # Create a unique directory for each URL
            url_dir = os.path.join(args.temp_dir, urlparse(url).netloc)
            js_files = scanner.download_js_files(url, url_dir)
            
            if js_files:
                results = scanner.scan_all_files(url_dir)
                if results:
                    all_results.update(results)
    else:
        # Scan current directory if no URL is provided
        if args.verbose:
            print("Scanning current directory...")
        all_results = scanner.scan_all_files(os.getcwd())

    # Calculate execution time
    execution_time = time.time() - start_time

    # Output results
    if args.output:
        save_results(all_results, args.output)
        print(f"\nResults saved to: {args.output}")
    else:
        if not all_results:
            print("\nNo credentials found in any JavaScript files.")
        else:
            print("\nPotential credentials found:")
            print("-" * 80)
            
            for file_path, findings in all_results.items():
                print(f"\nFile: {file_path}")
                print("-" * 40)
                for cred_type, credential, line_num in findings:
                    print(f"Type: {cred_type}")
                    print(f"Found: {credential}")
                    print(f"Line: {line_num}")
                    print("-" * 20)

    if args.verbose:
        print(f"\nExecution completed in {execution_time:.2f} seconds")

if __name__ == "__main__":
    main()
