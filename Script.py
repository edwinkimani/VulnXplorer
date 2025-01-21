import requests
import pyfiglet
import os
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def display_banner():
    banner_text = pyfiglet.figlet_format("VulnXplorer")
    print(Fore.CYAN + banner_text + Style.RESET_ALL)
    print(Fore.GREEN + "Created by: Edwin ngila kyalo".center(80) + Style.RESET_ALL)
    print(Fore.YELLOW + "Version: 1.1.0".center(80) + Style.RESET_ALL)
    print(Fore.MAGENTA + "=" * 80 + Style.RESET_ALL)

    print(Fore.LIGHTBLUE_EX + "Welcome to VulnXplorer - A Web Vulnerability Scanner!".center(80) + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + """
This tool helps security researchers and developers identify common 
vulnerabilities in web applications. Use responsibly and with authorization.

Features:
[1] SQL Injection Scan      - Identify SQL injection vulnerabilities.
[2] XSS Scan                - Detect Cross-Site Scripting issues.
[3] Header Analysis         - Analyze HTTP headers for security weaknesses.
[4] Common Files/Paths Scan - Locate potentially sensitive files or paths.
[5] Directory Traversal     - Test for directory traversal vulnerabilities.
[6] Dynamic Payload Testing - Test custom payloads dynamically.
    """.strip() + Style.RESET_ALL)

    print(Fore.YELLOW + "\nNote: Always have explicit permission before scanning any target!".center(
        80) + Style.RESET_ALL)
    print(Fore.MAGENTA + "=" * 80 + Style.RESET_ALL)


def main_menu():
    """Display the main menu and handle user selection."""
    while True:
        print(Fore.CYAN + "\n[1] SQL Injection Scan" + Style.RESET_ALL)
        print(Fore.CYAN + "[2] XSS Scan" + Style.RESET_ALL)
        print(Fore.CYAN + "[3] Header Analysis" + Style.RESET_ALL)
        print(Fore.CYAN + "[4] Common Files/Paths Scan" + Style.RESET_ALL)
        print(Fore.CYAN + "[5] Directory Traversal Scan" + Style.RESET_ALL)
        print(Fore.CYAN + "[6] Dynamic Payload Testing" + Style.RESET_ALL)
        print(Fore.CYAN + "[7] Back" + Style.RESET_ALL)
        print(Fore.RED + "[0] Exit" + Style.RESET_ALL)

        choice = input(Fore.YELLOW + "\nEnter your choice: " + Style.RESET_ALL).strip()

        if choice == "1":
            url = input(Fore.YELLOW + "Enter the target URL for SQL Injection scan (eg: http://example.com/search?q=test): " + Style.RESET_ALL).strip()
            response = validate_url(url)
            if response:
                findings = test_sql_injection(url)
                if findings:
                    print(Fore.GREEN + "\nSQL Injection findings:" + Style.RESET_ALL)
                    for finding in findings:
                        print(finding)
        elif choice == "2":
            url = input(Fore.YELLOW + "Enter the target URL for XSS scan(eg: http://example.com/search?=test): " + Style.RESET_ALL).strip()
            findings = test_xss(url)
            if findings:
                print(Fore.GREEN + "\nXSS findings:" + Style.RESET_ALL)
                for finding in findings:
                    print(finding)
        elif choice == "3":
            url = input(Fore.YELLOW + "Enter the target URL for Header Analysis: " + Style.RESET_ALL).strip()
            findings = analyze_headers(url)
            if findings:
                print(Fore.GREEN + "\nHeader Analysis findings:" + Style.RESET_ALL)
                for finding in findings:
                    print(finding)
        elif choice == "4":
            url = input(Fore.YELLOW + "Enter the target URL for Common Files/Paths scan: " + Style.RESET_ALL).strip()
            findings = test_common_files(url)
            if findings:
                print(Fore.GREEN + "\nCommon Files/Paths findings:" + Style.RESET_ALL)
                for finding in findings:
                    print(finding)
        elif choice == "5":
            url = input(Fore.YELLOW + "Enter the target URL for Directory Traversal scan: " + Style.RESET_ALL).strip()
            findings = test_directory_traversal(url)
            if findings:
                print(Fore.GREEN + "\nDirectory Traversal findings:" + Style.RESET_ALL)
                for finding in findings:
                    print(finding)
        elif choice == "6":
            url = input(Fore.YELLOW + "Enter the target URL for Dynamic Payload Testing scan: " + Style.RESET_ALL).strip()
            findings = dynamic_payload_testing(url)
            if findings:
                print(Fore.GREEN + "\nDynamic Payload Testing:" + Style.RESET_ALL)
                for finding in findings:
                    print(finding)
        elif choice == "7":
            print(Fore.YELLOW + "Returning to previous menu..." + Style.RESET_ALL)
            return
        elif choice == "0":
            print(Fore.RED + "Exiting the program..." + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)


def validate_url(url):
    """Validate the target URL."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })

    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] URL is valid: {url}" + Style.RESET_ALL)
            return response
        else:
            print(Fore.RED + f"[-] URL returned status code {response.status_code}" + Style.RESET_ALL)
            return None
    except Exception as e:
        print(Fore.RED + f"[-] Error validating URL: {e}" + Style.RESET_ALL)
        return None

def load_wordlist(os_type):
    """Load the appropriate word list based on the operating system (Linux/Windows)."""
    wordlist_path = "./utilities"
    linux_wordlist = os.path.join(wordlist_path, "Linux-Sensitive-Files.txt")
    windows_wordlist = os.path.join(wordlist_path, "Windows-Sensitive-Files.txt")

    if os_type.lower() == "linux" and os.path.exists(linux_wordlist):
        with open(linux_wordlist, 'r') as file:
            payloads = file.readlines()
        print(Fore.GREEN + "[+] Loaded Linux word list." + Style.RESET_ALL)
    elif os_type.lower() == "windows" and os.path.exists(windows_wordlist):
        with open(windows_wordlist, 'r') as file:
            payloads = file.readlines()
        print(Fore.GREEN + "[+] Loaded Windows word list." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No valid word list found for the specified OS." + Style.RESET_ALL)
        payloads = []

    # Strip newline characters from each line
    return [payload.strip() for payload in payloads]

def detect_os(response):
    """Detect the server's operating system based on the response headers."""
    server_header = response.headers.get('Server', '').lower()

    if 'windows' in server_header:
        return 'windows'
    elif 'linux' in server_header:
        return 'linux'
    else:
        print(Fore.YELLOW + "[-] Unable to detect server OS." + Style.RESET_ALL)
        return 'unknown'

def test_sql_injection(url):
    """Test for SQL Injection vulnerabilities using payloads from a file."""
    findings = []
    print(Fore.YELLOW + "\n[*] Testing SQL Injection..." + Style.RESET_ALL)

    # Load SQL Injection payloads from the file
    payloads = []
    try:
        with open('./utilities/SQL-Injection-Payloads.txt', 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]
        print(Fore.CYAN + f"[+] Loaded {len(payloads)} SQL injection payloads from file." + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "[-] Payload file not found!" + Style.RESET_ALL)
        return findings
    except Exception as e:
        print(Fore.RED + f"[-] Error loading payloads: {e}" + Style.RESET_ALL)
        return findings

    # Parse URL and extract query parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        print(Fore.RED + "[-] No query parameters detected in the URL. Cannot test for SQL injection." + Style.RESET_ALL)
        return findings

    # SQL error signatures to look for
    sql_error_signatures = [
        "syntax error", "mysql", "sql", "query failed", "unclosed quotation mark",
        "oracle", "native client", "unexpected error", "database error",
        "warning: pg_", "postgresql", "sqlite", "mssql"
    ]

    # Initialize a counter for vulnerabilities found
    vulnerability_count = 0
    max_vulnerabilities = 10

    # Loop through query parameters and test with each payload
    for param in query_params:
        for payload in payloads:
            if vulnerability_count >= max_vulnerabilities:
                print(Fore.GREEN + f"[!] Maximum vulnerability limit ({max_vulnerabilities}) reached. Exiting." + Style.RESET_ALL)
                return findings

            # Inject payload into the current parameter
            test_params = query_params.copy()
            test_params[param] = payload

            # Reconstruct the URL with the payload
            modified_query = urlencode(test_params, doseq=True)
            injected_url = urlunparse(parsed_url._replace(query=modified_query))

            try:
                response = requests.get(injected_url, timeout=5)

                if response.status_code == 200:
                    # Check for error messages indicating SQL issues
                    for signature in sql_error_signatures:
                        if signature.lower() in response.text.lower():
                            finding = (f"[!] Possible SQL Injection vulnerability detected: "
                                       f"Parameter: '{param}', Payload: '{payload}', "
                                       f"Error signature: '{signature}'")
                            print(Fore.GREEN + finding + Style.RESET_ALL)
                            findings.append(finding)
                            vulnerability_count += 1
                            break
                    else:
                        print(Fore.YELLOW + f"[-] No vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"[-] Received non-200 status code: {response.status_code}" + Style.RESET_ALL)

            except Exception as e:
                print(Fore.RED + f"[-] Error testing payload '{payload}': {e}" + Style.RESET_ALL)

    if not findings:
        print(Fore.YELLOW + "[*] No SQL Injection vulnerabilities detected." + Style.RESET_ALL)
    return findings

def test_xss(url):
    """Test for XSS vulnerabilities using payloads from a file."""
    findings = []
    print(Fore.YELLOW + "\n[*] Testing XSS..." + Style.RESET_ALL)

    # Load XSS payloads from the file
    payloads = []
    try:
        with open('./utilities/Cross-Site-Scripting-XSS-Payloads.txt', 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]
        print(Fore.CYAN + f"[+] Loaded {len(payloads)} payloads from file." + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "[-] Payload file not found!" + Style.RESET_ALL)
        return findings
    except Exception as e:
        print(Fore.RED + f"[-] Error loading payloads: {e}" + Style.RESET_ALL)
        return findings

    # Parse URL and extract query parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        print(Fore.RED + "[-] No query parameters detected in the URL. Cannot test for XSS." + Style.RESET_ALL)
        return findings

    # Loop through query parameters and test with each payload
    for param in query_params:
        for payload in payloads:
            # Inject payload into the current parameter
            test_params = query_params.copy()
            test_params[param] = payload

            # Reconstruct the URL with the payload
            modified_query = urlencode(test_params, doseq=True)
            injected_url = urlunparse(parsed_url._replace(query=modified_query))

            try:
                response = requests.get(injected_url, timeout=5)

                # Check for reflected payloads in the response
                if payload in response.text:
                    finding = f"[!] Possible XSS vulnerability in parameter '{param}' with payload: {payload}"
                    print(Fore.GREEN + finding + Style.RESET_ALL)
                    findings.append(finding)
                else:
                    print(Fore.YELLOW + f"[-] No vulnerability detected with payload: {payload}" + Style.RESET_ALL)

            except Exception as e:
                print(Fore.RED + f"[-] Error testing payload '{payload}': {e}" + Style.RESET_ALL)

    if not findings:
        print(Fore.YELLOW + "[*] No XSS vulnerabilities detected." + Style.RESET_ALL)
    return findings

def analyze_headers(url):
    """Analyze HTTP headers for security vulnerabilities."""
    findings = []
    print(Fore.YELLOW + "\n[*] Analyzing Headers..." + Style.RESET_ALL)

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Common security headers to check
        security_headers = {
            "Content-Security-Policy": "Protects against XSS attacks by restricting sources of content.",
            "Strict-Transport-Security": "Enforces secure (HTTPS) connections to the server.",
            "X-Frame-Options": "Prevents clickjacking attacks by disallowing iframe embedding.",
            "X-Content-Type-Options": "Prevents MIME-type sniffing by specifying a strict content type.",
            "Referrer-Policy": "Controls the information sent in the Referer header.",
            "Permissions-Policy": "Controls access to browser features like camera, microphone, etc.",
        }

        # Check each security header
        for header, description in security_headers.items():
            if header in headers:
                findings.append(f"[+] {header}: Present - {headers[header]}")
                print(Fore.GREEN + f"[+] {header}: Present - {headers[header]}" + Style.RESET_ALL)
            else:
                findings.append(f"[-] {header}: Missing - {description}")
                print(Fore.RED + f"[-] {header}: Missing - {description}" + Style.RESET_ALL)

        # Check for Server and X-Powered-By headers (information disclosure)
        if "Server" in headers:
            findings.append(f"[!] Server header: Present - {headers['Server']}")
            print(Fore.YELLOW + f"[!] Server header: Present - {headers['Server']}" + Style.RESET_ALL)
        else:
            findings.append("[+] Server header: Not disclosed")
            print(Fore.GREEN + "[+] Server header: Not disclosed" + Style.RESET_ALL)

        if "X-Powered-By" in headers:
            findings.append(f"[!] X-Powered-By header: Present - {headers['X-Powered-By']}")
            print(Fore.YELLOW + f"[!] X-Powered-By header: Present - {headers['X-Powered-By']}" + Style.RESET_ALL)
        else:
            findings.append("[+] X-Powered-By header: Not disclosed")
            print(Fore.GREEN + "[+] X-Powered-By header: Not disclosed" + Style.RESET_ALL)

    except Exception as e:
        findings.append(f"[-] Error analyzing headers: {e}")
        print(Fore.RED + f"[-] Error analyzing headers: {e}" + Style.RESET_ALL)

    if not findings:
        print(Fore.YELLOW + "[*] No significant header issues found." + Style.RESET_ALL)

    return findings

def test_common_files(url):
    """Test for common files and directories."""
    findings = []
    print(Fore.YELLOW + "\n[*] Testing for common files..." + Style.RESET_ALL)

    try:
        # Load the wordlist
        wordlist_path = "./utilities/common_paths.txt"
        if not os.path.exists(wordlist_path):
            print(Fore.RED + f"[-] Wordlist not found: {wordlist_path}" + Style.RESET_ALL)
            return findings

        with open(wordlist_path, "r") as file:
            common_paths = [line.strip() for line in file if line.strip()]

        # Prompt user for limit or use default
        limit = input(Fore.YELLOW + "Enter the limit for findings (default is 10): " + Style.RESET_ALL).strip()
        limit = int(limit) if limit.isdigit() else 10

        print(Fore.CYAN + f"\n[*] Using a findings limit of {limit}" + Style.RESET_ALL)

        # Test each path in the wordlist
        for count, path in enumerate(common_paths, start=1):
            test_url = f"{url.rstrip('/')}/{path}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    findings.append(f"[+] Found: {test_url} (Status: 200 OK)")
                    print(Fore.GREEN + f"[+] Found: {test_url} (Status: 200 OK)" + Style.RESET_ALL)
                elif response.status_code in [403, 401]:
                    findings.append(f"[!] Restricted: {test_url} (Status: {response.status_code})")
                    print(Fore.YELLOW + f"[!] Restricted: {test_url} (Status: {response.status_code})" + Style.RESET_ALL)

                # Stop if the findings exceed the limit
                if len(findings) >= limit:
                    print(Fore.RED + f"\n[!] Limit of {limit} findings reached. Exiting scan." + Style.RESET_ALL)
                    break
            except Exception as e:
                print(Fore.RED + f"[-] Error accessing {test_url}: {e}" + Style.RESET_ALL)

        if not findings:
            print(Fore.YELLOW + "[*] No common files or directories found." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[-] Error during common files scan: {e}" + Style.RESET_ALL)

    return findings

def test_directory_traversal(url):
    """Test for directory traversal vulnerabilities based on the server's OS."""
    findings = []
    print(Fore.YELLOW + "\n[*] Testing Directory Traversal..." + Style.RESET_ALL)

    # Send a request to detect the server OS
    try:
        response = requests.get(url, timeout=5)
        os_type = detect_os(response)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Error while detecting OS: {e}" + Style.RESET_ALL)
        return findings

    if os_type == 'unknown':
        print(Fore.RED + "[-] Could not determine OS type. Proceeding with both payload sets." + Style.RESET_ALL)
        # Load both payload lists if OS cannot be detected
        linux_payloads = load_wordlist("linux")
        windows_payloads = load_wordlist("windows")
        payloads = linux_payloads + windows_payloads
    else:
        # Load word list based on detected OS type
        payloads = load_wordlist(os_type)

    if not payloads:
        print(Fore.RED + "[-] No payloads loaded. Test cannot proceed." + Style.RESET_ALL)
        return findings

    # Check if the URL already has query parameters
    delimiter = "&" if "?" in url else "?"

    # Loop through the payloads
    for payload in payloads:
        test_url = f"{url}{delimiter}file={payload}"
        print(Fore.CYAN + f"[+] Testing: {test_url}" + Style.RESET_ALL)

        try:
            # Send a GET request to the URL
            response = requests.get(test_url, timeout=5)

            # Check for potential signs of a vulnerability
            if "root:x" in response.text or "boot loader" in response.text or "kernel32" in response.text:
                findings.append(f"Potential vulnerability detected at: {test_url}")
                print(Fore.RED + f"[!] Vulnerability detected: {test_url}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "[+] No issues detected." + Style.RESET_ALL)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Error while testing {test_url}: {e}" + Style.RESET_ALL)

    # Output results
    if findings:
        print(Fore.RED + f"\n[!] Found {len(findings)} potential vulnerabilities:" + Style.RESET_ALL)
        for finding in findings:
            print(f"- {finding}")
    else:
        print(Fore.GREEN + "\n[+] No directory traversal vulnerabilities found." + Style.RESET_ALL)

    return findings

def dynamic_payload_testing(url):
    """Test for dynamic payload vulnerabilities (e.g., XSS, SQL Injection)."""
    findings = []
    print(Fore.YELLOW + "\n[*] Testing Dynamic Payloads..." + Style.RESET_ALL)

    # List of sample payloads for testing
    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        '" OR ""="',
        "<script>alert('XSS')</script>",
        "' UNION SELECT null, username, password FROM users --"
    ]

    # Check if the URL already has query parameters
    delimiter = "&" if "?" in url else "?"

    # Loop through each payload and test it
    for payload in payloads:
        test_url = f"{url}{delimiter}input={payload}"
        print(Fore.CYAN + f"[+] Testing: {test_url}" + Style.RESET_ALL)

        try:
            # Send a GET request with the payload
            response = requests.get(test_url, timeout=5)

            # Check for potential signs of a vulnerability
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                findings.append(f"Potential vulnerability detected at: {test_url}")
                print(Fore.RED + f"[!] Vulnerability detected: {test_url}" + Style.RESET_ALL)
            elif "<script>alert('XSS')</script>" in response.text:
                findings.append(f"XSS vulnerability detected at: {test_url}")
                print(Fore.RED + f"[!] XSS vulnerability detected: {test_url}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "[+] No issues detected." + Style.RESET_ALL)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Error while testing {test_url}: {e}" + Style.RESET_ALL)

    # Output results
    if findings:
        print(Fore.RED + f"\n[!] Found {len(findings)} potential vulnerabilities:" + Style.RESET_ALL)
        for finding in findings:
            print(f"- {finding}")
    else:
        print(Fore.GREEN + "\n[+] No dynamic payload vulnerabilities found." + Style.RESET_ALL)

    return findings

if __name__ == "__main__":
    display_banner()
    main_menu()
