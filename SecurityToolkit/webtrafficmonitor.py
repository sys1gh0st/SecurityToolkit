import scapy.all as scapy # Packet manipulation and network traffic analysis
from bs4 import BeautifulSoup # Used to extract and examine forms, scripts, and inputs
import requests # For making HTTP requests to test web applications
import threading # For running tests in background threads
from urllib.parse import urlparse, urljoin # URL manipulation utilities
from alerts import alerts
from collections import defaultdict # - Used for threat counting/statistics
import re # Regular expressions
import os # Operating system interfaces / File system operations
from datetime import datetime # Date/time handling

class WebTrafficMonitor:
    def __init__(self):
        """
        Initialize the Web Traffic Monitor with:
        - Alert system for threat notifications
        - Dictionary to track suspicious activity counts
        - Monitoring state flag
        - Threading event to control sniffing
        - Report directory for scan outputs
        """
        self.alert_system = alerts()  # Alert generation module
        self.suspicious_activity = defaultdict(int)  # Track counts of different threat types
        self.is_monitoring = False  # Flag for monitoring state
        self.stop_sniffing = threading.Event()  # Event to stop packet sniffing
        self.report_dir = "scan_reports"  # Directory to store output reports
        os.makedirs(self.report_dir, exist_ok=True)  # Create report directory if doesn't exist
        print("Web Traffic Monitor initialized")

    def _generate_report(self, filename, content):
        """
        Save analysis results to a text file in the reports directory
        
        Args:
            filename (str): Name of the report file
            content (str): Content to write to the file
            
        Returns:
            str: Full path to the generated report file
        """
        filepath = os.path.join(self.report_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Report saved to: {filepath}")
        return filepath

    # Real-time Traffic Monitoring (Scapy)
    def start_traffic_monitor(self, interface="eth0"):
        """
        Start continuous network traffic monitoring on specified interface
        
        Args:
            interface (str): Network interface to monitor (default: eth0)
            
        Returns:
            bool: True if monitoring started successfully, False otherwise
        """
        if self.is_monitoring:
            print("Monitoring already running")
            return False

        print(f"Starting real-time monitoring on {interface}")
        self.is_monitoring = True
        self.stop_sniffing.clear()  # Reset the stop signal

        try:
            # Start packet sniffing in a separate thread
            sniff_thread = threading.Thread(
                target=self._sniff_traffic,
                args=(interface,),
                daemon=True  # Thread will exit when main program exits
            )
            sniff_thread.start()
            return True
        except Exception as e:
            print(f"Error starting monitor: {e}")
            self.is_monitoring = False
            return False

    def _sniff_traffic(self, interface):
        """
        Background task that captures and analyzes network packets
        
        Args:
            interface (str): Network interface to sniff packets from
        """
        try:
            # Sniff TCP traffic on HTTP/HTTPS ports
            scapy.sniff(
                iface=interface,
                filter="tcp port 80 or tcp port 443",  # Only web traffic
                prn=self._analyze_packet,  # Callback for each packet
                stop_filter=self._stop_sniffing,  # Condition to stop
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            print(f"Sniffing error: {e}")
        finally:
            self.is_monitoring = False
            print("Traffic monitoring stopped")

    def _analyze_packet(self, packet):
        """
        Inspect individual packets for malicious patterns
        
        Args:
            packet: Scapy packet object to analyze
        """
        if not packet.haslayer(scapy.Raw):
            return  # Skip packets without raw payload

        try:
            # Decode packet payload (lowercase for case-insensitive matching)
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore').lower()
            src_ip = packet[scapy.IP].src  # Get source IP for threat attribution

            # Common SQL injection attack patterns
            sql_patterns = [
                r'union\s+select',  # UNION SELECT attacks
                r'select\s+\*\s+from',  # Data extraction
                r'insert\s+into',  # Data injection
                r'1\s*=\s*1',  # Always true conditions
                r';--',  # SQL comment injection
                r'exec\s*\(',  # Command execution
                r'drop\s+table'  # Destructive commands
            ]

            # Common XSS attack patterns
            xss_patterns = [
                r'<script>',  # Script tag injection
                r'javascript:',  # JS protocol execution
                r'onerror=',  # Error handler exploitation
                r'alert\(',  # Basic XSS test
                r'document\.cookie',  # Cookie theft
                r'<img\s+src=x\s+onerror='  # Image tag exploitation
            ]

            # Check for SQL injection patterns in payload
            if any(re.search(pattern, payload) for pattern in sql_patterns):
                self._log_threat(
                    "SQL Injection Attempt",
                    f"Detected from {src_ip}\nPayload sample: {payload[:200]}..."
                )

            # Check for XSS patterns in payload
            if any(re.search(pattern, payload) for pattern in xss_patterns):
                self._log_threat(
                    "XSS Attempt",
                    f"Detected from {src_ip}\nPayload sample: {payload[:200]}..."
                )

        except Exception as e:
            if self.is_monitoring:
                print(f"Packet analysis error: {e}")

    # Deep Content Analysis (BS4)
    def deep_content_analysis(self, url):
        """
        Perform comprehensive security analysis of a webpage
        
        Args:
            url (str): URL of the webpage to analyze
            
        Returns:
            int: Total number of vulnerabilities found
        """
        print(f"\nStarting deep analysis of: {url}")
        
        try:
            # Fetch webpage with security scanner user agent
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'SecurityScanner/1.0'}
            )
            soup = BeautifulSoup(response.text, 'html.parser')

            # Initialize report structure
            report_content = f"=== Detailed Vulnerability Analysis Report ===\n"
            report_content += f"URL: {url}\n"
            report_content += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            # Storage for found vulnerabilities
            vulnerabilities = {
                'forms': [],    # Form-related issues
                'scripts': [],  # Dangerous scripts
                'inputs': []   # Input field problems
            }

            # Run all analysis checks
            self._analyze_forms(soup, url, vulnerabilities)
            self._analyze_scripts(soup, vulnerabilities)
            self._analyze_inputs(soup, vulnerabilities)

            # Build form vulnerabilities section
            report_content += "=== FORM VULNERABILITIES ===\n"
            if vulnerabilities['forms']:
                for vuln in vulnerabilities['forms']:
                    report_content += f"\n• Form at: {vuln['action']}\n"
                    report_content += f"  Method: {vuln['method'].upper()}\n"
                    report_content += "  Issues:\n"
                    for issue in vuln['issues']:
                        report_content += f"  - {issue}\n"
            else:
                report_content += "No form vulnerabilities found\n"

            # Build script vulnerabilities section
            report_content += "\n=== SCRIPT VULNERABILITIES ===\n"
            if vulnerabilities['scripts']:
                for i, vuln in enumerate(vulnerabilities['scripts'], 1):
                    report_content += f"\n• Script {i}:\n"
                    report_content += f"  Type: {vuln['type']}\n"
                    report_content += f"  Risk: {vuln['risk']}\n"
                    report_content += f"  Sample: {vuln['sample'][:100]}...\n"
            else:
                report_content += "No dangerous scripts found\n"

            # Build input vulnerabilities section
            report_content += "\n=== INPUT FIELD VULNERABILITIES ===\n"
            if vulnerabilities['inputs']:
                for vuln in vulnerabilities['inputs']:
                    report_content += f"\n• Input '{vuln['name']}' ({vuln['type']}):\n"
                    report_content += f"  Issues: {', '.join(vuln['issues'])}\n"
                    if 'parent_form' in vuln:
                        report_content += f"  Located in form: {vuln['parent_form']}\n"
            else:
                report_content += "No input vulnerabilities found\n"

            # Save the completed report
            filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            self._generate_report(filename, report_content)
            
            # Calculate total vulnerabilities found
            total_vulns = (len(vulnerabilities['forms']) + 
                         len(vulnerabilities['scripts']) + 
                         len(vulnerabilities['inputs']))
            
            print(f"Analysis completed. Found {total_vulns} vulnerabilities")
            return total_vulns

        except Exception as e:
            print(f"Analysis error: {e}")
            return 0

    def _analyze_forms(self, soup, base_url, vulnerabilities):
        """
        Analyze HTML forms for security vulnerabilities
        
        Args:
            soup: BeautifulSoup parsed document
            base_url: URL of the page being analyzed
            vulnerabilities: Dictionary to store found issues
        """
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),  # Form submission target
                'method': form.get('method', 'get').lower(),  # HTTP method
                'issues': []  # Found vulnerabilities
            }

            # Check 1: CSRF protection
            if not any(inp.get('type') == 'hidden' and 'csrf' in inp.get('name', '').lower()
                      for inp in form.find_all('input')):
                form_data['issues'].append("Missing CSRF token")

            # Check 2: Password fields without HTTPS
            if any(inp.get('type') == 'password' for inp in form.find_all('input')):
                if not form_data['action'].startswith('https'):
                    form_data['issues'].append("Password field without HTTPS protection")

            # Check 3: Unvalidated text inputs
            if any(inp.get('type') == 'text' and not inp.get('pattern')
                  for inp in form.find_all('input')):
                form_data['issues'].append("Unvalidated text input (potential SQLi/XSS)")

            # If issues found, add to vulnerabilities and log
            if form_data['issues']:
                vulnerabilities['forms'].append(form_data)
                for issue in form_data['issues']:
                    self._log_threat("Form Vulnerability", 
                                   f"{issue} in form at {form_data['action']}")

    def _analyze_scripts(self, soup, vulnerabilities):
        """
        Analyze script tags for dangerous patterns
        
        Args:
            soup: BeautifulSoup parsed document
            vulnerabilities: Dictionary to store found issues
        """
        for script in soup.find_all('script'):
            if script.string:  # Only check inline scripts
                script_content = script.string.lower()
                issues = []
                
                # Check for dangerous JavaScript patterns
                if 'eval(' in script_content:
                    issues.append("Dangerous eval() function")
                if 'innerhtml' in script_content:
                    issues.append("Potential XSS via innerHTML")
                if 'document.write' in script_content:
                    issues.append("Potential XSS via document.write()")
                if 'window.location' in script_content:
                    issues.append("Potential redirection vulnerability")

                # If issues found, add to vulnerabilities
                if issues:
                    vulnerabilities['scripts'].append({
                        'type': 'inline',
                        'risk': 'High',
                        'sample': script.string.strip(),  # First 100 chars of script
                        'issues': issues
                    })
                    self._log_threat("Dangerous Script", 
                                   f"Found {len(issues)} issues in inline script")

    def _analyze_inputs(self, soup, vulnerabilities):
        """
        Analyze input fields for security issues
        
        Args:
            soup: BeautifulSoup parsed document
            vulnerabilities: Dictionary to store found issues
        """
        for input_tag in soup.find_all(['input', 'textarea']):
            input_data = {
                'name': input_tag.get('name', 'unnamed'),  # Input name/identifier
                'type': input_tag.get('type', 'text'),  # Input type
                'issues': []  # Found vulnerabilities
            }

            # Password field specific checks
            if input_data['type'] == 'password':
                form = input_tag.find_parent('form')
                if form:
                    form_action = form.get('action', '')
                    if form_action and not form_action.startswith('https'):
                        input_data['issues'].append("Transmitted without HTTPS")
                        input_data['parent_form'] = urljoin(form_action, form.get('action', ''))
            
            # File upload specific checks
            elif input_data['type'] == 'file':
                input_data['issues'].append("Potential unrestricted file upload")
            
            # Text input validation checks
            elif input_data['type'] == 'text' and not input_tag.get('pattern'):
                input_data['issues'].append("No input validation pattern")

            # If issues found, add to vulnerabilities
            if input_data['issues']:
                vulnerabilities['inputs'].append(input_data)
                self._log_threat("Input Vulnerability",
                               f"Vulnerable {input_data['type']} input '{input_data['name']}'")

    # Web Scraping Functionality
    def perform_web_scraping(self, url):
        """
        Extract and catalog security-relevant elements from a webpage
        
        Args:
            url (str): URL of the page to scrape
            
        Returns:
            str: Generated report content, or None if failed
        """
        print(f"\nScraping security elements from: {url}")
        try:
            # Fetch webpage with security scanner user agent
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'SecurityScanner/1.0'}
            )
            soup = BeautifulSoup(response.text, 'html.parser')

            # Initialize report content
            report_content = f"=== Web Scraping Report ===\n"
            report_content += f"URL: {url}\n"
            report_content += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            # Basic page information
            report_content += f"Page Title: {soup.title.string if soup.title else 'No title'}\n\n"
            
            # Forms analysis section
            report_content += "=== Forms ===\n"
            forms = soup.find_all('form')
            report_content += f"Total forms found: {len(forms)}\n\n"
            
            # Detailed form information
            for i, form in enumerate(forms, 1):
                form_action = urljoin(url, form.get('action', ''))
                report_content += f"Form {i}:\n"
                report_content += f"Action: {form_action}\n"
                report_content += f"Method: {form.get('method', 'GET').upper()}\n"
                
                # List all form inputs
                inputs = form.find_all(['input', 'textarea', 'select'])
                report_content += f"Inputs ({len(inputs)}):\n"
                
                for inp in inputs:
                    inp_type = inp.get('type', 'text')
                    inp_name = inp.get('name', 'unnamed')
                    report_content += f"- {inp_name} ({inp_type})\n"
                report_content += "\n"
            
            # Links analysis section
            report_content += "\n=== Links ===\n"
            links = soup.find_all('a')
            report_content += f"Total links found: {len(links)}\n\n"
            
            # Collect and list unique links
            unique_links = set()
            for link in links:
                href = link.get('href', '')
                if href:
                    absolute_url = urljoin(url, href)
                    unique_links.add(absolute_url)
            
            for i, link_url in enumerate(sorted(unique_links), 1):
                report_content += f"{i}. {link_url}\n"
            
            # Scripts analysis section
            report_content += "\n=== Scripts ===\n"
            scripts = soup.find_all('script')
            report_content += f"Total script tags: {len(scripts)}\n"
            
            # Save the completed report
            filename = f"web_scraping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            self._generate_report(filename, report_content)
            
            print("[+] Web scraping completed and report generated")
            return report_content

        except Exception as e:
            print(f"[-] Scraping error: {e}")
            return None

    # Utility Methods
    def stop_monitoring(self):
        """Signal the monitoring thread to stop"""
        self.stop_sniffing.set()
        self.is_monitoring = False
        print("[+] Stopped traffic monitoring")

    def _stop_sniffing(self, packet):
        """
        Condition check for stopping packet sniffing
        
        Args:
            packet: Current packet (unused)
            
        Returns:
            bool: True if sniffing should stop, False otherwise
        """
        return self.stop_sniffing.is_set()

    def _log_threat(self, threat_type, details):
        """
        Record and alert about detected security threats
        
        Args:
            threat_type (str): Category of threat (e.g., "SQL Injection")
            details (str): Description of the specific threat
        """
        print(f"\n[!] {threat_type.upper()} DETECTED:")
        print(details)
        self.alert_system.generate_alert(threat_type, details)
        self.suspicious_activity[threat_type] += 1  # Increment threat counter

    def get_stats(self):
        """
        Get counts of detected threat types
        
        Returns:
            dict: Mapping of threat types to detection counts
        """
        return dict(self.suspicious_activity)

# References: [3], [7], [9], [10], [11], [13], [17], [18], [19]