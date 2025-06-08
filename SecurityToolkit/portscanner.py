import nmap  # Python-nmap library for port scanning
import subprocess  # For executing system commands
import re  # Regular expressions for input validation
import os  # Filesystem operations
from datetime import datetime  # For timestamping reports
from alerts import alerts  # Alert notification system
from reporter import Reporter  # Report generation module

class PortScanner:
    def __init__(self, alert_system):
        """
        Initialize the port scanner with:
        - Nmap scanner instance
        - Alert system integration
        - Report generation setup
        - Common ports configuration
        """
        self.scan_results = ""  # Buffer for storing scan results
        self.alerts = alert_system  # Alert notification handler
        self.reporter = Reporter()  # Report generator
        self.nm = nmap.PortScanner()  # Nmap scanner instance
        
        # Commonly targeted ports for quick scans:
        # - FTP (21), SSH (22), Telnet (23)
        # - SMTP (25), DNS (53), HTTP (80)
        # - POP3 (110), SMB (139,445)
        # - IMAP (143), HTTPS (443)
        # - RDP (3389), HTTP-alt (8080)
        self.common_ports = "21,22,23,25,53,80,110,139,143,443,445,3389,8080"
        
        self.report_dir = "scan_reports"  # Directory for storing reports
        os.makedirs(self.report_dir, exist_ok=True)  # Create directory if needed

    def show_scan_menu(self):
        """
        Interactive menu for port scanning operations.
        Handles user input and delegates to appropriate scan methods.
        """
        while True:
            print("\n=== Port Scanning & Vulnerability Assessment ===")
            print("1. Quick Port Scan (Common ports)")
            print("2. Full Port Scan (All 65535 ports)")
            print("3. Comprehensive Scan with Vulnerability Assessment")
            print("4. Custom Nmap Command")
            print("5. Return to Main Menu")
            
            choice = input("Select an option: ")
            
            if choice == '1':
                target = self._get_target()  # Get validated target
                self.run_quick_scan(target)
            elif choice == '2':
                target = self._get_target()
                self.run_full_scan(target)
            elif choice == '3':
                target = self._get_target()
                self.run_comprehensive_scan(target)
            elif choice == '4':
                self.run_custom_command()
            elif choice == '5':
                break  # Exit menu loop
            else:
                print("Invalid option")

    def run_quick_scan(self, target, verbose=True):
        """
        Perform quick scan of common ports using TCP SYN scan (-sS).
        Fast scan with moderate timing (T4) showing only open ports.
        
        Args:
            target (str): IP/hostname to scan
            verbose (bool): Whether to show real-time results
        """
        print(f"\nScanning {target} (common ports)...")
        try:
            # Nmap arguments:
            # -sS: TCP SYN scan (stealth)
            # -T4: Aggressive timing template
            # --open: Show only open ports
            self.nm.scan(hosts=target, ports=self.common_ports, arguments="-sS -T4 --open")
            
            if verbose:
                self._print_real_time_results()  # Display live results
                
            self._save_scan_report(target, "Quick_Scan")  # Save report
            self._check_service_versions(target, verbose)  # Check versions
        except Exception as e:
            error_msg = f"Quick scan failed: {str(e)}"
            self._save_failed_scan_report(target, "Quick_Scan", error_msg)

    def run_full_scan(self, target, verbose=True):
        """
        Scan all 65535 ports in chunks to avoid overwhelming the system.
        Uses faster scanning with min-rate 1000 packets/second.
        
        Args:
            target (str): IP/hostname to scan
            verbose (bool): Whether to show real-time results
        """
        print(f"\nScanning all ports on {target}...")
        try:
            # Scan ports in chunks to balance speed and reliability
            port_ranges = ["1-10000", "10001-20000", "20001-30000", 
                         "30001-40000", "40001-50000", "50001-65535"]
            
            for port_range in port_ranges:
                # Nmap arguments:
                # -sS: TCP SYN scan
                # -T4: Aggressive timing
                # --min-rate 1000: Minimum packet rate
                # --open: Show only open ports
                # -v: Verbose output
                self.nm.scan(hosts=target, ports=port_range, 
                            arguments="-sS -T4 --min-rate 1000 --open -v")
                
            self._save_scan_report(target, "Full_Scan")
            self._check_service_versions(target, verbose)
        except Exception as e:
            error_msg = f"Full scan failed: {str(e)}"
            self._save_failed_scan_report(target, "Full_Scan", error_msg)

    def run_comprehensive_scan(self, target, verbose=True):
        """
        Two-phase deep scan with vulnerability assessment:
        1. Port discovery on common ports
        2. Service detection and vulnerability scanning
        
        Args:
            target (str): IP/hostname to scan
            verbose (bool): Whether to show real-time results
        """
        print(f"\nComprehensive scan on {target}...")
        try:
            # Phase 1: Initial port discovery (-sS)
            self.nm.scan(hosts=target, ports=self.common_ports, 
                        arguments="-sS --open -v")
            open_ports = self._get_open_ports(target)
            
            # Phase 2: Service and vulnerability detection if ports open
            if open_ports:
                # Service version detection (-sV)
                self.nm.scan(hosts=target, ports=",".join(open_ports), 
                            arguments="-sV -v")
                # Run vulnerability scripts
                vuln_results = self._run_vulnerability_scan(target, open_ports, verbose)
                self._save_report_to_file(target, "Comprehensive_Scan", vuln_results)
        except Exception as e:
            error_msg = f"Comprehensive scan failed: {str(e)}"
            self._save_failed_scan_report(target, "Comprehensive_Scan", error_msg)

    def run_custom_command(self, verbose=True):
        """
        Execute user-provided Nmap command with validation.
        Ensures command starts with 'nmap' for security.
        
        Args:
            verbose (bool): Whether to show command output
        """
        command = input("\nEnter full Nmap command: ").strip()
        if not command.lower().startswith("nmap"):
            print("Command must start with 'nmap'")
            return
            
        try:
            target = self._extract_target_from_command(command)
            # Execute command with captured output
            result = subprocess.run(command, shell=True, 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:  # Success
                self._save_report_to_file(target or "custom_target", 
                                        "Custom_Scan", result.stdout)
        except Exception as e:
            print(f"Error: {str(e)}")
            
    def run_custom_scan(self, command, verbose=True):
        """
        Execute provided Nmap command from parameter.
        Used for programmatic custom scan execution.
        
        Args:
            command (str): Full Nmap command to execute
            verbose (bool): Whether to show command output
            
        Returns:
            bool: True if scan succeeded, False otherwise
        """
        if not command.lower().startswith("nmap"):
            print("Command must start with 'nmap'")
            return False
            
        try:
            target = self._extract_target_from_command(command)
            result = subprocess.run(command, shell=True,
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self._save_report_to_file(target or "custom_target",
                                        "Custom_Scan", result.stdout)
                return True
            return False
        except Exception as e:
            print(f"Error: {str(e)}")
            return False

    def _run_vulnerability_scan(self, target, ports, verbose=True):
        """
        Run Nmap vulnerability scripts against open ports.
        Uses vulners and http/ssl-related scripts with min CVSS 5.0.
        
        Args:
            target (str): IP/hostname to scan
            ports (list): Open ports to test
            verbose (bool): Whether to show results
            
        Returns:
            str: Vulnerability scan results
        """
        try:
            # Selected NSE scripts:
            # vulners: CVE database lookup
            # http-vuln*: HTTP vulnerability checks
            # ssl-*: SSL/TLS vulnerability checks
            vuln_scripts = "vulners,http-vuln*,ssl-*"
            
            command = (f"nmap -p {','.join(ports)} -sV --script {vuln_scripts} "
                      f"--script-args mincvss=5.0 -T4 -v {target}")
            
            result = subprocess.run(command, shell=True,
                                  capture_output=True, text=True)
            
            # Generate alert if critical vulnerabilities found
            if "CVE-" in result.stdout:
                self.alerts.generate_alert(
                    "VULNERABILITIES DETECTED",
                    f"Critical vulnerabilities found on {target}"
                )
            return result.stdout
        except Exception as e:
            return f"Vulnerability scan error: {str(e)}"

    def _print_real_time_results(self):
        """Print formatted live scan results to console"""
        for host in self.nm.all_hosts():
            print(f"\nHost: {host} ({self.nm[host].hostname()})")
            print(f"Status: {self.nm[host].state()}")
            
            for proto in self.nm[host].all_protocols():
                print(f"\nProtocol: {proto.upper()}")
                print("PORT\tSTATE\tSERVICE\tVERSION")
                for port in sorted(self.nm[host][proto].keys(), key=int):
                    port_info = self.nm[host][proto][port]
                    if port_info['state'] == 'open':
                        print(f"{port}\t{port_info['state']}\t"
                              f"{port_info['name']}\t"
                              f"{port_info.get('version', 'unknown')}")

    def _generate_report_content(self, target, scan_type):
        """
        Generate standardized report content with:
        - Target information
        - Scan metadata
        - Detailed port findings
        
        Args:
            target (str): Scanned IP/hostname
            scan_type (str): Type of scan performed
            
        Returns:
            str: Formatted report content
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_content = f"""=== SCAN REPORT ===
Target: {target}
Scan Type: {scan_type}
Date: {timestamp}
"""
        # Add detailed port information
        for host in self.nm.all_hosts():
            report_content += f"\nHost: {host}\n"
            for proto in self.nm[host].all_protocols():
                report_content += f"\nProtocol: {proto.upper()}\n"
                for port in sorted(self.nm[host][proto].keys(), key=int):
                    port_info = self.nm[host][proto][port]
                    if port_info['state'] == 'open':
                        report_content += (f"{port}\t{port_info['name']}\t"
                                        f"{port_info.get('version', 'unknown')}\n")
        return report_content

    def _save_scan_report(self, target, scan_type):
        """
        Save successful scan report with generated content.
        
        Args:
            target (str): Scanned IP/hostname
            scan_type (str): Type of scan performed
        """
        report_content = self._generate_report_content(target, scan_type)
        self._save_report_to_file(target, scan_type, report_content)

    def _save_failed_scan_report(self, target, scan_type, error_msg):
        """
        Save error report for failed scans with failure details.
        
        Args:
            target (str): Intended scan target
            scan_type (str): Type of attempted scan
            error_msg (str): Failure reason
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_content = f"""=== SCAN REPORT ===
Target: {target}
Scan Type: {scan_type}
Date: {timestamp}
Status: Failed
Error: {error_msg}
"""
        self._save_report_to_file(target, f"{scan_type}_Failed", report_content)

    def _save_report_to_file(self, target, scan_type, content):
        """
        Save content to timestamped report file.
        
        Args:
            target (str): Scanned IP/hostname
            scan_type (str): Type of scan performed
            content (str): Report content to save
        """
        # Create filename with timestamp to prevent collisions
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/{scan_type}_{target}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(content)
        print(f"\nReport saved: {filename}")

    def _check_service_versions(self, target, verbose=True):
        """
        Perform service version detection on open ports.
        
        Args:
            target (str): IP/hostname to check
            verbose (bool): Whether to show results
            
        Returns:
            str: Version detection results or None if failed
        """
        open_ports = self._get_open_ports(target)
        if not open_ports:
            return None
            
        command = f"nmap -p {','.join(open_ports)} -sV {target}"
        result = subprocess.run(command, shell=True, 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            self._save_report_to_file(target, "Service_Versions", result.stdout)
            return result.stdout
        return None

    def _get_open_ports(self, host):
        """
        Extract list of open ports from scan results.
        
        Args:
            host (str): Scanned IP/hostname
            
        Returns:
            list: Sorted list of open port numbers as strings
        """
        open_ports = []
        for proto in self.nm[host].all_protocols():
            open_ports.extend(
                str(port) for port in self.nm[host][proto].keys()
                if self.nm[host][proto][port]['state'] == 'open'
            )
        return sorted(open_ports, key=int)  # Numeric sort

    def _extract_target_from_command(self, command):
        """
        Parse Nmap command to extract target IP/hostname.
        
        Args:
            command (str): Full Nmap command
            
        Returns:
            str: Extracted target or None if not found
        """
        parts = command.split()
        for i, part in enumerate(parts):
            if part == 'nmap' and i+1 < len(parts):
                return parts[i+1]
        return None

    def _get_target(self):
        """
        Prompt user for target with validation.
        
        Returns:
            str: Validated target IP/hostname
        """
        while True:
            target = input("\nEnter target IP/hostname: ").strip()
            if self._validate_target(target):
                return target
            print("Invalid target format")

    def _validate_target(self, target):
        """
        Validate target format as IP or hostname.
        
        Args:
            target (str): Input to validate
            
        Returns:
            bool: True if valid format, False otherwise
        """
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        host_pattern = r"^[a-zA-Z0-9\-\.]+$"
        return re.match(ip_pattern, target) or re.match(host_pattern, target)
    
# References: [4], [5], [14], [15] 