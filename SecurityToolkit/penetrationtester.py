import requests  # For making HTTP requests to test web applications
import threading  # For running tests in background threads
from datetime import datetime  # For timestamping test reports
from alerts import alerts  # For sending security alerts
from reporter import Reporter  # For generating formatted reports
import os  # For filesystem operations

class PenetrationTester:
    def __init__(self):

        self.test_results = ""  # String buffer for accumulating test results
        self.is_testing = False  # Boolean flag indicating active test status
        self.stop_testing = threading.Event()  # Thread-safe event for test cancellation
        self.reporter = Reporter()  # Instance for generating formatted reports
        self.alerts = alerts()  # Alert notification handler
        self.report_dir = "scan_reports"  # Directory for storing test reports
        
        # Create report directory if it doesn't exist (with exist_ok to prevent race conditions)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Dictionary to track discovered vulnerability states:
        # - SQLi: SQL Injection vulnerabilities
        # - XSS: Cross-Site Scripting vulnerabilities  
        # - BruteForce: Weak authentication vulnerabilities
        self.vulnerabilities_found = {
            'SQLi': False,
            'XSS': False,
            'BruteForce': False
        }

    def test_website(self, url):
        """
        Public interface to initiate comprehensive website vulnerability testing.
        Handles thread creation and state management for SQLi/XSS tests.
        
        Args:
            url (str): Target website URL to test
            
        Returns:
            bool: True if test started successfully, False otherwise
        """
        if self.is_testing:  # Prevent overlapping tests
            print("Test already in progress")
            return False

        print(f"\nStarting website vulnerability test on: {url}")
        self.is_testing = True  # Set testing flag
        self.stop_testing.clear()  # Reset cancellation event

        try:
            # Create and start daemon thread for background testing:
            # - Daemon=True allows program to exit even if thread is running
            # - Target is the internal test execution method
            # - Args passes the URL parameter
            test_thread = threading.Thread(
                target=self._run_website_tests,
                args=(url,),
                daemon=True
            )
            test_thread.start()  # Begin asynchronous execution
            return True
        except Exception as e:
            print(f"Error starting test: {str(e)}")
            self.is_testing = False  # Reset state on failure
            return False

    def check_brute_force(self, url):
        """
        Public interface to test authentication systems for brute force vulnerabilities.
        Manages thread creation and state for credential testing.
        
        Args:
            url (str): Login page URL to test
            
        Returns: 
            bool: True if test started successfully, False otherwise
        """
        if self.is_testing:
            print("Test already in progress")
            return False

        print(f"\nStarting brute force test on: {url}")
        self.is_testing = True
        self.stop_testing.clear()

        try:
            # Background thread execution for brute force testing
            test_thread = threading.Thread(
                target=self._run_brute_force_test,
                args=(url,),
                daemon=True
            )
            test_thread.start()
            return True
        except Exception as e:
            print(f"Error starting test: {str(e)}")
            self.is_testing = False
            return False

    def _run_website_tests(self, url):
        """
        Internal method orchestrating SQLi and XSS testing sequence.
        Handles test execution, timing, reporting and alerting.
        
        Args:
            url (str): Target website URL
            
        Returns:
            str: Complete test report content
        """
        start_time = datetime.now()  # Record test start time
        
        # Execute security tests (both return formatted result strings)
        sqli_result = self._check_sql_injection(url)  # SQL injection tests
        xss_result = self._check_xss(url)  # Cross-site scripting tests
        
        # Generate comprehensive report with:
        # - Target information
        # - Timestamps
        # - Duration metrics 
        # - Detailed findings
        # - Vulnerability summary
        report_content = f"""=== WEBSITE VULNERABILITY TEST REPORT ===
Target URL: {url}
Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: {(datetime.now() - start_time).total_seconds():.2f} seconds

=== TEST RESULTS ===
{sqli_result}

{xss_result}

=== VULNERABILITY SUMMARY ===
SQL Injection: {'VULNERABLE' if self.vulnerabilities_found['SQLi'] else 'Secure'}
XSS: {'VULNERABLE' if self.vulnerabilities_found['XSS'] else 'Secure'}"""
        
        # Save report to timestamped file in scan_reports directory
        filename = f"website_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self._save_report(filename, report_content)
        
        # Print summary to console
        print("\nWebsite test completed. Results:")
        print(report_content.split("=== VULNERABILITY SUMMARY ===")[-1])
        
        self.is_testing = False  # Reset testing state
        return report_content  # Return full report content

    def _run_brute_force_test(self, url):
        """
        Internal method executing brute force credential testing.
        Manages test flow, timing, reporting and alerting.
        
        Args:
            url (str): Login page URL to test
            
        Returns:
            str: Complete test report content
        """
        start_time = datetime.now()
        brute_result = self._check_brute_force(url)  # Execute credential testing
        
        # Format brute force test report with:
        # - Target information
        # - Timestamps
        # - Duration metrics
        # - Test results
        # - Vulnerability status
        report_content = f"""=== BRUTE FORCE TEST REPORT ===
Target URL: {url}
Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: {(datetime.now() - start_time).total_seconds():.2f} seconds

=== TEST RESULTS ===
{brute_result}

=== VULNERABILITY SUMMARY ===
Brute Force: {'VULNERABLE' if self.vulnerabilities_found['BruteForce'] else 'Secure'}"""
        
        # Save report to timestamped file
        filename = f"brute_force_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self._save_report(filename, report_content)
        
        # Print summary to console
        print("\nBrute force test completed. Results:")
        print(report_content.split("=== VULNERABILITY SUMMARY ===")[-1])
        
        self.is_testing = False
        return report_content

    def _check_sql_injection(self, url):
        """
        Execute comprehensive SQL injection testing using common attack patterns.
        Tests for various SQLi vulnerability types and database responses.
        
        Args:
            url (str): Target URL to test
            
        Returns:
            str: Formatted test results
        """
        print("Testing for SQL Injection...")
        results = "=== SQL Injection Test Results ===\n"
        vulnerable = False  # Track overall vulnerability status
        
        # Common SQLi test payloads covering:
        # - Basic tautologies
        # - Comment-based attacks
        # - UNION attacks
        # - Database fingerprinting
        payloads = [
            "' OR '1'='1",  # Classic tautology
            "' OR 1=1--",   # Comment-terminated attack
            "' UNION SELECT null,username,password FROM users--",  # Data extraction
            "' AND 1=CONVERT(int,@@version)--",  # Version disclosure
            "admin'--"  # Basic comment attack
        ]

        for payload in payloads:
            if self.stop_testing.is_set():  # Check for cancellation
                results += "Testing stopped by user.\n"
                break
                
            test_url = f"{url}?id={payload}"  # Construct test URL
            try:
                response = requests.get(test_url, timeout=5)  # Send payload
                
                # Check response for vulnerability indicators:
                # - Database error messages
                # - Syntax errors
                # - SQL-related keywords
                if ("error" in response.text.lower() or 
                    "syntax" in response.text.lower() or 
                    "sql" in response.text.lower()):
                    results += f"Vulnerable to SQLi with payload: {payload}\n"
                    vulnerable = True
                    self.vulnerabilities_found['SQLi'] = True
                    # Generate security alert
                    self.alerts.generate_alert("SQL INJECTION", f"Vulnerability found at {test_url}")
                    
            except Exception as e:
                results += f"Error testing payload {payload}: {str(e)}\n"

        if not vulnerable:
            results += "No SQL Injection vulnerabilities detected\n"
            
        return results

    def _check_xss(self, url):
        """
        Test for Cross-Site Scripting vulnerabilities using common XSS payloads.
        Checks for unencoded script rendering in responses.
        
        Args:
            url (str): Target URL to test
            
        Returns:
            str: Formatted test results
        """
        print("Testing for XSS...")
        results = "=== XSS Test Results ===\n"
        vulnerable = False  # Track overall vulnerability status
        
        # Common XSS test vectors covering:
        # - Basic script tag injection
        # - Event handler-based XSS
        # - SVG vector attacks
        # - Attribute breakout
        payloads = [
            "<script>alert('XSS')</script>",  # Basic script injection
            "<img src=x onerror=alert('XSS')>",  # Error handler execution
            "<svg/onload=alert('XSS')>",  # SVG vector
            "\"><script>alert('XSS')</script>"  # Attribute escape
        ]

        for payload in payloads:
            if self.stop_testing.is_set():  # Check for cancellation
                results += "Testing stopped by user.\n"
                break
                
            test_url = f"{url}?search={payload}"  # Construct test URL
            try:
                response = requests.get(test_url, timeout=5)  # Send payload
                
                # Check if payload appears unencoded in response
                if payload in response.text:
                    results += f"Vulnerable to XSS with payload: {payload}\n"
                    vulnerable = True
                    self.vulnerabilities_found['XSS'] = True
                    # Generate security alert
                    self.alerts.generate_alert("XSS", f"Vulnerability found at {test_url}")
                    
            except Exception as e:
                results += f"Error testing payload {payload}: {str(e)}\n"

        if not vulnerable:
            results += "No XSS vulnerabilities detected\n"
            
        return results

    def _check_brute_force(self, url):
        """
        Test authentication system for weak credential acceptance.
        Attempts common default/weak credentials against login endpoint.
        
        Args:
            url (str): Login page URL to test
            
        Returns:
            str: Formatted test results
        """
        print("Testing for Brute Force...")
        results = "=== Brute Force Test Results ===\n"
        vulnerable = False  # Track overall vulnerability status
        
        # Common weak credential pairs covering:
        # - Default admin credentials
        # - Common weak passwords
        # - Simple username/password combinations
        credentials = [
            {"username": "admin", "password": "password"}, 
            {"username": "admin", "password": "admin"},
            {"username": "user", "password": "123456"},
            {"username": "test", "password": "test"},
            {"username": "root", "password": "root"}
        ]

        for cred in credentials:
            if self.stop_testing.is_set():  # Check for cancellation
                results += "Testing stopped by user.\n"
                break
                
            try:
                # Submit login attempt with test credentials
                response = requests.post(
                    url,
                    data=cred,  # Form-encoded credentials
                    timeout=5  # Request timeout
                )
                
                # Check for successful login indicators
                if "Login successful!" in response.text:
                    results += f"SUCCESSFUL LOGIN with credentials: {cred['username']}/{cred['password']}\n"
                    vulnerable = True
                    self.vulnerabilities_found['BruteForce'] = True
                    # Generate security alert
                    self.alerts.generate_alert("BRUTE FORCE", f"Successful login with {cred['username']}/{cred['password']}")
                    break  # Stop after first success
                else:
                    results += f"Failed attempt with: {cred['username']}/{cred['password']}\n"
                    
            except Exception as e:
                results += f"Error testing credentials {cred}: {str(e)}\n"

        if not vulnerable:
            results += "No Brute Force vulnerabilities detected (could not find valid credentials)\n"
            
        return results

    def _save_report(self, filename, content):
        """
        Save test report content to specified file in scan_reports directory.
        
        Args:
            filename (str): Name of report file to create
            content (str): Report content to write
        """
        filepath = os.path.join(self.report_dir, filename)  # Build full path
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)  # Write report content
        print(f"Report saved to: {filepath}")

    def stop_test(self):
        """
        Cancel any ongoing penetration tests.
        Sets thread event flag and resets testing state.
        """
        self.stop_testing.set()  # Signal threads to stop
        self.is_testing = False  # Reset testing flag
        print("\nTesting stopped by user")
        
        
# References: [3], [9], [10], [11], [17]         