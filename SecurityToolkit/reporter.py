from datetime import datetime
import os
from fpdf import FPDF  # PDF generation library
import re  # Regular expressions for pattern matching
import textwrap  # Text formatting utilities

class Reporter:
    def __init__(self):
        """
        Initialize the reporting system with:
        - Required directories structure
        - Comprehensive statistics tracking framework
        - Vulnerability pattern definitions
        """
        # Directory structure for storing different report types
        self.report_dirs = ["scan_reports", "security_reports"]
        for dir in self.report_dirs:
            os.makedirs(dir, exist_ok=True)  # Create dirs if they don't exist
        
        # Enhanced statistics tracking framework:
        # Structured to capture quantitative and qualitative vulnerability data
        self.stats = {
            # XSS tracking: count, example payloads, source reports
            "XSS": {"count": 0, "examples": [], "sources": []},
            
            # SQL Injection tracking
            "SQL Injection": {"count": 0, "examples": [], "sources": []},
            
            # Brute Force attack tracking
            "Brute Force": {"count": 0, "examples": [], "sources": []},
            
            # Network port exposure tracking
            "Open Ports": {"count": 0, "ports": [], "services": {}},
            
            # Service vulnerability tracking
            "Vulnerable Services": {"count": 0, "cves": [], "services": {}},
            
            # Configuration issue tracking
            "Security Misconfigurations": {"count": 0, "issues": [], "sources": []},
            
            # Critical vulnerability tracking (CVSS >= 7.0)
            "Critical Vulnerabilities": {"count": 0, "items": []}
        }

    def _wrap_text(self, text, width=100):
        """
        Format text for PDF output with proper line wrapping.
        
        Args:
            text (str): Input text to format
            width (int): Maximum line width in characters
            
        Returns:
            str: Wrapped text with newlines
        """
        if not isinstance(text, str):
            text = str(text)
        return '\n'.join(textwrap.wrap(text, width=width))

    def _get_all_reports(self):
        """
        Scan report directories and collect all text-based reports.
        
        Returns:
            list: Sorted list of full paths to report files
        """
        reports = []
        for dir in self.report_dirs:
            if os.path.exists(dir):
                # Collect all .txt files from report directories
                for filename in os.listdir(dir):
                    if filename.endswith(".txt"):
                        reports.append(os.path.join(dir, filename))
        return sorted(reports)  # Return chronologically sorted

    def _parse_report(self, filepath):
        """
        Perform deep content analysis of security reports to identify:
        - Vulnerability patterns
        - Security misconfigurations 
        - Service exposures
        - Critical findings
        
        Args:
            filepath (str): Path to report file
            
        Returns:
            dict: Structured report data with findings
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()  # Read report content
        
        # Initialize report metadata structure
        filename = os.path.basename(filepath)
        report_data = {
            "filename": filename,
            "content": content,
            "type": "Other",  # Default classification
            "timestamp": datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
            "findings": []  # Will contain specific vulnerabilities
        }

        # XSS Detection Patterns:
        # - Payload patterns from scanners
        # - Script tag variations
        # - HTML event handlers
        # - Explicit vulnerability markers
        xss_patterns = [
            r"Vulnerable to XSS with payload: (.+)",
            r"XSS Attempt.*Payload sample: (.+)",
            r"<script>.*</script>",
            r"<img src=x onerror=.+>",
            r"XSS: VULNERABLE"
        ]
        xss_findings = []
        for pattern in xss_patterns:
            xss_findings.extend(re.findall(pattern, content, re.IGNORECASE))
        if xss_findings:
            report_data["type"] = "XSS"
            self.stats["XSS"]["count"] += 1
            self.stats["XSS"]["examples"].extend(x[:200] for x in xss_findings)  # Truncate long payloads
            self.stats["XSS"]["sources"].append(filename)
            report_data["findings"].extend([f"XSS: {f[:200]}" for f in xss_findings])

        # SQL Injection Detection Patterns:
        # - Common SQLi payload patterns
        # - Tautology-based attacks
        # - Comment-based attacks
        # - UNION-based attacks
        # - Explicit vulnerability markers
        sqli_patterns = [
            r"Vulnerable to SQLi with payload: (.+)",
            r"SQL Injection Attempt.*Payload sample: (.+)",
            r"'.*OR.*'1'='1",
            r"'.*--",
            r"UNION SELECT",
            r"SQL Injection: VULNERABLE"
        ]
        sqli_findings = []
        for pattern in sqli_patterns:
            sqli_findings.extend(re.findall(pattern, content, re.IGNORECASE))
        if sqli_findings:
            report_data["type"] = "SQL Injection"
            self.stats["SQL Injection"]["count"] += 1
            self.stats["SQL Injection"]["examples"].extend(s[:200] for s in sqli_findings)
            self.stats["SQL Injection"]["sources"].append(filename)
            report_data["findings"].extend([f"SQLi: {f[:200]}" for f in sqli_findings])

        # Brute Force Detection Patterns:
        # - Successful login patterns
        # - Multiple attempt patterns
        # - Source IP indicators
        # - Explicit vulnerability markers
        brute_patterns = [
            r"SUCCESSFUL LOGIN with credentials: (.+)",
            r"Login attempt #\d+ from (.+)",
            r"Brute Force.*Source IP: (.+)",
            r"Brute Force: VULNERABLE"
        ]
        brute_findings = []
        for pattern in brute_patterns:
            brute_findings.extend(re.findall(pattern, content))
        if brute_findings:
            report_data["type"] = "Brute Force"
            self.stats["Brute Force"]["count"] += 1
            self.stats["Brute Force"]["examples"].extend(b[:200] for b in brute_findings)
            self.stats["Brute Force"]["sources"].append(filename)
            report_data["findings"].extend([f"Brute Force: {f[:200]}" for f in brute_findings])

        # Port Scan Analysis:
        # Identifies open ports and services in scan reports
        port_pattern = r"(\d+/tcp)\s+open\s+([^\n]+)"
        port_matches = re.findall(port_pattern, content)
        if port_matches:
            report_data["type"] = "Open Ports"
            self.stats["Open Ports"]["count"] += len(port_matches)
            for port, service in port_matches:
                port_info = f"{port} ({service.strip()})"
                self.stats["Open Ports"]["ports"].append(port_info)
                # Track service distribution
                svc_name = service.split()[0] if service else "unknown"
                self.stats["Open Ports"]["services"][svc_name] = self.stats["Open Ports"]["services"].get(svc_name, 0) + 1
            report_data["findings"].extend([f"Open Port: {p[0]} running {p[1][:50]}" for p in port_matches])

        # Vulnerability Scan Analysis:
        # Identifies CVE entries with scores in reports
        vuln_pattern = r"(CVE-\d+-\d+)\s+([\d.]+)\s+https?://[^\s]+"
        vuln_matches = re.findall(vuln_pattern, content)
        if vuln_matches:
            report_data["type"] = "Vulnerable Services"
            critical_vulns = [f"{cve} (Score: {score})" for cve, score in vuln_matches if float(score) >= 7.0]
            if critical_vulns:
                self.stats["Critical Vulnerabilities"]["count"] += len(critical_vulns)
                self.stats["Critical Vulnerabilities"]["items"].extend(critical_vulns)
            for cve, score in vuln_matches:
                self.stats["Vulnerable Services"]["cves"].append(f"{cve} (Score: {score})")
                # Track vulnerable services
                service_match = re.search(r"Service:\s*([^\n]+)", content)
                if service_match:
                    service = service_match.group(1).strip()
                    self.stats["Vulnerable Services"]["services"][service] = self.stats["Vulnerable Services"]["services"].get(service, 0) + 1
            report_data["findings"].extend([f"Vulnerability: {v[0]} (Score: {v[1]})" for v in vuln_matches])

        # Security Misconfigurations:
        # Identifies common security configuration issues
        misconfig_patterns = [
            r"Issues:\s*\n\s*-\s*(.+)",
            r"Vulnerable\s*:\s*(.+)",
            r"Missing\s*(.+)",
            r"without\s*(.+)",
            r"Unvalidated\s*(.+)"
        ]
        misconfig_findings = []
        for pattern in misconfig_patterns:
            misconfig_findings.extend(re.findall(pattern, content, re.IGNORECASE))
        if misconfig_findings:
            report_data["type"] = "Security Misconfigurations"
            self.stats["Security Misconfigurations"]["count"] += len(misconfig_findings)
            self.stats["Security Misconfigurations"]["issues"].extend(m[:200] for m in misconfig_findings)
            self.stats["Security Misconfigurations"]["sources"].append(filename)
            report_data["findings"].extend([f"Misconfiguration: {m[:200]}" for m in misconfig_findings])

        return report_data

    def _generate_security_recommendations(self):
        """
        Generate actionable security recommendations based on:
        - Identified vulnerabilities
        - Industry best practices
        - Defense-in-depth principles
        
        Returns:
            list: Prioritized security recommendations
        """
        recommendations = []
        
        # Authentication Security Recommendations
        if self.stats["Brute Force"]["count"] > 0:
            recommendations.extend([
                "Implement multi-factor authentication (MFA) for all user accounts",
                "Enforce account lockout after 5 failed login attempts with progressive delays",
                "Implement CAPTCHA or other bot prevention mechanisms on login forms",
                "Monitor and alert on brute force attempts in real-time",
                "Enforce strong password policies (minimum 12 characters, complexity requirements)"
            ])
        
        # Web Application Security Recommendations
        web_vulns = self.stats["XSS"]["count"] + self.stats["SQL Injection"]["count"]
        if web_vulns > 0:
            recommendations.extend([
                "Implement Content Security Policy (CSP) headers with strict directives",
                "Apply input validation and output encoding for all user-supplied data",
                "Migrate to parameterized queries or ORM for all database access",
                "Deploy a Web Application Firewall (WAF) with OWASP Core Rule Set",
                "Conduct regular secure code training for developers",
                "Implement automated security testing in CI/CD pipeline"
            ])
        
        # Network Security Recommendations
        if self.stats["Open Ports"]["count"] > 0:
            recommendations.extend([
                "Conduct a full review of all open ports and close unnecessary services",
                "Implement network segmentation to isolate critical systems",
                "Configure firewall rules to restrict access to services by source IP",
                "Enable logging and monitoring for all network access attempts",
                "Implement Intrusion Detection/Prevention System (IDS/IPS)"
            ])
        
        # Vulnerability Management Recommendations
        if self.stats["Vulnerable Services"]["count"] > 0:
            recommendations.extend([
                "Establish a vulnerability management program with regular scanning",
                "Prioritize patching of services with critical vulnerabilities (CVSS >= 7.0)",
                "Subscribe to vulnerability feeds for all used software/components",
                "Implement compensating controls for vulnerabilities that cannot be immediately patched",
                "Conduct threat modeling to identify attack surfaces"
            ])
        
        # General Security Operations Recommendations
        recommendations.extend([
            "Implement centralized logging and SIEM solution for correlation of security events",
            "Develop incident response playbooks for identified threat scenarios",
            "Conduct regular red team exercises to test defenses",
            "Establish a security awareness training program for all employees",
            "Implement configuration management to enforce security baselines"
        ])
        
        return recommendations

    def _add_formatted_page(self, pdf, title):
        """
        Add new PDF page with consistent formatting.
        
        Args:
            pdf (FPDF): PDF document object
            title (str): Page title
            
        Returns:
            FPDF: Updated PDF object
        """
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, title, 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.ln(5)
        return pdf

    def _safe_add_text(self, pdf, text, max_width=180):
        """
        Safely add text to PDF with proper line wrapping and formatting.
        
        Args:
            pdf (FPDF): PDF document object
            text (str): Text to add
            max_width (int): Maximum line width in characters
        """
        if not isinstance(text, str):
            text = str(text)
        wrapped_lines = textwrap.wrap(text, width=max_width)
        for line in wrapped_lines:
            pdf.cell(0, 6, line, 0, 1)
        pdf.ln(2)

    def generate_complete_report(self):
        """
        Generate comprehensive PDF security report containing:
        - Executive summary
        - Detailed findings
        - Vulnerability statistics 
        - Actionable recommendations
        - Full report index
        
        Returns:
            str: Path to generated PDF report or None if failed
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            pdf = FPDF()  # Initialize PDF document
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Configure base font
            pdf.set_font('Arial', '', 12)
            
            # Cover Page
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 40, "COMPREHENSIVE SECURITY ASSESSMENT REPORT", 0, 1, 'C')
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, f"Generated on: {timestamp}", 0, 1, 'C')
            pdf.ln(20)
            self._safe_add_text(pdf, "This report contains a complete analysis of security vulnerabilities, attack statistics, and strategic recommendations to improve the organization's security posture.")
            
            # Process all reports to populate statistics
            reports = self._get_all_reports()
            for report_path in reports:
                self._parse_report(report_path)
            
            # Executive Summary Section
            pdf = self._add_formatted_page(pdf, "EXECUTIVE SUMMARY")
            
            total_findings = sum(v["count"] for k,v in self.stats.items())
            self._safe_add_text(pdf, f"This assessment identified {total_findings} security findings across {len(reports)} scanned systems and applications. The following critical issues require immediate attention:")
            
            # Critical Findings Subsection
            pdf.set_font('Arial', 'B', 12)
            self._safe_add_text(pdf, "Critical Security Findings:")
            pdf.set_font('Arial', '', 10)
            
            if self.stats["Critical Vulnerabilities"]["count"] > 0:
                self._safe_add_text(pdf, f"- {self.stats['Critical Vulnerabilities']['count']} Critical Vulnerabilities (CVSS >= 7.0)")
                for vuln in self.stats["Critical Vulnerabilities"]["items"][:5]:
                    self._safe_add_text(pdf, f"  * {vuln}")
            
            if self.stats["Brute Force"]["count"] > 0:
                self._safe_add_text(pdf, f"- {self.stats['Brute Force']['count']} Successful Brute Force Attempts")
                for attempt in self.stats["Brute Force"]["examples"][:3]:
                    self._safe_add_text(pdf, f"  * {attempt}")
            
            if self.stats["SQL Injection"]["count"] > 0:
                self._safe_add_text(pdf, f"- {self.stats['SQL Injection']['count']} SQL Injection Vulnerabilities")
            
            pdf.ln(10)
            
            # Detailed Findings Section
            pdf = self._add_formatted_page(pdf, "DETAILED FINDINGS")
            
            # XSS Findings Subsection
            if self.stats["XSS"]["count"] > 0:
                pdf.set_font('Arial', 'B', 12)
                self._safe_add_text(pdf, f"Cross-Site Scripting (XSS) - {self.stats['XSS']['count']} instances")
                pdf.set_font('Courier', '', 8)
                for example in self.stats["XSS"]["examples"]:
                    self._safe_add_text(pdf, f"- {example}")
                pdf.ln(5)
            
            # SQL Injection Findings Subsection
            if self.stats["SQL Injection"]["count"] > 0:
                pdf.set_font('Arial', 'B', 12)
                self._safe_add_text(pdf, f"SQL Injection - {self.stats['SQL Injection']['count']} instances")
                pdf.set_font('Courier', '', 8)
                for example in self.stats["SQL Injection"]["examples"]:
                    self._safe_add_text(pdf, f"- {example}")
                pdf.ln(5)
            
            # Open Ports Findings Subsection
            if self.stats["Open Ports"]["count"] > 0:
                pdf.set_font('Arial', 'B', 12)
                self._safe_add_text(pdf, f"Open Ports - {self.stats['Open Ports']['count']} ports found")
                pdf.set_font('Courier', '', 8)
                
                # Full list of all ports
                self._safe_add_text(pdf, "Complete list of open ports:")
                for port in self.stats["Open Ports"]["ports"]:
                    self._safe_add_text(pdf, f"- {port}")
                
                # Service breakdown
                pdf.set_font('Arial', 'B', 10)
                self._safe_add_text(pdf, "\nService Breakdown:")
                pdf.set_font('Courier', '', 8)
                for service, count in sorted(self.stats["Open Ports"]["services"].items(), key=lambda x: x[1], reverse=True):
                    self._safe_add_text(pdf, f"- {service}: {count} ports")
                pdf.ln(5)
            
            # Vulnerable Services Findings Subsection
            if self.stats["Vulnerable Services"]["count"] > 0:
                pdf.set_font('Arial', 'B', 12)
                self._safe_add_text(pdf, f"Vulnerable Services - {self.stats['Vulnerable Services']['count']} CVEs found")
                pdf.set_font('Courier', '', 8)
                
                # Full list of all CVEs
                self._safe_add_text(pdf, "Complete list of vulnerabilities:")
                for cve in self.stats["Vulnerable Services"]["cves"]:
                    self._safe_add_text(pdf, f"- {cve}")
                
                # Critical vulnerabilities
                if self.stats["Critical Vulnerabilities"]["count"] > 0:
                    pdf.set_font('Arial', 'B', 10)
                    self._safe_add_text(pdf, "\nCritical Vulnerabilities (CVSS >= 7.0):")
                    pdf.set_font('Courier', '', 8)
                    for vuln in self.stats["Critical Vulnerabilities"]["items"]:
                        self._safe_add_text(pdf, f"- {vuln}")
                pdf.ln(5)
            
            # Security Recommendations Section
            pdf = self._add_formatted_page(pdf, "SECURITY RECOMMENDATIONS")
            pdf.set_font('Arial', '', 12)
            
            recommendations = self._generate_security_recommendations()
            for i, rec in enumerate(recommendations, 1):
                self._safe_add_text(pdf, f"{i}. {rec}")
            
            # Appendix: Full Report Index
            pdf = self._add_formatted_page(pdf, "APPENDIX: FULL REPORT INDEX")
            pdf.set_font('Arial', '', 10)
            
            self._safe_add_text(pdf, "The following reports were analyzed for this assessment:")
            pdf.ln(5)
            
            for report_path in reports:
                report = self._parse_report(report_path)
                pdf.set_font('Arial', 'B', 10)
                self._safe_add_text(pdf, f"Report: {report['filename']}")
                pdf.set_font('Arial', '', 8)
                self._safe_add_text(pdf, f"Type: {report['type']} | Date: {report['timestamp']}")
                if report['findings']:
                    self._safe_add_text(pdf, "Key Findings:")
                    for finding in report['findings']:
                        self._safe_add_text(pdf, f"- {finding}")
                pdf.ln(3)
            
            # Save PDF to file
            pdf_filename = f"security_reports/Comprehensive_Security_Report_{timestamp}.pdf"
            pdf.output(pdf_filename)
            print(f"Comprehensive PDF report generated: {pdf_filename}")
            return pdf_filename
            
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return None        
        
# References: [24], [25]