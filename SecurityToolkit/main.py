from portscanner import PortScanner
from trafficanalyzer import TrafficAnalyzer
from penetrationtester import PenetrationTester
from systemprotector import SystemProtector
from webtrafficmonitor import WebTrafficMonitor
from reporter import Reporter
from alerts import alerts

class SecurityToolkit:
    def __init__(self):
        """Initialize all security components and their integrations"""
        print("\nInitializing Security Toolkit")
        # Core components initialization
        self.alerts = alerts()  # Alert notification system
        self.reporter = Reporter()  # Report generation module
        # Security modules with required dependencies
        self.port_scanner = PortScanner(self.alerts)  # Port scanning with alert capability
        self.system_protector = SystemProtector()  # IP blocking functionality
        # Traffic analyzer needs system protector for automatic blocking
        self.traffic_analyzer = TrafficAnalyzer(self.system_protector)
        self.penetration_tester = PenetrationTester()  # Vulnerability testing
        self.web_traffic_monitor = WebTrafficMonitor()  # Web content analysis
        self._setup_integrations()  # Configure cross-module connections

    def _setup_integrations(self):
        """Establish connections between modules for alert sharing"""
        self.traffic_analyzer.alert_system = self.alerts
        self.penetration_tester.alerts = self.alerts
        self.web_traffic_monitor.alert_system = self.alerts

    def port_scanning_menu(self):
        """Delegate to PortScanner's menu interface"""
        self.port_scanner.show_scan_menu()

    def penetration_testing_menu(self):
        """Interactive menu for website vulnerability testing"""
        while True:
            print("\n--- Penetration Testing ---")
            print("1. Test website vulnerabilities (SQLi/XSS)")
            print("2. Check for brute force vulnerabilities")
            print("3. Return to main menu")
            
            choice = input("Select an option: ")

            if choice == '1':
                url = input("Enter the URL to test: ")
                self.penetration_tester.test_website(url)
            elif choice == '2':
                url = input("Enter the login URL to test: ")
                self.penetration_tester.check_brute_force(url)
            elif choice == '3':
                break
            else:
                print("Invalid option")

    def system_protection_menu(self):
        """Menu for IP address management and firewall controls"""
        while True:
            print("\n--- System Protection ---")
            print("1. Block suspicious IP")
            print("2. Unblock IP")
            print("3. List blocked IPs")
            print("4. Return to main menu")
            
            choice = input("Select an option: ")

            if choice == '1':
                ip = input("Enter the IP to block: ")
                self.system_protector.block_ip(ip)
            elif choice == '2':
                ip = input("Enter the IP to unblock: ")
                self.system_protector.unblock_ip(ip)
            elif choice == '3':
                self.system_protector.list_blocked_ips()
            elif choice == '4':
                break
            else:
                print("Invalid option")

    def traffic_analysis_menu(self):
        """Network monitoring and anomaly detection interface"""
        while True:
            print("\n--- Traffic Analysis Options ---")
            print("1. Detect anomalous patterns")
            print("2. Real-time Traffic Analyzer")
            print("3. Return to main menu")
            
            choice = input("Select an option: ")

            if choice == '1':
                self.traffic_analyzer.anti_brute_force()
            elif choice == '2':
                interface = input("Enter network interface (default: eth0): ") or "eth0"
                self.traffic_analyzer.analyze_traffic(interface=interface)
            elif choice == '3':
                break
            else:
                print("Invalid option")

    def web_traffic_menu(self):
        """Web content analysis and data extraction interface"""
        while True:
            print("\n--- Web Traffic Monitoring ---")
            print("1. App Layer Analysis (SQL & XSS)")
            print("2. Perform web scraping")
            print("3. Return to main menu")
            
            choice = input("Select an option: ")

            if choice == '1':
                url = input("Enter URL to analyze: ")
                self.web_traffic_monitor.deep_content_analysis(url)
            elif choice == '2':
                url = input("Enter URL to scrape: ")
                self.web_traffic_monitor.perform_web_scraping(url)
            elif choice == '3':
                break
            else:
                print("Invalid option")

    def menu(self):
        """Main control loop for the security toolkit"""
        while True:
            print("\n=== Security Toolkit ===")
            print("1. Port Scanning & Vulnerability Assessment")
            print("2. Network Traffic Analysis")
            print("3. Penetration Testing")
            print("4. System Protection")
            print("5. Web Traffic Monitoring")
            print("6. Generate Security Reports")
            print("7. Exit")
            
            choice = input("\nSelect an option: ")
            
            if choice == '1':
                self.port_scanning_menu()
            elif choice == '2':
                self.traffic_analysis_menu()
            elif choice == '3':
                self.penetration_testing_menu()
            elif choice == '4':
                self.system_protection_menu()
            elif choice == '5':
                self.web_traffic_menu()
            elif choice == '6':
                print("\nGenerating comprehensive security report...")
                self.reporter.generate_complete_report()
                print("Report generated successfully! Check security_reports directory")
            elif choice == '7':
                print("\nExiting Security Toolkit...")
                break
            else:
                print("Invalid option")

if __name__ == "__main__":
    try:
        # Start the toolkit with interactive menu
        toolkit = SecurityToolkit()
        toolkit.menu()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
    except Exception as e:
        print(f"\nCritical error: {str(e)}")