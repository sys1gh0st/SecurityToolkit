from flask import Flask, render_template, request, redirect, url_for, flash
from main import SecurityToolkit
import os
import getpass
import sys

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Global variable to track authentication status
_authenticated = False

def check_credentials():
    """
    Default credentials: admin/password
    """
    global _authenticated
    
    if _authenticated:
        return True
        
    print("\n=== Security Toolkit Authentication ===")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()
    
    if username == "admin" and password == "password":
        print("Authentication successful!\n")
        _authenticated = True
        return True
    else:
        print("Invalid credentials. Access denied.\n")
        return False

# Verify credentials before proceeding
if not check_credentials():
    sys.exit(1)

# Initialize security toolkit after successful authentication
toolkit = SecurityToolkit()  # Main security operations handler

# Tracks current active menu section in the UI
current_menu = "main"

@app.route('/')
def index():
    """Main view that renders the template with current menu state"""
    return render_template('index.html', menu=current_menu)

# Navigation handlers that update the current menu state
@app.route('/main_menu')
def main_menu():
    global current_menu
    current_menu = "main"
    return redirect(url_for('index'))

# Port scanning routes
@app.route('/port_scanning')
def port_scanning_menu():
    global current_menu
    current_menu = "port_scanning"
    return redirect(url_for('index'))

@app.route('/run_quick_scan', methods=['POST'])
def run_quick_scan():
    """Quick nmap scan with common ports only"""
    target = request.form.get('target')
    toolkit.port_scanner.run_quick_scan(target)
    flash(f"Quick scan completed on {target}", 'success')
    return redirect(url_for('index'))

@app.route('/run_full_scan', methods=['POST'])
def run_full_scan():
    """Standard nmap scan checking all 1024 well-known ports"""
    target = request.form.get('target')
    toolkit.port_scanner.run_full_scan(target)
    flash(f"Full scan completed on {target}", 'success')
    return redirect(url_for('index'))

@app.route('/run_comprehensive_scan', methods=['POST'])
def run_comprehensive_scan():
    """Advanced scan with OS detection and service version checking"""
    target = request.form.get('target')
    toolkit.port_scanner.run_comprehensive_scan(target)
    flash(f"Comprehensive scan completed on {target}", 'success')
    return redirect(url_for('index'))

@app.route('/run_custom_scan', methods=['POST'])
def run_custom_scan():
    """Validates and executes custom nmap commands (must start with 'nmap')"""
    full_command = request.form.get('full_command')
    if not full_command.lower().startswith('nmap '):
        full_command = 'nmap ' + full_command
    toolkit.port_scanner.run_custom_scan(full_command)
    flash(f"Custom scan executed: {full_command}", 'success')
    return redirect(url_for('index'))

# Traffic monitoring routes
@app.route('/traffic_analysis')
def traffic_analysis_menu():
    global current_menu
    current_menu = "traffic_analysis"
    return redirect(url_for('index'))

@app.route('/analyze_traffic', methods=['POST'])
def analyze_traffic():
    """Starts packet capture on specified network interface"""
    interface = request.form.get('interface', 'eth0')
    toolkit.traffic_analyzer.analyze_traffic(interface=interface)
    flash(f"Traffic analysis started on {interface}", 'success')
    return redirect(url_for('index'))

@app.route('/anti_brute_force', methods=['POST'])
def anti_brute_force():
    """Monitors specified port for brute force attempts"""
    port = request.form.get('port', '5000')
    toolkit.traffic_analyzer.anti_brute_force(port=int(port))
    flash("Brute force detection started", 'success')
    return redirect(url_for('index'))

@app.route('/stop_analysis', methods=['POST'])
def stop_analysis():
    """Terminates all running traffic analysis processes"""
    toolkit.traffic_analyzer.stop_analysis()
    toolkit.traffic_analyzer.stop_brute_force_detection()
    flash("Analysis stopped successfully", 'success')
    return redirect(url_for('index'))

# Security testing routes
@app.route('/penetration_testing')
def penetration_testing_menu():
    global current_menu
    current_menu = "penetration_testing"
    return redirect(url_for('index'))

@app.route('/test_website', methods=['POST'])
def test_website():
    """Runs basic vulnerability scan against target URL"""
    url = request.form.get('url')
    toolkit.penetration_tester.test_website(url)
    flash(f"Website vulnerability test completed for {url}", 'success')
    return redirect(url_for('index'))

@app.route('/check_brute_force', methods=['POST'])
def check_brute_force():
    """Tests login page resilience against brute force attacks"""
    url = request.form.get('url')
    toolkit.penetration_tester.check_brute_force(url)
    flash(f"Brute force test completed for {url}", 'success')
    return redirect(url_for('index'))

# System protection routes
@app.route('/system_protection')
def system_protection_menu():
    global current_menu
    current_menu = "system_protection"
    return redirect(url_for('index'))

@app.route('/block_ip', methods=['POST'])
def block_ip():
    """Adds iptables rule to block specified IP"""
    ip = request.form.get('ip')
    toolkit.system_protector.block_ip(ip)
    flash(f"IP {ip} blocked successfully", 'success')
    return redirect(url_for('index'))

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    """Removes iptables block rule for specified IP"""
    ip = request.form.get('ip')
    toolkit.system_protector.unblock_ip(ip)
    flash(f"IP {ip} unblocked successfully", 'success')
    return redirect(url_for('index'))

@app.route('/list_blocked_ips', methods=['GET', 'POST'])
def list_blocked_ips():
    """Retrieves and displays currently blocked IPs from system"""
    blocked_ips = toolkit.system_protector.list_blocked_ips()
    flash(f"Blocked IPs: {', '.join(blocked_ips)}", 'info')
    return redirect(url_for('index'))

# Web content analysis routes
@app.route('/web_traffic')
def web_traffic_menu():
    global current_menu
    current_menu = "web_traffic"
    return redirect(url_for('index'))

@app.route('/deep_content_analysis', methods=['POST'])
def deep_content_analysis():
    """Analyzes website content for hidden patterns/data"""
    url = request.form.get('url')
    toolkit.web_traffic_monitor.deep_content_analysis(url)
    flash(f"Deep content analysis completed for {url}", 'success')
    return redirect(url_for('index'))

@app.route('/perform_web_scraping', methods=['POST'])
def perform_web_scraping():
    """Extracts structured data from target webpage"""
    url = request.form.get('url')
    toolkit.web_traffic_monitor.perform_web_scraping(url)
    flash(f"Web scraping completed for {url}", 'success')
    return redirect(url_for('index'))

# Reporting functionality
@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():
    """Compiles all security findings into comprehensive report"""
    toolkit.reporter.generate_complete_report()
    flash("Comprehensive report generated successfully! Check security_reports directory", 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('scan_reports', exist_ok=True)
    
    # Disable reloader to prevent double authentication
    app.run(debug=True, host='127.0.0.1', port=5001, use_reloader=False)
    
# References: [1], [2], [16]
