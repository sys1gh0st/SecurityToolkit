import scapy.all as scapy  # Packet manipulation library
import threading  # For concurrent packet processing
import os  # Filesystem operations
import time  # Timestamp and delay functions
from datetime import datetime  # For timestamping events
from collections import defaultdict  # For efficient IP tracking
from systemprotector import SystemProtector  # IP blocking functionality
from alerts import alerts  # Alert notification system
from reporter import Reporter  # Report generation module

class TrafficAnalyzer:
    def __init__(self, system_protector=None, verbose=False):
        """
        Initialize the traffic analysis engine with:
        - Packet capture configuration
        - Anomaly detection thresholds
        - Security integration points
        - Reporting infrastructure
        """
        self.traffic_results = ""  # Buffer for analysis results
        self.is_monitoring = False  # Runtime state flag
        self.stop_sniffing = threading.Event()  # Thread-safe stop signal
        self.packet_count = 0  # Packet counter
        self.max_packets = 500  # Default capture limit
        self.suspicious_ips = defaultdict(lambda: {  # IP tracking structure
            'count': 0,            # Attempt counter
            'first_seen': None,     # Initial detection timestamp
            'last_attempt': None,   # Most recent attempt
            'target_port': None,    # Targeted service port
            'is_brute_force': False,# Brute force classification
            'reported': False       # Alert status
        })
        self.ip_blocker = system_protector  # IP blocking interface
        self.reporter = Reporter()  # Report generator
        self.verbose = verbose  # Debug output control
        self.report_dir = "scan_reports"  # Output directory
        os.makedirs(self.report_dir, exist_ok=True)  # Ensure dir exists
        self.packet_log = []  # Raw packet storage
        self.anomaly_threshold = 3  # Suspicious activity threshold
        self.whitelist = {'127.0.0.1', '::1', '10.0.2.15'}  # Trusted IPs
        self.current_report_filename = None  # Active report file
        self.brute_force_active = False  # Brute force detection state
        self.brute_force_detector = BruteForceDetector(self)  # Specialized detector
        self.alert_system = alerts()  # Alert notification handler

    def _is_suspicious_port(self, port):
        """
        Identify commonly targeted service ports.
        
        Args:
            port (int): Port number to check
            
        Returns:
            bool: True if port is high-risk, False otherwise
        """
        return str(port) in ['80', '443', '5000', '8080', '5001']  # HTTP, HTTPS, common app ports

    def analyze_traffic(self, interface="eth0", max_packets=100):
        """
        Main traffic analysis entry point.
        Starts packet capture on specified interface.
        
        Args:
            interface (str): Network interface to monitor
            max_packets (int): Maximum packets to capture
        """
        self.max_packets = max_packets
        self.packet_count = 0
        self.packet_log = []
        # Create timestamped report file
        self.current_report_filename = f"traffic_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        print(f"\nStarting traffic analysis on {interface} (max {max_packets} packets)")
        self.is_monitoring = True
        self.stop_sniffing.clear()  # Reset stop signal
        
        try:
            # Start packet capture in background thread
            sniff_thread = threading.Thread(
                target=self._start_sniffing,
                args=(interface,),
                daemon=True  # Allow main program to exit
            )
            sniff_thread.start()
            
            # Main monitoring loop
            while self.is_monitoring and not self.stop_sniffing.is_set():
                time.sleep(0.1)  # Reduce CPU usage
                
        except KeyboardInterrupt:
            print("\nTraffic analysis stopped by user")
            self.stop_analysis()

    def _start_sniffing(self, interface):
        """
        Low-level packet capture using Scapy.
        
        Args:
            interface (str): Network interface to sniff
        """
        try:
            scapy.sniff(
                iface=interface,  # Network interface
                prn=self._process_packet,  # Packet callback
                stop_filter=self._stop_condition,  # Termination check
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            print(f"Sniffing error: {str(e)}")
        finally:
            self._save_packet_log()  # Persist results
            print(f"\nAnalysis completed. Captured {self.packet_count} packets")
            self.is_monitoring = False

    def _process_packet(self, packet):
        """
        Process individual network packets.
        Performs analysis, logging, and anomaly detection.
        
        Args:
            packet (scapy.Packet): Captured network packet
        """
        if self.stop_sniffing.is_set():
            return
            
        self.packet_count += 1
        packet_summary = self._get_packet_summary(packet)
        self.packet_log.append(packet_summary)
        
        # Verbose debug output
        if self.verbose:
            print(f"\n[Packet #{packet_summary['number']}]")
            print(f"Timestamp: {packet_summary['timestamp']}")
            print(f"Source: {packet_summary.get('src', 'N/A')}")
            print(f"Destination: {packet_summary.get('dst', 'N/A')}")
            print(f"Protocol: {packet_summary.get('protocol', 'N/A')}")
            if 'sport' in packet_summary:
                print(f"Source Port: {packet_summary['sport']}")
                print(f"Dest Port: {packet_summary['dport']}")
            print(f"Payload Type: {packet_summary.get('payload_type', 'N/A')}")
        
        # Perform security analysis on IP traffic
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            if src_ip not in self.whitelist:  # Skip trusted IPs
                self._detect_anomalies(packet)

    def _get_packet_summary(self, packet):
        """
        Create structured packet metadata.
        
        Args:
            packet (scapy.Packet): Network packet
            
        Returns:
            dict: Structured packet information
        """
        summary = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            'number': self.packet_count,
            'payload_type': 'Unknown'
        }
        
        # IP layer analysis
        if packet.haslayer(scapy.IP):
            summary.update({
                'src': packet[scapy.IP].src,
                'dst': packet[scapy.IP].dst,
                'protocol': 'IP'
            })
            
            # TCP layer analysis
            if packet.haslayer(scapy.TCP):
                summary.update({
                    'protocol': 'TCP',
                    'sport': packet[scapy.TCP].sport,
                    'dport': packet[scapy.TCP].dport,
                    'flags': str(packet[scapy.TCP].flags)
                })
                
                # Payload analysis
                if packet.haslayer(scapy.Raw):
                    payload_bytes = packet[scapy.Raw].load
                    try:
                        decoded = payload_bytes.decode('utf-8', errors='strict')
                        if any(method in decoded for method in ['GET ', 'POST ', 'PUT ', 'HEAD ']):
                            summary['payload_type'] = 'HTTP Request'
                        elif 'HTTP/' in decoded.split('\r\n')[0]:
                            summary['payload_type'] = 'HTTP Response'
                        else:
                            summary['payload_type'] = 'Text Data'
                    except UnicodeDecodeError:
                        summary['payload_type'] = 'Encrypted/Non-HTTP Data'
        
        return summary

    def _detect_anomalies(self, packet):
        """
        Detect suspicious network patterns.
        Implements threshold-based detection.
        
        Args:
            packet (scapy.Packet): Network packet to analyze
        """
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.TCP].dport
            
            # Skip non-suspicious ports
            if not self._is_suspicious_port(dst_port):
                return
                
            # Initialize tracking for new IPs
            if not self.suspicious_ips[src_ip]['first_seen']:
                self.suspicious_ips[src_ip]['first_seen'] = datetime.now()
                self.suspicious_ips[src_ip]['target_port'] = dst_port
            
            # Update counters
            self.suspicious_ips[src_ip]['count'] += 1
            self.suspicious_ips[src_ip]['last_attempt'] = datetime.now()
            
            # Threshold-based alerting
            if self.suspicious_ips[src_ip]['count'] >= self.anomaly_threshold:
                if not self.suspicious_ips[src_ip]['reported']:
                    self.suspicious_ips[src_ip]['reported'] = True
                    self._trigger_anomaly_alert(src_ip, packet)
                    self._block_ip_with_verification(src_ip)

    def anti_brute_force(self, port=5000):
        """Start brute force detection on specified port"""
        self.brute_force_detector.start(port)

    def stop_brute_force_detection(self):
        """Stop active brute force detection"""
        self.brute_force_detector.stop()

    def _block_ip_with_verification(self, ip):
        """
        Block IP and verify success.
        
        Args:
            ip (str): IP address to block
            
        Returns:
            bool: True if blocked successfully
        """
        if self.ip_blocker.block_ip(ip):
            blocked_ips = self.ip_blocker.list_blocked_ips()
            print(f"\nSuccessfully blocked IP: {ip}")
            print(f"Current blocked IPs: {', '.join(blocked_ips)}")
            return True
        else:
            print(f"\nFailed to block IP: {ip}")
            return False

    def _trigger_anomaly_alert(self, src_ip, packet):
        """
        Generate security alert for anomalous traffic.
        
        Args:
            src_ip (str): Source IP of anomalous traffic
            packet (scapy.Packet): Associated network packet
        """
        port = self.suspicious_ips[src_ip]['target_port']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        alert_msg = (f"Anomalous traffic detected\n"
                    f"Source IP: {src_ip}\n"
                    f"Target Port: {port}\n"
                    f"Attempts: {self.suspicious_ips[src_ip]['count']}\n"
                    f"First Attempt: {self.suspicious_ips[src_ip]['first_seen']}\n"
                    f"Last Attempt: {timestamp}")
        
        print("\nALERT: ANOMALOUS TRAFFIC DETECTED")
        print(alert_msg)
        
        self.alert_system.generate_alert("ANOMALOUS TRAFFIC", alert_msg)
        self._append_to_report(alert_msg)

    def _trigger_brute_force_alert(self, src_ip, packet):
        """
        Generate security alert for brute force attack.
        
        Args:
            src_ip (str): Source IP of attack
            packet (scapy.Packet): Associated network packet
        """
        port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else None
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        alert_msg = (f"Brute force attack detected\n"
                    f"Source IP: {src_ip}\n"
                    f"Target Port: {port}\n"
                    f"Timestamp: {timestamp}")
        
        print("\nALERT: BRUTE FORCE ATTACK DETECTED")
        print(alert_msg)
        
        self.alert_system.generate_alert("BRUTE FORCE", alert_msg)
        self._append_to_report(alert_msg)

    def _append_to_report(self, content):
        """
        Append security events to report file.
        
        Args:
            content (str): Content to append
        """
        if not self.current_report_filename:
            return
            
        filepath = os.path.join(self.report_dir, self.current_report_filename)
        with open(filepath, 'a') as f:
            f.write("\n" + "="*50 + "\n")
            f.write(content)
            f.write("\n" + "="*50 + "\n")

    def _stop_condition(self, packet):
        """
        Determine when to stop packet capture.
        
        Args:
            packet (scapy.Packet): Current packet (unused)
            
        Returns:
            bool: True if should stop, False otherwise
        """
        return self.stop_sniffing.is_set() or self.packet_count >= self.max_packets

    def _save_packet_log(self):
        """
        Save captured packets and analysis to file.
        Creates structured report with:
        - Metadata
        - Anomaly summary
        - Packet details
        """
        if not self.packet_log:
            return
            
        filepath = os.path.join(self.report_dir, self.current_report_filename)
        
        with open(filepath, 'w') as f:
            # Report header
            f.write("=== TRAFFIC ANALYSIS REPORT ===\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Packets: {self.packet_count}\n")
            
            # Anomaly summary
            f.write("\n=== ANOMALOUS ACTIVITY ===\n")
            for ip, data in self.suspicious_ips.items():
                if data['count'] > 0:
                    f.write(f"IP: {ip} | Attempts: {data['count']} | Port: {data['target_port']} | Brute Force: {'Yes' if data['is_brute_force'] else 'No'}\n")
            
            # Detailed packet log
            f.write("\n=== PACKET LOG ===\n")
            for packet in self.packet_log:
                f.write(f"\n[Packet #{packet['number']}]\n")
                f.write(f"Timestamp: {packet['timestamp']}\n")
                if 'src' in packet:
                    f.write(f"Source: {packet['src']}\n")
                    f.write(f"Destination: {packet['dst']}\n")
                    f.write(f"Protocol: {packet['protocol']}\n")
                    if 'sport' in packet:
                        f.write(f"Source Port: {packet['sport']}\n")
                        f.write(f"Dest Port: {packet['dport']}\n")
                    f.write(f"Payload Type: {packet.get('payload_type', 'Unknown')}\n")
                f.write("-" * 40 + "\n")

    def stop_analysis(self):
        """Gracefully stop traffic analysis"""
        if not self.stop_sniffing.is_set():
            self.stop_sniffing.set()
            self.is_monitoring = False
            self._save_packet_log()
            print("\nTraffic analysis stopped")

class BruteForceDetector:
    """Specialized brute force attack detector"""
    def __init__(self, traffic_analyzer):
        """
        Initialize brute force detector with:
        - Reference to parent analyzer
        - Attack tracking state
        - Network interface configuration
        """
        self.traffic_analyzer = traffic_analyzer  # Parent analyzer
        self.counter = 0  # Attempt counter
        self.stop_sniffing = threading.Event()  # Stop signal
        self.interface = "lo"  # Default to loopback
        self.last_packet_time = None  # Rate limiting

    def packet_callback(self, packet):
        """
        Process packets for brute force patterns.
        Implements rate limiting and credential detection.
        
        Args:
            packet (scapy.Packet): Network packet to analyze
        """
        if self.stop_sniffing.is_set():
            return

        if packet.haslayer(scapy.Raw):
            try:
                load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                current_time = time.time()
                
                # Detect login attempts with rate limiting
                if ("username=" in load.lower() and 
                    "password=" in load.lower() and 
                    (self.last_packet_time is None or 
                     (current_time - self.last_packet_time) > 0.5)):
                    
                    self.counter += 1
                    self.last_packet_time = current_time
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"[{timestamp}] Failed login attempt #{self.counter}")
                    
                    # Threshold-based detection
                    if self.counter > 3:
                        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "127.0.0.1"
                        print(f"Bruteforce Attempt Detected")
                        
                        if packet.haslayer(scapy.IP) and src_ip not in self.traffic_analyzer.whitelist:
                            self.traffic_analyzer._trigger_brute_force_alert(src_ip, packet)
                            self.traffic_analyzer._block_ip_with_verification(src_ip)
            except Exception:
                pass  # Silently handle parsing errors

    def start(self, port):
        """
        Start brute force detection on specified port.
        
        Args:
            port (int): Port number to monitor
        """
        self.counter = 0
        self.stop_sniffing.clear()
        self.last_packet_time = None
        
        print(f"\nStarting BruteForce Detector")
        
        # Start detection in background thread
        self.sniff_thread = threading.Thread(
            target=self._run_detection,
            args=(port,),
            daemon=True
        )
        self.sniff_thread.start()

    def _run_detection(self, port):
        """
        Main detection loop with BPF filter.
        
        Args:
            port (int): Port number to monitor
        """
        try:
            scapy.sniff(
                filter=f"tcp port {port}",  # BPF filter
                prn=self.packet_callback,
                store=0,  # Don't store packets
                iface=self.interface,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            )
        except Exception as e:
            print(f"BruteForce Detector error: {str(e)}")
        finally:
            print("\nBruteForce Detector stopped")

    def stop(self):
        """Stop brute force detection"""
        self.stop_sniffing.set()
        if hasattr(self, 'sniff_thread') and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)  # Wait for thread
            
# References: [7], [8], [9], [10], [11], [12], [18], [19]