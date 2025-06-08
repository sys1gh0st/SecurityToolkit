import subprocess  # For executing system commands
import ipaddress  # For IP address validation
from alerts import alerts

class SystemProtector:
    def __init__(self):
        """
        Initialize the system protection module with:
        - IP blocking tracking set
        - Alert system integration
        - Linux iptables firewall control
        """
        self.blocked_ips = set()  # Using set for O(1) lookups
        self.alert_system = alerts()  # Alert notification handler
        print("\nIP Blocker initialized (Linux only)")

    def block_ip(self, ip):
        """
        Block specified IP address using iptables firewall rules.
        Implements bidirectional blocking (inbound/outbound).
        
        Args:
            ip (str): IP address to block
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self._validate_ip(ip):
            print(f"Invalid IP address: {ip}")
            return False

        if ip in self.blocked_ips:
            print(f"IP {ip} is already blocked")
            return True

        try:
            # iptables commands to block traffic in both directions:
            # - INPUT chain: Blocks incoming packets from the IP
            # - OUTPUT chain: Blocks outgoing packets to the IP
            # - -j DROP: Silently discard packets without response
            subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", 
                         shell=True, check=True)
            subprocess.run(f"iptables -A OUTPUT -d {ip} -j DROP", 
                         shell=True, check=True)
            
            self.blocked_ips.add(ip)  # Track blocked IP
            print(f"Successfully blocked IP: {ip}")
            
            # Generate security alert with context
            self.alert_system.generate_alert(
                "IP Blocked", 
                f"Blocked malicious IP: {ip}\n"
                f"Total blocked IPs: {len(self.blocked_ips)}"
            )
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {str(e)}")
            return False
        except Exception as e:
            print(f"Unexpected error blocking IP: {str(e)}")
            return False

    def unblock_ip(self, ip):
        """
        Remove blocking rules for specified IP address.
        Clears both inbound and outbound blocking rules.
        
        Args:
            ip (str): IP address to unblock
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self._validate_ip(ip):
            print(f"Invalid IP address: {ip}")
            return False

        if ip not in self.blocked_ips:
            print(f"IP {ip} is not currently blocked")
            return True

        try:
            # iptables commands to remove blocking rules:
            # -D deletes specific rules instead of -A which appends
            subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", 
                         shell=True, check=True)
            subprocess.run(f"iptables -D OUTPUT -d {ip} -j DROP", 
                         shell=True, check=True)
            
            self.blocked_ips.discard(ip)  # Remove from tracking
            print(f"Successfully unblocked IP: {ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock IP {ip}: {str(e)}")
            return False
        except Exception as e:
            print(f"Unexpected error unblocking IP: {str(e)}")
            return False

    def list_blocked_ips(self):
        """
        Retrieve and display all currently blocked IP addresses.
        
        Returns:
            list: Sorted list of blocked IP addresses
        """
        if not self.blocked_ips:
            print("No IPs are currently blocked")
            return []
        
        print("\nCurrently blocked IPs:")
        # Enumerate and sort IPs for consistent display
        for idx, ip in enumerate(sorted(self.blocked_ips), 1):
            print(f"  {idx}. {ip}")
        
        return list(self.blocked_ips)

    def _validate_ip(self, ip):
        """
        Validate IP address format using ipaddress module.
        Supports both IPv4 and IPv6 addresses.
        
        Args:
            ip (str): IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)  # Leverage stdlib validation
            return True
        except ValueError:
            return False

    def flush_rules(self):
        """
        Remove all active IP blocking rules.
        Clears both firewall rules and internal tracking.
        """
        # Create copy of set to avoid modification during iteration
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
        print("All IP blocks have been removed")
    
# References: [5], [6]