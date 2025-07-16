#!/usr/bin/env python3
"""
Network utilities for InjectHost.
Provides DNS cache flushing, connectivity testing, and network scanning capabilities.
"""

import subprocess
import socket
import time
import threading
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class NetworkUtils:
    """Network utility class for DNS and connectivity operations."""
    
    @staticmethod
    def flush_dns_cache() -> bool:
        """Flush DNS cache on various operating systems."""
        try:
            # Detect OS and use appropriate command
            import platform
            system = platform.system().lower()
            
            if system == "linux":
                # Try different DNS flush methods for Linux
                commands = [
                    ["systemctl", "reload", "systemd-resolved"],
                    ["service", "nscd", "restart"],
                    ["systemctl", "restart", "NetworkManager"],
                    ["nscd", "-i", "hosts"]
                ]
                
                for cmd in commands:
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            logger.info(f"DNS cache flushed using: {' '.join(cmd)}")
                            return True
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                
                # If no specific command worked, try a generic approach
                logger.warning("Could not flush DNS cache with system commands")
                return False
                
            elif system == "darwin":  # macOS
                subprocess.run(["sudo", "dscacheutil", "-flushcache"], check=True)
                subprocess.run(["sudo", "killall", "-HUP", "mDNSResponder"], check=True)
                logger.info("DNS cache flushed on macOS")
                return True
                
            elif system == "windows":
                subprocess.run(["ipconfig", "/flushdns"], check=True)
                logger.info("DNS cache flushed on Windows")
                return True
                
            else:
                logger.warning(f"Unknown OS: {system}, cannot flush DNS cache")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to flush DNS cache: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error flushing DNS cache: {e}")
            return False
    
    @staticmethod
    def test_hostname_resolution(hostname: str, timeout: int = 5) -> Tuple[bool, Optional[str]]:
        """Test if a hostname resolves to an IP address."""
        try:
            # Try to resolve the hostname
            ip = socket.gethostbyname(hostname)
            return True, ip
        except socket.gaierror:
            return False, None
        except Exception as e:
            logger.error(f"Error testing hostname resolution for {hostname}: {e}")
            return False, None
    
    @staticmethod
    def test_connectivity(hostname: str, port: int = 80, timeout: int = 5) -> bool:
        """Test connectivity to a hostname on a specific port."""
        try:
            # First resolve the hostname
            ip = socket.gethostbyname(hostname)
            
            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return result == 0
        except Exception as e:
            logger.error(f"Error testing connectivity to {hostname}:{port}: {e}")
            return False
    
    @staticmethod
    def ping_host(hostname: str, count: int = 3, timeout: int = 5) -> Dict[str, any]:
        """Ping a hostname and return results."""
        try:
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), hostname]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), hostname]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 2)
            
            if result.returncode == 0:
                # Parse ping output for statistics
                output = result.stdout
                lines = output.split('\n')
                
                # Extract packet loss and timing info
                packet_loss = 0
                avg_time = 0
                
                for line in lines:
                    if "packet loss" in line.lower() or "packets transmitted" in line.lower():
                        # Parse packet loss percentage
                        import re
                        loss_match = re.search(r'(\d+(?:\.\d+)?)%?\s*(?:packet loss|loss)', line)
                        if loss_match:
                            packet_loss = float(loss_match.group(1))
                    
                    if "avg" in line.lower() or "average" in line.lower():
                        # Parse average time
                        import re
                        time_match = re.search(r'(\d+(?:\.\d+)?)\s*ms', line)
                        if time_match:
                            avg_time = float(time_match.group(1))
                
                return {
                    "success": True,
                    "hostname": hostname,
                    "packet_loss": packet_loss,
                    "avg_time": avg_time,
                    "output": output
                }
            else:
                return {
                    "success": False,
                    "hostname": hostname,
                    "error": result.stderr,
                    "output": result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "hostname": hostname,
                "error": "Ping timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "hostname": hostname,
                "error": str(e)
            }
    
    @staticmethod
    def scan_local_network(base_ip: str = "192.168.1", start: int = 1, end: int = 254, timeout: float = 1.0) -> List[Dict[str, any]]:
        """Scan local network for active hosts."""
        active_hosts = []
        
        def scan_host(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, 22))  # SSH port as indicator
                sock.close()
                
                if result == 0:
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "unknown"
                    
                    active_hosts.append({
                        "ip": ip,
                        "hostname": hostname,
                        "status": "active"
                    })
            except:
                pass
        
        # Use threading for faster scanning
        threads = []
        for i in range(start, end + 1):
            ip = f"{base_ip}.{i}"
            thread = threading.Thread(target=scan_host, args=(ip,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join()
        
        return active_hosts
    
    @staticmethod
    def get_ssl_certificate_info(hostname: str, port: int = 443, timeout: int = 10) -> Optional[Dict[str, any]]:
        """Get SSL certificate information for a hostname."""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate dates safely
                    not_before = datetime.now()
                    not_after = datetime.now()
                    
                    if cert and 'notBefore' in cert:
                        try:
                            not_before = datetime.strptime(str(cert['notBefore']), '%b %d %H:%M:%S %Y %Z')
                        except (ValueError, TypeError):
                            pass
                    
                    if cert and 'notAfter' in cert:
                        try:
                            not_after = datetime.strptime(str(cert['notAfter']), '%b %d %H:%M:%S %Y %Z')
                        except (ValueError, TypeError):
                            pass
                    
                    # Parse subject and issuer safely
                    subject_dict = {}
                    if cert and 'subject' in cert and cert['subject']:
                        for item in cert['subject']:
                            if isinstance(item, tuple) and len(item) >= 2:
                                subject_dict[str(item[0])] = str(item[1])
                    
                    issuer_dict = {}
                    if cert and 'issuer' in cert and cert['issuer']:
                        for item in cert['issuer']:
                            if isinstance(item, tuple) and len(item) >= 2:
                                issuer_dict[str(item[0])] = str(item[1])
                    
                    return {
                        "subject": subject_dict,
                        "issuer": issuer_dict,
                        "not_before": not_before,
                        "not_after": not_after,
                        "serial_number": str(cert.get('serialNumber', '')) if cert else '',
                        "version": cert.get('version', 0) if cert else 0,
                        "san": cert.get('subjectAltName', []) if cert else [],
                        "is_valid": datetime.now() < not_after
                    }
        except Exception as e:
            logger.error(f"Error getting SSL certificate for {hostname}: {e}")
            return None

# Convenience functions
def flush_dns_cache() -> bool:
    """Flush DNS cache."""
    return NetworkUtils.flush_dns_cache()

def test_hostname(hostname: str) -> Tuple[bool, Optional[str]]:
    """Test hostname resolution."""
    return NetworkUtils.test_hostname_resolution(hostname)

def ping_hostname(hostname: str) -> Dict[str, any]:
    """Ping a hostname."""
    return NetworkUtils.ping_host(hostname)

def scan_network(base_ip: str = "192.168.1") -> List[Dict[str, any]]:
    """Scan local network."""
    return NetworkUtils.scan_local_network(base_ip) 