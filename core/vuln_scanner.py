#core/vuln_scanner.py
#!/usr/bin/env python3
"""
Vulnerability Scanner Module
Checks for common vulnerabilities in network services
"""

import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor
from utils.logger import Logger

logger = Logger()

class VulnerabilityScanner:
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout
        self.vulnerabilities = []

    def check_ssl_vulnerability(self, port):
        """Check for SSL/TLS vulnerabilities"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                        if expiry < ssl.cert_time_to_seconds():
                            self.vulnerabilities.append({
                                'port': port,
                                'type': 'SSL Certificate Expired',
                                'severity': 'High',
                                'details': f"Certificate expired on {cert['notAfter']}"
                            })
                    
                    # Check for weak protocols
                    protocols = ssock.shared_ciphers()
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                    for protocol in weak_protocols:
                        if any(p[1].startswith(protocol) for p in protocols):
                            self.vulnerabilities.append({
                                'port': port,
                                'type': 'Weak SSL/TLS Protocol',
                                'severity': 'Medium',
                                'details': f"Supports {protocol}"
                            })
        
        except Exception as e:
            logger.debug(f"SSL check error on port {port}: {str(e)}")

    def check_default_credentials(self, port, service):
        """Check for default credentials"""
        default_creds = {
            'ftp': [('anonymous', 'anonymous'), ('admin', 'admin')],
            'ssh': [('root', 'root'), ('admin', 'admin')],
            'mysql': [('root', ''), ('root', 'root')],
            'postgresql': [('postgres', 'postgres')],
            'mongodb': [('admin', 'admin')]
        }
        
        if service in default_creds:
            for username, password in default_creds[service]:
                try:
                    # Implement service-specific authentication checks here
                    # This is a placeholder for demonstration
                    self.vulnerabilities.append({
                        'port': port,
                        'type': 'Default Credentials Check',
                        'severity': 'High',
                        'details': f"Service: {service}, Credentials: {username}:{password}"
                    })
                except Exception as e:
                    logger.debug(f"Credentials check error: {str(e)}")

    def check_known_vulnerabilities(self, port, banner):
        """Check for known vulnerabilities based on banner information"""
        vuln_patterns = {
            r'Apache/(2\.4\.[0-9]|2\.2\.[0-9])': 'Vulnerable Apache Version',
            r'OpenSSH_(3|4|5|6|7\.[0-5])': 'Vulnerable OpenSSH Version',
            r'ProFTPD 1\.[3]\.[0-4]': 'Vulnerable ProFTPD Version'
        }
        
        for pattern, vuln_type in vuln_patterns.items():
            if re.search(pattern, banner):
                self.vulnerabilities.append({
                    'port': port,
                    'type': vuln_type,
                    'severity': 'High',
                    'details': f"Vulnerable version detected in banner: {banner}"
                })

def scan_vulnerabilities(target, ports, banners, timeout=10):
    """
    Main vulnerability scanning function
    
    Args:
        target (str): Target IP or hostname
        ports (list): List of open ports
        banners (dict): Dictionary of service banners
        timeout (float): Timeout for connections
        
    Returns:
        list: List of discovered vulnerabilities
    """
    scanner = VulnerabilityScanner(target, timeout)
    
    # Check SSL/TLS vulnerabilities on HTTPS ports
    ssl_ports = [p for p in ports if p in [443, 8443] or 
                 'ssl' in banners.get(p, {}).get('service', '').lower()]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scanner.check_ssl_vulnerability, ssl_ports)
    
    # Check other vulnerabilities
    for port in ports:
        banner_info = banners.get(port, {})
        service = banner_info.get('service', '').lower()
        banner = banner_info.get('banner', '')
        
        scanner.check_default_credentials(port, service)
        scanner.check_known_vulnerabilities(port, banner)
    
    return scanner.vulnerabilities

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        # Simple test with common ports
        test_ports = [80, 443, 22, 21]
        test_banners = {
            80: {'service': 'apache', 'banner': 'Apache/2.4.29'},
            443: {'service': 'https', 'banner': 'nginx/1.14.0'},
            22: {'service': 'ssh', 'banner': 'OpenSSH_7.6p1'},
            21: {'service': 'ftp', 'banner': 'ProFTPD 1.3.5'}
        }
        
        vulns = scan_vulnerabilities(target, test_ports, test_banners)
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']} on port {vuln['port']}")
            print(f"Details: {vuln['details']}\n")
    else:
        print("Usage: python vuln_scanner.py <target>")
