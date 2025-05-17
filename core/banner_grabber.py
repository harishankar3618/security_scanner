import re
import logging
import socket
import concurrent.futures

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def identify_service(port, banner):
    """
    Identify service and version based on banner and port
    
    Args:
        port (int): Port number
        banner (str): Service banner
        
    Returns:
        dict: Service and version information
    """
    result = {'service': 'unknown', 'version': None}
    
    # Common service patterns
    patterns = {
        'ssh': (r'SSH-(\d+\.\d+).*?', r'SSH-\d+\.\d+-([^\s]+)'),
        'http': (r'HTTP/(\d+\.\d+)', r'Server: ([^\r\n]+)'),
        'ftp': (r'FTP|FileZilla|ProFTPD|vsftpd', r'([^\s]+) FTP|ProFTPD ([^\s]+)|FileZilla Server ([^\s]+)|vsftpd ([^\s]+)'),
        'smtp': (r'SMTP|Postfix|Exim|Sendmail', r'([^\s]+) ESMTP|ESMTP ([^\s]+)|Postfix ([^\s]+)|Exim ([^\s]+)|Sendmail ([^\s]+)'),
        'mysql': (r'MySQL', r'MySQL v([^\s]+)'),
        'postgresql': (r'PostgreSQL', r'PostgreSQL ([^\s]+)'),
        'rdp': (r'RDP', None),
        'vnc': (r'VNC|RFB', r'RFB (\d+\.\d+)'),
        'telnet': (r'telnet', None)
    }
    
    # Default service based on common ports
    default_services = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        445: 'smb',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6379: 'redis',
        8080: 'http-alt',
        8443: 'https-alt',
        9200: 'elasticsearch',
        27017: 'mongodb'
    }
    
    # First try to identify by banner
    for service, (service_pattern, version_pattern) in patterns.items():
        if service_pattern and re.search(service_pattern, banner, re.IGNORECASE):
            result['service'] = service
            if version_pattern:
                version_match = re.search(version_pattern, banner, re.IGNORECASE)
                if version_match:
                    # Use the first non-None group
                    for group in version_match.groups():
                        if group:
                            result['version'] = group
                            break
            break
    
    # If not identified, use default service based on port
    if result['service'] == 'unknown' and port in default_services:
        result['service'] = default_services[port]
    
    return result
def grab_banner(target, port, timeout=2.0):
    """
    Grab service banner from a specific port
    
    Args:
        target (str): Target IP or hostname
        port (int): Port number
        timeout (float): Socket timeout in seconds
        
    Returns:
        dict: Banner information
    """
    banner = ""
    service_info = {'service': 'unknown', 'version': None}
    
    try:
        # Connect to the port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # Common protocol initiation strings
        probes = {
            21: b"",  # FTP - server sends banner on connect
            22: b"",  # SSH - server sends banner on connect
            23: b"",  # Telnet - server sends banner on connect
            25: b"EHLO security-scanner.local\r\n",  # SMTP
            80: b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n",  # HTTP
            110: b"",  # POP3 - server sends banner on connect
            143: b"a1 CAPABILITY\r\n",  # IMAP
            443: b"",  # HTTPS - requires SSL/TLS wrapper
            3306: b"\x0a",  # MySQL
            5432: b"",  # PostgreSQL
        }
        
        # Send probe if available for the port
        if port in probes:
            if probes[port]:  # Only send if not empty string
                sock.send(probes[port])
        
        # Receive banner
        try:
            banner = sock.recv(1024)
            if isinstance(banner, bytes):
                banner = banner.decode('utf-8', errors='ignore')
        except socket.timeout:
            banner = ""
        
        # Identify service and version from banner
        service_info = identify_service(port, banner)
        
        sock.close()
        
    except socket.error as e:
        banner = f"Error: {str(e)}"
    except Exception as e:
        banner = f"Error: {str(e)}"
    
    return {
        'port': port,
        'banner': banner,
        'service': service_info['service'],
        'version': service_info['version'],
        'protocol': 'tcp'
    }
def grab_banners(target, ports, threads=10, timeout=2.0):
    """
    Grab banners from multiple open ports using multithreading
    
    Args:
        target (str): Target IP or hostname
        ports (list): List of open ports
        threads (int): Number of threads to use
        timeout (float): Socket timeout in seconds
        
    Returns:
        dict: Dictionary of port information including banners
    """
    logger.info(f"Grabbing banners from {len(ports)} open ports using {threads} threads")
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(grab_banner, target, port, timeout): port for port in ports
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                banner_info = future.result()
                results[port] = banner_info
            except Exception as e:
                logger.error(f"Error grabbing banner from port {port}: {e}")
                results[port] = {
                    'port': port,
                    'banner': f"Error: {str(e)}",
                    'service': 'unknown',
                    'version': None,
                    'protocol': 'tcp'
                }
    
    return results

if __name__ == "__main__":
    # Simple test when module is run directly
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if len(sys.argv) > 2:
            ports = [int(p) for p in sys.argv[2].split(',')]
        else:
            ports = [21, 22, 25, 80, 443, 3306, 8080]
        
        results = grab_banners(target, ports)
        for port, info in results.items():
            print(f"Port {port} ({info['service']}): {info['banner']}")
    else:
        print("Usage: python banner_grabber.py <target> [ports]")