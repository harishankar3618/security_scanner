#!/usr/bin/env python3
"""
Port Scanner Module
Scans for open ports on a target using multithreading for faster results
"""

import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from utils.logger import Logger

# Initialize logger
logger = Logger()

def check_port(target, port, timeout=1.0):
    """
    Check if a specific port is open on the target
    
    Args:
        target (str): Target IP or hostname
        port (int): Port number to check
        timeout (float): Socket timeout in seconds
        
    Returns:
        int or None: Port number if open, None if closed
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port
        return None
    except socket.gaierror:
        logger.error(f"Hostname resolution failed for {target}")
        return None
    except socket.error:
        return None
    except Exception as e:
        logger.error(f"Error checking port {port}: {str(e)}")
        return None

def scan_ports(target, ports=None, threads=10, timeout=1.0):
    """
    Scan multiple ports on the target
    
    Args:
        target (str): Target IP or hostname
        ports (list): List of ports to scan
        threads (int): Number of threads to use
        timeout (float): Socket timeout in seconds
        
    Returns:
        list: List of open ports
    """
    if ports is None:
        # Default ports to scan
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    logger.info(f"Scanning {len(ports)} ports on {target} with {threads} threads")
    open_ports = []
    
    # Use ThreadPoolExecutor for cleaner thread management
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all tasks
        future_to_port = {
            executor.submit(check_port, target, port, timeout): port for port in ports
        }
        
        # Process results as they complete
        for future in future_to_port:
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.success(f"Port {result} is open")
            except Exception as e:
                port = future_to_port[future]
                logger.error(f"Error scanning port {port}: {str(e)}")
    
    return sorted(open_ports)

def scan_port_range(target, start_port, end_port, threads=10, timeout=1.0):
    """
    Scan a range of ports on the target
    
    Args:
        target (str): Target IP or hostname
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): Number of threads to use
        timeout (float): Socket timeout in seconds
        
    Returns:
        list: List of open ports
    """
    ports = range(start_port, end_port + 1)
    return scan_ports(target, ports, threads, timeout)

# Alternative implementation using queue for very large port ranges
def scan_ports_queue(target, ports=None, threads=10, timeout=1.0):
    """
    Scan ports using a queue-based approach (better for very large port ranges)
    
    Args:
        target (str): Target IP or hostname
        ports (list): List of ports to scan
        threads (int): Number of threads to use
        timeout (float): Socket timeout in seconds
        
    Returns:
        list: List of open ports
    """
    if ports is None:
        ports = range(1, 1001)  # Default scan first 1000 ports
    
    # Create a queue of ports to scan
    port_queue = queue.Queue()
    for port in ports:
        port_queue.put(port)
    
    # Shared list for open ports (with lock for thread safety)
    open_ports = []
    lock = threading.Lock()
    
    def worker():
        while not port_queue.empty():
            try:
                port = port_queue.get(block=False)
                result = check_port(target, port, timeout)
                if result:
                    with lock:
                        open_ports.append(result)
                        logger.success(f"Port {result} is open")
                port_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Worker error: {str(e)}")
                port_queue.task_done()
    
    # Create and start worker threads
    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    # Wait for all threads to complete
    for t in thread_list:
        t.join()
    
    return sorted(open_ports)

if __name__ == "__main__":
    # Simple test when module is run directly
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        results = scan_ports(target)
        print(f"Open ports on {target}: {results}")
    else:
        print("Usage: python port_scanner.py <target>")