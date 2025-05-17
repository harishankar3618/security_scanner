# scanner.py (Fixed)
#!/usr/bin/env python3
"""
Advanced Security Scanner
A modular security scanning tool for network reconnaissance and vulnerability detection
"""

import sys
import os
import argparse
import ipaddress
from datetime import datetime
from core import port_scanner, banner_grabber, web_scanner, dir_bruteforce, cve_lookup, vuln_scanner
from utils import logger, report, config

def validate_target(target):
    """Validate if target is a valid IP address or hostname"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Not an IP address, could be a hostname
        if len(target.split('.')) > 1:  # Simple check for domain-like format
            return True
    return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Advanced Security Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Port range to scan (e.g., 1-1000)', default='1-1000')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads to use', default=10)
    parser.add_argument('-o', '--output', help='Output format (json, html)', default='json')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--skip-web', action='store_true', help='Skip web scanning')
    parser.add_argument('--skip-dirs', action='store_true', help='Skip directory bruteforcing')
    parser.add_argument('--wordlist', help='Custom wordlist for directory bruteforcing')
    parser.add_argument('--timeout', type=float, help='Connection timeout in seconds', default=1.0)
    
    return parser.parse_args()

def parse_port_range(port_range):
    """Parse port range string (e.g., '1-1000,3000,8000-8100')"""
    ports = []
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def main():
    """Main function"""
    args = parse_arguments()
    
    # Configure logger
    log = logger.Logger(verbose=args.verbose)
    log.info(f"Advanced Security Scanner started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Validate target
    if not validate_target(args.target):
        log.error(f"Invalid target: {args.target}")
        sys.exit(1)
    
    target = args.target
    log.info(f"Target: {target}")
    
    # Parse port range
    try:
        ports = parse_port_range(args.ports)
        log.info(f"Scanning {len(ports)} ports")
    except ValueError:
        log.error(f"Invalid port range: {args.ports}")
        sys.exit(1)
    
    # Create scanner configuration
    scan_config = {
        'threads': args.threads,
        'timeout': args.timeout,
        'wordlist': args.wordlist
    }
    
    # Run port scan
    log.info("Starting port scan...")
    open_ports = port_scanner.scan_ports(target, ports, threads=args.threads, timeout=args.timeout)
    log.info(f"Found {len(open_ports)} open ports")
    
    # Skip the rest if no open ports found
    if not open_ports:
        log.warning("No open ports found. Exiting.")
        sys.exit(0)
    
    # Grab service banners
    log.info("Grabbing service banners...")
    banners = banner_grabber.grab_banners(target, open_ports, timeout=args.timeout)
    
    # Initialize results dictionary
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'open_ports': open_ports,
        'service_banners': banners,
        'web_findings': [],
        'directories': [],
        'vulnerabilities': []
    }
    
    # Check for web servers
    # FIX: Get the banner string correctly from the dictionary structure
    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443] or 
                 'HTTP' in banners.get(p, {}).get('banner', '').upper()]
    
    # Web scanning
    if web_ports and not args.skip_web:
        log.info(f"Found {len(web_ports)} potential web servers. Starting web scan...")
        for port in web_ports:
            # FIX: Get the banner string correctly from the dictionary structure
            protocol = 'https' if port in [443, 8443] or 'SSL' in banners.get(port, {}).get('banner', '').upper() else 'http'
            web_url = f"{protocol}://{target}:{port}"
            log.info(f"Scanning web server at {web_url}")
            
            # Run web vulnerability scan
            web_findings = web_scanner.scan_web(web_url, timeout=args.timeout)
            results['web_findings'].extend(web_findings)
            
            # Run directory bruteforce if not skipped
            if not args.skip_dirs:
                log.info(f"Starting directory bruteforce on {web_url}")
                directories = dir_bruteforce.bruteforce(web_url, 
                                                      wordlist=args.wordlist,
                                                      threads=args.threads,
                                                      timeout=args.timeout)
                results['directories'].extend(directories)
    
    # Look up CVEs based on banners
    log.info("Looking up CVEs based on service banners...")
    cves = cve_lookup.lookup(banners)
    results['cve_matches'] = cves
    
    # Run vulnerability scanner for known services
    log.info("Checking for common vulnerabilities...")
    vulns = vuln_scanner.scan_vulnerabilities(target, open_ports, banners, timeout=args.timeout)
    results['vulnerabilities'] = vulns
    
    # Generate report
    log.info("Generating report...")
    report_file = report.generate_report(results, format=args.output)
    log.info(f"Report saved as {report_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan aborted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)