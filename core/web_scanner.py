#core/web_scanner.py
#!/usr/bin/env python3
"""
Web Application Scanner Module
Checks for common web vulnerabilities including OWASP Top 10
"""

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from utils.logger import Logger

logger = Logger()

class WebScanner:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.findings = []

    def scan_xss(self, url, params):
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
        ]
        
        for param in params:
            for payload in payloads:
                try:
                    data = {param: payload}
                    resp = self.session.post(url, data=data, timeout=self.timeout)
                    if payload in resp.text:
                        self.findings.append({
                            'type': 'XSS',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    logger.error(f"XSS scan error: {str(e)}")

    def scan_sqli(self, url, params):
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1; SELECT * FROM users--",
        ]
        
        error_patterns = [
            'SQL syntax.*MySQL',
            'Warning.*mysql_.*',
            'PostgreSQL.*ERROR',
            'ORA-[0-9][0-9][0-9][0-9]',
        ]
        
        for param in params:
            for payload in payloads:
                try:
                    data = {param: payload}
                    resp = self.session.post(url, data=data, timeout=self.timeout)
                    
                    for pattern in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.findings.append({
                                'type': 'SQL Injection',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'severity': 'Critical'
                            })
                            break
                except Exception as e:
                    logger.error(f"SQLi scan error: {str(e)}")

    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            headers = resp.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    self.findings.append({
                        'type': 'Missing Security Header',
                        'url': url,
                        'detail': message,
                        'severity': 'Medium'
                    })
        except Exception as e:
            logger.error(f"Security header check error: {str(e)}")

    def scan(self):
        """Run all web security scans"""
        try:
            # Initial request to get forms and links
            resp = self.session.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Check security headers
            self.check_security_headers(self.url)
            
            # Scan forms
            forms = soup.find_all('form')
            for form in forms:
                action = urljoin(self.url, form.get('action', ''))
                params = [input.get('name') for input in form.find_all('input') if input.get('name')]
                
                self.scan_xss(action, params)
                self.scan_sqli(action, params)
            
            return self.findings
            
        except Exception as e:
            logger.error(f"Web scan error: {str(e)}")
            return []

def scan_web(url, timeout=10):
    """Main function to initiate web scanning"""
    scanner = WebScanner(url, timeout)
    return scanner.scan()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        findings = scan_web(url)
        for finding in findings:
            print(f"[{finding['severity']}] {finding['type']}: {finding['url']}")
    else:
        print("Usage: python web_scanner.py <url>")
