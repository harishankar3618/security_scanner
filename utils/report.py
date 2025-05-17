#utils/report.py
#!/usr/bin/env python3
"""
Report Generation Module
Generates scan reports in various formats
"""

import json
import os
from datetime import datetime
from utils.logger import Logger

logger = Logger()

class ReportGenerator:
    def __init__(self, results, format='json'):
        self.results = results
        self.format = format.lower()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def generate_json(self):
        """Generate JSON report"""
        filename = f"scan_report_{self.timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            return filename
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            return None

    def generate_html(self):
        """Generate HTML report"""
        filename = f"scan_report_{self.timestamp}.html"
        
        try:
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1, h2 { color: #333; }
                    .section { margin: 20px 0; }
                    .finding { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
                    .high { border-left: 5px solid #ff4444; }
                    .medium { border-left: 5px solid #ffbb33; }
                    .low { border-left: 5px solid #00C851; }
                    .details { margin-left: 20px; }
                </style>
            </head>
            <body>
            """
            
            # Add header
            html += f"""
                <h1>Security Scan Report</h1>
                <p>Target: {self.results['target']}</p>
                <p>Scan Date: {self.results['timestamp']}</p>
            """
            
            # Add open ports section
            html += """
                <div class='section'>
                    <h2>Open Ports</h2>
            """
            for port in self.results['open_ports']:
                banner = self.results['service_banners'].get(port, {})
                html += f"""
                    <div class='finding'>
                        <h3>Port {port}</h3>
                        <div class='details'>
                            <p>Service: {banner.get('service', 'unknown')}</p>
                            <p>Version: {banner.get('version', 'unknown')}</p>
                            <p>Banner: {banner.get('banner', 'N/A')}</p>
                        </div>
                    </div>
                """
            
            # Add vulnerabilities section
            if self.results.get('vulnerabilities'):
                html += """
                    <div class='section'>
                        <h2>Vulnerabilities</h2>
                """
                for vuln in self.results['vulnerabilities']:
                    severity_class = vuln['severity'].lower()
                    html += f"""
                        <div class='finding {severity_class}'>
                            <h3>{vuln['type']}</h3>
                            <div class='details'>
                                <p>Severity: {vuln['severity']}</p>
                                <p>Port: {vuln['port']}</p>
                                <p>Details: {vuln['details']}</p>
                            </div>
                        </div>
                    """
            
            # Close HTML
            html += """
                </div>
            </body>
            </html>
            """
            
            with open(filename, 'w') as f:
                f.write(html)
            return filename
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return None

    def generate(self):
        """Generate report in specified format"""
        if self.format == 'json':
            return self.generate_json()
        elif self.format == 'html':
            return self.generate_html()
        else:
            logger.error(f"Unsupported report format: {self.format}")
            return None

def generate_report(results, format='json'):
    """Main function to generate scan report"""
    generator = ReportGenerator(results, format)
    filename = generator.generate()
    
    if filename:
        logger.success(f"Report generated: {filename}")
        return filename
    else:
        logger.error("Failed to generate report")
        return None

if __name__ == "__main__":
    # Test report generation
    test_results = {
        'target': 'example.com',
        'timestamp': datetime.now().isoformat(),
        'open_ports': [80, 443, 22],
        'service_banners': {
            80: {'service': 'http', 'version': '2.4.29', 'banner': 'Apache/2.4.29'},
            443: {'service': 'https', 'version': '1.14.0', 'banner': 'nginx/1.14.0'},
            22: {'service': 'ssh', 'version': '7.6p1', 'banner': 'OpenSSH_7.6p1'}
        },
        'vulnerabilities': [
            {
                'port': 80,
                'type': 'Vulnerable Apache Version',
                'severity': 'High',
                'details': 'Apache 2.4.29 has known vulnerabilities'
            }
        ]
    }
    
    generate_report(test_results, 'html')
    generate_report(test_results, 'json')
