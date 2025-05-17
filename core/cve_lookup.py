#core/cve_lookup.py
#!/usr/bin/env python3
"""
CVE Lookup Module
Maps service banners to known CVEs using local database
"""

import json
import re
import os
from datetime import datetime
from utils.logger import Logger

logger = Logger()

class CVELookup:
    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.join('data', 'cve_database.json')
        self.cve_data = self.load_database()

    def load_database(self):
        """Load CVE database from JSON file"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"CVE database not found at {self.db_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading CVE database: {str(e)}")
            return {}

    def search_cves(self, service, version):
        """Search for CVEs matching service and version"""
        matches = []
        
        if not service or not version:
            return matches

        try:
            # Normalize service name
            service = service.lower()
            
            # Search in database
            for cve_id, cve_info in self.cve_data.items():
                if service in cve_info.get('affected_products', []):
                    version_pattern = cve_info.get('version_pattern', '')
                    if version_pattern and re.search(version_pattern, version):
                        matches.append({
                            'cve_id': cve_id,
                            'description': cve_info.get('description', ''),
                            'cvss_score': cve_info.get('cvss_score', 0.0),
                            'references': cve_info.get('references', []),
                            'published_date': cve_info.get('published_date', '')
                        })

        except Exception as e:
            logger.error(f"Error searching CVEs: {str(e)}")

        return matches

def lookup(banners):
    """
    Look up CVEs for service banners
    
    Args:
        banners (dict): Dictionary of port numbers to banner information
        
    Returns:
        dict: Dictionary of ports to CVE matches
    """
    cve_lookup = CVELookup()
    results = {}
    
    for port, banner_info in banners.items():
        service = banner_info.get('service')
        version = banner_info.get('version')
        
        if service and version:
            matches = cve_lookup.search_cves(service, version)
            if matches:
                results[port] = matches
    
    return results

if __name__ == "__main__":
    # Test CVE lookup
    test_banners = {
        80: {'service': 'apache', 'version': '2.4.29'},
        22: {'service': 'openssh', 'version': '7.6p1'}
    }
    
    results = lookup(test_banners)
    for port, cves in results.items():
        print(f"\nPort {port}:")
        for cve in cves:
            print(f"  {cve['cve_id']} (CVSS: {cve['cvss_score']})")
