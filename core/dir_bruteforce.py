#core/dir_bruteforce.py
#!/usr/bin/env python3
"""
Directory Bruteforce Module
Discovers hidden directories and files on web servers
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from utils.logger import Logger

logger = Logger()

class DirectoryBruteforcer:
    def __init__(self, url, wordlist=None, threads=10, timeout=10):
        self.url = url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.found_dirs = []
        self.lock = threading.Lock()
        
        # Load wordlist
        if wordlist:
            with open(wordlist, 'r') as f:
                self.wordlist = [line.strip() for line in f]
        else:
            # Default minimal wordlist
            self.wordlist = [
                'admin', 'wp-admin', 'administrator', 'login', 'wp-content',
                'upload', 'uploads', 'backup', 'backups', 'config', 'dashboard',
                'cms', 'test', 'dev', 'development', 'staging', 'prod',
                'api', 'v1', 'v2', 'docs', 'documentation', 'blog',
                'wp-includes', 'include', 'includes', 'tmp', 'temp',
                'images', 'img', 'css', 'js', 'javascript', 'static',
                'media', 'assets', 'downloads', 'download', 'file',
                'files', 'admin.php', 'index.php', 'info.php', 'phpinfo.php'
            ]

    def check_directory(self, path):
        """Check if a directory exists"""
        try:
            url = urljoin(self.url, path)
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            if resp.status_code in [200, 301, 302, 403]:
                result = {
                    'url': url,
                    'status_code': resp.status_code,
                    'size': len(resp.content),
                    'redirect': resp.headers.get('location', '') if resp.status_code in [301, 302] else None
                }
                
                with self.lock:
                    self.found_dirs.append(result)
                    logger.success(f"Found: {url} ({resp.status_code})")
                
                return result
            
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.error(f"Error checking {path}: {str(e)}")
        
        return None

    def bruteforce(self):
        """Start directory bruteforce"""
        logger.info(f"Starting directory bruteforce on {self.url} with {len(self.wordlist)} words")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_directory, self.wordlist)
        
        return self.found_dirs

def bruteforce(url, wordlist=None, threads=10, timeout=10):
    """Main function to initiate directory bruteforce"""
    bruteforcer = DirectoryBruteforcer(url, wordlist, threads, timeout)
    return bruteforcer.bruteforce()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        wordlist = sys.argv[2] if len(sys.argv) > 2 else None
        results = bruteforce(url, wordlist)
        for result in results:
            print(f"Found: {result['url']} ({result['status_code']})")
    else:
        print("Usage: python dir_bruteforce.py <url> [wordlist]")
