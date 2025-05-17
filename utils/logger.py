#utils/logger.py
#!/usr/bin/env python3
"""
Logger Module
Provides consistent logging functionality across the scanner
"""

import sys
import logging
from datetime import datetime
from threading import Lock

class Logger:
    # ANSI color codes
    COLORS = {
        'SUCCESS': '\033[92m',  # Green
        'INFO': '\033[94m',     # Blue
        'WARNING': '\033[93m',   # Yellow
        'ERROR': '\033[91m',    # Red
        'DEBUG': '\033[95m',    # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.lock = Lock()
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Create file handler
        self.log_file = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    def _log(self, level, message, color):
        """Internal logging method"""
        with self.lock:
            timestamp = datetime.now().strftime('%H:%M:%S')
            colored_message = f"{color}[{level}] {message}{self.COLORS['RESET']}"
            plain_message = f"[{level}] {message}"
            
            # Print to console with colors
            print(f"[{timestamp}] {colored_message}")
            
            # Log to file without colors
            if level == 'SUCCESS':
                logging.info(plain_message)
            else:
                getattr(logging, level.lower())(plain_message)

    def success(self, message):
        """Log success message"""
        self._log('SUCCESS', message, self.COLORS['SUCCESS'])

    def info(self, message):
        """Log info message"""
        self._log('INFO', message, self.COLORS['INFO'])

    def warning(self, message):
        """Log warning message"""
        self._log('WARNING', message, self.COLORS['WARNING'])

    def error(self, message):
        """Log error message"""
        self._log('ERROR', message, self.COLORS['ERROR'])

    def debug(self, message):
        """Log debug message"""
        if self.verbose:
            self._log('DEBUG', message, self.COLORS['DEBUG'])

if __name__ == "__main__":
    # Test logger
    logger = Logger(verbose=True)
    logger.success("This is a success message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.debug("This is a debug message")
