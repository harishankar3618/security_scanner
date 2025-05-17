#utils/config.py
#!/usr/bin/env python3
"""
Configuration Module
Handles scanner configuration and settings
"""

import os
import json
import yaml
from utils.logger import Logger

logger = Logger()

class Config:
    DEFAULT_CONFIG = {
        'scan': {
            'threads': 10,
            'timeout': 2.0,
            'ports': '1-1000',
            'default_wordlist': 'data/directories.txt'
        },
        'web': {
            'user_agent': 'Security Scanner/1.0',
            'follow_redirects': True,
            'max_depth': 3,
            'exclude_extensions': ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']
        },
        'reporting': {
            'output_dir': 'reports',
            'default_format': 'json'
        },
        'database': {
            'cve_path': 'data/cve_database.json',
            'update_interval': 7  # days
        }
    }

    def __init__(self, config_file=None):
        self.config_file = config_file or 'config.yaml'
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from file or use defaults"""
        config = self.DEFAULT_CONFIG.copy()
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    if self.config_file.endswith('.yaml'):
                        file_config = yaml.safe_load(f)
                    else:
                        file_config = json.load(f)
                
                # Update default config with file values
                self._update_recursive(config, file_config)
                logger.info(f"Loaded configuration from {self.config_file}")
            else:
                logger.info("Using default configuration")
                self.save_config(config)  # Save defaults for future use
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
        
        return config

    def _update_recursive(self, base, update):
        """Recursively update dictionary"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._update_recursive(base[key], value)
            else:
                base[key] = value

    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
            
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                if self.config_file.endswith('.yaml'):
                    yaml.dump(config, f, default_flow_style=False)
                else:
                    json.dump(config, f, indent=4)
                    
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")

    def get(self, section, key=None):
        """Get configuration value"""
        try:
            if key is None:
                return self.config[section]
            return self.config[section][key]
        except KeyError:
            logger.error(f"Configuration key not found: {section}.{key}")
            return None

    def set(self, section, key, value):
        """Set configuration value"""
        try:
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
            self.save_config()
            return True
        except Exception as e:
            logger.error(f"Error setting configuration: {str(e)}")
            return False

if __name__ == "__main__":
    # Test configuration
    config = Config()
    print("Scan threads:", config.get('scan', 'threads'))
    print("Web user agent:", config.get('web', 'user_agent'))
    
    # Test setting value
    config.set('scan', 'threads', 20)
    print("Updated scan threads:", config.get('scan', 'threads'))
