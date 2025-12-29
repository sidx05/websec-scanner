"""
Configuration management tool - View and modify scanner settings dynamically.
"""

import yaml
from pathlib import Path
import json


class ConfigManager:
    """Manage scanner configuration dynamically."""
    
    def __init__(self, config_path: str = None):
        """Initialize with config file path."""
        if config_path is None:
            config_path = Path(__file__).parent / 'config.yaml'
        self.config_path = Path(config_path)
        self.config = self.load()
    
    def load(self) -> dict:
        """Load configuration from file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def save(self):
        """Save configuration to file."""
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
        print(f"✅ Configuration saved to: {self.config_path}")
    
    def get(self, key: str, default=None):
        """Get configuration value by key (supports nested keys with dots)."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value):
        """Set configuration value by key (supports nested keys with dots)."""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
        print(f"✅ Set {key} = {value}")
    
    def display(self, section: str = None):
        """Display configuration (optionally filtered by section)."""
        if section:
            data = self.get(section, {})
            title = f"Configuration - {section}"
        else:
            data = self.config
            title = "Full Configuration"
        
        print("\n" + "=" * 80)
        print(title)
        print("=" * 80 + "\n")
        print(yaml.dump(data, default_flow_style=False, sort_keys=False))
    
    def list_sections(self):
        """List all top-level configuration sections."""
        print("\n" + "=" * 80)
        print("Available Configuration Sections")
        print("=" * 80 + "\n")
        
        for key in self.config.keys():
            value = self.config[key]
            if isinstance(value, dict):
                count = len(value)
                print(f"  📁 {key:<30} ({count} items)")
            else:
                print(f"  📄 {key:<30} = {value}")
    
    def reset_to_defaults(self):
        """Reset configuration to default values."""
        defaults = {
            'http_timeout': 10,
            'verify_ssl': False,
            'user_agent': 'WebsiteScanner/1.0',
            'auto_save_reports': True,
            'api_port': 8001,
            'batch_delay': 2.0,
        }
        
        for key, value in defaults.items():
            self.config[key] = value
        
        print("✅ Reset to default configuration")
    
    def validate(self) -> bool:
        """Validate configuration values."""
        errors = []
        
        # Validate numeric values
        if self.get('http_timeout', 0) <= 0:
            errors.append("http_timeout must be positive")
        
        if self.get('api_port', 0) < 1 or self.get('api_port', 0) > 65535:
            errors.append("api_port must be between 1-65535")
        
        # Validate weights sum to 100
        weights = self.get('advanced_weights', {})
        if weights:
            total = sum(weights.values())
            if abs(total - 100) > 0.01:
                errors.append(f"advanced_weights must sum to 100 (current: {total})")
        
        if errors:
            print("\n❌ Configuration Validation Errors:")
            for error in errors:
                print(f"  - {error}")
            return False
        else:
            print("\n✅ Configuration is valid")
            return True
    
    def export_json(self, filepath: str):
        """Export configuration as JSON."""
        with open(filepath, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"✅ Configuration exported to: {filepath}")
    
    def import_json(self, filepath: str):
        """Import configuration from JSON."""
        with open(filepath, 'r') as f:
            self.config = json.load(f)
        print(f"✅ Configuration imported from: {filepath}")


def interactive_config():
    """Interactive configuration management."""
    manager = ConfigManager()
    
    while True:
        print("\n" + "=" * 80)
        print("Configuration Manager - Interactive Mode")
        print("=" * 80)
        print("\n1. View all settings")
        print("2. View specific section")
        print("3. Modify a setting")
        print("4. List sections")
        print("5. Validate configuration")
        print("6. Save changes")
        print("7. Reset to defaults")
        print("8. Export as JSON")
        print("9. Exit")
        
        choice = input("\nSelect option (1-9): ").strip()
        
        if choice == '1':
            manager.display()
        
        elif choice == '2':
            manager.list_sections()
            section = input("\nEnter section name: ").strip()
            manager.display(section)
        
        elif choice == '3':
            print("\nEnter setting key (use dots for nested, e.g., 'risk_weights.https_missing'):")
            key = input("Key: ").strip()
            current = manager.get(key)
            print(f"Current value: {current}")
            
            print("\nEnter new value:")
            value_str = input("Value: ").strip()
            
            # Try to parse as number, bool, or list
            try:
                if value_str.lower() in ('true', 'false'):
                    value = value_str.lower() == 'true'
                elif value_str.startswith('[') and value_str.endswith(']'):
                    value = eval(value_str)
                elif '.' in value_str:
                    value = float(value_str)
                else:
                    value = int(value_str)
            except:
                value = value_str  # Keep as string
            
            manager.set(key, value)
        
        elif choice == '4':
            manager.list_sections()
        
        elif choice == '5':
            manager.validate()
        
        elif choice == '6':
            if manager.validate():
                manager.save()
        
        elif choice == '7':
            confirm = input("Reset to defaults? This will overwrite current settings (y/n): ")
            if confirm.lower() == 'y':
                manager.reset_to_defaults()
        
        elif choice == '8':
            filepath = input("Enter export path (e.g., config_backup.json): ").strip()
            manager.export_json(filepath)
        
        elif choice == '9':
            print("\n👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        # Command-line mode
        manager = ConfigManager()
        command = sys.argv[1]
        
        if command == 'show':
            section = sys.argv[2] if len(sys.argv) > 2 else None
            manager.display(section)
        
        elif command == 'get':
            if len(sys.argv) < 3:
                print("Usage: python config_manager.py get <key>")
            else:
                key = sys.argv[2]
                value = manager.get(key)
                print(f"{key} = {value}")
        
        elif command == 'set':
            if len(sys.argv) < 4:
                print("Usage: python config_manager.py set <key> <value>")
            else:
                key = sys.argv[2]
                value = sys.argv[3]
                manager.set(key, value)
                manager.save()
        
        elif command == 'validate':
            manager.validate()
        
        elif command == 'list':
            manager.list_sections()
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: show, get, set, validate, list")
    
    else:
        # Interactive mode
        interactive_config()
