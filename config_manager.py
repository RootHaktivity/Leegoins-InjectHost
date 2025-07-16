#!/usr/bin/env python3
"""
Configuration Management for InjectHost.
Allows saving, loading, and switching between different host configurations.
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class HostConfiguration:
    """Represents a host configuration with metadata."""
    
    def __init__(self, name: str, description: str = "", entries: Optional[List[Dict]] = None):
        self.name = name
        self.description = description
        self.entries = entries if entries is not None else []
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def add_entry(self, ip: str, hostname: str, comment: str = ""):
        """Add a host entry to this configuration."""
        entry = {
            "ip": ip,
            "hostname": hostname,
            "comment": comment,
            "added_at": datetime.now().isoformat()
        }
        self.entries.append(entry)
        self.updated_at = datetime.now().isoformat()
    
    def remove_entry(self, ip: str, hostname: str):
        """Remove a host entry from this configuration."""
        self.entries = [e for e in self.entries 
                       if not (e["ip"] == ip and e["hostname"] == hostname)]
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "entries": self.entries,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HostConfiguration':
        """Create configuration from dictionary."""
        config = cls(data["name"], data.get("description", ""))
        config.entries = data.get("entries", [])
        config.created_at = data.get("created_at", datetime.now().isoformat())
        config.updated_at = data.get("updated_at", datetime.now().isoformat())
        return config
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about this configuration."""
        return {
            "total_entries": len(self.entries),
            "unique_ips": len(set(e["ip"] for e in self.entries)),
            "unique_hostnames": len(set(e["hostname"] for e in self.entries)),
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


class ConfigurationManager:
    """Manages host configurations."""
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            # Use system-wide config directory for consistency
            config_dir = "/usr/local/lib/injecthost/configs"
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.current_config: Optional[str] = None
    
    def save_configuration(self, config: HostConfiguration) -> bool:
        """Save a configuration to disk."""
        try:
            config_file = self.config_dir / f"{config.name}.json"
            
            # Create backup if file exists
            if config_file.exists():
                backup_file = self.config_dir / f"{config.name}.backup.json"
                shutil.copy2(config_file, backup_file)
            
            # Save configuration
            with open(config_file, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)
            
            logger.info(f"Configuration '{config.name}' saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration '{config.name}': {e}")
            return False
    
    def load_configuration(self, name: str) -> Optional[HostConfiguration]:
        """Load a configuration from disk."""
        try:
            config_file = self.config_dir / f"{name}.json"
            
            if not config_file.exists():
                logger.warning(f"Configuration '{name}' not found")
                return None
            
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            config = HostConfiguration.from_dict(data)
            logger.info(f"Configuration '{name}' loaded successfully")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load configuration '{name}': {e}")
            return None
    
    def list_configurations(self) -> List[Dict[str, Any]]:
        """List all available configurations with metadata."""
        configs = []
        
        try:
            for config_file in self.config_dir.glob("*.json"):
                if config_file.name.endswith(".backup.json"):
                    continue
                
                try:
                    with open(config_file, 'r') as f:
                        data = json.load(f)
                    
                    config = HostConfiguration.from_dict(data)
                    configs.append({
                        "name": config.name,
                        "description": config.description,
                        "stats": config.get_stats(),
                        "filename": config_file.name
                    })
                except Exception as e:
                    logger.warning(f"Failed to read configuration file {config_file}: {e}")
                    continue
            
            # Sort by name
            configs.sort(key=lambda x: x["name"].lower())
            
        except Exception as e:
            logger.error(f"Failed to list configurations: {e}")
        
        return configs
    
    def delete_configuration(self, name: str) -> bool:
        """Delete a configuration."""
        try:
            config_file = self.config_dir / f"{name}.json"
            
            if not config_file.exists():
                logger.warning(f"Configuration '{name}' not found")
                return False
            
            # Create backup before deletion
            backup_file = self.config_dir / f"{name}.deleted.{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            shutil.copy2(config_file, backup_file)
            
            # Delete the file
            config_file.unlink()
            
            logger.info(f"Configuration '{name}' deleted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete configuration '{name}': {e}")
            return False
    
    def rename_configuration(self, old_name: str, new_name: str, new_description: Optional[str] = None) -> bool:
        """Rename a configuration and optionally update its description."""
        try:
            old_config_file = self.config_dir / f"{old_name}.json"
            new_config_file = self.config_dir / f"{new_name}.json"
            
            if not old_config_file.exists():
                logger.warning(f"Configuration '{old_name}' not found")
                return False
            
            if new_config_file.exists():
                logger.warning(f"Configuration '{new_name}' already exists")
                return False
            
            # Load the configuration
            config = self.load_configuration(old_name)
            if not config:
                return False
            
            # Update the configuration name
            config.name = new_name
            config.updated_at = datetime.now().isoformat()
            
            # Update description if provided
            if new_description is not None:
                config.description = new_description
            
            # Save with new name
            if self.save_configuration(config):
                # Delete the old file
                old_config_file.unlink()
                logger.info(f"Configuration '{old_name}' renamed to '{new_name}' successfully")
                return True
            else:
                return False
            
        except Exception as e:
            logger.error(f"Failed to rename configuration '{old_name}' to '{new_name}': {e}")
            return False
    
    def export_configuration(self, name: str, export_path: str) -> bool:
        """Export a configuration to a file."""
        try:
            config = self.load_configuration(name)
            if not config:
                return False
            
            export_file = Path(export_path)
            export_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_file, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)
            
            logger.info(f"Configuration '{name}' exported to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export configuration '{name}': {e}")
            return False
    
    def import_configuration(self, import_path: str, overwrite: bool = False) -> Optional[str]:
        """Import a configuration from a file."""
        try:
            import_file = Path(import_path)
            
            if not import_file.exists():
                logger.error(f"Import file not found: {import_path}")
                return None
            
            with open(import_file, 'r') as f:
                data = json.load(f)
            
            config = HostConfiguration.from_dict(data)
            
            # Check if configuration already exists
            existing_file = self.config_dir / f"{config.name}.json"
            if existing_file.exists() and not overwrite:
                logger.warning(f"Configuration '{config.name}' already exists. Use overwrite=True to replace.")
                return None
            
            # Save the imported configuration
            if self.save_configuration(config):
                logger.info(f"Configuration '{config.name}' imported successfully")
                return config.name
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to import configuration from {import_path}: {e}")
            return None
    
    def create_from_current_hosts(self, name: str, description: str = "") -> Optional[HostConfiguration]:
        """Create a configuration from the current /etc/hosts file."""
        try:
            from injecthost_logic import get_host_entries
            
            entries = get_host_entries()
            config = HostConfiguration(name, description)
            
            # Filter out system entries to avoid duplication
            system_ips = {
                "127.0.0.1", "127.0.1.1", "::1", "ff02::1", "ff02::2"
            }
            system_hostnames = {
                "localhost", "kali", "ip6-localhost", "ip6-loopback", 
                "ip6-allnodes", "ip6-allrouters"
            }
            
            for entry in entries:
                # Skip system entries to prevent duplication
                if (entry.ip in system_ips or 
                    entry.hostname in system_hostnames or
                    entry.hostname.startswith("ip6-")):
                    continue
                config.add_entry(entry.ip, entry.hostname, entry.comment or "")
            
            if self.save_configuration(config):
                logger.info(f"Configuration '{name}' created from current hosts file")
                return config
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to create configuration from current hosts: {e}")
            return None
    
    def apply_configuration(self, name: str, backup_current: bool = True) -> bool:
        """Apply a configuration to the current /etc/hosts file."""
        try:
            config = self.load_configuration(name)
            if not config:
                return False
            
            # Backup current hosts file if requested
            if backup_current:
                from injecthost_logic import backup_hosts
                backup_hosts()
            
            # Clear current hosts file and add new entries
            from injecthost_logic import batch_add_entries
            
            # First, we need to clear the current hosts file
            # This is a bit tricky since we need to preserve system entries
            # For now, we'll use a simple approach
            
            # Create new hosts file content
            hosts_content = []
            hosts_content.append("# /etc/hosts file generated by InjectHost")
            hosts_content.append("# Configuration: " + name)
            hosts_content.append("# Generated: " + datetime.now().isoformat())
            hosts_content.append("")
            
            # Add system entries (localhost, etc.)
            system_entries = [
                "127.0.0.1\tlocalhost",
                "127.0.1.1\tkali",
                "::1\tlocalhost ip6-localhost ip6-loopback",
                "ff02::1\tip6-allnodes",
                "ff02::2\tip6-allrouters"
            ]
            
            for entry in system_entries:
                hosts_content.append(entry)
            
            hosts_content.append("")
            hosts_content.append("# Custom entries from configuration: " + name)
            
            # Add configuration entries
            for entry in config.entries:
                line = f"{entry['ip']}\t{entry['hostname']}"
                if entry.get('comment'):
                    line += f"\t# {entry['comment']}"
                hosts_content.append(line)
            
            # Write to hosts file
            with open("/etc/hosts", 'w') as f:
                f.write('\n'.join(hosts_content) + '\n')
            
            self.current_config = name
            logger.info(f"Configuration '{name}' applied successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply configuration '{name}': {e}")
            return False
    
    def get_current_configuration_name(self) -> Optional[str]:
        """Get the name of the currently applied configuration."""
        return self.current_config
    
    def create_template(self, name: str, description: str = "") -> HostConfiguration:
        """Create a template configuration with common entries."""
        config = HostConfiguration(name, description)
        
        # Add some common template entries (no system entries)
        template_entries = [
            ("192.168.1.10", "router.local", "Local router"),
            ("192.168.1.100", "server.local", "Local server"),
            ("192.168.1.101", "database.local", "Database server"),
            ("192.168.1.102", "web.local", "Web server"),
            ("192.168.1.103", "mail.local", "Mail server"),
        ]
        
        for ip, hostname, comment in template_entries:
            config.add_entry(ip, hostname, comment)
        
        return config

# Convenience functions
def get_config_manager() -> ConfigurationManager:
    """Get the global configuration manager instance."""
    return ConfigurationManager()

def save_config(name: str, description: str = "", entries: Optional[List[Dict]] = None) -> bool:
    """Save a configuration."""
    manager = get_config_manager()
    config = HostConfiguration(name, description, entries)
    return manager.save_configuration(config)

def load_config(name: str) -> Optional[HostConfiguration]:
    """Load a configuration."""
    manager = get_config_manager()
    return manager.load_configuration(name)

def list_configs() -> List[Dict[str, Any]]:
    """List all configurations."""
    manager = get_config_manager()
    return manager.list_configurations()

def apply_config(name: str) -> bool:
    """Apply a configuration."""
    manager = get_config_manager()
    return manager.apply_configuration(name) 