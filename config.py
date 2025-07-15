#!/usr/bin/env python3
"""
Configuration management for InjectHost application.
Provides centralized configuration with environment variable support.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class InjectHostConfig:
    """Configuration class for InjectHost application."""
    
    # Core file paths
    hosts_file: Path = Path("/etc/hosts")
    backup_dir: Path = Path("/etc/hosts.backup")
    
    # Application settings
    marker: str = "# THM"
    log_dir: Path = field(default_factory=lambda: Path.home() / ".injecthost")
    log_level: str = "INFO"
    
    # Backup management
    max_backups: int = 10
    create_timestamped_backups: bool = True
    
    # Validation settings
    allow_ipv6: bool = True
    allow_localhost_modification: bool = False
    validate_hostnames: bool = True
    
    # GUI settings
    theme: str = "dark"
    window_geometry: str = "600x720"
    auto_refresh: bool = True
    
    # Security settings
    require_confirmation: bool = True
    audit_log: bool = True
    
    @classmethod
    def from_env(cls) -> 'InjectHostConfig':
        """Load configuration from environment variables with defaults."""
        return cls(
            hosts_file=Path(os.getenv("INJECTHOST_HOSTS_FILE", "/etc/hosts")),
            backup_dir=Path(os.getenv("INJECTHOST_BACKUP_DIR", "/etc/hosts.backup")),
            marker=os.getenv("INJECTHOST_MARKER", "# THM"),
            log_dir=Path(os.getenv("INJECTHOST_LOG_DIR", Path.home() / ".injecthost")),
            log_level=os.getenv("INJECTHOST_LOG_LEVEL", "INFO"),
            max_backups=int(os.getenv("INJECTHOST_MAX_BACKUPS", "10")),
            create_timestamped_backups=os.getenv("INJECTHOST_TIMESTAMPED_BACKUPS", "true").lower() == "true",
            allow_ipv6=os.getenv("INJECTHOST_ALLOW_IPV6", "true").lower() == "true",
            allow_localhost_modification=os.getenv("INJECTHOST_ALLOW_LOCALHOST", "false").lower() == "true",
            validate_hostnames=os.getenv("INJECTHOST_VALIDATE_HOSTNAMES", "true").lower() == "true",
            theme=os.getenv("INJECTHOST_THEME", "dark"),
            window_geometry=os.getenv("INJECTHOST_WINDOW_GEOMETRY", "600x720"),
            auto_refresh=os.getenv("INJECTHOST_AUTO_REFRESH", "true").lower() == "true",
            require_confirmation=os.getenv("INJECTHOST_REQUIRE_CONFIRMATION", "true").lower() == "true",
            audit_log=os.getenv("INJECTHOST_AUDIT_LOG", "true").lower() == "true"
        )
    
    @classmethod
    def from_file(cls, config_file: Path) -> 'InjectHostConfig':
        """Load configuration from a file (simple key=value format)."""
        config = cls()
        
        if not config_file.exists():
            return config
            
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip().strip('"\'')
                        
                        # Map configuration keys to attributes
                        if key == 'hosts_file':
                            config.hosts_file = Path(value)
                        elif key == 'backup_dir':
                            config.backup_dir = Path(value)
                        elif key == 'marker':
                            config.marker = value
                        elif key == 'max_backups':
                            config.max_backups = int(value)
                        elif key == 'log_level':
                            config.log_level = value.upper()
                        # Add more mappings as needed
                            
        except Exception as e:
            logging.warning(f"Error reading config file {config_file}: {e}")
            
        return config
    
    def save_to_file(self, config_file: Path) -> None:
        """Save current configuration to a file."""
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            f.write("# InjectHost Configuration File\n")
            f.write("# Edit these values to customize behavior\n\n")
            
            f.write(f"hosts_file={self.hosts_file}\n")
            f.write(f"backup_dir={self.backup_dir}\n")
            f.write(f"marker={self.marker}\n")
            f.write(f"max_backups={self.max_backups}\n")
            f.write(f"log_level={self.log_level}\n")
            f.write(f"theme={self.theme}\n")
            f.write(f"window_geometry={self.window_geometry}\n")
    
    def setup_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def setup_logging(self) -> None:
        """Setup logging based on configuration."""
        log_file = self.log_dir / "injecthost.log"
        
        # Convert log level string to logging constant
        level = getattr(logging, self.log_level.upper(), logging.INFO)
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        if not self.hosts_file.parent.exists():
            issues.append(f"Hosts file directory does not exist: {self.hosts_file.parent}")
        
        if self.max_backups < 1:
            issues.append("max_backups must be at least 1")
        
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            issues.append(f"Invalid log level: {self.log_level}")
        
        return issues


def get_config() -> InjectHostConfig:
    """Get configuration instance with precedence: env vars > config file > defaults."""
    config_file = Path.home() / ".injecthost" / "config.ini"
    
    # Start with file config if it exists
    if config_file.exists():
        config = InjectHostConfig.from_file(config_file)
    else:
        config = InjectHostConfig()
    
    # Override with environment variables
    env_config = InjectHostConfig.from_env()
    
    # Merge configurations (env takes precedence)
    for field_name in config.__dataclass_fields__:
        env_value = getattr(env_config, field_name)
        default_value = getattr(InjectHostConfig(), field_name)
        
        # If env value differs from default, use it
        if env_value != default_value:
            setattr(config, field_name, env_value)
    
    # Validate and setup
    issues = config.validate()
    if issues:
        logging.warning(f"Configuration issues found: {issues}")
    
    config.setup_directories()
    
    return config