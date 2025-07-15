#!/usr/bin/env python3
"""
Data models for InjectHost application.
Provides structured data handling with validation.
"""

import re
import ipaddress
import logging
from dataclasses import dataclass
from typing import List, Optional, NamedTuple, Union
from datetime import datetime
from enum import Enum


class EntryType(Enum):
    """Types of entries in hosts file."""
    HOST = "host"
    COMMENT = "comment"
    BLANK = "blank"
    MARKER = "marker"


class ValidationResult(NamedTuple):
    """Result of validation operation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str] = []


@dataclass
class HostEntry:
    """Represents a single host entry with validation."""
    
    ip: str
    hostname: str
    comment: Optional[str] = None
    line_number: Optional[int] = None
    original_line: Optional[str] = None
    
    def __post_init__(self):
        """Validate entry after initialization."""
        if self.original_line is None:
            self.original_line = self.to_line()
    
    @classmethod
    def from_line(cls, line: str, line_number: Optional[int] = None) -> Optional['HostEntry']:
        """Parse a host entry from a hosts file line."""
        line = line.strip()
        
        if not line or line.startswith('#'):
            return None
            
        # Split on whitespace, handling multiple spaces/tabs
        parts = line.split()
        if len(parts) < 2:
            return None
            
        ip = parts[0]
        hostname = parts[1]
        
        # Everything after hostname is considered comment
        comment = ' '.join(parts[2:]) if len(parts) > 2 else None
        
        return cls(
            ip=ip,
            hostname=hostname,
            comment=comment,
            line_number=line_number,
            original_line=line
        )
    
    def to_line(self) -> str:
        """Convert entry back to hosts file line format."""
        line = f"{self.ip}\t{self.hostname}"
        if self.comment:
            line += f"\t# {self.comment}"
        return line
    
    def validate(self) -> ValidationResult:
        """Validate the host entry."""
        errors = []
        warnings = []
        
        # Validate IP address
        ip_result = self.validate_ip(self.ip)
        if not ip_result.is_valid:
            errors.extend(ip_result.errors)
        warnings.extend(ip_result.warnings)
        
        # Validate hostname
        hostname_result = self.validate_hostname(self.hostname)
        if not hostname_result.is_valid:
            errors.extend(hostname_result.errors)
        warnings.extend(hostname_result.warnings)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    @staticmethod
    def validate_ip(ip: str) -> ValidationResult:
        """Enhanced IP validation supporting IPv4 and IPv6."""
        errors = []
        warnings = []
        
        if not ip:
            errors.append("IP address cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for special IP ranges
            if ip_obj.is_loopback and ip != "127.0.0.1":
                warnings.append(f"Loopback IP {ip} detected")
            elif ip_obj.is_multicast:
                warnings.append(f"Multicast IP {ip} detected")
            elif ip_obj.is_private:
                logging.debug(f"Private IP {ip} detected")
            elif ip_obj.is_link_local:
                warnings.append(f"Link-local IP {ip} detected")
                
            return ValidationResult(True, errors, warnings)
            
        except ValueError as e:
            errors.append(f"Invalid IP address '{ip}': {e}")
            return ValidationResult(False, errors, warnings)
    
    @staticmethod
    def validate_hostname(hostname: str) -> ValidationResult:
        """RFC-compliant hostname validation."""
        errors = []
        warnings = []
        
        if not hostname:
            errors.append("Hostname cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Check length
        if len(hostname) > 253:
            errors.append(f"Hostname too long: {len(hostname)} > 253 characters")
        
        # Remove trailing dot if present
        if hostname.endswith('.'):
            hostname = hostname[:-1]
            warnings.append("Trailing dot removed from hostname")
        
        # Check each label (part separated by dots)
        labels = hostname.split('.')
        
        # Hostname pattern: letters, digits, hyphens (but not starting/ending with hyphen)
        label_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
        
        for i, label in enumerate(labels):
            if not label:
                errors.append(f"Empty label in hostname at position {i}")
                continue
                
            if len(label) > 63:
                errors.append(f"Label '{label}' too long: {len(label)} > 63 characters")
                
            if not label_pattern.match(label):
                if label.startswith('-'):
                    errors.append(f"Label '{label}' cannot start with hyphen")
                elif label.endswith('-'):
                    errors.append(f"Label '{label}' cannot end with hyphen")
                elif '_' in label:
                    errors.append(f"Label '{label}' contains underscore (not RFC compliant)")
                else:
                    errors.append(f"Label '{label}' contains invalid characters")
        
        # Check for localhost
        if hostname.lower() in ['localhost', 'localhost.localdomain']:
            warnings.append("Modifying localhost entry detected")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def is_duplicate_of(self, other: 'HostEntry') -> bool:
        """Check if this entry is a duplicate of another."""
        return (self.ip == other.ip and self.hostname == other.hostname) or \
               (self.hostname == other.hostname and self.ip != other.ip)
    
    def conflicts_with(self, other: 'HostEntry') -> bool:
        """Check if this entry conflicts with another (same hostname, different IP)."""
        return self.hostname == other.hostname and self.ip != other.ip
    
    def __str__(self) -> str:
        return f"{self.ip} -> {self.hostname}"
    
    def __repr__(self) -> str:
        return f"HostEntry(ip='{self.ip}', hostname='{self.hostname}', comment='{self.comment}')"


@dataclass
class HostsFileEntry:
    """Represents any line in the hosts file."""
    
    content: str
    line_number: int
    entry_type: EntryType
    host_entry: Optional[HostEntry] = None
    
    @classmethod
    def from_line(cls, line: str, line_number: int) -> 'HostsFileEntry':
        """Create entry from hosts file line."""
        original_line = line
        line = line.strip()
        
        if not line:
            return cls(original_line, line_number, EntryType.BLANK)
        elif line.startswith('#'):
            return cls(original_line, line_number, EntryType.COMMENT)
        else:
            host_entry = HostEntry.from_line(line, line_number)
            if host_entry:
                return cls(original_line, line_number, EntryType.HOST, host_entry)
            else:
                return cls(original_line, line_number, EntryType.COMMENT)


@dataclass
class BackupInfo:
    """Information about a backup file."""
    
    path: str
    timestamp: datetime
    size: int
    original_file: str
    
    @classmethod
    def from_file(cls, backup_path: str, original_file: str) -> 'BackupInfo':
        """Create backup info from file path."""
        from pathlib import Path
        import os
        
        path_obj = Path(backup_path)
        stat = path_obj.stat()
        
        return cls(
            path=backup_path,
            timestamp=datetime.fromtimestamp(stat.st_mtime),
            size=stat.st_size,
            original_file=original_file
        )


@dataclass
class OperationResult:
    """Result of a hosts file operation."""
    
    success: bool
    message: str
    backup_created: Optional[str] = None
    entries_modified: List[HostEntry] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.entries_modified is None:
            self.entries_modified = []
        if self.warnings is None:
            self.warnings = []


class HostsFileStats:
    """Statistics about hosts file content."""
    
    def __init__(self, entries: List[HostsFileEntry]):
        self.entries = entries
        self._calculate_stats()
    
    def _calculate_stats(self):
        """Calculate statistics from entries."""
        self.total_lines = len(self.entries)
        self.host_entries = [e for e in self.entries if e.entry_type == EntryType.HOST]
        self.comment_lines = [e for e in self.entries if e.entry_type == EntryType.COMMENT]
        self.blank_lines = [e for e in self.entries if e.entry_type == EntryType.BLANK]
        
        self.total_hosts = len(self.host_entries)
        self.ipv4_hosts = []
        self.ipv6_hosts = []
        self.invalid_hosts = []
        
        for entry in self.host_entries:
            if entry.host_entry:
                validation = entry.host_entry.validate()
                if validation.is_valid:
                    try:
                        ip = ipaddress.ip_address(entry.host_entry.ip)
                        if isinstance(ip, ipaddress.IPv4Address):
                            self.ipv4_hosts.append(entry.host_entry)
                        else:
                            self.ipv6_hosts.append(entry.host_entry)
                    except:
                        self.invalid_hosts.append(entry.host_entry)
                else:
                    self.invalid_hosts.append(entry.host_entry)
    
    def get_duplicates(self) -> List[List[HostEntry]]:
        """Find duplicate entries."""
        duplicates = []
        seen = {}
        
        for entry in self.host_entries:
            if entry.host_entry:
                key = (entry.host_entry.ip, entry.host_entry.hostname)
                if key in seen:
                    # Found duplicate
                    if seen[key] not in [group[0] for group in duplicates]:
                        duplicates.append([seen[key], entry.host_entry])
                    else:
                        # Add to existing group
                        for group in duplicates:
                            if group[0] == seen[key]:
                                group.append(entry.host_entry)
                                break
                else:
                    seen[key] = entry.host_entry
        
        return duplicates
    
    def get_conflicts(self) -> List[List[HostEntry]]:
        """Find conflicting entries (same hostname, different IP)."""
        conflicts = []
        hostname_to_entries = {}
        
        for entry in self.host_entries:
            if entry.host_entry:
                hostname = entry.host_entry.hostname
                if hostname not in hostname_to_entries:
                    hostname_to_entries[hostname] = []
                hostname_to_entries[hostname].append(entry.host_entry)
        
        for hostname, entries in hostname_to_entries.items():
            if len(entries) > 1:
                # Check if they have different IPs
                ips = {entry.ip for entry in entries}
                if len(ips) > 1:
                    conflicts.append(entries)
        
        return conflicts
    
    def __str__(self) -> str:
        return (f"HostsFileStats(total_lines={self.total_lines}, "
                f"hosts={self.total_hosts}, "
                f"ipv4={len(self.ipv4_hosts)}, "
                f"ipv6={len(self.ipv6_hosts)}, "
                f"invalid={len(self.invalid_hosts)})")