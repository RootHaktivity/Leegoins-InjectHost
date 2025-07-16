#!/usr/bin/env python3
"""
Advanced Validation & Linting Module for Leegoins-InjectHost
Provides comprehensive validation, linting, and error detection for hosts files.
"""

import re
import ipaddress
import socket
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation levels for different types of checks."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in the hosts file."""
    line_number: int
    line_content: str
    issue_type: ValidationLevel
    message: str
    suggestion: Optional[str] = None
    column: Optional[int] = None


class HostsValidator:
    """Advanced validator for hosts file content."""
    
    def __init__(self):
        self.issues: List[ValidationIssue] = []
        self.duplicate_ips: Dict[str, List[int]] = {}
        self.duplicate_hostnames: Dict[str, List[int]] = {}
        self.used_ips: Set[str] = set()
        self.used_hostnames: Set[str] = set()
        
    def validate_hosts_content(self, content: str) -> List[ValidationIssue]:
        """Validate the entire hosts file content."""
        self.issues.clear()
        self.duplicate_ips.clear()
        self.duplicate_hostnames.clear()
        self.used_ips.clear()
        self.used_hostnames.clear()
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._validate_line(line, line_num)
        
        # Check for duplicates across the entire file
        self._check_duplicates()
        
        # Check for common issues
        self._check_common_issues(content)
        
        return sorted(self.issues, key=lambda x: (x.line_number, x.issue_type.value))
    
    def _validate_line(self, line: str, line_num: int):
        """Validate a single line of the hosts file."""
        original_line = line
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return
        
        # Check for basic syntax
        if not self._is_valid_hosts_syntax(line):
            self.issues.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.ERROR,
                message="Invalid hosts file syntax",
                suggestion="Format should be: IP_ADDRESS HOSTNAME [HOSTNAME2 ...]"
            ))
            return
        
        # Parse the line
        parts = line.split()
        if len(parts) < 2:
            self.issues.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.ERROR,
                message="Line must contain at least one IP address and one hostname",
                suggestion="Add a hostname after the IP address"
            ))
            return
        
        ip_part = parts[0]
        hostnames = parts[1:]
        
        # Validate IP address
        ip_validation = self._validate_ip_address(ip_part)
        if ip_validation:
            self.issues.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.ERROR,
                message=f"Invalid IP address: {ip_validation}",
                column=1
            ))
            return
        
        # Validate hostnames
        for i, hostname in enumerate(hostnames):
            hostname_validation = self._validate_hostname(hostname)
            if hostname_validation:
                self.issues.append(ValidationIssue(
                    line_number=line_num,
                    line_content=original_line,
                    issue_type=ValidationLevel.ERROR,
                    message=f"Invalid hostname '{hostname}': {hostname_validation}",
                    column=len(ip_part) + 2 + sum(len(h) + 1 for h in hostnames[:i])
                ))
        
        # Track for duplicate detection
        if ip_part not in self.duplicate_ips:
            self.duplicate_ips[ip_part] = []
        self.duplicate_ips[ip_part].append(line_num)
        
        for hostname in hostnames:
            if hostname not in self.duplicate_hostnames:
                self.duplicate_hostnames[hostname] = []
            self.duplicate_hostnames[hostname].append(line_num)
    
    def _is_valid_hosts_syntax(self, line: str) -> bool:
        """Check if line follows basic hosts file syntax."""
        # Pattern for IPv4 or IPv6 followed by one or more hostnames
        # IPv4 pattern: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
        # IPv6 pattern: [0-9a-fA-F:]+ (simplified)
        ipv4_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ipv6_pattern = r'[0-9a-fA-F:]+'
        combined_ip_pattern = f'({ipv4_pattern}|{ipv6_pattern})'
        pattern = rf'^\s*({combined_ip_pattern})\s+([a-zA-Z0-9.-]+(?:\s+[a-zA-Z0-9.-]+)*)\s*$'
        return bool(re.match(pattern, line))
    
    def _validate_ip_address(self, ip: str) -> Optional[str]:
        """Validate IP address format and range (IPv4 and IPv6)."""
        try:
            # Try IPv4 first
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                
                # Check for reserved/private IPs
                if ip_obj.is_private:
                    return None  # Private IPs are valid
                
                if ip_obj.is_loopback:
                    return None  # Loopback is valid
                
                if ip_obj.is_multicast:
                    return None  # Multicast is valid
                
                if ip_obj.is_reserved:
                    return "Reserved IP address"
                
                if ip_obj.is_unspecified:
                    return "Unspecified IP address (0.0.0.0)"
                
                return None
                
            except ipaddress.AddressValueError:
                # Try IPv6
                try:
                    ip_obj = ipaddress.IPv6Address(ip)
                    
                    # IPv6 addresses are generally valid
                    if ip_obj.is_loopback:
                        return None  # Loopback is valid
                    
                    if ip_obj.is_multicast:
                        return None  # Multicast is valid
                    
                    if ip_obj.is_link_local:
                        return None  # Link-local is valid
                    
                    if ip_obj.is_site_local:
                        return None  # Site-local is valid
                    
                    if ip_obj.is_unspecified:
                        return "Unspecified IPv6 address (::)"
                    
                    return None
                    
                except ipaddress.AddressValueError:
                    return "Invalid IP address format"
                    
        except Exception:
            return "Invalid IP address format"
    
    def _validate_hostname(self, hostname: str) -> Optional[str]:
        """Validate hostname format."""
        if not hostname:
            return "Empty hostname"
        
        if len(hostname) > 253:
            return "Hostname too long (max 253 characters)"
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', hostname):
            return "Invalid hostname characters (use letters, numbers, hyphens only)"
        
        # Check for consecutive hyphens
        if '--' in hostname:
            return "Consecutive hyphens not allowed"
        
        # Check for leading/trailing hyphens
        if hostname.startswith('-') or hostname.endswith('-'):
            return "Hostname cannot start or end with hyphen"
        
        # Check for valid TLD-like patterns
        if '.' in hostname:
            parts = hostname.split('.')
            for part in parts:
                if len(part) > 63:
                    return "Domain part too long (max 63 characters)"
                if not part or part.startswith('-') or part.endswith('-'):
                    return "Invalid domain part"
        
        return None
    
    def _check_duplicates(self):
        """Check for duplicate IPs and hostnames."""
        # Check duplicate IPs
        for ip, line_numbers in self.duplicate_ips.items():
            if len(line_numbers) > 1:
                self.issues.append(ValidationIssue(
                    line_number=line_numbers[0],
                    line_content=f"IP {ip}",
                    issue_type=ValidationLevel.WARNING,
                    message=f"Duplicate IP address '{ip}' found on lines {', '.join(map(str, line_numbers))}",
                    suggestion="Consider consolidating hostnames under a single entry"
                ))
        
        # Check duplicate hostnames
        for hostname, line_numbers in self.duplicate_hostnames.items():
            if len(line_numbers) > 1:
                self.issues.append(ValidationIssue(
                    line_number=line_numbers[0],
                    line_content=f"Hostname {hostname}",
                    issue_type=ValidationLevel.ERROR,
                    message=f"Duplicate hostname '{hostname}' found on lines {', '.join(map(str, line_numbers))}",
                    suggestion="Remove duplicate entries - only the first occurrence will be used"
                ))
    
    def _check_common_issues(self, content: str):
        """Check for common hosts file issues."""
        lines = content.split('\n')
        
        # Check for missing newline at end
        if content and not content.endswith('\n'):
            self.issues.append(ValidationIssue(
                line_number=len(lines),
                line_content="",
                issue_type=ValidationLevel.INFO,
                message="File should end with a newline",
                suggestion="Add a newline at the end of the file"
            ))
        
        # Check for mixed line endings
        if '\r\n' in content and '\n' in content:
            self.issues.append(ValidationIssue(
                line_number=1,
                line_content="",
                issue_type=ValidationLevel.WARNING,
                message="Mixed line endings detected",
                suggestion="Use consistent line endings (preferably Unix-style LF)"
            ))
        
        # Check for trailing whitespace
        for i, line in enumerate(lines, 1):
            if line.rstrip() != line:
                self.issues.append(ValidationIssue(
                    line_number=i,
                    line_content=line,
                    issue_type=ValidationLevel.WARNING,
                    message="Trailing whitespace detected",
                    suggestion="Remove trailing spaces and tabs"
                ))


class HostsLinter:
    """Linter for hosts file formatting and style."""
    
    def __init__(self):
        self.suggestions: List[ValidationIssue] = []
    
    def lint_hosts_content(self, content: str) -> List[ValidationIssue]:
        """Lint the hosts file content for style and formatting issues."""
        self.suggestions.clear()
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._lint_line(line, line_num)
        
        return sorted(self.suggestions, key=lambda x: x.line_number)
    
    def _lint_line(self, line: str, line_num: int):
        """Lint a single line for style issues."""
        original_line = line
        
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('#'):
            return
        
        # Check for inconsistent spacing
        if '  ' in line:  # Multiple spaces
            self.suggestions.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.INFO,
                message="Multiple consecutive spaces detected",
                suggestion="Use single spaces between IP and hostnames"
            ))
        
        # Check for tabs
        if '\t' in line:
            self.suggestions.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.WARNING,
                message="Tab characters detected",
                suggestion="Use spaces instead of tabs for consistency"
            ))
        
        # Check for leading/trailing spaces
        if line != line.strip():
            self.suggestions.append(ValidationIssue(
                line_number=line_num,
                line_content=original_line,
                issue_type=ValidationLevel.INFO,
                message="Leading or trailing whitespace",
                suggestion="Remove leading and trailing spaces"
            ))
        
        # Check for proper alignment
        parts = line.strip().split()
        if len(parts) >= 2:
            ip = parts[0]
            hostnames = parts[1:]
            
            # Suggest grouping related hostnames
            if len(hostnames) > 3:
                self.suggestions.append(ValidationIssue(
                    line_number=line_num,
                    line_content=original_line,
                    issue_type=ValidationLevel.INFO,
                    message="Many hostnames on single line",
                    suggestion="Consider grouping related hostnames or adding comments"
                ))
            
            # Check for consistent hostname ordering
            if len(hostnames) > 1:
                sorted_hostnames = sorted(hostnames, key=str.lower)
                if hostnames != sorted_hostnames:
                    self.suggestions.append(ValidationIssue(
                        line_number=line_num,
                        line_content=original_line,
                        issue_type=ValidationLevel.INFO,
                        message="Hostnames not in alphabetical order",
                        suggestion="Consider sorting hostnames alphabetically"
                    ))


class HostsFormatter:
    """Formatter for hosts file content."""
    
    def format_hosts_content(self, content: str) -> str:
        """Format hosts file content with consistent styling."""
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            formatted_line = self._format_line(line)
            if formatted_line is not None:
                formatted_lines.append(formatted_line)
        
        return '\n'.join(formatted_lines) + '\n'
    
    def _format_line(self, line: str) -> Optional[str]:
        """Format a single line."""
        line = line.strip()
        
        # Skip empty lines
        if not line:
            return None
        
        # Preserve comments
        if line.startswith('#'):
            return line
        
        # Format hosts entries
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            hostnames = parts[1:]
            
            # Sort hostnames alphabetically
            hostnames = sorted(hostnames, key=str.lower)
            
            # Join with single spaces
            return f"{ip} {' '.join(hostnames)}"
        
        return line


def validate_and_lint_hosts(content: str) -> Tuple[List[ValidationIssue], List[ValidationIssue]]:
    """Convenience function to validate and lint hosts content."""
    validator = HostsValidator()
    linter = HostsLinter()
    
    validation_issues = validator.validate_hosts_content(content)
    lint_issues = linter.lint_hosts_content(content)
    
    return validation_issues, lint_issues


def format_hosts_file(content: str) -> str:
    """Convenience function to format hosts content."""
    formatter = HostsFormatter()
    return formatter.format_hosts_content(content)


def get_validation_summary(issues: List[ValidationIssue]) -> Dict[str, int]:
    """Get a summary of validation issues by type."""
    summary = {
        'errors': 0,
        'warnings': 0,
        'info': 0
    }
    
    for issue in issues:
        if issue.issue_type == ValidationLevel.ERROR:
            summary['errors'] += 1
        elif issue.issue_type == ValidationLevel.WARNING:
            summary['warnings'] += 1
        elif issue.issue_type == ValidationLevel.INFO:
            summary['info'] += 1
    
    return summary


if __name__ == "__main__":
    # Test the validation module
    test_content = """127.0.0.1 localhost
192.168.1.1  router
192.168.1.1  router.local
10.0.0.1    server
invalid-ip   badhost
127.0.0.1    localhost
"""
    
    validation_issues, lint_issues = validate_and_lint_hosts(test_content)
    
    print("Validation Issues:")
    for issue in validation_issues:
        print(f"  Line {issue.line_number}: {issue.issue_type.value.upper()} - {issue.message}")
        if issue.suggestion:
            print(f"    Suggestion: {issue.suggestion}")
    
    print("\nLint Issues:")
    for issue in lint_issues:
        print(f"  Line {issue.line_number}: {issue.issue_type.value.upper()} - {issue.message}")
        if issue.suggestion:
            print(f"    Suggestion: {issue.suggestion}")
    
    print(f"\nSummary: {get_validation_summary(validation_issues + lint_issues)}") 