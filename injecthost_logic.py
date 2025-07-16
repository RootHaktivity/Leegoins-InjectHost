# injecthost_logic.py
"""
Legacy compatibility layer for InjectHost logic.
Now uses the new architecture with improved error handling and features.
"""

import os
import logging
from pathlib import Path

# Import new architecture components
from config import get_config, InjectHostConfig
from models import HostEntry, OperationResult
from repository import FileHostsRepository
from validation import validate_and_lint_hosts, format_hosts_file, get_validation_summary

# Legacy constants for backward compatibility
HOSTS_FILE = "/etc/hosts"
BACKUP_FILE = "/etc/hosts.bak"
MARKER = "# THM"

# Initialize global components
_config = None
_repository = None

def _get_repository():
    """Get or create repository instance."""
    global _config, _repository
    
    if _repository is None:
        try:
            _config = get_config()
        except Exception:
            # Fallback to default config if loading fails
            _config = InjectHostConfig()
        _repository = FileHostsRepository(_config)
    
    return _repository

def backup_hosts():
    """Legacy backup function - now uses new repository."""
    try:
        repo = _get_repository()
        backup_info = repo.create_backup()
        return f"Backup created at {backup_info.path}"
    except Exception as e:
        return f"Backup failed: {e}"

def read_hosts():
    """Legacy read function - now uses new repository."""
    try:
        repo = _get_repository()
        entries = repo.read_all_entries()
        return [entry.content for entry in entries]
    except Exception as e:
        logging.error(f"Failed to read hosts file: {e}")
        raise

def write_hosts(lines):
    """Legacy write function - now uses new repository (not recommended)."""
    logging.warning("write_hosts is deprecated, use repository.add_entry() instead")
    try:
        # Convert lines back to content and write
        content = ''.join(lines)
        repo = _get_repository()
        
        # This is a hack for legacy compatibility - not ideal
        with open(repo.config.hosts_file, 'w') as f:
            f.write(content)
        
        backup_info = repo.create_backup()
        return backup_info.path
    except Exception as e:
        logging.error(f"Failed to write hosts file: {e}")
        raise

def add_entry(ip, hostname):
    """Add entry to hosts file using new architecture."""
    try:
        repo = _get_repository()
        entry = HostEntry(ip, hostname)
        result = repo.add_entry(entry)
        
        if result.success:
            message = result.message
            if result.backup_created:
                message += f"\nBackup created: {result.backup_created}"
            if result.warnings:
                message += f"\nWarnings: {', '.join(result.warnings)}"
            
            # Flush DNS cache for immediate effect
            try:
                from network_utils import flush_dns_cache
                if flush_dns_cache():
                    message += "\nDNS cache flushed for immediate effect"
                else:
                    message += "\nDNS cache flush failed (changes may take time to take effect)"
            except ImportError:
                message += "\nDNS cache flush not available"
            
            return message
        else:
            return f"Failed to add entry: {result.message}"
            
    except Exception as e:
        logging.error(f"Failed to add entry {ip} {hostname}: {e}")
        return f"Unexpected error: {e}"

def remove_entry(ip, hostname):
    """Remove entry from hosts file using new architecture."""
    try:
        repo = _get_repository()
        entry = HostEntry(ip, hostname)
        result = repo.remove_entry(entry)
        
        if result.success:
            message = result.message
            if result.backup_created:
                message += f"\nBackup created: {result.backup_created}"
            
            # Flush DNS cache for immediate effect
            try:
                from network_utils import flush_dns_cache
                if flush_dns_cache():
                    message += "\nDNS cache flushed for immediate effect"
                else:
                    message += "\nDNS cache flush failed (changes may take time to take effect)"
            except ImportError:
                message += "\nDNS cache flush not available"
            
            return message
        else:
            return f"Failed to remove entry: {result.message}"
            
    except Exception as e:
        logging.error(f"Failed to remove entry {ip} {hostname}: {e}")
        return f"Unexpected error: {e}"

def update_entry(old_ip, old_hostname, new_ip, new_hostname):
    """Update entry in hosts file using new architecture."""
    try:
        repo = _get_repository()
        old_entry = HostEntry(old_ip, old_hostname)
        new_entry = HostEntry(new_ip, new_hostname)
        result = repo.update_entry(old_entry, new_entry)
        
        if result.success:
            message = result.message
            if result.backup_created:
                message += f"\nBackup created: {result.backup_created}"
            if result.warnings:
                message += f"\nWarnings: {', '.join(result.warnings)}"
            
            # Flush DNS cache for immediate effect
            try:
                from network_utils import flush_dns_cache
                if flush_dns_cache():
                    message += "\nDNS cache flushed for immediate effect"
                else:
                    message += "\nDNS cache flush failed (changes may take time to take effect)"
            except ImportError:
                message += "\nDNS cache flush not available"
            
            return message
        else:
            return f"Failed to update entry: {result.message}"
            
    except Exception as e:
        logging.error(f"Failed to update entry: {e}")
        return f"Unexpected error: {e}"

def get_host_entries():
    """Get all host entries using new architecture."""
    try:
        repo = _get_repository()
        return repo.get_host_entries()
    except Exception as e:
        logging.error(f"Failed to get host entries: {e}")
        return []

def get_stats():
    """Get hosts file statistics."""
    try:
        repo = _get_repository()
        return repo.get_stats()
    except Exception as e:
        logging.error(f"Failed to get stats: {e}")
        return None

def batch_add_entries(entries_list):
    """Add multiple entries at once."""
    try:
        repo = _get_repository()
        entries = [HostEntry(ip, hostname) for ip, hostname in entries_list]
        result = repo.batch_add_entries(entries)
        
        if result.success:
            message = result.message
            if result.backup_created:
                message += f"\nBackup created: {result.backup_created}"
            if result.warnings:
                message += f"\nWarnings: {', '.join(result.warnings)}"
            return message
        else:
            return f"Failed to add entries: {result.message}"
            
    except Exception as e:
        logging.error(f"Failed to batch add entries: {e}")
        return f"Unexpected error: {e}"

# You might also want a function to check root status for the GUI
def check_root_status():
    return os.geteuid() == 0

def validate_hosts_file():
    """Validate the current hosts file and return validation results."""
    try:
        repo = _get_repository()
        content = repo.read_raw_content()
        validation_issues, lint_issues = validate_and_lint_hosts(content)
        
        return {
            'validation_issues': validation_issues,
            'lint_issues': lint_issues,
            'summary': get_validation_summary(validation_issues + lint_issues),
            'content': content
        }
    except Exception as e:
        logging.error(f"Failed to validate hosts file: {e}")
        return {
            'validation_issues': [],
            'lint_issues': [],
            'summary': {'errors': 0, 'warnings': 0, 'info': 0},
            'error': str(e)
        }

def format_hosts_file_content():
    """Format the hosts file content with consistent styling."""
    try:
        repo = _get_repository()
        content = repo.read_raw_content()
        formatted_content = format_hosts_file(content)
        
        # Write the formatted content back
        with open(repo.config.hosts_file, 'w') as f:
            f.write(formatted_content)
        
        # Create backup
        backup_info = repo.create_backup()
        
        return f"Hosts file formatted successfully\nBackup created: {backup_info.path}"
    except Exception as e:
        logging.error(f"Failed to format hosts file: {e}")
        return f"Failed to format hosts file: {e}"

def get_validation_report():
    """Get a detailed validation report for the hosts file."""
    try:
        repo = _get_repository()
        content = repo.read_raw_content()
        validation_issues, lint_issues = validate_and_lint_hosts(content)
        
        report = {
            'total_validation_issues': len(validation_issues),
            'total_lint_issues': len(lint_issues),
            'validation_summary': get_validation_summary(validation_issues),
            'lint_summary': get_validation_summary(lint_issues),
            'validation_issues': validation_issues,
            'lint_issues': lint_issues,
            'file_size': len(content),
            'line_count': len(content.split('\n')),
            'has_errors': any(issue.issue_type.value == 'error' for issue in validation_issues),
            'has_warnings': any(issue.issue_type.value == 'warning' for issue in validation_issues + lint_issues)
        }
        
        return report
    except Exception as e:
        logging.error(f"Failed to generate validation report: {e}")
        return {'error': str(e)}
