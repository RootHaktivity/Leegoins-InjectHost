#!/usr/bin/env python3
"""
Enhanced InjectHost CLI tool with new architecture.
Provides advanced features like batch operations, statistics, and validation.
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import List, Optional

# Import new architecture components
from config import get_config, InjectHostConfig
from models import HostEntry, HostsFileStats
from repository import FileHostsRepository
from validation import ValidationIssue, ValidationLevel


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. Hosts file modifications may fail.")
        print("   Run with: sudo python3 injecthost_enhanced.py")
        return False
    return True


def add_entry_command(args, repo: FileHostsRepository):
    """Add a single host entry."""
    entry = HostEntry(args.ip, args.hostname, args.comment)
    
    # Validate entry first
    validation = entry.validate()
    if not validation.is_valid:
        print(f"❌ Invalid entry: {', '.join(validation.errors)}")
        return False
    
    if validation.warnings:
        print(f"⚠️  Warnings: {', '.join(validation.warnings)}")
        if not args.force and input("Continue? (y/N): ").lower() != 'y':
            return False
    
    result = repo.add_entry(entry)
    
    if result.success:
        print(f"✅ {result.message}")
        if result.warnings:
            print(f"⚠️  Warnings: {', '.join(result.warnings)}")
        return True
    else:
        print(f"❌ {result.message}")
        return False


def remove_entry_command(args, repo: FileHostsRepository):
    """Remove a host entry."""
    entry = HostEntry(args.ip, args.hostname)
    result = repo.remove_entry(entry)
    
    if result.success:
        print(f"✅ {result.message}")
        return True
    else:
        print(f"❌ {result.message}")
        return False


def update_entry_command(args, repo: FileHostsRepository):
    """Update a host entry."""
    old_entry = HostEntry(args.old_ip, args.old_hostname)
    new_entry = HostEntry(args.new_ip, args.new_hostname, args.comment)
    
    # Validate new entry
    validation = new_entry.validate()
    if not validation.is_valid:
        print(f"❌ Invalid new entry: {', '.join(validation.errors)}")
        return False
    
    result = repo.update_entry(old_entry, new_entry)
    
    if result.success:
        print(f"✅ {result.message}")
        if result.warnings:
            print(f"⚠️  Warnings: {', '.join(result.warnings)}")
        return True
    else:
        print(f"❌ {result.message}")
        return False


def list_entries_command(args, repo: FileHostsRepository):
    """List host entries with filtering."""
    try:
        entries = repo.get_host_entries()
        
        # Apply filters
        if args.filter_ip:
            entries = [e for e in entries if args.filter_ip.lower() in e.ip.lower()]
        
        if args.filter_hostname:
            entries = [e for e in entries if args.filter_hostname.lower() in e.hostname.lower()]
        
        if not entries:
            print("No host entries found.")
            return True
        
        # Display entries
        print(f"\nFound {len(entries)} host entries:")
        print("-" * 60)
        
        for i, entry in enumerate(entries, 1):
            validation = entry.validate()
            status = "✅" if validation.is_valid else "❌"
            
            print(f"{i:3d}. {status} {entry.ip:<15} -> {entry.hostname}")
            
            if entry.comment:
                print(f"     Comment: {entry.comment}")
            
            if not validation.is_valid:
                print(f"     Errors: {', '.join(validation.errors)}")
            
            if validation.warnings:
                print(f"     Warnings: {', '.join(validation.warnings)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to list entries: {e}")
        return False


def batch_add_command(args, repo: FileHostsRepository):
    """Add multiple entries from file."""
    try:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌ File not found: {file_path}")
            return False
        
        entries = []
        invalid_lines = []
        
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) < 2:
                    invalid_lines.append(f"Line {line_num}: {line}")
                    continue
                
                ip = parts[0]
                hostname = parts[1]
                comment = ' '.join(parts[2:]) if len(parts) > 2 else None
                
                entry = HostEntry(ip, hostname, comment)
                entries.append(entry)
        
        if invalid_lines:
            print(f"⚠️  Invalid lines skipped:")
            for invalid in invalid_lines:
                print(f"   {invalid}")
        
        if not entries:
            print("❌ No valid entries found in file.")
            return False
        
        print(f"📁 Found {len(entries)} entries to add...")
        
        if not args.force:
            print("\nPreview:")
            for entry in entries[:5]:  # Show first 5
                print(f"   {entry.ip} -> {entry.hostname}")
            if len(entries) > 5:
                print(f"   ... and {len(entries) - 5} more")
            
            if input("\nProceed with batch add? (y/N): ").lower() != 'y':
                return False
        
        result = repo.batch_add_entries(entries)
        
        if result.success:
            print(f"✅ {result.message}")
            if result.warnings:
                print(f"⚠️  Warnings: {', '.join(result.warnings)}")
            return True
        else:
            print(f"❌ {result.message}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to batch add entries: {e}")
        return False


def stats_command(args, repo: FileHostsRepository):
    """Show hosts file statistics."""
    try:
        stats = repo.get_stats()
        
        print("\n📊 Hosts File Statistics")
        print("=" * 40)
        print(f"Total lines:     {stats.total_lines}")
        print(f"Host entries:    {stats.total_hosts}")
        print(f"  - IPv4:        {len(stats.ipv4_hosts)}")
        print(f"  - IPv6:        {len(stats.ipv6_hosts)}")
        print(f"  - Invalid:     {len(stats.invalid_hosts)}")
        print(f"Comment lines:   {len(stats.comment_lines)}")
        print(f"Blank lines:     {len(stats.blank_lines)}")
        
        # Check for duplicates and conflicts
        duplicates = stats.get_duplicates()
        conflicts = stats.get_conflicts()
        
        if duplicates:
            print(f"\n⚠️  Found {len(duplicates)} duplicate groups:")
            for i, dup_group in enumerate(duplicates, 1):
                print(f"   {i}. {dup_group[0].ip} {dup_group[0].hostname} ({len(dup_group)} occurrences)")
        
        if conflicts:
            print(f"\n⚠️  Found {len(conflicts)} hostname conflicts:")
            for i, conf_group in enumerate(conflicts, 1):
                print(f"   {i}. {conf_group[0].hostname}:")
                for entry in conf_group:
                    print(f"      -> {entry.ip}")
        
        if args.show_invalid and stats.invalid_hosts:
            print(f"\n❌ Invalid entries:")
            for entry in stats.invalid_hosts:
                validation = entry.validate()
                print(f"   {entry.ip} {entry.hostname}: {', '.join(validation.errors)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to get statistics: {e}")
        return False


def backup_command(args, repo: FileHostsRepository):
    """Create backup of hosts file."""
    try:
        backup_info = repo.create_backup()
        print(f"✅ Backup created: {backup_info.path}")
        print(f"   Size: {backup_info.size} bytes")
        print(f"   Time: {backup_info.timestamp}")
        return True
    except Exception as e:
        print(f"❌ Failed to create backup: {e}")
        return False


def validate_command(args, repo: FileHostsRepository):
    """Validate hosts file with advanced validation and linting."""
    try:
        from injecthost_logic import validate_hosts_file, get_validation_report
        
        if args.detailed:
            # Get detailed validation report
            report = get_validation_report()
            
            if 'error' in report:
                print(f"❌ Failed to validate hosts file: {report['error']}")
                return False
            
            print("\n🔍 Advanced Hosts File Validation Report")
            print("=" * 60)
            
            # File statistics
            print(f"📄 File Statistics:")
            print(f"   Size: {report['file_size']} bytes")
            print(f"   Lines: {report['line_count']}")
            
            # Validation summary
            val_summary = report['validation_summary']
            lint_summary = report['lint_summary']
            
            print(f"\n📊 Validation Summary:")
            print(f"   Errors:   {val_summary['errors']}")
            print(f"   Warnings: {val_summary['warnings']}")
            print(f"   Info:     {val_summary['info']}")
            
            print(f"\n📊 Linting Summary:")
            print(f"   Errors:   {lint_summary['errors']}")
            print(f"   Warnings: {lint_summary['warnings']}")
            print(f"   Info:     {lint_summary['info']}")
            
            # Show validation issues
            if report['validation_issues']:
                print(f"\n❌ Validation Issues:")
                print("-" * 40)
                for issue in report['validation_issues']:
                    icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                    print(f"{icon} Line {issue.line_number}: {issue.message}")
                    if issue.suggestion:
                        print(f"    💡 Suggestion: {issue.suggestion}")
                    if issue.line_content.strip():
                        print(f"    📝 Content: {issue.line_content.strip()}")
            
            # Show linting issues
            if report['lint_issues']:
                print(f"\n🔧 Linting Issues:")
                print("-" * 40)
                for issue in report['lint_issues']:
                    icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                    print(f"{icon} Line {issue.line_number}: {issue.message}")
                    if issue.suggestion:
                        print(f"    💡 Suggestion: {issue.suggestion}")
            
            # Overall status
            if report['has_errors']:
                print(f"\n❌ Hosts file has validation errors that should be fixed.")
                return False
            elif report['has_warnings']:
                print(f"\n⚠️  Hosts file has warnings but no critical errors.")
                return True
            else:
                print(f"\n✅ Hosts file is valid and well-formatted!")
                return True
                
        else:
            # Simple validation
            result = validate_hosts_file()
            
            if 'error' in result:
                print(f"❌ Failed to validate hosts file: {result['error']}")
                return False
            
            summary = result['summary']
            validation_issues = result['validation_issues']
            lint_issues = result['lint_issues']
            
            print(f"\n🔍 Hosts File Validation")
            print("-" * 40)
            
            if validation_issues:
                print(f"❌ Found {len(validation_issues)} validation issues:")
                for issue in validation_issues[:5]:  # Show first 5
                    icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                    print(f"  {icon} Line {issue.line_number}: {issue.message}")
                if len(validation_issues) > 5:
                    print(f"  ... and {len(validation_issues) - 5} more issues")
            else:
                print("✅ No validation issues found")
            
            if lint_issues:
                print(f"🔧 Found {len(lint_issues)} linting issues:")
                for issue in lint_issues[:3]:  # Show first 3
                    icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                    print(f"  {icon} Line {issue.line_number}: {issue.message}")
                if len(lint_issues) > 3:
                    print(f"  ... and {len(lint_issues) - 3} more issues")
            else:
                print("✅ No linting issues found")
            
            print(f"\n📊 Summary: {summary['errors']} errors, {summary['warnings']} warnings, {summary['info']} info")
            
            return summary['errors'] == 0
        
    except ImportError:
        print("❌ Validation module not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to validate hosts file: {e}")
        return False


def test_command(args, repo: FileHostsRepository):
    """Test connectivity to host entries."""
    try:
        from network_utils import NetworkUtils
        
        entries = repo.get_host_entries()
        
        if not entries:
            print("No host entries to test.")
            return True
        
        print(f"\n🌐 Testing connectivity to {len(entries)} host entries...")
        print("-" * 60)
        
        successful_tests = 0
        failed_tests = 0
        
        for entry in entries:
            print(f"\nTesting: {entry.hostname} ({entry.ip})")
            
            # Test DNS resolution
            success, resolved_ip = NetworkUtils.test_hostname_resolution(entry.hostname)
            if success:
                print(f"  ✅ DNS Resolution: {entry.hostname} -> {resolved_ip}")
                if resolved_ip == entry.ip:
                    print(f"     ✅ Resolves to expected IP")
                else:
                    print(f"     ⚠️  Resolves to {resolved_ip} (expected {entry.ip})")
            else:
                print(f"  ❌ DNS Resolution: Failed to resolve {entry.hostname}")
                failed_tests += 1
                continue
            
            # Test ping
            ping_result = NetworkUtils.ping_host(entry.hostname)
            if ping_result["success"]:
                print(f"  ✅ Ping: {ping_result['packet_loss']}% loss, {ping_result['avg_time']}ms avg")
            else:
                print(f"  ❌ Ping: {ping_result.get('error', 'Failed')}")
                failed_tests += 1
                continue
            
            # Test HTTP connectivity
            http_success = NetworkUtils.test_connectivity(entry.hostname, 80)
            https_success = NetworkUtils.test_connectivity(entry.hostname, 443)
            
            if http_success:
                print(f"  ✅ HTTP (port 80): Connected")
            else:
                print(f"  ❌ HTTP (port 80): Connection failed")
            
            if https_success:
                print(f"  ✅ HTTPS (port 443): Connected")
            else:
                print(f"  ❌ HTTPS (port 443): Connection failed")
            
            successful_tests += 1
        
        print(f"\n📊 Test Summary:")
        print(f"   Successful tests: {successful_tests}")
        print(f"   Failed tests:     {failed_tests}")
        
        return failed_tests == 0
        
    except ImportError:
        print("❌ Network utilities not available. Install required dependencies.")
        return False
    except Exception as e:
        print(f"❌ Failed to test connectivity: {e}")
        return False


def flush_dns_command(args, repo: FileHostsRepository):
    """Flush DNS cache."""
    try:
        from network_utils import flush_dns_cache
        
        print("🔄 Flushing DNS cache...")
        if flush_dns_cache():
            print("✅ DNS cache flushed successfully")
            return True
        else:
            print("❌ Failed to flush DNS cache")
            return False
            
    except ImportError:
        print("❌ Network utilities not available. Install required dependencies.")
        return False
    except Exception as e:
        print(f"❌ Failed to flush DNS cache: {e}")
        return False


def scan_network_command(args, repo: FileHostsRepository):
    """Scan local network for active hosts."""
    try:
        from network_utils import NetworkUtils
        
        base_ip = args.base_ip
        print(f"🔍 Scanning network {base_ip}.0/24 for active hosts...")
        print("This may take a few moments...")
        
        active_hosts = NetworkUtils.scan_local_network(base_ip)
        
        if not active_hosts:
            print("❌ No active hosts found on the network.")
            return True
        
        print(f"\n✅ Found {len(active_hosts)} active hosts:")
        print("-" * 60)
        
        for i, host in enumerate(active_hosts, 1):
            print(f"{i:3d}. {host['ip']:<15} -> {host['hostname']}")
        
        if args.add_to_hosts:
            print(f"\n📝 Adding discovered hosts to /etc/hosts...")
            entries_to_add = []
            
            for host in active_hosts:
                if host['hostname'] != 'unknown':
                    entry = HostEntry(host['ip'], host['hostname'])
                    entries_to_add.append(entry)
            
            if entries_to_add:
                result = repo.batch_add_entries(entries_to_add)
                if result.success:
                    print(f"✅ Added {len(entries_to_add)} hosts to /etc/hosts")
                else:
                    print(f"❌ Failed to add hosts: {result.message}")
            else:
                print("⚠️  No hosts with valid hostnames found to add.")
        
        return True
        
    except ImportError:
        print("❌ Network utilities not available. Install required dependencies.")
        return False
    except Exception as e:
        print(f"❌ Failed to scan network: {e}")
        return False


def config_save_command(args, repo: FileHostsRepository):
    """Save current hosts as a configuration."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        config = manager.create_from_current_hosts(args.name, args.description)
        
        if config:
            print(f"✅ Configuration '{args.name}' saved successfully!")
            stats = config.get_stats()
            print(f"   Entries: {stats['total_entries']}")
            print(f"   Created: {stats['created_at']}")
            return True
        else:
            print(f"❌ Failed to save configuration '{args.name}'")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to save configuration: {e}")
        return False


def config_list_command(args, repo: FileHostsRepository):
    """List all saved configurations."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        configs = manager.list_configurations()
        
        if not configs:
            print("📋 No saved configurations found.")
            return True
        
        print(f"\n📋 Found {len(configs)} saved configurations:")
        print("-" * 80)
        
        for config in configs:
            stats = config['stats']
            print(f"📁 {config['name']}")
            if config['description']:
                print(f"   Description: {config['description']}")
            print(f"   Entries: {stats['total_entries']}")
            print(f"   Created: {stats['created_at'][:19]}")
            print(f"   Updated: {stats['updated_at'][:19]}")
            print()
        
        return True
        
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to list configurations: {e}")
        return False


def config_apply_command(args, repo: FileHostsRepository):
    """Apply a saved configuration."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        
        if not args.force:
            print(f"⚠️  This will replace your current /etc/hosts file with configuration '{args.name}'")
            if input("Continue? (y/N): ").lower() != 'y':
                return False
        
        success = manager.apply_configuration(args.name, backup_current=True)
        
        if success:
            print(f"✅ Configuration '{args.name}' applied successfully!")
            print("   Previous hosts file backed up automatically.")
            return True
        else:
            print(f"❌ Failed to apply configuration '{args.name}'")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to apply configuration: {e}")
        return False


def config_delete_command(args, repo: FileHostsRepository):
    """Delete a saved configuration."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        
        if not args.force:
            print(f"⚠️  This will permanently delete configuration '{args.name}'")
            if input("Continue? (y/N): ").lower() != 'y':
                return False
        
        success = manager.delete_configuration(args.name)
        
        if success:
            print(f"✅ Configuration '{args.name}' deleted successfully!")
            return True
        else:
            print(f"❌ Failed to delete configuration '{args.name}'")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to delete configuration: {e}")
        return False


def config_export_command(args, repo: FileHostsRepository):
    """Export a configuration to a file."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        success = manager.export_configuration(args.name, args.output)
        
        if success:
            print(f"✅ Configuration '{args.name}' exported to {args.output}")
            return True
        else:
            print(f"❌ Failed to export configuration '{args.name}'")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to export configuration: {e}")
        return False


def config_import_command(args, repo: FileHostsRepository):
    """Import a configuration from a file."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        config_name = manager.import_configuration(args.file, overwrite=args.overwrite)
        
        if config_name:
            print(f"✅ Configuration '{config_name}' imported successfully!")
            return True
        else:
            print(f"❌ Failed to import configuration from {args.file}")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to import configuration: {e}")
        return False


def config_rename_command(args, repo: FileHostsRepository):
    """Rename a configuration."""
    try:
        from config_manager import get_config_manager
        
        manager = get_config_manager()
        success = manager.rename_configuration(args.old_name, args.new_name, args.description)
        
        if success:
            if args.description:
                print(f"✅ Configuration '{args.old_name}' renamed to '{args.new_name}' with new description successfully!")
            else:
                print(f"✅ Configuration '{args.old_name}' renamed to '{args.new_name}' successfully!")
            return True
        else:
            print(f"❌ Failed to rename configuration '{args.old_name}' to '{args.new_name}'")
            return False
            
    except ImportError:
        print("❌ Configuration management not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to rename configuration: {e}")
        return False


def format_command(args, repo: FileHostsRepository):
    """Format the hosts file with consistent styling."""
    try:
        from injecthost_logic import format_hosts_file_content
        
        print("🔧 Formatting hosts file...")
        result = format_hosts_file_content()
        
        if "successfully" in result:
            print(f"✅ {result}")
            return True
        else:
            print(f"❌ {result}")
            return False
            
    except ImportError:
        print("❌ Formatting module not available.")
        return False
    except Exception as e:
        print(f"❌ Failed to format hosts file: {e}")
        return False


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Enhanced InjectHost CLI - Manage /etc/hosts entries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Add entry:        injecthost_enhanced.py add 10.10.10.10 target.thm
  Remove entry:     injecthost_enhanced.py remove 10.10.10.10 target.thm
  List entries:     injecthost_enhanced.py list --filter-hostname thm
  Batch add:        injecthost_enhanced.py batch-add hosts.txt
  Show stats:       injecthost_enhanced.py stats
  Validate:         injecthost_enhanced.py validate
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-f', '--force', action='store_true',
                       help='Skip confirmation prompts')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a host entry')
    add_parser.add_argument('ip', help='IP address')
    add_parser.add_argument('hostname', help='Hostname')
    add_parser.add_argument('-c', '--comment', help='Optional comment')
    
    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a host entry')
    remove_parser.add_argument('ip', help='IP address')
    remove_parser.add_argument('hostname', help='Hostname')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update a host entry')
    update_parser.add_argument('old_ip', help='Current IP address')
    update_parser.add_argument('old_hostname', help='Current hostname')
    update_parser.add_argument('new_ip', help='New IP address')
    update_parser.add_argument('new_hostname', help='New hostname')
    update_parser.add_argument('-c', '--comment', help='Optional comment')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List host entries')
    list_parser.add_argument('--filter-ip', help='Filter by IP address')
    list_parser.add_argument('--filter-hostname', help='Filter by hostname')
    
    # Batch add command
    batch_parser = subparsers.add_parser('batch-add', help='Add entries from file')
    batch_parser.add_argument('file', help='File containing entries (IP hostname [comment])')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    stats_parser.add_argument('--show-invalid', action='store_true',
                             help='Show invalid entries')
    
    # Backup command
    subparsers.add_parser('backup', help='Create backup')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate hosts file with advanced validation and linting')
    validate_parser.add_argument('--detailed', '-d', action='store_true',
                                help='Show detailed validation report')
    
    # Format command
    subparsers.add_parser('format', help='Format hosts file with consistent styling')
    
    # Test command
    subparsers.add_parser('test', help='Test connectivity to host entries')
    
    # Flush DNS command
    subparsers.add_parser('flush-dns', help='Flush DNS cache')
    
    # Scan network command
    scan_parser = subparsers.add_parser('scan', help='Scan local network for active hosts')
    scan_parser.add_argument('base_ip', help='Base IP address (e.g., 192.168.1)')
    scan_parser.add_argument('--add-to-hosts', action='store_true',
                            help='Add discovered hosts to /etc/hosts')
    
    # Configuration management commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_command', help='Configuration commands')
    
    # Save configuration
    save_parser = config_subparsers.add_parser('save', help='Save current hosts as configuration')
    save_parser.add_argument('name', help='Configuration name')
    save_parser.add_argument('--description', '-d', default='', help='Configuration description')
    save_parser.set_defaults(func=config_save_command)
    
    # List configurations
    list_parser = config_subparsers.add_parser('list', help='List all saved configurations')
    list_parser.set_defaults(func=config_list_command)
    
    # Apply configuration
    apply_parser = config_subparsers.add_parser('apply', help='Apply a saved configuration')
    apply_parser.add_argument('name', help='Configuration name')
    apply_parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation prompt')
    apply_parser.set_defaults(func=config_apply_command)
    
    # Delete configuration
    delete_parser = config_subparsers.add_parser('delete', help='Delete a saved configuration')
    delete_parser.add_argument('name', help='Configuration name')
    delete_parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation prompt')
    delete_parser.set_defaults(func=config_delete_command)
    
    # Export configuration
    export_parser = config_subparsers.add_parser('export', help='Export a configuration to file')
    export_parser.add_argument('name', help='Configuration name')
    export_parser.add_argument('output', help='Output file path')
    export_parser.set_defaults(func=config_export_command)
    
    # Import configuration
    import_parser = config_subparsers.add_parser('import', help='Import a configuration from file')
    import_parser.add_argument('file', help='Configuration file path')
    import_parser.add_argument('--overwrite', '-o', action='store_true', help='Overwrite existing configuration')
    import_parser.set_defaults(func=config_import_command)
    
    # Rename configuration
    rename_parser = config_subparsers.add_parser('rename', help='Rename a configuration')
    rename_parser.add_argument('old_name', help='Current configuration name')
    rename_parser.add_argument('new_name', help='New configuration name')
    rename_parser.add_argument('--description', '-d', help='New description (optional)')
    rename_parser.set_defaults(func=config_rename_command)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Check root status for modification commands
    modify_commands = ['add', 'remove', 'update', 'batch-add']
    if args.command in modify_commands:
        if not check_root():
            return 1
    
    try:
        # Initialize repository
        config = get_config()
        config.setup_logging()
        repo = FileHostsRepository(config)
        
        # Execute command
        if args.command == 'config':
            # Handle configuration subcommands
            if not hasattr(args, 'config_command') or not args.config_command:
                print("❌ Please specify a configuration command. Use 'config --help' for options.")
                return 1
            
            config_commands = {
                'save': config_save_command,
                'list': config_list_command,
                'apply': config_apply_command,
                'delete': config_delete_command,
                'export': config_export_command,
                'import': config_import_command,
                'rename': config_rename_command
            }
            
            if args.config_command not in config_commands:
                print(f"❌ Unknown configuration command: {args.config_command}")
                return 1
            
            success = config_commands[args.config_command](args, repo)
            return 0 if success else 1
        else:
            # Handle regular commands
            commands = {
                'add': add_entry_command,
                'remove': remove_entry_command,
                'update': update_entry_command,
                'list': list_entries_command,
                'batch-add': batch_add_command,
                'stats': stats_command,
                'backup': backup_command,
                'validate': validate_command,
                'format': format_command,
                'test': test_command,
                'flush-dns': flush_dns_command,
                'scan': scan_network_command
            }
            
            success = commands[args.command](args, repo)
            return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user.")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())