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
    """Validate all entries in hosts file."""
    try:
        entries = repo.get_host_entries()
        
        valid_count = 0
        invalid_count = 0
        warning_count = 0
        
        print("\n🔍 Validating hosts file entries...")
        print("-" * 60)
        
        for entry in entries:
            validation = entry.validate()
            
            if validation.is_valid:
                valid_count += 1
                if validation.warnings:
                    warning_count += 1
                    print(f"⚠️  {entry.ip} {entry.hostname}: {', '.join(validation.warnings)}")
            else:
                invalid_count += 1
                print(f"❌ {entry.ip} {entry.hostname}: {', '.join(validation.errors)}")
        
        print(f"\n📊 Validation Summary:")
        print(f"   Valid entries:    {valid_count}")
        print(f"   Invalid entries:  {invalid_count}")
        print(f"   Entries w/ warnings: {warning_count}")
        
        return invalid_count == 0
        
    except Exception as e:
        print(f"❌ Failed to validate entries: {e}")
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
    subparsers.add_parser('validate', help='Validate all entries')
    
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
        commands = {
            'add': add_entry_command,
            'remove': remove_entry_command,
            'update': update_entry_command,
            'list': list_entries_command,
            'batch-add': batch_add_command,
            'stats': stats_command,
            'backup': backup_command,
            'validate': validate_command
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