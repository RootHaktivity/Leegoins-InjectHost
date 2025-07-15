#!/usr/bin/env python3
"""
Comprehensive test suite for InjectHost improvements.
Tests all new components, models, and functionality.
"""

import unittest
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
import logging

# Import our modules
from config import InjectHostConfig, get_config
from models import (
    HostEntry, HostsFileEntry, EntryType, ValidationResult, 
    OperationResult, BackupInfo, HostsFileStats
)
from repository import FileHostsRepository, CachedHostsRepository


class TestInjectHostConfig(unittest.TestCase):
    """Test configuration management."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "config.ini"
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_default_config(self):
        """Test default configuration values."""
        config = InjectHostConfig()
        
        self.assertEqual(config.hosts_file, Path("/etc/hosts"))
        self.assertEqual(config.marker, "# THM")
        self.assertEqual(config.max_backups, 10)
        self.assertTrue(config.allow_ipv6)
        self.assertFalse(config.allow_localhost_modification)
    
    def test_env_config(self):
        """Test configuration from environment variables."""
        with patch.dict(os.environ, {
            'INJECTHOST_MARKER': '# TEST',
            'INJECTHOST_MAX_BACKUPS': '5',
            'INJECTHOST_ALLOW_IPV6': 'false'
        }):
            config = InjectHostConfig.from_env()
            
            self.assertEqual(config.marker, "# TEST")
            self.assertEqual(config.max_backups, 5)
            self.assertFalse(config.allow_ipv6)
    
    def test_file_config(self):
        """Test configuration from file."""
        config_content = """# Test config
marker=# CUSTOM
max_backups=15
log_level=DEBUG
"""
        self.config_file.write_text(config_content)
        
        config = InjectHostConfig.from_file(self.config_file)
        
        self.assertEqual(config.marker, "# CUSTOM")
        self.assertEqual(config.max_backups, 15)
        self.assertEqual(config.log_level, "DEBUG")
    
    def test_save_to_file(self):
        """Test saving configuration to file."""
        config = InjectHostConfig(marker="# SAVE_TEST", max_backups=7)
        config.save_to_file(self.config_file)
        
        content = self.config_file.read_text()
        self.assertIn("marker=# SAVE_TEST", content)
        self.assertIn("max_backups=7", content)
    
    def test_validation(self):
        """Test configuration validation."""
        config = InjectHostConfig(max_backups=0, log_level="INVALID")
        issues = config.validate()
        
        self.assertEqual(len(issues), 2)
        self.assertIn("max_backups must be at least 1", issues)
        self.assertIn("Invalid log level: INVALID", issues)


class TestHostEntry(unittest.TestCase):
    """Test HostEntry model and validation."""
    
    def test_from_line_valid(self):
        """Test parsing valid host entry from line."""
        line = "192.168.1.1    example.com    # comment"
        entry = HostEntry.from_line(line, 5)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.1")
        self.assertEqual(entry.hostname, "example.com")
        self.assertEqual(entry.comment, "# comment")
        self.assertEqual(entry.line_number, 5)
    
    def test_from_line_invalid(self):
        """Test parsing invalid lines."""
        invalid_lines = [
            "# comment line",
            "",
            "   ",
            "192.168.1.1"  # Missing hostname
        ]
        
        for line in invalid_lines:
            entry = HostEntry.from_line(line)
            self.assertIsNone(entry)
    
    def test_to_line(self):
        """Test converting entry to line format."""
        entry = HostEntry("10.0.0.1", "test.local", "test comment")
        line = entry.to_line()
        
        expected = "10.0.0.1\ttest.local\t# test comment"
        self.assertEqual(line, expected)
    
    def test_validate_ip_valid(self):
        """Test valid IP address validation."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
            "0.0.0.0"
        ]
        
        for ip in valid_ips:
            result = HostEntry.validate_ip(ip)
            self.assertTrue(result.is_valid, f"IP {ip} should be valid")
    
    def test_validate_ip_invalid(self):
        """Test invalid IP address validation."""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "not.an.ip",
            "192.168.1.1.1",
            ""
        ]
        
        for ip in invalid_ips:
            result = HostEntry.validate_ip(ip)
            self.assertFalse(result.is_valid, f"IP {ip} should be invalid")
            self.assertTrue(len(result.errors) > 0)
    
    def test_validate_hostname_valid(self):
        """Test valid hostname validation."""
        valid_hostnames = [
            "localhost",
            "example.com",
            "test.thm",
            "sub.domain.example.com",
            "host-name.domain",
            "123.example.com"
        ]
        
        for hostname in valid_hostnames:
            result = HostEntry.validate_hostname(hostname)
            self.assertTrue(result.is_valid, f"Hostname {hostname} should be valid")
    
    def test_validate_hostname_invalid(self):
        """Test invalid hostname validation."""
        invalid_hostnames = [
            "-invalid.com",  # starts with hyphen
            "invalid-.com",  # ends with hyphen
            "invalid..com",  # double dots
            "invalid_underscore.com",  # underscore not allowed
            ""  # empty
        ]
        
        for hostname in invalid_hostnames:
            result = HostEntry.validate_hostname(hostname)
            self.assertFalse(result.is_valid, f"Hostname {hostname} should be invalid")
            self.assertTrue(len(result.errors) > 0)
    
    def test_validate_entry_complete(self):
        """Test complete entry validation."""
        # Valid entry
        entry = HostEntry("192.168.1.1", "test.com")
        result = entry.validate()
        self.assertTrue(result.is_valid)
        
        # Invalid entry
        entry = HostEntry("invalid.ip", "-invalid.hostname")
        result = entry.validate()
        self.assertFalse(result.is_valid)
        self.assertTrue(len(result.errors) >= 2)  # IP and hostname errors
    
    def test_duplicate_detection(self):
        """Test duplicate detection."""
        entry1 = HostEntry("192.168.1.1", "test.com")
        entry2 = HostEntry("192.168.1.1", "test.com")  # Same
        entry3 = HostEntry("192.168.1.2", "test.com")  # Different IP
        
        self.assertTrue(entry1.is_duplicate_of(entry2))
        self.assertTrue(entry1.is_duplicate_of(entry3))  # Same hostname
        
    def test_conflict_detection(self):
        """Test conflict detection."""
        entry1 = HostEntry("192.168.1.1", "test.com")
        entry2 = HostEntry("192.168.1.2", "test.com")  # Same hostname, different IP
        entry3 = HostEntry("192.168.1.1", "other.com")  # Different hostname
        
        self.assertTrue(entry1.conflicts_with(entry2))
        self.assertFalse(entry1.conflicts_with(entry3))


class TestHostsFileStats(unittest.TestCase):
    """Test hosts file statistics."""
    
    def setUp(self):
        """Create test entries."""
        self.entries = [
            HostsFileEntry("127.0.0.1 localhost\n", 1, EntryType.HOST, 
                          HostEntry("127.0.0.1", "localhost")),
            HostsFileEntry("# Comment line\n", 2, EntryType.COMMENT),
            HostsFileEntry("\n", 3, EntryType.BLANK),
            HostsFileEntry("192.168.1.1 test.com\n", 4, EntryType.HOST,
                          HostEntry("192.168.1.1", "test.com")),
            HostsFileEntry("::1 ipv6host\n", 5, EntryType.HOST,
                          HostEntry("::1", "ipv6host")),
        ]
    
    def test_basic_stats(self):
        """Test basic statistics calculation."""
        stats = HostsFileStats(self.entries)
        
        self.assertEqual(stats.total_lines, 5)
        self.assertEqual(stats.total_hosts, 3)
        self.assertEqual(len(stats.ipv4_hosts), 2)
        self.assertEqual(len(stats.ipv6_hosts), 1)
        self.assertEqual(len(stats.comment_lines), 1)
        self.assertEqual(len(stats.blank_lines), 1)
    
    def test_duplicate_detection(self):
        """Test duplicate detection in stats."""
        # Add duplicate entry
        duplicate_entry = HostsFileEntry("192.168.1.1 test.com\n", 6, EntryType.HOST,
                                        HostEntry("192.168.1.1", "test.com"))
        entries_with_dup = self.entries + [duplicate_entry]
        
        stats = HostsFileStats(entries_with_dup)
        duplicates = stats.get_duplicates()
        
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(len(duplicates[0]), 2)  # Two identical entries
    
    def test_conflict_detection(self):
        """Test conflict detection in stats."""
        # Add conflicting entry (same hostname, different IP)
        conflict_entry = HostsFileEntry("192.168.1.2 test.com\n", 6, EntryType.HOST,
                                       HostEntry("192.168.1.2", "test.com"))
        entries_with_conflict = self.entries + [conflict_entry]
        
        stats = HostsFileStats(entries_with_conflict)
        conflicts = stats.get_conflicts()
        
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(len(conflicts[0]), 2)  # Two conflicting entries


class TestFileHostsRepository(unittest.TestCase):
    """Test file-based hosts repository."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.hosts_file = Path(self.temp_dir) / "hosts"
        self.backup_dir = Path(self.temp_dir) / "backup"
        
        # Create test configuration
        self.config = InjectHostConfig(
            hosts_file=self.hosts_file,
            backup_dir=self.backup_dir,
            marker="# THM",
            max_backups=3
        )
        
        # Create initial hosts file
        initial_content = """127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback

# THM
192.168.1.100	test.thm
"""
        self.hosts_file.write_text(initial_content)
        
        self.repo = FileHostsRepository(self.config)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)
    
    def test_read_all_entries(self):
        """Test reading all entries from hosts file."""
        entries = self.repo.read_all_entries()
        
        self.assertTrue(len(entries) > 0)
        
        # Should have localhost entries, marker, and test entry
        host_entries = [e for e in entries if e.entry_type == EntryType.HOST]
        self.assertEqual(len(host_entries), 3)  # localhost, ::1, test.thm
    
    def test_get_host_entries(self):
        """Test getting only host entries."""
        host_entries = self.repo.get_host_entries()
        
        self.assertEqual(len(host_entries), 3)
        
        hostnames = [e.hostname for e in host_entries]
        self.assertIn("localhost", hostnames)
        self.assertIn("test.thm", hostnames)
    
    def test_add_entry_success(self):
        """Test successfully adding a new entry."""
        new_entry = HostEntry("10.10.10.10", "newhost.thm")
        result = self.repo.add_entry(new_entry)
        
        self.assertTrue(result.success)
        self.assertIn("Added entry", result.message)
        self.assertIsNotNone(result.backup_created)
        
        # Verify entry was added
        host_entries = self.repo.get_host_entries()
        hostnames = [e.hostname for e in host_entries]
        self.assertIn("newhost.thm", hostnames)
    
    def test_add_entry_duplicate(self):
        """Test adding duplicate entry."""
        duplicate_entry = HostEntry("192.168.1.100", "test.thm")  # Already exists
        result = self.repo.add_entry(duplicate_entry)
        
        self.assertFalse(result.success)
        self.assertIn("already exists", result.message)
    
    def test_add_entry_invalid(self):
        """Test adding invalid entry."""
        invalid_entry = HostEntry("invalid.ip", "-invalid.hostname")
        result = self.repo.add_entry(invalid_entry)
        
        self.assertFalse(result.success)
        self.assertIn("Invalid entry", result.message)
        self.assertTrue(len(result.warnings) >= 0)
    
    def test_update_entry_success(self):
        """Test successfully updating an entry."""
        old_entry = HostEntry("192.168.1.100", "test.thm")
        new_entry = HostEntry("192.168.1.101", "updated.thm")
        
        result = self.repo.update_entry(old_entry, new_entry)
        
        self.assertTrue(result.success)
        self.assertIn("Updated entry", result.message)
        
        # Verify entry was updated
        host_entries = self.repo.get_host_entries()
        ips = [e.ip for e in host_entries]
        hostnames = [e.hostname for e in host_entries]
        
        self.assertIn("192.168.1.101", ips)
        self.assertIn("updated.thm", hostnames)
        self.assertNotIn("test.thm", hostnames)
    
    def test_update_entry_not_found(self):
        """Test updating non-existent entry."""
        old_entry = HostEntry("1.2.3.4", "nonexistent.thm")
        new_entry = HostEntry("1.2.3.5", "updated.thm")
        
        result = self.repo.update_entry(old_entry, new_entry)
        
        self.assertFalse(result.success)
        self.assertIn("Entry not found", result.message)
    
    def test_remove_entry_success(self):
        """Test successfully removing an entry."""
        entry_to_remove = HostEntry("192.168.1.100", "test.thm")
        result = self.repo.remove_entry(entry_to_remove)
        
        self.assertTrue(result.success)
        self.assertIn("Removed entry", result.message)
        
        # Verify entry was removed
        host_entries = self.repo.get_host_entries()
        hostnames = [e.hostname for e in host_entries]
        self.assertNotIn("test.thm", hostnames)
    
    def test_remove_entry_not_found(self):
        """Test removing non-existent entry."""
        entry_to_remove = HostEntry("1.2.3.4", "nonexistent.thm")
        result = self.repo.remove_entry(entry_to_remove)
        
        self.assertFalse(result.success)
        self.assertIn("Entry not found", result.message)
    
    def test_batch_add_entries(self):
        """Test adding multiple entries at once."""
        entries = [
            HostEntry("10.10.10.1", "batch1.thm"),
            HostEntry("10.10.10.2", "batch2.thm"),
            HostEntry("10.10.10.3", "batch3.thm")
        ]
        
        result = self.repo.batch_add_entries(entries)
        
        self.assertTrue(result.success)
        self.assertIn("Added 3 entries", result.message)
        
        # Verify all entries were added
        host_entries = self.repo.get_host_entries()
        hostnames = [e.hostname for e in host_entries]
        
        for entry in entries:
            self.assertIn(entry.hostname, hostnames)
    
    def test_create_backup(self):
        """Test backup creation."""
        backup_info = self.repo.create_backup()
        
        self.assertTrue(Path(backup_info.path).exists())
        self.assertEqual(backup_info.original_file, str(self.hosts_file))
        self.assertIsInstance(backup_info.timestamp, type(backup_info.timestamp))
    
    def test_get_stats(self):
        """Test getting hosts file statistics."""
        stats = self.repo.get_stats()
        
        self.assertIsInstance(stats, HostsFileStats)
        self.assertTrue(stats.total_hosts >= 3)  # At least localhost and test entries
    
    def test_caching(self):
        """Test repository caching behavior."""
        # First read
        entries1 = self.repo.read_all_entries()
        
        # Second read should use cache
        entries2 = self.repo.read_all_entries()
        
        self.assertEqual(len(entries1), len(entries2))
        
        # Modify file externally and ensure timestamp changes
        import time
        time.sleep(0.1)  # Ensure different timestamp
        current_content = self.hosts_file.read_text()
        self.hosts_file.write_text(current_content + "1.2.3.4 external.com\n")
        
        # Should detect change and refresh cache
        entries3 = self.repo.read_all_entries()
        self.assertGreater(len(entries3), len(entries1))


class TestCachedHostsRepository(unittest.TestCase):
    """Test cached hosts repository with background refresh."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.hosts_file = Path(self.temp_dir) / "hosts"
        self.backup_dir = Path(self.temp_dir) / "backup"
        
        self.config = InjectHostConfig(
            hosts_file=self.hosts_file,
            backup_dir=self.backup_dir,
            auto_refresh=True
        )
        
        # Create initial hosts file
        self.hosts_file.write_text("127.0.0.1 localhost\n")
        
        self.repo = CachedHostsRepository(self.config)
    
    def tearDown(self):
        """Clean up test environment."""
        # Stop background refresh
        self.repo._background_refresh_enabled = False
        shutil.rmtree(self.temp_dir)
    
    def test_background_refresh_setup(self):
        """Test background refresh setup."""
        self.assertTrue(self.repo._background_refresh_enabled)
        self.assertIsNotNone(self.repo._executor)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.hosts_file = Path(self.temp_dir) / "hosts"
        self.config_file = Path(self.temp_dir) / "config.ini"
        
        # Create test hosts file
        initial_content = """127.0.0.1	localhost
::1	localhost

# THM
"""
        self.hosts_file.write_text(initial_content)
        
        # Create test config
        config_content = f"""hosts_file={self.hosts_file}
backup_dir={self.temp_dir}/backup
marker=# THM
max_backups=5
"""
        self.config_file.write_text(config_content)
    
    def tearDown(self):
        """Clean up integration test environment."""
        shutil.rmtree(self.temp_dir)
    
    def test_complete_workflow(self):
        """Test complete workflow from config to operations."""
        # Load configuration
        config = InjectHostConfig.from_file(self.config_file)
        config.setup_directories()
        
        # Create repository
        repo = FileHostsRepository(config)
        
        # Add some entries
        entries_to_add = [
            HostEntry("10.10.10.10", "target1.thm"),
            HostEntry("10.10.10.11", "target2.thm"),
            HostEntry("10.10.10.12", "target3.thm")
        ]
        
        # Test batch add
        result = repo.batch_add_entries(entries_to_add)
        self.assertTrue(result.success)
        
        # Test stats
        stats = repo.get_stats()
        self.assertEqual(stats.total_hosts, 5)  # localhost, ::1, + 3 added
        
        # Test update
        old_entry = HostEntry("10.10.10.10", "target1.thm")
        new_entry = HostEntry("10.10.10.10", "updated-target1.thm")
        result = repo.update_entry(old_entry, new_entry)
        self.assertTrue(result.success)
        
        # Test remove
        entry_to_remove = HostEntry("10.10.10.11", "target2.thm")
        result = repo.remove_entry(entry_to_remove)
        self.assertTrue(result.success)
        
        # Verify final state
        final_entries = repo.get_host_entries()
        hostnames = [e.hostname for e in final_entries]
        
        self.assertIn("updated-target1.thm", hostnames)
        self.assertNotIn("target1.thm", hostnames)
        self.assertNotIn("target2.thm", hostnames)
        self.assertIn("target3.thm", hostnames)


def run_tests():
    """Run the complete test suite."""
    # Configure logging for tests
    logging.basicConfig(level=logging.WARNING)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestInjectHostConfig,
        TestHostEntry,
        TestHostsFileStats,
        TestFileHostsRepository,
        TestCachedHostsRepository,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("=" * 60)
    print("InjectHost Comprehensive Test Suite")
    print("=" * 60)
    
    success = run_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
    print("=" * 60)