#!/usr/bin/env python3
"""
Repository pattern implementation for hosts file operations.
Provides abstraction layer for data access with caching and validation.
"""

import os
import shutil
import tempfile
import fcntl
import time
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

from config import InjectHostConfig
from models import (
    HostEntry, HostsFileEntry, EntryType, ValidationResult, 
    OperationResult, BackupInfo, HostsFileStats
)


class HostsRepository(ABC):
    """Abstract repository interface for hosts file operations."""
    
    @abstractmethod
    def read_all_entries(self) -> List[HostsFileEntry]:
        """Read all entries from hosts file."""
        pass
    
    @abstractmethod
    def get_host_entries(self) -> List[HostEntry]:
        """Get only valid host entries."""
        pass
    
    @abstractmethod
    def add_entry(self, entry: HostEntry) -> OperationResult:
        """Add a new host entry."""
        pass
    
    @abstractmethod
    def update_entry(self, old_entry: HostEntry, new_entry: HostEntry) -> OperationResult:
        """Update an existing host entry."""
        pass
    
    @abstractmethod
    def remove_entry(self, entry: HostEntry) -> OperationResult:
        """Remove a host entry."""
        pass
    
    @abstractmethod
    def create_backup(self) -> BackupInfo:
        """Create a backup of the hosts file."""
        pass
    
    @abstractmethod
    def get_stats(self) -> HostsFileStats:
        """Get statistics about the hosts file."""
        pass


class FileHostsRepository(HostsRepository):
    """File-based implementation of hosts repository with caching and validation."""
    
    def __init__(self, config: InjectHostConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._cache: Optional[List[HostsFileEntry]] = None
        self._cache_timestamp: Optional[float] = None
        self._cache_lock = threading.RLock()
        self._file_lock = threading.RLock()
        
        # Ensure directories exist
        self.config.setup_directories()
    
    def _should_refresh_cache(self) -> bool:
        """Check if cache should be refreshed based on file modification time."""
        if self._cache is None or self._cache_timestamp is None:
            return True
        
        try:
            file_mtime = self.config.hosts_file.stat().st_mtime
            return file_mtime > self._cache_timestamp
        except (OSError, IOError):
            return True
    
    def _read_file_with_lock(self) -> List[str]:
        """Read hosts file with proper locking."""
        with self._file_lock:
            try:
                with open(self.config.hosts_file, 'r') as f:
                    # Apply file lock for reading
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    lines = f.readlines()
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                return lines
            except FileNotFoundError:
                self.logger.error(f"Hosts file not found: {self.config.hosts_file}")
                raise
            except PermissionError:
                self.logger.error(f"Permission denied reading: {self.config.hosts_file}")
                raise
            except Exception as e:
                self.logger.error(f"Unexpected error reading hosts file: {e}")
                raise
    
    def _write_file_atomically(self, content: str) -> str:
        """Write hosts file atomically with proper locking."""
        with self._file_lock:
            try:
                # Create backup first
                backup_path = self.create_backup().path
                
                # Write to temporary file in same directory
                with tempfile.NamedTemporaryFile(
                    mode='w', 
                    delete=False,
                    dir=self.config.hosts_file.parent,
                    prefix='.hosts_tmp_'
                ) as tmp:
                    # Apply exclusive lock
                    fcntl.flock(tmp.fileno(), fcntl.LOCK_EX)
                    tmp.write(content)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                    tmp_path = tmp.name
                
                # Atomic move
                os.rename(tmp_path, self.config.hosts_file)
                self.logger.info(f"Successfully updated hosts file, backup: {backup_path}")
                return backup_path
                
            except Exception as e:
                # Clean up temp file if it exists
                if 'tmp_path' in locals() and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                self.logger.error(f"Failed to write hosts file: {e}")
                raise
    
    def read_all_entries(self) -> List[HostsFileEntry]:
        """Read all entries from hosts file with caching."""
        with self._cache_lock:
            if not self._should_refresh_cache():
                return self._cache.copy()
            
            try:
                lines = self._read_file_with_lock()
                entries = []
                
                for line_num, line in enumerate(lines, 1):
                    entry = HostsFileEntry.from_line(line, line_num)
                    entries.append(entry)
                
                # Update cache
                self._cache = entries
                self._cache_timestamp = time.time()
                
                self.logger.debug(f"Loaded {len(entries)} entries from hosts file")
                return entries.copy()
                
            except Exception as e:
                self.logger.error(f"Failed to read hosts file: {e}")
                raise
    
    def get_host_entries(self) -> List[HostEntry]:
        """Get only valid host entries."""
        all_entries = self.read_all_entries()
        host_entries = []
        
        for entry in all_entries:
            if entry.entry_type == EntryType.HOST and entry.host_entry:
                host_entries.append(entry.host_entry)
        
        return host_entries
    
    def add_entry(self, entry: HostEntry) -> OperationResult:
        """Add a new host entry with validation and duplicate checking."""
        try:
            # Validate entry
            validation = entry.validate()
            if not validation.is_valid:
                return OperationResult(
                    success=False,
                    message=f"Invalid entry: {', '.join(validation.errors)}",
                    warnings=validation.warnings
                )
            
            # Check for duplicates
            existing_entries = self.get_host_entries()
            for existing in existing_entries:
                if existing.ip == entry.ip and existing.hostname == entry.hostname:
                    return OperationResult(
                        success=False,
                        message=f"Entry '{entry.ip} {entry.hostname}' already exists",
                        warnings=validation.warnings
                    )
            
            # Check for conflicts (same hostname, different IP)
            conflicts = [e for e in existing_entries if e.hostname == entry.hostname and e.ip != entry.ip]
            if conflicts and self.config.require_confirmation:
                return OperationResult(
                    success=False,
                    message=f"Hostname '{entry.hostname}' already exists with different IP: {conflicts[0].ip}",
                    warnings=validation.warnings
                )
            
            # Read current file and add entry
            all_entries = self.read_all_entries()
            
            # Find marker position or create it
            marker_found = False
            marker_line = -1
            
            for i, file_entry in enumerate(all_entries):
                if (file_entry.entry_type == EntryType.COMMENT and 
                    file_entry.content.strip() == self.config.marker):
                    marker_found = True
                    marker_line = i
                    break
            
            if not marker_found:
                # Add marker at end
                all_entries.append(HostsFileEntry(f"\n{self.config.marker}\n", len(all_entries) + 1, EntryType.COMMENT))
                marker_line = len(all_entries) - 1
            
            # Insert new entry after marker
            new_entry_line = HostsFileEntry(
                entry.to_line() + "\n", 
                marker_line + 2, 
                EntryType.HOST, 
                entry
            )
            all_entries.insert(marker_line + 1, new_entry_line)
            
            # Write back to file
            content = ''.join(e.content for e in all_entries)
            backup_path = self._write_file_atomically(content)
            
            # Invalidate cache
            self._invalidate_cache()
            
            return OperationResult(
                success=True,
                message=f"Added entry: {entry.ip} {entry.hostname}",
                backup_created=backup_path,
                entries_modified=[entry],
                warnings=validation.warnings
            )
            
        except Exception as e:
            self.logger.error(f"Failed to add entry {entry}: {e}")
            return OperationResult(
                success=False,
                message=f"Failed to add entry: {e}"
            )
    
    def update_entry(self, old_entry: HostEntry, new_entry: HostEntry) -> OperationResult:
        """Update an existing host entry."""
        try:
            # Validate new entry
            validation = new_entry.validate()
            if not validation.is_valid:
                return OperationResult(
                    success=False,
                    message=f"Invalid entry: {', '.join(validation.errors)}",
                    warnings=validation.warnings
                )
            
            # Read current file and find entry to update
            all_entries = self.read_all_entries()
            
            updated = False
            for i, file_entry in enumerate(all_entries):
                if (file_entry.entry_type == EntryType.HOST and 
                    file_entry.host_entry and
                    file_entry.host_entry.ip == old_entry.ip and
                    file_entry.host_entry.hostname == old_entry.hostname):
                    
                    # Replace with new entry
                    all_entries[i] = HostsFileEntry(
                        new_entry.to_line() + "\n",
                        file_entry.line_number,
                        EntryType.HOST,
                        new_entry
                    )
                    updated = True
                    break
            
            if not updated:
                return OperationResult(
                    success=False,
                    message=f"Entry not found: {old_entry.ip} {old_entry.hostname}"
                )
            
            # Write back to file
            content = ''.join(e.content for e in all_entries)
            backup_path = self._write_file_atomically(content)
            
            # Invalidate cache
            self._invalidate_cache()
            
            return OperationResult(
                success=True,
                message=f"Updated entry: {old_entry.ip} {old_entry.hostname} -> {new_entry.ip} {new_entry.hostname}",
                backup_created=backup_path,
                entries_modified=[new_entry],
                warnings=validation.warnings
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update entry {old_entry}: {e}")
            return OperationResult(
                success=False,
                message=f"Failed to update entry: {e}"
            )
    
    def remove_entry(self, entry: HostEntry) -> OperationResult:
        """Remove a host entry."""
        try:
            # Read current file and find entry to remove
            all_entries = self.read_all_entries()
            
            removed = False
            for i, file_entry in enumerate(all_entries):
                if (file_entry.entry_type == EntryType.HOST and 
                    file_entry.host_entry and
                    file_entry.host_entry.ip == entry.ip and
                    file_entry.host_entry.hostname == entry.hostname):
                    
                    # Remove entry
                    del all_entries[i]
                    removed = True
                    break
            
            if not removed:
                return OperationResult(
                    success=False,
                    message=f"Entry not found: {entry.ip} {entry.hostname}"
                )
            
            # Write back to file
            content = ''.join(e.content for e in all_entries)
            backup_path = self._write_file_atomically(content)
            
            # Invalidate cache
            self._invalidate_cache()
            
            return OperationResult(
                success=True,
                message=f"Removed entry: {entry.ip} {entry.hostname}",
                backup_created=backup_path,
                entries_modified=[entry]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to remove entry {entry}: {e}")
            return OperationResult(
                success=False,
                message=f"Failed to remove entry: {e}"
            )
    
    def batch_add_entries(self, entries: List[HostEntry]) -> OperationResult:
        """Add multiple entries in a single operation."""
        try:
            # Validate all entries first
            invalid_entries = []
            valid_entries = []
            all_warnings = []
            
            for entry in entries:
                validation = entry.validate()
                if validation.is_valid:
                    valid_entries.append(entry)
                    all_warnings.extend(validation.warnings)
                else:
                    invalid_entries.append((entry, validation.errors))
            
            if invalid_entries:
                error_msgs = [f"{entry.hostname}: {', '.join(errors)}" 
                             for entry, errors in invalid_entries]
                return OperationResult(
                    success=False,
                    message=f"Invalid entries: {'; '.join(error_msgs)}",
                    warnings=all_warnings
                )
            
            if not valid_entries:
                return OperationResult(
                    success=False,
                    message="No valid entries to add"
                )
            
            # Check for duplicates
            existing_entries = self.get_host_entries()
            duplicates = []
            
            for entry in valid_entries:
                for existing in existing_entries:
                    if existing.ip == entry.ip and existing.hostname == entry.hostname:
                        duplicates.append(entry)
                        break
            
            if duplicates:
                dup_msgs = [f"{e.ip} {e.hostname}" for e in duplicates]
                return OperationResult(
                    success=False,
                    message=f"Duplicate entries: {', '.join(dup_msgs)}",
                    warnings=all_warnings
                )
            
            # Add all valid entries
            all_entries = self.read_all_entries()
            
            # Find or create marker
            marker_found = False
            marker_line = -1
            
            for i, file_entry in enumerate(all_entries):
                if (file_entry.entry_type == EntryType.COMMENT and 
                    file_entry.content.strip() == self.config.marker):
                    marker_found = True
                    marker_line = i
                    break
            
            if not marker_found:
                all_entries.append(HostsFileEntry(f"\n{self.config.marker}\n", len(all_entries) + 1, EntryType.COMMENT))
                marker_line = len(all_entries) - 1
            
            # Insert all new entries after marker
            for j, entry in enumerate(valid_entries):
                new_entry_line = HostsFileEntry(
                    entry.to_line() + "\n",
                    marker_line + j + 2,
                    EntryType.HOST,
                    entry
                )
                all_entries.insert(marker_line + j + 1, new_entry_line)
            
            # Write back to file
            content = ''.join(e.content for e in all_entries)
            backup_path = self._write_file_atomically(content)
            
            # Invalidate cache
            self._invalidate_cache()
            
            return OperationResult(
                success=True,
                message=f"Added {len(valid_entries)} entries",
                backup_created=backup_path,
                entries_modified=valid_entries,
                warnings=all_warnings
            )
            
        except Exception as e:
            self.logger.error(f"Failed to batch add entries: {e}")
            return OperationResult(
                success=False,
                message=f"Failed to add entries: {e}"
            )
    
    def create_backup(self) -> BackupInfo:
        """Create a timestamped backup of the hosts file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"hosts_{timestamp}.bak"
        backup_path = self.config.backup_dir / backup_filename
        
        try:
            shutil.copy2(self.config.hosts_file, backup_path)
            
            # Clean up old backups if needed
            self._cleanup_old_backups()
            
            return BackupInfo.from_file(str(backup_path), str(self.config.hosts_file))
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            raise
    
    def get_stats(self) -> HostsFileStats:
        """Get statistics about the hosts file."""
        entries = self.read_all_entries()
        return HostsFileStats(entries)
    
    def _cleanup_old_backups(self):
        """Remove old backup files to keep only max_backups."""
        try:
            backup_files = list(self.config.backup_dir.glob("hosts_*.bak"))
            if len(backup_files) > self.config.max_backups:
                # Sort by modification time (oldest first)
                backup_files.sort(key=lambda x: x.stat().st_mtime)
                
                # Remove oldest files
                to_remove = backup_files[:-self.config.max_backups]
                for backup_file in to_remove:
                    backup_file.unlink()
                    self.logger.debug(f"Removed old backup: {backup_file}")
                    
        except Exception as e:
            self.logger.warning(f"Failed to cleanup old backups: {e}")
    
    def _invalidate_cache(self):
        """Invalidate the cache to force refresh on next read."""
        with self._cache_lock:
            self._cache = None
            self._cache_timestamp = None


class CachedHostsRepository(FileHostsRepository):
    """Extended repository with advanced caching and background refresh."""
    
    def __init__(self, config: InjectHostConfig):
        super().__init__(config)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hosts_repo")
        self._background_refresh_enabled = config.auto_refresh
    
    def start_background_refresh(self, interval: int = 30):
        """Start background cache refresh."""
        if self._background_refresh_enabled:
            self._executor.submit(self._background_refresh_loop, interval)
    
    def _background_refresh_loop(self, interval: int):
        """Background loop to refresh cache periodically."""
        import time as time_module
        
        while self._background_refresh_enabled:
            try:
                time_module.sleep(interval)
                if self._should_refresh_cache():
                    self.logger.debug("Background cache refresh")
                    self.read_all_entries()
            except Exception as e:
                self.logger.warning(f"Background refresh error: {e}")
    
    def __del__(self):
        """Cleanup executor on destruction."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)