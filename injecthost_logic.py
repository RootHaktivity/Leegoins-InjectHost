# injecthost_logic.py
import os
import shutil
import tempfile
import time

HOSTS_FILE = "/etc/hosts"
BACKUP_FILE = "/etc/hosts.bak"
MARKER = "# THM"

def backup_hosts():
    if not os.path.exists(BACKUP_FILE):
        shutil.copy2(HOSTS_FILE, BACKUP_FILE)
        return f"Backup created at {BACKUP_FILE}"
    else:
        return f"Backup already exists at {BACKUP_FILE}"

class HostsError(Exception):
    """Base exception for hosts file operations."""
    pass

def read_hosts():
    """Read hosts file with proper error handling."""
    try:
        with open(HOSTS_FILE, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        raise HostsError(f"Hosts file not found: {HOSTS_FILE}")
    except PermissionError:
        raise HostsError(f"Permission denied reading: {HOSTS_FILE}")
    except Exception as e:
        raise HostsError(f"Unexpected error reading hosts file: {e}")

def write_hosts(lines):
    """Write hosts file with proper error handling and atomic operations."""
    try:
        # Create timestamped backup first
        backup_path = f"{HOSTS_FILE}.bak.{int(time.time())}"
        shutil.copy2(HOSTS_FILE, backup_path)
        
        # Write atomically using temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, 
                                       dir=os.path.dirname(HOSTS_FILE)) as tmp:
            tmp.writelines(lines)
            tmp.flush()
            os.fsync(tmp.fileno())
        
        # Atomic move
        os.rename(tmp.name, HOSTS_FILE)
        return backup_path
        
    except PermissionError:
        raise HostsError(f"Permission denied writing: {HOSTS_FILE}")
    except Exception as e:
        # Clean up temp file if it exists
        if 'tmp' in locals() and os.path.exists(tmp.name):
            os.unlink(tmp.name)
        raise HostsError(f"Unexpected error writing hosts file: {e}")

def add_entry(ip, hostname):
    """Add entry to hosts file with improved error handling."""
    try:
        backup_msg = backup_hosts()
        lines = read_hosts()

        try:
            marker_index = next(i for i, line in enumerate(lines) if line.strip() == MARKER)
        except StopIteration:
            lines.append(f"\n{MARKER}\n")
            marker_index = len(lines) - 1

        existing_entries = []
        i = marker_index + 1
        while i < len(lines) and lines[i].strip() != "" and not lines[i].startswith("#"):
            existing_entries.append(lines[i].strip())
            i += 1

        new_entry = f"{ip} {hostname}"
        if new_entry in existing_entries:
            return f"Entry '{new_entry}' already exists under {MARKER}."

        lines.insert(marker_index + 1, new_entry + "\n")
        backup_path = write_hosts(lines)
        return f"Added entry: {new_entry}\nBackup created: {backup_path}"
        
    except HostsError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

# You might also want a function to check root status for the GUI
def check_root_status():
    return os.geteuid() == 0
