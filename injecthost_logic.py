# injecthost_logic.py
import os
import shutil

HOSTS_FILE = "/etc/hosts"
BACKUP_FILE = "/etc/hosts.bak"
MARKER = "# THM"

def backup_hosts():
    if not os.path.exists(BACKUP_FILE):
        shutil.copy2(HOSTS_FILE, BACKUP_FILE)
        return f"Backup created at {BACKUP_FILE}"
    else:
        return f"Backup already exists at {BACKUP_FILE}"

def read_hosts():
    with open(HOSTS_FILE, "r") as f:
        return f.readlines()

def write_hosts(lines):
    with open(HOSTS_FILE, "w") as f:
        f.writelines(lines)

def add_entry(ip, hostname):
    # This function will now return messages instead of printing them
    backup_msg = backup_hosts() # Call backup and get its message

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
    write_hosts(lines)
    return f"Added entry: {new_entry}\n{backup_msg}" # Combine messages

# You might also want a function to check root status for the GUI
def check_root_status():
    return os.geteuid() == 0
