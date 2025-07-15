#!/usr/bin/env python3
import os
import shutil

HOSTS_FILE = "/etc/hosts"
BACKUP_FILE = "/etc/hosts.bak"
MARKER = "# THM"

def backup_hosts():
    if not os.path.exists(BACKUP_FILE):
        shutil.copy2(HOSTS_FILE, BACKUP_FILE)
        print(f"Backup created at {BACKUP_FILE}")
    else:
        print(f"Backup already exists at {BACKUP_FILE}")

def read_hosts():
    with open(HOSTS_FILE, "r") as f:
        return f.readlines()

def write_hosts(lines):
    with open(HOSTS_FILE, "w") as f:
        f.writelines(lines)

def add_entry(ip, hostname):
    backup_hosts()
    lines = read_hosts()

    # Find marker line index
    try:
        marker_index = next(i for i, line in enumerate(lines) if line.strip() == MARKER)
    except StopIteration:
        # Marker not found, add it at the end
        lines.append(f"\n{MARKER}\n")
        marker_index = len(lines) - 1

    # Check if entry already exists below marker
    existing_entries = []
    i = marker_index + 1
    while i < len(lines) and lines[i].strip() != "" and not lines[i].startswith("#"):
        existing_entries.append(lines[i].strip())
        i += 1

    new_entry = f"{ip} {hostname}"
    if new_entry in existing_entries:
        print(f"Entry '{new_entry}' already exists under {MARKER}.")
        return

    # Insert new entry below marker
    lines.insert(marker_index + 1, new_entry + "\n")
    write_hosts(lines)
    print(f"Added entry: {new_entry}")

def main():
    print("Add entries to /etc/hosts under the # THM marker.")
    print("Enter 'exit' to quit.\n")

    while True:
        user_input = input("Enter IP and hostname (e.g. 10.10.10.10 whatever.thm): ").strip()
        if user_input.lower() == "exit":
            print("Exiting.")
            break

        parts = user_input.split()
        if len(parts) != 2:
            print("Invalid input. Please enter exactly two values: IP and hostname.")
            continue

        ip, hostname = parts
        add_entry(ip, hostname)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root (sudo).")
        exit(1)
    main()
