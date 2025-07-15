#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil

TARGET_NAME = "injecthost"
SYSTEM_BIN = "/usr/local/bin"
USER_BIN = os.path.expanduser("~/.local/bin")
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_BACKUP = "/etc/sudoers.bak"

def remove_file(path):
    if os.path.exists(path):
        try:
            os.remove(path)
            print(f"Removed: {path}")
        except PermissionError:
            print(f"Permission denied removing {path}. Try running with sudo.")
    else:
        print(f"File not found (skipped): {path}")

def check_sudoers_entry():
    try:
        with open(SUDOERS_FILE, "r") as f:
            lines = f.readlines()
        for line in lines:
            if TARGET_NAME in line and "NOPASSWD" in line:
                return True
        return False
    except Exception as e:
        print(f"Could not read sudoers file: {e}")
        return False

def backup_sudoers():
    try:
        shutil.copy2(SUDOERS_FILE, SUDOERS_BACKUP)
        print(f"Backup of sudoers file created at {SUDOERS_BACKUP}")
    except Exception as e:
        print(f"Failed to backup sudoers file: {e}")

def remove_sudoers_entry():
    try:
        with open(SUDOERS_FILE, "r") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not (TARGET_NAME in line and "NOPASSWD" in line)]
        backup_sudoers()
        with open(SUDOERS_FILE, "w") as f:
            f.writelines(new_lines)
        print("Removed sudoers entry for injecthost.")
    except Exception as e:
        print(f"Failed to modify sudoers file: {e}")

def prompt_sudoers_removal():
    if not check_sudoers_entry():
        print("No sudoers entry for injecthost found.")
        return

    print("\nSudoers entry for injecthost detected.")
    choice = input("Do you want to (e)dit sudoers manually or (a)uto-remove the entry? (e/a/skip): ").strip().lower()

    if choice == 'e':
        print("Opening sudoers file with visudo...")
        subprocess.run(["sudo", "visudo"])
    elif choice == 'a':
        print("Attempting to automatically remove the sudoers entry...")
        remove_sudoers_entry()
    else:
        print("Skipping sudoers modification. Remember to remove it manually if needed.")

def main():
    print("Uninstalling injecthost...")

    system_path = os.path.join(SYSTEM_BIN, TARGET_NAME)
    user_wrapper_path = os.path.join(USER_BIN, TARGET_NAME)

    # Remove system-wide script
    remove_file(system_path)

    # Remove user wrapper script
    remove_file(user_wrapper_path)

    # Handle sudoers entry
    prompt_sudoers_removal()

if __name__ == "__main__":
    main()
