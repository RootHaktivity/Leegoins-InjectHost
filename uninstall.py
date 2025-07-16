#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess

INSTALL_DIR = "/usr/local/lib/injecthost"
BIN_PATH = "/usr/local/bin/injecthost"
GUI_BIN_PATH = "/usr/local/bin/injecthost-gui"
REQUIRED_MODULE = "customtkinter"


def check_root():
    if os.geteuid() != 0:
        print("[!] Please run as root (sudo python3 uninstall.py)")
        sys.exit(1)

def remove_path(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
        print(f"[+] Removed directory: {path}")
    elif os.path.isfile(path):
        os.remove(path)
        print(f"[+] Removed file: {path}")
    else:
        print(f"[ ] Not found (already removed): {path}")

def uninstall_customtkinter():
    print("\nDo you want to uninstall the 'customtkinter' Python package as well? [y/N]: ", end='')
    try:
        resp = input().strip().lower()
    except EOFError:
        resp = 'n'
    if resp == 'y':
        subprocess.run(["pip3", "uninstall", "-y", REQUIRED_MODULE])
        print("[+] customtkinter uninstalled.")
    else:
        print("[ ] Skipped uninstalling customtkinter.")

def main():
    check_root()
    print("[+] Uninstalling InjectHost...")
    remove_path(INSTALL_DIR)
    remove_path(BIN_PATH)
    remove_path(GUI_BIN_PATH)
    print("\n[✓] InjectHost uninstalled.")
    uninstall_customtkinter()
    print("\nIf you added any sudoers entries for injecthost, you may want to remove them manually (sudo visudo).\n")
    print("[✓] Uninstallation complete.")

if __name__ == "__main__":
    main()
