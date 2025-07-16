#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
from pathlib import Path

INSTALL_DIR = "/usr/local/lib/injecthost"
BIN_PATH = "/usr/local/bin/injecthost"
GUI_BIN_PATH = "/usr/local/bin/injecthost-gui"
WRAPPER_SCRIPT = '''#!/bin/bash
cd /usr/local/lib/injecthost

# Try to find a Python installation with customtkinter
PYTHON_PATHS=("/usr/bin/python3" "/usr/bin/python3.11" "/usr/bin/python3.10" "/usr/bin/python3.9" "/usr/bin/python3.8")

for python_path in "${PYTHON_PATHS[@]}"; do
    if [ -f "$python_path" ] && "$python_path" -c "import customtkinter" 2>/dev/null; then
        exec "$python_path" injecthost.py "$@"
    fi
done

# If no Python with customtkinter found, try the default
exec /usr/bin/python3 injecthost.py "$@"
'''

GUI_WRAPPER_SCRIPT = '''#!/bin/bash
cd /usr/local/lib/injecthost

# Try to find a Python installation with customtkinter
PYTHON_PATHS=("/usr/bin/python3" "/usr/bin/python3.11" "/usr/bin/python3.10" "/usr/bin/python3.9" "/usr/bin/python3.8")

for python_path in "${PYTHON_PATHS[@]}"; do
    if [ -f "$python_path" ] && "$python_path" -c "import customtkinter" 2>/dev/null; then
        exec "$python_path" injecthost_gui.py "$@"
    fi
done

# If no Python with customtkinter found, show error
echo "Error: customtkinter not found. Please install it first:"
echo "  sudo pip3 install --break-system-packages customtkinter"
echo "  or"
echo "  sudo apt install python3-customtkinter"
exit 1
'''

REQUIRED_PYTHON = "/usr/bin/python3"
REQUIRED_MODULE = "customtkinter"


def check_root():
    if os.geteuid() != 0:
        print("[!] Please run as root (sudo python3 install.py)")
        sys.exit(1)

def check_python_module(python_path, module_name):
    """Check if a module is available in a specific Python installation."""
    try:
        result = subprocess.run([python_path, "-c", f"import {module_name}"], 
                              capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def find_python_with_module(module_name):
    """Find a Python installation that has the required module."""
    python_paths = [
        "/usr/bin/python3",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
        "/usr/bin/python3.9",
        "/usr/bin/python3.8"
    ]
    
    for python_path in python_paths:
        if os.path.exists(python_path) and check_python_module(python_path, module_name):
            return python_path
    return None

def install_dependencies():
    print("[+] Checking for customtkinter...")
    
    # First, try to find a Python installation that already has customtkinter
    python_with_module = find_python_with_module(REQUIRED_MODULE)
    if python_with_module:
        print(f"[+] customtkinter found in {python_with_module}")
        global REQUIRED_PYTHON
        REQUIRED_PYTHON = python_with_module
        return
    
    # Try to install via pip with different approaches
    print("[!] customtkinter not found. Attempting to install...")
    
    # Method 1: Try pip3 directly
    try:
        print("[+] Trying pip3 install customtkinter...")
        subprocess.run(["pip3", "install", "customtkinter"], check=True)
        print("[+] customtkinter installed via pip3.")
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 2: Try with --break-system-packages (not recommended but might work)
    try:
        print("[+] Trying pip install with --break-system-packages...")
        subprocess.run([REQUIRED_PYTHON, "-m", "pip", "install", "--break-system-packages", "customtkinter"], check=True)
        print("[+] customtkinter installed with --break-system-packages.")
        return
    except subprocess.CalledProcessError:
        pass
    
    # Method 3: Try apt install
    try:
        print("[+] Trying apt install python3-customtkinter...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "-y", "python3-customtkinter"], check=True)
        print("[+] customtkinter installed via apt.")
        return
    except subprocess.CalledProcessError:
        pass
    
    # If all methods fail, provide manual instructions
    print("\n[!] Automatic installation failed. Please install customtkinter manually:")
    print("\nOption 1 - Create a virtual environment:")
    print("  python3 -m venv ~/injecthost_env")
    print("  source ~/injecthost_env/bin/activate")
    print("  pip install customtkinter")
    print("  # Then modify the wrapper script to use the virtual environment Python")
    print("\nOption 2 - Use pipx (recommended):")
    print("  sudo apt install pipx")
    print("  pipx install customtkinter")
    print("\nOption 3 - Force install (use with caution):")
    print("  sudo pip3 install --break-system-packages customtkinter")
    print("\nOption 4 - Install via apt (if available):")
    print("  sudo apt update")
    print("  sudo apt install python3-customtkinter")
    print("\nAfter installing customtkinter, run this installer again.")
    sys.exit(1)

def copy_files():
    print(f"[+] Copying .py files to {INSTALL_DIR} ...")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    for fname in os.listdir('.'):
        if fname.endswith('.py'):
            shutil.copy2(fname, os.path.join(INSTALL_DIR, fname))
    print("[+] All Python files copied.")

def install_wrapper():
    print(f"[+] Installing CLI wrapper script to {BIN_PATH} ...")
    with open(BIN_PATH, 'w') as f:
        f.write(WRAPPER_SCRIPT)
    os.chmod(BIN_PATH, 0o755)
    print("[+] CLI wrapper script installed and made executable.")
    
    print(f"[+] Installing GUI wrapper script to {GUI_BIN_PATH} ...")
    with open(GUI_BIN_PATH, 'w') as f:
        f.write(GUI_WRAPPER_SCRIPT)
    os.chmod(GUI_BIN_PATH, 0o755)
    print("[+] GUI wrapper script installed and made executable.")

def main():
    check_root()
    install_dependencies()
    copy_files()
    install_wrapper()
    print("\n[✓] InjectHost installed!")
    print("\nYou can now run:")
    print("  injecthost      - CLI version")
    print("  injecthost-gui  - GUI version")
    print("\nTo uninstall, run:")
    print("  sudo rm -rf /usr/local/lib/injecthost /usr/local/bin/injecthost /usr/local/bin/injecthost-gui\n")
    print("If you installed customtkinter just for this tool and want to remove it:")
    print("  sudo pip3 uninstall customtkinter\n")

if __name__ == "__main__":
    main()
