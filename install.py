#!/usr/bin/env python3
import os
import sys
import shutil
import stat
import subprocess
import getpass
import pwd

CLI_SCRIPT = "injecthost.py"
CLI_CMD = "injecthost"

GUI_SCRIPT = "injecthost_gui.py"
GUI_CMD = "injecthost-gui"

SYSTEM_BIN = "/usr/local/bin"
VENV_DIR = os.path.expanduser("~/injecthost-venv")

def is_root():
    return os.geteuid() == 0

def make_executable(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def set_ownership(path, username):
    try:
        uid = pwd.getpwnam(username).pw_uid
        gid = pwd.getpwnam(username).pw_gid
        os.chown(path, uid, gid)
    except Exception as e:
        print(f"Warning: Could not change ownership of {path} to {username}: {e}")

def add_shebang_if_missing(path):
    try:
        with open(path, "r") as f:
            lines = f.readlines()
        if not lines or not lines[0].startswith("#!"):
            lines.insert(0, "#!/usr/bin/env python3\n")
            with open(path, "w") as f:
                f.writelines(lines)
            print(f"Added shebang line to {path}.")
    except Exception as e:
        print(f"Error reading or writing {path}: {e}")
        sys.exit(1)

def confirm_overwrite(path):
    if os.path.exists(path):
        resp = input(f"File {path} already exists. Overwrite? (y/n): ").strip().lower()
        return resp == 'y'
    return True

def copy_and_prepare(src_path, target_path):
    if not confirm_overwrite(target_path):
        print("Installation cancelled.")
        return False
    try:
        shutil.copy2(src_path, target_path)
        make_executable(target_path)
        print(f"Installed to {target_path}")
        return True
    except Exception as e:
        print(f"Error copying {src_path} to {target_path}: {e}")
        sys.exit(1)

def create_virtualenv():
    if not os.path.isdir(VENV_DIR):
        print(f"Creating virtual environment at {VENV_DIR}...")
        subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
    else:
        print(f"Virtual environment already exists at {VENV_DIR}")

def install_customtkinter():
    print("Installing/upgrading pip and customtkinter in virtual environment...")
    pip_path = os.path.join(VENV_DIR, "bin", "pip")
    subprocess.check_call([pip_path, "install", "--upgrade", "pip"])
    subprocess.check_call([pip_path, "install", "customtkinter"])

def create_wrapper_script():
    wrapper_path = os.path.join(SYSTEM_BIN, GUI_CMD)
    if not confirm_overwrite(wrapper_path):
        print("Installation cancelled.")
        return

    wrapper_content = f"""#!/bin/bash
VENV_PYTHON="{VENV_DIR}/bin/python"
SCRIPT_PATH="{os.path.abspath(GUI_SCRIPT)}"

nohup sudo -E "$VENV_PYTHON" "$SCRIPT_PATH" "$@" > /tmp/injecthost-gui.log 2>&1 &

echo "injecthost-gui started in background. Logs: /tmp/injecthost-gui.log"
"""
    try:
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)
        make_executable(wrapper_path)
        sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
        set_ownership(wrapper_path, sudo_user)
        print(f"Created detached wrapper script at {wrapper_path} with ownership set to {sudo_user}")
    except Exception as e:
        print(f"Error creating wrapper script: {e}")
        sys.exit(1)

def install_system_wide(script_name, cmd_name):
    target_path = os.path.join(SYSTEM_BIN, cmd_name)
    return copy_and_prepare(script_name, target_path)

def install_user_local(script_name, cmd_name):
    user_bin = os.path.expanduser("~/.local/bin")
    os.makedirs(user_bin, exist_ok=True)
    target_path = os.path.join(user_bin, cmd_name)
    return copy_and_prepare(script_name, target_path)

def install_with_sudoers(script_name, cmd_name):
    if not is_root():
        print("You need to run this script with sudo for this install option.")
        sys.exit(1)

    target_path = os.path.join(SYSTEM_BIN, cmd_name)
    if not copy_and_prepare(script_name, target_path):
        return

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        user_home = os.path.expanduser(f"~{sudo_user}")
        user_bin = os.path.join(user_home, ".local", "bin")
    else:
        user_home = os.path.expanduser("~")
        user_bin = os.path.join(user_home, ".local", "bin")
        sudo_user = getpass.getuser()

    os.makedirs(user_bin, exist_ok=True)
    wrapper_path = os.path.join(user_bin, cmd_name)

    if not confirm_overwrite(wrapper_path):
        print("Installation cancelled.")
        return

    wrapper_content = f"""#!/bin/bash
sudo {target_path} "$@"
"""
    try:
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)
        make_executable(wrapper_path)
        set_ownership(wrapper_path, sudo_user)
        print(f"Created wrapper script at {wrapper_path} with ownership set to {sudo_user}")
    except Exception as e:
        print(f"Error creating wrapper script: {e}")
        sys.exit(1)

    print("\nIMPORTANT:")
    print(f"To allow running '{cmd_name}' without typing a password, add this line to your sudoers file:")
    print(f"\n  {sudo_user} ALL=(ALL) NOPASSWD: {target_path}\n")
    print("Edit sudoers safely with: sudo visudo")
    print(f"After that, you can run the tool simply by typing:\n\n  {cmd_name}\n")

def main():
    # Check scripts exist
    missing = []
    for script in [CLI_SCRIPT, GUI_SCRIPT]:
        if not os.path.isfile(script):
            missing.append(script)
    if missing:
        print(f"Error: The following required script(s) are missing: {', '.join(missing)}")
        sys.exit(1)

    # Add shebang lines if missing
    add_shebang_if_missing(CLI_SCRIPT)
    add_shebang_if_missing(GUI_SCRIPT)

    print("Which component do you want to install?")
    print("1) CLI only")
    print("2) GUI only")
    print("3) Both CLI and GUI")
    choice = input("Enter choice (1, 2 or 3): ").strip()
    if choice not in {'1', '2', '3'}:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    print("\nChoose installation type:")
    print("1) System-wide (requires sudo/root)")
    print("2) Current user only (no sudo required)")
    print("3) System-wide with sudoers + wrapper script (passwordless sudo for this tool)")
    install_type = input("Enter choice (1, 2 or 3): ").strip()
    if install_type not in {'1', '2', '3'}:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    def install_component(script, cmd):
        if install_type == '1':
            if not is_root():
                print("You need to run this script with sudo for system-wide install.")
                sys.exit(1)
            install_system_wide(script, cmd)
        elif install_type == '2':
            install_user_local(script, cmd)
        elif install_type == '3':
            install_with_sudoers(script, cmd)

    if choice == '1':
        install_component(CLI_SCRIPT, CLI_CMD)
    elif choice == '2':
        # For GUI, create venv and wrapper script with detached run
        create_virtualenv()
        install_customtkinter()
        create_wrapper_script()
    else:
        install_component(CLI_SCRIPT, CLI_CMD)
        create_virtualenv()
        install_customtkinter()
        create_wrapper_script()

if __name__ == "__main__":
    main()
