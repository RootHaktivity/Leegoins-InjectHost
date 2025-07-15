# Host Editor (injecthost)

A powerful and user-friendly Python application for managing your `/etc/hosts` file. This tool provides both a command-line interface (CLI) and a graphical user interface (GUI) to easily add, remove, enable, disable, and manage host entries, with features like syntax highlighting, entry validation, dynamic search, and logging.

## ✨ Features

-   **CLI & GUI:** Choose your preferred way to interact with the hosts file.
-   **Safe Operations:** Automatically backs up your `/etc/hosts` file before any modifications.
-   **Entry Management:**
    -   Add new host entries (IP address, hostname, optional comments).
    -   Enable/disable existing entries.
    -   Remove entries.
-   **Validation:** Ensures correct IP address and hostname formats.
-   **Syntax Highlighting (GUI):** Improves readability of the hosts file content.
-   **Dynamic Search (GUI):** Quickly find specific entries.
-   **Action Logging (GUI):** Keeps a record of all changes made.
-   **Import/Export (GUI):** Easily manage host entries from external files.
-   **Passwordless Sudo Integration:** Seamlessly manage your hosts file without repeated password prompts (requires sudoers configuration).

## 🚀 Installation

This project requires Python 3 and `customtkinter`. The `install.py` script automates the setup process, including creating a virtual environment and setting up necessary permissions.

**Important:** The installation script requires `sudo` privileges to install the command-line tools and set up the GUI wrapper script in system paths.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
    cd YOUR_REPO_NAME
    ```

    *(Remember to replace `YOUR_USERNAME` and `YOUR_REPO_NAME` with your actual GitHub username and repository name.)*

2.  **Run the installation script:**

    ```bash
    sudo python3 install.py
    ```

    Follow the on-screen prompts to choose which components (CLI, GUI, or both) and installation type you prefer.

    -   **For GUI installation with passwordless sudo (recommended for convenience):**
        -   Choose option `2` (GUI only) or `3` (Both CLI and GUI).
        -   Choose installation type `3` (System-wide with sudoers + wrapper script).

3.  **Configure Sudoers for Passwordless GUI (if you chose option 3 above):**

    After the installation, the script will output an `IMPORTANT` message with a line to add to your `/etc/sudoers` file. This allows `injecthost-gui` to run with root privileges without prompting for a password.

    Open your sudoers file safely:

    ```bash
    sudo visudo
    ```

    Add the line provided by the `install.py` script. It will look something like this (replace `your_username` with your actual username, e.g., `kali`):

    ```
    your_username ALL=(ALL) NOPASSWD: /usr/local/bin/injecthost-gui
    ```

    Save and exit `visudo`.

## 💡 Usage

### Graphical User Interface (GUI)

To launch the GUI:

```bash
injecthost-gui


The GUI will open, allowing you to manage your hosts file visually. Any output or errors from the GUI will be logged to ~/injecthost-gui.log (in your home directory).

Command-Line Interface (CLI)

To use the CLI:

injecthost [command] [arguments]


Examples:

Add an entry:
injecthost add 192.168.1.10 mylocalmachine.com "My local dev server"

Disable an entry:
injecthost disable myoldserver.com

Enable an entry:
injecthost enable mylocalmachine.com

Remove an entry:
injecthost remove myoldserver.com

Show current hosts file content:
injecthost show

View help:
injecthost --help

🗑️ Uninstallation

To remove the Host Editor:

Run the uninstallation script:

sudo python3 uninstall.py


The script will attempt to remove the installed files and prompt you about removing the sudoers entry.

Manually remove Sudoers entry (if not auto-removed):

If you added a passwordless sudoers entry for injecthost-gui, it's good practice to remove it manually if the uninstall script doesn't.

sudo visudo


Delete the line you previously added:

your_username ALL=(ALL) NOPASSWD:  /usr/local/bin/injecthost-gui
your_username ALL=(ALL) NOPASSWD: /home/kali/.local/bin/

🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, bug reports, or want to add new features, please feel free to:

Fork the repository.
Create a new branch (git checkout -b feature/YourFeature).
Make your changes.
Commit your changes (git commit -m 'Add some feature').
Push to the branch (git push origin feature/YourFeature).
Open a Pull Request.
📄 License

This project is licensed under the MIT License.

Disclaimer: Modifying system files like /etc/hosts requires caution. Always ensure you understand the changes you are making. The author is not responsible for any system issues arising from improper use.


🎓 Learning Resources & Shout-Outs
If you’re new to cybersecurity or want to practice your skills in a safe, legal environment, check out platforms like TryHackMe, Hack The Box, and OverTheWire. These sites offer hands-on labs, challenges, and guided learning paths that are perfect for beginners and professionals alike.

They provide a great way to build your knowledge ethically and responsibly—just like this project encourages safe and authorized system management.
