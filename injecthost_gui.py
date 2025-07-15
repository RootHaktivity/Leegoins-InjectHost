#!/usr/bin/env python3
import customtkinter as ctk
import tkinter as tk
import sys
import re
import os
import ipaddress
import tempfile
import shutil
import time
from datetime import datetime

# Set appearance and color theme for consistent UI
ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
ctk.set_default_color_theme("dark-blue")  # Options: "blue", "dark-blue", "green"

try:
    from injecthost_logic import add_entry, check_root_status
    from custom_dialogs import (
        custom_showinfo, custom_showwarning, custom_showerror,
        custom_askyesno, custom_askyesnocancel,
        custom_askopenfilename, custom_asksaveasfilename
    )
except ImportError as e:
    root = tk.Tk()
    root.withdraw()
    # Fallback to standard messagebox for critical import errors
    from tkinter import messagebox
    messagebox.showerror("Error", f"Could not find required modules: {e}\nPlease ensure all files are in the same directory.")
    sys.exit(1)

LOG_DIR = os.path.expanduser("~/.injecthost")
LOG_FILE = os.path.join(LOG_DIR, "injecthost.log")

def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

def log_action(action, ip, hostname, old_entry=None):
    ensure_log_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        if action == "add":
            f.write(f"{timestamp} - ADD - IP: {ip}, Hostname: {hostname}\n")
        elif action == "update":
            f.write(f"{timestamp} - UPDATE - Old: {old_entry} -> New: {ip}\t{hostname}\n")
        elif action == "remove":
            f.write(f"{timestamp} - REMOVE - Entry: {old_entry}\n")
        elif action == "import":
            f.write(f"{timestamp} - IMPORT - {old_entry}\n")

# Custom dialog functions are now imported from custom_dialogs.py

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    label_pattern = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
    labels = hostname.split('.')
    for label in labels:
        if not label_pattern.match(label):
            return False
    return True

class InjectHostApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Leegion InjectHost GUI")
        self.geometry("600x720")
        self.resizable(False, False)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0,1,2,3,4,5,6,7,8,9,10), weight=1)

        self.root_status_label = ctk.CTkLabel(self, text="", text_color="red")
        self.root_status_label.grid(row=0, column=0, padx=20, pady=(10,5), sticky="ew")

        self.ip_label = ctk.CTkLabel(self, text="IP Address:")
        self.ip_label.grid(row=1, column=0, padx=20, pady=(5,2), sticky="w")
        self.ip_entry = ctk.CTkEntry(self, placeholder_text="e.g., 10.10.10.10")
        self.ip_entry.grid(row=1, column=0, padx=100, pady=(5,2), sticky="ew")
        self.ip_entry.bind("<Return>", self.add_or_update_entry)
        self.ip_entry.bind("<KP_Enter>", self.add_or_update_entry)
        self.ip_entry.bind("<KeyRelease>", self.on_input_change)

        self.hostname_label = ctk.CTkLabel(self, text="Hostname:")
        self.hostname_label.grid(row=2, column=0, padx=20, pady=(5,2), sticky="w")
        self.hostname_entry = ctk.CTkEntry(self, placeholder_text="e.g., whatever.thm")
        self.hostname_entry.grid(row=2, column=0, padx=100, pady=(5,2), sticky="ew")
        self.hostname_entry.bind("<Return>", self.add_or_update_entry)
        self.hostname_entry.bind("<KP_Enter>", self.add_or_update_entry)
        self.hostname_entry.bind("<KeyRelease>", self.on_input_change)

        self.add_button = ctk.CTkButton(self, text="Add Host Entry", command=self.add_or_update_entry)
        self.add_button.grid(row=3, column=0, padx=20, pady=(10,10), sticky="ew")

        self.hosts_label = ctk.CTkLabel(self, text="Current /etc/hosts entries:")
        self.hosts_label.grid(row=4, column=0, padx=20, pady=(5,0), sticky="w")

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_hosts_list)
        self.search_entry = ctk.CTkEntry(self, placeholder_text="Search entries...", textvariable=self.search_var)
        self.search_entry.grid(row=5, column=0, padx=20, pady=(5,10), sticky="ew")

        self.hosts_textbox = tk.Text(self, width=80, height=12, wrap="none")
        self.hosts_textbox.grid(row=6, column=0, padx=20, pady=(0,10), sticky="nsew")
        self.hosts_textbox.configure(bg="#1f1f1f", fg="white", insertbackground="white")
        self.hosts_textbox.bind("<ButtonRelease-1>", self.on_textbox_click)

        self.hosts_textbox.tag_configure("ip", foreground="#00ffff")
        self.hosts_textbox.tag_configure("hostname", foreground="#90ee90")
        self.hosts_textbox.tag_configure("comment", foreground="#888888")

        def disable_edit(event):
            return "break"

        for seq in ("<Key>", "<Control-v>", "<Control-V>", "<BackSpace>", "<Delete>", "<Button-2>", "<Button-3>"):
            self.hosts_textbox.bind(seq, disable_edit)

        # Frame for main action buttons
        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=7, column=0, padx=20, pady=(0,15), sticky="ew")
        button_frame.grid_columnconfigure((0,1), weight=1)

        self.remove_button = ctk.CTkButton(button_frame, text="Remove Entry", command=self.remove_selected_entry)
        self.remove_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.refresh_button = ctk.CTkButton(button_frame, text="Refresh", command=self.load_hosts_file)
        self.refresh_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Menu bar with File menu for Export, Import, View Log
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Hosts File", command=self.export_hosts_file)
        file_menu.add_command(label="Import Hosts File", command=self.import_hosts_file)
        file_menu.add_separator()
        file_menu.add_command(label="View Change Log", command=self.open_log_viewer)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about_dialog)

        self.all_hosts_lines = []
        self.editing_original_line = None
        self.unsaved_changes = False

        self.check_and_display_root_status()
        self.load_hosts_file()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_about_dialog(self):
        about_text = (
            "Leegion InjectHost GUI Tool\n"
            "Version: 1.0\n\n"
            "This tool helps manage your /etc/hosts file for ethical cybersecurity exercises.\n\n"
            "Usage Instructions:\n"
            "- Add or edit host entries by entering IP and hostname, then click 'Add Host Entry'.\n"
            "- Select entries to remove multiple at once.\n"
            "- Use search to filter entries.\n"
            "- Export and import hosts files for backup and sharing.\n"
            "- View change logs to audit modifications.\n\n"
            "Ethical Guidelines:\n"
            "- Use this tool responsibly and only on systems you own or have permission to modify.\n"
            "- Do not use this tool for malicious purposes.\n"
            "- Always backup your hosts file before making changes.\n\n"
            "Developed by Leegion.\n"
        )

        about_window = ctk.CTkToplevel(self)
        about_window.title("About Leegion InjectHost GUI")
        about_window.geometry("500x400")
        about_window.resizable(False, False)
        about_window.grab_set()

        text_box = ctk.CTkTextbox(about_window, wrap="word")
        text_box.pack(expand=True, fill="both", padx=10, pady=10)
        text_box.insert("0.0", about_text)
        text_box.configure(state="disabled")

        ok_button = ctk.CTkButton(about_window, text="OK", command=about_window.destroy)
        ok_button.pack(pady=(0, 10))

    def on_input_change(self, event=None):
        self.unsaved_changes = True

    def on_close(self):
        if self.unsaved_changes:
            confirm = custom_askyesno(self, "Unsaved Changes",
                                      "You have unsaved changes. Are you sure you want to exit and lose them?")
            if not confirm:
                return  # Cancel close
        self.destroy()

    def check_and_display_root_status(self):
        if not check_root_status():
            self.root_status_label.configure(text="⚠️ Not running as root. Host file modification will fail.", text_color="red")
            self.add_button.configure(state="disabled")
            self.remove_button.configure(state="disabled")
            custom_showwarning(self, "Permission Warning", "This application needs to be run with root privileges (sudo) to modify the hosts file. Please run 'sudo python3 injecthost_gui.py'.")
        else:
            self.root_status_label.configure(text="Running as root. Proceed with caution.", text_color="green")
            self.add_button.configure(state="normal")
            self.remove_button.configure(state="normal")

    def add_or_update_entry(self, event=None):
        ip = self.ip_entry.get().strip()
        hostname = self.hostname_entry.get().strip()

        if not ip or not hostname:
            custom_showwarning(self, "Input Error", "Both IP address and hostname are required.")
            return

        if not self.is_valid_ip(ip):
            custom_showwarning(self, "Input Error", "Invalid IP address format.")
            return

        if not is_valid_hostname(hostname):
            custom_showwarning(self, "Input Error", "Invalid hostname format.\n"
                "Hostnames may contain letters, digits, hyphens, and dots.\n"
                "Labels cannot start or end with a hyphen.\n"
                "Max length is 255 characters.")
            return

        new_line = f"{ip}\t{hostname}"

        try:
            if self.editing_original_line:
                self.update_entry(self.editing_original_line, new_line)
                log_action("update", ip, hostname, old_entry=self.editing_original_line)
                custom_showinfo(self, "Success", "Host entry updated successfully.")
                self.editing_original_line = None
                self.add_button.configure(text="Add Host Entry")
            else:
                result_message = add_entry(ip, hostname)
                log_action("add", ip, hostname)
                custom_showinfo(self, "Success", result_message)

            self.ip_entry.delete(0, ctk.END)
            self.hostname_entry.delete(0, ctk.END)
            self.unsaved_changes = False  # Reset flag on successful save
            self.load_hosts_file()
        except Exception as e:
            custom_showerror(self, "Error", f"An error occurred: {e}")

    def update_entry(self, old_line, new_line):
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()

        backup_path = "/etc/hosts.bak"
        with open(backup_path, "w") as backup_file:
            backup_file.writelines(lines)

        new_lines = []
        replaced = False
        for line in lines:
            if line.strip() == old_line and not replaced:
                new_lines.append(new_line + "\n")
                replaced = True
            else:
                new_lines.append(line)

        with open("/etc/hosts", "w") as f:
            f.writelines(new_lines)

    def on_textbox_click(self, event):
        index = self.hosts_textbox.index(f"@{event.x},{event.y}")
        line_num = int(index.split(".")[0])
        line_text = self.hosts_textbox.get(f"{line_num}.0", f"{line_num}.end").strip()
        if line_text and not line_text.startswith("#"):
            parts = re.split(r'\s+', line_text)
            if len(parts) >= 2:
                ip = parts[0]
                hostname = parts[1]
                self.ip_entry.delete(0, ctk.END)
                self.ip_entry.insert(0, ip)
                self.hostname_entry.delete(0, ctk.END)
                self.hostname_entry.insert(0, hostname)
                self.editing_original_line = line_text
                self.add_button.configure(text="Update Entry")
            else:
                self.clear_editing_state()
        else:
            self.clear_editing_state()

    def clear_editing_state(self):
        self.editing_original_line = None
        self.add_button.configure(text="Add Host Entry")
        self.ip_entry.delete(0, ctk.END)
        self.hostname_entry.delete(0, ctk.END)

    def is_valid_ip(self, ip_str):
        """Validate IPv4 and IPv6 addresses using the ipaddress module."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def load_hosts_file(self):
        """Load hosts file with better error recovery."""
        try:
            with open("/etc/hosts", "r") as f:
                lines = f.readlines()
            self.all_hosts_lines = [line.rstrip("\n") for line in lines if line.strip()]
            self.filter_hosts_list()
            self.clear_editing_state()
            
        except PermissionError:
            custom_showerror(self, "Permission Error", 
                           "Permission denied reading /etc/hosts.\n"
                           "Please run this application with sudo.")
            self.set_readonly_mode()
        except FileNotFoundError:
            custom_showerror(self, "File Not Found", 
                           "/etc/hosts file not found.\n"
                           "This is unusual - the hosts file should always exist.")
            self.offer_recovery_options()
        except Exception as e:
            custom_showerror(self, "Error", f"Unexpected error reading /etc/hosts:\n{e}")
            self.offer_recovery_options()

    def set_readonly_mode(self):
        """Set the application to read-only mode when hosts file can't be accessed."""
        self.add_button.configure(state="disabled", text="Read-Only Mode")
        self.remove_button.configure(state="disabled")
        self.root_status_label.configure(
            text="⚠️ Running in read-only mode due to file access issues", 
            text_color="orange"
        )

    def offer_recovery_options(self):
        """Offer recovery options when hosts file can't be read."""
        result = custom_askyesnocancel(
            self,
            "Recovery Options",
            "Unable to read the hosts file. Would you like to:\n\n"
            "Yes - Continue in read-only mode\n"
            "No - Exit application\n"
            "Cancel - Retry reading the file"
        )
        if result is True:
            self.set_readonly_mode()
        elif result is False:
            self.quit()
        else:
            # Retry
            self.load_hosts_file()

    def filter_hosts_list(self, *args):
        search_text = self.search_var.get().lower()
        filtered_lines = [line for line in self.all_hosts_lines if search_text in line.lower()]
        self.update_hosts_textbox(filtered_lines)

    def update_hosts_textbox(self, lines):
        self.hosts_textbox.configure(state="normal")
        self.hosts_textbox.delete("0.0", tk.END)

        for line in lines:
            if line.startswith("#"):
                self.hosts_textbox.insert(tk.END, line + "\n", "comment")
            else:
                parts = re.split(r'\s+', line, maxsplit=1)
                if len(parts) == 2:
                    ip, hostname = parts
                    self.hosts_textbox.insert(tk.END, ip, "ip")
                    self.hosts_textbox.insert(tk.END, " ")
                    self.hosts_textbox.insert(tk.END, hostname + "\n", "hostname")
                else:
                    self.hosts_textbox.insert(tk.END, line + "\n")

        self.hosts_textbox.configure(state="normal")  # Keep enabled for selection

    def remove_selected_entry(self):
        if not self.editing_original_line:
            custom_showwarning(self, "No Selection", "Please select an entry by clicking it in the list to remove.")
            return

        confirm = custom_askyesno(self, "Confirm Removal", f"Are you sure you want to remove the selected entry?\n{self.editing_original_line}")
        if not confirm:
            return

        try:
            with open("/etc/hosts", "r") as f:
                lines = f.readlines()

            new_lines = [line for line in lines if line.strip() != self.editing_original_line]

            backup_path = "/etc/hosts.bak"
            with open(backup_path, "w") as backup_file:
                backup_file.writelines(lines)

            with open("/etc/hosts", "w") as f:
                f.writelines(new_lines)

            log_action("remove", None, None, old_entry=self.editing_original_line)

            custom_showinfo(self, "Success", f"Removed entry. Backup saved to {backup_path}.")
            self.load_hosts_file()
            self.clear_editing_state()
        except Exception as e:
            custom_showerror(self, "Error", f"Failed to remove entry:\n{e}")

    def open_log_viewer(self):
        if not os.path.exists(LOG_FILE):
            custom_showinfo(self, "Log Viewer", "No log file found yet.")
            return

        log_window = ctk.CTkToplevel(self)
        log_window.title("InjectHost Change Log")
        log_window.geometry("600x400")

        text_area = ctk.CTkTextbox(log_window, wrap="none")
        text_area.pack(fill="both", expand=True, padx=10, pady=10)

        with open(LOG_FILE, "r") as f:
            content = f.read()
        text_area.insert("0.0", content)
        text_area.configure(state="disabled")  # Read-only

    def export_hosts_file(self):
        file_path = custom_asksaveasfilename(
            self,
            title="Export Hosts File",
            defaultextension=".hosts",
            filetypes=[("Hosts files", "*.hosts"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "w") as f:
                for line in self.all_hosts_lines:
                    f.write(line + "\n")
            custom_showinfo(self, "Export Successful", f"Hosts file exported to:\n{file_path}")
        except Exception as e:
            custom_showerror(self, "Export Failed", f"Failed to export hosts file:\n{e}")

    def import_hosts_file(self):
        file_path = custom_askopenfilename(
            self,
            title="Import Hosts File",
            filetypes=[("Hosts files", "*.hosts"), ("All files", "*.*")]
        )
        if not file_path:
            return

        confirm = custom_askyesno(self, "Confirm Import",
            f"Importing will replace your current /etc/hosts file.\n"
            f"Are you sure you want to continue?")
        if not confirm:
            return

        try:
            with open(file_path, "r") as f:
                imported_lines = [line.rstrip("\n") for line in f.readlines()]

            with open("/etc/hosts", "r") as f:
                current_lines = f.readlines()
            backup_path = "/etc/hosts.bak"
            with open(backup_path, "w") as backup_file:
                backup_file.writelines(current_lines)

            with open("/etc/hosts", "w") as f:
                for line in imported_lines:
                    f.write(line + "\n")

            log_action("import", None, None, old_entry=f"Imported from {file_path}")
            custom_showinfo(self, "Import Successful", f"Hosts file imported from:\n{file_path}\nBackup saved to {backup_path}")
            self.load_hosts_file()
        except Exception as e:
            custom_showerror(self, "Import Failed", f"Failed to import hosts file:\n{e}")

if __name__ == "__main__":
    try:
        app = InjectHostApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\nGUI interrupted by user. Exiting gracefully.")
        sys.exit(0)
