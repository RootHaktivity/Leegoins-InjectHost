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

        self.title("🌐 Leegion InjectHost GUI")
        self.geometry("1200x800")
        self.resizable(True, True)

        # Configure grid weights for responsive layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Title and status
        title_frame = ctk.CTkFrame(self)
        title_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="ew")
        
        title_label = ctk.CTkLabel(title_frame, text="🌐 InjectHost Manager", font=("Arial", 18, "bold"))
        title_label.pack(pady=(15, 5))
        
        subtitle_label = ctk.CTkLabel(title_frame, text="Manage your /etc/hosts file with ease", 
                                     font=("Arial", 12), text_color="gray")
        subtitle_label.pack(pady=(0, 15))

        self.root_status_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 10))
        self.root_status_label.grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 10), sticky="ew")

        # Left column - Input and Actions
        left_frame = ctk.CTkFrame(self)
        left_frame.grid(row=2, column=0, padx=(20, 10), pady=10, sticky="nsew")
        left_frame.grid_columnconfigure(0, weight=1)

        # Add/Edit Section
        add_section = ctk.CTkFrame(left_frame)
        add_section.pack(fill="x", padx=10, pady=(10, 5))
        
        add_title = ctk.CTkLabel(add_section, text="➕ Add/Edit Host Entry", font=("Arial", 14, "bold"))
        add_title.pack(pady=(15, 10))
        
        # IP Address input
        ip_frame = ctk.CTkFrame(add_section)
        ip_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(ip_frame, text="IP Address:", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        self.ip_entry = ctk.CTkEntry(ip_frame, placeholder_text="e.g., 192.168.1.100", height=35)
        self.ip_entry.pack(fill="x", padx=10, pady=(0, 10))
        self.ip_entry.bind("<Return>", self.add_or_update_entry)
        self.ip_entry.bind("<KP_Enter>", self.add_or_update_entry)
        self.ip_entry.bind("<KeyRelease>", self.on_input_change)

        # Hostname input
        hostname_frame = ctk.CTkFrame(add_section)
        hostname_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(hostname_frame, text="Hostname:", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        self.hostname_entry = ctk.CTkEntry(hostname_frame, placeholder_text="e.g., myserver.local", height=35)
        self.hostname_entry.pack(fill="x", padx=10, pady=(0, 10))
        self.hostname_entry.bind("<Return>", self.add_or_update_entry)
        self.hostname_entry.bind("<KP_Enter>", self.add_or_update_entry)
        self.hostname_entry.bind("<KeyRelease>", self.on_input_change)

        # Action buttons
        button_frame = ctk.CTkFrame(add_section)
        button_frame.pack(fill="x", padx=15, pady=(0, 15))
        button_frame.grid_columnconfigure((0, 1), weight=1)
        
        self.add_button = ctk.CTkButton(button_frame, text="➕ Add Entry", command=self.add_or_update_entry, 
                                       height=45, font=("Arial", 13, "bold"), fg_color="#28a745", hover_color="#218838")
        self.add_button.grid(row=0, column=0, padx=(0, 8), pady=12, sticky="ew")
        
        self.remove_button = ctk.CTkButton(button_frame, text="🗑️ Remove Selected", command=self.remove_selected_entry, 
                                          height=45, font=("Arial", 13), fg_color="#dc3545", hover_color="#c82333")
        self.remove_button.grid(row=0, column=1, padx=(8, 0), pady=12, sticky="ew")

        # Quick Actions Section
        actions_section = ctk.CTkFrame(left_frame)
        actions_section.pack(fill="x", padx=10, pady=5)
        
        actions_title = ctk.CTkLabel(actions_section, text="⚡ Quick Actions", font=("Arial", 14, "bold"))
        actions_title.pack(pady=(15, 10))
        
        # Search and refresh
        search_frame = ctk.CTkFrame(actions_section)
        search_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(search_frame, text="Search Entries:", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_hosts_list)
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Type to search...", textvariable=self.search_var, height=35)
        self.search_entry.pack(fill="x", padx=10, pady=(0, 10))

        # Action buttons
        action_buttons_frame = ctk.CTkFrame(actions_section)
        action_buttons_frame.pack(fill="x", padx=15, pady=(0, 15))
        action_buttons_frame.grid_columnconfigure((0, 1), weight=1)
        
        self.refresh_button = ctk.CTkButton(action_buttons_frame, text="🔄 Refresh", command=self.force_refresh_display, 
                                           height=40, font=("Arial", 12), fg_color="#17a2b8", hover_color="#138496")
        self.refresh_button.grid(row=0, column=0, padx=(0, 8), pady=12, sticky="ew")
        
        clear_search_button = ctk.CTkButton(action_buttons_frame, text="🧹 Clear Search", 
                                           command=lambda: self.search_var.set(""), height=40, font=("Arial", 12), fg_color="#6c757d", hover_color="#5a6268")
        clear_search_button.grid(row=0, column=1, padx=(8, 0), pady=12, sticky="ew")

        # Right column - Hosts Display
        right_frame = ctk.CTkFrame(self)
        right_frame.grid(row=2, column=1, padx=(10, 20), pady=10, sticky="nsew")
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)

        # Hosts display title
        hosts_title = ctk.CTkLabel(right_frame, text="📋 Current Host Entries", font=("Arial", 14, "bold"))
        hosts_title.grid(row=0, column=0, pady=(15, 10), sticky="w", padx=15)

        # Hosts textbox with scrollbar
        text_frame = ctk.CTkFrame(right_frame)
        text_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        text_frame.grid_columnconfigure(0, weight=1)
        text_frame.grid_rowconfigure(0, weight=1)

        self.hosts_textbox = tk.Text(text_frame, wrap="none", font=("Consolas", 10), 
                                    bg="#1f1f1f", fg="white", insertbackground="white")
        self.hosts_textbox.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.hosts_textbox.bind("<ButtonRelease-1>", self.on_textbox_click)

        # Scrollbar for textbox
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=self.hosts_textbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.hosts_textbox.configure(yscrollcommand=scrollbar.set)

        # Configure text tags for syntax highlighting
        self.hosts_textbox.tag_configure("ip", foreground="#00ffff")
        self.hosts_textbox.tag_configure("hostname", foreground="#90ee90")
        self.hosts_textbox.tag_configure("comment", foreground="#888888")

        # Disable editing in textbox
        def disable_edit(event):
            return "break"

        for seq in ("<Key>", "<Control-v>", "<Control-V>", "<BackSpace>", "<Delete>", "<Button-2>", "<Button-3>"):
            self.hosts_textbox.bind(seq, disable_edit)

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

        # Add Network Tools menu
        network_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Network Tools", menu=network_menu)
        network_menu.add_command(label="Open Network Tools", command=self.open_network_tools_window)
        
        # Add Configuration Management menu
        config_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Configurations", menu=config_menu)
        config_menu.add_command(label="Configuration Manager", command=self.open_config_manager)
        config_menu.add_separator()
        config_menu.add_command(label="Save Current as Config", command=self.save_current_config)
        config_menu.add_command(label="Quick Apply Config", command=self.quick_apply_config)
        
        # Add Validation & Linting menu
        validation_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Validation", menu=validation_menu)
        validation_menu.add_command(label="Validate & Lint", command=self.open_validation_window)
        validation_menu.add_command(label="Format Hosts File", command=self.format_hosts_file)

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
            
            # Force immediate refresh with multiple update calls
            self.force_refresh_display()
            self.update()
            self.update_idletasks()
        except Exception as e:
            custom_showerror(self, "Error", f"An error occurred: {e}")

    def update_entry(self, old_line, new_line):
        # Parse the old and new lines to get IP and hostname
        old_parts = re.split(r'\s+', old_line.strip())
        new_parts = re.split(r'\s+', new_line.strip())
        
        if len(old_parts) >= 2 and len(new_parts) >= 2:
            old_ip = old_parts[0]
            old_hostname = old_parts[1]
            new_ip = new_parts[0]
            new_hostname = new_parts[1]
            
            # Use the proper logic layer to update the entry
            from injecthost_logic import update_entry
            result_message = update_entry(old_ip, old_hostname, new_ip, new_hostname)
            
            if "Failed" in result_message:
                raise Exception(result_message)
        else:
            raise Exception("Invalid entry format. Cannot parse IP and hostname.")

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
            # Clear any cached data first
            self.all_hosts_lines = []
            
            with open("/etc/hosts", "r") as f:
                lines = f.readlines()
            # Preserve all lines including empty ones for display
            self.all_hosts_lines = [line.rstrip("\n") for line in lines]
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
        
        # Force the textbox to update and redraw
        self.hosts_textbox.see("1.0")  # Scroll to top
        self.hosts_textbox.update_idletasks()

    def force_refresh_display(self):
        """Force refresh the display to show current hosts file content."""
        # Show refreshing indicator
        original_text = self.refresh_button.cget("text")
        self.refresh_button.configure(text="Refreshing...")
        self.update()  # Ensure GUI is updated
        
        # Force a small delay to ensure file system sync
        self.after(100, self._complete_refresh)
        
    def _complete_refresh(self):
        """Complete the refresh operation after a small delay."""
        try:
            self.load_hosts_file()
            self.update_idletasks()  # Force GUI update
        except Exception as e:
            print(f"Refresh error: {e}")
        finally:
            # Restore button text
            self.refresh_button.configure(text="Refresh")

    def remove_selected_entry(self):
        if not self.editing_original_line:
            try:
                custom_showwarning(self, "No Selection", "Please select an entry by clicking it in the list to remove.")
            except:
                # Fallback to standard messagebox
                from tkinter import messagebox
                messagebox.showwarning("No Selection", "Please select an entry by clicking it in the list to remove.")
            return

        try:
            confirm = custom_askyesno(self, "Confirm Removal", f"Are you sure you want to remove the selected entry?\n{self.editing_original_line}")
        except:
            # Fallback to standard messagebox
            from tkinter import messagebox
            confirm = messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove the selected entry?\n{self.editing_original_line}")
        
        if not confirm:
            return

        try:
            # Parse the selected line to get IP and hostname
            parts = re.split(r'\s+', self.editing_original_line.strip())
            if len(parts) >= 2:
                ip = parts[0]
                hostname = parts[1]
                
                # Use the proper logic layer to remove the entry
                from injecthost_logic import remove_entry
                result_message = remove_entry(ip, hostname)
                
                log_action("remove", ip, hostname, old_entry=self.editing_original_line)

                try:
                    custom_showinfo(self, "Success", result_message)
                except:
                    # Fallback to standard messagebox
                    from tkinter import messagebox
                    messagebox.showinfo("Success", result_message)
                
                self.force_refresh_display()
                self.update()
                self.update_idletasks()
                self.clear_editing_state()
            else:
                custom_showerror(self, "Error", "Invalid entry format. Cannot parse IP and hostname.")
        except Exception as e:
            try:
                custom_showerror(self, "Error", f"Failed to remove entry:\n{e}")
            except:
                # Fallback to standard messagebox
                from tkinter import messagebox
                messagebox.showerror("Error", f"Failed to remove entry:\n{e}")

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

    def open_network_tools_window(self):
        import threading
        import queue
        from network_utils import flush_dns_cache, test_hostname, ping_hostname, NetworkUtils

        window = ctk.CTkToplevel(self)
        window.title("Network Tools")
        window.geometry("700x600")
        window.resizable(True, True)
        window.grab_set()

        # Configure grid weights
        window.grid_columnconfigure(0, weight=1)
        window.grid_columnconfigure(1, weight=1)
        window.grid_rowconfigure(3, weight=1)

        # Title
        title_label = ctk.CTkLabel(window, text="🌐 Network Tools", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

        # Left column - Controls
        left_frame = ctk.CTkFrame(window)
        left_frame.grid(row=1, column=0, padx=(20, 10), pady=10, sticky="nsew")
        left_frame.grid_columnconfigure(0, weight=1)

        # Host Testing Section
        host_section = ctk.CTkFrame(left_frame)
        host_section.pack(fill="x", padx=10, pady=(10, 5))
        
        host_title = ctk.CTkLabel(host_section, text="🔍 Host Testing", font=("Arial", 12, "bold"))
        host_title.pack(pady=(10, 5))
        
        host_input_frame = ctk.CTkFrame(host_section)
        host_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(host_input_frame, text="Hostname:").pack(anchor="w", padx=10, pady=(10, 5))
        host_entry = ctk.CTkEntry(host_input_frame, placeholder_text="e.g., google.com")
        host_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        test_button = ctk.CTkButton(host_input_frame, text="Test Connectivity", 
                                   command=lambda: test_selected_host(), height=35)
        test_button.pack(fill="x", padx=10, pady=(0, 10))

        # DNS Cache Section
        dns_section = ctk.CTkFrame(left_frame)
        dns_section.pack(fill="x", padx=10, pady=5)
        
        dns_title = ctk.CTkLabel(dns_section, text="🔄 DNS Cache", font=("Arial", 12, "bold"))
        dns_title.pack(pady=(10, 5))
        
        dns_desc = ctk.CTkLabel(dns_section, text="Flush DNS cache for immediate effect", 
                               font=("Arial", 10), text_color="gray")
        dns_desc.pack(pady=(0, 10))
        
        flush_button = ctk.CTkButton(dns_section, text="Flush DNS Cache", 
                                    command=lambda: flush_dns(), height=35)
        flush_button.pack(fill="x", padx=10, pady=(0, 10))

        # Network Scan Section
        scan_section = ctk.CTkFrame(left_frame)
        scan_section.pack(fill="x", padx=10, pady=5)
        
        scan_title = ctk.CTkLabel(scan_section, text="📡 Network Scanner", font=("Arial", 12, "bold"))
        scan_title.pack(pady=(10, 5))
        
        scan_input_frame = ctk.CTkFrame(scan_section)
        scan_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(scan_input_frame, text="Base IP Address:").pack(anchor="w", padx=10, pady=(10, 5))
        scan_entry = ctk.CTkEntry(scan_input_frame, placeholder_text="e.g., 192.168.1")
        scan_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        scan_button = ctk.CTkButton(scan_input_frame, text="Scan Network", 
                                   command=lambda: scan_network(), height=35)
        scan_button.pack(fill="x", padx=10, pady=(0, 10))

        # Right column - Output
        right_frame = ctk.CTkFrame(window)
        right_frame.grid(row=1, column=1, padx=(10, 20), pady=10, sticky="nsew")
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)

        output_title = ctk.CTkLabel(right_frame, text="📋 Results", font=("Arial", 12, "bold"))
        output_title.grid(row=0, column=0, pady=(10, 5), sticky="w", padx=10)

        output_box = ctk.CTkTextbox(right_frame, wrap="word", font=("Consolas", 10))
        output_box.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        output_box.insert("end", "Network Tools Ready\n==================\n\nClick any button to start testing...\n")
        output_box.configure(state="disabled")

        # Bottom row - Action buttons
        bottom_frame = ctk.CTkFrame(window)
        bottom_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
        bottom_frame.grid_columnconfigure(1, weight=1)

        clear_button = ctk.CTkButton(bottom_frame, text="Clear Output", 
                                    command=lambda: clear_output(), width=120, height=35)
        clear_button.grid(row=0, column=0, padx=(20, 10))

        close_button = ctk.CTkButton(bottom_frame, text="Close", 
                                    command=window.destroy, width=120, height=35)
        close_button.grid(row=0, column=2, padx=(10, 20))

        def append_output(text):
            output_box.configure(state="normal")
            output_box.insert("end", text + "\n")
            output_box.see("end")
            output_box.configure(state="disabled")

        def clear_output():
            output_box.configure(state="normal")
            output_box.delete("1.0", "end")
            output_box.insert("end", "Output cleared\n")
            output_box.configure(state="disabled")

        def run_in_thread(func):
            def wrapper(*args, **kwargs):
                threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
            return wrapper

        @run_in_thread
        def flush_dns():
            append_output("\n🔄 [DNS Flush] Flushing DNS cache...")
            try:
                result = flush_dns_cache()
                if result:
                    append_output("✅ DNS cache flushed successfully.")
                else:
                    append_output("❌ Failed to flush DNS cache.")
            except Exception as e:
                append_output(f"❌ Error: {e}")

        @run_in_thread
        def test_selected_host():
            hostname = host_entry.get().strip()
            if not hostname:
                append_output("❌ Please enter a hostname to test.")
                return
            append_output(f"\n🔍 [Host Test] Testing {hostname}...")
            try:
                # DNS resolution
                success, ip = test_hostname(hostname)
                if success:
                    append_output(f"  ✅ DNS: {hostname} -> {ip}")
                else:
                    append_output(f"  ❌ DNS: Failed to resolve {hostname}")
                # Ping
                ping_result = ping_hostname(hostname)
                if ping_result["success"]:
                    append_output(f"  ✅ Ping: {ping_result['packet_loss']}% loss, {ping_result['avg_time']}ms avg")
                else:
                    append_output(f"  ❌ Ping: {ping_result.get('error', 'Failed')}")
                # HTTP/HTTPS
                http = NetworkUtils.test_connectivity(hostname, 80)
                https = NetworkUtils.test_connectivity(hostname, 443)
                if http:
                    append_output("  ✅ HTTP (80): Connected")
                else:
                    append_output("  ❌ HTTP (80): Connection failed")
                if https:
                    append_output("  ✅ HTTPS (443): Connected")
                else:
                    append_output("  ❌ HTTPS (443): Connection failed")
            except Exception as e:
                append_output(f"❌ Error: {e}")

        @run_in_thread
        def scan_network():
            base_ip = scan_entry.get().strip()
            if not base_ip:
                append_output("❌ Please enter a base IP (e.g., 192.168.1)")
                return
            append_output(f"\n📡 [Network Scan] Scanning {base_ip}.0/24 ...")
            try:
                hosts = NetworkUtils.scan_local_network(base_ip)
                if not hosts:
                    append_output("❌ No active hosts found.")
                else:
                    append_output(f"✅ Found {len(hosts)} active hosts:")
                    for h in hosts:
                        append_output(f"  {h['ip']} -> {h['hostname']}")
            except Exception as e:
                append_output(f"❌ Error: {e}")

    def open_config_manager(self):
        """Open the configuration management window."""
        try:
            from config_gui import show_configuration_window
            show_configuration_window(self)
        except ImportError:
            custom_showerror(self, "Error", "Configuration management not available")
        except Exception as e:
            custom_showerror(self, "Error", f"Failed to open configuration manager: {e}")
    
    def save_current_config(self):
        """Save current hosts as a configuration."""
        try:
            from config_gui import CreateConfigDialog
            dialog = CreateConfigDialog(self, title="Save Current Configuration")
            if dialog.result:
                name, description = dialog.result
                from config_manager import get_config_manager
                manager = get_config_manager()
                config = manager.create_from_current_hosts(name, description)
                if config:
                    custom_showinfo(self, "Success", f"Current hosts saved as configuration '{name}'!")
                else:
                    custom_showerror(self, "Error", "Failed to save current hosts as configuration")
        except ImportError:
            custom_showerror(self, "Error", "Configuration management not available")
        except Exception as e:
            custom_showerror(self, "Error", f"Failed to save configuration: {e}")
    
    def quick_apply_config(self):
        """Quick apply a configuration with file dialog."""
        try:
            from config_manager import get_config_manager
            manager = get_config_manager()
            configs = manager.list_configurations()
            
            if not configs:
                custom_showinfo(self, "Info", "No saved configurations found. Use Configuration Manager to create some.")
                return
            
            # Create a simple dialog to select configuration
            dialog = ctk.CTkToplevel(self)
            dialog.title("Quick Apply Configuration")
            dialog.geometry("400x300")
            dialog.resizable(False, False)
            dialog.grab_set()
            
            # Center the dialog
            dialog.geometry("+%d+%d" % (self.winfo_rootx() + 50, self.winfo_rooty() + 50))
            
            # Title
            title_label = ctk.CTkLabel(dialog, text="Select Configuration to Apply", 
                                      font=ctk.CTkFont(size=16, weight="bold"))
            title_label.pack(pady=(20, 20))
            
            # Configuration list
            config_var = tk.StringVar()
            config_listbox = tk.Listbox(dialog, bg='#3c3c3c', fg='#ffffff', 
                                       font=('Segoe UI', 10), height=8)
            config_listbox.pack(pady=(0, 20), padx=20, fill='both', expand=True)
            
            # Populate list
            for config in configs:
                config_listbox.insert(tk.END, f"{config['name']} ({config['stats']['total_entries']} entries)")
            
            # Buttons
            button_frame = ctk.CTkFrame(dialog)
            button_frame.pack(pady=(0, 20), padx=20, fill='x')
            
            def apply_selected():
                selection = config_listbox.curselection()
                if not selection:
                    custom_showwarning(dialog, "Warning", "Please select a configuration")
                    return
                
                config_name = configs[selection[0]]['name']
                dialog.destroy()
                
                # Confirm application
                result = custom_askyesno(self, "Confirm", 
                                       f"This will replace your current /etc/hosts file with configuration '{config_name}'.\n\nContinue?")
                if result:
                    try:
                        success = manager.apply_configuration(config_name, backup_current=True)
                        if success:
                            custom_showinfo(self, "Success", f"Configuration '{config_name}' applied successfully!\nPrevious hosts file backed up automatically.")
                            self.force_refresh_display()
                        else:
                            custom_showerror(self, "Error", f"Failed to apply configuration '{config_name}'")
                    except Exception as e:
                        custom_showerror(self, "Error", f"Failed to apply configuration: {e}")
            
            apply_btn = ctk.CTkButton(button_frame, text="Apply", command=apply_selected,
                                     bg_color='#ffc107', fg_color='#ffc107', text_color='black')
            apply_btn.pack(side='left', padx=(0, 10))
            
            cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=dialog.destroy,
                                      bg_color='#6c757d', fg_color='#6c757d')
            cancel_btn.pack(side='left')
            
        except ImportError:
            custom_showerror(self, "Error", "Configuration management not available")
        except Exception as e:
            custom_showerror(self, "Error", f"Failed to open quick apply dialog: {e}")

    def open_validation_window(self):
        """Open the validation and linting window."""
        validation_window = ctk.CTkToplevel(self)
        validation_window.title("🔍 Hosts File Validation & Linting")
        validation_window.geometry("900x700")
        validation_window.resizable(True, True)
        validation_window.grab_set()

        # Configure grid
        validation_window.grid_columnconfigure(0, weight=1)
        validation_window.grid_rowconfigure(1, weight=1)

        # Title
        title_label = ctk.CTkLabel(validation_window, text="🔍 Advanced Hosts File Validation", 
                                  font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="ew")

        # Main content frame
        content_frame = ctk.CTkFrame(validation_window)
        content_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(1, weight=1)

        # Buttons frame
        button_frame = ctk.CTkFrame(content_frame)
        button_frame.grid(row=0, column=0, pady=(15, 10), padx=15, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)

        def run_validation():
            try:
                from injecthost_logic import validate_hosts_file
                result = validate_hosts_file()
                
                if 'error' in result:
                    custom_showerror(validation_window, "Error", f"Failed to validate hosts file: {result['error']}")
                    return
                
                # Clear previous results
                results_textbox.configure(state="normal")
                results_textbox.delete("1.0", tk.END)
                
                # Display results
                summary = result['summary']
                validation_issues = result['validation_issues']
                lint_issues = result['lint_issues']
                
                results_textbox.insert(tk.END, "🔍 VALIDATION RESULTS\n")
                results_textbox.insert(tk.END, "=" * 50 + "\n\n")
                
                # Summary
                results_textbox.insert(tk.END, f"📊 SUMMARY:\n")
                results_textbox.insert(tk.END, f"   Errors:   {summary['errors']}\n")
                results_textbox.insert(tk.END, f"   Warnings: {summary['warnings']}\n")
                results_textbox.insert(tk.END, f"   Info:     {summary['info']}\n\n")
                
                # Validation issues
                if validation_issues:
                    results_textbox.insert(tk.END, "❌ VALIDATION ISSUES:\n")
                    results_textbox.insert(tk.END, "-" * 30 + "\n")
                    for issue in validation_issues:
                        icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                        results_textbox.insert(tk.END, f"{icon} Line {issue.line_number}: {issue.message}\n")
                        if issue.suggestion:
                            results_textbox.insert(tk.END, f"    💡 Suggestion: {issue.suggestion}\n")
                        if issue.line_content.strip():
                            results_textbox.insert(tk.END, f"    📝 Content: {issue.line_content.strip()}\n")
                    results_textbox.insert(tk.END, "\n")
                else:
                    results_textbox.insert(tk.END, "✅ No validation issues found!\n\n")
                
                # Linting issues
                if lint_issues:
                    results_textbox.insert(tk.END, "🔧 LINTING ISSUES:\n")
                    results_textbox.insert(tk.END, "-" * 30 + "\n")
                    for issue in lint_issues:
                        icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                        results_textbox.insert(tk.END, f"{icon} Line {issue.line_number}: {issue.message}\n")
                        if issue.suggestion:
                            results_textbox.insert(tk.END, f"    💡 Suggestion: {issue.suggestion}\n")
                    results_textbox.insert(tk.END, "\n")
                else:
                    results_textbox.insert(tk.END, "✅ No linting issues found!\n\n")
                
                # Overall status
                if summary['errors'] > 0:
                    results_textbox.insert(tk.END, "❌ Hosts file has validation errors that should be fixed.\n")
                elif summary['warnings'] > 0:
                    results_textbox.insert(tk.END, "⚠️  Hosts file has warnings but no critical errors.\n")
                else:
                    results_textbox.insert(tk.END, "✅ Hosts file is valid and well-formatted!\n")
                
                results_textbox.configure(state="disabled")
                
            except ImportError:
                custom_showerror(validation_window, "Error", "Validation module not available.")
            except Exception as e:
                custom_showerror(validation_window, "Error", f"Failed to run validation: {e}")

        def run_detailed_validation():
            try:
                from injecthost_logic import get_validation_report
                report = get_validation_report()
                
                if 'error' in report:
                    custom_showerror(validation_window, "Error", f"Failed to get validation report: {report['error']}")
                    return
                
                # Clear previous results
                results_textbox.configure(state="normal")
                results_textbox.delete("1.0", tk.END)
                
                # Display detailed report
                results_textbox.insert(tk.END, "🔍 DETAILED VALIDATION REPORT\n")
                results_textbox.insert(tk.END, "=" * 50 + "\n\n")
                
                # File statistics
                results_textbox.insert(tk.END, f"📄 FILE STATISTICS:\n")
                results_textbox.insert(tk.END, f"   Size: {report['file_size']} bytes\n")
                results_textbox.insert(tk.END, f"   Lines: {report['line_count']}\n\n")
                
                # Validation summary
                val_summary = report['validation_summary']
                lint_summary = report['lint_summary']
                
                results_textbox.insert(tk.END, f"📊 VALIDATION SUMMARY:\n")
                results_textbox.insert(tk.END, f"   Errors:   {val_summary['errors']}\n")
                results_textbox.insert(tk.END, f"   Warnings: {val_summary['warnings']}\n")
                results_textbox.insert(tk.END, f"   Info:     {val_summary['info']}\n\n")
                
                results_textbox.insert(tk.END, f"📊 LINTING SUMMARY:\n")
                results_textbox.insert(tk.END, f"   Errors:   {lint_summary['errors']}\n")
                results_textbox.insert(tk.END, f"   Warnings: {lint_summary['warnings']}\n")
                results_textbox.insert(tk.END, f"   Info:     {lint_summary['info']}\n\n")
                
                # Show all validation issues
                if report['validation_issues']:
                    results_textbox.insert(tk.END, "❌ VALIDATION ISSUES:\n")
                    results_textbox.insert(tk.END, "-" * 30 + "\n")
                    for issue in report['validation_issues']:
                        icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                        results_textbox.insert(tk.END, f"{icon} Line {issue.line_number}: {issue.message}\n")
                        if issue.suggestion:
                            results_textbox.insert(tk.END, f"    💡 Suggestion: {issue.suggestion}\n")
                        if issue.line_content.strip():
                            results_textbox.insert(tk.END, f"    📝 Content: {issue.line_content.strip()}\n")
                    results_textbox.insert(tk.END, "\n")
                
                # Show all linting issues
                if report['lint_issues']:
                    results_textbox.insert(tk.END, "🔧 LINTING ISSUES:\n")
                    results_textbox.insert(tk.END, "-" * 30 + "\n")
                    for issue in report['lint_issues']:
                        icon = "❌" if issue.issue_type.value == "error" else "⚠️" if issue.issue_type.value == "warning" else "ℹ️"
                        results_textbox.insert(tk.END, f"{icon} Line {issue.line_number}: {issue.message}\n")
                        if issue.suggestion:
                            results_textbox.insert(tk.END, f"    💡 Suggestion: {issue.suggestion}\n")
                    results_textbox.insert(tk.END, "\n")
                
                results_textbox.configure(state="disabled")
                
            except ImportError:
                custom_showerror(validation_window, "Error", "Validation module not available.")
            except Exception as e:
                custom_showerror(validation_window, "Error", f"Failed to get detailed report: {e}")

        validate_button = ctk.CTkButton(button_frame, text="🔍 Run Validation", command=run_validation, height=35)
        validate_button.grid(row=0, column=0, padx=(0, 5), pady=10, sticky="ew")
        
        detailed_button = ctk.CTkButton(button_frame, text="📊 Detailed Report", command=run_detailed_validation, height=35)
        detailed_button.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        
        format_button = ctk.CTkButton(button_frame, text="🔧 Format File", command=self.format_hosts_file, height=35)
        format_button.grid(row=0, column=2, padx=(5, 0), pady=10, sticky="ew")

        # Results textbox
        results_frame = ctk.CTkFrame(content_frame)
        results_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)

        results_textbox = tk.Text(results_frame, wrap="word", font=("Consolas", 10), 
                                 bg="#1f1f1f", fg="white", insertbackground="white")
        results_textbox.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        results_textbox.insert(tk.END, "Click 'Run Validation' to start...\n")

        # Scrollbar for results
        results_scrollbar = tk.Scrollbar(results_frame, orient="vertical", command=results_textbox.yview)
        results_scrollbar.grid(row=0, column=1, sticky="ns")
        results_textbox.configure(yscrollcommand=results_scrollbar.set)

    def format_hosts_file(self):
        """Format the hosts file with consistent styling."""
        try:
            from injecthost_logic import format_hosts_file_content
            
            result = format_hosts_file_content()
            
            if "successfully" in result:
                custom_showinfo(self, "Success", f"Hosts file formatted successfully!\n\n{result}")
                self.force_refresh_display()
            else:
                custom_showerror(self, "Error", f"Failed to format hosts file: {result}")
                
        except ImportError:
            custom_showerror(self, "Error", "Formatting module not available.")
        except Exception as e:
            custom_showerror(self, "Error", f"Failed to format hosts file: {e}")

if __name__ == "__main__":
    try:
        app = InjectHostApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\nGUI interrupted by user. Exiting gracefully.")
        sys.exit(0)
