#!/usr/bin/env python3
"""
Configuration Management GUI for InjectHost.
Provides a modern interface for managing host configurations.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
import os

try:
    from config_manager import get_config_manager, HostConfiguration
except ImportError:
    print("Configuration management not available")
    get_config_manager = None
    HostConfiguration = None


class ConfigurationWindow:
    """Main configuration management window."""
    
    def __init__(self, parent=None):
        self.parent = parent
        self.config_manager = get_config_manager() if get_config_manager else None
        
        if not self.config_manager:
            messagebox.showerror("Error", "Configuration management not available")
            return
        
        self.window = tk.Toplevel(parent) if parent else tk.Tk()
        self.window.title("InjectHost - Configuration Management")
        self.window.geometry("900x700")
        self.window.configure(bg='#2b2b2b')
        
        # Configure grid weights
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(1, weight=1)
        
        self.setup_ui()
        self.refresh_configurations()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Header
        header_frame = tk.Frame(self.window, bg='#2b2b2b', height=60)
        header_frame.grid(row=0, column=0, sticky='ew', padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(1, weight=1)
        
        # Title
        title_label = tk.Label(header_frame, text="🔧 Configuration Management", 
                              font=('Segoe UI', 16, 'bold'), fg='#ffffff', bg='#2b2b2b')
        title_label.grid(row=0, column=0, sticky='w')
        
        # Refresh button
        refresh_btn = tk.Button(header_frame, text="🔄 Refresh", 
                               command=self.refresh_configurations,
                               font=('Segoe UI', 10), bg='#4a90e2', fg='white',
                               relief='flat', padx=15, pady=5)
        refresh_btn.grid(row=0, column=2, padx=(10, 0))
        
        # Main content area
        main_frame = tk.Frame(self.window, bg='#2b2b2b')
        main_frame.grid(row=1, column=0, sticky='nsew', padx=20, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Configuration list
        list_frame = tk.LabelFrame(main_frame, text="📁 Saved Configurations", 
                                  font=('Segoe UI', 12, 'bold'), fg='#ffffff', bg='#2b2b2b')
        list_frame.grid(row=0, column=0, sticky='ew', pady=(0, 20))
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview for configurations
        columns = ('Name', 'Description', 'Entries', 'Created', 'Updated')
        self.config_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        # Configure columns
        self.config_tree.heading('Name', text='Name')
        self.config_tree.heading('Description', text='Description')
        self.config_tree.heading('Entries', text='Entries')
        self.config_tree.heading('Created', text='Created')
        self.config_tree.heading('Updated', text='Updated')
        
        self.config_tree.column('Name', width=150)
        self.config_tree.column('Description', width=200)
        self.config_tree.column('Entries', width=80, anchor='center')
        self.config_tree.column('Created', width=150)
        self.config_tree.column('Updated', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.config_tree.yview)
        self.config_tree.configure(yscrollcommand=scrollbar.set)
        
        self.config_tree.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        scrollbar.grid(row=0, column=1, sticky='ns', pady=10)
        
        # Bind selection event
        self.config_tree.bind('<<TreeviewSelect>>', self.on_config_select)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg='#2b2b2b')
        buttons_frame.grid(row=1, column=0, sticky='ew', pady=(0, 20))
        buttons_frame.grid_columnconfigure(0, weight=1)
        
        # Left buttons
        left_buttons = tk.Frame(buttons_frame, bg='#2b2b2b')
        left_buttons.grid(row=0, column=0, sticky='w')
        
        # Create new configuration
        create_btn = tk.Button(left_buttons, text="➕ Create New", 
                              command=self.create_configuration,
                              font=('Segoe UI', 10), bg='#28a745', fg='white',
                              relief='flat', padx=15, pady=8)
        create_btn.pack(side='left', padx=(0, 10))
        
        # Save current as configuration
        save_current_btn = tk.Button(left_buttons, text="💾 Save Current", 
                                    command=self.save_current_configuration,
                                    font=('Segoe UI', 10), bg='#17a2b8', fg='white',
                                    relief='flat', padx=15, pady=8)
        save_current_btn.pack(side='left', padx=(0, 10))
        
        # Right buttons
        right_buttons = tk.Frame(buttons_frame, bg='#2b2b2b')
        right_buttons.grid(row=0, column=1, sticky='e')
        
        # Apply configuration
        apply_btn = tk.Button(right_buttons, text="▶️ Apply", 
                             command=self.apply_configuration,
                             font=('Segoe UI', 10), bg='#ffc107', fg='black',
                             relief='flat', padx=15, pady=8)
        apply_btn.pack(side='right', padx=(10, 0))
        
        # Export configuration
        export_btn = tk.Button(right_buttons, text="📤 Export", 
                              command=self.export_configuration,
                              font=('Segoe UI', 10), bg='#6f42c1', fg='white',
                              relief='flat', padx=15, pady=8)
        export_btn.pack(side='right', padx=(10, 0))
        
        # Import configuration
        import_btn = tk.Button(right_buttons, text="📥 Import", 
                              command=self.import_configuration,
                              font=('Segoe UI', 10), bg='#fd7e14', fg='white',
                              relief='flat', padx=15, pady=8)
        import_btn.pack(side='right', padx=(10, 0))
        
        # Delete configuration
        delete_btn = tk.Button(right_buttons, text="🗑️ Delete", 
                              command=self.delete_configuration,
                              font=('Segoe UI', 10), bg='#dc3545', fg='white',
                              relief='flat', padx=15, pady=8)
        delete_btn.pack(side='right', padx=(10, 0))
        
        # Rename configuration
        rename_btn = tk.Button(right_buttons, text="✏️ Rename", 
                              command=self.rename_configuration,
                              font=('Segoe UI', 10), bg='#20c997', fg='white',
                              relief='flat', padx=15, pady=8)
        rename_btn.pack(side='right', padx=(10, 0))
        
        # Configuration details frame
        details_frame = tk.LabelFrame(main_frame, text="📋 Configuration Details", 
                                     font=('Segoe UI', 12, 'bold'), fg='#ffffff', bg='#2b2b2b')
        details_frame.grid(row=2, column=0, sticky='ew')
        details_frame.grid_columnconfigure(0, weight=1)
        
        # Details text widget
        self.details_text = tk.Text(details_frame, height=8, bg='#3c3c3c', fg='#ffffff',
                                   font=('Consolas', 10), wrap='word')
        details_scrollbar = ttk.Scrollbar(details_frame, orient='vertical', 
                                         command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scrollbar.set)
        
        self.details_text.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        details_scrollbar.grid(row=0, column=1, sticky='ns', pady=10)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.window, textvariable=self.status_var, 
                             bg='#1e1e1e', fg='#cccccc', font=('Segoe UI', 9))
        status_bar.grid(row=2, column=0, sticky='ew', padx=20, pady=(0, 20))
    
    def refresh_configurations(self):
        """Refresh the configuration list."""
        try:
            # Clear existing items
            for item in self.config_tree.get_children():
                self.config_tree.delete(item)
            
            # Get configurations
            configs = self.config_manager.list_configurations()
            
            # Add to treeview
            for config in configs:
                stats = config['stats']
                created = stats['created_at'][:19] if stats['created_at'] else 'Unknown'
                updated = stats['updated_at'][:19] if stats['updated_at'] else 'Unknown'
                
                self.config_tree.insert('', 'end', values=(
                    config['name'],
                    config['description'] or 'No description',
                    stats['total_entries'],
                    created,
                    updated
                ))
            
            self.status_var.set(f"Found {len(configs)} configurations")
            
        except Exception as e:
            self.status_var.set(f"Error refreshing: {e}")
            messagebox.showerror("Error", f"Failed to refresh configurations: {e}")
    
    def on_config_select(self, event):
        """Handle configuration selection."""
        selection = self.config_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        config_name = self.config_tree.item(item, 'values')[0]
        
        try:
            config = self.config_manager.load_configuration(config_name)
            if config:
                self.show_config_details(config)
        except Exception as e:
            self.status_var.set(f"Error loading configuration: {e}")
    
    def show_config_details(self, config: HostConfiguration):
        """Show configuration details."""
        self.details_text.delete(1.0, tk.END)
        
        details = f"Configuration: {config.name}\n"
        details += f"Description: {config.description or 'No description'}\n"
        details += f"Created: {config.created_at}\n"
        details += f"Updated: {config.updated_at}\n"
        details += f"Total Entries: {len(config.entries)}\n"
        details += "\n" + "="*50 + "\n\n"
        
        if config.entries:
            details += "Host Entries:\n"
            details += "-" * 30 + "\n"
            for i, entry in enumerate(config.entries, 1):
                details += f"{i:3d}. {entry['ip']:<15} -> {entry['hostname']}"
                if entry.get('comment'):
                    details += f"  # {entry['comment']}"
                details += "\n"
        else:
            details += "No host entries in this configuration.\n"
        
        self.details_text.insert(1.0, details)
    
    def create_configuration(self):
        """Create a new configuration."""
        dialog = CreateConfigDialog(self.window)
        if dialog.result:
            name, description = dialog.result
            try:
                config = HostConfiguration(name, description)
                if self.config_manager.save_configuration(config):
                    self.refresh_configurations()
                    self.status_var.set(f"Configuration '{name}' created successfully")
                    messagebox.showinfo("Success", f"Configuration '{name}' created successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to create configuration '{name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create configuration: {e}")
    
    def save_current_configuration(self):
        """Save current hosts as a configuration."""
        dialog = CreateConfigDialog(self.window, title="Save Current Configuration")
        if dialog.result:
            name, description = dialog.result
            try:
                config = self.config_manager.create_from_current_hosts(name, description)
                if config:
                    self.refresh_configurations()
                    self.status_var.set(f"Current hosts saved as configuration '{name}'")
                    messagebox.showinfo("Success", f"Current hosts saved as configuration '{name}'!")
                else:
                    messagebox.showerror("Error", f"Failed to save current hosts as configuration")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save current hosts: {e}")
    
    def apply_configuration(self):
        """Apply selected configuration."""
        selection = self.config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a configuration to apply")
            return
        
        item = selection[0]
        config_name = self.config_tree.item(item, 'values')[0]
        
        result = messagebox.askyesno("Confirm", 
                                   f"This will replace your current /etc/hosts file with configuration '{config_name}'.\n\nContinue?")
        if result:
            try:
                success = self.config_manager.apply_configuration(config_name, backup_current=True)
                if success:
                    self.status_var.set(f"Configuration '{config_name}' applied successfully")
                    messagebox.showinfo("Success", f"Configuration '{config_name}' applied successfully!\nPrevious hosts file backed up automatically.")
                    if self.parent and hasattr(self.parent, 'force_refresh_display'):
                        self.parent.force_refresh_display()
                else:
                    messagebox.showerror("Error", f"Failed to apply configuration '{config_name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to apply configuration: {e}")
    
    def export_configuration(self):
        """Export selected configuration."""
        selection = self.config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a configuration to export")
            return
        
        item = selection[0]
        config_name = self.config_tree.item(item, 'values')[0]
        
        file_path = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfilename=f"{config_name}.json"
        )
        
        if file_path:
            try:
                success = self.config_manager.export_configuration(config_name, file_path)
                if success:
                    self.status_var.set(f"Configuration '{config_name}' exported to {file_path}")
                    messagebox.showinfo("Success", f"Configuration exported successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to export configuration '{config_name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export configuration: {e}")
    
    def import_configuration(self):
        """Import a configuration from file."""
        file_path = filedialog.askopenfilename(
            title="Import Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                config_name = self.config_manager.import_configuration(file_path, overwrite=False)
                if config_name:
                    self.refresh_configurations()
                    self.status_var.set(f"Configuration '{config_name}' imported successfully")
                    messagebox.showinfo("Success", f"Configuration '{config_name}' imported successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to import configuration from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import configuration: {e}")
    
    def delete_configuration(self):
        """Delete selected configuration."""
        selection = self.config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a configuration to delete")
            return
        
        item = selection[0]
        config_name = self.config_tree.item(item, 'values')[0]
        
        result = messagebox.askyesno("Confirm", 
                                   f"This will permanently delete configuration '{config_name}'.\n\nContinue?")
        if result:
            try:
                success = self.config_manager.delete_configuration(config_name)
                if success:
                    self.refresh_configurations()
                    self.status_var.set(f"Configuration '{config_name}' deleted successfully")
                    messagebox.showinfo("Success", f"Configuration '{config_name}' deleted successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to delete configuration '{config_name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete configuration: {e}")
    
    def rename_configuration(self):
        """Rename selected configuration."""
        selection = self.config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a configuration to rename")
            return
        
        item = selection[0]
        values = self.config_tree.item(item, 'values')
        old_name = values[0]
        old_description = values[1] if len(values) > 1 else ""
        
        # Create rename dialog
        dialog = RenameConfigDialog(self.window, old_name, old_description)
        if dialog.result:
            new_name, new_description = dialog.result
            try:
                success = self.config_manager.rename_configuration(old_name, new_name, new_description)
                if success:
                    self.refresh_configurations()
                    if new_description:
                        self.status_var.set(f"Configuration '{old_name}' renamed to '{new_name}' with new description successfully")
                    else:
                        self.status_var.set(f"Configuration '{old_name}' renamed to '{new_name}' successfully")
                    messagebox.showinfo("Success", f"Configuration renamed successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to rename configuration '{old_name}' to '{new_name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to rename configuration: {e}")


class RenameConfigDialog:
    """Dialog for renaming configurations."""
    
    def __init__(self, parent, old_name, old_description=""):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Rename Configuration")
        self.dialog.geometry("400x220")
        self.dialog.configure(bg='#2b2b2b')
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        # Configure grid
        self.dialog.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = tk.Label(self.dialog, text="Rename Configuration", font=('Segoe UI', 14, 'bold'),
                              fg='#ffffff', bg='#2b2b2b')
        title_label.grid(row=0, column=0, pady=(20, 20))
        
        # New name field
        name_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        name_frame.grid(row=1, column=0, sticky='ew', padx=20, pady=(0, 15))
        name_frame.grid_columnconfigure(1, weight=1)
        
        name_label = tk.Label(name_frame, text="New Name:", font=('Segoe UI', 10),
                             fg='#ffffff', bg='#2b2b2b')
        name_label.grid(row=0, column=0, sticky='w', padx=(0, 10))
        
        self.name_entry = tk.Entry(name_frame, font=('Segoe UI', 10), bg='#3c3c3c', fg='#ffffff')
        self.name_entry.grid(row=0, column=1, sticky='ew')
        self.name_entry.insert(0, old_name)  # Pre-fill with current name
        
        # New description field
        desc_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        desc_frame.grid(row=2, column=0, sticky='ew', padx=20, pady=(0, 20))
        desc_frame.grid_columnconfigure(1, weight=1)
        
        desc_label = tk.Label(desc_frame, text="New Description:", font=('Segoe UI', 10),
                             fg='#ffffff', bg='#2b2b2b')
        desc_label.grid(row=0, column=0, sticky='w', padx=(0, 10))
        
        self.desc_entry = tk.Entry(desc_frame, font=('Segoe UI', 10), bg='#3c3c3c', fg='#ffffff')
        self.desc_entry.grid(row=0, column=1, sticky='ew')
        self.desc_entry.insert(0, old_description)  # Pre-fill with current description
        
        # Buttons
        buttons_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        buttons_frame.grid(row=3, column=0, pady=(0, 20))
        
        ok_btn = tk.Button(buttons_frame, text="OK", command=self.ok_clicked,
                          font=('Segoe UI', 10), bg='#28a745', fg='white',
                          relief='flat', padx=20, pady=5)
        ok_btn.pack(side='left', padx=(0, 10))
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", command=self.cancel_clicked,
                              font=('Segoe UI', 10), bg='#6c757d', fg='white',
                              relief='flat', padx=20, pady=5)
        cancel_btn.pack(side='left')
        
        # Focus on name entry and select all text
        self.name_entry.focus()
        self.name_entry.select_range(0, tk.END)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def ok_clicked(self):
        """Handle OK button click."""
        new_name = self.name_entry.get().strip()
        new_description = self.desc_entry.get().strip()
        
        if not new_name:
            messagebox.showwarning("Warning", "Please enter a new configuration name")
            return
        
        # Return tuple of (new_name, new_description)
        self.result = (new_name, new_description if new_description else None)
        self.dialog.destroy()
    
    def cancel_clicked(self):
        """Handle Cancel button click."""
        self.dialog.destroy()


class CreateConfigDialog:
    """Dialog for creating new configurations."""
    
    def __init__(self, parent, title="Create New Configuration"):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x200")
        self.dialog.configure(bg='#2b2b2b')
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        # Configure grid
        self.dialog.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = tk.Label(self.dialog, text=title, font=('Segoe UI', 14, 'bold'),
                              fg='#ffffff', bg='#2b2b2b')
        title_label.grid(row=0, column=0, pady=(20, 30))
        
        # Name field
        name_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        name_frame.grid(row=1, column=0, sticky='ew', padx=20, pady=(0, 15))
        name_frame.grid_columnconfigure(1, weight=1)
        
        name_label = tk.Label(name_frame, text="Name:", font=('Segoe UI', 10),
                             fg='#ffffff', bg='#2b2b2b')
        name_label.grid(row=0, column=0, sticky='w', padx=(0, 10))
        
        self.name_entry = tk.Entry(name_frame, font=('Segoe UI', 10), bg='#3c3c3c', fg='#ffffff')
        self.name_entry.grid(row=0, column=1, sticky='ew')
        
        # Description field
        desc_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        desc_frame.grid(row=2, column=0, sticky='ew', padx=20, pady=(0, 30))
        desc_frame.grid_columnconfigure(1, weight=1)
        
        desc_label = tk.Label(desc_frame, text="Description:", font=('Segoe UI', 10),
                             fg='#ffffff', bg='#2b2b2b')
        desc_label.grid(row=0, column=0, sticky='w', padx=(0, 10))
        
        self.desc_entry = tk.Entry(desc_frame, font=('Segoe UI', 10), bg='#3c3c3c', fg='#ffffff')
        self.desc_entry.grid(row=0, column=1, sticky='ew')
        
        # Buttons
        buttons_frame = tk.Frame(self.dialog, bg='#2b2b2b')
        buttons_frame.grid(row=3, column=0, pady=(0, 20))
        
        ok_btn = tk.Button(buttons_frame, text="OK", command=self.ok_clicked,
                          font=('Segoe UI', 10), bg='#28a745', fg='white',
                          relief='flat', padx=20, pady=5)
        ok_btn.pack(side='left', padx=(0, 10))
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", command=self.cancel_clicked,
                              font=('Segoe UI', 10), bg='#6c757d', fg='white',
                              relief='flat', padx=20, pady=5)
        cancel_btn.pack(side='left')
        
        # Focus on name entry
        self.name_entry.focus()
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def ok_clicked(self):
        """Handle OK button click."""
        name = self.name_entry.get().strip()
        description = self.desc_entry.get().strip()
        
        if not name:
            messagebox.showwarning("Warning", "Please enter a configuration name")
            return
        
        self.result = (name, description)
        self.dialog.destroy()
    
    def cancel_clicked(self):
        """Handle Cancel button click."""
        self.dialog.destroy()


def show_configuration_window(parent=None):
    """Show the configuration management window."""
    try:
        if not get_config_manager:
            messagebox.showerror("Error", "Configuration management not available")
            return
        
        window = ConfigurationWindow(parent)
        return window
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open configuration window: {e}")


if __name__ == "__main__":
    # Test the configuration window
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    show_configuration_window(root)
    
    root.mainloop() 