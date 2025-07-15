#!/usr/bin/env python3
"""
Custom dialog classes for InjectHost GUI.
Replaces standard tkinter message boxes with modern, themed dialogs.
"""

import customtkinter as ctk
import tkinter as tk
import os
from typing import Optional, Callable, Any
import threading


class CustomDialog(ctk.CTkToplevel):
    """Base class for custom dialogs with consistent styling."""
    
    def __init__(self, parent, title: str, message: str, **kwargs):
        super().__init__(parent)
        
        self.title(title)
        self.geometry("400x200")
        self.resizable(False, False)
        self.grab_set()  # Make dialog modal
        self.transient(parent)  # Make dialog transient to parent
        
        # Center the dialog on parent
        self.center_on_parent(parent)
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Create widgets
        self.create_widgets(message, **kwargs)
        
        # Focus on the dialog
        self.focus_set()
        self.wait_window()
    
    def center_on_parent(self, parent):
        """Center the dialog on its parent window."""
        self.update_idletasks()
        
        # Get parent position and size
        parent_x = parent.winfo_x()
        parent_y = parent.winfo_y()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        # Get dialog size
        dialog_width = self.winfo_reqwidth()
        dialog_height = self.winfo_reqheight()
        
        # Calculate center position
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        # Ensure dialog stays on screen
        x = max(0, x)
        y = max(0, y)
        
        self.geometry(f"+{x}+{y}")
    
    def create_widgets(self, message: str, **kwargs):
        """Create dialog widgets. Override in subclasses."""
        pass


class InfoDialog(CustomDialog):
    """Information dialog with OK button."""
    
    def __init__(self, parent, title: str, message: str):
        self.result = None
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Message label
        message_label = ctk.CTkLabel(
            self, 
            text=message, 
            wraplength=350,
            justify="left"
        )
        message_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # OK button
        ok_button = ctk.CTkButton(
            self, 
            text="OK", 
            command=self.on_ok,
            width=100
        )
        ok_button.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        # Bind Enter key to OK button
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_ok())
        
        # Focus on OK button
        ok_button.focus_set()
    
    def on_ok(self):
        self.result = True
        self.destroy()


class WarningDialog(CustomDialog):
    """Warning dialog with OK button."""
    
    def __init__(self, parent, title: str, message: str):
        self.result = None
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Warning icon and message
        warning_frame = ctk.CTkFrame(self)
        warning_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        warning_frame.grid_columnconfigure(1, weight=1)
        
        # Warning icon (using text as icon)
        warning_icon = ctk.CTkLabel(
            warning_frame, 
            text="⚠️", 
            font=("Arial", 24)
        )
        warning_icon.grid(row=0, column=0, padx=(10, 15), pady=10)
        
        # Message
        message_label = ctk.CTkLabel(
            warning_frame, 
            text=message, 
            wraplength=280,
            justify="left"
        )
        message_label.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        
        # OK button
        ok_button = ctk.CTkButton(
            self, 
            text="OK", 
            command=self.on_ok,
            width=100
        )
        ok_button.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        # Bind Enter key to OK button
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_ok())
        
        # Focus on OK button
        ok_button.focus_set()
    
    def on_ok(self):
        self.result = True
        self.destroy()


class ErrorDialog(CustomDialog):
    """Error dialog with OK button."""
    
    def __init__(self, parent, title: str, message: str):
        self.result = None
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Error icon and message
        error_frame = ctk.CTkFrame(self)
        error_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        error_frame.grid_columnconfigure(1, weight=1)
        
        # Error icon (using text as icon)
        error_icon = ctk.CTkLabel(
            error_frame, 
            text="❌", 
            font=("Arial", 24)
        )
        error_icon.grid(row=0, column=0, padx=(10, 15), pady=10)
        
        # Message
        message_label = ctk.CTkLabel(
            error_frame, 
            text=message, 
            wraplength=280,
            justify="left"
        )
        message_label.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        
        # OK button
        ok_button = ctk.CTkButton(
            self, 
            text="OK", 
            command=self.on_ok,
            width=100
        )
        ok_button.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        # Bind Enter key to OK button
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_ok())
        
        # Focus on OK button
        ok_button.focus_set()
    
    def on_ok(self):
        self.result = True
        self.destroy()


class YesNoDialog(CustomDialog):
    """Yes/No confirmation dialog."""
    
    def __init__(self, parent, title: str, message: str):
        self.result = None
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Message label
        message_label = ctk.CTkLabel(
            self, 
            text=message, 
            wraplength=350,
            justify="left"
        )
        message_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # Button frame
        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        button_frame.grid_columnconfigure((0, 1), weight=1)
        
        # No button (left)
        no_button = ctk.CTkButton(
            button_frame, 
            text="No", 
            command=self.on_no,
            width=100
        )
        no_button.grid(row=0, column=0, padx=(0, 5), pady=5, sticky="ew")
        
        # Yes button (right)
        yes_button = ctk.CTkButton(
            button_frame, 
            text="Yes", 
            command=self.on_yes,
            width=100
        )
        yes_button.grid(row=0, column=1, padx=(5, 0), pady=5, sticky="ew")
        
        # Bind keys
        self.bind("<Return>", lambda e: self.on_yes())
        self.bind("<Escape>", lambda e: self.on_no())
        
        # Focus on Yes button
        yes_button.focus_set()
    
    def on_yes(self):
        self.result = True
        self.destroy()
    
    def on_no(self):
        self.result = False
        self.destroy()


class YesNoCancelDialog(CustomDialog):
    """Yes/No/Cancel dialog with three options."""
    
    def __init__(self, parent, title: str, message: str):
        self.result = None
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Message label
        message_label = ctk.CTkLabel(
            self, 
            text=message, 
            wraplength=350,
            justify="left"
        )
        message_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # Button frame
        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Cancel button (left)
        cancel_button = ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            command=self.on_cancel,
            width=100
        )
        cancel_button.grid(row=0, column=0, padx=(0, 3), pady=5, sticky="ew")
        
        # No button (center)
        no_button = ctk.CTkButton(
            button_frame, 
            text="No", 
            command=self.on_no,
            width=100
        )
        no_button.grid(row=0, column=1, padx=3, pady=5, sticky="ew")
        
        # Yes button (right)
        yes_button = ctk.CTkButton(
            button_frame, 
            text="Yes", 
            command=self.on_yes,
            width=100
        )
        yes_button.grid(row=0, column=2, padx=(3, 0), pady=5, sticky="ew")
        
        # Bind keys
        self.bind("<Return>", lambda e: self.on_yes())
        self.bind("<Escape>", lambda e: self.on_cancel())
        
        # Focus on Yes button
        yes_button.focus_set()
    
    def on_yes(self):
        self.result = True
        self.destroy()
    
    def on_no(self):
        self.result = False
        self.destroy()
    
    def on_cancel(self):
        self.result = None
        self.destroy()


class InputDialog(CustomDialog):
    """Input dialog with text entry and OK/Cancel buttons."""
    
    def __init__(self, parent, title: str, message: str, initial_value: str = ""):
        self.result = None
        self.initial_value = initial_value
        super().__init__(parent, title, message)
    
    def create_widgets(self, message: str, **kwargs):
        # Message label
        message_label = ctk.CTkLabel(
            self, 
            text=message, 
            wraplength=350,
            justify="left"
        )
        message_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # Input entry
        self.input_entry = ctk.CTkEntry(
            self,
            width=350
        )
        self.input_entry.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.input_entry.insert(0, self.initial_value)
        
        # Button frame
        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="ew")
        button_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Cancel button (left)
        cancel_button = ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            command=self.on_cancel,
            width=100
        )
        cancel_button.grid(row=0, column=0, padx=(0, 5), pady=5, sticky="ew")
        
        # OK button (right)
        ok_button = ctk.CTkButton(
            button_frame, 
            text="OK", 
            command=self.on_ok,
            width=100
        )
        ok_button.grid(row=0, column=1, padx=(5, 0), pady=5, sticky="ew")
        
        # Bind keys
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_cancel())
        
        # Focus on input entry
        self.input_entry.focus_set()
        self.input_entry.select_range(0, tk.END)
    
    def on_ok(self):
        self.result = self.input_entry.get()
        self.destroy()
    
    def on_cancel(self):
        self.result = None
        self.destroy()


# Convenience functions to match the original API
def custom_showinfo(parent, title, message):
    """Show information dialog."""
    dialog = InfoDialog(parent, title, message)
    return dialog.result

def custom_showwarning(parent, title, message):
    """Show warning dialog."""
    dialog = WarningDialog(parent, title, message)
    return dialog.result

def custom_showerror(parent, title, message):
    """Show error dialog."""
    dialog = ErrorDialog(parent, title, message)
    return dialog.result

def custom_askyesno(parent, title, message):
    """Show Yes/No dialog."""
    dialog = YesNoDialog(parent, title, message)
    return dialog.result

def custom_askyesnocancel(parent, title, message):
    """Show Yes/No/Cancel dialog."""
    dialog = YesNoCancelDialog(parent, title, message)
    return dialog.result

def custom_askstring(parent, title, message, initial_value=""):
    """Show input dialog."""
    dialog = InputDialog(parent, title, message, initial_value)
    return dialog.result


class CustomFileDialog(CustomDialog):
    """Custom file dialog with modern styling."""
    
    def __init__(self, parent, title: str, mode="open", filetypes=None, defaultextension=""):
        self.mode = mode
        self.filetypes = filetypes or [("All files", "*.*")]
        self.defaultextension = defaultextension
        self.result = None
        super().__init__(parent, title, "")
    
    def create_widgets(self, message: str, **kwargs):
        # File list frame
        file_frame = ctk.CTkFrame(self)
        file_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="nsew")
        file_frame.grid_columnconfigure(0, weight=1)
        file_frame.grid_rowconfigure(1, weight=1)
        
        # Current directory label
        self.dir_label = ctk.CTkLabel(
            file_frame,
            text="Current Directory: " + os.getcwd(),
            wraplength=350
        )
        self.dir_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        
        # File listbox
        self.file_listbox = tk.Listbox(
            file_frame,
            bg="#1f1f1f",
            fg="white",
            selectbackground="#2b2b2b",
            height=10
        )
        self.file_listbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        # Filename entry
        filename_frame = ctk.CTkFrame(self)
        filename_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")
        filename_frame.grid_columnconfigure(1, weight=1)
        
        filename_label = ctk.CTkLabel(filename_frame, text="Filename:")
        filename_label.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        
        self.filename_entry = ctk.CTkEntry(filename_frame)
        self.filename_entry.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        
        # File type dropdown
        filetype_frame = ctk.CTkFrame(self)
        filetype_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        filetype_frame.grid_columnconfigure(1, weight=1)
        
        filetype_label = ctk.CTkLabel(filetype_frame, text="File type:")
        filetype_label.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        
        self.filetype_var = tk.StringVar()
        self.filetype_dropdown = ctk.CTkOptionMenu(
            filetype_frame,
            variable=self.filetype_var,
            values=[desc for desc, ext in self.filetypes]
        )
        self.filetype_dropdown.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        
        # Button frame
        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Cancel button
        cancel_button = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self.on_cancel,
            width=100
        )
        cancel_button.grid(row=0, column=0, padx=(0, 5), pady=5, sticky="ew")
        
        # Open/Save button
        action_text = "Save" if self.mode == "save" else "Open"
        self.action_button = ctk.CTkButton(
            button_frame,
            text=action_text,
            command=self.on_action,
            width=100
        )
        self.action_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Browse button
        browse_button = ctk.CTkButton(
            button_frame,
            text="Browse",
            command=self.on_browse,
            width=100
        )
        browse_button.grid(row=0, column=2, padx=(5, 0), pady=5, sticky="ew")
        
        # Initialize file list
        self.populate_file_list()
        
        # Bind events
        self.file_listbox.bind("<Double-Button-1>", self.on_file_select)
        self.file_listbox.bind("<Return>", self.on_file_select)
        self.filename_entry.bind("<Return>", self.on_action)
        self.bind("<Escape>", lambda e: self.on_cancel())
        
        # Focus on filename entry
        self.filename_entry.focus_set()
    
    def populate_file_list(self):
        """Populate the file listbox with current directory contents."""
        self.file_listbox.delete(0, tk.END)
        
        try:
            current_dir = os.getcwd()
            self.dir_label.configure(text=f"Current Directory: {current_dir}")
            
            # Add parent directory option
            self.file_listbox.insert(tk.END, "..")
            
            # Add files and directories
            for item in sorted(os.listdir(current_dir)):
                if os.path.isdir(os.path.join(current_dir, item)):
                    self.file_listbox.insert(tk.END, f"[DIR] {item}")
                else:
                    self.file_listbox.insert(tk.END, item)
        except Exception as e:
            self.file_listbox.insert(tk.END, f"Error reading directory: {e}")
    
    def on_file_select(self, event=None):
        """Handle file selection from listbox."""
        selection = self.file_listbox.curselection()
        if not selection:
            return
        
        selected_item = self.file_listbox.get(selection[0])
        
        if selected_item == "..":
            # Go to parent directory
            try:
                os.chdir("..")
                self.populate_file_list()
            except Exception as e:
                pass
        elif selected_item.startswith("[DIR] "):
            # Enter directory
            dir_name = selected_item[6:]  # Remove "[DIR] " prefix
            try:
                os.chdir(dir_name)
                self.populate_file_list()
            except Exception as e:
                pass
        else:
            # Select file
            self.filename_entry.delete(0, tk.END)
            self.filename_entry.insert(0, selected_item)
    
    def on_browse(self):
        """Use system file dialog as fallback."""
        try:
            from tkinter import filedialog
            if self.mode == "save":
                result = filedialog.asksaveasfilename(
                    title=self.title(),
                    defaultextension=self.defaultextension,
                    filetypes=self.filetypes
                )
            else:
                result = filedialog.askopenfilename(
                    title=self.title(),
                    filetypes=self.filetypes
                )
            
            if result:
                self.result = result
                self.destroy()
        except Exception as e:
            # If system dialog fails, just return None
            self.result = None
            self.destroy()
    
    def on_action(self):
        """Handle Open/Save action."""
        filename = self.filename_entry.get().strip()
        if not filename:
            return
        
        # Add extension if needed
        if self.defaultextension and not filename.endswith(self.defaultextension):
            filename += self.defaultextension
        
        # Make path absolute
        if not os.path.isabs(filename):
            filename = os.path.abspath(filename)
        
        self.result = filename
        self.destroy()
    
    def on_cancel(self):
        """Handle cancel action."""
        self.result = None
        self.destroy()


# Convenience functions for file dialogs
def custom_askopenfilename(parent, title="Open File", filetypes=None):
    """Show custom file open dialog."""
    dialog = CustomFileDialog(parent, title, mode="open", filetypes=filetypes)
    return dialog.result

def custom_asksaveasfilename(parent, title="Save File", filetypes=None, defaultextension=""):
    """Show custom file save dialog."""
    dialog = CustomFileDialog(parent, title, mode="save", filetypes=filetypes, defaultextension=defaultextension)
    return dialog.result 