#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main GUI Window - Network Security Scanner Suite
Modern Tkinter Interface with Tabbed Layout
Author: Alen Pepa
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
from datetime import datetime

# Import custom tabs
from gui.scanner_tab import PortScannerTab
from gui.discovery_tab import NetworkDiscoveryTab
from gui.ssl_tab import SSLAnalysisTab
from gui.reports_tab import ReportsTab
from utils.logger import get_logger

class NetworkScannerGUI:
    """
    Main GUI application class
    """
    
    def __init__(self, root):
        self.root = root
        self.logger = get_logger()
        self.setup_window()
        self.create_widgets()
        self.setup_menu()
        
    def setup_window(self):
        """
        Configure main window properties
        """
        self.root.title("Network Security Scanner Suite v1.0 - by Alen Pepa")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Window icon (if available)
        try:
            icon_path = os.path.join("assets", "icons", "scanner.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            pass
            
        # Center window on screen
        self.center_window()
        
    def center_window(self):
        """
        Center the window on the screen
        """
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
    def create_widgets(self):
        """
        Create and layout all GUI widgets
        """
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title and status bar
        self.create_header(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Create tabs
        self.create_tabs()
        
        # Status bar
        self.create_status_bar(main_frame)
        
    def create_header(self, parent):
        """
        Create header with title and info
        """
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        header_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            header_frame, 
            text="🔒 Network Security Scanner Suite",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # Version and author info
        info_label = ttk.Label(
            header_frame,
            text="v1.0 | Professional Cybersecurity Tool | by Alen Pepa",
            font=("Arial", 9)
        )
        info_label.grid(row=1, column=0, sticky=tk.W)
        
        # Current time
        self.time_label = ttk.Label(
            header_frame,
            text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            font=("Arial", 9)
        )
        self.time_label.grid(row=0, column=1, sticky=tk.E)
        
        # Update time every second
        self.update_time()
        
    def update_time(self):
        """
        Update time display
        """
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
        
    def create_tabs(self):
        """
        Create all application tabs
        """
        # Port Scanner Tab
        self.scanner_tab = PortScannerTab(self.notebook)
        self.notebook.add(self.scanner_tab.frame, text="🔍 Port Scanner")
        
        # Network Discovery Tab
        self.discovery_tab = NetworkDiscoveryTab(self.notebook)
        self.notebook.add(self.discovery_tab.frame, text="🌐 Network Discovery")
        
        # SSL Analysis Tab
        self.ssl_tab = SSLAnalysisTab(self.notebook)
        self.notebook.add(self.ssl_tab.frame, text="🔐 SSL Analysis")
        
        # Reports Tab
        self.reports_tab = ReportsTab(self.notebook)
        self.notebook.add(self.reports_tab.frame, text="📊 Reports")
        
    def create_status_bar(self, parent):
        """
        Create status bar at bottom
        """
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        status_frame.columnconfigure(0, weight=1)
        
        # Status text
        self.status_var = tk.StringVar(value="Ready - Select a tab to start scanning")
        status_label = ttk.Label(
            status_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            padding="5"
        )
        status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def setup_menu(self):
        """
        Create application menu bar
        """
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Load Results", command=self.load_results)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear All Results", command=self.clear_results)
        tools_menu.add_command(label="Export Report", command=self.export_report)
        tools_menu.add_command(label="Settings", command=self.show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="GitHub Repository", command=self.open_github)
        
    def new_scan(self):
        """
        Start a new scan session
        """
        result = messagebox.askyesno(
            "New Scan",
            "This will clear all current results. Continue?"
        )
        if result:
            self.clear_results()
            self.update_status("Ready for new scan")
            
    def load_results(self):
        """
        Load results from file
        """
        file_path = filedialog.askopenfilename(
            title="Load Scan Results",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            # Implement loading logic
            self.update_status(f"Loaded results from {os.path.basename(file_path)}")
            
    def save_results(self):
        """
        Save current results to file
        """
        file_path = filedialog.asksaveasfilename(
            title="Save Scan Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            # Implement saving logic
            self.update_status(f"Results saved to {os.path.basename(file_path)}")
            
    def clear_results(self):
        """
        Clear all scan results
        """
        # Clear results in all tabs
        self.scanner_tab.clear_results()
        self.discovery_tab.clear_results()
        self.ssl_tab.clear_results()
        self.reports_tab.clear_results()
        
        self.update_status("All results cleared")
        
    def export_report(self):
        """
        Export comprehensive report
        """
        file_path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".html",
            filetypes=[
                ("HTML files", "*.html"),
                ("PDF files", "*.pdf"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            # Generate and export report
            self.reports_tab.export_report(file_path)
            self.update_status(f"Report exported to {os.path.basename(file_path)}")
            
    def show_settings(self):
        """
        Show settings dialog
        """
        messagebox.showinfo("Settings", "Settings dialog coming soon!")
        
    def show_about(self):
        """
        Show about dialog
        """
        about_text = """
Network Security Scanner Suite v1.0

Professional cybersecurity tool for network analysis and security assessment.

🔹 Multi-threaded port scanning
🔹 Network discovery and mapping  
🔹 SSL/TLS certificate analysis
🔹 Vulnerability detection
🔹 Comprehensive reporting

Developed by: Alen Pepa
License: MIT License

⚠️ For educational and authorized testing only!
Respect all applicable laws and regulations.
        """
        
        messagebox.showinfo("About Network Security Scanner", about_text)
        
    def show_docs(self):
        """
        Open documentation
        """
        import webbrowser
        webbrowser.open("https://github.com/alenpepa/network-security-scanner")
        
    def open_github(self):
        """
        Open GitHub repository
        """
        import webbrowser
        webbrowser.open("https://github.com/alenpepa/network-security-scanner")
        
    def update_status(self, message):
        """
        Update status bar message
        """
        self.status_var.set(message)
        self.logger.info(f"Status: {message}")
        
    def exit_app(self):
        """
        Exit application with confirmation
        """
        result = messagebox.askyesno(
            "Exit Application",
            "Are you sure you want to exit?"
        )
        if result:
            self.root.quit()
            self.root.destroy()