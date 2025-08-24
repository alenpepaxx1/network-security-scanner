#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner Tab - GUI Component
User interface for port scanning functionality
Author: Alen Pepa
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from datetime import datetime
from typing import List, Dict

from core.scanner import PortScanner
from utils.logger import get_logger

class PortScannerTab:
    """
    Port scanner tab interface
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.logger = get_logger()
        self.scanner = PortScanner()
        self.scan_thread = None
        self.scan_active = False
        
        self.create_widgets()
        
    def create_widgets(self):
        """
        Create tab widgets
        """
        # Main frame
        self.frame = ttk.Frame(self.parent, padding="10")
        
        # Configure grid weights
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(4, weight=1)
        
        # Target configuration
        self.create_target_section()
        
        # Port configuration
        self.create_port_section()
        
        # Scan options
        self.create_options_section()
        
        # Control buttons
        self.create_control_section()
        
        # Results display
        self.create_results_section()
        
        # Status and progress
        self.create_status_section()
        
    def create_target_section(self):
        """
        Create target input section
        """
        target_frame = ttk.LabelFrame(self.frame, text="Target Configuration", padding="5")
        target_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        target_frame.columnconfigure(1, weight=1)
        
        # Target type
        ttk.Label(target_frame, text="Target Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.target_type = ttk.Combobox(target_frame, values=["Single Host", "IP Range", "Network"], 
                                       state="readonly", width=15)
        self.target_type.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.target_type.set("Single Host")
        
        # Target input
        ttk.Label(target_frame, text="Target:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.target_entry = ttk.Entry(target_frame, width=30)
        self.target_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        self.target_entry.insert(0, "127.0.0.1")
        
        # Examples
        examples = {
            "Single Host": "Example: 192.168.1.1 or google.com",
            "IP Range": "Example: 192.168.1.1-192.168.1.50",
            "Network": "Example: 192.168.1.0/24"
        }
        
        self.example_label = ttk.Label(target_frame, text=examples["Single Host"], 
                                      font=("Arial", 8), foreground="gray")
        self.example_label.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))
        
        # Update examples when target type changes
        self.target_type.bind("<<ComboboxSelected>>", 
                             lambda e: self.example_label.config(text=examples[self.target_type.get()]))
                             
    def create_port_section(self):
        """
        Create port configuration section
        """
        port_frame = ttk.LabelFrame(self.frame, text="Port Configuration", padding="5")
        port_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        port_frame.columnconfigure(1, weight=1)
        
        # Port type
        ttk.Label(port_frame, text="Port Selection:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.port_type = ttk.Combobox(port_frame, values=["Common Ports", "Custom Range", "Specific Ports"], 
                                     state="readonly", width=15)
        self.port_type.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.port_type.set("Common Ports")
        
        # Port input
        self.port_entry = ttk.Entry(port_frame, width=30, state="disabled")
        self.port_entry.grid(row=0, column=2, sticky=(tk.W, tk.E))
        
        # Port examples
        port_examples = {
            "Common Ports": "Will scan: 21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,8080",
            "Custom Range": "Example: 1-1000 or 80-443",
            "Specific Ports": "Example: 80,443,22,21 or 80,443,8080-8090"
        }
        
        self.port_example_label = ttk.Label(port_frame, text=port_examples["Common Ports"], 
                                          font=("Arial", 8), foreground="gray", wraplength=500)
        self.port_example_label.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        
        # Update port input based on type
        def update_port_input(event):
            port_type = self.port_type.get()
            if port_type == "Common Ports":
                self.port_entry.config(state="disabled")
                self.port_entry.delete(0, tk.END)
            else:
                self.port_entry.config(state="normal")
                if port_type == "Custom Range":
                    self.port_entry.delete(0, tk.END)
                    self.port_entry.insert(0, "1-1000")
                else:
                    self.port_entry.delete(0, tk.END)
                    self.port_entry.insert(0, "80,443,22,21")
            self.port_example_label.config(text=port_examples[port_type])
            
        self.port_type.bind("<<ComboboxSelected>>", update_port_input)
        
    def create_options_section(self):
        """
        Create scan options section
        """
        options_frame = ttk.LabelFrame(self.frame, text="Scan Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Scan options
        self.grab_banners = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Grab Service Banners", 
                       variable=self.grab_banners).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
                       
        self.detect_os = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="OS Detection", 
                       variable=self.detect_os).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
                       
        self.check_vulns = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Vulnerability Check", 
                       variable=self.check_vulns).grid(row=0, column=2, sticky=tk.W)
        
        # Threading options
        ttk.Label(options_frame, text="Max Threads:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        self.thread_count = tk.IntVar(value=50)
        thread_spin = ttk.Spinbox(options_frame, from_=1, to=200, width=10, textvariable=self.thread_count)
        thread_spin.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        
        ttk.Label(options_frame, text="Timeout (sec):").grid(row=1, column=2, sticky=tk.W, padx=(20, 5), pady=(10, 0))
        self.timeout = tk.IntVar(value=3)
        timeout_spin = ttk.Spinbox(options_frame, from_=1, to=30, width=10, textvariable=self.timeout)
        timeout_spin.grid(row=1, column=3, sticky=tk.W, pady=(10, 0))
        
    def create_control_section(self):
        """
        Create control buttons section
        """
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        
        # Scan button
        self.scan_button = ttk.Button(control_frame, text="🔍 Start Scan", 
                                     command=self.start_scan, style="Accent.TButton")
        self.scan_button.grid(row=0, column=0, padx=(0, 5))
        
        # Stop button
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop Scan", 
                                     command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=(0, 5))
        
        # Clear button
        self.clear_button = ttk.Button(control_frame, text="🗑 Clear Results", 
                                      command=self.clear_results)
        self.clear_button.grid(row=0, column=2, padx=(0, 5))
        
        # Export button
        self.export_button = ttk.Button(control_frame, text="📁 Export Results", 
                                       command=self.export_results)
        self.export_button.grid(row=0, column=3)
        
    def create_results_section(self):
        """
        Create results display section
        """
        results_frame = ttk.LabelFrame(self.frame, text="Scan Results", padding="5")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results treeview
        columns = ('Host', 'Port', 'State', 'Service', 'Version', 'Banner')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=15)
        
        # Configure columns
        self.results_tree.heading('#0', text='#')
        self.results_tree.column('#0', width=50, minwidth=30)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == 'Host':
                self.results_tree.column(col, width=120)
            elif col == 'Port':
                self.results_tree.column(col, width=60)
            elif col == 'State':
                self.results_tree.column(col, width=60)
            elif col == 'Service':
                self.results_tree.column(col, width=100)
            elif col == 'Version':
                self.results_tree.column(col, width=100)
            else:  # Banner
                self.results_tree.column(col, width=200)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Context menu
        self.create_context_menu()
        
    def create_context_menu(self):
        """
        Create context menu for results
        """
        self.context_menu = tk.Menu(self.results_tree, tearoff=0)
        self.context_menu.add_command(label="Copy Host", command=self.copy_host)
        self.context_menu.add_command(label="Copy Port", command=self.copy_port)
        self.context_menu.add_command(label="Copy Banner", command=self.copy_banner)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Scan This Port Again", command=self.rescan_port)
        self.context_menu.add_command(label="Remove Entry", command=self.remove_entry)
        
        def show_context_menu(event):
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()
                
        self.results_tree.bind("<Button-3>", show_context_menu)  # Right click
        
    def create_status_section(self):
        """
        Create status and progress section
        """
        status_frame = ttk.Frame(self.frame)
        status_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                          maximum=100, length=300)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
        # Statistics
        self.stats_var = tk.StringVar(value="")
        self.stats_label = ttk.Label(status_frame, textvariable=self.stats_var, font=("Arial", 8))
        self.stats_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
        
    def start_scan(self):
        """
        Start the port scan
        """
        if self.scan_active:
            return
            
        # Validate inputs
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        # Get ports to scan
        try:
            ports = self.get_ports_to_scan()
            if not ports:
                messagebox.showerror("Error", "No valid ports specified")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Invalid port specification: {str(e)}")
            return
            
        # Update UI state
        self.scan_active = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")
        
        # Configure scanner
        self.scanner.max_threads = self.thread_count.get()
        self.scanner.timeout = self.timeout.get()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, ports),
            daemon=True
        )
        self.scan_thread.start()
        
    def get_ports_to_scan(self) -> List[int]:
        """
        Get list of ports to scan based on configuration
        """
        port_type = self.port_type.get()
        
        if port_type == "Common Ports":
            return self.scanner.get_common_ports()
        elif port_type == "Custom Range":
            range_str = self.port_entry.get().strip()
            if '-' in range_str:
                start, end = map(int, range_str.split('-', 1))
                return list(range(start, end + 1))
            else:
                return [int(range_str)]
        else:  # Specific Ports
            ports_str = self.port_entry.get().strip()
            ports = []
            for part in ports_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-', 1))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return ports
            
    def run_scan(self, target: str, ports: List[int]):
        """
        Run the actual scan (called in separate thread) - FIXED VERSION
        """
        try:
            def progress_callback(completed, total):
                progress = (completed / total) * 100
                self.progress_var.set(progress)
                self.status_var.set(f"Scanning... {completed}/{total} ports")
                
            # Perform the scan
            target_type = self.target_type.get()
            
            if target_type == "Single Host":
                results = self.scanner.scan_host(target, ports, progress_callback)
                self.display_results([(target, results)])
                # FIXED: Calculate open ports count separately
                open_ports_count = len([r for r in results if r.get('state') == 'open'])
                self.status_var.set(f"Scan completed - {open_ports_count} open ports found")
            else:
                # Network or range scan
                results = self.scanner.scan_network(target, ports, progress_callback)
                self.display_results(results.items())
                # FIXED: Calculate open ports for network scans
                total_open_ports = 0
                for host_results in results.values():
                    total_open_ports += len([r for r in host_results if r.get('state') == 'open'])
                self.status_var.set(f"Scan completed - {total_open_ports} open ports found")
                
        except Exception as e:
            self.status_var.set(f"Scan failed: {str(e)}")
            self.logger.error(f"Scan failed: {e}")
            
        finally:
            # Reset UI state
            self.scan_active = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_var.set(100)
            
    def display_results(self, results):
        """
        Display scan results in the tree view
        """
        for host, host_results in results:
            if isinstance(host_results, list):
                for i, result in enumerate(host_results):
                    if result.get('state') == 'open':
                        self.results_tree.insert('', 'end', text=str(len(self.results_tree.get_children()) + 1),
                                                values=(
                                                    result.get('host', host),
                                                    result.get('port', ''),
                                                    result.get('state', ''),
                                                    result.get('service', ''),
                                                    result.get('version', ''),
                                                    result.get('banner', '')[:100] + ('...' if len(result.get('banner', '')) > 100 else '')
                                                ))
                                                
        # Update statistics
        total_results = len(self.results_tree.get_children())
        self.stats_var.set(f"Total open ports found: {total_results}")
        
    def stop_scan(self):
        """
        Stop the current scan
        """
        if self.scan_active:
            self.scanner.stop_scan()
            self.status_var.set("Stopping scan...")
            
    def clear_results(self):
        """
        Clear all scan results
        """
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scanner.clear_results()
        self.status_var.set("Results cleared")
        self.stats_var.set("")
        self.progress_var.set(0)
        
    def export_results(self):
        """
        Export scan results
        """
        if not self.results_tree.get_children():
            messagebox.showwarning("Warning", "No results to export")
            return
            
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt")
            ]
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    results_json = self.scanner.export_results('json')
                    with open(file_path, 'w') as f:
                        f.write(results_json)
                # Add other export formats as needed
                
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                
    def copy_host(self):
        """Copy selected host to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            host = self.results_tree.item(selection[0])['values'][0]
            self.frame.clipboard_clear()
            self.frame.clipboard_append(host)
            
    def copy_port(self):
        """Copy selected port to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            port = self.results_tree.item(selection[0])['values'][1]
            self.frame.clipboard_clear()
            self.frame.clipboard_append(str(port))
            
    def copy_banner(self):
        """Copy selected banner to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            banner = self.results_tree.item(selection[0])['values'][5]
            self.frame.clipboard_clear()
            self.frame.clipboard_append(banner)
            
    def rescan_port(self):
        """Rescan selected port"""
        selection = self.results_tree.selection()
        if selection:
            values = self.results_tree.item(selection[0])['values']
            host, port = values[0], int(values[1])
            messagebox.showinfo("Info", f"Rescanning {host}:{port}...")
            # Implement rescan logic
            
    def remove_entry(self):
        """Remove selected entry"""
        selection = self.results_tree.selection()
        if selection:
            self.results_tree.delete(selection[0])
