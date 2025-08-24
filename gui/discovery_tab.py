#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Discovery Tab - GUI Component
User interface for network discovery functionality
Author: Alen Pepa
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from datetime import datetime
from typing import List, Dict

from core.discovery import NetworkDiscovery
from utils.network_utils import get_local_interfaces
from utils.logger import get_logger

class NetworkDiscoveryTab:
    """
    Network discovery tab interface
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.logger = get_logger()
        self.discovery = NetworkDiscovery()
        self.discovery_thread = None
        self.discovery_active = False
        
        self.create_widgets()
        
    def create_widgets(self):
        """
        Create tab widgets
        """
        self.frame = ttk.Frame(self.parent, padding="10")
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(3, weight=1)
        
        # Network configuration
        self.create_network_section()
        
        # Discovery options
        self.create_options_section()
        
        # Control buttons
        self.create_control_section()
        
        # Results display
        self.create_results_section()
        
        # Status section
        self.create_status_section()
        
    def create_network_section(self):
        """
        Create network configuration section
        """
        network_frame = ttk.LabelFrame(self.frame, text="Network Configuration", padding="5")
        network_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        network_frame.columnconfigure(1, weight=1)
        
        # Network type
        ttk.Label(network_frame, text="Discovery Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.network_type = ttk.Combobox(network_frame, values=["Local Networks", "Custom Network", "IP Range"], 
                                        state="readonly", width=15)
        self.network_type.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.network_type.set("Local Networks")
        
        # Network input
        ttk.Label(network_frame, text="Target:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.network_entry = ttk.Entry(network_frame, width=25, state="disabled")
        self.network_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        # Auto-detect button
        self.detect_button = ttk.Button(network_frame, text="🔍 Auto-Detect", 
                                       command=self.auto_detect_networks, width=12)
        self.detect_button.grid(row=0, column=4, padx=(10, 0))
        
        # Examples
        network_examples = {
            "Local Networks": "Will auto-detect local network interfaces",
            "Custom Network": "Example: 192.168.1.0/24 or 10.0.0.0/8",
            "IP Range": "Example: 192.168.1.1-192.168.1.100"
        }
        
        self.network_example_label = ttk.Label(network_frame, text=network_examples["Local Networks"], 
                                              font=("Arial", 8), foreground="gray")
        self.network_example_label.grid(row=1, column=0, columnspan=5, sticky=tk.W, pady=(5, 0))
        
        # Update input based on type
        def update_network_input(event):
            net_type = self.network_type.get()
            if net_type == "Local Networks":
                self.network_entry.config(state="disabled")
                self.network_entry.delete(0, tk.END)
                self.detect_button.config(state="normal")
            else:
                self.network_entry.config(state="normal")
                self.detect_button.config(state="disabled")
                if net_type == "Custom Network":
                    self.network_entry.delete(0, tk.END)
                    self.network_entry.insert(0, "192.168.1.0/24")
                else:
                    self.network_entry.delete(0, tk.END)
                    self.network_entry.insert(0, "192.168.1.1-192.168.1.100")
            self.network_example_label.config(text=network_examples[net_type])
            
        self.network_type.bind("<<ComboboxSelected>>", update_network_input)
        
    def create_options_section(self):
        """
        Create discovery options section
        """
        options_frame = ttk.LabelFrame(self.frame, text="Discovery Options", padding="5")
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Discovery method
        ttk.Label(options_frame, text="Method:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.discovery_method = ttk.Combobox(options_frame, values=["ICMP Ping", "ARP Scan", "TCP Connect"], 
                                           state="readonly", width=12)
        self.discovery_method.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.discovery_method.set("ICMP Ping")
        
        # Additional options
        self.resolve_hostnames = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Resolve Hostnames", 
                       variable=self.resolve_hostnames).grid(row=0, column=2, sticky=tk.W, padx=(0, 20))
                       
        self.detect_os = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="OS Detection", 
                       variable=self.detect_os).grid(row=0, column=3, sticky=tk.W)
        
        # Performance options
        ttk.Label(options_frame, text="Max Threads:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        self.thread_count = tk.IntVar(value=50)
        thread_spin = ttk.Spinbox(options_frame, from_=1, to=200, width=10, textvariable=self.thread_count)
        thread_spin.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        
        ttk.Label(options_frame, text="Timeout (sec):").grid(row=1, column=2, sticky=tk.W, padx=(20, 5), pady=(10, 0))
        self.timeout = tk.IntVar(value=2)
        timeout_spin = ttk.Spinbox(options_frame, from_=1, to=30, width=10, textvariable=self.timeout)
        timeout_spin.grid(row=1, column=3, sticky=tk.W, pady=(10, 0))
        
    def create_control_section(self):
        """
        Create control buttons
        """
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=2, column=0, columnspan=2, pady=(0, 10))
        
        # Start discovery button
        self.start_button = ttk.Button(control_frame, text="🌐 Start Discovery", 
                                      command=self.start_discovery, style="Accent.TButton")
        self.start_button.grid(row=0, column=0, padx=(0, 5))
        
        # Stop button
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop Discovery", 
                                     command=self.stop_discovery, state="disabled")
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
        Create results display
        """
        results_frame = ttk.LabelFrame(self.frame, text="Discovery Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results treeview
        columns = ('IP Address', 'Hostname', 'Response Time', 'Method', 'Status', 'MAC Address')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=12)
        
        # Configure columns
        self.results_tree.heading('#0', text='#')
        self.results_tree.column('#0', width=40)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == 'IP Address':
                self.results_tree.column(col, width=120)
            elif col == 'Hostname':
                self.results_tree.column(col, width=200)
            elif col == 'Response Time':
                self.results_tree.column(col, width=100)
            elif col == 'Method':
                self.results_tree.column(col, width=80)
            elif col == 'Status':
                self.results_tree.column(col, width=80)
            else:  # MAC Address
                self.results_tree.column(col, width=150)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
    def create_status_section(self):
        """
        Create status and progress section
        """
        status_frame = ttk.Frame(self.frame)
        status_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready for network discovery")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
        # Statistics
        self.stats_var = tk.StringVar(value="")
        self.stats_label = ttk.Label(status_frame, textvariable=self.stats_var, font=("Arial", 8))
        self.stats_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
        
    def auto_detect_networks(self):
        """
        Auto-detect local networks
        """
        try:
            interfaces = get_local_interfaces()
            if interfaces:
                networks = [iface['network'] for iface in interfaces if iface.get('network')]
                if networks:
                    # Show selection dialog
                    self.show_network_selection(networks)
                else:
                    messagebox.showwarning("Warning", "No local networks detected")
            else:
                messagebox.showerror("Error", "Failed to detect network interfaces")
        except Exception as e:
            messagebox.showerror("Error", f"Network detection failed: {str(e)}")
            
    def show_network_selection(self, networks: List[str]):
        """
        Show network selection dialog
        """
        selection_window = tk.Toplevel(self.frame)
        selection_window.title("Select Network")
        selection_window.geometry("400x300")
        selection_window.resizable(False, False)
        
        ttk.Label(selection_window, text="Detected Networks:", font=("Arial", 10, "bold")).pack(pady=10)
        
        # Network listbox
        listbox_frame = ttk.Frame(selection_window)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        listbox = tk.Listbox(listbox_frame)
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        
        for network in networks:
            listbox.insert(tk.END, network)
        
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(selection_window)
        button_frame.pack(pady=10)
        
        def select_network():
            selection = listbox.curselection()
            if selection:
                selected_network = networks[selection[0]]
                self.network_entry.config(state="normal")
                self.network_entry.delete(0, tk.END)
                self.network_entry.insert(0, selected_network)
                self.network_entry.config(state="disabled")
                selection_window.destroy()
            else:
                messagebox.showwarning("Warning", "Please select a network")
                
        ttk.Button(button_frame, text="Select", command=select_network).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=selection_window.destroy).pack(side=tk.LEFT)
        
    def start_discovery(self):
        """
        Start network discovery
        """
        if self.discovery_active:
            return
            
        # Get target network
        network_type = self.network_type.get()
        
        if network_type == "Local Networks":
            # Use auto-detected networks
            interfaces = get_local_interfaces()
            if not interfaces:
                messagebox.showerror("Error", "No local networks detected")
                return
            target_networks = [iface['network'] for iface in interfaces if iface.get('network')]
        else:
            target = self.network_entry.get().strip()
            if not target:
                messagebox.showerror("Error", "Please specify a target network")
                return
            target_networks = [target]
            
        # Update UI state
        self.discovery_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self.status_var.set("Starting discovery...")
        
        # Configure discovery engine
        self.discovery.max_threads = self.thread_count.get()
        self.discovery.timeout = self.timeout.get()
        
        # Start discovery in separate thread
        self.discovery_thread = threading.Thread(
            target=self.run_discovery,
            args=(target_networks,),
            daemon=True
        )
        self.discovery_thread.start()
        
    def run_discovery(self, networks: List[str]):
        """
        Run discovery process
        """
        try:
            all_hosts = []
            method = self.discovery_method.get().lower().replace(' ', '_')
            
            for i, network in enumerate(networks):
                if not self.discovery_active:
                    break
                    
                self.status_var.set(f"Discovering hosts in {network}...")
                
                def progress_callback(completed, total):
                    overall_progress = ((i * 100) + (completed / total * 100)) / len(networks)
                    self.progress_var.set(overall_progress)
                    self.status_var.set(f"Scanning {network}: {completed}/{total} hosts")
                
                hosts = self.discovery.discover_hosts(network, method, progress_callback)
                all_hosts.extend(hosts)
                
            # Display results
            self.display_discovery_results(all_hosts)
            self.status_var.set(f"Discovery completed - {len(all_hosts)} active hosts found")
            
        except Exception as e:
            self.status_var.set(f"Discovery failed: {str(e)}")
            self.logger.error(f"Discovery failed: {e}")
            
        finally:
            # Reset UI state
            self.discovery_active = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_var.set(100)
            
    def display_discovery_results(self, hosts: List[Dict]):
        """
        Display discovery results
        """
        for i, host in enumerate(hosts):
            self.results_tree.insert('', 'end', text=str(i + 1),
                                    values=(
                                        host.get('host', ''),
                                        host.get('hostname', 'N/A'),
                                        f"{host.get('response_time', 0):.2f}ms" if host.get('response_time') else 'N/A',
                                        host.get('method', ''),
                                        'Active',
                                        host.get('mac_address', 'N/A')
                                    ))
        
        # Update statistics
        total_hosts = len(hosts)
        unique_subnets = len(set(host['host'].rsplit('.', 1)[0] for host in hosts))
        avg_response = sum(h.get('response_time', 0) for h in hosts) / len(hosts) if hosts else 0
        
        self.stats_var.set(f"Total: {total_hosts} hosts | Subnets: {unique_subnets} | Avg Response: {avg_response:.2f}ms")
        
    def stop_discovery(self):
        """
        Stop discovery process
        """
        if self.discovery_active:
            self.discovery.stop_discovery()
            self.status_var.set("Stopping discovery...")
            
    def clear_results(self):
        """
        Clear all results
        """
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.status_var.set("Results cleared")
        self.stats_var.set("")
        self.progress_var.set(0)
        
    def export_results(self):
        """
        Export discovery results
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
                # Extract data from tree
                results = []
                for item in self.results_tree.get_children():
                    values = self.results_tree.item(item)['values']
                    results.append({
                        'ip': values[0],
                        'hostname': values[1],
                        'response_time': values[2],
                        'method': values[3],
                        'status': values[4],
                        'mac_address': values[5]
                    })
                
                if file_path.endswith('.json'):
                    import json
                    with open(file_path, 'w') as f:
                        json.dump(results, f, indent=2)
                elif file_path.endswith('.csv'):
                    import csv
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=results[0].keys())
                        writer.writeheader()
                        writer.writerows(results)
                        
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
