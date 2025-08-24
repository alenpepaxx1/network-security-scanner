#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL Analysis Tab - GUI Component
User interface for SSL/TLS certificate analysis
Author: Alen Pepa
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from datetime import datetime
from typing import List, Dict

from core.ssl_analyzer import SSLAnalyzer
from utils.logger import get_logger

class SSLAnalysisTab:
    """
    SSL analysis tab interface
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.logger = get_logger()
        self.ssl_analyzer = SSLAnalyzer()
        self.analysis_thread = None
        self.analysis_active = False
        
        self.create_widgets()
        
    def create_widgets(self):
        """
        Create tab widgets
        """
        self.frame = ttk.Frame(self.parent, padding="10")
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(2, weight=1)
        
        # Target configuration
        self.create_target_section()
        
        # Control buttons
        self.create_control_section()
        
        # Results display
        self.create_results_section()
        
        # Status section
        self.create_status_section()
        
    def create_target_section(self):
        """
        Create SSL target configuration
        """
        target_frame = ttk.LabelFrame(self.frame, text="SSL Target Configuration", padding="5")
        target_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        target_frame.columnconfigure(1, weight=1)
        
        # Single target or batch
        ttk.Label(target_frame, text="Analysis Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.analysis_type = ttk.Combobox(target_frame, values=["Single Target", "Batch Analysis", "From Port Scan"], 
                                         state="readonly", width=15)
        self.analysis_type.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.analysis_type.set("Single Target")
        
        # Target input
        ttk.Label(target_frame, text="Target:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.target_entry = ttk.Entry(target_frame, width=25)
        self.target_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        self.target_entry.insert(0, "google.com:443")
        
        # Port input
        ttk.Label(target_frame, text="Port:").grid(row=0, column=4, sticky=tk.W, padx=(10, 5))
        self.port_entry = ttk.Entry(target_frame, width=8)
        self.port_entry.grid(row=0, column=5, sticky=tk.W)
        self.port_entry.insert(0, "443")
        
        # Batch input area
        self.batch_frame = ttk.LabelFrame(target_frame, text="Batch Targets (one per line)", padding="5")
        self.batch_frame.grid(row=1, column=0, columnspan=6, sticky=(tk.W, tk.E), pady=(10, 0))
        self.batch_frame.columnconfigure(0, weight=1)
        
        self.batch_text = scrolledtext.ScrolledText(self.batch_frame, height=4, width=60)
        self.batch_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.batch_text.insert('1.0', "google.com:443\nfacebook.com:443\ngithub.com:443")
        self.batch_frame.grid_remove()  # Hide initially
        
        # Update UI based on analysis type
        def update_analysis_type(event):
            analysis_type = self.analysis_type.get()
            if analysis_type == "Batch Analysis":
                self.batch_frame.grid()
                self.target_entry.config(state="disabled")
                self.port_entry.config(state="disabled")
            else:
                self.batch_frame.grid_remove()
                self.target_entry.config(state="normal")
                self.port_entry.config(state="normal")
                
        self.analysis_type.bind("<<ComboboxSelected>>", update_analysis_type)
        
    def create_control_section(self):
        """
        Create control buttons
        """
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Analyze button
        self.analyze_button = ttk.Button(control_frame, text="🔐 Analyze SSL", 
                                        command=self.start_analysis, style="Accent.TButton")
        self.analyze_button.grid(row=0, column=0, padx=(0, 5))
        
        # Stop button
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop Analysis", 
                                     command=self.stop_analysis, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=(0, 5))
        
        # Clear button
        self.clear_button = ttk.Button(control_frame, text="🗑 Clear Results", 
                                      command=self.clear_results)
        self.clear_button.grid(row=0, column=2, padx=(0, 5))
        
        # Export button
        self.export_button = ttk.Button(control_frame, text="📁 Export Analysis", 
                                       command=self.export_results)
        self.export_button.grid(row=0, column=3)
        
    def create_results_section(self):
        """
        Create results display with detailed SSL information
        """
        results_frame = ttk.LabelFrame(self.frame, text="SSL Analysis Results", padding="5")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Create notebook for detailed results
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Certificate overview tab
        self.cert_overview_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.cert_overview_frame, text="📜 Certificate Overview")
        
        # Security analysis tab
        self.security_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.security_frame, text="🛡️ Security Analysis")
        
        # Vulnerabilities tab
        self.vulns_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.vulns_frame, text="⚠️ Vulnerabilities")
        
        # Raw certificate tab
        self.raw_cert_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.raw_cert_frame, text="📄 Raw Certificate")
        
        self.create_results_tabs()
        
    def create_results_tabs(self):
        """
        Create content for each results tab
        """
        # Certificate Overview
        self.cert_text = scrolledtext.ScrolledText(self.cert_overview_frame, wrap=tk.WORD)
        self.cert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Security Analysis
        self.security_text = scrolledtext.ScrolledText(self.security_frame, wrap=tk.WORD)
        self.security_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Vulnerabilities
        self.vulns_text = scrolledtext.ScrolledText(self.vulns_frame, wrap=tk.WORD)
        self.vulns_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Raw Certificate
        self.raw_cert_text = scrolledtext.ScrolledText(self.raw_cert_frame, wrap=tk.WORD, font=("Courier", 9))
        self.raw_cert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_status_section(self):
        """
        Create status section
        """
        status_frame = ttk.Frame(self.frame)
        status_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready for SSL analysis")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
    def start_analysis(self):
        """
        Start SSL analysis
        """
        if self.analysis_active:
            return
            
        # Get targets
        analysis_type = self.analysis_type.get()
        targets = []
        
        if analysis_type == "Single Target":
            hostname = self.target_entry.get().strip()
            port = int(self.port_entry.get().strip())
            if ':' in hostname:
                hostname, port = hostname.split(':', 1)
                port = int(port)
            targets = [(hostname, port)]
        elif analysis_type == "Batch Analysis":
            batch_text = self.batch_text.get('1.0', tk.END).strip()
            for line in batch_text.split('\n'):
                line = line.strip()
                if line and ':' in line:
                    hostname, port = line.split(':', 1)
                    targets.append((hostname.strip(), int(port.strip())))
                    
        if not targets:
            messagebox.showerror("Error", "No valid targets specified")
            return
            
        # Update UI state
        self.analysis_active = True
        self.analyze_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self.status_var.set("Starting SSL analysis...")
        
        # Start analysis in separate thread
        self.analysis_thread = threading.Thread(
            target=self.run_analysis,
            args=(targets,),
            daemon=True
        )
        self.analysis_thread.start()
        
    def run_analysis(self, targets: List[tuple]):
        """
        Run SSL analysis process
        """
        try:
            def progress_callback(completed, total):
                progress = (completed / total) * 100
                self.progress_var.set(progress)
                self.status_var.set(f"Analyzing... {completed}/{total} targets")
                
            if len(targets) == 1:
                # Single target analysis
                hostname, port = targets[0]
                result = self.ssl_analyzer.analyze_certificate(hostname, port)
                self.display_ssl_results(result)
            else:
                # Batch analysis
                results = self.ssl_analyzer.batch_analyze(targets, progress_callback)
                self.display_batch_results(results)
                
            self.status_var.set(f"SSL analysis completed for {len(targets)} target(s)")
            
        except Exception as e:
            self.status_var.set(f"SSL analysis failed: {str(e)}")
            self.logger.error(f"SSL analysis failed: {e}")
            
        finally:
            # Reset UI state
            self.analysis_active = False
            self.analyze_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_var.set(100)
            
    def display_ssl_results(self, result: Dict):
        """
        Display SSL analysis results for single target
        """
        # Clear previous results
        self.cert_text.delete('1.0', tk.END)
        self.security_text.delete('1.0', tk.END)
        self.vulns_text.delete('1.0', tk.END)
        self.raw_cert_text.delete('1.0', tk.END)
        
        hostname = result.get('hostname', 'Unknown')
        port = result.get('port', 443)
        
        # Certificate Overview
        cert_info = result.get('certificate', {})
        if cert_info:
            overview = f"SSL Certificate Analysis for {hostname}:{port}\n"
            overview += "=" * 50 + "\n\n"
            
            # Subject information
            subject = cert_info.get('subject', {})
            overview += "📋 CERTIFICATE SUBJECT:\n"
            overview += f"   Common Name: {subject.get('common_name', 'N/A')}\n"
            overview += f"   Organization: {subject.get('organization', 'N/A')}\n"
            overview += f"   Country: {subject.get('country', 'N/A')}\n\n"
            
            # Issuer information
            issuer = cert_info.get('issuer', {})
            overview += "🏢 CERTIFICATE ISSUER:\n"
            overview += f"   Common Name: {issuer.get('common_name', 'N/A')}\n"
            overview += f"   Organization: {issuer.get('organization', 'N/A')}\n\n"
            
            # Validity information
            validity = cert_info.get('validity', {})
            overview += "📅 VALIDITY PERIOD:\n"
            overview += f"   Valid From: {validity.get('not_before', 'N/A')}\n"
            overview += f"   Valid Until: {validity.get('not_after', 'N/A')}\n"
            overview += f"   Days Until Expiry: {validity.get('days_until_expiry', 'N/A')}\n"
            overview += f"   Status: {'❌ EXPIRED' if validity.get('is_expired') else '✅ Valid'}\n\n"
            
            # Public key information
            public_key = cert_info.get('public_key', {})
            overview += "🔑 PUBLIC KEY:\n"
            overview += f"   Algorithm: {public_key.get('algorithm', 'N/A')}\n"
            overview += f"   Key Size: {public_key.get('key_size', 'N/A')} bits\n\n"
            
            # Extensions
            extensions = cert_info.get('extensions', {})
            if extensions:
                overview += "📋 CERTIFICATE EXTENSIONS:\n"
                for ext_name, ext_value in extensions.items():
                    overview += f"   {ext_name}: {ext_value}\n"
                    
            self.cert_text.insert('1.0', overview)
            
        # Security Analysis
        security = result.get('security_analysis', {})
        if security:
            security_text = f"Security Analysis for {hostname}:{port}\n"
            security_text += "=" * 50 + "\n\n"
            
            rating = security.get('overall_rating', 'unknown')
            security_text += f"🎯 OVERALL RATING: {rating.upper()}\n\n"
            
            # Strengths
            strengths = security.get('strengths', [])
            if strengths:
                security_text += "✅ STRENGTHS:\n"
                for strength in strengths:
                    security_text += f"   • {strength}\n"
                security_text += "\n"
                
            # Issues
            issues = security.get('issues', [])
            if issues:
                security_text += "⚠️ SECURITY ISSUES:\n"
                for issue in issues:
                    security_text += f"   • {issue}\n"
                security_text += "\n"
                
            self.security_text.insert('1.0', security_text)
            
        # Vulnerabilities
        vulnerabilities = result.get('vulnerabilities', [])
        if vulnerabilities:
            vulns_text = f"Vulnerability Assessment for {hostname}:{port}\n"
            vulns_text += "=" * 50 + "\n\n"
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown').upper()
                vuln_type = vuln.get('type', 'Unknown')
                description = vuln.get('description', 'No description')
                recommendation = vuln.get('recommendation', 'No recommendation')
                
                vulns_text += f"🚨 {severity} - {vuln_type}\n"
                vulns_text += f"   Description: {description}\n"
                vulns_text += f"   Recommendation: {recommendation}\n\n"
                
            self.vulns_text.insert('1.0', vulns_text)
        else:
            self.vulns_text.insert('1.0', f"No vulnerabilities detected for {hostname}:{port}\n\n✅ SSL configuration appears secure!")
            
        # Raw certificate
        raw_cert = cert_info.get('pem', '')
        if raw_cert:
            self.raw_cert_text.insert('1.0', raw_cert)
            
    def display_batch_results(self, results: Dict):
        """
        Display batch analysis results
        """
        # For batch results, show summary in overview
        batch_summary = "Batch SSL Analysis Results\n"
        batch_summary += "=" * 50 + "\n\n"
        
        total_analyzed = len(results)
        secure_count = 0
        issues_count = 0
        
        for target, result in results.items():
            security = result.get('security_analysis', {})
            rating = security.get('overall_rating', 'unknown')
            
            if rating in ['excellent', 'good']:
                secure_count += 1
            elif rating in ['fair', 'poor']:
                issues_count += 1
                
            batch_summary += f"🔗 {target}:\n"
            batch_summary += f"   Rating: {rating.upper()}\n"
            batch_summary += f"   Issues: {len(security.get('issues', []))}\n"
            batch_summary += f"   Vulnerabilities: {len(result.get('vulnerabilities', []))}\n\n"
            
        # Summary statistics
        summary_stats = f"📊 BATCH SUMMARY:\n"
        summary_stats += f"   Total Analyzed: {total_analyzed}\n"
        summary_stats += f"   Secure Configurations: {secure_count}\n"
        summary_stats += f"   Configurations with Issues: {issues_count}\n\n"
        
        self.cert_text.delete('1.0', tk.END)
        self.cert_text.insert('1.0', summary_stats + batch_summary)
        
    def stop_analysis(self):
        """
        Stop SSL analysis
        """
        if self.analysis_active:
            self.analysis_active = False
            self.status_var.set("Stopping analysis...")
            
    def clear_results(self):
        """
        Clear all results
        """
        self.cert_text.delete('1.0', tk.END)
        self.security_text.delete('1.0', tk.END)
        self.vulns_text.delete('1.0', tk.END)
        self.raw_cert_text.delete('1.0', tk.END)
        self.status_var.set("Results cleared")
        self.progress_var.set(0)
        
    def export_results(self):
        """
        Export SSL analysis results
        """
        cert_content = self.cert_text.get('1.0', tk.END).strip()
        if not cert_content:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("HTML files", "*.html"),
                ("PDF files", "*.pdf")
            ]
        )
        
        if file_path:
            try:
                if file_path.endswith('.txt'):
                    with open(file_path, 'w') as f:
                        f.write(cert_content + "\n\n")
                        f.write("SECURITY ANALYSIS:\n")
                        f.write(self.security_text.get('1.0', tk.END))
                        f.write("\n\nVULNERABILITIES:\n")
                        f.write(self.vulns_text.get('1.0', tk.END))
                        
                messagebox.showinfo("Success", f"SSL analysis exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")