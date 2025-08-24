#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reports Tab - GUI Component
User interface for reports generation and export
Author: Alen Pepa
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import csv
from datetime import datetime
from typing import Dict, List

from utils.report_generator import ReportGenerator
from utils.logger import get_logger

class ReportsTab:
    """
    Reports and export tab interface
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.logger = get_logger()
        self.report_generator = ReportGenerator()
        self.scan_data = {
            'port_scans': [],
            'network_discovery': [],
            'ssl_analysis': [],
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '1.0',
                'operator': 'Security Analyst'
            }
        }
        
        self.create_widgets()
        
    def create_widgets(self):
        """
        Create tab widgets
        """
        self.frame = ttk.Frame(self.parent, padding="10")
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(2, weight=1)
        
        # Report configuration
        self.create_config_section()
        
        # Report content preview
        self.create_preview_section()
        
        # Export options
        self.create_export_section()
        
    def create_config_section(self):
        """
        Create report configuration section
        """
        config_frame = ttk.LabelFrame(self.frame, text="Report Configuration", padding="5")
        config_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Report type
        ttk.Label(config_frame, text="Report Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.report_type = ttk.Combobox(config_frame, values=["Executive Summary", "Technical Report", "Detailed Analysis"], 
                                       state="readonly", width=18)
        self.report_type.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.report_type.set("Technical Report")
        
        # Include options
        include_frame = ttk.Frame(config_frame)
        include_frame.grid(row=0, column=2, columnspan=2, sticky=tk.W)
        
        self.include_port_scans = tk.BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="Port Scans", variable=self.include_port_scans).grid(row=0, column=0, sticky=tk.W)
        
        self.include_network_discovery = tk.BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="Network Discovery", variable=self.include_network_discovery).grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        self.include_ssl_analysis = tk.BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="SSL Analysis", variable=self.include_ssl_analysis).grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        
        # Report metadata
        metadata_frame = ttk.Frame(config_frame)
        metadata_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        metadata_frame.columnconfigure(1, weight=1)
        metadata_frame.columnconfigure(3, weight=1)
        
        ttk.Label(metadata_frame, text="Report Title:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.report_title = ttk.Entry(metadata_frame, width=30)
        self.report_title.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 20))
        self.report_title.insert(0, f"Network Security Assessment - {datetime.now().strftime('%Y-%m-%d')}")
        
        ttk.Label(metadata_frame, text="Analyst:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.analyst_name = ttk.Entry(metadata_frame, width=20)
        self.analyst_name.grid(row=0, column=3, sticky=(tk.W, tk.E))
        self.analyst_name.insert(0, "Alen Pepa")
        
    def create_preview_section(self):
        """
        Create report preview section
        """
        preview_frame = ttk.LabelFrame(self.frame, text="Report Preview", padding="5")
        preview_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        preview_frame.columnconfigure(0, weight=1)
        
        # Control buttons for preview
        preview_controls = ttk.Frame(preview_frame)
        preview_controls.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Button(preview_controls, text="📋 Generate Preview", 
                  command=self.generate_preview).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(preview_controls, text="🔄 Refresh Data", 
                  command=self.refresh_scan_data).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(preview_controls, text="📊 Show Statistics", 
                  command=self.show_statistics).grid(row=0, column=2)
        
    def create_export_section(self):
        """
        Create export options section
        """
        export_frame = ttk.LabelFrame(self.frame, text="Export Options", padding="5")
        export_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        export_frame.columnconfigure(0, weight=1)
        export_frame.rowconfigure(1, weight=1)
        
        # Export format selection
        format_frame = ttk.Frame(export_frame)
        format_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(format_frame, text="Export Format:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        # Export format buttons
        ttk.Button(format_frame, text="📄 HTML Report", 
                  command=lambda: self.export_report('html')).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(format_frame, text="📕 PDF Report", 
                  command=lambda: self.export_report('pdf')).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(format_frame, text="📊 JSON Data", 
                  command=lambda: self.export_report('json')).grid(row=0, column=3, padx=(0, 5))
        ttk.Button(format_frame, text="📋 CSV Data", 
                  command=lambda: self.export_report('csv')).grid(row=0, column=4)
        
        # Report content area
        self.report_text = scrolledtext.ScrolledText(export_frame, wrap=tk.WORD, height=15)
        self.report_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Insert initial content
        self.report_text.insert('1.0', "📊 Network Security Assessment Report\n\n" +
                                "Click 'Generate Preview' to create a report based on current scan data.\n\n" +
                                "📋 Available Data:\n" +
                                "• Port scan results\n" +
                                "• Network discovery data\n" +
                                "• SSL certificate analysis\n" +
                                "• Vulnerability assessments\n\n" +
                                "🎯 Report Features:\n" +
                                "• Executive summary\n" +
                                "• Technical findings\n" +
                                "• Risk assessment\n" +
                                "• Remediation recommendations")
        
    def generate_preview(self):
        """
        Generate report preview
        """
        try:
            # Refresh scan data first
            self.refresh_scan_data()
            
            # Generate report content
            report_config = {
                'title': self.report_title.get(),
                'analyst': self.analyst_name.get(),
                'type': self.report_type.get(),
                'include_port_scans': self.include_port_scans.get(),
                'include_network_discovery': self.include_network_discovery.get(),
                'include_ssl_analysis': self.include_ssl_analysis.get()
            }
            
            report_content = self.report_generator.generate_text_report(self.scan_data, report_config)
            
            # Display in preview area
            self.report_text.delete('1.0', tk.END)
            self.report_text.insert('1.0', report_content)
            
            messagebox.showinfo("Success", "Report preview generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate preview: {str(e)}")
            self.logger.error(f"Report preview generation failed: {e}")
            
    def refresh_scan_data(self):
        """
        Refresh scan data from other tabs
        """
        try:
            # This would normally collect data from other tabs
            # For now, we'll use sample data
            self.scan_data['metadata']['scan_date'] = datetime.now().isoformat()
            self.scan_data['metadata']['total_targets'] = 0
            self.scan_data['metadata']['total_open_ports'] = 0
            
            # In a real implementation, this would collect actual data from scanner tabs
            self.logger.info("Scan data refreshed")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh scan data: {e}")
            
    def show_statistics(self):
        """
        Show scan statistics in popup window
        """
        stats_window = tk.Toplevel(self.frame)
        stats_window.title("Scan Statistics")
        stats_window.geometry("500x400")
        stats_window.resizable(True, True)
        
        # Statistics content
        stats_text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Generate statistics
        stats_content = self.generate_statistics()
        stats_text.insert('1.0', stats_content)
        
    def generate_statistics(self) -> str:
        """
        Generate scan statistics summary
        """
        stats = "📊 NETWORK SECURITY SCAN STATISTICS\n"
        stats += "=" * 50 + "\n\n"
        
        # Scan metadata
        metadata = self.scan_data.get('metadata', {})
        stats += f"📅 Scan Date: {metadata.get('scan_date', 'N/A')}\n"
        stats += f"👤 Analyst: {metadata.get('operator', 'N/A')}\n"
        stats += f"🔧 Scanner Version: {metadata.get('scanner_version', 'N/A')}\n\n"
        
        # Port scan statistics
        port_scans = self.scan_data.get('port_scans', [])
        if port_scans:
            stats += "🔍 PORT SCAN STATISTICS:\n"
            stats += f"   Total Hosts Scanned: {len(port_scans)}\n"
            total_ports = sum(len(scan.get('results', [])) for scan in port_scans)
            open_ports = sum(len([r for r in scan.get('results', []) if r.get('state') == 'open']) for scan in port_scans)
            stats += f"   Total Ports Scanned: {total_ports}\n"
            stats += f"   Open Ports Found: {open_ports}\n"
            stats += f"   Success Rate: {(open_ports/total_ports*100):.1f}%\n\n"
        
        # Network discovery statistics
        discovery_data = self.scan_data.get('network_discovery', [])
        if discovery_data:
            stats += "🌐 NETWORK DISCOVERY STATISTICS:\n"
            stats += f"   Total Networks Scanned: {len(discovery_data)}\n"
            total_hosts = sum(len(net.get('hosts', [])) for net in discovery_data)
            stats += f"   Active Hosts Found: {total_hosts}\n"
            stats += f"   Average Response Time: {self.calculate_avg_response_time(discovery_data):.2f}ms\n\n"
        
        # SSL analysis statistics
        ssl_data = self.scan_data.get('ssl_analysis', [])
        if ssl_data:
            stats += "🔐 SSL ANALYSIS STATISTICS:\n"
            stats += f"   Total Certificates Analyzed: {len(ssl_data)}\n"
            secure_certs = len([cert for cert in ssl_data if cert.get('security_analysis', {}).get('overall_rating') in ['excellent', 'good']])
            stats += f"   Secure Configurations: {secure_certs}\n"
            stats += f"   Certificates with Issues: {len(ssl_data) - secure_certs}\n"
            expiring_soon = len([cert for cert in ssl_data if cert.get('certificate', {}).get('validity', {}).get('expires_soon')])
            stats += f"   Expiring Soon (< 30 days): {expiring_soon}\n\n"
        
        # Overall security summary
        stats += "🎯 OVERALL SECURITY SUMMARY:\n"
        stats += f"   Total Scan Duration: {self.calculate_scan_duration()}\n"
        stats += f"   Critical Issues Found: {self.count_critical_issues()}\n"
        stats += f"   Recommendations Generated: {self.count_recommendations()}\n"
        
        return stats
        
    def calculate_avg_response_time(self, discovery_data: List[Dict]) -> float:
        """
        Calculate average response time from discovery data
        """
        response_times = []
        for net in discovery_data:
            for host in net.get('hosts', []):
                if host.get('response_time'):
                    response_times.append(float(host['response_time']))
        return sum(response_times) / len(response_times) if response_times else 0.0
        
    def calculate_scan_duration(self) -> str:
        """
        Calculate total scan duration
        """
        # This would calculate based on actual scan start/end times
        return "Estimated based on scan complexity"
        
    def count_critical_issues(self) -> int:
        """
        Count critical security issues across all scans
        """
        critical_count = 0
        
        # Count from SSL analysis
        for ssl_result in self.scan_data.get('ssl_analysis', []):
            vulns = ssl_result.get('vulnerabilities', [])
            critical_count += len([v for v in vulns if v.get('severity') == 'critical'])
            
        # Count from port scans (example: exposed critical services)
        critical_ports = [22, 23, 3389, 445, 1433, 3306]  # Example critical ports
        for port_scan in self.scan_data.get('port_scans', []):
            for result in port_scan.get('results', []):
                if result.get('state') == 'open' and result.get('port') in critical_ports:
                    critical_count += 1
                    
        return critical_count
        
    def count_recommendations(self) -> int:
        """
        Count total recommendations generated
        """
        total_recommendations = 0
        
        # Count from SSL analysis
        for ssl_result in self.scan_data.get('ssl_analysis', []):
            recommendations = ssl_result.get('recommendations', [])
            total_recommendations += len(recommendations)
            
        return total_recommendations
        
    def export_report(self, format_type: str):
        """
        Export report in specified format
        """
        if format_type in ['html', 'pdf']:
            file_ext = f".{format_type}"
            file_types = [(f"{format_type.upper()} files", f"*.{format_type}")]
        elif format_type == 'json':
            file_ext = ".json"
            file_types = [("JSON files", "*.json")]
        else:  # csv
            file_ext = ".csv"
            file_types = [("CSV files", "*.csv")]
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=file_ext,
            filetypes=file_types + [("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Refresh data before export
                self.refresh_scan_data()
                
                # Generate report
                report_config = {
                    'title': self.report_title.get(),
                    'analyst': self.analyst_name.get(),
                    'type': self.report_type.get(),
                    'include_port_scans': self.include_port_scans.get(),
                    'include_network_discovery': self.include_network_discovery.get(),
                    'include_ssl_analysis': self.include_ssl_analysis.get()
                }
                
                if format_type == 'html':
                    self.report_generator.generate_html_report(self.scan_data, report_config, file_path)
                elif format_type == 'pdf':
                    self.report_generator.generate_pdf_report(self.scan_data, report_config, file_path)
                elif format_type == 'json':
                    with open(file_path, 'w') as f:
                        json.dump(self.scan_data, f, indent=2)
                elif format_type == 'csv':
                    self.export_csv_data(file_path)
                    
                messagebox.showinfo("Success", f"Report exported successfully to {file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                self.logger.error(f"Report export failed: {e}")
                
    def export_csv_data(self, file_path: str):
        """
        Export data in CSV format
        """
        # Combine all scan results into CSV format
        all_data = []
        
        # Add port scan data
        for port_scan in self.scan_data.get('port_scans', []):
            for result in port_scan.get('results', []):
                all_data.append({
                    'type': 'port_scan',
                    'host': result.get('host'),
                    'port': result.get('port'),
                    'state': result.get('state'),
                    'service': result.get('service'),
                    'banner': result.get('banner', ''),
                    'timestamp': result.get('timestamp')
                })
                
        # Add network discovery data
        for net_discovery in self.scan_data.get('network_discovery', []):
            for host in net_discovery.get('hosts', []):
                all_data.append({
                    'type': 'network_discovery',
                    'host': host.get('host'),
                    'port': '',
                    'state': 'active',
                    'service': '',
                    'banner': host.get('hostname', ''),
                    'timestamp': host.get('timestamp')
                })
                
        # Write CSV
        with open(file_path, 'w', newline='') as f:
            if all_data:
                writer = csv.DictWriter(f, fieldnames=all_data[0].keys())
                writer.writeheader()
                writer.writerows(all_data)
                
    def clear_results(self):
        """
        Clear all report data
        """
        self.scan_data = {
            'port_scans': [],
            'network_discovery': [],
            'ssl_analysis': [],
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '1.0',
                'operator': 'Security Analyst'
            }
        }
        
        self.report_text.delete('1.0', tk.END)
        self.report_text.insert('1.0', "Report data cleared. Generate new scans to populate data.")
        
        self.logger.info("Report data cleared")