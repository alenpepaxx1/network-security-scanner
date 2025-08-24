#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator - Simplified Version
Basic report generation for Windows compatibility
Author: Alen Pepa
"""

import json
import os
from datetime import datetime
from typing import Dict, List

from utils.logger import get_logger

class ReportGenerator:
    """
    Simplified report generator for scan results
    """
    
    def __init__(self):
        self.logger = get_logger()
        
    def generate_text_report(self, scan_data: Dict, config: Dict) -> str:
        """
        Generate text-based report
        """
        try:
            report = f"""
🔒 {config.get('title', 'Network Security Assessment Report')}
{'=' * len(config.get('title', 'Network Security Assessment Report')) + 4}

📋 EXECUTIVE SUMMARY
───────────────────

Scan Date: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
Analyst: {config.get('analyst', 'Security Analyst')}
Report Type: {config.get('type', 'Technical Report')}
Scanner Version: {scan_data.get('metadata', {}).get('scanner_version', '1.0')}

🎯 KEY FINDINGS
──────────────

• Total Networks Scanned: {len(scan_data.get('network_discovery', []))}
• Total Hosts Discovered: {self.count_total_hosts(scan_data)}
• Total Open Ports Found: {self.count_open_ports(scan_data)}
• SSL Certificates Analyzed: {len(scan_data.get('ssl_analysis', []))}
• Critical Issues Identified: {self.count_critical_issues(scan_data)}

🚨 RISK ASSESSMENT
─────────────────

{self.generate_risk_assessment(scan_data)}

📊 DETAILED FINDINGS
───────────────────

"""
            
            # Add detailed sections based on configuration
            if config.get('include_port_scans') and scan_data.get('port_scans'):
                report += self.generate_port_scan_section(scan_data.get('port_scans', []))
                
            if config.get('include_network_discovery') and scan_data.get('network_discovery'):
                report += self.generate_network_discovery_section(scan_data.get('network_discovery', []))
                
            if config.get('include_ssl_analysis') and scan_data.get('ssl_analysis'):
                report += self.generate_ssl_analysis_section(scan_data.get('ssl_analysis', []))
                
            # Add recommendations
            report += self.generate_recommendations_section(scan_data)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating text report: {e}")
            return f"Error generating report: {str(e)}"
        
    def count_total_hosts(self, scan_data: Dict) -> int:
        """
        Count total unique hosts across all scans
        """
        hosts = set()
        
        try:
            # From port scans
            for scan in scan_data.get('port_scans', []):
                if 'target' in scan:
                    hosts.add(scan['target'])
                    
            # From network discovery
            for discovery in scan_data.get('network_discovery', []):
                for host in discovery.get('hosts', []):
                    if 'host' in host:
                        hosts.add(host['host'])
        except Exception as e:
            self.logger.error(f"Error counting hosts: {e}")
            
        return len(hosts)
        
    def count_open_ports(self, scan_data: Dict) -> int:
        """
        Count total open ports found
        """
        open_ports = 0
        
        try:
            for scan in scan_data.get('port_scans', []):
                for result in scan.get('results', []):
                    if result.get('state') == 'open':
                        open_ports += 1
        except Exception as e:
            self.logger.error(f"Error counting open ports: {e}")
                    
        return open_ports
        
    def count_critical_issues(self, scan_data: Dict) -> int:
        """
        Count critical security issues
        """
        critical_issues = 0
        
        try:
            # From SSL analysis
            for ssl_result in scan_data.get('ssl_analysis', []):
                vulns = ssl_result.get('vulnerabilities', [])
                critical_issues += len([v for v in vulns if v.get('severity') == 'critical'])
        except Exception as e:
            self.logger.error(f"Error counting critical issues: {e}")
            
        return critical_issues
        
    def generate_risk_assessment(self, scan_data: Dict) -> str:
        """
        Generate risk assessment summary
        """
        try:
            critical_issues = self.count_critical_issues(scan_data)
            open_ports = self.count_open_ports(scan_data)
            
            if critical_issues > 0:
                risk_level = "🔴 HIGH RISK"
                risk_desc = "Critical vulnerabilities detected that require immediate attention."
            elif open_ports > 10:
                risk_level = "🟡 MEDIUM RISK"
                risk_desc = "Multiple open ports detected. Review service exposure and security configurations."
            else:
                risk_level = "🟢 LOW RISK"
                risk_desc = "No critical issues detected. Continue monitoring and maintain security best practices."
                
            return f"Risk Level: {risk_level}\nAssessment: {risk_desc}"
        except Exception as e:
            self.logger.error(f"Error generating risk assessment: {e}")
            return "Risk assessment could not be generated"
        
    def generate_port_scan_section(self, port_scans: List[Dict]) -> str:
        """
        Generate port scan section of report
        """
        section = "\n🔍 PORT SCAN ANALYSIS\n"
        section += "─" * 20 + "\n\n"
        
        try:
            for i, scan in enumerate(port_scans, 1):
                target = scan.get('target', f'Target {i}')
                results = scan.get('results', [])
                open_results = [r for r in results if r.get('state') == 'open']
                
                section += f"Target {i}: {target}\n"
                section += f"Open Ports: {len(open_results)}/{len(results)}\n\n"
                
                if open_results:
                    section += "Open Ports Detected:\n"
                    for result in open_results[:10]:  # Limit to first 10
                        port = result.get('port')
                        service = result.get('service', 'unknown')
                        banner = result.get('banner', '')[:50]
                        section += f"   • Port {port} ({service}): {banner}\n"
                    
                    if len(open_results) > 10:
                        section += f"   ... and {len(open_results) - 10} more ports\n"
                    section += "\n"
        except Exception as e:
            self.logger.error(f"Error generating port scan section: {e}")
            section += "Error generating port scan details\n\n"
                
        return section
        
    def generate_network_discovery_section(self, discovery_data: List[Dict]) -> str:
        """
        Generate network discovery section
        """
        section = "\n🌐 NETWORK DISCOVERY ANALYSIS\n"
        section += "─" * 28 + "\n\n"
        
        try:
            for i, discovery in enumerate(discovery_data, 1):
                network = discovery.get('network', f'Network {i}')
                hosts = discovery.get('hosts', [])
                
                section += f"Network {i}: {network}\n"
                section += f"Active Hosts: {len(hosts)}\n\n"
                
                if hosts:
                    section += "Active Hosts Detected:\n"
                    for host in hosts[:10]:  # Limit to first 10
                        ip = host.get('host')
                        hostname = host.get('hostname', 'N/A')
                        response_time = host.get('response_time', 'N/A')
                        section += f"   • {ip} ({hostname}) - {response_time}ms\n"
                        
                    if len(hosts) > 10:
                        section += f"   ... and {len(hosts) - 10} more hosts\n"
                    section += "\n"
        except Exception as e:
            self.logger.error(f"Error generating network discovery section: {e}")
            section += "Error generating network discovery details\n\n"
                
        return section
        
    def generate_ssl_analysis_section(self, ssl_data: List[Dict]) -> str:
        """
        Generate SSL analysis section
        """
        section = "\n🔐 SSL/TLS CERTIFICATE ANALYSIS\n"
        section += "─" * 32 + "\n\n"
        
        try:
            for i, ssl_result in enumerate(ssl_data, 1):
                hostname = ssl_result.get('hostname', f'Target {i}')
                port = ssl_result.get('port', 443)
                
                section += f"Target {i}: {hostname}:{port}\n"
                
                # Certificate information
                cert = ssl_result.get('certificate', {})
                if cert:
                    subject = cert.get('subject', {})
                    validity = cert.get('validity', {})
                    
                    section += f"   Subject: {subject.get('common_name', 'N/A')}\n"
                    section += f"   Issuer: {cert.get('issuer', {}).get('common_name', 'N/A')}\n"
                    section += f"   Expires: {validity.get('not_after', 'N/A')}\n"
                    section += f"   Days Until Expiry: {validity.get('days_until_expiry', 'N/A')}\n"
                    
                # Security analysis
                security = ssl_result.get('security_analysis', {})
                if security:
                    rating = security.get('overall_rating', 'unknown')
                    section += f"   Security Rating: {rating.upper()}\n"
                    
                    issues = security.get('issues', [])
                    if issues:
                        section += "   Issues Found:\n"
                        for issue in issues[:3]:  # Show first 3 issues
                            section += f"     - {issue}\n"
                            
                section += "\n"
        except Exception as e:
            self.logger.error(f"Error generating SSL analysis section: {e}")
            section += "Error generating SSL analysis details\n\n"
            
        return section
        
    def generate_recommendations_section(self, scan_data: Dict) -> str:
        """
        Generate recommendations section
        """
        section = "\n💡 SECURITY RECOMMENDATIONS\n"
        section += "─" * 26 + "\n\n"
        
        try:
            recommendations = set()  # Use set to avoid duplicates
            
            # Collect recommendations from SSL analysis
            for ssl_result in scan_data.get('ssl_analysis', []):
                ssl_recommendations = ssl_result.get('recommendations', [])
                recommendations.update(ssl_recommendations)
                
            # Add general recommendations based on findings
            open_ports = self.count_open_ports(scan_data)
            if open_ports > 5:
                recommendations.add("Review and minimize exposed services")
                recommendations.add("Implement network segmentation")
                
            critical_issues = self.count_critical_issues(scan_data)
            if critical_issues > 0:
                recommendations.add("Address critical vulnerabilities immediately")
                recommendations.add("Implement vulnerability management process")
                
            # Format recommendations
            if recommendations:
                for i, rec in enumerate(sorted(recommendations), 1):
                    section += f"{i}. {rec}\n"
            else:
                section += "No specific recommendations at this time. Continue monitoring and maintain security best practices.\n"
                
            section += "\n" + "─" * 50 + "\n"
            section += "Report generated by Network Security Scanner Suite v1.0\n"
            section += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            section += "\n⚠️ This report is for authorized security testing only.\n"
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            section += "Error generating recommendations\n"
        
        return section
        
    def generate_html_report(self, scan_data: Dict, config: Dict, file_path: str):
        """
        Generate basic HTML report
        """
        try:
            # Generate text content first
            text_content = self.generate_text_report(scan_data, config)
            
            # Convert to basic HTML
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{config.get('title', 'Security Report')}</title>
    <style>
        body  font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; 
        .container  max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; 
        .header  text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; 
        .content  white-space: pre-wrap; font-family: monospace; 
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 {config.get('title', 'Network Security Report')}</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="content">{text_content}</div>
    </div>
</body>
</html>
            """
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            raise
            
    def generate_pdf_report(self, scan_data: Dict, config: Dict, file_path: str):
        """
        Generate PDF report (fallback to text file)
        """
        try:
            # For now, save as text file since PDF generation requires additional libraries
            text_content = self.generate_text_report(scan_data, config)
            text_file_path = file_path.replace('.pdf', '.txt')
            
            with open(text_file_path, 'w', encoding='utf-8') as f:
                f.write(text_content)
                
            self.logger.info(f"PDF generation not available, saved as text: {text_file_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            raise