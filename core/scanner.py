#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic Port Scanner - Simplified Version
Author: Alen Pepa
"""

import socket
import threading
from datetime import datetime
from typing import List, Dict

class PortScanner:
    def __init__(self, max_threads=50, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = []
        self.scan_active = False
        
    def get_common_ports(self) -> List[int]:
        """Return common ports to scan"""
        return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]
        
    def scan_host(self, target: str, ports: List[int], progress_callback=None) -> List[Dict]:
        """Basic host scanning"""
        results = []
        for i, port in enumerate(ports):
            if not self.scan_active:
                break
            result = self.scan_port(target, port)
            if result:
                results.append(result)
            if progress_callback:
                progress_callback(i + 1, len(ports))
        return results
        
    def scan_port(self, host: str, port: int) -> Dict:
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    'host': host,
                    'port': port,
                    'state': 'open',
                    'service': self.guess_service(port),
                    'banner': '',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'host': host,
                    'port': port,
                    'state': 'closed',
                    'service': '',
                    'banner': '',
                    'timestamp': datetime.now().isoformat()
                }
        except Exception:
            return {
                'host': host,
                'port': port,
                'state': 'filtered',
                'service': '',
                'banner': '',
                'timestamp': datetime.now().isoformat()
            }
            
    def guess_service(self, port: int) -> str:
        """Guess service based on port number"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'unknown')
        
    def stop_scan(self):
        """Stop scanning"""
        self.scan_active = False
        
    def clear_results(self):
        """Clear results"""
        self.results = []
        
    def export_results(self, format_type: str = 'json') -> str:
        """Export results"""
        if format_type == 'json':
            import json
            return json.dumps(self.results, indent=2)
        return str(self.results)

    def scan_network(self, network: str, ports: List[int], progress_callback=None) -> Dict:
        """Basic network scanning"""
        return {network: self.scan_host(network, ports, progress_callback)}