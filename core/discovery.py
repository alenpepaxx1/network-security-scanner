#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Discovery Engine - Simplified Version
Basic host discovery for Windows compatibility
Author: Alen Pepa
"""

import socket
import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from datetime import datetime

from utils.network_utils import get_local_interfaces, ping_host
from utils.logger import get_logger

class NetworkDiscovery:
    """
    Basic network discovery
    """
    
    def __init__(self, max_threads=50, timeout=2):
        self.max_threads = max_threads
        self.timeout = timeout
        self.logger = get_logger()
        self.discovery_active = False
        
    def discover_hosts(self, network: str, method='ping', progress_callback=None) -> List[Dict]:
        """
        Discover active hosts on network
        """
        self.discovery_active = True
        active_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = list(network_obj.hosts())
            
            # Limit for reasonable scan time
            if len(hosts) > 254:
                hosts = hosts[:254]
                self.logger.warning(f"Limited scan to first 254 hosts")
                
            self.logger.info(f"Starting host discovery on {network} ({len(hosts)} hosts)")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_host = {
                    executor.submit(self.ping_host, str(host)): str(host)
                    for host in hosts
                }
                
                completed = 0
                for future in as_completed(future_to_host):
                    if not self.discovery_active:
                        break
                        
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if result and result.get('alive'):
                            active_hosts.append(result)
                            self.logger.info(f"Active host found: {host}")
                    except Exception as e:
                        self.logger.error(f"Error discovering host {host}: {e}")
                        
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, len(hosts))
                        
        except ValueError as e:
            self.logger.error(f"Invalid network format: {e}")
            
        self.logger.info(f"Discovery complete: {len(active_hosts)} active hosts found")
        return active_hosts
        
    def ping_host(self, host: str) -> Optional[Dict]:
        """
        Ping-based host discovery
        """
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(self.timeout), host]
                
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout + 1
            )
            
            if result.returncode == 0:
                rtt = self.extract_ping_time(result.stdout)
                
                return {
                    'host': host,
                    'alive': True,
                    'method': 'ping',
                    'response_time': rtt,
                    'hostname': self.resolve_hostname(host),
                    'timestamp': datetime.now().isoformat()
                }
                
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.logger.debug(f"Ping failed for {host}: {e}")
            
        return None
        
    def extract_ping_time(self, ping_output: str) -> Optional[float]:
        """
        Extract response time from ping output
        """
        import re
        
        patterns = [
            r'time[=<](\d+(?:\.\d+)?)\s*ms',
            r'(\d+(?:\.\d+)?)\s*ms'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, ping_output)
            if match:
                return float(match.group(1))
                
        return None
        
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Resolve IP address to hostname
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
            
    def stop_discovery(self):
        """
        Stop discovery operation
        """
        self.discovery_active = False
        self.logger.info("Host discovery stopped by user")
        
    def get_network_topology(self, hosts: List[Dict]) -> Dict:
        """
        Generate basic network topology information
        """
        topology = {
            'total_hosts': len(hosts),
            'subnets': {},
            'response_times': []
        }
        
        for host in hosts:
            if host.get('response_time'):
                topology['response_times'].append(host['response_time'])
                
        if topology['response_times']:
            topology['avg_response_time'] = sum(topology['response_times']) / len(topology['response_times'])
            
        return topology