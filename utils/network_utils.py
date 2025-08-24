#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Utilities - Helper functions (Windows Compatible)
Network-related utility functions without netifaces dependency
Author: Alen Pepa
"""

import socket
import ipaddress
import platform
import subprocess
from typing import List, Dict, Optional

def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
        
def is_valid_network(network: str) -> bool:
    """
    Check if string is a valid network CIDR
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False
        
def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
        
def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.gaierror, socket.herror):
        return None
        
def get_local_interfaces() -> List[Dict]:
    """
    Get local network interfaces using Windows-compatible method
    """
    interfaces = []
    
    try:
        # Get local IP using hostname
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        if local_ip and not local_ip.startswith('127.'):
            # Determine network based on IP class
            if local_ip.startswith('192.168.'):
                network = f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
                netmask = '255.255.255.0'
            elif local_ip.startswith('10.'):
                network = "10.0.0.0/8" 
                netmask = '255.0.0.0'
            elif local_ip.startswith('172.'):
                second_octet = int(local_ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    network = f"172.{second_octet}.0.0/16"
                    netmask = '255.255.0.0'
                else:
                    network = f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
                    netmask = '255.255.255.0'
            else:
                network = f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
                netmask = '255.255.255.0'
                
            interfaces.append({
                'interface': 'Local Area Connection',
                'ip': local_ip,
                'netmask': netmask,
                'network': network,
                'broadcast': None
            })
            
        # Try to get additional IPs using socket method
        try:
            # Connect to external server to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                alt_local_ip = s.getsockname()[0]
                
                if alt_local_ip != local_ip and not alt_local_ip.startswith('127.'):
                    if alt_local_ip.startswith('192.168.'):
                        alt_network = f"{'.'.join(alt_local_ip.split('.')[:-1])}.0/24"
                    elif alt_local_ip.startswith('10.'):
                        alt_network = "10.0.0.0/8"
                    else:
                        alt_network = f"{'.'.join(alt_local_ip.split('.')[:-1])}.0/24"
                        
                    interfaces.append({
                        'interface': 'WiFi',
                        'ip': alt_local_ip,
                        'netmask': '255.255.255.0',
                        'network': alt_network,
                        'broadcast': None
                    })
        except:
            pass
            
    except Exception as e:
        print(f"Warning: Could not detect network interfaces: {e}")
        # Fallback to common networks
        interfaces = [
            {
                'interface': 'default',
                'ip': '192.168.1.100',
                'netmask': '255.255.255.0', 
                'network': '192.168.1.0/24',
                'broadcast': None
            }
        ]
        
    return interfaces
    
def get_network_hosts(network: str) -> List[str]:
    """
    Get list of host IPs in a network
    """
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in network_obj.hosts()]
        # Limit to reasonable number for scanning
        return hosts[:254] if len(hosts) > 254 else hosts
    except ValueError:
        return []
        
def ping_host(host: str, timeout: int = 3) -> bool:
    """
    Ping a host to check if it's alive
    """
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), host]
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )
        
        return result.returncode == 0
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False
        
def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway IP using Windows ipconfig
    """
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Default Gateway' in line or 'Default gateway' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        if is_valid_ip(gateway):
                            return gateway
        else:
            # Linux/Mac route command
            result = subprocess.run(['route', '-n'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if line.startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
                        
    except Exception:
        pass
        
    return None
    
def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
        
def get_public_ip() -> Optional[str]:
    """
    Get public IP address
    """
    try:
        # Try multiple services
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me'
        ]
        
        for service in services:
            try:
                import urllib.request
                with urllib.request.urlopen(service, timeout=5) as response:
                    ip = response.read().decode().strip()
                    if is_valid_ip(ip):
                        return ip
            except:
                continue
                
    except Exception:
        pass
        
    return None
    
def port_in_use(port: int, host: str = '127.0.0.1') -> bool:
    """
    Check if a port is in use
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception:
        return False
        
def get_open_ports(host: str, port_range: range) -> List[int]:
    """
    Get list of open ports on a host
    """
    open_ports = []
    
    for port in port_range:
        if port_in_use(port, host):
            open_ports.append(port)
            
    return open_ports