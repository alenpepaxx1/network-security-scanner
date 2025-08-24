#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Discovery Tests
Unit tests for network discovery functionality
Author: Alen Pepa
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import subprocess
from datetime import datetime

from core.discovery import NetworkDiscovery
from utils.network_utils import is_valid_ip, is_valid_network

class TestNetworkDiscovery(unittest.TestCase):
    """
    Test cases for NetworkDiscovery class
    """
    
    def setUp(self):
        """
        Set up test fixtures
        """
        self.discovery = NetworkDiscovery(max_threads=10, timeout=1)
        
    def test_discovery_initialization(self):
        """
        Test discovery initialization
        """
        self.assertEqual(self.discovery.max_threads, 10)
        self.assertEqual(self.discovery.timeout, 1)
        self.assertFalse(self.discovery.discovery_active)
        
    @patch('subprocess.run')
    def test_ping_host_success(self, mock_subprocess):
        """
        Test successful ping
        """
        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Reply from 192.168.1.1: bytes=32 time=1ms TTL=64"
        mock_subprocess.return_value = mock_result
        
        result = self.discovery.ping_host('192.168.1.1')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['host'], '192.168.1.1')
        self.assertTrue(result['alive'])
        self.assertEqual(result['method'], 'ping')
        
    @patch('subprocess.run')
    def test_ping_host_failure(self, mock_subprocess):
        """
        Test failed ping
        """
        # Mock failed ping
        mock_result = Mock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        result = self.discovery.ping_host('192.168.1.254')
        self.assertIsNone(result)
        
    def test_extract_ping_time(self):
        """
        Test ping time extraction
        """
        # Windows format
        windows_output = "Reply from 192.168.1.1: bytes=32 time=15ms TTL=64"
        time_ms = self.discovery.extract_ping_time(windows_output)
        self.assertEqual(time_ms, 15.0)
        
        # Linux format
        linux_output = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=12.3 ms"
        time_ms = self.discovery.extract_ping_time(linux_output)
        self.assertEqual(time_ms, 12.3)
        
    def test_extract_mac_address(self):
        """
        Test MAC address extraction
        """
        arp_output = "192.168.1.1               aa-bb-cc-dd-ee-ff     dynamic"
        mac = self.discovery.extract_mac_address(arp_output)
        self.assertEqual(mac, "aa-bb-cc-dd-ee-ff")
        
        # Test colon format
        arp_output2 = "192.168.1.1 ether aa:bb:cc:dd:ee:ff C wlan0"
        mac2 = self.discovery.extract_mac_address(arp_output2)
        self.assertEqual(mac2, "aa:bb:cc:dd:ee:ff")
        
    @patch('socket.gethostbyaddr')
    def test_resolve_hostname(self, mock_gethostbyaddr):
        """
        Test hostname resolution
        """
        mock_gethostbyaddr.return_value = ('router.local', [], ['192.168.1.1'])
        
        hostname = self.discovery.resolve_hostname('192.168.1.1')
        self.assertEqual(hostname, 'router.local')
        
    @patch('socket.gethostbyaddr')
    def test_resolve_hostname_failure(self, mock_gethostbyaddr):
        """
        Test hostname resolution failure
        """
        mock_gethostbyaddr.side_effect = Exception("Name resolution failed")
        
        hostname = self.discovery.resolve_hostname('192.168.1.254')
        self.assertIsNone(hostname)
        
    def test_get_network_topology(self):
        """
        Test network topology generation
        """
        hosts = [
            {
                'host': '192.168.1.1',
                'hostname': 'router.local',
                'method': 'ping',
                'response_time': 15.5
            },
            {
                'host': '192.168.1.100',
                'hostname': 'desktop.local',
                'method': 'ping',
                'response_time': 12.3
            }
        ]
        
        topology = self.discovery.get_network_topology(hosts)
        
        self.assertEqual(topology['total_hosts'], 2)
        self.assertIn('192.168.1.0/24', topology['subnets'])
        self.assertIn('192.168.1.1', topology['hostnames'])
        self.assertEqual(topology['hostnames']['192.168.1.1'], 'router.local')
        self.assertAlmostEqual(topology['avg_response_time'], 13.9, places=1)
        
    def test_stop_discovery(self):
        """
        Test stopping discovery
        """
        self.discovery.discovery_active = True
        self.discovery.stop_discovery()
        self.assertFalse(self.discovery.discovery_active)
        
class TestNetworkUtils(unittest.TestCase):
    """
    Test network utility functions
    """
    
    def test_is_valid_ip(self):
        """
        Test IP address validation
        """
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertTrue(is_valid_ip('127.0.0.1'))
        self.assertTrue(is_valid_ip('::1'))  # IPv6
        
        self.assertFalse(is_valid_ip('256.1.1.1'))
        self.assertFalse(is_valid_ip('not.an.ip'))
        self.assertFalse(is_valid_ip(''))
        
    def test_is_valid_network(self):
        """
        Test network CIDR validation
        """
        self.assertTrue(is_valid_network('192.168.1.0/24'))
        self.assertTrue(is_valid_network('10.0.0.0/8'))
        self.assertTrue(is_valid_network('172.16.0.0/12'))
        
        self.assertFalse(is_valid_network('192.168.1.0/33'))
        self.assertFalse(is_valid_network('not.a.network/24'))
        self.assertFalse(is_valid_network(''))
        
if __name__ == '__main__':
    unittest.main()