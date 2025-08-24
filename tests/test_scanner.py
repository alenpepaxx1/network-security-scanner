#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner Tests
Unit tests for port scanning functionality
Author: Alen Pepa
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import socket
from datetime import datetime

from core.scanner import PortScanner, ServiceDetector
from utils.network_utils import is_valid_ip

class TestPortScanner(unittest.TestCase):
    """
    Test cases for PortScanner class
    """
    
    def setUp(self):
        """
        Set up test fixtures
        """
        self.scanner = PortScanner(max_threads=10, timeout=1)
        
    def test_scanner_initialization(self):
        """
        Test scanner initialization
        """
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertEqual(self.scanner.timeout, 1)
        self.assertFalse(self.scanner.scan_active)
        self.assertEqual(len(self.scanner.results), 0)
        
    @patch('socket.socket')
    def test_scan_open_port(self, mock_socket):
        """
        Test scanning an open port
        """
        # Mock successful connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock
        
        result = self.scanner.scan_port('127.0.0.1', 80)
        
        self.assertEqual(result['host'], '127.0.0.1')
        self.assertEqual(result['port'], 80)
        self.assertEqual(result['state'], 'open')
        self.assertIn('timestamp', result)
        
    @patch('socket.socket')
    def test_scan_closed_port(self, mock_socket):
        """
        Test scanning a closed port
        """
        # Mock failed connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock
        
        result = self.scanner.scan_port('127.0.0.1', 81)
        
        self.assertEqual(result['state'], 'closed')
        
    def test_get_common_ports(self):
        """
        Test getting common ports list
        """
        ports = self.scanner.get_common_ports()
        self.assertIsInstance(ports, list)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(22, ports)
        
    def test_service_detection(self):
        """
        Test service detection from banner
        """
        # Test HTTP service detection
        http_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"
        service = self.scanner.detect_service_from_banner(http_banner, 80)
        self.assertIn('Apache', service)
        
        # Test SSH service detection
        ssh_banner = "SSH-2.0-OpenSSH_7.4"
        service = self.scanner.detect_service_from_banner(ssh_banner, 22)
        self.assertIn('SSH', service)
        
    def test_clear_results(self):
        """
        Test clearing scan results
        """
        # Add some dummy results
        self.scanner.results = [{'host': '127.0.0.1', 'port': 80}]
        
        self.scanner.clear_results()
        self.assertEqual(len(self.scanner.results), 0)
        
    def test_stop_scan(self):
        """
        Test stopping scan operation
        """
        self.scanner.scan_active = True
        self.scanner.stop_scan()
        self.assertFalse(self.scanner.scan_active)
        
class TestServiceDetector(unittest.TestCase):
    """
    Test cases for ServiceDetector class
    """
    
    def setUp(self):
        """
        Set up test fixtures
        """
        self.detector = ServiceDetector()
        
    def test_detect_services(self):
        """
        Test enhanced service detection
        """
        scan_results = [
            {
                'host': '127.0.0.1',
                'port': 80,
                'state': 'open',
                'service': 'HTTP',
                'banner': 'Apache/2.4.41'
            }
        ]
        
        enhanced_results = self.detector.detect_services(scan_results)
        self.assertEqual(len(enhanced_results), 1)
        self.assertIn('vulnerabilities', enhanced_results[0])
        
    def test_check_vulnerabilities(self):
        """
        Test vulnerability checking
        """
        vulns = self.detector.check_vulnerabilities('HTTP', 'Apache/2.4.41')
        self.assertIsInstance(vulns, list)
        
if __name__ == '__main__':
    unittest.main()