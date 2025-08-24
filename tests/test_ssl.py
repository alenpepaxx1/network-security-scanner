#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL Analysis Tests
Unit tests for SSL/TLS analysis functionality
Author: Alen Pepa
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import ssl

from core.ssl_analyzer import SSLAnalyzer

class TestSSLAnalyzer(unittest.TestCase):
    """
    Test cases for SSLAnalyzer class
    """
    
    def setUp(self):
        """
        Set up test fixtures
        """
        self.analyzer = SSLAnalyzer(timeout=5)
        
    def test_analyzer_initialization(self):
        """
        Test analyzer initialization
        """
        self.assertEqual(self.analyzer.timeout, 5)
        
    def test_get_name_attribute(self):
        """
        Test certificate name attribute extraction
        """
        # This would normally test with real certificate objects
        # For unit testing, we'd mock the certificate objects
        pass
        
    def test_analyze_security_good_config(self):
        """
        Test security analysis for good configuration
        """
        cert_info = {
            'public_key': {'key_size': 2048},
            'signature': {'algorithm': 'sha256WithRSAEncryption'},
            'validity': {
                'is_expired': False,
                'expires_soon': False,
                'days_until_expiry': 90
            }
        }
        
        security = self.analyzer.analyze_security(cert_info)
        
        self.assertEqual(security['key_strength'], 'strong')
        self.assertEqual(security['signature_algorithm'], 'strong')
        self.assertEqual(security['expiry_status'], 'valid')
        self.assertIn('excellent', security['overall_rating'].lower())
        
    def test_analyze_security_weak_config(self):
        """
        Test security analysis for weak configuration
        """
        cert_info = {
            'public_key': {'key_size': 1024},
            'signature': {'algorithm': 'sha1WithRSAEncryption'},
            'validity': {
                'is_expired': False,
                'expires_soon': True,
                'days_until_expiry': 15
            }
        }
        
        security = self.analyzer.analyze_security(cert_info)
        
        self.assertEqual(security['key_strength'], 'weak')
        self.assertEqual(security['signature_algorithm'], 'weak')
        self.assertEqual(security['expiry_status'], 'expires_soon')
        self.assertGreater(len(security['issues']), 0)
        
    def test_analyze_security_expired_cert(self):
        """
        Test security analysis for expired certificate
        """
        cert_info = {
            'public_key': {'key_size': 2048},
            'signature': {'algorithm': 'sha256WithRSAEncryption'},
            'validity': {
                'is_expired': True,
                'expires_soon': False,
                'days_until_expiry': -30
            }
        }
        
        security = self.analyzer.analyze_security(cert_info)
        
        self.assertEqual(security['expiry_status'], 'expired')
        self.assertIn('poor', security['overall_rating'].lower())
        
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_test_ssl_versions(self, mock_ssl_context, mock_connection):
        """
        Test SSL version testing
        """
        # Mock SSL context and connection
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        mock_sock = Mock()
        mock_connection.return_value.__enter__.return_value = mock_sock
        
        # Mock successful insecure connection
        mock_ssock = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        vulnerabilities = self.analyzer.test_ssl_versions('example.com', 443)
        
        # Should detect if insecure versions are supported
        self.assertIsInstance(vulnerabilities, list)
        
    def test_generate_recommendations_secure(self):
        """
        Test recommendations for secure configuration
        """
        analysis = {
            'certificate': {
                'validity': {
                    'expires_soon': False,
                    'is_expired': False,
                    'days_until_expiry': 90
                }
            },
            'security_analysis': {
                'key_strength': 'strong',
                'signature_algorithm': 'strong'
            },
            'vulnerabilities': []
        }
        
        recommendations = self.analyzer.generate_recommendations(analysis)
        self.assertIsInstance(recommendations, list)
        
    def test_generate_recommendations_issues(self):
        """
        Test recommendations for configuration with issues
        """
        analysis = {
            'certificate': {
                'validity': {
                    'expires_soon': True,
                    'is_expired': False,
                    'days_until_expiry': 15
                }
            },
            'security_analysis': {
                'key_strength': 'weak',
                'signature_algorithm': 'weak'
            },
            'vulnerabilities': [
                {
                    'severity': 'high',
                    'recommendation': 'Upgrade SSL configuration'
                }
            ]
        }
        
        recommendations = self.analyzer.generate_recommendations(analysis)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('15 days' in rec for rec in recommendations))
        self.assertTrue(any('2048-bit' in rec for rec in recommendations))
        
    def test_batch_analyze_targets(self):
        """
        Test batch analysis of multiple targets
        """
        targets = [('example.com', 443), ('google.com', 443)]
        
        # Mock the analyze_certificate method
        with patch.object(self.analyzer, 'analyze_certificate') as mock_analyze:
            mock_analyze.return_value = {
                'hostname': 'example.com',
                'port': 443,
                'certificate': {},
                'security_analysis': {},
                'vulnerabilities': []
            }
            
            results = self.analyzer.batch_analyze(targets)
            
            self.assertEqual(len(results), 2)
            self.assertIn('example.com:443', results)
            self.assertIn('google.com:443', results)
            
if __name__ == '__main__':
    unittest.main()