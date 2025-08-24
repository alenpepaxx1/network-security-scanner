#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL/TLS Certificate Analyzer - Simplified Version
Basic SSL/TLS security analysis for Windows compatibility
Author: Alen Pepa
"""

import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import json

from utils.logger import get_logger

class SSLAnalyzer:
    """
    Simplified SSL/TLS certificate analyzer
    """
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.logger = get_logger()
        
    def analyze_certificate(self, hostname: str, port: int = 443) -> Dict:
        """
        Basic SSL certificate analysis
        """
        analysis = {
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'certificate': None,
            'security_analysis': None,
            'vulnerabilities': [],
            'recommendations': [],
            'errors': []
        }
        
        try:
            # Get basic certificate info
            cert_info = self.get_certificate_info(hostname, port)
            if cert_info:
                analysis['certificate'] = cert_info
                analysis['security_analysis'] = self.analyze_security(cert_info)
                analysis['recommendations'] = self.generate_recommendations(analysis)
                
        except Exception as e:
            error_msg = f"SSL analysis failed: {str(e)}"
            analysis['errors'].append(error_msg)
            self.logger.error(error_msg)
            
        return analysis
        
    def get_certificate_info(self, hostname: str, port: int) -> Optional[Dict]:
        """
        Get basic certificate information
        """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            if cert:
                return self.parse_certificate(cert)
                
        except Exception as e:
            self.logger.error(f"Failed to get certificate for {hostname}:{port} - {e}")
            
        return None
        
    def parse_certificate(self, cert: Dict) -> Dict:
        """
        Parse certificate information
        """
        details = {
            'subject': {},
            'issuer': {},
            'validity': {},
            'extensions': {},
            'version': cert.get('version', 'unknown')
        }
        
        try:
            # Subject information
            subject_dict = dict(cert.get('subject', []))
            details['subject'] = {
                'common_name': subject_dict.get('commonName', 'N/A'),
                'organization': subject_dict.get('organizationName', 'N/A'),
                'country': subject_dict.get('countryName', 'N/A')
            }
            
            # Issuer information
            issuer_dict = dict(cert.get('issuer', []))
            details['issuer'] = {
                'common_name': issuer_dict.get('commonName', 'N/A'),
                'organization': issuer_dict.get('organizationName', 'N/A'),
                'country': issuer_dict.get('countryName', 'N/A')
            }
            
            # Validity period
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now()
            
            details['validity'] = {
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'days_until_expiry': (not_after - now).days,
                'is_expired': now > not_after,
                'expires_soon': (not_after - now).days < 30
            }
            
            # Extensions
            details['extensions'] = {
                'subject_alt_names': cert.get('subjectAltName', []),
                'serial_number': cert.get('serialNumber', 'N/A')
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing certificate: {e}")
            
        return details
        
    def analyze_security(self, cert_info: Dict) -> Dict:
        """
        Basic security analysis
        """
        security = {
            'overall_rating': 'unknown',
            'expiry_status': 'unknown',
            'issues': [],
            'strengths': []
        }
        
        try:
            validity = cert_info.get('validity', {})
            
            # Check expiry
            if validity.get('is_expired'):
                security['expiry_status'] = 'expired'
                security['issues'].append("Certificate has expired")
                security['overall_rating'] = 'poor'
            elif validity.get('expires_soon'):
                days = validity.get('days_until_expiry', 0)
                security['expiry_status'] = 'expires_soon'
                security['issues'].append(f"Certificate expires in {days} days")
                security['overall_rating'] = 'fair'
            else:
                security['expiry_status'] = 'valid'
                security['strengths'].append("Certificate is not expired")
                
            # Overall rating
            if len(security['issues']) == 0:
                security['overall_rating'] = 'good'
            elif security['overall_rating'] == 'unknown':
                security['overall_rating'] = 'fair'
                
        except Exception as e:
            self.logger.error(f"Error analyzing security: {e}")
            
        return security
        
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """
        Generate basic recommendations
        """
        recommendations = []
        
        try:
            security = analysis.get('security_analysis', {})
            cert = analysis.get('certificate', {})
            
            # Certificate expiry recommendations
            validity = cert.get('validity', {})
            if validity.get('expires_soon'):
                days = validity.get('days_until_expiry', 0)
                recommendations.append(f"Certificate expires in {days} days - plan renewal soon")
            elif validity.get('is_expired'):
                recommendations.append("Certificate has expired - renew immediately")
                
            # General recommendations
            recommendations.extend([
                "Monitor certificate expiry dates regularly",
                "Implement automated certificate renewal",
                "Use strong encryption ciphers",
                "Enable HSTS (HTTP Strict Transport Security)",
                "Regular security assessments recommended"
            ])
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            
        return recommendations
        
    def batch_analyze(self, targets: List[Tuple[str, int]], 
                     progress_callback=None) -> Dict[str, Dict]:
        """
        Analyze multiple SSL targets
        """
        results = {}
        
        for i, (host, port) in enumerate(targets):
            target_key = f"{host}:{port}"
            try:
                result = self.analyze_certificate(host, port)
                results[target_key] = result
            except Exception as e:
                self.logger.error(f"SSL analysis failed for {target_key}: {e}")
                results[target_key] = {
                    'hostname': host,
                    'port': port,
                    'errors': [f"Analysis failed: {str(e)}"],
                    'timestamp': datetime.now().isoformat()
                }
                
            if progress_callback:
                progress_callback(i + 1, len(targets))
                
        return results