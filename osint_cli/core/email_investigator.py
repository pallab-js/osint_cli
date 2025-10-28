"""
Email investigation module for OSINT CLI Tool
"""

import re
import requests
import dns.resolver
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import time


class EmailInvestigator:
    """Email investigation and analysis"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-CLI-Tool/1.0.0'
        })
    
    def investigate(self, email: str) -> Dict[str, Any]:
        """
        Perform comprehensive email investigation
        
        Args:
            email: Email address to investigate
            
        Returns:
            Dict containing investigation results
        """
        results = {
            'email': email,
            'valid': False,
            'domain': '',
            'mx_records': [],
            'breach_data': [],
            'social_media': {},
            'disposable': False,
            'deliverable': False,
            'investigation_time': None
        }
        
        start_time = time.time()
        
        try:
            # Extract domain
            domain = email.split('@')[1] if '@' in email else ''
            results['domain'] = domain
            
            # Basic email validation
            results['valid'] = self._validate_email_format(email)
            
            if results['valid']:
                # Check if disposable email
                results['disposable'] = self._check_disposable_email(domain)
                
                # Get MX records
                results['mx_records'] = self._get_mx_records(domain)
                
                # Check deliverability
                results['deliverable'] = self._check_deliverability(email)
                
                # Check for data breaches
                results['breach_data'] = self._check_breaches(email)
                
                # Social media lookup
                username = email.split('@')[0]
                results['social_media'] = self._lookup_social_media(username)
            
            results['investigation_time'] = round(time.time() - start_time, 2)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _validate_email_format(self, email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _check_disposable_email(self, domain: str) -> bool:
        """Check if domain is a disposable email service"""
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'getnada.com', 'maildrop.cc', 'yopmail.com'
        ]
        return domain.lower() in disposable_domains
    
    def _get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for domain"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(record.exchange) for record in mx_records]
        except Exception:
            return []
    
    def _check_deliverability(self, email: str) -> bool:
        """Basic deliverability check"""
        try:
            domain = email.split('@')[1]
            mx_records = self._get_mx_records(domain)
            return len(mx_records) > 0
        except Exception:
            return False
    
    def _check_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check if email has been involved in data breaches"""
        # Note: In a real implementation, you would use HaveIBeenPwned API
        # For this demo, we'll simulate the check
        breaches = []
        
        try:
            # Simulate API call delay
            time.sleep(0.5)
            
            # Mock breach data for demonstration
            if 'test' in email.lower():
                breaches.append({
                    'name': 'Test Breach',
                    'date': '2023-01-01',
                    'description': 'Test data breach for demonstration'
                })
        except Exception:
            pass
        
        return breaches
    
    def _lookup_social_media(self, username: str) -> Dict[str, bool]:
        """Lookup username across social media platforms"""
        platforms = {
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'github': f'https://github.com/{username}',
            'reddit': f'https://reddit.com/user/{username}'
        }
        
        results = {}
        
        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=5)
                results[platform] = response.status_code == 200
            except Exception:
                results[platform] = False
        
        return results
    
    def get_email_metadata(self, email: str) -> Dict[str, Any]:
        """Extract metadata from email address"""
        metadata = {
            'local_part': email.split('@')[0] if '@' in email else '',
            'domain': email.split('@')[1] if '@' in email else '',
            'length': len(email),
            'has_numbers': bool(re.search(r'\d', email)),
            'has_special_chars': bool(re.search(r'[._%+-]', email)),
            'common_provider': False
        }
        
        # Check for common email providers
        common_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'protonmail.com'
        ]
        
        metadata['common_provider'] = metadata['domain'].lower() in common_providers
        
        return metadata