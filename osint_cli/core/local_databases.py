"""
Local Intelligence Databases for Offline OSINT Analysis
Provides comprehensive offline data sources for independent operation
"""

import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path


class LocalDatabases:
    """Manages local intelligence databases for offline analysis"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize databases
        self.tld_database = self._load_tld_database()
        self.ip_ranges = self._load_ip_ranges()
        self.email_providers = self._load_email_providers()
        self.breach_patterns = self._load_breach_patterns()
        self.username_patterns = self._load_username_patterns()
        self.social_platforms = self._load_social_platforms()
        self.threat_indicators = self._load_threat_indicators()
        self.geo_data = self._load_geo_data()
    
    def _load_tld_database(self) -> Dict[str, Any]:
        """Load comprehensive TLD database"""
        return {
            'generic_tlds': [
                '.com', '.org', '.net', '.info', '.biz', '.name', '.pro',
                '.aero', '.coop', '.museum', '.travel', '.jobs', '.mobi'
            ],
            'country_tlds': [
                '.us', '.uk', '.de', '.fr', '.jp', '.ca', '.au', '.br',
                '.cn', '.in', '.ru', '.it', '.es', '.nl', '.se', '.no',
                '.dk', '.fi', '.pl', '.cz', '.hu', '.ro', '.bg', '.hr',
                '.si', '.sk', '.ee', '.lv', '.lt', '.mt', '.cy', '.ie',
                '.pt', '.gr', '.lu', '.be', '.at', '.ch', '.li', '.ad',
                '.mc', '.sm', '.va', '.it', '.es', '.fr', '.de', '.uk'
            ],
            'new_tlds': [
                '.app', '.dev', '.tech', '.ai', '.io', '.co', '.me', '.tv',
                '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.tk', '.ml',
                '.ga', '.cf', '.gq', '.tk', '.ml', '.ga', '.cf', '.gq'
            ],
            'suspicious_tlds': [
                '.tk', '.ml', '.ga', '.cf', '.gq', '.tk', '.ml', '.ga',
                '.cf', '.gq', '.tk', '.ml', '.ga', '.cf', '.gq'
            ],
            'tld_categories': {
                'generic': 'Generic top-level domains',
                'country': 'Country code top-level domains',
                'new': 'New generic top-level domains',
                'suspicious': 'Potentially suspicious TLDs'
            }
        }
    
    def _load_ip_ranges(self) -> Dict[str, Any]:
        """Load IP range database for classification"""
        return {
            'private_ranges': [
                {'start': '10.0.0.0', 'end': '10.255.255.255', 'class': 'A'},
                {'start': '172.16.0.0', 'end': '172.31.255.255', 'class': 'B'},
                {'start': '192.168.0.0', 'end': '192.168.255.255', 'class': 'C'},
                {'start': '127.0.0.0', 'end': '127.255.255.255', 'class': 'Loopback'},
                {'start': '169.254.0.0', 'end': '169.254.255.255', 'class': 'Link-Local'}
            ],
            'reserved_ranges': [
                {'start': '0.0.0.0', 'end': '0.255.255.255', 'class': 'Current Network'},
                {'start': '224.0.0.0', 'end': '239.255.255.255', 'class': 'Multicast'},
                {'start': '240.0.0.0', 'end': '255.255.255.255', 'class': 'Reserved'}
            ],
            'public_ranges': [
                {'start': '1.0.0.0', 'end': '9.255.255.255', 'class': 'Public'},
                {'start': '11.0.0.0', 'end': '126.255.255.255', 'class': 'Public'},
                {'start': '128.0.0.0', 'end': '168.255.255.255', 'class': 'Public'},
                {'start': '170.0.0.0', 'end': '172.15.255.255', 'class': 'Public'},
                {'start': '172.32.0.0', 'end': '192.167.255.255', 'class': 'Public'},
                {'start': '192.169.0.0', 'end': '223.255.255.255', 'class': 'Public'}
            ],
            'special_ranges': [
                {'start': '8.8.8.8', 'end': '8.8.8.8', 'class': 'Google DNS'},
                {'start': '1.1.1.1', 'end': '1.1.1.1', 'class': 'Cloudflare DNS'},
                {'start': '208.67.222.222', 'end': '208.67.222.222', 'class': 'OpenDNS'}
            ]
        }
    
    def _load_email_providers(self) -> Dict[str, Any]:
        """Load email provider database"""
        return {
            'major_providers': [
                'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                'aol.com', 'icloud.com', 'protonmail.com', 'tutanota.com'
            ],
            'disposable_providers': [
                '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
                'tempmail.org', 'throwaway.email', 'temp-mail.org',
                'getnada.com', 'maildrop.cc', 'sharklasers.com'
            ],
            'business_providers': [
                'microsoft.com', 'google.com', 'amazon.com', 'apple.com',
                'facebook.com', 'twitter.com', 'linkedin.com', 'salesforce.com'
            ],
            'suspicious_providers': [
                'tempmail.org', 'throwaway.email', 'temp-mail.org',
                'getnada.com', 'maildrop.cc', 'sharklasers.com'
            ],
            'provider_categories': {
                'major': 'Major email providers',
                'disposable': 'Disposable email providers',
                'business': 'Business email providers',
                'suspicious': 'Potentially suspicious providers'
            }
        }
    
    def _load_breach_patterns(self) -> Dict[str, Any]:
        """Load breach pattern database"""
        return {
            'common_breaches': [
                'linkedin', 'myspace', 'adobe', 'dropbox', 'yahoo',
                'ebay', 'equifax', 'marriott', 'target', 'home_depot'
            ],
            'breach_years': {
                '2012': ['linkedin', 'myspace'],
                '2013': ['adobe', 'target'],
                '2014': ['ebay', 'home_depot'],
                '2015': ['ashley_madison'],
                '2016': ['myspace', 'linkedin'],
                '2017': ['equifax', 'uber'],
                '2018': ['marriott', 'quora'],
                '2019': ['facebook', 'capital_one'],
                '2020': ['microsoft', 'twitter'],
                '2021': ['facebook', 'linkedin'],
                '2022': ['twitter', 'microsoft'],
                '2023': ['twitter', 'microsoft']
            },
            'breach_severity': {
                'high': ['equifax', 'marriott', 'target', 'home_depot'],
                'medium': ['linkedin', 'myspace', 'adobe', 'dropbox'],
                'low': ['yahoo', 'ebay', 'uber', 'quora']
            },
            'breach_types': {
                'personal_data': ['equifax', 'marriott', 'target'],
                'credentials': ['linkedin', 'myspace', 'adobe'],
                'financial': ['equifax', 'target', 'home_depot'],
                'social': ['facebook', 'twitter', 'linkedin']
            }
        }
    
    def _load_username_patterns(self) -> Dict[str, Any]:
        """Load username pattern database"""
        return {
            'common_patterns': [
                'firstname_lastname', 'firstname.lastname', 'firstname_lastname_year',
                'firstname_lastname_number', 'firstname_lastname_birthyear',
                'firstname_lastname_city', 'firstname_lastname_job'
            ],
            'suspicious_patterns': [
                'admin', 'administrator', 'root', 'user', 'test', 'demo',
                'guest', 'anonymous', 'public', 'default', 'system'
            ],
            'number_patterns': [
                'name123', 'name_123', 'name-123', 'name.123',
                'name_2023', 'name_23', 'name_2000'
            ],
            'special_char_patterns': [
                'name_', 'name-', 'name.', 'name__', 'name--',
                'name..', 'name___', 'name---', 'name...'
            ],
            'length_categories': {
                'very_short': (1, 3),
                'short': (4, 6),
                'medium': (7, 12),
                'long': (13, 20),
                'very_long': (21, 50)
            }
        }
    
    def _load_social_platforms(self) -> Dict[str, Any]:
        """Load social media platform database"""
        return {
            'major_platforms': [
                'facebook', 'twitter', 'instagram', 'linkedin', 'youtube',
                'tiktok', 'snapchat', 'pinterest', 'reddit', 'discord'
            ],
            'professional_platforms': [
                'linkedin', 'xing', 'viadeo', 'angel_list', 'crunchbase'
            ],
            'messaging_platforms': [
                'whatsapp', 'telegram', 'signal', 'discord', 'slack'
            ],
            'dating_platforms': [
                'tinder', 'bumble', 'hinge', 'okcupid', 'match'
            ],
            'platform_categories': {
                'social': 'Social networking platforms',
                'professional': 'Professional networking platforms',
                'messaging': 'Messaging and communication platforms',
                'dating': 'Dating and relationship platforms'
            }
        }
    
    def _load_threat_indicators(self) -> Dict[str, Any]:
        """Load threat indicator database"""
        return {
            'malicious_patterns': [
                'admin', 'administrator', 'root', 'user', 'test', 'demo',
                'guest', 'anonymous', 'public', 'default', 'system'
            ],
            'suspicious_keywords': [
                'hack', 'crack', 'exploit', 'malware', 'virus', 'trojan',
                'botnet', 'ddos', 'phishing', 'scam', 'fraud'
            ],
            'threat_levels': {
                'low': ['user', 'test', 'demo', 'guest'],
                'medium': ['admin', 'administrator', 'public'],
                'high': ['root', 'system', 'default'],
                'critical': ['hack', 'crack', 'exploit', 'malware']
            },
            'risk_factors': {
                'username_length': {'very_short': 0.8, 'short': 0.6, 'medium': 0.4, 'long': 0.2},
                'special_chars': {'none': 0.1, 'few': 0.3, 'many': 0.7},
                'numbers': {'none': 0.2, 'few': 0.4, 'many': 0.6},
                'suspicious_words': {'none': 0.1, 'some': 0.5, 'many': 0.9}
            }
        }
    
    def _load_geo_data(self) -> Dict[str, Any]:
        """Load basic geolocation data"""
        return {
            'country_codes': {
                'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
                'FR': 'France', 'JP': 'Japan', 'CA': 'Canada', 'AU': 'Australia',
                'BR': 'Brazil', 'CN': 'China', 'IN': 'India', 'RU': 'Russia',
                'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands', 'SE': 'Sweden'
            },
            'time_zones': {
                'UTC': 'Coordinated Universal Time',
                'EST': 'Eastern Standard Time',
                'PST': 'Pacific Standard Time',
                'GMT': 'Greenwich Mean Time',
                'CET': 'Central European Time',
                'JST': 'Japan Standard Time'
            },
            'regions': {
                'north_america': ['US', 'CA', 'MX'],
                'europe': ['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'SE'],
                'asia': ['JP', 'CN', 'IN', 'KR', 'SG'],
                'oceania': ['AU', 'NZ'],
                'south_america': ['BR', 'AR', 'CL', 'CO']
            }
        }
    
    def get_tld_info(self, tld: str) -> Dict[str, Any]:
        """Get TLD information"""
        tld = tld.lower()
        if not tld.startswith('.'):
            tld = '.' + tld
        
        for category, tlds in self.tld_database.items():
            if category == 'tld_categories':
                continue
            if tld in tlds:
                return {
                    'tld': tld[1:],  # Return without dot
                    'category': category,
                    'description': self.tld_database['tld_categories'].get(category, 'Unknown'),
                    'is_suspicious': category == 'suspicious_tlds'
                }
        
        return {
            'tld': tld[1:] if tld.startswith('.') else tld,
            'category': 'unknown',
            'description': 'Unknown TLD',
            'is_suspicious': False
        }
    
    def get_ip_classification(self, ip: str) -> Dict[str, Any]:
        """Classify IP address"""
        # Simple IP classification (would need proper IP parsing in real implementation)
        for range_info in self.ip_ranges['private_ranges']:
            if self._ip_in_range(ip, range_info['start'], range_info['end']):
                return {
                    'type': 'private',
                    'class': range_info['class'],
                    'description': 'Private IP address'
                }
        
        for range_info in self.ip_ranges['reserved_ranges']:
            if self._ip_in_range(ip, range_info['start'], range_info['end']):
                return {
                    'type': 'reserved',
                    'class': range_info['class'],
                    'description': 'Reserved IP address'
                }
        
        return {
            'type': 'public',
            'class': 'Public',
            'description': 'Public IP address'
        }
    
    def get_email_provider_info(self, domain: str) -> Dict[str, Any]:
        """Get email provider information"""
        domain = domain.lower()
        
        for category, providers in self.email_providers.items():
            if category == 'provider_categories':
                continue
            if domain in providers:
                return {
                    'domain': domain,
                    'category': category,
                    'description': self.email_providers['provider_categories'].get(category, 'Unknown'),
                    'is_disposable': category == 'disposable_providers',
                    'is_suspicious': category == 'suspicious_providers'
                }
        
        return {
            'domain': domain,
            'category': 'unknown',
            'description': 'Unknown email provider',
            'is_disposable': False,
            'is_suspicious': False
        }
    
    def get_breach_info(self, email: str) -> Dict[str, Any]:
        """Get breach information for email"""
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        breach_info = {
            'email': email,
            'domain': domain,
            'breaches': [],
            'breach_count': 0,
            'severity': 'none',
            'years': []
        }
        
        for breach in self.breach_patterns['common_breaches']:
            if breach in domain:
                breach_info['breaches'].append(breach)
                breach_info['breach_count'] += 1
        
        if breach_info['breaches']:
            breach_info['severity'] = 'medium'
            for year, breaches in self.breach_patterns['breach_years'].items():
                if any(breach in breach_info['breaches'] for breach in breaches):
                    breach_info['years'].append(year)
        
        return breach_info
    
    def get_username_analysis(self, username: str) -> Dict[str, Any]:
        """Analyze username patterns"""
        analysis = {
            'username': username,
            'length': len(username),
            'length_category': 'medium',
            'has_numbers': any(c.isdigit() for c in username),
            'has_special_chars': any(c in '._-' for c in username),
            'is_suspicious': False,
            'threat_level': 'low',
            'risk_score': 0.0
        }
        
        # Determine length category
        for category, (min_len, max_len) in self.username_patterns['length_categories'].items():
            if min_len <= len(username) <= max_len:
                analysis['length_category'] = category
                break
        
        # Check for suspicious patterns
        username_lower = username.lower()
        for pattern in self.username_patterns['suspicious_patterns']:
            if pattern in username_lower:
                analysis['is_suspicious'] = True
                analysis['threat_level'] = 'high'
                analysis['risk_score'] += 0.5
        
        # Calculate risk score
        risk_factors = self.threat_indicators['risk_factors']
        analysis['risk_score'] += risk_factors['username_length'].get(analysis['length_category'], 0.4)
        analysis['risk_score'] += risk_factors['special_chars'].get('few' if analysis['has_special_chars'] else 'none', 0.1)
        analysis['risk_score'] += risk_factors['numbers'].get('few' if analysis['has_numbers'] else 'none', 0.2)
        
        return analysis
    
    def _ip_in_range(self, ip: str, start: str, end: str) -> bool:
        """Check if IP is in range (simplified implementation)"""
        # This is a simplified implementation
        # In a real implementation, you'd need proper IP address parsing and comparison
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            start_parts = [int(x) for x in start.split('.')]
            end_parts = [int(x) for x in end.split('.')]
            
            for i in range(4):
                if not (start_parts[i] <= ip_parts[i] <= end_parts[i]):
                    return False
            return True
        except (ValueError, IndexError):
            return False
    
    def save_databases(self):
        """Save databases to JSON files"""
        databases = {
            'tld_database': self.tld_database,
            'ip_ranges': self.ip_ranges,
            'email_providers': self.email_providers,
            'breach_patterns': self.breach_patterns,
            'username_patterns': self.username_patterns,
            'social_platforms': self.social_platforms,
            'threat_indicators': self.threat_indicators,
            'geo_data': self.geo_data
        }
        
        for name, data in databases.items():
            file_path = self.data_dir / f"{name}.json"
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
    
    def load_databases(self):
        """Load databases from JSON files"""
        for name in ['tld_database', 'ip_ranges', 'email_providers', 'breach_patterns',
                     'username_patterns', 'social_platforms', 'threat_indicators', 'geo_data']:
            file_path = self.data_dir / f"{name}.json"
            if file_path.exists():
                with open(file_path, 'r') as f:
                    setattr(self, name, json.load(f))