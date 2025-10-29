"""
Pattern Recognition Engine for Offline OSINT Analysis
Provides advanced pattern analysis and correlation capabilities
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
from datetime import datetime, timedelta
import json


class PatternRecognitionEngine:
    """Advanced pattern recognition and analysis engine"""
    
    def __init__(self, local_databases=None):
        self.local_databases = local_databases
        self.pattern_cache = {}
        self.correlation_cache = {}
        
        # Pattern recognition rules
        self.email_patterns = self._load_email_patterns()
        self.domain_patterns = self._load_domain_patterns()
        self.username_patterns = self._load_username_patterns()
        self.threat_patterns = self._load_threat_patterns()
        self.behavioral_patterns = self._load_behavioral_patterns()
    
    def _load_email_patterns(self) -> Dict[str, Any]:
        """Load email pattern recognition rules"""
        return {
            'disposable_patterns': [
                r'temp.*mail', r'throw.*away', r'10.*minute', r'guerrilla.*mail',
                r'mail.*drop', r'shark.*lasers', r'get.*nada', r'temp.*mail'
            ],
            'business_patterns': [
                r'[a-z]+\.[a-z]+@[a-z]+\.[a-z]+',  # first.last@company.com
                r'[a-z]+_[a-z]+@[a-z]+\.[a-z]+',   # first_last@company.com
                r'[a-z]+\.[a-z]+\.[a-z]+@[a-z]+\.[a-z]+'  # first.m.last@company.com
            ],
            'suspicious_patterns': [
                r'[0-9]{10,}@',  # Long number sequences
                r'[a-z]{1,3}@',  # Very short usernames
                r'[^a-zA-Z0-9._-]@',  # Special characters
                r'\.{2,}@',  # Multiple consecutive dots
                r'_{2,}@',  # Multiple consecutive underscores
                r'-{2,}@'   # Multiple consecutive hyphens
            ],
            'common_patterns': [
                r'[a-z]+\.[a-z]+@',  # first.last
                r'[a-z]+_[a-z]+@',   # first_last
                r'[a-z]+\d+@',       # first123
                r'[a-z]+\.[a-z]+\d+@'  # first.last123
            ]
        }
    
    def _load_domain_patterns(self) -> Dict[str, Any]:
        """Load domain pattern recognition rules"""
        return {
            'suspicious_tlds': [r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$'],
            'new_tlds': [r'\.app$', r'\.dev$', r'\.tech$', r'\.ai$', r'\.io$'],
            'country_tlds': [r'\.us$', r'\.uk$', r'\.de$', r'\.fr$', r'\.jp$'],
            'generic_tlds': [r'\.com$', r'\.org$', r'\.net$', r'\.info$'],
            'subdomain_patterns': [
                r'www\.', r'api\.', r'admin\.', r'secure\.', r'login\.',
                r'mail\.', r'ftp\.', r'ssh\.', r'vpn\.', r'proxy\.'
            ],
            'suspicious_subdomains': [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP-like
                r'[a-z]{1,3}\.[a-z]{1,3}',  # Very short subdomains
                r'[0-9]{6,}',  # Long number sequences
                r'[a-z]{20,}'  # Very long subdomains
            ]
        }
    
    def _load_username_patterns(self) -> Dict[str, Any]:
        """Load username pattern recognition rules"""
        return {
            'common_patterns': [
                r'^[a-z]+\.[a-z]+$',  # first.last
                r'^[a-z]+_[a-z]+$',   # first_last
                r'^[a-z]+\d+$',       # first123
                r'^[a-z]+\.[a-z]+\d+$',  # first.last123
                r'^[a-z]+\d{4}$',     # first2023
                r'^[a-z]+\d{2}$'      # first23
            ],
            'suspicious_patterns': [
                r'^admin$', r'^administrator$', r'^root$', r'^user$',
                r'^test$', r'^demo$', r'^guest$', r'^anonymous$',
                r'^public$', r'^default$', r'^system$'
            ],
            'number_patterns': [
                r'\d{4}$',  # Year suffix
                r'\d{2}$',  # Two-digit suffix
                r'\d{3,}$',  # Three or more digits
                r'^\d+$'    # All numbers
            ],
            'special_char_patterns': [
                r'[._-]{2,}',  # Multiple consecutive special chars
                r'^[._-]',     # Starts with special char
                r'[._-]$',     # Ends with special char
                r'[^a-zA-Z0-9._-]'  # Invalid characters
            ]
        }
    
    def _load_threat_patterns(self) -> Dict[str, Any]:
        """Load threat pattern recognition rules"""
        return {
            'malicious_keywords': [
                'hack', 'crack', 'exploit', 'malware', 'virus', 'trojan',
                'botnet', 'ddos', 'phishing', 'scam', 'fraud', 'steal',
                'breach', 'leak', 'dump', 'sell', 'buy', 'market'
            ],
            'suspicious_phrases': [
                'admin panel', 'backdoor', 'shell access', 'root access',
                'database dump', 'credit card', 'ssn', 'social security',
                'password list', 'user database', 'email list'
            ],
            'threat_indicators': [
                r'[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}',  # Credit card pattern
                r'[0-9]{3}-[0-9]{2}-[0-9]{4}',  # SSN pattern
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email pattern
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  # IP pattern
            ]
        }
    
    def _load_behavioral_patterns(self) -> Dict[str, Any]:
        """Load behavioral pattern recognition rules"""
        return {
            'time_patterns': {
                'business_hours': (9, 17),  # 9 AM to 5 PM
                'night_hours': (22, 6),     # 10 PM to 6 AM
                'weekend_days': [5, 6]      # Friday, Saturday
            },
            'frequency_patterns': {
                'high_frequency': 100,      # More than 100 actions per day
                'medium_frequency': 50,     # 50-100 actions per day
                'low_frequency': 10         # 10-50 actions per day
            },
            'geographic_patterns': {
                'suspicious_countries': ['CN', 'RU', 'KP', 'IR'],
                'high_risk_regions': ['Middle East', 'Eastern Europe', 'Asia'],
                'low_risk_regions': ['North America', 'Western Europe', 'Oceania']
            }
        }
    
    def analyze_email_patterns(self, email: str) -> Dict[str, Any]:
        """Analyze email patterns for intelligence"""
        analysis = {
            'email': email,
            'patterns': [],
            'risk_score': 0.0,
            'threat_indicators': [],
            'behavioral_indicators': [],
            'correlation_score': 0.0
        }
        
        # Check disposable email patterns
        for pattern in self.email_patterns['disposable_patterns']:
            if re.search(pattern, email, re.IGNORECASE):
                analysis['patterns'].append('disposable_email')
                analysis['risk_score'] += 0.3
                analysis['threat_indicators'].append('disposable_email_provider')
        
        # Check business email patterns
        for pattern in self.email_patterns['business_patterns']:
            if re.search(pattern, email, re.IGNORECASE):
                analysis['patterns'].append('business_email')
                analysis['risk_score'] -= 0.1  # Business emails are generally safer
        
        # Check suspicious patterns (evaluate on local-part only)
        local_part = email.split('@', 1)[0] if '@' in email else email
        suspicious_checks = [
            re.search(r'^[0-9]{10,}$', local_part, re.IGNORECASE),
            re.search(r'^[a-z]{1,3}$', local_part, re.IGNORECASE),
            re.search(r'[^a-zA-Z0-9._-]', local_part),
            re.search(r'\.{2,}', local_part),
            re.search(r'_{2,}', local_part),
            re.search(r'-{2,}', local_part),
        ]
        if any(suspicious_checks):
            analysis['patterns'].append('suspicious_format')
            analysis['risk_score'] += 0.4
            analysis['threat_indicators'].append('suspicious_email_format')
        
        # Check common patterns
        for pattern in self.email_patterns['common_patterns']:
            if re.search(pattern, email, re.IGNORECASE):
                analysis['patterns'].append('common_format')
                analysis['risk_score'] -= 0.05  # Common patterns are generally safer
        # Generic simple email format as common
        if re.match(r'^[a-z0-9._%+\-]+@[a-z0-9\-]+\.[a-z]{2,}$', email, re.IGNORECASE):
            if 'common_format' not in analysis['patterns']:
                analysis['patterns'].append('common_format')
                analysis['risk_score'] -= 0.05
        
        # Analyze username and domain separately
        if '@' in email:
            username, domain = email.split('@', 1)
            username_analysis = self.analyze_username_patterns(username)
            domain_analysis = self.analyze_domain_patterns(domain)
            
            analysis['username_analysis'] = username_analysis
            analysis['domain_analysis'] = domain_analysis
            
            # Reduce contribution for common benign mailbox names
            benign_locals = {'user', 'info', 'contact', 'support', 'hello', 'sales'}
            if username.lower() in benign_locals:
                analysis['risk_score'] += min(0.1, username_analysis.get('risk_score', 0) * 0.1)
            else:
                analysis['risk_score'] += username_analysis.get('risk_score', 0)
            analysis['risk_score'] += domain_analysis.get('risk_score', 0)
        
        # Normalize risk score
        analysis['risk_score'] = max(0.0, min(1.0, analysis['risk_score']))
        
        return analysis
    
    def analyze_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """Analyze domain patterns for intelligence"""
        analysis = {
            'domain': domain,
            'patterns': [],
            'risk_score': 0.0,
            'threat_indicators': [],
            'tld_analysis': {},
            'subdomain_analysis': {}
        }
        
        # Check TLD patterns
        for pattern in self.domain_patterns['suspicious_tlds']:
            if re.search(pattern, domain, re.IGNORECASE):
                analysis['patterns'].append('suspicious_tld')
                analysis['risk_score'] += 0.5
                analysis['threat_indicators'].append('suspicious_tld_detected')
        
        for pattern in self.domain_patterns['new_tlds']:
            if re.search(pattern, domain, re.IGNORECASE):
                analysis['patterns'].append('new_tld')
                analysis['risk_score'] += 0.1
                analysis['threat_indicators'].append('new_tld_detected')
        
        # Analyze subdomains
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                analysis['subdomain_analysis'] = self._analyze_subdomain(subdomain)
                # Only evaluate suspicious subdomain patterns on subdomain part
                for pattern in self.domain_patterns['suspicious_subdomains']:
                    if re.search(pattern, subdomain, re.IGNORECASE):
                        analysis['patterns'].append('suspicious_subdomain')
                        analysis['risk_score'] += 0.3
                        analysis['threat_indicators'].append('suspicious_subdomain_detected')
        
        # Normalize risk score
        analysis['risk_score'] = max(0.0, min(1.0, analysis['risk_score']))
        
        return analysis
    
    def analyze_username_patterns(self, username: str) -> Dict[str, Any]:
        """Analyze username patterns for intelligence"""
        analysis = {
            'username': username,
            'patterns': [],
            'risk_score': 0.0,
            'threat_indicators': [],
            'behavioral_indicators': [],
            'length_analysis': {},
            'character_analysis': {}
        }
        
        # Check common patterns
        for pattern in self.username_patterns['common_patterns']:
            if re.search(pattern, username, re.IGNORECASE):
                analysis['patterns'].append('common_format')
                analysis['risk_score'] -= 0.05
        
        # Check suspicious patterns
        for pattern in self.username_patterns['suspicious_patterns']:
            if re.search(pattern, username, re.IGNORECASE):
                analysis['patterns'].append('suspicious_format')
                analysis['risk_score'] += 0.6
                analysis['threat_indicators'].append('suspicious_username_detected')
        
        # Check number patterns
        for pattern in self.username_patterns['number_patterns']:
            if re.search(pattern, username, re.IGNORECASE):
                analysis['patterns'].append('number_format')
                analysis['risk_score'] += 0.1
        
        # Check special character patterns
        for pattern in self.username_patterns['special_char_patterns']:
            if re.search(pattern, username, re.IGNORECASE):
                analysis['patterns'].append('special_char_format')
                analysis['risk_score'] += 0.2
                analysis['threat_indicators'].append('special_char_username_detected')
        
        # Length analysis
        analysis['length_analysis'] = self._analyze_username_length(username)
        analysis['risk_score'] += analysis['length_analysis']['risk_score']
        
        # Character analysis
        analysis['character_analysis'] = self._analyze_username_characters(username)
        analysis['risk_score'] += analysis['character_analysis']['risk_score']
        
        # Normalize risk score
        analysis['risk_score'] = max(0.0, min(1.0, analysis['risk_score']))
        
        return analysis
    
    def _analyze_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Analyze subdomain patterns"""
        analysis = {
            'subdomain': subdomain,
            'risk_score': 0.0,
            'indicators': []
        }
        
        # Check for IP-like patterns
        if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', subdomain):
            analysis['indicators'].append('ip_like_subdomain')
            analysis['risk_score'] += 0.4
        
        # Check for very short subdomains
        if len(subdomain) <= 3:
            analysis['indicators'].append('very_short_subdomain')
            analysis['risk_score'] += 0.2
        
        # Check for very long subdomains
        if len(subdomain) >= 20:
            analysis['indicators'].append('very_long_subdomain')
            analysis['risk_score'] += 0.1
        
        # Check for number sequences
        if re.search(r'[0-9]{6,}', subdomain):
            analysis['indicators'].append('long_number_sequence')
            analysis['risk_score'] += 0.3
        
        return analysis
    
    def _analyze_username_length(self, username: str) -> Dict[str, Any]:
        """Analyze username length patterns"""
        length = len(username)
        analysis = {
            'length': length,
            'category': 'medium',
            'risk_score': 0.0
        }
        
        if length <= 3:
            analysis['category'] = 'very_short'
            analysis['risk_score'] = 0.6
        elif length <= 6:
            analysis['category'] = 'short'
            analysis['risk_score'] = 0.3
        elif length <= 12:
            analysis['category'] = 'medium'
            analysis['risk_score'] = 0.1
        elif length <= 20:
            analysis['category'] = 'long'
            analysis['risk_score'] = 0.2
        else:
            analysis['category'] = 'very_long'
            analysis['risk_score'] = 0.4
        
        return analysis
    
    def _analyze_username_characters(self, username: str) -> Dict[str, Any]:
        """Analyze username character patterns"""
        analysis = {
            'total_chars': len(username),
            'letter_count': len([c for c in username if c.isalpha()]),
            'number_count': len([c for c in username if c.isdigit()]),
            'special_count': len([c for c in username if c in '._-']),
            'other_count': len([c for c in username if c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-']),
            'risk_score': 0.0
        }
        
        # Calculate character ratios
        if analysis['total_chars'] > 0:
            analysis['letter_ratio'] = analysis['letter_count'] / analysis['total_chars']
            analysis['number_ratio'] = analysis['number_count'] / analysis['total_chars']
            analysis['special_ratio'] = analysis['special_count'] / analysis['total_chars']
            analysis['other_ratio'] = analysis['other_count'] / analysis['total_chars']
        else:
            analysis['letter_ratio'] = 0
            analysis['number_ratio'] = 0
            analysis['special_ratio'] = 0
            analysis['other_ratio'] = 0
        
        # Risk scoring based on character patterns
        if analysis['other_ratio'] > 0.1:  # More than 10% invalid characters
            analysis['risk_score'] += 0.5
        
        if analysis['special_ratio'] > 0.3:  # More than 30% special characters
            analysis['risk_score'] += 0.3
        
        if analysis['number_ratio'] > 0.5:  # More than 50% numbers
            analysis['risk_score'] += 0.2
        
        if analysis['letter_ratio'] < 0.3:  # Less than 30% letters
            analysis['risk_score'] += 0.3
        
        return analysis
    
    def detect_threat_patterns(self, text: str) -> Dict[str, Any]:
        """Detect threat patterns in text"""
        analysis = {
            'text': text,
            'threats_detected': [],
            'risk_score': 0.0,
            'indicators': []
        }
        
        text_lower = text.lower()
        
        # Check for malicious keywords
        for keyword in self.threat_patterns['malicious_keywords']:
            if keyword in text_lower:
                analysis['threats_detected'].append(f'malicious_keyword: {keyword}')
                analysis['risk_score'] += 0.2
                analysis['indicators'].append('malicious_keyword_detected')
        
        # Check for suspicious phrases
        for phrase in self.threat_patterns['suspicious_phrases']:
            if phrase in text_lower:
                analysis['threats_detected'].append(f'suspicious_phrase: {phrase}')
                analysis['risk_score'] += 0.3
                analysis['indicators'].append('suspicious_phrase_detected')
        
        # Check for threat indicators
        for pattern in self.threat_patterns['threat_indicators']:
            matches = re.findall(pattern, text)
            if matches:
                analysis['threats_detected'].append(f'threat_indicator: {pattern}')
                analysis['risk_score'] += 0.4
                analysis['indicators'].append('threat_indicator_detected')
        
        # Normalize risk score
        analysis['risk_score'] = max(0.0, min(1.0, analysis['risk_score']))
        
        return analysis
    
    def correlate_patterns(self, targets: List[str]) -> Dict[str, Any]:
        """Correlate patterns across multiple targets"""
        correlation = {
            'targets': targets,
            'correlations': [],
            'correlation_score': 0.0,
            'common_patterns': [],
            'unique_patterns': [],
            'risk_assessment': {}
        }
        
        if len(targets) < 2:
            return correlation
        
        # Analyze each target
        target_analyses = []
        for target in targets:
            if '@' in target:
                analysis = self.analyze_email_patterns(target)
            elif '.' in target and not target.replace('.', '').isdigit():
                analysis = self.analyze_domain_patterns(target)
            else:
                analysis = self.analyze_username_patterns(target)
            target_analyses.append(analysis)
        
        # Find common patterns
        all_patterns = []
        for analysis in target_analyses:
            all_patterns.extend(analysis.get('patterns', []))
        
        pattern_counts = Counter(all_patterns)
        common_patterns = [pattern for pattern, count in pattern_counts.items() if count > 1]
        unique_patterns = [pattern for pattern, count in pattern_counts.items() if count == 1]
        
        correlation['common_patterns'] = common_patterns
        correlation['unique_patterns'] = unique_patterns
        
        # Calculate correlation score
        if common_patterns:
            correlation['correlation_score'] = len(common_patterns) / len(set(all_patterns))
        
        # Risk assessment
        risk_scores = [analysis.get('risk_score', 0) for analysis in target_analyses]
        correlation['risk_assessment'] = {
            'average_risk': sum(risk_scores) / len(risk_scores),
            'max_risk': max(risk_scores),
            'min_risk': min(risk_scores),
            'high_risk_targets': [targets[i] for i, score in enumerate(risk_scores) if score > 0.7]
        }
        
        return correlation
    
    def generate_intelligence_report(self, target: str) -> Dict[str, Any]:
        """Generate comprehensive intelligence report"""
        report = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'analysis': {},
            'threat_assessment': {},
            'recommendations': [],
            'confidence_score': 0.0
        }
        
        # Perform comprehensive analysis
        if '@' in target:
            report['analysis'] = self.analyze_email_patterns(target)
        elif '.' in target and not target.replace('.', '').isdigit():
            report['analysis'] = self.analyze_domain_patterns(target)
        else:
            report['analysis'] = self.analyze_username_patterns(target)
        
        # Threat assessment
        report['threat_assessment'] = {
            'risk_level': self._calculate_risk_level(report['analysis'].get('risk_score', 0)),
            'threat_indicators': report['analysis'].get('threat_indicators', []),
            'confidence': self._calculate_confidence(report['analysis'])
        }
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report['analysis'])
        
        # Calculate overall confidence
        report['confidence_score'] = self._calculate_confidence(report['analysis'])
        
        return report
    
    def _calculate_risk_level(self, risk_score: float) -> str:
        """Calculate risk level from score"""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        elif risk_score >= 0.2:
            return 'low'
        else:
            return 'minimal'
    
    def _calculate_confidence(self, analysis: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on pattern matches
        patterns = analysis.get('patterns', [])
        if patterns:
            confidence += min(0.3, len(patterns) * 0.05)
        
        # Increase confidence based on threat indicators
        threats = analysis.get('threat_indicators', [])
        if threats:
            confidence += min(0.2, len(threats) * 0.03)
        
        return min(1.0, confidence)
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        risk_score = analysis.get('risk_score', 0)
        patterns = analysis.get('patterns', [])
        threats = analysis.get('threat_indicators', [])
        
        if risk_score > 0.7:
            recommendations.append("HIGH RISK: Immediate investigation recommended")
        
        if 'disposable_email' in patterns:
            recommendations.append("Consider verifying email authenticity")
        
        if 'suspicious_tld' in patterns:
            recommendations.append("Investigate domain registration details")
        
        if 'suspicious_username' in threats:
            recommendations.append("Monitor for suspicious activity")
        
        if risk_score < 0.3:
            recommendations.append("Low risk profile - standard monitoring sufficient")
        
        return recommendations