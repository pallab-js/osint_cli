"""
Offline Intelligence Engine for Independent OSINT Analysis
Provides comprehensive offline intelligence capabilities without external dependencies
"""

import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import re

from .local_databases import LocalDatabases
from .pattern_engine import PatternRecognitionEngine


class OfflineIntelligenceEngine:
    """Comprehensive offline intelligence analysis engine"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.local_databases = LocalDatabases(str(self.data_dir))
        self.pattern_engine = PatternRecognitionEngine(self.local_databases)
        
        # Intelligence cache
        self.intelligence_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Analysis history
        self.analysis_history = []
        
        # Intelligence rules
        self.intelligence_rules = self._load_intelligence_rules()
    
    def _load_intelligence_rules(self) -> Dict[str, Any]:
        """Load intelligence analysis rules"""
        return {
            'email_intelligence': {
                'disposable_threshold': 0.3,
                'business_threshold': -0.1,
                'suspicious_threshold': 0.4,
                'breach_threshold': 0.5
            },
            'domain_intelligence': {
                'suspicious_tld_threshold': 0.5,
                'new_tld_threshold': 0.1,
                'subdomain_threshold': 0.3
            },
            'username_intelligence': {
                'suspicious_threshold': 0.6,
                'length_threshold': 0.4,
                'pattern_threshold': 0.2
            },
            'ip_intelligence': {
                'private_threshold': 0.1,
                'reserved_threshold': 0.2,
                'public_threshold': 0.0
            },
            'correlation_intelligence': {
                'high_correlation': 0.7,
                'medium_correlation': 0.4,
                'low_correlation': 0.1
            }
        }
    
    def analyze_email_intelligence(self, email: str) -> Dict[str, Any]:
        """Comprehensive email intelligence analysis"""
        # Check cache first
        cache_key = f"email_{hashlib.md5(email.encode()).hexdigest()}"
        if cache_key in self.intelligence_cache:
            cached_data = self.intelligence_cache[cache_key]
            if datetime.now().timestamp() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['data']
        
        analysis = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'intelligence_type': 'email',
            'basic_analysis': {},
            'pattern_analysis': {},
            'threat_analysis': {},
            'correlation_analysis': {},
            'intelligence_score': 0.0,
            'threat_level': 'unknown',
            'recommendations': []
        }
        
        # Basic email analysis
        analysis['basic_analysis'] = self._analyze_email_basic(email)
        
        # Pattern analysis
        analysis['pattern_analysis'] = self.pattern_engine.analyze_email_patterns(email)
        
        # Threat analysis
        analysis['threat_analysis'] = self._analyze_email_threats(email)
        
        # Provider analysis
        if '@' in email:
            domain = email.split('@')[1]
            analysis['provider_analysis'] = self.local_databases.get_email_provider_info(domain)
            analysis['breach_analysis'] = self.local_databases.get_breach_info(email)
        
        # TLD analysis
        if '@' in email:
            domain = email.split('@')[1]
            if '.' in domain:
                tld = domain.split('.')[-1]
                analysis['tld_analysis'] = self.local_databases.get_tld_info(tld)
        
        # Calculate intelligence score
        analysis['intelligence_score'] = self._calculate_email_intelligence_score(analysis)
        
        # Determine threat level
        analysis['threat_level'] = self._determine_threat_level(analysis['intelligence_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_email_recommendations(analysis)
        
        # Cache the result
        self.intelligence_cache[cache_key] = {
            'data': analysis,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add to history
        self.analysis_history.append({
            'target': email,
            'type': 'email',
            'timestamp': datetime.now().isoformat(),
            'intelligence_score': analysis['intelligence_score']
        })
        
        return analysis
    
    def analyze_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain intelligence analysis"""
        # Check cache first
        cache_key = f"domain_{hashlib.md5(domain.encode()).hexdigest()}"
        if cache_key in self.intelligence_cache:
            cached_data = self.intelligence_cache[cache_key]
            if datetime.now().timestamp() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['data']
        
        analysis = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'intelligence_type': 'domain',
            'basic_analysis': {},
            'pattern_analysis': {},
            'threat_analysis': {},
            'tld_analysis': {},
            'subdomain_analysis': {},
            'intelligence_score': 0.0,
            'threat_level': 'unknown',
            'recommendations': []
        }
        
        # Basic domain analysis
        analysis['basic_analysis'] = self._analyze_domain_basic(domain)
        
        # Pattern analysis
        analysis['pattern_analysis'] = self.pattern_engine.analyze_domain_patterns(domain)
        
        # TLD analysis
        if '.' in domain:
            tld = domain.split('.')[-1]
            analysis['tld_analysis'] = self.local_databases.get_tld_info(tld)
        
        # Subdomain analysis
        if domain.count('.') > 1:
            subdomain = '.'.join(domain.split('.')[:-2])
            analysis['subdomain_analysis'] = self._analyze_subdomain_intelligence(subdomain)
        
        # Threat analysis
        analysis['threat_analysis'] = self._analyze_domain_threats(domain)
        
        # Calculate intelligence score
        analysis['intelligence_score'] = self._calculate_domain_intelligence_score(analysis)
        
        # Determine threat level
        analysis['threat_level'] = self._determine_threat_level(analysis['intelligence_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_domain_recommendations(analysis)
        
        # Cache the result
        self.intelligence_cache[cache_key] = {
            'data': analysis,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add to history
        self.analysis_history.append({
            'target': domain,
            'type': 'domain',
            'timestamp': datetime.now().isoformat(),
            'intelligence_score': analysis['intelligence_score']
        })
        
        return analysis
    
    def analyze_username_intelligence(self, username: str) -> Dict[str, Any]:
        """Comprehensive username intelligence analysis"""
        # Check cache first
        cache_key = f"username_{hashlib.md5(username.encode()).hexdigest()}"
        if cache_key in self.intelligence_cache:
            cached_data = self.intelligence_cache[cache_key]
            if datetime.now().timestamp() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['data']
        
        analysis = {
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'intelligence_type': 'username',
            'basic_analysis': {},
            'pattern_analysis': {},
            'threat_analysis': {},
            'behavioral_analysis': {},
            'intelligence_score': 0.0,
            'threat_level': 'unknown',
            'recommendations': []
        }
        
        # Basic username analysis
        analysis['basic_analysis'] = self.local_databases.get_username_analysis(username)
        
        # Pattern analysis
        analysis['pattern_analysis'] = self.pattern_engine.analyze_username_patterns(username)
        
        # Threat analysis
        analysis['threat_analysis'] = self._analyze_username_threats(username)
        
        # Behavioral analysis
        analysis['behavioral_analysis'] = self._analyze_username_behavior(username)
        
        # Calculate intelligence score
        analysis['intelligence_score'] = self._calculate_username_intelligence_score(analysis)
        
        # Determine threat level
        analysis['threat_level'] = self._determine_threat_level(analysis['intelligence_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_username_recommendations(analysis)
        
        # Cache the result
        self.intelligence_cache[cache_key] = {
            'data': analysis,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add to history
        self.analysis_history.append({
            'target': username,
            'type': 'username',
            'timestamp': datetime.now().isoformat(),
            'intelligence_score': analysis['intelligence_score']
        })
        
        return analysis
    
    def analyze_ip_intelligence(self, ip: str) -> Dict[str, Any]:
        """Comprehensive IP intelligence analysis"""
        # Check cache first
        cache_key = f"ip_{hashlib.md5(ip.encode()).hexdigest()}"
        if cache_key in self.intelligence_cache:
            cached_data = self.intelligence_cache[cache_key]
            if datetime.now().timestamp() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['data']
        
        analysis = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'intelligence_type': 'ip',
            'basic_analysis': {},
            'classification_analysis': {},
            'threat_analysis': {},
            'geographic_analysis': {},
            'intelligence_score': 0.0,
            'threat_level': 'unknown',
            'recommendations': []
        }
        
        # Basic IP analysis
        analysis['basic_analysis'] = self._analyze_ip_basic(ip)
        
        # Classification analysis
        analysis['classification_analysis'] = self.local_databases.get_ip_classification(ip)
        
        # Geographic analysis (basic)
        analysis['geographic_analysis'] = self._analyze_ip_geography(ip)
        
        # Threat analysis
        analysis['threat_analysis'] = self._analyze_ip_threats(ip)
        
        # Calculate intelligence score
        analysis['intelligence_score'] = self._calculate_ip_intelligence_score(analysis)
        
        # Determine threat level
        analysis['threat_level'] = self._determine_threat_level(analysis['intelligence_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_ip_recommendations(analysis)
        
        # Cache the result
        self.intelligence_cache[cache_key] = {
            'data': analysis,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add to history
        self.analysis_history.append({
            'target': ip,
            'type': 'ip',
            'timestamp': datetime.now().isoformat(),
            'intelligence_score': analysis['intelligence_score']
        })
        
        return analysis
    
    def correlate_intelligence(self, targets: List[str]) -> Dict[str, Any]:
        """Correlate intelligence across multiple targets"""
        correlation = {
            'targets': targets,
            'timestamp': datetime.now().isoformat(),
            'correlation_type': 'multi_target',
            'individual_analyses': [],
            'correlation_patterns': {},
            'threat_network': {},
            'intelligence_summary': {},
            'correlation_score': 0.0,
            'recommendations': []
        }
        
        # Analyze each target individually
        for target in targets:
            if '@' in target:
                analysis = self.analyze_email_intelligence(target)
            elif '.' in target and not target.replace('.', '').isdigit():
                analysis = self.analyze_domain_intelligence(target)
            elif target.replace('.', '').isdigit():
                analysis = self.analyze_ip_intelligence(target)
            else:
                analysis = self.analyze_username_intelligence(target)
            
            correlation['individual_analyses'].append(analysis)
        
        # Find correlation patterns
        correlation['correlation_patterns'] = self.pattern_engine.correlate_patterns(targets)
        
        # Analyze threat network
        correlation['threat_network'] = self._analyze_threat_network(correlation['individual_analyses'])
        
        # Generate intelligence summary
        correlation['intelligence_summary'] = self._generate_intelligence_summary(correlation['individual_analyses'])
        
        # Calculate correlation score
        correlation['correlation_score'] = self._calculate_correlation_score(correlation)
        
        # Generate recommendations
        correlation['recommendations'] = self._generate_correlation_recommendations(correlation)
        
        return correlation
    
    def _analyze_email_basic(self, email: str) -> Dict[str, Any]:
        """Basic email analysis"""
        analysis = {
            'is_valid': '@' in email and '.' in email.split('@')[1],
            'username': email.split('@')[0] if '@' in email else '',
            'domain': email.split('@')[1] if '@' in email else '',
            'length': len(email),
            'has_special_chars': any(c in email for c in '._-+'),
            'has_numbers': any(c.isdigit() for c in email),
            'is_disposable': False
        }
        
        if analysis['domain']:
            provider_info = self.local_databases.get_email_provider_info(analysis['domain'])
            analysis['is_disposable'] = provider_info.get('is_disposable', False)
        
        return analysis
    
    def _analyze_domain_basic(self, domain: str) -> Dict[str, Any]:
        """Basic domain analysis"""
        analysis = {
            'is_valid': '.' in domain and len(domain) > 3,
            'length': len(domain),
            'subdomain_count': domain.count('.') - 1,
            'has_numbers': any(c.isdigit() for c in domain),
            'has_hyphens': '-' in domain,
            'tld': domain.split('.')[-1] if '.' in domain else ''
        }
        
        return analysis
    
    def _analyze_ip_basic(self, ip: str) -> Dict[str, Any]:
        """Basic IP analysis"""
        analysis = {
            'is_valid': self._is_valid_ip(ip),
            'version': 'IPv4' if '.' in ip else 'IPv6' if ':' in ip else 'unknown',
            'length': len(ip),
            'has_letters': any(c.isalpha() for c in ip)
        }
        
        return analysis
    
    def _analyze_email_threats(self, email: str) -> Dict[str, Any]:
        """Analyze email threats"""
        threats = {
            'threat_indicators': [],
            'risk_factors': [],
            'threat_score': 0.0
        }
        
        # Check for disposable email
        if '@' in email:
            domain = email.split('@')[1]
            provider_info = self.local_databases.get_email_provider_info(domain)
            if provider_info.get('is_disposable', False):
                threats['threat_indicators'].append('disposable_email')
                threats['threat_score'] += 0.3
        
        # Check for suspicious patterns
        if re.search(r'[0-9]{10,}@', email):
            threats['threat_indicators'].append('suspicious_number_sequence')
            threats['threat_score'] += 0.2
        
        if re.search(r'[^a-zA-Z0-9._-]@', email):
            threats['threat_indicators'].append('invalid_characters')
            threats['threat_score'] += 0.2
        
        return threats
    
    def _analyze_domain_threats(self, domain: str) -> Dict[str, Any]:
        """Analyze domain threats"""
        threats = {
            'threat_indicators': [],
            'risk_factors': [],
            'threat_score': 0.0
        }
        
        # Check TLD
        if '.' in domain:
            tld = domain.split('.')[-1]
            tld_info = self.local_databases.get_tld_info(tld)
            if tld_info.get('is_suspicious', False):
                threats['threat_indicators'].append('suspicious_tld')
                threats['threat_score'] += 0.4
        
        # Check subdomain patterns
        if domain.count('.') > 1:
            subdomain = '.'.join(domain.split('.')[:-2])
            if re.search(r'[0-9]{6,}', subdomain):
                threats['threat_indicators'].append('suspicious_subdomain')
                threats['threat_score'] += 0.3
        
        return threats
    
    def _analyze_username_threats(self, username: str) -> Dict[str, Any]:
        """Analyze username threats"""
        threats = {
            'threat_indicators': [],
            'risk_factors': [],
            'threat_score': 0.0
        }
        
        # Check for suspicious patterns
        suspicious_patterns = ['admin', 'administrator', 'root', 'user', 'test', 'demo']
        username_lower = username.lower()
        
        for pattern in suspicious_patterns:
            if pattern in username_lower:
                threats['threat_indicators'].append(f'suspicious_pattern: {pattern}')
                threats['threat_score'] += 0.2
        
        # Check length
        if len(username) <= 3:
            threats['threat_indicators'].append('very_short_username')
            threats['threat_score'] += 0.1
        
        return threats
    
    def _analyze_ip_threats(self, ip: str) -> Dict[str, Any]:
        """Analyze IP threats"""
        threats = {
            'threat_indicators': [],
            'risk_factors': [],
            'threat_score': 0.0
        }
        
        # Check IP classification
        classification = self.local_databases.get_ip_classification(ip)
        if classification['type'] == 'private':
            threats['threat_indicators'].append('private_ip')
            threats['threat_score'] += 0.1
        elif classification['type'] == 'reserved':
            threats['threat_indicators'].append('reserved_ip')
            threats['threat_score'] += 0.2
        
        return threats
    
    def _analyze_subdomain_intelligence(self, subdomain: str) -> Dict[str, Any]:
        """Analyze subdomain intelligence"""
        analysis = {
            'subdomain': subdomain,
            'length': len(subdomain),
            'has_numbers': any(c.isdigit() for c in subdomain),
            'has_letters': any(c.isalpha() for c in subdomain),
            'is_ip_like': re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', subdomain) is not None,
            'risk_score': 0.0
        }
        
        # Calculate risk score
        if analysis['is_ip_like']:
            analysis['risk_score'] += 0.4
        
        if len(subdomain) <= 3:
            analysis['risk_score'] += 0.2
        
        if re.search(r'[0-9]{6,}', subdomain):
            analysis['risk_score'] += 0.3
        
        return analysis
    
    def _analyze_username_behavior(self, username: str) -> Dict[str, Any]:
        """Analyze username behavioral patterns"""
        behavior = {
            'username': username,
            'length_category': 'medium',
            'character_patterns': {},
            'behavioral_indicators': [],
            'risk_score': 0.0
        }
        
        # Length analysis
        length = len(username)
        if length <= 3:
            behavior['length_category'] = 'very_short'
            behavior['risk_score'] += 0.3
        elif length <= 6:
            behavior['length_category'] = 'short'
            behavior['risk_score'] += 0.1
        elif length <= 12:
            behavior['length_category'] = 'medium'
        elif length <= 20:
            behavior['length_category'] = 'long'
        else:
            behavior['length_category'] = 'very_long'
            behavior['risk_score'] += 0.2
        
        # Character pattern analysis
        behavior['character_patterns'] = {
            'letter_count': len([c for c in username if c.isalpha()]),
            'number_count': len([c for c in username if c.isdigit()]),
            'special_count': len([c for c in username if c in '._-']),
            'other_count': len([c for c in username if c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-'])
        }
        
        return behavior
    
    def _analyze_ip_geography(self, ip: str) -> Dict[str, Any]:
        """Basic IP geographic analysis (offline)"""
        geography = {
            'ip': ip,
            'region': 'unknown',
            'country': 'unknown',
            'is_private': False,
            'is_reserved': False
        }
        
        # Basic IP range analysis
        classification = self.local_databases.get_ip_classification(ip)
        if classification['type'] == 'private':
            geography['is_private'] = True
            geography['region'] = 'private_network'
        elif classification['type'] == 'reserved':
            geography['is_reserved'] = True
            geography['region'] = 'reserved_range'
        else:
            geography['region'] = 'public_network'
        
        return geography
    
    def _analyze_threat_network(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat network from multiple analyses"""
        network = {
            'total_targets': len(analyses),
            'high_risk_targets': [],
            'common_threats': [],
            'network_risk_score': 0.0,
            'threat_indicators': []
        }
        
        # Collect high-risk targets
        for analysis in analyses:
            if analysis.get('threat_level', 'unknown') in ['high', 'critical']:
                network['high_risk_targets'].append(analysis)
        
        # Collect common threats
        all_threats = []
        for analysis in analyses:
            threats = analysis.get('threat_analysis', {}).get('threat_indicators', [])
            all_threats.extend(threats)
        
        threat_counts = {}
        for threat in all_threats:
            threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        network['common_threats'] = [threat for threat, count in threat_counts.items() if count > 1]
        
        # Calculate network risk score
        risk_scores = [analysis.get('intelligence_score', 0) for analysis in analyses]
        network['network_risk_score'] = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return network
    
    def _generate_intelligence_summary(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate intelligence summary from analyses"""
        summary = {
            'total_analyses': len(analyses),
            'average_intelligence_score': 0.0,
            'threat_level_distribution': {},
            'common_patterns': [],
            'recommendations': []
        }
        
        if not analyses:
            return summary
        
        # Calculate average intelligence score
        scores = [analysis.get('intelligence_score', 0) for analysis in analyses]
        summary['average_intelligence_score'] = sum(scores) / len(scores)
        
        # Threat level distribution
        threat_levels = [analysis.get('threat_level', 'unknown') for analysis in analyses]
        threat_counts = {}
        for level in threat_levels:
            threat_counts[level] = threat_counts.get(level, 0) + 1
        summary['threat_level_distribution'] = threat_counts
        
        # Common patterns
        all_patterns = []
        for analysis in analyses:
            patterns = analysis.get('pattern_analysis', {}).get('patterns', [])
            all_patterns.extend(patterns)
        
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        summary['common_patterns'] = [pattern for pattern, count in pattern_counts.items() if count > 1]
        
        return summary
    
    def _calculate_email_intelligence_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate email intelligence score"""
        score = 0.0
        
        # Basic analysis factors
        basic = analysis.get('basic_analysis', {})
        if basic.get('is_disposable', False):
            score += 0.3
        
        # Pattern analysis factors
        pattern = analysis.get('pattern_analysis', {})
        score += pattern.get('risk_score', 0) * 0.4
        
        # Threat analysis factors
        threat = analysis.get('threat_analysis', {})
        score += threat.get('threat_score', 0) * 0.3
        
        return min(1.0, score)
    
    def _calculate_domain_intelligence_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate domain intelligence score"""
        score = 0.0
        
        # Pattern analysis factors
        pattern = analysis.get('pattern_analysis', {})
        score += pattern.get('risk_score', 0) * 0.5
        
        # TLD analysis factors
        tld = analysis.get('tld_analysis', {})
        if tld.get('is_suspicious', False):
            score += 0.4
        
        # Subdomain analysis factors
        subdomain = analysis.get('subdomain_analysis', {})
        score += subdomain.get('risk_score', 0) * 0.3
        
        return min(1.0, score)
    
    def _calculate_username_intelligence_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate username intelligence score"""
        score = 0.0
        
        # Basic analysis factors
        basic = analysis.get('basic_analysis', {})
        score += basic.get('risk_score', 0) * 0.4
        
        # Pattern analysis factors
        pattern = analysis.get('pattern_analysis', {})
        score += pattern.get('risk_score', 0) * 0.4
        
        # Threat analysis factors
        threat = analysis.get('threat_analysis', {})
        score += threat.get('threat_score', 0) * 0.2
        
        return min(1.0, score)
    
    def _calculate_ip_intelligence_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate IP intelligence score"""
        score = 0.0
        
        # Classification analysis factors
        classification = analysis.get('classification_analysis', {})
        if classification.get('type') == 'private':
            score += 0.1
        elif classification.get('type') == 'reserved':
            score += 0.2
        
        # Threat analysis factors
        threat = analysis.get('threat_analysis', {})
        score += threat.get('threat_score', 0) * 0.5
        
        return min(1.0, score)
    
    def _calculate_correlation_score(self, correlation: Dict[str, Any]) -> float:
        """Calculate correlation score"""
        patterns = correlation.get('correlation_patterns', {})
        return patterns.get('correlation_score', 0.0)
    
    def _determine_threat_level(self, intelligence_score: float) -> str:
        """Determine threat level from intelligence score"""
        if intelligence_score >= 0.8:
            return 'critical'
        elif intelligence_score >= 0.6:
            return 'high'
        elif intelligence_score >= 0.4:
            return 'medium'
        elif intelligence_score >= 0.2:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_email_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate email recommendations"""
        recommendations = []
        
        intelligence_score = analysis.get('intelligence_score', 0)
        threat_level = analysis.get('threat_level', 'unknown')
        
        if threat_level in ['high', 'critical']:
            recommendations.append("HIGH PRIORITY: Immediate investigation required")
        
        if analysis.get('basic_analysis', {}).get('is_disposable', False):
            recommendations.append("Verify email authenticity - disposable provider detected")
        
        if analysis.get('tld_analysis', {}).get('is_suspicious', False):
            recommendations.append("Investigate domain registration - suspicious TLD detected")
        
        if intelligence_score < 0.3:
            recommendations.append("Low risk profile - standard monitoring sufficient")
        
        return recommendations
    
    def _generate_domain_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate domain recommendations"""
        recommendations = []
        
        intelligence_score = analysis.get('intelligence_score', 0)
        threat_level = analysis.get('threat_level', 'unknown')
        
        if threat_level in ['high', 'critical']:
            recommendations.append("HIGH PRIORITY: Immediate investigation required")
        
        if analysis.get('tld_analysis', {}).get('is_suspicious', False):
            recommendations.append("Investigate domain registration - suspicious TLD detected")
        
        if analysis.get('subdomain_analysis', {}).get('risk_score', 0) > 0.3:
            recommendations.append("Investigate subdomain - suspicious patterns detected")
        
        if intelligence_score < 0.3:
            recommendations.append("Low risk profile - standard monitoring sufficient")
        
        return recommendations
    
    def _generate_username_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate username recommendations"""
        recommendations = []
        
        intelligence_score = analysis.get('intelligence_score', 0)
        threat_level = analysis.get('threat_level', 'unknown')
        
        if threat_level in ['high', 'critical']:
            recommendations.append("HIGH PRIORITY: Immediate investigation required")
        
        if analysis.get('basic_analysis', {}).get('is_suspicious', False):
            recommendations.append("Monitor for suspicious activity - suspicious username detected")
        
        if intelligence_score < 0.3:
            recommendations.append("Low risk profile - standard monitoring sufficient")
        
        return recommendations
    
    def _generate_ip_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate IP recommendations"""
        recommendations = []
        
        intelligence_score = analysis.get('intelligence_score', 0)
        threat_level = analysis.get('threat_level', 'unknown')
        
        if threat_level in ['high', 'critical']:
            recommendations.append("HIGH PRIORITY: Immediate investigation required")
        
        classification = analysis.get('classification_analysis', {})
        if classification.get('type') == 'private':
            recommendations.append("Private IP detected - verify network context")
        elif classification.get('type') == 'reserved':
            recommendations.append("Reserved IP detected - investigate usage")
        
        if intelligence_score < 0.3:
            recommendations.append("Low risk profile - standard monitoring sufficient")
        
        return recommendations
    
    def _generate_correlation_recommendations(self, correlation: Dict[str, Any]) -> List[str]:
        """Generate correlation recommendations"""
        recommendations = []
        
        correlation_score = correlation.get('correlation_score', 0)
        threat_network = correlation.get('threat_network', {})
        
        if correlation_score > 0.7:
            recommendations.append("HIGH CORRELATION: Investigate potential threat network")
        
        if threat_network.get('high_risk_targets'):
            recommendations.append(f"Monitor {len(threat_network['high_risk_targets'])} high-risk targets")
        
        if threat_network.get('common_threats'):
            recommendations.append(f"Investigate common threats: {', '.join(threat_network['common_threats'])}")
        
        return recommendations
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get analysis history"""
        return self.analysis_history
    
    def clear_cache(self):
        """Clear intelligence cache"""
        self.intelligence_cache.clear()
    
    def save_intelligence_data(self, filepath: str):
        """Save intelligence data to file"""
        data = {
            'cache': self.intelligence_cache,
            'history': self.analysis_history,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_intelligence_data(self, filepath: str):
        """Load intelligence data from file"""
        if Path(filepath).exists():
            with open(filepath, 'r') as f:
                data = json.load(f)
                self.intelligence_cache = data.get('cache', {})
                self.analysis_history = data.get('history', [])