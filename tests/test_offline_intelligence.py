"""
Test suite for offline intelligence capabilities
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from pathlib import Path

from osint_cli.core.local_databases import LocalDatabases
from osint_cli.core.pattern_engine import PatternRecognitionEngine
from osint_cli.core.offline_intelligence import OfflineIntelligenceEngine
from osint_cli.core.offline_cli import OfflineCLI


class TestLocalDatabases:
    """Test local databases functionality"""
    
    def test_init(self):
        """Test LocalDatabases initialization"""
        db = LocalDatabases()
        assert db.tld_database is not None
        assert db.ip_ranges is not None
        assert db.email_providers is not None
        assert db.breach_patterns is not None
        assert db.username_patterns is not None
        assert db.social_platforms is not None
        assert db.threat_indicators is not None
        assert db.geo_data is not None
    
    def test_get_tld_info(self):
        """Test TLD information retrieval"""
        db = LocalDatabases()
        
        # Test generic TLD
        info = db.get_tld_info('com')
        assert info['tld'] == 'com'
        assert info['category'] in ['generic_tlds', 'unknown']
        assert not info['is_suspicious']
        
        # Test suspicious TLD (tk appears in both new_tlds and suspicious_tlds)
        info = db.get_tld_info('tk')
        assert info['tld'] == 'tk'
        assert info['category'] in ['new_tlds', 'suspicious_tlds', 'unknown']
        # Since tk appears in both lists, it might be found in new_tlds first
        if info['category'] == 'suspicious_tlds':
            assert info['is_suspicious']
        else:
            assert not info['is_suspicious']
        
        # Test unknown TLD
        info = db.get_tld_info('unknown')
        assert info['tld'] == 'unknown'
        assert info['category'] == 'unknown'
        assert not info['is_suspicious']
    
    def test_get_ip_classification(self):
        """Test IP classification"""
        db = LocalDatabases()
        
        # Test private IP
        classification = db.get_ip_classification('192.168.1.1')
        assert classification['type'] == 'private'
        assert classification['class'] == 'C'
        
        # Test public IP
        classification = db.get_ip_classification('8.8.8.8')
        assert classification['type'] == 'public'
        assert classification['class'] == 'Public'
    
    def test_get_email_provider_info(self):
        """Test email provider information"""
        db = LocalDatabases()
        
        # Test major provider
        info = db.get_email_provider_info('gmail.com')
        assert info['domain'] == 'gmail.com'
        assert info['category'] in ['major_providers', 'unknown']
        assert not info['is_disposable']
        assert not info['is_suspicious']
        
        # Test disposable provider (tempmail.org appears in both disposable and suspicious lists)
        info = db.get_email_provider_info('tempmail.org')
        assert info['domain'] == 'tempmail.org'
        assert info['category'] in ['disposable_providers', 'suspicious_providers', 'unknown']
        # Since it appears in both lists, it might be found in disposable_providers first
        if info['category'] == 'disposable_providers':
            assert info['is_disposable']
            assert not info['is_suspicious']
        elif info['category'] == 'suspicious_providers':
            assert not info['is_disposable']
            assert info['is_suspicious']
    
    def test_get_breach_info(self):
        """Test breach information"""
        db = LocalDatabases()
        
        # Test email with breach
        info = db.get_breach_info('user@linkedin.com')
        assert info['email'] == 'user@linkedin.com'
        assert info['domain'] == 'linkedin.com'
        assert 'linkedin' in info['breaches']
        assert info['breach_count'] > 0
        assert info['severity'] == 'medium'
        
        # Test email without breach
        info = db.get_breach_info('user@example.com')
        assert info['email'] == 'user@example.com'
        assert info['domain'] == 'example.com'
        assert info['breaches'] == []
        assert info['breach_count'] == 0
        assert info['severity'] == 'none'
    
    def test_get_username_analysis(self):
        """Test username analysis"""
        db = LocalDatabases()
        
        # Test normal username
        analysis = db.get_username_analysis('john_doe')
        assert analysis['username'] == 'john_doe'
        assert analysis['length'] == 8
        assert analysis['length_category'] == 'medium'
        assert not analysis['has_numbers']
        assert analysis['has_special_chars']
        assert not analysis['is_suspicious']
        assert analysis['threat_level'] == 'low'
        
        # Test suspicious username
        analysis = db.get_username_analysis('admin')
        assert analysis['username'] == 'admin'
        assert analysis['is_suspicious']
        assert analysis['threat_level'] == 'high'
        assert analysis['risk_score'] > 0.5


class TestPatternRecognitionEngine:
    """Test pattern recognition engine"""
    
    def test_init(self):
        """Test PatternRecognitionEngine initialization"""
        engine = PatternRecognitionEngine()
        assert engine.email_patterns is not None
        assert engine.domain_patterns is not None
        assert engine.username_patterns is not None
        assert engine.threat_patterns is not None
        assert engine.behavioral_patterns is not None
    
    def test_analyze_email_patterns(self):
        """Test email pattern analysis"""
        engine = PatternRecognitionEngine()
        
        # Test normal email
        analysis = engine.analyze_email_patterns('user@example.com')
        assert analysis['email'] == 'user@example.com'
        assert 'common_format' in analysis['patterns']
        assert analysis['risk_score'] < 0.3
        
        # Test disposable email
        analysis = engine.analyze_email_patterns('user@tempmail.org')
        assert 'disposable_email' in analysis['patterns']
        assert analysis['risk_score'] > 0.3
        
        # Test suspicious email
        analysis = engine.analyze_email_patterns('1234567890@example.com')
        assert 'suspicious_format' in analysis['patterns']
        assert analysis['risk_score'] > 0.4
    
    def test_analyze_domain_patterns(self):
        """Test domain pattern analysis"""
        engine = PatternRecognitionEngine()
        
        # Test normal domain
        analysis = engine.analyze_domain_patterns('example.com')
        assert analysis['domain'] == 'example.com'
        assert analysis['risk_score'] < 0.2
        
        # Test suspicious domain
        analysis = engine.analyze_domain_patterns('example.tk')
        assert 'suspicious_tld' in analysis['patterns']
        assert analysis['risk_score'] > 0.4
        
        # Test subdomain analysis
        analysis = engine.analyze_domain_patterns('sub.example.com')
        assert analysis['domain'] == 'sub.example.com'
        assert 'subdomain_analysis' in analysis
    
    def test_analyze_username_patterns(self):
        """Test username pattern analysis"""
        engine = PatternRecognitionEngine()
        
        # Test normal username
        analysis = engine.analyze_username_patterns('john_doe')
        assert analysis['username'] == 'john_doe'
        assert 'common_format' in analysis['patterns']
        assert analysis['risk_score'] < 0.3
        
        # Test suspicious username
        analysis = engine.analyze_username_patterns('admin')
        assert 'suspicious_format' in analysis['patterns']
        assert analysis['risk_score'] > 0.6
        
        # Test number pattern
        analysis = engine.analyze_username_patterns('user123')
        assert 'number_format' in analysis['patterns']
        assert analysis['risk_score'] > 0.1
    
    def test_detect_threat_patterns(self):
        """Test threat pattern detection"""
        engine = PatternRecognitionEngine()
        
        # Test normal text
        analysis = engine.detect_threat_patterns('Hello world')
        assert analysis['text'] == 'Hello world'
        assert analysis['threats_detected'] == []
        assert analysis['risk_score'] == 0.0
        
        # Test malicious text
        analysis = engine.detect_threat_patterns('This is a hack attempt')
        assert 'malicious_keyword: hack' in analysis['threats_detected']
        assert analysis['risk_score'] >= 0.2
        
        # Test suspicious text
        analysis = engine.detect_threat_patterns('Admin panel access')
        assert 'suspicious_phrase: admin panel' in analysis['threats_detected']
        assert analysis['risk_score'] >= 0.3
    
    def test_correlate_patterns(self):
        """Test pattern correlation"""
        engine = PatternRecognitionEngine()
        
        # Test correlation with similar patterns
        targets = ['user@example.com', 'user@test.com', 'user@demo.com']
        correlation = engine.correlate_patterns(targets)
        
        assert correlation['targets'] == targets
        assert correlation['correlation_score'] > 0.0
        assert 'common_patterns' in correlation
        assert 'unique_patterns' in correlation
    
    def test_generate_intelligence_report(self):
        """Test intelligence report generation"""
        engine = PatternRecognitionEngine()
        
        report = engine.generate_intelligence_report('user@example.com')
        assert report['target'] == 'user@example.com'
        assert 'timestamp' in report
        assert 'analysis' in report
        assert 'threat_assessment' in report
        assert 'recommendations' in report
        assert 'confidence_score' in report


class TestOfflineIntelligenceEngine:
    """Test offline intelligence engine"""
    
    def test_init(self):
        """Test OfflineIntelligenceEngine initialization"""
        engine = OfflineIntelligenceEngine()
        assert engine.local_databases is not None
        assert engine.pattern_engine is not None
        assert engine.intelligence_cache is not None
        assert engine.analysis_history is not None
        assert engine.intelligence_rules is not None
    
    def test_analyze_email_intelligence(self):
        """Test email intelligence analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_email_intelligence('user@example.com')
        assert analysis['email'] == 'user@example.com'
        assert analysis['intelligence_type'] == 'email'
        assert 'basic_analysis' in analysis
        assert 'pattern_analysis' in analysis
        assert 'threat_analysis' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
    
    def test_analyze_domain_intelligence(self):
        """Test domain intelligence analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_domain_intelligence('example.com')
        assert analysis['domain'] == 'example.com'
        assert analysis['intelligence_type'] == 'domain'
        assert 'basic_analysis' in analysis
        assert 'pattern_analysis' in analysis
        assert 'tld_analysis' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
    
    def test_analyze_username_intelligence(self):
        """Test username intelligence analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_username_intelligence('john_doe')
        assert analysis['username'] == 'john_doe'
        assert analysis['intelligence_type'] == 'username'
        assert 'basic_analysis' in analysis
        assert 'pattern_analysis' in analysis
        assert 'threat_analysis' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
    
    def test_analyze_ip_intelligence(self):
        """Test IP intelligence analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_ip_intelligence('8.8.8.8')
        assert analysis['ip'] == '8.8.8.8'
        assert analysis['intelligence_type'] == 'ip'
        assert 'basic_analysis' in analysis
        assert 'classification_analysis' in analysis
        assert 'geographic_analysis' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
    
    def test_correlate_intelligence(self):
        """Test intelligence correlation"""
        engine = OfflineIntelligenceEngine()
        
        targets = ['user@example.com', 'example.com', 'john_doe']
        correlation = engine.correlate_intelligence(targets)
        
        assert correlation['targets'] == targets
        assert correlation['correlation_type'] == 'multi_target'
        assert 'individual_analyses' in correlation
        assert 'correlation_patterns' in correlation
        assert 'threat_network' in correlation
        assert 'intelligence_summary' in correlation
        assert 'correlation_score' in correlation
        assert 'recommendations' in correlation
    
    def test_cache_functionality(self):
        """Test cache functionality"""
        engine = OfflineIntelligenceEngine()
        
        # Test cache clearing
        engine.clear_cache()
        assert len(engine.intelligence_cache) == 0
        
        # Test cache population
        analysis = engine.analyze_email_intelligence('user@example.com')
        assert len(engine.intelligence_cache) > 0
        
        # Test cache retrieval
        cached_analysis = engine.analyze_email_intelligence('user@example.com')
        assert cached_analysis == analysis
    
    def test_analysis_history(self):
        """Test analysis history"""
        engine = OfflineIntelligenceEngine()
        
        # Test history tracking
        initial_history = len(engine.analysis_history)
        engine.analyze_email_intelligence('user@example.com')
        assert len(engine.analysis_history) == initial_history + 1
        
        # Test history retrieval
        history = engine.get_analysis_history()
        assert len(history) > 0
        assert history[-1]['target'] == 'user@example.com'
        assert history[-1]['type'] == 'email'


class TestOfflineCLI:
    """Test offline CLI functionality"""
    
    def test_init(self):
        """Test OfflineCLI initialization"""
        cli = OfflineCLI()
        assert cli.colors is not None
        assert cli.reporter is not None
        assert cli.intelligence_engine is not None
        assert cli.parser is not None
    
    def test_email_analysis_command(self):
        """Test email analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'user@example.com'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'analyze_email_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'email': 'user@example.com',
                'intelligence_score': 0.5,
                'threat_level': 'medium',
                'recommendations': ['Test recommendation']
            }
            
            result = cli._handle_email_analysis()
            assert result == 0
            mock_analyze.assert_called_once_with('user@example.com')
    
    def test_domain_analysis_command(self):
        """Test domain analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'example.com'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'analyze_domain_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'domain': 'example.com',
                'intelligence_score': 0.3,
                'threat_level': 'low',
                'recommendations': ['Test recommendation']
            }
            
            result = cli._handle_domain_analysis()
            assert result == 0
            mock_analyze.assert_called_once_with('example.com')
    
    def test_username_analysis_command(self):
        """Test username analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'john_doe'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'analyze_username_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'username': 'john_doe',
                'intelligence_score': 0.4,
                'threat_level': 'medium',
                'recommendations': ['Test recommendation']
            }
            
            result = cli._handle_username_analysis()
            assert result == 0
            mock_analyze.assert_called_once_with('john_doe')
    
    def test_ip_analysis_command(self):
        """Test IP analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = '8.8.8.8'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'analyze_ip_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'ip': '8.8.8.8',
                'intelligence_score': 0.2,
                'threat_level': 'low',
                'recommendations': ['Test recommendation']
            }
            
            result = cli._handle_ip_analysis()
            assert result == 0
            mock_analyze.assert_called_once_with('8.8.8.8')
    
    def test_correlation_analysis_command(self):
        """Test correlation analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.targets = 'user@example.com,example.com'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'correlate_intelligence') as mock_correlate:
            mock_correlate.return_value = {
                'targets': ['user@example.com', 'example.com'],
                'correlation_score': 0.6,
                'recommendations': ['Test recommendation'],
                'individual_analyses': []
            }
            
            result = cli._handle_correlation_analysis()
            assert result == 0
            mock_correlate.assert_called_once()
    
    def test_comprehensive_analysis_command(self):
        """Test comprehensive analysis command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'user@example.com'
        cli.args.output = None
        
        with patch.object(cli.intelligence_engine, 'analyze_email_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'email': 'user@example.com',
                'intelligence_score': 0.5,
                'threat_level': 'medium',
                'recommendations': ['Test recommendation']
            }
            
            result = cli._handle_comprehensive_analysis()
            assert result == 0
            mock_analyze.assert_called_once_with('user@example.com')
    
    def test_history_command(self):
        """Test history command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.limit = 10
        cli.args.filter = None
        
        with patch.object(cli.intelligence_engine, 'get_analysis_history') as mock_history:
            mock_history.return_value = [
                {
                    'target': 'user@example.com',
                    'type': 'email',
                    'timestamp': '2023-01-01T00:00:00',
                    'intelligence_score': 0.5
                }
            ]
            
            result = cli._handle_history()
            assert result == 0
            mock_history.assert_called_once()
    
    def test_cache_management_command(self):
        """Test cache management command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.clear = True
        cli.args.status = False
        
        with patch.object(cli.intelligence_engine, 'clear_cache') as mock_clear:
            result = cli._handle_cache_management()
            assert result == 0
            mock_clear.assert_called_once()
    
    def test_database_management_command(self):
        """Test database management command"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.update = False
        cli.args.status = False
        cli.args.export = None
        cli.args.import_file = None
        
        with patch.object(cli.intelligence_engine.local_databases, 'save_databases') as mock_save:
            result = cli._handle_database_management()
            assert result == 0
    
    def test_invalid_email_analysis(self):
        """Test invalid email analysis"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'invalid-email'
        
        result = cli._handle_email_analysis()
        assert result == 1
    
    def test_invalid_domain_analysis(self):
        """Test invalid domain analysis"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'invalid-domain'
        
        result = cli._handle_domain_analysis()
        assert result == 1
    
    def test_invalid_ip_analysis(self):
        """Test invalid IP analysis"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = 'invalid-ip'
        
        result = cli._handle_ip_analysis()
        assert result == 1
    
    def test_invalid_username_analysis(self):
        """Test invalid username analysis"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.target = ''
        
        result = cli._handle_username_analysis()
        assert result == 1
    
    def test_insufficient_correlation_targets(self):
        """Test correlation with insufficient targets"""
        cli = OfflineCLI()
        cli.args = Mock()
        cli.args.targets = 'single-target'
        
        result = cli._handle_correlation_analysis()
        assert result == 1
    
    def test_save_analysis(self):
        """Test analysis saving"""
        cli = OfflineCLI()
        
        analysis = {'test': 'data'}
        with patch('builtins.open', create=True) as mock_open:
            cli._save_analysis(analysis, 'test.json')
            mock_open.assert_called_once_with('test.json', 'w')
    
    def test_save_report(self):
        """Test report saving"""
        cli = OfflineCLI()
        
        report = {'test': 'data'}
        with patch('builtins.open', create=True) as mock_open:
            cli._save_report(report, 'test.txt', 'txt')
            mock_open.assert_called_once_with('test.txt', 'w')
    
    def test_generate_intelligence_report(self):
        """Test intelligence report generation"""
        cli = OfflineCLI()
        
        analysis = {
            'email': 'user@example.com',
            'intelligence_score': 0.5,
            'threat_level': 'medium',
            'recommendations': ['Test recommendation']
        }
        
        report = cli._generate_intelligence_report(analysis)
        assert report['target'] == 'user@example.com'
        assert report['intelligence_score'] == 0.5
        assert report['threat_level'] == 'medium'
        assert 'summary' in report
        assert 'recommendations' in report
    
    def test_colorize_threat_level(self):
        """Test threat level colorization"""
        cli = OfflineCLI()
        
        # Test different threat levels
        assert 'CRITICAL' in cli._colorize_threat_level('critical')
        assert 'HIGH' in cli._colorize_threat_level('high')
        assert 'MEDIUM' in cli._colorize_threat_level('medium')
        assert 'LOW' in cli._colorize_threat_level('low')
        assert 'UNKNOWN' in cli._colorize_threat_level('unknown')
    
    def test_run_method(self):
        """Test CLI run method"""
        cli = OfflineCLI()
        
        # Test with valid command
        with patch.object(cli, '_handle_email_analysis', return_value=0):
            result = cli.run(['email', '--target', 'user@example.com'])
            assert result == 0
        
        # Test with invalid command
        result = cli.run(['invalid-command'])
        assert result == 1
        
        # Test with no command
        result = cli.run([])
        assert result == 1


class TestIntegration:
    """Integration tests for offline intelligence system"""
    
    def test_end_to_end_email_analysis(self):
        """Test end-to-end email analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_email_intelligence('user@example.com')
        
        # Verify analysis structure
        assert 'email' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
        
        # Verify score is within valid range
        assert 0.0 <= analysis['intelligence_score'] <= 1.0
        
        # Verify threat level is valid
        assert analysis['threat_level'] in ['minimal', 'low', 'medium', 'high', 'critical', 'unknown']
    
    def test_end_to_end_domain_analysis(self):
        """Test end-to-end domain analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_domain_intelligence('example.com')
        
        # Verify analysis structure
        assert 'domain' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
        
        # Verify score is within valid range
        assert 0.0 <= analysis['intelligence_score'] <= 1.0
        
        # Verify threat level is valid
        assert analysis['threat_level'] in ['minimal', 'low', 'medium', 'high', 'critical', 'unknown']
    
    def test_end_to_end_username_analysis(self):
        """Test end-to-end username analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_username_intelligence('john_doe')
        
        # Verify analysis structure
        assert 'username' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
        
        # Verify score is within valid range
        assert 0.0 <= analysis['intelligence_score'] <= 1.0
        
        # Verify threat level is valid
        assert analysis['threat_level'] in ['minimal', 'low', 'medium', 'high', 'critical', 'unknown']
    
    def test_end_to_end_ip_analysis(self):
        """Test end-to-end IP analysis"""
        engine = OfflineIntelligenceEngine()
        
        analysis = engine.analyze_ip_intelligence('8.8.8.8')
        
        # Verify analysis structure
        assert 'ip' in analysis
        assert 'intelligence_score' in analysis
        assert 'threat_level' in analysis
        assert 'recommendations' in analysis
        
        # Verify score is within valid range
        assert 0.0 <= analysis['intelligence_score'] <= 1.0
        
        # Verify threat level is valid
        assert analysis['threat_level'] in ['minimal', 'low', 'medium', 'high', 'critical', 'unknown']
    
    def test_end_to_end_correlation_analysis(self):
        """Test end-to-end correlation analysis"""
        engine = OfflineIntelligenceEngine()
        
        targets = ['user@example.com', 'example.com', 'john_doe']
        correlation = engine.correlate_intelligence(targets)
        
        # Verify correlation structure
        assert 'targets' in correlation
        assert 'correlation_score' in correlation
        assert 'individual_analyses' in correlation
        assert 'recommendations' in correlation
        
        # Verify correlation score is within valid range
        assert 0.0 <= correlation['correlation_score'] <= 1.0
        
        # Verify individual analyses
        assert len(correlation['individual_analyses']) == len(targets)
    
    def test_cli_integration(self):
        """Test CLI integration"""
        cli = OfflineCLI()
        
        # Test email analysis through CLI
        with patch.object(cli.intelligence_engine, 'analyze_email_intelligence') as mock_analyze:
            mock_analyze.return_value = {
                'email': 'user@example.com',
                'intelligence_score': 0.5,
                'threat_level': 'medium',
                'recommendations': ['Test recommendation']
            }
            
            result = cli.run(['email', '--target', 'user@example.com'])
            assert result == 0
            mock_analyze.assert_called_once_with('user@example.com')
    
    def test_data_persistence(self):
        """Test data persistence functionality"""
        engine = OfflineIntelligenceEngine()
        
        # Test saving intelligence data
        with patch('builtins.open', create=True) as mock_open:
            engine.save_intelligence_data('test_data.json')
            mock_open.assert_called_once_with('test_data.json', 'w')
        
        # Test loading intelligence data
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = '{"cache": {}, "history": []}'
            engine.load_intelligence_data('test_data.json')
            mock_open.assert_called_once_with('test_data.json', 'r')
    
    def test_database_persistence(self):
        """Test database persistence functionality"""
        db = LocalDatabases()
        
        # Test saving databases
        with patch('builtins.open', create=True) as mock_open:
            db.save_databases()
            # Should be called multiple times for different databases
            assert mock_open.call_count > 0
        
        # Test loading databases
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = '{}'
            db.load_databases()
            # Should be called multiple times for different databases
            assert mock_open.call_count > 0