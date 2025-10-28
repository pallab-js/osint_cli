"""
Tests for main module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from osint_cli.main import main, email_command, domain_command, ip_command, social_command, scan_command


class TestMainModule:
    """Test main module functionality"""
    
    def test_email_command_valid_email(self):
        """Test email command with valid email"""
        args = Mock()
        args.target = "test@example.com"
        
        with patch('osint_cli.main.validate_email', return_value=True), \
             patch('osint_cli.main.EmailInvestigator') as mock_investigator_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.return_value = {'email': 'test@example.com', 'valid': True}
            mock_investigator_class.return_value = mock_investigator
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = email_command(args)
            
            assert result == 0
            mock_investigator.investigate.assert_called_once_with("test@example.com")
            mock_reporter.print_email_report.assert_called_once()
    
    def test_email_command_invalid_email(self):
        """Test email command with invalid email"""
        args = Mock()
        args.target = "invalid-email"
        
        with patch('osint_cli.main.validate_email', return_value=False), \
             patch('builtins.print') as mock_print:
            
            result = email_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_email_command_exception(self):
        """Test email command with exception"""
        args = Mock()
        args.target = "test@example.com"
        
        with patch('osint_cli.main.validate_email', return_value=True), \
             patch('osint_cli.main.EmailInvestigator') as mock_investigator_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.side_effect = Exception("Test error")
            mock_investigator_class.return_value = mock_investigator
            
            result = email_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_domain_command_valid_domain(self):
        """Test domain command with valid domain"""
        args = Mock()
        args.target = "example.com"
        
        with patch('osint_cli.main.validate_domain', return_value=True), \
             patch('osint_cli.main.DomainAnalyzer') as mock_analyzer_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_analyzer = Mock()
            mock_analyzer.analyze.return_value = {'domain': 'example.com'}
            mock_analyzer_class.return_value = mock_analyzer
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = domain_command(args)
            
            assert result == 0
            mock_analyzer.analyze.assert_called_once_with("example.com")
            mock_reporter.print_domain_report.assert_called_once()
    
    def test_domain_command_invalid_domain(self):
        """Test domain command with invalid domain"""
        args = Mock()
        args.target = "invalid-domain"
        
        with patch('osint_cli.main.validate_domain', return_value=False), \
             patch('builtins.print') as mock_print:
            
            result = domain_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_domain_command_exception(self):
        """Test domain command with exception"""
        args = Mock()
        args.target = "example.com"
        
        with patch('osint_cli.main.validate_domain', return_value=True), \
             patch('osint_cli.main.DomainAnalyzer') as mock_analyzer_class, \
             patch('builtins.print') as mock_print:
            
            mock_analyzer = Mock()
            mock_analyzer.analyze.side_effect = Exception("Test error")
            mock_analyzer_class.return_value = mock_analyzer
            
            result = domain_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_ip_command_valid_ip(self):
        """Test IP command with valid IP"""
        args = Mock()
        args.target = "8.8.8.8"
        
        with patch('osint_cli.main.validate_ip', return_value=True), \
             patch('osint_cli.main.IPInvestigator') as mock_investigator_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.return_value = {'ip': '8.8.8.8'}
            mock_investigator_class.return_value = mock_investigator
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = ip_command(args)
            
            assert result == 0
            mock_investigator.investigate.assert_called_once_with("8.8.8.8")
            mock_reporter.print_ip_report.assert_called_once()
    
    def test_ip_command_invalid_ip(self):
        """Test IP command with invalid IP"""
        args = Mock()
        args.target = "invalid-ip"
        
        with patch('osint_cli.main.validate_ip', return_value=False), \
             patch('builtins.print') as mock_print:
            
            result = ip_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_ip_command_exception(self):
        """Test IP command with exception"""
        args = Mock()
        args.target = "8.8.8.8"
        
        with patch('osint_cli.main.validate_ip', return_value=True), \
             patch('osint_cli.main.IPInvestigator') as mock_investigator_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.side_effect = Exception("Test error")
            mock_investigator_class.return_value = mock_investigator
            
            result = ip_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_social_command_success(self):
        """Test social command success"""
        args = Mock()
        args.username = "testuser"
        
        with patch('osint_cli.main.SocialMediaLookup') as mock_lookup_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_lookup = Mock()
            mock_lookup.lookup_username.return_value = {'username': 'testuser'}
            mock_lookup_class.return_value = mock_lookup
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = social_command(args)
            
            assert result == 0
            mock_lookup.lookup_username.assert_called_once_with("testuser")
            mock_reporter.print_social_report.assert_called_once()
    
    def test_social_command_exception(self):
        """Test social command with exception"""
        args = Mock()
        args.username = "testuser"
        
        with patch('osint_cli.main.SocialMediaLookup') as mock_lookup_class, \
             patch('builtins.print') as mock_print:
            
            mock_lookup = Mock()
            mock_lookup.lookup_username.side_effect = Exception("Test error")
            mock_lookup_class.return_value = mock_lookup
            
            result = social_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_scan_command_email(self):
        """Test scan command with email target"""
        args = Mock()
        args.target = "test@example.com"
        args.type = "all"
        
        with patch('osint_cli.main.validate_email', return_value=True), \
             patch('osint_cli.main.EmailInvestigator') as mock_investigator_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.return_value = {'email': 'test@example.com'}
            mock_investigator_class.return_value = mock_investigator
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = scan_command(args)
            
            assert result == 0
            mock_investigator.investigate.assert_called_once_with("test@example.com")
            mock_reporter.print_comprehensive_report.assert_called_once()
    
    def test_scan_command_domain(self):
        """Test scan command with domain target"""
        args = Mock()
        args.target = "example.com"
        args.type = "all"
        
        with patch('osint_cli.main.validate_domain', return_value=True), \
             patch('osint_cli.main.DomainAnalyzer') as mock_analyzer_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_analyzer = Mock()
            mock_analyzer.analyze.return_value = {'domain': 'example.com'}
            mock_analyzer_class.return_value = mock_analyzer
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = scan_command(args)
            
            assert result == 0
            mock_analyzer.analyze.assert_called_once_with("example.com")
            mock_reporter.print_comprehensive_report.assert_called_once()
    
    def test_scan_command_ip(self):
        """Test scan command with IP target"""
        args = Mock()
        args.target = "8.8.8.8"
        args.type = "all"
        
        with patch('osint_cli.main.validate_email', return_value=False), \
             patch('osint_cli.main.validate_domain', return_value=False), \
             patch('osint_cli.main.validate_ip', return_value=True), \
             patch('osint_cli.main.IPInvestigator') as mock_investigator_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.return_value = {'ip': '8.8.8.8'}
            mock_investigator_class.return_value = mock_investigator
            
            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter
            
            result = scan_command(args)
            
            assert result == 0
            mock_investigator.investigate.assert_called_once_with("8.8.8.8")
            mock_reporter.print_comprehensive_report.assert_called_once()
    
    def test_scan_command_invalid_target(self):
        """Test scan command with invalid target"""
        args = Mock()
        args.target = "invalid-target"
        args.type = "all"
        
        with patch('osint_cli.main.validate_email', return_value=False), \
             patch('osint_cli.main.validate_domain', return_value=False), \
             patch('osint_cli.main.validate_ip', return_value=False), \
             patch('builtins.print') as mock_print:
            
            result = scan_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    def test_scan_command_exception(self):
        """Test scan command with exception"""
        args = Mock()
        args.target = "test@example.com"
        args.type = "all"
        
        with patch('osint_cli.main.validate_email', return_value=True), \
             patch('osint_cli.main.EmailInvestigator') as mock_investigator_class, \
             patch('builtins.print') as mock_print:
            
            mock_investigator = Mock()
            mock_investigator.investigate.side_effect = Exception("Test error")
            mock_investigator_class.return_value = mock_investigator
            
            result = scan_command(args)
            
            assert result == 1
            mock_print.assert_called()
    
    @patch('sys.argv', ['osint-cli', '--help'])
    def test_main_help(self):
        """Test main function with help argument"""
        with patch('osint_cli.main.print_banner') as mock_banner, \
             patch('argparse.ArgumentParser') as mock_parser_class:
            
            mock_parser = Mock()
            mock_parser.parse_args.return_value = Mock(command=None)
            mock_parser_class.return_value = mock_parser
            
            result = main()
            
            assert result == 1
            mock_banner.assert_called_once()
            mock_parser.print_help.assert_called_once()
    
    @patch('sys.argv', ['osint-cli', 'email', '--target', 'test@example.com'])
    def test_main_email_command(self):
        """Test main function with email command"""
        with patch('osint_cli.main.email_command', return_value=0) as mock_email_command:
            result = main()
            
            assert result == 0
            mock_email_command.assert_called_once()
    
    @patch('sys.argv', ['osint-cli', 'domain', '--target', 'example.com'])
    def test_main_domain_command(self):
        """Test main function with domain command"""
        with patch('osint_cli.main.domain_command', return_value=0) as mock_domain_command:
            result = main()
            
            assert result == 0
            mock_domain_command.assert_called_once()
    
    @patch('sys.argv', ['osint-cli', 'ip', '--target', '8.8.8.8'])
    def test_main_ip_command(self):
        """Test main function with IP command"""
        with patch('osint_cli.main.ip_command', return_value=0) as mock_ip_command:
            result = main()
            
            assert result == 0
            mock_ip_command.assert_called_once()
    
    @patch('sys.argv', ['osint-cli', 'social', '--username', 'testuser'])
    def test_main_social_command(self):
        """Test main function with social command"""
        with patch('osint_cli.main.social_command', return_value=0) as mock_social_command:
            result = main()
            
            assert result == 0
            mock_social_command.assert_called_once()
    
    @patch('sys.argv', ['osint-cli', 'scan', '--target', 'example.com'])
    def test_main_scan_command(self):
        """Test main function with scan command"""
        with patch('osint_cli.main.scan_command', return_value=0) as mock_scan_command:
            result = main()
            
            assert result == 0
            mock_scan_command.assert_called_once()
    
    @patch('sys.argv', ['osint-cli'])
    def test_main_no_command(self):
        """Test main function with no command"""
        with patch('osint_cli.main.print_banner') as mock_banner, \
             patch('argparse.ArgumentParser.print_help') as mock_print_help:
            result = main()
            
            assert result == 1
            mock_banner.assert_called_once()
            mock_print_help.assert_called_once()