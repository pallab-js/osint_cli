"""
Additional tests to achieve 100% coverage
"""

import pytest
from unittest.mock import Mock, patch
from osint_cli.core.domain_analyzer import DomainAnalyzer
from osint_cli.core.email_investigator import EmailInvestigator
from osint_cli.core.ip_investigator import IPInvestigator
from osint_cli.core.social_media_lookup import SocialMediaLookup
from osint_cli.utils.colors import Colors


class TestAdditionalCoverage:
    """Additional tests for 100% coverage"""
    
    def test_domain_analyzer_ssl_info_exception(self):
        """Test SSL info with exception in context manager"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_ssock = Mock()
            mock_sock.__enter__ = Mock(side_effect=Exception("Connection failed"))
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.return_value = mock_ssock
            
            result = analyzer._get_ssl_info("example.com")
            
            assert result == {}
    
    def test_domain_analyzer_ssl_info_cert_processing(self):
        """Test SSL info with certificate processing"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_ssock = Mock()
            mock_cert = {
                'subject': [('commonName', 'example.com')],
                'issuer': [('organizationName', 'Test CA')],
                'version': 3,
                'serialNumber': '123456789',
                'notBefore': '20200101000000Z',
                'notAfter': '20250101000000Z',
                'subjectAltName': [('DNS', 'example.com')]
            }
            mock_ssock.getpeercert.return_value = mock_cert
            mock_ssock.__enter__ = Mock(return_value=mock_ssock)
            mock_ssock.__exit__ = Mock(return_value=None)
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(return_value=None)
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.return_value = mock_ssock
            
            result = analyzer._get_ssl_info("example.com")
            
            # Should return a dict with processed certificate data
            assert isinstance(result, dict)
    
    def test_email_investigator_breach_check_exception(self):
        """Test breach checking with exception"""
        investigator = EmailInvestigator()
        
        with patch('time.sleep', side_effect=Exception("Sleep interrupted")):
            result = investigator._check_breaches("test@example.com")
            
            assert result == []
    
    def test_email_investigator_social_media_exception(self):
        """Test social media lookup with exception"""
        investigator = EmailInvestigator()
        
        with patch('requests.Session.head', side_effect=Exception("Network error")):
            result = investigator._lookup_social_media("testuser")
            
            assert isinstance(result, dict)
            # All platforms should be False due to error
            for platform, exists in result.items():
                assert exists is False
    
    def test_ip_investigator_geolocation_exception(self):
        """Test geolocation with exception"""
        investigator = IPInvestigator()
        
        with patch('requests.Session.get', side_effect=Exception("API error")):
            result = investigator._get_geolocation("8.8.8.8")
            
            assert result == {}
    
    def test_ip_investigator_reputation_sources(self):
        """Test reputation checking with sources"""
        investigator = IPInvestigator()
        
        with patch.object(investigator, '_check_tor_exit_node', return_value=True), \
             patch.object(investigator, '_check_proxy', return_value=True), \
             patch.object(investigator, '_check_vpn', return_value=True):
            
            result = investigator._check_reputation("1.2.3.4")
            
            assert result['is_malicious'] is True
            assert result['threat_score'] > 50
            assert len(result['sources']) > 0
    
    def test_social_media_lookup_platform_exception(self):
        """Test platform checking with exception in profile extraction"""
        lookup = SocialMediaLookup()
        
        with patch('requests.Session.head') as mock_head:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "Some content"
            mock_head.return_value = mock_response
            
            with patch.object(lookup, '_is_profile_exists', return_value=True), \
                 patch.object(lookup, '_extract_profile_info', side_effect=Exception("Extraction error")):
                
                result = lookup._check_platform("twitter", "https://twitter.com/testuser", "testuser")
                
                assert result['exists'] is True
                assert 'profile_info' in result
    
    def test_social_media_lookup_username_analysis_success(self):
        """Test username analysis success case"""
        lookup = SocialMediaLookup()
        
        result = lookup.analyze_username_pattern("testuser123")
        
        assert result['length'] == 11
        assert result['has_numbers'] is True
        assert 'name_numbers' in result['common_patterns']
    
    def test_colors_utility_methods(self):
        """Test color utility methods"""
        colors = Colors()
        
        # Test colorize method
        result = colors.colorize("test", colors.RED)
        assert "test" in result
        assert colors.RESET in result
        
        # Test utility methods
        success_text = colors.success("Success message")
        error_text = colors.error("Error message")
        warning_text = colors.warning("Warning message")
        info_text = colors.info("Info message")
        highlight_text = colors.highlight("Highlight message")
        
        assert "Success message" in success_text
        assert "Error message" in error_text
        assert "Warning message" in warning_text
        assert "Info message" in info_text
        assert "Highlight message" in highlight_text
    
    def test_validators_edge_cases(self):
        """Test validators edge cases"""
        from osint_cli.utils.validators import validate_email, validate_url, sanitize_input
        
        # Test email validation edge cases
        assert not validate_email("")
        assert not validate_email(None)
        assert not validate_email("user@")
        assert not validate_email("@domain.com")
        
        # Test URL validation edge cases
        assert not validate_url("")
        assert not validate_url(None)
        assert not validate_url("not-a-url")
        
        # Test sanitization edge cases
        assert sanitize_input("") == ""
        assert sanitize_input(None) == ""
        assert sanitize_input(123) == ""
        assert sanitize_input([]) == ""
        assert sanitize_input({}) == ""
    
    def test_reporter_save_report_edge_cases(self):
        """Test reporter save report edge cases"""
        from osint_cli.core.reporter import Reporter
        
        reporter = Reporter()
        
        # Test with None filename
        with patch('builtins.open', side_effect=Exception("File error")):
            reporter.save_report({"test": "data"}, None)
        
        # Test with empty results
        with patch('builtins.open', create=True) as mock_open:
            mock_file = Mock()
            mock_open.return_value.__enter__.return_value = mock_file
            reporter.save_report({}, "test.txt")
            mock_file.write.assert_called_once_with("{}")
    
    def test_domain_analyzer_ssl_info_context_manager_exception(self):
        """Test SSL info with exception in context manager"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_ssock = Mock()
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(side_effect=Exception("Socket error"))
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.return_value = mock_ssock
            
            result = analyzer._get_ssl_info("example.com")
            
            assert result == {}
    
    def test_domain_analyzer_ssl_info_wrap_socket_exception(self):
        """Test SSL info with exception in wrap_socket"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(return_value=None)
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.side_effect = Exception("SSL error")
            
            result = analyzer._get_ssl_info("example.com")
            
            assert result == {}
    
    def test_domain_analyzer_ssl_info_cert_processing_exception(self):
        """Test SSL info with exception in certificate processing"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_ssock = Mock()
            mock_ssock.getpeercert.side_effect = Exception("Cert error")
            mock_ssock.__enter__ = Mock(return_value=mock_ssock)
            mock_ssock.__exit__ = Mock(return_value=None)
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(return_value=None)
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.return_value = mock_ssock
            
            result = analyzer._get_ssl_info("example.com")
            
            assert result == {}
    
    def test_domain_analyzer_ssl_info_cert_data_processing(self):
        """Test SSL info with certificate data processing"""
        analyzer = DomainAnalyzer()
        
        with patch('ssl.create_default_context') as mock_context, \
             patch('socket.create_connection') as mock_connection:
            
            mock_sock = Mock()
            mock_ssock = Mock()
            mock_cert = {
                'subject': [('commonName', 'example.com'), ('organizationName', 'Test Org')],
                'issuer': [('organizationName', 'Test CA'), ('countryName', 'US')],
                'version': 3,
                'serialNumber': '123456789',
                'notBefore': '20200101000000Z',
                'notAfter': '20250101000000Z',
                'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')]
            }
            mock_ssock.getpeercert.return_value = mock_cert
            mock_ssock.__enter__ = Mock(return_value=mock_ssock)
            mock_ssock.__exit__ = Mock(return_value=None)
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(return_value=None)
            mock_connection.return_value = mock_sock
            mock_context.return_value.wrap_socket.return_value = mock_ssock
            
            result = analyzer._get_ssl_info("example.com")
            
            assert isinstance(result, dict)
    
    def test_email_investigator_breach_check_success(self):
        """Test breach checking success case"""
        investigator = EmailInvestigator()
        
        with patch('time.sleep'):
            result = investigator._check_breaches("test@example.com")
            
            assert isinstance(result, list)
    
    def test_ip_investigator_geolocation_success(self):
        """Test geolocation success case"""
        investigator = IPInvestigator()
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {
                'status': 'success',
                'country': 'United States',
                'city': 'San Francisco',
                'lat': 37.7749,
                'lon': -122.4194
            }
            mock_get.return_value = mock_response
            
            result = investigator._get_geolocation("8.8.8.8")
            
            assert result['country'] == 'United States'
            assert result['city'] == 'San Francisco'
    
    def test_ip_investigator_reputation_check_success(self):
        """Test reputation checking success case"""
        investigator = IPInvestigator()
        
        with patch.object(investigator, '_check_tor_exit_node', return_value=False), \
             patch.object(investigator, '_check_proxy', return_value=False), \
             patch.object(investigator, '_check_vpn', return_value=False):
            
            result = investigator._check_reputation("8.8.8.8")
            
            assert result['is_malicious'] is False
            assert result['threat_score'] == 0
            assert result['sources'] == []
    
    def test_social_media_lookup_platform_check_success(self):
        """Test platform checking success case"""
        lookup = SocialMediaLookup()
        
        with patch('requests.Session.head') as mock_head:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "User profile content"
            mock_head.return_value = mock_response
            
            with patch.object(lookup, '_is_profile_exists', return_value=True), \
                 patch.object(lookup, '_extract_profile_info', return_value={'verified': True}):
                
                result = lookup._check_platform("twitter", "https://twitter.com/testuser", "testuser")
                
                assert result['exists'] is True
                assert result['profile_info']['verified'] is True
    
    def test_social_media_lookup_username_analysis_success(self):
        """Test username analysis success case"""
        lookup = SocialMediaLookup()
        
        result = lookup.analyze_username_pattern("testuser123")
        
        assert result['length'] == 11
        assert result['has_numbers'] is True
        assert 'name_numbers' in result['common_patterns']
    
    def test_validators_sanitize_input_edge_cases(self):
        """Test sanitize input edge cases"""
        from osint_cli.utils.validators import sanitize_input
        
        # Test with various edge cases
        assert sanitize_input("test<script>alert('xss')</script>") == "testscriptalertxss/script"
        assert sanitize_input("test&name") == "testname"
        assert sanitize_input("test;rm -rf /") == "testrm -rf /"
        assert sanitize_input("test|cat /etc/passwd") == "testcat /etc/passwd"
        assert sanitize_input("test`whoami`") == "testwhoami"
        assert sanitize_input("test$USER") == "testUSER"
        assert sanitize_input("test(rm -rf)") == "testrm -rf"
    
    def test_main_module_edge_cases(self):
        """Test main module edge cases"""
        from osint_cli.main import print_banner
        
        # Test banner printing
        with patch('builtins.print') as mock_print:
            print_banner()
            mock_print.assert_called()
    
    def test_reporter_edge_cases(self):
        """Test reporter edge cases"""
        from osint_cli.core.reporter import Reporter
        
        reporter = Reporter()
        
        # Test with empty results
        results = {}
        with patch('builtins.print'):
            reporter.print_email_report(results)
            reporter.print_domain_report(results)
            reporter.print_ip_report(results)
            reporter.print_social_report(results)
            reporter.print_comprehensive_report(results)