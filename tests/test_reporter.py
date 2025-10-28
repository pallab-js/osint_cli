"""
Tests for reporter module
"""

import pytest
from unittest.mock import Mock, patch
from osint_cli.core.reporter import Reporter


class TestReporter:
    """Test report generation functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.reporter = Reporter()
    
    def test_init(self):
        """Test Reporter initialization"""
        assert self.reporter is not None
        assert hasattr(self.reporter, 'colors')
    
    def test_format_boolean_true(self):
        """Test boolean formatting for True values"""
        result = self.reporter._format_boolean(True)
        
        assert "Yes" in result
        assert "No" not in result
    
    def test_format_boolean_false(self):
        """Test boolean formatting for False values"""
        result = self.reporter._format_boolean(False)
        
        assert "No" in result
        assert "Yes" not in result
    
    @patch('builtins.print')
    def test_print_email_report_basic(self, mock_print):
        """Test basic email report printing"""
        results = {
            'email': 'test@example.com',
            'valid': True,
            'domain': 'example.com',
            'disposable': False,
            'deliverable': True,
            'mx_records': ['mail.example.com'],
            'breach_data': [],
            'social_media': {'twitter': True, 'instagram': False},
            'investigation_time': 1.5
        }
        
        self.reporter.print_email_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that key information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'test@example.com' in printed_content
        assert 'example.com' in printed_content
    
    @patch('builtins.print')
    def test_print_email_report_with_breaches(self, mock_print):
        """Test email report printing with breach data"""
        results = {
            'email': 'test@example.com',
            'valid': True,
            'domain': 'example.com',
            'disposable': False,
            'deliverable': True,
            'mx_records': [],
            'breach_data': [
                {'name': 'Test Breach', 'date': '2023-01-01', 'description': 'Test breach'}
            ],
            'social_media': {},
            'investigation_time': 1.0
        }
        
        self.reporter.print_email_report(results)
        
        # Check that breach information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'Test Breach' in printed_content
        assert '2023-01-01' in printed_content
    
    @patch('builtins.print')
    def test_print_email_report_with_error(self, mock_print):
        """Test email report printing with error"""
        results = {
            'email': 'test@example.com',
            'valid': False,
            'domain': 'example.com',
            'disposable': False,
            'deliverable': False,
            'mx_records': [],
            'breach_data': [],
            'social_media': {},
            'investigation_time': 0.5,
            'error': 'Test error message'
        }
        
        self.reporter.print_email_report(results)
        
        # Check that error information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'Test error message' in printed_content
    
    @patch('builtins.print')
    def test_print_domain_report_basic(self, mock_print):
        """Test basic domain report printing"""
        results = {
            'domain': 'example.com',
            'ip_addresses': ['192.168.1.1'],
            'mx_records': [{'exchange': 'mail.example.com', 'priority': 10}],
            'ns_records': ['ns1.example.com'],
            'txt_records': ['v=spf1 include:_spf.google.com ~all'],
            'whois_data': {'registrar': 'Test Registrar'},
            'subdomains': ['www.example.com'],
            'ssl_info': {'subject': {'commonName': 'example.com'}},
            'technologies': ['WordPress'],
            'analysis_time': 2.0
        }
        
        self.reporter.print_domain_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that key information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'example.com' in printed_content
        assert '192.168.1.1' in printed_content
    
    @patch('builtins.print')
    def test_print_domain_report_with_whois_error(self, mock_print):
        """Test domain report printing with WHOIS error"""
        results = {
            'domain': 'example.com',
            'ip_addresses': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'whois_data': {'error': 'WHOIS lookup failed'},
            'subdomains': [],
            'ssl_info': {},
            'technologies': [],
            'analysis_time': 1.0
        }
        
        self.reporter.print_domain_report(results)
        
        # Check that error information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'WHOIS lookup failed' in printed_content
    
    @patch('builtins.print')
    def test_print_ip_report_basic(self, mock_print):
        """Test basic IP report printing"""
        results = {
            'ip': '8.8.8.8',
            'type': 'IPv4',
            'is_private': False,
            'is_reserved': False,
            'geolocation': {
                'country': 'United States',
                'city': 'San Francisco',
                'isp': 'Google LLC'
            },
            'reverse_dns': ['dns.google'],
            'ports': [{'port': 80, 'service': 'HTTP', 'status': 'open'}],
            'reputation': {
                'threat_score': 10,
                'is_malicious': False,
                'is_tor_exit': False,
                'is_proxy': False,
                'is_vpn': False,
                'sources': []
            },
            'investigation_time': 1.5
        }
        
        self.reporter.print_ip_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that key information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert '8.8.8.8' in printed_content
        assert 'United States' in printed_content
    
    @patch('builtins.print')
    def test_print_ip_report_with_reputation(self, mock_print):
        """Test IP report printing with reputation data"""
        results = {
            'ip': '1.2.3.4',
            'type': 'IPv4',
            'is_private': False,
            'is_reserved': False,
            'geolocation': {},
            'reverse_dns': [],
            'ports': [],
            'reputation': {
                'threat_score': 75,
                'is_malicious': True,
                'is_tor_exit': True,
                'is_proxy': False,
                'is_vpn': True,
                'sources': ['Tor Exit Node', 'VPN']
            },
            'investigation_time': 1.0
        }
        
        self.reporter.print_ip_report(results)
        
        # Check that reputation information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert '75' in printed_content
        assert 'Tor Exit Node' in printed_content
        assert 'VPN' in printed_content
    
    @patch('builtins.print')
    def test_print_social_report_basic(self, mock_print):
        """Test basic social media report printing"""
        results = {
            'username': 'testuser',
            'total_found': 3,
            'platforms': {
                'twitter': {'exists': True, 'response_time': 0.5},
                'instagram': {'exists': False, 'response_time': 0.3},
                'github': {'exists': True, 'response_time': 0.7}
            },
            'lookup_time': 2.0
        }
        
        self.reporter.print_social_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that key information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'testuser' in printed_content
        assert '3' in printed_content
    
    @patch('builtins.print')
    def test_print_social_report_with_error(self, mock_print):
        """Test social media report printing with error"""
        results = {
            'username': 'testuser',
            'total_found': 0,
            'platforms': {},
            'lookup_time': 0.5,
            'error': 'Lookup failed'
        }
        
        self.reporter.print_social_report(results)
        
        # Check that error information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'Lookup failed' in printed_content
    
    @patch('builtins.print')
    def test_print_comprehensive_report_email(self, mock_print):
        """Test comprehensive report printing with email data"""
        results = {
            'email': {
                'email': 'test@example.com',
                'valid': True,
                'domain': 'example.com',
                'disposable': False,
                'deliverable': True,
                'mx_records': [],
                'breach_data': [],
                'social_media': {},
                'investigation_time': 1.0
            }
        }
        
        self.reporter.print_comprehensive_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that email information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'test@example.com' in printed_content
    
    @patch('builtins.print')
    def test_print_comprehensive_report_domain(self, mock_print):
        """Test comprehensive report printing with domain data"""
        results = {
            'domain': {
                'domain': 'example.com',
                'ip_addresses': ['192.168.1.1'],
                'mx_records': [],
                'ns_records': [],
                'txt_records': [],
                'whois_data': {},
                'subdomains': [],
                'ssl_info': {},
                'technologies': [],
                'analysis_time': 1.0
            }
        }
        
        self.reporter.print_comprehensive_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that domain information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'example.com' in printed_content
    
    @patch('builtins.print')
    def test_print_comprehensive_report_ip(self, mock_print):
        """Test comprehensive report printing with IP data"""
        results = {
            'ip': {
                'ip': '8.8.8.8',
                'type': 'IPv4',
                'is_private': False,
                'is_reserved': False,
                'geolocation': {},
                'reverse_dns': [],
                'ports': [],
                'reputation': {},
                'investigation_time': 1.0
            }
        }
        
        self.reporter.print_comprehensive_report(results)
        
        # Check that print was called multiple times
        assert mock_print.call_count > 0
        
        # Check that IP information is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert '8.8.8.8' in printed_content
    
    @patch('builtins.open', create=True)
    @patch('builtins.print')
    def test_save_report_success(self, mock_print, mock_open):
        """Test successful report saving"""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        results = {'test': 'data'}
        filename = 'test_report.txt'
        
        self.reporter.save_report(results, filename)
        
        mock_open.assert_called_once_with(filename, 'w')
        mock_file.write.assert_called_once_with(str(results))
        mock_print.assert_called_once()
    
    @patch('builtins.open', create=True)
    @patch('builtins.print')
    def test_save_report_failure(self, mock_print, mock_open):
        """Test report saving failure"""
        mock_open.side_effect = Exception("File write error")
        
        results = {'test': 'data'}
        filename = 'test_report.txt'
        
        self.reporter.save_report(results, filename)
        
        mock_print.assert_called_once()
        # Check that error message is printed
        printed_content = ' '.join([str(call) for call in mock_print.call_args_list])
        assert 'File write error' in printed_content