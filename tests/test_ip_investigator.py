"""
Tests for IP investigator module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from osint_cli.core.ip_investigator import IPInvestigator


class TestIPInvestigator:
    """Test IP investigation functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.investigator = IPInvestigator()
    
    def test_init(self):
        """Test IPInvestigator initialization"""
        assert self.investigator is not None
        assert hasattr(self.investigator, 'session')
        assert 'User-Agent' in self.investigator.session.headers
    
    def test_get_ip_info_ipv4(self):
        """Test IP info for IPv4 address"""
        result = self.investigator.get_ip_info("192.168.1.1")
        
        assert result['version'] == 4
        assert result['is_private'] is True
        assert result['is_reserved'] is False
        assert result['is_loopback'] is False
        assert result['is_multicast'] is False
        assert result['is_link_local'] is False
        assert result['is_global'] is False
    
    def test_get_ip_info_ipv6(self):
        """Test IP info for IPv6 address"""
        result = self.investigator.get_ip_info("2001:db8::1")
        
        assert result['version'] == 6
        assert result['is_private'] is True  # 2001:db8::/32 is private
        assert result['is_reserved'] is False
        assert result['is_loopback'] is False
        assert result['is_multicast'] is False
        assert result['is_link_local'] is False
        assert result['is_global'] is False  # private addresses are not global
    
    def test_get_ip_info_invalid(self):
        """Test IP info for invalid IP"""
        result = self.investigator.get_ip_info("invalid-ip")
        
        assert result == {}
    
    @patch('requests.Session.get')
    def test_get_geolocation_success(self, mock_get):
        """Test geolocation retrieval success"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'status': 'success',
            'country': 'United States',
            'countryCode': 'US',
            'region': 'CA',
            'regionName': 'California',
            'city': 'San Francisco',
            'zip': '94105',
            'lat': 37.7749,
            'lon': -122.4194,
            'timezone': 'America/Los_Angeles',
            'isp': 'Test ISP',
            'org': 'Test Organization',
            'as': 'AS12345 Test AS',
            'query': '8.8.8.8'
        }
        mock_get.return_value = mock_response
        
        result = self.investigator._get_geolocation("8.8.8.8")
        
        assert result['country'] == 'United States'
        assert result['country_code'] == 'US'
        assert result['city'] == 'San Francisco'
        assert result['lat'] == 37.7749
        assert result['lon'] == -122.4194
        assert result['isp'] == 'Test ISP'
    
    @patch('requests.Session.get')
    def test_get_geolocation_failure(self, mock_get):
        """Test geolocation retrieval failure"""
        mock_get.side_effect = Exception("API request failed")
        
        result = self.investigator._get_geolocation("8.8.8.8")
        
        assert result == {}
    
    @patch('requests.Session.get')
    def test_get_geolocation_api_error(self, mock_get):
        """Test geolocation API error response"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'status': 'fail',
            'message': 'Invalid IP address'
        }
        mock_get.return_value = mock_response
        
        result = self.investigator._get_geolocation("invalid-ip")
        
        assert result == {}
    
    @patch('socket.gethostbyaddr')
    def test_get_reverse_dns_success(self, mock_gethostbyaddr):
        """Test reverse DNS lookup success"""
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        
        result = self.investigator._get_reverse_dns("8.8.8.8")
        
        assert result == ["dns.google"]
        mock_gethostbyaddr.assert_called_once_with("8.8.8.8")
    
    @patch('socket.gethostbyaddr')
    def test_get_reverse_dns_failure(self, mock_gethostbyaddr):
        """Test reverse DNS lookup failure"""
        mock_gethostbyaddr.side_effect = Exception("Reverse DNS lookup failed")
        
        result = self.investigator._get_reverse_dns("8.8.8.8")
        
        assert result == []
    
    @patch('socket.socket')
    def test_scan_ports_success(self, mock_socket):
        """Test port scanning success"""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Port is open
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)
        mock_socket.return_value = mock_sock
        
        result = self.investigator._scan_ports("8.8.8.8")
        
        assert len(result) > 0
        assert all(port['status'] == 'open' for port in result)
    
    @patch('socket.socket')
    def test_scan_ports_failure(self, mock_socket):
        """Test port scanning failure"""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 1  # Port is closed
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)
        mock_socket.return_value = mock_sock
        
        result = self.investigator._scan_ports("8.8.8.8")
        
        assert result == []
    
    @patch('socket.socket')
    def test_scan_ports_exception(self, mock_socket):
        """Test port scanning with exception"""
        mock_socket.side_effect = Exception("Socket creation failed")
        
        result = self.investigator._scan_ports("8.8.8.8")
        
        assert result == []
    
    def test_get_service_name(self):
        """Test service name mapping"""
        test_cases = [
            (80, 'HTTP'),
            (443, 'HTTPS'),
            (22, 'SSH'),
            (25, 'SMTP'),
            (53, 'DNS'),
            (9999, 'Unknown')
        ]
        
        for port, expected_service in test_cases:
            result = self.investigator._get_service_name(port)
            assert result == expected_service
    
    def test_get_whois_data(self):
        """Test WHOIS data retrieval"""
        result = self.investigator._get_whois_data("8.8.8.8")
        
        assert isinstance(result, dict)
        assert 'netname' in result
        assert 'descr' in result
        assert 'country' in result
    
    def test_check_tor_exit_node(self):
        """Test Tor exit node checking"""
        result = self.investigator._check_tor_exit_node("8.8.8.8")
        
        assert isinstance(result, bool)
    
    def test_check_proxy(self):
        """Test proxy checking"""
        result = self.investigator._check_proxy("8.8.8.8")
        
        assert isinstance(result, bool)
    
    def test_check_vpn(self):
        """Test VPN checking"""
        result = self.investigator._check_vpn("8.8.8.8")
        
        assert isinstance(result, bool)
    
    def test_check_reputation(self):
        """Test reputation checking"""
        result = self.investigator._check_reputation("8.8.8.8")
        
        assert isinstance(result, dict)
        assert 'is_malicious' in result
        assert 'is_tor_exit' in result
        assert 'is_proxy' in result
        assert 'is_vpn' in result
        assert 'threat_score' in result
        assert 'sources' in result
        assert isinstance(result['threat_score'], int)
        assert isinstance(result['sources'], list)
    
    @patch('time.time')
    @patch.object(IPInvestigator, '_get_geolocation')
    @patch.object(IPInvestigator, '_get_reverse_dns')
    @patch.object(IPInvestigator, '_scan_ports')
    @patch.object(IPInvestigator, '_get_whois_data')
    @patch.object(IPInvestigator, '_check_reputation')
    def test_investigate_complete(self, mock_reputation, mock_whois, mock_ports, 
                                 mock_reverse_dns, mock_geo, mock_time):
        """Test complete IP investigation process"""
        # Mock time
        mock_time.side_effect = [0, 1.5]  # Start and end time
        
        # Mock all methods
        mock_geo.return_value = {'country': 'United States', 'city': 'San Francisco'}
        mock_reverse_dns.return_value = ['dns.google']
        mock_ports.return_value = [{'port': 80, 'service': 'HTTP', 'status': 'open'}]
        mock_whois.return_value = {'netname': 'Google', 'country': 'US'}
        mock_reputation.return_value = {'is_malicious': False, 'threat_score': 10}
        
        result = self.investigator.investigate("8.8.8.8")
        
        assert result['ip'] == "8.8.8.8"
        assert result['type'] == 'IPv4'
        assert result['is_private'] is False
        assert result['is_reserved'] is False
        assert result['geolocation']['country'] == 'United States'
        assert 'dns.google' in result['reverse_dns']
        assert len(result['ports']) == 1
        assert result['whois_data']['netname'] == 'Google'
        assert result['reputation']['is_malicious'] is False
        assert result['investigation_time'] == 1.5
    
    def test_investigate_invalid_ip(self):
        """Test investigation with invalid IP"""
        result = self.investigator.investigate("invalid-ip")
        
        assert 'error' in result
        assert result['ip'] == "invalid-ip"
    
    def test_investigate_exception_handling(self):
        """Test investigation exception handling"""
        with patch('ipaddress.ip_address', side_effect=Exception("Test error")):
            result = self.investigator.investigate("8.8.8.8")
            
            assert 'error' in result
            assert result['error'] == "Test error"