"""
Tests for email investigator module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from osint_cli.core.email_investigator import EmailInvestigator


class TestEmailInvestigator:
    """Test email investigation functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.investigator = EmailInvestigator()
    
    def test_init(self):
        """Test EmailInvestigator initialization"""
        assert self.investigator is not None
        assert hasattr(self.investigator, 'session')
        assert 'User-Agent' in self.investigator.session.headers
    
    def test_validate_email_format_valid(self):
        """Test email format validation with valid emails"""
        valid_emails = [
            "user@example.com",
            "test.email@domain.org",
            "user+tag@example.co.uk"
        ]
        
        for email in valid_emails:
            assert self.investigator._validate_email_format(email)
    
    def test_validate_email_format_invalid(self):
        """Test email format validation with invalid emails"""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "user@",
            "user@example",
            ""
        ]
        
        for email in invalid_emails:
            assert not self.investigator._validate_email_format(email)
    
    def test_check_disposable_email(self):
        """Test disposable email detection"""
        disposable_domains = [
            "10minutemail.com",
            "tempmail.org",
            "guerrillamail.com"
        ]
        
        for domain in disposable_domains:
            assert self.investigator._check_disposable_email(domain)
        
        # Test non-disposable domain
        assert not self.investigator._check_disposable_email("gmail.com")
    
    @patch('dns.resolver.resolve')
    def test_get_mx_records_success(self, mock_resolve):
        """Test MX record retrieval success"""
        # Mock DNS response
        mock_record1 = Mock()
        mock_record1.exchange = "mail1.example.com"
        mock_record2 = Mock()
        mock_record2.exchange = "mail2.example.com"
        mock_resolve.return_value = [mock_record1, mock_record2]
        
        result = self.investigator._get_mx_records("example.com")
        
        assert len(result) == 2
        assert "mail1.example.com" in result
        assert "mail2.example.com" in result
        mock_resolve.assert_called_once_with("example.com", "MX")
    
    @patch('dns.resolver.resolve')
    def test_get_mx_records_failure(self, mock_resolve):
        """Test MX record retrieval failure"""
        mock_resolve.side_effect = Exception("DNS resolution failed")
        
        result = self.investigator._get_mx_records("example.com")
        
        assert result == []
    
    @patch('dns.resolver.resolve')
    def test_check_deliverability_success(self, mock_resolve):
        """Test deliverability check success"""
        mock_record = Mock()
        mock_record.exchange = "mail.example.com"
        mock_resolve.return_value = [mock_record]
        
        result = self.investigator._check_deliverability("user@example.com")
        
        assert result is True
    
    @patch('dns.resolver.resolve')
    def test_check_deliverability_failure(self, mock_resolve):
        """Test deliverability check failure"""
        mock_resolve.side_effect = Exception("DNS resolution failed")
        
        result = self.investigator._check_deliverability("user@example.com")
        
        assert result is False
    
    def test_check_breaches(self):
        """Test breach checking functionality"""
        # Test with email that should trigger mock breach
        result = self.investigator._check_breaches("test@example.com")
        
        # Should return list (may be empty)
        assert isinstance(result, list)
    
    @patch('requests.Session.head')
    def test_lookup_social_media_success(self, mock_head):
        """Test social media lookup success"""
        # Mock successful responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response
        
        result = self.investigator._lookup_social_media("testuser")
        
        assert isinstance(result, dict)
        assert 'twitter' in result
        assert 'instagram' in result
        assert 'github' in result
    
    @patch('requests.Session.head')
    def test_lookup_social_media_failure(self, mock_head):
        """Test social media lookup failure"""
        mock_head.side_effect = Exception("Network error")
        
        result = self.investigator._lookup_social_media("testuser")
        
        assert isinstance(result, dict)
        # All platforms should be False due to error
        for platform, exists in result.items():
            assert exists is False
    
    def test_get_email_metadata(self):
        """Test email metadata extraction"""
        email = "test.user+tag@example.com"
        metadata = self.investigator.get_email_metadata(email)
        
        assert metadata['local_part'] == "test.user+tag"
        assert metadata['domain'] == "example.com"
        assert metadata['length'] == len(email)
        assert metadata['has_numbers'] is False
        assert metadata['has_special_chars'] is True
        assert metadata['common_provider'] is False
    
    def test_get_email_metadata_common_provider(self):
        """Test email metadata with common provider"""
        email = "user@gmail.com"
        metadata = self.investigator.get_email_metadata(email)
        
        assert metadata['common_provider'] is True
    
    @patch('time.time')
    @patch.object(EmailInvestigator, '_validate_email_format')
    @patch.object(EmailInvestigator, '_check_disposable_email')
    @patch.object(EmailInvestigator, '_get_mx_records')
    @patch.object(EmailInvestigator, '_check_deliverability')
    @patch.object(EmailInvestigator, '_check_breaches')
    @patch.object(EmailInvestigator, '_lookup_social_media')
    def test_investigate_complete(self, mock_social, mock_breaches, mock_deliverability, 
                                 mock_mx, mock_disposable, mock_validate, mock_time):
        """Test complete investigation process"""
        # Mock time
        mock_time.side_effect = [0, 1.5]  # Start and end time
        
        # Mock all methods
        mock_validate.return_value = True
        mock_disposable.return_value = False
        mock_mx.return_value = ["mail.example.com"]
        mock_deliverability.return_value = True
        mock_breaches.return_value = []
        mock_social.return_value = {"twitter": True, "instagram": False}
        
        result = self.investigator.investigate("test@example.com")
        
        assert result['email'] == "test@example.com"
        assert result['valid'] is True
        assert result['domain'] == "example.com"
        assert result['disposable'] is False
        assert result['deliverable'] is True
        assert result['investigation_time'] == 1.5
        assert 'social_media' in result
    
    def test_investigate_invalid_email(self):
        """Test investigation with invalid email"""
        result = self.investigator.investigate("invalid-email")
        
        assert result['email'] == "invalid-email"
        assert result['valid'] is False
        assert 'error' not in result  # Should not have error for invalid format
    
    def test_investigate_exception_handling(self):
        """Test investigation exception handling"""
        with patch.object(EmailInvestigator, '_validate_email_format', side_effect=Exception("Test error")):
            result = self.investigator.investigate("test@example.com")
            
            assert 'error' in result
            assert result['error'] == "Test error"