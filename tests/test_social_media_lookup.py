"""
Tests for social media lookup module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from osint_cli.core.social_media_lookup import SocialMediaLookup


class TestSocialMediaLookup:
    """Test social media lookup functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.lookup = SocialMediaLookup()
    
    def test_init(self):
        """Test SocialMediaLookup initialization"""
        assert self.lookup is not None
        assert hasattr(self.lookup, 'session')
        assert 'User-Agent' in self.lookup.session.headers
    
    def test_clean_username(self):
        """Test username cleaning functionality"""
        test_cases = [
            ("@username", "username"),
            ("user name", "username"),  # spaces are removed
            ("user-name", "user-name"),
            ("user.name", "user.name"),
            ("user@name", "username"),  # @ is removed
            ("user..name", "user..name"),  # dots are preserved
            ("", "invalid"),
            ("   ", "invalid"),
            ("user@#$%", "user"),  # special chars are removed
            ("123", "123")
        ]
        
        for input_username, expected in test_cases:
            result = self.lookup._clean_username(input_username)
            assert result == expected, f"Username '{input_username}' should clean to '{expected}'"
    
    def test_clean_username_edge_cases(self):
        """Test username cleaning edge cases"""
        # Empty string
        assert self.lookup._clean_username("") == "invalid"
        
        # Only special characters
        assert self.lookup._clean_username("@#$%") == "invalid"
        
        # Multiple @ symbols
        assert self.lookup._clean_username("@@username") == "username"
    
    @patch('requests.Session.head')
    def test_check_platform_success(self, mock_head):
        """Test platform checking success"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "User profile content"
        mock_head.return_value = mock_response
        
        with patch.object(self.lookup, '_is_profile_exists', return_value=True), \
             patch.object(self.lookup, '_extract_profile_info', return_value={}):
            result = self.lookup._check_platform("twitter", "https://twitter.com/testuser", "testuser")
            
            assert result['exists'] is True
            assert result['url'] == "https://twitter.com/testuser"
            assert result['status_code'] == 200
            assert result['response_time'] >= 0
            assert 'profile_info' in result
    
    @patch('requests.Session.head')
    def test_check_platform_failure(self, mock_head):
        """Test platform checking failure"""
        mock_head.side_effect = Exception("Network error")
        
        result = self.lookup._check_platform("twitter", "https://twitter.com/testuser", "testuser")
        
        assert result['exists'] is False
        assert result['url'] == "https://twitter.com/testuser"
        assert 'error' in result
        assert result['error'] == "Network error"
    
    @patch('requests.Session.head')
    def test_is_profile_exists_twitter(self, mock_head):
        """Test profile existence check for Twitter"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response
        
        result = self.lookup._is_profile_exists("twitter", mock_response)
        
        assert result is True
    
    @patch('requests.Session.head')
    def test_is_profile_exists_facebook(self, mock_head):
        """Test profile existence check for Facebook"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "User profile content"
        mock_head.return_value = mock_response
        
        result = self.lookup._is_profile_exists("facebook", mock_response)
        
        assert result is True
    
    @patch('requests.Session.head')
    def test_is_profile_exists_facebook_not_found(self, mock_head):
        """Test profile existence check for Facebook with not found"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "User not found"
        mock_head.return_value = mock_response
        
        result = self.lookup._is_profile_exists("facebook", mock_response)
        
        assert result is False
    
    def test_extract_profile_info_twitter(self):
        """Test profile info extraction for Twitter"""
        mock_response = Mock()
        mock_response.text = "Verified account content"
        
        result = self.lookup._extract_profile_info("twitter", mock_response)
        
        assert result['verified'] is True
    
    def test_extract_profile_info_instagram(self):
        """Test profile info extraction for Instagram"""
        mock_response = Mock()
        mock_response.text = "Private account content"
        
        result = self.lookup._extract_profile_info("instagram", mock_response)
        
        assert result['private'] is True
    
    def test_extract_profile_info_github(self):
        """Test profile info extraction for GitHub"""
        mock_response = Mock()
        mock_response.text = "User has followers and repositories"
        
        result = self.lookup._extract_profile_info("github", mock_response)
        
        assert result['has_followers'] is True
        assert result['has_repositories'] is True
    
    def test_extract_profile_info_reddit(self):
        """Test profile info extraction for Reddit"""
        mock_response = Mock()
        mock_response.text = "User has karma and cake day"
        
        result = self.lookup._extract_profile_info("reddit", mock_response)
        
        assert result['has_karma'] is True
        assert result['has_cake_day'] is True
    
    def test_extract_profile_info_exception(self):
        """Test profile info extraction with exception"""
        mock_response = Mock()
        mock_response.text = "Some content"
        # Mock the text property to raise an exception when accessed
        type(mock_response).text = property(lambda self: exec('raise Exception("Text processing error")'))
        
        result = self.lookup._extract_profile_info("twitter", mock_response)
        
        # Should return empty dict on exception
        assert result == {}
    
    def test_get_username_suggestions(self):
        """Test username suggestions generation"""
        username = "testuser"
        suggestions = self.lookup.get_username_suggestions(username)
        
        assert isinstance(suggestions, list)
        assert len(suggestions) <= 10
        assert username in suggestions
        assert f"{username}_" in suggestions
        assert f"_{username}" in suggestions
        assert f"{username}1" in suggestions
    
    def test_get_username_suggestions_empty(self):
        """Test username suggestions with empty username"""
        suggestions = self.lookup.get_username_suggestions("")
        
        assert isinstance(suggestions, list)
        assert len(suggestions) <= 10
    
    def test_analyze_username_pattern(self):
        """Test username pattern analysis"""
        username = "TestUser123"
        analysis = self.lookup.analyze_username_pattern(username)
        
        assert analysis['length'] == 11
        assert analysis['has_numbers'] is True
        assert analysis['has_underscores'] is False
        assert analysis['has_dots'] is False
        assert analysis['has_hyphens'] is False
        assert analysis['is_all_lowercase'] is False
        assert analysis['is_all_uppercase'] is False
        assert analysis['has_mixed_case'] is True
        assert analysis['starts_with_number'] is False
        assert analysis['ends_with_number'] is True
        assert 'common_patterns' in analysis
    
    def test_analyze_username_pattern_name_numbers(self):
        """Test username pattern analysis for name+numbers pattern"""
        username = "john123"
        analysis = self.lookup.analyze_username_pattern(username)
        
        assert 'name_numbers' in analysis['common_patterns']
    
    def test_analyze_username_pattern_numbers_name(self):
        """Test username pattern analysis for numbers+name pattern"""
        username = "123john"
        analysis = self.lookup.analyze_username_pattern(username)
        
        assert 'numbers_name' in analysis['common_patterns']
    
    def test_analyze_username_pattern_name_underscore_name(self):
        """Test username pattern analysis for name_underscore_name pattern"""
        username = "john_doe"
        analysis = self.lookup.analyze_username_pattern(username)
        
        assert 'name_underscore_name' in analysis['common_patterns']
    
    def test_analyze_username_pattern_name_dot_name(self):
        """Test username pattern analysis for name.dot.name pattern"""
        username = "john.doe"
        analysis = self.lookup.analyze_username_pattern(username)
        
        assert 'name_dot_name' in analysis['common_patterns']
    
    def test_analyze_username_pattern_empty(self):
        """Test username pattern analysis with empty username"""
        analysis = self.lookup.analyze_username_pattern("")
        
        assert analysis['length'] == 0
        assert analysis['has_numbers'] is False
        assert analysis['has_underscores'] is False
        assert analysis['has_dots'] is False
        assert analysis['has_hyphens'] is False
        # Empty string edge case - check the actual implementation behavior
        # For empty string, islower() and isupper() both return False
        assert analysis['is_all_lowercase'] is False
        assert analysis['is_all_uppercase'] is False
        assert analysis['has_mixed_case'] is False
        # For empty string, these should be False
        assert analysis['starts_with_number'] is False
        assert analysis['ends_with_number'] is False
    
    @patch('time.time')
    @patch.object(SocialMediaLookup, '_check_platform')
    def test_lookup_username_complete(self, mock_check_platform, mock_time):
        """Test complete username lookup process"""
        # Mock time
        mock_time.side_effect = [0, 1.0]  # Start and end time
        
        # Mock platform checking
        mock_check_platform.return_value = {
            'exists': True,
            'url': 'https://twitter.com/testuser',
            'status_code': 200,
            'response_time': 0.5,
            'profile_info': {}
        }
        
        result = self.lookup.lookup_username("testuser")
        
        assert result['username'] == "testuser"
        assert result['total_found'] > 0
        assert 'platforms' in result
        assert 'twitter' in result['platforms']
        assert result['platforms']['twitter']['exists'] is True
        assert result['lookup_time'] == 1.0
    
    def test_lookup_username_exception_handling(self):
        """Test username lookup exception handling"""
        with patch.object(SocialMediaLookup, '_clean_username', side_effect=Exception("Test error")):
            result = self.lookup.lookup_username("testuser")
            
            assert 'error' in result
            assert result['error'] == "Test error"
    
    def test_lookup_username_platform_exception(self):
        """Test username lookup with platform exception"""
        with patch.object(SocialMediaLookup, '_check_platform', side_effect=Exception("Platform error")):
            result = self.lookup.lookup_username("testuser")
            
            assert 'platforms' in result
            # Should handle platform errors gracefully
            assert len(result['platforms']) > 0