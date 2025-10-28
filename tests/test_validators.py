"""
Tests for validation utilities
"""

import pytest
from osint_cli.utils.validators import (
    validate_email, validate_domain, validate_ip, validate_url, sanitize_input
)


class TestEmailValidation:
    """Test email validation functionality"""
    
    def test_valid_emails(self):
        """Test valid email addresses"""
        valid_emails = [
            "user@example.com",
            "test.email@domain.org",
            "user+tag@example.co.uk",
            "user_name@example-domain.com",
            "123@example.com",
            "user@sub.domain.com"
        ]
        
        for email in valid_emails:
            assert validate_email(email), f"Email {email} should be valid"
    
    def test_invalid_emails(self):
        """Test invalid email addresses"""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "user@",
            "user@.com",
            "user@example",
            "user@example..com",
            "",
            "user@example.com@",
            "user@example.com."
        ]
        
        for email in invalid_emails:
            assert not validate_email(email), f"Email {email} should be invalid"
        
        # Test None separately as it's a special case
        assert not validate_email(None)
        
        # Test email with double dots in local part (this should be invalid)
        assert not validate_email("user..name@example.com")
    
    def test_edge_cases(self):
        """Test edge cases for email validation"""
        # Empty string
        assert not validate_email("")
        
        # None value
        assert not validate_email(None)
        
        # Non-string input
        assert not validate_email(123)
        assert not validate_email([])
        assert not validate_email({})


class TestDomainValidation:
    """Test domain validation functionality"""
    
    def test_valid_domains(self):
        """Test valid domain names"""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "example-domain.org",
            "test.co.uk",
            "example123.com",
            "a.b.c.d.e"
        ]
        
        for domain in valid_domains:
            assert validate_domain(domain), f"Domain {domain} should be valid"
    
    def test_invalid_domains(self):
        """Test invalid domain names"""
        invalid_domains = [
            "invalid",
            ".example.com",
            "example.",
            "example..com",
            "example-.com",
            "-example.com",
            "",
            None,
            "example.com.",
            "example..com"
        ]
        
        for domain in invalid_domains:
            assert not validate_domain(domain), f"Domain {domain} should be invalid"
    
    def test_domain_with_protocol(self):
        """Test domain validation with protocol"""
        assert validate_domain("https://example.com")
        assert validate_domain("http://example.com")
        assert not validate_domain("ftp://example.com")
    
    def test_domain_with_www(self):
        """Test domain validation with www prefix"""
        assert validate_domain("www.example.com")
        assert validate_domain("https://www.example.com")


class TestIPValidation:
    """Test IP address validation functionality"""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses"""
        valid_ipv4 = [
            "192.168.1.1",
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "10.0.0.1"
        ]
        
        for ip in valid_ipv4:
            assert validate_ip(ip), f"IP {ip} should be valid"
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses"""
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "::",
            "2001:db8::"
        ]
        
        for ip in valid_ipv6:
            assert validate_ip(ip), f"IP {ip} should be valid"
    
    def test_invalid_ips(self):
        """Test invalid IP addresses"""
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.1.1.",
            ".192.168.1.1",
            "192.168.1.01",
            "",
            None,
            "not-an-ip",
            "192.168.1.1:8080"
        ]
        
        for ip in invalid_ips:
            assert not validate_ip(ip), f"IP {ip} should be invalid"


class TestURLValidation:
    """Test URL validation functionality"""
    
    def test_valid_urls(self):
        """Test valid URLs"""
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://www.example.com/path",
            "http://sub.example.com:8080/path?query=value",
            "https://example.com:443/path#fragment"
        ]
        
        for url in valid_urls:
            assert validate_url(url), f"URL {url} should be valid"
    
    def test_invalid_urls(self):
        """Test invalid URLs"""
        invalid_urls = [
            "example.com",
            "not-a-url",
            "",
            "https://",
            "http://",
            "://example.com"
        ]
        
        for url in invalid_urls:
            assert not validate_url(url), f"URL {url} should be invalid"
        
        # Test None separately as it's a special case
        assert not validate_url(None)
        
        # Test FTP URL (this should be invalid for our use case)
        assert not validate_url("ftp://example.com")


class TestInputSanitization:
    """Test input sanitization functionality"""
    
    def test_sanitize_input(self):
        """Test input sanitization"""
        test_cases = [
            ("normal input", "normal input"),
            ("input with <script>", "input with script"),
            ("input with 'quotes'", "input with quotes"),
            ("input with \"double quotes\"", "input with double quotes"),
            ("input with & ampersand", "input with  ampersand"),
            ("input with ; semicolon", "input with  semicolon"),
            ("input with | pipe", "input with  pipe"),
            ("input with ` backtick", "input with  backtick"),
            ("input with $ dollar", "input with  dollar"),
            ("input with () parentheses", "input with  parentheses"),
            ("", ""),
            (None, ""),
            ("   whitespace   ", "whitespace")
        ]
        
        for input_str, expected in test_cases:
            result = sanitize_input(input_str)
            assert result == expected, f"Input '{input_str}' should sanitize to '{expected}'"
    
    def test_sanitize_edge_cases(self):
        """Test sanitization edge cases"""
        # Empty string
        assert sanitize_input("") == ""
        
        # None value
        assert sanitize_input(None) == ""
        
        # Non-string input
        assert sanitize_input(123) == ""
        assert sanitize_input([]) == ""
        assert sanitize_input({}) == ""